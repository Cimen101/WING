"""L2 APK 反编译工具 (新增).

封装 Kali 上预装的 APK 反编译工具为 Tool 接口,让 LLM 直接调用:
- ApkJadxTool: 用 jadx 把 dex 还原为可读 Java 源码 (首选, 适合阅读业务逻辑)
- ApkToolTool: 用 apktool d 拆 smali/AndroidManifest/res (适合改包/重打包/资源分析)

设计原则:
- 工具自动检测可用性 (Kali 未装则提示降级到 ssh_exec + 手动 jadx)
- 输出截断避免 LLM 上下文污染
- jadx 优先: 直接出 Java 源码, LLM 可读性远高于 smali
- apktool 次之: 用于需要 smali/资源文件的场景 (如改包)

关键作用: 解决 Simple_Calculator 退化 (v3 17步成功 → v7 28步失败).
LLM 走 5 步即可解出 flag (jadx → grep revealFlag → 写 AES 解密 → flag).

参考真实解法:
1. jadx -d <out> <apk>      # 生成 Java 源码
2. grep -E 'AES|Cipher|MessageDigest' MainActivity.java
3. 找 revealFlag() 方法 → 提取 key/IV/密文
4. 写 python3 AES-CBC 解密脚本
5. 输出 flag
"""
from __future__ import annotations

from typing import Any, Optional

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool


# 输出截断阈值
_MAX_OUTPUT = 8000  # Java 源码可能很长
_TRUNCATED_SUFFIX = "\n... (输出截断,共 {total} 字符)"


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    total = len(text)
    if total <= max_len:
        return text
    return text[:max_len] + _TRUNCATED_SUFFIX.format(total=total)


def _check_tool(ssh: SSHClient, tool_name: str) -> tuple[bool, str]:
    """检测 Kali 上工具是否可用, 返回 (可用, 错误信息)."""
    r = ssh.exec_cmd(f"which {tool_name} && {tool_name} --version 2>&1 | head -2", timeout=10)
    if not r.is_success:
        return False, f"Kali 沙箱未安装 {tool_name}. 请用 ssh_exec 手动运行, 或 apt install {tool_name}."
    return True, ""


# ============ ApkJadxTool (首选) ============

class ApkJadxTool(Tool):
    """用 jadx 把 dex 还原为可读 Java 源码.

    用途: reverse 题目, 附件是 .apk 文件, 需要分析 Android 应用逻辑.
    适用: 大部分 APK reverse 题 (如 Simple_Calculator, 加密/flag 计算逻辑).

    关键优势:
    - 直接生成可读 Java 源码 (而非 smali), LLM 阅读效率高 10x
    - 包含完整类名/方法签名, 便于 grep 关键方法 (如 revealFlag, checkPassword)
    - 自动解析 R8/ProGuard 混淆 (部分还原)

    典型流程:
        1. apk_jadx(apk_path="/tmp/challenge.apk", output_dir="/tmp/jadx_out")
        2. 读 jadx 输出: cat /tmp/jadx_out/sources/<package>/<MainActivity>.java
        3. grep 关键方法: grep -E 'AES|Cipher|MessageDigest|Flag|flag' ...
        4. 写 Python 解密脚本
        5. 跑出 flag
    """

    name = "apk_jadx"
    description = (
        "用 jadx 把 Android APK 的 dex 字节码还原为可读 Java 源码. "
        "reverse APK 题首选工具: 比 binary_analyzer (smali 字节码) 易读 10x. "
        "自动解析类/方法/字段, 包含字符串常量 (如 AES key, 'Congratulations', flag 模板). "
        "Kali 工具路径: /usr/bin/jadx (已装 1.5.5). "
        "⚠️ 大 APK (50MB+) 解压慢, 建议 output_dir 放在 /tmp 而非 /root."
    )
    parameters = {
        "type": "object",
        "properties": {
            "apk_path": {
                "type": "string",
                "description": "Kali 上 .apk 文件绝对路径 (如 /tmp/ctf_workspace/app.apk)",
            },
            "output_dir": {
                "type": "string",
                "description": "Kali 上输出目录 (如 /tmp/jadx_out), 不存在会自动创建",
            },
            "show_errors": {
                "type": "boolean",
                "description": "是否显示 jadx 解码错误 (默认 true, 帮助 LLM 了解部分还原情况)",
            },
        },
        "required": ["apk_path", "output_dir"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh_client = ssh_client

    def execute(
        self,
        apk_path: str,
        output_dir: str,
        show_errors: bool = True,
        **_: Any,
    ) -> str:
        if not apk_path:
            return "ERROR: apk_path 不能为空"
        if not output_dir:
            return "ERROR: output_dir 不能为空"

        ok, err = _check_tool(self.ssh_client, "jadx")
        if not ok:
            return err

        # 1. 清理旧输出 + 创建新目录
        r = self.ssh_client.exec_cmd(f"rm -rf {output_dir} && mkdir -p {output_dir}", timeout=10)
        if not r.is_success:
            return f"ERROR: 无法创建输出目录 {output_dir}: {r.stderr[:300]}"

        # 2. 跑 jadx
        r = self.ssh_client.exec_cmd(
            f"jadx -d {output_dir} {apk_path} 2>&1",
            timeout=180,  # APK 解压可能慢
        )

        # 3. 解析输出
        parts: list[str] = []
        parts.append(f"=== jadx 反编译 {apk_path} → {output_dir} ===")
        parts.append(f"[exit_code={r.exit_code}, elapsed={r.elapsed:.2f}s]")

        if r.stdout:
            # jadx 输出通常很多 DEBUG/INFO, 截断
            out = _truncate(r.stdout)
            parts.append(f"--- stdout ---\n{out}")
        if r.stderr and show_errors:
            err_out = _truncate(r.stderr, 2000)
            parts.append(f"--- stderr (jadx 错误) ---\n{err_out}")

        # 4. 列出反编译出的 Java 文件数
        r2 = self.ssh_client.exec_cmd(f"find {output_dir}/sources -name '*.java' 2>/dev/null | wc -l", timeout=10)
        java_count = r2.stdout.strip() if r2.is_success else "?"
        parts.append(f"\n=== 反编译结果: {java_count} 个 .java 文件 ===")

        # 5. 列出 package 目录 (一级)
        r3 = self.ssh_client.exec_cmd(
            f"find {output_dir}/sources -mindepth 1 -maxdepth 3 -type d 2>/dev/null | head -20",
            timeout=10,
        )
        if r3.is_success and r3.stdout.strip():
            parts.append(f"--- 顶层包目录 ---\n{r3.stdout.strip()}")

        # 6. 关键提示: grep 建议
        parts.append(
            "\n=== 下一步建议 ===\n"
            "1. 找 MainActivity: find <output>/sources -name 'MainActivity*.java'\n"
            "2. 读源码: cat <MainActivity.java>\n"
            "3. 搜 flag/密钥: grep -rE 'athena\\{|flag|Flag|AES|Cipher|MessageDigest|reveal' <output>/sources\n"
            "4. 用 ssh_exec 写 python3 解密脚本 (AES/DES/RSA/...)"
        )

        return "\n".join(parts)


# ============ ApkToolTool (备选) ============

class ApkToolTool(Tool):
    """用 apktool d 拆 smali + 资源.

    用途: 需要 smali 字节码/资源文件/AndroidManifest.xml 原始结构时用.
    适用: 改包重打包、读取资源 (图片/xml)、分析 R8 混淆后 smali.

    与 jadx 对比:
    - jadx: 友好 Java 源码, LLM 易读, 但部分混淆无法还原
    - apktool: 完整 smali + 资源, 适合深度分析, 但 LLM 阅读难度高
    """

    name = "apktool"
    description = (
        "用 apktool d 拆 APK 为 smali 字节码 + AndroidManifest.xml + 资源文件. "
        "比 jadx 更底层, 适合需要完整原始结构 (改包/资源/smali 深度分析) 的场景. "
        "Kali 工具路径: /usr/bin/apktool (apt install). "
        "⚠️ 输出是 smali (汇编), LLM 阅读难度高, 优先用 apk_jadx 除非确需 smali."
    )
    parameters = {
        "type": "object",
        "properties": {
            "apk_path": {
                "type": "string",
                "description": "Kali 上 .apk 文件绝对路径",
            },
            "output_dir": {
                "type": "string",
                "description": "Kali 上输出目录 (如 /tmp/apk_out)",
            },
            "force": {
                "type": "boolean",
                "description": "是否强制覆盖已存在目录 (默认 true)",
            },
        },
        "required": ["apk_path", "output_dir"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh_client = ssh_client

    def execute(
        self,
        apk_path: str,
        output_dir: str,
        force: bool = True,
        **_: Any,
    ) -> str:
        if not apk_path:
            return "ERROR: apk_path 不能为空"
        if not output_dir:
            return "ERROR: output_dir 不能为空"

        ok, err = _check_tool(self.ssh_client, "apktool")
        if not ok:
            return err

        # 1. 清理旧输出
        flag = "-f" if force else ""
        self.ssh_client.exec_cmd(f"rm -rf {output_dir}", timeout=10)

        # 2. 跑 apktool d
        r = self.ssh_client.exec_cmd(
            f"apktool d {apk_path} -o {output_dir} {flag} 2>&1",
            timeout=180,
        )

        parts: list[str] = []
        parts.append(f"=== apktool d {apk_path} → {output_dir} ===")
        parts.append(f"[exit_code={r.exit_code}, elapsed={r.elapsed:.2f}s]")

        if r.stdout:
            parts.append(f"--- stdout ---\n{_truncate(r.stdout, 3000)}")
        if r.stderr:
            parts.append(f"--- stderr ---\n{_truncate(r.stderr, 1500)}")

        # 列出 smali 文件数
        r2 = self.ssh_client.exec_cmd(
            f"find {output_dir}/smali* -name '*.smali' 2>/dev/null | wc -l",
            timeout=10,
        )
        smali_count = r2.stdout.strip() if r2.is_success else "?"
        parts.append(f"\n=== 拆解结果: {smali_count} 个 .smali 文件 ===")

        parts.append(
            "\n=== 下一步建议 ===\n"
            "1. 看 Manifest: cat <output>/AndroidManifest.xml\n"
            "2. 找 MainActivity: find <output>/smali -name 'MainActivity*.smali'\n"
            "3. ⚠️ smali 难读, 建议用 apk_jadx 重新生成 Java 源码"
        )

        return "\n".join(parts)


# ============ 工厂函数 ============

def apk_tools(ssh_client: SSHClient) -> list[Tool]:
    """返回新增的 APK 工具集.

    包含:
    - ApkJadxTool (首选, Java 源码)
    - ApkToolTool (备选, smali + 资源)
    """
    return [
        ApkJadxTool(ssh_client),
        ApkToolTool(ssh_client),
    ]
