"""L2 bkcrack 攻击工具 — zipCrypto 已知明文攻击封装.

适用场景:
- zipCrypto 加密的 zip 文件, 已知部分明文 (如文件头)
- 通过 bkcrack 恢复加密密钥, 再用密钥解压 zip

用法 (agent 调用):
    bkcrack_attack(zip_path, known_plain_path, zip_entry, offset=0, timeout=300)
    或在 zip 内已知明文时:
    bkcrack_attack(zip_path, known_plain_path, zip_entry="", offset=0, plain_offset=12, timeout=300)

实现:
- 通过 ssh_exec 调用容器内预装的 bkcrack
- 处理后台运行 + 进度检查 (避免 ssh_exec 超时)
- 自动解析 keys 并解压 zip
"""
from __future__ import annotations

import re
import time
from typing import Any

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool

_MAX_OUTPUT = 4000
_TRUNCATED_SUFFIX = "\n... (输出截断, 共 {total} 字符)"


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + _TRUNCATED_SUFFIX.format(total=len(text))


def _check_bkcrack(ssh: SSHClient) -> bool:
    """检测 bkcrack 是否可用."""
    r = ssh.exec_cmd("which bkcrack 2>/dev/null && bkcrack -h 2>&1 | head -1 || echo MISSING", timeout=10)
    return r.is_success and "bkcrack" in (r.stdout or "") and "MISSING" not in (r.stdout or "")


class BkcrackAttackTool(Tool):
    """bkcrack zipCrypto 已知明文攻击工具.

    封装 bkcrack 的完整攻击流程:
    1. 检查 bkcrack 可用性
    2. 执行已知明文攻击 (后台运行, 定期检查进度)
    3. 解析输出提取 keys
    4. 用 keys 解压 zip 输出文件
    """

    def __init__(self, ssh: SSHClient) -> None:
        super().__init__()
        self._ssh = ssh

    @property
    def name(self) -> str:
        return "bkcrack_attack"

    @property
    def description(self) -> str:
        return (
            "bkcrack 已知明文攻击: 破解 zipCrypto 加密的 zip 文件.\n"
            "参数:\n"
            "  zip_path: zip 文件路径 (必填)\n"
            "  known_plain_path: 已知明文文件路径 (必填)\n"
            "  zip_entry: zip 内目标文件名 (可选, 默认用已知明文攻击 zip 密码)\n"
            "  offset: 已知明文在 zip 数据中的偏移 (默认 0, zipCrypto 加密头 12 字节时用 12)\n"
            "  timeout: 攻击超时秒数 (默认 300)\n"
            "  extract: 是否自动解压 (默认 True)\n"
            "  output_dir: 解压输出目录 (默认 /tmp/bkcrack_out)\n"
            "用法示例:\n"
            "  bkcrack_attack(zip_path='/challenge/workspace/attachment.zip',\n"
            "    known_plain_path='/challenge/workspace/known_plain.raw',\n"
            "    zip_entry='challenge.avif', offset=0, timeout=300)"
        )

    @property
    def parameters(self) -> dict[str, dict[str, Any]]:
        return {
            "zip_path": {"type": "string", "description": "zip 文件路径 (必填)"},
            "known_plain_path": {"type": "string", "description": "已知明文文件路径 (必填)"},
            "zip_entry": {"type": "string", "description": "zip 内目标文件名 (可选)", "default": ""},
            "offset": {"type": "integer", "description": "已知明文在 zip 数据中的偏移 (默认 0)", "default": 0},
            "timeout": {"type": "integer", "description": "攻击超时秒数 (默认 300)", "default": 300},
            "extract": {"type": "boolean", "description": "是否自动解压 (默认 True)", "default": True},
            "output_dir": {"type": "string", "description": "解压输出目录 (默认 /tmp/bkcrack_out)", "default": "/tmp/bkcrack_out"},
        }

    def execute(self, **kwargs: Any) -> str:
        zip_path = kwargs.get("zip_path", "")
        known_plain = kwargs.get("known_plain_path", "")
        zip_entry = kwargs.get("zip_entry", "")
        offset = int(kwargs.get("offset", 0))
        timeout = int(kwargs.get("timeout", 300))
        extract = kwargs.get("extract", True)
        output_dir = kwargs.get("output_dir", "/tmp/bkcrack_out")

        if not zip_path or not known_plain:
            return "ERROR: zip_path 和 known_plain_path 为必填参数"

        # 1. 检查 bkcrack 可用性
        if not _check_bkcrack(self._ssh):
            return "ERROR: bkcrack 不可用, 请确保容器已预装 bkcrack"

        # 2. 构建攻击命令
        if zip_entry:
            # 已知明文是 zip 内某个文件的片段
            cmd = f"bkcrack -C '{zip_path}' -c '{zip_entry}' -p '{known_plain}' -o {offset}"
        else:
            # 已知明文是 zip 内某个文件的片段 (自动检测)
            cmd = f"bkcrack -C '{zip_path}' -p '{known_plain}' -o {offset}"

        # 3. 后台运行 bkcrack, 定期检查进度
        bg_cmd = f"cd /tmp && nohup {cmd} > /tmp/bkcrack_result.txt 2>&1 & echo PID:$!"
        r = self._ssh.exec_cmd(bg_cmd, timeout=15)
        if not r.is_success:
            return f"ERROR: 启动 bkcrack 失败: {r.stderr[:200] or r.stdout[:200]}"

        # 提取 PID
        pid_match = re.search(r"PID:(\d+)", r.stdout or "")
        if not pid_match:
            return f"ERROR: 无法获取 bkcrack PID, 输出: {r.stdout[:200]}"
        pid = pid_match.group(1)

        # 4. 轮询检查结果
        poll_interval = 15
        elapsed = 0
        keys = None
        result_text = ""

        while elapsed < timeout:
            time.sleep(poll_interval)
            elapsed += poll_interval

            # 检查进程是否还在运行
            check = self._ssh.exec_cmd(
                f"ps -p {pid} >/dev/null 2>&1 && echo RUNNING || echo DONE",
                timeout=10,
            )
            is_running = "RUNNING" in (check.stdout or "")

            # 读取结果文件
            read = self._ssh.exec_cmd(
                "cat /tmp/bkcrack_result.txt 2>/dev/null | tail -5",
                timeout=10,
            )
            result_text = read.stdout or ""

            # 解析 keys
            keys_match = re.search(
                r"Keys\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)",
                result_text,
            )
            if keys_match:
                keys = (keys_match.group(1), keys_match.group(2), keys_match.group(3))
                break

            if not is_running:
                # 进程已结束但没找到 keys
                break

        if not keys:
            status = "运行中" if elapsed < timeout else "超时"
            return (
                f"bkcrack 攻击 {status} ({elapsed}s)\n"
                f"最后输出:\n{_truncate(result_text, 1000)}\n\n"
                f"提示: 若攻击需要更长时间, 可增加 timeout 参数\n"
                f"也可手动检查: cat /tmp/bkcrack_result.txt"
            )

        # 5. 用 keys 解压 zip
        k1, k2, k3 = keys
        key_str = f"{k1} {k2} {k3}"

        if extract:
            extract_cmd = (
                f"mkdir -p '{output_dir}' && "
                f"bkcrack -C '{zip_path}' -k {key_str} -D '{output_dir}/decrypted.zip' 2>&1 && "
                f"cd '{output_dir}' && unzip -o decrypted.zip && ls -la"
            )
            r2 = self._ssh.exec_cmd(extract_cmd, timeout=60)
            extract_result = f"\n解压结果:\n{_truncate(r2.stdout or '', 1500)}"
            if r2.stderr:
                extract_result += f"\n解压 stderr: {r2.stderr[:300]}"
        else:
            extract_result = "\n(未自动解压, 可用 keys 手动解压)"

        return (
            f"bkcrack 攻击成功! (耗时 {elapsed}s)\n"
            f"Keys: {key_str}\n"
            f"原始输出摘要:\n{_truncate(result_text, 1000)}"
            f"{extract_result}"
        )


def bkcrack_tools(ssh: SSHClient) -> list[Tool]:
    """返回 bkcrack 工具列表."""
    return [BkcrackAttackTool(ssh)]