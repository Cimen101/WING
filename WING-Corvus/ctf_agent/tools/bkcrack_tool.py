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
            "  known_plain_path: 已知明文文件路径 (与 known_bytes 二选一)\n"
            "  known_bytes: 已知明文字节 (十六进制字符串, 如 '4354467b'=CTF{) (与 known_plain_path 二选一)\n"
            "  known_offset: known_bytes 在 zip 加密数据中的偏移 (默认 12, 跳过 12 字节加密头 nonce)\n"
            "  zip_entry: zip 内目标文件名 (必填, 如 'flag.txt'/'junk.dat')\n"
            "  offset: 已知明文文件在 zip 数据中的偏移 (默认 12, zipCrypto 加密头 12 字节)\n"
            "  timeout: 攻击超时秒数 (默认 300)\n"
            "  extract: 是否自动解压 (默认 True)\n"
            "  output_dir: 解压输出目录 (默认 /tmp/bkcrack_out)\n"
            "用法示例:\n"
            "  bkcrack_attack(zip_path='/challenge/workspace/attachment.zip',\n"
            "    known_plain_path='/challenge/workspace/known_plain.raw',\n"
            "    zip_entry='challenge.avif', offset=12, timeout=300)\n"
            "  # 已知 flag 明文前缀时用 known_bytes (GCTF ZIP 题: flag.txt 以 CTF{ 开头):\n"
            "  bkcrack_attack(zip_path='hard.zip', zip_entry='flag.txt',\n"
            "    known_bytes='4354467b', known_offset=12, timeout=300)"
        )

    @property
    def parameters(self) -> dict[str, dict[str, Any]]:
        return {
            "zip_path": {"type": "string", "description": "zip 文件路径 (必填)"},
            "known_plain_path": {"type": "string", "description": "已知明文文件路径 (与 known_bytes 二选一)"},
            "known_bytes": {"type": "string", "description": "已知明文十六进制字节, 如 '4354467b'=CTF{ (与 known_plain_path 二选一)"},
            "known_offset": {"type": "integer", "description": "known_bytes 在加密数据中的偏移 (默认 12)", "default": 12},
            "zip_entry": {"type": "string", "description": "zip 内目标文件名 (必填)"},
            "offset": {"type": "integer", "description": "已知明文文件在 zip 数据中的偏移 (默认 12)", "default": 12},
            "timeout": {"type": "integer", "description": "攻击超时秒数 (默认 300)", "default": 300},
            "extract": {"type": "boolean", "description": "是否自动解压 (默认 True)", "default": True},
            "output_dir": {"type": "string", "description": "解压输出目录 (默认 /tmp/bkcrack_out)", "default": "/tmp/bkcrack_out"},
        }

    def execute(self, **kwargs: Any) -> str:
        zip_path = kwargs.get("zip_path", "")
        known_plain = kwargs.get("known_plain_path", "")
        known_bytes = kwargs.get("known_bytes", "")
        known_offset = int(kwargs.get("known_offset", 12))
        zip_entry = kwargs.get("zip_entry", "")
        offset = int(kwargs.get("offset", 12))
        timeout = int(kwargs.get("timeout", 300))
        extract = kwargs.get("extract", True)
        output_dir = kwargs.get("output_dir", "/tmp/bkcrack_out")

        if not zip_path or not zip_entry:
            return "ERROR: zip_path 和 zip_entry 为必填参数"
        if not known_plain and not known_bytes:
            return (
                "ERROR: 需要提供已知明文 — known_plain_path (明文文件) 或 known_bytes (十六进制字节) 二选一.\n"
                "提示: ZipCrypto 已知明文攻击要求已知明文与 zip 内目标条目密文对应.\n"
                "  - 若生成脚本存在 (如 hard.py), 先读它确认哪些明文已知 (如 flag.txt 以 'CTF{' 开头)\n"
                "  - 用 known_bytes='4354467b' (CTF{) + known_offset=12 指定已知字节\n"
                "  - junk.dat 类随机数据条目**不是**有效已知明文"
            )

        # 0. 前置参数校验 (hex 合法性, 在任何 ssh 调用前)
        if known_bytes:
            kb = known_bytes.strip().lower()
            if not re.fullmatch(r"[0-9a-f]+", kb):
                return f"ERROR: known_bytes 必须是十六进制 (如 '4354467b'=CTF{{), 收到: {known_bytes!r}"

        # 1. 检查 bkcrack 可用性
        if not _check_bkcrack(self._ssh):
            return "ERROR: bkcrack 不可用, 请确保容器已预装 bkcrack"

        # 2. 构建攻击命令 (优先 -x 已知字节模式; 否则 -p 明文文件模式)
        if known_bytes:
            cmd = f"bkcrack -C '{zip_path}' -c '{zip_entry}' -x {known_offset} {kb}"
        else:
            cmd = f"bkcrack -C '{zip_path}' -c '{zip_entry}' -p '{known_plain}' -o {offset}"

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
        poll_interval = 10
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
                "cat /tmp/bkcrack_result.txt 2>/dev/null | tail -8",
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

            # Sprint 41: 已知明文不足 / Data error 明文不匹配 → 立即诊断, 不空转到超时
            _low = result_text.lower()
            if "not enough" in _low or "too short" in _low:
                return (
                    f"bkcrack 攻击失败 ({elapsed}s): 已知明文不足 (bkcrack 需 ≥8 连续明文).\n"
                    f"bkcrack 输出: {_truncate(result_text, 600)}\n\n"
                    f"诊断引导:\n"
                    f"1. **已知明文长度不足**: bkcrack 需要至少 8 字节**连续**已知明文, 当前只提供 "
                    f"`{known_bytes or known_plain or ''}` (实际可用 {len(known_bytes)//2 if known_bytes else '?'} 字节).\n"
                    f"2. **zipCrypto 校验字节**: bkcrack 从 zip 加载密文时会自动把 nonce 校验字节 "
                    f"(= CRC>>24) 计入已知明文 — 若 zip 头有 CRC, 先确认 `zip_entry` 对应的 CRC.\n"
                    f"3. **获取更多连续明文**: 读生成脚本 (hard.py) 找出已知明文片段; "
                    f"flag.txt 明文以 'CTF{{' 开头 (4 字节), 结合校验字节可能仍不足, 需找更长明文.\n"
                    f"4. 若题目仅提供 <8 字节已知明文, bkcrack 无法直接攻击 — 需手工实现 "
                    f"Biham-Kocher 攻击 (用已知 CRC 校验恢复 key 状态) 或用其他手段."
                )
            if "match" in _low or "data error" in _low or "no match" in _low or "unable" in _low:
                return (
                    f"bkcrack 攻击失败 ({elapsed}s): 已知明文不匹配或参数错误.\n"
                    f"bkcrack 输出: {_truncate(result_text, 600)}\n\n"
                    f"诊断引导 (常见错误):\n"
                    f"1. **已知明文错误**: 已知明文必须与 zip 内 '{zip_entry}' 的密文对应.\n"
                    f"   - 先读生成脚本 (hard.py) 确认明文内容; 随机数据条目 (如 junk.dat) 不是有效明文\n"
                    f"   - flag.txt 明文以 'CTF{{' 开头 → 用 known_bytes='4354467b' + known_offset=12\n"
                    f"2. **offset 错误**: zipCrypto 加密数据前 12 字节是 nonce, 已知明文通常 offset=12\n"
                    f"3. 若已知明文 <12 字节, 用 known_bytes 指定全部已知字节仍不足时, 换更长明文"
                )

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