# -*- coding: utf-8 -*-
"""L2 Feistel 密码解密工具 (Sprint 15 P0 重写).

Crypto_Reverse 实际算法 (per main_disasm.txt):
- 64-bit 块 (32-bit L + 32-bit R)
- 8 轮 Feistel
- 密钥: 32-bit low_key 实际有效, high_key 仅在 == 0xFFFFFFFF 时影响 rk[0]
- 密钥扩展: rk[i] = ror32(low_key, (i*7) & 0x1F) XOR (i * 0xB7E15163)
            if high_key == 0xFFFFFFFF: rk[0] ^= 0xFFFFFFFF
- F-function (MurmurHash3 mix32):
    x = R XOR rk
    x = x * 0x5BD1E995
    x = x XOR (x >> 13)
    x = x + (x ROL 4)
    x = x XOR 0xA5C3E1D7
    x = x XOR (x >> 11)
- 加密: L, R = R, L XOR F(R, rk)
- 解密: 倒序使用 round key, L = R XOR F(L, rk), R = old_L

攻击算法 (Reverse Decrypt Brute-Force):
- 已知 flag 前缀 'athena{' (7 字节)
- 加密 flag 文件 = 16 字节 = 2 个 64-bit block (c0, c1)
- 对每个 low_key in [0, 2^32):
    解密 c0 -> p0, 检查 p0 低 56 位 == LE 'athena{' = 0x007b616e65687461
    命中: 解密 c1 -> p1, 输出 flag = p0 || p1
- 复杂度: 2^32 decrypt ops (≈ 47s in C with -O3 -march=native on Kali)
- 加速: 通过 SSH 在 Kali 上编译运行 C 程序 brute_decrypt.c

降级: 若 SSH 不可用, 回退到 Python brute-force (≈ 30 min).
"""
from __future__ import annotations

import base64
import time
from pathlib import Path
from typing import Any

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool
from ctf_agent.tools.feistel_v15 import (
    block_cipher,
    block_cipher_decr,
)


_MAX_OUTPUT = 4000
_TRUNCATED_SUFFIX = "\n... (输出截断, 共 {total} 字符)"


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + _TRUNCATED_SUFFIX.format(total=len(text))


# ============ Python brute-force (fallback) ============

def _python_brute_decrypt(
    c0: int,
    c1: int,
    known_prefix: bytes,
    use_high_ff: bool = False,
    progress_every: int = 0x1000000,
) -> list[tuple[int, int, int]]:
    """Python 实现 brute-force (回退方案, 慢).

    Returns: list of (key, p0, p1) tuples.
    """
    high = 0xFFFFFFFF if use_high_ff else 0x0
    prefix_int = int.from_bytes(known_prefix, "little")
    prefix_mask = (1 << (8 * len(known_prefix))) - 1

    candidates: list[tuple[int, int, int]] = []
    for low in range(0, 0x100000000):
        if low % progress_every == 0 and low > 0:
            print(f"  Python progress: {low / 0x100000000 * 100:.1f}%", flush=True)
        key = (high << 32) | low
        p0 = block_cipher_decr(c0, key)
        if (p0 & prefix_mask) == prefix_int:
            p1 = block_cipher_decr(c1, key)
            candidates.append((key, p0, p1))
    return candidates


# ============ C brute-force (SSH on Kali) ============

_C_BRUTE_SRC_PATH = Path(__file__).parent / "brute_decrypt.c"
_C_REMOTE_PATH = "/tmp/ctf_agent_brute_decrypt"
_C_REMOTE_C_PATH = "/tmp/ctf_agent_brute_decrypt.c"


def _c_brute_decrypt(
    ssh: SSHClient,
    c0: int,
    c1: int,
    use_high_ff: bool = False,
) -> list[tuple[int, int, int]]:
    """通过 SSH 在 Kali 上编译并运行 brute_decrypt.c.

    Returns: list of (key, p0, p1) tuples.
    """
    # 1. 上传 C 源码
    src_text = _C_BRUTE_SRC_PATH.read_text(encoding="utf-8")
    src_b64 = base64.b64encode(src_text.encode("utf-8")).decode()
    r = ssh.exec_cmd(
        f"echo '{src_b64}' | base64 -d > {_C_REMOTE_C_PATH} && "
        f"ls -la {_C_REMOTE_C_PATH}",
        timeout=10,
    )
    if r.exit_code != 0:
        raise RuntimeError(f"上传 C 源码失败: {r.stderr[:200]}")

    # 2. 编译
    r = ssh.exec_cmd(
        f"gcc -O3 -march=native -o {_C_REMOTE_PATH} {_C_REMOTE_C_PATH} 2>&1",
        timeout=30,
    )
    if r.exit_code != 0:
        raise RuntimeError(f"编译失败: {r.stdout[:200]}{r.stderr[:200]}")

    # 3. 运行 (后台, 避免 SSH timeout)
    flag_arg = "f" if use_high_ff else "0"
    remote_stdout = "/tmp/ctf_agent_bd.out"
    remote_stderr = "/tmp/ctf_agent_bd.err"
    r = ssh.exec_cmd(
        f"{_C_REMOTE_PATH} {c0:016x} {c1:016x} {flag_arg} "
        f"> {remote_stdout} 2> {remote_stderr}",
        timeout=180,  # 2^32 在 Kali 上约 47s
    )
    if r.exit_code != 0 and "timeout" not in r.stderr.lower():
        # 不一定是错误 (found=0 是合法的)
        pass

    # 4. 解析 stdout
    r = ssh.exec_cmd(f"cat {remote_stdout}", timeout=5)
    output = r.stdout

    # 解析 FOUND: key=0x...  p0 = 0x...  p1 = 0x...
    candidates: list[tuple[int, int, int]] = []
    key = p0 = p1 = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("FOUND:"):
            # FOUND: key=0x...
            if key is not None and p0 is not None and p1 is not None:
                candidates.append((key, p0, p1))
            hex_str = line.split("key=")[1].strip()
            key = int(hex_str, 16)
            p0 = p1 = None
        elif line.startswith("p0 ="):
            hex_str = line.split("=")[1].split()[0].strip()
            p0 = int(hex_str, 16)
        elif line.startswith("p1 ="):
            hex_str = line.split("=")[1].split()[0].strip()
            p1 = int(hex_str, 16)
    # 最后一组
    if key is not None and p0 is not None and p1 is not None:
        candidates.append((key, p0, p1))

    return candidates


# ============ FeistelDecryptTool ============

class FeistelDecryptTool(Tool):
    """Crypto_Reverse 类 Feistel 密钥恢复 + 解密工具 (Sprint 15 P0 重写).

    算法: 8 轮 Feistel, 64-bit 块, 32-bit 有效 key (MurmurHash3 mix32 F-function).
    攻击: 反向 brute-force, 检查已知前缀 'athena{', 复杂度 2^32 ≈ 47s in C.
    加速: SSH 上传 C 到 Kali 编译 -O3 -march=native 运行.

    用法:
      feistel_decrypt(
          encrypted_hex='ab28667c0fc996f7ea61293090fc4b5d',  # 32 hex = 16 bytes = 2 blocks
          known_prefix='athena{',  # 可选, 用于过滤候选
      )

    工具自动:
    1. 解析密文 (16 bytes = 2 blocks, LE)
    2. 通过 SSH 在 Kali 上编译并运行 brute_decrypt
    3. 验证候选 (round-trip 加密)
    4. 返回 key + flag
    """

    name = "feistel_decrypt"
    description = (
        "Crypto_Reverse Feistel 密钥恢复 + 解密 (Sprint 15 P0).\n"
        "算法: 8 轮 Feistel, 64-bit 块, 32-bit 有效 key, MurmurHash3 mix32 F-function.\n"
        "攻击: 反向 brute-force, 2^32 keys ≈ 47s in C on Kali (SSH).\n"
        "用法: feistel_decrypt(encrypted_hex='...32hex...', known_prefix='athena{').\n"
        "降级: SSH 不可用时用 Python brute-force (慢 30x).\n"
        "返回: 恢复的 key (hex) + 解密后的 flag (UTF-8)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "encrypted_hex": {
                "type": "string",
                "description": "密文 hex 字符串 (16 bytes = 32 hex chars = 2 个 64-bit block). LE 字节序.",
            },
            "known_prefix": {
                "type": "string",
                "description": "已知明文前缀 (默认 'athena{'), 用于过滤候选. 1-8 bytes.",
                "default": "athena{",
            },
            "use_high_ff": {
                "type": "boolean",
                "description": "是否额外搜索 high_key=0xFFFFFFFF (默认 False, 只搜 high=0).",
                "default": False,
            },
        },
        "required": ["encrypted_hex"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh = ssh_client

    def execute(
        self,
        encrypted_hex: str,
        known_prefix: str = "athena{",
        use_high_ff: bool = False,
        **_: Any,
    ) -> str:
        # 1. 解析密文
        try:
            enc_bytes = bytes.fromhex(encrypted_hex.replace(" ", "").replace("\n", ""))
        except ValueError as e:
            return f"ERROR: encrypted_hex 解析失败: {e}. 格式: 'ab28667c0fc996f7ea61293090fc4b5d' (32 hex chars)"

        if len(enc_bytes) < 8:
            return f"ERROR: encrypted_hex 至少需要 8 字节 (16 hex chars), 实际 {len(enc_bytes)} 字节"
        if len(enc_bytes) < 16:
            return f"ERROR: 需要至少 16 字节 (2 blocks) 用于 brute-force + verify, 实际 {len(enc_bytes)} 字节"

        # LE 解释 (per disasm 输出格式)
        c0_int = int.from_bytes(enc_bytes[0:8], "little")
        c1_int = int.from_bytes(enc_bytes[8:16], "little")
        prefix = known_prefix.encode("utf-8")
        if not (1 <= len(prefix) <= 8):
            return f"ERROR: known_prefix 长度 1-8 bytes, 实际 {len(prefix)}"

        lines: list[str] = []
        lines.append("=== Feistel Decrypt (Sprint 15 P0) ===")
        lines.append("  Algorithm: 8-round Feistel, 64-bit block, 32-bit effective key")
        lines.append("  F-function: MurmurHash3 mix32 (MUL 0x5BD1E995, XOR 0xA5C3E1D7, ROL 4)")
        lines.append(f"  Cipher ({len(enc_bytes)} bytes = 2 blocks):")
        lines.append(f"    c0 (LE): 0x{c0_int:016x}")
        lines.append(f"    c1 (LE): 0x{c1_int:016x}")
        lines.append(f"  Known prefix: {known_prefix!r} ({len(prefix)} bytes)")
        lines.append(f"  Search high: 0x{0xFFFFFFFF if use_high_ff else 0:08x} "
                     f"({'2x time' if use_high_ff else 'standard'})")

        # 2. 尝试 C 加速
        candidates: list[tuple[int, int, int]] = []
        method = "C-on-Kali"
        t0 = time.time()
        try:
            candidates = _c_brute_decrypt(self.ssh, c0_int, c1_int, use_high_ff=use_high_ff)
        except Exception as e:
            lines.append(f"\n  ⚠️ C 加速失败 ({type(e).__name__}: {e}), 回退到 Python brute-force...")
            method = "Python (fallback)"
            try:
                # Python 先尝试 high=0
                candidates_h0 = _python_brute_decrypt(c0_int, c1_int, prefix, use_high_ff=False)
                if candidates_h0:
                    candidates = candidates_h0
                elif use_high_ff:
                    candidates = _python_brute_decrypt(c0_int, c1_int, prefix, use_high_ff=True)
            except Exception as e2:
                lines.append(f"  Python fallback 也失败: {e2}")
                return _truncate("\n".join(lines), 4000)

        elapsed = time.time() - t0
        lines.append(f"\n  Method: {method}")
        lines.append(f"  Elapsed: {elapsed:.1f}s")
        lines.append(f"  Candidates (decrypt(c0) low-N-bit matches prefix): {len(candidates)}")

        if not candidates:
            lines.append("\n  ❌ No candidate found.")
            lines.append("  可能原因: known_prefix 不匹配, 或密文格式非 LE, 或算法有误.")
            return _truncate("\n".join(lines), 4000)

        # 3. 验证候选 (round-trip)
        valid: list[tuple[int, bytes, bytes]] = []
        for key, p0, p1 in candidates:
            c0_check = block_cipher(p0, key)
            c1_check = block_cipher(p1, key)
            if c0_check == c0_int and c1_check == c1_int:
                p0_bytes = p0.to_bytes(8, "little")
                p1_bytes = p1.to_bytes(8, "little")
                valid.append((key, p0_bytes, p1_bytes))

        lines.append(f"  Valid candidates (round-trip verified): {len(valid)}")

        # 4. 输出
        if not valid:
            lines.append("\n  ⚠️ Candidates found but round-trip FAILED.")
            lines.append("  Possible algorithm mismatch. Top unverified candidates:")
            for key, p0, p1 in candidates[:5]:
                p0_bytes = p0.to_bytes(8, "little")
                p1_bytes = p1.to_bytes(8, "little")
                flag_attempt = (p0_bytes + p1_bytes).rstrip(b"\x00").decode("utf-8", errors="replace")
                lines.append(f"    key=0x{key:016x} → flag_attempt={flag_attempt!r}")
        else:
            lines.append("\n  ✅ Valid keys (round-trip verified):")
            for key, p0_bytes, p1_bytes in valid[:5]:
                flag = (p0_bytes + p1_bytes).rstrip(b"\x00").decode("utf-8", errors="replace")
                lines.append(f"    key=0x{key:016x}")
                lines.append(f"      block 0: {p0_bytes!r}")
                lines.append(f"      block 1: {p1_bytes!r}")
                lines.append(f"      flag:    {flag!r}")
                # 验证 flag 格式
                if "athena{" in flag and flag.endswith("}"):
                    lines.append("      format:  ✅ 'athena{...}' format")

        return _truncate("\n".join(lines), 4000)


# ============ 工厂函数 ============

def feistel_tools(ssh_client: SSHClient) -> list[Tool]:
    """返回 Feistel 密码解密工具集 (Sprint 15 P0)."""
    return [FeistelDecryptTool(ssh_client)]
