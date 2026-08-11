"""CRYPTO 扩展工具集（Sprint 36.5：ZKP / OTP / AES / Hash / McEliece）.

补齐以下缺失工具：
  1. zkp_forge_proof   — ZKP 零知识证明伪造
  2. otp_xor_analyze   — OTP 一次性密码本密钥重用分析
  3. aes_sidechannel   — AES 侧信道/后门分析
  4. hash_collision    — 哈希碰撞/Merkle-Damgård 检测
  5. mceliece_analyze  — McEliece 密码分析

设计原则：纯 Python 标准库（零重依赖），辅助分析为主，
实际攻击构造（如 ISD 解码）需配合 ssh_python 在容器中执行。
"""

from __future__ import annotations

import base64
import binascii
import math
import os
import re
import struct
from collections import Counter
from typing import Any

from ctf_agent.tools.base import Tool

_MAX_OUTPUT = 4000
_FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[^}]{1,200}\}")


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n... (输出截断, 共 {len(text)} 字符)"


def _to_int(v: Any) -> int | None:
    if v is None or v == "":
        return None
    if isinstance(v, int):
        return v
    s = str(v).strip().replace("_", "").replace(" ", "")
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s)
    except ValueError:
        try:
            return int(s, 16)
        except ValueError:
            return None


# ============================================================
# 1. ZKPForgeProofTool — 零知识证明伪造
# ============================================================

class ZKPForgeProofTool(Tool):
    """Rabin ZKP 证明伪造工具：构造通过验证的 (s, z) proof 对.

    原理：Rabin ZKP 协议中，验证者检查 z^2 ≡ s · c^b (mod n)。
    通过先选随机 z，再令 s = z^2 · c^{-b} mod n，可使验证始终通过。
    """

    name = "zkp_forge_proof"
    description = (
        "ZKP 零知识证明伪造工具（纯本地）。给定 n、c 和挑战比特列表 b_list，"
        "构造 (s, z) proof 对使得对每个挑战 b_i 均能通过验证 "
        "(z_i^2 ≡ s_i · c^{b_i} mod n)。支持 Rabin ZKP 协议。"
        "输出构造好的 proof 字典，可直接用于验证。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "n": {
                "type": "string",
                "description": "模数 n（十进制或 0x 十六进制）",
            },
            "c": {
                "type": "string",
                "description": "承诺值 c（整数，十进制或 0x 十六进制）",
            },
            "b_list": {
                "type": "array",
                "items": {"type": "integer"},
                "description": "挑战比特列表，如 [0, 1, 0, 1]",
            },
            "s_list": {
                "type": "array",
                "items": {"type": "string"},
                "description": "可选预设 s 值列表（十进制或 0x 十六进制）。"
                "若提供，则基于 s 构造 z；否则随机选 z 推导 s。",
            },
        },
        "required": ["n", "c", "b_list"],
    }

    def execute(self, **kwargs: Any) -> str:
        n = _to_int(kwargs.get("n"))
        c = _to_int(kwargs.get("c"))
        b_list = kwargs.get("b_list")
        s_list_raw = kwargs.get("s_list") or []

        if n is None:
            return "ERROR: 需要提供参数 n"
        if c is None:
            return "ERROR: 需要提供参数 c"
        if not isinstance(b_list, list) or not b_list:
            return "ERROR: 需要提供非空挑战列表 b_list"
        if not all(b in (0, 1) for b in b_list):
            return "ERROR: b_list 元素必须为 0 或 1"

        rounds = len(b_list)
        s_list = [_to_int(v) for v in s_list_raw if _to_int(v) is not None]

        # 尝试求 c 模 n 的逆元（可能失败是因为 c 与 n 不互质，但概率极低）
        try:
            c_inv = pow(c, -1, n)
        except ValueError:
            return "ERROR: c 在模 n 下不可逆（gcd(c,n) ≠ 1），无法构造 proof"

        proof: dict[str, list[dict[str, Any]]] = {"rounds": []}
        report: list[str] = []
        report.append(f"n = {n}")
        report.append(f"c = {c}")
        report.append(f"挑战比特序列: {b_list}")
        report.append("")

        for i in range(rounds):
            b = b_list[i]
            # 构造策略：若提供了 s_i 则基于 s_i 算 z_i；否则随机选 z_i 反推 s_i
            if i < len(s_list):
                # 给定 s_i，需解 z_i^2 ≡ s_i · c^b (mod n) → z_i = sqrt(s_i · c^b mod n)
                # 模 n 下开平方一般不可行（需要分解 n），此处尝试小整数开方 / 已知平方根
                target = (s_list[i] * pow(c, b, n)) % n
                # 尝试小整数搜索（平方根 < 2^24）
                z = None
                for candidate in range(2, min(1 << 24, n)):
                    if (candidate * candidate) % n == target:
                        z = candidate
                        break
                if z is None:
                    report.append(
                        f"  Round {i + 1}: 给定 s[{i}] 无法在合理范围内开平方，"
                        f"改用随机 z 构造"
                    )
                    # 退化：随机选 z 并重算 s
                    zi = int.from_bytes(os.urandom(max(1, n.bit_length() // 8)), "big") % n
                    if zi == 0:
                        zi = 1
                    si = (zi * zi * pow(c_inv, b, n)) % n
                    proof["rounds"].append({
                        "index": i,
                        "b": b,
                        "s": hex(si),
                        "z": hex(zi),
                        "method": "random_z_derive_s",
                    })
                    report.append(f"  Round {i + 1}: z(n/a) → s = {hex(si)}")
                else:
                    proof["rounds"].append({
                        "index": i,
                        "b": b,
                        "s": hex(s_list[i]),
                        "z": hex(z),
                        "method": "given_s_compute_z",
                    })
                    report.append(f"  Round {i + 1}: z = {hex(z)} (based on given s)")
                continue

            # 随机选 zi，计算 si = zi^2 * c^{-b} mod n
            zi = int.from_bytes(os.urandom(max(1, n.bit_length() // 8)), "big") % n
            if zi == 0:
                zi = 1
            si = (zi * zi * pow(c_inv, b, n)) % n

            # 验证：z_i^2 ≡ s_i · c^b (mod n)
            lhs = (zi * zi) % n
            rhs = (si * pow(c, b, n)) % n
            assert lhs == rhs, "内部构造不一致！"

            proof["rounds"].append({
                "index": i,
                "b": b,
                "s": hex(si),
                "z": hex(zi),
                "method": "random_z_derive_s",
            })
            report.append(
                f"  Round {i + 1}: b={b}, z={hex(zi)[:20]}..., s={hex(si)[:20]}..."
            )

        # 验证全通过
        ok = 0
        for r in proof["rounds"]:
            lhs = (int(r["z"], 16) ** 2) % n
            rhs = (int(r["s"], 16) * pow(c, r["b"], n)) % n
            if lhs == rhs:
                ok += 1

        report.append("")
        report.append(f"验证通过: {ok}/{rounds} 轮")
        details = {
            "success": ok == rounds,
            "proof": proof,
            "n": hex(n),
            "c": hex(c),
            "rounds_total": rounds,
            "rounds_passed": ok,
        }
        return _truncate("\n".join(report)) + f"\n\n[details]\n{details}"


# ============================================================
# 2. OTPXorAnalyzeTool — OTP 密钥重用分析
# ============================================================

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """按字节 XOR，短的一方补齐（重复短序列用于密钥恢复场景）。"""
    max_len = max(len(a), len(b))
    # 若一方较短，说明可能是密钥，需要循环补齐
    result = bytearray()
    for i in range(max_len):
        ba = a[i % len(a)] if a else 0
        bb = b[i % len(b)] if b else 0
        result.append(ba ^ bb)
    return bytes(result)


def _score_plaintext(text: bytes) -> float:
    """基于字母频率给明文打分（越高越像英文文本）。"""
    if not text:
        return 0.0
    score = 0.0
    for b in text:
        ch = chr(b)
        if "a" <= ch <= "z":
            score += 1.0
        elif "A" <= ch <= "Z":
            score += 0.8
        elif ch == " ":
            score += 0.5
        elif 32 <= b <= 126:
            score += 0.2
        else:
            score -= 0.5
    return score / len(text)


def _recover_otp_key(ciphertexts: list[bytes]) -> bytes:
    """通过多密文 XOR 交叉分析恢复 OTP 密钥（假设明文为英文 ASCII）。"""
    if not ciphertexts:
        return b""
    min_len = min(len(ct) for ct in ciphertexts)
    key = bytearray(min_len)
    for pos in range(min_len):
        # 收集当前位置所有密文字节
        ct_bytes = [ct[pos] for ct in ciphertexts]
        best_key_byte = 0
        best_score = -1.0
        # 尝试所有可能的密钥字节
        for k in range(256):
            plaintexts = [b ^ k for b in ct_bytes]
            # 如果所有解密结果都是可打印 ASCII 或空格，则加分
            score = sum(1 for p in plaintexts if 32 <= p <= 126 or p in (9, 10, 13))
            score -= sum(1 for p in plaintexts if p == 0)  # 全零不太可能
            if score > best_score:
                best_score = score
                best_key_byte = k
        key[pos] = best_key_byte
    return bytes(key)


def _detect_key_length(ciphertexts: list[bytes], max_len: int = 64) -> int | None:
    """通过重合指数检测可能的密钥长度（OTP 密钥重用场景）。"""
    if len(ciphertexts) < 2:
        return None
    min_len = min(len(c) for c in ciphertexts)
    best_len = 1
    best_score = 0.0
    for key_len in range(1, min(max_len + 1, min_len)):
        # 把密文拼起来，每隔 key_len 取一个字节算重合指数
        concat = b"".join(ciphertexts)
        # 取第一个密文的前 min_len 字节，按 key_len 分组算重合指数
        sample = ciphertexts[0][:min_len]
        if len(sample) < key_len * 2:
            continue
        # 计算每个组内的重合指数均值
        scores = []
        for offset in range(key_len):
            group = bytes(sample[offset::key_len])
            if len(group) < 2:
                continue
            freq = Counter(group)
            n = len(group)
            ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
            scores.append(ic)
        if scores:
            avg_ic = sum(scores) / len(scores)
            # 英文重合指数约 0.065，随机约 0.038
            if avg_ic > best_score:
                best_score = avg_ic
                best_len = key_len
    return best_len if best_score > 0.05 else None


def _png_frame_xor_analysis(file_path: str) -> str:
    """对多帧 PNG 进行 OTP 分析（每帧被同一密钥 XOR 加密）。"""
    report_parts: list[str] = []
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return f"文件不存在: {file_path}"
    except Exception as e:
        return f"读取文件失败: {e}"

    # 查找 PNG 帧边界（PNG magic: 89 50 4E 47 0D 0A 1A 0A）
    png_magic = b"\x89PNG\r\n\x1a\n"
    frames: list[bytes] = []
    start = 0
    while True:
        pos = data.find(png_magic, start)
        if pos == -1:
            break
        # 找下一帧或文件尾
        next_pos = data.find(png_magic, pos + 1)
        if next_pos == -1:
            frames.append(data[pos:])
        else:
            frames.append(data[pos:next_pos])
        start = pos + 1
        if next_pos == -1:
            break

    if len(frames) < 2:
        report_parts.append(f"发现 {len(frames)} 个 PNG 帧（至少需要 2 帧用于 XOR 分析）")
        return "\n".join(report_parts)

    report_parts.append(f"发现 {len(frames)} 个 PNG 帧")

    # 帧间 XOR 叠加（去除 PNG 头）
    ihdr_magic = b"IHDR"  # PNG IHDR 块标识
    min_len = min(len(f) for f in frames)
    # 截去 PNG 文件头（前 8 字节 magic + IHDR 块）
    header_len = 8  # PNG magic
    # 跳过各帧头部，从图像数据开始 XOR
    # 找到第一个帧的 IDAT 或图像数据起始位置
    data_starts = []
    for f in frames:
        # 找 IEND 块之后的位置（或者直接跳过固定头部）
        iend = f.find(b"IEND")
        if iend != -1:
            data_starts.append(iend + 8)
        else:
            data_starts.append(header_len)
    # 取最小公共数据起始点
    common_start = min(data_starts)
    # 帧间两两 XOR
    xor_results = []
    for i in range(len(frames)):
        for j in range(i + 1, len(frames)):
            a = frames[i][common_start:]
            b = frames[j][common_start:]
            xored = _xor_bytes(a, b)
            # 检查 XOR 结果中是否有明显的结构（非随机）
            entropy = _estimate_entropy(xored[:min(1024, len(xored))])
            xor_results.append((i, j, entropy, xored))

    # 按熵排序（熵越低越有结构）
    xor_results.sort(key=lambda x: x[2])
    report_parts.append("\n帧间 XOR 分析（按结构强度排序）：")
    for i, j, ent, xored in xor_results[:5]:
        report_parts.append(
            f"  帧 {i} XOR 帧 {j}: 熵值 {ent:.3f} (越低越有结构), "
            f"首 32 字节: {xored[:32].hex()}"
        )
        # 检测是否有明显的 PNG 结构残留
        if xored[:4] == b"\x89PNG" or b"PNG" in xored[:64]:
            report_parts.append(f"  ⚠ 发现 PNG 结构残留！可能存在帧间 XOR 恢复可能")

    return "\n".join(report_parts)


def _estimate_entropy(data: bytes) -> float:
    """估计字节序列的熵（0-8）。"""
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


class OTPXorAnalyzeTool(Tool):
    """OTP 密钥重用分析工具：多密文 XOR 交叉分析恢复密钥与明文."""

    name = "otp_xor_analyze"
    description = (
        "OTP 一次性密码本密钥重用分析工具（纯本地）。分析多个用同一密钥加密的密文，"
        "通过交叉 XOR 恢复密钥和明文。支持文本密文（hex/base64）和 "
        "PNG 多帧图像 OTP 分析。输出恢复的密钥和明文候选。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "ciphertexts": {
                "type": "array",
                "items": {"type": "string"},
                "description": "密文字符串列表（hex 编码或 base64 编码）",
            },
            "encoding": {
                "type": "string",
                "enum": ["hex", "base64", "raw"],
                "description": "密文编码方式，默认自动检测",
            },
            "file_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "密文文件路径列表（与 ciphertexts 二选一）",
            },
            "image_mode": {
                "type": "boolean",
                "description": "是否启用 PNG 多帧图像 XOR 分析模式",
            },
        },
    }

    def execute(self, **kwargs: Any) -> str:
        ciphertexts_raw = kwargs.get("ciphertexts") or []
        file_paths = kwargs.get("file_paths") or []
        encoding = kwargs.get("encoding") or "auto"
        image_mode = kwargs.get("image_mode") or False

        # 收集密文字节
        ciphertext_bytes: list[bytes] = []

        if file_paths:
            for fp in file_paths:
                if image_mode:
                    # PNG 多帧分析
                    result = _png_frame_xor_analysis(fp)
                    # 也尝试读取文件内容作为密文
                    try:
                        with open(fp, "rb") as f:
                            ciphertext_bytes.append(f.read())
                    except Exception:
                        pass
                    if not ciphertext_bytes:
                        return _truncate(result)
                else:
                    try:
                        with open(fp, "rb") as f:
                            raw = f.read().strip()
                        ciphertext_bytes.append(raw)
                    except FileNotFoundError:
                        return f"ERROR: 文件不存在: {fp}"
                    except Exception as e:
                        return f"ERROR: 读取文件失败 {fp}: {e}"

        if ciphertexts_raw:
            for ct in ciphertexts_raw:
                ct = ct.strip()
                if not ct:
                    continue
                if encoding == "hex" or (encoding == "auto" and re.match(r"^[0-9a-fA-F]+$", ct)):
                    try:
                        ciphertext_bytes.append(bytes.fromhex(ct))
                    except ValueError:
                        ciphertext_bytes.append(ct.encode("latin-1"))
                elif encoding == "base64" or (encoding == "auto" and re.match(
                        r"^[A-Za-z0-9+/=]+$", ct)):
                    try:
                        ciphertext_bytes.append(base64.b64decode(ct))
                    except binascii.Error:
                        ciphertext_bytes.append(ct.encode("latin-1"))
                else:
                    ciphertext_bytes.append(ct.encode("latin-1"))

        if len(ciphertext_bytes) < 2:
            return "ERROR: 至少需要 2 个密文用于 XOR 分析"

        report: list[str] = []
        report.append(f"密文数量: {len(ciphertext_bytes)}")
        report.append(f"各密文长度: {[len(c) for c in ciphertext_bytes]}")

        # 1) 检测密钥长度
        key_len = _detect_key_length(ciphertext_bytes)
        if key_len and key_len > 1 and key_len < min(len(c) for c in ciphertext_bytes):
            report.append(f"[检测] 可能密钥长度: {key_len}（基于重合指数）")
        else:
            report.append("[检测] 密钥长度检测：未发现明显周期性（可能密钥等长或为随机）")

        # 2) 恢复密钥
        key = _recover_otp_key(ciphertext_bytes)
        report.append(f"[密钥] 恢复的密钥 (hex): {key.hex()}")

        # 3) 解密
        plaintext_candidates: list[str] = []
        for i, ct in enumerate(ciphertext_bytes):
            pt = _xor_bytes(ct, key)
            score = _score_plaintext(pt)
            try:
                pt_text = pt.decode("utf-8", errors="replace")
            except Exception:
                pt_text = pt.decode("latin-1", errors="replace")
            flag = _FLAG_RE.search(pt_text)
            marker = " ⚑ FLAG" if flag else ""
            if score > 0.5 or flag:
                plaintext_candidates.append(
                    f"  密文 {i}: 评分 {score:.2f}{marker}\n    {pt_text[:200]}"
                )
            report.append(
                f"  密文 {i}: 评分 {score:.2f}{marker}"
            )

        # 4) 两两 XOR 分析
        report.append("\n[两两 XOR 分析] 交叉 XOR 结果（前 64 字节）：")
        for i in range(min(3, len(ciphertext_bytes))):
            for j in range(i + 1, min(4, len(ciphertext_bytes))):
                xored = _xor_bytes(ciphertext_bytes[i], ciphertext_bytes[j])
                ent = _estimate_entropy(xored[:min(256, len(xored))])
                report.append(f"  CT{i} XOR CT{j}: 熵值 {ent:.3f}")
                # 如果熵值很低，说明有大量可打印字符
                if ent < 4.0:
                    printable = sum(32 <= b <= 126 for b in xored[:min(256, len(xored))])
                    report.append(f"    可打印字符占比: {printable}/{min(256, len(xored))}")

        details = {
            "success": bool(plaintext_candidates),
            "key_hex": key.hex(),
            "key_length": len(key),
            "ciphertext_count": len(ciphertext_bytes),
            "plaintext_candidates": plaintext_candidates[:5],
        }
        return _truncate("\n".join(report)) + f"\n\n[details]\n{details}"


# ============================================================
# 3. AESSidechannelTool — AES 侧信道/后门分析
# ============================================================

# AES S-box 标准值（用于比较）
_AES_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

# AES 逆 S-box 标准值
_AES_INV_SBOX = [0] * 256
for i, v in enumerate(_AES_SBOX):
    _AES_INV_SBOX[v] = i

# AES 轮常量 (Rcon)
_AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _extract_integer_array(source: str, array_name: str) -> list[int] | None:
    """从源码字符串中提取整数数组（如 SBox, InvSBox, Rcon 等）。"""
    # 匹配形如 SBox = [...] 或 SBOX = [...] 或 sbox = [...] 的数组定义
    patterns = [
        rf"{array_name}\s*=\s*\[([^\]]+(?:\[[^\]]*\][^\]]*)*)\]",
        rf"{array_name}\s*=\s*\(([^\)]+)\)",
    ]
    for pat in patterns:
        m = re.search(pat, source, re.IGNORECASE | re.DOTALL)
        if m:
            arr_str = m.group(1)
            # 提取所有整数
            nums = re.findall(r"0x[0-9a-fA-F]+|\d+", arr_str)
            if nums:
                return [int(x, 0) for x in nums]
    return None


def _extract_key_schedule(source: str) -> list[list[int]] | None:
    """从源码中提取密钥调度表（RoundKeys / w 数组）。"""
    # 匹配 2D 数组
    m = re.search(r"(?:RoundKeys?|w|round_keys?)\s*=\s*\[", source, re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    # 找到对应的 ] 闭合
    start = m.end() - 1  # 回到 [
    depth = 1
    i = start + 1
    while i < len(source) and depth > 0:
        if source[i] == "[":
            depth += 1
        elif source[i] == "]":
            depth -= 1
        i += 1
    if depth != 0:
        return None
    arr_text = source[start:i]
    # 提取所有子数组
    rows: list[list[int]] = []
    for row_match in re.finditer(r"\[([^\]]+)\]", arr_text):
        nums = re.findall(r"0x[0-9a-fA-F]+|\d+", row_match.group(1))
        if nums:
            rows.append([int(x, 0) for x in nums])
    return rows if rows else None


def _analyze_sbox(sbox: list[int]) -> list[str]:
    """分析 S-box 的异常特征。"""
    findings: list[str] = []

    if len(sbox) != 256:
        findings.append(f"⚠ S-box 长度异常: {len(sbox)}（标准应为 256）")
        return findings

    # 检查是否与标准 AES S-box 一致
    if sbox == _AES_SBOX:
        findings.append("✓ S-box 为标准 AES S-box，无异常")
        return findings

    findings.append("⚠ S-box 与标准 AES S-box 不同，可能为自定义实现")

    # 1) 检查是否双射
    if len(set(sbox)) != 256:
        duplicates = [v for v, c in Counter(sbox).items() if c > 1]
        findings.append(f"⚠ S-box 非双射！重复值: {duplicates[:10]}")
    else:
        findings.append("✓ S-box 是双射")

    # 2) 检查不动点 (S[x] == x)
    fixed_points = [i for i in range(256) if sbox[i] == i]
    if fixed_points:
        findings.append(f"⚠ 发现不动点 (S[x]=x): {fixed_points[:20]}")
    else:
        findings.append("✓ 无不动点")

    # 3) 检查反不动点 (S[x] == ~x 或 S[x] == 255-x)
    anti_fixed = [i for i in range(256) if sbox[i] == (255 - i)]
    if anti_fixed:
        findings.append(f"⚠ 发现反不动点 (S[x]=255-x): {anti_fixed[:20]}")

    # 4) 检查代数次数（线性逼近）
    linear_bias = 0.0
    for a in range(1, 256):
        for b in range(1, 256):
            count = 0
            for x in range(256):
                x_in = bin(x & a).count("1") % 2
                x_out = bin(sbox[x] & b).count("1") % 2
                if x_in == x_out:
                    count += 1
            bias = abs(count - 128) / 256
            if bias > linear_bias:
                linear_bias = bias
    findings.append(f"  最大线性偏差: {linear_bias:.4f}（标准 AES ~0.0625）")
    if linear_bias > 0.1:
        findings.append("⚠ 线性偏差偏大，可能易受线性密码分析攻击")

    # 5) 检查差分均匀性
    max_diff = 0
    for dx in range(1, 256):
        for dy in range(1, 256):
            count = 0
            for x in range(256):
                if sbox[x] ^ sbox[x ^ dx] == dy:
                    count += 1
            if count > max_diff:
                max_diff = count
    findings.append(f"  最大差分概率: {max_diff}/256（标准 AES 为 4/256）")
    if max_diff > 16:
        findings.append("⚠ 差分均匀性差，可能易受差分密码分析攻击")

    # 6) 检查是否包含 0x00 或 0xFF 等特殊值位置
    if sbox[0] != _AES_SBOX[0]:
        findings.append(f"⚠ S-box[0] = 0x{sbox[0]:02x}（标准为 0x{_AES_SBOX[0]:02x}）")

    return findings


def _analyze_key_schedule(round_keys: list[list[int]] | None) -> list[str]:
    """分析密钥调度的异常。"""
    findings: list[str] = []
    if round_keys is None:
        findings.append("  - 未在源码中找到密钥调度表，跳过密钥调度分析")
        return findings

    # 检查轮数
    num_rounds = len(round_keys)
    if num_rounds < 10:
        findings.append(f"⚠ 密钥调度轮数异常: {num_rounds}（标准 AES-128 为 10+1=11 轮）")
    elif num_rounds > 14:
        findings.append(f"⚠ 密钥调度轮数异常: {num_rounds}（标准 AES-256 为 14+1=15 轮）")
    else:
        findings.append(f"✓ 密钥调度轮数: {num_rounds} 轮（含初始轮）")

    # 检查轮密钥长度
    if round_keys and len(round_keys[0]) != 16:
        findings.append(f"⚠ 轮密钥长度: {len(round_keys[0])} 字节（标准为 16 字节）")

    # 检查是否存在重复轮密钥（后门特征）
    key_strs = ["".join(f"{b:02x}" for b in rk) for rk in round_keys]
    dupes = [ks for ks, cnt in Counter(key_strs).items() if cnt > 1]
    if dupes:
        findings.append(f"⚠ 发现重复轮密钥！可能为后门: {dupes[:5]}")

    # 检查所有轮密钥是否相同（严重后门）
    if len(set(key_strs)) == 1 and len(round_keys) > 1:
        findings.append("⚠ 严重：所有轮密钥完全相同！这可能是故意的后门")

    # 检查轮密钥间是否有简单的线性关系
    for i in range(1, min(len(round_keys), 5)):
        xor_result = bytes(a ^ b for a, b in zip(round_keys[i], round_keys[i - 1]))
        if all(b == xor_result[0] for b in xor_result):
            findings.append(
                f"⚠ 轮密钥 {i} 与 {i - 1} 的 XOR 为常数字节 0x{xor_result[0]:02x}，"
                f"可能存在简单线性关系"
            )

    return findings


def _analyze_timing_aspects(source: str) -> list[str]:
    """分析源码中是否存在时序侧信道泄露点。"""
    findings: list[str] = []
    timing_patterns = [
        (r"time\s*\.\s*sleep", "包含 time.sleep 调用，可能引入时序依赖"),
        (r"for\s+\w+\s+in\s+range\s*\(\s*[^{}]+\w+", "循环次数依赖变量，可能产生时序差异"),
        (r"while\s+[^{}]*[<>!=]", "while 条件含比较，可能产生时序差异"),
        (r"if\s+[^{}]*==\s*[^{}]*\w+", "条件分支含 == 比较，可能侧信道泄露"),
        (r"if\s+[^{}]*!=\s*[^{}]*\w+", "条件分支含 != 比较，可能侧信道泄露"),
        (r"secret\s*=|key\s*=", "变量名含 secret/key，可能涉及敏感数据"),
        (r"cmp\s*\(|compare\s*\(", "比较函数调用，可能产生时序差异"),
    ]
    for pat, desc in timing_patterns:
        if re.search(pat, source, re.IGNORECASE):
            findings.append(f"  - 可能侧信道: {desc}")
    return findings


def _analyze_block_cipher_mode(source: str) -> list[str]:
    """分析分组密码模式是否存在弱点。"""
    findings: list[str] = []
    # ECB 模式检测
    if re.search(r"ECB|ecb_mode|\bAES\.MODE_ECB\b", source):
        findings.append("⚠ 使用 ECB 模式：相同明文块产生相同密文块，不适合加密 >16 字节的数据")
    # CBC 模式 IV 固定
    if re.search(r"CBC|AES\.MODE_CBC\b", source):
        if re.search(r"iv\s*=\s*0\b|iv\s*=\s*[0\'\"]|iv\s*=\s*b\'\s*\\x00", source, re.IGNORECASE):
            findings.append("⚠ CBC 模式 IV 固定为全零，违反安全要求")
    # CTR 模式 nonce 重用
    if re.search(r"CTR|AES\.MODE_CTR\b", source):
        if re.search(r"nonce\s*=\s*0\b|nonce\s*=\s*[\'\"]0*[\'\"]", source, re.IGNORECASE):
            findings.append("⚠ CTR 模式 nonce 固定为 0，可能导致密钥流重用")
    return findings


class AESSidechannelTool(Tool):
    """AES 侧信道/后门分析工具：检测实现中的异常与泄露."""

    name = "aes_sidechannel"
    description = (
        "AES 侧信道/后门分析工具（纯本地）。输入 AES Python 实现源码字符串，"
        "自动检测：S-box 异常（不动点、线性偏差、差分均匀性等）、"
        "密钥调度后门（重复轮密钥、线性关系等）、时序侧信道泄露、"
        "分组模式弱点。输出检测到的异常和可能的攻击路径。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "source": {
                "type": "string",
                "description": "AES Python 实现源码字符串",
            },
            "source_file": {
                "type": "string",
                "description": "AES 源码文件路径（与 source 二选一）",
            },
        },
    }

    def execute(self, **kwargs: Any) -> str:
        source = kwargs.get("source") or ""
        source_file = kwargs.get("source_file") or ""

        if source_file:
            try:
                with open(source_file, "r", encoding="utf-8") as f:
                    source = f.read()
            except FileNotFoundError:
                # Sprint 37: 文件在容器内时, 尝试 docker exec 读取
                import subprocess as _sp
                _docker_src = ""
                for _name in ["ctf_agent", "kali", "agent"]:
                    try:
                        _r = _sp.run(
                            ["docker", "exec", _name, "cat", source_file],
                            capture_output=True, text=True, timeout=5
                        )
                        if _r.returncode == 0 and _r.stdout:
                            _docker_src = _r.stdout
                            break
                    except Exception:
                        continue
                if _docker_src:
                    source = _docker_src
                else:
                    return (
                        f"ERROR: 文件不存在: {source_file}。"
                        "提示: 文件在解题容器内, 请先用 ssh_exec/ssh_python 读取文件, "
                        "再用 source 参数传入源码字符串 (而非 source_file 路径参数)。"
                    )
            except Exception as e:
                return f"ERROR: 读取文件失败: {e}"

        if not source.strip():
            return "ERROR: 需要提供 AES 源码（source 或 source_file）"

        report: list[str] = []
        report.append("=" * 50)
        report.append("AES 实现安全分析报告")
        report.append("=" * 50)

        # 1) S-box 分析
        report.append("\n[1] S-box 分析")
        sbox = _extract_integer_array(source, "sbox") or _extract_integer_array(source, "s_box")
        if sbox:
            report.extend("  " + f for f in _analyze_sbox(sbox))
        else:
            report.append("  - 未提取到 S-box 定义（可能为动态生成或使用标准库）")

        # 2) 密钥调度分析
        report.append("\n[2] 密钥调度分析")
        round_keys = _extract_key_schedule(source)
        if round_keys:
            report.extend("  " + f for f in _analyze_key_schedule(round_keys))
        else:
            report.append("  - 未提取到密钥调度表，尝试分析密钥派生逻辑")
            if re.search(r"key_expansion|KeyExpansion|expand_key", source, re.IGNORECASE):
                report.append("  - 发现密钥扩展函数，但未提取到具体值（需运行时分析）")

        # 3) 时序侧信道检测
        report.append("\n[3] 时序侧信道检测")
        timing_findings = _analyze_timing_aspects(source)
        if timing_findings:
            report.extend(timing_findings)
        else:
            report.append("  - 未发现明显时序侧信道泄露点")

        # 4) 分组模式分析
        report.append("\n[4] 分组密码模式分析")
        mode_findings = _analyze_block_cipher_mode(source)
        if mode_findings:
            report.extend(mode_findings)
        else:
            report.append("  - 未发现明显模式弱点")

        # 5) 其他后门检测
        report.append("\n[5] 其他后门/异常检测")
        other_findings: list[str] = []

        # 硬编码密钥
        key_patterns = re.findall(r"(?:key|secret|password)\s*=\s*[\"']([a-fA-F0-9]{32,64})[\"']",
                                  source, re.IGNORECASE)
        if key_patterns:
            other_findings.append(f"⚠ 发现硬编码密钥: {key_patterns[0][:20]}...")

        # 检查是否修改了轮数
        if re.search(r"n_r\s*=\s*\d+|nr\s*=\s*\d+|num_rounds\s*=\s*\d+", source, re.IGNORECASE):
            rounds_match = re.search(r"=\s*(\d+)", re.search(
                r"n_r\s*=\s*\d+|nr\s*=\s*\d+|num_rounds\s*=\s*\d+", source, re.IGNORECASE
            ).group(0))
            if rounds_match:
                nr = int(rounds_match.group(1))
                if nr < 10:
                    other_findings.append(f"⚠ 轮数异常: {nr}（标准 AES-128 为 10 轮）")

        # 检查是否包含后门函数
        backdoor_funcs = ["backdoor", "bypass", "debug_key", "master_key", "magic"]
        for func in backdoor_funcs:
            if re.search(rf"def\s+\w*{func}\w*\s*\(", source, re.IGNORECASE):
                other_findings.append(f"⚠ 发现疑似后门函数: {func}")

        # 检查是否修改了列混合(MixColumns)矩阵
        if re.search(r"mix_column|MixColumn|mix_column", source, re.IGNORECASE):
            if re.search(r"2\s*,\s*3\s*,\s*1\s*,\s*1", source):
                other_findings.append("  - 列混合矩阵为标准 AES 矩阵")
            else:
                other_findings.append("⚠ 列混合矩阵非常规！可能为自定义实现")

        if other_findings:
            report.extend("  " + f for f in other_findings)
        else:
            report.append("  - 未发现明显后门")

        # 汇总
        report.append("\n" + "=" * 50)
        total_warnings = sum(1 for f in report if f.startswith("  ⚠"))
        if total_warnings > 0:
            report.append(f"发现 {total_warnings} 个异常/警告，建议进一步分析")
        else:
            report.append("✓ 未发现明显异常（基于静态分析）")

        details = {
            "success": True,
            "warnings": total_warnings,
            "sbox_analyzed": sbox is not None,
            "key_schedule_analyzed": round_keys is not None,
        }
        return _truncate("\n".join(report)) + f"\n\n[details]\n{details}"


# ============================================================
# 4. HashCollisionTool — 哈希碰撞检测
# ============================================================

# MD5 初始向量
_MD5_IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

# SHA-1 初始向量
_SHA1_IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]


def _md5_pad(msg: bytes) -> bytes:
    """MD5 填充（Merkle-Damgård 风格）。"""
    mlen = len(msg)
    pad = bytearray()
    pad.extend(msg)
    pad.append(0x80)
    while (len(pad) % 64) != 56:
        pad.append(0x00)
    pad.extend((mlen * 8).to_bytes(8, "little"))
    return bytes(pad)


def _sha1_pad(msg: bytes) -> bytes:
    """SHA-1 填充（Merkle-Damgård 风格）。"""
    mlen = len(msg)
    pad = bytearray()
    pad.extend(msg)
    pad.append(0x80)
    while (len(pad) % 64) != 56:
        pad.append(0x00)
    pad.extend((mlen * 8).to_bytes(8, "big"))
    return bytes(pad)


def _detect_hash_function(source: str) -> str | None:
    """从源码中检测哈希函数类型。"""
    patterns = {
        "MD5": r"md5|MD5|md_5|MD_5",
        "SHA-1": r"sha1|SHA1|sha_1|SHA_1",
        "SHA-256": r"sha256|SHA256|sha_256|SHA_256",
        "SHA-512": r"sha512|SHA512",
        "SHA-3": r"sha3|SHA3|sha_3|SHA_3",
        "BLAKE": r"blake|BLAKE",
        "SHAKE": r"shake|SHAKE",
        "SM3": r"sm3|SM3",
    }
    for name, pat in patterns.items():
        if re.search(pat, source, re.IGNORECASE):
            return name
    return None


def _check_md5_collision_susceptibility(source: str) -> list[str]:
    """检测 MD5 碰撞攻击的可行性。"""
    findings: list[str] = []
    # 检查是否使用了不安全的分组模式
    if re.search(r"MD5|md5", source, re.IGNORECASE):
        findings.append("MD5 已知存在碰撞攻击（2004 年王小云等），建议使用 SHA-256 或更高")
    # 检查是否使用自定义初始向量
    iv = _extract_integer_array(source, "iv") or _extract_integer_array(source, "IV")
    if iv and len(iv) == 4:
        if iv != _MD5_IV:
            findings.append(f"⚠ 自定义 MD5 初始向量: {[hex(x) for x in iv]}")
        else:
            findings.append("  MD5 初始向量为标准值")
    return findings


def _check_sha1_collision_susceptibility(source: str) -> list[str]:
    """检测 SHA-1 碰撞攻击的可行性。"""
    findings: list[str] = []
    if re.search(r"SHA1|sha1", source, re.IGNORECASE):
        findings.append("SHA-1 已知存在碰撞攻击（SHAttered, 2017），建议使用 SHA-256")
    iv = _extract_integer_array(source, "iv") or _extract_integer_array(source, "IV")
    if iv and len(iv) == 5:
        if iv != _SHA1_IV:
            findings.append(f"⚠ 自定义 SHA-1 初始向量: {[hex(x) for x in iv]}")
        else:
            findings.append("  SHA-1 初始向量为标准值")
    return findings


def _check_length_extension(source: str | None, hash_value: str | None) -> list[str]:
    """检测哈希长度扩展攻击可行性。"""
    findings: list[str] = []
    if source:
        # 检查是否使用了 Merkle-Damgård 结构
        if re.search(r"compress|block_size|padding|Merkle|Damgard", source, re.IGNORECASE):
            findings.append("Merkle-Damgård 结构：可能易受长度扩展攻击")
            # 检测具体类型
            hf = _detect_hash_function(source)
            if hf in ("MD5", "SHA-1", "SHA-256", "SHA-512"):
                findings.append(f"  {hf} 基于 Merkle-Damgård 结构，存在长度扩展风险")
    if hash_value:
        hlen = len(hash_value.replace("0x", "").replace(" ", ""))
        if hlen in (32, 40, 64, 128):  # MD5=32, SHA1=40, SHA256=64, SHA512=128
            findings.append(
                f"  哈希值长度 {hlen} hex 字符，符合 MD5/SHA-1/SHA-256/SHA-512 特征"
            )
    return findings


def _analyze_merkle_damgard(source: str) -> list[str]:
    """分析 Merkle-Damgård 结构的具体实现。"""
    findings: list[str] = []
    # 查找压缩函数
    if re.search(r"compress|compression|F\s*\(|f\s*\(", source, re.IGNORECASE):
        findings.append("  发现压缩函数定义")
    # 查找填充逻辑
    if re.search(r"pad|padding|0x80", source, re.IGNORECASE):
        findings.append("  发现填充逻辑")
    # 查找状态链接
    if re.search(r"state|hash\s*=|h\d+\s*=", source, re.IGNORECASE):
        findings.append("  发现状态链接变量")
    # 检测是否使用了 HAIFA 或 Sponge 结构（抗长度扩展）
    if re.search(r"sponge|Sponge|HAIFA|haifa|salted|salt", source, re.IGNORECASE):
        findings.append("  可能使用 Sponge/HAIFA 结构，不直接受长度扩展攻击影响")
    return findings


def _hash_length_extension_attack(
    hash_type: str,
    known_hash: str,
    known_data: str,
    append_data: str,
) -> str:
    """构造哈希长度扩展攻击的 payload（仅辅助分析，不实际执行攻击）。"""
    parts: list[str] = []
    parts.append(f"[辅助分析] 哈希长度扩展攻击参数:")
    parts.append(f"  类型: {hash_type}")
    parts.append(f"  已知哈希: {known_hash}")
    parts.append(f"  已知数据: {known_data[:50]}...")
    parts.append(f"  附加数据: {append_data[:50]}...")

    # 计算填充后的数据长度
    if hash_type.upper() in ("MD5",):
        # MD5 长度扩展
        known_len = len(known_data.encode("utf-8"))
        padded = _md5_pad(known_data.encode("utf-8"))
        total_len = len(padded) + len(append_data)
        parts.append(f"  已知数据填充后长度: {len(padded)} 字节")
        parts.append(f"  攻击后总长度: {total_len} 字节")
        parts.append(f"  构造的 payload: {padded.hex()[:64]}... + {append_data}")
        parts.append(f"  注意：实际攻击需在容器中执行（ssh_python）")
    elif hash_type.upper() in ("SHA-1", "SHA-256", "SHA-512"):
        known_len = len(known_data.encode("utf-8"))
        padded = _sha1_pad(known_data.encode("utf-8"))
        total_len = len(padded) + len(append_data)
        parts.append(f"  已知数据填充后长度: {len(padded)} 字节")
        parts.append(f"  攻击后总长度: {total_len} 字节")
        parts.append(f"  构造的 payload: {padded.hex()[:64]}... + {append_data}")
    else:
        parts.append("  不支持的哈希类型，需手动分析")

    return "\n".join(parts)


class HashCollisionTool(Tool):
    """哈希碰撞检测工具：检测 MD5/SHA1 碰撞、长度扩展攻击等."""

    name = "hash_collision"
    description = (
        "哈希碰撞检测工具（纯本地）。检测哈希函数实现中的碰撞弱点、"
        "Merkle-Damgård 结构问题、长度扩展攻击可行性等。"
        "输入哈希函数源码或已知哈希值，输出碰撞攻击方法或构造的碰撞对。"
        "MD5 和 SHA-1 已知存在实际碰撞攻击，本工具辅助分析可行性。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "source": {
                "type": "string",
                "description": "哈希函数源码字符串（可选，用于深度分析）",
            },
            "source_file": {
                "type": "string",
                "description": "哈希函数源码文件路径（与 source 二选一）",
            },
            "hash_value": {
                "type": "string",
                "description": "已知哈希值（hex 字符串），用于识别类型和分析",
            },
            "known_data": {
                "type": "string",
                "description": "长度扩展攻击：已知的原始消息",
            },
            "append_data": {
                "type": "string",
                "description": "长度扩展攻击：要追加的消息",
            },
        },
    }

    def execute(self, **kwargs: Any) -> str:
        source = kwargs.get("source") or ""
        source_file = kwargs.get("source_file") or ""
        hash_value = kwargs.get("hash_value") or ""
        known_data = kwargs.get("known_data") or ""
        append_data = kwargs.get("append_data") or ""

        if source_file:
            try:
                with open(source_file, "r", encoding="utf-8") as f:
                    source = f.read()
            except FileNotFoundError:
                return f"ERROR: 文件不存在: {source_file}"
            except Exception as e:
                return f"ERROR: 读取文件失败: {e}"

        if not source.strip() and not hash_value:
            return "ERROR: 需要提供哈希函数源码（source/source_file）或哈希值（hash_value）"

        report: list[str] = []
        report.append("=" * 50)
        report.append("哈希函数安全分析报告")
        report.append("=" * 50)

        # 1) 识别哈希函数类型
        hash_type = None
        if source.strip():
            hash_type = _detect_hash_function(source)
            if hash_type:
                report.append(f"\n[1] 检测到哈希函数: {hash_type}")
            else:
                report.append(f"\n[1] 未识别到标准哈希函数，将进行通用分析")

        if hash_value:
            hlen = len(hash_value.replace("0x", "").replace(" ", "").strip())
            type_by_len = {32: "MD5", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}
            guessed = type_by_len.get(hlen, "未知")
            report.append(f"  哈希值长度: {hlen} hex 字符 → 可能类型: {guessed}")

        # 2) 碰撞可行性分析
        report.append("\n[2] 碰撞可行性分析")
        if source.strip():
            md5_findings = _check_md5_collision_susceptibility(source)
            report.extend(md5_findings)
            sha1_findings = _check_sha1_collision_susceptibility(source)
            report.extend(sha1_findings)

        if hash_value:
            hv = hash_value.strip().replace("0x", "").replace(" ", "")
            if len(hv) == 32:
                report.append("  MD5 哈希：可使用已知碰撞对（如 `md5-collision` 工具）构造碰撞")
                report.append("  参考：https://github.com/corkami/collisions 或 hashcat -m 0")
            elif len(hv) == 40:
                report.append("  SHA-1 哈希：已知 SHAttered 碰撞攻击，需约 2^63 计算量")
                report.append("  参考：https://shattered.io/")

        # 3) Merkle-Damgård 结构分析
        report.append("\n[3] Merkle-Damgård 结构分析")
        if source.strip():
            md_findings = _analyze_merkle_damgard(source)
            if md_findings:
                report.extend(md_findings)
            else:
                report.append("  - 未检测到明显的 Merkle-Damgård 结构特征")
        else:
            if hash_value:
                report.append("  - 基于哈希值长度，推测可能使用 Merkle-Damgård 结构")
            report.append("  - 提供源码可进行更详细的结构分析")

        # 4) 长度扩展攻击
        report.append("\n[4] 长度扩展攻击分析")
        ext_findings = _check_length_extension(
            source if source.strip() else None,
            hash_value if hash_value else None,
        )
        if ext_findings:
            report.extend(ext_findings)
        else:
            report.append("  - 未检测到长度扩展攻击风险")

        if known_data and append_data:
            report.append("\n[5] 长度扩展攻击构造")
            hf = hash_type or "SHA-256"
            ext_result = _hash_length_extension_attack(hf, hash_value, known_data, append_data)
            report.append(ext_result)

        # 5) 其他检测
        report.append("\n[6] 其他检测")
        if source.strip():
            # 检测自定义压缩函数
            if re.search(r"def\s+\w*[Ff]\d*\s*\(|def\s+compress\s*\(", source):
                report.append("  - 发现自定义压缩函数，需人工分析其安全性")
            # 检测是否使用随机数/salt
            if re.search(r"random|salt|nonce", source, re.IGNORECASE):
                report.append("  - 使用随机数/salt，可能抵抗部分攻击")
            # 检测输出长度
            output_match = re.search(r"digest_size|output_size|hash_size|hashlen\s*=\s*(\d+)",
                                     source, re.IGNORECASE)
            if output_match:
                dlen = int(output_match.group(1))
                report.append(f"  - 输出长度: {dlen} 位（{dlen // 2} hex 字符）")
                if dlen < 160:
                    report.append(f"  ⚠ 输出长度偏短（< 160 位），碰撞攻击可行性较高")

        details = {
            "success": True,
            "hash_type": hash_type,
            "hash_length": len(hash_value.strip()) if hash_value else None,
            "length_extension_risk": bool(ext_findings),
        }
        return _truncate("\n".join(report)) + f"\n\n[details]\n{details}"


# ============================================================
# 5. McElieceAnalyzeTool — McEliece 密码分析
# ============================================================

def _binary_matrix_rank(matrix: list[list[int]]) -> int:
    """计算二元矩阵的秩（高斯消元）。"""
    if not matrix or not matrix[0]:
        return 0
    m = [row[:] for row in matrix]
    rows = len(m)
    cols = len(m[0])
    rank = 0
    col = 0
    for r in range(rows):
        if col >= cols:
            break
        # 找 pivot
        pivot = None
        for i in range(r, rows):
            if m[i][col] == 1:
                pivot = i
                break
        if pivot is None:
            col += 1
            r -= 1  # 重试当前行
            continue
        # 交换行
        m[r], m[pivot] = m[pivot], m[r]
        # 消去其他行
        for i in range(rows):
            if i != r and m[i][col] == 1:
                for j in range(col, cols):
                    m[i][j] ^= m[r][j]
        rank += 1
        col += 1
    return rank


def _parse_mceliece_params(source: str) -> dict[str, Any]:
    """从源码或参数描述中解析 McEliece 参数。"""
    params: dict[str, Any] = {}

    # 提取 m（有限域 GF(2^m) 的扩展次数）
    m_match = re.search(r"[Mm]\s*[:=]\s*(\d+)", source)
    if m_match:
        params["m"] = int(m_match.group(1))

    # 提取 n（码长）
    n_match = re.search(r"[Nn]\s*[:=]\s*(\d+)", source)
    if n_match:
        params["n"] = int(n_match.group(1))

    # 提取 k（消息长度）
    k_match = re.search(r"[Kk]\s*[:=]\s*(\d+)", source)
    if k_match:
        params["k"] = int(k_match.group(1))

    # 提取 t（纠错能力）
    t_match = re.search(r"[Tt]\s*[:=]\s*(\d+)", source)
    if t_match:
        params["t"] = int(t_match.group(1))

    # 提取多项式
    poly_match = re.search(r"poly|polynomial|g\s*\([^)]*\)", source, re.IGNORECASE)
    if poly_match:
        params["poly_found"] = True

    # 提取公钥矩阵大小
    pk_match = re.search(r"public_key|PublicKey|pub_key|G\s*=", source, re.IGNORECASE)
    if pk_match:
        params["public_key_found"] = True
        # 尝试提取矩阵维度
        dim_match = re.search(r"shape\s*[:=]\s*\((\d+),\s*(\d+)\)", source)
        if dim_match:
            params["pk_rows"] = int(dim_match.group(1))
            params["pk_cols"] = int(dim_match.group(2))

    return params


def _analyze_goppa_code(params: dict[str, Any]) -> list[str]:
    """分析 Goppa 码参数的安全性。"""
    findings: list[str] = []
    m = params.get("m")
    n = params.get("n")
    k = params.get("k")
    t = params.get("t")

    if m:
        findings.append(f"  有限域: GF(2^{m})")
        expected_n = 2 ** m
        if n and n != expected_n:
            findings.append(f"  ⚠ 码长 n={n} ≠ 2^{m}={expected_n}，可能使用子域子码或其他变体")
        elif n:
            findings.append(f"  码长 n={n}（标准 Goppa 码: n=2^{m}={expected_n}）")

    if k and n:
        rate = k / n
        findings.append(f"  码率: {k}/{n} = {rate:.3f}")
        if rate > 0.8:
            findings.append("  ⚠ 码率偏高（>0.8），可能降低安全性")
        elif rate < 0.3:
            findings.append("  ⚠ 码率偏低（<0.3），效率可能较差")

    if t:
        findings.append(f"  纠错能力: t={t}")
        # 经典 McEliece 安全参数建议
        sec_level = "未知"
        if m and t:
            # 粗略安全估计：基于 m 和 t 的经典 McEliece 安全参数
            classic_params = {
                (11, 27): "80-bit (mceliece348864)",
                (12, 38): "128-bit (mceliece460896)",
                (13, 54): "192-bit (mceliece6688128)",
                (13, 67): "256-bit (mceliece6960119)",
                (14, 97): "256-bit (mceliece8192128)",
            }
            sec_level = classic_params.get((m, t), "非标准参数")
            findings.append(f"  估计安全强度: {sec_level}")

    if n and t:
        # 信息集解码复杂度估计
        isd_complexity = _estimate_isd_complexity(n, k or n // 2, t)
        findings.append(f"  ISD 攻击复杂度估计: 2^{isd_complexity:.1f}")

    return findings


def _estimate_isd_complexity(n: int, k: int, t: int) -> float:
    """估算信息集解码（ISD）攻击的比特复杂度（Stern's algorithm 近似）。"""
    # 经典 Stern ISD 复杂度近似：
    # cost = min_{l} (binom(n, t) * binom(n - k, l) / binom(n, k + l))
    # 简化为粗略估计
    if n <= 0 or k <= 0 or t <= 0:
        return 0.0
    try:
        import math as m
        # 非常粗略的估计
        rate = k / n
        # 基于经验公式
        bits = t * m.log2(n) * (1 - rate) * 0.5
        return max(bits, 0.0)
    except Exception:
        # 极简估计
        return t * 0.5 * (n - k) / n * 10


def _analyze_key_structure(params: dict[str, Any]) -> list[str]:
    """分析密钥结构弱点。"""
    findings: list[str] = []
    n = params.get("n")
    k = params.get("k")

    if params.get("public_key_found"):
        pk_rows = params.get("pk_rows")
        pk_cols = params.get("pk_cols")
        if pk_rows and pk_cols:
            findings.append(f"  公钥矩阵维度: {pk_rows}×{pk_cols}")
            if pk_rows < pk_cols:
                findings.append(f"  ✓ 公钥矩阵为 k×n 形式（k={pk_rows}, n={pk_cols}）")
            # 计算公钥大小
            pk_bits = pk_rows * pk_cols
            pk_bytes = pk_bits // 8
            findings.append(f"  公钥大小: ~{pk_bits} 比特（~{pk_bytes} 字节）")
            if pk_bytes < 1024:
                findings.append("  ⚠ 公钥偏小，可能易受攻击")
            elif pk_bytes > 1024 * 1024:
                findings.append("  公钥较大（>1MB），属于经典 McEliece 特征")

    # 检查是否有对称性（可能导致结构攻击）
    if params.get("poly_found"):
        findings.append("  发现多项式定义，Goppa 码结构完整")

    return findings


def _parse_ciphertext_params(source: str) -> dict[str, Any]:
    """解析密文/公钥参数。"""
    params: dict[str, Any] = {}

    # 尝试提取公钥矩阵（二进制或十六进制）
    pk_hex = re.search(r"public_key\s*[:=]\s*[\"']([0-9a-fA-F]+)[\"']", source, re.IGNORECASE)
    if pk_hex:
        params["pk_hex_len"] = len(pk_hex.group(1))

    # 提取密文
    ct_hex = re.search(r"ciphertext|cipher|cipher_text\s*[:=]\s*[\"']([0-9a-fA-F]+)[\"']",
                       source, re.IGNORECASE)
    if ct_hex:
        params["ct_hex_len"] = len(ct_hex.group(1))

    return params


class McElieceAnalyzeTool(Tool):
    """McEliece 密码分析工具：分析 Goppa 码参数与攻击可行性."""

    name = "mceliece_analyze"
    description = (
        "McEliece 密码系统分析工具（纯本地）。解析 Goppa 码参数、检测密钥结构弱点、"
        "估算信息集解码（ISD）攻击复杂度。输入公钥/密文参数或实现源码，"
        "输出参数分析报告和可能的攻击方法。"
        "注意：实际的 ISD 攻击实现需要 ssh_python 在容器中执行。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "params": {
                "type": "string",
                "description": "McEliece 参数描述或源码字符串（包含 m, n, k, t 等参数）",
            },
            "params_file": {
                "type": "string",
                "description": "参数文件路径（与 params 二选一）",
            },
            "public_key": {
                "type": "string",
                "description": "公钥（hex 编码），用于分析密钥结构",
            },
            "ciphertext": {
                "type": "string",
                "description": "密文（hex 编码），用于分析密文结构",
            },
        },
    }

    def execute(self, **kwargs: Any) -> str:
        params_str = kwargs.get("params") or ""
        params_file = kwargs.get("params_file") or ""
        public_key = kwargs.get("public_key") or ""
        ciphertext = kwargs.get("ciphertext") or ""

        if params_file:
            try:
                with open(params_file, "r", encoding="utf-8") as f:
                    params_str = f.read()
            except FileNotFoundError:
                return f"ERROR: 文件不存在: {params_file}"
            except Exception as e:
                return f"ERROR: 读取文件失败: {e}"

        if not params_str.strip() and not public_key and not ciphertext:
            return "ERROR: 需要提供参数（params/params_file）、公钥或密文"

        # 组合所有输入用于分析
        combined = params_str + "\n" + public_key + "\n" + ciphertext

        report: list[str] = []
        report.append("=" * 50)
        report.append("McEliece 密码系统分析报告")
        report.append("=" * 50)

        # 1) 参数解析
        report.append("\n[1] 参数解析")
        params = _parse_mceliece_params(combined)
        ct_params = _parse_ciphertext_params(combined)
        params.update(ct_params)

        if params:
            for key, val in params.items():
                report.append(f"  {key}: {val}")
        else:
            report.append("  - 未解析到明确参数，尝试基于公钥/密文推断")

        # 2) Goppa 码安全性分析
        report.append("\n[2] Goppa 码参数安全性")
        if params:
            code_findings = _analyze_goppa_code(params)
            report.extend(code_findings)
        else:
            report.append("  - 参数不足，无法进行安全性分析")

        # 3) 密钥结构分析
        report.append("\n[3] 密钥结构分析")
        if params:
            key_findings = _analyze_key_structure(params)
            report.extend(key_findings)
        else:
            report.append("  - 未提取到密钥信息")

        # 4) 攻击方法建议
        report.append("\n[4] 可能的攻击方法")
        m = params.get("m")
        n = params.get("n")
        k = params.get("k")
        t = params.get("t")

        attack_methods: list[str] = []

        if m and t:
            # 基于经典参数的安全评估
            if m <= 10:
                attack_methods.append("⚠ m={m} ≤ 10：有限域过小，可尝试穷举搜索 Goppa 码多项式")
            if t <= 20:
                attack_methods.append("⚠ t={t} ≤ 20：纠错能力较弱，ISD 攻击可行")
            if t >= 100:
                attack_methods.append("  t={t} ≥ 100：纠错能力强，经典 ISD 攻击复杂度高")

        if n and k:
            rate = k / n
            if rate > 0.9:
                attack_methods.append("⚠ 高码率可能允许结构攻击")

        attack_methods.extend([
            "  - 信息集解码 (ISD)：经典攻击方法，适用于较小参数",
            "  - 如需实际 ISD 攻击，请使用 ssh_python 执行（容器中实现）",
            "  - 参考工具：https://github.com/chaegle/CryptAttack",
            "  - 参考实现：https://bitbucket.org/malb/m4rice/",
        ])

        if not attack_methods:
            attack_methods.append("  - 参数不足，无法给出具体攻击建议")

        report.extend(attack_methods)

        # 5) 密文分析
        if ciphertext:
            report.append("\n[5] 密文分析")
            ct_clean = ciphertext.strip().replace("0x", "").replace(" ", "")
            ct_len = len(ct_clean) // 2  # 字节数
            report.append(f"  密文长度: {ct_len} 字节")
            if n and ct_len != n:
                report.append(f"  ⚠ 密文长度 {ct_len} ≠ 码长 n={n}，可能已截断或附加其他数据")

        # 汇总
        report.append("\n" + "=" * 50)
        report.append("分析总结")
        if params:
            sec_issues = sum(1 for f in report if f.startswith("  ⚠"))
            if sec_issues > 0:
                report.append(f"发现 {sec_issues} 个潜在安全问题")
            else:
                report.append("参数基本安全（基于静态分析）")
        else:
            report.append("参数不足，无法评估安全性。请提供更多信息。")

        details = {
            "success": True,
            "params": {k: v for k, v in params.items() if isinstance(v, (int, str, bool))},
            "attack_methods": attack_methods,
        }
        return _truncate("\n".join(report)) + f"\n\n[details]\n{details}"


# ============================================================
# 工具注册函数
# ============================================================

def crypto_extra_tools() -> list[Tool]:
    """返回 CRYPTO 扩展工具集（纯本地，无需 ssh_client）。"""
    return [
        ZKPForgeProofTool(),
        OTPXorAnalyzeTool(),
        AESSidechannelTool(),
        HashCollisionTool(),
        McElieceAnalyzeTool(),
    ]


__all__ = [
    "ZKPForgeProofTool",
    "OTPXorAnalyzeTool",
    "AESSidechannelTool",
    "HashCollisionTool",
    "McElieceAnalyzeTool",
    "crypto_extra_tools",
]