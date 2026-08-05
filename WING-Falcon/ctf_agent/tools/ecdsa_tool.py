"""L2 ECDSA 攻击工具 (Sprint 14 P0 新增).

为 Tiny_ECC_Tweak 类 ECDSA nonce reuse 攻击提供专用工具,
无需依赖庞大的 sagemath, 适合 Sprint 14 P0 优化 Tiny_ECC.

适用场景:
- 2 个 ECDSA 签名 (sig1, sig2) 共享相同的 r (即 nonce k 复用)
- 通过 k = (z1 - z2) * (s1 - s2)^-1 mod n 恢复 k
- 再由 d = (s1*k - z1) * r^-1 mod n 求私钥 d
- 自动尝试用 d 直接和 SHA256(d) 作为 AES key 解密

实现:
- 使用 ecdsa 0.19.2 (Kali 已装, 无需 sagemath)
- 使用 pycryptodome 3.23.0 (AES-GCM)
- 通用 secp256k1/secp256r1 曲线 (NIST)
- 可指定 z1/z2 的 hash 函数 (默认 SHA256, 可选 SHA1/SHA256/SHA512/raw)
- 自动 2 步尝试 AES key (d 直接 / SHA256(d))

降级:
- 若 ecdsa 不可用, 返回 ERROR 提示 pip install ecdsa
- 若 pycryptodome 不可用, 返回 ERROR 提示 pip install pycryptodome
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Optional

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool


_MAX_OUTPUT = 4000
_TRUNCATED_SUFFIX = "\n... (输出截断, 共 {total} 字符)"


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + _TRUNCATED_SUFFIX.format(total=len(text))


def _check_python_libs(ssh: SSHClient) -> tuple[bool, bool]:
    """检测 ecdsa + pycryptodome 是否可用."""
    r = ssh.exec_cmd(
        "python3 -c 'import ecdsa, hashlib, Crypto.Cipher.AES; print(\"OK\")' 2>&1",
        timeout=10,
    )
    return (
        r.is_success and "OK" in (r.stdout or ""),
        r.is_success and "OK" in (r.stdout or ""),
    )


# ============ CommonCurves ============
# 支持的曲线参数
_SUPPORTED_CURVES = {
    "secp256k1": {
        "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        "description": "Bitcoin/Ethereum 曲线 (Tiny_ECC_Tweak 用)",
    },
    "P-256": {
        "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        "description": "NIST P-256 (secp256r1)",
    },
}


# ============ EcdsaNonceReuseTool ============

class EcdsaNonceReuseTool(Tool):
    """ECDSA nonce reuse 攻击工具 (Sprint 14 P0).

    用途: 两个 ECDSA 签名共享 r (即 k 复用) 时, 恢复私钥 d 并自动解 AES-GCM.
    适用: 2 个 (z, r, s) 签名 + pubkey + aes_nonce + aes_ciphertext (可选).

    算法:
    k = (z1 - z2) * (s1 - s2)^-1 mod n
    d = (s1*k - z1) * r^-1 mod n
    AES key = d 或 SHA256(d)
    AES-GCM decrypt(ciphertext, tag, nonce, key) -> plaintext

    输入格式: 字符串 (十进制整数, 0x 前缀也支持)
    """

    name = "ecdsa_nonce_reuse"
    description = (
        "ECDSA nonce reuse 攻击. 2 个签名共享 r 时恢复私钥 d, 并自动解 AES-GCM.\n"
        "用法: ecdsa_nonce_reuse(curve='secp256k1', z1='msg1', r1='...', s1='...', "
        "z2='msg2', r2='...', s2='...', hash_algo='sha256', "
        "aes_nonce='hex', aes_ciphertext='hex', aes_tag='hex', "
        "aes_key_mode='sha256')\n"
        "输入: 全部十进制字符串 (0x 前缀自动处理). z 是消息字节的整数表示.\n"
        "hash_algo: sha256 (默认) / sha1 / sha512 / raw (z1/z2 直接用整数)\n"
        "aes_key_mode: 'sha256' (默认, SHA256(d) 作为 key) / 'direct' (d 直接当 key)\n"
        "返回: 还原的 d + AES-GCM 解密明文 (如果提供密文).\n"
        "适用场景: Tiny_ECC_Tweak 类 ECDSA nonce reuse 题 (v11 4步成功, 本工具 1 步搞定).\n"
        "Kali 上 ecdsa 0.19.2 + pycryptodome 3.23.0 已装, 无需 sagemath.\n"
        "降级: 如果 ecdsa/pycryptodome 不可用, 提示 pip install."
    )
    parameters = {
        "type": "object",
        "properties": {
            "curve": {"type": "string", "description": "曲线名 (secp256k1 / P-256)"},
            "z1": {"type": "string", "description": "签名1 的消息哈希 (十进制或 0x)"},
            "r1": {"type": "string", "description": "签名1 的 r (十进制或 0x)"},
            "s1": {"type": "string", "description": "签名1 的 s (十进制或 0x)"},
            "z2": {"type": "string", "description": "签名2 的消息哈希 (十进制或 0x)"},
            "r2": {"type": "string", "description": "签名2 的 r (十进制或 0x)"},
            "s2": {"type": "string", "description": "签名2 的 s (十进制或 0x)"},
            "hash_algo": {
                "type": "string",
                "description": "z 消息的 hash 算法: sha256 (默认) / sha1 / sha512 / raw",
            },
            "msg1": {
                "type": "string",
                "description": "(可选) 签名1 的原始消息 (字符串), 用作 z1 哈希输入",
            },
            "msg2": {
                "type": "string",
                "description": "(可选) 签名2 的原始消息 (字符串), 用作 z2 哈希输入",
            },
            "aes_nonce": {
                "type": "string",
                "description": "(可选) AES-GCM nonce (hex string)",
            },
            "aes_ciphertext": {
                "type": "string",
                "description": "(可选) AES-GCM ciphertext+tag (hex string, tag 在最后 16 字节)",
            },
            "aes_key_mode": {
                "type": "string",
                "description": "AES key 模式: 'sha256' (SHA256(d)) / 'direct' (d 直接)",
            },
            "aes_key_len": {
                "type": "integer",
                "description": "AES key 长度 (16 / 24 / 32, 默认 32 = AES-256)",
            },
        },
        "required": ["z1", "r1", "s1", "z2", "r2", "s2"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh = ssh_client
        self._available: Optional[bool] = None

    def _ensure(self) -> str:
        if self._available is None:
            ecdsa_ok, cc_ok = _check_python_libs(self.ssh)
            self._available = ecdsa_ok and cc_ok
            if not ecdsa_ok:
                return (
                    "ERROR: ecdsa 未在 Kali 上安装.\n"
                    "方案: pip3 install ecdsa"
                )
            if not cc_ok:
                return (
                    "ERROR: pycryptodome 未在 Kali 上安装.\n"
                    "方案: pip3 install pycryptodome"
                )
        if not self._available:
            return "ERROR: ecdsa + pycryptodome 都未在 Kali 上安装."
        return ""

    def _parse_int(self, s: str) -> int:
        """十进制或 0x 前缀自动处理."""
        s = s.strip()
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)

    def execute(
        self,
        z1: str,
        r1: str,
        s1: str,
        z2: str,
        r2: str,
        s2: str,
        curve: str = "secp256k1",
        hash_algo: str = "sha256",
        msg1: str = "",
        msg2: str = "",
        aes_nonce: str = "",
        aes_ciphertext: str = "",
        aes_key_mode: str = "sha256",
        aes_key_len: int = 32,
        **_: Any,
    ) -> str:
        err = self._ensure()
        if err:
            return err

        if curve not in _SUPPORTED_CURVES:
            return f"ERROR: 不支持的曲线 '{curve}'. 可选: {list(_SUPPORTED_CURVES.keys())}"

        try:
            r1_v = self._parse_int(r1)
            r2_v = self._parse_int(r2)
            s1_v = self._parse_int(s1)
            s2_v = self._parse_int(s2)
            n = _SUPPORTED_CURVES[curve]["n"]

            # z1/z2: 如果提供了 msg, 用 hash_algo 计算; 否则直接用提供的 z
            if msg1 and hash_algo != "raw":
                z1_v = int.from_bytes(_hash_msg(msg1, hash_algo), "big")
            else:
                z1_v = self._parse_int(z1)
            if msg2 and hash_algo != "raw":
                z2_v = int.from_bytes(_hash_msg(msg2, hash_algo), "big")
            else:
                z2_v = self._parse_int(z2)
        except (ValueError, TypeError) as e:
            return f"ERROR: 参数解析失败: {e}. 确保 z/r/s 是十进制/0x 整数, msg 是字符串."

        # 完整攻击脚本 (使用 ecdsa + pycryptodome)
        r1_s, r2_s = str(r1_v), str(r2_v)
        s1_s, s2_s = str(s1_v), str(s2_v)
        z1_s, z2_s = str(z1_v), str(z2_v)
        n_s = str(n)
        curve_name = curve
        hash_algo_s = hash_algo
        aes_nonce_s = aes_nonce or ""
        aes_ct_s = aes_ciphertext or ""
        aes_key_mode_s = aes_key_mode
        aes_key_len_s = str(aes_key_len)

        script = """
import hashlib
from Crypto.Cipher import AES

# 曲线参数
n = __N__
curve_name = '__CURVE_NAME__'

# 签名数据
z1 = __Z1__
z2 = __Z2__
r1 = __R1__
r2 = __R2__
s1 = __S1__
s2 = __S2__
hash_algo = '__HASH_ALGO__'

# AES-GCM 参数
aes_nonce_hex = '__AES_NONCE__'
aes_ct_hex = '__AES_CT__'
aes_key_mode = '__AES_KEY_MODE__'
aes_key_len = __AES_KEY_LEN__

print(f"=== ECDSA Nonce Reuse 攻击 (Sprint 14 P0) ===")
print(f"  curve = {curve_name}")
print(f"  hash_algo = {hash_algo}")
print(f"  r1 == r2 ? {r1 == r2}")
print(f"  n bits = {n.bit_length()}")

# 验证: r1 必须等于 r2 (nonce 复用)
if r1 != r2:
    print(f"  ERROR: r1 != r2, 不是 nonce reuse 攻击场景")
    print(f"    r1 = {r1}")
    print(f"    r2 = {r2}")
    print(f"  提示: 本工具只支持 nonce reuse, 其他 ECDSA 攻击需 sagemath 或手动实现.")
else:
    r = r1
    # 1. k = (z1 - z2) * (s1 - s2)^-1 mod n
    k = ((z1 - z2) * pow((s1 - s2) % n, -1, n)) % n
    print(f"  k = {k} (bits={k.bit_length()})")

    # 2. d = (s1*k - z1) * r^-1 mod n
    d = ((s1 * k - z1) * pow(r % n, -1, n)) % n
    print(f"  d = {d} (bits={d.bit_length()})")
    print(f"  d hex = {hex(d)}")

    # 3. 如果有 AES-GCM 参数, 尝试解密
    if aes_ct_hex and aes_nonce_hex:
        print(f"  --- AES-GCM 解密 ---")
        print(f"  aes_key_mode = {aes_key_mode}, aes_key_len = {aes_key_len}")

        # 准备 key
        if aes_key_mode == 'sha256':
            key = hashlib.sha256(d.to_bytes(32, 'big')).digest()[:aes_key_len]
        elif aes_key_mode == 'direct':
            key = d.to_bytes(32, 'big')[:aes_key_len]
        else:
            print(f"  ERROR: 不支持的 aes_key_mode: {aes_key_mode}")
            key = None

        if key:
            print(f"  key hex = {key.hex()}")
            try:
                nonce = bytes.fromhex(aes_nonce_hex)
                ct = bytes.fromhex(aes_ct_hex)
                # 假设 GCM 输出是 ciphertext+tag, tag 在最后 16 字节
                if len(ct) >= 16:
                    ct_part = ct[:-16]
                    tag = ct[-16:]
                else:
                    ct_part = ct
                    tag = b''
                print(f"  ciphertext len = {len(ct_part)}, tag len = {len(tag)}")

                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                try:
                    pt = cipher.decrypt_and_verify(ct_part, tag)
                    print(f"  ✅ Decrypted (mode={aes_key_mode}): {pt}")
                    try:
                        print(f"  Decoded: {pt.decode('utf-8', errors='replace')[:200]}")
                    except Exception:
                        pass
                except Exception as e:
                    print(f"  ❌ Decryption failed (mode={aes_key_mode}): {e}")
                    # 自动尝试另一个 mode
                    alt_mode = 'direct' if aes_key_mode == 'sha256' else 'sha256'
                    if alt_mode == 'sha256':
                        alt_key = hashlib.sha256(d.to_bytes(32, 'big')).digest()[:aes_key_len]
                    else:
                        alt_key = d.to_bytes(32, 'big')[:aes_key_len]
                    print(f"  自动尝试 alt mode={alt_mode}, key={alt_key.hex()}")
                    try:
                        cipher2 = AES.new(alt_key, AES.MODE_GCM, nonce=nonce)
                        pt2 = cipher2.decrypt_and_verify(ct_part, tag)
                        print(f"  ✅ Decrypted (mode={alt_mode}): {pt2}")
                        try:
                            print(f"  Decoded: {pt2.decode('utf-8', errors='replace')[:200]}")
                        except Exception:
                            pass
                    except Exception as e2:
                        print(f"  ❌ alt mode also failed: {e2}")
            except Exception as e:
                print(f"  AES-GCM setup error: {e}")
    else:
        print(f"  (未提供 AES-GCM 参数, 跳过解密)")

print("Done")
"""
        script = (
            script
            .replace("__N__", n_s)
            .replace("__CURVE_NAME__", curve_name)
            .replace("__HASH_ALGO__", hash_algo_s)
            .replace("__Z1__", z1_s)
            .replace("__Z2__", z2_s)
            .replace("__R1__", r1_s)
            .replace("__R2__", r2_s)
            .replace("__S1__", s1_s)
            .replace("__S2__", s2_s)
            .replace("__AES_NONCE__", aes_nonce_s)
            .replace("__AES_CT__", aes_ct_s)
            .replace("__AES_KEY_MODE__", aes_key_mode_s)
            .replace("__AES_KEY_LEN__", aes_key_len_s)
        )

        # 写到远程文件并执行
        remote_script = "/tmp/ecdsa_nonce_reuse.py"
        r = self.ssh.exec_cmd(
            f"cat > {remote_script} << 'PYEOF'\n{script}\nPYEOF",
            timeout=10,
        )
        if not r.is_success:
            return f"ERROR: 写脚本失败: {r.stderr[:200]}"

        r = self.ssh.exec_cmd(f"python3 {remote_script}", timeout=60)
        output = r.stdout or ""
        if r.is_success and output:
            return f"=== ECDSA Nonce Reuse (Sprint 14 P0) ===\n{_truncate(output)}"
        return f"ERROR: 攻击失败: {r.stderr[:300] or 'no output'}"


def _hash_msg(msg: str, algo: str) -> bytes:
    """计算消息哈希."""
    msg_bytes = msg.encode("utf-8") if isinstance(msg, str) else msg
    if algo == "sha256":
        return hashlib.sha256(msg_bytes).digest()
    elif algo == "sha1":
        return hashlib.sha1(msg_bytes).digest()
    elif algo == "sha512":
        return hashlib.sha512(msg_bytes).digest()
    raise ValueError(f"不支持的 hash_algo: {algo}")


# ============ 工厂函数 ============

def ecdsa_tools(ssh_client: SSHClient) -> list[Tool]:
    """返回 ECDSA 攻击工具集 (Sprint 14 P0)."""
    return [EcdsaNonceReuseTool(ssh_client)]
