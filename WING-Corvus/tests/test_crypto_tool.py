"""Sprint 16：本地密码学工具测试（crypto_rsa / crypto_classic）.

覆盖 RSA 多策略（已知 p,q / 自动分解 / 小 e 开方 / 共模攻击 / Wiener）与
经典编码一把梭（base64/hex/rot/xor + flag 检测），全部纯本地、不联网。
"""

from __future__ import annotations

import base64

from ctf_agent.tools.crypto_tool import (
    ClassicCipherTool,
    CryptoRSATool,
    crypto_tools,
)


# ============ crypto_rsa ============

def test_rsa_known_pq_decrypt() -> None:
    """已知 p,q 直接解密：经典 RSA 例 n=3233,e=17,d=2753，m=65('A')."""
    tool = CryptoRSATool()
    out = tool.execute(n="3233", e="17", c="2790", p="61", q="53")
    assert "65" in out  # m=65 => b'A'


def test_rsa_auto_factor_small_n() -> None:
    """未给 p,q，自动分解小 n（Fermat/Pollard/factordb 任一命中）并解密."""
    tool = CryptoRSATool()
    out = tool.execute(n="3233", e="17", c="2790")
    assert "65" in out


def test_rsa_small_e_cube_root() -> None:
    """小 e 未取模回绕：c=m^e，直接开整数 e 次方根还原 m."""
    m, e = 1000, 3
    c = m**e
    n = 10**18  # 远大于 c，保证未回绕
    out = CryptoRSATool().execute(n=str(n), e=str(e), c=str(c))
    assert "1000" in out


def test_rsa_common_modulus() -> None:
    """共模攻击：同 n 不同互素 e1,e2，无需分解即可还原 m."""
    n, m = 3233, 42
    c1 = pow(m, 3, n)
    c2 = pow(m, 5, n)
    out = CryptoRSATool().execute(n=str(n), e="3", c=str(c1), e2="5", c2=str(c2))
    assert "42" in out


def test_rsa_hex_input_parsing() -> None:
    """整数支持 0x 十六进制字符串输入."""
    out = CryptoRSATool().execute(
        n=hex(3233), e="0x11", c=str(2790), p="61", q="53"
    )
    assert "65" in out


def test_rsa_insufficient_params() -> None:
    out = CryptoRSATool().execute(e="65537")
    assert "ERROR" in out or "参数不足" in out


# ============ crypto_classic ============

def test_classic_base64_flag() -> None:
    data = base64.b64encode(b"flag{base64_ok}").decode()
    out = ClassicCipherTool().execute(data=data)
    assert "flag{base64_ok}" in out


def test_classic_rot13() -> None:
    # "flag{rot13}" 经 rot13 得到 "synt{ebg13}"，工具应还原
    out = ClassicCipherTool().execute(data="synt{ebg13}")
    assert "flag{rot13}" in out


def test_classic_hex_decode() -> None:
    data = b"flag{hex}".hex()
    out = ClassicCipherTool().execute(data=data)
    assert "flag{hex}" in out


def test_classic_xor_bruteforce() -> None:
    key = 0x2a
    raw = bytes(b ^ key for b in b"flag{xor_me}")
    data = raw.hex()
    out = ClassicCipherTool().execute(data=data, flag_prefix="flag")
    assert "flag{xor_me}" in out


def test_classic_no_result() -> None:
    out = ClassicCipherTool().execute(data="!!!@@@###$$$")
    # 无 flag 也不应崩溃
    assert isinstance(out, str) and out


# ============ 工厂 ============

def test_crypto_tools_factory() -> None:
    tools = crypto_tools()
    names = {t.name for t in tools}
    assert names == {"crypto_rsa", "crypto_classic"}
