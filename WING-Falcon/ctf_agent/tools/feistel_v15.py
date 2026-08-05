# -*- coding: utf-8 -*-
"""- 正确实现 复杂逆向题 disasm 算法 (验证用).

按 main_disasm.txt 真实 disasm 实现:
- ror32(x, n) - rotate right 32 bits by n
- expand_key(master_key_64) - 8 round keys (32-bit each)
- mix32(R, round_key) - F-function (MurmurHash3 风格)
- block_cipher(plain_64, key_64) - 8 轮 Feistel
"""
MASK32 = 0xFFFFFFFF


def ror32(x: int, n: int) -> int:
    """32-bit rotate right by n bits."""
    n = n & 31
    return ((x >> n) | (x << (32 - n))) & MASK32


def expand_key(master_key: int) -> list[int]:
    """按 disasm expand_key 真实逻辑:
    - low_key = (master_key >> 0) & 0xffffffff
    - high_key = (master_key >> 32) & 0xffffffff
    - for i in 0..7:
        edx = (i * 7) & 0x1f  (= 7*i % 32)
        eax = ror32(low_key, edx)
        ecx = i * 0xb7e15163
        rk[i] = eax ^ ecx
    - if high_key == 0xffffffff: rk[0] ^= 0xffffffff

    关键漏洞: 实际有效 key 只有 low_key (32 bits) + 1 bit (high_key == 0xffffffff)
    """
    low_key = master_key & MASK32
    high_key = (master_key >> 32) & MASK32
    rk = []
    for i in range(8):
        edx = (i * 7) & 0x1F
        eax = ror32(low_key, edx)
        ecx = (i * 0xB7E15163) & MASK32
        rk.append((eax ^ ecx) & MASK32)
    if high_key == 0xFFFFFFFF:
        rk[0] = (rk[0] ^ 0xFFFFFFFF) & MASK32
    return rk


def mix32(R: int, round_key: int) -> int:
    """按 disasm mix32 真实逻辑:
    - x = R XOR round_key
    - x = x * 0x5bd1e995
    - x = x XOR (x >> 13)
    - x = (x + (x ROL 4))
    - x = x XOR 0xa5c3e1d7
    - x = x XOR (x >> 11)
    - return x
    """
    x = (R ^ round_key) & MASK32
    x = (x * 0x5BD1E995) & MASK32
    x = (x ^ (x >> 13)) & MASK32
    x = (x + ror32(x, 32 - 4)) & MASK32  # ROL 4 = ROR 28
    x = (x ^ 0xA5C3E1D7) & MASK32
    x = (x ^ (x >> 11)) & MASK32
    return x


def block_cipher(plain: int, key: int) -> int:
    """按 disasm block_cipher 真实逻辑:
    - expand_key(key) → 8 round keys
    - L = upper 32 bits, R = lower 32 bits
    - for i in 0..7:
        T = R
        f_out = mix32(R, round_key[i])
        R = L XOR f_out
        L = T
    - return L || R
    """
    rk = expand_key(key)
    L = (plain >> 32) & MASK32
    R = plain & MASK32
    for rk_i in rk:
        T = R
        f_out = mix32(R, rk_i)
        R = (L ^ f_out) & MASK32
        L = T
    return (L << 32) | R


def block_cipher_decr(cipher: int, key: int) -> int:
    """按 disasm 40131f 真实逻辑 (倒序 Feistel):
    - expand_key(key) → 8 round keys
    - L = upper 32 bits, R = lower 32 bits
    - for i in 7 down to 0:
        T = L
        f_out = mix32(L, rk[i])   # 注意用 L, 不是 R
        L = R XOR f_out
        R = T
    - return L || R
    """
    rk = expand_key(key)
    L = (cipher >> 32) & MASK32
    R = cipher & MASK32
    for rk_i in reversed(rk):
        T = L
        f_out = mix32(L, rk_i)
        L = (R ^ f_out) & MASK32
        R = T
    return (L << 32) | R


if __name__ == "__main__":
    # Self-test: encrypt → decrypt round-trip
    print("=== expand_key + mix32 + block_cipher 自检 ===")

    # 已知明文: "athena{" + "\x00\x00" = 0x6174656e 61417b00
    plain_hex = "6174656e61417b00"
    plain = int(plain_hex, 16)
    print(f"plain: {plain_hex}")

    # 任意 key 测试
    test_key = 0x12345678_9ABCDEF0
    rk = expand_key(test_key)
    print(f"key: 0x{test_key:016x}")
    print(f"round keys: {[f'0x{r:08x}' for r in rk]}")

    c = block_cipher(plain, test_key)
    print(f"cipher: 0x{c:016x}")

    # Decrypt round-trip
    p2 = block_cipher_decr(c, test_key)
    print(f"decrypt: 0x{p2:016x} (should equal plain: 0x{plain:016x}, match: {p2 == plain})")

    # 加密 flag 实际值
    c_actual_block1 = 0xF796C90F7C6628AB
    print(f"\n实际密文 block 1: 0x{c_actual_block1:016x}")
    print(f"测试 key 的密文: 0x{c:016x}")
    print(f"匹配: {c == c_actual_block1}")
