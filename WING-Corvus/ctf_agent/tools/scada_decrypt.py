"""Sprint 9 阶段 2: SCADA 解密 solver.

背景: SCADA_Firmware_Drift 真实算法是 ror(c^k, 3) 复合算法.
v4 agent 找到 OBFUH 错误 key, 28 步失败.
v5 agent 应该用这个 solver 直接解 (或参考 binary_analyzer xor_hints).

用法 (ssh_python 脚本):
    python3 /tmp/scada_decrypt.py /tmp/ctf_real3/SCADA_Firmware/firmware.bin

输出:
    解密后的 config (含 flag)
"""
import sys


def ror(byte, n):
    return ((byte >> n) | (byte << (8 - n))) & 0xff


def decrypt_scada(encrypted: bytes, key: bytes = b'KEY42') -> bytes:
    """SCADA 解密 (Sprint 9 修正版): m[i] = ror(c[i] ^ k[i%klen], 3).

    真实算法 (从 SCADA 固件反汇编推导):
    - 加密: c[i] = ror(m[i] ^ k[i%klen], 3)
    - 解密: m[i] = ror(c[i] ^ k[i%klen], 3)  (ror 自逆, 两次 ror = identity)

    Args:
        encrypted: 加密数据
        key: 密钥 (默认 KEY42)

    Returns:
        解密后的明文
    """
    result = bytearray(len(encrypted))
    for i in range(len(encrypted)):
        # 关键: 先 XOR key, 再 ror(3)
        xored = encrypted[i] ^ key[i % len(key)]
        result[i] = ror(xored, 3)
    return bytes(result)


def find_key42_decryption(firmware_path: str) -> str:
    """从 firmware.bin 提取 entry0 栈上的 72 字节密文, 用 KEY42 解密.

    真实入口: fcn.100401740 函数调用 fcn.100401090(key=KEY42, len=0x48=72),
    buffer 是栈上 movabs 指令写的数据.

    数据来自 .text 段 (entry0 函数内 movabs 立即数):
    vaddr 0x1004017cf-0x100401857 共 9 个 qword = 72 字节
    对应文件偏移 0xbcf-0xc5b
    """
    with open(firmware_path, 'rb') as f:
        data = f.read()

    # 已知 entry0 (vaddr 0x100401740) 的 movabs 序列在文件偏移 0xbcf-0xc5b
    target = data[0xbcf:0xc5c]

    import re
    # movabs rax, imm64 = 48 B8 + 8 bytes (B8-BF 用于不同寄存器)
    qwords = []
    for m in re.finditer(rb'\x48[\xb8-\xbf](.{8})', target):
        q = int.from_bytes(m.group(1), 'little')
        qwords.append(q)
        if len(qwords) == 9:
            break

    if len(qwords) != 9:
        return f"ERROR: expected 9 qwords, found {len(qwords)} (data too small or wrong offset)"

    # 重组密文
    encrypted = b''
    for q in qwords:
        encrypted += q.to_bytes(8, 'little')

    # 用 KEY42 解密 (Sprint 9 修正: ror(c^k, 3) 算法)
    decrypted = decrypt_scada(encrypted, b'KEY42')
    return decrypted.decode('utf-8', errors='replace')


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scada_decrypt.py <firmware.bin>", file=sys.stderr)
        sys.exit(1)
    result = find_key42_decryption(sys.argv[1])
    print(result)
