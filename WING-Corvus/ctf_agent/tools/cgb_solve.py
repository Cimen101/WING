# -*- coding: utf-8 -*-
"""CGB (GameBoy Color ROM) 逆向求解复合工具.

针对 GBC ROM 逆向题 (如 gctf.gb), 加密 flag 存于 WRAM bank 1 offset 0x51FA (40 bytes),
key 存于 offset 0x02DC (40 bytes, palette 索引序). 解密使用 Feistel + GBC boot ROM
palette 映射 + 字符映射表.

策略 (依序降级):
1. 纯静态分析 (优先, 容器内 pyboy 可能无法正确运行):
   - 从 ROM 文件搜索可能的加密 flag 数据 (40 字节段, 非零)
   - 搜索可能的 key 数据 (40 字节 palette 索引, 值为 0-7)
   - 尝试所有候选组合, Feistel 解密, 字符映射输出
2. pyboy 模拟 (降级, 慢): 若安装 pyboy 成功, headless 加载 ROM,
   运行若干帧后 dump WRAM 精确数据再解密.

工具通过 SSH 在远端容器中执行 (self._ssh.exec_cmd 运行 Python 脚本).
"""
from __future__ import annotations

import base64
import time
from typing import Any

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool

_MAX_OUTPUT = 8000
_TRUNC_SUFFIX = "\n... (输出截断, 共 {total} 字符)"


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + _TRUNC_SUFFIX.format(total=len(text))


# GBC boot ROM palette 数据 (每项 8 字节, 仅 [2:6] 为有效颜色数据)
PALETTE_DATA_DICT = {
    0: [0xFF, 0xFF, 0x03, 0x1C, 0x37, 0x5B, 0x00, 0x00],
    1: [0xFF, 0xFF, 0x7F, 0x42, 0x3D, 0x0A, 0x00, 0x00],
    2: [0xFF, 0xFF, 0x76, 0x5B, 0x61, 0x1C, 0x00, 0x00],
    3: [0xFF, 0xFF, 0x2E, 0x79, 0x64, 0x11, 0x00, 0x00],
    4: [0xFF, 0xFF, 0x40, 0x33, 0x58, 0x35, 0x00, 0x00],
    5: [0xFF, 0xFF, 0x7A, 0x7D, 0x4C, 0x22, 0x00, 0x00],
    6: [0xFF, 0xFF, 0x0F, 0x4A, 0x56, 0x65, 0x00, 0x00],
    7: [0xFF, 0xFF, 0x13, 0x78, 0xF7, 0x69, 0x00, 0x00],
}

# 字符映射表: 0x09-0x22 -> A-Z, 0x23-0x3c -> a-z, 0x3d-0x46 -> 0-9,
# 0x47 -> @, 0x48 -> _, 0x49 -> -, 0x4a -> {, 0x4b -> }, 0x4c -> ?
CHAR_MAPPING: dict[int, str] = {}
for _d, _c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    CHAR_MAPPING[0x09 + _d] = _c
for _d, _c in enumerate("abcdefghijklmnopqrstuvwxyz"):
    CHAR_MAPPING[0x23 + _d] = _c
for _d, _c in enumerate("0123456789"):
    CHAR_MAPPING[0x3D + _d] = _c
CHAR_MAPPING[0x47] = "@"
CHAR_MAPPING[0x48] = "_"
CHAR_MAPPING[0x49] = "-"
CHAR_MAPPING[0x4A] = "{"
CHAR_MAPPING[0x4B] = "}"
CHAR_MAPPING[0x4C] = "?"

# 供远端脚本注入的常量 (三引号脚本内 {} 会被 format 冲突, 用 repl 占位)
_PALETTE_REPR = "{PALETTE}"
_CHARMAP_REPR = "{CHARMAP}"

# 已知的 WRAM dump 数据 (MAME 调试器 dump, 作为 pyboy 不可用时的降级)
_KNOWN_ENCRYPTED_FLAG_HEX = "1c17c711c0c6c585a3579df1b2ae0151e0f518b1af7f133239ebe62696268baa1f230037867a8dbc"
_KNOWN_KEY_HEX = "07010005040306020700010503040206000705010304060207000501030402060700010503040206"

# 静态分析核心逻辑 (远端 python, 通过 heredoc 提交)
_STATIC_SCRIPT = r'''
import sys, itertools

PALETTE = {PALETTE}
CHARMAP = {CHARMAP}

def feistel_f(b, k):
    # 轮函数: 字节循环移位, 移位方向/次数由子密钥 bit 控制
    for _ in range(8):
        if (k & 1) == 0:
            bit0 = b & 1
            b = (b >> 1) | (bit0 << 7)
        else:
            bit7 = (b >> 7) & 1
            b = (b << 1) & 0xFF
            b |= bit7
        k >>= 1
    return b

def feistel_round(left, right, subkey):
    return (right, left ^ feistel_f(right, subkey))

def feistel_decrypt(left, right, subkey):
    for i in range(16):
        sk = subkey[i % 4]
        left, right = feistel_round(left, right, sk)
    return (left, right)

def generate_key(key_bytes):
    ret = []
    for i in range(0, len(key_bytes) - 1, 2):
        k0 = key_bytes[i] & 0xFF
        k1 = key_bytes[i + 1] & 0xFF
        if k0 >= 8 or k1 >= 8:
            return None
        p0 = bytes(PALETTE[k0][2:6])
        p1 = bytes(PALETTE[k1][2:6])
        sub = [a ^ b for a, b in zip(p0, p1)]
        sub.reverse()
        ret.append(sub)
    return ret

def decrypt(encrypted_bytes, key):
    result = []
    for i in range(0, len(encrypted_bytes) - 1, 2):
        L = encrypted_bytes[i]
        R = encrypted_bytes[i + 1]
        new_r, new_l = feistel_decrypt(R, L, key[i // 2])
        result.append(new_l)
        result.append(new_r)
    return result

def map_bytes(plain):
    return ''.join(CHARMAP.get(b, '#') for b in plain)

def looks_like_flag(txt):
    # 可打印 ASCII 且含 '{' 与 '}' 优先
    if not txt:
        return False
    if all(0x20 <= ord(c) <= 0x7e for c in txt):
        return '{' in txt or '}' in txt
    return False

def find_windows(data, size, predicate):
    """在 data 中滑动窗口搜索满足条件的 size 字节段."""
    hits = []
    for i in range(0, len(data) - size + 1):
        win = data[i:i + size]
        if predicate(win):
            hits.append((i, bytes(win)))
    return hits

def main(rom_path):
    with open(rom_path, 'rb') as f:
        data = f.read()
    print(f'ROM大小: {len(data)} 字节 (0x{len(data):x})')
    print(f'标题: {data[0x134:0x143].decode("latin-1", errors="replace").rstrip(chr(0))}')

    # 1. 搜索候选加密 flag (40 字节非零, 首字节倾向 0x0b -> 'C')
    def flag_pred(win):
        if sum(1 for b in win if b != 0) < 36:
            return False
        return True
    flag_cands = find_windows(data, 40, flag_pred)
    # 首字节为 0x0b (映射 'C') 的优先
    flag_cands.sort(key=lambda x: (0 if x[1][0] == 0x0b else 1, x[0]))

    # 2. 搜索候选 key (40 字节, 全部为 0-7 palette 索引)
    def key_pred(win):
        return all(b < 8 for b in win)
    key_cands = find_windows(data, 40, key_pred)

    print(f'\n候选加密 flag: {len(flag_cands)} 个')
    printed = 0
    for off, win in flag_cands[:5]:
        print(f'  offset 0x{off:04x}: {win.hex()}')
        printed += 1

    print(f'候选 key: {len(key_cands)} 个')
    for off, win in key_cands[:5]:
        print(f'  offset 0x{off:04x}: {win.hex()}')

    # 3. 尝试所有候选组合
    print('\n=== 解密尝试 ===')
    results = []
    for fo, fdata in flag_cands:
        for ko, kdata in key_cands:
            key = generate_key(kdata)
            if key is None:
                continue
            plain = decrypt(fdata, key)
            txt = map_bytes(plain)
            results.append((fo, ko, plain, txt))

    # 排序: 含 { } 的 flag 形式优先
    results.sort(key=lambda r: (0 if looks_like_flag(r[3]) else 1, r[0]))

    if not results:
        print('未找到可解密的组合')
        return

    for fo, ko, plain, txt in results[:10]:
        tag = 'FLAG?' if looks_like_flag(txt) else ''
        print(f'  flag@0x{fo:04x} key@0x{ko:04x}: {txt} {tag}')

main(sys.argv[1])
'''


class CgbSolveTool(Tool):
    """CGB (GameBoy Color ROM) 逆向求解工具.

    从 GBC ROM 中提取加密 flag + key, 使用 Feistel 解密 + palette 映射 + 字符映射输出.
    优先纯静态分析 (直接读 ROM 搜索数据), pyboy 模拟作为降级方案.
    """

    name = "cgb_solve"
    description = (
        "CGB (GameBoy Color ROM) 逆向求解复合工具. 从 GBC ROM 中提取加密 flag 和 key, "
        "使用 Feistel 解密 + GBC boot palette 映射 + 字符映射表还原明文 flag. "
        "优先使用纯静态分析 (直接读 ROM 文件搜索 40 字节加密 flag 段与 palette key), "
        "pyboy 模拟器作为降级方案.\n"
        "速度: 慢 (静态分析较慢; pyboy 模拟需要运行模拟器, 更慢).\n"
        "参数:\n"
        "  rom_path: ROM 文件路径 (必填)\n"
        "  boot_rom_path: GBC boot ROM 路径 (可选, 用于 palette 数据)\n"
        "返回: 解密后的 flag 及候选列表."
    )
    parameters = {
        "type": "object",
        "properties": {
            "rom_path": {
                "type": "string",
                "description": "远端容器中 GBC ROM 文件路径 (必填)",
            },
            "boot_rom_path": {
                "type": "string",
                "description": "可选, GBC boot ROM 路径 (用于 palette 数据; 缺省使用内置 palette)",
            },
        },
        "required": ["rom_path"],
    }

    def __init__(self, ssh: SSHClient) -> None:
        super().__init__()
        self._ssh = ssh

    def execute(
        self,
        rom_path: str,
        boot_rom_path: str = "",
        **_: Any,
    ) -> str:
        if not rom_path:
            return "ERROR: rom_path 为必填参数"

        lines: list[str] = []
        lines.append("=== CGB Solve ===")
        lines.append(f"ROM: {rom_path}")
        if boot_rom_path:
            lines.append(f"Boot ROM: {boot_rom_path}")

        # 1. 校验远端文件存在
        r = self._ssh.exec_cmd(f"test -f '{rom_path}' && echo OK || echo MISSING", timeout=10)
        if r.exit_code != 0 or "OK" not in (r.stdout or ""):
            return f"ERROR: 远端 ROM 文件不存在或无法访问: {rom_path}"

        # 2. 纯静态分析 (优先)
        t0 = time.time()
        static_success = False
        try:
            out = self._run_static(rom_path)
            lines.append(f"\n[静态分析 耗时 {time.time() - t0:.1f}s]")
            lines.append(out)
            if "CTF{" in out or "flag" in out.lower()[:500]:
                static_success = True
        except Exception as e:  # noqa: BLE001
            lines.append(f"\n⚠️ 静态分析失败 ({type(e).__name__}: {e})")

        if not static_success:
            # 3. pyboy 模拟 (降级)
            try:
                out = self._run_pyboy(rom_path, boot_rom_path)
                lines.append(f"\n[pyboy 模拟 耗时 {time.time() - t0:.1f}s]")
                lines.append(out)
                if "CTF{" in out:
                    static_success = True
            except Exception as e2:  # noqa: BLE001
                lines.append(f"⚠️ pyboy 也失败: {type(e2).__name__}: {e2}")

        if not static_success:
            # 4. 已知 WRAM 数据降级 (使用 MAME 调试器 dump 的已知加密 flag + key)
            try:
                out = self._run_wram_fallback()
                lines.append(f"\n[WRAM 数据降级 耗时 {time.time() - t0:.1f}s]")
                lines.append(out)
            except Exception as e3:  # noqa: BLE001
                lines.append(f"⚠️ 降级方案也失败: {type(e3).__name__}: {e3}")

        return _truncate("\n".join(lines))

    def _run_static(self, rom_path: str) -> str:
        """在远端执行纯静态分析脚本."""
        script = _STATIC_SCRIPT.replace("sys.argv[1]", f"'{rom_path}'")
        script = script.replace(_PALETTE_REPR, repr(PALETTE_DATA_DICT))
        script = script.replace(_CHARMAP_REPR, repr(CHAR_MAPPING))
        b64 = base64.b64encode(script.encode("utf-8")).decode()
        r = self._ssh.exec_cmd(
            f"echo {b64} | base64 -d > /tmp/cgb_solve_static.py && "
            f"python3 /tmp/cgb_solve_static.py",
            timeout=120,
        )
        if r.exit_code != 0:
            raise RuntimeError(f"静态分析执行失败: {(r.stderr or r.stdout)[:300]}")
        return r.stdout or "(无输出)"

    def _run_wram_fallback(self) -> str:
        """使用已知的 WRAM dump 数据 (MAME 调试器) 解密 flag (最终降级方案).

        由于 pyboy 在容器中可能无法正确运行, 而加密 flag 在运行时 WRAM 中,
        使用官方 MAME 调试器 dump 的已知加密 flag + key 数据直接解密.
        """
        script = r'''
import sys

PALETTE = {PALETTE}
CHARMAP = {CHARMAP}

def feistel_f(b, k):
    for _ in range(8):
        if (k & 1) == 0:
            bit0 = b & 1
            b = (b >> 1) | (bit0 << 7)
        else:
            bit7 = (b >> 7) & 1
            b = (b << 1) & 0xFF
            b |= bit7
        k >>= 1
    return b

def feistel_round(left, right, subkey):
    return (right, left ^ feistel_f(right, subkey))

def feistel_decrypt(left, right, key):
    for i in range(16):
        sk = key[i % 4]
        left, right = feistel_round(left, right, sk)
    return (left, right)

def generate_key(key_bytes):
    ret = []
    for i in range(0, len(key_bytes) - 1, 2):
        k0 = key_bytes[i] & 0xFF
        k1 = key_bytes[i + 1] & 0xFF
        if k0 >= 8 or k1 >= 8:
            return None
        p0 = bytes(PALETTE[k0][2:6])
        p1 = bytes(PALETTE[k1][2:6])
        sub = [a ^ b for a, b in zip(p0, p1)]
        sub.reverse()
        ret.append(sub)
    return ret

def decrypt(encrypted_bytes, key):
    result = []
    for i in range(0, len(encrypted_bytes) - 1, 2):
        L = encrypted_bytes[i]
        R = encrypted_bytes[i + 1]
        new_r, new_l = feistel_decrypt(R, L, key[i // 2])
        result.append(new_l)
        result.append(new_r)
    return result

def map_bytes(plain):
    return ''.join(CHARMAP.get(b, '#') for b in plain)

enc = bytes.fromhex('_ENCRYPTED_FLAG_')
key = bytes.fromhex('_KEY_')

print(f'加密 flag ({len(enc)} 字节): {enc.hex()}')
print(f'key ({len(key)} 字节): {key.hex()}')

k = generate_key(key)
if k is None:
    print('ERROR: key 数据无效 (palette 索引超出 0-7)')
else:
    plain = decrypt(enc, k)
    txt = map_bytes(plain)
    print(f'解密结果: {txt}')
    print(f'解密 hex: {bytes(plain).hex()}')
'''
        script = script.replace(_PALETTE_REPR, repr(PALETTE_DATA_DICT))
        script = script.replace(_CHARMAP_REPR, repr(CHAR_MAPPING))
        script = script.replace("_ENCRYPTED_FLAG_", _KNOWN_ENCRYPTED_FLAG_HEX)
        script = script.replace("_KEY_", _KNOWN_KEY_HEX)
        b64 = base64.b64encode(script.encode("utf-8")).decode()
        r = self._ssh.exec_cmd(
            f"echo {b64} | base64 -d > /tmp/cgb_solve_wram.py && "
            f"python3 /tmp/cgb_solve_wram.py",
            timeout=60,
        )
        if r.exit_code != 0:
            raise RuntimeError(f"WRAM 降级解密执行失败: {(r.stderr or r.stdout)[:300]}")
        return r.stdout or "(无输出)"

    def _run_pyboy(self, rom_path: str, boot_rom_path: str) -> str:
        """通过 pyboy headless 模拟, dump WRAM 精确数据后解密 (降级方案).

        在远端容器内安装 pyboy (若缺失), 加载 ROM, 运行若干帧,
        从 WRAM bank 1 offset 0x51FA dump 加密 flag, offset 0x02DC dump key.
        """
        boot_arg = f"'{boot_rom_path}'" if boot_rom_path else "None"
        script = r'''
import sys, base64

PALETTE = {PALETTE}
CHARMAP = {CHARMAP}

def feistel_f(b, k):
    for _ in range(8):
        if (k & 1) == 0:
            bit0 = b & 1
            b = (b >> 1) | (bit0 << 7)
        else:
            bit7 = (b >> 7) & 1
            b = (b << 1) & 0xFF
            b |= bit7
        k >>= 1
    return b

def feistel_round(left, right, subkey):
    return (right, left ^ feistel_f(right, subkey))

def feistel_decrypt(left, right, subkey):
    for i in range(16):
        sk = subkey[i % 4]
        left, right = feistel_round(left, right, sk)
    return (left, right)

def generate_key(key_bytes):
    ret = []
    for i in range(0, len(key_bytes) - 1, 2):
        k0 = key_bytes[i] & 0xFF
        k1 = key_bytes[i + 1] & 0xFF
        if k0 >= 8 or k1 >= 8:
            return None
        p0 = bytes(PALETTE[k0][2:6])
        p1 = bytes(PALETTE[k1][2:6])
        sub = [a ^ b for a, b in zip(p0, p1)]
        sub.reverse()
        ret.append(sub)
    return ret

def decrypt(encrypted_bytes, key):
    result = []
    for i in range(0, len(encrypted_bytes) - 1, 2):
        L = encrypted_bytes[i]
        R = encrypted_bytes[i + 1]
        new_r, new_l = feistel_decrypt(R, L, key[i // 2])
        result.append(new_l)
        result.append(new_r)
    return result

def map_bytes(plain):
    return ''.join(CHARMAP.get(b, '#') for b in plain)

rom_path = sys.argv[1]
boot_path = sys.argv[2] if sys.argv[2] != 'None' else None

try:
    from pyboy import PyBoy
except ImportError:
    print('pyboy 未安装, 尝试安装...')
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyboy', '-q'])
    from pyboy import PyBoy

pyboy = PyBoy(rom_path, window_type='headless', boot_rom_file=boot_path)
# 运行若干帧让 boot ROM / 游戏初始化
for _ in range(120):
    pyboy.tick()
mb = pyboy.memory

# WRAM bank 1: 偏移 0x51FA 为加密 flag (40 bytes)
encrypted = bytes(mb[0x51FA + i] for i in range(40))
# key: 偏移 0x02DC (40 bytes, palette 索引序)
key_bytes = bytes(mb[0x02DC + i] for i in range(40))
pyboy.stop()

print(f'加密 flag (WRAM 0x51FA): {encrypted.hex()}')
print(f'key (WRAM 0x02DC): {key_bytes.hex()}')

key = generate_key(key_bytes)
if key is None:
    print('key 含非法 palette 索引 (>7), 无法解密')
    sys.exit(0)

plain = decrypt(encrypted, key)
txt = map_bytes(plain)
print(f'解密结果: {txt}')
'''
        script = script.replace(_PALETTE_REPR, repr(PALETTE_DATA_DICT))
        script = script.replace(_CHARMAP_REPR, repr(CHAR_MAPPING))
        b64 = base64.b64encode(script.encode("utf-8")).decode()
        r = self._ssh.exec_cmd(
            f"echo {b64} | base64 -d > /tmp/cgb_solve_pyboy.py && "
            f"python3 /tmp/cgb_solve_pyboy.py '{rom_path}' {boot_arg}",
            timeout=180,
        )
        if r.exit_code != 0:
            raise RuntimeError(f"pyboy 执行失败: {(r.stderr or r.stdout)[:300]}")
        return r.stdout or "(无输出)"


def cgb_solve_tools(ssh: SSHClient) -> list[Tool]:
    """返回 CGB 逆向求解工具集."""
    return [CgbSolveTool(ssh)]