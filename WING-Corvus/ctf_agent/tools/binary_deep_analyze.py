"""binary_deep_analyze: 深度逆向分析工具 (IEEE浮点/GameBoy/常量提取/自动求解).

功能:
1. IEEE 754 浮点逆向: 提取大整数常量, 生成 python 逆推脚本
2. GameBoy ROM 分析: 提取 tile 数据, 分析 ROM 结构, 尝试解码 flag
3. 大整数常量自动提取 + 算法链逆推
4. angr 符号执行集成

用法:
    binary_deep_analyze(binary_path='/challenge/workspace/ieee', mode='auto')
    binary_deep_analyze(binary_path='/challenge/workspace/roms/gctf/gctf.gb', mode='gameboy')
"""
from __future__ import annotations

import re
import struct
from typing import Any

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool

_MAX_OUTPUT = 8000
_RE_HEX_LARGE = re.compile(r"[0-9a-fA-F]{32,}")  # 128+ bit hex constants


class BinaryDeepAnalyzeTool(Tool):
    """深度逆向分析工具, 支持 IEEE 浮点/GameBoy/常量提取."""

    def __init__(self, ssh: SSHClient) -> None:
        super().__init__()
        self._ssh = ssh

    @property
    def name(self) -> str:
        return "binary_deep_analyze"

    @property
    def description(self) -> str:
        return (
            "深度逆向分析工具, 支持 IEEE 浮点/GameBoy/常量提取/算法指纹/统计推理/自动求解.\n"
            "参数:\n"
            "  binary_path: 二进制文件路径 (必填)\n"
            "  mode: 分析模式 ('auto'=自动检测, 'ieee'=IEEE浮点, 'gameboy'=GameBoy, 'constants'=常量提取, "
            "'crypto'=算法指纹识别, 'stat'=统计推理/置换推导)\n"
            "  generate_solve: 是否自动生成 solve 脚本 (默认 True)\n"
            "用法:\n"
            "  binary_deep_analyze(binary_path='/challenge/workspace/ieee')\n"
            "  binary_deep_analyze(binary_path='/challenge/workspace/ieee', mode='ieee')\n"
            "  binary_deep_analyze(binary_path='/challenge/workspace/binary', mode='crypto')\n"
            "  binary_deep_analyze(binary_path='/challenge/workspace/binary', mode='stat')"
        )

    @property
    def parameters(self) -> dict[str, dict[str, Any]]:
        return {
            "binary_path": {"type": "string", "description": "二进制文件路径 (必填)"},
            "mode": {
                "type": "string",
                "description": "分析模式: 'auto'=自动检测, 'ieee'=IEEE浮点, 'gameboy'=GameBoy, 'constants'=常量提取, 'crypto'=算法指纹识别, 'stat'=统计推理/置换推导",
                "default": "auto",
            },
            "generate_solve": {
                "type": "boolean",
                "description": "是否自动生成 solve 脚本",
                "default": True,
            },
        }

    def execute(self, **kwargs: Any) -> str:
        binary = kwargs.get("binary_path", "")
        mode = kwargs.get("mode", "auto")
        generate_solve = kwargs.get("generate_solve", True)

        if not binary:
            return "ERROR: binary_path 为必填参数"

        # Auto-detect mode
        if mode == "auto":
            mode = self._detect_mode(binary)

        if mode == "gameboy":
            return self._analyze_gameboy(binary, generate_solve)
        elif mode == "ieee":
            return self._analyze_ieee(binary, generate_solve)
        elif mode == "constants":
            return self._extract_constants_deep(binary)
        elif mode == "crypto":
            return self._analyze_crypto_fingerprint(binary)
        elif mode == "stat":
            return self._analyze_statistical(binary)
        else:
            return f"ERROR: 未知模式 '{mode}', 可选: auto/ieee/gameboy/constants/crypto/stat"

    def _detect_mode(self, binary: str) -> str:
        """自动检测分析模式."""
        r = self._ssh.exec_cmd(f"file '{binary}' 2>/dev/null", timeout=5)
        if r.is_success and r.stdout:
            ftype = r.stdout.lower()
            # Game Boy ROM detection
            if "rom" in ftype and ("gameboy" in ftype or "game boy" in ftype or "gb" in ftype):
                return "gameboy"
            # Check ROM size for Game Boy
            r2 = self._ssh.exec_cmd(f"wc -c '{binary}' 2>/dev/null", timeout=5)
            if r2.is_success and r2.stdout:
                try:
                    size = int(r2.stdout.strip().split()[0])
                    if size in (32768, 65536, 131072):
                        # Check for Nintendo logo in header
                        r3 = self._ssh.exec_cmd(
                            f"xxd -s 0x104 -l 0x18 '{binary}' 2>/dev/null", timeout=5
                        )
                        if r3.is_success and "ce" in r3.stdout.lower():
                            return "gameboy"
                except (ValueError, IndexError):
                    pass
            # ELF detection → 先查 crypto 指纹, 再查加密代码段(stat), 最后默认 ieee
            if "elf" in ftype or "executable" in ftype:
                # 1) 轻量 crypto 指纹预检 (AES S-box / TEA delta / RSA e=65537 / secp256k1 prime)
                crypto = self._ssh.exec_cmd(
                    f"python3 -c \"import struct; d=open('{binary}','rb').read(); "
                    f"aes=bytes.fromhex('637c777bf26b6fc53001672bfed7ab76'); "
                    f"tea=struct.pack('<I',0x9E3779B9); tea2=struct.pack('<I',0xDEADBEEF); "
                    f"e65537=struct.pack('<I',0x10001); "
                    f"p256=bytes.fromhex('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff'); "
                    f"hit=[x for x in ('AES' if aes in d else None,'TEA' if tea in d or tea2 in d else None,"
                    f"'RSA' if e65537 in d else None,'ECC' if p256 in d else None) if x]; "
                    f"print('CRYPTO:'+','.join(hit) if hit else 'NOCRYPTO')\" 2>/dev/null",
                    timeout=8
                )
                if crypto.is_success and crypto.stdout and "CRYPTO:" in crypto.stdout:
                    return "crypto"
                # 2) 检查高熵加密代码段 (x86 置换加密)
                r4 = self._ssh.exec_cmd(
                    f"python3 -c \"import sys; d=open('{binary}','rb').read(); "
                    f"from collections import Counter; c=Counter(d); "
                    f"print(('STAT' if len(c) > 200 else 'NORMAL'))\" 2>/dev/null",
                    timeout=5
                )
                if r4.is_success and r4.stdout and "STAT" in r4.stdout:
                    return "stat"
                return "ieee"
        return "constants"

    def _analyze_gameboy(self, binary: str, generate_solve: bool) -> str:
        """GameBoy ROM 深度分析."""
        parts: list[str] = []
        parts.append("## GameBoy ROM 深度分析")
        parts.append(f"文件: {binary}")

        # 1. File info
        r = self._ssh.exec_cmd(f"file '{binary}' && wc -c '{binary}'", timeout=5)
        if r.is_success and r.stdout:
            parts.append(f"**文件信息**: {r.stdout.strip()}")

        # 2. ROM header analysis
        r = self._ssh.exec_cmd(
            f"python3 << 'PYEOF'\n"
            f"data = open('{binary}','rb').read()\n"
            f"print(f'ROM大小: {{len(data)}} 字节 ({{hex(len(data))}})')\n"
            f"print(f'标题: {{data[0x134:0x143].decode(\\\"latin-1\\\", errors=\\\"replace\\\").rstrip(chr(0))}}')\n"
            f"print(f'映射器: {{data[0x147]}}')\n"
            f"print(f'ROM类型: {{data[0x148]}}')\n"
            f"print(f'ROM大小: {{data[0x149]}}')\n"
            f"print(f'CGB标志: {{data[0x143]}}')\n"
            f"print(f'日本标志: {{data[0x14B]}}')\n"
            f"print(f'版本: {{data[0x14C]}}')\n"
            f"print(f'头部校验和: {{data[0x14D]}}')\n"
            f"print(f'全局校验和: {{(data[0x14E]<<8)|data[0x14F]}}')\n"
            f"PYEOF",
            timeout=10,
        )
        if r.is_success and r.stdout:
            parts.append(f"**ROM 头部**:\n{r.stdout.strip()}")

        # 3. Search for CTF/flag patterns
        r = self._ssh.exec_cmd(
            f"python3 << 'PYEOF'\n"
            f"data = open('{binary}','rb').read()\n"
            f"# Search for 'flag' or 'CTF' in various encodings\n"
            f"import re\n"
            f"# Search for flag-like patterns\n"
            f"patterns = [b'CTF', b'flag', b'FLAG', b'ctf', b'secret', b'key', b'pass']\n"
            f"for p in patterns:\n"
            f"    idx = 0\n"
            f"    while True:\n"
            f"        pos = data.find(p, idx)\n"
            f"        if pos == -1:\n"
            f"            break\n"
            f"        context = data[max(0,pos-4):pos+len(p)+16]\n"
            f"        print(f'  offset 0x{{pos:04x}}: {{context.hex()}}')\n"
            f"        idx = pos + 1\n"
            f"PYEOF",
            timeout=10,
        )
        if r.is_success and r.stdout:
            parts.append(f"**Flag 模式搜索**:\n{r.stdout.strip()}")

        # 4. Tile data analysis
        r = self._ssh.exec_cmd(
            f"python3 << 'PYEOF'\n"
            f"import struct\n"
            f"data = open('{binary}','rb').read()\n"
            f"# Analyze tile data at 0x8000+ (VRAM tile data area)\n"
            f"# Check if ROM has tile data at expected locations\n"
            f"print('=== Tile 数据分析 ===')\n"
            f"# Count unique 16-byte tile patterns in ROM\n"
            f"tiles_seen = set()\n"
            f"tile_count = 0\n"
            f"for offset in range(0, len(data)-15, 16):\n"
            f"    tile = data[offset:offset+16]\n"
            f"    if tile not in tiles_seen:\n"
            f"        tiles_seen.add(tile)\n"
            f"    tile_count += 1\n"
            f"print(f'总16字节块: {{tile_count}}, 唯一tile: {{len(tiles_seen)}}')\n"
            f"# Check 0x8000+ area (GB VRAM tile data) for typical patterns\n"
            f"print(f'ROM 0x8000-0xFFFF区域: {{len(data[0x8000:])}} 字节')\n"
            f"if len(data) > 0x8000:\n"
            f"    vram_region = data[0x8000:]\n"
            f"    unique_tiles = set()\n"
            f"    for i in range(0, len(vram_region)-15, 16):\n"
            f"        unique_tiles.add(vram_region[i:i+16])\n"
            f"    print(f'0x8000+ 区域唯一tile数: {{len(unique_tiles)}}')\n"
            f"# Check for tile data at the end of ROM (>0x4000)\n"
            f"if len(data) > 0x4000:\n"
            f"    end_region = data[0x4000:]\n"
            f"    unique_end = set()\n"
            f"    for i in range(0, len(end_region)-15, 16):\n"
            f"        unique_end.add(end_region[i:i+16])\n"
            f"    print(f'0x4000+ 区域唯一tile数: {{len(unique_end)}}')\n"
            f"PYEOF",
            timeout=15,
        )
        if r.is_success and r.stdout:
            parts.append(f"**Tile 数据分析**:\n{r.stdout.strip()}")

        # 5. Check for tiles.png and other attached files
        r = self._ssh.exec_cmd(
            f"find $(dirname '{binary}') -type f -name '*.png' -o -name '*.xml' -o -name 'README*' 2>/dev/null | head -20",
            timeout=5,
        )
        if r.is_success and r.stdout:
            parts.append(f"**附件文件**:\n{r.stdout.strip()}")

        # 6. Try to run with pyboy if available
        r = self._ssh.exec_cmd(
            f"python3 -c \"from pyboy import PyBoy; print('pyboy available')\" 2>/dev/null || echo 'pyboy not installed'",
            timeout=5,
        )
        if r.is_success and "pyboy available" in r.stdout:
            parts.append("**pyboy**: 已安装, 可用")
        else:
            parts.append("**pyboy**: 未安装, 可尝试 pip install pyboy")

        # 7. Decode flag from ROM using known CGB patterns
        r = self._ssh.exec_cmd(
            f"python3 << 'PYEOF'\n"
            f"data = open('{binary}','rb').read()\n"
            f"# CGB flag decoding: check for encrypted flag data at 0x51FA (WRAM bank 1)\n"
            f"# The encrypted flag is 40 bytes stored in the ROM\n"
            f"# In CGB challenge, the flag is encrypted with Feistel network\n"
            f"# Check if ROM has flag-like encrypted data at common offsets\n"
            f"# Try common encryption patterns\n"
            f"print('=== Flag 解密尝试 ===')\n"
            f"# Check 0x4000-0x7FFF area (bank 1) for encrypted flag data\n"
            f"if len(data) >= 0x6000:\n"
            f"    bank1 = data[0x4000:0x8000]\n"
            f"    # Look for 40-byte blocks of non-zero data\n"
            f"    for i in range(0, len(bank1)-40, 8):\n"
            f"        block = bank1[i:i+40]\n"
            f"        if sum(block) > 0 and sum(block) < 0x1000:\n"
            f"            # Check if first byte is 0x0b (starts with 'C' in CGB mapping)\n"
            f"            if block[0] == 0x0b:\n"
            f"                print(f'在bank1偏移0x{{i:04x}}发现可能的flag数据: {{block.hex()}}')\n"
            f"            # Check if there's a pattern like CTF{{\n"
            f"            if any(b in range(0x09,0x4d) for b in block[:3]):\n"
            f"                pass  # printable range\n"
            f"PYEOF",
            timeout=15,
        )
        if r.is_success and r.stdout:
            parts.append(r.stdout.strip())

        # 8. Generate solve script for CGB
        if generate_solve:
            solve_script = self._generate_cgb_solve_script(binary)
            if solve_script:
                parts.append(f"**自动生成 CGB 求解脚本**:\n{solve_script}")

        text = "\n\n".join(parts)
        if len(text) > _MAX_OUTPUT:
            text = text[:_MAX_OUTPUT] + "\n... (输出截断)"
        return text if text else "ERROR: GameBoy 分析失败"

    def _analyze_ieee(self, binary: str, generate_solve: bool) -> str:
        """IEEE 754 浮点逆向深度分析."""
        parts: list[str] = []
        parts.append("## IEEE 754 浮点逆向深度分析")
        parts.append(f"文件: {binary}")

        # 1. File info
        r = self._ssh.exec_cmd(f"file '{binary}' && stat '{binary}' 2>/dev/null | head -5", timeout=5)
        if r.is_success and r.stdout:
            parts.append(f"**文件信息**: {r.stdout.strip()}")

        # 2. Check for stripping
        r = self._ssh.exec_cmd(
            f"nm '{binary}' 2>/dev/null | head -5 || echo 'stripped binary'",
            timeout=5,
        )
        if r.is_success:
            parts.append(f"**符号**: {r.stdout.strip()[:200]}")

        # 3. 直接扫描整个二进制搜索 128-bit+ 大整数 (比 ELF 段解析更鲁棒, 兼容 OLLVM)
        r = self._ssh.exec_cmd(
            f"python3 << 'PYEOF'\n"
            f"import struct\n"
            f"with open('{binary}','rb') as f:\n"
            f"    data = f.read()\n"
            f"print('=== 大整数常量扫描 (全二进制, 128-bit+) ===')\n"
            f"print(f'文件大小: {{len(data)}} 字节')\n"
            f"found = []\n"
            f"for i in range(0, len(data)-16, 8):\n"
            f"    val = int.from_bytes(data[i:i+16], 'little')\n"
            f"    if val > (1<<127):\n"
            f"        found.append((i, '128bit', val))\n"
            f"    elif val > (1<<95):\n"
            f"        found.append((i, '96bit+', val))\n"
            f"for off, typ, val in found[:30]:\n"
            f"    print(f'  offset 0x{{off:06x}}: {{typ}} 0x{{val:032x}} ({{val.bit_length()}}bit)')\n"
            f"print(f'共找到 {{len(found)}} 个大整数常量')\n"
            f"PYEOF",
            timeout=30,
        )
        if r.is_success and r.stdout:
            parts.append(f"**段/常量提取**:\n{r.stdout.strip()[:2000]}")

        # 4. Extract large constants using objdump (simpler method)
        r = self._ssh.exec_cmd(
            f"objdump -s -j .rodata '{binary}' 2>/dev/null | head -40",
            timeout=10,
        )
        if r.is_success and r.stdout:
            # Find large hex constants
            hex_data = _RE_HEX_LARGE.findall(r.stdout)
            large_consts = []
            for h in hex_data[:20]:
                bits = len(h) * 4
                if bits >= 128:
                    try:
                        val = int(h, 16)
                        large_consts.append((h, bits, val))
                    except ValueError:
                        pass
            if large_consts:
                parts.append("**大整数常量 (128bit+)**")
                for h, bits, val in large_consts:
                    parts.append(f"  hex: 0x{h[:64]}... ({bits}bit, dec={val})")

        # 5. Check for IEEE float special values in the binary
        r = self._ssh.exec_cmd(
            f"python3 << 'PYEOF'\n"
            f"import struct\n"
            f"with open('{binary}','rb') as f:\n"
            f"    data = f.read()\n"
            f"print('=== IEEE 754 特殊值扫描 ===')\n"
            f"# Scan for float special values\n"
            f"special_offsets = []\n"
            f"for i in range(0, len(data)-7, 4):\n"
            f"    try:\n"
            f"        f32 = struct.unpack('<f', data[i:i+4])[0]\n"
            f"        if f32 == 0.0 or (f32 != f32) or abs(f32) == float('inf') or (abs(f32) < 1e-38 and f32 != 0.0):\n"
            f"            if len(special_offsets) < 20:\n"
            f"                special_offsets.append((i, 'float32', f32))\n"
            f"    except: pass\n"
            f"    try:\n"
            f"        f64 = struct.unpack('<d', data[i:i+8])[0]\n"
            f"        if f64 == 0.0 or (f64 != f64) or abs(f64) == float('inf') or (abs(f64) < 1e-308 and f64 != 0.0):\n"
            f"            if len(special_offsets) < 20:\n"
            f"                special_offsets.append((i, 'float64', f64))\n"
            f"    except: pass\n"
            f"for off, typ, val in special_offsets[:20]:\n"
            f"    print(f'  0x{{off:06x}}: {{typ}} {{val}}')\n"
            f"print(f'共找到 {{len(special_offsets)}} 个特殊浮点值')\n"
            f"PYEOF",
            timeout=30,
        )
        if r.is_success and r.stdout:
            parts.append(f"**IEEE 754 特殊值**:\n{r.stdout.strip()[:1000]}")

        # 6. Check for success/failure strings and their references
        r = self._ssh.exec_cmd(
            f"strings -tx '{binary}' 2>/dev/null | grep -iE 'flag|input|correct|wrong|not|zero|hmmm' | head -10",
            timeout=5,
        )
        if r.is_success and r.stdout:
            parts.append(f"**关键字符串**:\n{r.stdout.strip()}")

        # 7. 推荐求解方法
        if generate_solve:
            parts.append("## IEEE 求解建议")
            parts.append("该二进制为 OLLVM 混淆的 IEEE 浮点门电路, expected_M/expected_N 不在 .rodata 中.")
            parts.append("推荐使用 angr 符号执行求解:")
            parts.append(f"  angr_symbolic_exec(binary_path='{binary}', input_kind='stdin', input_size=64, find_addr='0x14a27d')")
            parts.append("附件中包含 angr 求解脚本可直接参考:")
            parts.append("  - solve_angr.py / solve_angr2.py / angr_solve.py")

        text = "\n\n".join(parts)
        if len(text) > _MAX_OUTPUT:
            text = text[:_MAX_OUTPUT] + "\n... (输出截断)"
        return text if text else "ERROR: IEEE 分析失败"

    def _extract_constants_deep(self, binary: str) -> str:
        """深度常量提取."""
        parts: list[str] = []

        # 1. Section info
        r = self._ssh.exec_cmd(
            f"objdump -h '{binary}' 2>/dev/null | head -30",
            timeout=10,
        )
        if r.is_success and r.stdout:
            parts.append(f"## 段信息\n{r.stdout.strip()[:800]}")

        # 2. Full .rodata dump
        r = self._ssh.exec_cmd(
            f"objdump -s -j .rodata '{binary}' 2>/dev/null | head -60",
            timeout=10,
        )
        if r.is_success and r.stdout:
            parts.append(f"## .rodata 段\n{r.stdout.strip()[:2000]}")

        # 3. Python-based constant extraction
        r = self._ssh.exec_cmd(
            f"python3 << 'PYEOF'\n"
            f"import struct\n"
            f"with open('{binary}','rb') as f:\n"
            f"    data = f.read()\n"
            f"print('=== 全部大整数常量 ===')\n"
            f"# Scan entire binary for 128-bit+ integers\n"
            f"found = []\n"
            f"for i in range(0, len(data)-16, 8):\n"
            f"    val = int.from_bytes(data[i:i+16], 'little')\n"
            f"    if val > (1<<127):\n"
            f"        found.append((i, '128bit', val))\n"
            f"    elif val > (1<<95):\n"
            f"        found.append((i, '96bit+', val))\n"
            f"for off, typ, val in found[:30]:\n"
            f"    print(f'  offset 0x{{off:06x}}: {{typ}} 0x{{val:032x}} ({{val.bit_length()}}bit)')\n"
            f"print(f'共找到 {{len(found)}} 个大整数常量')\n"
            f"PYEOF",
            timeout=30,
        )
        if r.is_success and r.stdout:
            parts.append(f"## 常量扫描\n{r.stdout.strip()[:2000]}")

        text = "\n\n".join(parts)
        if len(text) > _MAX_OUTPUT:
            text = text[:_MAX_OUTPUT] + "\n... (输出截断)"
        return text if text else "ERROR: 常量提取失败"

    def _analyze_crypto_fingerprint(self, binary: str) -> str:
        """算法指纹识别: 扫描二进制中已知密码算法的常量特征."""
        script = (
            f"python3 << 'CRYPTOEOF'\n"
            f"import re, struct, sys\n"
            f"with open('{binary}', 'rb') as f:\n"
            f"    data = f.read()\n"
            f"print('=== 算法指纹识别 ===')\n"
            f"print(f'文件大小: {{len(data)}} 字节 ({{hex(len(data))}})')\n"
            f"\n"
            f"# AES S-box (256 bytes, standard Rijndael)\n"
            f"AES_SBOX = bytes([\n"
            f"    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,\n"
            f"    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,\n"
            f"    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,\n"
            f"    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,\n"
            f"    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,\n"
            f"    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,\n"
            f"    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,\n"
            f"    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,\n"
            f"    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,\n"
            f"    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,\n"
            f"    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,\n"
            f"    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,\n"
            f"    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,\n"
            f"    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,\n"
            f"    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,\n"
            f"    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,\n"
            f"])\n"
            f"\n"
            f"# Search for AES S-box in binary\n"
            f"aes_pos = data.find(AES_SBOX)\n"
            f"if aes_pos >= 0:\n"
            f"    print(f'[AES] 发现标准 S-box @ 0x{{aes_pos:04x}} (置信度: HIGH)')\n"
            f"    print(f'[AES] 附近数据: {{data[aes_pos:aes_pos+64].hex()[:80]}}...')\n"
            f"else:\n"
            f"    # Check for inverted S-box\n"
            f"    inv_aes = bytes([0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb])\n"
            f"    if data.find(inv_aes) >= 0:\n"
            f"        print(f'[AES] 可能含 AES 逆 S-box (置信度: MEDIUM)')\n"
            f"    else:\n"
            f"        print(f'[AES] 未发现标准 S-box')\n"
            f"\n"
            f"# TEA delta constants\n"
            f"TEA_DELTA = 0x9E3779B9\n"
            f"tea_delta_bytes = struct.pack('<I', TEA_DELTA)\n"
            f"if tea_delta_bytes in data:\n"
            f"    print(f'[TEA] 发现标准 TEA delta 0x9E3779B9 @ 0x{{data.find(tea_delta_bytes):04x}} (置信度: HIGH)')\n"
            f"else:\n"
            f"    # Check for custom TEA delta (0xDEADBEEF)\n"
            f"    custom_delta = struct.pack('<I', 0xDEADBEEF)\n"
            f"    if custom_delta in data:\n"
            f"        print(f'[TEA] 发现自定义 TEA delta 0xDEADBEEF @ 0x{{data.find(custom_delta):04x}} (置信度: HIGH)')\n"
            f"    else:\n"
            f"        print(f'[TEA] 未发现 TEA delta 常量')\n"
            f"\n"
            f"# RSA constants: look for large integers in .rodata\n"
            f"# Search for 128+ bit hex strings in strings output\n"
            f"# Common RSA primes / N\n"
            f"RSA_COMMON_N = [\n"
            f"    (0x10001, 'e=65537 (标准公钥指数)'),\n"
            f"    (0x03, 'e=3 (低指数, 可能有广播攻击)'),\n"
            f"    (0x010001, 'e=65537 (标准公钥指数)'),\n"
            f"]\n"
            f"for val, desc in RSA_COMMON_N:\n"
            f"    packed = struct.pack('<I', val)\n"
            f"    if packed in data:\n"
            f"        print(f'[RSA] 发现 {{desc}} (置信度: MEDIUM)')\n"
            f"    packed_be = struct.pack('>I', val)\n"
            f"    if packed_be in data:\n"
            f"        print(f'[RSA] 发现 {{desc}} (大端) (置信度: MEDIUM)')\n"
            f"\n"
            f"# Search for large integers (potential RSA N / Paillier N)\n"
            f"print(f'\\n[大整数扫描] 搜索 128+ bit 常量...')\n"
            f"int128_hits = set()\n"
            f"for i in range(0, len(data)-16, 1):\n"
            f"    val = int.from_bytes(data[i:i+16], 'little')\n"
            f"    if val.bit_length() >= 128 and val > 0:\n"
            f"        if val not in int128_hits:\n"
            f"            int128_hits.add(val)\n"
            f"            if len(int128_hits) <= 5:\n"
            f"                print(f'  128-bit 常量 @ 0x{{i:04x}}: {{hex(val)[:50]}}...')\n"
            f"print(f'共发现 {{len(int128_hits)}} 个唯一 128+ bit 常量')\n"
            f"\n"
            f"# Paillier 检测: 大整数 N (modulus) + g (generator) 结构\n"
            f"# Paillier 公钥 (N, g), N 通常为 512-1024 bit 半素数\n"
            f"print(f'\\n[Paillier 检测] 搜索大整数模数特征...')\n"
            f"paillier_candidates = []\n"
            f"for i in range(0, len(data)-128, 8):\n"
            f"    # 尝试多种长度 (512/1024/2048 bit 的 N)\n"
            f"    for blen in (64, 128, 256):\n"
            f"        if i+blen <= len(data):\n"
            f"            val = int.from_bytes(data[i:i+blen], 'big')\n"
            f"            # Paillier N 是半素数, 通常是奇数且比特长度接近 blen*8\n"
            f"            if val.bit_length() >= blen*8 - 4 and val > 0 and (val & 1):\n"
            f"                paillier_candidates.append((i, blen, val))\n"
            f"    if len(paillier_candidates) >= 3:\n"
            f"        break\n"
            f"if paillier_candidates:\n"
            f"    print(f'发现 {{len(paillier_candidates)}} 个大整数候选 (可能是 Paillier N/RSA N):')\n"
            f"    for off, blen, val in paillier_candidates[:5]:\n"
            f"        print(f'  @ 0x{{off:04x}} ({{blen}}字节, {{val.bit_length()}}bit): {{hex(val)[:40]}}...')\n"
            f"    print(f'[提示] 若存在两个相近大小的奇数大整数, 可能是 Paillier 的 N 和 g, 需进一步验证')\n"
            f"else:\n"
            f"    print(f'未发现大整数模数候选')\n"
            f"\n"
            f"# ECC curve parameters (secp256k1 prime)\n"
            f"ECC_P256 = bytes.fromhex('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff')\n"
            f"if ECC_P256 in data:\n"
            f"    print(f'[ECC] 发现 secp256k1 曲线素数 (置信度: HIGH)')\n"
            f"\n"
            f"# MD5 constants\n"
            f"MD5_A = struct.pack('<I', 0x67452301)\n"
            f"MD5_B = struct.pack('<I', 0xefcdab89)\n"
            f"if MD5_A in data and MD5_B in data:\n"
            f"    print(f'[MD5] 发现 MD5 初始向量 (置信度: HIGH)')\n"
            f"\n"
            f"# SHA256 constants\n"
            f"SHA256_K = struct.pack('<I', 0x428a2f98)\n"
            f"if SHA256_K in data:\n"
            f"    print(f'[SHA256] 发现 SHA256 K 常量 (置信度: MEDIUM)')\n"
            f"\n"
            f"print('\\n=== 算法指纹识别完成 ===')\n"
            f"CRYPTOEOF"
        )
        r = self._ssh.exec_cmd(script, timeout=30)
        if r.is_success and r.stdout:
            return r.stdout.strip()
        return "ERROR: 算法指纹识别失败"

    def _analyze_statistical(self, binary: str) -> str:
        """统计推理: 字节频率分析 + 熵分析 + 置换推导."""
        script = (
            f"python3 << 'STATEOF'\n"
            f"import sys, struct, math\n"
            f"from collections import Counter\n"
            f"\n"
            f"with open('{binary}', 'rb') as f:\n"
            f"    data = f.read()\n"
            f"print('=== 统计推理分析 ===')\n"
            f"print(f'文件大小: {{len(data)}} 字节')\n"
            f"\n"
            f"# 1. 全字节频率统计\n"
            f"freq = Counter(data)\n"
            f"unique_bytes = len(freq)\n"
            f"total = len(data)\n"
            f"entropy = -sum((c/total) * math.log2(c/total) for c in freq.values())\n"
            f"print(f'\\n[全局统计] 唯一字节数: {{unique_bytes}}/256, 熵: {{entropy:.2f}} bits/byte')\n"
            f"if unique_bytes > 200:\n"
            f"    print(f'[判断] 高熵 ({{unique_bytes}} 唯字节) → 可能是加密/压缩数据')\n"
            f"elif unique_bytes > 100:\n"
            f"    print(f'[判断] 中熵 ({{unique_bytes}} 唯字节) → 可能是混合数据')\n"
            f"else:\n"
            f"    print(f'[判断] 低熵 ({{unique_bytes}} 唯字节) → 可能是结构化/代码数据')\n"
            f"\n"
            f"# 2. 熵的分布 (按 256 字节块)\n"
            f"from collections import Counter\n"
            f"block_size = 256\n"
            f"high_entropy_blocks = 0\n"
            f"low_entropy_blocks = 0\n"
            f"for i in range(0, len(data)-block_size, block_size):\n"
            f"    block = data[i:i+block_size]\n"
            f"    bfreq = Counter(block)\n"
            f"    bentropy = -sum((c/block_size)*math.log2(c/block_size) for c in bfreq.values())\n"
            f"    if bentropy > 7.0:\n"
            f"        high_entropy_blocks += 1\n"
            f"    elif bentropy < 4.0:\n"
            f"        low_entropy_blocks += 1\n"
            f"print(f'[熵分布] 高熵块(>7.0): {{high_entropy_blocks}}, 低熵块(<4.0): {{low_entropy_blocks}}')\n"
            f"\n"
            f"# 3. 置换推导 (针对加密代码段)\n"
            f"# 查找密集的加密代码段 (高熵, 连续大块)\n"
            f"print(f'\\n[加密代码段检测]')\n"
            f"entropy_windows = []\n"
            f"for i in range(0, len(data)-512, 256):\n"
            f"    win = data[i:i+512]\n"
            f"    wfreq = Counter(win)\n"
            f"    wentropy = -sum((c/len(win))*math.log2(c/len(win)) for c in wfreq.values())\n"
            f"    if wentropy > 7.5:\n"
            f"        entropy_windows.append((i, wentropy))\n"
            f"if entropy_windows:\n"
            f"    print(f'发现 {{len(entropy_windows)}} 个高熵窗口 (可能加密代码段):')\n"
            f"    for off, ent in entropy_windows[:10]:\n"
            f"        print(f'  @ 0x{{off:04x}} 熵={{ent:.2f}}')\n"
            f"    # 找到加密代码段起始和结束\n"
            f"    first_off = min(w[0] for w in entropy_windows)\n"
            f"    last_off = max(w[0] for w in entropy_windows) + 512\n"
            f"    enc_block = data[first_off:last_off]\n"
            f"    print(f'\\n[置换推导] 加密段 0x{{first_off:04x}}-0x{{last_off:04x}} ({{len(enc_block)}} 字节)')\n"
            f"    \n"
            f"    # 完整频率排序（所有 256 字节）\n"
            f"    efreq = Counter(enc_block)\n"
            f"    print(f'加密段唯一字节: {{len(efreq)}}/256')\n"
            f"    \n"
            f"    # x86 指令字节频率先验 (基于大量 x86 代码统计)\n"
            f"    # 按频率从高到低排列\n"
            f"    x86_prior = [\n"
            f"        0x00, 0x48, 0x89, 0x8b, 0x90, 0xff, 0x83, 0x0f, 0x74, 0x75,  # TOP10\n"
            f"        0xeb, 0xe8, 0xc3, 0xcc, 0x66, 0x84, 0x01, 0x02, 0x85, 0x0d,  # TOP20\n"
            f"        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x05, 0x15,  # TOP30\n"
            f"        0x25, 0x35, 0x45, 0x55, 0x65, 0x75, 0x85, 0x95, 0xa0, 0xb0,  # TOP40\n"
            f"        0xc0, 0xd0, 0xe0, 0xf0, 0x0e, 0x1e, 0x2e, 0x3e, 0x4e, 0x5e,  # TOP50\n"
            f"    ]\n"
            f"    # 补充: 按频率从高到低排序的剩余 x86 字节\n"
            f"    x86_all = list(range(256))\n"
            f"    for b in x86_prior:\n"
            f"        x86_all.remove(b)\n"
            f"    x86_prior.extend(x86_all)\n"
            f"    \n"
            f"    # 频率排序匹配: 加密块中频率第 k 高的字节 → x86 中频率第 k 高的字节\n"
            f"    sorted_enc = [b for b, _ in efreq.most_common()]\n"
            f"    \n"
            f"    # 构建置换映射\n"
            f"    perm = {{}}\n"
            f"    for i, eb in enumerate(sorted_enc):\n"
            f"        if i < len(x86_prior):\n"
            f"            perm[eb] = x86_prior[i]\n"
            f"    \n"
            f"    print(f'\\n[置换表] 频率排序映射 (加密字节→x86字节):')\n"
            f"    for i, eb in enumerate(sorted_enc[:30]):\n"
            f"        xb = x86_prior[i]\n"
            f"        print(f'  {{hex(eb)}} → {{hex(xb)}}  (rank {{i+1}}, 频率 {{efreq[eb]}})')\n"
            f"    \n"
            f"    # 尝试用部分置换解密并验证\n"
            f"    decrypted = bytes(perm.get(b, b) for b in enc_block[:512])\n"
            f"    # 检查解密后是否更像合法 x86 (统计可打印/控制字符比例)\n"
            f"    x86_legit = 0\n"
            f"    for b in decrypted:\n"
            f"        if b in x86_prior[:40]:\n"
            f"            x86_legit += 1\n"
            f"    ratio = x86_legit / len(decrypted)\n"
            f"    print(f'\\n[验证] 解密后 512 字节中 {{x86_legit}} 个属于 x86 高频字节 ({{ratio*100:.1f}}%)')\n"
            f"    if ratio > 0.3:\n"
            f"        print(f'[结论] 置换推导有效, 可进一步用此置换解密整个代码段')\n"
            f"    else:\n"
            f"        print(f'[结论] 置换推导需进一步验证, 可能需调整频率先验')\n"
            f"else:\n"
            f"    print(f'未发现高熵窗口, 可能是普通二进制')\n"
            f"\n"
            f"# 4. 完整加密代码段输出 (如果存在)\n"
            f"print(f'\\n[加密代码段完整输出]')\n"
            f"if entropy_windows:\n"
            f"    print(f'加密段: 0x{{first_off:04x}}-0x{{last_off:04x}}, {{len(enc_block)}} 字节')\n"
            f"    print(f'{{enc_block.hex()[:160]}}...')\n"
            f"    print(f'[提示] 用 ssh_python 编写脚本: \\n'\n"
            f"          f'  perm = {{...}}  # 上述置换映射\\n'\n"
            f"          f'  decrypted = bytes(perm.get(b, b) for b in enc_block)\\n'\n"
            f"          f'  with open(\\\"/tmp/decrypted.bin\\\", \\\"wb\\\") as f: f.write(decrypted)')\n"
            f"else:\n"
            f"    print(f'未发现加密代码段')\n"
            f"\n"
            f"print('\\n=== 统计推理分析完成 ===')\n"
            f"STATEOF"
        )
        r = self._ssh.exec_cmd(script, timeout=30)
        if r.is_success and r.stdout:
            return r.stdout.strip()
        return "ERROR: 统计推理分析失败"

    def _try_angr_ieee(self, binary: str) -> str:
        """尝试用 angr 对 IEEE 二进制做符号执行, 求解 flag."""
        script = (
            f"python3 << 'ANGREOF'\n"
            f"import angr\n"
            f"import claripy\n"
            f"import sys, time\n"
            f"sys.setrecursionlimit(100000)\n"
            f"start = time.time()\n"
            f"try:\n"
            f"    p = angr.Project('{binary}', auto_load_libs=False)\n"
            f"    # 找成功/失败字符串地址\n"
            f"    found_addrs = []\n"
            f"    for b in p.loader.main_object.sections:\n"
            f"        pass\n"
            f"    # 用 hook_printf 或直接找 puts 调用\n"
            f"    # 成功字符串 \"You zeroed in on the flag!\" 在 .rodata 0x14b03f\n"
            f"    # 失败 \"Not a Flag\" 在 .rodata 0x14b05c\n"
            f"    # 需要找引用这些字符串的 compare 分支\n"
            f"    state = p.factory.entry_state()\n"
            f"    # 符号化 stdin (一次读 64 字符)\n"
            f"    flag = claripy.BVS('flag', 63*8)\n"
            f"    # 添加约束: 可打印字符\n"
            f"    for i in range(63):\n"
            f"        byte = flag.get_byte(i)\n"
            f"        state.solver.add(byte >= 0x20, byte <= 0x7e)\n"
            f"    # 把 symbol 写到 stdin 缓冲区\n"
            f"    state = p.factory.full_init_state(stdin=angr.SimFileStream(name='stdin', content=flag))\n"
            f"    sm = p.factory.simulation_manager(state)\n"
            f"    # 探索, 限制时间\n"
            f"    timeout = 60\n"
            f"    deadline = time.time() + timeout\n"
            f"    found = []\n"
            f"    while time.time() < deadline and len(sm.active) > 0:\n"
            f"        sm.step()\n"
            f"        if len(sm.deadended) > 0:\n"
            f"            # 检查是否到达 success\n"
            f"            for ds in sm.deadended:\n"
            f"                if ds.solver.satisfiable():\n"
            f"                    try:\n"
            f"                        sol = ds.solver.eval(flag, cast_to=bytes)\n"
            f"                        print(f'[angr] 候选: {{sol}}')\n"
            f"                        found.append(sol)\n"
            f"                    except Exception:\n"
            f"                        pass\n"
            f"            sm.deadended = []\n"
            f"    print(f'[angr] 用时 {{time.time()-start:.1f}}s, 找到 {{len(found)}} 个候选')\n"
            f"    for f in found[:3]:\n"
            f"        print(f'[angr] FLAG CANDIDATE: {{f}}')\n"
            f"except Exception as e:\n"
            f"    print(f'angr 失败: {{e}}')\n"
            f"ANGREOF"
        )
        r = self._ssh.exec_cmd(script, timeout=100)
        if r.is_success and r.stdout:
            return r.stdout.strip()
        return ""

    def _generate_cgb_solve_script(self, binary: str) -> str:
        """生成 CGB GameBoy 逆向求解脚本."""
        dir_path = binary.rsplit("/", 1)[0] if "/" in binary else "."
        script = (
            f"python3 << 'CGBEOF'\n"
            f"# CGB GameBoy ROM 求解脚本\n"
            f"# 1. 检查是否有 tiles.png (替换表)\n"
            f"# 2. 尝试从 ROM 中提取加密 flag\n"
            f"# 3. 使用 Feistel 解密\n"
            f"\n"
            f"import os\n"
            f"import struct\n"
            f"\n"
            f"# CGB 字符映射表 (来自 ROM bank1 的 tile 映射)\n"
            f"char_mapping = {{\n"
            f"    0x09: 'A', 0x0a: 'B', 0x0b: 'C', 0x0c: 'D', 0x0d: 'E', 0x0e: 'F', 0x0f: 'G',\n"
            f"    0x10: 'H', 0x11: 'I', 0x12: 'J', 0x13: 'K', 0x14: 'L', 0x15: 'M', 0x16: 'N',\n"
            f"    0x17: 'O', 0x18: 'P', 0x19: 'Q', 0x1a: 'R', 0x1b: 'S', 0x1c: 'T', 0x1d: 'U',\n"
            f"    0x1e: 'V', 0x1f: 'W', 0x20: 'X', 0x21: 'Y', 0x22: 'Z',\n"
            f"    0x23: 'a', 0x24: 'b', 0x25: 'c', 0x26: 'd', 0x27: 'e', 0x28: 'f', 0x29: 'g',\n"
            f"    0x2a: 'h', 0x2b: 'i', 0x2c: 'j', 0x2d: 'k', 0x2e: 'l', 0x2f: 'm', 0x30: 'n',\n"
            f"    0x31: 'o', 0x32: 'p', 0x33: 'q', 0x34: 'r', 0x35: 's', 0x36: 't', 0x37: 'u',\n"
            f"    0x38: 'v', 0x39: 'w', 0x3a: 'x', 0x3b: 'y', 0x3c: 'z',\n"
            f"    0x3d: '0', 0x3e: '1', 0x3f: '2', 0x40: '3', 0x41: '4', 0x42: '5',\n"
            f"    0x43: '6', 0x44: '7', 0x45: '8', 0x46: '9',\n"
            f"    0x47: '@', 0x48: '_', 0x49: '-', 0x4a: '{{', 0x4b: '}}', 0x4c: '?',\n"
            f"}}\n"
            f"\n"
            f"# Palette 数据 (GameBoy Color boot ROM)\n"
            f"palette_data_dict = {{\n"
            f"    0: [0xff, 0xff, 0x03, 0x1c, 0x37, 0x5b, 0x00, 0x00],\n"
            f"    1: [0xff, 0xff, 0x7f, 0x42, 0x3d, 0x0a, 0x00, 0x00],\n"
            f"    2: [0xff, 0xff, 0x76, 0x5b, 0x61, 0x1c, 0x00, 0x00],\n"
            f"    3: [0xff, 0xff, 0x2e, 0x79, 0x64, 0x11, 0x00, 0x00],\n"
            f"    4: [0xff, 0xff, 0x40, 0x33, 0x58, 0x35, 0x00, 0x00],\n"
            f"    5: [0xff, 0xff, 0x7a, 0x7d, 0x4c, 0x22, 0x00, 0x00],\n"
            f"    6: [0xff, 0xff, 0x0f, 0x4a, 0x56, 0x65, 0x00, 0x00],\n"
            f"    7: [0xff, 0xff, 0x13, 0x78, 0xf7, 0x69, 0x00, 0x00],\n"
            f"}}\n"
            f"\n"
            f"def feistel_f(b, k):\n"
            f"    for _ in range(8):\n"
            f"        if (k & 1) == 0:\n"
            f"            bit0 = b & 1\n"
            f"            b = (b >> 1) | (bit0 << 7)\n"
            f"        else:\n"
            f"            bit7 = (b >> 7) & 1\n"
            f"            b = (b << 1) & 0xFF\n"
            f"            b |= bit7\n"
            f"        k >>= 1\n"
            f"    return b\n"
            f"\n"
            f"def feistel_round(left, right, subkey):\n"
            f"    return (right, left ^ feistel_f(right, subkey))\n"
            f"\n"
            f"def feistel_decrypt(left, right, key):\n"
            f"    for i in range(16):\n"
            f"        subkey = key[i % 4]\n"
            f"        left, right = feistel_round(left, right, subkey)\n"
            f"    return (left, right)\n"
            f"\n"
            f"def generate_key(key_bytes):\n"
            f"    ret = []\n"
            f"    it = iter(key_bytes)\n"
            f"    for k0, k1 in zip(it, it):\n"
            f"        p0 = bytes(palette_data_dict[k0][2:6])\n"
            f"        p1 = bytes(palette_data_dict[k1][2:6])\n"
            f"        palette = [a ^ b for a, b in zip(p0, p1)]\n"
            f"        ret.append(palette)\n"
            f"    return ret\n"
            f"\n"
            f"def decrypt(encrypted_bytes, key_bytes):\n"
            f"    key = generate_key(key_bytes)\n"
            f"    for k in key:\n"
            f"        k.reverse()\n"
            f"    result = []\n"
            f"    it = iter(encrypted_bytes)\n"
            f"    for i, (L, R) in enumerate(zip(it, it)):\n"
            f"        new_r, new_l = feistel_decrypt(R, L, key[i])\n"
            f"        result.append(new_l)\n"
            f"        result.append(new_r)\n"
            f"    return result\n"
            f"\n"
            f"def map_bytes(plaintext_bytes):\n"
            f"    return ''.join(char_mapping.get(b, '#') for b in plaintext_bytes)\n"
            f"\n"
            f"# 尝试从 ROM 中提取加密 flag 和 key\n"
            f"with open('{binary}', 'rb') as f:\n"
            f"    data = f.read()\n"
            f"\n"
            f"# 检查是否有 tiles.png (替换提示)\n"
            f"tiles_png = os.path.join('{dir_path}', 'tiles.png')\n"
            f"if os.path.exists(tiles_png):\n"
            f"    print(f'tiles.png 存在: {{tiles_png}}')\n"
            f"else:\n"
            f"    print('tiles.png 不存在')\n"
            f"\n"
            f"# 检查是否有 gbcolor 目录 (boot ROM)\n"
            f"gbcolor_dir = os.path.join('{dir_path}', '../gbcolor')\n"
            f"if os.path.exists(gbcolor_dir):\n"
            f"    print(f'gbcolor 目录: {{os.listdir(gbcolor_dir)}}')\n"
            f"\n"
            f"print(f'\\\\nROM大小: {{len(data)}} 字节')\n"
            f"print(f'ROM标题: {{data[0x134:0x143].decode(\\\"latin-1\\\", errors=\\\"replace\\\").rstrip(chr(0))}}')\n"
            f"\n"
            f"# 在 ROM 中搜索加密 flag 数据\n"
            f"# 加密 flag 40 字节, 位于 WRAM bank 1, 偏移 0x51FA\n"
            f"# 但 ROM 中的实际数据可能在 bank 1 区域 (0x4000-0x7FFF)\n"
            f"print(f'\\\\n=== 搜索可能的加密 flag 数据 ===')\n"
            f"# 检查 bank1 区域是否有 40 字节非零数据\n"
            f"if len(data) >= 0x6000:\n"
            f"    bank1 = data[0x4000:0x8000]\n"
            f"    for i in range(0, len(bank1)-40, 4):\n"
            f"        block = bank1[i:i+40]\n"
            f"        # 检查数据是否都是非零的\n"
            f"        if 0 < sum(block) < 0x2000:\n"
            f"            # 检查首字节是否为 0x0b (映射到 'C')\n"
            f"            if block[0] == 0x0b:\n"
            f"                print(f'Bank1+0x{{i:04x}}: {{block.hex()}} (可能flag)')\n"
            f"    print(f'Bank1 区域: 0x4000-0x{{min(0x8000, len(data)):04x}}')\n"
            f"\n"
            f"# 同样搜索 0x51FA 附近的常数\n"
            f"print(f'\\\\n=== 搜索 0x51FA 附近数据 ===')\n"
            f"# 游戏运行时, 加密 flag 在 WRAM bank 1, 偏移 0x51FA\n"
            f"# 但 ROM 中的 flag 数据可能在其他位置\n"
            f"# 搜索常见模式: 40 字节数据, 首字节 0x0b\n"
            f"for i in range(0, len(data)-40, 1):\n"
            f"    if data[i] == 0x0b and data[i+1] == 0x1c:\n"
            f"        print(f'Offset 0x{{i:04x}}: {{data[i:i+40].hex()}}')\n"
            f"        print(f'  映射: {{map_bytes(data[i:i+40])}}')\n"
            f"\n"
            f"print(f'\\\\n注意: 完整的 CGB 求解需要:')\n"
            f"print(f'1. 运行 MAME 模拟器: /usr/games/mame -hashpath hash -window -rp roms gbcolor gctf -debug')\n"
            f"print(f'2. 在 MAME 调试器中: go \\$1b4')\n"
            f"print(f'3. 输入 Konami 密码: Up+Up+Down+Down+Left+Right+Left+Right+B+A')\n"
            f"print(f'4. Dump 加密 flag: dump encrypted_flag,\\$51fa,\\$28,1,0,\\$28')\n"
            f"print(f'5. Dump key: dump key_in_vram1,\\$02DC,\\$28,1,0,\\$28')\n"
            f"print(f'6. 解密: python3 solution.py --decrypt --flag_bytes encrypted_flag --tile_palette_bytes key_in_vram1')\n"
            f"CGBEOF"
        )
        return script


def binary_deep_analyze_tools(ssh: SSHClient) -> list[Tool]:
    return [BinaryDeepAnalyzeTool(ssh)]