"""binary_constants: 从二进制中提取常量并辅助逆向分析.

功能:
1. 提取二进制中的大整数常量 (128/256/512-bit)
2. 识别常见的 IEEE 浮点特殊值
3. 提取 .rodata 段中的字符串和结构化数据
4. 输出反汇编关键函数

用法:
    binary_constants(binary_path, deep=True)
"""
from __future__ import annotations

import re
from typing import Any

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool

_MAX_OUTPUT = 5000
_RE_HEX_LARGE = re.compile(r"[0-9a-fA-F]{32,}")  # 128+ bit hex constants


class BinaryConstantsTool(Tool):
    """从二进制中提取常量并辅助逆向分析."""

    def __init__(self, ssh: SSHClient) -> None:
        super().__init__()
        self._ssh = ssh

    @property
    def name(self) -> str:
        return "binary_constants"

    @property
    def description(self) -> str:
        return (
            "从二进制中提取常量并辅助逆向分析.\n"
            "参数:\n"
            "  binary_path: 二进制文件路径 (必填)\n"
            "  deep: 是否深度分析 (默认 True, 包含反汇编/常量提取)\n"
            "  extract_constants: 是否提取大整数常量 (默认 True)\n"
            "  extract_floats: 是否提取浮点常量 (默认 True)\n"
            "  disasm_func: 指定反汇编函数名 (可选, 默认自动分析 main)\n"
            "用法:\n"
            "  binary_constants(binary_path='/challenge/workspace/ieee')\n"
            "  binary_constants(binary_path='/challenge/workspace/ieee', deep=True, extract_constants=True)"
        )

    @property
    def parameters(self) -> dict[str, dict[str, Any]]:
        return {
            "binary_path": {"type": "string", "description": "二进制文件路径 (必填)"},
            "deep": {"type": "boolean", "description": "深度分析 (默认 True)", "default": True},
            "extract_constants": {"type": "boolean", "description": "提取大整数常量 (默认 True)", "default": True},
            "extract_floats": {"type": "boolean", "description": "提取浮点常量 (默认 True)", "default": True},
            "disasm_func": {"type": "string", "description": "指定反汇编函数名 (可选)", "default": ""},
        }

    def execute(self, **kwargs: Any) -> str:
        binary = kwargs.get("binary_path", "")
        deep = kwargs.get("deep", True)
        extract_constants = kwargs.get("extract_constants", True)
        extract_floats = kwargs.get("extract_floats", True)
        disasm_func = kwargs.get("disasm_func", "")

        if not binary:
            return "ERROR: binary_path 为必填参数"

        parts: list[str] = []

        # 1. 文件基本信息
        r = self._ssh.exec_cmd(f"file '{binary}' && stat '{binary}' 2>/dev/null | head -8", timeout=10)
        if r.is_success:
            parts.append("## 文件信息\n" + (r.stdout or "")[:500])

        # 2. 提取 .rodata 段字符串
        r = self._ssh.exec_cmd(
            f"strings -a '{binary}' 2>/dev/null | grep -E '^[[:print:]]{{4,}}$' | sort -u | head -50",
            timeout=10,
        )
        if r.is_success and r.stdout:
            parts.append("## 字符串 (长度≥4)\n" + r.stdout[:800])

        # 3. 提取大整数常量 (objdump .rodata 中的 hex 数据)
        if extract_constants:
            cmd = (
                f"objdump -s -j .rodata '{binary}' 2>/dev/null | head -60; "
                f"objdump -s -j .data '{binary}' 2>/dev/null | head -40"
            )
            r = self._ssh.exec_cmd(cmd, timeout=15)
            if r.is_success and r.stdout:
                data = r.stdout
                # 提取所有 hex 大数
                large_hex = _RE_HEX_LARGE.findall(data)
                if large_hex:
                    parts.append(f"## 检测到的大整数常量 ({len(large_hex)} 个)\n")
                    for h in large_hex[:10]:
                        bits = len(h) * 4
                        try:
                            val = int(h, 16)
                            parts.append(f"  hex: 0x{h[:64]}... ({bits}bit, dec={val})\n")
                        except ValueError:
                            parts.append(f"  hex: 0x{h[:64]}... (未解析)\n")

        # 4. 提取浮点常量
        if extract_floats:
            # 用 objdump 的浮点反汇编
            r = self._ssh.exec_cmd(
                f"objdump -d -M intel '{binary}' 2>/dev/null | grep -E '(movsd|movss|cvtsi2sd|ucomisd|cvtsd2si|addsd|mulsd|subsd)' | head -30",
                timeout=15,
            )
            if r.is_success and r.stdout:
                parts.append("## 浮点指令\n" + r.stdout[:1000])

            # 提取 .rodata 中的 8 字节浮点常量
            r = self._ssh.exec_cmd(
                f"python3 -c \"\n"
                f"import struct\n"
                f"with open('{binary}','rb') as f:\n"
                f"  data = f.read()\n"
                f"# scan for IEEE 754 double special values\n"
                f"count = 0\n"
                f"for i in range(0, len(data)-8, 8):\n"
                f"  try:\n"
                f"    val = struct.unpack('<d', data[i:i+8])[0]\n"
                f"    if val == 0.0 or val != val or abs(val) == float('inf'):\n"
                f"      print(f'  offset=0x{{i:x}} value={{val}}')\n"
                f"      count += 1\n"
                f"      if count >= 10: break\n"
                f"  except: pass\n"
                f"print('---')\n"
                f"# scan for large constants (8-byte)\n"
                f"count = 0\n"
                f"for i in range(0, len(data)-8, 8):\n"
                f"  val = int.from_bytes(data[i:i+8], 'little')\n"
                f"  if val > (1<<64): continue\n"
                f"  if val > (1<<32) and val < (1<<63):\n"
                f"    print(f'  offset=0x{{i:x}} 8byte=0x{{val:x}}')\n"
                f"    count += 1\n"
                f"    if count >= 5: break\n"
                f"\"",
                timeout=60,
            )
            if r.is_success and r.stdout:
                parts.append("## 浮点/常量扫描\n" + r.stdout[:800])

        # 5. 深度分析: 反汇编关键函数
        if deep:
            # 获取符号表
            r = self._ssh.exec_cmd(
                f"nm '{binary}' 2>/dev/null | grep -E ' T | t ' | head -20; "
                f"objdump -t '{binary}' 2>/dev/null | grep -E 'F .text' | head -10",
                timeout=10,
            )
            if r.is_success and r.stdout:
                parts.append("## 函数符号\n" + r.stdout[:500])

            # 反汇编 main 函数 (如果指定了函数名)
            func = disasm_func or "main"
            r = self._ssh.exec_cmd(
                f"objdump -d -M intel '{binary}' 2>/dev/null | "
                f"awk '/^[0-9a-f]+ <{func}>:/{{flag=1}} flag{{print}} /^$/:flag=0' | head -80",
                timeout=15,
            )
            if r.is_success and r.stdout:
                parts.append(f"## 函数 {func} 反汇编\n{r.stdout[:1500]}")

        # 6. 安全检查: 检查保护/PIE
        r = self._ssh.exec_cmd(
            f"python3 -c \"from pwn import *; e = ELF('{binary}'); "
            f"print('Arch:', e.arch, '| PIE:', e.pie, '| RELRO:', e.relro, '| Stack:', e.canary, '| NX:', e.nx)\"",
            timeout=10,
        )
        if r.is_success and r.stdout:
            parts.append("## 安全检查\n" + r.stdout[:200])

        text = "\n\n".join(parts)
        if len(text) > _MAX_OUTPUT:
            text = text[:_MAX_OUTPUT] + "\n... (输出截断)"

        return text if text else "ERROR: 无法分析二进制文件"


def binary_constants_tools(ssh: SSHClient) -> list[Tool]:
    return [BinaryConstantsTool(ssh)]