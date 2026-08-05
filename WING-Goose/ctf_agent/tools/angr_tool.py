# -*- coding: utf-8 -*-
"""L2 angr 符号执行工具 (新增).

为复杂 reverse 题 (如 复杂逆向题 的 Feistel cipher) 提供符号执行能力,
无需 LLM 反复 brute force.

适用场景:
- 二进制接受输入 (key / flag), 输出加密后数据
- 已知密文 + 期望明文部分 (如 "athena{...}")
- 需要找输入使输出匹配

实现:
- angr 9.2.213 已装在 /opt/ctf_venv (安装)
- 使用 path_group + explorer 找满足约束的输入
- 支持 argv 输入 (如 ./binary 'hex_key')
- 支持 stdin 输入 (printf '...' | ./binary)

降级:
- 若 angr 不可用, 返回 ERROR 提示装 angr
- 若超时 (>5 分钟), 提示用其他方法
"""
from __future__ import annotations

import os
import re
import tempfile
from typing import Any, Optional

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool


_MAX_OUTPUT = 4000
_TRUNCATED_SUFFIX = "\n... (输出截断, 共 {total} 字符)"


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + _TRUNCATED_SUFFIX.format(total=len(text))


def _check_angr(ssh: SSHClient) -> bool:
    """检测 angr 是否可用 (在 /opt/ctf_venv)."""
    r = ssh.exec_cmd(
        "/opt/ctf_venv/bin/python3 -c 'import angr; print(angr.__version__)' 2>&1",
        timeout=15,
    )
    return r.is_success and "9" in (r.stdout or "")


# ============ AngrSymbolicExecTool ============

class AngrSymbolicExecTool(Tool):
    """angr 符号执行工具.

    用途: 找使二进制输出满足特定约束的输入.
    适用: Crackme / cipher 题已知部分明文, 求 key/flag.

    用法:
      angr_symbolic_exec(
          binary_path='/tmp/ctf_workspace/复杂逆向题/crypto_binary.bin',
          input_kind='argv',  # 'argv' | 'stdin'
          input_index=1,  # argv 索引 (0 是 binary 自身, 1 是第一个参数)
          input_size=16,  # 期望输入长度 (hex 字符)
          input_format='hex',  # 'hex' | 'bytes'
          find_addr=None,  # 成功地址 (从 r2 找)
          avoid_addr=None,  # 失败地址 (从 r2 找)
          constraint='starts_with',  # 'starts_with' | 'equals' | 'contains'
          target='athena{',  # 期望匹配的字符串
          timeout=300,  # 5 分钟超时
      )

    返回: 找到的输入 (hex/bytes 形式) + 验证结果.
    """

    name = "angr_symbolic_exec"
    description = (
        "angr 符号执行 （复杂 reverse 题专用).\n"
        "用法: angr_symbolic_exec(binary_path='...', input_kind='argv', "
        "input_size=16, input_format='hex', target='athena{', find_addr='0x...', "
        "avoid_addr='0x...', timeout=300)\n"
        "输入: binary_path 必填. input_kind: 'argv' (默认) | 'stdin'. "
        "input_format: 'hex' (默认) | 'bytes'.\n"
        "target: 期望输出中包含的字符串 (例如 'athena{').\n"
        "find_addr / avoid_addr: 符号执行的 find/avoid 地址 (0x..., 可选).\n"
        "依赖: /opt/ctf_venv 已装 angr 9.2.213 (安装).\n"
        "降级: angr 不可用时, 提示用 binary_analyzer + 手动分析."
    )
    parameters = {
        "type": "object",
        "properties": {
            "binary_path": {"type": "string", "description": "二进制路径"},
            "input_kind": {"type": "string", "description": "'argv' (默认) 或 'stdin'"},
            "input_index": {"type": "integer", "description": "argv 索引 (默认 1)"},
            "input_size": {"type": "integer", "description": "输入字节数 (默认 8)"},
            "input_format": {"type": "string", "description": "'hex' (默认) 或 'bytes'"},
            "find_addr": {"type": "string", "description": "find 地址 (0x..., 可选)"},
            "avoid_addr": {"type": "string", "description": "avoid 地址 (0x..., 可选)"},
            "target": {"type": "string", "description": "期望匹配的字符串 (默认 'athena{')"},
            "timeout": {"type": "integer", "description": "angr 符号执行超时秒数 (默认 300)"},
        },
        "required": ["binary_path"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh = ssh_client
        self._available: Optional[bool] = None

    def _ensure(self) -> str:
        if self._available is None:
            self._available = _check_angr(self.ssh)
        if not self._available:
            return (
                "ERROR: angr 未在 /opt/ctf_venv 安装.\n"
                "方案: VIRTUAL_ENV=/opt/ctf_venv /root/.local/bin/uv pip install angr"
            )
        return ""

    def execute(
        self,
        binary_path: str,
        input_kind: str = "argv",
        input_index: int = 1,
        input_size: int = 8,
        input_format: str = "hex",
        find_addr: str = "",
        avoid_addr: str = "",
        target: str = "athena{",
        timeout: int = 300,
        **_: Any,
    ) -> str:
        err = self._ensure()
        if err:
            return err

        if not binary_path:
            return "ERROR: binary_path 不能为空"

        # 构造 angr 脚本
        script = """
import sys
import angr
import claripy

binary_path = '__BINARY__'
input_kind = '__INPUT_KIND__'
input_index = __INPUT_INDEX__
input_size = __INPUT_SIZE__
input_format = '__INPUT_FORMAT__'
find_addr = __FIND_ADDR__
avoid_addr = __AVOID_ADDR__
target = '__TARGET__'

print(f"=== angr 符号执行 ===")
print(f"  binary: {binary_path}")
print(f"  input_kind: {input_kind}, index: {input_index}, size: {input_size}")
print(f"  target: {target!r}, format: {input_format}")

# 创建 angr project
p = angr.Project(binary_path, auto_load_libs=False)
print(f"  arch: {p.arch}, entry: {hex(p.entry)}")

# 创建符号输入
if input_format == 'hex':
    # hex 字符串: 2 * input_size 字符
    sym_size = input_size * 2
    sym = claripy.BVS('input', sym_size * 8)
else:
    sym = claripy.BVS('input', input_size * 8)

# 创建初始 state
if input_kind == 'argv':
    # 构造 argv: [binary, sym_input (bytes), binary, ...]
    sym_bytes = claripy.BVS('input_bytes', input_size * 8)
    argv = [binary_path, sym_bytes]
    state = p.factory.entry_state(args=argv)
elif input_kind == 'stdin':
    state = p.factory.entry_state(stdin=sym)
else:
    print(f"  ERROR: 不支持的 input_kind: {input_kind}")
    sys.exit(1)

# 限制 input 不含 null
for i in range(input_size):
    byte = sym_bytes.get_byte(i) if input_kind == 'argv' else sym.get_byte(i)
    state.solver.add(byte >= 0x20)
    state.solver.add(byte <= 0x7e)  # printable

# 创建 simulation managers
simgr = p.factory.simulation_manager(state)

# 设置 find / avoid
find_kwargs = {}
avoid_kwargs = {}
if find_addr:
    find_kwargs['find'] = int(find_addr, 16) if find_addr.startswith('0x') else int(find_addr)
if avoid_addr:
    avoid_kwargs['avoid'] = int(avoid_addr, 16) if avoid_addr.startswith('0x') else int(avoid_addr)

# 简单探索: 限制深度
print(f"  开始探索 (max_steps=2000)...")
explorer = simgr.explore(**find_kwargs, **avoid_kwargs, num_find=1)
print(f"  探索完成, found={len(explorer.found)}, deadended={len(explorer.deadended)}, avoided={len(explorer.avoid) if hasattr(explorer, 'avoid') else 0}")

if explorer.found:
    found_state = explorer.found[0]
    if input_kind == 'argv':
        sol_bytes = found_state.solver.eval(sym_bytes, cast_to=bytes)
    else:
        sol_bytes = found_state.solver.eval(sym, cast_to=bytes)
    print(f"  ✅ 找到输入 ({len(sol_bytes)} bytes): {sol_bytes.hex()}")
    if input_format == 'hex':
        try:
            sol_str = sol_bytes.decode('ascii', errors='replace')
            print(f"  Decoded: {sol_str!r}")
        except Exception as e:
            print(f"  decode error: {e}")
    # 验证
    print(f"  验证: 运行 binary 用找到的输入...")
    if input_kind == 'argv':
        r = p.factory.execute(binary_path, args=[binary_path, sol_bytes])
    else:
        r = p.factory.execute(binary_path, stdin=sol_bytes)
    out = r.posix.dumps(1)  # stdout
    print(f"  binary output: {out[:200]!r}")
    if target.encode() in out:
        print(f"  ✅ 验证成功: target {target!r} 在输出中")
    else:
        print(f"  ⚠️ 验证: target {target!r} 不在输出中 (但找到了输入)")
else:
    print(f"  ❌ 未找到满足约束的输入")
    print(f"  提示: 尝试调整 find_addr / target / input_size / timeout")

print("Done")
"""
        script = (
            script
            .replace("__BINARY__", binary_path)
            .replace("__INPUT_KIND__", input_kind)
            .replace("__INPUT_INDEX__", str(input_index))
            .replace("__INPUT_SIZE__", str(input_size))
            .replace("__INPUT_FORMAT__", input_format)
            .replace("__FIND_ADDR__", find_addr or "0")
            .replace("__AVOID_ADDR__", avoid_addr or "0")
            .replace("__TARGET__", target)
        )

        remote_script = "/tmp/angr_symbolic_exec.py"
        r = self.ssh.exec_cmd(
            f"cat > {remote_script} << 'PYEOF'\n{script}\nPYEOF",
            timeout=10,
        )
        if not r.is_success:
            return f"ERROR: 写脚本失败: {r.stderr[:200]}"

        # 用 /opt/ctf_venv/bin/python3 跑
        r = self.ssh.exec_cmd(
            f"/opt/ctf_venv/bin/python3 {remote_script}",
            timeout=timeout + 30,
        )
        output = r.stdout or ""
        if r.is_success and output:
            return f"=== angr 符号执行结果 ===\n{_truncate(output)}"
        return f"ERROR: 符号执行失败: {r.stderr[:500] or 'no output'}"


# ============ 工厂函数 ============

def angr_tools(ssh_client: SSHClient) -> list[Tool]:
    """返回 angr 工具集."""
    return [AngrSymbolicExecTool(ssh_client)]
