"""PWN 利用工具集（L2.5，基于 Kali）.

补齐 PWN 方向短板：此前 pwn 完全依赖裸 ssh_python 手写，缺少专用工具。
这里封装 pwn 解题主线上的高频、易错步骤，让 agent 少写样板、少犯低级错误。

工具列表：
- ChecksecTool        : 查看二进制保护机制（NX/Canary/PIE/RELRO），pwn 第一步
- CyclicTool          : 生成/查询 cyclic pattern，定位栈溢出偏移
- RopGadgetTool       : 查找 ROP gadget / 字符串（pop rdi;ret、/bin/sh 等）
- PwnExploitTool      : 运行 pwntools exp 脚本（自动注入 remote/process 上下文）

底层统一走 SSHClient 在 Kali 内执行。PwnExploitTool 用 base64 传脚本避免转义。
"""

from __future__ import annotations

import base64
from typing import Any

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool

_MAX_OUTPUT = 8000


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n... (输出截断，共 {len(text)} 字符)"


class _KaliBackedTool(Tool):
    def __init__(
        self,
        ssh_client: SSHClient,
        *,
        default_timeout: int = 120,
        max_timeout: int = 600,
        cwd: str = "/tmp/ctf_workspace/",
    ) -> None:
        self.ssh_client = ssh_client
        self.default_timeout = default_timeout
        self.max_timeout = max_timeout
        self.cwd = cwd

    def _run(self, command: str, timeout: int | None = None) -> str:
        eff = min(timeout or self.default_timeout, self.max_timeout)
        result = self.ssh_client.exec_cmd(
            command, cwd=self.cwd, timeout=eff, env={"TERM": "xterm"}
        )
        parts = [f"[exit_code={result.exit_code}, elapsed={result.elapsed:.2f}s]"]
        if result.stdout:
            parts.append(_truncate(result.stdout))
        if result.stderr:
            parts.append(f"[stderr]\n{_truncate(result.stderr, 3000)}")
        if not result.stdout and not result.stderr:
            parts.append("(无输出)")
        out = "\n".join(parts)
        if result.exit_code not in (0, None):
            out = f"ERROR: 退出码 {result.exit_code}\n{out}"
        return out


class ChecksecTool(_KaliBackedTool):
    """checksec 查看二进制保护机制."""

    name = "pwn_checksec"
    description = (
        "【PWN 第一步】查看 ELF 保护机制 (NX/Canary/PIE/RELRO/FORTIFY)，决定利用手法："
        "无 Canary→栈溢出改返回地址；NX 开→ROP/ret2libc；PIE→需先泄露基址；"
        "Partial RELRO→可改 GOT。同时输出 file 信息（架构/静态动态）。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "binary": {"type": "string", "description": "二进制路径，如 /tmp/ctf_workspace/chall"},
        },
        "required": ["binary"],
    }

    def execute(self, binary: str, **_: Any) -> str:
        if not binary or not binary.strip():
            return "ERROR: binary 不能为空"
        cmd = (
            f"file '{binary}' ; echo '--- checksec ---' ; "
            f"(checksec --file='{binary}' 2>/dev/null || pwn checksec '{binary}' 2>&1)"
        )
        return self._run(cmd, timeout=60)


class CyclicTool(_KaliBackedTool):
    """生成 / 查询 cyclic pattern，定位溢出偏移."""

    name = "pwn_cyclic"
    description = (
        "【PWN 定偏移】生成 cyclic 唯一序列用于触发栈溢出崩溃；或用崩溃时寄存器里的值"
        "反查偏移。mode=gen 生成长度 length 的序列；mode=lookup 用 value(如崩溃 RSP 的 "
        "0x6161616c 或 'laaa') 反查偏移。64 位用 n=8。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "mode": {"type": "string", "description": "gen(生成) 或 lookup(反查)"},
            "length": {"type": "integer", "description": "gen 模式：序列长度（默认 200）"},
            "value": {"type": "string", "description": "lookup 模式：崩溃时的值（十六进制 0x.. 或 4/8 字节字符串）"},
            "n": {"type": "integer", "description": "字长：32 位用 4，64 位用 8（默认 8）"},
        },
        "required": ["mode"],
    }

    def execute(
        self,
        mode: str,
        length: int = 200,
        value: str | None = None,
        n: int = 8,
        **_: Any,
    ) -> str:
        if mode == "gen":
            script = f"from pwn import cyclic; import sys; sys.stdout.buffer.write(cyclic({int(length)}, n={int(n)}))"
        elif mode == "lookup":
            if not value:
                return "ERROR: lookup 模式需要提供 value"
            if value.startswith("0x") or value.startswith("0X"):
                val_expr = f"cyclic_find({value}, n={int(n)})"
            else:
                val_expr = f"cyclic_find({value!r}.encode(), n={int(n)})"
            script = f"from pwn import cyclic_find; print('offset =', {val_expr})"
        else:
            return "ERROR: mode 必须是 gen 或 lookup"
        b64 = base64.b64encode(script.encode()).decode()
        return self._run(f"echo {b64} | base64 -d | python3 -", timeout=30)


class RopGadgetTool(_KaliBackedTool):
    """ROPgadget 查找 gadget / 字符串."""

    name = "pwn_ropgadget"
    description = (
        "【PWN ROP 构造】在二进制中查找 ROP gadget 或字符串。"
        "query='pop rdi' 找传参 gadget；query='/bin/sh' 加 as_string=true 找字符串地址；"
        "query='syscall' 找系统调用。用于 ret2libc/ret2syscall 链构造。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "binary": {"type": "string", "description": "二进制路径"},
            "query": {"type": "string", "description": "gadget 关键词(如 'pop rdi'|'pop|ret'|'syscall') 或字符串(如 '/bin/sh')"},
            "as_string": {"type": "boolean", "description": "true 时按字符串搜索(--string)，否则按 gadget(--only)"},
        },
        "required": ["binary", "query"],
    }

    def execute(
        self,
        binary: str,
        query: str,
        as_string: bool = False,
        **_: Any,
    ) -> str:
        if not binary:
            return "ERROR: binary 不能为空"
        if as_string:
            cmd = f"ROPgadget --binary '{binary}' --string '{query}'"
        else:
            cmd = f"ROPgadget --binary '{binary}' --only '{query}' | head -n 80"
        return self._run(cmd, timeout=120)


class PwnExploitTool(_KaliBackedTool):
    """运行 pwntools exp 脚本（自动可选注入 remote/process 上下文）."""

    name = "pwn_exploit"
    description = (
        "【PWN 打 exp】运行 pwntools 利用脚本。脚本里可直接用 pwn 库；"
        "若提供 binary/host/port，会在脚本前自动注入变量：ELF 对象 `e`、以及 "
        "`io`（host+port 时=remote，否则=process(binary)）。脚本末尾建议解析并打印 flag。"
        "适合本地复现或打远程 127.0.0.1:1337。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "script": {"type": "string", "description": "pwntools Python 脚本主体（可用 e / io 变量）"},
            "binary": {"type": "string", "description": "可选：ELF 路径，注入为 e 并作为本地 process 目标"},
            "host": {"type": "string", "description": "可选：远程主机（如 127.0.0.1）"},
            "port": {"type": "integer", "description": "可选：远程端口（如 1337）"},
            "timeout": {"type": "integer", "description": "超时秒数（默认 120，最长 600）"},
        },
        "required": ["script"],
    }

    def execute(
        self,
        script: str,
        binary: str | None = None,
        host: str | None = None,
        port: int | None = None,
        timeout: int | None = None,
        **_: Any,
    ) -> str:
        if not script or not script.strip():
            return "ERROR: script 不能为空"
        prelude = ["from pwn import *", "context.log_level = 'info'"]
        if binary:
            prelude.append(f"e = context.binary = ELF({binary!r})")
        if host and port:
            prelude.append(f"io = remote({host!r}, {int(port)})")
        elif binary:
            prelude.append(f"io = process({binary!r})")
        full = "\n".join(prelude) + "\n" + script
        b64 = base64.b64encode(full.encode()).decode()
        return self._run(
            f"echo {b64} | base64 -d | python3 -", timeout=timeout
        )


def pwn_tools(ssh_client: SSHClient) -> list[Tool]:
    """创建 PWN 工具集（需要 Kali SSHClient）."""
    return [
        ChecksecTool(ssh_client),
        CyclicTool(ssh_client),
        RopGadgetTool(ssh_client),
        PwnExploitTool(ssh_client),
    ]


__all__ = [
    "ChecksecTool",
    "CyclicTool",
    "RopGadgetTool",
    "PwnExploitTool",
    "pwn_tools",
]
