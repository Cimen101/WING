"""L3 MCP 工具层（L5 工具层最顶层）.

依据 README §3.2，L3 层对接重型 GUI/API 工具：
- Ghidra (Headless)：反编译、函数列表、字符串提取（比 strings 更智能）
- IDA Pro (Headless)：需要 License，预留接口
- Burp Suite (Extender)：Web 渗透，预留接口
- Radare2：开源逆向框架，Kali 默认安装

设计原则：
- L1 内置 → L2 SSH → L3 MCP 降级策略
- L3 工具实际通过 SSH 调用 Kali 上的 Ghidra/r2/angr
- 真正的 MCP 协议（JSON-RPC over stdio）作为可选扩展点
- 优雅降级：工具不可用时返回明确错误，让 LLM 切换到 L2

工具列表：
- GhidraHeadlessTool: Ghidra 反编译、函数列表、控制流图
- Radare2Tool: r2 反编译、反汇编、函数分析
- MCPTool: 通用 MCP server 客户端（连接外部 MCP server）
"""

from __future__ import annotations

import json
import shlex
from typing import Any

from ctf_agent.tools.base import Tool
from ctf_agent.tools.ssh_tool import _truncate


# ============ Ghidra Headless 工具 ============

class GhidraHeadlessTool(Tool):
    """Ghidra Headless 反编译工具.

    通过 SSH 调用 Kali 上的 Ghidra analyzeHeadless，支持：
    - decompile: 反编译指定函数（默认 main）
    - list_functions: 列出所有函数
    - strings: 提取 defined strings（比 strings 命令更准确）
    - disassemble: 反汇编指定地址范围

    依赖 Kali 沙箱中已安装 Ghidra（默认 /opt/ghidra/）。
    若未安装，工具会返回明确错误，LLM 可降级到 radare2 或 objdump。
    """

    name = "ghidra_headless"
    description = (
        "调用 Ghidra Headless 进行二进制逆向分析（反编译/函数列表/字符串提取）。"
        "比 strings/objdump 更准确，能识别函数边界与高级语义。"
        "需要在 Kali 沙箱中预装 Ghidra（/opt/ghidra/）。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Kali 上 ELF/PE 文件路径（如 /tmp/ctf_workspace/task1/challenge）",
            },
            "action": {
                "type": "string",
                "enum": ["decompile", "list_functions", "strings", "disassemble"],
                "description": "操作类型",
            },
            "function_name": {
                "type": "string",
                "description": "decompile 时指定函数名（默认 main）",
            },
            "address": {
                "type": "string",
                "description": "disassemble 时指定起始地址（如 0x401000）",
            },
            "length": {
                "type": "integer",
                "description": "disassemble 时指定长度（字节数，默认 64）",
            },
        },
        "required": ["binary_path", "action"],
    }

    def __init__(
        self,
        ssh_client: Any,
        *,
        ghidra_home: str = "/opt/ghidra",
        default_timeout: int = 120,
    ) -> None:
        self.ssh_client = ssh_client
        self.ghidra_home = ghidra_home
        self.default_timeout = default_timeout

    def execute(
        self,
        binary_path: str,
        action: str,
        function_name: str = "main",
        address: str | None = None,
        length: int = 64,
        **_: Any,
    ) -> str:
        if not binary_path:
            return "ERROR: binary_path 不能为空"

        # 检查 Ghidra 是否可用
        check = self.ssh_client.exec_cmd(
            f'test -x "{self.ghidra_home}/support/analyzeHeadless" && echo OK'
        )
        if "OK" not in (check.stdout or ""):
            return (
                f"ERROR: Ghidra 未安装在 {self.ghidra_home}。"
                f"请用 radare2_tool 或 ssh_exec + objdump 作为替代。"
            )

        # 构造 Ghidra post-script
        if action == "decompile":
            script = self._build_decompile_script(function_name)
        elif action == "list_functions":
            script = self._build_list_functions_script()
        elif action == "strings":
            script = self._build_strings_script()
        elif action == "disassemble":
            if not address:
                return "ERROR: disassemble 需要 address 参数"
            script = self._build_disassemble_script(address, length)
        else:
            return f"ERROR: 未知 action: {action}"

        # 上传脚本到 Kali 临时目录
        import base64
        script_b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
        script_remote = f"/tmp/ghidra_script_{id(script)}.py"

        # 项目目录（每次新建避免污染）
        project_dir = f"/tmp/ghidra_proj_{id(script)}"
        project_name = "ctf_proj"

        cmd = (
            f"echo {script_b64} | base64 -d > {script_remote} && "
            f'mkdir -p {project_dir} && '
            f'{self.ghidra_home}/support/analyzeHeadless '
            f'{project_dir} {project_name} '
            f'-import "{binary_path}" -overwrite '
            f'-postScript {script_remote} '
            f'-deleteProject 2>&1 | tail -100'
        )

        result = self.ssh_client.exec_cmd(
            cmd, cwd="/tmp/ctf_workspace/", timeout=self.default_timeout
        )
        # 清理
        self.ssh_client.exec_cmd(f"rm -f {script_remote}; rm -rf {project_dir}")

        parts: list[str] = []
        parts.append(f"[ghidra {action}, elapsed={result.elapsed:.2f}s]")
        if result.stdout:
            # 提取脚本输出（Ghidra Headless 会输出大量日志，
            # 我们的脚本通过 print() 输出实际内容，需过滤）
            useful = self._extract_script_output(result.stdout)
            parts.append(_truncate(useful))
        if result.stderr and not result.is_success:
            parts.append(f"[stderr]\n{_truncate(result.stderr[:2000])}")
        if not result.stdout:
            parts.append("(无输出)")

        output = "\n".join(parts)
        if not result.is_success:
            output = f"ERROR: Ghidra 退出码 {result.exit_code}\n{output}"
        return output

    def _build_decompile_script(self, function_name: str) -> str:
        return f"""
# Ghidra Python script: decompile function
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

decomp = DecompInterface()
decomp.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

fm = currentProgram.getFunctionManager()
target = None
for func in fm.getFunctions(True):
    if func.getName() == '{function_name}':
        target = func
        break
if target is None:
    # 尝试入口函数
    target = fm.getFunctionAt(currentProgram.getSymbolTable().getExternalEntryPointIterator().next())
if target is None:
    print("ERROR: function not found: {function_name}")
else:
    result = decomp.decompileFunction(target, 60, monitor)
    if result.decompileCompleted():
        print("=== DECOMPILED {function_name} ===")
        print(result.getDecompiledFunction().getC())
    else:
        print("ERROR: decompile failed")
"""

    def _build_list_functions_script(self) -> str:
        return """
from ghidra.program.model.listing import Function
fm = currentProgram.getFunctionManager()
print("=== FUNCTIONS ===")
for func in fm.getFunctions(True):
    print(f"{func.getEntryPoint()}  {func.getName()}  (size={func.getBody().getNumAddresses()})")
"""

    def _build_strings_script(self) -> str:
        return """
from ghidra.program.model.data import StringDataType
listing = currentProgram.getListing()
data_iter = listing.getDefinedData(True)
print("=== DEFINED STRINGS ===")
count = 0
for data in data_iter:
    if data.hasStringValue():
        print(f"{data.getAddress()}  {data.getValue()}")
        count += 1
        if count >= 200:
            print("... (truncated at 200 strings)")
            break
"""

    def _build_disassemble_script(self, address: str, length: int) -> str:
        return f"""
from ghidra.program.model.address import AddressFactory
addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress({address})
listing = currentProgram.getListing()
instr = listing.getInstructionAt(addr)
if instr is None:
    instr = listing.getInstructionContaining(addr)
print("=== DISASSEMBLY ===")
if instr is None:
    print("ERROR: no instruction at " + "{address}")
else:
    bytes_seen = 0
    while instr is not None and bytes_seen < {length}:
        print(f"{{instr.getAddress()}}  {{instr}}")
        bytes_seen += instr.getLength()
        instr = instr.getNext()
"""

    def _extract_script_output(self, ghidra_log: str) -> str:
        """从 Ghidra Headless 日志中提取脚本 print() 输出.

        Ghidra 的 print() 输出通常无前缀，日志行有 INFO/WARN/ERROR 前缀。
        简单策略：找 '=== XXX ===' 标记后的内容直到下一个标记或日志结尾。
        """
        lines = ghidra_log.splitlines()
        useful: list[str] = []
        in_block = False
        for line in lines:
            # 块标记开始
            if line.startswith("=== ") and line.endswith(" ==="):
                in_block = True
                useful.append(line)
                continue
            if in_block:
                # 遇到下一段日志（INFO/WARN/ERROR）则结束
                if any(
                    line.startswith(prefix)
                    for prefix in ("INFO", "WARN", "ERROR", "####", "-----")
                ):
                    in_block = False
                    continue
                useful.append(line)
        if useful:
            return "\n".join(useful)
        # 未找到块，返回最后 50 行（可能含脚本输出）
        return "\n".join(lines[-50:])


# ============ Radare2 工具 ============

class Radare2Tool(Tool):
    """Radare2 逆向分析工具.

    通过 SSH 调用 Kali 上的 r2（Kali 默认安装），支持：
    - analyze: 自动分析 + 输出基本信息（架构/字节序/函数列表）
    - decompile: 反编译指定函数（用 r2ghidra 或 pdc）
    - disassemble: 反汇编指定函数或地址
    - strings: 提取字符串（比 strings 命令更准确，含地址）

    相比 Ghidra Headless 更轻量、更快，但反编译质量略低。
    """

    name = "radare2"
    description = (
        "调用 radare2 (r2) 进行二进制逆向分析。"
        "Kali 默认安装，启动快（< 1s），适合快速分析。"
        "支持反编译（r2ghidra/pdc）、反汇编、函数列表、字符串提取。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Kali 上 ELF/PE 文件路径",
            },
            "action": {
                "type": "string",
                "enum": ["analyze", "decompile", "disassemble", "strings"],
                "description": "操作类型",
            },
            "function_name": {
                "type": "string",
                "description": "decompile/disassemble 时指定函数名（默认 main）",
            },
            "address": {
                "type": "string",
                "description": "disassemble 时指定起始地址（如 0x401000）",
            },
            "length": {
                "type": "integer",
                "description": "disassemble 时指定指令条数（默认 20）",
            },
        },
        "required": ["binary_path", "action"],
    }

    def __init__(
        self,
        ssh_client: Any,
        *,
        default_timeout: int = 60,
    ) -> None:
        self.ssh_client = ssh_client
        self.default_timeout = default_timeout

    def execute(
        self,
        binary_path: str,
        action: str,
        function_name: str = "main",
        address: str | None = None,
        length: int = 20,
        **_: Any,
    ) -> str:
        if not binary_path:
            return "ERROR: binary_path 不能为空"

        # 检查 r2 是否可用
        check = self.ssh_client.exec_cmd("which r2 && r2 -v 2>&1 | head -1")
        if "r2" not in (check.stdout or ""):
            return "ERROR: radare2 未安装。请用 ssh_exec + objdump 作为替代。"

        # 构造 r2 命令序列
        if action == "analyze":
            cmds = "aaa; iI; afl"
        elif action == "decompile":
            cmds = f"aaa; s sym.{function_name}; pdc"  # 尝试 pdc (pseudo-decompiler)
            # 备选：pdg（需 r2ghidra 插件）
        elif action == "disassemble":
            if address:
                cmds = f"aaa; s {address}; pd {length}"
            else:
                cmds = f"aaa; s sym.{function_name}; pdf"
        elif action == "strings":
            cmds = "aaa; izz~[0-9]"  # izz 列出所有字符串
        else:
            return f"ERROR: 未知 action: {action}"

        # 安全转义 binary_path（防止路径注入）
        safe_path = shlex.quote(binary_path)
        cmd = f"r2 -q -e scr.color=0 -c '{cmds}' {safe_path} 2>&1 | head -200"

        result = self.ssh_client.exec_cmd(
            cmd, cwd="/tmp/ctf_workspace/", timeout=self.default_timeout
        )

        parts: list[str] = []
        parts.append(f"[r2 {action}, elapsed={result.elapsed:.2f}s]")
        if result.stdout:
            parts.append(_truncate(result.stdout))
        if result.stderr and not result.is_success:
            parts.append(f"[stderr]\n{_truncate(result.stderr[:1000])}")
        if not result.stdout:
            parts.append("(无输出)")

        output = "\n".join(parts)
        if not result.is_success:
            output = f"ERROR: r2 退出码 {result.exit_code}\n{output}"
        return output


# ============ 通用 MCP 客户端（抽象扩展点） ============

class MCPClient:
    """通用 MCP (Model Context Protocol) 客户端.

    通过 JSON-RPC over stdio 与 MCP server 通信。
    典型 MCP server：GhidraMCP / IDAProMCP / BurpSuiteMCP。

    用法：
        client = MCPClient(server_cmd=["python", "-m", "ghidra_mcp_server"])
        client.start()
        tools = client.list_tools()
        result = client.call_tool("decompile", {"function": "main"})
        client.stop()

    本类为预留扩展点，当前未直接接入 ReAct Engine。
    生产环境可通过 MCPTool 包装具体 MCP server 工具。
    """

    def __init__(self, server_cmd: list[str]) -> None:
        self.server_cmd = server_cmd
        self._process: Any = None  # subprocess.Popen

    def start(self) -> None:
        """启动 MCP server 子进程."""
        import subprocess
        self._process = subprocess.Popen(
            self.server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def stop(self) -> None:
        """关闭 MCP server."""
        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except Exception:  # noqa: BLE001
                self._process.kill()
            self._process = None

    def call_raw(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """发送 JSON-RPC 请求并等待响应."""
        if self._process is None or self._process.stdin is None:
            raise RuntimeError("MCP server 未启动")
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params or {},
        }
        self._process.stdin.write(json.dumps(request) + "\n")
        self._process.stdin.flush()
        # 读取响应（简化：单行 JSON）
        line = self._process.stdout.readline()
        if not line:
            raise RuntimeError("MCP server 无响应")
        return json.loads(line).get("result")

    def list_tools(self) -> list[dict[str, Any]]:
        """列出 MCP server 提供的工具."""
        result = self.call_raw("tools/list")
        return result.get("tools", []) if result else []

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        """调用指定 MCP 工具."""
        return self.call_raw("tools/call", {"name": name, "arguments": arguments})


class MCPTool(Tool):
    """通用 MCP 工具包装器.

    将 MCP server 的工具暴露为 ReAct Tool。
    需要先实例化 MCPClient，再用 MCPTool 包装其每个工具。

    用法：
        client = MCPClient(["python", "-m", "ghidra_mcp_server"])
        client.start()
        tool = MCPTool(client, tool_name="decompile", ...)
    """

    def __init__(
        self,
        client: MCPClient,
        tool_name: str,
        description: str,
        parameters: dict[str, Any],
    ) -> None:
        self.client = client
        self._tool_name = tool_name
        self.name = f"mcp_{tool_name}"
        self.description = description
        self.parameters = parameters

    def execute(self, **kwargs: Any) -> str:
        try:
            result = self.client.call_tool(self._tool_name, kwargs)
            if isinstance(result, dict) and "content" in result:
                # MCP 标准响应格式
                contents = result["content"]
                if isinstance(contents, list):
                    return "\n".join(
                        c.get("text", str(c)) for c in contents if isinstance(c, dict)
                    )
                return str(contents)
            return str(result)
        except Exception as e:  # noqa: BLE001
            return f"ERROR: MCP 调用失败: {type(e).__name__}: {e}"


# ============ 工厂 ============

def mcp_tools(
    ssh_client: Any = None,
    *,
    enable_ghidra: bool = True,
    enable_r2: bool = True,
) -> list[Tool]:
    """创建 L3 MCP 工具集.

    Args:
        ssh_client: SSHClient 实例（必传，L3 工具通过 SSH 调用 Kali 上的 Ghidra/r2）
        enable_ghidra: 是否启用 Ghidra Headless 工具
        enable_r2: 是否启用 radare2 工具

    Returns:
        L3 工具列表。若 ssh_client 为 None，返回空列表。
    """
    if ssh_client is None:
        return []
    tools: list[Tool] = []
    if enable_r2:
        tools.append(Radare2Tool(ssh_client))
    if enable_ghidra:
        tools.append(GhidraHeadlessTool(ssh_client))
    return tools


__all__ = [
    "GhidraHeadlessTool",
    "MCPClient",
    "MCPTool",
    "Radare2Tool",
    "mcp_tools",
]
