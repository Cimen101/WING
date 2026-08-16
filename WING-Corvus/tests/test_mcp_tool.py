"""Sprint 5.6 验收测试：L3 MCP 工具层.

依据 README §3.2，L3 工具通过 SSH 调用 Kali 上的重型逆向工具：
- GhidraHeadlessTool: 反编译/函数列表/字符串提取
- Radare2Tool: r2 反编译/反汇编/分析
- MCPClient/MCPTool: 通用 MCP server 客户端（JSON-RPC over stdio）

测试策略：
- Mock SSHClient，模拟 Kali 上的 Ghidra/r2 输出
- 验证工具参数校验、命令构造、输出解析
- 验证优雅降级：工具不可用时返回明确错误
- 端到端验证 default_tools(enable_l3=True) 包含 L3 工具

注意：Tool.__call__ 接收 JSON 字符串 action_input，返回 ToolResult。
工具内部错误返回 "ERROR: ..." 字符串，但 is_error 仅在抛异常时为 True。
本测试通过 output 是否含 "ERROR" 判断错误，与 ssh_tool 行为一致。
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from ctf_agent.tools import (
    GhidraHeadlessTool,
    MCPClient,
    MCPTool,
    Radare2Tool,
    default_tools,
    mcp_tools,
)


# ============ Mock 辅助 ============

class MockSSHResult:
    """模拟 SSHClient.exec_cmd 返回值."""

    def __init__(
        self,
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0,
        elapsed: float = 0.1,
    ):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.elapsed = elapsed

    @property
    def is_success(self) -> bool:
        return self.exit_code == 0


class MockSSHClient:
    """模拟 SSHClient，可脚本化多次 exec_cmd 返回值."""

    def __init__(self, responses: list[MockSSHResult] | None = None):
        self._responses = list(responses) if responses else []
        self.calls: list[str] = []

    def exec_cmd(self, cmd: str, **kwargs: Any) -> MockSSHResult:
        self.calls.append(cmd)
        if self._responses:
            return self._responses.pop(0)
        return MockSSHResult(stdout="", exit_code=0)


def _call(tool, **kwargs) -> str:
    """以 kwargs 调用工具，返回 output 字符串."""
    return tool(json.dumps(kwargs)).output


# ============ Radare2Tool ============

def test_r2_tool_parameters_schema() -> None:
    """Radare2Tool 的参数 schema 完整."""
    ssh = MockSSHClient()
    tool = Radare2Tool(ssh)
    assert tool.name == "radare2"
    assert "binary_path" in tool.parameters["properties"]
    assert "action" in tool.parameters["properties"]
    assert set(tool.parameters["properties"]["action"]["enum"]) == {
        "analyze", "decompile", "disassemble", "strings"
    }


def test_r2_tool_analyze_action() -> None:
    """analyze action 应执行 aaa; iI; afl."""
    ssh = MockSSHClient([
        MockSSHResult(stdout="/usr/bin/r2\nradare2 5.8.8\n"),  # which r2
        MockSSHResult(stdout="arch: x86 64\nbits: 64\nmain 0x401000\n"),  # r2 output
    ])
    tool = Radare2Tool(ssh)
    output = _call(tool, binary_path="/tmp/test.elf", action="analyze")
    assert "r2 analyze" in output
    assert "arch" in output
    # 验证 r2 命令包含 aaa; iI; afl
    r2_cmd = ssh.calls[1]
    assert "aaa" in r2_cmd
    assert "iI" in r2_cmd
    assert "afl" in r2_cmd


def test_r2_tool_decompile_uses_pdc() -> None:
    """decompile action 应使用 pdc（pseudo-decompiler）."""
    ssh = MockSSHClient([
        MockSSHResult(stdout="/usr/bin/r2\nradare2 5.8.8\n"),
        MockSSHResult(stdout="int main() { return 0; }\n"),
    ])
    tool = Radare2Tool(ssh)
    output = _call(
        tool, binary_path="/tmp/test.elf",
        action="decompile", function_name="main",
    )
    assert "int main" in output
    r2_cmd = ssh.calls[1]
    assert "s sym.main" in r2_cmd
    assert "pdc" in r2_cmd


def test_r2_tool_disassemble_with_address() -> None:
    """disassemble + address 应使用 pd N."""
    ssh = MockSSHClient([
        MockSSHResult(stdout="/usr/bin/r2\n"),
        MockSSHResult(stdout="0x401000: mov eax, 0\n0x401005: ret\n"),
    ])
    tool = Radare2Tool(ssh)
    output = _call(
        tool, binary_path="/tmp/test.elf",
        action="disassemble", address="0x401000", length=10,
    )
    r2_cmd = ssh.calls[1]
    assert "s 0x401000" in r2_cmd
    assert "pd 10" in r2_cmd


def test_r2_tool_strings_action() -> None:
    """strings action 应使用 izz."""
    ssh = MockSSHClient([
        MockSSHResult(stdout="/usr/bin/r2\n"),
        MockSSHResult(stdout="0x402000 flag{test}\n0x402010 hello world\n"),
    ])
    tool = Radare2Tool(ssh)
    output = _call(tool, binary_path="/tmp/test.elf", action="strings")
    assert "flag{test}" in output
    r2_cmd = ssh.calls[1]
    assert "izz" in r2_cmd


def test_r2_tool_not_installed_returns_error() -> None:
    """r2 未安装时返回明确错误，便于 LLM 切换工具."""
    ssh = MockSSHClient([
        MockSSHResult(stdout="", exit_code=1),  # which r2 失败
    ])
    tool = Radare2Tool(ssh)
    output = _call(tool, binary_path="/tmp/test.elf", action="analyze")
    assert "ERROR" in output
    assert "未安装" in output
    assert "objdump" in output  # 提示替代方案


def test_r2_tool_empty_binary_path_errors() -> None:
    ssh = MockSSHClient()
    tool = Radare2Tool(ssh)
    output = _call(tool, binary_path="", action="analyze")
    assert "ERROR" in output
    assert "binary_path" in output


def test_r2_tool_unknown_action_errors() -> None:
    ssh = MockSSHClient([
        MockSSHResult(stdout="/usr/bin/r2\n"),  # which r2 OK
    ])
    tool = Radare2Tool(ssh)
    output = _call(tool, binary_path="/tmp/test.elf", action="invalid_action")
    assert "ERROR" in output
    assert "invalid_action" in output


def test_r2_tool_failure_exit_code_in_output() -> None:
    """r2 退出码非 0 时标注 ERROR."""
    ssh = MockSSHClient([
        MockSSHResult(stdout="/usr/bin/r2\n"),
        MockSSHResult(stdout="", stderr="error: cannot open file", exit_code=1),
    ])
    tool = Radare2Tool(ssh)
    output = _call(tool, binary_path="/tmp/nonexistent", action="analyze")
    assert "ERROR" in output
    assert "退出码 1" in output


def test_r2_tool_path_injection_safe() -> None:
    """binary_path 用 shlex.quote 防止路径注入."""
    ssh = MockSSHClient([
        MockSSHResult(stdout="/usr/bin/r2\n"),
        MockSSHResult(stdout="ok\n"),
    ])
    tool = Radare2Tool(ssh)
    # 构造恶意路径
    evil_path = "/tmp/x; rm -rf /"
    _call(tool, binary_path=evil_path, action="analyze")
    r2_cmd = ssh.calls[1]
    # shlex.quote 应将恶意路径转义为单引号包裹
    # 危险的 rm -rf / 不应被 shell 解释
    assert "'/tmp/x; rm -rf /'" in r2_cmd or '"/tmp/x; rm -rf /"' in r2_cmd


# ============ GhidraHeadlessTool ============

def test_ghidra_tool_parameters_schema() -> None:
    ssh = MockSSHClient()
    tool = GhidraHeadlessTool(ssh)
    assert tool.name == "ghidra_headless"
    assert "binary_path" in tool.parameters["properties"]
    assert "action" in tool.parameters["properties"]
    assert set(tool.parameters["properties"]["action"]["enum"]) == {
        "decompile", "list_functions", "strings", "disassemble"
    }


def test_ghidra_tool_not_installed_returns_error() -> None:
    """Ghidra 未安装时返回明确错误."""
    ssh = MockSSHClient([
        MockSSHResult(stdout="", exit_code=1),  # test -x 失败
    ])
    tool = GhidraHeadlessTool(ssh)
    output = _call(tool, binary_path="/tmp/test.elf", action="decompile")
    assert "ERROR" in output
    assert "未安装" in output
    assert "radare2_tool" in output  # 提示替代


def test_ghidra_tool_decompile_invokes_analyzeheadless() -> None:
    """decompile action 应调用 analyzeHeadless."""
    ghidra_log = """INFO  Loading program...
=== DECOMPILED main ===
int main(int argc, char **argv) {
  puts("hello");
  return 0;
}
INFO  Done."""
    ssh = MockSSHClient([
        MockSSHResult(stdout="OK\n"),  # test -x OK
        MockSSHResult(stdout=ghidra_log),  # ghidra 输出
        MockSSHResult(stdout=""),  # 清理
    ])
    tool = GhidraHeadlessTool(ssh)
    output = _call(
        tool, binary_path="/tmp/test.elf",
        action="decompile", function_name="main",
    )
    assert "=== DECOMPILED main ===" in output
    assert "int main" in output
    assert "puts" in output
    # 验证调用了 analyzeHeadless
    ghidra_cmd = ssh.calls[1]
    assert "analyzeHeadless" in ghidra_cmd
    assert "-postScript" in ghidra_cmd
    assert "-import" in ghidra_cmd


def test_ghidra_tool_list_functions() -> None:
    """list_functions action 输出函数列表."""
    ghidra_log = """INFO  Loading...
=== FUNCTIONS ===
00401000  main  (size=42)
00401050  helper  (size=18)
00401080  puts@plt  (size=16)
"""
    ssh = MockSSHClient([
        MockSSHResult(stdout="OK\n"),
        MockSSHResult(stdout=ghidra_log),
        MockSSHResult(stdout=""),
    ])
    tool = GhidraHeadlessTool(ssh)
    output = _call(tool, binary_path="/tmp/test.elf", action="list_functions")
    assert "main" in output
    assert "helper" in output
    assert "puts@plt" in output


def test_ghidra_tool_strings_action() -> None:
    ssh = MockSSHClient([
        MockSSHResult(stdout="OK\n"),
        MockSSHResult(stdout="=== DEFINED STRINGS ===\n00402000  flag{ghidra}\n"),
        MockSSHResult(stdout=""),
    ])
    tool = GhidraHeadlessTool(ssh)
    output = _call(tool, binary_path="/tmp/test.elf", action="strings")
    assert "flag{ghidra}" in output


def test_ghidra_tool_disassemble_requires_address() -> None:
    ssh = MockSSHClient([
        MockSSHResult(stdout="OK\n"),
    ])
    tool = GhidraHeadlessTool(ssh)
    output = _call(tool, binary_path="/tmp/test.elf", action="disassemble")
    assert "ERROR" in output
    assert "address" in output


def test_ghidra_tool_empty_binary_path_errors() -> None:
    ssh = MockSSHClient()
    tool = GhidraHeadlessTool(ssh)
    output = _call(tool, binary_path="", action="decompile")
    assert "ERROR" in output
    assert "binary_path" in output


def test_ghidra_tool_cleanup_called() -> None:
    """工具执行后应清理临时脚本与项目目录."""
    ssh = MockSSHClient([
        MockSSHResult(stdout="OK\n"),
        MockSSHResult(stdout="=== FUNCTIONS ===\n00401000  main\n"),
        MockSSHResult(stdout=""),  # 清理命令
    ])
    tool = GhidraHeadlessTool(ssh)
    _call(tool, binary_path="/tmp/test.elf", action="list_functions")
    # 第 3 次调用应是清理 rm
    cleanup_cmd = ssh.calls[2]
    assert "rm -f" in cleanup_cmd or "rm -rf" in cleanup_cmd


def test_ghidra_tool_failure_exit_code_in_output() -> None:
    ssh = MockSSHClient([
        MockSSHResult(stdout="OK\n"),
        MockSSHResult(stdout="", stderr="Ghidra error", exit_code=1),
        MockSSHResult(stdout=""),
    ])
    tool = GhidraHeadlessTool(ssh)
    output = _call(tool, binary_path="/tmp/bad", action="decompile")
    assert "ERROR" in output


# ============ 工厂函数 ============

def test_mcp_tools_no_ssh_returns_empty() -> None:
    """ssh_client=None 返回空列表."""
    assert mcp_tools(ssh_client=None) == []


def test_mcp_tools_with_ssh_returns_r2_and_ghidra() -> None:
    """传入 ssh_client 应包含 r2 与 ghidra 工具."""
    ssh = MockSSHClient()
    tools = mcp_tools(ssh)
    names = [t.name for t in tools]
    assert "radare2" in names
    assert "ghidra_headless" in names


def test_mcp_tools_disable_r2() -> None:
    ssh = MockSSHClient()
    tools = mcp_tools(ssh, enable_r2=False)
    names = [t.name for t in tools]
    assert "radare2" not in names
    assert "ghidra_headless" in names


def test_mcp_tools_disable_ghidra() -> None:
    ssh = MockSSHClient()
    tools = mcp_tools(ssh, enable_ghidra=False)
    names = [t.name for t in tools]
    assert "radare2" in names
    assert "ghidra_headless" not in names


def test_default_tools_enable_l3_includes_mcp_tools() -> None:
    """default_tools(enable_l3=True) 应包含 L3 工具."""
    ssh = MockSSHClient()
    tools = default_tools(ssh, enable_l3=True)
    names = [t.name for t in tools]
    assert "radare2" in names
    assert "ghidra_headless" in names
    # 也应包含 L1 + L2
    assert "base64_decode" in names
    assert "ssh_exec" in names


def test_default_tools_l3_disabled_by_default() -> None:
    """默认不启用 L3."""
    ssh = MockSSHClient()
    tools = default_tools(ssh)
    names = [t.name for t in tools]
    assert "radare2" not in names
    assert "ghidra_headless" not in names
    # L1 + L2 仍在
    assert "base64_decode" in names
    assert "ssh_exec" in names


# ============ MCPClient（通用 MCP 协议扩展点） ============

def test_mcp_client_initialization() -> None:
    """MCPClient 可初始化."""
    client = MCPClient(server_cmd=["python", "-m", "fake_mcp_server"])
    assert client.server_cmd == ["python", "-m", "fake_mcp_server"]
    assert client._process is None


def test_mcp_client_stop_without_start_is_noop() -> None:
    """未 start 直接 stop 应安全无副作用."""
    client = MCPClient(server_cmd=["python", "-m", "fake"])
    client.stop()  # 不应抛异常


def test_mcp_tool_wrapper_exposes_mcp_tool() -> None:
    """MCPTool 把 MCP server 工具暴露为 ReAct Tool."""
    mock_client = MagicMock(spec=MCPClient)
    mock_client.call_tool.return_value = {
        "content": [{"type": "text", "text": "decompiled code here"}]
    }
    tool = MCPTool(
        client=mock_client,
        tool_name="decompile",
        description="Decompile via MCP",
        parameters={"type": "object", "properties": {}},
    )
    assert tool.name == "mcp_decompile"
    assert "Decompile" in tool.description
    result = tool("{}")
    assert "decompiled code here" in result.output


def test_mcp_tool_handles_call_failure() -> None:
    """MCP 调用失败应返回 ERROR 字符串."""
    mock_client = MagicMock(spec=MCPClient)
    mock_client.call_tool.side_effect = RuntimeError("connection lost")
    tool = MCPTool(
        client=mock_client,
        tool_name="bad",
        description="Bad tool",
        parameters={"type": "object", "properties": {}},
    )
    output = tool("{}").output
    assert "MCP 调用失败" in output
    assert "connection lost" in output


def test_mcp_tool_handles_string_response() -> None:
    """MCP 响应为字符串时直接返回."""
    mock_client = MagicMock(spec=MCPClient)
    mock_client.call_tool.return_value = "plain string result"
    tool = MCPTool(
        client=mock_client,
        tool_name="str_tool",
        description="String tool",
        parameters={"type": "object", "properties": {}},
    )
    output = tool("{}").output
    assert "plain string result" in output
