"""Sprint 14 P0 - angr 符号执行工具单元测试 + 真实数据 smoke 测试.

测试目标:
1. AngrSymbolicExecTool 工具元数据 (name, description, parameters)
2. 工具工厂 angr_tools 返回 1 个工具
3. angr 检测降级提示
4. 真实环境: 在 Crypto_Reverse 二进制上跑符号执行 (smoke 测试)
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

from ctf_agent.ssh import CmdResult, SSHClient
from ctf_agent.tools import angr_tools, default_tools
from ctf_agent.tools.angr_tool import AngrSymbolicExecTool


REAL_SSH = os.environ.get("RUN_REAL_SSH", "") == "1"


def _mock_ssh_client(
    *,
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    elapsed: float = 0.1,
) -> MagicMock:
    client = MagicMock(spec=SSHClient)
    client.exec_cmd.return_value = CmdResult(
        stdout=stdout, stderr=stderr, exit_code=exit_code, cmd="mock", elapsed=elapsed
    )
    return client


# ============ 元数据测试 ============

def test_angr_symbolic_exec_tool_name() -> None:
    """AngrSymbolicExecTool 名字为 'angr_symbolic_exec'."""
    tool = AngrSymbolicExecTool(_mock_ssh_client())
    assert tool.name == "angr_symbolic_exec"


def test_angr_description_contains_keywords() -> None:
    """description 包含 angr/符号执行/反汇编等关键信息."""
    tool = AngrSymbolicExecTool(_mock_ssh_client())
    desc = tool.description
    assert "angr" in desc
    assert "符号执行" in desc
    assert "reverse" in desc or "reverse" in desc.lower()


def test_angr_parameters_schema() -> None:
    """参数 schema 验证: binary_path 必填, 其他可选."""
    tool = AngrSymbolicExecTool(_mock_ssh_client())
    params = tool.parameters
    assert params["type"] == "object"
    props = params["properties"]
    # 必备参数
    assert "binary_path" in props
    # 可选参数
    assert "input_kind" in props
    assert "input_size" in props
    assert "input_format" in props
    assert "target" in props
    assert "find_addr" in props
    assert "avoid_addr" in props
    assert "timeout" in props
    # required
    required = params["required"]
    assert "binary_path" in required


# ============ 工厂测试 ============

def test_angr_tools_factory_returns_one_tool() -> None:
    """angr_tools(ssh) 返回 1 个工具: AngrSymbolicExecTool."""
    client = _mock_ssh_client()
    tools = angr_tools(client)
    assert len(tools) == 1
    assert tools[0].name == "angr_symbolic_exec"


# ============ 降级测试 ============

def test_angr_missing_degradation() -> None:
    """angr 未安装时, 工具应返回 ERROR 提示."""
    client = _mock_ssh_client(
        stdout="ModuleNotFoundError: No module named 'angr'",
        stderr="",
        exit_code=1,
    )
    tool = AngrSymbolicExecTool(client)
    result = tool.execute(binary_path="/nonexistent/binary")
    assert "ERROR" in result
    # 错误消息应包含 angr
    assert "angr" in result


def test_angr_empty_binary_path() -> None:
    """binary_path 为空时, 应返回 ERROR."""
    client = _mock_ssh_client(
        stdout="angr version: 9.2.213",  # 假装 angr 可用
        exit_code=0,
    )
    tool = AngrSymbolicExecTool(client)
    # 模拟 angr 检测成功
    tool._available = True
    result = tool.execute(binary_path="")
    assert "ERROR" in result
    assert "binary_path" in result


# ============ default_tools 集成测试 ============

def test_default_tools_with_ssh_client_has_33_tools() -> None:
    """Sprint 14 P2: 29 → 33 (+1 ecdsa +1 angr +1 des +1 feistel).
    累计: 13 builtin + 1 HTTP + 3 SSH + 1 binary_analyzer +
    1 mem_xor_analyzer + 4 OSINT + 2 APK + 1 sage + 2 reverse_image +
    1 ocr + 1 ecdsa + 1 angr + 1 des + 1 feistel = 33.
    """
    client = _mock_ssh_client()
    tools = default_tools(ssh_client=client)
    assert len(tools) == 33


def test_angr_tools_registered() -> None:
    """Sprint 14 P0: 验证 angr_tools 已注册到 default_tools."""
    client = _mock_ssh_client()
    tools = default_tools(ssh_client=client)
    names = {t.name for t in tools}
    assert "angr_symbolic_exec" in names
    assert "ecdsa_nonce_reuse" in names  # 同时验证 ecdsa 也注册了


def test_default_tools_can_disable_angr() -> None:
    """enable_angr=False 时, 工具数 33 → 32 (去掉 angr)."""
    client = _mock_ssh_client()
    tools = default_tools(ssh_client=client, enable_angr=False)
    names = {t.name for t in tools}
    assert "angr_symbolic_exec" not in names
    assert "ecdsa_nonce_reuse" in names  # ecdsa 仍启用
    assert "feistel_decrypt" in names  # feistel 仍启用
    assert len(tools) == 32


def test_default_tools_can_disable_ecdsa() -> None:
    """enable_ecdsa=False 时, 工具数 33 → 32 (去掉 ecdsa)."""
    client = _mock_ssh_client()
    tools = default_tools(ssh_client=client, enable_ecdsa=False)
    names = {t.name for t in tools}
    assert "ecdsa_nonce_reuse" not in names
    assert "angr_symbolic_exec" in names  # angr 仍启用
    assert "feistel_decrypt" in names  # feistel 仍启用
    assert len(tools) == 32


# ============ 集成测试: 真实 SSH + Crypto_Reverse 数据 ============

@pytest.mark.skipif(not REAL_SSH, reason="需要 RUN_REAL_SSH=1 环境变量触发")
def test_real_angr_crypto_reverse() -> None:
    """真实环境: 在 Crypto_Reverse 二进制上跑 angr 符号执行.

    验证 angr 工具能跑通 (不要求一定解出输入, 因为 Feistel cipher
    符号执行可能非常慢, 5 分钟超时内不一定收敛).
    """
    from ctf_agent.config import get_settings
    from ctf_agent.ssh import ssh_client_from_settings

    settings = get_settings()
    client = ssh_client_from_settings(settings)
    client.connect()
    try:
        tool = AngrSymbolicExecTool(client)
        result = tool.execute(
            binary_path="/tmp/ctf_real7/Crypto_Reverse/crypto_binary.bin",
            input_kind="argv",
            input_index=1,
            input_size=8,  # 8 bytes = 16 hex chars
            input_format="hex",
            target="athena{",
            timeout=60,  # smoke 测试 1 分钟超时
        )
        print(f"\n[angr 真实数据] {result[:1500]}")
        # 工具应该能跑通 (即不报 'angr 未安装' 错误)
        assert "angr 未在" not in result, f"angr 检测失败: {result[:500]}"
    finally:
        client.close()
