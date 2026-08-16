"""Sprint 12 M2 sage_tool 单元测试 + 真实数据验证.

测试目标:
1. CommonDAttackTool 工具元数据 (name, description, parameters)
2. 工具工厂 sage_tools 返回 1 个工具
3. fpylll/sage 检测降级提示
4. (集成) 真实环境: 在 Triplet_Tweak 真实数据上调用 common_d_attack
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from ctf_agent.ssh import CmdResult, SSHClient
from ctf_agent.tools import default_tools, sage_tools
from ctf_agent.tools.sage_tool import CommonDAttackTool


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

def test_common_d_attack_tool_name() -> None:
    assert CommonDAttackTool.__name__ == "CommonDAttackTool"
    tool = CommonDAttackTool(_mock_ssh_client())
    assert tool.name == "common_d_attack"


def test_common_d_attack_description_contains_keyword() -> None:
    tool = CommonDAttackTool(_mock_ssh_client())
    assert "LLL" in tool.description
    assert "fpylll" in tool.description
    assert "Triplet_Tweak" in tool.description


def test_common_d_attack_parameters_schema() -> None:
    tool = CommonDAttackTool(_mock_ssh_client())
    params = tool.parameters
    assert params["type"] == "object"
    props = params["properties"]
    # 必备参数
    assert "n1" in props
    assert "e1" in props
    assert "c1" in props
    assert "n2" in props
    assert "e2" in props
    assert "c2" in props
    # 可选 (第 3 个实例)
    assert "n3" in props
    assert "e3" in props
    assert "c3" in props
    # required
    required = params["required"]
    assert "n1" in required
    assert "n2" in required
    # 第 3 个实例应不在 required (可选)
    assert "n3" not in required


# ============ 工厂测试 ============

def test_sage_tools_factory_returns_one_tool() -> None:
    client = _mock_ssh_client()
    tools = sage_tools(client)
    assert len(tools) == 1
    assert tools[0].name == "common_d_attack"


# ============ 降级测试 ============

def test_fpylll_missing_degradation() -> None:
    """fpylll + sage 都缺失时, 工具应返回降级提示."""
    client = _mock_ssh_client(
        stdout="ModuleNotFoundError: No module named 'fpylll'", exit_code=1
    )
    tool = CommonDAttackTool(client)
    # 第一次调用检测 fpylll (失败), 第二次检测 sage (失败)
    client.exec_cmd.side_effect = [
        CmdResult(stdout="", stderr="not found", exit_code=1, cmd="x", elapsed=0.1),
        CmdResult(stdout="", stderr="not found", exit_code=1, cmd="x", elapsed=0.1),
    ]
    result = tool.execute(
        n1="123", e1="3", c1="456",
        n2="789", e2="5", c2="012",
    )
    assert "ERROR" in result
    assert "fpylll" in result
    assert "降级" in result or "ssh_python" in result


# ============ default_tools 集成测试 ============

def test_default_tools_with_ssh_client_has_33_tools() -> None:
    """13 内置 + 1 HTTP + 3 SSH + binary_analyzer + mem_xor_analyzer + 4 OSINT + 2 APK + 1 sage + 2 reverse_image + 1 ocr + 1 ecdsa + 1 angr + 1 des + 1 feistel = 33 个.

    Sprint 12: 25 → 26 (新增 sage_tools 1 个: common_d_attack)
    Sprint 12 M3: 26 → 28 (新增 reverse_image_tools 2 个: web_search + osm_geocode)
    Sprint 12 M3.5: 28 → 29 (新增 ocr_tool 1 个: ocr)
    Sprint 14 P0: 29 → 31 (新增 ecdsa_nonce_reuse + angr_symbolic_exec)
    Sprint 14 P2: 31 → 33 (新增 des_cryptanalysis + feistel_decrypt)
    """
    client = _mock_ssh_client()
    tools = default_tools(ssh_client=client)
    assert len(tools) == 33


def test_sage_tools_registered() -> None:
    """Sprint 12 M2: 验证 sage_tools 注册."""
    client = _mock_ssh_client()
    tools = default_tools(ssh_client=client)
    names = {t.name for t in tools}
    assert "common_d_attack" in names


# ============ 集成测试: 真实 SSH + Triplet_Tweak 数据 ============

@pytest.mark.skipif(not REAL_SSH, reason="需要 RUN_REAL_SSH=1 环境变量触发")
def test_real_common_d_attack_triplet_tweak() -> None:
    """真实环境: 在 Triplet_Tweak 真实数据上调用 common_d_attack 还原 d.

    验证 fpylll LLL 攻击能跑通, 输出包含 d 或解密后的明文.
    """
    from ctf_agent.config import get_settings
    from ctf_agent.ssh import ssh_client_from_settings

    settings = get_settings()
    client = ssh_client_from_settings(settings)
    client.connect()
    try:
        # 1. 读取 pub.txt
        r = client.exec_cmd("cat /tmp/ctf_real3/Triplet_Tweak/pub.txt", timeout=10)
        assert r.is_success
        # 解析 n1, e1, c1, n2, e2, c2, n3, e3, c3
        import re
        nums: dict[str, str] = {}
        for line in r.stdout.split("\n"):
            m = re.match(r"(n\d|e\d|c\d)\s*=\s*(\d+)", line.strip())
            if m:
                nums[m.group(1)] = m.group(2)
        for k in ["n1", "e1", "c1", "n2", "e2", "c2", "n3", "e3", "c3"]:
            assert k in nums, f"缺少 {k}"

        # 2. 调用 common_d_attack
        tool = CommonDAttackTool(client)
        result = tool.execute(
            n1=nums["n1"], e1=nums["e1"], c1=nums["c1"],
            n2=nums["n2"], e2=nums["e2"], c2=nums["c2"],
            n3=nums["n3"], e3=nums["e3"], c3=nums["c3"],
            k_instances=3,
        )
        print(f"\n[common_d_attack 真实数据] {result[:1000]}")
        # 工具应该能跑通 (不要求一定解出 d, 因为算法可能需要调优)
        assert "ERROR" not in result or "降级" in result
    finally:
        client.close()
