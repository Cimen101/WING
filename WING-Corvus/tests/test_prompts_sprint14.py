"""Sprint 14 P2 - system prompt 反幻觉规则验证.

确保 prompts.py 包含:
1. 反幻觉规则 (anti-hallucination)
2. 禁止写 secret.txt / flag.txt
3. 禁止输出占位符 flag (test_flag_here / placeholder / fix_me)
4. 反幻觉规则被 build_system_prompt() 正确注入
"""
from __future__ import annotations

from ctf_agent.agent.prompts import (
    SYSTEM_PROMPT_TEMPLATE,
    build_system_prompt,
)
from ctf_agent.tools.base import Tool
from ctf_agent.tools.builtin import builtin_tools


# ============ 模板包含检查 ============

def test_system_prompt_contains_anti_hallucination() -> None:
    """SYSTEM_PROMPT_TEMPLATE 必须含 '反幻觉' 或 'anti-hallucination' 标识."""
    assert "反幻觉" in SYSTEM_PROMPT_TEMPLATE, (
        "SYSTEM_PROMPT_TEMPLATE 必须包含反幻觉规则 (Sprint 14 P2 强化)"
    )


def test_system_prompt_forbids_secret_txt() -> None:
    """必须明确禁止写 secret.txt / flag.txt / answer.txt."""
    assert "secret.txt" in SYSTEM_PROMPT_TEMPLATE, (
        "Sprint 14 P2: 必须显式禁止 LLM 写 secret.txt / flag.txt"
    )
    assert "flag.txt" in SYSTEM_PROMPT_TEMPLATE


def test_system_prompt_forbids_placeholder_flags() -> None:
    """必须显式禁止占位符 flag (test_flag_here / placeholder / fix_me)."""
    assert "test_flag_here" in SYSTEM_PROMPT_TEMPLATE
    assert "placeholder" in SYSTEM_PROMPT_TEMPLATE
    assert "fix_me" in SYSTEM_PROMPT_TEMPLATE


def test_system_prompt_has_no_section() -> None:
    """反幻觉规则必须有明确的 绝对禁止 列表."""
    assert "绝对禁止" in SYSTEM_PROMPT_TEMPLATE or "禁止" in SYSTEM_PROMPT_TEMPLATE
    # 至少 3 个 ⛔ 标记 (Unicode \u26d4)
    no_count = SYSTEM_PROMPT_TEMPLATE.count("⛔")
    assert no_count >= 3, (
        f"应至少 3 个 ⛔ 标记, 实际: {no_count}"
    )


def test_system_prompt_has_correct_section() -> None:
    """反幻觉规则必须含 正确做法 列表."""
    assert "正确做法" in SYSTEM_PROMPT_TEMPLATE
    # 至少 2 个 ✅ 标记 (Unicode \u2705)
    ok_count = SYSTEM_PROMPT_TEMPLATE.count("✅")
    assert ok_count >= 2, (
        f"应至少 2 个 ✅ 标记, 实际: {ok_count}"
    )


def test_system_prompt_mentions_sprint14_p2() -> None:
    """Sprint 14 P2 标识必须存在, 便于追溯."""
    assert "Sprint 14 P2" in SYSTEM_PROMPT_TEMPLATE


# ============ build_system_prompt 集成 ============

class _MockTool(Tool):
    name = "mock_tool"
    description = "Mock tool for testing"
    parameters = {"type": "object", "properties": {}}

    def execute(self, **kwargs):
        return "mock"


def test_build_system_prompt_includes_anti_hallucination() -> None:
    """build_system_prompt() 输出的 prompt 必须含反幻觉规则."""
    tools = [_MockTool()]
    prompt = build_system_prompt(tools)
    assert "反幻觉" in prompt, "反幻觉规则必须在最终 prompt 中"
    assert "secret.txt" in prompt
    assert "test_flag_here" in prompt


def test_build_system_prompt_works_with_real_tools() -> None:
    """build_system_prompt() 用真实 builtin_tools 也能正常输出."""
    tools = builtin_tools()
    prompt = build_system_prompt(tools)
    assert "反幻觉" in prompt
    assert "mock_tool" not in prompt  # 真实工具无 mock
    # builtin_tools 至少有 base64_encode
    assert "base64_encode" in prompt or "Base64Encode" in prompt


# ============ 关键检查: 规则位置 ============

def test_anti_hallucination_after_basic_rules() -> None:
    """反幻觉规则必须在基础规则之后, 工具格式规则之前或之后."""
    idx_format = SYSTEM_PROMPT_TEMPLATE.find("# 输出格式")
    idx_rules = SYSTEM_PROMPT_TEMPLATE.find("# 规则")
    idx_anti = SYSTEM_PROMPT_TEMPLATE.find("反幻觉")
    assert idx_format < idx_rules < idx_anti, (
        f"顺序: format({idx_format}) < rules({idx_rules}) < anti_hallucination({idx_anti})"
    )


def test_anti_hallucination_mentions_specific_tools() -> None:
    """反幻觉规则应提到具体工具 (feistel_decrypt / des_cryptanalysis / angr)."""
    assert "feistel_decrypt" in SYSTEM_PROMPT_TEMPLATE
    assert "des_cryptanalysis" in SYSTEM_PROMPT_TEMPLATE
    assert "angr_symbolic_exec" in SYSTEM_PROMPT_TEMPLATE or "angr" in SYSTEM_PROMPT_TEMPLATE
