"""Sprint 7 P0-1 修复测试：parser 层"空输出免费重答"逻辑.

测试目标：
1. 模型连续 2 次空输出（empty output）不应立即触发 format_errors 熔断
2. 应注入 NULL_OBSERVATION_HINT 恢复提示作为 observation
3. 第 3 次空输出升级为 format_errors
4. 格式错乱（missing fields）仍走原 format_errors 路径

回归测试（确保未破坏现有功能）：
- 非空 Thought+Action+Input 仍正常解析
- Final Answer 终止路径
- max_format_errors 仍有效
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from ctf_agent.agent.react import (
    ParsedAction,
    ReActEngine,
    parse_llm_output,
)
from ctf_agent.tools.base import Tool, ToolResult


class _NoopTool(Tool):
    name = "noop"
    description = "noop tool"

    def execute(self, **kwargs: Any) -> str:
        return "ok"

    def __call__(self, action_input: str) -> ToolResult:
        return ToolResult(output="ok", is_error=False)


# ============ parser 单元测试 ============

def test_parse_llm_output_empty_string():
    """空字符串 → empty output, is_valid=False."""
    p = parse_llm_output("")
    assert p.is_valid is False
    assert p.parse_error == "empty output"


def test_parse_llm_output_whitespace_only():
    """仅空白 → empty output."""
    p = parse_llm_output("   \n\t  \n")
    assert p.is_valid is False
    assert p.parse_error == "empty output"


def test_parse_llm_output_none_input():
    """None → empty output (不应崩溃)."""
    p = parse_llm_output(None or "")
    assert p.is_valid is False
    assert p.parse_error == "empty output"


def test_parse_llm_output_missing_action():
    """有 Thought 但无 Action → missing fields, is_valid=False 但不是 empty."""
    p = parse_llm_output("Thought: I should look at the file\nAction Input: foo")
    assert p.is_valid is False
    assert p.parse_error != "empty output"
    assert "Action" in p.parse_error


def test_parse_llm_output_thought_and_action():
    """Thought + Action + Action Input → 正常解析."""
    p = parse_llm_output(
        "Thought: I need to read the file\nAction: noop\nAction Input: {\"path\": \"/tmp/x\"}"
    )
    assert p.is_valid is True
    assert p.thought.startswith("I need to read")
    assert p.action == "noop"
    assert "path" in p.action_input


def test_parse_llm_output_final_answer():
    """Final Answer → 终止路径."""
    p = parse_llm_output("Final Answer: athena{test_flag_123}")
    assert p.is_valid is True
    assert p.is_final is True
    assert "athena{" in p.final_answer


# ============ ReAct 引擎集成测试（mock LLM） ============

def _make_engine(llm_responses: list[str]) -> ReActEngine:
    """构造一个会按顺序返回预设响应的 ReActEngine."""
    client = MagicMock()
    # 每次 .chat() 返回下一个预设响应
    results = []
    for content in llm_responses:
        usage = MagicMock()
        usage.total_tokens = 100
        result = MagicMock()
        result.content = content
        result.usage = usage
        results.append(result)
    client.chat.side_effect = results
    return ReActEngine(llm=client, tools=[_NoopTool()], max_steps=10, max_format_errors=2)


def test_engine_empty_output_1st_does_not_break():
    """第 1 步 LLM 空输出 → 注入 hint 继续，不计入 format_errors."""
    engine = _make_engine([
        "",  # step 1: empty output
        "Thought: try again\nAction: noop\nAction Input: {}",  # step 2: 正常
        "Final Answer: athena{recovered_flag_123}",  # step 3: 终止
    ])
    result = engine.run("test task")
    assert result.success is True
    assert "athena{" in result.final_answer
    # step 1 应记录为 error but step 2 已恢复
    assert any(s.is_error for s in result.steps)
    assert any(s.action == "noop" for s in result.steps)


def test_engine_empty_output_2nd_recovers():
    """第 1-2 步连续空输出 → 仍不熔断（2 次免费重答）."""
    engine = _make_engine([
        "",  # step 1: empty
        "",  # step 2: empty (仍免费)
        "Thought: try tool\nAction: noop\nAction Input: {}",  # step 3: 有效工具调用
        "Final Answer: athena{second_chance_flag}",  # step 4: 终止
    ])
    result = engine.run("test task")
    assert result.success is True
    assert "second_chance_flag" in result.final_answer


def test_engine_empty_output_3rd_triggers_breaker():
    """第 3 次空输出（连续 3 次）→ 升级为 format_errors（max_format_errors=2）触发熔断."""
    engine = _make_engine([
        "",  # step 1: empty (free)
        "",  # step 2: empty (free)
        "",  # step 3: empty → format_errors=1
        "",  # step 4: empty → format_errors=2 → 熔断
    ])
    result = engine.run("test task")
    assert result.success is False
    # 连续空输出升级为 format_errors 后熔断
    assert "format" in result.fail_reason.lower() or "失败" in result.fail_reason


def test_engine_missing_fields_triggers_format_error():
    """有内容但缺字段（missing fields）→ 走原 format_errors 路径，第 3 次熔断."""
    engine = _make_engine([
        "Thought: I should try this",  # step 1: missing Action/Input
        "Thought: still trying",  # step 2: missing
        "Final Answer: athena{never_reached}",  # step 3: 不会到这里
    ])
    result = engine.run("test task")
    # max_format_errors=2, 第 2 次就熔断
    assert result.success is False
    assert "格式" in result.fail_reason or "format" in result.fail_reason.lower()


def test_engine_resets_empty_counter_on_valid_output():
    """空输出计数在有效输出后重置."""
    engine = _make_engine([
        "",  # step 1: empty
        "Thought: ok\nAction: noop\nAction Input: {}",  # step 2: 正常（重置计数）
        "",  # step 3: empty（重新开始计数）
        "Final Answer: athena{reset_flag}",  # step 4: 终止
    ])
    result = engine.run("test task")
    assert result.success is True
    assert "reset_flag" in result.final_answer


def test_engine_mixed_empty_and_format_errors():
    """混合空输出和格式错乱 → 两者独立计数."""
    engine = _make_engine([
        "",  # step 1: empty (1)
        "Thought: thinking but no action",  # step 2: missing fields → format_errors=1
        "Thought: try tool\nAction: noop\nAction Input: {}",  # step 3: 有效工具调用
        "Final Answer: athena{mixed_flag_1234}",  # step 4: 终止
    ])
    result = engine.run("test task")
    assert result.success is True
    assert "mixed_flag_1234" in result.final_answer
