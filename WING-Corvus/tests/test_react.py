"""Sprint 2.4 验收测试：ReAct 引擎核心.

覆盖：
1. 解析器：Final Answer / Action+Action Input / Thought 可选 / 格式错误 / 容错
2. 引擎完整循环：脚本化 LLM mock + fake 工具，跑通 Thought-Action-Observation
3. 终止条件：Final Answer / max_steps / 连续格式错误
4. 未知工具 / 工具异常处理
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from ctf_agent.agent import (
    ParsedAction,
    ReActEngine,
    ReActResult,
    ReActStep,
    parse_llm_output,
)
from ctf_agent.llm import ChatResult, ChatUsage, LLMClient, Message
from ctf_agent.orchestrator import CircuitBreaker, TaskState
from ctf_agent.tools.base import Tool


# ============ 脚本化 LLM mock ============

class ScriptedLLMClient(LLMClient):
    """按预设脚本顺序返回 LLM 响应的 mock 客户端."""

    def __init__(self, scripts: list[str], usages: list[int] | None = None):
        # 跳过父类初始化（不需要真实 API key）
        self.settings = None  # type: ignore[assignment]
        self._scripts = list(scripts)
        self._usages = usages or [10] * len(scripts)
        self._call_idx = 0
        self.calls: list[list[Message]] = []

    def chat(self, messages, model=None, temperature=0.0, max_tokens=None, timeout=None, extra=None) -> ChatResult:  # type: ignore[override]
        self.calls.append(list(messages))  # type: ignore[arg-type]
        if self._call_idx >= len(self._scripts):
            raise RuntimeError(
                f"ScriptedLLMClient 脚本耗尽：已调用 {self._call_idx + 1} 次但只有 {len(self._scripts)} 个预设"
            )
        content = self._scripts[self._call_idx]
        usage = self._usages[self._call_idx] if self._call_idx < len(self._usages) else 10
        self._call_idx += 1
        return ChatResult(
            content=content,
            usage=ChatUsage(prompt_tokens=usage, completion_tokens=usage, total_tokens=usage * 2),
            model=model or "mock",
        )


class _ConstTool(Tool):
    """返回固定字符串的测试工具."""

    name = "const_tool"
    description = "returns a constant string"
    parameters = {"type": "object", "properties": {}}

    def __init__(self, output: str = "ok"):
        self._output = output

    def execute(self, **_: Any) -> str:  # type: ignore[override]
        return self._output


class _BoomTool(Tool):
    """总是抛异常的测试工具."""

    name = "boom_tool"
    description = "always raises"
    parameters = {"type": "object", "properties": {}}

    def execute(self, **_: Any) -> str:  # type: ignore[override]
        raise RuntimeError("boom!")


# ============ 解析器测试 ============

def test_parse_final_answer() -> None:
    text = "Thought: 我找到了 flag\nFinal Answer: picoCTF{react_is_fun}"
    parsed = parse_llm_output(text)
    assert parsed.is_final is True
    assert parsed.final_answer == "picoCTF{react_is_fun}"
    assert parsed.thought == "我找到了 flag"


def test_parse_final_answer_without_thought() -> None:
    text = "Final Answer: flag{no_thought}"
    parsed = parse_llm_output(text)
    assert parsed.is_final is True
    assert parsed.final_answer == "flag{no_thought}"


def test_parse_action_and_input() -> None:
    text = (
        "Thought: 我需要发 HTTP 请求\n"
        'Action: http_request\n'
        'Action Input: {"url": "http://ctf.example/"}'
    )
    parsed = parse_llm_output(text)
    assert parsed.is_final is False
    assert parsed.needs_tool is True
    assert parsed.action == "http_request"
    assert parsed.action_input == '{"url": "http://ctf.example/"}'
    assert parsed.thought == "我需要发 HTTP 请求"


def test_parse_action_input_with_json_code_fence() -> None:
    text = (
        "Thought: test\n"
        "Action: http_request\n"
        "Action Input: ```json\n"
        '{"url": "http://ctf.example/"}\n'
        "```"
    )
    parsed = parse_llm_output(text)
    assert parsed.needs_tool is True
    assert parsed.action_input == '{"url": "http://ctf.example/"}'


def test_parse_case_insensitive_fields() -> None:
    text = (
        "thought: lowercase\n"
        "action: http_request\n"
        'action input: {"url": "http://x/"}'
    )
    parsed = parse_llm_output(text)
    assert parsed.needs_tool is True
    assert parsed.action == "http_request"
    assert parsed.thought == "lowercase"


def test_parse_final_answer_takes_priority_over_action() -> None:
    """同时出现 Final Answer 和 Action 时，Final Answer 优先."""
    text = (
        "Thought: done\n"
        "Action: http_request\n"
        'Action Input: {"url": "http://x/"}\n'
        "Final Answer: flag{priority}"
    )
    parsed = parse_llm_output(text)
    assert parsed.is_final is True
    assert parsed.final_answer == "flag{priority}"


def test_parse_missing_action_input() -> None:
    text = "Thought: 我要调用工具\nAction: http_request"
    parsed = parse_llm_output(text)
    assert parsed.is_valid is False
    assert "Action Input" in parsed.parse_error


def test_parse_missing_action() -> None:
    text = "Thought: 我要调用工具\nAction Input: {}"
    parsed = parse_llm_output(text)
    assert parsed.is_valid is False
    assert "Action" in parsed.parse_error


def test_parse_empty_output() -> None:
    parsed = parse_llm_output("")
    assert parsed.is_valid is False
    assert parsed.parse_error == "empty output"


def test_parse_only_thought() -> None:
    """只有 Thought，缺 Action 和 Final Answer."""
    text = "Thought: 我在思考\n但不知道下一步"
    parsed = parse_llm_output(text)
    assert parsed.is_valid is False


def test_parse_multiline_thought() -> None:
    text = (
        "Thought: 第一行推理\n"
        "第二行继续推理\n"
        "Action: http_request\n"
        'Action Input: {"url": "http://x/"}'
    )
    parsed = parse_llm_output(text)
    assert "第一行推理" in parsed.thought
    assert "第二行继续推理" in parsed.thought
    assert parsed.action == "http_request"


def test_parse_final_answer_strips_quotes() -> None:
    text = 'Final Answer: `flag{quoted}`'
    parsed = parse_llm_output(text)
    assert parsed.final_answer == "flag{quoted}"


def test_parsed_action_needs_tool_property() -> None:
    """needs_tool 属性：final 时为 False，valid action 时为 True."""
    final = ParsedAction(is_final=True, final_answer="x")
    assert final.needs_tool is False

    action = ParsedAction(action="http_request", action_input="{}")
    assert action.needs_tool is True

    invalid = ParsedAction(is_valid=False)
    assert invalid.needs_tool is False


# ============ 引擎完整循环测试 ============

def test_engine_completes_full_react_loop() -> None:
    """完整循环：Thought -> Action -> Observation -> Final Answer."""
    scripts = [
        # 第 1 步：调用工具
        "Thought: 我需要查询目标\n"
        'Action: const_tool\n'
        'Action Input: {}',
        # 第 2 步：基于 Observation 给出 Final Answer
        "Thought: 工具返回 ok，说明 flag 是 ok\n"
        "Final Answer: ok",
    ]
    llm = ScriptedLLMClient(scripts)
    tool = _ConstTool(output="ok")
    engine = ReActEngine(llm=llm, tools=[tool], max_steps=5)

    result = engine.run("获取 flag")

    assert result.success is True
    assert result.final_answer == "ok"
    assert result.step_count == 2
    # ScriptedLLMClient 每步 total_tokens=20（prompt=10 + completion=10）
    assert result.total_tokens == 20 * 2

    # 第 1 步：调用了工具
    assert result.steps[0].action == "const_tool"
    assert result.steps[0].observation == "ok"
    assert result.steps[0].is_final is False

    # 第 2 步：Final Answer
    assert result.steps[1].is_final is True
    assert result.steps[1].final_answer == "ok"


def test_engine_injects_observation_back_to_llm() -> None:
    """验证 Observation 被回灌到下一轮 LLM 输入."""
    scripts = [
        "Thought: 调用工具\nAction: const_tool\nAction Input: {}",
        "Thought: 收到结果\nFinal Answer: done",
    ]
    llm = ScriptedLLMClient(scripts)
    engine = ReActEngine(llm=llm, tools=[_ConstTool("hello")], max_steps=5)

    engine.run("task")

    # 第 2 次调用 LLM 时，消息历史应包含 Observation: hello
    second_call_messages = llm.calls[1]
    last_user_msg = second_call_messages[-1]
    assert last_user_msg.role == "user"
    assert "Observation: hello" in last_user_msg.content


def test_engine_max_steps_terminates() -> None:
    """达到 max_steps 且无实质进展时终止并返回失败 (软截断兜底)."""
    # 每步都调用工具，永不 Final Answer
    scripts = [
        f"Thought: step {i}\nAction: const_tool\nAction Input: {{}}" for i in range(5)
    ]
    llm = ScriptedLLMClient(scripts)
    # Sprint 32.4b: 相同 observation 不算进展; progress_grace=0 → 超限后立即兜底退出
    custom = CircuitBreaker(max_steps=3, progress_grace_seconds=0.0)
    engine = ReActEngine(llm=llm, tools=[_ConstTool("x")], max_steps=3, breaker=custom)

    result = engine.run("task")

    assert result.success is False
    assert "最大步数" in result.fail_reason
    assert result.step_count == 3


def test_engine_unknown_tool_returns_error_observation() -> None:
    """调用未知工具时，Observation 应为 ERROR，且循环继续."""
    scripts = [
        "Thought: 调用不存在的工具\nAction: nonexistent_tool\nAction Input: {}",
        "Thought: 工具不存在\nAction: const_tool\nAction Input: {}",  # 成功调用 (反幻觉要求 ≥1 有效工具调用)
        "Thought: 工具不存在，换一个\nFinal Answer: fallback",
    ]
    llm = ScriptedLLMClient(scripts)
    engine = ReActEngine(llm=llm, tools=[_ConstTool("ok")], max_steps=5)

    result = engine.run("task")

    assert result.success is True
    assert result.final_answer == "fallback"
    assert result.steps[0].is_error is True
    assert "ERROR" in result.steps[0].observation
    assert "nonexistent_tool" in result.steps[0].observation


def test_engine_tool_exception_caught_as_error_observation() -> None:
    """工具抛异常时，被 Tool.__call__ 捕获转为 ERROR Observation."""
    scripts = [
        "Thought: 调用会爆炸的工具\nAction: boom_tool\nAction Input: {}",
        "Thought: 工具失败\nAction: const_tool\nAction Input: {}",  # 成功调用 (反幻觉要求 ≥1 有效工具调用)
        "Thought: 工具失败，给出最终答案\nFinal Answer: recovered",
    ]
    llm = ScriptedLLMClient(scripts)
    engine = ReActEngine(llm=llm, tools=[_BoomTool(), _ConstTool("ok")], max_steps=5)

    result = engine.run("task")

    assert result.success is True
    assert result.final_answer == "recovered"
    assert result.steps[0].is_error is True
    assert "ERROR" in result.steps[0].observation
    assert "boom!" in result.steps[0].observation


def test_engine_consecutive_format_errors_terminate() -> None:
    """连续格式错误超过阈值时终止."""
    scripts = [
        "我忘记格式了，直接说话",
        "还是不按格式",
        "第三次也不按格式",
    ]
    llm = ScriptedLLMClient(scripts)
    engine = ReActEngine(
        llm=llm, tools=[_ConstTool("ok")], max_steps=10, max_format_errors=3
    )

    result = engine.run("task")

    assert result.success is False
    assert "格式解析失败" in result.fail_reason
    assert result.step_count == 3


def test_engine_format_error_then_recovery() -> None:
    """格式错误后，LLM 修正格式，循环继续."""
    scripts = [
        "我忘了格式",  # 格式错误
        "Thought: 重新按格式\nAction: const_tool\nAction Input: {}",  # 恢复
        "Thought: 完成\nFinal Answer: ok",
    ]
    llm = ScriptedLLMClient(scripts)
    engine = ReActEngine(llm=llm, tools=[_ConstTool("ok")], max_steps=10)

    result = engine.run("task")

    assert result.success is True
    assert result.final_answer == "ok"
    assert result.steps[0].is_error is True  # 第一步格式错误
    assert result.steps[1].action == "const_tool"  # 第二步恢复


def test_engine_system_prompt_contains_tool_schemas() -> None:
    """system prompt 应包含工具 schema 描述."""
    llm = ScriptedLLMClient([
        "Thought: t1\nAction: const_tool\nAction Input: {}",
        "Thought: x\nFinal Answer: x",
    ])
    tool = _ConstTool("ok")
    engine = ReActEngine(llm=llm, tools=[tool], max_steps=3)

    engine.run("task")

    first_call = llm.calls[0]
    system_msg = first_call[0]
    assert system_msg.role == "system"
    assert "const_tool" in system_msg.content
    assert "available tool" in system_msg.content.lower() or "可用工具" in system_msg.content


def test_engine_task_prompt_in_user_message() -> None:
    """任务描述应在第一个 user 消息中."""
    llm = ScriptedLLMClient([
        "Thought: t1\nAction: const_tool\nAction Input: {}",
        "Final Answer: x",
    ])
    engine = ReActEngine(llm=llm, tools=[_ConstTool("ok")], max_steps=3)

    engine.run("我的特殊任务")

    first_call = llm.calls[0]
    user_msg = first_call[1]
    assert user_msg.role == "user"
    assert "我的特殊任务" in user_msg.content


def test_engine_on_step_callback() -> None:
    """on_step 回调应在每步被调用."""
    llm = ScriptedLLMClient([
        "Thought: t\nAction: const_tool\nAction Input: {}",
        "Thought: done\nFinal Answer: ok",
    ])
    captured: list[ReActStep] = []
    engine = ReActEngine(
        llm=llm, tools=[_ConstTool("ok")], max_steps=5,
        on_step=lambda s: captured.append(s),
    )

    engine.run("task")

    assert len(captured) == 2
    assert captured[0].action == "const_tool"
    assert captured[1].is_final is True


def test_engine_collects_raw_outputs() -> None:
    """raw_outputs 应收集每步 LLM 原始输出，便于调试."""
    scripts = [
        "Thought: t1\nAction: const_tool\nAction Input: {}",
        "Thought: t2\nFinal Answer: ok",
    ]
    llm = ScriptedLLMClient(scripts)
    engine = ReActEngine(llm=llm, tools=[_ConstTool("ok")], max_steps=5)

    result = engine.run("task")

    assert len(result.raw_outputs) == 2
    assert "t1" in result.raw_outputs[0]
    assert "t2" in result.raw_outputs[1]


def test_engine_step_count_property() -> None:
    """step_count 应等于 steps 长度."""
    llm = ScriptedLLMClient([
        "Thought: t1\nAction: const_tool\nAction Input: {}",
        "Thought: t2\nFinal Answer: ok",
    ])
    engine = ReActEngine(llm=llm, tools=[_ConstTool("ok")], max_steps=5)

    result = engine.run("task")

    assert result.step_count == 2
    assert result.step_count == len(result.steps)


def test_engine_first_step_final_answer() -> None:
    """调用工具后给出 Final Answer（简单题快速完成）."""
    llm = ScriptedLLMClient([
        "Thought: 先探测\nAction: const_tool\nAction Input: {}",
        "Thought: 题目太简单\nFinal Answer: flag{easy}",
    ])
    engine = ReActEngine(llm=llm, tools=[_ConstTool("ok")], max_steps=5)

    result = engine.run("task")

    assert result.success is True
    assert result.final_answer == "flag{easy}"
    assert result.step_count == 2
    assert result.steps[1].is_final is True


def test_engine_respects_max_steps_from_settings() -> None:
    """max_steps 默认 35（README §3.5.2）."""
    llm = ScriptedLLMClient(["Final Answer: x"])
    engine = ReActEngine(llm=llm, tools=[_ConstTool("ok")])
    assert engine.max_steps == 35


# ============ Sprint 2.5：状态机集成测试 ============

def test_engine_status_done_on_success() -> None:
    """成功完成时，status 应流转到 DONE."""
    llm = ScriptedLLMClient([
        "Thought: t1\nAction: const_tool\nAction Input: {}",
        "Thought: t2\nFinal Answer: flag{ok}",
    ])
    engine = ReActEngine(llm=llm, tools=[_ConstTool("ok")], max_steps=5)

    result = engine.run("task")

    assert result.success is True
    assert engine.status.state == TaskState.DONE
    assert engine.status.is_terminal is True
    assert engine.status.final_answer == "flag{ok}"
    assert engine.status.step_count == 2
    assert engine.status.end_time > 0


def test_engine_status_failed_on_max_steps() -> None:
    """达到 max_steps 且无实质进展时，status 应流转到 FAILED."""
    scripts = [
        f"Thought: step {i}\nAction: const_tool\nAction Input: {{}}" for i in range(3)
    ]
    llm = ScriptedLLMClient(scripts)
    # Sprint 32.4b: 相同 observation 不算进展; progress_grace=0 → 超限后立即兜底
    custom = CircuitBreaker(max_steps=3, progress_grace_seconds=0.0)
    engine = ReActEngine(llm=llm, tools=[_ConstTool("x")], max_steps=3, breaker=custom)

    result = engine.run("task")

    assert result.success is False
    assert engine.status.state == TaskState.FAILED
    assert engine.status.is_terminal is True
    assert "最大步数" in engine.status.fail_reason


def test_engine_status_failed_on_format_errors() -> None:
    """连续格式错误终止时，status 应流转到 FAILED."""
    llm = ScriptedLLMClient(["no format", "still no format", "third no format"])
    engine = ReActEngine(
        llm=llm, tools=[_ConstTool("ok")], max_steps=10, max_format_errors=3
    )

    result = engine.run("task")

    assert result.success is False
    assert engine.status.state == TaskState.FAILED
    assert "格式解析失败" in engine.status.fail_reason


def test_engine_status_step_count_updates() -> None:
    """每步执行后 status.step_count 应更新."""
    llm = ScriptedLLMClient([
        "Thought: t1\nAction: const_tool\nAction Input: {}",
        "Thought: t2\nAction: const_tool\nAction Input: {}",
        "Thought: t3\nFinal Answer: done",
    ])
    captured_statuses: list[int] = []

    def on_step(step: ReActStep) -> None:
        captured_statuses.append(step.step_no)

    engine = ReActEngine(
        llm=llm, tools=[_ConstTool("ok")], max_steps=5, on_step=on_step
    )

    engine.run("task")

    assert captured_statuses == [1, 2, 3]
    assert engine.status.step_count == 3


def test_engine_max_rounds_default_is_10() -> None:
    """max_rounds 默认 10（README §3.3.1）."""
    llm = ScriptedLLMClient(["Final Answer: x"])
    engine = ReActEngine(llm=llm, tools=[_ConstTool("ok")])
    assert engine.max_rounds == 10


def test_engine_status_reset_on_new_run() -> None:
    """每次 run() 应重置 status（新的 TaskStatus）."""
    llm1 = ScriptedLLMClient([
        "Thought: t1\nAction: const_tool\nAction Input: {}",
        "Thought: t2\nFinal Answer: flag1",
    ])
    engine = ReActEngine(llm=llm1, tools=[_ConstTool("ok")], max_steps=5)
    engine.run("task1")
    first_status = engine.status
    assert first_status.state == TaskState.DONE

    # 第二次 run，应创建新 status
    llm2 = ScriptedLLMClient([
        "Thought: t1\nAction: const_tool\nAction Input: {}",
        "Thought: t2\nFinal Answer: flag2",
    ])
    engine.llm = llm2  # type: ignore[assignment]
    engine.run("task2")
    second_status = engine.status
    assert second_status is not first_status
    assert second_status.final_answer == "flag2"
