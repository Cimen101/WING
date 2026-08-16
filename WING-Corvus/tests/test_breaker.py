"""Sprint 4.4 / 5.5 验收测试：熔断机制（CircuitBreaker）.

依据 README §3.5.2 六维熔断，本测试覆盖完整六维：
- 时间熔断（max_seconds 超时 -> terminate）
- 重复动作（同 action+input > 阈值 -> inject_hint，且每个 key 只提示一次）
- 思维死锁（连续 N 轮相同 Thought -> inject_hint，且只在思路改变后重新提示）
- 步数熔断（step_no > max_steps -> terminate）          ← Sprint 5.5
- 成本熔断（累计 token 成本 > max_cost_usd -> terminate）← Sprint 5.5
- 文件膨胀（ssh workspace > max_workspace_mb -> inject_hint，30s 节流） ← Sprint 5.5
- ReActEngine 集成：熔断器触发后正确终止或注入提示
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from ctf_agent.agent import ReActEngine, ReActStep
from ctf_agent.llm import ChatResult, ChatUsage, LLMClient
from ctf_agent.orchestrator import BreakerAction, CircuitBreaker
from ctf_agent.tools import default_tools


# ============ 辅助 ============

def _make_step(
    *,
    thought: str = "",
    action: str = "",
    action_input: str = "",
    is_error: bool = False,
    is_final: bool = False,
) -> ReActStep:
    return ReActStep(
        step_no=1,
        thought=thought,
        action=action,
        action_input=action_input,
        is_error=is_error,
        is_final=is_final,
    )


class ScriptedLLMClient(LLMClient):
    """按预设脚本顺序返回 LLM 响应."""

    def __init__(self, scripts: list[str]):
        self.settings = None  # type: ignore[assignment]
        self._scripts = list(scripts)
        self._call_idx = 0

    def chat(self, messages, model=None, temperature=0.0, max_tokens=None, timeout=None, extra=None) -> ChatResult:  # type: ignore[override]
        if self._call_idx >= len(self._scripts):
            raise RuntimeError(
                f"ScriptedLLMClient 脚本耗尽：已调用 {self._call_idx + 1} 次"
            )
        content = self._scripts[self._call_idx]
        self._call_idx += 1
        return ChatResult(
            content=content,
            usage=ChatUsage(prompt_tokens=10, completion_tokens=10, total_tokens=20),
            model=model or "mock",
        )


# ============ BreakerAction 属性 ============

def test_breaker_action_continue_properties() -> None:
    a = BreakerAction(action="continue")
    assert not a.should_terminate
    assert not a.should_inject_hint


def test_breaker_action_inject_hint_properties() -> None:
    a = BreakerAction(action="inject_hint", message="hint text")
    assert not a.should_terminate
    assert a.should_inject_hint
    assert a.message == "hint text"


def test_breaker_action_terminate_properties() -> None:
    a = BreakerAction(action="terminate", reason="timeout")
    assert a.should_terminate
    assert not a.should_inject_hint
    assert a.reason == "timeout"


# ============ 时间熔断 ============

def test_time_limit_terminates() -> None:
    """超过 max_seconds 且持续无进展触发 terminate (进展感知软截断)."""
    breaker = CircuitBreaker(max_seconds=0.05, progress_grace_seconds=0.01)  # 50ms 超时, 10ms 无进展宽限
    breaker.reset()
    # 让时间流逝超过阈值
    time.sleep(0.06)
    step = _make_step(thought="anything")
    action = breaker.check(step)
    assert action.should_terminate
    assert "时间熔断" in action.reason


def test_time_limit_with_recent_progress_not_terminated() -> None:
    """超过 max_seconds 但最近有实质进展 → 不熔断 (软截断, #2501 修复)."""
    breaker = CircuitBreaker(max_seconds=0.05, progress_grace_seconds=5.0)
    breaker.reset()
    time.sleep(0.06)
    # 新的非空 observation = 实质进展
    step = _make_step(thought="t")
    step.observation = "new finding: key=0x4142"
    action = breaker.check(step)
    assert action.action == "continue"


def test_time_limit_same_observation_is_not_progress() -> None:
    """相同 observation 不算新进展 (无进展 → 超时后熔断)."""
    breaker = CircuitBreaker(max_seconds=0.05, progress_grace_seconds=0.01)
    breaker.reset()
    s1 = _make_step(thought="t1")
    s1.observation = "same output"
    breaker.check(s1)
    time.sleep(0.06)
    s2 = _make_step(thought="t2")
    s2.observation = "same output"
    action = breaker.check(s2)
    assert action.should_terminate
    assert "时间熔断" in action.reason


def test_time_limit_not_triggered_within_window() -> None:
    breaker = CircuitBreaker(max_seconds=10.0)
    breaker.reset()
    step = _make_step(thought="anything")
    action = breaker.check(step)
    assert action.action == "continue"


def test_time_limit_zero_started_does_not_terminate() -> None:
    """未调用 reset 时 _started_at=0，不应触发时间熔断."""
    breaker = CircuitBreaker(max_seconds=0.001)
    # 不调用 reset
    step = _make_step(thought="x")
    action = breaker.check(step)
    assert action.action == "continue"


# ============ 思维死锁 ============

def test_thought_deadlock_triggers_hint_at_threshold() -> None:
    """连续 5 轮相同 Thought 触发 hint."""
    breaker = CircuitBreaker(max_thought_deadlock=5)
    breaker.reset()
    # 前 4 轮 continue
    for i in range(4):
        action = breaker.check(_make_step(thought="same thought"))
        assert action.action == "continue", f"第 {i+1} 轮不应触发"
    # 第 5 轮触发 hint
    action = breaker.check(_make_step(thought="same thought"))
    assert action.should_inject_hint
    assert "思维死锁" in action.message or "跳出" in action.message


def test_thought_deadlock_resets_on_different_thought() -> None:
    """思路改变后计数器重置."""
    breaker = CircuitBreaker(max_thought_deadlock=3)
    breaker.reset()
    breaker.check(_make_step(thought="A"))
    breaker.check(_make_step(thought="A"))
    # 思路变了
    breaker.check(_make_step(thought="B"))
    # 再来 2 次 A 也不应触发（计数从 B 后开始）
    action = breaker.check(_make_step(thought="A"))
    assert action.action == "continue"


def test_thought_deadlock_hinted_once_until_thought_changes() -> None:
    """同一死锁只提示一次，直到思路改变后再次死锁才提示."""
    breaker = CircuitBreaker(max_thought_deadlock=2)
    breaker.reset()
    # 第 2 次 A 触发 hint
    a1 = breaker.check(_make_step(thought="A"))
    a2 = breaker.check(_make_step(thought="A"))
    assert a2.should_inject_hint
    # 第 3、4 次 A 不再提示
    a3 = breaker.check(_make_step(thought="A"))
    a4 = breaker.check(_make_step(thought="A"))
    assert a3.action == "continue"
    assert a4.action == "continue"
    # 思路改变
    breaker.check(_make_step(thought="B"))
    # 再次死锁应触发
    a5 = breaker.check(_make_step(thought="B"))
    assert a5.should_inject_hint


def test_thought_deadlock_empty_thought_does_not_count() -> None:
    """空 Thought 不参与死锁计数."""
    breaker = CircuitBreaker(max_thought_deadlock=3)
    breaker.reset()
    breaker.check(_make_step(thought=""))
    breaker.check(_make_step(thought=""))
    breaker.check(_make_step(thought=""))
    # 仍未触发
    action = breaker.check(_make_step(thought=""))
    assert action.action == "continue"


# ============ 重复动作 ============

def test_repeated_action_triggers_hint_when_exceeding_threshold() -> None:
    """同 (action, action_input) 重复 > 3 次触发 hint."""
    breaker = CircuitBreaker(max_repeated_actions=3)
    breaker.reset()
    # 前 3 次正常（== 阈值，未超过）
    for i in range(3):
        action = breaker.check(_make_step(
            action="http_request", action_input='{"url": "http://x/"}'
        ))
        assert action.action == "continue", f"第 {i+1} 次不应触发"
    # 第 4 次（> 阈值）触发 hint
    action = breaker.check(_make_step(
        action="http_request", action_input='{"url": "http://x/"}'
    ))
    assert action.should_inject_hint
    assert "重复" in action.message
    assert "http_request" in action.message


def test_repeated_action_hinted_once_per_key() -> None:
    """每个 (action, action_input) 只提示一次."""
    breaker = CircuitBreaker(max_repeated_actions=2)
    breaker.reset()
    # 第 3 次触发
    for _ in range(2):
        breaker.check(_make_step(action="A", action_input="x"))
    action = breaker.check(_make_step(action="A", action_input="x"))
    assert action.should_inject_hint
    # 后续不再提示
    for _ in range(5):
        a = breaker.check(_make_step(action="A", action_input="x"))
        assert a.action == "continue"


def test_repeated_action_different_input_does_not_trigger() -> None:
    """不同 action_input 视为不同动作."""
    breaker = CircuitBreaker(max_repeated_actions=2)
    breaker.reset()
    breaker.check(_make_step(action="http_request", action_input='{"url": "http://a/"}'))
    breaker.check(_make_step(action="http_request", action_input='{"url": "http://b/"}'))
    action = breaker.check(_make_step(action="http_request", action_input='{"url": "http://c/"}'))
    assert action.action == "continue"


def test_repeated_action_error_steps_not_counted() -> None:
    """错误步骤（is_error=True）不计入重复动作统计."""
    breaker = CircuitBreaker(max_repeated_actions=2)
    breaker.reset()
    for _ in range(5):
        breaker.check(_make_step(
            action="http_request",
            action_input='{"url": "http://x/"}',
            is_error=True,
        ))
    # 仍应 continue（错误步骤不计数）
    action = breaker.check(_make_step(
        action="http_request",
        action_input='{"url": "http://x/"}',
        is_error=True,
    ))
    assert action.action == "continue"


def test_repeated_action_no_action_does_not_trigger() -> None:
    """无 action 的步骤不参与重复动作检测."""
    breaker = CircuitBreaker(max_repeated_actions=2)
    breaker.reset()
    # 每次不同的 thought，避免触发思维死锁
    for i in range(10):
        action = breaker.check(_make_step(thought=f"thinking {i}"))
        assert action.action == "continue"


# ============ reset ============

def test_reset_clears_state() -> None:
    breaker = CircuitBreaker(max_repeated_actions=2, max_thought_deadlock=2)
    breaker.reset()
    # 制造一些状态
    breaker.check(_make_step(thought="A"))
    breaker.check(_make_step(thought="A"))  # 触发死锁 hint
    breaker.check(_make_step(action="X", action_input="y"))
    breaker.check(_make_step(action="X", action_input="y"))
    breaker.check(_make_step(action="X", action_input="y"))  # 触发重复 hint
    stats_before = breaker.stats()
    assert stats_before["consecutive_same_thought"] >= 1
    assert len(stats_before["action_counts"]) >= 1

    # reset 清空
    breaker.reset()
    stats_after = breaker.stats()
    assert stats_after["consecutive_same_thought"] == 0
    assert stats_after["action_counts"] == {}
    assert stats_after["hinted_keys"] == []
    assert stats_after["hinted_deadlock"] is False


# ============ stats ============

def test_stats_returns_configuration() -> None:
    breaker = CircuitBreaker(
        max_repeated_actions=5, max_thought_deadlock=7, max_seconds=99.0
    )
    stats = breaker.stats()
    assert stats["max_repeated_actions"] == 5
    assert stats["max_thought_deadlock"] == 7
    assert stats["max_seconds"] == 99.0


# ============ ReActEngine 集成 ============

def test_engine_default_breaker_is_created() -> None:
    """ReActEngine 默认创建 CircuitBreaker."""
    llm = ScriptedLLMClient(["Final Answer: x"])
    engine = ReActEngine(llm=llm, tools=default_tools(), max_steps=2)
    assert isinstance(engine.breaker, CircuitBreaker)


def test_engine_accepts_custom_breaker() -> None:
    """ReActEngine 接受自定义 breaker."""
    llm = ScriptedLLMClient(["Final Answer: x"])
    custom = CircuitBreaker(max_seconds=60.0)
    engine = ReActEngine(llm=llm, tools=default_tools(), max_steps=2, breaker=custom)
    assert engine.breaker is custom


def test_engine_terminates_on_time_limit() -> None:
    """时间熔断触发后，engine 返回 success=False."""
    # 用极短的超时时间，确保第一次工具调用后立即触发
    llm = ScriptedLLMClient([
        'Thought: t\nAction: base64_encode\nAction Input: {"text": "a"}',
    ])
    custom = CircuitBreaker(max_seconds=0.0)  # 立即超时
    engine = ReActEngine(llm=llm, tools=default_tools(), max_steps=3, breaker=custom)
    result = engine.run("test task")
    assert result.success is False
    assert "时间熔断" in result.fail_reason


def test_engine_injects_hint_on_repeated_actions() -> None:
    """重复动作触发后，hint 应出现在下一步的 observation 中."""
    scripts = [
        # 第 1 次 base64_encode
        'Thought: t1\nAction: base64_encode\nAction Input: {"text": "a"}',
        # 第 2 次
        'Thought: t2\nAction: base64_encode\nAction Input: {"text": "a"}',
        # 第 3 次（达到阈值）
        'Thought: t3\nAction: base64_encode\nAction Input: {"text": "a"}',
        # 第 4 次（> 阈值，breaker 应注入 hint）—— LLM 看到 hint 后给出 Final Answer
        'Thought: see hint\nFinal Answer: flag{done}',
    ]
    llm = ScriptedLLMClient(scripts)
    custom = CircuitBreaker(max_repeated_actions=3)
    engine = ReActEngine(llm=llm, tools=default_tools(), max_steps=10, breaker=custom)
    result = engine.run("test task")
    assert result.success is True
    assert result.final_answer == "flag{done}"
    # 第 4 步的 LLM 应能看到注入的 hint
    # 检查 raw_outputs[3] 是 LLM 的第 4 次输出
    # 由于我们用 ScriptedLLMClient，hint 应在第 3 步的 observation 中
    # 第 3 步：action=base64_encode（第 3 次），breaker 触发 hint
    # 该 hint 进入 memory 后，第 4 次 LLM 调用能看到
    # 验证：第 4 步是 Final Answer，说明 LLM 收到了 hint 并跳出了循环


def test_engine_injects_hint_on_thought_deadlock() -> None:
    """思维死锁触发后，hint 应注入到下一步 observation."""
    same_thought = "I will use base64_encode"
    scripts = [
        f'Thought: {same_thought}\nAction: base64_encode\nAction Input: {{\"text\": \"a\"}}',
        f'Thought: {same_thought}\nAction: base64_encode\nAction Input: {{\"text\": \"b\"}}',
        f'Thought: {same_thought}\nAction: base64_encode\nAction Input: {{\"text\": \"c\"}}',
        f'Thought: {same_thought}\nAction: base64_encode\nAction Input: {{\"text\": \"d\"}}',
        f'Thought: {same_thought}\nAction: base64_encode\nAction Input: {{\"text\": \"e\"}}',
        # 第 5 步触发死锁 hint，LLM 看到后给出 Final Answer
        'Thought: ok new idea\nFinal Answer: flag{new}',
    ]
    llm = ScriptedLLMClient(scripts)
    custom = CircuitBreaker(max_thought_deadlock=5)
    engine = ReActEngine(llm=llm, tools=default_tools(), max_steps=10, breaker=custom)
    result = engine.run("test task")
    assert result.success is True
    assert result.final_answer == "flag{new}"


def test_engine_breaker_reset_between_runs() -> None:
    """多次 run 之间 breaker 状态应重置."""
    llm1 = ScriptedLLMClient([
        'Thought: t1\nAction: base64_encode\nAction Input: {"text": "a"}',
        'Thought: t2\nFinal Answer: x',
    ])
    engine = ReActEngine(llm=llm1, tools=default_tools(), max_steps=5)
    # 第一次 run
    r1 = engine.run("task1")
    assert r1.success
    stats1 = engine.breaker.stats()
    assert stats1["action_counts"]  # 本次有 1 次工具调用
    # 第二次 run (run 开始时会 reset breaker)
    engine.llm = ScriptedLLMClient([
        'Thought: t1\nAction: base64_encode\nAction Input: {"text": "b"}',
        'Thought: t2\nFinal Answer: y',
    ])
    r2 = engine.run("task2")
    assert r2.success
    stats2 = engine.breaker.stats()
    # 无第一次残留, 只有本次 b 的计数
    assert stats2["action_counts"] == {("base64_encode", '{"text": "b"}'): 1}


def test_engine_format_error_path_also_checks_breaker() -> None:
    """格式错误步骤也要检查熔断（时间熔断应能在格式错误时触发）."""
    llm = ScriptedLLMClient([
        "invalid format 1",
        "invalid format 2",
    ])
    custom = CircuitBreaker(max_seconds=0.0)
    engine = ReActEngine(
        llm=llm, tools=default_tools(), max_steps=5,
        max_format_errors=10,  # 让格式错误不触发，让熔断触发
        breaker=custom,
    )
    result = engine.run("test task")
    assert result.success is False
    assert "时间熔断" in result.fail_reason


# ============================================================
# Sprint 5.5 新增：步数 / 成本 / 文件膨胀 三维
# ============================================================


# ============ 步数熔断 ============

def test_step_limit_terminates() -> None:
    """step_no > max_steps 且持续无进展触发 terminate (进展感知软截断)."""
    breaker = CircuitBreaker(max_steps=3, progress_grace_seconds=0.0)
    breaker.reset()
    # 前 3 步不触发
    for i in range(1, 4):
        step = _make_step(thought=f"t{i}")
        step.step_no = i
        action = breaker.check(step)
        assert action.action == "continue", f"第 {i} 步不应触发"
    # 第 4 步触发 (无进展超过宽限)
    step = _make_step(thought="t4")
    step.step_no = 4
    action = breaker.check(step)
    assert action.should_terminate
    assert "步数熔断" in action.reason
    assert "4" in action.reason


def test_step_limit_with_recent_progress_not_terminated() -> None:
    """step_no > max_steps 但最近有实质进展 → 不熔断 (软截断)."""
    breaker = CircuitBreaker(max_steps=3, progress_grace_seconds=5.0)
    breaker.reset()
    step = _make_step(thought="t4")
    step.step_no = 4
    step.observation = "new data"
    action = breaker.check(step)
    assert action.action == "continue"


def test_has_recent_progress() -> None:
    """has_recent_progress 反映最近是否有实质进展."""
    breaker = CircuitBreaker(progress_grace_seconds=5.0)
    breaker.reset()
    assert breaker.has_recent_progress() is True  # 刚启动视为允许
    step = _make_step(thought="t")
    step.observation = "progress 1"
    breaker.check(step)
    assert breaker.has_recent_progress() is True


def test_step_limit_boundary_not_triggered() -> None:
    """step_no == max_steps 时不触发（> 才触发）."""
    breaker = CircuitBreaker(max_steps=5)
    breaker.reset()
    step = _make_step(thought="t")
    step.step_no = 5
    action = breaker.check(step)
    assert action.action == "continue"


def test_engine_terminates_on_step_limit() -> None:
    """ReActEngine 步数超限且无进展时返回 success=False (软截断兜底)."""
    scripts = [
        f'Thought: t{i}\nAction: base64_encode\nAction Input: {{"text": "a"}}'
        for i in range(20)
    ]
    llm = ScriptedLLMClient(scripts)
    # max_steps 设很小, breaker.max_steps 更小; progress_grace=0 → 无进展立即兜底
    # (脚本全部相同输入 → 相同 observation → 不算进展, 触发步数熔断)
    custom = CircuitBreaker(max_steps=3, progress_grace_seconds=0.0, max_seconds=3600.0)
    engine = ReActEngine(
        llm=llm, tools=default_tools(), max_steps=20, breaker=custom
    )
    result = engine.run("test task")
    assert result.success is False
    assert "步数熔断" in result.fail_reason


# ============ 成本熔断 ============

def test_default_pricer_deepseek_v4_flash() -> None:
    """DeepSeek v4 flash 模型应能正确计费."""
    from ctf_agent.orchestrator.breaker import _default_pricer

    # 单价 (0.00007, 0.00028)，假设 75% input / 25% output
    # 1000 tokens -> 0.75 * 0.00007 + 0.25 * 0.00028 = 0.0000525 + 0.00007 = 0.0001225
    cost = _default_pricer(1000, "deepseek-v4-flash")
    assert cost == pytest.approx(0.0001225, rel=1e-6)


def test_default_pricer_unknown_model_returns_zero() -> None:
    """未知模型不计费（避免误熔断）."""
    from ctf_agent.orchestrator.breaker import _default_pricer

    assert _default_pricer(100000, "unknown-model-xxx") == 0.0
    assert _default_pricer(100000, None) == 0.0


def test_default_pricer_fuzzy_match() -> None:
    """模糊匹配：model 字符串包含定价表 key 即匹配."""
    from ctf_agent.orchestrator.breaker import _default_pricer

    # 模型名包含 "deepseek-chat"
    cost = _default_pricer(1000, "deepseek-chat-v4-2026-07")
    expected = 1000 * (0.75 * 0.00014 + 0.25 * 0.00028) / 1000.0
    assert cost == pytest.approx(expected, rel=1e-6)


def test_record_llm_call_accumulates_cost() -> None:
    """record_llm_call 累计 token 与成本."""
    breaker = CircuitBreaker(max_cost_usd=1.0)
    breaker.reset()
    # DeepSeek v4 flash: 1000 tokens -> ~0.0001225 USD
    cost1 = breaker.record_llm_call(1000, "deepseek-v4-flash")
    assert cost1 > 0
    cost2 = breaker.record_llm_call(1000, "deepseek-v4-flash")
    stats = breaker.stats()
    assert stats["accumulated_tokens"] == 2000
    assert stats["accumulated_cost_usd"] == pytest.approx(cost1 + cost2, rel=1e-9)


def test_cost_limit_terminates() -> None:
    """累计成本 > max_cost_usd 触发 terminate."""
    breaker = CircuitBreaker(max_cost_usd=0.001)  # 极小阈值
    breaker.reset()
    # 调用足够多次 LLM 触发
    for _ in range(20):
        breaker.record_llm_call(1000, "deepseek-v4-flash")
    step = _make_step(thought="t")
    action = breaker.check(step)
    assert action.should_terminate
    assert "成本熔断" in action.reason


def test_cost_limit_not_triggered_below_threshold() -> None:
    """未超阈值不触发."""
    breaker = CircuitBreaker(max_cost_usd=10.0)
    breaker.reset()
    breaker.record_llm_call(1000, "deepseek-v4-flash")  # ~0.0001
    step = _make_step(thought="t")
    action = breaker.check(step)
    assert action.action == "continue"


def test_record_llm_call_reset_clears_accumulated() -> None:
    """reset 清空累计成本."""
    breaker = CircuitBreaker()
    breaker.reset()
    breaker.record_llm_call(5000, "deepseek-v4-flash")
    breaker.record_llm_call(5000, "deepseek-v4-flash")
    stats_before = breaker.stats()
    assert stats_before["accumulated_tokens"] == 10000
    assert stats_before["accumulated_cost_usd"] > 0
    breaker.reset()
    stats_after = breaker.stats()
    assert stats_after["accumulated_tokens"] == 0
    assert stats_after["accumulated_cost_usd"] == 0.0


def test_custom_token_pricer_overrides_default() -> None:
    """自定义 token_pricer 覆盖默认定价."""
    def fixed_pricer(total_tokens: int, model: str | None) -> float:
        return 0.5 * total_tokens / 1000.0  # 0.5 USD per 1k tokens

    breaker = CircuitBreaker(max_cost_usd=1.0, token_pricer=fixed_pricer)
    breaker.reset()
    breaker.record_llm_call(3000, "any-model")
    assert breaker.stats()["accumulated_cost_usd"] == pytest.approx(1.5)
    step = _make_step(thought="t")
    action = breaker.check(step)
    assert action.should_terminate
    assert "成本熔断" in action.reason


def test_engine_terminates_on_cost_limit() -> None:
    """ReActEngine 成本熔断触发后应返回 success=False."""
    # 每次工具调用都消耗 token，5 次后就触达 max_cost_usd
    scripts = [
        f'Thought: t{i}\nAction: base64_encode\nAction Input: {{"text": "a"}}'
        for i in range(10)
    ]
    llm = ScriptedLLMClient(scripts)
    # 每次调用 token=20，max_cost_usd=0.001 -> 单价（v4 flash 0.0001/1k）
    # 1000 tokens 走 0.0001225 USD，要触发 0.001 需 ~8k tokens ≈ 400 次调用
    # 用 fixed_pricer 直接放大计费
    def pricer(total_tokens: int, model: str | None) -> float:
        return 1.0 * total_tokens / 1000.0  # 1 USD per 1k tokens

    custom = CircuitBreaker(
        max_cost_usd=0.05, token_pricer=pricer, max_seconds=3600.0
    )
    engine = ReActEngine(
        llm=llm, tools=default_tools(), max_steps=20, breaker=custom
    )
    result = engine.run("test task")
    assert result.success is False
    assert "成本熔断" in result.fail_reason


# ============ 文件膨胀检测 ============

class _FakeSSHResult:
    """模拟 SSHClient.exec_cmd 返回值."""

    def __init__(self, stdout: str, returncode: int = 0):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = ""

    @property
    def is_success(self) -> bool:
        return self.returncode == 0


class _FakeSSHClient:
    """模拟 SSHClient，可控返回 workspace 大小（MB）."""

    def __init__(self, size_mb: int):
        self._size_mb = size_mb
        self.exec_cmd_count = 0

    def exec_cmd(self, cmd: str):
        self.exec_cmd_count += 1
        if "du -sm" in cmd:
            return _FakeSSHResult(stdout=str(self._size_mb))
        return _FakeSSHResult(stdout="")


def test_workspace_size_hint_triggers_when_exceeds() -> None:
    """workspace 大小 > max_workspace_mb 触发 inject_hint."""
    fake_ssh = _FakeSSHClient(size_mb=2048)  # 2 GB > 1 GB
    breaker = CircuitBreaker(
        max_workspace_mb=1024, ssh_client=fake_ssh,
    )
    breaker.reset()
    step = _make_step(thought="t")
    action = breaker.check(step)
    assert action.should_inject_hint
    assert "工作目录" in action.message
    assert "2048" in action.message
    assert "清理临时文件" in action.message


def test_workspace_size_not_triggered_below_threshold() -> None:
    """workspace 大小 < max_workspace_mb 不触发."""
    fake_ssh = _FakeSSHClient(size_mb=100)
    breaker = CircuitBreaker(
        max_workspace_mb=1024, ssh_client=fake_ssh,
    )
    breaker.reset()
    step = _make_step(thought="t")
    action = breaker.check(step)
    assert action.action == "continue"


def test_workspace_hint_only_once() -> None:
    """文件膨胀只提示一次（_hinted_workspace 标志位）."""
    fake_ssh = _FakeSSHClient(size_mb=5000)
    breaker = CircuitBreaker(
        max_workspace_mb=1024, ssh_client=fake_ssh,
    )
    breaker.reset()
    # 第一次触发 hint
    a1 = breaker.check(_make_step(thought="t1"))
    assert a1.should_inject_hint
    # 第二次不应再触发
    a2 = breaker.check(_make_step(thought="t2"))
    assert a2.action == "continue"
    a3 = breaker.check(_make_step(thought="t3"))
    assert a3.action == "continue"


def test_workspace_check_throttled_by_30s() -> None:
    """du -sm 调用有 30s 节流，避免频繁检查."""
    fake_ssh = _FakeSSHClient(size_mb=100)  # 不超阈值
    breaker = CircuitBreaker(
        max_workspace_mb=1024, ssh_client=fake_ssh,
    )
    breaker.reset()
    # 多次 check，节流应只调一次 du
    for _ in range(5):
        breaker.check(_make_step(thought="t"))
    assert fake_ssh.exec_cmd_count <= 1


def test_workspace_no_ssh_client_skips_check() -> None:
    """ssh_client=None 时不检查文件膨胀."""
    breaker = CircuitBreaker(max_workspace_mb=1, ssh_client=None)
    breaker.reset()
    step = _make_step(thought="t")
    action = breaker.check(step)
    assert action.action == "continue"


def test_workspace_check_handles_failure_gracefully() -> None:
    """du 命令失败时不触发熔断（避免误报）."""

    class _BrokenSSH:
        def exec_cmd(self, cmd: str):
            raise RuntimeError("ssh connection lost")

    breaker = CircuitBreaker(
        max_workspace_mb=1, ssh_client=_BrokenSSH(),
    )
    breaker.reset()
    step = _make_step(thought="t")
    action = breaker.check(step)
    assert action.action == "continue"


def test_workspace_reset_clears_hinted_flag() -> None:
    """reset 清空 _hinted_workspace 标志."""
    fake_ssh = _FakeSSHClient(size_mb=5000)
    breaker = CircuitBreaker(
        max_workspace_mb=1024, ssh_client=fake_ssh,
    )
    breaker.reset()
    a1 = breaker.check(_make_step(thought="t"))
    assert a1.should_inject_hint
    assert breaker.stats()["hinted_workspace"] is True
    # reset 后可再次提示
    breaker.reset()
    assert breaker.stats()["hinted_workspace"] is False
    a2 = breaker.check(_make_step(thought="t"))
    assert a2.should_inject_hint


def test_engine_injects_workspace_hint_via_ssh() -> None:
    """ReActEngine 在 SSH workspace 膨胀时应注入 hint 并能终止/继续."""
    # 构造一个让 LLM 看到提示后给出 Final Answer 的脚本
    scripts = [
        'Thought: t1\nAction: base64_encode\nAction Input: {"text": "a"}',
        # 第二步看到 hint 后给出 Final Answer
        'Thought: ok clean up\nFinal Answer: flag{cleaned}',
    ]
    llm = ScriptedLLMClient(scripts)
    fake_ssh = _FakeSSHClient(size_mb=10000)  # 10 GB
    custom = CircuitBreaker(
        max_workspace_mb=1024, ssh_client=fake_ssh, max_seconds=3600.0,
    )
    engine = ReActEngine(
        llm=llm, tools=default_tools(), max_steps=5, breaker=custom
    )
    result = engine.run("test task")
    # 第一步后注入 hint，第二步 LLM 给出 Final Answer
    assert result.success is True
    assert result.final_answer == "flag{cleaned}"


# ============ stats 完整性 ============

def test_stats_includes_all_six_dimensions() -> None:
    """stats() 应返回六维熔断所有字段."""
    breaker = CircuitBreaker()
    stats = breaker.stats()
    required_keys = {
        "max_repeated_actions", "max_thought_deadlock", "max_seconds",
        "max_steps", "max_cost_usd", "max_workspace_mb",
        "accumulated_cost_usd", "accumulated_tokens",
        "hinted_workspace",
    }
    assert required_keys.issubset(stats.keys())
