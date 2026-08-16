"""Sprint 7 P1-1 修复测试：单步耗时过长熔断.

测试目标：
1. 单步耗时 > max_single_step_seconds → 注入降级提示（仅 1 次）
2. 同一 action 第二次仍超时不重复注入
3. 不同 action 各自独立触发
4. 短耗时 step 不触发
5. 默认阈值 120s 生效
"""
from __future__ import annotations

import time

import pytest

from ctf_agent.agent.react import ReActStep
from ctf_agent.orchestrator.breaker import BreakerAction, CircuitBreaker


def _make_step(
    step_no: int,
    *,
    action: str = "ssh_exec",
    thought: str = "do something",
    observation: str = "ok",
    is_error: bool = False,
    timestamp: float | None = None,
) -> ReActStep:
    """构造测试用 ReActStep."""
    return ReActStep(
        step_no=step_no,
        thought=thought,
        action=action,
        action_input='{"command": "ls"}',
        observation=observation,
        is_error=is_error,
        timestamp=timestamp if timestamp is not None else time.monotonic(),
    )


def test_long_step_triggers_hint():
    """单步耗时 > 阈值 → 注入降级提示."""
    breaker = CircuitBreaker(max_single_step_seconds=2.0)
    breaker.reset()
    # 构造一个 3 秒前的 step（耗时 3s）
    step = _make_step(1, timestamp=time.monotonic() - 3.0)
    action = breaker.check(step)
    assert action.should_inject_hint is True
    assert "单步耗时" in action.message or "⏱️" in action.message
    assert "docker" in action.message.lower() or "网络" in action.message


def test_long_step_same_action_no_repeat():
    """同一 action 第二次仍超时不重复注入（_long_step_hints 去重）."""
    breaker = CircuitBreaker(max_single_step_seconds=2.0)
    breaker.reset()
    step1 = _make_step(1, timestamp=time.monotonic() - 3.0)
    step2 = _make_step(2, timestamp=time.monotonic() - 3.0)
    a1 = breaker.check(step1)
    a2 = breaker.check(step2)
    assert a1.should_inject_hint is True
    # 第二次同 action 不再注入
    assert a2.action == "continue"


def test_long_step_different_actions_independent():
    """不同 action 各自独立触发."""
    breaker = CircuitBreaker(max_single_step_seconds=2.0)
    breaker.reset()
    s1 = _make_step(1, action="ssh_exec", timestamp=time.monotonic() - 3.0)
    s2 = _make_step(2, action="ssh_python", timestamp=time.monotonic() - 3.0)
    a1 = breaker.check(s1)
    a2 = breaker.check(s2)
    assert a1.should_inject_hint is True
    assert a2.should_inject_hint is True  # 第二个不同 action 仍触发


def test_short_step_no_hint():
    """短耗时 step 不触发."""
    breaker = CircuitBreaker(max_single_step_seconds=10.0)
    breaker.reset()
    step = _make_step(1, timestamp=time.monotonic() - 1.0)
    action = breaker.check(step)
    assert action.action == "continue"


def test_default_threshold_120s():
    """默认 max_single_step_seconds=120s."""
    breaker = CircuitBreaker()
    assert breaker.max_single_step_seconds == 120.0


def test_zero_threshold_disables_check():
    """max_single_step_seconds=0 → 禁用单步耗时检查."""
    breaker = CircuitBreaker(max_single_step_seconds=0)
    breaker.reset()
    step = _make_step(1, timestamp=time.monotonic() - 1000.0)
    action = breaker.check(step)
    assert action.action == "continue"


def test_no_action_no_hint():
    """无 action 的 step（如纯思考）不触发单步耗时提示."""
    breaker = CircuitBreaker(max_single_step_seconds=2.0)
    breaker.reset()
    step = _make_step(1, action="", timestamp=time.monotonic() - 10.0)
    action = breaker.check(step)
    assert action.action == "continue"


def test_reset_clears_hints():
    """reset() 后 _long_step_hints 清空，可重新触发."""
    breaker = CircuitBreaker(max_single_step_seconds=2.0)
    breaker.reset()
    s1 = _make_step(1, timestamp=time.monotonic() - 3.0)
    breaker.check(s1)  # 触发一次
    breaker.reset()
    s2 = _make_step(1, timestamp=time.monotonic() - 3.0)
    a = breaker.check(s2)
    assert a.should_inject_hint is True  # reset 后重新触发


def test_long_step_does_not_block_other_dimensions():
    """单步耗时提示不应阻止其他维度的检测（顺序：先短提示，再后续检查）."""
    breaker = CircuitBreaker(
        max_single_step_seconds=2.0,
        max_seconds=100.0,  # 任务总时间 100s
    )
    breaker.reset()
    # 让 _started_at 在 200s 前，模拟任务已超时 (同步无进展)
    breaker._started_at = time.monotonic() - 200.0
    breaker._last_progress_at = time.monotonic() - 200.0
    # observation 为空 → 不产生进展 (Sprint 32.4b: 有进展会延长, 无进展才熔断)
    step = _make_step(1, timestamp=time.monotonic() - 1.0, observation="")
    a = breaker.check(step)
    # 应该是时间熔断（terminate），不是单步耗时（inject_hint）
    assert a.should_terminate is True
    assert "时间" in a.reason or "超时" in a.reason or "熔断" in a.reason
