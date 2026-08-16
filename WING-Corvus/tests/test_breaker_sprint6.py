"""测试 CircuitBreaker 的 Sprint 6 P1 增强：无效步数检测."""
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctf_agent.orchestrator.breaker import CircuitBreaker


@dataclass
class MockStep:
    step_no: int
    thought: str = ""
    action: str = ""
    action_input: str = ""
    observation: str = ""
    is_error: bool = False


def test_normalize():
    assert CircuitBreaker._normalize_obs("  Hello\n  World  ") == "hello world"
    assert CircuitBreaker._normalize_obs("ABC") == "abc"
    assert CircuitBreaker._normalize_obs("") == ""
    print("  _normalize_obs: OK")


def test_similarity():
    assert CircuitBreaker._obs_similarity("abc", "abc") == 1.0
    assert CircuitBreaker._obs_similarity("hello world", "hello there") > 0.3
    assert CircuitBreaker._obs_similarity("abc", "xyz") < 0.5
    assert CircuitBreaker._obs_similarity("", "abc") == 0.0
    print("  _obs_similarity: OK")


def test_invalid_step_detection():
    """连续相同 action + 相似 observation 应触发无效步数提示."""
    cb = CircuitBreaker(max_invalid_steps=3, obs_similarity_threshold=0.85)
    cb.reset()
    obs = "PE32 executable for MS Windows (stripped), 4 sections"

    actions = []
    for i in range(1, 6):
        step = MockStep(
            step_no=i,
            thought=f"step {i}",
            action="ssh_exec",
            action_input=f"{{'cmd': 'strings fw{i}'}}",
            observation=obs,
        )
        action = cb.check(step)
        actions.append((i, action.action, action.message[:60] if action.message else ""))

    # 前 2 步是 continue，第 3 步开始应该提示
    for i, a, m in actions:
        print(f"  step {i}: action={a} msg={m!r}")
    # 第 3 步后应出现 inject_hint
    hint_steps = [i for i, a, _ in actions if a == "inject_hint"]
    assert len(hint_steps) >= 1, f"expected at least 1 hint, got {actions}"
    print(f"  无效步数检测: 第 {hint_steps} 步触发 inject_hint: OK")


def test_invalid_step_different_obs():
    """observation 不相似时不应触发."""
    cb = CircuitBreaker(max_invalid_steps=3)
    cb.reset()

    for i, obs in enumerate(["first result", "second result", "third result"], 1):
        step = MockStep(
            step_no=i,
            action="ssh_exec",
            action_input=f"{{'cmd': 'ls{i}'}}",
            observation=obs,
        )
        action = cb.check(step)
        assert action.action == "continue", f"step {i} should continue, got {action.action}"
    print("  不同 obs 不触发: OK")


def test_thought_deadlock_still_works():
    """思维死锁检测仍正常工作."""
    cb = CircuitBreaker(max_thought_deadlock=3)
    cb.reset()
    same_thought = "I should call strings again"

    triggered = False
    for i in range(1, 6):
        step = MockStep(
            step_no=i,
            thought=same_thought,
            action="ssh_exec" if i > 1 else "",
            action_input="{'cmd': 'ls'}" if i > 1 else "",
            observation="result" if i > 1 else "",
        )
        action = cb.check(step)
        if action.action == "inject_hint" and "思路" in action.message:
            triggered = True
            print(f"  思维死锁 step {i}: 触发 inject_hint: OK")
            break
    assert triggered, "思维死锁未触发"


def test_repeated_action_still_works():
    """重复动作检测仍正常工作."""
    cb = CircuitBreaker(max_repeated_actions=2)
    cb.reset()

    triggered = False
    for i in range(1, 5):
        step = MockStep(
            step_no=i,
            action="ssh_exec",
            action_input="{'cmd': 'ls'}",  # 完全相同
            observation=f"file {i}",
        )
        action = cb.check(step)
        if action.action == "inject_hint" and "重复" in action.message:
            triggered = True
            print(f"  重复动作 step {i}: 触发 inject_hint: OK")
            break
    assert triggered, "重复动作未触发"


if __name__ == "__main__":
    print("=== CircuitBreaker Sprint 6 P1 增强测试 ===\n")
    test_normalize()
    test_similarity()
    test_invalid_step_detection()
    test_invalid_step_different_obs()
    test_thought_deadlock_still_works()
    test_repeated_action_still_works()
    print("\n所有测试通过 ✓")
