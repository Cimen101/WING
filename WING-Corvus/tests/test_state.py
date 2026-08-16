"""Sprint 2.5 验收测试：任务状态机（TaskStatus / TaskState）."""

from __future__ import annotations

import time

import pytest

from ctf_agent.orchestrator import TaskState, TaskStatus


def test_initial_state_is_init() -> None:
    status = TaskStatus()
    assert status.state == TaskState.INIT
    assert status.is_terminal is False
    assert status.step_count == 0
    assert status.fail_reason == ""
    assert status.final_answer == ""


def test_legal_transition_init_to_executing() -> None:
    status = TaskStatus()
    status.mark_executing()
    assert status.state == TaskState.EXECUTING


def test_legal_transition_to_done() -> None:
    status = TaskStatus()
    status.mark_executing()
    status.mark_done("flag{test}")
    assert status.state == TaskState.DONE
    assert status.is_terminal is True
    assert status.final_answer == "flag{test}"
    assert status.end_time > 0


def test_legal_transition_to_failed() -> None:
    status = TaskStatus()
    status.mark_executing()
    status.mark_failed("达到最大步数 35")
    assert status.state == TaskState.FAILED
    assert status.is_terminal is True
    assert status.fail_reason == "达到最大步数 35"
    assert status.end_time > 0


def test_illegal_transition_init_to_done_raises() -> None:
    """不能从 INIT 直接跳到 DONE（必须先 EXECUTING）."""
    status = TaskStatus()
    with pytest.raises(ValueError, match="非法状态流转"):
        status.mark_done("flag")


def test_illegal_transition_init_to_failed_raises() -> None:
    status = TaskStatus()
    with pytest.raises(ValueError, match="非法状态流转"):
        status.mark_failed("error")


def test_illegal_transition_executing_to_init_raises() -> None:
    status = TaskStatus()
    status.mark_executing()
    with pytest.raises(ValueError, match="非法状态流转"):
        status.transition(TaskState.INIT)


def test_terminal_state_cannot_transition() -> None:
    """终态不能再流转."""
    status = TaskStatus()
    status.mark_executing()
    status.mark_done("flag")

    with pytest.raises(ValueError, match="非法状态流转"):
        status.mark_executing()
    with pytest.raises(ValueError, match="非法状态流转"):
        status.mark_failed("late error")


def test_step_count_tracking() -> None:
    status = TaskStatus()
    status.mark_executing()
    status.step_count = 5
    assert status.step_count == 5


def test_elapsed_seconds_in_progress() -> None:
    """未结束时 elapsed_seconds 持续增长."""
    status = TaskStatus()
    # 伪造 start_time 为 1 秒前
    status.start_time = time.time() - 1.0
    e1 = status.elapsed_seconds
    assert e1 >= 1.0
    time.sleep(0.01)
    e2 = status.elapsed_seconds
    assert e2 >= e1


def test_elapsed_seconds_frozen_after_terminal() -> None:
    """终态后 elapsed_seconds 固定."""
    status = TaskStatus()
    status.start_time = time.time() - 2.0
    status.mark_executing()
    status.mark_done("flag")

    e1 = status.elapsed_seconds
    time.sleep(0.05)
    e2 = status.elapsed_seconds
    assert e1 == e2  # end_time 已固定


def test_task_state_is_terminal_property() -> None:
    """TaskState.is_terminal 属性."""
    assert TaskState.DONE.is_terminal is True
    assert TaskState.FAILED.is_terminal is True
    assert TaskState.INIT.is_terminal is False
    assert TaskState.EXECUTING.is_terminal is False


def test_task_state_string_enum() -> None:
    """TaskState 是 str Enum，value 为字符串."""
    assert TaskState.INIT == "INIT"
    assert TaskState.EXECUTING == "EXECUTING"
    assert TaskState.DONE == "DONE"
    assert TaskState.FAILED == "FAILED"


def test_full_success_lifecycle() -> None:
    """完整成功生命周期：INIT -> EXECUTING -> DONE."""
    status = TaskStatus()
    assert status.state == TaskState.INIT
    status.mark_executing()
    assert status.state == TaskState.EXECUTING
    status.step_count = 3
    status.mark_done("picoCTF{success}")
    assert status.state == TaskState.DONE
    assert status.final_answer == "picoCTF{success}"
    assert status.is_terminal is True


def test_full_failure_lifecycle() -> None:
    """完整失败生命周期：INIT -> EXECUTING -> FAILED."""
    status = TaskStatus()
    status.mark_executing()
    status.step_count = 35
    status.mark_failed("达到最大步数 35")
    assert status.state == TaskState.FAILED
    assert status.fail_reason == "达到最大步数 35"
    assert status.is_terminal is True
