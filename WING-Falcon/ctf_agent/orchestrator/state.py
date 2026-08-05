"""任务状态机（阶段二简化版）.

依据 README §3.5.1，完整状态机为：
    INIT -> RETRIEVAL -> PLANNING -> EXECUTING -> VERIFYING -> DONE / FAILED

阶段二仅实现核心执行路径：INIT -> EXECUTING -> DONE / FAILED。
后续阶段补全 RETRIEVAL（RAG 检索）、PLANNING（多智能体派发）、VERIFYING（Critic 审核）。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class TaskState(str, Enum):
    """任务状态枚举."""

    INIT = "INIT"
    EXECUTING = "EXECUTING"
    DONE = "DONE"
    FAILED = "FAILED"

    @property
    def is_terminal(self) -> bool:
        """是否为终态（不可再流转）."""
        return self in (TaskState.DONE, TaskState.FAILED)


# 合法状态流转
_TRANSITIONS: dict[TaskState, set[TaskState]] = {
    TaskState.INIT: {TaskState.EXECUTING},
    TaskState.EXECUTING: {TaskState.DONE, TaskState.FAILED},
    TaskState.DONE: set(),  # 终态
    TaskState.FAILED: set(),  # 终态
}


@dataclass
class TaskStatus:
    """任务运行状态.

    Attributes:
        state: 当前状态
        step_count: 已执行步数
        start_time: 任务开始时间戳
        end_time: 任务结束时间戳（未结束时为 0）
        fail_reason: 失败原因（FAILED 时非空）
        final_answer: 最终答案（DONE 时非空）
    """

    state: TaskState = TaskState.INIT
    step_count: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    fail_reason: str = ""
    final_answer: str = ""

    def transition(self, new_state: TaskState) -> None:
        """流转到新状态，非法流转抛 ValueError."""
        if new_state not in _TRANSITIONS.get(self.state, set()):
            raise ValueError(
                f"非法状态流转: {self.state.value} -> {new_state.value}"
            )
        self.state = new_state
        if new_state.is_terminal:
            self.end_time = time.time()

    def mark_executing(self) -> None:
        """流转到 EXECUTING."""
        self.transition(TaskState.EXECUTING)

    def mark_done(self, final_answer: str) -> None:
        """流转到 DONE，记录最终答案."""
        self.final_answer = final_answer
        self.transition(TaskState.DONE)

    def mark_failed(self, reason: str) -> None:
        """流转到 FAILED，记录失败原因."""
        self.fail_reason = reason
        self.transition(TaskState.FAILED)

    @property
    def is_terminal(self) -> bool:
        """是否为终态."""
        return self.state.is_terminal

    @property
    def elapsed_seconds(self) -> float:
        """已耗时（秒），未结束时为当前耗时."""
        end = self.end_time if self.end_time > 0 else time.time()
        return end - self.start_time
