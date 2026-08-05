"""编排层（L2）.

依据 README §3.5.1，任务生命周期状态机：
    INIT -> RETRIEVAL -> PLANNING -> EXECUTING -> VERIFYING -> DONE / FAILED

阶段二简化为：INIT -> EXECUTING -> DONE / FAILED
（RETRIEVAL/PLANNING/VERIFYING 在阶段三/四接入）

阶段四扩展：CircuitBreaker（§3.5.2 熔断机制部分实现）
"""

from ctf_agent.orchestrator.breaker import BreakerAction, CircuitBreaker
from ctf_agent.orchestrator.state import TaskState, TaskStatus

__all__ = ["BreakerAction", "CircuitBreaker", "TaskState", "TaskStatus"]
