"""智能体层（L3）.

阶段二：单智能体 ReAct 引擎。
阶段五（Sprint 5.9）：Planner-Executor-Critic 多智能体协作。
阶段六（Sprint 5.10）：并行执行 + 赛马机制 + 冲突仲裁。
"""

from ctf_agent.agent.multi_agent import (
    Critic,
    CriticReview,
    Executor,
    ExecutorReport,
    MultiAgentOrchestrator,
    MultiAgentResult,
    ParallelMultiAgentOrchestrator,
    Planner,
    RacingExecutor,
    RacingResult,
    SubTask,
    TOOL_WHITELIST,
    arbitrate_conflicts,
    filter_tools_by_type,
)
from ctf_agent.agent.prompts import build_system_prompt, build_task_prompt
from ctf_agent.agent.react import (
    ParsedAction,
    ReActEngine,
    ReActResult,
    ReActStep,
    parse_llm_output,
)

__all__ = [
    "Critic",
    "CriticReview",
    "Executor",
    "ExecutorReport",
    "MultiAgentOrchestrator",
    "MultiAgentResult",
    "ParsedAction",
    "ParallelMultiAgentOrchestrator",
    "Planner",
    "RacingExecutor",
    "RacingResult",
    "ReActEngine",
    "ReActResult",
    "ReActStep",
    "SubTask",
    "TOOL_WHITELIST",
    "arbitrate_conflicts",
    "build_system_prompt",
    "build_task_prompt",
    "filter_tools_by_type",
    "parse_llm_output",
]
