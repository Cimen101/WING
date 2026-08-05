"""Sprint 36 (WING-Corvus): 总指挥子包.

- Commander: 全局协作指挥 (领题分工 / 汇报分析 / 方向校准 / 静默)
- 通信协议: FileBus report (战略层→总指挥) + directive (总指挥→战略层)
"""
from ctf_agent.commander.commander import (
    Commander,
    CommanderDirective,
    DEFAULT_STYLES,
    TaskAssignment,
)

__all__ = ["Commander", "CommanderDirective", "TaskAssignment", "DEFAULT_STYLES"]
