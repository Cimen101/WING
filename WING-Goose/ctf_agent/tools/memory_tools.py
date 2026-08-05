"""记忆相关工具（L5 工具层）.

提供 Agent 主动记录关键事实的工具，对接中期记忆（MidTermMemory）。
依据 README §3.3.1，关键事实防丢机制需要 Agent 能在推理过程中主动持久化重要信息。
"""

from __future__ import annotations

from typing import Any

from ctf_agent.memory import MidTermMemory
from ctf_agent.tools.base import Tool


class RememberFactTool(Tool):
    """记录关键事实到中期记忆.

    Agent 调用此工具把发现的关键信息（IP/端口/版本/漏洞函数等）写入 MidTermMemory，
    这些事实会在后续每轮推理中注入 system prompt 顶部，防止多轮推理后丢失。
    """

    name = "remember_fact"
    description = (
        "记录一条关键事实到中期记忆，防止多轮推理后丢失。"
        "用于持久化 IP、开放端口、服务版本、漏洞函数名、凭据等关键信息。"
        "记录后的事实会在后续每步推理中自动注入提示词。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "key": {
                "type": "string",
                "description": "事实键名，如 target_ip / open_ports / service_version / vuln_function",
            },
            "value": {
                "type": "string",
                "description": "事实值，如 192.168.1.1 / 22,80,443 / Apache 2.4.49",
            },
        },
        "required": ["key", "value"],
    }

    def __init__(self, mid_term: MidTermMemory, task_id: str) -> None:
        self._mid_term = mid_term
        self._task_id = task_id

    def execute(self, key: str, value: str, **_: Any) -> str:  # type: ignore[override]
        self._mid_term.add_fact(self._task_id, key, value)
        return f"已记录关键事实: {key}={value}"


def memory_tools(mid_term: MidTermMemory, task_id: str) -> list[Tool]:
    """返回记忆相关工具集."""
    return [RememberFactTool(mid_term=mid_term, task_id=task_id)]
