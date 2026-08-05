"""LLM 客户端层.

统一封装 OpenAI 兼容 API（OpenAI / DeepSeek / 其他兼容服务）的调用入口。
"""

from ctf_agent.llm.client import (
    ChatResult,
    ChatUsage,
    LLMClient,
    Message,
    Role,
)

__all__ = [
    "ChatResult",
    "ChatUsage",
    "LLMClient",
    "Message",
    "Role",
]
