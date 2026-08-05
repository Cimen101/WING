"""知识层（L-Knowledge）.

结构化的领域知识，可注入 system prompt 或供工具引用。

模块：
- kali_arsenal: Kali 工具兵器谱（每个方向有哪些工具、何时用、怎么用），
  让 agent 在不逐一试探的情况下清晰掌握 Kali 中可用工具与用法。
"""

from ctf_agent.knowledge.kali_arsenal import (
    ARSENAL,
    KaliTool,
    format_arsenal,
    list_categories,
)

__all__ = [
    "ARSENAL",
    "KaliTool",
    "format_arsenal",
    "list_categories",
]
