"""短期 + 中期 + 长期记忆 + RAG（L4 记忆层）.

依据 README §3.3：
- 短期记忆：当前 ReAct 循环的最近 N 轮交互，直接拼入 prompt
- 中期记忆：当前任务的关键事实，结构化存储于 SQLite，每次推理前强制注入
- 长期记忆：跨任务 writeup 向量库，基于 ChromaDB
- RAG：HyDE 假设性文档检索，把相似历史方案注入 prompt
"""

from ctf_agent.memory.long_term import LongTermMemory
from ctf_agent.memory.mid_term import MidTermMemory
from ctf_agent.memory.rag import RAGRetriever, format_retrieved_writeups, generate_hyde_document
from ctf_agent.memory.short_term import ShortTermMemory
from ctf_agent.memory.skill_library import Skill, SkillLibrary

__all__ = [
    "LongTermMemory",
    "MidTermMemory",
    "RAGRetriever",
    "ShortTermMemory",
    "Skill",
    "SkillLibrary",
    "format_retrieved_writeups",
    "generate_hyde_document",
]
