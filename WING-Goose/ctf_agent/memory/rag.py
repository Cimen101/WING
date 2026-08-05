"""RAG 检索增强（L4 记忆层）：HyDE 假设性文档检索.

依据 README §3.3.2：
- 采用 HyDE (Hypothetical Document Embeddings) 方法
- 先让 LLM 生成假设性解题步骤，再检索相似历史方案

流程：
1. LLM 接收任务描述，生成一段假设性的解题步骤文档（200-400字）
2. 用该文档作为 query 检索 LongTermMemory（向量相似度）
3. 把检索到的相似 writeup 格式化注入 ReAct system prompt

设计：
- generate_hyde_document(llm, task) 单次 LLM 调用（节省 API）
- RAGRetriever 封装完整流程，支持依赖注入 LLM 与 LongTermMemory
- 检索结果为空时返回空字符串（调用方据此决定是否注入）
"""

from __future__ import annotations

from typing import Any

from ctf_agent.llm import LLMClient
from ctf_agent.memory import LongTermMemory


HYDE_PROMPT_TEMPLATE = """你是一位 CTF 解题专家。请针对以下任务，生成一段假设性的解题步骤描述（不需要真正执行，只是预测可能的解题路径）。

任务：
{task}

要求：
1. 输出一段 200-400 字的解题思路描述，包含可能用到的工具、技术、关键步骤
2. 描述应具体（如"使用 nmap 扫描端口"而非"扫描"），便于语义检索匹配
3. 不要给出最终 flag，只描述解题过程
4. 不要使用 markdown 格式，输出纯文本

假设性解题步骤：
"""


def generate_hyde_document(
    llm: LLMClient,
    task: str,
    model: str | None = None,
    temperature: float = 0.3,
    max_tokens: int = 512,
) -> str:
    """调用 LLM 生成假设性解题步骤文档.

    Args:
        llm: LLM 客户端
        task: CTF 任务描述
        model: 模型名（None 用 LLM 默认）
        temperature: 温度（默认 0.3 鼓励多样性）
        max_tokens: 最大 token 数

    Returns:
        假设性解题步骤文本
    """
    from ctf_agent.llm import Message

    prompt = HYDE_PROMPT_TEMPLATE.format(task=task)
    messages = [Message(role="user", content=prompt)]
    result = llm.chat(
        messages,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return result.content.strip()


def format_retrieved_writeups(writeups: list[dict[str, Any]]) -> str:
    """把检索到的 writeup 列表格式化为可注入 prompt 的文本.

    Args:
        writeups: LongTermMemory.search() 返回的结果列表

    Returns:
        格式化文本，无结果时返回空字符串
    """
    if not writeups:
        return ""
    lines = ["# 相似历史解题方案（RAG 检索）"]
    for i, w in enumerate(writeups, 1):
        meta = w.get("metadata") or {}
        type_str = meta.get("type", "unknown")
        source = meta.get("source", "unknown")
        difficulty = meta.get("difficulty", "?")
        doc = w.get("document", "")
        # 截断过长文档避免污染上下文
        if len(doc) > 800:
            doc = doc[:800] + "..."
        lines.append(
            f"## 方案 {i}（type={type_str}, source={source}, difficulty={difficulty}）\n{doc}"
        )
    return "\n\n".join(lines)


class RAGRetriever:
    """RAG 检索器：用 HyDE 生成假设文档后检索长期记忆.

    用法：
        retriever = RAGRetriever(llm=llm, long_term=ltm)
        context = retriever.retrieve(task)
        # 把 context 注入 system prompt
    """

    def __init__(
        self,
        llm: LLMClient,
        long_term: LongTermMemory,
        *,
        model: str | None = None,
        n_results: int = 3,
        skip_hyde: bool = False,
    ) -> None:
        """
        Args:
            llm: LLM 客户端（用于 HyDE 生成）
            long_term: 长期记忆库
            model: LLM 模型名
            n_results: 检索结果数
            skip_hyde: 跳过 HyDE 直接用 task 原文检索（测试用，省 LLM 调用）
        """
        self.llm = llm
        self.long_term = long_term
        self.model = model
        self.n_results = n_results
        self.skip_hyde = skip_hyde

    def retrieve(self, task: str) -> str:
        """执行 HyDE + 检索流程，返回格式化的检索结果文本.

        Args:
            task: CTF 任务描述

        Returns:
            格式化文本，无结果时返回空字符串
        """
        # 1. 生成 HyDE 文档（或跳过用原文）
        if self.skip_hyde:
            query = task
        else:
            query = generate_hyde_document(
                self.llm, task, model=self.model
            )

        # 2. 检索长期记忆
        writeups = self.long_term.search(query, n_results=self.n_results)

        # 3. 格式化返回
        return format_retrieved_writeups(writeups)

    def retrieve_raw(self, task: str) -> tuple[str, list[dict[str, Any]]]:
        """返回 HyDE 文档与原始检索结果（调试用）.

        Returns:
            (hyde_doc, writeups)
        """
        if self.skip_hyde:
            query = task
        else:
            query = generate_hyde_document(
                self.llm, task, model=self.model
            )
        writeups = self.long_term.search(query, n_results=self.n_results)
        return query, writeups
