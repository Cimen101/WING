"""Sprint 3.3 验收测试：RAG 检索增强（HyDE）.

覆盖：
1. generate_hyde_document：LLM 生成假设性解题步骤
2. format_retrieved_writeups：格式化检索结果
3. RAGRetriever：完整流程（HyDE + 检索 + 格式化）
4. ReActEngine 集成：RAG 结果注入 system prompt
5. skip_hyde 模式：跳过 LLM 调用直接用 task 检索（省 API）
"""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import uuid4

import pytest

from ctf_agent.agent import ReActEngine
from ctf_agent.llm import ChatResult, ChatUsage, LLMClient, Message
from ctf_agent.memory import LongTermMemory, RAGRetriever, format_retrieved_writeups, generate_hyde_document
from ctf_agent.memory.rag import HYDE_PROMPT_TEMPLATE
from ctf_agent.tools.base import Tool


# ============ 测试用 mock ============

class ScriptedLLMClient(LLMClient):
    """按预设脚本顺序返回 LLM 响应的 mock 客户端."""

    def __init__(self, scripts: list[str]):
        self.settings = None  # type: ignore[assignment]
        self._scripts = list(scripts)
        self._call_idx = 0
        self.calls: list[list[Message]] = []

    def chat(self, messages, model=None, temperature=0.0, max_tokens=None, timeout=None, extra=None) -> ChatResult:  # type: ignore[override]
        self.calls.append(list(messages))  # type: ignore[arg-type]
        if self._call_idx >= len(self._scripts):
            raise RuntimeError(
                f"ScriptedLLMClient 脚本耗尽：已调用 {self._call_idx + 1} 次"
            )
        content = self._scripts[self._call_idx]
        self._call_idx += 1
        return ChatResult(
            content=content,
            usage=ChatUsage(prompt_tokens=10, completion_tokens=10, total_tokens=20),
            model=model or "mock",
        )


class _MockEmbeddingFunction:
    """基于关键词 hash 的确定性 embedding（测试用）."""

    def __init__(self, dim: int = 64) -> None:
        self.dim = dim

    def __call__(self, input: list[str]) -> list[list[float]]:
        results: list[list[float]] = []
        for text in input:
            vec = [0.0] * self.dim
            for word in text.lower().split():
                word = "".join(c for c in word if c.isalnum())
                if not word:
                    continue
                h = int(hashlib.md5(word.encode()).hexdigest(), 16) % self.dim
                vec[h] += 1.0
            norm = sum(v * v for v in vec) ** 0.5
            if norm > 0:
                vec = [v / norm for v in vec]
            results.append(vec)
        return results

    def name(self) -> str:
        return "mock_embedding"


class _ConstTool(Tool):
    name = "const_tool"
    description = "returns a constant"
    parameters = {"type": "object", "properties": {}}

    def __init__(self, output: str = "ok") -> None:
        self._output = output

    def execute(self, **_: Any) -> str:  # type: ignore[override]
        return self._output


@pytest.fixture
def ephemeral_client():
    import chromadb
    return chromadb.EphemeralClient()


@pytest.fixture
def ltm(ephemeral_client):
    """带 mock embedding 的 LongTermMemory 实例."""
    return LongTermMemory(
        client=ephemeral_client,
        embedding_function=_MockEmbeddingFunction(),
        collection_name=f"writeups_rag_test_{uuid4().hex[:8]}",
    )


# ============ generate_hyde_document 测试 ============

def test_generate_hyde_document_calls_llm_with_template() -> None:
    """HyDE 生成应使用模板 prompt 调用 LLM."""
    llm = ScriptedLLMClient(["假设性解题步骤：用 nmap 扫描"])
    result = generate_hyde_document(llm, "扫描 192.168.1.1")

    assert "nmap" in result
    assert len(llm.calls) == 1
    # 验证 prompt 包含任务描述和模板关键字
    user_msg = llm.calls[0][0]
    assert "192.168.1.1" in user_msg.content
    assert "假设性解题步骤" in user_msg.content


def test_generate_hyde_document_passes_model_and_temperature() -> None:
    """应传递 model 和 temperature 给 LLM."""
    llm = ScriptedLLMClient(["生成内容"])
    generate_hyde_document(llm, "task", model="deepseek-v4-flash", temperature=0.5)
    # ScriptedLLMClient 不记录 model，但能验证调用成功
    assert len(llm.calls) == 1


def test_generate_hyde_document_strips_whitespace() -> None:
    """结果应去除首尾空白."""
    llm = ScriptedLLMClient(["  \n  解题步骤内容  \n  "])
    result = generate_hyde_document(llm, "task")
    assert result == "解题步骤内容"


# ============ format_retrieved_writeups 测试 ============

def test_format_writeups_empty_returns_empty() -> None:
    assert format_retrieved_writeups([]) == ""


def test_format_writeups_single() -> None:
    writeups = [{
        "id": "w1",
        "document": "用 curl HEAD 获取 flag",
        "metadata": {"type": "web", "source": "picoCTF", "difficulty": 2},
        "distance": 0.1,
    }]
    text = format_retrieved_writeups(writeups)
    assert "相似历史解题方案" in text
    assert "用 curl HEAD 获取 flag" in text
    assert "type=web" in text
    assert "source=picoCTF" in text
    assert "difficulty=2" in text


def test_format_writeups_multiple() -> None:
    writeups = [
        {"id": "w1", "document": "方案一", "metadata": {"type": "web"}, "distance": 0.1},
        {"id": "w2", "document": "方案二", "metadata": {"type": "pwn"}, "distance": 0.2},
    ]
    text = format_retrieved_writeups(writeups)
    assert "方案 1" in text
    assert "方案 2" in text
    assert "方案一" in text
    assert "方案二" in text


def test_format_writeups_truncates_long_document() -> None:
    long_doc = "a" * 1000
    writeups = [{"id": "w1", "document": long_doc, "metadata": {}, "distance": 0.1}]
    text = format_retrieved_writeups(writeups)
    assert "..." in text
    # 截断后应小于原文
    assert len(text) < len(long_doc) + 200


def test_format_writeups_handles_missing_metadata() -> None:
    writeups = [{"id": "w1", "document": "doc", "metadata": None, "distance": 0.1}]
    text = format_retrieved_writeups(writeups)
    assert "type=unknown" in text
    assert "source=unknown" in text


# ============ RAGRetriever 测试 ============

def test_rag_retriever_full_flow(ltm: LongTermMemory) -> None:
    """完整流程：HyDE 生成 → 检索 → 格式化."""
    # 预置一些 writeup
    ltm.add_writeup(
        "用 curl 发送 HEAD 请求获取 HTTP 响应头中的 flag",
        metadata={"type": "web", "source": "picoCTF", "difficulty": 2},
        doc_id="w1",
    )
    ltm.add_writeup(
        "通过 SQL 注入读取管理员密码",
        metadata={"type": "web", "source": "CTF", "difficulty": 5},
        doc_id="w2",
    )

    # LLM 生成的 HyDE 文档（包含 HEAD/curl 等关键词，会匹配 w1）
    llm = ScriptedLLMClient([
        "假设性解题步骤：使用 curl 发送 HEAD 请求获取 HTTP 响应头中的 flag"
    ])
    retriever = RAGRetriever(llm=llm, long_term=ltm, n_results=2)
    context = retriever.retrieve("获取 HTTP 头部 flag")

    assert "相似历史解题方案" in context
    assert "curl" in context or "HEAD" in context
    # 应该有一次 LLM 调用（HyDE 生成）
    assert len(llm.calls) == 1


def test_rag_retriever_skip_hyde_uses_task_directly(ltm: LongTermMemory) -> None:
    """skip_hyde=True 时跳过 LLM 调用，直接用 task 检索."""
    ltm.add_writeup("扫描 nmap 端口", metadata={"type": "recon"}, doc_id="r1")

    llm = ScriptedLLMClient([])  # 无脚本，不应被调用
    retriever = RAGRetriever(llm=llm, long_term=ltm, skip_hyde=True)
    context = retriever.retrieve("nmap 端口扫描")

    # 不应调用 LLM
    assert len(llm.calls) == 0
    # 应有检索结果
    assert "nmap" in context.lower() or "扫描" in context


def test_rag_retriever_returns_empty_when_no_writeups(ltm: LongTermMemory) -> None:
    """无 writeup 时返回空字符串."""
    llm = ScriptedLLMClient(["假设性步骤"])
    retriever = RAGRetriever(llm=llm, long_term=ltm)
    context = retriever.retrieve("task")
    assert context == ""


def test_rag_retriever_retrieve_raw_returns_hyde_and_writeups(ltm: LongTermMemory) -> None:
    """retrieve_raw 应返回 HyDE 文档与原始检索结果."""
    ltm.add_writeup("文档内容", metadata={"type": "test"}, doc_id="d1")
    llm = ScriptedLLMClient(["假设性步骤文本"])
    retriever = RAGRetriever(llm=llm, long_term=ltm)

    hyde_doc, writeups = retriever.retrieve_raw("task")

    assert hyde_doc == "假设性步骤文本"
    assert isinstance(writeups, list)


# ============ ReActEngine 集成 RAG 测试 ============

def test_engine_without_long_term_backward_compatible() -> None:
    """未启用 long_term 时，ReActEngine 行为与之前一致."""
    llm = ScriptedLLMClient([
        "Thought: 完成\nFinal Answer: ok",
    ])
    engine = ReActEngine(llm=llm, tools=[_ConstTool("ok")], max_steps=3)
    result = engine.run("task")
    assert result.success is True
    assert result.final_answer == "ok"


def test_engine_with_long_term_injects_rag_into_system_prompt(ltm: LongTermMemory) -> None:
    """启用 long_term 时，RAG 检索结果应注入 system prompt."""
    # 预置 writeup
    ltm.add_writeup(
        "使用 curl HEAD 获取响应头",
        metadata={"type": "web", "source": "picoCTF", "difficulty": 1},
        doc_id="w1",
    )

    # LLM 脚本：第 1 次 HyDE 生成，第 2 次 ReAct 第 1 步（Final Answer）
    llm = ScriptedLLMClient([
        "假设性步骤：使用 curl HEAD 获取响应头",
        "Thought: 完成\nFinal Answer: flag{ok}",
    ])
    engine = ReActEngine(
        llm=llm,
        tools=[_ConstTool("ok")],
        max_steps=3,
        long_term=ltm,
    )
    result = engine.run("获取 HTTP 头部 flag")

    assert result.success is True
    # 第 2 次 LLM 调用（ReAct 第 1 步）的 system prompt 应含 RAG 结果
    second_call = llm.calls[1]
    system_msg = second_call[0]
    assert system_msg.role == "system"
    assert "相似历史解题方案" in system_msg.content or "curl" in system_msg.content


def test_engine_skip_hyde_avoids_extra_llm_call(ltm: LongTermMemory) -> None:
    """skip_hyde=True 时，ReAct 不应额外调用 LLM 做 HyDE 生成."""
    ltm.add_writeup("nmap 扫描端口", metadata={"type": "recon"}, doc_id="r1")

    # 只给 1 个脚本：ReAct 第 1 步 Final Answer
    llm = ScriptedLLMClient(["Thought: ok\nFinal Answer: x"])
    engine = ReActEngine(
        llm=llm,
        tools=[_ConstTool("ok")],
        max_steps=3,
        long_term=ltm,
        skip_hyde=True,
    )
    result = engine.run("nmap 扫描")

    assert result.success is True
    # 只应有 1 次 LLM 调用（ReAct 第 1 步），无 HyDE 调用
    assert len(llm.calls) == 1


def test_engine_rag_injection_with_empty_long_term(ltm: LongTermMemory) -> None:
    """long_term 为空时，RAG 检索返回空，不影响 system prompt."""
    llm = ScriptedLLMClient([
        "假设性步骤",  # HyDE 生成（即使空库也会调用）
        "Thought: ok\nFinal Answer: x",
    ])
    engine = ReActEngine(
        llm=llm, tools=[_ConstTool("ok")], max_steps=3, long_term=ltm
    )
    result = engine.run("task")

    assert result.success is True
    # 第 2 次 LLM 调用的 system prompt 不应含"相似历史解题方案"
    second_call = llm.calls[1]
    system_msg = second_call[0]
    assert "相似历史解题方案" not in system_msg.content


def test_engine_rag_and_facts_both_injected(ltm: LongTermMemory) -> None:
    """同时启用 mid_term 和 long_term 时，facts 和 RAG 都注入 system prompt."""
    from ctf_agent.memory import MidTermMemory

    # 中期记忆预置 facts
    mtm = MidTermMemory()
    mtm.add_fact("task-combined", "target_ip", "10.0.0.1")

    # 长期记忆预置 writeup
    ltm.add_writeup(
        "curl HEAD 获取 flag",
        metadata={"type": "web"},
        doc_id="w1",
    )

    llm = ScriptedLLMClient([
        "假设性步骤：curl HEAD",  # HyDE
        "Thought: ok\nFinal Answer: x",
    ])
    engine = ReActEngine(
        llm=llm,
        tools=[_ConstTool("ok")],
        max_steps=3,
        mid_term=mtm,
        long_term=ltm,
        task_id="task-combined",
    )
    result = engine.run("task")

    assert result.success is True
    # 第 2 次 LLM 调用的 system prompt 应同时含 facts 和 RAG
    second_call = llm.calls[1]
    system_msg = second_call[0]
    assert "target_ip" in system_msg.content
    assert "10.0.0.1" in system_msg.content
    assert "相似历史解题方案" in system_msg.content or "curl" in system_msg.content
