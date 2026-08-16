"""Sprint 3.4 验收测试：复盘闭环（Analyzer）.

覆盖：
1. generate_writeup：模板生成 writeup（不调 LLM）
2. generate_writeup_with_llm：LLM 生成 writeup
3. Analyzer.analyze：生成 writeup + metadata
4. Analyzer.analyze_and_store：生成并入库 LongTermMemory
5. 端到端：ReActEngine 执行后 Analyzer 入库，下次 RAG 能检索到
"""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import uuid4

import pytest

from ctf_agent.agent import ReActEngine, ReActResult, ReActStep
from ctf_agent.analyzer import (
    Analyzer,
    generate_writeup,
    generate_writeup_with_llm,
)
from ctf_agent.llm import ChatResult, ChatUsage, LLMClient, Message
from ctf_agent.memory import LongTermMemory, RAGRetriever
from ctf_agent.tools.base import Tool


# ============ 测试用 mock ============

class ScriptedLLMClient(LLMClient):
    def __init__(self, scripts: list[str]):
        self.settings = None  # type: ignore[assignment]
        self._scripts = list(scripts)
        self._call_idx = 0
        self.calls: list[list[Message]] = []

    def chat(self, messages, model=None, temperature=0.0, max_tokens=None, timeout=None, extra=None) -> ChatResult:  # type: ignore[override]
        self.calls.append(list(messages))  # type: ignore[arg-type]
        if self._call_idx >= len(self._scripts):
            raise RuntimeError("ScriptedLLMClient 脚本耗尽")
        content = self._scripts[self._call_idx]
        self._call_idx += 1
        return ChatResult(
            content=content,
            usage=ChatUsage(prompt_tokens=10, completion_tokens=10, total_tokens=20),
            model=model or "mock",
        )


class _ConstTool(Tool):
    name = "const_tool"
    description = "returns a constant"
    parameters = {"type": "object", "properties": {}}

    def __init__(self, output: str = "ok") -> None:
        self._output = output

    def execute(self, **_: Any) -> str:  # type: ignore[override]
        return self._output


class _MockEmbeddingFunction:
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


@pytest.fixture
def ltm():
    import chromadb
    return LongTermMemory(
        client=chromadb.EphemeralClient(),
        embedding_function=_MockEmbeddingFunction(),
        collection_name=f"writeups_analyzer_test_{uuid4().hex[:8]}",
    )


def _make_success_result() -> ReActResult:
    """构造一个成功的 ReActResult."""
    return ReActResult(
        success=True,
        final_answer="picoCTF{test_flag}",
        steps=[
            ReActStep(
                step_no=1,
                thought="我需要用 HEAD 请求",
                action="http_request",
                action_input='{"method": "HEAD", "url": "http://ctf/"}',
                observation="HTTP/1.1 200\nX-Flag: picoCTF{test_flag}",
            ),
            ReActStep(
                step_no=2,
                thought="在响应头找到 flag",
                is_final=True,
                final_answer="picoCTF{test_flag}",
            ),
        ],
        total_tokens=42,
    )


def _make_failure_result() -> ReActResult:
    """构造一个失败的 ReActResult."""
    return ReActResult(
        success=False,
        steps=[
            ReActStep(step_no=1, thought="尝试", is_error=True, error_msg="格式错误"),
        ],
        total_tokens=20,
        fail_reason="达到最大步数 5",
    )


# ============ generate_writeup 测试 ============

def test_generate_writeup_success_contains_required_fields() -> None:
    result = _make_success_result()
    writeup = generate_writeup("获取 HTTP 头部 flag", result)

    assert "CTF Writeup" in writeup
    assert "获取 HTTP 头部 flag" in writeup
    assert "成功" in writeup
    assert "picoCTF{test_flag}" in writeup
    assert "解题步骤" in writeup
    assert "http_request" in writeup
    assert "复盘" in writeup


def test_generate_writeup_failure_includes_fail_reason() -> None:
    result = _make_failure_result()
    writeup = generate_writeup("task", result)

    assert "失败" in writeup
    assert "达到最大步数 5" in writeup


def test_generate_writeup_no_steps() -> None:
    """无步骤时也应能生成（不会崩溃）."""
    result = ReActResult(success=True, final_answer="x", total_tokens=10)
    writeup = generate_writeup("task", result)
    assert "无步骤记录" in writeup


def test_generate_writeup_truncates_long_observation() -> None:
    """长 observation 应被截断."""
    long_obs = "x" * 500
    result = ReActResult(
        success=True,
        final_answer="x",
        steps=[
            ReActStep(step_no=1, thought="t", action="tool", action_input="{}",
                      observation=long_obs),
            ReActStep(step_no=2, is_final=True, final_answer="x"),
        ],
    )
    writeup = generate_writeup("task", result)
    assert "..." in writeup


def test_generate_writeup_max_steps_shown_limits_output() -> None:
    """max_steps_shown 应限制展示步数."""
    steps = [
        ReActStep(step_no=i, thought=f"step {i}", action="t", action_input="{}",
                  observation="o")
        for i in range(1, 6)
    ]
    steps.append(ReActStep(step_no=6, is_final=True, final_answer="x"))
    result = ReActResult(success=True, final_answer="x", steps=steps, total_tokens=100)

    writeup = generate_writeup("task", result, max_steps_shown=3)
    assert "省略 3 步" in writeup  # 共 6 步，展示 3 步，省略 3 步


def test_generate_writeup_extracts_tools_used() -> None:
    result = ReActResult(
        success=True,
        final_answer="x",
        steps=[
            ReActStep(step_no=1, thought="t", action="base64_decode", action_input="{}",
                      observation="result"),
            ReActStep(step_no=2, thought="t", action="http_request", action_input="{}",
                      observation="resp"),
            ReActStep(step_no=3, thought="t", action="base64_decode", action_input="{}",
                      observation="r2"),  # 重复
            ReActStep(step_no=4, is_final=True, final_answer="x"),
        ],
    )
    writeup = generate_writeup("task", result)
    # 工具去重，按首次使用顺序
    assert "base64_decode" in writeup
    assert "http_request" in writeup


# ============ generate_writeup_with_llm 测试 ============

def test_generate_writeup_with_llm_calls_llm() -> None:
    llm = ScriptedLLMClient(["LLM 生成的复盘内容"])
    result = _make_success_result()
    writeup = generate_writeup_with_llm(llm, "task", result)

    assert writeup == "LLM 生成的复盘内容"
    assert len(llm.calls) == 1


def test_generate_writeup_with_llm_prompt_contains_task_and_status() -> None:
    llm = ScriptedLLMClient(["内容"])
    result = _make_success_result()
    generate_writeup_with_llm(llm, "扫描 192.168.1.1", result)

    user_msg = llm.calls[0][0]
    assert "扫描 192.168.1.1" in user_msg.content
    assert "成功" in user_msg.content


# ============ Analyzer 测试 ============

def test_analyzer_analyze_template_mode() -> None:
    """use_llm=False 时用模板生成（不调 LLM）."""
    analyzer = Analyzer(use_llm=False)
    result = _make_success_result()
    writeup, meta = analyzer.analyze("task", result, metadata={"type": "web", "source": "picoCTF"})

    assert "CTF Writeup" in writeup
    assert meta["type"] == "web"
    assert meta["source"] == "picoCTF"
    assert meta["success"] is True
    assert meta["step_count"] == 2
    assert meta["tokens"] == 42


def test_analyzer_analyze_llm_mode() -> None:
    """use_llm=True 时调用 LLM."""
    llm = ScriptedLLMClient(["LLM 复盘内容"])
    analyzer = Analyzer(llm=llm, use_llm=True)
    result = _make_success_result()
    writeup, meta = analyzer.analyze("task", result)

    assert writeup == "LLM 复盘内容"
    assert len(llm.calls) == 1


def test_analyzer_use_llm_without_llm_raises() -> None:
    analyzer = Analyzer(use_llm=True)
    result = _make_success_result()
    with pytest.raises(ValueError, match="llm"):
        analyzer.analyze("task", result)


def test_analyzer_metadata_user_overrides_auto() -> None:
    """用户提供的 metadata 应覆盖自动生成的字段."""
    analyzer = Analyzer()
    result = _make_success_result()
    _, meta = analyzer.analyze("task", result, metadata={"success": False, "type": "pwn"})

    # 用户提供的 success=False 覆盖自动的 success=True
    assert meta["success"] is False
    assert meta["type"] == "pwn"


def test_analyzer_analyze_and_store_writes_to_long_term(ltm: LongTermMemory) -> None:
    """analyze_and_store 应写入 LongTermMemory."""
    analyzer = Analyzer()
    result = _make_success_result()
    doc_id = analyzer.analyze_and_store(
        "task", result, ltm,
        metadata={"type": "web", "source": "picoCTF", "difficulty": 2},
    )

    assert ltm.count() == 1
    doc = ltm.get(doc_id)
    assert doc is not None
    assert "CTF Writeup" in doc["document"]
    assert doc["metadata"]["type"] == "web"
    assert doc["metadata"]["success"] is True


def test_analyzer_analyze_and_store_with_explicit_id(ltm: LongTermMemory) -> None:
    analyzer = Analyzer()
    result = _make_success_result()
    doc_id = analyzer.analyze_and_store(
        "task", result, ltm, doc_id="custom-writeup-id"
    )
    assert doc_id == "custom-writeup-id"
    assert ltm.get("custom-writeup-id") is not None


# ============ 端到端：ReAct + Analyzer + RAG 闭环 ============

def test_e2e_analyzer_store_then_rag_retrieves(ltm: LongTermMemory) -> None:
    """端到端：任务1执行后 Analyzer 入库，任务2 RAG 能检索到."""
    # 任务1：执行成功
    scripts1 = [
        "Thought: 调用工具\nAction: const_tool\nAction Input: {}",
        "Thought: 完成\nFinal Answer: picoCTF{win}",
    ]
    llm1 = ScriptedLLMClient(scripts1)
    engine1 = ReActEngine(llm=llm1, tools=[_ConstTool("ok")], max_steps=5)
    result1 = engine1.run("用 HEAD 方法获取 flag")
    assert result1.success is True

    # Analyzer 入库
    analyzer = Analyzer()
    analyzer.analyze_and_store(
        "用 HEAD 方法获取 flag",
        result1,
        ltm,
        metadata={"type": "web", "source": "picoCTF", "difficulty": 2},
    )
    assert ltm.count() == 1

    # 任务2：相似任务，RAG 应能检索到任务1的 writeup
    # 用 skip_hyde=True 避免 LLM 调用（节省脚本）
    retriever = RAGRetriever(
        llm=ScriptedLLMClient([]),
        long_term=ltm,
        skip_hyde=True,
        n_results=3,
    )
    context = retriever.retrieve("获取 HTTP 响应头 flag")
    assert "CTF Writeup" in context or "HEAD" in context
    assert "picoCTF{win}" in context


def test_e2e_full_loop_with_engine_rag_injection(ltm: LongTermMemory) -> None:
    """完整闭环：任务1 入库 → 任务2 启动时 RAG 注入 system prompt."""
    # 任务1：执行 + 入库
    llm1 = ScriptedLLMClient([
        "Thought: t\nFinal Answer: picoCTF{first}",
    ])
    engine1 = ReActEngine(llm=llm1, tools=[_ConstTool("ok")], max_steps=3)
    result1 = engine1.run("curl HEAD 获取 flag")
    Analyzer().analyze_and_store(
        "curl HEAD 获取 flag", result1, ltm,
        metadata={"type": "web", "source": "test"},
    )

    # 任务2：开启 RAG，system prompt 应含历史 writeup
    # 注: 第 1 步必须调用工具再 Final Answer (反幻觉规则拒绝无工具直接提交)
    llm2 = ScriptedLLMClient([
        "假设性步骤：curl HEAD",  # HyDE
        "Thought: ok\nAction: const_tool\nAction Input: {}",  # ReAct step 1: 工具调用
        "Thought: ok\nFinal Answer: picoCTF{second}",  # ReAct step 2: 提交
    ])
    engine2 = ReActEngine(
        llm=llm2, tools=[_ConstTool("ok")], max_steps=3,
        long_term=ltm,
    )
    result2 = engine2.run("如何用 curl 获取响应头 flag")

    assert result2.success is True
    # 第 2 次 LLM 调用（ReAct 第 1 步）的 system prompt 应含历史 writeup
    second_call = llm2.calls[1]
    system_msg = second_call[0]
    assert "picoCTF{first}" in system_msg.content or "curl" in system_msg.content
