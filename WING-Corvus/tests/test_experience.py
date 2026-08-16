"""Sprint 16：经验闭环测试（experience.ingest_solution）.

验证成功解题被去标识化后写入长期记忆（供 RAG 自增长），并覆盖：
flag 去标识化、失败/步数不足不沉淀、去重、写入内容不含明文 flag。
"""

from __future__ import annotations

from typing import Any

from ctf_agent.agent import ReActResult, ReActStep
from ctf_agent.experience import (
    build_writeup_document,
    ingest_solution,
    redact_flags,
)


class FakeLTM:
    """内存版长期记忆，避免测试依赖 chromadb."""

    def __init__(self) -> None:
        self.docs: dict[str, dict[str, Any]] = {}

    def get(self, doc_id: str) -> dict[str, Any] | None:
        return self.docs.get(doc_id)

    def add_writeup(
        self,
        document: str,
        metadata: dict[str, Any] | None = None,
        doc_id: str | None = None,
    ) -> str:
        did = doc_id or f"auto-{len(self.docs)}"
        self.docs[did] = {"document": document, "metadata": metadata or {}}
        return did


def _success_result() -> ReActResult:
    return ReActResult(
        success=True,
        final_answer="athena{s3cr3t_flag_value}",
        steps=[
            ReActStep(
                step_no=1,
                thought="用 sqlmap 注入",
                action="web_sqlmap",
                action_input='{"url": "http://t/?id=1"}',
                observation="dump users: admin, flag=athena{s3cr3t_flag_value}",
            ),
            ReActStep(
                step_no=2,
                thought="拿到 flag",
                is_final=True,
                final_answer="athena{s3cr3t_flag_value}",
            ),
        ],
        total_tokens=100,
    )


def _failed_result() -> ReActResult:
    return ReActResult(
        success=False,
        fail_reason="超出步数",
        steps=[ReActStep(step_no=1, action="web_dirscan", observation="404")],
    )


# ============ redact_flags ============

def test_redact_flags_removes_braces() -> None:
    txt = "得到 athena{abc} 和 flag{xyz}"
    out = redact_flags(txt)
    assert "athena{abc}" not in out
    assert "flag{xyz}" not in out
    assert "<REDACTED_FLAG>" in out


def test_redact_flags_removes_final_answer() -> None:
    out = redact_flags("答案是 SECRET123", final_answer="SECRET123")
    assert "SECRET123" not in out


def test_redact_long_hex() -> None:
    out = redact_flags("hash=" + "a" * 40)
    assert "a" * 40 not in out


# ============ ingest_solution ============

def test_ingest_success_writes_redacted() -> None:
    ltm = FakeLTM()
    doc_id = ingest_solution(
        "SQL 注入题", _success_result(), long_term=ltm, challenge_type="web"
    )
    assert doc_id is not None
    stored = ltm.get(doc_id)
    assert stored is not None
    # 关键：写入内容绝不含明文 flag
    assert "athena{s3cr3t_flag_value}" not in stored["document"]
    assert "<REDACTED_FLAG>" in stored["document"]
    assert stored["metadata"]["type"] == "web"
    assert stored["metadata"]["source"] == "agent-experience"


def test_ingest_failure_skipped() -> None:
    ltm = FakeLTM()
    doc_id = ingest_solution("失败题", _failed_result(), long_term=ltm)
    assert doc_id is None
    assert len(ltm.docs) == 0


def test_ingest_dedup() -> None:
    ltm = FakeLTM()
    r = _success_result()
    id1 = ingest_solution("同一题", r, long_term=ltm, challenge_type="web")
    id2 = ingest_solution("同一题", r, long_term=ltm, challenge_type="web")
    assert id1 == id2
    assert len(ltm.docs) == 1  # 去重，不重复写入


def test_ingest_min_steps() -> None:
    ltm = FakeLTM()
    short = ReActResult(
        success=True,
        final_answer="flag{x}",
        steps=[ReActStep(step_no=1, action="a", observation="o")],
    )
    doc_id = ingest_solution("秒解题", short, long_term=ltm, min_steps=2)
    assert doc_id is None


def test_build_writeup_contains_tool_chain() -> None:
    doc = build_writeup_document("题目", _success_result(), "web")
    assert "web_sqlmap" in doc
    assert "解题工具链" in doc
    assert "athena{s3cr3t_flag_value}" not in doc
