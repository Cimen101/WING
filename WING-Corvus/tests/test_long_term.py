"""Sprint 3.2 验收测试：长期记忆（ChromaDB 向量库）.

覆盖：
1. LongTermMemory CRUD：add_writeup / get / count / clear / list_ids
2. 语义检索 search：相似度排序、metadata 过滤、空结果
3. 批量写入 add_writeups
4. 持久化：跨实例读取

测试用确定性 mock embedding function 避免下载 sentence-transformers 模型。
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from ctf_agent.memory import LongTermMemory


# ============ 测试用确定性 embedding function ============

class _MockEmbeddingFunction:
    """基于关键词 hash 的确定性 embedding（测试用）.

    简单策略：把文本分词，每个词 hash 到一个维度并累加，
    最后 L2 归一化。相同关键词的文本会有更接近的向量（cosine 距离更近）。
    """

    def __init__(self, dim: int = 64) -> None:
        self.dim = dim

    def __call__(self, input: list[str]) -> list[list[float]]:
        results: list[list[float]] = []
        for text in input:
            vec = [0.0] * self.dim
            for word in text.lower().split():
                # 去标点
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
def ephemeral_client():
    """每个测试独立的内存 chromadb client.

    注意：chromadb 0.5 的 EphemeralClient 在同进程内共享 collection 状态，
    所以 ltm fixture 用唯一 collection_name 隔离。
    """
    import chromadb
    return chromadb.EphemeralClient()


@pytest.fixture
def ltm(ephemeral_client):
    """带 mock embedding 的 LongTermMemory 实例（唯一 collection 名隔离）."""
    from uuid import uuid4
    return LongTermMemory(
        client=ephemeral_client,
        embedding_function=_MockEmbeddingFunction(),
        collection_name=f"writeups_test_{uuid4().hex[:8]}",
    )


# ============ CRUD 测试 ============

def test_add_writeup_returns_doc_id(ltm: LongTermMemory) -> None:
    doc_id = ltm.add_writeup("用 HEAD 方法获取 flag", metadata={"type": "web"})
    assert isinstance(doc_id, str)
    assert len(doc_id) > 0


def test_add_writeup_with_explicit_id(ltm: LongTermMemory) -> None:
    doc_id = ltm.add_writeup(
        "测试文档", metadata={"type": "test"}, doc_id="my-id-001"
    )
    assert doc_id == "my-id-001"
    doc = ltm.get("my-id-001")
    assert doc is not None
    assert doc["id"] == "my-id-001"
    assert doc["document"] == "测试文档"


def test_get_nonexistent_returns_none(ltm: LongTermMemory) -> None:
    assert ltm.get("nonexistent-id") is None


def test_count_increments_after_add(ltm: LongTermMemory) -> None:
    assert ltm.count() == 0
    ltm.add_writeup("doc 1")
    assert ltm.count() == 1
    ltm.add_writeup("doc 2")
    assert ltm.count() == 2


def test_list_ids_returns_all_ids(ltm: LongTermMemory) -> None:
    id1 = ltm.add_writeup("doc 1", doc_id="id-1")
    id2 = ltm.add_writeup("doc 2", doc_id="id-2")
    ids = ltm.list_ids()
    assert set(ids) == {id1, id2}


def test_clear_empties_collection(ltm: LongTermMemory) -> None:
    ltm.add_writeup("doc 1")
    ltm.add_writeup("doc 2")
    assert ltm.count() == 2
    ltm.clear()
    assert ltm.count() == 0


# ============ 批量写入 ============

def test_add_writeups_batch(ltm: LongTermMemory) -> None:
    docs = ["文档一", "文档二", "文档三"]
    metas = [{"type": "a"}, {"type": "b"}, {"type": "a"}]
    ids = ltm.add_writeups(docs, metas)
    assert len(ids) == 3
    assert ltm.count() == 3


def test_add_writeups_empty_list_returns_empty(ltm: LongTermMemory) -> None:
    ids = ltm.add_writeups([], [])
    assert ids == []
    assert ltm.count() == 0


def test_add_writeups_with_explicit_ids(ltm: LongTermMemory) -> None:
    docs = ["a", "b"]
    ids = ltm.add_writeups(docs, ids=["custom-1", "custom-2"])
    assert ids == ["custom-1", "custom-2"]
    assert set(ltm.list_ids()) == {"custom-1", "custom-2"}


# ============ 语义检索 ============

def test_search_returns_relevant_results(ltm: LongTermMemory) -> None:
    """检索应返回与查询相关的文档."""
    ltm.add_writeup(
        "用 curl 发送 HEAD 请求获取 HTTP 响应头中的 flag",
        metadata={"type": "web", "source": "picoCTF"},
        doc_id="doc-head",
    )
    ltm.add_writeup(
        "通过 SQL 注入读取 admin 用户密码字段",
        metadata={"type": "web", "source": "CTF"},
        doc_id="doc-sqli",
    )
    ltm.add_writeup(
        "缓冲区溢出覆盖返回地址，跳转 shellcode",
        metadata={"type": "pwn", "source": "pwnable.kr"},
        doc_id="doc-bof",
    )

    results = ltm.search("如何获取 HTTP 头部 flag", n_results=2)
    assert len(results) <= 2
    # 最相关的应该是 doc-head（基于 mock embedding 的关键词重叠）
    assert any(r["id"] == "doc-head" for r in results)


def test_search_returns_empty_when_collection_empty(ltm: LongTermMemory) -> None:
    results = ltm.search("任意查询")
    assert results == []


def test_search_with_metadata_filter(ltm: LongTermMemory) -> None:
    """where 过滤应只返回匹配 metadata 的文档."""
    ltm.add_writeup("web 文档一", metadata={"type": "web"}, doc_id="w1")
    ltm.add_writeup("web 文档二", metadata={"type": "web"}, doc_id="w2")
    ltm.add_writeup("pwn 文档", metadata={"type": "pwn"}, doc_id="p1")

    results = ltm.search("文档", n_results=10, where={"type": "web"})
    assert len(results) == 2
    for r in results:
        assert r["metadata"]["type"] == "web"


def test_search_results_contain_required_fields(ltm: LongTermMemory) -> None:
    ltm.add_writeup("doc", metadata={"type": "test"}, doc_id="d1")
    results = ltm.search("doc")
    assert len(results) == 1
    r = results[0]
    assert "id" in r
    assert "document" in r
    assert "metadata" in r
    assert "distance" in r
    assert r["id"] == "d1"
    assert r["document"] == "doc"
    assert r["metadata"] == {"type": "test"}


def test_search_n_results_limits_output(ltm: LongTermMemory) -> None:
    for i in range(5):
        ltm.add_writeup(f"文档 {i} 测试", doc_id=f"d{i}")
    results = ltm.search("测试", n_results=2)
    assert len(results) <= 2


# ============ 持久化测试 ============

def test_persistent_client_survives_new_instance(tmp_path) -> None:
    """PersistentClient 应能跨实例持久化数据."""
    import chromadb
    from ctf_agent.memory import LongTermMemory

    ef = _MockEmbeddingFunction()
    db_path = str(tmp_path / "chroma")

    # 第一次实例写入
    ltm1 = LongTermMemory(
        client=chromadb.PersistentClient(path=db_path),
        embedding_function=ef,
    )
    ltm1.add_writeup("持久化文档", metadata={"type": "test"}, doc_id="persist-1")
    assert ltm1.count() == 1

    # 第二次实例应能读到
    ltm2 = LongTermMemory(
        client=chromadb.PersistentClient(path=db_path),
        embedding_function=ef,
    )
    assert ltm2.count() == 1
    doc = ltm2.get("persist-1")
    assert doc is not None
    assert doc["document"] == "持久化文档"


def test_multiple_collections_isolated(ephemeral_client) -> None:
    """不同 collection 名应互相隔离."""
    from ctf_agent.memory import LongTermMemory

    ef = _MockEmbeddingFunction()
    ltm_a = LongTermMemory(
        client=ephemeral_client, embedding_function=ef, collection_name="writeups_a"
    )
    ltm_b = LongTermMemory(
        client=ephemeral_client, embedding_function=ef, collection_name="writeups_b"
    )
    ltm_a.add_writeup("doc in a", doc_id="a1")
    ltm_b.add_writeup("doc in b", doc_id="b1")

    assert ltm_a.count() == 1
    assert ltm_b.count() == 1
    assert ltm_a.get("b1") is None
    assert ltm_b.get("a1") is None
