"""长期记忆（L4 记忆层）：基于 ChromaDB 的向量库.

依据 README §3.3.2 与 §4.2：
- Collection: writeups
- Metadata: {"type": "web/pwn/crypto/...", "source": "picoCTF", "difficulty": 0-10}
- Document: 解题步骤文本
- 检索策略: HyDE（接入），此处只提供基础语义检索能力

设计：
- 依赖注入 embedding_function 与 client，便于测试用确定性 mock
- 默认 embedding_function=None 时 ChromaDB 用默认 sentence-transformers（首次会下载模型）
- 生产用 PersistentClient(path=chroma_path)，测试用 EphemeralClient 或 PersistentClient(tmp_path)
- 写入时自动生成唯一 doc_id（uuid），支持去重（同 id 覆盖）
"""

from __future__ import annotations

from typing import Any, Iterable, Protocol
from uuid import uuid4


class EmbeddingFunctionProtocol(Protocol):
    """ChromaDB 兼容的 embedding function 协议."""

    def __call__(self, input: list[str]) -> list[list[float]]: ...

    def name(self) -> str: ...


class LongTermMemory:
    """长期记忆：跨任务的 writeup 向量库.

    用法：
        mem = LongTermMemory()  # 持久化到 ./data/chroma
        mem.add_writeup("用 HEAD 方法获取 flag", metadata={"type": "web", "source": "picoCTF"})
        results = mem.search("如何获取 HTTP header 中的 flag", n_results=3)
    """

    COLLECTION_NAME = "writeups"

    def __init__(
        self,
        *,
        client: Any | None = None,
        embedding_function: EmbeddingFunctionProtocol | None = None,
        chroma_path: str = "./data/chroma",
        collection_name: str | None = None,
    ) -> None:
        # 延迟导入 chromadb，避免无此依赖时整体模块不可用
        import chromadb

        if client is None:
            self._client = chromadb.PersistentClient(path=chroma_path)
        else:
            self._client = client

        # 显式固定嵌入模型，避免依赖 Chroma 默认 embedding（版本升级可能改变
        # 默认维度，曾出现 256 维旧集合 vs 默认 384 维冲突导致 RAG 崩溃）。
        if embedding_function is None:
            from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

            embedding_function = DefaultEmbeddingFunction()
        self._embedding_function = embedding_function
        name = collection_name or self.COLLECTION_NAME
        # get_or_create_collection 在不存在时创建，存在时复用
        self._collection = self._client.get_or_create_collection(
            name=name,
            embedding_function=embedding_function,
            metadata={"hnsw:space": "cosine"},
        )

    def add_writeup(
        self,
        document: str,
        metadata: dict[str, Any] | None = None,
        doc_id: str | None = None,
    ) -> str:
        """写入一条 writeup.

        Args:
            document: 解题步骤文本
            metadata: 元数据（type/source/difficulty 等），可空
            doc_id: 文档 ID（不传则自动生成 uuid）

        Returns:
            写入的 doc_id
        """
        if doc_id is None:
            doc_id = uuid4().hex
        self._collection.add(
            documents=[document],
            metadatas=[metadata] if metadata is not None else [None],
            ids=[doc_id],
        )
        return doc_id

    def add_writeups(
        self,
        documents: list[str],
        metadatas: list[dict[str, Any]] | None = None,
        ids: list[str] | None = None,
    ) -> list[str]:
        """批量写入 writeup.

        Args:
            documents: 文档列表
            metadatas: 元数据列表（长度需与 documents 一致），可空
            ids: ID 列表（不传则自动生成）

        Returns:
            写入的 doc_id 列表
        """
        if not documents:
            return []
        if ids is None:
            ids = [uuid4().hex for _ in documents]
        if metadatas is None:
            metadatas = [None] * len(documents)
        self._collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids,
        )
        return ids

    def search(
        self,
        query: str,
        n_results: int = 3,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """语义检索相似 writeup.

        Args:
            query: 查询文本
            n_results: 返回结果数
            where: 元数据过滤条件（如 {"type": "web"}）

        Returns:
            结果列表，每项含 id/document/metadata/distance 字段，按相似度倒序
        """
        kwargs: dict[str, Any] = {
            "query_texts": [query],
            "n_results": n_results,
        }
        if where is not None:
            kwargs["where"] = where

        result = self._collection.query(**kwargs)

        # 标准化输出：ChromaDB 返回的是 list[list]（按 query 分组）
        ids_batch = result.get("ids", [[]])
        docs_batch = result.get("documents", [[]])
        metas_batch = result.get("metadatas", [[]])
        dists_batch = result.get("distances", [[]])

        output: list[dict[str, Any]] = []
        if not ids_batch:
            return output
        ids = ids_batch[0]
        docs = docs_batch[0] if docs_batch else [""] * len(ids)
        metas = metas_batch[0] if metas_batch else [None] * len(ids)
        dists = dists_batch[0] if dists_batch else [0.0] * len(ids)
        for i, doc_id in enumerate(ids):
            output.append({
                "id": doc_id,
                "document": docs[i] if i < len(docs) else "",
                "metadata": metas[i] if i < len(metas) else None,
                "distance": dists[i] if i < len(dists) else 0.0,
            })
        return output

    def get(self, doc_id: str) -> dict[str, Any] | None:
        """按 ID 获取文档.

        Returns:
            {"id", "document", "metadata"} 或 None（不存在时）
        """
        result = self._collection.get(ids=[doc_id])
        ids = result.get("ids", [])
        if not ids:
            return None
        docs = result.get("documents", [])
        metas = result.get("metadatas", [])
        return {
            "id": ids[0],
            "document": docs[0] if docs else "",
            "metadata": metas[0] if metas else None,
        }

    def count(self) -> int:
        """返回 collection 中文档数."""
        return self._collection.count()

    def clear(self) -> None:
        """清空 collection（删除并重建）."""
        name = self._collection.name
        self._client.delete_collection(name=name)
        self._collection = self._client.get_or_create_collection(
            name=name,
            embedding_function=self._embedding_function,
            metadata={"hnsw:space": "cosine"},
        )

    def list_ids(self) -> list[str]:
        """列出所有文档 ID."""
        result = self._collection.get()
        return list(result.get("ids", []))
