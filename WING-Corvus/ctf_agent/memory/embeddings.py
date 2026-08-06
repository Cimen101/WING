"""确定性本地 embedding 函数（无需下载模型，离线可用）.

背景
----
LongTermMemory 的 Chroma collection 由种子脚本以 ``KeywordHashEmbedding(dim=256)``
创建（64 条种子 writeup）。ChromaDB 的 ``get_or_create_collection`` 复用已存在
collection 时维度固定，若用其他维度 embedding（如官方 DefaultEmbeddingFunction 的
384 维）写入/检索会触发 ``InvalidDimensionException`` —— RAG 检索与自增长全部失效。

因此生产代码统一使用与种子一致的 256 维确定性 embedding：离线可用、跨版本稳定、
中英文混合文本有基本语义（unigram + bigram 哈希）。

若需更强语义检索：可注入自定义 ``embedding_function``（真实模型），
但需重建 collection 使其维度与模型一致（见 LongTermMemory.clear / seed 脚本）。
"""
from __future__ import annotations

import hashlib


class KeywordHashEmbedding:
    """基于关键词 hash 的确定性 embedding（支持中英文混合）.

    分词策略：
    - 英文：按空格切分，保留纯字母数字 token
    - 中文：按字符切分（unigram）+ 连续两字（bigram），捕获语义
    - 混合文本：先按空格切，再对每个 token 内部提取中文 bigram
    """

    def __init__(self, dim: int = 256) -> None:
        self.dim = dim

    def _tokenize(self, text: str) -> list[str]:
        """切分中英文混合文本为 token 列表."""
        tokens: list[str] = []
        # 1. 按空格/标点切出英文词
        for raw in text.lower().split():
            word = "".join(c for c in raw if c.isalnum())
            if not word:
                continue
            tokens.append(word)

        # 2. 提取中文 unigram + bigram（连续两个中文字符）
        chinese_chars = [c for c in text if "\u4e00" <= c <= "\u9fff"]
        for c in chinese_chars:
            tokens.append(c)
        for i in range(len(chinese_chars) - 1):
            tokens.append(chinese_chars[i] + chinese_chars[i + 1])

        return tokens

    def __call__(self, input: list[str]) -> list[list[float]]:
        results: list[list[float]] = []
        for text in input:
            vec = [0.0] * self.dim
            tokens = self._tokenize(text)
            for token in tokens:
                h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
                vec[h % self.dim] += 1.0
                # bigram 额外加权（中文语义匹配核心）
                if len(token) >= 2:
                    h2 = int(
                        hashlib.md5(token[:2].encode("utf-8")).hexdigest(), 16
                    )
                    vec[h2 % self.dim] += 0.5
            norm = sum(v * v for v in vec) ** 0.5
            if norm > 0:
                vec = [v / norm for v in vec]
            results.append(vec)
        return results

    def name(self) -> str:
        return "keyword_hash_embedding_v2"


__all__ = ["KeywordHashEmbedding"]
