"""Skill 库（持续学习·L4 记忆层扩展）.

灵感来自 Hermes-Agent：agent 不只在结束后生成 writeup，还应把"解题过程中积累的
工具使用方法与套路"沉淀为结构化、可复用、可自我迭代的 Skill——作为 writeup 的
补充与升级形式。

writeup vs skill:
- writeup: 记录"这道题怎么解的"（叙事、进向量库供语义检索）。
- skill:   记录"这类题/这个工具怎么用最有效"（结构化、可累积、可直接照做），
  带使用统计，能自我迭代（合并去重、淘汰低价值），避免无限膨胀。

存储：
- data/skills/index.json : 全部 skill 的元数据 + 使用统计
- data/skills/<id>.md    : 每个 skill 的正文（人类可读，可手改）

自我迭代（去臃肿）：
1. 创建前查重：同方向高相似则"合并升级"而非新建（version+1）。
2. 使用反馈：命中成功→success_count++；反复无效→被淘汰。
3. prune(): 按方向保留 Top-K，淘汰长期零命中/低成功率条目。
4. 正文长度上限：超限压缩。
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_STOPWORDS = {
    "的", "了", "是", "在", "和", "与", "或", "题目", "任务", "请", "解决",
    "the", "a", "an", "to", "of", "and", "or", "for", "with", "flag", "ctf",
    "challenge", "task", "solve", "find", "get",
}
_MAX_BODY_LEN = 2500
_MAX_PER_CATEGORY = 40
_MERGE_THRESHOLD = 0.55


def _tokenize(text: str) -> set[str]:
    """粗分词：英文/数字词（含 49、v2 这类）+ 中文按 bigram 切分。

    中文用 bigram 而非整段，能让"模板注入"与"注入套路"共享"注入"，
    显著提升中文相似度判断，避免 merge 因整段不同而失效。
    """
    if not text:
        return set()
    out: set[str] = set()
    for w in re.findall(r"[a-zA-Z0-9_]{2,}", text.lower()):
        if w not in _STOPWORDS:
            out.add(w)
    for run in re.findall(r"[\u4e00-\u9fff]{2,}", text):
        for i in range(len(run) - 1):
            bg = run[i : i + 2]
            if bg not in _STOPWORDS:
                out.add(bg)
    return out


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _slugify(text: str, maxlen: int = 40) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "skill"
    return slug[:maxlen]


@dataclass
class Skill:
    """一条可复用的解题/用工具技能."""

    id: str
    title: str
    category: str  # web/pwn/reverse/crypto/misc/tool
    trigger: str  # 何时适用（触发特征）
    body: str  # 正文（核心步骤 + 工具用法 + 坑）
    tags: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    script_ref: str = ""
    source_tasks: list[str] = field(default_factory=list)
    pattern_features: list[str] = field(default_factory=list) # 套路特征 (用于跨题匹配)
    version: int = 1
    use_count: int = 0
    success_count: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def score(self) -> float:
        age_days = max(0.0, (time.time() - self.updated_at) / 86400.0)
        return self.success_count * 3.0 + self.use_count * 1.0 - age_days * 0.05


class SkillLibrary:
    """Skill 库：创建/合并/检索/统计/自我迭代."""

    def __init__(self, root: str | Path = "data/skills") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.index_path = self.root / "index.json"
        self._skills: dict[str, Skill] = {}
        self._load()

    # ---------- 持久化 ----------
    def _load(self) -> None:
        if not self.index_path.exists():
            return
        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        for sid, meta in data.get("skills", {}).items():
            md = self.root / f"{sid}.md"
            body = md.read_text(encoding="utf-8") if md.exists() else ""
            meta = {k: v for k, v in meta.items() if k not in ("body", "id")}
            self._skills[sid] = Skill(id=sid, body=body, **meta)

    def _save(self) -> None:
        index: dict[str, Any] = {"skills": {}}
        for sid, sk in self._skills.items():
            meta = asdict(sk)
            meta.pop("body", None)
            meta.pop("id", None)
            index["skills"][sid] = meta
            (self.root / f"{sid}.md").write_text(sk.body, encoding="utf-8")
        self.index_path.write_text(
            json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    # ---------- 基本操作 ----------
    def all(self) -> list[Skill]:
        return list(self._skills.values())

    def get(self, skill_id: str) -> Skill | None:
        return self._skills.get(skill_id)

    def _find_similar(self, category: str, title: str, trigger: str) -> Skill | None:
        target = _tokenize(f"{title} {trigger}")
        best_sim, best_sk = 0.0, None
        for sk in self._skills.values():
            if sk.category != category:
                continue
            sim = _jaccard(target, _tokenize(f"{sk.title} {sk.trigger}"))
            if sim > best_sim:
                best_sim, best_sk = sim, sk
        return best_sk if best_sim >= _MERGE_THRESHOLD else None

    def add_or_update(
        self,
        *,
        title: str,
        category: str,
        trigger: str,
        body: str,
        tags: list[str] | None = None,
        tools: list[str] | None = None,
        script_ref: str = "",
        source_task: str = "",
        pattern_features: list[str] | None = None, # 套路特征
    ) -> Skill:
        """新增 skill；同方向高相似则合并升级（去臃肿）。"""
        tags, tools = tags or [], tools or []
        pattern_features = pattern_features or []
        existing = self._find_similar(category, title, trigger)
        if existing is not None:
            # 合并时更新 title — 如果新 title 无 [避坑] 前缀而旧 title 有,
            # 说明成功经验覆盖了失败经验, title 应从 [避坑] 升级为正常
            if "[避坑]" in existing.title and "[避坑]" not in title:
                existing.title = title.strip()
            existing.body = self._merge_body(existing.body, body)
            existing.tags = sorted(set(existing.tags) | set(tags))
            existing.tools = sorted(set(existing.tools) | set(tools))
            # 合并套路特征 (去重)
            if pattern_features:
                existing.pattern_features = sorted(
                    set(existing.pattern_features) | set(pattern_features)
                )
            if script_ref:
                existing.script_ref = script_ref
            if source_task and source_task not in existing.source_tasks:
                existing.source_tasks = (existing.source_tasks + [source_task])[-8:]
            existing.version += 1
            existing.updated_at = time.time()
            self._compress_if_needed(existing)
            self._save()
            return existing

        sid = self._unique_id(category, title)
        sk = Skill(
            id=sid, title=title.strip(), category=category, trigger=trigger.strip(),
            body=body.strip(), tags=sorted(set(tags)), tools=sorted(set(tools)),
            script_ref=script_ref, source_tasks=[source_task] if source_task else [],
            pattern_features=sorted(set(pattern_features)),
        )
        self._compress_if_needed(sk)
        self._skills[sid] = sk
        self._save()
        return sk

    def _unique_id(self, category: str, title: str) -> str:
        base = f"{category}-{_slugify(title)}"
        sid, i = base, 2
        while sid in self._skills:
            sid, i = f"{base}-{i}", i + 1
        return sid

    @staticmethod
    def _merge_body(old: str, new: str) -> str:
        seen = {ln.strip() for ln in old.splitlines() if ln.strip()}
        merged, appended = old.splitlines(), False
        for ln in new.splitlines():
            s = ln.strip()
            if s and s not in seen:
                if not appended:
                    merged += ["", "<!-- merged -->"]
                    appended = True
                merged.append(ln)
                seen.add(s)
        return "\n".join(merged)

    @staticmethod
    def _compress_if_needed(sk: Skill) -> None:
        if len(sk.body) > _MAX_BODY_LEN:
            sk.body = sk.body[:_MAX_BODY_LEN].rstrip() + "\n\n<!-- compressed -->"

    # ---------- 使用反馈 ----------
    def mark_used(self, skill_id: str, *, success: bool) -> None:
        sk = self._skills.get(skill_id)
        if sk is None:
            return
        sk.use_count += 1
        if success:
            sk.success_count += 1
        sk.updated_at = time.time()
        self._save()

    # ---------- 检索 ----------
    def search(
        self, query: str, *, category: str | None = None, top_k: int = 3
    ) -> list[Skill]:
        """按 query 相关性 + 套路特征匹配 + 价值分检索 skill.

        改进: 基于 pattern_features (套路特征) 匹配, 而非题目名称.
        - 文本相关性 (jaccard): 0-10 分
        - 套路特征命中 (pattern_features 子串匹配): 0-6 分 (每命中 +1, 上限 6)
        - 价值分 (score): *0.1
        """
        q = _tokenize(query)
        query_lower = query.lower()
        scored: list[tuple[float, Skill]] = []
        for sk in self._skills.values():
            if category and sk.category != category:
                continue
            text = f"{sk.title} {sk.trigger} {' '.join(sk.tags)} {sk.body}"
            rel = _jaccard(q, _tokenize(text))
            # 套路特征匹配 (pattern_features 子串命中 query)
            pattern_hits = 0
            if sk.pattern_features:
                for feat in sk.pattern_features:
                    if feat.lower() in query_lower:
                        pattern_hits += 1
                pattern_hits = min(pattern_hits, 6)
            total = rel * 10 + pattern_hits + sk.score() * 0.1
            if total <= 0 and category is None:
                continue
            scored.append((total, sk))
        scored.sort(key=lambda x: -x[0])
        return [sk for _, sk in scored[:top_k]]

    def search_by_pattern(
        self,
        observation_text: str,
        *,
        category: str | None = None,
        top_k: int = 2,
        min_pattern_hits: int = 2,
    ) -> list[Skill]:
        """基于做题中累积的 observation 文本, 按套路特征检索 skill.

        用于做题中动态检索 — 当 agent 收集到足够线索 (observation) 后,
        用线索文本匹配 pattern_features, 找出套路相同的 skill.

        Args:
            observation_text: 当前累积的 observation 文本 (工具输出+题目描述)
            min_pattern_hits: 至少命中 N 个套路特征才返回 (避免误匹配)
        """
        if not observation_text:
            return []
        obs_lower = observation_text.lower()
        scored: list[tuple[float, Skill]] = []
        for sk in self._skills.values():
            if category and sk.category != category:
                continue
            if not sk.pattern_features:
                continue
            hits = sum(1 for feat in sk.pattern_features if feat.lower() in obs_lower)
            if hits < min_pattern_hits:
                continue
            # 套路命中分 + 价值分
            score = hits * 2.0 + sk.score() * 0.2
            scored.append((score, sk))
        scored.sort(key=lambda x: -x[0])
        return [sk for _, sk in scored[:top_k]]

    def format_for_prompt(
        self, query: str, *, category: str | None = None, top_k: int = 3
    ) -> str:
        """检索并渲染为注入 prompt 的文本；无命中返回空串。"""
        hits = self.search(query, category=category, top_k=top_k)
        if not hits:
            return ""
        lines = ["# 已积累的解题技能（Skill，来自过往经验，可直接照做）"]
        for sk in hits:
            body = sk.body if len(sk.body) <= 900 else sk.body[:900] + " ..."
            lines.append(
                f"\n## [{sk.category}] {sk.title}\n"
                f"- 适用: {sk.trigger}\n"
                + (f"- 套路特征: {', '.join(sk.pattern_features)}\n" if sk.pattern_features else "")
                + (f"- 工具: {', '.join(sk.tools)}\n" if sk.tools else "")
                + (f"- 脚本: {sk.script_ref}\n" if sk.script_ref else "")
                + f"{body}"
            )
        return "\n".join(lines)

    def format_for_mid_solve(
        self, observation_text: str, *, category: str | None = None
    ) -> str:
        """做题中动态检索并渲染 skill 提示.

        与 format_for_prompt 区别:
        - 基于 observation 文本 (做题中累积的线索) 检索, 而非题目描述
        - 要求 min_pattern_hits>=2 (套路特征至少命中2个, 避免误匹配)
        - 渲染为"中途提示"格式, 强调"参考用, 需自主判断"

        Returns:
            注入文本 (空字符串如果无命中)
        """
        hits = self.search_by_pattern(
            observation_text, category=category, top_k=2, min_pattern_hits=2
        )
        if not hits:
            return ""
        lines = [
            "# 💡 中途 skill 提示 (基于当前线索动态检索)",
            "以下 skill 与当前收集到的线索套路相似, 可参考其工具链和步骤.",
            "⚠️ 请自主判断是否适用当前题目, 不要机械复制 (skill 来自其他题, 细节可能不同).",
        ]
        for sk in hits:
            body = sk.body if len(sk.body) <= 600 else sk.body[:600] + " ..."
            lines.append(
                f"\n## [{sk.category}] {sk.title}\n"
                f"- 套路特征: {', '.join(sk.pattern_features)}\n"
                + (f"- 工具链: {' -> '.join(sk.tools)}\n" if sk.tools else "")
                + f"{body}"
            )
        return "\n".join(lines)

    # ---------- 自我迭代 ----------
    def prune(
        self, *, max_per_category: int = _MAX_PER_CATEGORY, min_score: float = -5.0
    ) -> int:
        """按方向保留 Top-K 高价值 skill，淘汰低价值条目。返回删除数量。"""
        by_cat: dict[str, list[Skill]] = {}
        for sk in self._skills.values():
            by_cat.setdefault(sk.category, []).append(sk)
        to_delete: list[str] = []
        for cat, sks in by_cat.items():
            sks.sort(key=lambda s: -s.score())
            for sk in sks[max_per_category:]:
                to_delete.append(sk.id)
            for sk in sks[:max_per_category]:
                # 长期零命中且分数极低的也淘汰
                if sk.use_count == 0 and sk.score() < min_score:
                    to_delete.append(sk.id)
        for sid in set(to_delete):
            self._skills.pop(sid, None)
            md = self.root / f"{sid}.md"
            if md.exists():
                md.unlink()
        if to_delete:
            self._save()
        return len(set(to_delete))

    def stats(self) -> dict[str, Any]:
        by_cat: dict[str, int] = {}
        for sk in self._skills.values():
            by_cat[sk.category] = by_cat.get(sk.category, 0) + 1
        return {
            "total": len(self._skills),
            "by_category": by_cat,
            "total_uses": sum(s.use_count for s in self._skills.values()),
            "total_success": sum(s.success_count for s in self._skills.values()),
        }


__all__ = ["Skill", "SkillLibrary"]
