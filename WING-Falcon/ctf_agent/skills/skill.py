"""Skill 数据结构 (Sprint 16 P11-1).

一个 Skill 是一段"可重用的解题模式", 包含:
- vuln_class: 漏洞类型标识 (如 "cbc_bit_flipping")
- recon_signatures: 识别这个漏洞的关键词/模式 (用于自动匹配)
- recon_steps: 标准化侦查步骤 (给 LLM 流程参考)
- exploit_template: 攻击模板 (Python 代码骨架, 供 LLM 改写)
- tool_chain: 推荐工具链 (顺序使用)

两层 Skill:
- ABSTRACT: 抽象 (按 vuln class), 跨题可重用
- CONCRETE: 具体 (1题1Skill), 提供具体场景参考
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SkillLevel(str, Enum):
    """Skill 层级."""

    ABSTRACT = "abstract"  # 按 vuln class 抽象
    CONCRETE = "concrete"  # 1 题 1 Skill


@dataclass
class Skill:
    """结构化解题模式.

    Attributes:
        id: 唯一标识, 如 "abstract.cbc_bit_flipping" 或 "concrete.OWASP-A04-CBC-Medium"
        level: ABSTRACT / CONCRETE
        vuln_class: 漏洞类型, 如 "cbc_bit_flipping", "ssti_bypass", "jwt_weak_secret"
        challenge_type: web / pwn / crypto / reverse / forensics / misc
        difficulty: easy / medium / hard
        recon_signatures: 识别这个漏洞的特征, 如 ["AES", "CBC", "IV", "bit flipping"]
        recon_steps: 标准化侦查步骤列表
        exploit_template: 攻击模板 (Python 代码或 pseudo)
        tool_chain: 推荐工具链 (顺序)
        keywords: 注入提示用关键词 (与题目描述的简单 token 重叠)
        source_challenge_id: 具体 Skill 来自哪道题 (CONCRETE 才有)
        success_count: 已成功使用次数 (用于排序)
        notes: 备注/坑点 (Sprint 16 P11-3 重点)
        created_at: 创建时间戳
    """

    id: str
    level: SkillLevel
    vuln_class: str
    challenge_type: str
    difficulty: str
    recon_signatures: list[str] = field(default_factory=list)
    recon_steps: list[str] = field(default_factory=list)
    exploit_template: str = ""
    tool_chain: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    source_challenge_id: str | None = None
    success_count: int = 0
    notes: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def matches(self, task: str, challenge_type: str = "", difficulty: str = "") -> float:
        """根据题目描述/类型/难度返回匹配度 0-1.

        简化算法:
        - challenge_type 匹配: +0.2
        - difficulty 匹配: +0.1
        - keywords 重叠率: 0-0.4 (按 jaccard-like)
        - recon_signatures 子串匹配数: 0-0.3
        """
        score = 0.0
        task_lower = task.lower()

        if challenge_type and challenge_type.lower() == self.challenge_type.lower():
            score += 0.2
        if difficulty and difficulty.lower() == self.difficulty.lower():
            score += 0.1

        # keywords 重叠
        if self.keywords:
            task_tokens = set(task_lower.split())
            kw_set = set(k.lower() for k in self.keywords)
            overlap = len(task_tokens & kw_set)
            if kw_set:
                score += min(0.4, overlap / max(len(kw_set), 1) * 0.4)

        # recon_signatures 子串
        if self.recon_signatures:
            hit = sum(1 for s in self.recon_signatures if s.lower() in task_lower)
            if self.recon_signatures:
                score += min(0.3, hit / len(self.recon_signatures) * 0.3)

        return min(1.0, score)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "level": self.level.value if isinstance(self.level, SkillLevel) else self.level,
            "vuln_class": self.vuln_class,
            "challenge_type": self.challenge_type,
            "difficulty": self.difficulty,
            "recon_signatures": self.recon_signatures,
            "recon_steps": self.recon_steps,
            "exploit_template": self.exploit_template,
            "tool_chain": self.tool_chain,
            "keywords": self.keywords,
            "source_challenge_id": self.source_challenge_id,
            "success_count": self.success_count,
            "notes": self.notes,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Skill":
        return cls(
            id=d["id"],
            level=SkillLevel(d["level"]) if isinstance(d["level"], str) else d["level"],
            vuln_class=d["vuln_class"],
            challenge_type=d["challenge_type"],
            difficulty=d["difficulty"],
            recon_signatures=d.get("recon_signatures", []),
            recon_steps=d.get("recon_steps", []),
            exploit_template=d.get("exploit_template", ""),
            tool_chain=d.get("tool_chain", []),
            keywords=d.get("keywords", []),
            source_challenge_id=d.get("source_challenge_id"),
            success_count=d.get("success_count", 0),
            notes=d.get("notes", []),
            created_at=d.get("created_at", time.time()),
        )
