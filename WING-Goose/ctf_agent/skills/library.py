"""Skill 库.

负责 Skill 的注册/检索/持久化.

存储:
- JSON 格式存储到 data/skills/skill_library.json
- 启动时自动加载
- register() 自动持久化

检索:
- retrieve_for_task(): 根据 task + type + difficulty 返回 top_k Skill
- 排序: 匹配度 * 0.7 + (success_count / 10) * 0.3 (鼓励成功案例)
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from ctf_agent.skills.skill import Skill, SkillLevel


# 默认存储路径
DEFAULT_SKILL_PATH = Path("data/skills/skill_library.json")


class SkillLibrary:
    """Skill 库 - 注册/检索/持久化."""

    def __init__(self, storage_path: Path | None = None):
        self.storage_path = storage_path or DEFAULT_SKILL_PATH
        self._skills: dict[str, Skill] = {}
        self._load()

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            data = json.loads(self.storage_path.read_text(encoding="utf-8"))
            for sd in data.get("skills", []):
                skill = Skill.from_dict(sd)
                self._skills[skill.id] = skill
        except Exception as e:
            # 加载失败不阻塞, 保持空库
            print(f"[SkillLibrary] load failed: {e}")

    def save(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": "1.0",
            "updated_at": time.time(),
            "skill_count": len(self._skills),
            "skills": [s.to_dict() for s in self._skills.values()],
        }
        self.storage_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def register(self, skill: Skill, persist: bool = True) -> None:
        """注册 Skill (覆盖已存在的同 id)."""
        self._skills[skill.id] = skill
        if persist:
            self.save()

    def register_batch(self, skills: list[Skill], persist: bool = True) -> None:
        for s in skills:
            self._skills[s.id] = s
        if persist:
            self.save()

    def get(self, skill_id: str) -> Skill | None:
        return self._skills.get(skill_id)

    def all(self) -> list[Skill]:
        return list(self._skills.values())

    def by_level(self, level: SkillLevel) -> list[Skill]:
        return [s for s in self._skills.values() if s.level == level]

    def by_challenge_type(self, challenge_type: str) -> list[Skill]:
        return [s for s in self._skills.values() if s.challenge_type == challenge_type]

    def retrieve_for_task(
        self,
        task: str,
        challenge_type: str = "",
        difficulty: str = "",
        top_k: int = 3,
    ) -> list[Skill]:
        """根据 task + type + difficulty 检索最相关 Skill.

        排序公式: score = match_score * 0.7 + success_bonus * 0.3
        - match_score: Skill.matches() 0-1
        - success_bonus: min(1.0, success_count / 10) (10 次以上视为满分)
        """
        scored: list[tuple[Skill, float]] = []
        for skill in self._skills.values():
            m = skill.matches(task, challenge_type, difficulty)
            sb = min(1.0, skill.success_count / 10.0)
            score = m * 0.7 + sb * 0.3
            if score > 0.05:  # 过滤低匹配
                scored.append((skill, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [s for s, _ in scored[:top_k]]

    def retrieve_for_mid_solve(
        self,
        challenge_type: str,
        recent_observations: str,
        exclude_ids: set[str] | None = None,
        top_k: int = 2,
        min_score: float = 0.3,
    ) -> list[Skill]:
        """Mid-solve 动态检索: 基于累积 observation 匹配相关经验.

        与 retrieve_for_task 的区别:
        - 输入是 observation 文本 (包含工具输出) 而非 task 描述
        - 过滤已在 system prompt 注入的 skill (exclude_ids)
        - 使用更高的匹配阈值 (0.3 vs 0.05) 避免误匹配
        - 最多返回 2 条 (避免信息过载)
        """
        exclude_ids = exclude_ids or set()
        scored: list[tuple[Skill, float]] = []
        for skill in self._skills.values():
            if skill.id in exclude_ids:
                continue
            m = skill.matches(recent_observations, challenge_type, "")
            sb = min(1.0, skill.success_count / 10.0)
            # confidence 加权: high +0.1, medium +0, low -0.05
            conf = skill.effective_confidence
            conf_boost = 0.1 if conf == "high" else (-0.05 if conf == "low" else 0.0)
            score = m * 0.7 + sb * 0.3 + conf_boost
            if score >= min_score:
                scored.append((skill, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [s for s, _ in scored[:top_k]]

    def increment_success(self, skill_id: str) -> None:
        if skill_id in self._skills:
            self._skills[skill_id].success_count += 1
            self.save()

    def clear(self) -> None:
        """清空所有 Skill (用于基线测试隔离)."""
        self._skills.clear()
        if self.storage_path.exists():
            self.storage_path.unlink()

    def count(self) -> int:
        return len(self._skills)


_DEFAULT_LIBRARY: SkillLibrary | None = None


def get_default_library() -> SkillLibrary:
    """获取全局默认 Skill 库 (单例)."""
    global _DEFAULT_LIBRARY
    if _DEFAULT_LIBRARY is None:
        _DEFAULT_LIBRARY = SkillLibrary()
    return _DEFAULT_LIBRARY
