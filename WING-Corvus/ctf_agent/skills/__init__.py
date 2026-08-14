"""Sprint 16: 结构化 Skill 库 (替代 L-Memory 的 RAG writeup, 提供可重用的解题模式).

设计核心目标: 智能体在只有正常比赛题目描述时, 全自主解题, 期间能运用积累的 SKILL.

设计原则:
- 两层 Skill: 抽象 (按 vuln class) + 具体 (1题1Skill)
- 抽象 Skill: 通用解题模式, 跨题可重用
- 具体 Skill: 来自成功 trajectory, 提供具体场景参考
- 注入机制: 基于 (vuln_class, challenge_type, difficulty) 自动匹配
- 注入位置: ReAct system prompt (与 L-Memory 并存, 但结构化更强)

与 failed_trajectory_cache 的关系:
- failed_trajectory_cache: 失败案例 → 避免重蹈覆辙
- Skill library: 成功模式 → 加速自主解题
- 两者互补, 同时注入

数据结构:
- Skill: vuln_class + recon_signatures + recon_steps + exploit_template + tool_chain
- SkillLibrary: 注册/检索/注入
"""
from ctf_agent.skills.skill import Skill, SkillLevel
from ctf_agent.skills.library import SkillLibrary, get_default_library
from ctf_agent.skills.injector import format_skill_injection, inject_skills_into_prompt

__all__ = [
    "Skill",
    "SkillLevel",
    "SkillLibrary",
    "get_default_library",
    "format_skill_injection",
    "inject_skills_into_prompt",
]
