"""Skill 注入器.

将 Skill 格式化为可注入 ReAct system prompt 的文本.

注入策略:
- 注入位置: 反幻觉规则之前 (避免被规则遮挡)
- 内容: 抽象 Skill 模式 + (可选) 具体 Skill 参考
- 长度限制: 避免超过 max_chars (默认 4000 字符)
- 优先级: 匹配度 > 抽象层
"""
from __future__ import annotations

from ctf_agent.skills.skill import Skill, SkillLevel


# 注入模板
SKILL_INJECTION_HEADER = """# 🧠 积累的解题模式 (Skill 库)

**重要**: 以下是从过去成功 trajectory 中抽取的解题模式, 不是具体答案. 
请根据当前题目的实际情况, **自主决定**使用哪个 Skill 模式, 而**不是机械复制**步骤.

"""


def _format_single_skill(skill: Skill, compact: bool = False) -> str:
    """格式化单个 Skill 为注入文本."""
    lines = []
    # 标题
    title_prefix = "🧩 抽象模式" if skill.level == SkillLevel.ABSTRACT else "📌 具体参考"
    lines.append(f"## {title_prefix}: {skill.vuln_class}")
    if skill.source_challenge_id:
        lines.append(f"  (来源: {skill.source_challenge_id}, 已成功 {skill.success_count} 次)")
    else:
        lines.append(f"  (已成功 {skill.success_count} 次)")

    # 识别特征
    if skill.recon_signatures:
        sigs = " | ".join(skill.recon_signatures)
        lines.append(f"  识别特征: {sigs}")

    # 侦查步骤
    if skill.recon_steps and not compact:
        lines.append("  侦查步骤:")
        for i, step in enumerate(skill.recon_steps, 1):
            lines.append(f"    {i}. {step}")

    # 工具链
    if skill.tool_chain:
        tools = " → ".join(skill.tool_chain)
        lines.append(f"  推荐工具链: {tools}")

    # 攻击模板 (简化版不展开)
    if skill.exploit_template and not compact:
        # 最多 200 字符
        tmpl = skill.exploit_template[:200] + ("..." if len(skill.exploit_template) > 200 else "")
        lines.append(f"  攻击模板 (骨架, 需自主改写):\n    ```\n    {tmpl}\n    ```")

    # 坑点
    if skill.notes:
        lines.append("  ⚠️ 坑点:")
        for note in skill.notes:
            lines.append(f"    - {note}")

    return "\n".join(lines)


def format_skill_injection(
    skills: list[Skill],
    max_chars: int = 4000,
    prefer_abstract: bool = True,
) -> str:
    """格式化 Skill 列表为可注入的 prompt 文本.

    Args:
        skills: 检索到的 Skill 列表 (按匹配度排序)
        max_chars: 输出最大字符数
        prefer_abstract: 抽象层优先 (避免具体案例路径束缚 LLM)

    Returns:
        注入文本 (空字符串如果没有 skills)
    """
    if not skills:
        return ""

    # 分层
    abstract = [s for s in skills if s.level == SkillLevel.ABSTRACT]
    concrete = [s for s in skills if s.level == SkillLevel.CONCRETE]

    # 排序: 抽象层优先 (如果 prefer_abstract=True)
    if prefer_abstract:
        ordered = abstract + concrete
    else:
        ordered = skills

    out = [SKILL_INJECTION_HEADER]
    remaining = max_chars - len(out[0])

    for skill in ordered:
        block = _format_single_skill(skill)
        if len(block) > remaining:
            # 尝试紧凑模式
            compact = _format_single_skill(skill, compact=True)
            if len(compact) <= remaining:
                out.append(compact)
                remaining -= len(compact) + 2
            else:
                # 完全放不下, 跳过
                break
        else:
            out.append(block)
            remaining -= len(block) + 2

    if not out[0].endswith("\n"):
        out.append("")
    out.append("---\n")

    return "\n".join(out)


def format_mid_solve_injection(
    skills: list[Skill],
    max_chars: int = 1500,
) -> str:
    """格式化 mid-solve 动态注入文本 (简洁版, 只含步骤+禁忌).

    与 format_skill_injection 的区别:
    - 无 header (mid-solve 不需要重复说明)
    - 只含 recon_steps + notes (禁忌), 不含 exploit_template
    - 更短的 max_chars (1500 vs 4000)
    - 明确标记"仅供参考, 需自行验证"
    """
    if not skills:
        return ""
    lines = ["[经验参考] 以下为历史解题经验, 仅供参考, 需自行验证:\n"]
    for skill in skills:
        conf = skill.effective_confidence
        conf_tag = f"[{conf}]" if conf != "medium" else ""
        lines.append(f"【{skill.vuln_class}】{conf_tag}")
        if skill.recon_steps:
            for i, step in enumerate(skill.recon_steps[:5], 1):
                lines.append(f"  {i}. {step}")
        if skill.notes:
            lines.append("  ⚠️ 禁忌:")
            for note in skill.notes[:3]:
                lines.append(f"    - {note}")
        lines.append("")
    result = "\n".join(lines)
    if len(result) > max_chars:
        result = result[:max_chars] + "\n...(截断)"
    return result


def inject_skills_into_prompt(
    base_prompt: str,
    skills: list[Skill],
    max_chars: int = 4000,
) -> str:
    """将 Skill 注入到 system prompt (在反幻觉规则之前)."""
    skill_text = format_skill_injection(skills, max_chars=max_chars)
    if not skill_text:
        return base_prompt

    # 找到 "反幻觉规则" 位置, 插在它之前
    if "反幻觉规则" in base_prompt or "# ⚠️" in base_prompt:
        # 找到第一个出现的位置
        for marker in ["# ⚠️ 反幻觉规则", "反幻觉规则", "# ⚠️"]:
            idx = base_prompt.find(marker)
            if idx > 0:
                return base_prompt[:idx] + skill_text + base_prompt[idx:]
        return base_prompt + "\n" + skill_text
    else:
        # 没有反幻觉规则, 直接加在末尾
        return base_prompt + "\n" + skill_text
