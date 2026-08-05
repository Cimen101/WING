"""轨迹复盘模块.

从解题轨迹中提取可复用经验:
- facts: 可核验的事实 (标注来源)
- lessons: 有效/无效操作总结
- skills: 可复用技能 (入库后可被后续题目检索命中)

特点:
1. 独立上下文: LLM 只读轨迹文本, 不看解题过程内部状态
2. 无幻觉核对: 逐条核对 facts 中的实体是否在轨迹中出现
3. 可选入库: skills 可入 md 技能库 和/或 经验库

用法:
    from ctf_agent.review import TrajectoryReviewer

    reviewer = TrajectoryReviewer(llm=llm)
    result = reviewer.review(trajectories=[("conservative", log_text), ...])
    if result.no_hallucination:
        reviewer.ingest_skills(result, skill_library=lib)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

# 复盘 LLM prompt (独立上下文, 只读轨迹文本)
_REVIEW_PROMPT = """你是 CTF 解题轨迹的独立复盘分析师。你会看到同一道 CTF 挑战的多条解题轨迹。

你的任务:
1. facts: 提取可核验的事实, 只写轨迹中明确出现的事实, 每条标注来源 (轨迹名 + 步骤号).
2. lessons: 总结哪些操作无效/浪费 (如反复试被过滤的 payload), 哪些思路有效.
3. skills: 整理 2-3 条可复用 skill, 面向未来同类题可直接照做, 必须只用轨迹中出现过的技术.

严格输出 JSON, 不要多余文字. JSON 结构:
{
  "facts": [{"claim": "...", "source": "conservative step 6"}],
  "lessons": [{"point": "...", "source": "aggressive step 8"}],
  "skills": [{"title": "...", "category": "web", "trigger": "何时适用",
              "body": "步骤1\\n步骤2\\n步骤3", "tags": [], "tools": ["http_request"],
              "pattern_features": ["特征1", "特征2"], "evidence_steps": ["innovative step 12"]}]
}
只依据轨迹内容, 不得臆造轨迹中不存在的事实.

⚠️ 强制要求: 你的整个回答必须是且仅是一个合法的 JSON 对象, 不要输出任何思考过程、解释、前言或后记."""


@dataclass
class ReviewResult:
    """复盘结果."""
    facts: list[dict] = field(default_factory=list)
    lessons: list[dict] = field(default_factory=list)
    skills: list[dict] = field(default_factory=list)
    raw_output: str = ""
    hallucination_check: dict = field(default_factory=dict)

    @property
    def no_hallucination(self) -> bool:
        return self.hallucination_check.get("no_hallucination", False)

    @property
    def fact_count(self) -> int:
        return len(self.facts)

    @property
    def skill_count(self) -> int:
        return len(self.skills)


def _parse_review_json(text: str) -> dict:
    """多级 fallback 解析 LLM 输出的 JSON."""
    # 1) ```json 代码块
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if m:
        text = m.group(1).strip()
    # 2) 从末尾平衡匹配提取最后一个完整 JSON 对象
    end = text.rfind("}")
    if end >= 0:
        depth = 0
        for i in range(end, -1, -1):
            if text[i] == "}":
                depth += 1
            elif text[i] == "{":
                depth -= 1
                if depth == 0:
                    cand = text[i: end + 1]
                    try:
                        return json.loads(cand)
                    except json.JSONDecodeError:
                        break
    # 3) 直接 json
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # 4) 单引号规范化
    text = re.sub(r"'(?=[a-zA-Z_][a-zA-Z0-9_]*'\s*:)", '"', text)
    text = re.sub(r"'([^']*?)'(\s*[,}\]])", r'"\1"\2', text)
    text = text.replace("True", "true").replace("False", "false").replace("None", "null")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        import ast
        conv = text.replace("true", "True").replace("false", "False").replace("null", "None")
        return ast.literal_eval(conv)


# 幻觉核对: 常见 CTF 实体关键词
_CLAIM_ENTITIES = re.compile(
    r"private_notes|sqlite_master|/\*\*/|127\.0\.0\.1|athena\{|400|500|"
    r"union|like|http_request|ssh_python|空格|注释|过滤|引号|"
    r"AES|CBC|RSA|Feistel|DES|XOR|base64|rot13|jwt|session|cookie|"
    r"flask|django|php|nginx|apache|docker|gdb|objdump|strings|nc|",
    re.I,
)


def check_no_hallucination(trajectories: list[tuple[str, str]], review_json: dict) -> dict:
    """无幻觉核对: 逐条核对 facts 中的实体是否在轨迹文本中出现.

    Args:
        trajectories: [(style_name, log_text), ...]
        review_json: 复盘 LLM 输出的 JSON dict

    Returns:
        {
            "fact_claims_checked": int,
            "fact_rows": [{"idx", "claim", "source", "entities", "missing", "pass"}],
            "no_hallucination": bool,
        }
    """
    blob = "\n".join(t for _, t in trajectories).lower()
    rows = []
    ok = True
    for i, f in enumerate(review_json.get("facts", [])):
        claim = f.get("claim", "")
        ents = set(_CLAIM_ENTITIES.findall(claim))
        missing = [e for e in ents if blob.count(e.lower()) == 0]
        row_pass = not missing
        ok = ok and row_pass
        rows.append({
            "idx": i, "claim": claim, "source": f.get("source", ""),
            "entities": sorted(ents), "missing_in_trajectory": missing,
            "pass": row_pass,
        })
    return {
        "fact_claims_checked": len(rows),
        "fact_rows": rows,
        "no_hallucination": ok,
    }


class TrajectoryReviewer:
    """轨迹复盘器 (独立上下文 LLM 复盘)."""

    def __init__(self, llm: Any = None) -> None:
        """
        Args:
            llm: LLM 客户端 (需有 chat(messages, temperature, max_tokens) 方法)
        """
        self.llm = llm

    def review(self, trajectories: list[tuple[str, str]]) -> ReviewResult:
        """复盘多条轨迹, 提取 facts/lessons/skills + 无幻觉核对.

        Args:
            trajectories: [(style_name, log_text), ...]

        Returns:
            ReviewResult
        """
        if not trajectories:
            return ReviewResult()
        if self.llm is None:
            return ReviewResult()

        # Stage A: LLM 复盘
        parts = [f"===== 轨迹 [{st}] =====\n{text}" for st, text in trajectories]
        user_msg = "\n\n".join(parts)
        msgs = [
            {"role": "system", "content": _REVIEW_PROMPT},
            {"role": "user", "content": user_msg},
        ]
        res = self.llm.chat(msgs, temperature=0.0, max_tokens=8000)
        raw = res.content
        review_json = _parse_review_json(raw)

        # Stage B: 无幻觉核对
        hallucination = check_no_hallucination(trajectories, review_json)

        return ReviewResult(
            facts=review_json.get("facts", []),
            lessons=review_json.get("lessons", []),
            skills=review_json.get("skills", []),
            raw_output=raw,
            hallucination_check=hallucination,
        )

    def ingest_skills(
        self,
        result: ReviewResult,
        skill_library: Any = None,
    ) -> list[str]:
        """将复盘产出的 skill 入库 (md 技能库).

        Args:
            result: 复盘结果
            skill_library: md 系统的 SkillLibrary 实例

        Returns:
            入库的 skill ID 列表
        """
        if not result.skills or skill_library is None:
            return []
        added_ids: list[str] = []
        for sk in result.skills:
            try:
                s = skill_library.add_or_update(
                    title=sk.get("title", "untitled"),
                    category=sk.get("category", "misc"),
                    trigger=sk.get("trigger", ""),
                    body=sk.get("body", ""),
                    tags=sk.get("tags", []),
                    tools=sk.get("tools", []),
                    script_ref="",
                    source_task="trajectory_review",
                    pattern_features=sk.get("pattern_features", []),
                )
                added_ids.append(s.id)
            except Exception:  # noqa: BLE001
                pass
        return added_ids

    def to_dict(self, result: ReviewResult) -> dict:
        """序列化为可保存的 dict."""
        return {
            "facts": result.facts,
            "lessons": result.lessons,
            "skills": result.skills,
            "hallucination_check": result.hallucination_check,
            "no_hallucination": result.no_hallucination,
            "fact_count": result.fact_count,
            "skill_count": result.skill_count,
        }


__all__ = ["TrajectoryReviewer", "ReviewResult", "check_no_hallucination"]
