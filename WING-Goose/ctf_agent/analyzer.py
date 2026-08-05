"""复盘闭环（L2 编排层 + L4 记忆层）：Analyzer 模块.

依据 README §3.3.2 与阶段四验收：
- 任务结束后，Analyzer 生成结构化总结（writeup）
- 调用 LongTermMemory.add_writeup 入库，供后续 RAG 检索复用
- 默认用模板生成（不调 LLM，节省 API）；可选 LLM 增强生成更详细总结

写入 metadata: {"type": "...", "source": "...", "difficulty": 0-10, "success": true/false}
"""

from __future__ import annotations

from typing import Any

from ctf_agent.agent import ReActResult
from ctf_agent.llm import LLMClient, Message
from ctf_agent.memory import LongTermMemory


# ============ 模板生成 ============

WRITEUP_TEMPLATE = """# CTF Writeup

## 任务
{task}

## 结果
- 状态: {status}
- Flag: {flag}
- 步数: {step_count}
- Token 消耗: {tokens}
{fail_line}

## 解题步骤
{steps}

## 复盘
- 关键工具: {tools_used}
- 错误次数: {error_count}
- 简评: {comment}
"""

LLM_SUMMARY_PROMPT_TEMPLATE = """你是一位 CTF 解题复盘专家。请基于以下任务执行记录，生成一份简洁的解题 writeup（用于后续相似题目的检索参考）。

任务：{task}
最终状态：{status}
Flag：{flag}
步数：{step_count}
关键步骤：
{steps_brief}

要求：
1. 输出 200-400 字的解题总结，包含核心思路、关键工具、关键决策点
2. 描述应具体（如"用 nmap 扫描发现 8080 端口开放"），便于语义检索匹配
3. 不要使用 markdown 标题，输出纯文本
4. 如果任务失败，分析失败原因

Writeup：
"""


def _format_steps_for_writeup(result: ReActResult, max_steps_shown: int = 10) -> str:
    """格式化步骤列表为 writeup 中的步骤段落."""
    if not result.steps:
        return "(无步骤记录)"
    lines: list[str] = []
    shown = result.steps[:max_steps_shown]
    for i, step in enumerate(shown, 1):
        parts = [f"{i}. Thought: {step.thought}"]
        if step.action:
            parts.append(f"   Action: {step.action}({step.action_input})")
        if step.observation:
            obs = step.observation
            if len(obs) > 200:
                obs = obs[:200] + "..."
            parts.append(f"   Observation: {obs}")
        if step.is_final:
            parts.append(f"   Final Answer: {step.final_answer}")
        if step.is_error:
            parts.append(f"   [ERROR] {step.error_msg}")
        lines.append("\n".join(parts))
    if len(result.steps) > max_steps_shown:
        lines.append(f"... (省略 {len(result.steps) - max_steps_shown} 步)")
    return "\n\n".join(lines)


def _format_steps_brief(result: ReActResult, max_steps: int = 5) -> str:
    """生成简要步骤描述（用于 LLM prompt）."""
    if not result.steps:
        return "(无)"
    lines: list[str] = []
    for i, step in enumerate(result.steps[:max_steps], 1):
        action_str = f"-> {step.action}" if step.action else ""
        final_str = f"-> Final: {step.final_answer}" if step.is_final else ""
        lines.append(f"{i}. {step.thought[:80]} {action_str} {final_str}".strip())
    return "\n".join(lines)


def _extract_tools_used(result: ReActResult) -> list[str]:
    """提取使用过的工具列表（去重，按首次使用顺序）."""
    seen: list[str] = []
    for step in result.steps:
        if step.action and step.action not in seen:
            seen.append(step.action)
    return seen


def _count_errors(result: ReActResult) -> int:
    """统计错误步骤数."""
    return sum(1 for s in result.steps if s.is_error)


def _generate_comment(result: ReActResult) -> str:
    """基于结果生成简评（不调 LLM）."""
    if not result.success:
        return f"任务失败：{result.fail_reason}"
    if not result.steps:
        return "无步骤直接给出答案"
    error_count = _count_errors(result)
    if error_count == 0 and result.step_count <= 3:
        return "解题高效，无错误，步数少"
    if error_count == 0:
        return "解题顺利，无错误"
    return f"解题过程中有 {error_count} 次错误，已恢复"


def generate_writeup(
    task: str,
    result: ReActResult,
    *,
    max_steps_shown: int = 10,
) -> str:
    """用模板生成 writeup 文档（不调 LLM，节省 API）.

    Args:
        task: 任务描述
        result: ReAct 执行结果
        max_steps_shown: writeup 中最多展示的步骤数

    Returns:
        Markdown 格式的 writeup 文本
    """
    status = "成功" if result.success else "失败"
    flag = result.final_answer or "(未获取)"
    fail_line = f"- 失败原因: {result.fail_reason}" if not result.success else ""
    tools_used = ", ".join(_extract_tools_used(result)) or "(无)"
    error_count = _count_errors(result)
    comment = _generate_comment(result)

    return WRITEUP_TEMPLATE.format(
        task=task,
        status=status,
        flag=flag,
        step_count=result.step_count,
        tokens=result.total_tokens,
        fail_line=fail_line,
        steps=_format_steps_for_writeup(result, max_steps_shown),
        tools_used=tools_used,
        error_count=error_count,
        comment=comment,
    )


def generate_writeup_with_llm(
    llm: LLMClient,
    task: str,
    result: ReActResult,
    *,
    model: str | None = None,
    temperature: float = 0.3,
    max_tokens: int = 512,
) -> str:
    """用 LLM 生成更详细的 writeup（消耗 API）.

    Args:
        llm: LLM 客户端
        task: 任务描述
        result: ReAct 执行结果
        model: 模型名

    Returns:
        LLM 生成的 writeup 文本
    """
    status = "成功" if result.success else "失败"
    flag = result.final_answer or "(未获取)"
    prompt = LLM_SUMMARY_PROMPT_TEMPLATE.format(
        task=task,
        status=status,
        flag=flag,
        step_count=result.step_count,
        steps_brief=_format_steps_brief(result),
    )
    chat_result = llm.chat(
        [Message(role="user", content=prompt)],
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return chat_result.content.strip()


# ============ Analyzer ============

class Analyzer:
    """复盘分析器：任务结束后生成 writeup 并入库.

    用法：
        analyzer = Analyzer()
        writeup = analyzer.analyze(task, result)
        doc_id = analyzer.analyze_and_store(task, result, long_term, metadata={"type": "web"})
    """

    def __init__(
        self,
        llm: LLMClient | None = None,
        *,
        model: str | None = None,
        use_llm: bool = False,
        skill_library: Any = None,
        learn_skills: bool = True,
    ) -> None:
        """
        Args:
            llm: LLM 客户端（use_llm=True 时必需）
            model: 模型名
            use_llm: 是否用 LLM 生成 writeup（默认 False 用模板，省 API）
            skill_library: Sprint 15 持续学习——SkillLibrary 实例，
                提供时会在复盘同时提炼可复用 skill（writeup 的结构化升级形式）。
            learn_skills: 是否在 analyze_and_store 时同步学习 skill（默认 True）。
        """
        self.llm = llm
        self.model = model
        self.use_llm = use_llm
        self.skill_library = skill_library
        self.learn_skills = learn_skills

    def analyze(
        self,
        task: str,
        result: ReActResult,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """生成 writeup 文档与完整 metadata.

        Args:
            task: 任务描述
            result: ReAct 执行结果
            metadata: 用户提供的元数据（type/source/difficulty 等）

        Returns:
            (writeup_text, full_metadata)
        """
        # 生成 writeup 文档
        if self.use_llm:
            if self.llm is None:
                raise ValueError("use_llm=True 需要 llm 参数")
            writeup = generate_writeup_with_llm(
                self.llm, task, result, model=self.model
            )
        else:
            writeup = generate_writeup(task, result)

        # 合并 metadata：用户提供的优先，自动补充 success 字段
        full_meta: dict[str, Any] = {
            "success": result.success,
            "step_count": result.step_count,
            "tokens": result.total_tokens,
        }
        if metadata:
            full_meta.update(metadata)

        return writeup, full_meta

    def analyze_and_store(
        self,
        task: str,
        result: ReActResult,
        long_term: LongTermMemory,
        *,
        metadata: dict[str, Any] | None = None,
        doc_id: str | None = None,
    ) -> str:
        """生成 writeup 并写入长期记忆.

        Args:
            task: 任务描述
            result: ReAct 执行结果
            long_term: 长期记忆库
            metadata: 用户提供的元数据
            doc_id: 文档 ID（不传则自动生成）

        Returns:
            写入的 doc_id
        """
        writeup, full_meta = self.analyze(task, result, metadata=metadata)
        stored_id = long_term.add_writeup(
            document=writeup,
            metadata=full_meta,
            doc_id=doc_id,
        )
        # Sprint 15: 复盘同时提炼可复用 skill（writeup 的结构化升级形式）
        if self.learn_skills and self.skill_library is not None:
            self._learn_skill(task, result, metadata)
        return stored_id

    def _learn_skill(
        self,
        task: str,
        result: ReActResult,
        metadata: dict[str, Any] | None,
    ) -> None:
        """从解题结果提炼 skill 并写入 skill 库（失败不阻断主流程）。"""
        try:
            from ctf_agent.skill_learner import learn_skill

            meta = metadata or {}
            learn_skill(
                task,
                result,
                self.skill_library,
                challenge_type=str(meta.get("type", "misc")),
                difficulty=str(meta.get("difficulty", "")),
                llm=self.llm,
                model=self.model,
                use_llm=self.use_llm,
            )
        except Exception:  # noqa: BLE001
            pass

    def generate_report(
        self,
        task: str,
        result: ReActResult,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """生成完整 Markdown 报告（含时间线与改进建议）.

        依据 README 阶段四验收标准：
        "任务结束后自动生成包含时间线与改进建议的 Markdown 报告"

        Args:
            task: 任务描述
            result: ReAct 执行结果
            metadata: 题目元数据（type/source/difficulty 等）

        Returns:
            Markdown 格式的完整报告
        """
        return generate_full_report(task, result, metadata=metadata)


# ============ 完整 Markdown 报告 ============

FULL_REPORT_TEMPLATE = """# CTF 任务报告

## 概述

| 项目 | 内容 |
|------|------|
| 任务 | {task} |
| 状态 | {status} |
| Flag | `{flag}` |
| 总步数 | {step_count} |
| Token 消耗 | {tokens} |
| 耗时 | {elapsed} |
{meta_rows}

## 时间线

| 步骤 | 相对时间 | Action | 状态 |
|------|----------|--------|------|
{timeline}

## 详细步骤

{detailed_steps}

## 统计分析

{statistics}

## 改进建议

{suggestions}
"""


def _format_elapsed(seconds: float) -> str:
    """格式化耗时为可读字符串."""
    if seconds <= 0:
        return "N/A"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes}m {secs:.1f}s"


def _format_metadata_rows(metadata: dict[str, Any] | None) -> str:
    """格式化元数据为表格行."""
    if not metadata:
        return ""
    lines = []
    for k, v in metadata.items():
        lines.append(f"| {k} | {v} |")
    return "\n".join(lines)


def _format_timeline(result: ReActResult) -> str:
    """格式化时间线表格."""
    if not result.steps:
        return "| (无步骤) | | | |"
    lines = []
    base_ts = result.steps[0].timestamp if result.steps[0].timestamp else 0.0
    for step in result.steps:
        if step.timestamp and base_ts:
            rel = step.timestamp - base_ts
            rel_str = f"+{rel:.1f}s"
        else:
            rel_str = "N/A"
        action = step.action or "(Final Answer)" if step.is_final else (step.action or "(无)")
        if step.is_final:
            status = "完成"
        elif step.is_error:
            status = f"错误: {step.error_msg[:30]}"
        else:
            status = "成功"
        lines.append(f"| {step.step_no} | {rel_str} | {action} | {status} |")
    return "\n".join(lines)


def _format_detailed_steps(result: ReActResult, max_obs_len: int = 500) -> str:
    """格式化详细步骤段落."""
    if not result.steps:
        return "(无步骤记录)"
    blocks: list[str] = []
    for step in result.steps:
        lines = [f"### 步骤 {step.step_no}"]
        if step.thought:
            lines.append(f"**Thought**: {step.thought}")
        if step.action:
            lines.append(f"**Action**: `{step.action}`")
            lines.append(f"**Action Input**: `{step.action_input}`")
        if step.observation:
            obs = step.observation
            if len(obs) > max_obs_len:
                obs = obs[:max_obs_len] + f"... (截断，共 {len(step.observation)} 字符)"
            lines.append(f"**Observation**:\n```\n{obs}\n```")
        if step.is_final:
            lines.append(f"**Final Answer**: `{step.final_answer}`")
        if step.is_error:
            lines.append(f"**错误**: {step.error_msg}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def _format_statistics(result: ReActResult) -> str:
    """格式化统计分析段落."""
    lines: list[str] = []
    # 工具使用频次
    tool_counts: dict[str, int] = {}
    error_count = 0
    for step in result.steps:
        if step.action:
            tool_counts[step.action] = tool_counts.get(step.action, 0) + 1
        if step.is_error:
            error_count += 1
    if tool_counts:
        lines.append("**工具使用频次**:")
        for tool, count in sorted(tool_counts.items(), key=lambda x: -x[1]):
            lines.append(f"- `{tool}`: {count} 次")
    else:
        lines.append("**工具使用**: 无")
    lines.append(f"**错误次数**: {error_count}")
    if result.step_count > 0:
        avg_tokens = result.total_tokens / result.step_count
        lines.append(f"**平均每步 Token**: {avg_tokens:.0f}")
    lines.append(f"**总 Token**: {result.total_tokens}")
    return "\n".join(lines)


def _generate_suggestions(result: ReActResult) -> str:
    """基于执行结果生成改进建议（不调 LLM）."""
    lines: list[str] = []
    if result.success:
        lines.append("- 任务成功完成，关键路径可复用")
        if result.step_count <= 2:
            lines.append("- 解题高效，步数少，可作为相似题目的参考方案")
        if result.step_count > 10:
            lines.append("- 步数较多，可考虑优化提示词或增加工具以减少推理轮次")
    else:
        lines.append(f"- 任务失败：{result.fail_reason}")
        if "格式" in result.fail_reason:
            lines.append("- 建议优化 system prompt 的格式约束，或增加 few-shot 示例")
        if "最大步数" in result.fail_reason:
            lines.append("- 建议增加 max_steps 或拆分子任务")
    # 错误分析
    error_actions = [s.action for s in result.steps if s.is_error and s.action]
    if error_actions:
        unique_errors = list(set(error_actions))
        lines.append(f"- 出错的工具: {', '.join(unique_errors)}")
        lines.append("- 建议检查工具参数 schema 或增加错误恢复提示")
    # 重复动作检测
    action_seq = [s.action for s in result.steps if s.action]
    if len(action_seq) > len(set(action_seq)):
        lines.append("- 检测到重复工具调用，可考虑在 prompt 中提示避免重复动作")
    if not lines:
        lines.append("- 无特别建议")
    return "\n".join(lines)


def generate_full_report(
    task: str,
    result: ReActResult,
    *,
    metadata: dict[str, Any] | None = None,
) -> str:
    """生成完整 Markdown 报告（含时间线与改进建议）.

    依据 README 阶段四验收标准生成。

    Args:
        task: 任务描述
        result: ReAct 执行结果
        metadata: 题目元数据（type/source/difficulty 等）

    Returns:
        Markdown 格式的完整报告
    """
    status = "成功" if result.success else "失败"
    flag = result.final_answer or "(未获取)"
    elapsed = _format_elapsed(result.elapsed_seconds)
    meta_rows = _format_metadata_rows(metadata)
    timeline = _format_timeline(result)
    detailed_steps = _format_detailed_steps(result)
    statistics = _format_statistics(result)
    suggestions = _generate_suggestions(result)

    return FULL_REPORT_TEMPLATE.format(
        task=task,
        status=status,
        flag=flag,
        step_count=result.step_count,
        tokens=result.total_tokens,
        elapsed=elapsed,
        meta_rows=meta_rows,
        timeline=timeline,
        detailed_steps=detailed_steps,
        statistics=statistics,
        suggestions=suggestions,
    )
