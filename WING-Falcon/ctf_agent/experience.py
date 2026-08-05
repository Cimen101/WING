"""经验闭环：把成功解题沉淀为 writeup 写入长期记忆（Sprint 16 架构层）.

背景与动机
----------
此前持续学习只写入 ``SkillLibrary``（结构化技能），而 RAG 检索读取的是
``LongTermMemory``（向量库 writeups）。二者互相独立，导致 **RAG 只能命中最初的
78 条种子 writeup，永远不会因 agent 自身的解题经验而增长**——学习闭环是断的。

本模块补上缺失的一环：解题成功后，将该次经验去标识化后写入 LTM，使下一次同类
题在任务开局的 RAG 检索里能命中"自己解过的题"，实现知识库自增长。

安全（与靶场 flag 安全模型一致）
--------------------------------
写入 LTM 的 writeup **绝不包含真实 flag**：``final_answer`` 与一切
``xxx{...}`` / 十六进制长串等疑似 flag 会被替换为 ``<REDACTED_FLAG>``。
因为 LTM 内容会进入后续 LLM 上下文（RAG 注入），存明文 flag 等于把 flag 从
"正常途径"泄漏成"非正常途径"。

去重
----
doc_id 由 ``任务 + 工具链`` 的哈希派生，同类经验只写一次（已存在则跳过），
避免向量库因反复解同题而膨胀。
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from ctf_agent.agent import ReActResult

# 疑似 flag 特征：xxx{...} 包裹格式，以及常见 flag 词
_FLAG_BRACE = re.compile(r"[A-Za-z0-9_]{2,20}\{[^}]{1,200}\}")
_LONG_HEX = re.compile(r"\b[0-9a-fA-F]{32,}\b")
# Sprint 28: 绝对路径和内存地址也需脱敏 (与 skill_learner.py 保持一致)
_TMP_PATH = re.compile(r'/tmp/nss_arena/[a-zA-Z0-9_]+(/[^\s]*)?')
_HEX_ADDR = re.compile(r'0x[0-9a-fA-F]{4,}')
_OBJDUMP_ADDR = re.compile(r'\b[0-9a-f]{8,16}\b\s*<')


def redact_flags(text: str, final_answer: str | None = None) -> str:
    """去标识化：移除疑似 flag、绝对路径、内存地址，避免污染 RAG 上下文.

    Sprint 28: 新增路径和地址脱敏 — 与 skill_learner._sanitize_text 保持一致.
    """
    if not text:
        return text
    out = _FLAG_BRACE.sub("<REDACTED_FLAG>", text)
    out = _LONG_HEX.sub("<REDACTED_HEX>", out)
    # Sprint 28: 路径和地址脱敏
    out = _TMP_PATH.sub("{work_dir}\\1", out)
    out = _HEX_ADDR.sub("{address}", out)
    out = _OBJDUMP_ADDR.sub("{func_addr} <", out)
    if final_answer:
        fa = final_answer.strip()
        if fa:
            out = out.replace(fa, "<REDACTED_FLAG>")
    return out


def _tool_chain(result: ReActResult) -> list[str]:
    seen: list[str] = []
    for s in result.steps:
        if s.action and s.action not in seen:
            seen.append(s.action)
    return seen


def _key_steps(result: ReActResult, final_answer: str | None, limit: int = 6) -> list[str]:
    steps: list[str] = []
    for s in result.steps:
        if s.observation and not s.is_error and s.action:
            snippet = redact_flags(
                s.observation.strip().replace("\n", " "), final_answer
            )
            if len(snippet) > 200:
                snippet = snippet[:200] + "..."
            steps.append(f"{s.action}: {snippet}")
        if len(steps) >= limit:
            break
    return steps


def build_writeup_document(
    task: str,
    result: ReActResult,
    challenge_type: str,
) -> str:
    """把一次成功解题组织成 writeup 文本（已去标识化）."""
    tools = _tool_chain(result)
    steps = _key_steps(result, result.final_answer)
    lines = [
        f"[类型] {challenge_type}",
        f"[题目] {redact_flags(task[:400], result.final_answer)}",
    ]
    if tools:
        lines.append(f"[解题工具链] {' -> '.join(tools)}")
    if steps:
        lines.append("[关键步骤]")
        lines.extend(f"- {s}" for s in steps)
    lines.append(
        f"[结论] 通过上述 {len(tools)} 类工具协作在 {result.step_count} 步内成功解出"
        f"（flag 已隐去）。同类题可优先复用该工具链与思路。"
    )
    return "\n".join(lines)


def _doc_id(task: str, tools: list[str]) -> str:
    h = hashlib.sha1((task + "|" + ",".join(tools)).encode("utf-8")).hexdigest()
    return f"exp-{h[:12]}"


def ingest_solution(
    task: str,
    result: ReActResult,
    *,
    long_term: Any | None = None,
    challenge_type: str = "misc",
    source: str = "agent-experience",
    difficulty: int | None = None,
    min_steps: int = 2,
    chroma_path: str = "./data/chroma",
) -> str | None:
    """把一次成功解题写入长期记忆（供 RAG 自增长）。

    Args:
        task: 题目描述/任务文本。
        result: ReAct 解题结果。
        long_term: 可注入的 LongTermMemory（测试用）；缺省时按需惰性创建。
        challenge_type: 题目方向（web/pwn/reverse/crypto/misc）。
        source: 元数据来源标记，默认 agent-experience（区别于种子）。
        difficulty: 难度（可选）。
        min_steps: 步数下限，过短的解题不沉淀（噪声）。
        chroma_path: LTM 持久化路径（仅在未注入 long_term 时使用）。

    Returns:
        写入的 doc_id；若不满足条件或写入失败则返回 None（不影响主流程）。
    """
    if not result.success:
        return None
    if result.step_count < min_steps:
        return None
    tools = _tool_chain(result)
    if not tools:
        return None

    ltm = long_term
    if ltm is None:
        try:
            from ctf_agent.memory.long_term import LongTermMemory
            ltm = LongTermMemory(chroma_path=chroma_path)
        except Exception:  # noqa: BLE001 - 无 chromadb/依赖缺失时静默降级
            return None

    doc_id = _doc_id(task, tools)
    # 去重：同类经验已存在则不重复写入
    try:
        if ltm.get(doc_id) is not None:
            return doc_id
    except Exception:  # noqa: BLE001
        pass

    document = build_writeup_document(task, result, challenge_type)
    metadata: dict[str, Any] = {
        "type": challenge_type,
        "source": source,
    }
    if difficulty is not None:
        metadata["difficulty"] = int(difficulty)
    try:
        return ltm.add_writeup(document, metadata=metadata, doc_id=doc_id)
    except Exception:  # noqa: BLE001 - 写入失败不影响解题主流程
        return None


__all__ = ["ingest_solution", "build_writeup_document", "redact_flags"]
