"""共享发现工具 (WING-Goose Item 5 M4 / S12, S13 问答增强).

基于消息总线的两个 ReAct 工具:
- share_finding: 发布一条解题发现/问题/回答 (agent 绑定, 自动带 agent_id 与 task_id)
- check_findings: 读取游标后的新发现 (多 agent 同题共享)

S13 增强:
- kind 扩展: fact/hint/finding/question/answer
  - question: 向同题兄弟 agent 提问 (如"flag 格式是什么?")
  - answer: 回答兄弟的问题 (reply_to 引用提问 id)
- reply_to: 回答时引用提问的 id, 形成提问-回答闭环
- 总线后端鸭子类型: 支持进程内 MessageBus 与跨进程 FileBus
  (后者让 swarm 多进程 agent 的共享也互相可见)

零侵入: 仅当 default_tools 收到 message_bus 实例时才注册;
未配置总线的题目工具列表完全不变 (设计文档 §12.6 Step 13 回滚语义)。
"""
from __future__ import annotations

from typing import Any

from ctf_agent.tools.base import Tool


def _post(bus: Any, agent_id: str, task_id: str, content: str,
          kind: str, reply_to: int) -> int:
    """适配进程内 MessageBus 与跨进程 FileBus 的发布接口."""
    if hasattr(bus, "post_finding"):  # FileBus (跨进程)
        return bus.post_finding(agent_id, task_id, content, kind=kind,
                                reply_to=reply_to)
    return bus.post(agent_id, task_id, content, kind=kind, reply_to=reply_to)


def _check(bus: Any, cursor: int, task_id: str | None, kind: str | None):
    """适配进程内 MessageBus 与跨进程 FileBus 的读取接口."""
    if hasattr(bus, "check_findings"):  # FileBus (跨进程)
        return bus.check_findings(cursor, task_id=task_id, kind=kind)
    return bus.check(cursor, task_id=task_id, kind=kind)


class ShareFindingTool(Tool):
    """发布解题发现/问题/回答到共享总线, 供同题其他 agent 参考."""

    name = "share_finding"
    description = (
        "将你在解题过程中发现的可靠线索/结论 (如 flag 格式、关键偏移、"
        "加密方式、可利用漏洞点、某命令的关键输出等) 发布到共享总线, "
        "同题的其他 agent 可通过 check_findings 看到。\n"
        "适合多 agent 协作解题时共享已验证的有效信息; 不确定/猜测内容"
        "建议先在本地验证再发布。\n"
        "kind 可选: fact(已验证事实)/hint(线索)/finding(发现)/"
        "question(向兄弟 agent 提问, 如 flag 格式或某步思路)/"
        "answer(回答兄弟的提问, 需用 reply_to 引用提问 id, "
        "提问 id 从 check_findings 的返回中获取)。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "content": {
                "type": "string",
                "description": "要共享的内容 (一句话或简短段落)",
            },
            "task_id": {
                "type": "string",
                "description": "所属题目标识 (必须与当前题一致, 其他 agent 同题可见)",
            },
            "kind": {
                "type": "string",
                "enum": ["fact", "hint", "finding", "question", "answer"],
                "description": "类型: fact/hint/finding/question/answer (默认 finding)",
            },
            "reply_to": {
                "type": "integer",
                "description": "回答时引用的提问 id (仅 kind=answer 时填写, 来自 check_findings)",
            },
        },
        "required": ["content", "task_id"],
    }

    def __init__(self, bus: Any, agent_id: str) -> None:
        self.bus = bus
        self.agent_id = agent_id

    def execute(self, content: str, task_id: str, kind: str = "finding",
                reply_to: int = 0, **_: Any) -> str:
        fid = _post(self.bus, self.agent_id, task_id, content, kind,
                    int(reply_to or 0))
        tag = "问题" if kind == "question" else "回答" if kind == "answer" else "发现"
        extra = f" (回答 #{reply_to})" if kind == "answer" and reply_to else ""
        return f"已发布{tag} #{fid}{extra} (task={task_id}, kind={kind})"


class CheckFindingsTool(Tool):
    """读取共享总线上同题 agent 发布的发现 (游标增量)."""

    name = "check_findings"
    description = (
        "读取共享总线上发布的解题发现/提问/回答 (默认只看当前题)。"
        "首次调用 cursor=0 或省略, 之后请用上次返回的 next_cursor 继续增量读取, 避免重复。\n"
        "用于多 agent 协作: 查看同题其他 agent 已发布的可靠线索/结论,"
        "避免重复劳动, 也能发现自己遗漏的思路。\n"
        "kind 可选 question 时只查看兄弟的提问 (想帮助兄弟或需要确认信息时);"
        "kind=answer 的条目会标注 [答#提问id], 可与对应提问对应上。\n"
        "重要: 如果发现来自兄弟 agent 且你尚未回答的提问, 返回结果会附带 [MUST] "
        "强制回答指令 — 你必须用 share_finding(kind=answer, reply_to=提问id) 回复, "
        "不清楚时回答\"不知道\", 不得忽略。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "cursor": {
                "type": "integer",
                "description": "已读到的位置 (默认 0 = 从头读; 增量用上次的 next_cursor)",
            },
            "task_id": {
                "type": "string",
                "description": "题目标识 (默认当前题; 省略=只看本 agent 所在题)",
            },
            "kind": {
                "type": "string",
                "enum": ["fact", "hint", "finding", "question", "answer"],
                "description": "只读该类型 (默认全部)",
            },
        },
        "required": [],
    }

    def __init__(self, bus: Any, agent_id: str) -> None:
        self.bus = bus
        self.agent_id = agent_id

    def execute(self, cursor: int | None = None, task_id: str | None = None,
                kind: str | None = None, **_: Any) -> str:
        cursor = int(cursor or 0)
        entries, new_cursor = _check(self.bus, cursor, task_id=task_id,
                                     kind=kind)
        # 强制回答检查: 扫描全部条目, 找出来自其他 agent 且本 agent 尚未回答的提问
        # 防止兄弟 agent 因等待答复而卡死 (如某解题器死循环)
        all_entries, _ = _check(self.bus, 0, task_id=task_id, kind=None)
        answered_ids = {e.reply_to for e in all_entries
                        if e.kind == "answer" and e.agent_id == self.agent_id}
        pending_questions = [e for e in all_entries
                             if e.kind == "question"
                             and e.agent_id != self.agent_id
                             and e.id not in answered_ids]

        if not entries and not pending_questions:
            return f"暂无新消息 (cursor={new_cursor})"

        lines: list[str] = []
        if entries:
            lines.append(
                f"--- 共享消息 (共 {len(entries)} 条, next_cursor={new_cursor}) ---")
            for e in entries:
                tag = e.kind
                if e.kind == "question":
                    tag = "提问"
                elif e.kind == "answer":
                    tag = f"回答(答#{e.reply_to})" if e.reply_to else "回答"
                lines.append(
                    f"#{e.id} [{tag}] agent={e.agent_id}: {e.content}")
        if pending_questions:
            lines.append("")
            lines.append("[MUST] 你收到了来自兄弟解题器的提问, 必须立即回答:")
            for q in pending_questions:
                lines.append(
                    f"  - 提问 #{q.id} (agent={q.agent_id}): {q.content}")
            lines.append(
                "请使用 share_finding 工具 (kind=answer, reply_to=提问id) "
                "回答上述每一个提问。")
            lines.append(
                "如果你不清楚答案, 必须回答\"不知道\"或\"暂无相关信息\", "
                "不得忽略提问。")
            lines.append(
                "这是强制要求: 收到提问后必须回复, 否则提问的兄弟 agent "
                "会一直等待你的答复而卡死。")
        return "\n".join(lines)


def bus_tools(bus: Any, agent_id: str) -> list[Tool]:
    """创建共享发现工具集 (S12)."""
    return [
        ShareFindingTool(bus, agent_id),
        CheckFindingsTool(bus, agent_id),
    ]


__all__ = ["CheckFindingsTool", "ShareFindingTool", "bus_tools"]
