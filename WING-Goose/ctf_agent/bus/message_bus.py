"""消息总线 (WING-Goose Item 5 M4 / S11).

纯宿主侧、无外部依赖的 append-only findings 总线，供多 agent 解题发现共享
（S12 的 check_findings / share_finding 工具基于此模块）：

- append-only: 条目只追加, 不修改/单条删除 (仅超量整体裁剪例外)
- cursor: 每个 reader 独立持游标 (整数, 已读到的最大 id), 单调递增;
  check(cursor) 返回 id > cursor 的条目 + 新游标 (全局最大 id)
- task_id 过滤: check 可选只投影指定任务的条目, 但游标仍按全局推进
  (过滤是投影而非独立游标 → 语义简单, 跨任务共享同样正确)
- 裁剪: 超 max_entries 时丢弃最旧条目; 已推进 reader 的游标是整数 id,
  不受裁剪影响 (新条目 id 仍单调递增 > 旧游标)

线程安全: threading.Lock 保护, 支持多 agent 并行 post/check。
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """一条解题发现 (fact/hint/finding/question/answer 等, 由 kind 区分)."""

    id: int
    agent_id: str
    task_id: str
    content: str
    kind: str = "finding"
    reply_to: int = 0  # 回答时引用的提问 id (0 = 独立发现, 非回答)
    created_at: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "kind": self.kind,
            "content": self.content,
            "reply_to": self.reply_to,
            "created_at": self.created_at,
        }


class MessageBus:
    """线程安全的 append-only 消息总线.

    Args:
        max_entries: 保留的最大条目数, 超出裁剪最旧 (默认 200).
    """

    def __init__(self, max_entries: int = 200) -> None:
        self._entries: list[Finding] = []
        self._next_id = 1
        self._max_entries = max(1, int(max_entries))
        self._lock = threading.Lock()

    # ---------- 写入 ----------

    def post(self, agent_id: str, task_id: str, content: str,
             kind: str = "finding", reply_to: int = 0) -> int:
        """发布一条发现, 返回其 id (全局单调递增).

        Args:
            agent_id: 发布者标识
            task_id: 所属题目
            content: 内容
            kind: 类型 (fact/hint/finding/question/answer 等)
            reply_to: 回答时引用的提问 id (0 = 独立发现, 非回答)
        """
        if not content or not content.strip():
            raise ValueError("content 不能为空")
        with self._lock:
            f = Finding(id=self._next_id, agent_id=agent_id,
                        task_id=task_id, content=content.strip(),
                        kind=kind, reply_to=int(reply_to or 0))
            self._next_id += 1
            self._entries.append(f)
            self._trim_locked()
            return f.id

    def _trim_locked(self) -> None:
        """超量裁剪最旧条目 (锁内调用)."""
        excess = len(self._entries) - self._max_entries
        if excess > 0:
            del self._entries[:excess]

    # ---------- 读取 ----------

    def check(self, cursor: int = 0, task_id: str | None = None,
              kind: str | None = None) -> tuple[list[Finding], int]:
        """读取游标之后的新条目.

        Args:
            cursor: 调用方已读到的最大 id (0 = 从头读).
            task_id: 只返回该任务的条目 (None = 全部).
            kind: 只返回该类型的条目 (None = 全部).

        Returns:
            (新条目列表, 新游标). 新游标 = 当前全局最大 id (过滤不影响推进).
            若裁剪后游标之前的条目已消失, 仍从 id > cursor 读取, 语义不变.
        """
        with self._lock:
            max_id = self._next_id - 1
            out = [f for f in self._entries
                   if f.id > cursor
                   and (task_id is None or f.task_id == task_id)
                   and (kind is None or f.kind == kind)]
            return list(out), max_id

    def size(self) -> int:
        with self._lock:
            return len(self._entries)

    def max_id(self) -> int:
        with self._lock:
            return self._next_id - 1

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._next_id = 1


# ---------- 进程内默认总线单例 (S12 真实链路接入) ----------

_DEFAULT_BUS: MessageBus | None = None
_DEFAULT_BUS_LOCK = threading.Lock()


def get_default_bus() -> MessageBus:
    """进程内共享的默认总线单例.

    真实解题入口 (solve.py / web / main) 直接用它接入共享发现工具:
    同进程的多 agent (多线程) 天然共享同一条总线。
    跨进程部署 (多进程 agent) 时由部署方显式构造共享 MessageBus 注入,
    本函数仅保证单进程内语义一致。
    """
    global _DEFAULT_BUS
    with _DEFAULT_BUS_LOCK:
        if _DEFAULT_BUS is None:
            _DEFAULT_BUS = MessageBus()
        return _DEFAULT_BUS


__all__ = ["Finding", "MessageBus", "get_default_bus"]
