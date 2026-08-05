"""In-process EventBus (渐进式事件化第一步).

设计原则:
1. 极简: 只有 emit/subscribe/clear 三个方法
2. 线程安全: Swarm 多线程场景下可用
3. 可选: ReActEngine 的 event_bus 参数默认 None, 不影响现有行为
4. 不替换 callback: 与现有 on_step/on_coordinator 并行, 逐步迁移

事件类型 (推荐命名, 不强制):
- step.started: {"step_no": int, "action": str, "challenge_id": str}
- step.completed: {"step_no": int, "action": str, "observation": str, "elapsed": float}
- flag.found: {"flag": str, "step_no": int, "challenge_id": str}
- coordinator.guidance: {"should_intervene": bool, "reason": str, "step_no": int}
- skill.injected: {"source": "static"|"mid_solve"|"coordinator", "skill_ids": list[str]}
- bus.message: {"agent_id": str, "level": str, "content": str}
- engine.started: {"challenge_id": str, "challenge_type": str, "max_steps": int}
- engine.finished: {"challenge_id": str, "success": bool, "steps": int, "elapsed": float}
"""
from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any, Callable


class EventBus:
    """In-process 事件总线 (线程安全)."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callable[[dict], None]]] = defaultdict(list)
        self._lock = threading.Lock()
        self._event_count = 0

    def subscribe(self, event_type: str, handler: Callable[[dict], None]) -> None:
        """订阅事件类型. handler 接收单个 dict 参数."""
        with self._lock:
            self._subscribers[event_type].append(handler)

    def emit(self, event_type: str, payload: dict[str, Any] | None = None) -> None:
        """发射事件. 所有订阅者的 handler 被同步调用.

        异常不会传播给调用方 (永不阻塞 emitter).
        """
        self._event_count += 1
        payload = payload or {}
        with self._lock:
            handlers = list(self._subscribers.get(event_type, []))
        for handler in handlers:
            try:
                handler(payload)
            except Exception:  # noqa: BLE001 - 永不阻塞 emitter
                pass

    def unsubscribe(self, event_type: str, handler: Callable[[dict], None]) -> None:
        """取消订阅."""
        with self._lock:
            if event_type in self._subscribers:
                try:
                    self._subscribers[event_type].remove(handler)
                except ValueError:
                    pass

    def clear(self) -> None:
        """清空所有订阅."""
        with self._lock:
            self._subscribers.clear()

    @property
    def event_count(self) -> int:
        """累计发射的事件数 (供调试/监控)."""
        return self._event_count


# 全局默认实例 (可选, 测试/脚本可直接用)
_default_bus: EventBus | None = None


def get_default_bus() -> EventBus:
    """获取全局默认 EventBus 实例 (懒初始化)."""
    global _default_bus
    if _default_bus is None:
        _default_bus = EventBus()
    return _default_bus
