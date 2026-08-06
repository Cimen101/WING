"""Sprint 26: 全局 stop 信号 (独立模块, 避免循环导入).

solve.py 和 react.py 都需要访问 stop 标志, 但 solve.py 导入 react.py
(ReActEngine), react.py 不能反向导入 solve.py (循环导入).
将 stop 标志放在独立模块中, 双方都能安全导入.
"""
from __future__ import annotations

import threading

# 全局 stop 标志 (线程安全)
_stop_event = threading.Event()


def request_stop() -> None:
    """设置 stop 标志 (由 solve.py 的 stdin listener 调用)."""
    _stop_event.set()


def is_stop_requested() -> bool:
    """检查 stop 标志 (由 react.py 每步调用)."""
    return _stop_event.is_set()


def reset() -> None:
    """重置 stop 标志 (每次新任务开始时调用)."""
    _stop_event.clear()
