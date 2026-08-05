"""中期记忆（L4 记忆层）.

依据 README §3.3.1，中期记忆存储当前任务的关键事实（IP、开放端口、服务版本、
发现的漏洞函数名等），结构化存储于 SQLite 的 task_facts 表。
每次推理前强制检索并注入提示词顶部（"关键事实防丢机制"）。

设计：
- 使用 Python 标准库 sqlite3，无需额外依赖
- 默认内存数据库（:memory:），生产环境用文件路径
- task_facts 表按 (task_id, key) 唯一约束，重复记录覆盖更新
- 提供 format_facts() 输出可注入 prompt 的文本
"""

from __future__ import annotations

import sqlite3
import time
from typing import Iterable


_SCHEMA = """
CREATE TABLE IF NOT EXISTS task_facts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at REAL NOT NULL,
    UNIQUE(task_id, key)
);
CREATE INDEX IF NOT EXISTS idx_task_facts_task_id ON task_facts(task_id);
"""


class MidTermMemory:
    """中期记忆：基于 SQLite 的关键事实存储.

    用法：
        mem = MidTermMemory()  # 内存库
        mem.add_fact("task-1", "target_ip", "10.0.0.5")
        mem.add_fact("task-1", "open_ports", "22,80,443")
        facts_text = mem.format_facts("task-1")  # 注入 prompt
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        # check_same_thread=False 允许跨线程访问（ReAct 引擎可能在异步上下文使用）
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def add_fact(self, task_id: str, key: str, value: str) -> None:
        """记录一条关键事实（同 task_id+key 覆盖更新）."""
        self._conn.execute(
            "INSERT OR REPLACE INTO task_facts (task_id, key, value, created_at) "
            "VALUES (?, ?, ?, ?)",
            (task_id, key, value, time.time()),
        )
        self._conn.commit()

    def add_facts(self, task_id: str, facts: dict[str, str]) -> None:
        """批量记录关键事实."""
        now = time.time()
        rows = [(task_id, k, v, now) for k, v in facts.items()]
        self._conn.executemany(
            "INSERT OR REPLACE INTO task_facts (task_id, key, value, created_at) "
            "VALUES (?, ?, ?, ?)",
            rows,
        )
        self._conn.commit()

    def get_facts(self, task_id: str) -> list[tuple[str, str]]:
        """获取指定任务的全部关键事实（按写入顺序）."""
        cur = self._conn.execute(
            "SELECT key, value FROM task_facts WHERE task_id = ? ORDER BY id",
            (task_id,),
        )
        return cur.fetchall()

    def get_facts_dict(self, task_id: str) -> dict[str, str]:
        """以字典形式返回关键事实."""
        return dict(self.get_facts(task_id))

    def format_facts(self, task_id: str) -> str:
        """格式化为可注入 prompt 的文本.

        无事实时返回空字符串（调用方据此决定是否注入）。
        """
        facts = self.get_facts(task_id)
        if not facts:
            return ""
        lines = ["# 已知关键事实（防丢，基于历史观察）"]
        for key, value in facts:
            lines.append(f"- {key}: {value}")
        return "\n".join(lines)

    def fact_count(self, task_id: str) -> int:
        """返回指定任务的事实条数."""
        cur = self._conn.execute(
            "SELECT COUNT(*) FROM task_facts WHERE task_id = ?",
            (task_id,),
        )
        return int(cur.fetchone()[0])

    def clear(self, task_id: str) -> None:
        """清空指定任务的全部事实."""
        self._conn.execute(
            "DELETE FROM task_facts WHERE task_id = ?", (task_id,)
        )
        self._conn.commit()

    def clear_all(self) -> None:
        """清空所有任务的事实（测试用）."""
        self._conn.execute("DELETE FROM task_facts")
        self._conn.commit()

    def list_task_ids(self) -> list[str]:
        """列出所有有事实记录的 task_id（去重）."""
        cur = self._conn.execute(
            "SELECT DISTINCT task_id FROM task_facts ORDER BY task_id"
        )
        return [row[0] for row in cur.fetchall()]

    def close(self) -> None:
        """关闭数据库连接."""
        self._conn.close()

    # 上下文管理器支持
    def __enter__(self) -> "MidTermMemory":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
