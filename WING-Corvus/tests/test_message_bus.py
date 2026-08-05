"""S11 消息总线单测 (无外部依赖, 纯内存).

覆盖 (设计文档 §12.6 Step 12 门禁):
1. post/check 游标语义: id 单调递增、check 返回游标后新条目、新游标推进
2. 超量裁剪: 最旧丢弃、新读者从裁剪后起点读、已推进 reader 不受影响
3. 多 agent 隔离读取: 独立游标互不影响、task_id/kind 过滤
4. 线程安全: 并发 post 无丢失、size 一致
"""
from __future__ import annotations

import threading

import pytest

from ctf_agent.bus.message_bus import Finding, MessageBus, get_default_bus


# ============ post / check 游标语义 ============

def test_post_returns_monotonic_ids() -> None:
    """post 返回全局单调递增 id."""
    bus = MessageBus()
    i1 = bus.post("agent-a", "t1", "first")
    i2 = bus.post("agent-a", "t1", "second")
    assert i1 == 1 and i2 == 2
    assert bus.max_id() == 2 and bus.size() == 2


def test_check_cursor_returns_new_entries_only() -> None:
    """check(cursor) 只返回 id > cursor 的条目; 新游标 = 全局最大 id."""
    bus = MessageBus()
    bus.post("a", "t1", "m1")
    bus.post("a", "t1", "m2")
    bus.post("a", "t1", "m3")

    entries, new_cursor = bus.check(0)
    assert [e.id for e in entries] == [1, 2, 3]
    assert new_cursor == 3

    # 游标推进后再发一条 → 只返回新增
    bus.post("a", "t1", "m4")
    entries, new_cursor = bus.check(3)
    assert [e.id for e in entries] == [4]
    assert new_cursor == 4


def test_check_cursor_halfway() -> None:
    """从中间游标读: 只返回后半段."""
    bus = MessageBus()
    for i in range(5):
        bus.post("a", "t1", f"m{i}")
    entries, cursor = bus.check(2)
    assert [e.id for e in entries] == [3, 4, 5]
    assert cursor == 5


def test_post_empty_content_raises() -> None:
    """空 content 拒绝发布."""
    bus = MessageBus()
    with pytest.raises(ValueError):
        bus.post("a", "t1", "   ")


# ============ 超量裁剪 ============

def test_trim_keeps_newest() -> None:
    """超量裁剪: 保留最新 max_entries 条, 最旧丢弃."""
    bus = MessageBus(max_entries=3)
    for i in range(5):
        bus.post("a", "t1", f"m{i}")
    assert bus.size() == 3
    # 新读者从 0 读 → 只能看到保留下来的 id 3,4,5
    entries, cursor = bus.check(0)
    assert [e.id for e in entries] == [3, 4, 5]
    assert cursor == 5


def test_trim_does_not_break_advanced_reader() -> None:
    """已推进 reader 不受裁剪影响: 游标是整数 id, 新条目 id 仍 > 旧游标."""
    bus = MessageBus(max_entries=3)
    for i in range(3):
        bus.post("a", "t1", f"m{i}")
    _, cursor = bus.check(0)          # reader 读到 3
    for i in range(3, 6):             # 触发裁剪 (id 1,2,3 被裁)
        bus.post("a", "t1", f"m{i}")
    entries, new_cursor = bus.check(cursor)   # 只应看到 4,5,6
    assert [e.id for e in entries] == [4, 5, 6]
    assert new_cursor == 6


# ============ 多 agent 隔离读取 ============

def test_agent_isolated_cursors() -> None:
    """多 agent 独立游标: A 的读取/游标不受 B post 影响."""
    bus = MessageBus()
    bus.post("a", "t1", "a1")
    _, cursor_a = bus.check(0)        # A 读到 1
    bus.post("b", "t1", "b1")         # B 发布
    entries, _ = bus.check(cursor_a)  # A 再读 → 只看到 b1 (id 2)
    assert [e.id for e in entries] == [2]
    assert entries[0].agent_id == "b"


def test_task_filter_projection() -> None:
    """task_id 过滤是投影: 只返回该任务条目, 游标仍按全局推进."""
    bus = MessageBus()
    bus.post("a", "t1", "t1-m1")
    bus.post("b", "t2", "t2-m1")
    bus.post("a", "t1", "t1-m2")

    entries, cursor = bus.check(0, task_id="t1")
    assert [e.id for e in entries] == [1, 3]
    assert [e.task_id for e in entries] == ["t1", "t1"]
    assert cursor == 3               # 全局推进 (含 t2 条目)


def test_kind_filter() -> None:
    """kind 过滤只返回指定类型."""
    bus = MessageBus()
    bus.post("a", "t1", "fact-1", kind="fact")
    bus.post("a", "t1", "finding-1", kind="finding")
    entries, _ = bus.check(0, kind="fact")
    assert [e.content for e in entries] == ["fact-1"]


# ============ 线程安全 ============

def test_concurrent_post_no_loss() -> None:
    """多线程并发 post: id 无重复无丢失, 最终条数一致."""
    bus = MessageBus(max_entries=1000)
    n_threads, n_each = 4, 100

    def _worker(tid: int) -> None:
        for i in range(n_each):
            bus.post(f"agent-{tid}", f"task-{tid}", f"msg-{tid}-{i}")

    ths = [threading.Thread(target=_worker, args=(t,)) for t in range(n_threads)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()

    assert bus.size() == n_threads * n_each
    entries, _ = bus.check(0)
    ids = [e.id for e in entries]
    assert len(ids) == len(set(ids))          # 无重复
    assert ids == sorted(ids)                 # 单调
    assert bus.max_id() == n_threads * n_each


def test_get_default_bus_is_singleton() -> None:
    """S12: get_default_bus() 同进程返回同一实例 (真实链路多 agent 共享底座)."""
    assert get_default_bus() is get_default_bus()
    assert isinstance(get_default_bus(), MessageBus)


def test_finding_as_dict() -> None:
    """Finding 序列化字段齐全."""
    bus = MessageBus()
    fid = bus.post("a", "t1", "content", kind="hint")
    entries, _ = bus.check(0)
    d = entries[0].as_dict()
    assert d["id"] == fid
    assert d["agent_id"] == "a" and d["task_id"] == "t1"
    assert d["kind"] == "hint" and d["content"] == "content"
    assert d["created_at"] > 0
