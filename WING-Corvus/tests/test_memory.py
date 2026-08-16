"""Sprint 2.5 验收测试：短期记忆（ShortTermMemory）."""

from __future__ import annotations

from ctf_agent.memory import ShortTermMemory


def test_initial_memory_has_system_and_task_only() -> None:
    mem = ShortTermMemory(system_prompt="SYS", task="TASK", max_rounds=5)
    msgs = mem.get_messages()
    assert len(msgs) == 2
    assert msgs[0].role == "system"
    assert msgs[0].content == "SYS"
    assert msgs[1].role == "user"
    assert msgs[1].content == "TASK"
    assert mem.round_count == 0
    assert mem.total_message_count == 2


def test_add_round_increments_count() -> None:
    mem = ShortTermMemory(system_prompt="SYS", task="TASK", max_rounds=5)
    mem.add_round("assistant_1", "Observation: obs_1")
    assert mem.round_count == 1
    assert mem.total_message_count == 4  # system + task + assistant + observation

    msgs = mem.get_messages()
    assert msgs[2].role == "assistant"
    assert msgs[2].content == "assistant_1"
    assert msgs[3].role == "user"
    assert msgs[3].content == "Observation: obs_1"


def test_add_multiple_rounds_preserves_order() -> None:
    mem = ShortTermMemory(system_prompt="SYS", task="TASK", max_rounds=5)
    mem.add_round("a1", "o1")
    mem.add_round("a2", "o2")
    mem.add_round("a3", "o3")

    assert mem.round_count == 3
    msgs = mem.get_messages()
    # [system, task, a1, o1, a2, o2, a3, o3]
    assert len(msgs) == 8
    assert msgs[2].content == "a1"
    assert msgs[4].content == "a2"
    assert msgs[6].content == "a3"
    assert msgs[7].content == "o3"


def test_sliding_window_drops_oldest_round() -> None:
    """超过 max_rounds 时，丢弃最早的轮次."""
    mem = ShortTermMemory(system_prompt="SYS", task="TASK", max_rounds=2)
    mem.add_round("a1", "o1")
    mem.add_round("a2", "o2")
    assert mem.round_count == 2

    # 第三轮应触发裁剪，丢弃 a1/o1
    mem.add_round("a3", "o3")
    assert mem.round_count == 2  # 仍为 2（被裁剪）

    msgs = mem.get_messages()
    # [system, task, a2, o2, a3, o3]
    assert len(msgs) == 6
    assert msgs[2].content == "a2"  # a1 被丢弃
    assert msgs[4].content == "a3"


def test_sliding_window_keeps_system_and_task() -> None:
    """无论多少轮，system 和 task 始终保留."""
    mem = ShortTermMemory(system_prompt="SYS", task="TASK", max_rounds=3)
    for i in range(10):
        mem.add_round(f"a{i}", f"o{i}")

    assert mem.round_count == 3  # 裁剪到 3 轮
    msgs = mem.get_messages()
    assert msgs[0].role == "system"
    assert msgs[0].content == "SYS"
    assert msgs[1].role == "user"
    assert msgs[1].content == "TASK"
    # 保留最近 3 轮：a7/a8/a9
    assert msgs[2].content == "a7"
    assert msgs[-1].content == "o9"


def test_clear_resets_rounds_but_keeps_system_task() -> None:
    mem = ShortTermMemory(system_prompt="SYS", task="TASK", max_rounds=5)
    mem.add_round("a1", "o1")
    mem.add_round("a2", "o2")

    mem.clear()

    assert mem.round_count == 0
    assert mem.total_message_count == 2
    msgs = mem.get_messages()
    assert msgs[0].content == "SYS"
    assert msgs[1].content == "TASK"


def test_max_rounds_one_keeps_only_latest() -> None:
    mem = ShortTermMemory(system_prompt="SYS", task="TASK", max_rounds=1)
    mem.add_round("a1", "o1")
    mem.add_round("a2", "o2")

    assert mem.round_count == 1
    msgs = mem.get_messages()
    # [system, task, a2, o2]
    assert len(msgs) == 4
    assert msgs[2].content == "a2"
    assert msgs[3].content == "o2"


def test_default_max_rounds_is_10() -> None:
    """README §3.3.1 规定短期记忆保留最近 10 轮."""
    mem = ShortTermMemory(system_prompt="SYS", task="TASK")
    assert mem.max_rounds == 10


def test_messages_are_independent_copy() -> None:
    """get_messages 返回的列表修改不应影响内部状态."""
    mem = ShortTermMemory(system_prompt="SYS", task="TASK", max_rounds=5)
    mem.add_round("a1", "o1")

    msgs1 = mem.get_messages()
    msgs1.append("injected")  # type: ignore[arg-type]
    msgs1.clear()

    msgs2 = mem.get_messages()
    assert len(msgs2) == 4  # 原始数据未受影响
