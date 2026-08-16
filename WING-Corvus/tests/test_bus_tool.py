"""S12 共享发现工具端到端单测 (无外部依赖).

覆盖 (设计文档 §12.6 Step 13 门禁):
1. 双 agent 同题: A 发布发现 → B check_findings 可见 (经 default_tools 注册)
2. 游标增量读取: B 用 next_cursor 续读不重复
3. 零侵入: default_tools 未传 message_bus → 不注册共享工具 (无副作用)
4. task 隔离: 不同题不可见; kind 过滤
5. 工具 JSON 调用路径 (Tool.__call__ 解析 Action Input)
"""
from __future__ import annotations

from ctf_agent.bus.message_bus import MessageBus
from ctf_agent.tools import (
    CheckFindingsTool,
    ShareFindingTool,
    bus_tools,
    default_tools,
)


def _tools_by_name(tools):
    return {t.name: t for t in tools}


def test_bus_tools_factory() -> None:
    """工厂返回两个共享工具, name 正确."""
    bus = MessageBus()
    ts = bus_tools(bus, "agent-a")
    assert [t.name for t in ts] == ["share_finding", "check_findings"]
    assert isinstance(ts[0], ShareFindingTool) and isinstance(ts[1], CheckFindingsTool)


def test_two_agents_share_same_task() -> None:
    """门禁①: A 发布 → B 同题 check_findings 可见 (真实总线实例)."""
    bus = MessageBus()
    a_share, a_check = bus_tools(bus, "agent-a")
    b_share, b_check = bus_tools(bus, "agent-b")

    # A 发布发现
    out = a_share.execute(content="flag 格式为 athena{...}, 用 ROT13 混淆",
                          task_id="t-share", kind="hint")
    assert "已发布发现 #1" in out

    # B 读取 (同题) → 可见, 且带 A 署名
    out = b_check.execute(task_id="t-share")
    assert "flag 格式为 athena{...}" in out
    assert "agent-a" in out and "hint" in out
    assert "next_cursor=1" in out


def test_cursor_incremental_no_duplicate() -> None:
    """B 用 next_cursor 增量续读: 已读的不重复, 只返回新增."""
    bus = MessageBus()
    a_share, _ = bus_tools(bus, "agent-a")
    _, b_check = bus_tools(bus, "agent-b")

    a_share.execute(content="第一段: 偏移 0x1234", task_id="t-c")
    first = b_check.execute(task_id="t-c")
    assert "第一段" in first
    # 从输出提取 next_cursor
    import re
    cursor = int(re.search(r"next_cursor=(\d+)", first).group(1))
    assert cursor == 1

    a_share.execute(content="第二段: ret2libc", task_id="t-c")
    second = b_check.execute(task_id="t-c", cursor=cursor)
    assert "第二段" in second and "第一段" not in second


def test_no_new_findings_message() -> None:
    """无新发现 → 明确提示并返回当前游标."""
    bus = MessageBus()
    _, b_check = bus_tools(bus, "agent-b")
    out = b_check.execute(task_id="t-none")
    assert "暂无新消息" in out and "cursor=0" in out


def test_task_isolation() -> None:
    """task_id 隔离: B 只看同题, 异题发现不可见."""
    bus = MessageBus()
    a_share, _ = bus_tools(bus, "agent-a")
    _, b_check = bus_tools(bus, "agent-b")
    a_share.execute(content="t1 的秘密", task_id="t1")
    a_share.execute(content="t2 的秘密", task_id="t2")
    out = b_check.execute(task_id="t1")
    assert "t1 的秘密" in out and "t2 的秘密" not in out


def test_default_tools_registers_when_bus_provided() -> None:
    """default_tools 传 message_bus → 注册两个共享工具."""
    bus = MessageBus()
    tools = default_tools(ssh_client=None, message_bus=bus, agent_id="agent-x")
    names = _tools_by_name(tools)
    assert "share_finding" in names and "check_findings" in names


def test_default_tools_zero_intrusion_without_bus() -> None:
    """门禁③: 未传 message_bus → 不注册共享工具 (无副作用, 题解流程不变)."""
    tools = default_tools(ssh_client=None)
    names = _tools_by_name(tools)
    assert "share_finding" not in names and "check_findings" not in names


def test_tool_call_json_path() -> None:
    """Tool.__call__ JSON Action Input 路径 (ReAct 实际调用方式)."""
    bus = MessageBus()
    share, check = bus_tools(bus, "agent-a")
    r = share('{"content": "via-json", "task_id": "t-j", "kind": "fact"}')
    assert r.is_error is False and "已发布发现 #1" in r.output
    r = check('{"task_id": "t-j"}')
    assert r.is_error is False and "via-json" in r.output


def test_check_kind_filter() -> None:
    """kind 过滤: 只返回指定类型."""
    bus = MessageBus()
    share, check = bus_tools(bus, "agent-a")
    share.execute(content="fact 内容", task_id="t-k", kind="fact")
    share.execute(content="hint 内容", task_id="t-k", kind="hint")
    out = check.execute(task_id="t-k", kind="fact")
    assert "fact 内容" in out and "hint 内容" not in out
