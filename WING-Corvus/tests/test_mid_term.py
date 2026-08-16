"""Sprint 3.1 验收测试：中期记忆 + remember_fact 工具 + ReActEngine 注入.

覆盖：
1. MidTermMemory CRUD：add_fact / get_facts / format_facts / clear / 重复覆盖
2. RememberFactTool：execute 写入 / __call__ JSON 输入 / schema
3. ReActEngine 集成：关键事实跨轮注入 system prompt（防丢）
4. 无 mid_term 时与原行为一致（向后兼容）
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from ctf_agent.agent import ReActEngine
from ctf_agent.llm import ChatResult, ChatUsage, LLMClient, Message
from ctf_agent.memory import MidTermMemory, ShortTermMemory
from ctf_agent.tools.base import Tool
from ctf_agent.tools.memory_tools import RememberFactTool, memory_tools


# ============ MidTermMemory CRUD ============

def test_mid_term_add_and_get_single_fact() -> None:
    mem = MidTermMemory()
    mem.add_fact("task-1", "target_ip", "192.168.1.1")
    facts = mem.get_facts("task-1")
    assert facts == [("target_ip", "192.168.1.1")]


def test_mid_term_add_facts_batch() -> None:
    mem = MidTermMemory()
    mem.add_facts("task-1", {"target_ip": "10.0.0.1", "open_ports": "22,80"})
    d = mem.get_facts_dict("task-1")
    assert d == {"target_ip": "10.0.0.1", "open_ports": "22,80"}


def test_mid_term_duplicate_key_overwrites() -> None:
    """同 task_id+key 重复写入应覆盖更新（不新增行）."""
    mem = MidTermMemory()
    mem.add_fact("task-1", "target_ip", "192.168.1.1")
    mem.add_fact("task-1", "target_ip", "10.0.0.1")  # 覆盖
    assert mem.fact_count("task-1") == 1
    assert mem.get_facts_dict("task-1")["target_ip"] == "10.0.0.1"


def test_mid_term_isolates_tasks() -> None:
    """不同 task_id 的事实互相隔离."""
    mem = MidTermMemory()
    mem.add_fact("task-1", "k", "v1")
    mem.add_fact("task-2", "k", "v2")
    assert mem.get_facts_dict("task-1") == {"k": "v1"}
    assert mem.get_facts_dict("task-2") == {"k": "v2"}


def test_mid_term_format_facts_empty() -> None:
    mem = MidTermMemory()
    assert mem.format_facts("nonexistent") == ""


def test_mid_term_format_facts_single() -> None:
    mem = MidTermMemory()
    mem.add_fact("task-1", "target_ip", "192.168.1.1")
    text = mem.format_facts("task-1")
    assert "已知关键事实" in text
    assert "target_ip: 192.168.1.1" in text


def test_mid_term_format_facts_multiple_preserves_insertion_order() -> None:
    mem = MidTermMemory()
    mem.add_fact("task-1", "open_ports", "22,80")
    mem.add_fact("task-1", "target_ip", "192.168.1.1")
    text = mem.format_facts("task-1")
    # 按 id 顺序（写入顺序）
    lines = text.split("\n")
    assert lines[1] == "- open_ports: 22,80"
    assert lines[2] == "- target_ip: 192.168.1.1"


def test_mid_term_clear_specific_task() -> None:
    mem = MidTermMemory()
    mem.add_fact("task-1", "k", "v")
    mem.add_fact("task-2", "k", "v")
    mem.clear("task-1")
    assert mem.fact_count("task-1") == 0
    assert mem.fact_count("task-2") == 1


def test_mid_term_clear_all() -> None:
    mem = MidTermMemory()
    mem.add_fact("task-1", "k", "v")
    mem.add_fact("task-2", "k", "v")
    mem.clear_all()
    assert mem.fact_count("task-1") == 0
    assert mem.fact_count("task-2") == 0


def test_mid_term_list_task_ids() -> None:
    mem = MidTermMemory()
    mem.add_fact("task-2", "k", "v")
    mem.add_fact("task-1", "k", "v")
    ids = mem.list_task_ids()
    assert sorted(ids) == ["task-1", "task-2"]


def test_mid_term_context_manager_closes_connection() -> None:
    with MidTermMemory() as mem:
        mem.add_fact("task-1", "k", "v")
        assert mem.fact_count("task-1") == 1
    # 退出后连接已关闭
    with pytest.raises(Exception):
        mem.fact_count("task-1")


def test_mid_term_persists_to_file(tmp_path) -> None:
    """文件数据库应能跨实例持久化."""
    db_file = str(tmp_path / "test.db")
    with MidTermMemory(db_path=db_file) as m1:
        m1.add_fact("task-1", "target_ip", "10.0.0.1")
    # 重新打开应能读到
    with MidTermMemory(db_path=db_file) as m2:
        assert m2.get_facts_dict("task-1") == {"target_ip": "10.0.0.1"}


# ============ RememberFactTool ============

def test_remember_fact_tool_execute_writes_to_mid_term() -> None:
    mem = MidTermMemory()
    tool = RememberFactTool(mid_term=mem, task_id="task-1")
    result = tool.execute(key="target_ip", value="192.168.1.1")
    assert "已记录" in result
    assert "target_ip" in result
    assert mem.get_facts_dict("task-1") == {"target_ip": "192.168.1.1"}


def test_remember_fact_tool_call_with_json_input() -> None:
    """通过 __call__ 传入 JSON 字符串."""
    mem = MidTermMemory()
    tool = RememberFactTool(mid_term=mem, task_id="task-1")
    action_input = json.dumps({"key": "open_ports", "value": "22,80"})
    result = tool(action_input)
    assert result.is_error is False
    assert "open_ports" in result.output
    assert mem.get_facts_dict("task-1") == {"open_ports": "22,80"}


def test_remember_fact_tool_missing_required_field_returns_error() -> None:
    mem = MidTermMemory()
    tool = RememberFactTool(mid_term=mem, task_id="task-1")
    # 缺 value
    result = tool(json.dumps({"key": "k"}))
    assert result.is_error is True
    assert "ERROR" in result.output
    assert mem.fact_count("task-1") == 0


def test_remember_fact_tool_schema() -> None:
    mem = MidTermMemory()
    tool = RememberFactTool(mid_term=mem, task_id="task-1")
    s = tool.schema()
    assert s["name"] == "remember_fact"
    assert "key" in s["parameters"]["properties"]
    assert "value" in s["parameters"]["properties"]
    assert s["parameters"]["required"] == ["key", "value"]


def test_memory_tools_factory_returns_remember_fact() -> None:
    mem = MidTermMemory()
    tools = memory_tools(mem, "task-1")
    assert len(tools) == 1
    assert tools[0].name == "remember_fact"


# ============ ShortTermMemory.update_system_prompt ============

def test_short_term_update_system_prompt_reflects_in_messages() -> None:
    mem = ShortTermMemory(system_prompt="original", task="t")
    mem.update_system_prompt("new prompt with facts")
    msgs = mem.get_messages()
    assert msgs[0].role == "system"
    assert msgs[0].content == "new prompt with facts"


# ============ ReActEngine 集成测试 ============

class ScriptedLLMClient(LLMClient):
    """按预设脚本顺序返回 LLM 响应的 mock 客户端."""

    def __init__(self, scripts: list[str]):
        self.settings = None  # type: ignore[assignment]
        self._scripts = list(scripts)
        self._call_idx = 0
        self.calls: list[list[Message]] = []

    def chat(self, messages, model=None, temperature=0.0, max_tokens=None, timeout=None, extra=None) -> ChatResult:  # type: ignore[override]
        self.calls.append(list(messages))  # type: ignore[arg-type]
        if self._call_idx >= len(self._scripts):
            raise RuntimeError(
                f"ScriptedLLMClient 脚本耗尽：已调用 {self._call_idx + 1} 次"
            )
        content = self._scripts[self._call_idx]
        self._call_idx += 1
        return ChatResult(
            content=content,
            usage=ChatUsage(prompt_tokens=10, completion_tokens=10, total_tokens=20),
            model=model or "mock",
        )


class _ConstTool(Tool):
    name = "const_tool"
    description = "returns a constant"
    parameters = {"type": "object", "properties": {}}

    def __init__(self, output: str = "ok") -> None:
        self._output = output

    def execute(self, **_: Any) -> str:  # type: ignore[override]
        return self._output


def test_engine_without_mid_term_backward_compatible() -> None:
    """未启用 mid_term 时，ReActEngine 行为与之前一致."""
    scripts = [
        "Thought: 调用工具\nAction: const_tool\nAction Input: {}",
        "Thought: 完成\nFinal Answer: ok",
    ]
    llm = ScriptedLLMClient(scripts)
    engine = ReActEngine(llm=llm, tools=[_ConstTool("ok")], max_steps=5)
    result = engine.run("task")

    assert result.success is True
    assert result.final_answer == "ok"
    # 工具集应不含 remember_fact
    assert "remember_fact" not in engine.tools


def test_engine_with_mid_term_registers_remember_fact_tool() -> None:
    """启用 mid_term 时，自动注册 remember_fact 工具."""
    llm = ScriptedLLMClient(["Final Answer: x"])
    mem = MidTermMemory()
    engine = ReActEngine(
        llm=llm, tools=[_ConstTool("ok")], max_steps=3, mid_term=mem
    )
    engine.run("task")
    assert "remember_fact" in engine.tools
    # 原 const_tool 仍保留
    assert "const_tool" in engine.tools


def test_engine_remember_fact_persists_across_rounds() -> None:
    """关键事实跨轮不丢：Agent 第 1 步记录事实，第 2 步 LLM 能在 system prompt 看到."""
    scripts = [
        # 第 1 步：Agent 主动记录关键事实
        "Thought: 我发现了目标 IP，先记录下来\n"
        'Action: remember_fact\n'
        'Action Input: {"key": "target_ip", "value": "192.168.1.100"}',
        # 第 2 步：基于事实给出最终答案
        "Thought: 已记录的事实可用\nFinal Answer: flag{ok}",
    ]
    llm = ScriptedLLMClient(scripts)
    mem = MidTermMemory()
    engine = ReActEngine(
        llm=llm, tools=[_ConstTool("ok")], max_steps=5, mid_term=mem
    )

    result = engine.run("扫描目标")

    assert result.success is True
    assert result.final_answer == "flag{ok}"

    # 中期记忆中应有该事实
    assert mem.get_facts_dict(engine._user_task_id or "") or mem.list_task_ids()
    # 第 2 次调用 LLM 时，system prompt 应包含 target_ip
    second_call_messages = llm.calls[1]
    system_msg = second_call_messages[0]
    assert system_msg.role == "system"
    assert "target_ip" in system_msg.content
    assert "192.168.1.100" in system_msg.content


def test_engine_remember_fact_visible_in_first_call_when_preexisting() -> None:
    """已有事实应在第 1 轮推理时就注入 system prompt（任务复现场景）."""
    mem = MidTermMemory()
    # 预先写入一条事实（模拟上次任务记录）
    mem.add_fact("task-abc", "target_ip", "10.0.0.5")

    llm = ScriptedLLMClient(["Final Answer: x"])
    engine = ReActEngine(
        llm=llm,
        tools=[_ConstTool("ok")],
        max_steps=3,
        mid_term=mem,
        task_id="task-abc",
    )
    engine.run("重新扫描目标")

    first_call = llm.calls[0]
    system_msg = first_call[0]
    assert "target_ip" in system_msg.content
    assert "10.0.0.5" in system_msg.content


def test_engine_task_id_auto_generated_when_not_specified() -> None:
    """未指定 task_id 时自动生成（uuid hex 短形式，12 位）."""
    llm = ScriptedLLMClient(["Final Answer: x"])
    mem = MidTermMemory()
    engine = ReActEngine(
        llm=llm, tools=[_ConstTool("ok")], max_steps=3, mid_term=mem
    )
    engine.run("task")
    # 自动生成的 task_id 应能在 mid_term 中查到（若 Agent 调用过 remember_fact）
    # 至少 list_task_ids 应为空或包含自动生成的 ID（这里没调用 remember_fact，应为空）
    assert mem.list_task_ids() == []


def test_engine_task_id_user_specified_used_for_storage() -> None:
    """用户指定的 task_id 用于索引中期记忆."""
    scripts = [
        "Thought: 记录\n"
        'Action: remember_fact\n'
        'Action Input: {"key": "k1", "value": "v1"}',
        "Thought: 完成\nFinal Answer: x",
    ]
    llm = ScriptedLLMClient(scripts)
    mem = MidTermMemory()
    engine = ReActEngine(
        llm=llm,
        tools=[_ConstTool("ok")],
        max_steps=5,
        mid_term=mem,
        task_id="my-task-id",
    )
    engine.run("task")

    # 应能用指定 task_id 查到
    assert mem.get_facts_dict("my-task-id") == {"k1": "v1"}


def test_engine_facts_injected_each_round() -> None:
    """每轮推理都应注入最新事实（不只首次）."""
    scripts = [
        # 第 1 步：记录 fact_a
        "Thought: 记录 a\n"
        'Action: remember_fact\n'
        'Action Input: {"key": "fact_a", "value": "value_a"}',
        # 第 2 步：记录 fact_b
        "Thought: 记录 b\n"
        'Action: remember_fact\n'
        'Action Input: {"key": "fact_b", "value": "value_b"}',
        # 第 3 步：给出最终答案
        "Thought: 完成\nFinal Answer: done",
    ]
    llm = ScriptedLLMClient(scripts)
    mem = MidTermMemory()
    engine = ReActEngine(
        llm=llm, tools=[_ConstTool("ok")], max_steps=5,
        mid_term=mem, task_id="t1",
    )

    result = engine.run("task")

    assert result.success is True
    # 第 2 次调用时 system prompt 应包含 fact_a（第 1 步记录的）
    second_call_sys = llm.calls[1][0]
    assert "fact_a" in second_call_sys.content
    # 第 3 次调用时 system prompt 应包含 fact_a 和 fact_b
    third_call_sys = llm.calls[2][0]
    assert "fact_a" in third_call_sys.content
    assert "fact_b" in third_call_sys.content
