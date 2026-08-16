"""Sprint 5.9 多智能体 Planner-Executor-Critic 框架测试.

验证：
1. Planner 任务拆解（JSON 解析、降级策略）
2. Executor 工具白名单过滤
3. Critic 审核（成功/失败/降级）
4. MultiAgentOrchestrator 端到端流程
5. CHAP 上下文交接
6. 依赖检查
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

import pytest

from ctf_agent.agent import (
    Critic,
    CriticReview,
    Executor,
    ExecutorReport,
    MultiAgentOrchestrator,
    MultiAgentResult,
    ParallelMultiAgentOrchestrator,
    Planner,
    RacingExecutor,
    RacingResult,
    SubTask,
    TOOL_WHITELIST,
    arbitrate_conflicts,
    filter_tools_by_type,
)
from ctf_agent.agent.react import ReActResult
from ctf_agent.llm import ChatResult, ChatUsage, LLMClient, Message
from ctf_agent.tools.base import Tool


# ============ 辅助 mock ============

class MockTool(Tool):
    """测试用 mock 工具."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.description = f"Mock tool {name}"
        self.parameters = {"type": "object", "properties": {}}

    def execute(self, **kwargs: Any) -> str:
        return f"mock_{self.name}_result"


def _make_tools(*names: str) -> list[Tool]:
    return [MockTool(n) for n in names]


class MockLLMClient:
    """Mock LLMClient，按预设响应序列返回.

    支持 chat() 返回 ChatResult。responses 是 list[ChatResult | str]。
    """

    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def chat(self, messages, model=None, temperature=None, **kwargs):
        self.calls.append({
            "messages": messages,
            "model": model,
            "temperature": temperature,
        })
        if not self.responses:
            raise RuntimeError("MockLLMClient 响应已耗尽")
        resp = self.responses.pop(0)
        if isinstance(resp, ChatResult):
            return resp
        if isinstance(resp, str):
            return ChatResult(content=resp, usage=ChatUsage(total_tokens=100))
        if isinstance(resp, Exception):
            raise resp
        # callable: 动态生成
        if callable(resp):
            return resp(messages, model, temperature)
        return ChatResult(content=str(resp), usage=ChatUsage(total_tokens=50))


# ============ 工具白名单过滤测试 ============

class TestToolWhitelist:
    """测试 filter_tools_by_type."""

    def test_web_type_filters_to_whitelist(self):
        tools = _make_tools(
            "ssh_exec", "ssh_python", "http_request",
            "base64_encode", "ghidra_headless", "radare2",
        )
        filtered = filter_tools_by_type(tools, "web")
        names = {t.name for t in filtered}
        assert "ssh_exec" in names
        assert "http_request" in names
        assert "ghidra_headless" not in names
        assert "radare2" not in names

    def test_pwn_type_includes_reverse_tools(self):
        tools = _make_tools(
            "ssh_exec", "ssh_python", "ghidra_headless", "radare2",
            "hex_dump", "http_request",
        )
        filtered = filter_tools_by_type(tools, "pwn")
        names = {t.name for t in filtered}
        assert "ghidra_headless" in names
        assert "radare2" in names
        assert "http_request" not in names

    def test_crypto_type_excludes_ssh_exec(self):
        tools = _make_tools(
            "ssh_exec", "ssh_python", "caesar_cipher", "rot13",
            "base64_encode", "hash_compute",
        )
        filtered = filter_tools_by_type(tools, "crypto")
        names = {t.name for t in filtered}
        assert "ssh_python" in names
        assert "caesar_cipher" in names
        assert "ssh_exec" not in names  # crypto 不允许 ssh_exec

    def test_misc_type_returns_all_tools(self):
        tools = _make_tools("ssh_exec", "http_request", "anything_else")
        filtered = filter_tools_by_type(tools, "misc")
        assert len(filtered) == 3

    def test_unknown_type_returns_all(self):
        """未知题型保守返回全部工具."""
        tools = _make_tools("ssh_exec", "http_request")
        filtered = filter_tools_by_type(tools, "unknown_category")
        assert len(filtered) == 2

    def test_reverse_type_includes_ghidra_and_strings(self):
        tools = _make_tools(
            "ssh_exec", "ghidra_headless", "radare2",
            "strings", "file_type", "hex_dump",
            "http_request", "caesar_cipher",
        )
        filtered = filter_tools_by_type(tools, "reverse")
        names = {t.name for t in filtered}
        assert "ghidra_headless" in names
        assert "strings" in names
        assert "http_request" not in names
        assert "caesar_cipher" not in names


# ============ Planner 测试 ============

class TestPlanner:
    """测试 Planner 任务拆解."""

    def test_plan_parses_valid_json(self):
        """Planner 能正确解析 LLM 返回的 JSON 数组."""
        llm_response = '''```json
[
  {
    "id": "step1",
    "type": "recon",
    "description": "扫描目标端口",
    "target": "192.168.1.1",
    "depends_on": [],
    "executor_hint": "nmap 全端口扫描"
  },
  {
    "id": "step2",
    "type": "web",
    "description": "针对 80 端口 web 服务渗透",
    "target": "http://192.168.1.1",
    "depends_on": ["step1"],
    "executor_hint": "目录爆破 + SQL 注入测试"
  }
]
```'''
        client = MockLLMClient([llm_response])
        planner = Planner(client)  # type: ignore[arg-type]
        plan = planner.plan("渗透 192.168.1.1")

        assert len(plan) == 2
        assert plan[0].id == "step1"
        assert plan[1].id == "step2"
        assert plan[1].depends_on == ["step1"]
        # recon 不在白名单，应被规范化为 misc
        assert plan[0].type == "misc"
        assert plan[1].type == "web"

    def test_plan_fallback_on_invalid_json(self):
        """LLM 返回非 JSON 时降级为单任务."""
        client = MockLLMClient(["抱歉，我无法处理此任务"])
        planner = Planner(client)  # type: ignore[arg-type]
        plan = planner.plan("test task")

        assert len(plan) == 1
        assert plan[0].id == "fallback"
        assert plan[0].type == "misc"

    def test_plan_fallback_on_llm_exception(self):
        """LLM 抛异常时降级为单任务."""
        client = MockLLMClient([RuntimeError("API unavailable")])
        planner = Planner(client)  # type: ignore[arg-type]
        plan = planner.plan("test task")

        assert len(plan) == 1
        assert plan[0].id == "fallback"

    def test_plan_normalizes_unknown_type_to_misc(self):
        """未知 type 字段被规范化为 misc."""
        llm_response = '''[
          {"id": "s1", "type": "forensics", "description": "取证分析"}
        ]'''
        client = MockLLMClient([llm_response])
        planner = Planner(client)  # type: ignore[arg-type]
        plan = planner.plan("取证任务")

        assert len(plan) == 1
        assert plan[0].type == "misc"

    def test_plan_includes_rag_context(self):
        """RAG 上下文应注入到 user prompt."""
        llm_response = '[{"id": "s1", "type": "misc", "description": "x"}]'
        client = MockLLMClient([llm_response])
        planner = Planner(client)  # type: ignore[arg-type]
        planner.plan("test task", rag_context="历史方案：RSA 偶数分解")

        user_msg = client.calls[0]["messages"][-1].content
        assert "RSA 偶数分解" in user_msg


# ============ Critic 测试 ============

class TestCritic:
    """测试 Critic 审核."""

    def test_review_rejects_failed_executor(self):
        """失败的 Executor 不调用 LLM 直接判不通过."""
        client = MockLLMClient([])  # 不应有 LLM 调用
        critic = Critic(client)  # type: ignore[arg-type]
        subtask = SubTask(id="s1", type="misc", description="测试")
        report = ExecutorReport(
            subtask_id="s1", success=False, fail_reason="工具调用失败"
        )

        review = critic.review(subtask, report)
        assert not review.approved
        assert "工具调用失败" in review.reason
        assert len(client.calls) == 0  # 未调用 LLM

    def test_review_approves_successful_executor(self):
        """成功的 Executor 通过 LLM 审核."""
        llm_response = '''```json
        {
          "approved": true,
          "reason": "Executor 成功提取 flag",
          "suggestion": ""
        }
        ```'''
        client = MockLLMClient([llm_response])
        critic = Critic(client)  # type: ignore[arg-type]
        subtask = SubTask(id="s1", type="misc", description="提取 flag")
        report = ExecutorReport(
            subtask_id="s1",
            success=True,
            final_answer="flag{test}",
            summary="成功提取 flag",
        )

        review = critic.review(subtask, report)
        assert review.approved
        assert "成功" in review.reason

    def test_review_rejects_with_suggestion(self):
        """Critic 不通过时给出建议."""
        llm_response = '''{
          "approved": false,
          "reason": "未找到 flag",
          "suggestion": "尝试 8080 端口"
        }'''
        client = MockLLMClient([llm_response])
        critic = Critic(client)  # type: ignore[arg-type]
        subtask = SubTask(id="s1", type="web", description="web 渗透")
        report = ExecutorReport(
            subtask_id="s1",
            success=True,
            final_answer="未找到",
            summary="扫描了 80 端口",
        )

        review = critic.review(subtask, report)
        assert not review.approved
        assert "8080" in review.suggestion

    def test_review_fallback_on_llm_exception(self):
        """LLM 异常时默认通过."""
        client = MockLLMClient([RuntimeError("API error")])
        critic = Critic(client)  # type: ignore[arg-type]
        subtask = SubTask(id="s1", type="misc", description="测试")
        report = ExecutorReport(
            subtask_id="s1",
            success=True,
            final_answer="flag{x}",
        )

        review = critic.review(subtask, report)
        assert review.approved
        assert "默认通过" in review.reason

    def test_review_fallback_on_invalid_json(self):
        """LLM 返回非 JSON 时默认通过."""
        client = MockLLMClient(["这不是 JSON"])
        critic = Critic(client)  # type: ignore[arg-type]
        subtask = SubTask(id="s1", type="misc", description="测试")
        report = ExecutorReport(
            subtask_id="s1",
            success=True,
            final_answer="flag{x}",
        )

        review = critic.review(subtask, report)
        assert review.approved
        assert "默认通过" in review.reason


# ============ Executor 测试 ============

class TestExecutor:
    """测试 Executor 执行."""

    def test_execute_calls_react_engine(self):
        """Executor 通过 ReActEngine 执行子任务."""
        # 构造一个 mock LLMClient，让 ReActEngine 走通一次循环
        # 第一次：Final Answer 直接返回
        final_response = ChatResult(
            content="Thought: 任务很简单\nFinal Answer: flag{test}",
            usage=ChatUsage(total_tokens=50),
        )
        client = MockLLMClient([final_response])
        executor = Executor(client, _make_tools("ssh_exec", "base64_encode"), model="test-model")  # type: ignore[arg-type]

        subtask = SubTask(
            id="s1",
            type="crypto",
            description="解密 Base64",
            executor_hint="使用 base64_decode",
        )
        report = executor.execute(subtask)

        assert report.success
        assert report.final_answer == "flag{test}"
        assert report.subtask_id == "s1"

    def test_execute_filters_tools_by_type(self):
        """Executor 按题型过滤工具."""
        final_response = ChatResult(
            content="Thought: 完成\nFinal Answer: flag{x}",
            usage=ChatUsage(total_tokens=30),
        )
        client = MockLLMClient([final_response])
        # 全部工具
        tools = _make_tools(
            "ssh_exec", "http_request", "ghidra_headless",
            "base64_encode", "caesar_cipher",
        )
        executor = Executor(client, tools)  # type: ignore[arg-type]

        # crypto 类型应过滤掉 ssh_exec/http_request/ghidra_headless
        # 但 ReActEngine 会用 system_prompt 描述工具，验证调用时 LLM 看到的工具
        subtask = SubTask(id="s1", type="crypto", description="crypto 题")
        executor.execute(subtask)

        # 第一次调用 LLM 时 system prompt 中应包含 caesar_cipher 但不含 ghidra_headless
        system_msg = client.calls[0]["messages"][0].content
        assert "caesar_cipher" in system_msg
        assert "ghidra_headless" not in system_msg

    def test_execute_passes_context_summaries(self):
        """Executor 将前置摘要注入任务描述."""
        final_response = ChatResult(
            content="Final Answer: flag{x}",
            usage=ChatUsage(total_tokens=20),
        )
        client = MockLLMClient([final_response])
        executor = Executor(client, _make_tools("ssh_exec"))  # type: ignore[arg-type]

        subtask = SubTask(id="s2", type="misc", description="后续任务")
        executor.execute(subtask, context_summaries=["前置: 扫描完成，发现 8080 端口"])

        user_msg = client.calls[0]["messages"][-1].content
        assert "前置: 扫描完成" in user_msg

    def test_execute_handles_react_failure(self):
        """Executor 处理 ReAct 失败."""
        # 连续格式错误触发 max_format_errors 终止
        bad_response = ChatResult(
            content="这不是合法格式",
            usage=ChatUsage(total_tokens=10),
        )
        client = MockLLMClient([bad_response] * 10)
        executor = Executor(client, _make_tools("ssh_exec"))  # type: ignore[arg-type]

        subtask = SubTask(id="s1", type="misc", description="测试")
        report = executor.execute(subtask)

        assert not report.success
        assert "格式" in report.fail_reason or "失败" in report.fail_reason


# ============ MultiAgentOrchestrator 端到端测试 ============

class TestMultiAgentOrchestrator:
    """测试多智能体编排端到端."""

    def test_run_single_subtask_success(self):
        """单子任务场景：Planner 拆 1 个 + Executor 成功 + Critic 通过."""
        # 1. Planner 返回单子任务
        plan_response = '''[
          {"id": "s1", "type": "misc", "description": "解题", "executor_hint": ""}
        ]'''
        # 2. Executor ReAct 循环：直接 Final Answer
        executor_response = ChatResult(
            content="Thought: 解出来了\nFinal Answer: flag{single}",
            usage=ChatUsage(total_tokens=80),
        )
        # 3. Critic 审核：通过
        critic_response = '''{
          "approved": true,
          "reason": "成功",
          "suggestion": ""
        }'''

        client = MockLLMClient([plan_response, executor_response, critic_response])
        orchestrator = MultiAgentOrchestrator(
            client,  # type: ignore[arg-type]
            _make_tools("ssh_exec", "base64_encode"),
        )
        result = orchestrator.run("单步任务")

        assert result.success
        assert result.final_answer == "flag{single}"
        assert result.subtask_count == 1
        assert len(result.executor_reports) == 1
        assert len(result.critic_reviews) == 1
        assert result.critic_reviews[0].approved

    def test_run_multi_subtask_with_dependency(self):
        """多子任务 + 依赖：step1 成功后 step2 执行."""
        plan_response = '''[
          {"id": "s1", "type": "misc", "description": "侦察", "depends_on": []},
          {"id": "s2", "type": "web", "description": "渗透", "depends_on": ["s1"]}
        ]'''
        # s1 Executor
        s1_response = ChatResult(
            content="Final Answer: 80 端口开放",
            usage=ChatUsage(total_tokens=50),
        )
        # s1 Critic
        s1_critic = '{"approved": true, "reason": "完成"}'
        # s2 Executor
        s2_response = ChatResult(
            content="Final Answer: flag{multi}",
            usage=ChatUsage(total_tokens=70),
        )
        # s2 Critic
        s2_critic = '{"approved": true, "reason": "完成"}'

        client = MockLLMClient([
            plan_response, s1_response, s1_critic, s2_response, s2_critic,
        ])
        orchestrator = MultiAgentOrchestrator(
            client,  # type: ignore[arg-type]
            _make_tools("ssh_exec", "http_request"),
        )
        result = orchestrator.run("多步任务")

        assert result.success
        assert result.final_answer == "flag{multi}"
        assert result.subtask_count == 2
        # 验证 s2 看到了 s1 的摘要
        # s2 的 Executor 调用是第 4 次调用（plan=1, s1_exec=2, s1_critic=3, s2_exec=4）
        s2_user_msg = client.calls[3]["messages"][-1].content
        assert "80 端口开放" in s2_user_msg or "s1" in s2_user_msg

    def test_run_dependency_not_met_skips_subtask(self):
        """依赖未满足的子任务被跳过."""
        plan_response = '''[
          {"id": "s1", "type": "misc", "description": "前置", "depends_on": []},
          {"id": "s2", "type": "misc", "description": "后置", "depends_on": ["s1"]}
        ]'''
        # s1 Executor 失败
        s1_response = ChatResult(
            content="无效格式",
            usage=ChatUsage(total_tokens=10),
        )
        # s1 Critic（因 s1 失败直接不通过，不调 LLM）
        # s2 应被跳过（不调用 LLM）

        client = MockLLMClient([plan_response, s1_response] + [s1_response] * 10)
        orchestrator = MultiAgentOrchestrator(
            client,  # type: ignore[arg-type]
            _make_tools("ssh_exec"),
        )
        result = orchestrator.run("依赖失败任务")

        # 整体失败：s1 失败 + s2 被跳过
        assert not result.success
        assert len(result.executor_reports) == 2
        # s2 报告应说明依赖未满足
        s2_report = result.executor_reports[1]
        assert not s2_report.success
        assert "依赖" in s2_report.fail_reason

    def test_run_critic_disabled(self):
        """enable_critic=False 时跳过 Critic."""
        plan_response = '[{"id": "s1", "type": "misc", "description": "x"}]'
        executor_response = ChatResult(
            content="Final Answer: flag{x}",
            usage=ChatUsage(total_tokens=30),
        )
        # 不应有 Critic 调用，所以只 2 个响应
        client = MockLLMClient([plan_response, executor_response])
        orchestrator = MultiAgentOrchestrator(
            client,  # type: ignore[arg-type]
            _make_tools("ssh_exec"),
            enable_critic=False,
        )
        result = orchestrator.run("无 Critic 任务")

        assert result.success
        assert len(result.critic_reviews) == 1
        assert "未启用" in result.critic_reviews[0].reason

    def test_run_planner_fallback_single_task(self):
        """Planner 降级为单任务时仍能执行."""
        # Planner 返回非 JSON
        plan_response = "我无法拆解此任务"
        executor_response = ChatResult(
            content="Final Answer: flag{fallback}",
            usage=ChatUsage(total_tokens=40),
        )
        critic_response = '{"approved": true, "reason": "ok"}'

        client = MockLLMClient([plan_response, executor_response, critic_response])
        orchestrator = MultiAgentOrchestrator(
            client,  # type: ignore[arg-type]
            _make_tools("ssh_exec"),
        )
        result = orchestrator.run("无法拆解的任务")

        assert result.success
        assert result.final_answer == "flag{fallback}"
        assert result.subtask_count == 1

    def test_run_aggregates_total_tokens(self):
        """total_tokens 聚合所有 Executor 的 token 消耗."""
        plan_response = '''[
          {"id": "s1", "type": "misc", "description": "x"},
          {"id": "s2", "type": "misc", "description": "y"}
        ]'''
        s1_resp = ChatResult(
            content="Final Answer: flag{1}",
            usage=ChatUsage(total_tokens=100),
        )
        s1_critic = '{"approved": true, "reason": ""}'
        s2_resp = ChatResult(
            content="Final Answer: flag{2}",
            usage=ChatUsage(total_tokens=200),
        )
        s2_critic = '{"approved": true, "reason": ""}'

        client = MockLLMClient([
            plan_response, s1_resp, s1_critic, s2_resp, s2_critic,
        ])
        orchestrator = MultiAgentOrchestrator(
            client,  # type: ignore[arg-type]
            _make_tools("ssh_exec"),
        )
        result = orchestrator.run("token 聚合测试")

        # total_tokens = 100 + 200 = 300（不含 Planner/Critic 调用）
        assert result.total_tokens == 300

    def test_run_takes_last_successful_answer(self):
        """多子任务都成功时，取最后一个的 final_answer."""
        plan_response = '''[
          {"id": "s1", "type": "misc", "description": "x"},
          {"id": "s2", "type": "misc", "description": "y"}
        ]'''
        s1_resp = ChatResult(
            content="Final Answer: flag{first}",
            usage=ChatUsage(total_tokens=50),
        )
        s1_critic = '{"approved": true, "reason": ""}'
        s2_resp = ChatResult(
            content="Final Answer: flag{second}",
            usage=ChatUsage(total_tokens=50),
        )
        s2_critic = '{"approved": true, "reason": ""}'

        client = MockLLMClient([
            plan_response, s1_resp, s1_critic, s2_resp, s2_critic,
        ])
        orchestrator = MultiAgentOrchestrator(
            client,  # type: ignore[arg-type]
            _make_tools("ssh_exec"),
        )
        result = orchestrator.run("取最后答案测试")

        assert result.final_answer == "flag{second}"


# ============ SubTask 数据结构测试 ============

class TestSubTask:
    """测试 SubTask 数据结构."""

    def test_subtask_default_values(self):
        s = SubTask(id="s1", type="misc", description="x")
        assert s.target == ""
        assert s.depends_on == []
        assert s.executor_hint == ""

    def test_subtask_with_all_fields(self):
        s = SubTask(
            id="s1",
            type="web",
            description="渗透",
            target="http://example.com",
            depends_on=["s0"],
            executor_hint="用 sqlmap",
        )
        assert s.target == "http://example.com"
        assert s.depends_on == ["s0"]


# ============ RacingExecutor 赛马测试 ============

class TestRacingExecutor:
    """测试 RacingExecutor 赛马机制."""

    def test_race_returns_first_success(self):
        """多个模型并行，首个成功者胜出."""
        # 3 个模型都返回成功（不同 flag），任意一个都可胜出
        responses = [
            ChatResult(content="Final Answer: flag{m1}", usage=ChatUsage(total_tokens=30)),
            ChatResult(content="Final Answer: flag{m2}", usage=ChatUsage(total_tokens=30)),
            ChatResult(content="Final Answer: flag{m3}", usage=ChatUsage(total_tokens=30)),
        ]
        client = MockLLMClient(responses)
        racer = RacingExecutor(
            client,  # type: ignore[arg-type]
            _make_tools("ssh_exec"),
            models=["m1", "m2", "m3"],
        )
        subtask = SubTask(id="s1", type="misc", description="test")
        result = racer.race(subtask)

        assert result.winner is not None
        assert result.winner.success
        assert "flag{" in result.winner.final_answer

    def test_race_all_failures_returns_none_winner(self):
        """所有模型都失败时 winner 为 None."""
        # 连续格式错误触发失败
        bad = ChatResult(content="无效格式", usage=ChatUsage(total_tokens=5))
        # 2 个模型，每个至少触发 max_format_errors=3 次错误
        client = MockLLMClient([bad] * 20)
        racer = RacingExecutor(
            client,  # type: ignore[arg-type]
            _make_tools("ssh_exec"),
            models=["m1", "m2"],
        )
        subtask = SubTask(id="s1", type="misc", description="test")
        result = racer.race(subtask)

        assert result.winner is None
        assert len(result.losers) >= 1

    def test_race_mixed_success_failure(self):
        """部分模型成功部分失败，胜出者有效."""
        success = ChatResult(content="Final Answer: flag{ok}", usage=ChatUsage(total_tokens=20))
        bad = ChatResult(content="无效格式", usage=ChatUsage(total_tokens=5))
        # 模型1成功，模型2失败（多次格式错误）
        client = MockLLMClient([success, bad, bad, bad, bad])
        racer = RacingExecutor(
            client,  # type: ignore[arg-type]
            _make_tools("ssh_exec"),
            models=["m1", "m2"],
        )
        subtask = SubTask(id="s1", type="misc", description="test")
        result = racer.race(subtask)

        assert result.winner is not None
        assert result.winner.success

    def test_race_requires_at_least_one_model(self):
        """models 为空时抛 ValueError."""
        client = MockLLMClient([])
        with pytest.raises(ValueError, match="至少"):
            RacingExecutor(client, _make_tools("ssh_exec"), models=[])  # type: ignore[arg-type]

    def test_race_records_losers(self):
        """赛马完成后 losers 应包含未胜出的报告."""
        # 第一个成功，第二个也成功但作为 loser
        r1 = ChatResult(content="Final Answer: flag{1}", usage=ChatUsage(total_tokens=10))
        r2 = ChatResult(content="Final Answer: flag{2}", usage=ChatUsage(total_tokens=10))
        client = MockLLMClient([r1, r2])
        racer = RacingExecutor(
            client,  # type: ignore[arg-type]
            _make_tools("ssh_exec"),
            models=["m1", "m2"],
        )
        subtask = SubTask(id="s1", type="misc", description="test")
        result = racer.race(subtask)

        assert result.winner is not None
        # 至少有一个 loser（可能是成功或失败的）
        # 注：因线程调度，胜负顺序可能不同，但总数 = 2
        assert len(result.losers) >= 1


# ============ arbitrate_conflicts 仲裁测试 ============

class TestArbitrateConflicts:
    """测试投票仲裁."""

    def test_majority_wins(self):
        """多数派胜出（3 个中 2 个答案相同）."""
        reports = [
            ExecutorReport(subtask_id="s1", success=True, final_answer="flag{A}"),
            ExecutorReport(subtask_id="s1", success=True, final_answer="flag{A}"),
            ExecutorReport(subtask_id="s1", success=True, final_answer="flag{B}"),
        ]
        winner = arbitrate_conflicts(reports)
        assert winner is not None
        assert winner.final_answer == "flag{A}"

    def test_no_majority_falls_back_to_first(self):
        """无多数派时取第一个成功者（无 Critic）."""
        reports = [
            ExecutorReport(subtask_id="s1", success=True, final_answer="flag{A}"),
            ExecutorReport(subtask_id="s1", success=True, final_answer="flag{B}"),
        ]
        winner = arbitrate_conflicts(reports)
        assert winner is not None
        # 平票时无 Critic，取第一个
        assert winner.final_answer == "flag{A}"

    def test_all_failed_returns_none(self):
        """全部失败返回 None."""
        reports = [
            ExecutorReport(subtask_id="s1", success=False, fail_reason="err"),
            ExecutorReport(subtask_id="s1", success=False, fail_reason="err"),
        ]
        winner = arbitrate_conflicts(reports)
        assert winner is None

    def test_single_success_returns_directly(self):
        """单个成功直接返回."""
        reports = [
            ExecutorReport(subtask_id="s1", success=True, final_answer="flag{x}"),
        ]
        winner = arbitrate_conflicts(reports)
        assert winner is not None
        assert winner.final_answer == "flag{x}"

    def test_empty_reports_returns_none(self):
        winner = arbitrate_conflicts([])
        assert winner is None

    def test_critic_breaks_tie(self):
        """Critic 打破平局：审核第一个通过则返回."""
        reports = [
            ExecutorReport(subtask_id="s1", success=True, final_answer="flag{A}"),
            ExecutorReport(subtask_id="s1", success=True, final_answer="flag{B}"),
        ]
        # Critic 审核第一个时通过
        critic_response = '{"approved": true, "reason": "ok"}'
        critic = Critic(MockLLMClient([critic_response]))  # type: ignore[arg-type]
        subtask = SubTask(id="s1", type="misc", description="test")
        winner = arbitrate_conflicts(reports, critic=critic, subtask=subtask)
        assert winner is not None
        assert winner.final_answer == "flag{A}"


# ============ ParallelMultiAgentOrchestrator 测试 ============

class TestParallelMultiAgentOrchestrator:
    """测试并行多智能体编排."""

    def test_parallel_run_single_subtask(self):
        """并行编排单子任务场景."""
        plan_response = '[{"id": "s1", "type": "misc", "description": "x"}]'
        executor_response = ChatResult(
            content="Final Answer: flag{parallel}",
            usage=ChatUsage(total_tokens=50),
        )
        critic_response = '{"approved": true, "reason": ""}'
        client = MockLLMClient([plan_response, executor_response, critic_response])
        orchestrator = ParallelMultiAgentOrchestrator(
            client,  # type: ignore[arg-type]
            _make_tools("ssh_exec"),
        )
        result = orchestrator.run("并行单任务")

        assert result.success
        assert result.final_answer == "flag{parallel}"

    def test_parallel_run_independent_subtasks(self):
        """两个无依赖子任务并行执行."""
        plan_response = '''[
          {"id": "s1", "type": "misc", "description": "task1", "depends_on": []},
          {"id": "s2", "type": "misc", "description": "task2", "depends_on": []}
        ]'''
        # 两个 Executor 都成功
        r1 = ChatResult(content="Final Answer: flag{1}", usage=ChatUsage(total_tokens=30))
        r2 = ChatResult(content="Final Answer: flag{2}", usage=ChatUsage(total_tokens=30))
        # 两个 Critic 通过
        c1 = '{"approved": true, "reason": ""}'
        c2 = '{"approved": true, "reason": ""}'
        client = MockLLMClient([plan_response, r1, r2, c1, c2])
        orchestrator = ParallelMultiAgentOrchestrator(
            client,  # type: ignore[arg-type]
            _make_tools("ssh_exec"),
        )
        result = orchestrator.run("并行独立任务")

        # 取最后一个成功的 final_answer
        assert result.success
        assert result.final_answer in {"flag{1}", "flag{2}"}
        assert result.subtask_count == 2

    def test_parallel_run_layered_dependency(self):
        """分层依赖：s1 完成后 s2 才执行."""
        plan_response = '''[
          {"id": "s1", "type": "misc", "description": "first", "depends_on": []},
          {"id": "s2", "type": "misc", "description": "second", "depends_on": ["s1"]}
        ]'''
        s1_resp = ChatResult(content="Final Answer: 80端口", usage=ChatUsage(total_tokens=30))
        s1_critic = '{"approved": true, "reason": ""}'
        s2_resp = ChatResult(content="Final Answer: flag{layered}", usage=ChatUsage(total_tokens=40))
        s2_critic = '{"approved": true, "reason": ""}'
        client = MockLLMClient([
            plan_response, s1_resp, s1_critic, s2_resp, s2_critic,
        ])
        orchestrator = ParallelMultiAgentOrchestrator(
            client,  # type: ignore[arg-type]
            _make_tools("ssh_exec"),
        )
        result = orchestrator.run("分层任务")

        assert result.success
        assert result.final_answer == "flag{layered}"

    def test_parallel_run_with_racing(self):
        """启用赛马：单子任务多模型并行."""
        plan_response = '[{"id": "s1", "type": "misc", "description": "x"}]'
        # 2 个模型都返回成功
        r1 = ChatResult(content="Final Answer: flag{r1}", usage=ChatUsage(total_tokens=20))
        r2 = ChatResult(content="Final Answer: flag{r2}", usage=ChatUsage(total_tokens=20))
        critic_resp = '{"approved": true, "reason": ""}'
        client = MockLLMClient([plan_response, r1, r2, critic_resp])
        orchestrator = ParallelMultiAgentOrchestrator(
            client,  # type: ignore[arg-type]
            _make_tools("ssh_exec"),
            racing_models=["m1", "m2"],
        )
        result = orchestrator.run("赛马任务")

        assert result.success
        assert result.final_answer in {"flag{r1}", "flag{r2}"}

    def test_parallel_run_deadlock_detection(self):
        """依赖死锁：所有剩余子任务因依赖未满足被标记失败."""
        # s2 依赖 s1，但 s1 失败导致 completed_ids 不含 s1
        plan_response = '''[
          {"id": "s1", "type": "misc", "description": "first", "depends_on": []},
          {"id": "s2", "type": "misc", "description": "second", "depends_on": ["s1"]}
        ]'''
        # s1 失败（格式错误）
        bad = ChatResult(content="无效格式", usage=ChatUsage(total_tokens=5))
        client = MockLLMClient([plan_response] + [bad] * 10)
        orchestrator = ParallelMultiAgentOrchestrator(
            client,  # type: ignore[arg-type]
            _make_tools("ssh_exec"),
            enable_critic=False,  # 简化：不调 Critic
        )
        result = orchestrator.run("死锁任务")

        # s1 失败，s2 因依赖未满足也失败
        assert not result.success
        # 应有 2 个报告（s1 失败 + s2 依赖未满足）
        assert len(result.executor_reports) == 2
