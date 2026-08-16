"""Sprint 4.1 验收测试：Analyzer Markdown 报告生成.

依据 README 阶段四验收标准：
"任务结束后自动生成包含时间线与改进建议的 Markdown 报告"

覆盖：
1. generate_full_report：完整报告结构（概述/时间线/详细步骤/统计/建议）
2. 时间线：相对时间计算、状态显示
3. 改进建议：成功/失败/重复动作/错误工具
4. Analyzer.generate_report 方法
5. 边界：无步骤、无时间戳、超长 observation
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from ctf_agent.agent import ReActResult, ReActStep
from ctf_agent.analyzer import Analyzer, generate_full_report


# ============ 测试数据构造 ============

def _make_success_result_with_timestamps() -> ReActResult:
    """构造带时间戳的成功结果."""
    base = 1000.0
    return ReActResult(
        success=True,
        final_answer="picoCTF{win}",
        steps=[
            ReActStep(
                step_no=1,
                thought="我需要用 HEAD 请求",
                action="http_request",
                action_input='{"method": "HEAD", "url": "http://ctf/"}',
                observation="HTTP/1.1 200\nX-Flag: picoCTF{win}",
                timestamp=base,
            ),
            ReActStep(
                step_no=2,
                thought="在响应头找到 flag",
                is_final=True,
                final_answer="picoCTF{win}",
                timestamp=base + 2.5,
            ),
        ],
        total_tokens=42,
        started_at=base,
        ended_at=base + 3.0,
        task="获取 http://ctf/ 的 flag",
    )


def _make_failure_result() -> ReActResult:
    """构造失败结果."""
    return ReActResult(
        success=False,
        steps=[
            ReActStep(step_no=1, thought="尝试", action="http_request",
                      action_input='{"url":"http://x/"}', observation="ok"),
            ReActStep(step_no=2, thought="重试", action="http_request",
                      action_input='{"url":"http://x/"}', observation="ok"),
            ReActStep(step_no=3, thought="再试", action="http_request",
                      action_input='{"url":"http://x/"}', observation="ok",
                      is_error=True, error_msg="timeout"),
        ],
        total_tokens=60,
        fail_reason="达到最大步数 3",
    )


# ============ 报告结构测试 ============

def test_report_contains_required_sections() -> None:
    """报告应包含 README 要求的段落：概述/时间线/详细步骤/统计/改进建议."""
    result = _make_success_result_with_timestamps()
    report = generate_full_report("task", result)

    assert "# CTF 任务报告" in report
    assert "## 概述" in report
    assert "## 时间线" in report
    assert "## 详细步骤" in report
    assert "## 统计分析" in report
    assert "## 改进建议" in report


def test_report_overview_contains_key_info() -> None:
    """概述应包含任务/状态/flag/步数/tokens/耗时."""
    result = _make_success_result_with_timestamps()
    report = generate_full_report("获取 http://ctf/ 的 flag", result)

    assert "获取 http://ctf/ 的 flag" in report
    assert "成功" in report
    assert "picoCTF{win}" in report
    assert "2" in report  # step_count
    assert "42" in report  # tokens
    assert "3.0s" in report  # elapsed


def test_report_includes_metadata_rows() -> None:
    """元数据应作为表格行显示."""
    result = _make_success_result_with_timestamps()
    report = generate_full_report(
        "task", result,
        metadata={"type": "web", "source": "picoCTF", "difficulty": 2},
    )
    assert "type" in report
    assert "web" in report
    assert "source" in report
    assert "picoCTF" in report
    assert "difficulty" in report


def test_report_timeline_shows_relative_time() -> None:
    """时间线应显示相对时间."""
    result = _make_success_result_with_timestamps()
    report = generate_full_report("task", result)

    # 第 1 步相对时间为 +0.0s
    assert "+0.0s" in report
    # 第 2 步相对时间为 +2.5s
    assert "+2.5s" in report


def test_report_timeline_shows_action_and_status() -> None:
    """时间线应显示 Action 和状态."""
    result = _make_success_result_with_timestamps()
    report = generate_full_report("task", result)

    assert "http_request" in report
    assert "Final Answer" in report or "(Final Answer)" in report
    assert "完成" in report


def test_report_detailed_steps_contains_thought_action_observation() -> None:
    """详细步骤应包含 Thought/Action/Observation."""
    result = _make_success_result_with_timestamps()
    report = generate_full_report("task", result)

    assert "我需要用 HEAD 请求" in report
    assert "http_request" in report
    assert "X-Flag: picoCTF{win}" in report
    assert "Thought" in report
    assert "Action" in report
    assert "Observation" in report


def test_report_statistics_contains_tool_usage() -> None:
    """统计应包含工具使用频次."""
    result = _make_success_result_with_timestamps()
    report = generate_full_report("task", result)

    assert "工具使用频次" in report
    assert "http_request" in report
    assert "1 次" in report


def test_report_statistics_contains_error_count_and_avg_tokens() -> None:
    """统计应包含错误次数和平均 token."""
    result = _make_success_result_with_timestamps()
    report = generate_full_report("task", result)

    assert "错误次数" in report
    assert "平均每步 Token" in report
    # 42 / 2 = 21
    assert "21" in report


# ============ 改进建议测试 ============

def test_suggestions_success_high_efficiency() -> None:
    """成功且步数少时应有高效建议."""
    result = _make_success_result_with_timestamps()  # 2 步
    report = generate_full_report("task", result)

    assert "任务成功完成" in report
    assert "解题高效" in report


def test_suggestions_failure_max_steps() -> None:
    """失败于最大步数时应有相应建议."""
    result = _make_failure_result()
    report = generate_full_report("task", result)

    assert "任务失败" in report
    assert "达到最大步数 3" in report
    assert "增加 max_steps" in report or "拆分子任务" in report


def test_suggestions_detects_repeated_actions() -> None:
    """重复工具调用应被检测."""
    result = _make_failure_result()  # http_request 调用 3 次
    report = generate_full_report("task", result)

    assert "重复工具调用" in report or "重复动作" in report


def test_suggestions_detects_error_tools() -> None:
    """出错的工具应被列出."""
    result = _make_failure_result()  # 第 3 步错误
    report = generate_full_report("task", result)

    assert "出错的工具" in report
    assert "http_request" in report


# ============ 边界情况 ============

def test_report_no_steps() -> None:
    """无步骤时也应能生成报告."""
    result = ReActResult(success=True, final_answer="x", total_tokens=10)
    report = generate_full_report("task", result)

    assert "CTF 任务报告" in report
    assert "无步骤" in report or "(无步骤记录)" in report


def test_report_no_timestamps_shows_na() -> None:
    """无时间戳时时间线显示 N/A."""
    result = ReActResult(
        success=True,
        final_answer="x",
        steps=[
            ReActStep(step_no=1, thought="t", action="tool", action_input="{}",
                      observation="o"),
            ReActStep(step_no=2, is_final=True, final_answer="x"),
        ],
        total_tokens=20,
    )
    report = generate_full_report("task", result)

    assert "N/A" in report


def test_report_truncates_long_observation() -> None:
    """超长 observation 应被截断."""
    long_obs = "x" * 1000
    result = ReActResult(
        success=True,
        final_answer="x",
        steps=[
            ReActStep(step_no=1, thought="t", action="tool", action_input="{}",
                      observation=long_obs),
            ReActStep(step_no=2, is_final=True, final_answer="x"),
        ],
        total_tokens=20,
    )
    report = generate_full_report("task", result)

    assert "截断" in report
    assert "1000 字符" in report


def test_report_elapsed_formats_minutes_and_seconds() -> None:
    """耗时超过 60s 应格式化为分钟."""
    result = ReActResult(
        success=True,
        final_answer="x",
        steps=[ReActStep(step_no=1, is_final=True, final_answer="x")],
        total_tokens=10,
        started_at=0.0,
        ended_at=125.5,
    )
    report = generate_full_report("task", result)
    assert "2m 5.5s" in report


# ============ Analyzer.generate_report 方法 ============

def test_analyzer_generate_report_method() -> None:
    """Analyzer.generate_report 应等价于 generate_full_report."""
    analyzer = Analyzer()
    result = _make_success_result_with_timestamps()
    report = analyzer.generate_report("task", result)

    assert "# CTF 任务报告" in report
    assert "## 时间线" in report
    assert "## 改进建议" in report


def test_report_can_be_saved_to_file(tmp_path) -> None:
    """报告应能写入文件（CLI 集成预备）."""
    result = _make_success_result_with_timestamps()
    report = generate_full_report("task", result)

    report_file = tmp_path / "report.md"
    report_file.write_text(report, encoding="utf-8")

    assert report_file.exists()
    saved = report_file.read_text(encoding="utf-8")
    assert "CTF 任务报告" in saved
