"""Sprint 2.6 验收测试：CLI runner 与端到端流程.

端到端验证 PicoCTF GET aHEAD 类题目：
    1. Agent 调用 http_request HEAD 方法
    2. HTTP 工具返回含 flag 的响应头（respx mock）
    3. Agent 从响应头提取 flag，输出 Final Answer
    4. run_task 返回 success=True + flag

同时覆盖：
- build_task_description 拼接逻辑
- run_task 依赖注入（engine 注入 vs 配置构造）
- main() CLI 入口的 run 子命令
"""

from __future__ import annotations

import httpx
import pytest
import respx

from ctf_agent.agent import ReActEngine, ReActResult, ReActStep
from ctf_agent.cli import build_task_description, run_task
from ctf_agent.cli.runner import format_result_summary
from ctf_agent.config import Settings
from ctf_agent.llm import ChatResult, ChatUsage, LLMClient, Message
from ctf_agent.tools import default_tools


# ============ 脚本化 LLM mock（与 test_react.py 同构，独立定义避免跨文件依赖） ============

class ScriptedLLMClient(LLMClient):
    """按预设脚本顺序返回 LLM 响应."""

    def __init__(self, scripts: list[str]):
        self.settings = None  # type: ignore[assignment]
        self._scripts = list(scripts)
        self._call_idx = 0

    def chat(self, messages, model=None, temperature=0.0, max_tokens=None, timeout=None, extra=None) -> ChatResult:  # type: ignore[override]
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


# ============ build_task_description ============

def test_build_task_description_all_fields() -> None:
    desc = build_task_description(
        target="http://ctf.example/", file="/tmp/chall.elf", desc="PicoCTF Web 题"
    )
    assert "PicoCTF Web 题" in desc
    assert "目标: http://ctf.example/" in desc
    assert "附件: /tmp/chall.elf" in desc


def test_build_task_description_target_only() -> None:
    desc = build_task_description(target="http://ctf.example/")
    assert desc == "目标: http://ctf.example/"


def test_build_task_description_desc_only() -> None:
    desc = build_task_description(target=None, desc="纯文本题目")
    assert desc == "纯文本题目"


def test_build_task_description_empty_returns_default() -> None:
    desc = build_task_description(target=None, file=None, desc="")
    assert "CTF" in desc


def test_build_task_description_strips_whitespace() -> None:
    desc = build_task_description(target="  http://x/  ", desc="  hi  ")
    assert "目标: http://x/" in desc
    assert "hi" in desc


# ============ run_task 依赖注入 ============

def test_run_task_with_injected_engine() -> None:
    """注入 engine 时，run_task 应直接调用 engine.run."""
    llm = ScriptedLLMClient(["Thought: t\nFinal Answer: flag{injected}"])
    engine = ReActEngine(llm=llm, tools=default_tools(), max_steps=3)

    result = run_task(target="http://x/", engine=engine)

    assert result.success is True
    assert result.final_answer == "flag{injected}"


def test_run_task_without_api_key_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """未注入 engine 且无 API Key 时应报错."""
    # 禁用 .env 文件加载，避免 .env 中的真实 key 覆盖 monkeypatch.delenv
    from ctf_agent.config import Settings
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("MAX_STEPS", "5")
    # 清除 get_settings 缓存，确保读到新配置
    from ctf_agent.config import get_settings
    get_settings.cache_clear()

    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        run_task(target="http://x/")

    get_settings.cache_clear()


def test_run_task_passes_task_description_to_engine() -> None:
    """run_task 应把 target/desc 拼成任务描述传给 engine."""
    llm = ScriptedLLMClient(["Thought: t\nFinal Answer: x"])
    captured_tasks: list[str] = []

    class _CapturingEngine(ReActEngine):
        def run(self, task: str) -> ReActResult:  # type: ignore[override]
            captured_tasks.append(task)
            return super().run(task)

    engine = _CapturingEngine(llm=llm, tools=default_tools(), max_steps=3)
    run_task(target="http://target.example/", desc="my desc", engine=engine)

    assert len(captured_tasks) == 1
    assert "http://target.example/" in captured_tasks[0]
    assert "my desc" in captured_tasks[0]


# ============ format_result_summary ============

def test_format_result_summary_success() -> None:
    result = ReActResult(
        success=True,
        final_answer="picoCTF{win}",
        steps=[ReActStep(step_no=1, is_final=True, final_answer="picoCTF{win}")],
        total_tokens=42,
    )
    summary = format_result_summary(result)
    assert "成功" in summary
    assert "picoCTF{win}" in summary
    assert "42" in summary


def test_format_result_summary_failure() -> None:
    result = ReActResult(
        success=False,
        fail_reason="达到最大步数 35",
        steps=[],
        total_tokens=100,
    )
    summary = format_result_summary(result)
    assert "失败" in summary
    assert "达到最大步数 35" in summary
    assert "100" in summary


# ============ 端到端：PicoCTF GET aHEAD ============

@respx.mock
def test_e2e_get_ahead_challenge_full_loop() -> None:
    """端到端验证：模拟 PicoCTF GET aHEAD 题目全自动解题.

    GET aHEAD 题目特征：flag 在 HEAD 请求的响应头中。
    Agent 应：
      1. 调用 http_request HEAD 方法
      2. 从响应头 x-flag 提取 flag
      3. 输出 Final Answer
    """
    # mock HEAD 请求：响应头含 flag
    respx.head("http://ctf.example/").mock(
        return_value=httpx.Response(
            200,
            headers={"x-flag": "picoCTF{r3qu3st_g3ts_a_h3ad}", "content-type": "text/html"},
        )
    )

    # 脚本化 LLM：模拟 Agent 的两步推理
    llm = ScriptedLLMClient([
        # 第 1 步：识别题目，决定用 HEAD 请求
        "Thought: 这是 GET aHEAD 题目，提示用 HEAD 方法。我发一个 HEAD 请求看响应头。\n"
        'Action: http_request\n'
        'Action Input: {"url": "http://ctf.example/", "method": "HEAD"}',
        # 第 2 步：从响应头提取 flag
        "Thought: 响应头 x-flag 中有 flag: picoCTF{r3qu3st_g3ts_a_h3ad}\n"
        "Final Answer: picoCTF{r3qu3st_g3ts_a_h3ad}",
    ])

    engine = ReActEngine(llm=llm, tools=default_tools(), max_steps=5)

    result = run_task(
        target="http://ctf.example/",
        desc="PicoCTF GET aHEAD - find the flag",
        engine=engine,
    )

    # 验收：全自动获取 flag
    assert result.success is True
    assert result.final_answer == "picoCTF{r3qu3st_g3ts_a_h3ad}"
    assert result.step_count == 2

    # 第 1 步调用了 http_request HEAD
    assert result.steps[0].action == "http_request"
    assert '"method": "HEAD"' in result.steps[0].action_input
    assert "picoCTF{r3qu3st_g3ts_a_h3ad}" in result.steps[0].observation

    # 第 2 步给出 Final Answer
    assert result.steps[1].is_final is True


@respx.mock
def test_e2e_get_ahead_with_format_error_recovery() -> None:
    """端到端验证：LLM 第一步格式错误，修正后成功解题."""
    respx.head("http://ctf.example/").mock(
        return_value=httpx.Response(
            200, headers={"x-flag": "picoCTF{recovered}"}
        )
    )

    llm = ScriptedLLMClient([
        "我直接告诉你 flag 是什么",  # 格式错误
        "Thought: 重新按格式来，先发 HEAD 请求\n"
        'Action: http_request\n'
        'Action Input: {"url": "http://ctf.example/", "method": "HEAD"}',
        "Thought: 找到 flag\nFinal Answer: picoCTF{recovered}",
    ])

    engine = ReActEngine(llm=llm, tools=default_tools(), max_steps=5)

    result = run_task(target="http://ctf.example/", engine=engine)

    assert result.success is True
    assert result.final_answer == "picoCTF{recovered}"
    assert result.step_count == 3
    assert result.steps[0].is_error is True  # 第一步格式错误


@respx.mock
def test_e2e_http_error_observation_visible_to_llm() -> None:
    """端到端验证：工具返回 ERROR 时，LLM 能在后续步骤看到并修正."""
    # 第一次 HEAD 返回 404，第二次 GET 返回 200 + flag
    respx.head("http://ctf.example/").mock(
        return_value=httpx.Response(404, headers={"x-flag": "picoCTF{not_here}"})
    )

    llm = ScriptedLLMClient([
        "Thought: 先用 HEAD\n"
        'Action: http_request\n'
        'Action Input: {"url": "http://ctf.example/", "method": "HEAD"}',
        # 即使 404，响应头里其实有 flag，LLM 应能提取
        "Thought: 虽然 404，但响应头有 x-flag\n"
        "Final Answer: picoCTF{not_here}",
    ])

    engine = ReActEngine(llm=llm, tools=default_tools(), max_steps=5)
    result = run_task(target="http://ctf.example/", engine=engine)

    assert result.success is True
    assert result.final_answer == "picoCTF{not_here}"
    # 验证 LLM 在第 2 步能看到第 1 步的 Observation（含 404 状态）
    assert "HTTP 404" in result.steps[0].observation


# ============ main() CLI 入口 ============

def test_main_version(capsys: pytest.CaptureFixture[str]) -> None:
    """--version 输出版本号."""
    import main

    with pytest.raises(SystemExit) as exc_info:
        main.main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "ctf-agent" in captured.out
    assert "0.1.0" in captured.out


def test_main_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    """无子命令时打印帮助."""
    import main

    rc = main.main([])
    assert rc == 0
    captured = capsys.readouterr()
    assert "ctf-agent" in captured.out.lower() or "usage" in captured.out.lower()


def test_main_run_without_api_key_returns_1(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """无 API Key 时 run 子命令返回 1 并报错."""
    # 禁用 .env 文件加载，避免 .env 中的真实 key 覆盖 monkeypatch.delenv
    from ctf_agent.config import Settings
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    from ctf_agent.config import get_settings
    get_settings.cache_clear()

    import main

    rc = main.main(["run", "--target", "http://x/"])
    assert rc == 1

    get_settings.cache_clear()


def test_main_run_without_target_or_file_returns_1(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """有 API Key 但无 target/file 时 run 子命令返回 1."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    from ctf_agent.config import get_settings
    get_settings.cache_clear()

    import main

    rc = main.main(["run"])
    assert rc == 1

    get_settings.cache_clear()


def test_main_run_with_injected_engine_succeeds(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """通过 monkeypatch ReActEngine，验证 run 子命令完整流程."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    from ctf_agent.config import get_settings
    get_settings.cache_clear()

    llm = ScriptedLLMClient([
        "Thought: t\nFinal Answer: picoCTF{cli_e2e}"
    ])
    fake_engine = ReActEngine(llm=llm, tools=default_tools(), max_steps=3)

    import main
    # main._cmd_run 内部 `from ctf_agent.agent import ReActEngine` 会取到 patched 版本
    # lambda 吞掉所有构造参数，返回预构造的 fake_engine
    monkeypatch.setattr(
        "ctf_agent.agent.ReActEngine",
        lambda **kwargs: fake_engine,
    )

    rc = main.main(["run", "--target", "http://ctf.example/", "--desc", "test"])

    assert rc == 0
    get_settings.cache_clear()


# ============ Sprint 4.2: --report 参数集成 ============

def _patch_engine_for_cli(
    monkeypatch: pytest.MonkeyPatch,
    scripts: list[str],
) -> ReActEngine:
    """在 CLI 流程中注入脚本化 engine，返回 fake_engine 引用."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    from ctf_agent.config import get_settings
    get_settings.cache_clear()

    llm = ScriptedLLMClient(scripts)
    fake_engine = ReActEngine(llm=llm, tools=default_tools(), max_steps=3)
    monkeypatch.setattr(
        "ctf_agent.agent.ReActEngine",
        lambda **kwargs: fake_engine,
    )
    return fake_engine


def test_main_run_with_report_writes_markdown_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--report PATH 触发报告生成并写入文件."""
    _patch_engine_for_cli(monkeypatch, ["Thought: t\nFinal Answer: picoCTF{rep}"])

    import main

    report_path = tmp_path / "out" / "report.md"
    rc = main.main([
        "run", "--target", "http://x/",
        "--report", str(report_path),
    ])

    assert rc == 0
    assert report_path.exists()
    content = report_path.read_text(encoding="utf-8")
    assert "CTF 任务报告" in content
    assert "picoCTF{rep}" in content
    assert "时间线" in content
    assert "改进建议" in content
    # 控制台输出确认
    captured = capsys.readouterr()
    assert "报告已写入" in captured.err

    from ctf_agent.config import get_settings
    get_settings.cache_clear()


def test_main_run_with_report_includes_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """--type/--source/--difficulty 元数据应进入报告."""
    _patch_engine_for_cli(monkeypatch, ["Thought: t\nFinal Answer: flag{m}"])

    import main

    report_path = tmp_path / "r.md"
    rc = main.main([
        "run", "--target", "http://x/",
        "--type", "web",
        "--source", "picoCTF",
        "--difficulty", "5",
        "--report", str(report_path),
    ])

    assert rc == 0
    content = report_path.read_text(encoding="utf-8")
    assert "web" in content
    assert "picoCTF" in content
    assert "5" in content

    from ctf_agent.config import get_settings
    get_settings.cache_clear()


def test_main_run_without_report_does_not_create_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """未传 --report 时不创建报告文件."""
    _patch_engine_for_cli(monkeypatch, ["Thought: t\nFinal Answer: flag{x}"])

    import main

    rc = main.main(["run", "--target", "http://x/"])
    assert rc == 0
    # tmp_path 下不应有任意 .md
    assert not list(tmp_path.glob("*.md"))

    from ctf_agent.config import get_settings
    get_settings.cache_clear()


def test_main_run_report_generation_failure_does_not_affect_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """报告生成失败不应影响任务本身的退出码."""
    _patch_engine_for_cli(monkeypatch, ["Thought: t\nFinal Answer: flag{ok}"])

    # 让 Analyzer.generate_report 抛异常
    def _boom(*args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "ctf_agent.analyzer.Analyzer.generate_report",
        _boom,
    )

    import main

    report_path = tmp_path / "r.md"
    rc = main.main([
        "run", "--target", "http://x/",
        "--report", str(report_path),
    ])

    # 任务本身成功，rc 应为 0
    assert rc == 0
    # 报告文件未生成
    assert not report_path.exists()
    captured = capsys.readouterr()
    assert "报告生成失败" in captured.err

    from ctf_agent.config import get_settings
    get_settings.cache_clear()
