"""CLI run 子命令的核心执行逻辑.

将 main.py 的命令行参数转换为 ReAct 引擎任务并执行。
通过依赖注入 ReActEngine，使端到端流程可在测试中用 mock 验证
（设计约定：不为测试修改生产 API，而是让接口本身可测试）。
"""

from __future__ import annotations

from typing import Any

from ctf_agent.agent import ReActEngine, ReActResult
from ctf_agent.config import Settings, get_settings
from ctf_agent.llm import LLMClient
from ctf_agent.tools import default_tools
from ctf_agent.tools.base import Tool


def build_task_description(
    target: str | None,
    file: str | None = None,
    desc: str = "",
) -> str:
    """从 CLI 参数构建任务描述文本.

    Args:
        target: 目标 IP/域名/URL
        file: 题目附件路径
        desc: 题目描述文本

    Returns:
        拼接后的任务描述字符串
    """
    parts: list[str] = []
    if desc:
        parts.append(desc.strip())
    if target:
        parts.append(f"目标: {target.strip()}")
    if file:
        parts.append(f"附件: {file.strip()}")

    if not parts:
        return "请解决此 CTF 题目。"
    return "\n".join(parts)


def run_task(
    target: str | None = None,
    file: str | None = None,
    desc: str = "",
    *,
    engine: ReActEngine | None = None,
    settings: Settings | None = None,
    llm: LLMClient | None = None,
    tools: list[Tool] | None = None,
) -> ReActResult:
    """运行 CTF 任务.

    优先使用注入的 engine（测试用）；否则从 settings 构造完整执行链。

    Args:
        target: 目标 IP/域名/URL
        file: 题目附件路径
        desc: 题目描述文本
        engine: 注入的 ReAct 引擎（测试用，优先级最高）
        settings: 配置（未提供时用 get_settings）
        llm: 注入的 LLM 客户端（engine 为 None 时使用）
        tools: 注入的工具列表（engine 为 None 时使用）

    Returns:
        ReActResult
    """
    task = build_task_description(target=target, file=file, desc=desc)

    if engine is not None:
        return engine.run(task)

    # 从配置构造执行链
    settings = settings or get_settings()
    if not settings.has_llm_config():
        raise ValueError(
            "OPENAI_API_KEY 未配置，请在 .env 中设置（参考 .env.example）"
        )

    llm = llm or LLMClient(settings)
    tools = tools or default_tools()

    # 经验闭环（LTM/RAG）：默认接入长期记忆库辅助解题，不可用时静默降级为原生能力。
    long_term = None
    try:
        from ctf_agent.memory import LongTermMemory

        long_term = LongTermMemory(chroma_path=settings.chroma_path)
    except Exception:  # noqa: BLE001
        long_term = None

    engine = ReActEngine(
        llm=llm,
        tools=tools,
        max_steps=settings.max_steps,
        long_term=long_term,
        skip_hyde=False,
    )
    return engine.run(task)


def format_result_summary(result: ReActResult) -> str:
    """格式化结果摘要供 CLI 输出."""
    lines: list[str] = []
    if result.success:
        lines.append(f"[bold green]成功[/bold green] Flag: {result.final_answer}")
    else:
        lines.append(f"[bold red]失败[/bold red] 原因: {result.fail_reason}")
    lines.append(
        f"步数: {result.step_count} | Tokens: {result.total_tokens}"
    )
    return "\n".join(lines)
