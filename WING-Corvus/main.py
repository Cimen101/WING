"""CTF-Agent CLI 入口.

阶段二提供 --version 与 run 子命令：
    python main.py run --target http://ctf.example/ --desc "PicoCTF GET aHEAD"
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console

from ctf_agent import __version__

console = Console(stderr=True)


def build_parser() -> argparse.ArgumentParser:
    """构建 CLI 参数解析器."""
    parser = argparse.ArgumentParser(
        prog="ctf-agent",
        description="CTF-Agent 全能型自动化攻防智能体系统",
    )
    parser.add_argument(
        "--version", action="version", version=f"ctf-agent {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # run 子命令
    run_parser = subparsers.add_parser("run", help="运行 CTF 任务")
    run_parser.add_argument("--target", help="目标 IP/域名/URL")
    run_parser.add_argument("--file", help="题目附件路径")
    run_parser.add_argument(
        "--desc", default="", help="题目描述文本（可选）"
    )
    run_parser.add_argument(
        "--show-steps", action="store_true",
        help="输出每步详细 Thought/Action/Observation",
    )
    run_parser.add_argument(
        "--report", metavar="PATH", default=None,
        help="任务结束后将 Markdown 报告写入指定文件（含时间线与改进建议）",
    )
    run_parser.add_argument(
        "--type", default=None,
        help="题目类型元数据（web/pwn/crypto/misc/recon，用于报告与入库）",
    )
    run_parser.add_argument(
        "--source", default=None,
        help="题目来源元数据（如 picoCTF，用于报告与入库）",
    )
    run_parser.add_argument(
        "--difficulty", type=int, default=None,
        help="题目难度元数据（0-10，用于报告与入库）",
    )
    run_parser.add_argument(
        "--no-rag", action="store_true",
        help="关闭 RAG 经验检索（默认开启：开局从长期记忆库检索相似历史方案辅助解题）",
    )

    # web 子命令
    web_parser = subparsers.add_parser("web", help="启动 WebUI 服务器")
    web_parser.add_argument(
        "--host", default="127.0.0.1", help="监听地址（默认 127.0.0.1）"
    )
    web_parser.add_argument(
        "--port", type=int, default=8000, help="监听端口（默认 8000）"
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI 主入口.

    Args:
        argv: 命令行参数，None 时读取 sys.argv

    Returns:
        进程退出码（0 成功，1 失败）
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "run":
        return _cmd_run(args)

    if args.command == "web":
        return _cmd_web(args)

    return 0


def _cmd_web(args: argparse.Namespace) -> int:
    """启动 WebUI 服务器."""
    from ctf_agent.config import get_settings
    from ctf_agent.web import run_server

    settings = get_settings()
    if not settings.has_llm_config():
        console.print(
            "[bold yellow]警告[/bold yellow]：OPENAI_API_KEY 未配置，"
            "WebUI 可启动但无法提交任务"
        )

    console.print(
        f"[bold cyan]启动 WebUI[/bold cyan]\n"
        f"  地址: http://{args.host}:{args.port}\n"
        f"  LLM: {'已配置' if settings.has_llm_config() else '未配置'}\n"
        f"  Kali: {'已配置' if settings.has_kali_config() else '未配置'}"
    )
    try:
        run_server(host=args.host, port=args.port, settings=settings)
    except KeyboardInterrupt:
        console.print("[bold yellow]WebUI 已停止[/bold yellow]")
    except Exception as e:  # noqa: BLE001
        console.print(f"[bold red]WebUI 启动失败[/bold red]：{type(e).__name__}: {e}")
        return 1
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    """执行 run 子命令."""
    # 延迟导入，避免未执行 run 时加载 LLM/openai 等重依赖
    from ctf_agent.cli.runner import build_task_description, format_result_summary, run_task
    from ctf_agent.config import get_settings

    settings = get_settings()
    if not settings.has_llm_config():
        console.print(
            "[bold red]错误[/bold red]：OPENAI_API_KEY 未配置，"
            "请在 .env 中设置（参考 .env.example）"
        )
        return 1

    if not args.target and not args.file:
        console.print(
            "[bold red]错误[/bold red]：至少需要提供 --target 或 --file 之一"
        )
        return 1

    console.print(
        f"[bold cyan]启动 CTF 任务[/bold cyan]\n"
        f"  目标: {args.target or '(无)'}\n"
        f"  附件: {args.file or '(无)'}\n"
        f"  描述: {args.desc or '(无)'}\n"
        f"  模型: {settings.executor_model} | 最大步数: {settings.max_steps}"
    )

    def _on_step(step) -> None:  # type: ignore[no-untyped-def]
        if args.show_steps:
            tag = "FINAL" if step.is_final else ("ERROR" if step.is_error else "ACTION")
            console.print(
                f"[dim]─── 步骤 {step.step_no} [{tag}] ───[/dim]\n"
                f"[yellow]Thought:[/yellow] {step.thought}"
            )
            if step.action:
                console.print(
                    f"[blue]Action:[/blue] {step.action}\n"
                    f"[blue]Action Input:[/blue] {step.action_input}"
                )
            if step.observation:
                console.print(f"[green]Observation:[/green] {step.observation[:500]}")
            if step.is_final:
                console.print(f"[bold green]Final Answer:[/bold green] {step.final_answer}")
            if step.is_error:
                console.print(f"[red]Error:[/red] {step.error_msg}")

    try:
        # 注入 on_step 回调到 engine（通过重新构造 engine 注入）
        from ctf_agent.agent import ReActEngine
        from ctf_agent.llm import LLMClient
        from ctf_agent.tools import default_tools
        from ctf_agent.ssh import ssh_client_from_settings

        llm = LLMClient(settings)
        # 当 Kali 配置可用时，自动启用 SSH 工具
        ssh_client = None
        if settings.has_kali_config():
            try:
                ssh_client = ssh_client_from_settings(settings)
                ssh_client.connect()
                console.print(
                    f"[bold green]Kali SSH 已连接[/bold green]："
                    f"{settings.kali_user}@{settings.kali_host}"
                )
            except Exception as ssh_err:  # noqa: BLE001
                console.print(
                    f"[bold yellow]Kali SSH 连接失败[/bold yellow]：{ssh_err}"
                    "（将仅使用内置工具）"
                )
                ssh_client = None

        # S12: 消息总线接入 → 共享发现工具可用
        from ctf_agent.bus.message_bus import get_default_bus
        tools = default_tools(ssh_client=ssh_client,
                              message_bus=get_default_bus(), agent_id="agent")
        # Sprint 15: 持续学习——加载 Skill 库，解题时注入过往积累的套路/工具用法
        try:
            from ctf_agent.memory import SkillLibrary

            skill_library = SkillLibrary()
        except Exception:  # noqa: BLE001
            skill_library = None

        # 经验闭环（LTM/RAG）：默认接入长期记忆库，开局检索相似历史方案注入
        # system prompt；求解成功后再由 ingest_solution 沉淀回去，实现知识自增长。
        long_term = None
        if not args.no_rag:
            try:
                from ctf_agent.memory import LongTermMemory

                long_term = LongTermMemory(chroma_path=settings.chroma_path)
                console.print(
                    f"[bold green]RAG 经验库已接入[/bold green]："
                    f"{settings.chroma_path}（docs={long_term.count()}）"
                )
            except Exception as rag_err:  # noqa: BLE001
                console.print(
                    f"[bold yellow]RAG 经验库接入失败[/bold yellow]：{rag_err}"
                    "（将仅使用原生能力）"
                )
                long_term = None

        engine = ReActEngine(
            llm=llm,
            tools=tools,
            max_steps=settings.max_steps,
            on_step=_on_step,
            challenge_type=args.type,
            challenge_difficulty=args.difficulty,
            skill_library=skill_library,
            long_term=long_term,
            skip_hyde=False,
        )
        result = run_task(
            target=args.target,
            file=args.file,
            desc=args.desc,
            engine=engine,
        )
    except ValueError as e:
        console.print(f"[bold red]配置错误[/bold red]：{e}")
        return 1
    except Exception as e:  # noqa: BLE001 - CLI 顶层捕获所有异常避免崩溃
        console.print(f"[bold red]运行异常[/bold red]：{type(e).__name__}: {e}")
        return 1
    finally:
        # 确保 SSH 连接关闭
        if 'ssh_client' in locals() and ssh_client is not None:
            try:
                ssh_client.close()
            except Exception:  # noqa: BLE001
                pass

    console.print(format_result_summary(result))

    # Sprint 15: 持续学习——从本次解题过程提炼可复用 skill（writeup 的结构化升级）
    if "skill_library" in locals() and skill_library is not None:
        try:
            from ctf_agent.skill_learner import learn_skill

            sk = learn_skill(
                build_task_description(args.target, args.file, args.desc),
                result,
                skill_library,
                challenge_type=args.type or "misc",
                difficulty=args.difficulty or "",
            )
            if sk is not None:
                skill_library.prune()  # 自我迭代：控制规模，避免臃肿
                console.print(f"[dim]已积累/更新技能：{sk.id} (v{sk.version})[/dim]")
        except Exception:  # noqa: BLE001
            pass

    # Sprint 16: 经验闭环——成功解题去标识化后写入长期记忆（LTM），使 RAG
    # 能在后续同类题开局检索到"自己解过的题"，实现知识库自增长（flag 已隐去）。
    if result.success:
        try:
            from ctf_agent.experience import ingest_solution

            doc_id = ingest_solution(
                build_task_description(args.target, args.file, args.desc),
                result,
                challenge_type=args.type or "misc",
                difficulty=args.difficulty,
            )
            if doc_id:
                console.print(f"[dim]已沉淀解题经验到知识库：{doc_id}[/dim]")
        except Exception:  # noqa: BLE001
            pass

    # 生成 Markdown 报告（如果用户指定 --report）
    if args.report:
        try:
            from ctf_agent.analyzer import Analyzer
            from pathlib import Path

            # 构造 metadata
            metadata: dict = {}
            if args.type:
                metadata["type"] = args.type
            if args.source:
                metadata["source"] = args.source
            if args.difficulty is not None:
                metadata["difficulty"] = args.difficulty

            analyzer = Analyzer()
            task_desc = build_task_description(args.target, args.file, args.desc)
            report = analyzer.generate_report(task_desc, result, metadata=metadata or None)

            report_path = Path(args.report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(report, encoding="utf-8")
            console.print(f"[bold green]报告已写入[/bold green]：{report_path}")
        except Exception as e:  # noqa: BLE001
            console.print(f"[bold red]报告生成失败[/bold red]：{type(e).__name__}: {e}")

    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())

