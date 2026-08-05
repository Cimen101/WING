"""CLI 入口层（L1）.

依据 README §3.6，阶段二提供 CLI 模式（argparse + Rich）。
TUI/WebUI 在阶段八接入。
"""

from ctf_agent.cli.runner import build_task_description, run_task

__all__ = ["build_task_description", "run_task"]
