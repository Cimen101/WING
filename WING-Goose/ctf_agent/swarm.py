"""WING-Goose 第 7 节第 1 项: runner 层 swarm 编排.

同题 N 子进程并行 (每路一个 style) + 跨进程提交协调 (一解出即杀其余) +
难度 → 并发度策略 (T3 结论: easy 单路, medium/hard 3 风格并行).

用法:
    from ctf_agent.swarm import SwarmCoordinator

    sw = SwarmCoordinator(project_root=".", verify_flag=lambda f: (f == EXPECTED, "ok"))
    result = sw.run(task, styles=None, max_seconds=600.0)
    # result.solved / result.flag / result.winner_style / result.agents[...]

实现要点:
  - 每路一个 AgentClient.solve 子进程 (task JSON 带 style 字段, solve.py 已支持)
  - 任一子进程提交正确 flag → kill 其余兄弟进程 (on_proc 注册的句柄)
  - 全部线程 join 或超时兜底 (kill 全部存活进程)
"""
from __future__ import annotations

import json
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ctf_agent.client import AgentCallbacks, AgentClient, AgentResult

# T3 结论: easy 单路; medium/hard 3 风格并行
DEFAULT_STYLES_BY_DIFFICULTY = {
    "easy": [""],                                            # 单路默认保守
    "medium": ["conservative", "aggressive", "innovative"],
    "hard": ["conservative", "aggressive", "innovative"],
}


@dataclass
class SwarmAgentResult:
    """单路 (单风格) 求解结果."""
    style: str
    success: bool = False
    flag: str = ""
    steps: int = 0
    elapsed: float = 0.0
    tokens: int = 0
    fail_reason: str = ""
    killed_by_sibling: bool = False   # 兄弟解出后被终止
    result: AgentResult | None = None


@dataclass
class SwarmResult:
    """swarm 汇总结果."""
    solved: bool = False
    flag: str = ""
    winner_style: str = ""
    elapsed: float = 0.0
    total_tokens: int = 0
    agents: list[SwarmAgentResult] = field(default_factory=list)
    styles: list[str] = field(default_factory=list)
    killed_count: int = 0
    task: dict[str, Any] = field(default_factory=dict)

    def by_style(self, style: str) -> SwarmAgentResult | None:
        for a in self.agents:
            if a.style == style:
                return a
        return None


class SwarmCoordinator:
    """同题多风格并行编排器 (runner 层)."""

    def __init__(
        self,
        project_root: str | Path = ".",
        python_executable: str | None = None,
        verify_flag: Callable[[str], tuple[bool, str]] | None = None,
        workdir: str | Path | None = None,
    ) -> None:
        """
        Args:
            project_root: 项目根目录 (含 ctf_agent 包)
            python_executable: Python 解释器 (默认 sys.executable)
            verify_flag: flag 校验回调 (flag) -> (is_correct, feedback).
                默认 None: 接受第一个提交的 flag 为解出 (agent 只提交确认的 flag)
                ⚠️ 设计约定 (Crypto_Reverse 复盘):
                  - verify_flag 的职责是"平台/确证性校验"(如 NSS 真实提交), 不是"防幻觉"
                    (防幻觉已由 react.py 内部兜底: 无工具调用直接 Final 会被拒绝).
                  - 只有存在确凿反证 (明确不匹配证据) 时才返回 False; 无法判定时应
                    倾向返回 True (接受 + 调用者自行审计), 否则会误伤已真实解出的 flag,
                    带偏 agent 并导致兄弟 kill 不触发 (资源空转).
                  - 回调抛异常不冒泡: 记录并返回 False, agent 收到明确反馈继续分析.
            workdir: task JSON 临时目录 (默认 <project_root>/data/swarm_tasks)
        """
        self.client = AgentClient(project_root=project_root,
                                  python_executable=python_executable)
        root = Path(project_root).resolve()
        self.workdir = Path(workdir) if workdir else root / "data" / "swarm_tasks"
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.verify_flag = verify_flag

        self._lock = threading.Lock()
        self._procs: dict[str, subprocess.Popen] = {}
        self._solved: dict[str, str] = {"flag": "", "style": ""}

    # ---------- 内部 ----------
    def _submit(self, style: str, flag: str) -> tuple[bool, str]:
        if self.verify_flag is not None:
            try:
                return self.verify_flag(flag)
            except Exception as e:  # noqa: BLE001
                # 验证器异常不冒泡: 拒绝 + 明确反馈, agent 收到后继续分析
                return False, f"verify_flag 异常: {type(e).__name__}: {e}"
        return True, "swarm: 接受首个提交"

    def _on_submission(self, style: str, flag: str) -> tuple[bool, str]:
        correct, feedback = self._submit(style, flag)
        if not correct:
            return False, feedback
        # 正确 → 标记解出 + kill 其余兄弟进程
        with self._lock:
            if not self._solved["flag"]:
                self._solved = {"flag": flag, "style": style}
                for st, p in list(self._procs.items()):
                    if st != style and p.poll() is None:
                        try:
                            p.kill()
                        except Exception:
                            pass
                return True, "正确! 已解出, 其余并行进程已终止"
        return True, "正确!"

    def _run_one(self, style: str, task: dict[str, Any], task_file: Path,
                 max_seconds: float, on_step=None, on_log=None) -> SwarmAgentResult:
        t0 = time.monotonic()
        res = SwarmAgentResult(style=style)

        def _cb(*, name: str, style: str, on_cb, **kwargs):
            if on_cb:
                try:
                    on_cb(style, **kwargs)
                except Exception:
                    pass

        callbacks = AgentCallbacks(
            on_proc=lambda p: self._procs.__setitem__(style, p),
            on_submission=lambda flag: self._on_submission(style, flag),
            on_step=lambda obj: _cb(name="on_step", style=style, on_cb=on_step, obj=obj),
            on_log=lambda lv, msg: _cb(name="on_log", style=style, on_cb=on_log,
                                       level=lv, message=msg),
        )
        try:
            ar = self.client.solve(task_file, callbacks, max_seconds=max_seconds)
            res.result = ar
            res.success = ar.success
            res.flag = ar.flag
            res.steps = ar.steps
            res.elapsed = ar.elapsed
            res.tokens = ar.tokens
            res.fail_reason = ar.fail_reason
            if res.flag:
                res.flag = ar.flag
            # 被兄弟解出后 kill → raw_result 为空且非 winner
            with self._lock:
                if self._solved["flag"] and self._solved["style"] != style and not ar.raw_result:
                    res.killed_by_sibling = True
        except Exception as e:  # noqa: BLE001
            res.fail_reason = f"swarm 线程异常: {type(e).__name__}: {e}"
        finally:
            res.elapsed = round(time.monotonic() - t0, 1)
        return res

    def run(
        self,
        task: dict[str, Any],
        styles: list[str] | None = None,
        max_seconds: float = 600.0,
        on_step=None,
        on_log=None,
    ) -> SwarmResult:
        """同题多风格 swarm 并行求解.

        Args:
            task: 任务 dict (desc/type/difficulty/challenge_id/title/max_seconds 等);
                  style 字段由本方法按路注入
            styles: 参与风格列表; None 按难度默认 (T3: easy 单路, medium/hard 3 路)
            max_seconds: 每路硬超时
            on_step/on_log: 外部实时回调, 签名 (style, obj) / (style, level, message)

        Returns:
            SwarmResult
        """
        styles = styles if styles is not None else DEFAULT_STYLES_BY_DIFFICULTY.get(
            str(task.get("difficulty", "medium")).lower(), ["conservative", "aggressive", "innovative"])
        styles = list(styles) or [""]
        if "" in styles and len(styles) > 1:
            styles = [s for s in styles if s != ""]   # 单路才允许空风格

        self._procs = {}
        self._solved = {"flag": "", "style": ""}
        base_id = str(task.get("challenge_id") or "swarm")
        swarm_start = time.monotonic()

        threads: list[threading.Thread] = []
        agents: dict[str, SwarmAgentResult] = {}
        for style in styles:
            t = dict(task)
            if style:
                t["style"] = style
            t["challenge_id"] = f"{base_id}:{style or 'single'}"
            tf = self.workdir / f"{base_id}_{style or 'single'}.json"
            tf.write_text(json.dumps(t, ensure_ascii=False, indent=2), encoding="utf-8")

            def _worker(st: str = style, f: Path = tf):
                agents[st] = self._run_one(st, t, f, max_seconds, on_step=on_step, on_log=on_log)

            th = threading.Thread(target=_worker, daemon=True)
            threads.append(th)
            th.start()

        for th in threads:
            th.join(timeout=max_seconds + 60)
        # 超时兜底: kill 全部存活子进程
        for p in self._procs.values():
            if p.poll() is None:
                try:
                    p.kill()
                except Exception:
                    pass
        for th in threads:
            th.join(timeout=5)

        order = [s for s in styles]
        results = [agents.get(s, SwarmAgentResult(style=s)) for s in order]
        solved_flag = self._solved["flag"]
        winner = self._solved["style"]
        killed = sum(1 for r in results if r.killed_by_sibling)
        return SwarmResult(
            solved=bool(solved_flag),
            flag=solved_flag,
            winner_style=winner,
            elapsed=round(time.monotonic() - swarm_start, 1),
            total_tokens=sum(r.tokens for r in results),
            agents=results,
            styles=order,
            killed_count=killed,
            task=task,
        )

    def stop(self) -> bool:
        """停止所有存活子进程 (供外部调用, 如 NSS Runner stop 信号).

        Returns:
            True 如果至少 kill 了一个进程
        """
        killed_any = False
        for p in self._procs.values():
            if p.poll() is None:
                try:
                    p.kill()
                    killed_any = True
                except Exception:
                    pass
        return killed_any


__all__ = ["SwarmCoordinator", "SwarmResult", "SwarmAgentResult",
           "DEFAULT_STYLES_BY_DIFFICULTY"]
    