"""WING-Goose 第 7 节第 1 项: runner 层 swarm 编排.

同题 N 子进程并行 (每路一个 style) + 跨进程提交协调 (一解出即杀其余) +
难度 → 并发度策略 (历史测试结论: easy 单路, medium/hard 3 风格并行).

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

# 历史测试结论: easy 单路; medium/hard 3 风格并行
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
        commander_enabled: bool | None = None,
    ) -> None:
        """
        Args:
            project_root: 项目根目录 (含 ctf_agent 包)
            python_executable: Python 解释器 (默认 sys.executable)
            verify_flag: flag 校验回调 (flag) -> (is_correct, feedback).
                默认 None: 接受第一个提交的 flag 为解出 (agent 只提交确认的 flag)
                ⚠️ 设计约定 (复杂逆向题 复盘):
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
        # 总指挥开关 — None=读 config SWARM_COMMANDER_ENABLED
        self.commander_enabled = commander_enabled

        self._lock = threading.Lock()
        self._procs: dict[str, subprocess.Popen] = {}
        self._solved: dict[str, str] = {"flag": "", "style": ""}

    # ---------- 总指挥生命周期 ----------

    @staticmethod
    def _kill_tree(proc) -> None:
        """kill 进程树 (Windows: taskkill /F /T 杀主进程+子孙进程; 其他: kill).

        背景 (历史复盘): 单用 proc.kill() 只杀 python 主进程,
        其 spawn 的 docker exec/ssh 孙进程残留, 子进程 stdout 不关闭,
        readline 阻塞导致线程不结束, swarm join 等待失效 ("未及时 kill").
        """
        import os
        import subprocess as _sp

        if os.name == "nt":
            try:
                _sp.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                        capture_output=True, timeout=10)
                return
            except Exception:
                pass
        proc.kill()


    @staticmethod
    def _commander_default_enabled() -> bool:
        """读取 config 的总指挥开关 (LLM 不可用时会再降级)."""
        try:
            from ctf_agent.config import get_settings
            return bool(get_settings().swarm_commander_enabled)
        except Exception:
            return False

    def _setup_commander(self, task: dict[str, Any], on_commander=None):
        """启动总指挥: 领题分工 → 初始任务契约下发到总线.

        仅在开关启用时工作 (commander_enabled=False → 直接返回 None, 纯雁阵).
        on_commander: (level, message) 回调, 供调用方 (NSS Runner) 记录总指挥生命周期日志.
        Returns:
            (commander, bus, bus_key) 或 None (未启用/不可用 → 降级回雁阵).
        """
        want = (self.commander_enabled if self.commander_enabled is not None
                else self._commander_default_enabled())
        if not want:
            return None
        bus_dir = str(task.get("bus_dir") or "").strip()
        if not bus_dir:
            return None
        try:
            from ctf_agent.bus import FileBus
            from ctf_agent.commander import Commander
            from ctf_agent.config import get_settings
            from ctf_agent.llm.routed import RoutedLLMClient

            bus = FileBus(bus_dir)
            bus_key = str(task.get("bus_challenge_id")
                          or task.get("challenge_id") or "swarm")
            styles = [s for s in (task.get("styles") or []) if s]
            cmdr = Commander(
                llm=RoutedLLMClient(settings=get_settings()),
                title=str(task.get("title") or ""),
                task_desc=str(task.get("desc") or ""),
                challenge_type=str(task.get("type") or ""),
                challenge_difficulty=str(task.get("difficulty") or ""),
                styles=styles or None,
                challenge_id=bus_key,
                bus=bus,
                bus_challenge_id=bus_key,
            )
            assignments = cmdr.assign_initial()
            if not assignments:
                return None
            # 初始任务契约 → 每条 post_directive (战略层首步 check 读取, 统一走总线协议)
            # 领题即 P1 侦查阶段 (阶段信息随指令下发给战略层)
            for a in assignments:
                bus.post_directive(
                    agent_id=a.style, task_id=bus_key, content=a.task,
                    task_no=a.task_no, priority="SHOULD", reason="领题分工",
                    phase="P1",
                )
            # 领题分工日志 → 调用方 (NSS Runner 日志: 命令行 + 文件)
            if on_commander:
                try:
                    parts = "; ".join(
                        f"{a.style}→任务{a.task_no}: {a.task[:80]}" for a in assignments)
                    on_commander("INFO", f"总指挥领题分工: {parts}")
                except Exception:
                    pass
            return cmdr, bus, bus_key
        except Exception as e:  # noqa: BLE001 - 总指挥不可用降级回雁阵
            if on_commander:
                try:
                    on_commander("WARN",
                                 f"总指挥启动失败, 降级回雁阵: {type(e).__name__}: {e}")
                except Exception:
                    pass
            else:
                try:
                    print(f"[COMMANDER] 总指挥启动失败, 降级回雁阵: {type(e).__name__}: {e}")
                except Exception:
                    pass
            return None

    def _commander_loop(self, cmdr, bus, bus_key: str, stop_event, on_commander=None) -> None:
        """总指挥后台轮询: 消费战略层汇报 → LLM 分析 → 下发 directive (异步事件驱动)."""
        while not stop_event.is_set():
            try:
                directives = cmdr.run_once(bus=bus)
                # 总指挥指令日志 → 调用方 (NSS Runner 日志: 命令行 + 文件)
                if directives and on_commander:
                    for d in directives:
                        try:
                            on_commander(
                                "CMDR",
                                f"指令[{d.priority}] {d.style}(任务{d.task_no}): "
                                f"{d.direction[:120]} — 依据: {d.reason[:80]}",
                            )
                        except Exception:
                            pass
            except Exception:  # noqa: BLE001 - 总指挥异常不影响主流程
                pass
            stop_event.wait(5.0)

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
                 max_seconds: float, on_step=None, on_log=None,
                 on_coordinator=None) -> SwarmAgentResult:
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
            # 完整巡查/总指挥 dict 透传 (belief_state/reflection 详情写文件)
            on_coordinator=(lambda obj: _cb(name="on_coordinator", style=style,
                                            on_cb=on_coordinator, obj=obj))
            if on_coordinator else None,
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
        # 完整巡查 dict (style, obj) 透传 + 总指挥生命周期日志
        on_coordinator=None,
        on_commander=None,
    ) -> SwarmResult:
        """同题多风格 swarm 并行求解.

        Args:
            task: 任务 dict (desc/type/difficulty/challenge_id/title/max_seconds 等);
                  style 字段由本方法按路注入
            styles: 参与风格列表; None 按难度默认 (T3: easy 单路, medium/hard 3 路)
            max_seconds: 每路硬超时
            on_step/on_log: 外部实时回调, 签名 (style, obj) / (style, level, message)
            on_coordinator: 完整巡查/总指挥消息回调 (style, obj) — belief_state 详情等
            on_commander: 总指挥生命周期日志回调 (level, message) — 领题分工/指令/降级

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

        # 注入实际风格列表到 task (总指挥领题分工按真实参与风格分配,
        # 避免 Commander 内部 DEFAULT_STYLES 与调用方显式 styles 不一致)
        task = dict(task)
        task["styles"] = list(styles)

        # 总指挥生命周期 — 异步事件驱动, 不阻塞主 LLM.
        # 总指挥初始化 (assign_initial 是同步 LLM 调用, 最坏 90s×2 重试) 必须放后台线程:
        # 否则 worker 启动被阻塞, 整题开局停滞 (实测: 卡在"总指挥模式: 3 风格并行"
        # 后无 worker 日志). 初始 directive 后到无碍 — worker 首轮 check 才读取总线.
        # 总指挥不可用 (无 bus_dir / LLM 失败) → 自动降级回纯雁阵, 不影响主流程.
        commander_stop = threading.Event()
        want_commander = (self.commander_enabled if self.commander_enabled is not None
                          else self._commander_default_enabled())
        if want_commander and str(task.get("bus_dir") or "").strip():
            task = dict(task)
            # 乐观注入: 战略层启用总指挥协作 (初始化在后台完成, 失败时读空总线无害)
            task["commander_enabled"] = True
            self._commander_loops: list[threading.Thread] = []

            def _async_commander_setup() -> None:
                """后台初始化总指挥 (领题分工 LLM) + 启动事件驱动轮询."""
                try:
                    cmdr_info = self._setup_commander(task, on_commander=on_commander)
                except Exception as e:  # noqa: BLE001 - 总指挥失败降级雁阵
                    cmdr_info = None
                    if on_commander:
                        try:
                            on_commander(
                                "WARN", f"总指挥异步初始化异常: {type(e).__name__}: {e}")
                        except Exception:
                            pass
                if cmdr_info is not None:
                    cmdr, cbus, ckey = cmdr_info
                    loop = threading.Thread(
                        target=self._commander_loop,
                        args=(cmdr, cbus, ckey, commander_stop, on_commander),
                        daemon=True, name="commander-loop",
                    )
                    self._commander_loops.append(loop)
                    loop.start()

            threading.Thread(target=_async_commander_setup, daemon=True,
                             name="commander-init").start()

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
                agents[st] = self._run_one(st, t, f, max_seconds,
                                           on_step=on_step, on_log=on_log,
                                           on_coordinator=on_coordinator)

            th = threading.Thread(target=_worker, daemon=True)
            threads.append(th)
            th.start()

        # 修复: join 必须所有线程共享同一 deadline 并行等待
        # (旧实现逐个 join(timeout) 累计等待: 3 路 × 540s = 1620s,
        #  导致子进程早该被 kill 却拖到 N×timeout 才返回 "未及时 kill").
        deadline = time.monotonic() + max_seconds + 60
        for th in threads:
            th.join(timeout=max(0.0, deadline - time.monotonic()))
        # 到点: kill 进程树 (Windows 用 taskkill /T 杀孙子进程, 防 readline 残留阻塞)
        for p in self._procs.values():
            if p.poll() is None:
                try:
                    self._kill_tree(p)
                except Exception:
                    pass
        for th in threads:
            th.join(timeout=5)
        # 停止总指挥后台轮询
        commander_stop.set()
        for ct in getattr(self, "_commander_loops", []):
            ct.join(timeout=3)

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
    