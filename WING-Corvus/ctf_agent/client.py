"""AgentClient SDK (Sprint 26): 统一的 CTF-Agent 调用接口.

封装子进程管理 + JSONL 协议解析 + 双向通信, 让任何调用方 (NSS Runner /
测试中继 / 第三方应用) 都能用 3 行代码接入 CTF-Agent.

用法 (最简):
    from ctf_agent.client import AgentClient, AgentCallbacks

    client = AgentClient(project_root=".")
    result = client.solve(task_file="task.json", callbacks=AgentCallbacks(
        on_submission=lambda flag: (flag == "CTF{expected}", "正确!"),
    ))

用法 (带实时日志):
    class MyCallbacks(AgentCallbacks):
        def on_step(self, step): print(f"Step {step['step_no']}: {step['action']}")
        def on_heartbeat(self, hb): print(f"  [{hb['elapsed']}s] step={hb['step']} {hb['phase']}")
        def on_submission(self, flag): return True, "正确!"
        def on_log(self, level, msg): print(f"[{level}] {msg}")

    client = AgentClient(project_root=".")
    result = client.solve(task_file="task.json", callbacks=MyCallbacks())

设计原则:
  - 零依赖 (仅标准库 subprocess/json/threading)
  - 协议版本兼容 (自动检测 protocol_version)
  - 实时输出 (subprocess 用 readline 而非迭代器, 避免 Python 缓冲)
  - 双向通信 (submission 回调 + stop 信号)
  - 可拓展 (子类化 AgentCallbacks 添加自定义行为)
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


@dataclass
class AgentCallbacks:
    """调用方回调接口 — 按需实现任意方法, 未实现的方法会被忽略.

    on_submission 是多次提交机制的核心: 返回 (is_correct, feedback),
    AgentClient 会自动通过 stdin 将结果返回给 agent.
    """
    on_start: Callable[[dict], None] | None = None
    on_step: Callable[[dict], None] | None = None
    on_heartbeat: Callable[[dict], None] | None = None
    on_log: Callable[[str, str], None] | None = None
    on_submission: Callable[[str], tuple[bool, str]] | None = None
    on_result: Callable[[dict], None] | None = None
    on_proc: Callable[[subprocess.Popen], None] | None = None  # WING-Goose: 子进程注册 (swarm 杀兄弟用)
    # Sprint 36 (WING-Corvus): 完整巡查/总指挥消息透传 (含 belief_state/reflection/
    # commander 战略层详情). on_log 只转发摘要, 需要完整详情 (写文件复盘) 的调用方订阅此回调.
    on_coordinator: Callable[[dict], None] | None = None


@dataclass
class AgentResult:
    """agent 求解结果."""
    success: bool = False
    flag: str = ""
    steps: int = 0
    elapsed: float = 0.0
    tokens: int = 0
    model: str = ""
    fail_reason: str = ""
    submissions: list[dict] = field(default_factory=list)
    trajectory: list[dict] = field(default_factory=list)
    raw_result: dict | None = None


class AgentClient:
    """CTF-Agent 统一调用客户端.

    封装子进程管理 + JSONL 协议 + 双向通信, 供 NSS Runner / 测试中继等使用.
    """

    def __init__(
        self,
        project_root: str | Path = ".",
        python_executable: str | None = None,
    ) -> None:
        """
        Args:
            project_root: CTF-Agent 项目根目录 (含 ctf_agent 包)
            python_executable: Python 解释器路径 (默认 sys.executable)
        """
        self.project_root = Path(project_root).resolve()
        self.python = python_executable or sys.executable

    def solve(
        self,
        task_file: str | Path,
        callbacks: AgentCallbacks | None = None,
        max_seconds: float = 1800,
        max_submissions: int = 1,
    ) -> AgentResult:
        """启动 agent 子进程求解.

        Args:
            task_file: task JSON 文件路径
            callbacks: 回调接口 (on_step/on_heartbeat/on_submission 等)
            max_seconds: 硬超时 (秒), 超时后 kill 子进程
            max_submissions: 单轮最大提交次数 (>1 启用多次提交)

        Returns:
            AgentResult
        """
        callbacks = callbacks or AgentCallbacks()
        task_file = Path(task_file)

        # 如果需要多次提交, 修改 task JSON
        actual_task_file = task_file
        if max_submissions > 1:
            task = json.loads(task_file.read_text(encoding="utf-8"))
            task["max_submissions"] = max_submissions
            actual_task_file = task_file.parent / f"{task_file.stem}_multi.json"
            actual_task_file.write_text(
                json.dumps(task, ensure_ascii=False, indent=2), encoding="utf-8"
            )

        cmd = [
            self.python, "-u",  # -u: 强制 unbuffered (Sprint 26 实时性)
            "-m", "ctf_agent.solve",
            "--task-file", str(actual_task_file),
        ]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,   # 用于 submission 双向通信
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            cwd=str(self.project_root),
            env={**__import__("os").environ, "PYTHONUNBUFFERED": "1"},
        )
        # WING-Goose: 注册子进程句柄, 供 swarm 编排层"一解出即杀其余"使用
        if callbacks.on_proc:
            try:
                callbacks.on_proc(proc)
            except Exception:
                pass

        result = AgentResult()
        submissions: list[dict] = []

        def _log(msg: str) -> None:
            if callbacks.on_log:
                callbacks.on_log("INFO", msg)

        # Sprint 36.1: 无进度 watchdog — 子进程卡住 (LLM 挂起/工具阻塞) 时,
        # readline() 会无限阻塞, max_seconds 形同虚设 (根因: swarm 模式无
        # no_progress 兜底, 3 路共享 go provider 变慢时日志全停 → 用户感知"卡死").
        # watchdog 监控任何非 heartbeat 消息进度, 超时 kill 进程树 (含 docker/ssh
        # 孙进程, 否则 stdout 管道被孙进程持有, readline 仍阻塞) → EOF → 循环退出.
        last_progress = [time.monotonic()]
        no_progress_timeout = max(300.0, min(max_seconds * 0.5, 600.0))  # 5-10 分钟

        def _kill_tree(p) -> None:
            """杀进程树 (Windows taskkill /T 连带 docker exec/ssh 孙进程)."""
            import os

            if os.name == "nt":
                try:
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)],
                                   capture_output=True, timeout=10)
                    return
                except Exception:
                    pass
            p.kill()

        def _watchdog() -> None:
            started = time.monotonic()
            while True:
                time.sleep(10)
                try:
                    if proc.poll() is not None:
                        return  # 子进程已退出
                    now = time.monotonic()
                    if now - last_progress[0] > no_progress_timeout:
                        _log(f"agent 无进度 {no_progress_timeout:.0f}s (心跳正常但无输出), kill 子进程")
                        _kill_tree(proc)
                        return
                    if now - started > max_seconds:
                        _log(f"agent 超时 ({max_seconds:.0f}s), kill 子进程")
                        _kill_tree(proc)
                        return
                except Exception:
                    pass

        threading.Thread(target=_watchdog, daemon=True,
                         name="agent-watchdog").start()

        try:
            assert proc.stdout is not None
            # 用 readline 而非 for line in (避免 Python 缓冲, 确保实时性)
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue

                try:
                    obj = json.loads(line)
                except Exception:
                    if callbacks.on_log:
                        callbacks.on_log("WARN", f"非JSON输出: {line[:100]}")
                    continue

                msg_type = obj.get("type", "")
                # 心跳不算进度 (15s 一次, 卡在长工具调用时仍在发, 不能当进展)
                if msg_type != "heartbeat":
                    last_progress[0] = time.monotonic()

                if msg_type == "start":
                    if callbacks.on_start:
                        callbacks.on_start(obj)

                elif msg_type == "step":
                    result.trajectory.append(obj)
                    if callbacks.on_step:
                        callbacks.on_step(obj)

                elif msg_type == "heartbeat":
                    if callbacks.on_heartbeat:
                        callbacks.on_heartbeat(obj)

                elif msg_type == "coordinator":
                    # WING-Goose: 巡查指导器消息 — 通用转发为 COORD 日志.
                    # 不解析具体字段 (保持 SDK 通用性), 构造可读摘要供调用方显示.
                    # Sprint 36: 同时透传完整 dict 给 on_coordinator (如调用方订阅),
                    # 供文件日志记录 belief_state/reflection 等完整详情.
                    if callbacks.on_coordinator:
                        try:
                            callbacks.on_coordinator(obj)
                        except Exception:
                            pass
                    if callbacks.on_log:
                        step_no = obj.get("step_no", "?")
                        intervene = obj.get("should_intervene", False)
                        summary = obj.get("analysis_summary") or ""
                        if intervene:
                            tag = "[MUST]" if obj.get("priority") == "MUST" else "[SHOULD]"
                            guidance = obj.get("guidance") or ""
                            callbacks.on_log("COORD",
                                             f"巡查 step={step_no} [干预]{tag}: {summary} | {guidance}")
                        else:
                            callbacks.on_log("COORD", f"巡查 step={step_no} [沉默]: {summary}")

                elif msg_type == "log":
                    if callbacks.on_log:
                        callbacks.on_log(obj.get("level", "INFO"), obj.get("message", ""))

                elif msg_type == "submission":
                    flag = obj.get("flag", "")
                    submissions.append(obj)
                    # 调用 callback 提交 flag
                    if callbacks.on_submission:
                        try:
                            is_correct, feedback = callbacks.on_submission(flag)
                        except Exception as e:
                            is_correct, feedback = False, f"提交异常: {e}"
                    else:
                        is_correct, feedback = False, "未配置 on_submission 回调"
                    # 通过 stdin 返回结果
                    response = json.dumps({"correct": is_correct, "feedback": feedback})
                    try:
                        assert proc.stdin is not None
                        proc.stdin.write(response + "\n")
                        proc.stdin.flush()
                    except Exception:
                        pass

                elif msg_type == "result":
                    result.raw_result = obj
                    result.success = obj.get("success", False)
                    result.flag = obj.get("flag", "")
                    result.steps = obj.get("steps", 0)
                    result.elapsed = obj.get("elapsed", 0.0)
                    result.tokens = obj.get("tokens", 0)
                    result.model = obj.get("model", "")
                    result.fail_reason = obj.get("fail_reason", "")
                    result.submissions = submissions
                    if callbacks.on_result:
                        callbacks.on_result(obj)
                    break

        except Exception as e:
            _log(f"AgentClient 异常: {e}")
        finally:
            # 超时或结束后清理
            if proc.poll() is None:
                proc.kill()
            try:
                if proc.stdin:
                    proc.stdin.close()
            except Exception:
                pass

            # 残余 stderr
            try:
                err = proc.stderr.read() if proc.stderr else ""
                if err and err.strip() and callbacks.on_log:
                    callbacks.on_log("WARN", f"agent stderr: {err.strip()[:300]}")
            except Exception:
                pass

            # 清理临时 task 文件
            if max_submissions > 1 and actual_task_file != task_file:
                try:
                    actual_task_file.unlink()
                except Exception:
                    pass

        return result

    def stop(self, proc: subprocess.Popen) -> None:
        """向 agent 发送 stop 信号 (通过 stdin)."""
        try:
            assert proc.stdin is not None
            proc.stdin.write(json.dumps({"control": "stop"}) + "\n")
            proc.stdin.flush()
        except Exception:
            pass
