"""CTF-agent 独立求解入口（调用器协议）.

本模块是 CTF-agent 对外的稳定调用契约：任何"应用/调用器"（如 NSS Runner）
只需以子进程方式运行本入口，即可完成一次完整的 CTF 题目求解，
无需改动 ctf_agent 的任何内部源码。

用法:
    python -u -m ctf_agent.solve --task-file <path>
    (-u 强制 unbuffered, 确保实时输出)

输入 (task JSON, 见 readme):
    {
      "challenge_id": "nss_2314",   // 题目 ID
      "title": "题目名",
      "desc": "任务描述 (题面+附件路径+靶机URL+规则)",
      "type": "web",                // 题型
      "difficulty": "easy",         // 难度
      "max_steps": 0,               // 0=自适应
      "max_seconds": 1500.0,        // 熔断时间
      "retry_hint": "",             // 重试提示
      "force_max_thinking": false,  // Sprint 26: 强制 max 思考强度
      "max_submissions": 1,         // Sprint 26: 单轮最大提交次数
    }

输出 (stdout JSON Lines, 每行一个对象):
    {"type":"start","protocol_version":"1.1","challenge_id":...}     // 启动信息
    {"type":"log","level":"INFO","message":...}                      // 日志
    {"type":"step","step_no":N,"thought":...,"action":...,...}       // 每步记录
    {"type":"heartbeat","elapsed":N,"step":N,"phase":"..."}          // 心跳 (每15s)
    {"type":"submission","flag":...}                                  // flag 提交请求
    {"type":"result","success":bool,"flag":...,...}                  // 最终结果

输入 (stdin JSON Lines, 调用器 → agent):
    {"correct":bool,"feedback":"..."}                                // submission 结果
    {"control":"stop"}                                               // 停止信号

设计原则:
    - 不改动 ctf_agent 任何现有源码, 仅复用其公开 API
    - stdout 只输出 JSONL; 第三方库的 print 会被包装成 log 行
    - 经验/技能/记忆/自学习全部在 agent 侧完成, 全局共享
    - 无内部超时线程: 子进程模型下, 调用器负责硬超时 kill
    - Sprint 26: 协议版本 1.1, 新增 heartbeat/submission/control
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from ctf_agent.agent.react import ReActEngine, ReActResult
from ctf_agent.config import get_settings
from ctf_agent.llm.routed import RoutedLLMClient
from ctf_agent.memory.skill_library import SkillLibrary
from ctf_agent.orchestrator.adaptive import AdaptiveBreaker
from ctf_agent.ssh import ssh_client_from_settings
from ctf_agent.tools import default_tools


# ── 协议输出 ──────────────────────────────────────────────────

PROTOCOL_VERSION = "1.1"  # Sprint 26: 协议版本化

# 强制 unbuffered: 解决 Python 文本模式 bufsize=1 无效的实时性问题
# (Python 文档: bufsize=1 行缓冲只在二进制模式下生效, 文本模式被忽略)
os.environ.setdefault("PYTHONUNBUFFERED", "1")

class _ProtocolStdout:
    """stdout 包装器: 第三方 print() 转为 log 行, 保证 JSONL 协议不被污染.

    协议行 (start/log/step/heartbeat/submission/result) 通过 _out() 直接写底层 fd;
    其它库意外 print() 的内容会被包装为 {"type":"log"} 输出.
    """

    def __init__(self, real) -> None:
        self._real = real
        self.encoding = getattr(real, "encoding", "utf-8")
        # 强制行缓冲 (Sprint 26: 解决实时性问题)
        try:
            real.reconfigure(line_buffering=True)
        except Exception:
            pass

    def write(self, s: str) -> int:
        s = str(s)
        if s.strip():
            _out({"type": "log", "level": "RAW", "message": s.rstrip()})
        return len(s)

    def flush(self) -> None:
        self._real.flush()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


_real_stdout: Any = sys.stdout

# Sprint 26: 强制 unbuffered
try:
    _real_stdout.reconfigure(line_buffering=True)
except Exception:
    pass


def _out(obj: dict[str, Any]) -> None:
    """输出一行 JSONL 协议 (直接写底层 stdout, 立即 flush)."""
    try:
        _real_stdout.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
        _real_stdout.flush()
    except Exception:
        pass


def _log(level: str, message: str) -> None:
    _out({"type": "log", "level": level, "message": message})


# ── 心跳机制 (Sprint 26) ──────────────────────────────────────
# 每 15s 输出 heartbeat 行, 让调用器知道 agent 还活着
# 解决: 长时间 LLM 推理期间无输出, 调用器无法区分"agent 卡住"与"正在思考"

_heartbeat_started = False
_heartbeat_step = 0
_heartbeat_phase = "init"
_heartbeat_start_time = 0.0


def _start_heartbeat() -> None:
    """启动心跳线程 (daemon, 每 15s 输出一次)."""
    global _heartbeat_started, _heartbeat_start_time
    if _heartbeat_started:
        return
    _heartbeat_started = True
    _heartbeat_start_time = time.monotonic()

    def _beat() -> None:
        while True:
            time.sleep(15)
            elapsed = time.monotonic() - _heartbeat_start_time
            _out({
                "type": "heartbeat",
                "elapsed": round(elapsed, 1),
                "step": _heartbeat_step,
                "phase": _heartbeat_phase,
            })

    t = threading.Thread(target=_beat, daemon=True, name="heartbeat")
    t.start()


def _set_heartbeat(step: int, phase: str) -> None:
    """更新心跳状态 (由 ReAct 引擎每步调用)."""
    global _heartbeat_step, _heartbeat_phase
    _heartbeat_step = step
    _heartbeat_phase = phase


# ── stdin 统一分发器 (Sprint 30) ──────────────────────────────
# 解决: stop-listener 和 submission-handler 竞争 stdin 的问题.
# 原设计: 两个线程各自 readline(sys.stdin), stop-listener 可能吞掉
#         submission 响应 {"correct":true}, 导致 agent 误以为提交失败.
#
# 新设计: 一个专用线程统一读取所有 stdin 输入, 按消息类型分发:
#   {"control":"stop"}        → 设置 stop 标志
#   {"correct":...,"feedback":...} → 放入 submission 响应队列
# 同时解决 Windows 上 selectors 不能注册 stdin 的问题 (WinError 10038).

from ctf_agent.stop_signal import request_stop as _signal_request_stop

import queue as _queue

_stdin_dispatcher_started = False
_submission_queue: _queue.Queue = _queue.Queue()


def _is_stop_requested() -> bool:
    """检查是否收到 stop 信号 (供 ReActEngine 每步调用)."""
    from ctf_agent.stop_signal import is_stop_requested
    return is_stop_requested()


def _start_stdin_dispatcher() -> None:
    """启动 stdin 统一分发线程 (daemon).

    所有 stdin 输入由一个线程读取, 按消息类型分发到 stop 标志或 submission 队列.
    避免 stop-listener 和 submission-handler 竞争 stdin.
    """
    global _stdin_dispatcher_started
    if _stdin_dispatcher_started:
        return
    _stdin_dispatcher_started = True

    def _dispatch() -> None:
        try:
            while True:
                line = sys.stdin.readline()
                if not line:
                    break  # stdin EOF (调用器关闭)
                try:
                    obj = json.loads(line.strip())
                    if obj.get("control") == "stop":
                        _signal_request_stop()
                        _log("WARN", "收到调用器 stop 信号, agent 将在当前步完成后停止")
                        # 也放入队列, 让正在等待的 submission_handler 能退出
                        _submission_queue.put({"control": "stop"})
                        break
                    elif "correct" in obj:
                        # submission 响应, 放入队列
                        _submission_queue.put(obj)
                    else:
                        # 未知消息, 忽略
                        pass
                except Exception:
                    pass  # 非 JSON 行, 忽略
        except Exception:
            pass  # stdin 异常 (如非交互模式), 静默退出

    t = threading.Thread(target=_dispatch, daemon=True, name="stdin-dispatcher")
    t.start()


# ── flag 提取 (agent 侧知识) ─────────────────────────────────

_FLAG_PATTERNS = [
    re.compile(r"\bNSSCTF\{[^}]+\}", re.IGNORECASE),
    re.compile(r"\bmoectf\{[^}]+\}", re.IGNORECASE),
    re.compile(r"\bflag\{[^}]+\}", re.IGNORECASE),
    re.compile(r"\bCTF\{[^}]+\}", re.IGNORECASE),
    re.compile(r"\bnssctf\{[^}]+\}", re.IGNORECASE),
    re.compile(r"\bathena\{[^}]+\}", re.IGNORECASE),
    re.compile(r"\b([a-zA-Z_]+)\{([a-zA-Z0-9_!@#$%^&*\-+.=:?]{4,})\}"),
]


def _extract_flag(text: str) -> str:
    """从最终答案文本中提取 flag."""
    if not text:
        return ""
    for pat in _FLAG_PATTERNS[:4]:
        m = pat.search(text)
        if m:
            return m.group(0).strip()
    m = _FLAG_PATTERNS[-1].search(text)
    if m:
        return m.group(0).strip()
    text = text.strip()
    if "{" in text and "}" in text and len(text) < 200:
        return text
    return ""


# ── 求解流程 ──────────────────────────────────────────────────

def _make_on_step() -> Any:
    """构造 ReActEngine.on_step 回调: 每步输出 step JSONL + 更新心跳."""
    def on_step(step: Any) -> None:
        step_no = getattr(step, "step_no", 0)
        action = getattr(step, "action", "") or ""
        # 更新心跳状态 (让 heartbeat 线程知道当前进度)
        phase = action if action else "thinking"
        _set_heartbeat(step_no, phase)
        _out({
            "type": "step",
            "step_no": step_no,
            "thought": getattr(step, "thought", "") or "",
            "action": action,
            "action_input": getattr(step, "action_input", "") or "",
            "observation": getattr(step, "observation", "") or "",
            "is_error": bool(getattr(step, "is_error", False)),
            "is_final": bool(getattr(step, "is_final", False)),
            "final_answer": getattr(step, "final_answer", "") or "",
            "error_msg": getattr(step, "error_msg", "") or "",
            "timestamp": getattr(step, "timestamp", 0),
        })
    return on_step


def _make_submission_handler() -> Any:
    """Sprint 26/30: 构造 submission_handler 回调 (从队列读取响应, 无 stdin 竞争).

    机制: agent 找到候选 flag 后调用本回调:
      1. 向 stdout 输出 {"type":"submission","flag":...} JSONL 行
      2. 从 _submission_queue 读取调用器的响应 (60s 超时)
      3. 返回 (correct, feedback) 给 ReActEngine
      4. 如果收到 stop 信号, 返回失败并标记停止

    Sprint 30 修复: 不再用 selectors 直接读 stdin (会与 stop-listener 竞争,
    且 Windows 上 selectors 不支持 stdin 导致 WinError 10038).
    改为从 _submission_queue 读取, 由 stdin 统一分发器放入.
    """
    def handler(flag: str) -> tuple[bool, str]:
        _out({"type": "submission", "flag": flag})
        try:
            # 从队列读取 (60s 超时, 防止调用器崩溃时 agent 永久挂起)
            result = _submission_queue.get(timeout=60.0)
            # 检查 stop 信号
            if result.get("control") == "stop":
                _signal_request_stop()
                return False, "调用器发送了停止信号"
            return bool(result.get("correct", False)), str(result.get("feedback", ""))
        except _queue.Empty:
            _log("WARN", "submission 等待调用器响应超时 (60s), 自动失败")
            return False, "调用器响应超时 (60s), 请重新分析并提交不同答案"
    return handler


def _build_engine_with_timeout(task: dict[str, Any], settings: Any, timeout: float = 150.0):
    """构造引擎, 但 SSH 连接等初始化放在子线程, 超时则快速失败.

    背景 (Sprint 21 复盘 #2314): 无防护时 SSH 连接挂起会让 agent 进程
    全程无输出, 调用器只能等满 max_seconds 再 kill, 白白浪费整题时间.
    这里 150s 超时后抛 TimeoutError, solve_task 会输出 result 快速失败.
    """
    import threading

    holder: dict[str, Any] = {}

    def _worker() -> None:
        try:
            engine, ms = _build_engine(task, settings)
            holder["ok"] = (engine, ms)
        except Exception as e:  # noqa: BLE001
            holder["err"] = e

    t = threading.Thread(target=_worker, daemon=True, name="engine-init")
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError(f"engine init timeout ({timeout:.0f}s, 可能 SSH 连接挂起)")
    if "err" in holder:
        raise holder["err"]
    return holder["ok"]


def _build_engine(task: dict[str, Any], settings: Any):
    """构造 ReAct 引擎 (复用 agent 公开 API)."""
    ctype = str(task.get("type") or "misc").lower().strip()
    difficulty = str(task.get("difficulty") or "").lower().strip()

    # SSH 沙箱 (从 .env 配置, 全局共享)
    ssh = ssh_client_from_settings(settings)
    ssh.connect_timeout = 60
    ssh.connect()

    llm = RoutedLLMClient(settings=settings)
    # Sprint 32.5: 应用 controller 领题前的冒烟测试标记,
    # 快速跳过不可用 provider, 避免 45s*3 超时重试浪费时间
    try:
        llm.apply_smoke_from_file(str(_PROJECT_ROOT / "data" / "api_smoke.json"))
    except Exception:
        pass
    # NSS 等竞赛场景: 禁用本地靶场控制 (range_control) —— 任务描述已禁止,
    # 工具层面直接不提供, 杜绝 agent 误用本地靶场
    tools = default_tools(ssh_client=ssh, enable_range=False)

    # 熔断器: 按题型+难度自适应 (与独立运行保持一致)
    max_seconds = float(task.get("max_seconds") or 1800.0)
    breaker = AdaptiveBreaker(
        challenge_type=ctype or None,
        challenge_difficulty=difficulty or None,
        max_seconds=max_seconds,
        max_cost_usd=1.5,
    )
    max_steps = int(task.get("max_steps") or 0)
    if max_steps <= 0:
        max_steps = breaker._dynamic_max_steps

    # Sprint 26: 多次提交机制 — task JSON 配置 max_submissions
    # max_submissions=1 (默认) = 传统单次提交模式; >1 = 多次提交模式
    max_submissions = int(task.get("max_submissions") or 1)

    # Sprint 22.5: Skill 库 (自学习积累的套路), 同一实例传给 engine 和 coordinator
    skill_library = SkillLibrary()

    # Sprint 27: 长期记忆 (RAG), 供巡查指导器查询历史 writeup
    # 失败时静默降级为 None (coordinator 走纯规则预检)
    long_term = None
    try:
        from ctf_agent.memory import LongTermMemory
        long_term = LongTermMemory(chroma_path=settings.chroma_path)
    except Exception:
        long_term = None

    engine = ReActEngine(
        llm=llm,
        tools=tools,
        max_steps=max_steps,
        model=settings.executor_model,
        temperature=0.0,
        challenge_id=str(task.get("challenge_id") or ""),
        challenge_type=ctype or None,
        challenge_difficulty=difficulty or None,
        breaker=breaker,
        on_step=_make_on_step(),
        # Sprint 22.5: 接入 Skill 库 — 自学习积累的套路要能注入解题 prompt
        skill_library=skill_library,
        # Sprint 26: 重试时强制 max 思考强度 (NSS Runner retry_hint 非空时设置)
        force_max_thinking=bool(task.get("force_max_thinking", False)),
        # Sprint 26: 多次提交机制 (max_submissions>1 时启用)
        submission_handler=_make_submission_handler() if max_submissions > 1 else None,
        max_submissions=max_submissions,
        # Sprint 27: 巡查指导器 — LLM 驱动的智能旁观者, 查询知识库辅助判断
        coordinator=_make_coordinator(llm, skill_library, long_term),
        # Sprint 29: 巡查日志回调 (输出 coordinator JSONL, 便于观察巡查行为)
        on_coordinator=_make_on_coordinator(),
    )
    return engine, max_steps


def _make_coordinator(llm: Any = None, skill_library: Any = None, long_term: Any = None) -> Any:
    """Sprint 27: 创建巡查指导器 (LLM 驱动的智能旁观者).

    Args:
        llm: LLM 客户端 (用于深度分析, None 时降级为纯规则预检)
        skill_library: Skill 库 (查询匹配的解题套路)
        long_term: RAG 长期记忆 (查询历史 writeup)
    """
    from ctf_agent.agent.coordinator import Coordinator
    return Coordinator(
        llm=llm,
        skill_library=skill_library,
        long_term=long_term,
        check_interval=10,  # Sprint 32.4c: 15→10, 落实"10 轮 1 巡查" (之前硬编码 15 覆盖默认值)
        first_check=10,
        lookback=10,
    )


def _make_on_coordinator() -> Any:
    """Sprint 29: 构造巡查日志回调, 输出 coordinator JSONL 行.

    每次巡查后调用, 输出 {"type":"coordinator", ...} 让调用器能观察巡查行为.
    """
    def on_coordinator(guidance: Any, step_no: int) -> None:
        _out({
            "type": "coordinator",
            "step_no": step_no,
            "should_intervene": bool(getattr(guidance, "should_intervene", False)),
            "priority": getattr(guidance, "priority", "SHOULD"),
            "reason": getattr(guidance, "reason", "") or "",
            "guidance": getattr(guidance, "guidance", "") or "",
            "extend_steps": bool(getattr(guidance, "extend_steps", False)),
            "detected_issues": list(getattr(guidance, "detected_issues", []) or []),
            "forbidden_actions": list(getattr(guidance, "forbidden_actions", []) or []),
            "revert_guidance": bool(getattr(guidance, "revert_guidance", False)),
            "remove_forbidden": list(getattr(guidance, "remove_forbidden", []) or []),
            "analysis_summary": getattr(guidance, "analysis_summary", "") or "",
            # Sprint 32.7: 透传推论分级 + 反思 (供调用器完整日志显示)
            "reflection": getattr(guidance, "reflection", "") or "",
            "belief_state": list(getattr(guidance, "belief_state", []) or []),
        })
    return on_coordinator


def _learn(result: ReActResult, task: dict[str, Any], desc: str) -> None:
    """自学习: 从本轮结果提炼 Skill (成功→套路, 失败→避坑)."""
    try:
        from ctf_agent.memory.skill_library import SkillLibrary
        from ctf_agent.skill_learner import learn_skill

        ctype = str(task.get("type") or "misc").lower().strip()
        difficulty = str(task.get("difficulty") or "").lower().strip()
        skill = learn_skill(
            task=desc,
            result=result,
            library=SkillLibrary(),
            challenge_type=ctype or "misc",
            difficulty=difficulty,
            llm=None,       # 模板生成, 不调 LLM (省 token)
            use_llm=False,
        )
        if skill:
            tag = "套路" if result.success else "避坑"
            _log("INFO", f"自学习: 生成{tag} Skill [{skill.title}] (category={ctype or 'misc'})")
        else:
            _log("INFO", f"自学习: 信息不足, 未生成 Skill (steps={result.step_count})")
    except Exception as e:  # noqa: BLE001 - 自学习失败不影响主流程
        _log("WARN", f"自学习失败: {e}")


def solve_task(task: dict[str, Any]) -> int:
    """执行一次求解 (返回进程退出码)."""
    # Sprint 26: 重置 stop 信号 (新任务开始)
    from ctf_agent.stop_signal import reset as _reset_stop
    _reset_stop()

    desc = str(task.get("desc") or "")
    retry_hint = str(task.get("retry_hint") or "")
    if retry_hint:
        desc = f"{desc}\n\n=== 重试提示 ===\n{retry_hint}\n请仔细重新分析, 不要重复之前的错误."

    settings = get_settings()
    if not settings.has_llm_config():
        _log("ERROR", "LLM API Key 未配置, 无法求解")
        _out({"type": "result", "success": False,
              "flag": "", "fail_reason": "llm not configured",
              "steps": 0, "elapsed": 0.0, "tokens": 0,
              "model": settings.executor_model})
        return 1

    started = time.monotonic()

    try:
        # 引擎构造含 SSH 连接, 可能挂起 (DNS/网络), 用线程超时兜底:
        # 避免 agent 进程无任何输出 (连 start 都没有) 被调用器硬超时 kill 浪费整题时间
        engine, max_steps = _build_engine_with_timeout(task, settings, timeout=150.0)
        _log("INFO", f"求解启动: {task.get('challenge_id', '')} "
                     f"type={task.get('type', '?')} difficulty={task.get('difficulty', '?')} "
                     f"max_steps={max_steps} model={settings.executor_model}")
        _out({"type": "start",
              "protocol_version": PROTOCOL_VERSION,  # Sprint 26: 协议版本
              "challenge_id": task.get("challenge_id", ""),
              "title": task.get("title", ""),
              "challenge_type": task.get("type", ""),
              "difficulty": task.get("difficulty", ""),
              "max_steps": max_steps,
              "max_seconds": float(task.get("max_seconds") or 0),
              "max_submissions": int(task.get("max_submissions") or 1),  # Sprint 26
              "model": settings.executor_model})
        # Sprint 26: 启动心跳 (引擎构造成功后)
        _start_heartbeat()
        # Sprint 30: 启动 stdin 统一分发器 (替代 stop-listener, 避免与 submission-handler 竞争)
        _start_stdin_dispatcher()
    except Exception as e:  # noqa: BLE001 - 引擎构造失败
        _log("ERROR", f"引擎构造失败: {type(e).__name__}: {e}")
        _out({"type": "result", "success": False,
              "flag": "", "fail_reason": f"engine init: {type(e).__name__}: {e}",
              "steps": 0, "elapsed": time.monotonic() - started,
              "tokens": 0, "model": settings.executor_model})
        return 1

    try:
        result = engine.run(desc)
        elapsed = time.monotonic() - started
    except Exception as e:  # noqa: BLE001 - 运行异常兜底
        _log("ERROR", f"求解异常: {type(e).__name__}: {e}")
        _out({"type": "result", "success": False,
              "flag": "", "fail_reason": f"engine run: {type(e).__name__}: {e}",
              "steps": 0, "elapsed": time.monotonic() - started,
              "tokens": 0, "model": settings.executor_model})
        return 1

    # 自学习 (全局共享经验)
    _learn(result, task, desc)

    # 结果
    flag = _extract_flag(result.final_answer or "") if result.success else ""
    _log("RESULT", f"求解完成: success={result.success}, steps={result.step_count}, "
                   f"elapsed={elapsed:.0f}s, tokens={result.total_tokens}, "
                   f"flag={'找到' if flag else '未找到'}")
    _out({"type": "result",
          "success": bool(result.success),
          "flag": flag,
          "final_answer": (result.final_answer or "")[:500],
          "fail_reason": result.fail_reason or "",
          "steps": result.step_count,
          "elapsed": round(elapsed, 1),
          "tokens": result.total_tokens,
          "model": settings.executor_model})
    return 0


def main(argv: list[str] | None = None) -> int:
    """入口: python -m ctf_agent.solve --task-file <path>."""
    global _real_stdout
    parser = argparse.ArgumentParser(description="CTF-agent 独立求解入口")
    parser.add_argument("--task-file", required=True, help="task JSON 文件路径")
    args = parser.parse_args(argv)

    task_path = Path(args.task_file)
    if not task_path.exists():
        print(f"task 文件不存在: {task_path}", file=sys.stderr)
        return 1
    try:
        task = json.loads(task_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"task 文件解析失败: {e}", file=sys.stderr)
        return 1
    if not isinstance(task, dict):
        print("task 必须是 JSON 对象", file=sys.stderr)
        return 1

    # 保护协议: 第三方 print() 转为 log 行
    _real_stdout = sys.stdout
    sys.stdout = _ProtocolStdout(_real_stdout)

    return solve_task(task)


if __name__ == "__main__":
    sys.exit(main())
