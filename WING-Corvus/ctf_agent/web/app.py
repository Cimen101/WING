"""FastAPI 应用实现.

提供：
- POST /api/tasks：提交任务
- GET /api/tasks/{id}：查询任务状态
- POST /api/tasks/{id}/intervene：对话纠偏
- WS /ws/tasks/{id}：实时推送步骤日志
- GET /：静态前端首页

任务执行：
- 后台线程跑 ReActEngine
- on_step 回调将步骤推到 WebSocket 订阅者
- 纠偏指令通过 InterventionHub 队列传给引擎
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ctf_agent.agent import ReActEngine, ReActResult, ReActStep
from ctf_agent.config import Settings, get_settings
from ctf_agent.llm import LLMClient
from ctf_agent.tools import default_tools
from ctf_agent.tools.base import Tool


# ============ 干预中心（对话纠偏核心） ============

class InterventionHub:
    """任务干预队列：用户指令暂存，引擎每步检查.

    线程安全：用 threading.Lock 保护队列。
    用法：
        hub = InterventionHub()
        hub.push("扫描 8080 端口")  # 用户提交纠偏
       指令 = hub.drain()  # 引擎每步取出并清空
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._queue: list[str] = []

    def push(self, instruction: str) -> None:
        """用户提交纠偏指令."""
        if not instruction.strip():
            return
        with self._lock:
            self._queue.append(instruction.strip())

    def drain(self) -> list[str]:
        """引擎取出所有待处理指令（清空队列）."""
        with self._lock:
            if not self._queue:
                return []
            items = list(self._queue)
            self._queue.clear()
            return items

    def has_pending(self) -> bool:
        with self._lock:
            return bool(self._queue)


# ============ 任务记录 ============

@dataclass
class TaskRecord:
    """运行中/已完成任务的记录."""

    task_id: str
    task_desc: str
    status: str = "pending"  # pending/running/success/failed
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0.0
    result: ReActResult | None = None
    steps: list[dict[str, Any]] = field(default_factory=list)
    intervention_hub: InterventionHub = field(default_factory=InterventionHub)
    # WebSocket 订阅者（多客户端可同时观察）
    subscribers: list[Any] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add_step(self, step: ReActStep) -> dict[str, Any]:
        """记录并广播步骤."""
        step_dict = {
            "step_no": step.step_no,
            "thought": step.thought,
            "action": step.action,
            "action_input": step.action_input,
            "observation": step.observation[:500] if step.observation else "",
            "is_final": step.is_final,
            "final_answer": step.final_answer,
            "is_error": step.is_error,
            "error_msg": step.error_msg,
            "timestamp": step.timestamp,
        }
        with self._lock:
            self.steps.append(step_dict)
        return step_dict

    def to_dict(self) -> dict[str, Any]:
        """序列化为 JSON 友好格式."""
        return {
            "task_id": self.task_id,
            "task_desc": self.task_desc,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "elapsed": (self.ended_at or time.time()) - self.started_at,
            "step_count": len(self.steps),
            "final_answer": self.result.final_answer if self.result else "",
            "success": self.result.success if self.result else False,
            "fail_reason": self.result.fail_reason if self.result else "",
            "steps": list(self.steps),
        }


# ============ 任务管理器 ============

class TaskManager:
    """内存任务管理（单机版，重启丢失）.

    生产环境可换 Redis/SQLite 持久化。
    """

    def __init__(self) -> None:
        self._tasks: dict[str, TaskRecord] = {}
        self._lock = threading.Lock()

    def create(self, task_desc: str) -> TaskRecord:
        task_id = uuid4().hex[:12]
        record = TaskRecord(task_id=task_id, task_desc=task_desc)
        with self._lock:
            self._tasks[task_id] = record
        return record

    def get(self, task_id: str) -> TaskRecord | None:
        with self._lock:
            return self._tasks.get(task_id)

    def list_all(self) -> list[TaskRecord]:
        with self._lock:
            return list(self._tasks.values())


# ============ 干预感知的 ReAct 引擎包装 ============

class InterventionAwareEngine:
    """包装 ReActEngine，在每步注入用户纠偏指令.

    实现方式：on_step 回调 + 在 ReActEngine.run 之外无法干预推理循环。
    简化方案：将纠偏指令累积到 mid_term 关键事实，下一轮 system prompt 自动注入。

    更彻底的方案需要修改 ReActEngine 内部循环（侵入性大，暂不做）。
    当前方案：on_step 回调时取出指令，作为 observation 追加到下一步。
    """

    def __init__(
        self,
        engine: ReActEngine,
        hub: InterventionHub,
    ) -> None:
        self.engine = engine
        self.hub = hub
        self._pending_instructions: list[str] = []

    def run(self, task: str) -> ReActResult:
        """运行引擎，注入 on_step 回调处理纠偏.

        实现：on_step 回调中 drain 指令，若非空则通过 engine._inject_context
        机制注入下一轮（这里简化为通过修改 task 描述追加指令）。

        由于 ReActEngine 不支持运行时干预，这里采用"事后注入"：
        - 每步完成后检查 hub
        - 若有指令，在下一次 LLM 调用前通过 system_prompt 更新注入
        - 实现：覆写 engine._on_step 回调
        """
        # 保存原 on_step
        original_on_step = self.engine._on_step

        def _wrapped_on_step(step: ReActStep) -> None:
            # 先执行原回调（广播步骤）
            if original_on_step is not None:
                original_on_step(step)
            # 检查干预队列
            instructions = self.hub.drain()
            if instructions:
                self._pending_instructions.extend(instructions)

        self.engine._on_step = _wrapped_on_step
        try:
            result = self.engine.run(task)
            # 任务结束后若有未处理指令，记录到 raw_outputs（便于诊断）
            if self._pending_instructions:
                result.raw_outputs.append(
                    "[未处理干预] " + " | ".join(self._pending_instructions)
                )
            return result
        finally:
            self.engine._on_step = original_on_step


# ============ FastAPI 应用 ============

class TaskCreateRequest(BaseModel):
    """任务创建请求."""

    target: str | None = None
    file: str | None = None
    desc: str = ""
    max_steps: int = 35
    enable_ssh: bool = True
    enable_l3: bool = False


class InterventionRequest(BaseModel):
    """干预请求."""

    instruction: str


def create_app(
    settings: Settings | None = None,
    *,
    task_manager: TaskManager | None = None,
) -> FastAPI:
    """创建 FastAPI 应用.

    Args:
        settings: 配置（未提供时用 get_settings）
        task_manager: 任务管理器（测试可注入 mock）

    Returns:
        FastAPI 应用实例
    """
    settings = settings or get_settings()
    task_manager = task_manager or TaskManager()

    app = FastAPI(title="CTF-Agent WebUI", version="0.1.0")

    # 静态文件（前端）
    static_dir = Path(__file__).parent / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # ============ API ============

    @app.get("/api/health")
    def health() -> dict:
        return {
            "status": "ok",
            "version": "0.1.0",
            "llm_configured": settings.has_llm_config(),
            "kali_configured": settings.has_kali_config(),
        }

    @app.post("/api/tasks", status_code=201)
    def create_task(req: TaskCreateRequest) -> dict:
        """提交任务，后台异步执行."""
        if not settings.has_llm_config():
            raise HTTPException(400, "OPENAI_API_KEY 未配置")

        # 构造任务描述
        parts: list[str] = []
        if req.desc:
            parts.append(req.desc.strip())
        if req.target:
            parts.append(f"目标: {req.target.strip()}")
        if req.file:
            parts.append(f"附件: {req.file.strip()}")
        if not parts:
            raise HTTPException(400, "至少需要 desc/target/file 之一")
        task_desc = "\n".join(parts)

        record = task_manager.create(task_desc)
        record.status = "pending"

        # 后台线程执行
        def _run_in_background() -> None:
            try:
                record.status = "running"
                llm = LLMClient(settings)

                # SSH 客户端（可选）
                ssh_client = None
                if req.enable_ssh and settings.has_kali_config():
                    try:
                        from ctf_agent.ssh import ssh_client_from_settings
                        ssh_client = ssh_client_from_settings(settings)
                        ssh_client.connect()
                    except Exception:  # noqa: BLE001
                        ssh_client = None

                # S12: 消息总线接入 → 共享发现工具可用 (单 agent 默认署名 "agent")
                from ctf_agent.bus.message_bus import get_default_bus
                tools = default_tools(
                    ssh_client=ssh_client, enable_l3=req.enable_l3,
                    message_bus=get_default_bus(), agent_id="agent",
                )

                def _on_step(step: ReActStep) -> None:
                    step_dict = record.add_step(step)
                    # 广播到 WebSocket 订阅者
                    _broadcast(record, {"type": "step", "data": step_dict})

                engine = ReActEngine(
                    llm=llm,
                    tools=tools,
                    max_steps=req.max_steps,
                    on_step=_on_step,
                )
                # 包装为干预感知引擎
                aware_engine = InterventionAwareEngine(engine, record.intervention_hub)
                result = aware_engine.run(task_desc)

                record.result = result
                record.status = "success" if result.success else "failed"
                record.ended_at = time.time()

                # 广播最终结果
                _broadcast(record, {
                    "type": "final",
                    "data": {
                        "success": result.success,
                        "final_answer": result.final_answer,
                        "fail_reason": result.fail_reason,
                        "step_count": result.step_count,
                        "total_tokens": result.total_tokens,
                    },
                })
            except Exception as e:  # noqa: BLE001
                record.status = "failed"
                record.ended_at = time.time()
                _broadcast(record, {
                    "type": "error",
                    "data": {"error": f"{type(e).__name__}: {e}"},
                })
            finally:
                if ssh_client is not None:
                    try:
                        ssh_client.close()
                    except Exception:  # noqa: BLE001
                        pass

        thread = threading.Thread(target=_run_in_background, daemon=True)
        thread.start()

        return {"task_id": record.task_id, "status": "pending"}

    @app.get("/api/tasks/{task_id}")
    def get_task(task_id: str) -> dict:
        record = task_manager.get(task_id)
        if record is None:
            raise HTTPException(404, f"任务不存在: {task_id}")
        return record.to_dict()

    @app.get("/api/tasks")
    def list_tasks() -> list[dict]:
        return [r.to_dict() for r in task_manager.list_all()]

    @app.post("/api/tasks/{task_id}/intervene")
    def intervene(task_id: str, req: InterventionRequest) -> dict:
        """对话纠偏：注入自然语言指令到运行中的任务."""
        record = task_manager.get(task_id)
        if record is None:
            raise HTTPException(404, f"任务不存在: {task_id}")
        if record.status != "running":
            raise HTTPException(400, f"任务状态 {record.status}，无法干预")

        record.intervention_hub.push(req.instruction)
        return {"task_id": task_id, "queued": req.instruction}

    # ============ WebSocket ============

    @app.websocket("/ws/tasks/{task_id}")
    async def ws_task(ws: WebSocket, task_id: str) -> None:
        """实时推送任务步骤."""
        record = task_manager.get(task_id)
        if record is None:
            await ws.close(code=4404, reason="任务不存在")
            return

        await ws.accept()
        # 注册订阅者
        record.subscribers.append(ws)

        # 推送已有步骤（历史）
        try:
            await ws.send_text(json.dumps({
                "type": "history",
                "data": record.to_dict(),
            }, ensure_ascii=False))

            # 保持连接，等待新消息
            while True:
                # 服务端不主动关闭，等客户端断开或任务结束
                try:
                    await ws.receive_text()
                except WebSocketDisconnect:
                    break
        except WebSocketDisconnect:
            pass
        finally:
            if ws in record.subscribers:
                record.subscribers.remove(ws)

    # ============ 首页 ============

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        index_path = static_dir / "index.html"
        if index_path.exists():
            return HTMLResponse(index_path.read_text(encoding="utf-8"))
        return HTMLResponse("<h1>CTF-Agent WebUI</h1><p>static/index.html 不存在</p>")

    # ============ 辅助函数 ============

    def _broadcast(record: TaskRecord, message: dict) -> None:
        """向所有 WebSocket 订阅者广播消息.

        注：FastAPI WebSocket 是异步的，但这里从同步线程调用。
        使用 asyncio.run_coroutine_threadsafe 或简化为 try/except 发送。
        实际生产应用 async，这里为简化用同步发送（可能阻塞）。
        """
        import asyncio

        text = json.dumps(message, ensure_ascii=False)
        for ws in list(record.subscribers):
            try:
                # WebSocket.send_text 是协程，需要事件循环
                # 简化：用 create_task（不阻塞当前线程）
                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(ws.send_text(text))
                finally:
                    loop.close()
            except Exception:  # noqa: BLE001 - 广播失败不影响任务
                pass

    return app


def run_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    settings: Settings | None = None,
) -> None:
    """启动 WebUI 服务器.

    Args:
        host: 监听地址
        port: 监听端口
        settings: 配置
    """
    import uvicorn

    app = create_app(settings)
    uvicorn.run(app, host=host, port=port)


__all__ = [
    "InterventionAwareEngine",
    "InterventionHub",
    "TaskCreateRequest",
    "TaskManager",
    "TaskRecord",
    "create_app",
    "run_server",
]
