"""WebUI 入口层（L1）—— FastAPI + WebSocket.

依据 README §3.6 阶段八：
- 后端：FastAPI + WebSocket
- 功能：任务提交、实时日志推送、对话纠偏输入框
- 纠偏机制：用户输入自然语言指令，写入任务干预队列，
  ReAct 引擎每步检查队列，将指令注入下一轮 system prompt

设计原则：
- 单进程同步执行任务（任务在后台线程跑，避免阻塞主事件循环）
- 静态前端：原生 HTML+JS（避免 Vue3/Vite 构建链）
- 任务隔离：每个任务独立线程 + 独立干预队列
"""

from ctf_agent.web.app import create_app, run_server

__all__ = ["create_app", "run_server"]
