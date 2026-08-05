"""靶场控制工具（agent 可管理靶场，但无法读取真 flag）.

提供 list/start/stop/status/verify 五个动作：
- list/status：展示题库与运行容器（flag 一律掩码，connection 地址帮助 agent 连接解题）
- start/stop：部署/停止题目容器
- verify：仅返回 correct/incorrect，绝不返回真 flag

安全：本工具不暴露任何读取 flag 明文或容器内部文件的接口；agent 应通过
web_tool / pwn_tool 连接题目端口、利用漏洞解题。
"""
from __future__ import annotations

import json
from typing import Any

from ctf_agent.ssh.client import SSHClient
from ctf_agent.tools.base import Tool

from .manager import RangeManager


class RangeTool(Tool):
    """靶场控制（部署/停止/状态/校验），不泄露真 flag."""

    name = "range_control"
    description = (
        "靶场管理工具：为 web/pwn/infra/crypto 等依赖服务器的题目提供运行环境。"
        "可用动作：list(列出题库与连接地址)、start(部署并启动题目容器)、"
        "stop(停止题目)、status(查看运行中的靶场容器)、verify(校验你解出的 flag 是否正确)。"
        "安全约束：verify 只返回 correct/incorrect，不会透露真 flag；"
        "请用 web_tool/pwn_tool 连接题目端口、通过漏洞解题，不得读取容器内部文件。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["list", "start", "stop", "status", "verify"],
                "description": "list=列出题库; start=部署并启动; stop=停止; status=查看运行容器; verify=校验 flag",
            },
            "name": {
                "type": "string",
                "description": "题目名（start/stop/verify 必填），如 Echo_Chamber",
            },
            "flag": {
                "type": "string",
                "description": "verify 时提交的 flag 明文",
            },
        },
        "required": ["action"],
    }

    def __init__(self, ssh_client: SSHClient | None = None, manager: RangeManager | None = None) -> None:
        self._ssh = ssh_client
        self._manager = manager or RangeManager(ssh_client=ssh_client)

    def execute(
        self,
        action: str,
        name: str | None = None,
        flag: str | None = None,
        **kwargs: Any,
    ) -> str:
        try:
            if action == "list":
                return json.dumps(self._manager.catalog_view(), ensure_ascii=False, indent=2)
            if action == "status":
                return json.dumps(self._manager.status(), ensure_ascii=False, indent=2)
            if action == "start":
                if not name:
                    return "ERROR: start 需要 name 参数"
                result = self._manager.deploy(name=name)
                return json.dumps(result, ensure_ascii=False, indent=2)
            if action == "stop":
                if not name:
                    return "ERROR: stop 需要 name 参数"
                return json.dumps(self._manager.down(name=name), ensure_ascii=False, indent=2)
            if action == "verify":
                if not name or not flag:
                    return "ERROR: verify 需要 name 和 flag"
                return "correct" if self._manager.verify(name, flag) else "incorrect"
            return f"ERROR: 未知 action: {action}"
        except Exception as e:  # noqa: BLE001
            return f"ERROR: {type(e).__name__}: {e}"


def range_tools(ssh_client: SSHClient | None = None) -> list[Tool]:
    """工厂：返回靶场控制工具列表."""
    return [RangeTool(ssh_client)]


__all__ = ["RangeTool", "range_tools"]
