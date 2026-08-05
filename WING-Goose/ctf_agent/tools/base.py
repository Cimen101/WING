"""工具基类.

定义 ReAct 引擎调用的工具契约。每个工具接收 JSON 字符串形式的 Action Input，
返回字符串形式的 Observation。工具内部异常被捕获并转为 ERROR 前缀字符串，
避免打断 ReAct 循环（依据 README §3.5.2 重复动作熔断需要 Observation 可识别错误）。
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


def _robust_json_loads(text: str) -> Any:
    """容错 JSON 解析.

    背景: LLM (deepseek-v4-flash) 输出复杂命令的 Action Input 时,
    常出现: JSON 后跟多余字符 ("Extra data"), 尾随逗号, markdown 装饰等.
    直接 json.loads 会失败, 导致 Agent 连续格式错误浪费步数 (PWN/RE 题复盘).

    修复策略 (逐级降级):
    1. 去尾随逗号/空白后直接解析
    2. 截取首个 { 到最后一个 } 之间的内容再解析 (处理 Extra data)
    3. 去 markdown 装饰 (*/`/_ 包围) 后重试
    全部失败则抛出原始 JSONDecodeError
    """
    text = (text or "").strip()

    def _try(s: str) -> Any | None:
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return None

    def _repair(s: str) -> str:
        # 去尾随逗号 (LLM 常见: {"a": 1,} 逗号在 } 前)
        return re.sub(r",\s*}", "}", s)

    # 1. 原样 / 修复尾随逗号
    r = _try(text)
    if r is not None:
        return r
    r = _try(_repair(text))
    if r is not None:
        return r

    # 2. 截取首 { 到末 } (处理 JSON 后跟说明文字 / 前后装饰)
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        cand = text[start:end + 1]
        r = _try(cand)
        if r is not None:
            return r
        r = _try(_repair(cand))
        if r is not None:
            return r

    # 3. 去 markdown 装饰 (LLM 加 ** 包围 JSON)
    stripped = re.sub(r"^[\*_`\s]+|[\*_`\s]+$", "", text)
    r = _try(_repair(stripped))
    if r is not None:
        return r

    raise json.JSONDecodeError(f"robust parse failed: {text[:80]}", text, 0)


@dataclass
class ToolResult:
    """工具执行结果."""

    output: str
    is_error: bool = False

    def __str__(self) -> str:
        return self.output


class Tool(ABC):
    """ReAct 工具基类.

    子类需定义：
        name: 工具名（ReAct Action 字段值）
        description: 工具用途（注入 system prompt）
        parameters: JSON Schema 描述 Action Input
    并实现 execute(**kwargs) -> str。
    """

    name: str = ""
    # WING-Goose: 别名 (经验库/旧脚本中的等价工具名).
    # react 注册时同一 Tool 挂多个名字 → LLM 用哪个名都能命中.
    # 用途: docker 工具主名统一为 ssh_* (与 Kali 经验一致), docker_* 作别名兼容.
    aliases: tuple[str, ...] = ()
    description: str = ""
    parameters: dict[str, Any] = {}

    @abstractmethod
    def execute(self, **kwargs: Any) -> str:
        """执行工具，返回 Observation 字符串。

        kwargs 来自 Action Input JSON 反序列化。
        实现者应返回人类可读的字符串，便于 LLM 理解。
        """
        raise NotImplementedError

    def __call__(self, action_input: str) -> ToolResult:
        """从 ReAct Action Input 字符串调用工具.

        Args:
            action_input: JSON 字符串，反序列化为 execute 的 kwargs

        Returns:
            ToolResult，is_error=True 时 output 以 "ERROR:" 开头
        """
        action_input = (action_input or "").strip()
        if not action_input:
            kwargs: dict[str, Any] = {}
        else:
            try:
                parsed = _robust_json_loads(action_input)
                if not isinstance(parsed, dict):
                    return ToolResult(
                        output=f"ERROR: action_input must be a JSON object, got {type(parsed).__name__}",
                        is_error=True,
                    )
                kwargs = parsed
            except json.JSONDecodeError as e:
                return ToolResult(
                    output=f"ERROR: invalid JSON action_input: {e}",
                    is_error=True,
                )

        try:
            output = self.execute(**kwargs)
            return ToolResult(output=output, is_error=False)
        except Exception as e:  # noqa: BLE001 - 工具层需捕获所有异常避免打断 ReAct
            return ToolResult(
                output=f"ERROR: {type(e).__name__}: {e}",
                is_error=True,
            )

    def schema(self) -> dict[str, Any]:
        """返回注入 system prompt 的工具描述."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
        }
