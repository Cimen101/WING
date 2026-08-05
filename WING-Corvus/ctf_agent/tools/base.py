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


def _extract_balanced_json(text: str) -> str | None:
    """提取首个花括号配平完整的 JSON 对象 (跳过字符串内 {}/转义引号).

    Sprint 36 复盘根因修复: LLM 在 JSON 后直接跟解释文本且文本含 {} 时
    (如 `Action Input: {"file": "/tmp/x"} 文件内容包含 {"flag": "..."}`),
    旧 "首{到末}" 截取会把中间文本一并包进 JSON → json.loads 失败.

    配平扫描: 首个 { 起, 状态机跳过 "..." 字符串 (含 \\" 转义) 与嵌套 {}.
    """
    if not text:
        return None
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _robust_json_loads(text: str) -> Any:
    """容错 JSON 解析 (Sprint 32.2 / 36).

    背景: LLM (deepseek-v4-flash) 输出复杂命令的 Action Input 时,
    常出现: JSON 后跟多余字符 ("Extra data"), 尾随逗号, markdown 装饰等.
    直接 json.loads 会失败, 导致 Agent 连续格式错误浪费步数 (PWN/RE 题复盘).

    Sprint 36 增强: "首{到末}" → "配平花括号提取完整 JSON 对象"
    (修复 JSON 后跟含 {} 文本时把文本包进 JSON 的解析失败).

    修复策略 (逐级降级):
    1. 去尾随逗号/空白后直接解析
    2. 配平花括号提取首个完整 JSON 对象再解析 (处理 Extra data / 中间混入文本)
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
        return re.sub(r",\s*([}\]])", r"\1", s)

    # 1. 原样 / 修复尾随逗号
    r = _try(text)
    if r is not None:
        return r
    r = _try(_repair(text))
    if r is not None:
        return r

    # 2. 配平花括号提取首个完整 JSON 对象 (处理 Extra data / 中间混入文本)
    bal = _extract_balanced_json(text)
    if bal is not None:
        r = _try(bal)
        if r is not None:
            return r
        r = _try(_repair(bal))
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
            except json.JSONDecodeError:
                # Sprint 36 复盘: 破损 JSON 恢复 — 配平提取已失败 (值内引号未转义等),
                # 尝试从原文本提取必填字段的 "key": "value" 对, 最大限度救回本步
                # (threshold 复盘: aggressive 写脚本时反复因未转义 {}/引号失败烧掉 9.4M tokens).
                recovered = self._recover_kwargs(action_input)
                if recovered is None:
                    return ToolResult(
                        output=f"ERROR: invalid JSON action_input: {action_input[:120]}",
                        is_error=True,
                    )
                kwargs = recovered

        try:
            output = self.execute(**kwargs)
            return ToolResult(output=output, is_error=False)
        except Exception as e:  # noqa: BLE001 - 工具层需捕获所有异常避免打断 ReAct
            return ToolResult(
                output=f"ERROR: {type(e).__name__}: {e}",
                is_error=True,
            )

    def _recover_kwargs(self, text: str) -> dict[str, Any] | None:
        """Sprint 36: 破损 JSON 的字段级恢复.

        配平提取后仍无法 json.loads (典型: 值内双引号未转义, 如
        `{"cmd": "echo 'x' && cat /tmp/{"a":1}"}`), 改为从原文本提取
        必填字段的 `"key": "value"` 对 (值内含 {} 时按花括号配平跳过, 避免
        在 dict/脚本内容处提前终止字符串).

        Returns:
            kwargs dict; 无法恢复返回 None (调用方保留原始错误)
        """
        required = list((self.parameters or {}).get("required") or [])
        if not required:
            return None

        def _extract_value(start: int, quote: str = '"') -> str | None:
            """从 ':' 之后提取首个引号字符串值, 值内 {} 配平 + \\" 转义."""
            i = start
            while i < len(text) and text[i] != quote:
                i += 1
            if i >= len(text):
                return None
            i += 1  # 跳过开引号
            buf: list[str] = []
            depth = 0
            while i < len(text):
                ch = text[i]
                if ch == "\\" and i + 1 < len(text):
                    buf.append(text[i:i + 2])
                    i += 2
                    continue
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth = max(0, depth - 1)
                elif ch == quote and depth == 0:
                    return "".join(buf)
                buf.append(ch)
                i += 1
            return None

        kwargs: dict[str, Any] = {}
        for key in required:
            # 键双引号优先, 单引号兼容 (deepseek 常见单引号 JSON)
            m = re.search(r'"' + re.escape(key) + r'"\s*:', text)
            quote = '"'
            if not m:
                m = re.search(r"'" + re.escape(key) + r"'\s*:", text)
                quote = "'"
            if not m:
                return None
            val = _extract_value(m.end(), quote)
            if val is None and quote != '"':
                val = _extract_value(m.end(), '"')
            if val is None and quote != "'":
                val = _extract_value(m.end(), "'")
            if val is None:
                return None
            try:
                # 反转义 (JSON 字符串转义序列)
                val = json.loads('"' + val.replace('"', '\\"') + '"')
            except Exception:
                val = val.replace('\\"', '"').replace("\\n", "\n")
            kwargs[key] = val
        return kwargs

    def schema(self) -> dict[str, Any]:
        """返回注入 system prompt 的工具描述."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
        }
