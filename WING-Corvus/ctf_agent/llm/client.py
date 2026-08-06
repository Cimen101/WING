"""LLM 客户端实现.

封装 OpenAI Python SDK，提供同步与异步 chat completion 接口。
通过依赖注入底层 client，使测试无需真实 API Key 即可验证接口契约。

设计依据：
- README §3.4.1 Executor 绑定模型（DeepSeek-V3 / Claude 3.5 等），均兼容 OpenAI Chat API
- README §3.5.2 成本熔断需要 token usage，故 ChatResult 必须返回 usage
- README §6.1 OPENAI_BASE_URL 支持 DeepSeek 等兼容端点
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, TypedDict, runtime_checkable

from openai import AsyncOpenAI, OpenAI

from ctf_agent.config import Settings, get_settings

Role = Literal["system", "user", "assistant", "tool"]


class MessageDict(TypedDict):
    """OpenAI Chat API 消息格式."""

    role: Role
    content: str


@dataclass
class Message:
    """结构化消息，序列化后与 OpenAI Chat API 兼容."""

    role: Role
    content: str

    def to_dict(self) -> MessageDict:
        return {"role": self.role, "content": self.content}


@dataclass
class ChatUsage:
    """单次调用的 token 用量."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    @classmethod
    def from_openai(cls, usage: Any) -> "ChatUsage":
        """从 OpenAI 响应对象构造；usage 为 None 时返回零用量."""
        if usage is None:
            return cls()
        return cls(
            prompt_tokens=int(getattr(usage, "prompt_tokens", 0) or 0),
            completion_tokens=int(getattr(usage, "completion_tokens", 0) or 0),
            total_tokens=int(getattr(usage, "total_tokens", 0) or 0),
        )


@dataclass
class ChatResult:
    """单次 chat completion 结果."""

    content: str
    usage: ChatUsage = field(default_factory=ChatUsage)
    model: str = ""
    finish_reason: str = ""
    reasoning_content: str = ""  # 推理模型的思维链内容（如 deepseek reasoner 系列）
    reasoning_fallback: bool = False  # Sprint 36.3: content 为空时回退了 reasoning_content
    raw: Any = None  # 原始响应，调试/扩展用


@runtime_checkable
class _SyncChatProtocol(Protocol):
    def chat_completions_create(self, **kwargs: Any) -> Any: ...


def _normalize_messages(
    messages: list[Message] | list[MessageDict] | list[dict[str, str]],
) -> list[MessageDict]:
    """统一消息格式为 list[dict]."""
    result: list[MessageDict] = []
    for m in messages:
        if isinstance(m, Message):
            result.append(m.to_dict())
        else:
            result.append({"role": m["role"], "content": m["content"]})  # type: ignore[index]
    return result


def _parse_response(resp: Any, model: str) -> ChatResult:
    """从 OpenAI ChatCompletion 响应解析出 ChatResult.

    兼容 DeepSeek 等推理模型：部分模型（如 deepseek-v4-flash）会把答案放在
    ``message.reasoning_content`` 而 ``message.content`` 为空。此时回退使用
    ``reasoning_content`` 作为主内容，保证下游 agent 循环能拿到有效输出。
    """
    choice = resp.choices[0]
    message = choice.message
    content = getattr(message, "content", None) or ""
    reasoning_content = getattr(message, "reasoning_content", None) or ""
    finish_reason = getattr(choice, "finish_reason", "") or ""
    # content 为空但存在 reasoning_content 时，回退使用后者作为主内容
    # Sprint 36.3: 标记 reasoning_fallback, 供 ReAct 引擎识别"退化思考输出" —
    # 思考文本通常不含 Action 字段, 直接当主内容会触发格式解析失败;
    # 引擎侧应走"空输出"恢复路径而非立即计格式错误.
    reasoning_fallback = False
    if not content.strip() and reasoning_content.strip():
        content = reasoning_content
        reasoning_fallback = True
    return ChatResult(
        content=content,
        usage=ChatUsage.from_openai(getattr(resp, "usage", None)),
        model=model,
        finish_reason=finish_reason,
        reasoning_content=reasoning_content,
        reasoning_fallback=reasoning_fallback,
        raw=resp,
    )


class LLMClient:
    """OpenAI 兼容 API 客户端.

    使用方式：
        client = LLMClient()  # 从 Settings 自动加载 key/base_url
        result = client.chat([Message("user", "你好")])

    测试时注入 mock client：
        client = LLMClient(sync_client=mock_openai)
    """

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        sync_client: OpenAI | Any | None = None,
        async_client: AsyncOpenAI | Any | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._sync_client: OpenAI | Any | None = sync_client
        self._async_client: AsyncOpenAI | Any | None = async_client

    def _ensure_sync_client(self) -> Any:
        if self._sync_client is None:
            api_key = self.settings.openai_api_key.get_secret_value()
            if not api_key:
                raise ValueError(
                    "OPENAI_API_KEY 未配置，请在 .env 中设置（参考 .env.example）"
                )
            self._sync_client = OpenAI(
                api_key=api_key,
                base_url=self.settings.openai_base_url,
            )
        return self._sync_client

    def _ensure_async_client(self) -> Any:
        if self._async_client is None:
            api_key = self.settings.openai_api_key.get_secret_value()
            if not api_key:
                raise ValueError(
                    "OPENAI_API_KEY 未配置，请在 .env 中设置（参考 .env.example）"
                )
            self._async_client = AsyncOpenAI(
                api_key=api_key,
                base_url=self.settings.openai_base_url,
            )
        return self._async_client

    def chat(
        self,
        messages: list[Message] | list[MessageDict] | list[dict[str, str]],
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        timeout: float | None = None,
        extra: dict[str, Any] | None = None,
    ) -> ChatResult:
        """同步 chat completion.

        Args:
            messages: 消息列表，支持 Message 对象或 dict
            model: 模型名，None 时使用 settings.executor_model
            temperature: 采样温度，默认 0（确定性输出，适合工具调用）
            max_tokens: 最大生成 token 数
            timeout: 请求超时秒数
            extra: 透传给 OpenAI API 的额外参数

        Returns:
            ChatResult 包含 content 与 usage
        """
        used_model = model or self.settings.executor_model
        payload: dict[str, Any] = {
            "model": used_model,
            "messages": _normalize_messages(messages),
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if timeout is not None:
            payload["timeout"] = timeout
        if extra:
            payload.update(extra)

        client = self._ensure_sync_client()
        resp = client.chat.completions.create(**payload)
        return _parse_response(resp, used_model)

    async def achat(
        self,
        messages: list[Message] | list[MessageDict] | list[dict[str, str]],
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        timeout: float | None = None,
        extra: dict[str, Any] | None = None,
    ) -> ChatResult:
        """异步 chat completion，参数语义与 chat() 一致."""
        used_model = model or self.settings.executor_model
        payload: dict[str, Any] = {
            "model": used_model,
            "messages": _normalize_messages(messages),
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if timeout is not None:
            payload["timeout"] = timeout
        if extra:
            payload.update(extra)

        client = self._ensure_async_client()
        resp = await client.chat.completions.create(**payload)
        return _parse_response(resp, used_model)
