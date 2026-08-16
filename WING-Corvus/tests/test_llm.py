"""Sprint 2.2 验收测试：LLM 客户端封装.

使用 MagicMock 模拟 OpenAI 客户端，验证：
1. 消息格式归一化
2. 同步/异步 chat 调用契约
3. usage 解析
4. 缺失 API Key 时的错误提示
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ctf_agent.config import Settings
from ctf_agent.llm import ChatResult, ChatUsage, LLMClient, Message


def _fake_openai_response(
    content: str = "hello",
    *,
    prompt_tokens: int = 10,
    completion_tokens: int = 5,
    finish_reason: str = "stop",
) -> SimpleNamespace:
    """构造一个最小可用的 OpenAI ChatCompletion 响应对象."""
    return SimpleNamespace(
        id="chatcmpl-fake",
        model="deepseek-chat",
        choices=[
            SimpleNamespace(
                index=0,
                message=SimpleNamespace(role="assistant", content=content),
                finish_reason=finish_reason,
            )
        ],
        usage=SimpleNamespace(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        ),
    )


def _make_mock_sync_client(resp: SimpleNamespace | None = None) -> MagicMock:
    """构造 mock 同步 OpenAI 客户端."""
    resp = resp or _fake_openai_response()
    client = MagicMock()
    client.chat.completions.create.return_value = resp
    return client


def _make_mock_async_client(resp: SimpleNamespace | None = None) -> MagicMock:
    """构造 mock 异步 OpenAI 客户端."""
    resp = resp or _fake_openai_response()
    client = MagicMock()
    client.chat.completions.create = AsyncMock(return_value=resp)
    return client


# ---- 测试用 Settings（不依赖 .env）----
@pytest.fixture
def test_settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    """带 fake key 的 Settings."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.deepseek.com/v1")
    monkeypatch.setenv("EXECUTOR_MODEL", "deepseek-chat")
    return Settings(_env_file=None)  # type: ignore[call-arg]


# ---- Message 归一化 ----
def test_message_to_dict() -> None:
    m = Message(role="user", content="hi")
    assert m.to_dict() == {"role": "user", "content": "hi"}


def test_chat_accepts_message_objects(test_settings: Settings) -> None:
    """LLMClient 应接受 Message 对象列表."""
    mock_client = _make_mock_sync_client(_fake_openai_response("pong"))
    client = LLMClient(test_settings, sync_client=mock_client)
    result = client.chat([Message("user", "ping")])
    assert result.content == "pong"
    # 验证 payload 中 messages 已归一化为 dict
    call_kwargs = mock_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["messages"] == [{"role": "user", "content": "ping"}]


def test_chat_accepts_dict_messages(test_settings: Settings) -> None:
    """LLMClient 应接受 dict 消息列表."""
    mock_client = _make_mock_sync_client()
    client = LLMClient(test_settings, sync_client=mock_client)
    client.chat([{"role": "user", "content": "hi"}])
    call_kwargs = mock_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["messages"] == [{"role": "user", "content": "hi"}]


# ---- 同步 chat ----
def test_chat_returns_content_and_usage(test_settings: Settings) -> None:
    mock_client = _make_mock_sync_client(
        _fake_openai_response("answer", prompt_tokens=20, completion_tokens=8)
    )
    client = LLMClient(test_settings, sync_client=mock_client)
    result = client.chat([Message("user", "?")])

    assert isinstance(result, ChatResult)
    assert result.content == "answer"
    assert result.usage.prompt_tokens == 20
    assert result.usage.completion_tokens == 8
    assert result.usage.total_tokens == 28
    assert result.finish_reason == "stop"
    assert result.model == "deepseek-chat"


def test_chat_uses_executor_model_by_default(test_settings: Settings) -> None:
    mock_client = _make_mock_sync_client()
    client = LLMClient(test_settings, sync_client=mock_client)
    client.chat([Message("user", "hi")])
    call_kwargs = mock_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["model"] == "deepseek-chat"


def test_chat_explicit_model_overrides(test_settings: Settings) -> None:
    mock_client = _make_mock_sync_client()
    client = LLMClient(test_settings, sync_client=mock_client)
    client.chat([Message("user", "hi")], model="gpt-4o")
    call_kwargs = mock_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["model"] == "gpt-4o"


def test_chat_passes_temperature_and_max_tokens(test_settings: Settings) -> None:
    mock_client = _make_mock_sync_client()
    client = LLMClient(test_settings, sync_client=mock_client)
    client.chat([Message("user", "hi")], temperature=0.7, max_tokens=100, timeout=30.0)
    call_kwargs = mock_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["temperature"] == 0.7
    assert call_kwargs["max_tokens"] == 100
    assert call_kwargs["timeout"] == 30.0


# ---- 异步 chat ----
async def test_achat_returns_content(test_settings: Settings) -> None:
    mock_client = _make_mock_async_client(_fake_openai_response("async-pong"))
    client = LLMClient(test_settings, async_client=mock_client)
    result = await client.achat([Message("user", "ping")])

    assert result.content == "async-pong"
    assert result.usage.total_tokens == 15
    assert mock_client.chat.completions.create.await_count == 1


# ---- 错误处理 ----
def test_chat_without_api_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """缺失 API Key 时应给出明确错误."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    client = LLMClient(settings)  # 不注入 mock，触发 _ensure 路径
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        client.chat([Message("user", "hi")])


async def test_achat_without_api_key_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    client = LLMClient(settings)
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        await client.achat([Message("user", "hi")])


# ---- usage 解析边界 ----
def test_chat_usage_handles_none_usage(test_settings: Settings) -> None:
    """某些兼容端点可能不返回 usage."""
    resp = SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(role="assistant", content="x"),
                finish_reason="stop",
            )
        ],
        usage=None,
    )
    mock_client = _make_mock_sync_client(resp)
    client = LLMClient(test_settings, sync_client=mock_client)
    result = client.chat([Message("user", "?")])
    assert result.usage == ChatUsage()


def test_chat_usage_handles_none_content(test_settings: Settings) -> None:
    """content 为 None 时应转为空字符串."""
    resp = SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(role="assistant", content=None),
                finish_reason="length",
            )
        ],
        usage=SimpleNamespace(prompt_tokens=5, completion_tokens=0, total_tokens=5),
    )
    mock_client = _make_mock_sync_client(resp)
    client = LLMClient(test_settings, sync_client=mock_client)
    result = client.chat([Message("user", "?")])
    assert result.content == ""
    assert result.finish_reason == "length"
