"""Sprint 2.1 验收测试：配置加载层."""

from __future__ import annotations

import pytest

from ctf_agent.config import Settings, get_settings


def test_settings_defaults(_no_env: None) -> None:
    """默认值符合 README §6.1 规范."""
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.max_steps == 35
    assert settings.max_task_time == 1800
    assert settings.max_cost_limit == 1.5
    assert settings.kali_port == 22
    assert settings.openai_base_url == "https://api.openai.com/v1"
    assert settings.planner_model == "gpt-4o"


def test_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """环境变量优先级高于默认值."""
    monkeypatch.setenv("MAX_STEPS", "10")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.deepseek.com/v1")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.max_steps == 10
    assert settings.openai_api_key.get_secret_value() == "sk-test"
    assert settings.openai_base_url == "https://api.deepseek.com/v1"


def test_has_llm_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """has_llm_config 反映 API Key 是否存在."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.has_llm_config() is False

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    settings2 = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings2.has_llm_config() is True


def test_has_kali_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """has_kali_config 需要 host+user+(pass 或 key_path)."""
    monkeypatch.delenv("KALI_HOST", raising=False)
    monkeypatch.delenv("KALI_USER", raising=False)
    monkeypatch.delenv("KALI_PASS", raising=False)
    monkeypatch.delenv("KALI_KEY_PATH", raising=False)
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.has_kali_config() is False

    monkeypatch.setenv("KALI_HOST", "192.168.100.2")
    monkeypatch.setenv("KALI_USER", "root")
    monkeypatch.setenv("KALI_PASS", "password")
    settings2 = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings2.has_kali_config() is True


def test_get_settings_cached() -> None:
    """get_settings 返回单例."""
    get_settings.cache_clear()
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2
    get_settings.cache_clear()


# ---- fixtures ----
@pytest.fixture
def _no_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """清空所有 CTF 相关环境变量，保证默认值测试纯净."""
    for key in (
        "OPENAI_API_KEY", "OPENAI_BASE_URL", "PLANNER_MODEL", "EXECUTOR_MODEL",
        "KALI_HOST", "KALI_PORT", "KALI_USER", "KALI_PASS", "KALI_KEY_PATH",
        "MAX_STEPS", "MAX_TASK_TIME", "MAX_COST_LIMIT",
        "SQLITE_PATH", "CHROMA_PATH", "LOG_LEVEL",
    ):
        monkeypatch.delenv(key, raising=False)
    return None
