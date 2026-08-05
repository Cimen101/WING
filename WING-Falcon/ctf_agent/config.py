"""配置加载层.

依据 README §6.1 的 .env 配置规范，使用 pydantic-settings 提供类型安全的配置访问。
所有字段均带默认值，缺失环境变量不会导致启动崩溃（便于阶段二在无 Kali 环境下运行）。
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """全局配置.

    通过环境变量或 .env 文件加载，字段别名与 .env 中的键名一一对应。
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---- LLM 配置 ----
    openai_api_key: SecretStr = Field(default="", alias="OPENAI_API_KEY")
    openai_base_url: str = Field(
        default="https://api.openai.com/v1", alias="OPENAI_BASE_URL"
    )
    planner_model: str = Field(default="gpt-4o", alias="PLANNER_MODEL")
    executor_model: str = Field(default="deepseek-chat", alias="EXECUTOR_MODEL")

    # ---- 模型路由 ----
    # 优先 endpoint (免费但可能不稳定), 失败后回退官方
    zen_api_key: SecretStr = Field(default="", alias="ZEN_API_KEY")
    zen_base_url: str = Field(
        default="https://opencode.ai/zen/v1", alias="ZEN_BASE_URL"
    )
    zen_model: str = Field(default="deepseek-v4-flash-free", alias="ZEN_MODEL")
    # 官方回退 endpoint
    fallback_api_key: SecretStr = Field(default="", alias="FALLBACK_API_KEY")
    fallback_base_url: str = Field(
        default="https://api.deepseek.com/v1", alias="FALLBACK_BASE_URL"
    )
    fallback_model: str = Field(default="deepseek-v4-flash", alias="FALLBACK_MODEL")
    # 重试次数 (zen 失败后重试 N 次才回退)
    llm_max_retries: int = Field(default=2, alias="LLM_MAX_RETRIES")

    # ---- Pro 模型路由 (deprecated) ----
    # ⚠️ pro 路由默认关闭且不再推荐使用:
    #   deepseek-v4-flash 正式版能力已足够强, 按难度调思考强度(thinking_mode)可覆盖 pro 的"难题增强"诉求
    #   pro 模型成本高 3-5x、速度慢 2x, 对当前瓶颈(工具/策略)无帮助
    # 功能保留(仅 .env 显式 ENABLE_PRO_FALLBACK=true 才生效), 后续不再维护
    pro_api_key: SecretStr = Field(default="", alias="PRO_API_KEY")
    pro_base_url: str = Field(
        default="https://api.deepseek.com/v1", alias="PRO_BASE_URL"
    )
    pro_model: str = Field(default="deepseek-v4-pro", alias="PRO_MODEL")
    # 是否启用 pro 模型回退 (默认关闭, 通过 .env 开启) — deprecated
    enable_pro_fallback: bool = Field(default=False, alias="ENABLE_PRO_FALLBACK")
    # flash 阶段判断"不足以完成"的步数阈值比例 (达成比例时切换pro)
    pro_fallback_step_ratio: float = Field(default=0.7, alias="PRO_FALLBACK_STEP_RATIO")
    # pro 模型最大重试步数
    pro_max_steps: int = Field(default=40, alias="PRO_MAX_STEPS")

    # ---- 思考模式 (deepseek-v4-flash thinking_mode) ----
    # 官方文档: https://api-docs.deepseek.com/zh-cn/guides/thinking_mode
    # 启用后模型先输出思维链(reasoning_content)再输出最终回答(content), 提升准确性
    # reasoning_effort 支持 high/max (low/medium 会被映射为 high, xhigh 映射为 max)
    # 思考模式不支持 temperature/top_p 等采样参数 (设置不报错但不生效)
    # 是否启用思考模式 (默认启用; 关闭后走模型默认行为, 不传 reasoning_effort)
    enable_thinking_mode: bool = Field(default=True, alias="ENABLE_THINKING_MODE")
    # 按难度分级的 reasoning_effort (low 会被映射为 high, 故不使用 low)
    # easy/medium 题用 high (平衡速度与准确率), hard/extreme 题用 max (最大推理深度)
    thinking_effort_easy: str = Field(default="high", alias="THINKING_EFFORT_EASY")
    thinking_effort_medium: str = Field(default="high", alias="THINKING_EFFORT_MEDIUM")
    thinking_effort_hard: str = Field(default="max", alias="THINKING_EFFORT_HARD")
    thinking_effort_extreme: str = Field(default="max", alias="THINKING_EFFORT_EXTREME")
    # 未知难度时的默认 effort (未指定 difficulty 的题目)
    thinking_effort_default: str = Field(default="high", alias="THINKING_EFFORT_DEFAULT")

    # ---- Kali SSH 配置（阶段一启用）----
    kali_host: str = Field(default="", alias="KALI_HOST")
    kali_port: int = Field(default=22, alias="KALI_PORT")
    kali_user: str = Field(default="root", alias="KALI_USER")
    kali_pass: SecretStr = Field(default="", alias="KALI_PASS")
    kali_key_path: str = Field(default="", alias="KALI_KEY_PATH")

    # ---- 熔断阈值 ----
    # max_steps 50→80 硬性上限, 动态熔断由 AdaptiveBreaker 按难度调整
    max_steps: int = Field(default=80, alias="MAX_STEPS")
    max_task_time: int = Field(default=1800, alias="MAX_TASK_TIME")
    max_cost_limit: float = Field(default=1.5, alias="MAX_COST_LIMIT")

    # ---- 数据库 ----
    sqlite_path: str = Field(default="./data/ctf.db", alias="SQLITE_PATH")
    chroma_path: str = Field(default="./data/chroma", alias="CHROMA_PATH")

    # ---- 日志 ----
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    def has_kali_config(self) -> bool:
        """判断是否配置了可用的 Kali SSH 连接信息."""
        return bool(self.kali_host and self.kali_user and (self.kali_pass.get_secret_value() or self.kali_key_path))

    def has_llm_config(self) -> bool:
        """判断是否配置了可用的 LLM API Key."""
        return bool(self.openai_api_key.get_secret_value())


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """获取全局配置单例.

    使用 lru_cache 保证全应用共享同一份配置实例，避免重复 IO。
    测试时可通过 `get_settings.cache_clear()` 重置。
    """
    return Settings()  # type: ignore[call-arg]
