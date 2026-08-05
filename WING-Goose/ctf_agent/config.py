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

    # ---- 模型路由 （opencode zen/go + 官方 flash) ----
    # 三级降级: zen(免费 flash-free) → go(付费 flash, 无峰谷) → 官方 flash
    # 优先 endpoint (免费但可能不稳定), 失败后回退 go → 官方
    zen_api_key: SecretStr = Field(default="", alias="ZEN_API_KEY")
    zen_base_url: str = Field(
        default="https://opencode.ai/zen/v1", alias="ZEN_BASE_URL"
    )
    zen_model: str = Field(default="deepseek-v4-flash-free", alias="ZEN_MODEL")
    # 关闭 zen 免费层 → 直接路由至 go (默认开启, 调试阶段避免免费层不稳定干扰)
    disable_zen: bool = Field(default=True, alias="DISABLE_ZEN")
    # 模型路由模式 (WING-Goose 2026-08): "go"=只走 go 套餐 (国内部署, 直连快,
    # 冲榜稳定); "auto"=zen→go→官方→pro 三级降级 (调试期保留).
    llm_provider: str = Field(default="go", alias="LLM_PROVIDER")
    # Opencode go 付费层: deepseek-v4-flash, 定价与官方一致且无峰谷收费倍率
    go_api_key: SecretStr = Field(default="", alias="GO_API_KEY")
    go_base_url: str = Field(
        default="https://opencode.ai/zen/go/v1", alias="GO_BASE_URL"
    )
    go_model: str = Field(default="deepseek-v4-flash", alias="GO_MODEL")
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
    # Kali 路由开关 (WING-Goose 2026-08): 默认 false = 关闭 Kali 路由, 执行层只用 Docker.
    # 关闭时领题前检查 Docker 容器可用性, 不可用直接报错退出 (不向下路由 Kali).
    kali_enabled: bool = Field(default=False, alias="KALI_ENABLED")
    kali_host: str = Field(default="", alias="KALI_HOST")
    kali_port: int = Field(default=22, alias="KALI_PORT")
    kali_user: str = Field(default="root", alias="KALI_USER")
    kali_pass: SecretStr = Field(default="", alias="KALI_PASS")
    kali_key_path: str = Field(default="", alias="KALI_KEY_PATH")

    # ---- Docker 工具链 (WING-Goose Item 5) ----
    # Docker Desktop 容器替代 ssh 执行层。daemon 不可用时自动降级到 ssh。
    # S7: 默认镜像切到 wing-goose:v2 (补装 fpylll/angr/torch 等 6 库 + 预封装入口),
    #      v1 仍以 latest 标签保留作为回滚点。
    docker_enabled: bool = Field(default=True, alias="DOCKER_ENABLED")
    docker_image: str = Field(default="wing-goose:v2", alias="DOCKER_IMAGE")
    docker_backend: str = Field(default="sdk", alias="DOCKER_BACKEND")
    docker_container: str = Field(default="wing-goose-worker", alias="DOCKER_CONTAINER")
    docker_workdir: str = Field(default="/challenge", alias="DOCKER_WORKDIR")
    docker_build_on_missing: bool = Field(default=False, alias="DOCKER_BUILD_ON_MISSING")
    # Dockerfile 路径（构建镜像用，默认 scripts/docker_test/Dockerfile.wing-goose）
    docker_dockerfile: str = Field(
        default="scripts/docker_test/Dockerfile.wing-goose", alias="DOCKER_DOCKERFILE")
    # ---- Docker 资源调控 (S3, 设计文档 §13) ----
    # 每容器配额 Profile: light(1核/1G) / normal(2核/2G) / brute(4核/2G) / heavy(4核/4G)
    docker_cpu_profile: str = Field(default="normal", alias="DOCKER_CPU_PROFILE")
    # 显式覆盖（>0 / 非空时优先于 Profile）
    docker_cpu_cores: int = Field(default=0, alias="DOCKER_CPU_CORES")
    docker_mem_limit: str = Field(default="", alias="DOCKER_MEM_LIMIT")
    # 最大并发容器数（0=按 §13.3 自动计算）；预留因子（宿主 OS/Docker Desktop 自身）
    docker_max_containers: int = Field(default=0, alias="DOCKER_MAX_CONTAINERS")
    docker_reserve_cpu: float = Field(default=0.25, alias="DOCKER_RESERVE_CPU")
    docker_reserve_ram: float = Field(default=0.25, alias="DOCKER_RESERVE_RAM")

    # ---- 多解题器 (WING-Goose swarm) ----
    # 2026-08: NSSCTF 难度评判不标准 (easy 实为 middle/hard 也常见, 如 [De1ctf 2019]babyrsa),
    # 默认开启多解题器: 所有难度 (含 easy) 都走 3 风格并行 swarm.
    # false → 回退 T3 结论 (仅 medium/hard 并行, easy 单路).
    swarm_enabled: bool = Field(default=True, alias="SWARM_ENABLED")

    # ---- 巡查指导器 (异步事件驱动) ----
    # 巡查发起节奏: 上一次注入结果之后 N 步再次发起 (默认 5, 范围 5~10).
    # 异步事件驱动: 巡查分析在后台线程执行不阻塞 agent 行动, 完成经事件召回注入后续步
    # (如第 10 步发起、第 12 步注入), 注入时声明来源步数避免过时信息误导.
    coordinator_patrol_gap: int = Field(default=5, alias="COORDINATOR_PATROL_GAP")

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
