"""ReAct 引擎核心.

实现 Thought-Action-Observation 循环：
1. LLM 输出 Thought + Action + Action Input
2. 引擎解析并调用工具，得到 Observation
3. Observation 回灌给 LLM，进入下一轮
4. LLM 输出 Final Answer 时终止

依据 README §3.5.2，max_steps 默认 35（与 Settings.max_steps 一致）。
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol
from uuid import uuid4

from ctf_agent.llm import LLMClient, Message
from ctf_agent.memory import LongTermMemory, MidTermMemory, ShortTermMemory
from ctf_agent.orchestrator import CircuitBreaker, TaskStatus
from ctf_agent.tools.base import Tool, ToolResult
from ctf_agent.tools.memory_tools import memory_tools
from ctf_agent.agent.failed_trajectory_cache import (
    FailedTrajectoryCache,
    get_default_cache,
)
from ctf_agent.agent.prompts import (
    FORMAT_ERROR_HINT,
    NULL_OBSERVATION_HINT,  # null observation 兜底
    OBSERVATION_TEMPLATE,
    build_system_prompt,
    build_task_prompt,
)
from ctf_agent.memory.rag import RAGRetriever


# ============ 解析器 ============

@dataclass
class ParsedAction:
    """LLM 单步输出的解析结果."""

    thought: str = ""
    is_final: bool = False
    final_answer: str = ""
    action: str = ""  # 工具名
    action_input: str = ""  # JSON 字符串
    is_valid: bool = True
    parse_error: str = ""

    @property
    def needs_tool(self) -> bool:
        """是否需要调用工具（非 Final Answer 且 action 非空）."""
        return self.is_valid and not self.is_final and bool(self.action)


# 正则：Final Answer（容错大小写、冒号后可有空格）
_RE_FINAL = re.compile(r"Final\s*Answer\s*:\s*(.+)", re.IGNORECASE | re.DOTALL)
# 正则：Action: 工具名（一行内的非空白字符序列）
# 改为匹配 [a-z_][a-z0-9_]* (工具名格式), 跳过 ** 等 Markdown 装饰
# LLM (deepseek-chat) 经常输出 `**Action:** ssh_exec`, 旧 regex `([^\s\n]+)` 会捕获 `**`
# 也支持 `Action: \`ssh_exec\`` 反引号格式 (LLM 偶尔用)
# 加负向前瞻 (?!\s*:?\s*Input\b) 避免把 "Action Input: {}" 中
# 的 "Input" 误解析为工具名 (缺 Action 字段时导致 is_valid 误判为 True)
_RE_ACTION = re.compile(
    r"Action(?!\s*:?\s*Input\b)\s*:?\s*\*{0,2}\s*:?\s*`?([a-z_][a-z0-9_]*)`?",
    re.IGNORECASE,
)
# 正则：Action Input: 后到行尾或下一个字段（容错多行 JSON）
_RE_ACTION_INPUT = re.compile(
    r"Action\s*Input\s*:\s*(.*?)(?=\n\s*(?:Thought|Action|Final\s*Answer|Observation)\s*:|\Z)",
    re.IGNORECASE | re.DOTALL,
)
# Action Input 别名 (LLM 偶尔输出 Input:/Args:/参数:/Parameters: 等)
_RE_ACTION_INPUT_ALT = re.compile(
    r"(?:Input|Args|Arguments|Parameters|Params|参数)\s*:\s*(.*?)(?=\n\s*(?:Thought|Action|Final\s*Answer|Observation)\s*:|\Z)",
    re.IGNORECASE | re.DOTALL,
)
# 正则：Thought
_RE_THOUGHT = re.compile(
    r"Thought\s*:\s*(.*?)(?=\n\s*(?:Action|Final\s*Answer|Observation)\s*:|\Z)",
    re.IGNORECASE | re.DOTALL,
)
# markdown 代码块剔除
_RE_CODE_FENCE = re.compile(r"^```(?:json)?\s*\n?|\n?```\s*$", re.MULTILINE)
# LLM 经常在 Action Input 前后加 ** (markdown 加粗)
# 真实数据: action_input = "**\n{...}\n**" 触发 JSON 解析失败
_RE_MD_BOLD = re.compile(r"^[\*_`]+|[\*_`]+$", re.MULTILINE)


def _strip_code_fence(text: str) -> str:
    """去除 JSON 周围的 ```json ... ``` 标记 + 前后 markdown 加粗符号.

    LLM (deepseek-chat) 输出模式:
    ```
    **Action Input:**
    ```json
    {"url": "...", "...": "..."}
    ```
    ```
    旧 parser 捕获: "**\n```json\n{...}\n```", 之后 _RE_CODE_FENCE 只去 ``` 但不去 **, JSON 解析失败.
    修复: 先去 ```, 再去前后 ** 装饰.
    """
    if not text:
        return text
    # 1. 去 ```json ... ``` 代码块标记
    text = _RE_CODE_FENCE.sub("", text)
    # 2. 去前后 markdown 装饰 (**, *, _, `)
    text = _RE_MD_BOLD.sub("", text)
    return text.strip()


def _extract_balanced_json(text: str) -> str | None:
    """提取首个花括号配平完整的 JSON 对象 (跳过字符串内 {}/转义引号).

    复盘根因修复: LLM 在 JSON 对象后直接跟解释文本且文本含 {} 时
    (如 `Action Input: {"file": "/tmp/x"} 文件内容包含 {"flag": "..."}`),
    旧 "首{到末}" 截取会把中间文本一并包进 JSON → json.loads 失败
    (threshold 22 条 "Thought 混入 action_input" 报告实证).

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


def _clean_action_input(raw: str) -> str:
    """action_input 鲁棒清洗 — 修复"Thought 文本混入"与"特殊字符"导致的
    工具层 JSON 解析失败 (linx/threshold 复盘中多路死于"连续 5 次格式解析失败").

    背景: LLM 输出格式混乱时, _RE_ACTION_INPUT 捕获的 action_input 可能:
      1. 混入 Thought 文本/解释 (如 "Action Input: {\"cmd\":\"ls\"} 这是为了查看目录")
      2. 含特殊字符/换行导致 json.loads 失败
      3. 用单引号替代双引号 (deepseek 常见)
    清洗策略: 配平花括号截取完整 JSON 对象 + 单引号/尾逗号容错. 返回最可能可解析的版本.
    """
    if not raw or not raw.strip():
        return raw
    s = raw.strip()
    # 1. 配平花括号提取首个完整 JSON 对象 (去除前后/中间混入文本)
    #    (旧 "首{到末}" 在 JSON 后跟含 {} 文本时会把文本包进 JSON → 解析失败)
    bal = _extract_balanced_json(s)
    if bal is not None:
        s = bal
    else:
        # 兜底: 无配平对象 (如全是散文本) 保持原样, 工具层报错信息保留
        return raw
    # 2. 原样可解析 → 直接返回
    try:
        json.loads(s)
        return s
    except Exception:
        pass
    # 3. 尾逗号容错 (LLM 常在数组/对象末尾加逗号)
    s2 = re.sub(r",\s*([}\]])", r"\1", s)
    try:
        json.loads(s2)
        return s2
    except Exception:
        pass
    # 4. 单引号 → 双引号 (最后手段; 仅当字符串内无单引号冲突时才有效, 失败无害)
    s3 = s2.replace("'", '"')
    try:
        json.loads(s3)
        return s3
    except Exception:
        pass
    # 5. 全失败: 返回原样 (工具层会报错, 信息保留供提示)
    return raw


def _strip_markdown_artifacts(action: str) -> str:
    r"""去除 Action 字段中 LLM 加的 Markdown 装饰 (修复).

    背景: LLM (deepseek-chat) 经常输出 **Action:** ssh_exec 格式,
    regex Action\s*:\s*([^\s\n]+) 会捕获到 ** (因为 * 不是空白),
    导致所有工具调用失败.

    修复策略:
    - LLM 输出 **Action:** ssh_exec, 实际捕获的是 **
    - 修复: 检测常见 Markdown 装饰并替换为正确的工具名.
    - 启发式: 如果 action 全是 Markdown 字符 (**, *, `, :, 等), 尝试从 input_match 后面的内容找工具名.
    """
    if not action:
        return action
    # 情况 1: action 全是 Markdown 字符, 没有任何字母数字
    if not any(c.isalnum() or c == "_" for c in action):
        # 返回空串, 让调用方处理 (e.g. fallback regex)
        return ""
    # 情况 2: 前后有少量 Markdown 装饰 (e.g. `ssh_exec`)
    cleaned = action.strip("*`")
    # 去除尾部 : 和空白 (e.g. "ssh_exec:" -> "ssh_exec")
    cleaned = cleaned.rstrip(":").strip()
    return cleaned


def parse_llm_output(text: str) -> ParsedAction:
    """解析 LLM 输出为 ParsedAction.

    解析优先级：
    1. Final Answer -> is_final=True
    2. Action + Action Input -> needs_tool=True
    3. 都缺失 -> is_valid=False

    容错：
    - 字段大小写不敏感
    - Action Input 可被 ```json``` 包裹
    - Thought 可选
    """
    if not text or not text.strip():
        return ParsedAction(is_valid=False, parse_error="empty output")

    thought_match = _RE_THOUGHT.search(text)
    thought = thought_match.group(1).strip() if thought_match else ""

    # Thought 回退 — LLM (deepseek-v4-flash) 经常省略 "Thought:" 前缀
    # 直接输出 "Action: ..." 导致 thought 为空, agent 无推理盲动.
    # 回退策略: 若无 "Thought:" 前缀, 取 "Action:"/"Final Answer:" 前的文本作为 thought.
    # 要求: Action:/Final Answer: 前必须有换行 + 至少 1 字符, 避免纯 Action 文本被误抓.
    if not thought:
        _re_prefix_split = re.compile(
            r"^\s*(.+?)(?=\n\s*(?:Action|Final\s*Answer)\s*:)",
            re.DOTALL,
        )
        m = _re_prefix_split.search(text)
        if m and m.group(1).strip():
            thought = m.group(1).strip()

    # 优先判断 Final Answer
    final_match = _RE_FINAL.search(text)
    if final_match:
        answer = final_match.group(1).strip()
        # 去除可能的尾随引号
        answer = answer.strip("`\"'")
        return ParsedAction(
            thought=thought,
            is_final=True,
            final_answer=answer,
        )

    # Action + Action Input
    action_match = _RE_ACTION.search(text)
    input_match = _RE_ACTION_INPUT.search(text)
    # 别名回退 (Input:/Args:/参数: 等)
    if not input_match:
        input_match = _RE_ACTION_INPUT_ALT.search(text)
    # 若 Action 匹配但 Action Input 仍缺, 尝试从 Action 行后提取首个 JSON 对象
    # 适用场景: LLM 输出 "Action: http_request\n{"url":"..."}" 漏写 "Action Input:" 前缀
    # 用配平提取替代贪婪 {.*} (后跟含 {} 文本时会截错)
    if action_match and not input_match:
        json_text = _extract_balanced_json(text)
        if json_text:
            class _Stub:
                pass
            stub = _Stub()
            stub.group = lambda _i=1: json_text
            input_match = stub
    if action_match and input_match:
        # strip Markdown artifacts from action
        # LLM (deepseek-chat) 经常输出 `**Action:** ssh_exec`,
        # regex 捕获 `**` 当 action. rstrip 末尾的 * / ` / : 修复.
        action = _strip_markdown_artifacts(action_match.group(1).strip())
        # action_input 鲁棒清洗 (Thought 混入/特殊字符/单引号容错)
        action_input = _clean_action_input(_strip_code_fence(input_match.group(1)))
        return ParsedAction(
            thought=thought,
            action=action,
            action_input=action_input,
        )

    # 解析失败
    missing = []
    if not action_match:
        missing.append("Action")
    if not input_match:
        missing.append("Action Input")
    return ParsedAction(
        thought=thought,
        is_valid=False,
        parse_error=f"missing fields: {', '.join(missing)}",
    )


# ============ 引擎 ============

@dataclass
class ReActStep:
    """单步执行记录."""

    step_no: int
    thought: str = ""
    action: str = ""
    action_input: str = ""
    observation: str = ""
    is_final: bool = False
    final_answer: str = ""
    is_error: bool = False
    error_msg: str = ""
    timestamp: float = 0.0  # 单调时钟（time.monotonic），用于时间线计算

    def to_dict(self) -> dict[str, Any]:
        """序列化为 dict（用于 trajectory JSON 持久化）."""
        return {
            "step_no": self.step_no,
            "thought": self.thought,
            "action": self.action,
            "action_input": self.action_input,
            "observation": self.observation,
            "is_final": self.is_final,
            "final_answer": self.final_answer,
            "is_error": self.is_error,
            "error_msg": self.error_msg,
            "timestamp": self.timestamp,
        }


@dataclass
class ReActResult:
    """ReAct 循环最终结果."""

    success: bool
    final_answer: str = ""
    steps: list[ReActStep] = field(default_factory=list)
    total_tokens: int = 0
    fail_reason: str = ""
    raw_outputs: list[str] = field(default_factory=list)
    started_at: float = 0.0  # 任务开始时间戳（time.monotonic）
    ended_at: float = 0.0  # 任务结束时间戳（time.monotonic）
    task: str = ""  # 任务描述（便于报告生成）

    @property
    def step_count(self) -> int:
        return len(self.steps)

    @property
    def elapsed_seconds(self) -> float:
        """任务总耗时（秒），无时间戳时返回 0."""
        # 用 > 0 判断 ended_at，started_at 可以为 0.0（合法值）
        if self.ended_at > 0 and self.ended_at >= self.started_at:
            return self.ended_at - self.started_at
        return 0.0


def _tool_map(tools: list[Tool]) -> dict[str, Tool]:
    """构建 name → Tool 映射 (含别名).

    WING-Goose: docker 工具主名与 Kali 经验一致 (ssh_exec 等), docker_* 为别名.
    LLM 无论用经验中的旧名还是 docker 前缀名, 都能命中同一工具.
    主名优先: 同名时先注册的 (主名) 保留.
    """
    m: dict[str, Tool] = {}
    for t in tools:
        m.setdefault(t.name, t)
        for a in getattr(t, "aliases", ()) or ():
            m.setdefault(a, t)
    return m


class ReActEngine:
    """ReAct 推理引擎.

    用法：
        engine = ReActEngine(llm=LLMClient(...), tools=default_tools())
        result = engine.run("获取 http://ctf.example/ 的 flag")
    """

    def __init__(
        self,
        llm: LLMClient,
        tools: list[Tool],
        *,
        max_steps: int = 35,
        # 3→5 — 并发多 agent 抢 LLM API 时输出质量波动,
        # 3 次格式失败易误杀深入思考中的 agent (hard 并发测试 5/6 题各有一路
        # "连续 3 次格式解析失败"). 5 次容错 + 重试注入更稳.
        max_format_errors: int = 5,
        max_rounds: int = 10,
        model: str | None = None,
        temperature: float = 0.0,
        system_prompt: str | None = None,
        mid_term: MidTermMemory | None = None,
        long_term: LongTermMemory | None = None,
        task_id: str | None = None,
        skip_hyde: bool = False,
        breaker: CircuitBreaker | None = None,
        on_step: Callable[[ReActStep], None] | None = None,
        failed_cache: FailedTrajectoryCache | None = None,
        challenge_id: str | None = None,  # 用于失败记忆检索
        challenge_type: str | None = None,  # 阶段 1.3: cross-challenge 知识共享
        challenge_difficulty: str | None = None,  # 阶段 1.3
        skill_library: Any = None,  # 持续学习 Skill 库，注入相关技能
        planner: Any = None,  # 任务拆解 (CHAP Planner)
        force_max_thinking: bool = False,  # 重试时强制 max 思考强度
        # 多次提交机制 — 找到答案后通过 callback 提交, 失败则继续循环
        submission_handler: Callable[[str], tuple[bool, str]] | None = None,
        max_submissions: int = 1,  # 单轮最大提交次数
        coordinator: Any = None,  # 巡查指导器
        on_coordinator: Callable[[Any, int], None] | None = None,  # 巡查日志回调
        flag_verifier: Any = None,  # 提交前 flag 验证 (代码机制 + LLM)
        bus: Any = None,  # WING-Goose: 消息总线 (跨 agent 兄弟发现共享)
        bus_agent_id: str = "",  # 本 agent 在总线中的标识 (用于日志/去重)
        bus_challenge_id: str = "",  # WING-Goose: 总线统一键 (swarm 各风格共享同一总线文件)
        experience_library: Any = None,  # 经验库 (skill_library.json), mid-solve 动态注入
        event_bus: Any = None,  # 渐进式事件化: in-process EventBus (可选, 不影响现有行为)
    ) -> None:
        self.llm = llm
        self._original_tools = list(tools)
        self.tools: dict[str, Tool] = _tool_map(tools)
        self.max_steps = max_steps
        self.max_format_errors = max_format_errors
        self.max_rounds = max_rounds
        self.model = model
        self.temperature = temperature
        self._user_system_prompt = system_prompt
        self._mid_term = mid_term
        self._long_term = long_term
        self._user_task_id = task_id
        self._skip_hyde = skip_hyde
        # 熔断器：未提供时使用默认配置（30 分钟超时 + 重复动作 + 思维死锁检测）
        self.breaker = breaker if breaker is not None else CircuitBreaker()
        self._on_step = on_step
        # 失败轨迹缓存 (默认全局单例)
        self._failed_cache = failed_cache or get_default_cache()
        self._challenge_id = challenge_id
        # 阶段 1.3: cross-challenge 知识共享
        self._challenge_type = challenge_type
        self._challenge_difficulty = challenge_difficulty
        # 持续学习 Skill 库（可选），解题时注入相关技能作为指引
        self._skill_library = skill_library
        # Planner 拆解任务 (CHAP 协议)
        self._planner = planner
        self._planner_plan_text: str = ""  # Planner 拆解结果 (注入到 system prompt)
        self._force_max_thinking = force_max_thinking  # 重试强制 max
        # 多次提交机制
        self._submission_handler = submission_handler
        self._max_submissions = max(1, max_submissions)
        self._coordinator = coordinator  # 巡查指导器
        self._coordinator_guidance = ""   # 当前巡查指导 (注入下一步 prompt)
        # 提交前 flag 验证 (代码机制 + LLM) — 防外部题解污染/幻觉
        self._flag_verifier = flag_verifier
        # MUST 指导持久注入 — 重复注入剩余次数
        # (历史复盘: 协调器 step10 的 MUST 只注入 1 次, agent 忽略后无强制力.
        #  现在 MUST 指导连续注入 must_repeat 步, 且与禁忌拦截配合形成闭环)
        self._must_repeat_left = 0
        # MUST 执行检测 — 记录 MUST 注入时主导动作, 若后续持续重复
        # (未执行指令) 则注入 [强制跳转] 更强阻断 (不依赖禁忌列表, 直接干预).
        self._must_action: str = ""
        self._must_ignore_steps: int = 0
        self._on_coordinator = on_coordinator  # 巡查日志回调
        # 异步事件驱动巡查 — 发起步记录 + 指导来源步 (注入时声明分析基于哪一步)
        self._pending_patrol_step = 0
        self._coordinator_guidance_step = 0
        self._submitted_flags: set[str] = set()  # 已提交 flag 去重
        self._submission_count = 0  # 已提交次数
        self.status: TaskStatus = TaskStatus()
        # WING-Goose: 消息总线 (兄弟发现共享)
        self._bus = bus
        self._bus_agent_id = bus_agent_id
        self._bus_key = bus_challenge_id or (challenge_id or "")  # 总线统一键
        self._bus_since = 0.0  # 已消费到的时间戳
        self._bus_injected_count = 0  # 累计注入条数 (供采纳率统计)
        self._bus_posted_count = 0  # 累计发布条数 (供双向性统计)
        # 经验库 (skill_library.json): mid-solve 动态注入
        self._experience_library = experience_library
        self._injected_exp_ids: set[str] = set()  # 已在 system prompt 注入的 skill ID
        self._exp_cooldown: dict[str, int] = {}  # skill_id → 上次注入的 step_no (10 步冷却)
        # 渐进式事件化: in-process EventBus (可选)
        self._event_bus = event_bus

    def _thinking_extra(self) -> dict[str, Any] | None:
        """按难度+题型选择 reasoning_effort, 通过 extra 传给 LLM.

        判断优先级 (从高到低):
        1. force_max_thinking=True (重试场景, 第一次失败后强制 max)
        2. hard/extreme 难度 → max
        3. medium + reverse/pwn/crypto (深度分析题型) → max
        4. medium + web/misc/forensics/osint (套路化题型) → high
        5. easy → high
        6. 未知难度 → default

        历史依据 (BSidesSF 测试):
        - medium reverse (bug-me/obscuratron) 失败 → 需深度逆向分析
        - medium crypto (dragon-spell) 失败 → 需复杂数学推理
        - medium forensics/misc (toothless/crossworthy) 成功 → 套路化 high 够用

        Returns:
            {"reasoning_effort": "high"/"max"} 或 None
        """
        # 延迟导入避免循环依赖
        try:
            from ctf_agent.config import get_settings
            settings = get_settings()
        except Exception:
            return None
        if not getattr(settings, "enable_thinking_mode", False):
            return None

        # 优先级 1: 重试强制 max
        if self._force_max_thinking:
            return {"reasoning_effort": "max"}

        diff = (self._challenge_difficulty or "").lower().strip()
        ctype = (self._challenge_type or "").lower().strip()

        # 优先级 2: hard/extreme → max
        if diff in ("hard", "extreme"):
            return {"reasoning_effort": settings.thinking_effort_hard if diff == "hard" else settings.thinking_effort_extreme}

        # 优先级 3: medium + 深度分析题型 → max
        # misc 加入 max (实测  misc/medium 用 max 进度更快)
        # reverse/pwn: 逆向/漏洞利用需深度推理; crypto: 密码分析需数学推理; misc: 常有嵌套解密链
        if diff == "medium" and ctype in ("reverse", "re", "pwn", "crypto", "misc"):
            return {"reasoning_effort": "max"}

        # 优先级 4: medium + 套路化题型 → high
        if diff == "medium":
            return {"reasoning_effort": settings.thinking_effort_medium}

        # 优先级 5: easy → high
        if diff == "easy":
            return {"reasoning_effort": settings.thinking_effort_easy}

        # 优先级 6: 未知难度 → default
        return {"reasoning_effort": settings.thinking_effort_default}

    def run(self, task: str) -> ReActResult:
        """执行 ReAct 循环.

        Args:
            task: 任务描述（CTF 题目文本/目标）

        Returns:
            ReActResult，success=True 时 final_answer 非空

        失败时自动存储到 failed_cache, 第二次跑同 challenge_id 时
        通过 _inject_context() 注入失败历史提示。
        """
        try:
            return self._run_inner(task)
        except Exception:
            # 异常路径不存储 (避免污染 cache)
            raise

    def _run_inner(self, task: str) -> ReActResult:
        """run() 的实际实现 (拆分以支持失败 cache 存储)."""
        # 任务 ID：用户指定或自动生成（用于中期记忆索引）
        task_id = self._user_task_id or uuid4().hex[:12]

        # EventBus: engine.started
        if self._event_bus is not None:
            self._event_bus.emit("engine.started", {
                "challenge_id": self._challenge_id or "",
                "challenge_type": self._challenge_type or "",
                "difficulty": self._challenge_difficulty or "",
                "max_steps": self.max_steps,
            })

        # 经验库: 记录已在 system prompt 静态注入的 skill ID (mid-solve 时排除)
        # 解题前静态注入已默认关闭 (题目混淆根因), 此处仅当外部
        # system prompt 显式注入过 skill 时才追踪; 否则 _injected_exp_ids 保持空集,
        # 所有经验可延后到侦查阶段完成后基于实际观测做 mid-solve 动态注入.
        if self._experience_library is not None and self._user_system_prompt is not None:
            try:
                # 探测外部 system prompt 是否含 Skill 注入标记 (只有显式注入才追踪)
                if "积累的解题模式" in self._user_system_prompt:
                    static_skills = self._experience_library.retrieve_for_task(
                        task, self._challenge_type or "", self._challenge_difficulty or ""
                    )
                    self._injected_exp_ids = {s.id for s in static_skills}
            except Exception:  # noqa: BLE001
                pass

        # 工具集：开启中期记忆时自动注册 RememberFactTool
        if self._mid_term is not None:
            extended = list(self._original_tools)
            extended.extend(memory_tools(self._mid_term, task_id))
            self.tools = _tool_map(extended)
        # 否则保持 __init__ 中的 self.tools

        # Planner 拆解任务 (CHAP 协议)
        # 拆解结果格式化为"作战计划"文本, 注入到 system prompt
        # 注意: Planner 失败时静默降级, 不阻断主流程
        if self._planner is not None:
            try:
                subtasks = self._planner.plan(task)
                if subtasks:
                    self._planner_plan_text = self._format_plan(subtasks)
                else:
                    self._planner_plan_text = ""
            except Exception:  # noqa: BLE001
                self._planner_plan_text = ""

        # 基础 system prompt（用户覆盖 or 基于工具集生成）
        # 透传 task + challenge_type + difficulty 用于 Skill 注入
        base_system_prompt = self._user_system_prompt or build_system_prompt(
            list(self.tools.values()),
            task=task,
            challenge_type=self._challenge_type or "",
            difficulty=self._challenge_difficulty or "",
        )

        # RAG 检索：改为**延迟到侦查阶段后**基于实际观测注入,
        # 不再在任务开始时基于 task 描述 (极简题面) 匹配历史 writeup —
        # 题面仅含 flag 格式+地址时, 静态匹配会命中无关套路 (题目混淆根因,
        # 如 ouroboros 匹配到 MPEG 题). 侦查后注入见循环内 step_no>=8 分支.
        rag_context = ""

        # 初始化短期记忆（首笔 context 注入：facts + RAG）
        memory = ShortTermMemory(
            system_prompt=self._inject_context(
                base_system_prompt, task_id, rag_context, task=task
            ),
            task=build_task_prompt(task),
            max_rounds=self.max_rounds,
        )
        self.status = TaskStatus()
        self.status.mark_executing()
        started_at = time.monotonic()
        # 重置熔断器（开始新一轮任务）
        self.breaker.reset()

        steps: list[ReActStep] = []
        raw_outputs: list[str] = []
        total_tokens = 0
        consecutive_format_errors = 0
        # 跟踪连续空 observation 次数（含"模型端空输出"与"obs 端空"）
        consecutive_null_obs = 0
        # 模型端空输出"免费重答"配额（注入恢复 hint 但不计入 format_errors）
        consecutive_empty_outputs = 0
        max_empty_outputs_before_breaker = 2  # 连续 2 次仍空才计入 format_errors

        # 修复加步 (extend_steps) 从未生效的 bug —
        # 之前 `for step_no in range(1, self.max_steps + 1)` 的 range 在进入
        # 循环时一次性求值, 即使协调器 extend_steps 更新了 self.max_steps
        # (self.max_steps = self.breaker.max_steps), for 循环也不会延长,
        # 方向正确的 agent 到原上限就被硬杀 (历史复盘: 协调器建议加步
        # 但实际无效果).
        # (用户要求: 尽量不做严格硬截断, 优先 LLM 软截断):
        # 改为 while True + 进展感知软截断 —
        # - 每步动态判断 max_steps (extend_steps 立即生效)
        # - 超过 max_steps 后不立即硬停, 由 breaker 进展感知决定:
        #   持续有实质进展 (新的非空 observation) 则继续, 仅当无进展
        #   超过宽限期才兜底退出. 时间维度由 breaker 时间熔断
        #   (max_seconds + progress_grace, 及 hard_max 3x 保险) 兜底.
        step_no = 1
        while True:
            # 步数软截断兜底: 超限且无进展才退出, 有进展由时间熔断 (3x) 兜底
            if step_no > self.max_steps:
                if self.breaker is not None and hasattr(self.breaker, "has_recent_progress"):
                    if not self.breaker.has_recent_progress():
                        break
                else:
                    break  # 无 breaker → 保持原步数硬上限行为
            self.status.step_count = step_no
            step_timestamp = time.monotonic()

            # 检查调用器 stop 信号 (每步开始前)
            # 使用独立模块 ctf_agent.stop_signal 避免循环导入 (solve ↔ react)
            try:
                from ctf_agent.stop_signal import is_stop_requested
                if is_stop_requested():
                    return ReActResult(
                        success=False,
                        final_answer="",
                        fail_reason="收到调用器 stop 信号, 主动停止",
                        steps=steps,
                        total_tokens=total_tokens,
                        raw_outputs=raw_outputs,
                        started_at=started_at,
                        ended_at=time.monotonic(),
                        task=task,
                    )
            except Exception:
                pass  # 非子进程模式 (直接调用), 无 stop 信号检查

            # /33: 巡查指导器 — 异步事件驱动 (LLM 驱动的智能旁观者)
            # 发起: 达到巡查时机即后台发起分析, 不阻塞 agent 行动;
            # 召回: 分析完成后在后续步事件召回注入 (如第 10 步发起、第 12 步注入).
            # 发起节奏 = 上一次注入结果后 check_interval 步 (默认 5), 队列上限 1 防叠加.
            live_errs = 0
            for s in reversed(steps[-8:]):
                if getattr(s, "is_error", False):
                    live_errs += 1
                else:
                    break
            if self._coordinator is not None and self._coordinator.should_check(
                step_no, self.max_steps, live_errors=live_errs
            ):
                try:
                    # 构造轨迹快照给 coordinator 分析 (含 observation, 供 LLM 深度分析)
                    traj = [
                        {
                            "thought": getattr(s, "thought", "") or "",
                            "action": getattr(s, "action", "") or "",
                            "action_input": getattr(s, "action_input", "") or "",
                            "observation": (getattr(s, "observation", "") or "")[:500],
                            "is_error": getattr(s, "is_error", False),
                        }
                        for s in steps
                    ]
                    fired = self._coordinator.fire_async_analysis(
                        traj,
                        challenge_type=self._challenge_type or "",
                        challenge_difficulty=self._challenge_difficulty or "",
                        task_desc=task,
                        step_no=step_no,
                        max_steps=self.max_steps,
                    )
                    if fired:
                        self._pending_patrol_step = step_no  # 记录发起步 (注入时声明来源)
                except Exception:
                    pass  # 巡查异常不影响主流程

            # 事件召回 — 消费已完成的异步巡查结果并应用 (注入到后续步)
            if self._coordinator is not None:
                try:
                    async_guidance = self._coordinator.consume_pending_guidance(step_no)
                    if async_guidance is not None:
                        self._apply_coordinator_guidance(async_guidance, self._pending_patrol_step)
                except Exception:
                    pass  # 消费异常不影响主流程

            # 总指挥指令注入 (战略层能力) — 每步检查,
            # 有新 directive 时立即注入 (MUST 走持久重复机制, 优先级高于巡查输出).
            # 无新指令零开销 (check_directives 返回空).
            if self._coordinator is not None and getattr(
                self._coordinator, "_commander_enabled", False
            ):
                try:
                    cmd_guidance = self._coordinator.check_commander_directives()
                    if cmd_guidance is not None:
                        self._apply_coordinator_guidance(cmd_guidance, step_no)
                except Exception:
                    pass  # 总指挥指令异常不影响主流程

            # (WING-Corvus P1): P1 侦查阶段每 5 步向总指挥汇报进度
            # (当前发现/下一步计划/是否卡死). 总指挥据此监控三路侦查进度:
            # - 某路长时间无进展 → 介入调整
            # - 三路全部完成侦查 (recon_done) → 整合全局情报摘要并确定主方向 → P2
            if self._coordinator is not None and getattr(
                self._coordinator, "_commander_enabled", False
            ):
                try:
                    self._coordinator.report_p1_progress_if_due(step_no, steps[-3:])
                except Exception:
                    pass  # 进度汇报异常不影响主流程

            # 刷新 system prompt：每轮重新注入最新关键事实（防丢）
            # RAG context 是静态的，但 facts 可能因 remember_fact 而新增
            if self._mid_term is not None or rag_context:
                memory.update_system_prompt(
                    self._inject_context(
                        base_system_prompt, task_id, rag_context, task=task
                    )
                )

            # 注入巡查指导 (如果有)
            # MUST 指导持久注入 — 未执行完之前持续重复强调
            if self._coordinator_guidance:
                # 异步事件驱动 — 注入时声明分析来源步数 (避免过时信息误导;
                # 分析基于发起时轨迹快照, 实际注入可能已滞后若干步)
                source_tag = ""
                src_step = getattr(self, "_coordinator_guidance_step", 0)
                if src_step > 0:
                    lag = max(0, step_no - src_step)
                    source_tag = (
                        f"\n[巡查来源] 此指导基于 step {src_step} 的轨迹分析结果"
                        f" (注入于 step {step_no}, 滞后 {lag} 步); "
                        f"若与你的最新进展冲突, 以最新观察为准."
                    )
                if self._must_repeat_left > 0:
                    # MUST 执行检测 — 记录注入时主导动作; 若后续持续重复
                    # 相同动作 (未执行 MUST), 注入 [强制跳转] 更强阻断.
                    recent_actions = [getattr(s, "action", "") or "" for s in steps[-3:]]
                    if not self._must_action and recent_actions:
                        self._must_action = recent_actions[-1]
                    if self._must_action:
                        if recent_actions and recent_actions[-1] == self._must_action:
                            self._must_ignore_steps += 1
                        else:
                            self._must_ignore_steps = 0  # 已换动作 (可能在执行指令)
                    if self._must_ignore_steps >= 2:
                        # 更强阻断: 直接要求切换, 并清空重复注入状态
                        force_jump = (
                            f"\n[强制跳转] 你已连续 {self._must_ignore_steps} 步仍在执行 "
                            f"'{self._must_action}' (与 [MUST] 指令相悖). "
                            f"立即停止该操作, 必须切换到完全不同的方法. 此路径已封锁, 不得再尝试."
                        )
                        memory.add_user_message(force_jump)
                        self._must_action = ""
                        self._must_ignore_steps = 0
                        self._must_repeat_left = 0
                    else:
                        persist_hint = (
                            f"\n[MUST][重复执行] 上一条 [MUST] 指令必须立即执行"
                            f" (还剩 {self._must_repeat_left} 次强调): "
                            f"不要继续当前思路, 按指令切换方向."
                        )
                        memory.add_user_message(self._coordinator_guidance + source_tag + persist_hint)
                        self._must_repeat_left -= 1
                else:
                    memory.add_user_message(self._coordinator_guidance + source_tag)
                    self._coordinator_guidance = ""  # 用完即清

            # WING-Goose: 消息总线 — 每 5 步 check 兄弟发现 (高置信度) 并注入
            # T4 优化: check_sanitized 消毒命令级细节为方向性线索, 避免 agent 反复验证
            if self._bus is not None and step_no % 5 == 0:
                try:
                    visible = self._bus.check_sanitized(self._bus_key, since=self._bus_since)
                    if visible:
                        self._bus_since = max(m.get("ts", 0) for m in visible)
                        lines = []
                        for m in visible:
                            lines.append(
                                f"- (来自 {m.get('agent', '兄弟')} [{m.get('level', 'LIKELY')}]) "
                                f"{m.get('content', '')}"
                            )
                        bus_block = (
                            "\n[兄弟发现] 其他并行 agent 已发现以下方向性线索"
                            " (仅作参考方向, 需自行探索验证):\n"
                            + "\n".join(lines)
                        )
                        memory.add_user_message(bus_block)
                        self._bus_injected_count += len(visible)

                    # 强制分享关键发现 — 每 5 步注入协作义务提示,
                    # 要求 agent 将已验证的关键线索 (常量/偏移/算法/格式) 发布到总线.
                    # 防止"各自独立解题、共享仅互相借鉴" (雁阵 v2 协作升级点 1):
                    # 战术层专注解题, 但关键事实必须回流共享池供战略层/兄弟参考.
                    share_duty = (
                        "\n[协作义务] 请检查你最近几步是否发现了可供兄弟解题器直接复用的"
                        "关键线索 (如: 加密算法与 key/偏移、flag 格式、可复现的绕过方法、"
                        "已确认的死路). 若有, 请用 share_finding 工具发布到共享总线 "
                        "(kind=fact/finding), 一句话即可. 若已发布过或暂无新线索, 忽略本条."
                    )
                    memory.add_user_message(share_duty)
                except Exception:  # noqa: BLE001 - 总线异常不影响主流程
                    pass

            # 强制回答检查: 每 5 步检测来自兄弟 agent 且本 agent 尚未回答的提问
            # 收到提问后必须回复 (即使回答"不知道"), 防止提问方卡死等待
            if self._bus is not None and step_no % 5 == 0:
                try:
                    if hasattr(self._bus, 'check_findings'):
                        all_entries, _ = self._bus.check_findings(
                            cursor=0, task_id=self._bus_key, kind=None)
                    elif hasattr(self._bus, 'check'):
                        all_entries, _ = self._bus.check(
                            cursor=0, task_id=self._bus_key, kind=None)
                    else:
                        all_entries = []
                    answered_ids = {e.reply_to for e in all_entries
                                    if e.kind == "answer"
                                    and e.agent_id == self._bus_agent_id}
                    pending = [e for e in all_entries
                               if e.kind == "question"
                               and e.agent_id != self._bus_agent_id
                               and e.id not in answered_ids]
                    if pending:
                        qlines = [
                            "[MUST] 你收到了来自兄弟解题器的提问, 必须立即回答:"]
                        for q in pending:
                            qlines.append(
                                f"  - 提问 #{q.id} (agent={q.agent_id}): "
                                f"{q.content}")
                        qlines.append(
                            "请使用 share_finding 工具 (kind=answer, "
                            "reply_to=提问id) 回答上述每一个提问。")
                        qlines.append(
                            "如果你不清楚答案, 必须回答\"不知道\"或"
                            "\"暂无相关信息\", 不得忽略提问。")
                        memory.add_user_message("\n".join(qlines))
                except Exception:  # noqa: BLE001 - 总线异常不影响主流程
                    pass

            # 做题中动态检索 skill (每 8 步, 基于累积 observation)
            # 当 agent 收集到足够线索后, 用线索文本匹配 pattern_features,
            # 找出套路相同的 skill 并注入提示 (基于套路而非题目名称匹配)
            if (
                self._skill_library is not None
                and step_no % 8 == 0
                and step_no >= 8
                and len(steps) >= 4
            ):
                try:
                    # 构造当前累积的 observation 文本 (题目 + 最近 6 步输出)
                    recent_obs = [task]
                    for s in steps[-6:]:
                        if s.observation:
                            recent_obs.append(s.observation)
                    obs_text = "\n".join(recent_obs)
                    skill_hint = self._skill_library.format_for_mid_solve(
                        obs_text, category=self._challenge_type
                    )
                    if skill_hint:
                        memory.add_user_message(skill_hint)
                except Exception:  # noqa: BLE001 - 动态检索失败不阻断
                    pass

            # 经验库 (skill_library.json) mid-solve 动态注入
            # 与 md 系统 parallel, 基于累积 observation 匹配相关经验
            # 只注入未在 system prompt 出现过的新经验, 避免重复
            # 10 步冷却: 同一 skill 注入后 10 步内不再重复注入
            if (
                self._experience_library is not None
                and step_no % 8 == 0
                and step_no >= 8
                and len(steps) >= 4
            ):
                try:
                    from ctf_agent.skills.injector import format_mid_solve_injection

                    recent_obs = [task]
                    for s in steps[-6:]:
                        if s.observation:
                            recent_obs.append(s.observation)
                    obs_text = "\n".join(recent_obs)
                    # 冷却期过滤: 排除最近 10 步内已注入的 skill
                    cooled_ids = {
                        sid for sid, last_step in self._exp_cooldown.items()
                        if step_no - last_step < 10
                    }
                    exp_skills = self._experience_library.retrieve_for_mid_solve(
                        self._challenge_type or "",
                        obs_text,
                        exclude_ids=self._injected_exp_ids | cooled_ids,
                        top_k=2,
                        min_score=0.3,
                    )
                    if exp_skills:
                        exp_hint = format_mid_solve_injection(exp_skills)
                        if exp_hint:
                            memory.add_user_message(exp_hint)
                            for s in exp_skills:
                                self._injected_exp_ids.add(s.id)
                                self._exp_cooldown[s.id] = step_no
                except Exception:  # noqa: BLE001 - 经验库注入失败不阻断
                    pass

            # RAG (历史 writeup) 延迟注入 — 侦查阶段完成后
            # 基于实际观测检索 (取代任务开始时的 task 描述静态匹配, 防题目混淆)
            if (
                self._long_term is not None
                and step_no % 8 == 0
                and step_no >= 8
                and len(steps) >= 4
            ):
                try:
                    recent_obs = [task]
                    for s in steps[-6:]:
                        if s.observation:
                            recent_obs.append(s.observation)
                    obs_text = "\n".join(recent_obs)[:1500]
                    retriever = RAGRetriever(
                        llm=self.llm,
                        long_term=self._long_term,
                        model=self.model,
                        skip_hyde=self._skip_hyde,
                    )
                    rag_hint = retriever.retrieve(obs_text)
                    if rag_hint:
                        memory.add_user_message(
                            "[历史经验参考] 基于当前观测检索到相似历史 writeup (仅作思路参考, 非答案):\n"
                            + rag_hint[:1500]
                        )
                except Exception:  # noqa: BLE001 - RAG 注入失败不阻断
                    pass

            # LLM 推理（每次从短期记忆获取裁剪后的消息列表）
            # 按难度注入 reasoning_effort (thinking_mode)
            # LLM 调用异常容错 — 中途 API 故障不能整题 0 步失败:
            #   flash 失败 → 重试 → pro 降级 → 仍失败则注入提示跳过本步继续 (不崩溃)
            try:
                chat_result = self.llm.chat(
                    memory.get_messages(),
                    model=self.model,
                    temperature=self.temperature,
                    extra=self._thinking_extra(),
                )
            except Exception as _llm_err1:  # noqa: BLE001
                time.sleep(2)  # 网络抖动瞬时恢复
                try:
                    chat_result = self.llm.chat(
                        memory.get_messages(),
                        model=self.model,
                        temperature=self.temperature,
                        extra=self._thinking_extra(),
                    )
                except Exception as _llm_err2:  # noqa: BLE001
                    time.sleep(2)
                    try:
                        # 第 3 次: 降级 pro 重试 (flash 全线故障时的最后手段)
                        chat_result = self.llm.chat(
                            memory.get_messages(),
                            model=self.model,
                            temperature=self.temperature,
                            extra=self._thinking_extra(),
                            model_tier="pro",
                        )
                    except Exception as _llm_err3:  # noqa: BLE001
                        # 全部失败: 注入提示并跳过本步, 保持循环继续 (breaker 熔断兜底)
                        memory.add_user_message(
                            f"⚠️ LLM API 暂时不可用 (多次重试失败: "
                            f"{type(_llm_err3).__name__}: {_llm_err3}).\n"
                            "请保持当前解题思路, 下一步继续分析, 不要重复之前的动作."
                        )
                        step_no += 1
                        continue
            total_tokens += chat_result.usage.total_tokens
            # 熔断器记录本次 LLM 调用（用于成本熔断，README §3.5.2 第 4 维）
            self.breaker.record_llm_call(
                chat_result.usage.total_tokens, self.model
            )
            raw_outputs.append(chat_result.content)

            # 解析
            parsed = parse_llm_output(chat_result.content)

            # 终止：Final Answer
            if parsed.is_final:
                # + 反幻觉兜底 — 无任何工具调用直接 Final = 幻觉
                # (Triplet_Tweak 根因: LLM 未读附件直接猜答案;
                #  hard_r2 复现 — 第 2 步无工具调用直接 Final 编造 flag)
                # 拒绝并注入 hint 让 LLM 先收集信息 (所有题型强制 ≥1 次工具调用)
                # 排除 is_error 的步骤 (action_input JSON 解析失败不算有效工具调用)
                if not any(s.action and not s.is_error for s in steps):
                    memory.add_round(
                        chat_result.content,
                        "⚠️ 你在没有任何工具调用的情况下直接给出了 Final Answer, 这是幻觉!\n"
                        "CTF 题目禁止凭记忆或猜测提交 flag. 你必须先调用至少 1 个工具 "
                        "(ssh_exec/ssh_python/file_read/strings 等) 探测靶机或读取附件, "
                        "通过工具观测到 flag 文本后再提交 Final Answer.\n\n"
                        "请重新开始: 先调用 1 个信息收集工具."
                    )
                    consecutive_format_errors += 1
                    step_no += 1
                    continue
                step = ReActStep(
                    step_no=step_no,
                    thought=parsed.thought,
                    is_final=True,
                    final_answer=parsed.final_answer,
                    timestamp=step_timestamp,
                )
                steps.append(step)
                self._notify(step)

                # 多次提交机制 — 找到答案后通过 callback 提交, 失败则继续循环
                flag_candidate = parsed.final_answer.strip()
                if self._submission_handler is not None:
                    # 去重检查: 已提交过的答案直接驳回
                    if flag_candidate in self._submitted_flags:
                        memory.add_round(
                            chat_result.content,
                            f"⛔ 答案已被驳回过: {flag_candidate}\n"
                            f"已提交 {self._submission_count}/{self._max_submissions} 次, "
                            f"已驳回答案: {list(self._submitted_flags)}\n\n"
                            f"请重新分析, 找出一个**不同的**答案. "
                            f"检查之前的工具输出是否有遗漏的线索, 尝试不同的解题路径."
                        )
                        consecutive_format_errors += 1
                        step_no += 1
                        continue

                    # 提交次数上限检查 — 不直接退出, 继续循环分析
                    # 用户要求: 即使连续提交 20 次错误答案也不要直接退出
                    # 机制: 达上限后不再调用 submission_handler, 注入指导让 agent 继续工具分析
                    # 安全保护: increment consecutive_format_errors, 防止 agent 反复 Final Answer 死循环
                    # (agent 调用工具后 consecutive_format_errors 会重置为 0)
                    if self._submission_count >= self._max_submissions:
                        if not getattr(self, '_submissions_exhausted_notified', False):
                            self._submissions_exhausted_notified = True
                            memory.add_round(
                                chat_result.content,
                                f"⚠️ 已达提交次数上限 ({self._max_submissions} 次), 后续 Final Answer 将不再提交到平台.\n"
                                f"请继续调用工具深入分析题目, 寻找新的线索和不同的解题路径.\n"
                                f"已驳回答案: {list(self._submitted_flags)}\n\n"
                                f"重要: 不要重复提交相同答案. 如果确认找到正确答案, 可以用 Final Answer 输出, 系统会记录."
                            )
                        else:
                            memory.add_round(
                                chat_result.content,
                                f"⛔ 提交已用完, 不要再给 Final Answer! 继续调用工具分析题目, 寻找新线索."
                            )
                        consecutive_format_errors += 1
                        step_no += 1
                        continue

                    # 提交前 flag 验证 (代码机制 + LLM) —
                    # 防外部题解 (writeup/官方仓库) 污染与幻觉. 验证不通过不消耗提交次数,
                    # 注入反馈让 agent 继续从靶机/附件真实观测获取 flag.
                    if self._flag_verifier is not None:
                        v_res = self._flag_verifier.verify(flag_candidate, steps)
                        if not v_res.passed:
                            memory.add_round(
                                chat_result.content,
                                f"⛔ flag 验证未通过 (提交前轨迹检查): {v_res.reason}\n"
                                f"本次不消耗提交次数 (剩余 {self._max_submissions - self._submission_count}).\n"
                                f"请重新基于靶机/附件的**真实工具观测**分析, "
                                f"从靶机响应或附件内容中提取 flag 后再提交."
                            )
                            consecutive_format_errors += 1
                            step_no += 1
                            continue

                    # 调用 submission_handler 提交答案
                    self._submitted_flags.add(flag_candidate)
                    self._submission_count += 1
                    try:
                        is_correct, feedback = self._submission_handler(flag_candidate)
                    except Exception as e:  # noqa: BLE001
                        is_correct, feedback = False, f"提交异常: {e}"

                    if is_correct:
                        # 提交成功 → 正常结束
                        self.status.mark_done(parsed.final_answer)
                        self._clear_failed_if_solved()
                        return ReActResult(
                            success=True,
                            final_answer=parsed.final_answer,
                            steps=steps,
                            total_tokens=total_tokens,
                            raw_outputs=raw_outputs,
                            started_at=started_at,
                            ended_at=time.monotonic(),
                            task=task,
                        )
                    else:
                        # 提交失败 → 注入反馈, 继续循环 (不重新开始)
                        remaining = self._max_submissions - self._submission_count
                        memory.add_round(
                            chat_result.content,
                            f"❌ 答案提交失败: {flag_candidate}\n"
                            f"反馈: {feedback}\n"
                            f"剩余提交次数: {remaining}/{self._max_submissions}\n"
                            f"已驳回答案: {list(self._submitted_flags)}\n\n"
                            f"⚠️ 不要重复提交相同答案! 请基于反馈重新分析:\n"
                            f"1. 仔细阅读反馈线索\n"
                            f"2. 重新检查工具输出, 寻找遗漏\n"
                            f"3. 尝试不同的解题路径\n"
                            f"4. 确保新答案与已驳回的不同"
                        )
                        step_no += 1
                        continue

                # 无 submission_handler (传统模式) 或 max_submissions=1 → 直接成功
                self.status.mark_done(parsed.final_answer)
                # 阶段 1.2: 成功后清理失败历史(避免成功解出后再次跑时还注入旧的失败提示)
                self._clear_failed_if_solved()
                return ReActResult(
                    success=True,
                    final_answer=parsed.final_answer,
                    steps=steps,
                    total_tokens=total_tokens,
                    raw_outputs=raw_outputs,
                    started_at=started_at,
                    ended_at=time.monotonic(),
                    task=task,
                )

            # 解析失败处理
            if not parsed.is_valid:
                # 修复：区分"模型端空输出"与"格式错乱"
                # 场景：模型连续返回空字符串/无 Thought+Action+Input
                # 旧实现会直接计入 format_errors 触发熔断；
                # 新实现给"空输出"2 次免费重答机会（注入恢复 hint），超过才计入 format_errors
                if parsed.parse_error == "empty output":
                    consecutive_empty_outputs += 1
                    step = ReActStep(
                        step_no=step_no,
                        thought="",
                        is_error=True,
                        error_msg="empty output",
                        timestamp=step_timestamp,
                    )
                    steps.append(step)
                    self._notify(step)

                    # 熔断器也要检查（时间/成本）
                    breaker_action = self.breaker.check(step)
                    if breaker_action.should_terminate:
                        return self._fail_and_return(
                            reason=breaker_action.reason,
                            steps=steps,
                            total_tokens=total_tokens,
                            raw_outputs=raw_outputs,
                            started_at=started_at,
                            task=task,
                        )

                    if consecutive_empty_outputs > max_empty_outputs_before_breaker:
                        # 连续 3 次仍空，升级为正式格式错误（触发熔断）
                        consecutive_format_errors += 1
                        # 先检查熔断（与"格式错乱"路径一致）
                        if consecutive_format_errors >= self.max_format_errors:
                            reason = f"连续 {consecutive_format_errors} 次格式解析失败（含空输出）"
                            return self._fail_and_return(
                                reason=reason,
                                steps=steps,
                                total_tokens=total_tokens,
                                raw_outputs=raw_outputs,
                                started_at=started_at,
                                task=task,
                            )
                        # 走和"格式错乱"一样的 FORMAT_ERROR_HINT 路径
                        hint = breaker_action.message if breaker_action.should_inject_hint else ""
                        error_obs = FORMAT_ERROR_HINT
                        if hint:
                            error_obs = f"⚠️ {hint}\n\n{error_obs}"
                        memory.add_round(chat_result.content, error_obs)
                        step_no += 1
                        continue
                    else:
                        # 免费重答：注入 NULL_OBSERVATION_HINT 作为 "observation"，让 LLM 重新输出
                        # 用 tool 失败模板包装，LLM 会按 ReAct 模式重新生成 Thought+Action
                        recovery_obs = (
                            f"⚠️ 已连续 {consecutive_empty_outputs} 步 LLM 输出为空。\n\n"
                            f"{NULL_OBSERVATION_HINT}"
                        )
                        memory.add_round(
                            chat_result.content, OBSERVATION_TEMPLATE.format(observation=recovery_obs)
                        )
                        step_no += 1
                        continue
                else:
                    # 真实格式错乱（missing fields）—— 立即计入 format_errors
                    consecutive_format_errors += 1
                    consecutive_empty_outputs = 0  # 任意非空输出重置空输出计数
                    step = ReActStep(
                        step_no=step_no,
                        thought=parsed.thought,
                        is_error=True,
                        error_msg=parsed.parse_error,
                        timestamp=step_timestamp,
                    )
                    steps.append(step)
                    self._notify(step)

                    # 熔断检测（格式错误步骤也要检查时间/思维死锁）
                    breaker_action = self.breaker.check(step)
                    if breaker_action.should_terminate:
                        return self._fail_and_return(
                            reason=breaker_action.reason,
                            steps=steps,
                            total_tokens=total_tokens,
                            raw_outputs=raw_outputs,
                            started_at=started_at,
                            task=task,
                        )

                    if consecutive_format_errors >= self.max_format_errors:
                        reason = f"连续 {consecutive_format_errors} 次格式解析失败"
                        return self._fail_and_return(
                            reason=reason,
                            steps=steps,
                            total_tokens=total_tokens,
                            raw_outputs=raw_outputs,
                            started_at=started_at,
                            task=task,
                        )
                    # 提示 LLM 修正格式（如熔断器有 hint，前置注入）
                    hint = breaker_action.message if breaker_action.should_inject_hint else ""
                    error_obs = FORMAT_ERROR_HINT
                    if hint:
                        error_obs = f"⚠️ {hint}\n\n{error_obs}"
                    memory.add_round(chat_result.content, error_obs)
                    step_no += 1
                    continue

            # 成功解析——重置所有错误计数
            consecutive_format_errors = 0
            consecutive_empty_outputs = 0

            # 禁忌操作拦截 — 工具执行前检查协调器禁忌列表
            # (历史复盘: 协调器 step10 否定 MD5 爆破假设, 但 agent 继续 20 步.
            #  现在确认无效的操作在巡查间隔之外也被立即拦截, 不再浪费步数)
            if self._coordinator is not None and hasattr(self._coordinator, "intercept_forbidden"):
                try:
                    block_msg = self._coordinator.intercept_forbidden(
                        parsed.action, parsed.action_input
                    )
                    if block_msg:
                        memory.add_round(chat_result.content, block_msg)
                        step_no += 1
                        continue
                except Exception:  # noqa: BLE001 - 拦截失败不影响主流程
                    pass

            # 调用工具
            observation = self._invoke_tool(parsed.action, parsed.action_input)
            # 工具异常 → 战略层死路检测
            # (环境缺失类错误连续 2 次 → 自动切换方向 + dead_end 事后汇报, 不等总指挥轮询)
            if observation.is_error and self._coordinator is not None:
                try:
                    on_err = getattr(self._coordinator, "on_tool_error", None)
                    if on_err is not None:
                        switch_dir = on_err(parsed.action, observation.output or "")
                        if switch_dir:
                            memory.add_user_message(f"[战略层] {switch_dir}")
                except Exception:
                    pass  # 死路检测异常不影响主流程
            step = ReActStep(
                step_no=step_no,
                thought=parsed.thought,
                action=parsed.action,
                action_input=parsed.action_input,
                observation=observation.output,
                is_error=observation.is_error,
                timestamp=step_timestamp,
            )
            steps.append(step)
            self._notify(step)

            # range_control verify 成功后立即 Final Answer (避免 Cache_Footprint 10min 问题)
            # 当 observation 包含 "Flag verified" / "verify: True" 等成功标志时, 自动终止
            if parsed.action == "range_control" and "verify" in parsed.action_input.lower():
                obs_lower = (observation.output or "").lower()
                if any(kw in obs_lower for kw in ["flag verified", "verify: true", "verified: true", '"verified": true', "✓ verified"]):
                    # 提取 flag from action_input
                    import re as _re
                    flag_match = _re.search(r"athena\{[^}]*\}", parsed.action_input)
                    flag = flag_match.group(0) if flag_match else (parsed.action_input[:200])
                    return ReActResult(
                        success=True,
                        final_answer=flag,
                        steps=steps,
                        total_tokens=total_tokens,
                        raw_outputs=raw_outputs,
                        started_at=started_at,
                        ended_at=time.monotonic(),
                        task=task,
                    )

            # 空 observation 检测与兜底
            obs_text = observation.output or ""
            obs_is_empty = (
                not obs_text.strip()
                or obs_text.strip() in ("()", "[]", "{}", "''", '""')
            )
            if obs_is_empty:
                consecutive_null_obs += 1
            else:
                consecutive_null_obs = 0

            # 熔断检测
            breaker_action = self.breaker.check(step)
            if breaker_action.should_terminate:
                return self._fail_and_return(
                    reason=breaker_action.reason,
                    steps=steps,
                    total_tokens=total_tokens,
                    raw_outputs=raw_outputs,
                    started_at=started_at,
                    task=task,
                )

            # 构造 observation 文本
            if breaker_action.should_inject_hint:
                obs_text = f"⚠️ {breaker_action.message}\n\n{obs_text}"

            # 连续空 observation 兜底：第 2 步起注入恢复 hint（不再触发熔断）
            if consecutive_null_obs >= 2:
                obs_text = (
                    f"⚠️ 已连续 {consecutive_null_obs} 步 Observation 为空。\n\n"
                    f"{NULL_OBSERVATION_HINT}\n\n"
                    f"--- 上一步 Observation ---\n{obs_text}"
                )

            # Observation 回灌（入短期记忆，触发滑动窗口裁剪）
            memory.add_round(
                chat_result.content,
                OBSERVATION_TEMPLATE.format(observation=obs_text),
            )

            # while True 循环每步末尾手动递增步数
            step_no += 1

        # 超出步数 (无进展兜底退出)
        return self._fail_and_return(
            reason=f"达到最大步数 {self.max_steps} (无实质进展自动停止)",
            steps=steps,
            total_tokens=total_tokens,
            raw_outputs=raw_outputs,
            started_at=started_at,
            task=task,
        )

    def _store_failed_if_needed(self, result: ReActResult) -> None:
        """失败时存储 trajectory 到 failed_cache.

        Stage 10: 存储后自动触发 reflect() 生成反思,
        下次跑同 challenge_id 时通过 _inject_context() 注入反思提示。
        """
        if result.success:
            return
        if not self._challenge_id or not self._failed_cache:
            return
        try:
            self._failed_cache.store(
                challenge_id=self._challenge_id,
                steps=result.steps,
                final_answer=result.final_answer,
                fail_reason=result.fail_reason,
                success=False,
            )
            # Stage 10: 自动反思 (失败即触发, 无额外 LLM 调用)
            self._failed_cache.reflect(
                challenge_id=self._challenge_id,
                ch_type=self._challenge_type or "",
                ch_difficulty=self._challenge_difficulty or "",
            )
        except Exception:  # noqa: BLE001
            # 存储/反思失败不影响主流程
            pass

    def _clear_failed_if_solved(self) -> None:
        """阶段 1.2: 成功后清理该 challenge 的失败历史.

        设计原因: 一旦某题成功解出, 历史失败提示不再有意义,
        保留反而会污染未来重跑 (例如回归测试/题库更新后重跑).
        """
        if not self._challenge_id or not self._failed_cache:
            return
        try:
            self._failed_cache.clear(self._challenge_id)
        except Exception:  # noqa: BLE001
            pass

    def _fail_and_return(
        self,
        *,
        reason: str,
        steps: list,
        total_tokens: int,
        raw_outputs: list,
        started_at: float,
        task: str,
    ) -> ReActResult:
        """创建失败 ReActResult + 自动存储到 failed_cache."""
        self.status.mark_failed(reason)
        result = ReActResult(
            success=False,
            steps=steps,
            total_tokens=total_tokens,
            fail_reason=reason,
            raw_outputs=raw_outputs,
            started_at=started_at,
            ended_at=time.monotonic(),
            task=task,
        )
        self._store_failed_if_needed(result)

        # EventBus: engine.finished
        if self._event_bus is not None:
            self._event_bus.emit("engine.finished", {
                "challenge_id": self._challenge_id or "",
                "success": result.success,
                "steps": result.step_count,
                "elapsed": result.elapsed,
                "tokens": result.total_tokens,
            })

        return result

    @staticmethod
    def _format_plan(subtasks: list) -> str:
        """将 Planner 拆解的子任务格式化为"作战计划"文本.

        注入到 system prompt, 让 LLM 在自主解题时有明确参考计划.
        关键: 标注"参考而非约束", 避免 LLM 机械执行 (违反自主解题目标).
        """
        if not subtasks:
            return ""
        lines: list[str] = ["# 🗺️ 作战计划 (Planner 拆解参考)\n"]
        lines.append("> 重要: 这是参考计划, 不是约束. 你可以根据实际发现调整方向.\n")
        for i, st in enumerate(subtasks, 1):
            type_tag = f"[{getattr(st, 'type', 'misc')}]"
            lines.append(f"## 阶段 {i} {type_tag}: {getattr(st, 'id', '?')}")
            desc = getattr(st, "description", "") or ""
            if desc:
                lines.append(f"  目标: {desc}")
            target = getattr(st, "target", "") or ""
            if target:
                lines.append(f"  对象: {target}")
            hint = getattr(st, "executor_hint", "") or ""
            if hint:
                lines.append(f"  提示: {hint}")
            deps = getattr(st, "depends_on", None) or []
            if deps:
                lines.append(f"  依赖: {', '.join(deps)}")
            lines.append("")
        lines.append("---\n")
        return "\n".join(lines)

    def _inject_context(
        self, base_prompt: str, task_id: str, rag_context: str, task: str = ""
    ) -> str:
        """注入中期记忆 facts 与长期记忆 RAG 结果到 system prompt.

        无对应记忆或无内容时跳过对应部分。

        追加失败轨迹 hint (从 failed_cache 读取).
        阶段 1.3: 追加 (type, difficulty) 级别的通用解题提示.
        Stage 10: 追加演化反思提示 (失败模式 + 工具建议).
        """
        parts: list[str] = [base_prompt]
        # Planner 拆解结果作为"作战计划"注入
        if self._planner_plan_text:
            parts.append(self._planner_plan_text)
        if self._mid_term is not None:
            facts_text = self._mid_term.format_facts(task_id)
            if facts_text:
                parts.append(facts_text)
        if rag_context:
            parts.append(rag_context)
        # 阶段 1.3: (type, difficulty) 通用提示
        if (
            self._challenge_type
            and self._challenge_difficulty
            and self._failed_cache is not None
        ):
            type_hint = self._failed_cache.format_type_hint(
                self._challenge_type, self._challenge_difficulty
            )
            if type_hint:
                parts.append(type_hint)
        # 失败轨迹提示
        if self._challenge_id and self._failed_cache is not None:
            fail_hint = self._failed_cache.format_hint(self._challenge_id)
            if fail_hint:
                parts.append(fail_hint)
        # Stage 10: 演化反思提示
        if self._challenge_id and self._failed_cache is not None:
            ref_hint = self._failed_cache.format_reflection_hint(
                self._challenge_id,
                self._challenge_type or "",
                self._challenge_difficulty or "",
            )
            if ref_hint:
                parts.append(ref_hint)
        # 持续学习——注入相关 Skill（过往积累的解题套路/工具用法）
        if self._skill_library is not None:
            try:
                query = task or self._challenge_type or ""
                skill_text = self._skill_library.format_for_prompt(
                    query, category=self._challenge_type, top_k=3
                )
                if skill_text:
                    parts.append(skill_text)
            except Exception:  # noqa: BLE001 - 技能注入失败不阻断解题
                pass
        return "\n\n".join(parts)

    def _invoke_tool(self, action: str, action_input: str) -> ToolResult:
        """调用工具并返回 ToolResult."""
        tool = self.tools.get(action)
        if tool is None:
            available = ", ".join(sorted(self.tools.keys()))
            return ToolResult(
                output=f"ERROR: 未知工具 '{action}'。可用工具: {available}",
                is_error=True,
            )
        return tool(action_input)

    def _notify(self, step: ReActStep) -> None:
        if self._on_step is not None:
            self._on_step(step)
        # EventBus: step.completed
        if self._event_bus is not None:
            self._event_bus.emit("step.completed", {
                "step_no": step.step_no,
                "action": step.action,
                "challenge_id": self._challenge_id or "",
                "success": not (step.observation or "").startswith("ERROR"),
            })

    def _apply_coordinator_guidance(self, guidance: Any, fired_step: int) -> None:
        """应用一次巡查分析结果 (异步事件召回后调用).

        原同步巡查分支的应用逻辑抽离 — 设置 _coordinator_guidance / MUST 持久注入 /
        禁忌提醒 / 灵感板 / 自我纠错 / 扩展步数 / 巡查日志 / 总线发布.
        在主线程执行 (后台线程只做 analyze, 副作用全部回到主线程, 避免跨线程竞态).

        Args:
            guidance: CoordinatorGuidance (异步分析完成结果)
            fired_step: 该分析基于的轨迹发起步 (注入时声明来源, 防过时误导)
        """
        if guidance.should_intervene:
            # 添加 [MUST]/[SHOULD] 标记和禁忌列表
            priority_tag = f"[{guidance.priority}] " if guidance.priority == "MUST" else ""
            self._coordinator_guidance = priority_tag + guidance.guidance
            # MUST 指导持久注入 — 连续重复 must_repeat 步
            # (确保 agent 真正执行, 而非注入一次被忽略)
            if guidance.priority == "MUST":
                self._must_repeat_left = 2  # 本步 + 后续 2 步 = 3 次注入
            else:
                self._must_repeat_left = 0
            # 如果有禁忌列表, 追加提醒
            if guidance.forbidden_actions:
                forbidden_text = "\n⚠️ 禁忌操作 (不要再尝试): " + "; ".join(guidance.forbidden_actions[:3])
                self._coordinator_guidance += forbidden_text
            # 战略深化 — 非创新风格注入"下一步战略方向"
            # (沉默原则: 仅干预时注入; 创新风格用灵感板, 此处由 coordinator 侧留空)
            strategic_direction = str(getattr(guidance, "strategic_direction", "") or "").strip()
            if strategic_direction:
                self._coordinator_guidance = (
                    f"{self._coordinator_guidance}\n\n[战略方向] {strategic_direction}".strip()
                )
        else:
            self._coordinator_guidance = ""
        # WING-Goose 第 8.3 节: 创新模式灵感板 — 仅创新风格无论是否干预都注入创造性 hints
        # (其他风格不使用灵感板, 由 strategic_direction 承担方向深化)
        # (标注"探索建议, 非强制", 冲突时按 agent 思路继续)
        is_innovative = (
            getattr(self, "_coordinator", None) is not None
            and getattr(self._coordinator, "style", "") == "innovative"
        )
        creative_hints = list(getattr(guidance, "creative_hints", []) or []) if is_innovative else []
        if creative_hints:
            hints_text = "\n".join(f"- {h}" for h in creative_hints)
            hint_block = (
                "\n\n[灵感板] 巡查提供的创造性探索建议 (非强制, 冲突时按你的思路继续):\n"
                + hints_text
            )
            self._coordinator_guidance = (self._coordinator_guidance + hint_block).strip()
        # 巡查器自我纠错 — 撤销被后续轨迹证伪的上次指导
        # (react 侧只需停止旧 MUST 的持久重复注入; 若本次干预, 新指导已替换旧指导)
        if guidance.revert_guidance:
            self._must_repeat_left = 0
        # extend_steps 处理移到 if/else 外, 干预时也执行
        # (之前只在沉默时处理, 导致接近上限+干预时永远不扩展)
        if guidance.extend_steps and self.breaker is not None:
            if hasattr(self.breaker, "extend_steps"):
                extended = self.breaker.extend_steps()
                if extended:
                    self.max_steps = self.breaker.max_steps
        # 输出巡查日志 (无论是否干预, 都记录分析结果)
        if self._on_coordinator is not None:
            try:
                self._on_coordinator(guidance, fired_step)
            except Exception:
                pass  # 日志异常不影响主流程
        # WING-Goose: 将本 agent 巡查提炼的 FACT/LIKELY 事实发布到总线
        # (兄弟发现共享 — 跨进程传播高置信度线索, 与 check 端配对形成双向)
        self._post_to_bus(fired_step, guidance)
        # 记录指导来源步 (注入时声明, 供过时性标注)
        self._coordinator_guidance_step = fired_step

    def _post_to_bus(self, step_no: int, guidance: Any) -> None:
        """WING-Goose: 消息总线发布端 — 将巡查提炼的 FACT/LIKELY 事实发布到总线.

        与每 5 步 check (消费兄弟发现) 配对, 形成双向通信:
          - post: 本 agent 巡查提炼的高置信度事实 → 总线文件
          - check: 每 5 步拉取兄弟的 FACT/LIKELY 发现 → 注入 prompt

        只发布巡查 (Coordinator) 产出的事实, 确保内容是高置信度而非每步噪声.
        belief_state 由巡查 LLM 分级 (FACT/LIKELY/POSSIBLE), 这里只传播前两级.

        Args:
            step_no: 当前步号 (仅用于日志)
            guidance: CoordinatorGuidance (含 belief_state 推论清单)
        """
        if self._bus is None:
            return
        try:
            belief_state = list(getattr(guidance, "belief_state", []) or [])
            for b in belief_state:
                level = str(b.get("level", "")).upper()
                statement = (b.get("statement") or "").strip()
                # 只传播高置信度 (FACT/LIKELY) 且非空的事实
                if level not in ("FACT", "LIKELY") or not statement:
                    continue
                self._bus.post(
                    self._bus_key,
                    content=statement,
                    agent=self._bus_agent_id or "agent",
                    level=level,
                    topic="coordinator",
                )
                self._bus_posted_count += 1
                # FACT 级线索同步上报总指挥 (LIKELY 只进兄弟
                # 总线, 控制汇报噪音; 总指挥按三档: clue/dead_end/question)
                if level == "FACT" and self._coordinator is not None:
                    try:
                        rpt = getattr(self._coordinator, "report_to_commander", None)
                        if rpt is not None:
                            rpt(report_type="clue", content=statement, level=level)
                    except Exception:
                        pass
        except Exception:  # noqa: BLE001 - 总线异常不影响主流程
            pass
