"""多智能体协作框架（L3 智能体层）.

依据 README §3.4.2 CHAP (Context Handover and Arbitration Protocol) 协议：
1. Planner 拆解任务为子任务列表（Ticket）
2. Executor 按类型绑定工具白名单执行子任务（复用 ReActEngine）
3. Critic 审核 Executor 输出，通过则汇总，不通过则打回或请求其他 Executor

设计原则：
- 复用现有 ReActEngine（不重写推理循环）
- 失败降级：Critic 调用失败时默认通过，不阻塞流程
- 单线程顺序执行（并行赛马已实现）
- 工具白名单按题型（web/pwn/crypto/misc/reverse）过滤
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ctf_agent.agent.react import ReActEngine, ReActResult
from ctf_agent.llm import LLMClient, Message
from ctf_agent.tools.base import Tool


# ============ 数据结构 ============

@dataclass
class SubTask:
    """Planner 拆解的子任务（Ticket）."""

    id: str
    type: str  # web/pwn/crypto/misc/reverse
    description: str
    target: str = ""  # 子任务目标（IP/URL/文件路径）
    depends_on: list[str] = field(default_factory=list)  # 依赖的子任务 id
    executor_hint: str = ""  # 给 Executor 的提示


@dataclass
class ExecutorReport:
    """Executor 执行子任务后的阶段报告."""

    subtask_id: str
    success: bool
    final_answer: str = ""
    fail_reason: str = ""
    summary: str = ""  # 简短摘要（供后续 Executor 上下文用）
    result: ReActResult | None = None  # 完整 ReAct 结果


@dataclass
class CriticReview:
    """Critic 审核结果."""

    approved: bool
    reason: str = ""
    suggestion: str = ""  # 不通过时的改进建议


@dataclass
class MultiAgentResult:
    """多智能体编排最终结果."""

    success: bool
    final_answer: str = ""
    subtask_count: int = 0
    executor_reports: list[ExecutorReport] = field(default_factory=list)
    critic_reviews: list[CriticReview] = field(default_factory=list)
    total_tokens: int = 0
    fail_reason: str = ""
    plan: list[SubTask] = field(default_factory=list)


# ============ 工具白名单 ============

# 按题型的工具白名单（README §3.4.1）
# 注：通用工具（编解码/哈希）所有 Executor 都可用
TOOL_WHITELIST: dict[str, set[str]] = {
    "web": {
        "ssh_exec", "ssh_python", "ssh_upload",
        "http_request",
        "base64_encode", "base64_decode",
        "url_encode", "url_decode",
        "hex_encode", "hex_decode",
        "hash_compute", "hash_identify",
    },
    "pwn": {
        "ssh_exec", "ssh_python", "ssh_upload",
        "ghidra_headless", "radare2",
        "hex_dump", "file_type", "strings",
        "base64_encode", "base64_decode",
        "hex_encode", "hex_decode",
    },
    "crypto": {
        "ssh_python",
        "base64_encode", "base64_decode",
        "hex_encode", "hex_decode",
        "hash_compute", "hash_identify",
        "caesar_cipher", "rot13",
    },
    "reverse": {
        "ssh_exec", "ssh_python", "ssh_upload",
        "ghidra_headless", "radare2",
        "hex_dump", "file_type", "strings",
        "base64_encode", "base64_decode",
    },
    "misc": {
        # misc 最通用：全部工具
        # 用 None 哨兵表示"全部允许"
    },
}


def filter_tools_by_type(tools: list[Tool], task_type: str) -> list[Tool]:
    """按题型过滤工具白名单.

    misc 类型返回全部工具（最通用）。未知类型也返回全部（保守）。
    """
    whitelist = TOOL_WHITELIST.get(task_type)
    if not whitelist:  # misc 或未知：全部允许
        return list(tools)
    return [t for t in tools if t.name in whitelist]


# ============ Planner ============

PLANNER_SYSTEM_PROMPT = """你是一位 CTF 解题任务规划专家（Planner）。

你的职责：将复杂 CTF 任务拆解为有序的子任务列表，每个子任务由专项 Executor 处理。

# 题型分类

- web: Web 渗透（SQL 注入、XSS、文件上传、SSRF 等）
- pwn: 二进制漏洞利用（栈溢出、堆利用、ROP）
- crypto: 密码学（RSA、AES、古典密码、哈希）
- reverse: 逆向工程（ELF/APK 静态分析、算法还原）
- misc: 杂项（取证、隐写、编码、OSINT）

# 拆解原则

1. 只在确实需要分阶段时拆解（简单任务可只产出 1 个子任务）
2. 每个子任务必须有明确目标和可验证产出
3. 子任务之间的依赖关系必须显式标注（depends_on）
4. 不要过度拆解：典型任务 1-3 个子任务即可
5. 描述应具体，包含关键信息（目标 IP、附件路径、已知约束）

# 输出格式

严格输出 JSON 数组，不要包含任何其他文字：

```json
[
  {
    "id": "step1",
    "type": "recon",
    "description": "扫描目标 10.0.0.5 的开放端口与服务版本",
    "target": "10.0.0.5",
    "depends_on": [],
    "executor_hint": "使用 nmap 全端口扫描，记录开放端口与服务版本"
  }
]
```

注意：type 字段必须是 web/pwn/crypto/reverse/misc 之一。
"""


def _extract_json_array(text: str) -> list[dict[str, Any]]:
    """从 LLM 输出中提取 JSON 数组（容忍 markdown 代码块包裹）."""
    # 去除 markdown 代码块
    text = re.sub(r"^```(?:json)?\s*\n?", "", text.strip())
    text = re.sub(r"\n?```\s*$", "", text)
    # 找第一个 [ 到最后一个 ]
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return []
    try:
        parsed = json.loads(text[start : end + 1])
        if not isinstance(parsed, list):
            return []
        return [item for item in parsed if isinstance(item, dict)]
    except json.JSONDecodeError:
        return []


class Planner:
    """任务规划者：将原始任务拆解为子任务列表."""

    def __init__(
        self,
        llm: LLMClient,
        *,
        model: str | None = None,
        temperature: float = 0.0,
    ) -> None:
        self.llm = llm
        self.model = model
        self.temperature = temperature

    def plan(
        self,
        task: str,
        rag_context: str = "",
    ) -> list[SubTask]:
        """拆解任务为子任务列表.

        Args:
            task: 原始任务描述
            rag_context: RAG 检索到的相似历史方案（可选）

        Returns:
            子任务列表，失败时返回单元素列表（直接执行原任务）
        """
        user_prompt = f"任务：\n{task}\n"
        if rag_context:
            user_prompt += f"\n相似历史方案参考：\n{rag_context}\n"
        user_prompt += "\n请输出子任务 JSON 数组。"

        messages = [
            Message(role="system", content=PLANNER_SYSTEM_PROMPT),
            Message(role="user", content=user_prompt),
        ]
        try:
            result = self.llm.chat(
                messages, model=self.model, temperature=self.temperature
            )
        except Exception:  # noqa: BLE001 - Planner 失败时降级为单任务
            return [SubTask(
                id="fallback",
                type="misc",
                description=task,
                executor_hint="Planner 不可用，直接执行原任务",
            )]

        items = _extract_json_array(result.content)
        if not items:
            # Planner 输出无效，降级为单任务
            return [SubTask(
                id="fallback",
                type="misc",
                description=task,
                executor_hint="Planner 输出无效，直接执行原任务",
            )]

        subtasks: list[SubTask] = []
        for item in items:
            sub_id = str(item.get("id", f"step{len(subtasks) + 1}"))
            sub_type = str(item.get("type", "misc")).lower()
            if sub_type not in TOOL_WHITELIST:
                sub_type = "misc"
            subtasks.append(
                SubTask(
                    id=sub_id,
                    type=sub_type,
                    description=str(item.get("description", task)),
                    target=str(item.get("target", "")),
                    depends_on=list(item.get("depends_on", []) or []),
                    executor_hint=str(item.get("executor_hint", "")),
                )
            )
        return subtasks


# ============ Critic ============

CRITIC_SYSTEM_PROMPT = """你是一位严格的 CTF 解题审核专家（Critic）。

你的职责：审核 Executor 提交的阶段报告，判断是否通过。

# 审核标准

1. **结果有效性**：Final Answer 是否符合 flag 格式或合理答案
2. **过程合理性**：关键步骤是否合理（无明显幻觉/错误推理）
3. **任务完成度**：是否真正解决了子任务描述的目标

# 输出格式

严格输出 JSON 对象，不要任何其他文字：

```json
{
  "approved": true,
  "reason": "Executor 成功提取 flag，过程合理",
  "suggestion": ""
}
```

或：

```json
{
  "approved": false,
  "reason": "Executor 未找到 flag，仅扫描了端口",
  "suggestion": "应针对 8080 端口的 web 服务进行目录爆破"
}
```
"""


def _extract_json_object(text: str) -> dict[str, Any] | None:
    """从 LLM 输出中提取 JSON 对象."""
    text = re.sub(r"^```(?:json)?\s*\n?", "", text.strip())
    text = re.sub(r"\n?```\s*$", "", text)
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        parsed = json.loads(text[start : end + 1])
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


class Critic:
    """审核者：审核 Executor 输出."""

    def __init__(
        self,
        llm: LLMClient,
        *,
        model: str | None = None,
        temperature: float = 0.0,
    ) -> None:
        self.llm = llm
        self.model = model
        self.temperature = temperature

    def review(
        self,
        subtask: SubTask,
        report: ExecutorReport,
    ) -> CriticReview:
        """审核单个 Executor 报告.

        Args:
            subtask: 子任务定义
            report: Executor 阶段报告

        Returns:
            CriticReview，失败时默认 approved=True（不阻塞流程）
        """
        # 失败的 Executor 直接判不通过（不需要 LLM 浪费 token）
        if not report.success:
            return CriticReview(
                approved=False,
                reason=f"Executor 失败: {report.fail_reason}",
                suggestion="考虑调整策略或切换工具",
            )

        # 成功的 Executor 调用 LLM 审核
        steps_brief = ""
        if report.result and report.result.steps:
            steps_brief = "\n".join(
                f"  Step {s.step_no}: {s.action}({s.action_input[:80]})"
                for s in report.result.steps[:10]
                if s.action
            )

        user_prompt = (
            f"子任务描述：\n{subtask.description}\n\n"
            f"Executor 报告：\n"
            f"- 成功: {report.success}\n"
            f"- Final Answer: {report.final_answer[:200]}\n"
            f"- 摘要: {report.summary[:300]}\n"
            f"- 关键步骤:\n{steps_brief}\n\n"
            f"请审核是否通过。"
        )
        messages = [
            Message(role="system", content=CRITIC_SYSTEM_PROMPT),
            Message(role="user", content=user_prompt),
        ]
        try:
            result = self.llm.chat(
                messages, model=self.model, temperature=self.temperature
            )
        except Exception:  # noqa: BLE001 - Critic 失败默认通过
            return CriticReview(
                approved=True,
                reason="Critic 不可用，默认通过",
            )

        parsed = _extract_json_object(result.content)
        if parsed is None:
            return CriticReview(
                approved=True,
                reason="Critic 输出无效，默认通过",
            )
        return CriticReview(
            approved=bool(parsed.get("approved", True)),
            reason=str(parsed.get("reason", "")),
            suggestion=str(parsed.get("suggestion", "")),
        )


# ============ Executor ============

class Executor:
    """执行者：复用 ReActEngine 执行子任务.

    按题型绑定工具白名单。上下文来自前置 Executor 的 summary
    （通过 system_prompt 注入）。
    """

    def __init__(
        self,
        llm: LLMClient,
        tools: list[Tool],
        *,
        model: str | None = None,
        max_steps: int = 35,
    ) -> None:
        self.llm = llm
        self._all_tools = list(tools)
        self.model = model
        self.max_steps = max_steps

    def execute(
        self,
        subtask: SubTask,
        context_summaries: list[str] | None = None,
    ) -> ExecutorReport:
        """执行子任务.

        Args:
            subtask: 子任务定义
            context_summaries: 前置 Executor 的摘要列表（用于上下文交接）

        Returns:
            ExecutorReport
        """
        # 按题型过滤工具
        tools = filter_tools_by_type(self._all_tools, subtask.type)
        # 构造任务描述
        task_parts: list[str] = []
        if subtask.executor_hint:
            task_parts.append(f"提示：{subtask.executor_hint}")
        if context_summaries:
            task_parts.append(
                "前置阶段结果：\n" + "\n".join(f"- {s}" for s in context_summaries)
            )
        task_parts.append(f"任务：{subtask.description}")
        if subtask.target:
            task_parts.append(f"目标：{subtask.target}")
        task = "\n\n".join(task_parts)

        # 实例化 ReActEngine
        engine = ReActEngine(
            llm=self.llm,
            tools=tools,
            max_steps=self.max_steps,
            model=self.model,
        )
        result = engine.run(task)

        # 生成摘要（成功时取 final_answer 前 200 字，失败时取 fail_reason）
        summary = (
            result.final_answer[:200] if result.success
            else f"失败: {result.fail_reason}"
        )
        return ExecutorReport(
            subtask_id=subtask.id,
            success=result.success,
            final_answer=result.final_answer,
            fail_reason=result.fail_reason,
            summary=summary,
            result=result,
        )


# ============ 多智能体编排器 ============

class MultiAgentOrchestrator:
    """多智能体编排器（CHAP 协议核心实现）.

    流程：
    1. Planner 拆解任务
    2. 对每个子任务：
       a. Executor 执行
       b. Critic 审核
       c. 不通过则反馈建议给后续 Executor（不重试，避免死循环）
    3. 汇总最终结果（取最后一个成功 Executor 的 final_answer）

    用法：
        orchestrator = MultiAgentOrchestrator(llm, tools)
        result = orchestrator.run(task)
    """

    def __init__(
        self,
        llm: LLMClient,
        tools: list[Tool],
        *,
        planner_model: str | None = None,
        executor_model: str | None = None,
        critic_model: str | None = None,
        max_steps: int = 35,
        enable_critic: bool = True,
    ) -> None:
        self.planner = Planner(llm, model=planner_model)
        self.executor = Executor(llm, tools, model=executor_model, max_steps=max_steps)
        self.critic = Critic(llm, model=critic_model)
        self.enable_critic = enable_critic

    def run(
        self,
        task: str,
        rag_context: str = "",
    ) -> MultiAgentResult:
        """运行多智能体编排.

        Args:
            task: 原始任务描述
            rag_context: RAG 检索到的相似方案（注入 Planner）

        Returns:
            MultiAgentResult
        """
        # 1. Planner 拆解
        plan = self.planner.plan(task, rag_context=rag_context)

        reports: list[ExecutorReport] = []
        reviews: list[CriticReview] = []
        total_tokens = 0
        context_summaries: list[str] = []

        # 2. 顺序执行各子任务
        for subtask in plan:
            # 过滤依赖未完成的子任务
            if not self._check_dependencies(subtask, reports):
                reports.append(ExecutorReport(
                    subtask_id=subtask.id,
                    success=False,
                    fail_reason=f"依赖未满足: {subtask.depends_on}",
                ))
                reviews.append(CriticReview(
                    approved=False,
                    reason="依赖未满足，跳过",
                ))
                continue

            report = self.executor.execute(subtask, context_summaries)
            reports.append(report)
            if report.result:
                total_tokens += report.result.total_tokens

            # Critic 审核
            if self.enable_critic:
                review = self.critic.review(subtask, report)
            else:
                review = CriticReview(
                    approved=report.success,
                    reason="Critic 未启用",
                )
            reviews.append(review)

            # 上下文交接：通过或成功的报告加入摘要
            if review.approved or report.success:
                context_summaries.append(
                    f"[{subtask.id}] {report.summary}"
                )

        # 3. 汇总最终结果
        final_answer = ""
        success = False
        for r in reversed(reports):
            if r.success and r.final_answer:
                final_answer = r.final_answer
                success = True
                break

        return MultiAgentResult(
            success=success,
            final_answer=final_answer,
            subtask_count=len(plan),
            executor_reports=reports,
            critic_reviews=reviews,
            total_tokens=total_tokens,
            fail_reason="" if success else "所有子任务均未产出最终答案",
            plan=plan,
        )

    def _check_dependencies(
        self,
        subtask: SubTask,
        completed_reports: list[ExecutorReport],
    ) -> bool:
        """检查子任务依赖是否满足（所有依赖子任务必须成功）."""
        if not subtask.depends_on:
            return True
        completed_ids = {
            r.subtask_id for r in completed_reports if r.success
        }
        return all(dep in completed_ids for dep in subtask.depends_on)


# ============ 并行执行与赛马（阶段六） ============

from concurrent.futures import ThreadPoolExecutor, as_completed, Future  # noqa: E402


@dataclass
class RacingResult:
    """赛马结果：多个 Executor 并行尝试同一子任务，取首个成功者."""

    winner: ExecutorReport | None
    losers: list[ExecutorReport] = field(default_factory=list)
    elapsed_seconds: float = 0.0


class RacingExecutor:
    """赛马执行器：同一子任务用多个模型/配置并行尝试.

    依据 README §3.4.2 与阶段六：
    - 异构 LLM 切换：同一子任务可指定多个 model 并行执行
    - 首个成功者胜出，其余取消
    - 全部失败时返回 None

    用法：
        racer = RacingExecutor(llm, tools, models=["m1", "m2", "m3"])
        result = racer.race(subtask)
        if result.winner: ...
    """

    def __init__(
        self,
        llm: LLMClient,
        tools: list[Tool],
        models: list[str | None],
        *,
        max_steps: int = 35,
        max_workers: int | None = None,
    ) -> None:
        if not models:
            raise ValueError("models 至少 1 个")
        self.llm = llm
        self.tools = list(tools)
        self.models = list(models)
        self.max_steps = max_steps
        self.max_workers = max_workers or min(len(models), 4)

    def race(
        self,
        subtask: SubTask,
        context_summaries: list[str] | None = None,
    ) -> RacingResult:
        """并行执行多个模型，首个成功者胜出.

        Args:
            subtask: 子任务
            context_summaries: 前置摘要

        Returns:
            RacingResult
        """
        import time as _time

        started = _time.monotonic()
        # 每个模型一个 Executor 实例
        executors = [
            Executor(self.llm, self.tools, model=m, max_steps=self.max_steps)
            for m in self.models
        ]

        # ThreadPoolExecutor 并行执行
        # 注：LLMClient 内部是同步 OpenAI client，可在线程中安全调用
        futures: dict[Future, Executor] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            for ex in executors:
                fut = pool.submit(ex.execute, subtask, context_summaries)
                futures[fut] = ex

            winner: ExecutorReport | None = None
            losers: list[ExecutorReport] = []

            # 按完成顺序处理
            for fut in as_completed(futures):
                try:
                    report = fut.result()
                except Exception as e:  # noqa: BLE001 - 单个 Executor 异常不影响其他
                    ex = futures[fut]
                    model_name = ex.model or "default"
                    report = ExecutorReport(
                        subtask_id=subtask.id,
                        success=False,
                        fail_reason=f"Executor[{model_name}] 异常: {type(e).__name__}: {e}",
                    )

                if winner is None and report.success:
                    winner = report
                    # 取消未完成的 futures（已完成的无法取消，但结果作 losers）
                    for other_fut in futures:
                        if other_fut is not fut and not other_fut.done():
                            other_fut.cancel()
                elif winner is not None:
                    # winner 已确定，后续完成的都计入 losers
                    if report.success:
                        losers.append(report)
                    # 失败的也记录用于诊断
                    else:
                        losers.append(report)
                else:
                    # winner 未确定且本次失败
                    losers.append(report)

        elapsed = _time.monotonic() - started
        return RacingResult(winner=winner, losers=losers, elapsed_seconds=elapsed)


def arbitrate_conflicts(
    reports: list[ExecutorReport],
    critic: Critic | None = None,
    subtask: SubTask | None = None,
) -> ExecutorReport | None:
    """投票仲裁：多个 Executor 给出不同结论时，选择多数派.

    依据 README §3.4.2 "当出现多个 Executor 给出矛盾结论时，Planner 启动投票仲裁"。

    仲裁规则：
    1. 只有成功的 report 参与（失败的直接淘汰）
    2. 按 final_answer 分组，多数派（>= ceil(n/2)）胜出
    3. 若无多数派，调用 Critic 选择最优（如 Critic 不可用则取第一个）
    4. 全部失败返回 None

    Args:
        reports: 多个 Executor 的报告
        critic: 可选的 Critic 实例（用于打破平局）
        subtask: 子任务（用于 Critic 上下文）

    Returns:
        仲裁后的胜出报告，或 None
    """
    successful = [r for r in reports if r.success and r.final_answer]
    if not successful:
        return None
    if len(successful) == 1:
        return successful[0]

    # 按 final_answer 分组投票
    from collections import Counter, defaultdict

    votes = Counter(r.final_answer for r in successful)
    top_answer, top_count = votes.most_common(1)[0]
    threshold = (len(successful) + 1) // 2  # ceil(n/2)

    if top_count >= threshold:
        # 多数派胜出
        return next(r for r in successful if r.final_answer == top_answer)

    # 无多数派，尝试 Critic 仲裁
    if critic is not None and subtask is not None:
        # 选第一个 report 作为候选，让 Critic 审核
        # 如果 Critic 否决，尝试下一个
        for r in successful:
            review = critic.review(subtask, r)
            if review.approved:
                return r

    # Critic 不可用或都未通过，取第一个成功的
    return successful[0]


class ParallelMultiAgentOrchestrator(MultiAgentOrchestrator):
    """并行版多智能体编排器.

    依据 README 阶段六：
    - 无依赖的子任务并行执行（ThreadPoolExecutor）
    - 同一子任务可选赛马（RacingExecutor，多模型并行）
    - 冲突时投票仲裁

    用法：
        orchestrator = ParallelMultiAgentOrchestrator(
            llm, tools, racing_models=["m1", "m2"]
        )
        result = orchestrator.run(task)
    """

    def __init__(
        self,
        llm: LLMClient,
        tools: list[Tool],
        *,
        planner_model: str | None = None,
        executor_model: str | None = None,
        critic_model: str | None = None,
        max_steps: int = 35,
        enable_critic: bool = True,
        racing_models: list[str | None] | None = None,
        max_workers: int = 4,
    ) -> None:
        super().__init__(
            llm,
            tools,
            planner_model=planner_model,
            executor_model=executor_model,
            critic_model=critic_model,
            max_steps=max_steps,
            enable_critic=enable_critic,
        )
        self.racing_models = racing_models
        self.max_workers = max_workers
        self._racer: RacingExecutor | None = (
            RacingExecutor(
                llm, tools, racing_models,
                max_steps=max_steps,
                max_workers=max_workers,
            )
            if racing_models and len(racing_models) > 1
            else None
        )

    def run(
        self,
        task: str,
        rag_context: str = "",
    ) -> MultiAgentResult:
        """并行执行多智能体编排.

        流程：
        1. Planner 拆解任务
        2. 按依赖拓扑分层，同层子任务并行执行
        3. 每个子任务可选赛马（多模型并行）
        4. Critic 审核 + 冲突仲裁
        5. 汇总最终结果
        """
        # 1. Planner 拆解
        plan = self.planner.plan(task, rag_context=rag_context)

        reports: list[ExecutorReport] = []
        reviews: list[CriticReview] = []
        total_tokens = 0
        context_summaries: list[str] = []
        completed_ids: set[str] = set()

        # 2. 按依赖分层
        remaining = list(plan)
        while remaining:
            # 找出当前可执行的子任务（依赖已满足）
            ready = [
                s for s in remaining
                if all(dep in completed_ids for dep in s.depends_on)
            ]
            if not ready:
                # 死锁：剩余子任务依赖未满足
                for s in remaining:
                    reports.append(ExecutorReport(
                        subtask_id=s.id,
                        success=False,
                        fail_reason=f"依赖未满足: {s.depends_on}",
                    ))
                    reviews.append(CriticReview(
                        approved=False, reason="依赖死锁"
                    ))
                break

            # 3. 同层并行执行
            layer_reports = self._execute_layer_parallel(
                ready, context_summaries
            )

            # 4. Critic 审核 + 上下文交接
            for subtask, report in zip(ready, layer_reports):
                reports.append(report)
                if report.result:
                    total_tokens += report.result.total_tokens

                if self.enable_critic:
                    review = self.critic.review(subtask, report)
                else:
                    review = CriticReview(
                        approved=report.success,
                        reason="Critic 未启用",
                    )
                reviews.append(review)

                if review.approved or report.success:
                    completed_ids.add(subtask.id)
                    context_summaries.append(f"[{subtask.id}] {report.summary}")

            # 从 remaining 移除已处理
            ready_ids = {s.id for s in ready}
            remaining = [s for s in remaining if s.id not in ready_ids]

        # 5. 汇总
        final_answer = ""
        success = False
        for r in reversed(reports):
            if r.success and r.final_answer:
                final_answer = r.final_answer
                success = True
                break

        return MultiAgentResult(
            success=success,
            final_answer=final_answer,
            subtask_count=len(plan),
            executor_reports=reports,
            critic_reviews=reviews,
            total_tokens=total_tokens,
            fail_reason="" if success else "所有子任务均未产出最终答案",
            plan=plan,
        )

    def _execute_layer_parallel(
        self,
        layer: list[SubTask],
        context_summaries: list[str] | None,
    ) -> list[ExecutorReport]:
        """并行执行同层子任务.

        如配置了 racing_models，每个子任务用 RacingExecutor 赛马。
        否则用顺序 Executor（线程开销不值得）。
        """
        # 无赛马配置：单线程顺序执行（避免线程开销）
        if self._racer is None:
            return [
                self.executor.execute(s, context_summaries) for s in layer
            ]

        # 赛马模式：每个子任务并行赛马
        results: dict[int, ExecutorReport] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(
                    self._race_one, subtask, context_summaries
                ): idx
                for idx, subtask in enumerate(layer)
            }
            for fut in as_completed(futures):
                idx = futures[fut]
                try:
                    results[idx] = fut.result()
                except Exception as e:  # noqa: BLE001
                    results[idx] = ExecutorReport(
                        subtask_id=layer[idx].id,
                        success=False,
                        fail_reason=f"赛马异常: {type(e).__name__}: {e}",
                    )
        return [results[i] for i in range(len(layer))]

    def _race_one(
        self,
        subtask: SubTask,
        context_summaries: list[str] | None,
    ) -> ExecutorReport:
        """对单个子任务执行赛马."""
        racing_result = self._racer.race(subtask, context_summaries)
        if racing_result.winner is not None:
            return racing_result.winner
        # 所有模型都失败：返回第一个 loser 的失败信息
        if racing_result.losers:
            first = racing_result.losers[0]
            return ExecutorReport(
                subtask_id=subtask.id,
                success=False,
                fail_reason=f"所有模型失败; 首个错误: {first.fail_reason}",
            )
        return ExecutorReport(
            subtask_id=subtask.id,
            success=False,
            fail_reason="赛马无结果",
        )


__all__ = [
    "Critic",
    "CriticReview",
    "Executor",
    "ExecutorReport",
    "MultiAgentOrchestrator",
    "MultiAgentResult",
    "ParallelMultiAgentOrchestrator",
    "Planner",
    "RacingExecutor",
    "RacingResult",
    "SubTask",
    "TOOL_WHITELIST",
    "arbitrate_conflicts",
    "filter_tools_by_type",
]
