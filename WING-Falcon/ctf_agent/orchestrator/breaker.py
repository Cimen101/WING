"""熔断控制器（L2 编排层）.

依据 README §3.5.2 六维熔断机制，本模块实现完整六维：
- 时间限制：单任务耗时 > 阈值（默认 30 分钟） -> 终止
- 重复动作：同一 (action, action_input) 重复 > 阈值（默认 3 次） -> 注入"切换策略"提示
- 思维死锁：LLM 连续 N 轮（默认 5）输出相同 Thought -> 注入"跳出循环"提示
- 步数限制：ReAct 循环步数 > 阈值（默认 35） -> 终止
- 成本限制：API 累计消耗 > 阈值（默认 $1.5） -> 终止
- 文件膨胀：SSH 工作目录大小 > 阈值（默认 1GB） -> 注入"清理临时文件"提示

成本/文件膨胀维度需要外部输入：
- 成本：ReActEngine 在每次 LLM 调用后调用 record_llm_call(tokens, model)
- 文件膨胀：传入 ssh_client，check() 时自动 du 工作目录
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:
    from ctf_agent.agent import ReActStep


# ============ 默认 token 定价（USD per 1K tokens） ============
# 参考 DeepSeek v4 定价（2026），可按需调整
_DEFAULT_PRICING: dict[str, tuple[float, float]] = {
    # model -> (input_per_1k, output_per_1k)
    "deepseek-v4-flash": (0.00007, 0.00028),
    "deepseek-chat": (0.00014, 0.00028),
    "deepseek-reasoner": (0.00055, 0.00219),
    "gpt-4o": (0.0025, 0.01),
    "gpt-4o-mini": (0.00015, 0.0006),
    "gpt-3.5-turbo": (0.0005, 0.0015),
}


def _default_pricer(total_tokens: int, model: str | None) -> float:
    """默认定价函数：按 model 查表，输出 token 按均价估算.

    简化：假设 input:output = 3:1（典型 ReAct 模式），用平均价。
    生产环境可注入精确分项计费。
    """
    if not model:
        return 0.0
    # 模糊匹配（处理别名/版本号）
    key = next(
        (k for k in _DEFAULT_PRICING if k in model.lower()),
        None,
    )
    if key is None:
        return 0.0  # 未知模型不计费（避免误熔断）
    in_price, out_price = _DEFAULT_PRICING[key]
    # 假设 75% input / 25% output
    return total_tokens * (0.75 * in_price + 0.25 * out_price) / 1000.0


# ============ 熔断动作 ============

@dataclass
class BreakerAction:
    """熔断检测结果.

    action:
        - "continue": 无干预，继续循环
        - "inject_hint": 注入提示到下一轮 observation，不终止
        - "terminate": 终止 ReAct 循环，返回失败结果
    """

    action: str = "continue"
    message: str = ""
    reason: str = ""

    @property
    def should_terminate(self) -> bool:
        return self.action == "terminate"

    @property
    def should_inject_hint(self) -> bool:
        return self.action == "inject_hint"


# ============ 熔断器 ============

class CircuitBreaker:
    """六维熔断检测器.

    用法：
        breaker = CircuitBreaker(max_seconds=1800, max_cost_usd=1.5)
        breaker.reset()  # 任务开始时重置
        for step in steps:
            breaker.record_llm_call(tokens, model)  # 每次调用 LLM 后
            action = breaker.check(step)
            if action.should_terminate:
                return fail(action.reason)
            if action.should_inject_hint:
                observation = f"⚠️ {action.message}\\n\\n{observation}"
    """

    def __init__(
        self,
        *,
        max_repeated_actions: int = 3,
        max_thought_deadlock: int = 5,
        # 修复：无效步数（action 相同 + observation 高相似）
        max_invalid_steps: int = 5,
        obs_similarity_threshold: float = 0.85,
        max_seconds: float = 1800.0,  # 30 分钟
        max_steps: int = 35,
        max_cost_usd: float = 1.5,
        max_workspace_mb: int = 1024,  # 1 GB
        # 单步耗时上限（防止 docker build / long-running 命令卡死）
        max_single_step_seconds: float = 120.0,
        ssh_client: Optional[Any] = None,
        ssh_workspace_path: str = "/tmp/ctf_workspace/",
        token_pricer: Optional[Callable[[int, str | None], float]] = None,
        # 时间熔断进展感知 (历史复盘修复)
        # 之前时间熔断"一刀切": 到 max_seconds 就 terminate, 不看是否有进展.
        # 第47步方向正确、刚发现关键线索 ("MD5 输入是整个后缀"),
        # 却在 1200s 被熔断误杀, 且 executor 传入的 1500s 被 medium 强制压到 1200s.
        # 修复: 超过 max_seconds 后, 若最近 progress_grace_seconds 秒内仍有实质进展
        # (产生新的非空 observation), 则自动延长.
        # (用户要求): 尽量不做严格硬截断 — 优先 LLM 软截断
        # (协调器 [MUST] 指导 + extend_steps 加步). hard_max_seconds 放宽到
        # max_seconds*3 (单轮 75 分钟) 仅作防失控保险, 真正的硬兜底由
        # executor 侧 no_progress 检测 (5-10 分钟无输出) 承担.
        progress_grace_seconds: float = 120.0,  # 超过上限后, 持续无进展的宽限期
        hard_max_seconds: float = 0.0,          # 防失控绝对上限; 0 = 自动 = max_seconds * 3
    ) -> None:
        self.max_repeated_actions = max_repeated_actions
        self.max_thought_deadlock = max_thought_deadlock
        self.max_invalid_steps = max_invalid_steps
        self.obs_similarity_threshold = obs_similarity_threshold
        self.max_seconds = max_seconds
        self.max_steps = max_steps
        self.max_cost_usd = max_cost_usd
        self.max_workspace_mb = max_workspace_mb
        self.max_single_step_seconds = max_single_step_seconds
        self.ssh_client = ssh_client
        self.ssh_workspace_path = ssh_workspace_path
        self._token_pricer = token_pricer or _default_pricer
        # 时间熔断进展感知
        self.progress_grace_seconds = progress_grace_seconds
        self.hard_max_seconds = hard_max_seconds if hard_max_seconds > 0 else max_seconds * 3

        # 运行时状态
        self._action_counts: dict[tuple[str, str], int] = {}
        self._consecutive_same_thought: int = 0
        self._last_thought: str = ""
        self._started_at: float = 0.0
        # 最近一次有实质进展的时间 + 上次 observation (判进展用)
        self._last_progress_at: float = 0.0
        self._last_progress_obs: str = ""
        # 已注入过的提示类型，避免无限注入
        self._hinted_keys: set[tuple[str, str]] = set()
        self._hinted_deadlock: bool = False
        self._hinted_workspace: bool = False
        # 无效步数跟踪（同 action 连续产生相似 observation）
        self._invalid_step_counts: dict[str, int] = {}  # action -> count
        self._last_obs_per_action: dict[str, str] = {}  # action -> 归一化后的 obs
        self._hinted_invalid: set[str] = set()  # 已提示过的 action
        # 单步耗时跟踪
        self._long_step_hints: set[str] = set()  # 已提示过的 action
        # 成本累计
        self._accumulated_cost_usd: float = 0.0
        self._accumulated_tokens: int = 0
        self._last_workspace_check: float = 0.0  # 节流：每 30s 检查一次工作目录

    def reset(self) -> None:
        """任务开始时重置状态."""
        self._action_counts.clear()
        self._consecutive_same_thought = 0
        self._last_thought = ""
        self._started_at = time.monotonic()
        # 进展感知重置
        self._last_progress_at = self._started_at
        self._last_progress_obs = ""
        self._hinted_keys.clear()
        self._hinted_deadlock = False
        self._hinted_workspace = False
        # 无效步数重置
        self._invalid_step_counts.clear()
        self._last_obs_per_action.clear()
        self._hinted_invalid.clear()
        # 单步耗时重置
        self._long_step_hints.clear()
        self._accumulated_cost_usd = 0.0
        self._accumulated_tokens = 0
        self._last_workspace_check = 0.0

    @staticmethod
    def _normalize_obs(obs: str) -> str:
        """归一化 observation 用于相似度比较（去空白、统一大小写、截断到 200 字符）."""
        if not obs:
            return ""
        s = " ".join(obs.split())  # 合并所有空白
        s = s.lower()[:200]
        return s

    @staticmethod
    def _obs_similarity(a: str, b: str) -> float:
        """两 observation 的字符级相似度（Jaccard-like）."""
        if not a or not b:
            return 0.0
        if a == b:
            return 1.0
        set_a, set_b = set(a), set(b)
        if not set_a or not set_b:
            return 0.0
        inter = len(set_a & set_b)
        union = len(set_a | set_b)
        return inter / union if union > 0 else 0.0

    def record_llm_call(self, total_tokens: int, model: str | None) -> float:
        """记录一次 LLM 调用的 token 消耗并累计成本.

        Returns:
            本次调用估算成本（USD）
        """
        self._accumulated_tokens += total_tokens
        cost = self._token_pricer(total_tokens, model)
        self._accumulated_cost_usd += cost
        return cost

    def _check_workspace_size(self) -> int:
        """通过 ssh_client 检查工作目录大小（MB）.

        失败返回 0（避免误熔断）。
        """
        if self.ssh_client is None:
            return 0
        try:
            # du -sm 输出 MB 单位
            result = self.ssh_client.exec_cmd(
                f"du -sm {self.ssh_workspace_path} 2>/dev/null | awk '{{print $1}}'"
            )
            if result.is_success and result.stdout.strip().isdigit():
                return int(result.stdout.strip())
        except Exception:
            pass
        return 0

    def check(self, step: ReActStep) -> BreakerAction:
        """检查单步是否触发熔断.

        Returns:
            BreakerAction，调用方根据 action 字段决定后续处理
        """
        # 0. 进展跟踪: 新的非空 observation = 实质进展
        # 时间熔断依赖此信息: 有进展则自动延长, 无进展才熔断
        if step is not None and getattr(step, "observation", "") and not getattr(step, "is_error", False):
            norm = self._normalize_obs(step.observation)
            if norm and norm != self._last_progress_obs:
                self._last_progress_at = time.monotonic()
                self._last_progress_obs = norm

        # 1. 时间熔断 (进展感知, 修复 方向正确仍被误杀)
        if self._started_at > 0:
            elapsed = time.monotonic() - self._started_at
            if elapsed > self.max_seconds:
                idle = time.monotonic() - self._last_progress_at
                if idle > self.progress_grace_seconds or elapsed > self.hard_max_seconds:
                    return BreakerAction(
                        action="terminate",
                        reason=(
                            f"时间熔断：耗时 {elapsed:.0f}s 超过阈值 {self.max_seconds:.0f}s, "
                            f"且已 {idle:.0f}s 无实质进展"
                        ),
                    )
                # 有实质进展 → 自动延长 (不熔断), 仅当接近硬上限时提醒
                # (方向正确、进展正常时绝不误杀; 硬上限由 executor 侧兜底)

        # 2. 步数熔断 (进展感知软截断)
        # 之前 `step_no > max_steps` 直接 terminate, 是严格硬截断 — 若加步
        # (extend_steps) 未及时生效, 方向正确的 agent 会被步数上限硬杀.
        # 现改为: 超过 max_steps 后, 若持续无进展 (progress_grace 内无新
        # observation) 才熔断; 有进展则继续, 由时间熔断 (3x 保险) 兜底.
        if step.step_no > self.max_steps:
            idle = time.monotonic() - self._last_progress_at
            if idle > self.progress_grace_seconds:
                return BreakerAction(
                    action="terminate",
                    reason=(
                        f"步数熔断：步数 {step.step_no} 超过阈值 {self.max_steps}, "
                        f"且已 {idle:.0f}s 无实质进展"
                    ),
                )

        # 3. 成本熔断
        if self._accumulated_cost_usd > self.max_cost_usd:
            return BreakerAction(
                action="terminate",
                reason=(
                    f"成本熔断：累计 ${self._accumulated_cost_usd:.4f} "
                    f"超过阈值 ${self.max_cost_usd:.4f}"
                ),
            )

        # 4. 文件膨胀检测（节流：每 30s 检查一次）
        now = time.monotonic()
        if (
            self.ssh_client is not None
            and not self._hinted_workspace
            and now - self._last_workspace_check > 30.0
        ):
            self._last_workspace_check = now
            size_mb = self._check_workspace_size()
            if size_mb > self.max_workspace_mb:
                self._hinted_workspace = True
                return BreakerAction(
                    action="inject_hint",
                    message=(
                        f"工作目录 {self.ssh_workspace_path} 大小 {size_mb} MB "
                        f"超过阈值 {self.max_workspace_mb} MB，"
                        "请清理临时文件：rm -rf /tmp/ctf_workspace/*.tmp、"
                        "压缩大文件、删除中间产物。"
                    ),
                )

        # 4.5 单步耗时检测（防止 docker build / long-running 卡死）
        # 计算本步耗时（从 LLM 调用开始到本 step 提交）
        step_elapsed = 0.0
        step_timestamp = getattr(step, "timestamp", 0)
        if step_timestamp > 0:
            step_elapsed = now - step_timestamp
        if (
            self.max_single_step_seconds > 0
            and step_elapsed > self.max_single_step_seconds
            and step.action
            and step.action not in self._long_step_hints
        ):
            self._long_step_hints.add(step.action)
            return BreakerAction(
                action="inject_hint",
                message=(
                    f"⏱️ 检测到单步耗时 {step_elapsed:.0f}s 超过阈值 {self.max_single_step_seconds:.0f}s"
                    f"（动作: {step.action}）。\n"
                    "请立即考虑：\n"
                    "1. 如果是 docker build 之类的长任务，缩短或后台化（加 timeout/&）\n"
                    "2. 如果是网络等待，先 ping 测试连通性\n"
                    "3. 如果是文件处理，缩小输入范围（head/grep/limit）\n"
                    "4. 实在无法加速，请直接给 Final Answer 总结已知线索并终止"
                ),
            )

        # 5. 思维死锁检测（只对非空 Thought 计数）
        if step.thought:
            if step.thought == self._last_thought:
                self._consecutive_same_thought += 1
            else:
                self._consecutive_same_thought = 1
                self._last_thought = step.thought
                self._hinted_deadlock = False  # 思路变了，重置提示标志

            if (
                self._consecutive_same_thought >= self.max_thought_deadlock
                and not self._hinted_deadlock
            ):
                self._hinted_deadlock = True
                # 不重置计数器，但下次相同 Thought 不再注入提示
                # 若思路改变，上面会重置 _hinted_deadlock
                return BreakerAction(
                    action="inject_hint",
                    message=(
                        f"检测到连续 {self._consecutive_same_thought} 轮输出相同 Thought，"
                        "请跳出当前思路：尝试换一个工具、换一个角度，或重新审视题目。"
                    ),
                )

        # 6. 重复动作检测（只对实际工具调用计数）
        if step.action and step.action_input and not step.is_error:
            key = (step.action, step.action_input)
            self._action_counts[key] = self._action_counts.get(key, 0) + 1
            count = self._action_counts[key]
            if count > self.max_repeated_actions and key not in self._hinted_keys:
                self._hinted_keys.add(key)
                return BreakerAction(
                    action="inject_hint",
                    message=(
                        f"检测到动作 `{step.action}({step.action_input[:60]})` "
                        f"已重复执行 {count} 次（阈值 {self.max_repeated_actions}），"
                        "请切换策略或跳过此步骤，避免无效循环。"
                    ),
                )

        # 7. 无效步数检测（同 action + 高度相似 obs）
        # 比"重复动作"更宽松（参数可微变，只要输出类似就视为无效）
        if step.action and step.observation and not step.is_error:
            norm_obs = self._normalize_obs(step.observation)
            if not norm_obs or len(norm_obs) < 10:
                # 太短的 obs（如 "(empty)"）不算无效，避免误判
                return BreakerAction(action="continue")
            last_obs = self._last_obs_per_action.get(step.action, "")
            if last_obs and self._obs_similarity(norm_obs, last_obs) >= self.obs_similarity_threshold:
                self._invalid_step_counts[step.action] = self._invalid_step_counts.get(step.action, 0) + 1
                count = self._invalid_step_counts[step.action]
                if count >= self.max_invalid_steps and step.action not in self._hinted_invalid:
                    self._hinted_invalid.add(step.action)
                    return BreakerAction(
                        action="inject_hint",
                        message=(
                            f"检测到动作 `{step.action}` 已连续 {count} 步产生高度相似的 Observation"
                            f"（相似度 ≥ {self.obs_similarity_threshold}），"
                            "但未取得有效进展。请立即：\n"
                            "1. 停止重复当前工具/命令\n"
                            "2. 重新审视目标：你想从这条 Observation 找到什么？\n"
                            "3. 尝试不同工具（如 python → gdb → strings），或换一组参数\n"
                            "4. 若 2 步内仍无新线索，请给出 Final Answer 总结当前推断"
                        ),
                    )
            else:
                # obs 不相似，重置计数
                self._invalid_step_counts[step.action] = 1
            self._last_obs_per_action[step.action] = norm_obs

        return BreakerAction(action="continue")

    def has_recent_progress(self) -> bool:
        """是否有最近实质进展 (供 ReAct 步数软截断判断).

        超过 max_steps 后, 只要 progress_grace_seconds 内有新的非空 observation
        (实质进展), 就允许继续 — 优先 LLM 软截断/加步, 不做严格硬截断.
        返回 False = 已无进展超过宽限期, 应兜底退出 (防死循环).
        """
        if self._started_at <= 0:
            return True  # 未启动视为允许继续 (避免误杀)
        idle = time.monotonic() - self._last_progress_at
        return idle <= self.progress_grace_seconds

    def stats(self) -> dict[str, Any]:
        """返回当前熔断器统计信息（供报告使用）."""
        return {
            "max_repeated_actions": self.max_repeated_actions,
            "max_thought_deadlock": self.max_thought_deadlock,
            "max_seconds": self.max_seconds,
            "max_steps": self.max_steps,
            "max_cost_usd": self.max_cost_usd,
            "max_workspace_mb": self.max_workspace_mb,
            "action_counts": dict(self._action_counts),
            "consecutive_same_thought": self._consecutive_same_thought,
            "hinted_keys": list(self._hinted_keys),
            "hinted_deadlock": self._hinted_deadlock,
            "hinted_workspace": self._hinted_workspace,
            "accumulated_cost_usd": round(self._accumulated_cost_usd, 6),
            "accumulated_tokens": self._accumulated_tokens,
        }


__all__ = ["BreakerAction", "CircuitBreaker"]
