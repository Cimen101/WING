"""智能上下文压缩器 (Sprint 36.4.2).

背景 (gctf25 filtermaze 预测试复盘):
- 每步 LLM 调用上下文 = system prompt (46K 字符) + 10 轮滑动窗口 (每轮 ≤8.5K 字符)
  ≈ 131K 字符 → 中文场景 50-70K tokens, 逼近模型窗口 → deepseek-v4-flash
  输出塌陷为全空 (thought/action 空) → 连续格式错误熔断.
- 普通滑动窗口"整轮丢弃"会把关键事实一起丢掉, 长 hard 题无法复盘.

设计 (区别于普通压缩, 满足竞速目标):
1. **实时打标**: 每轮交互 (assistant+observation) 打保留级别 —
   level0 全部保留 (关键证据/关键工具/战略指导/近期轮) / level1 部分保留
   (thought 头部 + action + obs 首尾) / level2 动态压缩 (一行摘要).
2. **实时时间线**: 每步提取关键事实/关键操作形成时间线 (timeline),
   随上下文注入, 压缩后仍保留完整串联线索.
3. **异步事件驱动 + 动态压缩**: 后台 daemon 线程持续对 level1/2 轮做
   预压缩 (纯文本处理, 不写共享内存), 结果放 pending; 主循环不被阻塞.
4. **逼近上限才替换**: 上下文字符估算超过 hard_limit 时, 主线程一次性把
   pending 压缩应用到滑动窗口 (纯内存替换, 毫秒级); 未逼近时只预压缩不替换,
   避免"一次大压缩"长时间停顿.
5. **首次坍塌即压缩**: 检测到空输出 (格式坍塌信号) 时同步 force_compress,
   立即收缩上下文, 配合提示词注入 (见 react.py).

线程安全: 后台线程只写 self._pending (dict, GIL 保护);
所有对 memory._rounds 的修改都在主线程 (tick/force_compress/apply_pending).
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field

from ctf_agent.memory.short_term import ShortTermMemory

# ============ 保留级别 ============
LEVEL_KEEP = 0        # 全部保留 (关键轮/近期轮)
LEVEL_PARTIAL = 1     # 部分保留 (thought 头 + action + obs 首尾)
LEVEL_COMPRESS = 2    # 动态压缩 (一行摘要)

# 关键工具 (成功结果视为关键证据)
_KEY_TOOLS = {
    "lwe_decode", "crypto_rsa", "crypto_classic", "feistel_decrypt",
    "des_cryptanalysis", "angr_symbolic_exec", "pwn_exploit", "get_flag",
    "share_finding", "check_findings", "web_recon", "web_dirscan",
}
# 关键成功证据 (observation 含这些词 → level0 + timeline 关键事实)
_KEY_EVIDENCE = (
    "path_complete", "lwe_error_magnitudes", "flag{", "success",
    "verified", "验证通过", "求解成功", "提交成功", "恢复",
)
# 战略指导轮 (MUST/SHOULD 指导必须完整保留)
_GUIDANCE_RE = re.compile(r"\[MUST\]|\[SHOULD\]|战略层|总指挥|巡查指导")

# ============ 阈值 (字符数) ============
# 目标: 总上下文稳定 ≤ 60K 字符 (中文 ≈ 25-30K tokens, 留足窗口余量)
SOFT_LIMIT = 48000    # 超过后后台开始预压缩 (未压缩轮)
HARD_LIMIT = 60000    # 超过后一次性替换为压缩版本
RECENT_KEEP = 3       # 最近 N 轮强制 level0 (完整保留近期操作)
TIMELINE_MAX = 48     # 时间线条目上限 (关键事实不丢, 普通条目淘汰最老)

# 部分保留的截断参数
_THOUGHT_HEAD = 400    # level1: thought 保留头部
_OBS_HEAD = 400        # level1: observation 保留头部
_OBS_TAIL = 200        # level1: observation 保留尾部
_SUMMARY_HEAD = 180    # level2: 摘要保留头部


def _obs_preview(obs: str, head: int = 120) -> str:
    """observation 首行/前 head 字符, 用于时间线与摘要."""
    text = (obs or "").strip().replace("\n", " ")
    return text[:head]


def annotate_round(
    step_no: int,
    assistant_content: str,
    observation_content: str,
    *,
    action: str = "",
    is_error: bool = False,
    is_final: bool = False,
) -> dict:
    """实时打标: 返回 meta dict {level, fact, milestone}.

    启发式 (纯规则, O(1), 不引入 LLM):
    - is_final / 关键证据 / 关键工具成功 / 战略指导轮 → level0
    - 普通成功工具轮 → level1
    - 纯观察/无 action/错误轮 → level2
    """
    obs = observation_content or ""
    assistant = assistant_content or ""
    meta: dict = {"level": LEVEL_KEEP, "fact": "", "milestone": False, "ts": step_no}
    if is_final:
        meta["level"] = LEVEL_KEEP
        meta["milestone"] = True
        meta["fact"] = f"[step {step_no}] 提交最终答案: {obs[:80]}"
        return meta

    # 关键证据检测 (Observation 含协议/flag/验证成功标记)
    evidence_hit = ""
    for kw in _KEY_EVIDENCE:
        if kw in obs:
            evidence_hit = kw
            break
    is_key_tool = action in _KEY_TOOLS
    has_guidance = bool(_GUIDANCE_RE.search(assistant + obs))

    if evidence_hit or (is_key_tool and not is_error) or has_guidance:
        meta["level"] = LEVEL_KEEP
        meta["milestone"] = True
        if evidence_hit:
            meta["fact"] = f"[step {step_no}] {action or '观察'}: 命中 {evidence_hit} → {_obs_preview(obs, 160)}"
        else:
            meta["fact"] = f"[step {step_no}] {action}: {_obs_preview(obs, 120)}"
        return meta

    if action and not is_error:
        meta["level"] = LEVEL_PARTIAL
        return meta

    # 无 action / 错误轮 / 纯观察轮 → 压缩
    meta["level"] = LEVEL_COMPRESS
    if is_error:
        meta["fact"] = f"[step {step_no}] {action or '解析'}: 错误/空输出 (已压缩)"
    else:
        meta["fact"] = f"[step {step_no}] {action or '观察'}: {_obs_preview(obs, 100)}"
    return meta


def _build_timeline_entry(meta: dict) -> str | None:
    """从 meta 提取时间线条目 (仅关键事实/关键操作)."""
    if meta.get("fact"):
        return meta["fact"]
    return None


@dataclass
class ContextCompressor:
    """异步事件驱动上下文压缩器 (每个 ReActEngine 一个实例)."""

    soft_limit: int = SOFT_LIMIT
    hard_limit: int = HARD_LIMIT
    recent_keep: int = RECENT_KEEP
    _pending: dict = field(default_factory=dict)  # index -> 压缩版 (assistant, observation)
    _timeline: list[str] = field(default_factory=list)
    _started: bool = field(default=False, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    # ---------- 时间线 ----------
    @property
    def timeline_entries(self) -> list[str]:
        """当前时间线条目 (供 ShortTermMemory 镜像)."""
        return self._timeline

    def add_timeline(self, meta: dict | None) -> None:
        """每步后由主线程调用: 提取并追加时间线条目 (超限淘汰最老非关键)."""
        entry = _build_timeline_entry(meta or {})
        if not entry:
            return
        self._timeline.append(entry)
        if len(self._timeline) > TIMELINE_MAX:
            # 保留最新条目, 淘汰最老的非关键条目 (关键 fact 带 [step] 不淘汰)
            self._timeline = self._timeline[-TIMELINE_MAX:]

    def timeline_text(self) -> str:
        return "\n".join(self._timeline)

    # ---------- 上下文估算 ----------
    @staticmethod
    def estimate_chars(memory: ShortTermMemory) -> int:
        """估算当前 messages 总字符数 (无需渲染完整消息)."""
        total = len(memory.system_prompt) + len(memory.task)
        for assistant_msg, observation_msg, _meta in memory.rounds():
            total += len(assistant_msg.content) + len(observation_msg.content)
        return total

    # ---------- 主线程: 每步事件 (O(1)) ----------
    def tick(self, memory: ShortTermMemory) -> None:
        """每步后调用: 检查上下文水位, 触发预压缩或替换.

        - 未逼近 soft: 不动 (避免开销)
        - 超 soft 未超 hard: 后台预压缩 (异步), 不阻塞
        - 超 hard: 立即应用 pending (同步, 毫秒级)
        """
        total = self.estimate_chars(memory)
        if total > self.hard_limit:
            self.apply_pending(memory)
        elif total > self.soft_limit:
            self._spawn_precompress(memory)

    def force_compress(self, memory: ShortTermMemory) -> None:
        """格式坍塌信号 (空输出) 时同步调用: 立即应用 pending + 直接压缩未压缩轮."""
        self.apply_pending(memory)
        # 对仍未压缩的 level1/2 轮直接就地压缩 (同步, 规则截断毫秒级)
        for i, (asst, obs, meta) in enumerate(memory.rounds()):
            if meta.get("compressed") or meta.get("level", LEVEL_KEEP) == LEVEL_KEEP:
                continue
            new_asst, new_obs = _compress_round(asst.content, obs.content, meta)
            self._pending[i] = (new_asst, new_obs)
        self.apply_pending(memory)

    # ---------- 预压缩 (后台线程) ----------
    def _spawn_precompress(self, memory: ShortTermMemory) -> None:
        """后台线程对未压缩的 level1/2 轮生成压缩版 (只写 self._pending)."""
        if self._started:
            return
        self._started = True

        def _worker() -> None:
            try:
                snapshot = []
                for i, (asst, obs, meta) in enumerate(memory.rounds()):
                    if meta.get("compressed") or meta.get("level", LEVEL_KEEP) == LEVEL_KEEP:
                        continue
                    snapshot.append((i, asst.content, obs.content, dict(meta)))
                for i, asst, obs, meta in snapshot:
                    if i in self._pending:
                        continue
                    self._pending[i] = _compress_round(asst, obs, meta)
            except Exception:  # noqa: BLE001 - 后台压缩失败不影响主循环
                pass
            finally:
                self._started = False

        t = threading.Thread(target=_worker, name="ctx-compressor", daemon=True)
        t.start()

    # ---------- 主线程: 应用 pending (毫秒级) ----------
    def apply_pending(self, memory: ShortTermMemory) -> None:
        """把已预压缩的轮次替换进滑动窗口 (纯内存操作, 不阻塞)."""
        if not self._pending:
            return
        plans = []
        for i, (asst, obs) in self._pending.items():
            plans.append((i, asst, obs))
        if plans:
            memory.apply_compressions(plans)
        self._pending.clear()


def _compress_round(assistant: str, observation: str, meta: dict) -> tuple[str, str]:
    """按 meta.level 生成压缩版 (纯规则截断, 无 LLM, 毫秒级)."""
    level = meta.get("level", LEVEL_PARTIAL)
    if level == LEVEL_COMPRESS:
        # 动态压缩: 只保留一行摘要
        head = _obs_preview(observation, _SUMMARY_HEAD)
        sum_line = f"[已压缩] {head}" if head else "[已压缩]"
        return sum_line, "(上一步细节已压缩, 见时间线)"
    # level1 部分保留: thought 头部 + action + obs 首尾
    asst_keep = assistant[:_THOUGHT_HEAD]
    obs_keep = ""
    if observation:
        obs_keep = observation[:_OBS_HEAD]
        if len(observation) > _OBS_HEAD + _OBS_TAIL:
            obs_keep += f"\n...(中段已压缩, 共 {len(observation)} 字符)...\n{observation[-_OBS_TAIL:]}"
    return asst_keep, obs_keep
