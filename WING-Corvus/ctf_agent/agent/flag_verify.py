"""Flag 验证系统 (Sprint 36.2): 提交前轨迹检查 — 代码机制 + LLM 审查.

背景 (2026-08-05 hard5 复盘): agent 在 web 题中通过 GitHub API 抓取官方
writeup.md 获得 flag 并直接提交, 轨迹看起来"有工具调用"但 flag 来源是非正常
解题渠道 (外部题解), 现有"至少 1 次工具调用"反幻觉兜底无法拦截.

设计: 两次验证, 均通过才放行提交:
1. 代码机制 (零成本, 先跑):
   - ① flag 必须**出现在某一步的 Observation 中** (flag 来自工具输出, 而非 LLM 记忆/编造)
   - ② flag 出现的步骤若来自可疑渠道 (GitHub/raw.githubusercontent/api.github/
     搜索引擎/官方题解目录), 且 action/输入含 writeup/solution/flags/README/题解 等
     关键词 → 判定为"非正常解题渠道", 拒绝
2. LLM 审查 (仅代码机制通过后):
   - 把最近 N 步轨迹 (Thought/Action/Observation 摘要) 交给审查 LLM,
     判定 flag 是否来自靶机/附件的真实观测, 是否存在幻觉或外部题解污染.
     输出结构化 JSON: {"pass": bool, "reason": str, "confidence": "high/medium/low"}

验证失败 → 不消耗提交次数, 注入反馈让 agent 继续从靶机/附件真实观测中获取 flag.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

# 可疑外部题解渠道 (域名/主机名关键词)
_SUSPICIOUS_HOSTS = (
    "github.com",
    "raw.githubusercontent.com",
    "api.github.com",
    "gist.github.com",
    "gitlab.com",
    "writeup",
    "solver",
    "exploit-db",
    "ctftime",
)
# 可疑内容关键词 (命中说明该步可能在读取外部题解/官方答案文件)
_SUSPICIOUS_KEYWORDS = (
    "writeup",
    "solution",
    "solve.py",
    "solver.py",
    "exploit.js",
    "flags.txt",
    "flag.txt",
    "official",
    "官方",
    "题解",
    "答案",
    "README",
)


@dataclass
class FlagVerifyResult:
    """验证结果."""
    passed: bool = False
    reason: str = ""
    source_step: int = 0          # flag 首次出现的步骤号 (代码机制找到)
    source_channel: str = ""      # 来源渠道: target/attachment/web/suspicious
    llm_pass: bool | None = None  # LLM 判定 (未启用/失败时为 None)
    llm_reason: str = ""
    suspicious_hit: str = ""      # 命中的可疑关键词


class FlagVerifier:
    """提交前 flag 验证器 (代码机制 + 可选 LLM 审查)."""

    def __init__(self, llm: Any = None, *, enable_llm: bool = True,
                 max_trajectory_steps: int = 8, max_chars: int = 6000) -> None:
        self._llm = llm
        self.enable_llm = enable_llm and llm is not None
        self.max_trajectory_steps = max_trajectory_steps
        self.max_chars = max_chars

    # ---------- 对外接口 ----------

    def verify(self, flag_candidate: str, steps: list[Any]) -> FlagVerifyResult:
        """验证 flag_candidate 是否可提交. steps: ReActStep 列表."""
        flag = (flag_candidate or "").strip()
        if not flag:
            return FlagVerifyResult(passed=False, reason="flag 为空")
        # ① 代码机制: flag 必须出现在某步 Observation
        src = self._find_source(flag, steps)
        if src is None:
            return FlagVerifyResult(
                passed=False,
                reason=("flag 未出现在任何工具观测 (Observation) 中. "
                        "它必须来自靶机响应/附件文件的实际读取, 而非记忆或猜测. "
                        "请继续通过工具 (ssh_exec/ssh_python/http_request/file_read 等) "
                        "从靶机或附件中获取 flag 文本后再提交."),
            )
        step_no, observation, action, action_input = src
        res = FlagVerifyResult(source_step=step_no,
                               source_channel=self._classify_channel(action, action_input, observation))
        # ② 代码机制: 自导自演检测 (SU_RSA 假 flag 复盘修复) —
        # flag 若出现在该步的**工具输入** (agent 自己写的脚本/命令) 中,
        # 说明 agent 把猜测/编造的 flag 直接硬编码进脚本再执行,
        # 输出里出现 flag 只是脚本 echo 了它, 并非从附件/靶机真实提取 → 拒绝.
        # 真实解法: flag 应只出现在工具**输出** (解密/读取/靶机响应), 输入中不含 flag.
        core = self._flag_core(flag)
        if flag in action_input or (core and core in action_input):
            return FlagVerifyResult(
                passed=False,
                source_step=step_no,
                source_channel=res.source_channel,
                reason=(
                    "flag 同时出现在该步的工具输入(脚本/命令)中: 疑似 agent 把猜测的 "
                    "flag 硬编码进脚本自导自演, 而非从附件/靶机真实提取. "
                    "真实 flag 必须只来自工具输出观测. 请删除该来源, 重新从靶机/附件获取."
                ),
            )
        # ③ 代码机制: 可疑渠道拦截
        hit = self._suspicious_hit(action, action_input, observation)
        if hit:
            res.passed = False
            res.suspicious_hit = hit
            res.reason = (
                f"flag 出现在第 {step_no} 步, 但该步疑似在读取外部题解/官方答案"
                f"(命中关键词: {hit}). 禁止通过查询 writeup/官方仓库/搜索引擎获取 flag. "
                "请删除该来源, 仅从靶机或附件本身的观测中获取 flag."
            )
            return res
        # ③ LLM 审查 (代码机制通过后)
        if self.enable_llm and self._llm is not None:
            try:
                llm_pass, llm_reason = self._llm_verify(flag, steps)
                res.llm_pass = llm_pass
                res.llm_reason = llm_reason
                if not llm_pass:
                    res.passed = False
                    res.reason = (
                        f"LLM 轨迹审查未通过: {llm_reason}\n"
                        "请重新分析靶机/附件观测, 通过真实工具输出获取 flag."
                    )
                    return res
            except Exception as e:  # noqa: BLE001 - LLM 审查失败不阻断 (降级为代码机制)
                res.llm_pass = None
                res.llm_reason = f"LLM 审查异常, 降级为代码机制: {str(e)[:120]}"
        res.passed = True
        res.reason = (
            f"验证通过: flag 来自第 {step_no} 步工具观测"
            f" ({res.source_channel})"
            + (f"; LLM 审查通过: {llm_reason}" if res.llm_pass else "")
        )
        return res

    # ---------- 代码机制 ----------

    def _find_source(self, flag: str, steps: list[Any]) -> tuple[int, str, str, str] | None:
        """在 Observation 中搜索 flag 子串, 返回 (step_no, observation, action, action_input).

        优先匹配完整 flag; 允许 flag 内容过长时匹配其核心片段 (花括号内前 8 字符)
        以避免观测被截断导致的误判.
        """
        core = self._flag_core(flag)
        for s in steps:
            if s.is_final:
                continue
            obs = (s.observation or "")
            if not obs:
                continue
            if flag in obs:
                return s.step_no, obs, (s.action or ""), (s.action_input or "")
        if core and len(core) >= 8:
            for s in steps:
                if s.is_final:
                    continue
                obs = (s.observation or "")
                if not obs:
                    continue
                if core in obs:
                    return s.step_no, obs, (s.action or ""), (s.action_input or "")
        return None

    @staticmethod
    def _flag_core(flag: str) -> str:
        """提取 flag 花括号内的核心内容 (用于截断观测匹配)."""
        m = re.search(r"\{([^{}]+)\}", flag)
        return (m.group(1) if m else "").strip()

    def _classify_channel(self, action: str, action_input: str, observation: str) -> str:
        """分类 flag 来源渠道."""
        text = f"{action} {action_input}".lower()
        if any(h in text for h in ("http://", "https://")):
            return "web"
        if any(k in text for k in ("file_read", "file_analyze", "strings", "cat", "unzip", "xxd", "file ", "binary")):
            return "attachment"
        return "target"

    def _suspicious_hit(self, action: str, action_input: str, observation: str) -> str:
        """检测该步是否命中可疑外部题解渠道. 返回命中的关键词 (空=未命中)."""
        text = f"{action} {action_input} {observation[:800]}"
        lower = text.lower()
        host_hit = next((h for h in _SUSPICIOUS_HOSTS if h in lower), "")
        kw_hit = next((k for k in _SUSPICIOUS_KEYWORDS if k.lower() in lower), "")
        if host_hit and kw_hit:
            return f"{host_hit}+{kw_hit}"
        # 仅访问 GitHub 且带 readme/flags/题目路径也可疑
        if host_hit in ("github.com", "raw.githubusercontent.com", "api.github.com", "gist.github.com"):
            if any(k in lower for k in ("contents", "raw/", "blob/", "/flags", "/flag", "writeup")):
                return f"{host_hit}+{kw_hit or 'contents/raw'}"
        return ""

    # ---------- LLM 审查 ----------

    _LLM_PROMPT = """你是 CTF 解题轨迹审查员. 判断以下候选 flag 是否**来自靶机或附件的真实观测**,
而不是来自外部题解 (writeup/官方仓库/搜索引擎) 或 LLM 记忆/编造.

## 判定标准 (只要命中任一即 PASS 判定为 False):
1. flag 出现在"读取 GitHub/搜索引擎/官方题解"类操作的输出中 (如 curl github.com、
   raw.githubusercontent、api.github.com、搜索 writeup/solution/flags.txt)
2. 轨迹中没有任何一步直接访问靶机/读取附件 (flag 凭空出现)
3. flag 是编造的 (与所有观测内容无关)
4. flag 只出现在 agent 自己构造并执行的脚本 (docker_python/ssh_python 等) 的
   stdout 中, 而该脚本的**输入/脚本内容本身硬编码了 flag 文本** (即 agent 把猜测的
   flag 写进脚本再 echo 出来, 未从附件文件或靶机响应中真实提取) → 判定为编造

## 判定为 PASS 的情况:
- flag 出现在靶机响应 (HTTP 页面/接口返回)、附件文件内容、或对靶机交互 (nc/pwn/shell)
  的输出中, 且该观测与候选 flag 直接相关.

## 输出 (严格 JSON, 不要输出其他内容):
{{"pass": true/false, "reason": "一句话依据 (引用具体步骤号与观测来源)", "confidence": "high/medium/low"}}

## 候选 flag
{flag}

## 解题轨迹 (最近 {n} 步)
{trajectory}
"""

    def _llm_verify(self, flag: str, steps: list[Any]) -> tuple[bool, str]:
        """LLM 审查轨迹, 返回 (pass, reason)."""
        recent = steps[-self.max_trajectory_steps:]
        lines = []
        for s in recent:
            obs = (s.observation or "")[:1200]
            lines.append(
                f"[step {s.step_no}] Action: {s.action or '(final)'}\n"
                f"  Input: {(s.action_input or '')[:400]}\n"
                f"  Obs: {obs}"
            )
        trajectory = "\n".join(lines)[: self.max_chars]
        prompt = self._LLM_PROMPT.format(flag=flag, n=len(recent), trajectory=trajectory)
        try:
            from ctf_agent.llm import Message
            resp = self._llm.chat(
                messages=[Message(role="system", content="你只输出 JSON.").to_dict(),
                          Message(role="user", content=prompt).to_dict()],
                temperature=0.0,
                max_tokens=300,
            )
            content = getattr(resp, "content", "") or ""
            m = re.search(r"\{.*\}", content, re.DOTALL)
            if not m:
                # SU_RSA 假 flag 复盘修复: LLM 审查输出无法解析时保守拒绝 (fail-closed),
                # 避免"审查不可用 → 放行"导致的幻觉 flag 假阳性.
                return False, "LLM 审查输出无法解析, 保守拒绝 (fail-closed)"
            data = json.loads(m.group(0))
            return bool(data.get("pass")), str(data.get("reason") or "")
        except Exception as e:  # noqa: BLE001
            return False, f"LLM 审查异常, 保守拒绝 (fail-closed): {str(e)[:100]}"


__all__ = ["FlagVerifier", "FlagVerifyResult"]
