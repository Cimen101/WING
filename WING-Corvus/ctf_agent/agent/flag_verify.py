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

Sprint 36.6 修复:
- 不再将 "README" 单独视为可疑关键词 (本地 README.md 是合法附件)
- 优先选择非可疑渠道的 flag 来源 (即使 flag 先在 README 中出现, 只要后来通过其他工具验证即可)
- 只有同时命中外部 host + 可疑关键词才标记为可疑
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
    "exploit-db",
    "ctftime",
)
# 可疑内容关键词 (命中说明该步可能在读取外部题解/官方答案文件)
# 注意: "README" 已移除 — 本地 README.md 是合法附件, 不应被误判
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
)

# Sprint 36.9: 诱饵模式签名 — 用于检测音频隐写/多层编码中的诱饵 flag
# 特征: 格式前缀正确但内容过短, 或格式前缀与预期不符
_DECOY_SIGNATURES = (
    ("csaw{", "csawctf{"),   # well-tempered 诱饵: csaw{...} vs csawctf{...}
    ("flag{", "csawctf{"),   # 同题另一诱饵: flag{...} vs csawctf{...}
    ("CTF{", "CSAW{"),       # 通用: 前缀不匹配
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
        # Sprint 36.7: 跟踪已拒绝的 flag — 防止重复提交相同错误答案
        self._rejected_flags: dict[str, str] = {}  # flag -> reason

    # ---------- 对外接口 ----------

    @staticmethod
    def _decoy_hint(flag: str) -> str:
        """检测 flag 是否为诱饵, 返回提示文本 (空=非诱饵)."""
        for decoy_prefix, expected_prefix in _DECOY_SIGNATURES:
            if flag.startswith(decoy_prefix) and not flag.startswith(expected_prefix):
                return (
                    "\n\n💡 检测到可能为诱饵 flag: "
                    f"以 '{decoy_prefix}' 开头但预期为 '{expected_prefix}' 格式. "
                    "音频隐写/多层编码题往往有诱饵, 需要调整检测参数 "
                    "(阈值/窗口大小/步长/频率) 或尝试不同密码才能提取真实 flag. "
                    "建议: 使用 audio_stego_sweep 工具自动扫描参数组合."
                )
        return ""

    def verify(self, flag_candidate: str, steps: list[Any]) -> FlagVerifyResult:
        """验证 flag_candidate 是否可提交. steps: ReActStep 列表."""
        flag = (flag_candidate or "").strip()
        if not flag:
            return FlagVerifyResult(passed=False, reason="flag 为空")

        # ① 代码机制: 搜索 flag 来源 (明文 + hex/字节编码变体, Sprint 37)
        # Sprint 37 (ida-reverse-course 复盘): reverse 题 flag 常以 hex/字节序列形式
        # 从二进制提取 (objdump/xxd 输出 `666c61677b...` 或 `[102, 108, ...]`),
        # 明文 flag 反而从不直接出现在 observation. 因此同时匹配编码变体.
        all_sources = self._find_all_sources(flag, steps)

        # Sprint 36.7 + Sprint 37 修复: 拒绝记忆改为"软锁" —
        # 只有"当前轨迹仍无任何观测证据"时才拒绝; 一旦出现新证据 (明文或编码),
        # 解除拉黑允许重新验证. 避免 reverse 题中"先用 echo 验证被拒 → 之后干净
        # 提取同 flag 也被永久拦截"的死锁 (CH4 maze 三路全超时根因).
        if flag in self._rejected_flags and not all_sources:
            reason = self._rejected_flags[flag]
            return FlagVerifyResult(
                passed=False,
                reason=f"该 flag 已在之前的验证中被拒绝: {reason}. 请换一个不同的 flag 或从附件/靶机重新获取."
            )
        if all_sources:
            # 有新证据 → 解除拒绝拉黑, 允许重新验证
            self._rejected_flags.pop(flag, None)

        if not all_sources:
            result = FlagVerifyResult(
                passed=False,
                reason=("flag 未出现在任何工具观测 (Observation) 中. "
                        "它必须来自靶机响应/附件文件的实际读取, 而非记忆或猜测. "
                        "请继续通过工具 (ssh_exec/ssh_python/http_request/file_read 等) "
                        "从靶机或附件中获取 flag 文本后再提交."),
            )
            # 记录拒绝原因
            self._rejected_flags[flag] = result.reason
            return result
        # 优先选择非可疑渠道的来源 (如工具输出、解密结果), 避免因 README 首次出现而误拒
        src = None
        for s in reversed(all_sources):
            step_no_s, obs_s, act_s, inp_s = s
            if not self._is_suspicious(act_s, inp_s, obs_s):
                src = s
                break
        if src is None:
            src = all_sources[0]
        step_no, observation, action, action_input = src
        res = FlagVerifyResult(source_step=step_no,
                               source_channel=self._classify_channel(action, action_input, observation))
        # ② 代码机制: 自导自演检测 (Sprint 37: 程序验证豁免)
        core = self._flag_core(flag)
        scripted = (flag in action_input or (core and core in action_input)
                    or any(v in action_input for v in self._encode_variants(flag)))
        if scripted and not self._is_program_verify(action, action_input, observation):
            result = FlagVerifyResult(
                passed=False,
                source_step=step_no,
                source_channel=res.source_channel,
                reason=(
                    "flag 同时出现在该步的工具输入(脚本/命令)中: 疑似 agent 把猜测的 "
                    "flag 硬编码进脚本自导自演, 而非从附件/靶机真实提取. "
                    "真实 flag 必须只来自工具输出观测. 请删除该来源, 重新从靶机/附件获取."
                ),
            )
            # 记录拒绝原因
            self._rejected_flags[flag] = result.reason
            return result
        # ③ 代码机制: 可疑渠道拦截 (仅拦截来源为外部题解的情况)
        hit = self._suspicious_hit(action, action_input, observation)
        if hit:
            res.passed = False
            res.suspicious_hit = hit
            res.reason = (
                f"flag 出现在第 {step_no} 步, 但该步疑似在读取外部题解/官方答案"
                f"(命中关键词: {hit}). 禁止通过查询 writeup/官方仓库/搜索引擎获取 flag. "
                "请删除该来源, 仅从靶机或附件本身的观测中获取 flag."
            )
            # 记录拒绝原因
            self._rejected_flags[flag] = res.reason
            return res
        # ④ LLM 审查 (代码机制通过后)
        if self.enable_llm and self._llm is not None:
            try:
                llm_pass, llm_reason = self._llm_verify(flag, steps)
                res.llm_pass = llm_pass
                res.llm_reason = llm_reason
                if llm_pass is False:
                    # Sprint 36.8: 仅 llm_pass=False (明确拒绝) 才 fail-closed;
                    # llm_pass=None (技术失败) 降级为代码机制, 不拒绝正确 flag.
                    res.passed = False
                    decoy = self._decoy_hint(flag)
                    res.reason = (
                        f"LLM 轨迹审查未通过: {llm_reason}\n"
                        "请重新分析靶机/附件观测, 通过真实工具输出获取 flag."
                        + decoy
                    )
                    # 记录拒绝原因
                    self._rejected_flags[flag] = res.reason
                    return res
            except Exception as e:
                res.llm_pass = None
                res.llm_reason = f"LLM 审查异常, 降级为代码机制: {str(e)[:120]}"
        res.passed = True
        res.reason = (
            f"验证通过: flag 来自第 {step_no} 步工具观测"
            f" ({res.source_channel})"
            + (f"; LLM 审查通过: {llm_reason}" if res.llm_pass else "")
        )
        # 验证通过, 从拒绝列表中移除 (允许后续重试同 flag)
        self._rejected_flags.pop(flag, None)
        return res

    # ---------- 代码机制 ----------

    @staticmethod
    def _encode_variants(flag: str) -> list[str]:
        """生成 flag 的常见编码变体, 用于匹配二进制提取形式的观测 (Sprint 37).

        reverse 题中 agent 常用 objdump/xxd/strings 提取字节, observation 里 flag
        以 hex 串 (`666c61677b...`)、空格分隔 hex (`66 6c 61 67 7b`)、十进制字节列表
        (`[102, 108, 97, 103, 123]`) 等形式出现, 明文反而缺失. 这些编码形式
        与明文等价 (可双向还原), 应作为合法观测来源.
        """
        raw = flag.encode("utf-8", errors="ignore")
        variants = [
            raw.hex(),                                  # 666c61677b...
            " ".join(f"{b:02x}" for b in raw),          # 66 6c 61 67 7b...
            ",".join(str(b) for b in raw),              # 102,108,97,103,123...
            " ".join(str(b) for b in raw),              # 102 108 97 103 123...
            str(list(raw)),                             # [102, 108, 97, 103, 123]
            ",".join(f"0x{b:02x}" for b in raw),        # 0x66,0x6c,0x61...
        ]
        # 去重并过滤过短变体 (长度 < 6 的匹配无意义)
        return [v for v in dict.fromkeys(variants) if len(v) >= 6]

    @staticmethod
    def _is_program_verify(action: str, action_input: str, observation: str) -> bool:
        """判断该步是否为"用 flag 运行程序验证"的合法操作 (Sprint 37).

        reverse 题标准流程: agent 拼出候选 flag 后用 `echo 'flag{...}' | wine ./bin`
        或 `printf 'flag{...}' | ./challenge` 运行程序, 程序输出 Correct!/Right!
        即为 flag 被程序接受的真实观测. 此时 flag 出现在 action_input 是**验证输入**,
        不是"把猜测的 flag 硬编码进脚本自导自演". 判定条件:
        1. action 是运行类工具 (ssh_exec/ssh_python 等) 或输入含运行命令特征
        2. observation 含程序成功接受 flag 的标志 (Correct!/Right!/验证通过/成功等)
        """
        act_inp = f"{action} {action_input}".lower()
        # 输入侧: 含运行程序的命令特征
        run_hint = any(k in act_inp for k in (
            "wine", "./", ".exe", "timeout", "|", "printf", "echo ", "python", "input"
        ))
        # 输出侧: 程序明确接受/验证通过
        obs_lower = (observation or "").lower()
        accept_hint = any(k in obs_lower for k in (
            "correct", "right", "验证通过", "验证成功", "成功", "恭喜",
            "accepted", "success", "win", "passed", "congratulations", "✓"
        ))
        return run_hint and accept_hint

    def _find_all_sources(self, flag: str, steps: list[Any]) -> list[tuple[int, str, str, str]]:
        """搜索所有出现 flag 的观测, 返回 [(step_no, observation, action, action_input), ...].

        匹配优先级 (Sprint 37 扩展, ida-reverse-course CH8 复盘):
        1. 完整 flag 明文
        2. flag 的 hex/字节编码变体 (objdump/xxd 提取场景)
        3. core 前 8 字符 (截断观测场景)
        4. **core 分段覆盖** (拼接式 flag): flag 被垃圾代码/多函数拆分成多个片段,
           每个片段出现在不同观测中 (如 `flag{jun` + `nk_c0d3` + `_h1d3s_i`...),
           完整明文从不单步出现. 若 core 的全部片段可被观测集合覆盖 → 视为
           合法拼接来源 (与手工从附件提取等价), 由 LLM 审查最终把关.
        """
        core = self._flag_core(flag)
        variants = self._encode_variants(flag)
        sources: list[tuple[int, str, str, str]] = []
        seen_steps: set[int] = set()

        for s in steps:
            if s.is_final:
                continue
            obs = (s.observation or "")
            if not obs:
                continue
            if flag in obs or any(v in obs for v in variants):
                sources.append((s.step_no, obs, (s.action or ""), (s.action_input or "")))
                seen_steps.add(s.step_no)

        if core and len(core) >= 8:
            for s in steps:
                if s.is_final:
                    continue
                if s.step_no in seen_steps:
                    continue
                obs = (s.observation or "")
                if not obs:
                    continue
                if core in obs:
                    sources.append((s.step_no, obs, (s.action or ""), (s.action_input or "")))
                    seen_steps.add(s.step_no)

        # ④ core 分段覆盖 (拼接式 flag, CH8 场景)
        if not sources and core and len(core) >= 12:
            fragments = self._split_core(core)
            if fragments:
                frag_steps: list[tuple[int, str, str, str]] = []
                for frag in fragments:
                    if not frag:
                        continue
                    hit = next((s for s in steps
                                if not s.is_final and (s.observation or "")
                                and frag in s.observation), None)
                    if hit is None:
                        frag_steps = []
                        break
                    if not any(fs[0] == hit.step_no for fs in frag_steps):
                        frag_steps.append((hit.step_no, hit.observation or "",
                                           (hit.action or ""), (hit.action_input or "")))
                # 全部片段命中且来自 ≥2 个不同步骤 → 拼接来源成立
                if len(frag_steps) >= 2:
                    sources = frag_steps

        return sources

    @staticmethod
    def _split_core(core: str, frag_len: int = 10) -> list[str]:
        """把 flag core 拆成覆盖全部字符的连续片段 (供分段覆盖匹配).

        策略: 固定长度滑窗 + 剩余补齐, 保证相邻片段有重叠, 覆盖 core 全部字符.
        """
        if not core:
            return []
        frags = [core[i:i + frag_len] for i in range(0, len(core), frag_len - 4)]
        # 过滤空串与过短尾巴 (长度 < 4 的片段无区分度)
        return [f for f in frags if len(f) >= 4]

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

    def _is_suspicious(self, action: str, action_input: str, observation: str) -> bool:
        """判断某步是否来自可疑外部题解渠道 (Sprint 36.6 修复版).

        区分本地文件 (README.md) vs 外部题解 (GitHub writeup):
        - 本地 README/challenge 文件是合法的题目附件, 不应标记为可疑
        - 外部 writeup/solution 才是可疑
        """
        text = f"{action} {action_input} {observation[:400]}".lower()
        # 外部 host + 可疑关键词 = 明确可疑
        external_hosts = ("github.com", "raw.githubusercontent.com",
                          "api.github.com", "gist.github.com", "gitlab.com",
                          "ctftime.org", "exploit-db.com")
        if any(h in text for h in external_hosts):
            if any(k in text for k in ("writeup", "solution", "solver", "exploit",
                                        "官方", "题解", "答案", "flags.txt", "flag.txt")):
                return True
        return False

    def _suspicious_hit(self, action: str, action_input: str, observation: str) -> str:
        """检测该步是否命中可疑外部题解渠道. 返回命中的关键词 (空=未命中).

        Sprint 36.6 修复: 更精准的判断 — 只有同时命中外部 host + 可疑关键词才拦截.
        本地 README.md / challenge 文件不再被误判.
        """
        text = f"{action} {action_input} {observation[:800]}"
        lower = text.lower()

        # 外部 host + 可疑关键词 = 明确可疑
        external_hosts = ("github.com", "raw.githubusercontent.com",
                          "api.github.com", "gist.github.com", "gitlab.com",
                          "ctftime.org", "exploit-db.com")
        host_hit = next((h for h in external_hosts if h in lower), "")
        kw_hit = next((k for k in _SUSPICIOUS_KEYWORDS if k.lower() in lower), "")

        if host_hit and kw_hit:
            return f"{host_hit}+{kw_hit}"

        # 外部 host + 访问特定路径 (如 /flags, /writeup) = 可疑
        if host_hit:
            if any(k in lower for k in ("contents", "raw/", "blob",
                                         "/flags", "/flag", "writeup", "solution", "solver")):
                return f"{host_hit}+contents/raw"

        return ""

    # ---------- LLM 审查 ----------

    _LLM_PROMPT = """你是 CTF 解题轨迹审查员. 判断以下候选 flag 是否**来自靶机或附件的真实观测**,
而不是来自外部题解 (writeup/官方仓库/搜索引擎) 或 LLM 记忆/编造.

## 判定为 PASS 的情况 (任一即可):
1. flag 出现在靶机响应 (HTTP 页面/接口返回)、附件文件内容、或对靶机交互 (nc/pwn/shell)
   的输出中, 且该观测与候选 flag 直接相关.
2. flag 是**对附件/靶机数据执行真实计算得到的结果** (解密/逆向/爆破/攻击脚本输出的明文,
   如 OpenSSL 3DES 解密、RSA 共享 d 恢复后解密、LLL 格攻击输出、CRC/校验逆向等):
   - 前提: 脚本**输入**是附件/靶机数据 (密文/密钥/参数/密文文件), **不含 flag 文本**;
   - flag 只出现在计算**输出**中 (明文/解密结果).
   这是合法的计算产物 (与手工从附件提取 flag 等价), 不是编造, 应判定 PASS.

## 判定为 False 的情况 (任一即拒绝):
1. flag 出现在"读取 GitHub/搜索引擎/官方题解"类操作的输出中 (如 curl github.com、
   raw.githubusercontent、api.github.com、搜索 writeup/solution/flags.txt)
2. 轨迹中没有任何一步访问靶机/读取附件, 且**没有任何解密/逆向计算步骤** (flag 凭空出现)
3. flag 是编造的 (与所有观测内容无关)
4. flag 只出现在 agent 自己构造并执行的脚本 (docker_python/ssh_python 等) 的
   stdout 中, 且该脚本的**输入/脚本内容本身硬编码了 flag 文本** (即 agent 把猜测的
   flag 写进脚本再 echo 出来, 未从附件文件或靶机响应中提取, 也非对附件数据的计算)
   → 自导自演, 判定为编造.
   ⚠️ 注意: 若脚本输入是附件数据 (密文/密钥/参数) 而输出是真实计算得到的明文,
   则**不属于**自导自演, 应判定 PASS (计算产物, 见上第 2 条).

## 输出 (严格 JSON, 不要输出其他内容):
{{"pass": true/false, "reason": "一句话依据 (引用具体步骤号与观测来源)", "confidence": "high/medium/low"}}

## 候选 flag
{flag}

## 解题轨迹 (最近 {n} 步)
{trajectory}
"""

    def _llm_verify(self, flag: str, steps: list[Any]) -> tuple[bool | None, str]:
        """LLM 审查轨迹, 返回 (pass, reason).

        pass=True: LLM 明确通过
        pass=False: LLM 明确拒绝 (幻觉/外部题解)
        pass=None: 技术失败 (LLM 响应无法解析), 降级为代码机制

        Sprint 36.8 修复: 复用 react.py 的鲁棒 JSON 解析 (配平 + markdown 清洗),
        避免 LLM 审查输出含粗体/前后缀文本/尾逗号时 json.loads 失败导致
        fail-closed 误拒"正确 flag" (csaw_capture-the-bee 实证: 正确解密 flag
        因"Expecting property name enclosed in double quotes"被反复拒绝).
        Sprint 36.9 修复: 技术失败返回 None 而非 False, 区分"明确拒绝"与"无法判断".
        """
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
            from ctf_agent.agent.react import _extract_balanced_json, _strip_code_fence
            from ctf_agent.llm import Message
            resp = self._llm.chat(
                messages=[Message(role="system", content="你只输出 JSON.").to_dict(),
                          Message(role="user", content=prompt).to_dict()],
                temperature=0.0,
                max_tokens=300,
            )
            content = getattr(resp, "content", "") or ""
            # 鲁棒提取: 先去 markdown 装饰, 再配平花括号
            cleaned = _strip_code_fence(content)
            jstr = _extract_balanced_json(cleaned) or cleaned
            if not jstr.strip():
                return None, "LLM 审查响应为空, 降级为代码机制"
            # 尾逗号容错
            try:
                data = json.loads(jstr)
            except Exception:
                try:
                    data = json.loads(re.sub(r",\s*([}\]])", r"\1", jstr))
                except Exception:
                    return None, f"LLM 审查响应 JSON 解析失败, 降级为代码机制: {jstr[:80]}"
            return bool(data.get("pass")), str(data.get("reason") or "")
        except Exception as e:
            return None, f"LLM 审查异常, 降级为代码机制: {str(e)[:100]}"


__all__ = ["FlagVerifier", "FlagVerifyResult"]