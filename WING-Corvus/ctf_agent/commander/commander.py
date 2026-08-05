"""总指挥 (Commander) — 全局协作指挥.

三层协作小队 (Coordinated Squad) 的顶层:
- 领题时按风格差异分配探索任务 (任务契约)
- 接收战略层汇报 (report: clue/dead_end/question)
- 全局方向校准 → 下发 directive (方向性指引, 非强制枷锁)
- 静默原则: 方向正确且无重大收获时不下发指令

与战略层的通信走 FileBus (跨进程共享):
- 战略层 post_report → 总指挥 consume_reports → LLM 分析 →
  总指挥 post_directive → 战略层 check_directives

设计约束 (docs/sprint36_commander_design.md):
- 只聚合汇报的事实摘要 (FACT/LIKELY), 不读轨迹全文
- 任务=方向性指引非强制枷锁: 战略层遇明确死路可自动切换+事后 dead_end 汇报
- 反幻觉: 未汇报内容不得作为依据; 证据不足保持静默
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from ctf_agent.commander.prompts import (
    _ANALYZE_REPORTS_USER_TEMPLATE,
    _COMMANDER_SYSTEM_PROMPT,
    _INITIAL_ASSIGN_USER_TEMPLATE,
    _P1_SUMMARY_USER_TEMPLATE,
    _P2_VERIFY_USER_TEMPLATE,
)

# LLM 输出可能带 markdown 装饰/代码块, 提取首个 JSON 对象
_RE_CODE_FENCE = re.compile(r"^```(?:json)?\s*\n?|\n?```\s*$", re.MULTILINE)
_RE_MD_BOLD = re.compile(r"^[\*_`]+|[\*_`]+$", re.MULTILINE)
_RE_JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)

# 汇报证据分级: 只有 FACT/LIKELY 可作 MUST 依据
_MUST_LEVELS = ("FACT", "LIKELY")

# 默认参与风格 (与 swarm 默认一致)
DEFAULT_STYLES = ["conservative", "aggressive", "innovative"]

_CONTEXT_WINDOW = 12  # 历史上下文保留条数 (只聚合摘要, 控制 token)

# (WING-Corvus P1): 某路超过该秒数未向总指挥汇报 → 无进展信号
# (任务驱动 + 进度汇报驱动的监控侧: 总指挥持续监控汇报流, 长时间无进展则介入调整)
_STALE_REPORT_SECS = 60.0


def _strip_code_fence(text: str) -> str:
    """去除 LLM 输出的 ```json 代码块与前后 markdown 加粗装饰."""
    if not text:
        return text
    text = _RE_CODE_FENCE.sub("", text)
    text = _RE_MD_BOLD.sub("", text)
    return text.strip()


def _extract_json(text: str) -> dict | None:
    """从 LLM 输出中提取首个 JSON 对象 (容错 markdown/前后缀文本)."""
    if not text:
        return None
    cleaned = _strip_code_fence(text)
    m = _RE_JSON_OBJECT.search(cleaned)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


@dataclass
class TaskAssignment:
    """总指挥分配的任务契约 (方向性指引, 非强制枷锁)."""

    task_no: int
    style: str
    task: str
    rationale: str = ""


@dataclass
class CommanderDirective:
    """总指挥下发的方向指令."""

    style: str
    direction: str
    task_no: int = 0
    priority: str = "SHOULD"  # MUST = 明确方向错误/死路; SHOULD = 方向性建议 (默认)
    reason: str = ""


class Commander:
    """全局总指挥 (runner 层 LLM 组件).

    Args:
        llm: LLM 客户端 (RoutedLLMClient 或兼容 chat 接口)
        title: 题目名
        task_desc: 题目描述
        challenge_type: 题型
        challenge_difficulty: 难度
        styles: 参与风格列表 (默认 conservative/aggressive/innovative)
        bus: FileBus 实例 (可选; 无 bus 时 consume/post 跳过, 供单测)
        bus_challenge_id: 总线键 (默认 challenge_id)
        context_window: 历史上下文保留条数
    """

    def __init__(
        self,
        llm: Any,
        title: str = "",
        task_desc: str = "",
        challenge_type: str = "",
        challenge_difficulty: str = "",
        styles: list[str] | None = None,
        challenge_id: str = "commander",
        bus: Any = None,
        bus_challenge_id: str = "",
        context_window: int = _CONTEXT_WINDOW,
    ) -> None:
        self.llm = llm
        self.title = title
        self.task_desc = task_desc
        self.challenge_type = challenge_type
        self.challenge_difficulty = challenge_difficulty
        self.challenge_id = challenge_id
        self.bus = bus
        self.bus_key = bus_challenge_id or challenge_id
        self.styles = list(styles) if styles else list(DEFAULT_STYLES)
        self.context_window = max(2, int(context_window))

        # 状态
        self._assignments: dict[str, TaskAssignment] = {}  # style → 任务契约
        self._context: list[str] = []       # 历史摘要 (指令 + 汇报), 时间序
        self._report_cursor: int = 0        # report 消费游标
        self._last_analyze_ts: float = 0.0
        self._directive_count = 0

        # ── WING-Corvus 2.0: 多阶段状态机 (P1 侦查 / P2 漏洞识别 / P3 利用 / P4 验证) ──
        self._phase: str = "P1"             # 当前阶段 (初始 P1 侦查)
        self._phase_enter_ts: float = time.time()
        # 每路最近汇报跟踪 (卡住/趋同检测): {style: {"last_ts", "topics": [str...], "fails": int,
        #                                             "progress_count": int, "reported": bool}}
        self._style_reports: dict[str, dict] = {}
        self._convergence_events: list[str] = []   # 路径趋同事件记录 (累计 ≥2 → MUST)
        # 主方向与备选方向管理 (主方向修改仅两种途径: 保守/激进证伪; 创新经允许深入证实)
        self._main_direction: str = ""              # 当前主方向 (P1 完成后由全局情报摘要确定)
        self._alt_directions: list[str] = []        # 备选方向列表 (创新发散确认的可能性方向)
        # 阶段切换的规则阈值 (改为"任务驱动 + 进度汇报驱动", 非步数硬门槛)
        # P1→P2: 三路全部完成侦查汇报 (progress_count ≥1 且无死锁) 才进入 P2
        self._phase_p3_fail_threshold = 2   # P3→P2: 多路连续失败数 (激进+保守均报告失败)

    # ---------- 领题: 任务分解与分工 ----------

    def assign_initial(self, bus: Any = None) -> list[TaskAssignment]:
        """LLM 任务分解 → 按风格分工. 返回任务契约列表 (并记录到状态)."""
        styles_block = "\n".join(f"- {s}" for s in self.styles)
        user_prompt = _INITIAL_ASSIGN_USER_TEMPLATE.format(
            title=self.title or self.challenge_id,
            challenge_type=self.challenge_type or "misc",
            challenge_difficulty=self.challenge_difficulty or "?",
            task_desc=(self.task_desc or "")[:1500],
            styles=styles_block,
        )
        obj = self._llm_json(
            [_COMMANDER_SYSTEM_PROMPT, user_prompt], max_tokens=600, tag="assign"
        )
        assignments: list[TaskAssignment] = []
        if obj and isinstance(obj.get("assignments"), list):
            for i, a in enumerate(obj["assignments"]):
                style = str(a.get("style") or "").strip().lower()
                task = str(a.get("task") or "").strip()
                if not style or style not in self.styles or not task:
                    continue
                # 任务契约编号统一按顺序递增 (忽略 LLM 输出, 保证唯一性,
                # 战略层以 task_no 识别当前任务契约)
                assignment = TaskAssignment(
                    task_no=i + 1,
                    style=style,
                    task=task,
                    rationale=str(a.get("rationale") or "")[:200],
                )
                self._assignments[style] = assignment
                assignments.append(assignment)
        # 兜底: LLM 未覆盖的风格, 按默认方向补齐 (保证任务契约完整)
        covered = {a.style for a in assignments}
        for style in self.styles:
            if style not in covered:
                assignments.append(TaskAssignment(
                    task_no=0,  # 占位, 下方统一编号
                    style=style,
                    task=self._default_task(style),
                    rationale="LLM 未分配, 默认方向兜底",
                ))
        # 统一按 styles 顺序分配 task_no (唯一且稳定, 战略层以 task_no 识别契约)
        ordered = {a.style: a for a in assignments}
        final: list[TaskAssignment] = []
        for idx, style in enumerate(self.styles, start=1):
            a = ordered.get(style)
            if a is None:
                continue
            a.task_no = idx
            final.append(a)
        self._assignments = {a.style: a for a in final}
        assignments = final
        self._context.append(
            f"[领题] 分工: " + "; ".join(
                f"{a.style}→任务{a.task_no}: {a.task[:80]}" for a in assignments
            )
        )
        self._trim_context()
        return assignments

    @staticmethod
    def _default_task(style: str) -> str:
        """LLM 未覆盖风格时的默认方向 (与设计文档 2.2 领题示例一致)."""
        return {
            "conservative": "主攻静态结构: 梳理文件格式/架构/关键函数, 稳健推进",
            "aggressive": "主攻动态验证: 运行观察/调试/快速试错, 定位核心逻辑",
            "innovative": "主攻非常规路径: 符号执行/代数闭式解/侧信道/线索交叉",
        }.get(style, f"按 {style} 风格探索解题路径")

    # ---------- 汇报消费 ----------

    def consume_reports(self, bus: Any = None) -> list[dict]:
        """从总线拉取新的战略层汇报 (append 到上下文摘要), 返回本次新汇报.

        只聚合 FACT/LIKELY 的摘要进上下文 (控制 token); POSSIBLE 汇报仅本次可见.
        """
        b = bus or self.bus
        if b is None:
            return []
        try:
            reports, new_cursor = b.check_reports(self.bus_key, cursor=self._report_cursor)
            self._report_cursor = new_cursor
        except Exception:
            return []
        for r in reports:
            level = str(r.get("level") or "FACT").upper()
            if level not in ("FACT", "LIKELY"):
                continue  # POSSIBLE 不聚合进上下文 (防误导)
            self._context.append(
                f"[汇报:{r.get('report_type', 'clue')}] {r.get('agent', '?')}"
                f"(任务{r.get('task_no', '?')}, {level}): {str(r.get('content') or '')[:200]}"
            )
        self._update_style_reports(reports)
        self._trim_context()
        return reports

    # ---------- WING-Corvus 2.0: 多阶段状态机与规则检测 ----------

    # 主题提取停用词 (排除通用词, 保留 CTF 方向性词)
    _TOPIC_STOPWORDS = {
        "the", "and", "for", "with", "that", "this", "from", "have", "has",
        "was", "were", "will", "been", "but", "not", "are", "you", "your",
        "step", "stepno", "agent", "style", "task", "taskno", "report",
        "continue", "应该", "需要", "进行", "已经", "可以", "是否", "当前",
        "使用", "通过", "这个", "一个", "发现", "结果", "问题", "信息",
    }
    # CTF 中文方向关键词表 (命中即为主题词, 解决短中文汇报提取不到词的问题)
    _CN_TOPIC_KEYWORDS = (
        "basename", "绕过", "编码", "解码", "注入", "爆破", "解密", "加密",
        "偏移", "源码", "指纹", "路径", "命令", "密码", "哈希", "异或", "xor",
        "侧信道", "越权", "上传", "反序列化", "序列化", "目录", "扫描", "端口",
        "漏洞", "payload", "exploit", "exp", "shell", "webshell", "include",
        "lfi", "rfi", "ssti", "sql", "命令执行", "代码执行", "文件包含",
        "读取", "截断", "截获", "字节", "溢出", "堆", "栈", "格式化", "字符串",
        "flag", "key", "secret", "utils", "参数", "请求", "响应", "cookies",
        "session", "鉴权", "认证", "逻辑", "竞态", "race", "时间", "差异",
    )

    def _extract_topics(self, content: str) -> set[str]:
        """从汇报内容提取方向主题词 (英文 token + 中文预置词 + 中文 n-gram)."""
        if not content:
            return set()
        lower = content.lower()
        topics: set[str] = set()
        # 1. 英文 token (≥3 字母, 非停用词)
        for w in re.findall(r"[a-zA-Z][a-zA-Z0-9_]{2,}", lower):
            if w not in self._TOPIC_STOPWORDS:
                topics.add(w)
        # 2. 中文预置方向词 (命中即加入)
        for kw in self._CN_TOPIC_KEYWORDS:
            if kw in lower:
                topics.add(kw)
        # 3. 中文 2/3 字 n-gram 兜底: 仅当预置词+英文均未命中 (纯生僻中文短文本) 时启用.
        #    不设为常备 — n-gram 噪声词 (如"径绕/码技") 会稀释主题重叠度, 干扰趋同检测.
        if not topics:
            cn = re.findall(r"[\u4e00-\u9fff]{2,}", content)
            if cn:
                ngrams: list[str] = []
                for s in cn:
                    for n in (2, 3):
                        if len(s) >= n:
                            for i in range(len(s) - n + 1):
                                ngrams.append(s[i:i + n])
                if ngrams:
                    from collections import Counter
                    top = Counter(ngrams).most_common(4)
                    for word, _ in top:
                        if word not in self._TOPIC_STOPWORDS:
                            topics.add(word)
        return topics

    def _update_style_reports(self, reports: list[dict]) -> None:
        """更新每路最近汇报跟踪 (主题 + 失败计数 + 进度计数), 供趋同/卡住/阶段切换."""
        for r in reports:
            style = str(r.get("agent") or "").strip()
            if not style:
                continue
            content = str(r.get("content") or "")
            topics = self._extract_topics(content)
            rtype = str(r.get("report_type") or "clue")
            # 失败信号: dead_end 汇报 或 内容含失败/无效/证伪 关键词
            fail_signals = ("dead_end",)
            is_fail = rtype in fail_signals or any(
                k in content.lower() for k in ("失败", "无效", "证伪", "不可行", "无法", "failed"))
            entry = self._style_reports.setdefault(style, {
                "topics": [], "fails": 0, "last_ts": 0.0, "last_report": "",
                "progress_count": 0, "reported": False,
                "recon_done": False, "recon_done_summary": "",
            })
            if topics:
                entry["topics"].append(topics)
                entry["topics"] = entry["topics"][-3:]  # 只保留最近 3 条
            if is_fail:
                entry["fails"] += 1
            else:
                entry["fails"] = 0
            # progress 汇报 (P1 侦查进度) — 累计该路完成的侦查汇报数
            if rtype == "progress":
                entry["progress_count"] += 1
                entry["reported"] = True
            # (2026-08-05 校准): recon_done = 该路 P1 侦查完成
            # (战略层 LLM 判断基础侦查已覆盖题目全貌). 三路全部完成后才整合全局情报 → P2.
            if rtype == "recon_done":
                entry["recon_done"] = True
                entry["recon_done_summary"] = content[:200]
            entry["last_ts"] = time.time()
            entry["last_report"] = content[:150]

    def _phase_advance_rule(self) -> str:
        """基于当前汇报状态, 规则判定阶段切换 (重构: 任务驱动 + 进度汇报驱动).

        核心变更 (2026-08-05, 用户规范校准):
        - **P1→P2: 三路全部完成侦查汇报** (progress_count ≥1 且无死锁) 才进入 P2.
          不再是"任一 LIKELY 或汇报数≥4"的宽松门槛 — P1 必须对整题全面了解.
          简单题侦查范围收敛 (总指挥领题时按难度定制), 难题发散; 定期汇报防卡死.
        - **P2→P3: 某方向有足够证据支撑并取得验证** (verified 信号), 且总指挥
          LLM 分析确凿后才切换. 不再是"任一 FACT clue"的宽松门槛.
        - P3→P2: ≥2 路报告失败/死路且无 FACT 成功 (方向错误回退, 优先于前进)
        - P3→P4: 汇报含 flag 候选 (report_type=flag 或 content 含 flag 模式)
        返回新阶段; 无切换返回当前.
        """
        fact_clues, likely_reports, fail_styles, flag_candidate, verified = (
            self._collect_phase_signal())
        cur = self._phase
        # 回退优先: P3 时 ≥2 路失败且无 FACT 成功 → 直接回 P2 (本轮不再前进)
        if cur == "P3":
            if len(fail_styles) >= self._phase_p3_fail_threshold and fact_clues == 0:
                return "P2"
            if flag_candidate:
                return "P4"
        # 前进链路 (每级都有确凿门槛, 不能跳过)
        while True:
            nxt = cur
            if cur == "P1":
                # P1→P2: 三路全部完成侦查 (recon_done) 才可切换 (任务驱动 + 进度汇报驱动).
                # 2026-08-05 校准: 不再用"任一 progress 即算完成" — 战略层 LLM 判断
                # 该路基础侦查已覆盖题目全貌 (recon_done) 才算完成; 全部完成后由
                # run_once 触发全局情报摘要整合 + 主方向确定, 之后才正式进入 P2.
                all_done = all(
                    entry.get("recon_done") for entry in self._style_reports.values()
                ) and len(self._style_reports) >= len(self.styles)
                if all_done:
                    nxt = "P2"
            elif cur == "P2" and verified:
                # P2→P3: 存在已验证的方向 (证据支撑 + 验证通过), 由总指挥 LLM 确凿确认
                nxt = "P3"
            elif cur == "P3" and flag_candidate:
                nxt = "P4"
            if nxt == cur:
                break
            cur = nxt
        return cur

    def _p1_synthesize(self, bus: Any = None) -> list[CommanderDirective]:
        """(WING-Corvus P1): 三路侦查全部完成 → 整合全局情报摘要 + 确定主方向.

        流程 (用户规范 2026-08-05):
        1. 拉取三路全部 progress/recon_done 汇报 (各自独立侦查的成果)
        2. LLM 汇总生成**全局情报摘要** + **主方向** + 备选方向
        3. 记录摘要与主方向 (主方向正式确定, 之后修改仅两种途径)
        4. 广播 P2 分工指令 (随指令附带全局情报摘要, phase=P2 同步下发)
        LLM 失败时降级: 用汇报原文拼接摘要, 不阻塞阶段推进.
        """
        b = bus or self.bus
        reports_block = self._format_p1_reports(b)
        user_prompt = _P1_SUMMARY_USER_TEMPLATE.format(
            title=self.title or self.challenge_id,
            challenge_type=self.challenge_type or "misc",
            challenge_difficulty=self.challenge_difficulty or "?",
            reports=reports_block,
        )
        obj = self._llm_json(
            [_COMMANDER_SYSTEM_PROMPT, user_prompt], max_tokens=900, tag="p1_summary"
        )
        summary = ""
        if obj:
            summary = str(obj.get("summary") or "").strip()[:500]
            md = str(obj.get("main_direction") or "").strip()
            if md:
                self._main_direction = md[:200]
            alt = obj.get("alt_directions") or []
            if isinstance(alt, list):
                self._alt_directions = [str(a).strip()[:200] for a in alt if str(a).strip()]
        if not summary:
            summary = self._fallback_p1_summary(b)
        # 记录全局情报摘要 + 主方向确定
        self._context.append(f"[P1 汇总] 全局情报摘要: {summary[:150]}")
        if self._main_direction:
            self._context.append(f"[主方向确定] {self._main_direction[:120]}")
        # 正式进入 P2 (先于广播: 即使后续广播失败, 阶段也已正确切换.
        # run_once 中 _p1_synthesize 返回非空即 return, 故必须在此处完成切换)
        self._set_phase("P2")
        self._trim_context()
        # 广播 P2 分工指令 (附带全局情报摘要, 各路据此进入 P2 阶段)
        dirs: list[CommanderDirective] = []
        p2_tasks = {
            "conservative": "P2 漏洞识别: 稳步推进主方向 — 每步充分验证 (保护/偏移/脚本稳健), "
                            "捕捉激进遗漏的细节线索",
            "aggressive": "P2 漏洞识别: 快速深入主方向 — 构造最小验证 payload 快速验证漏洞"
                          "存在性, 优先效率忽略部分细节",
            "innovative": "P2 漏洞识别: 发散探索可能方向 — 浅层搜集线索并向上汇报, 不深入"
                          "任何单一方向; 经总指挥允许后才可深入",
        }
        for style in self.styles:
            task = p2_tasks.get(style)
            if not task:
                continue
            d = self._make_directive(
                style,
                f"{task}\n[全局情报摘要] {summary[:200]}",
                priority="SHOULD",
                reason="P1 三路侦查全部完成, 全局情报摘要已生成并确定主方向, 进入 P2",
            )
            if d:
                dirs.append(d)
        if dirs:
            self.post_directives(dirs, bus=b)
        return dirs

    def _fallback_p1_summary(self, bus: Any = None) -> str:
        """LLM 汇总失败时的降级摘要: 拼接三路 recon_done/progress 汇报原文."""
        parts: list[str] = []
        for entry in self._style_reports.values():
            if entry.get("recon_done_summary"):
                parts.append(entry["recon_done_summary"][:80])
            elif entry.get("last_report"):
                parts.append(entry["last_report"][:80])
        return "全局情报摘要(降级): " + (" | ".join(parts) if parts else "三路侦查已完成")

    def _format_p1_reports(self, bus: Any = None) -> str:
        """拉取全部 progress/recon_done 汇报 (P1 侦查成果), 格式化供汇总分析."""
        b = bus or self.bus
        if b is None:
            return "(无汇报)"
        try:
            reports, _ = b.check_reports(self.bus_key, cursor=0)
        except Exception:
            return "(无汇报)"
        p1 = [r for r in reports if str(r.get("report_type") or "") in ("progress", "recon_done")]
        if not p1:
            return "(无 P1 侦查汇报)"
        lines = []
        for r in p1[-12:]:  # 最近 12 条进度/完成汇报
            lines.append(
                f"- [{r.get('report_type', 'progress')}] {r.get('agent', '?')} "
                f"(任务{r.get('task_no', '?')}, {r.get('level', '?')}): "
                f"{str(r.get('content') or '')[:250]}"
            )
        return "\n".join(lines)

    def _p2_verify_direction(self, bus: Any = None) -> list[CommanderDirective] | None:
        """(WING-Corvus P2): P2→P3 前总指挥**确凿分析** verified 汇报.

        用户规范 2026-08-05: 进入 P3 的必要因素是某方向**足够的证据支撑 + 取得验证**
        + **汇报完整** + **总指挥分析确凿**. 此方法即"总指挥确凿分析"环节:
        1. 拉取全部 verified 汇报 (方向 + 完整验证证据)
        2. LLM 确凿分析: 证据支撑? 验证通过? 汇报完整? (反幻觉, 不脑补)
        3. confirmed → set_phase(P3) + 广播 P3 分工 (附确认主方向) → 返回 dirs
        4. 未确认 → 保持 P2, 返回 None (run_once 不切换, 继续正常分析)
        LLM 失败降级: verified 汇报本身已是战略层 FACT 级判断, 按确认处理 (不阻塞推进).
        """
        b = bus or self.bus
        reports_block = self._format_verified_reports(b)
        user_prompt = _P2_VERIFY_USER_TEMPLATE.format(
            title=self.title or self.challenge_id,
            challenge_type=self.challenge_type or "misc",
            challenge_difficulty=self.challenge_difficulty or "?",
            main_direction=self._main_direction or "(未确定)",
            reports=reports_block,
        )
        obj = self._llm_json(
            [_COMMANDER_SYSTEM_PROMPT, user_prompt], max_tokens=700, tag="p2_verify"
        )
        if obj is not None and not bool(obj.get("confirmed", False)):
            self._context.append(
                f"[P2 校验] 总指挥判定验证证据不足 "
                f"(reasoning: {str(obj.get('reasoning') or '')[:80]}), 保持 P2")
            self._trim_context()
            return None
        # 确认 (或 LLM 失败降级确认): 切换 P3 + 广播 P3 分工 (附已验证方向)
        direction_summary = ""
        if obj:
            direction_summary = str(obj.get("direction_summary") or "").strip()[:300]
        if not direction_summary and self._main_direction:
            direction_summary = self._main_direction
        self._context.append(f"[P2 校验] 方向确凿, 切换 P3: {direction_summary[:120]}")
        self._set_phase("P3")
        self._trim_context()
        dirs: list[CommanderDirective] = []
        p3_tasks = {
            "conservative": "P3 利用: 搜集细节且严谨利用 — 先验证关键地址/环境/依赖, 保证一次成功率高",
            "aggressive": "P3 利用: 快速深入利用漏洞 — 快速迭代逼近 flag, 卡住由战略层判断换子方向",
            "innovative": "P3 利用: 对该漏洞尝试创造性利用 — 新颖利用方式 (侧信道/竞态/替代路径), 应对脑洞题",
        }
        for style in self.styles:
            task = p3_tasks.get(style)
            if not task:
                continue
            d = self._make_directive(
                style,
                f"{task}\n[已验证方向] {direction_summary[:200]}",
                priority="SHOULD",
                reason="P2 方向验证确凿 (证据支撑+验证通过+总指挥确凿分析), 进入 P3",
            )
            if d:
                dirs.append(d)
        if dirs:
            self.post_directives(dirs, bus=b)
        return dirs

    def _format_verified_reports(self, bus: Any = None) -> str:
        """拉取全部 verified 汇报 (方向验证结果), 格式化供总指挥确凿分析."""
        b = bus or self.bus
        if b is None:
            return "(无 verified 汇报)"
        try:
            reports, _ = b.check_reports(self.bus_key, cursor=0)
        except Exception:
            return "(无 verified 汇报)"
        verified = [r for r in reports if str(r.get("report_type") or "") == "verified"]
        if not verified:
            return "(无 verified 汇报)"
        lines = []
        for r in verified[-5:]:  # 最近 5 条验证汇报
            lines.append(
                f"- {r.get('agent', '?')} (任务{r.get('task_no', '?')}, {r.get('level', '?')}): "
                f"{str(r.get('content') or '')[:300]}"
            )
        return "\n".join(lines)

    def _collect_phase_signal(self) -> tuple[int, int, set[str], bool, bool]:
        """汇总阶段切换信号: (FACT clue 数, LIKELY 汇报数, 失败风格集, flag 候选, 方向验证信号)."""
        fact_clues = 0
        likely_reports = 0
        fail_styles: set[str] = set()
        flag_candidate = False
        verified = False
        for style, entry in self._style_reports.items():
            if self._report_type_of(style) == "flag":
                flag_candidate = True
            # verified 汇报 (方向验证成功, 证据支撑+验证通过)
            if self._report_type_of(style) == "verified":
                verified = True
            if entry["fails"] >= 1:
                fail_styles.add(style)
        # 从上下文推断 (最近汇报) — 匹配 context 格式 "(任务N, FACT/LIKELY)"
        for line in self._context[-self.context_window:]:
            if "[汇报:clue]" in line and re.search(r"\(任务\d+,\s*FACT\)", line):
                fact_clues += 1
            if re.search(r"\(任务\d+,\s*LIKELY\)", line):
                likely_reports += 1
            if "flag{" in line or "候选flag" in line or "flag 候选" in line:
                flag_candidate = True
            if "[汇报:verified]" in line or "验证成功" in line or "已验证" in line:
                verified = True
        return fact_clues, likely_reports, fail_styles, flag_candidate, verified

    def _report_type_of(self, style: str) -> str:
        """从上下文摘要中识别某路最近汇报的 report_type (简版)."""
        for line in reversed(self._context[-self.context_window:]):
            if f"{style}" in line and "[汇报:" in line:
                m = re.search(r"\[汇报:(\w+)\]", line)
                if m:
                    return m.group(1)
        return "clue"

    def _set_phase(self, new_phase: str) -> bool:
        """切换阶段 (记录上下文), 返回是否发生切换."""
        if new_phase == self._phase:
            return False
        self._context.append(f"[阶段] {self._phase} → {new_phase} (耗时 {time.time() - self._phase_enter_ts:.0f}s)")
        self._phase = new_phase
        self._phase_enter_ts = time.time()
        self._trim_context()
        return True

    def _detect_convergence(self) -> list[CommanderDirective]:
        """方向趋同检测: ≥2 路最近主题重叠度 ≥ 阈值 → 差异化指令.

        规则级 (无需 LLM): 每路最近 3 条汇报主题做两两 Jaccard 重叠.
        命中 → SHOULD 指令让后发路转向; 累计 2 次趋同 → 升级 MUST.
        """
        styles = [s for s in self.styles if s in self._style_reports]
        if len(styles) < 2:
            return []
        pairs: list[tuple[str, str]] = []
        for i in range(len(styles)):
            for j in range(i + 1, len(styles)):
                pairs.append((styles[i], styles[j]))
        directives: list[CommanderDirective] = []
        seen: set[tuple[str, str]] = set()
        for sa, sb in pairs:
            if (sa, sb) in seen or (sb, sa) in seen:
                continue
            ta = set().union(*self._style_reports[sa].get("topics", [{}])) if self._style_reports[sa].get("topics") else set()
            tb = set().union(*self._style_reports[sb].get("topics", [{}])) if self._style_reports[sb].get("topics") else set()
            if not ta or not tb:
                continue
            inter = len(ta & tb)
            union = len(ta | tb)
            if union == 0:
                continue
            overlap = inter / union
            if overlap >= 0.4:
                seen.add((sa, sb))
                self._convergence_events.append(f"{sa}×{sb} overlap={overlap:.2f}")
                # 优先让 innovative 转向 (若参与); 否则让后汇报的路转向
                diverge_style = "innovative" if "innovative" in (sa, sb) else sb
                other_style = sa if diverge_style == sb else sb
                priority = "MUST" if len(self._convergence_events) >= 2 else "SHOULD"
                d = self._make_directive(
                    diverge_style,
                    f"检测到与 {other_style} 方向趋同 (主题重叠 {overlap:.0%}): "
                    f"立即转向未探索的方向 ({'发散探索备选攻击面' if diverge_style == 'innovative' else '换个角度深入'}), "
                    f"不要继续当前主题. 已确认死路除外.",
                    priority=priority,
                    reason=f"路径趋同检测: {sa}×{sb} 主题重叠 {overlap:.0%} (第 {len(self._convergence_events)} 次趋同)",
                )
                if d:
                    directives.append(d)
        return directives

    def _detect_stuck(self) -> list[CommanderDirective]:
        """卡住检测: 某路最近 3 条主题完全相同且连续失败 ≥3 次 → 换子方向.

        规则级 (无需 LLM):
        - aggressive: 卡住 → MUST 立即换子方向 (快速迭代不停止)
        - conservative: 卡住 → SHOULD 稳步换方向或复核
        - innovative: 卡住 → SHOULD 发散换方向
        """
        directives: list[CommanderDirective] = []
        for style, entry in self._style_reports.items():
            topics = entry.get("topics") or []
            fails = entry.get("fails") or 0
            if len(topics) < 2 or fails < 3:
                continue
            # 最近 ≥2 条主题完全相同 (set 归一化后)
            norm = [frozenset(t) for t in topics]
            if len(set(norm)) == 1:
                if style == "aggressive":
                    d = self._make_directive(
                        style,
                        f"检测到卡住: 最近 {len(topics)} 条汇报主题完全相同且连续失败 {fails} 次. "
                        f"不要停下来 — 立即切换到另一个子方向 (换偏移/换参数/换编码/换攻击方式) 继续推进.",
                        priority="MUST",
                        reason=f"卡住检测: {style} 连续 {fails} 次失败且主题未变",
                    )
                else:
                    d = self._make_directive(
                        style,
                        f"检测到卡住: 最近 {len(topics)} 条汇报主题相同且连续失败 {fails} 次. "
                        f"{'发散切换到备选方向' if style == 'innovative' else '复核当前方向, 若确认则稳步换方向推进'}.",
                        priority="SHOULD",
                        reason=f"卡住检测: {style} 连续 {fails} 次失败且主题未变",
                    )
                if d:
                    directives.append(d)
        return directives

    def _make_directive(self, style: str, direction: str, priority: str = "SHOULD",
                        reason: str = "") -> CommanderDirective | None:
        """构造 directive (并更新任务契约), 供规则检测直接产出."""
        if not style or style not in self.styles or not direction:
            return None
        cur = self._assignments.get(style)
        task_no = cur.task_no if cur else 0
        d = CommanderDirective(style=style, direction=direction,
                               task_no=task_no, priority=priority, reason=reason)
        if cur is not None:
            cur.task = direction
        self._directive_count += 1
        self._context.append(f"[指令:{priority}(规则)] {style}: {direction[:100]}")
        self._trim_context()
        return d

    def _phase_strategy_block(self) -> str:
        """当前阶段的分工策略文本 (注入 analyze prompt 供 LLM 参考)."""
        return {
            "P1": "P1 侦查 (任务驱动+进度汇报驱动, 非步数硬门槛): conservative 系统性扫描产出"
                  "结构化情报 / aggressive 直接尝试攻击可能方向记录响应报错 / innovative 非常规"
                  "信息挖掘. 三路各自独立侦查, **每 5 步向总指挥汇报进度** (当前发现/下一步计划/"
                  "是否卡死); 总指挥持续监控汇报流, 某路长时间无进展则介入调整. 侦查广度按难度定制"
                  "(简单题收敛、难题发散). 三路全部汇报侦查完成 (recon_done) 后, 总指挥才整合"
                  "全局情报摘要并确定主方向 → P2.",
            "P2": "P2 漏洞识别: conservative+aggressive 深入主方向 (保守稳步注意细节 / "
                  "激进快速忽略细节, 互补为解题核心; 总指挥只引导这两个, 具体小方向由战略层调控). "
                  "innovative 发散探索可能方向 (浅层搜集线索汇报, 总指挥判断可能性后可允许深入, "
                  "可能性大于主方向才可改主方向). 某方向证据支撑+验证通过 → P3.",
            "P3": "P3 利用: aggressive 快速深入利用 / conservative 搜集细节严谨利用 / "
                  "innovative 创造性利用. 协调以引导为主, 死循环/方向调整由战略层负责; "
                  "除非验证漏洞不存在返回 P2.",
            "P4": "P4 验证: 保守型验证候选 flag, 验证失败回退 P3",
        }.get(self._phase, "")

    def _make_phase_directives(self) -> list[CommanderDirective]:
        """阶段切换时按阶段为每路生成差异化任务指令 (SHOULD, 方向性指引).

        各阶段每路的任务侧重 (校准, 用户规范为准):
        - P1: conservative 系统性扫描 / aggressive 直接尝试攻击记录响应 / innovative 非常规挖掘
        - P2: conservative 稳步主方向细节 / aggressive 快速深入主方向 / innovative 发散探索可能方向
        - P3: conservative 严谨利用 / aggressive 快速利用 / innovative 创造性利用
        - P4: conservative 验证 flag
        """
        phase = self._phase
        tasks = {
            "P1": {
                "conservative": "P1 侦查: 系统性扫描 — 指纹/框架/源码结构/robots/备份文件, 产出结构化情报; 每 5 步汇报进度",
                "aggressive": "P1 侦查: 直接尝试攻击可能的方向 — 常见漏洞入口/边界输入快速试错, 核心是记录响应与报错; 每 5 步汇报进度",
                "innovative": "P1 侦查: 非常规信息挖掘 — exiftool/strings/binwalk/隐藏目录/注释/元数据, 寻找意外线索; 每 5 步汇报进度",
            },
            "P2": {
                "conservative": "P2 漏洞识别: 稳步推进主方向 — 每步充分验证 (确认保护/偏移/写稳健脚本), 捕捉激进遗漏的细节线索",
                "aggressive": "P2 漏洞识别: 快速深入主方向 — 构造最小验证 payload 快速验证漏洞存在性, 优先效率忽略部分细节",
                "innovative": "P2 漏洞识别: 发散探索可能方向 — 浅层搜集线索并向上汇报, 不深入任何单一方向; 经总指挥允许后才可深入",
            },
            "P3": {
                "conservative": "P3 利用: 搜集细节且严谨利用 — 先验证关键地址/环境/依赖, 保证一次成功率高",
                "aggressive": "P3 利用: 快速深入利用漏洞 — 快速迭代逼近 flag, 卡住由战略层判断换子方向",
                "innovative": "P3 利用: 对该漏洞尝试创造性利用 — 新颖利用方式 (侧信道/竞态/替代路径), 应对脑洞题",
            },
            "P4": {
                "conservative": "P4 验证: 最终验证候选 flag 合法性, 确认后交由系统提交",
            },
        }.get(phase, {})
        dirs: list[CommanderDirective] = []
        for style in self.styles:
            task = tasks.get(style)
            if not task:
                continue
            d = self._make_directive(style, task, priority="SHOULD",
                                     reason=f"阶段切换至 {phase}: 按阶段策略重新分配任务")
            if d:
                dirs.append(d)
        return dirs

    # ---------- 分析 + 下发 (一轮完整处理) ----------

    def run_once(self, bus: Any = None) -> list[CommanderDirective]:
        """消费新汇报 → 阶段状态机 → LLM 分析 (含规则信号参考) → 下发.

        返回本次下发的指令列表; silent 或汇报为空时返回 [].
        校准: 不再用死板代码直接产 MUST — 趋同/卡住规则检测降级为
        **LLM 分析的参考信号** (注入 analyze prompt), 由总指挥 LLM 基于完整上下文
        判断是否干预及优先级. 阶段切换仍为规则驱动 (进度/验证信号是客观事实).
        """
        reports = self.consume_reports(bus)
        if not reports:
            return []
        # 1. 阶段状态机: 规则判定切换 (基于客观汇报信号: 三路完成侦查 / 方向验证)
        new_phase = self._phase_advance_rule()
        if new_phase != self._phase:
            # (2026-08-05 校准): P1→P2 必须先整合全局情报摘要并确定
            # 主方向 (LLM 汇总三路侦查成果), 再随 P2 分工指令广播摘要 — 而非直接切换.
            if self._phase == "P1" and new_phase == "P2":
                summary_dirs = self._p1_synthesize(bus=bus)
                if summary_dirs:
                    return summary_dirs
            # (2026-08-05 校准): P2→P3 必须先由总指挥**确凿分析**
            # verified 汇报 (证据支撑+验证通过+汇报完整) — 确凿后才切换 P3;
            # 证据不足则保持 P2, 本轮正常分析其余汇报.
            elif self._phase == "P2" and new_phase == "P3":
                verify_dirs = self._p2_verify_direction(bus=bus)
                if verify_dirs:
                    return verify_dirs
                return self.analyze_reports(bus)
            # 阶段切换 → 广播阶段提示 (下发各路 SHOULD, 让战术层知晓当前阶段任务)
            self._set_phase(new_phase)
            # 阶段切换 → 广播阶段提示 (下发各路 SHOULD, 让战术层知晓当前阶段任务)
            strategy = self._phase_strategy_block()
            self._context.append(f"[阶段策略] {strategy}")
            self._trim_context()
            phase_dirs = self._make_phase_directives()
            if phase_dirs:
                self.post_directives(phase_dirs, bus=bus)
                return phase_dirs
        # 2. LLM 深度分析 (规则信号作为参考注入, 由 LLM 判断干预与否)
        return self.analyze_reports(bus)

    def _rule_signals_block(self) -> str:
        """规则检测信号摘要 (供 LLM 参考, 不直接产指令).

        趋同/卡住检测降级为 LLM 分析输入 — 是否干预、干预强度
        (MUST/SHOULD) 由总指挥 LLM 基于完整上下文判断, 避免死板代码误判.
        2026-08-05 校准: **P3 阶段不注入趋同/卡住信号** — 死循环与方向调整
        由战略层负责, 总指挥协调以引导为主 (仅保留进程级无汇报监控).
        """
        signals: list[str] = []
        # 长时间无汇报信号 (任务驱动 + 进度汇报驱动的监控侧 —
        # 某路超过阈值未向总指挥汇报 = 可能卡死/进程异常, 需 LLM 判断是否介入调整)
        now = time.time()
        for style, entry in self._style_reports.items():
            last = entry.get("last_ts") or 0.0
            if last and (now - last) > _STALE_REPORT_SECS and not entry.get("recon_done"):
                signals.append(
                    f"[无进展信号] {style}: 已 {int(now - last)}s 未向总指挥汇报 — "
                    f"请 LLM 判断该路是否卡死/进程异常, 若是则介入调整")
        # P3 阶段: 方向调整类信号 (卡住/趋同) 交由战略层负责, 不再注入总指挥
        if self._phase == "P3":
            return "\n".join(signals) if signals else "(无规则信号)"
        # 卡住信号 (某路主题相同 + 连续失败)
        for style, entry in self._style_reports.items():
            topics = entry.get("topics") or []
            fails = entry.get("fails") or 0
            if len(topics) >= 2 and fails >= 3:
                norm = [frozenset(t) for t in topics]
                if len(set(norm)) == 1:
                    signals.append(
                        f"[卡住信号] {style}: 最近 {len(topics)} 条汇报主题相同且连续失败 "
                        f"{fails} 次 — 请 LLM 判断是否真卡死, 若是则建议换子方向")
        # 趋同信号 (两两主题重叠 ≥40%)
        styles = [s for s in self.styles if s in self._style_reports]
        for i in range(len(styles)):
            for j in range(i + 1, len(styles)):
                sa, sb = styles[i], styles[j]
                ta = set().union(*self._style_reports[sa].get("topics", [{}])) if self._style_reports[sa].get("topics") else set()
                tb = set().union(*self._style_reports[sb].get("topics", [{}])) if self._style_reports[sb].get("topics") else set()
                if not ta or not tb:
                    continue
                overlap = len(ta & tb) / len(ta | tb) if (ta | tb) else 0
                if overlap >= 0.4:
                    signals.append(
                        f"[趋同信号] {sa}×{sb} 主题重叠 {overlap:.0%} — 请 LLM 判断是否"
                        f"路径趋同, 若是则建议其中一路发散到未探索方向")
        return "\n".join(signals) if signals else "(无规则信号)"

    def _main_direction_block(self) -> str:
        """主方向与备选方向状态块 (注入 analyze prompt 供 LLM 对照)."""
        if not self._main_direction and not self._alt_directions:
            return "(尚未确定 — P1 三路侦查汇报完成后由你整合生成)"
        lines = [f"- 主方向: {self._main_direction or '(未确定)'}"]
        if self._alt_directions:
            lines.append(f"- 备选方向: {'; '.join(self._alt_directions)}")
        lines.append("- 主方向修改仅两种途径: ①保守/激进明确证伪主方向; "
                     "②创新发散方向经你允许深入并证实正确")
        return "\n".join(lines)

    def _update_directions_from_llm(self, obj: dict) -> None:
        """解析 LLM 输出的主方向/备选方向, 更新状态.

        主方向修改仅两种途径 (LLM 侧判断):
        1. 保守/激进在探索中明确发现主方向错误 (证据证伪) → 更新主方向
        2. 创新发散方向经允许深入并证实正确 → 更新主方向
        若只是"有可能方向" → 加入备选列表 (主方向被证伪后才启用).
        """
        # (2026-08-05 校准): P1 侦查阶段**不确认主方向** —
        # 主方向须等三路侦查全部完成后由全局情报摘要整合确定 (_p1_synthesize).
        # P1 期间 LLM 输出的 main_direction 一律忽略 (避免过早锁定方向).
        if self._phase == "P1":
            obj = dict(obj)
            obj.pop("main_direction", None)
        try:
            md = str(obj.get("main_direction") or "").strip()
            if md and md != self._main_direction:
                if self._main_direction:
                    self._context.append(
                        f"[主方向更新] {self._main_direction[:60]} → {md[:60]} "
                        f"(reasoning: {str(obj.get('reasoning') or '')[:80]})")
                self._main_direction = md[:200]
            alt = obj.get("alt_directions") or []
            if isinstance(alt, list):
                cleaned = [str(a).strip()[:200] for a in alt if str(a).strip()]
                if cleaned:
                    self._alt_directions = cleaned
                    self._context.append(
                        f"[备选方向] " + "; ".join(d[:40] for d in cleaned))
        except Exception:  # noqa: BLE001 - 方向解析失败不阻断
            pass
        self._trim_context()

    def analyze_reports(self, bus: Any = None) -> list[CommanderDirective]:
        """基于已消费的汇报做 LLM 分析, 产出并下发 directive (静默则不下发).

        WING-Corvus 2.0: 注入当前阶段与阶段策略 (LLM 依据阶段生成差异化指令).
        注入规则信号 (趋同/卡住) 与主方向/备选方向, 供 LLM 确凿判断.
        """
        b = bus or self.bus
        assignments_block = "\n".join(
            f"- {a.style} → 任务{a.task_no}: {a.task}" for a in self._assignments.values()
        ) or "(尚未分配)"
        context_block = "\n".join(self._context[-self.context_window:]) or "(空)"
        reports_block = self._format_reports(b)
        phase_block = (f"当前阶段: {self._phase}\n阶段策略: {self._phase_strategy_block()}")
        main_direction_block = self._main_direction_block()

        user_prompt = _ANALYZE_REPORTS_USER_TEMPLATE.format(
            title=self.title or self.challenge_id,
            challenge_type=self.challenge_type or "misc",
            challenge_difficulty=self.challenge_difficulty or "?",
            assignments_block=assignments_block,
            context_block=context_block,
            reports_block=reports_block,
            phase_block=phase_block,
            main_direction_block=main_direction_block,
        )
        # 规则信号 (趋同/卡住) 作为 LLM 参考注入, 由 LLM 判断干预与否
        rule_signals = self._rule_signals_block()
        if rule_signals and rule_signals != "(无规则信号)":
            user_prompt += f"\n\n## 规则检测参考信号 (非强制, 请 LLM 判断)\n{rule_signals}"
        obj = self._llm_json(
            [_COMMANDER_SYSTEM_PROMPT, user_prompt], max_tokens=800, tag="analyze"
        )
        self._last_analyze_ts = time.time()

        directives: list[CommanderDirective] = []
        if not obj:
            return directives

        # 更新主方向/备选方向 (主方向修改仅两种途径的 LLM 侧判断)
        self._update_directions_from_llm(obj)

        silent = bool(obj.get("silent", False))
        if silent:
            self._context.append(f"[分析] 静默 (方向正确, 无重大收获), 不下发指令")
            self._trim_context()
            return directives

        raw = obj.get("directives") or []

        # P3 阶段协调以引导为主 — 除非返回 P2 (漏洞验证失败),
        # 否则将转向类指令降级为 SHOULD (死循环/方向调整由战略层负责).
        # 修复 (2026-08-05): 此前在 raw 赋值前引用, NameError 导致 P3 阶段
        # analyze_reports 异常 → 总指挥在 P3 静默失效.
        if self._phase == "P3":
            for d in raw if isinstance(raw, list) else []:
                prio = str(d.get("priority") or "SHOULD").upper()
                if prio == "MUST" and "返回P2" not in str(d.get("direction") or ""):
                    d["priority"] = "SHOULD"

        for d in raw if isinstance(raw, list) else []:
            style = str(d.get("style") or "").strip().lower()
            direction = str(d.get("direction") or "").strip()
            if not style or style not in self.styles or not direction:
                continue
            priority = str(d.get("priority") or "SHOULD").upper()
            if priority not in ("MUST", "SHOULD"):
                priority = "SHOULD"
            # 反幻觉: MUST 必须有 FACT/LIKELY 支撑 (由 reports_block 内的分级决定,
            # 此处仅做最低约束: MUST 方向不能为空, 依据不能为空)
            reason = str(d.get("reason") or "")[:300]
            # WING-Corvus 升级 (2026-08-05, 历史复盘): MUST 依据门槛 —
            # 总指挥基于汇报摘要决策, 若无明确理由 (空 reason / 未引用任何汇报),
            # 该指令本质是猜测, 不得以 MUST 强制 (会让 agent 被迫执行错误方向,
            # 案例: 总指挥 MUST "直接请求 /utils.php" 但该路径已被证实空/404).
            if priority == "MUST" and not reason.strip():
                priority = "SHOULD"
            cur = self._assignments.get(style)
            task_no = int(d.get("task_no") or (cur.task_no if cur else 0))
            directive = CommanderDirective(
                style=style,
                direction=direction,
                task_no=task_no,
                priority=priority,
                reason=reason,
            )
            # 更新任务契约 (重定向 = 更新该路任务方向)
            if cur is not None:
                cur.task = direction
                cur.task_no = task_no
            directives.append(directive)
            self._directive_count += 1
            self._context.append(
                f"[指令:{priority}] {style}: {direction[:100]} (依据: {reason[:60]})"
            )
        if b is not None:
            self.post_directives(directives, bus=b)
        self._trim_context()
        return directives

    def post_directives(self, directives: list[CommanderDirective], bus: Any = None) -> list[int]:
        """将指令写入总线 (目标风格战略层消费). 返回各消息 seq."""
        b = bus or self.bus
        if b is None:
            return []
        seqs: list[int] = []
        for d in directives:
            try:
                seqs.append(b.post_directive(
                    agent_id=d.style,
                    task_id=self.bus_key,
                    content=d.direction,
                    task_no=d.task_no,
                    priority=d.priority,
                    reason=d.reason,
                    phase=self._phase,  # 附带当前阶段, 供战略层感知注入任务
                ))
            except Exception:
                continue
        return seqs

    # ---------- 内部 ----------

    def _format_reports(self, bus: Any = None) -> str:
        """从总线重新拉取全部 report (本次上下文), 格式化供 LLM 判断证据分级."""
        b = bus or self.bus
        if b is None:
            return "(无汇报)"
        try:
            reports, _ = b.check_reports(self.bus_key, cursor=0)
        except Exception:
            return "(无汇报)"
        if not reports:
            return "(无汇报)"
        lines = []
        for r in reports[-10:]:  # 最近 10 条
            lines.append(
                f"- [{r.get('report_type', 'clue')}] {r.get('agent', '?')} "
                f"(任务{r.get('task_no', '?')}, {r.get('level', '?')}): "
                f"{str(r.get('content') or '')[:200]}"
            )
        return "\n".join(lines)

    def _llm_json(self, messages: list[str], max_tokens: int, tag: str) -> dict | None:
        """调用 LLM 并解析 JSON (带 1 次重试; 失败返回 None 由调用方静默处理)."""

        def _call(msgs: list[dict]) -> dict | None:
            r = self.llm.chat(msgs, temperature=0.0, max_tokens=max_tokens)
            return _extract_json(r.content)

        msgs = [
            {"role": "system", "content": messages[0]},
            {"role": "user", "content": messages[1]},
        ]
        try:
            obj = _call(msgs)
            if obj is not None:
                return obj
        except Exception as e:  # noqa: BLE001
            self._context.append(f"[LLM-{tag} 异常] {type(e).__name__}: {str(e)[:80]}")
        # 1 次重试 (提示严格输出 JSON)
        try:
            retry_msgs = [
                {"role": "system", "content": messages[0]},
                {"role": "user", "content": messages[1]},
                {"role": "user",
                 "content": "请严格只输出合法 JSON 对象 (不要 markdown 代码块、前后缀文本、思考过程)。"},
            ]
            return _call(retry_msgs)
        except Exception as e:  # noqa: BLE001
            self._context.append(f"[LLM-{tag} 重试异常] {type(e).__name__}: {str(e)[:80]}")
            return None

    def _trim_context(self) -> None:
        """裁剪历史上下文 (只保留最近 context_window 条摘要)."""
        if len(self._context) > self.context_window:
            self._context = self._context[-self.context_window:]

    # ---------- 只读状态 ----------

    @property
    def assignments(self) -> dict[str, TaskAssignment]:
        return dict(self._assignments)

    @property
    def directive_count(self) -> int:
        return self._directive_count

    def summary(self) -> str:
        """当前状态摘要 (供日志/调试)."""
        parts = [f"styles={self.styles}"]
        if self._assignments:
            parts.append("分工: " + "; ".join(
                f"{a.style}→任务{a.task_no}: {a.task[:40]}" for a in self._assignments.values()))
        parts.append(f"directives={self._directive_count} context={len(self._context)}")
        return " | ".join(parts)


__all__ = ["Commander", "CommanderDirective", "TaskAssignment",
           "DEFAULT_STYLES", "_extract_json"]
