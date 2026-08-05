"""巡查指导器 (Coordinator LLM) — 智能旁观者.

核心设计思想: 旁观者清，当局者迷.
解题 Agent 在解题时由于专注于当下可能陷入困境或方向走错,
巡查指导器作为第三者宏观审视完整行为轨迹, 全局视角更容易发现问题,
并提供精准的战术指导和方向调整. 在无人监管独立运行时, 代替人提供战术指导.

设计原则:
1. 沉默原则: 方向正确且进展正常时保持沉默, 不打扰 Agent
2. 精准指导: 发现问题时给出具体的战术建议 (不是模板化提示)
3. 知识增强: 查询 RAG/Skill 库辅助判断, 提供更专业的指导
4. 两级分析: 先规则预检 (快速), 再 LLM 深度分析 (精准)

触发规则:
- 首次巡查: 第 10 步 (早期方向检查, 避免开局走错)
- 后续巡查: 每 15 步 (25, 40, 55, 70...)
- 异常触发: 连续 3 个错误步时立即触发 (不等间隔)
- 步数接近上限: 倒数 20 步时触发 (检查是否需要扩展)

分析内容:
1. 方向检查: 当前操作是否与题型匹配? 是否在解决正确的问题?
2. 死循环判断: 是否在重复相同的操作?
3. 进展停滞: 是否长时间没有新发现?
4. 知识库匹配: RAG/Skill 中是否有更优解法?
5. 战术建议: 发现问题时给出精准的纠正建议
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CoordinatorGuidance:
    """巡查指导器的输出."""

    should_intervene: bool = False          # 是否需要干预
    guidance: str = ""                      # 给 agent 的战术指导
    reason: str = ""                        # 干预原因 (或"方向正确"说明)
    extend_steps: bool = False              # 是否建议扩展步数
    detected_issues: list[str] = field(default_factory=list)
    analysis_summary: str = ""              # LLM 分析摘要 (用于日志)
    priority: str = "SHOULD"                # "MUST" = 必须执行, "SHOULD" = 建议执行
    forbidden_actions: list[str] = field(default_factory=list)  # 禁忌列表 (已确认无效的操作)
    # 巡查器自我纠错 — 用后续轨迹验证自己之前的判断
    revert_guidance: bool = False           # 撤销上次指导 (上次判断被后续轨迹证伪)
    remove_forbidden: list[str] = field(default_factory=list)  # 从禁忌列表移除误判项 (agent 用该操作取得了突破)
    # 推论分级框架 — 透传给调用器用于完整日志显示
    reflection: str = ""                    # 巡查器反思过程 (必填, 供日志/调试)
    belief_state: list[dict] = field(default_factory=list)  # 推论清单 [{id, statement, level, evidence, action}]


# ── LLM 分析 prompt 模板 ──────────────────────────────────────

_COORDINATOR_SYSTEM_PROMPT = """你是 CTF 解题巡查指导器 (Coordinator), 一个"旁观者"角色.

你的任务是: 宏观审视解题 Agent 的完整行为轨迹, 判断它是否走在正确的方向上,
并在发现问题时提供精准的战术指导.

## 核心原则

1. **旁观者清**: 你不参与具体解题, 只做宏观判断. 你能看到 Agent 看不到的全局问题.
2. **沉默是金**: 如果 Agent 方向正确且进展正常, 保持沉默 (should_intervene=false).
   不必要的干预会打乱 Agent 的节奏.
3. **精准指导**: 发现问题时, 给出具体的、可操作的战术建议.
   不要说"请换方向"这种空泛的话, 要说"当前在用费马分解, 但 n 的两个素数差异大,
   费马法无效, 应该用 factordb 或 sympy.factorint".
4. **基于证据**: 判断必须基于轨迹中的实际行为, 不要猜测 Agent 的意图.

## 推论分级框架 (— 核心改造)

你对轨迹的每次分析都必须基于**推论分级**. 所有判断分为四个等级:

1. **事实 (FACT)**: 轨迹中直接观察到的确定信息.
   - 例: "step 24 POST /index/test 返回 HTTP 200"
   - 例: "源码 app/controller/Index.php 第 12 行包含 unserialize($_POST['a'])"
   - 例: "step 34 本地 PHP 执行 payload 成功写入 info.php"
   ⚠️ 事实不需要推测, 是轨迹中明确记录的.

2. **高可能性推论 (LIKELY)**: 基于事实的合理推断, 有充分证据支持.
   - 例: "入口存在且可用 (基于 FACT: step 24 返回 200 + FACT: 源码确认 unserialize)"
   - 例: "payload 格式有误 (基于 FACT: 本地成功但远程 500 + FACT: 类名长度曾算错)"
   ⚠️ LIKELY 可以作为决策依据, 但需标注支撑事实.

3. **低可能性推论 (POSSIBLE)**: 缺乏充分证据的推测, 需要更多验证.
   - 例: "远程版本可能与附件不同 (仅基于 500 错误推测, 无直接证据)"
   - 例: "多语言中间件可能未启用 (基于 lang 参数无异常, 但未确认配置)"
   ⚠️ POSSIBLE 不能单独作为 MUST 干预依据, 只能作为 SHOULD 建议.

4. **已证否推论 (DISPROVED)**: 被后续轨迹明确否定的判断.
   - 例: "入口不存在 (DISPROVED: 源码 FACT 确认 unserialize 存在 + step 24 返回 200)"
   - 例: "BAT2EXE 假设 (DISPROVED: agent 成功提取 t.bat 但内容是 ThinkPHP 源码)"
   ⚠️ DISPROVED 推论必须立即从禁忌列表移除, 不得继续影响决策.

### 每次巡查的推论更新流程

1. **回顾**: 审视上次的推论清单 (在用户消息中提供)
2. **更新**: 用最新轨迹中的事实, 对每个推论进行升级(LIKELY→FACT)、降级(LIKELY→POSSIBLE)、证否(→DISPROVED)
3. **新增**: 基于新观察到的事实, 添加新推论
4. **反思**: 在做决策前, 先反思:
   - 我的推论中哪些是 FACT (有轨迹直接支撑)? 哪些是推断?
   - 我是否把 POSSIBLE 当成了 FACT 来做决策?
   - 我上次的禁忌/指导是否基于已被证否的推论?
   - Agent 是否用自己的方式取得了进展, 证明我之前的判断有误?
5. **决策**: 基于更新后的推论分级做决策. 只有 FACT + LIKELY 可以作为 MUST 依据.

## 分析维度

1. **方向检查**: Agent 的操作是否与题目类型匹配? 是否在解决正确的问题?
   - crypto 题不应该在做 web 目录扫描
   - reverse 题不应该在做 SQL 注入
   - 但注意: 有些题目需要跨题型操作 (如 crypto_reverse), 不要过度限制

2. **死循环判断**: Agent 是否在重复相同的操作?
   - 同一工具 + 相似参数出现 3 次以上 = 死循环
   - 不同参数但相同思路反复尝试 = 也可能是死循环
   - ⚠️ 但如果每次都有新 observation (新发现), 可能是系统性验证, 不是死循环

3. **进展停滞**: Agent 是否长时间没有新发现?
   - 连续错误步 ≥ 3 = 可能停滞
   - 连续 N 步都在做信息收集但没有进入攻击阶段 = 可能迷失

4. **知识库参考**: 根据提供的 RAG/Skill 检索结果, 当前是否有更优解法?
   - 如果知识库中有匹配的 Skill, Agent 是否在用?
   - 如果 Agent 的方向与知识库建议完全不同, 是否 Agent 发现了新路径还是走错了?

5. **自我纠错 (+ 32.6 强化)**: 你之前的判断不一定是正确的, 你要用后续轨迹验证它.
   - 如果上次指导后 Agent 未按指导执行, 但用自己的方式持续取得进展 (轨迹显示新的发现/线索/突破),
     说明上次指导可能不准确 → 撤销上次指导 (revert_guidance=true).
     此时若 Agent 当前方向正确, 应保持沉默 (should_intervene=false), 让 Agent 按自己的有效路径推进.
   - 如果禁忌列表中的某个操作后来被 Agent 成功使用并取得突破, 说明该禁忌是误判 →
     用 remove_forbidden 列出应移除的禁忌项.
   - **关键**: 禁忌列表的依据如果只是 POSSIBLE 推论 (非 FACT), 不应加入禁忌.
     已在禁忌列表中的, 如果依据被证否, 必须立即移除.
   - 承认错误不是问题, 坚持错误才是. 你是"旁观者", 判断依据是轨迹证据, 证据变了就要改.
   - 只有当 Agent 既未执行指导、又无任何进展且明显在无效循环时, 才判定 MUST 未执行并强制干预.

## 输出格式 (严格 JSON)

⚠️ 在输出 JSON 前, 你必须先在 `reflection` 字段中写出你的反思过程.

你必须输出以下 JSON 格式 (不要输出其他内容):

{
  "reflection": "反思: 1) 我的推论中 FACT 有哪些? 2) 是否把 POSSIBLE 当 FACT 用了? 3) 上次禁忌/指导是否被证否? (必填, 不少于 30 字)",
  "belief_state": [
    {"id": "B1", "statement": "推论描述", "level": "FACT/LIKELY/POSSIBLE/DISPROVED", "evidence": "支撑事实(轨迹步骤)", "action": "keep/upgrade/downgrade/disprove/new"},
  ],
  "should_intervene": true/false,
  "priority": "MUST"/"SHOULD",
  "guidance": "具体的战术指导 (仅 should_intervene=true 时填写, 否则留空)",
  "reason": "干预原因 或 '方向正确, 继续推进' (必须引用推论 ID 作为依据, 如 '基于 B1(FACT)+B2(LIKELY)')",
  "extend_steps": true/false,
  "forbidden_actions": ["已确认无效的操作描述 (仅基于 FACT/DISPROVED 推论, 不得基于 POSSIBLE)", ...],
  "revert_guidance": true/false,
  "remove_forbidden": ["应移除的误判禁忌项 (基于 DISPROVED 推论)", ...],
  "analysis_summary": "一句话分析摘要"
}

## revert_guidance / remove_forbidden 说明 (自我纠错)
- revert_guidance=true: 你之前的下达的指导被后续轨迹证伪 (Agent 用自己的方式取得了进展).
  此时应撤销该指导, 不再强制 Agent 执行. 如果 Agent 当前方向正确, 同时保持 should_intervene=false.
- remove_forbidden: 禁忌列表中已被 Agent 成功使用的操作 (误判), 应移除.

## priority 说明
- "MUST": Agent 必须立即执行指导, 不得自主判断优先级. 用于明显方向错误/死循环/禁忌操作.
  强化: MUST 指导必须给出**强制工具链切换** — 明确"停止 X, 改用 Y 工具/方法",
  不要只说"换个思路". 例: "停止单字符 MD5 爆破, 用 gdb 在 call 0x404140 处断点读取 MD5 输入".
- "SHOULD": 建议执行, Agent 可结合实际情况判断. 用于软线索/改进建议.

## 假设证伪 (新增维度)

当 Agent 长期围绕同一假设反复操作 (如"逐字符 MD5 爆破") 但轨迹结果不支持时:
1. **必须识别该假设已被结果否定**: 检查目标表/观测值是否与假设预期匹配
2. **直接下达 [MUST] 指令要求放弃假设**: guidance 中明确写"假设 A 已证伪 (原因: 目标表与 md5(单字符) 不匹配), 立即停止, 改查输入变换"
3. 同一假设被否定 ≥2 次后, 把该操作加入 forbidden_actions

## guidance 写作要求

如果 should_intervene=true, guidance 必须包含三部分:
1. **做什么**: 具体的下一步操作 (如"用 ffmpeg 解码 MPEG 视频为帧序列")
2. **怎么做**: 具体的命令或方法 (如"ffmpeg -y -i cloud_key.mpeg -vsync 0 frames/%03d.png")
3. **为什么**: 解释为什么当前方向错了 (如"你一直在爆破 zip 密码, 但题目提示 MPEG, 关键线索在视频画面中")

示例 (好):
"停止爆破 cloud.zip 密码 (已连续 3 次失败, hashcat 无法破解).
用 ffmpeg 解码 cloud_key.mpeg 为帧序列: ffmpeg -y -i cloud_key.mpeg -vsync 0 frames/%03d.png.
题目提示 'Was MPEG ever good?' 指向视频画面内容, 密码线索在视频中."

示例 (差, 不要这样):
"请换一个方向, 尝试分析 MPEG 文件."

guidance 不要超过 400 字, 要精准、可操作.

## forbidden_actions 说明
当某类操作已确认无效时 (如"hashcat 爆破 cloud.zip 密码"连续失败), 加入 forbidden_actions.
Agent 下次尝试同类操作时会被拦截并重定向.
"""

_COORDINATOR_USER_TEMPLATE = """## 题目信息
题目描述: {task_desc}
题型: {challenge_type}
难度: {challenge_difficulty}
当前步数: {step_no} / {max_steps}

## 上次推论清单 (用于推论更新 — 回顾→更新→反思→决策)
{belief_state_block}

## L1 规则预检线索 (供参考, 需你判断是否真的有问题)
{l1_hints}

## 当前禁忌列表 (已确认无效的操作, Agent 不应再尝试)
{forbidden_actions}

## 上次巡查指导及执行情况 (用于自我纠错)
{last_guidance_block}

## 知识库检索结果
{knowledge_context}

## Agent 行为轨迹 (完整)
{trajectory_summary}

## 请分析

⚠️ 强制流程: 你必须按以下顺序分析, 不得跳过任何步骤:

### 步骤 1: 推论回顾
审视"上次推论清单", 逐条检查每个推论在最新轨迹中是否被证实/证否/需要调整.

### 步骤 2: 推论更新
- 用最新轨迹中的事实, 对每个推论进行升级/降级/证否
- 基于新观察到的事实, 添加新推论
- 将更新后的推论清单写入 belief_state

### 步骤 3: 反思 (必填!)
在 reflection 字段中回答:
1. 我的推论中哪些是 FACT (有轨迹直接支撑)? 哪些只是推断?
2. 我是否把 POSSIBLE 当成了 FACT 来做决策?
3. 我上次的禁忌/指导是否基于已被证否的推论? 如果是, 必须撤销.

### 步骤 4: 决策
基于更新后的推论分级做决策:
- 只有 FACT + LIKELY 推论可以作为 MUST 干预依据
- POSSIBLE 推论只能作为 SHOULD 建议
- 禁忌列表只能基于 FACT (已确认无效) 或 DISPROVED (被证否后不得再禁忌)
- 如果 Agent 在用自己的方式取得进展, 且方向正确, 保持沉默

注意:
1. L1 线索只是启发式提示, 不一定是问题. 你需要结合轨迹的具体内容判断.
2. guidance 必须包含"做什么+怎么做+为什么"三部分.
3. reason 字段必须引用推论 ID 作为依据 (如 "基于 B1(FACT): 入口确认 + B2(LIKELY): payload格式有误").
"""


class Coordinator:
    """巡查指导器: LLM 驱动的智能旁观者.

    两级分析 (优化触发逻辑):
    1. L1-A 规则预检 (快速, 不调 LLM): 只处理确定性问题
       - 完全重复死循环 (同一工具+相似参数 ≥3 次) → 直接生成指导
       - 明显方向错误 (题型完全不匹配) → 直接生成指导
    2. L1-B 软线索 (快速, 不调 LLM): 作为 L2 的参考信息
       - 工具过度使用 (同一工具 ≥5 次但参数不同) → 传给 L2
       - 连续错误步 (≥3 个) → 传给 L2
       - 指导持久性 (上次指导后未改变行为) → 传给 L2
    3. L2 LLM 深度分析 (精准): 始终触发 (如果有 LLM)
       - 宏观审视完整轨迹 + L1 线索 + 知识库辅助
       - 能区分"工具过度使用但方向正确"和"真正的思路固化"
       - 方向正确时保持沉默 (should_intervene=false)

    降级模式 (无 LLM): L1-B 软线索也作为干预依据.
    """

    def __init__(
        self,
        llm: Any = None,                    # LLM 客户端 (用于深度分析)
        skill_library: Any = None,          # Skill 库 (用于查询匹配 Skill)
        long_term: Any = None,              # RAG 库 (用于查询相似 writeup)
        check_interval: int = 10,           # 后续巡查间隔 (步) — 15→10, 更频繁纠偏, 减少总轮数
        first_check: int = 10,              # 首次巡查步数
        lookback: int = 10,                 # 规则预检回看步数
        max_repeats: int = 3,               # 同一操作重复 N 次判定为死循环
        max_errors: int = 3,                # 连续 N 个错误步判定为停滞
        early_exit_steps: int = 20,         # 步数接近上限时触发 (倒数 N 步)
    ) -> None:
        self.llm = llm
        self.skill_library = skill_library
        self.long_term = long_term
        self.check_interval = check_interval
        self.first_check = first_check
        self.lookback = lookback
        self.max_repeats = max_repeats
        self.max_errors = max_errors
        self.early_exit_steps = early_exit_steps
        # 异常触发: 连续错误步计数
        self._consecutive_errors = 0
        self._last_check_step = 0
        # 指导持久性 — 记录上次指导, 若 agent 未改变行为则强化提醒
        self._last_guidance: str = ""
        self._last_guidance_step: int = 0
        self._last_guidance_action: str = ""  # 上次指导时 agent 的主导工具
        self._last_guidance_priority: str = ""  # 上次指导的优先级 (MUST/SHOULD)
        # 禁忌列表 — 已确认无效的操作, agent 再尝试时拦截
        self._forbidden_actions: list[str] = []
        # 动态干预频率 — 出现错误后缩短间隔
        self._error_since_last_check: int = 0
        # 推论状态 — 跨巡查持久化, 每次更新后存回
        # 格式: [{"id": "B1", "statement": "...", "level": "FACT/LIKELY/POSSIBLE/DISPROVED", "evidence": "..."}]
        self._belief_state: list[dict] = []

    def should_check(self, step_no: int, max_steps: int = 0) -> bool:
        """是否到了巡查点.

        动态干预频率:
        1. 首次巡查: 第 first_check 步 (默认 10)
        2. 正常后续: 每 check_interval 步 (默认 15)
        3. 出现错误后: 间隔缩短至 5 步 (快速纠偏)
        4. 接近步数上限: 倒数 10 步内每 3 步 (强制收敛)
        5. 异常触发: 连续 max_errors 个错误步 (立即触发)
        6. 禁忌操作触发: agent 在尝试禁忌列表中的操作 (立即触发)
        """
        if step_no <= 0:
            return False

        # 异常触发: 连续错误步
        if self._consecutive_errors >= self.max_errors:
            return True

        # 首次巡查
        if step_no == self.first_check and self._last_check_step < self.first_check:
            return True

        # 后续巡查: 根据状态动态调整间隔
        if step_no > self.first_check and self._last_check_step > 0:
            steps_since_last = step_no - self._last_check_step

            # 接近步数上限: 倒数 10 步内每 3 步
            if max_steps > 0 and step_no >= max_steps - 10:
                if steps_since_last >= 3:
                    return True

            # 出现错误后: 每 5 步
            elif self._error_since_last_check > 0:
                if steps_since_last >= 5:
                    return True

            # 正常: 每 check_interval 步
            elif steps_since_last >= self.check_interval:
                return True

        # 步数接近上限 (兜底)
        if max_steps > 0 and step_no >= max_steps - self.early_exit_steps:
            if self._last_check_step < max_steps - self.early_exit_steps:
                return True

        return False

    def intercept_forbidden(self, action: str, action_input: str) -> str:
        """工具执行前拦截禁忌操作 (供 ReAct 引擎调用).

        禁忌列表中的操作 (如"hashcat 爆破 cloud.zip 密码"已被确认无效) 在
        巡查间隔之外也会被拦截, 立即重定向 Agent, 避免继续浪费步数.
        返回拦截提示 (非空 = 应拦截该操作), 空串 = 放行.
        """
        if not self._forbidden_actions:
            return ""
        combined = f"{action} {action_input}".lower()
        for forbidden in self._forbidden_actions:
            keywords = [w for w in forbidden.lower().split() if len(w) > 3]
            if keywords and any(kw in combined for kw in keywords):
                return (
                    f"⚠️ 拦截: 该操作 '{action}' 已被巡查判定为无效 (禁忌列表: "
                    f"{forbidden[:80]}). 立即停止, 换一个完全不同的方法. "
                    f"请重新输出 Thought + Action + Action Input."
                )
        return ""

    def analyze(
        self,
        trajectory: list[dict],
        challenge_type: str = "",
        challenge_difficulty: str = "",
        task_desc: str = "",
        step_no: int = 0,
        max_steps: int = 0,
    ) -> CoordinatorGuidance:
        """分析轨迹, 返回指导.

        两级分析 (优化触发逻辑):
        1. L1 规则预检 (快速, 不调 LLM):
           - 完全重复死循环 (同一工具+相似参数 ≥3 次) → 直接生成指导
           - 明显方向错误 (题型完全不匹配) → 直接生成指导
           - 思路固化/连续错误步 → 作为"线索"传给 L2, 不直接干预
        2. LLM 深度分析 (精准): 始终触发 (如果有 LLM), 传入 L1 线索 + 知识库辅助

        这样 L2 LLM 能基于完整轨迹 + L1 线索 + 知识库做精准判断, 避免误判.
        """
        if len(trajectory) < 3:
            return CoordinatorGuidance()

        self._last_check_step = step_no

        # 更新连续错误步计数
        if trajectory and trajectory[-1].get("is_error"):
            self._consecutive_errors += 1
            self._error_since_last_check += 1
        else:
            self._consecutive_errors = 0

        recent = trajectory[-self.lookback:] if len(trajectory) >= self.lookback else trajectory

        # ── L1-A: 确定性问题 (直接干预, 不调 LLM) ──
        hard_issues: list[str] = []
        # soft_hints 提前定义 — exact_repeat 有进展时降级到此
        soft_hints: list[str] = []

        # 完全重复死循环 (同一工具+相似参数 ≥3 次)
        # 完全重复但持续有新 observation → 降级为软线索 (交 L2 LLM 判断),
        # 避免对"同脚本模板反复验证不同目标"的系统性逆向误判 (历史复盘: agent 反复
        # 用同一 capstone 模板验证不同函数/假设, 实际是严谨的验证性推进)
        exact_repeat = self._check_exact_repeats(recent)
        if exact_repeat:
            if self._has_progress(recent):
                soft_hints.append(exact_repeat + " (但持续有新发现, 需 LLM 判断是否思路固化)")
            else:
                hard_issues.append(exact_repeat)

        # 明显方向错误 (题型完全不匹配)
        direction_issue = self._check_direction(recent, challenge_type)
        if direction_issue:
            hard_issues.append(direction_issue)

        # 禁忌操作检测 (agent 在尝试已确认无效的操作)
        forbidden_hit = self._check_forbidden_actions(recent)
        if forbidden_hit:
            hard_issues.append(forbidden_hit)

        # MUST 指令未被执行 — 上次 MUST 指导后 agent 行为未改变
        # (分析 协调器 step10 下达 MUST 但 agent 忽略, 继续 MD5 爆破 20 步)
        must_ignored = self._check_must_noncompliance(recent)
        if must_ignored:
            hard_issues.append(must_ignored)

        if hard_issues:
            guidance = self._build_rule_guidance(hard_issues, challenge_type)
            self._last_guidance = guidance
            self._last_guidance_step = step_no
            self._last_guidance_action = self._dominant_action(recent)
            self._last_guidance_priority = "MUST"  # 记录优先级
            self._error_since_last_check = 0  # 巡查后重置
            return CoordinatorGuidance(
                should_intervene=True,
                priority="MUST",  # 确定性问题必须执行
                guidance=guidance,
                reason="; ".join(hard_issues),
                extend_steps=False,
                detected_issues=hard_issues,
                analysis_summary=f"L1 规则预检发现确定性问题: {'; '.join(hard_issues)}",
                forbidden_actions=list(self._forbidden_actions),
            )

        # ── L1-B: 软线索 (传给 L2, 不直接干预) ──
        tool_overuse = self._check_tool_overuse(recent)
        if tool_overuse:
            soft_hints.append(tool_overuse)

        error_streak = self._check_errors(recent)
        if error_streak:
            soft_hints.append(error_streak)

        # 指导持久性检查: 上次指导后 agent 是否改变了行为?
        persistence_hint = self._check_guidance_persistence(recent)
        if persistence_hint:
            soft_hints.append(persistence_hint)

        # ── L2: LLM 深度分析 (始终触发, 如果有 LLM) ──
        if self.llm is not None:
            result = self._llm_analyze(
                trajectory, challenge_type, challenge_difficulty,
                task_desc, step_no, max_steps, soft_hints,
            )
            self._error_since_last_check = 0  # 巡查后重置
            # 同步禁忌列表到返回值
            result.forbidden_actions = list(self._forbidden_actions)
            return result

        # 无 LLM 时: L1-B 软线索也作为干预依据 (降级模式)
        if soft_hints:
            guidance = self._build_rule_guidance(soft_hints, challenge_type)
            self._last_guidance = guidance
            self._last_guidance_step = step_no
            self._last_guidance_priority = "SHOULD"  # 
            self._last_guidance_action = self._dominant_action(recent)
            self._error_since_last_check = 0
            return CoordinatorGuidance(
                should_intervene=True,
                priority="SHOULD",  # 降级模式: 建议执行
                guidance=guidance,
                reason="; ".join(soft_hints),
                extend_steps=False,
                detected_issues=soft_hints,
                analysis_summary=f"L1 软线索 (无 LLM 降级): {'; '.join(soft_hints)}",
                forbidden_actions=list(self._forbidden_actions),
            )

        # 无 LLM 且无任何问题
        self._error_since_last_check = 0
        # 也检查步数接近上限 (与 L2 路径一致)
        near_limit = step_no >= max_steps - self.early_exit_steps if max_steps > 0 else False
        extend = len(trajectory) >= self.lookback or near_limit
        return CoordinatorGuidance(
            should_intervene=False,
            reason="方向正确, 继续推进",
            extend_steps=extend,
            analysis_summary="L1 规则预检未发现问题",
            forbidden_actions=list(self._forbidden_actions),
        )

    # ── L1 规则预检方法 ──

    def _check_exact_repeats(self, recent: list[dict]) -> str:
        """L1-A: 检测完全重复操作 (死循环).

        判定: 同一工具 + 相似参数 (路径归一化后) 出现 ≥max_repeats 次.
        这是确定性死循环, 直接干预不调 LLM.
        """
        actions = []
        for step in recent:
            action = (step.get("action") or "").strip()
            action_input = (step.get("action_input") or "").strip()[:100]
            norm_input = re.sub(r"/tmp/[^ /\"]+", "/tmp/X", action_input)
            actions.append(f"{action}:{norm_input}")

        from collections import Counter
        counter = Counter(actions)
        for action, count in counter.items():
            if count >= self.max_repeats:
                return f"完全重复: '{action[:80]}' 出现 {count} 次"
        return ""

    def _check_tool_overuse(self, recent: list[dict]) -> str:
        """L1-B: 检测工具过度使用 (思路固化线索).

        判定: 同一工具使用 ≥(max_repeats+2) 次 (默认 5 次), 但参数不同.
        这是软线索, 传给 L2 LLM 判断是否真的思路固化.
        """
        tool_counter: dict[str, int] = {}
        for step in recent:
            action = (step.get("action") or "").strip()
            if action:
                tool_counter[action] = tool_counter.get(action, 0) + 1
        for tool, count in tool_counter.items():
            if count >= self.max_repeats + 2:
                return f"工具过度使用: '{tool}' 使用 {count} 次 (参数不同, 需 LLM 判断是否思路固化)"
        return ""

    def _check_errors(self, recent: list[dict]) -> str:
        """L1-B: 检测连续错误步 (进展停滞线索).

        判定: 连续 ≥max_errors 个错误步.
        这是软线索, 传给 L2 LLM 判断是必要的试错还是真的停滞.
        """
        consecutive_errors = 0
        for step in reversed(recent):
            if step.get("is_error"):
                consecutive_errors += 1
                if consecutive_errors >= self.max_errors:
                    return f"连续 {consecutive_errors} 个错误步 (需 LLM 判断是试错还是停滞)"
            else:
                break
        return ""

    def _check_guidance_persistence(self, recent: list[dict]) -> str:
        """检查上次指导后 agent 是否改变了行为.

        如果上次指导后 agent 仍在用相同的工具, 说明指导被忽视, 需要强化.
        """
        if not self._last_guidance or self._last_guidance_step <= 0:
            return ""
        current_dominant = self._dominant_action(recent)
        if self._last_guidance_action and current_dominant == self._last_guidance_action:
            steps_since = self._last_check_step - self._last_guidance_step
            if steps_since > 0:
                return (
                    f"上次指导 (step {self._last_guidance_step}) 后 agent 仍在用 '{current_dominant}', "
                    f"已过 {steps_since} 步, 指导可能被忽视"
                )
        return ""

    def _check_must_noncompliance(self, recent: list[dict]) -> str:
        """检测 MUST 指令未被执行 (硬问题, 直接干预).

        背景 (历史复盘): 协调器 step10 下达 MUST 指令
        ("停止单字符 MD5 爆破"), 但 agent 忽略, 继续 MD5 穷举 20 步.
        旧逻辑只把"指导持久性"作为软线索传给 L2 LLM, LLM 可能继续沉默,
        导致 MUST 指令形同虚设.

        规则: 上次干预是 MUST 且 agent 主导工具未改变 → 升级为 MUST 阻断:
        - 已过 ≥1 个巡查间隔仍未改变 = MUST 未执行, 直接干预
        - 同时把上次指导追加为禁忌操作 (agent 再试同类操作立即拦截)

        自我纠错: 主导工具未变**且无任何实质进展**才算未执行.
        若 agent 持续产生新 observation (在推进), 即使工具未变也视为有效推进,
        交由 L2 LLM 全局判断方向正确性 (历史复盘: agent 深挖调用链逐步
        突破 XOR→6-bit 编码逻辑, 但被机械判定为 MUST 未执行, 属误判).
        """
        if not self._last_guidance or self._last_guidance_step <= 0:
            return ""
        if self._last_guidance_priority != "MUST":
            return ""
        current_dominant = self._dominant_action(recent)
        if not self._last_guidance_action or current_dominant != self._last_guidance_action:
            return ""  # 主导工具已改变, 视为执行了指导
        steps_since = self._last_check_step - self._last_guidance_step
        if steps_since < self.check_interval:
            return ""  # 间隔太短, 可能正在切换中
        # 主导工具未变但持续有实质进展 → 不判未执行
        if self._has_progress_after_guidance(recent):
            return ""
        # 主导工具未变且已过一个间隔且无进展 → MUST 未执行
        return (
            f"MUST 指令未被执行: step {self._last_guidance_step} 下达 [MUST] 指导后, "
            f"已过 {steps_since} 步仍在使用 '{current_dominant}' 且无实质进展. "
            f"上次指导: {self._last_guidance[:120]}"
        )

    def _has_progress(self, recent: list[dict]) -> bool:
        """最近轨迹是否有实质进展.

        判定: 存在 ≥2 种不同的非空 observation (说明有新发现/新输出, 不是原地打转).
        用于将"完全重复但持续有新发现"降级为软线索, 交 L2 LLM 判断.
        """
        obs_set: set[str] = set()
        for step in recent:
            if step.get("is_error"):
                continue
            obs = str(step.get("observation") or "").strip()
            if obs and obs.lower() not in ("(no observation)", "none", "无"):
                obs_set.add(obs[:100])
        return len(obs_set) >= 2

    def _has_progress_after_guidance(self, recent: list[dict]) -> bool:
        """指导后的轨迹是否有实质进展.

        判定: 最近轨迹中存在非空、非错误的 observation (有新发现/新输出).
        注意: recent 窗口内的步都在上次指导之后 (间隔 ≥ check_interval),
        所以只要其中任何一步产生了新 observation, 即视为在推进.
        """
        for step in recent:
            if step.get("is_error"):
                continue
            obs = str(step.get("observation") or "").strip()
            # 空观察 / 占位观察不算进展
            if obs and obs.lower() not in ("(no observation)", "none", "无"):
                return True
        return False

    def _dominant_action(self, recent: list[dict]) -> str:
        """获取最近轨迹中的主导工具."""
        tool_counter: dict[str, int] = {}
        for step in recent:
            action = (step.get("action") or "").strip()
            if action:
                tool_counter[action] = tool_counter.get(action, 0) + 1
        if not tool_counter:
            return ""
        return max(tool_counter, key=tool_counter.get)

    def _check_forbidden_actions(self, recent: list[dict]) -> str:
        """检测 agent 是否在尝试禁忌列表中的操作.

        禁忌列表由 LLM 分析时生成 (如"hashcat 爆破 cloud.zip 密码"连续失败后).
        如果 agent 仍在尝试同类操作, 立即干预 (priority=MUST).
        """
        if not self._forbidden_actions:
            return ""
        # 简单关键词匹配: 检查最近 3 步的 action+action_input 是否包含禁忌关键词
        for step in recent[-3:]:
            action = (step.get("action") or "").strip()
            action_input = (step.get("action_input") or "").strip()[:200]
            combined = f"{action} {action_input}".lower()
            for forbidden in self._forbidden_actions:
                # 提取禁忌描述中的关键词 (如"hashcat"/"john"/"fcrackzip"等)
                keywords = [w for w in forbidden.lower().split() if len(w) > 3]
                if keywords and any(kw in combined for kw in keywords):
                    return f"禁忌操作: agent 在尝试已确认无效的操作 '{forbidden[:60]}'"
        return ""

    def _check_direction(self, recent: list[dict], challenge_type: str) -> str:
        """L1-A: 检测明显方向错误 (题型完全不匹配).

        判定: 最近 5 步的操作集合与题型期望工具集完全不相交.
        这是确定性方向错误, 直接干预不调 LLM.
        """
        if not challenge_type:
            return ""

        type_actions = {
            "crypto": {"ssh_python", "ssh_exec", "crypto_rsa", "crypto_classic", "des_cryptanalysis", "feistel_decrypt", "ecdsa_nonce_reuse", "sage_common_d_attack", "vision_analyze"},
            "web": {"http_request", "ssh_exec", "ssh_python", "web_recon", "web_fingerprint", "web_dirscan", "lfi_scanner", "encoding_helper", "sqlmap"},
            "pwn": {"ssh_python", "ssh_exec", "pwn_checksec", "pwn_cyclic", "pwn_ropgadget", "pwn_exploit"},
            "reverse": {"ssh_exec", "ssh_python", "angr_symbolic_exec", "binary_analyze", "apk_decompile", "vision_analyze"},
            "misc": {"ssh_exec", "ssh_python", "vision_analyze", "ocr", "osint_exiftool", "osint_steghide", "osint_binwalk", "osint_tshark", "mem_xor_analyze"},
            "forensics": {"ssh_exec", "ssh_python", "vision_analyze", "osint_exiftool", "osint_tshark", "mem_xor_analyze"},
            "osint": {"http_request", "ssh_exec", "osint_exiftool", "ocr", "web_search", "osm_geocode", "reverse_image_search", "vision_analyze"},
        }

        expected = type_actions.get(challenge_type.lower(), set())
        if not expected:
            return ""

        recent_actions = set()
        for step in recent[-5:]:
            action = (step.get("action") or "").strip()
            if action:
                recent_actions.add(action)

        if recent_actions and recent_actions.isdisjoint(expected):
            return f"方向错误: 最近操作 {recent_actions} 与题型 {challenge_type} 不匹配"
        return ""

    def _build_rule_guidance(self, issues: list[str], challenge_type: str) -> str:
        """基于规则预检结果生成指导."""
        parts = ["⚠️ 巡查指导 (规则预检发现问题):"]
        for issue in issues:
            if "完全重复" in issue:
                parts.append(
                    "  检测到死循环: 你在重复执行完全相同的操作. "
                    "请停止重复, 尝试完全不同的思路. "
                    "建议: 换一个工具、换一个分析角度、或重新审视题目要求."
                )
            elif "工具过度使用" in issue:
                parts.append(
                    "  检测到思路固化: 你过度依赖单一工具. "
                    "请尝试其他工具或方法. "
                    "例如: 如果一直在用 ssh_exec 手动操作, 改用 ssh_python 写完整脚本."
                )
            elif "连续" in issue and "错误" in issue:
                parts.append(
                    "  检测到进展停滞: 近期连续出现错误. "
                    "请检查工具参数是否正确, 或尝试更简单的测试用例先验证思路. "
                    "如果当前方法持续失败, 请换一个完全不同的方向."
                )
            elif "方向错误" in issue:
                parts.append(
                    f"  检测到方向偏离: 当前操作与题目类型 ({challenge_type}) 不匹配. "
                    f"请重新审视题目类型, 确保解题方向正确."
                )
            elif "指导可能被忽视" in issue:
                parts.append(
                    "  注意: 上次巡查指导后你的行为没有改变. "
                    "请认真回顾上次的建议并调整策略, 否则继续重复可能无法取得进展."
                )
            elif "禁忌操作" in issue:
                parts.append(
                    "  [MUST] 禁忌操作: 你在尝试已确认无效的操作. "
                    "该操作之前已多次失败, 不要再重复. "
                    "请立即切换到完全不同的方法."
                )
            elif "MUST 指令未被执行" in issue:
                parts.append(
                    "  [MUST][强制] 上一条 MUST 指令被忽略了: 你必须立即停止当前主导操作 "
                    "并执行上次指导中指定的动作. 继续当前思路已被判定为无效, "
                    "不要再以自身判断为由拖延. 请立即按上次指导执行."
                )
            else:
                # 未知硬问题兜底 — 强制切换方向
                parts.append(
                    "  [MUST][强制] 检测到确定性问题, 必须立即改变当前操作方式: "
                    "停止重复当前思路, 换一个完全不同的工具或分析方法."
                )
        return "\n".join(parts)

    # ── LLM 深度分析方法 ──

    def _llm_analyze(
        self,
        trajectory: list[dict],
        challenge_type: str,
        challenge_difficulty: str,
        task_desc: str,
        step_no: int,
        max_steps: int,
        soft_hints: list[str] | None = None,
    ) -> CoordinatorGuidance:
        """L2 LLM 深度分析: 宏观审视完整轨迹 + 知识库辅助 + L1 线索.

        始终触发 (不再依赖 L1 无问题), 传入 L1 软线索供 LLM 参考.
        LLM 能区分"工具过度使用但方向正确"和"真正的思路固化", 避免误判.
        """
        try:
            # 1. 查询知识库 (Skill + RAG)
            knowledge_context = self._query_knowledge(task_desc, challenge_type)

            # 2. 构造轨迹摘要 (压缩, 避免 token 爆炸)
            trajectory_summary = self._summarize_trajectory(trajectory)

            # 3. 构造 L1 线索文本
            if soft_hints:
                l1_hints = "\n".join(f"- {h}" for h in soft_hints)
            else:
                l1_hints = "(L1 规则预检未发现线索, 方向和重复性均正常)"

            # 构造当前禁忌列表文本
            if self._forbidden_actions:
                forbidden_text = "\n".join(f"- {f}" for f in self._forbidden_actions)
            else:
                forbidden_text = "(无, 还没有确认无效的操作)"

            # 构造上次指导区块 (供 LLM 自我纠错)
            if self._last_guidance and self._last_guidance_step > 0:
                steps_since = step_no - self._last_guidance_step
                last_block = (
                    f"上次指导 (step {self._last_guidance_step}, 优先级 {self._last_guidance_priority}): "
                    f"{self._last_guidance[:200]}\n"
                    f"距今已过 {steps_since} 步. 请判断:\n"
                    f"1. Agent 是否执行了该指导?\n"
                    f"2. 若未执行: 是 Agent 拒绝执行, 还是它用自己的方式取得了进展"
                    f" (说明上次指导可能不准确, 应 revert_guidance=true)?\n"
                    f"3. 结合后续轨迹, 上次指导是否已被证伪? 若是, 撤销并给出修正方向."
                )
            else:
                last_block = "(无上次指导)"

            # 构造推论状态区块 (供 LLM 回顾更新)
            if self._belief_state:
                belief_lines = []
                for b in self._belief_state:
                    belief_lines.append(
                        f"- [{b.get('id', '?')}] ({b.get('level', '?')}) {b.get('statement', '?')}"
                        f" | 证据: {b.get('evidence', '?')}"
                    )
                belief_block = "\n".join(belief_lines)
            else:
                belief_block = "(首次巡查, 无历史推论. 请基于当前轨迹建立初始推论清单.)"

            # 4. 构造 LLM prompt
            user_prompt = _COORDINATOR_USER_TEMPLATE.format(
                task_desc=task_desc[:500] if task_desc else "(未提供)",
                challenge_type=challenge_type or "(未知)",
                challenge_difficulty=challenge_difficulty or "(未知)",
                step_no=step_no,
                max_steps=max_steps or "(自适应)",
                belief_state_block=belief_block,
                l1_hints=l1_hints,
                forbidden_actions=forbidden_text,
                last_guidance_block=last_block,
                knowledge_context=knowledge_context,
                trajectory_summary=trajectory_summary,
            )

            # 5. 调用 LLM (低温度保证稳定输出)
            from ctf_agent.llm import Message
            messages = [
                Message(role="system", content=_COORDINATOR_SYSTEM_PROMPT),
                Message(role="user", content=user_prompt),
            ]
            chat_result = self.llm.chat(messages, temperature=0.0)
            response = chat_result.content.strip()

            # 6. 解析 LLM 输出 (JSON) — 优先匹配含 belief_state 的完整 JSON
            json_match = re.search(r'\{.*\}', response, re.DOTALL)

            if json_match:
                try:
                    result = json.loads(json_match.group())
                    # 更新推论状态 (跨巡查持久化)
                    new_beliefs = result.get("belief_state", [])
                    if isinstance(new_beliefs, list) and new_beliefs:
                        self._belief_state = [
                            {
                                "id": str(b.get("id", f"B{i+1}")),
                                "statement": str(b.get("statement", "")),
                                "level": str(b.get("level", "POSSIBLE")).upper(),
                                "evidence": str(b.get("evidence", "")),
                                # 透传 action (keep/upgrade/downgrade/disprove/new) 供日志显示
                                "action": str(b.get("action", "")),
                            }
                            for i, b in enumerate(new_beliefs)
                            if isinstance(b, dict)
                        ]
                    # 解析 reflection (巡查器反思过程, 供调用器日志显示)
                    reflection = str(result.get("reflection", "")).strip()
                    # 自动清理 DISPROVED 推论对应的禁忌项
                    for b in self._belief_state:
                        if b.get("level") == "DISPROVED":
                            stmt_keywords = [w for w in b.get("statement", "").lower().split() if len(w) > 3]
                            for kw in stmt_keywords:
                                for fa in list(self._forbidden_actions):
                                    if kw in fa.lower():
                                        self._forbidden_actions.remove(fa)

                    should_intervene = bool(result.get("should_intervene", False))
                    guidance = result.get("guidance", "").strip()
                    reason = result.get("reason", "").strip()
                    extend = bool(result.get("extend_steps", False))
                    summary = result.get("analysis_summary", "").strip()
                    # 解析 priority 和 forbidden_actions
                    priority = result.get("priority", "SHOULD").strip().upper()
                    if priority not in ("MUST", "SHOULD"):
                        priority = "SHOULD"
                    new_forbidden = result.get("forbidden_actions", [])
                    if isinstance(new_forbidden, list):
                        # 合并新禁忌项 (去重)
                        for f in new_forbidden:
                            f = str(f).strip()
                            if f and f not in self._forbidden_actions:
                                self._forbidden_actions.append(f)

                    # 自我纠错 — 解析撤销/移除禁忌
                    revert = bool(result.get("revert_guidance", False))
                    remove_list = result.get("remove_forbidden", [])
                    if isinstance(remove_list, list):
                        for f in remove_list:
                            f = str(f).strip()
                            if f and f in self._forbidden_actions:
                                self._forbidden_actions.remove(f)
                                # 让返回值带出, 供 react.py 记录
                                result.setdefault("_remove_forbidden", []).append(f)
                    if revert:
                        # 撤销上次指导: 清理 MUST 状态, 避免基于已证伪指导继续强制
                        self._last_guidance = ""
                        self._last_guidance_priority = ""
                        self._last_guidance_action = ""
                        self._last_guidance_step = 0

                    # 沉默原则: 方向正确时不干预
                    if not should_intervene:
                        return CoordinatorGuidance(
                            should_intervene=False,
                            reason=reason or "方向正确, 继续推进",
                            extend_steps=extend or (step_no >= max_steps - self.early_exit_steps if max_steps > 0 else False),
                            analysis_summary=summary or "L2 LLM 分析: 方向正确",
                            priority=priority,
                            forbidden_actions=list(self._forbidden_actions),
                            revert_guidance=revert,
                            remove_forbidden=list(result.get("_remove_forbidden", [])),
                            # 透传推论分级 + 反思 (供调用器完整日志)
                            reflection=reflection,
                            belief_state=[dict(b) for b in self._belief_state],
                        )

                    # 干预: 更新指导持久性属性
                    self._last_guidance = guidance
                    self._last_guidance_step = step_no
                    self._last_guidance_priority = priority  # 
                    self._last_guidance_action = self._dominant_action(
                        trajectory[-self.lookback:] if len(trajectory) >= self.lookback else trajectory
                    )
                    return CoordinatorGuidance(
                        should_intervene=True,
                        guidance=guidance,
                        reason=reason,
                        # 干预时也检查步数接近上限自动扩展 (之前只在沉默时检查, 导致 never triggered)
                        extend_steps=extend or (step_no >= max_steps - self.early_exit_steps if max_steps > 0 else False),
                        analysis_summary=summary,
                        priority=priority,
                        forbidden_actions=list(self._forbidden_actions),
                        revert_guidance=revert,
                        remove_forbidden=list(result.get("_remove_forbidden", [])),
                        # 透传推论分级 + 反思 (供调用器完整日志)
                        reflection=reflection,
                        belief_state=[dict(b) for b in self._belief_state],
                    )
                except (json.JSONDecodeError, KeyError):
                    pass

            # JSON 解析失败, 降级为规则判断
            return CoordinatorGuidance(
                should_intervene=False,
                reason="L2 LLM 分析完成但输出格式异常, 降级为不干预",
                extend_steps=True,
                analysis_summary="L2 LLM 输出解析失败, 降级处理",
            )

        except Exception as e:
            # LLM 分析失败不影响主流程
            return CoordinatorGuidance(
                should_intervene=False,
                reason=f"L2 LLM 分析异常: {e}, 降级为不干预",
                extend_steps=True,
                analysis_summary=f"L2 LLM 分析异常: {type(e).__name__}",
            )

    def _query_knowledge(self, task_desc: str, challenge_type: str) -> str:
        """查询知识库 (Skill + RAG) 辅助判断.

        直接调用底层 API, 不用 RAGRetriever (避免 HyDE 的额外 LLM 调用,
        巡查器场景已有 task_desc, 直接语义检索即可, 省 token + 低延迟).
        """
        parts: list[str] = []

        # 1. 查询 Skill 库 (基于套路的解题套路)
        if self.skill_library is not None:
            try:
                skill_hint = self.skill_library.format_for_prompt(
                    task_desc, category=challenge_type, top_k=2
                )
                if skill_hint:
                    parts.append("### 匹配的 Skill:\n" + skill_hint[:800])
            except Exception:
                pass

        # 2. 查询 RAG (长期记忆: 历史 writeup)
        # 直接用 long_term.search, 不走 RAGRetriever (避免 HyDE LLM 调用)
        if self.long_term is not None:
            try:
                docs = self.long_term.search(task_desc, n_results=2)
                if docs:
                    rag_lines: list[str] = []
                    for d in docs:
                        # long_term.search 返回 dict 含 document/metadata/distance
                        doc_text = (d.get("document") or "")[:300]
                        meta = d.get("metadata") or {}
                        type_str = meta.get("type", "")
                        label = f"[{type_str}] " if type_str else ""
                        rag_lines.append(f"- {label}{doc_text}")
                    parts.append("### RAG 检索结果 (历史 writeup):\n" + "\n".join(rag_lines))
            except Exception:
                pass

        return "\n\n".join(parts) if parts else "(知识库无匹配结果)"

    def _summarize_trajectory(self, trajectory: list[dict]) -> str:
        """压缩轨迹为摘要 (避免 token 爆炸).

        策略:
        - 前 3 步: 完整 thought + action
        - 中间步: 只保留 action + action_input 前 80 字符
        - 最近 5 步: 完整 thought + action + observation 前 200 字符
        """
        if not trajectory:
            return "(空轨迹)"

        lines: list[str] = []
        total = len(trajectory)

        # 前 3 步 (完整)
        for i, step in enumerate(trajectory[:3]):
            thought = (step.get("thought") or "")[:150]
            action = step.get("action") or ""
            action_input = (step.get("action_input") or "")[:100]
            lines.append(f"Step {i+1}: [{action}] {thought}")
            if action_input:
                lines.append(f"  参数: {action_input}")

        # 中间步 (压缩)
        if total > 8:
            mid = trajectory[3:-5]
            lines.append(f"... (省略 {len(mid)} 步) ...")
            for i, step in enumerate(mid):
                action = step.get("action") or ""
                action_input = (step.get("action_input") or "")[:80]
                is_error = " [ERROR]" if step.get("is_error") else ""
                lines.append(f"Step {i+4}: [{action}]{is_error} {action_input}")

        # 最近 5 步 (完整)
        recent_start = max(3, total - 5)
        for i, step in enumerate(trajectory[recent_start:]):
            step_no = recent_start + i + 1
            thought = (step.get("thought") or "")[:200]
            action = step.get("action") or ""
            action_input = (step.get("action_input") or "")[:150]
            observation = (step.get("observation") or "")[:300]
            is_error = " [ERROR]" if step.get("is_error") else ""
            lines.append(f"Step {step_no}: [{action}]{is_error}")
            if thought:
                lines.append(f"  Thought: {thought}")
            if action_input:
                lines.append(f"  参数: {action_input}")
            if observation:
                lines.append(f"  结果: {observation}")

        return "\n".join(lines)


__all__ = ["Coordinator", "CoordinatorGuidance"]
