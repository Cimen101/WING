"""Sprint 27/29: 巡查指导器 (Coordinator LLM) — 智能旁观者.

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
import threading
import time
from dataclasses import dataclass, field
from typing import Any

# Sprint 36 复盘: "执行类"工具 — 实际运行命令/脚本或与外部交互的工具.
# 用于"分析瘫痪"检测: 长时间只读源码/解析数据/静态分析而不用执行类工具,
# 说明 agent 停留在理解阶段, 未推进到攻击实施 (linx/threshold/faulty_mayo 三题
# 均死于"思路清晰但迟迟不落地攻击脚本/不连靶机").
_EXECUTION_TOOLS = {
    "ssh_exec", "ssh_python", "docker_exec", "docker_python",
    "ssh_upload", "docker_upload", "http_request", "exploit_template",
}


@dataclass
class CoordinatorGuidance:
    """巡查指导器的输出."""

    should_intervene: bool = False          # 是否需要干预
    guidance: str = ""                      # 给 agent 的战术指导
    reason: str = ""                        # 干预原因 (或"方向正确"说明)
    extend_steps: bool = False              # 是否建议扩展步数
    detected_issues: list[str] = field(default_factory=list)
    analysis_summary: str = ""              # LLM 分析摘要 (用于日志)
    priority: str = "SHOULD"                # Sprint 31: "MUST" = 必须执行, "SHOULD" = 建议执行
    forbidden_actions: list[str] = field(default_factory=list)  # Sprint 31: 禁忌列表 (已确认无效的操作)
    # Sprint 32.4c: 巡查器自我纠错 — 用后续轨迹验证自己之前的判断
    revert_guidance: bool = False           # 撤销上次指导 (上次判断被后续轨迹证伪)
    remove_forbidden: list[str] = field(default_factory=list)  # 从禁忌列表移除误判项 (agent 用该操作取得了突破)
    # Sprint 32.7: 推论分级框架 — 透传给调用器用于完整日志显示
    reflection: str = ""                    # 巡查器反思过程 (必填, 供日志/调试)
    belief_state: list[dict] = field(default_factory=list)  # 推论清单 [{id, statement, level, evidence, action}]
    # WING-Goose 第 8.3 节: 创新模式灵感板 — 无论是否干预必产 2-3 条创造性探索建议
    # 注入 agent 下一轮 prompt 的"灵感板"段, 标注"探索建议, 非强制"
    creative_hints: list[str] = field(default_factory=list)
    # Sprint 34: 双系统 (快思考主LLM × 慢思考巡查器) — 非创新风格的"下一步战略方向"
    # 仅在 should_intervene=true 时随 guidance 注入 (沉默原则: 方向未偏移不注入任何内容)
    strategic_direction: str = ""


# ── LLM 分析 prompt 模板 ──────────────────────────────────────

_COORDINATOR_SYSTEM_PROMPT = """你是 CTF 解题巡查指导器 (Coordinator), 一个"旁观者"角色.

你的任务是: 宏观审视解题 Agent 的完整行为轨迹, 判断它是否走在正确的方向上,
并在发现问题时提供精准的战术指导.

## 角色定位: 慢思考 (System 2) × 主LLM 快思考 (System 1) — Sprint 34 双系统

整个系统是"快思考 + 慢思考"的互补结构:

- **主 LLM = 快思考 (System 1)**: 基于当前对话上下文快速推进, 只做**战术决策**
  (这一步执行什么命令/工具). 它反应快, 但视野局限于近期几轮.
- **你 = 慢思考 (System 2)**: 拥有跨步数的完整轨迹视野 + 跨巡查持久化的推论状态
  (belief state), 做**战略决策**:
  1. **方向判断**: 当前进攻方向是否偏移/低效, 必要时纠正方向;
  2. **错误修正**: 除了纠正方向, 还要**纠正 Agent 之前步骤中的错误内容**
     (错误判断/错误假设/无效尝试), 明确"哪一步错、错在哪、正确做法", 避免它反复消耗;
  3. **战略深化**: 在主 LLM 当前的推理基础上**进一步深入并细化** — 结合当前情况,
     给出**下一步的战略方向** (往哪个方向深入、优先验证哪个假设、哪个区域还有未挖掘的线索).
     注意: 你是对主 LLM 推理的深化, 不是另起炉灶, 不要否定其已建立的正确部分.

**上下文权衡 (每次决策前必须做)**: 你看到的是发起巡查时的轨迹快照, 可能滞后于主 LLM
最新几步的推理 — 这是你的**缺点**; 但同时你有全局视野与跨巡查记忆 — 这是你的**优点**.
决策前先权衡: ① 我的判断是否已被快照之后的进展推翻? ② 若可能过时, 优先静默分析与整理;
③ 若方向性偏移/错误内容明确且稳定 (不是刚发生的一两次波动), 果断干预.

**沉默原则 (Sprint 34 强化)**: 方向未偏移、进展正常时, 不得向主 LLM 注入任何内容
(should_intervene=false, guidance 与 strategic_direction 均留空), 静默分析与整理信息
(更新 belief state / 禁忌列表) 即可. 不必要的干预会打乱主 LLM 的节奏.

## 核心原则

1. **旁观者清**: 你不参与具体解题, 只做宏观判断. 你能看到 Agent 看不到的全局问题.
2. **沉默是金**: 如果 Agent 方向正确且进展正常, 保持沉默 (should_intervene=false).
   不必要的干预会打乱 Agent 的节奏.
3. **精准指导**: 发现问题时, 给出具体的、可操作的战术建议.
   不要说"请换方向"这种空泛的话, 要说"当前在用费马分解, 但 n 的两个素数差异大,
   费马法无效, 应该用 factordb 或 sympy.factorint".
4. **基于证据**: 判断必须基于轨迹中的实际行为, 不要猜测 Agent 的意图.
5. **无充分证据禁止否定方向 (Sprint 36.1 强化, CTF 漏洞寻找阶段)**: 在寻找漏洞
   的过程中, 绝大多数方向在未获**充分证据** (FACT 级证伪) 之前都可能是有效路径.
   - 判定"方向错误/死路/禁忌"必须基于 FACT 或 DISPROVED 级推论, 或 ≥8 步持续
     完全无关操作 (明确无进展); 不得基于 POSSIBLE 级推测否定方向.
   - 单次失败/单条异常响应 ≠ 死路; 报错也可能是线索 (如报错信息泄露内部路径).
   - 对"看似无关"的方向, 优先发散性探索并记录, 而不是否定; 只有当该方向被
     明确证伪 (如连续多次相同尝试均失败且无新信息) 才可降权或禁止.
   - 例外: 已由 DISPROVED 推论证伪的方向、或经验库 high 置信度明确禁忌的方向,
     可否定 — 这属于"有充分证据"的否定.

## 推论分级框架 (Sprint 32.6 — 核心改造)

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

5. **自我纠错 (Sprint 32.4c + 32.6 强化)**: 你之前的判断不一定是正确的, 你要用后续轨迹验证它.
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
  "strategic_direction": "下一步战略方向 (非创新风格: 仅 should_intervene=true 时填写; 创新风格: 留空用 creative_hints)",
  "reason": "干预原因 或 '方向正确, 继续推进' (必须引用推论 ID 作为依据, 如 '基于 B1(FACT)+B2(LIKELY)')",
  "extend_steps": true/false,
  "forbidden_actions": ["已确认无效的操作描述 (仅基于 FACT/DISPROVED 推论, 不得基于 POSSIBLE)", ...],
  "revert_guidance": true/false,
  "remove_forbidden": ["应移除的误判禁忌项 (基于 DISPROVED 推论)", ...],
  "analysis_summary": "一句话分析摘要",
  "p1_done": true/false,
  "p1_done_summary": "P1 侦查完成时的该路成果摘要 (仅 p1_done=true 时填写, 否则留空)",
  "p2_verified": true/false,
  "p2_verified_direction": "已验证的方向 (仅 p2_verified=true 时填写)",
  "p2_verified_evidence": "验证证据 (工具输出/复现结果等, 必须完整, 仅 p2_verified=true 时填写)"
}

## p1_done 说明 (Sprint 36.2, 仅 P1 阶段)
- 仅当当前为 P1 侦查阶段, 且你判断该路 agent 的基础侦查**已覆盖题目全貌**
  (入口/附件/版本指纹/关键线索均已有初步了解, 广度足够) 时, p1_done=true.
- 三路全部汇报 p1_done 后, 总指挥才整合全局情报摘要并确定主方向 → 进入 P2.
- P1 阶段未完成基础侦查时 p1_done=false (不要过早汇报完成).

## p2_verified 说明 (Sprint 36.2, 仅 P2 阶段)
- 仅当当前为 P2 漏洞识别阶段, 且你判断某方向已有**足够的证据支撑并取得了验证**
  (不是猜测; 如工具输出确认漏洞原语/本地复现成功/响应证实假设) 时, p2_verified=true.
- 汇报必须**完整**: 给出具体方向 + 验证证据 (什么操作、什么输出、如何证实).
- 三路中任一路汇报 p2_verified 后, 总指挥会确凿分析汇报是否完整可信,
  确认后才切换 P3. 证据不足时 p2_verified=false (不要过早汇报).

## revert_guidance / remove_forbidden 说明 (Sprint 32.4c 自我纠错)
- revert_guidance=true: 你之前的下达的指导被后续轨迹证伪 (Agent 用自己的方式取得了进展).
  此时应撤销该指导, 不再强制 Agent 执行. 如果 Agent 当前方向正确, 同时保持 should_intervene=false.
- remove_forbidden: 禁忌列表中已被 Agent 成功使用的操作 (误判), 应移除.

## priority 说明
- "MUST": Agent 必须立即执行指导, 不得自主判断优先级. 用于明显方向错误/死循环/禁忌操作.
  Sprint 32.4 强化: MUST 指导必须给出**强制工具链切换** — 明确"停止 X, 改用 Y 工具/方法",
  不要只说"换个思路". 例: "停止单字符 MD5 爆破, 用 gdb 在 call 0x404140 处断点读取 MD5 输入".
- "SHOULD": 建议执行, Agent 可结合实际情况判断. 用于软线索/改进建议.

## 假设证伪 (Sprint 32.4 新增维度)

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

## strategic_direction 写作要求 (Sprint 34: 战略深化 — 非创新风格)

除 guidance 外, 非创新风格还需给出 **下一步战略方向** (strategic_direction):
- **定位**: 不是重复 guidance 的具体命令, 而是**方向层**指导 — 在主 LLM 当前推理基础上
  进一步深入细化: 下一步往哪个方向深挖 / 优先验证哪个假设 / 哪块区域还有未挖掘的线索 /
  哪些线索需要交叉关联.
- **示例**: "当前 RSA 公钥已分解 (B1 FACT), 下一步优先推导私钥 d 并用它解出密文; 若 e·d
  不满足, 回头核查 p-1 与 q-1 的 gcd 是否为 d 的倍数."
- **前提**: 仅 when should_intervene=true; 方向未偏移时留空 (沉默原则). 不超过 200 字.

## 错误内容修正 (Sprint 34 强化)

当 Agent 之前步骤存在**错误内容** (错误判断 / 被证伪仍坚持的假设 / 无效尝试) 时,
在 guidance 中明确修正: 指出"哪一步 / 哪个假设错了、为什么错、正确做法是什么".
不要只纠正方向而放任错误细节残留. 例如:
"step 31 假设 'flag 是 8 位数字' 已证伪 (FACT: 爆破到 99999999 均失败) — 停止单字符爆破,
改从输出字符集反推输入变换; step 25 你误读了字节序, 实际是 little-endian."

## forbidden_actions 说明
当某类操作已确认无效时 (如"hashcat 爆破 cloud.zip 密码"连续失败), 加入 forbidden_actions.
Agent 下次尝试同类操作时会被拦截并重定向.
"""

_COORDINATOR_USER_TEMPLATE = """## 题目信息
题目描述: {task_desc}
题型: {challenge_type}
难度: {challenge_difficulty}
当前步数: {step_no} / {max_steps}

## 当前解题阶段 (总指挥下发, 决定你的巡查侧重)
{phase_task_block}

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

### 步骤 5: 上下文权衡 + 战略深化 (Sprint 34 必做)
1. **上下文权衡**: 你看到的是发起巡查时的轨迹快照 (可能滞后于主 LLM 最新几步).
   权衡利弊: 全局视野/跨巡查记忆 (优点) vs 快照滞后 (缺点).
   结论影响决策: 判断可能已过时 → 保持静默, 只静默整理信息; 方向偏移明确且稳定 → 干预.
2. **战略深化**: 若要干预, 在 guidance 之外给出 strategic_direction — 在主 LLM 当前
   推理基础上进一步深入细化 (下一步方向 / 优先验证的假设 / 未挖掘的线索区域).
   非创新风格填 strategic_direction; 创新风格留空 (用 creative_hints 发散).
3. **错误修正**: 若之前步骤有错误内容 (错误判断/被证伪仍坚持的假设), 在 guidance 中
   明确指出错在哪一步、错在哪、正确做法, 不要只纠正方向.

注意:
1. L1 线索只是启发式提示, 不一定是问题. 你需要结合轨迹的具体内容判断.
2. guidance 必须包含"做什么+怎么做+为什么"三部分.
3. reason 字段必须引用推论 ID 作为依据 (如 "基于 B1(FACT): 入口确认 + B2(LIKELY): payload格式有误").
4. 沉默原则: 方向未偏移 → should_intervene=false, guidance 与 strategic_direction 均留空,
   只更新 belief_state 与禁忌列表 (静默分析与整理信息).
"""


# ── WING-Goose 第 8 节: 风格差异化 prompt 段落 ──────────────────
# (风格词表与 ctf_agent.agent.styles.STYLE_GUIDANCE 同源, 见 8.5 节约束)

_STYLE_COORDINATOR_SECTIONS = {
    "conservative": """
## 风格: 保守 (Conservative) — 巡查适配 (Sprint 34: 稳健节奏)

1. **节奏稳健**: 巡查间隔较长 (约 10 步), 不轻易打扰 Agent; 干预必须基于充分证据
   (至少 FACT + LIKELY 支撑), 避免引入不必要的方向切换.
2. **方向输出**: 干预时除 guidance 外, 给出 strategic_direction — 在主 LLM 当前推理
   基础上**稳健地深化**: 建议小步验证、先确认再推进, 不鼓励跳跃式联想.
3. **错误修正**: 逐条修正 Agent 已确认的错误判断, 明确证据, 防止其反复消耗在错误假设上.
4. **不使用 creative_hints** (灵感板仅属创新风格), 不产发散性探索建议.
5. **沉默优先**: 方向正确且稳定 → 静默分析与整理, 不注入任何内容.
""",
    "neutral": """
## 风格: 中立 (Neutral) — 巡查适配 (Sprint 34: 均衡节奏)

1. **节奏均衡**: 巡查间隔适中 (约 8 步), 方向偏移迹象出现即复核, 但不过度打扰.
2. **方向输出**: 干预时除 guidance 外, 给出 strategic_direction — 结合当前情况给出
   下一步方向 (优先验证的假设 / 未挖掘的线索), 深化主 LLM 的当前推理.
3. **错误修正**: 修正已确认的错误内容, 明确哪一步错、正确做法.
4. **不使用 creative_hints** (灵感板仅属创新风格), 不产发散性探索建议.
5. **沉默原则**: 方向未偏移 → 静默分析与整理信息, 不注入.
""",
    "aggressive": """
## 风格: 激进 (Aggressive) — 巡查适配 (第 8.2 节 + Sprint 34: 快节奏)

1. **节奏较快**: 巡查间隔短 (约 5 步), 更频繁复核方向; 但判断要快准狠 — 干预即
   果断切换, 不拖泥带水, 给目标不给步骤 ("搞定它, 方式你选"), 仅在 MUST 时给命令级细节.
2. **判断基准**: 不要因为 Agent 频繁试错或多次失败就干预.
   区分"有效试错"与"盲目撞墙": 失败后 action_input 有变化 = 有效试错, 不干预;
   只有连续失败且参数/方法完全不变 = 盲目撞墙, 才考虑干预.
3. **方向错误判定放宽**: 仅当"持续 ≥8 步完全无关操作"才判定方向错误.
4. **方向输出**: 干预时除 guidance 外, 给出 strategic_direction — 直接指出下一步
   最优进攻路径, 快速收敛, 不留犹豫空间.
5. **禁忌列表谨慎**: 激进 Agent 的"看似无效"尝试可能恰好撞对, 不要轻易加入禁忌.
6. **不使用 creative_hints** (灵感板仅属创新风格).
7. **沉默优先**: 只要 Agent 在产出新的 observation / 在推进, 保持沉默.
""",
    "innovative": """
## 风格: 创新 (Innovative) — 巡查适配 (第 8.3 节): 双轨输出

你的分析必须包含**两个轨道**, 缺一不可:

**轨道 A — 判断** (同默认分析): 方向是否正确 / 是否死循环 / 是否停滞, 照常输出 should_intervene 等字段.
**此风格不使用 strategic_direction** (方向深化由创意灵感板承担).

**轨道 B — 发散** (创造性灵感板): **无论是否干预**, 都必须产出 2-3 条 `creative_hints`。
参照创造性思路 5 模板, 结合轨迹给出具体、可执行的探索建议 (不是空话):
1. **目标反转**: 解密/验证卡住 → "也许该文件不是密文而是 key?"
2. **空间重估**: 爆破太慢 → "实际 key 空间可能远小于名义位宽?"
3. **代数结构**: 算法复杂 → "找逆变换闭式解而非枚举?"
4. **侧信道/内嵌**: 表面无线索 → "rodata 中是否有未引用常量/表?"
5. **线索交叉**: 零散发现 → "把 step N 与 step M 的发现合并成一个假设"

要求:
- creative_hints 每条必须结合当前轨迹的具体情况, 给出可操作的方向, 不少于 1 句.
- 禁忌列表在创新模式基本停用 (除非 FACT 级确证无效), 不要频繁阻止 Agent 发散.
- 若 Agent 在尝试有创意但未成功的方法, 优先给"换个角度"的 hint, 而不是判定失败.
- 温度较高发散: 允许比默认更跳跃的联想, 但保持结构稳定 (仍输出完整 JSON).
- **发散优先约束 (WING-Corvus 2.0)**: 若轨迹显示创新 Agent 在**无充分证据时**向
  某一方向**深入重复** (同一思路连续 ≥3 步深挖、或反复微调同一假设), 应判定为
  "过早深入" — 下发提示要求其**停止深入, 回到发散状态** (同时探索 2-3 条不同假设).
  只有出现 FACT 级明确方向后, 深入才是合理的.""",
}


# ── 风格参数表 (第 8.1/8.2 节) ────────────────────────────────

STYLE_PARAMS = {
    # 所有风格统一 5 步一巡查 (用户要求: 干预必须准确果断、及时干预)
    # conservative: 稳健节奏, 干预门槛高
    "conservative": {"max_errors": 3, "check_interval": 5, "temperature": 0.0},
    # neutral: 均衡节奏
    "neutral": {"max_errors": 3, "check_interval": 5, "temperature": 0.0},
    # aggressive: 快节奏, 容忍快速试错 (max_errors 3→5)
    "aggressive": {"max_errors": 5, "check_interval": 5, "temperature": 0.0},
    # innovative: 探索节奏, 必产 hints, 温度 0.4
    "innovative": {"max_errors": 3, "check_interval": 5, "temperature": 0.4},
}


class Coordinator:
    """巡查指导器: LLM 驱动的智能旁观者.

    Sprint 30 两级分析 (优化触发逻辑):
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
        style: str = "conservative",        # WING-Goose 8.1: 解题风格 (conservative/neutral/aggressive/innovative)
        check_interval: int | None = None,  # 后续巡查间隔 (步) — Sprint 34: None=按风格节奏 (保守10/中立8/激进5/创新8), 显式值全局覆盖
        first_check: int = 5,               # 首次巡查步数 (2026-08-05: 10→5, 简单题可能 <10 步解出)
        lookback: int = 10,                 # 规则预检回看步数
        max_repeats: int = 3,               # 同一操作重复 N 次判定为死循环
        max_errors: int = 3,                # 连续 N 个错误步判定为停滞
        early_exit_steps: int = 20,         # 步数接近上限时触发 (倒数 N 步)
        execution_starvation_min_steps: int = 20,  # Sprint 36: 分析瘫痪检测启用步数 (前期信息收集合理)
        experience_library: Any = None,     # 经验库 (skill_library.json), 辅助禁忌判断
        knowledge_base: Any = None,         # WING KB: 四层知识库 (战略层参考)
        # Sprint 36 (WING-Corvus): 战略层能力 (默认关闭, 开启后行为才变化)
        bus: Any = None,                    # FileBus 实例 (跨进程, 与总指挥通信)
        bus_challenge_id: str = "",         # 总线键 (默认 challenge_id)
        commander_enabled: bool = False,    # 总指挥模式开关 (False = 纯雁阵行为不变)
        initial_task_contract: dict | None = None,  # 初始任务契约 {"task_no", "task", "priority"}
    ) -> None:
        self.llm = llm
        self.skill_library = skill_library
        self.long_term = long_term
        self.experience_library = experience_library
        self.knowledge_base = knowledge_base  # WING KB: 战略层参考
        # Sprint 36 (WING-Corvus): 战略层能力 (默认关闭, 开启后行为才变化)
        self._bus = bus                    # FileBus 实例 (跨进程, 与总指挥通信)
        self._bus_challenge_id = bus_challenge_id  # 总线键 (默认 challenge_id)
        self._commander_enabled = bool(commander_enabled and bus is not None)
        # Sprint 36.2: 阶段感知 (随总指挥指令更新) — 用于按阶段注入巡查任务:
        # P1 关注侦查完整性 / P2 关注主方向小方向调控 / P3 负责死循环与方向调整
        self._current_phase: str = "P1"    # 初始为 P1 侦查 (领题即 P1)
        # P1 进度汇报节奏 (每 5 步向总指挥汇报侦查进度)
        self._last_progress_step: int = 0
        # WING-Goose 第 8.1/8.2 节: 按风格应用差异化阈值 (显式传入非默认参数优先)
        self.style = style if style in STYLE_PARAMS else "conservative"
        style_params = STYLE_PARAMS.get(self.style, {})
        self._temperature = style_params.get("temperature", 0.0)
        if check_interval is None:  # Sprint 34: 未显式定制 → 用风格节奏 (稳健/均衡/快/探索)
            check_interval = style_params.get("check_interval", 5)
        if max_errors == 3:  # 未显式定制 → 用风格默认
            max_errors = style_params.get("max_errors", max_errors)
        self.check_interval = check_interval
        self.first_check = first_check
        self.lookback = lookback
        self.max_repeats = max_repeats
        self.max_errors = max_errors
        self.early_exit_steps = early_exit_steps
        self.execution_starvation_min_steps = execution_starvation_min_steps
        # 异常触发: 连续错误步计数
        self._consecutive_errors = 0
        self._last_check_step = 0
        # Sprint 30: 指导持久性 — 记录上次指导, 若 agent 未改变行为则强化提醒
        self._last_guidance: str = ""
        self._last_guidance_step: int = 0
        self._last_guidance_action: str = ""  # 上次指导时 agent 的主导工具
        self._last_guidance_priority: str = ""  # Sprint 32.4: 上次指导的优先级 (MUST/SHOULD)
        # Sprint 31: 禁忌列表 — 已确认无效的操作, agent 再尝试时拦截
        self._forbidden_actions: list[str] = []
        # Sprint 35: 精确签名禁忌 — 死循环自动添加, 用精确匹配避免关键词误伤
        self._forbidden_signatures: set[str] = set()
        # Sprint 35: 全局已尝试方向追踪 — 跨 lookback 窗口记录每个 action 签名的
        # 尝试次数和是否有进展, 用于检测 lookback 窗口外的死循环重试.
        # 格式: {signature: {"count": int, "has_progress": bool, "last_step": int}}
        self._tried_directions: dict[str, dict] = {}
        # Sprint 31: 动态干预频率 — 出现错误后缩短间隔
        self._error_since_last_check: int = 0
        # Sprint 32.6: 推论状态 — 跨巡查持久化, 每次更新后存回
        # 格式: [{"id": "B1", "statement": "...", "level": "FACT/LIKELY/POSSIBLE/DISPROVED", "evidence": "..."}]
        self._belief_state: list[dict] = []
        # Sprint 33: 异步事件驱动巡查 — 分析在后台线程执行, 不阻塞 agent 主循环.
        # 队列上限 1: 同一时刻最多 1 个在途分析 + 1 个未消费结果 (避免叠加过频).
        self._lock = threading.RLock()
        self._analyze_thread: threading.Thread | None = None
        self._pending_guidance: CoordinatorGuidance | None = None
        self._pending_fired_step = 0   # 在途/待消费分析对应的发起步 (注入时声明来源步)
        self._last_fired_step = 0      # 最近一次发起巡查的步数 (首次/近上限门槛)
        self._last_injected_step = 0   # 最近一次注入结果的步数 (发起节奏基准: +N 步再巡查)
        # 巡查间隔钳制在 5~10 步 (用户约束 2026-08-03: 避免整体过于频繁)
        self.check_interval = max(5, min(10, self.check_interval))

        # ── Sprint 36 (WING-Corvus): 战略层能力状态 ──
        self._bus = bus
        self._bus_challenge_id = bus_challenge_id or str(getattr(bus, "bus_challenge_id", "") or "")
        self._commander_enabled = bool(commander_enabled and bus is not None)
        # 任务契约 (总指挥分配的方向性指引, 非强制枷锁)
        contract = initial_task_contract or {}
        self._task_no: int = int(contract.get("task_no") or 0)
        self._task_direction: str = str(contract.get("task") or "")
        self._task_priority: str = str(contract.get("priority") or "SHOULD")
        self._directive_cursor: int = 0      # directive 消费游标
        self._dead_end_switched: bool = False
        self._tool_unavailable: dict[str, int] = {}  # 工具连续不可用计数 (死路检测)

    def should_check(self, step_no: int, max_steps: int = 0, live_errors: int = -1) -> bool:
        """是否到了巡查发起时机 (Sprint 33 异步事件驱动版).

        发起节奏 (用户 2026-08-03 约束: 上一次注入后 5 步, 整体不过频):
        1. 队列空 (无在途分析 + 无未消费结果) — 堆积上限 1
        2. 首次巡查: 第 first_check 步 (默认 5, 2026-08-05 从 10 提前 — 简单题可能 <10 步解出)
        3. 常规: 上一次注入结果之后 check_interval 步 (默认 5) — 以注入时刻为基准,
           分析延迟几步注入, 下次巡查就顺延几步, 不会叠加堆积
        4. 异常触发: 连续错误步 ≥ max_errors (live_errors 由主循环实时传入, 免去状态滞后)
        5. 步数接近上限: 倒数 early_exit_steps 步内 (检查是否需要扩展)
        """
        if step_no <= 0:
            return False

        with self._lock:
            t = self._analyze_thread
            queue_full = (t is not None and t.is_alive()) or self._pending_guidance is not None
            if queue_full:
                return False

            # 异常触发: 连续错误步 (立即巡查, 快速纠偏)
            errs = live_errors if live_errors >= 0 else self._consecutive_errors
            if errs >= self.max_errors:
                return True

            # 首次巡查
            if step_no >= self.first_check and self._last_fired_step < self.first_check:
                return True

            # 常规: 上一次注入结果之后 check_interval 步
            if self._last_injected_step > 0 and step_no - self._last_injected_step >= self.check_interval:
                return True

            # 步数接近上限 (兜底)
            if max_steps > 0 and step_no >= max_steps - self.early_exit_steps:
                if self._last_fired_step < max_steps - self.early_exit_steps:
                    return True

        return False

    def fire_async_analysis(
        self,
        trajectory: list[dict],
        challenge_type: str = "",
        challenge_difficulty: str = "",
        task_desc: str = "",
        step_no: int = 0,
        max_steps: int = 0,
    ) -> bool:
        """Sprint 33: 异步发起巡查分析 — 后台线程执行, 不阻塞 agent 主循环.

        分析完成后结果存入 _pending_guidance, 由主循环在后续步
        consume_pending_guidance() 事件召回注入 (如第 10 步发起、第 12 步注入).
        队列上限 1: 已有在途分析或未消费结果时不重复发起.
        返回 True = 已发起 (发起步记入 _last_fired_step).
        """
        if len(trajectory) < 3:
            return False
        with self._lock:
            t = self._analyze_thread
            if (t is not None and t.is_alive()) or self._pending_guidance is not None:
                return False
            self._analyze_thread = threading.Thread(
                target=self._async_analyze_worker,
                args=(list(trajectory), challenge_type, challenge_difficulty,
                      task_desc, step_no, max_steps),
                daemon=True,
                name="coordinator-async-analyze",
            )
            self._analyze_thread.start()
            self._last_fired_step = step_no
            self._pending_fired_step = step_no
            return True

    def _async_analyze_worker(
        self,
        trajectory: list[dict],
        challenge_type: str,
        challenge_difficulty: str,
        task_desc: str,
        step_no: int,
        max_steps: int,
    ) -> None:
        """后台分析线程: 复用同步 analyze() 完整逻辑, 结果存入待消费队列."""
        try:
            guidance = self.analyze(
                trajectory,
                challenge_type=challenge_type,
                challenge_difficulty=challenge_difficulty,
                task_desc=task_desc,
                step_no=step_no,
                max_steps=max_steps,
            )
        except Exception as e:  # noqa: BLE001 - 分析异常降级为不干预
            guidance = CoordinatorGuidance(
                should_intervene=False,
                reason=f"L2 LLM 异步分析异常: {e}, 降级为不干预",
                extend_steps=True,
                analysis_summary=f"L2 LLM 异步分析异常: {type(e).__name__}",
            )
        with self._lock:
            self._pending_guidance = guidance
            self._analyze_thread = None

    def consume_pending_guidance(self, current_step: int = 0) -> CoordinatorGuidance | None:
        """Sprint 33: 取走已完成的异步巡查结果 (事件召回, 供主循环注入).

        每次消费即记录注入时刻 (发起节奏基准): 下一次发起 = 本次注入 + check_interval 步.
        返回 None = 无待消费结果.
        """
        with self._lock:
            g = self._pending_guidance
            self._pending_guidance = None
            if g is not None:
                self._last_injected_step = current_step if current_step > 0 else self._last_fired_step
            return g

    # ── Sprint 36 (WING-Corvus): 战略层能力 (与总指挥协作) ──
    # 任务契约 = 总指挥分配的方向性指引, 非强制枷锁; 遇明确死路可自动切换并事后汇报.

    def set_task_contract(self, task_no: int, direction: str, priority: str = "SHOULD") -> None:
        """总指挥注入/更新任务契约 (领题分工或重定向).

        方向性指引, 非强制枷锁: 战略层执行时遇明确死路可自行切换+事后汇报.
        """
        self._task_no = int(task_no or 0)
        self._task_direction = str(direction or "")
        self._task_priority = str(priority or "SHOULD")

    def report_to_commander(self, report_type: str = "clue", content: str = "",
                            level: str = "FACT") -> bool:
        """向总指挥汇报 (clue 重要线索 / dead_end 死路确认 / question 提问).

        只报高置信度 (FACT/LIKELY), 不报每步噪声; 返回是否成功上报.
        """
        if not self._commander_enabled or not content.strip():
            return False
        try:
            self._bus.post_report(
                agent_id=self.style, task_id=self._bus_challenge_id,
                content=content.strip()[:400], report_type=report_type,
                level=level, task_no=self._task_no,
            )
            return True
        except Exception:
            return False

    def report_progress(self, findings: str, next_plan: str = "",
                        stuck: bool = False) -> bool:
        """Sprint 36.2: P1 侦查进度汇报 (每 5 步向总指挥汇报).

        内容含: 当前发现 / 下一步计划 / 是否卡死. 总指挥据此:
        - 判断该路侦查是否完成 (三路全部完成 → 整合全局情报 → P2)
        - 某路长时间无进展时介入调整
        """
        if not self._commander_enabled:
            return False
        parts = [f"侦查进度: {findings.strip()[:250]}"]
        if next_plan:
            parts.append(f"下一步: {next_plan.strip()[:150]}")
        parts.append("是否卡死: " + ("是" if stuck else "否"))
        return self.report_to_commander(
            report_type="progress", content=" | ".join(parts), level="FACT")

    def report_recon_done(self, summary: str = "") -> bool:
        """Sprint 36.2: 汇报该路 P1 侦查完成 (三路全部完成后总指挥整合全局情报 → P2).

        由战略层巡查分析 (LLM 判断该路基础侦查已覆盖题目全貌) 触发;
        summary 为该路侦查成果一句话摘要 (供总指挥全局情报摘要使用).
        """
        if not self._commander_enabled:
            return False
        content = f"P1 侦查完成: {summary.strip()[:300]}" if summary.strip() else "P1 侦查完成"
        return self.report_to_commander(
            report_type="recon_done", content=content, level="FACT")

    def report_verified(self, direction: str = "", evidence: str = "") -> bool:
        """Sprint 36.2: 汇报某方向已验证成功 (证据支撑 + 验证通过) — P2→P3 信号.

        由战略层巡查分析 (LLM 判断该方向已有足够证据支撑并**取得验证**, 非猜测) 触发.
        汇报需**完整**: 方向 + 验证证据, 供总指挥确凿分析后切换 P3.
        """
        if not self._commander_enabled:
            return False
        parts = []
        if direction.strip():
            parts.append(f"已验证方向: {direction.strip()[:150]}")
        if evidence.strip():
            parts.append(f"验证证据: {evidence.strip()[:300]}")
        if not parts:
            return False
        return self.report_to_commander(
            report_type="verified", content=" | ".join(parts), level="FACT")

    def report_flag_solved(self, flag: str) -> bool:
        """Sprint 36.5: 战术层取得 flag 候选时实时上报 — P3→P4 信号.

        由主循环在 Final Answer 提交前调用 (flag 验证通过后). 这是**事实信号**
        (flag 文本本身), 不依赖战略层巡查 LLM 恰好输出 p2_verified —
        从根源解决"agent 已解出但总指挥阶段还停在 P2"的断裂 (nss_2950 复盘).
        总指挥据此: P2→P3 (flag=最强验证证据) → P3→P4 (flag 候选进入验证阶段).
        """
        if not self._commander_enabled or not (flag or "").strip():
            return False
        return self.report_to_commander(
            report_type="flag", content=f"flag 候选: {flag.strip()[:200]}", level="FACT")

    def report_submit_fail(self, flag: str, feedback: str = "") -> bool:
        """Sprint 36.5: 提交失败时实时上报 — P4→P3 回退信号.

        由主循环在 submission 返回失败后调用. 总指挥据此回退 P4→P3
        (设计文档 4.5 存在但此前未实现), 避免阶段停留在"验证提交"而实际已失败.
        """
        if not self._commander_enabled:
            return False
        content = f"提交失败: {flag.strip()[:100]} | 反馈: {feedback.strip()[:200]}"
        return self.report_to_commander(
            report_type="submit_fail", content=content, level="FACT")

    def report_p1_progress_if_due(self, step_no: int, recent_steps: list[dict]) -> bool:
        """Sprint 36.2: P1 阶段每 5 步向总指挥汇报侦查进度 (主循环调用).

        - 仅在 P1 阶段 + 总指挥模式启用时工作 (P2/P3 由巡查汇报 clue/dead_end 替代)
        - 每 5 步一次 (自上次汇报起 <5 步不重复)
        - 内容从最近轨迹提取: 当前发现 (最近 2 步 observation 精华) /
          下一步计划 (最近一步 thought 末尾) / 是否卡死 (连续错误 ≥ max_errors)
        返回是否成功上报.
        """
        if not self._commander_enabled or self._current_phase != "P1":
            return False
        if step_no - self._last_progress_step < 5:
            return False
        self._last_progress_step = step_no

        recent = list(recent_steps or [])[-3:]
        findings: list[str] = []
        for s in recent:
            obs = str(getattr(s, "observation", "") or "").strip()
            if obs and obs not in findings:
                findings.append(obs[:120])
        findings_str = " / ".join(findings[-2:]) if findings else "继续侦查中"
        # 下一步计划: 最近一步 thought 末尾的计划意图 (截断防噪声)
        next_plan = ""
        if recent:
            thought = str(getattr(recent[-1], "thought", "") or "").strip()
            if thought:
                next_plan = thought[-80:]
        # 是否卡死: 连续错误步 ≥ max_errors (规则信号, 供总指挥判断)
        stuck = self._consecutive_errors >= self.max_errors
        return self.report_progress(findings_str, next_plan, stuck)

    def report_dead_end(self, content: str, auto_switch: bool = True) -> str:
        """遇明确死路 (环境缺失/任务方向被事实证否): 自动切换并事后汇报.

        不等待总指挥下次轮询 (任务=方向性指引非强制枷锁);
        返回切换后的新方向 (调用方注入战术层), 总指挥收到 dead_end 后事后校准.
        """
        self.report_to_commander(report_type="dead_end", content=content, level="FACT")
        if auto_switch:
            new_dir = self._default_switch_direction()
            self._task_direction = new_dir
            self._dead_end_switched = True
        return self._task_direction

    def _default_switch_direction(self) -> str:
        """死路后的兜底切换方向 (按风格给不同侧重, 避免全队趋同)."""
        base = {
            "conservative": "转向静态分析: 重新梳理文件结构/符号/关键函数, 寻找不依赖缺失环境的路径",
            "aggressive": "转向黑盒验证: 用现有可执行路径/工具构造输入观察输出, 归纳行为规律",
            "innovative": "转向非常规路径: 符号执行/代数分析/侧信道/线索交叉, 绕开缺失环境",
        }.get(self.style, "切换探索方向, 避免继续依赖缺失环境")
        return f"【死路自救·已自动切换】{base}"

    def check_commander_directives(self) -> CoordinatorGuidance | None:
        """检查总指挥新指令: 收到则更新任务契约并返回注入指导 (MUST 强制优先).

        由主循环每步/巡查时调用; 无新指令返回 None (零开销).

        WING-Corvus 升级 (2026-08-05, nss_2800 复盘): MUST 本地冲突校验 —
        总指挥基于跨 agent 汇报摘要决策, 可能遗漏本 agent 已实证的死路.
        若指令方向与本地已验证死路 (forbidden_actions/精确签名) 冲突:
        - 不盲目强制 (案例: 总指挥 MUST "直接请求 /utils.php", 但本 agent
          已证实该路径返回空/404, 强制执行只会浪费步数)
        - 降级为 SHOULD (本地证据优先) + 事后 dead_end 回报总指挥

        Sprint 36.2: 指令附带 phase (P1/P2/P3/P4) — 更新战略层的阶段感知,
        用于按阶段注入不同巡查任务 (P1 关注侦查完整性 / P2 关注主方向小方向调控 /
        P3 负责死循环与方向调整).
        """
        if not self._commander_enabled:
            return None
        try:
            directives, new_cursor = self._bus.check_directives(
                self._bus_challenge_id, agent_id=self.style, cursor=self._directive_cursor)
            self._directive_cursor = new_cursor
        except Exception:
            return None
        if not directives:
            return None
        # 只取最新一条 (避免过时指令累积注入, 后续指令覆盖先前的)
        d = directives[-1]
        direction = str(d.get("content") or "").strip()
        if not direction:
            return None
        priority = str(d.get("priority") or "SHOULD").upper()
        if priority not in ("MUST", "SHOULD"):
            priority = "SHOULD"
        task_no = int(d.get("task_no") or self._task_no or 0)
        reason = str(d.get("reason") or "")
        # Sprint 36.2: 阶段感知 — 随指令更新当前阶段
        new_phase = str(d.get("phase") or "").strip().upper()
        if new_phase in ("P1", "P2", "P3", "P4"):
            self._current_phase = new_phase

        # ── MUST 本地冲突校验: 与已验证死路冲突 → 降级 SHOULD + 回报 ──
        local_conflict = self._directive_conflicts_local(direction)
        if priority == "MUST" and local_conflict:
            self.report_to_commander(
                report_type="dead_end",
                content=(f"总指挥 MUST 指令与本地已验证死路冲突: "
                         f"{direction[:150]} | 本地证据: {local_conflict[:200]}"),
                level="FACT",
            )
            priority = "SHOULD"
            reason = (f"{reason} | ⚠️ 本地冲突: {local_conflict[:120]} "
                      f"(已降级为 SHOULD, 以本地证据为准, 已回报总指挥)")

        self.set_task_contract(task_no, direction, priority)
        guidance_text = f"[总指挥·任务{task_no}] {direction}"
        if reason:
            guidance_text += f"\n[依据] {reason}"
        return CoordinatorGuidance(
            should_intervene=True,
            guidance=guidance_text,
            reason=f"总指挥重定向 (任务{task_no}): {reason[:100] or '方向校准'}",
            priority=priority,
            analysis_summary=f"[COMMANDER] 方向重定向: 任务{task_no}",
        )

    def _directive_conflicts_local(self, direction: str) -> str:
        """校验总指挥指令方向是否与本地已验证死路冲突.

        返回冲突证据描述 (非空 = 冲突), 空串 = 无冲突放行.
        只检查 FACT 级死路 (forbidden_actions / 精确签名), 不误伤未验证方向.
        """
        if not direction:
            return ""
        combined = direction.lower()
        # 1. 精确签名禁忌 (死循环自动标记, 高置信)
        with self._lock:
            sig_hits = [s for s in self._forbidden_signatures if s and s.split(":", 1)[0].lower() in combined]
            act_hits = [f for f in self._forbidden_actions
                        if any(len(w) > 3 and w in combined for w in f.lower().split())]
        if sig_hits:
            return f"精确签名禁忌命中: {sig_hits[0][:80]}"
        if act_hits:
            return f"禁忌列表命中: {act_hits[0][:80]}"
        return ""

    def on_tool_error(self, tool: str, error: str = "") -> str:
        """工具执行异常上报 (react.py 工具异常时调用, 用于死路检测).

        明确"环境缺失"类错误连续 2 次 → 判定死路, 自动切换 + 事后 dead_end 汇报.
        返回空串 = 正常; 非空 = 死路切换建议 (调用方注入战术层).
        """
        if not self._commander_enabled or not tool:
            return ""
        err = (error or "").lower()
        dead_keywords = (
            "not found", "no such file", "cannot find", "not installed",
            "command not found", "exec format", "no wine", "not available",
            "unavailable", "connection refused", "permission denied",
        )
        if not any(k in err for k in dead_keywords):
            return ""
        self._tool_unavailable[tool] = self._tool_unavailable.get(tool, 0) + 1
        if self._tool_unavailable[tool] < 2:
            return ""  # 单次失败可能是抖动, 连续 2 次才判死路
        content = (f"工具 {tool} 连续 {self._tool_unavailable[tool]} 次不可用 "
                   f"({str(error or '')[:120]}), 当前任务依赖的环境缺失, 已自行切换")
        return self.report_dead_end(content)

    def intercept_forbidden(self, action: str, action_input: str) -> str:
        """Sprint 32.4: 工具执行前拦截禁忌操作 (供 ReAct 引擎调用).

        禁忌列表中的操作 (如"hashcat 爆破 cloud.zip 密码"已被确认无效) 在
        巡查间隔之外也会被拦截, 立即重定向 Agent, 避免继续浪费步数.
        返回拦截提示 (非空 = 应拦截该操作), 空串 = 放行.
        """
        # Sprint 33: 异步事件驱动下禁忌列表由后台分析线程并发更新, 快照读取避免迭代竞争
        with self._lock:
            if not self._forbidden_actions:
                return ""
            forbidden_snapshot = list(self._forbidden_actions)
        combined = f"{action} {action_input}".lower()
        for forbidden in forbidden_snapshot:
            keywords = [w for w in forbidden.lower().split() if len(w) > 3]
            if keywords and any(kw in combined for kw in keywords):
                return (
                    f"⚠️ 拦截: 该操作 '{action}' 已被巡查判定为无效 (禁忌列表: "
                    f"{forbidden[:80]}). 立即停止, 换一个完全不同的方法. "
                    f"请重新输出 Thought + Action + Action Input."
                )
        return ""

    # ── Sprint 36.2: 阶段感知 — 按当前阶段注入不同巡查任务 ──

    def _phase_task_block(self) -> str:
        """按当前阶段 (随总指挥指令更新) 注入巡查侧重 (P1/P2/P3/P4).

        修复 (2026-08-05): 此前该方法的调用已存在但从未定义, 导致 P1 阶段
        巡查分析每次抛 AttributeError → 降级为"不干预" (巡查器形同虚设).
        """
        return {
            "P1": ("P1 侦查阶段: 关注**侦查完整性与进度** — 检查 agent 是否在全面收集"
                   "题目信息 (系统性扫描/快速试探记录响应/非常规信息挖掘), 是否遗漏必查"
                   "信息源 (附件、入口、版本指纹、隐藏线索). **此阶段不深入任何单一方向**,"
                   "重点是广度; 若你判断该路基础侦查已覆盖题目全貌 (完成), 必须汇报"
                   "侦查完成 (recon_done), 三路全部完成后总指挥才整合全局情报进入 P2."),
            "P2": ("P2 漏洞识别阶段: 关注**主方向小方向调控** — 判断 agent 是否在正确"
                   "方向上推进 (保守/激进深入主方向, 创新发散探索可能方向), 是否卡在"
                   "死循环或偏离主方向; **死循环检测与方向调整由你负责**, 总指挥只引导."
                   "若某方向已有**足够证据支撑并取得验证** (非猜测), 必须完整汇报"
                   "验证结果 (p2_verified: 方向+验证证据), 总指挥确凿分析后才切换 P3."),
            "P3": ("P3 利用阶段: 关注**死循环与方向调整** — agent 应在已验证的方向上"
                   "利用漏洞 (激进快速利用/保守严谨利用/创新创造性利用); 卡死与方向调整"
                   "由你负责, 总指挥协调以引导为主."),
            "P4": ("P4 验证阶段: 关注**flag 验证** — 确认候选 flag 来源可靠 (轨迹中有"
                   "确凿证据支撑), 验证通过后再提交."),
        }.get(self._current_phase, self._current_phase or "P1")

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

        Sprint 30 两级分析 (优化触发逻辑):
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

        # Sprint 35: 全局已尝试方向追踪 — 扫描完整轨迹 (非仅 recent 窗口),
        # 记录每个 action 签名的尝试次数和进展状态.
        # 用于检测 lookback 窗口外的死循环重试 (如 step 50 试过的方法 step 80 又试).
        self._update_tried_directions(trajectory)

        # ── L1-A: 确定性问题 (直接干预, 不调 LLM) ──
        hard_issues: list[str] = []
        # Sprint 32.4c: soft_hints 提前定义 — exact_repeat 有进展时降级到此
        soft_hints: list[str] = []

        # 完全重复死循环 (同一工具+相似参数 ≥3 次)
        # Sprint 32.4c: 完全重复但持续有新 observation → 降级为软线索 (交 L2 LLM 判断),
        # 避免对"同脚本模板反复验证不同目标"的系统性逆向误判 (#2516 复盘: agent 反复
        # 用同一 capstone 模板验证不同函数/假设, 实际是严谨的验证性推进)
        exact_repeat = self._check_exact_repeats(recent)
        if exact_repeat:
            if self._has_progress(recent):
                soft_hints.append(exact_repeat + " (但持续有新发现, 需 LLM 判断是否思路固化)")
            else:
                hard_issues.append(exact_repeat)
                # Sprint 35: 死循环时自动将重复操作加入禁忌列表 (所有风格)
                # 防止 MUST 被忽略后 agent 继续重复同一操作
                self._auto_add_forbidden(recent)

        # Sprint 36.5: 意图级重复 — 相同工具+相同思路连续重复 (参数微调但本质固化).
        # 补 _check_exact_repeats 盲区: 后者要求 action_input 相似, 思路重复捕获不到
        # (复盘: aggressive 连续 4 步"分析 ELF .data 段查找 flag 和随机数"未被干预)
        repetitive_intent = self._check_repetitive_intent(recent)
        if repetitive_intent:
            if self._has_progress(recent):
                soft_hints.append(repetitive_intent + " (但持续有新发现, 需 LLM 判断是否思路固化)")
            else:
                hard_issues.append(repetitive_intent)
                self._auto_add_forbidden(recent)

        # Sprint 35: 全局死循环检测 — 跨 lookback 窗口的重复 (如 step 50 试过 step 80 又试)
        global_repeat = self._check_tried_directions(recent)
        if global_repeat:
            hard_issues.append(global_repeat)
            self._auto_add_forbidden(recent)

        # 明显方向错误 (题型完全不匹配) — Sprint 36.1: 降级为软线索.
        # "方向存疑"只是启发式提示 (题型工具集映射不精确, 跨题型操作常见),
        # 无充分证据禁止否定方向 → 交 L2 LLM 结合完整轨迹/知识库判断, 不直接 MUST.
        direction_issue = self._check_direction(recent, challenge_type)
        if direction_issue:
            soft_hints.append(direction_issue)

        # Sprint 31: 禁忌操作检测 (agent 在尝试已确认无效的操作)
        forbidden_hit = self._check_forbidden_actions(recent)
        if forbidden_hit:
            hard_issues.append(forbidden_hit)

        # Sprint 32.4: MUST 指令未被执行 — 上次 MUST 指导后 agent 行为未改变
        # (分析 #2501: 协调器 step10 下达 MUST 但 agent 忽略, 继续 MD5 爆破 20 步)
        must_ignored = self._check_must_noncompliance(recent)
        if must_ignored:
            hard_issues.append(must_ignored)

        # Sprint 36 复盘: 分析瘫痪 — 长时间无执行类工具 (只读源码/解析数据/静态分析)
        execution_starvation = self._check_execution_starvation(recent, step_no)
        if execution_starvation:
            hard_issues.append(execution_starvation)

        if hard_issues:
            guidance = self._build_rule_guidance(hard_issues, challenge_type)
            self._last_guidance = guidance
            self._last_guidance_step = step_no
            self._last_guidance_action = self._dominant_action(recent)
            self._last_guidance_priority = "MUST"  # Sprint 32.4: 记录优先级
            self._error_since_last_check = 0  # 巡查后重置
            return CoordinatorGuidance(
                should_intervene=True,
                priority="MUST",  # Sprint 31: 确定性问题必须执行
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

        # Sprint 36.5: 交互回显型程序纠偏 — 深陷静态分析但程序实为"运行+回显"型.
        # 软线索交 L2 LLM 结合完整轨迹判断 (避免误伤真正的逆向题).
        interactive_program = self._check_interactive_program(recent, task_desc)
        if interactive_program:
            soft_hints.append(interactive_program)

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
            # Sprint 31: 同步禁忌列表到返回值
            result.forbidden_actions = list(self._forbidden_actions)
            return result

        # 无 LLM 时: L1-B 软线索也作为干预依据 (降级模式)
        if soft_hints:
            guidance = self._build_rule_guidance(soft_hints, challenge_type)
            self._last_guidance = guidance
            self._last_guidance_step = step_no
            self._last_guidance_priority = "SHOULD"  # Sprint 32.4
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
        # Sprint 32: 也检查步数接近上限 (与 L2 路径一致)
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

    @staticmethod
    def _norm_intent(text: str) -> str:
        """归一化意图文本 (去数字/路径/地址/标点), 用于识别"思路重复但参数不同"的死循环."""
        t = (text or "").lower()
        t = re.sub(r"\d+", "N", t)
        t = re.sub(r"/tmp/[^ \"']+", "P", t)
        t = re.sub(r"0x[0-9a-f]+", "A", t)
        t = re.sub(r"[^a-z\u4e00-\u9fff]+", " ", t)
        return " ".join(t.split())[:80]

    def _check_repetitive_intent(self, recent: list[dict]) -> str:
        """Sprint 36.5: 意图级重复检测 — 相同工具 + 相似思路连续重复.

        与 _check_exact_repeats 互补: 后者要求 action_input 相似, 而 agent 每次
        thought 微调/参数不同时签名不同, 不会被捕获. 这里归一化 thought 后比较,
        连续 ≥max_repeats+1 步同一 action + 同一意图 = 思路固化死循环
        (如反复"分析 .data 段查找 flag 和随机数"). 有实质进展时由调用方降级软线索.
        """
        if len(recent) < self.max_repeats + 1:
            return ""
        streak = 0
        last_key = None
        for step in recent:
            action = (step.get("action") or "").strip()
            if not action:
                streak = 0
                last_key = None
                continue
            key = f"{action}:{self._norm_intent(step.get('thought') or '')}"
            if key == last_key:
                streak += 1
            else:
                streak = 1
                last_key = key
            if streak >= self.max_repeats + 1:
                intent = key.split(":", 1)[1][:40]
                return (f"意图重复: 同一工具 [{action}] 连续 {streak} 步思路相同 "
                        f"'{intent}' (思路固化, 参数虽不同但本质在重复同一件事)")
        return ""

    def _check_interactive_program(self, recent: list[dict], task_desc: str) -> str:
        """Sprint 36.5: 交互回显型程序纠偏 — 深陷静态分析而程序实为"交互回显"时给方向提示.

        特征: 程序输出 base64 自包含程序 / 要求用户猜数字 / "Tell me what the number" /
        随机数回显. 正解常为: 运行提取的程序 → 取输出 (如随机数) → 回显给远程.
        当 agent 连续用静态分析 (objdump/readelf/strings/binary_analyze) 而观测含
        上述交互特征时, 产出软线索交 L2 LLM 判断 (避免误伤真正的逆向题).
        """
        blob = task_desc + " " + " ".join(
            str(s.get("observation") or "") for s in recent[-3:]
        )
        low = blob.lower()
        interactive = any(k in low for k in (
            "guess the number", "random number", "random num", "随机数", "猜数字",
            "my mind", "my brain", "tell me what the number", "回显", "菜单",
            "what the number is", "think of a number",
        ))
        if not interactive:
            return ""
        static_actions = 0
        for s in recent[-5:]:
            a = (s.get("action") or "").lower()
            if "exec" in a or "analyze" in a or "objdump" in a or "readelf" in a or "strings" in a:
                static_actions += 1
        if static_actions >= 3:
            return ("交互回显型程序特征: 观测含猜数字/随机数回显/菜单等交互信号, 而你近期连续"
                    "静态分析. 这类题正解常为: 运行提取的程序/二进制, 读取其完整输出 "
                    "(如随机数/提示), 并把该输出回显给远程 (sendline), 而非漏洞利用.")
        return ""

    @staticmethod
    def _action_signature(step: dict) -> str:
        """归一化 action 签名 (action + action_input 前 100 字符, 路径归一化)."""
        action = (step.get("action") or "").strip()
        action_input = (step.get("action_input") or "").strip()[:100]
        norm_input = re.sub(r"/tmp/[^ /\"]+", "/tmp/X", action_input)
        return f"{action}:{norm_input}"

    def _update_tried_directions(self, trajectory: list[dict]) -> None:
        """Sprint 35: 扫描完整轨迹, 更新全局已尝试方向记录.

        记录每个 action 签名的尝试次数、是否有进展 (不同 observation)、最后步号.
        用于检测 lookback 窗口外的死循环重试.

        注意: count 是轨迹中的绝对出现次数 (非累积), 每次调用重新统计.
        """
        from collections import Counter
        # 统计每个签名的绝对出现次数
        sig_counts: Counter[str] = Counter()
        sig_last_step: dict[str, int] = {}
        obs_per_sig: dict[str, set[str]] = {}
        for step in trajectory:
            sig = self._action_signature(step)
            if not sig or sig == ":":
                continue
            sig_counts[sig] += 1
            sig_last_step[sig] = step.get("step_no", sig_last_step.get(sig, 0))
            # 收集 observation 多样性
            if not step.get("is_error"):
                obs = str(step.get("observation") or "").strip()[:100]
                if obs and obs.lower() not in ("(no observation)", "none", "无"):
                    obs_per_sig.setdefault(sig, set()).add(obs)
        # 更新 _tried_directions (设定绝对值, 非递增)
        for sig, count in sig_counts.items():
            entry = self._tried_directions.setdefault(sig, {
                "count": 0, "has_progress": False, "last_step": 0,
            })
            entry["count"] = count
            entry["last_step"] = sig_last_step.get(sig, 0)
        # 更新 has_progress: ≥2 种不同 observation = 有进展
        for sig, obs_set in obs_per_sig.items():
            if len(obs_set) >= 2:
                self._tried_directions[sig]["has_progress"] = True

    def _check_tried_directions(self, recent: list[dict]) -> str:
        """Sprint 35: 检测 agent 是否在重试全局已记录的失败方向.

        判定: recent 中的 action 签名在 _tried_directions 中:
        - 尝试次数 ≥ max_repeats * 2 (跨多轮巡查仍重复)
        - 且无实质进展 (has_progress=False)
        → 返回干预指令, 适用于所有风格.
        """
        threshold = self.max_repeats * 2  # 默认 6 次, 比单窗口检测更宽松
        for step in recent[-3:]:  # 只检查最近 3 步
            sig = self._action_signature(step)
            if not sig or sig == ":":
                continue
            entry = self._tried_directions.get(sig)
            if not entry:
                continue
            if entry["count"] >= threshold and not entry["has_progress"]:
                return (
                    f"全局死循环: 操作 '{sig[:80]}' 已在整个轨迹中重复 "
                    f"{entry['count']} 次且无实质进展, 必须切换到完全不同的方向."
                )
        return ""

    def _auto_add_forbidden(self, recent: list[dict]) -> None:
        """Sprint 35: 死循环检测时自动将重复操作加入禁忌列表.

        只加入 _forbidden_signatures (精确签名匹配), 不加入 _forbidden_actions
        (关键词匹配), 避免共同路径/工具名等关键词误伤不同命令.

        适用于所有风格 — 即使创新风格也不能重复已确认无效的方向.
        这是避免死循环的核心路径: 标记 → 限制 → 强制切换.
        """
        from collections import Counter
        signatures: list[str] = []
        for step in recent:
            sig = self._action_signature(step)
            if sig and sig != ":":
                signatures.append(sig)
        if not signatures:
            return
        counter = Counter(signatures)
        for sig, count in counter.most_common(2):  # 取重复最多的 2 个
            if count >= self.max_repeats:
                # 精确签名: 拦截完全相同的操作 (action + action_input 前 100 字符)
                self._forbidden_signatures.add(sig)

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

    def _check_execution_starvation(self, recent: list[dict], step_no: int) -> str:
        """Sprint 36: 分析瘫痪检测 — 长时间无执行类工具调用 (L1-A 确定性).

        复盘根因 (linx/threshold/faulty_mayo 三题 hard 全败):
          - threshold: "攻击思路停留在重复描述, 尚未真正落地实现 LLL 攻击代码"
          - faulty_mayo: "纯静态逆向分析, 尚未连接靶机验证攻击"
          - linx: 直到 step 35-37 才意识到进入攻击, 随后超时
        共同模式: agent 在"理解/读源码/解析数据"阶段无限滞留, 从不执行攻击脚本.

        判定: 总步数 ≥ execution_starvation_min_steps (默认 20, 前期信息收集合理),
        且最近 8 步内无任何执行类工具 (ssh_exec/ssh_python/docker_exec/http_request 等).
        """
        if step_no < self.execution_starvation_min_steps:
            return ""
        window = recent[-8:]
        if not window:
            return ""
        if any((s.get("action") or "") in _EXECUTION_TOOLS for s in window):
            return ""
        return (
            f"分析瘫痪: 最近 {len(window)} 步未调用任何执行类工具 "
            f"(ssh_exec/ssh_python/docker_exec/docker_python/http_request 等), "
            f"仅停留在读源码/解析数据/静态分析, 未推进到攻击实施. "
            f"立即写一个最小攻击脚本并运行验证: 用 ssh_exec 执行关键命令 或 "
            f"ssh_python 跑一段验证代码, 用真实输出推进 (不要继续纯分析)."
        )

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
        """Sprint 30: 检查上次指导后 agent 是否改变了行为.

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
        """Sprint 32.4: 检测 MUST 指令未被执行 (硬问题, 直接干预).

        背景 (#2501 Blast 复盘): 协调器 step10 下达 MUST 指令
        ("停止单字符 MD5 爆破"), 但 agent 忽略, 继续 MD5 穷举 20 步.
        旧逻辑只把"指导持久性"作为软线索传给 L2 LLM, LLM 可能继续沉默,
        导致 MUST 指令形同虚设.

        规则: 上次干预是 MUST 且 agent 主导工具未改变 → 升级为 MUST 阻断:
        - 已过 ≥1 个巡查间隔仍未改变 = MUST 未执行, 直接干预
        - 同时把上次指导追加为禁忌操作 (agent 再试同类操作立即拦截)

        Sprint 32.4c 自我纠错: 主导工具未变**且无任何实质进展**才算未执行.
        若 agent 持续产生新 observation (在推进), 即使工具未变也视为有效推进,
        交由 L2 LLM 全局判断方向正确性 (#2516 复盘: agent 深挖调用链逐步
        突破 XOR→6-bit 编码逻辑, 但被机械判定为 MUST 未执行, 属误判).
        """
        if not self._last_guidance or self._last_guidance_step <= 0:
            return ""
        if self._last_guidance_priority != "MUST":
            return ""
        # Sprint 35.1 修复: 空 action (格式解析失败/missing fields) 不能视为"工具已改变".
        # 旧逻辑: _dominant_action 对全空 action 返回 "", 与 _last_guidance_action (非空)
        # 不相等 → 判定"工具已改变, 指导已执行" → MUST 未执行检测被绕过.
        # 实际: agent 连续格式崩溃 (空输出) = 完全没有执行指导, 反而更严重.
        # 连续 ≥2 个空 action = 格式崩溃, 直接视为 MUST 未执行 (升级干预).
        empty_actions = [s for s in recent if not (s.get("action") or "").strip()]
        if len(empty_actions) >= 2:
            steps_since = self._last_check_step - self._last_guidance_step
            if steps_since >= 1:  # 至少过 1 步就干预, 不等完整间隔
                return (
                    f"MUST 指令未被执行: step {self._last_guidance_step} 下达 [MUST] 指导后, "
                    f"已过 {steps_since} 步出现 {len(empty_actions)} 次格式解析失败/空输出 "
                    f"(action 为空), 指导完全未执行. "
                    f"上次指导: {self._last_guidance[:120]}"
                )
        current_dominant = self._dominant_action(recent)
        if not self._last_guidance_action or current_dominant != self._last_guidance_action:
            return ""  # 主导工具已改变, 视为执行了指导
        steps_since = self._last_check_step - self._last_guidance_step
        if steps_since < self.check_interval:
            return ""  # 间隔太短, 可能正在切换中
        # Sprint 32.4c: 主导工具未变但持续有实质进展 → 不判未执行
        if self._has_progress_after_guidance(recent):
            return ""
        # 主导工具未变且已过一个间隔且无进展 → MUST 未执行
        return (
            f"MUST 指令未被执行: step {self._last_guidance_step} 下达 [MUST] 指导后, "
            f"已过 {steps_since} 步仍在使用 '{current_dominant}' 且无实质进展. "
            f"上次指导: {self._last_guidance[:120]}"
        )

    def _has_progress(self, recent: list[dict]) -> bool:
        """Sprint 32.4c: 最近轨迹是否有实质进展.

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
        """Sprint 32.4c: 指导后的轨迹是否有实质进展.

        判定: 指导后存在 ≥2 种不同的非空 observation (新发现/新输出).
        单一重复 observation = 死循环, 不是进展.

        修复 (#2520 dantes innovative 死循环): 旧逻辑只检查 observation 非空,
        agent 重复同一命令产生相同 observation 也被判为"有进展",
        导致 MUST 未执行检测失效, agent 在死循环中运行 60+ 步.
        """
        post_obs_set: set[str] = set()
        for step in recent:
            if step.get("is_error"):
                continue
            obs = str(step.get("observation") or "").strip()[:100]
            # 空观察 / 占位观察不算进展
            if obs and obs.lower() not in ("(no observation)", "none", "无"):
                post_obs_set.add(obs)
        # ≥2 种不同 observation 才算实质进展
        return len(post_obs_set) >= 2

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
        """Sprint 31: 检测 agent 是否在尝试禁忌列表中的操作.

        禁忌列表由 LLM 分析时生成 (如"hashcat 爆破 cloud.zip 密码"连续失败后).
        如果 agent 仍在尝试同类操作, 立即干预 (priority=MUST).

        Sprint 35: 增加精确签名匹配 (_forbidden_signatures),
        用于拦截死循环自动添加的精确 action 签名, 避免关键词误伤.
        """
        # Sprint 35: 精确签名匹配 (优先于关键词匹配, 避免误伤)
        if self._forbidden_signatures:
            for step in recent[-3:]:
                sig = self._action_signature(step)
                if sig in self._forbidden_signatures:
                    return (
                        f"禁忌操作: agent 在尝试已确认无效的精确操作 '{sig[:60]}' "
                        f"(死循环自动标记, 必须切换到完全不同的方向)"
                    )
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

        判定: 最近 N 步的操作集合与题型期望工具集完全不相交.
        这是确定性方向错误, 直接干预不调 LLM.

        Sprint 36.1 强化 (nss_2800 复盘): 收紧否定门槛 — 无充分证据禁止否定方向.
        - 旧: 最近 5 步完全不相交即判定方向错误 (web 题 agent 前几步做信息收集时
          可能未出现题型工具, 5 步窗口过窄易误判; 创新风格发散探索也常"看似无关").
        - 新: 最近 8 步完全不相交且 **最近 8 步内无任何题型相关工具** 才判定;
          同时要求 recent 步数足够 (≥6 步), 避免开局空窗期误判.
        - 判定结果只作为 SHOULD 级提示 (不直接 MUST), 因题型工具集是启发式映射,
          跨题型操作 (crypto_reverse 等) 可能被误判.
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

        window = recent[-8:]
        if len(recent) < 6:  # Sprint 36.1: 步数不足不判定 (开局空窗期)
            return ""
        window_actions = set()
        for step in window:
            action = (step.get("action") or "").strip()
            if action:
                window_actions.add(action)

        if window_actions and window_actions.isdisjoint(expected):
            return (f"方向存疑: 最近 {len(window)} 步操作 {window_actions} 与题型 "
                    f"{challenge_type} 期望工具集完全不相交 (可能方向偏离, "
                    f"建议对照题目类型重新审视; 若属跨题型操作请说明理由继续)")
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
                # Sprint 32.4: 未知硬问题兜底 — 强制切换方向
                parts.append(
                    "  [MUST][强制] 检测到确定性问题, 必须立即改变当前操作方式: "
                    "停止重复当前思路, 换一个完全不同的工具或分析方法."
                )
        # Sprint 36: 协作义务 — 巡查干预时同时提醒发布关键线索到共享总线.
        # 战术层专注解题, 但已验证的关键事实 (常量/偏移/算法/死路) 必须回流共享池,
        # 供战略层汇总与其他解题器参考, 避免"各自独立解题、共享仅互相借鉴".
        parts.append(
            "  [协作义务] 若你最近已确认了可供兄弟解题器直接复用的关键线索 "
            "(加密算法与 key/偏移、flag 格式、可复现的绕过方法、已确认的死路), "
            "请在本步之后用 share_finding 工具发布到共享总线 (kind=fact/finding). "
            "若已发布过或暂无新线索, 忽略本条."
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

        Sprint 30: 始终触发 (不再依赖 L1 无问题), 传入 L1 软线索供 LLM 参考.
        LLM 能区分"工具过度使用但方向正确"和"真正的思路固化", 避免误判.
        """
        try:
            # 1. 查询知识库 (Skill + RAG) — Sprint 36.2: 基于轨迹实际观测匹配,
            #    不再基于 task_desc (极简题面匹配会命中无关套路, 造成题目混淆,
            #    如 ouroboros 匹配到 MPEG 题). 经验匹配须在侦查产生观测后进行.
            knowledge_context = self._query_knowledge(
                task_desc, challenge_type, trajectory=trajectory
            )

            # 2. 构造轨迹摘要 (压缩, 避免 token 爆炸)
            trajectory_summary = self._summarize_trajectory(trajectory)

            # 3. 构造 L1 线索文本
            if soft_hints:
                l1_hints = "\n".join(f"- {h}" for h in soft_hints)
            else:
                l1_hints = "(L1 规则预检未发现线索, 方向和重复性均正常)"

            # Sprint 31: 构造当前禁忌列表文本
            if self._forbidden_actions:
                forbidden_text = "\n".join(f"- {f}" for f in self._forbidden_actions)
            else:
                forbidden_text = "(无, 还没有确认无效的操作)"

            # Sprint 32.4c: 构造上次指导区块 (供 LLM 自我纠错)
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

            # Sprint 32.6: 构造推论状态区块 (供 LLM 回顾更新)
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
            phase_task_block = self._phase_task_block()
            user_prompt = _COORDINATOR_USER_TEMPLATE.format(
                task_desc=task_desc[:500] if task_desc else "(未提供)",
                challenge_type=challenge_type or "(未知)",
                challenge_difficulty=challenge_difficulty or "(未知)",
                step_no=step_no,
                max_steps=max_steps or "(自适应)",
                phase_task_block=phase_task_block,
                belief_state_block=belief_block,
                l1_hints=l1_hints,
                forbidden_actions=forbidden_text,
                last_guidance_block=last_block,
                knowledge_context=knowledge_context,
                trajectory_summary=trajectory_summary,
            )

            # 5. 调用 LLM (温度按风格: 保守/激进 0.0, 创新 0.4 — 第 8.3 节)
            from ctf_agent.llm import Message
            system_prompt = _COORDINATOR_SYSTEM_PROMPT
            style_section = _STYLE_COORDINATOR_SECTIONS.get(self.style)
            if style_section:
                system_prompt += style_section
            messages = [
                Message(role="system", content=system_prompt),
                Message(role="user", content=user_prompt),
            ]
            chat_result = self.llm.chat(messages, temperature=self._temperature)
            response = chat_result.content.strip()

            # 6. 解析 LLM 输出 (JSON) — Sprint 32.6: 优先匹配含 belief_state 的完整 JSON
            json_match = re.search(r'\{.*\}', response, re.DOTALL)

            if json_match:
                try:
                    result = json.loads(json_match.group())
                    # Sprint 32.6: 更新推论状态 (跨巡查持久化)
                    new_beliefs = result.get("belief_state", [])
                    if isinstance(new_beliefs, list) and new_beliefs:
                        self._belief_state = [
                            {
                                "id": str(b.get("id", f"B{i+1}")),
                                "statement": str(b.get("statement", "")),
                                "level": str(b.get("level", "POSSIBLE")).upper(),
                                "evidence": str(b.get("evidence", "")),
                                # Sprint 32.7: 透传 action (keep/upgrade/downgrade/disprove/new) 供日志显示
                                "action": str(b.get("action", "")),
                            }
                            for i, b in enumerate(new_beliefs)
                            if isinstance(b, dict)
                        ]
                    # Sprint 32.7: 解析 reflection (巡查器反思过程, 供调用器日志显示)
                    reflection = str(result.get("reflection", "")).strip()
                    # 自动清理 DISPROVED 推论对应的禁忌项
                    # (Sprint 33: 后台线程与主线程 intercept_forbidden 并发, 变更需加锁)
                    with self._lock:
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
                    # WING-Goose 第 8.3 节: 创新模式灵感板 (无论是否干预必产 2-3 条)
                    creative_hints = result.get("creative_hints", [])
                    if isinstance(creative_hints, list):
                        creative_hints = [str(h).strip() for h in creative_hints if str(h).strip()][:3]
                    else:
                        creative_hints = []
                    # Sprint 34: 战略深化 — 非创新风格的"下一步战略方向" (仅干预时随 guidance 注入)
                    strategic_direction = result.get("strategic_direction", "").strip()
                    # Sprint 36.2 (WING-Corvus P1): P1 侦查完成判断 —
                    # LLM 判断该路基础侦查已覆盖题目全貌 → 向总指挥汇报 recon_done.
                    # 总指挥三路全部收到 recon_done 后才整合全局情报摘要并确定主方向 → P2.
                    if result.get("p1_done") and self._current_phase == "P1":
                        self.report_recon_done(
                            summary=result.get("p1_done_summary", "") or summary)
                    # Sprint 36.2 (WING-Corvus P2): 方向验证信号 —
                    # P2 阶段 LLM 判断某方向已有足够证据支撑并**取得验证** (非猜测)
                    # → 汇报 verified (完整: 方向+验证证据). 总指挥据此确凿分析后切换 P3.
                    if result.get("p2_verified") and self._current_phase == "P2":
                        self.report_verified(
                            direction=result.get("p2_verified_direction", "") or "",
                            evidence=result.get("p2_verified_evidence", "") or "",
                        )
                    # Sprint 31: 解析 priority 和 forbidden_actions
                    priority = result.get("priority", "SHOULD").strip().upper()
                    if priority not in ("MUST", "SHOULD"):
                        priority = "SHOULD"
                    new_forbidden = result.get("forbidden_actions", [])
                    if isinstance(new_forbidden, list):
                        # 合并新禁忌项 (去重)
                        with self._lock:
                            for f in new_forbidden:
                                f = str(f).strip()
                                if f and f not in self._forbidden_actions:
                                    self._forbidden_actions.append(f)

                    # Sprint 32.4c: 自我纠错 — 解析撤销/移除禁忌
                    revert = bool(result.get("revert_guidance", False))
                    remove_list = result.get("remove_forbidden", [])
                    if isinstance(remove_list, list):
                        with self._lock:
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
                            # Sprint 32.7: 透传推论分级 + 反思 (供调用器完整日志)
                            reflection=reflection,
                            belief_state=[dict(b) for b in self._belief_state],
                            # WING-Goose 8.3: 创新模式灵感板 (沉默时也必产 hints)
                            creative_hints=creative_hints,
                            # Sprint 34: 沉默原则 — 方向未偏移不注入任何内容 (含战略方向)
                            strategic_direction="",
                        )

                    # 干预: 更新指导持久性属性
                    self._last_guidance = guidance
                    self._last_guidance_step = step_no
                    self._last_guidance_priority = priority  # Sprint 32.4
                    self._last_guidance_action = self._dominant_action(
                        trajectory[-self.lookback:] if len(trajectory) >= self.lookback else trajectory
                    )
                    return CoordinatorGuidance(
                        should_intervene=True,
                        guidance=guidance,
                        reason=reason,
                        # Sprint 32: 干预时也检查步数接近上限自动扩展 (之前只在沉默时检查, 导致 never triggered)
                        extend_steps=extend or (step_no >= max_steps - self.early_exit_steps if max_steps > 0 else False),
                        analysis_summary=summary,
                        priority=priority,
                        forbidden_actions=list(self._forbidden_actions),
                        revert_guidance=revert,
                        remove_forbidden=list(result.get("_remove_forbidden", [])),
                        # Sprint 32.7: 透传推论分级 + 反思 (供调用器完整日志)
                        reflection=reflection,
                        belief_state=[dict(b) for b in self._belief_state],
                        # WING-Goose 8.3: 创新模式灵感板
                        creative_hints=creative_hints,
                        # Sprint 34: 战略深化 — 下一步方向 (非创新风格, 随 guidance 注入)
                        strategic_direction=strategic_direction,
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

    def _query_knowledge(self, task_desc: str, challenge_type: str,
                         trajectory: list[dict] | None = None) -> str:
        """查询知识库 (Skill + RAG) 辅助判断.

        直接调用底层 API, 不用 RAGRetriever (避免 HyDE 的额外 LLM 调用,
        巡查器场景已有查询文本, 直接语义检索即可, 省 token + 低延迟).

        Sprint 36.2 (题目混淆修复): 匹配文本从 task_desc 改为**轨迹实际观测**
        (observation 累积), 避免极简题面命中无关套路 (如 ouroboros 匹配到
        MPEG 题). 仅当轨迹为空 (首次巡查无观测) 时才退化用 task_desc.
        """
        # 构造匹配文本: 优先用轨迹观测 (最近若干步的实际输出), 而非题面
        if trajectory:
            obs_parts: list[str] = []
            for t in trajectory[-6:]:
                obs = (t.get("observation") or "").strip()
                if obs:
                    obs_parts.append(obs[:400])
            match_text = "\n".join(obs_parts) if obs_parts else task_desc
        else:
            match_text = task_desc
        # 截断控制长度 (防超长)
        match_text = match_text[:1500]

        parts: list[str] = []

        # 1. 查询 Skill 库 (基于套路的解题套路)
        if self.skill_library is not None:
            try:
                skill_hint = self.skill_library.format_for_prompt(
                    match_text, category=challenge_type, top_k=2
                )
                if skill_hint:
                    parts.append("### 匹配的 Skill:\n" + skill_hint[:800])
            except Exception:
                pass

        # 2. 查询 RAG (长期记忆: 历史 writeup)
        # 直接用 long_term.search, 不走 RAGRetriever (避免 HyDE LLM 调用)
        if self.long_term is not None:
            try:
                docs = self.long_term.search(match_text, n_results=2)
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

        # 3. 查询经验库 (skill_library.json: 抽象解题方法 + 禁忌)
        # 巡查器基于经验库的 recon_steps 判断方向, 基于 notes (禁忌) 纠正错误
        # 匹配只用 keywords + recon_signatures (结构签名), 不含具体 IP/端口
        # confidence 规则: 仅 high 经验可触发 [MUST] 纠正, medium/low 仅作参考
        if self.experience_library is not None:
            try:
                exp_skills = self.experience_library.retrieve_for_task(
                    match_text, challenge_type, "", top_k=2
                )
                if exp_skills:
                    exp_lines: list[str] = []
                    for skill in exp_skills:
                        conf = skill.effective_confidence
                        exp_lines.append(f"【{skill.vuln_class}】[confidence: {conf}]")
                        if skill.recon_steps:
                            for i, step in enumerate(skill.recon_steps[:4], 1):
                                exp_lines.append(f"  {i}. {step}")
                        if skill.notes:
                            exp_lines.append("  ⚠️ 禁忌:")
                            for note in skill.notes[:3]:
                                exp_lines.append(f"    - {note}")
                    exp_lines.append(
                        "\n(规则: 仅 confidence=high 的经验禁忌可触发 [MUST] 纠正, "
                        "medium/low 仅作参考提示)"
                    )
                    parts.append("### 经验库参考 (解题方向+禁忌):\n" + "\n".join(exp_lines))
            except Exception:
                pass

        # 4. WING KB 战略层参考 (题型分工指南 + 外部包主题 + 抽象经验)
        # 按当前阶段注入 role_guide 段落 + patterns, 供巡查器判断方向/纠正
        if self.knowledge_base is not None:
            try:
                from ctf_agent.knowledge import infer_phase
                kb_phase = infer_phase(trajectory or [], 60)
                kb_hint = self.knowledge_base.retrieve(
                    task=task_desc,
                    challenge_type=challenge_type,
                    role="strategy",
                    style=self.style,
                    phase=kb_phase,
                    max_chars=2500,
                )
                if kb_hint:
                    parts.append(f"### 知识库参考 (阶段 {kb_phase}):\n{kb_hint}")
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
