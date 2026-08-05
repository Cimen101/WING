# WING-Corvus（渡鸦）设计与使用文档

> **文档性质**：CTF 自动化解题系统 WING-Corvus 的完整设计文档 + 使用指南
> **版本**：WING-Corvus（协作小队 Coordinated Squad）
> **最后更新**：2026-08-05
> **上游版本**：WING-Goose（雁阵，含 swarm 三风格并行 / 总线 / 复盘 / docker 链）
> **代码位置**：`_publish/wing/WING-Corvus/`（含 `ctf_agent/` 源码、`main.py`、`pyproject.toml`、`.env.example`）
> **编写方式**：本文档基于对 WING-Corvus 源码的实际逐行审计撰写，所有描述与实现一致，未编造任何代码中不存在的功能。

---

## 目录

1. [项目概述与设计目标](#1-项目概述与设计目标)
2. [设计原则](#2-设计原则)
3. [总体架构：三层协作小队](#3-总体架构三层协作小队)
4. [核心模块：总指挥 Commander](#4-核心模块总指挥-commander)
5. [核心模块：战略层 Coordinator（巡查指导器）](#5-核心模块战略层-coordinator巡查指导器)
6. [核心模块：战术层 ReAct 主循环](#6-核心模块战术层-react-主循环)
7. [核心模块：swarm 编排与总指挥生命周期](#7-核心模块swarm-编排与总指挥生命周期)
8. [核心模块：Flag 验证系统（反幻觉）](#8-核心模块flag-验证系统反幻觉)
9. [多阶段协调详解（P1-P4）](#9-多阶段协调详解p1-p4)
10. [版本演进：相对 WING-Goose 的更新](#10-版本演进相对-wing-goose-的更新)
11. [消息总线设计](#11-消息总线设计)
12. [记忆层与知识体系](#12-记忆层与知识体系)
13. [工具层设计](#13-工具层设计)
14. [LLM 路由与容错](#14-llm-路由与容错)
15. [熔断机制](#15-熔断机制)
16. [轨迹复盘与自学习](#16-轨迹复盘与自学习)
17. [数据设计](#17-数据设计)
18. [部署与运维](#18-部署与运维)
19. [安全与伦理](#19-安全与伦理)
20. [使用方法](#20-使用方法)
21. [常见问题排查](#21-常见问题排查)
22. [附录](#22-附录)

---

## 1. 项目概述与设计目标

### 1.1 项目目标

WING-Corvus（渡鸦）是 WING 系列 CTF 自动化解题智能体的**第三代版本**。它继承了 WING-Falcon（猎隼）的单 agent 核心引擎与 WING-Goose（雁阵）的多 agent 并行编排能力，并将其升级为**协作小队（Coordinated Squad）**形态：

> 在只有正常比赛题目描述的情况下，由一名**总指挥（Commander）**、三名**战略层巡查指导器（Coordinator）**、三名**战术层主 LLM（ReAct Agent）**组成的"指挥-参谋-执行"三层团队，**全自主、多阶段、协同地**完成 CTF 题目求解——从信息收集、漏洞识别、攻击构造到 flag 验证提交，全程无需人工干预。

### 1.2 项目定位

| 维度 | 定位 |
|------|------|
| 角色 | CTF 比赛自动解题智能体，非辅助工具 |
| 形态 | 多 agent 协作小队（3+3+1），非单 agent |
| 自主性 | 全自主决策，全程无需人工干预 |
| 通用性 | 全题型覆盖（Web/Pwn/Crypto/Reverse/Misc/Forensics/OSINT） |
| 协作模式 | 三层架构 + 多阶段协调（P1 侦查 / P2 漏洞识别 / P3 利用 / P4 验证） |
| 可集成性 | 通过标准化 JSONL 子进程协议 + FileBus 跨进程总线对外暴露 |

### 1.3 版本谱系

| 版本 | 代号 | 核心能力 |
|------|------|----------|
| WING-Falcon | 猎隼 | 单 agent 核心引擎：ReAct + 记忆 + Skill + 熔断 + 工具链 |
| WING-Goose | 雁阵 | 同题 N 子进程并行（三风格）、兄弟发现总线、复盘自学习、docker 执行链 |
| **WING-Corvus** | **渡鸦** | **协作小队：总指挥 + 战略层 + 战术层三层架构 + 多阶段协调（P1-P4）+ 反幻觉 Flag 验证** |

### 1.4 核心理念

1. **三层分工**：总指挥看全局（阶段、主方向）、战略层看本路（方向、死循环、小方向调控）、战术层看当下（具体动作）。三层各司其职，不越权。
2. **多阶段协调**：解题过程严格划分为 P1 侦查 / P2 漏洞识别 / P3 利用 / P4 验证 四个阶段，阶段切换必须"确凿"，不能跳过；方向错误快速回退。
3. **风格互补**：保守型（稳步、注意细节）+ 激进型（快速、优先效率）构成解题核心；创新型（发散探索、创造性利用）不承担核心解题职责，负责避免路径趋同与应对"脑洞"题。
4. **任务 = 方向性指引，非强制枷锁**：总指挥下发的任务是"探索方向建议"，不是唯一路径；战略层遇明确死路可自动切换并事后汇报，不视为违抗。
5. **静默是美德**：方向正确、各有进展时，总指挥与战略层都保持静默，不下发指令打断节奏；仅在出现全局性问题时才干预。
6. **反幻觉优先**：flag 必须来自靶机/附件的真实工具观测（Flag 验证系统双通道把关）；无工具调用直接 Final Answer 会被拒绝；宁可老实失败也不编造答案。
7. **证据分级驱动决策**：FACT/LIKELY 可作 MUST 依据，POSSIBLE 只能作 SHOULD 建议；无充分证据禁止否定方向（强化）。

---

## 2. 设计原则

### 2.1 分层解耦与职责隔离

| 层级 | 角色 | 职责 | 关键约束 |
|------|------|------|----------|
| 总指挥层 | Commander × 1 | 阶段管理、任务分解与分工、主方向确定与校准 | 只读战略层汇报的事实摘要（FACT/LIKELY），不读轨迹全文，控制上下文 |
| 战略层 | Coordinator × 3 | 各监督一路 agent：方向判断、死循环检测、小方向调控、向总指挥汇报 | 具体小方向调控、死循环检测与方向调整由战略层负责，总指挥不越权干预 |
| 战术层 | ReAct 主 LLM × 3 | 只负责具体解题动作，执行战略层指导 | 每 5 步 P1 进度汇报义务；无工具调用直接 Final 会被拒绝 |

### 2.2 阶段有序推进原则

解题流程严格按 **P1 → P2 → P3** 顺序推进，P4 为验证提交，**不能跳过**：

- **P1 侦查与信息收集**：目标是对整道题有大致的、全面的、但不深入的了解；三路方向互斥分工、每 5 步汇报进度；三路全部汇报侦查完成（recon_done）后，总指挥整合全局情报摘要并确定主方向，才正式进入 P2。
- **P2 漏洞识别与方向确认**：保守+激进深入主方向（互补为解题核心），创新发散探索备选方向；某方向有足够证据支撑并**取得验证**，汇报完整，总指挥确凿分析后才切换 P3。
- **P3 漏洞利用开发与执行**：在已验证方向上构造 exploit 获取 flag；总指挥协调以引导为主，死循环与方向调整由战略层负责。
- **P4 验证与提交**：总指挥只允许保守型进行最终验证，验证通过后提交；失败回退 P3。

### 2.3 证据分级与反幻觉原则

- 汇报与推论统一采用四级分级：**FACT**（轨迹中直接观察到的确定信息）/ **LIKELY**（基于事实的合理推断）/ **POSSIBLE**（缺乏充分证据的推测）/ **DISPROVED**（被后续轨迹明确否定）。
- 只有 FACT + LIKELY 可作 MUST 指令依据；POSSIBLE 只能作 SHOULD 建议。
- 总指挥的 MUST 指令**必须引用明确理由**，无理由的 MUST 会被系统自动降级为 SHOULD（历史复盘中总指挥 MUST"直接请求 /utils.php"而该路径已被证实空/404，正是无依据 MUST 的教训）。
- 战略层判定"方向错误/死路/禁忌"必须基于 FACT 或 DISPROVED 级推论，或 ≥8 步持续完全无关操作；单次失败/单条异常响应 ≠ 死路。
- flag 必须来自靶机/附件的真实工具观测（见第 8 章 Flag 验证系统）。

### 2.4 规则检测与 LLM 判断分层

的核心设计校准：**趋同/卡住等规则检测只产生"参考信号"，是否干预、干预强度（MUST/SHOULD）由总指挥 LLM 结合完整上下文判断**，避免死板代码误判（如把"系统性验证性推进"误判为死循环）。规则层负责客观事实（阶段切换信号、进度信号、无进展信号），LLM 层负责主观决策（是否干预、如何分配任务）。

### 2.5 设计原则与多阶段升级方案的映射

`docs/总指挥多阶段升级方案.md` 将总指挥从"被动监听者"升级为"多阶段自适应调度器"，代码实现与方案条目一一对应：

| 方案条目 | 代码实现 | 落地位置 |
|----------|----------|----------|
| 阶段状态机（P1-P4 不能跳过） | `_phase` 字段 + `_phase_advance_rule` 规则切换 | commander.py |
| 阶段切换有明确条件 | P1→P2 三路 recon_done / P2→P3 verified+确凿分析 / P3→P2 ≥2 路失败 | `_phase_advance_rule` |
| 按阶段差异化分配任务 | `_make_phase_directives` + `_phase_strategy_block` | commander.py |
| 方向趋同检测 | 主题 Jaccard 重叠 ≥0.4（规则级，注入 LLM 判断） | `_rule_signals_block` / `_detect_convergence` |
| 卡住检测与干预 | 主题相同 + 连续失败 ≥3 → 信号注入；激进卡住 MUST 换子方向 | `_rule_signals_block` / `_detect_stuck` |
| 回退机制（P3→P2 / P4→P3） | `_phase_p3_fail_threshold=2` 规则回退 + 任务契约重置 | `_phase_advance_rule` |
| 创新型强制发散 | 创新风格 prompt"发散优先禁止过早深入" + 巡查"过早深入"检测 | styles.py / coordinator.py |
| MUST 误判缓解 | MUST 必须有 reason + 战略层本地冲突校验降级 | commander.py / coordinator.py |
| 汇报完整才切 P3 | `_p2_verify_direction` 确凿分析（证据/验证/完整/反幻觉四问） | commander.py |
| P1 侦查广度按难度定制 | 领题 prompt 难度分支（easy 收敛 / medium 标准 / hard 发散） | commander/prompts.py |
| 总指挥开销控制 | flash 模型 + none 思考 + 有汇报才 LLM + 12 条摘要窗口 | commander.py / routed.py |

---

## 3. 总体架构：三层协作小队

### 3.1 架构总览

```
┌─────────────────────────────────────────────────────────────────────┐
│                       总指挥层 (Commander × 1)                       │
│  commander/commander.py + commander/prompts.py                      │
│  阶段状态机 P1→P2→P3→P4 · 领题分工 · 主方向管理 · 汇报分析 · 指令下发  │
└───────────────▲──────────────────────────────┬──────────────────────┘
                │ post_report (战略层→总指挥)     │ post_directive (总指挥→战略层)
                │ clue/dead_end/question/        │ priority: MUST/SHOULD
                │ progress/recon_done/verified   │ phase: P1/P2/P3/P4
┌───────────────┴──────────────────────────────▼──────────────────────┐
│                共享文件总线 FileBus (bus/file_bus.py)                │
│  每 challenge 一个 JSONL 文件 · 原子 append · 游标消费               │
│  report / directive / finding 三类消息同空间 seq 递增                │
└───────┬──────────────────────────────────────────────────┬──────────┘
        │                                                  │
┌───────▼──────────┐  ┌───────▼──────────┐  ┌───────▼──────────┐
│ 战略层 ×3 (Coordinator, agent/coordinator.py)              │
│ 任务契约 · 汇报 · 指令消费 · 阶段感知 · 禁忌 · 推论分级      │
└───────┬──────────┘  └───────┬──────────┘  └───────┬──────────┘
        │ 巡查指导注入            │                   │
┌───────▼──────────┐  ┌───────▼──────────┐  ┌───────▼──────────┐
│ 战术层 ×3 (ReAct 主 LLM, agent/react.py)                 │
│ conservative    │  │ aggressive        │  │ innovative        │
│ 稳步·细节        │  │ 快速·试错         │  │ 发散·创造        │
└───────┬──────────┘  └───────┬──────────┘  └───────┬──────────┘
        │                      │                     │
        ▼                      ▼                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 工具层 (tools/) · 记忆层 (memory/) · 熔断 (orchestrator/)           │
│ LLM 路由 (llm/routed.py) · Docker/Kali 执行层 · 附件/靶机           │
└─────────────────────────────────────────────────────────────────────┘
```

三层之间通过 **FileBus（跨进程共享文件总线）** 通信：

1. **战略层 → 总指挥**：`post_report` 上报重要线索（clue）、死路确认（dead_end）、提问副本（question）、P1 侦查进度（progress）、侦查完成（recon_done）、方向验证成功（verified）六类汇报；总指挥 `check_reports` 游标消费。
2. **总指挥 → 战略层**：`post_directive` 下发方向指令（领题分工、阶段切换提示、重定向、规则检测干预），带 `priority`（MUST/SHOULD）与 `phase` 阶段标记；战略层 `check_directives` 游标消费，**只取最新一条**避免过时指令累积注入。
3. **兄弟 agent 之间**：`post_finding / check_findings` 共享高置信度发现（每 5 步注入兄弟发现），`share_finding` 工具发布、`check_findings` 工具拉取、question/answer 互相提问回答。

### 3.2 进程模型

- swarm 层（`swarm.py`）为每个风格启动一个 **AgentClient.solve 子进程**（task JSON 带 style 字段，走 `solve.py` 的 JSONL 协议），三路并行；总指挥实例运行在 swarm 主进程内（`_commander_loop` 后台线程轮询，不阻塞主 LLM）。
- 总指挥初始化（`assign_initial` 是同步 LLM 调用，最坏 90s×2 重试）放在**后台线程**完成，否则 worker 启动被阻塞，整题开局停滞（实测卡在"总指挥模式：3 风格并行"后无 worker 日志）。
- 任一子进程提交正确 flag → kill 其余兄弟进程（`_kill_tree` 在 Windows 用 `taskkill /F /T` 杀主进程+子孙进程，防止 docker exec/ssh 孙进程残留导致 readline 阻塞）。

### 3.3 难度 → 并发度策略

`DEFAULT_STYLES_BY_DIFFICULTY`：easy 单路，medium/hard 三风格并行。但 2026-08 起 NSSCTF 难度评判不标准（easy 实为 middle/hard 也常见），config 中 `SWARM_ENABLED=true` 时**所有难度（含 easy）都走 3 风格并行 swarm**；`SWARM_ENABLED=false` 回退早期结论。

### 3.4 协作小队 vs 雁阵

WING-Goose（雁阵）的 swarm 是三路并行 + 兄弟发现总线：三路各自独立解题，通过消息总线互相借鉴，**没有全局协调者**。WING-Corvus 在雁阵之上新增**总指挥**作为全局协调者：

| 维度 | WING-Goose 雁阵 | WING-Corvus 协作小队 |
|------|----------------|----------------------|
| 全局协调 | 无（纯并行+总线借鉴） | 总指挥领题分工、阶段管理、主方向管理 |
| 路径趋同 | 无法检测（三路可能扎堆） | 趋同检测 + 领题方向互斥 + 创新强制发散 |
| 方向错误回退 | 无（持续空转到超时） | P3→P2 回退、P4→P3 回退 |
| 阶段划分 | 无 | P1-P4 四阶段，切换须确凿 |
| 协作协议 | finding 总线（兄弟发现） | report/directive 总线（上下级协议） |
| 反幻觉 flag | 无 | Flag 验证系统（代码机制 + LLM 审查） |
| 降级路径 | - | 总指挥 LLM 不可用 → 自动降级回雁阵行为不变 |

### 3.5 协作协议时序示例

以一次典型的 P1→P2 阶段推进为例，展示三层之间的完整协作时序：

```
[swarm 主进程]                            [子进程 ×3]                     [总线文件]
   │  领题分工 (assign_initial, 后台线程)                                  │
   │──post_directive(P1 任务×3, phase=P1)───────────────────────────────▶│
   │                                                                      │
   │                             每 5 步: report_progress ─────────────▶│
   │                             每 5 步: check_directives ◀─────────────│
   │                             兄弟发现 check_sanitized ◀───────────▶│
   │                             巡查 FACT 级: post_report(clue) ──────▶│
   │                             侦查完成: post_report(recon_done) ─────▶│
   │◀──check_reports(游标消费 3×recon_done + progress)──────────────────│
   │  _phase_advance_rule → P1→P2 信号                                   │
   │  _p1_synthesize: LLM 整合全局情报摘要 + 确定主方向                   │
   │──post_directive(P2 分工×3, 附全局情报摘要, phase=P2)───────────────▶│
   │                                                                      │
   │                             方向验证成功: post_report(verified) ───▶│
   │◀──check_reports(verified)──────────────────────────────────────────│
   │  _phase_advance_rule → P2→P3 信号                                   │
   │  _p2_verify_direction: LLM 确凿分析 → confirmed                     │
   │──post_directive(P3 分工×3, 附已验证方向, phase=P3)─────────────────▶│
   │                              ...                                    │
   │                              flag 候选: post_report(clue) ─────────▶│
   │  _phase_advance_rule → P3→P4 → 广播 P4 提示                        │
   │                              Final Answer → FlagVerifier → 提交     │
   │◀──任一子进程提交正确 flag → kill 其余兄弟 ──────────────────────────│
```

### 3.6 单题全生命周期（从领题到提交）

1. **领题**：调用器构造 task JSON（含 desc/type/difficulty/challenge_id/bus_dir 等），swarm 注入风格列表，总指挥后台领题分工（assign_initial → post_directive phase=P1）。
2. **P1 侦查**：三路子进程启动（solve.py），战略层首步读取任务契约；三路按风格独立侦查，每 5 步 progress 汇报；战略层巡查判断侦查完成 → recon_done。
3. **P1→P2**：三路全部 recon_done → 总指挥 `_p1_synthesize` 整合全局情报摘要 + 确定主方向 → 广播 P2 分工。
4. **P2 漏洞识别**：保守+激进深入主方向、创新发散；战略层判断方向验证成功 → verified 汇报；总指挥 `_p2_verify_direction` 确凿分析。
5. **P2→P3**：确凿确认 → 广播 P3 分工；P3 利用阶段总指挥协调以引导为主，方向调整由战略层负责。
6. **P3→P4**：flag 候选 → 广播 P4 提示；保守型验证 flag。
7. **提交**：战术层 Final Answer → 反幻觉兜底 → Flag 验证系统 → submission_handler 提交；任一子进程提交正确 flag → kill 其余兄弟。
8. **收尾**：swarm 汇总 SwarmResult（solved/flag/winner_style/各路统计）；子进程内自学习（_learn + _review）；成功沉淀经验到 RAG；总线文件保留供复盘。

---

## 4. 核心模块：总指挥 Commander

### 4.1 职责总览

总指挥（`ctf_agent/commander/commander.py`，共约 1100 行）是三层协作小队的顶层，职责包括：

1. **领题任务分解与分工**（`assign_initial`）：根据题目信息按风格差异分配方向互斥的 P1 侦查任务契约。
2. **接收战略层汇报**（`consume_reports`）：游标消费总线上的六类汇报，只把 FACT/LIKELY 级汇报摘要聚合进上下文。
3. **全局方向校准**（`analyze_reports`）：LLM 分析汇报，产出 directive 或保持静默；维护主方向与备选方向。
4. **多阶段状态机**（`_phase_advance_rule`）：规则驱动阶段切换（P1→P2→P3→P4，含 P3→P2 回退），切换必须确凿。
5. **主方向与备选方向管理**（`_update_directions_from_llm`）：主方向修改仅两种途径。
6. **P1 全局情报摘要整合**（`_p1_synthesize`）：三路侦查完成后 LLM 汇总全局情报摘要并确定主方向。
7. **P2→P3 确凿校验**（`_p2_verify_direction`）：进入 P3 前对 verified 汇报做 LLM 确凿分析。
8. **规则检测**：方向趋同检测、卡住检测、长时间无汇报检测（作为 LLM 参考信号注入）。

设计约束（`docs/sprint36_commander_design.md`）：

- 只聚合汇报的事实摘要（FACT/LIKELY），**不读轨迹全文**（控制上下文，避免爆炸）。
- 任务 = 方向性指引非强制枷锁：战略层遇明确死路可自动切换+事后 dead_end 汇报。
- 反幻觉：未汇报内容不得作为依据；证据不足保持静默。

### 4.2 数据结构

#### TaskAssignment（任务契约）

```python
@dataclass
class TaskAssignment:
    task_no: int      # 任务契约编号（按 styles 顺序 1,2,3...，唯一且稳定）
    style: str        # 目标风格（conservative/aggressive/innovative）
    task: str         # 方向性任务描述（非命令清单）
    rationale: str    # 分配理由（≤200 字）
```

任务契约编号**统一由代码按 styles 顺序分配**（忽略 LLM 输出的 task_no，保证唯一性），战略层以 task_no 识别当前任务契约。

#### CommanderDirective（方向指令）

```python
@dataclass
class CommanderDirective:
    style: str        # 目标风格
    direction: str    # 新方向或细化描述
    task_no: int      # 任务契约编号（重定向沿用或更新）
    priority: str     # MUST = 明确方向错误/死路; SHOULD = 方向性建议（默认）
    reason: str       # 指令依据（引用汇报证据）
```

#### Commander 核心状态

| 字段 | 含义 |
|------|------|
| `_assignments` | style → TaskAssignment 映射（当前任务契约） |
| `_context` | 历史摘要列表（指令+汇报，时间序），只保留最近 `_CONTEXT_WINDOW=12` 条 |
| `_report_cursor` | report 消费游标（check_reports 推进） |
| `_directive_count` | 累计下发指令数 |
| `_phase` | 当前阶段（初始 "P1"） |
| `_phase_enter_ts` | 进入当前阶段的时间戳 |
| `_style_reports` | 每路最近汇报跟踪（主题、失败计数、进度计数、recon_done、last_ts 等） |
| `_convergence_events` | 路径趋同事件记录（累计 ≥2 → 规则级 MUST） |
| `_main_direction` | 当前主方向（P1 完成后由全局情报摘要确定） |
| `_alt_directions` | 备选方向列表（创新发散确认的可能性方向） |
| `_phase_p3_fail_threshold` | P3→P2 回退阈值（多路连续失败数，默认 2） |

### 4.3 领题分工（assign_initial）

领题时总指挥基于题目信息（title / challenge_type / difficulty / task_desc）调用 LLM 做任务分解，输出 `assignments` 列表（每路恰好一个任务），要求：

- **三路方向互斥**：不得指向同一类攻击面/同一工具/同一排查路径；若题目只有单一明显入口，也应从不同角度切入（如一路查入口过滤逻辑、一路查后端处理、一路查侧信道差异）。
- **侦查广度按难度定制**（校准）：easy 收敛（只覆盖最小必要信息源，快速进入 P2）；medium 标准（常规信息源全覆盖）；hard 发散（全面覆盖所有可能信息源，深度挖掘，不急于进入 P2）。
- **解题合规约束**：任务必须要求 agent 从靶机/附件的真实工具观测中获取信息（访问靶机页面/接口、读取附件、交互调试），严禁指示"上网搜索题解/读取官方 writeup/查询 flags.txt"等非正常解题路径。
- 每路任务带 **P1 阶段标记**：领题即 P1 侦查阶段，阶段信息随指令下发给战略层（`phase="P1"`）。

兜底机制：LLM 未覆盖的风格按默认方向补齐（`_default_task`），保证任务契约完整。分配结果写入上下文摘要并记录日志。

### 4.4 汇报消费（consume_reports）

```python
reports, new_cursor = b.check_reports(self.bus_key, cursor=self._report_cursor)
```

- 每次 `run_once` 先消费新汇报；**只把 FACT/LIKELY 级汇报的摘要**（≤200 字符）追加进 `_context`，POSSIBLE 汇报仅本次可见不聚合（防误导）。
- 同时更新 `_style_reports` 跟踪：提取主题词、累计失败信号（dead_end 汇报或内容含"失败/无效/证伪/不可行/无法/failed"）、累计 progress 汇报数、标记 recon_done/verified。
- 汇报类型六类：`clue`（重要线索）/ `dead_end`（死路确认）/ `question`（提问副本）/ `progress`（P1 侦查进度）/ `recon_done`（P1 侦查完成）/ `verified`（方向验证成功）。

### 4.5 多阶段状态机（_phase_advance_rule）

重构为"**任务驱动 + 进度汇报驱动**"（非步数硬门槛），切换规则：

| 切换 | 条件（客观汇报信号） | 说明 |
|------|---------------------|------|
| P1 → P2 | 三路**全部**汇报 recon_done（战略层 LLM 判断该路基础侦查已覆盖题目全貌） | 不再用"任一 LIKELY 或汇报数≥4"的宽松门槛；切换前必须由 `_p1_synthesize` 整合全局情报摘要并确定主方向 |
| P2 → P3 | 存在 verified 汇报（方向有证据支撑 + 取得验证） | 切换前必须由 `_p2_verify_direction` LLM 确凿分析；证据不足保持 P2 |
| P3 → P4 | 汇报含 flag 候选（report_type=flag 或 content 含 flag 模式） | 进入验证提交 |
| P3 → P2 | ≥2 路报告失败/死路（fail_styles ≥ 阈值 2）且无 FACT 成功 | 方向错误回退，**优先于前进** |
| P4 → P3 | 验证失败（由外部提交结果触发） | 回退继续利用 |

阶段切换判定**基于规则（客观事实）而非 LLM 死板判断**；LLM 只负责任务描述生成。`_set_phase` 记录切换日志（含耗时），`run_once` 中切换后广播阶段提示（`_make_phase_directives` 按阶段为每路生成差异化 SHOULD 指令）。

### 4.6 主方向与备选方向管理（_update_directions_from_llm）

**主方向修改仅两种途径**（核心设计约束）：

1. **保守/激进在探索中明确发现主方向错误**（证据确凿证伪）；
2. **创新发散某个方向，经总指挥允许深入后证实该方向正确**。

若只是发现"有可能方向"，则加入**备选列表**（`_alt_directions`），待主方向被证伪后才考虑启用。

校准：**P1 侦查阶段不确认主方向**——主方向须等三路侦查全部完成后由全局情报摘要整合确定（`_p1_synthesize`）；P1 期间 LLM 输出的 main_direction 一律忽略（避免过早锁定方向，防止重蹈此前复盘中的覆盖"过早锁定 basename 绕过"的覆辙）。P1 阶段只维护 alt_directions。

LLM 分析时注入 `_main_direction_block`（当前主方向 + 备选方向 + 修改规则），供 LLM 对照判断。

### 4.7 P1 全局情报摘要整合（_p1_synthesize）

三路侦查全部完成后，由总指挥完成 **P1 → P2 的全局情报整合**：

1. 拉取全部 progress/recon_done 汇报（最近 12 条，各含 ≤250 字符）。
2. LLM 汇总生成：**全局情报摘要**（summary，覆盖题目全貌：入口/功能/技术栈/保护机制/关键线索/已排除方向，必须只基于汇报中出现的发现，反幻觉）+ **主方向**（main_direction，最有把握的攻击方向）+ **备选方向**（alt_directions）。
3. 记录摘要与主方向，**正式进入 P2**（先于广播：即使后续广播失败，阶段也已正确切换）。
4. 广播 P2 分工指令（随指令附带全局情报摘要，各路据此进入 P2 阶段）。

LLM 失败时降级：`_fallback_p1_summary` 用汇报原文拼接摘要，不阻塞阶段推进。

### 4.8 P2→P3 确凿校验（_p2_verify_direction）

进入 P3 的必要条件：某方向**足够的证据支撑 + 取得验证** + **汇报完整** + **总指挥确凿分析**。`_p2_verify_direction` 即"总指挥确凿分析"环节：

1. 拉取全部 verified 汇报（方向 + 完整验证证据，最近 5 条）。
2. LLM 确凿分析四问：证据支撑是否具体可查？验证是否真正取得（本地复现/远程响应证实/原语确认）？汇报是否完整（足以让其他解题器直接复用）？是否存在脑补？
3. `confirmed=true` → 切换 P3 + 广播 P3 分工（附确认主方向）；`confirmed=false` → 保持 P2，本轮正常分析其余汇报。
4. LLM 失败降级：verified 汇报本身已是战略层 FACT 级判断，按确认处理（不阻塞推进）。

### 4.9 LLM 分析（analyze_reports）与静默原则

`analyze_reports` 每轮构造 user prompt 注入五块上下文：

1. **当前解题阶段**（`phase_block`：当前阶段 + 阶段策略文本 `_phase_strategy_block`）；
2. **当前任务契约**（assignments 快照）；
3. **主方向与备选方向**（`main_direction_block`）；
4. **历史上下文**（最近 12 条指令+汇报摘要）；
5. **新收到的战略层汇报**（最近 10 条，含 report_type/agent/task_no/level）。

LLM 输出 JSON（silent / directives / main_direction / alt_directions / belief_state / reasoning）。核心处理逻辑：

- **静默原则**：`silent=true` 且 directives 为空时不下发任何指令（3 路方向分散、各有进展时不需要干预）。
- **指令分级**：priority 只能是 MUST/SHOULD；**MUST 必须有非空 reason**（无理由的 MUST 自动降级为 SHOULD——反幻觉门槛，历史教训）。
- **P3 阶段协调以引导为主**：除非指令含"返回P2"（漏洞验证失败），否则 P3 阶段所有转向类 MUST 指令**降级为 SHOULD**（死循环/方向调整由战略层负责）。
- **实现卡点识别**（复盘新增）：若汇报显示某路已理解攻击原理/已确认漏洞原语，但卡在具体实现细节（字节偏移取值、参数格式进制、工具调用参数、攻击脚本写法），应给出具体实现步骤引导（明确的命令/参数/进制/偏移），而非仅方向性建议——"临门一脚"干预价值最高。
- **死路校准**：收到 dead_end 汇报 → 为该路重新分配方向（不视为违抗）。
- 下发后更新任务契约（`cur.task = direction`）并记录上下文。

### 4.10 规则检测（趋同 / 卡住 / 无进展）

关键校准：**规则检测只产生参考信号，由 LLM 判断是否干预及干预强度**（`_rule_signals_block`），避免死板代码误判。三类信号：

| 信号 | 检测逻辑 | 注入方式 |
|------|----------|----------|
| 无进展信号 | 某路超过 `_STALE_REPORT_SECS=60s` 未向总指挥汇报且未 recon_done | 注入 analyze prompt："请 LLM 判断该路是否卡死/进程异常，若是则介入调整" |
| 卡住信号 | 某路最近 ≥2 条汇报主题完全相同（frozenset 归一化）且连续失败 ≥3 次 | 注入："请 LLM 判断是否真卡死，若是则建议换子方向" |
| 趋同信号 | ≥2 路最近 3 条汇报主题两两 Jaccard 重叠 ≥0.4 | 注入："请 LLM 判断是否路径趋同，若是则建议其中一路发散到未探索方向" |

**P3 阶段不注入卡住/趋同信号**（死循环与方向调整由战略层负责，总指挥仅保留进程级无汇报监控）。

主题提取 `_extract_topics` 三级策略：① 英文 token（≥3 字母、非停用词）；② 中文预置 CTF 方向词（basename/绕过/编码/注入/爆破/偏移/侧信道/竞态 等约 60 词）；③ 中文 2/3 字 n-gram 兜底（仅当预置词+英文均未命中时启用，避免 n-gram 噪声稀释重叠度）。

此外保留了规则级 `_detect_convergence` / `_detect_stuck` 直产指令能力（创新优先转向、激进 MUST 换子方向），但当前 `run_once` 主链路走"信号注入 → LLM 判断"路径。

### 4.11 指令下发（post_directives）与任务契约

```python
b.post_directive(agent_id=d.style, task_id=self.bus_key, content=d.direction,
                 task_no=d.task_no, priority=d.priority, reason=d.reason,
                 phase=self._phase)   # 附带当前阶段
```

- 每条 directive 写入总线 JSONL（kind=directive），战略层 `check_directives` 游标消费。
- **阶段随指令下发**：战略层据此更新阶段感知（`_current_phase`），按阶段注入不同巡查任务（P1 侦查完整性 / P2 主方向小方向调控 / P3 死循环与方向调整 / P4 flag 验证）。
- `_make_directive`（规则检测直产）与 `analyze_reports`（LLM 产出）共用此下发路径，均同步更新任务契约。

### 4.12 LLM 调用容错与上下文裁剪

- `_llm_json`：调用 LLM 并解析 JSON，带 1 次重试（提示"请严格只输出合法 JSON 对象，不要 markdown 代码块、前后缀文本、思考过程"）；失败返回 None 由调用方静默处理（阶段切换有规则兜底、P1 汇总有降级摘要、P2 校验有降级确认）。
- `_extract_json`：去除 ```json 代码块与 markdown 加粗装饰后匹配首个 `{...}` JSON 对象。
- `_trim_context`：上下文只保留最近 `_CONTEXT_WINDOW=12` 条摘要（控制 token，只聚合 FACT/LIKELY 摘要）。

### 4.13 总指挥 Prompt 设计

`commander/prompts.py` 包含 5 个模板：

| 模板 | 用途 | 关键输出 |
|------|------|----------|
| `_COMMANDER_SYSTEM_PROMPT` | 系统提示词：三层定位、三路核心定位、阶段管理、主方向管理、核心原则、汇报三档、输出格式 | - |
| `_INITIAL_ASSIGN_USER_TEMPLATE` | 领题分工 | `assignments`（每路一个、方向互斥、P1 任务、难度定制侦查广度） |
| `_ANALYZE_REPORTS_USER_TEMPLATE` | 汇报分析 | `silent / directives / main_direction / alt_directions / belief_state / reasoning` |
| `_P1_SUMMARY_USER_TEMPLATE` | P1 全局情报整合 | `summary / main_direction / alt_directions / reasoning` |
| `_P2_VERIFY_USER_TEMPLATE` | P2→P3 确凿校验 | `confirmed / direction_summary / reasoning` |

系统提示词核心要点：

- **总指挥只读战略层汇报的事实摘要，不读任何解题轨迹全文**（控制上下文）。
- **具体小方向的调控、死循环检测与方向调整由战略层负责**——总指挥不越权。
- 三路定位：conservative/aggressive 是解题核心（互补），innovative 不作为解题核心（发散探索 + 创造性利用）。
- 阶段切换必须确凿：P1→P2 三路全部 recon_done；P2→P3 证据支撑+验证通过+汇报完整+确凿分析；P3→P2 验证漏洞不存在。
- 主方向修改仅两种途径；MUST 必须引用明确理由。
- 静默是美德：全局性问题（路径趋同/集体卡死/明确死路/重大线索需全队利用）才干预。

### 4.14 总指挥一轮完整处理链路（run_once）

`run_once` 是总指挥每次轮询（后台线程每 5 秒）的完整处理单元，流程如下：

```
run_once(bus)
 ├─ 1. consume_reports: 消费新汇报 → 更新 _style_reports / _context
 ├─ 2. 无新汇报 → 立即返回 []（零开销轮询）
 ├─ 3. _phase_advance_rule(): 规则判定阶段切换
 │     ├─ P1→P2（三路全部 recon_done）→ _p1_synthesize：
 │     │     整合全局情报摘要 + 确定主方向 → set_phase(P2) → 广播 P2 分工指令 → 返回
 │     ├─ P2→P3（有 verified）→ _p2_verify_direction：
 │     │     LLM 确凿分析 → confirmed → set_phase(P3) → 广播 P3 分工 → 返回
 │     │     未确认 → 保持 P2 → 继续正常 analyze_reports（本轮处理其余汇报）
 │     ├─ P3→P2（≥2 路失败且无 FACT 成功）→ set_phase(P2) → 广播阶段提示
 │     └─ P3→P4（flag 候选）→ set_phase(P4) → 广播阶段提示
 │   （阶段切换后 _make_phase_directives 为每路生成差异化 SHOULD 指令并广播）
 ├─ 4. analyze_reports: LLM 深度分析
 │     ├─ 注入: 阶段+策略 / 任务契约 / 主方向+备选 / 历史上下文 / 新汇报 / 规则信号
 │     ├─ LLM 输出: silent / directives / main_direction / alt_directions / ...
 │     ├─ 更新主方向/备选（_update_directions_from_llm，P1 期间忽略 main_direction）
 │     ├─ silent=true → 记录静默，不下发
 │     └─ 非静默 → 校验指令（style 合法性 / priority / MUST 必须有 reason /
 │          P3 阶段转向类 MUST 降级 SHOULD）→ post_directives 下发
 └─ 返回本次下发的指令列表
```

### 4.15 总指挥失败降级与可观测性

- **总指挥 LLM 不可用**：`_setup_commander` 捕获一切异常（无 bus_dir / 领题 LLM 失败 / 初始化异常），返回 None → swarm **降级回纯雁阵**（`commander_enabled=False` 行为不变），不影响主流程；降级时通过 `on_commander("WARN", ...)` 记录日志。
- **总指挥单轮分析异常**：`_commander_loop` 中 `run_once` 抛异常被捕获忽略，不中断轮询；LLM 输出解析失败由 `_llm_json` 返回 None，调用方静默处理（有规则兜底）。
- **总线异常**：`consume_reports` / `post_directives` 对总线异常均 try/except 兜底，不阻断主流程。
- **可观测性**：总指挥生命周期日志通过 `on_commander(level, message)` 回调输出（NSS Runner 记录到命令行 + 文件）：领题分工（INFO）、指令下发（CMDR，含优先级/目标/方向/依据）、降级警告（WARN）。`Commander.summary()` 提供状态摘要（styles/分工/directives 数/上下文条数）供调试。

### 4.16 总指挥典型决策场景

| 场景 | 信号 | 总指挥行为 | 依据（代码位置） |
|------|------|-----------|------------------|
| 三路各有进展 | 新汇报为正常 clue，无失败 | `silent=true` 不下发（静默是美德） | `analyze_reports` silent 分支 |
| 某路 60s+ 无汇报 | `_rule_signals_block` 无进展信号 | 注入信号，LLM 判断是否卡死并介入 | `_STALE_REPORT_SECS=60.0` |
| 两路主题趋同 | 主题 Jaccard 重叠 ≥0.4 | 注入趋同信号，LLM 建议一路发散（优先创新） | `_rule_signals_block` 趋同分支 |
| 某路连续失败 3 次主题未变 | 卡住信号 | 注入信号，LLM 判断真卡死则建议换子方向 | 卡住分支 |
| 收到 dead_end | 死路确认 | 事后校准：为该路重新分配方向，不视为违抗 | `analyze_reports` 死路校准 |
| 某路卡在实现细节 | 汇报显示"已懂原理未完成实现" | 下发具体实现步骤引导（命令/参数/进制/偏移）——"临门一脚"干预价值最高 | analyze prompt 第 7 条 |
| P3 阶段 | 任意汇报 | 转向类指令一律降级 SHOULD（除非"返回P2"） | `analyze_reports` P3 降级 |
| 主方向被证伪 | 保守/激进明确报告方向错误（证据确凿） | 更新主方向（途径①） | `_update_directions_from_llm` |
| 创新证实备选方向 | 创新发散方向经允许深入并验证正确 | 更新主方向（途径②） | 同上 |

### 4.17 总指挥决策质量保障机制

1. **双保险反幻觉**：只读 FACT/LIKELY 摘要（`consume_reports` 过滤）+ MUST 必须有 reason（`analyze_reports` 降级）。
2. **阶段切换不依赖 LLM 主观判断**：规则层判定客观信号（recon_done/verified/flag 候选），LLM 只生成任务描述；LLM 失败有降级（P1 摘要拼接 / P2 校验默认确认）。
3. **上下文窗口控制**：12 条摘要窗口，避免长上下文稀释注意力与 token 爆炸。
4. **证据分级约束**：`_MUST_LEVELS = ("FACT", "LIKELY")`——只有 FACT/LIKELY 可作 MUST 依据。
5. **可回滚性**：所有状态（阶段/主方向/任务契约）通过上下文摘要可追踪，`summary()` 可调试。

## 5. 核心模块：战略层 Coordinator（巡查指导器）

### 5.1 角色定位

战略层（`ctf_agent/agent/coordinator.py`，共约 1900 行）是"**智能旁观者**"：旁观者清，当局者迷。解题 agent 专注于当下可能陷入困境或方向走错，巡查指导器以第三者视角宏观审视完整行为轨迹，提供精准的战术指导和方向调整。在 WING-Corvus 中，每路 agent 有一个战略层实例，同时承担两项职责：

1. **本路战术指导**（能力）：方向检查、死循环检测、禁忌拦截、推论分级、异步巡查；
2. **总指挥协作**（新增能力）：任务契约、向总指挥汇报、指令消费、阶段感知。

设计原则：

- **沉默原则**：方向正确且进展正常时保持沉默，不打扰 agent。
- **精准指导**：发现问题时给出具体的战术建议（不是模板化提示），guidance 必须含"做什么 + 怎么做 + 为什么"。
- **知识增强**：查询 RAG / Skill 库 / 经验库辅助判断。
- **两级分析**：先规则预检（L1，快速），再 LLM 深度分析（L2，精准）。

### 5.2 巡查触发时机（should_check）

起为**异步事件驱动**：巡查分析在后台线程执行，不阻塞 agent 主循环，完成经事件召回注入后续步。

| 触发条件 | 说明 |
|----------|------|
| 队列空闲 | 无在途分析 + 无未消费结果（堆积上限 1，防叠加过频） |
| 首次巡查 | 第 `first_check` 步（默认 5，2026-08-05 从 10 提前——简单题可能 <10 步解出） |
| 常规巡查 | 上一次注入结果之后 `check_interval` 步（默认 5，范围钳制 5~10） |
| 异常触发 | 连续错误步 ≥ max_errors（实时传入，免状态滞后） |
| 接近上限 | 倒数 `early_exit_steps=20` 步内（检查是否需要扩展） |

风格差异化节奏与参数（`STYLE_PARAMS`）：

| 风格 | check_interval | max_errors | temperature | 特点 |
|------|---------------|-----------|-------------|------|
| conservative | 5 | 3 | 0.0 | 稳健节奏，干预门槛高 |
| neutral | 5 | 3 | 0.0 | 均衡节奏 |
| aggressive | 5 | 5 | 0.0 | 快节奏，容忍快速试错 |
| innovative | 5 | 3 | 0.4 | 探索节奏，必产 creative_hints |

### 5.3 两级分析（analyze）

`analyze` 是战略层的核心分析入口（同步版，被异步线程复用）：

```
analyze(trajectory)
 ├─ 更新连续错误计数 / 全局已尝试方向追踪（_update_tried_directions，跨 lookback 窗口）
 ├─ L1-A 规则预检（确定性硬问题，直接 MUST 干预，不调 LLM）:
 │   ├─ 完全重复死循环（同工具+相似参数 ≥3 次，无新发现时）
 │   ├─ 全局死循环（整个轨迹重复 ≥6 次且无进展，跨窗口重试）
 │   ├─ 禁忌操作命中（精确签名 / 关键词匹配）
 │   ├─ MUST 未执行（上次 MUST 后工具未变且无进展 / 连续 ≥2 个空 action）
 │   └─ 分析瘫痪（≥20 步后最近 8 步无执行类工具）
 ├─ L1-B 软线索（传给 L2 参考）:
 │   ├─ 工具过度使用（同一工具 ≥5 次参数不同）
 │   ├─ 连续错误步 ≥3
 │   ├─ 指导持久性（上次指导后行为未改变）
 │   └─ 方向存疑（最近 8 步与题型工具集完全不相交）
 ├─ L2 LLM 深度分析（始终触发）:
 │   ├─ 注入: 阶段任务 / 推论清单 / L1 线索 / 禁忌列表 / 上次指导 / 知识库 / 轨迹摘要
 │   ├─ LLM 输出 JSON（belief_state / should_intervene / guidance / priority /
 │   │        forbidden_actions / revert_guidance / remove_forbidden /
 │   │        creative_hints / strategic_direction / p1_done / p2_verified / ...）
 │   └─ 更新推论状态 / 禁忌列表 / 自我纠错 / 汇报 p1_done / p2_verified
 └─ 无 LLM 降级: L1-B 软线索也作为干预依据（SHOULD）
```

### 5.4 推论分级框架（belief_state）

核心改造：战略层每次分析必须基于**推论分级**，四档：

1. **FACT**：轨迹中直接观察到的确定信息（如"step 24 POST 返回 HTTP 200"、"源码第 12 行含 unserialize($_POST['a'])"）。
2. **LIKELY**：基于事实的合理推断，有充分证据支持（如"入口存在且可用"）。
3. **POSSIBLE**：缺乏充分证据的推测，需要更多验证。
4. **DISPROVED**：被后续轨迹明确否定的判断（必须立即从禁忌列表移除）。

推论更新流程（强制）：**回顾 → 更新（升级/降级/证否）→ 新增 → 反思（reflection 必填）→ 决策**。只有 FACT + LIKELY 可以作为 MUST 干预依据；POSSIBLE 只能作为 SHOULD 建议；禁忌列表只能基于 FACT/DISPROVED。

### 5.5 无充分证据禁止否定方向（强化）

在寻找漏洞的过程中，绝大多数方向在未获**充分证据**（FACT 级证伪）之前都可能是有效路径：

- 判定"方向错误/死路/禁忌"必须基于 FACT 或 DISPROVED 级推论，或 ≥8 步持续完全无关操作（明确无进展）；**不得基于 POSSIBLE 级推测否定方向**。
- 单次失败/单条异常响应 ≠ 死路；报错也可能是线索（如报错信息泄露内部路径）。
- 对"看似无关"的方向，优先发散性探索并记录；只有被明确证伪（连续多次相同尝试均失败且无新信息）才可降权或禁止。
- 例外：已由 DISPROVED 推论证伪的方向、或经验库 high 置信度明确禁忌的方向，可否定。

方向存疑检测（`_check_direction`）也随之收紧：最近 8 步完全不相交**且**无任何题型相关工具才判定，同时要求 recent ≥6 步（避免开局空窗期误判）；判定结果只作 SHOULD 级提示（题型工具集是启发式映射，跨题型操作可能被误判）。

### 5.6 自我纠错（revert_guidance / remove_forbidden）

巡查器用后续轨迹验证自己之前的判断：

- 上次指导后 agent 未按指导执行，但用自己的方式持续取得进展 → 撤销上次指导（`revert_guidance=true`），若方向正确保持沉默。
- 禁忌列表中的操作后来被 agent 成功使用并突破 → `remove_forbidden` 移除误判项。
- DISPROVED 推论对应的禁忌项自动清理。
- **承认错误不是问题，坚持错误才是**：判断依据是轨迹证据，证据变了就要改。

### 5.7 死循环检测与禁忌体系

- **精确签名禁忌**（`_forbidden_signatures`）：死循环自动将重复操作（action + action_input 前 100 字符归一化）加入禁忌，精确匹配避免关键词误伤不同命令。
- **关键词禁忌**（`_forbidden_actions`）：LLM 分析时生成（如"hashcat 爆破 cloud.zip 密码"连续失败后），提取 >3 字符关键词匹配拦截。
- **MUST 未执行检测**：上次干预是 MUST 且主导工具未变 + 无实质进展（≥2 种不同 observation 才算进展）→ 升级为 MUST 阻断，同时追加禁忌。
- **拦截时机**：`intercept_forbidden` 在工具执行前检查（巡查间隔之外也拦截），避免继续浪费步数。

### 5.8 分析瘫痪检测

复盘根因（linx/threshold/faulty_mayo 三题 hard 全败）：agent 在"理解/读源码/解析数据"阶段无限滞留，从不执行攻击脚本。检测逻辑：总步数 ≥ `execution_starvation_min_steps=20`（前期信息收集合理），且最近 8 步内无任何执行类工具（`_EXECUTION_TOOLS`：ssh_exec / ssh_python / docker_exec / docker_python / ssh_upload / docker_upload / http_request / exploit_template）→ 判定分析瘫痪，MUST 级干预要求立即写最小攻击脚本运行验证。

### 5.9 创新模式：灵感板 + 发散优先约束

创新风格巡查 LLM 必须输出**双轨**：

- **轨道 A — 判断**：方向是否正确/是否死循环/是否停滞（同默认分析，但**不使用 strategic_direction**）。
- **轨道 B — 发散**（创造性灵感板）：无论是否干预，必产 2-3 条 `creative_hints`，参照创造性思路 5 模板：目标反转 / 空间重估 / 代数结构 / 侧信道内嵌 / 线索交叉。

**发散优先约束（WING-Corvus 2.0）**：若轨迹显示创新 agent 在**无充分证据时**向某一方向**深入重复**（同一思路连续 ≥3 步深挖、或反复微调同一假设），判定为"过早深入"，下发提示要求停止深入、回到发散状态（同时探索 2-3 条不同假设）。只有出现 FACT 级明确方向后，深入才合理。

### 5.10 战略深化（strategic_direction）

双系统设计：主 LLM = 快思考（System 1，战术决策），巡查器 = 慢思考（System 2，战略决策）。非创新风格干预时，除 guidance 外还需给出 `strategic_direction`——在主 LLM 当前推理基础上**进一步深化细化**（下一步往哪个方向深挖/优先验证哪个假设/哪块区域还有未挖掘的线索），不是重复 guidance 的具体命令，不超过 200 字。沉默原则：方向未偏移时不注入任何内容。

### 5.11 协作义务

巡查干预时同时提醒发布关键线索到共享总线：

> [协作义务] 若你最近已确认了可供兄弟解题器直接复用的关键线索（加密算法与 key/偏移、flag 格式、可复现的绕过方法、已确认的死路），请在本步之后用 share_finding 工具发布到共享总线（kind=fact/finding）。

战术层专注解题，但已验证的关键事实必须回流共享池，供战略层汇总与其他解题器参考，避免"各自独立解题、共享仅互相借鉴"（雁阵 v2 协作升级点 1）。

### 5.12 总指挥协作能力（新增）

战略层在 WING-Corvus 中新增的总指挥协作能力（默认关闭，`commander_enabled=True` 且 bus 非空才启用；关闭时纯雁阵行为不变）：

#### 5.12.1 任务契约（set_task_contract）

总指挥注入/更新任务契约 `{task_no, task, priority}`——**方向性指引，非强制枷锁**：战略层执行时遇明确死路可自行切换 + 事后汇报。任务契约编号 task_no 用于汇报时标识当前任务。

#### 5.12.2 汇报协议（report_to_commander 家族）

| 方法 | report_type | 触发场景 |
|------|-------------|----------|
| `report_to_commander` | clue / dead_end / question | 通用汇报（只报 FACT/LIKELY，不报每步噪声） |
| `report_progress` | progress | P1 侦查进度（含当前发现/下一步计划/是否卡死） |
| `report_recon_done` | recon_done | 该路 P1 侦查完成（LLM 判断基础侦查已覆盖题目全貌） |
| `report_verified` | verified | 某方向已验证成功（方向 + 验证证据，P2→P3 信号） |
| `report_dead_end` | dead_end | 遇明确死路自动切换 + 事后汇报 |
| `report_p1_progress_if_due` | progress | 主循环调用：P1 阶段每 5 步自动汇报 |

汇报内容上限：content ≤400 字符，level 取 FACT/LIKELY。**只报高置信度事实，不报每步噪声**（控制总指挥 token）。

#### 5.12.3 P1 每 5 步进度汇报（report_p1_progress_if_due）

由主循环每步调用，仅 P1 阶段 + 总指挥模式启用时工作（P2/P3 由巡查汇报 clue/dead_end 替代）：

- 每 5 步一次（自上次汇报起 <5 步不重复）；
- 内容自动提取：当前发现（最近 2 步 observation 精华）/ 下一步计划（最近一步 thought 末尾 80 字符）/ 是否卡死（连续错误 ≥ max_errors）；
- 总指挥据此监控三路侦查进度：某路长时间无进展（>60s 未汇报）→ 介入调整；三路全部 recon_done → 整合全局情报摘要并确定主方向 → P2。

#### 5.12.4 指令消费与 MUST 本地冲突校验（check_commander_directives）

由主循环**每步**调用（无新指令零开销），逻辑：

1. 游标拉取发给自己的新 directive；**只取最新一条**（避免过时指令累积注入，后续指令覆盖先前的）。
2. **阶段感知**：directive 附带 phase（P1/P2/P3/P4）→ 更新 `_current_phase`（用于按阶段注入不同巡查任务）。
3. **MUST 本地冲突校验**（WING-Corvus 升级，历史复盘）：总指挥基于跨 agent 汇报摘要决策，可能遗漏本 agent 已实证的死路。若指令方向与本地已验证死路（forbidden_actions / 精确签名）冲突：
   - 不盲目强制（案例：总指挥 MUST"直接请求 /utils.php"，但本 agent 已证实该路径返回空/404，强制执行只会浪费步数）；
   - **降级为 SHOULD（本地证据优先）+ 事后 dead_end 回报总指挥**（reason 中标注"已降级为 SHOULD，以本地证据为准，已回报总指挥"）。
4. 返回注入指导（`[总指挥·任务N] 方向\n[依据] reason`），主循环注入战术层 prompt；MUST 走持久重复机制，优先级高于巡查输出。

#### 5.12.5 死路自动切换（report_dead_end + on_tool_error）

- `report_dead_end(content, auto_switch=True)`：汇报死路 + 自动切换方向（`_default_switch_direction` 按风格给不同侧重，避免全队趋同：保守转向静态分析 / 激进转向黑盒验证 / 创新转向非常规路径），返回新方向注入战术层；不等待总指挥下次轮询。
- `on_tool_error(tool, error)`：工具执行异常时调用，**环境缺失类错误**（not found / no such file / not installed / no wine / connection refused / permission denied 等关键词）连续 2 次才判定死路（单次失败可能是抖动）→ 自动切换 + dead_end 汇报。

#### 5.12.6 阶段感知巡查任务（_phase_task_block）

按当前阶段注入不同巡查侧重（随总指挥指令更新，2026-08-05 修复了该方法"从未定义导致 P1 阶段巡查每次抛 AttributeError 降级为不干预"的 bug）：

| 阶段 | 巡查侧重 |
|------|----------|
| P1 | 侦查完整性与进度：是否全面收集题目信息（系统性扫描/快速试探记录响应/非常规信息挖掘），是否遗漏必查信息源（附件/入口/版本指纹/隐藏线索）；**不深入任何单一方向**，重点是广度；判断该路基础侦查已覆盖题目全貌时汇报 recon_done |
| P2 | 主方向小方向调控：是否在正确方向上推进（保守/激进深入主方向，创新发散探索可能方向），是否卡在死循环或偏离主方向；**死循环检测与方向调整由战略层负责**；某方向证据支撑+取得验证时完整汇报 p2_verified（方向+验证证据） |
| P3 | 死循环与方向调整：agent 应在已验证方向上利用漏洞；卡死与方向调整由战略层负责，总指挥协调以引导为主 |
| P4 | flag 验证：确认候选 flag 来源可靠（轨迹中有确凿证据支撑），验证通过后再提交 |

#### 5.12.7 巡查 LLM 输出的阶段信号（p1_done / p2_verified）

战略层巡查 LLM 输出 JSON 中新增两个信号字段，由 `_llm_analyze` 解析后自动汇报：

- **p1_done**（仅 P1 阶段）：LLM 判断该路 agent 的基础侦查已覆盖题目全貌（入口/附件/版本指纹/关键线索均已有初步了解，广度足够）→ `report_recon_done(summary)`。三路全部汇报后，总指挥才整合全局情报摘要并确定主方向 → P2。P1 未完成时 p1_done=false（不要过早汇报完成）。
- **p2_verified**（仅 P2 阶段）：LLM 判断某方向已有**足够的证据支撑并取得了验证**（不是猜测；如工具输出确认漏洞原语/本地复现成功/响应证实假设）→ `report_verified(direction, evidence)`。汇报必须完整（方向 + 验证证据），总指挥确凿分析确认后才切换 P3；证据不足时 p2_verified=false。

#### 5.12.8 巡查 FACT 级线索同步上报

`react.py` 的 `_post_to_bus` 在将巡查 belief_state 的 FACT/LIKELY 发布到兄弟总线时，**FACT 级同时同步上报总指挥**（`report_to_commander(report_type="clue")`）；LIKELY 只进兄弟总线，控制汇报噪音。

---

## 6. 核心模块：战术层 ReAct 主循环

### 6.1 角色定位

战术层（`ctf_agent/agent/react.py`，共约 1700 行）是每路 agent 的 ReAct 推理引擎，实现 Thought-Action-Observation 循环：LLM 输出 Thought + Action + Action Input → 引擎解析并调用工具得到 Observation → Observation 回灌 LLM 进入下一轮 → LLM 输出 Final Answer 时进入提交流程。三路战术层分别承载三种解题风格（`agent/styles.py`）。

### 6.2 三种解题风格

| 风格 | 核心定位（贯穿全部阶段） |
|------|--------------------------|
| conservative（保守） | **稳步推进，注意细节**：每一步充分验证（保护/偏移/脚本稳健），捕捉激进遗漏的线索。与激进互补，是解题核心之一 |
| aggressive（激进） | **快速推进，优先效率**：快速迭代试错，忽视部分细节，最快逼近 flag。与保守互补，是解题核心之一 |
| innovative（创新） | **不作为解题核心**：①其他解题器深入主方向时继续侦查其他可能方向（发散探索）；②主方向确定后尝试新颖的利用方式应对"脑洞"题。创新不能代替保守/激进深入主方向 |

创新风格带"**创造性工具箱**"（卡住或思路重复时逐条对照）：目标反转 / 空间重估 / 代数结构 / 侧信道内嵌 / 线索交叉；加上 **WING-Corvus 2.0 发散优先约束**（无 FACT 级方向禁止过早深入）。

### 6.3 主循环（_run_inner）

每步循环按固定顺序执行：

1. **步数软截断兜底**：`while True` + 进展感知软截断（修复 extend_steps 从未生效的 bug）——超过 max_steps 后不立即硬停，由 breaker 进展感知决定（持续有实质进展则继续，无进展超宽限期才退出；时间维度由 breaker 时间熔断兜底）。
2. **stop 信号检查**（每步开始前，子进程模式）。
3. **巡查发起**（异步事件驱动）：`should_check` 达巡查时机 → `fire_async_analysis` 后台线程分析（不阻塞）。
4. **巡查事件召回**：`consume_pending_guidance` 消费已完成分析 → `_apply_coordinator_guidance` 注入。
5. **总指挥指令注入**（WING-Corvus 新增）：每步 `check_commander_directives`（战略层能力），有新 directive 立即注入（MUST 走持久重复机制，优先级高于巡查输出）。
6. **P1 进度汇报**（WING-Corvus 新增）：P1 阶段每 5 步 `report_p1_progress_if_due`。
7. **刷新 system prompt**（中期记忆 facts + RAG）。
8. **注入巡查指导**（`_coordinator_guidance`）：MUST 持久注入（`_must_repeat_left` 连续重复强调）+ 强制跳转（连续 ≥2 步仍执行与 MUST 相悖动作 → `[强制跳转]` 阻断）+ 灵感板（创新风格）+ 战略方向 + 来源步声明（避免过时信息误导）。
9. **消息总线兄弟发现**（每 5 步）：`check_sanitized` 拉取消毒后的兄弟发现注入 prompt；同时注入协作义务提示（要求发布可复用关键线索）。
10. **强制回答检查**（每 5 步）：检测来自兄弟且本 agent 尚未回答的提问，强制回答（即使"不知道"），防止提问方卡死等待。
11. **动态知识注入**（每 8 步，step ≥8）：Skill 库 mid-solve 动态注入 + 经验库动态注入（10 步冷却）+ RAG 延迟注入（改为侦查后基于实际观测检索，防题目混淆）。
12. **LLM 推理**（异常容错：重试 → 降级 pro → 注入提示跳过本步继续）。
13. **解析**（`parse_llm_output`）→ Final Answer 提交流程 / 格式错误处理 / 工具调用。
14. **禁忌拦截**（工具执行前 `intercept_forbidden`）。
15. **调用工具** → 工具异常死路检测（`on_tool_error`）→ 构造 ReActStep → 熔断检测 → Observation 回灌。

### 6.4 解析容错体系

WING-Corvus 强化了 LLM 输出解析的鲁棒性（基于 linx/threshold 复盘："连续 5 次格式解析失败"是 hard 题常见死因）：

- **配平花括号 JSON 提取**（`_extract_balanced_json`）：状态机扫描首个 `{` 起，跳过字符串内 `{}/转义引号` 与嵌套 `{}`，提取配平完整的 JSON 对象——修复 LLM 在 JSON 后直接跟含 `{}` 解释文本时（如 `Action Input: {"file": "/tmp/x"} 文件内容包含 {"flag": "..."}`）旧"首{到末"截取把文本包进 JSON 的解析失败。
- **action_input 鲁棒清洗**（`_clean_action_input`）：配平提取 + 尾逗号容错 + 单引号→双引号兜底。
- **Markdown 装饰剥离**：Action 字段 `**Action:** ssh_exec` 等装饰剥离（`_strip_markdown_artifacts`）；Action Input 前后 `**` 剥离（`_strip_code_fence`）。
- **Action Input 别名**：Input/Args/Arguments/Parameters/Params/参数 等前缀。
- **Action 缺 Input 回退**：漏写 "Action Input:" 前缀时从 Action 行后配平提取首个 JSON 对象。
- **Thought 回退**：LLM 省略 "Thought:" 前缀时取 "Action:" 前的文本作为 thought。
- **格式错误容错**：`max_format_errors=5`（从 3 放宽——并发多 agent 抢 LLM API 时输出质量波动，3 次易误杀深入思考中的 agent）；空输出 2 次免费重答（注入恢复 hint），超过才计入 format_errors。

### 6.5 提交流程与反幻觉兜底

Final Answer 后的提交流程（多次提交机制）：

1. **反幻觉兜底**：无任何有效工具调用直接 Final = 幻觉（拒绝并注入 hint 让 LLM 先收集信息，所有题型强制 ≥1 次工具调用）。
2. **去重检查**：已提交过的答案直接驳回。
3. **提交次数上限**：达上限后不再调用 submission_handler，注入指导继续工具分析（即使连续提交 20 次错误答案也不直接退出）。
4. **Flag 验证**（WING-Corvus 新增）：提交前 `FlagVerifier.verify` 双通道检查，验证不通过不消耗提交次数（详见第 8 章）。
5. **提交回调**：`submission_handler` 返回 (correct, feedback)；失败注入反馈继续循环（不重新开始）；成功正常结束。

### 6.6 思考强度注入（_thinking_extra）

按难度+题型选择 reasoning_effort（仅 `ENABLE_THINKING_MODE=true` 时生效），优先级：

1. `force_max_thinking=True`（重试场景）→ max；
2. hard/extreme → max（thinking_effort_hard / thinking_effort_extreme）；
3. medium + reverse/pwn/crypto/misc（深度分析题型）→ max；
4. medium + web/forensics/osint（套路化题型）→ high；
5. easy → high；未知难度 → default。

> ⚠️ 重要约束：go/opencode 端点为 Agent 类请求，思考链强制无界生成，非 none 的 effort 一律撞满 max_tokens（74-86s/次, content=0）——2026-07-31 deepseek-v4-flash 升级 reasoning 模型后 9 组受控实验定论。因此 **LLM_PROVIDER=go 时 reasoning_effort 强制为 "none"**（思考归零，content 正常，每步 10-20s，推理由 ReAct Thought 承担）；非 go 提供方才按上述分级注入。

### 6.7 工具集与总线接入

- `_tool_map` 构建 name → Tool 映射（含别名）：docker 工具主名与 Kali 经验一致（ssh_exec 等），docker_* 为别名；LLM 无论用经验中的旧名还是 docker 前缀名都能命中同一工具。
- 消息总线接入：`bus` + `bus_agent_id` + `bus_key`；每 5 步 `check_sanitized` 注入兄弟发现；巡查 FACT/LIKELY 经 `_post_to_bus` 发布（FACT 同时上报总指挥）。
- 中期记忆开启时自动注册 RememberFactTool。

### 6.8 主循环单步时序图（含三层交互）

```
┌─ ReAct 主循环 (第 N 步) ─────────────────────────────────────────────┐
│ 1. stop 信号检查                                                       │
│ 2. 巡查发起: coordinator.should_check → fire_async_analysis (后台线程) │
│ 3. 巡查召回: consume_pending_guidance → _apply_coordinator_guidance    │
│ 4. 总指挥指令: coordinator.check_commander_directives (每步)           │
│    ├─ 有新 directive → 更新任务契约 + 阶段感知 → 注入 (MUST 持久重复)   │
│    └─ MUST 与本地死路冲突 → 降级 SHOULD + dead_end 回报总指挥           │
│ 5. P1 进度汇报: report_p1_progress_if_due (P1 阶段每 5 步)             │
│ 6. system prompt 刷新 (中期记忆 facts + RAG)                           │
│ 7. 巡查指导注入 (MUST 重复/强制跳转/灵感板/战略方向/来源步)            │
│ 8. 总线兄弟发现注入 (每 5 步) + 强制回答检查 (每 5 步)                  │
│ 9. 动态知识注入 (每 8 步: Skill / 经验库 / RAG)                        │
│ 10. LLM 推理 (重试 → pro 降级 → 跳过本步)                              │
│ 11. 解析 (配平 JSON / markdown 剥离 / 别名回退)                        │
│     ├─ Final Answer → 反幻觉兜底 → Flag 验证 → 提交/继续               │
│     └─ Action → 禁忌拦截 → 工具调用 → on_tool_error 死路检测           │
│ 12. 熔断检测 → Observation 回灌 → 步数 +1                              │
└──────────────────────────────────────────────────────────────────────┘
```

### 6.9 战术层与战略层、总指挥的交互矩阵

| 场景 | 战术层（ReAct） | 战略层（Coordinator） | 总指挥（Commander） |
|------|----------------|----------------------|---------------------|
| 领题 | 首步读取任务契约（check_directives） | set_task_contract 更新方向 | assign_initial 领题分工 |
| 侦查中 | 每 5 步 report_p1_progress_if_due | 巡查判断侦查完整性 | 监控进度流，60s 无进展介入 |
| 侦查完成 | - | LLM 判断 p1_done → report_recon_done | 三路全到 → _p1_synthesize → P2 |
| 方向验证 | - | LLM 判断 p2_verified → report_verified | _p2_verify_direction 确凿分析 → P3 |
| 死循环 | MUST 持久重复 + 强制跳转 | 禁忌拦截 + MUST 未执行检测 | 卡住信号注入 LLM 判断 |
| 方向错误 | 执行总指挥/巡查重定向 | 死路自动切换 + dead_end 汇报 | 事后校准分工 |
| 兄弟协作 | share_finding / check_findings | FACT 级线索同步上报 | clue 汇报纳入决策 |
| 提交 | Final → 反幻觉兜底 → Flag 验证 → 提交 | - | P4 提示（保守型验证） |

---

## 7. 核心模块：swarm 编排与总指挥生命周期

### 7.1 SwarmCoordinator 职责

`ctf_agent/swarm.py`（约 460 行）是 runner 层多风格并行编排器：

- 同题 N 子进程并行（每路一个 style），任一子进程提交正确 flag → kill 其余兄弟进程；
- 难度 → 并发度策略（easy 单路 / medium/hard 三风格并行；SWARM_ENABLED=true 时全部三路）；
- 共享同一 `verify_flag` 回调（平台/确证性校验，不是防幻觉——防幻觉由 react.py 内部兜底）。

### 7.2 总指挥生命周期（新增）

#### 7.2.1 开关与降级

```python
commander_enabled: bool | None  # None=读 config SWARM_COMMANDER_ENABLED
```

- `_commander_default_enabled()` 读取 `settings.swarm_commander_enabled`；
- `_setup_commander(task, on_commander)`：开关未启用或无 bus_dir → 返回 None（纯雁阵）；LLM/初始化异常 → 捕获并返回 None（降级回雁阵，on_commander 记 WARN 日志）。

#### 7.2.2 领题分工（_setup_commander）

```python
cmdr = Commander(llm=RoutedLLMClient(settings), title=..., task_desc=..., styles=styles, ...)
assignments = cmdr.assign_initial()
if not assignments: return None
for a in assignments:
    bus.post_directive(agent_id=a.style, task_id=bus_key, content=a.task,
                       task_no=a.task_no, priority="SHOULD", reason="领题分工",
                       phase="P1")   # 领题即 P1 侦查阶段
```

- 初始任务契约 → 每条 post_directive（战略层首步 check 读取，统一走总线协议）；
- 领题分工日志 → on_commander("INFO", ...)。

#### 7.2.3 异步事件驱动（关键实现）

```python
# 总指挥初始化 (assign_initial 是同步 LLM 调用, 最坏 90s×2 重试) 必须放后台线程:
# 否则 worker 启动被阻塞, 整题开局停滞
threading.Thread(target=_async_commander_setup, daemon=True).start()
```

- `_async_commander_setup`：后台初始化总指挥 → 成功则启动 `_commander_loop` 轮询线程；
- 任务 dict 乐观注入 `task["commander_enabled"]=True`（初始化在后台完成，失败时读空总线无害）；
- 注入实际风格列表到 task（总指挥领题分工按真实参与风格分配，避免 DEFAULT_STYLES 与调用方显式 styles 不一致）。

#### 7.2.4 后台轮询（_commander_loop）

```python
while not stop_event.is_set():
    directives = cmdr.run_once(bus=bus)   # 消费汇报 → LLM 分析 → 下发
    # 指令日志 → on_commander("CMDR", ...)
    stop_event.wait(5.0)                   # 5 秒轮询周期
```

- 异步事件驱动，不阻塞主 LLM；
- 指令日志：`指令[优先级] 风格(任务N): 方向 — 依据: reason`；
- 异常捕获不中断轮询。

#### 7.2.5 线程 join 与进程清理（修复）

- **join 必须所有线程共享同一 deadline 并行等待**：旧实现逐个 join(timeout) 累计等待（3 路 × 540s = 1620s，子进程早该被 kill 却拖到 N×timeout 才返回"未及时 kill"）。
- 到点 kill 进程树：`_kill_tree` Windows 用 `taskkill /F /T` 杀主进程+子孙进程（单用 proc.kill() 只杀 python 主进程，其 spawn 的 docker exec/ssh 孙进程残留，stdout 不关闭，readline 阻塞导致线程不结束）。
- 结束后 `commander_stop.set()` 停止总指挥轮询线程。

---

## 8. 核心模块：Flag 验证系统（反幻觉）

### 8.1 背景

（复盘）：agent 在 web 题中通过 GitHub API 抓取官方 writeup.md 获得 flag 并直接提交，轨迹看起来"有工具调用"但 flag 来源是非正常解题渠道（外部题解），现有"至少 1 次工具调用"反幻觉兜底无法拦截。

### 8.2 设计：两次验证，均通过才放行提交

`ctf_agent/agent/flag_verify.py`（约 246 行）的 `FlagVerifier.verify(flag_candidate, steps)`：

```
verify(flag, steps)
 ├─ ① 代码机制 1: flag 必须出现在某一步的 Observation 中
 │     （flag 来自工具输出, 而非 LLM 记忆/编造; 优先匹配完整 flag,
 │       允许匹配花括号内核心片段 ≥8 字符防观测截断误判）
 ├─ ② 代码机制 2: 可疑渠道拦截
 │     flag 出现的步骤若来自可疑外部题解渠道（GitHub/raw.githubusercontent/
 │     api.github/搜索引擎/官方题解目录 等域名关键词）且 action/输入含
 │     writeup/solution/flags/README/题解 等关键词 → 判定非正常渠道, 拒绝
 ├─ ③ LLM 审查（仅代码机制通过后）:
 │     最近 N 步轨迹（Thought/Action/Observation 摘要）交给审查 LLM,
 │     判定 flag 是否来自靶机/附件的真实观测, 是否存在幻觉或外部题解污染.
 │     输出结构化 JSON: {"pass": bool, "reason": str, "confidence": "high/medium/low"}
 └─ 验证失败 → 不消耗提交次数, 注入反馈让 agent 继续从真实观测获取 flag
```

### 8.3 代码机制细节

- **来源搜索**（`_find_source`）：跳过 is_final 步骤，在 observation 中搜索 flag 子串；优先完整匹配，失败后匹配核心片段（`_flag_core`：花括号内前 8 字符），避免观测被截断导致的误判。
- **渠道分类**（`_classify_channel`）：含 http(s):// → web；含 file_read/file_analyze/strings/cat/unzip/xxd/file /binary → attachment；否则 target。
- **可疑渠道拦截**（`_suspicious_hit`）：可疑主机（github.com / raw.githubusercontent.com / api.github.com / gist.github.com / gitlab.com / writeup / solver / exploit-db / ctftime）**且**可疑关键词（writeup / solution / solve.py / solver.py / exploit.js / flags.txt / flag.txt / official / 官方 / 题解 / 答案 / README）双命中 → 拒绝；仅访问 GitHub 且带 contents/raw/blob//flags/flag/writeup 也可疑。

### 8.4 LLM 轨迹审查

- 只取最近 `max_trajectory_steps=8` 步，每步输出 Action/Input（≤400 字符）/Obs（≤1200 字符），总长 ≤6000 字符；
- 判定标准（任一命中即 FAIL）：① flag 出现在"读取 GitHub/搜索引擎/官方题解"类操作输出中；② 轨迹中没有任何一步直接访问靶机/读取附件（flag 凭空出现）；③ flag 是编造的（与所有观测内容无关）；
- 判定 PASS：flag 出现在靶机响应（HTTP 页面/接口返回）、附件文件内容、或对靶机交互（nc/pwn/shell）的输出中，且该观测与候选 flag 直接相关；
- 异常降级：LLM 审查异常/输出无法解析 → 视为通过（代码机制已兜底），不阻断。

### 8.5 与提交流程的集成

`react.py` Final Answer 提交前调用 `FlagVerifier.verify`：验证不通过 → 注入反馈（`⛔ flag 验证未通过 (提交前轨迹检查): ... 本次不消耗提交次数 (剩余 N). 请重新基于靶机/附件的真实工具观测分析...`）+ `consecutive_format_errors += 1` → 继续循环（不提交）。

## 9. 多阶段协调详解（P1-P4）

### 9.1 总体框架

WING-Corvus 将单题解题流程划分为四个阶段，每阶段有明确目标、任务分配策略和退出条件。**阶段顺序强制 P1 → P2 → P3 严格按序推进，不能跳过**；P4 为验证提交。每阶段开始时，总指挥根据阶段目标、题目难度和各 agent 当前状态下发差异化任务（`_make_phase_directives`）。

```
P1 侦查 → P2 漏洞识别 → P3 利用 → P4 验证 → 结束
   ↑            │           │         │
   │            │     方向错误↓     验证失败
   │            └──←──←──┘          │
   └──←──←──←──←──←──←──←──←──←──┘
```

| 阶段 | 名称 | 进入条件 | 退出条件 |
|------|------|----------|----------|
| **P1** | 侦查与信息收集 | 领题（默认） | 三路全部 recon_done → 总指挥整合全局情报摘要确定主方向 → P2 |
| **P2** | 漏洞识别与方向确认 | P1 产出主方向 | 某方向证据支撑 + 验证通过 + 汇报完整 + 总指挥确凿分析 → P3；全部方向被证伪 → 回 P1 或退出 |
| **P3** | 漏洞利用开发与执行 | P2 确凿确认方向 | 候选 flag → P4；≥2 路失败且无 FACT 成功 → 回 P2 |
| **P4** | 验证与提交 | 候选 flag | 提交成功 → 结束；失败 → 回 P3 |

### 9.2 P1 侦查阶段

**目标**：对整道题有大致的、全面的、但不深入的了解（覆盖更多信息面，避免遗漏关键线索），**不能跳过**。

**分工策略**（三路方向互斥，领题时强制）：

| 风格 | P1 侦查任务 | 产出 |
|------|-------------|------|
| conservative | 系统性扫描：web_recon / binary_analyze / file_type，指纹/框架/源码结构/robots/备份文件 | 结构化情报（版本/框架/保护机制/文件类型/关键函数） |
| aggressive | 直接尝试攻击可能的方向：常见漏洞入口/边界输入快速试错 | **记录响应和报错**等信息（即使失败也记录），不追求一次成功 |
| innovative | 非常规信息挖掘：exiftool / strings / binwalk / 隐藏目录 / 注释 / 元数据 | "意外线索"，发散覆盖非主流攻击面 |

**侦查广度按难度定制**（领题 prompt 强制）：easy 收敛（只覆盖最小必要信息源，快速完成侦查进入 P2，不铺开大范围扫描）；medium 标准（常规信息源全覆盖）；hard 发散（全面覆盖所有可能信息源，深度挖掘，侦查阶段可适当延长，不急于进入 P2）。

**进度汇报机制**：三路各自独立侦查，但**每 5 步必须向总指挥汇报进度**（当前发现/下一步计划/是否卡死）；总指挥持续监控汇报流（`_STALE_REPORT_SECS=60s` 无进展信号），某路长时间无进展则介入调整。

**完成门槛（任务驱动 + 进度汇报驱动，非步数硬门槛）**：三路**全部**完成侦查并提交报告（recon_done，战略层 LLM 判断该路基础侦查已覆盖题目全貌）后，总指挥才整合所有信息生成**全局情报摘要**并确定**主方向**，正式进入 P2。

**P1 期间不确认主方向**（避免过早锁定方向，历史教训：三路全扎堆 basename 绕过）。

### 9.3 P2 漏洞识别与方向确认

**目标**：在 P1 了解的基础上尝试并初步深入，分**主方向**（最有把握）与**有可能方向**（备选），让不同解题器按不同策略探索对应方向。

**分工策略**：

| 风格 | P2 任务 | 关键规则 |
|------|---------|----------|
| aggressive | **快速深入主方向**：快速构造最小验证 payload，最快速度验证漏洞是否存在（优先效率，忽略部分细节） | 总指挥只能引导保守+激进（除非它们偏离方向），**不偏移主方向的具体小方向调控由战略层负责** |
| conservative | **稳步推进主方向**：同步验证同一方向，每步充分验证（检查保护/确认偏移/编写稳健脚本），捕捉激进遗漏的细节 | 与激进互补，作为解题核心 |
| innovative | **发散自主探索可能的方向**：不能深入主方向，只能在浅层搜集线索并向上汇报 | 总指挥只能给建议，不能强迫其深入主方向；创新浅层搜集线索汇报 → 总指挥判断可能性 → 可能性较高可下令深入 |

**主方向修改仅两种途径**：

1. 保守/激进在探索中**明确发现该方向错误**（证据确凿证伪）；
2. 创新在发散某个方向并得到总指挥**允许深入**后，**证实该方向为正确方向**。

若只是发现"有可能方向"，则加入**备选列表**，待主方向被证实错误后才考虑启用。

**进入 P3 的必要条件**：探索的一个方向有**足够的证据支撑，并取得了验证**（不是猜测）；此时**汇报要完整**（方向 + 验证证据，verified 汇报），总指挥进行**确凿分析**（`_p2_verify_direction`）后才能切换 P3。证据不足则不切换，保持 P2 继续探索。

### 9.4 P3 漏洞利用开发与执行

**目标**：在已验证的方向上完成 exploit 并获取 flag。

**分工策略**：

| 风格 | P3 任务 |
|------|---------|
| aggressive | **快速深入利用漏洞**：最快速度编写并运行 exploit（可能多次失败），每次失败后快速调整参数或替换小方向（如不同偏移、不同 ROP 链），不因单次失败而停下 |
| conservative | **搜集细节且严谨利用**：同步开发 exploit，更注重可靠性，会先验证关键地址、环境、依赖，确保一次成功率高 |
| innovative | **对该漏洞尝试创造性的利用方法**：在主利用方案之外，尝试非常规利用方式（如侧信道、竞态条件、替代路径），应对"脑洞"题 |

**关键规则**：

- **总指挥协调以引导为主**：除非**验证漏洞不存在**（需返回 P2 重新确认方向），否则总指挥不下发转向类 MUST 指令（代码层面：P3 阶段所有非"返回P2"的 MUST 自动降级为 SHOULD）。
- **所有避免死循环、调整方向的决策都必须由战略层做出**，总指挥不干预具体小方向。
- **卡住不停止**：激进型即使遇到阻碍，也不允许停止尝试，必须立即切换到另一个子方向（如换 ROP gadget、换 libc 版本）并继续。
- **P3 阶段不注入卡住/趋同规则信号**（死循环与方向调整由战略层负责，总指挥仅保留进程级无汇报监控）。

**回退机制（P3→P2）**：≥2 路报告失败/死路（fail_styles ≥ `_phase_p3_fail_threshold=2`）且无 FACT 成功 → 总指挥规则判定回退 P2，重新确认方向；回退时任务契约重置为 P2 策略。

### 9.5 P4 验证与提交

**目标**：确保 flag 正确，并提交。

- **所有风格**都会收到 flag 候选，但总指挥只允许**保守型**进行最终验证（因其最细致）；
- 提交前经 **Flag 验证系统**（代码机制 + LLM 审查）把关，验证通过后由系统统一提交；
- 若验证失败，则回退到 P3 继续利用。

### 9.6 阶段切换条件汇总（确凿性门槛）

| 切换 | 触发信号（客观） | 前置处理（LLM） |
|------|------------------|-----------------|
| P1→P2 | 三路全部 recon_done | `_p1_synthesize`：整合全局情报摘要 + 确定主方向 → 广播 P2 分工（附摘要） |
| P2→P3 | 存在 verified 汇报 | `_p2_verify_direction`：确凿分析（证据支撑/验证通过/汇报完整/反幻觉）→ confirmed 才切换 |
| P3→P4 | 汇报含 flag 候选 | - |
| P3→P2 | ≥2 路失败且无 FACT 成功 | 回退优先于前进；重新确认方向 |
| P4→P3 | 提交验证失败 | 外部反馈触发 |

> 校准说明：阶段切换**判定基于规则（客观汇报信号）**——进度/验证信号是客观事实，规则判定不会误判；LLM 只负责切换前后的**任务描述生成**（P1 摘要、P2 分工、P3 分工、确凿分析）。LLM 失败 → 保持当前阶段静默或走降级路径，不阻塞推进。

### 9.7 回退机制与任务重置

- **P3→P2**：激进+保守均报告 exploit 失败且无进展 → 总指挥评估方向 → 回退 P2，重新确认方向（任务契约重置为 P2 策略）。
- **P4→P3**：验证失败 → 回 P3。
- 回退时总指挥在 directive 中明确"**阶段已回退至 P2，重新确认漏洞方向**"。

### 9.8 各阶段汇报协议映射

| 阶段 | 战略层 → 总指挥 | 总指挥 → 战略层 |
|------|----------------|-----------------|
| P1 | progress（每 5 步）/ recon_done（侦查完成）/ clue / dead_end | 领题分工（P1 任务）/ 阶段提示 / 无进展介入调整 |
| P2 | verified（方向验证成功）/ clue / dead_end / question | P2 分工（附全局情报摘要）/ 主方向引导 / 创新发散建议 |
| P3 | dead_end（漏洞不存在信号）/ clue（flag 候选） | P3 分工（附已验证方向）/ 引导为主（转向类 MUST 降级 SHOULD） |
| P4 | clue（flag 候选） | P4 验证提示（保守型验证） |

### 9.9 阶段协调实际运行示例（基于历史复盘场景）

以下用 EasyP 题演示多阶段协调如何避免复盘中的五类问题：

| 复盘问题 | 旧雁阵行为 | WING-Corvus 多阶段协调行为 |
|----------|-----------|---------------------------|
| 路径趋同无干预 | 3 路全扎堆 basename 绕过 | 领题时三路方向互斥（创新被分配侧信道/非 ASCII 截断等非常规方向）；总指挥持续监控汇报流，检测到趋同信号注入 LLM 判断 |
| 创新未发散 | innovative 也深挖 basename 路径 | 创新风格 prompt 强制"发散优先，禁止过早深入"（无 FACT 级方向禁止深入）；战略层巡查对"过早深入"下发停止提示 |
| MUST 误判 | 总指挥 MUST"直接请求 /utils.php"（该路径已 404），战略层照单全收，agent 被迫重复执行 3 次 | ① MUST 必须有非空 reason（无依据自动降级 SHOULD）；② 战略层 MUST 本地冲突校验（本地已证实 404 → 降级 SHOULD + dead_end 回报） |
| 无回退机制 | 方向错误后持续空转到超时 | P3→P2 规则回退（≥2 路失败且无 FACT 成功）；任务契约重置为 P2 策略 |
| 卡住无干预 | 激进卡在 basename 细节无人管 | 卡住信号（主题相同+连续失败 ≥3）注入总指挥 LLM 判断；激进卡住 → MUST 换子方向（"不要停下来，立即切换"） |

**预期收益量化**（总指挥多阶段升级方案中的目标）：

| 收益 | 量化预期 |
|------|----------|
| 消除路径趋同 | 3 路主题重叠率 ↓（目标：无 2 路同时深挖同一子方向） |
| 提高 hard 题成功率 | hard 题解题率 ↑（当前 0% 部分 → 目标 ≥30%） |
| 降低无效步数 | 平均步数 ↓（历史复盘用 30 步空转 → 目标 ≤15 步无效步） |
| 创新价值释放 | 新增有效线索数 ↑（每题 ≥1 条兄弟可复用线索） |
| 卡住快速自救 | 单路卡死时间 ↓ |

**成本影响**：总指挥仍用 flash 模型（none 思考强度），每次 analyze 汇报才调用（约每 5s 轮询 + 有汇报才 LLM）；阶段标记走总线文本，无额外 token 压力。**预计总指挥开销增加 <5%**。

---

## 10. 版本演进：相对 WING-Goose 的更新

本章基于对 WING-Corvus 源码的逐行审计，列出相对 WING-Goose（雁阵）的全部更新及其价值。

### 10.1 新增文件清单

| 文件 | 内容 | 价值 |
|------|------|------|
| `ctf_agent/commander/__init__.py` | 总指挥包导出 | 模块化组织 |
| `ctf_agent/commander/commander.py` | 总指挥核心类（约 1100 行） | 三层协作的顶层指挥 |
| `ctf_agent/commander/prompts.py` | 总指挥 5 个 prompt 模板 | 指挥决策的 LLM 依据 |
| `ctf_agent/agent/flag_verify.py` | 反幻觉 flag 验证系统（约 246 行） | 拦截外部题解污染 |

### 10.2 总指挥 Commander（新增）

**领题分工（assign_initial）**：LLM 任务分解 + 按风格分工，产出任务契约（task_no 统一编号、三路方向互斥、P1 阶段标记、难度定制侦查广度、解题合规约束）。价值：从"三路自由开局"升级为"总指挥统一领题"，从源头避免路径趋同。

**汇报消费（consume_reports）**：游标消费六类汇报（clue/dead_end/question/progress/recon_done/verified），只聚合 FACT/LIKELY 摘要进上下文。价值：总指挥决策只基于高置信度事实摘要，控制 token 且反幻觉。

**LLM 分析（analyze_reports）**：注入阶段+策略/任务契约/主方向/历史上下文/新汇报/规则信号，LLM 输出 silent/directives/main_direction/alt_directions 等。价值：全局方向校准 + 主方向管理 + 静默原则。

**指令下发（post_directives）**：带 priority（MUST/SHOULD）与 phase 阶段标记。价值：指令分级明确强制力，阶段随指令下发供战略层感知。

**多阶段状态机（_phase_advance_rule）**：P1→P2→P3→P4 规则驱动切换（三路全部 recon_done / verified + 确凿分析 / flag 候选），含 P3→P2 回退。价值：**解决 "方向错误后无回退机制，持续空转到超时"问题**。

**主方向与备选方向管理（_update_directions_from_llm）**：主方向修改仅两种途径（保守/激进证伪；创新经允许深入证实），P1 期间不确认主方向。价值：防止过早锁定方向 + 防止主方向随意漂移。

**P1 全局情报摘要整合（_p1_synthesize）**：三路侦查完成后 LLM 汇总全局情报摘要 + 确定主方向 + 广播 P2 分工（附摘要）。价值：P2 所有解题器有统一的"题目全貌"工作基础。

**P2→P3 确凿校验（_p2_verify_direction）**：对 verified 汇报做确凿分析（证据支撑/验证通过/汇报完整/反幻觉）。价值：防止仅凭 POSSIBLE 猜测或单条 FACT 线索就切换 P3（"阶段切换需确凿"落地）。

**规则检测降级为 LLM 参考信号**：趋同（Jaccard 重叠 ≥0.4）/ 卡住（主题相同+连续失败 ≥3）检测结果注入 analyze prompt 由 LLM 判断是否干预；P3 阶段不注入卡住/趋同信号。价值：**避免死板代码误判**（如把系统性验证误判为死循环），同时保留规则层的客观事实感知。

**MUST 依据门槛**：无 reason 的 MUST 自动降级 SHOULD。价值：**解决 "MUST 误判"问题**（总指挥 MUST"直接请求 /utils.php"但该路径已被证实空/404）。

**P3 转向类 MUST 降级**：P3 阶段所有非"返回P2"的 MUST 降级 SHOULD。价值：落实"P3 协调以引导为主，方向调整由战略层负责"。

**修复 P3 阶段 NameError bug**（2026-08-05 代码审计发现）：此前 `analyze_reports` 中 P3 降级逻辑在 raw 赋值前引用 raw，NameError 导致 P3 阶段 analyze_reports 异常 → 总指挥在 P3 静默失效。修复后 P3 阶段总指挥恢复正常工作。

### 10.3 战略层 Coordinator（新增能力）

**任务契约（set_task_contract）**：总指挥注入/更新任务契约（task_no/task/priority）。价值：战略层始终知道当前任务方向，汇报带任务编号。

**汇报家族（report_to_commander / report_progress / report_recon_done / report_verified / report_dead_end）**：五类主动汇报 + 通用汇报。价值：总指挥决策所需的客观信号全部有来源。

**P1 每 5 步进度汇报（report_p1_progress_if_due）**：主循环调用，内容自动提取（发现/计划/是否卡死）。价值：**任务驱动 + 进度汇报驱动**的监控侧——总指挥可判断某路是否卡死并及时介入。

**指令消费 + MUST 本地冲突校验（check_commander_directives）**：每步检查，MUST 与本地已验证死路冲突时降级 SHOULD + 事后回报。价值：**解决 "战略层照单全收总指挥 MUST"问题**——本地证据优先，总指挥不强制执行已证伪方向。

**阶段感知（_phase_task_block）**：按阶段注入不同巡查任务（P1 侦查完整性 / P2 主方向小方向调控 / P3 死循环与方向调整 / P4 flag 验证）。价值：战略层的巡查侧重随阶段变化，职责精准匹配。**修复了该方法"从未定义导致 P1 阶段巡查每次抛 AttributeError 降级为不干预"的 bug**。

**巡查 LLM 输出 p1_done / p2_verified 信号**：LLM 判断侦查完成/方向验证成功 → 自动汇报 recon_done / verified。价值：阶段切换的"确凿信号"由最了解本路情况的战略层 LLM 产生。

**死路自动切换（report_dead_end + on_tool_error）**：环境缺失类错误连续 2 次判定死路 → 自动切换（按风格差异化）+ 事后汇报。价值：不等待总指挥轮询，快速自救。

### 10.4 战术层 ReAct（新增接线）

- **每步 check_commander_directives**：总指挥指令立即注入（MUST 持久重复机制，优先级高于巡查输出）。价值：总指挥干预实时生效。
- **每 5 步 P1 进度汇报**：`report_p1_progress_if_due` 由主循环调用。价值：P1 侦查进度实时上报。
- **Flag 验证接入**：Final 提交前 `FlagVerifier.verify` 双通道把关。价值：拦截外部题解污染与幻觉 flag。
- **max_format_errors 3→5**：并发多 agent 抢 LLM API 时输出质量波动，5 次容错 + 重试注入更稳。价值：hard 并发测试 5/6 题各有一路"连续 3 次格式解析失败"，放宽后减少误杀。

### 10.5 消息总线总指挥协议（bus/file_bus.py 新增）

- `post_report / check_reports`：战略层 → 总指挥（六类 report_type）。价值：上下级汇报通道。
- `post_directive / check_directives`：总指挥 → 战略层（priority + phase）。价值：指令下发通道，阶段随指令同步。
- 与 finding 总线同空间 seq 递增、游标推进。价值：单一文件统一消息序列，消费侧幂等。

### 10.6 Flag 验证系统（agent/flag_verify.py 新增）

- 代码机制：flag 必须出现在某步 Observation + 可疑渠道拦截（GitHub/writeup 关键词双命中拒绝）。
- LLM 审查：最近轨迹交给审查 LLM 判定 flag 来源。
- 价值：**解决 hard5 复盘问题**——agent 通过 GitHub API 抓取官方 writeup.md 获得 flag 直接提交，现有"至少 1 次工具调用"兜底无法拦截。

### 10.7 配平花括号 JSON 提取（tools/base.py / agent/react.py）

`_extract_balanced_json`：状态机扫描首个 `{` 起，跳过字符串内 `{}/转义引号` 与嵌套 `{}`，提取配平完整 JSON 对象。价值：**修复 LLM JSON 后跟含 {} 文本的解析失败**（threshold 22 条"Thought 混入 action_input"报告实证）；`_clean_action_input` 配套（尾逗号/单引号容错）。

### 10.8 其他小优化（代码审计发现）

| 位置 | 优化 | 价值 |
|------|------|------|
| swarm.py | join 所有线程共享同一 deadline 并行等待 | 修复"3 路 × 540s = 1620s 累计等待"导致"未及时 kill" |
| swarm.py | `_kill_tree` Windows 用 taskkill /F /T | 杀主进程+子孙进程，防止孙进程残留阻塞 readline |
| swarm.py | 总指挥初始化放后台线程 | 修复"卡在'总指挥模式：3 风格并行'后无 worker 日志"的开局停滞 |
| swarm.py | 注入实际风格列表到 task | 避免 Commander DEFAULT_STYLES 与调用方显式 styles 不一致 |
| commander.py | `_STALE_REPORT_SECS=60s` 无进展信号 | 任务驱动+进度汇报驱动的监控侧实现 |
| commander.py | 主题提取三级策略（英文 token/中文预置词/n-gram 兜底） | 解决短中文汇报提取不到主题词的问题 |
| coordinator.py | `first_check` 10→5 | 简单题可能 <10 步解出，首次巡查提前 |
| coordinator.py | RAG/Skill 匹配文本从 task_desc 改为轨迹观测 | 修复题目混淆（ouroboros 匹配到 MPEG 题）；经验匹配在侦查产生观测后进行 |
| react.py | RAG 延迟到侦查阶段后基于实际观测注入 | 取代任务开始时基于 task 描述的静态匹配（防题目混淆根因） |
| routed.py | go 端点 reasoning_effort 强制 none | 修复 go 端点思考链无界生成撞满 max_tokens（9 组受控实验定论） |
| routed.py | LLM_PROVIDER=go 只走 go 套餐，禁系统代理直连 | 国内部署直连快且稳定（历史复盘：走代理每步 LLM 卡 90s+） |

### 10.9 演进验证与验收清单

| 验收项 | 方法 | 通过标准 |
|--------|------|----------|
| 阶段状态机 | 单元测试（纯规则可测） | 阶段在 P1 起步，按汇报证据正确迁移（P1→P2→P3→P4，含 P3→P2 回退） |
| 方向趋同检测 | 构造汇报序列单测 | 主题重叠 ≥0.4 时正确产生趋同信号 |
| 卡住检测 | 构造汇报序列单测 | 主题相同 + 连续失败 ≥3 时正确产生卡住信号 |
| 领题分工 | prompt 解析单测 | assignments 覆盖全部风格、每路一个、task_no 从 1 开始 |
| P1 汇总 | prompt 解析单测 | 输出 summary/main_direction/alt_directions 字段 |
| P2 校验 | prompt 解析单测 | 输出 confirmed/direction_summary/reasoning 字段 |
| 回归验证 | 重跑历史复盘 (EasyP) | 对比阶段分配日志：应看到 P1→P2→P3 切换 + 创新型被强制发散 |
| Benchmark | 选取 2-3 道 hard 题（含之前失败的 Skip32） | 对比解题率/时间有明显改善 |
| 总指挥降级 | 关闭 LLM / 移除 bus_dir | 自动降级回雁阵，三路照常求解，行为不变 |

### 10.10 关键数据流路径清单

| 数据流 | 路径 |
|--------|------|
| 领题分工 | `SwarmCoordinator._async_commander_setup` → `_setup_commander` → `Commander.assign_initial` → `bus.post_directive`（phase=P1） |
| 战略层汇报 | `Coordinator.report_*` → `bus.post_report` → `Commander.consume_reports` → `_update_style_reports` |
| 总指挥决策 | `Commander.run_once` → `_phase_advance_rule` / `analyze_reports` → `post_directives` |
| 指令消费 | `react.py` 每步 → `Coordinator.check_commander_directives` → `set_task_contract` + 注入 guidance |
| P1 进度 | `react.py` 每 5 步 → `Coordinator.report_p1_progress_if_due` → `report_progress` → 总线 |
| 侦查完成 | 巡查 LLM 输出 p1_done → `Coordinator.report_recon_done` → 总线 → 总指挥 `_p1_synthesize` |
| 方向验证 | 巡查 LLM 输出 p2_verified → `Coordinator.report_verified` → 总线 → 总指挥 `_p2_verify_direction` |
| 兄弟共享 | 巡查 belief_state FACT/LIKELY → `react._post_to_bus` → `bus.post` → 兄弟每 5 步 `check_sanitized` |
| flag 提交 | `react.py` Final → 反幻觉兜底 → `FlagVerifier.verify` → `submission_handler` → swarm `_on_submission` → kill 兄弟 |

---

## 11. 消息总线设计

### 11.1 总览

`ctf_agent/bus/file_bus.py`（约 300 行）实现跨进程共享文件总线：每个 challenge 一个 JSONL 文件，原子 append，游标消费。三类消息在同一 seq 空间递增：

| kind | 方向 | 方法 | 用途 |
|------|------|------|------|
| report | 战略层 → 总指挥 | `post_report` / `check_reports` | 六类汇报（clue/dead_end/question/progress/recon_done/verified） |
| directive | 总指挥 → 战略层 | `post_directive` / `check_directives` | 方向指令（priority + phase + task_no + reason） |
| finding | 兄弟 agent 之间 | `post_finding` / `check_findings` | 高置信度发现共享（share_finding / check_findings 工具） |

### 11.2 游标消费机制

- `_read_kind(task_id, kind, cursor)`：按 kind 读取 seq > cursor 的新消息（升序）；**new_cursor 按该 kind 的全局 max seq 推进**——即使过滤后为空也推进，避免重复读取旧消息。
- 总指挥 `check_reports` / 战略层 `check_directives` / 战术层 `check_findings` 各自维护游标。
- 战略层 `check_directives` 支持 `agent_id` 过滤（只取发给自己的）；`agent_id=None` 返回全部（供调试）。

### 11.3 传播策略与内容消毒

- **分级过滤**：只传播高置信度发现（FACT/LIKELY），低置信度（POSSIBLE）不传播（防误导）。
- **内容消毒**（`sanitize_content`，T4 优化）：命令级具体线索提炼为方向性线索，避免 agent 反复验证细节：
  1. 移除 URL 查询参数（保留路径）；
  2. 移除具体 SQL/payload 片段（保留技术名称）；
  3. 移除具体 IP:端口（替换为 `<target>`）；
  4. 限制 200 字符。
- 原始消息保留在文件中（供调试），注入用消毒版本（`check_sanitized`）。

### 11.4 双向通信（WING-Corvus）

- **post 端**：`react.py` 的 `_post_to_bus` 将巡查 belief_state 的 FACT/LIKELY 发布到总线（只传播前两级，topic=coordinator）；FACT 级同时同步上报总指挥（report_type=clue）。
- **check 端**：战术层每 5 步 `check_sanitized` 拉取兄弟发现注入 prompt（`[兄弟发现] 其他并行 agent 已发现以下方向性线索 (仅作参考方向, 需自行探索验证)`）。
- 强制回答机制：检测来自兄弟且本 agent 尚未回答的提问（kind=question），强制回答（即使"不知道"），防止提问方卡死等待。

### 11.5 总线安全

- 题目 id 归一化文件名（`/` `\` → `_`），防止路径注入。
- 全部写操作持锁（threading.Lock），原子 append。
- 所有读操作异常兜底（文件不存在返回空、JSON 解析失败跳过该行）。

---

## 12. 记忆层与知识体系

### 12.1 四层记忆架构

| 层 | 实现 | 作用域 | 用途 |
|----|------|--------|------|
| 短期记忆 | `ShortTermMemory` | 单题单 agent | ReAct 对话消息管理 + 滑动窗口裁剪（max_rounds） |
| 中期记忆 | `MidTermMemory` | 单题 | RememberFactTool 记录关键事实，注入 system prompt |
| 长期记忆 | `LongTermMemory`（chroma 向量库） | 跨题 | RAG 检索历史 writeup（去标识化沉淀） |
| Skill 库 | `SkillLibrary` + 经验库 | 跨题 | 可复用解题套路（持续学习积累） |

### 12.2 RAG 检索策略（校准）

**延迟注入**：RAG（历史 writeup）不再在任务开始时基于 task 描述（极简题面）静态匹配——题面仅含 flag 格式+地址时，静态匹配会命中无关套路（题目混淆根因，如 ouroboros 匹配到 MPEG 题）。改为**侦查阶段后**（step_no ≥8，每 8 步）基于**轨迹实际观测**（最近 6 步 observation 累积）检索注入：

```
recent_obs = [task] + [s.observation for s in steps[-6:]]
obs_text = "\n".join(recent_obs)[:1500]
rag_hint = retriever.retrieve(obs_text)   # 注入 "[历史经验参考] ...(仅作思路参考, 非答案)"
```

巡查器的 `_query_knowledge` 同理：匹配文本从 task_desc 改为轨迹观测（仅当轨迹为空——首次巡查无观测——才退化用 task_desc）。直接调用底层 API（`long_term.search`），不用 RAGRetriever（避免 HyDE 的额外 LLM 调用，省 token + 低延迟）。

### 12.3 Skill 库与经验库

- **Skill 库**（`SkillLibrary`，持续学习）：解题时注入相关技能；每 8 步基于累积 observation mid-solve 动态注入（`format_for_mid_solve`）。
- **经验库**（skill_library.json，抽象解题方法 + 禁忌）：mid-solve 动态注入（10 步冷却，去重）；巡查器基于 recon_steps 判断方向、基于 notes（禁忌）纠正错误；confidence 规则：仅 high 经验可触发 [MUST] 纠正，medium/low 仅作参考。
- ****：解题前静态注入默认关闭（题目混淆根因）；所有经验延后到侦查阶段完成后基于实际观测做 mid-solve 动态注入。

### 12.4 失败轨迹缓存与演化反思

`FailedTrajectoryCache`：

- 失败时自动存储 trajectory + 自动触发 `reflect()` 生成反思；
- 下次跑同 challenge_id 时注入失败历史提示 + 反思提示 + (type, difficulty) 级通用提示；
- 成功后清理失败历史（避免污染未来重跑）。

---

## 13. 工具层设计

### 13.1 工具契约

`ctf_agent/tools/base.py`：每个工具接收 JSON 字符串形式的 Action Input，返回字符串形式的 Observation。工具内部异常被捕获并转为 ERROR 前缀字符串，避免打断 ReAct 循环。

### 13.2 配平花括号 JSON 解析（_extract_balanced_json / _robust_json_loads）

核心修复：状态机扫描首个 `{` 起，跳过字符串内 `{}/转义引号` 与嵌套 `{}`，提取配平完整的 JSON 对象。`_robust_json_loads` 逐级降级：① 原样/修复尾随逗号 → ② 配平花括号提取 → ③ 去 markdown 装饰。

### 13.3 工具清单（按题型划分）

| 题型 | 工具示例 |
|------|----------|
| 通用执行 | ssh_exec / ssh_python / docker_exec / docker_python / ssh_upload / docker_upload / file_read / file_analyze |
| Web | http_request / web_recon / web_fingerprint / web_dirscan / lfi_scanner / sqlmap（总线） / encoding_helper |
| Pwn | pwn_checksec / pwn_cyclic / pwn_ropgadget / pwn_exploit / exploit_template |
| Reverse | angr_symbolic_exec / binary_analyze / binary_tool / apk_decompile / feistel_tool / mem_xor_analyze |
| Crypto | crypto_rsa / crypto_classic / des_cryptanalysis / feistel_decrypt / ecdsa_nonce_reuse / sage_common_d_attack |
| Misc/Forensics | osint_exiftool / osint_steghide / osint_binwalk / osint_tshark / vision_analyze / ocr / mem_xor_tool |
| OSINT | web_search / osm_geocode / reverse_image_search / vision_analyze |
| 协作 | share_finding / check_findings（总线）/ shared_fs_tool（共享文件目录） |
| 记忆 | remember_fact（中期记忆） |

### 13.4 Docker 执行链（WING-Goose Item 5）

- `DOCKER_ENABLED=true`（默认）→ Docker Desktop 容器替代 ssh 执行层；daemon 不可用自动降级到 ssh；KALI_ENABLED=false（默认）时关闭 Kali 路由，纯 Docker 执行层。
- 默认镜像 `wing-goose:v2`（补装 fpylll/angr/torch 等 6 库 + 预封装入口）；v1 以 latest 标签保留作为回滚点。
- 多容器：每 agent 独立容器（容器名按题参数化 `wing-goose-<agent_id>`，同题复用/异题隔离）；显式配置 DOCKER_CONTAINER 尊重单容器模式。
- 资源调控 Profile：light(1核/1G) / normal(2核/2G) / brute(4核/2G) / heavy(4核/4G)；最大并发容器数 + 预留因子。
- 附件宿主目录 → 容器 `/challenge/workspace`；同题共享目录 → 容器 `/shared`；`force_reset=true` 强制全新环境。

## 14. LLM 路由与容错

### 14.1 路由层级

`ctf_agent/llm/routed.py`（约 530 行）实现带模型路由的 LLM 客户端 `RoutedLLMClient`，flash 模式路由链：

```
zen(免费 flash-free) → go(付费 flash, 无峰谷) → 官方 flash → pro(官方 flash, deprecated)
```

WING-Goose（2026-08）起 `LLM_PROVIDER=go`（默认）时：**只走 go 套餐，go 失败直接抛错（禁用官方/pro 降级链）**——go 国内部署直连，领题前冒烟已保证 ≤10s 响应；`LLM_PROVIDER=auto` 保留 zen→go→官方→pro 三级降级（调试期）。

### 14.2 动态 provider 健康状态

冒烟测试标记不是"终身制"：中途 API 故障（限流/挂起）时实时降级，恢复后自动重新尝试。

- 连续失败达阈值（`_PROVIDER_FAIL_THRESHOLD=2`）→ 标记 down + 进入跳过期（`_PROVIDER_SKIP_AFTER_FAIL=120s`）；
- 调用成功 → 标记 up，立即恢复；
- 距上次失败超过 `_PROVIDER_RESET_SECONDS=60s` → 计数清零（视为新的一轮）；
- 避免"冒烟测试通过 → 中途 fallback 挂起 → 每次调用死等 30s×3 重试"的卡死。

### 14.3 超时体系（多层防护）

| 层级 | 值 | 目的 |
|------|-----|------|
| zen 客户端级超时 | 45s（v5: httpx.Timeout 防卡死） | 避免误杀正常请求 |
| go 客户端级超时 | 90s（45→90: thinking 长推理常超 45s，45s 硬超时触发 3 轮重试链白扔 ~139s） | 长思考一次成功 |
| fallback 客户端级超时 | 30s（60→30: 加速半死连接暴露） | 配合 no_progress 兜底 |
| wall-clock 总超时 | 45s 通用 / go 90s | **慢速流（slow-drip streaming）绕过 httpx read timeout，ssl.read 无限阻塞**——daemon 线程 + join(timeout) 应用层总超时，超时即放弃该请求 |
| 系统代理 | `proxy=None, trust_env=False`（全部 client） | 国内部署模型必须直连（禁系统代理），走代理绕境外 IP 导致请求慢/超时（历史复盘：每步 LLM 卡 90s+） |

### 14.4 思考模式注入

`enable_thinking_mode=true`（默认）时按难度注入 reasoning_effort（high/max）：

- **LLM_PROVIDER=go**：`reasoning_effort="none"`（强制）——go 端点为 Agent 类请求，思考链强制无界生成，非 none 的 effort 一律撞满 max_tokens（74-86s/次, content=0），唯一可控档 = none（推理由 ReAct Thought 承担）；
- **非 go 提供方**：按 `_thinking_extra` 优先级注入 effort + `extra_body={"thinking": {"type": "enabled"}}`。

### 14.5 冒烟测试

- `smoke_test(timeout=10s)`：冲榜场景下 LLM API 不可用时，与其让每次调用等 45s*3 超时重试，不如启动前/领题前快速探测，只调用可用的 provider；
- `apply_smoke_results` / `apply_smoke_from_file`：应用冒烟标记（agent 子进程启动时从 `data/api_smoke.json` 读取）；
- go-only 模式只探测 go（不浪费 10s×N 探测其他 provider）。

### 14.6 LLM 调用异常容错（战术层）

`react.py` 每步 LLM 调用三级容错：① 失败 → sleep(2) 重试 → ② 再失败 → sleep(2) 再重试 → ③ 降级 `model_tier="pro"` 重试 → ④ 全部失败 → 注入提示跳过本步继续（不崩溃，breaker 熔断兜底）。

---

## 15. 熔断机制

### 15.1 六维熔断（CircuitBreaker）

`ctf_agent/orchestrator/breaker.py` 实现六维熔断：

| 维度 | 阈值（默认） | 动作 |
|------|-------------|------|
| 时间限制 | 单任务 >30 分钟（MAX_TASK_TIME=1800） | 终止 |
| 重复动作 | 同一 (action, action_input) 重复 >3 次 | 注入"切换策略"提示 |
| 思维死锁 | LLM 连续 5 轮输出相同 Thought | 注入"跳出循环"提示 |
| 步数限制 | ReAct 循环步数 > 阈值（MAX_STEPS=80，从 50 上调） | 终止 |
| 成本限制 | API 累计消耗 > $1.5（MAX_COST_LIMIT） | 终止 |
| 文件膨胀 | SSH 工作目录 > 1GB | 注入"清理临时文件"提示 |

### 15.2 自适应熔断（AdaptiveBreaker）

`orchestrator/adaptive.py` 按题型+难度动态调整阈值（`_dynamic_max_steps`）；进度感知宽限期（`has_recent_progress`）——超过 max_steps 后持续有实质进展则继续，无进展才兜底退出；`extend_steps()` 供巡查器建议加步。

### 15.3 熔断器与主循环的交互

- 每步 `breaker.check(step)` → `should_terminate`（返回失败结果，含失败轨迹缓存）/ `should_inject_hint`（注入提示到下一轮 observation）；
- 每次 LLM 调用后 `breaker.record_llm_call(tokens, model)`（成本熔断输入）；
- 任务开始时 `breaker.reset()`。

---

## 16. 轨迹复盘与自学习

### 16.1 双通道自学习

- **`_learn()`（模板生成，快速，不调 LLM，每题都跑）**：从本轮结果提炼 Skill（成功→套路，失败→避坑）。
- **`_review()`（LLM 深度复盘，高质量，仅步数 ≥8 时跑）**：`TrajectoryReviewer`（`ctf_agent/review.py`）独立上下文复盘轨迹。

### 16.2 复盘流程（review.py）

`TrajectoryReviewer.review(trajectories)`：

1. **独立上下文**：LLM 只读轨迹文本，不看解题过程内部状态；
2. 提取三样输出：`facts`（可核验的事实，标注来源：轨迹名+步骤号）/ `lessons`（有效/无效操作总结）/ `skills`（可复用技能，2-3 条，面向未来同类题可直接照做，必须只用轨迹中出现过的技术）；
3. **无幻觉核对**：逐条核对 facts 中的实体是否在轨迹中出现（`hallucination_check.no_hallucination`）；
4. **可选入库**：`no_hallucination=true` 且 skill_count>0 → `ingest_skills` 入 md 技能库（和/或经验库）；检测到幻觉 → skill 未入库。

### 16.3 持续学习闭环

- 解题成功 → `ingest_solution` 去标识化写入长期记忆（LTM）→ RAG 后续同类题开局可检索到"自己解过的题"（flag 已隐去）；
- Skill 库 `prune()` 自我迭代：控制规模，避免臃肿；
- 失败 → 失败轨迹缓存 + 演化反思。

---

## 17. 数据设计

### 17.1 目录布局

```
WING-Corvus/
├── ctf_agent/                # 源码包
│   ├── commander/            # 总指挥（commander.py + prompts.py）
│   ├── agent/                # 战术层（react.py）+ 战略层（coordinator.py）+ flag_verify.py + styles.py
│   ├── bus/                  # 消息总线（file_bus.py + message_bus.py）
│   ├── cli/                  # CLI runner
│   ├── knowledge/            # Kali 武器库
│   ├── llm/                  # LLM 客户端（client.py + routed.py）
│   ├── memory/               # 记忆层（short/mid/long_term + rag + skill_library）
│   ├── orchestrator/         # 编排（adaptive.py + breaker.py + state.py）
│   ├── range/                # 本地靶场（catalog/compose/flag/manager/tool）
│   ├── skills/               # 经验库（injector/library/skill）
│   ├── ssh/                  # SSH 客户端（client.py + safety.py）
│   ├── tools/                # 工具层（30+ 工具）
│   ├── web/                  # WebUI
│   ├── swarm.py              # 多风格并行编排 + 总指挥生命周期
│   ├── solve.py              # 子进程求解入口（JSONL 协议）
│   ├── config.py             # 配置加载（pydantic-settings）
│   ├── review.py             # 轨迹复盘
│   ├── skill_learner.py      # Skill 学习
│   ├── experience.py         # 经验沉淀
│   └── ...（analyzer/events/stop_signal/client.py 等）
├── data/
│   ├── chroma/               # 向量库（RAG）
│   ├── skills/               # Skill 库（index.json）
│   ├── agent_share/          # 同题共享文件目录
│   └── swarm_tasks/          # swarm task JSON 临时目录
├── main.py                   # CLI 入口
├── pyproject.toml            # 项目配置
└── .env.example              # 环境变量模板
```

### 17.2 总线文件格式（JSONL）

每 challenge 一个 `<challenge_id>.jsonl`，三类消息同空间 seq 递增：

```json
{"ts": 1754352000.0, "agent": "conservative", "task_id": "task_001", "content": "...", "kind": "report", "report_type": "clue", "level": "FACT", "task_no": 1, "seq": 3}
{"ts": 1754352005.0, "agent": "aggressive", "task_id": "task_001", "content": "...", "kind": "directive", "priority": "SHOULD", "task_no": 2, "reason": "...", "phase": "P2", "seq": 4}
```

### 17.3 solve.py 子进程协议（JSONL）

- **输入**：task JSON 文件（challenge_id/title/desc/type/difficulty/max_steps/max_seconds/max_submissions/style/bus_dir/bus_challenge_id/commander_enabled 等）。
- **输出（stdout JSONL）**：`start` / `log` / `step` / `heartbeat`（每 15s）/ `coordinator`（巡查详情）/ `submission` / `result`。
- **输入（stdin JSONL）**：`{"correct":bool,"feedback":...}`（submission 响应）/ `{"control":"stop"}`。
- 协议版本 1.1；stdin 统一分发器避免 stop-listener 和 submission-handler 竞争 stdin（同时解决 Windows selectors 不能注册 stdin 的问题）。

### 17.4 状态数据

- `TaskStatus`（orchestrator/state.py）：任务执行状态（executing/done/failed）；
- `_solved`（swarm）：已解出 flag + winner style；
- 失败轨迹缓存：失败时存储，成功后清理。

---

## 18. 部署与运维

### 18.1 环境要求

- Python ≥3.10；
- 依赖：openai>=1.40 / httpx>=0.27 / python-dotenv>=1.0 / pydantic>=2.6 / pydantic-settings>=2.2 / rich>=13.7（docker 后端额外 docker>=7.0）；
- 执行层二选一：Docker Desktop（默认，DOCKER_ENABLED=true）+ wing-goose:v2 镜像；或 Kali SSH（KALI_ENABLED=true 时启用）；
- LLM API：至少配置 go 套餐（推荐）或 zen/官方 flash。

### 18.2 安装步骤

```bash
# 1. 安装依赖
pip install -e ".[docker]"          # 或 pip install -e .（无 docker 后端）

# 2. 配置环境变量
cp .env.example .env                # 编辑 .env 填写 API Key 等

# 3. （可选）构建 Docker 镜像
docker build -f scripts/docker_test/Dockerfile.wing-goose -t wing-goose:v2 .

# 4. 冒烟验证（可选）
python -c "from ctf_agent.llm.routed import RoutedLLMClient; from ctf_agent.config import get_settings; print(RoutedLLMClient(get_settings()).smoke_test())"
```

### 18.3 运行模式

| 模式 | 命令 | 说明 |
|------|------|------|
| 单题单 agent | `python main.py run --target URL --desc "..."` | CLI 入口，run/web 子命令 |
| swarm 并行 | 通过调用器（NSS Runner）以子进程方式调 `python -m ctf_agent.solve --task-file <path>` | 每路一个子进程 |
| WebUI | `python main.py web --host 127.0.0.1 --port 8000` | 浏览器交互 |

### 18.4 运维要点

- **日志**：LOG_LEVEL 控制；swarm 场景每路 stdout JSONL；总指挥生命周期日志经 on_commander 回调输出；
- **总线文件清理**：`bus.clear()` 可清空单题或全部总线；
- **容器资源**：docker_cpu_profile / docker_max_containers / docker_reserve_cpu / docker_reserve_ram 调控并发与预留；
- **故障恢复**：总指挥降级回雁阵、LLM provider 动态跳过期、breaker 兜底——单点故障不影响整题运行。

---

## 19. 安全与伦理

### 19.1 反幻觉设计（多层防线）

| 层 | 机制 |
|----|------|
| 提交层 | Flag 验证系统：flag 必须出现在工具观测 + 可疑渠道拦截 + LLM 轨迹审查 |
| ReAct 层 | 无工具调用直接 Final = 幻觉拒绝（强制 ≥1 次工具调用） |
| 决策层 | 证据分级（FACT/LIKELY 才可 MUST）；无充分证据禁止否定方向 |
| 总指挥层 | 只读 FACT/LIKELY 摘要，不读轨迹全文；未汇报内容不得作为依据 |
| 复盘层 | 无幻觉核对（facts 实体必须在轨迹中出现），检测到幻觉 skill 不入库 |

### 19.2 外部题解污染防护

- 领题 prompt 强制解题合规约束（严禁上网搜索题解/读取官方 writeup/查询 flags.txt）；
- Flag 验证可疑渠道拦截（GitHub/raw.githubusercontent/api.github/gist/gitlab/writeup/solver/exploit-db/ctftime + 关键词双命中）；
- LLM 轨迹审查判定 flag 是否来自靶机/附件真实观测。

### 19.3 目标系统安全

- 全部攻击动作仅针对用户授权的 CTF 靶机/附件；
- 不包含对真实互联网系统的攻击能力配置（工具集面向靶场设计）；
- range 工具（本地靶场控制）在竞赛场景被禁用（`enable_range=False`，任务描述已禁止）。

### 19.4 数据与隐私

- RAG 沉淀去标识化（flag 隐去）；
- API Key 通过 .env 管理，不写入代码/日志；
- 总线共享目录仅限同题 agent。

### 19.5 伦理边界

- 系统仅用于 CTF 竞赛、安全教学与授权的渗透测试环境；
- 不提供绕过授权、非法入侵等用途的指导；使用者在法律允许范围内使用。

## 20. 使用方法

### 20.1 环境准备

1. **Python 环境**：Python ≥3.10；建议虚拟环境（venv/conda）。
2. **安装依赖**：
   ```bash
   cd WING-Corvus
   pip install -e ".[docker]"        # 推荐（含 docker-py）；纯内置工具可 pip install -e .
   ```
3. **Docker 执行层（推荐默认）**：
   - 安装并启动 Docker Desktop；
   - 准备 `wing-goose:v2` 镜像（若 `DOCKER_BUILD_ON_MISSING=true` 会自动构建；否则手动构建或改用已有镜像）。
4. **LLM API**：
   - 推荐：Opencode go 套餐（`GO_API_KEY` + `GO_BASE_URL=https://opencode.ai/zen/go/v1`），国内部署直连快且稳定；
   - 备选：zen 免费层 / 官方 deepseek flash（FALLBACK_*）；
   - 配置后可用冒烟测试验证：`python -c "from ctf_agent.llm.routed import RoutedLLMClient; from ctf_agent.config import get_settings; print(RoutedLLMClient(get_settings()).smoke_test())"`。
5. **创建 .env**：`cp .env.example .env`，按 20.2 逐字段填写。

### 20.2 .env 配置说明（逐字段）

#### LLM 配置

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `OPENAI_API_KEY` | 空 | 兼容旧配置；`has_llm_config()` 据此判断 LLM 是否已配置 |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | 兼容旧配置 |
| `PLANNER_MODEL` | `gpt-4o` | Planner 拆解模型 |
| `EXECUTOR_MODEL` | `deepseek-chat` | 执行模型 |

#### 模型路由（opencode zen/go + 官方 flash）

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `ZEN_API_KEY` / `ZEN_BASE_URL` / `ZEN_MODEL` | 空 / `https://opencode.ai/zen/v1` / `deepseek-v4-flash-free` | zen 免费层（flash-free） |
| `DISABLE_ZEN` | `true` | 关闭 zen 免费层 → 直接路由至 go（默认开启，调试期避免免费层不稳定干扰） |
| `GO_API_KEY` / `GO_BASE_URL` / `GO_MODEL` | 空 / `https://opencode.ai/zen/go/v1` / `deepseek-v4-flash` | **go 付费层（推荐主用）**，定价与官方一致且无峰谷收费倍率 |
| `FALLBACK_API_KEY` / `FALLBACK_BASE_URL` / `FALLBACK_MODEL` | 空 / `https://api.deepseek.com/v1` / `deepseek-v4-flash` | 官方 flash 兜底 |
| `LLM_MAX_RETRIES` | 2 | 每次 provider 失败后重试次数 |
| `LLM_PROVIDER` | `go` | **模型路由模式**：`go`=只走 go 套餐（国内部署直连快、冲榜稳定）；`auto`=zen→go→官方→pro 三级降级（调试期保留） |

#### 思考模式

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `ENABLE_THINKING_MODE` | `true` | 启用后模型先输出思维链再输出最终回答（deepseek-v4-flash thinking_mode） |
| `THINKING_EFFORT_EASY/MEDIUM/HARD/EXTREME/DEFAULT` | high/high/max/max/high | 按难度分级的 reasoning_effort（仅支持 high/max） |
| （隐含）`LLM_PROVIDER=go` 时 | - | reasoning_effort 强制为 `none`（go 端点思考链无界生成会撞满 max_tokens，勿改） |

#### Kali SSH 配置（WING-Goose 起默认关闭）

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `KALI_ENABLED` | `false` | Kali 路由开关（默认 false = 关闭 Kali 路由，执行层只用 Docker） |
| `KALI_HOST` / `KALI_PORT` / `KALI_USER` | <kali-host> / 22 / root | Kali 连接信息 |
| `KALI_PASS` / `KALI_KEY_PATH` | 空 | 密码或 SSH Key 路径（Key 优先） |

#### Docker 工具链（WING-Goose Item 5）

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `DOCKER_ENABLED` | `true` | Docker 容器替代 ssh 执行层；daemon 不可用自动降级到 ssh |
| `DOCKER_IMAGE` | `wing-goose:v2` | 默认镜像（补装 fpylll/angr/torch 等 6 库）；v1 以 latest 标签保留作回滚点 |
| `DOCKER_BACKEND` | `sdk` | cli \| sdk（docker-py） |
| `DOCKER_CONTAINER` | `wing-goose-worker` | 容器名（swarm 场景每 agent 独立容器 `wing-goose-<id>`） |
| `DOCKER_WORKDIR` | `/challenge` | 容器工作目录 |
| `DOCKER_BUILD_ON_MISSING` | `false` | 镜像缺失时是否自动构建 |
| `DOCKER_DOCKERFILE` | `scripts/docker_test/Dockerfile.wing-goose` | 构建用 Dockerfile 路径 |
| `DOCKER_CPU_PROFILE` | `normal` | 每容器配额：light(1核/1G) / normal(2核/2G) / brute(4核/2G) / heavy(4核/4G) |
| `DOCKER_CPU_CORES` / `DOCKER_MEM_LIMIT` | 0 / 空 | 显式覆盖（>0/非空时优先于 Profile） |
| `DOCKER_MAX_CONTAINERS` / `DOCKER_RESERVE_CPU` / `DOCKER_RESERVE_RAM` | 0 / 0.25 / 0.25 | 最大并发容器数（0=自动计算）+ 预留因子 |

#### 多解题器（swarm）与总指挥

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `SWARM_ENABLED` | `true` | 默认开启多解题器：所有难度（含 easy）都走 3 风格并行 swarm（NSSCTF 难度评判不标准）；false → 回退早期结论（仅 medium/hard 并行，easy 单路） |
| **`SWARM_COMMANDER_ENABLED`** | **`false`** | **总指挥（Commander）开关——三层协作小队。默认 false = 纯雁阵行为不变（升级验证期间）；开启后 swarm 启动总指挥实例：领题分工 → 战略层汇报 → 全局重定向。LLM 不可用/领题失败自动降级回雁阵** |

#### 巡查指导器

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `COORDINATOR_PATROL_GAP` | 5 | 巡查发起间隔（步，范围钳制 5~10）；默认 5 时按风格节奏 |

#### 熔断阈值

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `MAX_STEPS` | 80 | ReAct 步数硬上限（从 50 上调；实际由 AdaptiveBreaker 按难度动态调整 + 进展感知软截断） |
| `MAX_TASK_TIME` | 1800 | 单任务最大时长（秒） |
| `MAX_COST_LIMIT` | 1.5 | 单任务 API 成本上限（美元） |

#### 数据库 / 日志

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `SQLITE_PATH` | `./data/ctf.db` | SQLite 数据库路径 |
| `CHROMA_PATH` | `./data/chroma` | 向量库路径（RAG 长期记忆） |
| `LOG_LEVEL` | `INFO` | 日志级别 |

### 20.3 命令行使用

#### CLI 入口（main.py）

```bash
# 单题求解（单 agent，非 swarm）
python main.py run --target http://ctf.example/ --desc "PicoCTF GET aHEAD" [--file 附件] [--show-steps] [--report report.md] [--type web] [--difficulty 5] [--no-rag]

# WebUI
python main.py web --host 127.0.0.1 --port 8000

# 版本
python main.py --version
```

参数说明：`--target`/`--file` 至少一个；`--show-steps` 输出每步 Thought/Action/Observation；`--report` 生成 Markdown 报告（含时间线与改进建议）；`--no-rag` 关闭 RAG 经验检索。

#### 子进程求解入口（solve.py，swarm/调用器使用）

```bash
python -u -m ctf_agent.solve --task-file <task.json>
```

task JSON 示例：

```json
{
  "challenge_id": "challenge_001",
  "title": "题目名",
  "desc": "任务描述 (题面+附件路径+靶机URL+规则)",
  "type": "web",
  "difficulty": "easy",
  "max_steps": 0,
  "max_seconds": 1500.0,
  "max_submissions": 3,
  "style": "conservative",
  "bus_dir": "data/bus",
  "bus_challenge_id": "challenge_001",
  "commander_enabled": true,
  "annex_dir": "path/to/annex"
}
```

### 20.4 总指挥模式：启用与降级

**启用**：在 `.env` 设置 `SWARM_COMMANDER_ENABLED=true`（同时需 `SWARM_ENABLED=true` 且调用器提供 `bus_dir`/`bus_challenge_id`）。启动后日志应出现：

```
总指挥领题分工: conservative→任务1: ...; aggressive→任务2: ...; innovative→任务3: ...
```

**自动降级**（任一条件满足即回雁阵，`on_commander` 输出 WARN 日志）：

| 降级条件 | 说明 |
|----------|------|
| `commander_enabled` 显式 False | 纯雁阵 |
| 无 `bus_dir` | 无总线无法通信 |
| 领题分工 LLM 失败 / 返回空 assignments | `_setup_commander` 捕获异常返回 None |
| 总指挥初始化异常 | 同上 |

降级后：三路 agent 仍并行求解（`commander_enabled=False` 时战略层所有汇报/消费方法立即返回 False/None，零开销），行为与 WING-Goose 雁阵完全一致。

**验证总指挥是否工作**：观察 `on_commander` 回调日志（领题分工 INFO / 指令下发 CMDR / 降级 WARN）；或检查总线文件（`<bus_dir>/<challenge_id>.jsonl`）中 kind=report/directive 的消息流。

### 20.5 Docker 执行链

1. `DOCKER_ENABLED=true`（默认）：`solve.py` 构造 `DockerClient`（镜像 wing-goose:v2，容器 `wing-goose-<agent_id>`，工作目录 /challenge）。
2. 附件挂载：宿主附件目录 → 容器 `/challenge/workspace`；同题共享目录 → 容器 `/shared`。
3. 工具层：docker_exec / docker_python / docker_upload 优先；daemon 不可用自动降级 ssh（若 KALI_ENABLED=true 且 Kali 可达）。
4. 资源配额：按 DOCKER_CPU_PROFILE 限制容器 CPU/内存；`DOCKER_MAX_CONTAINERS` 控制并发。
5. 清理：swarm 结束时 `_kill_tree` 确保容器孙进程不残留（taskkill /F /T）。

### 20.6 解题输出解读

子进程 stdout JSONL 关键行：

| type | 关键字段 | 解读 |
|------|----------|------|
| `start` | protocol_version / max_steps / max_seconds / max_submissions | 任务启动信息 |
| `step` | step_no / action / action_input / observation / is_error / is_final | 每步 Thought-Action-Observation |
| `coordinator` | step_no / should_intervene / priority / guidance / reflection / belief_state | 巡查详情（何时干预、依据什么推论） |
| `heartbeat` | elapsed / step / phase | 每 15s 心跳（区分"卡住"与"正在思考"） |
| `submission` | flag | agent 请求提交的 flag（调用器经 stdin 回复 correct/feedback） |
| `result` | success / flag / final_answer / fail_reason / steps / elapsed / tokens | 最终结果 |

swarm 汇总结果（SwarmResult）：`solved` / `flag` / `winner_style`（哪路解出）/ `elapsed` / `total_tokens` / `agents[]`（每路 steps/elapsed/tokens/fail_reason/killed_by_sibling）/ `killed_count`。

**多阶段运行观察点**：

- **P1**：三路各自侦查，每 5 步 progress 汇报；观察 `coordinator` 行的 p1_done 信号；总线中 recon_done 到达 3 条 → 总指挥广播 P2 分工（含全局情报摘要）。
- **P2**：总指挥引导保守+激进深入主方向、创新发散；观察到 verified 汇报 → 总指挥确凿分析 → P3。
- **P3**：三路利用漏洞；总指挥转向类指令降级 SHOULD；观察 dead_end 汇报（≥2 路失败 → 回退 P2）。
- **P4**：保守型验证 flag；提交前 Flag 验证（代码机制 + LLM 审查）。

### 20.7 常见问题排查

| 现象 | 可能原因 | 排查/解决 |
|------|----------|-----------|
| 启动即报"LLM API Key 未配置" | .env 缺失或 OPENAI_API_KEY 为空 | 配置 OPENAI_API_KEY（has_llm_config 判定依据）；确认 .env 位于工作目录 |
| 总指挥未启动（无领题分工日志） | SWARM_COMMANDER_ENABLED=false / 无 bus_dir / 领题 LLM 失败 | 检查 .env 开关与调用器 task 的 bus_dir；观察 on_commander WARN 日志 |
| 总指挥领题后无 worker 日志（开局停滞） | 旧版本总指挥初始化阻塞主线程 | 确认使用异步初始化版本；检查 commander-init 线程异常 |
| "卡在'总指挥模式：3 风格并行'后无输出" | 同上（已知问题已修复） | 升级代码；或 SWARM_COMMANDER_ENABLED=false 临时绕过 |
| 每步 LLM 调用耗时 90s+ | 走了系统代理（绕境外 IP） | 确认 llm/routed.py 使用 proxy=None 直连；LLM_PROVIDER=go |
| go 请求超时 / 频繁降级 | go 套餐不可达 / 余额不足 | 冒烟测试定位：`smoke_test()`；检查 GO_API_KEY |
| agent 连续"格式解析失败" | LLM 输出格式混乱 | max_format_errors=5 已放宽；观察 FORMAT_ERROR_HINT 注入；考虑切换 LLM_PROVIDER |
| agent 反复重复相同操作 | 死循环未拦截 | 观察 coordinator 行的 forbidden_actions / 精确签名禁忌；检查 MUST 未执行检测日志 |
| flag 提交被拒（Flag 验证未通过） | flag 来自外部题解渠道 / 未在观测中出现 | 检查验证原因（suspicious_hit / 未出现在 Observation / LLM 审查不通过）；让 agent 从靶机/附件真实观测获取 |
| P1 迟迟不进入 P2 | 某路未汇报 recon_done（卡死/进程异常） | 观察 60s 无进展信号；总指挥应介入调整；检查该路 heartbeat 是否存活 |
| P3 阶段总指挥静默（无指令） | 正常现象（P3 协调以引导为主）+ 历史上曾有 NameError bug（已修复） | 确认使用修复后版本；P3 观察战略层是否正常下发方向调整 |
| 提交等待 60s 超时 | 调用器未回复 submission | 检查调用器 stdin 分发器；max_submissions 配置 |
| Windows 下 swarm join 超时 | 孙进程残留阻塞 readline | 确认使用 `_kill_tree`（taskkill /F /T）版本 |
| 一解出但兄弟未 kill | 进程树残留 | 检查 _kill_tree 是否生效；手动 taskkill 残留容器/进程 |
| 巡检指导器不干预（形同虚设） | 旧版本 `_phase_task_block` 未定义（AttributeError 降级） | 确认使用修复后版本（2026-08-05 修复） |

### 20.8 快速上手示例（端到端，总指挥模式）

```bash
# 0. 准备
cd WING-Corvus
cp .env.example .env
# 编辑 .env: GO_API_KEY / GO_BASE_URL / SWARM_ENABLED=true / SWARM_COMMANDER_ENABLED=true
#             / KALI_ENABLED=false / DOCKER_ENABLED=true

# 1. 冒烟测试 LLM 可用性（应输出 {"go": true, ...}）
python -c "from ctf_agent.llm.routed import RoutedLLMClient; from ctf_agent.config import get_settings; print(RoutedLLMClient(get_settings()).smoke_test())"

# 2. 准备 task JSON（或由 NSS Runner 自动生成）
# 见 20.3 的 task JSON 示例（含 bus_dir/bus_challenge_id/commander_enabled=true）

# 3. 多路 swarm 驱动（推荐；每路一个 solve.py 子进程，总指挥在 swarm 主进程内）
cat > swarm_demo.py <<'EOF'
from ctf_agent.swarm import SwarmCoordinator

def verify_flag(flag: str):            # 提交前验证（返回 (correct, feedback)）
    return flag.startswith("SUCTF{"), "格式校验"

task = {
    "challenge_id": "demo",
    "bus_challenge_id": "demo",
    "bus_dir": "data/bus/demo",
    "desc": "题目描述（题面+附件路径+靶机URL+规则）",
    "type": "web", "difficulty": "medium",
    "max_steps": 40, "max_submissions": 3,
}
sw = SwarmCoordinator(project_root=".", verify_flag=verify_flag)
res = sw.run(task=task, styles=["conservative", "aggressive", "innovative"], max_seconds=1200)
print(f"solved={res.solved} flag={res.flag} winner={res.winner_style}")
EOF
python swarm_demo.py

# 3b. 单路调试（可先只跑一路，验证总指挥链路）
python -u -m ctf_agent.solve --task-file task.json

# 4. 观察输出
#    - start 行确认协议版本与参数
#    - coordinator 行观察巡查（p1_done / p2_verified 信号）
#    - 总指挥日志（由调用器经 on_commander 输出）：领题分工 → 指令[SHOULD] → 阶段切换
#    - submission 行出现 → 调用器回复 correct/feedback
#    - result 行确认 success / flag

# 5. 排查：检查总线文件确认 report/directive 消息流
Get-Content data/bus/<challenge_id>.jsonl
```

**单 agent 模式（不使用总指挥/swarm）**：`python main.py run --target URL --desc "..."`——独立运行，无总线无总指挥，适用于单题快速验证。

---

## 21. 常见问题排查（补充）

### 21.1 已收录问题外的场景

| 现象 | 可能原因 | 解决 |
|------|----------|------|
| docker 工具全部报错（unknown tool） | DockerClient 构造失败（daemon 未启动/镜像缺失） | 检查 Docker Desktop 状态；DOCKER_BUILD_ON_MISSING=true 或手动构建镜像 |
| 总线文件无限增长 | 单题长跑、汇报频繁 | 总线按题隔离；题后可 `bus.clear(challenge_id)` 清理 |
| 成本快速超限熔断 | LLM token 消耗大 | 调高 MAX_COST_LIMIT 或优化 prompt（总指挥上下文窗口仅 12 条摘要） |
| agent 拿到的兄弟发现是命令级细节（旧版本） | 未消毒 | 确认使用 `check_sanitized`（消毒方向性线索） |
| RAG 检索命中无关套路 | 任务开始时静态匹配极简题面 | 确认使用延迟注入（step≥8 基于轨迹观测匹配） |

### 21.2 性能与成本调优指南

| 目标 | 手段 | 说明 |
|------|------|------|
| 降低 LLM 成本 | 总指挥保持 flash + none 思考 | 总指挥只读 12 条摘要上下文，每次 analyze 才调 LLM（约 5s 轮询 + 有汇报才处理） |
| 降低 LLM 成本 | 汇报只报 FACT/LIKELY（≤400 字符） | 战略层 `report_to_commander` 只报高置信度，控制总指挥 token |
| 降低 LLM 成本 | RAG/巡查直接调底层 API（不走 HyDE） | `_query_knowledge` 避免额外 LLM 调用，省 token + 低延迟 |
| 降低 LLM 成本 | 复盘按步数门槛 | `_review` 仅步数 ≥8 时跑（LLM 深度复盘）；`_learn` 模板生成每题都跑（不调 LLM） |
| 提速 | LLM_PROVIDER=go（国内直连禁代理） | 每步 LLM 从 90s+（走代理）降到 10-20s |
| 提速 | 单题并发按难度 | SWARM_ENABLED=true 时 3 路并行；简单题可考虑 SWARM_ENABLED=false 单路 |
| 提速 | 巡查异步事件驱动 | 巡查分析后台线程，不阻塞 agent 行动 |
| 稳定性 | 熔断阈值按题型难度自适应 | AdaptiveBreaker `_dynamic_max_steps` 动态调整 |
| 稳定性 | provider 动态跳过期 | 中途故障自动跳过 120s，恢复自动重试，避免每次死等 |
| 稳定性 | max_format_errors=5 | 并发抢 API 时输出质量波动的容错 |

### 21.3 多 agent 并发资源预算

- 每路 agent 一个 Docker 容器（wing-goose-<id>），资源按 DOCKER_CPU_PROFILE 配额；
- 3 路并行时建议：normal profile（2核/2G ×3）+ 预留 0.25 CPU/0.25 RAM 给宿主 OS/Docker Desktop；
- `DOCKER_MAX_CONTAINERS=0` 时按宿主资源自动计算最大并发容器数；
- 成本预算：单题 3 路 × 单路 MAX_COST_LIMIT（1.5 USD）为最坏上限，实际通常远低于此（总指挥开销 <5%）。

---

## 22. 附录

### 22.1 关键类与方法速查表（附录 A）

#### A.1 总指挥（commander/commander.py）

| 方法 | 签名要点 | 说明 |
|------|----------|------|
| `assign_initial` | `(bus=None) -> list[TaskAssignment]` | 领题分工（LLM 分解 + 默认兜底 + task_no 统一编号） |
| `consume_reports` | `(bus=None) -> list[dict]` | 游标消费新汇报，只聚合 FACT/LIKELY 摘要 |
| `run_once` | `(bus=None) -> list[CommanderDirective]` | 一轮完整处理（消费→状态机→LLM 分析→下发） |
| `analyze_reports` | `(bus=None) -> list[CommanderDirective]` | LLM 深度分析 + 指令校验下发 |
| `post_directives` | `(directives, bus=None) -> list[int]` | 指令写入总线（带 phase） |
| `_phase_advance_rule` | `() -> str` | 规则判定阶段切换（P1→P2→P3→P4，含回退） |
| `_p1_synthesize` | `(bus=None) -> list[CommanderDirective]` | P1 全局情报摘要整合 + 主方向确定 + P2 分工广播 |
| `_p2_verify_direction` | `(bus=None) -> list[CommanderDirective] \| None` | P2→P3 确凿校验（confirmed 才切换） |
| `_update_directions_from_llm` | `(obj: dict) -> None` | 解析主方向/备选方向（两种途径约束，P1 忽略主方向） |
| `_rule_signals_block` | `() -> str` | 规则信号（无进展/卡住/趋同）注入 LLM 参考 |
| `_detect_convergence` / `_detect_stuck` | `() -> list[CommanderDirective]` | 规则级直产指令（保留能力） |
| `_extract_topics` | `(content) -> set[str]` | 三级主题提取（英文 token/中文预置词/n-gram） |
| `_set_phase` | `(new_phase) -> bool` | 阶段切换（记录上下文+耗时） |
| `_llm_json` | `(messages, max_tokens, tag) -> dict \| None` | LLM 调用 + JSON 解析 + 1 次重试 |
| `_trim_context` | `() -> None` | 上下文裁剪（保留最近 12 条） |
| `summary` | `() -> str` | 状态摘要（调试用） |

#### A.2 战略层（agent/coordinator.py）

| 方法 | 签名要点 | 说明 |
|------|----------|------|
| `should_check` | `(step_no, max_steps, live_errors) -> bool` | 巡查触发时机判定 |
| `fire_async_analysis` | `(trajectory, ...) -> bool` | 后台线程发起分析 |
| `consume_pending_guidance` | `(current_step) -> CoordinatorGuidance \| None` | 事件召回分析结果 |
| `analyze` | `(trajectory, ...) -> CoordinatorGuidance` | 两级分析（L1 规则 + L2 LLM） |
| `set_task_contract` | `(task_no, direction, priority) -> None` | 任务契约注入/更新 |
| `report_to_commander` | `(report_type, content, level) -> bool` | 通用汇报（clue/dead_end/question） |
| `report_progress` | `(findings, next_plan, stuck) -> bool` | P1 侦查进度汇报 |
| `report_recon_done` | `(summary) -> bool` | P1 侦查完成汇报 |
| `report_verified` | `(direction, evidence) -> bool` | 方向验证成功汇报 |
| `report_p1_progress_if_due` | `(step_no, recent_steps) -> bool` | P1 每 5 步自动汇报（主循环调用） |
| `report_dead_end` | `(content, auto_switch) -> str` | 死路自动切换 + 事后汇报 |
| `check_commander_directives` | `() -> CoordinatorGuidance \| None` | 指令消费 + MUST 本地冲突校验 + 阶段感知 |
| `on_tool_error` | `(tool, error) -> str` | 工具异常死路检测（环境缺失连续 2 次） |
| `intercept_forbidden` | `(action, action_input) -> str` | 工具执行前禁忌拦截 |
| `_phase_task_block` | `() -> str` | 按阶段注入巡查侧重 |
| `_llm_analyze` | `(...) -> CoordinatorGuidance` | L2 LLM 深度分析（p1_done/p2_verified 信号处理） |
| `_query_knowledge` | `(task_desc, challenge_type, trajectory) -> str` | 知识库查询（Skill + RAG + 经验库，基于轨迹观测） |

#### A.3 战术层（agent/react.py）

| 方法 | 签名要点 | 说明 |
|------|----------|------|
| `run` / `_run_inner` | `(task) -> ReActResult` | ReAct 主循环 |
| `parse_llm_output` | `(text) -> ParsedAction` | LLM 输出解析（Final/Action+Input/失败） |
| `_extract_balanced_json` | `(text) -> str \| None` | 配平花括号 JSON 提取（修复后跟含 {} 文本） |
| `_clean_action_input` | `(raw) -> str` | action_input 鲁棒清洗（配平/尾逗号/单引号） |
| `_thinking_extra` | `() -> dict \| None` | 按难度+题型注入 reasoning_effort |
| `_apply_coordinator_guidance` | `(guidance, fired_step) -> None` | 应用巡查结果（MUST 持久注入/灵感板/扩展步数） |
| `_post_to_bus` | `(step_no, guidance) -> None` | 巡查 FACT/LIKELY 发布总线 + FACT 上报总指挥 |
| `_invoke_tool` | `(action, action_input) -> ToolResult` | 工具调用 |

#### A.4 编排与其他

| 类/模块 | 关键方法 | 说明 |
|---------|----------|------|
| `SwarmCoordinator`（swarm.py） | `run` / `_setup_commander` / `_commander_loop` / `_kill_tree` / `_on_submission` | 多风格并行 + 总指挥生命周期 |
| `FlagVerifier`（flag_verify.py） | `verify(flag, steps) -> FlagVerifyResult` / `_find_source` / `_suspicious_hit` / `_llm_verify` | 提交前 flag 验证 |
| `FileBus`（bus/file_bus.py） | `post_report` / `check_reports` / `post_directive` / `check_directives` / `post_finding` / `check_findings` / `check_sanitized` | 跨进程消息总线 |
| `RoutedLLMClient`（llm/routed.py） | `chat` / `smoke_test` / `apply_smoke_from_file` / `_call_flash` | 模型路由 |
| `CircuitBreaker` / `AdaptiveBreaker`（orchestrator/） | `check` / `reset` / `record_llm_call` / `extend_steps` / `has_recent_progress` | 六维熔断 |
| `ReActResult` / `ReActStep` | - | 结果/步骤数据结构 |
| `SwarmResult` / `SwarmAgentResult` | `by_style` | swarm 汇总结果 |

### 22.2 消息字段全览（附录 B）

#### report（战略层 → 总指挥，kind=report）

| 字段 | 类型 | 说明 |
|------|------|------|
| `agent` | str | 汇报方风格（conservative/aggressive/innovative） |
| `task_id` | str | 总线键（challenge_id） |
| `content` | str | 汇报内容（≤400 字符） |
| `report_type` | str | clue / dead_end / question / progress / recon_done / verified |
| `level` | str | FACT / LIKELY / POSSIBLE（只报前两级） |
| `task_no` | int | 当前任务契约编号 |
| `seq` | int | 全局递增序号 |

#### directive（总指挥 → 战略层，kind=directive）

| 字段 | 类型 | 说明 |
|------|------|------|
| `agent` | str | 目标风格 |
| `task_id` | str | 总线键 |
| `content` | str | 指令方向（≤500 字符） |
| `task_no` | int | 更新后的任务契约编号 |
| `priority` | str | MUST / SHOULD |
| `reason` | str | 指令依据（≤300 字符，MUST 必须非空） |
| `phase` | str | P1 / P2 / P3 / P4（阶段随指令下发） |
| `seq` | int | 全局递增序号 |

#### finding（兄弟 agent 之间）

| 字段 | 类型 | 说明 |
|------|------|------|
| `agent` | str | 发布方 |
| `content` | str | 发现内容（注入用消毒版本） |
| `level` | str | FACT / LIKELY |
| `kind` | str | finding / question / answer |
| `reply_to` | int | 回答时引用的问题 id |
| `seq` | int | 全局递增序号 |

### 22.3 附录 C：prompt 模板字段一览

#### 总指挥领题分工输出（assign_initial）

```json
{
  "assignments": [
    {"style": "conservative", "task_no": 1, "task": "方向性任务描述 (非命令清单, 必须与其他人方向互斥)", "rationale": "分配理由"}
  ],
  "reasoning": "一句话分解依据"
}
```

要求：assignments 必须覆盖全部传入风格、每路恰好一个（不许重复或遗漏）；task_no 领题时 1,2,3...。

#### 总指挥汇报分析输出（analyze_reports）

```json
{
  "silent": true,
  "directives": [
    {"style": "conservative", "task_no": 2, "direction": "新方向或细化描述", "priority": "MUST/SHOULD", "reason": "指令依据 (引用汇报, MUST 必须非空)"}
  ],
  "main_direction": "当前主方向 (一句话, P1 期间不输出)",
  "alt_directions": ["备选方向描述", "..."],
  "belief_state": [{"id": "B1", "statement": "推论", "level": "FACT/LIKELY/POSSIBLE", "evidence": "支撑汇报"}],
  "reasoning": "分析过程摘要"
}
```

#### 战略层巡查输出（Coordinator）

```json
{
  "reflection": "反思 (必填, ≥30 字)",
  "belief_state": [{"id": "B1", "statement": "...", "level": "FACT/LIKELY/POSSIBLE/DISPROVED", "evidence": "...", "action": "keep/upgrade/downgrade/disprove/new"}],
  "should_intervene": true,
  "priority": "MUST/SHOULD",
  "guidance": "具体的战术指导 (做什么+怎么做+为什么)",
  "strategic_direction": "下一步战略方向 (非创新风格, 仅干预时)",
  "reason": "干预原因 (引用推论 ID)",
  "extend_steps": false,
  "forbidden_actions": ["已确认无效的操作 (仅 FACT/DISPROVED)"],
  "revert_guidance": false,
  "remove_forbidden": [],
  "analysis_summary": "一句话摘要",
  "p1_done": false,
  "p1_done_summary": "P1 侦查完成摘要 (p1_done=true 时)",
  "p2_verified": false,
  "p2_verified_direction": "已验证的方向",
  "p2_verified_evidence": "验证证据 (必须完整)"
}
```

#### Flag 审查输出（FlagVerifier LLM 审查）

```json
{"pass": true/false, "reason": "一句话依据 (引用具体步骤号与观测来源)", "confidence": "high/medium/low"}
```

#### 复盘输出（TrajectoryReviewer）

```json
{
  "facts": [{"claim": "...", "source": "conservative step 6"}],
  "lessons": [{"point": "...", "source": "aggressive step 8"}],
  "skills": [{"title": "...", "category": "web", "trigger": "何时适用", "body": "步骤1\\n步骤2", "tags": [], "tools": ["http_request"], "pattern_features": ["特征1"], "evidence_steps": ["innovative step 12"]}]
}
```

### 22.6 术语表

| 术语 | 含义 |
|------|------|
| Commander（总指挥） | 三层协作小队顶层：阶段管理、领题分工、主方向管理、汇报分析、指令下发 |
| Coordinator（战略层/巡查指导器） | 每路 agent 的"智能旁观者"：方向判断、死循环检测、小方向调控、向总指挥汇报 |
| ReAct Agent（战术层主 LLM） | 执行 Thought-Action-Observation 循环的解题 agent |
| 协作小队（Coordinated Squad） | WING-Corvus 的三层协作架构 |
| 雁阵（Goose/Swarm） | WING-Goose 的多风格并行编排模式（无全局协调者） |
| P1-P4 | 侦查 / 漏洞识别 / 利用 / 验证 四阶段 |
| report / directive | 战略层→总指挥的汇报 / 总指挥→战略层的指令 |
| MUST / SHOULD | 指令优先级：必须执行 / 方向性建议（默认） |
| recon_done / verified | P1 侦查完成信号 / P2 方向验证成功信号 |
| 主方向 / 备选方向 | 最有把握的攻击方向 / 有可能方向（创新发散确认） |
| FACT / LIKELY / POSSIBLE / DISPROVED | 证据四级分级 |
| FileBus | 跨进程共享文件总线（JSONL，游标消费） |
| belief_state | 战略层跨巡查持久化的推论清单 |
| creative_hints | 创新模式灵感板（创造性探索建议，非强制） |
| FlagVerifier | 提交前 flag 验证器（代码机制 + LLM 审查） |

### 22.4 参考文档

| 文档 | 说明 |
|------|------|
| `docs/CTF_AGENT_DESIGN.md` | WING-Falcon 设计文档（单 agent 核心引擎） |
| `docs/CTF_AGENT_GUIDE.md` | WING-Falcon 使用指南 |
| `docs/WING_GOOSE_UPGRADE_PLAN.md` | WING-Goose 升级方案（swarm/总线/复盘/docker 链） |
| `docs/阶段式协调.md` | 多阶段协调设计（P1-P4 定义） |
| `docs/总指挥多阶段升级方案.md` | 总指挥多阶段升级方案（WING-Corvus 2.0） |
| `docs/sprint36_commander_design.md` | 总指挥设计 |
| `docs/DOCKER_SANDBOX_DESIGN.md` | Docker 沙箱设计 |
| `docs/NSS_RUNNER_GUIDE.md` | NSS Runner 指南 |

### 22.5 文档说明

本文档基于 WING-Corvus 源码逐行审计编写，覆盖全部新增能力（总指挥、战略层协作、多阶段协调、Flag 验证、总线协议、解析容错等）及相对 WING-Goose 的版本演进。如源码后续更新，请以代码为准并同步本文档。