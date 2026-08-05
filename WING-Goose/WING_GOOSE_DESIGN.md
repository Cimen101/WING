# WING-Goose（雁阵）设计与使用文档

> **文档性质**：系统设计 + 使用指南（基于源码审计生成，不含臆造功能）
> **版本**：WING-Goose（雁阵）｜生产代码快照：2026-08-04
> **上游基线**：WING-Falcon（猎隼，单 agent 基线）
> **下游方向**：WING-Corvus（总指挥，本快照为升级前的生产代码）
> **最后更新**：2026-08-05

---

## 目录

1. [项目概述与设计目标](#1-项目概述与设计目标)
2. [总体架构](#2-总体架构)
3. [核心模块详细设计](#3-核心模块详细设计)
4. [数据设计](#4-数据设计)
5. [版本演进：相对 WING-Falcon 的更新](#5-版本演进相对-wing-falcon-的更新)
6. [部署与运维](#6-部署与运维)
7. [安全与伦理](#7-安全与伦理)
8. [使用方法](#8-使用方法)
9. [附录](#9-附录)

---

## 1. 项目概述与设计目标

### 1.1 项目目标

WING-Goose（雁阵）是一个**多解题器并行编排的 CTF 自动化攻防智能体系统**。它在 WING-Falcon（猎隼，单 agent 基线）的基础之上，将"同一道题目由多个解题风格各异的 agent 并行求解，一解出即杀其余"作为核心能力引入生产，目标是：

> 在只有正常比赛题目描述的情况下，全自主完成 CTF 题目求解，并且**用风格差异对冲单一路线的思维盲区**，以更高的单题命中率、更短的墙钟耗时完成解题。

具体目标分解：

- **同题多风格并行**：同一道题由保守（conservative）、激进（aggressive）、创新（innovative）三路解题器并行推进，任意一路解出即终止其余（swarm 编排）。
- **跨进程发现共享**：三路 agent 通过消息总线（进程内 MessageBus + 跨进程 FileBus）共享高置信度线索，避免重复劳动、互相补盲。
- **独立轨迹复盘**：每轮求解结束后由独立上下文的 LLM 对轨迹做复盘（facts / lessons / skills），并通过无幻觉核对后入库，沉淀可复用技能。
- **Docker 执行链**：以常驻 Linux 容器（wing-goose:v2）作为默认执行层，替代 SSH 往返，并支持到 SSH / MCP 的多级降级。
- **全题型覆盖**：继承 Falcon 的 Web / Pwn / Crypto / Reverse / Misc / Forensics / OSINT 七大题型能力与 30+ 专用工具。
- **持续学习**：Skill 库 + 经验库（skill_library.json）+ 长期记忆（ChromaDB RAG）+ 轨迹复盘四路闭环，让系统越用越强。

### 1.2 项目定位

WING-Goose 的定位是 **CTF 解题智能体"编队"引擎**，处于单 agent 核心（Falcon）与多阶段总指挥（Corvus）之间：

| 维度 | WING-Falcon（猎隼） | WING-Goose（雁阵） | WING-Corvus（总指挥，后续版本） |
|------|--------------------|--------------------|-------------------------------|
| 求解组织方式 | 单 agent 单路线 | 同题 3 风格并行（swarm） | 多 agent 分阶段协调 |
| 进程模型 | 单子进程 | N 子进程并行 + 提交协调 | 总指挥 + 多执行器 |
| 共享机制 | 无 | 消息总线（跨进程）+ 共享文件系统 | 更高级的指挥协调 |
| 复盘 | Skill 学习器（模板） | 独立 LLM 轨迹复盘 + 无幻觉核对 | 延续并强化 |
| 执行层 | Kali SSH | Docker 容器（默认）+ SSH 降级 | 延续 |

> ⚠️ 本文档**不包含** WING-Corvus 的总指挥（commander）、flag 校验器（flag_verify）、多阶段协调等设计——那些属于 Corvus 快照，不是本快照（2026-08-04）的内容。

与同类项目的区别：

- **vs 传统 CTF 工具**（sqlmap、pwntools）：传统工具被动执行指令；Goose 的 agent 自主决策工具链与攻击路径。
- **vs 半自动平台**：Goose 无需人工选择攻击类型，自动识别题型与路径。
- **vs 单 agent 框架**（如 AutoGPT）：Goose 不仅内置 CTF 领域知识，还在**同题多风格并行**维度上做工程化（进程编排、跨进程总线、一解出即杀），把"并行多样性"变成了稳定可复用的架构能力。

### 1.3 核心理念

1. **ReAct 范式**：推理（Reasoning）与行动（Acting）交替，每步先 Thought 再 Action，基于 Observation 调整。
2. **风格多样性对冲盲区**：单一解题风格存在系统性思维盲区（保守怕冒险、激进怕深入、创新怕收敛）；三路并行让不同风格各展所长，任一突破即全队胜利。
3. **协作是工程而不是提示**：兄弟发现共享不止写在 prompt 里，而是通过消息总线（每 5 步 check、强制分享义务、强制回答提问）在引擎层面强制执行。
4. **旁观者清**：巡查指导器（Coordinator）以独立 LLM 视角宏观审视轨迹，方向正确时保持沉默，方向偏移时果断 [MUST] 干预。
5. **执行层确定性**：Docker 常驻容器提供低延迟、可复现的执行环境；daemon 不可用时逐级降级到 SSH，绝不让"没有执行层"导致整题 0 步失败。
6. **反幻觉优先**：无工具调用直接 Final Answer 一律拒绝；轨迹复盘的 facts 必须逐条核对出现在轨迹文本中才允许入库。
7. **方法论而非剧本**：注入的是"如何发现漏洞"的方法论与风格引导，而非具体攻击指令；Skill 是加速器而非剧本。

### 1.4 版本快照说明

本快照（2026-08-04）是 WING-Corvus 升级前的**生产代码**，包含自 Falcon 以来全部已验证的进化（三风格并行、消息总线、轨迹复盘、docker 执行链、异步事件驱动巡查等），是后续总指挥版本升级的稳定基线。`pyproject.toml` 中包版本号为 `0.1.0`，协议版本为 `1.1`。

---

## 2. 总体架构

### 2.1 架构总览

```
┌──────────────────────────────────────────────────────────────────────────┐
│                            调用器层 (Caller)                               │
│   NSS Runner / CLI main.py / WebUI / 批量测试脚本 / SwarmCoordinator      │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │ JSONL 协议 (stdin/stdout) / subprocess
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                       WING-Goose 编队层 (Swarm)                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                    │
│  │ conservative │  │  aggressive  │  │  innovative  │   ← 每路一个子进程   │
│  │  子进程 A     │  │  子进程 B     │  │  子进程 C     │   ← 一解出即杀其余   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                    │
│         │  消息总线 FileBus (JSONL 文件, 同题共享)                        │
│         └───────────────┬──────────────────┘                             │
│                         ▼                                               │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                        单 agent 子进程内部                          │ │
│  │  ┌─────────────────────────────────────────────────────────────┐  │ │
│  │  │            ReActEngine (agent/react.py)                     │  │ │
│  │  │  Thought → Action → Observation 循环                        │  │ │
│  │  │  · 每 5 步 check 总线兄弟发现 + 协作义务 + 强制回答提问        │  │ │
│  │  │  · 巡查指导器异步事件驱动 (fire/consume)                     │  │ │
│  │  └──────────────┬──────────────────────────┬──────────────────┘  │ │
│  │                 ▼                          ▼                     │ │
│  │  ┌────────────────────────┐  ┌─────────────────────────────┐    │ │
│  │  │  Coordinator 巡查指导器 │  │  Tools 工具层                │    │ │
│  │  │  (L1 规则 + L2 LLM)    │  │  · L1 内置 / 专用题型工具    │    │ │
│  │  │  · 禁忌列表/精确签名     │  │  · bus_tool 共享发现         │    │ │
│  │  │  · 全局方向追踪/推论分级 │  │  · shared_fs 共享文件        │    │ │
│  │  └────────────────────────┘  │  · docker_tool 执行链        │    │ │
│  │  ┌────────────────────────┐  │    (docker→ssh→MCP 降级)     │    │ │
│  │  │  熔断器 CircuitBreaker │  └─────────────────────────────┘    │ │
│  │  │  六维熔断 + 动态扩展    │                                      │ │
│  │  └────────────────────────┘                                      │ │
│  │  ┌─────────────────────────────────────────────────────────┐    │ │
│  │  │  LLM 路由 RoutedLLMClient                                │    │ │
│  │  │  go 直连 / zen→go→官方 三级降级 / 动态健康 / wall-clock    │    │ │
│  │  └─────────────────────────────────────────────────────────┘    │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  记忆层: ShortTerm(滑动窗口) / MidTerm(SQLite facts) / LongTerm(ChromaDB) │
│  知识层: Skill 库(md) / 经验库(skill_library.json) / 失败轨迹缓存         │
│  复盘层: TrajectoryReviewer (LLM 独立复盘 + 无幻觉核对 + 入库)            │
└──────────────────────────────────────────────────────────────────────────┘
```

### 2.2 模块分层

| 层级 | 模块 | 职责 |
|------|------|------|
| L1 执行层 | `tools/`（builtin / http / docker / ssh / 专用题型工具） | 提供原子能力：编解码、HTTP、容器/SSH 命令、密码分析、逆向等 |
| L2 智能体层 | `agent/react.py`（ReActEngine） | Thought-Action-Observation 循环、输出解析、熔断对接、总线协作注入 |
| L2 智能体层 | `agent/coordinator.py`（Coordinator） | 巡查指导器：L1 规则预检 + L2 LLM 深度分析、禁忌、方向追踪 |
| L2 智能体层 | `agent/styles.py` | 三风格提示词常量（与巡查风格词表同源） |
| L3 编排层 | `swarm.py`（SwarmCoordinator） | 同题多风格并行、跨进程提交协调、一解出即杀其余 |
| L3 编排层 | `orchestrator/`（CircuitBreaker / AdaptiveBreaker） | 六维熔断、按题型/难度动态步数与时间、动态扩展 |
| L4 通信层 | `bus/message_bus.py` / `bus/file_bus.py` / `events.py` | 进程内消息总线 / 跨进程文件总线 / 进程内事件总线 |
| L4 通信层 | `tools/bus_tool.py` | share_finding / check_findings 两个 ReAct 工具 |
| L5 接口层 | `cli/runner.py` / `main.py` / `solve.py` / `client.py` | CLI、JSONL 协议（1.1）、AgentClient SDK |
| L6 知识层 | `memory/`（short/mid/long/rag/skill_library）+ `skills/` | 四层记忆、RAG、Skill 库、经验库 |
| L6 知识层 | `review.py` / `skill_learner.py` / `experience.py` | 轨迹复盘、Skill 学习、经验沉淀 |
| L6 知识层 | `analyzer.py` | 任务报告生成（Markdown） |

### 2.3 数据流与协作流

1. **领题**：调用器（如 NSS Runner）构造 task JSON（desc/type/difficulty/challenge_id/max_seconds 等），以子进程方式调用 `python -m ctf_agent.solve --task-file <path>`。
2. **编队**：`SwarmCoordinator.run()` 按难度决定风格列表（easy 单路，medium/hard 三路），每路写独立 task JSON（注入 style 字段与带 `:style` 后缀的 challenge_id），各起一个子进程。
3. **并行求解**：每个子进程内 ReActEngine 循环执行；期间：
   - 每 5 步 `check_sanitized` 拉取总线兄弟发现并注入 prompt；
   - 每 5 步检测兄弟提问并强制回答（[MUST]）；
   - 巡查指导器异步分析轨迹，产出指导/禁忌/推论，并把 FACT/LIKELY 事实 post 回总线。
4. **提交协调**：任一子进程提交 flag 且 `verify_flag`（或默认接受逻辑）判定正确 → `_on_submission` 标记解出并 **kill 其余兄弟进程**。
5. **收尾**：全部线程 join 或超时兜底；`SwarmResult` 汇总 winner_style、killed_count、各路结果。
6. **复盘闭环**：单 agent 结果经 `_learn()`（模板 Skill）与 `_review()`（LLM 独立复盘 + 无幻觉核对 + 入库）沉淀；经验闭环 `ingest_solution` 去标识化写入长期记忆。

### 2.4 目录结构

```
WING-Goose/
├── main.py                     # CLI 入口 (run / web 子命令)
├── pyproject.toml              # 包定义 (deps: openai/httpx/pydantic/rich; extra: docker)
├── .env.example                # 环境变量模板
├── data/
│   ├── chroma/                 # ChromaDB 长期记忆
│   ├── skills/                 # md 技能库 (index.json)
│   ├── swarm_tasks/            # swarm 临时 task JSON
│   ├── agent_share/            # 同题共享文件目录 (按 challenge_id)
│   └── api_smoke.json          # LLM provider 冒烟测试结果 (由 controller 写入)
└── ctf_agent/
    ├── config.py               # pydantic-settings 配置
    ├── solve.py                # JSONL 协议独立求解入口 (协议 1.1)
    ├── client.py               # AgentClient SDK (swarm 依赖)
    ├── swarm.py                # SwarmCoordinator 同题多风格并行编排
    ├── review.py               # 轨迹复盘 (LLM 独立上下文 + 无幻觉核对)
    ├── events.py               # In-process EventBus
    ├── experience.py           # 经验闭环 (去标识化入库)
    ├── skill_learner.py        # Skill 学习器
    ├── analyzer.py             # Markdown 报告生成
    ├── stop_signal.py          # 全局 stop 信号
    ├── agent/
    │   ├── react.py            # ReActEngine (核心循环)
    │   ├── coordinator.py      # 巡查指导器
    │   ├── styles.py           # 三风格提示词
    │   ├── prompts.py          # 系统提示词模板 (5 阶段方法论)
    │   ├── multi_agent.py      # CHAP 协议 (Planner/Executor/Critic, Falcon 遗留)
    │   └── failed_trajectory_cache.py  # 失败轨迹缓存
    ├── bus/
    │   ├── message_bus.py      # 进程内消息总线
    │   └── file_bus.py         # 跨进程文件总线
    ├── llm/
    │   ├── client.py           # 基础 LLM 客户端
    │   └── routed.py           # 路由 LLM 客户端 (三级降级)
    ├── orchestrator/
    │   ├── breaker.py          # 六维熔断
    │   ├── adaptive.py         # 自适应熔断 (题型/难度)
    │   └── state.py            # 任务状态
    ├── memory/                 # 四层记忆 (short/mid/long/rag/skill_library)
    ├── skills/                 # 抽象经验库 (library/skill/injector)
    ├── tools/                  # 30+ 工具 (含 docker/bus/shared_fs)
    ├── range/                  # 本地靶场控制 (竞赛场景禁用)
    ├── ssh/                    # SSH 客户端与安全检查
    ├── knowledge/              # Kali 工具清单
    └── web/                    # WebUI
```

### 2.5 依赖与运行环境

`pyproject.toml` 核心依赖：

| 依赖 | 版本 | 用途 |
|------|------|------|
| openai | >=1.40 | LLM SDK（zen/go/官方端点均走 OpenAI 兼容接口） |
| httpx | >=0.27 | 客户端级超时控制、禁代理直连 |
| python-dotenv | >=1.0 | .env 加载 |
| pydantic / pydantic-settings | >=2.6 / >=2.2 | 类型安全配置 |
| rich | >=13.7 | CLI 终端渲染 |
| docker（extra `docker`） | >=7.0 | `DOCKER_BACKEND=sdk` 时的 docker-py 后端 |

运行要求：Python >= 3.10；Windows 宿主 + Docker Desktop（Linux 容器）为默认执行环境；Kali SSH 为降级目标（默认关闭）。

---

## 3. 核心模块详细设计

### 3.1 智能体层：ReAct 引擎（agent/react.py）

#### 3.1.1 引擎职责与循环

`ReActEngine` 是单 agent 的推理核心，实现 Thought → Action → Observation 循环：

1. LLM 输出 Thought + Action + Action Input（或 Final Answer）；
2. 引擎解析输出（`parse_llm_output`）；
3. Final Answer → 反幻觉校验 → 提交/成功返回；
4. 否则调用工具得到 Observation，回灌短期记忆，进入下一轮。

构造参数（WING-Goose 新增参数加粗标注）：

```python
ReActEngine(
    llm, tools,
    max_steps=35, max_format_errors=3, max_rounds=10,
    model=None, temperature=0.0,
    system_prompt=None, mid_term=None, long_term=None,
    task_id=None, skip_hyde=False,
    breaker=None, on_step=None,
    failed_cache=None, challenge_id=None,
    challenge_type=None, challenge_difficulty=None,
    skill_library=None, planner=None, force_max_thinking=False,
    submission_handler=None, max_submissions=1,
    coordinator=None, on_coordinator=None,
    **bus=None, bus_agent_id="", bus_challenge_id="",**   # WING-Goose: 消息总线
    experience_library=None,
    **event_bus=None,**                                     # WING-Goose: 事件总线
)
```

#### 3.1.2 输出解析器（容错设计）

`parse_llm_output` 面向真实 LLM 输出的各种不规范形态做了大量容错，这是 Falcon 时代积累的健壮性资产：

- 字段大小写不敏感；Action Input 可被 ```json``` 包裹；
- `**Action:**` 等 Markdown 加粗装饰剥离（Sprint 14 P4）；
- Action 名只匹配 `[a-z_][a-z0-9_]*` 工具名格式，跳过 `**`；
- `Action(?!\s*:?\s*Input\b)` 负向前瞻避免把 `Action Input:` 的 "Input" 误当工具名；
- Thought 缺失时回退：取 `Action:`/`Final Answer:` 前的文本作为 thought（Sprint 20）；
- Action Input 别名回退：`Input:/Args:/Arguments:/Parameters:/Params:/参数:`（Sprint 20）；
- 漏写 `Action Input:` 前缀时，从文本中提取首个 JSON 对象作为输入（Sprint 20）；
- 代码块 + 首尾 `*`/`_`/`` ` `` 装饰统一剥离（Sprint 15 P6）。

#### 3.1.3 步数软截断（while True + 进展感知）

Sprint 32.4b 修复了"协调器 extend_steps 从未生效"的 bug：旧实现 `for range(max_steps)` 在进入循环时一次性求值，协调器动态扩展的步数永远不会生效。新实现改为 `while True` 循环：

- 每步动态判断 `self.max_steps`（extend_steps 立即生效）；
- 超过 `max_steps` 后**不立即硬停**：若熔断器判定"持续有实质进展"（`has_recent_progress`，最近步有非空 observation）则继续；
- 仅当超限且无进展时才退出；时间维度由熔断器（max_seconds + progress_grace，及 hard_max 3x 保险）兜底。

#### 3.1.4 反幻觉兜底

- **强制工具调用**：任何 Final Answer 若之前没有任何工具调用（`any(s.action and not s.is_error)` 为假），一律判定为幻觉，拒绝并注入提示，让 LLM 先做信息收集。
- **flag 提取**：solve.py 用 `_FLAG_PATTERNS` 正则从最终答案提取 flag（NSSCTF{}/moectf{}/flag{}/CTF{}/athena{} 等格式）。
- **交叉验证**：max 思考强度（thinking_mode）下，prompt 强制要求 Final Answer 前用工具交叉验证。

#### 3.1.5 多次提交机制

当 `max_submissions > 1` 时启用：

- 候选 flag 通过 `submission_handler` 提交（solve.py 输出 `{"type":"submission"}` JSONL，从 stdin 队列读取调用器响应，60s 超时）；
- 已提交过的答案去重驳回；
- 提交失败后不重新开始，在当前上下文继续分析，注入反馈与剩余次数；
- 达到提交上限后不再调用 handler，注入提示继续工具分析（防死循环）；
- `consecutive_format_errors` 安全保护防止 agent 反复 Final Answer。

#### 3.1.6 总线协作注入（WING-Goose 核心增强）

引擎与消息总线深度绑定（`self._bus` / `self._bus_agent_id` / `self._bus_key`）：

**a) 每 5 步 check 兄弟发现（消费端）**

```python
if self._bus is not None and step_no % 5 == 0:
    visible = self._bus.check_sanitized(self._bus_key, since=self._bus_since)
    # 注入 [兄弟发现] 段: "其他并行 agent 已发现以下方向性线索 (仅作参考方向, 需自行探索验证)"
```

- `check_sanitized` 只返回高置信度（FACT/LIKELY）且经消毒的内容；
- 注入时声明来源 agent 与置信度等级；
- `_bus_since` 记录已消费时间戳，增量拉取。

**b) 强制分享关键发现（协作义务）**

每 5 步注入协作义务提示：要求 agent 检查最近几步是否发现了可供兄弟直接复用的关键线索（加密算法与 key/偏移、flag 格式、可复现的绕过方法、已确认的死路），若有则用 `share_finding`（kind=fact/finding）发布。这解决了复盘发现的问题——"agent 从未主动分享的根因是 prompt 无协作引导，而非工具缺失"。

**c) 强制回答兄弟提问**

每 5 步扫描总线中来自兄弟 agent 且本 agent 尚未回答的 `question` 条目，未回答的以 `[MUST] 强制回答` 注入：要求用 `share_finding(kind=answer, reply_to=提问id)` 回复，不清楚时也必须回答"不知道"，防止兄弟 agent 因等待答复而卡死（复盘案例：conservative dantes 死循环）。

**d) 巡查事实发布（发布端）**

巡查指导器每次分析产出 `belief_state` 推论清单，引擎 `_post_to_bus` 只把其中 FACT/LIKELY 等级的非空 statement 发布到总线（topic="coordinator"），与消费端配对形成**双向通信**：

```
post:  本 agent 巡查提炼的高置信度事实 → 总线文件
check: 每 5 步拉取兄弟的 FACT/LIKELY 发现 → 注入 prompt
```

统计字段 `_bus_injected_count` / `_bus_posted_count` 供采纳率/双向性分析。

#### 3.1.7 LLM 调用容错（Sprint 32.8）

每步 LLM 调用带三级容错，保证"中途 API 故障不能整题 0 步失败"：

1. 第 1 次失败 → sleep 2s 重试；
2. 第 2 次失败 → sleep 2s 再重试；
3. 第 3 次失败 → 降级 `model_tier="pro"` 重试；
4. 全部失败 → 注入"LLM API 暂时不可用，请保持当前思路，下一步继续分析"提示并跳过本步（不崩溃），由熔断器时间维度兜底。

### 3.2 三风格：解题风格（agent/styles.py）

#### 3.2.1 风格定义

`STYLE_GUIDANCE` 定义三种解题风格的 system prompt 附加段（swarm 每路注入一种）：

| 风格 | 特征 | 关键引导 |
|------|------|---------|
| conservative（保守） | 侦察先行、小步验证、标准工具链 | 先 file/strings/架构确认；每步先验证假设再推进；对输出做合理性检查；失败先分析原因再重试 |
| aggressive（激进） | 快速试错、多路径并行、已知攻击工具优先 | 优先尝试 ghidra/radare2/angr/内置工具；容忍失败快速换路；有候选答案立即验证 |
| innovative（创新） | 非常规思路 + 创造性工具箱 | 质疑显而易见的结论；卡住时逐条对照"创造性工具箱"5 法（见下） |

创新风格的"创造性工具箱"（针对 T2-REV 复盘发现的"创新创造性不足"专门设计）5 条发散模板：

1. **目标反转**：解密/验证卡住时反问"也许这个文件不是密文而是 key？不是输出而是输入？"
2. **空间重估**：爆破太慢时重新评估实际 key/搜索空间——"名义位宽 vs 实际可达空间"往往远小；
3. **代数结构**：算法看似复杂时找逆变换闭式解/数学结构，而非暴力枚举；
4. **侧信道/内嵌**：表面无线索时检查 rodata/资源段/未引用常量/注释/弱符号；
5. **线索交叉**：把早期某步与最新发现合并成一个新假设再验证。

并强制"快速失败快速换路"：假设被验证失败即明确记录"已证伪"并转向下一个思路，而不是微调参数重试。

#### 3.2.2 风格与巡查联动

风格词表与巡查指导器的风格 prompt 段落**同源**（`STYLE_PARAMS` / `_STYLE_COORDINATOR_SECTIONS`），避免"agent 风格理解"与"巡查风格理解"不一致。巡查按风格差异化：

| 风格 | 巡查间隔 | max_errors | 温度 | 特点 |
|------|---------|-----------|------|------|
| conservative | 5 步（用户约束统一 5） | 3 | 0.0 | 稳健节奏，干预门槛高（至少 FACT+LIKELY 支撑） |
| neutral | 5 | 3 | 0.0 | 均衡节奏 |
| aggressive | 5 | 5 | 0.0 | 快节奏，容忍快速试错；"有效试错"不干预 |
| innovative | 5 | 3 | 0.4 | 探索节奏，必产 creative_hints 灵感板 |

#### 3.2.3 风格注入机制

solve.py 构造引擎时读取 task JSON 的 `style` 字段：

- 有 style → `build_system_prompt(...)` 基础提示词 + 追加 `STYLE_GUIDANCE[style]`；
- 无 style → 走默认保守路径；
- 总线启用时无论有无 style 都追加 `_COOP_GUIDANCE`（兄弟协作引导段，让 agent 知道存在并行兄弟并主动使用 share_finding/check_findings）。

### 3.3 巡查指导器（agent/coordinator.py）

#### 3.3.1 设计思想

**旁观者清，当局者迷。** 解题 Agent 专注当下容易陷入困境或方向走错；巡查指导器作为"第三者"宏观审视完整行为轨迹，代替人在无人监管的独立运行时提供战术指导。

核心原则：

1. **沉默原则**：方向正确且进展正常时保持沉默（should_intervene=false），不打扰 agent；
2. **精准指导**：发现问题时给出具体可操作建议（做什么 + 怎么做 + 为什么），不空谈；
3. **知识增强**：查询 Skill 库 / RAG / 经验库辅助判断；
4. **两级分析**：先 L1 规则预检（快速、不调 LLM），再 L2 LLM 深度分析（精准）。

#### 3.3.2 两级分析（L1 / L2）

**L1-A 规则预检（确定性硬问题，直接 MUST 干预）**：

- 完全重复死循环：同一工具 + 相似参数（路径归一化后）≥3 次；
- 明显方向错误：最近 5 步操作集合与题型期望工具集完全不相交（`_check_direction`）；
- 禁忌操作命中：agent 在尝试已确认无效的操作；
- MUST 指令未执行：上次 MUST 指导后主导工具未变且无实质进展。

**L1-B 软线索（传给 L2，不直接干预）**：

- 工具过度使用（同一工具 ≥5 次但参数不同）——思路固化线索；
- 连续错误步（≥3）——进展停滞线索；
- 指导持久性——上次指导后行为未改变。

**L2 LLM 深度分析（始终触发，如果有 LLM）**：

- 宏观审视完整轨迹（压缩摘要，避免 token 爆炸：前 3 步完整、中间压缩、最近 5 步完整）；
- 结合 L1 线索 + 知识库（Skill top2 + RAG top2 + 经验库 top2）判断方向；
- 输出严格 JSON（reflection / belief_state / should_intervene / priority / guidance / strategic_direction / forbidden_actions / revert_guidance / remove_forbidden ...）；
- JSON 解析失败时降级为"不干预 + extend_steps"，不阻断主流程。

**降级模式**：无 LLM 时 L1-B 软线索也作为干预依据（priority=SHOULD）。

#### 3.3.3 风格化巡查（第 8 节）

- `_STYLE_COORDINATOR_SECTIONS` 为每种风格定制系统提示词段落（保守稳健 / 中立均衡 / 激进快节奏 / 创新双轨）；
- 创新风格：无论是否干预都必产 2-3 条 `creative_hints`（灵感板），且不使用 strategic_direction；
- 非创新风格：仅在干预时随 guidance 注入 `strategic_direction`（战略深化，在主 LLM 当前推理基础上深入细化，不另起炉灶）；
- 沉默原则：方向未偏移时不注入任何内容（含战略方向）。

#### 3.3.4 异步事件驱动（Sprint 33）

巡查分析不再阻塞 agent 主循环：

- `should_check(step_no, max_steps, live_errors)`：判定是否到了发起时机（队列空 + 首次第 10 步 / 上次注入后 check_interval 步 / 连续错误 ≥max_errors 异常触发 / 倒数 early_exit_steps 近上限兜底）；
- `fire_async_analysis(...)`：后台线程 `_async_analyze_worker` 执行分析，队列上限 1（同一时刻最多 1 个在途分析 + 1 个未消费结果，防叠加过频）；
- `consume_pending_guidance(current_step)`：主循环后续步事件召回结果（如第 10 步发起、第 12 步注入），并记录注入时刻作为下次巡查节奏基准；
- 注入时声明来源步数（`[巡查来源] 此指导基于 step N 的轨迹分析结果 (注入于 step M, 滞后 X 步); 若与你的最新进展冲突, 以最新观察为准`），避免过时信息误导；
- 副作用全部回主线程执行（`_apply_coordinator_guidance`），后台线程只做 analyze，避免跨线程竞态；
- 巡查间隔钳制在 5~10 步（`max(5, min(10, check_interval))`）。

#### 3.3.5 禁忌列表与精确签名禁忌

- `_forbidden_actions`：LLM 分析时生成的描述性禁忌（如"hashcat 爆破 cloud.zip 密码"），`intercept_forbidden` 在工具执行前以关键词匹配拦截（仅取长度 >3 的词，降低误伤）；
- `_forbidden_signatures`：Sprint 35 精确签名禁忌——死循环检测时自动把重复的精确 action 签名（action + action_input 前 100 字符归一化）加入集合，拦截完全相同的操作，避免关键词误伤不同命令；
- DISPROVED 推论自动清理对应禁忌项；`remove_forbidden` 支持移除被证伪的误判禁忌；
- 禁忌依据必须是 FACT/DISPROVED，不得基于 POSSIBLE。

#### 3.3.6 全局已尝试方向追踪（Sprint 35）

`_tried_directions` 跨 lookback 窗口记录每个 action 签名的尝试次数、是否有进展、最后步号：

- 每次巡查扫描**完整轨迹**（非仅 recent 窗口）统计每个签名的绝对出现次数；
- `has_progress`：同一签名出现 ≥2 种不同 observation 视为有进展；
- 死循环判定：recent 最近 3 步中的签名在整个轨迹中重复 ≥max_repeats×2（默认 6 次）且无进展 → 全局死循环，强制切换方向；
- 检测到死循环时 `_auto_add_forbidden` 自动把重复操作加入精确签名禁忌（所有风格适用，创新风格也不能重复已确认无效的方向）。

#### 3.3.7 推论分级 belief_state（Sprint 32.6）

巡查 LLM 的每次分析都基于**推论分级框架**，跨巡查持久化：

| 等级 | 含义 | 决策权 |
|------|------|--------|
| FACT | 轨迹中直接观察到的确定信息 | 可作为 MUST 依据 |
| LIKELY | 基于事实的合理推断 | 可作为 MUST 依据（需标注支撑事实） |
| POSSIBLE | 缺乏充分证据的推测 | 只能作为 SHOULD 建议 |
| DISPROVED | 被后续轨迹明确否定 | 立即从禁忌列表移除，不得继续影响决策 |

每次巡查流程：回顾上次推论 → 用最新轨迹事实更新（升级/降级/证否/新增）→ 反思 → 决策。`reflection` 字段（必填，≥30 字）供日志与调试。

#### 3.3.8 MUST 未执行检测（Sprint 32.4 / 32.4c）

复盘发现（#2501 Blast）：协调器 step10 下达 MUST（"停止单字符 MD5 爆破"）后 agent 忽略，继续穷举 20 步。现实现：

- 上次指导是 MUST 且主导工具未变、已过 ≥1 个巡查间隔、且无实质进展 → 升级为 MUST 阻断干预；
- 连续 ≥2 个空 action（格式崩溃）也视为 MUST 未执行（Sprint 35.1 修复：空 action 不能算"工具已改变"）；
- 自我纠错（32.4c）：主导工具未变**但持续有实质进展**（≥2 种不同 observation）不判未执行——agent 可能用自己的方式推进（修复 #2516 误判案例）；
- `revert_guidance=true` 时撤销上次指导并停止 MUST 持久重复注入。

#### 3.3.9 知识库辅助

`_query_knowledge` 直接调用底层 API（不走 RAGRetriever，避免 HyDE 额外 LLM 调用）：

- Skill 库：`format_for_prompt(task_desc, category, top_k=2)`；
- RAG 长期记忆：`long_term.search(task_desc, n_results=2)`；
- 经验库（skill_library.json）：`retrieve_for_task(top_k=2)`，仅 confidence=high 的经验禁忌可触发 [MUST] 纠正，medium/low 仅作参考。

#### 3.3.10 巡查日志

`on_coordinator` 回调输出 `{"type":"coordinator", ...}` JSONL 行（step_no / should_intervene / priority / reason / guidance / forbidden_actions / revert_guidance / reflection / belief_state 等），供调用器观察巡查行为。

### 3.4 swarm 多解题器编排（swarm.py）

#### 3.4.1 职责与定位

`SwarmCoordinator` 是 **runner 层**的同题多风格并行编排器：同一道题起 N 个子进程（每路一个 style），任一子进程提交正确 flag 即 kill 其余兄弟进程，全部线程 join 或超时兜底。它不参与单 agent 内部逻辑，只负责进程编排与提交协调。

#### 3.4.2 难度 → 并发策略

```python
DEFAULT_STYLES_BY_DIFFICULTY = {
    "easy":   [""],                                        # 单路默认保守
    "medium": ["conservative", "aggressive", "innovative"],
    "hard":   ["conservative", "aggressive", "innovative"],
}
```

- 默认（`styles=None`）：按 difficulty 字段查表，未知难度回退三路并行；
- 单路才允许空风格（`""` 代表默认保守），多路时过滤掉空串；
- 配置层面 `swarm_enabled`（config.py，默认 True）控制是否启用 swarm；NSSCTF 难度评判不标准（easy 实为 middle/hard 常见），故所有难度默认都走 3 风格并行。

#### 3.4.3 数据结构

```python
@dataclass
class SwarmAgentResult:
    style: str
    success: bool = False
    flag: str = ""
    steps: int = 0
    elapsed: float = 0.0
    tokens: int = 0
    fail_reason: str = ""
    killed_by_sibling: bool = False   # 兄弟解出后被终止
    result: AgentResult | None = None

@dataclass
class SwarmResult:
    solved: bool = False
    flag: str = ""
    winner_style: str = ""
    elapsed: float = 0.0
    total_tokens: int = 0
    agents: list[SwarmAgentResult] = field(default_factory=list)
    styles: list[str] = field(default_factory=list)
    killed_count: int = 0
    task: dict[str, Any] = field(default_factory=dict)
    # by_style(style) -> SwarmAgentResult | None
```

#### 3.4.4 执行流程

```
run(task, styles=None, max_seconds=600.0, on_step=None, on_log=None) -> SwarmResult
│
├─ 1. 确定风格列表 (默认按难度查表)
├─ 2. 对每个 style:
│     · task 注入 style 字段; challenge_id 改为 "base_id:style"
│     · 写 task JSON 到 workdir (默认 <project_root>/data/swarm_tasks/<base_id>_<style>.json)
│     · 起 daemon 线程, 线程内 AgentClient.solve(task_file, callbacks, max_seconds)
│       - on_proc: 注册子进程句柄到 self._procs (swarm 杀兄弟用)
│       - on_submission: _on_submission(style, flag) — 正确则标记解出 + kill 其余
├─ 3. join 全部线程 (timeout=max_seconds+60)
├─ 4. 超时兜底: kill 全部存活子进程
├─ 5. 汇总 SwarmResult (winner_style / killed_count / agents)
```

#### 3.4.5 一解出即杀其余（核心机制）

```python
def _on_submission(self, style, flag):
    correct, feedback = self._submit(style, flag)
    if not correct:
        return False, feedback
    with self._lock:
        if not self._solved["flag"]:
            self._solved = {"flag": flag, "style": style}
            for st, p in list(self._procs.items()):
                if st != style and p.poll() is None:
                    p.kill()          # 其余兄弟进程直接终止
            return True, "正确! 已解出, 其余并行进程已终止"
    return True, "正确!"
```

- `_submit` 走 `verify_flag` 回调；回调抛异常不冒泡（记录并返回 False，agent 收到明确反馈继续分析）；
- 被兄弟 kill 的路：`raw_result` 为空且非 winner → `killed_by_sibling=True`（用于统计 killed_count）；
- `stop()` 方法供外部（如 NSS Runner stop 信号）kill 全部存活进程。

#### 3.4.6 verify_flag 设计约定（Crypto_Reverse 复盘）

swarm.py 文档字符串明确记录的设计约定：

> - verify_flag 的职责是"平台/确证性校验"（如 NSS 真实提交），不是"防幻觉"（防幻觉已由 react.py 内部兜底：无工具调用直接 Final 会被拒绝）；
> - 只有存在确凿反证（明确不匹配证据）时才返回 False；无法判定时应**倾向返回 True**（接受 + 调用者自行审计），否则会误伤已真实解出的 flag、带偏 agent 并导致兄弟 kill 不触发（资源空转）；
> - 回调抛异常不冒泡：记录并返回 False，agent 收到明确反馈继续分析。

默认（`verify_flag=None`）接受第一个提交的 flag 为解出。

### 3.5 消息总线（bus/）

#### 3.5.1 进程内总线 MessageBus（bus/message_bus.py）

纯宿主侧、无外部依赖的 append-only findings 总线：

- **append-only**：条目只追加，不修改/单条删除（仅超量整体裁剪例外）；
- **cursor 游标**：每个 reader 独立持游标（整数，已读到的最大 id），`check(cursor)` 返回 `id > cursor` 的条目 + 新游标（全局最大 id）；游标是整数 id，不受裁剪影响（新条目 id 仍单调递增 > 旧游标）；
- **task_id 过滤**：`check` 可选只投影指定任务的条目，但游标仍按全局推进（过滤是投影而非独立游标，语义简单，跨任务共享同样正确）；
- **裁剪**：超 `max_entries`（默认 200）时丢弃最旧条目；
- **线程安全**：`threading.Lock` 保护，支持多 agent 并行 post/check。

```python
@dataclass
class Finding:
    id: int
    agent_id: str
    task_id: str
    content: str
    kind: str = "finding"        # fact/hint/finding/question/answer
    reply_to: int = 0            # 回答时引用的提问 id (0 = 独立发现)
    created_at: float = time.time()

bus = MessageBus(max_entries=200)
fid = bus.post(agent_id, task_id, content, kind="finding", reply_to=0)  # -> 全局 id
new_entries, new_cursor = bus.check(cursor=0, task_id=None, kind=None)
```

`get_default_bus()` 提供进程内共享默认总线单例（真实解题入口 solve.py/web/main 直接用它接入共享发现工具；同进程多 agent 天然共享同一条总线）。

#### 3.5.2 跨进程文件总线 FileBus（bus/file_bus.py）

swarm 多进程场景下，每路 agent 是独立子进程，进程内总线不可见，因此用**共享文件总线**：每个 challenge 一个 JSONL 文件，原子 append（锁保护）。

```python
bus = FileBus(bus_dir)
bus.post(challenge_id, content="...", agent="aggressive", level="FACT", topic="key")
msgs = bus.check_sanitized(challenge_id, since=ts)   # 消毒后的可见消息
```

**传播策略（T4 决策点 + 优化）**：

1. **分级过滤**：`visible(msg)` 只传播高置信度发现（level ∈ FACT/LIKELY），POSSIBLE 不传播，防误导；
2. **内容消毒** `sanitize_content`（T4 测试发现命令级具体线索会诱导 agent 反复验证细节，优化为只保留方向性描述）：
   - 移除 URL 查询参数（保留路径，如 `/?q=xxx` → `/`）；
   - 移除具体 SQL/payload 片段（保留技术名称，如 UNION SELECT）；
   - 移除 `IP:端口`（替换为 `<target>`）；
   - 限制 200 字符；
3. 原始消息保留在文件中（供调试），注入用消毒版本。

**MessageBus 兼容接口**：`post_finding(agent_id, task_id, content, kind, reply_to)` / `check_findings(cursor, task_id, kind)` 以 task_id 为键、seq 为游标（扫描现有行取最大 id + 1 自增），使 `share_finding`/`check_findings` 工具**跨进程复用**：各进程读写同一 bus_dir 下的同一 JSONL 文件，兄弟可见。

#### 3.5.3 总线工具（tools/bus_tool.py）

两个 ReAct 工具基于总线，**鸭子类型适配** MessageBus 与 FileBus（`hasattr(bus, "post_finding")` 判定）：

**`share_finding`**（ShareFindingTool）——发布解题发现/问题/回答：

- `kind` 扩展：fact（已验证事实）/ hint（线索）/ finding（发现）/ question（向兄弟提问，如"flag 格式是什么？"）/ answer（回答兄弟提问，用 reply_to 引用提问 id）；
- 发布后返回条目 id（如"已发布发现 #7 (task=..., kind=finding)"）；
- 工具描述引导 agent"不确定/猜测内容建议先在本地验证再发布"。

**`check_findings`**（CheckFindingsTool）——读取游标后的新发现：

- 首次 `cursor=0`，之后用返回的 `next_cursor` 增量读取；
- `kind=question` 只看提问；answer 条目标注 `[答#提问id]`；
- **强制回答检查**：扫描全部条目，找出来自其他 agent 且本 agent 尚未回答的提问，输出 `[MUST] 你收到了来自兄弟解题器的提问, 必须立即回答:` 段落，要求用 `share_finding(kind=answer, reply_to=提问id)` 回复，不清楚时回答"不知道"，防止提问方卡死。

**零侵入**：`default_tools` 未收到 message_bus 实例时不注册这两个工具，工具列表完全不变（回滚语义）。

#### 3.5.4 事件总线 EventBus（events.py）

In-process EventBus 是"渐进式事件化"的第一步（为后续架构演进铺路）：

- 极简：只有 `subscribe / emit / unsubscribe / clear` 四个方法 + `event_count` 计数；
- 线程安全：swarm 多线程场景下可用；
- 可选：ReActEngine 的 `event_bus` 参数默认 None，不影响现有行为；
- 不替换 callback：与现有 on_step/on_coordinator 并行，逐步迁移；
- 异常不传播：emit 时 handler 抛异常被捕获，永不阻塞 emitter。

推荐事件类型（命名约定，不强制）：

| 事件 | payload 关键字段 |
|------|-----------------|
| step.started | step_no / action / challenge_id |
| step.completed | step_no / action / observation / elapsed |
| flag.found | flag / step_no / challenge_id |
| coordinator.guidance | should_intervene / reason / step_no |
| skill.injected | source / skill_ids |
| bus.message | agent_id / level / content |
| engine.started | challenge_id / challenge_type / max_steps |
| engine.finished | challenge_id / success / steps / elapsed |

ReActEngine 已在 `engine.started` / `engine.finished` / `step.completed` 三处实际 emit。

### 3.6 轨迹复盘（review.py）

#### 3.6.1 定位

`TrajectoryReviewer` 是 **T6 验证流程封装**：从解题轨迹中提取可复用经验。与 `skill_learner._learn()`（模板生成、不调 LLM、每题都跑）互补——`_review()` 是 LLM 深度复盘、高质量、仅步数 ≥8 且轨迹文本 ≥200 字符时运行。

三个特点：

1. **独立上下文**：LLM 只读轨迹文本，不看解题过程内部状态（避免自我辩解偏差）；
2. **无幻觉核对**：逐条核对 facts 中的实体是否在轨迹中出现（实体关键词匹配）；
3. **可选入库**：skills 可入 md 技能库（`ingest_skills`）。

#### 3.6.2 复盘 Prompt（_REVIEW_PROMPT）

独立复盘分析师角色，输入多条轨迹（`===== 轨迹 [style] =====` 分段），任务：

1. `facts`：提取可核验的事实，只写轨迹中明确出现的事实，每条标注来源（轨迹名 + 步骤号）；
2. `lessons`：总结哪些操作无效/浪费（如反复试被过滤的 payload）、哪些思路有效；
3. `skills`：整理 2-3 条可复用 skill，面向未来同类题可直接照做，必须只用轨迹中出现过的技术。

严格输出 JSON（含 skill 的 title/category/trigger/body/tags/tools/pattern_features/evidence_steps 字段），强制"整个回答必须是且仅是一个合法的 JSON 对象"。

#### 3.6.3 多级 JSON 解析（_parse_review_json）

对 LLM 输出做 4 级 fallback：

1. ```json 代码块提取；
2. 从末尾平衡匹配提取最后一个完整 JSON 对象；
3. 直接 json.loads；
4. 单引号规范化（`'key':` → `"key":`、字符串引号转换、True/False/None 归一）后 json.loads，最后 ast.literal_eval 兜底。

#### 3.6.4 无幻觉核对（check_no_hallucination）

```python
_CLAIM_ENTITIES = re.compile(
    r"private_notes|sqlite_master|/\*\*/|127\.0\.0\.1|athena\{|400|500|"
    r"union|like|http_request|ssh_python|空格|注释|过滤|引号|"
    r"AES|CBC|RSA|Feistel|DES|XOR|base64|rot13|jwt|session|cookie|"
    r"flask|django|php|nginx|apache|docker|gdb|objdump|strings|nc|", re.I)
```

流程：把全部轨迹文本拼成 blob（lower）；对每条 fact 的 claim 提取命中实体集合；凡是**实体未在轨迹 blob 中出现**的即标记 missing；任一 missing → `no_hallucination=False`。返回明细（fact_claims_checked / fact_rows / no_hallucination）。

#### 3.6.5 入库与封装

- `ingest_skills(result, skill_library)`：逐条 `add_or_update` 入库（title/category/trigger/body/tags/tools/pattern_features，source_task="trajectory_review"），返回入库 skill ID 列表；
- solve.py `_review()` 封装：`no_hallucination=True 且 skill_count>0` 才入库；检测到幻觉时打 WARN 并跳过入库。

### 3.7 记忆层（memory/ + skills/）

#### 3.7.1 四层记忆架构

| 层 | 实现 | 内容 | 生命周期 |
|----|------|------|---------|
| 短期记忆 ShortTermMemory | 内存 | 当前 ReAct 循环最近 max_rounds（默认 10）轮交互 + system prompt + task | 单轮解题 |
| 中期记忆 MidTermMemory | SQLite | 当前任务关键 facts（remember_fact 工具写入），每轮推理前强制注入 | 单任务 |
| 长期记忆 LongTermMemory | ChromaDB | 跨任务 writeup 向量库（experience.py 去标识化沉淀） | 全局持久 |
| Skill 库 | md 文件 + index.json | 结构化解题套路（vuln_class + recon_steps + tool_chain） | 全局持久 |
| 经验库 skill_library.json | JSON | 抽象解题方法 + 禁忌（skills/ 包） | 全局持久 |
| 失败轨迹缓存 FailedTrajectoryCache | 内存/磁盘 | 失败轨迹 + 反思，重跑同题时注入 | 按 challenge_id |

#### 3.7.2 短期记忆（ShortTermMemory）

- 消息结构：`[system, task, (assistant_1, obs_1), (assistant_2, obs_2), ...]`；
- system_prompt 与 task 永久保留；中间的 (assistant, observation) 按滑动窗口裁剪；
- `update_system_prompt`：每轮刷新 system prompt（动态注入中期记忆 facts 与 RAG）；
- `add_user_message`：追加额外 user 消息（巡查指导 / Skill 注入 / 兄弟发现 / 强制回答等），`get_messages` 时追加并自动清空（用完即清，避免重复注入）。

#### 3.7.3 注入时序（ReActEngine 每轮）

每步循环内按序可能注入：

1. system prompt 刷新（mid-term facts + RAG，若有）——`_inject_context`；
2. 巡查指导（`_coordinator_guidance`，含 [MUST] 持久注入，剩 `_must_repeat_left` 次强调；来源步数标注）——Sprint 33 异步召回后注入；
3. 兄弟发现块（每 5 步，bus check_sanitized）；
4. 协作义务提示（每 5 步）；
5. 强制回答指令（每 5 步，若有 pending 提问）；
6. 做题中动态 skill 检索（每 8 步，`skill_library.format_for_mid_solve` 基于累积 observation 匹配 pattern_features）；
7. 经验库 mid-solve 动态注入（每 8 步，10 步冷却 + 去重，top_k=2，min_score=0.3）；
8. LLM 推理 → 解析 → 工具调用 → observation 回灌（`OBSERVATION_TEMPLATE`）。

#### 3.7.4 RAG 与 HyDE

- 任务开始时一次性检索（不每轮刷新，节省 LLM 调用）：`RAGRetriever.retrieve(task)` 经 HyDE（假设性文档生成）检索相似历史方案注入 system prompt；
- 巡查指导器不走 RAGRetriever（避免 HyDE 额外 LLM 调用），直接用 `long_term.search(task_desc, n_results=2)` 语义检索；
- 成功解题后 `ingest_solution`（experience.py）去标识化（flag/绝对路径/内存地址脱敏）写入长期记忆，实现知识库自增长。

#### 3.7.5 Skill 体系

- **md 技能库**（memory/skill_library.py）：`SkillLibrary()` 提供 `format_for_prompt`（开局注入 top3）/ `format_for_mid_solve`（做题中套路匹配）/ `add_or_update` / `prune`（自我迭代控制规模）；
- **抽象经验库**（skills/）：`Skill`（vuln_class + recon_signatures + recon_steps + exploit_template + tool_chain + notes 禁忌 + confidence）、`get_default_library()`、`format_mid_solve_injection` 注入器；confidence=high 的经验禁忌可触发 [MUST] 纠正；
- **Skill 学习器**（skill_learner.py）：`learn_skill(task, result, library, ...)` 从解题结果提炼可复用 skill（成功→套路，失败→避坑），solve.py 每题结束后调用；
- **失败轨迹缓存**（failed_trajectory_cache.py）：失败时存储 + 自动 `reflect()` 生成反思，重跑同 challenge_id 时注入失败历史提示；成功解出后清理该题失败历史。

### 3.8 工具层（tools/）

#### 3.8.1 工具集总览

`default_tools()` 按开关组装工具集（`tools/__init__.py`）：

| 分组 | 工具 | 依赖 |
|------|------|------|
| L1 内置 | base64_encode/decode、hex_encode/decode、url_encode/decode、caesar_cipher、rot13、hash_compute/identify、file_type、strings、hex_dump | 无（纯 Python） |
| HTTP | http_request | 无 |
| 编码辅助 | encoding_helper_tools（Sprint 23） | 无 |
| 本地密码学 | crypto_rsa、crypto_classic（Sprint 16） | 无 |
| Exploit 模板 | exploit_template（Sprint 19） | 无 |
| 总线协作 | share_finding / check_findings（S12） | 传 message_bus 时注册 |
| 共享文件 | list_shared_files / read_shared_file / write_shared_file（S13） | 传 shared_fs_dir 时注册 |
| 执行层 | ssh_exec / ssh_python / ssh_upload（主名，docker 或 ssh 后端） | docker_client 或 ssh_client |
| 专用题型 | binary_analyze、mem_xor_analyze、osint（exiftool/steghide/binwalk/tshark）、apk（jadx/apktool）、sage（common_d_attack）、reverse_image（web_search/osm_geocode）、ocr、ecdsa_nonce_reuse、angr_symbolic_exec、des_cryptanalysis、feistel_decrypt、web（web_recon/fingerprint/dirscan/sqlmap）、lfi（lfi_scanner/log_inject）、pwn（pwn_checksec/cyclic/ropgadget/exploit）、vision_analyze、range_control | exec_client（docker 或 ssh） |
| MCP | ghidra_headless / radare2（enable_l3） | exec_client |

**WING-Goose 关键变更**：执行层工具**独立注册**——docker 优先，ssh 降级：

```python
exec_tools = []
exec_client = None
if docker_client is not None:
    exec_tools = docker_tools(docker_client)      # 仅 docker 可用时返回非空
    exec_client = docker_client
if not exec_tools and ssh_client is not None:
    exec_tools = ssh_tools(ssh_client)            # 降级到 ssh
    exec_client = ssh_client
tools.extend(exec_tools)
```

修复了 S14 发现的 bug：旧实现把 docker 工具链放在 `if ssh_client is not None` 分支内，导致关闭 Kali（无 ssh）时 docker 工具也丢失、纯 Docker 环境无执行层。现在专用题型工具（osint/apk/sage/ecdsa/angr/web/pwn/...）统一基于 `exec_client`（接口只有 `exec_cmd`），docker 或 ssh 均可 → **纯 Docker 环境下经验同样可用**。

#### 3.8.2 Docker 执行链（tools/docker_tool.py）

**降级链（层层降级）**：

```
docker_exec / docker_python (Docker Desktop 常驻容器, 默认)
        ↓ 降级
ssh_exec / ssh_python (Kali VM, 内置工具保留)
        ↓ 降级
MCP 工具 (结构化扫描)
```

**DockerClient** 封装 `docker` CLI（subprocess 直调）或 docker-py SDK，复用 SSHClient 的 `CmdResult` 结构，让上层工具与 ssh 版**签名完全一致，切换零成本**：

```python
client = DockerClient(image="wing-goose:v2", container_name="wing-goose-worker",
                      workdir="/challenge", backend="sdk", ...)
result = client.exec_cmd("ls -la")     # CmdResult(stdout/stderr/exit_code)
client.upload_file("local.bin", "/challenge/local.bin")
```

**资源调控 Profile（S3，多容器并行基础）**：

| Profile | CPU | 内存 | 适用 |
|---------|-----|------|------|
| light | 1 核 | 1g | web / misc 轻量 |
| normal | 2 核 | 2g | 一般题目（默认，crypto 计算 / pwn 调试） |
| brute | 4 核 | 2g | 爆破类（内存按难度覆盖） |
| heavy | 4 核 | 4g | angr / sagemath 大格 / 内存取证 |

- 原则：**内存严格按难度（独占资源防 OOM）**，CPU 按题型宽松上限（爆破类 4 核）；
- 统一追加：`--memory-swap` 同值（禁 swap 逃逸拖垮宿主）+ `--pids-limit 512`（防 fork bomb）+ `--cap-add SYS_PTRACE` + `--security-opt seccomp=unconfined`（CTF 调试必需）；
- `resolve_quota(profile, cpu_cores, mem_limit)`：Profile 表 + 显式覆盖；
- `compute_max_containers`：§13.3 并发度模型——`usable = total × (1 - reserve)`，`max = min(usable_cpu // profile.cpu, usable_ram // profile.ram)`，预留因子默认 0.25；
- `ContainerScheduler`：全局容器并发信号量（线程安全），运行中容器数 ≤ max_containers，超出阻塞等待，供多 agent 并行调度复用。

**S1 快路径**（消灭固定 sleep 1 轮询开销）：基线实测 docker exec CLI 全链路约 144ms，而原 B+ 后台轮询 p50 = 1.14s。快路径判定（`_use_fast_path`）：

- timeout 未声明（None）→ 快路径（默认调用多为快速命令）；
- timeout == "quick" → 快路径（30s 窗口）；
- wait_sec ≤ 15（`_FAST_SYNC_THRESHOLD`）→ 快路径；
- normal/long/background/大整数 → B+ 后台（保留软超时转后台 + PID 追踪）；
- `FAST_PATH_ENABLED` 总开关可还原 Step 0 行为。

**S2 容器消失自愈**：exec 返回非零且 stderr 命中容器消失模式（"No such container"/"is not running"/"Cannot connect to the Docker daemon"/"error during connect"）→ 标记 `_container_ok=False` → 本调用内自愈重试一次（`ensure_container` 重建）→ "下一次 exec 即恢复"。

**S4 多容器 + task label**：容器名外部参数化（`wing-goose-{agent_id}`，`_sanitize_name` 限制 [a-zA-Z0-9_.-] 且 ≤60 字符），每 agent 独立容器；`task_id` 写入 label，同题复用（不重建），异题标记 `_task_mismatch`。

**S5 跨题重置 + 附件挂载**：

- `ENABLE_TASK_RESET=True`：异题 → rm + run 全新环境（消除跨题污染）；开关关闭退回 S4 兼容复用；
- 附件宿主目录 bind mount 到容器 `/challenge/workspace`（rm 容器不影响宿主文件）；容器已存在但缺挂载时重建（S14 修复：否则 agent 容器内找不到附件，白白浪费整题时间）；
- `cleanup_orphans()`：清理 label=ctf-agent=true 且已停止的孤儿容器（仅清理非运行容器，不误删并行 agent 正在使用的容器）。

**S8/S9 后端抽象**：`DockerBackend` 语义级接口（探测/生命周期/exec/上传下载），`CliBackend`（subprocess）与 `SdkBackend`（docker-py）等价实现：

- `make_backend(name)`：`"cli"` → CliBackend；`"sdk"` → SdkBackend；docker-py 缺失时 sdk 请求**降级为 cli**（warnings 提示）保降级链可用，而非崩溃（S10）；
- SDK 后端细节：exec 用底层 API（exec_create + exec_start + exec_inspect）+ 后台线程 join 实现超时（docker-py 高层 exec_run 无 timeout 参数），超时语义与 CLI subprocess 一致（宿主侧断开，容器内进程继续执行）；exec_create 传命令时补回 `sh -lc` 包装（SDK 字符串命令无 shell 语义，管道/重定向/; 会失效）；upload/download 经 tar 流（put_archive/get_archive），注意容器内路径是 Linux 风格不能用 pathlib；
- `_parse_volume_spec`：修复 Windows 盘符路径（`C:/host:/ctr`）被 partition(":") 拆错的 bug（旧实现把盘符 C: 拆成命名卷名 "C"，导致 Windows 宿主路径挂载全部错位）。

**工具命名统一（WING-Goose 决策）**：`DockerExecTool` 主名 `ssh_exec`（别名 `docker_exec`）、`DockerPythonTool` 主名 `ssh_python`（别名 `docker_python`）、`DockerFileUploadTool` 主名 `ssh_upload`（别名 `docker_upload`）——与 Kali 经验一致，**经验跨场景可用**（LLM 无论用经验中的旧名还是 docker 前缀名都能命中同一工具）。`_tool_map` 支持别名注册，主名优先。

**工具内容引导**：DockerExecTool 描述引导 agent 先 `cat /tools.txt` 查看容器内全部预装工具（网络/逆向/取证/隐写/密码学/Python 库），缺少时 `apt-get install -y` / `pip3 install` 临时安装（已预配清华镜像源）。

#### 3.8.3 共享文件工具（tools/shared_fs_tool.py）

多 agent 同题协作时通过宿主共享目录互通文件（`data/agent_share/{challenge_id}`）：

- `list_shared_files`：列出兄弟放入的文件（名/大小/修改时间）；
- `read_shared_file`：读取内容（文本上限 64KB，超限截断；非 UTF-8 显示前 200 字节十六进制）；
- `write_shared_file`：写入文件供兄弟读取（UTF-8，同名覆盖）；
- 配合容器 `/shared` 挂载（DockerClient.shared_dir），agent 可在容器内直接访问同一目录（`docker_exec` 的 /shared），实现"容器内读写 + 工具经宿主读写"双通道；
- **路径安全**：`_safe_name` 只允许简单文件名（禁止绝对路径/../目录穿越），防越权访问宿主其他目录；
- **零侵入**：default_tools 未配置 shared_fs_dir 时不注册。

### 3.9 LLM 路由容错（llm/routed.py）

#### 3.9.1 三级降级与 go-only 模式

`RoutedLLMClient` 支持 `model_tier`：

- `"flash"`（默认）：zen → go → 官方 flash fallback（→ pro，可选）；
- `"pro"`：flash 失败后跳 pro；
- `"pro_only"`：直接 pro（Sprint 26 deprecated）。

**WING-Goose 关键变更——`LLM_PROVIDER` 模式**（config.py，默认 `"go"`）：

- **`go` 模式**（国内部署冲榜默认）：只走 Opencode go 付费层（deepseek-v4-flash，定价与官方一致且无峰谷收费倍率），`_should_try_zen()` 恒 False；go 失败**直接抛错，禁用官方/pro 降级链**——领题前冒烟测试已保证 go ≤10s 响应，降级链反而浪费时间；
- **`auto` 模式**（调试期保留）：zen（免费 flash-free）→ go → 官方 flash 三级降级，zen 连续失败 5 次进入 60s 跳过期，5xx 不重试直接降级。

#### 3.9.2 客户端级超时与直连

- 客户端全部使用 `httpx.Timeout` 客户端级超时：zen 45s / go 90s / fallback 30s / pro 120s；
- **WING-Goose：全部 client 强制 `http_client=httpx.Client(proxy=None, trust_env=False)` 直连（禁系统代理）**——复盘案例 #2664：走 127.0.0.1:7890 代理导致 go 请求 45s+ 超时，每步 LLM 耗时 90s+，easy 题 12 分钟才解出；国内部署模型必须直连国内 IP，响应快且稳定；
- go 超时 45→90s（thinking 长推理常超 45s，45s 硬超时会触发 3 轮重试链 45×3+2×2=139s 白扔，放宽后长思考一次成功，见 #2669 复盘）。

#### 3.9.3 wall-clock 总超时

httpx read timeout 防不了慢速流（服务器持续缓慢发 chunk，每次间隔 < read timeout，ssl.read 永远不返回）。`_call_with_wallclock` 用 daemon 线程 + `join(timeout)` 做应用层总超时：

- `_CALL_WALLCLOCK = 45.0`（单次 create 硬总超时，zen/fallback）；
- `_GO_WALLCLOCK = 90.0`（go 分支专用，thinking 长推理生成 45s+ 常见）；
- 超时抛 TimeoutError，provider 被动态标记 down，不会反复创建线程（daemon 线程即使底层 socket 阻塞也不阻止进程退出）。

#### 3.9.4 动态 provider 健康状态

冒烟测试标记不是"终身制"（Sprint 32.8）：

- 连续失败 ≥2 次（`_PROVIDER_FAIL_THRESHOLD`）→ 标记 down + 进入 120s 跳过期（`_PROVIDER_SKIP_AFTER_FAIL`）；
- 调用成功 → 立即恢复健康（清除故障状态）；
- 距上次失败超过 60s（`_PROVIDER_RESET_SECONDS`）计数清零（视为新一轮）；
- 优先级：动态 down_until（中途故障）> 冒烟测试标记 > 默认 True。

#### 3.9.5 冒烟测试

- `smoke_test(timeout=10.0)`：领题前快速探测所有可用 provider（冲榜场景 LLM API 不可用时，与其每次调用等 45s×3 超时重试，不如启动前/领题前快速探测）；
- go-only 模式只探测 go（不浪费 10s×N 探测其他 provider）；
- `apply_smoke_from_file`：agent 子进程启动时读取 `data/api_smoke.json` 应用 controller 领题前的探测结果；
- 探测方法：`chat.completions.create(messages=[{"role":"user","content":"ping"}], max_tokens=1, timeout=t)`。

#### 3.9.6 思考模式（thinking_mode）

- `enable_thinking_mode=True` 时按难度注入 `reasoning_effort`（easy/medium→high，hard/extreme→max，未知→default）；
- 优先级：`force_max_thinking`（重试强制 max）> hard/extreme → max > medium+深度分析题型（reverse/pwn/crypto/misc）→ max > medium 套路化 → high > easy → high > 未知 → default；
- **2026-08-03 根因修复（go/opencode 端点）**：deepseek-v4-flash 升级为 reasoning 模型后，go 端点为 Agent 类请求，思考链强制无界生成，非 none 的 effort 一律撞满 max_tokens（74-86s/次，content=0），提示词压缩/thinking disabled/effort 分级全部无效（9 组受控实验定论）。唯一可控档 = `"none"`：`llm_provider == "go"` 时 `payload["reasoning_effort"] = "none"`，思考归零、content 正常、每步 10-20s（推理由 ReAct Thought 承担）；
- 思考模式不支持 temperature/top_p（设置不报错但不生效）。

### 3.10 熔断（orchestrator/）

#### 3.10.1 六维熔断（breaker.py）

`CircuitBreaker` 实现六维熔断：

| 维度 | 默认阈值 | 动作 |
|------|---------|------|
| 时间 | max_seconds（默认 1800s） | 终止（进展感知见下） |
| 重复动作 | 同一 (action, action_input) 重复 >3 次 | 注入"切换策略"提示 |
| 思维死锁 | LLM 连续 5 轮相同 Thought | 注入"跳出循环"提示 |
| 步数 | max_steps（动态） | 终止 |
| 成本 | 累计 > max_cost_usd（默认 $1.5） | 终止 |
| 文件膨胀 | 工作目录 > 1GB | 注入"清理临时文件"提示 |

- 成本维度：`record_llm_call(tokens, model)` 按模型定价表估算（假设 75% input / 25% output）；
- 无效步数检测：action 相同 + observation 高相似（相似度阈值 0.85，连续 ≥5 步）；
- 单步耗时上限 120s；
- **Sprint 32.4 进展感知时间熔断**（#2501 复盘修复）：到 max_seconds 不"一刀切"终止——有实质进展（最近步非空 observation）则进入 progress_grace 宽限，时间熔断由 hard_max 3x 保险兜底。

#### 3.10.2 自适应熔断（adaptive.py）

`AdaptiveBreaker` 按题型+难度动态决定 max_steps / max_seconds：

```python
_DIFFICULTY_MULTIPLIER = {"easy": 1.0, "medium": 1.5, "hard": 2.5}
_TYPE_MULTIPLIER = {"pwn": 1.5, "reverse": 1.2, "crypto": 0.8,
                    "web": 1.0, "forensics": 1.2, "misc": 1.2, "osint": 1.0}
BASE_STEPS = 60; HARD_MAX_STEPS = 200
```

- `compute_max_steps(type, difficulty)`：BASE_STEPS 60 × 难度倍率 × 题型倍率，上限 200；
- max_seconds 下限兜底（尊重调用方传入值，不压上限）：hard ≥2700s（pwn/forensics/reverse hard ≥3000s）、medium ≥1200s、其他 ≥900s；
- **动态扩展**：`extend_steps(additional=20)` 每次 +20 步，最多 2 次（`MAX_EXTENSIONS`），上限 200——巡查指导器判断方向正确时调用，`extend_steps` 立即生效（配合 react.py 的 while True 软截断）；
- solve.py 中 `task.max_steps <= 0` 时取 `breaker._dynamic_max_steps`。

### 3.11 端到端解题流程（swarm 视角完整时序）

以下时序以 NSS Runner + SwarmCoordinator + 三路 agent（conservative/aggressive/innovative）+ FileBus + Docker 执行链为例，串起全部模块：

```
调用器 (NSS Runner)                      SwarmCoordinator                agent 子进程 (×3)
     │                                        │                              │
     │ 1. 领题 (题目 ID/描述/难度)            │                              │
     │ ─────────────────────────────────────► │                              │
     │                                        │ 2. 按难度确定 styles         │
     │                                        │    easy→[""]; medium/hard→3路 │
     │                                        │ 3. 写 task JSON (style/challenge_id:style/
     │                                        │    bus_challenge_id/bus_dir/annex_dir) 到
     │                                        │    data/swarm_tasks/          │
     │                                        │ 4. 每路起线程 AgentClient.solve()
     │                                        │ ── on_proc 注册子进程句柄 ──► │
     │                                        │                              │ 5. solve.py 启动
     │                                        │                              │    · 引擎构造 (150s 超时兜底)
     │                                        │                              │    · 消息总线初始化 (FileBus)
     │                                        │                              │    · DockerClient ensure (S4 多容器/
     │                                        │                              │      S5 附件挂载/S3 资源配额)
     │                                        │                              │    · 输出 {"type":"start"} + 心跳线程
     │                                        │                              │ 6. ReAct 循环:
     │                                        │                              │    · 每步: 巡查异步 fire/consume、
     │                                        │                              │      总线 check_sanitized (每5步)、
     │                                        │                              │      协作义务、强制回答、skill 注入、
     │                                        │                              │      LLM 调用 (三级容错)、工具执行
     │                                        │                              │ 7. 巡查分析完成 → 指导注入 +
     │                                        │                              │    FACT/LIKELY 事实 post 到总线
     │                                        │◄── bus.post / bus.check ────►│  (跨进程共享)
     │                                        │                              │ 8. 某路 (如 innovative) 解出:
     │                                        │◄── {"type":"submission"} ────│
     │ 9. verify_flag(flag) 确证              │                              │
     │  ◄─────────────────────────────────── │                              │
     │  (平台提交, 返回正确)                  │                              │
     │                                        │ 10. _on_submission 标记解出    │
     │                                        │     + kill 其余两路子进程 ──► │ (其余被终止)
     │                                        │ 11. join 线程; 超时兜底 kill  │
     │                                        │ 12. 汇总 SwarmResult          │
     │ ◄────────────────────────────────────  │  (solved/winner_style/       │
     │                                        │   killed_count/agents)        │
     │ 13. 记录成绩; 结束                     │                              │
```

单 agent 子进程内部（solve.py `_build_engine` → `engine.run(desc)`）完整顺序：

1. **配置与工具装配**：读取 .env → `RoutedLLMClient`（应用 api_smoke.json 冒烟标记）→ Kali SSH（`KALI_ENABLED` 开启才尝试，失败降级纯 Docker）→ DockerClient（容器名 `wing-goose-{agent_id}`，附件挂载、共享目录挂载）→ `default_tools`（docker 优先，ssh 降级，bus/shared_fs 按传入注册）。
2. **引擎构造**：`AdaptiveBreaker`（题型/难度动态步数与时间）、`SkillLibrary`、经验库、`LongTermMemory`（失败静默降级）、`Coordinator`（按 style 差异化参数与 prompt）、style 注入（STYLE_GUIDANCE + _COOP_GUIDANCE）。
3. **任务启动**：输出 start JSONL（协议版本 1.1）、启动心跳线程（15s）、启动 stdin 统一分发器。
4. **ReAct 循环**（详见 3.1）：每步按 3.7.3 的注入时序组织 prompt → LLM → 解析 → 反幻觉校验 → 工具调用 → observation 回灌 → 熔断检测；每 5 步总线 check/协作义务/强制回答；巡查异步分析。
5. **提交与收尾**：Final Answer → 反幻觉兜底 → submission_handler（输出 submission JSONL，从 stdin 队列等响应 60s）→ 成功返回 / 失败注入反馈继续。
6. **闭环沉淀**：`_learn()`（模板 Skill）→ `_review()`（LLM 独立复盘 + 无幻觉核对 + 入库）→ 结果 result JSONL。
7. **结果输出**：`_extract_flag` 提取 flag，输出 `{"type":"result", ...}`，退出码 0/1。

### 3.12 协作消息生命周期（示例）

以"aggressive 发现关键线索 → innovative 复用并提问 → conservative 回答"为例：

```
时间线 (总线文件 data/bus/nss_2314.jsonl):
────────────────────────────────────────────────────────────────────────
[agg]  step 8   post_finding(kind=finding, level=FACT)
                content="目标表前 2 项与 md5(单字符) 不匹配, 单字符爆破已证伪"
                → seq=1
[inn]  step 10  check_sanitized → 注入 [兄弟发现] (消毒后内容, 方向性线索)
[inn]  step 12  post(kind=question) "flag 格式是什么? 是 athena{} 还是 NSSCTF{}?"
                → seq=2
[con]  step 15  check_findings → 检测到 pending 提问 → 注入 [MUST] 强制回答
[con]  step 16  post_finding(kind=answer, reply_to=2) "NSSCTF{...} 格式"
                → seq=3
[inn]  step 20  check_findings → 看到 answer (标注 [答#2]) + next_cursor=3
────────────────────────────────────────────────────────────────────────
传播约束:
  · POSSIBLE 级别发现不传播 (visible=False)
  · 注入前 sanitize: 去 URL 参数/去 payload 细节/去 IP:端口/限 200 字符
  · 巡查 (coordinator) 产出的 FACT/LIKELY belief_state 自动 post (topic=coordinator)
  · 每 5 步 check 以 _bus_since (时间戳) 增量拉取, 不重复注入
```

### 3.13 关键设计决策记录（ADR 风格）

以下决策直接来源于代码注释中的复盘记录，理解它们有助于二次开发时**不重蹈覆辙**。

**ADR-1：verify_flag 的职责边界（swarm.py）**

- 问题：verify_flag 返回 False 会带偏 agent 并阻止兄弟 kill 触发（资源空转）。
- 决策：verify_flag 只做"平台/确证性校验"，**不是**防幻觉（防幻觉由 react.py 兜底：无工具调用直接 Final 被拒绝）。只有存在确凿反证才返回 False；无法判定时倾向 True。
- 来源：Crypto_Reverse 复盘。

**ADR-2：总线消息必须消毒（file_bus.py）**

- 问题：T4 测试发现命令级具体线索（完整 URL+payload）会诱导 agent 反复验证细节，浪费步数。
- 决策：`sanitize_content` 把命令级细节提炼为方向性线索（去 URL 查询参数 / 去 payload 细节 / 去 IP:端口 / 限 200 字符）；原始消息保留供调试，注入用消毒版。
- 来源：T4 传播策略优化。

**ADR-3：go-only 模式（llm/routed.py）**

- 问题：国内部署走代理导致 go 请求 45s+ 超时（#2664）；zen 免费层不稳定干扰调试。
- 决策：`LLM_PROVIDER=go` 只走 go 套餐、禁系统代理直连、go 失败直接抛错（不降级）；`DISABLE_ZEN=true` 默认关免费层。
- 来源：#2664 / #2669 复盘 + 9 组受控实验。

**ADR-4：go 端点思考归零（llm/routed.py）**

- 问题：deepseek-v4-flash 升级为 reasoning 模型后，go 端点 Agent 类请求思考链强制无界生成，非 none 的 effort 一律撞满 max_tokens（74-86s/次，content=0）。
- 决策：`llm_provider == "go"` 时 `reasoning_effort="none"`，思考归零、content 正常、每步 10-20s，推理由 ReAct Thought 承担。
- 来源：2026-08-03 根因修复（9 组受控实验定论）。

**ADR-5：MUST 持久注入（react.py + coordinator.py）**

- 问题：#2501 复盘——协调器 step10 下达 MUST（"停止单字符 MD5 爆破"），agent 忽略后继续穷举 20 步，MUST 只注入 1 次无强制力。
- 决策：MUST 指导连续重复注入 3 次（本步 + 后续 2 步）；与禁忌拦截配合闭环（`intercept_forbidden` 在巡查间隔之外也拦截确认无效的操作）；MUST 未执行检测（主导工具未变 + 无实质进展 → 升级阻断）。
- 来源：#2501 Blast 复盘。

**ADR-6：进展判定必须"不同 observation"（coordinator.py）**

- 问题：#2520 dantes innovative 死循环——旧逻辑只检查 observation 非空，agent 重复同一命令产生相同 obs 也被判为"有进展"，MUST 未执行检测失效，死循环 60+ 步。
- 决策：`_has_progress` / `_has_progress_after_guidance` 要求 ≥2 种**不同**的非空 observation；单一重复 observation = 死循环。
- 来源：#2520 / #2516 复盘。

**ADR-7：完全重复但持续有新发现 ≠ 死循环（coordinator.py）**

- 问题：#2516——agent 反复用同一 capstone 模板验证不同函数/假设（系统性验证性推进），被机械判定为死循环。
- 决策：完全重复但 `_has_progress` 为真时降级为软线索，交 L2 LLM 判断是否思路固化。
- 来源：#2516 复盘。

**ADR-8：异步巡查必须回主线程应用（react.py + coordinator.py）**

- 问题：后台线程直接改 `_coordinator_guidance` / `_must_repeat_left` 等状态会与主线程竞态。
- 决策：后台线程只做 analyze（结果存 `_pending_guidance`），副作用（指导注入/禁忌提醒/扩展步数/总线发布/日志）全部在 `_apply_coordinator_guidance` 于主线程执行；队列上限 1 防叠加；注入时声明来源步数防过时误导。
- 来源：Sprint 33 异步事件驱动设计。

**ADR-9：容器工具主名统一为 ssh_*（docker_tool.py）**

- 问题：docker_* 与 ssh_* 两套名字导致"经验跨场景不可用"（LLM 在纯 Docker 环境用经验中的 ssh_exec 会命中未知工具）。
- 决策：工具主名与 Kali 经验一致（ssh_exec/ssh_python/ssh_upload），docker_* 为别名；`_tool_map` 别名注册、主名优先。
- 来源：WING-Goose 执行层统一。

**ADR-10：步数软截断 + 进展感知时间熔断（react.py + breaker.py）**

- 问题：`for range(max_steps)` 一次性求值导致 extend_steps 永不生效；时间熔断"一刀切"误杀方向正确、刚发现关键线索的 agent（#2501 第 47 步案例）。
- 决策：while True + 每步动态判断 max_steps（extend 立即生效），超限且有进展继续（时间熔断兜底）；时间熔断尊重调用方传入值、只做下限兜底、有实质进展进入 progress_grace。
- 来源：Sprint 32.4b / #2501 复盘。

**ADR-11：docker 快路径 vs B+ 后台并存（docker_tool.py）**

- 问题：每条命令都走 B+ 后台轮询（nohup + sleep 1），命令瞬间结束也要等第一次 sleep 1，p50 = 1.14s；docker exec CLI 全链路仅约 144ms。
- 决策：默认/quick/短等待（≤15s）直连 exec 同步执行；normal/long/background 保留 B+ 后台（软超时转后台 + PID 追踪）；`FAST_PATH_ENABLED` 总开关可还原。
- 来源：S1 快路径（基线 checkpoint_0_baseline.txt）。

**ADR-12：协作义务注入（react.py + coordinator.py）**

- 问题：Crypto_Reverse 复盘——本次运行 40 条 bus 全为巡查发布，agent 从未主动分享/提问，根因是 prompt 无协作引导，而非工具缺失。
- 决策：总线启用时注入 `_COOP_GUIDANCE`（告知存在并行兄弟 + 主动使用两个工具）；每 5 步注入协作义务提示；巡查干预时也提醒发布关键线索。
- 来源：Sprint 36 协作升级点 1（雁阵 v2）。

**ADR-13：swarm 默认全难度并行（config.py）**

- 问题：NSSCTF 难度评判不标准（easy 实为 middle/hard 常见，如 [De1ctf 2019]babyrsa），easy 单路会错过并行收益。
- 决策：`SWARM_ENABLED=true` 默认所有难度（含 easy）都走 3 风格并行；false 回退 T3 结论。
- 来源：T3 结论 + 2026-08 实测。

**ADR-14：Kali 路由默认关闭（config.py）**

- 问题：执行层双通道（Docker + Kali）导致不确定性与运维负担；Kali 不可达时连接挂起浪费整题时间。
- 决策：`KALI_ENABLED=false` 默认关闭 Kali 路由，执行层只用 Docker；关闭时领题前检查 Docker 容器可用性，不可用直接报错退出（不向下路由 Kali）；engine 构造 150s 线程超时兜底 SSH 挂起。
- 来源：WING-Goose 2026-08 执行层决策。

---

## 4. 数据设计

### 4.1 task JSON 协议（solve.py 输入）

```json
{
  "challenge_id": "nss_2314",
  "title": "题目名",
  "desc": "任务描述 (题面+附件路径+靶机URL+规则)",
  "type": "web",
  "difficulty": "easy",
  "max_steps": 0,
  "max_seconds": 1500.0,
  "retry_hint": "",
  "force_max_thinking": false,
  "max_submissions": 1,
  "style": "conservative",
  "bus_challenge_id": "nss_2314",
  "bus_dir": "/path/to/data/bus",
  "annex_dir": "/path/to/annex",
  "reset_container": false
}
```

WING-Goose 新增字段说明：

| 字段 | 含义 |
|------|------|
| style | 解题风格（conservative/aggressive/innovative），swarm 每路注入；空=默认保守 |
| bus_challenge_id | 总线统一键（swarm 会给每路改 challenge_id，用 bus_challenge_id 保证同题 agent 共享同一总线文件与共享目录） |
| bus_dir | FileBus 目录（跨进程共享时必填） |
| annex_dir | 附件宿主目录（挂载到容器 /challenge/workspace） |
| reset_container | 同题重做强制 rm+run 全新环境（默认复用现场） |

### 4.2 JSONL 输出协议（协议版本 1.1）

stdout 每行一个 JSON 对象：

| type | 说明 |
|------|------|
| start | `protocol_version / challenge_id / title / challenge_type / difficulty / max_steps / max_seconds / max_submissions / model` |
| log | `level / message`（第三方 print() 被 `_ProtocolStdout` 包装为 RAW log，保证协议不被污染） |
| step | `step_no / thought / action / action_input / observation / is_error / is_final / final_answer / error_msg / timestamp` |
| heartbeat | `elapsed / step / phase`（每 15s，让调用器区分"卡住"与"正在思考"） |
| submission | `flag`（agent → 调用器提交请求） |
| coordinator | 巡查日志（step_no / should_intervene / priority / guidance / forbidden_actions / belief_state 等） |
| result | `success / flag / final_answer / fail_reason / steps / elapsed / tokens / model` |

stdin 输入（调用器 → agent）：`{"correct":bool,"feedback":str}`（submission 响应）/ `{"control":"stop"}`（停止信号）。stdin 由**统一分发器**单线程读取后按消息类型分发（Sprint 30 修复 stop-listener 与 submission-handler 竞争 stdin 的问题，同时解决 Windows selectors 不能注册 stdin 的 WinError 10038）。

### 4.3 总线文件格式

FileBus 每条消息（JSONL 一行，`data/bus/{safe_challenge_id}.jsonl`）：

```json
{"seq": 7, "ts": 1754300000.0, "agent": "aggressive", "task_id": "nss_2314",
 "content": "RSA e=65537 n=2048bit 且 p/q 接近, 适合费马分解", "kind": "finding",
 "reply_to": 0, "level": "FACT", "topic": "finding"}
```

- `level`：FACT/LIKELY/POSSIBLE（visible 只放行前两级）；
- `content` 上限 500 字符（post 截断），注入前再经 `sanitize_content` 消毒（≤200 字符）；
- seq 全局自增（扫描现有行取最大 id + 1），供 `check_findings` 游标使用。

### 4.4 持久化存储

| 存储 | 路径（默认） | 内容 |
|------|-------------|------|
| SQLite | data/ctf.db | 中期记忆 facts |
| ChromaDB | data/chroma | 长期记忆 writeup 向量库 |
| md 技能库 | data/skills/（index.json） | 结构化解题套路 |
| 经验库 | skills 包内 skill_library.json | 抽象解题方法 + 禁忌 |
| 总线文件 | data/bus/*.jsonl | 跨进程共享发现 |
| swarm 临时任务 | data/swarm_tasks/*.json | 各路 task JSON |
| 共享文件 | data/agent_share/{challenge_id}/ | 同题文件互通（容器挂载 /shared） |
| 冒烟标记 | data/api_smoke.json | provider 可用性探测结果 |

### 4.5 配置数据模型（config.py 全字段）

`Settings` 基于 pydantic-settings，字段别名与 .env 键一一对应，全部带默认值（缺失不崩溃）。分组如下：

**LLM 配置**

| 字段 | 别名 | 默认 | 说明 |
|------|------|------|------|
| openai_api_key | OPENAI_API_KEY | "" | 基础 key（has_llm_config 判定用） |
| openai_base_url | OPENAI_BASE_URL | api.openai.com/v1 | 基础端点 |
| planner_model / executor_model | PLANNER_MODEL / EXECUTOR_MODEL | gpt-4o / deepseek-chat | 规划/执行模型 |

**模型路由（Sprint 17 / 33 + WING-Goose）**

| 字段 | 别名 | 默认 | 说明 |
|------|------|------|------|
| llm_provider | LLM_PROVIDER | "go" | "go"=只走 go 套餐（国内部署直连，冲榜稳定）；"auto"=zen→go→官方→pro 降级 |
| disable_zen | DISABLE_ZEN | true | 关闭 zen 免费层 → 直接路由至 go |
| zen_api_key/base_url/model | ZEN_* | opencode.ai/zen/v1 / deepseek-v4-flash-free | 免费层 |
| go_api_key/base_url/model | GO_* | opencode.ai/zen/go/v1 / deepseek-v4-flash | 付费层（无峰谷） |
| fallback_api_key/base_url/model | FALLBACK_* | api.deepseek.com/v1 / deepseek-v4-flash | 官方兜底 |
| llm_max_retries | LLM_MAX_RETRIES | 2 | 每 provider 重试次数 |
| pro_* | PRO_* | — | Sprint 26 deprecated，仅 ENABLE_PRO_FALLBACK=true 生效 |

**思考模式（Sprint 26）**

| 字段 | 默认 | 说明 |
|------|------|------|
| ENABLE_THINKING_MODE | true | 启用思考模式 |
| THINKING_EFFORT_EASY/MEDIUM | high/high | 轻量难度 |
| THINKING_EFFORT_HARD/EXTREME | max/max | 深度推理 |
| THINKING_EFFORT_DEFAULT | high | 未知难度 |

**Kali SSH（WING-Goose 路由开关）**

| 字段 | 默认 | 说明 |
|------|------|------|
| KALI_ENABLED | false | **WING-Goose：默认关闭 Kali 路由，执行层只用 Docker**；关闭时领题前检查 Docker 容器可用性，不可用直接报错退出（不向下路由 Kali） |
| KALI_HOST/PORT/USER/PASS/KEY_PATH | — | SSH 连接参数 |

**Docker 工具链（WING-Goose Item 5）**

| 字段 | 默认 | 说明 |
|------|------|------|
| DOCKER_ENABLED | true | Docker 执行层总开关 |
| DOCKER_IMAGE | wing-goose:v2 | 默认镜像（补装 fpylll/angr/torch 等 6 库 + 预封装入口；v1 以 latest 保留作回滚点） |
| DOCKER_BACKEND | sdk | cli（subprocess）/ sdk（docker-py） |
| DOCKER_CONTAINER | wing-goose-worker | 容器名（非默认值时尊重单容器模式） |
| DOCKER_WORKDIR | /challenge | 容器工作目录 |
| DOCKER_BUILD_ON_MISSING | false | 镜像缺失时自动构建 |
| DOCKER_DOCKERFILE | scripts/docker_test/Dockerfile.wing-goose | Dockerfile 路径 |
| DOCKER_CPU_PROFILE | normal | light/normal/brute/heavy 配额 Profile |
| DOCKER_CPU_CORES / DOCKER_MEM_LIMIT | 0 / "" | 显式覆盖（>0 / 非空优先） |
| DOCKER_MAX_CONTAINERS | 0 | 0=按 §13.3 自动计算 |
| DOCKER_RESERVE_CPU / DOCKER_RESERVE_RAM | 0.25 / 0.25 | 宿主预留因子 |

**多解题器（WING-Goose swarm）**

| 字段 | 默认 | 说明 |
|------|------|------|
| SWARM_ENABLED | true | 默认开启多解题器：所有难度（含 easy）都走 3 风格并行；false → 回退 T3 结论（仅 medium/hard 并行，easy 单路） |

**巡查指导器（Sprint 33 异步事件驱动）**

| 字段 | 默认 | 说明 |
|------|------|------|
| COORDINATOR_PATROL_GAP | 5 | 上一次注入结果之后 N 步再次发起（范围 5~10；=5 时按风格节奏，否则全局覆盖） |

**熔断阈值**：MAX_STEPS=80（动态由 AdaptiveBreaker 调整）/ MAX_TASK_TIME=1800 / MAX_COST_LIMIT=1.5。

**数据库/日志**：SQLITE_PATH=./data/ctf.db / CHROMA_PATH=./data/chroma / LOG_LEVEL=INFO。

---

## 5. 版本演进：相对 WING-Falcon 的更新

> 本章基于对 WING-Goose 源码的完整审计，逐项列出相对 WING-Falcon（单 agent 基线）的新增能力与细节优化，并说明每项的价值。

### 5.1 新增文件总览

| 文件 | 类型 | 一句话说明 |
|------|------|-----------|
| `agent/styles.py` | 新增 | 三风格提示词常量（与巡查风格词表同源） |
| `bus/message_bus.py` | 新增 | 进程内 append-only 消息总线（cursor 游标） |
| `bus/file_bus.py` | 新增 | 跨进程文件总线（JSONL + 分级过滤 + 内容消毒） |
| `events.py` | 新增 | In-process 事件总线（渐进式事件化第一步） |
| `review.py` | 新增 | 独立 LLM 轨迹复盘 + 无幻觉核对 + skill 入库 |
| `swarm.py` | 新增 | 同题多风格并行编排（难度→并发策略，一解出即杀其余） |
| `tools/bus_tool.py` | 新增 | share_finding / check_findings 总线工具 |
| `tools/docker_tool.py` | 新增 | docker→ssh 降级执行链（容器常驻 + 资源调控 + 双后端） |
| `tools/shared_fs_tool.py` | 新增 | 同题共享文件工具（list/read/write + 路径安全） |

### 5.2 新增能力一：swarm 同题多风格并行（swarm.py）

- **能力**：`SwarmCoordinator` 起 N 个子进程并行求解同一道题，每路注入 style；任一子进程提交正确 flag 即 kill 其余；超时兜底 kill 全部存活进程。
- **价值**：用风格多样性对冲单一路线思维盲区，提升单题命中率与整体墙钟效率；"一解出即杀其余"避免资源空转。
- **细节**：难度→并发策略（easy 单路 / medium、hard 三路）；`verify_flag` 回调设计约定（防幻觉由 react.py 内部兜底，verify_flag 只做平台确证校验，倾向接受）；on_proc 注册子进程句柄；SwarmResult 含 winner_style/killed_count 统计。

### 5.3 新增能力二：消息总线（bus/）

- **进程内 MessageBus**：线程安全、append-only、cursor 游标、task_id 过滤、超量裁剪。价值：多 agent 同进程共享发现的语义基础。
- **跨进程 FileBus**：每个 challenge 一个 JSONL 文件原子 append；**分级过滤**（只传播 FACT/LIKELY 防误导）+ **内容消毒**（命令级细节提炼为方向性线索：去 URL 参数/去 payload 细节/去 IP:端口/限 200 字符，防止 agent 反复验证细节）；`post_finding/check_findings` 兼容接口使总线工具跨进程复用。
- **价值**：兄弟发现共享从"提示词建议"变成"引擎强制执行"，且跨进程可见（swarm 多进程场景）。
- **细节**：`get_default_bus()` 单例；bus 异常不影响主流程（try/except 包裹）。

### 5.4 新增能力三：事件总线（events.py）

- **能力**：极简 in-process EventBus（subscribe/emit/unsubscribe/clear），线程安全，异常不传播。
- **价值**：渐进式事件化的第一步，为后续架构（Corvus）的异步事件驱动铺路；ReActEngine 已实际 emit engine.started/engine.finished/step.completed。

### 5.5 新增能力四：独立 LLM 轨迹复盘（review.py）

- **能力**：`TrajectoryReviewer` 用独立上下文 LLM 只读轨迹文本，提取 facts（标注来源）/lessons/skills；`check_no_hallucination` 逐条核对 facts 实体是否在轨迹中出现；`ingest_skills` 入库 md 技能库。
- **价值**：复盘结果不依赖解题过程内部状态，避免"自我辩解"偏差；无幻觉核对保证入库技能可溯源；与模板 Skill 学习器（_learn）互补形成双通道沉淀。
- **细节**：4 级 fallback JSON 解析；solve.py 仅在 step_count ≥8 且轨迹 ≥200 字符时运行；no_hallucination=False 时 WARN 并跳过入库。

### 5.6 新增能力五：三风格解题（agent/styles.py）

- **能力**：conservative（侦察先行/小步验证）/ aggressive（快速试错/多路径并行）/ innovative（非常规思路 + 创造性工具箱 5 模板）。
- **价值**：风格差异是 swarm 并行的前提；创新风格专门针对 T2-REV 复盘发现的"创造性不足"增强。
- **细节**：风格词表与巡查风格段落同源（避免 agent 与巡查理解不一致）；solve.py 按 task.style 注入 STYLE_GUIDANCE + _COOP_GUIDANCE 协作引导。

### 5.7 新增能力六：Docker 执行链（tools/docker_tool.py）

- **能力**：常驻 Linux 容器替代 SSH 执行层，`docker exec` 往返延迟极低；降级链 docker → ssh → MCP 层层兜底；工具主名统一为 ssh_*（docker_* 别名），经验跨场景可用。
- **价值**：执行层确定性 + 低延迟 + 可复现；纯 Docker 环境下专用题型工具仍可用（修复 S14 bug）。
- **细节**（审计发现的丰富细节）：
  - S1 快路径（消灭固定 sleep 1，p50 1.14s → 144ms）；
  - S2 容器消失自愈（本调用内重试，<10s 门禁）；
  - S3 资源 Profile（light/normal/brute/heavy）+ 统一安全参数（memory-swap 同值禁 swap 逃逸、pids-limit 512 防 fork bomb、SYS_PTRACE + seccomp=unconfined 调试必需）；
  - S4 多容器（容器名参数化 + task label）+ S5 跨题重置（异题 rm+run）+ 附件挂载校验（缺挂载重建）；
  - S8/S9 后端抽象（CliBackend/SdkBackend），S10 docker-py 缺失降级 cli；
  - SDK exec 底层 API + 线程超时（与 CLI timeout 语义一致）；exec_create 补 sh -lc 包装；upload/download tar 流；
  - `_parse_volume_spec` 修复 Windows 盘符挂载错位 bug。

### 5.8 新增能力七：共享文件系统（tools/shared_fs_tool.py）

- **能力**：list/read/write 三个工具经宿主共享目录互通文件；容器内 /shared 挂载形成双通道。
- **价值**：结构化产物（脚本/提取结果/中间文件）的共享比文本总线更完整。
- **细节**：文件名白名单（防路径穿越）、64KB 读取上限、UTF-8 校验、零侵入注册。

### 5.9 增强一：ReAct 引擎总线协作与事件驱动（agent/react.py）

- 每 5 步 `check_sanitized` 注入兄弟发现（T4 消毒版）；
- 每 5 步**协作义务**提示（强制分享关键发现）——解决复盘发现的"agent 从未主动分享"根因；
- 每 5 步**强制回答**兄弟提问（[MUST]，防提问方卡死）；
- 巡查 FACT/LIKELY 事实 `_post_to_bus` 发布（双向通信）；
- **异步巡查**：`fire_async_analysis` 后台分析不阻塞行动，`consume_pending_guidance` 事件召回后续步注入，注入时声明来源步数（防过时误导）；
- while True + 进展感知软截断（extend_steps 立即生效）；
- LLM 调用三级容错（重试→重试→pro→跳过）；
- 工具别名注册（docker 工具主名 ssh_*）。

### 5.10 增强二：巡查指导器风格化与自我纠错（agent/coordinator.py）

- 风格参数表 STYLE_PARAMS（温度/错误容忍/节奏）与风格化 prompt 段落（保守稳健/激进快节奏/创新双轨灵感板）；
- 创新模式灵感板 creative_hints（无论是否干预必产 2-3 条）+ 非创新模式 strategic_direction（仅干预时注入，沉默原则）；
- 异步事件驱动（队列上限 1 防叠加，副作用回主线程）；
- **禁忌列表 forbidden_actions + 精确签名禁忌 forbidden_signatures**（死循环自动标记，精确匹配避免关键词误伤）；
- **全局已尝试方向追踪 _tried_directions**（跨 lookback 窗口死循环检测，≥6 次且无进展强制切换）；
- 推论分级 belief_state（FACT/LIKELY/POSSIBLE/DISPROVED 跨巡查持久化，DISPROVED 自动清理禁忌）；
- MUST 未执行检测（主导工具未变 + 无实质进展 → 阻断；空 action 格式崩溃也计入）；
- 自我纠错 revert_guidance / remove_forbidden（上次判断被轨迹证伪即撤销）；
- 进展判定精确化：≥2 种不同 observation 才算实质进展（修复 #2520/#2516 误判案例）；
- 巡查间隔钳制 5~10 步。

### 5.11 增强三：配置系统新字段（config.py）

代码审计确认的新增字段（详见 4.5 节配置表）：

- `llm_provider`（go/auto）+ go 套餐三件套（GO_API_KEY/BASE_URL/MODEL）；
- `kali_enabled`（默认 false，关闭 Kali 路由，执行层只用 Docker；关闭时领题前检查 Docker 容器可用性，不可用直接报错退出）；
- Docker 工具链全套（image/backend/container/workdir/build_on_missing/dockerfile + 资源调控 cpu_profile/cpu_cores/mem_limit/max_containers/reserve_cpu/reserve_ram）；
- `swarm_enabled`（默认 true，所有难度走 3 风格并行）；
- `coordinator_patrol_gap`（巡查发起节奏，默认 5，范围 5~10，=5 时按风格节奏）。

### 5.12 增强四：solve.py / client.py

- solve.py：style 注入与协作引导（_COOP_GUIDANCE）、FileBus 优先 + bus_challenge_id 统一键、DockerClient 构造（S4 多容器/S5 附件挂载/S13 共享目录）、smoke_test 应用、`_review()` 轨迹复盘封装、Kali 路由开关、engine 构造 150s 线程超时兜底；
- client.py：`AgentCallbacks.on_proc`（swarm 杀兄弟用）、coordinator JSONL 消息转发（COORD 日志）、`AgentClient.solve` 双向通信（submission 响应经 stdin）。

### 5.13 代码审计发现的小优化清单

除上述主线外，审计发现以下值得记录的细节优化：

1. **工具主名统一**：docker 工具主名与 Kali 经验一致（ssh_exec 等），docker_* 为别名——LLM 用经验中的旧名也能命中，经验跨场景复用（react.py `_tool_map` 别名注册、主名优先）。
2. **纯 Docker 无执行层修复**：exec_tools 独立于 ssh 分支注册（S14），关闭 Kali 后 docker 工具不再丢失。
3. **`_parse_volume_spec` Windows 盘符修复**：`C:/host:/ctr` 不再被拆成命名卷 "C"，附件挂载不再错位。
4. **SDK 后端命令语义保真**：exec_create 显式补 `sh -lc` 包装（否则管道/重定向/; 全部失效）；get_archive/put_archive 用 tar 流；容器内路径不经 pathlib（Windows 分隔符问题）。
5. **快路径 + 后台路径并存**：默认/quick/短等待直连 exec，normal/long/background 保留 B+ 后台（PID 追踪 + 日志轮询），`FAST_PATH_ENABLED` 可整体回退。
6. **`_use_fast_path` 判定**：timeout=None（默认调用多为快速命令）直接快路径——p50 收益最大来源。
7. **exec_cmd 前幂等创建 cwd 目录**：专用工具默认 cwd（如 /tmp/ctf_workspace/）容器内不存在 → 先 `mkdir -p`（失败不阻断主命令）。
8. **容器消失自愈（S2+S6）**：`_container_ok` 缓存 + exec 错误模式检测 + 本调用内重试，保证"下一次 exec 即恢复"成立。
9. **孤儿容器清理**：仅清理 label=ctf-agent=true 且已停止的容器，不误删并行 agent 正在使用的容器。
10. **verify_flag 异常不冒泡**：回调抛异常记录并返回 False，agent 收到明确反馈继续分析，兄弟 kill 机制不被异常破坏。
11. **总线零侵入**：default_tools 未传 message_bus / shared_fs_dir 时不注册对应工具（回滚语义）。
12. **总线异常兜底**：react.py 中所有总线操作 try/except 包裹，总线故障不影响主流程。
13. **smoke_test 冒烟 + 动态健康叠加**：领题前快速探测 + 中途故障实时降级 + 恢复后自动重试，避免"冒烟通过 → 中途挂起 → 每次死等 30s×3"卡死。
14. **go-only 模式思考归零**：reasoning_effort="none"（go 端点 Agent 类请求强制无界思考链的 9 组受控实验结论），推理由 ReAct Thought 承担，每步 10-20s。
15. **wall-clock 总超时**：daemon 线程 + join(timeout) 覆盖 slow-drip 半死连接（httpx read timeout 防不了）。
16. **协作义务注入**（Sprint 36）：巡查干预与每 5 步注入都提醒 agent 发布关键线索到总线——"战术层专注解题，关键事实必须回流共享池"。
17. **进度判定阈值**：`_has_progress` / `_has_progress_after_guidance` 要求 ≥2 种**不同** observation（单一重复 observation 不算进展）——修复"重复命令产生相同 obs 被判为有进展"的死循环漏检。
18. **step 时间戳**：ReActStep.timestamp 用 time.monotonic，供时间线计算。
19. **多级 JSON 解析**：复盘与巡查 LLM 输出都做多级 fallback 解析，容错不崩溃。
20. **巡查摘要压缩**：`_summarize_trajectory`（前 3 步完整 + 中间压缩 + 最近 5 步完整）防 token 爆炸。

### 5.14 能力对比矩阵：WING-Falcon vs WING-Goose

| 能力域 | WING-Falcon（猎隼） | WING-Goose（雁阵） | 升级价值 |
|--------|--------------------|--------------------|---------|
| 求解组织 | 单 agent 单路线 | 同题 3 风格并行（swarm） | 风格对冲思维盲区，命中率↑ 墙钟↓ |
| 进程模型 | 单子进程 | N 子进程 + 提交协调 | 一解出即杀，资源不空转 |
| 兄弟协作 | 无 | 消息总线（跨进程）+ 共享文件 + 强制回答 | 避免重复劳动、互相补盲 |
| 执行层 | Kali SSH | Docker 容器（默认）+ SSH 降级 | 低延迟（144ms vs 1.14s p50）、可复现 |
| 镜像 | — | wing-goose:v2（6 库 + 预封装入口） | 开箱即用的 CTF 工具环境 |
| 巡查指导器 | 同步分析 | 异步事件驱动（fire/consume） | 分析不阻塞行动，注入标注来源步 |
| 巡查干预 | 单一 SHOULD | MUST/SHOULD + 禁忌列表 + 精确签名 + MUST 未执行检测 | 强制力闭环，杜绝"指令被忽略" |
| 巡查记忆 | 无 | belief_state 推论分级跨巡查持久化 | FACT/LIKELY 决策依据可追溯 |
| 死循环检测 | 窗口内重复检测 | 全局已尝试方向追踪（跨窗口） | 捕获 step50 用过 step80 又试的隐蔽循环 |
| 解题风格 | 无 | conservative/aggressive/innovative | 差异化并行 + 创新灵感板 |
| 轨迹复盘 | Skill 学习器（模板） | 独立 LLM 复盘 + 无幻觉核对 + 入库 | 高质量可溯源技能沉淀 |
| LLM 路由 | zen→官方 | LLM_PROVIDER=go（直连禁代理）+ 动态健康 + wall-clock | 国内部署稳定，中途故障实时降级 |
| 事件化 | 无 | EventBus（engine/step 事件） | 为 Corvus 异步架构铺路 |
| 配置开关 | — | KALI_ENABLED=false、SWARM_ENABLED=true、DOCKER_* 全套 | 按部署形态一键切换 |

---

## 6. 部署与运维

### 6.1 环境准备

**运行环境要求**：

| 组件 | 要求 | 说明 |
|------|------|------|
| Python | >= 3.10 | 建议 3.11+（性能与 typing 支持） |
| Docker Desktop | 任意近期版本 | Windows 宿主默认执行环境（Linux 容器模式） |
| LLM API | go 套餐或官方 deepseek key | 见 .env 配置 |
| Kali VM（可选） | — | `KALI_ENABLED=true` 时才需要，默认关闭 |

**安装**：

```powershell
# 1. 克隆代码后进入 WING-Goose 目录
cd _publish/wing/WING-Goose

# 2. 创建虚拟环境并安装依赖
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .            # 基础依赖 (openai/httpx/pydantic/rich...)
pip install -e ".[docker]"  # 如需 DOCKER_BACKEND=sdk (docker-py)

# 3. 准备 .env（从模板复制并填写）
copy .env.example .env
```

**验证安装**：

```powershell
python main.py --version
python -c "from ctf_agent.config import get_settings; s = get_settings(); print(s.executor_model, s.swarm_enabled)"
```

### 6.2 Docker 镜像构建

默认镜像 `wing-goose:v2`（补装 fpylll/angr/torch 等 6 库 + 预封装入口；v1 以 latest 标签保留作为回滚点）。Dockerfile 路径默认 `scripts/docker_test/Dockerfile.wing-goose`（配置项 `DOCKER_DOCKERFILE`）。

```powershell
# 手动构建
docker build -f scripts/docker_test/Dockerfile.wing-goose -t wing-goose:v2 .

# 或设置 DOCKER_BUILD_ON_MISSING=true，容器不存在时自动构建
```

容器内预装内容（来自 DockerExecTool/PythonTool 工具描述与代码注释）：
- 网络：nmap / sqlmap / gobuster / tshark 等；
- 逆向：objdump / readelf / gdb / radare2 / ghidra / angr / capstone；
- 取证/隐写：file / xxd / strings / binwalk / steghide / exiftool / tesseract；
- 密码学：pycryptodome / sage / fpylll / z3；
- Pwn：pwntools；
- 通用：python3 / pip3（已预配清华镜像源，`cat /tools.txt` 可查看完整清单）。

### 6.3 目录与数据初始化

首次运行自动创建（代码中 `mkdir(parents=True, exist_ok=True)`）：

```
data/
├── chroma/          # 长期记忆向量库
├── skills/          # md 技能库 (index.json)
├── swarm_tasks/     # swarm 临时 task JSON
├── agent_share/     # 同题共享文件目录
└── bus/             # 跨进程总线 JSONL（solve.py 按 bus_dir 创建）
```

### 6.4 运行形态

| 形态 | 入口 | 场景 |
|------|------|------|
| 单 agent CLI | `python main.py run --target ... --desc ...` | 单题调试/人工分析 |
| WebUI | `python main.py web --host 127.0.0.1 --port 8000` | 可视化调试 |
| 子进程协议 | `python -u -m ctf_agent.solve --task-file task.json` | 批量自动化（NSS Runner） |
| swarm 编队 | 编程调用 `SwarmCoordinator.run()` | 同题多风格并行（NSS 冲榜主用） |

### 6.5 监控与日志

- **进程输出**：solve.py 以 JSONL 协议输出 start/log/step/heartbeat/submission/coordinator/result，调用器（AgentClient）按 type 分发回调；
- **心跳**：每 15s 输出 `{"type":"heartbeat","elapsed":N,"step":N,"phase":"..."}`，让调用器区分"卡住"与"正在思考"；
- **巡查日志**：`{"type":"coordinator",...}` 行含 should_intervene/priority/guidance/forbidden_actions/reflection/belief_state，可离线分析巡查质量；
- **总线统计**：ReActEngine 维护 `_bus_injected_count` / `_bus_posted_count`（采纳率/双向性分析）；
- **熔断状态**：`TaskStatus` 记录执行/完成/失败状态与步数。

### 6.6 资源管理

- **容器配额**：按难度/题型选 Profile（light/normal/brute/heavy），或 DOCKER_CPU_CORES / DOCKER_MEM_LIMIT 显式覆盖；
- **并发度**：`DOCKER_MAX_CONTAINERS=0` 时按宿主资源自动计算（`compute_max_containers`，预留因子 0.25）；`ContainerScheduler` 信号量控制运行中容器数；
- **孤儿清理**：agent 启动时 `cleanup_orphans()` 清理 label=ctf-agent=true 且已停止的容器（不误删并行 agent 在用的容器）；
- **清理命令**：

```powershell
# 手动清理停止的 ctf-agent 容器
docker ps -a --filter "label=ctf-agent=true" --filter "status=exited" -q | ForEach-Object { docker rm -f $_ }
# 清理总线与共享目录（重置协作状态）
Remove-Item data/bus/*.jsonl, data/agent_share/* -Recurse -Force -ErrorAction SilentlyContinue
```

### 6.7 升级与回滚

- 本快照（2026-08-04）是 Corvus 升级前的生产基线；升级到 Corvus 前应保留本目录备份；
- 镜像回滚：`DOCKER_IMAGE=wing-goose:latest`（v1 以 latest 标签保留）；
- 后端回滚：`DOCKER_BACKEND=cli` 一键回退 subprocess 后端；
- 行为回退开关：`FAST_PATH_ENABLED`（docker 快路径）、`ENABLE_TASK_RESET`（跨题重置）、`SWARM_ENABLED=false`（回退单 agent）、`LLM_PROVIDER=auto`（回退三级降级）。

---

## 7. 安全与伦理

### 7.1 目标授权与合法使用

WING-Goose 是**竞赛场景**的自动化解题系统，仅可用于：

- 已授权的 CTF 竞赛平台（如 NSSCTF）；
- 自己搭建的靶场与本地环境；
- 明确授权的渗透测试目标。

严禁用于未授权系统、真实生产环境的攻击。使用者须遵守所在司法管辖区的法律法规与比赛规则。

### 7.2 沙箱隔离（容器安全）

- 容器统一施加：`--memory-swap` 同值（禁 swap 逃逸拖垮宿主）、`--pids-limit 512`（防 fork bomb）、`--cap-add SYS_PTRACE` + `--security-opt seccomp=unconfined`（CTF 调试必需的权衡，仅在受控容器内生效）；
- 附件目录与共享目录以只读/绑定挂载方式进入容器，rm 容器不影响宿主文件；
- 容器以 label（ctf-agent=true + task=...）标记，便于审计与清理；
- Docker daemon 不可用时**降级到 SSH**（不静默失败）；两者都不可用时专用工具不注册，内置纯 Python 工具仍可用。

### 7.3 工具层安全

- **共享文件路径安全**：`_safe_name` 只允许简单文件名（禁止绝对路径、`/`、`\`、`..`），防路径穿越越权读写宿主其他目录；
- **读取上限**：read_shared_file 限 64KB，防误读大二进制拖垮上下文；
- **总线内容消毒**：跨进程传播前移除 URL 查询参数 / payload 细节 / IP:端口，只传播方向性线索，降低"共享污染"；
- **flag 脱敏**：经验沉淀（experience.py ingest_solution）对 flag / 绝对路径 / 内存地址统一脱敏，避免知识库污染。

### 7.4 反幻觉机制

- **强制工具调用**：无任何工具调用直接 Final Answer 一律拒绝（所有题型强制 ≥1 次工具调用），杜绝凭记忆猜 flag；
- **交叉验证**：max 思考强度下 Final Answer 前必须用工具交叉验证（crypto 验明文可读、reverse 过 check_flag、web 验响应中 flag）；
- **提交去重**：已驳回答案不能重复提交，错误提交不浪费有限次数；
- **复盘无幻觉核对**：轨迹复盘 facts 的实体必须出现在轨迹文本中才允许入库；
- **Flag 提取**：仅从最终答案提取匹配 flag 格式（NSSCTF{}/flag{}/athena{} 等）的内容。

### 7.5 数据脱敏

- 经验/技能入库前去除具体 flag 与敏感路径；
- 总线注入内容经 sanitize（去 IP:端口 → `<target>`）；
- 日志输出 observation 截断（ssh_tool `_MAX_OUTPUT=8000`，共享文件 64KB 上限），控制上下文膨胀与敏感信息外泄面。

### 7.6 竞赛合规

- NSS 等竞赛场景**禁用本地靶场控制**（`enable_range=False`）：任务描述已禁止的操作在工具层面直接不提供，杜绝 agent 误用本地靶场；
- `verify_flag` 由平台确证校验（真实提交），agent 侧不自行判定"赢"；
- 多次提交受 `max_submissions` 限制，尊重平台提交频率约定。

### 7.7 伦理边界

- 系统设计的目的是**学习与竞赛**：让 AI 学会"如何发现漏洞、如何构造攻击"，而不是提供"一键打穿"的黑客工具；
- 所有攻击能力（注入/利用/爆破）均限定在受控沙箱与授权目标内；
- 复盘的 lessons（哪些操作无效）只沉淀到本地知识库，不对外传播目标细节。

---

## 8. 使用方法

### 8.1 快速开始

**场景 A：单题调试（CLI）**

```powershell
python main.py run --target http://ctf.example/ --desc "PicoCTF GET aHEAD" --show-steps
```

**场景 B：带报告输出**

```powershell
python main.py run --target http://ctf.example/ --file ./annex/chal.elf --type reverse --difficulty medium --report ./reports/r1.md
```

**场景 C：swarm 并行（NSS Runner 集成方式）**

```powershell
# 直接编程调用 SwarmCoordinator（示例见 8.4）
python -c "from ctf_agent.swarm import SwarmCoordinator; ..."
```

### 8.2 .env 配置说明（逐字段）

完整模板见 `.env.example`，逐组说明如下：

**LLM 基础**

| 键 | 说明 |
|----|------|
| OPENAI_API_KEY | 基础 API Key（`has_llm_config` 判定；未配置时 CLI/WebUI 拒绝启动任务） |
| OPENAI_BASE_URL | 基础端点（默认官方） |
| PLANNER_MODEL / EXECUTOR_MODEL | 规划/执行模型名 |

**模型路由（Sprint 33）**

| 键 | 说明 |
|----|------|
| LLM_PROVIDER | `go`（默认，只走 go 套餐，国内部署直连冲榜稳定）/ `auto`（zen→go→官方三级降级，调试期保留） |
| ZEN_API_KEY / ZEN_BASE_URL / ZEN_MODEL | zen 免费层（deepseek-v4-flash-free）；DISABLE_ZEN=true 时不用填 |
| DISABLE_ZEN | true=关闭 zen 免费层，直接路由至 go（默认开启，避免免费层不稳定干扰） |
| GO_API_KEY / GO_BASE_URL / GO_MODEL | Opencode go 付费层（deepseek-v4-flash，定价与官方一致、无峰谷） |
| FALLBACK_API_KEY / FALLBACK_BASE_URL / FALLBACK_MODEL | 官方 deepseek flash 兜底 |
| LLM_MAX_RETRIES | 每 provider 重试次数（默认 2） |

**思考模式（Sprint 26）**

| 键 | 说明 |
|----|------|
| ENABLE_THINKING_MODE | true=启用（go 模式实际固定 reasoning_effort="none"，推理由 ReAct Thought 承担） |
| THINKING_EFFORT_EASY/MEDIUM | high/high |
| THINKING_EFFORT_HARD/EXTREME | max/max |
| THINKING_EFFORT_DEFAULT | high |

**Kali SSH（WING-Goose 默认关闭）**

| 键 | 说明 |
|----|------|
| KALI_ENABLED | false=关闭 Kali 路由，执行层只用 Docker（默认）；true=启用 SSH 执行层 |
| KALI_HOST / KALI_PORT / KALI_USER | SSH 连接参数 |
| KALI_PASS / KALI_KEY_PATH | 密码或 Key 路径（Key 优先） |

**Docker 工具链**

| 键 | 说明 |
|----|------|
| DOCKER_ENABLED | true=启用 Docker 执行层 |
| DOCKER_IMAGE | wing-goose:v2（默认） |
| DOCKER_BACKEND | sdk（docker-py，需 `pip install ".[docker]"`）/ cli（subprocess） |
| DOCKER_CONTAINER | 默认 wing-goose-worker；非默认值时尊重单容器模式（向后兼容） |
| DOCKER_WORKDIR | /challenge |
| DOCKER_BUILD_ON_MISSING | false=镜像缺失报错；true=自动构建 |
| DOCKER_DOCKERFILE | Dockerfile 路径 |
| DOCKER_CPU_PROFILE | light/normal/brute/heavy（默认 normal） |
| DOCKER_CPU_CORES / DOCKER_MEM_LIMIT | 显式覆盖配额（>0/非空优先于 Profile） |
| DOCKER_MAX_CONTAINERS | 0=按宿主资源自动计算 |
| DOCKER_RESERVE_CPU / DOCKER_RESERVE_RAM | 宿主预留因子（默认 0.25） |

**多解题器 / 巡查 / 熔断 / 数据库 / 日志**

| 键 | 说明 |
|----|------|
| SWARM_ENABLED | true=所有难度走 3 风格并行（默认）；false=回退 T3 结论（easy 单路，medium/hard 并行） |
| COORDINATOR_PATROL_GAP | 巡查发起间隔（默认 5，范围 5~10；=5 时按风格节奏） |
| MAX_STEPS / MAX_TASK_TIME / MAX_COST_LIMIT | 熔断阈值（80 / 1800s / $1.5） |
| SQLITE_PATH / CHROMA_PATH | data/ctf.db / data/chroma |
| LOG_LEVEL | INFO |

### 8.3 命令行使用

`python main.py run` 参数一览：

| 参数 | 说明 |
|------|------|
| `--target` | 目标 IP/域名/URL（与 --file 至少其一） |
| `--file` | 题目附件路径 |
| `--desc` | 题目描述（可选） |
| `--show-steps` | 实时输出每步 Thought/Action/Observation |
| `--report PATH` | 任务结束后写 Markdown 报告（含时间线与改进建议） |
| `--type / --source / --difficulty` | 题目元数据（web/pwn/crypto/...、来源、0-10 难度，用于报告与入库） |
| `--no-rag` | 关闭 RAG 经验检索 |

```powershell
# 示例：Reverse 题 + 报告
python main.py run --file .\annex\chal.elf --desc "reverseme: find the flag" --type reverse --difficulty 6 --report .\reports\rev1.md --show-steps
```

### 8.4 swarm 模式如何启用

**配置层**：`.env` 中 `SWARM_ENABLED=true`（默认）即启用；false 回退单 agent。

**调用层**（NSS Runner 等集成方）：

```python
from ctf_agent.swarm import SwarmCoordinator

def verify_flag(flag: str) -> tuple[bool, str]:
    # 平台确证校验（如 NSS 真实提交）；无法判定时倾向返回 True
    return (flag == EXPECTED_FLAG, "ok")

sw = SwarmCoordinator(
    project_root=".",                       # 含 ctf_agent 包的根目录
    verify_flag=verify_flag,                # 可选；None=接受首个提交
)
task = {
    "challenge_id": "nss_2314",
    "title": "babyrsa",
    "desc": "题目描述...",
    "type": "crypto",
    "difficulty": "easy",                  # easy→单路; medium/hard→3 路
    "max_seconds": 1500.0,
    "bus_challenge_id": "nss_2314",        # 总线统一键（同题共享）
    "bus_dir": "./data/bus",               # 跨进程总线目录
}
result = sw.run(task, max_seconds=600.0)   # styles=None 按难度默认
print(result.solved, result.winner_style, result.flag, result.killed_count)
```

`SwarmResult` 解读：

- `solved` / `flag` / `winner_style`：是否解出、flag、获胜风格；
- `elapsed`：墙钟总耗时；`total_tokens`：各路 token 总和；
- `agents`：每路 `SwarmAgentResult`（style/success/steps/elapsed/tokens/fail_reason/killed_by_sibling）；
- `killed_count`：被兄弟终止的路数。

注意：`SwarmCoordinator` 内部每路以 `AgentClient.solve` 子进程运行，task JSON 写在 `data/swarm_tasks/`；`verify_flag` 回调在 swarm 进程内被调用。

### 8.5 docker 执行链配置

**选择后端**：

| 后端 | 依赖 | 适用 |
|------|------|------|
| sdk（默认） | `pip install "ctf-agent[docker]"`（docker-py） | 生产推荐（进程内单例复用连接） |
| cli | 无（subprocess 直调 docker 命令） | 无需额外依赖 / 与单测 patch 兼容 |

**资源 Profile 选择**：

| Profile | CPU/内存 | 适用场景 |
|---------|---------|---------|
| light | 1核/1G | web/misc 轻量 |
| normal（默认） | 2核/2G | 一般题目 |
| brute | 4核/2G | 爆破类 |
| heavy | 4核/4G | angr/sagemath 大格/内存取证 |

```powershell
# 环境变量示例
DOCKER_ENABLED=true
DOCKER_IMAGE=wing-goose:v2
DOCKER_BACKEND=sdk
DOCKER_CPU_PROFILE=heavy
```

**容器生命周期**：容器常驻（sleep infinity），同题复用 / 异题重建（S5）；`cleanup_orphans()` 清理停止的孤儿容器；附件目录挂载到 `/challenge/workspace`，同题共享目录挂载到 `/shared`。

### 8.6 解题输出解读

**单 agent JSONL 示例**：

```json
{"type":"start","protocol_version":"1.1","challenge_id":"nss_2314","title":"babyrsa","challenge_type":"crypto","difficulty":"easy","max_steps":60,"max_seconds":1500,"max_submissions":1,"model":"deepseek-v4-flash"}
{"type":"step","step_no":1,"thought":"先查看附件文件类型...","action":"ssh_exec","action_input":"{\"command\": \"file /challenge/workspace/task.py\"}","observation":"$ file ...","is_error":false,"is_final":false,"final_answer":"","error_msg":"","timestamp":1754300001.2}
{"type":"heartbeat","elapsed":15.3,"step":3,"phase":"ssh_exec"}
{"type":"coordinator","step_no":10,"should_intervene":true,"priority":"SHOULD","reason":"基于 B1(FACT)...","guidance":"停止爆破...","forbidden_actions":[],"revert_guidance":false,"reflection":"反思...","belief_state":[{"id":"B1","statement":"...","level":"FACT"}]}
{"type":"submission","flag":"NSSCTF{...}"}
{"type":"result","success":true,"flag":"NSSCTF{...}","final_answer":"...","fail_reason":"","steps":23,"elapsed":412.5,"tokens":48621,"model":"deepseek-v4-flash"}
```

字段含义：

- `step.observation`：工具输出（可能截断，ERROR 前缀=工具失败）；
- `step.is_error`：解析失败或工具错误步；
- `coordinator.should_intervene=false` = 沉默（方向正确）；true = 干预（priority MUST/SHOULD）；
- `result.success=false` 时看 `fail_reason`（熔断/超时/格式错误/无进展等）。

**Markdown 报告**（`--report`）：含任务、结果（flag/步数/token）、解题步骤、复盘（关键工具/错误次数/简评）与改进建议，由 `analyzer.py` 生成。

### 8.7 常见问题排查

| 现象 | 可能原因 | 处理 |
|------|---------|------|
| `python main.py run` 报 "OPENAI_API_KEY 未配置" | .env 缺失/键名错误 | 从 .env.example 复制并填写 `OPENAI_API_KEY` |
| LLM 每步调用超时/卡 90s+ | 系统代理劫持（#2664） | 确认 `LLM_PROVIDER=go`；代码已强制 proxy=None 直连；检查网络到 opencode.ai 是否直连可达 |
| 容器无法启动（镜像缺失/daemon 异常） | 镜像未构建 / Docker Desktop 未运行 | `docker info` 检查 daemon；`docker build -f scripts/docker_test/Dockerfile.wing-goose -t wing-goose:v2 .`；或 `DOCKER_BUILD_ON_MISSING=true` |
| `DOCKER_BACKEND=sdk` 报 docker-py 未安装 | 未装 extra 依赖 | `pip install -e ".[docker]"`（代码会自动降级 cli 并 warnings 提示） |
| 附件在容器内找不到 | 容器是旧版本创建（无挂载） | 删除容器让其重建（S14 已自动校验缺挂载重建）；或设置 `reset_container=true` |
| swarm 只有一路在跑 | SWARM_ENABLED=false / 难度为 easy | 检查 .env；easy 按 T3 默认单路，可显式传 styles |
| 兄弟发现从未出现 | bus_dir 未配置 / 总线异常 | task JSON 设置 `bus_challenge_id` + `bus_dir`；看 solve 启动日志 "消息总线启用" |
| agent 不主动 share_finding | prompt 无协作引导 | 总线启用时会自动注入 _COOP_GUIDANCE；若仍不主动，靠每 5 步协作义务注入兜底 |
| 提交后兄弟不 kill | verify_flag 判定不通过 | 确认 verify_flag 倾向接受（无法判定返回 True）；回调异常会被记录并拒绝 |
| 连续格式错误退出 | LLM 输出不合规 | 看 `format_errors` 计数；max_format_errors=3；可换模型/难度重试 |
| 复盘显示 "检测到幻觉, skill 未入库" | facts 实体不在轨迹中 | 属正常保护；检查轨迹完整度（step_count ≥8、文本 ≥200 字符） |
| 巡查从不干预 | 方向正确（沉默原则） | 这是设计行为；看 coordinator JSONL 的 reflection/belief_state 确认分析在发生 |
| `docker exec` 报 "No such container" 后自动恢复 | 容器被外部删除 | S2 自愈：本调用内重建并重试；持续失败检查镜像是否存在 |
| 多题并行时容器数超限 | 并发未调控 | 设置 `DOCKER_MAX_CONTAINERS` 或调整 Profile（heavy 会显著降低并发） |

---

## 9. 附录

### 9.1 术语表

| 术语 | 含义 |
|------|------|
| swarm | 同题多风格并行编队（本版本核心） |
| style | 解题风格（conservative/aggressive/innovative） |
| 兄弟 agent | 同一道题并行求解的其他风格 agent |
| 消息总线 / FileBus | 跨进程共享发现通道（JSONL 文件） |
| 巡查指导器 / Coordinator | 独立 LLM 视角的旁观者，宏观审视轨迹并给出战术指导 |
| belief_state | 巡查 LLM 的推论分级清单（FACT/LIKELY/POSSIBLE/DISPROVED） |
| 禁忌列表 | 已确认无效的操作（关键词匹配） |
| 精确签名禁忌 | 死循环自动标记的精确 action 签名（精确匹配） |
| MUST / SHOULD | 巡查指导优先级（必须执行 / 建议执行） |
| 灵感板 creative_hints | 创新风格巡查必产的创造性探索建议（非强制） |
| 无幻觉核对 | 复盘 facts 实体必须在轨迹中出现的校验 |
| 降级链 | docker → ssh → MCP 的执行层逐级降级 |
| B+ 后台执行 | nohup 后台 + 日志轮询的长任务执行模式 |
| 快路径 | 短命令直连 docker exec 同步执行（消灭固定 sleep 1） |
| wall-clock 超时 | 线程级总超时，覆盖慢速流半死连接 |
| 冒烟测试 | 领题前快速探测 LLM provider 可用性 |

### 9.2 主要工具清单（执行层 + 专用题型）

- 执行层：`ssh_exec`（别名 docker_exec）、`ssh_python`（别名 docker_python）、`ssh_upload`（别名 docker_upload）；
- 协作：`share_finding`、`check_findings`、`list_shared_files`、`read_shared_file`、`write_shared_file`；
- 内置：base64/hex/url 编解码、caesar_cipher、rot13、hash_compute/identify、file_type、strings、hex_dump；
- HTTP：http_request；
- 密码学：crypto_rsa、crypto_classic、des_cryptanalysis、feistel_decrypt、ecdsa_nonce_reuse、sage_common_d_attack、encoding_helper；
- 逆向：binary_analyze、angr_symbolic_exec、apk_decompile（jadx/apktool）、ghidra_headless、radare2；
- Web：web_recon、web_fingerprint、web_dirscan、sqlmap、lfi_scanner、lfi_log_inject；
- Pwn：pwn_checksec、pwn_cyclic、pwn_ropgadget、pwn_exploit；
- OSINT/取证：osint_exiftool、osint_steghide、osint_binwalk、osint_tshark、mem_xor_analyze、vision_analyze、ocr、web_search、osm_geocode、reverse_image_search；
- 记忆：remember_fact（mid-term 事实）、exploit_template。

### 9.3 参考文档与设计约束

- 本文件与源码一致；关键实现锚点：
  - 消息总线：`ctf_agent/bus/message_bus.py`、`ctf_agent/bus/file_bus.py`；
  - swarm 编排：`ctf_agent/swarm.py`；
  - 巡查指导器：`ctf_agent/agent/coordinator.py`；
  - 三风格：`ctf_agent/agent/styles.py`；
  - 轨迹复盘：`ctf_agent/review.py`；
  - docker 执行链：`ctf_agent/tools/docker_tool.py`；
  - 配置：`ctf_agent/config.py`。
- 设计约束（复盘驱动）：
  - verify_flag 只做平台确证校验，防幻觉由 react.py 兜底；
  - 巡查间隔钳制 5~10 步（避免整体过频）；
  - 所有注入内容标注"参考方向/非强制"，冲突以 agent 最新观察为准；
  - 总线只传播高置信度（FACT/LIKELY）且经消毒的发现；
  - 无工具调用直接 Final Answer 一律拒绝（所有题型）。

---

### 9.4 关键类与方法速查表

**编排层（swarm.py）**

| 类/方法 | 签名 | 说明 |
|---------|------|------|
| SwarmCoordinator | `__init__(project_root, python_executable=None, verify_flag=None, workdir=None)` | 编队协调器 |
| SwarmCoordinator.run | `run(task, styles=None, max_seconds=600.0, on_step=None, on_log=None) -> SwarmResult` | 并行求解主入口 |
| SwarmCoordinator.stop | `stop() -> bool` | 停止全部存活子进程 |
| SwarmResult.by_style | `by_style(style) -> SwarmAgentResult \| None` | 按风格取单路结果 |

**消息总线（bus/）**

| 类/方法 | 签名 | 说明 |
|---------|------|------|
| MessageBus.post | `post(agent_id, task_id, content, kind="finding", reply_to=0) -> int` | 发布，返回全局 id |
| MessageBus.check | `check(cursor=0, task_id=None, kind=None) -> (list[Finding], int)` | 游标增量读取 |
| FileBus.post | `post(challenge_id, content, agent="", level="FACT", topic="") -> float` | 发布（返回 ts） |
| FileBus.check_sanitized | `check_sanitized(challenge_id, since=0.0) -> list[dict]` | 拉取消毒后的可见消息 |
| FileBus.post_finding | `post_finding(agent_id, task_id, content, kind="finding", reply_to=0) -> int` | MessageBus 兼容发布（seq 游标） |
| FileBus.check_findings | `check_findings(cursor=0, task_id=None, kind=None) -> (list[Finding], int)` | MessageBus 兼容读取 |
| EventBus | `subscribe/emit/unsubscribe/clear/event_count` | 进程内事件总线 |

**智能体层（agent/）**

| 类/方法 | 签名 | 说明 |
|---------|------|------|
| ReActEngine.run | `run(task) -> ReActResult` | ReAct 主循环 |
| parse_llm_output | `parse_llm_output(text) -> ParsedAction` | LLM 输出容错解析 |
| Coordinator.should_check | `should_check(step_no, max_steps=0, live_errors=-1) -> bool` | 巡查时机判定 |
| Coordinator.fire_async_analysis | `fire_async_analysis(trajectory, challenge_type="", challenge_difficulty="", task_desc="", step_no=0, max_steps=0) -> bool` | 异步发起分析 |
| Coordinator.consume_pending_guidance | `consume_pending_guidance(current_step=0) -> CoordinatorGuidance \| None` | 消费异步结果 |
| Coordinator.intercept_forbidden | `intercept_forbidden(action, action_input) -> str` | 工具执行前禁忌拦截 |
| Coordinator.analyze | `analyze(trajectory, ...) -> CoordinatorGuidance` | L1+L2 完整分析 |

**复盘（review.py）**

| 类/方法 | 签名 | 说明 |
|---------|------|------|
| TrajectoryReviewer.review | `review(trajectories: list[tuple[str, str]]) -> ReviewResult` | 复盘多条轨迹 |
| TrajectoryReviewer.ingest_skills | `ingest_skills(result, skill_library=None) -> list[str]` | skill 入库 |
| check_no_hallucination | `check_no_hallucination(trajectories, review_json) -> dict` | 无幻觉核对 |
| ReviewResult.no_hallucination | property | 是否通过核对 |

**工具层（tools/）**

| 类/方法 | 签名 | 说明 |
|---------|------|------|
| default_tools | `default_tools(ssh_client=None, docker_client=None, message_bus=None, agent_id="", shared_fs_dir="", enable_l3=False, ...) -> list[Tool]` | 组装工具集 |
| DockerClient.exec_cmd | `exec_cmd(cmd, cwd=None, timeout=60, env=None) -> CmdResult` | 容器内执行命令 |
| DockerClient.ensure_container | `ensure_container(task_id=None) -> bool` | 确保容器可用 |
| DockerClient.cleanup_orphans | `cleanup_orphans(docker_cmd="docker") -> int` | 清理孤儿容器 |
| resolve_quota | `resolve_quota(profile, cpu_cores=0, mem_limit="") -> (int, str)` | 解析容器配额 |
| compute_max_containers | `compute_max_containers(profile_cpu, profile_mem_gb, ncpu, docker_mem_bytes, reserve_cpu=0.25, reserve_ram=0.25) -> int` | 并发度模型 |
| make_backend | `make_backend(name, docker_cmd="docker") -> DockerBackend` | 后端工厂（cli/sdk） |
| ShareFindingTool.execute | `execute(content, task_id, kind="finding", reply_to=0)` | 发布发现 |
| CheckFindingsTool.execute | `execute(cursor=None, task_id=None, kind=None)` | 读取发现（含 [MUST] 强制回答） |

**LLM 路由（llm/routed.py）**

| 类/方法 | 签名 | 说明 |
|---------|------|------|
| RoutedLLMClient.chat | `chat(messages, model=None, temperature=0.0, max_tokens=None, timeout=None, extra=None, model_tier="flash") -> ChatResult` | 带路由 chat |
| RoutedLLMClient.smoke_test | `smoke_test(timeout=10.0) -> dict[str, bool]` | provider 冒烟探测 |
| RoutedLLMClient.apply_smoke_from_file | `apply_smoke_from_file(path)` | 应用冒烟标记 |

**熔断（orchestrator/）**

| 类/方法 | 签名 | 说明 |
|---------|------|------|
| CircuitBreaker.check | `check(step) -> BreakerAction` | 六维熔断检测 |
| CircuitBreaker.record_llm_call | `record_llm_call(tokens, model)` | 成本统计 |
| AdaptiveBreaker.extend_steps | `extend_steps(additional=20) -> bool` | 动态扩展步数 |
| compute_max_steps | `compute_max_steps(challenge_type=None, challenge_difficulty=None) -> int` | 动态步数计算 |

**配置（config.py）**

| 方法 | 说明 |
|------|------|
| get_settings() | 全局配置单例（lru_cache，测试用 cache_clear 重置） |
| Settings.has_llm_config() | 是否配置 LLM Key |
| Settings.has_kali_config() | 是否配置 Kali SSH |

### 9.5 测试与验证清单

**单元级（pytest）**：

- 输出解析：`parse_llm_output` 对 Markdown 装饰/别名/缺前缀/代码块包裹等 20+ 容错场景；
- 总线：MessageBus 游标语义（裁剪后游标正确性）、FileBus 消毒规则（URL 参数/payload/IP 移除、200 字符截断）；
- 无幻觉核对：facts 实体出现在/不出现轨迹的判定；
- 配额：`resolve_quota` Profile 与显式覆盖、`compute_max_containers` 并发度计算；
- 配置：.env 缺省值、字段别名映射。

**集成级**：

- swarm 冒烟：`SwarmCoordinator.run` 对本地 mock 题目（verify_flag 用预期 flag），验证一解出即 kill、killed_count 统计；
- 总线跨进程：两个进程同读一个 bus_dir，验证 post_finding/check_findings 互相可见；
- docker 链：daemon 停止时工具降级到 ssh；容器删除后 exec 自愈重建；
- 复盘：构造短轨迹（≥8 步），验证 `_review` 触发、幻觉时拒绝入库。

**回归保护点**：

- 工具白名单与题型期望集（`_check_direction`）保持一致；
- 总线注入格式与 prompt 中"[兄弟发现]"段一致；
- coordinator JSONL 字段与 AgentClient 解析一致；
- 协议版本 1.1 字段（start/heartbeat/submission/result）与 .env.example 一致。

### 9.6 阅读指引与文档维护约定

**推荐阅读顺序**：

1. 新读者 / 集成方：第 1 章（定位）→ 第 8 章（使用方法）→ 第 2 章（架构）→ 第 4 章（数据设计）；
2. 二次开发者：第 3 章（核心模块）→ 第 5 章（版本演进）→ 第 9.4 节（API 速查）；
3. 运维人员：第 6 章（部署运维）→ 第 8.7 节（故障排查）→ 第 7 章（安全）；
4. 复盘研究者：第 3.13 节（ADR 决策记录）→ 第 3.3 节（巡查指导器）→ 第 5.13 节（小优化清单）。

**维护约定**：

- 本文档与 `_publish/wing/WING-Goose/` 源码一一对应；修改源码后应同步更新对应章节；
- 新增模块需在 2.4 目录结构、5.1 新增文件总览、9.4 API 速查三处登记；
- 配置字段变更需同步 4.5 配置表与 8.2 .env 说明；
- 复盘驱动的行为变更（如新的 MUST 机制）应登记到 3.13 ADR 记录；
- 本文档不描述 WING-Corvus（总指挥）功能，升级到 Corvus 后应另立文档。

**文档统计**：本文档覆盖 WING-Goose 全部核心模块（智能体层 / 巡查指导器 / swarm 编排 / 消息总线 / 轨迹复盘 / 记忆层 / 工具层 / LLM 路由 / 熔断）、数据协议、版本演进、部署运维、安全伦理与使用方法，共 9 章 + 附录。

---

> 本文档基于 WING-Goose 生产代码快照（2026-08-04）审计生成，所有描述与 `_publish/wing/WING-Goose/` 目录下源码一致。本文档不包含 WING-Corvus 的总指挥/flag 校验/多阶段协调设计。



