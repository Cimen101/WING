# WING-Falcon（猎隼）设计与使用文档

> **文档性质**：系统设计文档 + 使用指南（基于实际源码审计编写，不包含未实现的功能描述）
> **版本**：WING-Falcon（猎隼）——精英单兵基线（Sprint 32.10 后快照）
> **发布日期**：2026-08-02
> **代码位置**：`_publish/wing/WING-Falcon/`（含 `ctf_agent/` 源码、`main.py`、`pyproject.toml`、`.env.example`）
> **配套文档**：`docs/CTF_AGENT_DESIGN.md`（设计文档）、`docs/CTF_AGENT_GUIDE.md`（使用指南）

---

## 目录

1. [项目概述与设计目标](#1-项目概述与设计目标)
2. [总体架构](#2-总体架构)
3. [智能体层：ReAct 推理引擎](#3-智能体层react-推理引擎)
4. [巡查指导器 Coordinator](#4-巡查指导器-coordinator)
5. [记忆层：三层记忆 + Skill 库 + 失败缓存](#5-记忆层三层记忆--skill-库--失败缓存)
6. [工具层：三层调用链与工具清单](#6-工具层三层调用链与工具清单)
7. [LLM 路由与容错](#7-llm-路由与容错)
8. [熔断机制：六维熔断 + 自适应与动态扩展](#8-熔断机制六维熔断--自适应与动态扩展)
9. [任务状态机与编排](#9-任务状态机与编排)
10. [入口层：CLI / WebUI / JSONL 子进程协议](#10-入口层cli--webui--jsonl-子进程协议)
11. [数据设计](#11-数据设计)
12. [部署与运维](#12-部署与运维)
13. [安全与伦理](#13-安全与伦理)
14. [使用方法](#14-使用方法)
15. [附录](#15-附录)

---

## 1. 项目概述与设计目标

### 1.1 项目定位

WING-Falcon（猎隼）是 CTF 自动化解题系统的**精英单兵基线版本**：一个单 agent 的完整解题引擎。它接收一段题目描述（可选目标 URL、附件路径），在无人干预的情况下自主完成"信息收集 → 漏洞识别 → 计划制定 → 攻击执行 → 验证提交"的全流程，最终输出 flag。

| 维度 | 定位 |
|------|------|
| 形态 | 单 agent 完整解题引擎（无多解题器协作） |
| 自主性 | 全自主决策，无需人工提示 |
| 题型覆盖 | Web / Pwn / Crypto / Reverse / Misc / Forensics / OSINT |
| 对外接口 | CLI（`main.py`）、WebUI（FastAPI）、子进程 JSONL 协议（`solve.py`） |
| 演进方式 | Skill 库 + 长期记忆库（RAG）持续自学习 |

### 1.2 设计目标

WING-Falcon 的核心设计目标可以归纳为六条：

1. **全自主**：只给题目描述，agent 自己决定下一步做什么、用哪个工具、何时收手。
2. **不空想**：flag 必须来自工具观测结果，禁止凭记忆/猜测编造 flag（反幻觉）。
3. **不迷路**：巡查指导器（Coordinator）以"旁观者"视角审视完整轨迹，在 agent 走偏、死循环、停滞时给出精准战术指导（MUST/SHOULD 分级）。
4. **不硬死**：LLM 三级路由（zen→fallback→pro）+ 动态 provider 健康状态 + wall-clock 总超时，保证单次 API 故障不拖垮整题；熔断器按难度/题型自适应并支持进展感知延长。
5. **持续学习**：解题成功/失败后自动沉淀 Skill 与经验（去标识化），下次同类题开局即可检索命中。
6. **安全可控**：Kali SSH 命令审计、flag 安全模型（verify 只返回布尔）、知识库去标识化、反幻觉规则。

### 1.3 核心理念

WING-Falcon 的设计贯穿以下理念：

- **方法论而非剧本**：system prompt 注入的是"如何自己发现 X"的 5 阶段自主解题方法论，而不是"用 X 攻击"的具体指令；Skill 注入一律标注"参考用，需自主判断"，避免机械复制。
- **旁观者清**：解题 agent 当局者迷，巡查指导器作为第三者宏观审视完整行为轨迹，全局视角更容易发现问题（Sprint 27 起引入）。
- **证据驱动**：巡查指导器的所有干预都必须基于轨迹中的事实（FACT/LIKELY 推论分级），POSSIBLE 只能作为建议，DISPROVED 立即撤销。
- **渐进式增强**：每个 Sprint 聚焦一个能力域，改动遵循"最小侵入"原则（新增模块/可选参数，不破坏已验证接口）。
- **失败要快**：收敛策略要求解不出的题快速收手（连续 20 步无 flag 线索即重新审视），不耗满步数做无效探测。

### 1.4 版本演进与快照说明

本版本是 Sprint 32.10 之后的功能快照（2026-08-02），属于**精英单兵**基线，核心能力栈：

| 能力域 | 说明 |
|--------|------|
| ReAct 推理引擎 | Thought-Action-Observation 循环，带容错解析与反幻觉兜底 |
| LLM 三级路由 | zen（免费）→ fallback（官方）→ pro，动态 provider 健康状态 + wall-clock 总超时 |
| B+ 长任务超时转后台 | 超过时限后由熔断器进展感知 + 协调器 extend_steps 动态扩展，避免硬杀 |
| 巡查指导器 | FACT/LIKELY/POSSIBLE/DISPROVED 推论分级 + MUST 强制 + 自我纠错 |
| 失败轨迹缓存 | 同题第二次跑自动注入失败提示 + 演化反思 |
| 技能库 | `data/skills/` 结构化解题套路，自学习积累、合并去重、淘汰 |
| LLM 调用三层容错 | flash 失败 → 重试 → pro 降级 → 注入提示跳过本步继续 |
| 日志精简 | JSONL 协议日志按需输出，heartbeat 防"假死"误判 |

### 1.5 本版本**不包含**的能力（范围边界）

为了清晰界定"精英单兵"基线，以下能力**不在**本版本中（阅读代码时也不会找到对应实现）：

- **Swarm 多解题器**：无多个 agent 并行解题与赛马机制（`agent/multi_agent.py` 中的 Planner/Executor/Critic 为早期实验遗留代码，本版本的实际装配路径——`solve.py` 与 `main.py`——均只使用单 agent `ReActEngine`）。
- **消息总线（bus）**：无全局消息总线；agent 与调用器之间通过子进程 stdin/stdout JSONL 协议通信。
- **总指挥（commander）**：无上层调度器；每个任务在独立进程中由单个引擎完成。
- **Docker 工具链**：无 docker SDK 后端；远程执行统一走 SSH（Kali 沙箱）或纯内置工具。

> ⚠️ 说明：`main.py` 中存在一行对 `ctf_agent.bus.message_bus` 的历史引用（Sprint 12 遗留），该模块在本发布包中不存在；`tools/__init__.py` 的 `default_tools()` 签名也不含 `message_bus` 参数。本版本**推荐**使用 `solve.py` 子进程协议或纯内置模式运行，避免该遗留路径。

---

## 2. 总体架构

### 2.1 分层架构

WING-Falcon 采用严格的分层架构，上层依赖下层、下层不感知上层：

```
┌─────────────────────────────────────────────────────────────────┐
│                     入口层 (L5)                                    │
│   main.py (CLI)  /  web/app.py (WebUI)  /  solve.py (JSONL 协议)  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                     编排层 (L4)                                    │
│   orchestrator/state.py (任务状态机)                               │
│   orchestrator/breaker.py + adaptive.py (六维熔断 + 自适应)         │
│   agent/coordinator.py (巡查指导器)                                │
│   agent/failed_trajectory_cache.py (失败轨迹缓存)                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                     引擎层 (L3)                                    │
│   agent/react.py (ReAct 引擎) + agent/prompts.py (提示词系统)       │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                     记忆层 (L4' 记忆子系统)                          │
│   memory/short_term.py (短期)  memory/mid_term.py (中期)            │
│   memory/long_term.py (长期 ChromaDB)  memory/rag.py (HyDE)         │
│   memory/skill_library.py (具体 Skill 库)  skills/ (抽象 Skill 库)    │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                     工具层 (L1/L2/L3)                               │
│   tools/base.py (Tool 基类)                                        │
│   L1 内置纯 Python 工具 (编解码/HTTP/分析)                           │
│   L2 SSH 工具 (ssh_exec/ssh_python/ssh_upload + 专用工具集)          │
│   L3 MCP 工具 (ghidra_headless/radare2, 默认关闭)                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                     基础设施层 (L6)                                  │
│   ssh/client.py (paramiko)  ssh/safety.py (命令审计)                 │
│   llm/client.py + routed.py (LLM 客户端与路由)                       │
│   config.py (pydantic-settings 配置)                                │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 模块目录结构

```
WING-Falcon/
├── main.py                    # CLI 入口（run / web 子命令）
├── pyproject.toml             # 项目元数据与依赖
├── .env.example               # 环境变量模板
├── data/
│   ├── chroma/                # ChromaDB 向量库持久化（RAG 长期记忆）
│   ├── skills/                # 具体 Skill 库（index.json + <id>.md）
│   └── .gitkeep
└── ctf_agent/
    ├── config.py              # pydantic-settings 配置加载
    ├── solve.py               # 子进程 JSONL 协议求解入口（对外稳定契约）
    ├── analyzer.py            # 复盘闭环（writeup + 完整 Markdown 报告）
    ├── experience.py          # 经验沉淀（成功解题去标识化写入 LTM）
    ├── skill_learner.py       # Skill 学习器（模板/LLM 两种生成方式）
    ├── stop_signal.py         # 全局停止信号（避免循环导入）
    ├── agent/
    │   ├── react.py           # ReAct 引擎核心（解析器 + 主循环）
    │   ├── prompts.py         # 提示词系统（方法论/反幻觉/格式规则）
    │   ├── coordinator.py     # 巡查指导器（LLM 智能旁观者）
    │   ├── failed_trajectory_cache.py  # 失败轨迹缓存 + 演化反思
    │   └── multi_agent.py     # （遗留）多智能体框架，本版本不装配
    ├── llm/
    │   ├── client.py          # 基础 LLM 客户端（OpenAI 兼容）
    │   └── routed.py          # 三级路由 + 动态健康 + wall-clock 超时
    ├── memory/
    │   ├── short_term.py      # 短期记忆（滑动窗口）
    │   ├── mid_term.py        # 中期记忆（SQLite 关键事实）
    │   ├── long_term.py       # 长期记忆（ChromaDB 向量库）
    │   ├── rag.py             # HyDE 检索增强
    │   └── skill_library.py   # 具体 Skill 库（自学习积累）
    ├── skills/
    │   ├── skill.py           # Skill 数据结构（抽象/具体两层）
    │   ├── library.py         # 抽象 Skill 库注册/检索
    │   └── injector.py        # Skill 注入器（格式化注入 system prompt）
    ├── orchestrator/
    │   ├── state.py           # 任务状态机
    │   ├── breaker.py         # 六维熔断器
    │   └── adaptive.py        # 自适应熔断（按题型/难度 + 动态扩展）
    ├── tools/                 # 30+ 专用工具（详见 §6）
    ├── ssh/
    │   ├── client.py          # paramiko SSH 客户端
    │   └── safety.py          # 命令审计与工作区白名单
    ├── knowledge/
    │   └── kali_arsenal.py    # Kali 工具兵器谱（命令级知识注入）
    ├── range/                 # 本地靶场控制（list/start/stop/status/verify）
    ├── cli/
    │   └── runner.py          # CLI run 子命令核心逻辑
    └── web/
        ├── app.py             # FastAPI 应用（任务/干预/WebSocket）
        └── static/index.html  # 前端首页
```

### 2.3 数据流：一次任务的生命周期

以 `solve.py` 子进程方式为例，一次完整任务的数据流如下：

```
调用器 (如 NSS Runner / 批量测试脚本)
   │  写 task JSON 文件 (challenge_id/title/desc/type/difficulty/max_steps/max_seconds)
   ▼
python -u -m ctf_agent.solve --task-file task.json
   │
   ├─ 1. 重置 stop 信号；读取配置 Settings
   ├─ 2. _build_engine_with_timeout(150s)：
   │       SSH 连接（可选）→ RoutedLLMClient → 冒烟测试标记应用
   │       → default_tools(enable_range=False) → AdaptiveBreaker(按题型/难度)
   │       → SkillLibrary → LongTermMemory（失败静默降级）
   │       → ReActEngine(coordinator + on_step + on_coordinator)
   ├─ 3. 输出 {"type":"start", protocol_version:"1.1", ...}
   ├─ 4. 启动 heartbeat 线程（每 15s）+ stdin 统一分发线程
   ├─ 5. engine.run(desc)：
   │       ├─ Planner/RAG 注入（若有）→ ShortTermMemory 初始化
   │       ├─ 循环：协调器巡查 → system prompt 刷新 → LLM 调用(三层容错)
   │       │        → 解析 → 反幻觉检查 → 禁忌拦截 → 工具调用
   │       │        → Observation 回灌 → 熔断检查 → 步数推进
   │       └─ Final Answer → submission_handler 提交（多次提交机制）
   ├─ 6. 每步输出 {"type":"step",...}；巡查时输出 {"type":"coordinator",...}
   ├─ 7. 自学习：learn_skill（成功→套路，失败→避坑）
   ├─ 8. 输出 {"type":"result", success, flag, steps, elapsed, tokens, ...}
   └─ 9. 进程退出（调用器负责硬超时 kill）
```

CLI 路径（`main.py run`）与 WebUI 路径流程类似，差异在于：CLI 由用户直接给定 `--target/--file/--desc`，WebUI 通过 HTTP API 提交并在后台线程运行引擎、通过 WebSocket 推送步骤，并支持"对话纠偏"（InterventionHub）。

### 2.4 进程与线程模型

- **进程模型**：每个任务一个独立进程（子进程方式）。隔离性好，单题崩溃不影响其他任务；调用器负责硬超时 kill。CLI/WebUI 在单进程内以线程方式运行。
- **线程使用**：
  - `solve.py`：heartbeat 线程（每 15s 输出心跳）、stdin 统一分发线程（读 stdin 并按消息类型分发）、engine 构造超时线程（150s 兜底）、wall-clock 超时线程（LLM 调用，45s 硬总超时，daemon）。
  - `ssh/client.py`：命令执行等待线程（`recv_exit_status()` 无法被 paramiko timeout 中断，用线程 + join 实现真正超时）。
  - `web/app.py`：后台任务线程（每个任务一个 daemon 线程）。
- **停止信号**：`stop_signal.py` 提供线程安全的全局 `threading.Event`，`solve.py` 的 stdin 分发器收到 `{"control":"stop"}` 时置位，ReAct 引擎每步开始前检查。

---

## 3. 智能体层：ReAct 推理引擎

### 3.1 设计总览

ReAct 引擎（`ctf_agent/agent/react.py`）实现经典的 Thought-Action-Observation 循环：

```
Thought: <推理过程>
Action: <工具名>
Action Input: <JSON 参数>
──────────────────────────────
Observation: <工具返回结果>
──────────────────────────────
（循环，直到输出 Final Answer）
```

引擎核心类为 `ReActEngine`，关键构造参数（均为可选，带默认值）：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `max_steps` | 35 | 步数上限（运行时由熔断器/协调器动态调整） |
| `max_format_errors` | 3 | 连续格式错误上限 |
| `max_rounds` | 10 | 短期记忆保留轮数 |
| `temperature` | 0.0 | 采样温度（工具调用场景固定 0 保证确定性） |
| `breaker` | CircuitBreaker() | 熔断器 |
| `coordinator` | None | 巡查指导器 |
| `submission_handler` | None | 多次提交回调 |
| `skill_library` | None | 具体 Skill 库 |
| `long_term` | None | 长期记忆（RAG） |
| `failed_cache` | 全局单例 | 失败轨迹缓存 |

### 3.2 输出解析器：parse_llm_output

LLM 输出解析是 ReAct 循环的咽喉，`parse_llm_output(text) -> ParsedAction` 对 LLM 的各种"坏习惯"做了大量容错（历经 Sprint 14/15/20/32.4b 多轮修复）：

1. **Final Answer 优先**：`Final\s*Answer\s*:\s*(.+)` 大小写不敏感、冒号后可有空格；答案去除尾随引号。
2. **Action 字段 Markdown 装饰剥离**：LLM 经常输出 `**Action:** ssh_exec` 或 `Action: \`ssh_exec\``，正则 `Action(?!\s*:?\s*Input\b)\s*:?\s*\*{0,2}\s*:?\s*\`?([a-z_][a-z0-9_]*)` 只匹配工具名格式（`[a-z_][a-z0-9_]*`），并加负向前瞻避免把 "Action Input" 中的 "Input" 误解析为工具名。
3. **Action Input 多行 JSON**：`Action\s*Input\s*:\s*(.*?)` 到下一个字段或结尾；支持 ```json``` 代码块包裹、markdown 加粗（`**{...}**`）、尾随逗号。
4. **别名回退（Sprint 20）**：LLM 偶尔输出 `Input:` / `Args:` / `Parameters:` / `参数:` 等，用别名正则二次匹配。
5. **裸 JSON 回退（Sprint 20）**：若 Action 匹配但 Action Input 缺失，尝试从文本中提取首个 `{...}` JSON 对象（LLM 漏写 "Action Input:" 前缀的场景）。
6. **Thought 回退（Sprint 20）**：LLM 经常省略 "Thought:" 前缀直接输出 "Action: ..."，此时取 Action/Final Answer 前的文本作为 thought，避免"无推理盲动"。
7. **空输出识别**：空字符串返回 `is_valid=False, parse_error="empty output"`，引擎对空输出有专门的免费重答机制（见 §3.5）。

`ParsedAction` 结构：

```python
@dataclass
class ParsedAction:
    thought: str = ""            # 推理文本
    is_final: bool = False       # 是否 Final Answer
    final_answer: str = ""       # 最终答案
    action: str = ""             # 工具名
    action_input: str = ""       # JSON 参数字符串
    is_valid: bool = True        # 是否解析有效
    parse_error: str = ""        # 解析失败原因
```

### 3.3 引擎主循环

`ReActEngine.run(task)` 委托给 `_run_inner(task)`，主循环关键逻辑（对应源码逐步）：

1. **任务 ID 与工具集**：`task_id = 用户指定 or uuid4().hex[:12]`；若启用了中期记忆，自动注册 `remember_fact` 工具。
2. **Planner 拆解（预留）**：若注入了 planner，将其输出格式化为"作战计划"注入 system prompt（标注"参考而非约束"，失败静默降级）。
3. **System prompt 构建**：`build_system_prompt(tools, task, challenge_type, difficulty)` 自动注入方法论、工具 schema、格式规则、反幻觉规则、Skill 检索结果、Kali 兵器谱。
4. **RAG 检索**：任务开始时一次性检索相似历史方案（`RAGRetriever.retrieve(task)`），不每轮刷新（省 LLM 调用）。
5. **短路退出检查**：每步开始前检查 stop 信号与巡查点。
6. **巡查**：`coordinator.should_check(step_no, max_steps)` 决定是否巡查（详见 §4）。
7. **LLM 调用（三层容错）**：`llm.chat(messages, extra=thinking_extra)`，异常时重试 2 次（间隔 2s）→ pro 降级重试 → 全部失败则注入提示跳过本步继续（Sprint 32.8）。
8. **解析与分支**：
   - `is_final`：反幻觉检查（必须 ≥1 次有效工具调用，否则拒绝并注入提示）；通过后走多次提交逻辑或直接成功。
   - `is_valid=False`：空输出走免费重答；格式错误累计到 `max_format_errors` 后熔断失败。
   - 成功解析：先做禁忌操作拦截（`coordinator.intercept_forbidden`），再调用工具。
9. **工具调用**：`_invoke_tool(action, action_input)` 从 `self.tools` 字典查工具并调用；未知工具返回 `ERROR: 未知工具 'xxx'。可用工具: ...`。
10. **Observation 回灌**：构造 `Observation: <文本>` 加入短期记忆；连续空 observation ≥2 次注入恢复提示。
11. **熔断检查**：`breaker.check(step)`，`should_terminate` 则失败返回；`should_inject_hint` 则提示前置。
12. **range_control 快速终止**：若 `range_control verify` 观测到 "Flag verified" 等成功标志，立即提取 flag 并成功返回（避免 verify 成功后仍继续消耗步数）。
13. **步数推进**：`while True` + 步进（Sprint 32.4b 修复了 `for range` 一次性求值导致 extend_steps 无效的 bug）。

### 3.4 反幻觉机制

反幻觉是 WING-Falcon 的硬约束（Sprint 14-17 多轮强化），引擎层面有两道闸门：

**闸门一：无工具调用直接 Final Answer = 幻觉**
```python
if not any(s.action and not s.is_error for s in steps):
    # 拒绝并注入 hint：必须先调用至少 1 个工具探测/读取
```
任何题型强制 ≥1 次有效工具调用（`is_error` 的步骤不算）。这修复了"Triplet_Tweak 0 工具幻觉"与 "hard_r2 第 2 步编造 flag" 两个真实案例。

**闸门二：提示词层面**（`ANTI_HALLUCINATION_RULES`）：
- 禁止自写 secret.txt / flag.txt 等文件；
- 禁止输出占位符式 flag（test_flag_here / placeholder / lorem / dummy 等）；
- 禁止用 Final Answer 提交未通过工具验证的字符串；
- 禁止 Z3/加密未解出时猜测答案；
- 禁止直接读取环境中的 secret.txt（必须通过 verify 接口）；
- 无回显/盲注类题型：flag 必须真实出现在 Observation 中才能提交，Thought 不得虚构工具返回。

### 3.5 空输出与格式错误容错

引擎对"模型端空输出"与"格式错乱"分别处理（Sprint 7 P0-1）：

| 场景 | 处理 |
|------|------|
| `empty output`（空字符串） | 连续 2 次内"免费重答"：注入 NULL_OBSERVATION_HINT 作为 observation 让 LLM 重新输出，不计入格式错误 |
| 空输出超过 2 次 | 升级为正式格式错误，计入 `consecutive_format_errors` |
| 格式错乱（missing fields） | 立即计入格式错误，注入 FORMAT_ERROR_HINT |
| 格式错误 ≥ `max_format_errors`(3) | 熔断失败，返回 `连续 N 次格式解析失败` |

连续空 observation（工具返回空）≥2 次也会注入 `NULL_OBSERVATION_HINT` 帮助恢复，不直接触发熔断。

### 3.6 思考模式（thinking mode / reasoning_effort）

Sprint 26 起，对 DeepSeek 系模型启用思考模式（thinking_mode）：模型先输出思维链（reasoning_content）再输出最终回答（content），提升准确性。`_thinking_extra()` 按以下优先级选择 `reasoning_effort`：

1. `force_max_thinking=True`（重试场景）→ `max`
2. hard/extreme 难度 → `max`
3. medium + reverse/pwn/crypto/misc（深度分析题型）→ `max`
4. medium + web/forensics/osint（套路化题型）→ `high`
5. easy → `high`
6. 未知难度 → `default`

思考参数通过 `extra_body={"thinking": {"type": "enabled"}}` 透传（DeepSeek 扩展字段，非 OpenAI 标准）。注意思考模式不支持 temperature/top_p（设置不报错但不生效），`_parse_response` 会兼容 `reasoning_content` 为空 content 的场景（回退使用 reasoning_content 作为主内容）。

### 3.7 多次提交机制

当提供 `submission_handler` 回调（`solve.py` 的 JSONL 协议路径，`max_submissions > 1`）时：

- agent 输出 Final Answer → 引擎调用 handler 提交 → 向 stdout 输出 `{"type":"submission","flag":...}` → 从 stdin 队列读取调用器响应（60s 超时）。
- **提交成功** → 正常结束；**提交失败** → 注入驳回反馈，agent 在当前上下文中继续分析（不重新开始）。
- **去重**：已提交过的答案直接驳回（`_submitted_flags` 集合）。
- **上限**：达到 `max_submissions` 后不再调用 handler，注入提示让 agent 继续工具分析（不直接退出），同时累计 `consecutive_format_errors` 防止反复 Final Answer 死循环。
- 无 handler 时（传统单次模式）直接成功返回。

### 3.8 步数软截断（Sprint 32.4b）

旧实现 `for step_no in range(1, max_steps+1)` 在进入循环时一次性求值，协调器 `extend_steps` 即使更新了 `self.max_steps` 也不会延长循环。新实现改为：

```python
while True:
    if step_no > self.max_steps:
        if self.breaker.has_recent_progress():
            pass          # 有实质进展 → 继续（由时间熔断 3x 兜底）
        else:
            break         # 无进展超过宽限期 → 兜底退出
```

配合熔断器的 `has_recent_progress()`（`progress_grace_seconds` 内无新 observation 才退出），实现"优先 LLM 软截断（MUST 指导 + 加步），不做严格硬截断"。

### 3.9 LLM 调用三层容错（Sprint 32.8）

引擎每步的 LLM 调用有三层容错（对应代码中的嵌套 try）：

```
第 1 层: llm.chat(...)                       # flash 路由
   失败 → sleep(2)                           # 网络抖动瞬时恢复
第 2 层: llm.chat(...)                       # 再次 flash
   失败 → sleep(2)
第 3 层: llm.chat(..., model_tier="pro")     # 降级 pro 重试
   仍失败 → 注入提示"LLM API 暂时不可用, 请保持思路, 下一步继续" → step_no += 1 → continue
```

这样中途 API 故障不会导致整题 0 步失败；最终由熔断器（时间/成本）兜底。配合 routed.py 的动态 provider 健康状态（§7.3），provider 故障会被快速标记 down 并进入跳过期。

### 3.10 停止信号

`ctf_agent/stop_signal.py` 提供全局停止标志（独立模块避免 solve ↔ react 循环导入）：

```python
request_stop()        # solve.py stdin 分发器收到 {"control":"stop"} 时调用
is_stop_requested()   # react.py 每步开始前检查
reset()               # 每次新任务开始时调用
```

收到停止信号后，引擎返回 `success=False, fail_reason="收到调用器 stop 信号, 主动停止"`。非子进程模式（直接调用引擎）无此信号检查。

### 3.11 提示词系统详解（agent/prompts.py）

#### 3.11.1 提示词总结构

`build_system_prompt(tools, task, challenge_type, difficulty)` 用 `.replace` 占位符机制拼装（**不用 `.format`**——因为注入内容里含大量字面大括号如 `{xxx}`，`.format` 会抛 KeyError）：

```
SYSTEM_PROMPT_TEMPLATE =
  你是 CTF 解题 Agent ... 
  {autonomous_methodology}   ← 5 阶段自主解题方法论
  # 可用工具
  {tool_schemas}             ← 每个工具 name/description/JSON Schema
  # 输出格式与规则
  {common_rules}             ← 输出格式硬约束
  {anti_hallucination_rules} ← 反幻觉规则
  {skill_injection}          ← Skill 检索结果（位于末尾，先拼在 tool_schemas 之前）
```

随后可选追加 Kali 兵器谱（`format_arsenal(cats=["web","pwn","recon"], include_playbook=True, only_unwrapped=True)`）。用户任务 prompt 由 `build_task_prompt(task)` 生成："请解决以下 CTF 任务:\n\n{task}\n\n开始你的推理 (按 5 阶段方法论推进)."

#### 3.11.2 五阶段自主解题方法论（AUTONOMOUS_METHODOLOGY）

Sprint 16 起移除了具体攻击提示，改为教 LLM"如何自己发现 X"：

| 阶段 | 目标 | 步数参考 |
|------|------|----------|
| 阶段 1：信息收集（Reconnaissance） | 提取题目关键信息（技术栈/题型/攻击面/关键字）；Web 题 1 步 web_recon；Pwn/Reverse 题 file_analyze + strings；Crypto 读明文识别算法；OSINT 用 exiftool + ocr | 1-3 步 |
| 阶段 2：漏洞识别（Identification） | 列出攻击面、参考 Skill 库、用排除法选路径；Thought 中**明确写出攻击推断** | 1-2 步 Thought |
| 阶段 3：计划制定（Planning） | 明确 1-2 步做什么；选定工具链；复杂利用优先 ssh_python 一次写完 | 1 步 Thought |
| 阶段 4：攻击执行（Exploitation） | 每次只调 1 个工具；必读 Observation 完整响应；失败即换方向 | N 步 Action |
| 阶段 5：验证与提交（Validation） | flag 格式确认；verify 接口验证；拿不到老实报告失败 | 1 步 Final Answer |

**假设验证与证伪机制（Sprint 32.4 强制纪律）**：

- 建立假设时 Thought 必须写全三要素：**假设 A**（如"校验逻辑是逐字符标准 MD5"）+ **预期 B**（如"目标表与 md5(单字符) 匹配"）+ **验证**（用什么工具验证 B）；
- B 成立 → 继续用 A 推进；**B 不成立 → 立即放弃 A**，检查输入变换（查表/拼接/异或），切到假设 C，**不要在旧假设上反复消耗步数**；
- 同一假设验证 ≥2 次不成立 = 假设已死：强制切换方向，并在 Thought 写明"假设 A 已证伪，原因: ..."；
- **协调器干预 = 强制约束**：巡查指导器发 [MUST] 指令时必须立即执行，不得以自身判断为由忽略。

**交叉验证（max 思考强度下强制）**：crypto 题用脚本验证解密结果合理性；reverse 题用 gdb/angr 验证 flag 通过 check_flag；misc 题验证答案长度/字符集；web 题验证 flag 出现在 HTTP 响应中。**思考越深，越要验证**——max 强度下推理能力强，容易过度自信直接给答案。

#### 3.11.3 反幻觉规则详解（ANTI_HALLUCINATION_RULES）

**绝对禁止**：

- 自写 secret.txt / flag.txt / answer.txt 等文件；
- 输出占位符 flag（test_flag_here / placeholder / fix_me / lorem / ipsum / dummy / sample / TODO / TBD / xxx）；
- 用 Final Answer 提交未通过工具验证的字符串；
- Z3/加密未解出时猜答案；
- 直接读取环境中的 secret.txt（必须通过 verify 接口）；
- **第 1 步直接 Final Answer**（无工具调用 = 幻觉，会被引擎自动拒绝）。

**无回显 / 盲注类题型（Sprint 21，no_echo_ssti 复盘）**：页面不回显渲染结果时用时间盲注 / 报错注入 / 写文件再读（RCE 后写 static/out.txt 再 http_request 读取）/ DNS 外带；flag 必须真实出现在 observation 中；Thought 不得虚构工具返回。

**Web 页面交互入口优先（Sprint 21，bypass1 复盘）**：首页 HTML 的 form/input/button 是真实入口，先按表单逻辑测参数再爆破；页面标题/注释/提示文本是核心线索；参数测试要"对比基线"；不要在目录爆破上消耗 >5 步。

**共享靶机 flag 定位（Sprint 22，round5 复盘）**：RCE 后找 flag 优先级——① 按题目标题匹配 `/flag_<关键词>`；② 列出全部 `/flag*` 逐个比对；③ 才考虑环境变量/数据库。不要深挖共享靶机上的无关遗留文件（诱饵）。

**框架漏洞套路库（Sprint 23，ThinkPHP 复盘）**：

- ThinkPHP 3.x assign+display 模板注入链（`_templateFile` 覆盖 → LFI）；日志包含 RCE（UA 注入 `<?php system($_GET['c']);?>` → 包含 Runtime/Logs 日志）；
- ThinkPHP 5.x 经典 RCE：`?s=index/\think\App/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id`；
- Laravel debug RCE（.env APP_KEY 泄露 → CVE-2018-15133；Ignition CVE-2021-3129）；
- PHP 反序列化 POP 链构造三陷阱：private 属性长度公式 `1+len(class)+1+len(prop)`（不是 len 直接拼接）；PHP 8.4 参数类型严格（readfile 第二参传 [] → TypeError，system/passthru/exec 可行）；null 字节传输必须用 POST；
- 源码分析收敛规则：框架源码分析 ≤5 步、.git 泄露 ≤3 步、确认 LFI 后直接用。

**JWT crack 套路（Sprint 23，jwt_crack 复盘）**：提取 JWT → base64 解码 header+payload → 爆破密钥（PyJWT/hashcat）→ 签发伪造 JWT → 查看完整响应 body → 提取 flag。⛔ action_input JSON 解析失败（is_error=true）时不能直接提交 Final Answer。

#### 3.11.4 题型专项强化（内置于提示词）

| 题型 | 强化规则（复盘来源） |
|------|----------------------|
| Crypto Narrow_DES | 64-bit key 通常只有 32-bit 有效位；必须用 des_cryptanalysis（24/32-bit MITM → Python MITM → Z3 兜底）；收集 2-3 对明密文即可 |
| Crypto AES-CBC 无 IV | PyCryptodome `AES.new(K, MODE_CBC)` **随机生成 IV**（不是全零）；CBC 自恢复：第一块错后续对；用已知文件头（PNG/JPG/PDF/ZIP magic）替换第一块 |
| Crypto 图片密码 | "decipher/decode" + 图片附件 → 图片内容即密文（替换密码），**不是隐写**；直接用 vision_analyze 1 步识别符号 |
| Pwn 静态分析优先 | 必须先静态（file → checksec → strings → objdump 反汇编 main）再动态；找"后门条件"（cmp 特定偏移字节 vs 常量）；黑盒探测是最后手段 |
| Pwn UAF/格式串 | pwn_checksec → 一次性 ssh_python 探测菜单协议 → exploit_template 拿骨架 → 泄露地址后写出计算过程 |
| Reverse 反调试 | 发现"逐字符校验 argv[1]"模式立即用 angr；angr 状态消失/除零 → 检查 main 是否生成 flag 到 buf → gdb 读 buf；LD_PRELOAD 绕过 ptrace |
| Reverse OLLVM | 识别 CFG-flattening 后不要完整反汇编；用 gdb 在 call 指令处下断点读寄存器/内存；对比 A/B/C/D 寄存器判断 MD5 Init/Update/Final；先验证假设再爆破 |
| Forensics USB pcap | CBW 31 字节（USBC）/CSW 13 字节（USBS）/DATA 512/2048；rotated → 字节旋转；直接 exploit_template(usb_bot) |
| Forensics magic bytes | 文件打不开 = 第一步 xxd 查 magic；修复文件头（printf+dd）；"magic" 题名 = magic bytes 不是立体图；彩色文字用颜色通道差定位 + OCR |
| Misc HTML 谜题 | exolve 格式 clues 直接在 HTML 中，grep 提取即可；"flag is 66 across" → 只解第 66 条，不需要填整个 grid |
| OSINT | exiftool → ocr → web_search → osm_geocode 严格顺序，总步数 ≤5；网络工具失败 1 次立即用 LLM 知识 |
| 附件型 | 优先分析附件（cat/file/xxd/strings），⛔ 不要在 GitHub 搜索题目标题或答案 |

#### 3.11.5 输出格式规则（COMMON_RULES）

- 每步严格输出 `Thought / Action / Action Input` 三段式，或 `Thought / Final Answer`；
- 每次只能调用一个工具；Action Input 必须是合法 JSON；Action 字段只能是工具名（不含参数/括号）；
- Observation 以 ERROR 开头 = 工具失败，应修正参数或换工具；
- **逐字节完整读取 Observation 响应体**（即使 HTTP 2xx/4xx，body 常藏 flag/线索/错误原因）；短响应往往是 JSON 错误码或重定向提示，必须读；base64 片段先解码；
- Thought 不能为空（Sprint 20）：写出已知信息 + 下一步意图 + 关键参数计算（泄露地址后写 `leaked=0x..., base=leaked-offset, target=...`）。

#### 3.11.6 收敛与放弃策略（Sprint 22）

- **连续 20+ 步未出现任何 flag 线索**（flag 模式/新端点/新文件）时必须停下来重新审视：是否环境死局（页面恒回显固定内容/无表单无 JS/所有路径同一 fallback/提交无差异 → 果断 Final Answer 报告，不要继续爆破）、是否思路重复（同一工具换参数 >3 次仍无新线索 → 换方向）、是否利用 3 次失败（→ 换思路）；
- 目录爆破/参数枚举/无差异探测消耗 >8 步即收敛；收敛前在 Thought 写明已尝试的 2-3 条路径与结论，保证失败报告有信息量；
- **flag 已得即终（Sprint 22.5）**：一旦 Observation 中看到完整 flag 文本（格式合理、来自靶机/附件），**立即 Final Answer**，禁止再开新连接验证/试其他利用链/比对多个 flag 文件；提交前在 Thought 写明该 flag 来自哪一步的哪个 Observation（可追溯防幻觉）。

---

## 4. 巡查指导器 Coordinator

### 4.1 设计哲学：旁观者清

巡查指导器（`ctf_agent/agent/coordinator.py`）是 Sprint 27 引入的核心智能模块，设计思想一句话：**旁观者清，当局者迷**。解题 agent 专注于当下，可能陷入困境或方向走错；Coordinator 作为第三者宏观审视完整行为轨迹，全局视角更容易发现问题，在无人监管独立运行时**代替人提供战术指导**。

设计原则：

1. **沉默原则**：方向正确且进展正常时保持沉默（`should_intervene=false`），不打扰 agent 节奏。
2. **精准指导**：发现问题时给出具体可操作的战术建议（做什么 + 怎么做 + 为什么），而非模板化提示。
3. **知识增强**：查询 RAG / Skill 库辅助判断，提供更专业的指导。
4. **两级分析**：先规则预检（快速，不调 LLM），再 LLM 深度分析（精准）。

### 4.2 触发规则（Sprint 31 动态干预频率）

`Coordinator.should_check(step_no, max_steps)` 决定是否巡查：

| 触发条件 | 说明 |
|----------|------|
| 首次巡查 | 第 `first_check`（默认 10）步——早期方向检查，避免开局走错 |
| 正常后续 | 每 `check_interval`（默认 10）步 |
| 出错后加速 | 两次巡查间出现过错误 → 间隔缩短至 5 步（快速纠偏） |
| 接近上限 | 倒数 10 步内每 3 步巡查一次（强制收敛） |
| 异常触发 | 连续 `max_errors`（3）个错误步 → 立即触发 |
| 兜底 | 倒数 `early_exit_steps`（20）步时至少巡查一次 |

### 4.3 两级分析（Sprint 30 优化）

`Coordinator.analyze(trajectory, challenge_type, ...)` 返回 `CoordinatorGuidance`，分两级：

**L1 规则预检（快速，不调 LLM）**

- **L1-A 硬问题 → 直接干预（priority=MUST）**：
  - 完全重复死循环：同一工具 + 相似参数（路径归一化）出现 ≥3 次（`_check_exact_repeats`）；
  - 明显方向错误：最近 5 步操作集合与题型期望工具集完全不相交（`_check_direction`，内置各题型工具表）；
  - 禁忌操作命中：agent 正在尝试已确认无效的操作（`_check_forbidden_actions`）；
  - MUST 指令未执行：上次 MUST 指导后一个巡查间隔内主导工具未变且无实质进展（`_check_must_noncompliance`）。
- **L1-B 软线索 → 传给 L2 LLM 参考**：
  - 工具过度使用：同一工具 ≥5 次但参数不同（`_check_tool_overuse`）；
  - 连续错误步 ≥3（`_check_errors`）；
  - 指导持久性：上次指导后行为未改变（`_check_guidance_persistence`）。

**L2 LLM 深度分析（精准，始终触发）**

- 宏观审视完整轨迹 + L1 线索 + 知识库检索结果；
- 能区分"工具过度使用但方向正确"和"真正的思路固化"；
- 方向正确时保持沉默（`should_intervene=false`）；
- 输出严格 JSON（含 `reflection` 反思字段），解析失败降级为不干预。

**降级模式（无 LLM）**：L1-B 软线索也作为干预依据（priority=SHOULD）。

### 4.4 推论分级框架（Sprint 32.6 核心改造）

Coordinator 对轨迹的每次分析都基于推论分级，所有判断分为四个等级，跨巡查持久化在 `belief_state` 列表（`[{id, statement, level, evidence, action}]`）：

| 等级 | 含义 | 决策权重 |
|------|------|----------|
| **FACT** | 轨迹中直接观察到的确定信息（如 "step 24 POST /index/test 返回 HTTP 200"） | 可作 MUST 依据 |
| **LIKELY** | 基于事实的合理推断，有充分证据（如 "入口存在且可用"） | 可作 MUST 依据 |
| **POSSIBLE** | 缺乏充分证据的推测（如 "远程版本可能与附件不同"） | 只能作 SHOULD 建议 |
| **DISPROVED** | 被后续轨迹明确否定的判断 | 必须立即从禁忌列表移除 |

每次巡查的强制流程（写在 prompt 中）：**回顾**上次推论清单 → **更新**（升级/降级/证否）→ **反思**（我是否把 POSSIBLE 当 FACT 用了？）→ **决策**（只有 FACT+LIKELY 可作 MUST 依据）。`reason` 字段必须引用推论 ID（如 "基于 B1(FACT)+B2(LIKELY)"）。

### 4.5 禁忌列表（forbidden_actions）

Sprint 31 引入：已确认无效的操作（如 "hashcat 爆破 cloud.zip 密码"连续失败）加入禁忌列表。

- **来源**：L2 LLM 分析时生成，仅允许基于 FACT/DISPROVED 推论（不得基于 POSSIBLE）；
- **拦截**：`intercept_forbidden(action, action_input)` 在**巡查间隔之外**也被引擎调用（工具执行前），关键词匹配命中即拦截并重定向 agent，不再浪费步数；
- **移除**：推论被证否（DISPROVED）时自动清理对应禁忌项；agent 用某操作取得突破时通过 `remove_forbidden` 撤销误判（Sprint 32.4c 自我纠错）。

### 4.6 MUST / SHOULD 强制机制

- **MUST（必须执行）**：用于明显方向错误 / 死循环 / 禁忌操作。Sprint 32.4 强化：MUST 指导必须给出**强制工具链切换**——明确"停止 X，改用 Y 工具/方法"，不要说"换个思路"这种空话。
- **SHOULD（建议执行）**：用于软线索/改进建议，agent 可结合实际判断。
- **持久注入**：MUST 指导在引擎侧连续重复注入 3 次（`must_repeat_left=2`，本步 + 后续 2 步），防止"注入一次被忽略"（#2501 Blast 复盘：协调器 step10 下达 MUST，agent 却继续 MD5 穷举 20 步）。
- **未执行检测**：上次 MUST 后一个巡查间隔内主导工具未变**且无实质进展** → 判定 MUST 未执行，升级为 L1-A 硬问题直接干预，并把该操作加入禁忌列表。若 agent 虽工具未变但持续有新 observation（有效推进），交由 L2 LLM 全局判断（#2516 复盘防误判）。

### 4.7 自我纠错（Sprint 32.4c）

Coordinator 承认"我之前的判断不一定正确"，用后续轨迹验证自己：

- **revert_guidance**：上次指导后 agent 未按指导执行，但用自己的方式持续取得进展 → 撤销上次指导（清空 MUST 状态），若当前方向正确则保持沉默。
- **remove_forbidden**：禁忌列表中的操作被 agent 成功使用并取得突破 → 移除该误判禁忌项。
- 原则："承认错误不是问题，坚持错误才是"——判断依据是轨迹证据，证据变了就要改。

### 4.8 知识库辅助

`_query_knowledge(task_desc, challenge_type)` 在 L2 分析时查询知识库（直接调用底层 API，避免 HyDE 的额外 LLM 调用）：

1. **Skill 库**：`skill_library.format_for_prompt(task_desc, category, top_k=2)` 检索匹配的解题套路；
2. **RAG 长期记忆**：`long_term.search(task_desc, n_results=2)` 检索历史 writeup（含 type 标注）。

任一查询失败都静默跳过，不阻断分析。

### 4.9 轨迹摘要（防 token 爆炸）

`_summarize_trajectory(trajectory)` 把完整轨迹压缩为摘要：

- 前 3 步：完整 thought + action + 参数前 100 字符；
- 中间步：只保留 action + 参数前 80 字符（若 >8 步则省略标记）；
- 最近 5 步：完整 thought + action + observation 前 300 字符。

### 4.10 CoordinatorGuidance 输出结构

```python
@dataclass
class CoordinatorGuidance:
    should_intervene: bool            # 是否需要干预
    guidance: str                     # 战术指导（做什么+怎么做+为什么）
    reason: str                       # 干预原因（引用推论 ID）
    extend_steps: bool                # 是否建议扩展步数
    detected_issues: list[str]        # 检测到的问题列表
    analysis_summary: str             # LLM 分析摘要（日志用）
    priority: str                     # "MUST" / "SHOULD"
    forbidden_actions: list[str]      # 禁忌列表
    revert_guidance: bool             # 撤销上次指导
    remove_forbidden: list[str]       # 移除误判禁忌项
    reflection: str                   # 巡查器反思过程（日志/调试）
    belief_state: list[dict]          # 推论清单 [{id, statement, level, evidence, action}]
```

巡查结果通过 `on_coordinator` 回调以 `{"type":"coordinator", ...}` JSONL 行输出（Sprint 29），完整透传 reflection 与 belief_state（Sprint 32.7），便于调用器显示完整日志。

### 4.11 巡查器与 ReAct 引擎的协作时序

引擎主循环中与巡查器相关的完整协作流程（对应 `react.py` 主循环代码）：

```text
每步开始 (step_no, max_steps)
 │
 ├─ 1. 判断是否到巡查点: coordinator.should_check(step_no, max_steps)
 │      （首次第 10 步 / 每 10 步 / 出错后每 5 步 / 倒数 10 步内每 3 步 / 连续 3 错立即）
 │
 ├─ 2. 构造轨迹数据: 每步只取 thought/action/action_input/observation(前500字符)/is_error
 │
 ├─ 3. coordinator.analyze(traj, challenge_type, challenge_difficulty, task_desc, step_no, max_steps)
 │      ├─ L1-A 硬问题 → 直接返回 MUST 干预
 │      ├─ L1-B 软线索 → 传 L2 LLM 深度分析
 │      └─ 返回 CoordinatorGuidance
 │
 ├─ 4. 处理干预结果:
 │      ├─ should_intervene=true:
 │      │    ├─ guidance 加 [MUST]/[SHOULD] 标记 → _coordinator_guidance
 │      │    ├─ MUST → _must_repeat_left = 2（本步 + 后续 2 步共注入 3 次）
 │      │    └─ forbidden_actions 追加"禁忌操作"提醒文本
 │      ├─ should_intervene=false → _coordinator_guidance = ""
 │      ├─ revert_guidance=true → _must_repeat_left = 0（停止旧 MUST 重复注入）
 │      └─ extend_steps=true → breaker.extend_steps() → 同步 self.max_steps
 │
 ├─ 5. 注入指导到短期记忆:
 │      ├─ _must_repeat_left > 0 → 注入指导 + "[MUST][重复执行] ... 还剩 N 次强调" → 递减
 │      └─ 否则 → 注入指导一次并清空 _coordinator_guidance
 │
 ├─ 6. on_coordinator(guidance, step_no) → 输出 coordinator JSONL 行（日志）
 │
 └─ 7. 工具执行前拦截: coordinator.intercept_forbidden(action, action_input)
        └─ 命中禁忌 → 注入拦截提示 → 步数 +1 → 重新让 LLM 输出
```

**MUST 持久注入的强制力来源**（#2501 Blast 复盘修复）：

1. MUST 指导连续注入 3 次，agent 想忽略也难；
2. 一个巡查间隔后主导工具未变 + 无实质进展 → L1-A 判定"MUST 指令未被执行"再次 MUST 干预；
3. 同时该操作进入禁忌列表 → 巡查间隔之外也被 `intercept_forbidden` 立即拦截；
4. 但若 agent 用自己的方式持续取得进展（新 observation）→ `_has_progress_after_guidance` 判定为有效推进，不误判，且 L2 LLM 可 `revert_guidance` 撤销上次指导。

**异常安全**：analyze / 注入 / 拦截 / 日志回调的任何异常都被捕获并静默忽略（`except Exception: pass`），巡查器故障绝不阻断主流程。

---

## 5. 记忆层：三层记忆 + Skill 库 + 失败缓存

记忆子系统（`ctf_agent/memory/`）由"短期 → 中期 → 长期"三层记忆、RAG 检索、具体 Skill 库、失败轨迹缓存共同构成，再加上经验闭环（analyzer / experience / skill_learner），实现"解题即学习"的知识自增长。

### 5.1 记忆体系总览

| 记忆 | 实现 | 存储 | 生命周期 | 用途 |
|------|------|------|----------|------|
| 短期记忆 | `ShortTermMemory` | 内存 | 单任务 | 当前 ReAct 循环的消息历史（滑动窗口） |
| 中期记忆 | `MidTermMemory` | SQLite `task_facts` 表 | 单任务 | 关键事实（IP/端口/漏洞函数名）防丢 |
| 长期记忆 | `LongTermMemory` | ChromaDB 向量库 | 跨任务持久 | 历史 writeup 语义检索（RAG） |
| 具体 Skill 库 | `memory/skill_library.py` | `data/skills/`（index.json + md） | 跨任务持久 | 可复用的解题套路（自学习积累） |
| 抽象 Skill 库 | `skills/` 包 | 内存注册 + 文件 | 跨任务 | 按漏洞类型的抽象解题模式 |
| 失败轨迹缓存 | `failed_trajectory_cache.py` | `data/failed_trajectories/*.jsonl` | TTL 7 天 | 同题失败记忆 + 演化反思 |

### 5.2 短期记忆：ShortTermMemory

`ShortTermMemory` 管理 ReAct 循环的消息历史，结构为：

```
[system 消息(永久保留), task 消息(永久保留),
 (assistant_1, observation_1), (assistant_2, observation_2), ...]
```

- **滑动窗口**：轮次超过 `max_rounds`（默认 10）时丢弃最早的 (assistant, observation) 对；
- **system_prompt 可更新**：`update_system_prompt()` 用于每轮重新注入最新关键事实（中期记忆 facts + RAG 上下文是动态的）；
- **额外 user 消息**：`add_user_message()` 用于注入巡查指导 / 做题中动态 Skill 提示，消息取出即清（避免重复注入）；
- **消息总量**：`total_message_count = 2 + 2 * round_count`。

### 5.3 中期记忆：MidTermMemory

`MidTermMemory` 基于 Python 标准库 sqlite3（无额外依赖），存储当前任务的关键事实：

```sql
CREATE TABLE task_facts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at REAL NOT NULL,
    UNIQUE(task_id, key)
);
```

- 同一 `(task_id, key)` 重复写入覆盖更新（`INSERT OR REPLACE`）；
- 默认内存库（`:memory:`），生产用文件路径；
- 引擎开启中期记忆时自动注册 `remember_fact` 工具（`tools/memory_tools.py`），agent 可显式记录关键事实；
- `format_facts(task_id)` 输出 "# 已知关键事实（防丢，基于历史观察）" 文本，**每轮推理前强制注入 system prompt 顶部**（关键事实防丢机制）；
- 支持上下文管理器（`with MidTermMemory() as mem:`）。

### 5.4 长期记忆：LongTermMemory（ChromaDB 向量库）

`LongTermMemory` 封装 ChromaDB `PersistentClient`：

- Collection 名：`writeups`；向量空间：cosine（`metadata={"hnsw:space": "cosine"}`）；
- **显式固定嵌入模型**：默认 `DefaultEmbeddingFunction()`（sentence-transformers，首次使用会下载模型），避免依赖 Chroma 默认 embedding 因版本升级改变维度（曾出现 256 维旧集合 vs 384 维冲突崩溃）；
- 文档结构：`document`（writeup 文本）+ `metadata`（type/source/difficulty/success/step_count/tokens）+ 唯一 `doc_id`（uuid 或派生哈希）；
- 核心方法：`add_writeup / add_writeups / search(query, n_results, where) / get / count / clear / list_ids`；
- `search` 返回按相似度倒序的结果列表，每项含 `id/document/metadata/distance`；
- 支持 `where` 元数据过滤（如 `{"type": "web"}`）。

### 5.5 RAG 检索：HyDE 假设性文档检索

`memory/rag.py` 实现 HyDE（Hypothetical Document Embeddings）：

1. `generate_hyde_document(llm, task)`：让 LLM 针对任务生成一段 200-400 字的"假设性解题步骤"（用到的工具、技术、关键步骤），temperature=0.3；
2. 用假设文档作为 query 调用 `LongTermMemory.search`（向量相似度）；
3. `format_retrieved_writeups` 把检索结果格式化为 "# 相似历史解题方案（RAG 检索）" 注入 system prompt（每条截断 800 字符）。

`RAGRetriever` 封装完整流程，支持 `skip_hyde=True`（直接用 task 原文检索，省 LLM 调用）。注意：**RAG 检索只在任务开始时做一次**（`_run_inner` 中一次性注入），不每轮刷新，以节省 LLM 调用；`retrieve_raw()` 返回 HyDE 文档与原始结果（调试用）。

### 5.6 具体 Skill 库：memory/skill_library.py

具体 Skill 库是"经验 → 可复用套路"的结构化升级形态（灵感来自 Hermes-Agent），区别于 writeup（叙事型、进向量库）：

| 维度 | writeup | skill |
|------|---------|-------|
| 内容 | 这道题怎么解的（叙事） | 这类题/这个工具怎么用最有效（结构化、可直接照做） |
| 存储 | ChromaDB 向量库 | `data/skills/index.json`（元数据）+ `data/skills/<id>.md`（正文） |
| 迭代 | 无 | 带使用统计，合并去重、淘汰低价值，避免无限膨胀 |

**Skill 数据结构**：

```python
@dataclass
class Skill:
    id: str                    # 如 "web-jwt-crack-2"
    title: str                 # 标题（失败经验带 "[避坑]" 前缀）
    category: str              # web/pwn/reverse/crypto/misc/tool
    trigger: str               # 何时适用（触发特征）
    body: str                  # 正文（核心步骤 + 工具用法 + 坑）
    tags / tools               # 标签与工具链
    script_ref: str            # 关联快速解题脚本
    source_tasks: list[str]    # 来源题目（最多保留 8 条）
    pattern_features: list[str] # 套路特征（跨题匹配，Sprint 28）
    version: int               # 合并升级时 +1
    use_count / success_count  # 使用统计
    score()                    # 价值分 = success*3 + use*1 - age*0.05
```

**自我迭代机制**：

1. **创建前查重**：`_find_similar` 用 tokenize（英文词 + 中文 bigram）+ Jaccard 相似度（阈值 0.55），同方向高相似则"合并升级"（version+1，正文去重合并，`<!-- merged -->` 标记）而非新建；
2. **正文长度上限**：`_MAX_BODY_LEN = 2500`，超限压缩（`<!-- compressed -->` 标记）；
3. **使用反馈**：`mark_used(id, success)` 更新统计；
4. **淘汰**：`prune()` 按方向保留 Top-40（`_MAX_PER_CATEGORY`），淘汰长期零命中/低分条目（`min_score=-5.0`）。

**检索**（Sprint 28 起基于套路特征而非题目名称）：

- `search(query, category, top_k)`：文本相关性（Jaccard，0-10 分）+ 套路特征命中（pattern_features 子串命中，每命中 +1，上限 6）+ 价值分 *0.1；
- `search_by_pattern(observation_text, ...)`：做题中动态检索，要求套路特征至少命中 2 个（避免误匹配）；
- `format_for_prompt`：渲染为 "# 已积累的解题技能（Skill，来自过往经验，可直接照做）" 注入 system prompt（正文截断 900 字符）；
- `format_for_mid_solve`：渲染为 "# 💡 中途 skill 提示（基于当前线索动态检索）"，强调"请自主判断是否适用，不要机械复制"。

### 5.7 抽象 Skill 库：skills/ 包

`ctf_agent/skills/`（Sprint 16 引入）提供**两层 Skill 设计**：

- **ABSTRACT（抽象）**：按 vuln_class 抽象（如 `cbc_bit_flipping`、`ssti_bypass`、`jwt_weak_secret`），跨题可重用，含 recon_signatures（识别特征）、recon_steps（侦查步骤）、exploit_template（攻击模板骨架）、tool_chain（推荐工具链）；
- **CONCRETE（具体）**：1 题 1 Skill，提供具体场景参考，带 `source_challenge_id` 与成功次数。

`injector.py` 的 `format_skill_injection(skills, max_chars=4000)` 把检索结果格式化注入 system prompt（**在反幻觉规则之前**插入，避免被规则遮挡），抽象层优先，超过长度限制时切换紧凑模式。`inject_skills_into_prompt` 支持将 Skill 文本插入到 base_prompt 中反幻觉规则之前的位置。

> 注：本发布包 `data/skills/index.json` 初始为空（`{"skills": {}}`），Skill 库随使用自动积累——这正是"持续学习"的起点。

### 5.8 失败轨迹缓存：failed_trajectory_cache.py

**背景**：v5 测试中 RAM_Drift 从 v4 6 步成功退化为 24 步失败，根因是 LLM 反复尝试多种 XOR key 索引模式陷入循环。失败记忆机制：同一题第二次跑时自动注入前次失败提示，引导 LLM 绕开错误路径。

**存储**：

- 按 `challenge_id` 存储，文件 `data/failed_trajectories/<challenge_id>.jsonl`（append-only JSONL，简单可靠）；
- 每条记录只保留**前 5 步**（thought/action/参数预览/观察预览）+ 最后 thought + 失败原因 + 用过的工具列表（精简防污染）；
- TTL 7 天自动过期；单题最多 10 条（防误用刷爆）。

**注入机制**（引擎 `_inject_context` 中）：

1. `format_hint(challenge_id)`：失败历史摘要（步数/原因/错误答案/用过工具/前 3 步动作 + 建议），标注 `[失败记忆]`；
2. `format_type_hint(type, difficulty)`：**(type, difficulty) 级别的通用解题提示**（cross-challenge 知识共享），内置 forensics/reverse/crypto/web/osint 各难度的手写提示词（如 forensics medium → 立即用 mem_xor_analyze；osint medium → 严格 4 步上限 + 禁止 strings/binwalk/steghide）；
3. `format_reflection_hint(challenge_id, type, difficulty)`：**演化反思**（Sprint 10 Stage 10），基于失败轨迹推断失败模式 + 推荐未用过的工具。

**演化器（Reflector）**：`reflect()` 自动分类失败模式（8 类：LOOP_TOOL_USAGE / REPEATED_ACTION / WRONG_APPROACH / NULL_OBSERVATION / FORMAT_ERROR / MAX_STEPS / TOKEN_WASTE / UNKNOWN），按题型工具表 + 失败模式优先级推荐 3 个未用过的工具，生成 1-3 行改进提示，持久化到 `data/failed_trajectories/_reflections/<challenge_id>.jsonl`。

**清理**：成功解出后 `clear(challenge_id)` 清除失败历史（避免污染重跑）；`cleanup_expired()` 清理过期文件。

### 5.9 经验闭环：成功经验去标识化回写

- **analyzer.py**：`Analyzer` 生成 writeup（模板生成，默认不调 LLM 省 API；可选 LLM 增强）与完整 Markdown 报告（含时间线 + 统计分析 + 改进建议）；`analyze_and_store()` 写入长期记忆；
- **experience.py**：`ingest_solution()` 把成功解题写入 LTM（Sprint 16 补上"RAG 永不增长"的断环）。**安全红线**：写入 LTM 的 writeup 绝不包含真实 flag——`redact_flags()` 把 `xxx{...}`、32+ 位十六进制长串替换为 `<REDACTED_FLAG>`，绝对路径/内存地址替换为占位符（Sprint 28 与 skill_learner 保持一致）；doc_id 由"任务 + 工具链"哈希派生，同类经验只写一次（去重防膨胀）；
- **skill_learner.py**：`learn_skill()` 从一次解题提炼 Skill。两种生成方式：
  - **模板生成（默认，不调 LLM）**：抽取工具调用链 + 关键 Observation 特征 + 成功路径，组织成 If-Then 结构化正文（`_template_body`），全文脱敏；
  - **LLM 生成（可选）**：`_LLM_SKILL_PROMPT` 让 LLM 归纳"识别/步骤/坑"，严格规则：禁止拷贝绝对路径与地址、禁止记录 flag 明文、必须用"条件→动作"格式；
  - 成功任务 → 正向套路 Skill；失败任务 → `[避坑]` 前缀的避坑 Skill（仅在有明确失败信号时生成，避免噪声）；
  - **套路特征提取**（Sprint 28）：`_extract_pattern_features` 从题目 + observation 中提取技术关键词（RSA/CBC/XOR/SSTI/checksec/...），用于跨题匹配；
  - 关联快速解题脚本：`_match_quick_solve` 让 `skill.script_ref` 指向 scripts/quick_solve 注册表中的模板脚本（脚本库不在本发布包内，缺失时静默降级）。

### 5.10 记忆注入优先级（引擎 _inject_context 拼接顺序）

`ReActEngine._inject_context(base_prompt, task_id, rag_context, task)` 按以下顺序拼装 system prompt（无对应内容时跳过）：

```text
1. base_prompt            ← 方法论 + 工具 schema + 格式规则 + 反幻觉 + Skill 注入
2. Planner 作战计划       ← （预留，本版本默认无 planner）
3. 中期记忆 facts         ← MidTermMemory.format_facts（"已知关键事实（防丢）"）
4. RAG 上下文             ← 开局一次性的相似历史方案
5. (type, difficulty) 提示 ← FailedTrajectoryCache.format_type_hint（cross-challenge）
6. 失败轨迹提示           ← format_hint(challenge_id)（同题失败记忆）
7. 演化反思提示           ← format_reflection_hint(challenge_id)（失败模式 + 工具建议）
8. 具体 Skill 注入        ← SkillLibrary.format_for_prompt(query, category, top_k=3)
```

**运行时增量注入**（不在 _inject_context 内，由主循环按需触发）：

- **巡查指导**：每步巡查时 `memory.add_user_message(guidance)`；MUST 指导重复注入 3 次；
- **做题中 Skill 动态检索**：`step_no % 8 == 0` 且步数 ≥8 时，用"题目 + 最近 6 步 observation"文本调用 `format_for_mid_solve`（套路特征 ≥2 命中才注入）；
- **格式错误/空输出恢复提示**：FORMAT_ERROR_HINT / NULL_OBSERVATION_HINT；
- **提交驳回反馈**：多次提交机制注入。

> 设计要点：开局一次性注入（RAG/Skill/失败记忆）控制成本；运行中增量注入（巡查/动态 Skill/错误恢复）保证时效；所有注入内容都以"user 消息"追加，用完即清，避免重复。

---

## 6. 工具层：三层调用链与工具清单

### 6.1 工具基类：tools/base.py

所有工具继承 `Tool` 抽象基类，契约如下：

```python
class Tool(ABC):
    name: str = ""                    # 工具名（ReAct Action 字段值）
    description: str = ""             # 工具用途（注入 system prompt）
    parameters: dict[str, Any] = {}   # JSON Schema 描述 Action Input

    @abstractmethod
    def execute(self, **kwargs) -> str: ...   # 执行并返回 Observation 字符串

    def __call__(self, action_input: str) -> ToolResult: ...  # 从 JSON 字符串调用
```

关键设计：

- **JSON 容错解析**（Sprint 32.2 `_robust_json_loads`）：LLM 输出的 Action Input 常带尾随逗号、JSON 后跟说明文字、markdown 加粗装饰。逐级降级修复：① 去尾随逗号直解；② 截取首个 `{` 到末个 `}` 再解（处理 Extra data）；③ 去 markdown 装饰重试；
- **异常兜底**：`execute()` 内任何异常被捕获并转为 `ToolResult(output="ERROR: <类型>: <消息>", is_error=True)`，不打断 ReAct 循环——熔断器的重复动作检测依赖 Observation 可识别错误；
- **schema()**：返回 `{name, description, parameters}` 供 prompt 渲染。

### 6.2 三层调用链

| 层 | 依赖 | 工具 | 启用条件 |
|----|------|------|----------|
| L1 内置 | 纯 Python（响应 <10ms） | 编解码/HTTP/字符串/文件类型/古典密码/哈希/exploit 模板/crypto_rsa/编码辅助 | 始终可用 |
| L2 SSH | Kali 沙箱（paramiko） | ssh_exec/ssh_python/ssh_upload + 专用分析工具集 | 配置 KALI_* 后自动启用 |
| L3 MCP | Kali 预装 Ghidra/radare2 | ghidra_headless / radare2 | `enable_l3=True` 显式开启（默认关闭） |

`default_tools(ssh_client=None, enable_xxx=True)` 的装配逻辑（`tools/__init__.py`）：

```python
tools = [*builtin_tools(), http_tool()]        # L1 基础
tools.append(ExploitTemplateTool())            # Sprint 19 纯 Python
if enable_crypto: tools.extend(crypto_tools()) # crypto_rsa / crypto_classic
tools.extend(encoding_helper_tools())          # Sprint 23 编码辅助
if ssh_client is not None:
    tools.extend(ssh_tools(ssh_client))        # ssh_exec/ssh_python/ssh_upload
    if enable_binary_analyzer: tools.append(BinaryAnalyzeTool(ssh_client))
    if enable_mem_xor_analyzer: tools.append(MemXorAnalyzeTool(ssh_client))
    if enable_osint: tools.extend(osint_tools(ssh_client))        # exiftool/steghide/binwalk/tshark
    if enable_apk: tools.extend(apk_tools(ssh_client))            # apk_jadx/apktool
    if enable_sage: tools.extend(sage_tools(ssh_client))          # common_d_attack
    if enable_reverse_image: tools.extend(reverse_image_tools(ssh_client))  # web_search/osm_geocode
    if enable_ocr: tools.append(ocr_tool(ssh_client))             # ocr
    if enable_ecdsa: tools.extend(ecdsa_tools(ssh_client))        # ecdsa_nonce_reuse
    if enable_angr: tools.extend(angr_tools(ssh_client))          # angr_symbolic_exec
    if enable_des: tools.extend(des_tools(ssh_client))            # des_cryptanalysis
    if enable_feistel: tools.extend(feistel_tools(ssh_client))    # feistel_decrypt
    if enable_web: tools.extend(web_tools(ssh_client)); tools.extend(lfi_tools(ssh_client))
    if enable_pwn: tools.extend(pwn_tools(ssh_client))            # pwn_checksec/cyclic/ropgadget/exploit
    if enable_range: tools.extend(range_tools(ssh_client))        # range_control
    if enable_vision: tools.extend(vision_tools(ssh_client))      # vision_analyze
    if enable_l3: tools.extend(mcp_tools(ssh_client))             # ghidra_headless/radare2
```

### 6.3 工具全量清单（以实际代码为准）

**L1 内置工具（builtin.py）**：

| 工具名 | 功能 |
|--------|------|
| `base64_encode` / `base64_decode` | Base64 编解码（容错 padding） |
| `hex_encode` / `hex_decode` | Hex 编解码（容错 0x 前缀与空白） |
| `url_encode` / `url_decode` | URL 编解码 |
| `strings` | 可打印字符串提取（含编码参数） |
| `file_type` | 文件类型识别（magic bytes） |
| `hex_dump` | Hex 预览 |
| `caesar_cipher` / `rot13` | 古典密码 |
| `hash_compute` / `hash_identify` | 哈希计算与算法识别 |

**通用工具（http.py / exploit_template.py / crypto_tool.py / encoding_helper.py）**：

| 工具名 | 功能 |
|--------|------|
| `http_request` | HTTP/HTTPS 请求（method/headers/body，支持 POST） |
| `exploit_template` | 生成漏洞利用骨架脚本（uaf/fmtstr_uaf/usb_bot 等） |
| `crypto_rsa` | RSA 攻击（本地纯 Python） |
| `crypto_classic` | 古典密码分析 |
| `multi_encode` / `auto_decode` | 多编码转换 / 自动解码尝试 |
| `url_partial_encode` | URL 部分编码（绕过过滤） |
| `php_filter_chain` | php://filter 链生成 |

**L2 SSH 工具（ssh_tool.py）**：

| 工具名 | 功能 |
|--------|------|
| `ssh_exec` | 在 Kali 执行任意 shell 命令（nmap/gobuster/strings/objdump/xxd/binwalk/steghide/sqlmap 等） |
| `ssh_python` | 执行 Python 脚本（复杂分析/攻击脚本一次写完） |
| `ssh_upload` | 上传文件到 Kali |

**L2 专用分析工具集**：

| 工具名 | 模块 | 功能 |
|--------|------|------|
| `binary_analyze` | binary_analyzer.py | 结构化二进制分析（函数表/字符串表/栈摘要/xor_hints，替代反复 objdump） |
| `mem_xor_analyze` | mem_xor_tool.py | 内存 dump 专用 XOR 分析（4 种 key 模式自动尝试） |
| `exiftool` / `steghide` / `binwalk` / `tshark` | osint_tool.py | OSINT/取证工具集 |
| `apk_jadx` / `apktool` | apk_tool.py | APK 反编译 |
| `common_d_attack` | sage_tool.py | RSA 小公钥指数/共享素数攻击（依赖 fpylll/sagemath） |
| `web_search` / `osm_geocode` | reverse_image_tool.py | 网络搜索（DuckDuckGo）+ 地理编码（Nominatim，零 API key） |
| `ocr` | ocr_tool.py | Tesseract OCR |
| `ecdsa_nonce_reuse` | ecdsa_tool.py | ECDSA nonce 复用攻击 |
| `angr_symbolic_exec` | angr_tool.py | 符号执行求解（复杂 reverse） |
| `des_cryptanalysis` | des_tool.py | DES 变体密钥恢复（24/32-bit MITM → Python MITM → Z3 兜底） |
| `feistel_decrypt` | feistel_tool.py | Feistel 密码解密 |
| `web_fingerprint` / `web_dirscan` / `sqlmap` / `web_recon` / `web_sqli` | web_tool.py | WEB 工具集 |
| `lfi_scanner` / `lfi_log_inject` | lfi_helper.py | LFI 辅助 |
| `pwn_checksec` / `pwn_cyclic` / `pwn_ropgadget` / `pwn_exploit` | pwn_tool.py | PWN 工具集 |
| `range_control` | range/tool.py | 本地靶场控制（list/start/stop/status/verify） |
| `vision_analyze` | vision_tool.py | MIMO-2.5 全模态视觉识别（图片/视频/音频） |

**L3 MCP 工具（mcp_tool.py，默认关闭）**：`ghidra_headless` / `radare2`。

**记忆工具（memory_tools.py，条件注册）**：`remember_fact`（仅引擎启用中期记忆时注册）。

### 6.4 Kali 兵器谱：knowledge/kali_arsenal.py

为了让 agent 在解题前就"清晰地知道 Kali 中有哪些工具、什么情况用、具体怎么用"，`kali_arsenal.py` 以结构化数据描述每个 Kali 工具的 `name / category / when（触发场景）/ how（具体命令）/ note（坑与技巧）/ wrapped（是否已有专用 Tool 封装）`，覆盖 web/pwn/reverse/crypto/misc/recon 方向（whatweb、gobuster、ffuf、sqlmap、nmap、hydra、john、hashcat、gdb、objdump 等）。

`format_arsenal(cats, include_playbook, only_unwrapped)` 将其渲染为紧凑文本注入 system prompt（默认聚焦 web/pwn，可按题型裁剪避免 prompt 臃肿）。设计要点：大量 Kali 工具无需逐一封装为 Tool，对它们最有效的方式是让 agent 通过 `ssh_exec` 直接调用——但前提是 agent 知道命令怎么写，兵器谱正是为此提供"命令级"知识。

### 6.5 工具安全约束

- **range_control 安全模型**（range/__init__.py）：明文 flag 仅存在于运行中的容器内部 + 本地受保护状态文件 `.range_state.json`（chmod 600 + gitignore，仅供 verify）；所有面向 LLM/日志的输出一律 `mask()` 掩码；对外工具只提供 `verify(flag)->bool`，绝不返回真 flag；
- **NSS 等竞赛场景**（solve.py）：`enable_range=False` 直接不提供 range_control 工具，杜绝 agent 误用本地靶场；
- **SSH 审计**：`ssh/safety.py` 额外阻断 `docker exec/inspect/logs/cp/diff` 进靶场容器（详见 §13.3）。

---

## 7. LLM 路由与容错

### 7.1 两级客户端

LLM 层有两个客户端：

- **`llm/client.py`（LLMClient）**：基础客户端，封装 OpenAI Python SDK（同步 `chat` + 异步 `achat`），默认直连 `OPENAI_BASE_URL`；`_parse_response` 兼容 DeepSeek 推理模型的 `reasoning_content` 回退；`ChatResult` 含 `content/usage/model/finish_reason/reasoning_content/raw`；
- **`llm/routed.py`（RoutedLLMClient）**：带三级路由的客户端（Sprint 17+19+32.5/32.8/32.9 迭代），`solve.py` 与引擎容错路径使用。

### 7.2 三级路由策略（zen → fallback → pro）

`RoutedLLMClient.chat(messages, model_tier="flash")` 的 `_call_flash` 路由链：

```
Phase 1: zen（opencode.ai 免费层，deepseek-v4-flash-free）
    - 单次默认超时 45s（httpx.Timeout 客户端级）
    - 重试 llm_max_retries+1 次（默认 2 次重试）
    - 5xx 连续 3 次 → 跳过 zen 60s；连续失败达阈值 → 动态标记 down
    - 全部失败 → 记录动态故障 → 进入 Phase 2
Phase 2: fallback（官方 deepseek-v4-flash）
    - 单次默认超时 30s（Sprint 32.7: 60→30s，加速暴露半死连接）
    - 重试 llm_max_retries+1 次，失败间隔 sleep(2)
    - 冒烟测试标记 False 或动态故障跳过期 → 直接跳过
    - 全部失败 → 记录动态故障 → 进入 Phase 3
Phase 3: pro（deepseek-v4-pro 兜底，Sprint 32.8）
    - 默认超时 120s；冒烟/动态健康检查
    - 这是"长期全自动运行的关键"：中途某 provider 故障不能整题 0 步失败
```

`model_tier` 取值：`flash`（默认三级路由）/ `pro`（先 flash 后 pro）/ `pro_only`（直接 pro）。⚠️ 注意：pro 路由自 Sprint 26 起 **deprecated**（`ENABLE_PRO_FALLBACK` 默认关闭，官方 flash 按难度调 thinking_mode 已可覆盖难题增强诉求，pro 成本高 3-5x 且慢 2x），但作为路由兜底仍保留实现。

### 7.3 动态 provider 健康状态（Sprint 32.8）

冒烟测试标记不再是"终身制"：API 中途故障（限流/挂起）时实时降级，恢复后自动重新尝试。

```python
_PROVIDER_FAIL_THRESHOLD = 2       # 连续失败 2 次判定 provider 故障
_PROVIDER_SKIP_AFTER_FAIL = 120.0  # 故障后跳过期（s）
_PROVIDER_RESET_SECONDS = 60.0     # 60s 无失败则计数清零（视为新的一轮）
```

- `_record_provider_fail(name)`：连续失败达阈值 → 设置 `down_until`（跳过期），同步写入冒烟标记；
- `_record_provider_ok(name)`：任何成功立即恢复健康（清除故障状态）；
- `_provider_healthy(name)`：优先级 = 动态 down_until（中途故障）> 冒烟测试标记 > 默认 True；跳过期已过则清除故障状态允许重新探测；
- `_should_try_zen()`：动态健康 + 旧的连续失败计数（≥5 次跳过 60s）双保险。

**冒烟测试**（Sprint 32.5，冲榜场景）：`smoke_test()` 用 1-token "ping" 探测全部 provider 可用性；`apply_smoke_results()` / `apply_smoke_from_file("data/api_smoke.json")` 在 agent 子进程启动时应用 controller 领题前的探测结果，快速跳过不可用 provider（避免每次调用等 45s×3 超时重试）。

### 7.4 wall-clock 总超时（Sprint 32.9）

httpx 的 read timeout 防不了慢速流（slow-drip streaming）：服务器持续缓慢发 chunk（每次间隔 < read timeout），`ssl.read` 可能无限阻塞。`_call_with_wallclock(fn, timeout=45.0)` 用 daemon 线程 + `join(timeout)` 实现应用层硬总超时：

- daemon 线程：即使底层 socket 永远阻塞，也不阻止进程退出；
- 超时后线程泄漏在后台，但 provider 会被动态标记 down（跳过期内不会反复创建）；
- 三个 provider 的调用（zen/fallback/pro）都包在这个兜底里。

### 7.5 思考模式参数注入（Sprint 26）

`chat()` 内（`enable_thinking_mode=True` 时）：

```python
effort = extra.pop("reasoning_effort", None) or settings.thinking_effort_default
payload["reasoning_effort"] = effort
payload["extra_body"] = {**existing_extra_body, "thinking": {"type": "enabled"}}
```

`reasoning_effort` 支持 high/max（low/medium 被映射为 high，xhigh 映射为 max）；思考模式不支持 temperature/top_p（设置不报错但不生效）。engine 侧按难度/题型选择 effort（见 §3.6）。

### 7.6 LLM 调用三层容错与日志精简

- **引擎层三层容错**（§3.9）：flash → 重试 → pro → 注入提示继续；
- **Coordinator 层容错**：巡查器 LLM 分析失败/输出解析失败一律降级为不干预（`should_intervene=false`），不影响主流程；
- **RAG/知识库容错**：HyDE 生成、Skill 检索、长期记忆查询失败均静默降级；
- **日志精简**：`solve.py` 的 JSONL 协议只输出必要行（start/log/step/heartbeat/submission/coordinator/result），第三方库意外 print 被 `_ProtocolStdout` 包装为 `{"type":"log","level":"RAW"}` 行，保证协议不被污染；heartbeat 每 15s 一行让调用器区分"卡住"与"正在思考"。

### 7.7 路由故障时序示例（动态降级）

以下展示"zen 正常 → zen 中途故障 → 自动恢复"的完整时序（对应 `_call_flash` + 动态健康状态）：

```text
t0    agent 调用 chat()（flash 路由）
t0+1  _should_try_zen() → True（无故障记录，冒烟标记 True/未测）
      zen 调用成功 → _record_provider_ok("zen") → 返回（用时 ~2s）
t5    下一次调用：zen 返回 5xx（限流）
      重试 llm_max_retries 次仍 5xx → _zen_consecutive_failures=1 → 记录动态故障
t5+3  下一次调用：zen 超时（45s wall-clock 触发 TimeoutError）
      → _zen_consecutive_failures=2 → _record_provider_fail("zen") 达阈值
      → zen 进入 120s 跳过期（down_until = now + 120）
t10   后续调用：_should_try_zen() → False（跳过期内）→ 直接走 fallback
      fallback 成功 → 返回（用时 ~3s）——agent 无感知，题目继续
t130  跳过期已过 → 清除故障状态 → 恢复探测 zen
      zen 调用成功 → _record_provider_ok("zen") → 恢复正常路由
```

要点：

- **agent 无感知**：路由降级/恢复对 ReAct 引擎完全透明，解题不中断；
- **多级兜底**：即使 zen/fallback/pro 全部失败，引擎还会注入提示跳过本步继续（§3.9），最终才由熔断器兜底；
- **冒烟测试加速**：冲榜场景下 `api_smoke.json` 可一次性跳过不可用 provider，避免每步 45s×3 等待。

## 8. 熔断机制：六维熔断 + 自适应与动态扩展

### 8.1 六维熔断（CircuitBreaker）

`orchestrator/breaker.py` 实现六维熔断检测，防止 agent 无界消耗时间/token/磁盘：

| 维度 | 阈值（默认） | 触发动作 |
|------|--------------|----------|
| 时间限制 | `max_seconds=1800`（30 分钟） | terminate |
| 步数限制 | `max_steps=35` | terminate（进展感知软截断） |
| 成本限制 | `max_cost_usd=1.5` | terminate |
| 重复动作 | 同一 (action, action_input) > 3 次 | inject_hint（切换策略） |
| 思维死锁 | 连续 5 轮相同 Thought | inject_hint（跳出循环） |
| 文件膨胀 | SSH 工作目录 > 1GB（每 30s 节流检查） | inject_hint（清理临时文件） |

**额外两个检测维度**（Sprint 6/7 补充，实际共八项）：

- **无效步数**（Sprint 6 P1）：同一 action 连续产生高度相似 Observation（字符级 Jaccard 相似度 ≥ 0.85，连续 5 次）→ inject_hint。比"重复动作"更宽松（参数可微变，只要输出类似就视为无效）；
- **单步耗时**（Sprint 7 P1-1）：单步超过 `max_single_step_seconds=120s` → inject_hint（防止 docker build / long-running 命令卡死）。

**成本核算**：`record_llm_call(total_tokens, model)` 每次 LLM 调用后累计，按模型查表定价（`_DEFAULT_PRICING`，含 deepseek-v4-flash/deepseek-chat/deepseek-reasoner/gpt-4o 等），假设 input:output = 3:1 用均价估算；未知模型不计费（避免误熔断）。

**BreakerAction** 三种动作：

```python
@dataclass
class BreakerAction:
    action: str    # "continue" | "inject_hint" | "terminate"
    message: str   # 提示/原因文本
    reason: str
```

### 8.2 进展感知熔断（Sprint 32.4）

时间/步数熔断从"一刀切"改为**进展感知**：

- **背景**：#2501 Blast 复盘——agent 第 47 步方向正确、刚发现关键线索（"MD5 输入是整个后缀"），却在 1200s 被时间熔断误杀；
- **机制**：`check()` 中跟踪"最近一次实质进展"（新的非空 observation，`_last_progress_at`）。超过 `max_seconds` 后，若 `idle > progress_grace_seconds(120s)` 或超过 `hard_max_seconds`（默认 `max_seconds * 3`）才 terminate；有进展则自动延长；
- **步数软截断**：`step_no > max_steps` 后不再立即 terminate，`has_recent_progress()` 返回 True 就继续（由时间熔断 3x 保险兜底），配合协调器 extend_steps 加步；
- **原则**：方向正确、进展正常时绝不误杀；真正的硬兜底由 executor 侧 no_progress 检测（5-10 分钟无输出）承担。

### 8.3 自适应熔断（AdaptiveBreaker）

`orchestrator/adaptive.py` 按题型 + 难度动态决定实际 `max_steps` 与 `max_seconds`：

**步数计算**：`compute_max_steps(type, difficulty)` = `BASE_STEPS(60) × 难度倍率 × 类型倍率`，硬性上限 `HARD_MAX_STEPS=200`。

| 难度 | 倍率 | 步数（基础） |
|------|------|--------------|
| easy | 1.0 | 60 |
| medium | 1.5 | 90 |
| hard | 2.5 | 150 |

| 类型 | 倍率 | 说明 |
|------|------|------|
| pwn | 1.5 | 写 exploit 需更多步 |
| reverse | 1.2 | 逆向需更多分析 |
| crypto | 0.8 | 通常脚本即可 |
| web | 1.0 | 标准 |
| forensics / misc | 1.2 | 二进制解析/嵌套解密链需更多 |

**时间下限**（尊重调用方传入值，难度只做下限兜底，Sprint 32.4 修复"medium 分支恒等 1200s 无视传入 1500s"的 bug）：

- hard：≥ 2700s（45min），其中 pwn/forensics/reverse hard 进一步 ≥ 3000s；
- medium：≥ 1200s（20min）；
- easy/未知：≥ 900s（15min）。

**动态扩展**（Sprint 27）：`extend_steps(additional=20)` 每次 +20 步，最多 2 次（总计可加 40 步），不超 `HARD_MAX_STEPS`。由巡查指导器 `extend_steps=true` 触发（引擎收到后调用 breaker.extend_steps 并同步 `self.max_steps`）。

### 8.4 熔断与巡查的协同

| 场景 | 熔断器 | 巡查指导器 |
|------|--------|------------|
| 重复动作 | 注入"切换策略"提示 | 完全重复 ≥3 次 → L1-A MUST 干预 |
| 思路固化 | 思维死锁提示 | 工具过度使用 → L1-B 软线索 → L2 LLM 判断 |
| 停滞 | 无效步数提示 | 连续错误步 ≥3 → 触发巡查 |
| 步数不足 | 进展感知延长 + 3x 保险 | extend_steps 动态加步 |
| 时间将尽 | 进展感知熔断 | 倒数 20 步强制巡查 |

### 8.5 熔断器统计与报告

`CircuitBreaker.stats()` 输出运行统计（供报告/调试）：

```python
{
    "max_repeated_actions": 3,        # 重复动作阈值
    "max_thought_deadlock": 5,        # 思维死锁阈值
    "max_seconds": 1800.0,            # 时间阈值
    "max_steps": 35,                  # 步数阈值（自适应时为动态值）
    "max_cost_usd": 1.5,              # 成本阈值
    "max_workspace_mb": 1024,         # 文件膨胀阈值
    "action_counts": {"ssh_exec": 4, "http_request": 2},   # 动作频次
    "consecutive_same_thought": 0,    # 当前连续相同 Thought 数
    "hinted_keys": [],                # 已注入过的重复动作提示
    "hinted_deadlock": False,         # 是否已注入死锁提示
    "hinted_workspace": False,        # 是否已注入膨胀提示
    "accumulated_cost_usd": 0.32,     # 累计成本
    "accumulated_tokens": 45678,      # 累计 token
}
```

熔断器与引擎状态在失败报告中的体现：`ReActResult.fail_reason` 会携带熔断维度信息（如 "时间熔断：耗时 1842s 超过阈值 1800s, 且已 140s 无实质进展" / "成本熔断：累计 $1.62 超过阈值 $1.50" / "连续 3 次格式解析失败"），CLI 与 JSONL result 行均可直接展示。

---

## 9. 任务状态机与编排

### 9.1 TaskStatus 状态机

`orchestrator/state.py` 实现简化版任务状态机：

```
INIT ──→ EXECUTING ──→ DONE
                  └──→ FAILED
```

- `TaskState` 枚举：INIT / EXECUTING / DONE / FAILED（DONE 与 FAILED 为终态）；
- `_TRANSITIONS` 表约束合法流转，非法流转抛 `ValueError`；
- `TaskStatus` 记录 state / step_count / start_time / end_time / fail_reason / final_answer；
- 引擎在 `run()` 中调用 `mark_executing()`、`mark_done(answer)`、`mark_failed(reason)`。

### 9.2 编排职责划分

| 组件 | 职责 |
|------|------|
| ReActEngine | 主循环调度（每步：巡查 → 刷新 context → LLM → 解析 → 拦截 → 工具 → 熔断 → 回灌） |
| Coordinator | 方向纠偏（MUST/SHOULD、禁忌、推论分级、自我纠错） |
| CircuitBreaker | 资源熔断（时间/步数/成本/重复/死锁/膨胀/无效步/单步耗时） |
| FailedTrajectoryCache | 失败记忆注入（同题）与演化反思（跨题） |
| SkillLibrary | 解题套路注入（开局 + 做题中每 8 步动态检索） |
| LongTermMemory + RAG | 历史经验检索（开局一次性） |

---

## 10. 入口层：CLI / WebUI / JSONL 子进程协议

### 10.1 CLI 入口（main.py）

`main.py` 提供两个子命令（详见 §14 使用方法）：

- `python main.py run --target <目标> --file <附件> --desc <描述> [--type] [--source] [--difficulty] [--report] [--show-steps] [--no-rag]`
- `python main.py web --host 127.0.0.1 --port 8000`

`run` 流程：校验 LLM 配置与 target/file → 可选 SSH 连接（失败则仅用内置工具）→ SkillLibrary / LongTermMemory 接入（失败静默降级）→ 构造 ReActEngine（注入 on_step 回调打印 Thought/Action/Observation）→ `run_task` → 输出结果摘要 → 成功后 `learn_skill` 积累技能 + `ingest_solution` 沉淀经验 → `--report` 时用 Analyzer 生成完整 Markdown 报告。

### 10.2 独立求解入口（solve.py，对外稳定契约）

**协议版本**：`1.1`（Sprint 26 起版本化）。任何"应用/调用器"（如 NSS Runner）只需以子进程方式运行：

```
python -u -m ctf_agent.solve --task-file <path>
```

**输入 task JSON**：

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
  "max_submissions": 1
}
```

**stdout JSONL 输出**（每行一个对象）：

| type | 字段 | 说明 |
|------|------|------|
| `start` | protocol_version/challenge_id/title/challenge_type/difficulty/max_steps/max_seconds/max_submissions/model | 启动信息 |
| `log` | level/message | 日志（第三方 print 也包装为此） |
| `step` | step_no/thought/action/action_input/observation/is_error/is_final/final_answer/error_msg/timestamp | 每步记录 |
| `heartbeat` | elapsed/step/phase | 心跳（每 15s） |
| `submission` | flag | flag 提交请求（等调用器响应） |
| `coordinator` | step_no/should_intervene/priority/reason/guidance/extend_steps/detected_issues/forbidden_actions/revert_guidance/remove_forbidden/analysis_summary/reflection/belief_state | 巡查日志 |
| `result` | success/flag/final_answer/fail_reason/steps/elapsed/tokens/model | 最终结果 |

**stdin JSONL 输入**（调用器 → agent）：

```json
{"correct": true, "feedback": "..."}    // submission 响应
{"control": "stop"}                      // 停止信号
```

**设计原则**：

1. 不改动 ctf_agent 任何现有源码，仅复用其公开 API；
2. stdout 只输出 JSONL；第三方库的 print 被 `_ProtocolStdout` 包装为 log 行（协议不被污染）；
3. 经验/技能/记忆/自学习全部在 agent 侧完成，全局共享；
4. 无内部超时线程：子进程模型下，调用器负责硬超时 kill；
5. 引擎构造含 SSH 连接，可能挂起（DNS/网络）→ `_build_engine_with_timeout` 150s 超时快速失败（Sprint 21 #2314 复盘修复）；
6. stdin 统一分发器（Sprint 30）：单一线程读取所有 stdin 输入，按消息类型分发到 stop 标志或 submission 响应队列——修复了 stop-listener 与 submission-handler 竞争 stdin（以及 Windows selectors 不能注册 stdin 的 WinError 10038）的问题；
7. submission 队列 60s 超时（调用器崩溃时 agent 不永久挂起）。

**flag 提取**（`_extract_flag`）：按正则优先级匹配 NSSCTF{...} / moectf{...} / flag{...} / CTF{...} / nssctf{...} / athena{...}，最后兜底 `[a-zA-Z_]+{...}` 通用模式（花括号内 ≥4 字符），再兜底整段文本（含 `{` `}` 且 <200 字符）。

### 10.3 WebUI（web/app.py）

FastAPI 应用，提供：

| 端点 | 功能 |
|------|------|
| `GET /api/health` | 健康检查（含 llm_configured / kali_configured） |
| `POST /api/tasks` | 提交任务（target/file/desc/max_steps/enable_ssh/enable_l3），后台线程异步执行 |
| `GET /api/tasks` / `GET /api/tasks/{id}` | 任务列表 / 任务详情（含完整步骤） |
| `POST /api/tasks/{id}/intervene` | **对话纠偏**：注入自然语言指令到运行中的任务 |
| `WS /ws/tasks/{id}` | 实时推送步骤（history + step + final + error） |
| `GET /` | 静态前端首页（static/index.html） |

**干预机制**：`InterventionHub`（线程安全队列）暂存用户指令，`InterventionAwareEngine` 包装 ReActEngine，在 on_step 回调中 drain 指令注入下一步（每步注入到 system_prompt/observation）。任务记录保存在 `TaskManager`（内存版，重启丢失）。

### 10.4 入口对比

| 入口 | 场景 | 结果输出 | 特点 |
|------|------|----------|------|
| `main.py run` | 单题调试/人工分析 | 终端摘要 + 可选 Markdown 报告 | 有 on_step 逐步打印 |
| `main.py web` | 人工可视化 + 对话纠偏 | HTTP + WebSocket | 后台线程，支持干预 |
| `solve.py --task-file` | 批量自动化（NSS Runner 等） | stdout JSONL 协议 | 稳定契约、心跳、多次提交、stop 信号 |

### 10.5 一次完整的 JSONL 协议交互示例

以下是一个典型任务（单次提交模式）的 stdout 交互流（`#` 为注释，实际输出无注释）：

```jsonl
{"type": "start", "protocol_version": "1.1", "challenge_id": "nss_2314", "title": "测试题", "challenge_type": "web", "difficulty": "easy", "max_steps": 60, "max_seconds": 1500.0, "max_submissions": 1, "model": "deepseek-v4-flash"}
{"type": "log", "level": "INFO", "message": "求解启动: nss_2314 type=web difficulty=easy max_steps=60 model=deepseek-v4-flash"}
{"type": "step", "step_no": 1, "thought": "先做信息收集，读取题目附件源码", "action": "ssh_exec", "action_input": "{\"cmd\": \"cat /tmp/nss_arena/2314/app.py\"}", "observation": "from flask import Flask, request\napp = Flask(__name__)\n@app.route('/')\ndef index():\n    return 'hello'", "is_error": false, "is_final": false, "final_answer": "", "error_msg": "", "timestamp": 1754172000.0}
{"type": "step", "step_no": 2, "thought": "发现 /flag 路由直接返回 flag，尝试访问", "action": "http_request", "action_input": "{\"url\": \"http://127.0.0.1:8080/flag\"}", "observation": "NSSCTF{test_flag_123}", "is_error": false, "is_final": false, "final_answer": "", "error_msg": "", "timestamp": 1754172005.0}
{"type": "coordinator", "step_no": 10, "should_intervene": false, "priority": "SHOULD", "reason": "方向正确, 继续推进", "guidance": "", "extend_steps": false, "detected_issues": [], "forbidden_actions": [], "revert_guidance": false, "remove_forbidden": [], "analysis_summary": "L2 LLM 分析: 方向正确", "reflection": "推论均为 FACT: 源码确认 /flag 路由, step2 已观测到 flag 文本", "belief_state": [{"id": "B1", "statement": "入口存在且可用", "level": "FACT", "evidence": "step2 HTTP 返回 flag", "action": "keep"}]}
{"type": "heartbeat", "elapsed": 30.0, "step": 2, "phase": "http_request"}
{"type": "step", "step_no": 3, "thought": "已从工具观测到 flag 文本，直接提交", "action": "", "action_input": "", "observation": "", "is_error": false, "is_final": true, "final_answer": "NSSCTF{test_flag_123}", "error_msg": "", "timestamp": 1754172010.0}
{"type": "log", "level": "RESULT", "message": "求解完成: success=true, steps=3, elapsed=12s, tokens=4567, flag=找到"}
{"type": "result", "success": true, "flag": "NSSCTF{test_flag_123}", "final_answer": "NSSCTF{test_flag_123}", "fail_reason": "", "steps": 3, "elapsed": 12.0, "tokens": 4567, "model": "deepseek-v4-flash"}
```

多次提交模式（`max_submissions>1`）下，agent 找到候选 flag 后流程变为：

```jsonl
{"type": "step", "step_no": 15, "thought": "候选答案", "action": "", "action_input": "", "observation": "", "is_error": false, "is_final": true, "final_answer": "flag{wrong_guess}", "error_msg": "", "timestamp": 1754173000.0}
{"type": "submission", "flag": "flag{wrong_guess}"}
# ← 调用器此刻向 stdin 写入: {"correct": false, "feedback": "答案错误"}
{"type": "step", "step_no": 16, "thought": "提交被驳回，反馈提示答案错误。重新检查工具输出……", "action": "ssh_python", "action_input": "{\"code\": \"...\"}", "observation": "...", "is_error": false, "is_final": false, "final_answer": "", "error_msg": "", "timestamp": 1754173010.0}
{"type": "submission", "flag": "flag{correct_flag}"}
# ← 调用器向 stdin 写入: {"correct": true, "feedback": "回答正确"}
{"type": "result", "success": true, "flag": "flag{correct_flag}", "steps": 18, "elapsed": 95.0, "tokens": 23456, "model": "deepseek-v4-flash"}
```

若调用器中途发送 `{"control": "stop"}`，agent 会在当前步完成后输出：

```jsonl
{"type": "log", "level": "WARN", "message": "收到调用器 stop 信号, agent 将在当前步完成后停止"}
{"type": "result", "success": false, "flag": "", "fail_reason": "收到调用器 stop 信号, 主动停止", "steps": 7, "elapsed": 40.2, "tokens": 12345, "model": "deepseek-v4-flash"}
```

---

## 11. 数据设计

### 11.1 存储总览

| 数据 | 存储位置（默认） | 格式 | 技术 |
|------|------------------|------|------|
| 配置 | `.env`（工作目录） | KEY=VALUE | pydantic-settings |
| 中期记忆 | 内存（`task_facts` 表） | SQLite | sqlite3 |
| 长期记忆（RAG） | `data/chroma/` | 向量库 | ChromaDB PersistentClient |
| 具体 Skill 库 | `data/skills/index.json` + `data/skills/<id>.md` | JSON + Markdown | 文件系统 |
| 失败轨迹 | `data/failed_trajectories/<id>.jsonl` + `_reflections/` | JSONL（append-only） | 文件系统 |
| 冒烟测试标记 | `data/api_smoke.json` | JSON | 文件系统 |
| 靶场状态 | `.range_state.json`（chmod 600 + gitignore） | JSON | 文件系统 |
| 任务记录（WebUI） | 内存 | - | 重启丢失 |

> 注：`config.py` 中有 `sqlite_path`（默认 `./data/ctf.db`）配置项，供中期记忆等场景使用；`settings.chroma_path`（默认 `./data/chroma`）供长期记忆使用。

### 11.2 数据安全设计

- **去标识化红线**：凡进入 LLM 上下文的知识（RAG writeup、Skill 正文）绝不含真实 flag/绝对路径/内存地址（`redact_flags` / `_sanitize_text` 双实现，规则一致）；
- **flag 存储最小化**：明文 flag 只存在于①运行中的靶场容器内部（agent 经漏洞读取属正常途径）②本地受保护状态文件（仅供 verify）；所有面向 LLM/日志的输出 mask()；
- **失败缓存防污染**：仅存前 5 步 + 最后 thought，TTL 7 天，单题 10 条上限；成功后立即清除。

### 11.3 自学习数据流（闭环）

```
解题成功/失败
   ├─ learn_skill() → SkillLibrary.add_or_update（合并去重/脱敏/套路特征）
   ├─ ingest_solution() → LongTermMemory（去标识化 writeup，doc_id 哈希去重）
   └─ 失败 → FailedTrajectoryCache.store() + reflect()
下次同类题
   ├─ RAG 开局检索命中"自己解过的题"
   ├─ Skill 注入（开局 format_for_prompt + 做题中每 8 步 format_for_mid_solve）
   └─ 失败记忆注入（同 challenge_id）
```

---

## 12. 部署与运维

### 12.1 环境要求

| 项 | 要求 |
|----|------|
| Python | ≥ 3.10（pyproject.toml `requires-python`） |
| 操作系统 | Windows / Linux / macOS（宿主） |
| 远程执行 | Kali Linux 沙箱（可选，需 SSH 可达；纯内置模式可无） |
| 网络 | LLM API 可达（opencode.ai / api.deepseek.com） |

### 12.2 依赖

核心依赖（`pyproject.toml`）：

```
openai>=1.40  httpx>=0.27  python-dotenv>=1.0
pydantic>=2.6  pydantic-settings>=2.2  rich>=13.7
```

开发依赖（`[dev]`）：pytest>=8.0 / pytest-asyncio>=0.23 / respx>=0.21。

SSH / RAG / WebUI 依赖按需安装（paramiko、chromadb、fastapi、uvicorn、sentence-transformers 等未列入核心依赖，首次使用时按报错安装）。

### 12.3 日志与监控

- **CLI**：rich 彩色输出（stderr）；
- **子进程协议**：JSONL（start/log/step/heartbeat/coordinator/submission/result），调用器按 type 分发；
- **心跳**：每 15s 输出 `{"type":"heartbeat","elapsed":N,"step":N,"phase":"..."}`，phase 为当前 action 或 "thinking"；
- **日志级别**：`LOG_LEVEL` 环境变量（默认 INFO）。

### 12.4 性能与成本

- **成本熔断**：默认 $1.5/题上限（`MAX_COST_LIMIT`），按 token 查表估算；
- **token 优化**：轨迹摘要（巡查用）、Observation 截断（500 字符入 trajectory）、RAG 只开局检索一次、Skill 注入限长（4000 字符）、HyDE 可跳过（skip_hyde）；
- **步数预算**：BASE_STEPS=60 × 难度/类型倍率，最高 200 步硬上限；协调器可 +20×2 扩展；
- **时间预算**：默认 30 分钟/题（熔断器），进展感知可自动延长至 3x 上限（90 分钟保险）。

### 12.5 常见运维操作

- **查看版本**：`python main.py --version`；
- **清理数据**：删除 `data/chroma/`（清 RAG）、`data/skills/`（清 Skill）、`data/failed_trajectories/`（清失败记忆）、`data/api_smoke.json`（重置冒烟标记）；
- **排查 LLM**：写 `data/api_smoke.json`（`{"zen":false,"flash_fallback":true,"pro":false}`）强制跳过不可用 provider；
- **重跑同题**：失败缓存自动注入失败提示（同 challenge_id 才命中）。

### 12.6 性能指标与已知限制

#### 12.6.1 实测参考（源自各 Sprint 复盘记录）

| 指标 | 参考值 | 来源 |
|------|--------|------|
| 失败题平均耗时 | 约 753s（目标 ≤300s） | Sprint 22 失败题耗时复盘 |
| 单轮任务时间上限 | 默认 1800s；进展感知可延长至 max_seconds×3 | 熔断器配置 |
| easy reverse 题步数 | 3-6 步（strings + binary_analyze + try keys） | 失败缓存类型提示 |
| medium reverse 题步数 | 8-15 步 | 同上 |
| hard reverse 题步数 | 15-30 步 | 同上 |
| 框架漏洞题（ThinkPHP 等） | 有套路库后 5-10 步（此前 120 步失败） | Sprint 23 复盘 |
| SSH 单命令超时 | 60s（exec_cmd 默认） | ssh/client.py |
| LLM 单次调用 wall-clock | 45s 硬总超时 | routed.py |

#### 12.6.2 已知限制

1. **无 swarm/总线/commander**：单 agent 顺序执行，复杂多阶段大作业（如跨多靶机协同）无并行加速；`agent/multi_agent.py` 为遗留代码，不参与实际装配；
2. **OSINT 环境依赖**：web_search 稳定性受 DuckDuckGo 反爬影响、osm_geocode 依赖 Nominatim 公开端点（可能 timeout），失败后回退 LLM 知识（提示词已内置回退策略）；
3. **RAG 首次使用需下载 embedding 模型**：首次初始化 ChromaDB 默认嵌入模型耗时与网络相关；embedding 维度变更可能导致旧库冲突（需要删除旧 `data/chroma/`）；
4. **WebUI 任务记录在内存**：`TaskManager` 重启丢失（注释明确"生产环境可换 Redis/SQLite 持久化"）；
5. **思考模式依赖模型支持**：`reasoning_effort`/`extra_body.thinking` 是 DeepSeek 扩展字段，若切换非 DeepSeek 端点需设置 `ENABLE_THINKING_MODE=false`；
6. **CLI 路径遗留引用**：`main.py` 中对 `ctf_agent.bus.message_bus` 的历史引用在本发布包不存在（§1.5），建议使用 `solve.py` 子进程路径；
7. **本地靶场（range）需要 docker 环境**：range_control 依赖 Kali 侧 docker（本地练习场景），NSS 等竞赛场景默认禁用；
8. **pro 模型 deprecated**：自 Sprint 26 起 pro 路由默认关闭，后续不再维护（保留实现仅供兜底）。

---

## 13. 安全与伦理

### 13.1 反幻觉（防 flag 污染）

见 §3.4：引擎闸门（无工具调用禁止 Final）+ 提示词规则（禁止占位符/猜测/虚构 Observation）+ 收敛策略（连续 20 步无线索重新审视）。核心动机：**错误提交会浪费有限的提交次数**。

### 13.2 SSH 命令审计（ssh/safety.py）

Kali 沙箱执行前审计，三级危险等级：

| 等级 | 处置 | 示例 |
|------|------|------|
| BLOCK（高危，直接拒绝） | 文件系统毁灭（rm -rf /、fork bomb）、磁盘操作（dd 写 /dev、mkfs、fdisk）、系统控制（shutdown/reboot）、网络劫持（iptables -F）、用户管理（userdel root）、Docker 逃逸（--privileged/--pid=host/--net=host）、**靶场安全（docker exec/logs/inspect 进 athena_ 容器）** | `rm -rf /` → 拒绝 |
| REQUIRE_JUDGE（中危，需判决模型二次确认，当前默认放行并提示人工 review） | 网络扫描（nmap --script/内网段）、在线爆破（hydra）、监听端口（nc -l）、全局提权 | `nmap -sP 192.168.x.x` → 放行+提示 |
| WARN（低危，警告但允许） | apt/pip install、下载到 /etc | `apt install xxx` → 警告 |

**工作区白名单**：`ALLOWED_WORKSPACES = (/tmp/ctf_workspace/, /tmp/ctf_real/, /tmp/ctf_real2/, /tmp/ctf_real3/, /tmp/)`，拒绝 `..` 路径逃逸与非白名单目录——避免 agent 误操作宿主环境。

### 13.3 flag 安全模型

- agent 只能通过**漏洞利用**（正常途径）读取 flag；
- 靶场容器：verify 接口只返回 correct/incorrect，绝不返回真 flag；
- 审计层阻断 docker exec/inspect/logs/cp/diff 进靶场容器；
- 知识库（RAG/Skill）写入时强制去标识化。

### 13.4 伦理边界

- 系统面向**授权 CTF 竞赛**（NSSCTF、picoCTF、BSidesSF 等）环境设计，攻击目标限定于比赛提供的靶机；
- 危险命令黑名单、工作区白名单、范围限制（NSS 场景禁用 range_control）构成三重约束，防止滥用；
- 巡检器 MUST 指导与禁忌列表进一步压缩无效攻击面消耗。

## 14. 使用方法

本章从零开始，覆盖环境准备、配置、命令行使用、输出解读与常见问题排查。

### 14.1 环境准备

#### 14.1.1 Python 版本

WING-Falcon 要求 **Python ≥ 3.10**（见 `pyproject.toml` 的 `requires-python`）。建议使用 3.10-3.12 的稳定版本。检查：

```bash
python --version   # 应输出 Python 3.10.x 或更高
```

#### 14.1.2 安装依赖

进入 WING-Falcon 发布目录，安装核心依赖与开发依赖：

```bash
cd _publish/wing/WING-Falcon
pip install -e .[dev]
```

- `pip install -e .` 安装核心依赖（openai / httpx / python-dotenv / pydantic / pydantic-settings / rich）；
- `[dev]` 额外安装测试依赖（pytest / pytest-asyncio / respx）；
- 若不想用 editable 安装，也可直接安装依赖包：`pip install openai httpx python-dotenv pydantic pydantic-settings rich`。

**按需附加依赖**（非核心，首次使用对应功能时报错再装）：

| 功能 | 依赖 |
|------|------|
| Kali SSH 工具 | `pip install paramiko` |
| RAG 长期记忆（ChromaDB） | `pip install chromadb sentence-transformers`（首次启动会下载 embedding 模型） |
| WebUI | `pip install fastapi uvicorn` |

#### 14.1.3 两种运行模式

WING-Falcon 支持两种模式，按题目类型与可用资源选择：

| 模式 | 能力 | 适用场景 |
|------|------|----------|
| **纯内置模式** | L1 内置工具（编解码/HTTP/字符串/哈希/古典密码/exploit 模板/crypto_rsa/编码辅助）+ LLM | 不需要 Kali 的题目（多数 Crypto/Misc 题、纯 HTTP 分析题） |
| **Kali SSH 模式** | 上述 + L2 SSH 工具全集（ssh_exec/ssh_python/ssh_upload + binary_analyze/mem_xor/osint/apk/sage/web/pwn/des/feistel/angr/ecdsa/vision 等） | Pwn/Reverse/Forensics/复杂 Web 题（依赖 Kali 预装工具） |

选择依据：`.env` 中是否配置 `KALI_HOST/KALI_USER` 且 `KALI_PASS` 或 `KALI_KEY_PATH` 非空（`has_kali_config()`）。配置了但连接失败时，CLI 会提示"Kali SSH 连接失败（将仅使用内置工具）"并降级运行，不会崩溃。

### 14.2 .env 配置说明（逐字段）

复制模板并编辑：

```bash
cp .env.example .env
```

`Settings`（`ctf_agent/config.py`）用 pydantic-settings 从 `.env` 加载，**所有字段带默认值，缺失不崩溃**；未知键被 `extra="ignore"` 忽略。以下按分组逐字段说明（标注"实际生效键"），并与 `.env.example` 对照：

#### 14.2.1 LLM 基础配置

| 键 | 默认值 | 说明 |
|----|--------|------|
| `OPENAI_API_KEY` | （空） | 主 API Key。**必填**（`has_llm_config()` 判定依据），缺失时 CLI 报错拒绝启动 |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | OpenAI 兼容端点，可指向 DeepSeek 等 |
| `PLANNER_MODEL` | `gpt-4o` | Planner 模型名（本版本实际路由未使用 planner 拆解，保留兼容） |
| `EXECUTOR_MODEL` | `deepseek-chat` | 执行模型名（引擎默认模型） |

#### 14.2.2 LLM 三级路由（zen → fallback → pro）

> ⚠️ **配置口径提醒**：`.env.example` 顶部的注释描述了"zen(免费 flash-free) → go(付费 flash) → 官方 flash"三级；但 `config.py` 的 `Settings` 中**实际生效**的路由键是 `ZEN_*`（免费层）与 `FALLBACK_*`（官方兜底层），`.env.example` 中出现的 `DISABLE_ZEN` / `GO_API_KEY` / `GO_BASE_URL` / `GO_MODEL` **没有对应的 Settings 字段**，写入后会被 `extra="ignore"` 忽略（不影响启动，但也不会生效）。请按下表使用实际生效的键。

| 键 | 默认值 | 说明 |
|----|--------|------|
| `ZEN_API_KEY` | （空） | zen 免费层 API Key（opencode.ai）。留空则跳过 zen，直接走 fallback |
| `ZEN_BASE_URL` | `https://opencode.ai/zen/v1` | zen 端点 |
| `ZEN_MODEL` | `deepseek-v4-flash-free` | zen 模型（免费） |
| `FALLBACK_API_KEY` | （空） | 官方兜底层 API Key（如 DeepSeek 官方） |
| `FALLBACK_BASE_URL` | `https://api.deepseek.com/v1` | 官方兜底端点 |
| `FALLBACK_MODEL` | `deepseek-v4-flash` | 官方兜底模型 |
| `LLM_MAX_RETRIES` | `2` | zen/fallback 每层失败重试次数（实际尝试 N+1 次） |
| `PRO_API_KEY` | （空） | pro 层 API Key（Sprint 26 deprecated，可选） |
| `PRO_BASE_URL` | `https://api.deepseek.com/v1` | pro 端点 |
| `PRO_MODEL` | `deepseek-v4-pro` | pro 模型 |
| `ENABLE_PRO_FALLBACK` | `false` | 是否启用 pro 回退（默认关闭，仅显式开启才生效） |
| `PRO_FALLBACK_STEP_RATIO` | `0.7` | flash 阶段"不足以完成"的步数比例阈值（deprecated） |
| `PRO_MAX_STEPS` | `40` | pro 模型最大重试步数（deprecated） |

**路由行为**：默认 `model_tier="flash"` 时按 `zen → fallback → pro` 三级降级；`solve.py` 的引擎容错路径在 flash 全失败后还会以 `model_tier="pro"` 再试一次（§3.9）。zen 免费层不可用时建议将 `ZEN_API_KEY` 留空，直接使用官方 flash（免费层故障会带来每次 45s×3 的等待开销）。

#### 14.2.3 思考模式（thinking mode）

| 键 | 默认值 | 说明 |
|----|--------|------|
| `ENABLE_THINKING_MODE` | `true` | 是否启用思考模式（true 时传 `reasoning_effort` + `extra_body.thinking`；false 走模型默认行为） |
| `THINKING_EFFORT_EASY` | `high` | easy 题 effort |
| `THINKING_EFFORT_MEDIUM` | `high` | medium 题 effort |
| `THINKING_EFFORT_HARD` | `max` | hard 题 effort |
| `THINKING_EFFORT_EXTREME` | `max` | extreme 题 effort |
| `THINKING_EFFORT_DEFAULT` | `high` | 未知难度时的默认 effort |

注意：思考模式不支持 low/medium（会被映射为 high）；不支持 temperature/top_p（设置不报错但不生效）。

#### 14.2.4 Kali SSH 配置

| 键 | 默认值 | 说明 |
|----|--------|------|
| `KALI_HOST` | （空） | Kali 沙箱 IP/域名。留空 = 纯内置模式 |
| `KALI_PORT` | `22` | SSH 端口 |
| `KALI_USER` | `root` | 登录用户 |
| `KALI_PASS` | （空） | 密码（与 Key 二选一，Key 优先） |
| `KALI_KEY_PATH` | （空） | SSH 私钥路径（优先于密码） |

**Kali 沙箱预装建议**（启用对应工具集需要）：gobuster/sqlmap/whatweb（web）、pwntools/ROPgadget/checksec（pwn）、jadx+apktool（APK）、fpylll 或 sagemath（sage）、tesseract（OCR）、Ghidra/radare2（MCP L3，默认关闭）。

#### 14.2.5 熔断阈值

| 键 | 默认值 | 说明 |
|----|--------|------|
| `MAX_STEPS` | `80`（Settings 默认）/ `.env.example` 给出 `35` | 引擎步数上限（CLI 路径使用；`solve.py` 路径由 AdaptiveBreaker 按题型/难度计算，0=自适应） |
| `MAX_TASK_TIME` | `1800` | 单任务熔断时间（秒） |
| `MAX_COST_LIMIT` | `1.5` | 单任务成本上限（USD） |

> `solve.py` 路径中 `task JSON` 的 `max_steps: 0` 表示由 `AdaptiveBreaker` 动态计算（BASE_STEPS 60 × 难度/类型倍率，最高 200）；`max_seconds` 由调用器传入，熔断器只做难度下限兜底（§8.3）。

#### 14.2.6 数据库路径

| 键 | 默认值 | 说明 |
|----|--------|------|
| `SQLITE_PATH` | `./data/ctf.db` | SQLite 路径（中期记忆等场景） |
| `CHROMA_PATH` | `./data/chroma` | ChromaDB 向量库路径（RAG 长期记忆） |

#### 14.2.7 日志

| 键 | 默认值 | 说明 |
|----|--------|------|
| `LOG_LEVEL` | `INFO` | 日志级别 |

### 14.3 命令行使用

#### 14.3.1 查看版本与帮助

```bash
python main.py --version    # ctf-agent <版本>
python main.py --help       # 显示 run / web 子命令帮助
```

#### 14.3.2 运行一道题（run 子命令）

**最小用法**（至少提供 `--target` 或 `--file` 之一）：

```bash
# Web 题：只给目标 URL + 描述
python main.py run --target http://ctf.example/ --desc "PicoCTF GET aHEAD"

# 附件题：只给附件路径
python main.py run --file ./challenge.zip --desc "解开压缩包获得 flag"

# 完整参数：元数据 + 逐步输出 + 报告
python main.py run \
  --target http://ctf.example:8080/ \
  --file ./source.zip \
  --desc "ThinkPHP 模板注入" \
  --type web \
  --source picoCTF \
  --difficulty 5 \
  --show-steps \
  --report ./reports/task1.md
```

**run 子命令参数全表**：

| 参数 | 说明 |
|------|------|
| `--target` | 目标 IP/域名/URL（可选，与 --file 至少其一） |
| `--file` | 题目附件路径（可选） |
| `--desc` | 题目描述文本（可选） |
| `--type` | 题型元数据（web/pwn/crypto/misc/recon 等，用于报告与入库、巡查方向检查、thinking effort 选择） |
| `--source` | 题目来源元数据（如 picoCTF，用于报告与入库） |
| `--difficulty` | 难度元数据（0-10 整数；也可传 easy/medium/hard 字符串给引擎，用于 thinking effort） |
| `--show-steps` | 输出每步详细 Thought/Action/Observation（调试用） |
| `--report PATH` | 任务结束后将 Markdown 报告写入指定文件（含时间线与改进建议） |
| `--no-rag` | 关闭 RAG 经验检索（默认开启） |

**运行行为**：

- 启动时打印目标/附件/描述/模型/最大步数；
- 若配置了 Kali 且连接成功，打印"Kali SSH 已连接：root@host"；
- 若 RAG 接入成功，打印"RAG 经验库已接入：./data/chroma（docs=N）"；
- 结束后打印 `format_result_summary`（成功/失败 + 步数 + tokens）；
- 成功后自动 `learn_skill`（打印"已积累/更新技能：<id> (vN)"）与 `ingest_solution`（打印"已沉淀解题经验到知识库：<doc_id>"）；
- `--report` 生成完整报告（概述表/时间线/详细步骤/统计分析/改进建议）；
- 退出码：0 = 成功，1 = 失败/配置错误。

#### 14.3.3 启动 WebUI（web 子命令）

```bash
python main.py web --host 127.0.0.1 --port 8000
```

- 启动前检查 LLM 配置：未配置时警告"WebUI 可启动但无法提交任务"；
- 启动后访问 `http://127.0.0.1:8000`，页面提供：任务提交（desc/target/file）、实时步骤日志（WebSocket）、历史任务查看；
- 任务运行中可通过 `POST /api/tasks/{id}/intervene` 注入自然语言纠偏指令（例如"扫描 8080 端口"、"别再用 hashcat 了"），引擎在下一步注入该指令。

#### 14.3.4 子进程方式（solve.py，批量自动化）

适合 NSS Runner 或自定义批量脚本（§10.2 协议细节）：

```bash
# 1. 构造 task JSON（task.json）
# 2. 运行
python -u -m ctf_agent.solve --task-file task.json
# 3. 观察 stdout JSONL：start → log → step → heartbeat → coordinator → result
```

带多次提交的调用器（max_submissions>1）需要在 agent 输出 `{"type":"submission","flag":...}` 后，向 stdin 写入 `{"correct":bool,"feedback":"..."}` 响应。

#### 14.3.5 自定义调用器最小实现（Python）

以下示例演示如何以子进程方式调用 `solve.py` 并解析 JSONL（单次提交模式）：

```python
"""minimal_caller.py — WING-Falcon 最小调用器示例."""
import json
import subprocess
import sys

TASK = {
    "challenge_id": "demo_001",
    "title": "示例题",
    "desc": "目标 http://127.0.0.1:8080/，获取 flag。",
    "type": "web",
    "difficulty": "easy",
    "max_steps": 0,           # 0 = 自适应（AdaptiveBreaker 计算）
    "max_seconds": 1500.0,
    "max_submissions": 1,
}

def main() -> None:
    with open("task.json", "w", encoding="utf-8") as f:
        json.dump(TASK, f, ensure_ascii=False)

    proc = subprocess.Popen(
        [sys.executable, "-u", "-m", "ctf_agent.solve", "--task-file", "task.json"],
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    assert proc.stdout is not None

    for line in proc.stdout:
        obj = json.loads(line)
        t = obj.get("type")
        if t == "start":
            print(f"[启动] challenge={obj['challenge_id']} "
                  f"max_steps={obj['max_steps']} max_seconds={obj['max_seconds']}")
        elif t == "step":
            flag = f" FINAL={obj['final_answer']}" if obj["is_final"] else ""
            err = " [ERROR]" if obj["is_error"] else ""
            print(f"[步骤{obj['step_no']}] {obj['action']}{flag}{err}")
        elif t == "coordinator":
            if obj["should_intervene"]:
                print(f"[巡查@step{obj['step_no']}] {obj['priority']}: {obj['guidance']}")
        elif t == "heartbeat":
            pass  # 心跳行可忽略，或用于超时判定
        elif t == "submission":
            # 多次提交模式下这里应向 stdin 写响应；单次提交不会走到这里
            print(f"[提交] {obj['flag']}")
        elif t == "result":
            print(f"[结果] success={obj['success']} flag={obj['flag']} "
                  f"steps={obj['steps']} elapsed={obj['elapsed']}s tokens={obj['tokens']}")
            print(f"[失败原因] {obj['fail_reason']}" if not obj["success"] else "")
            proc.wait()
            return
    # 进程异常退出（无 result 行）时兜底
    proc.kill()

if __name__ == "__main__":
    main()
```

运行方式（需在 WING-Falcon 目录内、已 `pip install -e .`）：

```bash
python minimal_caller.py
```

要点提示：

1. 必须用 `-u`（unbuffered）启动子进程，保证 JSONL 实时输出；
2. 用 `text=True, encoding="utf-8", bufsize=1` 读取行；
3. 每行 `json.loads` 后按 `type` 分发；`result` 行即任务结束（也可用 `proc.wait()` + 退出码判断）；
4. 心跳行可用于"无输出超时"判定（如 5-10 分钟无任何行 → 认为假死，kill 子进程）；
5. 多次提交模式（`max_submissions>1`）：收到 `submission` 行后向 `proc.stdin` 写 `{"correct": bool, "feedback": "..."}`；
6. 需要强制停止时向 stdin 写 `{"control": "stop"}`，agent 会在当前步完成后输出 result 退出。

### 14.4 解题输出解读

#### 14.4.1 结果摘要（CLI）

```text
成功 Flag: flag{...}
步数: 12 | Tokens: 45678
```

或失败：

```text
失败 原因: 达到最大步数 80 (无实质进展自动停止)
步数: 80 | Tokens: 123456
```

#### 14.4.2 解题轨迹（step JSONL / --show-steps）

每步包含：`step_no`（步号）、`thought`（推理）、`action`（工具名）、`action_input`（JSON 参数）、`observation`（工具输出，入 trajectory 时截断 500 字符）、`is_error`、`is_final`、`final_answer`、`timestamp`。

解读要点：

- **开头 1-3 步**应为信息收集（strings/file_type/http_request/web_recon/ssh_exec 等）——若第 1 步直接 Final Answer，会被反幻觉机制拒绝；
- **`is_error=true`** 表示工具调用失败（JSON 解析失败/命令报错），观察 `error_msg` 判断是参数问题还是环境问题；
- **`is_final=true`** 且 `final_answer` 含 `xxx{...}` 即 flag 候选；
- **`coordinator` 行**展示巡查行为：`priority=MUST` 表示强制纠偏，`forbidden_actions` 为禁忌列表，`belief_state` 为推论分级清单（FACT/LIKELY/POSSIBLE/DISPROVED），`reflection` 为巡查器反思。

#### 14.4.3 完整 Markdown 报告（--report）

`Analyzer.generate_full_report` 生成，结构：

| 章节 | 内容 |
|------|------|
| 概述 | 任务/状态/Flag/总步数/Token/耗时 + 元数据（type/source/difficulty） |
| 时间线 | 每步相对时间（+N.Ns）/ Action / 状态（成功/错误/完成） |
| 详细步骤 | 每步 Thought / Action / Action Input / Observation（截断 500 字符）/ Final Answer / 错误 |
| 统计分析 | 工具使用频次排序、错误次数、平均每步 Token |
| 改进建议 | 成功/失败原因分析、错误工具提示、重复动作检测 |

#### 14.4.4 flag 提取规则

`_extract_flag`（solve.py）按优先级提取：`NSSCTF{...}` / `moectf{...}` / `flag{...}` / `CTF{...}` / `nssctf{...}` / `athena{...}` → 通用 `xxx{...}`（花括号内 ≥4 字符）→ 整段文本兜底。result 行的 `flag` 字段为提取结果，`final_answer` 为完整回答。

### 14.5 常见问题排查

#### 14.5.1 LLM 不可用与降级

| 现象 | 原因 | 处理 |
|------|------|------|
| 启动即报"OPENAI_API_KEY 未配置" | 未设置主 Key | 配置 `OPENAI_API_KEY`（路由链的兜底/官方层至少留一个可用 Key） |
| 每步等待 45s×3 后仍失败 | zen 免费层挂起 | 将 `ZEN_API_KEY` 留空直连官方；或写 `data/api_smoke.json`：`{"zen":false,"flash_fallback":true,"pro":false}` |
| 整题 0 步失败，result 行 fail_reason 含 `llm not configured` | `has_llm_config()` 为假 | 检查 `.env` 位置（必须在工作目录）与 `OPENAI_API_KEY` 是否非空 |
| 中途 provider 故障但任务继续 | 引擎三层容错 + 动态健康状态 | 正常行为：flash→重试→pro→注入提示继续，最终由熔断兜底 |
| 慢速流导致长时间无输出 | wall-clock 超时未触发前的半死连接 | 45s 后自动放弃该请求并标记 provider down；配合 heartbeat 判断"假死" |

#### 14.5.2 SSH 连接失败

| 现象 | 原因 | 处理 |
|------|------|------|
| "Kali SSH 连接失败（将仅使用内置工具）" | 网络不可达/认证失败/超时 | 检查 `KALI_HOST/PORT/USER`；密码与 Key 二选一（Key 优先）；`ssh_client_from_settings` 要求 host+user+(pass 或 key_path) 三者齐全 |
| solve.py 引擎构造 150s 超时 | SSH 连接挂起（DNS/网络） | `_build_engine_with_timeout` 会快速失败输出 result；检查 Kali 可达性 |
| 命令执行卡死 | paramiko 的 `recv_exit_status` 无法被 timeout 中断 | 内部已用线程 + join 实现真超时，超时后关闭 channel 强制中断；若仍复现，缩短命令或加 shell timeout |

#### 14.5.3 RAG 空库 / 检索无结果

| 现象 | 原因 | 处理 |
|------|------|------|
| "RAG 经验库已接入（docs=0）" | `data/chroma/` 为空库（首次使用） | 正常现象；首次会下载默认 embedding 模型，之后随解题成功自动增长（`ingest_solution`） |
| "RAG 经验库接入失败" | chromadb/sentence-transformers 未安装或维度冲突 | `pip install chromadb`；删掉旧 `data/chroma/`（曾出现 256 vs 384 维冲突崩溃） |
| 检索命中旧经验误导 | 库中 writeup 可能过时 | 用 `--no-rag` 关闭；或删除 `data/chroma/` 重置 |

#### 14.5.4 其他高频问题

| 现象 | 原因 | 处理 |
|------|------|------|
| 每步都报"未知工具 'xxx'" | LLM 编造了工具名 | 正常容错路径；观察可用工具列表，检查 prompt 中 tool schema 是否被截断 |
| 反复格式错误熔断失败 | LLM 输出不合规 | 检查 `max_format_errors`（默认 3）；思考模式或模型版本差异可能导致格式漂移 |
| 题目明明简单却跑很久 | 步数预算大（hard 150 步）+ 进展感知延长 | 用 `--type`/`--difficulty` 收紧；收敛策略要求 20 步无线索即重新审视 |
| 提交答案被驳回后死循环 | 多次提交模式下 agent 反复猜 | 引擎已做去重 + 上限保护（达上限后不再提交，引导继续分析）；调用器可发 `{"control":"stop"}` 强制停止 |
| main.py 报 `bus.message_bus` 导入错误 | 发布包遗留引用（§1.5） | 改用 `python -m ctf_agent.solve --task-file` 子进程方式（本版本推荐路径），或从 main.py 删除该行 |

---

## 15. 附录

### 15.1 术语表

| 术语 | 含义 |
|------|------|
| ReAct | Reasoning + Acting，推理与行动交替的 agent 范式 |
| Thought / Action / Observation | ReAct 循环的三要素：推理 / 工具调用 / 结果 |
| Coordinator（巡查指导器） | 以旁观者视角审视完整轨迹的 LLM 指导模块 |
| MUST / SHOULD | 巡查指导的强制 / 建议优先级 |
| FACT / LIKELY / POSSIBLE / DISPROVED | 推论分级：事实 / 高可能性 / 低可能性 / 已证否 |
| forbidden_actions（禁忌列表） | 已确认无效、agent 再尝试即被拦截的操作集合 |
| belief_state | 跨巡查持久化的推论清单 |
| CircuitBreaker（熔断器） | 六维资源熔断 + 进展感知 + 自适应 |
| AdaptiveBreaker | 按题型/难度调整步数与时间的熔断器，支持 +20×2 扩展 |
| extend_steps | 巡查指导器建议、熔断器执行的动态加步机制 |
| RoutedLLMClient | 三级路由（zen→fallback→pro）+ 动态健康状态的 LLM 客户端 |
| 冒烟测试（smoke test） | 启动前用 1-token ping 探测 provider 可用性 |
| wall-clock 超时 | 应用层硬总超时（daemon 线程 + join），防慢速流半死连接 |
| thinking mode | 思考模式：先输出思维链再输出回答，`reasoning_effort` 分级 |
| HyDE | Hypothetical Document Embeddings，先让 LLM 生成假设文档再检索 |
| ShortTermMemory | 短期记忆：滑动窗口保留最近 N 轮交互 |
| MidTermMemory | 中期记忆：SQLite 存储关键事实（防丢） |
| LongTermMemory | 长期记忆：ChromaDB 向量库（writeup 语义检索） |
| SkillLibrary | 具体 Skill 库（data/skills），自学习积累、合并去重、淘汰 |
| pattern_features | Skill 的套路特征（跨题匹配用技术关键词） |
| FailedTrajectoryCache | 失败轨迹缓存（同题失败记忆 + 演化反思） |
| ingest_solution | 成功解题去标识化写入长期记忆 |
| learn_skill | 从一次解题提炼可复用 Skill |
| range_control | 本地靶场控制工具（list/start/stop/status/verify） |
| JSONL 协议 | solve.py 与调用器之间的换行分隔 JSON 协议（v1.1） |
| heartbeat | 每 15s 的心跳行，区分"卡住"与"正在思考" |
| 反幻觉 | 强制 flag 来自工具观测、禁止编造/猜测的规则体系 |
| 去标识化（脱敏） | 将 flag/绝对路径/内存地址替换为占位符后再入库 |

### 15.2 Sprint 演进一览

| Sprint 范围 | 主题 | 代表能力 |
|-------------|------|----------|
| Sprint 1-5 | 基础框架 | ReAct 引擎、L1 工具、SSH 接入 |
| Sprint 6-10 | 工具增强 + 失败记忆 | 空 observation 兜底、mem_xor、失败轨迹缓存 + 演化反思、cross-challenge 知识共享 |
| Sprint 11-12 | 题型扩展 | OSINT、APK、Sage、OCR、逆向搜索、地理编码 |
| Sprint 13-16 | 深度能力 + 方法论 | ECDSA、angr、DES、Feistel、Web/Pwn 工具集、自主解题方法论、Skill 系统 |
| Sprint 17-20 | 智能化 | LLM 路由（zen→fallback）、思考模式、自适应熔断、输出解析容错 |
| Sprint 21-23 | 实战强化 | 无回显/盲注规则、共享靶机 flag 定位、框架漏洞库、LFI/编码辅助 |
| Sprint 24-25 | 视觉与复盘 | magic bytes 修复、OCR 最佳实践、vision_analyze（MIMO）、密码题识别 |
| Sprint 26 | 提交与思考 | 思考模式、多次提交机制、协议 v1.1、心跳 |
| Sprint 27-29 | 巡查指导器 | Coordinator、动态扩展、两级分析、巡查日志回调 |
| Sprint 30-31 | 巡查强化 | stdin 统一分发器、禁忌列表、动态干预频率、MUST 优先级 |
| Sprint 32.x | 稳定性与纠错 | 进展感知熔断、MUST 持久注入、自我纠错、推论分级、wall-clock、动态健康、LLM 三层容错、软截断 |

### 15.3 配置键速查表（config.py 实际生效）

| 分组 | 键 |
|------|-----|
| LLM 基础 | OPENAI_API_KEY / OPENAI_BASE_URL / PLANNER_MODEL / EXECUTOR_MODEL |
| 路由 | ZEN_API_KEY / ZEN_BASE_URL / ZEN_MODEL / FALLBACK_API_KEY / FALLBACK_BASE_URL / FALLBACK_MODEL / LLM_MAX_RETRIES |
| pro（deprecated） | PRO_API_KEY / PRO_BASE_URL / PRO_MODEL / ENABLE_PRO_FALLBACK / PRO_FALLBACK_STEP_RATIO / PRO_MAX_STEPS |
| 思考模式 | ENABLE_THINKING_MODE / THINKING_EFFORT_EASY / _MEDIUM / _HARD / _EXTREME / _DEFAULT |
| Kali SSH | KALI_HOST / KALI_PORT / KALI_USER / KALI_PASS / KALI_KEY_PATH |
| 熔断 | MAX_STEPS / MAX_TASK_TIME / MAX_COST_LIMIT |
| 数据 | SQLITE_PATH / CHROMA_PATH |
| 日志 | LOG_LEVEL |

### 15.4 参考资料

- `docs/CTF_AGENT_DESIGN.md`：WING-Falcon 早期（Sprint 28）设计文档；
- `docs/CTF_AGENT_GUIDE.md`：完整使用指南（含 NSS Runner 集成示例）；
- `_publish/wing/WING-Falcon/.env.example`：环境变量模板；
- DeepSeek thinking mode 官方文档：`https://api-docs.deepseek.com/zh-cn/guides/thinking_mode`。

### 15.5 核心模块文件索引

| 文件 | 职责 | 关键导出 |
|------|------|----------|
| `ctf_agent/agent/react.py` | ReAct 引擎 | ReActEngine / ReActResult / ReActStep / ParsedAction / parse_llm_output |
| `ctf_agent/agent/coordinator.py` | 巡查指导器 | Coordinator / CoordinatorGuidance |
| `ctf_agent/agent/prompts.py` | 提示词系统 | build_system_prompt / build_task_prompt / AUTONOMOUS_METHODOLOGY / ANTI_HALLUCINATION_RULES / COMMON_RULES |
| `ctf_agent/agent/failed_trajectory_cache.py` | 失败轨迹缓存 | FailedTrajectoryCache / Reflection / get_default_cache |
| `ctf_agent/llm/routed.py` | 三级路由客户端 | RoutedLLMClient |
| `ctf_agent/llm/client.py` | 基础 LLM 客户端 | LLMClient / Message / ChatResult / ChatUsage |
| `ctf_agent/memory/short_term.py` | 短期记忆 | ShortTermMemory |
| `ctf_agent/memory/mid_term.py` | 中期记忆 | MidTermMemory |
| `ctf_agent/memory/long_term.py` | 长期记忆 | LongTermMemory |
| `ctf_agent/memory/rag.py` | HyDE 检索 | RAGRetriever / generate_hyde_document |
| `ctf_agent/memory/skill_library.py` | 具体 Skill 库 | SkillLibrary / Skill |
| `ctf_agent/orchestrator/breaker.py` | 六维熔断器 | CircuitBreaker / BreakerAction |
| `ctf_agent/orchestrator/adaptive.py` | 自适应熔断 | AdaptiveBreaker / compute_max_steps |
| `ctf_agent/orchestrator/state.py` | 任务状态机 | TaskStatus / TaskState |
| `ctf_agent/tools/__init__.py` | 工具装配 | default_tools |
| `ctf_agent/tools/base.py` | 工具基类 | Tool / ToolResult / _robust_json_loads |
| `ctf_agent/ssh/client.py` | SSH 客户端 | SSHClient / CmdResult / ssh_client_from_settings |
| `ctf_agent/ssh/safety.py` | 命令审计 | audit_command / audit_workspace |
| `ctf_agent/config.py` | 配置加载 | Settings / get_settings |
| `ctf_agent/solve.py` | 子进程协议入口 | solve_task / main |
| `ctf_agent/analyzer.py` | 复盘与报告 | Analyzer / generate_full_report |
| `ctf_agent/experience.py` | 经验沉淀 | ingest_solution / redact_flags |
| `ctf_agent/skill_learner.py` | Skill 学习器 | learn_skill |
| `ctf_agent/stop_signal.py` | 停止信号 | request_stop / is_stop_requested / reset |
| `ctf_agent/web/app.py` | WebUI | create_app / run_server / InterventionHub |
| `ctf_agent/cli/runner.py` | CLI 执行 | run_task / build_task_description / format_result_summary |

### 15.6 .env.example 与 config.py 字段差异对照

`.env.example` 是配置模板，`config.py` 的 `Settings` 是实际生效层；两者存在差异，使用时应以 `Settings` 字段（`alias`）为准：

| .env.example 中的键 | Settings 中是否生效 | 说明 |
|---------------------|---------------------|------|
| `OPENAI_API_KEY` / `OPENAI_BASE_URL` / `PLANNER_MODEL` / `EXECUTOR_MODEL` | ✅ 生效 | 基础配置 |
| `ZEN_API_KEY` / `ZEN_BASE_URL` / `ZEN_MODEL` | ✅ 生效 | zen 免费层 |
| `DISABLE_ZEN` | ❌ 无对应字段（extra="ignore" 忽略） | 想跳过 zen 请将 `ZEN_API_KEY` 留空 |
| `GO_API_KEY` / `GO_BASE_URL` / `GO_MODEL` | ❌ 无对应字段（忽略） | 实际兜底键为 `FALLBACK_*` |
| `FALLBACK_API_KEY` / `FALLBACK_BASE_URL` / `FALLBACK_MODEL` | ✅ 生效 | 官方兜底层 |
| `LLM_MAX_RETRIES` | ✅ 生效 | 重试次数 |
| `ENABLE_THINKING_MODE` / `THINKING_EFFORT_*` | ✅ 生效 | 思考模式 |
| `KALI_HOST` / `KALI_PORT` / `KALI_USER` / `KALI_PASS` / `KALI_KEY_PATH` | ✅ 生效 | Kali SSH |
| `MAX_STEPS` / `MAX_TASK_TIME` / `MAX_COST_LIMIT` | ✅ 生效 | 熔断阈值 |
| `SQLITE_PATH` / `CHROMA_PATH` | ✅ 生效 | 数据路径 |
| `LOG_LEVEL` | ✅ 生效 | 日志级别 |
| （模板中未列出）`PRO_API_KEY` / `PRO_BASE_URL` / `PRO_MODEL` / `ENABLE_PRO_FALLBACK` / `PRO_FALLBACK_STEP_RATIO` / `PRO_MAX_STEPS` | ✅ 生效（deprecated） | pro 层，仅显式开启 |

---

*本文档基于 `_publish/wing/WING-Falcon/ctf_agent/` 实际源码审计编写；凡文中描述与源码不一致之处，以源码为准。*



