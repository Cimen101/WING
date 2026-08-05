> 🚧 WARNING: AI‑Generated Shit‑Mountain Project | For fun only, NOT for learning / production

<img src="./logo.png" alt="True-CTF-Agent" width="50%" />

## 🎉 恭喜你，发现了 AI 屎山！
本项目代码完全由 DeepSeek‑V4 系列模型生成，开发模式为增量叠加 + 补丁式修补。
开发准则：**优先打补丁，尽量避免重构，能凑合用就绝不重构**。

### ✅ 可以玩、可以跑（效果貌似还可以？）
### ❌ 禁止用来学习、禁止生产复用
架构看着高级，但内部代码可能存在大量AI生成遗留问题。（PS：至少能跑）

⚠️ **请勿将本项目作为学习范例、生产参考**

### 想要学习规范、高质量的 CTF‑Agent 实现，推荐参考：[verialabs/ctf‑agent](https://github.com/verialabs/ctf-agent)，本项目在设计层面借鉴了该仓库。

### 项目维护说明

1. 作者只负责当初的设计与实现；
2. **偶尔维护，处理 Issue 随缘、不提供技术咨询**；
3. 版本更新随缘，无固定迭代计划，不保证BUG修复。

# WING — CTF 自动化解题智能体系统（三版本）

> WING 系列：基于 LLM 的自动化 CTF（Capture The Flag）解题智能体系统，模拟人类选手独立/合作解题，覆盖 Web / Pwn / Reverse / Crypto / Misc 五大题型。

本仓库是 WING 系列CTF解题Agent**三个版本**的公开核心代码库，每个版本独立可用（含各自的设计与使用文档）。

## 版本谱系

```
WING-Falcon（猎隼）── 精英单兵（单 agent 解题引擎基线）
        │
        ▼ 新增：三风格并行 swarm、消息总线、轨迹复盘、docker 执行链
WING-Goose（雁阵）── 多 agent 编队（同题多风格并行协作）
        │
        ▼ 新增：总指挥三层协作、多阶段协调（P1-P4）、flag 验证系统
WING-Corvus（渡鸦）── 协作小队（总指挥 + 战略层 + 战术层，当前最新版）
```

## 三版本核心差异

| 维度          | WING-Falcon 猎隼       | WING-Goose 雁阵                   | WING-Corvus 渡鸦                 |
| ----------- | -------------------- | ------------------------------- | ------------------------------ |
| **定位**      | 精英单兵                 | 多 agent 编队                      | 协作小队（当前最新）                     |
| **解题器数量**   | 单 agent              | 同题 3 风格并行（保守/激进/创新）             | 同题 3 风格并行 + 总指挥 + 3 战略层        |
| **协作机制**    | 无（单兵）                | 消息总线共享发现（每 5 步 check/强制分享/强制回答） | 总线协议 + 总指挥领题分工 / 汇报 / 方向指令     |
| **调度机制**    | 单引擎直接跑               | swarm 一解出即杀其余                   | 多阶段协调 P1→P2→P3→P4（任务驱动+进度汇报驱动） |
| **执行层**     | SSH-Kali             | SSH-Kali / docker→ssh 降级链       | SSH-Kali / docker→ssh 降级链      |
| **记忆层**     | 三层记忆 + RAG + Skill 库 | 三层记忆 + RAG + Skill 库            | 三层记忆 + RAG + Skill 库           |
| **巡查指导器**   | 有（推论分级 + MUST）       | 有（风格化 + 异步事件驱动 + 禁忌列表）          | 有（+ 战略层汇报协议 + 阶段感知）            |
| **flag 验证** | 反幻觉双闸门               | 反幻觉双闸门                          | + Flag 验证系统（代码机制 + LLM 轨迹审查）   |
| **轨迹复盘**    | 无                    | 独立 LLM 复盘 + 无幻觉核对               | 独立 LLM 复盘 + 无幻觉核对              |
| **适合场景**    | 快速单题、调试              | 中等/hard 题并行冲榜                   | 复杂题多阶段协作、需要全局方向把控              |

## 目录结构

```
WING/
├── README.md              # 本文件（三版本差异介绍）
├── WING-Falcon/           # 精英单兵
│   ├── ctf_agent/         # 核心引擎（ReAct + 巡查 + 三层记忆 + 工具链）
│   ├── data/              # 白板数据库（空库，下载即用）
│   ├── main.py / pyproject.toml / .env.example
│   ├── README.md
│   └── WING_FALCON_DESIGN.md   # 2000+ 行设计 + 使用方法
├── WING-Goose/            # 多 agent 编队
│   ├── ctf_agent/         # 核心引擎（+ swarm + bus + review + docker 链）
│   ├── data/              # 白板数据库（空库）
│   ├── main.py / pyproject.toml / .env.example
│   ├── README.md
│   └── WING_GOOSE_DESIGN.md    # 1500+ 行设计 + 使用方法（含相对 Falcon 的更新审计）
└── WING-Corvus/           # 协作小队（最新）
    ├── ctf_agent/         # 核心引擎（+ commander 总指挥 + flag 验证 + 多阶段协调）
    ├── data/              # 白板数据库（空库）
    ├── main.py / pyproject.toml / .env.example
    ├── README.md
    └── WING_CORVUS_DESIGN.md   # 2000+ 行设计 + 使用方法（含相对 Goose 的更新审计）
```

## 快速开始

```bash
# 选择一个版本，进入对应目录
cd WING-Corvus          # 或 WING-Goose / WING-Falcon

# 1. 安装依赖（Python >= 3.10）
pip install -e .

# 2. 配置环境（每个版本自带 .env.example，逐字段说明见对应 DESIGN 文档）
cp .env.example .env
# 编辑 .env：填入 OPENAI_API_KEY / ZEN_API_KEY 等 LLM 配置

# 3. 运行
python main.py run --target http://target/ --desc "题目描述" --type web --report report.md

# 4. WebUI
python main.py web --port 8000
```

> 每个版本的 `data/` 已内置**空白数据库骨架**（chroma 空库 + skills 空 index.json），下载即可运行；解题过程中会自动积累技能与经验（存入本地 data/，不进 git）。

## 设计文档

每个版本自带一份 **1500+ 行完整设计与使用文档**（格式参考技术设计文档，末尾含使用方法章节）：

| 版本          | 文档                                                             | 内容                                                   |
| ----------- | -------------------------------------------------------------- | ---------------------------------------------------- |
| WING-Falcon | [WING\_FALCON\_DESIGN.md](./WING-Falcon/WING_FALCON_DESIGN.md) | 架构/ReAct/巡查/记忆/工具/路由/熔断 + 使用方法                       |
| WING-Goose  | [WING\_GOOSE\_DESIGN.md](./WING-Goose/WING_GOOSE_DESIGN.md)    | 架构/swarm/总线/复盘/docker 链 + **相对 Falcon 的更新审计** + 使用方法 |
| WING-Corvus | [WING\_CORVUS\_DESIGN.md](./WING-Corvus/WING_CORVUS_DESIGN.md) | 架构/总指挥/战略层/多阶段协调/flag 验证 + **相对 Goose 的更新审计** + 使用方法 |

## 隐私与数据

- 本仓库为**公开仓库**，仅包含三个版本的核心代码与文档，**不含**任何积累技能、题目数据、运行日志、API 密钥等隐私内容
- 隐私内容（技能库、报告、日志、任务数据、配置文件等）备份在私有仓库 [WING-data](https://github.com/Cimen101/WING-data)（私有，仅授权访问）
- 各版本 `data/` 为白板空库，解题积累的数据仅保存在本地

## 声明

1. **仅供授权的 CTF 竞赛环境或自有靶机使用**，禁止对未授权目标进行扫描或攻击
2. 所有流量与载荷仅在本地沙箱内闭环，不上传至云端（除 LLM API 请求外）
3. 若发现智能体可突破沙箱访问宿主机文件，视为最高优先级安全漏洞

## License

MIT
