# WING-Goose 雁阵 — 多 agent 编队

> **定位**：雁阵 — 同题多风格并行编队（WING-Corvus 升级前的生产代码快照，2026-08-04）
> 版本谱系：WING-Falcon（猎隼）→ **WING-Goose（雁阵）** → WING-Corvus（渡鸦）

## 核心能力

在 WING-Falcon（单 agent 基线）之上新增：

- **同题多风格并行 swarm**：conservative（保守）/ aggressive（激进）/ innovative（创新）三路解题器并行求解同一题，一解出即杀其余（easy 单路 / medium、hard 三路并行）
- **消息总线**：MessageBus（进程内）+ FileBus（跨进程文件总线），兄弟发现每 5 步 check 注入，强制分享关键发现 + 强制回答提问
- **三风格差异化**（agent/styles.py）：保守稳步注意细节 / 激进快速忽略细节 / 创新发散探索，风格化巡查节奏
- **独立 LLM 轨迹复盘**（review.py）：无幻觉核对 + skill 入库，swarm 多轨迹合并复盘
- **docker 执行链**（tools/docker_tool.py）：docker → ssh 降级，内置工具构建进镜像，资源调控 Profile
- **事件总线**（events.py）：in-process pub/sub，engine 生命周期事件
- **巡查指导器异步事件驱动**：后台线程分析不阻塞 agent 行动，完成经事件召回注入

## 目录结构

```
WING-Goose/
├── ctf_agent/            # 核心解题引擎
│   ├── agent/            # ReAct + 三风格 + 巡查指导器
│   ├── bus/              # 消息总线（跨进程共享发现）
│   ├── tools/            # 内置工具 + docker 执行链 + 总线工具
│   ├── memory/           # 三层记忆 + Skill 库
│   ├── llm/              # 三级路由（zen→go→官方）
│   ├── swarm.py          # 同题多风格并行编排
│   ├── review.py         # 轨迹复盘
│   └── events.py         # 事件总线
├── data/                 # 白板数据库（空库，下载即用）
├── main.py / pyproject.toml / .env.example
├── README.md
└── WING_GOOSE_DESIGN.md # 1500+ 行完整设计+使用文档
```

## 快速开始

```bash
# 1. 安装依赖
pip install -e .

# 2. 配置环境（含 LLM API Key；swarm/docker 相关字段见文档）
cp .env.example .env

# 3. 运行（默认 SWARM_ENABLED=true 走三风格并行）
python main.py run --target http://target/ --desc "题目描述" --type web --report report.md

# 4. docker 执行链（可选）：构建镜像后 DOCKER_ENABLED=true 生效
docker build -f scripts/docker_test/Dockerfile.wing-goose -t wing-goose:v2 .
```

详细说明见 **[WING_GOOSE_DESIGN.md](./WING_GOOSE_DESIGN.md) 使用方法章节**（含 .env 逐字段、swarm 启用、docker 链配置、14 项常见问题排查）。

## 三个版本对比

| 版本 | 定位 | 关键差异 |
|------|------|----------|
| [WING-Falcon](./WING-Falcon) | 精英单兵 | 单 agent 解题引擎基线 |
| [WING-Goose](./WING-Goose) | 雁阵 | 同题三风格并行 + 消息总线 + 轨迹复盘 + docker 链 |
| [WING-Corvus](./WING-Corvus) | 渡鸦 | 三层协作小队（总指挥+战略层+战术层）+ 多阶段协调 |

## 声明

- 仅供**授权的 CTF 竞赛环境或自有靶机**使用
- 隐私/日志/积累技能不在此公开仓库中（见私有库 WING-data）
