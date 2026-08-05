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
└── WING_GOOSE_DESIGN.md # 2000+ 行完整设计+使用文档
```

## 快速开始

本版本提供**两种运行模式**：

| 模式 | 入口 | 说明 |
| :-- | :-- | :-- |
| 单 agent 快速模式 | `python main.py run ...` | 单题快速验证/调试，**不启动** swarm |
| swarm 并行模式 | `.env` 开 `SWARM_ENABLED` + 调 `SwarmCoordinator` | 同题三风格并行（一解出即杀其余） |

### 单 agent 快速模式

```bash
# 1. 安装依赖
pip install -e ".[docker]"      # 推荐（含 docker-py）；纯内置工具可 pip install -e .

# 2. 配置环境（至少填入 OPENAI_API_KEY / OPENAI_BASE_URL）
cp .env.example .env

# 3. 运行（单 agent，非 swarm）
python main.py run --target http://target/ --desc "题目描述" --type web --report report.md
```

### swarm 并行模式

> `main.py run` 是单 agent，不会启动 swarm。需要同题三风格并行时，用 `SwarmCoordinator` 驱动（每路一个 solve.py 子进程，见 DESIGN 使用方法章节）：

```bash
# .env 开启开关
SWARM_ENABLED=true
DOCKER_ENABLED=true
KALI_ENABLED=false
```

```python
from ctf_agent.swarm import SwarmCoordinator

def verify_flag(flag: str):
    return flag.startswith("CTF{"), "格式校验"

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
```

详细说明见 **[WING_GOOSE_DESIGN.md](./WING_GOOSE_DESIGN.md) 使用方法章节**（含 .env 逐字段、swarm 启用、docker 链配置、14 项常见问题排查）。

## 三个版本对比

| 版本 | 定位 | 关键差异 |
|------|------|----------|
| [WING-Falcon](../WING-Falcon) | 精英单兵 | 单 agent 解题引擎基线 |
| [WING-Goose](../WING-Goose) | 雁阵 | 同题三风格并行 + 消息总线 + 轨迹复盘 + docker 链 |
| [WING-Corvus](../WING-Corvus) | 渡鸦 | 三层协作小队（总指挥+战略层+战术层）+ 多阶段协调 |

## 声明

- 仅供**授权的 CTF 竞赛环境或自有靶机**使用
- 隐私/日志/积累技能不在此公开仓库中（见私有库 WING-data）
