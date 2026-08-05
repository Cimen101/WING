# WING-Corvus 渡鸦 — 协作小队

> **定位**：协作小队（Coordinated Squad）— 三层协作架构 + 多阶段协调（当前最新版）
> 版本谱系：WING-Falcon（猎隼）→ WING-Goose（雁阵）→ **WING-Corvus（渡鸦）**

## 核心能力

在 WING-Goose（雁阵）之上新增：

- **总指挥（Commander）三层协作**：
  - **总指挥 ×1**：全局战略决策者，领题分工 / 消费战略层汇报 / LLM 分析 / 下发方向指令（方向性指引，非强制枷锁）
  - **战略层 ×3**：各路巡查指导器，监督方向、死循环检测、小方向调控，向总指挥汇报
  - **战术层 ×3**：各路主 LLM，只负责具体解题动作
- **多阶段协调（P1→P2→P3→P4）**：
  - P1 侦查：三路差异化分工（保守系统性扫描 / 激进快速试探记录响应 / 创新非常规挖掘），每 5 步汇报进度，三路全部完成（recon_done）后整合全局情报摘要并确定主方向
  - P2 漏洞识别：保守+激进互补深入主方向（总指挥只引导），创新发散探索备选；主方向修改仅两种途径
  - P3 利用：总指挥协调以引导为主，死循环/方向调整由战略层负责
  - P4 验证：保守型验证候选 flag
- **任务驱动 + 进度汇报驱动**：非步数硬门槛，简单题侦查收敛、难题发散，定期汇报防卡死
- **Flag 验证系统**（agent/flag_verify.py）：代码机制（flag 必须出现在轨迹 observation + 可疑渠道拦截 GitHub/writeup）+ LLM 轨迹审查
- **总指挥协议总线**（bus/file_bus.py）：report（clue/dead_end/question/progress/recon_done/verified）+ directive（priority MUST/SHOULD + phase 阶段标记）
- **主方向管理**：P1 完成后确定；修改仅两种途径（保守/激进明确证伪；创新经允许深入并证实正确）

## 目录结构

```
WING-Corvus/
├── ctf_agent/
│   ├── commander/        # 总指挥（commander.py + prompts.py）
│   ├── agent/            # 战略层 Coordinator + 战术层 ReAct + flag 验证
│   ├── bus/              # 消息总线 + 总指挥协议
│   ├── tools/            # 内置工具 + docker 链
│   ├── memory/           # 三层记忆 + Skill 库
│   ├── llm/              # 三级路由
│   ├── swarm.py          # 多风格并行 + 总指挥生命周期
│   └── review.py / events.py
├── data/                 # 白板数据库（空库，下载即用）
├── main.py / pyproject.toml / .env.example
├── README.md
└── WING_CORVUS_DESIGN.md # 2000+ 行完整设计+使用文档
```

## 快速开始

本版本提供**两种运行模式**：

| 模式 | 入口 | 说明 |
| :-- | :-- | :-- |
| 单 agent 快速模式 | `python main.py run ...` | 单题快速验证/调试，**不启动** swarm/总指挥 |
| 总指挥完整模式 | `.env` 开 `SWARM_ENABLED` + `SWARM_COMMANDER_ENABLED` + 调 `SwarmCoordinator` | 三风格并行 + 总指挥三层协作 |

### 单 agent 快速模式

```bash
# 1. 安装依赖
pip install -e ".[docker]"      # 推荐（含 docker-py）；纯内置工具可 pip install -e .

# 2. 配置环境（至少填入 OPENAI_API_KEY / OPENAI_BASE_URL）
cp .env.example .env

# 3. 运行（单 agent，非 swarm）
python main.py run --target http://target/ --desc "题目描述" --type web --report report.md
```

### 总指挥完整模式（swarm + 三层协作）

> `main.py run` 是单 agent，不会启动总指挥。需要三风格并行 + 总指挥领题分工时：

```bash
# 1. .env 开启开关
SWARM_ENABLED=true
SWARM_COMMANDER_ENABLED=true
DOCKER_ENABLED=true
KALI_ENABLED=false

# 2. 最小 swarm 驱动（保存为 demo_swarm.py 后运行；完整示例见 DESIGN 20.8）
```

```python
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
```

```bash
python demo_swarm.py
```

> 说明：swarm 每路 agent 是一个 `solve.py` 子进程（task JSON 带 style/bus_dir），由 `SwarmCoordinator` 统一编排；总指挥实例运行在 swarm 主进程内。总指挥 LLM 不可用时自动降级回纯雁阵（swarm），不影响主流程。

详细说明（总指挥模式启用/降级、多阶段协调、.env 逐字段）见 **[WING_CORVUS_DESIGN.md](./WING_CORVUS_DESIGN.md) 使用方法章节**。

## 三个版本对比

| 版本 | 定位 | 关键差异 |
|------|------|----------|
| [WING-Falcon](../WING-Falcon) | 精英单兵 | 单 agent 解题引擎基线 |
| [WING-Goose](../WING-Goose) | 雁阵 | 同题三风格并行 + 消息总线 + 轨迹复盘 + docker 链 |
| [WING-Corvus](../WING-Corvus) | 渡鸦 | 三层协作小队（总指挥+战略层+战术层）+ 多阶段协调 |

## 声明

- 仅供**授权的 CTF 竞赛环境或自有靶机**使用
- 隐私/日志/积累技能不在此公开仓库中（见私有库 WING-data）
