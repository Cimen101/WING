# WING-Falcon 猎隼 — 精英单兵

> **定位**：精英单兵 — 单 agent 完整解题引擎基线（Sprint 32.10 快照，2026-08-02）
> 版本谱系：**WING-Falcon → WING-Goose（雁阵）→ WING-Corvus（渡鸦）**

## 核心能力

- **ReAct 推理引擎**：推理与行动交替推进，解析器容错（markdown 装饰/别名/裸 JSON）
- **LLM 三级路由**：zen（免费 flash）→ fallback（官方 flash）→ pro，动态 provider 健康状态 + wall-clock 总超时
- **B+ 长任务超时转后台**：timeout 语义档位 quick/normal/long/background + 120s 自动兜底
- **巡查指导器**：慢思考旁观者，FACT/LIKELY/POSSIBLE/DISPROVED 推论分级 + MUST 强制 + 禁忌列表
- **三层记忆**：短期（上下文）/ 中期（任务事实）/ 长期（RAG 经验库 + Skill 技能库）
- **三层工具链**：内置 Python 工具 → SSH-Kali 系统命令 → MCP 重型工具，自动降级
- **失败轨迹缓存** + LLM 调用三层容错 + 日志精简

## 目录结构

```
WING-Falcon/
├── ctf_agent/            # 核心解题引擎
│   ├── agent/            # ReAct 引擎 + 巡查指导器
│   ├── tools/            # 内置工具库（编解码/HTTP/crypto/pwn/逆向分析等）
│   ├── memory/           # 短期/中期/长期记忆 + Skill 库
│   ├── llm/              # LLM 客户端与三级路由
│   ├── ssh/              # Kali SSH 沙箱连接
│   └── web/              # WebUI
├── data/                 # 白板数据库（空库，下载即用）
│   ├── chroma/           # RAG 经验库（空）
│   └── skills/           # 技能库（空 index.json）
├── main.py               # CLI 入口
├── pyproject.toml
├── .env.example          # 环境配置模板
├── README.md
└── WING_FALCON_DESIGN.md # 2000+ 行完整设计+使用文档
```

## 快速开始

```bash
# 1. 安装依赖（Python >= 3.10）
pip install -e .

# 2. 配置环境（含 LLM API Key，参考 .env.example 逐字段说明）
cp .env.example .env

# 3. 运行（解一道题）
python main.py run --target http://target/ --desc "题目描述" --type web --report report.md

# 4. 启动 WebUI
python main.py web --port 8000
```

详细说明（环境配置、命令行参数、常见问题）见 **[WING_FALCON_DESIGN.md](./WING_FALCON_DESIGN.md) 使用方法章节**。

## 三个版本对比

| 版本 | 定位 | 关键差异 |
|------|------|----------|
| [WING-Falcon](./WING-Falcon) | 精英单兵 | 单 agent 解题引擎基线 |
| [WING-Goose](./WING-Goose) | 雁阵 | 同题三风格并行 + 消息总线 + 轨迹复盘 + docker 链 |
| [WING-Corvus](./WING-Corvus) | 渡鸦 | 三层协作小队（总指挥+战略层+战术层）+ 多阶段协调 |

> 本版本是 WING-Goose 的升级基线：WING-Goose 在此基线上新增同题多风格并行（消息总线 + 独立上下文 LLM 轨迹复盘 + docker 工具链）。

## 声明

- 仅供**授权的 CTF 竞赛环境或自有靶机**使用，禁止对未授权目标扫描或攻击
- 所有流量与载荷仅在本地沙箱内闭环
- 隐私/日志/积累技能不在此公开仓库中（见私有库 WING-data）
