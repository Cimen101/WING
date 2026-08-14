# 测试报告：rev-zermatt 分层 LLM 对照测试（Sprint 39 pro 分层 vs 全 flash）

- 日期：2026-08-14
- 版本：WING-Corvus（渡鸦）——主线
- 测试目的：验证分层 LLM 机制（LAYER_LLM_MAP / --layer-llm）并对比"官方 pro 分层"与"全 zen flash"在极难 reverse 题上的效果与成本

## 题目来源与信息

| 项 | 值 |
| :-- | :-- |
| 题目 | rev-zermatt（GCTF 2023 sandbox escape，reverse 极难） |
| 运行方式 | 双组并发 × 各 3 风格 × 40 分钟（2400s） |
| 干扰清理 | 残留容器 27 个 + agent_share 旧目录 + 旧 bus 数据 |

## 结果汇总

| 配置 | 步数（conserv/aggr/innov） | 结果 | 官方 pro 成本 |
| :-- | :-- | :-- | :-- |
| commander/strategy=pro + tactic=flash | 102（21/40/41） | 跑满 2400s 未解出（推进到 v7 XOR 解密/VM 指令分析） | ¥2.88 |
| tactic=pro（单组二次测试） | 244（85/82/77） | 三路均 4M token 硬熔断提前终止（9.5-16 分钟） | ¥9.60 |
| 全 flash（对照） | 89（25/36/28） | 跑满 2400s 未解出 | ¥0 |

## 关键发现

### 1. 分层机制运转正常

- `LAYER_LLM_MAP=commander=pro,strategy=pro,tactic=zen:deepseek-v4-flash` 端到端验证：commander/strategy 走官方 pro（2s 有内容）、tactic 走 zen flash ✓；
- ¥2.88 消耗证实官方 pro 调用真实发生（flash 组官方余额不变）；
- 官方 pro 思考模式（high/max）服务端"思考不收敛"（输出 100% reasoning_content、content 为空、撞满 max_tokens）→ 系统强制 pro 层 `reasoning_effort=none`（仅 none 档可用）。

### 2. pro 战术层步骤效率显著提升（但成本不可接受）

- aggressive：flash 40 分钟 40 步 → pro 11.7 分钟 82 步（~7 倍速度）；conservative flash 21 步 → pro 85 步；
- pro 单步更快（none 档 9-14s vs flash 慢速 20-30s+），推理深度更高（aggressive 推进到 run.lua VM 交互验证阶段）；
- **瓶颈**：pro 战术层单路 ~400 万 token 触发系统 4M 硬熔断提前终止；单题成本 ¥9.60。

### 3. 最终结论（决策依据）

- 效率提升主要来自 **API 响应速度**（步数多 3-4 倍但 ~25% 步为 `<DSML>` 格式错误废步），推理能力无实质增益；
- flash 组致命缺陷 = **P2 侦查死循环**（三路全困在 ls/cat/grep/xxd/strings 无限重复 20-30 步，从不写脚本推进）——这是系统架构问题而非模型能力问题；
- **决策：模型维持 flash，通过系统/架构升级提升能力（→ Sprint 41 侦查饱和检测 + 命令/脚本去重）**；pro 仅作为分层可选能力保留（成本敏感场景谨慎使用）。

## 关联记录

- 更新记录：`updates/2026-08-14-layer-llm.md`、`updates/2026-08-14-recon-saturation-dedup.md`
- 设计文档 §14.8 分层 LLM 覆盖
- 数据源：`data/test_reports/test20_verify/rev-zermatt*.jsonl`
