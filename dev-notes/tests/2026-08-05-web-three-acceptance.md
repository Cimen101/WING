# 测试报告：WING-Corvus 2.0 升级效果验收 — 三道未做过的 web 动态题

- 日期：2026-08-05
- 版本：WING-Corvus（渡鸦）——最新版本小版本更新
- 测试目的：验证总指挥多阶段调度升级后的实战效果（见 `../updates/2026-08-05-commander-multi-stage.md`）

## 题目来源与信息

| 项 | 值 |
| :-- | :-- |
| 比赛来源 | GitHub athena 公开仓库 web 动态题 |
| 题目 | Session Slip / Echo Chamber / Meridian Ladder |
| 题目状态 | 均未做过（全新题目） |
| 题型 | web / 动态部署 |

## 结果汇总

| 题目 | 结果 | 耗时 | 胜出风格 | 真实漏洞路径 |
| :-- | :-- | :-- | :-- | :-- |
| Session Slip | 解出 | 64s | innovative | 会话凭据管理缺陷（会话滑移类） |
| Echo Chamber | 解出 | 81s | aggressive | SSTI（Jinja2）黑名单绕过 → RCE |
| Meridian Ladder | 解出 | 143s | conservative | 原型污染 + IDOR + source map 溯源 |

**3/3 全部解出**，且均经由真实漏洞路径完成，非猜测命中。

## 能力点验证

### 1. 阶段切换（P1 → P2 → P3 → P4）

- Meridian Ladder：P1 侦查即发现前端 source map，据此溯源到后端接口，再经原型污染 + IDOR 串联利用；P2 收敛 → P3 利用 → P4 验证流程完整；
- Session Slip：innovative 路在 P2 阶段提出非主流攻击向量并被采纳，体现阶段化调度下的方向发散。

### 2. 首次巡查提前（step 2）

- 三题均观察到 step 2 即开始主动巡查（目录/端点/源码），比旧版更早进入 P1 侦查，缩短无用铺垫。

### 3. MUST 指令纠偏

- Echo Chamber 中某路一度偏离主线，总指挥下发 MUST 级指令强制拉回 SSTI 主线，随后 aggressive 路完成 Jinja2 黑名单绕过并 RCE。

### 4. 兄弟总线协作

- 三题全程总线消息正常，线索（漏洞点、黑名单条目、参数名）跨路共享，兄弟 kill 机制在首题解出后即终止其余两路，无空转。

## 结论

- WING-Corvus 2.0（多阶段调度 + 差异化分工）在全新 web 动态题上验收通过；
- 三题解出耗时均远低于上限，验证阶段化编排未引入额外开销；
- 后续将用 crypto / reverse / misc 题型继续压测（见 `tests/2026-08-06-gctf20-report.md`）。
