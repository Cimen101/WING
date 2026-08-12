# 测试报告：SUCTF 2026 新题验证（4 题）

- 日期：2026-08-08
- 版本：WING-Corvus（渡鸦）——最新版本小版本更新
- 测试目的：SUCTF 2026 新题首轮验证（4 题，3 并发）

## 题目来源与信息

| 项 | 值 |
| :-- | :-- |
| 比赛来源 | SUCTF 2026 |
| 题目 | SU_RSA / SU_老年固件 / SU_chaos / SU_Revird |
| 运行方式 | 3 并发（三路 swarm + 总指挥） |
| 时间上限 | 1800s / 题 |

## 结果汇总

| 题目 | 类别 | 结果 | 耗时 | 胜出风格 |
| :-- | :-- | :-- | :-- | :-- |
| SU_RSA | crypto | 解出 | 237s | conservative |
| SU_老年固件 | reverse | 解出 | 997s | innovative |
| SU_chaos | misc | 失败 | 耗尽 1800s 上限 | — |
| SU_Revird | reverse | 失败 | 耗尽 1800s 上限 | — |

**2/4 解出**。

## 观察

- SU_RSA：conservative 路以确定性数学验证收敛，237s 快速解出（对比 08-05 同题首测 637s，调度效率显著提升）；
- SU_老年固件：innovative 路耗时 997s 的长链路逆向，体现多阶段调度下长任务不被过早 kill；
- SU_chaos / SU_Revird：均在预算内穷尽三路方向仍未突破，轨迹已留档；失败模式与脑洞类/特殊壳类题目缺口一致，随专项升级排期跟进。

## 结论

- 新题泛化能力正常（非题库内原题复现），crypto/reverse 主路径稳定；
- misc 与特殊壳 reverse 仍是短板方向，持续积累 pitfalls 并等待脑洞能力升级落地。
