# 测试报告：CSAW Finals 2025 全量测试（3 并发）

- 日期：2026-08-07 ~ 08-08
- 版本：WING-Corvus（渡鸦）——最新版本小版本更新
- 测试目的：CSAW Finals 2025 全部 8 题全量能力验证（3 并发）

## 题目来源与信息

| 项 | 值 |
| :-- | :-- |
| 比赛来源 | CSAW Finals 2025 |
| 题目数量 | 8 题（easy 2 / medium 3 / hard 3） |
| 运行方式 | 3 并发 |
| 总耗时 | 1721s |

## 结果汇总

| 题目 | 类别 | 难度 | 结果 |
| :-- | :-- | :-- | :-- |
| Barnyard Blues | crypto | easy | 解出 |
| Cat Ate My Homework | forensics | easy | 解出 |
| Crypto Chain | crypto | hard | 解出 |
| Violet Torch | forensics | medium | 解出 |
| hehexd | misc | medium | 解出 |
| Capture the Bee | rev | hard | 解出 |
| Legacy Auth | forensics | medium | 失败 |
| Well-Tempered Cipher | misc | hard | 失败 |

**6/8 解出**：easy 2/2、medium 2/3、hard 2/3。

## 失败题分析

### 1. Legacy Auth（forensics / medium）

- 失败模式留档 pitfalls；与既有 forensics 题失败案例存在共性，待专项复盘。

### 2. Well-Tempered Cipher（misc / hard）

- 失败模式留档 pitfalls；misc 类的非标准编码/变换类题目仍属短板，与脑洞题能力缺口同源（参见 `tests/2026-08-06-gctf20-report.md`）。

## 修复后复测（csaw_fix_verify）

- 针对修复项对失败题 3 题发起复测；
- 结果 **0/3 全部 steps=0 超时**：复测在启动阶段即耗尽时间，未进入实际解题；
- 结论：修复未生效或复测环境存在问题，两者需二选一排查后再复测（排期跟进）。
