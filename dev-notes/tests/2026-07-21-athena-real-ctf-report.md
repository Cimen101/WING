# 测试报告：Athena CTF 2026 历年真题十题实战（首次真实竞赛规模化测试）

- 日期：2026-07-21
- 版本：WING-Goose（雁阵）——旧版本
- 测试目的：首次以真实竞赛历年真题为样本的规模化测试，检验 WING-Goose 在跨题型、跨难度场景下的端到端自主解题能力

## 题目来源与信息

| 项 | 值 |
| :-- | :-- |
| 比赛来源 | Athena CTF 2026（历年真题） |
| 题目 | Small_Root、Tiny_ECC_Tweak、Crypto_Reverse、Table_Stakes、Logic_Puzzle、SCADA_Firmware、RAM_Drift、Mailroom_Echo、PCAP_Secret、API_Relay |
| 题型构成 | crypto / reverse / forensics / infra 混合 |
| 难度分布 | easy 4 题 / medium 4 题 / hard 2 题 |

## 结果汇总

| 维度 | 值 |
| :-- | :-- |
| 整体 | 6/10（60%）解出 |
| 题型统计 | crypto 2/2、reverse 2/4、forensics 2/3、infra 0/1 |
| 难度统计 | easy 4/4、medium 2/4、hard 0/2 |
| 资源消耗 | 总 115 步 / 1.7M tokens / 1717.8s |

### 逐题结果

| 题目 | 题型 | 结果 |
| :-- | :-- | :-- |
| Small_Root | crypto | ✅ 解出 |
| Tiny_ECC_Tweak | crypto | ✅ 解出 |
| Logic_Puzzle | reverse | ✅ 解出 |
| SCADA_Firmware | reverse | ✅ 解出 |
| Mailroom_Echo | forensics | ✅ 解出 |
| PCAP_Secret | forensics | ✅ 解出 |
| Crypto_Reverse | reverse | ❌ 步数耗尽（key schedule 推错） |
| Table_Stakes | reverse | ❌ 步数耗尽（LLM 输出空格式解析失败） |
| RAM_Drift | forensics | ❌ 步数耗尽（未找到 XOR key） |
| API_Relay | infra | ❌ 步数耗尽（SSRF 绕过未完成） |

## 失败原因分析

4 道失败题均为步数耗尽（未触达时间上限，先耗尽步数）：

| 题目 | 卡点 |
| :-- | :-- |
| Crypto_Reverse | 加密 key schedule 推导错误，多次重试未纠正 |
| Table_Stakes | LLM 输出空格式导致解析失败，后续步骤无法衔接 |
| RAM_Drift | 未找到 XOR key，数据无法解密还原 |
| API_Relay | SSRF 绕过链路未完成 |

## 结论

- 首次真实竞赛真题规模化测试整体 6/10，easy 全过，具备中等难度以下场景的可靠解题能力。
- crypto 类稳定性最好（2/2）；infra 类暂无突破。
- 4 道失败全部为步数耗尽型，主要瓶颈集中在「局部错误反复重试消耗步数」而非能力整体缺失，后续迭代优先改进错误纠正与步数分配策略。
