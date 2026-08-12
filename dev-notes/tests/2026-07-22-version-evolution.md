# 测试报告：版本演进对比汇总（v3 → v14，Sprint 7–14）

- 日期：2026-07-21 ~ 2026-07-27（中下旬）
- 版本：WING-Goose（雁阵）——旧版本
- 说明：合并 9 份 compare / evolution 报告，梳理 v3 至 v14 的成功率与耗时演进

## 题目来源与信息

| 项 | 值 |
| :-- | :-- |
| 数据来源 | 9 份版本对比 / 演化分析报告（Sprint 7–14） |
| 覆盖版本 | v3 / v7 / v8 / v9 / v10 / v11 / v12 / v14 |
| 测试集 | 各版本测试集略有调整（6 题 / 9 题 / 5 题） |

## 演进总览

| 版本 | 关键改动 | 成功率 | 备注 |
| :-- | :-- | :-- | :-- |
| v3 | 基线 | 3/6 | — |
| v7 | failed_cache + mem_xor + osint | 4/6 | +1 |
| v8 | APK 工具集 | 5/6 | +1 |
| v9 | sage_tool / LLL | 5/6 | 持平，耗时 -10.7 min |
| v10 | reverse_image + OCR | 6/6 | 首次全过 |
| v11 | 演化器 | 6/6 | 持平，耗时增加 |
| v12 | OCR 修复 | 7/9 + 1 FLOW | 新增攻破 8 题 |
| v14 | ecdsa_nonce_reuse + angr_symbolic_exec | 4/5 | Crypto_Reverse 仍失败 |

## 演进分析

### v3 → v7（3/6 → 4/6）

新增 failed_cache（失败缓存）、mem_xor（内存 XOR 处理）、osint 能力，解锁 1 题，验证「能力补齐 → 成功率提升」的路线。

### v7 → v8（4/6 → 5/6）

引入 APK 工具集，安卓类逆向题目打通。

### v8 → v9（5/6 持平，耗时 -10.7 min）

新增 sage_tool / LLL 格攻击工具；成功率持平，但单题平均耗时下降 10.7 分钟，效率显著提升——同一成功率下资源成本明显收敛。

### v9 → v10（5/6 → 6/6）

新增 reverse_image + OCR，图像类逆向题目打通，首次实现 6/6 全过。

### v10 → v11（6/6 持平，耗时增加）

引入演化器（evolution engine）后成功率维持全过，但耗时增加，演化探索带来额外开销。

### v11 → v12（7/9 + 1 FLOW）

OCR 修复后测试集扩展至 9 题（另 +1 FLOW 流程题），新增攻破 8 题。

### v12 → v14（4/5）

新增 ecdsa_nonce_reuse（ECDSA nonce 重用）与 angr_symbolic_exec（符号执行）能力；测试集调整后 4/5，Crypto_Reverse 仍为未解难题。

## 结论

- **工具链逐步补齐是成功率提升的主驱动**：每一轮成功率跃升均对应具体工具能力（failed_cache/mem_xor/osint → APK → sage/LLL → reverse_image/OCR → OCR 修复）。
- 耗时曲线呈现「先降后升」：工具补齐期效率提升（v8→v9），引入演化 / 协作类模块后效率回吐（v11 起），成本控制是后续版本重点。
- Crypto_Reverse 从 v3 至 v14 长期未解，属系统性难点（对应测试报告中 key schedule 推导问题），后续需专项攻关。
