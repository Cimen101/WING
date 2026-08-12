# 测试报告：Sprint 15 里程碑汇总（P3–P10）

- 日期：2026-07-27
- 版本：WING-Goose（雁阵）——旧版本
- 说明：将 Sprint 15 的 8 份阶段报告（P3–P10）合并为本篇里程碑汇总，正文按阶段分段列出

## 汇总

| 阶段 | 主题 | 结果 |
| :-- | :-- | :-- |
| P3 | Narrow_DES 32-bit sub-key | 1/1 |
| P4 | reverse 回归 | Logic_Puzzle ✅ / Table_Stakes verifier 不认 |
| P5 | 题库迁移 GitHub OWASP | 3/3 |
| P6 | 剩余 4 道 OWASP medium web | 4/4 |
| P7+P8 | A10 FailOpen + A04 JWT alg confusion | 2/2（hard 首试通过） |
| P9 | A01 SSRF Bypass | 1/1（3 步 16s） |
| P10 | 自主基线（清缓存无 Skill 注入） | 3/6 |

## P3 — Narrow_DES 32-bit sub-key（1/1）

| 项 | 值 |
| :-- | :-- |
| 题目 | Narrow_DES（32-bit sub-key 变体） |
| 题型 | crypto |
| 方法 | des_mitm32 + LLM 引导 |
| 结果 | ✅ 1/1 |

32 位子密钥的 DES 变体，通过内置 des_mitm32 中间相遇工具配合 LLM 参数推导完成破解，验证了 DES 类降维密钥场景的处理能力。

## P4 — reverse 回归

| 题目 | 结果 |
| :-- | :-- |
| Logic_Puzzle | ✅ 通过 |
| Table_Stakes | ⚠️ 得出结果但 verifier 不认 |

Logic_Puzzle 回归通过；Table_Stakes 虽解出结果但提交验证器不认，说明求解结果与判题器预期不一致，需进一步对齐输出口径。

## P5 — 题库迁移 GitHub OWASP（3/3）

OWASP 题库完成迁移，迁移后跑通 3 道题，验证「题目获取 → 解析 → 解题 → 提交」全链路在迁移后依然可用。

## P6 — 剩余 4 道 OWASP medium web（4/4）

| 题目类别 | 结果 |
| :-- | :-- |
| IDOR | ✅ |
| XSS | ✅ |
| Race（竞态） | ✅ |
| Pickle（反序列化） | ✅ |

4 道 medium 级 OWASP web 题全部通过，web 类题型覆盖补全。

## P7+P8 — A10 FailOpen + A04 JWT alg confusion（2/2）

- A10 FailOpen：认证 fail-open 场景 ✅
- A04 JWT alg confusion：JWT 算法混淆攻击 ✅
- 亮点：hard 难度首次尝试即通过（首试通过），此前 hard 题普遍需要多轮重试。

## P9 — A01 SSRF Bypass（1/1）

- 难度：hard
- 结果：✅ 1/1，仅 3 步 / 16s 完成
- 说明：SSRF 绕过一次性构造成功，为当前 hard 类最快通过记录。

## P10 — 自主基线（3/6）

- 条件：清空缓存、无 Skill 注入，测纯自主基线
- 结果：3/6
  - 纯风格路线 1/3
  - 黑盒路线 2/3
- 反直觉结论：黑盒路线表现优于纯风格路线，与「风格注入提升表现」的既有假设相反，需后续专项归因。

## 结论

Sprint 15 覆盖 crypto 专用能力（P3）、reverse 回归（P4）、题库迁移（P5）、web 全覆盖（P6–P9）与自主基线摸底（P10），工具与题库链路持续完善；P10 揭示的「黑盒优于纯风格」与 P4 的 verifier 口径问题，列为后续迭代重点。
