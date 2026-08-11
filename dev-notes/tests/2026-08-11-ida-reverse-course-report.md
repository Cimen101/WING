# Sprint 37 验证报告：ida-reverse-course CH1-CH8 全量（修复前后对比）

日期: 2026-08-11 · 题目源: GitHub immml/ida-reverse-course（14 个基础 .exe 逆向题，取 CH1-CH8）· 三风格协作小队

## 结果总览

| 指标 | 修复前（API 恢复后首测） | 修复后 |
|------|--------------------------|--------|
| 解题率 | 6/8 | **8/8** |
| CH4 (medium) | ❌ 1207s 超时（三路） | ✅ 241.0s |
| CH8 (medium) | ❌ 1207s 超时（三路） | ✅ 650.9s |
| 回归测试 | - | 145 项全过 + 新增 10 项 |

## 分题明细（修复后）

| 题目 | 难度 | 结果 | 用时 | 胜利风格 |
|------|------|------|------|----------|
| CH1 plain | easy | ✅ | 47.2s | innovative |
| CH2 stack | easy | ✅ | 388.1s | conservative |
| CH3 xor | easy | ✅ | 163.3s | conservative |
| CH4 maze | medium | ✅ | 241.0s | conservative |
| CH5 encoding | medium | ✅ | 115.9s | aggressive |
| CH6 antidebug | medium | ✅ | 695.9s | aggressive |
| CH7 crackme | medium | ✅ | 401.4s | aggressive |
| CH8 junkcode | medium | ✅ | 650.9s | conservative |

## 关键修复验证

### CH4 (Maze of Functions) — FlagVerifier 三重死锁修复

- **修复前根因**：agent 用 `echo 'flag{...}' | wine` 验证 flag（reverse 合法手段）→ 被"自导自演检测"误判；objdump 提取的 hex 字节序列不被 `_find_all_sources` 识别；被拒后 flag 永久拉黑 → 三路反复提取证明循环直至超时。
- **修复后**：证据链升级（hex/编码变体匹配 + 程序验证豁免 + 拒绝软锁 + 拼接覆盖）→ conservative 241s 解出。

### CH8 (Junk Code) — 已解出未提交检测修复

- **修复前根因**：aggressive step 11-14 已完整解析 flag，但阶段停在 P2，巡查判"接近还原"未干预，agent 反复静态验证（movabs 拼接疑义）直至超时。
- **修复后**：`_check_solved_not_submitted` L1 规则级检测，双分支干预（未验证→引导运行程序验证/直接提交试错，解释 `junnk` 重叠）→ conservative 650.9s 解出。

## 相关文档

- 更新：`updates/2026-08-11-flag-verifier-evidence-chain.md`
- 问题：`issues/2026-08-11-flag-solved-but-not-submitted.md`
- 设计文档：WING_CORVUS_DESIGN.md §5.16 / §8.2-8.3 / 附录 22.7（Sprint 37/37.1）
