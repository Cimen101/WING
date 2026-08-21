# NSS Runner 近 10 小时运行数据分析报告

> 数据来源: `data/nss_logs/hub_20260817_233511.log` (2026-08-17 23:35 ~ 2026-08-18 10:18, 约 10.7 小时)
> 分析时间: 2026-08-18

## 一、总体运行概况

| 指标 | 数值 |
|------|------|
| 运行时长 | ~10.7 小时 |
| 领取题目数 | 25 题 (含 #4859 复用 1 次) |
| **解出** | **14 题 (56%)** |
| **abandon/失败** | **11 题 (44%)** |
| LLM 超时次数 | 91 次 |
| 提交失败次数 | 90 次 |
| 巡查 MUST/FORCE 干预 | 248 次 |
| 死循环/重复检测 | 320 次 |
| 工具不可用 | 71 次 |
| swarm 复盘异常 (LLM 超时) | 12 次 |

### 各题结果明细

| 题目 | 题型/难度 | 结果 | 耗时 | 解出者 |
|------|-----------|------|------|--------|
| #4827 | Reverse/easy | ✅ 解出 | 778s | innovative |
| #4828 | Web/medium | ✅ 解出 | 237s | aggressive |
| #4830 | Web/easy | ✅ 解出 | 132s | aggressive |
| #4832 | Crypto/medium | ✅ 解出 | 76s | conservative |
| #4833 | Reverse/easy | ✅ 解出 | 164s | innovative |
| #4834 | Crypto/medium | ✅ 解出 | 537s | conservative |
| #4836 | Misc/medium | ❌ abandon | 3248s | - |
| #4840 | Crypto/medium | ✅ 解出 | 303s | conservative |
| #4841 | Reverse/medium | ❌ abandon | 3173s | - |
| #4846 | Pwn/medium | ✅ 解出 | 800s | innovative |
| #4848 | Crypto/medium | ❌ abandon | 2772s | - |
| #4851 | Web/medium | ✅ 解出 | 700s | aggressive |
| #4853 | Web/medium | ❌ abandon | 3162s | - |
| #4855 | Crypto/medium | ✅ 解出 | 44s | aggressive |
| #4856 | Web/medium | ❌ abandon | 3169s | - |
| #4859 | Web/medium | ❌ abandon | 2661s+1205s | - |
| #4862 | Crypto/medium | ❌ abandon | 3870s | - |
| #4866 | Pwn/medium | ✅ 解出 | 990s | aggressive |
| #4868 | Reverse/medium | ❌ abandon | 3127s | - |
| #4872 | Pwn/medium | ✅ 解出 | 686s | innovative |
| #4873 | Web/medium | ✅ 解出 | 90s | conservative |
| #4874 | Pwn/medium | ✅ 解出 | 223s | innovative |
| #4875 | Reverse/medium | ❌ abandon | 3123s | - |
| #4879 | Reverse/medium | ❌ abandon | 兜底 | - |

---

## 二、核心问题分析

### 问题 1：LLM 超时是最大瓶颈（91 次 + 12 次 swarm 复盘异常）

**现象**：
- 日志反复出现 `TimeoutError: LLM 调用超过 wall-clock 120s (疑似慢速流半死连接)`
- **swarm 复盘异常 12 次**：每次题目结束后 swarm 复盘因 LLM 超时失败，导致复盘结果丢失、经验无法沉淀
- 大量题目（#4836/#4841/#4848/#4853/#4856/#4859/#4862/#4868/#4875）在解题过程中频繁 LLM 超时，agent 连续 2 次失败只跑 1-3 步

**根因**：
- `_CALL_TOTAL_BUDGET = 120s` 对 zen/慢速流过严（**已在上一轮修复为 180s**）
- 慢速流（slow-drip streaming）绕过 httpx read timeout，需要 wall-clock 兜底

**影响**：LLM 超时导致 agent 每步耗时剧增、巡查干预延迟、swarm 复盘失败（经验无法沉淀）。

**状态**：✅ 已修复（120s→180s）

---

### 问题 2：flag 前缀误判导致无效提交（90 次提交失败）

**现象**：
- #4827: 提交 `GFCTF{u_are2wordy}` 失败 → 修正为 `NSSCTF{u_are2wordy}` 才通过
- #4834: 提交 `GWHT{pell_equation_is_very_interes...}` 失败 → 修正为 `NSSCTF{...}` 才通过
- #4836: 提交 `suctf{have_fun!}` 失败
- 三路 agent 共享提交额度（max_wrong_count=20），错误前缀浪费大量提交次数

**根因**：
- 从二进制/解密结果提取的 flag 常带原比赛前缀（GFCTF/GWHT/suctf 等）
- executor 本地格式预检只查通用 `xxx{...}` 格式，拦不住错误前缀

**影响**：浪费共享提交额度，且 agent 需额外步数修正前缀。

**状态**：✅ 已修复（上一轮新增 flag 前缀拦截 + 巡查 L1-A 检测）

---

### 问题 3：abandon 机制缺陷（11 题 abandon，含 #4859 复用浪费）

**现象**：
- 11 题 abandon，平均耗时 ~3100s（约 52 分钟/题）
- **#4859 复用缺陷**：abandon 后立即"复用进行中题目"，继承上次轨迹重新解，又耗 1205s 仍未解出
- #4879 兜底 abandon：程序退出后才发现未完成题目，调用 abandon API 清理

**根因**：
- abandon 判定阈值（~3000s）对 medium 题过严，多数题在 3000s 内无法解出
- #4859 复用机制：abandon 后立即复用同一题，浪费额外时间
- 兜底 abandon 依赖程序退出检测，不够及时

**影响**：大量时间浪费在注定解不出的题上，且复用机制加剧浪费。

**状态**：⚠️ 部分修复（abandon 重试机制已加，但复用缺陷和阈值待优化）

---

### 问题 4：死循环/重复操作严重（320 次检测）

**现象**：
- 巡查 MUST/FORCE 干预 248 次，死循环检测 320 次
- #4836（USB 流量题）：tshark 同类命令重复 7 次以上，直到巡查强制 MUST 干预
- #4868/#4875（Reverse）：大量重复反汇编/静态分析，工具不可用 71 次

**根因**：
- 工具不可用（71 次）导致 agent 反复尝试同一失败命令
- 方向误判后在同质化操作上打转

**状态**：✅ 部分修复（新增 usb_analyze/env_check/deobfuscate_binary/pe_analyze 工具 + 巡查增强）

---

### 问题 5：工具不可用（71 次）

**现象**：
- #4827: angr_symbolic_exec 工具因路径检查失败
- #4836: tshark 字段提取失败（usb.capdata 空值）
- #4868/#4875: 大量工具不可用

**根因**：
- 专项工具（angr/sagemath/tshark 字段）环境缺失或调用路径错误
- USB 流量字段名不标准

**状态**：✅ 已修复（新增 usb_analyze/env_check 等工具）

---

### 问题 6：信息同步滞后（三路重复劳动）

**现象**：
- #4833: innovative 率先识别出 bat2exe 结构，但另外两路仍在按原方向无效探索
- 总线检查间隔 5 步，线索回流延迟

**状态**：✅ 已修复（总线检查间隔 5→3 步）

---

## 三、设计冗余 / 未考虑到的地方

### 1. 复用机制（#4859）设计缺陷
abandon 后立即复用同一题，继承轨迹重新解，浪费额外 1205s。应评估复用价值（若上次已证明方向错误，复用无意义）。

### 2. abandon 阈值一刀切
所有 medium 题统一 ~3000s 阈值，未按题型/难度/进展动态调整。应结合"最近是否有进展"动态决定是否 abandon。

### 3. swarm 复盘依赖 LLM，超时即失败
swarm 复盘异常 12 次，导致经验无法沉淀。应增加复盘降级机制（LLM 超时时用规则化摘要兜底）。

### 4. 提交额度共享无保护
三路 agent 共享 max_wrong_count=20，错误前缀/猜测 flag 会快速耗尽额度。应增加提交前更严格的验证（已部分修复）。

### 5. 兜底 abandon 依赖程序退出检测
#4879 直到程序退出才发现未完成题目。应主动监控未完成题目并及时清理。

---

## 四、结论

近 10 小时运行 **14/25 (56%) 解出率**，主要瓶颈是：
1. **LLM 超时**（91 次 + 12 次复盘异常）— 已修复
2. **flag 前缀误判**（90 次无效提交）— 已修复
3. **abandon 机制缺陷**（11 题 abandon + 复用浪费）— 部分修复
4. **死循环/工具不可用**（320 次 + 71 次）— 已修复

**待优化**：
- abandon 阈值动态化 + 复用价值评估
- swarm 复盘 LLM 超时降级
- 兜底 abandon 主动监控
