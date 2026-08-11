# 问题与修复：reverse 题 flag 已解出但无法提交（双重死锁）

- 日期：2026-08-11
- 影响：ida-reverse-course CH4/CH8 三路全部 1200s 超时（flag 实际已解出）

## 现象

全量验证 8 题中 6 题解出，CH4/CH8 失败——但轨迹显示**三路 agent 都已解出正确 flag**，问题不在解题能力而在"解出后无法完成提交"：

- CH4：agent 反复提交 → 被 Flag 验证系统拒绝 → 反复用不同方式"证明"flag 来自工具观测 → 死循环
- CH8：agent 已拼出 flag，但一直静态反汇编验证（movabs 拼接疑义），无人强制提交

## 根因分析

### CH4：FlagVerifier 三重拦截死锁

1. **自导自演误判**：`echo 'flag{...}' | wine ./binary` 是 reverse 标准验证手段（程序输出 Correct! 即 flag 被接受），但 flag 出现在 action_input → 被"疑似硬编码自导自演"拒绝；
2. **编码形态不识别**：agent 用 objdump/xxd 提取到的是 hex 字节序列（`666c61677b...`）或十进制字节列表（`[102, 108, ...]`），明文 flag 反而不出现在 observation → "flag 未出现在任何观测"被拒；
3. **永久拉黑**：一旦被拒，flag 记入 `_rejected_flags`，之后即使干净提取同 flag 也被直接拦截（"该 flag 已在之前的验证中被拒绝"）→ agent 无法理解为何被拒，陷入重复提取证明循环。

### CH8：已拼出未提交

aggressive 在 step 11-14 已通过 movabs 立即数完整解析出 flag（甚至指出自己曾拼错 `junnk`），但总指挥阶段停在 P2（指令=3），巡查判"接近还原"而非"已还原"，从未下发 [MUST] 提交指令 → agent 继续 xxd 验证直到超时。

## 修复方案

1. **FlagVerifier 证据链升级**（`agent/flag_verify.py`）：
   - `_encode_variants`：6 种编码变体匹配（hex/空格hex/十进制/0x 列表等），二进制提取输出可识别为来源；
   - `_is_program_verify`：程序输出 Correct!/Right! 等接受信号时豁免自导自演（echo 验证合法）；
   - `_rejected_flags` 改软锁：有新证据（明文或编码）即解除拉黑，允许重提；
   - `_split_core` 分段覆盖：拼接式 flag 多片段识别为合法来源。
2. **已解出未提交检测**（`agent/coordinator.py`）：L1 规则级识别"完整 flag 候选 + 验证信号 + 无提交意图 + 反复提取"→ 双分支干预（已验证→MUST 提交；未验证→引导运行程序验证或直接提交试错）。

## 验证

- 新增 10 项单元测试全过；145 项回归全绿
- CH4：三路 1207s 超时 → conservative 241s 解出
- CH8：三路 1207s 超时 → conservative 650.9s 解出
- 全量 CH1-CH8：6/8 → **8/8**

详见 `updates/2026-08-11-flag-verifier-evidence-chain.md` 与 `tests/2026-08-11-ida-reverse-course-report.md`
