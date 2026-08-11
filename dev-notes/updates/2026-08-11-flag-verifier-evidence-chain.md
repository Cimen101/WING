# 更新记录：FlagVerifier 证据链升级 + 已解出未提交检测（Sprint 37/37.1）

- 日期：2026-08-11
- 版本：WING-Corvus（主线）

## 背景

ida-reverse-course（GitHub immml/ida-reverse-course）全量验证：CH1-CH8 测试暴露出两个"flag 已解出但无法提交"的系统性死锁，与题型无关（reverse 二进制提取场景通用）：

- **CH4 (maze)**：三路 agent 均解出正确 flag，但提交被 Flag 验证系统三重拦截，陷入"重复提取证明循环"直至 1200s 超时
- **CH8 (junkcode)**：agent 已从 movabs 立即数完整解析出 flag，但阶段停在 P2、巡查判"接近还原"而非"已还原"，从未下发提交指令，agent 反复静态验证直至超时

## 变更内容

### 1. FlagVerifier 证据链升级（`agent/flag_verify.py`）

**`_find_all_sources` 四级证据形态**（替代旧的"完整 flag 或 core 前 8 字符"二元匹配）：

1. 完整 flag 明文 或 **flag 编码变体**（`_encode_variants`：连续 hex / 空格分隔 hex / 逗号分隔十进制 / 空格分隔十进制 / `[102, 108, ...]` 列表 / `0x66,0x6c,...` 六种形态）——覆盖 objdump/xxd/strings 二进制提取输出（明文反而缺失）场景；
2. core 前 8 字符（防观测截断误判）；
3. **core 分段覆盖**（`_split_core` 滑窗拆片段）：全部片段分别出现在 ≥2 个不同步骤观测 → 拼接式 flag 合法来源（交由 LLM 审查把关）。

**`_is_program_verify` 程序验证豁免**：来源步 action_input 含 flag 或其编码变体 → 默认判"硬编码自导自演"；但输入含运行命令特征（wine/./.exe/timeout/|/printf/echo）**且**观测含程序接受信号（correct/right/验证通过/win/passed 等）→ 视为"用 flag 运行程序验证"（reverse 标准流程），豁免。

**`_rejected_flags` 拒绝软锁**：被拒 flag 记忆从"永久拉黑"改为"软锁"——只有当前轨迹仍无任何观测证据时才拒绝重复提交；一旦后续出现新证据（明文或编码变体）自动解除拉黑。破解"先 echo 验证被误拒 → 之后干净提取同 flag 也被永久拦截"死锁。

### 2. 已解出未提交检测（`agent/coordinator.py`）

`_check_solved_not_submitted`（L1 规则级，不依赖 L2 LLM 恰好判"已还原"）：

- **触发条件**（全部满足）：① 最近 lookback 步出现完整 `flag{...}` 候选；② 候选有验证信号（程序接受输出 / flag 明文或编码出现在观测）；③ 最近窗口无提交意图；④ 仍在反复做提取类工具（strings/objdump/xxd/file/binary ≥2 步）。
- **双分支干预**：
  - 已验证 → MUST 级强制提交（附 flag 文本）；
  - 未验证（仅 thought 拼出候选）→ 引导"运行程序验证或直接提交试错"，并解释 movabs 边界字节重叠（如 `flag{jun`+`nk_c0d3` 简单拼接成 `junnk`）下唯一可靠判定是运行程序或提交试错，不再无限静态分析。

## 验证

- 新增单元测试 10 项（`tests/test_flag_verify_sprint37.py`）：hex 编码来源 / 程序验证豁免 / 自导自演仍拒绝 / 拒绝软锁 / 拼接 flag 来源 / 幻觉仍拒绝 / 已解出未提交（CH8 场景）/ 无误报 / 已提交不重复干预 / 未验证引导
- 回归测试：react/breaker/collab/analyzer 等 145 项全绿
- 全量验证：CH1-CH8 从 6/8 → **8/8**（详见 `tests/2026-08-11-ida-reverse-course-report.md`）
