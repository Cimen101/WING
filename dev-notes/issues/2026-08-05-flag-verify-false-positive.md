# 问题记录：单 agent 模式假 flag 幻觉（假阳性）

- 日期：2026-08-05
- 影响版本：WING-Corvus（单 agent 直接求解路径）
- 状态：已修复

## 现象

SU_RSA（crypto/hard）首轮调试中，直接单 agent 求解时，系统在约 5 步内
「解出」一个 flag 并判定 `success=true`，但该 flag 经数学验证不成立：

```
验证结果: pow(bytes_to_long(提交的flag), e, N) != c   → 假 flag
（真实 flag 与官方 writeup 一致，此处不公开）
```

即：系统输出的是一个**幻觉 flag**（猜测的、与题目参数无关），却被当作成功结果。

## 根因分析

提交前 flag 验证（`flag_verify.py`）的检查链路存在两处薄弱点：

1. **「自导自演」可绕过代码机制**：
   代码机制只要求「flag 出现在某一步的 Observation（工具输出）中」。
   若 agent 把猜测的 flag **硬编码进自己写的脚本**再执行，
   脚本 stdout 会输出该 flag —— 此时 Observation 中出现 flag，
   但该 flag 只是脚本 echo 了输入，并非从附件/靶机真实提取。

2. **LLM 审查失败时「视为通过」**：
   LLM 审查输出无法解析或调用异常时，旧逻辑返回「视为通过（代码机制已兜底）」。
   当代码机制被上述方式绕过时，这个放行通道直接导致假 flag 通过验证。

## 修复

见 `../updates/2026-08-05-flag-verify-fix.md`，核心：

1. 新增代码机制：flag 出现在该步工具输入（脚本/命令）中 → 判定编造，拒绝。
2. LLM 审查 fail-closed：解析失败 / 异常 → 保守拒绝。
3. LLM prompt 增加自导自演判定标准。

## 验证

单元验证 3 场景全部符合预期（自导自演拒绝 / 真实解密放行 / 凭空编造拒绝）。
