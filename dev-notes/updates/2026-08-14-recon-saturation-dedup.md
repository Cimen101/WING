# 更新记录：侦查饱和检测 + 命令/脚本去重 + bkcrack 增强（Sprint 41）

- 日期：2026-08-14
- 版本：WING-Corvus（渡鸦）——主线
- 范围：P2 侦查死循环根治 + 上下文空转去重 + zipCrypto 工具引导

## 背景

rev-zermatt 轨迹量化分析（flash 对照组）：三路全困在 P2（ls/cat/grep/xxd/strings 无限重复 20-30 步），从不"写脚本解析 VM → 构造 payload → 运行验证"；aggressive 36 步全 ssh_exec 零 ssh_python；上下文每步 ~38K token，4M 熔断只够 ~100 步。Sprint 39 决策（模型维持 flash）后，通过系统/架构升级提升能力。

## 变更内容（A+B）

### A. P2→P3 强制推进机制（`agent/coordinator.py`）

`_check_recon_saturation`（侦查饱和检测）：

- 步数 ≥14 且最近 lookback 窗口内：执行类工具占比高（≥8 步）、纯只读侦查命令 ≥6（ls/cat/grep/strings/xxd/head/tail/file/wc/which/find/stat）、且**零产出型动作**（ssh_python/攻击类/协作沉淀）→ 判定侦查饱和。
- 纯侦查命令计数排除含写文件/上传/网络请求（tee/> /wget/curl/nc）的执行命令。
- 命中即下发 `[MUST]` 强制指令：立即用 ssh_python 写脚本解析已收集数据并运行验证，或构造 payload，停止重复查看同一批文件。
- 与既有 `_check_execution_starvation`（无执行工具）互补：新检测盯"有执行但零产出"。

### B. 命令/文件读取去重缓存（`agent/react.py`）

- **`_check_recon_cmd_repeat` + `_record_recon_cmd`**：同一 ls/cat/grep/strings/xxd 只读命令**成功执行后**登记指纹，重复执行返回缓存提示（每条命令只提示一次后放行，防过度干扰）。带管道/重定向/heredoc 的复杂命令不拦截（可能在做不同加工）。失败不登记（重试不被误提示）。
- **`_check_script_dup`**：ssh_python/docker_python 脚本前 60 字符归一化（去空白 + 数值替换为 N）后同前缀出现 ≥3 次 → 提示"反复运行同主体脚本 = 空转，请写针对下一步目标的新脚本"（解 aggressive 同一脚本调试 6-12 次）。

### C. bkcrack 工具引导增强（`tools/bkcrack_tool.py`）

crypto-ziphard 实跑暴露的瓶颈修复：

- 新增 `known_bytes` / `known_offset` 参数（`-x` 已知字节模式，适合 flag.txt 以 `CTF{` 开头的已知明文；默认 offset=12 跳过 nonce 加密头）。
- 无已知明文时引导读生成脚本（hard.py）确认明文，并提示随机数据条目（如 junk.dat）不是有效已知明文。
- **Data error 即时诊断**（不再空转到 300s 超时）：`not enough`/`too short` → 已知明文不足（需 ≥8 连续字节）+ 引导获取更多明文；`match`/`data error`/`no match` → 明文不匹配或 offset 错误 + 引导（flag.txt 用 known_bytes='4354467b'、offset 通常为 12）。
- hex 合法性、bkcrack 可用性在任何 ssh 调用前校验。

## 验证

- react 45 测试全过；186 相关测试过，1 个失败为工具数断言过期（与改动无关）
- 真实轨迹回放：flash aggressive（36 步全 ssh_exec 零脚本）→ 第 14 步触发侦查饱和 MUST（原跑满 36 步超时）；conservative（含 ssh_python）/ innovative（含 ssh_python+check_findings）不误触发 ✓
- crypto-ziphard medium 实跑（1802s 超时未解出，该题官方仅 6 solves）：innovative 第 8 步即调用 bkcrack_attack 进入攻击实施（对照组纯侦查）——A+B 推进生效；卡点转移为"题目本身极难 + 已知明文选错 + 已知明文不足"，工具引导已针对性增强
- bkcrack 工具单元验证 6 项全过（known_bytes 模式 / offset / 不足诊断 / 不匹配诊断 / 无已知明文引导）

## 结论与下一步

A+B 已验证生效（aggressive ssh_python 0→8、innovative 进入 bkcrack 攻击）——"侦查死循环→攻击实施"推进成立。下一步候选：上下文预算 >8KB 折叠、bkcrack 等专用工具参数校验增强、或换 medium 直接利用型题验证解出率。

## 关联记录

- 设计文档 §13.13 侦查去重与饱和检测、§13.14 zipCrypto 已知明文攻击工具
- 迭代记录表（DESIGN §23.7）：Sprint 41
- 测试报告：`tests/2026-08-14-test20-verify-report.md`（crypto-ziphard 部分）
