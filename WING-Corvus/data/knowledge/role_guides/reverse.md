# Reverse 题型分工指南 (Role Guide)

> 维护规则: 本文件**只改不增** — 不新增 skill, 只在现有段落上完善; 篇幅 ≤4KB.
> 注入规则: 按当前阶段 (P1~P4) 只注入对应段落, 压缩上下文避免分心.

## P1 侦查 (Recon)

**目标**: 确定二进制架构/壳/保护, 定位核心校验逻辑.

**工具链**: `ssh_exec` (file/checksec/strings/readelf) → `binary_analyze` (结构化反汇编) → `ssh_python` (提取关键字符串).

- 先 `file` 看架构 (ELF/PE/APK/固件) 与是否加壳; 加壳先找脱壳点 (upx 等)
- `strings` 找 flag 格式/关键比较字符串/提示; 附件常含脚本/注释
- **交互回显型程序先"运行+回显"**: 若程序输出自包含逻辑/要你提交某个值 (见通用规则), 正解常为本地运行取答案发回, 不是纯逆向

**推进标准**: 已知架构/保护 + 定位到核心函数 (校验/解密/生成) → 进入 P2.

## P2 逻辑分析 (Identify)

**目标**: 还原核心算法 (校验条件/解密流程/序列生成).

**工具链**: `binary_analyze` (反汇编关键函数) → `angr_symbolic_exec` (符号执行) → `ssh_python` (z3 求解).

- 找 main/校验函数: 入口 → 主流程; 用 `angr_symbolic_exec` 直接求解约束 (flag 校验类)
- 识别算法: 加密 (AES/DES/Feistel/RC4/魔改) / 编码 (base64/异或/位移) / 数学 (RSA/ECC)
- 动态观察: gdb/strace 看输入输出; 数据流: 输入 → 变换 → 比较
- 常量提取: S 盒/密钥/IV/魔数 都要从二进制准确取出, 不猜

**推进标准**: 算法还原到可写脚本复现 (输入→预期输出) → 进入 P3.

## P3 求解 (Exploit)

**目标**: 逆推 flag/满足校验的输入.

**工具链**: `ssh_python` (z3/py 逆算法) → `angr_symbolic_exec` → `encoding_helper`/`crypto_tool` (解码).

- 校验类: angr 求 path 约束 / z3 解方程; 魔改算法先还原成标准形式再逆
- 解密类: 用工具解密得到明文/flag; 结果必须可复现验证 (重跑加密比对)
- 远程交互: 提交算出的值/flag, 观察响应; 大运算用 timeout=long/background

**推进标准**: 工具观测到 flag 文本或满足校验的输入 → 进入 P4.

## P4 验证提交 (Validate)

**目标**: 确认 flag 真实可用并提交.

- flag 必须真实出现在工具输出中才能提交; 校验类题提交前用本地校验函数验证输入合法
- 无工具调用直接 Final Answer = 幻觉 (系统会拒绝)
- 拿不到 → Final Answer 老实报告已尝试方法, 不编造
