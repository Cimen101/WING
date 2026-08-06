# Pwn 题型分工指南 (Role Guide)

> 维护规则: 本文件**只改不增** — 不新增 skill, 只在现有段落上完善; 篇幅 ≤4KB.
> 注入规则: 按当前阶段 (P1~P4) 只注入对应段落, 压缩上下文避免分心.

## P1 侦查 (Recon)

**目标**: 拿到二进制/源码与保护信息, 确定程序入口与交互协议.

**工具链**: `ssh_exec` (ls /challenge/workspace, checksec, file) → `ssh_python` (连接远程观察菜单) → `binary_analyze` (结构化反汇编).

- 必跑 checksec: 记录 NX/PIE/Canary/RELRO/FORTIFY; PIE+Canary = 需要泄露基址/栈保护绕过
- 附件必读: 源码/README 常直接给漏洞点; ELF 用 `file`/`readelf -h` 看架构与入口
- 远程交互先完整走一遍菜单 (每个选项都试), 记录输入→输出行为
- **交互回显型程序先"运行+回显"**: 若程序输出 base64/自包含程序、要你猜数字或回显答案 (见通用规则), 正解常为运行提取程序取答案发回远程, 不是找溢出

**推进标准**: 已知保护 + 漏洞类型候选 (栈溢出/格式化字符串/UAF/整数溢出) + 输入点 → 进入 P2.

## P2 漏洞识别 (Identify)

**目标**: 定位具体可利用原语 (溢出偏移/格式化参数/堆布局).

**工具链**: `ssh_python` (pwntools 探测) → `binary_analyze`/objdump (确认关键函数地址) → gdb (动态验证).

- 栈溢出: 用 pattern 找偏移 (cyclic), 确认能否覆盖返回地址/栈上参数
- 格式化字符串: 逐参数偏移试 `%p` 泄露栈/地址; canary 高字节 \x00 会截断 printf 时改逐字节爆破或换泄露途径
- UAF/堆: 分析 alloc/free 时序, 找 double-free/off-by-null
- 远程探测与本地一致: 先本地 process() 复现, 再 remote() 打靶

**推进标准**: 漏洞原语确认 (能改变执行流/泄露地址) → 进入 P3.

## P3 利用 (Exploit)

**目标**: 构造 exploit 拿到 RCE/读取 flag.

**工具链**: `ssh_python` (pwntools 一次性写完) → `exploit_template` (骨架) → `binary_analyze` (查 gadgets).

- 泄露后算基址: leaked=0x..., base=leaked-offset, 再算 target=base+offset, 写入 Thought
- PIE 绕过: 部分覆盖返回地址低字节 / 泄露一处地址算基址; canary 泄露后原样回填
- 复杂 exploit 用 `timeout=long/background` 跑, 不要死等; 远程无回显时用时间盲注/报错区分
- 每个尝试都保留成功样本, 失败改单参数, 不整套重写

**推进标准**: 工具观测到 flag 文本或拿到 shell → 进入 P4.

## P4 验证提交 (Validate)

**目标**: 确认 flag 真实可用并提交.

- flag 必须真实出现在工具输出中才能提交; 提交被驳回 → 基于反馈换答案/换利用链
- 无工具调用直接 Final Answer = 幻觉 (系统会拒绝)
- 拿不到 → Final Answer 老实报告已尝试方法, 不编造
