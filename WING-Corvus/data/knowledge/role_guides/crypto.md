# Crypto 题型分工指南 (Role Guide)

> 维护规则: 本文件**只改不增** — 不新增 skill, 只在现有段落上完善; 篇幅 ≤4KB.
> 注入规则: 按当前阶段 (P1~P4) 只注入对应段落, 压缩上下文避免分心.

## P1 侦查 (Recon)

**目标**: 拿到加密脚本/参数/密文, 确定加密类型与攻击面.

**工具链**: `ssh_exec` (读源码/附件) → `crypto_rsa`/`crypto_classic` (本地识别) → `ssh_python` (试跑脚本).

- 必读加密脚本源码: 记录 密钥长度/生成方式/随机源/交互协议 (如 LWE 题 b=A·s+e mod q 的参数与泄露项)
- 识别加密族: RSA (N/e/c 大小、d 泄露、多模数)/分组密码 (模式/IV/密钥)/流密码 (keystream 复用)/格密码 (LWE/NTRU)/签名 (nonce 复用)
- 远程交互题: 观察能拿到的 oracle (加密/解密/验证/前缀预言), 记录每个 oracle 的输入输出
- **交互回显型程序先"运行+回显"**: 若程序输出自包含逻辑/要你提交某个计算值 (见通用规则), 正解常为本地算出发回远程

**推进标准**: 确认加密类型 + 可利用弱点 (参数过小/已知部分/预言机) → 进入 P2.

## P2 漏洞确认 (Identify)

**目标**: 确认攻击模型并验证可行性.

**工具链**: `crypto_rsa` (RSA 攻击族) → `lwe_decode` (已知 |e| 恢复 s) → `sage_tool`/`ssh_python` (fpylll/z3) → `ecdsa_tool`.

- RSA: 试小 d (Wiener)/共模/低指数/已知 p+q 高位 (Herrmann-May Coppersmith)/p 相近 (Fermat)
- 格攻击: 确认 LWE 是否泄露 |e| → 用 lwe_decode data_file 模式 (大矩阵) + 数学验证 (A·s+e≡b mod q)
- 分组: 看 CBC 字节翻转/ECB 相同块/IV 复用; 流密码: keystream 复用 XOR
- 先本地用题给参数验证攻击可行, 再上远程 oracle

**推进标准**: 攻击模型验证成功 (能恢复明文/密钥/私钥) → 进入 P3.

## P3 利用 (Exploit)

**目标**: 恢复明文/密钥, 解密出 flag.

**工具链**: `ssh_python` (LLL/fpylll/z3/求解脚本) → `lwe_decode` → `crypto_rsa` → `encoding_helper`.

- 数学结果必须**确定性验证** (如 pow(m,e,N)==c), 杜绝幻觉/猜测
- 大矩阵/大数据用文件模式, 不用手填; 求解失败先检查参数装配 (维度/进制/mod)
- 远程交互: 提交恢复的密钥/答案, 观察是否返回 flag
- 每个攻击脚本保留成功样本, 失败改单参数

**推进标准**: 工具观测到 flag 文本或解密输出 → 进入 P4.

## P4 验证提交 (Validate)

**目标**: 确认 flag 真实可用并提交.

- flag 必须真实出现在工具输出中才能提交; 提交前用数学验证 (解密后明文可读/校验匹配)
- 无工具调用直接 Final Answer = 幻觉 (系统会拒绝)
- 拿不到 → Final Answer 老实报告已尝试方法, 不编造
