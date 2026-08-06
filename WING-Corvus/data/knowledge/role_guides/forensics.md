# Forensics 题型分工指南 (Role Guide)

> 维护规则: 本文件**只改不增** — 不新增 skill, 只在现有段落上完善; 篇幅 ≤4KB.
> 注入规则: 按当前阶段 (P1~P4) 只注入对应段落, 压缩上下文避免分心.

## P1 侦查 (Recon)

**目标**: 判断取证物类型 (磁盘/内存/流量/文件系统) 与线索载体.

**工具链**: `ssh_exec` (file/strings/binwalk/tshark) → `mem_xor_analyzer` (内存 dump) → `osint_tool`.

- 附件类型: pcap/raw disk/mem dump/加密压缩包/损坏文件 → 决定工具链
- `strings` 全量扫: flag 特征/URL/文件名/命令痕迹
- 看文件头 (magic) 判断真实类型; 扩展名可疑时先 `file`

**推进标准**: 确认载体类型 + 至少一条可解析线索 → 进入 P2.

## P2 提取与分析 (Identify)

**目标**: 从载体中提取隐藏数据/重建文件.

**工具链**: `ssh_exec` (binwalk 拆/foremost/tshark/volatility) → `ssh_python` (自定义解析) → `ocr_tool`.

- 流量: tshark 过滤 HTTP/DNS/SMB; 导出对象/凭据/上传文件; 看加密流量找密钥交换
- 磁盘: 挂载/解析分区, 找删除文件/残留/日志; 压缩包爆破 (弱口令/掩码)
- 内存: volatility 枚举进程/网络/文件, 找 flag 明文或密钥; 异或加密用 mem_xor_analyzer 分析
- 图片/音频隐写: 元数据/追加数据/频谱/LSB

**推进标准**: 定位到 flag 或最终解密所需材料 → 进入 P3.

## P3 重建与求解 (Exploit)

**目标**: 还原文件/解密出 flag.

**工具链**: `ssh_python` (重建/解密脚本) → `encoding_helper` → `ocr_tool`.

- 损坏/拼接文件: 按格式规范修复头/补齐数据; 用已知格式校验 (PNG chunk/ELF header)
- 解密: 用提取的密钥/IV 解密得到 flag; 结果必须可复现验证
- 多层线索: 每层都记录证据来源, 避免幻觉拼接

**推进标准**: 工具观测到 flag 文本 → 进入 P4.

## P4 验证提交 (Validate)

**目标**: 确认 flag 真实可用并提交.

- flag 必须真实出现在工具输出中才能提交; 提交被驳回 → 检查格式/提取完整性
- 无工具调用直接 Final Answer = 幻觉 (系统会拒绝)
- 拿不到 → Final Answer 老实报告已尝试方法, 不编造
