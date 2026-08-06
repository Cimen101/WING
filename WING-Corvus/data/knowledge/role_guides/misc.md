# Misc 题型分工指南 (Role Guide)

> 维护规则: 本文件**只改不增** — 不新增 skill, 只在现有段落上完善; 篇幅 ≤4KB.
> 注入规则: 按当前阶段 (P1~P4) 只注入对应段落, 压缩上下文避免分心.

## P1 侦查 (Recon)

**目标**: 判断题目子类 (隐写/编码/取证/脑洞/交互), 列出全部线索.

**工具链**: `ssh_exec` (file/strings/xxd/binwalk/tshark) → `encoding_helper` (试编码) → `ssh_python` (解析).

- 附件先 `file` + `strings`: 找隐藏文本/URL/flag 特征/多重压缩
- 常见子类: 隐写 (图片/音频/视频)、编码 (base64/hex/摩斯/凯撒/栅栏)、流量 (pcap)、脑洞 (题目描述即线索)、交互 (nc/程序回显)
- **交互回显型程序先"运行+回显"**: 若程序输出自包含逻辑/要你提交某个值 (见通用规则), 正解常为本地运行取答案发回远程

**推进标准**: 确认子类 + 至少一条线索 → 进入 P2.

## P2 深入解析 (Identify)

**目标**: 解析线索链 (一层层解到明文).

**工具链**: `encoding_helper` (多层编码) → `ssh_exec` (binwalk 拆文件/exiftool 元数据) → `ocr_tool` (图片文字) → `ssh_python` (自定义脚本).

- 多层编码: 一层层试解码, 每次记录结果; 常见链 base64→hex→栅栏→凯撒
- 隐写: 图片看 EXIF/追加数据/LSB; 音频听频谱/慢放; binwalk 拆嵌套
- 流量: tshark 过滤 HTTP/DNS/文件导出; 看对象/凭据/flag 明文
- 交互/远程: 观察协议, 收集 oracle 输出; 按提示逐轮作答

**推进标准**: 定位到最终编码/生成逻辑 → 进入 P3.

## P3 求解 (Exploit)

**目标**: 解出 flag.

**工具链**: `ssh_python` (自定义解码/爆破) → `encoding_helper` → `ocr_tool`/`osint_tool`.

- 编码类: 写出完整解码链脚本, 一步到位; 结果可复现
- 爆破类: 字典/穷举用 timeout=long/background, 不阻塞
- 交互类: 正确响应 oracle 拿 flag; 复杂逻辑 (如猜数字) 用脚本自动应答
- 卡住时可用 web_search 查该编码/交互机制的通用做法 (合规搜索, 只查通用原理)

**推进标准**: 工具观测到 flag 文本 → 进入 P4.

## P4 验证提交 (Validate)

**目标**: 确认 flag 真实可用并提交.

- flag 必须真实出现在工具输出中才能提交; 提交被驳回 → 检查格式/解码链是否有误
- 无工具调用直接 Final Answer = 幻觉 (系统会拒绝)
- 拿不到 → Final Answer 老实报告已尝试方法, 不编造
