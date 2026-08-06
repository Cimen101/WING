# Web 题型分工指南 (Role Guide)

> 维护规则: 本文件**只改不增** — 不新增 skill, 只在现有段落上完善; 篇幅 ≤4KB.
> 注入规则: 按当前阶段 (P1~P4) 只注入对应段落, 压缩上下文避免分心.

## P1 侦查 (Recon)

**目标**: 拿到页面入口与全部可观察线索, 缩小攻击面.

**工具链**: `web_recon` (指纹+敏感路径) → `http_request` (细读 HTML/JS) → `ssh_exec` (读附件源码).

- 首页 HTML 的 form/input/button 就是真实入口: 读前端 JS (search.js/app.js) 看请求格式与参数名
- 必查 robots.txt / .git / .env / 源码; 附件目录 `ls -la /challenge/workspace/` 必读 (README/协议文档=关键线索)
- 所有路径返回相同 fallback 页 ≠ 纯静态: 返回首页细读找真实端点, 不要继续爆破
- 目录爆破不超过 5 步: 爆破无果且页面有交互元素时, 100% 回头分析页面本身

**推进标准**: 已确认 1 个可交互入口 + 参数名 → 进入 P2. 无入口 → 继续 P1 补侦查, 不空转.

## P2 漏洞识别 (Identify)

**目标**: 判断漏洞类别 (注入/SSTI/反序列化/LFI/SSRF/上传/框架漏洞).

**工具链**: `http_request` (参数测试) → 对比基线 → `ssh_exec`/`ssh_python` (本地复现).

- 参数测试要"对比基线": 先记正常响应 (长度/body), 再逐参数变化; 参数导致响应变化 = 进入后端逻辑, 立即深挖
- 识别框架后查已知漏洞链 (ThinkPHP/Laravel/SSTI payload), 源码分析不超过 5 步
- 页面标题/注释/提示文本 = 核心线索 ("PHP 模拟解释器"→eval; "Unable to open file!"→文件读取)

**推进标准**: 确认漏洞类别 + 利用向量 → 进入 P3. 假设验证 ≥2 次不成立 = 证伪, 立即切换方向.

## P3 利用 (Exploit)

**目标**: 构造 payload 拿 RCE/任意读/flag.

**工具链**: `ssh_python` (一次性写完整脚本) → `http_request` (发送) → `encoding_helper`/`base64_encode`.

- 复杂命令 (含嵌套引号/XML) **优先 base64**: 本机编码后 `echo <b64> | base64 -d | bash`
- 无回显 (盲注/无输出 RCE): 时间盲注 / 报错注入 / 写文件再读 (static/out.txt) / DNS 外带; 绝不编造 flag
- 上传查杀绕过: 短标签 `<?=` + 非黑名单函数 (`exec`/`file_get_contents`), 读多行用 `file_get_contents`
- 多候选 flag 必须全部读取比对: 按题目标题匹配 `/flag_<关键词>`, 不深挖无关遗留文件 (诱饵)

**推进标准**: 工具观测到 flag 文本 → 进入 P4. 同一利用向量失败 2 次 → 换向量.

## P4 验证提交 (Validate)

**目标**: 确认 flag 真实可用并提交.

- flag 必须**真实出现在工具输出**中才能提交; 提交前用 verify 接口/再读一次确认
- 无工具调用直接 Final Answer = 幻觉 (系统会拒绝); 提交被驳回 → 基于反馈换不同答案
- 拿不到 → Final Answer 老实报告已尝试方法, 不编造

**推进标准**: 提交成功即结束; 提交次数用完 → 回 P3 换路径.
