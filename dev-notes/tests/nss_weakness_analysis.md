# NSS Runner 未解出题目弱势分析报告（排除 API 因素）

> 数据来源: `data/nss_logs/hub_20260817_233511.log` (2026-08-17 23:35 ~ 2026-08-18 10:18)
> 分析: 11 个未解出题目，逐一排除 API 因素（LLM 超时），定位真实解题能力弱势

## 一、未解出题目分类

| 题目 | 题型 | 未解出主因 | 是否 API 因素 |
|------|------|-----------|--------------|
| #4836 | Misc/medium | Stream Deck 宏键盘解码失败 | ❌ 纯能力 |
| #4841 | Reverse/medium | 算法识别错误（DES 误判） | ❌ 纯能力 |
| #4848 | Crypto/medium | **三路全 LLM 超时** | ✅ API |
| #4853 | Web/medium | PHP 反序列化 POP 链未完成 | ⚠️ 部分 API |
| #4856 | Web/medium | 文件上传绕过未完成 | ⚠️ 部分 API |
| #4859 | Web/medium | **三路全 LLM 超时** | ✅ API |
| #4862 | Crypto/medium | **三路全 LLM 超时 + 靶机不可达** | ✅ API |
| #4868 | Reverse/medium | PE 资源解码 + 工具缺失 | ❌ 纯能力 |
| #4875 | Reverse/medium | Brainfuck 模拟器 cell size 错误 | ❌ 纯能力 |
| #4879 | Reverse/medium | Windows PE 反调试 + RC4 | ❌ 纯能力（用户停止） |

**排除 API 因素后，真实能力弱势题目：7 个**（#4836/#4841/#4868/#4875/#4879 纯能力 + #4853/#4856 部分能力）

---

## 二、各题弱势分析

### 1. #4836 Misc — Stream Deck 宏键盘解码（纯能力弱势）

**题目本质**：USB 流量不是常规键盘/鼠标，而是 **Elgato Stream Deck 宏键盘**。115 张 120x120 PNG 图标（按钮显示字符）+ 33 个按钮按下位置序列。flag = 按钮序列映射到图标字符。

**轨迹表现**：
- 三路 agent 都正确识别出 Stream Deck 设备（✅ 设备识别能力 OK）
- 但**卡在解码**：在"OCR 图标字符"和"按钮序列解码"之间反复切换
- innovative 提交 `suctf{have_fun!}`（字符串描述符，诱饵）失败
- 未正确建立"按钮位置 → 图标字符"的映射关系

**弱势**：**非标准设备/协议的定制解码能力弱**。没有通用模板，需要自定义分析按键编码。agent 识别出设备但无法完成"按钮序列 + 图标映射"的复合解码。

---

### 2. #4841 Reverse — 算法识别错误（纯能力弱势）

**题目本质**：stripped ELF，CFG 简单（branches=0, loops=0），核心是**自定义 base64 字母表**解码。

**轨迹表现**：
- 三路 agent 都误判为 **DES 加密**（看到 OpenSSL DES 特征）
- 巡查器明确指出"CFG简单(无循环)，不太可能使用复杂DES/RC4，base64字母表是最直接的线索"
- 但 agent 在 DES/RC4 上反复尝试，浪费大量步数

**弱势**：**算法识别能力弱**。看到 OpenSSL DES 符号就误判为 DES 加密，没有结合 CFG 复杂度判断实际算法。这是典型的"符号误导"——库函数符号 ≠ 核心算法。

---

### 3. #4868 Reverse — PE 资源解码 + 工具缺失（纯能力弱势）

**题目本质**："RE-URL从哪儿来"。PE 文件 .rsrc 资源数据解码后得到 URL，用 `InternetOpenUrlA` 获取。

**轨迹表现**：
- aggressive 正确识别出 `InternetOpenUrlA` 导入（✅ 导入表分析 OK）
- 但**卡在 URL 构造**（从 .rsrc 资源数据解码）
- **radare2 未安装在容器中**（工具不可用）
- **巡查误拦截**：`re.finditer` 包含 "find" 被禁忌拦截（`find` 被加入禁忌列表，误伤 Python 的 `re.finditer`）

**弱势**：
- **PE 资源段（.rsrc）解码能力弱**
- **工具缺失**（radare2 未装）
- **禁忌列表误伤**：`find` 关键词误拦截 Python 的 `re.finditer`（设计缺陷）

---

### 4. #4875 Reverse — Brainfuck 模拟器 cell size 错误（纯能力弱势）

**题目本质**："这是什么语言呢"。Brainfuck 逆向题：bf_code.txt 校验程序 + PyInstaller 打包的 Python 解释器（brainfuck.pyd）。

**轨迹表现**：
- aggressive 正确识别出 Brainfuck + 需要"内置 BF 模拟器，用步数侧信道爆破 flag"（✅ 思路正确）
- conservative 卡在"所有字符都输出 nonono"——**BF 模拟器 cell size 配置错误**（`bits` 参数）
- swarm 复盘检测到幻觉，skill 未入库

**弱势**：**自定义解释器/VM 的模拟执行能力弱**。识别出 Brainfuck 但模拟器 cell size 配置错误，导致所有输入输出相同。需要更精确的 VM 语义还原。

---

### 5. #4879 Reverse — Windows PE 反调试 + RC4（纯能力弱势）

**题目本质**：DbgIsFun.exe，32 位 Windows PE，带 TLS 反调试。假 flag 校验 `input[i]^i == "WsmmcCjfo"` → "WrongFlag"；0x4010f0 有 XOR 解密启动代码，解密后是 RC4 初始化，密钥 "GKCTF"。

**轨迹表现**：
- aggressive 正确识别出假 flag 校验 + XOR 解密启动代码 + RC4 密钥 "GKCTF"（✅ 逆向分析能力 OK）
- 需要动态模拟（Unicorn）或找到真实 RC4 密文数据
- **用户手动停止**（收到停止指令）

**弱势**：**Windows PE 动态执行/模拟能力弱**（Linux 环境无法直接运行 PE，需 Unicorn 模拟）。agent 已识别出核心逻辑但无法动态验证。

---

### 6. #4853 Web — PHP 反序列化 POP 链（部分能力弱势）

**题目本质**："POWER!!" Image Viewer，Apache+PHP 7.4.30。PHP 反序列化 Backdoor 链。

**轨迹表现**：
- aggressive 只跑 7 步就因 LLM 超时终止（API 因素）
- conservative 29 步、innovative 17 步，识别出 Backdoor 链 + FileViewer 外层（✅ 思路正确）
- 但**卡在远程触发 fatal error**（类属性名差异/HTTP 触发细节）

**弱势**：**PHP 反序列化 POP 链的远程触发调试能力弱**。本地验证可行但远程 fatal error，无法快速定位差异。

---

### 7. #4856 Web — 文件上传绕过（部分能力弱势）

**题目本质**："chmod 740 /flag"。文件上传绕过（.user.ini / .htaccess / null 字节）。

**轨迹表现**：
- conservative 8 步、aggressive 2 步都因 LLM 超时终止（API 因素）
- innovative 23 步，识别出 `urldecode($_FILES['file']['name'])` + null 字节截断（✅ 思路正确）
- 但**未完成 .user.ini%00.jpg 截断上传验证**（1500s 超时）

**弱势**：**文件上传绕过的验证效率低**。识别出 .user.ini 截断但验证耗时过长。

---

## 三、能力弱势总结

### 按题型

| 题型 | 解出率 | 弱势 |
|------|--------|------|
| **Reverse** | 2/6 (33%) | **最弱**：算法识别、PE 资源解码、VM 模拟、Windows PE 动态执行 |
| **Misc** | 0/1 (0%) | 非标准设备定制解码 |
| **Web** | 4/8 (50%) | PHP 反序列化远程触发、文件上传验证效率 |
| **Crypto** | 4/6 (67%) | 主要受 API 因素影响 |
| **Pwn** | 4/4 (100%) | 无弱势 |

### 核心弱势（按严重度）

1. **算法识别错误**（#4841）：看到 OpenSSL DES 符号就误判，未结合 CFG 复杂度。→ 需增强"符号 ≠ 核心算法"判断
2. **自定义解释器/VM 模拟**（#4875）：Brainfuck 模拟器 cell size 错误。→ 需增强 VM 语义还原
3. **PE 资源段解码**（#4868）：.rsrc 资源数据解码能力弱。→ 需增强 PE 资源分析
4. **Windows PE 动态执行**（#4879）：Linux 环境无法运行 PE，需 Unicorn 模拟。→ 需增强 PE 动态模拟
5. **非标准设备定制解码**（#4836）：Stream Deck 宏键盘无通用模板。→ 需增强设备识别后的定制解码
6. **PHP 反序列化远程触发**（#4853）：本地可行但远程 fatal error。→ 需增强远程调试

### 系统设计缺陷（非解题能力）

1. **禁忌列表误伤**（#4868）：`find` 关键词误拦截 Python 的 `re.finditer`。→ 需精确匹配，避免误伤
2. **工具缺失**（#4868）：radare2 未安装在容器中。→ 需补装工具
3. **swarm 复盘幻觉检测**（#4875）：no_hallucination=False 时 skill 未入库，经验无法沉淀。→ 需改进幻觉检测

---

## 四、结论

排除 API 因素后，**真实能力弱势集中在 Reverse 题型**（2/6 解出率）：
- **算法识别**（符号误导）
- **自定义 VM/解释器模拟**
- **PE 资源解码 + Windows PE 动态执行**

其次是 **Misc 非标准设备定制解码** 和 **Web 反序列化远程触发**。

这些是解题能力的真实短板，需要针对性增强工具和提示词。
