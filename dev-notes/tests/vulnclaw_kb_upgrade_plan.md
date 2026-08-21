# VulnClaw 知识库借鉴与 WING 升级规划

> 目标：深入分析 VulnClaw 项目，找出值得 WING 学习、参考、复用的部分，将 VulnClaw 知识库中有而 WING 没有的内容补充上去并做好适配。
> 原则：**不是一味地增加功能，而是在原系统基础上改进；优化架构而不是打补丁或增添式开发。**
> 范围：本次只做**知识库的扩充与升级规划**。VulnClaw 是"漏洞挖掘 + CTF 解题"项目，部分内容（如渗透测试方法论、CVE 库、红队流程）WING 用不到，先保存但**不实装**，作为未来方向拓展后的知识库储备。

---

## 一、VulnClaw 项目概览

VulnClaw 是 AI 驱动的渗透测试 CLI 工具（Python 3.10+，MIT 协议），核心架构：

| 模块 | 说明 |
|------|------|
| **solve 引擎** | 模型主导循环，AgentState 证据记忆 + 反幻觉闸门 |
| **Skill 参考索引** | `skills/loader.py` + `resolver.py`，只解析相关参考资料，不注入强制流程 |
| **结构化 KB** | `kb/store.py` + `retriever.py`，JSON 五类存储（cve/techniques/protocols/tools/payloads）+ ChromaDB 语义检索 + 关键词 TF-IDF 回退 |
| **MCP 工具链** | fetch/memory/chrome-devtools/burp 四服务 |
| **插件体系** | 低耦合漏洞检测插件运行时 |

**知识库核心**：`vulnclaw/skills/` 下的 Skill 参考索引（core 7 个 + specialized 16 个），每个 Skill 有 `SKILL.md`（frontmatter 含 typed routing 元数据）+ `references/`（详细方法论文档）。

---

## 二、WING 知识库现状（对比结论）

### 2.1 WING 已具备且强于 VulnClaw 的部分

经过逐文件对比，**WING 的知识库在内容深度上已经超过 VulnClaw**：

1. **知识深度**：WING 的 packages 覆盖更全面、更深入
   - crypto：含 2026 年最新攻击（Manger's attack、Polynomial CRT、Affine cipher over non-prime modulus 等），VulnClaw 只有经典 RSA 速查
   - web：含 PHP 伪协议、双写绕过、命令注入绕过、RCE 长度限制绕过等**全部 payload 值**，与 VulnClaw 相当甚至更全
2. **分层架构**：WING 有 role_guides（分题型×风格×P1-P4 阶段）+ playbooks + pitfalls + patterns + structured + tool_catalog 七层，比 VulnClaw 的"KB + Skill"两层更精细
3. **实战沉淀**：WING 有从真实轨迹自动沉淀的 playbooks/pitfalls（curator 管线），VulnClaw 没有

### 2.2 WING 缺失、VulnClaw 值得借鉴的部分（架构层面）

**核心结论：WING 缺的不是"知识内容"，而是"知识路由与按需加载的架构能力"。**

| 缺口 | VulnClaw 的做法 | WING 现状 |
|------|----------------|-----------|
| **① 判题路由层** | typed routing 元数据驱动的**确定性 skill 选择器**：根据题目特征（如"参数接受文件名"→ php://filter）自动打分选择最匹配的 skill bundle | `retrieve()` 是"按题型+阶段"**粗粒度注入**，无"题目特征→攻击方法"的细粒度路由 |
| **② 按需加载机制** | `load_skill_reference` 工具，让 agent 按需读取 skill 的 references 文件 | `package_topics()` 只返回 SKILL.md 简介，**agent 无法按需读取 package 内具体主题文件** |
| **③ 判题决策树** | 各 SKILL.md 有"题目特征 → 可能攻击/考点"的快速判题映射表 | packages 是"知识"但缺"判题路由"决策表 |
| **④ CTF 特有流程** | flag 位置优先级、highlight_file 输出顺序陷阱、CTFd API 操作 | 部分有（web SKILL.md 有 flag 位置），但缺 CTFd API、highlight_file 陷阱等 |

---

## 三、升级规划（架构优化，非打补丁）

### 方向一：判题路由层（架构增强，最高优先级）

**问题**：WING 的 `retrieve()` 按题型+阶段粗粒度注入 role_guides，但**无法根据题目具体特征**（如"参数接受文件名"、"e=3"、"eval 长度限制"）自动选择最匹配的知识主题。agent 拿到的是"该题型该阶段的通用策略"，而非"针对这个具体题目的攻击方法"。

**方案**：借鉴 VulnClaw 的 typed routing 元数据机制，为 WING 增加**判题路由层**：

1. **新增 `data/knowledge/routing/` 目录**，存放各题型的判题路由元数据（JSON）：
   ```json
   {
     "web": {
       "routing_rules": [
         {
           "trigger": ["参数接受文件名", "file=", "page=", "include", "require"],
           "attack": "PHP 伪协议读文件",
           "payload": "php://filter/read=convert.base64-encode/resource=flag.php",
           "topic": "ctf-web/core_input_processing.md"
         },
         {
           "trigger": ["eval", "长度限制", "strlen"],
           "attack": "RCE 长度限制绕过",
           "payload": "eval($_GET['A']);&A=system('cat /flag');",
           "topic": "ctf-web/dynamic_module_processing.md"
         }
       ]
     },
     "crypto": {
       "routing_rules": [
         {
           "trigger": ["e=3", "小指数", "e 很小"],
           "attack": "RSA 小指数攻击",
           "topic": "ctf-crypto-1.0.0/rsa-attacks.md"
         },
         {
           "trigger": ["n 相同", "共模", "多组"],
           "attack": "RSA 共模攻击",
           "topic": "ctf-crypto-1.0.0/rsa-attacks.md"
         }
       ]
     }
   }
   ```

2. **在 `kb.py` 的 `retrieve()` 中增加判题路由逻辑**：解析 task 文本，匹配 routing_rules 的 trigger 关键词，命中则注入对应的攻击方法 + payload + 主题文件路径。

3. **判题路由与现有分层的关系**：判题路由是**新增的一层**，位于 role_guides（粗粒度）和 packages（知识内容）之间，作为"题目特征 → 攻击方法"的桥接。不修改现有 role_guides/packages，只新增 routing 层并在 `retrieve()` 中组装。

**为什么是架构优化而非打补丁**：这是给知识库增加一个**缺失的路由维度**（从"按题型"到"按题目特征"），而不是往现有文件里塞内容。它让知识库从"被动注入"升级为"主动路由"。

### 方向二：按需加载 package 主题文件（架构增强）

**问题**：WING 的 `package_topics()` 只返回 SKILL.md 简介，agent 无法按需读取 package 内具体主题文件（如 rsa-attacks.md 的完整攻击代码）。这导致 agent 只能看到"有哪些主题"，无法获取"具体怎么做"。

**方案**：借鉴 VulnClaw 的 `load_skill_reference`，为 WING 增加**按需加载 package 主题文件**的工具：

1. **新增工具 `load_kb_topic`**（或复用现有工具机制）：接受 `challenge_type` + `topic` 参数，返回对应 package 主题文件的完整内容。
2. **在 `kb.py` 中新增 `package_topic(challenge_type, topic)` 方法**：定位 package 内指定主题文件并返回内容。
3. **在 react.py 中注册该工具**，让 agent 在需要时主动调用。

**为什么是架构优化**：这是给知识库增加一个**按需读取能力**，让 agent 从"被动接收注入"升级为"主动按需获取"。避免把所有知识一次性塞进上下文（节省 token），只在需要时加载。

### 方向三：CTF 特有流程补充（内容补充）

补充 WING 缺失的 CTF 特有流程，作为 structured 层的新 JSON：

1. **`ctf_workflows.json`**：flag 位置优先级、highlight_file 输出顺序陷阱、CTFd API 操作、常见 flag 位置等。
2. **`judging_decision_trees.json`**：各题型的"题目特征 → 可能攻击/考点"快速判题决策表（借鉴 VulnClaw 的 SKILL.md 判题指南）。

### 方向四：VulnClaw 内容储备（保存不实装）

VulnClaw 中 WING 用不到但值得保存的内容（作为未来方向拓展后的知识库储备）：

- **渗透测试方法论**（pentest-flow/recon/vuln-discovery/exploitation/post-exploitation/reporting/waf-bypass）
- **CVE 库**（kb/cve/ 下的结构化 CVE 条目）
- **红队流程**（授权红队 detail packs）
- **Android/客户端逆向**（android-pentest/client-reverse）
- **AI/MCP 安全**（ai-mcp-security）

这些先保存到 `data/knowledge/archived/vulnclaw_reserve/`，**不实装**，作为未来方向拓展后的知识库。

---

## 四、分阶段实施计划

### 阶段 A：判题路由层（架构增强）
1. 设计 routing 元数据 schema（trigger/attack/payload/topic）
2. 为 web/crypto/reverse/pwn/misc 五类高频题型编写判题路由规则
3. 在 `kb.py` 的 `retrieve()` 中增加判题路由逻辑
4. 测试：给定题目特征，验证能路由到正确的攻击方法

### 阶段 B：按需加载机制（架构增强）
1. 在 `kb.py` 中新增 `package_topic(challenge_type, topic)` 方法
2. 新增 `load_kb_topic` 工具并注册到 react.py
3. 测试：agent 能按需读取 package 主题文件

### 阶段 C：CTF 特有流程补充（内容补充）
1. 编写 `ctf_workflows.json`（flag 位置/CTFd API/highlight_file 陷阱）
2. 编写 `judging_decision_trees.json`（判题决策表）
3. 在 `kb.py` 的 `structured()` 中接入

### 阶段 D：VulnClaw 内容储备（保存不实装）
1. 将 VulnClaw 的渗透方法论/CVE/红队/Android/AI 安全内容归档到 `archived/vulnclaw_reserve/`
2. 编写索引说明，标注"未来方向拓展后启用"

---

## 五、验收标准

1. **判题路由**：给定 5 个典型题目特征（如"参数接受文件名"、"e=3"、"eval 长度限制"、"n 相同"、"反序列化"），`retrieve()` 能正确路由到对应的攻击方法 + payload + 主题文件。
2. **按需加载**：agent 能通过 `load_kb_topic` 工具按需读取 package 主题文件的完整内容。
3. **CTF 流程**：`ctf_workflows.json` 和 `judging_decision_trees.json` 就位，`structured()` 能正确注入。
4. **不破坏现有功能**：现有 role_guides/packages/playbooks/pitfalls/patterns 全部保留，新增 routing 层和按需加载机制不影响现有注入。
5. **架构优化而非打补丁**：所有改动都是新增独立层/机制，不修改现有知识文件内容。

---

## 六、风险与边界

1. **判题路由的准确性**：trigger 关键词匹配可能误判。需设计合理的 trigger 词表，避免过度匹配。
2. **按需加载的 token 控制**：`load_kb_topic` 返回完整主题文件可能较大，需控制返回长度（截断或分页）。
3. **不实装内容的管理**：VulnClaw 储备内容需明确标注"未启用"，避免 agent 误用。
4. **与现有 curator 管线的协同**：判题路由规则可作为 curator 沉淀的一部分，从真实轨迹中提取"题目特征→攻击方法"映射。

---

## 七、除知识注入外，VulnClaw 其他值得学习的机制

> 深入对比 VulnClaw 的 agent 核心（AgentState 证据记忆 / correction_layer 纠偏层 / solver 完成闸门）与 WING 现有机制后，识别出以下 WING 缺失或可增强的机制。

### 7.1 对比结论：WING 已覆盖且更强的机制

| 机制 | VulnClaw | WING 现状 | 结论 |
|------|----------|-----------|------|
| **反幻觉闸门** | evidence gate（flag 必须在工具输出出现） | `flag_verify.py`：flag 必须出现在观测 + 外部题解拦截 + LLM 审查 + 编码变体匹配 + 分段覆盖匹配 | **WING 更强**，无需改动 |
| **上下文压缩** | context_auto_compact（触发比例压缩） | `compressor.py`：异步事件驱动 + 动态压缩 + 首次坍塌即压缩 | **WING 更强**，无需改动 |
| **巡查指导器** | 无 | `coordinator.py`：双系统定位 + 战略指导 + MUST 指令 | **WING 独有**，VulnClaw 没有 |

### 7.2 WING 缺失、值得借鉴的机制（按价值排序）

#### ① 高信号事实提取与固定（pinned facts）— 最高价值

**VulnClaw 做法**（`correction_layer.py`）：工具调用后，从输出中**提取高信号事实**并独立固定为长期可见（`pinned_facts`）：
- **Source SQL**：`select ... from ... where ...` 源码片段
- **HTML form/input**：method/action/name/type 属性
- **JS/API endpoint**：`fetch(...)`/`axios(...)` 中的 URL
- **parser/filter 边界**：`preg_match`/`unserialize` 等过滤与解析器不一致
- **PHP POP 链**：`unserialize` + `__destruct` + 危险 sink 的 entry/sink 关系

这些事实**独立于原始输出**固定，即使后续探测把真实入口淹没，高信号事实仍长期可见。

**WING 现状**：`_trim_observation` 是**通用截断**（折叠重复行 + 头尾截断），没有"提取高信号行并固定"的能力。agent 的 observation 被截断后，SQL 源码/表单/endpoint 等关键信息可能丢失。

**方案**：借鉴 VulnClaw，为 WING 增加**高信号事实提取器**：
- 在 react.py 中新增 `_extract_high_signal_facts(observation)` 函数，复用 VulnClaw 的正则模式（SQL/form/endpoint/parser-filter/POP 链）
- 提取的事实独立存储，注入下一轮 system_prompt 的"高信号事实"段
- 与现有 `_trim_observation` 协同：截断原始输出 + 提取高信号事实，两者互补

**为什么是架构优化**：这是给 observation 处理增加一个**语义提取维度**（从"截断"到"提取关键信息"），不是往现有文件塞内容。

#### ② 证据去重（content_hash + duplicate_of）— 高价值

**VulnClaw 做法**（`agent_state.py`）：每个工具结果计算 `content_hash`，相同 raw 输出只保留引用（`same_as=eXXX`），不重复塞上下文。

**WING 现状**：`_trim_observation` 有**行级去重**（折叠重复行），但没有**证据级去重**（相同工具+相同参数+相同输出 → 只保留引用）。

**方案**：在 react.py 中为 observation 增加**证据级去重**：
- 计算 observation 的 content_hash
- 若与历史 observation 相同，只注入 `[same as step N]` 引用，不重复塞正文

**为什么是架构优化**：这是给 observation 回灌增加一个**去重维度**，减少上下文膨胀，与现有截断机制互补。

#### ③ 工具健康度（tool_health）— 中价值

**VulnClaw 做法**（`agent_state.py`）：记录每个工具的失败/降级/耗时，注入下一轮上下文（"tool X is degraded after N failures"）。

**WING 现状**：无工具健康度记录。

**方案**：在 react.py 中为工具调用增加**健康度记录**：
- 记录每个工具的成功/失败/耗时
- 连续失败的工具注入"已降级"提示，引导 agent 换工具或调整参数

**为什么是架构优化**：这是给工具调用增加一个**健康度维度**，帮助 agent 感知工具状态。

#### ④ 重复调用软提示（repeated_call_hint）— 中价值

**VulnClaw 做法**（`agent_state.py`）：检测最近 6 步内相同工具+相同参数的重复调用，注入软提示（"recent action X has repeated, use a different argument"）。

**WING 现状**：有**分析瘫痪检测**（≥20 步无执行工具 → 强制写脚本），但那是**硬性强制**。VulnClaw 是**软提示**（不阻断，只提示）。

**方案**：在 react.py 中增加**重复调用软提示**，作为分析瘫痪检测的补充（软提示在前，硬性强制在后）。

**为什么是架构优化**：这是给循环检测增加一个**软提示维度**，与现有硬性强制互补。

### 7.3 实施建议

这些机制与知识注入升级（方向一~四）**相互独立**，可并行实施。建议优先级：
1. **高信号事实提取**（价值最高，直接提升解题能力）
2. **证据去重**（减少上下文膨胀，间接提升稳定性）
3. **工具健康度 + 重复调用软提示**（提升鲁棒性）

**验收标准**：
1. 给定含 SQL 源码/表单/endpoint 的工具输出，`_extract_high_signal_facts` 能正确提取并注入下一轮。
2. 相同工具输出重复出现时，只注入 `[same as step N]` 引用。
3. 工具连续失败时，注入"已降级"提示。
4. 相同工具+参数重复调用时，注入软提示。
5. 不破坏现有 `_trim_observation`/`_trim_assistant`/分析瘫痪检测。

### 7.4 与原有架构的结合（关键：不是孤立新增，而是融入现有证据/事实/推理系统）

> 用户关切：这些升级必须与 WING 现有的证据/事实/推理系统相结合，而非孤立的新增模块。
> 经核对 WING 现有架构（EvidenceTree 证据树 / belief_state 推论分级 / ShortTermMemory facts / `_verified_facts`），确认每个升级都有明确的结合点。

#### WING 现有证据/事实/推理系统（结合的基础）

| 系统 | 位置 | 作用 |
|------|------|------|
| **EvidenceTree** | `evidence/__init__.py` | P2 漏洞确认：节点=二元问题，`record_observation(node_id, answer, evidence)` 记录支撑观测，confirmed 才可共享 |
| **belief_state** | `coordinator.py` | 推论分级框架：FACT/LIKELY/POSSIBLE/DISPROVED 四级，跨巡查持久化，回顾→更新→反思→决策 |
| **ShortTermMemory facts** | `react.py` `_inject_context` | 每轮注入中期记忆 facts（`format_facts`）+ RAG + 失败提示 + skill 库 |
| **`_verified_facts`** | `react.py`（预留未启用） | 已验证结论，重算拦截（当前只初始化，未实际读写） |

#### 各升级的结合点

**① 高信号事实提取 → 融入 EvidenceTree + belief_state + ShortTermMemory**

高信号事实（SQL 源码/表单/endpoint/parser-filter/POP 链）不是孤立存储，而是**三路汇入现有系统**：

1. **汇入 EvidenceTree**：高信号事实作为**节点支撑证据**。例如 `_extract_sql_facts` 提取的 SQL 源码片段，正好作为 EvidenceTree 节点"是否存在 SQL 注入"的 `record_observation` 的 evidence 字段，帮助确认/证否该节点。这直接强化 P2 漏洞确认阶段的证据链。
2. **汇入 belief_state**：高信号事实作为 **FACT 级推论**（有轨迹直接支撑的事实）。coordinator 巡查时，这些事实可作为"方向正确/错误"的判断依据（只有 FACT + LIKELY 可作为 MUST 依据）。
3. **汇入 ShortTermMemory facts**：高信号事实注入 `_inject_context` 的 facts 段，每轮重新注入（防丢），与现有 `format_facts` 机制协同。

**② 证据去重 → 融入 observation 回灌管线**

证据去重不是独立模块，而是**增强现有 `_trim_observation` 回灌管线**：
- 在 `_trim_observation` 之前增加 content_hash 计算
- 相同 raw 输出只注入 `[same as step N]` 引用，不重复塞正文
- 与现有 `_trim_observation`（折叠重复行 + 头尾截断）协同，形成"去重 → 截断"两级处理

**③ 工具健康度 → 融入 coordinator 巡查信号**

工具健康度不是独立存储，而是**作为 coordinator 巡查的输入信号**：
- 连续失败的工具 → 注入"已降级"提示，引导 agent 换工具
- 与现有 belief_state 结合：工具健康度可作为"该工具方向是否可行"的 FACT 级推论

**④ 重复调用软提示 → 融入现有循环检测**

重复调用软提示不是替代现有分析瘫痪检测，而是**补充**：
- 软提示在前（检测到重复调用即提示，不阻断）
- 硬性强制在后（分析瘫痪检测，≥20 步无执行工具才强制）
- 与现有 `_check_re_read`（已读文件指纹拦截）协同，形成多级循环防护

#### 结合原则

1. **复用现有数据结构**：高信号事实存入现有 EvidenceTree/belief_state/ShortTermMemory，不新建孤立存储。
2. **增强现有管线**：证据去重/工具健康度/重复提示都是增强现有 `_trim_observation`/coordinator 巡查/循环检测，不新增独立模块。
3. **不破坏现有机制**：所有结合点都是"在现有系统上增加输入/增强处理"，不修改现有系统的核心逻辑。
4. **`_verified_facts` 激活**：react.py 中 `_verified_facts` 已预留但未启用，高信号事实可作为其首批数据源，激活这个预留机制。
