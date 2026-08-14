# 更新记录：证据决策二叉树 + 攻击链 + 观测真实性层（Sprint 38 / 38.5）

- 日期：2026-08-13 ~ 2026-08-14
- 版本：WING-Corvus（渡鸦）——主线
- 范围：P2 漏洞确认阶段的证据树共享、P3 攻击链驱动、P1 任务驱动验收、观测真实性层（H1/H2/H3）

## 背景

test20 全题型能力修复计划（基于 51 条失败轨迹全量审计）：复杂题（多步组合/间接型）失败的三个根因——
1. **P2 无验收标准**：侦查结论 → 攻击方向的过程无结构化推理，靠 LLM 自由发挥；
2. **P2→P3 切换无确凿依据**：方向未验证即切换或永不切换；
3. **观测失真**：LLM 自造过滤管道吞掉关键响应 → 系统性误判（与模型强弱无关）。

## 变更内容

### 1. 证据决策二叉树（`ctf_agent/evidence/__init__.py`，P2 漏洞确认）

- **内部节点 = 二元问题**（是否？），附 `verify_method`（验证方法/命令）、`expected_yes/expected_no`（判定标准）、`confirm_action`（确认动作，如正反对照/双独立验证）。
- **叶子节点 = 假设（漏洞候选）**；根到叶路径 = 完整证据链。
- **节点确认协议**：答案须通过确认动作（tentative → confirmed）才参与路径选择与共享；未确认节点（pending/tentative/unknown）不参与路径、不共享。
- **共享协议（node_verdict）**：`FileBus.post_node_verdict` 仅允许发布 `status=confirmed` 结论（100% 正确才共享）；`check_node_verdicts` 三级去重采纳（L1 精确键 / L2 语义 / L3 无匹配独立验证）。
- **战术层接入**：每 5 步消费兄弟 confirmed verdict 注入采纳提示 → 发布本路 confirmed → 注入待验证节点任务（问题+验证方法+判定标准）→ 注入树摘要。

### 2. P1 任务驱动 + 验收标准（Phase B）

- `TaskAssignment` 新增 `deliverables`（产出物清单），领题分工时 LLM 生成、缺失按风格兜底；`FileBus.post_directive` 透传。
- 战术层 `report_p1_progress_if_due` 汇报附带**产出物验收进度**（基于最近观测关键词启发式标记，如"产出物 1/3 已完成"）。
- 新增 L1 规则 `_check_flag_hunt_trap`：最近窗口 ≥2 次 find/cat/xxd flag 搜索且无新信息 → MUST [FORCE] 跳转 + 自动加禁忌。
- P1 汇报附带**最近实际动作**前缀（`[动作:ssh_exec/ssh_python]`），总指挥能看到该路真实行为。

### 3. P3 攻击链驱动（Phase D）

- `AttackChain` 类 + `ATTACK_CHAIN_TEMPLATES`（5 题型粗骨架各 4 环，战略层填参数）；环节 input_keys/output_key 链式依赖。
- 状态机（pending→verified→failed）+ **三级回溯**（impl 回本环重试/超 3 次升 method；method 回上一分支点/超 2 次回 P2；dead 直接回 P2）+ 环级验证（全链完成 succeeded）。
- L1 规则 `_check_plan_execution`：最近窗口出现攻击意图且其后连续 ≥2 步纯读取 → MUST [FORCE] "方案已提出未执行，下一步必须落地"（test20 最致命问题）。
- 脚本鲁棒性（S5）：工具错误后检测 Python 报错 → 注入修复提示；同一脚本同错 ≥2 次 → 强制改用 ssh_python 写文件方式。

### 4. 观测真实性层（Sprint 38.5，H1/H2/H3）

根因：第四轮 web-uc 验证中 innovative 用 `curl -s | grep -E 'HTTP|Location'` 探测 HPP——grep 无匹配退出码 1 → 整条管道失败且输出全空 → 工具层 observation 只剩命令回显 → LLM 误判 "didn't work" 放弃正确攻击路径。**工具输出裁剪权在 LLM 手里是架构缺陷**。

- **H1 命令模板库**（`prompts.py` `OBSERVATION_SAFETY` + `WEB_OBSERVATION_TEMPLATES` + `_inject_observation_safety`）：按题型/场景预置不过度过滤的探测模板（web 用 `curl -i -s` 带响应头 / `curl -s -w '%{http_code} %{redirect_url}'`；grep 改为先存文件再 grep）；注入 system prompt。
- **H2 输出保底协议**（`ssh_tool.py`）：检测到"过滤管道 + 失败 + 无输出"时，对**只读网络探测**（curl/wget/nc 且无写操作）自动重跑剥离过滤管道后的原始命令（`<raw> 2>&1 | head -c 3000`，timeout 30s），把真实响应直接带进 observation（不依赖 LLM 是否会听提示）；写操作/非网络命令不重跑（防副作用）。
- **H3 观测规范器**：①过滤管道吞输出 → 注入提示"重跑不带过滤管道的原始命令，不要基于当前空输出下结论"；②302/301 未看 Location 头（web 方法论）；③`curl -s` 隐藏响应头误判。

### 5. 其他修复

- **F1（总指挥 P1 限时误触发）**：`_phase_enter_ts` 在 `__init__` 时设置而 `assign_initial` 耗时 1-2 分钟 → 领题分工与 P2 指令同秒发出。修复：`assign_initial` 末尾重置（P1 限时从分工完成起算）。
- **F2（LLM 全挂空转）**：跳过步不产生 step 输出 → 调用器 300s 卡死判定才终止。修复：react.py `_llm_fail_streak` 连续 ≥2 次 LLM 失败 → 主动返回 fail_reason 早失败。
- **G1（证据树/攻击链从未激活）**：`init_evidence_tree()`/`init_attack_chain()` 定义但无调用点 → 机制完全未生效。修复：`check_commander_directives` 阶段更新处自动激活（P2→树，P3→链，幂等不重建）。
- **G2（总线键不一致）**：swarm 给每路改 `challenge_id="{base}:{style}"` 但未设 `bus_challenge_id` → 总线键含冒号（Windows 文件名非法），总指挥与 agent 读写不同文件。修复：`swarm.py` 注入 `t["bus_challenge_id"] = base_id`。
- **G4（验证脚本 gbk 编码崩溃）**：Windows 控制台默认 gbk，日志含 U+FFFD 时 print 抛 UnicodeEncodeError → 整题结果丢失。修复：强制 stdout/stderr `reconfigure(encoding='utf-8', errors='replace')`。

## 验证

- Phase 冒烟累计：A 11 项 / B 11 项 / C 26 项 / D 16 项 / E 28 项 / E2 19 项 / F 6 项 / G 9 项 / H 28 项，全过
- pytest 回归：232 个（Phase D 后）→ 950 passed（Phase H 后），65 failed 均为既有断言过期（工具数断言、测试环境路径依赖）
- 真实环境验证（详见 `tests/2026-08-14-test20-verify-report.md`）：web-under-construction 第三轮/第五轮真实解出（HPP 双参数污染正解链），观测真实性层生效后同题重跑稳定性 2/3

## 关联记录

- 设计方案：`docs/阶段式协调.md`、`data/gctf_new_test/升级方案_test20全题型能力修复.md`
- 迭代记录表（DESIGN §23.7）：Sprint 38 / 38.1 / 38.5
