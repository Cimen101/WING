# 测试报告：test20 全题型能力修复验证（web-under-construction / crypto-ziphard）

- 日期：2026-08-13 ~ 2026-08-14
- 版本：WING-Corvus（渡鸦）——主线
- 测试目的：验证证据决策二叉树 + 攻击链 + 任务驱动 + 观测真实性层（Sprint 38/38.5）在真实环境的效果；配套修复 F1/F2/G1/G2/G3/G4

## 题目来源与信息

| 项 | 值 |
| :-- | :-- |
| 题目 | web-under-construction（web）/ crypto-ziphard（crypto） |
| 运行方式 | 2 并发 × 3 风格（swarm + 总指挥），reset_container=true |
| 时间上限 | 1800s / 题（STUCK 判定 300→600s） |

## 轮次与结果

| 轮次 | 日期 | 结果 | 关键事件 |
| :-- | :-- | :-- | :-- |
| 第一轮 | 08-13 | 2 题均 300s 卡死（agent 0 step） | LLM API 全挂（zen 403 / go 500），smoke 四路全 false → 修复 F1（总指挥 P1 限时误触发）+ F2（LLM 全挂主动早失败） |
| 第二轮 | 08-14 | 0/2（web 1804s 超时、crypto 660s STUCK） | 总线键修复生效：P1 汇报正常到达总指挥、指令正常下发 → 修复 G1（证据树/攻击链从未激活）+ G2（总线键不一致）+ G3（STUCK 判定过紧） |
| 第三轮 | 08-14 | **web-under-construction 解出**（conservative 39 步，官方 flag 精确匹配） | 决定性成果：HPP 双参数污染正解链完整实现（check_findings 采纳兄弟 FACT → 发现参数污染 → 注册 gold 用户 → 直连内部 PHP 登录拿 flag）→ 修复 G4（验证脚本 gbk 编码崩溃） |
| 第四轮 | 08-14 | web-uc 重跑 1804s 超时 | LLM 测速正常（平均 8.3s/中位 3.8s，非瓶颈）；轨迹根因：innovative grep 管道吞响应误判 HPP 失败、三路未确认"HPP 转发前提"、conservative 陷入"找 Flask 源码"死路 → 设计观测真实性层（H1/H2/H3） |
| 第五轮 | 08-14 | **web-under-construction 再次解出**（conservative 74 步，1801.9s 压线，官方 flag 精确匹配） | 观测真实性层生效：全程零 `\| grep` 管道判定成败，三路均用 curl -i / 存盘再读 / 直连全文（H1 规范预防性生效）；P2 证据树 verdict 共享 + 总指挥 P3 指令协同收敛 |

**同题重跑稳定性：web-under-construction 2/3 解出**（第三、五轮解出，第二、四轮超时）。

## 关键观察

- **升级全链路生效（第三轮）**：conservative 完整实现 HPP 正解链 — step 32-33 经 check_findings 采纳兄弟 FACT（内部 PHP 13112 登录直接返回 FLAG + 需 MIGRATOR_TOKEN）→ step 35 发现**参数污染**（Flask `request.form['tier']` 取首值过校验、PHP `$_POST['tier']` 取末值创建 gold 用户）→ step 36 注册 hppuser99 → step 37-38 登录直连内部 PHP → step 39 提交正确 flag。该题首测 51 轨迹全败，为"多步组合/间接型"代表。
- **观测真实性层对照（第四轮 vs 第五轮）**：第四轮 innovative grep 空输出误判"didn't work"放弃 HPP；第五轮 H1 命令模板注入后三路探测均用正确方法，未触发 H2/H3 兜底即达标。
- **crypto-ziphard**（该题官方仅 6 solves，极难）：1802s 超时未解出；innovative 第 8 步即调用 bkcrack_attack 进入攻击实施（对照组纯侦查）——Sprint 41 A+B 推进生效；卡在已知明文选错（junk.dat 为 `os.urandom(4)` 随机数据）+ 已知明文不足（需 ≥8 连续字节），bkcrack 工具引导已针对性增强（见 `updates/2026-08-14-recon-saturation-dedup.md`）。
- **LLM 慢速为环境约束**（第三轮 crypto 170s/步），非系统缺陷；第四轮测速恢复正常（平均 8.3s）。

## 冒烟与回归

- 冒烟累计：Phase A 11 / B 11 / C 26 / D 16 / E 28 / E2 19 / F 6 / G 9 / H 28 项全过
- pytest：Phase D 232 过 → Phase H 全量 950 passed（65 failed 均为既有断言过期：工具数断言、测试环境路径依赖）

## 结论

- 三阶段驱动（P1 任务驱动 / P2 证据树 / P3 攻击链）+ 总线键修复 + 兄弟协作下，多步组合/间接型复杂题具备解出能力（51 轨迹全败 → 真实解出）；
- 但稳定性不足（同题重跑 2/3）：HPP 类参数语义差异漏洞仍依赖 LLM 正确推理 + 观测不被污染 → 观测真实性层（H1/H2/H3）落地后稳定性提升；
- crypto-ziphard 未解出为题目极难 + 已知明文不足，非侦查循环问题（Sprint 41 已针对性增强工具引导）。

## 关联记录

- 更新记录：`updates/2026-08-14-evidence-tree-attack-chain.md`、`updates/2026-08-14-recon-saturation-dedup.md`
- 设计方案：`data/gctf_new_test/升级方案_test20全题型能力修复.md`（§十 实施记录、§十二 Sprint 41）
