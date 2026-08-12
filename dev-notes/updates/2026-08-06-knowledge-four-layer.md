# 更新记录：知识库四层重构 + skill_curator 管线

- 日期：2026-08-06
- 版本：WING-Corvus（渡鸦）——最新版本小版本更新

## 变更背景

旧版知识库为 200+ 个散落 Markdown 文件，来源混杂（历史轨迹、外部资料、实验笔记），无分层、无生命周期管理，Agent 检索时噪音大且新旧内容互相矛盾。本次重构按"内容属性与治理边界"划分为四层。

## 变更内容

### 1. 四层结构

| 层 | 目录 | 内容 | 治理规则 |
| :-- | :-- | :-- | :-- |
| 外部知识包 | `packages/` | 10 个外部知识包（解压后 + 统一 `index.json` 索引） | 只读，只允许整体替换/升级，不允许散改 |
| 题型分工指南 | `role_guides/` | 各题型的固定分工与流程指南 | 只改不增（维护既有条目，不新增零散条目） |
| 打法与坑位 | `playbooks/` + `pitfalls/` | 打法手册与踩坑记录，分题型子目录 | 分目录管理；`auto.md` 由 curator 自动生成，人工不手改 |
| 抽象经验 | `patterns/` | 跨题型的抽象经验，统一 `skill_library.json` | 由 curator 提炼入库 |
| 旧版封存 | `archived/` | 旧版 200+ MD 全量封存 | 只读归档，不参与检索 |

### 2. skill_curator 管线

经验从原始轨迹到知识库的自动加工链路：

```
extract → verdict → refine → merge → compress → persist
```

- **extract**：从轨迹中抽取工具成功/失败片段与关键事实；
- **verdict**：判定该经验是否值得入库（去重、去噪音）；
- **refine**：转写为结构化条目（触发条件 / 步骤 / 结果）；
- **merge**：与既有条目合并，避免重复；
- **compress**：压缩表述，控制检索体积；
- **persist**：按层落盘（playbooks / pitfalls / patterns）。

### 3. 注入点

| 注入点 | 层级 | 说明 |
| :-- | :-- | :-- |
| `react.py` | 战术层 | 阶段化流程中按阶段注入对应打法与坑位 |
| `coordinator.py` | 战略层 | 跨题型调度时注入分工指南 |
| `commander.py` | 总指挥层 | 分工与发散决策时注入抽象经验 |

## 验证

- 54 个既有单元测试全绿（新增 curator 单测：extract→persist 全链路）；
- 检索命中率对比：重构后旧版噪音条目不再进入检索结果；
- 全量 hard 题回归见 `tests/2026-08-06-hard5-run.md` 与 `tests/2026-08-06-gctf20-report.md`。
