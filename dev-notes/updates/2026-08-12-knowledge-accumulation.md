# 更新记录：知识库持续沉淀统计（curator 自动管线）

- 日期：2026-08-12
- 版本：WING-Corvus（渡鸦）——最新版本小版本更新

## 概述

curator 自动沉淀管线持续运行：每次解题批次结束后，自动从轨迹中提取可复用知识，沉淀为 playbook（可复用流程）与 pitfall（失败教训）两类条目。本文为阶段统计摘要。

## 沉淀统计

| 指标 | 值 |
| :-- | :-- |
| curator_log 累计沉淀 | **302 条**（playbook 130 / pitfall 172） |
| playbooks 分目录 | 47 项（crypto / misc / reverse / osint / web） |
| pitfalls | 18 项（crypto / misc / reverse / brainteaser / pwn / web） |
| role_guides agents | 84 文件，随轨迹持续更新 |

## 覆盖范围

- 覆盖 gctf / csaw / suctf / hardtest / gh / ida 等批次的解题轨迹
- playbook：可复用的解题流程 / 工具用法 / 参数模式
- pitfall：常见失败模式 / 误判教训 / 环境坑点

## 关联组件

- role_guides：agents 目录 84 文件随轨迹持续更新（见 `updates/2026-08-08-role-guides-restructure.md`）
- archived：旧版指南封存 200+ MD，保持主目录可维护性
- structured/ 结构化知识层：与 Reverse 泛化方案联动（见 `updates/2026-08-11-reverse-generalization.md`）
- 脑洞题自学习闭环：与脑洞题能力升级方案联动（见 `updates/2026-08-11-brainteaser-capability.md`）
