# 测试报告：Google CTF hard reverse 专项测试（gctf_new_test 扩展批次）

- 日期：2026-08-08 ~ 08-10
- 版本：WING-Corvus（渡鸦）——最新版本小版本更新

## 题目来源与信息

| 项 | 值 |
| :-- | :-- |
| 比赛来源 | Google CTF |
| 题目 | hard reverse 专项 5 题（x86perm / ilovecrackmes / multiarch-1 / arcade / fluffy） |
| 题型 / 难度 | reverse / hard |
| 批次 | gctf_new_test 扩展批次 |
| 扩展轨迹 | asteroids-redux / cgb / bomberman / rustyschool / notobfuscated / ieee / mceliece / filtermaze |

## 结果汇总

| 指标 | 值 |
| :-- | :-- |
| 专项 5 题 hard reverse | **0/5（全部失败）** |
| 扩展轨迹 | 作为交叉验证与回归轨迹随批次运行，支撑根因归纳 |

### 分题明细

| 题目 | 失败点归纳 |
| :-- | :-- |
| x86perm | 置换表推导：需从二进制中提取字节置换规律并推导置换表，纯静态分析无法完成 |
| ilovecrackmes | Paillier 参数形状与 RSA 相似被误判为 RSA；且依赖 GLIBCXX 运行环境，缺环境无法动态验证 |
| multiarch-1 | 虚拟机多架构：需先识别 VM / 多架构字节码语义，缺少架构识别能力 |
| arcade | MAME 环境：运行依赖街机模拟器环境，环境缺失导致动态执行断链 |
| fluffy | 混淆复杂 + 环境依赖，结构化逆向知识不足以支撑拆解 |

## 根因归纳

5 题 0/5 并非单点算法问题，失败模式可归纳为三个单点能力缺失：

1. **统计 / 模式推理缺失**：面对置换表、字节频率规律等"统计型"逆向，缺少面向统计的模式提取与推导手段（典型：x86perm）。
2. **环境依赖预检缺失**：GLIBCXX、MAME、多架构模拟器等运行依赖未在容器初始化阶段预检与预装，动态验证链路断裂（典型：ilovecrackmes / arcade / multiarch-1）。
3. **结构化逆向知识缺失**：算法指纹（Paillier / RSA / TEA / AES / ECC 等）、架构指南、环境解决方案等知识未沉淀为可检索结构，依赖模型内嵌记忆导致误判（典型：ilovecrackmes）。

## 后续动作

- 基于上述根因分析产出 Reverse 泛化能力架构优化方案：详见 `updates/2026-08-11-reverse-generalization.md`
- 脑洞题识别与 role_guides 注入问题联动修复：详见 `updates/2026-08-08-role-guides-restructure.md`、`updates/2026-08-11-brainteaser-capability.md`
