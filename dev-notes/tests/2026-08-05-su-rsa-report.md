# 测试报告：WING-Corvus 完整模式 — SU_RSA（crypto / hard）

- 日期：2026-08-05
- 版本：WING-Corvus（总指挥协作小队）
- 测试目的：WING-Corvus 大幅迭代后的首次完整能力验证

## 题目来源与信息

| 项 | 值 |
| :-- | :-- |
| 比赛来源 | SUCTF 2026 |
| 题目 | SU_RSA（crypto） |
| 难度 | hard |
| 题型机制 | 1024 位 RSA，小私钥指数 d≈N^0.33（超出 Wiener 界）；题目给出 p+q 高位提示 S |
| 附件 | SU_RSA.py（N / e / c / S 参数） |
| 攻击模型 | 小 d + 已知 p+q 高位 → 格攻击（Herrmann-May / Coppersmith 类） |
| flag 格式 | SUCTF{...} |

## 一、测试配置

| 项 | 值 |
| :-- | :-- |
| 运行模式 | swarm 三路并行 + 总指挥（Commander） |
| 解题风格 | conservative / aggressive / innovative |
| 题型 / 难度 | crypto / hard |
| 题目 | SU_RSA（1024 位 RSA，小私钥指数 d≈N^0.33，已知 p+q 高位提示 S） |
| flag 验证 | 确定性数学验证 `pow(bytes_to_long(flag), e, N) == c` |
| 步数上限 | 80 步 / 题 |
| 时间上限 | 1800s |

## 二、结果汇总

```
Swarm 汇总: solved=True  winner=conservative  elapsed=637s
flag: SUCTF{...}（与官方 writeup 一致）
```

| 路线 | 状态 | 步数 | 耗时 | token |
| :-- | :-- | :-- | :-- | :-- |
| conservative | WIN（解出真实 flag） | 22 | 634.9s | ~142.9 万（全队合计） |
| aggressive | KILLED（兄弟解出） | — | — | — |
| innovative | KILLED（兄弟解出） | — | — | — |

解出的 flag 与官方 writeup 一致，且通过数学验证（确定性验真，非猜测）。

## 三、轨迹摘要（时间线）

```
T+0s      启动 WING-Corvus swarm（3 路 + 总指挥 + 数学 flag 验证）
T+~5s     总指挥下发 3 条 P1 侦查分工指令
          - conservative → 系统解析题目脚本与公开参数
          - aggressive   → 直接试跑经典小私钥指数攻击
          - innovative   → 探索非常规信息源
T+~90s    aggressive 尝试 Wiener 连分数 → 失败（符合预期，d≈N^0.33 超出 Wiener 界）
T+~100s   innovative 开始 Herrmann-May 格攻击实现（多次迭代调整格参数）
T+~200s   conservative 使用内置 RSA 攻击工具，进入恢复私钥阶段
T+~500s   conservative 完成私钥恢复并解密出明文 flag
T+~540s   conservative 提交 flag → 数学验证通过（pow(m,e,N)==c）→ 判定真实
T+~545s   兄弟 kill 生效：aggressive / innovative 被终止
T+~637s   swarm 汇总：solved=True, winner=conservative
```

## 四、验证链路

1. **总指挥领题分工**：启动后总指挥按题目特征下发 3 条 P1 侦查指令
   （conservative=系统解析参数；aggressive=直接试跑经典攻击；innovative=探索非常规信息源）。
2. **三路并行独立容器**：每路独立容器、独立解题轨迹。
3. **总线协作**：全程 93 条消息（FACT 78 / LIKELY 12），知识共享正常。
4. **真实解题**：conservative 使用内置 RSA 攻击工具从公开参数中恢复私钥并解密出 flag。
5. **兄弟 kill**：conservative 提交正确 flag 后，其余两路被终止，避免空转。
6. **确定性验证**：提交前数学验证通过，杜绝幻觉 flag。

## 四、测试中发现并修复的问题

| 问题 | 影响 | 状态 |
| :-- | :-- | :-- |
| 单 agent 模式曾出现假 flag 幻觉（5 步内判定 success=true） | 假阳性 | 已修复（见 `../updates/2026-08-05-flag-verify-fix.md`） |
| swarm 汇总中非胜出路 steps/tokens 显示为 0 | 统计展示不完整 | 观察中（不影响解题） |

## 六、结论

- WING-Corvus 完整模式（总指挥 + 三路协作 + 数学验证）全链路可用。
- 对 crypto/hard 题具备真实解题能力，且能防止幻觉 flag。
- 耗时约 10.6 分钟 / 题，token 消耗较大（~143 万 / 题），后续测试需关注成本控制。
