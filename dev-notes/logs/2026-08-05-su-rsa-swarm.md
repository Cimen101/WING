# 运行日志：WING-Corvus — SU_RSA（crypto / hard）

- 日期：2026-08-05
- 内容为公开可发布的运行摘要（时间线 + 统计），原始轨迹保留在本地

## 时间线

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

## 总线消息统计

| 指标 | 值 |
| :-- | :-- |
| 消息总数 | 93 |
| FACT（事实） | 78 |
| LIKELY（推测） | 12 |
| 其他 | 3 |

## 各路线状态摘要

| 路线 | 阶段 | 说明 |
| :-- | :-- | :-- |
| conservative | 完成（WIN） | 内置 RSA 工具恢复 d，解密得真实 flag，22 步 |
| aggressive | 被终止 | 格攻击方向正确，但脚本构造多次报错（LLM 输出脚本含超长重复文本） |
| innovative | 被终止 | Herrmann-May 格构造多次迭代，LLL 仅得单位向量，未突破 |

## 备注

- 三路均识别出「小 d + 已知 p+q 高位」攻击模型，攻击方向正确。
- 本题官方解法需 Sage 三元 Coppersmith；容器无 Sage，agent 用纯 Python
  （fpylll + sympy）实现格攻击，最终由内置 RSA 工具路径完成突破。
- 完整原始 JSONL 轨迹保留在本地，不入库（避免体积与敏感信息扩散）。
