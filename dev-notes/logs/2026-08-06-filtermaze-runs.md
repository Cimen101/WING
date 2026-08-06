# 运行日志：WING-Corvus — crypto / hard（LWE + 哈密顿路径）

- 日期：2026-08-06
- 内容为公开可发布的运行摘要（时间线 + 统计），原始轨迹保留在本地

## 时间线（通过轮，84s）

```
T+0s      启动 WING-Corvus swarm（3 路 + 总指挥）
T+~3s     总指挥下发 3 条 P1 侦查分工指令
T+~10s    conservative 读取附件源码，梳理 check_path 协议与 LWE 参数
T+~20s    conservative 从总线复用兄弟恢复的哈密顿路径
T+~25s    conservative 提交完整路径，从远程获取 100 个误差绝对值 |e|
T+~35s    lwe_decode 首次尝试（数据文件缺键）→ 报错提示可用键
T+~40s    构造正确数据文件（A/b/mags/q）
T+~45s    lwe_decode 求解成功 + 数学验证通过（A·s+e ≡ b mod q）
T+~50s    get_flag 提交私钥 → status=success
T+~55s    Final Answer 提交 flag
T+~73s    兄弟 kill 生效（aggressive / innovative 终止）
T+~84s    swarm 汇总：solved=True, winner=conservative, tokens=506,617
```

## 各路线状态

| 路线 | 阶段 | 说明 |
| :-- | :-- | :-- |
| conservative | 完成（WIN） | 复用协作路径 + lwe_decode 文件模式，12 步解出 |
| aggressive | 被终止 | 兄弟解出后 kill |
| innovative | 被终止 | 兄弟解出后 kill |

## 备注

- 决定性因素：lwe_decode 文件模式（上轮 agent 自研 LLL 失败，本轮工具一步解出）
- 协作总线复用哈密顿路径与误差数据，显著缩短前置探测
- 完整原始 JSONL 轨迹保留在本地，不入库（避免体积与敏感信息扩散）
