# 测试报告：WING-Corvus — crypto / hard（LWE + 哈密顿路径）

- 日期：2026-08-06
- 内容为公开可发布的测试摘要（时间线 + 统计），原始轨迹保留在本地

## 题目来源与信息

| 项 | 值 |
| :-- | :-- |
| 比赛来源 | Google CTF 2025 资格赛（quals） |
| 题目 | filtermaze（crypto） |
| 难度 | hard |
| 题型机制 | 哈密顿路径前缀预言（check_path）+ LWE（b = A·s + e mod q） |
| 关键参数 | LWE n=50 / m=100 / q=1009；误差向量分量绝对值 \|e\| 全部泄露 |
| 附件 | filtermaze.py / graph.json / lwe_pub_params.json |
| 服务 | 远程 nc：check_path（前缀预言 + 完整路径返回 \|e\|）/ get_flag（提交 s） |
| flag 格式 | CTF{...} |

## 测试目标

验证三项升级在真实 hard 题上的端到端效果：

1. 智能上下文压缩（长上下文不坍塌）
2. lwe_decode 工具（已知 |e| 恢复 s）
3. 合规联网搜索 + 协作总线（无外部题解依赖）

## 结果对比（同一题目两轮运行）

| 指标 | 修复前 | 修复后 |
| :-- | :-- | :-- |
| 结果 | 失败（tokens 熔断） | **通过** |
| 用时 | 713s（未解出） | **84s** |
| 步数 | 95 步 | 12 步 |
| tokens | 4,001,723（熔断 4M 上限） | 506,617 |
| 格式错误 | 尾部连续空输出（坍塌） | 0 |

## 轨迹摘要（通过轮 12 步）

```
step 1    ssh_exec: 读附件源码 filtermaze.py，梳理 check_path 前缀预言与 LWE 构造
step 2    ssh_exec: 读 graph.json（30 节点图）+ lwe_pub_params.json（A/b 维度）
step 3    ssh_exec: 确认 A(100×50)/b(100)/q=1009 与协议要点
step 4    ssh_python: 尝试自行探测秘密路径（脚本语法错误 1 次，快速放弃）
step 5    ssh_python: 复用兄弟 agent 总线共享的哈密顿路径 [0,15,1,16,...]（30 节点）
step 6    ssh_python: 提交完整路径 → 远程返回真实 lwe_error_magnitudes（100 个 |e|）
step 7    lwe_decode: 首次尝试 data_file=lwe_pub_params.json（缺 error_magnitudes 键）→ 报错列出可用键
step 8    ssh_python: 构造正确数据文件 lwe_data.json（A/b/mags/q 拼装）
step 9    lwe_decode: data_file 求解成功 + 数学验证通过（A·s+e≡b mod 1009）
step 10   ssh_python: get_flag 提交恢复的 s → status=success + flag
step 11-12 Final Answer（基于真实观测提交）
```

## 关键结论

- **lwe_decode 文件模式是决定性改进**：上一轮 agent 因 A 矩阵无法手填放弃工具、自研 LLL 失败（约 40 步泥潭）；本轮两步完成求解
- **协作总线复用**路径与误差数据，省去约 30 次前缀探测（约 30 步）
- 12 步上下文远未饱和，零格式错误；压缩机制保障长步骤场景不坍塌

## 回归

- 54 个既有单元测试全绿（memory / react / 空输出处理等）
