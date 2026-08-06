# Sprint 36.5.2 稳定性验证报告: GitHub athena hard 单题 (Triplet Tweak)

日期: 2026-08-06 · 题目: Triplet Tweak (crypto, hard, athena CTF 2026)
结果: **SOLVED** · 用时 **56s** (conservative 40s) · flag: `athena{sh4r3d_d_3xp}`

## 一、实测轨迹关键节点

| 时间 | 事件 |
|------|------|
| 18:16:24 | 三路启动 (crypto hard, 共享小 d RSA 攻击题) |
| 18:16:33 | 总指挥领题分工 (互斥: 结构化读取/连分数快速尝试/非常规元数据) |
| 18:16:41 | conservative/aggressive 直接调用内置 common_d_attack 工具解出 flag (P1 阶段) |
| 18:16:45 | aggressive Final Answer 提交 → **被 flag 验证器误拒** (LLM 审查把工具计算产物当"非附件观测") |
| 18:16:48 | 心跳: 阶段=P1 P1限时=90s |
| 18:17:00 | conservative 被迫用 ssh_python 独立实现 Wiener 攻击重算 (输出 m1 bytes: b'athena{...}') → 通过 |
| 18:17:14 | **单路先行触发**: conservative recon_done 含 flag → 总指挥单独下发 P3 先行 (不等待其他路) |
| 18:17:16 | 求解完成 success=True steps=5 elapsed=40s (conservative) |

## 二、逐条对照 docs/阶段式协调.md 检查

| 文档要求 | 实测 | 结论 |
|----------|------|------|
| P1 三路方向互斥分工 | 领题分工三路互斥 | ✅ |
| P1 任务禁忌 | directive forbidden 下发 (机制已由 medium 题 + 单测验证) | ✅ |
| P1 每 5 步汇报进度 | progress 汇报 | ✅ |
| P1 侦查 1-2 分钟限时 | 心跳 P1限时=90s | ✅ |
| **单路先行** (完成侦查的路不等待) | **真实触发**: conservative recon_done 含 flag → 单路先行 P3, 全局仍 P1 | ✅ |
| P1→P2 全局切换 | 未发生 (题目 56s 解出, 全局阶段 P1 时已解完) | ✅ (题太快, 状态机无机会推进, 符合"谁解出谁提交") |
| 总指挥日志 (领题/心跳/单路先行) | 领题分工 + 心跳 (阶段/限时) + **单路先行日志** | ✅ |
| 反幻觉 (flag 须来自真实观测) | flag 验证器两次拦截 + agent 真实重算通过 | ✅ (见问题 1) |

## 三、发现的问题与修复

### 问题 1 (已修复): flag 验证器 LLM 审查误拒"工具计算产物" (#2950 遗留)
- 现象: conservative/aggressive 用内置 `common_d_attack` 工具 (LLL 恢复共享 d) 解密出
  `athena{sh4r3d_d_3xp}`, 提交时被 LLM 轨迹审查误判为"flag 未出现在靶机/附件观测"拒绝.
- 根因: `_LLM_PROMPT` 判定 False 的第 4 条把"agent 脚本输出"泛化, 且 PASS 情况未涵盖
  "对附件数据真实计算的解密/攻击产物" — 与 #2950 的 3DES 解密误拒同源 (Sprint 36.5 遗留待办).
- 影响: agent 被迫用 ssh_python 独立重算 (浪费 2-3 步), 可能误伤真实解出.
- 修复: [flag_verify.py](file:///c:/Users/RAINBOW/Documents/trae_projects/ctf-agent/ctf_agent/agent/flag_verify.py) `_LLM_PROMPT`:
  - PASS 增加第 2 条: **对附件/靶机数据执行真实计算得到的明文 (解密/逆向/爆破/攻击输出)
    属合法计算产物**, 前提是脚本输入不含 flag 文本 (自导自演检测由代码机制负责).
  - False 第 4 条收窄: 仅当脚本**硬编码 flag 文本** (输入含 flag) 才算自导自演;
    脚本输入是密文/密钥/参数而输出是计算明文 → 判定 PASS.
  - False 第 2 条补强: "无任何解密/逆向计算步骤" 才算凭空出现 (有计算步骤则不算).

### 问题 2 (观察, 符合设计): P1 阶段 agent 直接用解题工具解出
- conservative/aggressive 在 P1 侦查阶段 (step 2) 就调用 common_d_attack 解出 flag.
- 符合"谁解出谁提交" (用户确认); aggressive 的 P1 任务本就是"快速尝试连分数探测".
- flag 验证器兜底防幻觉: 第一次提交被拒后 agent 真实重算通过, 无幻觉 flag 放行.

### 问题 3 (观察): 题目过快导致 P2-P4 未走完
- hard 题 56s 解出 (内置工具直接命中), 阶段状态机停在 P1 (保守 recon_done → 单路先行 P3).
- 这不代表 P2/P3/P4 有缺陷 — medium 题 (Table Stakes 153s) 已完整走完 P1→P2→P3→P4.

## 四、结论

hard 题 56s 解出, **单路先行在真实 hard 题中触发** (conservative recon_done 含 flag → P3 先行,
不等待其他路), P1 限时/心跳/领题分工日志均正常. 对照文档逐条检查无阶段协调硬伤.
发现并修复 1 处遗留问题: flag 验证器 LLM 审查误拒"工具计算产物" (与 #2950 同源, 已收窄判定标准).
