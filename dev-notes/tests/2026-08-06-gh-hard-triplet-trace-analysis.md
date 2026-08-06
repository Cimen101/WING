# Triplet Tweak 高效解题轨迹分析报告

日期: 2026-08-06 · 题目: Triplet Tweak (crypto, hard, athena CTF 2026)
结果: **SOLVED 56s** · winner=conservative (40s) · flag=`athena{sh4r3d_d_3xp}`
题目本质: 共享小私钥 d 的多 RSA 实例攻击 (LLL/Wiener 恢复 d 后解密)

---

## 一、完整轨迹时间线

### conservative（胜出, 40s, 5 步）

| 步 | 动作 | 内容 | 耗时 |
|----|------|------|------|
| 1 | ssh_exec `cat pub.txt` | 读取附件, 提取 n1..n3/e1..e3/c1..c3 | ~8s |
| 2 | **common_d_attack** 工具 | 传入三组 (n,e,c), LLL 恢复 d=340bit, 解密 m1=m2=m3=`athena{sh4r3d_d_3xp}` | ~5s |
| 3 | Final Answer 提交 | **被 flag 验证器误拒** (工具计算产物被 LLM 审查误判) | ~12s |
| 4 | ssh_python 独立验证 | 实现 Wiener 连分数攻击 + 用 d 独立解密, 输出 `m1 bytes: b'athena{...}'` | ~8s |
| 5 | Final Answer 提交 | **通过** (真实计算产物) → 胜出 | ~8s |

### aggressive（4 步, 同步解出但提交被拒后未重算成功）

| 步 | 动作 | 内容 |
|----|------|------|
| 1 | ssh_exec `cat pub.txt` | 读取附件 |
| 2 | common_d_attack 工具 | 解出 `athena{sh4r3d_d_3xp}` |
| 3 | Final Answer 提交 | 被 flag 验证器误拒 |
| 4 | Final Answer 再次提交 | thought 声明"用 ssh_python 独立验证"但 action 为空直接 Final (再次被拒/被兄弟抢占) |

### innovative（4 步, 手工路径, 被兄弟解出后 kill）

| 步 | 动作 | 内容 |
|----|------|------|
| 1 | ssh_exec `cat pub.txt` | 读取附件 |
| 2 | ssh_python 连分数 | 对 e1/n1 做连分数展开 → 未命中 |
| 3 | ssh_python 公因子检查 | 三组 n 无公因子 → 转向 LLL 手工实现 |
| 4 | ssh_python fpylll | LLL 格攻击进行中 → 兄弟解出被 kill |

### 总指挥/阶段状态机

| 时间 | 事件 |
|------|------|
| t+9s | 领题分工 (三路互斥: 结构化读取/连分数尝试/非常规元数据) |
| t+24s | 心跳: 阶段=P1 P1限时=90s |
| t+50s | **单路先行触发**: conservative recon_done 含 flag → 总指挥单独下发 P3 先行 (不等待其他路) |
| t+52s | 求解完成 |

---

## 二、高效解题的关键因素

### 1. 内置工具直接命中（最大因素）
- `common_d_attack`（Sprint 12 开发的共享 d LLL 攻击工具）**一步完成"恢复 d + 解密"**。
- conservative/aggressive 在 **step 2（≈13s）就拿到 flag**，省去手动实现 LLL/Wiener 的 5-10 步。
- 这是知识库/工具库沉淀的直接收益：`common_d_attack` 是历史题目经验沉淀的内置工具。

### 2. 题目认知准确（侦查零浪费）
- 三路都在 step 1 读取附件后**立即识别"共享小 d RSA"**（无无关侦查）。
- 题面（task_desc 明确提示连分数/LLL）+ 附件结构（三组 e/n/c + 三个相同长度的密文）→ 特征高度可识别。

### 3. 阶段协调机制（P1 限时 + 单路先行）
- P1 限时 90s 兜底（本题 52s 就解完，未到限时）。
- conservative recon_done 后**单路先行 P3**（不等待其他路）——机制在真实 hard 题触发。

### 4. flag 验证器反幻觉纠偏（双刃剑）
- 第一次提交被拒 → conservative 用 ssh_python **独立实现 Wiener 攻击**真实验证 → 提交通过。
- 保证了"flag 必须来自真实计算"（防幻觉），代价是 1-2 步重算。

---

## 三、发现的问题（已修复）

### 问题 1: flag 验证器误拒"工具计算产物"（#2950 遗留）
- 现象: `common_d_attack` 输出的解密明文被 LLM 审查误判为"非靶机/附件观测"，导致
  conservative/aggressive 首次提交均被拒。
- 修复: `flag_verify.py` `_LLM_PROMPT` 增加 PASS 条件——"对附件/靶机数据执行真实计算
  得到的明文（解密/逆向/爆破/攻击输出）属合法计算产物"；False 条件收窄为仅"脚本硬编码
  flag 文本"才算自导自演。
- 影响: 修复后 aggressive 第 3 步提交即可通过（省去第 4 步重算），预计可再省 ~10s。

### 问题 2（观察）: 两路工具路径趋同
- conservative/aggressive 都直接调 common_d_attack（P1 阶段趋同）。属可接受：
  aggressive 的 P1 任务本就是"快速尝试"，且工具命中即胜利。innovative 走手工路径被 kill。

---

## 四、结论

- **56s 解出 hard 题**（40s conservative），核心功臣是**内置 common_d_attack 工具直接命中**
  + **题目特征快速识别**（无侦查浪费）+ **flag 验证器纠偏保证真实性**。
- 阶段协调机制（P1 限时/单路先行/心跳）在 hard 题正常触发。
- 唯一实质问题（flag 验证器误拒计算产物）已修复；修复后此类题预计 40s 内解出。
