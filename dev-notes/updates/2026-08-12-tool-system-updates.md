# 更新记录：工具系统综合升级（复合求解工具 / 工具目录 / 注入机制 / 补充与修复）

- 日期：2026-08-12
- 版本：WING-Corvus（渡鸦）——最新版本
- 范围：汇总 WING 系列演进过程中工具系统的全部迭代沉淀（部分来自 WING-Goose 时代迭代，部分为渡鸦时代新增/增强），统一收录于本文

## 概述

工具系统是解题成功率提升的主驱动之一。当前 `ctf_agent/tools/` 含 40 个工具模块 + 6 个 C 加速源码，覆盖 crypto / reverse / web / pwn / forensics / misc / osint 七大领域。本文按五类更新汇总：复合求解工具、工具使用说明、工具信息注入、工具补充、工具修复。

## 1. 复合求解工具

复合求解工具在单次调用内组合多种解法或自动路由子模式，减少 agent 反复试错的步数开销：

| 工具 | 定位 | 复合点 |
| :-- | :-- | :-- |
| binary_deep_analyze | 深度逆向分析 | mode 子模式：`auto / ieee / gameboy / constants / crypto / stat`；auto 内做算法指纹预检（AES S-box / TEA delta / RSA e=65537 / secp256k1 prime）自动路由到 crypto；高熵 ELF 路由到 stat；Nintendo logo + ROM 尺寸特征路由到 gameboy |
| cgb_solve | GBC ROM 逆向复合求解 | 静态分析（加密 flag 段 + palette key 段 + Feistel 解密 + 字符映射）→ pyboy 模拟 dump WRAM 逐级降级 |
| fluffy_solve | Flutter APK 复合求解 | 解压 APK → 提取 libapp.so → 搜 base62 密文 + 时间戳 → 远端 crack.py 暴力破解 PIN → 拼接 flag |
| lwe_decode | LWE 解码（已知 \|e\| 恢复 s） | `inline / file` 双输入模式（大矩阵场景）；按幅度缩放构造嵌入格 + LLL 恢复误差向量 → mod-q 求解私钥 → 数学自动验证 A·s+e≡b (mod q) |
| des_cryptanalysis | Narrow_DES 变体密钥恢复 | 32-bit 子密钥 MITM（C 加速）→ Z3 兜底 → Python des_block 验证 |
| feistel_decrypt | Feistel 密码反向暴力 | 已知前缀约束 + 2^32 low_key 暴力；C 加速主路径 + Python 兜底 |
| crypto_rsa | RSA 组合攻击 | factordb / 共模 GCD / Fermat / Pollard rho / 小 e 开方 / 共模攻击 / Wiener 自动组合 |
| crypto_classic | 经典编码/古典密码组合 | base64/base32/hex/rot/atbash/morse 多层自动解码 + 单字节 XOR 爆破 + 自动识别 flag |
| audio_stego_sweep | 音频隐写参数扫描 | 自动扫描频率/阈值/窗口/步长/密码组合，FFT 峰值检测 + LSB 提取 + 长度头 + XOR 解密 |
| mem_xor_analyze | 内存 dump XOR 分析 | `header_concat / header_per_page / full_concat / full_per_page` 四模式 + DEADBEEF 等内存标记剥离 |
| web_recon | 组合侦查 | 指纹识别 + 常见敏感路径探测一步完成 |

## 2. 工具使用说明（tool_catalog）

`data/knowledge/tool_catalog/tool_catalog.json` 提供结构化的工具使用说明，是 agent 选择工具时的权威依据：

- **22 个工具条目**，每条含 `name / speed / function / usage / params（含默认值）/ scenarios / domain / tool_chain / note`
- **9 条工具链**：reverse_elf_binary / reverse_apk / reverse_gameboy / reverse_ieee_float / crypto_rsa / web_exploit / pwn_exploit / osint_geolocation / forensics_memory
- **15 条场景映射**，如"遇到疑似含密码算法的二进制 → `binary_deep_analyze(mode='crypto')`"

## 3. 工具信息注入

- **加载**：KnowledgeBase 启动时加载 tool_catalog，缺失时置空不报错，保证系统可用性。
- **过滤**：按题型映射 domain → 工具按 `domain ∈ (domain, "all")` 过滤 → 工具链按 domain 过滤 → 场景映射按 Jaccard 相似度 > 0.05 过滤。
- **注入点**：仅注入**战术层（tactic）** system prompt，按"阶段执行策略 → playbooks → pitfalls → patterns → 工具目录 → 结构化知识"的顺序；战略层/总指挥不注入工具目录（避免干扰高层决策）。
- **预装工具提示**：role_guides/agents/ 共 84 个 agent 文件，其中 43 个注入"工具预装: angr/pwntools/jadx/apktool/sage/fpylll/tshark/binwalk/exiftool/volatility/ocr 等已预装, 严禁用 pip install / apt-get install 重新安装（会浪费步数）"；P4 验证阶段不注入该提示。

## 4. 工具补充

单体/专项工具按领域补齐（Sprint 8 ~ 37，横跨 WING-Goose 与渡鸦时代）：

- **基础（L1 内置）**：base64/hex/url 编解码、strings、file_type、hex_dump、caesar_cipher、rot13、hash_compute / hash_identify
- **逆向**：ghidra_headless / radare2（L3）、binary_analyze（结构化分析）、binary_constants（大整数 / IEEE 浮点 / 字符串 / 关键函数）、angr_symbolic_exec、apk_jadx / apktool
- **密码**：ecdsa_nonce_reuse、sage_common_d_attack（LLL 公共私钥）、zkp_forge_proof、otp_xor_analyze、aes_sidechannel、hash_collision、mceliece_analyze、bkcrack_attack（zipCrypto 已知明文，后台运行+进度检查）
- **Web**：web_fingerprint / web_dirscan / web_sqli / http_request、multi_encode / auto_decode / url_partial_encode / php_filter_chain、lfi_scanner / lfi_log_inject
- **Pwn**：pwn_checksec / pwn_cyclic / pwn_ropgadget / pwn_exploit、exploit_template（exploit 骨架生成）
- **取证 / OSINT**：exiftool / steghide / binwalk / tshark、osm_geocode、web_search（含反 writeup 护栏）、ocr（含假阳性检测）、vision_analyze（图片 / 视频 / 音频多模态）
- **协作**：share_finding / check_findings（消息总线，零侵入）、list_shared_files / read_shared_file（同题共享）、remember_fact（中期记忆）
- **执行层**：ssh_exec / ssh_python / ssh_upload（docker 优先、ssh 降级；工具主名统一 `ssh_*`，`docker_*` 为别名）

## 5. 工具修复

| 工具 | 修复点 |
| :-- | :-- |
| docker_tool | Windows 盘符 `C:` 被 `partition(":")` 拆成命名卷 "C" 导致附件挂载丢失 → 卷规格解析修复 |
| base.py JSON 解析 | LLM 输出含 `{}` 的解释文本导致 json.loads 失败 → 配平花括号提取完整 JSON 对象（跳过字符串 / 转义 / 嵌套） |
| ssh_tool | 环境降级检测正则灾难性回溯（长输出 CPU 100% 卡死）→ 检测输入截断至 7KB |
| http.py | httpx params 整体替换 URL 已有 query 导致参数丢失 → 仅显式传参时使用 |
| des_tool | 磁盘预检目录不存在导致误报磁盘不足 → 改用父目录 /root |
| ecdsa_tool | z1/z2 必填导致缺参数 TypeError → 有 msg 时按 hash_algo 自动算 z |
| lwe_tool | 大矩阵无法手填 JSON → 新增 file 模式 + 数学自动验证（杜绝 LLL 误报） |
| aes_sidechannel | 本地 source_file 缺失路径断裂 → 尝试容器内读取 + 纳入工具自检清单 |
| ocr_tool | tesseract 状态日志被误当识别结果 → 假阳性检测标记 |
| exploit_template | usb.capdata 可能返回空 → 直接解析 pcap 二进制 |
| 执行层注册 | docker 工具链从 ssh_client 分支移出，纯 Docker 环境不再丢执行层 |

## 关联记录

- 工具目录注入与 role_guides 重构：`updates/2026-08-08-role-guides-restructure.md`
- LWE 工具新增与上下文控制：`updates/2026-08-06-context-compressor.md`
- AESSidechannel 路径修复：`updates/2026-08-11-brainteaser-capability.md`
- 版本演进（工具链补齐驱动成功率）：`tests/2026-07-22-version-evolution.md`
