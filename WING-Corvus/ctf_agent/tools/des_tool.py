# -*- coding: utf-8 -*-
"""L2 DES cryptanalysis 工具 (新增).

为 Narrow_DES 类自定义 DES 变体提供密钥恢复能力.
本题 DES 变体特征:
- 48-bit 块 (24-bit L + 24-bit R)
- 64-bit key 拆为 2 个 32-bit sub-key (高/低 32 位)
- 32 轮: rounds 0-15 用 sub_key0, rounds 16-31 用 sub_key1
- 8 个 S-box: 每个 4 bits -> 3 bits
- 自定义 P-box (24 bits)

攻击算法:
- 输入 2+ 个已知明文-密文对 (m, c) 各 12 hex chars
- 主算法: 32-bit 子密钥中间相遇 (des_mitm32.c)
    * 对两个 32-bit 子密钥做 2^32 + 2^32 相遇, 正确恢复完整 64-bit key
    * 旧 24-bit MITM 假设子密钥高 8 位=0, 对真实部署 (sha256(flag)[:8]) 必然失败
- 兜底: Z3 求解 2 个 32-bit sub-key (32 轮常 timeout unknown)
- 验证: des_block(m, key) == c
- 自动输出恢复的 64-bit key (hex)

降级:
- 若 32-bit MITM 超时/磁盘不足, 回退 Z3 并提示增加资源
- 若已知对不足, 提示需要 >= 2 个
"""
from __future__ import annotations

from typing import Any, Optional

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool


_MAX_OUTPUT = 4000
_TRUNCATED_SUFFIX = "\n... (输出截断, 共 {total} 字符)"


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + _TRUNCATED_SUFFIX.format(total=len(text))


def _check_z3(ssh: SSHClient) -> bool:
    """检测 z3-solver 是否在 Kali 上可用.

    z3 可能装在 3 个位置:
    - /opt/ctf_venv (Python 3.11, 装的)
    - /usr/local/lib/python3.13/dist-packages/z3 (Kali 系统 Python 3.13)
    - /usr/lib/python3/dist-packages/z3 (apt 装的)
    """
    r = ssh.exec_cmd(
        "python3 -c 'import z3; print(\"z3 OK:\", z3.get_version_string())' 2>&1",
        timeout=10,
    )
    out = (r.stdout or "") + (r.stderr or "")
    if "z3" not in out.lower() and "Z3" not in out:
        return False
    if r.is_success and ("version" in out.lower() or "/" in out or "z3" in out.lower()):
        return True
    return False


def _python_des_block(msg: int, key: int, rounds: int = 32) -> int:
    """Python 实现的 des_block (与 server 一致, 用于验证)."""
    P = [8, 18, 3, 2, 15, 24, 10, 14, 20, 7, 5, 13, 1, 6, 21, 9,
         4, 11, 23, 22, 12, 19, 16, 17]
    S = [
        [5, 3, 0, 2, 7, 1, 4, 6, 1, 6, 4, 7, 5, 0, 3, 2],
        [4, 1, 0, 5, 3, 7, 6, 2, 1, 4, 0, 5, 2, 6, 3, 7],
        [3, 4, 2, 0, 7, 6, 1, 5, 3, 7, 6, 0, 4, 2, 1, 5],
        [5, 6, 4, 2, 7, 0, 3, 1, 6, 5, 7, 2, 1, 3, 4, 0],
        [5, 6, 7, 3, 1, 0, 4, 2, 3, 6, 2, 1, 7, 4, 0, 5],
        [0, 3, 1, 4, 6, 5, 2, 7, 0, 3, 5, 4, 7, 6, 1, 2],
        [6, 0, 4, 2, 3, 5, 1, 7, 0, 6, 7, 3, 2, 1, 4, 5],
        [0, 5, 6, 2, 3, 7, 4, 1, 2, 4, 0, 7, 3, 1, 5, 6],
    ]
    L = (msg >> 24) & 0xFFFFFF
    R = msg & 0xFFFFFF
    sub_k = [(key >> 32) & 0xFFFFFFFF, key & 0xFFFFFFFF]
    for i in range(rounds):
        expanded = 0
        for j in range(7):
            expanded |= ((R >> (20 - 3 * j)) & 0xF) << (28 - 4 * j)
        expanded |= (R & 7) << 1 | (R >> 23)
        expanded ^= sub_k[i // 16]
        s_output = 0
        for j in range(8):
            temp = (expanded >> (4 * j)) & 0xF
            s_output = (s_output << 3) | S[j][temp]
        p_output = 0
        for j in range(24):
            p_output = (p_output << 1) | ((s_output >> (24 - P[j])) & 1)
        temp = R
        R = L ^ p_output
        L = temp
    return (L << 24) | R


def _forward_16(msg: int, k0: int) -> tuple[int, int]:
    """前 16 轮 Feistel, 返回 (L_16, R_16) 中间状态."""
    S = [
        [5, 3, 0, 2, 7, 1, 4, 6, 1, 6, 4, 7, 5, 0, 3, 2],
        [4, 1, 0, 5, 3, 7, 6, 2, 1, 4, 0, 5, 2, 6, 3, 7],
        [3, 4, 2, 0, 7, 6, 1, 5, 3, 7, 6, 0, 4, 2, 1, 5],
        [5, 6, 4, 2, 7, 0, 3, 1, 6, 5, 7, 2, 1, 3, 4, 0],
        [5, 6, 7, 3, 1, 0, 4, 2, 3, 6, 2, 1, 7, 4, 0, 5],
        [0, 3, 1, 4, 6, 5, 2, 7, 0, 3, 5, 4, 7, 6, 1, 2],
        [6, 0, 4, 2, 3, 5, 1, 7, 0, 6, 7, 3, 2, 1, 4, 5],
        [0, 5, 6, 2, 3, 7, 4, 1, 2, 4, 0, 7, 3, 1, 5, 6],
    ]
    P = [8, 18, 3, 2, 15, 24, 10, 14, 20, 7, 5, 13, 1, 6, 21, 9,
         4, 11, 23, 22, 12, 19, 16, 17]
    L = (msg >> 24) & 0xFFFFFF
    R = msg & 0xFFFFFF
    for _ in range(16):
        expanded = 0
        for j in range(7):
            expanded |= ((R >> (20 - 3 * j)) & 0xF) << (28 - 4 * j)
        expanded |= (R & 7) << 1 | (R >> 23)
        expanded ^= k0
        s_output = 0
        for j in range(8):
            temp = (expanded >> (4 * j)) & 0xF
            s_output = (s_output << 3) | S[j][temp]
        p_output = 0
        for j in range(24):
            p_output = (p_output << 1) | ((s_output >> (24 - P[j])) & 1)
        temp = R
        R = L ^ p_output
        L = temp
    return L, R


def _backward_16(ct: int, k1: int) -> tuple[int, int]:
    """后 16 轮 Feistel 反向, 返回 (L_16, R_16) 中间状态."""
    S = [
        [5, 3, 0, 2, 7, 1, 4, 6, 1, 6, 4, 7, 5, 0, 3, 2],
        [4, 1, 0, 5, 3, 7, 6, 2, 1, 4, 0, 5, 2, 6, 3, 7],
        [3, 4, 2, 0, 7, 6, 1, 5, 3, 7, 6, 0, 4, 2, 1, 5],
        [5, 6, 4, 2, 7, 0, 3, 1, 6, 5, 7, 2, 1, 3, 4, 0],
        [5, 6, 7, 3, 1, 0, 4, 2, 3, 6, 2, 1, 7, 4, 0, 5],
        [0, 3, 1, 4, 6, 5, 2, 7, 0, 3, 5, 4, 7, 6, 1, 2],
        [6, 0, 4, 2, 3, 5, 1, 7, 0, 6, 7, 3, 2, 1, 4, 5],
        [0, 5, 6, 2, 3, 7, 4, 1, 2, 4, 0, 7, 3, 1, 5, 6],
    ]
    P = [8, 18, 3, 2, 15, 24, 10, 14, 20, 7, 5, 13, 1, 6, 21, 9,
         4, 11, 23, 22, 12, 19, 16, 17]
    L = (ct >> 24) & 0xFFFFFF
    R = ct & 0xFFFFFF
    # 反向 16 轮: round 31 -> 16, k1 在 rounds 16-31 用
    for _ in range(16):
        # 解一轮: (L_new, R_new) = (R_old, L_old ^ F(R_old, rk))
        # 解: (L_old, R_old) = (R_new ^ F(L_new, rk), L_new)
        expanded = 0
        for j in range(7):
            expanded |= ((L >> (20 - 3 * j)) & 0xF) << (28 - 4 * j)
        expanded |= (L & 7) << 1 | (L >> 23)
        expanded ^= k1
        s_output = 0
        for j in range(8):
            temp = (expanded >> (4 * j)) & 0xF
            s_output = (s_output << 3) | S[j][temp]
        p_output = 0
        for j in range(24):
            p_output = (p_output << 1) | ((s_output >> (24 - P[j])) & 1)
        new_L = R ^ p_output
        new_R = L
        L = new_L
        R = new_R
    return L, R


def _brute_force_key(pairs: list[tuple[int, int]], verbose: bool = False) -> list[int]:
    """MITM 攻击: 2^24 + 2^24 = 2^25 总复杂度 (~10s Python).

    Strategy:
    - Phase 1: 对每个 k0 (2^24), forward 16 轮 (m1, m2) 求 (L1_mid, R1_mid, L2_mid, R2_mid)
    - Phase 2: 对每个 k1 (2^24), backward 16 轮 (c1, c2) 求同样中间状态
    - Phase 3: 匹配中间状态, 输出 candidate key
    """
    if len(pairs) < 2:
        return []
    m1, c1 = pairs[0]
    m2, c2 = pairs[1]

    # Phase 1: 2^24 forward
    if verbose:
        print(f"  Phase 1: Forward 2^24 = {1 << 24} k0 candidates...")
    forward_map: dict[tuple[int, int, int, int], list[int]] = {}
    for k0 in range(1 << 24):
        L1, R1 = _forward_16(m1, k0)
        L2, R2 = _forward_16(m2, k0)
        key = (L1, R1, L2, R2)
        if key not in forward_map:
            forward_map[key] = []
        forward_map[key].append(k0)
    if verbose:
        print(f"  Phase 1 done. {len(forward_map)} unique states.")

    # Phase 2 + 3: 2^24 backward, 匹配
    if verbose:
        print(f"  Phase 2: Backward 2^24 = {1 << 24} k1 candidates...")
    candidates: list[int] = []
    for k1 in range(1 << 24):
        L1, R1 = _backward_16(c1, k1)
        L2, R2 = _backward_16(c2, k1)
        key = (L1, R1, L2, R2)
        if key in forward_map:
            for k0 in forward_map[key]:
                full_key = (k0 << 32) | k1
                if verbose:
                    print(f"  candidate: 0x{full_key:016x}")
                candidates.append(full_key)
    if verbose:
        print(f"  Phase 2+3 done. {len(candidates)} candidates.")

    return candidates


# ============ DesCryptanalysisTool ============

class DesCryptanalysisTool(Tool):
    """Narrow_DES 类自定义 DES 密钥恢复工具.

    用途: 给定已知明文-密文对, 恢复 64-bit DES 变体密钥.

    用法:
      des_cryptanalysis(
          pairs=[(0x000000000000, 0x6ac33339a3fc), ...],  # 至少 2 对
          verify='athena{...}'  # 可选, 用来自动 verify 恢复的 key
      )

    工具接受 2+ 个 (m, c) 整数对, m 和 c 是 48-bit 整数 (12 hex chars).
    通过 Z3 用 32-bit sub-key 模型 (而非 64-bit 整体) 求解, 速度快 2^32 倍.

    降级: z3 不可用时, 返回 ERROR.
    """

    name = "des_cryptanalysis"
    description = (
        "Narrow_DES 类自定义 DES 变体密钥恢复.\n"
        "用法: des_cryptanalysis(pairs_json='[[\"000000000000\",\"6ac33339a3fc\"],...]')\n"
        "输入: pairs_json 是 JSON 字符串, 每对是 [m, c] 各 12 hex chars (至少 2 对).\n"
        "主算法: 32-bit 子密钥中间相遇 (des_mitm32.c), 正确恢复完整 64-bit key\n"
        "        (sha256(flag)[:8] 派生的子密钥高 8 位非 0, 旧 24-bit MITM 会失败).\n"
        "       资源: 数分钟 CPU + ~86GB 临时磁盘 (/root/des_mitm_tmp, 全量 nbits=32).\n"
        "快速测试: 可传 nbits=<小值> + k0base/k1base 缩小范围 (秒级).\n"
        "快速试探: 24-bit C-MITM (仅当子密钥高 8 位恰为 0 时秒级成功).\n"
        "兜底: Z3 求解 2 个 32-bit sub-key (32 轮常 timeout unknown).\n"
        "返回: 恢复的 64-bit key (hex), DES 子密钥结构, 验证结果."
    )
    parameters = {
        "type": "object",
        "properties": {
            "pairs_json": {
                "type": "string",
                "description": "JSON 字符串, [m1, c1], [m2, c2], ... (各 12 hex chars)",
            },
            "max_seconds": {
                "type": "integer",
                "description": "Z3 求解超时 (秒, 默认 60)",
            },
            "nbits": {
                "type": "integer",
                "description": "32-bit MITM 每个子密钥搜索位数 (默认 32 = 全量, 需 ~86GB 磁盘 + 数分钟). 小值用于快速测试.",
            },
            "k0base": {
                "type": "integer",
                "description": "子密钥 k0 搜索基址 (hex), 与 nbits 配合缩小范围, 用于已知高位置时的快速测试.",
            },
            "k1base": {
                "type": "integer",
                "description": "子密钥 k1 搜索基址 (hex), 与 nbits 配合缩小范围.",
            },
        },
        "required": ["pairs_json"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh = ssh_client
        self._available: Optional[bool] = None

    def _ensure(self) -> str:
        if self._available is None:
            self._available = _check_z3(self.ssh)
            if not self._available:
                return (
                    "ERROR: z3-solver 未在 Kali 上安装.\n"
                    "方案: pip3 install z3-solver"
                )
        if not self._available:
            return "ERROR: z3-solver 未在 Kali 上安装."
        return ""

    def execute(
        self,
        pairs_json: str,
        max_seconds: int = 60,
        method: str = "mitm",
        nbits: int = 32,
        k0base: int = 0,
        k1base: int = 0,
        **_: Any,
    ) -> str:
        # 默认用 MITM (比 Z3 快 ~100x, ~10s vs ~120s)
        # Z3 32 轮 DES 求解太复杂, 经常 timeout unknown
        # MITM 2^24 + 2^24 = 2^25 总复杂度, Python ~10s, 100% 成功
        if method == "mitm":
            return self._execute_mitm(pairs_json, nbits=nbits, k0base=k0base, k1base=k1base)
        # method == "z3" (fallback)
        err = self._ensure()
        if err:
            return err
        return self._execute_z3(pairs_json, max_seconds)

    def _execute_mitm(self, pairs_json: str, nbits: int = 32, k0base: int = 0, k1base: int = 0) -> str:
        """MITM 攻击实现 (+ P4 + P5).

        优先使用 C 加速版 (上传 des_mitm.c 到 Kali, 编译, 运行)
                      比 Python MITM 快 ~5-10x (Python 10s → C 1-2s)
        三层 fallback
                      1. C-MITM (24-bit, 1-2s) - 仅在 sub_key 高 8 位 = 0 时成功
                      2. Python MITM (24-bit, 60-90s) - 同样限制
                      3. Z3 32-bit fallback (30-60s) - 求解 32-bit sub-key
        限制: Z3 对 32-bit sub-key 经常 unknown (test_des_result2.txt)
                          已知 6 pairs + 120s timeout = unknown
        """
        # 解析 pairs
        import json as _json
        # 容错 single-quote JSON
        try:
            pairs_raw = _json.loads(pairs_json)
        except _json.JSONDecodeError:
            try:
                fixed = pairs_json.replace("'", '"')
                pairs_raw = _json.loads(fixed)
            except _json.JSONDecodeError as e2:
                return f"ERROR: pairs_json 解析失败: {e2}. 格式: '[[\"000000000000\",\"6ac33339a3fc\"],...]' 或 \"[['000000000000','6ac33339a3fc'],...]\""
        try:
            if not isinstance(pairs_raw, list) or len(pairs_raw) < 2:
                return "ERROR: pairs_json 必须是 [[m1,c1], [m2,c2], ...] 至少 2 对"
            pairs: list[tuple[int, int]] = []
            for pair in pairs_raw:
                if not isinstance(pair, list) or len(pair) != 2:
                    return f"ERROR: 每对必须是 [m, c] 两个 hex 字符串, 实际: {pair}"
                m_str, c_str = pair
                m_v = int(m_str, 16)
                c_v = int(c_str, 16)
                if not (0 <= m_v < (1 << 48)):
                    return f"ERROR: m 必须是 12 hex chars (48-bit), 实际: {m_str}"
                if not (0 <= c_v < (1 << 48)):
                    return f"ERROR: c 必须是 12 hex chars (48-bit), 实际: {c_str}"
                pairs.append((m_v, c_v))
        except (ValueError, TypeError, _json.JSONDecodeError) as e:
            return f"ERROR: pairs_json 解析失败: {e}"

        # 优先尝试 24-bit C 加速版本 (仅当子密钥高 8 位=0 时成功, 秒级)
        c_result = self._try_c_mitm(pairs)
        if c_result and "SUCCESS" in c_result:
            return c_result

        # 磁盘预检 + 有限 nbits 尝试, 防止全量 32-bit MITM 占满磁盘
        # 全量 32-bit MITM 需 ~86GB 磁盘 + 20 分钟, 仅在显式请求且磁盘充裕时才运行
        if nbits >= 32:
            # 先快速检测可用磁盘
            dr = self.ssh.exec_cmd("df -Pk /root 2>/dev/null | awk 'NR==2{print $4}'", timeout=10)
            free_kb = 0
            try:
                free_kb = int((dr.stdout or "0").strip().splitlines()[-1])
            except Exception:
                free_kb = 0
            # 估算 32-bit MITM 所需: 2 * 2^nbits * 10 bytes + 1GB 余量
            need_bytes = 2 * (1 << nbits) * 10
            need_kb = need_bytes // 1024 + 1 * 1024 * 1024
            if free_kb >= need_kb:
                # 磁盘充裕, 尝试 32-bit C MITM
                r32 = self._execute_mitm32(pairs, timeout=1800, nbits=nbits, k0base=k0base, k1base=k1base)
                if r32 and "FOUND" in r32:
                    return r32
            else:
                # 磁盘不足, 跳过 32-bit C MITM
                pass  # fall through to Python MITM + Z3

        # 回退: Python MITM (24-bit, ~10s)
        py_result = self._execute_mitm_python(pairs)
        if py_result and "KEY" in py_result and "0x" in py_result and "ERROR" not in py_result[:50]:
            return py_result

        # Z3 兜底加长时间 (300s 代替 60s, 32-bit 子密钥有更高概率收敛)
        z3_result = self._try_z3_fallback(pairs, max_seconds=300)
        return z3_result

    def _try_z3_fallback(self, pairs: list[tuple[int, int]], max_seconds: int = 30) -> str:
        """Z3 32-bit sub-key 求解 fallback.

        当 C-MITM 和 Python MITM 都失败时调用.
        使用 2-3 pairs (Z3 对多于 2 对的速度明显变慢), 30s timeout.

        Returns: Z3 求解结果字符串. 若 Z3 也不可解, 返回明确的 "FAILED" 信息.
        """
        import json as _json
        # Z3 对 4+ pairs 速度明显变慢, 用 2-3 pairs
        z3_pairs = pairs[:3] if len(pairs) > 3 else pairs
        # 关键: dump 为字符串格式 (hex 12 chars), 与 _execute_z3 期望的格式一致
        z3_json = _json.dumps([[f"{m:012x}", f"{c:012x}"] for m, c in z3_pairs])
        return self._execute_z3(pairs_json=z3_json, max_seconds=max_seconds)

    def _try_c_mitm(self, pairs: list[tuple[int, int]]) -> str | None:
        """尝试用 C 加速 MITM. 返回 None 表示 C 不可用."""
        import base64
        import os

        # 本地 C 源文件路径
        local_c = os.path.join(os.path.dirname(__file__), "des_mitm.c")
        if not os.path.exists(local_c):
            return None  # C 源不存在, 跳过

        with open(local_c, "r", encoding="utf-8") as f:
            c_src = f.read()
        c_b64 = base64.b64encode(c_src.encode()).decode()

        # 上传 C 源到 Kali
        remote_c = "/tmp/des_mitm.c"
        remote_bin = "/tmp/des_mitm_main"
        r = self.ssh.exec_cmd(
            f"echo '{c_b64}' | base64 -d > {remote_c} && wc -l {remote_c}",
            timeout=10,
        )
        if not r.is_success:
            return None

        # 编译
        r = self.ssh.exec_cmd(
            f"gcc -O3 -march=native -o {remote_bin} {remote_c} 2>&1",
            timeout=30,
        )
        if not r.is_success or "error" in (r.stderr or "").lower():
            return None

        # 运行 C MITM
        m1, c1 = pairs[0]
        m2, c2 = pairs[1]
        cmd = (
            f"timeout 60 {remote_bin} 0x{m1:012x} 0x{c1:012x} 0x{m2:012x} 0x{c2:012x} 2>&1"
        )
        r = self.ssh.exec_cmd(cmd, timeout=90)
        if r.is_success and "SUCCESS" in (r.stdout or ""):
            return (
                f"=== Narrow DES C-MITM (Sprint 14 P4) ===\n"
                f"{_truncate(r.stdout + r.stderr, 4000)}"
            )
        return None  # 失败, 回退到 Python

    def _execute_mitm32(
        self,
        pairs: list[tuple[int, int]],
        timeout: int = 1200,
        nbits: int = 32,
        k0base: int = 0,
        k1base: int = 0,
    ) -> str:
        """完整 32-bit 子密钥 MITM (des_mitm32.c).

        对两个 32-bit 子密钥做 2^32 + 2^32 中间相遇, 正确恢复完整 64-bit key.
        旧版 24-bit MITM 假设子密钥高 8 位 = 0, 对真实部署 (sha256(flag)[:8] 派生)
        必然失败. 本方法无需该假设.

        资源需求: 数分钟 CPU + ~135GB 临时磁盘 (/tmp/des_mitm_fwd_*.bin,
        /tmp/des_mitm_bwd_*.bin). 分桶落盘, 单桶入内存, 内存占用仅数十 MB.
        """
        import base64
        import os

        local_c = os.path.join(os.path.dirname(__file__), "des_mitm32.c")
        if not os.path.exists(local_c):
            return "ERROR: des_mitm32.c 不存在"
        with open(local_c, "r", encoding="utf-8") as f:
            c_src = f.read()
        c_b64 = base64.b64encode(c_src.encode()).decode()

        remote_c = "/tmp/des_mitm32.c"
        remote_bin = "/tmp/des_mitm32"
        r = self.ssh.exec_cmd(
            f"echo '{c_b64}' | base64 -d > {remote_c} && echo uploaded",
            timeout=10,
        )
        if not r.is_success:
            return f"ERROR: 上传 des_mitm32.c 失败: {r.stderr[:200]}"

        r = self.ssh.exec_cmd(
            f"gcc -O3 -march=native -fopenmp -o {remote_bin} {remote_c} 2>&1",
            timeout=60,
        )
        if not r.is_success:
            return f"ERROR: des_mitm32 编译失败: {r.stderr[:400]}"

        # 数据写到 / 上 (Kali /tmp 是 tmpfs 仅 ~2GB, 全量 32-bit 需 ~86GB)
        mitm_dir = "/root/des_mitm_tmp"
        # 磁盘预检: 按 nbits 估算所需空间 (2 趟各 2^nbits 条 10 字节记录)
        need_bytes = 2 * (1 << nbits) * 10
        need_kb = need_bytes // 1024 + 1 * 1024 * 1024  # +1GB 余量 (实测 80GB 峰值)
        # 修复: 之前用 {mitm_dir} 但目录不存在, df 返回空, 误报磁盘不足.
        # 现在用 /root (mitm_dir 的父目录, 一定存在) 检查可用空间.
        dr = self.ssh.exec_cmd(
            "df -Pk /root 2>/dev/null | awk 'NR==2{print $4}'", timeout=10
        )
        free_kb = 0
        try:
            free_kb = int((dr.stdout or "0").strip().splitlines()[-1])
        except Exception:
            free_kb = 0
        if free_kb < need_kb:
            need_gb = need_kb // 1024 // 1024
            return (
                f"ERROR: 磁盘空间不足运行 {nbits}-bit MITM: /root 空闲 {free_kb//1024//1024}GB, "
                f"需 >= {need_gb}GB. 请挂载更大磁盘或在更小 --nbits 下运行."
            )

        # 取前 6 对 (最多 12 个参数); 至少需 2 对
        args = []
        for m, c in pairs[:6]:
            args.append(f"0x{m:012x}")
            args.append(f"0x{c:012x}")
        cmd = (
            f"rm -rf {mitm_dir} && mkdir -p {mitm_dir}; "
            f"timeout {timeout} {remote_bin} " + " ".join(args)
            + f" --nbits {nbits} --k0base 0x{k0base:x} --k1base 0x{k1base:x}"
            + f" --dir {mitm_dir} --clean"
            + f" 2>{mitm_dir}/des_mitm32.log"
        )
        r = self.ssh.exec_cmd(cmd, timeout=timeout + 120)
        out = (r.stdout or "").strip()
        if "FOUND" in out:
            return (
                f"=== Narrow DES 32-bit MITM (Sprint 14 P6) ===\n"
                f"{_truncate(out + '\n--- log ---\n' + (r.stderr or ''), 4000)}"
            )
        if "NOTFOUND" in out:
            return "FAILED: 32-bit MITM 未找到密钥 (明文-密文对可能有误或密钥超出搜索范围)"
        # 超时 / 无输出: 读取进度日志
        log = ""
        try:
            lr = self.ssh.exec_cmd(
                f"tail -c 800 {mitm_dir}/des_mitm32.log 2>/dev/null", timeout=10
            )
            log = lr.stdout or ""
        except Exception:
            pass
        return (
            f"ERROR: 32-bit MITM 无结果 (exit={r.exit_code}). "
            f"日志尾: {log[:500] or (r.stderr or '')[:500]}"
        )

    def _execute_mitm_python(self, pairs: list[tuple[int, int]]) -> str:
        """Python MITM (24-bit, ~10s). Fallback when C version fails."""
        pairs_str = "[\n"
        for m, c in pairs:
            pairs_str += f"    (0x{m:012x}, 0x{c:012x}),\n"
        pairs_str += "]"

        script = f"""
import sys

# P-box
P = [8, 18, 3, 2, 15, 24, 10, 14, 20, 7, 5, 13, 1, 6, 21, 9,
     4, 11, 23, 22, 12, 19, 16, 17]

# S-box
S = [
    [5,3,0,2,7,1,4,6,1,6,4,7,5,0,3,2],
    [4,1,0,5,3,7,6,2,1,4,0,5,2,6,3,7],
    [3,4,2,0,7,6,1,5,3,7,6,0,4,2,1,5],
    [5,6,4,2,7,0,3,1,6,5,7,2,1,3,4,0],
    [5,6,7,3,1,0,4,2,3,6,2,1,7,4,0,5],
    [0,3,1,4,6,5,2,7,0,3,5,4,7,6,1,2],
    [6,0,4,2,3,5,1,7,0,6,7,3,2,1,4,5],
    [0,5,6,2,3,7,4,1,2,4,0,7,3,1,5,6]
]

PAIRS = {pairs_str}

def _forward_16(msg, k0):
    L = (msg >> 24) & 0xFFFFFF
    R = msg & 0xFFFFFF
    for _ in range(16):
        expanded = 0
        for j in range(7):
            expanded |= ((R >> (20 - 3 * j)) & 0xF) << (28 - 4 * j)
        expanded |= (R & 7) << 1 | (R >> 23)
        expanded ^= k0
        s_output = 0
        for j in range(8):
            temp = (expanded >> (4 * j)) & 0xF
            s_output = (s_output << 3) | S[j][temp]
        p_output = 0
        for j in range(24):
            p_output = (p_output << 1) | ((s_output >> (24 - P[j])) & 1)
        temp = R
        R = L ^ p_output
        L = temp
    return L, R

def _backward_16(ct, k1):
    L = (ct >> 24) & 0xFFFFFF
    R = ct & 0xFFFFFF
    for _ in range(16):
        expanded = 0
        for j in range(7):
            expanded |= ((L >> (20 - 3 * j)) & 0xF) << (28 - 4 * j)
        expanded |= (L & 7) << 1 | (L >> 23)
        expanded ^= k1
        s_output = 0
        for j in range(8):
            temp = (expanded >> (4 * j)) & 0xF
            s_output = (s_output << 3) | S[j][temp]
        p_output = 0
        for j in range(24):
            p_output = (p_output << 1) | ((s_output >> (24 - P[j])) & 1)
        new_L = R ^ p_output
        new_R = L
        L = new_L
        R = new_R
    return L, R

def _python_des_block(msg, key, rounds=32):
    L = (msg >> 24) & 0xFFFFFF
    R = msg & 0xFFFFFF
    sub_k = [(key >> 32) & 0xFFFFFFFF, key & 0xFFFFFFFF]
    for i in range(rounds):
        expanded = 0
        for j in range(7):
            expanded |= ((R >> (20 - 3 * j)) & 0xF) << (28 - 4 * j)
        expanded |= (R & 7) << 1 | (R >> 23)
        expanded ^= sub_k[i // 16]
        s_output = 0
        for j in range(8):
            temp = (expanded >> (4 * j)) & 0xF
            s_output = (s_output << 3) | S[j][temp]
        p_output = 0
        for j in range(24):
            p_output = (p_output << 1) | ((s_output >> (24 - P[j])) & 1)
        temp = R
        R = L ^ p_output
        L = temp
    return (L << 24) | R

def _mitm(pairs):
    if len(pairs) < 2:
        return []
    m1, c1 = pairs[0]
    m2, c2 = pairs[1]
    print(f"  Phase 1: Forward 2^24 = {{1 << 24}} k0 candidates...")
    fwd = {{}}
    for k0 in range(1 << 24):
        L1, R1 = _forward_16(m1, k0)
        L2, R2 = _forward_16(m2, k0)
        key = (L1, R1, L2, R2)
        if key not in fwd:
            fwd[key] = []
        fwd[key].append(k0)
    print(f"  Phase 1 done. {{len(fwd)}} unique states.")
    print(f"  Phase 2: Backward 2^24 = {{1 << 24}} k1 candidates...")
    cands = []
    for k1 in range(1 << 24):
        L1, R1 = _backward_16(c1, k1)
        L2, R2 = _backward_16(c2, k1)
        key = (L1, R1, L2, R2)
        if key in fwd:
            for k0 in fwd[key]:
                cands.append((k0 << 32) | k1)
    print(f"  Phase 2+3 done. {{len(cands)}} candidates.")
    return cands

print("=== Narrow DES MITM (Sprint 14 P3) ===")
print(f"  Known pairs: {{len(PAIRS)}}")
for i, (m, c) in enumerate(PAIRS):
    print(f"  Pair {{i+1}}: m=0x{{m:012x}}, c=0x{{c:012x}}")

import time
t0 = time.time()
cands = _mitm(PAIRS)
t1 = time.time()
print(f"\\n  Total: {{len(cands)}} candidates, {{t1-t0:.2f}}s")

if cands:
    for cand in cands:
        all_ok = True
        for i, (m, c) in enumerate(PAIRS):
            c_check = _python_des_block(m, cand)
            ok = (c_check == c)
            all_ok = all_ok and ok
            print(f"    Pair {{i+1}}: m=0x{{m:012x}} -> c=0x{{c_check:012x}} (expected 0x{{c:012x}}) {{'OK' if ok else 'FAIL'}}")
        if all_ok:
            print(f"\\n  ALL PAIRS VERIFIED. Key: 0x{{cand:016x}}")
            break
else:
    print(f"  FAILED: No key found")
print("Done")
"""
        remote_script = "/tmp/des_mitm.py"
        r = self.ssh.exec_cmd(
            f"cat > {remote_script} << 'PYEOF'\n{script}\nPYEOF",
            timeout=10,
        )
        if not r.is_success:
            return f"ERROR: 写脚本失败: {r.stderr[:200]}"

        # 跑 MITM (可能 10-60 秒)
        r = self.ssh.exec_cmd(
            f"cd /tmp/ctf_real4/Narrow_DES && timeout 90 python3 {remote_script}",
            timeout=120,
        )
        output = r.stdout or ""
        if output:
            return f"=== Narrow DES MITM (Sprint 14 P3) ===\n{_truncate(output, 6000)}"
        return f"ERROR: MITM 失败: {r.stderr[:300] or 'no output'}"

    def _execute_z3(self, pairs_json: str, max_seconds: int) -> str:
        """Z3 求解实现 (fallback, 经常 timeout unknown)."""
        # 解析 pairs
        import json as _json
        try:
            pairs_raw = _json.loads(pairs_json)
            if not isinstance(pairs_raw, list) or len(pairs_raw) < 1:
                return "ERROR: pairs_json 必须是 [m1,c1], [m2,c2], ... 至少 1 对"
            pairs: list[tuple[int, int]] = []
            for pair in pairs_raw:
                if not isinstance(pair, list) or len(pair) != 2:
                    return f"ERROR: 每对必须是 [m, c] 两个 hex 字符串, 实际: {pair}"
                m_str, c_str = pair
                m_v = int(m_str, 16)
                c_v = int(c_str, 16)
                if not (0 <= m_v < (1 << 48)):
                    return f"ERROR: m 必须是 12 hex chars (48-bit), 实际: {m_str}"
                if not (0 <= c_v < (1 << 48)):
                    return f"ERROR: c 必须是 12 hex chars (48-bit), 实际: {c_str}"
                pairs.append((m_v, c_v))
        except (ValueError, TypeError, _json.JSONDecodeError) as e:
            return f"ERROR: pairs_json 解析失败: {e}. 格式: '[[\"000000000000\",\"6ac33339a3fc\"],...]'"

        # 构造 pairs 列表和 Z3 脚本
        pairs_str = "[\n"
        for m, c in pairs:
            pairs_str += f"    (0x{m:012x}, 0x{c:012x}),\n"
        pairs_str += "]"
        timeout_s = str(max_seconds)

        script = """
import sys
from z3 import *

# P-box
P = [8, 18, 3, 2, 15, 24, 10, 14, 20, 7, 5, 13, 1, 6, 21, 9,
     4, 11, 23, 22, 12, 19, 16, 17]

# S-box (4 bits -> 3 bits)
S = [
    [5,3,0,2,7,1,4,6,1,6,4,7,5,0,3,2],
    [4,1,0,5,3,7,6,2,1,4,0,5,2,6,3,7],
    [3,4,2,0,7,6,1,5,3,7,6,0,4,2,1,5],
    [5,6,4,2,7,0,3,1,6,5,7,2,1,3,4,0],
    [5,6,7,3,1,0,4,2,3,6,2,1,7,4,0,5],
    [0,3,1,4,6,5,2,7,0,3,5,4,7,6,1,2],
    [6,0,4,2,3,5,1,7,0,6,7,3,2,1,4,5],
    [0,5,6,2,3,7,4,1,2,4,0,7,3,1,5,6]
]

PAIRS = __PAIRS__
TIMEOUT_S = __TIMEOUT__

def encrypt_z3(msg, k0, k1, rounds=32):
        # msg: 48-bit BitVec, k0/k1: 32-bit BitVec
        L = Extract(47, 24, msg)  # 24 bits
        R = Extract(23, 0, msg)   # 24 bits

        for i in range(rounds):
            sk = k0 if i < 16 else k1
            # Expand R (24 bits) to 32 bits via zero-extend to 32 bits
            R32 = ZeroExt(8, R)  # 32 bits
            # Build 32-bit expanded: 8 S-boxes, each takes 4 bits
            expanded = BitVecVal(0, 32)
            for j in range(7):
                # R >> (20 - 3*j) & 0xf, then << (28 - 4*j)
                shift_src = 20 - 3*j
                val = LShR(R32, shift_src) & BitVecVal(0xf, 32)
                shift_dst = 28 - 4*j
                expanded = expanded | (val << shift_dst)
            # last 4 bits: (R & 7) << 1 | (R >> 23)
            # R is 24-bit, so use 24-bit constants
            part_last = ((R & BitVecVal(7, 24)) << 1) | LShR(R, 23)
            expanded = expanded | ZeroExt(8, part_last)

            # XOR with sub-key
            expanded = expanded ^ sk

            # S-box: 32 bits -> 24 bits
            s_output = BitVecVal(0, 24)
            for j in range(8):
                # Take 4 bits at position 4*j
                idx = LShR(expanded, 4*j) & BitVecVal(0xf, 32)
                # Convert idx (0-15) to S[j][idx] (0-7)
                s_val = BitVecVal(S[j][0], 24)
                for v in range(1, 16):
                    s_val = If(idx == v, BitVecVal(S[j][v], 24), s_val)
                # Shift left and OR
                s_output = (s_output << 3) | s_val

            # P-box
            p_output = BitVecVal(0, 24)
            for j in range(24):
                bit = LShR(s_output, 24 - P[j]) & 1
                p_output = (p_output << 1) | bit

            # Feistel: keep R/L at 24 bits to avoid bit-width growth
            # (Previously extended to 32 bits, but R grows by 8 bits per round)
            new_R = L ^ p_output  # both 24 bits
            L = R
            R = new_R

        return Concat(Extract(23, 0, L), Extract(23, 0, R))


print("=== Narrow DES Cryptanalysis (Sprint 14 P2) ===")
print(f"  Known pairs: {len(PAIRS)}")
for i, (m, c) in enumerate(PAIRS):
    print(f"  Pair {i+1}: m=0x{m:012x}, c=0x{c:012x}")

# 关键: 用 2 个 32-bit sub-key (而非 64-bit)
# sub_key0 = 高 32 bits, sub_key1 = 低 32 bits
k0 = BitVec('k0', 32)
k1 = BitVec('k1', 32)

solver = Solver()
for m, c in PAIRS:
    msg = BitVecVal(m, 48)
    ct = encrypt_z3(msg, k0, k1)
    solver.add(ct == BitVecVal(c, 48))

print(f"  Adding {len(PAIRS)} constraints...")
print(f"  Timeout: {TIMEOUT_S}s")

# 设置 timeout
solver.set("timeout", TIMEOUT_S * 1000)  # Z3 timeout 单位是 ms

import time
t0 = time.time()
result = solver.check()
t1 = time.time()
print(f"  Result: {result} (elapsed: {t1-t0:.2f}s)")

if result == sat:
    model = solver.model()
    k0_v = model.eval(k0).as_long()
    k1_v = model.eval(k1).as_long()
    full_key = (k0_v << 32) | k1_v
    print(f"  sub_key0 (high 32) = 0x{k0_v:08x}")
    print(f"  sub_key1 (low 32)  = 0x{k1_v:08x}")
    print(f"  full_key (64)       = 0x{full_key:016x}")

    # 验证
    def des_block(msg, key, rounds=32):
        L = (msg >> 24) & ((1<<24)-1)
        R = msg & ((1<<24)-1)
        sub_k = [(key >> 32) & ((1<<32)-1), key & ((1<<32)-1)]
        for i in range(rounds):
            expanded = 0
            for j in range(7):
                expanded |= ((R >> (20 - 3*j)) & 0xf) << (28 - 4*j)
            expanded |= (R & 7) << 1 | (R >> 23)
            expanded ^= sub_k[i // 16]
            s_output = 0
            for j in range(8):
                temp = (expanded >> (4*j)) & 0xf
                s_output <<= 3
                s_output |= S[j][temp]
            p_output = 0
            for j in range(24):
                p_output <<= 1
                p_output |= (s_output >> (24 - P[j])) & 1
            temp = R
            R = L ^ p_output
            L = temp
        return (L << 24) | R

    print(f"  --- Verification ---")
    all_ok = True
    for i, (m, c) in enumerate(PAIRS):
        c_check = des_block(m, full_key)
        ok = (c_check == c)
        all_ok = all_ok and ok
        print(f"  Pair {i+1}: m=0x{m:012x} -> c=0x{c_check:012x} (expected 0x{c:012x}) {'OK' if ok else 'FAIL'}")
    if all_ok:
        print(f"  ALL PAIRS VERIFIED. Key is correct: 0x{full_key:016x}")
    else:
        print(f"  Some pairs failed. Z3 may have produced invalid solution.")
else:
    print(f"  FAILED: Z3 returned {result}. 可能需要更多 known pairs.")
print("Done")
"""
        script = (
            script
            .replace("__PAIRS__", pairs_str)
            .replace("__TIMEOUT__", timeout_s)
        )

        # 写到远程文件并执行
        remote_script = "/tmp/des_cryptanalysis.py"
        r = self.ssh.exec_cmd(
            f"cat > {remote_script} << 'PYEOF'\n{script}\nPYEOF",
            timeout=10,
        )
        if not r.is_success:
            return f"ERROR: 写脚本失败: {r.stderr[:200]}"

        # Z3 求解可能较慢, 给充足 timeout
        r = self.ssh.exec_cmd(
            f"timeout {max_seconds + 30} python3 {remote_script}",
            timeout=max_seconds + 60,
        )
        output = r.stdout or ""
        if output:
            return f"=== Narrow DES Cryptanalysis (Sprint 14 P2) ===\n{_truncate(output, 6000)}"
        return f"ERROR: 攻击失败: {r.stderr[:300] or 'no output'}"


# ============ 工厂函数 ============

def des_tools(ssh_client: SSHClient) -> list[Tool]:
    """返回 DES 密码分析工具集."""
    return [DesCryptanalysisTool(ssh_client)]
