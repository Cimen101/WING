"""L2 密码学 LLL 攻击工具 (Sprint 12 M2 新增).

封装 fpylll 实现的 Common Private Exponent (Common d) 攻击,
无需依赖庞大的 sagemath, 适合 Sprint 12 修复 Triplet_Tweak 微退化.

适用场景:
- 多个 RSA 实例 (n_i, e_i, c_i) 共享同一个短私钥 d
- n_i 接近 (1024 bits 量级)
- d 远小于 n_i (d bits < n bits / 3)

实现原理 (基于 v7 18 步成功算法):
W = isqrt(min(n_1, ..., n_k))
构造 4x4 格 B:
  B[0] = [n1, 0, 0, 0]
  B[1] = [0, n2, 0, 0]
  B[2] = [0, 0, n3, 0]
  B[3] = [e1, e2, e3, W]

目标短向量: (k1*n1 - d*e1, k2*n2 - d*e2, k3*n3 - d*e3, -d*W)
LLL 还原后第 0 行最后一列 = -d*W (或 d*W)
d = abs(LLL_B[0][3]) // W

验证: pow(2, e1*d, n1) == 2
解密: m_i = pow(c_i, d, n_i)

降级:
- 若 fpylll 不可用, 返回 ERROR 提示装 fpylll 或用 sage
- 若 k != 3, 提示用更通用的实现
"""
from __future__ import annotations

import math
import re
from typing import Any, Optional

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool


_MAX_OUTPUT = 4000
_TRUNCATED_SUFFIX = "\n... (输出截断, 共 {total} 字符)"


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + _TRUNCATED_SUFFIX.format(total=len(text))


def _check_fpylll(ssh: SSHClient) -> bool:
    """检测 fpylll 是否可用."""
    r = ssh.exec_cmd("python3 -c 'import fpylll; print(fpylll.__version__)'", timeout=10)
    return r.is_success and "0" in r.stdout  # 0.6.x


def _check_sage(ssh: SSHClient) -> bool:
    """检测 sagemath 是否可用 (备选)."""
    r = ssh.exec_cmd("which sage 2>&1 || which sagemath 2>&1", timeout=5)
    return r.is_success and ("/sage" in r.stdout or "/sagemath" in r.stdout)


# ============ CommonDAttackTool ============

class CommonDAttackTool(Tool):
    """Common Private Exponent RSA LLL 攻击 (Sprint 12 M2).

    用途: 多个 RSA 实例共享同一个短私钥 d 时, 用 LLL 格还原 d.
    适用: 3 个 (n_i, e_i, c_i) 元组, 共享 d, d 远小于 n_i.

    算法参考 v7 18 步成功实现 (triplet_tweak 验证):
    W = isqrt(min(n_1, n_2, n_3))
    B = [[n1, 0, 0, 0], [0, n2, 0, 0], [0, 0, n3, 0], [e1, e2, e3, W]]
    LLL.reduction(B)
    d = abs(B[0][3]) // W
    """

    name = "common_d_attack"
    description = (
        "Common Private Exponent RSA LLL 攻击. 多个 RSA 实例 (n_i, e_i, c_i) 共享短私钥 d 时, "
        "用 LLL 格还原 d. 内部使用 fpylll 0.6.x (无需 sagemath).\n"
        "输入: 3 个 (n_i, e_i, c_i) 元组, 都用十进制大整数. 输出: 还原的 d + 用 d 解密的明文.\n"
        "适用场景: Triplet_Tweak 类 RSA 共享私钥题 (v7 18步成功, v8 退化到 26 步, 本工具一步搞定).\n"
        "Kali 上 fpylll 已装 (0.6.4), 无需额外安装.\n"
        "降级: 如果 fpylll 不可用, 提示用 sage (apt install sagemath) 或 ssh_python 手动实现."
    )
    parameters = {
        "type": "object",
        "properties": {
            "n1": {"type": "string", "description": "实例 1 的模数 (十进制字符串)"},
            "e1": {"type": "string", "description": "实例 1 的公钥指数 (十进制字符串)"},
            "c1": {"type": "string", "description": "实例 1 的密文 (十进制字符串)"},
            "n2": {"type": "string", "description": "实例 2 的模数 (十进制字符串)"},
            "e2": {"type": "string", "description": "实例 2 的公钥指数 (十进制字符串)"},
            "c2": {"type": "string", "description": "实例 2 的密文 (十进制字符串)"},
            "n3": {"type": "string", "description": "实例 3 的模数 (十进制字符串, 可选)"},
            "e3": {"type": "string", "description": "实例 3 的公钥指数 (十进制字符串, 可选)"},
            "c3": {"type": "string", "description": "实例 3 的密文 (十进制字符串, 可选)"},
        },
        "required": ["n1", "e1", "c1", "n2", "e2", "c2"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh = ssh_client
        self._fpylll_ok: Optional[bool] = None
        self._sage_ok: Optional[bool] = None

    def _ensure(self) -> str:
        if self._fpylll_ok is None:
            self._fpylll_ok = _check_fpylll(self.ssh)
        if not self._fpylll_ok:
            if self._sage_ok is None:
                self._sage_ok = _check_sage(self.ssh)
            if self._sage_ok:
                return ""  # sagemath 可用, fpylll 也通常可用
            return (
                "ERROR: fpylll 与 sagemath 都未在 Kali 上安装.\n"
                "方案 A: pip3 install fpylll  (推荐, 体积小, 5-10 分钟)\n"
                "方案 B: apt install sagemath  (体积大 1GB+, 30+ 分钟编译)\n"
                "降级: 用 ssh_python + sympy/numpy 写简化攻击 (如 Wiener / CRT + 三次方根)."
            )
        return ""

    def execute(
        self,
        n1: str,
        e1: str,
        c1: str,
        n2: str,
        e2: str,
        c2: str,
        n3: str = "",
        e3: str = "",
        c3: str = "",
        **_: Any,
    ) -> str:
        err = self._ensure()
        if err:
            return err

        # 解析为整数
        try:
            n_list = [int(n1), int(n2)]
            e_list = [int(e1), int(e2)]
            c_list = [int(c1), int(c2)]
            if n3 and e3 and c3:
                n_list.append(int(n3))
                e_list.append(int(e3))
                c_list.append(int(c3))
        except ValueError as e:
            return f"ERROR: 参数解析失败: {e}. 确保 n/e/c 都是十进制整数."

        k = len(n_list)
        if k < 2 or k > 3:
            return f"ERROR: 当前实现支持 2 或 3 个实例, 实际 {k} 个."

        # 完整攻击脚本 (基于 v7 18 步成功算法)
        # 注意: 用 str.replace() 注入, 避免 .format() 与 f-string 冲突
        n1_val, n2_val, n3_val = n_list[0], n_list[1], n_list[2] if k >= 3 else 0
        e1_val, e2_val, e3_val = e_list[0], e_list[1], e_list[2] if k >= 3 else 0
        c1_val, c2_val, c3_val = c_list[0], c_list[1], c_list[2] if k >= 3 else 0

        script = """
import math
from fpylll import IntegerMatrix, LLL
from math import gcd

# 实例数据 (由工具注入)
n1 = __N1__
n2 = __N2__
n3 = __N3__
e1 = __E1__
e2 = __E2__
e3 = __E3__
c1 = __C1__
c2 = __C2__
c3 = __C3__

n_list = [n1, n2, n3]
e_list = [e1, e2, e3]
c_list = [c1, c2, c3]
k = 3

# 验证: gcd(n_i, n_j) = 1 (确保不是共享因子)
for i in range(k):
    for j in range(i+1, k):
        ni = n_list[i]
        nj = n_list[j]
        g = gcd(ni, nj)
        if g > 1:
            print(f"  WARNING: gcd(n{i+1}, n{j+1}) = {g}, 可能是共享因子!")

# W = floor(sqrt(min(n_i))) to balance norm
W = int(math.isqrt(min(n_list)))
print(f"  W bits = {W.bit_length()}")

# 构造 (k+1) x (k+1) 格
# B[0..k-1] = n_i 在对角
# B[k] = [e_1, e_2, ..., e_k, W]
M = [[0]*(k+1) for _ in range(k+1)]
for i in range(k):
    M[i][i] = n_list[i]
M[k] = e_list + [W]

print(f"  构造 {len(M)}x{len(M[0])} 格, 起始最后行前 3 个: {M[-1][:3]}, W={W.bit_length()}bits")
print("  运行 LLL reduction...")
mat = IntegerMatrix.from_matrix(M)
LLL.reduction(mat)
print("  LLL 完成")

# 提取 d: 检查每行最后一列
d_found = None
for i in range(k+1):
    last = abs(mat[i, k])
    if last == 0:
        continue
    d_candidate = last // W
    if d_candidate == 0:
        continue
    # 验证: pow(2, e1*d, n1) == 2
    if pow(2, e_list[0] * d_candidate, n_list[0]) == 2:
        d_found = d_candidate
        print(f"  ✅ Row {i}: d = {d_candidate} (bits={d_candidate.bit_length()})")
        break
    else:
        print(f"  Row {i}: d_candidate={d_candidate} 验证失败")

if d_found is None:
    print("  ❌ LLL 未找到有效 d. 可能 d 不够短, 或格构造需调整.")
    # 退路: 输出所有候选让 LLM 手动选
    for i in range(k+1):
        last = abs(mat[i, k])
        if last > 0:
            print(f"  Row {i}: last = {last} (bits={last.bit_length()})")
else:
    d = d_found
    # 解密所有实例
    print("  --- 解密 ---")
    for i in range(k):
        m = pow(c_list[i], d, n_list[i])
        mb = m.to_bytes((m.bit_length()+7)//8, 'big') if m > 0 else b''
        try:
            print(f"  m{i+1} = {mb.decode('utf-8', errors='replace')[:200]}")
        except Exception as ex:
            print(f"  m{i+1} decode error: {ex}")

print("Done")
"""
        # 用 str.replace() 注入变量, 避免 .format() 与 f-string 冲突
        script = (
            script
            .replace("__N1__", str(n1_val))
            .replace("__N2__", str(n2_val))
            .replace("__N3__", str(n3_val))
            .replace("__E1__", str(e1_val))
            .replace("__E2__", str(e2_val))
            .replace("__E3__", str(e3_val))
            .replace("__C1__", str(c1_val))
            .replace("__C2__", str(c2_val))
            .replace("__C3__", str(c3_val))
        )
        # 写到远程文件并执行
        remote_script = "/tmp/common_d_attack.py"
        # 写文件
        r = self.ssh.exec_cmd(
            f"cat > {remote_script} << 'PYEOF'\n{script}\nPYEOF",
            timeout=10,
        )
        if not r.is_success:
            return f"ERROR: 写脚本失败: {r.stderr[:200]}"

        r = self.ssh.exec_cmd(f"python3 {remote_script}", timeout=120)
        output = r.stdout or ""
        if r.is_success and output:
            return f"=== Common d LLL 攻击 (Sprint 12 M2) ===\n{_truncate(output)}"
        return f"ERROR: 攻击失败: {r.stderr[:300] or 'no output'}"


# ============ 工厂函数 ============

def sage_tools(ssh_client: SSHClient) -> list[Tool]:
    """返回密码学 LLL 攻击工具集 (Sprint 12 M2)."""
    return [CommonDAttackTool(ssh_client)]
