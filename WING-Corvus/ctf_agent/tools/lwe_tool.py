"""通用 LWE 求解工具 (Sprint 36.4 强化工具集, Sprint 36.4.1 增强).

场景: CTF 中出现 LWE (Learning With Errors) 实例 b = A·s + e (mod q),
且误差向量各分量的**绝对值 |e|** 已知 (e_i = ±mag_i, 符号未知) 时,
用"按已知幅度缩放"的技巧: e/mag ∈ {±1} 是超短向量, 构造嵌入格 LLL 恢复 e,
再线性求解 s.

Sprint 36.4.1 增强 (filtermaze 预测试复盘):
- **文件路径模式**: A 矩阵 (m×n) 常达 100×50, agent 无法手动逐项填 JSON 参数.
  新增 data_file 参数: 指向容器内已导出的数据文件 (含 A/b/mags/q), 一行调用即可.
- **数学自动验证**: 求解后验证 A·s + e_pred ≡ b (mod q) 全部成立才返回成功,
  杜绝"LLL 误找短行导致错误 s 却报成功"的误导 (step49 玩具数据误报复盘).
- 输出明确"数学验证通过", 提升 agent 对结果的信任度, 不再重复自研 LLL.

实现: 纯 Python 生成求解脚本, 在执行容器 (wing-goose 含 fpylll) 内运行.
设计原则: 通用工具 (与 crypto_rsa/feistel_decrypt 同级), 不绑定任何具体题目.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from ctf_agent.tools.base import Tool

_MAX_OUTPUT = 3000

_SOLVER_SCRIPT = r'''
import json, sys
try:
    from fpylll import IntegerMatrix, LLL
except Exception as e:
    print(json.dumps({"error": "fpylll unavailable in container: %s" % e}))
    sys.exit(1)

d = json.load(open("/tmp/lwe_data.json", "r"))
mode = d.get("mode", "inline")
if mode == "file":
    try:
        fd = json.load(open(d["data_file"], "r"))
    except Exception as e:
        print(json.dumps({"error": "data_file 读取失败: %s (请确认文件路径在容器内可达)" % e}))
        sys.exit(1)
    if not isinstance(fd, dict):
        print(json.dumps({"error": "data_file 顶层必须是 JSON 对象 (含 A/b/error_magnitudes/q 键)"}))
        sys.exit(1)
    A = fd.get("A") or fd.get("a") or fd.get("matrix")
    b = fd.get("b") or fd.get("B")
    mags = fd.get("error_magnitudes") or fd.get("mags") or fd.get("e_mags") or fd.get("e_abs")
    q = fd.get("q") or fd.get("mod") or fd.get("lwe_q")
    if A is None or b is None or mags is None or q is None:
        print(json.dumps({"error": "data_file 缺少必要键, 可用键: %s (需要 A/b/error_magnitudes/q)" % list(fd.keys())}))
        sys.exit(1)
else:
    A = d["A"]; b = d["b"]; mags = d["mags"]; q = d["q"]
m = len(b); n = len(A[0])
if len(A) != m or any(len(r) != n for r in A) or len(mags) != m:
    print(json.dumps({"error": "shape mismatch: A=%dx%d b=%d mags=%d" % (len(A), n, len(b), len(mags))}))
    sys.exit(1)
if any(mg == 0 for mg in mags):
    print(json.dumps({"error": "error_magnitudes 含 0, 无法求模逆, 需换方法"}))
    sys.exit(1)

# 按已知幅度缩放: Al[j][i] = A[i][j] * inv(mag_i) mod q, bl[i] = b[i]*inv(mag_i) mod q
inv = [pow(mg, -1, q) for mg in mags]
Al = [[(A[i][j] * inv[i]) % q for i in range(m)] for j in range(n)]
bl = [(b[i] * inv[i]) % q for i in range(m)]

# 嵌入格 L: (1+n+m) x (m+1)
#   [ bl   1 ]
#   [ Al   0 ]   (n 行)
#   [ qI   0 ]   (m 行)
dim = 1 + n + m
L = IntegerMatrix(dim, m + 1)
for j in range(m):
    L[0, j] = bl[j]
L[0, m] = 1
for j in range(n):
    for i in range(m):
        L[1 + j, i] = Al[j][i]
    L[1 + j, m] = 0
for i in range(m):
    for j in range(m):
        L[1 + n + i, j] = q if i == j else 0
    L[1 + n + i, m] = 0

LLL.reduction(L)

def solve_mod_q(Aq, y, q, n):
    """高斯消元 mod q (q 素数), 取前 n 个独立行解 s; 失败返回 None."""
    rows = []
    for r in range(len(Aq)):
        rows.append(list(Aq[r]) + [y[r]])
    piv = []
    for r in range(len(rows)):
        if len(piv) >= n:
            break
        c = len(piv)
        piv_r = None
        for rr in range(r, len(rows)):
            if rows[rr][c] % q != 0:
                piv_r = rr
                break
        if piv_r is None:
            continue
        rows[r], rows[piv_r] = rows[piv_r], rows[r]
        invp = pow(rows[r][c] % q, -1, q)
        rows[r] = [(x * invp) % q for x in rows[r]]
        for rr in range(len(rows)):
            if rr != r and rows[rr][c] % q != 0:
                f = rows[rr][c] % q
                rows[rr] = [(rows[rr][cc] - f * rows[r][cc]) % q for cc in range(len(rows[r]))]
        piv.append(r)
    if len(piv) < n:
        return None
    s = [0] * n
    for i, r in enumerate(piv):
        s[i] = rows[r][-1] % q
    return s

def verify(A, s, e_pred, b, q):
    """数学验证: A*s + e_pred == b (mod q) 逐分量成立."""
    for i in range(len(b)):
        acc = (sum(A[i][j] * s[j] for j in range(len(s))) + e_pred[i]) % q
        if acc != b[i] % q:
            return False
    return True

found = False
for r in range(dim):
    row = [L[r, j] for j in range(m + 1)]
    last = row[-1]
    if last in (1, -1):
        if last == -1:
            row = [-x for x in row]
        if all(abs(x) <= 1 for x in row[:-1]):
            e_pred = [(row[i] * mags[i]) % q for i in range(m)]
            y = [(b[i] - e_pred[i]) % q for i in range(m)]
            s = solve_mod_q(A, y, q, n)
            if s is not None and verify(A, s, e_pred, b, q):
                print(json.dumps({"s": s, "e_pred": e_pred, "verified": True,
                                  "n": n, "m": m, "q": q}))
                found = True
                break
if not found:
    print(json.dumps({"error": "LLL 未找到满足数学验证的超短误差行 (mags/q/数据可能不匹配)"}))
'''

# 常见 data_file 键名映射（执行端提示用）
_KEYS_HINT = (
    "数据文件需含: A(矩阵) / b(向量) / error_magnitudes 或 mags 或 e_mags (|e|) / q(模数)。"
)


class LweDecodeTool(Tool):
    """LWE 解码: 已知误差绝对值 |e| (符号未知) 时恢复私钥 s (缩放格 + LLL)."""

    name = "lwe_decode"
    description = (
        "LWE (Learning With Errors) 私钥恢复 — 当已知误差向量各分量绝对值 "
        "|e|（即每个 e_i = ±mag_i，符号未知、幅度已知）时，用按幅度缩放的嵌入格 "
        "+ LLL 恢复秘密向量 s，并自动数学验证。\n"
        "数学背景: b = A·s + e (mod q)。若已知 mag=|e|，则 e/mag ∈ {±1} 是超短向量，"
        "构造 [bl; Al; q·I] 嵌入格做 LLL 可恢复 e，再线性解 s。\n"
        "两种用法:\n"
        "  1) 文件模式 (推荐): data_file='<容器内数据文件路径>', 文件为 JSON 对象，"
        "含 A (m×n 矩阵)/b (长度 m)/error_magnitudes (长度 m 的 |e|)/q。"
        "数据文件可用 ssh_python 从附件/靶机导出到 /challenge/workspace/ 下。\n"
        "  2) 内联模式: 直接传 A=<m×n 嵌套列表>, b=<长度 m 列表>, "
        "error_magnitudes=<长度 m 的 |e| 列表>, q=<模数>。\n"
        "返回: {s, e_pred, verified:true} 表示 s 已通过 A·s+e≡b (mod q) 数学验证，"
        "可直接用于 get_flag 提交；未验证通过会返回明确 ERROR。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "data_file": {"type": "string", "description": "容器内数据文件 JSON 路径 (含 A/b/error_magnitudes/q)"},
            "A": {"type": "array", "description": "LWE 公开矩阵 (m 行 n 列, 嵌套列表; 文件模式可省略)"},
            "b": {"type": "array", "description": "LWE 公开向量 (长度 m; 文件模式可省略)"},
            "error_magnitudes": {"type": "array", "description": "误差绝对值向量 |e| (长度 m; 文件模式可省略)"},
            "q": {"type": "integer", "description": "模数 (素数; 文件模式可省略)"},
        },
    }

    def __init__(self, exec_client: Any = None) -> None:
        self.exec = exec_client

    def execute(
        self,
        A: Any = None,
        b: Any = None,
        error_magnitudes: Any = None,
        q: Any = None,
        data_file: str | None = None,
        **_: Any,
    ) -> str:
        if not data_file:
            # 内联模式: 必须有完整参数
            if A is None or b is None or error_magnitudes is None or q is None:
                return (
                    "ERROR: 缺少参数。两种用法:\n"
                    "  1) data_file='<容器内JSON路径>' (含 A/b/error_magnitudes/q) — 推荐, A 矩阵大时用\n"
                    "  2) A=<矩阵>, b=<向量>, error_magnitudes=<|e|>, q=<模数> — 全量内联\n"
                    f"{_KEYS_HINT}"
                )
            try:
                A_l = [[int(x) for x in row] for row in (A or [])]
                b_l = [int(x) for x in (b or [])]
                mags = [int(x) for x in (error_magnitudes or [])]
                q_i = int(q)
            except Exception as e:  # noqa: BLE001
                return f"ERROR: 参数解析失败: {e}"
            m = len(b_l)
            if not A_l or m == 0:
                return "ERROR: A/b 为空"
            n = len(A_l[0])
            if len(A_l) != m or any(len(r) != n for r in A_l) or len(mags) != m:
                return f"ERROR: 维度不匹配 (A={len(A_l)}×{n}, b={m}, mags={len(mags)})"
            if any(mg == 0 for mg in mags):
                return "ERROR: error_magnitudes 含 0 (无法求模逆, 需换方法)"
            data = json.dumps({"mode": "inline", "A": A_l, "b": b_l, "mags": mags, "q": q_i})
        else:
            # 文件模式: 路径交给容器内脚本解析
            if not str(data_file).strip():
                return "ERROR: data_file 为空"
            data = json.dumps({"mode": "file", "data_file": str(data_file).strip()})

        data_b64 = base64.b64encode(data.encode()).decode()
        script_b64 = base64.b64encode(_SOLVER_SCRIPT.encode()).decode()
        # 在容器内: 写入数据文件 + 求解脚本 + 运行
        bg = (
            f"echo '{data_b64}' | base64 -d > /tmp/lwe_data.json; "
            f"echo '{script_b64}' | base64 -d > /tmp/lwe_solve.py; "
            f"python3 /tmp/lwe_solve.py"
        )
        if self.exec is None or not hasattr(self.exec, "exec_cmd"):
            return (
                "ERROR: 无执行层 (需要 docker/ssh 执行层, 容器内需安装 fpylll).\n"
                f"可用脚本 (在容器内运行): {script_b64}"
            )
        try:
            result = self.exec.exec_cmd(bg, cwd="/challenge/", timeout=180)
        except Exception as e:  # noqa: BLE001
            return f"ERROR: 容器执行失败: {e}"
        out = (result.stdout or "") + (f"\n[stderr] {result.stderr}" if getattr(result, "stderr", None) else "")
        out = out.strip()
        # 提取最后一行 JSON (求解结果)
        last_json = ""
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    json.loads(line)
                    last_json = line
                except Exception:
                    pass
        if last_json:
            try:
                parsed = json.loads(last_json)
                if parsed.get("s") is not None and parsed.get("verified"):
                    s = parsed["s"]
                    e_pred = parsed.get("e_pred", [])
                    n = parsed.get("n"); m = parsed.get("m"); q_v = parsed.get("q")
                    return (
                        f"LWE 求解成功并通过数学验证 (A·s+e ≡ b mod {q_v} 逐分量成立):\n"
                        f"维度: n={n}, m={m}, q={q_v}\n"
                        f"s = {s}\n"
                        f"e_pred = {e_pred}\n"
                        f"该 s 可直接用于 get_flag 提交 (lwe_secret_s)。"
                    )
                return f"ERROR: {parsed.get('error', 'unknown')}"
            except Exception:  # noqa: BLE001
                pass
        return ("lwe_decode 输出:\n" + out)[:_MAX_OUTPUT]


def lwe_tools(exec_client: Any = None) -> list[Tool]:
    """返回 LWE 工具集 (需要执行层, 容器内 fpylll)."""
    return [LweDecodeTool(exec_client)]


__all__ = ["LweDecodeTool", "lwe_tools"]
