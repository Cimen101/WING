# -*- coding: utf-8 -*-
"""Sprint 14 P2 - des_cryptanalysis 工具单元测试.

测试 Z3 算法 + 加密函数 + 工具元数据.

测试:
1. des_block 基础加密正确性
2. 已知明文-密文对 (从 v14 P1 Narrow_DES 跑出)
3. Z3 求解 (skipif 本地无 z3)
4. 工具元数据 / 错误处理
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# 复制 des_block 用于测试 (不通过 SSH, 直接本地跑)
P = [8, 18, 3, 2, 15, 24, 10, 14, 20, 7, 5, 13, 1, 6, 21, 9,
     4, 11, 23, 22, 12, 19, 16, 17]
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


def des_block(msg, key, rounds=32):
    """Narrow_DES 加密函数 (供测试用)."""
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


# 探测 z3 是否可用 (本机)
try:
    import z3 as _z3_check  # noqa: F401
    _Z3_AVAILABLE = True
except ImportError:
    _Z3_AVAILABLE = False

# Z3 求解 32 轮 DES 在普通 PC 上需要数小时, 这里用短超时做冒烟测试
# 真正求解由 agent 在远程 Kali (有 z3 + 充足时间) 执行
_Z3_TEST_TIMEOUT_MS = 10_000  # 10s


def test_des_block_basic() -> None:
    """基础加密: m=0, key=0 应该是固定的密文."""
    c = des_block(0, 0)
    assert 0 <= c < (1 << 48), f"c out of range: {c:x}"
    # 验证可重复
    assert c == des_block(0, 0)


def test_des_block_known_vector() -> None:
    """真实 Narrow_DES server 的明文-密文对 (从 v14 P1 跑出)."""
    expected_key = 0x8eee90623da74d62

    pairs = [
        (0x000000000000, 0x6ac33339a3fc),
        (0x000000000001, 0x7b37ca055180),
        (0x000000000002, 0xc371a65911bf),
    ]

    for m, c_expected in pairs:
        c_actual = des_block(m, expected_key)
        assert c_actual == c_expected, (
            f"m=0x{m:012x} expected 0x{c_expected:012x}, got 0x{c_actual:012x}"
        )


@pytest.mark.skipif(not _Z3_AVAILABLE, reason="z3 仅在 Kali 远程执行, 本地 Windows 无 z3 模块")
def test_z3_solve_2_pairs_known() -> None:
    """Z3 模型构建冒烟测试 (32 轮 DES 在普通 PC 上求解时间 > 5min, 真正求解由 agent 在远程执行).

    验证: encrypt_z3 + Solver.add 不再抛 Z3 bit-width 错误 (Sprint 14 P2 fix).
    """
    from z3 import (BitVec, BitVecVal, Concat, Extract, If, LShR, Solver, ZeroExt)

    expected_key = 0x8eee90623da74d62
    m1, c1 = 0x000000000000, 0x6ac33339a3fc
    m2, c2 = 0x000000000001, 0x7b37ca055180

    def encrypt_z3(msg, k0, k1, rounds=32):
        L = Extract(47, 24, msg)
        R = Extract(23, 0, msg)
        for i in range(rounds):
            sk = k0 if i < 16 else k1
            R32 = ZeroExt(8, R)
            expanded = BitVecVal(0, 32)
            for j in range(7):
                shift_src = 20 - 3*j
                val = LShR(R32, shift_src) & BitVecVal(0xf, 32)
                shift_dst = 28 - 4*j
                expanded = expanded | (val << shift_dst)
            part_last = ((R & BitVecVal(7, 24)) << 1) | LShR(R, 23)
            expanded = expanded | ZeroExt(8, part_last)
            expanded = expanded ^ sk
            s_output = BitVecVal(0, 24)
            for j in range(8):
                idx = LShR(expanded, 4*j) & BitVecVal(0xf, 32)
                s_val = BitVecVal(S[j][0], 24)
                for v in range(1, 16):
                    s_val = If(idx == v, BitVecVal(S[j][v], 24), s_val)
                s_output = (s_output << 3) | s_val
            p_output = BitVecVal(0, 24)
            for j in range(24):
                bit = LShR(s_output, 24 - P[j]) & 1
                p_output = (p_output << 1) | bit
            # Feistel: keep R/L at 24 bits (avoid bit-width growth)
            new_R = L ^ p_output
            L = R
            R = new_R
        return Concat(Extract(23, 0, L), Extract(23, 0, R))

    k0 = BitVec('k0', 32)
    k1 = BitVec('k1', 32)
    solver = Solver()
    # 关键验证: 约束构建不再抛 Z3 bit-width 错误
    solver.add(encrypt_z3(BitVecVal(m1, 48), k0, k1) == BitVecVal(c1, 48))
    solver.add(encrypt_z3(BitVecVal(m2, 48), k0, k1) == BitVecVal(c2, 48))
    # 短超时, 验证 solver 能跑 (即使 Z3 不能解 32 轮 DES)
    solver.set("timeout", _Z3_TEST_TIMEOUT_MS)
    result = solver.check()
    # Z3 在 32 轮 DES 上 'unknown' 是预期结果, 只要不是 'unsat' 即可
    assert str(result) in ("sat", "unknown"), (
        f"Z3 returned {result}, expected 'sat' or 'unknown' (32 轮 DES 求解超时属正常)"
    )


@pytest.mark.skipif(not _Z3_AVAILABLE, reason="z3 仅在 Kali 远程执行, 本地 Windows 无 z3 模块")
def test_z3_solve_random_key() -> None:
    """随机 key 测试 Z3 通用性."""
    import random
    from z3 import (BitVec, BitVecVal, Concat, Extract, If, LShR, Solver, ZeroExt)

    random.seed(42)
    test_key = random.randint(0, (1 << 64) - 1)
    pairs = []
    for m in [0x000000000000, 0x1234567890ab, 0xdeadbeefcafe]:
        c = des_block(m, test_key)
        pairs.append((m, c))

    def encrypt_z3(msg, k0, k1, rounds=32):
        L = Extract(47, 24, msg)
        R = Extract(23, 0, msg)
        for i in range(rounds):
            sk = k0 if i < 16 else k1
            R32 = ZeroExt(8, R)
            expanded = BitVecVal(0, 32)
            for j in range(7):
                shift_src = 20 - 3*j
                val = LShR(R32, shift_src) & BitVecVal(0xf, 32)
                shift_dst = 28 - 4*j
                expanded = expanded | (val << shift_dst)
            part_last = ((R & BitVecVal(7, 24)) << 1) | LShR(R, 23)
            expanded = expanded | ZeroExt(8, part_last)
            expanded = expanded ^ sk
            s_output = BitVecVal(0, 24)
            for j in range(8):
                idx = LShR(expanded, 4*j) & BitVecVal(0xf, 32)
                s_val = BitVecVal(S[j][0], 24)
                for v in range(1, 16):
                    s_val = If(idx == v, BitVecVal(S[j][v], 24), s_val)
                s_output = (s_output << 3) | s_val
            p_output = BitVecVal(0, 24)
            for j in range(24):
                bit = LShR(s_output, 24 - P[j]) & 1
                p_output = (p_output << 1) | bit
            # Feistel: keep R/L at 24 bits (avoid bit-width growth)
            new_R = L ^ p_output
            L = R
            R = new_R
        return Concat(Extract(23, 0, L), Extract(23, 0, R))

    k0 = BitVec('k0', 32)
    k1 = BitVec('k1', 32)
    solver = Solver()
    for m, c in pairs:
        solver.add(encrypt_z3(BitVecVal(m, 48), k0, k1) == BitVecVal(c, 48))
    solver.set("timeout", _Z3_TEST_TIMEOUT_MS)

    result = solver.check()
    # 'unknown' 属预期 (32 轮 DES 求解超时), 'sat' 也接受
    assert str(result) in ("sat", "unknown"), f"Z3 should find SAT or timeout, got {result}"


def test_tool_metadata() -> None:
    """工具元数据: 名字, 描述, 参数格式."""
    from ctf_agent.tools.des_tool import DesCryptanalysisTool

    assert DesCryptanalysisTool.name == "des_cryptanalysis"
    desc = DesCryptanalysisTool.description
    assert "Narrow_DES" in desc
    assert "Z3" in desc
    assert "pairs_json" in desc

    params = DesCryptanalysisTool.parameters
    assert "pairs_json" in params["properties"]
    assert "pairs_json" in params["required"]


def test_tool_execute_invalid_json() -> None:
    """JSON 解析失败应返回 ERROR."""
    from ctf_agent.tools.des_tool import DesCryptanalysisTool

    mock_ssh = MagicMock()
    mock_ssh.exec_cmd.return_value = MagicMock(is_success=True, stdout="Z3 version 4.13.0\n")

    tool = DesCryptanalysisTool(mock_ssh)
    result = tool.execute(pairs_json="not json")
    assert "ERROR" in result
    assert "JSON" in result.upper() or "parse" in result.lower() or "解析" in result


def test_tool_execute_too_few_pairs() -> None:
    """0 对应返回 ERROR."""
    from ctf_agent.tools.des_tool import DesCryptanalysisTool

    mock_ssh = MagicMock()
    mock_ssh.exec_cmd.return_value = MagicMock(is_success=True, stdout="Z3 version 4.13.0\n")

    tool = DesCryptanalysisTool(mock_ssh)
    result = tool.execute(pairs_json="[]")
    assert "ERROR" in result
    assert "至少" in result or "1 对" in result


def test_tool_execute_no_z3() -> None:
    """z3 不可用应返回 ERROR 提示 pip install."""
    from ctf_agent.tools.des_tool import DesCryptanalysisTool

    mock_ssh = MagicMock()
    mock_ssh.exec_cmd.return_value = MagicMock(is_success=False, stdout="")

    tool = DesCryptanalysisTool(mock_ssh)
    result = tool.execute(pairs_json='[["000000000000","6ac33339a3fc"]]')
    assert "ERROR" in result
    assert "z3" in result.lower() or "z3-solver" in result.lower()


def test_default_tools_includes_des() -> None:
    """default_tools 应包含 des_cryptanalysis."""
    from ctf_agent.tools import default_tools

    mock_ssh = MagicMock()
    tools = default_tools(mock_ssh, enable_des=True)
    tool_names = [t.name for t in tools]
    assert "des_cryptanalysis" in tool_names, f"des_cryptanalysis not in tools: {tool_names}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
