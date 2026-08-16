# -*- coding: utf-8 -*-
"""回归测试: Narrow_DES 32-bit 子密钥 MITM 的核心算法 (des_mitm32.c 的 Python 参考).

用缩小密钥空间 (NB 位子密钥) 验证:
  forward_16(plaintext, k0) 的中间状态 == backward_16(ciphertext, k1) 的中间状态
  <==> des_block(plaintext, key=(k0<<32|k1)) == ciphertext

des_mitm32.c 是该算法在 NB=32 下的外部分桶落盘实现 (逻辑完全一致, 仅用磁盘代替内存).
本测试在 NB=16 下运行以秒级完成, 覆盖 forward_16 / backward_16 / meet 等价性.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctf_agent.tools.des_tool import _python_des_block  # 与服务器一致的 32 轮实现

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
MASK24 = (1 << 24) - 1


def _forward_16(msg, k0):
    L = (msg >> 24) & MASK24
    R = msg & MASK24
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
    L = (ct >> 24) & MASK24
    R = ct & MASK24
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


def _meet(m1, c1, m2, c2, k0, k1):
    L1, R1 = _forward_16(m1, k0)
    L2, R2 = _forward_16(m2, k0)
    fwd_meet = (L1 << 72) | (R1 << 48) | (L2 << 24) | R2
    L1b, R1b = _backward_16(c1, k1)
    L2b, R2b = _backward_16(c2, k1)
    bwd_meet = (L1b << 72) | (R1b << 48) | (L2b << 24) | R2b
    return fwd_meet, bwd_meet


def _mitm_nb(nb, pairs):
    m1, c1 = pairs[0]
    m2, c2 = pairs[1]
    fwd = {}
    for k0 in range(1 << nb):
        L1, R1 = _forward_16(m1, k0)
        L2, R2 = _forward_16(m2, k0)
        fwd[(L1, R1, L2, R2)] = k0
    for k1 in range(1 << nb):
        L1, R1 = _backward_16(c1, k1)
        L2, R2 = _backward_16(c2, k1)
        k0 = fwd.get((L1, R1, L2, R2))
        if k0 is not None:
            key = ((k0 & ((1 << nb) - 1)) << 32) | (k1 & ((1 << nb) - 1))
            if all(_python_des_block(m, key) == c for m, c in pairs):
                return key
    return None


NB = 16  # 缩小密钥空间, 秒级完成


def test_mitm_recovers_truncated_key():
    # 真实 key 0x8eee90623da74d62, 子密钥截断到 NB 位做算法验证
    real_k0 = 0x8EEE9062 & ((1 << NB) - 1)
    real_k1 = 0x3DA74D62 & ((1 << NB) - 1)
    test_key = ((real_k0 << 32) | real_k1) & 0xFFFFFFFFFFFFFFFF
    pairs = [(0x000000000000, _python_des_block(0x000000000000, test_key)),
             (0x0123456789AB, _python_des_block(0x0123456789AB, test_key)),
             (0xA5A5A5A5A5A5, _python_des_block(0xA5A5A5A5A5A5, test_key))]
    recovered = _mitm_nb(NB, pairs)
    assert recovered == test_key, f"MITM 失败: 期望 0x{test_key:016x}, 得到 {recovered}"


def test_meet_equivalence():
    # meet 等价性是 MITM 正确性的基石: 在正确 (k0,k1) 下 fwd==bwd
    k0, k1 = 0x1234, 0x5678
    key = (k0 << 32) | k1
    m1, m2 = 0x000000000000, 0x0123456789AB
    c1, c2 = _python_des_block(m1, key), _python_des_block(m2, key)
    fwd_meet, bwd_meet = _meet(m1, c1, m2, c2, k0, k1)
    assert fwd_meet == bwd_meet


def test_backward_is_inverse_of_forward():
    # backward_16(c, k1) 必须等于 forward_16 之后的中间状态
    k0, k1 = 0xABCD, 0x1234
    key = (k0 << 32) | k1
    m = 0x0F0F0F0F0F0F
    c = _python_des_block(m, key)
    # 中间状态 (forward 16 轮后)
    midL, midR = _forward_16(m, k0)
    # 后向 16 轮 (从密文还原输入到后半部分的状态) 应等于 midL,midR
    bl, br = _backward_16(c, k1)
    assert (bl, br) == (midL, midR)
