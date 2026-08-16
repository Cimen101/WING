# -*- coding: utf-8 -*-
"""Sprint 14 P2 - feistel_decrypt 工具单元测试.

测试目标:
1. Feistel 加密/解密 round-trip 正确性
2. F-function 正确性
3. Round key 调度正确性
4. Meet-in-the-Middle 攻击正确性
5. 工具元数据 + 错误处理
6. default_tools 集成 (32 → 33 工具)
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ============ 基础算法测试 ============

def test_f_function_basic() -> None:
    """F-function: x = R XOR (rk << 16) ; x = x + (x >> 3) ; x = x XOR (x << 7)"""
    from ctf_agent.tools.feistel_tool import _f_function

    # R=0, rk=0: x = 0 ^ 0 = 0; x = 0 + 0 = 0; x = 0 ^ 0 = 0
    assert _f_function(0, 0) == 0

    # R=0, rk=1: x = 0 ^ (1 << 16) = 0x10000
    # x = 0x10000 + (0x10000 >> 3) = 0x10000 + 0x2000 = 0x12000
    # x = 0x12000 ^ (0x12000 << 7) = 0x12000 ^ 0x900000 = 0x912000
    result = _f_function(0, 1)
    assert result == 0x912000, f"F(0,1) = 0x{result:x}, expected 0x912000"


def test_round_keys_extraction() -> None:
    """Round key 调度: rk[i] = (master_key >> (6 * i)) & 0x3F"""
    from ctf_agent.tools.feistel_tool import _round_keys

    # 0xabcdef012345 实际 rk 值 (经 Python 计算)
    rks = _round_keys(0xabcdef012345)
    assert rks[0] == 0x5
    assert rks[1] == 0xd
    assert rks[2] == 0x12
    assert rks[3] == 0x0
    assert rks[4] == 0x2f
    assert rks[5] == 0x37
    assert rks[6] == 0x3c
    assert rks[7] == 0x2a


def test_encrypt_decrypt_roundtrip() -> None:
    """Round-trip: encrypt then decrypt returns original."""
    from ctf_agent.tools.feistel_tool import _encrypt_block, _decrypt_block

    test_key = 0xabcdef012345
    plain = int.from_bytes(b"athena{\x00", "big")
    cipher = _encrypt_block(plain, test_key)
    assert cipher != plain
    plain2 = _decrypt_block(cipher, test_key)
    assert plain2 == plain, f"Round-trip failed: 0x{plain:016x} != 0x{plain2:016x}"


def test_encrypt_decrypt_various_keys() -> None:
    """多种 key 都能 round-trip 成功."""
    from ctf_agent.tools.feistel_tool import _encrypt_block, _decrypt_block

    plain = int.from_bytes(b"hello123", "big")
    for key in [0, 1, 0x123456, 0xabcdef012345, 0xffffffffffff, 0x281474976710655]:
        cipher = _encrypt_block(plain, key)
        plain2 = _decrypt_block(cipher, key)
        assert plain2 == plain, f"Key 0x{key:012x} round-trip failed"


# ============ MITM 攻击测试 ============

def test_mitm_finds_known_key() -> None:
    """MITM 攻击: 给定 (plain, cipher) 对, 应能找到 master_key."""
    from ctf_agent.tools.feistel_tool import _encrypt_block, _mitm_attack

    test_key = 0xabcdef012345
    plain = int.from_bytes(b"athena{\x00", "big")
    cipher = _encrypt_block(plain, test_key)
    candidates = _mitm_attack(plain, cipher)
    assert test_key in candidates, (
        f"Key 0x{test_key:012x} not found in {len(candidates)} candidates: "
        f"{[hex(c) for c in candidates[:5]]}"
    )


def test_mitm_with_2_block_verification() -> None:
    """MITM 攻击 + 第二个 block 验证: 应能唯一确定 key."""
    from ctf_agent.tools.feistel_tool import _encrypt_block, _decrypt_block, _mitm_attack

    test_key = 0xabcdef012345
    plain1 = int.from_bytes(b"athena{\x00", "big")
    plain2 = int.from_bytes(b"123456\x00\x00", "big")
    cipher1 = _encrypt_block(plain1, test_key)
    cipher2 = _encrypt_block(plain2, test_key)

    candidates = _mitm_attack(plain1, cipher1)
    valid = [k for k in candidates if _decrypt_block(cipher2, k) == plain2]
    assert test_key in valid, (
        f"Key 0x{test_key:012x} not in {len(valid)} valid keys: "
        f"{[hex(k) for k in valid[:5]]}"
    )


# ============ 工具元数据测试 ============

def test_feistel_decrypt_tool_name() -> None:
    """工具名: feistel_decrypt."""
    from ctf_agent.tools.feistel_tool import FeistelDecryptTool

    assert FeistelDecryptTool.name == "feistel_decrypt"


def test_feistel_decrypt_description_contains_keywords() -> None:
    """工具描述含关键信息: Feistel / MITM / Crypto_Reverse."""
    from ctf_agent.tools.feistel_tool import FeistelDecryptTool

    desc = FeistelDecryptTool.description
    assert "Feistel" in desc
    assert "MITM" in desc or "Meet-in-the-Middle" in desc
    assert "Crypto_Reverse" in desc


def test_feistel_decrypt_parameters_schema() -> None:
    """工具参数: encrypted_hex (必需), known_prefix, max_seconds (可选)."""
    from ctf_agent.tools.feistel_tool import FeistelDecryptTool

    params = FeistelDecryptTool.parameters
    assert params["type"] == "object"
    props = params["properties"]
    assert "encrypted_hex" in props
    assert "known_prefix" in props
    assert "max_seconds" in props
    assert "encrypted_hex" in params["required"]


# ============ 工具执行测试 ============

def test_feistel_decrypt_invalid_hex() -> None:
    """encrypted_hex 解析失败应返回 ERROR."""
    from ctf_agent.tools.feistel_tool import FeistelDecryptTool

    mock_ssh = MagicMock()
    tool = FeistelDecryptTool(mock_ssh)
    result = tool.execute(encrypted_hex="not_hex!!!")
    assert "ERROR" in result
    assert "解析失败" in result or "encrypted_hex" in result


def test_feistel_decrypt_too_short() -> None:
    """密文太短 (< 8 bytes) 应返回 ERROR."""
    from ctf_agent.tools.feistel_tool import FeistelDecryptTool

    mock_ssh = MagicMock()
    tool = FeistelDecryptTool(mock_ssh)
    result = tool.execute(encrypted_hex="abcd")
    assert "ERROR" in result
    assert "8 字节" in result or "16 hex" in result


def test_feistel_decrypt_known_prefix_too_long() -> None:
    """known_prefix > 8 字节应返回 ERROR."""
    from ctf_agent.tools.feistel_tool import FeistelDecryptTool

    mock_ssh = MagicMock()
    tool = FeistelDecryptTool(mock_ssh)
    result = tool.execute(encrypted_hex="00" * 16, known_prefix="athena{1234567890}")
    assert "ERROR" in result
    assert "8 字节" in result or "known_prefix" in result


# ============ 工厂函数测试 ============

def test_feistel_tools_factory_returns_one_tool() -> None:
    """Factory 函数返回 1 个工具."""
    from ctf_agent.tools.feistel_tool import feistel_tools

    mock_ssh = MagicMock()
    tools = feistel_tools(mock_ssh)
    assert len(tools) == 1
    assert tools[0].name == "feistel_decrypt"


# ============ default_tools 集成测试 ============

def test_default_tools_includes_feistel() -> None:
    """default_tools 应包含 feistel_decrypt."""
    from ctf_agent.tools import default_tools

    mock_ssh = MagicMock()
    tools = default_tools(mock_ssh, enable_feistel=True)
    tool_names = [t.name for t in tools]
    assert "feistel_decrypt" in tool_names, f"feistel_decrypt not in tools: {tool_names}"


def test_default_tools_with_ssh_client_has_33_tools() -> None:
    """Sprint 14 P2: 31 → 33 (新增 des_cryptanalysis + feistel_decrypt).

    13 内置 + 1 HTTP + 3 SSH + 1 binary_analyzer + 1 mem_xor_analyzer + 4 OSINT +
    2 APK + 1 sage + 2 reverse_image + 1 ocr + 1 ecdsa + 1 angr + 1 des + 1 feistel = 33
    """
    from ctf_agent.tools import default_tools

    mock_ssh = MagicMock()
    tools = default_tools(mock_ssh)
    assert len(tools) == 33, f"Expected 33 tools, got {len(tools)}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
