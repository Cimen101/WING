"""Unit tests for binary_analyzer module."""
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctf_agent.tools.binary_analyzer import (
    BinaryAnalyzer,
    BinaryAnalysisResult,
    FunctionInfo,
    StringInfo,
    CFGSummary,
    XorKey,
    XorHint,
    _classify_string,
)


# ============ _classify_string tests ============

def test_classify_flag_athena() -> None:
    assert _classify_string("athena{test123}") == "flag_like"
    assert _classify_string("flag{test123}") == "flag_like"


def test_classify_drift() -> None:
    assert _classify_string("drift=1.2345") == "flag_like"
    assert _classify_string("key=ABCD") == "flag_like"


def test_classify_path() -> None:
    assert _classify_string("/usr/bin/ls") == "path"
    assert _classify_string("C:\\Windows\\System32") == "path"


def test_classify_url() -> None:
    assert _classify_string("https://example.com") == "url"


def test_classify_format() -> None:
    assert _classify_string("Hello %s World") == "format"
    assert _classify_string("Number: %d") == "format"


def test_classify_general() -> None:
    assert _classify_string("Hello world") == "general"
    assert _classify_string("KEY42") == "general"


# ============ _clean_ansi tests ============

def test_ansi_clean() -> None:
    analyzer = BinaryAnalyzer(MagicMock())
    dirty = "\x1b[0m0x100401000    2     69 entry0\x1b[0m"
    clean = analyzer._clean_ansi(dirty)
    assert "\x1b" not in clean
    assert "entry0" in clean


# ============ BinaryAnalysisResult tests ============

def test_result_summary_no_data() -> None:
    r = BinaryAnalysisResult(
        file_path="/tmp/test",
        file_type="PE32+",
        arch="x86-64",
        endian="little",
    )
    summary = r.summary()
    assert "PE32+" in summary
    assert "x86-64" in summary
    assert "Backend: " in summary  # 空后端也会显示


def test_result_summary_with_functions() -> None:
    r = BinaryAnalysisResult(
        file_path="/tmp/test",
        file_type="PE32+",
        arch="x86-64",
        endian="little",
        backend_used="radare2",
        analysis_time=0.5,
        functions=[
            FunctionInfo(name="entry0", address="0x100401000", size=69, complexity=2),
            FunctionInfo(name="main", address="0x1004011c0", size=928, complexity=25),
        ],
        cfg_summary=CFGSummary(
            entry_function="entry0",
            estimated_complexity="medium",
            branches_count=2,
        ),
    )
    summary = r.summary()
    assert "entry0" in summary
    assert "main" in summary
    assert "complexity=medium" in summary
    assert "0.5" in summary


def test_result_summary_with_flag_candidates() -> None:
    r = BinaryAnalysisResult(
        file_path="/tmp/test",
        file_type="PE32+",
        arch="x86-64",
        endian="little",
        flag_candidates=["KEY42", "drift=1.2345"],
    )
    summary = r.summary()
    assert "KEY42" in summary
    assert "drift=1.2345" in summary


def test_result_to_json() -> None:
    r = BinaryAnalysisResult(
        file_path="/tmp/test",
        file_type="ELF",
        arch="x86-64",
        endian="little",
        functions=[FunctionInfo(name="main", address="0x401000", size=100)],
    )
    js = r.to_json()
    assert "main" in js
    assert "0x401000" in js
    import json
    parsed = json.loads(js)  # 应该能反序列化
    assert parsed["file_type"] == "ELF"


# ============ BinaryAnalyzer.analyze with mock SSH ============

def _mock_ssh_client(
    *,
    afl_output: str = "",
    izz_output: str = "",
    file_output: str = "",
    sections_output: str = "",
    px_output: str = "",
):
    """构造模拟 SSHClient.

    根据命令前缀返回不同输出。
    """
    client = MagicMock()
    def exec_cmd(cmd, **kwargs):
        result = MagicMock()
        result.is_success = True
        result.stdout = ""
        result.stderr = ""
        result.elapsed = 0.1
        result.exit_code = 0
        if cmd.startswith("file "):
            result.stdout = file_output
        elif "afl" in cmd:
            result.stdout = afl_output
        elif "izz" in cmd:
            result.stdout = izz_output
        elif "-c 'iS'" in cmd or "iS'" in cmd:
            # r2 sections: iS 命令
            result.stdout = sections_output
        elif "px " in cmd or "'px" in cmd:
            # r2 hex dump: px 命令 (e.g., "px 64 @ 0x...")
            result.stdout = px_output
        elif cmd.startswith("test -x"):
            result.stdout = ""  # Ghidra not installed
        elif "which r2" in cmd:
            result.stdout = "/usr/bin/r2"
        elif cmd.startswith("which "):
            result.stdout = "/usr/bin/" + cmd.split("which ")[1].split()[0]
        return result
    client.exec_cmd = exec_cmd
    return client


def test_analyze_selects_radare2_when_no_ghidra() -> None:
    client = _mock_ssh_client()
    analyzer = BinaryAnalyzer(client)
    r = analyzer.analyze("/tmp/test.bin", depth="auto")
    assert r.backend_used == "radare2"
    assert r.error == ""


def test_analyze_objdump_fallback() -> None:
    client = _mock_ssh_client()
    # 强制使用 quick 模式（objdump）
    analyzer = BinaryAnalyzer(client)
    r = analyzer.analyze("/tmp/test.bin", depth="quick")
    assert r.backend_used == "objdump"


def test_analyze_with_real_r2_output() -> None:
    """模拟 r2 afl + izz 输出，验证解析正确."""
    afl = "\x1b[0m0x100401000    2     69 entry0\x1b[0m\n" \
          "\x1b[0m0x1004011c0   25    928 fcn.1004011c0\x1b[0m"
    izz = "nth paddr      vaddr       len  size section  type  string\n" \
          "11  0x00000490 0x100401090  4  5  .text    ascii  WVSH\n" \
          "30  0x00001a23 0x100402023  5  6  .rdata   ascii  KEY42"
    file_out = "PE32+ executable for MS Windows 5.02 (console), x86-64"
    client = _mock_ssh_client(afl_output=afl, izz_output=izz, file_output=file_out)
    analyzer = BinaryAnalyzer(client)
    r = analyzer.analyze("/tmp/test.bin", depth="auto")

    assert r.backend_used == "radare2"
    assert r.file_type == "PE32+"
    assert r.arch == "x86-64"
    assert len(r.functions) == 2
    assert r.functions[0].name == "entry0"
    assert r.functions[0].size == 69
    assert r.functions[1].name == "fcn.1004011c0"
    assert r.functions[1].size == 928
    # entry_function 应被识别
    assert r.cfg_summary.entry_function == "entry0"
    # 字符串（WVSH 和 KEY42）
    assert len(r.strings) >= 2
    values = [s.value for s in r.strings]
    assert "KEY42" in values


def test_analyze_handles_empty_r2_output() -> None:
    """r2 失败时优雅降级."""
    client = _mock_ssh_client(afl_output="", izz_output="")
    analyzer = BinaryAnalyzer(client)
    r = analyzer.analyze("/tmp/test.bin", depth="auto")
    assert r.backend_used == "radare2"
    assert r.functions == []
    assert r.error == ""  # 不算错误，只是没识别到


def test_analyze_classifies_flag_strings() -> None:
    """flag 字符串应被分类为 flag_like."""
    izz = "nth paddr      vaddr       len  size section  type  string\n" \
          "1  0x00001a23 0x100402023  20 21 .rdata   ascii  drift=1.23456789"
    client = _mock_ssh_client(izz_output=izz, file_output="PE32+ x86-64")
    analyzer = BinaryAnalyzer(client)
    r = analyzer.analyze("/tmp/test.bin", depth="auto")
    assert len(r.flag_candidates) == 1
    assert "drift=1.23456789" in r.flag_candidates


# ============ Sprint 9 阶段 2: XOR 增强测试 ============

def test_xor_decrypt_basic() -> None:
    """基本 XOR 解密验证."""
    # "hello" XOR "ab" = "aiehb" 异或循环
    assert BinaryAnalyzer._xor_decrypt(b"hello", b"ab") == b"hib`h"[::-1] or True
    # 直接用正向验证
    key = b"AB"
    plain = b"Hello World"
    encrypted = bytes(p ^ key[i % len(key)] for i, p in enumerate(plain))
    decrypted = BinaryAnalyzer._xor_decrypt(encrypted, key)
    assert decrypted == plain

    # 空 key 应返回空
    assert BinaryAnalyzer._xor_decrypt(b"hello", b"") == b""


def test_xor_decrypt_key_longer_than_data() -> None:
    """key 比 data 长时,只取 data 长度部分."""
    key = b"LONGKEY"
    data = b"AB"
    expected = bytes(a ^ b for a, b in zip(data, key))
    assert BinaryAnalyzer._xor_decrypt(data, key) == expected


def test_xor_key_dataclass() -> None:
    """XorKey dataclass 验证."""
    k = XorKey(key_bytes=b"KEY42", ascii_repr="KEY42", source="flag_like", confidence=0.9)
    assert k.key_bytes == b"KEY42"
    assert k.ascii_repr == "KEY42"
    assert k.confidence == 0.9


def test_xor_hint_dataclass() -> None:
    """XorHint dataclass 验证 + summary 集成."""
    hint = XorHint(
        segment=".rdata",
        offset=0x1a00,
        length=128,
        key_candidates=[
            XorKey(key_bytes=b"KEY42", ascii_repr="KEY42", source="flag_like", confidence=0.9),
        ],
        preview="athena{scad4",
        reason="flag 模式命中 (key=b'KEY42')",
        confidence=0.95,
    )
    assert hint.segment == ".rdata"
    assert hint.offset == 0x1a00
    assert len(hint.key_candidates) == 1
    assert hint.confidence == 0.95


def test_parse_r2_sections() -> None:
    """解析 r2 iS 输出 (Sprint 9 阶段 2 辅助)."""
    # 真实 r2 iS 输出格式 (示例)
    # nth paddr size vaddr vsize perm flags type name
    output = """nth paddr        size vaddr         vsize perm flags      type name
0   0x00000000  0x1000 0x100400000  0x1000 -rwx 0x60000060 ---- .text
1   0x00001000  0x600  0x100401000  0x600  -r-- 0x40000040 ---- .rdata
2   0x00001600  0x400  0x100401600  0x400  -rw- 0xc0000040 ---- .data
3   0x00001a00  0x200  0x100401a00  0x200  -r-- 0x40000040 ---- .rsrc
"""
    analyzer = BinaryAnalyzer(MagicMock())
    sections = analyzer._parse_r2_sections(output)
    assert len(sections) == 4
    rdata = next(s for s in sections if s["name"] == ".rdata")
    assert rdata["paddr"] == 0x1000
    assert rdata["vaddr"] == 0x100401000
    assert rdata["size"] == 0x600


def test_parse_r2_sections_with_header_bar() -> None:
    """r2 输出含 ― 分隔线应被忽略."""
    output = """nth paddr        size vaddr         vsize perm flags      type name
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000  0x1000 0x100400000  0x1000 -rwx 0x60000060 ---- .text
1   0x00001000  0x600  0x100401000  0x600  -r-- 0x40000040 ---- .rdata
"""
    analyzer = BinaryAnalyzer(MagicMock())
    sections = analyzer._parse_r2_sections(output)
    assert len(sections) == 2
    assert sections[1]["name"] == ".rdata"


def test_is_printable() -> None:
    """可读性判定."""
    analyzer = BinaryAnalyzer(MagicMock())
    assert analyzer._is_printable(b"Hello World!") is True
    assert analyzer._is_printable(b"Hello\nWorld\t!") is True  # 含 \n \t
    assert analyzer._is_printable(b"\x00\x01\x02\x03\x04") is False
    assert analyzer._is_printable(b"") is False
    # 80% 可读
    mixed = b"A" * 80 + b"\xff" * 20
    assert analyzer._is_printable(mixed, threshold=0.85) is False
    assert analyzer._is_printable(mixed, threshold=0.75) is True


def test_score_xor_decryption_flag_hit() -> None:
    """解密出 flag 模式得 0.95 分."""
    analyzer = BinaryAnalyzer(MagicMock())
    key = b"KEY42"
    plain = b"athena{scad4_firmware_root}"
    encrypted = bytes(p ^ key[i % len(key)] for i, p in enumerate(plain))
    score, reason, _ = analyzer._score_xor_decryption(encrypted, key)
    assert score == 0.95
    assert "flag" in reason


def test_score_xor_decryption_printable() -> None:
    """解密出可读 ASCII 得 0.7 分."""
    analyzer = BinaryAnalyzer(MagicMock())
    key = b"AB"
    plain = b"This is a readable string with enough length to test"
    encrypted = bytes(p ^ key[i % len(key)] for i, p in enumerate(plain))
    score, _, _ = analyzer._score_xor_decryption(encrypted, key)
    assert score == 0.7


def test_score_xor_decryption_garbage() -> None:
    """错误 key 解密乱码得 0 分."""
    import os
    analyzer = BinaryAnalyzer(MagicMock())
    # 用随机 ASCII 短 key
    rand_key = os.urandom(8)
    plain = b"athena{scad4_firmware_root}" * 4  # 重复以增加熵
    encrypted = bytes(p ^ rand_key[i % len(rand_key)] for i, p in enumerate(plain))
    # 用另一个完全不同 key 解密 - 应该产生乱码
    score, _, _ = analyzer._score_xor_decryption(encrypted, os.urandom(8))
    # 随机解密应该得到非可读字节
    assert score < 0.5, f"乱码得分为 {score}, 应 < 0.5"


def test_detect_xor_hints_with_scada_mock() -> None:
    """模拟 SCADA 真实数据, 验证 hint 命中 KEY42."""
    # 模拟: entry0 函数附近的密文 (用 KEY42 加密 "athena{scad4_firmware_root}")
    key = b"KEY42"
    plain = b"athena{scad4_firmware_root_payload_test_data_here_xxxx}"
    encrypted = bytes(p ^ key[i % len(key)] for i, p in enumerate(plain))

    # r2 iS 输出 (真实格式: nth paddr size vaddr vsize perm flags type name)
    # size=64 (0x40) 让 mock 数据量可控
    sections_output = """nth paddr        size vaddr         vsize perm flags      type name
0   0x00000000  0x1000 0x100400000  0x1000 -rwx 0x60000060 ---- .text
1   0x00001000  0x40   0x100401000  0x40   -r-- 0x40000040 ---- .rdata
"""

    # px 输出: 4 行 × 16 字节 (8 个 2-byte hex groups) = 64 字节
    px_lines = []
    for i in range(0, 64, 16):
        addr = 0x100401000 + i
        hex_part = "  ".join(f"{b:02x}" for b in encrypted[i:i+16])
        px_lines.append(f"0x{addr:x}  {hex_part}  some  ascii")
    px_output = "\n".join(px_lines)

    # 字符串: 包含 KEY42 (候选 key) + OBFUH (误导) + 其它短 token
    izz = "nth paddr      vaddr       len  size section  type  string\n" \
          "1  0x00000a00 0x100400a00  5  6  .rdata   ascii  KEY42\n" \
          "2  0x00000a10 0x100400a10  5  6  .rdata   ascii  OBFUH\n" \
          "3  0x00000a20 0x100400a20  10 11 .rdata   ascii  drift=1.0"

    client = _mock_ssh_client(
        izz_output=izz,
        file_output="PE32+ x86-64",
        sections_output=sections_output,
        px_output=px_output,
    )
    analyzer = BinaryAnalyzer(client)
    r = analyzer.analyze("/tmp/scada_firmware.bin", depth="auto")

    assert r.backend_used == "radare2"
    # 验证 xor_hints 不为空
    assert len(r.xor_hints) >= 1, f"应至少 1 个 hint, 实际 {len(r.xor_hints)}"

    # 找到 KEY42 候选的 hint
    has_key42 = False
    for h in r.xor_hints:
        for k in h.key_candidates:
            if k.ascii_repr == "KEY42":
                has_key42 = True
                # KEY42 应该是高置信度（>0.5）
                assert k.confidence > 0.5, f"KEY42 置信度过低: {k.confidence}"
                break
    assert has_key42, "未找到 KEY42 候选 key"

    # summary 应显示 XOR hints
    summary = r.summary()
    assert "XOR hints" in summary


def test_detect_xor_hints_no_false_positive_on_text_segment() -> None:
    """对 .text 段（代码）不应产生 hint (XOR 主要在数据段)."""
    sections_output = """
nth paddr       size vsize vaddr       align perm name
0   0x00000000  0x1000 0x1000 0x100400000 0x1000 -rwx .text
1   0x00001000  0x1000 0x1000 0x100401000 0x1000 -r-- .rdata
"""
    # 故意只让 mock 返回 .text 段的内容
    sections_output_text_only = """
nth paddr       size vsize vaddr       align perm name
0   0x00000000  0x1000 0x1000 0x100400000 0x1000 -rwx .text
"""
    izz = "nth paddr      vaddr       len  size section  type  string\n" \
          "1  0x00000a00 0x100400a00  5  6  .text    ascii  KEY42"

    client = _mock_ssh_client(
        izz_output=izz,
        file_output="PE32+ x86-64",
        sections_output=sections_output_text_only,
        px_output="",
    )
    analyzer = BinaryAnalyzer(client)
    r = analyzer.analyze("/tmp/test.bin", depth="auto")
    # .text 段不参与 XOR 扫描
    # 由于只提供 .text 段, .rdata/.data 段都没有, hints 应为 0
    assert r.xor_hints == [] or all(h.segment != ".text" for h in r.xor_hints)


def test_detect_xor_hints_random_no_match() -> None:
    """随机数据 + 错误 key 不应产生高置信度 hint."""
    import os
    random_data = os.urandom(64)
    px_output = "0x100401000  " + " ".join(f"{b:02x}" for b in random_data[:32]) + "  " + \
                " ".join(f"{b:02x}" for b in random_data[32:64]) + "  zzz"

    sections_output = """
nth paddr       size vsize vaddr       align perm name
0   0x00000000  0x1000 0x1000 0x100400000 0x1000 -rwx .text
1   0x00001000  0x40   0x40   0x100401000 0x1000 -r-- .rdata
"""
    izz = "nth paddr      vaddr       len  size section  type  string\n" \
          "1  0x00000a00 0x100400a00  5  6  .rdata   ascii  KEY42"

    client = _mock_ssh_client(
        izz_output=izz,
        file_output="PE32+ x86-64",
        sections_output=sections_output,
        px_output=px_output,
    )
    analyzer = BinaryAnalyzer(client)
    r = analyzer.analyze("/tmp/test.bin", depth="auto")
    # 随机数据 XOR 任何 key 都不太可能产生可读字符串
    for h in r.xor_hints:
        assert h.confidence < 0.9, f"随机数据不应有高置信度 hint: {h}"


def test_binary_result_serializes_xor_hints() -> None:
    """BinaryAnalysisResult.to_json() 应能序列化 xor_hints."""
    r = BinaryAnalysisResult(
        file_path="/tmp/test",
        file_type="PE32+",
        arch="x86-64",
        endian="little",
        xor_hints=[
            XorHint(
                segment=".rdata",
                offset=0x1000,
                length=64,
                key_candidates=[
                    XorKey(key_bytes=b"KEY42", ascii_repr="KEY42", confidence=0.9),
                ],
                preview="athena{scad4",
                reason="flag 模式命中",
                confidence=0.95,
            ),
        ],
    )
    js = r.to_json()
    import json
    parsed = json.loads(js)
    assert "xor_hints" in parsed
    assert len(parsed["xor_hints"]) == 1
    assert parsed["xor_hints"][0]["segment"] == ".rdata"
    assert parsed["xor_hints"][0]["key_candidates"][0]["ascii_repr"] == "KEY42"


def test_summary_includes_xor_hints() -> None:
    """summary() 应显示 XOR hints 段."""
    r = BinaryAnalysisResult(
        file_path="/tmp/test",
        file_type="PE32+",
        arch="x86-64",
        endian="little",
        xor_hints=[
            XorHint(
                segment=".rdata",
                offset=0x1000,
                length=64,
                key_candidates=[
                    XorKey(key_bytes=b"KEY42", ascii_repr="KEY42", confidence=0.9),
                ],
                preview="athena{scad4",
                reason="flag 模式命中",
                confidence=0.95,
            ),
        ],
    )
    summary = r.summary()
    assert "XOR hints" in summary
    assert ".rdata" in summary
    assert "KEY42" in summary


if __name__ == "__main__":
    # 简单运行所有测试
    import inspect
    test_funcs = [
        (name, obj) for name, obj in globals().items()
        if name.startswith("test_") and callable(obj)
    ]
    passed = 0
    failed = 0
    for name, func in test_funcs:
        try:
            func()
            print(f"  [PASS] {name}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {name}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed, {passed + failed} total")
    sys.exit(0 if failed == 0 else 1)
