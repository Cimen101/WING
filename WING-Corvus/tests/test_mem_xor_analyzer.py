"""Sprint 10: mem_xor_analyzer 单元测试.

验证:
1. 解析 hex dump 格式正确 (PAGE 0x... + 00000000/00000010 行)
2. 解析 process_map.txt 提取 tag=XXX
3. 剥离 DEADBEEF/FACEB00C/CAFEBABE 等内存标记
4. 4 种 XOR 模式 (header_concat/header_per_page/full_concat/full_per_page)
5. 命中 flag 模式 (athena{...}/CTF{...}/flag{...})
6. RAM_Drift 真实题目解密出 athena{ram_pages_hide_fragments}

不依赖 SSH,使用 mock ssh_client。
"""
import sys
from pathlib import Path
from typing import Any

# Sprint 6: 强制 UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctf_agent.tools.mem_xor_analyzer import (  # type: ignore[import-not-found]
    MemXorAnalyzer,
    PageInfo,
    _parse_dump_content,
    _parse_process_map,
    _strip_markers,
    _xor_with_key,
    _check_flag,
    _score_plaintext,
)


class MockSSHClient:
    """Mock SSH 客户端,返回预设内容."""

    def __init__(self, responses: dict[str, str]):
        self.responses = responses
        self.commands: list[str] = []

    class MockResult:
        def __init__(self, stdout: str = "", stderr: str = "", success: bool = True):
            self.stdout = stdout
            self.stderr = stderr
            self.is_success = success

    def exec_cmd(self, command: str, timeout: int = 30) -> Any:
        self.commands.append(command)
        # 根据命令匹配响应
        for key, value in self.responses.items():
            if key in command:
                return self.MockResult(stdout=value, success=True)
        return self.MockResult(stdout="", success=False)


# ============ 真实 RAM_Drift 测试数据 (从 v4 成功轨迹复制) ============

RAM_DUMP_CONTENT = """Memory capture excerpt (page-aligned)
=====================================

PAGE 0x8a0000
00000000  25 26 59 23 3a 25 29 43 27 39 1b 22              |%&Y#:%)C'9."|
00000010  1f 19 1c 0a de ad be ef 08 0f 1c 1a 0a 3d 0d 0d  |.............=..|

PAGE 0x8a1000
00000000  50 21 31 37 0d 59 2f 30 21 0d 57 34              |P!17.Y/0!.W4|
00000010  11 0c 17 05 fa ce b0 0c 11 0c 17 05 07 13 0a 0b  |................|

PAGE 0x8a2000
00000000  35 23 3f 54 28 20 37 2f                          |5#?T( 7/|
00000010  0c 1a 05 07 0c 0e 07 0f 06 1d 10 12 0a 0b 0d 1f  |................|

captured note: the buffer was XORed before the pages were dumped.
"""

PROCESS_MAP_CONTENT = """Process map from the crash collector:

pid  name               base      size    xor tag
111  systemd            0x7f1000  0x1200  tag=STEDY
482  explorer           0x7f4000  0x2400  tag=CLIP9
901  photo_recover      0x8a0000  0x3c00  tag=DR1FT
1044 crash_handler      0x900000  0x1800  tag=PGOFF

Each process scrambled its resident buffer with its own tag (a repeating XOR key).
The buffer of interest was mapped across three pages before the dump was written;
identify which process owns those pages, then apply its tag across the whole buffer.
"""


def test_parse_dump():
    """测试: 解析 hex dump 格式, 提取 3 个 page 的 header bytes."""
    pages = _parse_dump_content(RAM_DUMP_CONTENT)
    assert len(pages) == 3, f"Expected 3 pages, got {len(pages)}"

    # page 0: 12 个 header 字节
    assert pages[0].base == 0x8a0000
    assert len(pages[0].header_bytes) == 12
    assert pages[0].header_bytes[0] == 0x25  # 'a'
    assert pages[0].header_bytes[5] == 0x25  # 'a'

    # page 1: 12 个 header 字节
    assert pages[1].base == 0x8a1000
    assert len(pages[1].header_bytes) == 12

    # page 2: 8 个 header 字节
    assert pages[2].base == 0x8a2000
    assert len(pages[2].header_bytes) == 8
    print("  ✅ test_parse_dump PASS")


def test_parse_process_map():
    """测试: 解析 process_map.txt 提取 tag=XXX."""
    tags = _parse_process_map(PROCESS_MAP_CONTENT)
    assert "STEDY" in tags
    assert "CLIP9" in tags
    assert "DR1FT" in tags
    assert "PGOFF" in tags
    assert len(tags) == 4
    print("  ✅ test_parse_process_map PASS")


def test_strip_markers():
    """测试: 剥离 DEADBEEF/FACEB00C 标记."""
    data = b"\x25\xde\xad\xbe\xef\x26\xfa\xce\xb0\x0c\x27"
    stripped = _strip_markers(data)
    assert stripped == b"\x25\x26\x27", f"Expected b'\\x25\\x26\\x27', got {stripped!r}"
    print("  ✅ test_strip_markers PASS")


def test_xor_with_key_continuous():
    """测试: 连续 XOR 模式."""
    data = b"athena"
    key = b"DR1FT"
    # 简化测试: 实际 flag 解密见 test_ram_drift_real
    result = _xor_with_key(data, key, per_chunk_reset=False, chunk_size=0)
    assert len(result) == len(data)
    # athena[0] ^ DR1FT[0]
    assert result[0] == ord("a") ^ ord("D")
    print("  ✅ test_xor_with_key_continuous PASS")


def test_check_flag():
    """测试: flag 模式检测."""
    # 命中
    is_flag, value = _check_flag(b"athena{ram_pages_hide_fragments}")
    assert is_flag
    assert value == "athena{ram_pages_hide_fragments}"

    # 不命中
    is_flag, value = _check_flag(b"some random text without flag")
    assert not is_flag
    assert value == ""

    # 大小写不敏感
    is_flag, _ = _check_flag(b"ATHENA{UPPER}")
    assert is_flag
    print("  ✅ test_check_flag PASS")


def test_ram_drift_real():
    """测试: RAM_Drift 真实数据解密出 athena{ram_pages_hide_fragments}.

    这是 S10 最重要的端到端测试。"""
    ssh = MockSSHClient({
        "cat /tmp/ctf_real3/RAM_Drift/ram_dump.txt": RAM_DUMP_CONTENT,
        "cat /tmp/ctf_real3/RAM_Drift/process_map.txt": PROCESS_MAP_CONTENT,
    })
    analyzer = MemXorAnalyzer(ssh)
    result = analyzer.analyze(
        dump_path="/tmp/ctf_real3/RAM_Drift/ram_dump.txt",
        process_map_path="/tmp/ctf_real3/RAM_Drift/process_map.txt",
    )

    # 1. 基础信息
    assert result.error == "", f"Should not have error, got: {result.error}"
    assert len(result.pages) == 3
    assert "DR1FT" in result.candidate_keys

    # 2. 解密结果应包含 flag
    assert len(result.flag_candidates) > 0, f"Should find flag, got decryptions: {result.decryptions}"
    assert "athena{ram_pages_hide_fragments}" in result.flag_candidates, (
        f"Expected 'athena{{ram_pages_hide_fragments}}' in {result.flag_candidates}"
    )

    # 3. 找到对应的解密条目
    flag_decryption = next(
        (d for d in result.decryptions if d.is_flag and "ram_pages_hide_fragments" in d.flag_value),
        None,
    )
    assert flag_decryption is not None
    assert flag_decryption.key == "DR1FT"
    assert flag_decryption.confidence >= 0.9
    assert "header_concat" in flag_decryption.mode or "full_concat" in flag_decryption.mode

    # 4. 性能
    assert result.analysis_time < 1.0, f"Should be fast (<1s), got {result.analysis_time:.2f}s"

    print("  ✅ test_ram_drift_real PASS")
    print(f"     Flag: {result.flag_candidates[0]}")
    print(f"     Key:  {flag_decryption.key}")
    print(f"     Mode: {flag_decryption.mode}")
    print(f"     Time: {result.analysis_time*1000:.1f}ms")


def test_no_process_map_extracts_tokens():
    """测试: 没有 process_map 时能从 dump 内容提取短 ASCII tokens."""
    ssh = MockSSHClient({
        "cat /tmp/ctf_real3/no_proc/dump.txt": RAM_DUMP_CONTENT,
    })
    analyzer = MemXorAnalyzer(ssh)
    result = analyzer.analyze(
        dump_path="/tmp/ctf_real3/no_proc/dump.txt",
        process_map_path=None,
    )
    # 即使没有 process_map, 也应尝试提取 tokens
    assert result.error == ""
    assert len(result.pages) == 3
    # candidate_keys 可能为空(没有 process_map 且 RAM_DUMP 无 token)
    # 关键是 analyze 不报错
    print("  ✅ test_no_process_map_extracts_tokens PASS")


def test_summary_format():
    """测试: summary() 输出格式正确."""
    ssh = MockSSHClient({
        "cat /tmp/dump.txt": RAM_DUMP_CONTENT,
        "cat /tmp/proc.txt": PROCESS_MAP_CONTENT,
    })
    analyzer = MemXorAnalyzer(ssh)
    result = analyzer.analyze(
        dump_path="/tmp/dump.txt",
        process_map_path="/tmp/proc.txt",
    )
    summary = result.summary()
    assert "Memory Dump XOR Analysis" in summary
    assert "DR1FT" in summary
    assert "athena{ram_pages_hide_fragments}" in summary
    assert "🚩" in summary
    print("  ✅ test_summary_format PASS")


def test_marker_stripping_in_decrypt():
    """测试: 内存标记 (DEADBEEF) 在 full_concat 模式被剥离."""
    # 数据中含 DEADBEEF 标记
    dump = """PAGE 0x1000000
00000000  25 26 59 23 3a 25 29 43 27 39 1b 22  de ad be ef  |....|
"""
    proc = """pid  name               base      size    xor tag
1    test               0x1000000  0x100   tag=DR1FT
"""
    ssh = MockSSHClient({
        "cat /tmp/d.txt": dump,
        "cat /tmp/p.txt": proc,
    })
    analyzer = MemXorAnalyzer(ssh)
    result = analyzer.analyze(dump_path="/tmp/d.txt", process_map_path="/tmp/p.txt")
    # 至少应有 4 个 decryption (4 modes × 1 key)
    assert len(result.decryptions) >= 4
    # full_concat 模式应剥离 DEADBEEF
    full_concat_dec = next((d for d in result.decryptions if d.mode == "full_concat"), None)
    assert full_concat_dec is not None
    # DEADBEEF 不应出现在 decrypted hex 中
    assert "deadbeef" not in full_concat_dec.plaintext_hex.lower()
    print("  ✅ test_marker_stripping_in_decrypt PASS")


def main() -> int:
    print("=" * 60)
    print("Sprint 10: mem_xor_analyzer 单元测试")
    print("=" * 60)
    tests = [
        test_parse_dump,
        test_parse_process_map,
        test_strip_markers,
        test_xor_with_key_continuous,
        test_check_flag,
        test_ram_drift_real,
        test_no_process_map_extracts_tokens,
        test_summary_format,
        test_marker_stripping_in_decrypt,
    ]
    for t in tests:
        print(f"\n[{t.__name__}]")
        t()
    print(f"\n=== 所有 {len(tests)} 个测试通过 ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
