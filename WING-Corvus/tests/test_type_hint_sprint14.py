"""Sprint 14 P1: TYPE_DIFFICULTY_HINTS 增强测试.

验证:
1. reverse easy hint 显式禁止 angr
2. reverse medium hint 限制 angr 使用次数
3. reverse hard hint 明确 angr workflow
4. osint medium hint 严格 4 步上限 + 禁止 strings/binwalk/steghide
5. 所有 8 个 (type, difficulty) 组合都有 hint
"""
import sys
import tempfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctf_agent.agent.failed_trajectory_cache import (  # type: ignore[import-not-found]
    TYPE_DIFFICULTY_HINTS,
    FailedTrajectoryCache,
)


# ============ 1. reverse easy hint 显式禁止 angr ============

def test_reverse_easy_hint_forbids_angr() -> None:
    """reverse easy hint 必须显式禁止 angr_symbolic_exec."""
    hint = TYPE_DIFFICULTY_HINTS[("reverse", "easy")]
    assert "angr_symbolic_exec" in hint
    assert "绝对不要" in hint or "禁止" in hint or "⛔" in hint


def test_reverse_easy_hint_suggests_basic_tools() -> None:
    """reverse easy hint 必须包含 strings + binary_analyze + ssh_python."""
    hint = TYPE_DIFFICULTY_HINTS[("reverse", "easy")]
    assert "strings" in hint
    assert "binary_analyze" in hint
    assert "ssh_python" in hint


# ============ 2. reverse medium hint 限制 angr ============

def test_reverse_medium_hint_warns_angr_limit() -> None:
    """reverse medium hint 必须警告 angr 限制 (1 次为限)."""
    hint = TYPE_DIFFICULTY_HINTS[("reverse", "medium")]
    assert "angr_symbolic_exec" in hint
    assert "1 次为限" in hint or "1-2 次" in hint


# ============ 3. reverse hard hint angr workflow ============

def test_reverse_hard_hint_angr_workflow() -> None:
    """reverse hard hint 必须明确 angr 触发条件 (binary_analyze 失败后, 1 次为限)."""
    hint = TYPE_DIFFICULTY_HINTS[("reverse", "hard")]
    assert "angr_symbolic_exec" in hint
    assert "binary_analyze" in hint
    assert "timeout" in hint or "5 分钟" in hint or "300" in hint


# ============ 4. osint medium hint 严格 4 步上限 ============

def test_osint_medium_hint_4_step_limit() -> None:
    """osint medium hint 必须有 4 步上限说明."""
    hint = TYPE_DIFFICULTY_HINTS[("osint", "medium")]
    assert "≤" in hint or "<=" in hint or "4 步" in hint or "5 步" in hint


def test_osint_medium_hint_forbids_exploration_tools() -> None:
    """osint medium hint 必须禁止 strings/file/hex_dump/binwalk/steghide/identify."""
    hint = TYPE_DIFFICULTY_HINTS[("osint", "medium")]
    for forbidden in ["strings", "binwalk", "steghide", "identify", "hex_dump"]:
        assert forbidden in hint, f"hint 应该提到 {forbidden} (用于禁止)"


def test_osint_medium_hint_strong_emoji() -> None:
    """osint medium hint 用 ⛔ 强标记禁止行为."""
    hint = TYPE_DIFFICULTY_HINTS[("osint", "medium")]
    assert "⛔" in hint


# ============ 5. 所有 8 个组合都有 hint ============

def test_all_type_difficulty_combinations_have_hints() -> None:
    """验证 8 个 (type, difficulty) 组合都有非空 hint."""
    expected = [
        ("forensics", "medium"),
        ("forensics", "hard"),
        ("reverse", "easy"),
        ("reverse", "medium"),
        ("reverse", "hard"),
        ("crypto", "medium"),
        ("crypto", "hard"),
        ("web", "medium"),
        ("osint", "easy"),
        ("osint", "medium"),
        ("osint", "hard"),
    ]
    for k in expected:
        assert k in TYPE_DIFFICULTY_HINTS, f"缺少 {k} 的 hint"
        assert len(TYPE_DIFFICULTY_HINTS[k]) > 30, f"{k} 的 hint 太短"


# ============ 6. format_type_hint 接受 challenge_type/difficulty ============

def test_format_type_hint_reverse_easy() -> None:
    """format_type_hint('reverse', 'easy') 返回 reverse easy hint."""
    cache = FailedTrajectoryCache(cache_dir=Path(tempfile.mkdtemp()))
    hint = cache.format_type_hint("reverse", "easy")
    assert "angr" in hint
    assert "⛔" in hint


def test_format_type_hint_osint_medium() -> None:
    """format_type_hint('osint', 'medium') 返回 osint medium hint (5 步上限)."""
    cache = FailedTrajectoryCache(cache_dir=Path(tempfile.mkdtemp()))
    hint = cache.format_type_hint("osint", "medium")
    assert "exiftool" in hint
    assert "strings" in hint  # 在禁止列表中


def test_format_type_hint_returns_empty_for_unknown() -> None:
    """format_type_hint(unknown type) 返回空字符串."""
    cache = FailedTrajectoryCache(cache_dir=Path(tempfile.mkdtemp()))
    hint = cache.format_type_hint("unknown_type", "medium")
    assert hint == "" or "未知" in hint
