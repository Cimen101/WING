"""Sprint 10: 失败轨迹缓存器单元测试.

验证:
1. store() 仅在 success=False 时存储
2. fetch_recent() 返回按时间倒序的最近 N 次
3. count() 返回失败次数
4. format_hint() 在无历史时返回空字符串,有历史时返回有用提示
5. clear() 清除指定 challenge 历史
6. 多次 store 后 fetch 顺序正确

不依赖 SSH/网络,纯 Python 测试。
"""
import sys
import tempfile
from pathlib import Path

# Sprint 6: 强制 UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctf_agent.agent.failed_trajectory_cache import (  # type: ignore[import-not-found]
    FailedTrajectoryCache,
    FailedRun,
    get_default_cache,
)
from ctf_agent.agent.react import ReActStep  # type: ignore[import-not-found]


def make_fake_step(step_no: int, thought: str = "", action: str = "",
                   action_input: str = "", observation: str = "",
                   final_answer: str = "", is_final: bool = False) -> ReActStep:
    """构造伪 ReActStep 对象."""
    return ReActStep(
        step_no=step_no,
        thought=thought,
        action=action,
        action_input=action_input,
        observation=observation,
        is_final=is_final,
        final_answer=final_answer,
        timestamp=0.0,
    )


def make_fake_steps(n: int) -> list[ReActStep]:
    """构造 n 个伪步骤."""
    return [
        make_fake_step(
            i + 1,
            thought=f"thought {i+1}",
            action="ssh_exec" if i % 2 == 0 else "ssh_python",
            action_input=f"command {i+1}",
            observation=f"obs {i+1}",
        )
        for i in range(n)
    ]


def test_no_history_returns_empty():
    """测试: 无历史时 format_hint 返回空字符串."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        hint = cache.format_hint("CTF-UNSEEN")
        assert hint == "", f"Expected empty hint, got: {hint!r}"
        assert cache.count("CTF-UNSEEN") == 0
        assert cache.fetch_recent("CTF-UNSEEN") == []
    print("  ✅ test_no_history_returns_empty PASS")


def test_store_only_on_failure():
    """测试: success=True 时不存储."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        steps = make_fake_steps(5)

        # success=True 不应存储
        cache.store("CTF-A", steps=steps, final_answer="flag{a}", fail_reason="", success=True)
        assert cache.count("CTF-A") == 0, "Should not store on success"

        # success=False 应存储
        cache.store("CTF-A", steps=steps, final_answer="wrong", fail_reason="max_steps", success=False)
        assert cache.count("CTF-A") == 1, "Should store on failure"
    print("  ✅ test_store_only_on_failure PASS")


def test_multiple_stores_ordered():
    """测试: 多次 store 后 fetch_recent 按时间倒序."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)

        for i in range(3):
            steps = make_fake_steps(i + 3)  # 3, 4, 5 步
            cache.store(
                "CTF-B",
                steps=steps,
                final_answer=f"wrong_{i}",
                fail_reason=f"reason_{i}",
                success=False,
            )

        assert cache.count("CTF-B") == 3

        recent = cache.fetch_recent("CTF-B", n=3)
        assert len(recent) == 3
        # 最近的在最前 (按 ts 倒序)
        assert recent[0].final_answer == "wrong_2", f"Expected 'wrong_2', got {recent[0].final_answer}"
        assert recent[1].final_answer == "wrong_1"
        assert recent[2].final_answer == "wrong_0"
    print("  ✅ test_multiple_stores_ordered PASS")


def test_format_hint_with_history():
    """测试: 有历史时 format_hint 返回非空 + 包含关键信息."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        steps = make_fake_steps(5)
        cache.store(
            "CTF-C",
            steps=steps,
            final_answer="bad_flag",
            fail_reason="max_steps",
            success=False,
        )

        hint = cache.format_hint("CTF-C")
        assert hint != "", "Hint should not be empty"
        assert "失败记忆" in hint, f"Hint should mention 失败记忆, got: {hint!r}"
        assert "max_steps" in hint, f"Hint should include fail_reason"
        assert "bad_flag" in hint, f"Hint should include wrong answer"
        assert "ssh_exec" in hint, f"Hint should list used tools"
    print("  ✅ test_format_hint_with_history PASS")


def test_clear():
    """测试: clear() 清除指定 challenge."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        steps = make_fake_steps(3)

        cache.store("CTF-D", steps=steps, final_answer="x", fail_reason="r", success=False)
        cache.store("CTF-E", steps=steps, final_answer="y", fail_reason="r", success=False)
        assert cache.count("CTF-D") == 1
        assert cache.count("CTF-E") == 1

        cache.clear("CTF-D")
        assert cache.count("CTF-D") == 0
        assert cache.count("CTF-E") == 1
    print("  ✅ test_clear PASS")


def test_clear_all():
    """测试: clear_all() 清除所有."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        steps = make_fake_steps(2)

        for ch in ["CTF-F", "CTF-G", "CTF-H"]:
            cache.store(ch, steps=steps, final_answer="x", fail_reason="r", success=False)

        assert cache.count("CTF-F") == 1
        cache.clear_all()
        assert cache.count("CTF-F") == 0
        assert cache.count("CTF-G") == 0
        assert cache.count("CTF-H") == 0
    print("  ✅ test_clear_all PASS")


def test_truncation():
    """测试: 长 thought/observation 截断."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)

        long_thought = "X" * 1000
        long_obs = "Y" * 1000
        steps = [
            make_fake_step(1, thought=long_thought, action="a", action_input="b", observation=long_obs),
            make_fake_step(2, thought="short"),
        ]
        cache.store("CTF-I", steps=steps, final_answer="x", fail_reason="r", success=False)

        recent = cache.fetch_recent("CTF-I", n=1)
        assert len(recent) == 1
        first_step = recent[0].first_5_steps[0]
        # 截断到 200 字符
        assert len(first_step["thought"]) == 200
        assert len(first_step["observation_preview"]) == 200
        # last_step_thought 也截断到 300
        assert len(recent[0].last_step_thought) == 300 or len(recent[0].last_step_thought) < 300
    print("  ✅ test_truncation PASS")


def test_global_singleton():
    """测试: get_default_cache() 返回单例."""
    c1 = get_default_cache()
    c2 = get_default_cache()
    assert c1 is c2, "Should be the same instance"
    print("  ✅ test_global_singleton PASS")


def main() -> int:
    print("=" * 60)
    print("Sprint 10: failed_trajectory_cache 单元测试")
    print("=" * 60)
    tests = [
        test_no_history_returns_empty,
        test_store_only_on_failure,
        test_multiple_stores_ordered,
        test_format_hint_with_history,
        test_clear,
        test_clear_all,
        test_truncation,
        test_global_singleton,
    ]
    for t in tests:
        print(f"\n[{t.__name__}]")
        t()
    print(f"\n=== 所有 {len(tests)} 个测试通过 ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
