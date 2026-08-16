"""Sprint 10 Stage 10: 演化器 (Reflector) 单元测试.

验证:
1. _classify_failure_mode() 正确分类各种失败模式
2. _suggest_tools() 按失败模式优先级推荐工具
3. _build_improvement_hint() 生成有意义提示
4. reflect() 端到端: store → reflect → format_reflection_hint
5. Reflection 数据结构序列化/反序列化
6. reflect() 持久化到 reflections/ 目录
7. clear() 同时清理 failures + reflections
8. ReActEngine 失败时自动触发 reflect()
9. _inject_context() 包含 reflection hint
10. _normalize_tool_name() 正确归一化工具名

不依赖 SSH/网络, 纯 Python 测试。
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
    FAILURE_MODE_FORMAT_ERROR,
    FAILURE_MODE_LOOP_TOOL,
    FAILURE_MODE_MAX_STEPS,
    FAILURE_MODE_NULL_OBSERVATION,
    FAILURE_MODE_REPEAT_ACTION,
    FAILURE_MODE_TOKEN_WASTE,
    FAILURE_MODE_UNKNOWN,
    FAILURE_MODE_WRONG_APPROACH,
    FailedRun,
    FailedTrajectoryCache,
    Reflection,
    TOOL_CATEGORY_MAP,
    _normalize_tool_name,
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


def make_fake_steps(n: int, *, action: str = "ssh_exec",
                    action_input: str = "command",
                    thought: str = "thinking") -> list[ReActStep]:
    """构造 n 个伪步骤 (默认循环同工具)."""
    return [
        make_fake_step(
            i + 1,
            thought=thought,
            action=action,
            action_input=action_input,
            observation="",
        )
        for i in range(n)
    ]


# ==================== 测试 1: _normalize_tool_name 归一化 ====================

def test_normalize_tool_name_aliases():
    """测试: 别名归一化 (python→ssh_python, yandex→web_search 等)."""
    assert _normalize_tool_name("python") == "ssh_python"
    assert _normalize_tool_name("py") == "ssh_python"
    assert _normalize_tool_name("yandex") == "web_search"
    assert _normalize_tool_name("google") == "web_search"
    assert _normalize_tool_name("cat") == "file_read"
    assert _normalize_tool_name("photon") == "osm_geocode"
    assert _normalize_tool_name("exif") == "exiftool"
    assert _normalize_tool_name("tesseract") == "ocr"
    # 大小写不敏感
    assert _normalize_tool_name("PYTHON") == "ssh_python"
    # 已标准名保持
    assert _normalize_tool_name("ssh_python") == "ssh_python"
    assert _normalize_tool_name("binary_analyze") == "binary_analyze"
    # 空字符串
    assert _normalize_tool_name("") == ""
    print("  PASS test_normalize_tool_name_aliases")


# ==================== 测试 2: TOOL_CATEGORY_MAP 完整性 ====================

def test_tool_category_map_completeness():
    """测试: TOOL_CATEGORY_MAP 覆盖主要题目类型."""
    expected_types = {"forensics", "reverse", "crypto", "osint", "web", "misc"}
    actual_types = set(TOOL_CATEGORY_MAP.keys())
    assert expected_types.issubset(actual_types), (
        f"Missing types: {expected_types - actual_types}"
    )
    # 每个类型至少有 3 个工具
    for t, tools in TOOL_CATEGORY_MAP.items():
        assert len(tools) >= 3, f"Type {t} has only {len(tools)} tools: {tools}"
    # 关键工具存在
    assert "mem_xor_analyze" in TOOL_CATEGORY_MAP["forensics"]
    assert "binary_analyze" in TOOL_CATEGORY_MAP["reverse"]
    assert "common_d_attack" in TOOL_CATEGORY_MAP["crypto"]
    assert "ocr" in TOOL_CATEGORY_MAP["osint"]
    print("  PASS test_tool_category_map_completeness")


# ==================== 测试 3: _classify_failure_mode 各模式 ====================

def test_classify_format_error():
    """测试: 格式错误被正确识别."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        run = FailedRun(
            ts=0.0,
            challenge_id="X",
            steps=3,
            final_answer="",
            fail_reason="连续 3 次格式解析失败",
            first_5_steps=[],
            last_step_thought="",
            used_tools=["ssh_exec"],
        )
        mode, conf = cache._classify_failure_mode(run, run.fail_reason)
        assert mode == FAILURE_MODE_FORMAT_ERROR
        assert conf >= 0.9
    print("  PASS test_classify_format_error")


def test_classify_max_steps():
    """测试: 步数超限被正确识别."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        run = FailedRun(
            ts=0.0,
            challenge_id="X",
            steps=35,
            final_answer="",
            fail_reason="达到最大步数 35",
            first_5_steps=[],
            last_step_thought="",
            used_tools=["ssh_exec"],
        )
        mode, conf = cache._classify_failure_mode(run, run.fail_reason)
        assert mode == FAILURE_MODE_MAX_STEPS
        assert conf >= 0.9
    print("  PASS test_classify_max_steps")


def test_classify_repeat_action():
    """测试: 重复动作被正确识别 (前 5 步中同 action+input 出现 3+ 次)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        first_5 = [
            {"step_no": 1, "thought": "", "action": "ssh_exec",
             "action_input_preview": "ls", "observation_preview": ""},
            {"step_no": 2, "thought": "", "action": "ssh_exec",
             "action_input_preview": "ls", "observation_preview": ""},
            {"step_no": 3, "thought": "", "action": "ssh_exec",
             "action_input_preview": "ls", "observation_preview": ""},
            {"step_no": 4, "thought": "", "action": "ssh_exec",
             "action_input_preview": "ls", "observation_preview": ""},
        ]
        run = FailedRun(
            ts=0.0,
            challenge_id="X",
            steps=10,
            final_answer="",
            fail_reason="其他原因",
            first_5_steps=first_5,
            last_step_thought="",
            used_tools=["ssh_exec"],
        )
        mode, conf = cache._classify_failure_mode(run, run.fail_reason)
        assert mode == FAILURE_MODE_REPEAT_ACTION
        assert conf >= 0.7
    print("  PASS test_classify_repeat_action")


def test_classify_loop_tool():
    """测试: 循环工具使用 (用 1-2 种工具 + 步数 >= 5)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        first_5 = [
            {"step_no": i, "thought": "", "action": "ls",
             "action_input_preview": f"cmd{i}", "observation_preview": ""}
            for i in range(1, 6)
        ]
        run = FailedRun(
            ts=0.0,
            challenge_id="X",
            steps=10,
            final_answer="",
            fail_reason="其他",
            first_5_steps=first_5,
            last_step_thought="",
            used_tools=["ls"],  # 单工具
        )
        mode, conf = cache._classify_failure_mode(run, run.fail_reason)
        assert mode == FAILURE_MODE_LOOP_TOOL
        assert conf >= 0.6
    print("  PASS test_classify_loop_tool")


def test_classify_token_waste():
    """测试: Token 浪费 (步数高 + 工具少 + 无 final_answer)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        first_5 = [
            {"step_no": i, "thought": "", "action": "ssh_exec",
             "action_input_preview": f"diff{i}", "observation_preview": ""}
            for i in range(1, 6)
        ]
        run = FailedRun(
            ts=0.0,
            challenge_id="X",
            steps=25,
            final_answer="",
            fail_reason="其他",
            first_5_steps=first_5,
            last_step_thought="",
            used_tools=["ssh_exec"],
        )
        mode, conf = cache._classify_failure_mode(run, run.fail_reason)
        # 25 步 + 1 工具 + 无 final → token_waste
        assert mode == FAILURE_MODE_TOKEN_WASTE
        assert conf >= 0.5
    print("  PASS test_classify_token_waste")


def test_classify_wrong_approach():
    """测试: 解题方向错误 (有 final_answer 但失败)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        first_5 = [
            {"step_no": i, "thought": "", "action": "binary_analyze",
             "action_input_preview": f"path{i}", "observation_preview": ""}
            for i in range(1, 6)
        ]
        run = FailedRun(
            ts=0.0,
            challenge_id="X",
            steps=8,
            final_answer="flag{wrong_answer}",
            fail_reason="flag 不匹配",
            first_5_steps=first_5,
            last_step_thought="",
            used_tools=["binary_analyze", "strings"],
        )
        mode, conf = cache._classify_failure_mode(run, run.fail_reason)
        assert mode == FAILURE_MODE_WRONG_APPROACH
        assert conf >= 0.4
    print("  PASS test_classify_wrong_approach")


def test_classify_unknown():
    """测试: 无法分类时返回 UNKNOWN."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        run = FailedRun(
            ts=0.0,
            challenge_id="X",
            steps=1,
            final_answer="",
            fail_reason="",
            first_5_steps=[],
            last_step_thought="",
            used_tools=[],
        )
        mode, conf = cache._classify_failure_mode(run, run.fail_reason)
        assert mode == FAILURE_MODE_UNKNOWN
        assert conf <= 0.5
    print("  PASS test_classify_unknown")


# ==================== 测试 4: _suggest_tools 工具推荐 ====================

def test_suggest_tools_excludes_used():
    """测试: 推荐工具排除已用工具."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        # forensics, 已用 file_read + strings
        suggestions = cache._suggest_tools(
            "forensics",
            used_tools=["file_read", "strings"],
            failure_mode=FAILURE_MODE_UNKNOWN,
            max_n=3,
        )
        assert "file_read" not in suggestions
        assert "strings" not in suggestions
        assert len(suggestions) <= 3
        # 应推荐未用工具
        assert all(t in TOOL_CATEGORY_MAP["forensics"] for t in suggestions)
    print("  PASS test_suggest_tools_excludes_used")


def test_suggest_tools_loop_tool_priority():
    """测试: 循环失败模式优先推荐 L2 专用工具."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        # 已用通用工具
        suggestions = cache._suggest_tools(
            "forensics",
            used_tools=["file_read", "hex_dump", "strings"],
            failure_mode=FAILURE_MODE_LOOP_TOOL,
            max_n=3,
        )
        # 应优先推 mem_xor_analyze / exiftool / binwalk 等专用工具
        assert "mem_xor_analyze" in suggestions or "exiftool" in suggestions
        # 通用工具被排除
        assert "file_read" not in suggestions
    print("  PASS test_suggest_tools_loop_tool_priority")


def test_suggest_tools_unknown_type():
    """测试: 未知类型 fallback 到 misc."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        suggestions = cache._suggest_tools(
            "nonexistent_type",
            used_tools=[],
            failure_mode=FAILURE_MODE_UNKNOWN,
            max_n=3,
        )
        assert len(suggestions) > 0
        assert all(t in TOOL_CATEGORY_MAP["misc"] for t in suggestions)
    print("  PASS test_suggest_tools_unknown_type")


def test_suggest_tools_max_n():
    """测试: 推荐数量受 max_n 限制."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        s = cache._suggest_tools("forensics", [], FAILURE_MODE_UNKNOWN, max_n=2)
        assert len(s) <= 2
    print("  PASS test_suggest_tools_max_n")


# ==================== 测试 5: _build_improvement_hint 提示生成 ====================

def test_build_improvement_hint_all_modes():
    """测试: 所有失败模式都能生成提示."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        for mode in [
            FAILURE_MODE_LOOP_TOOL,
            FAILURE_MODE_REPEAT_ACTION,
            FAILURE_MODE_WRONG_APPROACH,
            FAILURE_MODE_NULL_OBSERVATION,
            FAILURE_MODE_FORMAT_ERROR,
            FAILURE_MODE_MAX_STEPS,
            FAILURE_MODE_TOKEN_WASTE,
            FAILURE_MODE_UNKNOWN,
        ]:
            hint = cache._build_improvement_hint(
                mode, ["ls"], ["binary_analyze", "mem_xor_analyze"]
            )
            assert isinstance(hint, str)
            assert len(hint) > 0
            # FORMAT_ERROR 不含工具推荐, 其他模式应含推荐工具
            if mode == FAILURE_MODE_FORMAT_ERROR:
                # 应包含格式修正提示
                assert "格式" in hint or "三段式" in hint
            else:
                # 应包含推荐工具名
                assert "binary_analyze" in hint or "mem_xor_analyze" in hint
    print("  PASS test_build_improvement_hint_all_modes")


# ==================== 测试 6: reflect() 端到端 ====================

def test_reflect_no_history_returns_none():
    """测试: 无失败历史时 reflect 返回 None."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        ref = cache.reflect("CTF-UNSEEN", "forensics", "medium")
        assert ref is None
    print("  PASS test_reflect_no_history_returns_none")


def test_reflect_end_to_end():
    """测试: store → reflect 完整流程."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        steps = make_fake_steps(10, action="ls", action_input="ls")
        cache.store(
            "CTF-Where_am_i",
            steps=steps,
            final_answer="athena{wrong}",
            fail_reason="flag 不匹配",
            success=False,
        )
        # 触发反思
        ref = cache.reflect("CTF-Where_am_i", "osint", "medium")
        assert ref is not None
        assert ref.challenge_id == "CTF-Where_am_i"
        assert ref.related_type == "osint"
        assert ref.related_difficulty == "medium"
        # mode 应是已识别的失败模式之一
        assert ref.failure_mode in [
            FAILURE_MODE_WRONG_APPROACH,
            FAILURE_MODE_LOOP_TOOL,    # 单工具 + 步数 >= 5
            FAILURE_MODE_REPEAT_ACTION,  # 10 步同 ls
            FAILURE_MODE_TOKEN_WASTE,
        ]
        # ls 被归一化为 shell
        assert "shell" in ref.used_tools
        assert len(ref.suggested_tools) <= 3
        # osint 类型应推荐 osint 工具
        assert all(t in TOOL_CATEGORY_MAP["osint"] for t in ref.suggested_tools)
        assert ref.improvement_hint != ""
        # 置信度合法
        assert 0.0 <= ref.confidence <= 1.0
    print("  PASS test_reflect_end_to_end")


def test_reflect_persistence():
    """测试: reflect 持久化到 reflections/ 目录."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        steps = make_fake_steps(5)
        cache.store("CTF-X", steps=steps, final_answer="", fail_reason="max_steps", success=False)
        ref = cache.reflect("CTF-X", "crypto", "hard")
        assert ref is not None
        # 验证文件存在
        rf = cache._reflection_file("CTF-X")
        assert rf.exists()
        # 读取最新
        latest = cache.get_latest_reflection("CTF-X")
        assert latest is not None
        assert latest.challenge_id == "CTF-X"
        assert latest.failure_mode == FAILURE_MODE_MAX_STEPS
    print("  PASS test_reflect_persistence")


def test_reflect_multiple_calls_accumulate():
    """测试: 多次 reflect 都持久化 (历史)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        # 第一次失败 + 反思
        cache.store("CTF-Y", make_fake_steps(5), "", "格式错", success=False)
        r1 = cache.reflect("CTF-Y", "reverse", "medium")
        # 第二次失败 + 反思
        cache.store("CTF-Y", make_fake_steps(8), "", "达到最大步数 35", success=False)
        r2 = cache.reflect("CTF-Y", "reverse", "medium")
        # 两条都应持久化
        rf = cache._reflection_file("CTF-Y")
        lines = [l for l in rf.read_text(encoding="utf-8").split("\n") if l.strip()]
        assert len(lines) == 2
        # get_latest 返回最新
        latest = cache.get_latest_reflection("CTF-Y")
        assert latest is not None
        assert latest.failure_mode == FAILURE_MODE_MAX_STEPS
    print("  PASS test_reflect_multiple_calls_accumulate")


# ==================== 测试 7: format_reflection_hint 提示生成 ====================

def test_format_reflection_hint_empty():
    """测试: 无失败历史时返回空字符串."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        hint = cache.format_reflection_hint("CTF-UNSEEN", "forensics", "medium")
        assert hint == ""
    print("  PASS test_format_reflection_hint_empty")


def test_format_reflection_hint_with_history():
    """测试: 有历史时生成完整提示."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        steps = make_fake_steps(8, action="ls", action_input="ls")
        cache.store("CTF-Where_am_i", steps, "wrong", "其他", success=False)
        hint = cache.format_reflection_hint("CTF-Where_am_i", "osint", "medium")
        assert hint != ""
        # 中文 tag 验证 (用 chr 避免编码问题): 演化反思
        tag = chr(0x6F14) + chr(0x5316) + chr(0x53CD) + chr(0x601D)
        assert tag in hint
        # ls 被归一化为 shell
        assert "shell" in hint
        # 建议改用 tag
        assert chr(0x5EFA) + chr(0x8BAE) + chr(0x6539) + chr(0x7528) in hint
    print("  PASS test_format_reflection_hint_with_history")


# ==================== 测试 8: clear() 同时清理 failures + reflections ====================

def test_clear_cleans_reflections_too():
    """测试: clear() 同时清理 reflections/."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        steps = make_fake_steps(5)
        cache.store("CTF-CLR", steps, "wrong", "max_steps", success=False)
        cache.reflect("CTF-CLR", "forensics", "medium")
        # 验证 reflections 存在
        rf = cache._reflection_file("CTF-CLR")
        assert rf.exists()
        # 清理
        cache.clear("CTF-CLR")
        # 失败历史 + reflection 都应被清
        assert not rf.exists()
        assert cache.count("CTF-CLR") == 0
    print("  PASS test_clear_cleans_reflections_too")


# ==================== 测试 9: Reflection 数据结构 ====================

def test_reflection_dataclass_serialization():
    """测试: Reflection 序列化/反序列化."""
    original = Reflection(
        ts=1234567890.0,
        challenge_id="CTF-X",
        failure_mode=FAILURE_MODE_LOOP_TOOL,
        confidence=0.85,
        used_tools=["ls", "cat"],
        suggested_tools=["binary_analyze"],
        improvement_hint="建议改用专用工具",
        related_type="reverse",
        related_difficulty="medium",
    )
    d = original.to_dict()
    assert d["challenge_id"] == "CTF-X"
    assert d["failure_mode"] == FAILURE_MODE_LOOP_TOOL
    assert d["confidence"] == 0.85

    # 反序列化
    restored = Reflection.from_dict(d)
    assert restored.challenge_id == original.challenge_id
    assert restored.failure_mode == original.failure_mode
    assert restored.used_tools == original.used_tools
    assert restored.suggested_tools == original.suggested_tools
    print("  PASS test_reflection_dataclass_serialization")


def test_reflection_from_dict_compat():
    """测试: from_dict 兼容缺失字段 (旧数据无 related_*)."""
    old_data = {
        "ts": 100.0,
        "challenge_id": "OLD",
        "failure_mode": FAILURE_MODE_UNKNOWN,
        "confidence": 0.3,
        "used_tools": [],
        "suggested_tools": [],
        "improvement_hint": "old",
    }
    ref = Reflection.from_dict(old_data)
    assert ref.related_type == ""
    assert ref.related_difficulty == ""
    assert ref.improvement_hint == "old"
    print("  PASS test_reflection_from_dict_compat")


# ==================== 测试 10: ReActEngine 集成 (mock LLM) ====================

def test_react_engine_triggers_reflect_on_failure():
    """测试: ReActEngine 失败时自动调用 reflect()."""
    from ctf_agent.agent.react import ReActEngine, ReActResult  # type: ignore[import-not-found]
    from ctf_agent.llm import LLMClient  # type: ignore[import-not-found]
    from ctf_agent.tools.base import Tool, ToolResult  # type: ignore[import-not-found]

    # Mock LLM: 始终返回 Final Answer (但答案错误)
    class MockLLM:
        def __init__(self):
            self.calls = 0
        def chat(self, messages, model=None, temperature=0.0):
            from ctf_agent.llm import ChatResult  # type: ignore[import-not-found]
            self.calls += 1
            return ChatResult(
                content="Final Answer: wrong_flag",
                usage=type("U", (), {"total_tokens": 100})(),
            )

    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        llm = MockLLM()
        # 空工具列表
        engine = ReActEngine(
            llm=llm,
            tools=[],
            max_steps=5,
            failed_cache=cache,
            challenge_id="CTF-TEST",
            challenge_type="crypto",
            challenge_difficulty="medium",
        )
        # 直接调用 _fail_and_return 模拟失败
        result = ReActResult(
            success=False,
            final_answer="wrong",
            fail_reason="测试失败",
            steps=make_fake_steps(3, action="ls", action_input="ls"),
        )
        # 模拟 _store_failed_if_needed
        engine._store_failed_if_needed(result)
        # 验证: 失败存储 + 反思都已触发
        assert cache.count("CTF-TEST") == 1
        latest_ref = cache.get_latest_reflection("CTF-TEST")
        assert latest_ref is not None
        assert latest_ref.related_type == "crypto"
    print("  PASS test_react_engine_triggers_reflect_on_failure")


def test_inject_context_includes_reflection_hint():
    """测试: _inject_context 包含 reflection hint."""
    from ctf_agent.agent.react import ReActEngine  # type: ignore[import-not-found]

    with tempfile.TemporaryDirectory() as tmpdir:
        cache = FailedTrajectoryCache(cache_dir=tmpdir)
        # 先 store + reflect
        steps = make_fake_steps(8, action="ls", action_input="ls")
        cache.store("CTF-INJ", steps, "wrong", "其他", success=False)
        cache.reflect("CTF-INJ", "osint", "medium")

        class DummyLLM:
            def chat(self, *a, **kw):
                from ctf_agent.llm import ChatResult  # type: ignore[import-not-found]
                return ChatResult(content="", usage=type("U", (), {"total_tokens": 0})())

        engine = ReActEngine(
            llm=DummyLLM(),
            tools=[],
            failed_cache=cache,
            challenge_id="CTF-INJ",
            challenge_type="osint",
            challenge_difficulty="medium",
        )
        # 注入上下文
        prompt = engine._inject_context("base prompt", "task1", "")
        # 验证包含: base + type hint + fail hint + reflection hint
        assert "base prompt" in prompt
        # 演化反思 tag
        tag = chr(0x6F14) + chr(0x5316) + chr(0x53CD) + chr(0x601D)
        assert tag in prompt
        # 建议改用 tag
        assert chr(0x5EFA) + chr(0x8BAE) + chr(0x6539) + chr(0x7528) in prompt
    print("  PASS test_inject_context_includes_reflection_hint")


# ==================== Test Runner ====================

if __name__ == "__main__":
    tests = [
        test_normalize_tool_name_aliases,
        test_tool_category_map_completeness,
        test_classify_format_error,
        test_classify_max_steps,
        test_classify_repeat_action,
        test_classify_loop_tool,
        test_classify_token_waste,
        test_classify_wrong_approach,
        test_classify_unknown,
        test_suggest_tools_excludes_used,
        test_suggest_tools_loop_tool_priority,
        test_suggest_tools_unknown_type,
        test_suggest_tools_max_n,
        test_build_improvement_hint_all_modes,
        test_reflect_no_history_returns_none,
        test_reflect_end_to_end,
        test_reflect_persistence,
        test_reflect_multiple_calls_accumulate,
        test_format_reflection_hint_empty,
        test_format_reflection_hint_with_history,
        test_clear_cleans_reflections_too,
        test_reflection_dataclass_serialization,
        test_reflection_from_dict_compat,
        test_react_engine_triggers_reflect_on_failure,
        test_inject_context_includes_reflection_hint,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            print(f"  FAIL {t.__name__}: {e}")
            failed += 1
        except Exception as e:  # noqa: BLE001
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{'='*50}")
    if failed == 0:
        print(f"ALL {len(tests)} TESTS PASSED")
    else:
        print(f"{failed}/{len(tests)} TESTS FAILED")
        sys.exit(1)
