"""Sprint 15: skill_learner 与 quick_solve 联动验证.

验证：
1. learn_skill 在成功解题时，关联 quick_solve 模板脚本并填充 skill.script_ref；
   成功后回填脚本使用统计（record_use 被调用 success=True）。
2. 失败解题不回填统计，且标题带 [避坑] 标记。
3. 无匹配脚本时 script_ref 为空且流程不报错（不污染 manifest）。

注：通过 monkeypatch 替换 _match_quick_solve，避免测试真实读写 manifest.json。
"""
from __future__ import annotations

import tempfile
from unittest.mock import MagicMock

from ctf_agent.agent.react import ReActResult, ReActStep
from ctf_agent.memory import SkillLibrary
from ctf_agent.skill_learner import learn_skill


def _result(success: bool) -> ReActResult:
    return ReActResult(
        success=success,
        final_answer="flag{x}" if success else "",
        fail_reason="" if success else "超时",
        steps=[
            ReActStep(step_no=1, action="web_recon", observation="found /admin sqli"),
            ReActStep(step_no=2, action="sqlmap", observation="dumped users"),
        ],
    )


def test_success_fills_script_ref_and_records_use(monkeypatch) -> None:
    """成功解题：关联 quick_solve 脚本填充 script_ref，并回填使用统计."""
    fake_reg = MagicMock()
    monkeypatch.setattr(
        "ctf_agent.skill_learner._match_quick_solve",
        lambda category, tools, task: ("web_quick_probe.py", fake_reg),
    )
    with tempfile.TemporaryDirectory() as d:
        lib = SkillLibrary(d)
        sk = learn_skill(
            "SQLi 登录绕过", _result(True), lib,
            challenge_type="web", difficulty="easy",
        )
        assert sk is not None
        assert sk.script_ref == "web_quick_probe.py"
        fake_reg.record_use.assert_called_once_with("web_quick_probe.py", success=True)


def test_failure_marks_avoid_and_no_record(monkeypatch) -> None:
    """失败解题：标题带 [避坑]，且不回填成功统计."""
    fake_reg = MagicMock()
    monkeypatch.setattr(
        "ctf_agent.skill_learner._match_quick_solve",
        lambda category, tools, task: ("web_quick_probe.py", fake_reg),
    )
    with tempfile.TemporaryDirectory() as d:
        lib = SkillLibrary(d)
        sk = learn_skill(
            "SQLi 题", _result(False), lib,
            challenge_type="web", difficulty="easy",
        )
        assert sk is not None
        assert "[避坑]" in sk.title
        fake_reg.record_use.assert_not_called()


def test_no_match_leaves_empty_script_ref(monkeypatch) -> None:
    """无匹配脚本：script_ref 为空，且流程不报错."""
    monkeypatch.setattr(
        "ctf_agent.skill_learner._match_quick_solve",
        lambda category, tools, task: ("", None),
    )
    with tempfile.TemporaryDirectory() as d:
        lib = SkillLibrary(d)
        sk = learn_skill(
            "冷门逆向题", _result(True), lib,
            challenge_type="reverse", difficulty="easy",
        )
        assert sk is not None
        assert sk.script_ref == ""


def test_below_min_steps_returns_none() -> None:
    """信息量不足（步数 < min_steps）时不生成 skill，避免噪声."""
    with tempfile.TemporaryDirectory() as d:
        lib = SkillLibrary(d)
        r = ReActResult(success=True, final_answer="flag{x}")
        sk = learn_skill("题", r, lib, challenge_type="web", difficulty="easy")
        assert sk is None
