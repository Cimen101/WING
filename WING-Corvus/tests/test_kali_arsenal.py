"""Kali 兵器谱知识模块测试."""

from __future__ import annotations

from ctf_agent.knowledge import ARSENAL, format_arsenal, list_categories


def test_arsenal_has_web_and_pwn():
    cats = list_categories()
    assert "web" in cats
    assert "pwn" in cats


def test_format_filters_category():
    web = format_arsenal(["web"])
    assert "[WEB]" in web
    assert "[PWN]" not in web
    assert "sqlmap" in web


def test_format_only_unwrapped_excludes_wrapped():
    # whatweb 被标记为 wrapped，only_unwrapped 时不应出现在条目里
    text = format_arsenal(["web"], only_unwrapped=True)
    assert "**whatweb**" not in text
    # nikto 未封装，应保留
    assert "nikto" in text


def test_playbook_included():
    text = format_arsenal(["pwn"], include_playbook=True)
    assert "决策流" in text


def test_empty_for_unknown_category():
    assert format_arsenal(["nonexistent"]) == ""


def test_all_entries_have_required_fields():
    for t in ARSENAL:
        assert t.name and t.category and t.when and t.how
