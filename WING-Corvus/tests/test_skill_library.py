"""SkillLibrary（持续学习技能库）单元测试."""

from __future__ import annotations

from ctf_agent.memory.skill_library import SkillLibrary


def test_add_and_get(tmp_path):
    lib = SkillLibrary(tmp_path)
    sk = lib.add_or_update(
        title="RSA 小指数攻击",
        category="crypto",
        trigger="e 很小(如 3)且无 padding",
        body="步骤: 直接对 c 开 e 次方",
        tools=["ssh_python"],
    )
    assert lib.get(sk.id) is not None
    assert lib.stats()["total"] == 1
    # 持久化后重载
    lib2 = SkillLibrary(tmp_path)
    assert lib2.stats()["total"] == 1
    assert "开 e 次方" in lib2.get(sk.id).body


def test_merge_similar(tmp_path):
    lib = SkillLibrary(tmp_path)
    # 学习器对同类题产出的 title/trigger 高度一致，应触发合并升级
    lib.add_or_update(
        title="web 题解题套路(web_recon+sqlmap)",
        category="web",
        trigger="web 类题目 SSTI 模板注入",
        body="步骤: {{7*7}} 验证",
    )
    lib.add_or_update(
        title="web 题解题套路(web_recon+sqlmap)",
        category="web",
        trigger="web 类题目 SSTI 模板注入",
        body="补充: {{config}} 读配置",
    )
    # 高相似应合并为 1 条
    assert lib.stats()["total"] == 1
    sk = lib.all()[0]
    assert sk.version == 2
    assert "读配置" in sk.body


def test_different_category_not_merged(tmp_path):
    lib = SkillLibrary(tmp_path)
    lib.add_or_update(title="注入", category="web", trigger="SSTI", body="a")
    lib.add_or_update(title="注入", category="pwn", trigger="SSTI", body="b")
    assert lib.stats()["total"] == 2


def test_search_and_feedback(tmp_path):
    lib = SkillLibrary(tmp_path)
    sk = lib.add_or_update(
        title="栈溢出 ret2libc",
        category="pwn",
        trigger="无 canary 栈溢出 NX 开",
        body="泄露 libc 再 getshell",
        tools=["pwn_exploit"],
    )
    hits = lib.search("栈溢出 libc", category="pwn")
    assert hits and hits[0].id == sk.id
    lib.mark_used(sk.id, success=True)
    assert lib.get(sk.id).success_count == 1
    assert lib.get(sk.id).use_count == 1


def test_prune(tmp_path):
    lib = SkillLibrary(tmp_path)
    distinct = [
        ("stego lsb decode", "png lsb steganography"),
        ("zip crack password", "encrypted zip archive"),
        ("pcap http extract", "wireshark network capture"),
        ("qrcode reconstruct", "broken qr image"),
        ("memory volatility dump", "ram forensic image"),
    ]
    for title, trig in distinct:
        lib.add_or_update(title=title, category="misc", trigger=trig, body="body")
    assert lib.stats()["total"] == 5
    removed = lib.prune(max_per_category=2)
    assert removed == 3
    assert lib.stats()["total"] == 2


def test_format_for_prompt_empty(tmp_path):
    lib = SkillLibrary(tmp_path)
    assert lib.format_for_prompt("anything") == ""
