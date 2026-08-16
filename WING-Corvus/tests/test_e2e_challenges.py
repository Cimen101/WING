"""Sprint 5.3 真实样题端到端测试.

在 Kali 沙箱准备 CTF 挑战文件，用真实 DeepSeek API + SSH 工具解决。
覆盖题型：misc (strings/cat)、reverse (XOR)、crypto (RSA)。

挑战文件预先在 Kali /tmp/ctf_challenges/ 下准备：
- strings.bin: 含 flag{ssh_misc_strings_2026} 的二进制文件
- flag.txt: 含 flag{ssh_cat_simple_2026} 的文本文件
- reverse_xor.bin: XOR(key=0x42) 加密的 flag{ssh_reverse_xor_2026}
- rsa_challenge.txt: n=3233, e=17, c=2790（明文 m=65）

测试默认 skip，需 RUN_REAL_API=1 + RUN_REAL_SSH=1 同时触发。
"""

from __future__ import annotations

import os

import pytest

from ctf_agent.agent import ReActEngine
from ctf_agent.config import get_settings
from ctf_agent.llm import LLMClient
from ctf_agent.ssh import ssh_client_from_settings
from ctf_agent.tools import default_tools


REAL_API = os.environ.get("RUN_REAL_API", "") == "1"
REAL_SSH = os.environ.get("RUN_REAL_SSH", "") == "1"
RUN_E2E = REAL_API and REAL_SSH


def _make_engine_with_ssh(max_steps: int = 8) -> ReActEngine:
    """创建带 SSH 工具的 ReActEngine."""
    settings = get_settings()
    assert settings.has_llm_config(), "需要 OPENAI_API_KEY"
    assert settings.has_kali_config(), "需要 KALI SSH 配置"

    llm = LLMClient(settings)
    ssh_client = ssh_client_from_settings(settings)
    ssh_client.connect()
    tools = default_tools(ssh_client=ssh_client)

    return ReActEngine(
        llm=llm,
        tools=tools,
        max_steps=max_steps,
        model=settings.executor_model,
        breaker=None,  # 默认熔断器
    ), ssh_client  # type: ignore[return-value]


@pytest.mark.skipif(not RUN_E2E, reason="需要 RUN_REAL_API=1 + RUN_REAL_SSH=1")
def test_e2e_misc_cat_read_flag() -> None:
    """端到端: misc 题 - 用 ssh_exec 读取 flag.txt.

    最简单的 SSH 挑战，验证 LLM 能调用 ssh_exec 工具。
    预期 1-2 步：cat 文件 -> Final Answer
    """
    engine, ssh_client = _make_engine_with_ssh(max_steps=5)
    try:
        task = (
            "CTF 杂项挑战：在 Kali Linux 沙箱的 /tmp/ctf_challenges/flag.txt 文件中"
            "藏有一个 flag（格式 flag{...}）。请使用 ssh_exec 工具执行 cat 命令"
            "读取该文件内容，并将 flag 作为最终答案。"
        )
        result = engine.run(task)
        print(f"\n[misc/cat] success={result.success}, steps={result.step_count}, tokens={result.total_tokens}")
        print(f"[Final Answer] {result.final_answer}")
        for i, s in enumerate(result.steps):
            print(f"  Step {s.step_no}: action={s.action}, final={s.is_final}")

        assert result.success is True, f"任务失败: {result.fail_reason}"
        assert "flag{ssh_cat_simple_2026}" in result.final_answer
        # 验证使用了 ssh_exec 工具
        assert any(s.action == "ssh_exec" for s in result.steps), \
            "LLM 未调用 ssh_exec 工具"
    finally:
        ssh_client.close()


@pytest.mark.skipif(not RUN_E2E, reason="需要 RUN_REAL_API=1 + RUN_REAL_SSH=1")
def test_e2e_misc_strings_extract_flag() -> None:
    """端到端: misc 题 - 用 ssh_exec strings 提取二进制文件中的 flag.

    验证 LLM 能用 strings 命令从二进制文件提取 flag。
    预期 1-2 步。
    """
    engine, ssh_client = _make_engine_with_ssh(max_steps=5)
    try:
        task = (
            "CTF 杂项挑战：在 Kali Linux 沙箱的 /tmp/ctf_challenges/strings.bin 文件中"
            "藏有一个 flag（格式 flag{...}），但文件是二进制格式，包含非可打印字符。"
            "请使用 ssh_exec 工具执行 strings 命令提取该文件中的可打印字符串，"
            "找出 flag 并作为最终答案。"
        )
        result = engine.run(task)
        print(f"\n[misc/strings] success={result.success}, steps={result.step_count}, tokens={result.total_tokens}")
        print(f"[Final Answer] {result.final_answer}")
        for s in result.steps:
            print(f"  Step {s.step_no}: action={s.action}")

        assert result.success is True, f"任务失败: {result.fail_reason}"
        assert "flag{ssh_misc_strings_2026}" in result.final_answer
        assert any(s.action == "ssh_exec" for s in result.steps)
    finally:
        ssh_client.close()


@pytest.mark.skipif(not RUN_E2E, reason="需要 RUN_REAL_API=1 + RUN_REAL_SSH=1")
def test_e2e_reverse_xor_decrypt() -> None:
    """端到端: reverse 题 - XOR 解密.

    文件 /tmp/ctf_challenges/reverse_xor.bin 是用 XOR 单字节密钥加密的 flag。
    LLM 需要用 ssh_python 写解密脚本，或用 ssh_exec + xxd 分析。

    预期 2-3 步。
    """
    engine, ssh_client = _make_engine_with_ssh(max_steps=8)
    try:
        task = (
            "CTF 逆向挑战：在 Kali Linux 沙箱的 /tmp/ctf_challenges/reverse_xor.bin 文件"
            "是用单字节 XOR 密钥加密的 flag（格式 flag{...}）。"
            "已知明文以 'flag{' 开头，可以通过分析密文前几字节与 'flag{' 的关系求出密钥。"
            "请使用 ssh_python 工具编写 Python 脚本：读取文件，枚举 0-255 的密钥，"
            "找出能解出以 'flag{' 开头的密钥，输出完整 flag 作为最终答案。"
        )
        result = engine.run(task)
        print(f"\n[reverse/xor] success={result.success}, steps={result.step_count}, tokens={result.total_tokens}")
        print(f"[Final Answer] {result.final_answer}")
        for s in result.steps:
            print(f"  Step {s.step_no}: action={s.action}")

        assert result.success is True, f"任务失败: {result.fail_reason}"
        assert "flag{ssh_reverse_xor_2026}" in result.final_answer
        # 应该用了 ssh_python 或 ssh_exec
        actions = {s.action for s in result.steps}
        assert "ssh_python" in actions or "ssh_exec" in actions, \
            f"LLM 未调用 SSH 工具，actions={actions}"
    finally:
        ssh_client.close()


@pytest.mark.skipif(not RUN_E2E, reason="需要 RUN_REAL_API=1 + RUN_REAL_SSH=1")
def test_e2e_crypto_rsa_decrypt() -> None:
    """端到端: crypto 题 - RSA 解密.

    文件 /tmp/ctf_challenges/rsa_challenge.txt 含 n=3233, e=17, c=2790。
    LLM 需要分解 n（小素数），计算 d，解密得到 m。

    预期 2-3 步。
    """
    engine, ssh_client = _make_engine_with_ssh(max_steps=8)
    try:
        task = (
            "CTF 密码学挑战：在 Kali Linux 沙箱的 /tmp/ctf_challenges/rsa_challenge.txt 文件"
            "中包含 RSA 加密参数（格式 n=xxx, e=xxx, c=xxx）。"
            "n 是两个小素数的乘积，可以用简单分解求出 p 和 q。"
            "请使用 ssh_exec 工具读取文件内容，然后用 ssh_python 工具编写 Python 脚本："
            "分解 n 求 p/q，计算私钥 d，解密密文 c 得到明文 m（整数）。"
            "将明文整数 m 转换为字符（chr(m)）后作为最终答案。"
            "提示：m 是单个字符的 ASCII 码。"
        )
        result = engine.run(task)
        print(f"\n[crypto/rsa] success={result.success}, steps={result.step_count}, tokens={result.total_tokens}")
        print(f"[Final Answer] {result.final_answer}")
        for s in result.steps:
            print(f"  Step {s.step_no}: action={s.action}")

        assert result.success is True, f"任务失败: {result.fail_reason}"
        # 明文 m=65，即字符 'A'
        assert "A" in result.final_answer, f"最终答案: {result.final_answer}"
        actions = {s.action for s in result.steps}
        assert "ssh_python" in actions or "ssh_exec" in actions, \
            f"LLM 未调用 SSH 工具，actions={actions}"
    finally:
        ssh_client.close()


@pytest.mark.skipif(not RUN_E2E, reason="需要 RUN_REAL_API=1 + RUN_REAL_SSH=1")
def test_e2e_crypto_base64_with_internal_tool() -> None:
    """端到端: crypto 题 - Base64 解密（用 L1 内置工具，不用 SSH）.

    验证 L1 内置工具与 L2 SSH 工具共存时，LLM 能正确选择 base64_decode。
    预期 1-2 步。
    """
    engine, ssh_client = _make_engine_with_ssh(max_steps=5)
    try:
        import base64
        flag = "flag{b64_with_ssh_tools}"
        encoded = base64.b64encode(flag.encode()).decode()
        task = (
            f"CTF 密码学挑战：以下字符串是 Base64 编码的 flag：\n\n{encoded}\n\n"
            "请使用 base64_decode 工具解码，并将解码后的 flag 作为最终答案。"
        )
        result = engine.run(task)
        print(f"\n[crypto/b64] success={result.success}, steps={result.step_count}, tokens={result.total_tokens}")
        print(f"[Final Answer] {result.final_answer}")

        assert result.success is True, f"任务失败: {result.fail_reason}"
        assert "flag{b64_with_ssh_tools}" in result.final_answer
        # 应该用 base64_decode 而非 ssh_exec
        assert any(s.action == "base64_decode" for s in result.steps), \
            "LLM 未调用 base64_decode 工具"
    finally:
        ssh_client.close()
