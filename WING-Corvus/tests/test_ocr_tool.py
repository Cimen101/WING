"""Unit tests for OCR tool (Sprint 12 M3.5).

覆盖:
- OcrTool: 工具名, 参数 schema, description 关键字
- 工厂函数 ocr_tool() 返回 1 个工具
- 降级路径: tesseract 不可用时返回 ERROR
- 空 file_path / 无效 lang 校验
- 模拟 tesseract 输出解析 (含 longest lines, statistics)
- 测试 default_tools 含 ocr
- 真实环境: tesseract 测 Whereami.jpeg (Sprint 12 验证)
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ctf_agent.tools.base import ToolResult
from ctf_agent.tools.ocr_tool import OcrTool, ocr_tool


# ============ Mock SSH ============

def _mock_ssh(tesseract_success: bool = True) -> MagicMock:
    """构造 mock SSHClient."""
    mock = MagicMock()
    r_which = MagicMock()
    r_which.is_success = tesseract_success
    r_which.stdout = "/usr/bin/tesseract\n" if tesseract_success else ""
    r_exec = MagicMock()
    r_exec.is_success = True
    r_exec.stdout = ""
    r_exec.stderr = ""
    mock.exec_cmd.side_effect = lambda *args, **kw: r_which if "which" in args[0] else r_exec
    return mock


# ============ 基础 schema ============

def test_ocr_tool_name() -> None:
    tool = OcrTool(_mock_ssh())
    assert tool.name == "ocr"


def test_ocr_description_contains_tesseract() -> None:
    tool = OcrTool(_mock_ssh())
    desc = tool.description
    assert "Tesseract" in desc or "tesseract" in desc
    assert "OSINT" in desc or "forensics" in desc


def test_ocr_parameters_schema() -> None:
    tool = OcrTool(_mock_ssh())
    params = tool.parameters
    assert params["type"] == "object"
    props = params["properties"]
    assert "file_path" in props
    assert "lang" in props
    assert "psm" in props
    assert "file_path" in params["required"]


def test_ocr_lang_default_is_eng() -> None:
    tool = OcrTool(_mock_ssh())
    props = tool.parameters["properties"]
    assert props["lang"]["default"] == "eng"


# ============ 工厂 ============

def test_ocr_factory_returns_one_tool() -> None:
    tools = ocr_tool(_mock_ssh())
    names = {t.name for t in tools}
    assert "ocr" in names
    assert len(tools) == 1


# ============ 降级路径 ============

def test_tesseract_missing_degradation() -> None:
    """tesseract 未装时返回降级提示."""
    mock = MagicMock()
    r_which_fail = MagicMock()
    r_which_fail.is_success = False
    r_which_fail.stdout = ""
    mock.exec_cmd.return_value = r_which_fail

    tool = OcrTool(mock)
    out = tool.execute(file_path="/tmp/test.jpg")
    assert "ERROR" in out
    assert "tesseract" in out.lower()


def test_ocr_empty_file_path() -> None:
    tool = OcrTool(_mock_ssh())
    out = tool.execute(file_path="")
    assert "ERROR" in out
    assert "不能为空" in out


def test_ocr_invalid_lang() -> None:
    """lang 包含非法字符时报错."""
    tool = OcrTool(_mock_ssh())
    out = tool.execute(file_path="/tmp/x.jpg", lang="eng; rm -rf /")
    assert "ERROR" in out
    assert "非法" in out


# ============ 模拟 tesseract 输出 ============

def test_ocr_parse_success() -> None:
    """模拟 tesseract 成功提取文字."""
    mock = MagicMock()
    r_which = MagicMock(is_success=True, stdout="/usr/bin/tesseract\n")
    # 模拟: tesseract 命令 + cat 输出
    ocr_text = (
        "Welcome to Petroglyph Site\n"
        "Tamgaly, Kazakhstan\n"
        "Established 2003"
    )
    mock_resp = f"Tesseract Open Source OCR Engine v5.5.0\n===RESULT===\n{ocr_text}"
    r_exec = MagicMock(is_success=True, stdout=mock_resp, stderr="")
    mock.exec_cmd.side_effect = lambda *args, **kw: r_which if "which" in args[0] else r_exec

    tool = OcrTool(mock)
    out = tool.execute(file_path="/tmp/site.jpg", lang="eng")

    assert "Welcome to Petroglyph Site" in out
    assert "Tamgaly" in out
    assert "Kazakhstan" in out
    assert "字符" in out  # statistics


def test_ocr_no_text_extracted() -> None:
    """tesseract 成功但无文字 (如纯色图片)."""
    mock = MagicMock()
    r_which = MagicMock(is_success=True, stdout="/usr/bin/tesseract\n")
    mock_resp = "Tesseract log\n===RESULT===\n"
    r_exec = MagicMock(is_success=True, stdout=mock_resp, stderr="")
    mock.exec_cmd.side_effect = lambda *args, **kw: r_which if "which" in args[0] else r_exec

    tool = OcrTool(mock)
    out = tool.execute(file_path="/tmp/blank.jpg")

    assert "0 字符" in out or "没有可见文字" in out


# ============ Sprint 13 P0: OCR 假阳性检测 (whereami 退化根因) ============

def test_is_likely_no_text_empty():
    """空文本/纯空白视为无文字."""
    from ctf_agent.tools.ocr_tool import _is_likely_no_text
    assert _is_likely_no_text("") is True
    assert _is_likely_no_text("   \n  ") is True
    assert _is_likely_no_text(None or "") is True


def test_is_likely_no_text_estimating_resolution():
    """[关键] tesseract "Estimating resolution as 381" 视为无文字 (v11 whereami 退化根因)."""
    from ctf_agent.tools.ocr_tool import _is_likely_no_text
    # v11 实际触发: tesseract 在无文字时只输出这行
    text = "Estimating resolution as 381"
    assert _is_likely_no_text(text) is True, (
        f"应识别为无文字 (tesseract 内部状态), 实际: {text!r}"
    )


def test_is_likely_no_text_short():
    """短文本 (< 20 字符) 视为无文字."""
    from ctf_agent.tools.ocr_tool import _is_likely_no_text
    assert _is_likely_no_text("hi") is True
    assert _is_likely_no_text("1234567890123456789") is True  # 19 chars


def test_is_likely_no_text_real_text():
    """真文字 (含地名/标志) 不被误判."""
    from ctf_agent.tools.ocr_tool import _is_likely_no_text
    assert _is_likely_no_text("Tamgaly Petroglyphs site, Central Asia") is False
    assert _is_likely_no_text("Site: Tamgaly\nCoordinates: 43.793, 75.538\nKAZ") is False
    assert _is_likely_no_text("Warning: deprecated API used") is True  # 全是 warning


def test_ocr_no_text_detected_v11_regression():
    """Sprint 13 回归测试: v11 whereami 触发 [NO_TEXT_DETECTED] 标记.

    v11 真实场景: ocr 返回 "Estimating resolution as 381" (无真实文字),
    之前 LLM 把这行当 web_search query, 浪费 4 步 (5 → 15 步).
    Sprint 13 修复: ocr 工具应标记 [NO_TEXT_DETECTED], 引导 LLM 跳到 osm_geocode.
    """
    mock = MagicMock()
    r_which = MagicMock(is_success=True, stdout="/usr/bin/tesseract\n")
    # v11 真实输出: 28 chars tesseract 内部状态
    mock_resp = "tesseract log\n===RESULT===\nEstimating resolution as 381"
    r_exec = MagicMock(is_success=True, stdout=mock_resp, stderr="")
    mock.exec_cmd.side_effect = lambda *args, **kw: r_which if "which" in args[0] else r_exec

    tool = OcrTool(mock)
    out = tool.execute(file_path="/tmp/ctf_real4/Where_am_i/Whereami.jpeg", lang="eng")

    # 关键断言: 包含 [NO_TEXT_DETECTED] 标记
    assert "[NO_TEXT_DETECTED]" in out, (
        f"应包含 [NO_TEXT_DETECTED] 标记, 实际输出: {out!r}"
    )
    # 应警告 LLM 不要拿 OCR 输出做 web_search
    assert "不要" in out or "do not" in out.lower() or "not" in out.lower()
    # 应给出下一步建议
    assert "osm_geocode" in out or "LLM" in out


def test_ocr_multilang() -> None:
    """支持多语言组合 (eng+chi_sim)."""
    mock = MagicMock()
    r_which = MagicMock(is_success=True, stdout="/usr/bin/tesseract\n")
    r_exec = MagicMock(
        is_success=True,
        stdout="Tesseract log\n===RESULT===\n岩画 site\nPetroglyphs",
        stderr="",
    )
    mock.exec_cmd.side_effect = lambda *args, **kw: r_which if "which" in args[0] else r_exec

    tool = OcrTool(mock)
    out = tool.execute(file_path="/tmp/x.jpg", lang="eng+chi_sim")

    assert "岩画" in out
    assert "Petroglyphs" in out


def test_ocr_psm_clamp() -> None:
    """psm 越界时被截断 (Tesseract 0-13)."""
    mock = MagicMock()
    r_which = MagicMock(is_success=True, stdout="/usr/bin/tesseract\n")
    r_exec = MagicMock(
        is_success=True,
        stdout="===RESULT===\nresult text",
        stderr="",
    )
    captured_cmd: list[str] = []

    def capture_exec(cmd, **kw):
        captured_cmd.append(cmd)
        if "which" in cmd:
            return r_which
        return r_exec

    mock.exec_cmd.side_effect = capture_exec

    tool = OcrTool(mock)
    # psm 999 越界, 应被截断到 13
    tool.execute(file_path="/tmp/x.jpg", psm=999)

    # 检查实际命令中 --psm 13
    assert any("--psm 13" in c for c in captured_cmd), f"psm 999 should be clamped to 13, got: {captured_cmd}"


# ============ default_tools 集成 ============

def test_default_tools_includes_ocr() -> None:
    from ctf_agent.tools import default_tools
    tools = default_tools(_mock_ssh())
    names = {t.name for t in tools}
    assert "ocr" in names


def test_default_tools_with_ssh_client_has_33_tools() -> None:
    """Sprint 14 P2: 29 → 33 (新增 ecdsa_nonce_reuse + angr_symbolic_exec + des_cryptanalysis + feistel_decrypt)."""
    from ctf_agent.tools import default_tools
    tools = default_tools(_mock_ssh())
    assert len(tools) == 33


# ============ 真实环境端到端 (skip if no SSH) ============

def test_real_ocr_whereami() -> None:
    """真实 tesseract 测 Whereami.jpeg (Sprint 12 验证)."""
    from ctf_agent.config import get_settings
    from ctf_agent.ssh.client import ssh_client_from_settings

    try:
        client = ssh_client_from_settings(get_settings())
        r = client.exec_cmd("echo ok", timeout=5)
        if not r.is_success or r.stdout.strip() != "ok":
            pytest.skip("SSH not reachable")
    except Exception:
        pytest.skip("SSH connection failed")

    tool = OcrTool(client)
    # Whereami.jpeg 是岩画 (无文字), tesseract 应返回 0 字符
    out = tool.execute(
        file_path="/tmp/ctf_real3/Where_am_i/Whereami.jpeg",
        lang="eng",
    )
    # 即使无文字, 工具也要返回有意义的降级提示
    assert "OCR" in out or "===RESULT===" in out or "没有可见文字" in out or "0 字符" in out
    print(f"\n[OCR Whereami] {out[:300]}")
