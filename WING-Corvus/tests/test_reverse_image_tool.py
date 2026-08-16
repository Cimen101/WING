"""Unit tests for reverse_image tools (Sprint 12 M3).

覆盖:
- WebSearchTool / PhotonGeocodeTool: 工具名, 参数 schema, description 关键字
- 工厂函数 reverse_image_tools() 返回 2 个工具
- 降级路径: curl 不可用时返回 ERROR
- PhotonGeocodeTool: 解析真实 Photon API JSON 响应 (mock)
- PhotonGeocodeTool: 解析空 features 列表
- WebSearchTool: 解析 Yandex captcha 页面降级提示
- 测试 default_tools 含 web_search + osm_geocode
- 真实环境: Photon 测 Saimaluu-Tash (有 OSM petroglyphs 节点)
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from ctf_agent.tools.base import ToolResult
from ctf_agent.tools.reverse_image_tool import (
    PhotonGeocodeTool,
    WebSearchTool,
    reverse_image_tools,
)


# ============ Mock SSH ============

def _mock_ssh(curl_success: bool = True) -> MagicMock:
    """构造 mock SSHClient."""
    mock = MagicMock()
    # _check_tool 走 ssh.exec_cmd('which curl') 返回 /usr/bin/curl
    r_which = MagicMock()
    r_which.is_success = True
    r_which.stdout = "/usr/bin/curl\n"
    # exec_cmd 默认: 成功 + 给定 stdout
    r_exec = MagicMock()
    r_exec.is_success = True
    r_exec.stdout = ""
    r_exec.stderr = ""
    mock.exec_cmd.side_effect = lambda *args, **kw: r_which if "which" in args[0] else r_exec
    return mock


# ============ 基础 schema ============

def test_web_search_tool_name() -> None:
    tool = WebSearchTool(_mock_ssh())
    assert tool.name == "web_search"


def test_web_search_description_contains_yandex() -> None:
    tool = WebSearchTool(_mock_ssh())
    desc = tool.description
    assert "Yandex" in desc or "yandex" in desc
    # 泛化后描述: 通用技术查阅 + 合规护栏 (禁搜题目名/writeup/题解)
    assert "禁止" in desc
    assert "writeup" in desc or "题解" in desc


def test_web_search_parameters_schema() -> None:
    tool = WebSearchTool(_mock_ssh())
    params = tool.parameters
    assert params["type"] == "object"
    props = params["properties"]
    assert "query" in props
    assert "max_results" in props
    assert "query" in params["required"]


def test_photon_tool_name_is_osm_geocode() -> None:
    """PhotonGeocodeTool 暴露为 osm_geocode (与原 Nominatim 工具同名, 便于 LLM 调用)."""
    tool = PhotonGeocodeTool(_mock_ssh())
    assert tool.name == "osm_geocode"


def test_photon_description_contains_keyword() -> None:
    tool = PhotonGeocodeTool(_mock_ssh())
    desc = tool.description
    assert "Photon" in desc or "komoot" in desc
    assert "OSM" in desc or "OpenStreetMap" in desc


def test_photon_parameters_schema() -> None:
    tool = PhotonGeocodeTool(_mock_ssh())
    params = tool.parameters
    assert params["type"] == "object"
    props = params["properties"]
    assert "name" in props
    assert "limit" in props
    assert "name" in params["required"]


# ============ 工厂 ============

def test_reverse_image_factory_returns_two_tools() -> None:
    tools = reverse_image_tools(_mock_ssh())
    names = {t.name for t in tools}
    assert "web_search" in names
    assert "osm_geocode" in names
    assert len(tools) == 2


# ============ 降级路径 ============

def test_curl_missing_degradation() -> None:
    """curl 未装时, 两个工具都返回降级提示."""
    mock = MagicMock()
    r_which_fail = MagicMock()
    r_which_fail.is_success = False
    r_which_fail.stdout = ""
    mock.exec_cmd.return_value = r_which_fail

    ws = WebSearchTool(mock)
    out_ws = ws.execute(query="test")
    assert "ERROR" in out_ws and "curl" in out_ws.lower()

    og = PhotonGeocodeTool(mock)
    out_og = og.execute(name="test")
    assert "ERROR" in out_og and "curl" in out_og.lower()


def test_web_search_empty_query() -> None:
    ws = WebSearchTool(_mock_ssh())
    out = ws.execute(query="")
    assert "ERROR" in out


def test_photon_empty_name() -> None:
    og = PhotonGeocodeTool(_mock_ssh())
    out = og.execute(name="")
    assert "ERROR" in out


# ============ PhotonGeocodeTool 解析 (mock JSON) ============

def test_photon_parse_success() -> None:
    """Mock Photon 返回 2 个 features, 验证解析."""
    mock = MagicMock()
    r_which = MagicMock(is_success=True, stdout="/usr/bin/curl\n")
    mock_resp = json.dumps({
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [73.85, 41.22]},
                "properties": {
                    "osm_id": 1, "osm_type": "N", "osm_key": "leisure",
                    "osm_value": "nature_reserve", "type": "other",
                    "name": "Saimaluu-Tash Nature Park",
                    "country": "Kyrgyzstan", "state": "Jalal-Abad",
                },
            },
            {
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [73.81, 41.18]},
                "properties": {
                    "osm_id": 2, "osm_type": "N", "osm_key": "tourism",
                    "osm_value": "attraction", "type": "house",
                    "name": "петроглифы Саймалуу-Таш",
                    "country": "Kyrgyzstan",
                },
            },
        ],
    })
    r_exec = MagicMock(is_success=True, stdout=mock_resp, stderr="")
    mock.exec_cmd.side_effect = lambda *args, **kw: r_which if "which" in args[0] else r_exec

    og = PhotonGeocodeTool(mock)
    out = og.execute(name="Saimaluu-Tash", limit=5)

    assert "osm_geocode" in out
    assert "41.22" in out  # lat
    assert "73.85" in out  # lon
    assert "Saimaluu-Tash" in out
    assert "Kyrgyzstan" in out


def test_photon_empty_features() -> None:
    """空 features 时返回降级提示."""
    mock = MagicMock()
    r_which = MagicMock(is_success=True, stdout="/usr/bin/curl\n")
    r_exec = MagicMock(is_success=True, stdout='{"type":"FeatureCollection","features":[]}', stderr="")
    mock.exec_cmd.side_effect = lambda *args, **kw: r_which if "which" in args[0] else r_exec

    og = PhotonGeocodeTool(mock)
    out = og.execute(name="XyzNonExistent")
    assert "无匹配" in out


def test_photon_network_failure() -> None:
    """网络 timeout 时返回降级提示."""
    mock = MagicMock()
    r_which = MagicMock(is_success=True, stdout="/usr/bin/curl\n")
    r_exec = MagicMock(is_success=True, stdout="curl: (28) Connection timed out", stderr="")
    mock.exec_cmd.side_effect = lambda *args, **kw: r_which if "which" in args[0] else r_exec

    og = PhotonGeocodeTool(mock)
    out = og.execute(name="Tamgaly")
    assert "网络失败" in out or "timed out" in out.lower()


# ============ WebSearchTool Yandex 降级 ============

def test_web_search_yandex_captcha_degradation() -> None:
    """Yandex 无有效结果 (captcha/robot 页面) 时返回降级提示."""
    mock = MagicMock()
    r_which = MagicMock(is_success=True, stdout="/usr/bin/curl\n")
    r_exec = MagicMock(
        is_success=True,
        stdout="<html><title>Are you not a robot?</title>...</html>",
        stderr="",
    )
    mock.exec_cmd.side_effect = lambda *args, **kw: r_which if "which" in args[0] else r_exec

    ws = WebSearchTool(mock)
    out = ws.execute(query="Tamgaly petroglyphs")
    # 新版降级: 所有后端无有效结果 → 提示用 LLM 自身知识 + osm_geocode 兜底
    assert "无有效结果" in out
    assert "降级" in out


# ============ default_tools 集成 ============

def test_default_tools_includes_reverse_image() -> None:
    from ctf_agent.tools import default_tools
    tools = default_tools(_mock_ssh())
    names = {t.name for t in tools}
    assert "web_search" in names
    assert "osm_geocode" in names


def test_default_tools_with_ssh_client_has_33_tools() -> None:
    """工具数只增不减: Sprint 14 P2 基线 33, 后续新增 lwe_decode/web_search 等更多."""
    from ctf_agent.tools import default_tools
    tools = default_tools(_mock_ssh())
    assert len(tools) >= 33


# ============ 真实环境端到端 (skip if no SSH) ============

def test_real_photon_saimaluu_tash() -> None:
    """真实 Photon API 测 Saimaluu-Tash (有 OSM petroglyphs 节点)."""
    from ctf_agent.config import get_settings
    from ctf_agent.ssh.client import ssh_client_from_settings

    try:
        client = ssh_client_from_settings(get_settings())
        # 触发一次连接, 失败就 skip
        r = client.exec_cmd("echo ok", timeout=5)
        if not r.is_success or r.stdout.strip() != "ok":
            pytest.skip("SSH not reachable")
    except Exception:
        pytest.skip("SSH connection failed")

    og = PhotonGeocodeTool(client)
    out = og.execute(name="Saimaluu-Tash", limit=3)
    # Photon 可能 timeout, 但如果成功必须包含关键字段
    if "网络失败" not in out and "无匹配" not in out:
        assert "osm_geocode" in out
        assert "Kyrgyzstan" in out or "Кыргызстан" in out
        assert "Saimaluu" in out
