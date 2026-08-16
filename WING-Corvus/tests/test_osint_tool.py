"""Sprint 11: OSINT 工具集单元测试."""
from unittest.mock import MagicMock

import pytest

from ctf_agent.ssh.client import CmdResult
from ctf_agent.tools.osint_tool import (
    BinwalkTool,
    ExifToolTool,
    SteghideTool,
    TsharkTool,
    osint_tools,
)


def make_ssh(*, available: bool = True, stdout: str = "", stderr: str = "") -> MagicMock:
    ssh = MagicMock()
    ssh.exec_cmd.return_value = CmdResult(
        stdout=stdout,
        stderr=stderr,
        exit_code=0 if available else 127,
        elapsed=0.1,
    )
    return ssh


def test_exiftool_unavailable_returns_degradation_hint() -> None:
    """工具未装时返回降级提示."""
    ssh = make_ssh(available=False, stdout="not found")
    tool = ExifToolTool(ssh)
    r = tool.execute("/tmp/test.jpg")
    assert "ERROR" in r
    assert "降级" in r


def test_exiftool_success_with_gps_camera_time() -> None:
    """成功路径: GPS/相机/时间高亮."""
    ssh = make_ssh(available=True)
    # 第一次 exec_cmd: `which exiftool` 检测, 第二次: `exiftool` 真实输出
    ssh.exec_cmd.side_effect = [
        CmdResult(stdout="/usr/bin/exiftool\n", stderr="", exit_code=0, elapsed=0.1),
        CmdResult(stdout=(
            "GPS Latitude: 37°46'29.6\" N\n"
            "GPS Longitude: 122°25'9.7\" W\n"
            "Make: Apple\n"
            "Model: iPhone 14 Pro\n"
            "Date: 2026:01:15 14:32:18\n"
        ), stderr="", exit_code=0, elapsed=0.1),
    ]
    tool = ExifToolTool(ssh)
    r = tool.execute("/tmp/Whereami.jpeg")
    assert "GPS" in r
    assert "Apple" in r
    assert "iPhone" in r
    assert "📍" in r  # 高亮 GPS
    assert "📷" in r  # 高亮 相机
    assert "🕐" in r  # 高亮 时间


def test_exiftool_empty_metadata_friendly() -> None:
    """无 EXIF 时友好提示."""
    ssh = make_ssh(available=True)
    ssh.exec_cmd.side_effect = [
        CmdResult(stdout="/usr/bin/exiftool\n", stderr="", exit_code=0, elapsed=0.1),
        CmdResult(stdout="", stderr="", exit_code=0, elapsed=0.1),
    ]
    tool = ExifToolTool(ssh)
    r = tool.execute("/tmp/empty.jpg")
    assert "无元数据" in r or "无" in r


def test_steghide_wrong_password() -> None:
    """密码错误检测."""
    ssh = make_ssh(available=True)
    ssh.exec_cmd.side_effect = [
        CmdResult(stdout="/usr/bin/steghide\n", stderr="", exit_code=0, elapsed=0.1),
        CmdResult(stdout=("steghide: could not extract any data with that passphrase!\n"),
                  stderr="", exit_code=0, elapsed=0.1),
    ]
    tool = SteghideTool(ssh)
    r = tool.execute("/tmp/img.jpg", password="wrong")
    assert "密码错误" in r


def test_steghide_success_extract() -> None:
    """成功提取."""
    ssh = make_ssh(available=True)
    ssh.exec_cmd.side_effect = [
        # 1. which steghide
        CmdResult(stdout="/usr/bin/steghide\n", stderr="", exit_code=0, elapsed=0.1),
        # 2. steghide extract 成功
        CmdResult(stdout='wrote extracted data to "/tmp/steghide_extracted_1234.bin".\n',
                  stderr="", exit_code=0, elapsed=0.1),
        # 3. file + head 提取
        CmdResult(stdout="/tmp/steghide_extracted_1234.bin: ASCII text\nathena{secret_flag}\n",
                  stderr="", exit_code=0, elapsed=0.1),
    ]
    tool = SteghideTool(ssh)
    r = tool.execute("/tmp/img.jpg", password="")
    assert "✅" in r
    assert "athena{secret_flag}" in r


def test_binwalk_scan() -> None:
    """扫描路径."""
    ssh = make_ssh(available=True)
    ssh.exec_cmd.side_effect = [
        CmdResult(stdout="/usr/bin/binwalk\n", stderr="", exit_code=0, elapsed=0.1),
        CmdResult(stdout=(
            "DECIMAL  HEXADECIMAL  DESCRIPTION\n"
            "0        0x0          PNG image, 200 x 200, 8-bit/color RGBA\n"
            "1024     0x400        Zip archive data, at least v2.0\n"
        ), stderr="", exit_code=0, elapsed=0.1),
    ]
    tool = BinwalkTool(ssh)
    r = tool.execute("/tmp/firmware.bin", extract=False)
    assert "PNG" in r or "Zip" in r


def test_tshark_parse_pcap() -> None:
    """pcap 解析路径."""
    ssh = make_ssh(available=True)
    ssh.exec_cmd.side_effect = [
        CmdResult(stdout="/usr/bin/tshark\n", stderr="", exit_code=0, elapsed=0.1),
        CmdResult(stdout=(
            "1   0.000000  192.168.1.1 -> 192.168.1.2  HTTP 200 GET /secret.html\n"
            "2   0.001000  192.168.1.2 -> 192.168.1.1  HTTP 200 OK (text/html)\n"
        ), stderr="", exit_code=0, elapsed=0.1),
    ]
    tool = TsharkTool(ssh)
    r = tool.execute("/tmp/cap.pcap", display_filter="http", max_packets=10)
    assert "HTTP" in r or "GET" in r


def test_tshark_unavailable_degradation() -> None:
    """tshark 工具未装时降级."""
    ssh = make_ssh(available=False, stdout="not found")
    tool = TsharkTool(ssh)
    r = tool.execute("/tmp/cap.pcap")
    assert "ERROR" in r


def test_empty_filepath_rejected() -> None:
    """空 file_path 被 4 个工具拒绝."""
    ssh = make_ssh(available=True)
    for ToolCls in [ExifToolTool, SteghideTool, BinwalkTool, TsharkTool]:
        tool = ToolCls(ssh)
        r = tool.execute("")
        assert "不能为空" in r


def test_factory_returns_4_tools_in_order() -> None:
    """工厂函数返回 4 个工具,按顺序."""
    tools = osint_tools(make_ssh())
    assert len(tools) == 4
    names = [t.name for t in tools]
    assert names == ["exiftool", "steghide", "binwalk", "tshark"]


def test_default_tools_include_osint_when_ssh_provided() -> None:
    """default_tools(ssh_client) 包含 osint_tools (Sprint 11)."""
    from ctf_agent.tools import default_tools
    tools = default_tools(ssh_client=make_ssh())
    names = {t.name for t in tools}
    assert "exiftool" in names
    assert "steghide" in names
    assert "binwalk" in names
    assert "tshark" in names


def test_default_tools_can_disable_osint() -> None:
    """enable_osint=False 时不注册 osint_tools."""
    from ctf_agent.tools import default_tools
    tools = default_tools(ssh_client=make_ssh(), enable_osint=False)
    names = {t.name for t in tools}
    assert "exiftool" not in names
    assert "steghide" not in names
