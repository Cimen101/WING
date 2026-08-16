"""L2 SSH 工具测试（Sprint 5.2）.

测试分层：
1. 单元测试（mock SSHClient）—— 验证 SSHExecTool/SSHPythonTool/SSHFileUploadTool 逻辑
2. 真实 SSH 测试（RUN_REAL_SSH=1 触发）—— 端到端验证
3. default_tools 集成测试 —— 验证 ssh_client 传入时自动添加 SSH 工具
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from ctf_agent.ssh import CmdResult, SSHClient
from ctf_agent.tools import SSHExecTool, SSHFileUploadTool, SSHPythonTool, default_tools, ssh_tools


REAL_SSH = os.environ.get("RUN_REAL_SSH", "") == "1"


# ============ mock 辅助 ============

def _mock_ssh_client(
    *,
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    elapsed: float = 0.1,
) -> MagicMock:
    """创建 mock SSHClient，exec_cmd 返回指定结果."""
    client = MagicMock(spec=SSHClient)
    client.exec_cmd.return_value = CmdResult(
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        cmd="mock",
        elapsed=elapsed,
    )
    return client


# ============ SSHExecTool 单元测试 ============

def test_ssh_exec_tool_basic_execution() -> None:
    client = _mock_ssh_client(stdout="root\n", exit_code=0)
    tool = SSHExecTool(client)
    result = tool.execute(command="whoami")

    assert "root" in result
    assert "exit_code=0" in result
    assert "$ whoami" in result
    client.exec_cmd.assert_called_once()


def test_ssh_exec_tool_empty_command_returns_error() -> None:
    client = _mock_ssh_client()
    tool = SSHExecTool(client)
    result = tool.execute(command="")
    assert "ERROR" in result
    assert "不能为空" in result
    client.exec_cmd.assert_not_called()


def test_ssh_exec_tool_includes_stderr_in_output() -> None:
    client = _mock_ssh_client(stdout="out", stderr="warn", exit_code=0)
    tool = SSHExecTool(client)
    result = tool.execute(command="ls")
    assert "out" in result
    assert "[stderr]" in result
    assert "warn" in result


def test_ssh_exec_tool_nonzero_exit_marks_error() -> None:
    client = _mock_ssh_client(stdout="", stderr="not found", exit_code=1)
    tool = SSHExecTool(client)
    result = tool.execute(command="nonexistent_cmd")
    assert "ERROR" in result
    assert "退出码 1" in result


def test_ssh_exec_tool_no_output_returns_hint() -> None:
    client = _mock_ssh_client(stdout="", stderr="", exit_code=0)
    tool = SSHExecTool(client)
    result = tool.execute(command="true")
    assert "无输出" in result


def test_ssh_exec_tool_uses_default_cwd() -> None:
    client = _mock_ssh_client(stdout="ok")
    tool = SSHExecTool(client, default_cwd="/tmp/ctf_workspace/")
    tool.execute(command="ls")

    call_args = client.exec_cmd.call_args
    assert call_args.kwargs.get("cwd") == "/tmp/ctf_workspace/"


def test_ssh_exec_tool_custom_cwd_overrides_default() -> None:
    client = _mock_ssh_client(stdout="ok")
    tool = SSHExecTool(client, default_cwd="/tmp/ctf_workspace/")
    tool.execute(command="ls", cwd="/tmp/ctf_real2/")

    call_args = client.exec_cmd.call_args
    assert call_args.kwargs.get("cwd") == "/tmp/ctf_real2/"


def test_ssh_exec_tool_timeout_capped_at_max() -> None:
    client = _mock_ssh_client(stdout="ok")
    tool = SSHExecTool(client, default_timeout=60, max_timeout=600)
    # 传入超过 max_timeout 的值应被截断为 600（wait_sec），
    # 客户端 exec_cmd 超时 = wait_sec + 40s 轮询缓冲（_BG_CLIENT_BUFFER）
    tool.execute(command="ls", timeout=99999)

    call_args = client.exec_cmd.call_args
    assert call_args.kwargs.get("timeout") == 640


def test_ssh_exec_tool_truncates_long_output() -> None:
    long_output = "x" * 20000
    client = _mock_ssh_client(stdout=long_output)
    tool = SSHExecTool(client)
    result = tool.execute(command="cat big_file")

    assert "截断" in result
    assert "20000" in result
    # 截断后长度应小于原始
    assert len(result) < 20000 + 1000  # 加上其他文本的余量


def test_ssh_exec_tool_via_call_with_json() -> None:
    client = _mock_ssh_client(stdout="root\n")
    tool = SSHExecTool(client)
    tool_result = tool('{"command": "whoami"}')
    assert tool_result.is_error is False
    assert "root" in tool_result.output


def test_ssh_exec_tool_via_call_with_invalid_json() -> None:
    client = _mock_ssh_client()
    tool = SSHExecTool(client)
    tool_result = tool('not json')
    assert tool_result.is_error is True
    assert "ERROR" in tool_result.output


# ============ SSHPythonTool 单元测试 ============

def test_ssh_python_tool_basic_execution() -> None:
    client = _mock_ssh_client(stdout="42\n", exit_code=0)
    tool = SSHPythonTool(client)
    result = tool.execute(script="print(6 * 7)")

    assert "42" in result
    assert "python3 执行" in result
    client.exec_cmd.assert_called_once()
    # 验证命令包含 base64 解码
    call_args = client.exec_cmd.call_args
    cmd = call_args.args[0] if call_args.args else call_args[0][0]
    assert "base64" in cmd
    assert "python3" in cmd


def test_ssh_python_tool_empty_script_returns_error() -> None:
    client = _mock_ssh_client()
    tool = SSHPythonTool(client)
    result = tool.execute(script="")
    assert "ERROR" in result
    assert "不能为空" in result
    client.exec_cmd.assert_not_called()


def test_ssh_python_tool_includes_stderr() -> None:
    client = _mock_ssh_client(stdout="", stderr="DeprecationWarning", exit_code=0)
    tool = SSHPythonTool(client)
    result = tool.execute(script="import warnings")
    assert "[stderr]" in result
    assert "DeprecationWarning" in result


def test_ssh_python_tool_nonzero_exit_marks_error() -> None:
    client = _mock_ssh_client(stdout="", stderr="SyntaxError", exit_code=1)
    tool = SSHPythonTool(client)
    result = tool.execute(script="invalid syntax !!!")
    assert "ERROR" in result
    assert "退出码 1" in result


def test_ssh_python_tool_sets_term_env() -> None:
    """应设置 TERM=xterm 避免 pwntools curses 警告."""
    client = _mock_ssh_client(stdout="ok")
    tool = SSHPythonTool(client)
    tool.execute(script="print('hi')")

    call_args = client.exec_cmd.call_args
    env = call_args.kwargs.get("env", {})
    assert env.get("TERM") == "xterm"


def test_ssh_python_tool_via_call_with_json() -> None:
    client = _mock_ssh_client(stdout="hello\n")
    tool = SSHPythonTool(client)
    result = tool('{"script": "print(\'hello\')"}')
    assert result.is_error is False
    assert "hello" in result.output


# ============ SSHFileUploadTool 单元测试 ============

def test_ssh_upload_tool_success() -> None:
    client = _mock_ssh_client(stdout="-rwxr-xr-x 1 root root 100 Jan 1 file.elf\nfile.elf: ELF 64-bit", exit_code=0)
    tool = SSHFileUploadTool(client)
    result = tool.execute(local_path="/tmp/local.bin", remote_path="/tmp/remote.bin")

    client.upload_file.assert_called_once_with("/tmp/local.bin", "/tmp/remote.bin")
    assert "上传成功" in result
    assert "ELF" in result


def test_ssh_upload_tool_local_file_not_found() -> None:
    client = MagicMock(spec=SSHClient)
    client.upload_file.side_effect = FileNotFoundError("local file missing")
    tool = SSHFileUploadTool(client)
    result = tool.execute(local_path="/nonexistent", remote_path="/tmp/x")

    assert "ERROR" in result
    assert "本地文件不存在" in result


def test_ssh_upload_tool_upload_failure() -> None:
    client = MagicMock(spec=SSHClient)
    client.upload_file.side_effect = OSError("permission denied")
    tool = SSHFileUploadTool(client)
    result = tool.execute(local_path="/tmp/x", remote_path="/tmp/y")

    assert "ERROR" in result
    assert "上传失败" in result
    assert "permission denied" in result


# ============ ssh_tools 工厂测试 ============

def test_ssh_tools_factory_returns_three_tools() -> None:
    client = _mock_ssh_client()
    tools = ssh_tools(client)
    assert len(tools) == 3
    names = {t.name for t in tools}
    assert names == {"ssh_exec", "ssh_python", "ssh_upload"}


def test_ssh_tools_factory_custom_cwd() -> None:
    client = _mock_ssh_client()
    tools = ssh_tools(client, default_cwd="/custom/", default_timeout=120)
    ssh_exec = next(t for t in tools if t.name == "ssh_exec")
    assert ssh_exec.default_cwd == "/custom/"
    assert ssh_exec.default_timeout == 120


# ============ default_tools 集成测试 ============

def test_default_tools_without_ssh_client_has_no_ssh_tools() -> None:
    tools = default_tools()
    names = {t.name for t in tools}
    assert "ssh_exec" not in names
    assert "ssh_python" not in names
    assert "ssh_upload" not in names


def test_default_tools_with_ssh_client_includes_ssh_tools() -> None:
    client = _mock_ssh_client()
    tools = default_tools(ssh_client=client)
    names = {t.name for t in tools}
    assert "ssh_exec" in names
    assert "ssh_python" in names
    assert "ssh_upload" in names
    # 原有内置工具仍存在
    assert "base64_encode" in names
    assert "http_request" in names
    assert "caesar_cipher" in names


def test_default_tools_with_ssh_client_has_31_tools() -> None:
    """Sprint 14 P2 后工具集扩充至 53 个（2026-08 实测）.

    Sprint 14 P2: 33 → 35 (新增 lfi_log_inject + lfi_scanner)
    Sprint 15+: 陆续新增 multi_encode / php_filter_chain / url_partial_encode /
      vision_analyze / web_dirscan / web_fingerprint / web_sqli / range_control /
      pwn_checksec / pwn_cyclic / pwn_ropgadget / tshark / sqlmap 等
    """
    client = _mock_ssh_client()
    tools = default_tools(ssh_client=client)
    assert len(tools) == 53


def test_osint_tools_registered() -> None:
    """Sprint 11: 验证 osint_tools 全部注册."""
    client = _mock_ssh_client()
    tools = default_tools(ssh_client=client)
    names = {t.name for t in tools}
    assert "exiftool" in names
    assert "steghide" in names
    assert "binwalk" in names
    assert "tshark" in names


# ============ 真实 SSH 工具测试 ============

@pytest.mark.skipif(not REAL_SSH, reason="需要 RUN_REAL_SSH=1 环境变量触发")
def test_real_ssh_exec_tool_whoami() -> None:
    """真实 SSH：ssh_exec 工具执行 whoami."""
    from ctf_agent.config import get_settings
    from ctf_agent.ssh import ssh_client_from_settings

    settings = get_settings()
    client = ssh_client_from_settings(settings)
    client.connect()
    try:
        tool = SSHExecTool(client)
        result = tool.execute(command="whoami")
        print(f"\n[ssh_exec whoami] {result}")
        assert "root" in result
        assert "exit_code=0" in result
    finally:
        client.close()


@pytest.mark.skipif(not REAL_SSH, reason="需要 RUN_REAL_SSH=1 环境变量触发")
def test_real_ssh_exec_tool_nmap_version() -> None:
    """真实 SSH：ssh_exec 工具执行 nmap --version."""
    from ctf_agent.config import get_settings
    from ctf_agent.ssh import ssh_client_from_settings

    settings = get_settings()
    client = ssh_client_from_settings(settings)
    client.connect()
    try:
        tool = SSHExecTool(client)
        result = tool.execute(command="nmap --version")
        print(f"\n[ssh_exec nmap --version] {result[:200]}")
        assert "Nmap" in result or "nmap" in result
    finally:
        client.close()


@pytest.mark.skipif(not REAL_SSH, reason="需要 RUN_REAL_SSH=1 环境变量触发")
def test_real_ssh_python_tool_simple_calc() -> None:
    """真实 SSH：ssh_python 工具执行简单 Python 脚本."""
    from ctf_agent.config import get_settings
    from ctf_agent.ssh import ssh_client_from_settings

    settings = get_settings()
    client = ssh_client_from_settings(settings)
    client.connect()
    try:
        tool = SSHPythonTool(client)
        result = tool.execute(script="print(6 * 7)")
        print(f"\n[ssh_python 6*7] {result}")
        assert "42" in result
    finally:
        client.close()


@pytest.mark.skipif(not REAL_SSH, reason="需要 RUN_REAL_SSH=1 环境变量触发")
def test_real_ssh_python_tool_pycryptodome() -> None:
    """真实 SSH：ssh_python 工具调用 pycryptodome 计算 MD5."""
    from ctf_agent.config import get_settings
    from ctf_agent.ssh import ssh_client_from_settings

    settings = get_settings()
    client = ssh_client_from_settings(settings)
    client.connect()
    try:
        tool = SSHPythonTool(client)
        script = (
            "from Crypto.Hash import MD5\n"
            "h = MD5.new(b'hello')\n"
            "print(h.hexdigest())\n"
        )
        result = tool.execute(script=script)
        print(f"\n[ssh_python MD5(hello)] {result}")
        assert "5d41402abc4b2a76b9719d911017c592" in result
    finally:
        client.close()


@pytest.mark.skipif(not REAL_SSH, reason="需要 RUN_REAL_SSH=1 环境变量触发")
def test_real_ssh_python_tool_pwntools() -> None:
    """真实 SSH：ssh_python 工具调用 pwntools."""
    from ctf_agent.config import get_settings
    from ctf_agent.ssh import ssh_client_from_settings

    settings = get_settings()
    client = ssh_client_from_settings(settings)
    client.connect()
    try:
        tool = SSHPythonTool(client)
        script = (
            "import pwn\n"
            "print('pwntools loaded:', pwn.__file__[:30])\n"
        )
        result = tool.execute(script=script, timeout=30)
        print(f"\n[ssh_python pwntools] {result}")
        assert "pwntools loaded" in result
    finally:
        client.close()


@pytest.mark.skipif(not REAL_SSH, reason="需要 RUN_REAL_SSH=1 环境变量触发")
def test_real_ssh_upload_and_strings() -> None:
    """真实 SSH：上传文件 + ssh_exec strings 提取."""
    import tempfile
    from pathlib import Path
    from ctf_agent.config import get_settings
    from ctf_agent.ssh import ssh_client_from_settings

    settings = get_settings()
    client = ssh_client_from_settings(settings)
    client.connect()
    try:
        # 创建本地测试文件（含 flag 字符串的二进制数据）
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".bin", delete=False
        ) as f:
            f.write(b"\x00\x01flag{ssh_strings_test}\x02\x03")
            local_file = f.name

        try:
            remote_file = "/tmp/ctf_workspace/test_upload.bin"
            upload_tool = SSHFileUploadTool(client)
            upload_result = upload_tool.execute(
                local_path=local_file, remote_path=remote_file
            )
            print(f"\n[ssh_upload] {upload_result[:200]}")
            assert "上传成功" in upload_result

            # 用 ssh_exec 执行 strings 提取
            exec_tool = SSHExecTool(client)
            strings_result = exec_tool.execute(
                command=f"strings {remote_file}"
            )
            print(f"[ssh_exec strings] {strings_result}")
            assert "flag{ssh_strings_test}" in strings_result

            # 清理
            client.exec_cmd(f"rm -f {remote_file}")
        finally:
            os.remove(local_file)
    finally:
        client.close()
