"""SSH 沙箱连接器测试（Sprint 5.1）.

测试分层：
1. 单元测试（mock paramiko）—— 验证 SSHClient 逻辑，无真实连接
2. 真实 SSH 测试（RUN_REAL_SSH=1 触发）—— 连接 192.168.85.140 验证端到端

阶段一验收标准：Windows 端 Python 脚本成功在 Kali 内执行 whoami 并返回 root
"""

from __future__ import annotations

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from ctf_agent.ssh import CmdResult, SSHClient, ssh_client_from_settings


# ============ 是否运行真实 SSH 测试 ============
REAL_SSH = os.environ.get("RUN_REAL_SSH", "") == "1"


# ============ CmdResult 单元测试 ============

def test_cmd_result_success_property() -> None:
    r = CmdResult(stdout="ok\n", stderr="", exit_code=0, cmd="whoami")
    assert r.is_success is True


def test_cmd_result_failure_property() -> None:
    r = CmdResult(stdout="", stderr="error", exit_code=1, cmd="bad_cmd")
    assert r.is_success is False


def test_cmd_result_output_merges_stderr() -> None:
    r = CmdResult(stdout="out", stderr="err", exit_code=0)
    assert "out" in r.output
    assert "err" in r.output
    assert "[stderr]" in r.output


def test_cmd_result_output_no_stderr() -> None:
    r = CmdResult(stdout="out", stderr="", exit_code=0)
    assert r.output == "out"
    assert "[stderr]" not in r.output


def test_cmd_result_str_format() -> None:
    r = CmdResult(stdout="root\n", stderr="", exit_code=0, cmd="whoami", elapsed=0.1)
    s = str(r)
    assert "$ whoami" in s
    assert "exit=0" in s
    assert "root" in s


# ============ SSHClient 单元测试（mock paramiko） ============

def test_ssh_client_init_defaults() -> None:
    c = SSHClient(host="1.2.3.4", user="root", password="pass")
    assert c.host == "1.2.3.4"
    assert c.user == "root"
    assert c.password == "pass"
    assert c.port == 22
    assert c.is_connected is False


def test_ssh_client_init_with_key_path() -> None:
    c = SSHClient(host="1.2.3.4", user="root", key_path="/tmp/key")
    assert c.key_path == "/tmp/key"
    assert c.password is None


def test_ssh_client_requires_auth() -> None:
    """无 password 且无 key_path 应报错."""
    c = SSHClient(host="1.2.3.4", user="root")
    with pytest.raises(ValueError, match="password 或 key_path"):
        c.connect()


def test_ssh_client_connect_calls_paramiko() -> None:
    """connect 应调用 paramiko.SSHClient.connect."""
    with patch("ctf_agent.ssh.client.paramiko.SSHClient") as MockSSH:
        mock_instance = MockSSH.return_value
        mock_transport = MagicMock()
        mock_instance.get_transport.return_value = mock_transport
        mock_transport.is_active.return_value = True

        c = SSHClient(host="1.2.3.4", user="root", password="pass")
        c.connect()

        MockSSH.assert_called_once()
        mock_instance.set_missing_host_key_policy.assert_called_once()
        mock_instance.connect.assert_called_once()
        mock_transport.set_keepalive.assert_called_once_with(30)
        assert c.is_connected is True


def test_ssh_client_connect_idempotent() -> None:
    """重复调用 connect 不应重连."""
    with patch("ctf_agent.ssh.client.paramiko.SSHClient") as MockSSH:
        mock_instance = MockSSH.return_value
        mock_transport = MagicMock()
        mock_instance.get_transport.return_value = mock_transport
        mock_transport.is_active.return_value = True

        c = SSHClient(host="1.2.3.4", user="root", password="pass")
        c.connect()
        c.connect()  # 第二次应无操作
        assert mock_instance.connect.call_count == 1


def test_ssh_client_close_resets_state() -> None:
    with patch("ctf_agent.ssh.client.paramiko.SSHClient") as MockSSH:
        mock_instance = MockSSH.return_value
        mock_transport = MagicMock()
        mock_instance.get_transport.return_value = mock_transport
        mock_transport.is_active.return_value = True

        c = SSHClient(host="1.2.3.4", user="root", password="pass")
        c.connect()
        c.close()
        assert c.is_connected is False
        mock_instance.close.assert_called_once()


def test_ssh_client_context_manager() -> None:
    with patch("ctf_agent.ssh.client.paramiko.SSHClient") as MockSSH:
        mock_instance = MockSSH.return_value
        mock_transport = MagicMock()
        mock_instance.get_transport.return_value = mock_transport
        mock_transport.is_active.return_value = True

        with SSHClient(host="1.2.3.4", user="root", password="pass") as c:
            assert c.is_connected is True
        # 退出 with 后应关闭
        mock_instance.close.assert_called_once()


def test_exec_cmd_returns_cmd_result() -> None:
    with patch("ctf_agent.ssh.client.paramiko.SSHClient") as MockSSH:
        mock_instance = MockSSH.return_value
        mock_transport = MagicMock()
        mock_instance.get_transport.return_value = mock_transport
        mock_transport.is_active.return_value = True

        # mock exec_command 返回 (stdin, stdout, stderr)
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.read.return_value = b"root\n"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_instance.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        c = SSHClient(host="1.2.3.4", user="root", password="pass")
        c.connect()
        result = c.exec_cmd("whoami")

        assert isinstance(result, CmdResult)
        assert result.stdout == "root\n"
        assert result.exit_code == 0
        assert result.is_success
        assert "whoami" in result.cmd


def test_exec_cmd_with_cwd_and_env() -> None:
    with patch("ctf_agent.ssh.client.paramiko.SSHClient") as MockSSH:
        mock_instance = MockSSH.return_value
        mock_transport = MagicMock()
        mock_instance.get_transport.return_value = mock_transport
        mock_transport.is_active.return_value = True

        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.read.return_value = b""
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_instance.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        c = SSHClient(host="1.2.3.4", user="root", password="pass")
        c.connect()
        c.exec_cmd("ls", cwd="/tmp", env={"FOO": "bar"})

        # 验证传给 exec_command 的命令包含 cd 和 export
        called_cmd = mock_instance.exec_command.call_args[0][0]
        assert "cd /tmp" in called_cmd  # shlex.quote("/tmp") 不加引号
        assert "export FOO=bar" in called_cmd
        assert "ls" in called_cmd


def test_whoami_returns_stripped_stdout() -> None:
    with patch("ctf_agent.ssh.client.paramiko.SSHClient") as MockSSH:
        mock_instance = MockSSH.return_value
        mock_transport = MagicMock()
        mock_instance.get_transport.return_value = mock_transport
        mock_transport.is_active.return_value = True

        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.read.return_value = b"root\n"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_instance.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        c = SSHClient(host="1.2.3.4", user="root", password="pass")
        c.connect()
        assert c.whoami() == "root"


def test_upload_file_local_not_exists_raises() -> None:
    c = SSHClient(host="1.2.3.4", user="root", password="pass")
    with pytest.raises(FileNotFoundError):
        c.upload_file("/nonexistent/file.txt", "/tmp/x.txt")


def test_ssh_client_from_settings_requires_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """配置不完整应报错."""
    from ctf_agent.config import Settings
    # 禁用 .env 加载，避免被真实配置干扰
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    # 字段有 alias，需用大写 alias 作为构造参数名
    settings = Settings(KALI_HOST="", KALI_USER="root", KALI_PASS="x")  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="KALI_HOST"):
        ssh_client_from_settings(settings)


def test_ssh_client_from_settings_requires_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ctf_agent.config import Settings
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    settings = Settings(KALI_HOST="1.2.3.4", KALI_USER="root", KALI_PASS="", KALI_KEY_PATH="")  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="KALI_PASS 或 KALI_KEY_PATH"):
        ssh_client_from_settings(settings)


def test_ssh_client_from_settings_creates_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ctf_agent.config import Settings
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    settings = Settings(KALI_HOST="1.2.3.4", KALI_USER="root", KALI_PASS="secret", KALI_PORT=2222)  # type: ignore[call-arg]
    client = ssh_client_from_settings(settings)
    assert client.host == "1.2.3.4"
    assert client.user == "root"
    assert client.password == "secret"
    assert client.port == 2222


# ============ 真实 SSH 测试（默认 skip） ============

@pytest.mark.skipif(not REAL_SSH, reason="需要 RUN_REAL_SSH=1 环境变量触发")
def test_real_ssh_whoami_returns_root() -> None:
    """阶段一验收：Windows 端 Python 脚本在 Kali 内执行 whoami 返回 root."""
    from ctf_agent.config import get_settings
    settings = get_settings()
    assert settings.has_kali_config(), "需要在 .env 中配置 KALI_HOST/KALI_USER/KALI_PASS"

    client = ssh_client_from_settings(settings)
    client.connect()
    try:
        user = client.whoami()
        print(f"\n[真实 SSH] whoami = {user}")
        assert user == "root", f"期望 root，实际 {user}"
    finally:
        client.close()


@pytest.mark.skipif(not REAL_SSH, reason="需要 RUN_REAL_SSH=1 环境变量触发")
def test_real_ssh_exec_uname() -> None:
    """真实 SSH：执行 uname -a 验证命令执行."""
    from ctf_agent.config import get_settings
    settings = get_settings()
    client = ssh_client_from_settings(settings)
    client.connect()
    try:
        result = client.exec_cmd("uname -a")
        print(f"\n[真实 SSH] uname = {result.stdout.strip()}")
        assert result.is_success
        assert "Linux" in result.stdout
        assert "kali" in result.stdout.lower()
    finally:
        client.close()


@pytest.mark.skipif(not REAL_SSH, reason="需要 RUN_REAL_SSH=1 环境变量触发")
def test_real_ssh_upload_download_file() -> None:
    """真实 SSH：文件上传 + 下载."""
    from ctf_agent.config import get_settings
    settings = get_settings()
    client = ssh_client_from_settings(settings)
    client.connect()
    try:
        # 创建本地测试文件
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as f:
            f.write("test from Windows\nflag{ssh_real_test}\n")
            local_file = f.name

        try:
            remote_file = "/tmp/ctf_agent_test/real_upload_test.txt"
            client.upload_file(local_file, remote_file)

            # 验证远程文件内容
            result = client.exec_cmd(f"cat {remote_file}")
            assert "flag{ssh_real_test}" in result.stdout

            # 下载回本地
            downloaded = local_file + ".dl"
            client.download_file(remote_file, downloaded)
            with open(downloaded, encoding="utf-8") as f:
                content = f.read()
            assert "flag{ssh_real_test}" in content

            # 清理
            client.exec_cmd(f"rm -f {remote_file}")
            os.remove(downloaded)
        finally:
            os.remove(local_file)
    finally:
        client.close()


@pytest.mark.skipif(not REAL_SSH, reason="需要 RUN_REAL_SSH=1 环境变量触发")
def test_real_ssh_ctf_tools_available() -> None:
    """真实 SSH：验证 Kali 上关键 CTF 工具可用."""
    from ctf_agent.config import get_settings
    settings = get_settings()
    client = ssh_client_from_settings(settings)
    client.connect()
    try:
        required_tools = ["nmap", "strings", "file", "xxd", "python3", "objdump"]
        for tool in required_tools:
            result = client.exec_cmd(f"which {tool}")
            assert result.is_success, f"工具 {tool} 不可用"
            print(f"  {tool}: {result.stdout.strip()}")
    finally:
        client.close()


@pytest.mark.skipif(not REAL_SSH, reason="需要 RUN_REAL_SSH=1 环境变量触发")
def test_real_ssh_python_packages() -> None:
    """真实 SSH：验证 Kali Python 包可用."""
    from ctf_agent.config import get_settings
    settings = get_settings()
    client = ssh_client_from_settings(settings)
    client.connect()
    try:
        # pwntools 和 pycryptodome 是 crypto/pwn 题的关键依赖
        # 设置 TERM 避免 curses 警告
        r1 = client.exec_cmd(
            'TERM=xterm python3 -c "import pwn; print(pwn.__file__)"',
            env={"TERM": "xterm"},
        )
        assert r1.is_success, f"pwntools 未安装: {r1.stderr}"
        print(f"  pwntools: {r1.stdout.strip()}")

        r2 = client.exec_cmd('python3 -c "import Crypto; print(Crypto.__version__)"')
        assert r2.is_success, f"pycryptodome 未安装: {r2.stderr}"
        print(f"  pycryptodome: {r2.stdout.strip()}")
    finally:
        client.close()
