"""Sprint 7 P0-2 修复测试：SSHExecTool docker 降级检测.

测试目标：
1. docker build 失败（含 'command not found' / 'Cannot connect'）→ 注入降级建议
2. 普通命令失败（exit != 0）但不是 docker/网络问题 → 不注入降级建议
3. 命令成功（exit == 0）→ 不注入降级建议
4. connection refused 1337 → 注入"服务未启动"建议
5. redis-cli / mysql 缺失 → 注入"用 python3 替代"建议
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from ctf_agent.ssh import CmdResult, SSHClient
from ctf_agent.tools.ssh_tool import SSHExecTool, _detect_env_degradation


def _mock_ssh_client(
    *, stdout: str = "", stderr: str = "", exit_code: int = 0
) -> MagicMock:
    client = MagicMock(spec=SSHClient)
    client.exec_cmd.return_value = CmdResult(
        stdout=stdout, stderr=stderr, exit_code=exit_code, cmd="mock", elapsed=0.1
    )
    return client


# ============ _detect_env_degradation 单元测试 ============

def test_detect_docker_not_found():
    """docker: command not found → 降级建议."""
    hint = _detect_env_degradation(
        command="docker build -t test .",
        stdout="",
        stderr="/bin/sh: docker: not found",
        exit_code=127,
    )
    assert hint is not None
    assert "docker" in hint.lower()
    assert "静态分析" in hint or "源码" in hint


def test_detect_docker_daemon_not_running():
    """Cannot connect to the Docker daemon → 降级建议."""
    hint = _detect_env_degradation(
        command="docker ps",
        stdout="",
        stderr="Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
        exit_code=1,
    )
    assert hint is not None
    assert "Docker daemon" in hint or "docker" in hint.lower()


def test_detect_connection_refused_1337():
    """connection refused 端口 1337 → 服务未启动建议."""
    hint = _detect_env_degradation(
        command="nc localhost 1337",
        stdout="",
        stderr="nc: connect to localhost port 1337 (tcp) failed: Connection refused",
        exit_code=1,
    )
    assert hint is not None
    assert "1337" in hint or "服务" in hint or "未启动" in hint


def test_detect_redis_cli_missing():
    """redis-cli not found → 建议用 python3 替代."""
    hint = _detect_env_degradation(
        command="redis-cli -h localhost PING",
        stdout="",
        stderr="bash: redis-cli: command not found",
        exit_code=127,
    )
    assert hint is not None
    assert "redis" in hint.lower() or "python3" in hint


def test_no_hint_for_unrelated_error():
    """普通命令错误（不匹配模式）→ 不注入降级建议."""
    hint = _detect_env_degradation(
        command="cat /nonexistent",
        stdout="",
        stderr="cat: /nonexistent: No such file or directory",
        exit_code=1,
    )
    assert hint is None


def test_no_hint_on_success():
    """命令成功 → 不注入降级建议."""
    hint = _detect_env_degradation(
        command="echo hello",
        stdout="hello\n",
        stderr="",
        exit_code=0,
    )
    assert hint is None


def test_no_hint_for_normal_python_error():
    """Python 脚本错误（非 docker/网络）→ 不注入降级建议."""
    hint = _detect_env_degradation(
        command="python3 -c 'print(undefined)'",
        stdout="",
        stderr="Traceback (most recent call last):\nNameError: name 'undefined' is not defined",
        exit_code=1,
    )
    assert hint is None


# ============ SSHExecTool 集成测试 ============

def test_ssh_exec_docker_not_found_returns_hint():
    """docker build 失败 → SSHExecTool 输出含降级建议."""
    client = _mock_ssh_client(
        stdout="",
        stderr="/bin/sh: docker: not found",
        exit_code=127,
    )
    tool = SSHExecTool(client)
    result = tool.execute(command="docker build -t test .")
    assert "降级" in result or "静态分析" in result
    assert "docker" in result.lower()


def test_ssh_exec_normal_error_no_hint():
    """普通命令失败 → SSHExecTool 输出不含降级建议."""
    client = _mock_ssh_client(
        stdout="",
        stderr="cat: /x: No such file or directory",
        exit_code=1,
    )
    tool = SSHExecTool(client)
    result = tool.execute(command="cat /x")
    assert "降级" not in result
    assert "静态分析" not in result


def test_ssh_exec_success_no_hint():
    """成功命令 → 输出不含降级建议."""
    client = _mock_ssh_client(stdout="hello", exit_code=0)
    tool = SSHExecTool(client)
    result = tool.execute(command="echo hello")
    assert "降级" not in result
    assert "hello" in result


def test_ssh_exec_connection_refused_1337_hint():
    """curl 1337 connection refused → 提示服务未启动."""
    client = _mock_ssh_client(
        stdout="",
        stderr="curl: (7) Failed to connect to localhost port 1337: Connection refused",
        exit_code=7,
    )
    tool = SSHExecTool(client)
    result = tool.execute(command="curl http://localhost:1337/")
    assert "降级" in result or "未启动" in result or "1337" in result


def test_ssh_exec_safe_command_does_not_get_hint():
    """成功执行的 docker 命令（如有 docker）→ 不注入降级建议."""
    client = _mock_ssh_client(stdout="CONTAINER ID  IMAGE", exit_code=0)
    tool = SSHExecTool(client)
    result = tool.execute(command="docker ps")
    assert "降级" not in result
