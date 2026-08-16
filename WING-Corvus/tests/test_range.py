"""靶场（range）模块测试.

覆盖：
1. flag 安全：随机生成、掩码、格式、verify 不泄露真 flag
2. catalog：14 动态题、端口唯一、容器名合法、静态题 18
3. compose：生成文本含服务/端口/FLAG_FULL
4. manager：deploy 通过 SSH 执行正确 build/run 命令且注入随机 flag；状态受保护
5. safety：审计阻断 docker exec 进靶场容器读 flag
6. tool：range_control 工具只暴露 list/start/stop/status/verify，verify 仅返回 correct/incorrect
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from ctf_agent.range.catalog import (
    DYNAMIC, STATIC, ALL, by_name, container_name, dynamic_challenges,
    local_container_dir,
)
from ctf_agent.range.compose import build_compose_text
from ctf_agent.range.flag import gen_flag, mask, is_valid_flag_format
from ctf_agent.range.manager import RangeManager
from ctf_agent.range.tool import RangeTool, range_tools
from ctf_agent.ssh.client import CmdResult
from ctf_agent.ssh.safety import audit_command


# ============ flag 安全 ============

def test_gen_flag_format_and_random() -> None:
    f1, f2 = gen_flag(), gen_flag()
    assert is_valid_flag_format(f1) and is_valid_flag_format(f2)
    assert f1 != f2  # 随机性
    assert f1.startswith("athena{") and f1.endswith("}")


def test_mask_hides_inner() -> None:
    f = "athena{ABCDEFGH1234567890WXYZ}"
    m = mask(f)
    assert "*" in m
    assert "1234567890" not in m  # 中间被掩码
    assert m.startswith("athena{ABCD")  # 仅首尾可见
    assert m.endswith("WXYZ}")


# ============ catalog ============

def test_dynamic_count_and_unique_ports() -> None:
    assert len(DYNAMIC) == 14
    ports = [c["host_port"] for c in DYNAMIC]
    assert len(ports) == len(set(ports)), "动态题端口必须唯一"
    assert all(1000 < p < 9000 for p in ports)


def test_container_name_legal() -> None:
    for c in DYNAMIC:
        cn = container_name(c)
        assert cn.startswith("athena_")
        assert " " not in cn and "(" not in cn and ")" not in cn


def test_static_count() -> None:
    assert len(STATIC) == 18
    assert len(ALL) == 32


def test_local_container_dir_exists() -> None:
    # 抽查若干动态题的本地 container 目录存在
    for name in ("Echo_Chamber", "Query_Mirage", "Heap_Smash_v1"):
        assert local_container_dir(by_name(name)).is_dir()


# ============ compose ============

def test_compose_text() -> None:
    text = build_compose_text()
    # 容器/服务名统一小写（Docker tag 规范，见 catalog.container_name）
    assert "athena_echo_chamber:" in text
    assert "8001:1337" in text
    assert "FLAG_FULL=${FLAG_FULL}" in text  # 占位，不落明文


# ============ manager（mock SSH） ============

def _mock_ssh() -> MagicMock:
    ssh = MagicMock()
    ssh.exec_cmd.return_value = CmdResult(stdout="", stderr="", exit_code=0, cmd="")
    ssh.upload_directory.return_value = {"files": 1, "bytes": 1, "checksum_ok": True}
    return ssh


def test_manager_deploy_injects_flag_and_stores_state() -> None:
    ssh = _mock_ssh()
    with tempfile.TemporaryDirectory() as d:
        mgr = RangeManager(ssh_client=ssh, state_path=Path(d) / "state.json")
        res = mgr.deploy(name="Echo_Chamber")
        # 验证 run 命令注入随机 flag（掩码前缀）
        run_calls = [c.args[0] for c in ssh.exec_cmd.call_args_list]
        run_cmd = [c for c in run_calls if "docker run -d" in c]
        assert run_cmd, "应执行 docker run"
        assert "-e FLAG_FULL='athena{" in run_cmd[0]
        # 状态文件存在且权限受限，含 flag 明文（仅供 verify）
        assert res["Echo_Chamber"]["ok"] is True
        state = json.loads((Path(d) / "state.json").read_text(encoding="utf-8"))
        cname = container_name(by_name("Echo_Chamber"))
        real_flag = state[cname]["flag"]
        assert is_valid_flag_format(real_flag)
        # verify 逻辑
        assert mgr.verify("Echo_Chamber", real_flag) is True
        assert mgr.verify("Echo_Chamber", "athena{wrong}") is False
        # status 返回掩码，不泄露明文
        ssh.exec_cmd.return_value = CmdResult(
            stdout=f"{cname}\tUp 1 second\t0.0.0.0:8001->1337/tcp", stderr="", exit_code=0, cmd=""
        )
        st = mgr.status()
        assert st and st[0]["flag_masked"] and "*" in st[0]["flag_masked"]


def test_manager_deploy_unknown_static_rejected() -> None:
    ssh = _mock_ssh()
    with tempfile.TemporaryDirectory() as d:
        mgr = RangeManager(ssh_client=ssh, state_path=Path(d) / "state.json")
        try:
            mgr.deploy(name="Cipher_Chorus")  # 静态题
            raise AssertionError("静态题不应可部署")
        except ValueError:
            pass


# ============ safety 审计 ============

def test_audit_blocks_docker_exec_into_range() -> None:
    assert not audit_command("docker exec athena_echo cat flag.txt").allowed
    assert not audit_command("docker exec athena_Echo_Chamber cat /app/flag.txt").allowed
    assert not audit_command("docker logs athena_Query_Mirage").allowed
    assert not audit_command("docker inspect athena_Heap_Smash_v1").allowed
    assert not audit_command("docker exec webserver cat flag").allowed


def test_audit_allows_normal_ops() -> None:
    assert audit_command("docker ps -a").allowed
    assert audit_command("docker build -t x .").allowed
    assert audit_command("ls /tmp/ctf_workspace").allowed


# ============ tool ============

def test_range_tool_factory() -> None:
    tools = range_tools()
    assert len(tools) == 1
    assert tools[0].name == "range_control"


def test_range_tool_verify_only_returns_bool() -> None:
    # 用 fake manager 验证工具不泄露真 flag
    fake = MagicMock()
    real = "athena{SECRETBUTVALID12345678}"
    fake.verify.side_effect = lambda n, f: f == real
    fake.catalog_view.return_value = [{"name": "Echo_Chamber", "dynamic": True}]
    fake.status.return_value = []
    tool = RangeTool(manager=fake)
    assert tool.execute("verify", name="Echo_Chamber", flag=real) == "correct"
    assert tool.execute("verify", name="Echo_Chamber", flag="athena{wrong}") == "incorrect"
    # 工具不应暴露读取真 flag 的接口
    assert not hasattr(tool, "read_flag")
    assert "athena{" not in tool.execute("list")
