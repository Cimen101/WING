"""Docker 工具链测试套件（Step 0 基线冻结新增）.

覆盖（当前已实现行为，随升级步骤逐步扩展）：
1. DockerExecTool/DockerPythonTool 后台路径（B+ bg 标记解析、输出格式、错误处理）
2. DockerClient.exec_cmd 集成（mock subprocess.run：info/ps/exec 分发）
3. DockerClient.is_available 缓存语义
4. docker_tools 工厂降级（docker 不可用 → 空列表 → default_tools 自动降级 ssh）
5. DockerFileUploadTool / upload_file / download_file
6. S1 快路径（默认/quick/短等待直连 exec）+ S2 去 ps 探测 + 容器消失自愈
7. S3 资源调控（Profile 配额 / 并发度模型 / ContainerScheduler / run flags）

后续 Step 3-5（多容器生命周期）对应测试在本文件追加。
"""

from __future__ import annotations

import subprocess
import time
from unittest.mock import MagicMock, patch

import pytest

from ctf_agent.ssh import CmdResult
from ctf_agent.tools.docker_tool import (
    CliBackend,
    ContainerScheduler,
    DockerBackend,
    DockerClient,
    DockerExecTool,
    DockerFileUploadTool,
    DockerPythonTool,
    ENABLE_TASK_RESET,
    SdkBackend,
    _parse_exec_args,
    _parse_run_flags,
    _sanitize_name,
    compute_max_containers,
    docker_tools,
    make_backend,
    resolve_quota,
)


# ============ mock 辅助 ============

def _mock_client(
    *,
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    elapsed: float = 0.5,
) -> MagicMock:
    """创建 mock DockerClient，exec_cmd 返回指定结果."""
    client = MagicMock(spec=DockerClient)
    client.exec_cmd.return_value = CmdResult(
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        cmd="mock",
        elapsed=elapsed,
    )
    client.workdir = "/challenge"
    return client


def _mock_subprocess(docker_ok: bool = True, exec_stdout: str = "", exec_rc: int = 0):
    """mock subprocess.run：按 argv 分发 info/ps/exec/cp.

    Returns:
        (mock_run, 记录的 exec 命令列表)
    """
    exec_calls: list[list[str]] = []

    def _fake_run(args, *a, **kw):
        args = list(args)
        if len(args) >= 2 and args[0] == "docker":
            if args[1] == "info":
                return MagicMock(returncode=0 if docker_ok else 1, stdout="25.0\n", stderr="")
            if args[1] == "ps":
                return MagicMock(returncode=0, stdout="wing-goose-worker\n", stderr="")
            if args[1] == "exec":
                exec_calls.append(args)
                return MagicMock(returncode=exec_rc, stdout=exec_stdout, stderr="")
            if args[1] == "cp":
                return MagicMock(returncode=0, stdout="", stderr="")
        if args[0] == "docker" and args[1] == "run":
            return MagicMock(returncode=0, stdout="", stderr="")
        if args[0] == "docker" and args[1] == "start":
            return MagicMock(returncode=0, stdout="", stderr="")
        raise AssertionError(f"unexpected argv: {args}")

    mock_run = MagicMock(side_effect=_fake_run)
    return mock_run, exec_calls


# ============ DockerExecTool 后台路径（long/normal/大整数 → B+） ============

def test_docker_exec_tool_bg_finished_output_format() -> None:
    """后台完成路径：输出含命令、完成标记、日志内容."""
    client = _mock_client(stdout="[BG_FINISHED] rc=0\nhello world\n", elapsed=2.1)
    tool = DockerExecTool(client)
    result = tool.execute(command="echo hello world", timeout="long")

    assert "$ echo hello world" in result
    assert "[完成, 同步等待" in result
    assert "elapsed=2.10s" in result
    assert "hello world" in result


def test_docker_exec_tool_bg_running_marks_background() -> None:
    """超时转后台路径：输出 BG_STILL_RUNNING 标记与日志路径提示."""
    client = _mock_client(stdout="[BG_STILL_RUNNING] pid=123\n[BG_LOG=/tmp/ctf_workspace/.bg/x.log]\n[BG_TAIL]:\npart\n")
    tool = DockerExecTool(client)
    result = tool.execute(command="sleep 300", timeout="long")

    assert "已转入后台运行" in result
    assert "pid=123" in result
    assert "/tmp/ctf_workspace/.bg/x.log" in result
    assert "part" in result


def test_docker_exec_tool_empty_command_returns_error() -> None:
    client = _mock_client()
    tool = DockerExecTool(client)
    result = tool.execute(command="")
    assert "ERROR" in result
    assert "不能为空" in result
    client.exec_cmd.assert_not_called()


def test_docker_exec_tool_bg_for_long_band() -> None:
    """long 档位走 B+ 后台路径（脚本含 nohup/base64 轮询）."""
    client = _mock_client(stdout="[BG_FINISHED] rc=0\nout\n")
    tool = DockerExecTool(client, default_timeout=60)
    tool.execute(command="ls", timeout="long")
    script = client.exec_cmd.call_args.args[0]
    assert "nohup" in script
    assert "base64 -d" in script


def test_docker_exec_tool_bg_for_large_int() -> None:
    """大整数 timeout (300) 走 B+ 后台路径."""
    client = _mock_client(stdout="[BG_FINISHED] rc=0\nout\n")
    tool = DockerExecTool(client)
    tool.execute(command="ls", timeout=300)
    script = client.exec_cmd.call_args.args[0]
    assert "nohup" in script


def test_docker_exec_tool_upload_script_payload_base64() -> None:
    """后台路径命令经 base64 传输，避免引号转义."""
    client = _mock_client(stdout="[BG_FINISHED] rc=0\nok\n")
    tool = DockerExecTool(client)
    tool.execute(command="echo 'a b'; cat /etc/os-release", timeout="long")
    script = client.exec_cmd.call_args.args[0]
    # base64 后应不含原始命令明文（防注入/转义问题）
    assert "a b" not in script


# ============ DockerExecTool 快路径（S1: 默认/quick/短等待 → 直连 exec） ============

def test_docker_exec_tool_fast_path_default() -> None:
    """默认 timeout → 快路径：exec_cmd 收到原始命令（无 nohup/base64 包装）."""
    client = _mock_client(stdout="hi\n")
    tool = DockerExecTool(client)
    result = tool.execute(command="echo hi")
    args = client.exec_cmd.call_args.args
    assert args[0] == "echo hi"          # 原始命令直连
    assert "nohup" not in args[0]
    assert "base64" not in args[0]


def test_docker_exec_tool_fast_path_quick_band() -> None:
    """quick 档位 → 快路径."""
    client = _mock_client(stdout="hi\n")
    tool = DockerExecTool(client)
    tool.execute(command="echo hi", timeout="quick")
    assert client.exec_cmd.call_args.args[0] == "echo hi"


def test_docker_exec_tool_fast_path_short_int() -> None:
    """小整数 timeout (5) → 快路径."""
    client = _mock_client(stdout="hi\n")
    tool = DockerExecTool(client)
    tool.execute(command="echo hi", timeout=5)
    assert client.exec_cmd.call_args.args[0] == "echo hi"


def test_docker_exec_tool_fast_path_output_format() -> None:
    """快路径输出：$ cmd + [完成, elapsed=...]，无 [BG_*] 标记."""
    client = _mock_client(stdout="hello world\n", elapsed=0.15)
    tool = DockerExecTool(client)
    result = tool.execute(command="echo hello world")

    assert "$ echo hello world" in result
    assert "[完成, elapsed=0.15s]" in result
    assert "hello world" in result
    assert "[BG_" not in result
    assert "[完成, 同步等待" not in result     # 非 B+ 完成路径


def test_docker_exec_tool_fast_path_timeout_warning() -> None:
    """快路径宿主侧超时（exit_code=-1）→ 返回超时提示."""
    client = _mock_client(stdout="", exit_code=-1, elapsed=130.0)
    client.exec_cmd.return_value = CmdResult(
        stdout="", stderr="[TIMEOUT] 命令超时", exit_code=-1, cmd="sleep 200", elapsed=130.0,
    )
    tool = DockerExecTool(client)
    result = tool.execute(command="sleep 200", timeout=10)
    assert "超时 10s" in result
    assert "background" in result


def test_docker_exec_tool_fast_path_disabled_falls_back_to_bg() -> None:
    """开关 FAST_PATH_ENABLED=False → 默认调用回退 B+ 后台路径."""
    client = _mock_client(stdout="[BG_FINISHED] rc=0\nout\n")
    tool = DockerExecTool(client)
    with patch("ctf_agent.tools.docker_tool.FAST_PATH_ENABLED", False):
        tool.execute(command="ls")
    script = client.exec_cmd.call_args.args[0]
    assert "nohup" in script
    assert "base64 -d" in script


# ============ DockerPythonTool ============

def test_docker_python_tool_output() -> None:
    client = _mock_client(stdout="[BG_FINISHED] rc=0\n42\n")
    tool = DockerPythonTool(client)
    result = tool.execute(script="print(42)", timeout="long")
    assert "42" in result
    assert "$ [docker_python]" in result
    assert "[完成, 同步等待" in result


def test_docker_python_tool_nonzero_exit_marks_error() -> None:
    """bg 完成后 rc=1：输出中保留 rc=1 与脚本输出（LLM 可识别失败）."""
    client = _mock_client(stdout="[BG_FINISHED] rc=1\nTraceback (most recent call last):\nboom\n")
    tool = DockerPythonTool(client)
    result = tool.execute(script="raise ValueError('boom')", timeout="long")
    assert "rc=1" in result
    assert "Traceback" in result


# ============ DockerPythonTool 快路径（S1） ============

def test_docker_python_tool_fast_path_default() -> None:
    """默认 timeout → 快路径：python3 -c base64 注入（无 nohup/bg 脚本）."""
    client = _mock_client(stdout="42\n")
    tool = DockerPythonTool(client)
    result = tool.execute(script="print(42)")

    cmd = client.exec_cmd.call_args.args[0]
    assert cmd.startswith("python3 -c")
    assert "base64.b64decode" in cmd
    assert "nohup" not in cmd
    # 输出格式: [python3 执行, elapsed=...]
    assert "[python3 执行" in result
    assert "42" in result


def test_docker_python_tool_fast_path_quick() -> None:
    """quick 档位 → 快路径."""
    client = _mock_client(stdout="ok\n")
    tool = DockerPythonTool(client)
    tool.execute(script="print('ok')", timeout="quick")
    cmd = client.exec_cmd.call_args.args[0]
    assert cmd.startswith("python3 -c")
    assert "nohup" not in cmd


def test_docker_python_tool_fast_path_nonzero_exit() -> None:
    """快路径 rc=1 → 输出 ERROR 标记."""
    client = _mock_client(stdout="Traceback\n", exit_code=1)
    tool = DockerPythonTool(client)
    result = tool.execute(script="raise ValueError('x')")
    assert "ERROR" in result
    assert "退出码 1" in result
    assert "Traceback" in result


def test_docker_python_tool_fast_path_timeout_warning() -> None:
    """快路径宿主侧超时（exit_code=-1）→ 返回超时提示."""
    client = _mock_client(stdout="", exit_code=-1, elapsed=40.0)
    client.exec_cmd.return_value = CmdResult(
        stdout="", stderr="[TIMEOUT]", exit_code=-1, cmd="x", elapsed=40.0,
    )
    tool = DockerPythonTool(client)
    result = tool.execute(script="import time; time.sleep(300)", timeout=10)
    assert "超时 10s" in result
    assert "background" in result


# ============ DockerClient.exec_cmd 集成（mock subprocess） ============

def test_docker_client_exec_cmd_basic() -> None:
    """exec_cmd 集成：info→ps→exec 全链路 mock，返回 CmdResult 字段正确."""
    mock_run, exec_calls = _mock_subprocess(exec_stdout="root\n")
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        client = DockerClient(backend="cli", container_name="wing-goose-worker")
        result = client.exec_cmd("whoami", cwd="/challenge")

    assert result.exit_code == 0
    assert result.stdout == "root\n"
    assert result.cmd == "whoami"
    assert result.elapsed >= 0
    # exec 命令结构: docker exec [-w cwd] <ctr> sh -lc <cmd>
    assert any(a[0] == "docker" and a[1] == "exec" for a in exec_calls)
    exec_args = next(a for a in exec_calls if a[0] == "docker" and a[1] == "exec")
    assert "wing-goose-worker" in exec_args
    assert exec_args[-3] == "sh"
    assert exec_args[-2] == "-lc"
    assert exec_args[-1] == "whoami"


def test_docker_client_exec_cmd_daemon_down_raises() -> None:
    """daemon 不可用 → 抛 RuntimeError."""
    mock_run, _ = _mock_subprocess(docker_ok=False)
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        client = DockerClient(backend="cli")
        with pytest.raises(RuntimeError, match="daemon"):
            client.exec_cmd("whoami")


def test_docker_client_is_available_cached() -> None:
    """60s 缓存：首次探测后不再重复调用 docker info."""
    mock_run, _ = _mock_subprocess()
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run) as m:
        client = DockerClient(backend="cli")
        assert client.is_available() is True
        assert client.is_available() is True
        assert client.is_available() is True
    info_calls = [c for c in m.call_args_list if c.args[0][1] == "info"]
    assert len(info_calls) == 1


# ============ S2 去每次 docker ps 探测 ============

def test_docker_client_no_ps_probe_on_warm_container() -> None:
    """S2: _container_ok 确认后, 后续 exec 不再产生 docker ps 探测."""
    mock_run, exec_calls = _mock_subprocess(exec_stdout="root\n")
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run) as m:
        client = DockerClient(backend="cli", container_name="wing-goose-worker")
        client.exec_cmd("whoami", cwd="/challenge")   # 首次: 探测 + exec
        client.exec_cmd("whoami", cwd="/challenge")   # 后续: 直接 exec
        client.exec_cmd("whoami", cwd="/challenge")
    ps_calls = [c for c in m.call_args_list if c.args[0][1] == "ps"]
    assert len(ps_calls) == 2      # 仅首次 ensure_container 的 exists+running 各 1 次
    assert len(exec_calls) == 3


def test_docker_client_marks_failed_on_container_gone() -> None:
    """S2+S6: exec 报容器消失 → 本调用内自愈重建 → 返回成功结果."""
    exec_count = {"n": 0}

    def _fake_run(args, *a, **kw):
        args = list(args)
        if args[1] == "ps":
            return MagicMock(returncode=0, stdout="", stderr="")   # 容器不存在
        if args[1] == "exec":
            exec_count["n"] += 1
            if exec_count["n"] == 1:
                return MagicMock(returncode=1, stdout="",
                                 stderr="Error response from daemon: No such container: wing-goose-worker")
            return MagicMock(returncode=0, stdout="ok\n", stderr="")
        if args[1] == "run":
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")   # info 等

    mock_run = MagicMock(side_effect=_fake_run)
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        client = DockerClient(backend="cli", container_name="wing-goose-worker")
        # 容器被删 → 第一次 exec 报 No such container → 本调用内重建 → 重试成功
        r1 = client.exec_cmd("whoami")
        assert r1.exit_code == 0
        assert r1.stdout == "ok\n"
        assert client._container_ok is True
    assert exec_count["n"] == 2      # 1 次失败 + 1 次自愈重试


def test_docker_client_no_false_failed_on_cmd_error() -> None:
    """S2: 普通命令错误（rc=1, 无容器消失字样）不应标记容器失效."""
    mock_run, _ = _mock_subprocess(exec_stdout="", exec_rc=1)
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        client = DockerClient(backend="cli", container_name="wing-goose-worker")
        client.exec_cmd("false", cwd="/challenge")
        assert client._container_ok is True


# ============ S6 崩溃自愈（kill/stop 后自动恢复） ============

def test_docker_client_restarts_stopped_container() -> None:
    """S6: 容器被 kill (exec 报 is not running) → 本调用内 docker start 恢复."""
    exec_count = {"n": 0}
    start_calls = {"n": 0}
    started = {"n": 0}   # start 之后容器视为 running

    def _fake_run(args, *a, **kw):
        args = list(args)
        if args[1] == "ps":
            if "-a" in args:
                return MagicMock(returncode=0, stdout="wing-goose-worker\n", stderr="")  # 容器存在
            # 不带 -a: 仅 running 容器; start 之后才出现
            if started["n"] > 0:
                return MagicMock(returncode=0, stdout="wing-goose-worker\n", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")
        if args[1] == "inspect":
            return MagicMock(returncode=0, stdout="TASK-X\n", stderr="")
        if args[1] == "exec":
            exec_count["n"] += 1
            if exec_count["n"] == 1:
                return MagicMock(returncode=1, stdout="",
                                 stderr="Error response from daemon: Container wing-goose-worker is not running")
            return MagicMock(returncode=0, stdout="ok\n", stderr="")
        if args[1] == "start":
            start_calls["n"] += 1
            started["n"] = 1
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    mock_run = MagicMock(side_effect=_fake_run)
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        client = DockerClient(backend="cli", container_name="wing-goose-worker", task_id="TASK-X")
        # 容器 stopped → 第一次 exec 报 is not running → 本调用内 start 恢复 → 重试成功
        r1 = client.exec_cmd("whoami")
        assert r1.exit_code == 0
        assert r1.stdout == "ok\n"
        assert client._container_ok is True
    assert start_calls["n"] == 1
    assert exec_count["n"] == 2      # 1 次失败 + 1 次自愈重试


# ============ docker_tools 工厂降级 ============

def test_docker_tools_empty_when_unavailable() -> None:
    """docker 不可用 → 返回空列表 → default_tools 自动降级 ssh."""
    client = MagicMock(spec=DockerClient)
    client.is_available.return_value = False
    assert docker_tools(client) == []


def test_docker_tools_returns_three_tools_when_available() -> None:
    client = MagicMock(spec=DockerClient)
    client.is_available.return_value = True
    client.workdir = "/challenge"
    tools = docker_tools(client)
    names = {t.name for t in tools}
    assert names == {"docker_exec", "docker_python", "docker_upload"}


# ============ DockerFileUploadTool / 文件传输 ============

def test_docker_upload_tool_success() -> None:
    client = MagicMock(spec=DockerClient)
    client.upload_file.return_value = None
    tool = DockerFileUploadTool(client)
    result = tool.execute(local_path="C:/tmp/a.bin", remote_path="/challenge/a.bin")
    assert "上传成功" in result
    client.upload_file.assert_called_once_with("C:/tmp/a.bin", "/challenge/a.bin")


def test_docker_upload_tool_missing_local_file() -> None:
    client = MagicMock(spec=DockerClient)
    client.upload_file.side_effect = FileNotFoundError("no file")
    tool = DockerFileUploadTool(client)
    result = tool.execute(local_path="C:/nope.bin", remote_path="/challenge/nope.bin")
    assert "ERROR" in result
    assert "本地文件不存在" in result


def test_docker_client_upload_download_file() -> None:
    mock_run, _ = _mock_subprocess()
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        client = DockerClient(backend="cli", container_name="wing-goose-worker")
        # upload: 本地文件存在才走 docker cp
        import tempfile
        from pathlib import Path
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".bin") as f:
            f.write("data")
            local = f.name
        try:
            client.upload_file(local, "/challenge/a.bin")
        finally:
            Path(local).unlink()
        # download
        with tempfile.TemporaryDirectory() as td:
            client.download_file("/challenge/a.bin", str(Path(td) / "a.bin"))


# ============ S3 资源调控（§13） ============

def test_resolve_quota_default_normal() -> None:
    """默认 Profile=normal → 2 核 / 2g."""
    cpu, mem = resolve_quota("")
    assert cpu == 2
    assert mem == "2g"


def test_resolve_quota_profile_lookup() -> None:
    assert resolve_quota("light") == (1, "1g")
    assert resolve_quota("brute") == (4, "2g")
    assert resolve_quota("heavy") == (4, "4g")


def test_resolve_quota_explicit_override() -> None:
    """显式覆盖优先于 Profile."""
    assert resolve_quota("light", cpu_cores=4, mem_limit="3g") == (4, "3g")
    assert resolve_quota("normal", cpu_cores=0, mem_limit="") == (2, "2g")


def test_resolve_quota_unknown_profile_falls_back() -> None:
    assert resolve_quota("bogus") == (2, "2g")


def test_compute_max_containers_normal() -> None:
    """§13.3: 32 核 / 16.3GB(≈15.2GiB) / normal(2核2G) → 5.

    注意: 设计文档表格按十进制 GB 近似得 6；实现按精确 GiB 向下取整
    （16.3e9×0.75/2GiB = 5.71 → 5），内存维度更保守，安全优先。
    """
    n = compute_max_containers(2, 2, ncpu=32, docker_mem_bytes=16_349_106_176)
    assert n == 5


def test_compute_max_containers_heavy() -> None:
    """heavy(4核4G) → 2（内存维度受限, 同理按 GiB 向下取整）."""
    n = compute_max_containers(4, 4, ncpu=32, docker_mem_bytes=16_349_106_176)
    assert n == 2


def test_compute_max_containers_invalid_input() -> None:
    assert compute_max_containers(2, 2, ncpu=0, docker_mem_bytes=0) == 1


def test_container_scheduler_limits_concurrency() -> None:
    """§13.3: 超配额请求不立即放行."""
    sched = ContainerScheduler(max_containers=2)
    assert sched.acquire() is True
    assert sched.acquire() is True
    assert sched.acquire(blocking=False) is False     # 第三个请求被拒绝（排队）
    assert sched.active == 2
    sched.release()
    assert sched.acquire(blocking=False) is True      # 释放后放行
    assert sched.active == 2


def test_container_scheduler_acquire_timeout() -> None:
    """阻塞 acquire 超时未获得 → False."""
    sched = ContainerScheduler(max_containers=1)
    assert sched.acquire() is True
    t0 = time.monotonic()
    assert sched.acquire(blocking=True, timeout=0.1) is False
    assert time.monotonic() - t0 >= 0.09
    sched.release()


def test_docker_client_run_applies_quota_flags() -> None:
    """S3: 容器创建 (docker run) 携带 --cpus/--memory/--memory-swap/--pids-limit 配额."""
    run_args: dict[str, list] = {}

    def _fake_run(args, *a, **kw):
        args = list(args)
        if args[1] == "ps":
            return MagicMock(returncode=0, stdout="", stderr="")   # 容器不存在 → 触发 run
        if args[1] == "run":
            run_args["list"] = args
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    mock_run = MagicMock(side_effect=_fake_run)
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        client = DockerClient(backend="cli", container_name="wg-quota", cpu_profile="normal")
        assert client.ensure_container() is True

    args = run_args["list"]
    assert "--cpus" in args and args[args.index("--cpus") + 1] == "2"
    assert "--memory" in args and args[args.index("--memory") + 1] == "2g"
    assert "--memory-swap" in args
    assert "--pids-limit" in args and args[args.index("--pids-limit") + 1] == "512"
    assert "--cap-add" in args and args[args.index("--cap-add") + 1] == "SYS_PTRACE"


def test_docker_client_quota_resolved_on_init() -> None:
    """S3: DockerClient 构造即解析配额（Profile + 显式覆盖）."""
    c = DockerClient(backend="cli", cpu_profile="light", cpu_cores=4, mem_limit="3g")
    assert c.cpu_cores == 4
    assert c.mem_limit == "3g"
    c2 = DockerClient(backend="cli")          # 默认 normal
    assert c2.cpu_cores == 2
    assert c2.mem_limit == "2g"


# ============ S4 多容器参数化（agent_id 容器名 + task 标签 + 同题复用） ============

def test_sanitize_name() -> None:
    """S4: 容器名 sanitize — 非法字符替换为 _，超长截断到 60."""
    assert _sanitize_name("OUROBOROS") == "OUROBOROS"
    assert _sanitize_name("web path traversal") == "web_path_traversal"
    assert _sanitize_name("crypto/RSA-512") == "crypto_RSA-512"
    assert _sanitize_name("a" * 80) == "a" * 60          # 截断
    assert _sanitize_name("") == ""
    assert _sanitize_name(None) == ""


def test_docker_client_run_new_with_task_label() -> None:
    """S4: 新建容器携带 --label ctf-agent=true + --label task={task_id}（配额 flags 仍在镜像前）."""
    run_args: dict[str, list] = {}

    def _fake_run(args, *a, **kw):
        args = list(args)
        if args[1] == "ps":
            return MagicMock(returncode=0, stdout="", stderr="")   # 容器不存在 → 触发 run
        if args[1] == "run":
            run_args["list"] = args
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    mock_run = MagicMock(side_effect=_fake_run)
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        client = DockerClient(backend="cli", container_name="wing-goose-OUROBOROS", task_id="OUROBOROS")
        assert client.ensure_container("OUROBOROS") is True

    args = run_args["list"]
    assert args[args.index("--name") + 1] == "wing-goose-OUROBOROS"
    labels = [args[i + 1] for i in range(len(args)) if args[i] == "--label"]
    assert "ctf-agent=true" in labels
    assert "task=OUROBOROS" in labels
    # S3 配额 flags 仍在（镜像之前）—— 多容器场景配额不丢失
    assert "--cpus" in args and args[args.index("--cpus") + 1] == "2"
    img_idx = args.index("wing-goose:v2")
    assert "--cpus" in args[:img_idx] and "--memory" in args[:img_idx]


def test_ensure_container_same_task_reuses() -> None:
    """S4: 容器已存在且 task label 匹配 → 复用（无 docker run）."""
    run_calls = {"n": 0}

    def _fake_run(args, *a, **kw):
        args = list(args)
        if args[1] == "ps":
            return MagicMock(returncode=0, stdout="wing-goose-OUROBOROS\n", stderr="")
        if args[1] == "inspect":
            return MagicMock(returncode=0, stdout="OUROBOROS\n", stderr="")
        if args[1] == "run":
            run_calls["n"] += 1
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    mock_run = MagicMock(side_effect=_fake_run)
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        client = DockerClient(backend="cli", container_name="wing-goose-OUROBOROS", task_id="OUROBOROS")
        assert client.ensure_container("OUROBOROS") is True

    assert run_calls["n"] == 0
    assert client._task_mismatch is False
    assert client._container_ok is True


# ============ S8 后端抽象 (DOCKER_BACKEND=cli|sdk) ============

def test_make_backend_default_cli() -> None:
    """S8: 默认/None/空/"cli" → CliBackend."""
    for v in (None, "", "cli"):
        b = make_backend(v)
        assert isinstance(b, CliBackend)
        assert b.docker_cmd == "docker"
    b = make_backend("cli", docker_cmd="podman")
    assert isinstance(b, CliBackend) and b.docker_cmd == "podman"


def test_make_backend_sdk_returns_sdk_backend() -> None:
    """S9/S10: "sdk" → SdkBackend; docker-py 缺失 → 降级 CliBackend + 警告 (保降级链)."""
    try:
        import docker  # noqa: F401
    except ImportError:
        with pytest.warns(UserWarning, match="回落为 cli"):
            b = make_backend("sdk")
        assert isinstance(b, CliBackend)
        return
    b = make_backend("sdk")
    assert isinstance(b, SdkBackend)
    assert b.docker_cmd == "docker"


def test_make_backend_unknown_raises() -> None:
    """S8: 未知后端名 → ValueError."""
    with pytest.raises(ValueError):
        make_backend("k8s")


def test_make_backend_accepts_instance() -> None:
    """S8: 直接传入后端实例 → 原样返回."""
    b = CliBackend(docker_cmd="docker")
    assert make_backend(b) is b


def test_docker_client_default_backend_is_sdk() -> None:
    """S10: DockerClient 默认 backend="sdk" → 内部 _backend 为 SdkBackend."""
    client = DockerClient()
    assert isinstance(client._backend, SdkBackend)


def test_docker_client_accepts_custom_backend() -> None:
    """S8: 传入自定义后端实例 → 生命周期操作分派到该后端."""
    calls: list[str] = []

    class FakeBackend(DockerBackend):
        def is_available(self) -> bool:
            calls.append("is_available")
            return True
        def container_exists(self, name: str) -> bool:
            calls.append("container_exists")
            return True
        def container_running(self, name: str) -> bool:
            calls.append("container_running")
            return True
        def create_and_start(self, name, image, flags, command) -> bool:
            calls.append("create_and_start")
            return True
        def start(self, name: str) -> bool:
            calls.append("start")
            return True
        def remove(self, name: str) -> None:
            calls.append("remove")
        def inspect_label(self, name: str, key: str) -> str:
            calls.append("inspect_label")
            return "t1"
        def list_exited_ctf_containers(self) -> list[str]:
            calls.append("list_exited")
            return []
        def exec_run(self, args, *, timeout: int):
            calls.append("exec_run")
            return MagicMock(returncode=0, stdout="out", stderr="")
        def upload(self, name, local_path, remote_path) -> None:
            calls.append("upload")
        def download(self, name, remote_path, local_path) -> None:
            calls.append("download")

    client = DockerClient(backend=FakeBackend(), task_id="t1")
    assert client.is_available() is True
    assert client.ensure_container("t1") is True
    r = client.exec_cmd("echo hi")
    assert r.exit_code == 0 and r.stdout == "out"
    assert "is_available" in calls and "exec_run" in calls


def test_cli_backend_exec_run_passes_timeout() -> None:
    """S8: CliBackend.exec_run 转发 timeout（且用模块级 subprocess 便于 patch）."""
    mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        b = CliBackend()
        b.exec_run(["docker", "exec", "c", "sh", "-lc", "true"], timeout=70)
    kw = mock_run.call_args.kwargs
    assert kw["timeout"] == 70 and kw["capture_output"] is True


def test_cli_backend_upload_failure_raises() -> None:
    """S8: CliBackend.upload docker cp 失败 → RuntimeError."""
    mock_run = MagicMock(return_value=MagicMock(returncode=1, stdout="", stderr="boom"))
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        b = CliBackend()
        with pytest.raises(RuntimeError, match="boom"):
            b.upload("c", "a", "/b")


def test_ensure_container_diff_task_marks_mismatch() -> None:
    """S4 兼容: 开关关闭 (ENABLE_TASK_RESET=False) 时异题仅标记 mismatch 不复用重建."""
    def _fake_run(args, *a, **kw):
        args = list(args)
        if args[1] == "ps":
            return MagicMock(returncode=0, stdout="wing-goose-web\n", stderr="")
        if args[1] == "inspect":
            return MagicMock(returncode=0, stdout="OUROBOROS\n", stderr="")
        if args[1] == "run":
            raise AssertionError("开关关闭时异题不应新建容器")
        return MagicMock(returncode=0, stdout="", stderr="")

    mock_run = MagicMock(side_effect=_fake_run)
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        with patch("ctf_agent.tools.docker_tool.ENABLE_TASK_RESET", False):
            client = DockerClient(backend="cli", container_name="wing-goose-web", task_id="web")
            assert client.ensure_container("web") is True

    assert client._task_mismatch is True
    assert client._container_ok is True


# ============ S5 跨题重置 + 孤儿清理 + 工作区挂载 ============

def test_ensure_container_diff_task_resets() -> None:
    """S5: 异题 → docker rm -f 旧容器 + 重新 run（全新环境, 消除跨题污染）."""
    calls: list[list[str]] = []

    def _fake_run(args, *a, **kw):
        args = list(args)
        calls.append(args)
        if args[1] == "ps":
            return MagicMock(returncode=0, stdout="wing-goose-web\n", stderr="")
        if args[1] == "inspect":
            return MagicMock(returncode=0, stdout="OUROBOROS\n", stderr="")
        if args[1] == "rm":
            return MagicMock(returncode=0, stdout="", stderr="")
        if args[1] == "run":
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    mock_run = MagicMock(side_effect=_fake_run)
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        client = DockerClient(backend="cli", container_name="wing-goose-web", task_id="web")
        assert client.ensure_container("web") is True

    # 执行顺序: ps → inspect → rm -f → run
    rm_calls = [c for c in calls if c[1] == "rm"]
    run_calls = [c for c in calls if c[1] == "run"]
    assert len(rm_calls) == 1 and rm_calls[0][2:4] == ["-f", "wing-goose-web"]
    assert len(run_calls) == 1
    assert client._task_mismatch is False      # 重建后复位
    assert client._container_ok is True
    # 重建的 run 带新 task label
    labels = [run_calls[0][i + 1] for i in range(len(run_calls[0])) if run_calls[0][i] == "--label"]
    assert "task=web" in labels


def test_ensure_container_reset_skipped_when_disabled() -> None:
    """S5 开关关闭: 异题不 rm/run, 退回 S4 复用（不影响其他功能）."""
    def _fake_run(args, *a, **kw):
        args = list(args)
        if args[1] == "ps":
            return MagicMock(returncode=0, stdout="wing-goose-web\n", stderr="")
        if args[1] == "inspect":
            return MagicMock(returncode=0, stdout="OUROBOROS\n", stderr="")
        if args[1] in ("rm", "run"):
            raise AssertionError("开关关闭时不应 rm/run")
        return MagicMock(returncode=0, stdout="", stderr="")

    mock_run = MagicMock(side_effect=_fake_run)
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        with patch("ctf_agent.tools.docker_tool.ENABLE_TASK_RESET", False):
            client = DockerClient(backend="cli", container_name="wing-goose-web", task_id="web")
            assert client.ensure_container("web") is True
    assert client._task_mismatch is True


def test_cleanup_orphans() -> None:
    """S5: 仅清理 stopped 的 ctf-agent 容器, running 容器保留（不误删并行 agent）."""
    rm_names: list[str] = []

    def _fake_run(args, *a, **kw):
        args = list(args)
        if args[1] == "ps":
            # 第一个 ps: 列出孤儿 (stopped); 之后每个 rm 后不再有 ps
            return MagicMock(returncode=0, stdout="wing-goose-orphan1\nwing-goose-orphan2\n", stderr="")
        if args[1] == "rm":
            rm_names.append(args[args.index("-f") + 1])
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    mock_run = MagicMock(side_effect=_fake_run)
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run) as m:
        n = DockerClient.cleanup_orphans()

    assert n == 2
    assert rm_names == ["wing-goose-orphan1", "wing-goose-orphan2"]
    # ps 过滤条件: 仅 label=ctf-agent=true 且 status=exited
    ps_args = next(c.args[0] for c in m.call_args_list if c.args[0][1] == "ps")
    assert "status=exited" in ps_args
    assert "label=ctf-agent=true" in ps_args


def test_cleanup_orphans_empty() -> None:
    """S5: 无孤儿 → 返回 0, 无 rm 调用."""
    def _fake_run(args, *a, **kw):
        if args[1] == "ps":
            return MagicMock(returncode=0, stdout="", stderr="")
        if args[1] == "rm":
            raise AssertionError("不应清理任何容器")
        return MagicMock(returncode=0, stdout="", stderr="")

    mock_run = MagicMock(side_effect=_fake_run)
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        assert DockerClient.cleanup_orphans() == 0


def test_docker_client_run_with_workspace_mount() -> None:
    """S5: 指定 workspace_dir 时 run 带 -v 宿主目录:/challenge/workspace:rw（镜像前）."""
    run_args: dict[str, list] = {}

    def _fake_run(args, *a, **kw):
        args = list(args)
        if args[1] == "ps":
            return MagicMock(returncode=0, stdout="", stderr="")
        if args[1] == "run":
            run_args["list"] = args
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        mock_run = MagicMock(side_effect=_fake_run)
        with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
            client = DockerClient(backend="cli", container_name="wing-goose-ws", task_id="t",
                                  workspace_dir=td)
            assert client.ensure_container("t") is True
        args = run_args["list"]
        assert "-v" in args
        v_idx = args.index("-v")
        assert args[v_idx + 1] == f"{td}:/challenge/workspace:rw"
        img_idx = args.index("wing-goose:v2")
        assert "-v" in args[:img_idx]          # 挂载 flags 在镜像前
        assert "--cpus" in args[:img_idx]      # 配额 flags 同时保留


def test_docker_client_run_no_workspace_by_default() -> None:
    """S5: 未指定 workspace_dir → run 不带 -v（默认行为不变）."""
    run_args: dict[str, list] = {}

    def _fake_run(args, *a, **kw):
        args = list(args)
        if args[1] == "ps":
            return MagicMock(returncode=0, stdout="", stderr="")
        if args[1] == "run":
            run_args["list"] = args
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    mock_run = MagicMock(side_effect=_fake_run)
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        client = DockerClient(backend="cli", container_name="wing-goose-nws", task_id="t")
        assert client.ensure_container("t") is True
    assert "-v" not in run_args["list"]


def test_ensure_container_existing_no_label_no_mismatch() -> None:
    """S4: 旧容器无 task label → 不标记 mismatch（兼容旧容器，S5 升级时统一清理）."""
    def _fake_run(args, *a, **kw):
        args = list(args)
        if args[1] == "ps":
            return MagicMock(returncode=0, stdout="wing-goose-old\n", stderr="")
        if args[1] == "inspect":
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    mock_run = MagicMock(side_effect=_fake_run)
    with patch("ctf_agent.tools.docker_tool.subprocess.run", mock_run):
        client = DockerClient(backend="cli", container_name="wing-goose-old", task_id="new")
        assert client.ensure_container("new") is True

    assert client._task_mismatch is False
    assert client._container_ok is True


# ============ S9 SDK 后端（docker-py, DOCKER_BACKEND=sdk） ============

def test_parse_exec_args_basic() -> None:
    """S9: 解析 DockerClient._build_exec_cmd 生成的 CLI exec args."""
    args = ["docker", "exec", "wing-goose-w", "sh", "-lc", "ls -la"]
    name, cmd, cwd, env = _parse_exec_args(args)
    assert name == "wing-goose-w"
    assert cmd == "ls -la"
    assert cwd is None and env == {}


def test_parse_exec_args_with_cwd_and_env() -> None:
    """S9: -w cwd + 多个 -e K=V 均被解析."""
    args = ["docker", "exec", "-w", "/challenge", "-e", "TERM=xterm", "-e", "A=1",
            "wing-goose-w", "sh", "-lc", "echo $A"]
    name, cmd, cwd, env = _parse_exec_args(args)
    assert name == "wing-goose-w"
    assert cmd == "echo $A"
    assert cwd == "/challenge"
    assert env == {"TERM": "xterm", "A": "1"}


def test_parse_run_flags_all_supported() -> None:
    """S9: 全量 flags → SDK kwargs（labels/volumes/nano_cpus/mem/caps/security）."""
    flags = [
        "--label", "ctf-agent=true", "--label", "task=t1",
        "-v", "/host/ws:/challenge/workspace:rw",
        "--cpus", "2", "--memory", "2g", "--memory-swap", "2g",
        "--pids-limit", "512", "--cap-add", "SYS_PTRACE",
        "--security-opt", "seccomp=unconfined",
    ]
    kw = _parse_run_flags(flags)
    assert kw["labels"] == {"ctf-agent": "true", "task": "t1"}
    assert kw["volumes"] == {"/host/ws": {"bind": "/challenge/workspace", "mode": "rw"}}
    assert kw["nano_cpus"] == 2_000_000_000
    assert kw["mem_limit"] == "2g" and kw["memswap_limit"] == "2g"
    assert kw["pids_limit"] == 512
    assert kw["cap_add"] == ["SYS_PTRACE"]
    assert kw["security_opt"] == ["seccomp=unconfined"]


def test_parse_run_flags_unknown_ignored() -> None:
    """S9: 未知/无值 flags 安全跳过, 不影响已解析项."""
    flags = ["--cpus", "1", "--bogus", "x"]
    kw = _parse_run_flags(flags)
    assert kw["nano_cpus"] == 1_000_000_000
    assert "bogus" not in kw


def test_sdk_backend_exec_run_maps_output() -> None:
    """S9: SdkBackend.exec_run 经 SDK 底层 API, demux 输出还原为 CompletedProcess."""
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_container.id = "abc123"
    mock_client.containers.get.return_value = mock_container
    mock_client.api.exec_create.return_value = {"Id": "exec-1"}
    mock_client.api.exec_start.return_value = (b"stdout-line\n", b"stderr-line\n")
    mock_client.api.exec_inspect.return_value = {"ExitCode": 0}

    with patch.object(SdkBackend, "_get_client", return_value=mock_client):
        b = SdkBackend()
        r = b.exec_run(
            ["docker", "exec", "wing-goose-w", "sh", "-lc", "echo hi"], timeout=70)

    assert r.returncode == 0
    assert r.stdout == "stdout-line\n"
    assert r.stderr == "stderr-line\n"
    mock_client.api.exec_create.assert_called_once()
    call_args = mock_client.api.exec_create.call_args
    assert call_args.args[0] == "abc123"      # container (位置参数)
    assert call_args.args[1] == ["sh", "-lc", "echo hi"]   # sh -lc 包裹 (CLI 等价)
    assert call_args.kwargs.get("workdir") is None
    assert call_args.kwargs.get("environment") is None
    mock_client.api.exec_start.assert_called_once_with("exec-1", demux=True)


def test_sdk_backend_exec_run_raises_timeout() -> None:
    """S9: SDK exec 超过 timeout → 抛 TimeoutExpired (与 CLI subprocess 契约一致)."""
    mock_client = MagicMock()
    mock_client.containers.get.return_value = MagicMock(id="abc123")
    mock_client.api.exec_create.return_value = {"Id": "exec-1"}

    # exec_start 永不返回 → 线程 join(timeout) 后判定超时
    def _hang(*a, **kw):
        import time as _t
        _t.sleep(30)
        return (b"", b"")

    mock_client.api.exec_start.side_effect = _hang

    with patch.object(SdkBackend, "_get_client", return_value=mock_client):
        b = SdkBackend()
        with pytest.raises(subprocess.TimeoutExpired):
            b.exec_run(["docker", "exec", "w", "sh", "-lc", "sleep 999"], timeout=1)


def test_sdk_backend_exec_run_error_returns_exit1() -> None:
    """S9: SDK 异常（容器不存在）→ CompletedProcess(returncode=1, stderr=异常)."""
    mock_client = MagicMock()
    mock_client.containers.get.side_effect = Exception("No such container: x")

    with patch.object(SdkBackend, "_get_client", return_value=mock_client):
        b = SdkBackend()
        r = b.exec_run(["docker", "exec", "x", "sh", "-lc", "true"], timeout=10)

    assert r.returncode == 1
    assert "No such container" in r.stderr
    assert r.stdout == ""


def test_sdk_backend_upload_uses_put_archive() -> None:
    """S9: SdkBackend.upload 走 tarfile + put_archive（目标目录为父目录）."""
    import io
    import tempfile
    import tarfile

    mock_container = MagicMock()
    mock_client = MagicMock()
    mock_client.containers.get.return_value = mock_container

    with tempfile.TemporaryDirectory() as td:
        src = f"{td}/a.bin"
        with open(src, "wb") as f:
            f.write(b"hello")
        with patch.object(SdkBackend, "_get_client", return_value=mock_client):
            b = SdkBackend()
            b.upload("wing-goose-w", src, "/challenge/a.bin")

    mock_container.put_archive.assert_called_once()
    remote_dir, buf = mock_container.put_archive.call_args.args
    assert remote_dir == "/challenge"
    # 校验 tar 内容与 arcname
    buf.seek(0)
    with tarfile.open(fileobj=buf, mode="r") as tar:
        names = tar.getnames()
        assert names == ["a.bin"]
        assert tar.extractfile("a.bin").read() == b"hello"


def test_sdk_backend_download_uses_get_archive() -> None:
    """S9: SdkBackend.download 走 get_archive + tarfile 提取写文件."""
    import io
    import tarfile
    import tempfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("result.txt")
        data = b"ctf-flag{ok}"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    buf.seek(0)

    mock_client = MagicMock()
    mock_client.containers.get.return_value = MagicMock()
    mock_client.containers.get.return_value.get_archive.return_value = (buf, {})

    with tempfile.TemporaryDirectory() as td:
        dst = f"{td}/result.txt"
        with patch.object(SdkBackend, "_get_client", return_value=mock_client):
            b = SdkBackend()
            b.download("wing-goose-w", "/challenge/result.txt", dst)
        with open(dst, "rb") as f:
            assert f.read() == b"ctf-flag{ok}"


def test_sdk_backend_upload_failure_raises() -> None:
    """S9: SDK put_archive 失败 → RuntimeError（与 CliBackend.upload 对齐）."""
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_container.put_archive.side_effect = Exception("archive failed")
    mock_client.containers.get.return_value = mock_container

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        src = f"{td}/a.txt"
        with open(src, "w") as f:
            f.write("x")
        with patch.object(SdkBackend, "_get_client", return_value=mock_client):
            b = SdkBackend()
            with pytest.raises(RuntimeError, match="put_archive"):
                b.upload("w", src, "/challenge/a.txt")
