"""Docker 容器工具层（WING-Goose Item 5）.

通过 Windows Docker Desktop 在 Linux 容器内执行命令，替代 ssh_exec/ssh_python
在架构中的位置。容器常驻（sleep infinity），`docker exec` 往返延迟极低。

工具链降级链（层层降级）：
    docker_exec/docker_python (Docker Desktop, 替代内置工具)
        ↓ 降级
    ssh_exec/ssh_python (Kali VM, 内置工具保留)
        ↓ 降级
    MCP 工具 (结构化扫描)

实现要点：
- DockerClient 封装 `docker` CLI（subprocess 直调），复用 SSHClient 的 CmdResult 结构，
  让上层工具（exec/python）与 ssh 版签名完全一致，切换零成本
- 复用 ssh_tool 的 B+ 后台执行逻辑（_build_bg_script/_parse_bg_output/_resolve_timeout），
  容器内同样支持 nohup 后台 + 日志轮询
- docker 不可用（daemon 未启动/CLI 缺失）时，工厂返回空列表 → default_tools 自动降级到 ssh
"""
from __future__ import annotations

import re
import subprocess
import threading
import time
import warnings
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ctf_agent.ssh.client import CmdResult
from ctf_agent.tools.base import Tool

# 复用 ssh_tool 的 B+ 后台执行逻辑（容器内同样适用: nohup + 日志轮询）
from ctf_agent.tools.ssh_tool import (
    _BG_CLIENT_BUFFER,
    _build_bg_script,
    _parse_bg_output,
    _resolve_timeout,
    _truncate,
)

# 输出截断阈值（与 ssh_tool 一致）
_MAX_OUTPUT = 8000

# ============ S1 快路径（消灭固定 sleep 1 轮询开销） ============
# 背景: 原实现每条命令都走 B+ 后台轮询（nohup + sleep 1 逐秒探测），
# 命令瞬间结束也要等第一次 sleep 1 → 日志实测 docker_exec p50 = 1.14s,
# 而 docker exec CLI 全链路仅 ~144ms（基线 checkpoint_0_baseline.txt）。
# 快路径: 默认/quick/短等待命令直接 docker exec 同步执行, 跳过后台轮询;
# 长任务（normal/long/background）仍走 B+ 后台路径, 转后台语义完全保留。
_FAST_SYNC_THRESHOLD = 15      # 快路径同步等待窗口上限 (s)
FAST_PATH_ENABLED = True       # 总开关: 置 False 完全还原 Step 0 行为（B+ 全路径）

# S2: 容器消失/异常错误模式（exec 非零返回时检测 → 标记 _container_ok 失效 → 下次自动重探重建）
_CONTAINER_GONE_PATTERNS = (
    "No such container",
    "is not running",
    "Cannot connect to the Docker daemon",
    "error during connect",
)


def _looks_like_container_gone(stderr: str) -> bool:
    """exec 返回非零时, 判断 stderr 是否表明容器/daemon 已不可用."""
    return any(p in stderr for p in _CONTAINER_GONE_PATTERNS)


# S4: 容器名 sanitize（docker 容器名仅允许 [a-zA-Z0-9_.-], 且 ≤63 字符）
_CTR_NAME_RE = re.compile(r"[^a-zA-Z0-9_.-]")


def _sanitize_name(name: str) -> str:
    """把 agent/challenge 标识转为合法 docker 容器名片段."""
    s = _CTR_NAME_RE.sub("_", name or "")
    return s[:60]


# S5: 跨题重置开关（_task_mismatch → rm+run 全新环境; False 退回 S4 兼容复用）
ENABLE_TASK_RESET = True


# ============ S3 资源调控（多容器并行基础, 设计文档 §13） ============
# 原则: 内存严格按难度（独占资源防 OOM）; CPU 按题型宽松上限（爆破类 4 核）。
# 统一追加: --memory-swap 同值（禁 swap 逃逸拖垮宿主）+ --pids-limit（防 fork bomb）
#          + --cap-add SYS_PTRACE --security-opt seccomp=unconfined（CTF 调试必需）。
CPU_PROFILES: dict[str, dict[str, Any]] = {
    "light":  {"cpu": 1, "mem": "1g"},   # web / misc 轻量
    "normal": {"cpu": 2, "mem": "2g"},   # 一般题目（默认, crypto 计算/pwn 调试）
    "brute":  {"cpu": 4, "mem": "2g"},   # 爆破类（内存按难度覆盖, §13.2）
    "heavy":  {"cpu": 4, "mem": "4g"},   # angr / sagemath 大格 / 内存取证
}
_DEFAULT_PROFILE = "normal"
_PIDS_LIMIT = 512


def resolve_quota(
    profile: str,
    *,
    cpu_cores: int = 0,
    mem_limit: str = "",
) -> tuple[int, str]:
    """解析容器配额: Profile 表 + 显式覆盖（cpu_cores>0 / mem_limit 非空时覆盖）.

    Returns:
        (cpu 核数, 内存限制字符串, 如 "2g")
    """
    p = CPU_PROFILES.get(profile or _DEFAULT_PROFILE, CPU_PROFILES[_DEFAULT_PROFILE])
    cpu = int(cpu_cores) if cpu_cores and cpu_cores > 0 else int(p["cpu"])
    mem = mem_limit or str(p["mem"])
    return cpu, mem


def compute_max_containers(
    profile_cpu: int,
    profile_mem_gb: float,
    *,
    ncpu: int,
    docker_mem_bytes: int,
    reserve_cpu: float = 0.25,
    reserve_ram: float = 0.25,
) -> int:
    """§13.3 并发度模型: 按 Profile 与宿主资源计算最大并发容器数.

    usable = total × (1 - reserve); max = min(usable_cpu // profile.cpu,
                                              usable_ram // profile.ram)
    """
    if ncpu <= 0 or docker_mem_bytes <= 0 or profile_cpu <= 0 or profile_mem_gb <= 0:
        return 1
    usable_cpu = int(ncpu * (1 - reserve_cpu))
    usable_ram_bytes = int(docker_mem_bytes * (1 - reserve_ram))
    usable_ram_gb = usable_ram_bytes / (1024 ** 3)
    return max(1, min(usable_cpu // profile_cpu, int(usable_ram_gb // profile_mem_gb)))


def detect_host_resources(docker_cmd: str = "docker") -> tuple[int, int]:
    """探测宿主 Docker 资源 (NCPU, MemTotal bytes). 失败返回 (0, 0)."""
    try:
        r = subprocess.run(
            [docker_cmd, "info", "--format", "{{.NCPU}} {{.MemTotal}}"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return 0, 0
        parts = r.stdout.split()
        return int(parts[0]), int(parts[1])
    except Exception:
        return 0, 0


class ContainerScheduler:
    """§13.3 全局容器并发信号量（orchestrator 层持有, 线程安全）.

    运行中容器数 ≤ max_containers; 超出请求阻塞等待（而非立即启动新容器）,
    有容器退出后自动放行。供多 agent 并行调度复用。
    """

    def __init__(self, max_containers: int) -> None:
        self.max_containers = max(1, int(max_containers))
        self._sem = threading.Semaphore(self.max_containers)
        self._lock = threading.Lock()
        self._active = 0

    @property
    def active(self) -> int:
        with self._lock:
            return self._active

    def acquire(self, blocking: bool = True, timeout: float | None = None) -> bool:
        """占用一个容器名额. 返回是否成功（非阻塞/超时未获得 → False）."""
        if not self._sem.acquire(blocking=blocking, timeout=timeout):
            return False
        with self._lock:
            self._active += 1
        return True

    def release(self) -> None:
        """归还一个容器名额（容器销毁/任务结束时调用）."""
        with self._lock:
            self._active = max(0, self._active - 1)
        self._sem.release()


def _use_fast_path(timeout: Any, wait_sec: int) -> bool:
    """S1 快路径判定: 满足其一即直连 exec, 否则走 B+ 后台.

    - timeout 未声明 (None)  → 快路径 (默认调用多为快速命令, p50 收益最大来源)
    - timeout == "quick"     → 快路径 (显式声明快速命令, 30s 窗口)
    - wait_sec ≤ 阈值        → 快路径 (短等待同步无风险)
    - normal/long/background/大整数 → B+ 后台 (保留软超时转后台 + PID 追踪)
    """
    if not FAST_PATH_ENABLED:
        return False
    if wait_sec <= 0:                    # background → 立即转后台
        return False
    if timeout is None or timeout == "quick":
        return True
    return wait_sec <= _FAST_SYNC_THRESHOLD


# ============ S8 后端抽象 (DOCKER_BACKEND=cli|sdk, 设计文档 Step 9) ============
# 目标: DockerClient 只依赖语义级后端接口, 不直接拼 docker CLI 参数。
# 默认 cli 后端行为与 S0-S7 完全一致 (零变化); sdk 后端在 S9 实现。
# ⚠️ CliBackend 内部必须引用本模块的 subprocess (模块级), 保证现有单测
#    patch "ctf_agent.tools.docker_tool.subprocess.run" 继续生效。
class DockerBackend(ABC):
    """Docker 语义级后端接口（CLI / SDK 共享）.

    DockerClient 的所有底层容器操作均经由该接口, 便于替换实现
    （CLI subprocess → SDK docker-py, 或未来的其他 runtime）。
    """

    def __init__(self, docker_cmd: str = "docker") -> None:
        self.docker_cmd = docker_cmd

    # --- 探测 ---
    @abstractmethod
    def is_available(self) -> bool:
        """daemon 是否可用."""

    # --- 生命周期 ---
    @abstractmethod
    def container_exists(self, name: str) -> bool: ...
    @abstractmethod
    def container_running(self, name: str) -> bool: ...
    @abstractmethod
    def create_and_start(self, name: str, image: str,
                         flags: list[str], command: list[str]) -> bool:
        """创建并启动容器 (run -d). flags 在 image 前, command 在 image 后."""
    @abstractmethod
    def start(self, name: str) -> bool: ...
    @abstractmethod
    def remove(self, name: str) -> None: ...
    @abstractmethod
    def inspect_label(self, name: str, key: str) -> str: ...
    @abstractmethod
    def inspect_mounts(self, name: str) -> list[str]:
        """返回容器已挂载的目标路径列表 (S5 附件挂载校验用)."""
    @abstractmethod
    def list_exited_ctf_containers(self) -> list[str]:
        """列出 label=ctf-agent=true 且已退出的容器名 (孤儿清理用)."""

    # --- 执行 / 文件 ---
    @abstractmethod
    def exec_run(self, args: list[str], *, timeout: int) -> subprocess.CompletedProcess:
        """执行 docker exec（args 为完整命令列表, 含容器名与 sh -lc 前缀）."""
    @abstractmethod
    def upload(self, name: str, local_path: str, remote_path: str) -> None: ...
    @abstractmethod
    def download(self, name: str, remote_path: str, local_path: str) -> None: ...


class CliBackend(DockerBackend):
    """docker CLI 后端（subprocess 直调, 默认）. 行为与 S0-S7 完全一致."""

    def is_available(self) -> bool:
        try:
            r = subprocess.run(
                [self.docker_cmd, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=5,
            )
            return r.returncode == 0
        except Exception:
            return False

    def container_exists(self, name: str) -> bool:
        r = subprocess.run(
            [self.docker_cmd, "ps", "-a", "--filter", f"name=^{name}$",
             "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10,
        )
        return bool(r.stdout.strip())

    def container_running(self, name: str) -> bool:
        r = subprocess.run(
            [self.docker_cmd, "ps", "--filter", f"name=^{name}$",
             "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10,
        )
        return bool(r.stdout.strip())

    def create_and_start(self, name: str, image: str,
                         flags: list[str], command: list[str]) -> bool:
        # ⚠️ flags 必须在 IMAGE 之前, 否则被当作容器 command 参数
        args = [self.docker_cmd, "run", "-d", "--name", name, *flags, image, *command]
        r = subprocess.run(args, capture_output=True, text=True, timeout=120)
        return r.returncode == 0

    def start(self, name: str) -> bool:
        r = subprocess.run(
            [self.docker_cmd, "start", name],
            capture_output=True, text=True, timeout=60,
        )
        return r.returncode == 0

    def remove(self, name: str) -> None:
        subprocess.run(
            [self.docker_cmd, "rm", "-f", name],
            capture_output=True, text=True, timeout=60,
        )

    def inspect_label(self, name: str, key: str) -> str:
        r = subprocess.run(
            [self.docker_cmd, "inspect", "--format",
             f"{{{{index .Config.Labels \"{key}\"}}}}", name],
            capture_output=True, text=True, timeout=10,
        )
        return (r.stdout or "").strip()

    def inspect_mounts(self, name: str) -> list[str]:
        r = subprocess.run(
            [self.docker_cmd, "inspect", "--format",
             "{{range .Mounts}}{{.Destination}}{{println}}{{end}}", name],
            capture_output=True, text=True, timeout=10,
        )
        return [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]

    def list_exited_ctf_containers(self) -> list[str]:
        r = subprocess.run(
            [self.docker_cmd, "ps", "-a", "--filter", "label=ctf-agent=true",
             "--filter", "status=exited", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10,
        )
        return [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]

    def exec_run(self, args: list[str], *, timeout: int) -> subprocess.CompletedProcess:
        return subprocess.run(
            args, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace",
        )

    def upload(self, name: str, local_path: str, remote_path: str) -> None:
        r = subprocess.run(
            [self.docker_cmd, "cp", local_path, f"{name}:{remote_path}"],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            raise RuntimeError(f"docker cp 失败: {r.stderr.strip() or 'unknown'}")

    def download(self, name: str, remote_path: str, local_path: str) -> None:
        r = subprocess.run(
            [self.docker_cmd, "cp", f"{name}:{remote_path}", local_path],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            raise RuntimeError(f"docker cp 失败: {r.stderr.strip() or 'unknown'}")


def _parse_exec_args(args: list[str]) -> tuple[str, str, str | None, dict[str, str]]:
    """解析 DockerClient._build_exec_cmd 生成的 CLI args → (容器名, cmd, cwd, env).

    格式: [docker, exec, -w <cwd>?, -e K=V?, ..., <name>, sh, -lc, <cmd>]
    S9 SDK 后端复用: 仅本工具生成该格式, 解析稳定。
    """
    rest = list(args)
    # 去掉 [docker, exec] 前缀
    if len(rest) >= 2 and rest[0] == "docker":
        rest = rest[2:]
    cwd: str | None = None
    env: dict[str, str] = {}
    i = 0
    while i < len(rest):
        if rest[i] == "-w" and i + 1 < len(rest):
            cwd = rest[i + 1]
            i += 2
        elif rest[i] == "-e" and i + 1 < len(rest):
            k, _, v = rest[i + 1].partition("=")
            env[k] = v
            i += 2
        else:
            break
    name = rest[i]
    sh = rest[i + 1:]
    if len(sh) >= 3 and sh[0] == "sh" and sh[1] == "-lc":
        cmd = sh[2]
    else:
        cmd = " ".join(sh)
    return name, cmd, cwd, env


def _parse_volume_spec(spec: str) -> tuple[str, str, str]:
    """解析 docker -v 参数 → (host, remote, mode).

    兼容:
      - Windows 盘符路径: C:/host/path:/container/path:rw
      - Linux 绝对路径:   /host/path:/container/path:ro
      - 命名卷:           myvol:/data
      - 匿名卷:           /data (仅容器路径)
    修复: 旧实现用 partition(":") 会把盘符 C: 拆成命名卷名 "C",
    导致 Windows 宿主路径挂载全部错位 (workspace 挂载丢失 → agent 找不到附件).
    """
    parts = spec.split(":")
    if len(parts) >= 2 and len(parts[0]) == 1 and parts[0].isalpha():
        # Windows 盘符: C:/... → host 合并 C: + 路径
        host = f"{parts[0]}:{parts[1]}"
        rest = parts[2:]
    else:
        host = parts[0]
        rest = parts[1:]
    remote = rest[0] if rest else ""
    mode = rest[1] if len(rest) > 1 else "rw"
    return host, remote, mode


def _parse_run_flags(flags: list[str]) -> dict[str, Any]:
    """解析 create_and_start 的 CLI flags → docker SDK 关键字参数."""
    kw: dict[str, Any] = {}
    i = 0
    labels: dict[str, str] = {}
    volumes: dict[str, dict[str, str]] = {}
    cap_add: list[str] = []
    sec_opt: list[str] = []
    while i < len(flags):
        f = flags[i]
        v = flags[i + 1] if i + 1 < len(flags) else None
        if f == "--label" and v:
            k, _, val = v.partition("=")
            labels[k] = val
            i += 2
        elif f == "-v" and v:
            host, remote, mode = _parse_volume_spec(v)
            volumes[host] = {"bind": remote, "mode": mode}
            i += 2
        elif f == "--cpus" and v:
            kw["nano_cpus"] = int(float(v) * 1_000_000_000)
            i += 2
        elif f == "--memory" and v:
            kw["mem_limit"] = v
            i += 2
        elif f == "--memory-swap" and v:
            kw["memswap_limit"] = v
            i += 2
        elif f == "--pids-limit" and v:
            kw["pids_limit"] = int(v)
            i += 2
        elif f == "--cap-add" and v:
            cap_add.append(v)
            i += 2
        elif f == "--security-opt" and v:
            sec_opt.append(v)
            i += 2
        elif f == "--add-host" and v:
            host, _, val = v.partition(":")
            extra = kw.setdefault("extra_hosts", {})
            extra[host] = val
            i += 2
        else:
            i += 1
    if labels:
        kw["labels"] = labels
    if volumes:
        kw["volumes"] = volumes
    if cap_add:
        kw["cap_add"] = cap_add
    if sec_opt:
        kw["security_opt"] = sec_opt
    return kw


class SdkBackend(DockerBackend):
    """docker SDK (docker-py) 后端.

    与 CliBackend 语义等价: exec / upload / download / 容器生命周期。
    CLI 风格参数在边界解析 (exec args / run flags), DockerClient 与上层零改动。
    依赖: pip install 'ctf-agent[docker]' (docker-py)。缺失时 make_backend 显式报错。
    """

    _client = None  # 进程内单例 (from_env 一次, 复用连接)

    def _get_client(self):
        if SdkBackend._client is None:
            import docker
            SdkBackend._client = docker.from_env()
        return SdkBackend._client

    def is_available(self) -> bool:
        try:
            return bool(self._get_client().ping())
        except Exception:
            return False

    def container_exists(self, name: str) -> bool:
        try:
            return bool(self._get_client().containers.list(
                all=True, filters={"name": f"^{name}$"}))
        except Exception:
            return False

    def container_running(self, name: str) -> bool:
        try:
            return bool(self._get_client().containers.list(
                filters={"name": f"^{name}$"}))
        except Exception:
            return False

    def create_and_start(self, name: str, image: str,
                         flags: list[str], command: list[str]) -> bool:
        try:
            kw = _parse_run_flags(flags)
            self._get_client().containers.run(
                image, command=command, name=name, detach=True, **kw)
            return True
        except Exception:
            return False

    def start(self, name: str) -> bool:
        try:
            self._get_client().containers.get(name).start()
            return True
        except Exception:
            return False

    def remove(self, name: str) -> None:
        try:
            self._get_client().containers.get(name).remove(force=True)
        except Exception:
            pass

    def inspect_label(self, name: str, key: str) -> str:
        try:
            return str(self._get_client().containers.get(name).labels.get(key, "") or "")
        except Exception:
            return ""

    def inspect_mounts(self, name: str) -> list[str]:
        try:
            attrs = self._get_client().containers.get(name).attrs
            return [str(m.get("Destination", ""))
                    for m in (attrs.get("Mounts") or []) if m.get("Destination")]
        except Exception:
            return []

    def list_exited_ctf_containers(self) -> list[str]:
        try:
            cs = self._get_client().containers.list(
                all=True, filters={"label": "ctf-agent=true", "status": "exited"})
            return [c.name for c in cs if c.name]
        except Exception:
            return []

    def exec_run(self, args: list[str], *, timeout: int) -> subprocess.CompletedProcess:
        """经 docker SDK 底层 API 执行 (exec_create + exec_start + exec_inspect).

        ⚠️ docker-py 高层 Container.exec_run 无 timeout 参数 (7.x 签名不含),
        故用底层 API + 后台线程 join 实现超时 —— 与 CliBackend 的 subprocess
        timeout 语义一致: 宿主侧断开, 容器内进程继续执行。
        """
        name, cmd, cwd, env = _parse_exec_args(args)
        client = self._get_client()
        try:
            c = client.containers.get(name)
            # ⚠️ SDK exec_create 传字符串命令时按单个 argv 直接 exec (无 shell 语义,
            # 管道/重定向/; 全部失效)。CLI 端是 sh -lc <cmd>, 这里显式补回等价包装。
            exec_id = client.api.exec_create(
                c.id, ["sh", "-lc", cmd], stdout=True, stderr=True,
                workdir=cwd or None, environment=env or None,
            )["Id"]
        except Exception as e:
            return subprocess.CompletedProcess(
                args=args, returncode=1, stdout="", stderr=str(e))

        holder: dict[str, Any] = {}

        def _run() -> None:
            try:
                holder["out"] = client.api.exec_start(exec_id, demux=True)
                holder["code"] = int(client.api.exec_inspect(exec_id)["ExitCode"] or 0)
            except Exception as e:  # noqa: BLE001
                holder["err"] = e

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout if timeout and timeout > 0 else None)
        if "err" in holder:
            return subprocess.CompletedProcess(
                args=args, returncode=1, stdout="", stderr=str(holder["err"]))
        if t.is_alive():
            # 与 CLI subprocess.run(timeout=...) 相同契约: 抛 TimeoutExpired,
            # 上层 DockerClient.exec_cmd 捕获后返回 exit_code=-1 超时语义。
            raise subprocess.TimeoutExpired(cmd=args, timeout=timeout)

        out = holder.get("out")
        if isinstance(out, tuple):
            stdout_b, stderr_b = out
        else:
            stdout_b, stderr_b = (out or b""), b""
        return subprocess.CompletedProcess(
            args=args,
            returncode=int(holder.get("code", 0)),
            stdout=(stdout_b or b"").decode("utf-8", "replace"),
            stderr=(stderr_b or b"").decode("utf-8", "replace"),
        )

    def upload(self, name: str, local_path: str, remote_path: str) -> None:
        import io
        import tarfile
        # ⚠️ 容器内路径是 Linux 风格, 不能经 pathlib.Path 处理 (Windows 下会转成 \ 分隔)
        remote_dir = remote_path.rsplit("/", 1)[0] or "/"
        arcname = remote_path.rsplit("/", 1)[-1]
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            tar.add(local_path, arcname=arcname)
        buf.seek(0)
        try:
            self._get_client().containers.get(name).put_archive(remote_dir, buf)
        except Exception as e:
            raise RuntimeError(f"SDK put_archive 失败: {e}")

    def download(self, name: str, remote_path: str, local_path: str) -> None:
        import io
        import tarfile
        # get_archive 返回 (stream, stat), stream 是字节块生成器 (非 file-like)
        stream, _ = self._get_client().containers.get(name).get_archive(remote_path)
        buf = io.BytesIO(b"".join(stream))
        with tarfile.open(fileobj=buf, mode="r") as tar:
            member = tar.next()
            if member is None:
                raise RuntimeError(f"SDK get_archive 空: {remote_path}")
            f = tar.extractfile(member)
            data = f.read() if f else b""
        with open(local_path, "wb") as out:
            out.write(data)


def make_backend(name: str | DockerBackend | None, docker_cmd: str = "docker") -> DockerBackend:
    """后端工厂: "cli" → CliBackend; "sdk" → SdkBackend (需 docker 库, S9+).

    S10: docker-py 缺失时 sdk 请求降级为 cli (warnings 提示), 保降级链可用
    (设计文档 §12.6 Step 11 门禁: 降级链仍可用), 而非让工具链崩溃。
    """
    if isinstance(name, DockerBackend):
        return name
    if name in (None, "", "cli"):
        return CliBackend(docker_cmd=docker_cmd)
    if name == "sdk":
        try:
            import docker  # noqa: F401   (仅探测依赖, 实例化交给 SdkBackend)
        except ImportError:
            warnings.warn(
                "docker-py 未安装 (pip install 'ctf-agent[docker]'), "
                "DOCKER_BACKEND=sdk 回落为 cli 后端", stacklevel=2)
            return CliBackend(docker_cmd=docker_cmd)
        return SdkBackend(docker_cmd=docker_cmd)
    raise ValueError(f"未知 docker backend: {name!r} (可用: cli / sdk)")


# ============ Docker 客户端 ============

class DockerClient:
    """Docker 容器执行客户端（基于 docker CLI）.

    与 SSHClient 提供相同接口（exec_cmd / upload_file），
    上层工具可无差别调用。容器常驻，exec 延迟远低于 SSH 往返。

    用法：
        client = DockerClient(image="wing-goose", container_name="wing-goose-worker")
        result = client.exec_cmd("ls -la")   # CmdResult(stdout=..., exit_code=...)
        client.upload_file("local.bin", "/challenge/local.bin")
    """

    # 探测结果缓存（秒）：daemon 状态变化不频繁，避免每次 exec 都探测
    _AVAIL_CACHE_SEC = 60.0

    def __init__(
        self,
        image: str = "wing-goose:v2",
        container_name: str = "wing-goose-worker",
        workdir: str = "/challenge",
        *,
        docker_cmd: str = "docker",
        backend: str | DockerBackend = "sdk",   # S10: 默认 sdk (docker-py); cli 一键回退
        cpu_profile: str = _DEFAULT_PROFILE,
        cpu_cores: int = 0,
        mem_limit: str = "",
        task_id: str = "",
        workspace_dir: str = "",
        shared_dir: str = "",   # S13: 同题 agent 共享目录 (宿主目录 bind 挂载 /shared, 空则跳过)
        force_reset: bool = False,  # S13: 同题重做强制 rm+run 全新环境 (默认复用)
    ) -> None:
        self.image = image
        self.container_name = container_name
        self.workdir = workdir
        self.docker_cmd = docker_cmd
        # S8: 语义级后端（CLI subprocess / 未来 SDK）。所有底层容器操作经 self._backend。
        self._backend = make_backend(backend, docker_cmd=docker_cmd)
        # S4 多容器: 容器名由外部参数化 (f"wing-goose-{agent_id}"), task_id 标记所属题目
        self.task_id = task_id
        self._task_mismatch = False      # 容器已存在但 task label 不匹配 (S5 据此重置)
        # S5 工作区宿主挂载: 宿主目录 bind mount 到 /challenge/workspace (空则跳过挂载)
        self.workspace_dir = workspace_dir
        # S13 共享目录: 宿主目录 bind mount 到 /shared (同题 agent 互通文件, 空则跳过)
        self.shared_dir = shared_dir
        # S13 同题重做强制重置: True = ensure 时若容器存在也 rm+run (重做要全新环境)
        self.force_reset = force_reset
        # S3 资源配额: Profile 表 + 显式覆盖（容器创建时应用, §13.2）
        self.cpu_cores, self.mem_limit = resolve_quota(
            cpu_profile, cpu_cores=cpu_cores, mem_limit=mem_limit)
        self._container_ok = False          # 容器已确认运行
        self._avail: bool | None = None     # daemon 可用性缓存
        self._avail_at = 0.0

    # ---------- 可用性探测 ----------

    def is_available(self) -> bool:
        """探测 docker CLI + daemon 是否可用（带缓存）.

        Returns:
            True 表示可以执行 docker exec（daemon 运行中）
        """
        now = time.monotonic()
        if self._avail is not None and (now - self._avail_at) < self._AVAIL_CACHE_SEC:
            return self._avail
        self._avail = self._backend.is_available()
        self._avail_at = now
        return self._avail

    # ---------- 容器生命周期 ----------

    def _container_exists(self) -> bool:
        return self._backend.container_exists(self.container_name)

    def _container_running(self) -> bool:
        return self._backend.container_running(self.container_name)

    def ensure_container(self, task_id: str | None = None) -> bool:
        """确保工作容器存在且运行.

        不存在 → docker run -d（常驻）；已停止 → docker start；已运行 → 直接复用.

        S2 优化：`_container_ok` 为 True 时直接复用，**不再每次 docker ps 探测**
        （基线实测 docker ps ~85ms/次，是 exec 固定开销的主要部分）。
        容器消失由 exec_cmd 的错误模式检测触发 `_mark_container_failed()`，
        下次调用自动重新探测/重建（自愈兜底）。

        S4 多容器：容器名外部参数化（每 agent 独立容器）；`task_id` 用于
        检查已有容器的 task label —— 同题复用（不重建），异题标记
        `_task_mismatch=True`（S5 据此 rm+run 全新环境）。

        S5 跨题重置：`_task_mismatch=True` 且 `ENABLE_TASK_RESET` 开 → 销毁旧
        容器并重建（消除跨题污染）；开关关闭时退回 S4 兼容复用。

        Args:
            task_id: 题目标识（默认用构造时传入的 self.task_id）

        Returns:
            True 容器可用，False 失败（镜像缺失/daemon 异常）
        """
        if self._container_ok:
            return True
        effective_task = task_id or self.task_id
        try:
            if not self._container_exists():
                return self._run_new(effective_task)
            # S13 同题重做强制重置: 容器存在但本次要求全新环境 → rm+run
            # (第一次失败后重做, 默认仍复用现场; 需要干净环境时由调用方显式开启)
            if self.force_reset:
                self._backend.remove(self.container_name)
                return self._run_new(effective_task)
            # 已存在: 检查 task label 是否匹配（同题复用; 异题标记待 S5 重置）
            if effective_task:
                cur = self._container_task_label()
                self._task_mismatch = bool(cur and cur != effective_task)
                if self._task_mismatch and ENABLE_TASK_RESET:
                    # S5: 异题 → 销毁旧容器重建（全新环境, 消除跨题污染）
                    self._backend.remove(self.container_name)
                    return self._run_new(effective_task)
                # S14 修复: 容器是旧版本创建 (无附件挂载) 但 task label 恰好相同,
                # 或附件目录已指定但容器未挂载 /challenge/workspace → 必须重建,
                # 否则 agent 在容器内找不到附件, 白白浪费整题时间.
                if self.workspace_dir and not self._has_workspace_mount():
                    self._logger.warn(
                        f"容器 {self.container_name} 缺少 /challenge/workspace 挂载"
                        f" (workspace_dir={self.workspace_dir}), 重建")
                    self._backend.remove(self.container_name)
                    return self._run_new(effective_task)
            running = self._container_running()
            if not running:
                running = self._backend.start(self.container_name)
                if not running:
                    running = self._container_running()
            self._container_ok = running
            return self._container_ok
        except Exception:
            self._container_ok = False
            return False

    def _run_new(self, task_id: str | None) -> bool:
        """创建新容器（S4 标签 ctf-agent/task + S5 工作区挂载 + S3 资源配额）."""
        flags = ["--label", "ctf-agent=true"]
        if task_id:
            flags += ["--label", f"task={task_id}"]
        # S5 工作区宿主挂载: 宿主目录 → 容器 /challenge/workspace (rm 容器不影响宿主文件)
        if self.workspace_dir:
            try:
                Path(self.workspace_dir).mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
            flags += ["-v", f"{self.workspace_dir}:/challenge/workspace:rw"]
        # S13 同题共享目录挂载: 宿主目录 → 容器 /shared (多 agent 同题互通文件)
        if self.shared_dir:
            try:
                Path(self.shared_dir).mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
            flags += ["-v", f"{self.shared_dir}:/shared:rw"]
        # S3 资源配额（§13.2/§13.4）: CPU 宽松上限 + 内存严格上限
        # ⚠️ flags 必须在 IMAGE 之前, 否则被当作容器 command 参数 (CliBackend.create_and_start 保证)
        flags += [
            "--cpus", str(self.cpu_cores),
            "--memory", self.mem_limit, "--memory-swap", self.mem_limit,
            "--pids-limit", str(_PIDS_LIMIT),
            "--cap-add", "SYS_PTRACE", "--security-opt", "seccomp=unconfined",
        ]
        # GCTF25 本地靶机访问: agent 容器需经 host.docker.internal 连接宿主映射的靶机端口
        # (Docker Desktop / Linux 容器均支持 host-gateway 写法, 无副作用)
        flags += ["--add-host", "host.docker.internal:host-gateway"]
        if not self._backend.create_and_start(
                self.container_name, self.image, flags, ["sleep", "infinity"]):
            return False
        self._container_ok = True
        self._task_mismatch = False
        return True

    def _container_task_label(self) -> str:
        """读取已有容器的 task label（空字符串 = 无该标签）."""
        return self._backend.inspect_label(self.container_name, "task")

    def _has_workspace_mount(self) -> bool:
        """容器是否已挂载附件目录 /challenge/workspace (S5 复用校验)."""
        try:
            mounts = self._backend.inspect_mounts(self.container_name)
        except Exception:
            return False
        # 兼容容器内路径的多种写法 (WSL2 下 Docker Desktop 以 /challenge/workspace 挂载)
        return any(m.rstrip("/\\") == "/challenge/workspace" for m in mounts)

    @staticmethod
    def cleanup_orphans(docker_cmd: str = "docker") -> int:
        """S5: 清理残留孤儿容器（label ctf-agent=true 且已停止）.

        仅清理非运行容器 —— 不误删并行 agent 正在使用的容器。
        agent 启动时调用, 清除上次进程异常退出遗留的 stopped 容器。

        Returns:
            清理的容器数量
        """
        try:
            names = CliBackend(docker_cmd=docker_cmd).list_exited_ctf_containers()
        except Exception:
            return 0
        n = 0
        for name in names:
            subprocess.run(
                [docker_cmd, "rm", "-f", name],
                capture_output=True, text=True, timeout=60,
            )
            n += 1
        return n

    def _mark_container_failed(self) -> None:
        """标记容器可能已消失/停止，下次 ensure_container 重新探测."""
        self._container_ok = False

    # ---------- 命令执行 ----------

    def _build_exec_cmd(
        self,
        cmd: str,
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> list[str]:
        """构造 docker exec 命令（保持与 SSH _build_cmd 等价语义）."""
        args = [self.docker_cmd, "exec"]
        if cwd:
            args += ["-w", cwd]
        if env:
            for k, v in env.items():
                args += ["-e", f"{k}={v}"]
        # 容器内用 sh -lc 执行（保持 shell 语义 + 支持管道/重定向）
        args += [self.container_name, "sh", "-lc", cmd]
        return args

    def exec_cmd(
        self,
        cmd: str,
        *,
        cwd: str | None = None,
        timeout: int = 60,
        env: dict[str, str] | None = None,
    ) -> CmdResult:
        """在容器内执行命令.

        Args:
            cmd: shell 命令字符串
            cwd: 工作目录（默认容器 workdir）
            timeout: 超时秒数
            env: 额外环境变量

        Returns:
            CmdResult 包含 stdout/stderr/exit_code

        Raises:
            RuntimeError: docker 不可用 / 容器无法启动
        """
        if not self.is_available():
            raise RuntimeError("docker daemon 不可用 (Docker Desktop 未运行?)")
        if not self.ensure_container():
            raise RuntimeError(
                f"容器 {self.container_name} 无法启动 (镜像 {self.image} 未构建或 daemon 异常)")

        # WING-Goose: 专用工具 (osint/web/pwn 等) 默认 cwd=/tmp/ctf_workspace/ 等
        # 在容器内不存在 → docker exec -w 会失败. 先幂等创建目录 (仅非默认 workdir 时).
        if cwd and cwd != self.workdir:
            try:
                self._backend.exec_run(
                    [self.docker_cmd, "exec", self.container_name,
                     "mkdir", "-p", cwd],
                    timeout=15,
                )
            except Exception:  # noqa: BLE001 - 目录创建失败不阻断主命令
                pass

        effective_cwd = cwd or self.workdir
        args = self._build_exec_cmd(cmd, cwd=effective_cwd, env=env)
        started = time.monotonic()
        try:
            r = self._backend.exec_run(args, timeout=timeout + 10)
            # S2+S6: exec 报容器消失/停止 → 标记失效 + 本调用内自愈重试一次。
            # 背景: S2 去探测使 _container_ok=True 时跳过 ensure 探测; 若容器被
            # kill (docker kill 后 exec 报 is not running), 不重试则恢复要推迟到
            # 下一次调用。这里本调用内自愈 → "下一次 exec 即恢复" 成立 (<10s 门禁)。
            if (r.returncode != 0 and self._container_ok
                    and _looks_like_container_gone(r.stderr or "")):
                self._mark_container_failed()
                if self.ensure_container():
                    r = self._backend.exec_run(args, timeout=timeout + 10)
            return CmdResult(
                stdout=r.stdout or "",
                stderr=r.stderr or "",
                exit_code=r.returncode,
                cmd=cmd,
                elapsed=time.monotonic() - started,
            )
        except subprocess.TimeoutExpired:
            return CmdResult(
                stdout="",
                stderr=f"[TIMEOUT] 命令超时 ({timeout}s)，已强制终止",
                exit_code=-1,
                cmd=cmd,
                elapsed=time.monotonic() - started,
            )
        except FileNotFoundError:
            raise RuntimeError("docker CLI 未找到 (请安装 Docker Desktop)")

    # ---------- 文件传输 ----------

    def upload_file(self, local_path: str | Path, remote_path: str) -> None:
        """上传本地文件到容器（docker cp）.

        Args:
            local_path: 本地文件路径（Windows 路径）
            remote_path: 容器内目标路径

        Raises:
            FileNotFoundError: 本地文件不存在
            RuntimeError: docker cp 失败
        """
        local_path = Path(local_path)
        if not local_path.exists():
            raise FileNotFoundError(f"本地文件不存在: {local_path}")
        if not self.ensure_container():
            raise RuntimeError(f"容器 {self.container_name} 不可用")
        self._backend.upload(self.container_name, str(local_path), remote_path)

    def download_file(self, remote_path: str, local_path: str | Path) -> None:
        """从容器下载文件到本地（docker cp）."""
        local_path = Path(local_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.ensure_container():
            raise RuntimeError(f"容器 {self.container_name} 不可用")
        self._backend.download(self.container_name, remote_path, str(local_path))

    def close(self) -> None:
        """释放资源（容器保持运行，供复用）."""
        pass


# ============ 工具 ============

class DockerExecTool(Tool):
    """通用 Docker 容器命令执行工具.

    在常驻 Linux 容器内执行任意 shell 命令（nmap/strings/objdump/file/xxd/binwalk/
    gdb/pwntools 等）。与 ssh_exec 同签名，Docker Desktop 环境下延迟更低。

    安全策略（与 ssh_exec 对齐）：
    - 工作目录默认容器 workdir（/challenge）
    - 默认超时 60s，最长 600s
    - 支持 timeout 语义档位 quick/normal/long/background（B+ 后台执行）
    """

    name = "ssh_exec"
    # WING-Goose: 主名与 Kali 经验一致 (ssh_exec), docker_exec 为别名 → 经验跨场景可用
    aliases = ("docker_exec",)
    description = (
        "在 Linux 容器内执行任意 shell 命令（如 nmap/strings/objdump/file/xxd/binwalk/"
        "gdb/python3/radare2/tshark/sqlmap/gobuster 等）。"
        "工具名 ssh_exec 与 Kali 版一致 (docker 后端), 别名 docker_exec。"
        "适用于需要 Linux 环境的 CTF 工具调用。\n"
        "【工具清单】先执行 `cat /tools.txt` 查看容器内全部预装工具及其分类"
        "（网络/逆向/取证/隐写/密码学/Python 库等），确认工具是否可用；"
        "缺少时用 `apt-get install -y <pkg>` 或 `pip3 install <pkg>` 临时安装"
        "（已预配清华镜像源，下载快）。\n"
        "超时控制: timeout 支持语义档位 quick(30s)/normal(120s)/long(600s)/"
        "background(立即后台) 或整数秒数。超过等待窗口命令自动转入后台运行,"
        "工具立即返回 PID 和日志文件路径, 用 ssh_exec 'cat <日志>' 随时查看结果。"
        "长任务 (exploit 运行/爆破/本地验证) 建议设 timeout=long 或 background,"
        "不要死等; 快速命令 (ls/cat/file) 用默认或 quick。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "要执行的 shell 命令（如 'nmap -p 80 127.0.0.1'）",
            },
            "cwd": {
                "type": "string",
                "description": "工作目录（默认容器 /challenge）",
            },
            "timeout": {
                "type": ["integer", "string"],
                "description": "超时控制: 整数秒数 (如 180) 或档位 "
                    "quick=30s / normal=120s(默认) / long=600s / background=立即后台。"
                    "超过等待窗口命令自动转后台运行 (不杀进程), 返回 PID+日志路径, "
                    "用 docker_exec 'cat <日志>' 查看结果。",
            },
        },
        "required": ["command"],
    }

    def __init__(
        self,
        docker_client: DockerClient,
        *,
        default_cwd: str | None = None,
        default_timeout: int = 60,
    ) -> None:
        self.docker = docker_client
        self.default_cwd = default_cwd or docker_client.workdir
        self.default_timeout = default_timeout

    def execute(
        self,
        command: str,
        cwd: str | None = None,
        timeout: Any = None,
        **_: Any,
    ) -> str:
        if not command or not command.strip():
            return "ERROR: command 不能为空"

        effective_cwd = cwd or self.default_cwd
        wait_sec = _resolve_timeout(timeout)

        # S1 快路径: 未声明/quick/短等待 → 直接 exec 同步执行（消灭固定 sleep 1 轮询）
        if _use_fast_path(timeout, wait_sec):
            return self._exec_fast(command, effective_cwd, wait_sec)

        # 长任务/background → B+ 后台执行（nohup + 日志轮询, 转后台语义保留）
        import base64
        payload_b64 = base64.b64encode(command.encode("utf-8")).decode("ascii")
        bg_script = _build_bg_script(payload_b64, effective_cwd, wait_sec, runner="sh {f}")
        client_timeout = max(15, wait_sec + 40) if wait_sec > 0 else 20
        try:
            result = self.docker.exec_cmd(bg_script, cwd=effective_cwd, timeout=client_timeout)
        except RuntimeError as e:
            return f"ERROR: docker 不可用: {e}"

        bg_output = _parse_bg_output(result, command, wait_sec)
        if bg_output is not None:
            return bg_output

        # 无后台标记（异常路径）→ 回退原逻辑
        parts: list[str] = [f"$ {command}"]
        parts.append(f"[exit_code={result.exit_code}, elapsed={result.elapsed:.2f}s]")
        if result.stdout:
            parts.append(_truncate(result.stdout))
        if result.stderr:
            parts.append(f"[stderr]\n{_truncate(result.stderr)}")
        if not result.stdout and not result.stderr:
            parts.append("(无输出)")
        output = "\n".join(parts)
        if not result.is_success and result.exit_code != 0:
            output = f"ERROR: 命令退出码 {result.exit_code}\n{output}"
        return output

    def _exec_fast(
        self,
        command: str,
        cwd: str,
        wait_sec: int,
    ) -> str:
        """S1 快路径: 直接 docker exec 同步执行.

        跳过 B+ 后台轮询（nohup + sleep 1），快速命令无固定 ~1s 开销。
        输出格式与 B+ 完成路径一致（`$ cmd` + `[完成, elapsed=...]`）。
        宿主侧超时（命令超出等待窗口）时返回提示，引导以 background 档位重试。
        """
        client_timeout = wait_sec + _BG_CLIENT_BUFFER if wait_sec > 0 else 40
        try:
            result = self.docker.exec_cmd(command, cwd=cwd, timeout=client_timeout)
        except RuntimeError as e:
            return f"ERROR: docker 不可用: {e}"

        parts: list[str] = [f"$ {command}"]
        if result.exit_code == -1:
            parts.append(f"[超时 {wait_sec}s, 宿主侧已断开; 容器内进程可能仍在执行]")
            parts.append("  可用 timeout=background 重新执行以获取 PID 追踪")
        else:
            parts.append(f"[完成, elapsed={result.elapsed:.2f}s]")
        if result.stdout:
            parts.append(_truncate(result.stdout))
        if result.stderr:
            parts.append(f"[stderr]\n{_truncate(result.stderr)}")
        if not result.stdout and not result.stderr:
            parts.append("(无输出)")
        output = "\n".join(parts)
        if result.exit_code not in (0, -1):
            output = f"ERROR: 命令退出码 {result.exit_code}\n{output}"
        return output


class DockerPythonTool(Tool):
    """在 Docker 容器内执行 Python 3 脚本.

    与 ssh_python 同签名。可用库：pwntools (pwn)、pycryptodome (Crypto)、z3、
    capstone、requests 等（镜像预装）。用于 crypto 解密、pwn exp 编写、二进制分析。
    """

    name = "ssh_python"
    # WING-Goose: 主名与 Kali 经验一致 (ssh_python), docker_python 为别名
    aliases = ("docker_python",)
    description = (
        "在 Linux 容器内执行 Python 3 脚本。"
        "工具名 ssh_python 与 Kali 版一致 (docker 后端), 别名 docker_python。"
        "可用库：pwntools (pwn)、pycryptodome (Crypto)、z3、capstone、requests 等。"
        "适用于 crypto 解密、pwn exp 编写、二进制分析等复杂逻辑。\n"
        "【库清单】先执行 `cat /tools.txt` 查看容器内全部预装 Python 库；"
        "缺少时用 `pip3 install <pkg>` 临时安装（已预配清华镜像源，下载快）。\n"
        "超时控制: timeout 支持语义档位 quick(30s)/normal(120s)/long(600s)/"
        "background(立即后台) 或整数秒数。超过等待窗口脚本自动转入后台运行,"
        "工具立即返回 PID 和日志文件路径, 用 ssh_exec 'cat <日志>' 随时查看结果。"
        "长任务 (exploit 交互/爆破/本地验证) 建议设 timeout=long 或 background,"
        "不要死等; 快速计算用默认或 quick。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "script": {
                "type": "string",
                "description": "Python 脚本内容（多行字符串）",
            },
            "timeout": {
                "type": ["integer", "string"],
                "description": "超时控制: 整数秒数 (如 180) 或档位 "
                    "quick=30s / normal=120s(默认) / long=600s / background=立即后台。"
                    "超过等待窗口脚本自动转后台运行 (不杀进程), 返回 PID+日志路径, "
                    "用 docker_exec 'cat <日志>' 查看结果。",
            },
        },
        "required": ["script"],
    }

    def __init__(
        self,
        docker_client: DockerClient,
        *,
        default_timeout: int = 60,
    ) -> None:
        self.docker = docker_client
        self.default_timeout = default_timeout

    def execute(
        self,
        script: str,
        timeout: Any = None,
        **_: Any,
    ) -> str:
        if not script or not script.strip():
            return "ERROR: script 不能为空"

        wait_sec = _resolve_timeout(timeout)

        # S1 快路径: 直接 python3 -c 注入执行（base64 防引号问题）
        if _use_fast_path(timeout, wait_sec):
            return self._exec_py_fast(script, wait_sec)

        # 长任务/background → B+ 后台执行
        import base64
        script_b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
        bg_script = _build_bg_script(script_b64, "/challenge/", wait_sec, runner="python3 {f}")
        client_timeout = max(15, wait_sec + 40) if wait_sec > 0 else 20
        try:
            result = self.docker.exec_cmd(bg_script, cwd="/challenge/", timeout=client_timeout,
                                          env={"TERM": "xterm"})
        except RuntimeError as e:
            return f"ERROR: docker 不可用: {e}"

        bg_output = _parse_bg_output(result, "[docker_python]", wait_sec)
        if bg_output is not None:
            return bg_output

        parts: list[str] = [f"[python3 执行, elapsed={result.elapsed:.2f}s]"]
        if result.stdout:
            parts.append(_truncate(result.stdout))
        if result.stderr:
            parts.append(f"[stderr]\n{_truncate(result.stderr)}")
        if not result.stdout and not result.stderr:
            parts.append("(无输出)")
        output = "\n".join(parts)
        if not result.is_success:
            output = f"ERROR: python3 退出码 {result.exit_code}\n{output}"
        return output

    def _exec_py_fast(self, script: str, wait_sec: int) -> str:
        """S1 快路径: python3 -c 直接执行（base64 注入, 避免引号转义问题）."""
        import base64
        script_b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
        py_cmd = (
            "python3 -c \"import base64;"
            f"exec(base64.b64decode('{script_b64}').decode())\""
        )
        client_timeout = wait_sec + _BG_CLIENT_BUFFER if wait_sec > 0 else 40
        try:
            result = self.docker.exec_cmd(py_cmd, cwd="/challenge/", timeout=client_timeout,
                                          env={"TERM": "xterm"})
        except RuntimeError as e:
            return f"ERROR: docker 不可用: {e}"

        parts: list[str] = [f"[python3 执行, elapsed={result.elapsed:.2f}s]"]
        if result.exit_code == -1:
            parts.append(f"[超时 {wait_sec}s, 宿主侧已断开; 容器内进程可能仍在执行]")
            parts.append("  可用 timeout=background 重新执行以获取 PID 追踪")
        if result.stdout:
            parts.append(_truncate(result.stdout))
        if result.stderr:
            parts.append(f"[stderr]\n{_truncate(result.stderr)}")
        if not result.stdout and not result.stderr:
            parts.append("(无输出)")
        output = "\n".join(parts)
        if result.exit_code not in (0, -1):
            output = f"ERROR: python3 退出码 {result.exit_code}\n{output}"
        return output


class DockerFileUploadTool(Tool):
    """上传本地文件到 Docker 容器."""

    name = "ssh_upload"
    # WING-Goose: 主名与 Kali 经验一致 (ssh_upload), docker_upload 为别名
    aliases = ("docker_upload",)
    description = (
        "上传本地文件到 Linux 容器的指定路径。"
        "工具名 ssh_upload 与 Kali 版一致 (docker 后端), 别名 docker_upload。"
        "用于将题目附件（ELF/APK/流量包等）传到容器进行分析。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "local_path": {
                "type": "string",
                "description": "本地文件路径（Windows 路径）",
            },
            "remote_path": {
                "type": "string",
                "description": "容器内目标路径（如 /challenge/task1/challenge.elf）",
            },
        },
        "required": ["local_path", "remote_path"],
    }

    def __init__(self, docker_client: DockerClient) -> None:
        self.docker = docker_client

    def execute(
        self,
        local_path: str,
        remote_path: str,
        **_: Any,
    ) -> str:
        try:
            self.docker.upload_file(local_path, remote_path)
            return f"上传成功: {remote_path}"
        except FileNotFoundError as e:
            return f"ERROR: 本地文件不存在: {e}"
        except Exception as e:  # noqa: BLE001
            return f"ERROR: 上传失败: {type(e).__name__}: {e}"


# ============ 工厂 ============

def docker_tools(
    docker_client: DockerClient,
    *,
    default_timeout: int = 60,
) -> list[Tool]:
    """创建基于 DockerClient 的工具集.

    仅当 docker 可用时返回非空列表；不可用返回空列表，
    由 default_tools 自动降级到 ssh 工具集。

    Args:
        docker_client: 已配置的 DockerClient 实例
        default_timeout: 默认命令超时

    Returns:
        Docker 工具列表（DockerExecTool + DockerPythonTool + DockerFileUploadTool）
    """
    if not docker_client.is_available():
        return []
    return [
        DockerExecTool(docker_client, default_timeout=default_timeout),
        DockerPythonTool(docker_client, default_timeout=default_timeout),
        DockerFileUploadTool(docker_client),
    ]


__all__ = [
    "DockerClient",
    "DockerExecTool",
    "DockerFileUploadTool",
    "DockerPythonTool",
    "docker_tools",
]
