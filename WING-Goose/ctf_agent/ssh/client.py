"""SSH-Kali 沙箱连接器（L6 基础设施层）.

依据 README §3.1，使用 paramiko 实现 SSH 连接池与命令执行接口。
Windows 宿主机通过此模块与 Kali Linux 沙箱通信，执行 nmap/pwntools/strings 等工具。

核心接口：
    client = SSHClient(host="192.168.85.140", user="root", password="xxx")
    result = client.exec_cmd("whoami")  # CmdResult(stdout="root\n", ...)
    client.upload_file("local.bin", "/tmp/ctf_workspace/task1/local.bin")
    client.close()

也支持上下文管理器：
    with SSHClient(...) as client:
        client.exec_cmd("ls")
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import paramiko


# ============ 命令执行结果 ============

@dataclass
class CmdResult:
    """SSH 命令执行结果."""

    stdout: str
    stderr: str
    exit_code: int
    cmd: str = ""
    elapsed: float = 0.0  # 耗时（秒）

    @property
    def is_success(self) -> bool:
        """命令是否成功（exit_code == 0）."""
        return self.exit_code == 0

    @property
    def output(self) -> str:
        """合并 stdout + stderr 的便捷访问."""
        if self.stderr:
            return f"{self.stdout}\n[stderr]\n{self.stderr}"
        return self.stdout

    def __str__(self) -> str:
        return (
            f"$ {self.cmd}\n"
            f"[exit={self.exit_code}, elapsed={self.elapsed:.2f}s]\n"
            f"{self.stdout}"
            + (f"\n[stderr]\n{self.stderr}" if self.stderr else "")
        )


# ============ SSH 客户端 ============

class SSHClient:
    """SSH 连接客户端（基于 paramiko）.

    用法：
        client = SSHClient(host="192.168.85.140", user="root", password="xxx")
        client.connect()
        result = client.exec_cmd("whoami")
        client.close()

    或使用上下文管理器：
        with SSHClient(...) as client:
            result = client.exec_cmd("whoami")
    """

    def __init__(
        self,
        host: str,
        user: str = "root",
        password: str | None = None,
        key_path: str | None = None,
        port: int = 22,
        *,
        connect_timeout: float = 15.0,
        keepalive_interval: int = 30,
    ) -> None:
        self.host = host
        self.user = user
        self.password = password
        self.key_path = key_path
        self.port = port
        self.connect_timeout = connect_timeout
        self.keepalive_interval = keepalive_interval

        self._client: paramiko.SSHClient | None = None
        self._sftp: paramiko.SFTPClient | None = None

    # ============ 连接管理 ============

    def connect(self) -> None:
        """建立 SSH 连接.

        Raises:
            paramiko.SSHException: 连接失败
            socket.timeout: 连接超时
        """
        if self._client is not None:
            return  # 已连接

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        kwargs: dict[str, Any] = {
            "hostname": self.host,
            "port": self.port,
            "username": self.user,
            "timeout": self.connect_timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if self.key_path:
            kwargs["key_filename"] = self.key_path
        elif self.password:
            kwargs["password"] = self.password
        else:
            raise ValueError("必须提供 password 或 key_path 之一")

        client.connect(**kwargs)
        # 启用 keepalive 防止 NAT 超时断连
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(self.keepalive_interval)
        self._client = client

    def close(self) -> None:
        """关闭 SSH 连接."""
        if self._sftp is not None:
            self._sftp.close()
            self._sftp = None
        if self._client is not None:
            self._client.close()
            self._client = None

    @property
    def is_connected(self) -> bool:
        """是否已建立有效连接."""
        if self._client is None:
            return False
        transport = self._client.get_transport()
        return transport is not None and transport.is_active()

    def __enter__(self) -> "SSHClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        self.close()

    def _ensure_connected(self) -> paramiko.SSHClient:
        """确保已连接，返回底层 SSHClient."""
        if self._client is None or not self.is_connected:
            self.connect()
        assert self._client is not None
        return self._client

    # ============ 命令执行 ============

    def exec_cmd(
        self,
        cmd: str,
        *,
        cwd: str | None = None,
        timeout: int = 60,
        env: dict[str, str] | None = None,
    ) -> CmdResult:
        """在远程 Kali 执行命令.

        Args:
            cmd: shell 命令字符串
            cwd: 工作目录（None 表示默认 /root）
            timeout: 超时秒数
            env: 额外环境变量

        Returns:
            CmdResult 包含 stdout/stderr/exit_code

        Raises:
            paramiko.SSHException: 命令执行失败
            socket.timeout: 命令超时
        """
        # 构造完整命令（cd + env + cmd）
        full_cmd = self._build_cmd(cmd, cwd=cwd, env=env)

        import time
        import threading

        # Sprint 23: SSH 断连自动重试 (最多 2 次)
        # 解决长时间运行时 SSH session not active 导致 agent 卡死的问题
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                client = self._ensure_connected()
                if attempt > 0:
                    # 重连后等待一下确保稳定
                    time.sleep(1)
                started = time.monotonic()
                stdin, stdout, stderr = client.exec_command(full_cmd, timeout=timeout)
                break
            except (paramiko.SSHException, EOFError, OSError) as e:
                last_error = e
                # 强制标记为断开, 下次 _ensure_connected 会重连
                self._client = None
                if attempt < 2:
                    continue
                raise
        else:
            if last_error:
                raise last_error

        # recv_exit_status() 会无限阻塞，paramiko 的 timeout 只影响 read。
        # 用线程+join 实现真正的命令超时，超时后关闭 channel 释放资源。
        # (修复 Pwn 题 pwntools recv()/interactive() 卡住导致整题永久阻塞)
        result_holder: dict = {"exit_code": None, "error": None}

        def _wait_exit():
            try:
                result_holder["exit_code"] = stdout.channel.recv_exit_status()
            except Exception as e:  # noqa: BLE001
                result_holder["error"] = e

        waiter = threading.Thread(target=_wait_exit, daemon=True)
        waiter.start()
        waiter.join(timeout=timeout)

        if waiter.is_alive():
            # 超时：关闭 channel 强制中断远程命令
            try:
                stdout.channel.close()
            except Exception:  # noqa: BLE001
                pass
            elapsed = time.monotonic() - started
            # 尽量读取已有输出
            out = ""
            err = ""
            try:
                out = stdout.read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                pass
            try:
                err = stderr.read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                pass
            return CmdResult(
                stdout=out,
                stderr=err + f"\n[TIMEOUT] 命令超时 ({timeout}s)，已强制终止",
                exit_code=-1,
                cmd=full_cmd,
                elapsed=elapsed,
            )

        exit_code = result_holder["exit_code"]
        if result_holder["error"] is not None:
            raise result_holder["error"]
        elapsed = time.monotonic() - started

        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")

        return CmdResult(
            stdout=out,
            stderr=err,
            exit_code=exit_code,
            cmd=full_cmd,
            elapsed=elapsed,
        )

    @staticmethod
    def _build_cmd(
        cmd: str,
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> str:
        """构造完整命令（mkdir + cd + env 前缀 + cmd）."""
        parts: list[str] = []
        if cwd:
            # 先创建目录再 cd，避免目录不存在导致命令失败
            parts.append(f"mkdir -p {shlex.quote(cwd)}")
            parts.append(f"cd {shlex.quote(cwd)}")
        if env:
            for k, v in env.items():
                parts.append(f"export {k}={shlex.quote(v)}")
        parts.append(cmd)
        return " && ".join(parts)

    # ============ 文件传输 ============

    def _get_sftp(self) -> paramiko.SFTPClient:
        """获取 SFTP 客户端（惰性初始化）."""
        if self._sftp is None:
            client = self._ensure_connected()
            self._sftp = client.open_sftp()
        return self._sftp

    def upload_file(
        self,
        local_path: str | Path,
        remote_path: str,
        *,
        confirm: bool = True,
    ) -> None:
        """上传文件到 Kali.

        Args:
            local_path: 本地文件路径
            remote_path: 远程目标路径（如 /tmp/ctf_workspace/task1/file.bin）
            confirm: 是否调用 sftp.put 的 confirm 参数（默认 True）

        Raises:
            FileNotFoundError: 本地文件不存在
            IOError: 远程写入失败
        """
        local_path = Path(local_path)
        if not local_path.exists():
            raise FileNotFoundError(f"本地文件不存在: {local_path}")

        sftp = self._get_sftp()
        # 确保远程目录存在
        remote_dir = os.path.dirname(remote_path)
        if remote_dir:
            self._ensure_remote_dir(remote_dir)
        sftp.put(str(local_path), remote_path, confirm=confirm)

    def download_file(
        self,
        remote_path: str,
        local_path: str | Path,
    ) -> None:
        """从 Kali 下载文件.

        Args:
            remote_path: 远程文件路径
            local_path: 本地目标路径

        Raises:
            FileNotFoundError: 远程文件不存在
        """
        local_path = Path(local_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        sftp = self._get_sftp()
        sftp.get(remote_path, str(local_path))

    def _ensure_remote_dir(self, remote_dir: str) -> None:
        """递归创建远程目录."""
        if not remote_dir or remote_dir == "/":
            return
        sftp = self._get_sftp()
        # 检查目录是否已存在
        try:
            sftp.stat(remote_dir)
            return  # 已存在
        except IOError:
            pass
        # 递归创建父目录
        parent = os.path.dirname(remote_dir)
        if parent and parent != remote_dir:
            self._ensure_remote_dir(parent)
        try:
            sftp.mkdir(remote_dir)
        except IOError:
            # 并发情况下可能已被创建，忽略
            pass

    # ============ 批量传输 (Sprint 6 优化) ============

    def upload_directory(
        self,
        local_dir: str | Path,
        remote_dir: str,
        *,
        method: str = "tar",  # "tar" | "individual"
    ) -> dict[str, Any]:
        """批量上传目录到 Kali（Sprint 6 优化）.

        Args:
            local_dir: 本地目录
            remote_dir: 远程目标目录
            method: 上传方法
                - "tar"（推荐）：本地 tar 压缩 → 单次 SFTP 上传 → 远端解压
                - "individual"：逐文件 SFTP（兼容性好但慢）

        Returns:
            dict: {"files": int, "bytes": int, "method": str, "elapsed": float, "checksum_ok": bool}
        """
        import hashlib
        import tarfile
        import tempfile
        import time

        local_dir = Path(local_dir)
        if not local_dir.is_dir():
            raise FileNotFoundError(f"本地目录不存在: {local_dir}")

        files = list(local_dir.rglob("*"))
        file_count = sum(1 for f in files if f.is_file())
        if file_count == 0:
            return {"files": 0, "bytes": 0, "method": method, "elapsed": 0.0, "checksum_ok": True}

        started = time.monotonic()

        if method == "tar":
            # 1. 本地打 tar
            with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
                tar_path = Path(tmp.name)
            with tarfile.open(tar_path, "w:gz") as tf:
                tf.add(str(local_dir), arcname=local_dir.name)

            # 2. 计算本地校验和
            local_sha = hashlib.sha256(tar_path.read_bytes()).hexdigest()
            tar_size = tar_path.stat().st_size

            # 3. 上传 tar
            remote_tar = f"/tmp/_upload_{tar_path.name}"
            self._ensure_remote_dir(remote_dir)
            sftp = self._get_sftp()
            sftp.put(str(tar_path), remote_tar)

            # 4. 远端校验和
            sha_result = self.exec_cmd(f"sha256sum {remote_tar}")
            remote_sha = sha_result.stdout.split()[0] if sha_result.stdout else ""
            checksum_ok = (local_sha == remote_sha)

            # 5. 远端解压
            self.exec_cmd(
                f"cd {remote_dir} && tar xzf {remote_tar}"
                f" && mv {local_dir.name}/* . 2>/dev/null; rm -rf {local_dir.name} {remote_tar}"
            )

            # 6. 清理本地
            tar_path.unlink(missing_ok=True)

            elapsed = time.monotonic() - started
            return {
                "files": file_count,
                "bytes": tar_size,
                "method": "tar",
                "elapsed": elapsed,
                "checksum_ok": checksum_ok,
                "local_sha256": local_sha,
                "remote_sha256": remote_sha,
            }
        else:
            # 个别文件上传（兼容路径）
            sftp = self._get_sftp()
            self._ensure_remote_dir(remote_dir)
            total_bytes = 0
            for f in files:
                if not f.is_file():
                    continue
                rel = f.relative_to(local_dir)
                remote_path = os.path.join(remote_dir, str(rel).replace("\\", "/"))
                if f.parent != local_dir:
                    self._ensure_remote_dir(os.path.dirname(remote_path))
                sftp.put(str(f), remote_path)
                total_bytes += f.stat().st_size
            elapsed = time.monotonic() - started
            return {
                "files": file_count,
                "bytes": total_bytes,
                "method": "individual",
                "elapsed": elapsed,
                "checksum_ok": True,
            }

    # ============ 便捷方法 ============

    def whoami(self) -> str:
        """快速获取当前用户名（用于连接测试）."""
        result = self.exec_cmd("whoami")
        return result.stdout.strip()

    def file_exists(self, remote_path: str) -> bool:
        """检查远程文件是否存在."""
        sftp = self._get_sftp()
        try:
            sftp.stat(remote_path)
            return True
        except IOError:
            return False

    def list_dir(self, remote_path: str = ".") -> list[str]:
        """列出远程目录内容."""
        sftp = self._get_sftp()
        return sftp.listdir(remote_path)


# ============ 工厂 ============

def ssh_client_from_settings(settings: Any) -> SSHClient:
    """从 Settings 创建 SSHClient.

    Args:
        settings: ctf_agent.config.Settings 实例

    Returns:
        已配置但未连接的 SSHClient

    Raises:
        ValueError: 配置不完整
    """
    host = settings.kali_host
    user = settings.kali_user
    password = settings.kali_pass.get_secret_value() if settings.kali_pass else None
    key_path = settings.kali_key_path or None
    port = settings.kali_port

    if not host:
        raise ValueError("KALI_HOST 未配置")
    if not user:
        raise ValueError("KALI_USER 未配置")
    if not password and not key_path:
        raise ValueError("必须配置 KALI_PASS 或 KALI_KEY_PATH")

    return SSHClient(
        host=host,
        user=user,
        password=password,
        key_path=key_path,
        port=port,
    )


__all__ = ["CmdResult", "SSHClient", "ssh_client_from_settings"]
