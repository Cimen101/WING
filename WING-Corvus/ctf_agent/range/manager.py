"""靶场管理器：在 Kali 上构建/启动/停止 CTF 题目容器。

安全约束（用户输入：flag 不得通过非正常途径被 agent 获取）：
- flag 随机生成，仅在 `docker run -e FLAG_FULL=...` 注入容器（容器内由 flag_replace
  写文件，agent 通过漏洞读取属正常途径）
- 明文 flag 仅持久化到本地 .range_state.json（chmod 600 + gitignore），仅供 verify 校验
- 本模块对外只暴露 verify(flag)->bool，绝不返回真 flag；日志/状态一律 mask()
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from ctf_agent.config import Settings, get_settings
from ctf_agent.ssh.client import SSHClient, ssh_client_from_settings

from .catalog import (
    ALL, ChallengeSpec, by_name, container_name, dynamic_challenges,
    image_name, local_container_dir,
)
from .flag import gen_flag, mask


DEFAULT_STATE_PATH = Path(__file__).resolve().parent / ".range_state.json"
REMOTE_ROOT = "/opt/athena"


class RangeManager:
    """靶场生命周期管理器（构建/启动/停止/校验）."""

    def __init__(
        self,
        settings: Settings | None = None,
        state_path: str | Path = DEFAULT_STATE_PATH,
        ssh_client: SSHClient | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.state_path = Path(state_path)
        self._ssh = ssh_client
        self._state: dict[str, dict[str, Any]] = self._load_state()

    # ---------- 本地状态（flag 明文，chmod 600） ----------
    def _load_state(self) -> dict[str, dict[str, Any]]:
        if self.state_path.exists():
            try:
                return json.loads(self.state_path.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _save_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(
            json.dumps(self._state, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        try:
            os.chmod(self.state_path, 0o600)
        except OSError:
            pass

    # ---------- SSH ----------
    def _client(self) -> SSHClient:
        if self._ssh is None:
            if not self.settings.has_kali_config():
                raise RuntimeError(
                    "Kali 未配置（需 KALI_HOST/KALI_USER/KALI_PASS），无法部署靶场"
                )
            self._ssh = ssh_client_from_settings(self.settings)
        return self._ssh

    # ---------- 解析题目 ----------
    def _resolve(self, name: str | None, all_: bool) -> list[ChallengeSpec]:
        if all_:
            return dynamic_challenges()
        if not name:
            raise ValueError("需提供 name 或 all=true")
        spec = by_name(name)
        if spec is None:
            raise ValueError(f"未知题目: {name}")
        if not spec["dynamic"]:
            raise ValueError(f"{name} 是静态题，无需部署靶场")
        return [spec]

    # ---------- 部署单个题目 ----------
    def _deploy_one(self, spec: ChallengeSpec, client: SSHClient) -> dict[str, Any]:
        cname = container_name(spec)
        remote = f"{REMOTE_ROOT}/{cname}"  # 用 slug 目录名，避免空格/括号被 shell 解析
        local = local_container_dir(spec)
        # 1) 上传构建上下文
        client.exec_cmd(f"rm -rf {remote}")
        upload = client.upload_directory(local, remote, method="tar")
        # 2) 构建镜像
        build = client.exec_cmd(
            f"cd {remote} && docker build -t {image_name(spec)} .", timeout=900
        )
        if not build.is_success:
            return {"ok": False, "stage": "build", "error": build.output[-2000:], "upload": upload}
        # 3) 启动容器（注入随机 flag）
        up = self._up_one(spec, client)
        up["build_log_tail"] = build.output[-500:]
        up["upload"] = upload
        return up

    def _up_one(self, spec: ChallengeSpec, client: SSHClient | None = None) -> dict[str, Any]:
        client = client or self._client()
        cname = container_name(spec)
        flag = gen_flag()
        port = spec["host_port"]
        client.exec_cmd(f"docker rm -f {cname} 2>/dev/null")
        run = client.exec_cmd(
            f"docker run -d --name {cname} -p {port}:{spec['container_port']} "
            f"--restart unless-stopped -e FLAG_FULL='{flag}' {image_name(spec)}",
            timeout=120,
        )
        if not run.is_success:
            return {"ok": False, "stage": "run", "error": run.output[-2000:]}
        self._state[cname] = {
            "name": spec["name"],
            "flag": flag,
            "host_port": port,
            "status": "running",
        }
        self._save_state()
        return {"ok": True, "container": cname, "host_port": port, "flag_masked": mask(flag)}

    # ---------- 对外 API ----------
    def deploy(self, name: str | None = None, all_: bool = False) -> dict[str, Any]:
        specs = self._resolve(name, all_)
        client = self._client()
        return {s["name"]: self._deploy_one(s, client) for s in specs}

    def down(self, name: str | None = None, all_: bool = False) -> dict[str, Any]:
        specs = self._resolve(name, all_)
        client = self._client()
        stopped: list[str] = []
        for s in specs:
            cname = container_name(s)
            client.exec_cmd(f"docker rm -f {cname} 2>/dev/null")
            if cname in self._state:
                self._state[cname]["status"] = "stopped"
            stopped.append(cname)
        self._save_state()
        return {"ok": True, "stopped": stopped}

    def regen(self, name: str) -> dict[str, Any]:
        """重新生成 flag 并重启（flag 泄漏后使用）."""
        spec = by_name(name)
        if spec is None:
            return {"ok": False, "error": "未知题目"}
        self.down(name=name)
        return self._up_one(spec)

    def status(self) -> list[dict[str, Any]]:
        client = self._client()
        res = client.exec_cmd(
            "docker ps -a --filter name=athena_ --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'"
        )
        out: list[dict[str, Any]] = []
        for line in res.stdout.splitlines():
            parts = line.split("\t")
            cname = parts[0] if parts else ""
            st = parts[1] if len(parts) > 1 else ""
            ports = parts[2] if len(parts) > 2 else ""
            info = self._state.get(cname, {})
            out.append({
                "container": cname,
                "name": info.get("name", cname),
                "status": st,
                "ports": ports,
                "host_port": info.get("host_port"),
                "flag_masked": mask(info["flag"]) if info.get("flag") else None,
            })
        return out

    def verify(self, name: str, candidate: str) -> bool:
        """校验 agent 提交的 flag。仅返回 bool，绝不返回真 flag。

        对 candidate 做归一化：strip 前后空白、提取所有 athena{...} 子串，
        避免 agent 输出带引号/前缀说明（如 "flag is athena{...}"）造成假阴性。
        只有子串完整等于真 flag 才通过，不会让错误 flag 误判通过。
        """
        spec = by_name(name)
        if spec is None:
            return False
        info = self._state.get(container_name(spec), {})
        real = info.get("flag")
        if not real:
            return False
        cand = (candidate or "").strip()
        if real == cand:
            return True
        # 兼容包裹/前缀：提取 candidate 中所有 athena{...} 子串，任一等于真 flag 即通过
        matches = re.findall(r"athena\{[^}]*\}", cand)
        return real in matches

    def catalog_view(self) -> list[dict[str, Any]]:
        host = self.settings.kali_host or "<kali-host>"
        rows: list[dict[str, Any]] = []
        for spec in ALL:
            cname = container_name(spec)
            info = self._state.get(cname, {})
            row: dict[str, Any] = {
                "name": spec["name"],
                "category": spec["category"],
                "dynamic": spec["dynamic"],
                "notes": spec["notes"],
            }
            if spec["dynamic"]:
                row["host_port"] = spec["host_port"]
                row["connection"] = f"http://{host}:{spec['host_port']}"
                row["deployed"] = info.get("status", "not deployed")
            rows.append(row)
        return rows


__all__ = ["RangeManager", "DEFAULT_STATE_PATH", "REMOTE_ROOT"]
