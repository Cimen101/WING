"""生成 docker-compose.yml（备用完整编排）.

manager 主路径使用 `docker run` 单容器部署（便于单题生命周期管理）。
本模块提供一次性拉起全部靶场的 compose 文件，供人工运维或批量启动使用。
FLAG 通过环境变量 FLAG_FULL 注入（配合 .env，权限 600，不进版本库）。
"""
from __future__ import annotations

from typing import Mapping

from .catalog import DYNAMIC, container_name


def _service_block(spec, flag: str) -> str:
    cname = container_name(spec)
    host = spec["host_port"]
    cport = spec["container_port"]
    flag_val = flag if flag else "${FLAG_FULL}"
    return (
        f"  {cname}:\n"
        f"    build: ./{spec['name']}/container\n"
        f"    image: {cname}\n"
        f"    container_name: {cname}\n"
        f"    ports:\n"
        f"      - \"{host}:{cport}\"\n"
        f"    environment:\n"
        f"      - FLAG_FULL={flag_val}\n"
        f"    restart: unless-stopped\n"
    )


def build_compose_text(flags: Mapping[str, str] | None = None) -> str:
    """生成 compose YAML 文本.

    Args:
        flags: {容器名: 明文 flag}；为 None 时 FLAG_FULL 用 ${FLAG_FULL} 占位。
    """
    flags = flags or {}
    header = (
        "# Athena CTF 靶场编排（自动生成，请勿手改）\n"
        "# FLAG_FULL 由同目录 .env 提供（权限 600，不进版本库）\n"
        "services:\n"
    )
    body = "".join(_service_block(spec, flags.get(container_name(spec), "")) for spec in DYNAMIC)
    return header + body


def write_compose(target_dir: str, flags: Mapping[str, str] | None = None) -> str:
    """将 compose 文件写入 target_dir，返回路径."""
    from pathlib import Path

    path = Path(target_dir) / "docker-compose.athena.yml"
    path.write_text(build_compose_text(flags), encoding="utf-8")
    return str(path)


__all__ = ["build_compose_text", "write_compose"]
