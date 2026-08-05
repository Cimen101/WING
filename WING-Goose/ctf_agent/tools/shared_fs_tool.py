"""同题 agent 共享文件工具 (S13).

多 agent 同题协作时, 通过宿主共享目录互通文件:
- 每个 agent 看到同一目录 (solve.py 配置 shared_fs_dir, 通常 data/agent_share/{challenge_id})
- list_shared_files: 列出兄弟 agent 放入的文件
- read_shared_file: 读取共享文件内容
- write_shared_file: 写入文件供兄弟 agent 读取

配合容器 /shared 挂载 (DockerClient.shared_dir), agent 也可在容器内直接访问
同一目录 (docker_exec 的 /shared), 实现"容器内读写 + 工具经宿主读写"双通道。

路径安全: 文件名仅允许 basename (禁止绝对路径/../目录穿越), 防越权访问宿主其他目录.
零侵入: default_tools 未配置 shared_fs_dir 时不注册 (None/空 = 不启用).
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from ctf_agent.tools.base import Tool

_MAX_READ_BYTES = 64 * 1024  # 单文件读取上限 (64KB, 防误读大二进制)


def _safe_name(name: str) -> str:
    """校验文件名: 只允许 basename, 禁止路径穿越/绝对路径/空名."""
    name = (name or "").strip()
    if not name or name in (".", ".."):
        raise ValueError("文件名不能为空或 . / ..")
    base = os.path.basename(name.replace("\\", "/"))
    if base != name or "/" in name or "\\" in name:
        raise ValueError("文件名必须是简单文件名 (不含路径)")
    if base in (".", ".."):
        raise ValueError("文件名不能是 . 或 ..")
    return base


class ListSharedFilesTool(Tool):
    """列出同题共享目录中的文件."""

    name = "list_shared_files"
    description = (
        "列出同题共享目录中其他 agent 放入的文件 (文件/大小/修改时间)。\n"
        "多 agent 协作时用于查看兄弟 agent 共享的附件、脚本、输出等。"
        "write_shared_file 写入后可用本工具确认; read_shared_file 读取内容。"
    )
    parameters = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    def __init__(self, shared_dir: str) -> None:
        self.shared_dir = Path(shared_dir)

    def execute(self, **_: Any) -> str:
        if not self.shared_dir.exists():
            return "共享目录为空 (尚未有任何共享文件)"
        entries = []
        try:
            for p in sorted(self.shared_dir.iterdir()):
                if p.is_file():
                    entries.append(
                        f"{p.name}  ({p.stat().st_size}B, "
                        f"{time.strftime('%m-%d %H:%M', time.localtime(p.stat().st_mtime))})")
        except OSError as e:
            return f"读取共享目录失败: {e}"
        if not entries:
            return "共享目录为空 (尚未有任何共享文件)"
        return "共享文件列表:\n" + "\n".join(entries)


class ReadSharedFileTool(Tool):
    """读取同题共享目录中的文件内容."""

    name = "read_shared_file"
    description = (
        "读取同题共享目录中指定文件的内容 (文本, 上限 64KB)。\n"
        "先 list_shared_files 确认文件名, 再读取。适合读取兄弟 agent 共享的"
        "脚本/输出/提取结果等文本文件; 二进制文件请用 docker 工具下载处理。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "共享目录中的文件名 (简单文件名, 不含路径)",
            },
        },
        "required": ["name"],
    }

    def __init__(self, shared_dir: str) -> None:
        self.shared_dir = Path(shared_dir)

    def execute(self, name: str, **_: Any) -> str:
        safe = _safe_name(name)
        path = self.shared_dir / safe
        if not path.exists() or not path.is_file():
            return f"共享文件不存在: {safe}"
        try:
            data = path.read_bytes()
        except OSError as e:
            return f"读取失败: {e}"
        if len(data) > _MAX_READ_BYTES:
            return (f"文件 {safe} 大小 {len(data)}B 超过读取上限 "
                    f"{_MAX_READ_BYTES}B, 已截断:\n" +
                    data[:_MAX_READ_BYTES].decode("utf-8", errors="replace"))
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return (f"文件 {safe} 非 UTF-8 文本 (前 200 字节十六进制):\n"
                    + data[:200].hex(" "))
        return f"--- {safe} ---\n{text}"


class WriteSharedFileTool(Tool):
    """写入文件到同题共享目录, 供其他 agent 读取."""

    name = "write_shared_file"
    description = (
        "将内容写入同题共享目录中的文件 (UTF-8 文本)。\n"
        "多 agent 协作时向兄弟 agent 共享脚本/提取结果/中间产物等;"
        "兄弟 agent 用 list_shared_files / read_shared_file 查看。\n"
        "同一文件名会覆盖; 容器内同一目录挂载在 /shared (可用 docker_exec 访问)。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "共享目录中的文件名 (简单文件名, 不含路径)",
            },
            "content": {
                "type": "string",
                "description": "文件内容 (UTF-8 文本)",
            },
        },
        "required": ["name", "content"],
    }

    def __init__(self, shared_dir: str) -> None:
        self.shared_dir = Path(shared_dir)

    def execute(self, name: str, content: str, **_: Any) -> str:
        safe = _safe_name(name)
        try:
            self.shared_dir.mkdir(parents=True, exist_ok=True)
            path = self.shared_dir / safe
            path.write_text(content, encoding="utf-8")
        except OSError as e:
            return f"写入失败: {e}"
        return f"已写入共享文件 {safe} ({len(content.encode('utf-8'))}B)"


def shared_fs_tools(shared_dir: str) -> list[Tool]:
    """创建共享文件工具集 (S13)."""
    return [
        ListSharedFilesTool(shared_dir),
        ReadSharedFileTool(shared_dir),
        WriteSharedFileTool(shared_dir),
    ]


__all__ = ["ListSharedFilesTool", "ReadSharedFileTool",
           "WriteSharedFileTool", "shared_fs_tools"]
