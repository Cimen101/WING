"""靶场题库清单（基于 data/repos/athena-ctf-2026-challs）.

- dynamic=True：依赖服务器/二进制运行环境，需部署到 Kali（web/pwn/infra/crypto 等）
- dynamic=False：静态题，附件本地分析即可，无需靶场

端口编排：动态题映射到 Kali 宿主机 8001-8014（避开 1337 与常见服务端口），
容器内统一监听 1337（与现有 Dockerfile EXPOSE 一致）。
"""
from __future__ import annotations

from pathlib import Path
from typing import TypedDict


# 题库仓库根目录
REPO_ROOT = (
    Path(__file__).resolve().parent.parent.parent
    / "data"
    / "repos"
    / "athena-ctf-2026-challs"
)


class ChallengeSpec(TypedDict):
    name: str
    category: str
    dynamic: bool
    host_port: int          # 仅 dynamic=True 使用
    container_port: int     # 题目容器内端口（默认 1337）
    notes: str


# ---- 14 道动态题（需部署靶场）----
DYNAMIC: list[ChallengeSpec] = [
    {"name": "Echo_Chamber", "category": "web", "dynamic": True, "host_port": 8001, "container_port": 1337, "notes": "web 题"},
    {"name": "Meridian_Ladder", "category": "web", "dynamic": True, "host_port": 8002, "container_port": 1337, "notes": "web 题"},
    {"name": "Session_Slip", "category": "web", "dynamic": True, "host_port": 8003, "container_port": 1337, "notes": "web 题"},
    {"name": "API_Relay", "category": "infra", "dynamic": True, "host_port": 8004, "container_port": 1337, "notes": "infra 题"},
    {"name": "Query_Mirage", "category": "infra", "dynamic": True, "host_port": 8005, "container_port": 1337, "notes": "infra 题"},
    {"name": "Upload_Lantern", "category": "infra", "dynamic": True, "host_port": 8006, "container_port": 1337, "notes": "infra 题"},
    {"name": "Net_Custom_Protocol", "category": "infra", "dynamic": True, "host_port": 8007, "container_port": 1337, "notes": "infra 题"},
    {"name": "Net_MITM_TLS", "category": "infra", "dynamic": True, "host_port": 8008, "container_port": 1337, "notes": "infra 题"},
    {"name": "Heap_Smash_v1", "category": "pwn", "dynamic": True, "host_port": 8009, "container_port": 1337, "notes": "pwn 题"},
    {"name": "Classy_who", "category": "pwn", "dynamic": True, "host_port": 8010, "container_port": 1337, "notes": "pwn 题"},
    {"name": "Fast_is_need", "category": "pwn", "dynamic": True, "host_port": 8011, "container_port": 1337, "notes": "pwn 题"},
    {"name": "Padding_Oracle_(RSA)", "category": "crypto", "dynamic": True, "host_port": 8012, "container_port": 1337, "notes": "crypto 题"},
    {"name": "Narrow_DES", "category": "crypto", "dynamic": True, "host_port": 8013, "container_port": 1337, "notes": "crypto 题"},
    {"name": "Operation_OUROBOROS", "category": "misc", "dynamic": True, "host_port": 8014, "container_port": 1337, "notes": "misc 题"},
]

# ---- 18 道静态题（本地分析，无需靶场）----
_STATIC_NAMES = [
    "Cipher_Chorus", "CrackMe_2025", "CrackMe_v2", "CrackMe_v3", "ESP_Morse",
    "Forensic_Flame", "Locked_Safe", "Logic_Lock", "MCP_Mischief", "Morse_Mystery",
    "Pixel_Puzzle", "QR_Quest", "Reverse_Riddle", "Scroll_Sage", "Stego_Shadow",
    "Symbol_Sleuth", "Timing_Trap", "USB_Whisper",
]
STATIC: list[ChallengeSpec] = [
    {"name": n, "category": "static", "dynamic": False, "host_port": 0, "container_port": 0, "notes": "静态题（本地分析）"}
    for n in _STATIC_NAMES
]

ALL: list[ChallengeSpec] = DYNAMIC + STATIC


def _slug(name: str) -> str:
    """容器名/镜像名合法化（去掉空格与括号）."""
    return name.replace(" ", "_").replace("(", "").replace(")", "")


def container_name(spec: ChallengeSpec) -> str:
    """靶场容器名（统一 athena_ 前缀小写，便于安全审计识别；Docker tag 必须小写）."""
    return f"athena_{_slug(spec['name'])}".lower()


def image_name(spec: ChallengeSpec) -> str:
    return container_name(spec)


def by_name(name: str) -> ChallengeSpec | None:
    for c in ALL:
        if c["name"] == name or _slug(c["name"]) == name:
            return c
    return None


def dynamic_challenges() -> list[ChallengeSpec]:
    return [c for c in ALL if c["dynamic"]]


def local_container_dir(spec: ChallengeSpec) -> Path:
    """题目本地 container 目录（用于上传到 Kali 构建镜像）."""
    return REPO_ROOT / spec["name"] / "container"


__all__ = [
    "REPO_ROOT", "ChallengeSpec", "DYNAMIC", "STATIC", "ALL",
    "container_name", "image_name", "by_name", "dynamic_challenges",
    "local_container_dir",
]
