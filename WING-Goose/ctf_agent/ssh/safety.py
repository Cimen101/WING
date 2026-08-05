"""Kali 沙箱安全审计 (Sprint 6 加固).

依据用户架构校准：
- 工作目录白名单（/tmp/ctf_real*/）：避免 agent 误操作宿主机
- 危险命令黑名单（rm -rf /, dd, mkfs, fdisk, shutdown, halt 等）
- 危险命令需"判决模型"二次确认（架构预留接口）

工作区原则：
- /tmp/ctf_real/  → 第 1 轮真题
- /tmp/ctf_real2/ → 第 2 轮真题（Sprint 6）
- /tmp/ctf_real3/ → 第 3 轮真题
- /tmp/ctf_workspace/ → 默认工作区
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


# ============ 工作区白名单 ============

ALLOWED_WORKSPACES = (
    "/tmp/ctf_workspace/",
    "/tmp/ctf_real/",
    "/tmp/ctf_real2/",
    "/tmp/ctf_real3/",
    "/tmp/",  # 系统临时目录（用于个别解压缩场景）
)


def is_workspace_allowed(cwd: str) -> bool:
    """工作目录是否在白名单内.

    规则：
    - 必须以白名单前缀开头
    - 不允许 .. 路径逃逸
    """
    if not cwd:
        return False
    # 防路径逃逸
    if ".." in Path(cwd).parts:
        return False
    norm = cwd if cwd.endswith("/") else cwd + "/"
    return any(norm.startswith(p) for p in ALLOWED_WORKSPACES)


# ============ 危险命令黑名单 ============

# 危险等级常量（用字符串便于序列化）
class DangerLevel:
    """危险等级."""
    BLOCK = "block"           # 直接拒绝
    REQUIRE_JUDGE = "judge"   # 需"判决模型"二次确认
    WARN = "warn"             # 仅警告，但仍允许


# 高危命令：直接拒绝
# 模式：命令开头（允许管道前缀），模式不区分大小写
_BLOCK_PATTERNS: list[tuple[str, str]] = [
    # 文件系统毁灭
    (r"rm\s+(-[a-z]*f[a-z]*\s+)*[/~]\s*$", "递归删除根目录或家目录"),
    (r"rm\s+-rf?\s+/(?:\s|$)", "删除根目录"),
    (r"rm\s+-rf?\s+/\*", "删除根目录所有文件"),
    (r"rm\s+-rf?\s+~", "删除家目录"),
    (r"rm\s+-rf?\s+/(?:bin|etc|var|usr|home|root|opt|sbin|lib|sys|proc|boot|mnt|media|srv)\b", "删除关键系统目录"),
    (r":\(\)\s*\{.*\};:", "fork bomb"),
    # 磁盘操作
    (r"\bdd\s+.*of=/dev/(sd|hd|nvme|vd|mmcblk)", "dd 写磁盘设备"),
    (r"\bmkfs(\.\w+)?\s+/dev/", "格式化磁盘"),
    (r"\bfdisk\s+/dev/", "修改分区表"),
    (r"\bparted\s+/dev/", "修改分区"),
    (r"\bwipefs\s+/dev/", "擦除磁盘签名"),
    # 系统控制
    (r"\b(shutdown|halt|reboot|poweroff|init\s+[06])\b", "关机/重启"),
    (r"\bsystemctl\s+(poweroff|reboot|halt)", "systemctl 关机"),
    # 网络劫持
    (r"\bip\s+link\s+set\s+\S+\s+(down|up)\s*$;", "禁用网卡"),
    (r"\biptables\s+-F", "清空防火墙"),
    (r"\bnft\s+flush\s+ruleset", "清空 nftables"),
    # 用户管理
    (r"\buserdel\s+-r?\s+root", "删除 root 用户"),
    (r"\bpasswd\s+root", "修改 root 密码"),
    # Docker 逃逸
    (r"docker\s+run\s+.*--privileged", "特权容器"),
    (r"docker\s+run\s+.*--pid=host", "宿主机 PID 命名空间"),
    (r"docker\s+run\s+.*--net=host", "宿主机网络"),
    # 靶场安全（Sprint 15）：禁止直接读取靶场容器 flag（非正常途径）
    (r"docker\s+exec\s+\S*athena_\S*", "禁止 exec 进靶场容器（防直接读取 flag）"),
    (r"docker\s+(logs|inspect|cp|diff)\s+\S*athena_\S*", "禁止读取靶场容器日志/配置/文件（可能泄露 flag）"),
    (r"docker\s+exec\b[^\n;|&\r]*\bflag\b", "禁止在容器内执行读取 flag 的命令"),
]

# 需"判决模型"确认的命令（中危）
_JUDGE_PATTERNS: list[tuple[str, str]] = [
    # 网络扫描（合规 vs 越权）
    (r"\bnmap\s+.*\s+(--open|--script|192\.168|10\.|172\.)", "网络扫描"),
    (r"\bhydra\b", "在线爆破"),
    (r"\b(nc|ncat|netcat)\s+-[a-z]*l", "监听端口"),
    # 提权相关
    (r"\bchmod\s+777\s+/", "全局可写"),
    (r"\bchown\s+-R\s+\S+\s+/(?:\s|$)", "递归修改根目录属主"),
]

# 警告但不阻止（低危：可能产生副作用但易恢复）
_WARN_PATTERNS: list[tuple[str, str]] = [
    (r"\bapt(-get)?\s+install", "apt 安装（沙箱内允许）"),
    (r"\bpip\s+install", "pip 安装（沙箱内允许）"),
    (r"\bcurl\s+.*-o\s+/etc/", "下载到 /etc"),
    (r"\bwget\s+.*-O\s+/etc/", "下载到 /etc"),
]


@dataclass
class AuditResult:
    """命令审计结果."""
    allowed: bool
    danger_level: str = DangerLevel.WARN  # block / judge / warn
    pattern_matched: str = ""
    description: str = ""
    sanitized_command: str = ""  # 净化后命令（如有）

    def __str__(self) -> str:
        if self.allowed:
            return f"[{self.danger_level.upper()}] {self.description or '通过'}"
        return f"[BLOCKED:{self.danger_level}] {self.description} (pattern: {self.pattern_matched})"


def _strip_pipeline_prefix(cmd: str) -> str:
    """去掉管道前缀（如 'cd /tmp && ...' 中的 'cd /tmp && '）.

    简化版：找到第一个未被反斜杠转义的分号/&&/||，从那里开始审计。
    """
    # 简化：直接审计整个命令（pattern 通常足够具体）
    return cmd.strip()


def audit_command(command: str) -> AuditResult:
    """审计 shell 命令.

    Returns:
        AuditResult，allowed=False 时调用方应拒绝执行。
    """
    if not command or not command.strip():
        return AuditResult(allowed=False, danger_level=DangerLevel.BLOCK, description="空命令")

    # 检查黑名单（高危：直接拒绝）
    for pattern, desc in _BLOCK_PATTERNS:
        m = re.search(pattern, command, re.IGNORECASE | re.MULTILINE)
        if m:
            return AuditResult(
                allowed=False,
                danger_level=DangerLevel.BLOCK,
                pattern_matched=pattern,
                description=f"拒绝执行：{desc}",
            )

    # 检查需"判决"的命令
    for pattern, desc in _JUDGE_PATTERNS:
        m = re.search(pattern, command, re.IGNORECASE | re.MULTILINE)
        if m:
            # 当前实现：默认放行（架构预留，未来接入 LLM judge）
            return AuditResult(
                allowed=True,
                danger_level=DangerLevel.REQUIRE_JUDGE,
                pattern_matched=pattern,
                description=f"需判决：{desc}（当前默认放行，建议人工 review）",
            )

    # 检查警告类
    for pattern, desc in _WARN_PATTERNS:
        m = re.search(pattern, command, re.IGNORECASE | re.MULTILINE)
        if m:
            return AuditResult(
                allowed=True,
                danger_level=DangerLevel.WARN,
                pattern_matched=pattern,
                description=f"警告：{desc}",
            )

    return AuditResult(allowed=True, danger_level=DangerLevel.WARN, description="通过")


def audit_workspace(cwd: str) -> AuditResult:
    """审计工作目录."""
    if not is_workspace_allowed(cwd):
        return AuditResult(
            allowed=False,
            danger_level=DangerLevel.BLOCK,
            description=f"工作目录 {cwd!r} 不在白名单内（允许: {ALLOWED_WORKSPACES}）",
        )
    return AuditResult(allowed=True, danger_level=DangerLevel.WARN, description="工作区白名单通过")


__all__ = [
    "ALLOWED_WORKSPACES",
    "AuditResult",
    "DangerLevel",
    "audit_command",
    "audit_workspace",
    "is_workspace_allowed",
]
