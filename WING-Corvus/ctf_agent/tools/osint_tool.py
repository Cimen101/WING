"""L2 OSINT/取证工具 (Sprint 11 新增).

封装 Kali 上预装的 OSINT/取证工具为 Tool 接口,让 LLM 直接调用:
- ExifToolTool: 读取 JPEG/PNG EXIF 元数据 (GPS/相机/时间戳)
- SteghideTool: 隐写术分析 (JPEG steghide extract)
- BinwalkTool: 嵌入式文件提取 (固件/forensics)
- StringsTool: 提取可读字符串 (Sprint 11 OSINT 增强版: 支持中文+宽字符)
- TsharkTool: pcap 协议解析 (forensics PCAP_Secret 用)

设计原则:
- 与 SSHExecTool 互补: 通用工具用 SSHExecTool,专用工具用本模块
- 工具自动检测可用性 (Kali 未装则提示降级到 ssh_exec)
- 输出截断避免 LLM 上下文污染
"""
from __future__ import annotations

from typing import Any, Optional

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool


# 输出截断阈值
_MAX_OUTPUT = 6000
_TRUNCATED_SUFFIX = "\n... (输出截断,共 {total} 字符)"


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + _TRUNCATED_SUFFIX.format(total=len(text))


def _check_tool(ssh: SSHClient, tool_name: str) -> bool:
    """检测 Kali 上工具是否可用."""
    r = ssh.exec_cmd(f"which {tool_name}", timeout=5)
    return r.is_success and tool_name in r.stdout


# ============ ExifTool ============

class ExifToolTool(Tool):
    """读取图片 EXIF 元数据 (Sprint 11).

    用途: OSINT 图片题 (如 Where_am_i, 包含 GPS/相机/时间戳).
    适用: JPEG, PNG, TIFF, HEIC 等常见格式.
    """

    name = "exiftool"
    description = (
        "读取图片/文件的 EXIF 元数据 (GPS, 相机型号, 时间戳, 软件, ICC profile 等).\n"
        "OSINT/forensics 题首选工具: 包含图片 GPS 坐标可立即定位, "
        "相机/镜头型号可在 Google 反查, 时间戳可缩小搜索范围.\n"
        "支持格式: JPEG, PNG, TIFF, HEIC, PDF, MP4, MOV, RAW 等 50+ 格式.\n"
        "Kali 工具路径: /usr/bin/exiftool."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Kali 上图片/文件的绝对路径 (如 /tmp/ctf_real3/Where_am_i/Whereami.jpeg)",
            },
            "tags": {
                "type": "string",
                "description": "可选,只提取指定 tag (如 'GPS' 或 'GPS:GPSLatitude,GPS:GPSLongitude')",
            },
        },
        "required": ["file_path"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh = ssh_client
        self._available: Optional[bool] = None

    def _ensure(self) -> str:
        """检测可用性,失败返回降级提示."""
        if self._available is None:
            self._available = _check_tool(self.ssh, "exiftool")
        if not self._available:
            return (
                "ERROR: exiftool 未在 Kali 上安装.\n"
                "降级方案: 用 ssh_exec 跑 'exiftool <file>' 或 'strings <file> | grep -iE "
                "(gps|lat|lon|where|coord|camera)' 提取类似信息."
            )
        return ""

    def execute(self, file_path: str, tags: str = "", **_: Any) -> str:
        if not file_path:
            return "ERROR: file_path 不能为空"
        err = self._ensure()
        if err:
            return err

        # 构建命令
        if tags:
            cmd = f"exiftool -{tags} {file_path}"
        else:
            cmd = f"exiftool {file_path}"

        r = self.ssh.exec_cmd(cmd, timeout=15)
        if not r.is_success:
            return f"ERROR: exiftool 失败: {r.stderr[:300]}"

        output = r.stdout or ""
        if not output.strip():
            return "exiftool 成功,但无元数据. 文件可能无 EXIF 或已剥离."

        # 关键字段高亮: GPS/坐标/相机
        highlights: list[str] = []
        for line in output.split("\n"):
            ll = line.lower()
            if any(kw in ll for kw in ("gps", "latitude", "longitude", "coordinate", "altitude")):
                highlights.append(f"📍 {line}")
            elif any(kw in ll for kw in ("make", "model", "lens", "software")):
                highlights.append(f"📷 {line}")
            elif "date" in ll or "time" in ll:
                highlights.append(f"🕐 {line}")

        truncated = _truncate(output)
        if highlights:
            hl = "\n".join(highlights[:20])
            return f"=== exiftool 关键字段 ===\n{hl}\n\n=== 完整输出 ===\n{truncated}"
        return f"=== exiftool 完整输出 ===\n{truncated}"


# ============ Steghide ============

class SteghideTool(Tool):
    """隐写术分析 (Sprint 11).

    用途: 提取 JPEG/BMP/WAV/AU 中的隐写数据.
    注意: 需要密码 (steghide 默认空密码).
    """

    name = "steghide"
    description = (
        "从 JPEG/BMP/WAV/AU 文件中提取隐写数据 (steghide).\n"
        "用法: steghide extract -sf <file> [-p <password>] [-xf <out_file>]\n"
        "常见密码: '' (空), 'password', 文件名, 'athena', 'ctf2026'.\n"
        "OSINT/stego 题专用工具."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Kali 上图片/音频路径",
            },
            "password": {
                "type": "string",
                "description": "隐写密码 (默认空密码 '')",
            },
            "out_path": {
                "type": "string",
                "description": "可选,提取数据输出路径 (默认 <file>.extracted)",
            },
        },
        "required": ["file_path"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh = ssh_client
        self._available: Optional[bool] = None

    def _ensure(self) -> str:
        if self._available is None:
            self._available = _check_tool(self.ssh, "steghide")
        if not self._available:
            return (
                "ERROR: steghide 未在 Kali 上安装.\n"
                "降级方案: 用 ssh_exec 跑 'steghide extract -sf <file> -p \"\" -xf /tmp/out' 试空密码."
            )
        return ""

    def execute(
        self,
        file_path: str,
        password: str = "",
        out_path: str = "",
        **_: Any,
    ) -> str:
        if not file_path:
            return "ERROR: file_path 不能为空"
        err = self._ensure()
        if err:
            return err

        out = out_path or f"/tmp/steghide_extracted_{hash(file_path) & 0xFFFF:04x}.bin"
        # 关键: 空密码用 "" 而非省略,避免 steghide 交互提示
        pwd = password if password else ""
        cmd = f'steghide extract -sf "{file_path}" -p "{pwd}" -xf "{out}" -f 2>&1'
        r = self.ssh.exec_cmd(cmd, timeout=15)

        if r.is_success and "wrote extracted" in r.stdout.lower():
            # 读取提取的文件预览
            r2 = self.ssh.exec_cmd(f"file {out} && head -c 500 {out} | od -c | head -20", timeout=10)
            return (
                f"✅ steghide 提取成功! 输出: {out}\n\n"
                f"=== 文件信息 ===\n{r2.stdout or '(empty)'}"
            )
        elif "could not extract" in r.stdout.lower() or "passphrase" in r.stdout.lower():
            return (
                f"❌ 密码错误: {r.stdout[:300]}\n"
                f"提示: 尝试常见密码: password, athena, ctf2026, filename, 'drift', "
                f"或用 ssh_exec 跑 stegbrute."
            )
        else:
            return f"steghide 输出:\n{r.stdout[:500]}\nSTDERR: {r.stderr[:200]}"


# ============ Binwalk ============

class BinwalkTool(Tool):
    """嵌入式文件提取 (Sprint 11).

    用途: 固件/forensics 文件中提取嵌入的 zip/jpg/elf/squashfs 等.
    """

    name = "binwalk"
    description = (
        "扫描/提取文件中的嵌入数据 (binwalk).\n"
        "用法 1 (扫描): binwalk <file>  - 列出所有嵌入文件偏移\n"
        "用法 2 (提取): binwalk -e <file> - 提取到 ./_<file>.extracted/\n"
        "用途: 固件/磁盘镜像/forensics 隐写分析."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Kali 上文件路径",
            },
            "extract": {
                "type": "boolean",
                "description": "是否提取 (默认仅扫描)",
            },
        },
        "required": ["file_path"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh = ssh_client
        self._available: Optional[bool] = None

    def _ensure(self) -> str:
        if self._available is None:
            self._available = _check_tool(self.ssh, "binwalk")
        if not self._available:
            return (
                "ERROR: binwalk 未在 Kali 上安装.\n"
                "降级方案: 用 ssh_exec 跑 'binwalk <file>' 或 'foremost -i <file> -o /tmp/out'."
            )
        return ""

    def execute(self, file_path: str, extract: bool = False, **_: Any) -> str:
        if not file_path:
            return "ERROR: file_path 不能为空"
        err = self._ensure()
        if err:
            return err

        if extract:
            cmd = f"cd /tmp && binwalk -e -C /tmp/binwalk_extract_{hash(file_path) & 0xFFFF:04x} {file_path} 2>&1"
        else:
            cmd = f"binwalk {file_path}"

        r = self.ssh.exec_cmd(cmd, timeout=30)
        output = r.stdout or ""
        return _truncate(output)


# ============ Tshark (forensics PCAP) ============

class TsharkTool(Tool):
    """pcap 协议解析 (Sprint 11).

    用途: PCAP_Secret 等 pcap 流量分析题.
    """

    name = "tshark"
    description = (
        "解析 pcap/pcapng 文件 (tshark).\n"
        "用法: tshark -r <file> [-Y 'filter'] [-T fields -e <field>]\n"
        "常用 filter: http, http.request.uri, dns, tcp.stream eq 0, ftp, telnet.\n"
        "forensics/pcap 题专用."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Kali 上 pcap/pcapng 文件路径",
            },
            "display_filter": {
                "type": "string",
                "description": "Wireshark display filter (如 'http.request' 或 'dns')",
            },
            "max_packets": {
                "type": "integer",
                "description": "最多显示多少包 (默认 50, 避免输出爆炸)",
            },
        },
        "required": ["file_path"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh = ssh_client
        self._available: Optional[bool] = None

    def _ensure(self) -> str:
        if self._available is None:
            self._available = _check_tool(self.ssh, "tshark")
        if not self._available:
            return (
                "ERROR: tshark 未在 Kali 上安装.\n"
                "降级方案: tcpdump -r <file> -A 或 strings <file> | grep -iE '(pass|flag|secret|user)'."
            )
        return ""

    def execute(
        self,
        file_path: str,
        display_filter: str = "",
        max_packets: int = 50,
        **_: Any,
    ) -> str:
        if not file_path:
            return "ERROR: file_path 不能为空"
        err = self._ensure()
        if err:
            return err

        parts = [f"tshark -r {file_path}"]
        if display_filter:
            parts.append(f'-Y "{display_filter}"')
        parts.append(f"-c {max_packets}")
        cmd = " ".join(parts)

        r = self.ssh.exec_cmd(cmd, timeout=30)
        output = r.stdout or ""
        if r.stderr and "Running as user" not in r.stderr:
            output = f"STDERR: {r.stderr[:200]}\n\n{output}"
        return _truncate(output, max_len=10000)


# ============ 工厂 ============

def osint_tools(ssh_client: SSHClient) -> list[Tool]:
    """创建 OSINT/取证工具集 (Sprint 11).

    Args:
        ssh_client: 已连接的 SSHClient 实例

    Returns:
        OSINT 工具列表: exiftool + steghide + binwalk + tshark
    """
    return [
        ExifToolTool(ssh_client),
        SteghideTool(ssh_client),
        BinwalkTool(ssh_client),
        TsharkTool(ssh_client),
    ]


__all__ = [
    "ExifToolTool",
    "SteghideTool",
    "BinwalkTool",
    "TsharkTool",
    "osint_tools",
]
