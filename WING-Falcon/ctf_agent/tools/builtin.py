"""内置编解码工具（L1 工具层）.

纯 Python 实现，响应 < 10ms，无外部依赖。
覆盖 CTF 常见编解码与轻量分析：Base64、Hex、URL、字符串提取、文件类型识别、
Hex Dump、古典密码（Caesar/ROT13）、哈希计算与识别。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import string
import urllib.parse
from typing import Any

from ctf_agent.tools.base import Tool


# ============ 输入字节解码辅助 ============

def _decode_input(text: str, encoding: str) -> bytes:
    """按 encoding 将输入字符串解码为原始字节.

    支持的 encoding：
    - "text"  : UTF-8 文本（默认）
    - "hex"   : 十六进制（容错 0x 前缀与空白）
    - "base64": Base64（容错 padding）
    """
    encoding = (encoding or "text").lower()
    if encoding == "text":
        return text.encode("utf-8", errors="replace")
    if encoding == "hex":
        cleaned = text.strip()
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        cleaned = cleaned.replace(" ", "").replace("\n", "")
        return binascii.unhexlify(cleaned)
    if encoding == "base64":
        padding = "=" * (-len(text) % 4)
        return base64.b64decode(text + padding)
    raise ValueError(f"unsupported encoding: {encoding}")


class Base64EncodeTool(Tool):
    name = "base64_encode"
    description = "Encode a UTF-8 string to Base64."
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Text to encode"},
        },
        "required": ["text"],
    }

    def execute(self, text: str, **_: Any) -> str:
        return base64.b64encode(text.encode("utf-8")).decode("ascii")


class Base64DecodeTool(Tool):
    name = "base64_decode"
    description = "Decode a Base64 string to UTF-8 text."
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Base64 string to decode"},
        },
        "required": ["text"],
    }

    def execute(self, text: str, **_: Any) -> str:
        # 容错：自动补齐 padding
        padding = "=" * (-len(text) % 4)
        raw = base64.b64decode(text + padding)
        return raw.decode("utf-8", errors="replace")


class HexEncodeTool(Tool):
    name = "hex_encode"
    description = "Encode a UTF-8 string to hexadecimal."
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Text to encode"},
        },
        "required": ["text"],
    }

    def execute(self, text: str, **_: Any) -> str:
        return text.encode("utf-8").hex()


class HexDecodeTool(Tool):
    name = "hex_decode"
    description = "Decode a hexadecimal string to UTF-8 text."
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Hex string to decode"},
        },
        "required": ["text"],
    }

    def execute(self, text: str, **_: Any) -> str:
        # 容错：去除 0x 前缀与空白
        cleaned = text.strip()
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        cleaned = cleaned.replace(" ", "").replace("\n", "")
        raw = binascii.unhexlify(cleaned)
        return raw.decode("utf-8", errors="replace")


class UrlEncodeTool(Tool):
    name = "url_encode"
    description = "URL-encode a string (percent-encoding)."
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Text to URL-encode"},
        },
        "required": ["text"],
    }

    def execute(self, text: str, **_: Any) -> str:
        return urllib.parse.quote(text, safe="")


class UrlDecodeTool(Tool):
    name = "url_decode"
    description = "URL-decode a percent-encoded string."
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "URL-encoded string to decode"},
        },
        "required": ["text"],
    }

    def execute(self, text: str, **_: Any) -> str:
        return urllib.parse.unquote(text)


# ============ 字符串/文件/HxDump 工具 ============

# 可打印字符集（含空格，不含控制字符）
_PRINTABLE = set(string.printable) - {"\x0b", "\x0c"}


def _extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    """从字节序列中提取可打印字符串."""
    result: list[str] = []
    current = bytearray()
    for b in data:
        c = chr(b)
        if c in _PRINTABLE and c != "\n" and c != "\r" and c != "\t":
            current.append(b)
        else:
            if len(current) >= min_len:
                result.append(current.decode("ascii", errors="ignore"))
            current = bytearray()
    if len(current) >= min_len:
        result.append(current.decode("ascii", errors="ignore"))
    return result


class StringsTool(Tool):
    """提取可打印字符串（仿 Linux `strings` 命令）.

    用于 CTF 逆向/杂项题目从二进制中提取 flag 或关键字符串。
    输入支持 text/hex/base64 编码。
    """

    name = "strings"
    description = (
        "Extract printable strings (>= 4 chars) from binary or text input. "
        "Useful for finding flags or hints inside binary files."
    )
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Input data"},
            "encoding": {
                "type": "string",
                "enum": ["text", "hex", "base64"],
                "description": "Input encoding (default: text)",
            },
            "min_length": {
                "type": "integer",
                "description": "Minimum string length (default: 4)",
            },
        },
        "required": ["text"],
    }

    def execute(
        self,
        text: str,
        encoding: str = "text",
        min_length: int = 4,
        **_: Any,
    ) -> str:
        data = _decode_input(text, encoding)
        if min_length < 1:
            min_length = 4
        strings = _extract_strings(data, min_length)
        if not strings:
            return "(no printable strings found)"
        # 限制输出长度，避免过长
        max_strings = 200
        truncated = False
        if len(strings) > max_strings:
            strings = strings[:max_strings]
            truncated = True
        lines = [f"[{i}] {s}" for i, s in enumerate(strings, 1)]
        out = "\n".join(lines)
        if truncated:
            out += "\n... (truncated)"
        return out


# 常见文件 magic bytes（前 N 字节）
_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\x7fELF", "ELF executable/shared object (Linux)"),
    (b"MZ", "PE/EXE (Windows)"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF87a image"),
    (b"GIF89a", "GIF89a image"),
    (b"BM", "BMP image"),
    (b"PK\x03\x04", "ZIP archive (or docx/xlsx/jar/apk)"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"BZh", "BZIP2 archive"),
    (b"\x37\x7a\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"%PDF", "PDF document"),
    (b"rtfd", "RTF document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "MS Office (legacy doc/xls/ppt)"),
    (b"\xca\xfe\xba\xbe", "Java class file (or Mach-O fat binary)"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit binary"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit binary"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit (LE)"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit (LE)"),
    (b"OggS", "OGG audio"),
    (b"ID3", "MP3 audio (ID3 tag)"),
    (b"fLaC", "FLAC audio"),
    (b"RIFF", "WAV/AVI (RIFF container)"),
    (b"\x00\x00\x01\x00", "ICO icon"),
    (b"\x00\x00\x02\x00", "CUR cursor"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"pcap", "PCAP capture (legacy)"),
    (b"\xd4\xc3\xb2\xa1", "PCAP capture (LE)"),
    (b"\xa1\xb2\xc3\xd4", "PCAP capture (BE)"),
    (b"<!DOCTYPE", "HTML document"),
    (b"<html", "HTML document"),
    (b"<?xml", "XML document"),
    (b"{", "JSON document (likely)"),
    (b"[", "JSON array (likely)"),
]


class FileTypeTool(Tool):
    """识别文件类型（仿 Linux `file` 命令，基于 magic bytes）."""

    name = "file_type"
    description = (
        "Identify file type from magic bytes (like the `file` command). "
        "Supports common formats: ELF, PE, ZIP, PNG, JPEG, PDF, etc."
    )
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Input data"},
            "encoding": {
                "type": "string",
                "enum": ["text", "hex", "base64"],
                "description": "Input encoding (default: base64 for binary)",
            },
        },
        "required": ["text"],
    }

    def execute(
        self,
        text: str,
        encoding: str = "base64",
        **_: Any,
    ) -> str:
        data = _decode_input(text, encoding)
        if not data:
            return "ERROR: empty input"
        for magic, desc in _MAGIC_SIGNATURES:
            if data.startswith(magic):
                size = len(data)
                return f"{desc} (size: {size} bytes)"
        # 未识别：返回前 16 字节的 hex 与可打印预览
        head_hex = data[:16].hex(" ")
        printable = "".join(
            chr(b) if chr(b) in _PRINTABLE else "." for b in data[:16]
        )
        return (
            f"Unknown file type (size: {len(data)} bytes)\n"
            f"First 16 bytes (hex): {head_hex}\n"
            f"First 16 bytes (ascii): {printable}"
        )


class HexDumpTool(Tool):
    """Hex dump 工具（仿 Linux `xxd` 命令）."""

    name = "hex_dump"
    description = (
        "Produce a hex+ASCII dump of input data (like `xxd`). "
        "Useful for inspecting binary content."
    )
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Input data"},
            "encoding": {
                "type": "string",
                "enum": ["text", "hex", "base64"],
                "description": "Input encoding (default: text)",
            },
            "max_bytes": {
                "type": "integer",
                "description": "Maximum bytes to dump (default: 512)",
            },
        },
        "required": ["text"],
    }

    def execute(
        self,
        text: str,
        encoding: str = "text",
        max_bytes: int = 512,
        **_: Any,
    ) -> str:
        data = _decode_input(text, encoding)
        if max_bytes < 1:
            max_bytes = 512
        truncated = False
        if len(data) > max_bytes:
            data = data[:max_bytes]
            truncated = True
        if not data:
            return "(empty input)"
        lines: list[str] = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            # 补齐 16 字节的 hex 长度对齐
            hex_part = hex_part.ljust(48)
            ascii_part = "".join(
                chr(b) if chr(b) in _PRINTABLE else "."
                for b in chunk
            )
            lines.append(f"{i:08x}  {hex_part}  |{ascii_part}|")
        out = "\n".join(lines)
        if truncated:
            out += f"\n... (truncated at {max_bytes} bytes)"
        return out


# ============ 古典密码工具 ============

class CaesarCipherTool(Tool):
    """Caesar / 凯撒密码解密.

    若 shift 提供：仅输出该位移的结果；
    若 shift 未提供：输出所有 25 种位移，便于人工/LLM 选择有意义的明文。
    """

    name = "caesar_cipher"
    description = (
        "Apply Caesar cipher shift to letters. "
        "Provide 'shift' (0-25) to apply forward shift (encrypt), "
        "or omit to try all 25 shifts and pick the readable one. "
        "To decrypt ciphertext encrypted with shift N, use shift=(26-N)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Input text"},
            "shift": {
                "type": "integer",
                "description": "Shift amount (0-25). If omitted, try all 25.",
            },
        },
        "required": ["text"],
    }

    @staticmethod
    def _shift(text: str, shift: int) -> str:
        result = []
        for c in text:
            if "a" <= c <= "z":
                result.append(chr((ord(c) - ord("a") + shift) % 26 + ord("a")))
            elif "A" <= c <= "Z":
                result.append(chr((ord(c) - ord("A") + shift) % 26 + ord("A")))
            else:
                result.append(c)
        return "".join(result)

    def execute(
        self,
        text: str,
        shift: int | None = None,
        **_: Any,
    ) -> str:
        if shift is not None:
            if not (0 <= shift <= 25):
                return "ERROR: shift must be in [0, 25]"
            return self._shift(text, shift)
        # 尝试所有位移
        lines = []
        for s in range(1, 26):
            lines.append(f"[shift={s:>2}] {self._shift(text, s)}")
        return "\n".join(lines)


class Rot13Tool(Tool):
    """ROT13 编解码（Caesar shift=13 的特例，自反）."""

    name = "rot13"
    description = "ROT13 encode/decode (self-inverse, same operation both ways)."
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Input text"},
        },
        "required": ["text"],
    }

    def execute(self, text: str, **_: Any) -> str:
        return CaesarCipherTool._shift(text, 13)


# ============ 哈希工具 ============

_HASH_ALGOS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


class HashComputeTool(Tool):
    """计算哈希值（md5/sha1/sha256/sha512 等）."""

    name = "hash_compute"
    description = (
        "Compute hash of input text. "
        "Supported algorithms: md5, sha1, sha224, sha256, sha384, sha512."
    )
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Input text"},
            "algorithm": {
                "type": "string",
                "enum": list(_HASH_ALGOS.keys()),
                "description": "Hash algorithm (default: md5)",
            },
        },
        "required": ["text"],
    }

    def execute(
        self,
        text: str,
        algorithm: str = "md5",
        **_: Any,
    ) -> str:
        algo = algorithm.lower()
        if algo not in _HASH_ALGOS:
            return f"ERROR: unsupported algorithm '{algorithm}'. Available: {', '.join(_HASH_ALGOS)}"
        h = _HASH_ALGOS[algo]()
        h.update(text.encode("utf-8"))
        return h.hexdigest()


# 哈希长度 -> 候选算法
_HASH_LENGTH_MAP: dict[int, list[str]] = {
    32: ["md5", "ntlm", "md4"],
    40: ["sha1", "ripemd160", "mysql5"],
    56: ["sha224", "sha3-224"],
    64: ["sha256", "sha3-256", "blake2s"],
    96: ["sha384", "sha3-384"],
    128: ["sha512", "sha3-512", "blake2b"],
}

_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")


class HashIdentifyTool(Tool):
    """根据长度与字符集识别哈希可能类型."""

    name = "hash_identify"
    description = (
        "Identify possible hash types from a hash string based on length and charset."
    )
    parameters = {
        "type": "object",
        "properties": {
            "hash": {"type": "string", "description": "Hash string to identify"},
        },
        "required": ["hash"],
    }

    def execute(self, hash: str = "", **_: Any) -> str:  # type: ignore[override]
        h = (hash or "").strip()
        if not h:
            return "ERROR: empty hash"
        length = len(h)
        # 字符集分析
        is_hex = bool(_HEX_PATTERN.match(h))
        is_base64_like = bool(re.match(r"^[A-Za-z0-9+/=]+$", h))
        candidates: list[str] = []
        if is_hex:
            candidates = _HASH_LENGTH_MAP.get(length, [])
            if not candidates:
                # 任意长度的 hex
                candidates = [f"unknown hex hash (length={length})"]
        elif is_base64_like:
            candidates = [f"base64-like (length={length})"]
        else:
            candidates = [f"non-standard charset (length={length})"]

        lines = [
            f"Hash: {h}",
            f"Length: {length}",
            f"Charset: {'hex' if is_hex else ('base64-like' if is_base64_like else 'other')}",
            f"Possible types: {', '.join(candidates) if candidates else 'unknown'}",
        ]
        return "\n".join(lines)


# ============ 工厂 ============

def builtin_tools() -> list[Tool]:
    """返回全部内置编解码与分析工具实例."""
    return [
        Base64EncodeTool(),
        Base64DecodeTool(),
        HexEncodeTool(),
        HexDecodeTool(),
        UrlEncodeTool(),
        UrlDecodeTool(),
        StringsTool(),
        FileTypeTool(),
        HexDumpTool(),
        CaesarCipherTool(),
        Rot13Tool(),
        HashComputeTool(),
        HashIdentifyTool(),
    ]
