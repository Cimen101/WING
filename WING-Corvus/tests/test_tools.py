"""Sprint 2.3 验收测试：内置工具集（L1 工具层）.

覆盖：
1. 编解码工具的正确性与容错（padding/0x 前缀/空白）
2. Tool 基类的 JSON 解析与异常捕获
3. HTTP 工具支持 GET/POST/HEAD，返回 headers + body
4. HEAD 方法用于 GET aHEAD 类题目（flag 在响应头）
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from ctf_agent.tools import (
    Base64DecodeTool,
    Base64EncodeTool,
    CaesarCipherTool,
    FileTypeTool,
    HashComputeTool,
    HashIdentifyTool,
    HexDecodeTool,
    HexDumpTool,
    HexEncodeTool,
    HttpRequestTool,
    Rot13Tool,
    StringsTool,
    Tool,
    UrlDecodeTool,
    UrlEncodeTool,
    default_tools,
)


# ============ Tool 基类 ============
class _EchoTool(Tool):
    name = "echo"
    description = "echo input"
    parameters = {"type": "object", "properties": {"text": {"type": "string"}}}

    def execute(self, text: str = "", **_) -> str:  # type: ignore[override]
        return f"echo:{text}"


def test_tool_call_with_valid_json() -> None:
    tool = _EchoTool()
    result = tool('{"text": "hello"}')
    assert result.is_error is False
    assert result.output == "echo:hello"


def test_tool_call_with_empty_input() -> None:
    tool = _EchoTool()
    result = tool("")
    assert result.is_error is False
    assert result.output == "echo:"


def test_tool_call_with_invalid_json() -> None:
    tool = _EchoTool()
    result = tool("not a json")
    assert result.is_error is True
    assert "ERROR" in result.output


def test_tool_call_with_non_object_json() -> None:
    tool = _EchoTool()
    result = tool('["array", "not", "object"]')
    assert result.is_error is True
    assert "JSON object" in result.output


def test_tool_call_catches_execute_exception() -> None:
    class _BoomTool(Tool):
        name = "boom"
        description = "always raises"
        parameters = {}

        def execute(self, **_) -> str:  # type: ignore[override]
            raise RuntimeError("boom!")

    result = _BoomTool()("{}")
    assert result.is_error is True
    assert "ERROR" in result.output
    assert "boom!" in result.output


def test_tool_schema() -> None:
    tool = _EchoTool()
    schema = tool.schema()
    assert schema["name"] == "echo"
    assert schema["description"] == "echo input"
    assert "properties" in schema["parameters"]


# ============ Base64 ============
def test_base64_encode() -> None:
    assert Base64EncodeTool().execute(text="hello") == "aGVsbG8="


def test_base64_encode_unicode() -> None:
    assert Base64EncodeTool().execute(text="你好") == "5L2g5aW9"


def test_base64_decode() -> None:
    assert Base64DecodeTool().execute(text="aGVsbG8=") == "hello"


def test_base64_decode_without_padding() -> None:
    # "aGVsbG8" 缺少 "=" padding，工具应自动补齐
    assert Base64DecodeTool().execute(text="aGVsbG8") == "hello"


def test_base64_decode_invalid_returns_replace() -> None:
    # 非法 UTF-8 字节应被替换字符，不抛异常
    result = Base64DecodeTool().execute(text="////")
    assert isinstance(result, str)


def test_base64_roundtrip() -> None:
    original = "CTF{test_flag_123}"
    encoded = Base64EncodeTool().execute(text=original)
    decoded = Base64DecodeTool().execute(text=encoded)
    assert decoded == original


# ============ Hex ============
def test_hex_encode() -> None:
    assert HexEncodeTool().execute(text="AB") == "4142"


def test_hex_decode() -> None:
    assert HexDecodeTool().execute(text="4142") == "AB"


def test_hex_decode_with_0x_prefix() -> None:
    assert HexDecodeTool().execute(text="0x4142") == "AB"


def test_hex_decode_with_spaces() -> None:
    assert HexDecodeTool().execute(text="41 42") == "AB"


def test_hex_roundtrip() -> None:
    original = "flag{hex_roundtrip}"
    encoded = HexEncodeTool().execute(text=original)
    decoded = HexDecodeTool().execute(text=encoded)
    assert decoded == original


# ============ URL ============
def test_url_encode() -> None:
    assert UrlEncodeTool().execute(text="a b&c") == "a%20b%26c"


def test_url_decode() -> None:
    assert UrlDecodeTool().execute(text="a%20b%26c") == "a b&c"


def test_url_encode_special_chars() -> None:
    assert UrlEncodeTool().execute(text="<script>") == "%3Cscript%3E"


def test_url_roundtrip() -> None:
    original = "https://example.com/path?q=hello world&x=1"
    encoded = UrlEncodeTool().execute(text=original)
    decoded = UrlDecodeTool().execute(text=encoded)
    assert decoded == original


# ============ HTTP 工具 ============
@respx.mock
def test_http_get_returns_status_headers_body() -> None:
    respx.get("http://ctf.example/").mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "text/html", "X-Flag": "picoCTF{test}"},
            text="<html>home</html>",
        )
    )
    tool = HttpRequestTool()
    result = tool.execute(url="http://ctf.example/")
    assert "HTTP 200" in result
    # httpx Headers 迭代时返回小写 key（HTTP headers 大小写不敏感）
    assert "x-flag" in result.lower()
    assert "picoCTF{test}" in result
    assert "<html>home</html>" in result


@respx.mock
def test_http_head_returns_headers_for_get_ahead() -> None:
    """GET aHEAD 题型：flag 在 HEAD 响应头中."""
    respx.head("http://ctf.example/").mock(
        return_value=httpx.Response(
            200,
            headers={"X-Flag": "picoCTF{r3qu3st_g3ts_a_h3ad}", "Content-Type": "text/html"},
        )
    )
    tool = HttpRequestTool()
    result = tool.execute(url="http://ctf.example/", method="HEAD")
    assert "HTTP 200" in result
    assert "picoCTF{r3qu3st_g3ts_a_h3ad}" in result
    # HEAD 响应通常无 body
    assert "Response Body:" in result


@respx.mock
def test_http_post_sends_body() -> None:
    route = respx.post("http://ctf.example/login").mock(
        return_value=httpx.Response(200, text="logged in")
    )
    tool = HttpRequestTool()
    result = tool.execute(
        url="http://ctf.example/login",
        method="POST",
        body="username=admin&password=admin",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert "HTTP 200" in result
    assert "logged in" in result
    # 验证请求体被发送
    sent_request = route.calls[0].request
    assert sent_request.content == b"username=admin&password=admin"


@respx.mock
def test_http_custom_headers_sent() -> None:
    route = respx.get("http://ctf.example/api").mock(
        return_value=httpx.Response(200, text="ok")
    )
    tool = HttpRequestTool()
    tool.execute(url="http://ctf.example/api", headers={"Authorization": "Bearer xxx"})
    sent_request = route.calls[0].request
    assert sent_request.headers["authorization"] == "Bearer xxx"


@respx.mock
def test_http_query_params() -> None:
    route = respx.get("http://ctf.example/search").mock(
        return_value=httpx.Response(200, text="results")
    )
    tool = HttpRequestTool()
    tool.execute(url="http://ctf.example/search", params={"q": "flag", "page": "1"})
    sent_request = route.calls[0].request
    assert sent_request.url.params["q"] == "flag"
    assert sent_request.url.params["page"] == "1"


@respx.mock
def test_http_method_case_insensitive() -> None:
    respx.get("http://ctf.example/").mock(return_value=httpx.Response(200, text="ok"))
    tool = HttpRequestTool()
    # 小写 method
    result = tool.execute(url="http://ctf.example/", method="get")
    assert "HTTP 200" in result


def test_http_unsupported_method_returns_error() -> None:
    tool = HttpRequestTool()
    result = tool.execute(url="http://ctf.example/", method="TRACE")
    assert result.startswith("ERROR")
    assert "unsupported" in result.lower()


@respx.mock
def test_http_truncates_long_body() -> None:
    long_body = "A" * 10000
    respx.get("http://ctf.example/big").mock(
        return_value=httpx.Response(200, text=long_body)
    )
    tool = HttpRequestTool()
    result = tool.execute(url="http://ctf.example/big")
    assert "truncated" in result
    assert "10000 chars" in result
    # 截断后不应包含完整 body
    assert long_body not in result


@respx.mock
def test_http_404_status() -> None:
    respx.get("http://ctf.example/missing").mock(
        return_value=httpx.Response(404, text="not found")
    )
    tool = HttpRequestTool()
    result = tool.execute(url="http://ctf.example/missing")
    assert "HTTP 404" in result


# ============ default_tools ============
def test_default_tools_includes_all_builtin() -> None:
    tools = default_tools()
    names = {t.name for t in tools}
    assert names == {
        "auto_decode", "base64_encode", "base64_decode",
        "hex_encode", "hex_decode",
        "url_encode", "url_decode", "url_partial_encode",
        "multi_encode", "php_filter_chain",
        "strings", "file_type", "hex_dump",
        "caesar_cipher", "rot13",
        "crypto_classic", "crypto_rsa",
        "hash_compute", "hash_identify",
        "http_request", "exploit_template",
    }


def test_default_tools_all_subclass_tool() -> None:
    for tool in default_tools():
        assert isinstance(tool, Tool)
        assert tool.name
        assert tool.description
        assert tool.parameters


# ============ S14: 无 ssh 时 docker 执行层独立注册 ============
class _FakeDockerClient:
    """模拟 DockerClient: is_available() 返回 True (不实际连 docker daemon)."""

    def __init__(self, available: bool = True) -> None:
        self._available = available
        self.workdir = "/challenge/workspace"

    def is_available(self) -> bool:
        return self._available


def test_default_tools_docker_without_ssh() -> None:
    """S14: 关闭 Kali (ssh_client=None) 时, docker_client 可用 → 执行层工具仍注册.

    WING-Goose: docker 工具主名统一为 ssh_* (与 Kali 经验一致), docker_* 为别名.
    """
    fake = _FakeDockerClient()
    tools = default_tools(ssh_client=None, docker_client=fake)
    names = {t.name for t in tools}
    # 主名与 Kali 经验一致 → skill 库中 ssh_exec/ssh_python 的套路跨场景可用
    assert "ssh_exec" in names
    assert "ssh_python" in names
    assert "ssh_upload" in names
    # 别名命中验证 (react 注册时同一 Tool 挂多名字)
    from ctf_agent.agent.react import _tool_map
    tmap = _tool_map(tools)
    assert "docker_exec" in tmap and tmap["docker_exec"] is tmap["ssh_exec"]
    assert "docker_python" in tmap and tmap["docker_python"] is tmap["ssh_python"]
    assert "docker_upload" in tmap and tmap["docker_upload"] is tmap["ssh_upload"]
    # 专用工具 (osint/web/pwn 等) 在纯 Docker 模式同样注册
    assert "osint_exiftool" in names or "exiftool" in names
    assert "web_recon" in names


def test_default_tools_no_exec_layer() -> None:
    """S14: 无 ssh 且 docker 不可用 → 无执行层工具 (仅内置)."""
    tools = default_tools(ssh_client=None, docker_client=_FakeDockerClient(available=False))
    names = {t.name for t in tools}
    assert "docker_exec" not in names
    assert "ssh_exec" not in names
    # 内置工具不受影响
    assert "base64_encode" in names


# ============ StringsTool ============

def test_strings_extracts_from_text() -> None:
    tool = StringsTool()
    # 含 flag 字符串
    out = tool.execute(text="hello flag{abc123} world")
    assert "flag{abc123}" in out
    assert "hello" in out


def test_strings_extracts_from_hex() -> None:
    # 字节序列：\x00\x00flag{hex_test}\x00
    data = b"\x00\x00flag{hex_test}\x00"
    out = StringsTool().execute(text=data.hex(), encoding="hex")
    assert "flag{hex_test}" in out


def test_strings_extracts_from_base64() -> None:
    import base64 as b64
    data = b"\xff\xfe flag{b64_str} \x00"
    out = StringsTool().execute(
        text=b64.b64encode(data).decode(), encoding="base64"
    )
    assert "flag{b64_str}" in out


def test_strings_respects_min_length() -> None:
    tool = StringsTool()
    # 短串（3字符）应被过滤掉，min_length=4
    out = tool.execute(text="abc xxxxx defg")
    # "abc" 不出现作为单独项；"xxxxx" 和 "defg" 出现
    assert "xxxxx" in out
    assert "defg" in out


def test_strings_no_match_returns_hint() -> None:
    tool = StringsTool()
    # 全部非可打印
    data = b"\x00\x01\x02\x03"
    out = tool.execute(text=data.hex(), encoding="hex")
    assert "no printable strings" in out


def test_strings_via_call_with_json() -> None:
    """通过 __call__ 入口验证 JSON 参数解析."""
    tool = StringsTool()
    result = tool('{"text": "flag{json_call}"}')
    assert result.is_error is False
    assert "flag{json_call}" in result.output


def test_strings_invalid_encoding_returns_error() -> None:
    tool = StringsTool()
    result = tool('{"text": "x", "encoding": "rot13"}')
    assert result.is_error is True
    assert "ERROR" in result.output


# ============ FileTypeTool ============

def test_file_type_identifies_elf() -> None:
    tool = FileTypeTool()
    # ELF magic
    data = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 50
    out = tool.execute(text=data.hex(), encoding="hex")
    assert "ELF" in out


def test_file_type_identifies_zip() -> None:
    tool = FileTypeTool()
    data = b"PK\x03\x04" + b"\x00" * 30
    out = tool.execute(text=data.hex(), encoding="hex")
    assert "ZIP" in out


def test_file_type_identifies_png() -> None:
    tool = FileTypeTool()
    data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 30
    out = tool.execute(text=data.hex(), encoding="hex")
    assert "PNG" in out


def test_file_type_identifies_pdf() -> None:
    tool = FileTypeTool()
    data = b"%PDF-1.4\n%" + b"\x00" * 30
    out = tool.execute(text=data.hex(), encoding="hex")
    assert "PDF" in out


def test_file_type_unknown_returns_hex_preview() -> None:
    tool = FileTypeTool()
    data = b"\x01\x02\x03\x04unknown\xff"
    out = tool.execute(text=data.hex(), encoding="hex")
    assert "Unknown" in out
    assert "01 02 03 04" in out


def test_file_type_empty_input_returns_error() -> None:
    tool = FileTypeTool()
    result = tool('{"text": "", "encoding": "text"}')
    assert result.is_error is False  # 工具自身返回 ERROR 字符串，不是 ToolResult.is_error
    assert "ERROR" in result.output


# ============ HexDumpTool ============

def test_hex_dump_text_input() -> None:
    tool = HexDumpTool()
    out = tool.execute(text="AB")
    assert "00000000" in out
    assert "41 42" in out  # A=0x41, B=0x42
    assert "|AB|" in out


def test_hex_dump_hex_input() -> None:
    tool = HexDumpTool()
    out = tool.execute(text="48656c6c6f", encoding="hex")  # "Hello"
    assert "48 65 6c 6c 6f" in out
    assert "|Hello|" in out


def test_hex_dump_truncates_long_input() -> None:
    tool = HexDumpTool()
    text = "A" * 1000
    out = tool.execute(text=text, max_bytes=32)
    assert "truncated at 32 bytes" in out


def test_hex_dump_empty_input() -> None:
    tool = HexDumpTool()
    out = tool.execute(text="")
    assert "empty" in out


def test_hex_dump_handles_non_printable() -> None:
    tool = HexDumpTool()
    out = tool.execute(text="\x00\x01\x02", encoding="text")
    # 非可打印字节用 . 表示
    assert "00 01 02" in out
    assert "|...|" in out


# ============ CaesarCipherTool ============

def test_caesar_single_shift_decrypt() -> None:
    # Hello 加 shift=3 -> Khoor (前向位移加密)
    out = CaesarCipherTool().execute(text="Hello", shift=3)
    assert out == "Khoor"


def test_caesar_shift_zero_returns_unchanged() -> None:
    out = CaesarCipherTool().execute(text="Hello", shift=0)
    assert out == "Hello"


def test_caesar_shift_out_of_range_returns_error() -> None:
    out = CaesarCipherTool().execute(text="Hello", shift=26)
    assert "ERROR" in out


def test_caesar_preserves_non_alpha() -> None:
    out = CaesarCipherTool().execute(text="Hello, World!", shift=1)
    assert out == "Ifmmp, Xpsme!"


def test_caesar_all_shifts_returns_25_lines() -> None:
    out = CaesarCipherTool().execute(text="abc")
    lines = out.strip().split("\n")
    assert len(lines) == 25
    assert "[shift= 1]" in lines[0]
    assert "[shift=25]" in lines[-1]


def test_caesar_via_call_with_shift() -> None:
    tool = CaesarCipherTool()
    result = tool('{"text": "Hello", "shift": 3}')
    assert result.is_error is False
    assert result.output == "Khoor"


def test_caesar_decrypt_via_inverse_shift() -> None:
    """解密 Khoor (加密位移=3) 用 shift=23 (26-3) 得到 Hello."""
    out = CaesarCipherTool().execute(text="Khoor", shift=23)
    assert out == "Hello"


# ============ Rot13Tool ============

def test_rot13_basic() -> None:
    assert Rot13Tool().execute(text="Hello") == "Uryyb"


def test_rot13_self_inverse() -> None:
    tool = Rot13Tool()
    original = "flag{rot13_test}"
    encoded = tool.execute(text=original)
    decoded = tool.execute(text=encoded)
    assert decoded == original


def test_rot13_preserves_non_alpha() -> None:
    assert Rot13Tool().execute(text="abc123!") == "nop123!"


# ============ HashComputeTool ============

def test_hash_compute_md5() -> None:
    # md5("hello") = 5d41402abc4b2a76b9719d911017c592
    out = HashComputeTool().execute(text="hello", algorithm="md5")
    assert out == "5d41402abc4b2a76b9719d911017c592"


def test_hash_compute_sha256() -> None:
    # sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    out = HashComputeTool().execute(text="hello", algorithm="sha256")
    assert out == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_hash_compute_default_algorithm_is_md5() -> None:
    out = HashComputeTool().execute(text="hello")
    assert out == "5d41402abc4b2a76b9719d911017c592"


def test_hash_compute_unsupported_algorithm_returns_error() -> None:
    out = HashComputeTool().execute(text="hello", algorithm="foobar")
    assert "ERROR" in out
    assert "unsupported" in out


def test_hash_compute_unicode_input() -> None:
    # 验证 unicode 不抛异常
    out = HashComputeTool().execute(text="你好")
    assert len(out) == 32  # md5


# ============ HashIdentifyTool ============

def test_hash_identify_md5() -> None:
    out = HashIdentifyTool().execute(hash="5d41402abc4b2a76b9719d911017c592")
    assert "md5" in out
    assert "Length: 32" in out


def test_hash_identify_sha256() -> None:
    out = HashIdentifyTool().execute(
        hash="2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )
    assert "sha256" in out
    assert "Length: 64" in out


def test_hash_identify_sha1() -> None:
    out = HashIdentifyTool().execute(
        hash="aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"  # sha1("hello")
    )
    assert "sha1" in out


def test_hash_identify_empty_returns_error() -> None:
    out = HashIdentifyTool().execute(hash="")
    assert "ERROR" in out


def test_hash_identify_unknown_length_hex() -> None:
    # 12 字符 hex（非标准哈希长度）
    out = HashIdentifyTool().execute(hash="0123456789abcdef01234567")
    assert "unknown hex hash" in out
    assert "Length: 24" in out


def test_hash_identify_base64_like() -> None:
    out = HashIdentifyTool().execute(hash="dGVzdGhhc2g=")  # base64("testhash")
    assert "base64-like" in out


# ============ 集成：__call__ 入口 ============

def test_strings_call_with_min_length_param() -> None:
    tool = StringsTool()
    result = tool('{"text": "a bb ccc dddd", "min_length": 4}')
    assert result.is_error is False
    assert "dddd" in result.output
    # "a", "bb", "ccc" 都不到 4 字符
    assert "[1]" in result.output


def test_hash_compute_call_with_algorithm() -> None:
    tool = HashComputeTool()
    result = tool('{"text": "hello", "algorithm": "sha1"}')
    assert result.is_error is False
    assert result.output == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"


# ============ docker run flags 解析 (Windows 盘符挂载) ============

def test_parse_volume_spec_windows_drive() -> None:
    """S14 修复: Windows 盘符路径不得被 partition 拆成命名卷名."""
    from ctf_agent.tools.docker_tool import _parse_volume_spec

    host, remote, mode = _parse_volume_spec(
        "C:/Users/dev/proj/files:/challenge/workspace:rw")
    assert host == "C:/Users/dev/proj/files"
    assert remote == "/challenge/workspace"
    assert mode == "rw"


def test_parse_run_flags_keeps_workspace_and_shared_mounts() -> None:
    """S14 修复: 双 Windows 挂载 (workspace + shared) 不得互相覆盖."""
    from ctf_agent.tools.docker_tool import _parse_run_flags

    kw = _parse_run_flags([
        "-v", "C:/proj/files:/challenge/workspace:rw",
        "-v", "C:/proj/share:/shared:rw",
    ])
    vols = kw["volumes"]
    assert vols["C:/proj/files"] == {"bind": "/challenge/workspace", "mode": "rw"}
    assert vols["C:/proj/share"] == {"bind": "/shared", "mode": "rw"}
    assert len(vols) == 2  # 两个挂载都保留, 未被 dict 覆盖


def test_parse_run_flags_linux_and_named_volumes() -> None:
    """Linux 绝对路径与命名卷解析不受影响."""
    from ctf_agent.tools.docker_tool import _parse_run_flags

    kw = _parse_run_flags(["-v", "/host/x:/cont/y:ro", "-v", "myvol:/data"])
    vols = kw["volumes"]
    assert vols["/host/x"] == {"bind": "/cont/y", "mode": "ro"}
    assert vols["myvol"] == {"bind": "/data", "mode": "rw"}

