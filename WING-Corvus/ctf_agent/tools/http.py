"""HTTP 客户端工具（L1 工具层）.

基于 httpx 实现，支持任意 HTTP 方法（含 HEAD），用于 CTF Web 题侦察与利用。
GET aHEAD 类题目需要 HEAD 方法读取响应头，故本工具始终返回 headers 字段。

依据 README §3.2，HTTP 客户端属 L1 内置工具（< 10ms 启动，免费），
与 L2 SSH 的 nmap/curl 等系统命令区分。
"""

from __future__ import annotations

from typing import Any

import httpx

from ctf_agent.tools.base import Tool

_SUPPORTED_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
_DEFAULT_TIMEOUT = 30.0
_MAX_BODY_DISPLAY = 4096  # 响应 body 截断长度，避免超长内容污染 ReAct 上下文


class HttpRequestTool(Tool):
    name = "http_request"
    description = (
        "Send an HTTP request and return status code, response headers, and body. "
        "Supports methods: GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH. "
        "Use HEAD to inspect headers only (e.g. PicoCTF GET aHEAD challenge)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Target URL (must include scheme)"},
            "method": {
                "type": "string",
                "default": "GET",
                "description": "HTTP method (case-insensitive)",
            },
            "headers": {
                "type": "object",
                "description": "Request headers as key-value pairs",
                "additionalProperties": {"type": "string"},
            },
            "body": {
                "type": "string",
                "description": "Request body (raw string, sent as-is)",
            },
            "params": {
                "type": "object",
                "description": "Query string parameters",
                "additionalProperties": {"type": "string"},
            },
            "timeout": {
                "type": "number",
                "default": 30,
                "description": "Request timeout in seconds",
            },
            "follow_redirects": {
                "type": "boolean",
                "default": False,
                "description": "Whether to follow HTTP redirects",
            },
        },
        "required": ["url"],
    }

    def __init__(self, client: httpx.Client | None = None) -> None:
        """可选注入 httpx.Client 用于测试（respx 拦截）."""
        self._client = client

    def execute(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        params: dict[str, str] | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        follow_redirects: bool = False,
        **_: Any,
    ) -> str:
        method_upper = method.upper()
        if method_upper not in _SUPPORTED_METHODS:
            return f"ERROR: unsupported HTTP method '{method}'. Supported: {sorted(_SUPPORTED_METHODS)}"

        owns_client = self._client is None
        client = self._client or httpx.Client(
            timeout=timeout, follow_redirects=follow_redirects
        )

        try:
            # HEAD/GET 等不应携带 body；POST/PUT/PATCH 可携带
            request_kwargs: dict[str, Any] = {
                "headers": headers or {},
            }
            # 注意: httpx 的 params 会完全替换 URL 中的 query string!
            # 只有显式传 params 时才使用; URL 已带 query (如 ?a=1) 时不传,
            # 否则空 dict 会把已有 query 清空 (Sprint 21 修复: web 题参数丢失)
            if params:
                request_kwargs["params"] = params
            if method_upper in {"POST", "PUT", "PATCH"} and body is not None:
                request_kwargs["content"] = body.encode("utf-8") if isinstance(body, str) else body

            resp = client.request(method_upper, url, **request_kwargs)

            return self._format_response(resp, method_upper, url)
        finally:
            if owns_client:
                client.close()

    def _format_response(
        self, resp: httpx.Response, method: str, url: str
    ) -> str:
        """格式化响应为 LLM 可读字符串."""
        body_text = resp.text or ""
        if len(body_text) > _MAX_BODY_DISPLAY:
            body_text = body_text[:_MAX_BODY_DISPLAY] + f"\n... [truncated, total {len(body_text)} chars]"

        # headers 转为可读多行格式（key: value）
        header_lines = "\n".join(
            f"  {k}: {v}" for k, v in resp.headers.items()
        )

        return (
            f"HTTP {resp.status_code} {resp.reason_phrase}\n"
            f"Request: {method} {url}\n"
            f"Response Headers:\n{header_lines}\n"
            f"Response Body:\n{body_text}"
        )


def http_tool(client: httpx.Client | None = None) -> HttpRequestTool:
    """构造 HTTP 工具实例，可选注入 client 用于测试."""
    return HttpRequestTool(client=client)
