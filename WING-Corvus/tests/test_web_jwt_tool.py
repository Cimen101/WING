"""web_jwt 工具单元测试 (Sprint 43 web 专项).

验证 JWT 算法混淆攻击工具:
- 从 /public.pem 获取公钥并生成伪造 token
- 从 /.well-known/jwks.json 的 n/e 构造公钥并生成伪造 token
- 公钥 PEM 末尾换行保留 (签名一致性关键)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest

from ctf_agent.tools.web_jwt_tool import WebJwtTool, _b64url_encode


# 测试用 RSA 公钥 PEM (含末尾换行)
TEST_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2GzseIeEcFM0p70wPi0p\n"
    "HObchldmtsYt7plQR9/LV1yf7zaY2W88yjX534kEN/Ec3WWdpfshfGU1U4uRtcAF\n"
    "dxcwC1QiekJ2cmtNbqvjYlg4IJrj2JAw7jv+cLVm0wRX8QX8fXT/V7DTqMM7w/na\n"
    "/MO4XO/FBEPyyMnivEbguaXRpOAODyhilyQEtcNCWO/4pMVHr89Jc9pjblqxTg2D\n"
    "+DbY8MrxwZS4Qke4rTNPe7Aq9hYIJFp6hkuvsiZHJqVfzSQ+8Pa5SRZxL3mxNnWB\n"
    "h2Z4B3A/JG2qA/OZntzBu5PFxECfAnzpnkrjpDa+FcLkjyr1iHW3i+JoJsBJvbBH\n"
    "TQIDAQAB\n"
    "-----END PUBLIC KEY-----\n"
)


class _FakeClient:
    """模拟 httpx.Client, 返回固定公钥."""

    def __init__(self, timeout):
        self.timeout = timeout

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get(self, url):
        class _Resp:
            status_code = 200
            text = TEST_PEM

            def json(self):
                return {}

        return _Resp()


def test_web_jwt_from_pem():
    """从 /public.pem 获取公钥并生成伪造 token."""
    tool = WebJwtTool()
    # 替换 _fetch_public_key 为返回固定 PEM
    tool._fetch_public_key = lambda base, url: TEST_PEM
    out = tool.execute("http://localhost:8084/")
    assert "token:" in out
    token = out.split("token: ")[1].split("\n")[0].strip()
    # 验证 token 结构
    parts = token.split(".")
    assert len(parts) == 3
    # 验证 header
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    assert header["alg"] == "HS256"
    # 验证 payload
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    assert payload == {"sub": "admin", "role": "admin"}
    # 验证签名 (用含末尾换行的 PEM)
    msg = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = _b64url_encode(
        hmac.new(TEST_PEM.encode(), msg, hashlib.sha256).digest()
    )
    assert parts[2] == expected_sig


def test_web_jwt_custom_payload():
    """自定义 payload."""
    tool = WebJwtTool()
    tool._fetch_public_key = lambda base, url: TEST_PEM
    out = tool.execute(
        "http://localhost:8084/", payload={"sub": "root", "role": "admin"}
    )
    token = out.split("token: ")[1].split("\n")[0].strip()
    payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    assert payload == {"sub": "root", "role": "admin"}


def test_web_jwt_missing_url():
    """url 为空时报错."""
    tool = WebJwtTool()
    out = tool.execute("")
    assert out.startswith("ERROR:")


def test_web_jwt_fetch_failure():
    """公钥获取失败时报错."""
    tool = WebJwtTool()

    def _fail(base, url):
        raise RuntimeError("no key")

    tool._fetch_public_key = _fail
    out = tool.execute("http://localhost:8084/")
    assert out.startswith("ERROR:")


def test_web_jwt_registered_in_default_tools():
    """web_jwt 工具在 default_tools 中注册."""
    from ctf_agent.tools import default_tools

    tools = default_tools()
    names = [t.name for t in tools]
    assert "web_jwt" in names
