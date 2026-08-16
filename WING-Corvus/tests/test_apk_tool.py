"""Sprint 12 APK 反编译工具单元测试.

测试覆盖:
1. ApkJadxTool: 工具元数据 + jadx 实际反编译 Simple_Calculator APK
2. ApkToolTool: 工具元数据 + apktool 实际拆 Simple_Calculator APK
3. apk_tools 工厂: 返回 2 个工具
4. 工具可用性降级: jadx 缺失时的错误处理 (mock)
5. 参数校验: apk_path/output_dir 必填
6. 集成: Simple_Calculator jadx 输出含 revealFlag() 方法

不需要真实 SSH 连接的部分用 mock;需要真实测试的部分用真 SSH。
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.absolute()))

from ctf_agent.tools.apk_tool import (
    ApkJadxTool,
    ApkToolTool,
    apk_tools,
)


# ============ Mock 测试 (不依赖 SSH) ============

class TestApkJadxToolMetadata:
    """测试工具元数据 (不调用真实 SSH)."""

    def test_tool_name(self):
        tool = ApkJadxTool(MagicMock())
        assert tool.name == "apk_jadx"

    def test_description_contains_keyword(self):
        tool = ApkJadxTool(MagicMock())
        assert "jadx" in tool.description
        assert "dex" in tool.description
        assert "Java" in tool.description

    def test_parameters_schema(self):
        tool = ApkJadxTool(MagicMock())
        schema = tool.parameters
        assert schema["type"] == "object"
        props = schema["properties"]
        assert "apk_path" in props
        assert "output_dir" in props
        assert "show_errors" in props
        assert set(schema["required"]) == {"apk_path", "output_dir"}

    def test_apk_path_validation(self):
        tool = ApkJadxTool(MagicMock())
        result = tool.execute(apk_path="", output_dir="/tmp/jadx")
        assert "ERROR" in result
        assert "apk_path" in result

    def test_output_dir_validation(self):
        tool = ApkJadxTool(MagicMock())
        result = tool.execute(apk_path="/tmp/test.apk", output_dir="")
        assert "ERROR" in result
        assert "output_dir" in result

    def test_jadx_missing_degradation(self):
        """当 jadx 在 Kali 不可用时, 返回降级提示."""
        ssh = MagicMock()
        result = MagicMock(stdout="jadx not found\n", stderr="", exit_code=1, elapsed=0.01)
        result.is_success = False  # MagicMock 默认 True, 需显式 False
        ssh.exec_cmd.return_value = result
        tool = ApkJadxTool(ssh)
        result = tool.execute(apk_path="/tmp/test.apk", output_dir="/tmp/jadx")
        assert "未安装" in result or "apt install" in result, f"应提示降级, 实际: {result[:200]}"


class TestApkToolToolMetadata:
    """测试 apktool 工具元数据."""

    def test_tool_name(self):
        tool = ApkToolTool(MagicMock())
        assert tool.name == "apktool"

    def test_description_contains_keyword(self):
        tool = ApkToolTool(MagicMock())
        assert "apktool" in tool.description
        assert "smali" in tool.description

    def test_parameters_schema(self):
        tool = ApkToolTool(MagicMock())
        schema = tool.parameters
        props = schema["properties"]
        assert "apk_path" in props
        assert "output_dir" in props
        assert "force" in props

    def test_apk_path_validation(self):
        tool = ApkToolTool(MagicMock())
        result = tool.execute(apk_path="", output_dir="/tmp/apk")
        assert "ERROR" in result

    def test_apktool_missing_degradation(self):
        """当 apktool 在 Kali 不可用时, 返回降级提示."""
        ssh = MagicMock()
        result = MagicMock(stdout="apktool not found\n", stderr="", exit_code=1, elapsed=0.01)
        result.is_success = False
        ssh.exec_cmd.return_value = result
        tool = ApkToolTool(ssh)
        result = tool.execute(apk_path="/tmp/test.apk", output_dir="/tmp/apk")
        assert "未安装" in result or "apt install" in result, f"应提示降级, 实际: {result[:200]}"


class TestApkToolsFactory:
    """测试工厂函数."""

    def test_returns_two_tools(self):
        tools = apk_tools(MagicMock())
        assert len(tools) == 2

    def test_tool_types(self):
        tools = apk_tools(MagicMock())
        names = {t.name for t in tools}
        assert names == {"apk_jadx", "apktool"}

    def test_jadx_first(self):
        """jadx 应该排在前面 (推荐工具)."""
        tools = apk_tools(MagicMock())
        assert tools[0].name == "apk_jadx"
        assert tools[1].name == "apktool"


# ============ 真实 SSH 测试 (需要 Kali 可达 + APK 已上传) ============

# 通过环境变量 CTF_RUN_INTEGRATION=1 启用真实 SSH 测试, 默认跳过
import os

integration = pytest.mark.skipif(
    os.environ.get("CTF_RUN_INTEGRATION") != "1",
    reason="需要设置 CTF_RUN_INTEGRATION=1 才会跑真实 SSH 测试",
)


@integration
class TestApkJadxReal:
    """用真实 Kali 测试 jadx 反编译 Simple_Calculator APK."""

    def test_jadx_decompile_real_apk(self):
        """jadx 真实反编译 Simple_Calculator 的 illogical.apk, 验证能找到 revealFlag."""
        from ctf_agent.config import Settings
        from ctf_agent.ssh import SSHClient

        settings = Settings()
        client = SSHClient(
            host=settings.kali_host,
            user=settings.kali_user,
            password=settings.kali_pass.get_secret_value(),
            port=settings.kali_port,
        )
        try:
            client.connect()

            tool = ApkJadxTool(client)
            result = tool.execute(
                apk_path="/tmp/ctf_real3/Simple_Calculator/illogical.apk",
                output_dir="/tmp/test_jadx_out",
            )

            # 验证反编译输出
            assert "jadx" in result.lower()
            # 反编译应该产生 .java 文件
            r = client.exec_cmd("find /tmp/test_jadx_out/sources -name 'MainActivity.java' 2>&1", timeout=10)
            assert r.is_success, "MainActivity.java 应在 jadx 输出中"
            assert "MainActivity" in r.stdout

        finally:
            client.close()


@integration
class TestApkToolReal:
    """用真实 Kali 测试 apktool d 拆 Simple_Calculator APK."""

    def test_apktool_decompile_real_apk(self):
        from ctf_agent.config import Settings
        from ctf_agent.ssh import SSHClient

        settings = Settings()
        client = SSHClient(
            host=settings.kali_host,
            user=settings.kali_user,
            password=settings.kali_pass.get_secret_value(),
            port=settings.kali_port,
        )
        try:
            client.connect()

            tool = ApkToolTool(client)
            result = tool.execute(
                apk_path="/tmp/ctf_real3/Simple_Calculator/illogical.apk",
                output_dir="/tmp/test_apktool_out",
            )

            # 验证拆解
            assert "apktool" in result.lower()
            r = client.exec_cmd("find /tmp/test_apktool_out/smali -name 'MainActivity.smali' 2>&1", timeout=10)
            assert r.is_success, "MainActivity.smali 应在 apktool 输出中"

        finally:
            client.close()


# ============ 端到端: flag 解密验证 ============

@integration
def test_end_to_end_decrypt_flag():
    """端到端: 用 jadx → grep revealFlag → python3 AES-CBC 解出 flag."""
    import hashlib
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from ctf_agent.config import Settings
    from ctf_agent.ssh import SSHClient

    settings = Settings()
    client = SSHClient(
        host=settings.kali_host,
        user=settings.kali_user,
        password=settings.kali_pass.get_secret_value(),
        port=settings.kali_port,
    )
    try:
        client.connect()

        # 1. jadx
        jadx_tool = ApkJadxTool(client)
        jadx_tool.execute(
            apk_path="/tmp/ctf_real3/Simple_Calculator/illogical.apk",
            output_dir="/tmp/e2e_jadx",
        )

        # 2. cat MainActivity.java
        r = client.exec_cmd("cat /tmp/e2e_jadx/sources/me/mahakagg/calculator/MainActivity.java", timeout=10)
        assert r.is_success
        assert "revealFlag" in r.stdout
        assert "AES/CBC/PKCS5Padding" in r.stdout

        # 3. cat g9.java 拿 f786a
        r2 = client.exec_cmd("cat /tmp/e2e_jadx/sources/defpackage/g9.java | head -60", timeout=10)
        assert r2.is_success
        assert "f786a" in r2.stdout, f"g9.java head -60 应含 f786a, 实际: {r2.stdout[:500]}"

        # 4. 提取 f786a 数组值 (正则)
        import re
        m = re.search(r"f786a\s*=\s*\{([^}]+)\}", r2.stdout)
        assert m, "应能从 g9.java 提取 f786a 数组"
        f786a = [int(x.strip()) for x in m.group(1).split(",")]
        assert len(f786a) == 8

        # 5. 提取 c, d, e 数组
        c_match = re.search(r"public static final int\[\] c\s*=\s*\{([^}]+)\}", r.stdout)
        d_match = re.search(r"public static final int\[\] d\s*=\s*\{([^}]+)\}", r.stdout)
        e_match = re.search(r"public static final int\[\] e\s*=\s*\{([^}]+)\}", r.stdout)
        assert c_match and d_match and e_match
        c = [int(x.strip()) for x in c_match.group(1).split(",")]
        d_arr = [int(x.strip()) for x in d_match.group(1).split(",")]
        e = [int(x.strip()) for x in e_match.group(1).split(",")]

        # 6. 解密
        key_pre = bytes([c[i] ^ f786a[i] for i in range(8)])
        key = hashlib.sha256(key_pre).digest()[:16]
        iv = bytes(d_arr)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        pt = decryptor.update(bytes(e)) + decryptor.finalize()
        # 去 PKCS7 padding
        pad_len = pt[-1]
        pt = pt[:-pad_len]
        flag = pt.decode("utf-8")

        assert flag.startswith("athena{")
        assert flag.endswith("}")
        print(f"\n  解出 flag: {flag}")

    finally:
        client.close()
