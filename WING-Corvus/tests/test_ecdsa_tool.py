# -*- coding: utf-8 -*-
"""Sprint 14 P0 - ECDSA nonce reuse 工具单元测试."""
import sys
import unittest
from unittest.mock import MagicMock

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


class TestEcdsaToolUnit(unittest.TestCase):
    """单元测试 EcdsaNonceReuseTool, 不依赖 SSH (mock)."""

    def setUp(self) -> None:
        sys.path.insert(0, str(__file__).rsplit("/", 2)[0] if "/" in __file__ else ".")

    def test_parse_int_decimal(self) -> None:
        from ctf_agent.tools.ecdsa_tool import EcdsaNonceReuseTool
        mock = MagicMock()
        tool = EcdsaNonceReuseTool(mock)
        self.assertEqual(tool._parse_int("123"), 123)
        self.assertEqual(tool._parse_int("  456  "), 456)
        self.assertEqual(tool._parse_int("0x7b"), 123)
        self.assertEqual(tool._parse_int("0X7B"), 123)

    def test_parse_int_hex(self) -> None:
        from ctf_agent.tools.ecdsa_tool import EcdsaNonceReuseTool
        mock = MagicMock()
        tool = EcdsaNonceReuseTool(mock)
        self.assertEqual(tool._parse_int("0xabcdef"), 0xabcdef)
        self.assertEqual(tool._parse_int("0xABCDEF"), 0xABCDEF)

    def test_supported_curves(self) -> None:
        from ctf_agent.tools.ecdsa_tool import _SUPPORTED_CURVES
        self.assertIn("secp256k1", _SUPPORTED_CURVES)
        self.assertIn("P-256", _SUPPORTED_CURVES)
        # n 应该是大整数
        for name, info in _SUPPORTED_CURVES.items():
            self.assertGreater(info["n"], 2**255, f"{name} n too small")

    def test_ensure_no_libs(self) -> None:
        """当 ecdsa 不可用时, _ensure 返回 ERROR."""
        from ctf_agent.tools.ecdsa_tool import EcdsaNonceReuseTool
        mock = MagicMock()
        r = MagicMock(is_success=False, stdout="", stderr="ModuleNotFoundError")
        mock.exec_cmd.return_value = r
        tool = EcdsaNonceReuseTool(mock)
        tool._available = None
        err = tool._ensure()
        self.assertIn("ERROR", err)

    def test_execute_not_supported_curve(self) -> None:
        from ctf_agent.tools.ecdsa_tool import EcdsaNonceReuseTool
        mock = MagicMock()
        r = MagicMock(is_success=True, stdout="OK", stderr="")
        mock.exec_cmd.return_value = r
        tool = EcdsaNonceReuseTool(mock)
        tool._available = True
        result = tool.execute(
            z1="0", r1="1", s1="1",
            z2="0", r2="1", s2="1",
            curve="invalid_curve",
        )
        self.assertIn("ERROR", result)
        self.assertIn("不支持的曲线", result)

    def test_execute_r1_not_equal_r2(self) -> None:
        """当 r1 != r2 (非 nonce reuse), 工具应识别并提示."""
        from ctf_agent.tools.ecdsa_tool import EcdsaNonceReuseTool
        mock = MagicMock()
        r = MagicMock(is_success=True, stdout="ERROR: r1 != r2, 不是 nonce reuse 攻击场景", stderr="")
        # write_script 成功 + exec 脚本返回 r1 != r2 错误
        mock.exec_cmd.return_value = r
        tool = EcdsaNonceReuseTool(mock)
        tool._available = True
        result = tool.execute(
            z1="0", r1="100", s1="1",
            z2="0", r2="200", s2="1",
            curve="secp256k1",
        )
        self.assertIn("不是 nonce reuse", result)


class TestEcdsaToolSmoke(unittest.TestCase):
    """Smoke 测试 - 需要 SSH, 跳过如果没有."""

    def setUp(self) -> None:
        try:
            from ctf_agent.config import Settings
            from ctf_agent.ssh.client import ssh_client_from_settings
            self.s = Settings()
            self.c = ssh_client_from_settings(self.s)
            self.c.connect()
            self.has_ssh = True
        except Exception as e:
            self.has_ssh = False
            self.skip_reason = str(e)

    def test_real_tiny_ecc(self) -> None:
        """真实 Tiny_ECC_Tweak pub.txt 数据, 1 步解出."""
        if not self.has_ssh:
            self.skipTest(f"SSH 不可用: {self.skip_reason}")
        from ctf_agent.tools.ecdsa_tool import EcdsaNonceReuseTool
        tool = EcdsaNonceReuseTool(self.c)
        result = tool.execute(
            curve="secp256k1",
            z1="0",
            r1="85648066978054117297931732228825879776919476959248536209880673617777258551576",
            s1="9201749990054392630326738993981507791280139616009590576070734116206809113927",
            z2="0",
            r2="85648066978054117297931732228825879776919476959248536209880673617777258551576",
            s2="8462704732267552867539133466066949384082947748926361554817429665701053787331",
            hash_algo="sha256",
            msg1="public message alpha",
            msg2="public message beta",
            aes_nonce="429f5788ac9f95a7ff00b71b",
            aes_ciphertext="8af0c838f666ff56951dc7a72cc4ebd3cbcc7a08564d9d4a6268ecbc2cd6233ae460fd8fe91a35",
            aes_key_mode="sha256",
            aes_key_len=32,
        )
        self.assertIn("athena{n0nc3_r3us3_3cc}", result,
                      f"应解出 flag, 实际: {result[:500]}")


if __name__ == "__main__":
    unittest.main()
