"""工具层（L5）.

阶段四已扩展 L1 内置工具（编解码 + HTTP + strings/file_type/hex_dump/caesar/rot13/hash）。
阶段五已接入 L2 SSH 工具（ssh_exec/ssh_python/ssh_upload，当 Kali 配置可用时自动启用）。
阶段七已接入 L3 MCP 工具（ghidra_headless/radare2）。
新增 binary_analyzer（结构化二进制分析，hard 逆向题专用）。
新增 mem_xor_analyzer（内存 dump 专用 XOR 分析,forensics 题）。
新增 osint_tools（OSINT/取证工具集, exiftool/steghide/binwalk/tshark）。
新增 apk_tools（APK 反编译工具集, jadx/apktool, reverse APK 题专用）。
新增 sage_tools（密码学 LLL 攻击, common_d_attack 工具）。
新增 reverse_image_tools（OSINT 网络搜索 + 地理编码, 解决 Where_am_i）。
新增 ocr_tool（Tesseract OCR, OSINT 图片文字提取）。
"""

from ctf_agent.tools.base import Tool, ToolResult
from ctf_agent.tools.builtin import (
    Base64DecodeTool,
    Base64EncodeTool,
    CaesarCipherTool,
    FileTypeTool,
    HashComputeTool,
    HashIdentifyTool,
    HexDecodeTool,
    HexDumpTool,
    HexEncodeTool,
    Rot13Tool,
    StringsTool,
    UrlDecodeTool,
    UrlEncodeTool,
    builtin_tools,
)
from ctf_agent.tools.http import HttpRequestTool, http_tool
from ctf_agent.tools.mcp_tool import (
    GhidraHeadlessTool,
    MCPClient,
    MCPTool,
    Radare2Tool,
    mcp_tools,
)
from ctf_agent.tools.ssh_tool import (
    SSHExecTool,
    SSHFileUploadTool,
    SSHPythonTool,
    ssh_tools,
)
from ctf_agent.tools.binary_tool import BinaryAnalyzeTool  # 
from ctf_agent.tools.mem_xor_tool import MemXorAnalyzeTool  # 
from ctf_agent.tools.osint_tool import osint_tools  # 
from ctf_agent.tools.apk_tool import apk_tools  # 
from ctf_agent.tools.sage_tool import sage_tools  # 
from ctf_agent.tools.reverse_image_tool import reverse_image_tools  # 
from ctf_agent.tools.ocr_tool import ocr_tool  # 
from ctf_agent.tools.ecdsa_tool import ecdsa_tools  # 
from ctf_agent.tools.angr_tool import angr_tools  # 
from ctf_agent.tools.des_tool import des_tools  # 
from ctf_agent.tools.feistel_tool import feistel_tools  # 
from ctf_agent.tools.web_tool import web_tools  # WEB 短板补齐
from ctf_agent.tools.pwn_tool import pwn_tools  # PWN 短板补齐
from ctf_agent.tools.crypto_tool import (  # 本地 CRYPTO 工具（无需 ssh）
    ClassicCipherTool,
    CryptoRSATool,
    crypto_tools,
)
from ctf_agent.tools.encoding_helper import encoding_helper_tools  # 编码辅助
from ctf_agent.tools.lfi_helper import lfi_tools  # LFI 辅助
from ctf_agent.tools.vision_tool import vision_tools  # MIMO 视觉识别

__all__ = [
    "Tool",
    "ToolResult",
    "Base64EncodeTool",
    "Base64DecodeTool",
    "HexEncodeTool",
    "HexDecodeTool",
    "UrlEncodeTool",
    "UrlDecodeTool",
    "HttpRequestTool",
    "StringsTool",
    "FileTypeTool",
    "HexDumpTool",
    "CaesarCipherTool",
    "Rot13Tool",
    "HashComputeTool",
    "HashIdentifyTool",
    "SSHExecTool",
    "SSHFileUploadTool",
    "SSHPythonTool",
    "GhidraHeadlessTool",
    "MCPClient",
    "MCPTool",
    "Radare2Tool",
    "BinaryAnalyzeTool",  # 
    "MemXorAnalyzeTool",  # 
    "osint_tools",  # 
    "apk_tools",  # 
    "sage_tools",  # 
    "ocr_tool",  # 
    "ecdsa_tools",  # 
    "angr_tools",  # 
    "feistel_tools",  # 
    "web_tools",  # 
    "pwn_tools",  # 
    "CryptoRSATool",  # 
    "ClassicCipherTool",  # 
    "crypto_tools",  # 
    "encoding_helper_tools",  # 
    "lfi_tools",  # 
    "vision_tools",  # 
    "builtin_tools",
    "http_tool",
    "ssh_tools",
    "mcp_tools",
]


def default_tools(
    ssh_client=None,
    *,
    enable_l3: bool = False,
    enable_binary_analyzer: bool = True,  # 
    enable_mem_xor_analyzer: bool = True,  # 
    enable_osint: bool = True,  # 
    enable_apk: bool = True,  # 
    enable_sage: bool = True,  # 
    enable_reverse_image: bool = True,  # 
    enable_ocr: bool = True,  # 
    enable_ecdsa: bool = True,  # 
    enable_angr: bool = True,  # 
    enable_des: bool = True,  # 
    enable_feistel: bool = True,  # 
    enable_web: bool = True,  # WEB 工具集
    enable_pwn: bool = True,  # PWN 工具集
    enable_range: bool = True,  # 靶场控制（部署/停止/状态/校验）
    enable_crypto: bool = True,  # 本地 CRYPTO 工具（RSA/古典密码）
    enable_vision: bool = True,  # MIMO 视觉识别
) -> list[Tool]:
    """返回默认工具集.

    Args:
        ssh_client: 可选的 SSHClient 实例。传入时自动添加 L2 SSH 工具
                   （ssh_exec/ssh_python/ssh_upload）。
        enable_l3: 是否启用 L3 MCP 工具（Ghidra/radare2）。默认 False，
                  因为 L3 工具较重且依赖 Kali 预装。需要时显式开启。
        enable_binary_analyzer: 新增。是否启用 binary_analyzer 工具
                  （结构化二进制分析）。需要 ssh_client。默认 True（推荐），
                  因为它会替代反复 objdump 的低效模式。
        enable_mem_xor_analyzer: 新增。是否启用 mem_xor_analyzer
                  工具（内存 dump 专用）。需要 ssh_client。默认 True，
                  forensics 类题目（内存取证）专用。
        enable_osint: 新增。是否启用 OSINT 工具集
                  (exiftool/steghide/binwalk/tshark)。需要 ssh_client。
                  OSINT/forensics 题专用。
        enable_apk: 新增。是否启用 APK 反编译工具集
                  (jadx/apktool)。需要 ssh_client。reverse APK 题专用。
                  依赖 Kali 预装 jadx (1.5.5) + apktool (2.7.0+)。
                  Kali apt install apktool 已通过 验证。
        enable_sage: 新增。是否启用密码学 LLL 攻击工具集
                  (common_d_attack)。需要 ssh_client。crypto hard 题专用。
                  依赖 Kali 预装 fpylll (0.6.x) 或 sagemath.
        enable_reverse_image: 新增。是否启用 OSINT 网络搜索 +
                  地理编码工具集 (web_search + osm_geocode)。需要 ssh_client。
                  OSINT 图片题 (如 Where_am_i) 专用, 零 API key (DuckDuckGo +
                  Nominatim 公开端点)。
        enable_ocr: 新增。是否启用 OCR 工具 (Tesseract)。
                  需要 ssh_client。OSINT 图片含可见文字时专用。
                  依赖 Kali 预装 tesseract (5.5.0+).

    Returns:
        工具列表：L1 内置工具 + HTTP + （可选）L2 SSH + （可选）L3 MCP + （可选）binary_analyzer + （可选）mem_xor_analyzer + （可选）osint_tools + （可选）apk_tools + （可选）sage_tools
    """
    tools: list[Tool] = [*builtin_tools(), http_tool()]
    # Exploit 模板工具 (生成骨架脚本), 纯 Python 无需 ssh
    from ctf_agent.tools.exploit_template import ExploitTemplateTool
    tools.append(ExploitTemplateTool())
    # 本地密码学工具（crypto_rsa/crypto_classic），纯 Python 无需 ssh，
    # 始终可用，直接补齐 CRYPTO 方向解题能力。
    if enable_crypto:
        tools.extend(crypto_tools())
    # 编码辅助工具 (纯 Python, 无需 ssh, 始终可用)
    tools.extend(encoding_helper_tools())
    if ssh_client is not None:
        tools.extend(ssh_tools(ssh_client))
        # binary_analyzer（结构化二进制分析，比反复 objdump 高效）
        if enable_binary_analyzer:
            tools.append(BinaryAnalyzeTool(ssh_client))
        # mem_xor_analyzer（内存 dump 专用 XOR 分析）
        if enable_mem_xor_analyzer:
            tools.append(MemXorAnalyzeTool(ssh_client))
        # OSINT 工具集 (exiftool/steghide/binwalk/tshark)
        if enable_osint:
            tools.extend(osint_tools(ssh_client))
        # APK 反编译工具集 (jadx/apktool, 解决 Simple_Calculator 退化)
        if enable_apk:
            tools.extend(apk_tools(ssh_client))
        # 密码学 LLL 攻击工具集 (common_d_attack, 修复 Triplet_Tweak 退化)
        if enable_sage:
            tools.extend(sage_tools(ssh_client))
        # OSINT 网络搜索 + 地理编码 (web_search + osm_geocode, 解决 Where_am_i)
        if enable_reverse_image:
            tools.extend(reverse_image_tools(ssh_client))
        # OCR 工具 (tesseract, 提取图片中可见文字)
        if enable_ocr:
            tools.extend(ocr_tool(ssh_client))
        # ECDSA 攻击工具集 (ecdsa_nonce_reuse, 优化 Tiny_ECC)
        if enable_ecdsa:
            tools.extend(ecdsa_tools(ssh_client))
        # angr 符号执行 (复杂 reverse 题, 复杂逆向题 专用)
        if enable_angr:
            tools.extend(angr_tools(ssh_client))
        # Narrow_DES 变体密钥恢复 (des_cryptanalysis)
        if enable_des:
            tools.extend(des_tools(ssh_client))
        # Feistel 密码解密 (feistel_decrypt, 解决 复杂逆向题 退化)
        if enable_feistel:
            tools.extend(feistel_tools(ssh_client))
        # WEB 工具集 (web_recon/web_fingerprint/web_dirscan/sqlmap)
        if enable_web:
            tools.extend(web_tools(ssh_client))
            # LFI 辅助工具 (lfi_scanner/lfi_log_inject)
            tools.extend(lfi_tools(ssh_client))
        # PWN 工具集 (pwn_checksec/pwn_cyclic/pwn_ropgadget/pwn_exploit)
        if enable_pwn:
            tools.extend(pwn_tools(ssh_client))
        # 靶场控制（部署/停止/状态/校验，flag 安全）
        if enable_range:
            from ctf_agent.range import range_tools
            tools.extend(range_tools(ssh_client))
        # MIMO 视觉识别 (图片符号/截图/图表理解)
        if enable_vision:
            tools.extend(vision_tools(ssh_client))
        if enable_l3:
            tools.extend(mcp_tools(ssh_client))
    return tools
