"""工具层（L5）.

阶段四已扩展 L1 内置工具（编解码 + HTTP + strings/file_type/hex_dump/caesar/rot13/hash）。
阶段五已接入 L2 SSH 工具（ssh_exec/ssh_python/ssh_upload，当 Kali 配置可用时自动启用）。
阶段七（Sprint 5.6）已接入 L3 MCP 工具（ghidra_headless/radare2）。
Sprint 8 新增 binary_analyzer（结构化二进制分析，hard 逆向题专用）。
Sprint 10 新增 mem_xor_analyzer（内存 dump 专用 XOR 分析,forensics 题）。
Sprint 11 新增 osint_tools（OSINT/取证工具集, exiftool/steghide/binwalk/tshark）。
Sprint 12 新增 apk_tools（APK 反编译工具集, jadx/apktool, reverse APK 题专用）。
Sprint 12 M2 新增 sage_tools（密码学 LLL 攻击, common_d_attack 工具）。
Sprint 12 M3 新增 reverse_image_tools（OSINT 网络搜索 + 地理编码, 解决 Where_am_i）。
Sprint 12 M3.5 新增 ocr_tool（Tesseract OCR, OSINT 图片文字提取）。
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
from ctf_agent.tools.bus_tool import (  # S12: 共享发现工具 (消息总线)
    CheckFindingsTool,
    ShareFindingTool,
    bus_tools,
)
from ctf_agent.tools.docker_tool import (  # WING-Goose Item 5
    DockerClient,
    DockerExecTool,
    DockerFileUploadTool,
    DockerPythonTool,
    docker_tools,
)
from ctf_agent.tools.binary_tool import BinaryAnalyzeTool  # Sprint 8
from ctf_agent.tools.mem_xor_tool import MemXorAnalyzeTool  # Sprint 10
from ctf_agent.tools.osint_tool import osint_tools  # Sprint 11
from ctf_agent.tools.apk_tool import apk_tools  # Sprint 12
from ctf_agent.tools.sage_tool import sage_tools  # Sprint 12 M2
from ctf_agent.tools.reverse_image_tool import reverse_image_tools, web_search_tools  # Sprint 12 M3 / 36.4
from ctf_agent.tools.ocr_tool import ocr_tool  # Sprint 12 M3.5
from ctf_agent.tools.ecdsa_tool import ecdsa_tools  # Sprint 14 P0
from ctf_agent.tools.angr_tool import angr_tools  # Sprint 14 P0
from ctf_agent.tools.des_tool import des_tools  # Sprint 14 P2
from ctf_agent.tools.feistel_tool import feistel_tools  # Sprint 14 P2
from ctf_agent.tools.web_tool import web_tools  # Sprint 15: WEB 短板补齐
from ctf_agent.tools.pwn_tool import pwn_tools  # Sprint 15: PWN 短板补齐
from ctf_agent.tools.crypto_tool import (  # Sprint 16: 本地 CRYPTO 工具（无需 ssh）
    ClassicCipherTool,
    CryptoRSATool,
    crypto_tools,
)
from ctf_agent.tools.crypto_extra import (  # Sprint 36.5: CRYPTO 扩展工具（ZKP/OTP/AES/Hash/McEliece）
    AESSidechannelTool,
    HashCollisionTool,
    McElieceAnalyzeTool,
    OTPXorAnalyzeTool,
    ZKPForgeProofTool,
    crypto_extra_tools,
)
from ctf_agent.tools.encoding_helper import encoding_helper_tools  # Sprint 23: 编码辅助
from ctf_agent.tools.lfi_helper import lfi_tools  # Sprint 23: LFI 辅助
from ctf_agent.tools.vision_tool import vision_tools  # Sprint 25: MIMO 视觉识别
from ctf_agent.tools.audio_stego_sweep import audio_stego_sweep_tool  # audio_stego_sweep
from ctf_agent.tools.bkcrack_tool import bkcrack_tools  # bkcrack zipCrypto 攻击
from ctf_agent.tools.binary_constants_tool import binary_constants_tools  # 二进制常量提取
from ctf_agent.tools.binary_deep_analyze import binary_deep_analyze_tools  # 深度逆向分析
from ctf_agent.tools.cgb_solve import cgb_solve_tools  # CGB GameBoy 复合求解
from ctf_agent.tools.fluffy_solve import fluffy_solve_tools  # Flutter APK 复合求解

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
    "BinaryAnalyzeTool",  # Sprint 8
    "MemXorAnalyzeTool",  # Sprint 10
    "osint_tools",  # Sprint 11
    "apk_tools",  # Sprint 12
    "sage_tools",  # Sprint 12 M2
    "ocr_tool",  # Sprint 12 M3.5
    "ecdsa_tools",  # Sprint 14 P0
    "angr_tools",  # Sprint 14 P0
    "feistel_tools",  # Sprint 14 P2
    "web_tools",  # Sprint 15
    "pwn_tools",  # Sprint 15
    "CryptoRSATool",  # Sprint 16
    "ClassicCipherTool",  # Sprint 16
    "crypto_tools",  # Sprint 16
    "ZKPForgeProofTool",  # Sprint 36.5
    "OTPXorAnalyzeTool",  # Sprint 36.5
    "AESSidechannelTool",  # Sprint 36.5
    "HashCollisionTool",  # Sprint 36.5
    "McElieceAnalyzeTool",  # Sprint 36.5
    "crypto_extra_tools",  # Sprint 36.5
    "encoding_helper_tools",  # Sprint 23
    "lfi_tools",  # Sprint 23
    "vision_tools",  # Sprint 25
    "audio_stego_sweep_tool",  # audio_stego_sweep
    "bkcrack_tools",  # bkcrack zipCrypto 攻击
    "binary_constants_tools",  # 二进制常量提取
    "binary_deep_analyze_tools",  # 深度逆向分析
    "cgb_solve_tools",  # CGB GameBoy 复合求解
    "fluffy_solve_tools",  # Flutter APK 复合求解
    "builtin_tools",
    "http_tool",
    "ssh_tools",
    "mcp_tools",
    "docker_tools",  # WING-Goose Item 5
    "DockerClient",
    "DockerExecTool",
    "DockerPythonTool",
    "DockerFileUploadTool",
    "bus_tools",  # S12: 共享发现工具
    "ShareFindingTool",
    "CheckFindingsTool",
]


def default_tools(
    ssh_client=None,
    *,
    docker_client: DockerClient | None = None,  # WING-Goose Item 5
    message_bus=None,  # S12: 消息总线实例 (None=不注册共享工具, 零侵入)
    agent_id: str = "",  # S12: 当前 agent 标识 (总线发布者署名)
    shared_fs_dir: str = "",  # S13: 同题共享文件目录 (空=不注册共享文件工具, 零侵入)
    enable_l3: bool = False,
    enable_binary_analyzer: bool = True,  # Sprint 8
    enable_mem_xor_analyzer: bool = True,  # Sprint 10
    enable_osint: bool = True,  # Sprint 11
    enable_apk: bool = True,  # Sprint 12
    enable_sage: bool = True,  # Sprint 12 M2
    enable_reverse_image: bool = True,  # Sprint 12 M3
    enable_web_search: bool = True,  # Sprint 36.4: 通用网络搜索 (技术查阅, 含防 writeup 护栏)
    enable_ocr: bool = True,  # Sprint 12 M3.5
    enable_ecdsa: bool = True,  # Sprint 14 P0
    enable_angr: bool = True,  # Sprint 14 P0
    enable_des: bool = True,  # Sprint 14 P2
    enable_feistel: bool = True,  # Sprint 14 P2
    enable_web: bool = True,  # Sprint 15: WEB 工具集
    enable_pwn: bool = True,  # Sprint 15: PWN 工具集
    enable_range: bool = True,  # Sprint 15: 靶场控制（部署/停止/状态/校验）
    enable_crypto: bool = True,  # Sprint 16: 本地 CRYPTO 工具（RSA/古典密码）
    enable_lwe: bool = True,  # Sprint 36.4: LWE 解码工具 (已知 |e| 时恢复 s)
    enable_vision: bool = True,  # Sprint 25: MIMO 视觉识别
) -> list[Tool]:
    """返回默认工具集.

    Args:
        ssh_client: 可选的 SSHClient 实例。传入时自动添加 L2 SSH 工具
                   （ssh_exec/ssh_python/ssh_upload）。
        enable_l3: 是否启用 L3 MCP 工具（Ghidra/radare2）。默认 False，
                  因为 L3 工具较重且依赖 Kali 预装。需要时显式开启。
        enable_binary_analyzer: Sprint 8 新增。是否启用 binary_analyzer 工具
                  （结构化二进制分析）。需要 ssh_client。默认 True（推荐），
                  因为它会替代反复 objdump 的低效模式。
        enable_mem_xor_analyzer: Sprint 10 新增。是否启用 mem_xor_analyzer
                  工具（内存 dump 专用）。需要 ssh_client。默认 True，
                  forensics 类题目（内存取证）专用。
        enable_osint: Sprint 11 新增。是否启用 OSINT 工具集
                  (exiftool/steghide/binwalk/tshark)。需要 ssh_client。
                  OSINT/forensics 题专用。
        enable_apk: Sprint 12 新增。是否启用 APK 反编译工具集
                  (jadx/apktool)。需要 ssh_client。reverse APK 题专用。
                  依赖 Kali 预装 jadx (1.5.5) + apktool (2.7.0+)。
                  Kali apt install apktool 已通过 Sprint 12 验证。
        enable_sage: Sprint 12 M2 新增。是否启用密码学 LLL 攻击工具集
                  (common_d_attack)。需要 ssh_client。crypto hard 题专用。
                  依赖 Kali 预装 fpylll (0.6.x) 或 sagemath.
        enable_reverse_image: Sprint 12 M3 新增。是否启用 OSINT 网络搜索 +
                  地理编码工具集 (web_search + osm_geocode)。需要 ssh_client。
                  OSINT 图片题 (如 Where_am_i) 专用, 零 API key (DuckDuckGo +
                  Nominatim 公开端点)。
        enable_ocr: Sprint 12 M3.5 新增。是否启用 OCR 工具 (Tesseract)。
                  需要 ssh_client。OSINT 图片含可见文字时专用。
                  依赖 Kali 预装 tesseract (5.5.0+).

    Returns:
        工具列表：L1 内置工具 + HTTP + （可选）L2 SSH + （可选）L3 MCP + （可选）binary_analyzer + （可选）mem_xor_analyzer + （可选）osint_tools + （可选）apk_tools + （可选）sage_tools
    """
    tools: list[Tool] = [*builtin_tools(), http_tool()]
    # S12: 共享发现工具 (消息总线) — 零侵入: 未传 message_bus 不注册
    if message_bus is not None:
        tools.extend(bus_tools(message_bus, agent_id or "agent"))
    # S13: 同题共享文件工具 — 零侵入: 未传 shared_fs_dir 不注册
    if shared_fs_dir:
        from ctf_agent.tools.shared_fs_tool import shared_fs_tools
        tools.extend(shared_fs_tools(shared_fs_dir))
    # Sprint 19: Exploit 模板工具 (生成骨架脚本), 纯 Python 无需 ssh
    from ctf_agent.tools.exploit_template import ExploitTemplateTool
    tools.append(ExploitTemplateTool())
    # Sprint 16: 本地密码学工具（crypto_rsa/crypto_classic），纯 Python 无需 ssh，
    # 始终可用，直接补齐 CRYPTO 方向解题能力。
    if enable_crypto:
        tools.extend(crypto_tools())
    # Sprint 36.5: CRYPTO 扩展工具（ZKP/OTP/AES/Hash/McEliece），纯 Python 无需 ssh，
    # 始终可用，补齐密码学分析工具短板。
    tools.extend(crypto_extra_tools())
    # Sprint 23: 编码辅助工具 (纯 Python, 无需 ssh, 始终可用)
    tools.extend(encoding_helper_tools())
    # Sprint 36.9: 音频隐写参数扫描工具 (纯 Python, 无需 ssh, 始终可用)
    tools.extend(audio_stego_sweep_tool())
    # WING-Goose Item 5: 执行层独立注册 (docker 优先, ssh 降级).
    # 修复 (S14): 之前 docker 工具链位于 `if ssh_client is not None` 分支内,
    # 导致关闭 Kali (无 ssh) 时 docker 工具也丢失, 纯 Docker 环境无执行层.
    # WING-Goose (本次): 工具主名统一为 ssh_* (与 Kali 经验一致), docker_* 为别名;
    # 且专用工具 (osint/apk/sage/ecdsa/angr/web/pwn/...) 统一基于 exec_client
    # (docker 或 ssh 均可, 接口只有 exec_cmd) → 纯 Docker 环境经验同样可用.
    exec_tools: list[Tool] = []
    exec_client = None
    if docker_client is not None:
        try:
            exec_tools = docker_tools(docker_client)
            exec_client = docker_client
        except Exception:
            exec_tools = []
    if not exec_tools and ssh_client is not None:
        exec_tools = ssh_tools(ssh_client)
        exec_client = ssh_client
    tools.extend(exec_tools)
    if exec_client is not None:
        # Sprint 8: binary_analyzer（结构化二进制分析，比反复 objdump 高效）
        if enable_binary_analyzer:
            tools.append(BinaryAnalyzeTool(exec_client))
        # Sprint 10: mem_xor_analyzer（内存 dump 专用 XOR 分析）
        if enable_mem_xor_analyzer:
            tools.append(MemXorAnalyzeTool(exec_client))
        # Sprint 11: OSINT 工具集 (exiftool/steghide/binwalk/tshark)
        if enable_osint:
            tools.extend(osint_tools(exec_client))
        # Sprint 12: APK 反编译工具集 (jadx/apktool)
        if enable_apk:
            tools.extend(apk_tools(exec_client))
        # Sprint 12 M2: 密码学 LLL 攻击工具集 (common_d_attack)
        if enable_sage:
            tools.extend(sage_tools(exec_client))
        # Sprint 12 M3: OSINT 网络搜索 + 地理编码 (web_search + osm_geocode)
        if enable_reverse_image:
            # 只取 osm_geocode; web_search 由 enable_web_search 独立控制 (避免重复注册)
            tools.extend(t for t in reverse_image_tools(exec_client) if t.name != "web_search")
        # Sprint 36.4: 通用网络搜索 (独立注册, 技术查阅/解题辅助, 含防 writeup 护栏)
        # 不再依赖 enable_reverse_image, 任何题型遇到"不会的东西"都可查通用技术原理
        if enable_web_search:
            tools.extend(web_search_tools(exec_client))
        # Sprint 12 M3.5: OCR 工具 (tesseract)
        if enable_ocr:
            tools.extend(ocr_tool(exec_client))
        # Sprint 14 P0: ECDSA 攻击工具集 (ecdsa_nonce_reuse)
        if enable_ecdsa:
            tools.extend(ecdsa_tools(exec_client))
        # Sprint 14 P0: angr 符号执行 (复杂 reverse 题)
        if enable_angr:
            tools.extend(angr_tools(exec_client))
        # Sprint 14 P2: Narrow_DES 变体密钥恢复 (des_cryptanalysis)
        if enable_des:
            tools.extend(des_tools(exec_client))
        # Sprint 14 P2: Feistel 密码解密 (feistel_decrypt)
        if enable_feistel:
            tools.extend(feistel_tools(exec_client))
        # Sprint 36.4: LWE 解码 (已知误差绝对值 |e| 时恢复私钥 s)
        if enable_lwe:
            from ctf_agent.tools.lwe_tool import lwe_tools
            tools.extend(lwe_tools(exec_client))
        # Sprint 15: WEB 工具集 (web_recon/web_fingerprint/web_dirscan/sqlmap)
        if enable_web:
            tools.extend(web_tools(exec_client))
            # Sprint 23: LFI 辅助工具 (lfi_scanner/lfi_log_inject)
            tools.extend(lfi_tools(exec_client))
        # Sprint 15: PWN 工具集 (pwn_checksec/pwn_cyclic/pwn_ropgadget/pwn_exploit)
        if enable_pwn:
            tools.extend(pwn_tools(exec_client))
        # Sprint 15: 靶场控制（部署/停止/状态/校验，flag 安全）— 依赖 Kali 本地靶场,
        # docker 模式无意义, 仅 ssh 时注册.
        if enable_range and ssh_client is not None:
            from ctf_agent.range import range_tools
            tools.extend(range_tools(ssh_client))
        # Sprint 25: MIMO 视觉识别
        if enable_vision:
            tools.extend(vision_tools(exec_client))
        # bkcrack zipCrypto 已知明文攻击 (misc 杂项/取证题)
        tools.extend(bkcrack_tools(exec_client))
        # 二进制常量提取增强 (reverse 题)
        tools.extend(binary_constants_tools(exec_client))
        # 深度逆向分析 (reverse 题, 含 IEEE/GameBoy/自动求解)
        tools.extend(binary_deep_analyze_tools(exec_client))
        # CGB GameBoy 复合求解 (reverse 题, 自动提取WRAM+Feistel解密)
        tools.extend(cgb_solve_tools(exec_client))
        # Flutter APK 复合求解 (reverse 题, 自动提取加密数据+暴力破解PIN)
        tools.extend(fluffy_solve_tools(exec_client))
        if enable_l3:
            tools.extend(mcp_tools(exec_client))
    return tools
