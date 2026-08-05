"""Sprint 8: binary_analyzer 模块 - L2.5 高级二进制分析.

背景:
  v3 测试中 3 道 hard 题全失败（Triplet/SCADA/Simple_Calculator），主因是
  agent 反复 objdump/strings 提取碎片，30+ 步仍无法拼出控制流。
  本模块提供结构化 JSON 输出（CFG 关键节点/XREF/常量池），降低 LLM token 消耗。

设计原则:
  - 渐进式增强: 不依赖 Ghidra，先用 r2/objdump/strings 聚合（quick 模式）
  - 后续可加 Ghidra 后端（standard 模式）
  - 结构化输出: 返回 dataclass，序列化为 JSON
  - 沙箱兼容: 所有命令通过 SSHClient 执行（与现有架构一致）

层级:
  BinaryAnalyzer (Python 类，封装 SSH 调用)
    -> BinaryAnalysisResult (dataclass，结构化结果)
  BinaryAnalyzerTool (ReAct 工具接口，agent 调用入口)

后端优先级（自动选择可用）:
  1. Ghidra (standard/deep) - 最强但慢
  2. Radare2 (standard) - 轻量快速
  3. objdump + strings (quick) - 兜底
"""
from __future__ import annotations

import json
import math
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Optional


# ============ 结果数据结构 ============

@dataclass
class FunctionInfo:
    """单个函数信息."""
    name: str
    address: str  # hex (e.g., "0x401040")
    size: int  # 字节
    complexity: int = 0  # 圈复杂度（r2 估算）
    calls_to: list[str] = field(default_factory=list)  # 调用的函数地址
    called_by: list[str] = field(default_factory=list)
    has_flag_string: bool = False  # 是否包含 flag-like 字符串


@dataclass
class StringInfo:
    """提取的字符串."""
    value: str
    address: str  # hex
    category: str = "general"  # "general" / "flag_like" / "format" / "path" / "url"


@dataclass
class CFGSummary:
    """控制流图关键信息."""
    entry_function: str = ""
    longest_path: list[str] = field(default_factory=list)  # 函数名序列
    branches_count: int = 0
    loops_count: int = 0
    estimated_complexity: str = "low"  # "low" / "medium" / "high"


@dataclass
class ConstantInfo:
    """常量（如 .rodata 中的字符串/字节）."""
    address: str
    value: str  # 字符串或 hex
    type: str  # "string" / "byte_seq" / "number"


# ============ XOR 候选位置标记 (Sprint 9 阶段 2 增强) ============

# 常见 flag 模式（用于校验 XOR 解密结果）
_FLAG_RESULT_PATTERNS = [
    re.compile(r"athena\{[a-zA-Z0-9_!@#$%^&*+=-]+\}", re.IGNORECASE),
    re.compile(r"flag\{[a-zA-Z0-9_!@#$%^&*+=-]+\}", re.IGNORECASE),
    re.compile(r"CTF\{[a-zA-Z0-9_!@#$%^&*+=-]+\}"),
]


@dataclass
class XorKey:
    """XOR 候选 key.

    Attributes:
        key_bytes: 实际 key 字节
        ascii_repr: ASCII 表示 (e.g., "KEY42")
        source: 来源（如 "flag_like_string" / "short_token"）
        confidence: 置信度 [0.0, 1.0]
    """
    key_bytes: bytes
    ascii_repr: str
    source: str = "flag_like_string"
    confidence: float = 0.5


@dataclass
class XorHint:
    """XOR 解密候选位置 (Sprint 9 阶段 2 增强).

    Attributes:
        segment: 段名（如 ".rdata" / ".data" / ".text"）
        offset: 文件内偏移 (字节, 相对文件起始)
        length: 候选加密数据长度
        key_candidates: 多个候选 key (按 confidence 降序)
        preview: 解密前几个字节的十六进制表示（用于 LLM 快速预览）
        reason: 推测原因（如"包含 flag_like 字符串 KEY42"）
        confidence: 该 hint 的整体置信度
        decrypted_preview: 解密后明文 (Sprint 9 阶段 2.5 增强: 直接给 LLM 看 flag)
    """
    segment: str
    offset: int
    length: int
    key_candidates: list[XorKey] = field(default_factory=list)
    preview: str = ""
    reason: str = ""
    confidence: float = 0.0
    decrypted_preview: str = ""  # Sprint 9.5: 解密后明文片段 (含 flag)


@dataclass
class BinaryAnalysisResult:
    """二进制分析完整结果."""
    file_path: str
    file_type: str  # "ELF 64-bit" / "PE32+" / "APK" / "Unknown"
    arch: str  # "x86-64" / "arm" / "mips" / "unknown"
    endian: str  # "little" / "big"
    entry_point: str = ""  # hex
    functions: list[FunctionInfo] = field(default_factory=list)
    strings: list[StringInfo] = field(default_factory=list)
    cfg_summary: CFGSummary = field(default_factory=CFGSummary)
    constants: list[ConstantInfo] = field(default_factory=list)
    flag_candidates: list[str] = field(default_factory=list)  # 高优先级 flag-like 字符串
    xor_hints: list[XorHint] = field(default_factory=list)  # Sprint 9: XOR 候选位置
    backend_used: str = ""  # "ghidra" / "radare2" / "objdump" / "unknown"
    analysis_time: float = 0.0
    error: str = ""
    text_dump_hint: str = ""  # Sprint 10: .txt 内存 dump 引导信息

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Sprint 9: bytes 转 hex 字符串, JSON 可序列化
        for h in d.get("xor_hints", []):
            for k in h.get("key_candidates", []):
                if isinstance(k.get("key_bytes"), bytes):
                    k["key_bytes_hex"] = k["key_bytes"].hex()
                    k["key_bytes"] = k["key_bytes"].decode("utf-8", errors="replace")
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def summary(self) -> str:
        """生成适合 LLM 阅读的简短摘要."""
        lines = [
            f"=== Binary Analysis Summary ===",
            f"File: {self.file_path}",
            f"Type: {self.file_type} ({self.arch}, {self.endian}-endian)",
            f"Backend: {self.backend_used}",
            f"Analysis time: {self.analysis_time:.2f}s",
        ]
        # Sprint 10: text_dump 引导信息优先显示
        if self.text_dump_hint:
            lines.append(self.text_dump_hint)
            return "\n".join(lines)
        if self.error:
            lines.append(f"Error: {self.error}")
        if self.entry_point:
            lines.append(f"Entry: {self.entry_point}")
        if self.functions:
            lines.append(f"Functions: {len(self.functions)}")
            # Top 5 largest functions
            top = sorted(self.functions, key=lambda f: -f.size)[:5]
            for f in top:
                calls = f" -> {len(f.calls_to)} calls" if f.calls_to else ""
                lines.append(
                    f"  {f.name:30s} @ {f.address}  size={f.size:>6d}  "
                    f"complexity={f.complexity}{calls}"
                )
        if self.flag_candidates:
            lines.append(f"Flag candidates ({len(self.flag_candidates)}):")
            for fc in self.flag_candidates[:5]:
                lines.append(f"  {fc}")
        if self.cfg_summary.estimated_complexity:
            lines.append(
                f"CFG: complexity={self.cfg_summary.estimated_complexity}, "
                f"branches={self.cfg_summary.branches_count}, "
                f"loops={self.cfg_summary.loops_count}"
            )
        if self.xor_hints:
            lines.append(
                f"XOR hints ({len(self.xor_hints)} - "
                f"high-confidence decryption positions):"
            )
            for h in self.xor_hints[:5]:
                keys = ", ".join(k.ascii_repr for k in h.key_candidates[:3])
                lines.append(
                    f"  [{h.segment} @ 0x{h.offset:x}, len={h.length}] "
                    f"keys=[{keys}] conf={h.confidence:.2f} | {h.reason}"
                )
                # Sprint 9.5: 显示解密后明文 (含 flag)
                if h.decrypted_preview:
                    lines.append(f"    Decrypted: {h.decrypted_preview[:200]}")
        return "\n".join(lines)


# ============ Flag 字符串检测 ============

# 常见 flag 格式正则（与 real_ctf_test.py 中的 FLAG_PATTERNS 一致）
_FLAG_PATTERNS = [
    re.compile(r"athena\{[a-zA-Z0-9_!@#$%^&*+=-]+\}", re.IGNORECASE),
    re.compile(r"flag\{[a-zA-Z0-9_!@#$%^&*+=-]+\}", re.IGNORECASE),
    re.compile(r"CTF\{[a-zA-Z0-9_!@#$%^&*+=-]+\}"),
    re.compile(r"drift[=:][^ \t\n,;]{3,30}"),  # SCADA 特定
    re.compile(r"key[=:][^ \t\n,;]{3,30}"),
    re.compile(r"secret[=:][^ \t\n,;]{3,30}", re.IGNORECASE),
]


def _classify_string(s: str) -> str:
    """判断字符串是否像 flag."""
    for pat in _FLAG_PATTERNS:
        if pat.search(s):
            return "flag_like"
    if re.match(r"^[A-Za-z]:[/\\]", s) or s.startswith("/"):
        return "path"
    if s.startswith("http://") or s.startswith("https://"):
        return "url"
    if "%" in s and re.search(r"%[sdifxXoO]", s):
        return "format"
    return "general"


# ============ BinaryAnalyzer 核心类 ============

class BinaryAnalyzer:
    """L2.5 二进制分析器（SSH 客户端 + 多种后端）.

    用法:
        analyzer = BinaryAnalyzer(ssh_client)
        result = analyzer.analyze("/tmp/ctf_real3/SCADA_Firmware/firmware.bin")
        print(result.summary())
    """

    def __init__(self, ssh_client: Any) -> None:
        self.ssh = ssh_client

    # ---------- 公共 API ----------

    def analyze(
        self,
        file_path: str,
        depth: str = "auto",
        mode: str = "auto",
    ) -> BinaryAnalysisResult:
        """分析二进制文件.

        Args:
            file_path: 沙箱上二进制文件路径
            depth: "auto" (自动选择) / "quick" (objdump+strings) /
                   "standard" (r2) / "deep" (ghidra, 慢)
            mode: "auto" (根据文件类型自动选择) /
                  "binary" (强制二进制分析) /
                  "text_dump" (检测到 .txt 时返回提示, 引导使用 mem_xor_analyzer)

        Returns:
            BinaryAnalysisResult
        """
        started = time.monotonic()
        result = BinaryAnalysisResult(
            file_path=file_path,
            file_type="Unknown",
            arch="unknown",
            endian="",
        )
        try:
            # Sprint 10: 显式 mode='text_dump' 提前返回,避免 LLM 走错路径
            if mode == "text_dump":
                self._handle_text_dump(result)
                result.analysis_time = time.monotonic() - started
                return result

            # 1. 基础信息（file 命令）
            self._detect_file_type(result)
            if result.error:
                return result

            # Sprint 10: auto 模式且检测到 .txt,提示 LLM 用 mem_xor_analyzer
            if mode == "auto" and self._is_text_dump(result):
                self._handle_text_dump(result)
                result.analysis_time = time.monotonic() - started
                return result

            # 2. 选择后端
            backend = self._select_backend(depth)
            result.backend_used = backend

            # 3. 调用对应后端
            if backend == "ghidra":
                self._analyze_ghidra(result)
            elif backend == "radare2":
                self._analyze_radare2(result)
            else:
                self._analyze_objdump(result)

            # 4. 后处理：flag 候选、复杂度估算
            self._post_process(result)

        except Exception as e:  # noqa: BLE001
            result.error = f"{type(e).__name__}: {e}"

        result.analysis_time = time.monotonic() - started
        return result

    def _is_text_dump(self, result: BinaryAnalysisResult) -> bool:
        """判断文件是否为 .txt 格式内存 dump (Sprint 10).

        判定条件 (任一满足):
        - file_type 包含 "ASCII text" 或 "UTF-8"
        - file_type 包含 "data" 但 size > 1KB 且 file_path 以 .txt 结尾
        - 文件路径含 "ram_dump" / "memory" / ".txt" 关键词
        """
        ft = (result.file_type or "").lower()
        fp = (result.file_path or "").lower()

        if "ascii text" in ft or "utf-8" in ft or "utf-8 unicode" in ft:
            return True
        if fp.endswith(".txt"):
            return True
        if "ram_dump" in fp or "memory_dump" in fp:
            return True
        return False

    def _handle_text_dump(self, result: BinaryAnalysisResult) -> None:
        """处理 .txt 内存 dump: 填充 result 为引导信息, 不返回误导性空数据."""
        result.backend_used = "text_dump_redirect"
        result.file_type = "Text Dump (memory/hex)"
        result.arch = "n/a"
        result.error = ""  # 清除可能的 file 错误
        result.flag_candidates = []
        result.xor_hints = []
        result.functions = []
        result.strings = []
        # 注入引导信息到 summary (放在 flag_candidates 前面)
        result.text_dump_hint = (
            "⚠️ 检测到 .txt 格式内存 dump 文件,本工具不适用。\n"
            "💡 请改用 mem_xor_analyze 工具:\n"
            "   mem_xor_analyze(dump_path='<file>', process_map_path='<process_map.txt>')\n"
            "它会自动解析 hex dump 格式 + 提取 process_map 候选 key + 尝试 4 种 XOR 模式。"
        )

    # ---------- 文件类型检测 ----------

    def _detect_file_type(self, result: BinaryAnalysisResult) -> None:
        """用 file 命令识别文件类型."""
        r = self.ssh.exec_cmd(f"file {result.file_path}", timeout=10)
        if not r.is_success:
            result.error = f"file 命令失败: {r.stderr[:200]}"
            return
        info = (r.stdout or "").strip()
        # 解析 file 命令输出
        # 例: "PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped)"
        if "PE32+" in info or "PE32 " in info:
            result.file_type = "PE32+" if "PE32+" in info else "PE32"
            if "x86-64" in info or "x86_64" in info:
                result.arch = "x86-64"
            elif "x86" in info:
                result.arch = "x86"
        elif "ELF 64" in info:
            result.file_type = "ELF 64-bit"
            if "x86-64" in info:
                result.arch = "x86-64"
            elif "aarch64" in info or "ARM aarch64" in info:
                result.arch = "aarch64"
            elif "ARM" in info:
                result.arch = "arm"
        elif "ELF 32" in info:
            result.file_type = "ELF 32-bit"
            result.arch = "x86" if "Intel" in info or "i386" in info else "unknown"
        elif "Zip archive" in info or "Android package" in info or "APK" in info:
            result.file_type = "APK"
            result.arch = "dex"
        else:
            result.file_type = info.split(",")[0] if info else "Unknown"
        result.endian = "little"  # 几乎所有现代二进制都是 little-endian

        # 提取 entry point（仅对 ELF/PE 有意义）
        if result.file_type.startswith("ELF") or result.file_type.startswith("PE"):
            self._detect_entry_point(result)

    def _detect_entry_point(self, result: BinaryAnalysisResult) -> None:
        """检测入口点."""
        if result.file_type.startswith("ELF"):
            r = self.ssh.exec_cmd(
                f"readelf -h {result.file_path} 2>/dev/null | grep 'Entry point'"
            )
            m = re.search(r"0x([0-9a-fA-F]+)", r.stdout or "")
            if m:
                result.entry_point = f"0x{m.group(1)}"
        elif result.file_type.startswith("PE"):
            # PE 入口点在 OptionalHeader.AddressOfEntryPoint
            # 简化：objdump -p
            r = self.ssh.exec_cmd(
                f"objdump -p {result.file_path} 2>/dev/null | grep -i 'entry' | head -1"
            )
            m = re.search(r"0x([0-9a-fA-F]+)", r.stdout or "")
            if m:
                result.entry_point = f"0x{m.group(1)}"

    # ---------- 后端选择 ----------

    def _select_backend(self, depth: str) -> str:
        """选择可用的后端."""
        if depth == "auto":
            # 优先 Ghidra（最强），其次 r2，最后 objdump
            r = self.ssh.exec_cmd("test -x /opt/ghidra/support/analyzeHeadless && echo OK")
            if "OK" in (r.stdout or ""):
                return "ghidra"
            r = self.ssh.exec_cmd("which r2")
            if (r.stdout or "").strip():
                return "radare2"
            return "objdump"
        if depth == "deep":
            return "ghidra"
        if depth == "standard":
            # 优先 r2，无 r2 降级到 objdump
            r = self.ssh.exec_cmd("which r2")
            if (r.stdout or "").strip():
                return "radare2"
            return "objdump"
        return "objdump"

    # ---------- Radare2 后端 ----------

    # 匹配 ANSI 颜色码以便清洗
    _ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

    def _clean_ansi(self, s: str) -> str:
        """去除 ANSI 颜色码."""
        return self._ANSI_RE.sub("", s or "")

    def _analyze_radare2(self, result: BinaryAnalysisResult) -> None:
        """用 r2 提取函数列表 + 字符串."""
        # 1. 函数列表（aaa 后 afl）— 必须禁用颜色避免 ANSI 码干扰正则
        r = self.ssh.exec_cmd(
            f"r2 -q -e scr.color=0 -c 'aaa; afl' {result.file_path} 2>/dev/null",
            timeout=60,
        )
        for line in self._clean_ansi(r.stdout or "").splitlines():
            # r2 afl 输出: 0x00001234   N  size  name
            m = re.match(
                r"0x([0-9a-fA-F]+)\s+(\d+)\s+(\d+)\s+(\S+)",
                line,
            )
            if m:
                addr = f"0x{m.group(1)}"
                complexity = int(m.group(2))
                size = int(m.group(3))
                name = m.group(4)
                result.functions.append(
                    FunctionInfo(
                        name=name,
                        address=addr,
                        size=size,
                        complexity=complexity,
                    )
                )

        # 2. 字符串（izz）— 禁用颜色
        r = self.ssh.exec_cmd(
            f"r2 -q -e scr.color=0 -c 'aaa; izz' {result.file_path} 2>/dev/null",
            timeout=60,
        )
        # r2 izz 列：nth paddr vaddr len size section type string
        # type 列已知值: ascii / utf8 / utf16le / utf16be
        # 实际格式:
        #   11  0x00000490 0x100401090  4  5  .text  ascii  WVSH
        #   12  0x000004ac 0x1004010ac  4  5  .text  ascii  ~)Lc
        KNOWN_TYPES = {"ascii", "utf8", "utf16le", "utf16be"}
        for line in self._clean_ansi(r.stdout or "").splitlines():
            # 跳过表头
            if line.startswith("nth ") or not line.strip():
                continue
            parts = line.split(None, 6)  # 最多 7 段，前面 6 段是固定列
            if len(parts) < 7:
                continue
            # parts: [nth, paddr, vaddr, len, size, section, type+string]
            try:
                # 验证 part[1] 是 hex 地址
                int(parts[1], 16)
            except (ValueError, IndexError):
                continue
            last = parts[6]
            # 切分 type + string
            first_space = last.find(" ")
            if first_space < 0:
                continue
            type_token = last[:first_space].strip()
            string = last[first_space:].strip()
            if type_token not in KNOWN_TYPES or not string:
                continue
            if len(string) < 4:
                continue
            cat = _classify_string(string)
            # 过滤纯段名（噪声）
            if string in {".text", ".data", ".rdata", ".bss", ".idata", ".reloc"}:
                continue
            result.strings.append(
                StringInfo(
                    value=string[:200],
                    address=parts[2],  # vaddr
                    category=cat,
                )
            )

        # 3. 入口函数
        if result.functions:
            # r2 的 entry0 通常是入口
            for f in result.functions:
                if f.name in ("entry0", "main", "sym.main"):
                    result.cfg_summary.entry_function = f.name
                    break
            if not result.cfg_summary.entry_function:
                result.cfg_summary.entry_function = result.functions[0].name

        # 4. 复杂度估算
        if result.functions:
            total_size = sum(f.size for f in result.functions)
            total_complexity = sum(f.complexity for f in result.functions)
            if total_size > 50000 or total_complexity > 200:
                result.cfg_summary.estimated_complexity = "high"
            elif total_size > 10000 or total_complexity > 50:
                result.cfg_summary.estimated_complexity = "medium"
            else:
                result.cfg_summary.estimated_complexity = "low"
            result.cfg_summary.branches_count = sum(
                1 for f in result.functions if f.complexity > 3
            )

    # ---------- objdump 后端（兜底）----------

    def _analyze_objdump(self, result: BinaryAnalysisResult) -> None:
        """用 objdump + strings 提取基础信息."""
        # 函数（简化：objdump -t 提取符号表）
        r = self.ssh.exec_cmd(
            f"objdump -t {result.file_path} 2>/dev/null | grep -E '\\.text' | head -100",
            timeout=30,
        )
        for line in (r.stdout or "").splitlines():
            # objdump -t 输出: address ... size name
            parts = line.split()
            if len(parts) >= 6:
                try:
                    addr = f"0x{int(parts[0], 16):x}"
                    size_str = parts[4] if len(parts) > 4 else "0"
                    size = int(size_str, 16) if size_str.startswith("0") else 0
                    name = parts[-1] if parts else ""
                    if name and not name.startswith("."):
                        result.functions.append(
                            FunctionInfo(
                                name=name,
                                address=addr,
                                size=size,
                            )
                        )
                except (ValueError, IndexError):
                    continue

        # 字符串
        r = self.ssh.exec_cmd(
            f"strings -n 6 {result.file_path} 2>/dev/null | head -100",
            timeout=30,
        )
        for line in (r.stdout or "").splitlines():
            s = line.strip()
            if len(s) >= 6:
                result.strings.append(
                    StringInfo(
                        value=s[:200],
                        address="0x0",  # objdump -t 不知道地址
                        category=_classify_string(s),
                    )
                )

        if result.functions:
            result.cfg_summary.entry_function = result.functions[0].name

        # 复杂度估算（粗略）
        if len(result.functions) > 50:
            result.cfg_summary.estimated_complexity = "high"
        elif len(result.functions) > 10:
            result.cfg_summary.estimated_complexity = "medium"
        else:
            result.cfg_summary.estimated_complexity = "low"

    # ---------- Ghidra 后端（预留）----------

    def _analyze_ghidra(self, result: BinaryAnalysisResult) -> None:
        """Ghidra Headless 后端（需 /opt/ghidra/support/analyzeHeadless）.

        此方法在 Ghidra 安装后可用。当前沙箱未装 Ghidra，会降级到 r2。
        """
        # 简化：直接复用 r2（避免实现复杂）
        self._analyze_radare2(result)
        result.backend_used = "ghidra_fallback_to_r2"

    # ---------- 后处理 ----------

    def _post_process(self, result: BinaryAnalysisResult) -> None:
        """提取 flag 候选、关联函数、XOR 候选位置。"""
        # 1. flag 候选（所有 flag_like 字符串）
        result.flag_candidates = [
            s.value for s in result.strings if s.category == "flag_like"
        ]
        # 去重保持顺序
        seen = set()
        unique = []
        for fc in result.flag_candidates:
            if fc not in seen:
                seen.add(fc)
                unique.append(fc)
        result.flag_candidates = unique

        # 2. 标记含 flag 字符串的函数（需要 xref，暂时跳过）
        # 简化：如果函数名包含 main/encrypt/check/decrypt 等关键词，标记
        KEY_FUNCS = {"main", "encrypt", "decrypt", "check", "verify", "flag", "key", "drift"}
        for f in result.functions:
            if any(kw in f.name.lower() for kw in KEY_FUNCS):
                f.has_flag_string = True

        # 3. Sprint 9 阶段 2: XOR 候选位置标记
        # 仅在有 r2 后端时执行（需要 sections 信息）
        if result.backend_used in ("radare2", "ghidra_fallback_to_r2", "ghidra"):
            self._detect_xor_hints(result)

    # ---------- XOR 候选位置检测 (Sprint 9 阶段 2) ----------

    # r2 iS 实际输出列: nth paddr size vaddr vsize perm flags type name
    # 例: 0   0x00000400  0xa00 0x100401000  0x1000 -r-x 0x60000060 ---- .text
    _R2_SECTION_RE = re.compile(
        r"^\s*\d+\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+"
        r"0x([0-9a-fA-F]+)\s+(\S+)\s+\S+\s+\S+\s+(\S+)"
    )

    def _parse_r2_sections(self, output: str) -> list[dict[str, Any]]:
        """解析 r2 iS 输出.

        Returns:
            [{"name": ".rdata", "vaddr": 0x100401000, "paddr": 0x1000,
              "vsize": 0x100, "size": 0x80, "perms": "r--"}, ...]
        """
        sections: list[dict[str, Any]] = []
        for line in (output or "").splitlines():
            line = self._clean_ansi(line).strip()
            if not line or line.startswith("["):
                continue
            # 跳过表头
            if line.startswith("nth ") or line.startswith("―"):
                continue
            m = self._R2_SECTION_RE.match(line)
            if not m:
                continue
            try:
                sections.append({
                    "paddr": int(m.group(1), 16),
                    "size": int(m.group(2), 16),
                    "vaddr": int(m.group(3), 16),
                    "vsize": int(m.group(4), 16),
                    "perms": m.group(5),
                    "name": m.group(6),
                })
            except (ValueError, IndexError):
                continue
        return sections

    @staticmethod
    def _xor_decrypt(data: bytes, key: bytes) -> bytes:
        """简单 XOR 解密: c[i] = data[i] ^ key[i % klen]."""
        if not key:
            return b""
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    @staticmethod
    def _ror3_xor_decrypt(data: bytes, key: bytes) -> bytes:
        """ror(3) + XOR 复合解密 (SCADA_Firmware 真实算法): m[i] = ror(c[i] ^ k[i%klen], 3).

        真实算法 (从 SCADA 固件反汇编推导):
        - 加密: c[i] = ror(m[i] ^ k[i%klen], 3)
        - 解密: m[i] = ror(c[i] ^ k[i%klen], 3)  ← 因为 ror 是自逆的 (两次 ror=identity)
        验证: 9 个 movabs qword × KEY42 → "sys_version=...drift_payload=athena{scad4_firmware_root}"
        """
        if not key:
            return b""
        result = bytearray(len(data))
        for i, b in enumerate(data):
            # 关键: 先 XOR key, 再 ror(3) (与 v1 错误算法 ror(c,3)^k 不同)
            xored = b ^ key[i % len(key)]
            result[i] = ((xored >> 3) | (xored << 5)) & 0xFF
        return bytes(result)

    @staticmethod
    def _entropy(data: bytes) -> float:
        """Shannon 熵 (字节级)."""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        total = len(data)
        ent = 0.0
        for c in freq:
            if c == 0:
                continue
            p = c / total
            ent -= p * math.log2(p)
        return ent

    def _is_printable(self, data: bytes, threshold: float = 0.85) -> bool:
        """判断字节流是否大部分可打印 ASCII."""
        if not data:
            return False
        printable = sum(1 for b in data if 0x20 <= b < 0x7F or b in (0x0A, 0x0D, 0x09))
        return printable / len(data) >= threshold

    def _score_xor_decryption(
        self,
        encrypted: bytes,
        key: bytes,
        window_size: int = 32,
        step: int = 16,
    ) -> tuple[float, str, bytes]:
        """评估 XOR 解密结果质量 (Sprint 9 阶段 2 增强).

        策略:
        1. 尝试 xor-only 和 ror3+xor 两种算法
        2. 滑动窗口扫描, 任一窗口命中 flag 模式即得高分
        3. 这样能应对密文在段中任意位置 (如 SCADA .text 段 entry0 movabs)
        4. Sprint 9 增强: 识别 movabs 立即数 (48 b? imm64), 提取 imm64 字节流单独解密

        Args:
            encrypted: 加密字节流
            key: 候选 key
            window_size: 窗口大小 (默认 32 字节)
            step: 滑动步长 (默认 16 字节)

        Returns:
            (score, reason, decrypted_bytes) - score 越大越像正确解密
        """
        if not key or not encrypted:
            return 0.0, "", b""

        # 尝试两种算法, 取最高分
        algorithms = [
            ("xor", self._xor_decrypt(encrypted, key)),
            ("ror3+xor", self._ror3_xor_decrypt(encrypted, key)),
        ]

        best_overall: tuple[float, str, bytes] = (0.0, "", b"")

        for algo_name, decrypted in algorithms:
            dec_text = decrypted.decode("utf-8", errors="replace")

            # 1. 滑动窗口扫描
            if len(encrypted) >= window_size:
                for off in range(0, len(encrypted) - window_size + 1, step):
                    window = decrypted[off:off + window_size]
                    window_text = window.decode("utf-8", errors="replace")
                    for pat in _FLAG_RESULT_PATTERNS:
                        if pat.search(window_text):
                            return 0.95, f"flag 模式在偏移 0x{off:x} 命中 ({algo_name}, key={key!r})", decrypted

            # 2. 整段 flag 模式命中
            for pat in _FLAG_RESULT_PATTERNS:
                if pat.search(dec_text):
                    return 0.95, f"flag 模式命中 ({algo_name}, key={key!r})", decrypted

            # 3. Sprint 9 增强: 识别 movabs 立即数 (48 b? imm64)
            # 在 .text 段中密文常作为 movabs 立即数嵌入, 滑动窗口因指令字节干扰
            # 无法命中. 此处提取所有 imm64 字节流作为密文再扫描 flag 模式.
            movabs_stream = self._extract_movabs_imm64(encrypted)
            if len(movabs_stream) >= 16:
                for algo2_name, decrypt_fn in [
                    ("xor_movabs", self._xor_decrypt),
                    ("ror3+xor_movabs", self._ror3_xor_decrypt),
                ]:
                    dec_movabs = decrypt_fn(movabs_stream, key)
                    dec_movabs_text = dec_movabs.decode("utf-8", errors="replace")
                    for pat in _FLAG_RESULT_PATTERNS:
                        if pat.search(dec_movabs_text):
                            return 0.95, (
                                f"movabs 流 flag 模式命中 ({algo2_name}, "
                                f"key={key!r}, imm64_count={len(movabs_stream) // 8})"
                            ), dec_movabs

            # 4. 可读性
            if self._is_printable(decrypted, threshold=0.90):
                score_reason: tuple[float, str, bytes] = (0.7, f"高可读性 ({algo_name}, key={key!r})", decrypted)
                if score_reason[0] > best_overall[0]:
                    best_overall = score_reason
            elif self._is_printable(decrypted, threshold=0.75):
                score_reason = (0.4, f"中等可读性 ({algo_name}, key={key!r})", decrypted)
                if score_reason[0] > best_overall[0]:
                    best_overall = score_reason

        return best_overall

    @staticmethod
    def _extract_movabs_imm64(data: bytes) -> bytes:
        """提取 x86-64 movabs 立即数 (REX.W + opcode b8-bf + imm64).

        模式: 48 [b8-bf] <8 bytes little-endian>
        典型: movabs rax, 0xc2d66081cec28ed0

        用于 SCADA 类题目: 密文嵌入代码段 movabs 立即数中, 滑动窗口
        因指令字节干扰无法命中, 提取后单独解密可命中 flag 模式.

        过滤条件 (避免误匹配 add/cmp 等指令中的 0x48 0xb? 模式):
        - 跳过全 0 / 全 0xff
        - 跳过 entropy < 3.0 (字节变化小, 像 00 00 00 00 55 01 00 00)
        - 跳过首字节为 0x00 (32-bit 扩展, 不是真密文)
        - 跳过值 < 0x10000000000 (排除 mov reg, <small_int> 模式)
        """
        if not data:
            return b""
        out = bytearray()
        for m in re.finditer(rb"\x48[\xb8-\xbf](.{8})", data):
            imm = m.group(1)
            # 过滤全 0 (movabs reg, 0 - 常见 NOP-like)
            if all(b == 0 for b in imm):
                continue
            # 过滤全 0xff
            if all(b == 0xFF for b in imm):
                continue
            # 过滤 entropy 过低 (字节变化小, 不是真密文)
            # 阈值 2.5: 既过滤明显噪声 (0x0000015500000000 ent=1.06, 0xbbb00000148 ent=2.00),
            # 又保留真密文 (0xc2d66081cec28ed0 ent=2.75)
            ent = BinaryAnalyzer._entropy(imm)
            if ent < 2.5:
                continue
            # 过滤首字节为 0x00 (小值 32-bit 扩展, 通常 mov reg, <imm32>)
            if imm[0] == 0x00:
                continue
            # 过滤值 < 0x10000000000 (10^12 以下, 排除 "mov reg, 0x48" 之类小值)
            val = int.from_bytes(imm, "little")
            if val < 0x10000000000:
                continue
            out.extend(imm)
        return bytes(out)

    def _detect_xor_hints(self, result: BinaryAnalysisResult) -> None:
        """检测 XOR 加密候选位置 (Sprint 9 阶段 2).

        策略:
        1. 提取 r2 sections (.rdata/.data 优先)
        2. 从 flag_like 字符串和短 token 构造候选 key 池
        3. 对每段高熵区域用候选 key 尝试 XOR
        4. 解密结果命中 flag 模式 → 高置信度 hint
        """
        try:
            # 1. 提取 sections
            r = self.ssh.exec_cmd(
                f"r2 -q -e scr.color=0 -c 'iS' {result.file_path} 2>/dev/null",
                timeout=30,
            )
            sections = self._parse_r2_sections(r.stdout or "")
            if not sections:
                return

            # 2. 构造候选 key 池
            # 优先级: flag_like 字符串 → 短 ASCII token (3-6 字节) → 单一短 key
            key_candidates: list[tuple[bytes, str, float]] = []

            # (a) flag_like 字符串（可能是 "KEY42" / "drift=" 等）
            for s in result.strings:
                if s.category == "flag_like":
                    val = s.value
                    # 取 token（用 = 或 : 分隔，取右半部分）
                    token = re.split(r"[=:\s]", val, 1)[-1].strip() if re.search(r"[=:\s]", val) else val
                    if 3 <= len(token) <= 12 and all(0x20 <= ord(c) < 0x7F for c in token):
                        key_candidates.append((token.encode(), f"flag_like:{token}", 0.8))
                    # 整个字符串也作为 key
                    if 3 <= len(val) <= 12 and all(0x20 <= ord(c) < 0x7F for c in val):
                        key_candidates.append((val.encode(), f"flag_like_full:{val}", 0.6))

            # (b) 短 ASCII token (3-6 字节) - 从所有字符串中提取
            # Sprint 9 增强: 不限于 flag_like, general 中含 KEY42 这类短大写 token 也要纳入
            # 关键: 跳过太常见的 "WVSH" / "AUATH" 这类纯随机大写 (entropy 异常高)
            for s in result.strings:
                val = s.value
                # 跳过明显是段名/PE 头噪声
                if val in {".text", ".data", ".rdata", ".bss", ".idata", ".reloc", ".buildid",
                           ".pdata", ".xdata", ".rsrc", "ASCII", "MS Windows"}:
                    continue
                if 3 <= len(val) <= 6 and all(0x20 <= ord(c) < 0x7F for c in val):
                    # 计算 token 熵 - 全随机大写 entropy 接近 log2(26)=4.7
                    # KEY42 这种混合数字的 entropy < 3.5
                    from collections import Counter
                    cnt = Counter(val)
                    token_ent = -sum((c/len(val)) * math.log2(c/len(val))
                                     for c in cnt.values() if c > 0)
                    if val.upper() == val and any(c.isalpha() for c in val) and token_ent < 3.5:
                        # 短大写 token, 偏低熵 (含数字)
                        key_candidates.append((val.encode(), f"short_upper_lowent:{val}", 0.5))
                    elif val.upper() == val and any(c.isalpha() for c in val):
                        # 短大写 token (高熵, 较少优)
                        key_candidates.append((val.encode(), f"short_upper:{val}", 0.4))

            # 去重
            seen_keys: set[bytes] = set()
            unique_keys: list[tuple[bytes, str, float]] = []
            for k_bytes, src, conf in key_candidates:
                if k_bytes not in seen_keys:
                    seen_keys.add(k_bytes)
                    unique_keys.append((k_bytes, src, conf))
            key_candidates = unique_keys[:20]  # 限制最多 20 个 key

            if not key_candidates:
                return

            # 3. 扫描所有段（除 .bss/.reloc 等噪声段）
            # Sprint 9 增强: 也扫 .text 段 (有 movabs 立即数密文)
            # 按 confidence 排序后取 top N
            EXCLUDED_SEGMENTS = {".bss", ".reloc", ".buildid"}
            MAX_HINTS = 8
            candidate_hints: list[XorHint] = []

            for sec in sections:
                if sec["name"] in EXCLUDED_SEGMENTS:
                    continue
                paddr = sec["paddr"]
                size = sec["size"]
                # .text 段放宽到 32KB (SCADA 固件 .text ~10KB)
                max_size = 32768 if sec["name"] == ".text" else 8192
                if size < 16 or size > max_size:
                    continue

                # 提取段字节
                # r2: 'px N @ addr' 打印 N 字节 hex dump
                r = self.ssh.exec_cmd(
                    f"r2 -q -e scr.color=0 -c 'px {size} @ 0x{sec['vaddr']:x}' "
                    f"{result.file_path} 2>/dev/null | head -200",
                    timeout=30,
                )
                # 解析 r2 px 输出
                # 格式: 0x100401000  4865 6c6c 6f20 776f 726c 6420 0000  Hello world ..
                # 即: 8 个 4 字节 hex group (16 字节) + ASCII 16 字符
                data = bytearray()
                for line in self._clean_ansi(r.stdout or "").splitlines():
                    # 跳过表头和空行
                    if not line.strip() or line.startswith("- offset") or line.startswith("offset "):
                        continue
                    # 数据行格式: "<vaddr>  <hex...>  <ascii>"
                    parts = line.split(None, 1)
                    if len(parts) < 2:
                        continue
                    hex_part = parts[1]
                    # 提取前 16 个 hex bytes (8 个 4-char tokens, 每个 = 2 bytes)
                    line_start = len(data)
                    for token in hex_part.split():
                        # 跳过 ASCII (含非 hex 字符或长度异常)
                        if not token or not all(c in "0123456789abcdefABCDEF" for c in token):
                            continue
                        # r2 px 输出: 4-char tokens = 2 bytes, 但有时短 token 是 1 byte
                        # 用偶数长度 pad, 确保正确解析
                        hex_str = token
                        if len(hex_str) % 2 == 1:
                            hex_str = "0" + hex_str
                        try:
                            raw = bytes.fromhex(hex_str)
                        except ValueError:
                            continue
                        data.extend(raw)
                        if len(data) - line_start >= 16:
                            break
                    if len(data) >= size:
                        break

                if len(data) < 16:
                    continue

                data = bytes(data[:size])

                # 跳过全 0 / 全 0xff 段
                if all(b == 0 for b in data) or all(b == 0xFF for b in data):
                    continue

                # 4. 用候选 key 尝试 XOR
                best_score = 0.0
                best_key_data: list[XorKey] = []
                best_preview = ""
                best_reason = ""
                best_decrypted = b""

                for k_bytes, src, base_conf in key_candidates:
                    score, reason, decrypted_bytes = self._score_xor_decryption(data, k_bytes)
                    if score > 0:
                        # 结合 base_conf 和 score
                        combined = score * 0.7 + base_conf * 0.3
                        if combined > best_score:
                            best_score = combined
                            best_reason = reason or f"key={k_bytes!r} 解密产生可读数据"
                            best_decrypted = decrypted_bytes
                            # 重置 best_key_data
                            best_key_data = [
                                XorKey(
                                    key_bytes=k_bytes,
                                    ascii_repr=k_bytes.decode("utf-8", errors="replace"),
                                    source=src,
                                    confidence=combined,
                                )
                            ]
                            best_preview = decrypted_bytes[:32].decode("utf-8", errors="replace")
                        elif combined > 0.3:
                            # 添加为次优候选
                            best_key_data.append(
                                XorKey(
                                    key_bytes=k_bytes,
                                    ascii_repr=k_bytes.decode("utf-8", errors="replace"),
                                    source=src,
                                    confidence=combined,
                                )
                            )

                if best_score > 0.3 and best_key_data:
                    # 按 confidence 排序
                    best_key_data.sort(key=lambda k: -k.confidence)
                    # Sprint 9.5: 提取解密文本 (含 flag 模式优先)
                    decrypted_text = best_decrypted.decode("utf-8", errors="replace")
                    # 优先显示含 flag 的 200 字节片段
                    flag_in_text = None
                    for pat in _FLAG_RESULT_PATTERNS:
                        m = pat.search(decrypted_text)
                        if m:
                            # 提取 flag 周围 100 字节
                            start = max(0, m.start() - 50)
                            end = min(len(decrypted_text), m.end() + 50)
                            flag_in_text = decrypted_text[start:end]
                            break
                    candidate_hints.append(
                        XorHint(
                            segment=sec["name"],
                            offset=paddr,
                            length=size,
                            key_candidates=best_key_data[:3],
                            preview=best_preview,
                            reason=best_reason,
                            confidence=best_score,
                            decrypted_preview=flag_in_text or decrypted_text[:200],
                        )
                    )

            # 按 confidence 降序排序, 取 top MAX_HINTS
            # 这样真实高置信度 hint (flag 模式 0.95) 会排第一
            candidate_hints.sort(key=lambda h: -h.confidence)
            result.xor_hints = candidate_hints[:MAX_HINTS]
        except Exception as e:  # noqa: BLE001
            # 静默失败 - XOR 增强是 best-effort
            return


# ============ ReAct 工具接口 ============

class BinaryAnalyzerTool:  # 不直接继承 Tool，因为 Tool 基类在另一个模块
    """binary_analyze 工具（agent 调用入口）.

    独立类，不继承 ctf_agent.tools.base.Tool 以避免循环导入。
    在 binary_tool.py 中适配为 Tool 接口。
    """
    name = "binary_analyze"
    description = (
        "对二进制文件执行结构化分析，返回 JSON：文件类型/架构/函数列表/字符串/CFG 摘要。"
        "比直接跑 objdump/strings 节省 60%+ token，输出更适合 LLM 解析。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Kali 上二进制文件路径（ELF/PE/APK）",
            },
            "depth": {
                "type": "string",
                "enum": ["auto", "quick", "standard", "deep"],
                "description": "分析深度：auto(自动选择后端) / quick(objdump) / standard(r2) / deep(ghidra)",
            },
        },
        "required": ["file_path"],
    }

    def __init__(self, ssh_client: Any) -> None:
        self.analyzer = BinaryAnalyzer(ssh_client)

    def execute(
        self,
        file_path: str,
        depth: str = "auto",
        **_: Any,
    ) -> str:
        if not file_path:
            return "ERROR: file_path 不能为空"

        result = self.analyzer.analyze(file_path, depth)

        # 返回结构化结果（JSON）+ 简短摘要
        parts = [result.summary(), "", "=== Full JSON ===", result.to_json()]
        return "\n".join(parts)
