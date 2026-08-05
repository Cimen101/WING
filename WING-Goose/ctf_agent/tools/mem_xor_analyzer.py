"""内存 dump 专用分析器 (Memory XOR Analyzer).

背景:
  v5 测试中 RAM_Drift 从 v4 6 步成功退化为 v5 24 步失败。
  根因: LLM 反复尝试多种 XOR key 索引模式,陷入循环。
  本模块提供专用 .txt 内存 dump 分析,自动尝试所有常见 XOR 模式,
  一次性输出所有 flag 候选,LLM 只需 1-2 步即可完成。

支持:
  - 解析 hex dump 格式: PAGE 0x...\n 00000000  25 26 59 23 ...\n 00000010  1f 19 ...
  - 解析 process_map.txt 提取 candidate keys (tag=XXX)
  - 自动剥离死/标记字节 (0xdeadbeef, 0xfaceb00c, 0xcafebabe 等)
  - 尝试 4 种 XOR 模式:
    1. 拼接所有页 header bytes, 连续 XOR key
    2. 拼接所有页 header bytes, 每页重新从 key[0] 开始
    3. 拼接 page 0x00 + 0x10 行, 连续 XOR key
    4. 拼接 page 0x00 + 0x10 行, 每页重新从 key[0] 开始
  - 命中 flag 模式 (athena{...} / flag{...} / CTF{...}) 的高置信度

集成: ctf_agent/tools/mem_xor_tool.py (ReAct Tool 包装)
"""
from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional


# ============ 常见 flag 模式 (与 binary_analyzer.py 一致) ============
_FLAG_PATTERNS = [
    re.compile(r"athena\{[a-zA-Z0-9_!@#$%^&*+=\-]+\}", re.IGNORECASE),
    re.compile(r"flag\{[a-zA-Z0-9_!@#$%^&*+=\-]+\}", re.IGNORECASE),
    re.compile(r"CTF\{[a-zA-Z0-9_!@#$%^&*+=\-]+\}"),
]


# 死/标记字节序列 (4-byte magic)
_MARKER_SEQUENCES = [
    b"\xde\xad\xbe\xef",  # DEADBEEF
    b"\xfa\xce\xb0\x0c",  # FACEB00C
    b"\xca\xfe\xba\xbe",  # CAFEBABE
    b"\xfe\xed\xfa\xce",  # FEEDFACE
    b"\xba\xbe\xfe\xed",  # BABEFEE D
]


# ============ 数据结构 ============

@dataclass
class PageInfo:
    """单页信息."""
    base: int
    header_bytes: list[int]  # 0x00 行的字节
    body_bytes: list[int]  # 0x10 行的字节
    all_bytes: list[int]  # header + body

    def __post_init__(self) -> None:
        # 自动拼接 all_bytes
        if not self.all_bytes and (self.header_bytes or self.body_bytes):
            self.all_bytes = self.header_bytes + self.body_bytes


@dataclass
class XorDecryption:
    """单次 XOR 解密结果."""
    key: str
    key_bytes_hex: str
    mode: str  # "header_concat" / "header_per_page" / "full_concat" / "full_per_page"
    plaintext: str
    plaintext_hex: str
    confidence: float
    is_flag: bool = False
    flag_value: str = ""


@dataclass
class MemoryDumpAnalysis:
    """内存 dump 分析完整结果."""
    dump_path: str
    process_map_path: str = ""
    pages: list[PageInfo] = field(default_factory=list)
    candidate_keys: list[str] = field(default_factory=list)
    decryptions: list[XorDecryption] = field(default_factory=list)
    flag_candidates: list[str] = field(default_factory=list)
    backend_used: str = "text_parser"
    analysis_time: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def summary(self) -> str:
        """生成适合 LLM 阅读的简短摘要."""
        lines = [
            "=== Memory Dump XOR Analysis ===",
            f"Dump: {self.dump_path}",
            f"Pages: {len(self.pages)}",
            f"Candidate keys: {self.candidate_keys}",
            f"Backend: {self.backend_used}",
            f"Analysis time: {self.analysis_time:.2f}s",
        ]
        if self.error:
            lines.append(f"Error: {self.error}")
        if self.pages:
            lines.append("Page details:")
            for i, p in enumerate(self.pages):
                lines.append(
                    f"  Page {i}: base=0x{p.base:08x} header={len(p.header_bytes)}B "
                    f"body={len(p.body_bytes)}B"
                )
        if self.flag_candidates:
            lines.append(f"🚩 Flag candidates ({len(self.flag_candidates)}):")
            for fc in self.flag_candidates:
                lines.append(f"  >>> {fc} <<<")
        elif self.decryptions:
            lines.append("Top decryptions (top 5 by confidence):")
            top = sorted(self.decryptions, key=lambda d: -d.confidence)[:5]
            for d in top:
                lines.append(
                    f"  [{d.mode}] key={d.key!r} conf={d.confidence:.2f} "
                    f"| {d.plaintext[:120]}"
                )
        return "\n".join(lines)


# ============ 解析器 ============

# 匹配 PAGE 0x8a0000 等
_RE_PAGE = re.compile(r"^PAGE\s+0x([0-9a-fA-F]+)\s*$", re.MULTILINE)
# 匹配 00000000  25 26 59 23 3a 25 29 43 27 39 1b 22  |%&Y#:%)C'9."|
_RE_HEX_LINE = re.compile(
    r"^([0-9a-fA-F]{8})\s+((?:[0-9a-fA-F]{2}\s?){1,32})",
    re.MULTILINE,
)
# 匹配 tag=XXX
_RE_TAG = re.compile(r"tag=([A-Z0-9_]+)", re.IGNORECASE)


def _parse_dump_content(content: str) -> list[PageInfo]:
    """解析 hex dump 文本,提取所有页的 (base, header_bytes, body_bytes).

    hex dump 格式:
        PAGE 0x8a0000
        00000000  25 26 59 23 3a 25 29 43 27 39 1b 22  |%&Y#:%)C'9."|
        00000010  1f 19 1c 0a de ad be ef 08 0f 1c 1a 0a 3d 0d 0d  |.............=..|

        PAGE 0x8a1000
        ...
    """
    pages: list[PageInfo] = []
    # 按 PAGE 分块
    page_blocks = _RE_PAGE.split(content)
    # page_blocks[0] = 第一个 PAGE 之前的内容 (header 部分,丢弃)
    # page_blocks[1::2] = base 地址
    # page_blocks[2::2] = 块内容
    bases = page_blocks[1::2]
    bodies = page_blocks[2::2]

    for base_hex, body in zip(bases, bodies):
        try:
            base = int(base_hex, 16)
        except ValueError:
            continue

        header_bytes: list[int] = []
        body_bytes: list[int] = []

        for m in _RE_HEX_LINE.finditer(body):
            offset_hex = m.group(1)
            hex_part = m.group(2).strip()
            try:
                offset = int(offset_hex, 16)
            except ValueError:
                continue

            bytes_in_line = [int(b, 16) for b in hex_part.split() if b]
            if not bytes_in_line:
                continue

            if offset == 0x00:
                header_bytes = bytes_in_line
            elif offset == 0x10:
                body_bytes = bytes_in_line
            else:
                # 其他行也归为 body
                body_bytes.extend(bytes_in_line)

        if header_bytes or body_bytes:
            pages.append(
                PageInfo(
                    base=base,
                    header_bytes=header_bytes,
                    body_bytes=body_bytes,
                    all_bytes=[],
                )
            )

    return pages


def _parse_process_map(content: str) -> list[str]:
    """从 process_map.txt 提取 candidate keys (tag=XXX)."""
    tags = _RE_TAG.findall(content)
    # 去重保持顺序
    seen: set[str] = set()
    result: list[str] = []
    for t in tags:
        if t not in seen:
            seen.add(t)
            result.append(t)
    return result


def _strip_markers(data: bytes) -> bytes:
    """剥离 4-byte 标记序列 (DEADBEEF 等)."""
    out = bytearray()
    i = 0
    while i < len(data):
        matched = False
        for marker in _MARKER_SEQUENCES:
            if data[i:i + len(marker)] == marker:
                matched = True
                i += len(marker)
                break
        if not matched:
            out.append(data[i])
            i += 1
    return bytes(out)


def _xor_with_key(data: bytes, key: bytes, per_chunk_reset: bool = False,
                  chunk_size: int = 0) -> bytes:
    """XOR data with key.

    Args:
        data: 待解密数据
        key: XOR key
        per_chunk_reset: 若 True, 每 chunk_size 字节重新从 key[0] 开始
        chunk_size: 块大小 (per_chunk_reset=True 时使用)
    """
    if not key:
        return data
    out = bytearray()
    if per_chunk_reset and chunk_size > 0:
        for i, b in enumerate(data):
            chunk_offset = i % chunk_size
            out.append(b ^ key[chunk_offset % len(key)])
    else:
        for i, b in enumerate(data):
            out.append(b ^ key[i % len(key)])
    return bytes(out)


def _check_flag(plaintext: bytes) -> tuple[bool, str]:
    """检查 plaintext 是否命中 flag 模式."""
    try:
        text = plaintext.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return False, ""

    for pat in _FLAG_PATTERNS:
        m = pat.search(text)
        if m:
            return True, m.group(0)
    return False, ""


def _score_plaintext(plaintext: bytes, key: bytes, mode: str) -> float:
    """评估 plaintext 的可信度 [0, 1].

    评分因素:
    - 是否命中 flag 模式 (+0.5)
    - 可打印 ASCII 比例 (+0.3)
    - header bytes 模式 vs full bytes 模式 (header 模式 +0.1)
    """
    score = 0.0
    is_flag, _ = _check_flag(plaintext)
    if is_flag:
        score += 0.5

    # 可打印 ASCII 比例
    if plaintext:
        printable = sum(1 for b in plaintext if 32 <= b <= 126)
        ratio = printable / len(plaintext)
        score += ratio * 0.3

    # header 模式加分 (适用于结构化内存 dump)
    if "header" in mode:
        score += 0.1

    return min(score, 1.0)


# ============ 核心类 ============

class MemXorAnalyzer:
    """内存 dump 专用分析器.

    用法:
        analyzer = MemXorAnalyzer(ssh_client)
        result = analyzer.analyze(
            dump_path="/tmp/ctf_workspace/ram_dump.txt",
            process_map_path="/tmp/ctf_workspace/process_map.txt",
        )
        print(result.summary())
    """

    def __init__(self, ssh_client: Any) -> None:
        self.ssh = ssh_client

    def analyze(
        self,
        dump_path: str,
        process_map_path: Optional[str] = None,
    ) -> MemoryDumpAnalysis:
        """分析内存 dump,提取 flag 候选.

        Args:
            dump_path: 沙箱上 .txt 格式 hex dump 路径
            process_map_path: 可选, 沙箱上 process_map.txt 路径
        """
        started = time.monotonic()
        result = MemoryDumpAnalysis(dump_path=dump_path)

        try:
            # 1. 读取 dump 内容
            r = self.ssh.exec_cmd(f"cat {dump_path}", timeout=10)
            if not r.is_success:
                result.error = f"读取 dump 失败: {r.stderr[:200]}"
                return result
            dump_content = r.stdout or ""

            # 2. 解析页信息
            result.pages = _parse_dump_content(dump_content)
            if not result.pages:
                result.error = "未识别到任何 PAGE 块,文件可能不是标准 hex dump 格式"
                return result

            # 3. 读取 process_map (可选)
            candidate_keys: list[str] = []
            if process_map_path:
                r2 = self.ssh.exec_cmd(f"cat {process_map_path}", timeout=10)
                if r2.is_success:
                    result.process_map_path = process_map_path
                    candidate_keys = _parse_process_map(r2.stdout or "")
            result.candidate_keys = candidate_keys

            # 4. 如果 process_map 没提供 keys, 尝试从 dump 内容提取短 ASCII tokens
            if not candidate_keys:
                candidate_keys = self._extract_short_tokens(dump_content)
                result.candidate_keys = candidate_keys

            # 5. 尝试所有 (key, mode) 组合
            result.decryptions = self._try_all_decryptions(
                result.pages, candidate_keys
            )

            # 6. 提取 flag 候选
            for d in result.decryptions:
                if d.is_flag and d.flag_value:
                    if d.flag_value not in result.flag_candidates:
                        result.flag_candidates.append(d.flag_value)

        except Exception as e:  # noqa: BLE001
            result.error = f"{type(e).__name__}: {e}"

        result.analysis_time = time.monotonic() - started
        return result

    def _extract_short_tokens(self, content: str) -> list[str]:
        """从 dump 内容中提取短 ASCII tokens (3-10 字符, 全字母数字)."""
        # 提取所有 "tag=XXX" 模式 (如果 process_map 嵌在 dump 中)
        tokens = _RE_TAG.findall(content)
        # 提取连续 ASCII 序列
        ascii_tokens = re.findall(r"\b[A-Z][A-Z0-9_]{2,9}\b", content)
        # 去重保持顺序
        seen: set[str] = set()
        result: list[str] = []
        for t in tokens + ascii_tokens:
            if t not in seen and t.isupper() and t.isalnum() or "_" in t:
                seen.add(t)
                result.append(t)
        return result[:10]  # 限制最多 10 个

    def _try_all_decryptions(
        self,
        pages: list[PageInfo],
        keys: list[str],
    ) -> list[XorDecryption]:
        """尝试所有 (key, mode) 组合,返回所有解密结果."""
        results: list[XorDecryption] = []
        if not pages or not keys:
            return results

        # 准备 4 种数据切片
        # 模式 1: header_concat - 拼接所有 header bytes, 连续 XOR
        header_concat = bytearray()
        for p in pages:
            header_concat.extend(p.header_bytes)
        header_concat = bytes(header_concat)

        # 模式 2: header_per_page - 每页 header 重新从 key[0] 开始
        # 模式 3: full_concat - 拼接所有 bytes, 连续 XOR
        full_concat = bytearray()
        for p in pages:
            full_concat.extend(p.all_bytes)
        full_concat = bytes(full_concat)

        # 模式 4: full_per_page - 每页 all_bytes 重新从 key[0] 开始

        # 剥离标记 (header_concat 通常不含标记, 但 full_concat 可能)
        header_concat_clean = _strip_markers(header_concat)
        full_concat_clean = _strip_markers(full_concat)

        modes_data = [
            ("header_concat", header_concat_clean, False, 0),
            ("header_per_page", header_concat_clean, True, 32),  # 假设每页 < 32 字节
            ("full_concat", full_concat_clean, False, 0),
            ("full_per_page", full_concat_clean, True, 256),
        ]

        for key_str in keys:
            key = key_str.encode("utf-8")
            for mode_name, data, per_chunk, chunk_size in modes_data:
                if not data:
                    continue
                plain = _xor_with_key(data, key, per_chunk, chunk_size)
                is_flag, flag_value = _check_flag(plain)
                conf = _score_plaintext(plain, key, mode_name)
                # 如果命中 flag, 大幅提升置信度
                if is_flag:
                    conf = max(conf, 0.9)

                results.append(
                    XorDecryption(
                        key=key_str,
                        key_bytes_hex=key.hex(),
                        mode=mode_name,
                        plaintext=plain.decode("utf-8", errors="replace"),
                        plaintext_hex=plain.hex(),
                        confidence=conf,
                        is_flag=is_flag,
                        flag_value=flag_value,
                    )
                )

        return results
