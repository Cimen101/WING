"""L2 OCR 工具 (Sprint 12 M3.5 新增, Sprint 13 增强).

封装 Kali 上预装的 Tesseract OCR 引擎为 Tool 接口:
- OcrTool: 提取图片中的文字 (支持多语言: eng/rus/chi_sim/chi_tra/jpn 等)

设计原则:
- 与现有 OSINT 工具集互补: exiftool 看元数据, ocr 提取文字
- Tesseract 5.5.0+ 已支持 100+ 语言
- 输出截断避免 LLM 上下文污染
- 自动检测可用性, 未装则降级提示
- Sprint 13 增强: 检测"假阳性"输出 (如 "Estimating resolution as 381" / "Tesseract Open Source")
  标记为 `no_text_detected`, 避免 LLM 误用做搜索 query

使用场景:
- OSINT 图片题: 提取照片中的标志/路牌/文字线索
- forensics 截图分析: 提取截图中的关键文本
- 包含文字线索的 challenge
"""
from __future__ import annotations

import re
from typing import Any, Optional

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool


# 输出截断阈值
_MAX_OUTPUT = 4000
_TRUNCATED_SUFFIX = "\n... (输出截断,共 {total} 字符)"


# Sprint 13 P0: OCR 假阳性检测 — 标记"非真实文字"输出
# 这些是 tesseract 在无文字时的内部日志/状态, 不是真实 OCR 结果
_OCR_FALSE_POSITIVES = [
    re.compile(r"^\s*Estimating resolution as \d+\s*$", re.MULTILINE),
    re.compile(r"^\s*Tesseract Open Source OCR Engine.*$", re.MULTILINE),
    re.compile(r"^\s*Page \d+$", re.MULTILINE),
    re.compile(r"^\s*OSD:.*$", re.MULTILINE),
    re.compile(r"^\s*Warning.*$", re.MULTILINE | re.IGNORECASE),
]

# 真阳性的最小字符数 (低于此视为"没文字")
_MIN_REAL_TEXT_CHARS = 20


def _is_likely_no_text(text: str) -> bool:
    """Sprint 13 P0: 判断 OCR 输出是否为"无文字"假阳性.

    Returns:
        True: 输出只是 tesseract 内部日志/状态, 无真实文字
        False: 输出包含真实文字
    """
    if not text or not text.strip():
        return True
    # 清理后字符数
    cleaned = text.strip()
    if len(cleaned) < _MIN_REAL_TEXT_CHARS:
        return True
    # 检测假阳性模式
    for pat in _OCR_FALSE_POSITIVES:
        if pat.search(cleaned):
            # 全部内容都是假阳性
            non_fp = pat.sub("", cleaned).strip()
            if len(non_fp) < _MIN_REAL_TEXT_CHARS:
                return True
    return False


# 常用语言代码 + 全名映射 (用于 LLM 提示)
LANG_HELP = {
    "eng": "英文 (Latin)",
    "rus": "俄文 (Cyrillic)",
    "chi_sim": "简体中文",
    "chi_tra": "繁体中文",
    "jpn": "日文",
    "kor": "韩文",
    "ara": "阿拉伯文",
    "deu": "德文",
    "fra": "法文",
    "spa": "西班牙文",
}


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + _TRUNCATED_SUFFIX.format(total=len(text))


def _check_tool(ssh: SSHClient, tool_name: str) -> bool:
    """检测 Kali 上工具是否可用."""
    r = ssh.exec_cmd(f"which {tool_name}", timeout=5)
    return r.is_success and tool_name in r.stdout


class OcrTool(Tool):
    """Tesseract OCR 文字提取 (Sprint 12 M3.5).

    用途: 从图片/JPEG/PNG/PDF 中提取文字.
    适用: OSINT 图片题 (有标志/路牌/文字线索), forensics 截图分析.
    不适用: petroglyphs 抽象图片 (无文字, 需 reverse image 工具).
    """

    name = "ocr"
    description = (
        "Tesseract OCR 文字提取 (图片 → 文字).\n"
        "用法: ocr(file_path='/tmp/x.jpg', lang='eng') → 提取的文字.\n"
        "支持格式: JPEG, PNG, TIFF, BMP, GIF, PDF, WebP (Tesseract 5.5.0).\n"
        "支持语言: eng, rus, chi_sim, chi_tra, jpn, kor, ara, deu, fra, spa (可组合, 如 'eng+rus').\n"
        "OSINT/forensics 题用法: 先用 exiftool 读 EXIF (GPS/相机), "
        "如果图片含可见文字 (路牌/标志/说明), 用 ocr 提取.\n"
        "Kali 工具路径: /usr/bin/tesseract (5.5.0 已验证可用).\n"
        "⚠️ 注意: OCR 对抽象图片 (岩画/壁画/无文字) 无效, 这种情况用 osm_geocode + LLM 知识推理."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Kali 上图片/文件的绝对路径 (如 /tmp/ctf_real3/Where_am_i/Whereami.jpeg)",
            },
            "lang": {
                "type": "string",
                "description": (
                    "OCR 语言代码 (默认 'eng'). 支持: "
                    + ", ".join(f"{k} ({v})" for k, v in LANG_HELP.items())
                    + ". 可组合多个 (如 'eng+chi_sim')."
                ),
                "default": "eng",
            },
            "psm": {
                "type": "integer",
                "description": (
                    "Page Segmentation Mode (默认 3 - 自动). "
                    "常用: 3=auto, 6=uniform block, 7=单行, 11=sparse text, 12=sparse+OSD."
                ),
                "default": 3,
            },
        },
        "required": ["file_path"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh = ssh_client
        self._available: Optional[bool] = None

    def _ensure(self) -> str:
        if self._available is None:
            self._available = _check_tool(self.ssh, "tesseract")
        if not self._available:
            return (
                "ERROR: tesseract 未在 Kali 上安装.\n"
                "降级方案: apt install tesseract-ocr [tesseract-ocr-chi-sim tesseract-ocr-rus]."
            )
        return ""

    def execute(self, file_path: str, lang: str = "eng", psm: int = 3, **_: Any) -> str:
        if not file_path:
            return "ERROR: file_path 不能为空"
        err = self._ensure()
        if err:
            return err

        # 校验 lang (Tesseract 不支持的语言会报错)
        if not re.match(r"^[a-z_+\-]+$", lang):
            return f"ERROR: lang 格式非法: '{lang}' (只允许字母+下划线+加号)"

        # 校验 psm (0-13, 详见 tesseract --help-psm)
        psm = max(0, min(int(psm), 13))

        # 用临时文件保存 OCR 输出, 然后 cat (避免 stdout 中文/特殊字符编码问题)
        out_tmp = "/tmp/ocr_output.txt"
        cmd = (
            f"tesseract '{file_path}' /tmp/ocr_output -l '{lang}' --psm {psm} 2>&1 "
            f"&& echo ===RESULT=== && cat {out_tmp}"
        )
        r = self.ssh.exec_cmd(cmd, timeout=30)
        raw = r.stdout or ""

        if not raw:
            return f"OCR 无输出. 文件可能不是图片, 或图片太小 (太小字 OCR 失败). STDERR: {r.stderr[:200]}"

        # 切分 Tesseract 进度输出 vs 实际结果
        if "===RESULT===" in raw:
            actual = raw.split("===RESULT===", 1)[1].strip()
            tesseract_log = raw.split("===RESULT===", 1)[0].strip()
        else:
            actual = raw.strip()
            tesseract_log = ""

        if not actual:
            return (
                "OCR 提取出 0 字符. 文件可能没有可见文字 (岩画/纯色块).\n"
                "[NO_TEXT_DETECTED] Sprint 13 P0: 图片无文字, 不要拿 OCR 输出做 web_search query.\n"
                "提示: 换 lang (eng+rus+chi_sim 组合), 或换 psm (11=sparse text), "
                "或用 LLM 知识推理 (OSINT 抽象图用 osm_geocode 拿坐标)."
            )

        # Sprint 13 P0: 检测假阳性 (如 "Estimating resolution as 381" 是 tesseract 内部状态, 不是真实文字)
        if _is_likely_no_text(actual):
            return (
                f"[NO_TEXT_DETECTED] Sprint 13 P0: OCR 未提取出真实文字 (只输出 {len(actual)} 字符 tesseract 内部日志).\n"
                f"原始输出: {actual[:200]}\n"
                f"⚠️ 不要用上述内容做 web_search query (这是 tesseract 内部状态, 不是图片文字).\n"
                f"建议: 直接用 osm_geocode 找坐标, 或用 LLM 知识推理 (图片线索已在题目描述中)."
            )

        # 提取关键元数据
        line_count = actual.count("\n") + 1
        char_count = len(actual)
        word_count = len(actual.split())

        # 移除空行, 找出最长的几行 (最有信息量)
        non_empty_lines = [l for l in actual.split("\n") if l.strip()]
        top_lines = sorted(non_empty_lines, key=len, reverse=True)[:5]

        result_lines = [
            f"=== OCR 提取结果 (lang='{lang}', psm={psm}) ===",
            f"文件: {file_path}",
            f"统计: {char_count} 字符, {word_count} 词, {line_count} 行",
        ]
        if tesseract_log:
            result_lines.append(f"tesseract log: {tesseract_log[:200]}")

        if top_lines:
            result_lines.append("\n[最长的 5 行 (可能含关键信息)]")
            for i, line in enumerate(top_lines, 1):
                result_lines.append(f"  {i}. {line[:200]}")

        result_lines.append("\n[完整 OCR 输出]")
        result_lines.append(actual)
        return _truncate("\n".join(result_lines))


def ocr_tool(ssh_client: SSHClient) -> list[Tool]:
    """创建 OCR 工具 (Sprint 12 M3.5).

    Args:
        ssh_client: 已连接的 SSHClient 实例

    Returns:
        OCR 工具列表: ocr
    """
    return [OcrTool(ssh_client)]


__all__ = ["OcrTool", "ocr_tool", "LANG_HELP"]
