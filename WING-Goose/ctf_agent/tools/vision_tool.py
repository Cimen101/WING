"""L2 全模态识别工具 (新增, 扩展全模态).

接入小米 MIMO-2.5 全模态模型, 支持图片/视频/音频理解:
- 图片: 识别符号/图形/文字 (OCR 无法处理的抽象图形、密码符号、手写体等)
- 视频: 分析视频内容/关键帧/画面变化 (CTF 视频隐写/帧分析)
- 音频: 语音内容识别/音频隐写分析 (SSTV/摩斯电码/频谱图)

设计原则:
- 在 Kali 上执行 (文件不传到本地, 避免大文件 SSH 传输)
- 图片: 自动压缩到 1024px 最大边 (控制 API 调用体积)
- 视频: 用 ffmpeg 提取关键帧或压缩 (避免超 4MB 限制)
- 音频: 用 ffmpeg 转码到 16kHz mono (控制体积)
- question 用 base64 编码传入, 避免转义问题
- 依赖 Kali 预装 Python3 + PIL (Pillow) + ffmpeg

使用场景:
- Crypto 图片密码题 (dragon-spell 等): 识别符号并转为文字
- Misc/Forensics 视频/音频题: 分析视频画面/音频内容
- OCR 失败时的兜底 (手写体、艺术字、符号文字)
"""
from __future__ import annotations

import base64
from typing import Any, Optional

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool


# 小米 MIMO-2.5 全模态模型配置
MIMO_API_URL = "https://token-plan-cn.xiaomimimo.com/v1/chat/completions"
MIMO_API_KEY = "tp-cgg7b3h86cg0f4h47m5ir6acyptqpvwvxmpphy3sxei3kkx6"
MIMO_MODEL = "mimo-v2.5"

# 输出截断阈值
_MAX_OUTPUT = 6000
_TRUNCATED_SUFFIX = "\n... (输出截断,共 {total} 字符)"

# Kali 上执行的 Python 脚本 (用 base64 传参避免转义)
# 支持图片/视频/音频全模态
_VISION_SCRIPT = r'''import base64, json, sys, io, os, subprocess, urllib.request
file_path = base64.b64decode(sys.argv[1]).decode("utf-8")
question = base64.b64decode(sys.argv[2]).decode("utf-8")

# 按扩展名/魔数判断模态类型
def detect_modality(fp):
    ext = os.path.splitext(fp)[1].lower()
    IMG_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff", ".tif"}
    VID_EXT = {".mp4", ".mpeg", ".mpg", ".avi", ".mov", ".mkv", ".webm", ".flv", ".wmv", ".3gp"}
    AUD_EXT = {".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a", ".wma", ".opus", ".amr"}
    if ext in IMG_EXT:
        return "image", ext
    if ext in VID_EXT:
        return "video", ext
    if ext in AUD_EXT:
        return "audio", ext
    # 无扩展名或未知: 读魔数
    try:
        with open(fp, "rb") as f:
            head = f.read(16)
        if head.startswith(b"\x89PNG") or head.startswith(b"\xff\xd8\xff") or head.startswith(b"GIF8"):
            return "image", ".jpg"
        if head.startswith(b"ID3") or head.startswith(b"\xff\xfb") or head.startswith(b"fLaC") or head.startswith(b"OggS"):
            return "audio", ".mp3"
        if head.startswith(b"\x00\x00\x00") and (b"ftyp" in head or b"moov" in head):
            return "video", ".mp4"
    except Exception:
        pass
    # 默认当图片处理 (兼容旧行为)
    return "image", ".jpg"

modality, ext = detect_modality(file_path)

# ── 图片处理: PIL 压缩到 1024px JPEG ──
def prepare_image(fp):
    try:
        from PIL import Image
        img = Image.open(fp)
        if img.mode in ("RGBA", "P", "LA"):
            img = img.convert("RGB")
        max_dim = 1024
        if max(img.size) > max_dim:
            img.thumbnail((max_dim, max_dim), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=85)
        return base64.b64encode(buf.getvalue()).decode(), "image/jpeg"
    except Exception as e:
        # PIL 不可用或非图片: 尝试直接 base64 读文件
        try:
            with open(fp, "rb") as f:
                raw = f.read()
            if len(raw) > 4 * 1024 * 1024:
                print("ERROR: image file too large (>4MB) and PIL unavailable for compression")
                sys.exit(0)
            return base64.b64encode(raw).decode(), "image/jpeg"
        except Exception as e2:
            print(f"ERROR: cannot read image file: {e2}")
            sys.exit(0)

# ── 视频处理: ffmpeg 压缩到 480p + 限长 30s, 避免超体积 ──
def prepare_video(fp):
    tmp = "/tmp/_mimo_video.mp4"
    try:
        # 压缩: 480p, 限 30s, 降低码率
        subprocess.run(
            ["ffmpeg", "-y", "-i", fp, "-t", "30", "-vf", "scale=-2:480",
             "-b:v", "200k", "-an", "-movflags", "+faststart", tmp],
            capture_output=True, timeout=60,
        )
        with open(tmp, "rb") as f:
            raw = f.read()
        if len(raw) > 4 * 1024 * 1024:
            # 仍太大: 进一步降码率
            subprocess.run(
                ["ffmpeg", "-y", "-i", fp, "-t", "20", "-vf", "scale=-2:360",
                 "-b:v", "100k", "-an", "-movflags", "+faststart", tmp],
                capture_output=True, timeout=60,
            )
            with open(tmp, "rb") as f:
                raw = f.read()
        if len(raw) > 4 * 1024 * 1024:
            print("ERROR: video too large even after compression (>4MB), extract key frames instead")
            sys.exit(0)
        return base64.b64encode(raw).decode(), "video/mp4"
    except FileNotFoundError:
        print("ERROR: ffmpeg not installed on Kali")
        sys.exit(0)
    except Exception as e:
        print(f"ERROR: video prepare failed: {e}")
        sys.exit(0)

# ── 音频处理: ffmpeg 转码到 16kHz mono wav, 限长 60s ──
def prepare_audio(fp):
    tmp = "/tmp/_mimo_audio.wav"
    try:
        subprocess.run(
            ["ffmpeg", "-y", "-i", fp, "-t", "60", "-ar", "16000", "-ac", "1", tmp],
            capture_output=True, timeout=60,
        )
        with open(tmp, "rb") as f:
            raw = f.read()
        if len(raw) > 4 * 1024 * 1024:
            # 降采样到 8kHz
            subprocess.run(
                ["ffmpeg", "-y", "-i", fp, "-t", "30", "-ar", "8000", "-ac", "1", tmp],
                capture_output=True, timeout=60,
            )
            with open(tmp, "rb") as f:
                raw = f.read()
        if len(raw) > 4 * 1024 * 1024:
            print("ERROR: audio too large even after compression (>4MB)")
            sys.exit(0)
        return base64.b64encode(raw).decode(), "audio/wav"
    except FileNotFoundError:
        print("ERROR: ffmpeg not installed on Kali")
        sys.exit(0)
    except Exception as e:
        print(f"ERROR: audio prepare failed: {e}")
        sys.exit(0)

# 根据模态准备数据
if modality == "image":
    data_b64, mime = prepare_image(file_path)
    content_type = "image_url"
    url_key = "url"
    url_prefix = f"data:{mime};base64,"
elif modality == "video":
    data_b64, mime = prepare_video(file_path)
    content_type = "video_url"
    url_key = "url"
    url_prefix = f"data:{mime};base64,"
else:  # audio
    data_b64, mime = prepare_audio(file_path)
    content_type = "audio_url"
    url_key = "url"
    url_prefix = f"data:{mime};base64,"

API_URL = "https://token-plan-cn.xiaomimimo.com/v1/chat/completions"
API_KEY = "tp-cgg7b3h86cg0f4h47m5ir6acyptqpvwvxmpphy3sxei3kkx6"
MODEL = "mimo-v2.5"

payload = {
    "model": MODEL,
    "messages": [{"role": "user", "content": [
        {"type": "text", "text": question},
        {"type": content_type, content_type: {url_key: f"{url_prefix}{data_b64}"}},
    ]}],
    "max_tokens": 2000,
}
import time as _time
last_err = ""
for attempt in range(3):
    try:
        req = urllib.request.Request(
            API_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        content = data["choices"][0]["message"]["content"]
        print(content)
        sys.exit(0)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        last_err = f"HTTP {e.code} - {body}"
    except Exception as e:
        last_err = f"{type(e).__name__}: {e}"
    if attempt < 2:
        _time.sleep(3)
print(f"ERROR: {last_err} (after 3 retries)")
'''


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + _TRUNCATED_SUFFIX.format(total=len(text))


class VisionAnalyzeTool(Tool):
    """MIMO-2.5 全模态识别 (扩展全模态).

    用途: 让多模态大模型理解图片/视频/音频并回答问题.
    适用: 符号识别 (图片密码题)、截图分析、视频帧分析、音频内容识别.
    不适用: 纯文字 OCR (先用 ocr 工具, 更快).
    """

    name = "vision_analyze"
    description = (
        "MIMO-2.5 全模态识别 (图片/视频/音频 → 模型理解 → 文字回答).\n"
        "用法: vision_analyze(file_path='/tmp/x.png', question='识别图中所有符号并转为字母') → 模型回答.\n"
        "支持模态:\n"
        "  - 图片: PNG/JPEG/GIF/BMP/WebP (自动压缩到 1024px)\n"
        "  - 视频: MP4/MPEG/AVI/MOV/MKV/WebM (ffmpeg 压缩到 480p + 限长 30s)\n"
        "  - 音频: MP3/WAV/OGG/FLAC/AAC/M4A (ffmpeg 转码到 16kHz mono + 限长 60s)\n"
        "适用场景:\n"
        "  - 图片密码题: 识别替换密码符号 (runes/符号字母) → 转为文字\n"
        "  - 截图/UI 分析: 读取界面中的文字、按钮、布局\n"
        "  - 视频题: 分析视频画面内容/隐藏信息/帧间差异\n"
        "  - 音频题: 识别语音内容/SSTV/摩斯电码/音频隐写\n"
        "  - OCR 兜底: 手写体/艺术字/符号文字 (tesseract 失败时用)\n"
        "⚠️ 纯文字图片优先用 ocr 工具 (更快). 本工具用于需要'理解'媒体内容的场景."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Kali 上文件的绝对路径 (图片/视频/音频, 如 /tmp/ctf/puzzle.png)",
            },
            "question": {
                "type": "string",
                "description": (
                    "向模型提出的问题 (必填). 例如:\n"
                    "  - '识别图中所有不同符号, 按出现顺序列出, 每个符号对应一个英文字母'\n"
                    "  - '图中有哪些文字? 完整输出'\n"
                    "  - '描述这段视频的内容, 是否有异常画面或隐藏信息'\n"
                    "  - '这段音频的语音内容是什么? 是否有摩斯电码或 SSTV 信号'\n"
                    "  - '这是一个替换密码的密文图片, 请识别所有符号并转换为字母文本'"
                ),
            },
        },
        "required": ["file_path", "question"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh = ssh_client

    def execute(self, file_path: str, question: str = "", **_: Any) -> str:
        if not file_path:
            return "ERROR: file_path 不能为空"
        if not question:
            return "ERROR: question 不能为空 (告诉模型要识别什么)"

        # base64 编码参数 (避免 shell 转义问题)
        fp_b64 = base64.b64encode(file_path.encode("utf-8")).decode("ascii")
        q_b64 = base64.b64encode(question.encode("utf-8")).decode("ascii")

        # 写脚本到 Kali 并执行
        script_b64 = base64.b64encode(_VISION_SCRIPT.encode("utf-8")).decode("ascii")
        cmd = (
            f"echo '{script_b64}' | base64 -d > /tmp/_vision_analyze.py && "
            f"python3 /tmp/_vision_analyze.py '{fp_b64}' '{q_b64}' 2>&1"
        )
        r = self.ssh.exec_cmd(cmd, timeout=400)
        raw = (r.stdout or "").strip()

        if not raw:
            return (
                f"vision_analyze 无输出. STDERR: {(r.stderr or '')[:300]}\n"
                f"可能原因: Kali 网络无法访问 MIMO API, 或 PIL/ffmpeg 未安装."
            )

        # 检测错误
        if raw.startswith("ERROR:"):
            return f"vision_analyze 调用失败:\n{raw}\n\n建议: 检查 Kali 网络是否可访问 token-plan-cn.xiaomimimo.com, 以及 ffmpeg 是否已安装 (视频/音频需要)"

        # 成功: 返回模型回答
        result_lines = [
            f"=== MIMO-2.5 全模态识别结果 ===",
            f"文件: {file_path}",
            f"问题: {question[:200]}",
            "",
            raw,
        ]
        return _truncate("\n".join(result_lines))


def vision_tools(ssh_client: SSHClient) -> list[Tool]:
    """创建视觉识别工具.

    Args:
        ssh_client: 已连接的 SSHClient 实例

    Returns:
        视觉工具列表: vision_analyze
    """
    return [VisionAnalyzeTool(ssh_client)]


__all__ = ["VisionAnalyzeTool", "vision_tools"]
