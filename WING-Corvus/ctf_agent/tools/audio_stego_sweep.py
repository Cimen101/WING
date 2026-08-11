"""Audio Stego Sweep: 音频隐写参数扫描工具.

针对 CTF 中音频隐写题 (如 CSAW well-tempered cipher)，自动扫描频率、阈值、
窗口大小、步长、密码等参数组合，从 WAV 文件中提取隐藏的 flag。

核心算法:
  1. 用 Hanning 窗口 + FFT 检测指定频率的峰值时刻
  2. 在峰值位置提取 LSB bit
  3. 读取 32 位长度头 → 按长度提取消息 bit
  4. 用密码 XOR 解密
  5. 检查是否以 flag_prefix 开头

实现: 纯 Python + numpy/scipy (零额外依赖), 本地运行。
"""

from __future__ import annotations

import json
from typing import Any

import numpy as np
from scipy.io import wavfile

from ctf_agent.tools.base import Tool

# Bach 音乐形式相关密码 (well-tempered cipher 常见密码)
_BACH_PASSWORDS = [
    "fugue",
    "prelude",
    "toccata",
    "partita",
    "invention",
    "sonata",
    "suite",
    "concerto",
    "cantata",
    "mass",
    "passacaglia",
    "chaconne",
    "fantasy",
    "chorale",
    "counterpoint",
    "well_tempered_cipher",
    "welltempered",
    "bach",
    "well-tempered",
    "wtc",
]

_MAX_OUTPUT = 6000


def _detect(
    audio_data: np.ndarray,
    sample_rate: int,
    target_freq: float,
    threshold: float,
    window_size: int,
    hop_size: int,
    min_distance: float,
) -> list[float]:
    """检测指定频率的峰值时间戳.

    Args:
        audio_data: 归一化后的音频数据 (float 数组)
        sample_rate: 采样率
        target_freq: 目标频率
        threshold: 检测阈值 (相对最大幅度的比例)
        window_size: FFT 窗口大小
        hop_size: 滑动步长
        min_distance: 两个峰值之间的最小时间间隔

    Returns:
        检测到的时间戳列表 (秒)
    """
    timestamps: list[float] = []
    for i in range(0, len(audio_data) - window_size, hop_size):
        window = audio_data[i : i + window_size] * np.hanning(window_size)
        fft = np.fft.rfft(window)
        freqs = np.fft.rfftfreq(window_size, 1 / sample_rate)
        magnitudes = np.abs(fft)
        target_idx = np.argmin(np.abs(freqs - target_freq))
        if magnitudes[target_idx] > threshold * np.max(magnitudes):
            ts = i / sample_rate
            if not timestamps or ts - timestamps[-1] > min_distance:
                timestamps.append(ts)
    return timestamps


def _extract_bits(
    audio_data: np.ndarray,
    sample_rate: int,
    timestamps: list[float],
) -> str:
    """在时间戳位置提取 LSB bit.

    Args:
        audio_data: 原始音频数据 (int 数组)
        sample_rate: 采样率
        timestamps: 时间戳列表

    Returns:
        bit 字符串 (如 "010101...")
    """
    bits: list[str] = []
    for ts in timestamps:
        idx = int(ts * sample_rate)
        if idx < len(audio_data):
            bits.append(str(int(audio_data[idx]) & 1))
    return "".join(bits)


def _decode_message(bit_string: str, password: str | None) -> str | None:
    """从 bit 字符串解码消息.

    Args:
        bit_string: bit 字符串
        password: 可选密码 (用于 XOR 解密)

    Returns:
        解码后的字符串, 失败返回 None
    """
    try:
        if len(bit_string) < 32:
            return None
        length_bits = bit_string[:32]
        msg_len = int(length_bits, 2)
        if msg_len < 1 or msg_len > 500:
            return None
        msg_bits = bit_string[32 : 32 + msg_len * 8]
        if len(msg_bits) < msg_len * 8:
            return None
        msg_bytes = bytearray()
        for i in range(0, len(msg_bits), 8):
            msg_bytes.append(int(msg_bits[i : i + 8], 2))
        msg = bytes(msg_bytes).decode("utf-8", errors="ignore")
        if password:
            msg = "".join(
                chr(ord(c) ^ ord(password[i % len(password)]))
                for i, c in enumerate(msg)
            )
        return msg
    except Exception:
        return None


class AudioStegoSweepTool(Tool):
    """audio_stego_sweep: 音频隐写参数扫描工具.

    自动扫描多种参数组合 (频率、阈值、窗口大小、步长、密码)，
    从 WAV 文件中提取隐藏的 flag。适用于 FFT 频谱隐写类题目。
    """

    name = "audio_stego_sweep"
    description = (
        "音频隐写参数扫描工具。自动扫描频率、阈值、窗口大小、步长、密码等参数组合，"
        "从 WAV 文件中提取隐藏的 flag。核心算法: Hanning 窗口 + FFT 检测指定频率峰值 → "
        "峰值位置 LSB 提取 → 32 位长度头 → 密码 XOR 解密 → 检查 flag 前缀。"
        "适用于音频隐写题 (如 CSAW well-tempered cipher)。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "wav_path": {
                "type": "string",
                "description": "WAV 文件路径 (本地或容器内)",
            },
            "frequencies": {
                "type": "array",
                "items": {"type": "number"},
                "description": "要检测的频率列表 (默认 [233.08, 466.16, 932.33])",
            },
            "thresholds": {
                "type": "array",
                "items": {"type": "number"},
                "description": "检测阈值列表 (默认 [0.3, 0.25, 0.2, 0.15, 0.1])",
            },
            "window_sizes": {
                "type": "array",
                "items": {"type": "integer"},
                "description": "FFT 窗口大小列表 (默认 [4096, 2048, 8192])",
            },
            "hop_sizes": {
                "type": "array",
                "items": {"type": "integer"},
                "description": "滑动步长列表 (默认 [512, 256, 1024])",
            },
            "passwords": {
                "type": "array",
                "items": {"type": "string"},
                "description": "尝试的密码列表 (默认从 Bach 音乐形式加载)",
            },
            "min_distance": {
                "type": "number",
                "description": "两个峰值之间的最小时间间隔 (秒, 默认 0.2)",
            },
            "flag_prefix": {
                "type": "string",
                "description": "查找的 flag 前缀 (默认 'csawctf{')",
            },
            "max_results": {
                "type": "integer",
                "description": "最大返回结果数 (默认 5)",
            },
        },
        "required": ["wav_path"],
    }

    def execute(
        self,
        wav_path: str,
        frequencies: list[float] | None = None,
        thresholds: list[float] | None = None,
        window_sizes: list[int] | None = None,
        hop_sizes: list[int] | None = None,
        passwords: list[str] | None = None,
        min_distance: float = 0.2,
        flag_prefix: str = "csawctf{",
        max_results: int = 5,
        **_: Any,
    ) -> str:
        if not wav_path:
            return "ERROR: wav_path 不能为空"

        # 设置默认值
        freqs = frequencies or [233.08, 466.16, 932.33]
        threshs = thresholds or [0.3, 0.25, 0.2, 0.15, 0.1]
        wins = window_sizes or [4096, 2048, 8192]
        hops = hop_sizes or [512, 256, 1024]
        pwds = passwords or _BACH_PASSWORDS
        # 确保空密码也在列表中（不传 password 时）
        if "" not in pwds:
            pwds = list(pwds) + [""]

        try:
            sample_rate, audio_data = wavfile.read(wav_path)
        except Exception as e:
            return f"ERROR: 读取 WAV 文件失败: {e}"

        # 多声道取平均
        if len(audio_data.shape) > 1:
            audio_data = audio_data.mean(axis=1)

        # 保存原始整数数据用于 LSB 提取
        raw_audio = audio_data.copy()
        # 归一化用于频谱分析
        audio_float = audio_data.astype(float) / max(
            np.max(np.abs(audio_data)), 1e-10
        )

        results: list[dict[str, Any]] = []
        total_combos = len(freqs) * len(threshs) * len(wins) * len(hops) * len(pwds)

        for freq in freqs:
            for thresh in threshs:
                for win in wins:
                    for hop in hops:
                        # 检测峰值
                        timestamps = _detect(
                            audio_float, sample_rate, freq, thresh, win, hop, min_distance
                        )
                        if len(timestamps) < 32:
                            continue

                        # 提取 bits
                        bit_string = _extract_bits(raw_audio, sample_rate, timestamps)
                        if len(bit_string) < 32:
                            continue

                        for pwd in pwds:
                            password = pwd if pwd else None
                            message = _decode_message(bit_string, password)
                            if message is None:
                                continue

                            # 检查是否匹配 flag 前缀
                            if flag_prefix and flag_prefix not in message:
                                continue

                            results.append({
                                "frequency": freq,
                                "threshold": thresh,
                                "window_size": win,
                                "hop_size": hop,
                                "password": password or "",
                                "message": message,
                                "message_length": len(message),
                            })

                            if len(results) >= max_results:
                                break
                        if len(results) >= max_results:
                            break
                    if len(results) >= max_results:
                        break
                if len(results) >= max_results:
                    break
            if len(results) >= max_results:
                break

        if not results:
            return (
                f"音频隐写扫描完成 (共扫描 {total_combos} 个参数组合)。\n"
                f"未找到以 '{flag_prefix}' 开头的 flag。\n"
                f"建议: 尝试不同的频率、阈值、密码或检查 WAV 文件是否正确。"
            )

        output_lines = [
            f"音频隐写扫描完成 (共扫描 {total_combos} 个参数组合)。",
            f"找到 {len(results)} 个匹配结果 (显示前 {min(len(results), max_results)} 个):\n",
        ]

        for i, r in enumerate(results, 1):
            output_lines.append(
                f"--- 结果 #{i} ---\n"
                f"  频率: {r['frequency']}\n"
                f"  阈值: {r['threshold']}\n"
                f"  窗口大小: {r['window_size']}\n"
                f"  步长: {r['hop_size']}\n"
                f"  密码: {r['password']!r}\n"
                f"  消息长度: {r['message_length']}\n"
                f"  消息: {r['message']}\n"
            )

        output_lines.append("=== JSON ===\n" + json.dumps(results, ensure_ascii=False, indent=2))
        return "\n".join(output_lines)


def audio_stego_sweep_tool() -> list[Tool]:
    """返回音频隐写参数扫描工具 (纯 Python, 无需 SSH)."""
    return [AudioStegoSweepTool()]


__all__ = ["AudioStegoSweepTool", "audio_stego_sweep_tool"]