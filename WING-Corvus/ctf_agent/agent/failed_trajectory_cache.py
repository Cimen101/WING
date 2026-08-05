"""Sprint 10: 失败轨迹缓存器 (Failed Trajectory Cache).

背景:
  v5 测试中, RAM_Drift 从 v4 6 步成功退化为 v5 24 步失败。
  根因: LLM 反复尝试多种 XOR key 索引模式,陷入循环。
  本模块提供"失败记忆"机制: 同一题第二次跑时,自动注入前次失败提示,
  引导 LLM 绕开错误路径。

设计:
  - 按 challenge_id 存储最近 N 次失败 trajectory (仅前 5 步 + last thought)
  - format_hint() 生成注入到 system prompt 的提示文本
  - JSONL 格式, append-only, 简单可靠
  - TTL: 7 天后自动过期 (Sprint 10 阶段 1.2 防止历史无限积累)
  - max_records_per_challenge: 单题最多 10 条 (防止误用刷爆)

Sprint 10 Stage 10 (M4): 演化器 (Reflector)
  - reflect(): 基于失败 trajectory 推断 failure_mode + 推荐未用过的工具
  - Reflection 数据结构: 失败模式分类 + 工具建议 + 改进提示
  - format_reflection_hint(): 注入 LLM system prompt 的简短提示
  - 目的: 跨题学习 (cross-challenge learning), 引导 LLM 自我反思
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

# Sprint 10 阶段 1.2: TTL 与上限,防止 cache 无限增长/污染后续测试
DEFAULT_TTL_SECONDS = 7 * 24 * 3600  # 7 天
DEFAULT_MAX_RECORDS = 10  # 单题最多 10 条


# Sprint 10 阶段 1.3: cross-challenge 知识共享
# 按 (type, difficulty) 共享"通用解题模式", 避免每题都重新发现
# 注: 这是通用模式, 不是具体失败 history
TYPE_DIFFICULTY_HINTS: dict[tuple[str, str], str] = {
    # forensics - 内存 dump 题目专用工具
    ("forensics", "medium"): (
        "[类型提示] forensics medium 题通常涉及:\n"
        "  - 内存 dump (.txt hex format): 立即使用 mem_xor_analyze 工具\n"
        "  - pcap 文件: 用 tshark/tcpdump 解析\n"
        "  - 浏览器历史 (sqlite): 查 Cookies/History/Visits 表\n"
        "  - 邮件: 查附件 + eml headers\n"
        "💡 不要反复 hex_dump 试错, 先识别文件类型再选专用工具。"
    ),
    ("forensics", "hard"): (
        "[类型提示] forensics hard 题通常涉及:\n"
        "  - 多层 XOR/AES 链: 优先用 mem_xor_analyze 一次尝试所有 key\n"
        "  - 自定义文件系统: binwalk + 解包\n"
        "  - VM 磁盘镜像: qemu-nbd/losetup + mount\n"
        "💡 多 XOR key 题目: mem_xor_analyze 会自动尝试 header_concat/header_per_page/"
        "full_concat/full_per_page 4 种模式, 节省手动试错时间。"
    ),
    # reverse - 结构化分析 (Sprint 14 P1: 限制 angr 过度使用)
    ("reverse", "easy"): (
        "[reverse easy] 简单魔数/字符串匹配, 3-6 步搞定:\n"
        "  1. strings (查 flag_like 模式, 1 步)\n"
        "  2. binary_analyze 1 次 (看 xor_hints, 1 步)\n"
        "  3. ssh_python 写解密脚本 (1-2 步)\n"
        "  4. ssh_exec 试 2-3 个常见 key (deadbeef/12345678/全0, 1-2 步)\n\n"
        "⛔ 绝对不要用 angr_symbolic_exec! easy 题不值得 5 分钟超时, "
        "直接 strings+binary_analyze+try keys 就能解.\n"
        "⛔ 不要用 file/hex_dump 反复看 (>= 2 次就停, 浪费步数)."
    ),
    ("reverse", "medium"): (
        "[reverse medium] 标准反编译+反汇编, 8-15 步搞定:\n"
        "  1. binary_analyze 1-2 次 (深度 standard/deep, 看 xor_hints + functions + strings)\n"
        "  2. ssh_python 写解密脚本 (XOR/ROR3/加减常量, 1-2 步)\n"
        "  3. ssh_exec 试常见 key (1-2 步)\n\n"
        "⛔ angr_symbolic_exec 仅在 binary_analyze 完全没有线索 + "
        "已知 plaintext/ciphertext 对时才用, 1 次为限.\n"
        "⛔ 不要反复 objdump -d, binary_analyze 已包含反汇编."
    ),
    ("reverse", "hard"): (
        "[reverse hard] 复杂加密/混淆, 15-30 步:\n"
        "  1. binary_analyze 1-2 次 (深度 deep, 看 xor_hints + cfg_complexity)\n"
        "  2. 看 main 函数反汇编, 找关键算法\n"
        "  3. ssh_python 实现算法 + 解密 (2-3 步)\n"
        "  4. angr_symbolic_exec 1 次, timeout=300s, 找 find/avoid 地址 (最后才用)\n\n"
        "⚠️ angr 5 分钟超时, 失败立刻停手, 用 ssh_python 手动解.\n"
        "💡 binary_analyze depth='deep' 可做更彻底的分析 (耗时 5-10s)."
    ),
    # crypto - 数学攻击
    ("crypto", "medium"): (
        "[类型提示] crypto medium 题通常涉及:\n"
        "  - ECDSA nonce reuse: k = (z1-z2)/(s1-s2) mod n\n"
        "  - RSA small e: c 直接开 e 次方根\n"
        "  - XOR 重复: 用已知明文 (如 flag 头) 求 key\n"
        "💡 用 ssh_python 写完整攻击脚本, 一次写完避免重试。"
    ),
    ("crypto", "hard"): (
        "[类型提示] crypto hard 题通常涉及:\n"
        "  - LLL 攻击 (lattice reduction): 需 sage, Kali 可装\n"
        "  - 离散对数: baby-step-giant-step 或 Pohlig-Hellman\n"
        "  - 椭圆曲线: order 检查, twist attack\n"
        "💡 复杂代数题用 sage (Sprint 11 待集成), 当前用 ssh_python + sympy。"
    ),
    # web - 网络协议
    ("web", "medium"): (
        "[类型提示] web medium 题通常涉及:\n"
        "  - SQL 注入: sqlmap 自动化\n"
        "  - XSS/SSTI: 手工 payload\n"
        "  - JWT/Cookie 篡改: base64decode + 重新签名\n"
        "💡 用 http_request 工具 + curl/wget 多次试错。"
    ),
    # osint - 信息收集 (Sprint 14 P1 强化: 严格 4 步上限, 禁止 strings/binwalk/steghide)
    ("osint", "medium"): (
        "[OSINT 流程] 严格按以下顺序, 总步数 ≤ 5 步 (含 final_answer):\n"
        "  1. exiftool (找 GPS/相机元数据) → 有 GPS 直接 final_answer (3 位小数, 例 43.793,75.538)\n"
        "  2. ocr (提取图片文字) → 如果 [NO_TEXT_DETECTED], 立刻跳过, 不要 web_search tesseract 内部日志\n"
        "  3. web_search (用真实图片描述/题目线索, 不是 OCR 输出) → 找地理位置或实体\n"
        "  4. osm_geocode (用 web_search 找到的地名) → 拿 GPS 坐标\n"
        "  5. final_answer (athena{lat,lon}, 3 位小数)\n\n"
        "⛔ 绝对禁止以下工具 (medium OSINT 不需要):\n"
        "  - strings / file / hex_dump / hexdump (二进制探查)\n"
        "  - binwalk (嵌入文件, medium 题极少用)\n"
        "  - steghide / stegsolve (隐写, medium 题极少用)\n"
        "  - identify -verbose (ImageMagick 元数据, exiftool 已包含)\n\n"
        "⚠️ ocr 工具如果返回 [NO_TEXT_DETECTED], 这是真的没文字, 不要重试, 直接跳到 step 3.\n"
        "⚠️ web_search/osm_geocode 失败 1 次, 立刻用 LLM 知识 (不要重试 2+ 次).\n"
        "💡 flag 格式: athena{lat,lon} (3 位小数), 例: athena{43.793,75.538}"
    ),
    # Sprint 13 P0: osint hard 强化 — 网络失败回退到 LLM 知识, 防止步数耗尽
    ("osint", "hard"): (
        "[OSINT 进阶] 多图/多线索综合:\n"
        "  1. exiftool (必做第1步) → 提取 GPS/时间戳/软件/设备\n"
        "  2. ocr (必做第2步) → 提取图片文字, [NO_TEXT_DETECTED] 立即跳过\n"
        "  3. web_search (Yandex 沙箱常被 captcha, 失败立即用 LLM 知识)\n"
        "  4. osm_geocode (Photon 沙箱常 timeout, 失败立即用 LLM 知识)\n"
        "  5. strings/binwalk (仅在 exiftool+ocr 都没线索时才做)\n\n"
        "⚠️ 网络工具失败 1 次立即停手:\n"
        "  - osm_geocode 报 'Connection timed out' 或 'Network is unreachable' → 立刻用 LLM 自身地理/航空/创作者知识\n"
        "  - web_search 报 'captcha' → 立刻用 LLM 知识\n"
        "  - 不要重试 3+ 次, 浪费时间! 直接 final_answer 用知识\n\n"
        "💡 LLM 知识回退样本 (常见题):\n"
        "  - GPS 在 Bavaria 50°N 11°E → Bayreuth/Hof 区, 附近机场 MUC/NUE, 商用航线\n"
        "  - GPS 在 Kazakhstan 43°N 75°E → Tamgaly 岩画 (UNESCO)\n"
        "  - 软件 'gnome-screenshot' + Linux → 创作者可能在 Reddit/Twitter 早期梗图\n"
        "  - 'Global Blue' + 'Policia' → 西班牙警方梗图, 创作者多为 Instagram/Twitter 用户\n\n"
        "💡 hard OSINT 常用: steghide (仅 jpg) + exiftool + 多语言 OCR + 1-2 次 osm_geocode 失败就停"
    ),
    ("osint", "easy"): (
        "[OSINT 入门] 通常 exiftool 直接出 GPS, 1 步搞定.\n"
        "  - exiftool (找 GPS) → 有 GPS 直接 final_answer\n"
        "  - 或 strings + web_search 找关键字"
    ),
}


# 常见内存标记 (4-byte magic) - 在 hint 中提示 LLM 剥离
_MEMORY_MARKERS = [
    b"\xde\xad\xbe\xef",  # DEADBEEF (填充)
    b"\xfa\xce\xb0\x0c",  # FACEB00C (Linux kernel debug)
    b"\xca\xfe\xba\xbe",  # CAFEBABE (Java class marker)
    b"\xfe\xed\xfa\xce",  # FEEDFACE
    b"\x00\x00\x00\x00",  # 全零
    b"\xff\xff\xff\xff",  # 全 1
]


# ==================== Sprint 10 Stage 10: 演化器 (Reflector) ====================

# 失败模式分类常量
FAILURE_MODE_LOOP_TOOL = "LOOP_TOOL_USAGE"  # 反复用同一工具
FAILURE_MODE_REPEAT_ACTION = "REPEATED_ACTION"  # 重复相同 action_input
FAILURE_MODE_WRONG_APPROACH = "WRONG_APPROACH"  # 解题方向错误
FAILURE_MODE_NULL_OBSERVATION = "NULL_OBSERVATION"  # 反复空 observation
FAILURE_MODE_FORMAT_ERROR = "FORMAT_ERROR"  # 反复格式错误
FAILURE_MODE_MAX_STEPS = "MAX_STEPS"  # 步数超限
FAILURE_MODE_TOKEN_WASTE = "TOKEN_WASTE"  # 输出大量无信息内容
FAILURE_MODE_UNKNOWN = "UNKNOWN"  # 无法分类

# 工具能力分组 (按题目类型推荐)
TOOL_CATEGORY_MAP: dict[str, list[str]] = {
    "forensics": [
        "mem_xor_analyze",  # 内存 dump XOR 攻击
        "exiftool",          # EXIF/GPS
        "steghide",          # 隐写术
        "binwalk",           # 嵌入文件
        "tshark",            # PCAP 流量
        "file_analyze",      # 文件类型识别
        "hex_dump",          # hex 预览
        "strings",           # 字符串提取
    ],
    "reverse": [
        "binary_analyze",    # 自动化反编译
        "apk_jadx",          # APK → Java
        "apktool",           # APK 拆解
        "disassemble",       # objdump
        "strings",           # 字符串
        "ssh_python",        # 复杂分析脚本
    ],
    "crypto": [
        "common_d_attack",   # RSA LLL 攻击
        "sympy_compute",     # 数学运算
        "ssh_python",        # 完整攻击脚本
        "factor",            # 整数分解
    ],
    "osint": [
        "exiftool",          # EXIF/GPS
        "ocr",               # 图片文字提取
        "web_search",        # Yandex 搜索
        "osm_geocode",       # GPS 地理编码
        "steghide",          # 隐写
    ],
    "web": [
        "http_request",      # HTTP 请求
        "ssh_python",        # 复杂 payload
        "sqlmap",            # SQL 注入
    ],
    "misc": [
        "ssh_python",        # 通用
        "file_read",         # 读文件
        "hex_dump",          # hex 预览
        "strings",           # 字符串
    ],
}

# 工具名常见别名归一化 (用于去重和匹配)
_TOOL_ALIASES: dict[str, str] = {
    "python": "ssh_python",
    "py": "ssh_python",
    "read": "file_read",
    "cat": "file_read",
    "ls": "shell",
    "sh": "shell",
    "bash": "shell",
    "search": "web_search",
    "yandex": "web_search",
    "google": "web_search",
    "geocode": "osm_geocode",
    "photon": "osm_geocode",
    "tesseract": "ocr",
    "exif": "exiftool",
    "stego": "steghide",
    "jadx": "apk_jadx",
    "analyze": "binary_analyze",
    "analyse": "binary_analyze",
    "dis": "disassemble",
    "disasm": "disassemble",
}


def _normalize_tool_name(name: str) -> str:
    """归一化工具名 (用于反射分析去重)."""
    if not name:
        return ""
    n = name.strip().lower()
    return _TOOL_ALIASES.get(n, n)


@dataclass
class Reflection:
    """Sprint 10 Stage 10: 失败轨迹反思结果.

    由 FailedTrajectoryCache.reflect() 生成, 用于:
    1. 注入到 LLM system prompt (避免再次犯同样错误)
    2. 持久化到 reflections/ 目录 (跨题学习, 后续可基于 type/difficulty 共享)
    """

    ts: float
    challenge_id: str
    failure_mode: str  # FAILURE_MODE_* 之一
    confidence: float  # 0.0-1.0, 失败模式识别置信度
    used_tools: list[str]  # 用过的工具 (归一化后)
    suggested_tools: list[str]  # 建议下次尝试的工具 (排除已用)
    improvement_hint: str  # 1-3 行改进建议
    related_type: str = ""  # 题目类型 (osint/crypto/...)
    related_difficulty: str = ""  # 难度 (easy/medium/hard)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Reflection":
        # 兼容旧版本可能没有的字段
        return cls(
            ts=d.get("ts", 0.0),
            challenge_id=d.get("challenge_id", ""),
            failure_mode=d.get("failure_mode", FAILURE_MODE_UNKNOWN),
            confidence=d.get("confidence", 0.0),
            used_tools=d.get("used_tools", []),
            suggested_tools=d.get("suggested_tools", []),
            improvement_hint=d.get("improvement_hint", ""),
            related_type=d.get("related_type", ""),
            related_difficulty=d.get("related_difficulty", ""),
        )


@dataclass
class FailedRun:
    """单次失败记录 (精简版,只保留前 5 步和最后 thought)."""

    ts: float
    challenge_id: str
    steps: int
    final_answer: str
    fail_reason: str
    first_5_steps: list[dict]
    last_step_thought: str
    used_tools: list[str]  # 用过的工具名 (检测循环)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "FailedRun":
        return cls(**d)


class FailedTrajectoryCache:
    """按 challenge_id 缓存最近 N 次失败 trajectory.

    用法:
        cache = FailedTrajectoryCache()
        # 跑完一道题后:
        cache.store(challenge_id="CTF-RAM_Drift", steps=result.steps,
                    final_answer=result.final_answer,
                    fail_reason=result.fail_reason,
                    trajectory=result.steps, success=False)
        # 下次跑同题前:
        hint = cache.format_hint("CTF-RAM_Drift")
        # 将 hint 拼接到 system prompt
    """

    def __init__(
        self,
        cache_dir: str = "data/failed_trajectories",
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_records_per_challenge: int = DEFAULT_MAX_RECORDS,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_seconds
        self.max_records = max_records_per_challenge

    def _path_for(self, challenge_id: str) -> Path:
        return self.cache_dir / f"{challenge_id}.jsonl"

    def _is_expired(self, ts: float) -> bool:
        """Sprint 10 阶段 1.2: 检查记录是否已过期."""
        if self.ttl_seconds <= 0:
            return False  # TTL=0 表示不过期
        return (time.time() - ts) > self.ttl_seconds

    def _read_valid_lines(self, cache_file: Path) -> list[dict]:
        """读取未过期的记录 (Sprint 10 阶段 1.2)."""
        if not cache_file.exists():
            return []
        valid: list[dict] = []
        for line in cache_file.read_text(encoding="utf-8").split("\n"):
            if not line.strip():
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if self._is_expired(d.get("ts", 0)):
                continue
            valid.append(d)
        return valid

    def _write_all(self, cache_file: Path, records: list[dict]) -> None:
        """覆盖写入（用于清理/裁剪后）."""
        with cache_file.open("w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    def store(
        self,
        challenge_id: str,
        steps: list[Any],
        final_answer: str,
        fail_reason: str,
        success: bool,
    ) -> None:
        """仅当 success=False 时存储. steps 是 ReActStep 列表."""
        if success:
            return

        # ReActStep 列表 -> 简化字典
        first_5 = []
        used_tools: list[str] = []
        for s in steps[:5]:
            step_dict = {
                "step_no": s.step_no,
                "thought": s.thought[:200],  # 截断
                "action": s.action,
                "action_input_preview": (s.action_input or "")[:200],
                "observation_preview": (s.observation or "")[:200],
            }
            first_5.append(step_dict)
            if s.action:
                used_tools.append(s.action)

        last_thought = steps[-1].thought[:300] if steps and steps[-1].thought else ""

        record = FailedRun(
            ts=time.time(),
            challenge_id=challenge_id,
            steps=len(steps),
            final_answer=final_answer[:200],
            fail_reason=fail_reason[:200],
            first_5_steps=first_5,
            last_step_thought=last_thought,
            used_tools=list(set(used_tools)),
        )

        cache_file = self._path_for(challenge_id)
        # 写前确保目录存在 (spawn 子进程/目录被清时可能缺失 → 幂等重建, 防 FileNotFoundError)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Sprint 10 阶段 1.2: 读取未过期记录 + 追加新记录 + 限制条数
        existing = self._read_valid_lines(cache_file)
        existing.append(record.to_dict())
        # 超出 max_records 时, 保留最新的 max_records 条
        if self.max_records > 0 and len(existing) > self.max_records:
            existing = existing[-self.max_records:]
        self._write_all(cache_file, existing)

    def fetch_recent(self, challenge_id: str, n: int = 1) -> list[FailedRun]:
        """读取最近 n 次失败 (按时间倒序, 跳过过期记录)."""
        cache_file = self._path_for(challenge_id)
        if not cache_file.exists():
            return []
        # Sprint 10 阶段 1.2: 跳过过期记录
        valid_records = self._read_valid_lines(cache_file)
        # 末 n 条 (最新), 反转成时间倒序
        recent = valid_records[-n:] if n > 0 else valid_records
        result: list[FailedRun] = []
        for d in recent:
            try:
                result.append(FailedRun.from_dict(d))
            except (KeyError, TypeError):
                continue
        return list(reversed(result))

    def fetch_all(self, challenge_id: str) -> list[FailedRun]:
        """读取所有失败历史 (按时间倒序, 跳过过期记录)."""
        return self.fetch_recent(challenge_id, n=10**6)

    def count(self, challenge_id: str) -> int:
        """返回未过期失败记录数."""
        cache_file = self._path_for(challenge_id)
        if not cache_file.exists():
            return 0
        return len(self._read_valid_lines(cache_file))

    def cleanup_expired(self) -> int:
        """Sprint 10 阶段 1.2: 清理所有过期的 cache 文件.

        Returns:
            清理的 challenge_id 数量
        """
        cleaned = 0
        for f in self.cache_dir.glob("*.jsonl"):
            valid = self._read_valid_lines(f)
            if len(valid) == 0 and f.exists():
                # 全过期, 直接删除文件
                f.unlink()
                cleaned += 1
            else:
                # 部分过期, 写回未过期部分
                self._write_all(f, valid)
        return cleaned

    def format_hint(self, challenge_id: str) -> str:
        """生成注入到 LLM prompt 的提示文本.

        Returns:
            空字符串: 无历史失败 (无 hint)
            非空: 失败历史摘要
        """
        recent = self.fetch_recent(challenge_id, n=1)
        if not recent:
            return ""

        last = recent[0]
        tools_str = ", ".join(last.used_tools) if last.used_tools else "无"

        hint_lines = [
            f"\n[失败记忆] ⚠️ 此题 {self.count(challenge_id)} 次失败历史 (最近 1 次):",
            f"  - 步数: {last.steps}",
            f"  - 失败原因: {last.fail_reason}",
            f"  - 错误 final_answer: {last.final_answer!r}",
            f"  - 用过的工具: {tools_str}",
        ]

        # 提取前 3 步的关键 action (避免 hint 过长)
        if last.first_5_steps:
            hint_lines.append("  - 前 3 步动作:")
            for s in last.first_5_steps[:3]:
                act = s.get("action", "")
                inp = s.get("action_input_preview", "")
                hint_lines.append(f"    Step {s['step_no']}: {act}({inp[:80]}...)")

        hint_lines.append(
            "  💡 建议: 避免重复相同思路,尝试不同工具/不同 key 索引方式/专用分析工具。"
        )
        return "\n".join(hint_lines)

    def format_type_hint(self, ch_type: str, ch_difficulty: str) -> str:
        """Sprint 10 阶段 1.3: 获取 (type, difficulty) 级别的通用解题提示.

        这是 cross-challenge 知识共享: 同类型同难度的题, 共享通用模式,
        避免每题都重新发现 (例如所有 forensics medium 都需要 mem_xor_analyzer).

        与 format_hint() 的区别:
        - format_hint: 该 challenge_id 历史的失败 trajectory (具体)
        - format_type_hint: 该 (type, difficulty) 通用解题模式 (抽象)

        Args:
            ch_type: 题目类型 (forensics/reverse/crypto/...)
            ch_difficulty: 难度 (easy/medium/hard)

        Returns:
            提示文本; 无匹配时返回空字符串
        """
        key = (ch_type, ch_difficulty)
        return TYPE_DIFFICULTY_HINTS.get(key, "")

    # ==================== Sprint 10 Stage 10: 演化器 (Reflector) ====================

    def _reflections_path(self) -> Path:
        """返回 reflections 存储目录 (与 cache_dir 同级, 命名为 reflections)."""
        p = self.cache_dir / "_reflections"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def _reflection_file(self, challenge_id: str) -> Path:
        return self._reflections_path() / f"{challenge_id}.jsonl"

    def _classify_failure_mode(
        self, last: FailedRun, fail_reason: str
    ) -> tuple[str, float]:
        """推断失败模式分类.

        Returns:
            (failure_mode, confidence) 元组

        优先级 (从具体到通用):
        1. 格式错误 (reason 显式说明)
        2. 最大步数 (reason 显式说明)
        3. 重复动作 (前 5 步中同 action+input 出现 3+ 次)
        4. 解题方向错误 (有 final_answer + 步数 <= 20)
        5. Token 浪费 (步数高 + 工具少 + 无 final_answer)
        6. 循环工具 (单工具 + 步数高)
        7. 空 observation
        8. UNKNOWN
        """
        reason_lower = (fail_reason or "").lower()
        steps = last.steps or 0
        first_5 = last.first_5_steps or []
        used = [t for t in (last.used_tools or []) if t]
        has_final = bool(last.final_answer and last.final_answer.strip())

        # 1) 格式错误
        if "格式" in reason_lower or "format" in reason_lower:
            return FAILURE_MODE_FORMAT_ERROR, 0.95

        # 2) 最大步数
        if "最大步数" in reason_lower or "max_steps" in reason_lower or "step" in reason_lower:
            return FAILURE_MODE_MAX_STEPS, 0.95

        # 3) 重复动作: 多次相同 action_input
        if first_5:
            inputs = [
                (s.get("action") or "", (s.get("action_input_preview") or "")[:80])
                for s in first_5
            ]
            seen: dict[tuple, int] = {}
            for k in inputs:
                seen[k] = seen.get(k, 0) + 1
            if any(c >= 3 for c in seen.values()):
                return FAILURE_MODE_REPEAT_ACTION, 0.85

        # 4) 解题方向错误: 有 final_answer 但步数不太离谱 (说明 LLM 给了错答案)
        if has_final and steps <= 20:
            return FAILURE_MODE_WRONG_APPROACH, 0.7

        # 5) Token 浪费: 步数高 + 工具少 + 无 final_answer
        if steps >= 20 and len(used) <= 2 and not has_final:
            return FAILURE_MODE_TOKEN_WASTE, 0.7

        # 6) 循环工具使用: 单工具 + 步数 >= 5
        if used and steps > 0:
            uniq = len(set(_normalize_tool_name(u) for u in used))
            if uniq == 1 and steps >= 5:
                return FAILURE_MODE_LOOP_TOOL, 0.8

        # 7) 空 observation
        if "空" in reason_lower or "null" in reason_lower or "empty" in reason_lower:
            return FAILURE_MODE_NULL_OBSERVATION, 0.8

        return FAILURE_MODE_UNKNOWN, 0.3

    def _suggest_tools(
        self,
        ch_type: str,
        used_tools: list[str],
        failure_mode: str,
        max_n: int = 3,
    ) -> list[str]:
        """根据类型 + 已用工具 + 失败模式, 推荐未用过的工具.

        Args:
            ch_type: 题目类型
            used_tools: 失败轨迹中用过的工具 (归一化后)
            failure_mode: 推断出的失败模式
            max_n: 最多推荐几个工具

        Returns:
            推荐工具列表 (排除已用 + 优先按 failure_mode 排序)
        """
        candidates = list(TOOL_CATEGORY_MAP.get(ch_type, TOOL_CATEGORY_MAP["misc"]))
        used_norm = {_normalize_tool_name(t) for t in used_tools if t}
        # 排除已用
        unused = [t for t in candidates if t not in used_norm]
        if not unused:
            return []

        # 失败模式特定优先级
        priority: list[str] = []
        if failure_mode == FAILURE_MODE_LOOP_TOOL:
            # 循环: 优先推荐 L2 专用工具 (避免再用通用工具)
            priority = [t for t in unused if t not in {"file_read", "shell", "hex_dump", "strings"}]
        elif failure_mode == FAILURE_MODE_WRONG_APPROACH:
            # 方向错误: 优先推荐可"自动化"工具
            priority = [t for t in unused if "analyze" in t or "attack" in t or "compute" in t]
        elif failure_mode == FAILURE_MODE_TOKEN_WASTE:
            # token 浪费: 优先推荐一步到位工具
            priority = [t for t in unused if t in {"binary_analyze", "common_d_attack", "mem_xor_analyze", "apk_jadx", "apktool"}]
        else:
            priority = unused

        if not priority:
            priority = unused
        return priority[:max_n]

    def _build_improvement_hint(
        self,
        failure_mode: str,
        used_tools: list[str],
        suggested_tools: list[str],
    ) -> str:
        """生成 1-3 行改进建议文本."""
        used_str = ", ".join(used_tools[:5]) if used_tools else "无"
        sugg_str = ", ".join(suggested_tools) if suggested_tools else "无"

        templates = {
            FAILURE_MODE_LOOP_TOOL: (
                f"检测到循环使用工具 ({used_str})。请切换到专用工具: {sugg_str}。"
            ),
            FAILURE_MODE_REPEAT_ACTION: (
                f"检测到重复相同 action_input。请改变思路, 尝试: {sugg_str}。"
            ),
            FAILURE_MODE_WRONG_APPROACH: (
                f"上次最终答案错误。请换思路, 优先尝试: {sugg_str}。"
            ),
            FAILURE_MODE_NULL_OBSERVATION: (
                f"Observation 多次为空。请检查工具参数或换用: {sugg_str}。"
            ),
            FAILURE_MODE_FORMAT_ERROR: (
                "检测到多次格式错误。请严格按 Thought/Action/Action Input 三段式输出。"
            ),
            FAILURE_MODE_MAX_STEPS: (
                f"上次超过步数上限。建议提高单步效率, 优先用: {sugg_str}。"
            ),
            FAILURE_MODE_TOKEN_WASTE: (
                f"上次消耗过多 token 但未取得进展。请用更直接的: {sugg_str}。"
            ),
            FAILURE_MODE_UNKNOWN: (
                f"上次失败。建议换用未尝试的工具: {sugg_str}。"
            ),
        }
        return templates.get(failure_mode, templates[FAILURE_MODE_UNKNOWN])

    def reflect(
        self,
        challenge_id: str,
        ch_type: str = "",
        ch_difficulty: str = "",
    ) -> Optional[Reflection]:
        """Sprint 10 Stage 10: 基于最近失败 trajectory 生成反思.

        Args:
            challenge_id: 题目 ID
            ch_type: 题目类型 (forensics/osint/...) 可选
            ch_difficulty: 难度 (easy/medium/hard) 可选

        Returns:
            Reflection 对象; 无失败历史时返回 None
        """
        recent = self.fetch_recent(challenge_id, n=1)
        if not recent:
            return None
        last = recent[0]
        fail_reason = last.fail_reason or ""

        # 1) 推断失败模式
        mode, conf = self._classify_failure_mode(last, fail_reason)

        # 2) 归一化 used_tools
        used_norm = sorted({
            _normalize_tool_name(t)
            for t in (last.used_tools or [])
            if t
        })

        # 3) 推荐工具 (按类型 + 失败模式)
        ctype = ch_type or "misc"
        suggested = self._suggest_tools(ctype, used_norm, mode, max_n=3)

        # 4) 生成改进提示
        hint = self._build_improvement_hint(mode, used_norm, suggested)

        ref = Reflection(
            ts=time.time(),
            challenge_id=challenge_id,
            failure_mode=mode,
            confidence=conf,
            used_tools=used_norm,
            suggested_tools=suggested,
            improvement_hint=hint,
            related_type=ch_type,
            related_difficulty=ch_difficulty,
        )

        # 5) 持久化到 reflections/
        try:
            rf = self._reflection_file(challenge_id)
            with rf.open("a", encoding="utf-8") as f:
                f.write(json.dumps(ref.to_dict(), ensure_ascii=False) + "\n")
        except Exception:  # noqa: BLE001
            pass  # 持久化失败不影响主流程

        return ref

    def get_latest_reflection(self, challenge_id: str) -> Optional[Reflection]:
        """读取最近一次反思 (按时间倒序)."""
        rf = self._reflection_file(challenge_id)
        if not rf.exists():
            return None
        last_line: Optional[str] = None
        with rf.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line
        if not last_line:
            return None
        try:
            return Reflection.from_dict(json.loads(last_line))
        except (json.JSONDecodeError, KeyError, TypeError):
            return None

    def format_reflection_hint(
        self,
        challenge_id: str,
        ch_type: str = "",
        ch_difficulty: str = "",
    ) -> str:
        """Sprint 10 Stage 10: 生成注入到 LLM prompt 的反思提示.

        与 format_hint 的区别:
        - format_hint: 失败 history 摘要 (事实)
        - format_reflection_hint: 失败模式分析 + 工具建议 (反思)
        """
        ref = self.get_latest_reflection(challenge_id)
        if ref is None:
            # 第一次失败: 触发 reflect 生成
            ref = self.reflect(challenge_id, ch_type, ch_difficulty)
        if ref is None:
            return ""

        # 重新读盘避免时效问题
        ref = self.get_latest_reflection(challenge_id) or ref

        lines = [
            f"\n[演化反思] 上次失败模式: {ref.failure_mode} (置信度 {ref.confidence:.2f})",
        ]
        if ref.used_tools:
            lines.append(f"  - 已用工具: {', '.join(ref.used_tools)}")
        if ref.suggested_tools:
            lines.append(f"  - 建议改用: {', '.join(ref.suggested_tools)}")
        lines.append(f"  - 改进提示: {ref.improvement_hint}")
        return "\n".join(lines)

    def clear(self, challenge_id: str) -> None:
        """清除指定 challenge 的失败历史 (成功解题后调用)."""
        cache_file = self._path_for(challenge_id)
        if cache_file.exists():
            cache_file.unlink()
        # Sprint 10 Stage 10: 同步清理 reflection
        rf = self._reflection_file(challenge_id)
        if rf.exists():
            rf.unlink()

    def clear_all(self) -> None:
        """清除所有失败历史 (谨慎使用)."""
        for f in self.cache_dir.glob("*.jsonl"):
            f.unlink()
        # Sprint 10 Stage 10: 同步清理 reflections
        rp = self._reflections_path()
        if rp.exists():
            for f in rp.glob("*.jsonl"):
                f.unlink()


# ============ 便捷工厂函数 ============

_default_cache: Optional[FailedTrajectoryCache] = None


def get_default_cache() -> FailedTrajectoryCache:
    """获取默认全局缓存实例 (单例)."""
    global _default_cache
    if _default_cache is None:
        _default_cache = FailedTrajectoryCache()
    return _default_cache
