"""Skill 学习器（持续学习闭环的"生成"环节）.

从一次 ReAct 解题结果中，提炼出可复用的 Skill 并写入 SkillLibrary。
两种生成方式：
- 模板生成（默认，不调 LLM）：抽取工具调用链、关键 Observation 特征、成功路径，
  组织成结构化 skill 正文。
- LLM 生成（可选）：让 LLM 归纳更凝练的"套路 + 工具用法 + 坑"。

策略：
- 成功任务 → 生成"正向套路 skill"（这类题这样解）。
- 失败任务 → 生成"避坑 skill"（这类题不要这样/环境有此限制），但仅在有明确
  失败信号时生成，避免噪声。
- 交给 SkillLibrary.add_or_update 做合并去重，天然避免臃肿。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

from ctf_agent.agent import ReActResult
from ctf_agent.llm import LLMClient, Message
from ctf_agent.memory.skill_library import Skill, SkillLibrary


# ── Sprint 28: Skill 脱敏与泛化 ──────────────────────────────

# 匹配 /tmp/nss_arena/{数字或名称}/ 前缀
_RE_TMP_PATH = re.compile(r'/tmp/nss_arena/[a-zA-Z0-9_]+(/[^\s]*)?')
# 匹配 0x 格式十六进制地址 (至少 4 位)
_RE_HEX_ADDR = re.compile(r'0x[0-9a-fA-F]{4,}')
# 匹配 0000000000001252 格式地址 (8-16 位连续十六进制, 后跟 <func>)
_RE_OBJDUMP_ADDR = re.compile(r'\b[0-9a-f]{8,16}\b\s*<')
# 匹配 flag 内容
_RE_FLAG = re.compile(r'(NSSCTF|flag|moectf|ctf)\{[^}]*\}', re.IGNORECASE)
# 匹配 FLAG_REDACTED 残留
_RE_REDACTED = re.compile(r'FLAG_REDACTED\.+', re.IGNORECASE)


def _sanitize_text(text: str) -> str:
    """Sprint 28: 脱敏 — 将绝对路径、具体地址、flag 内容替换为通用占位符.

    用户要求: skill 是"解题智慧"不是"执行日志".
    - /tmp/nss_arena/1234/file.zip → {work_dir}/file.zip
    - 0x14001f008 → {address}
    - 0000000000001252 <func> → {func_addr} <func>
    - NSSCTF{xxx} → {flag}
    """
    text = _RE_TMP_PATH.sub('{work_dir}\\1', text)
    text = _RE_HEX_ADDR.sub('{address}', text)
    text = _RE_OBJDUMP_ADDR.sub('{func_addr} <', text)
    text = _RE_FLAG.sub('{flag}', text)
    text = _RE_REDACTED.sub('{flag}', text)
    return text


def _match_quick_solve(category: str, tools: list[str], task: str) -> tuple[str, Any]:
    """从 quick_solve registry 匹配最相关的模板脚本.

    让 skill 与"快速解题脚本库"联动：skill.script_ref 指向这里的脚本，
    prompt 注入 skill 时会一并提示"可用脚本"，实现秒解模板题。

    Returns:
        (脚本名, registry 实例)；匹配失败返回 ("", None)。返回 registry 便于
        调用方回填使用统计（成功经验实时更新脚本排序）。
    """
    try:
        root = Path(__file__).resolve().parent.parent
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from scripts.quick_solve.registry import QuickSolveRegistry
    except Exception:  # noqa: BLE001 - 无 registry 不影响 skill 主流程
        return "", None
    try:
        reg = QuickSolveRegistry()
        query = f"{' '.join(tools)} {task}"
        hits = reg.find(category=category, query=query)
        if not hits:  # 同方向兜底（不做关键词过滤）
            hits = reg.find(category=category)
        return (hits[0].name if hits else ""), reg
    except Exception:  # noqa: BLE001
        return "", None


def _tool_chain(result: ReActResult) -> list[str]:
    seen: list[str] = []
    for s in result.steps:
        if s.action and s.action not in seen:
            seen.append(s.action)
    return seen


def _key_observations(result: ReActResult, limit: int = 4) -> list[str]:
    """抽取有信息量的 Observation 片段（成功步骤优先, Sprint 28: 脱敏后输出）。"""
    obs: list[str] = []
    for s in result.steps:
        if s.observation and not s.is_error:
            # Sprint 28: 脱敏 — 移除绝对路径/地址/flag, 只保留方法论
            snippet = _sanitize_text(s.observation.strip().replace("\n", " "))
            if len(snippet) > 160:
                snippet = snippet[:160] + "..."
            if s.action:
                obs.append(f"{s.action} -> {snippet}")
        if len(obs) >= limit:
            break
    return obs


_LLM_SKILL_PROMPT = """你是 CTF 解题教练。请把下面这次{status}的解题过程，提炼成一条"可复用技能(skill)"，
供以后遇到同类题直接照做。只输出技能正文，不要客套。

⚠️ 严格规则（违反则 skill 无效）:
1. 禁止拷贝绝对路径（如 /tmp/nss_arena/1234/）— 一律用 {{work_dir}} 代替
2. 禁止拷贝具体内存地址（如 0x1252）— 一律用 {{address}} 代替
3. 禁止记录 flag 明文
4. 必须用"条件→动作"格式（If-Then），不要流水账式复制终端输出
5. 只记录方法论和错误码解决方案，不记录具体步骤号或临时文件名

题目类型: {ctype}  难度: {difficulty}
工具链: {tools}
关键过程（已脱敏）:
{steps}

请按如下结构输出（简洁、可操作）:
识别: <怎么判断这是这类题 — 触发特征如 checksec 输出、文件类型、关键词>
步骤:
  1) <条件> → <动作: 用哪个工具、关键参数>
  2) <条件> → <动作>
坑: <易错点/环境限制/注意事项 — 如 "Bad file descriptor → 用 1>&2 重定向 stderr 到 stdout">
"""


# Sprint 28: 套路特征提取 — 用于跨题匹配 (基于套路而非题目名称)
# 这些是 CTF 题目中常见的、能标识题目类型的技术特征词
_PATTERN_KEYWORDS = {
    # Crypto
    "rsa": "RSA", "n =": "RSA", "e =": "RSA", "c =": "RSA ciphertext",
    "aes": "AES", "cbc": "CBC", "ecb": "ECB", "iv:": "IV:ciphertext",
    "xor": "XOR", "base64": "base64", "des": "DES", "feistel": "Feistel",
    "jwt": "JWT", "hs256": "HS256", "rs256": "RS256",
    # Web
    "ssti": "SSTI", "jinja2": "Jinja2", "template": "template injection",
    "pickle": "pickle", "deserialize": "deserialization",
    "ssrf": "SSRF", "127.0.0.1": "SSRF", "fetch": "fetch/proxy",
    "cookie": "cookie", "session": "session",
    "sql": "SQL", "sqli": "SQLi", "inject": "injection",
    "lfi": "LFI", "php://": "php://filter",
    # Pwn/Reverse
    "elf": "ELF", "gets": "gets overflow", "scanf": "scanf overflow",
    "printf": "printf", "format string": "format string",
    "shellcode": "shellcode", "ret2win": "ret2win", "win": "win function",
    "uaf": "UAF", "heap": "heap", "tcache": "tcache",
    "nx": "NX", "canary": "canary", "pie": "PIE",
    # Misc
    "pcap": "pcap", "tshark": "tshark", "wireshark": "wireshark",
    "steghide": "steghide", "zsteg": "zsteg", "lsb": "LSB",
    "exiftool": "exiftool", "binwalk": "binwalk",
    "zip": "zip", "rar": "rar", "7z": "7z",
    "png": "PNG", "jpg": "JPG", "jpeg": "JPG",
    # 工具特征
    "checksec": "checksec", "objdump": "objdump", "gdb": "gdb",
    "angr": "angr", "pwntools": "pwntools",
}


def _extract_pattern_features(task: str, result: ReActResult) -> list[str]:
    """Sprint 28: 从题目描述 + 解题过程中提取套路特征.

    套路特征是能标识"这类题"的技术关键词, 用于跨题匹配.
    例如: 一道 RSA 题的套路特征 = ["RSA", "n =", "e =", "c ="]
    下次遇到另一道 RSA 题 (即使题目名不同), 这些特征会在 observation 中出现,
    从而匹配到这条 skill.
    """
    features: set[str] = set()
    # 合并 task + 所有 observation 文本
    all_text = (task or "").lower()
    for s in result.steps:
        if s.observation:
            all_text += "\n" + s.observation.lower()
        if s.action:
            all_text += "\n" + s.action.lower()

    for kw, feat in _PATTERN_KEYWORDS.items():
        if kw in all_text:
            features.add(feat)

    # 工具链本身也是套路特征
    for tool in _tool_chain(result):
        features.add(f"tool:{tool}")

    # 题目类型
    if result.steps:
        features.add(f"category_hint")

    return sorted(features)[:15]  # 限制数量, 避免过长


def _template_body(result: ReActResult, task: str) -> str:
    """Sprint 28: 结构化 skill 模板 — 脱敏 + If-Then 格式."""
    tools = _tool_chain(result)
    obs = _key_observations(result)
    lines = []

    # 识别: 触发特征
    ctype = ""
    if task:
        # 从 task 中提取关键特征 (文件类型、关键词等)
        task_sanitized = _sanitize_text(task[:200])
        lines.append(f"识别: {task_sanitized[:120]}")

    # 步骤: 工具链 + 关键经验 (已脱敏)
    if tools:
        lines.append(f"工具链: {' -> '.join(tools)}")
    if obs:
        lines.append("关键经验:")
        for o in obs:
            lines.append(f"- {o}")

    # 坑: 失败原因 (脱敏)
    if not result.success and result.fail_reason:
        reason = _sanitize_text(result.fail_reason)
        lines.append(f"坑: {reason}")
    if result.final_answer and result.success:
        # Sprint 22.5: 禁止把 flag 明文写入 skill
        lines.append("结果: 成功得到 flag（内容不记录, 防污染）")
    return "\n".join(lines) if lines else "(无足够信息)"


def learn_skill(
    task: str,
    result: ReActResult,
    library: SkillLibrary,
    *,
    challenge_type: str = "misc",
    difficulty: str = "",
    llm: LLMClient | None = None,
    model: str | None = None,
    use_llm: bool = False,
    min_steps: int = 2,
) -> Skill | None:
    """从解题结果提炼并存储一条 skill。

    Returns:
        新建/更新后的 Skill；若信息不足则返回 None（不产生噪声）。
    """
    # 信息量不足不生成，避免臃肿
    if result.step_count < min_steps:
        return None
    tools = _tool_chain(result)
    if not tools:
        return None

    status = "成功" if result.success else "失败"
    if use_llm and llm is not None:
        prompt = _LLM_SKILL_PROMPT.format(
            status=status,
            ctype=challenge_type,
            difficulty=difficulty or "unknown",
            task=task[:300],
            tools=", ".join(tools),
            steps="\n".join(_key_observations(result, limit=6)) or "(无)",
        )
        try:
            body = llm.chat(
                [Message(role="user", content=prompt)],
                model=model, temperature=0.3, max_tokens=400,
            ).content.strip()
        except Exception:  # noqa: BLE001
            body = _template_body(result, task)
    else:
        body = _template_body(result, task)

    prefix = "" if result.success else "[避坑] "
    title = f"{prefix}{challenge_type} 题解题套路（{'+'.join(tools[:3])}）"
    trigger = f"{challenge_type} 类题目" + (f"（{difficulty}）" if difficulty else "")

    # Sprint 15: 关联快速解题脚本（skill 与 quick_solve 联动）
    script_ref, reg = _match_quick_solve(challenge_type, tools, task)
    if script_ref and reg is not None and result.success:
        # 成功经验实时回填：提升该方向模板脚本的排序权重
        try:
            reg.record_use(script_ref, success=True)
        except Exception:  # noqa: BLE001
            pass

    # Sprint 28: 提取套路特征 (用于跨题匹配, 基于套路而非题目名称)
    pattern_features = _extract_pattern_features(task, result)

    return library.add_or_update(
        title=title,
        category=challenge_type,
        trigger=trigger,
        body=body,
        tags=[difficulty] if difficulty else [],
        tools=tools,
        source_task=task[:120],
        script_ref=script_ref,
        pattern_features=pattern_features,
    )


__all__ = ["learn_skill"]
