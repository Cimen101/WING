"""靶场 flag 安全模块.

设计原则（满足"flag 不通过非正常途径被 agent 获取"）：
- flag 随机生成，格式 athena{<32 位随机字母数字>}
- 明文 flag 仅存在于两处：
  1) 运行中的容器内部（agent 通过题目漏洞读取属"正常途径"）
  2) 本地受保护状态文件 .range_state.json（仅供 verify 校验，chmod 600，gitignore）
- 任何面向 LLM / 日志的输出一律使用 mask()，绝不暴露明文
- 靶场工具/管理器对外接口只提供 verify(flag) -> bool，绝不返回真 flag
"""
from __future__ import annotations

import secrets
import string

FLAG_PREFIX = "athena{"
FLAG_SUFFIX = "}"

_ALPHABET = string.ascii_letters + string.digits


def gen_flag(length: int = 32) -> str:
    """生成一个随机 flag."""
    body = "".join(secrets.choice(_ALPHABET) for _ in range(length))
    return f"{FLAG_PREFIX}{body}{FLAG_SUFFIX}"


def mask(flag: str) -> str:
    """将 flag 掩码化，便于在日志/LLM 上下文中安全展示."""
    if not flag or not (flag.startswith(FLAG_PREFIX) and flag.endswith(FLAG_SUFFIX)):
        return "athena{***}"
    inner = flag[len(FLAG_PREFIX) : -len(FLAG_SUFFIX)]
    if len(inner) <= 8:
        return f"{FLAG_PREFIX}{'*' * len(inner)}{FLAG_SUFFIX}"
    return f"{FLAG_PREFIX}{inner[:4]}{'*' * (len(inner) - 8)}{inner[-4:]}{FLAG_SUFFIX}"


def is_valid_flag_format(flag: str) -> bool:
    """判断字符串是否为合法 flag 格式（用于校验 agent 提交的候选）."""
    return bool(flag) and flag.startswith(FLAG_PREFIX) and flag.endswith(FLAG_SUFFIX) and len(flag) > len(FLAG_PREFIX) + len(FLAG_SUFFIX)


__all__ = ["FLAG_PREFIX", "FLAG_SUFFIX", "gen_flag", "mask", "is_valid_flag_format"]
