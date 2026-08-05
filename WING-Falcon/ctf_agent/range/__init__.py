"""靶场（range）模块：为依赖服务器的 CTF 题目提供运行环境与生命周期管理.

安全模型（用户输入：flag 不得通过非正常途径被 agent 获取）：
- 明文 flag 仅存在于：① 运行中的容器内部（agent 经漏洞读取属正常途径）
  ② 本地受保护状态文件 .range_state.json（chmod 600 + gitignore，仅供 verify）
- 所有面向 LLM / 日志的输出一律 mask() 掩码
- 对外工具只提供 verify(flag)->bool，绝不返回真 flag
- SSH 审计层（ctf_agent.ssh.safety）额外阻断 docker exec/inspect/logs 进靶场容器
"""
from __future__ import annotations

from .catalog import (
    ALL, ChallengeSpec, DYNAMIC, STATIC, by_name, container_name,
    dynamic_challenges, image_name, local_container_dir,
)
from .flag import FLAG_PREFIX, FLAG_SUFFIX, gen_flag, is_valid_flag_format, mask
from .manager import DEFAULT_STATE_PATH, REMOTE_ROOT, RangeManager
from .tool import RangeTool, range_tools

__all__ = [
    "ALL", "ChallengeSpec", "DYNAMIC", "STATIC", "by_name", "container_name",
    "dynamic_challenges", "image_name", "local_container_dir",
    "FLAG_PREFIX", "FLAG_SUFFIX", "gen_flag", "is_valid_flag_format", "mask",
    "DEFAULT_STATE_PATH", "REMOTE_ROOT", "RangeManager",
    "RangeTool", "range_tools",
]
