"""Sprint 8: binary_tool - 将 BinaryAnalyzer 包装为 ReAct Tool 接口.

设计：
  - BinaryAnalyzer (binary_analyzer.py) 是核心分析类
  - BinaryAnalyzeTool (本文件) 是 ReAct agent 可调用的工具入口
  - 继承 ctf_agent.tools.base.Tool 接口

集成位置：ctf_agent.tools.__init__.py:default_tools(enable_l3=True)
"""
from __future__ import annotations

from typing import Any

from ctf_agent.tools.base import Tool
from ctf_agent.tools.binary_analyzer import BinaryAnalyzer


class BinaryAnalyzeTool(Tool):
    """binary_analyze: 结构化二进制分析工具.

    替代反复执行 objdump/strings 的低效模式，一次调用返回：
    - 文件类型 / 架构 / 入口点
    - 函数列表（地址/大小/圈复杂度/调用关系）
    - 字符串列表（含 flag 分类）
    - CFG 摘要（复杂度/分支/循环数）
    - Flag 候选（高优先级 flag-like 字符串）

    自动选择后端：
    - Ghidra（若 /opt/ghidra/support/analyzeHeadless 可用）
    - Radare2（默认，Kali 已预装）
    - objdump + strings（兜底）

    比纯 objdump 节省 60%+ token，特别适合 hard 逆向题。
    """

    name = "binary_analyze"
    description = (
        "对二进制文件执行结构化分析，返回 JSON：文件类型/架构/函数列表/字符串/CFG 摘要/flag 候选/"
        "XOR 候选位置 (Sprint 9)。支持 ELF/PE/APK。比直接跑 objdump/strings 节省 60%+ token，"
        "输出更适合 LLM 解析。auto 模式自动选择 Ghidra > radare2 > objdump。"
        "hard 逆向题首选此工具。XOR 候选位置会自动扫描 .rdata/.data 段，"
        "标记高置信度解密点（命中 flag 模式或可读 ASCII）。"
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
                "description": (
                    "分析深度：auto(自动)/quick(objdump,快)/standard(r2,推荐)/"
                    "deep(ghidra,慢但强)"
                ),
            },
            "mode": {
                "type": "string",
                "enum": ["auto", "binary", "text_dump"],
                "description": (
                    "Sprint 10: 处理模式. auto(根据文件类型自动选择) / "
                    "binary(强制二进制分析) / "
                    "text_dump(.txt 内存 dump,返回提示改用 mem_xor_analyze)"
                ),
            },
        },
        "required": ["file_path"],
    }

    def __init__(self, ssh_client: Any) -> None:
        self.analyzer = BinaryAnalyzer(ssh_client)

    def execute(self, file_path: str, depth: str = "auto", mode: str = "auto", **_: Any) -> str:
        if not file_path:
            return "ERROR: file_path 不能为空"

        result = self.analyzer.analyze(file_path, depth, mode)
        # 返回：summary + 完整 JSON
        return f"{result.summary()}\n\n=== Full JSON ===\n{result.to_json()}"
