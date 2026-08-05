"""mem_xor_tool - 将 MemXorAnalyzer 包装为 ReAct Tool 接口.

集成: ctf_agent.tools.__init__.py:default_tools()
"""
from __future__ import annotations

from typing import Any

from ctf_agent.tools.base import Tool
from ctf_agent.tools.mem_xor_analyzer import MemXorAnalyzer


class MemXorAnalyzeTool(Tool):
    """mem_xor_analyze: 内存 dump 专用 XOR 分析工具.

    针对 .txt 格式 hex dump (forensics 类题目),自动:
    1. 解析 hex dump 格式 (PAGE 0x... + 00000000/00000010 行)
    2. 解析 process_map.txt 提取 candidate keys (tag=XXX)
    3. 尝试 4 种 XOR 模式:
       - header_concat: 拼接每页 header bytes, 连续 XOR
       - header_per_page: 每页重新从 key[0] 开始
       - full_concat: 拼接所有字节, 连续 XOR
       - full_per_page: 每页重新从 key[0] 开始
    4. 剥离内存标记 (DEADBEEF / FACEB00C / CAFEBABE)
    5. 返回所有 flag 候选 + 排序的解密结果

    比手写 ssh_python 反复试错节省 80%+ token。
    forensics 类题目 (尤其是 RAM dump) 首选。
    """

    name = "mem_xor_analyze"
    description = (
        "内存 dump 专用 XOR 分析工具。针对 .txt 格式 hex dump 内存转储 "
        "(含 PAGE 0x... 块和 00000000/00000010 行),自动解析所有页的 header bytes 和 body bytes, "
        "结合 process_map.txt 提供的 XOR key tag,尝试 4 种 XOR 模式 "
        "(header_concat/header_per_page/full_concat/full_per_page),"
        "剥离 DEADBEEF/FACEB00C/CAFEBABE 等内存标记,"
        "一次性返回所有 flag 候选和按置信度排序的解密结果。"
        "forensics 类内存取证题 (如 RAM_Drift) 首选此工具。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "dump_path": {
                "type": "string",
                "description": "Kali 上 .txt 格式内存 dump 文件路径",
            },
            "process_map_path": {
                "type": "string",
                "description": (
                    "可选,Kali 上 process_map.txt 路径。"
                    "提供时从中提取 tag=XXX 作为 candidate keys。"
                ),
            },
        },
        "required": ["dump_path"],
    }

    def __init__(self, ssh_client: Any) -> None:
        self.analyzer = MemXorAnalyzer(ssh_client)

    def execute(self, dump_path: str, process_map_path: str = "", **_: Any) -> str:
        if not dump_path:
            return "ERROR: dump_path 不能为空"

        result = self.analyzer.analyze(
            dump_path=dump_path,
            process_map_path=process_map_path or None,
        )
        return f"{result.summary()}\n\n=== Full JSON ===\n" + _to_json(result)


def _to_json(result: Any) -> str:
    """将 MemoryDumpAnalysis 序列化为 JSON 字符串."""
    import json
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)
