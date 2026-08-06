"""WING-Goose: 跨进程共享文件总线 (消息总线).

第 7 节第 3 项实施 + T4 测试基础设施.
多 agent 并行解题时, 一个 agent 发现的"高置信度线索"通过 post 写入共享目录,
其他 agent 每 5 步 check 拉取并注入 prompt (兄弟发现).

传播策略 (WING_GOOSE_UPGRADE_PLAN.md T4 决策点 + 优化):
1. 分级过滤: 只传播高置信度发现 (FACT/LIKELY), 低置信度 (POSSIBLE) 不传播
2. 内容消毒 (T4 优化): 命令级具体线索提炼为方向性线索, 避免 agent 反复验证细节
   - 移除 URL 查询参数 (保留路径)
   - 移除具体 payload (保留技术名称)
   - 限制长度 200 字符

用法:
  bus = FileBus(bus_dir)
  bus.post(challenge_id, content="...", agent="aggressive", level="FACT", topic="key")
  msgs = bus.check_sanitized(challenge_id, since=ts)   # 返回消毒后的可见消息
"""
from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path

from ctf_agent.bus.message_bus import Finding


class FileBus:
    """共享文件总线: 每个 challenge 一个 JSONL 文件, 原子 append."""

    def __init__(self, bus_dir: str | Path) -> None:
        self.bus_dir = Path(bus_dir)
        self.bus_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, challenge_id: str) -> Path:
        # 题目 id 可能含分隔符, 归一化为文件名
        safe = challenge_id.replace("/", "_").replace("\\", "_")
        return self.bus_dir / f"{safe}.jsonl"

    def post(
        self,
        challenge_id: str,
        content: str,
        agent: str = "",
        level: str = "FACT",
        topic: str = "",
    ) -> float:
        """发布一条发现. 返回消息时间戳 (供 check since 使用)."""
        msg = {
            "ts": time.time(),
            "agent": agent,
            "content": content[:500],
            "level": level,
            "topic": topic,
        }
        with self._lock:
            with open(self._path(challenge_id), "a", encoding="utf-8") as f:
                f.write(json.dumps(msg, ensure_ascii=False) + "\n")
        return msg["ts"]

    def check(self, challenge_id: str, since: float = 0.0) -> list[dict]:
        """拉取该题 since 之后的新消息 (升序). 不存在文件返回空."""
        path = self._path(challenge_id)
        if not path.exists():
            return []
        msgs: list[dict] = []
        with self._lock:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    m = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if m.get("ts", 0) > since:
                    msgs.append(m)
        return msgs

    def clear(self, challenge_id: str | None = None) -> None:
        """清空总线 (单题或全部)."""
        if challenge_id is None:
            for p in self.bus_dir.glob("*.jsonl"):
                p.unlink(missing_ok=True)
        else:
            self._path(challenge_id).unlink(missing_ok=True)

    def visible(self, msg: dict) -> bool:
        """传播策略: 只传播高置信度发现 (FACT/LIKELY), 防误导."""
        return str(msg.get("level", "")).upper() in ("FACT", "LIKELY")

    @staticmethod
    def sanitize_content(content: str) -> str:
        """T4 传播策略优化: 将命令级细节提炼为方向性线索.

        T4 测试发现命令级具体线索 (如完整 URL+payload) 会诱导 agent 反复验证细节,
        优化为只保留方向性描述 (技术名称 + 发现结论).

        规则:
        1. 移除 URL 查询参数 (保留路径, 如 /?q=xxx → /)
        2. 移除具体 SQL/payload 片段 (保留技术名称, 如 UNION SELECT)
        3. 移除 IP:端口 (替换为 <target>)
        4. 限制 200 字符
        """
        if not content:
            return ""
        # 1. 移除 URL 查询参数
        content = re.sub(r"\?[^\s'\"]+", "", content)
        # 2. 移除 /**/ 具体绕过细节 (保留 /**/ 标记)
        content = re.sub(r"/\*\*/[^\s'\"]+", "/**/", content)
        # 3. 移除具体 IP:端口
        content = re.sub(r"\d+\.\d+\.\d+\.\d+:\d+", "<target>", content)
        # 4. 限制长度
        if len(content) > 200:
            content = content[:200] + "..."
        return content.strip()

    def check_sanitized(self, challenge_id: str, since: float = 0.0) -> list[dict]:
        """拉取并消毒消息 (T4 优化: 方向性线索优先).

        返回 visible=True 的消息, content 经 sanitize_content 消毒.
        原始消息保留在文件中 (供调试), 注入用消毒版本.
        """
        msgs = self.check(challenge_id, since)
        result: list[dict] = []
        for m in msgs:
            if not self.visible(m):
                continue
            sanitized = dict(m)  # shallow copy
            sanitized["content"] = self.sanitize_content(m.get("content", ""))
            if sanitized["content"]:  # 消毒后非空才传播
                result.append(sanitized)
        return result

    # ---------- MessageBus 兼容接口 (S13: 共享工具跨进程复用) ----------

    def _append_msg(self, path: Path, msg: dict) -> int:
        """追加一条消息 (seq 全局递增, 与 post_finding 的 seq 同空间), 返回 seq."""
        with self._lock:
            seq = 0
            if path.exists():
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        m = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    seq = max(seq, int(m.get("seq", 0)))
            seq += 1
            msg["seq"] = seq
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(msg, ensure_ascii=False) + "\n")
            return seq

    def _read_kind(self, task_id: str, kind: str, cursor: int) -> tuple[list[dict], int]:
        """按 kind 读取 seq > cursor 的新消息 (升序), 返回 (msgs, new_cursor).

        new_cursor 按该 kind 的全局 max seq 推进: 即使过滤后为空也推进,
        避免重复读取旧消息 (消费侧需确保每次调用都会推进游标).
        """
        msgs = self.check(task_id, since=0.0)
        out: list[dict] = []
        max_seq = int(cursor)
        for m in msgs:
            seq = int(m.get("seq", 0))
            max_seq = max(max_seq, seq)
            if seq <= cursor:
                continue
            if m.get("kind") != kind:
                continue
            out.append(m)
        return out, max_seq

    # ---------- Sprint 36 (WING-Corvus): 总指挥协议 ----------
    # report   = 战略层 → 总指挥 (重要线索 / 方向确认 / 死路确认, 三档)
    # directive= 总指挥 → 战略层 (方向校准 / 细化分工; 任务=方向性指引非强制枷锁)

    def post_report(self, agent_id: str, task_id: str, content: str,
                    report_type: str = "clue", level: str = "FACT",
                    task_no: int = 0, reply_to: int = 0) -> int:
        """战略层向总指挥汇报一条消息. 返回 seq.

        Args:
            report_type: "clue" 重要线索 | "dead_end" 死路确认(已自行切换) | "question" 提问
            level: 证据分级 FACT/LIKELY/POSSIBLE (只有 FACT/LIKELY 可作总指挥 MUST 依据)
            task_no: 战略层当前执行的任务契约编号 (0=未分配任务)
        """
        if not content or not content.strip():
            raise ValueError("content 不能为空")
        return self._append_msg(self._path(task_id), {
            "ts": time.time(), "agent": agent_id, "task_id": task_id,
            "content": content[:500], "kind": "report",
            "report_type": report_type, "level": level,
            "task_no": int(task_no or 0), "reply_to": int(reply_to or 0),
        })

    def check_reports(self, task_id: str, cursor: int = 0) -> tuple[list[dict], int]:
        """总指挥消费: 拉取该题 kind=report 的新消息 (升序)."""
        return self._read_kind(task_id, "report", cursor)

    def post_directive(self, agent_id: str, task_id: str, content: str,
                       task_no: int = 0, priority: str = "SHOULD",
                       reason: str = "", phase: str = "",
                       forbidden: list[str] | None = None) -> int:
        """总指挥向指定战略层下发方向指令. 返回 seq.

        Args:
            agent_id: 目标战略层 (style 名, 如 "conservative")
            task_no: 更新后的任务契约编号 (战略层据此更新持有的任务)
            priority: "MUST" 必须执行 | "SHOULD" 方向性建议 (默认, 非强制枷锁)
            reason: 指令依据 (总指挥 LLM 的推理, 引用汇报证据)
            phase: Sprint 36.2 当前解题阶段 (P1/P2/P3/P4, 供战略层感知阶段注入任务)
            forbidden: Sprint 36.5.2 任务禁忌列表 (针对任务+当前阶段的约束,
                       战略层合并进本地禁忌拦截; 单路先行时禁忌"稍微放松")
        """
        if not content or not content.strip():
            raise ValueError("content 不能为空")
        return self._append_msg(self._path(task_id), {
            "ts": time.time(), "agent": agent_id, "task_id": task_id,
            "content": content[:500], "kind": "directive",
            "priority": priority, "task_no": int(task_no or 0),
            "reason": reason[:300], "phase": str(phase or ""),
            "forbidden": [str(f)[:200] for f in (forbidden or [])][:8],
        })

    def check_directives(self, task_id: str, agent_id: str | None = None,
                         cursor: int = 0) -> tuple[list[dict], int]:
        """战略层消费: 拉取发给自己的 kind=directive 新消息 (升序).

        agent_id 为 None 时返回全部 directive (供调试); 游标按该 kind 全局推进.
        """
        msgs, new_cursor = self._read_kind(task_id, "directive", cursor)
        if agent_id:
            msgs = [m for m in msgs if m.get("agent") == agent_id]
        return msgs, new_cursor

    def post_finding(self, agent_id: str, task_id: str, content: str,
                     kind: str = "finding", reply_to: int = 0) -> int:
        """MessageBus.post 的文件总线版本 (键=task_id, 返回全局递增 id).

        供 share_finding/check_findings 工具跨进程 (swarm 多进程) 复用:
        各进程读写同一 bus_dir 下的同一 JSONL 文件, 兄弟可见.
        """
        if not content or not content.strip():
            raise ValueError("content 不能为空")
        path = self._path(task_id)
        with self._lock:
            # 自增 seq: 扫描现有行取最大 id + 1 (文件小, 直接读)
            seq = 0
            if path.exists():
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        m = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    seq = max(seq, int(m.get("seq", 0)))
            seq += 1
            msg = {
                "seq": seq,
                "ts": time.time(),
                "agent": agent_id,
                "task_id": task_id,
                "content": content[:500],
                "kind": kind,
                "reply_to": int(reply_to or 0),
                "level": "FACT",
                "topic": "finding",
            }
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(msg, ensure_ascii=False) + "\n")
            return seq

    def check_findings(self, cursor: int = 0, task_id: str | None = None,
                       kind: str | None = None) -> tuple[list[Finding], int]:
        """MessageBus.check 的文件总线版本 (键=task_id, 游标=seq)."""
        if task_id is None:
            return [], 0
        msgs = self.check(task_id, since=0.0)
        out: list[Finding] = []
        max_id = cursor
        for m in msgs:
            seq = int(m.get("seq", 0))
            max_id = max(max_id, seq)
            if seq <= cursor:
                continue
            if kind is not None and m.get("kind") != kind:
                continue
            out.append(Finding(
                id=seq,
                agent_id=str(m.get("agent", "")),
                task_id=str(m.get("task_id", task_id)),
                content=str(m.get("content", "")),
                kind=str(m.get("kind", "finding")),
                reply_to=int(m.get("reply_to", 0)),
                created_at=float(m.get("ts", 0.0)),
            ))
        return out, max_id


__all__ = ["FileBus"]
