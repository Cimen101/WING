"""证据决策二叉树 (Sprint 38 Phase C: P2 漏洞确认阶段).

每路解题器独立维护一棵证据二叉树:
- 内部节点 = 二元问题 (是/否), 关联验证方法 + 判定标准 + 确认动作
- 叶子节点 = 假设 (漏洞候选); 根到叶路径 = 完整证据链
- 战术层从根开始验证节点 → 得 是/否 → 沿分支下行 → 直至叶子
- 节点答案必须通过"确认协议" (tentative → confirmed) 才参与路径选择与共享

原则 (2026-08-13 设计定案):
- 共享事实必须 100% 正确: 只有 confirmed 节点才可共享 (node_verdict)
- 未确认节点 (pending/tentative/unknown) 不参与路径选择, 不共享
- 渐进式生长: 只生成"能验证的问题" (二元+验证方法+判定标准三要素)
- 剪枝保留可复活 (excluded + 原因, 不删除)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

# ============ 节点状态 ============
NODE_PENDING = "pending"        # 未验证
NODE_VERIFYING = "verifying"    # 验证中
NODE_TENTATIVE = "tentative"    # 初步观测 (禁止参与路径/禁止共享)
NODE_CONFIRMED = "confirmed"    # 确认 (✅ 参与路径 + 可共享)
NODE_FAILED = "failed"          # 无法判定 (分支阻塞)

# 假设状态
HYP_CANDIDATE = "candidate"     # 候选 (路径未全确认)
HYP_READY = "ready"             # 路径 key 节点全 confirmed → 可提交 P3
HYP_REJECTED = "rejected"       # 被证否


@dataclass
class EvidenceNode:
    """证据树内部节点 = 一个二元问题."""
    id: str
    question: str                       # 二元问题 (条件式)
    verify_method: str = ""             # 验证方法 (工具/命令)
    expected_yes: str = ""              # 判定标准: 是 → 观测到?
    expected_no: str = ""               # 判定标准: 否 → 观测到?
    confirm_action: str = ""            # 确认动作 (正反对比/双独立验证/断言)
    answer: bool | None = None          # 战术层验证结果 (仅 confirmed 时有效)
    status: str = NODE_PENDING
    left: str | None = None             # True 分支
    right: str | None = None            # False 分支
    leaf: str | None = None             # 叶子 → 假设 id
    evidence: str = ""                  # 支撑观测片段 (可复核)
    excluded: bool = False              # 剪枝标记 (保留不删, 可复活)
    excluded_reason: str = ""
    key: bool = False                   # 关键节点 (路径 ready 的硬性要求)
    verified_by: str = ""               # 确认者 (style)
    ts: float = field(default_factory=time.time)

    def to_verdict(self, style: str) -> dict[str, Any] | None:
        """序列化为可共享的 node_verdict — 仅 confirmed 节点允许共享."""
        if self.status != NODE_CONFIRMED or self.answer is None:
            return None
        return {
            "type": "node_verdict",
            "node_id": self.id,
            "node_question": self.question,
            "answer": bool(self.answer),
            "status": NODE_CONFIRMED,
            "evidence": self.evidence[:500],
            "confirm_action": self.confirm_action[:200],
            "verified_by": style,
            "ts": self.ts,
        }


@dataclass
class Hypothesis:
    """叶子 = 假设 (漏洞候选). 根到叶路径 = 完整证据链."""
    id: str
    statement: str
    path: list[str] = field(default_factory=list)   # 根到叶节点 id 序列
    status: str = HYP_CANDIDATE
    key_nodes: list[str] = field(default_factory=list)  # 关键节点 id
    owner_style: str = ""
    note: str = ""

    def is_ready(self, nodes: dict[str, EvidenceNode]) -> bool:
        """路径证据链逻辑完整 = 所有 key 节点 confirmed (+ 支撑节点基本确认)."""
        if not self.path:
            return False
        keys = self.key_nodes or self.path
        for nid in keys:
            node = nodes.get(nid)
            if node is None or node.status != NODE_CONFIRMED or node.answer is None:
                return False
        # 支撑节点: confirmed 为主, 允许 ≤1 个未确认且非 key
        unknown = [nid for nid in self.path
                   if nid not in (self.key_nodes or [])
                   and (nodes.get(nid) is None
                        or nodes.get(nid).status not in (NODE_CONFIRMED, NODE_PENDING))]
        return len(unknown) <= 1


@dataclass
class AttackLink:
    """P3 攻击链环节 (Phase D 使用, 先定义模型)."""
    link_id: str
    desc: str = ""
    input_keys: list[str] = field(default_factory=list)
    output_key: str = ""
    action: str = ""
    verify_assert: str = ""
    status: str = "pending"   # pending | in_progress | verified | failed
    fail_type: str = ""       # impl | method | dead
    attempts: int = 0


class EvidenceTree:
    """证据决策二叉树 (每路解题器独立维护)."""

    def __init__(self, root_question: str = "", owner_style: str = "") -> None:
        self.nodes: dict[str, EvidenceNode] = {}
        self.hypotheses: dict[str, Hypothesis] = {}
        self.root_id: str | None = None
        self.owner_style = owner_style
        self._node_seq = 0
        self._hyp_seq = 0
        if root_question:
            self.set_root(root_question)
            self.root_id = "N0"

    # ---------- 构建 ----------

    def _add_node(self, node: EvidenceNode) -> None:
        self.nodes[node.id] = node

    def _new_id(self, prefix: str = "N") -> str:
        nid = f"{prefix}{self._node_seq}"
        self._node_seq += 1
        return nid

    def set_root(self, question: str, verify_method: str = "",
                 expected_yes: str = "", expected_no: str = "",
                 confirm_action: str = "") -> str:
        """设置/重建根节点问题 (渐进式生长初始步骤)."""
        if self.root_id and self.root_id in self.nodes:
            root = self.nodes[self.root_id]
            root.question = question
            root.verify_method = verify_method
            root.expected_yes = expected_yes
            root.expected_no = expected_no
            root.confirm_action = confirm_action
            return self.root_id
        nid = self._new_id()
        self._add_node(EvidenceNode(
            id=nid, question=question, verify_method=verify_method,
            expected_yes=expected_yes, expected_no=expected_no,
            confirm_action=confirm_action,
        ))
        self.root_id = nid
        return nid

    def add_branch(self, parent_id: str, answer: bool, question: str,
                   verify_method: str = "", expected_yes: str = "",
                   expected_no: str = "", confirm_action: str = "",
                   key: bool = False) -> str:
        """在父节点下沿 answer 分支生长下一层节点."""
        parent = self.nodes.get(parent_id)
        if parent is None:
            raise KeyError(f"节点 {parent_id} 不存在")
        nid = self._new_id()
        node = EvidenceNode(
            id=nid, question=question, verify_method=verify_method,
            expected_yes=expected_yes, expected_no=expected_no,
            confirm_action=confirm_action, key=key,
        )
        self._add_node(node)
        if answer:
            parent.left = nid
        else:
            parent.right = nid
        return nid

    def add_leaf(self, parent_id: str, answer: bool, statement: str,
                 key_nodes: list[str] | None = None, owner_style: str = "") -> str:
        """在父节点下沿 answer 分支生长叶子 (假设)."""
        parent = self.nodes.get(parent_id)
        if parent is None:
            raise KeyError(f"节点 {parent_id} 不存在")
        hid = f"H{self._hyp_seq}"
        self._hyp_seq += 1
        path = self._path_to(parent_id) + [parent_id]
        hyp = Hypothesis(
            id=hid, statement=statement, path=path,
            key_nodes=key_nodes or path[-1:],
            owner_style=owner_style or self.owner_style,
        )
        self.hypotheses[hid] = hyp
        if answer:
            parent.left = hid
        else:
            parent.right = hid
        return hid

    # ---------- 路径 ----------

    def _path_to(self, node_id: str) -> list[str]:
        """从根到指定节点的路径 (不含该节点)."""
        if not self.root_id:
            return []
        path: list[str] = []
        cur = self.root_id
        visited = 0
        while cur and cur != node_id and visited < 100:
            path.append(cur)
            node = self.nodes.get(cur)
            if node is None:
                break
            nxt = None
            for cand in (node.left, node.right):
                if cand:
                    # 需判断 cand 是否为 node_id 或在其子树
                    if self._subtree_contains(cand, node_id):
                        nxt = cand
                        break
            if nxt is None:
                break
            cur = nxt
            visited += 1
        return path

    def _subtree_contains(self, node_ref: str, target_id: str, depth: int = 0) -> bool:
        if depth > 100:
            return False
        if node_ref == target_id:
            return True
        if node_ref.startswith("H"):
            return False
        node = self.nodes.get(node_ref)
        if node is None:
            return False
        for cand in (node.left, node.right):
            if cand and self._subtree_contains(cand, target_id, depth + 1):
                return True
        return False

    def path_of_hypothesis(self, hid: str) -> list[str]:
        """返回假设的根到叶路径节点 id 序列."""
        hyp = self.hypotheses.get(hid)
        return list(hyp.path) if hyp else []

    # ---------- 验证/确认 (状态机) ----------

    def record_observation(self, node_id: str, answer: bool | None,
                           evidence: str = "") -> None:
        """战术层上报节点观测 → 置 tentative (初步, 尚未确认)."""
        node = self.nodes.get(node_id)
        if node is None:
            return
        if answer is not None:
            node.answer = answer
            node.evidence = evidence[:500]
        node.status = NODE_TENTATIVE

    def confirm(self, node_id: str, style: str = "") -> None:
        """确认动作通过 → confirmed (✅ 可参与路径 + 可共享)."""
        node = self.nodes.get(node_id)
        if node is None or node.answer is None:
            return
        node.status = NODE_CONFIRMED
        if style:
            node.verified_by = style

    def mark_failed(self, node_id: str, reason: str = "") -> None:
        """无法判定 → failed (分支阻塞, 不旁路猜测)."""
        node = self.nodes.get(node_id)
        if node is None:
            return
        node.status = NODE_FAILED
        node.excluded = True
        node.excluded_reason = reason or "验证无法判定"

    def prune(self, node_id: str, reason: str) -> None:
        """剪枝 (证否方向) — 标记 excluded, 保留可复活."""
        node = self.nodes.get(node_id)
        if node is None:
            return
        node.excluded = True
        node.excluded_reason = reason

    def revive(self, node_id: str) -> None:
        node = self.nodes.get(node_id)
        if node is not None:
            node.excluded = False
            node.excluded_reason = ""

    # ---------- 查询 ----------

    def next_unconfirmed(self) -> str | None:
        """当前可验证节点: 沿根到最近未确认节点 (父路径已确认)."""
        if not self.root_id:
            return None
        cur = self.root_id
        visited = 0
        while visited < 100:
            node = self.nodes.get(cur)
            if node is None:
                return None
            if node.status != NODE_CONFIRMED:
                return cur
            # 沿已确认答案分支下行
            if node.answer is True and node.left:
                cur = node.left
            elif node.answer is False and node.right:
                cur = node.right
            else:
                return None  # 已到尽头 (无分支或叶子)
            visited += 1
        return None

    def ready_hypotheses(self) -> list[str]:
        return [hid for hid, h in self.hypotheses.items()
                if h.is_ready(self.nodes) and h.status == HYP_CANDIDATE]

    def to_shareable_verdicts(self) -> list[dict[str, Any]]:
        """导出全部 confirmed 节点为可共享 verdict."""
        out = []
        for node in self.nodes.values():
            v = node.to_verdict(self.owner_style)
            if v:
                out.append(v)
        return out

    def summary(self) -> str:
        n_ok = sum(1 for n in self.nodes.values() if n.status == NODE_CONFIRMED)
        n_pending = sum(1 for n in self.nodes.values() if n.status == NODE_PENDING)
        n_hyp = len(self.hypotheses)
        ready = len(self.ready_hypotheses())
        return f"树: {len(self.nodes)} 节点 (confirmed={n_ok}, pending={n_pending}), " \
               f"{n_hyp} 假设, {ready} ready"


# ============ P3 攻击链 (Phase D) ============

# 环节状态
LINK_PENDING = "pending"
LINK_IN_PROGRESS = "in_progress"
LINK_VERIFIED = "verified"
LINK_FAILED = "failed"

# 失败类型 (决定回溯点)
FAIL_IMPL = "impl"       # 实现细节 (参数/语法/脚本 bug) → 回溯本环重做
FAIL_METHOD = "method"   # 方法错误 (该环方法不行) → 回溯最近分支点重设计
FAIL_DEAD = "dead"       # 假设证否 (环验证推翻 P2 假设) → 回 P2 换假设

# 题型模板骨架 (攻击链粗骨架, 战略层按实际填充)
ATTACK_CHAIN_TEMPLATES: dict[str, list[dict]] = {
    "pwn": [
        {"desc": "构造触发输入/连接服务", "action": "连接服务并发送构造的恶意输入"},
        {"desc": "触发漏洞原语", "action": "触发目标漏洞 (栈溢出/堆利用/格式化等)"},
        {"desc": "利用原语构建 exploit", "action": "把原语串成任意读写/代码执行"},
        {"desc": "执行拿 flag", "action": "执行 exploit 读取 flag"},
    ],
    "crypto": [
        {"desc": "恢复密钥/参数", "action": "从题目数据恢复密钥或加密参数"},
        {"desc": "构造攻击脚本", "action": "编写解密/还原脚本"},
        {"desc": "验证解密结果", "action": "验证解密输出可读/格式正确"},
        {"desc": "提取 flag", "action": "从还原结果中提取 flag"},
    ],
    "web": [
        {"desc": "构造 payload", "action": "构造漏洞利用 payload"},
        {"desc": "注入/触发", "action": "向目标提交 payload 触发漏洞"},
        {"desc": "回收数据", "action": "从响应/回传通道回收敏感数据"},
        {"desc": "提取 flag", "action": "从回收数据中提取 flag"},
    ],
    "rev": [
        {"desc": "定位校验逻辑", "action": "定位关键校验函数/算法"},
        {"desc": "提取算法/写求解器", "action": "逆向算法并编写求解脚本/模拟器"},
        {"desc": "求解序列", "action": "运行求解器得到正确输入"},
        {"desc": "验证执行", "action": "提交正确输入验证通过并拿 flag"},
    ],
    "misc": [
        {"desc": "定位编码/约束", "action": "识别文件格式/编码/图论约束"},
        {"desc": "构造解析器", "action": "编写解析/还原脚本"},
        {"desc": "解析还原", "action": "运行解析器还原内容"},
        {"desc": "提取 flag", "action": "从还原结果中提取 flag"},
    ],
}


class AttackChain:
    """P3 攻击链 (链式驱动): 一串强依赖环节, 每环有输入/输出/验证断言.

    回溯机制 (不全局否定):
    - FAIL_IMPL → 回溯本环 (保留前环产物) 重做
    - FAIL_METHOD → 回溯最近分支点重设计该环及后续
    - FAIL_DEAD → 回 P2 换假设
    """

    def __init__(self, challenge_type: str = "", hypothesis_id: str = "") -> None:
        self.challenge_type = str(challenge_type or "misc").lower().strip()
        self.hypothesis_id = hypothesis_id
        self.links: list[AttackLink] = []
        self.status: str = "designing"   # designing | executing | succeeded | failed
        self.current_idx: int = 0        # 当前执行环节下标
        self.method_backtracks = 0       # method 回溯计数 (上限 2)

    # ---------- 构建 ----------

    def build_from_template(self, fills: list[dict] | None = None) -> int:
        """按题型模板骨架生成攻击链, 战略层可传 fills 覆盖 action/verify_assert."""
        fills = fills or []
        tmpl = ATTACK_CHAIN_TEMPLATES.get(self.challenge_type,
                                          ATTACK_CHAIN_TEMPLATES["misc"])
        self.links = []
        for i, t in enumerate(tmpl):
            fill = fills[i] if i < len(fills) and fills[i] else {}
            link = AttackLink(
                link_id=f"L{i + 1}",
                desc=str(fill.get("desc") or t.get("desc") or f"环节{i + 1}"),
                input_keys=list(fill.get("input_keys") or ([] if i == 0 else [f"L{i}_out"])),
                output_key=str(fill.get("output_key") or f"L{i + 1}_out"),
                action=str(fill.get("action") or t.get("action") or ""),
                verify_assert=str(fill.get("verify_assert") or ""),
            )
            self.links.append(link)
        self.status = "executing"
        self.current_idx = 0
        return len(self.links)

    # ---------- 执行/回溯状态机 ----------

    def current_link(self) -> AttackLink | None:
        if 0 <= self.current_idx < len(self.links):
            return self.links[self.current_idx]
        return None

    def mark_verified(self) -> bool:
        """当前环验证通过 → 进下一环; 全部完成 → succeeded."""
        link = self.current_link()
        if link is None:
            return False
        link.status = LINK_VERIFIED
        if self.current_idx >= len(self.links) - 1:
            self.status = "succeeded"
            return True
        self.current_idx += 1
        return True

    def mark_failed(self, fail_type: str, reason: str = "") -> str:
        """当前环失败 → 按类型回溯. 返回动作描述 (供注入战术层).

        返回: "impl_retry" | "method_backtrack" | "dead_end"
        """
        link = self.current_link()
        if link is None:
            return "dead_end"
        link.status = LINK_FAILED
        link.fail_type = fail_type
        link.attempts += 1
        if fail_type == FAIL_IMPL:
            if link.attempts > 3:
                # impl 超限 → 升级为 method (方法可能真不行)
                return self.mark_failed(FAIL_METHOD, f"实现重试 {link.attempts} 次仍失败: {reason}")
            link.status = LINK_IN_PROGRESS  # 重做本环
            return "impl_retry"
        if fail_type == FAIL_METHOD:
            self.method_backtracks += 1
            if self.method_backtracks > 2:
                return "dead_end"  # method 回溯超限 → 回 P2
            # 回溯到最近分支点: 简单实现 = 回到上一环, 重新设计当前环
            if self.current_idx > 0:
                self.current_idx -= 1
                self.links[self.current_idx].status = LINK_IN_PROGRESS
                self.links[self.current_idx].fail_type = ""
                return "method_backtrack"
            return "dead_end"
        # FAIL_DEAD
        return "dead_end"

    def summary(self) -> str:
        parts = []
        for i, l in enumerate(self.links):
            mark = {LINK_VERIFIED: "[v]", LINK_FAILED: "[x]", LINK_IN_PROGRESS: "->"}.get(
                l.status, "[ ]")
            parts.append(f"{mark}L{i + 1}:{l.desc[:20]}")
        return f"攻击链 {self.status} ({len(self.links)} 环): " + " ".join(parts)


__all__ = [
    "EvidenceNode", "Hypothesis", "AttackLink", "EvidenceTree",
    "AttackChain", "ATTACK_CHAIN_TEMPLATES",
    "NODE_PENDING", "NODE_VERIFYING", "NODE_TENTATIVE", "NODE_CONFIRMED",
    "NODE_FAILED", "HYP_CANDIDATE", "HYP_READY", "HYP_REJECTED",
    "LINK_PENDING", "LINK_IN_PROGRESS", "LINK_VERIFIED", "LINK_FAILED",
    "FAIL_IMPL", "FAIL_METHOD", "FAIL_DEAD",
]
