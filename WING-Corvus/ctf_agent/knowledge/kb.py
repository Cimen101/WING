"""KnowledgeBase — 四层知识库 (WING 重构 Stage B).

结构 (data/knowledge/):
- packages/    外部 skill 包 (只读): SKILL.md + 主题 md, index.json 索引
- role_guides/ 题型分工指南: 每题型 1 个 + 每题型×风格 1 个, **只改不增**
               MD 按 ## P1~P4 分阶段, 每阶段含 目标/工具链/推进标准
- playbooks/   分阶段套路 (增添前查重合并, 见 merge_playbook)
- pitfalls/    避坑 (与正常 skill 分目录)
- patterns/    抽象经验 (skill_library.json, 重设计 schema)
- archived/    旧库封存 (只读)

核心 API:
- KnowledgeBase.retrieve(task, challenge_type, role, style, phase) -> 注入文本
- KnowledgeBase.infer_phase(steps) -> 从轨迹推断当前阶段
- merge_playbook(existing, new) -> 增添前查重合并
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# 默认知识库根目录
DEFAULT_KB_ROOT = Path("data/knowledge")

# 题型 → 包名映射 (外部包 slug)
_PACKAGE_BY_TYPE = {
    "web": "ctf-web",
    "pwn": "ctf-pwn-1.0.0",
    "crypto": "ctf-crypto-1.0.0",
    "reverse": "ctf-reverse-1.0.0",
    "re": "ctf-reverse-1.0.0",
    "misc": "ctf-misc-1.0.0",
    "forensics": "ctf-forensics-1.0.0",
    "osint": "ctf-osint-1.0.0",
    "malware": "ctf-malware-1.0.0",
    "ai-ml": "ctf-ai-ml-1.0.0",
    "rsa": "rsa-ctf-skills-1.0.0",
}

# 阶段识别工具特征 (P3 利用阶段 = 执行/求解类工具; 侦查/请求类不属于)
_EXPLOIT_TOOLS = {
    "ssh_python", "docker_python", "ssh_exec", "docker_exec",
    "angr_symbolic_exec", "z3", "pwntools", "payload", "exploit",
    "gdb", "strace", "python",
}
_FLAG_RE = re.compile(r"(?:ctf|flag|athena|nssctf|moectf|picoctf)\{[^}]{4,}\}", re.IGNORECASE)


def infer_phase(steps: list[Any], max_steps: int = 60) -> str:
    """从 ReAct 轨迹推断当前解题阶段 (P1 侦查 / P2 识别 / P3 利用 / P4 验证).

    规则 (与 SwarmCoordinator._phase_advance_rule 对齐):
    - 已有 flag 特征或提交行为 → P4
    - 已使用利用/执行类工具 → P3
    - 已采集观测 ≥2 步 → P2
    - 其余 → P1
    """
    actions = [getattr(s, "action", "") or "" for s in steps]
    obs_text = "\n".join(getattr(s, "observation", "") or "" for s in steps)
    if _FLAG_RE.search(obs_text):
        return "P4"
    if any(a in _EXPLOIT_TOOLS for a in actions):
        return "P3"
    if len(steps) >= 2:
        return "P2"
    return "P1"


def _tokenize(text: str) -> set[str]:
    """中文/英文 token 化 (用于相似度).

    英文取单词; 中文按连续 CJK 段切 2-gram (粒度适中, 相似度更稳).
    """
    words = set(re.findall(r"[a-zA-Z0-9_]{2,}", (text or "").lower()))
    cjk_runs = re.findall(r"[\u4e00-\u9fff]+", text or "")
    bigrams: set[str] = set()
    for run in cjk_runs:
        if len(run) >= 2:
            bigrams.update(run[i:i + 2] for i in range(len(run) - 1))
        else:
            bigrams.add(run)
    return words | bigrams


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _section_by_phase(md_text: str, phase: str) -> str:
    """从 role_guides MD 中按 ## P1~P4 提取对应段落 (只取当前阶段, 不含前言).

    设计规则: "按对应阶段注入压缩上下文同时避免分心" — 只注入当前阶段段落,
    不携带维护规则/其他阶段内容; 保留阶段标题行供 LLM 识别阶段.
    无分阶段标题时回退取开头 (兼容未分阶段的历史文件).
    """
    if not md_text:
        return ""
    lines = md_text.splitlines()
    # 匹配 "## P1 ..." / "## P2 ..." 前缀 (标题后可带说明文字)
    header_re = re.compile(r"^##\s*(P[1-4])\b")
    # 找所有阶段标题的行号
    header_idx: list[tuple[str, int]] = []
    for i, ln in enumerate(lines):
        m = header_re.match(ln.strip())
        if m:
            header_idx.append((f"## {m.group(1)}", i))
    if not header_idx:
        return md_text[:2000]
    # 只返回目标阶段段落 (含标题行), 不注入前言
    for pos, (h, i) in enumerate(header_idx):
        if h == f"## {phase}":
            end = header_idx[pos + 1][1] if pos + 1 < len(header_idx) else len(lines)
            return "\n".join(lines[i:end]).strip()
    return ""


class KnowledgeBase:
    """四层知识库检索器."""

    def __init__(self, root: Path | None = None):
        self.root = Path(root) if root else DEFAULT_KB_ROOT
        self._role_cache: dict[str, str] = {}
        self._pattern_cache: dict[str, dict[str, Any]] | None = None
        self._tool_catalog: dict = {}
        self._structured: dict = {}   # Sprint 40.5.2: 结构化知识 (JSON)
        self._load_tool_catalog()
        self._load_structured()

    # ── role_guides (Sprint 37: 角色层分离) ──────────────────
    def role_guide(self, challenge_type: str, role: str = "tactic",
                   style: str = "", phase: str = "P1", max_chars: int = 4000) -> str:
        """按角色/题型/阶段返回指南.

        Sprint 37 重构:
        - commander/strategy: role_guides/{ctype}.md (总指挥分工经验, 整段注入)
        - tactic: role_guides/agents/{ctype}-{phase}-{style}.md (解题器执行策略, 整段注入)
        """
        ctype = (challenge_type or "").lower().strip()
        if not ctype:
            return ""

        if role in ("commander", "strategy"):
            # 总指挥/巡查器: 注入 {type}.md (总指挥分工经验, 不分阶段截取)
            text = self._read_role(f"{ctype}.md")
            return text[:max_chars] if text else ""

        # tactic: 注入 agents/{ctype}-{phase}-{style}.md (解题器执行策略)
        path = f"agents/{ctype}-{phase}-{style}.md"
        text = self._read_role(path)
        if not text:
            # 降级: 没有精准匹配时用 conservative 兜底
            fallback = f"agents/{ctype}-{phase}-conservative.md"
            text = self._read_role(fallback)
        return text[:max_chars] if text else ""

    def _read_role(self, name: str) -> str:
        if name in self._role_cache:
            return self._role_cache[name]
        p = self.root / "role_guides" / name
        if not p.exists():
            return ""
        try:
            self._role_cache[name] = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            self._role_cache[name] = ""
        return self._role_cache[name]

    # ── tool_catalog (工具目录) ────────────────────────────
    def _load_tool_catalog(self) -> None:
        """加载 tool_catalog/tool_catalog.json (工具目录, 失败时置空)."""
        catalog_path = Path(self.root) / "tool_catalog" / "tool_catalog.json"
        if catalog_path.exists():
            try:
                self._tool_catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            except Exception:
                self._tool_catalog = {}

    def _get_domain_for_type(self, challenge_type: str) -> str:
        """将 challenge_type 映射到 tool_catalog 中的 domain."""
        mapping = {
            "reverse": "reverse",
            "crypto": "crypto",
            "web": "web",
            "pwn": "pwn",
            "forensics": "forensics",
            "misc": "misc",
            "osint": "osint",
        }
        return mapping.get((challenge_type or "").lower().strip(), "all")

    def _format_tool_catalog(self, challenge_type: str, task: str, phase: str) -> str:
        """将工具目录格式化为易读文本 (按 domain 过滤, 标记为【工具目录】段).

        返回 None 等价用途: 无匹配内容时返回 "" (调用方判空).
        """
        domain = self._get_domain_for_type(challenge_type)
        tools = self._tool_catalog.get("tools", {})
        tool_chains = self._tool_catalog.get("tool_chains", {})
        mapping = self._tool_catalog.get("scenario_tool_mapping", [])

        lines: list[str] = []
        # 1. 该 domain 的工具
        domain_tools = [t for t in tools.values() if t.get("domain") in (domain, "all")]
        if domain_tools:
            lines.append("可用工具:")
            for t in domain_tools:
                name = t.get("name", "")
                speed = t.get("speed", "")
                func = t.get("function", "")
                usage = t.get("usage", "")
                lines.append(f"- {name} [{speed}]：{func}")
                if usage:
                    lines.append(f"  用法：{usage}")
        # 2. 该 domain 的工具链
        domain_chains = [c for c in tool_chains.values() if c.get("domain") == domain]
        if domain_chains:
            lines.append("工具链:")
            for c in domain_chains:
                desc = c.get("description", "")
                chain = c.get("chain", [])
                lines.append(f"- {desc}：{' → '.join(chain) if isinstance(chain, list) else chain}")
        # 3. 上下文相关的场景映射
        t = _tokenize(task or "")
        filtered = []
        for item in mapping:
            if not isinstance(item, dict):
                continue
            scenario = str(item.get("scenario", ""))
            if not t or _jaccard(t, _tokenize(scenario)) > 0.05:
                filtered.append(item)
        if filtered:
            lines.append("场景提示:")
            for item in filtered:
                lines.append(f"- {item.get('scenario', '')}：{item.get('suggest', '')}")

        if not lines:
            return ""
        return "【工具目录】\n" + "\n".join(lines)

    # ── structured (Sprint 40.5.2: 结构化知识库) ─────────────
    def _load_structured(self) -> None:
        """加载 structured/ 下的 JSON 结构化知识 (算法指纹/架构指南/环境解法)."""
        sd = self.root / "structured"
        if not sd.exists():
            return
        for fname in ("algorithm_fingerprints.json", "architecture_guides.json",
                      "environment_solutions.json"):
            p = sd / fname
            if not p.exists():
                continue
            try:
                self._structured[fname] = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                self._structured[fname] = {}

    def structured(self, challenge_type: str = "", task: str = "", max_chars: int = 2500) -> str:
        """按题型/任务关键词查询结构化知识.

        返回匹配的算法指纹/架构指南/环境解法, 注入 agent 辅助逆向.
        """
        if not self._structured:
            return ""
        ctype = (challenge_type or "").lower().strip()
        t = _tokenize(task or "")
        lines: list[str] = []

        # 1. 架构指南: 按关键词匹配 (gameboy/mame/multiarch/neogeo/x86perm/vm)
        arch = self._structured.get("architecture_guides.json", {})
        for gid, guide in (arch.get("guides", {}) or {}).items():
            name = str(guide.get("name", ""))
            # 命中关键词: 题型reverse + 标题/描述含架构特征词
            arch_kw = ["gameboy", "mame", "neogeo", "multiarch", "vm", "x86", "置换", "模拟器", "game boy"]
            if ctype == "reverse" and any(a in (name + " " + str(guide.get("description", ""))).lower() for a in arch_kw):
                # 提取关键字段
                usage = guide.get("usage", "") or guide.get("solution_hint", "") or ""
                inter = guide.get("interaction", "")
                if usage:
                    lines.append(f"  · {usage}")
                if inter:
                    lines.append(f"  · {inter}")

        # 2. 环境解法: 按任务关键词匹配 (glibcxx/qemu/mame/pyboy)
        env = self._structured.get("environment_solutions.json", {})
        for sid, sol in (env.get("solutions", {}) or {}).items():
            name = str(sol.get("name", ""))
            if any(k in t for k in ("glibcxx", "libstdc", "运行", "依赖", "环境", "qemu", "mame", "模拟")):
                for s in sol.get("solutions", [])[:2]:
                    cmd = s.get("command", "")
                    if cmd:
                        lines.append(f"  · [{name}] {cmd}")

        # 3. 算法指纹: 按算法关键词匹配 (aes/rsa/paillier/tea/ecc)
        fp = self._structured.get("algorithm_fingerprints.json", {})
        algo_kw = ["aes", "rsa", "paillier", "tea", "ecc", "加密", "算法", "crypto", "公钥", "homomorphic"]
        if ctype in ("crypto", "reverse") or any(k in t for k in algo_kw):
            for aid, algo in (fp.get("algorithms", {}) or {}).items():
                det = algo.get("detection", {})
                det_text = " ".join(str(v) for v in det.values())
                lines.append(f"  · [{algo.get('name', aid)}] {det_text[:200]}")

        if not lines:
            return ""
        return "【结构化知识参考】\n" + "\n".join(lines)[:max_chars]

    # ── playbooks / pitfalls ───────────────────────────────
    def playbooks(self, challenge_type: str, query: str = "", top_k: int = 2, max_chars: int = 3000) -> str:
        return self._search_dir("playbooks", challenge_type, query, top_k, max_chars)

    def pitfalls(self, challenge_type: str, query: str = "", top_k: int = 3, max_chars: int = 3000) -> str:
        return self._search_dir("pitfalls", challenge_type, query, top_k, max_chars)

    def _search_dir(self, sub: str, challenge_type: str, query: str, top_k: int, max_chars: int) -> str:
        ctype = (challenge_type or "").lower().strip()
        base = self.root / sub
        if not base.exists():
            return ""
        # 目录: {sub}/{ctype}/xxx.md 或 {sub}/xxx.md
        ctype_dir = base / ctype if (base / ctype).exists() else base
        files = sorted(ctype_dir.glob("*.md"))
        if not files:
            return ""
        q = _tokenize(query or ctype)
        scored: list[tuple[Path, float]] = []
        for f in files:
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            sim = _jaccard(q, _tokenize(text[:2000]))
            if sim > 0.05:
                scored.append((f, sim))
        scored.sort(key=lambda x: x[1], reverse=True)
        out: list[str] = []
        used = 0
        for f, _ in scored[:top_k]:
            text = f.read_text(encoding="utf-8", errors="replace")
            used += len(text)
            if used > max_chars:
                text = text[: max(max_chars - (used - len(text)), 200)]
            out.append(f"## {f.stem}\n{text}")
        return "\n\n".join(out)

    # ── patterns (抽象经验, skill_library.json) ─────────────
    def patterns(self, challenge_type: str, query: str = "", top_k: int = 3, max_chars: int = 3000) -> str:
        """从 patterns/skill_library.json 检索抽象经验 (重设计 schema 兼容)."""
        lib = self._load_patterns()
        if not lib:
            return ""
        q = _tokenize(query or "")
        scored: list[tuple[dict[str, Any], float]] = []
        for sk in lib.get("skills", []):
            text = " ".join(str(sk.get(k, "")) for k in ("title", "vuln_class", "trigger", "keywords", "category"))
            sim = _jaccard(q, _tokenize(text))
            if challenge_type and sk.get("challenge_type") == challenge_type:
                sim += 0.15
            if sim > 0.1:
                scored.append((sk, sim))
        scored.sort(key=lambda x: x[1], reverse=True)
        out: list[str] = []
        used = 0
        for sk, _ in scored[:top_k]:
            title = sk.get("title") or sk.get("vuln_class") or sk.get("id", "")
            body = sk.get("body") or sk.get("summary") or ""
            block = f"## {title}\n{body}"
            used += len(block)
            if used > max_chars:
                block = block[: max(max_chars - (used - len(block)), 200)]
            out.append(block)
        return "\n\n".join(out)

    def _load_patterns(self) -> dict[str, Any] | None:
        if self._pattern_cache is not None:
            return self._pattern_cache
        p = self.root / "patterns" / "skill_library.json"
        if not p.exists():
            return None
        try:
            self._pattern_cache = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            self._pattern_cache = {}
        return self._pattern_cache

    # ── packages (外部包, 只读) ─────────────────────────────
    def package_topics(self, challenge_type: str, max_chars: int = 2500) -> str:
        """返回对应题型外部包 SKILL.md 的简介 + 主题清单 (路由用)."""
        pkg = _PACKAGE_BY_TYPE.get((challenge_type or "").lower().strip())
        if not pkg:
            return ""
        for d in (self.root / "packages").iterdir() if (self.root / "packages").exists() else ():
            if d.name == pkg or d.name.startswith(pkg.split("-")[0] + "-"):
                skill_md = d / "SKILL.md"
                if skill_md.exists():
                    text = skill_md.read_text(encoding="utf-8", errors="replace")
                    return text[:max_chars]
        return ""

    # ── 汇总入口 ────────────────────────────────────────────
    def retrieve(
        self,
        task: str = "",
        challenge_type: str = "",
        role: str = "tactic",
        style: str = "",
        phase: str = "P1",
        max_chars: int = 6000,
        is_brainteaser: bool = False,  # Sprint 37: 脑洞题标记
    ) -> str:
        """按角色/题型/阶段组装注入文本.

        Sprint 37 重构:
        - commander 总指挥: {type}.md (总指挥分工经验) + package_topics + patterns
          + brainteaser/* (若 is_brainteaser)
        - strategy 战略层: {type}.md + patterns + package_topics
          + brainteaser/* (若 is_brainteaser)
        - tactic  战术层: agents/{type}-{phase}-{style}.md + playbooks + pitfalls + patterns
        """
        parts: list[str] = []
        ctype = (challenge_type or "").lower().strip()

        # 1. 角色指南 (按角色分流)
        g = self.role_guide(ctype, role=role, style=style, phase=phase,
                            max_chars=max(2000, max_chars // 2))
        if g:
            if role == "tactic":
                parts.append("【当前阶段执行策略 ({phase}×{style})】\n{g}".format(phase=phase, style=style, g=g))
            else:
                parts.append("【题型分工参考】\n{g}".format(g=g))

        # 2. 脑洞题策略覆盖 (仅 commander/strategy, 当 is_brainteaser=True)
        if role in ("commander", "strategy") and is_brainteaser:
            bt_detection = self._read_role("brainteaser/detection.md")
            if bt_detection:
                parts.append("【脑洞题特征库 (判断用)】\n{bt}".format(bt=bt_detection[:2000]))
            bt_general = self._read_role("brainteaser/general.md")
            if bt_general:
                parts.append("【脑洞题通用策略】\n{bt}".format(bt=bt_general[:3000]))

        if role == "tactic":
            pb = self.playbooks(ctype, task, top_k=2)
            if pb:
                parts.append("【套路 playbooks】\n{pb}".format(pb=pb))
            pf = self.pitfalls(ctype, task, top_k=3)
            if pf:
                parts.append("【避坑 pitfalls】\n{pf}".format(pf=pf))
            pt = self.patterns(ctype, task, top_k=3)
            if pt:
                parts.append("【抽象经验 patterns】\n{pt}".format(pt=pt))
        elif role in ("strategy", "commander"):
            pkg = self.package_topics(ctype, max_chars=max(1500, max_chars // 3))
            if pkg:
                parts.append("【外部包主题参考】\n{pkg}".format(pkg=pkg))
            pt = self.patterns(ctype, task, top_k=2, max_chars=2000)
            if pt:
                parts.append("【抽象经验 patterns】\n{pt}".format(pt=pt))
        # 工具目录注入 (仅 tactic 层)
        if role == "tactic" and self._tool_catalog:
            try:
                catalog_text = self._format_tool_catalog(challenge_type, task, phase)
                if catalog_text:
                    parts.append(catalog_text)
            except Exception:
                pass
        # 结构化知识注入 (tactic/strategy 层, 辅助算法/架构/环境识别)
        if role in ("tactic", "strategy"):
            try:
                struct_text = self.structured(challenge_type, task)
                if struct_text:
                    parts.append(struct_text)
            except Exception:
                pass
        return "\n\n".join(parts)[:max_chars]


def merge_playbook(existing: str, new: str, threshold: float = 0.35) -> tuple[str, bool]:
    """playbook 增添前查重合并 (设计规则: 增添前先查重, 相似则在原文件上完善).

    Returns:
        (merged_text, changed): 合并后文本 + 是否发生了实际变更.
    相似度 ≥ threshold 且新内容大部分已存在 → 不重复添加 (changed=False);
    否则把新内容作为新段落追加 (changed=True).
    """
    if not existing:
        return new, True
    if not new:
        return existing, False
    sim = _jaccard(_tokenize(existing), _tokenize(new))
    if sim >= threshold:
        # 高相似 → 检查是否有增量信息 (长度显著不同则合并)
        if len(new) > len(existing) * 1.5:
            return f"{existing}\n\n## 增量补充\n{new}", True
        return existing, False
    return f"{existing}\n\n{new}", True


def load_playbook(path: Path) -> str:
    """读取 playbook 文件 (不存在返回空串)."""
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def save_playbook(path: Path, text: str) -> None:
    """写回 playbook 文件 (自动建目录)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
