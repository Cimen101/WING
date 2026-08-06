"""skill_curator — 轨迹 → 知识库沉淀管线 (WING 知识库重构 Stage C).

管线: extract → verdict → refine → merge → compress → persist

核心纪律 (用户规则):
- **不管成功/失败都要整理**: 成功 → playbook (正向套路); 失败 → pitfall (避坑)
- **意外退出也要整理完才能退出**: 每条轨迹用 try/finally 兜底, 异常时先把
  轨迹引用/部分产物落盘到 curator_log.jsonl, 不丢失已提取内容
- **脱敏**: 绝对路径/地址/flag → 占位符, 禁止把执行日志当技能
- **查重合并**: 增添 playbook 前先与已有内容算相似度, 相似则合并不重复添加

用法:
    python -m ctf_agent.knowledge.curate --traces data/swarm_logs
"""
from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from typing import Any

from ctf_agent.knowledge.kb import KnowledgeBase, merge_playbook, save_playbook, _jaccard, _tokenize

# 脱敏规则 (与 skill_learner 对齐 + 增强)
_RE_TMP_PATH = re.compile(r"/tmp/[a-zA-Z0-9_./-]+")
_RE_HEX_ADDR = re.compile(r"0x[0-9a-fA-F]{4,}")
_RE_FLAG = re.compile(r"(?:NSSCTF|CTF|flag|athena|moectf|picoctf)\{[^}]{4,}\}", re.IGNORECASE)
_RE_REDACTED = re.compile(r"FLAG_REDACTED\.+", re.IGNORECASE)
# 大数字符串 (RSA N/e/c 等题面常量) — 保留但截断
_RE_BIGNUM = re.compile(r"\b\d{60,}\b")


def sanitize(text: str) -> str:
    """脱敏: 绝对路径/地址/flag/超长数字 → 占位符."""
    if not text:
        return text
    text = _RE_TMP_PATH.sub("{work_dir}", text)
    text = _RE_HEX_ADDR.sub("{address}", text)
    text = _RE_FLAG.sub("{flag}", text)
    text = _RE_REDACTED.sub("{flag}", text)
    text = _RE_BIGNUM.sub("{bigint}", text)
    return text


def _load_trace(path: Path) -> list[dict] | None:
    """加载 jsonl 轨迹 (swarm step 记录)."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return None
    steps: list[dict] = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            obj = json.loads(ln)
        except Exception:
            continue
        if isinstance(obj, dict) and obj.get("type") == "step":
            steps.append(obj)
    return steps or None


def _verdict(steps: list[dict]) -> tuple[str, str]:
    """判定轨迹结果: ("success"/"fail", fail_reason 摘要)."""
    for s in steps:
        if s.get("is_final") and (s.get("final_answer") or "").strip():
            return "success", ""
    fails = [s for s in steps if s.get("is_error")]
    err_msgs = [str(s.get("error_msg") or "") for s in fails if s.get("error_msg")]
    if err_msgs:
        reason = err_msgs[-1]
    else:
        last = steps[-1] if steps else {}
        reason = f"未拿到 flag 提前终止 (共 {len(steps)} 步, 最后动作: {(last.get('action') or '')[:40] or '无'})"
    return "fail", reason


def _tool_chain(steps: list[dict]) -> list[str]:
    seen: list[str] = []
    for s in steps:
        a = (s.get("action") or "").strip()
        if a and a not in seen:
            seen.append(a)
    return seen


def _strip_echo(obs: str) -> str:
    """剥离工具 observation 的命令回显前缀, 保留实际输出.

    格式示例: "$ cat /path/file\n[完成, elapsed=0.08s]\n<实际内容>"
    """
    for marker in ("[完成, elapsed=", "[ERROR, elapsed=", "[python3 执行, elapsed=", "$ [docker_python]"):
        idx = obs.find(marker)
        if idx != -1:
            rest = obs[idx + len(marker):]
            # 去掉 "[完成, elapsed=0.08s]" 的收尾 "]"
            end = rest.find("]")
            if end != -1:
                rest = rest[end + 1:]
            return rest.strip()
    # 无 elapsed 标记: 去掉首行 "$ ..." 回显
    lines = obs.splitlines()
    if lines and lines[0].lstrip().startswith("$ "):
        return "\n".join(lines[1:]).strip()
    return obs


def _key_observations(steps: list[dict], limit: int = 5) -> list[str]:
    """抽取信息量高的 observation 片段 (剥离回显, 脱敏后, 截断)."""
    out: list[str] = []
    for s in steps:
        obs = (s.get("observation") or "").strip()
        if not obs or s.get("is_error"):
            continue
        content = sanitize(_strip_echo(obs).replace("\n", " ")[:260])
        if not content:
            continue
        action = (s.get("action") or "").strip()
        out.append(f"{action} -> {content}")
        if len(out) >= limit:
            break
    return out


def _pitfall_items(steps: list[dict], limit: int = 4) -> list[str]:
    """失败轨迹提取避坑点: error 步 + 失败后的 Thought."""
    out: list[str] = []
    for s in steps:
        if not s.get("is_error"):
            continue
        err = str(s.get("error_msg") or "")
        thought = sanitize(str(s.get("thought") or "").replace("\n", " ")[:200])
        if err and err not in ("empty output",):
            out.append(f"错误: {err} | 后续思路: {thought}")
        if len(out) >= limit:
            break
    return out


def _guess_ctype(steps: list[dict], task: str = "") -> str:
    """从轨迹/任务推断题型 (默认 misc). 扫描 action + observation 前 600 字符."""
    texts = [task]
    for s in steps:
        texts.append(str(s.get("action") or ""))
        obs = str(s.get("observation") or "")
        texts.append(obs[:600])
        texts.append(str(s.get("thought") or "")[:200])
    low = "\n".join(texts).lower()
    # 按特异性从高到低匹配 (避免 "ssh" 等泛词误判)
    for kw, ctype in (
        ("feistel", "crypto"), ("rsa", "crypto"), ("aes", "crypto"), ("ciphertext", "crypto"),
        ("e =", "crypto"), ("n =", "crypto"), ("encrypted_flag", "crypto"),
        ("angr", "reverse"), ("objdump", "reverse"), ("disasm", "reverse"),
        ("checksec", "pwn"), ("overflow", "pwn"), ("canary", "pwn"),
        ("http_request", "web"), ("web_recon", "web"), ("ssti", "web"), ("sqli", "web"),
        ("pcap", "misc"), ("tshark", "misc"), ("binwalk", "misc"), ("exif", "misc"),
        ("osint", "osint"), ("github", "osint"),
    ):
        if kw in low:
            return ctype
    return "misc"


def _build_playbook(steps: list[dict], tool_chain: list[str], obs: list[str]) -> str:
    lines = ["# 套路 (来自 Corvus 轨迹)", f"工具链: {' -> '.join(tool_chain)}"]
    if obs:
        lines.append("关键经验:")
        lines.extend(f"- {o}" for o in obs)
    return "\n".join(lines)


# ============ Sprint 36.5: LLM 分阶段提炼 (用户规则: 独立 LLM 分析整理) ============

def _step_phase(s: dict) -> str:
    """按工具/观测特征给单步定阶段 (粗略分组, 供 LLM 提炼时参考).

    P4 = flag/提交; P3 = 攻击/求解类工具; 其余 (侦查/分析/协作) = P1.
    不细分 P2 — 阶段语义由 LLM 从事件内容推断.
    """
    a = (s.get("action") or "").lower()
    obs = (s.get("observation") or "").lower()
    if s.get("is_final") or (s.get("final_answer") or "").strip() or \
       "flag{" in obs or "nssctf{" in obs or "moectf{" in obs:
        return "P4"
    if any(k in a for k in ("exploit", "payload", "pwntools", "angr", "z3",
                            "lwe_decode", "crypto_rsa", "feistel_decrypt",
                            "ecdsa_nonce", "des_cryptanalysis", "binary_analyze")):
        return "P3"
    return "P1"


def _phase_events(steps: list[dict], limit_per_phase: int = 3) -> list[tuple[str, str]]:
    """把轨迹转成 (阶段, 事件摘要) 序列 (每阶段最多 limit_per_phase 条)."""
    by_phase: dict[str, list[str]] = {}
    for s in steps:
        p = _step_phase(s)
        a = (s.get("action") or "").strip() or "?"
        thought = sanitize(str(s.get("thought") or "").replace("\n", " ")[:120])
        by_phase.setdefault(p, []).append(f"[{a}] {thought}" if thought else f"[{a}]")
    out: list[tuple[str, str]] = []
    for p in ("P1", "P2", "P3", "P4"):
        for ev in by_phase.get(p, [])[:limit_per_phase]:
            out.append((p, ev))
    return out


_REFINE_PROMPT = """你是 CTF 解题轨迹分析师。把下面的解题轨迹提炼为分阶段知识条目，供未来同类题直接参考。

要求：
1. 按 **P1 侦查 / P2 漏洞确认 / P3 利用 / P4 验证提交** 分阶段记录（每阶段用 `## P1 侦查` 这类标题）
2. 每阶段记录：**关键工具链**（实际用过的）、**可参考做法**、**踩过的坑/禁忌**（如反复失败的思路）
3. 成功轨迹提炼"正向套路"；失败轨迹提炼"避坑要点"（哪些方向无效、为什么）
4. **脱敏**：严禁出现内部题名/flag/IP/端口/绝对路径/容器名/用户名，一律用占位符（{work_dir}/{address}/{flag}）
5. 简洁可执行，总长度 ≤2500 字符；只输出 markdown 正文，不要多余说明

轨迹工具链: {tool_chain}
阶段事件序列:
{events}
"""


def _llm_refine(
    steps: list[dict],
    tool_chain: list[str],
    ctype: str,
    verdict: str,
    llm: Any,
) -> str:
    """LLM 分阶段提炼 playbook/pitfall (用户规则: 需要独立 LLM 分析整理).

    无 LLM 时回退到模板拼接 (_build_playbook/_build_pitfall), 保证离线可用.
    """
    if llm is None:
        return ""
    events = _phase_events(steps)
    if not events:
        return ""
    try:
        events_text = "\n".join(f"[{p}] {e}" for p, e in events)
        # 用 replace 而非 format: prompt 内的 {work_dir}/{flag} 等脱敏示例会与 format 花括号冲突
        sys_prompt = (_REFINE_PROMPT
                      .replace("{tool_chain}", " -> ".join(tool_chain))
                      .replace("{events}", events_text))
        msgs = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": f"题型: {ctype}; 结果: {verdict}\n请输出分阶段知识条目."},
        ]
        res = llm.chat(msgs, temperature=0.0, max_tokens=2500)
        md = str(res.content or "").strip()
        if len(md) < 50:
            return ""
        # 二次脱敏兜底 (LLM 可能漏掉内部信息)
        return sanitize(md)[:3000]
    except Exception:  # noqa: BLE001 - LLM 提炼失败回退模板
        return ""


def _update_role_guide(kb: KnowledgeBase, ctype: str, style: str, verdict: str, refined: str) -> bool:
    """按用户规则更新 role_guides: **只改不增** + 超限压缩.

    - 只修改对应题型 role_guide 文件 (role_guides/{ctype}.md 或 {ctype}-{style}.md)
    - 成功 → 在对应阶段段落追加经验; 失败 → 追加"禁忌"要点
    - 文件不存在不创建 (role_guides 由预置初始化, curator 只维护)
    """
    name = f"{ctype}-{style}.md" if style else f"{ctype}.md"
    p = kb.root / "role_guides" / name
    if not p.exists():
        return False
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    # 追加块 (脱敏已在上游完成)
    tag = "经验" if verdict == "success" else "禁忌"
    block = f"\n\n<!-- curator 追加 ({tag}) -->\n{refined}"
    new_text = text + block
    # 只改不增 + 超限压缩: 超过 4KB 时保留各阶段标题与正文头尾
    if len(new_text) > 4000:
        new_text = _compress(new_text, max_chars=4000)
    try:
        p.write_text(new_text, encoding="utf-8")
        return True
    except Exception:
        return False


def _update_patterns(kb: KnowledgeBase, ctype: str, verdict: str, refined: str) -> bool:
    """成功轨迹 → patterns/skill_library.json (抽象经验, 增强字段)."""
    if verdict != "success" or not refined:
        return False
    p = kb.root / "patterns" / "skill_library.json"
    lib: dict[str, Any] = {"skills": []}
    if p.exists():
        try:
            lib = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            if not isinstance(lib, dict):
                lib = {"skills": []}
        except Exception:
            lib = {"skills": []}
    title = f"{ctype} 解题套路 ({len(lib.get('skills', [])) + 1})"
    lib.setdefault("skills", []).append({
        "title": title,
        "challenge_type": ctype,
        "vuln_class": "",
        "trigger": f"遇到 {ctype} 类题且特征匹配时参考",
        "summary": sanitize(refined[:600]),
        "body": refined,
        "source": "skill_curator",
        "last_verified_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    })
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(lib, ensure_ascii=False, indent=2), encoding="utf-8")
        return True
    except Exception:
        return False


def _build_pitfall(steps: list[dict], tool_chain: list[str], fail_reason: str, items: list[str]) -> str:
    lines = ["# 避坑 (来自失败轨迹)", f"失败原因: {sanitize(fail_reason)[:200]}"]
    lines.append(f"工具链: {' -> '.join(tool_chain)}")
    if items:
        lines.append("注意:")
        lines.extend(f"- {i}" for i in items)
    return "\n".join(lines)


def _compress(text: str, max_chars: int = 2500) -> str:
    """压缩: 超长截断保留头尾."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars * 3 // 5] + "\n...[已压缩]...\n" + text[-max_chars * 2 // 5:]


def _merge_into_dir(body: str, ctype: str, kind: str, trace_name: str, kb: KnowledgeBase) -> tuple[Path, bool]:
    """按用户规则把提炼内容并入知识库对应目录: 增添前查重, 相似则在原文件上完善.

    Args:
        body: 提炼后的 playbook/pitfall 文本 (已脱敏/压缩)
        ctype: 题型 (playbooks/{ctype} 或 pitfalls/{ctype})
        kind: "playbook" | "pitfall"
        trace_name: 轨迹文件名 (用于新建条目命名)
        kb: KnowledgeBase 实例

    Returns:
        (目标文件路径, 是否发生变更)
    查重规则: 与目录内已有文件算 Jaccard 相似度, ≥threshold 且新内容有增量 →
    并入相似文件; 相似且无增量 → 不重复添加; 无相似文件 → 新建 {stem}.md.
    """
    sub = "playbooks" if kind == "playbook" else "pitfalls"
    target_dir = kb.root / sub / ctype
    target_dir.mkdir(parents=True, exist_ok=True)
    # 目录级查重
    best_sim, best_path = 0.0, None
    for f in sorted(target_dir.glob("*.md")):
        try:
            existing = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        sim = _jaccard(_tokenize(existing[:3000]), _tokenize(body[:3000]))
        if sim > best_sim:
            best_sim, best_path = sim, f
    threshold = 0.30 if kind == "playbook" else 0.25
    if best_path is not None and best_sim >= threshold:
        existing = best_path.read_text(encoding="utf-8", errors="replace")
        merged, changed = merge_playbook(existing, body, threshold=threshold)
        if changed:
            save_playbook(best_path, merged)
        return best_path, changed
    # 无相似 → 新建条目 (按轨迹名)
    stem = Path(trace_name).stem
    if not stem or stem in (".", "auto"):
        stem = f"{kind}_{len(list(target_dir.glob('*.md'))) + 1}"
    target = target_dir / f"{stem}.md"
    if not target.exists():
        save_playbook(target, body)
        return target, True
    return target, False


def _guess_style(trace_name: str) -> str:
    """从轨迹文件名猜测风格 (xxx_conservative.jsonl → conservative)."""
    stem = Path(trace_name).stem.lower()
    for s in ("conservative", "aggressive", "innovative"):
        if s in stem:
            return s
    return ""


def curate_trace(trace_path: Path, kb: KnowledgeBase, log_path: Path, llm: Any = None) -> dict[str, Any]:
    """单条轨迹 → 沉淀 playbook/pitfall + role_guides + patterns (try/finally 兜底).

    finally 兜底: 无论成功/异常, 都把轨迹引用 + 处理结果写入 curator_log.jsonl;
    异常时把原始轨迹归档到 traces/ (下次可离线补整理) — 满足"意外退出也整理完才能退出".
    """
    record: dict[str, Any] = {
        "trace": str(trace_path),
        "ts": time.time(),
        "status": "processing",
        "output": None,
        "error": None,
    }
    try:
        steps = _load_trace(trace_path)
        if not steps:
            record["status"] = "skip-empty"
            return record

        # 1. extract: 工具链 + 关键观测
        tool_chain = _tool_chain(steps)
        if not tool_chain:
            record["status"] = "skip-no-tool"
            return record

        # 2. verdict: 成功/失败
        verdict, fail_reason = _verdict(steps)
        ctype = _guess_ctype(steps)
        style = _guess_style(trace_path.name)
        record["verdict"] = verdict
        record["ctype"] = ctype
        record["style"] = style
        record["tool_chain"] = tool_chain

        # 3. refine: 优先 LLM 分阶段提炼 (用户规则: 独立 LLM 分析整理), 无 LLM 回退模板
        refined = _llm_refine(steps, tool_chain, ctype, verdict, llm)
        if not refined:
            obs = _key_observations(steps)
            if verdict == "success":
                refined = _compress(_build_playbook(steps, tool_chain, obs))
            else:
                items = _pitfall_items(steps)
                refined = _compress(_build_pitfall(steps, tool_chain, fail_reason, items))

        # 4. persist: playbook/pitfall (目录级查重合并)
        if verdict == "success":
            target, changed = _merge_into_dir(refined, ctype, "playbook", trace_path.name, kb)
        else:
            target, changed = _merge_into_dir(refined, ctype, "pitfall", trace_path.name, kb)
        record["output"] = {"kind": "playbook" if verdict == "success" else "pitfall",
                            "path": str(target), "changed": changed}

        # 5. role_guides 更新 (只改不增): 成功→经验, 失败→禁忌
        rg_changed = _update_role_guide(kb, ctype, style, verdict, refined)
        record["role_guide_changed"] = rg_changed
        # 6. patterns 更新 (抽象经验库, 仅成功)
        pt_changed = _update_patterns(kb, ctype, verdict, refined)
        record["patterns_changed"] = pt_changed

        record["status"] = "done"
        return record
    except Exception as e:  # noqa: BLE001
        record["status"] = "error"
        record["error"] = f"{type(e).__name__}: {e}"
        # 兜底: 异常时把原始轨迹归档到 traces/ (下次可离线补整理)
        try:
            traces_dir = kb.root / "traces"
            traces_dir.mkdir(parents=True, exist_ok=True)
            dst = traces_dir / trace_path.name
            if not dst.exists():
                dst.write_text(trace_path.read_text(encoding="utf-8", errors="replace"),
                               encoding="utf-8")
                record["traces_archived"] = str(dst)
        except Exception:  # noqa: BLE001
            pass
        return record
    finally:
        # 兜底落盘: 即使上面 return, finally 也会执行 (记录已完成状态)
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:  # noqa: BLE001
            pass


def curate_dir(traces_dir: Path, kb_root: Path | None = None, llm: Any = None) -> int:
    """批量策展一个目录下的所有 jsonl 轨迹."""
    kb = KnowledgeBase(root=kb_root) if kb_root else KnowledgeBase()
    log_path = kb.root / "curator_log.jsonl"
    traces = sorted(traces_dir.glob("*.jsonl"))
    if not traces:
        print(f"no jsonl in {traces_dir}")
        return 0
    done = skipped = errors = playbook = pitfall = role_guide = patterns = 0
    for t in traces:
        rec = curate_trace(t, kb, log_path, llm=llm)
        st = rec["status"]
        if st == "done":
            done += 1
            kind = (rec.get("output") or {}).get("kind", "?")
            changed = (rec.get("output") or {}).get("changed", False)
            if kind == "playbook":
                playbook += 1
            else:
                pitfall += 1
            if rec.get("role_guide_changed"):
                role_guide += 1
            if rec.get("patterns_changed"):
                patterns += 1
            print(f"  [{kind:8s}]{'merged' if changed else 'dup' :6s} {t.name} -> {(rec.get('output') or {}).get('path', '')}"
                  f"{' [role_guide]' if rec.get('role_guide_changed') else ''}"
                  f"{' [patterns]' if rec.get('patterns_changed') else ''}")
        elif st == "error":
            errors += 1
            print(f"  [ERROR] {t.name}: {rec.get('error')} {'[traces 已归档]' if rec.get('traces_archived') else ''}")
        else:
            skipped += 1
            print(f"  [skip ] {t.name}: {st}")
    print(f"curated: done={done} (playbook={playbook}, pitfall={pitfall}, role_guide={role_guide}, "
          f"patterns={patterns}) skipped={skipped} errors={errors} log={log_path}")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description="skill_curator: 轨迹 → 知识库沉淀")
    ap.add_argument("--traces", required=True, help="轨迹目录 (含 *.jsonl)")
    ap.add_argument("--kb-root", default=None, help="知识库根目录 (默认 data/knowledge)")
    ap.add_argument("--no-llm", action="store_true", help="不用 LLM 提炼 (模板拼接兜底, 离线更快)")
    args = ap.parse_args()
    llm = None
    if not args.no_llm:
        try:
            from ctf_agent.config import get_settings
            from ctf_agent.llm import RoutedLLMClient
            llm = RoutedLLMClient(settings=get_settings())
        except Exception:  # noqa: BLE001 - 无 LLM 配置时走模板兜底
            llm = None
    return curate_dir(Path(args.traces), Path(args.kb_root) if args.kb_root else None, llm=llm)


if __name__ == "__main__":
    raise SystemExit(main())
