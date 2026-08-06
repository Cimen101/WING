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


def curate_trace(trace_path: Path, kb: KnowledgeBase, log_path: Path) -> dict[str, Any]:
    """单条轨迹 → 沉淀 playbook/pitfall (try/finally 兜底).

    finally 兜底: 无论成功/异常, 都把轨迹引用 + 处理结果写入 curator_log.jsonl,
    保证"意外退出也整理完才能退出".
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
        record["verdict"] = verdict
        record["ctype"] = ctype
        record["tool_chain"] = tool_chain

        # 3. refine: 脱敏
        obs = _key_observations(steps)
        pitfalls = _pitfall_items(steps) if verdict == "fail" else []

        # 4+5. merge (目录级查重) + persist
        if verdict == "success":
            body = _compress(_build_playbook(steps, tool_chain, obs))
            target, changed = _merge_into_dir(body, ctype, "playbook", trace_path.name, kb)
            record["output"] = {"kind": "playbook", "path": str(target), "changed": changed}
        else:
            body = _compress(_build_pitfall(steps, tool_chain, fail_reason, pitfalls))
            target, changed = _merge_into_dir(body, ctype, "pitfall", trace_path.name, kb)
            record["output"] = {"kind": "pitfall", "path": str(target), "changed": changed}
        record["status"] = "done"
        return record
    except Exception as e:  # noqa: BLE001
        record["status"] = "error"
        record["error"] = f"{type(e).__name__}: {e}"
        return record
    finally:
        # 兜底落盘: 即使上面 return, finally 也会执行 (记录已完成状态)
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:  # noqa: BLE001
            pass


def curate_dir(traces_dir: Path, kb_root: Path | None = None) -> int:
    """批量策展一个目录下的所有 jsonl 轨迹."""
    kb = KnowledgeBase(root=kb_root) if kb_root else KnowledgeBase()
    log_path = kb.root / "curator_log.jsonl"
    traces = sorted(traces_dir.glob("*.jsonl"))
    if not traces:
        print(f"no jsonl in {traces_dir}")
        return 0
    done = skipped = errors = playbook = pitfall = 0
    for t in traces:
        rec = curate_trace(t, kb, log_path)
        st = rec["status"]
        if st == "done":
            done += 1
            kind = (rec.get("output") or {}).get("kind", "?")
            changed = (rec.get("output") or {}).get("changed", False)
            if kind == "playbook":
                playbook += 1
            else:
                pitfall += 1
            print(f"  [{kind:8s}]{'merged' if changed else 'dup' :6s} {t.name} -> {(rec.get('output') or {}).get('path', '')}")
        elif st == "error":
            errors += 1
            print(f"  [ERROR] {t.name}: {rec.get('error')}")
        else:
            skipped += 1
            print(f"  [skip ] {t.name}: {st}")
    print(f"curated: done={done} (playbook={playbook}, pitfall={pitfall}) skipped={skipped} errors={errors} log={log_path}")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description="skill_curator: 轨迹 → 知识库沉淀")
    ap.add_argument("--traces", required=True, help="轨迹目录 (含 *.jsonl)")
    ap.add_argument("--kb-root", default=None, help="知识库根目录 (默认 data/knowledge)")
    args = ap.parse_args()
    return curate_dir(Path(args.traces), Path(args.kb_root) if args.kb_root else None)


if __name__ == "__main__":
    raise SystemExit(main())
