"""Sprint 36.2 (WING-Corvus P1): 侦查阶段「任务驱动 + 进度汇报驱动」机制测试.

验证 (用户规范 2026-08-05):
1. 三路全部汇报 recon_done 前, 总指挥保持 P1 (不跳过)
2. 三路全部 recon_done 后 → 总指挥整合全局情报摘要 + 确定主方向 → 才进入 P2
3. P1 期间屏蔽 LLM 输出的 main_direction (主方向由 P1 汇总确定)
4. 战略层每 5 步向总指挥汇报进度 (当前发现/下一步/是否卡死)
5. 战略层 _phase_task_block 不再 AttributeError (修复巡查器失效 bug)
"""

from __future__ import annotations

import json
import tempfile
import time
from dataclasses import dataclass
from types import SimpleNamespace

from ctf_agent.agent.coordinator import Coordinator
from ctf_agent.bus.file_bus import FileBus
from ctf_agent.commander.commander import Commander


@dataclass
class _ChatResult:
    content: str


class _StubLLM:
    """按顺序弹出预设响应的 stub LLM."""

    def __init__(self, responses: list[dict]):
        self._responses = list(responses)
        self.calls: list[list[dict]] = []

    def chat(self, messages: list[dict], **kwargs) -> _ChatResult:
        self.calls.append(list(messages))
        resp = self._responses.pop(0)
        return _ChatResult(content=json.dumps(resp, ensure_ascii=False))


def _make_commander(bus: FileBus, llm: _StubLLM, styles=None) -> Commander:
    return Commander(
        llm=llm,
        title="P1测试题",
        task_desc="测试用题目描述",
        challenge_type="web",
        challenge_difficulty="medium",
        styles=styles or ["conservative", "aggressive", "innovative"],
        challenge_id="t1",
        bus=bus,
        bus_challenge_id="t1",
    )


def _post_recon_done(bus: FileBus, style: str) -> None:
    bus.post_report(
        agent_id=style, task_id="t1",
        content=f"{style} 侦查完成: 入口/指纹/线索已覆盖",
        report_type="recon_done", level="FACT", task_no=1,
    )


def test_p1_partial_done_stays_p1():
    """只有一路 recon_done → 全局保持 P1, 但该路收到单路先行指令 (Sprint 36.5.2).

    用户规范 2026-08-06: 某路完成 P1 侦查后**不等待其他路** — 总指挥单独下发
    该路 P2 先行任务 (不空转); 全局阶段不变 (只有全部完成或超时才全局切换).
    """
    bus = FileBus(tempfile.mkdtemp())
    cmdr = _make_commander(bus, _StubLLM([
        {"silent": True, "directives": [], "main_direction": "", "reasoning": "P1 未完成"},
    ]))
    _post_recon_done(bus, "conservative")
    dirs = cmdr.run_once(bus=bus)
    assert cmdr._phase == "P1", f"只有一路完成不应全局切换, 当前 {cmdr._phase}"
    # 单路先行: conservative 收到 P2 先行指令 (phase=P2, 全局仍 P1)
    assert len(dirs) == 1, f"应下发 1 条先行指令, got {len(dirs)}"
    assert dirs[0].style == "conservative"
    assert cmdr._solo_advanced.get("conservative") == "P2"
    msgs, _ = bus.check_directives("t1", agent_id="conservative", cursor=0)
    assert msgs and msgs[-1].get("phase") == "P2", "先行指令 phase 应为 P2 (仅该路)"


def test_p1_all_done_triggers_p2_with_summary():
    """三路全部 recon_done → 总指挥整合全局情报摘要 + 主方向 → 广播 P2 分工."""
    bus = FileBus(tempfile.mkdtemp())
    cmdr = _make_commander(bus, _StubLLM([
        {
            "summary": "三路侦查汇总: 发现登录入口与源码备份, 疑似反序列化点",
            "main_direction": "反序列化利用",
            "alt_directions": ["备份文件泄露", "弱口令"],
            "reasoning": "情报摘要支撑主方向",
        },
    ]))
    for s in ("conservative", "aggressive", "innovative"):
        _post_recon_done(bus, s)
    dirs = cmdr.run_once(bus=bus)
    # 阶段切换 + 主方向确定
    assert cmdr._phase == "P2", f"三路完成后应进入 P2, 当前 {cmdr._phase}"
    assert cmdr._main_direction == "反序列化利用"
    assert cmdr._alt_directions == ["备份文件泄露", "弱口令"]
    # P2 分工指令已广播 (含全局情报摘要, phase=P2)
    assert len(dirs) == 3
    assert all("全局情报摘要" in d.direction for d in dirs)
    msgs, _ = bus.check_directives("t1", agent_id="conservative", cursor=0)
    assert msgs and msgs[-1].get("phase") == "P2"
    assert "三路侦查汇总" in msgs[-1].get("content", "")


def test_p1_blocks_main_direction_update():
    """P1 期间 LLM 输出的 main_direction 被屏蔽 (主方向由 P1 汇总确定)."""
    bus = FileBus(tempfile.mkdtemp())
    cmdr = _make_commander(bus, _StubLLM([]))
    assert cmdr._phase == "P1"
    cmdr._update_directions_from_llm({
        "main_direction": "过早锁定的方向",
        "alt_directions": ["备选A"],
        "reasoning": "P1 测试",
    })
    assert cmdr._main_direction == "", "P1 期间不应确认主方向"
    assert cmdr._alt_directions == ["备选A"], "P1 期间只允许维护备选方向"


def test_p1_llm_summary_failure_falls_back():
    """LLM 汇总失败 → 降级摘要, 不阻塞阶段推进."""
    bus = FileBus(tempfile.mkdtemp())
    cmdr = _make_commander(bus, _StubLLM([{"not_json": True}]))
    for s in ("conservative", "aggressive", "innovative"):
        _post_recon_done(bus, s)
    dirs = cmdr.run_once(bus=bus)
    assert cmdr._phase == "P2", "LLM 失败不应阻塞 P1→P2"
    assert "降级" in cmdr._context[-1] or any("降级" in c for c in cmdr._context)
    assert dirs, "降级路径也应广播 P2 分工"


def test_p2_verified_triggers_p3():
    """P2 阶段收到 verified 汇报 + 总指挥确凿分析通过 → 切换 P3."""
    bus = FileBus(tempfile.mkdtemp())
    cmdr = _make_commander(bus, _StubLLM([{
        "confirmed": True,
        "direction_summary": "反序列化利用",
        "reasoning": "验证证据完整可复现, 证据支撑充分",
    }]))
    cmdr._phase = "P2"  # 模拟已完成 P1→P2
    cmdr._main_direction = "反序列化利用"
    bus.post_report(
        agent_id="aggressive", task_id="t1",
        content="已验证方向: 反序列化利用 | 验证证据: 本地复现 pop chain 成功",
        report_type="verified", level="FACT", task_no=1,
    )
    dirs = cmdr.run_once(bus=bus)
    assert cmdr._phase == "P3", f"verified 汇报应触发 P2→P3, 当前 {cmdr._phase}"
    assert dirs, "P3 分工指令应广播"
    # P3 分工指令 phase 标记正确, 附已验证方向
    msgs, _ = bus.check_directives("t1", agent_id="aggressive", cursor=0)
    assert msgs and msgs[-1].get("phase") == "P3"
    assert "反序列化利用" in msgs[-1].get("content", "")


def test_p2_verify_rejected_stays_p2():
    """总指挥确凿分析判定验证证据不足 → 保持 P2 (不切换 P3)."""
    bus = FileBus(tempfile.mkdtemp())
    cmdr = _make_commander(bus, _StubLLM([{
        "confirmed": False,
        "direction_summary": "",
        "reasoning": "验证证据不完整, 仅有推测无复现输出",
    }, {
        "silent": True, "directives": [], "main_direction": "", "reasoning": "保持 P2",
    }]))
    cmdr._phase = "P2"
    cmdr._main_direction = "反序列化利用"
    bus.post_report(
        agent_id="aggressive", task_id="t1",
        content="已验证方向: 反序列化利用 | 验证证据: 推测有反序列化点",
        report_type="verified", level="FACT", task_no=1,
    )
    dirs = cmdr.run_once(bus=bus)
    assert cmdr._phase == "P2", f"证据不足不应切换 P3, 当前 {cmdr._phase}"
    assert dirs == []


# ── 战略层侧 ──

def _make_coordinator(bus: FileBus) -> Coordinator:
    return Coordinator(
        llm=None, style="conservative", bus=bus, bus_challenge_id="t1",
        commander_enabled=True,
    )


def test_strategy_phase_task_block_no_attr_error():
    """_phase_task_block 不再 AttributeError (此前未定义导致巡查器静默失效)."""
    co = _make_coordinator(FileBus(tempfile.mkdtemp()))
    for phase in ("P1", "P2", "P3", "P4"):
        co._current_phase = phase
        block = co._phase_task_block()
        assert isinstance(block, str) and block.strip()
        assert phase in block


def test_strategy_p1_progress_report_every_5_steps():
    """P1 阶段每 5 步向总指挥汇报进度 (第 5/10 步汇报, 中间不重复)."""
    bus = FileBus(tempfile.mkdtemp())
    co = _make_coordinator(bus)
    assert co._current_phase == "P1"

    def _step(step_no: int, obs: str = "") -> bool:
            return co.report_p1_progress_if_due(step_no, [
                SimpleNamespace(thought="继续侦查", observation=obs or "发现线索", is_error=False),
            ])

    assert not _step(1), "第 1 步不到汇报节奏"
    assert not _step(4), "第 4 步不到汇报节奏"
    assert _step(5), "第 5 步应汇报"
    assert not _step(6), "第 6 步未满 5 步不重复"
    assert _step(10), "第 10 步应再次汇报"

    reports, _ = bus.check_reports("t1", cursor=0)
    progress = [r for r in reports if r.get("report_type") == "progress"]
    assert len(progress) == 2, f"应有 2 条 progress 汇报, 实际 {len(progress)}"
    content = progress[0].get("content", "")
    assert "侦查进度" in content and "下一步" in content and "是否卡死" in content


def test_strategy_p1_progress_stops_outside_p1():
    """非 P1 阶段 (P2+) 不再做每 5 步进度汇报 (改由巡查汇报 clue/dead_end)."""
    bus = FileBus(tempfile.mkdtemp())
    co = _make_coordinator(bus)
    co._current_phase = "P2"
    co._last_progress_step = 0
    assert not co.report_p1_progress_if_due(5, [
        SimpleNamespace(thought="深入利用", observation="payload 成功", is_error=False),
    ])
    reports, _ = bus.check_reports("t1", cursor=0)
    assert reports == []


def test_strategy_p2_reports_verified():
    """P2 阶段巡查 LLM 判断方向已验证 (p2_verified) → 战略层向总指挥汇报完整证据."""
    bus = FileBus(tempfile.mkdtemp())
    llm = _StubLLM([{
        "reflection": "方向已有证据支撑且本地验证成功, 非猜测",
        "belief_state": [],
        "should_intervene": False,
        "analysis_summary": "反序列化方向已验证",
        "p2_verified": True,
        "p2_verified_direction": "反序列化利用",
        "p2_verified_evidence": "本地复现 pop chain 成功, 触发 _doSystem 回调",
    }])
    co = Coordinator(
        llm=llm, style="aggressive", bus=bus, bus_challenge_id="t1",
        commander_enabled=True,
    )
    co._current_phase = "P2"
    traj = [
        {"thought": "侦查入口", "action": "http_request", "action_input": "GET /",
         "observation": "200 返回", "is_error": False},
        {"thought": "确认反序列化点", "action": "http_request", "action_input": "POST /api",
         "observation": "反序列化报错暴露类名", "is_error": False},
        {"thought": "本地验证", "action": "exploit_template", "action_input": "pop chain",
         "observation": "本地复现成功", "is_error": False},
    ]
    co.analyze(traj, step_no=8, max_steps=50)
    reports, _ = bus.check_reports("t1", cursor=0)
    verified = [r for r in reports if r.get("report_type") == "verified"]
    assert len(verified) == 1, f"应有 1 条 verified 汇报, 实际 {len(verified)}"
    content = verified[0].get("content", "")
    assert "反序列化利用" in content and "验证证据" in content
    assert "pop chain" in content


def test_strategy_p1_done_blocked_in_p2():
    """P1 完成信号 (p1_done) 在非 P1 阶段不触发 recon_done 汇报."""
    bus = FileBus(tempfile.mkdtemp())
    llm = _StubLLM([{
        "reflection": "非 P1 阶段不应汇报侦查完成",
        "belief_state": [],
        "should_intervene": False,
        "analysis_summary": "P2 阶段",
        "p1_done": True,
        "p1_done_summary": "不应上报",
    }])
    co = Coordinator(
        llm=llm, style="conservative", bus=bus, bus_challenge_id="t1",
        commander_enabled=True,
    )
    co._current_phase = "P2"
    traj = [
        {"thought": "a", "action": "http_request", "action_input": "GET /",
         "observation": "200", "is_error": False},
        {"thought": "b", "action": "http_request", "action_input": "GET /admin",
         "observation": "403", "is_error": False},
        {"thought": "c", "action": "http_request", "action_input": "POST /login",
         "observation": "302", "is_error": False},
    ]
    co.analyze(traj, step_no=8, max_steps=50)
    reports, _ = bus.check_reports("t1", cursor=0)
    assert reports == [], "P2 阶段不应上报 recon_done"
