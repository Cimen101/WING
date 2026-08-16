"""Sprint 37: FlagVerifier 证据链升级回归测试 (ida-reverse-course CH4/CH8 复盘).

覆盖 4 个场景:
1. reverse 题 hex/字节编码提取作为来源 (CH4 maze: objdump 提取 666c61677b...)
2. 程序验证豁免: echo 'flag{...}' | wine 输出 Correct! 不算自导自演 (CH4)
3. 拒绝软锁: 先被拒 (无证据) → 后干净提取 → 同 flag 允许重新验证 (CH4 死锁修复)
4. 拼接式 flag: flag 明文从不出现在 observation, 但各编码片段出现 (CH8)
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctf_agent.agent.flag_verify import FlagVerifier


@dataclass
class _Step:
    step_no: int
    thought: str = ""
    action: str = ""
    action_input: str = ""
    observation: str = ""
    is_final: bool = False


def make_verifier(**kw) -> FlagVerifier:
    # 不启用 LLM 审查, 只测代码机制
    return FlagVerifier(llm=None, enable_llm=False, **kw)


def test_hex_source_reverse():
    """场景 1: objdump/xxd 提取 hex 字节序列 → 来源识别."""
    flag = "flag{f0ll0w_th3_c4ll_gr4ph}"
    hex_repr = flag.encode().hex()  # 666c61677b66306c6c...
    steps = [
        _Step(1, action="ssh_exec", action_input='{"command": "file_type challenge04_maze.exe"}',
              observation="PE32+ executable"),
        _Step(2, action="ssh_exec",
              action_input='{"command": "objdump -d challenge04_maze.exe | grep -o ..."}',
              observation=f"提取 mov 立即数: {hex_repr}  (来自二进制 .text 段)"),
    ]
    v = make_verifier()
    res = v.verify(flag, steps)
    assert res.passed, f"hex 编码来源应通过: {res.reason}"
    assert res.source_step == 2
    print("[PASS] 场景1 hex 编码来源")


def test_program_verify_exempt():
    """场景 2: echo 'flag{...}' | wine 输出 Correct! → 程序验证豁免."""
    flag = "flag{f0ll0w_th3_c4ll_gr4ph}"
    steps = [
        _Step(1, action="ssh_exec",
              action_input='{"command": "echo \'flag{f0ll0w_th3_c4ll_gr4ph}\' | wine challenge04_maze.exe"}',
              # 真实 ssh_exec 回显完整命令 (含 flag) + 程序输出 Correct!
              observation="$ echo 'flag{f0ll0w_th3_c4ll_gr4ph}' | wine challenge04_maze.exe\nCorrect! You traced the call graph."),
    ]
    v = make_verifier()
    res = v.verify(flag, steps)
    assert res.passed, f"程序验证应豁免自导自演: {res.reason}"
    print("[PASS] 场景2 程序验证豁免")


def test_program_verify_self_scripted_still_rejected():
    """场景 2b: 脚本内硬编码 flag 直接打印 (无程序验证) → 仍拒绝."""
    flag = "flag{f0ll0w_th3_c4ll_gr4ph}"
    steps = [
        _Step(1, action="ssh_python",
              action_input='{"script": "print(\'flag{f0ll0w_th3_c4ll_gr4ph}\')"}',
              observation="flag{f0ll0w_th3_c4ll_gr4ph}"),
    ]
    v = make_verifier()
    res = v.verify(flag, steps)
    assert not res.passed, "纯脚本打印 (无程序验证) 应仍拒绝"
    print("[PASS] 场景2b 自导自演仍拒绝")


def test_rejected_softlock():
    """场景 3: 先无证据被拒 → 后干净提取 → 同 flag 允许重新验证 (软锁)."""
    flag = "flag{f0ll0w_th3_c4ll_gr4ph}"
    hex_repr = flag.encode().hex()
    v = make_verifier()

    # 第一次: 只有 thought 里的猜测, 无 observation 证据 → 拒绝
    steps1 = [
        _Step(1, action="ssh_exec", action_input='{"command": "ls /challenge"}',
              observation="/challenge/workspace"),
    ]
    res1 = v.verify(flag, steps1)
    assert not res1.passed, "无观测证据应拒绝"

    # 第二次: 同 flag, 但已通过 objdump 干净提取 hex → 应通过 (软锁解除)
    steps2 = steps1 + [
        _Step(2, action="ssh_exec",
              action_input='{"command": "objdump -d challenge04_maze.exe"}',
              observation=f"mov 立即数序列: {hex_repr}"),
    ]
    res2 = v.verify(flag, steps2)
    assert res2.passed, f"有新证据后同 flag 应解除拉黑: {res2.reason}"
    print("[PASS] 场景3 拒绝软锁")


def test_concatenated_flag_ch8():
    """场景 4: CH8 拼接式 flag — 各段片段在早期观测, 最终 ssh_python 拼接解码打印."""
    flag = "flag{junk_c0d3_h1d3s_in_pl41n_s1ght}"
    steps = [
        _Step(1, action="ssh_exec", action_input='{"command": "strings -n 3 challenge08.exe"}',
              observation="flag{junH nk_c0d3 En_ju nk_C0d3_"),  # 垃圾代码插入 H
        _Step(2, action="ssh_exec",
              action_input='{"command": "objdump -d challenge08.exe | grep movabs"}',
              observation="movabs rax, 0x6e756a7b67616c66 ; movabs rax, 0x336430635f6b6e"),  # 小端: flag{jun / nk_c0d3
        _Step(3, action="ssh_python",
              action_input='{"script": "import struct; segs=[0x6e756a7b67616c66,0x336430635f6b6e,0x695f73336431685f,0x346c705f6e695f,0x74686731735f6e31]; print(\\"\\".join(struct.pack(\\"<Q\\",s).decode(errors=\\"ignore\\").rstrip(\\"\\\\0\\") for s in segs))"}',
              observation="flag{junk_c0d3_h1d3s_in_pl41n_s1ght"),  # 拼接解码输出完整明文
    ]
    v = make_verifier()
    res = v.verify(flag, steps)
    # 拼接式 flag: 早期只有片段, 最终拼接解码输出完整明文 — 应通过
    assert res.passed, f"拼接 flag 最终解码输出应通过: {res.reason}"
    assert res.source_step == 3
    print(f"[PASS] 场景4 拼接 flag 来源识别: source_step={res.source_step}")


def test_hallucination_still_rejected():
    """防回归: 纯幻觉 flag (从未出现) 仍拒绝."""
    flag = "flag{tot4lly_f4k3_gu3ss}"
    steps = [
        _Step(1, action="ssh_exec", action_input='{"command": "ls"}', observation="bin lib"),
    ]
    v = make_verifier()
    res = v.verify(flag, steps)
    assert not res.passed
    print("[PASS] 幻觉 flag 仍拒绝")


# ─────────── Sprint 37: 已解出未提交检测 (CH8) ───────────


class _FakeBus:
    def __init__(self):
        self.published = []

    def publish(self, *a, **kw):
        self.published.append((a, kw))


def _mk_step(step_no, thought="", action="", action_input="", observation="", final_answer=""):
    return {
        "step_no": step_no,
        "thought": thought,
        "action": action,
        "action_input": action_input,
        "observation": observation,
        "final_answer": final_answer,
    }


def test_solved_not_submitted_ch8():
    """CH8 场景: agent 已提取 flag 片段+movabs, thought 出现完整 flag, 仍在反复 objdump/xxd."""
    from ctf_agent.agent.coordinator import Coordinator
    coord = Coordinator(llm=None, style="aggressive", bus=_FakeBus())
    recent = [
        _mk_step(1, thought="找到片段 flag{jun", action="strings", action_input='{"cmd": "strings"}',
                 observation="flag{junH nk_c0d3"),
        _mk_step(2, thought="movabs 立即数", action="objdump", action_input='{"cmd": "objdump"}',
                 observation="movabs rax, 0x6e756a7b67616c66"),
        _mk_step(3, thought="完整 flag = flag{junk_c0d3_h1d3s_in_pl41n_s1ght}, 让我再验证字节",
                 action="ssh_python", action_input='{"script": "extract bytes"}',
                 observation="提取完成: 66 6c 61 67 7b 6a 75 6e"),
        _mk_step(4, thought="再确认没有垃圾字节", action="ssh_exec",
                 action_input='{"cmd": "xxd"}', observation="xxd hex dump"),
    ]
    res = coord._check_solved_not_submitted(recent)
    assert res != "", "CH8 场景应触发已解出未提交"
    assert "flag{junk_c0d3_h1d3s_in_pl41n_s1ght}" in res
    print("[PASS] 已解出未提交检测 (CH8)")


def test_solved_not_submitted_no_false_positive():
    """正常场景: 只是收集线索 (无完整 flag), 不触发."""
    from ctf_agent.agent.coordinator import Coordinator
    coord = Coordinator(llm=None, style="aggressive", bus=_FakeBus())
    recent = [
        _mk_step(1, thought="先看文件类型", action="file_type",
                 action_input='{"text": "a.exe"}', observation="PE32+ executable"),
        _mk_step(2, thought="看字符串", action="strings",
                 action_input='{"cmd": "strings"}', observation="Hello, World!"),
        _mk_step(3, thought="再看入口", action="objdump",
                 action_input='{"cmd": "objdump"}', observation="entry 0x140001000"),
    ]
    res = coord._check_solved_not_submitted(recent)
    assert res == "", "无完整 flag 不应触发"
    print("[PASS] 已解出未提交无误报")


def test_solved_not_submitted_already_submitting():
    """已提交中 (有 Final Answer), 不重复干预."""
    from ctf_agent.agent.coordinator import Coordinator
    coord = Coordinator(llm=None, style="aggressive", bus=_FakeBus())
    recent = [
        _mk_step(1, thought="解出 flag", action="strings", action_input='{}',
                 observation="flag{f0ll0w_th3_c4ll_gr4ph}"),
        _mk_step(2, thought="提交", action="final_answer", action_input="",
                 observation="", final_answer="flag{f0ll0w_th3_c4ll_gr4ph}"),
    ]
    res = coord._check_solved_not_submitted(recent)
    assert res == "", "已有提交意图不重复干预"
    print("[PASS] 已提交中不重复干预")


def test_solved_not_submitted_unverified_guide():
    """CH8 核心: 已拼出 flag 候选但从未程序验证 (未 verified) → 引导运行验证/提交."""
    from ctf_agent.agent.coordinator import Coordinator
    coord = Coordinator(llm=None, style="aggressive", bus=_FakeBus())
    recent = [
        _mk_step(1, thought="片段 flag{jun", action="strings", action_input='{"cmd": "strings"}',
                 observation="flag{junH nk_c0d3"),
        _mk_step(2, thought="movabs", action="objdump", action_input='{"cmd": "objdump"}',
                 observation="movabs rax, 0x6e756a7b67616c66"),
        _mk_step(3, thought="完整 flag = flag{junk_c0d3_h1d3s_in_pl41n_s1ght}, 但拼接有重叠疑义 (junnk)",
                 action="ssh_exec", action_input='{"cmd": "objdump -d"}',
                 observation="movabs rax, 0x336430635f6b6e"),
        _mk_step(4, thought="再确认段2", action="objdump", action_input='{"cmd": "objdump -d"}',
                 observation="movabs rax, 0x695f73336431685f"),
    ]
    res = coord._check_solved_not_submitted(recent)
    assert res != "", "未验证但已拼出候选也应触发"
    assert "运行程序验证" in res or "提交" in res
    assert "junnk" in res  # 提示中应解释 movabs 边界重叠问题
    print("[PASS] 未验证已拼出候选 → 引导运行验证/提交")


if __name__ == "__main__":
    test_hex_source_reverse()
    test_program_verify_exempt()
    test_program_verify_self_scripted_still_rejected()
    test_rejected_softlock()
    test_concatenated_flag_ch8()
    test_hallucination_still_rejected()
    test_solved_not_submitted_ch8()
    test_solved_not_submitted_no_false_positive()
    test_solved_not_submitted_already_submitting()
    test_solved_not_submitted_unverified_guide()
    print("\n=== 全部 Sprint 37 测试通过 ===")
