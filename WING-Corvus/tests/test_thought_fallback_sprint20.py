"""Sprint 20: Thought 回退机制验证."""
from ctf_agent.agent.react import parse_llm_output


def test_thought_fallback_no_prefix():
    """无 Thought: 前缀时, 回退捕获 Action: 前的文本作为 thought."""
    r = parse_llm_output("我需要先检查文件\nAction: ssh_exec\nAction Input: {\"command\": \"ls\"}")
    assert r.thought == "我需要先检查文件", f"Expected thought, got [{r.thought}]"
    assert r.action == "ssh_exec"
    assert r.is_valid


def test_thought_with_prefix_unchanged():
    """有 Thought: 前缀时, 正常解析 (不破坏现有行为)."""
    r = parse_llm_output("Thought: 分析中\nAction: ssh_exec\nAction Input: {\"command\": \"ls\"}")
    assert r.thought == "分析中"
    assert r.action == "ssh_exec"
    assert r.is_valid


def test_thought_empty_when_only_action():
    """纯 Action 无前置文本时, thought 为空 (不误抓)."""
    r = parse_llm_output("Action: ssh_exec\nAction Input: {\"command\": \"ls\"}")
    assert r.thought == ""
    assert r.action == "ssh_exec"
    assert r.is_valid


def test_thought_fallback_final_answer():
    """Final Answer 无 Thought 前缀时, 回退捕获前置文本."""
    r = parse_llm_output("flag 找到了\nFinal Answer: athena{test}")
    assert r.thought == "flag 找到了"
    assert r.is_final
    assert r.final_answer == "athena{test}"
