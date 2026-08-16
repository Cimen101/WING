"""S13 协作能力专项单测 (无外部依赖).

覆盖 (本会话新增能力):
1. FileBus 兼容接口 (post_finding/check_findings):
   - 单调递增 seq + 游标增量读取
   - 跨实例 (两次 new FileBus 指向同目录 = 模拟跨进程) 兄弟可见
   - kind/task_id 过滤; 空 content 拒绝
2. 问答闭环 (share_finding kind=question/answer + reply_to):
   - FileBus (跨进程) 与 MessageBus (进程内) 双后端
   - A 提问 → B 看到提问 → B 回答 (reply_to=提问id) → A 看到 回答(答#N)
3. 共享文件工具 (shared_fs_tool):
   - _safe_name 拒绝路径穿越 (../、/abs、\\、空、.)
   - 写/读/列闭环; 64KB 读取截断
4. docker_tool force_reset + shared_dir:
   - force_reset=True: 容器存在也 rm+run (同题重做强制全新环境)
   - force_reset=False: 复用现场 (默认, 不 rm)
   - _run_new 挂载 shared_dir → /shared
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ctf_agent.bus.file_bus import FileBus
from ctf_agent.bus.message_bus import MessageBus
from ctf_agent.tools.bus_tool import bus_tools
from ctf_agent.tools.docker_tool import DockerBackend, DockerClient
from ctf_agent.tools.shared_fs_tool import (
    ReadSharedFileTool,
    WriteSharedFileTool,
    _safe_name,
    shared_fs_tools,
)


# ============ 1. FileBus 兼容接口 (post_finding/check_findings) ============

def test_filebus_post_finding_monotonic_and_cursor(tmp_path: Path) -> None:
    """post_finding 返回全局递增 seq; check_findings 游标只返回新增."""
    bus = FileBus(tmp_path / "bus")
    i1 = bus.post_finding("agent-a", "t1", "first")
    i2 = bus.post_finding("agent-a", "t1", "second")
    assert i1 == 1 and i2 == 2

    entries, cursor = bus.check_findings(0, task_id="t1")
    assert [e.id for e in entries] == [1, 2]
    assert cursor == 2

    bus.post_finding("agent-b", "t1", "third")
    entries, cursor = bus.check_findings(2, task_id="t1")
    assert [e.id for e in entries] == [3]
    assert cursor == 3
    assert entries[0].agent_id == "agent-b"


def test_filebus_cross_instance_incremental(tmp_path: Path) -> None:
    """跨实例 (模拟跨进程): A 进程写 → B 进程 (新 FileBus) 增量读到."""
    bus_dir = tmp_path / "bus"
    bus_a = FileBus(bus_dir)
    bus_a.post_finding("aggressive", "chal-x", "端口 8080 有 admin 面板", kind="fact")

    bus_b = FileBus(bus_dir)  # 新实例 = 新进程
    entries, cursor = bus_b.check_findings(0, task_id="chal-x")
    assert len(entries) == 1
    assert entries[0].content == "端口 8080 有 admin 面板"
    assert entries[0].agent_id == "aggressive"
    assert cursor == 1

    # B 继续增量: 读到 A 又发的一条
    bus_a.post_finding("aggressive", "chal-x", "后台有目录遍历", kind="hint")
    entries, cursor = bus_b.check_findings(cursor, task_id="chal-x")
    assert [e.content for e in entries] == ["后台有目录遍历"]
    assert cursor == 2


def test_filebus_kind_and_task_filter(tmp_path: Path) -> None:
    """check_findings kind/task_id 过滤."""
    bus = FileBus(tmp_path / "bus")
    bus.post_finding("a", "t1", "q?", kind="question")
    bus.post_finding("a", "t1", "ans", kind="answer", reply_to=1)
    bus.post_finding("a", "t2", "t2 秘密", kind="finding")

    q, _ = bus.check_findings(0, task_id="t1", kind="question")
    assert len(q) == 1 and q[0].kind == "question" and q[0].reply_to == 0

    ans, _ = bus.check_findings(0, task_id="t1", kind="answer")
    assert len(ans) == 1 and ans[0].kind == "answer" and ans[0].reply_to == 1

    # t1 看不到 t2 的条目
    all_t1, _ = bus.check_findings(0, task_id="t1")
    assert "t2 秘密" not in [e.content for e in all_t1]


def test_filebus_post_empty_raises(tmp_path: Path) -> None:
    """空 content 拒绝发布 (与 MessageBus.post 一致)."""
    bus = FileBus(tmp_path / "bus")
    with pytest.raises(ValueError):
        bus.post_finding("a", "t1", "   ")


# ============ 2. 问答闭环 (question → answer reply_to) ============

def _qa_roundtrip(share_a, check_a, share_b, check_b, task_id: str) -> None:
    """通用问答闭环断言 (双后端共用)."""
    # A 提问
    out = share_a.execute(content="flag 格式是什么?", task_id=task_id, kind="question")
    assert "已发布问题 #1" in out
    # B 只看提问 → 看到 #1
    out = check_b.execute(task_id=task_id, kind="question")
    assert "提问" in out and "flag 格式是什么?" in out
    # B 回答 (reply_to=1)
    out = share_b.execute(content="athena{...}", task_id=task_id,
                          kind="answer", reply_to=1)
    assert "已发布回答 #2 (回答 #1)" in out
    # A 全量读取 → 看到回答并标注 答#1
    out = check_a.execute(task_id=task_id)
    assert "回答(答#1)" in out and "athena{...}" in out
    assert "#1 [提问]" in out and "#2 [回答(答#1)]" in out


def test_qa_roundtrip_filebus(tmp_path: Path) -> None:
    """FileBus (跨进程) 问答闭环: A 提问 → B 回答 → A 看到 回答(答#1)."""
    bus = FileBus(tmp_path / "bus")
    share_a, check_a = bus_tools(bus, "agent-a")
    share_b, check_b = bus_tools(bus, "agent-b")
    _qa_roundtrip(share_a, check_a, share_b, check_b, "t-qa")


def test_qa_roundtrip_messagebus() -> None:
    """MessageBus (进程内) 问答闭环保持一致."""
    bus = MessageBus()
    share_a, check_a = bus_tools(bus, "agent-a")
    share_b, check_b = bus_tools(bus, "agent-b")
    _qa_roundtrip(share_a, check_a, share_b, check_b, "t-qa")


# ============ 3. 共享文件工具 (shared_fs_tool) ============

def test_safe_name_rejects_path_traversal() -> None:
    """_safe_name 拒绝路径穿越/绝对路径/空名."""
    for bad in ["", " ", "../secret", "/etc/passwd", "a/../b", "a\\b",
                "..", ".", "sub\\file.txt", "C:\\windows\\x"]:
        with pytest.raises(ValueError):
            _safe_name(bad)
    # 合法简单文件名
    assert _safe_name("notes.txt") == "notes.txt"
    assert _safe_name("  flag.txt  ") == "flag.txt"


def test_shared_fs_write_read_list_roundtrip(tmp_path: Path) -> None:
    """写 → 读 → 列 闭环."""
    shared_dir = tmp_path / "share"
    tools = {t.name: t for t in shared_fs_tools(str(shared_dir))}
    assert set(tools) == {"list_shared_files", "read_shared_file", "write_shared_file"}

    out = tools["write_shared_file"].execute(name="solution.py", content="print('hi')")
    assert "已写入共享文件 solution.py" in out

    out = tools["read_shared_file"].execute(name="solution.py")
    assert "print('hi')" in out

    out = tools["list_shared_files"].execute()
    assert "solution.py" in out and "B" in out

    # 读不存在文件 → 明确提示
    out = tools["read_shared_file"].execute(name="nope.txt")
    assert "共享文件不存在" in out

    # 目录为空 → 明确提示
    out = shared_fs_tools(str(tmp_path / "empty"))[0].execute()
    assert "共享目录为空" in out


def test_shared_fs_read_truncates_64kb(tmp_path: Path) -> None:
    """超过 64KB 读取上限 → 截断并提示."""
    shared_dir = tmp_path / "share"
    shared_dir.mkdir()
    big = "x" * (70 * 1024)
    (shared_dir / "big.txt").write_text(big, encoding="utf-8")

    tool = ReadSharedFileTool(str(shared_dir))
    out = tool.execute(name="big.txt")
    assert "超过读取上限" in out and "已截断" in out
    # 截断内容约等于上限
    assert out.count("x") >= 64 * 1024 - 512  # 只截断一次, 不重复


# ============ 4. docker_tool force_reset + shared_dir 挂载 ============

class _RecBackend(DockerBackend):
    """记录调用序列的假后端 (容器已存在且运行)."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def is_available(self) -> bool:
        self.calls.append("is_available")
        return True

    def container_exists(self, name: str) -> bool:
        self.calls.append("container_exists")
        return True

    def container_running(self, name: str) -> bool:
        self.calls.append("container_running")
        return True

    def create_and_start(self, name, image, flags, command) -> bool:
        self.calls.append("create_and_start")
        return True

    def start(self, name: str) -> bool:
        self.calls.append("start")
        return True

    def remove(self, name: str) -> None:
        self.calls.append("remove")

    def inspect_label(self, name: str, key: str) -> str:
        self.calls.append("inspect_label")
        return "t-same"

    def inspect_mounts(self, name: str) -> list[str]:
        self.calls.append("inspect_mounts")
        return []

    def list_exited_ctf_containers(self) -> list[str]:
        return []

    def exec_run(self, args, *, timeout: int):
        self.calls.append("exec_run")
        return MagicMock(returncode=0, stdout="out", stderr="")

    def upload(self, name, local_path, remote_path) -> None:
        self.calls.append("upload")

    def download(self, name, remote_path, local_path) -> None:
        self.calls.append("download")


def test_force_reset_true_removes_and_reruns() -> None:
    """S13: force_reset=True → 容器存在也 rm+run (同题重做强制全新环境)."""
    backend = _RecBackend()
    client = DockerClient(backend=backend, task_id="t-same", force_reset=True)
    assert client.ensure_container("t-same") is True
    # remove 后 create_and_start (新容器); 且未 inspect_label (跳过复用检查)
    assert "remove" in backend.calls
    assert "create_and_start" in backend.calls
    assert "inspect_label" not in backend.calls


def test_force_reset_false_reuses_existing() -> None:
    """S13 默认: force_reset=False → 复用现场 (不 rm, 不重建)."""
    backend = _RecBackend()
    client = DockerClient(backend=backend, task_id="t-same", force_reset=False)
    assert client.ensure_container("t-same") is True
    assert "remove" not in backend.calls
    assert "create_and_start" not in backend.calls


def test_run_new_mounts_shared_dir(tmp_path: Path) -> None:
    """S13: 配置 shared_dir 时 _run_new 挂载宿主目录 → /shared."""
    calls: list[list[str]] = []

    def _fake_run(args, *a, **kw):
        args = list(args)
        calls.append(args)
        if args[1] == "ps":
            return MagicMock(returncode=0, stdout="", stderr="")
        if args[1] == "run":
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("ctf_agent.tools.docker_tool.subprocess.run", _fake_run):
        client = DockerClient(backend="cli", container_name="wing-goose-x",
                              task_id="t-x", shared_dir=str(tmp_path / "share"))
        assert client.ensure_container("t-x") is True

    run_calls = [c for c in calls if c[1] == "run"]
    assert len(run_calls) == 1
    flags = run_calls[0]
    assert "-v" in flags
    mount = flags[flags.index("-v") + 1]
    assert mount.endswith(":/shared:rw")
    # 挂载源目录被自动创建
    assert (tmp_path / "share").is_dir()
