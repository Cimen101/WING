"""测试 ssh.safety 模块 (Sprint 6 加固)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctf_agent.ssh.safety import (
    ALLOWED_WORKSPACES,
    audit_command,
    audit_workspace,
    is_workspace_allowed,
)


def test_workspace_allowed():
    print("--- 工作区白名单 ---")
    for cwd in [
        "/tmp/ctf_workspace/",
        "/tmp/ctf_workspace/abc/",
        "/tmp/ctf_real/",
        "/tmp/ctf_real2/",
        "/tmp/",
        "/tmp/some_task/",
    ]:
        allowed = is_workspace_allowed(cwd)
        print(f"  {cwd:30s} -> {'✓' if allowed else '✗'}")
        assert allowed

    for cwd in [
        "/root/",
        "/etc/",
        "/var/",
        "/home/user/",
        "/tmp/ctf_real/../etc/",  # 路径逃逸
        "../../etc/",
        "/tmp/ctf_real/..",  # 末尾 .. 也算
    ]:
        allowed = is_workspace_allowed(cwd)
        print(f"  {cwd:30s} -> {'✗' if not allowed else '! UNEXPECTED PASS'}")
        assert not allowed
    print("  全部通过 ✓")


def test_danger_commands_blocked():
    print("\n--- 危险命令黑名单（应被 block） ---")
    dangerous = [
        "rm -rf /",
        "rm -rf /*",
        "rm -rf ~",
        "rm -rf /etc",
        "rm -rf /var",
        ":(){ :|:& };:",  # fork bomb
        "dd if=/dev/zero of=/dev/sda bs=1M",
        "mkfs.ext4 /dev/sda1",
        "fdisk /dev/sda",
        "parted /dev/sda",
        "wipefs /dev/sda",
        "shutdown -h now",
        "reboot",
        "halt",
        "poweroff",
        "init 0",
        "init 6",
        "systemctl poweroff",
        "systemctl reboot",
        "iptables -F",
        "nft flush ruleset",
        "userdel -r root",
        "passwd root",
        "docker run --privileged ubuntu bash",
        "docker run --pid=host ubuntu bash",
        "docker run --net=host ubuntu bash",
    ]
    for cmd in dangerous:
        result = audit_command(cmd)
        status = "✓" if not result.allowed else "✗ UNEXPECTED PASS"
        print(f"  [{status}] {cmd:50s} -> {result.danger_level} {result.description[:50]}")
        assert not result.allowed, f"应拒绝但放行: {cmd}"


def test_safe_commands_allowed():
    print("\n--- 安全命令（应通过） ---")
    safe = [
        "ls -la /tmp/ctf_workspace/",
        "python3 solve.py",
        "strings firmware.bin",
        "objdump -d fw.elf",
        "nmap -p 80 192.168.1.1",
        "nc -lvnp 4444",
        "curl http://example.com/flag",
        "echo hello > /tmp/test.txt",
        "cat /tmp/ctf_real/challenge.bin | xxd | head",
    ]
    for cmd in safe:
        result = audit_command(cmd)
        print(f"  [{result.danger_level:6s}] {cmd:50s} -> allowed={result.allowed}")
        assert result.allowed, f"应通过但被拒: {cmd}"


def test_judge_commands():
    print("\n--- 需判决的命令 ---")
    judge_cmds = [
        "nmap --open 192.168.1.0/24",
        "nmap --script vuln 10.0.0.1",
        "hydra -l admin -P pass.txt ssh://192.168.1.1",
        "nc -lvp 4444",
        "chmod 777 /tmp/share",
    ]
    for cmd in judge_cmds:
        result = audit_command(cmd)
        print(f"  [{result.danger_level:6s}] {cmd:50s} -> allowed={result.allowed}")
        assert result.allowed, f"判决类应放行（架构预留）: {cmd}"
        assert result.danger_level == "judge", f"应标记为 judge: {cmd}"


if __name__ == "__main__":
    print("=== ssh.safety 测试 (Sprint 6) ===\n")
    test_workspace_allowed()
    test_danger_commands_blocked()
    test_safe_commands_allowed()
    test_judge_commands()
    print("\n所有测试通过 ✓")
