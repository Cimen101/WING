"""L2 SSH 工具层（L5 工具层）.

依据 README §3.2，封装 SSH-Kali 命令执行为 Tool 接口。
当 Kali 配置可用时，通过 ssh_tools(ssh_client) 工厂创建基于该连接的工具集，
自动加入 default_tools()。

工具列表：
- SSHExecTool: 通用 SSH 命令执行（最灵活，LLM 可执行任意 Kali 命令）
- SSHPythonTool: 在 Kali 上执行 Python 脚本（用于 crypto/pwn 复杂逻辑）

设计原则：
- 工作目录默认 /tmp/ctf_workspace/（沙箱隔离）
- 默认超时 60s，可配置
- 输出截断避免污染上下文
- 命令审计日志（后续阶段实现）
"""

from __future__ import annotations

from typing import Any

from ctf_agent.ssh import SSHClient
from ctf_agent.ssh.safety import (  # 加固
    DangerLevel,
    audit_command,
    audit_workspace,
)
from ctf_agent.tools.base import Tool


# 输出截断阈值（避免超长输出污染 LLM 上下文）
_MAX_OUTPUT = 8000
_TRUNCATED_SUFFIX = "\n... (输出截断，共 {total} 字符)"


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    """截断过长输出."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + _TRUNCATED_SUFFIX.format(total=len(text))


# ============ 长任务超时转后台 (B+ 方案) ============
# 背景: ssh_exec/ssh_python 的同步调用在长任务 (exploit 运行/本地验证/爆破)
# 上会阻塞 LLM 数分钟. 方案: 命令经 nohup 后台运行 + 日志文件轮询,
# 超过等待窗口后自动"转后台", 立即返回 PID + 日志路径, LLM 可继续做别的,
# 再用 ssh_exec 'cat <日志>' 随时取结果. 命令只执行一次, 不重复执行.
# - timeout 参数: 语义档位 quick/normal/long/background 或整数秒数
# - 未声明/格式错误 → 120s 自动兜底 (与 normal 档位一致)
_BG_DIR = "/tmp/ctf_workspace/.bg"          # 后台任务目录 (日志/脚本/pid 集中存放)
_TIMEOUT_BANDS = {"quick": 30, "normal": 120, "long": 600}
_DEFAULT_WAIT = 120                          # 未声明时的自动兜底等待 (s)
_MAX_SYNC_WAIT = 600                         # 同步等待上限 (s), 对应原 max_timeout
_BG_CLIENT_BUFFER = 40                       # 客户端 exec_cmd 超时缓冲 (轮询尾差)
_BG_TAIL_CHARS = 2000                        # 转后台时返回的部分输出长度

# 后台运行结果标记 (脚本输出前缀, 客户端解析用)
_BG_FINISHED = "[BG_FINISHED]"               # 等待窗口内完成 → 日志全文在标记后
_BG_RUNNING = "[BG_STILL_RUNNING]"           # 超时仍在跑 → 已转后台
_BG_STARTED = "[BG_STARTED]"                 # background 档位 → 立即转后台


def _resolve_timeout(value: Any) -> int:
    """解析 timeout 参数 → 同步等待秒数.

    - None / 格式错误      → 120 (自动兜底)
    - int                 → 秒数 (1~600)
    - str 档位            → quick=30 / normal=120 / long=600 / background=0
    - str 秒数 (如 "180") → 180
    返回 0 表示立即转后台 (background 档位).
    """
    if value is None:
        return _DEFAULT_WAIT
    if isinstance(value, bool):  # bool 是 int 子类, 单独拦截
        return _DEFAULT_WAIT
    if isinstance(value, int):
        return max(1, min(value, _MAX_SYNC_WAIT))
    if isinstance(value, str):
        s = value.strip().lower()
        if s == "background":
            return 0
        if s in _TIMEOUT_BANDS:
            return _TIMEOUT_BANDS[s]
        try:
            return max(1, min(int(s), _MAX_SYNC_WAIT))
        except ValueError:
            return _DEFAULT_WAIT
    return _DEFAULT_WAIT


def _build_bg_script(
    payload_b64: str,
    cwd: str,
    wait_sec: int,
    runner: str,
) -> str:
    """构造"后台执行 + 轮询"的 Kali 端 shell 脚本.

    Args:
        payload_b64: 要执行的命令/脚本的 base64 (避免引号转义问题)
        cwd: 工作目录 (脚本内 cd 过去)
        wait_sec: 同步等待秒数, 0 = 立即转后台
        runner: 启动方式模板, 含 {f} 占位 (脚本文件路径)
            e.g. "sh {f}" / "python3 {f}"
    Returns:
        完整 shell 脚本 (客户端用 exec_cmd 一次执行, timeout=wait_sec+缓冲)
    """
    import random
    import time

    name = f"bg_{time.time_ns()}_{random.randint(0, 9999)}"
    script_f = f"{_BG_DIR}/{name}"
    log_f = f"{_BG_DIR}/{name}.log"
    lines = [
        f"mkdir -p {_BG_DIR}",
        f"echo {payload_b64} | base64 -d > {script_f}",
        f"cd {cwd} 2>/dev/null || true",
        f"nohup {runner.format(f=script_f)} > {log_f} 2>&1 &",
        "PID=$!",
    ]
    if wait_sec <= 0:
        lines += [
            f'echo "{_BG_STARTED} pid=$PID"',
            f'echo "[BG_LOG={log_f}]"',
        ]
    else:
        lines += [
            f"for i in $(seq 1 {wait_sec}); do",
            "  kill -0 $PID 2>/dev/null || break",
            "  sleep 1",
            "done",
            "if kill -0 $PID 2>/dev/null; then",
            f'  echo "{_BG_RUNNING} pid=$PID"',
            f'  echo "[BG_LOG={log_f}]"',
            '  echo "[BG_TAIL]:"',
            f"  tail -c {_BG_TAIL_CHARS} {log_f} 2>/dev/null || true",
            "else",
            "  wait $PID 2>/dev/null",
            f'  echo "{_BG_FINISHED} rc=$?"',
            f"  cat {log_f} 2>/dev/null || true",
            "fi",
        ]
    return "\n".join(lines)


def _parse_bg_output(result: Any, command: str, wait_sec: int) -> str | None:
    """解析后台执行结果, 构造 LLM 可见输出.

    Returns:
        构造好的输出字符串; 无后台标记 (异常路径) 时返回 None, 由调用方回退原逻辑.
    """
    stdout = result.stdout or ""
    for m in (_BG_FINISHED, _BG_RUNNING, _BG_STARTED):
        if m in stdout:
            break
    else:
        return None

    marker = next(m for m in (_BG_FINISHED, _BG_RUNNING, _BG_STARTED) if m in stdout)
    parts: list[str] = [f"$ {command}"]

    if marker == _BG_FINISHED:
        log_text = stdout.split(_BG_FINISHED, 1)[-1].strip()
        parts.append(f"[完成, 同步等待 {wait_sec}s 内结束, elapsed={result.elapsed:.2f}s]")
        if log_text:
            parts.append(_truncate(log_text))
        else:
            parts.append("(无输出)")
    else:
        status_txt = (
            "命令已转入后台运行 (超过等待窗口, 进程仍在执行)"
            if marker == _BG_RUNNING
            else "命令已立即转入后台运行 (background 档位)"
        )
        parts.append(f"⚠️ {status_txt}")
        for line in stdout.splitlines():
            if line.startswith(_BG_RUNNING) or line.startswith(_BG_STARTED):
                parts.append(f"  {line.strip()}")
            elif line.startswith("[BG_LOG="):
                parts.append(f"  {line.strip()}")
        parts.append("  查看结果: 用 ssh_exec 'cat <日志文件>' 获取完整输出")
        parts.append("  终止任务: 用 ssh_exec 'kill <PID>'")
        if "[BG_TAIL]:" in stdout:
            tail_part = stdout.split("[BG_TAIL]:", 1)[-1].strip()
            if tail_part:
                parts.append("  当前部分输出 (等待窗口内):")
                parts.append(_truncate(tail_part, _BG_TAIL_CHARS))
    return "\n".join(parts)


# ============ 环境降级检测 ============
# 当 agent 在沙箱中尝试 docker build / 启动服务失败时，自动注入降级提示，
# 引导 agent 切换到"静态分析源码"模式（避免反复重试 docker 卡死 30 分钟）。
# 匹配关键词（大小写不敏感）：
# 所有 .* 改为 .{0,300} (有界长度) — 嵌套 .* 交替在长输出上
# 会灾难性回溯 (CPU 100% 死锁), 有界量词保证最坏回溯 O(300*n) 毫秒级完成.
_ENV_DEGRADATION_PATTERNS: list[tuple[str, str, str]] = [
    # (匹配关键词, 触发条件描述, 降级建议)
    (
        r"docker[:\s].{0,300}not found|/bin/sh.{0,300}docker.{0,300}not found",
        "Kali 沙箱未安装 docker",
        "无法使用 docker build/run。请改为静态分析源码：\n"
        "  - 用 cat/head/less 读 app.py/server.py/ctf.c 等源文件\n"
        "  - 用 strings/objdump 读二进制\n"
        "  - 用 python3 直接运行 .py 脚本（无容器）",
    ),
    (
        r"Cannot connect to the Docker daemon",
        "Docker daemon 未运行",
        "Docker daemon 未启动。请改为静态分析源码，不要再尝试 docker 命令。",
    ),
    (
        r"(?:Connection refused|connect.{0,300}refused).{0,300}1337|.{0,300}1337.{0,300}(?:Connection refused|connect.{0,300}refused)",
        "动态服务未启动（端口 1337 不可达）",
        "服务未在 1337 端口启动。请检查：\n"
        "  1. 是否漏掉 docker build + run 步骤？\n"
        "  2. 改用静态分析：读 server.py/app.py/ctf.c 等源文件，推理协议/逻辑",
    ),
    (
        r"(?:redis-cli|mysql|nc).{0,300}command not found|command not found.{0,300}(?:redis-cli|mysql|nc)",
        "动态题依赖工具缺失",
        "依赖的 client 工具未安装。请用 python3 -c 替代：\n"
        "  - redis: pip install redis 后用 python3 操作\n"
        "  - 网络: 用 python3 socket 或 pwntools remote()",
    ),
]


def _detect_env_degradation(
    command: str, stdout: str, stderr: str, exit_code: int
) -> str | None:
    """检测环境降级信号，返回降级建议.

    只在命令失败（exit_code != 0）时触发，避免误报。
    返回 None 表示无降级需求。

    修复: 长输出导致正则灾难性回溯 (CPU 100% 卡死).
    _ENV_DEGRADATION_PATTERNS 含嵌套 .* 交替, 对超大 stdout (hexdump 等)
    会指数级回溯. 现在截断检测输入: stdout/stderr 只取尾部 4000/2000 字符,
    环境降级信号 (command not found 等) 都出现在输出尾部, 截断不影响检测.
    """
    if exit_code == 0:
        return None
    # 截断防止灾难性回溯 (输入 ≤7KB, 最坏回溯 ~50M 次, 毫秒级完成)
    combined = f"{stdout[-4000:]}\n{stderr[-2000:]}\n{command[-1000:]}"
    import re
    for pattern, condition, advice in _ENV_DEGRADATION_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return f"⚠️ 环境降级检测: {condition}\n💡 建议: {advice}"
    return None


class SSHExecTool(Tool):
    """通用 SSH 命令执行工具.

    在 Kali 沙箱内执行任意 shell 命令。用于 nmap/gobuster/strings/objdump/
    file/xxd/binwalk/steghide 等所有 Kali 系统工具。

    安全策略（依据 README §3.1.3）：
    - 工作目录限制在 /tmp/ctf_workspace/（可通过 cwd 参数指定子目录）
    - 默认超时 60s，最长 600s
    - 命令在 root 权限下执行（Kali 沙箱内）
    """

    name = "ssh_exec"
    description = (
        "在 Kali Linux 沙箱内执行任意 shell 命令（如 nmap/strings/objdump/file/"
        "xxd/binwalk/steghide/gobuster/sqlmap 等）。"
        "适用于需要 Linux 环境的 CTF 工具调用。\n"
        "超时控制: timeout 支持语义档位 quick(30s)/normal(120s)/long(600s)/"
        "background(立即后台) 或整数秒数。超过等待窗口命令自动转入后台运行,"
        "工具立即返回 PID 和日志文件路径, 用 ssh_exec 'cat <日志>' 随时查看结果。"
        "长任务 (exploit 运行/爆破/本地验证) 建议设 timeout=long 或 background,"
        "不要死等; 快速命令 (ls/cat/file) 用默认或 quick。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "要执行的 shell 命令（如 'nmap -p 80 192.168.1.1'）",
            },
            "cwd": {
                "type": "string",
                "description": "工作目录（默认 /tmp/ctf_workspace/）",
            },
            "timeout": {
                "type": ["integer", "string"],
                "description": "超时控制: 整数秒数 (如 180) 或档位 "
                    "quick=30s / normal=120s(默认) / long=600s / background=立即后台。"
                    "超过等待窗口命令自动转后台运行 (不杀进程), 返回 PID+日志路径, "
                    "用 ssh_exec 'cat <日志>' 查看结果。",
            },
        },
        "required": ["command"],
    }

    def __init__(
        self,
        ssh_client: SSHClient,
        *,
        default_cwd: str = "/tmp/ctf_workspace/",
        default_timeout: int = 60,
        max_timeout: int = 600,
    ) -> None:
        self.ssh_client = ssh_client
        self.default_cwd = default_cwd
        self.default_timeout = default_timeout
        self.max_timeout = max_timeout

    def execute(
        self,
        command: str,
        cwd: str | None = None,
        timeout: Any = None,
        **_: Any,
    ) -> str:
        if not command or not command.strip():
            return "ERROR: command 不能为空"

        effective_cwd = cwd or self.default_cwd
        # timeout 支持语义档位/秒数, 0 = 立即转后台
        wait_sec = _resolve_timeout(timeout)

        # 加固：先审计工作目录（白名单）
        ws_audit = audit_workspace(effective_cwd)
        if not ws_audit.allowed:
            return (
                f"ERROR: 工作目录审计失败 - {ws_audit.description}\n"
                f"  允许的工作区: /tmp/ctf_workspace/, /tmp/ctf_real2/, /tmp/ctf_real3/"
            )

        # 加固：审计命令（危险黑名单）
        cmd_audit = audit_command(command)
        if not cmd_audit.allowed:
            return (
                f"ERROR: 命令被安全审计拒绝 - {cmd_audit.description}\n"
                f"  匹配模式: {cmd_audit.pattern_matched}\n"
                f"  如确需执行，请人工 review 后从 SSH 直接操作。"
            )
        if cmd_audit.danger_level == DangerLevel.REQUIRE_JUDGE:
            # 中危：仅警告（架构预留：未来接入 LLM judge）
            cmd_audit_warning = f"⚠️ {cmd_audit.description}\n"
        else:
            cmd_audit_warning = ""

        # 长任务后台执行 — 命令经 nohup 后台运行 + 轮询等待,
        # 超过等待窗口自动转后台 (不杀进程), 命令只执行一次.
        import base64
        payload_b64 = base64.b64encode(command.encode("utf-8")).decode("ascii")
        bg_script = _build_bg_script(
            payload_b64, effective_cwd, wait_sec, runner="sh {f}"
        )
        client_timeout = (
            max(15, wait_sec + _BG_CLIENT_BUFFER) if wait_sec > 0 else 20
        )
        result = self.ssh_client.exec_cmd(
            bg_script,
            cwd=effective_cwd,
            timeout=client_timeout,
        )

        # 构造输出
        parts: list[str] = []
        if cmd_audit_warning:
            parts.append(cmd_audit_warning.rstrip())

        bg_output = _parse_bg_output(result, command, wait_sec)
        if bg_output is not None:
            output = "\n".join(parts + [bg_output]) if parts else bg_output
        else:
            # 无后台标记 (异常路径, 如 exec_cmd 自身超时被强杀) → 回退原逻辑
            parts.append(f"$ {command}")
            parts.append(f"[exit_code={result.exit_code}, elapsed={result.elapsed:.2f}s]")
            if result.stdout:
                parts.append(_truncate(result.stdout))
            if result.stderr:
                parts.append(f"[stderr]\n{_truncate(result.stderr)}")
            if not result.stdout and not result.stderr:
                parts.append("(无输出)")
            output = "\n".join(parts)
            # 错误命令标注（便于 LLM 识别失败）
            if not result.is_success and result.exit_code != 0:
                output = f"ERROR: 命令退出码 {result.exit_code}\n{output}"
            # 环境降级检测（docker 不可用 / 端口不可达）
            # 当 agent 尝试 docker build 或连接动态服务失败时，注入降级建议
            # 引导 agent 切换到"静态分析源码"模式，避免反复重试卡死 30 分钟
            degradation_hint = _detect_env_degradation(
                command, result.stdout, result.stderr, result.exit_code
            )
            if degradation_hint:
                output = f"{output}\n\n{degradation_hint}"
        return output


class SSHPythonTool(Tool):
    """在 Kali 上执行 Python 脚本.

    用于 crypto/pwn 题目需要 pwntools/pycryptodome/z3 等库的复杂逻辑。
    脚本通过 stdin 传入，避免命令行转义问题。
    """

    name = "ssh_python"
    description = (
        "在 Kali Linux 沙箱内执行 Python 3 脚本。"
        "可用库：pwntools (pwn)、pycryptodome (Crypto)、z3、capstone、requests 等。"
        "适用于 crypto 解密、pwn exp 编写、二进制分析等复杂逻辑。\n"
        "超时控制: timeout 支持语义档位 quick(30s)/normal(120s)/long(600s)/"
        "background(立即后台) 或整数秒数。超过等待窗口脚本自动转入后台运行,"
        "工具立即返回 PID 和日志文件路径, 用 ssh_exec 'cat <日志>' 随时查看结果。"
        "长任务 (exploit 交互/爆破/本地验证) 建议设 timeout=long 或 background,"
        "不要死等; 快速计算用默认或 quick。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "script": {
                "type": "string",
                "description": "Python 脚本内容（多行字符串）",
            },
            "timeout": {
                "type": ["integer", "string"],
                "description": "超时控制: 整数秒数 (如 180) 或档位 "
                    "quick=30s / normal=120s(默认) / long=600s / background=立即后台。"
                    "超过等待窗口脚本自动转后台运行 (不杀进程), 返回 PID+日志路径, "
                    "用 ssh_exec 'cat <日志>' 查看结果。",
            },
        },
        "required": ["script"],
    }

    def __init__(
        self,
        ssh_client: SSHClient,
        *,
        default_timeout: int = 60,
        max_timeout: int = 600,
    ) -> None:
        self.ssh_client = ssh_client
        self.default_timeout = default_timeout
        self.max_timeout = max_timeout

    def execute(
        self,
        script: str,
        timeout: Any = None,
        **_: Any,
    ) -> str:
        if not script or not script.strip():
            return "ERROR: script 不能为空"

        # timeout 支持语义档位/秒数, 0 = 立即转后台
        wait_sec = _resolve_timeout(timeout)

        # 脚本 base64 传输 (避免转义问题)
        import base64
        script_b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
        bg_script = _build_bg_script(
            script_b64, "/tmp/ctf_workspace/", wait_sec, runner="python3 {f}"
        )
        client_timeout = (
            max(15, wait_sec + _BG_CLIENT_BUFFER) if wait_sec > 0 else 20
        )
        result = self.ssh_client.exec_cmd(
            bg_script,
            cwd="/tmp/ctf_workspace/",
            timeout=client_timeout,
            env={"TERM": "xterm"},  # 避免 pwntools curses 警告
        )

        bg_output = _parse_bg_output(result, "[ssh_python]", wait_sec)
        if bg_output is not None:
            return bg_output

        # 无后台标记 (异常路径) → 回退原逻辑
        parts: list[str] = []
        parts.append(f"[python3 执行, elapsed={result.elapsed:.2f}s]")
        if result.stdout:
            parts.append(_truncate(result.stdout))
        if result.stderr:
            parts.append(f"[stderr]\n{_truncate(result.stderr)}")
        if not result.stdout and not result.stderr:
            parts.append("(无输出)")

        output = "\n".join(parts)
        if not result.is_success:
            output = f"ERROR: python3 退出码 {result.exit_code}\n{output}"
        return output


class SSHFileUploadTool(Tool):
    """上传本地文件到 Kali 沙箱.

    用于将题目附件（ELF/APK/流量包等）传到 Kali 进行分析。
    """

    name = "ssh_upload"
    description = (
        "上传本地文件到 Kali 沙箱的指定路径。"
        "用于将题目附件（ELF/APK/流量包等）传到 Kali 进行分析。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "local_path": {
                "type": "string",
                "description": "本地文件路径（Windows 路径）",
            },
            "remote_path": {
                "type": "string",
                "description": "远程目标路径（如 /tmp/ctf_workspace/task1/challenge.elf）",
            },
        },
        "required": ["local_path", "remote_path"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh_client = ssh_client

    def execute(
        self,
        local_path: str,
        remote_path: str,
        **_: Any,
    ) -> str:
        try:
            self.ssh_client.upload_file(local_path, remote_path)
            # 验证上传
            result = self.ssh_client.exec_cmd(
                f'ls -la "{remote_path}" && file "{remote_path}"'
            )
            return f"上传成功: {remote_path}\n{result.stdout}"
        except FileNotFoundError as e:
            return f"ERROR: 本地文件不存在: {e}"
        except Exception as e:  # noqa: BLE001
            return f"ERROR: 上传失败: {type(e).__name__}: {e}"


# ============ 工厂 ============

def ssh_tools(
    ssh_client: SSHClient,
    *,
    default_cwd: str = "/tmp/ctf_workspace/",
    default_timeout: int = 60,
) -> list[Tool]:
    """创建基于 SSHClient 的工具集.

    Args:
        ssh_client: 已连接的 SSHClient 实例
        default_cwd: 默认工作目录
        default_timeout: 默认命令超时

    Returns:
        SSH 工具列表（SSHExecTool + SSHPythonTool + SSHFileUploadTool）
    """
    return [
        SSHExecTool(
            ssh_client,
            default_cwd=default_cwd,
            default_timeout=default_timeout,
        ),
        SSHPythonTool(ssh_client, default_timeout=default_timeout),
        SSHFileUploadTool(ssh_client),
    ]


__all__ = [
    "SSHExecTool",
    "SSHFileUploadTool",
    "SSHPythonTool",
    "ssh_tools",
]
