"""WEB 利用工具集（L2.5，基于 Kali）.

补齐 WEB 方向短板。设计原则（依据用户诉求）：
- WEB 题以 Kali 现成工具为主，但把"高频、参数复杂、易错"的调用封装成
  参数清晰的 Tool，让 agent 不必记忆冗长命令行、也不会写错关键参数。
- 每个工具的 description 明确说明"何时用"，与 kali_arsenal 决策流呼应。
- 底层统一走 SSHClient 在 Kali 内执行，超时/输出截断沿用 ssh_tool 约定。

工具列表：
- WebFingerprintTool  (whatweb): 指纹识别，web 题第一步
- WebDirScanTool      (gobuster/ffuf): 目录/文件爆破
- SqlmapTool          (sqlmap): SQL 注入检测与利用
- WebReconTool        : 组合侦查（指纹+常见敏感路径快速探测），一步给全景
"""

from __future__ import annotations

from typing import Any

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool

_MAX_OUTPUT = 8000


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n... (输出截断，共 {len(text)} 字符)"


class _KaliBackedTool(Tool):
    """共享 SSHClient 执行逻辑的基类."""

    def __init__(
        self,
        ssh_client: SSHClient,
        *,
        default_timeout: int = 120,
        max_timeout: int = 600,
        cwd: str = "/tmp/ctf_workspace/",
    ) -> None:
        self.ssh_client = ssh_client
        self.default_timeout = default_timeout
        self.max_timeout = max_timeout
        self.cwd = cwd

    def _run(self, command: str, timeout: int | None = None) -> str:
        eff = min(timeout or self.default_timeout, self.max_timeout)
        result = self.ssh_client.exec_cmd(command, cwd=self.cwd, timeout=eff)
        parts = [f"$ {command}", f"[exit_code={result.exit_code}, elapsed={result.elapsed:.2f}s]"]
        if result.stdout:
            parts.append(_truncate(result.stdout))
        if result.stderr:
            parts.append(f"[stderr]\n{_truncate(result.stderr, 2000)}")
        if not result.stdout and not result.stderr:
            parts.append("(无输出)")
        out = "\n".join(parts)
        if result.exit_code not in (0, None):
            # 很多 web 工具非 0 退出仍有有效结果，不强制标 ERROR，仅提示
            out = f"[命令退出码 {result.exit_code}，结果可能仍有效]\n{out}"
        return out


class WebFingerprintTool(_KaliBackedTool):
    """whatweb 指纹识别."""

    name = "web_fingerprint"
    description = (
        "【WEB 第一步】用 whatweb 识别目标 web 服务的指纹（框架/CMS/语言/中间件/版本）。"
        "拿到 web 题先跑它，据结果决定方向：Flask/Jinja2→SSTI，PHP→LFI/反序列化，"
        "Node→原型链，含数据库报错→SQLi。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "目标 URL，如 http://127.0.0.1:1337/"},
        },
        "required": ["url"],
    }

    def execute(self, url: str, **_: Any) -> str:
        if not url or not url.strip():
            return "ERROR: url 不能为空"
        return self._run(f"whatweb -a3 --color=never '{url}'", timeout=60)


class WebDirScanTool(_KaliBackedTool):
    """gobuster / ffuf 目录爆破."""

    name = "web_dirscan"
    description = (
        "【WEB 找入口】爆破隐藏目录/文件/备份/后台（gobuster 优先，可选 ffuf）。"
        "常见泄露：/admin /backup /.git /robots.txt 及 .bak/.old/.zip 备份。"
        "指纹识别后用它扩大攻击面。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "目标基址，如 http://127.0.0.1:1337/"},
            "wordlist": {
                "type": "string",
                "description": "字典路径，默认 /usr/share/wordlists/dirb/common.txt",
            },
            "extensions": {
                "type": "string",
                "description": "追加爆破的后缀，逗号分隔，如 'php,txt,zip,bak'。默认 php,txt,zip,bak,old",
            },
            "engine": {"type": "string", "description": "gobuster(默认) 或 ffuf"},
        },
        "required": ["url"],
    }

    def execute(
        self,
        url: str,
        wordlist: str | None = None,
        extensions: str | None = None,
        engine: str = "gobuster",
        **_: Any,
    ) -> str:
        if not url or not url.strip():
            return "ERROR: url 不能为空"
        wl = wordlist or "/usr/share/wordlists/dirb/common.txt"
        exts = extensions or "php,txt,zip,bak,old"
        if engine == "ffuf":
            base = url.rstrip("/") + "/FUZZ"
            cmd = f"ffuf -u '{base}' -w {wl} -mc 200,204,301,302,307,401,403 -e .{',.'.join(exts.split(','))} -s"
        else:
            cmd = (
                f"gobuster dir -u '{url}' -w {wl} -x {exts} -t 40 -q "
                f"--no-error --timeout 10s"
            )
        return self._run(cmd, timeout=180)


class SqlmapTool(_KaliBackedTool):
    """sqlmap SQL 注入检测与利用."""

    name = "sqlmap"
    description = (
        "【WEB SQL 注入】用 sqlmap 自动检测并利用 SQL 注入（登录框/搜索/id 参数/出现 SQL 报错时）。"
        "支持直接给 URL，或给保存的原始请求文件（POST/带 cookie 时更稳）。"
        "action 决定动作：detect(仅检测)/dbs(列库)/dump(拖数据)。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "注入点 URL，如 http://T/?id=1（与 request_file 二选一）"},
            "request_file": {
                "type": "string",
                "description": "Kali 上保存的原始 HTTP 请求文件路径（-r），适合 POST/带 header",
            },
            "action": {
                "type": "string",
                "description": "detect(默认,仅探测) / dbs(列数据库) / tables / dump(拖全部数据)",
            },
            "extra": {"type": "string", "description": "追加的 sqlmap 参数，如 '-D ctf -T flags'"},
        },
    }

    def execute(
        self,
        url: str | None = None,
        request_file: str | None = None,
        action: str = "detect",
        extra: str | None = None,
        **_: Any,
    ) -> str:
        if not url and not request_file:
            return "ERROR: 必须提供 url 或 request_file 之一"
        target = f"-u '{url}'" if url else f"-r '{request_file}'"
        act_map = {
            "detect": "",
            "dbs": "--dbs",
            "tables": "--tables",
            "dump": "--dump",
        }
        act = act_map.get(action, "")
        extra_s = f" {extra}" if extra else ""
        cmd = (
            f"sqlmap {target} --batch --level 3 --risk 2 "
            f"--random-agent --flush-session {act}{extra_s}"
        )
        return self._run(cmd, timeout=300)


class WebReconTool(_KaliBackedTool):
    """一步式 web 侦查：指纹 + 常见敏感路径快速探测."""

    name = "web_recon"
    description = (
        "【WEB 全景侦查·推荐首选】一步完成：whatweb 指纹 + 探测一批高频敏感路径"
        "(/robots.txt /.git/HEAD /admin /backup.zip /flag 等) + 首页响应头。"
        "适合 web 题开局快速建立全景，再据结果选 sqlmap/SSTI/LFI 等定向手法。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "目标基址，如 http://127.0.0.1:1337/"},
        },
        "required": ["url"],
    }

    _PROBES = [
        "robots.txt",
        ".git/HEAD",
        ".env",
        "admin",
        "admin/",
        "login",
        "backup.zip",
        "backup.tar.gz",
        "www.zip",
        "flag",
        "flag.txt",
        "index.php.bak",
        "phpinfo.php",
        "api/",
        "console",
    ]

    def execute(self, url: str, **_: Any) -> str:
        if not url or not url.strip():
            return "ERROR: url 不能为空"
        base = url.rstrip("/")
        # 组合成一个 shell 脚本一次执行，减少往返
        probe_cmds = " ; ".join(
            f"echo -n '[{p}] ' ; curl -s -o /dev/null -w '%{{http_code}} %{{size_download}}B' '{base}/{p}' ; echo"
            for p in self._PROBES
        )
        cmd = (
            f"echo '=== whatweb ===' ; whatweb -a1 --color=never '{url}' 2>/dev/null ; "
            f"echo ; echo '=== headers ===' ; curl -s -I '{url}' ; "
            f"echo ; echo '=== path probes (code size) ===' ; {probe_cmds}"
        )
        return self._run(cmd, timeout=90)


class WebSqliTool(_KaliBackedTool):
    """v5: 专用 SQL 注入工具 (CTF 优化版).

    比 sqlmap 更简化的接口, 自动处理空格过滤/注释符/UNION 注入等 CTF 常见场景.
    遇到 SQL 报错、搜索框、id 参数时优先使用此工具.
    """

    name = "web_sqli"
    description = (
        "【CTF SQL 注入专用】自动检测并利用 SQL 注入漏洞."
        "遇到搜索框、URL 参数、SQL 报错时优先使用此工具."
        "支持两种模式: detect(检测) / inject(SQL 语句执行)."
        "自动处理空格过滤 (/**/ 替代空格) 等 CTF 常见 bypass."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "注入点 URL，如 http://T/?q=test"},
            "method": {
                "type": "string",
                "enum": ["get", "post"],
                "description": "HTTP 方法, 默认 GET",
            },
            "mode": {
                "type": "string",
                "enum": ["detect", "dbs", "tables", "dump"],
                "description": "detect(检测) / dbs(列库) / tables(列表) / dump(拖数据)",
            },
            "data": {
                "type": "string",
                "description": "POST body, 如 'user=admin&pass=1'",
            },
        },
        "required": ["url"],
    }

    def execute(
        self,
        url: str,
        method: str = "get",
        mode: str = "detect",
        data: str | None = None,
        **_: Any,
    ) -> str:
        if method == "post" and data:
            target = f"-u '{url}' --data '{data}'"
        else:
            target = f"-u '{url}'"

        act_map = {
            "detect": "",
            "dbs": "--dbs",
            "tables": "--tables --exclude-sysdbs",
            "dump": "--dump --exclude-sysdbs",
        }
        act = act_map.get(mode, "")
        # CTF 优化参数: level/risk 适中, 随机 UA, 空格 bypass
        cmd = (
            f"sqlmap {target} --batch --level 3 --risk 2 "
            f"--random-agent --flush-session --tamper=space2comment "
            f"{act} --time-sec 5"
        )
        return self._run(cmd, timeout=120)


def web_tools(ssh_client: SSHClient) -> list[Tool]:
    """创建 WEB 工具集（需要 Kali SSHClient）."""
    return [
        WebReconTool(ssh_client),
        WebFingerprintTool(ssh_client),
        WebDirScanTool(ssh_client),
        SqlmapTool(ssh_client),
        WebSqliTool(ssh_client),  # v5: CTF SQL 注入专用
    ]


__all__ = [
    "WebFingerprintTool",
    "WebDirScanTool",
    "SqlmapTool",
    "WebReconTool",
    "WebSqliTool",
    "web_tools",
]
