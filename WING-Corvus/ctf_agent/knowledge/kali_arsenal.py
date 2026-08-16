"""Kali 工具兵器谱 (Arsenal).

目标：让 CTF Agent 在解题前就"清晰地知道 Kali 中有哪些工具、什么情况用、
具体怎么用"，而不是靠盲目试探。这里以结构化数据描述每个工具的：
- 名称 / 所属方向 (web/pwn/reverse/crypto/misc/recon)
- when: 什么情况下使用（触发场景）
- how: 具体命令用法（可直接经 ssh_exec / ssh_python 执行）
- note: 常见坑与技巧

`format_arsenal()` 将其渲染为紧凑文本，注入 system prompt（默认聚焦 web/pwn，
因为这是当前工具覆盖的短板；可按题目类型裁剪，避免 prompt 臃肿）。

设计要点：
- Kali 中大量工具没有必要为每个都封装成 Tool；对它们最有效的方式是让
  agent 通过 ssh_exec 直接调用，但前提是 agent 知道命令怎么写。本兵器谱正是
  为此提供"命令级"知识。
- 高频、参数复杂、易错的工具（gobuster/sqlmap/pwntools 交互等）另有专用
  Tool 封装（见 web_tool.py / pwn_tool.py），本表标注 wrapped=True。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KaliTool:
    """一个 Kali 工具的结构化知识条目."""

    name: str
    category: str  # web / pwn / reverse / crypto / misc / recon
    when: str  # 什么情况用
    how: str  # 具体命令（可含多行）
    note: str = ""  # 坑/技巧
    wrapped: bool = False  # 是否已有专用 Tool 封装


# ============ WEB ============
_WEB: list[KaliTool] = [
    KaliTool(
        name="whatweb",
        category="web",
        when="拿到 web 题第一步：指纹识别（框架/CMS/语言/中间件/版本）。",
        how="whatweb -a3 http://TARGET:PORT/",
        note="据指纹选后续方向：Flask→SSTI，PHP→LFI/反序列化，Node→原型链。",
        wrapped=True,
    ),
    KaliTool(
        name="gobuster",
        category="web",
        when="需要发现隐藏目录 / 文件 / 备份 / 后台入口。",
        how=(
            "gobuster dir -u http://TARGET/ -w /usr/share/wordlists/dirb/common.txt "
            "-x php,txt,zip,bak,old -t 40 -q"
        ),
        note="常见泄露：/backup /admin /.git /robots.txt .bak .swp；先跑 common.txt 再上大字典。",
        wrapped=True,
    ),
    KaliTool(
        name="ffuf",
        category="web",
        when="更快的目录/参数/子域 fuzz；需要过滤响应或 fuzz 任意位置（FUZZ 占位符）。",
        how=(
            "ffuf -u http://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 ; "
            "ffuf -u 'http://TARGET/?FUZZ=1' -w params.txt -fs 0   # fuzz 参数名"
        ),
        note="-fs/-fc/-fw 过滤大小/状态码/词数，用于剔除统一的错误页。",
        wrapped=True,
    ),
    KaliTool(
        name="sqlmap",
        category="web",
        when="怀疑 SQL 注入（登录框/搜索/id 参数/报错含 SQL）。",
        how=(
            "sqlmap -u 'http://TARGET/?id=1' --batch --level 3 --risk 2 --dbs ; "
            "sqlmap -r req.txt --batch --dump   # req.txt 为抓包保存的完整请求"
        ),
        note="POST/带 cookie 时用 -r 保存请求文件最稳；--flush-session 清缓存重测。",
        wrapped=True,
    ),
    KaliTool(
        name="nikto",
        category="web",
        when="快速扫已知漏洞/敏感文件/配置错误（补充 gobuster）。",
        how="nikto -h http://TARGET:PORT/",
        note="噪音大，用于快速盘点线索，不作为唯一依据。",
    ),
    KaliTool(
        name="nuclei",
        category="web",
        when="用社区模板批量检测已知 CVE / 常见漏洞模式。",
        how="nuclei -u http://TARGET/ -severity medium,high,critical",
        note="模板需最新；离线沙箱可能无法更新模板库，此时改用手工验证。",
    ),
    KaliTool(
        name="wfuzz",
        category="web",
        when="爆破参数值、Cookie、隐藏字段；需要对 payload 做编码变换。",
        how="wfuzz -c -z file,/usr/share/wordlists/rockyou.txt -d 'user=admin&pass=FUZZ' http://TARGET/login",
        note="--hh 隐藏指定字符数响应，用于定位成功登录的差异。",
    ),
    KaliTool(
        name="tplmap",
        category="web",
        when="确认/利用 SSTI（模板注入，输入 {{7*7}} 回显 49 时）。",
        how="tplmap -u 'http://TARGET/?name=*' ; 或手工：Flask/Jinja2 用 {{config}}、{{''.__class__.__mro__}} 链 RCE。",
        note="识别引擎：Jinja2({{7*7}}=49) vs Twig vs Freemarker，payload 各不同。",
    ),
    KaliTool(
        name="jwt_tool",
        category="web",
        when="出现 JWT（eyJ... 三段式 token），测试 alg=none / 弱密钥 / 篡改。",
        how="jwt_tool <token> -X a  # alg:none 绕过 ; jwt_tool <token> -C -d rockyou.txt  # 爆破 HS256 密钥",
        note="常见考点：alg none、把 RS256 降级 HS256 用公钥当密钥、弱 secret。",
    ),
    KaliTool(
        name="curl",
        category="web",
        when="精确构造请求：改 header/method/cookie、测 SSRF/LFI/命令注入、看原始响应。",
        how=(
            "curl -s -i http://TARGET/ ; "
            "curl -s 'http://TARGET/?file=../../../../etc/passwd' ; "
            "curl -s -X POST -d 'cmd=id' http://TARGET/exec"
        ),
        note="比浏览器更适合脚本化验证；-i 看响应头，--path-as-is 保留 ../。",
    ),
    KaliTool(
        name="hydra",
        category="web",
        when="需要爆破登录（http-form/basic-auth/ssh/ftp 等）。",
        how="hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect'",
        note="F= 后填登录失败的特征字符串；CTF 中账号常是 admin/guest。",
    ),
]

# ============ PWN ============
_PWN: list[KaliTool] = [
    KaliTool(
        name="checksec",
        category="pwn",
        when="拿到 pwn 二进制第一步：查看保护机制决定利用手法。",
        how="checksec --file=./chall   (或 pwn checksec ./chall)",
        note="NX 开→ROP/ret2libc；无 Canary→栈溢出改返回；PIE→需泄露基址；RELRO 影响 GOT 改写。",
        wrapped=True,
    ),
    KaliTool(
        name="pwntools",
        category="pwn",
        when="编写利用脚本：本地/远程交互、打包地址、构造 payload。",
        how=(
            "from pwn import *\n"
            "context.binary=e=ELF('./chall')\n"
            "p=remote('127.0.0.1',1337)  # 或 process('./chall')\n"
            "p.sendlineafter(b'>', payload)\n"
            "p.interactive()"
        ),
        note="p64/p32 打包、cyclic 找偏移、ELF/ROP 自动化；context.log_level='debug' 排错。",
        wrapped=True,
    ),
    KaliTool(
        name="cyclic",
        category="pwn",
        when="确定栈溢出返回地址覆盖偏移量。",
        how="cyclic 200  # 生成 ; 崩溃后取 RSP/EIP 值 cyclic -l 0x6161616c 得偏移",
        note="64 位崩溃看 RSP 里的值（cyclic -l -n 8）；配合 gdb 看崩溃现场。",
        wrapped=True,
    ),
    KaliTool(
        name="ROPgadget",
        category="pwn",
        when="构造 ROP 链：找 pop rdi/ret、syscall、/bin/sh 字符串。",
        how="ROPgadget --binary ./chall --only 'pop|ret' ; ROPgadget --binary ./chall --string '/bin/sh'",
        note="ret2libc 常用链：pop rdi; ret -> /bin/sh -> system；栈对齐加一个 ret。",
        wrapped=True,
    ),
    KaliTool(
        name="one_gadget",
        category="pwn",
        when="已知 libc 基址，想一步 getshell（免构造 system 参数）。",
        how="one_gadget /path/to/libc.so.6  # 得到若干偏移及其约束条件",
        note="需满足约束（如 [rsp+0x..]==NULL）；不满足就换 gadget 或走 system。",
    ),
    KaliTool(
        name="gdb-peda/pwndbg",
        category="pwn",
        when="动态调试：看崩溃、堆布局、寄存器、内存。",
        how="gdb ./chall ; 常用：b *main+X, r, c, x/40gx $rsp, heap, bins, telescope",
        note="pwndbg 的 heap/bins 命令对堆题极关键；vmmap 看段权限与基址。",
    ),
    KaliTool(
        name="libc-database",
        category="pwn",
        when="泄露某函数地址后，识别远程 libc 版本以算基址/偏移。",
        how="./find printf 0xXXX  # 用泄露的低 12 位匹配 libc 版本",
        note="离线沙箱可用本地已知 libc；确认版本后用 ELF('libc').symbols 算偏移。",
    ),
    KaliTool(
        name="patchelf",
        category="pwn",
        when="本地用题目给定 libc 复现（替换动态链接器与 libc）。",
        how="patchelf --set-interpreter ./ld.so --replace-needed libc.so.6 ./libc.so.6 ./chall",
        note="确保本地环境与远程 libc 一致，否则偏移对不上。",
    ),
]

# ============ RECON（通用侦查，web/pwn 都用） ============
_RECON: list[KaliTool] = [
    KaliTool(
        name="nmap",
        category="recon",
        when="题目给 IP:PORT 或需发现开放服务时。",
        how="nmap -sV -sC -p- TARGET --min-rate 2000",
        note="-sV 识别服务版本，-sC 跑默认脚本；CTF 动态题服务常在题面给定端口。",
    ),
    KaliTool(
        name="nc (netcat)",
        category="recon",
        when="与 tcp 服务原始交互（pwn/misc 网络题快速试探协议）。",
        how="nc TARGET 1337  ; echo -e 'payload' | nc TARGET 1337",
        note="沙箱若无 nc，用 python3 socket 或 pwntools remote() 替代。",
    ),
]

ARSENAL: list[KaliTool] = [*_WEB, *_PWN, *_RECON]

# 每个方向的"决策流"总纲，帮助 agent 选工具而非乱试。
_PLAYBOOK: dict[str, str] = {
    "web": (
        "WEB 决策流: whatweb 指纹 -> gobuster/ffuf 找入口 -> 据指纹定向: "
        "SQL 报错→sqlmap; 模板回显({{7*7}})→SSTI; file/path 参数→LFI/../; "
        "JWT→jwt_tool; 上传点→绕过后缀+马; 反序列化→构造 gadget。"
        "优先用 curl 精确验证漏洞，再用专用工具批量利用。"
    ),
    "pwn": (
        "PWN 决策流: file+checksec 看保护 -> 逆向找漏洞(溢出/fmt/UAF/off-by-one) "
        "-> cyclic 定偏移 -> 据保护选手法(无canary栈溢出/NX→ROP/ret2libc/"
        "堆题tcache) -> pwntools 写 exp 打 remote(127.0.0.1:1337) -> "
        "泄露libc→算基址→getshell→cat flag。"
    ),
}


def list_categories() -> list[str]:
    """返回兵器谱中出现的所有方向."""
    return sorted({t.category for t in ARSENAL})


def format_arsenal(
    categories: list[str] | None = None,
    *,
    include_playbook: bool = True,
    only_unwrapped: bool = False,
) -> str:
    """渲染兵器谱为注入 prompt 的紧凑文本.

    Args:
        categories: 只渲染这些方向（如 ["web", "pwn", "recon"]）。None=全部。
        include_playbook: 是否包含每个方向的决策流总纲。
        only_unwrapped: 只列没有专用 Tool 封装的工具（避免与工具 schema 重复）。

    Returns:
        markdown 文本；无匹配时返回空串。
    """
    cats = categories or list_categories()
    cats = [c.lower() for c in cats]
    selected = [
        t
        for t in ARSENAL
        if t.category in cats and (not only_unwrapped or not t.wrapped)
    ]
    if not selected:
        return ""

    lines: list[str] = ["# Kali 兵器谱（当前环境可用工具：何时用 + 怎么用）"]
    for cat in cats:
        cat_tools = [t for t in selected if t.category == cat]
        if not cat_tools:
            continue
        lines.append(f"\n## [{cat.upper()}]")
        if include_playbook and cat in _PLAYBOOK:
            lines.append(f"- 决策流: {_PLAYBOOK[cat]}")
        for t in cat_tools:
            tag = " (已封装为专用工具)" if t.wrapped else ""
            how_oneline = t.how.replace("\n", " ⏎ ")
            entry = f"- **{t.name}**{tag}: 何时→{t.when} 用法→`{how_oneline}`"
            if t.note:
                entry += f" 注意→{t.note}"
            lines.append(entry)
    return "\n".join(lines)


__all__ = [
    "ARSENAL",
    "KaliTool",
    "format_arsenal",
    "list_categories",
]
