"""靶场题库清单（基于 data/repos/athena-ctf-2026-challs）.

- dynamic=True：依赖服务器/二进制运行环境，需部署到 Kali（web/pwn/infra/crypto 等）
- dynamic=False：静态题，附件本地分析即可，无需靶场

端口编排：动态题映射到 Kali 宿主机 8001-8014（避开 1337 与常见服务端口），
容器内统一监听 1337（与现有 Dockerfile EXPOSE 一致）。
"""
from __future__ import annotations

from pathlib import Path
from typing import TypedDict


# 题库仓库根目录
REPO_ROOT = (
    Path(__file__).resolve().parent.parent.parent
    / "data"
    / "repos"
    / "athena-ctf-2026-challs"
)


class ChallengeSpec(TypedDict):
    name: str
    category: str
    dynamic: bool
    host_port: int          # 仅 dynamic=True 使用
    container_port: int     # 题目容器内端口（默认 1337）
    notes: str


# ---- 14 道动态题（需部署靶场）----
DYNAMIC: list[ChallengeSpec] = [
    {"name": "Echo_Chamber", "category": "web", "dynamic": True, "host_port": 8001, "container_port": 1337, "notes": "Flask SSTI 模板注入"},
    {"name": "Meridian_Ladder", "category": "web", "dynamic": True, "host_port": 8002, "container_port": 1337, "notes": "Node.js 债券阶梯 robo-advisor：取 /static/app.js.map 源码，审计 PATCH /api/preferences 的 deepMerge（原型污染/业务逻辑），unwind house reserve 阶梯获取 flag"},
    {"name": "Session_Slip", "category": "web", "dynamic": True, "host_port": 8003, "container_port": 1337, "notes": "会话/反序列化"},
    {"name": "API_Relay", "category": "infra", "dynamic": True, "host_port": 8004, "container_port": 1337, "notes": "TCP 中继：客户端发 |host|port|（5 段，首末占位）头，服务端双向转发到目标；拦截 127.0.0.1/localhost/0.0.0.0（SSRF 防护）。绕过：域名解析到本地、IPv6 [::1]、十进制/八进制 IP 等访问内网服务拿 flag"},
    {"name": "Query_Mirage", "category": "infra", "dynamic": True, "host_port": 8005, "container_port": 1337, "notes": "Flask search_notes 用 f-string 拼接 LIKE '%term%' 注入点；拦截 空格/--/# ；用 /**/ 替代空格做 UNION 注入从库中取 flag"},
    {"name": "Upload_Lantern", "category": "infra", "dynamic": True, "host_port": 8006, "container_port": 1337, "notes": "文件上传/预览(HTTP)：legacy sanitize_filename 只去 / 不去 \\，resolve_production_path 按 Windows 以 \\ 为分隔符且 .. 回退栈 → 用反斜杠 ..\\ 做路径穿越读取 private/ 或上层 flag；GET /view?name= 触发"},
    {"name": "Net_Custom_Protocol", "category": "infra", "dynamic": True, "host_port": 8007, "container_port": 1337, "notes": "自定义 CMD|LEN|PAYLOAD 文本协议(以 \\n 分隔帧)：ECHO 把 payload 前32字节与 secret(flag) 拼接后按攻击者 LEN 返回 memory[:LEN]；令 LEN 超过32即越界读泄露 secret。用 raw socket 交互"},
    {"name": "Net_MITM_TLS", "category": "infra", "dynamic": True, "host_port": 8008, "container_port": 1337, "notes": "client 以 CERT_NONE(不校验证书) 连接 net-mitm.local:4443，校验 peer 证书 CN==net-mitm.local 后把 flag 以 HTTP POST /submit 发出；攻击:伪造 CN=net-mitm.local 的自签证书做 TLS MITM 中间人，截获 POST 体中的 flag"},
    {"name": "Heap_Smash_v1", "category": "pwn", "dynamic": True, "host_port": 8009, "container_port": 1337, "notes": "flag 读入堆块后 free 进 tcache（唯一可回收入口）；创建同尺寸块(80B/0x60 bin)回收该 freed chunk 再 read 即泄露 flag（tcache reclaim / 堆块复用）"},
    {"name": "Classy_who", "category": "pwn", "dynamic": True, "host_port": 8010, "container_port": 1337, "notes": "TCP 菜单 note 服务(RC's note service)：命令格式 `C <idx> <size>` 建、`W <idx> <off> <len>` 写(读 len 字节到 data+off，**offset 无边界检查=>越界堆写**)、`R <idx>` 读(输出 data 前 min(size,1024) 字节)、`D <idx>` 删(free data+struct 但**不置空 notes[idx]=>UAF/悬垂指针**)、`E` 退出。**flag 在 main 栈上 local_flag[256]，不在堆块**。利用：UAF 悬垂的 struct 仍含 data 指针，用另一块的越界写 `W` 覆盖该 struct 的 data 指针指向栈上 flag 地址，再 `R <idx>` 泄露；或用 UAF 改 size/指针做任意读写。务必先用 checksec+file_read/strings/hex_dump 确认保护(PIE/RELRO/canary)与栈布局再写 pwntools，勿盲试浪费步数"},
    {"name": "Fast_is_need", "category": "pwn", "dynamic": True, "host_port": 8011, "container_port": 1337, "notes": "note 服务：show() 用 printf(用户数据) 存在格式化字符串漏洞可泄露；delete 释放后不置空 data 指针(used=0) 形成 UAF/双重释放；菜单 create/edit/show/delete/list。结合格式化字符串泄露地址 + UAF 利用取 flag"},
    {"name": "Padding_Oracle_(RSA)", "category": "crypto", "dynamic": True, "host_port": 8012, "container_port": 1337, "notes": "RSA 填充预言机：has_valid_padding 校验 pt[0]==0x00 且 pt[1]==secret t；用 valid/invalid 响应逐字节恢复明文(经典 padding oracle 攻击) 得 flag"},
    {"name": "Narrow_DES", "category": "crypto", "dynamic": True, "host_port": 8013, "container_port": 1337, "notes": "DES 弱密钥"},
    {"name": "Operation_OUROBOROS", "category": "misc", "dynamic": True, "host_port": 8014, "container_port": 1337, "notes": "超长多阶段链式(15+关)：握手XOR(0xAA)→迷宫(BFS)→LFI(百分号解码绕过..过滤)→SQLi(空格过滤 UNION)→JWT(alg:none)→pwn(ret2win:64B栈缓冲读512,无PIE/canary)→TOCTOU竞争→LSB隐写(PGM)→重复密钥XOR(已知banner)→逆向字节码VM→命令注入→SSRF→沙箱逃逸(eval)→噪声预言机→DSA nonce复用→拼合4个shard+oracle值得 flag；注意 decoy flag 干扰，按正确路径逐关收集 shard"},
]

# ---- 18 道静态题（本地分析，无需靶场）----
_STATIC_NAMES = [
    "Cipher_Chorus", "CrackMe_2025", "CrackMe_v2", "CrackMe_v3", "ESP_Morse",
    "Forensic_Flame", "Locked_Safe", "Logic_Lock", "MCP_Mischief", "Morse_Mystery",
    "Pixel_Puzzle", "QR_Quest", "Reverse_Riddle", "Scroll_Sage", "Stego_Shadow",
    "Symbol_Sleuth", "Timing_Trap", "USB_Whisper",
]
STATIC: list[ChallengeSpec] = [
    {"name": n, "category": "static", "dynamic": False, "host_port": 0, "container_port": 0, "notes": "静态题（本地分析）"}
    for n in _STATIC_NAMES
]

ALL: list[ChallengeSpec] = DYNAMIC + STATIC


def _slug(name: str) -> str:
    """容器名/镜像名合法化（去掉空格与括号）."""
    return name.replace(" ", "_").replace("(", "").replace(")", "")


def container_name(spec: ChallengeSpec) -> str:
    """靶场容器名（统一 athena_ 前缀小写，便于安全审计识别；Docker tag 必须小写）."""
    return f"athena_{_slug(spec['name'])}".lower()


def image_name(spec: ChallengeSpec) -> str:
    return container_name(spec)


def by_name(name: str) -> ChallengeSpec | None:
    for c in ALL:
        if c["name"] == name or _slug(c["name"]) == name:
            return c
    return None


def dynamic_challenges() -> list[ChallengeSpec]:
    return [c for c in ALL if c["dynamic"]]


def local_container_dir(spec: ChallengeSpec) -> Path:
    """题目本地 container 目录（用于上传到 Kali 构建镜像）."""
    return REPO_ROOT / spec["name"] / "container"


__all__ = [
    "REPO_ROOT", "ChallengeSpec", "DYNAMIC", "STATIC", "ALL",
    "container_name", "image_name", "by_name", "dynamic_challenges",
    "local_container_dir",
]
