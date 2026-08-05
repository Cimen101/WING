"""本地密码学工具集（：CRYPTO 方向工具层补齐）.

设计目标：为 CRYPTO 类题目提供"随手可用、纯 Python、无需 Kali/SSH"的解题助手，
覆盖绝大多数中低难度 RSA 题与经典编码题。所有实现零重依赖（仅标准库；factordb
走网络时可选依赖 requests，缺失自动降级）。

包含两个一级 Agent 工具：
- crypto_rsa   : RSA 一把梭（factordb / 共模数公因子 GCD / Fermat 近素数 /
                 Pollard rho 小因子 / 小 e 直接开方 / 共模攻击 / Wiener 小私钥），
                 恢复出 p,q,d 后解密 c，尝试还原明文/flag。
- crypto_classic: 经典编码/古典密码一把梭（多层自动解码 base64/base32/hex/rot/
                 atbash/morse + 单字节 XOR 爆破），自动识别 flag 特征。

安全：工具只做"计算辅助"，不联网提交 flag；输出会截断，避免污染上下文。
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from typing import Any

from ctf_agent.tools.base import Tool

_MAX_OUTPUT = 4000
_FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[^}]{1,200}\}")


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n... (输出截断, 共 {len(text)} 字符)"


def _to_int(v: Any) -> int | None:
    """把 int / 十进制字符串 / 0x 十六进制字符串统一解析为 int."""
    if v is None or v == "":
        return None
    if isinstance(v, int):
        return v
    s = str(v).strip().replace("_", "").replace(" ", "")
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s)
    except ValueError:
        try:
            return int(s, 16)
        except ValueError:
            return None


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def _invmod(a: int, m: int) -> int | None:
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        return None
    return x % m


def _iroot(x: int, n: int) -> tuple[int, bool]:
    """整数 n 次方根；返回 (root, is_exact)."""
    if x < 0:
        return 0, False
    if x == 0:
        return 0, True
    if n == 1:
        return x, True
    # 二分求根，避免浮点误差
    lo, hi = 0, 1 << ((x.bit_length() // n) + 2)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid**n < x:
            lo = mid + 1
        else:
            hi = mid
    # lo 可能略大，回退校验
    for r in (lo - 1, lo, lo + 1):
        if r >= 0 and r**n == x:
            return r, True
    return lo, False


def _long_to_bytes(n: int) -> bytes:
    if n <= 0:
        return b""
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _decode_plaintext(m: int) -> str:
    """把明文整数转字节并尝试可读化，附带 flag 检测."""
    raw = _long_to_bytes(m)
    txt = ""
    try:
        txt = raw.decode("utf-8")
    except UnicodeDecodeError:
        txt = raw.decode("latin-1", errors="replace")
    flag = _FLAG_RE.search(txt)
    lines = [f"m(int) = {m}", f"m(bytes) = {raw!r}"]
    if txt.isprintable() or flag:
        lines.append(f"m(text) = {txt}")
    if flag:
        lines.append(f"[!] 发现疑似 flag: {flag.group(0)}")
    return "\n".join(lines)


# ============ RSA 分解策略 ============

def _fermat(n: int, max_iter: int = 200000) -> tuple[int, int] | None:
    """Fermat 分解：适用于 p、q 相近的情形."""
    a, _exact = _iroot(n, 2)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        if b2 >= 0:
            b, exact = _iroot(b2, 2)
            if exact:
                return a - b, a + b
        a += 1
    return None


def _pollard_rho(n: int, max_iter: int = 500000) -> int | None:
    """Pollard rho：适用于存在较小因子的情形."""
    if n % 2 == 0:
        return 2
    x, y, c, d = 2, 2, 1, 1
    for _ in range(max_iter):
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = math.gcd(abs(x - y), n)
        if d != 1:
            return d if d != n else None
    return None


def _factordb(n: int) -> tuple[int, int] | None:
    """查询 factordb.com（可选，需 requests + 网络；失败静默降级）."""
    try:
        import requests  # type: ignore
    except ImportError:
        return None
    try:
        r = requests.get(
            f"http://factordb.com/api?query={n}", timeout=8
        )
        data = r.json()
        factors = data.get("factors", [])
        primes: list[int] = []
        for f, cnt in factors:
            primes.extend([int(f)] * int(cnt))
        if len(primes) == 2 and primes[0] * primes[1] == n:
            return primes[0], primes[1]
        if len(primes) >= 2 and math.prod(primes) == n:
            # 多因子：合并成两半（仍可算 phi）
            return primes[0], n // primes[0]
    except Exception:  # noqa: BLE001
        return None
    return None


def _decrypt_with_pq(n: int, e: int, c: int, p: int, q: int) -> str | None:
    phi = (p - 1) * (q - 1)
    d = _invmod(e, phi)
    if d is None:
        return None
    m = pow(c, d, n)
    return _decode_plaintext(m)


def _wiener(n: int, e: int) -> int | None:
    """Wiener 攻击：小私钥 d 时通过连分数恢复 d."""
    def contfrac(a: int, b: int) -> list[int]:
        out = []
        while b:
            out.append(a // b)
            a, b = b, a % b
        return out

    def convergents(cf: list[int]):
        n0, n1 = 0, 1
        d0, d1 = 1, 0
        for a in cf:
            n0, n1 = n1, a * n1 + n0
            d0, d1 = d1, a * d1 + d0
            yield n0, d0

    cf = contfrac(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # 解 x^2 - (n - phi + 1) x + n = 0
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        s, exact = _iroot(disc, 2)
        if exact and (b + s) % 2 == 0:
            return d
    return None


class CryptoRSATool(Tool):
    """RSA 一把梭：多策略分解 + 解密，覆盖中低难度 RSA 题."""

    name = "crypto_rsa"
    description = (
        "RSA 攻击一把梭（纯本地，无需 Kali）。给定 n,e,c 自动尝试："
        "factordb 查询、共模数公因子(传 n_list)、Fermat 近素数分解、"
        "Pollard rho 小因子、小 e 直接开方、共模攻击(传 e2,c2)、Wiener 小私钥；"
        "已知 p,q 或 d 时直接解密。恢复明文并检测 flag。"
        "整数可用十进制或 0x 十六进制字符串。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "n": {"type": "string", "description": "模数 N（十进制或 0x 十六进制）"},
            "e": {"type": "string", "description": "公钥指数 e，默认 65537"},
            "c": {"type": "string", "description": "密文 c（整数）"},
            "p": {"type": "string", "description": "已知素因子 p（可选）"},
            "q": {"type": "string", "description": "已知素因子 q（可选）"},
            "d": {"type": "string", "description": "已知私钥 d（可选，直接解密）"},
            "n_list": {
                "type": "array",
                "items": {"type": "string"},
                "description": "多个模数（共模数公因子攻击，两两求 GCD）",
            },
            "e2": {"type": "string", "description": "共模攻击第二个指数 e2"},
            "c2": {"type": "string", "description": "共模攻击第二个密文 c2"},
        },
    }

    def execute(self, **kwargs: Any) -> str:
        n = _to_int(kwargs.get("n"))
        e = _to_int(kwargs.get("e")) or 65537
        c = _to_int(kwargs.get("c"))
        p = _to_int(kwargs.get("p"))
        q = _to_int(kwargs.get("q"))
        d = _to_int(kwargs.get("d"))
        report: list[str] = []

        # 0) 共模数公因子攻击（多个 N 共享素数）
        n_list_raw = kwargs.get("n_list") or []
        n_list = [x for x in (_to_int(v) for v in n_list_raw) if x]
        if n is not None and n_list:
            for other in n_list:
                if other == n:
                    continue
                g = math.gcd(n, other)
                if 1 < g < n:
                    p, q = g, n // g
                    report.append(f"[公因子] 与另一模数 GCD={g} 命中，分解成功")
                    break

        # 1) 已知 d 直接解密
        if n is not None and c is not None and d is not None:
            m = pow(c, d, n)
            return _truncate("[已知 d 解密]\n" + _decode_plaintext(m))

        # 2) 已知 p,q 解密
        if n is None and p is not None and q is not None:
            n = p * q
        if p is not None and q is not None and c is not None:
            out = _decrypt_with_pq(p * q, e, c, p, q)
            if out:
                return _truncate("[已知 p,q 解密]\n" + out)

        # 3) 共模攻击（同 n，不同 e1,e2）
        e2 = _to_int(kwargs.get("e2"))
        c2 = _to_int(kwargs.get("c2"))
        if n is not None and c is not None and e2 and c2 is not None:
            g, a, b = _egcd(e, e2)
            if g == 1:
                m1 = pow(c, a, n) if a >= 0 else pow(_invmod(c, n) or 1, -a, n)
                m2 = pow(c2, b, n) if b >= 0 else pow(_invmod(c2, n) or 1, -b, n)
                m = (m1 * m2) % n
                return _truncate("[共模攻击]\n" + _decode_plaintext(m))
            report.append(f"[共模攻击] gcd(e,e2)={g}≠1，跳过")

        # 4) 小 e 直接开方（c = m^e，未取模回绕）
        if n is not None and c is not None and e <= 10:
            for k in range(0, 20000):
                root, exact = _iroot(c + k * n, e)
                if exact:
                    report.append(f"[小e开方] c+{k}*n 开 {e} 次方精确命中")
                    return _truncate(
                        "\n".join(report) + "\n" + _decode_plaintext(root)
                    )
            report.append(f"[小e开方] e={e} 未在 20000*N 内命中")

        # 5) 若尚无 p,q，尝试自动分解
        if n is not None and (p is None or q is None):
            strategies = [
                ("factordb", lambda: _factordb(n)),
                ("Fermat", lambda: _fermat(n)),
                ("Pollard-rho", lambda: (
                    (lambda f: (f, n // f) if f else None)(_pollard_rho(n))
                )),
            ]
            for sname, fn in strategies:
                try:
                    res = fn()
                except Exception:  # noqa: BLE001
                    res = None
                if res and res[0] * res[1] == n and 1 < res[0] < n:
                    p, q = res
                    report.append(f"[{sname}] 分解成功: p={p}")
                    break
                report.append(f"[{sname}] 未命中")

        # 6) 分解成功则解密
        if p is not None and q is not None and c is not None and n is not None:
            out = _decrypt_with_pq(n, e, c, p, q)
            if out:
                return _truncate(
                    "\n".join(report) + "\n[解密]\n" + out
                )

        # 7) Wiener（大 e、小 d）
        if n is not None and e > 1 and (p is None or q is None):
            dw = _wiener(n, e)
            if dw is not None:
                report.append(f"[Wiener] 恢复小私钥 d={dw}")
                if c is not None:
                    m = pow(c, dw, n)
                    return _truncate(
                        "\n".join(report) + "\n" + _decode_plaintext(m)
                    )
            else:
                report.append("[Wiener] 未命中（d 非足够小）")

        if not report:
            return "ERROR: 参数不足，至少提供 n,e,c 或 p,q,c 或 d,n,c"
        report.append(
            "未直接得到明文。可尝试：提供更多已知量、"
            "改用 sage_tools 处理 hard 格攻击、或人工分析特殊结构。"
        )
        return _truncate("\n".join(report))


# ============ 经典编码 / 古典密码 ============

_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}


def _rotn(s: str, n: int) -> str:
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + n) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + n) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def _atbash(s: str) -> str:
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr(219 - ord(ch)))
        elif "A" <= ch <= "Z":
            out.append(chr(155 - ord(ch)))
        else:
            out.append(ch)
    return "".join(out)


def _try_morse(s: str) -> str | None:
    toks = re.split(r"[/\s]+", s.strip())
    if not toks or any(set(t) - {".", "-"} for t in toks if t):
        return None
    dec = "".join(_MORSE.get(t, "?") for t in toks if t)
    return dec if dec and "?" not in dec else None


class ClassicCipherTool(Tool):
    """经典编码/古典密码一把梭：多层自动解码 + 单字节 XOR 爆破."""

    name = "crypto_classic"
    description = (
        "经典编码/古典密码一把梭（纯本地）。对输入自动尝试：base64/base32/"
        "hex 解码、ROT-N(含 rot13)/Atbash、Morse 电码、单字节 XOR 爆破，"
        "并检测 flag 特征（xxx{...}）。适合古典密码/多层编码题开局。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "data": {"type": "string", "description": "待解码的字符串（密文/编码）"},
            "flag_prefix": {
                "type": "string",
                "description": "flag 前缀提示（如 flag、athena），用于优先命中",
            },
        },
        "required": ["data"],
    }

    def execute(self, **kwargs: Any) -> str:
        data = kwargs.get("data")
        if not data:
            return "ERROR: 需要提供 data"
        prefix = (kwargs.get("flag_prefix") or "").lower()
        s = str(data).strip()
        hits: list[str] = []

        def _check(label: str, text: str) -> None:
            if not text:
                return
            m = _FLAG_RE.search(text)
            interesting = bool(m) or (
                prefix and prefix in text.lower()
            )
            printable = sum(c.isprintable() for c in text) / max(len(text), 1)
            if interesting or printable > 0.9:
                snippet = text if len(text) <= 200 else text[:200] + "..."
                flag_note = f"  <== flag: {m.group(0)}" if m else ""
                hits.append(f"[{label}] {snippet}{flag_note}")

        # base64
        try:
            _check("base64", base64.b64decode(s + "==", validate=False).decode(
                "utf-8", errors="replace"))
        except (binascii.Error, ValueError):
            pass
        # base32
        try:
            pad = s.upper() + "=" * ((8 - len(s) % 8) % 8)
            _check("base32", base64.b32decode(pad, casefold=True).decode(
                "utf-8", errors="replace"))
        except (binascii.Error, ValueError):
            pass
        # hex
        try:
            hs = re.sub(r"[^0-9a-fA-F]", "", s)
            if hs and len(hs) % 2 == 0:
                _check("hex", bytes.fromhex(hs).decode("utf-8", errors="replace"))
        except ValueError:
            pass
        # ROT-N 全表
        for n in range(1, 26):
            _check(f"rot{n}", _rotn(s, n))
        # Atbash
        _check("atbash", _atbash(s))
        # Morse
        mo = _try_morse(s)
        if mo:
            _check("morse", mo)
        # 单字节 XOR 爆破（对 hex 或原文字节）
        raw: bytes | None = None
        try:
            hs = re.sub(r"[^0-9a-fA-F]", "", s)
            if hs and len(hs) % 2 == 0:
                raw = bytes.fromhex(hs)
        except ValueError:
            raw = None
        if raw is None:
            raw = s.encode("latin-1", errors="ignore")
        for key in range(256):
            dec = bytes(b ^ key for b in raw)
            try:
                txt = dec.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if _FLAG_RE.search(txt) or (prefix and prefix in txt.lower()):
                _check(f"xor(0x{key:02x})", txt)

        if not hits:
            return (
                "未发现明显可读结果或 flag。原文可能是多层嵌套/需密钥的密码，"
                "可将疑似中间结果再次投喂本工具，或改用 sage_tools/自定义脚本。"
            )
        # 去重保序
        seen = set()
        uniq = []
        for h in hits:
            if h not in seen:
                seen.add(h)
                uniq.append(h)
        return _truncate("候选解码结果:\n" + "\n".join(uniq))


def crypto_tools() -> list[Tool]:
    """返回本地密码学工具集（无需 ssh_client）."""
    return [CryptoRSATool(), ClassicCipherTool()]


__all__ = ["CryptoRSATool", "ClassicCipherTool", "crypto_tools"]
