"""L2 OSINT 网络搜索 + 地理编码工具 (Sprint 12 M3 新增).

为 OSINT 题 (如 Where_am_i) 提供外部知识查询能力:
- WebSearchTool: Yandex 公开搜索端点 (Kali 可达, 但常返回 captcha)
- PhotonGeocodeTool: Photon (komoot.io) 地理编码 (基于 OSM, 公开, 无 key)

Kali 沙箱网络限制 (Sprint 12 M3 实测):
- DuckDuckGo/Google/Wikipedia/Nominatim: 都 timeout 不可用
- Yandex: 200 但常返回 captcha 页面, 大多数场景失败
- Photon (komoot.io): 200 稳定可用, 基于 OSM 数据

设计原则:
- 零外部 API key: 全部用 curl + 公开 HTML/JSON 端点
- 工具自动检测可用性 (Kali 未装 curl 提示降级)
- 输出截断避免 LLM 上下文污染
- 返回结构化结果, 便于 LLM 解析
"""
from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from typing import Any, Optional
from urllib.parse import quote_plus

from ctf_agent.ssh import SSHClient
from ctf_agent.tools.base import Tool


# 输出截断阈值
_MAX_OUTPUT = 4000
_TRUNCATED_SUFFIX = "\n... (输出截断,共 {total} 字符)"


def _truncate(text: str, max_len: int = _MAX_OUTPUT) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + _TRUNCATED_SUFFIX.format(total=len(text))


def _check_tool(ssh: SSHClient, tool_name: str) -> bool:
    """检测 Kali 上工具是否可用."""
    r = ssh.exec_cmd(f"which {tool_name}", timeout=5)
    return r.is_success and tool_name in r.stdout


# ============ PhotonGeocodeTool (替代 Nominatim) ============

class PhotonGeocodeTool(Tool):
    """Photon (komoot.io) 地理编码 (Sprint 12 M3).

    用途: 给定遗址/地名 → 返回 GPS 坐标 (lat, lon, display_name).
    优势: 公开 API, 无 key, 基于 OpenStreetMap 数据, 包含 nature_reserve / petroglyph 等 OSM 类型.
    替换原 Nominatim 方案 (Kali 沙箱中 Nominatim 被防火墙 timeout, Photon 可用).

    典型用例 (Where_am_i 考古遗址定位):
    - osm_geocode('Tamgaly petroglyphs') → 哈萨克斯坦 Tamgaly 坐标
    - osm_geocode('Saimaluu-Tash') → 吉尔吉斯斯坦 Saimaluu-Tash 坐标
    - osm_geocode('petroglyphs Kyrgyzstan') → 多个 OSM petroglyph 节点
    """

    name = "osm_geocode"
    description = (
        "Photon (komoot.io) 地理编码 (公开 API, 基于 OSM, 无 key).\n"
        "用法: osm_geocode(name='Tamgaly petroglyphs', limit=5) → 返回 lat, lon, OSM type.\n"
        "OSINT 题已知遗址名/城市/纪念碑时, 拿 GPS 坐标. 配合 LLM 推理一起用.\n"
        "返回: 多候选 (前 5), 含 (lat, lon, type, display_name, OSM type).\n"
        "支持的 OSM 标签: nature_reserve, tourism=attraction, historic=monument, "
        "leisure=park 等. 对考古遗址 (petroglyphs, cave_painting) 有较好覆盖.\n"
        "速率限制: Photon 公开策略 1 req/s, 不要高频调用.\n"
        "Kali 上 curl 必须可用."
    )
    parameters = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "地名/遗址名/纪念碑名 (英文效果最好, 中文也行)",
            },
            "limit": {
                "type": "integer",
                "description": "返回候选数 (默认 5, 最大 10)",
            },
        },
        "required": ["name"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh = ssh_client
        self._available: Optional[bool] = None

    def _ensure(self) -> str:
        if self._available is None:
            self._available = _check_tool(self.ssh, "curl")
        if not self._available:
            return (
                "ERROR: curl 未在 Kali 上安装.\n"
                "降级方案: apt install curl."
            )
        return ""

    def execute(self, name: str, limit: int = 5, **_: Any) -> str:
        if not name:
            return "ERROR: name 不能为空"
        err = self._ensure()
        if err:
            return err
        n = max(1, min(int(limit), 10))

        encoded = quote_plus(name)
        # Photon 公开 API (komoot.io), 无 key
        url = f"https://photon.komoot.io/api/?q={encoded}&limit={n}"
        cmd = (
            f"curl -sSL --max-time 10 -A 'CTF-Agent/1.0 (research)' "
            f"'{url}' 2>&1"
        )
        r = self.ssh.exec_cmd(cmd, timeout=15)
        raw = r.stdout or ""
        if not raw or "timed out" in raw.lower() or not raw.strip().startswith("{"):
            return (
                f"osm_geocode 网络失败: name='{name}'\n"
                f"原始: {raw[:200]}\n"
                f"提示: Photon 偶尔 timeout, 重试或换地名 (英/中文)."
            )

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            return f"osm_geocode JSON 解析失败: {e}\n原始: {raw[:300]}"

        features = data.get("features", [])
        if not features:
            return f"osm_geocode 无匹配: name='{name}'\n提示: 换英文/原文/简化关键词."

        # 格式化输出
        lines: list[str] = [f"=== osm_geocode 结果 (name='{name}') ==="]
        for i, feat in enumerate(features, 1):
            geom = feat.get("geometry", {})
            coords = geom.get("coordinates", ["?", "?"])
            lon, lat = coords[0], coords[1]  # GeoJSON 是 [lon, lat]
            props = feat.get("properties", {})
            name_v = props.get("name", "?")
            osm_key = props.get("osm_key", "?")
            osm_value = props.get("osm_value", "?")
            type_v = props.get("type", "?")
            country = props.get("country", "?")
            state = props.get("state", "")
            county = props.get("county", "")
            display = (
                f"{name_v} ({osm_key}={osm_value}, type={type_v}, {country}"
                + (f", {state}" if state else "")
                + (f", {county}" if county else "")
                + ")"
            )
            lines.append(f"\n[{i}] ({lat}, {lon})")
            lines.append(f"    {display[:200]}")
        return _truncate("\n".join(lines))


# ============ WebSearchTool (Yandex 公开端点) ============

class _YandexResultParser(HTMLParser):
    """从 Yandex 搜索 HTML 抓取标题/链接 (轻量)."""

    def __init__(self) -> None:
        super().__init__()
        self.results: list[dict[str, str]] = []
        self._in_title = False
        self._current: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attrs_d = dict(attrs)
        if tag == "a" and attrs_d.get("class", "").startswith("Link"):
            self._in_title = True
            self._current = {"title": "", "url": attrs_d.get("href", "")}

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._in_title:
            if self._current.get("title") or self._current.get("url"):
                self.results.append(self._current)
            self._in_title = False
            self._current = {}

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._current["title"] = (self._current.get("title", "") + data).strip()


class WebSearchTool(Tool):
    """多后端网络搜索 (Sprint 12 M3 增强, Sprint 36.4 泛化).

    用途: 通用技术查阅/解题辅助 — 查算法原理、库/工具用法、数学技巧、语言特性、
    已知攻击的通用描述等 (不查具体题目). 任何 CTF 题型遇到"不会的东西"都可以用.
    后端顺序: DuckDuckGo HTML -> Bing -> Yandex, 取第一个返回有效结果的.
    降级: 全部失败时提示 LLM 用自身知识推理.

    合规护栏 (Sprint 36.4): 禁止搜索 writeup/题解/本题信息. query 若含
    writeup/solution/solve/cheat 等关键词, 直接拒绝执行并提示改为查通用技术原理.
    """

    name = "web_search"
    description = (
        "通用网络搜索 (解题辅助/技术查阅). 自动尝试多个后端 (DuckDuckGo / Bing / Yandex), "
        "返回标题 + URL 列表.\n"
        "用法: web_search(query='<技术关键词>', max_results=5)\n"
        "适用: 查算法/密码学/二进制/协议/工具库的通用原理与用法, 如 'LLL lattice attack', "
        "'python pickle deserialization exploit', 'GDB attach 技巧' 等.\n"
        "禁止: 不得搜索本题题目名 / writeup / solution / 出题人题解. 只能搜通用技术原理.\n"
        "失败时用 LLM 自身知识推理."
    )
    parameters = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "搜索关键词 (通用技术原理/算法/工具用法, 不得含题目名/writeup)",
            },
            "max_results": {
                "type": "integer",
                "description": "返回结果数 (默认 5, 最大 10)",
            },
        },
        "required": ["query"],
    }

    def __init__(self, ssh_client: SSHClient) -> None:
        self.ssh = ssh_client
        self._available: Optional[bool] = None

    def _ensure(self) -> str:
        if self._available is None:
            self._available = _check_tool(self.ssh, "curl")
        if not self._available:
            return (
                "ERROR: curl 未在 Kali 上安装.\n"
                "降级方案: apt install curl, 或用 ssh_exec 直接 curl."
            )
        return ""

    @staticmethod
    def _clean(text: str) -> str:
        import html as _html
        return _html.unescape(re.sub(r"<[^>]+>", "", text)).strip()

    def _curl(self, url: str) -> str:
        cmd = (
            f"curl -sSL --max-time 12 -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36' "
            f"'{url}' 2>&1 | head -c 250000"
        )
        r = self.ssh.exec_cmd(cmd, timeout=18)
        return r.stdout or ""

    def _parse_ddg(self, html: str, n: int) -> list[dict]:
        out: list[dict] = []
        for m in re.finditer(
            r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', html, re.S
        ):
            href, title = m.group(1), self._clean(m.group(2))
            url = href
            if "uddg=" in href:
                from urllib.parse import unquote, urlparse, parse_qs
                q = parse_qs(urlparse(href).query)
                if "uddg" in q:
                    url = unquote(q["uddg"][0])
            if url and title:
                out.append({"title": title, "url": url})
            if len(out) >= n:
                break
        return out

    def _parse_bing(self, html: str, n: int) -> list[dict]:
        out: list[dict] = []
        for m in re.finditer(
            r'<li class="b_algo">.*?<h2><a href="([^"]+)"[^>]*>(.*?)</a>', html, re.S
        ):
            url, title = m.group(1), self._clean(m.group(2))
            if url and title:
                out.append({"title": title, "url": url})
            if len(out) >= n:
                break
        return out

    def _parse_yandex(self, html: str, n: int) -> list[dict]:
        parser = _YandexResultParser()
        try:
            parser.feed(html)
        except Exception:
            return []
        return parser.results[:n]

    def execute(self, query: str, max_results: int = 5, **_: Any) -> str:
        if not query:
            return "ERROR: query 不能为空"
        # Sprint 36.4 合规护栏: 禁止搜索 writeup/题解/本题信息
        q_lower = query.lower()
        banned = ("writeup", "write-up", "solution", "solver", "cheat", "spoiler",
                  "how to solve", "solution file", "官方题解", "题解")
        for kw in banned:
            if kw in q_lower:
                return (
                    f"ERROR: 查询含违规关键词 '{kw}' (禁止搜索 writeup/题解/本题信息).\n"
                    f"改为搜索通用技术原理/算法/工具用法, 例如: 'LLL lattice attack recovery', "
                    f"'ctf crypto common attack techniques', 'GDB 动态调试技巧'."
                )
        err = self._ensure()
        if err:
            return err
        n = max(1, min(int(max_results), 10))
        from urllib.parse import quote_plus
        q = quote_plus(query)
        backends = [
            ("DuckDuckGo", f"https://html.duckduckgo.com/html/?q={q}", self._parse_ddg),
            ("Bing", f"https://www.bing.com/search?q={q}", self._parse_bing),
            ("Yandex", f"https://yandex.com/search/?text={q}", self._parse_yandex),
        ]
        for name, url, parser in backends:
            try:
                html = self._curl(url)
            except Exception:
                continue
            if not html or len(html) < 1500:
                continue
            if any(k in html.lower() for k in ("captcha", "are you a robot", "unusual traffic")):
                continue
            try:
                results = parser(html, n)
            except Exception:
                results = []
            if results:
                lines = [f"=== web_search ({name}) 结果 (query='{query}') ==="]
                for i, res in enumerate(results, 1):
                    title = res.get("title", "").strip() or "(无标题)"
                    url = res.get("url", "").strip() or "(无 URL)"
                    lines.append(f"\n[{i}] {title}")
                    lines.append(f"    URL: {url}")
                return _truncate("\n".join(lines))
        return (
            f"web_search 所有后端均无有效结果: query='{query}'\n"
            f"降级方案: 用 LLM 自身知识推理候选, 再用 osm_geocode(name='候选名') 拿坐标."
        )


# ============ 工厂 ============

def reverse_image_tools(ssh_client: SSHClient) -> list[Tool]:
    """创建 OSINT 网络搜索/地理编码工具集 (Sprint 12 M3).

    Args:
        ssh_client: 已连接的 SSHClient 实例

    Returns:
        reverse image 工具列表: web_search (多后端) + osm_geocode (Photon)
    """
    return [
        WebSearchTool(ssh_client),
        PhotonGeocodeTool(ssh_client),
    ]


def web_search_tools(ssh_client: SSHClient) -> list[Tool]:
    """创建通用网络搜索工具 (Sprint 36.4 泛化, 独立注册, 不依赖 OSINT 开关).

    Args:
        ssh_client: 已连接的 SSHClient 实例

    Returns:
        仅 web_search 工具 (通用技术查阅/解题辅助, 含防 writeup 护栏)
    """
    return [WebSearchTool(ssh_client)]


__all__ = [
    "WebSearchTool",
    "PhotonGeocodeTool",
    "reverse_image_tools",
    "web_search_tools",
]
