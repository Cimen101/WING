"""Sprint 17+19: 模型路由 LLM 客户端.

策略:
1. 优先使用 zen endpoint (opencode.ai, 免费 deepseek-v4-flash-free)
2. zen 失败时重试 N 次 (默认 2)
3. 仍失败则回退到官方 deepseek-v4-flash
4. (Sprint 19) 支持 model_tier="pro" 模式, 直接使用 pro 模型

Sprint 17 修复:
- zen 单次调用默认超时 30s
- fallback 单次调用默认超时 60s

Sprint 19 新增:
- model_tier="pro" 跳过 flash, 使用 deepseek-v4-pro 求更高成功率
- 调用方 (runner/engine) 决定何时切换到 pro
"""
from __future__ import annotations

import time
from typing import Any

from openai import OpenAI

from ctf_agent.config import Settings, get_settings
from ctf_agent.llm.client import ChatResult, Message, MessageDict, _normalize_messages, _parse_response


_ZEN_DEFAULT_TIMEOUT = 45.0   # Sprint 19 v5: httpx.Timeout 客户端级防卡死, 45s 避免误杀正常请求
_FALLBACK_DEFAULT_TIMEOUT = 30.0  # Sprint 32.7: 60→30s, 加速半死连接暴露 (慢速流会绕过 read timeout, 配合 no_progress 兜底)
_PRO_DEFAULT_TIMEOUT = 120.0

# Sprint 32.8: 动态 provider 健康状态 — 冒烟测试标记不是"终身制":
# 中途 API 故障 (限流/挂起) 时实时降级, 恢复后自动重新尝试.
# - 连续失败达阈值 → 标记 down + 进入跳过期 (skip_seconds)
# - 调用成功 → 标记 up, 立即恢复
# 避免"冒烟测试通过 → 中途 fallback 挂起 → 每次调用死等 30s×3 重试" 的卡死.
_PROVIDER_FAIL_THRESHOLD = 2       # 连续失败 N 次判定 provider 故障
_PROVIDER_SKIP_AFTER_FAIL = 120.0  # 故障后跳过时长 (s)
_PROVIDER_RESET_SECONDS = 60.0     # 长时间未失败则重置计数

# Sprint 32.9: wall-clock 总超时 — httpx read timeout 防不了慢速流:
# 服务器持续缓慢发 chunk (每次间隔 < read timeout), ssl.read 永远不返回.
# 用 daemon 线程 + join(timeout) 实现应用层总超时, 超时即放弃该请求.
# - daemon 线程: 即使底层 socket 永远阻塞, 也不阻止进程退出
# - 超时后线程泄漏在后台, 但 provider 会被动态标记 down, 不会反复创建
_CALL_WALLCLOCK = 45.0  # 单次 create 调用的硬总超时 (s), 覆盖 slow-drip 场景


def _call_with_wallclock(
    fn: Any, *args: Any, timeout: float = _CALL_WALLCLOCK, **kwargs: Any
) -> Any:
    """在 daemon 线程中执行 fn, 超时抛出 TimeoutError.

    目的: 慢速流连接 (slow-drip streaming) 会绕过 httpx 的 read timeout,
    ssl.read 可能无限阻塞. 这里用线程 + join(timeout) 做 wall-clock 兜底.
    """
    import threading

    result_holder: dict[str, Any] = {}

    def _runner() -> None:
        try:
            result_holder["value"] = fn(*args, **kwargs)
        except BaseException as e:  # noqa: BLE001
            result_holder["error"] = e

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError(
            f"LLM 调用超过 wall-clock {timeout:.0f}s (疑似慢速流半死连接), 已放弃该请求"
        )
    if "error" in result_holder:
        raise result_holder["error"]
    return result_holder.get("value")


class RoutedLLMClient:
    """带模型路由的 LLM 客户端.

    支持 model_tier:
        "flash" (默认): zen → flash fallback
        "pro":   zen → flash → pro fallback
        "pro_only": 直接使用 pro 模型 (跳过 zen/flash)
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._zen_client: OpenAI | None = None
        self._fallback_client: OpenAI | None = None
        self._pro_client: OpenAI | None = None
        self._zen_consecutive_failures = 0
        self._zen_skip_until: float = 0.0
        # Sprint 32.5: 冒烟测试标记 — None=未测试(默认尝试), {provider: bool}=测试结果
        # True=可用, False=不可用(跳过). 由 smoke_test() 或 apply_smoke_*() 更新.
        self._provider_ok: dict[str, bool] | None = None
        # Sprint 32.8: 动态健康状态 — 每次调用的实时结果, 覆盖冒烟测试的一次性标记
        # {provider: {"fails": int(连续失败), "last_ts": float, "down_until": float}}
        self._provider_state: dict[str, dict[str, float | int]] = {}

    # ── Sprint 32.8: 动态 provider 健康状态 ──

    def _provider_healthy(self, name: str, smoke_default: bool = True) -> bool:
        """判断 provider 当前是否可用 (冒烟测试标记 + 动态故障状态叠加).

        优先级: 动态 down_until (中途故障) > 冒烟测试标记 > 默认 True.
        """
        st = self._provider_state.get(name) or {}
        down_until = st.get("down_until") or 0.0
        if time.monotonic() < down_until:
            return False
        # 跳过期已过: 清除故障状态, 允许重新尝试 (恢复探测)
        if down_until:
            st["fails"] = 0
            st["down_until"] = 0.0
        # 冒烟测试标记
        if self._provider_ok is not None:
            return self._provider_ok.get(name, smoke_default)
        return True

    def _record_provider_fail(self, name: str) -> None:
        """记录一次 provider 失败, 达阈值进入跳过期 (自动恢复探测)."""
        st = self._provider_state.setdefault(name, {"fails": 0, "last_ts": 0.0, "down_until": 0.0})
        now = time.monotonic()
        # 距上次失败超过重置窗口 → 计数清零 (视为新的一轮)
        if now - (st.get("last_ts") or 0.0) > _PROVIDER_RESET_SECONDS:
            st["fails"] = 0
        st["fails"] = int(st.get("fails") or 0) + 1
        st["last_ts"] = now
        if st["fails"] >= _PROVIDER_FAIL_THRESHOLD:
            st["down_until"] = now + _PROVIDER_SKIP_AFTER_FAIL
            # 同步写入冒烟标记, 便于排查 (apply_smoke 下次读文件也能看到)
            if self._provider_ok is not None:
                self._provider_ok[name] = False

    def _record_provider_ok(self, name: str) -> None:
        """记录一次 provider 成功, 立即恢复健康 (清除故障状态)."""
        self._provider_state.pop(name, None)
        if self._provider_ok is not None:
            self._provider_ok[name] = True

    def _should_try_zen(self) -> bool:
        # Sprint 32.8: 动态健康状态优先 (中途故障跳过期 > 连续失败计数)
        if not self._provider_healthy("zen"):
            return False
        if self._zen_consecutive_failures >= 5:
            if time.monotonic() < self._zen_skip_until:
                return False
            self._zen_consecutive_failures = 0
        return True

    # ── Sprint 32.5: API 冒烟测试 (冲榜场景, 快速探测可用性) ──

    def apply_smoke_results(self, results: dict[str, bool]) -> None:
        """应用冒烟测试标记 (来自 controller 每题领题前的探测结果)."""
        self._provider_ok = dict(results)

    def apply_smoke_from_file(self, path: str) -> None:
        """从 JSON 文件应用冒烟测试标记 (agent 子进程启动时读取)."""
        import json
        from pathlib import Path

        f = Path(path)
        if not f.exists():
            return
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            ok: dict[str, bool] = {}
            for key in ("zen", "flash_fallback", "pro"):
                v = data.get(key)
                if isinstance(v, bool):
                    ok[key] = v
            if ok:
                self._provider_ok = ok
        except Exception:
            pass

    def smoke_test(self, timeout: float = 10.0) -> dict[str, bool]:
        """冒烟测试所有可用 provider (单次超时 timeout 秒).

        冲榜场景下 LLM API 不可用时, 与其让每次调用等 45s*3 超时重试,
        不如启动前/领题前快速探测, 只调用可用的 provider.
        返回 {"zen": bool, "flash_fallback": bool, "pro": bool} 并写入标记.
        """
        results: dict[str, bool] = {}

        def _probe(client: OpenAI | None, model: str, t: float) -> bool:
            if client is None:
                return False
            resp = client.chat.completions.create(
                messages=[{"role": "user", "content": "ping"}],
                model=model,
                max_tokens=1,
                timeout=t,
            )
            return resp is not None

        # zen
        try:
            results["zen"] = _probe(self._get_zen_client(timeout=timeout), self.settings.zen_model, timeout)
        except Exception:
            results["zen"] = False

        # flash fallback
        try:
            results["flash_fallback"] = _probe(self._get_fallback_client(), self.settings.fallback_model, timeout)
        except Exception:
            results["flash_fallback"] = False

        # pro
        try:
            results["pro"] = _probe(self._get_pro_client(timeout=timeout), self.settings.pro_model, timeout)
        except Exception:
            results["pro"] = False

        self._provider_ok = results
        return results

    @property
    def provider_ok(self) -> dict[str, bool] | None:
        return self._provider_ok

    def _get_zen_client(self, timeout: float = 15.0) -> OpenAI | None:
        import httpx
        key = self.settings.zen_api_key.get_secret_value()
        if not key:
            return None
        if self._zen_client is None:
            self._zen_client = OpenAI(
                api_key=key,
                base_url=self.settings.zen_base_url,
                timeout=httpx.Timeout(timeout, connect=5, read=timeout),
            )
        return self._zen_client

    def _get_fallback_client(self, timeout: float = 30.0) -> OpenAI | None:
        """获取 fallback client.

        Sprint 32.7: 修复无 timeout 导致 10 分钟卡死 — SDK 默认超时 600s,
        API 挂起时请求会阻塞 10 分钟 (实际案例: no_progress 600s 触发的元凶).
        现在与 zen/pro 一致使用 httpx.Timeout 客户端级超时 (30s 加速暴露半死连接).
        """
        import httpx
        if self._fallback_client is None:
            key = self.settings.fallback_api_key.get_secret_value()
            if not key:
                return None  # fallback 禁用
            self._fallback_client = OpenAI(
                api_key=key,
                base_url=self.settings.fallback_base_url,
                timeout=httpx.Timeout(timeout, connect=10, read=timeout),
            )
        return self._fallback_client

    def _get_pro_client(self, timeout: float = 120.0) -> OpenAI | None:
        """获取 pro client (Sprint 19)."""
        import httpx
        key = self.settings.pro_api_key.get_secret_value()
        if not key:
            key = self.settings.openai_api_key.get_secret_value()
        if not key:
            return None
        if self._pro_client is None:
            self._pro_client = OpenAI(
                api_key=key,
                base_url=self.settings.pro_base_url,
                timeout=httpx.Timeout(timeout, connect=10, read=timeout),
            )
        return self._pro_client

    def _call_flash(self, payload: dict[str, Any], timeout: float | None) -> ChatResult:
        """flash 路由: zen → fallback → pro (Sprint 17 逻辑 + Sprint 32.8 动态降级)."""
        used_model_zen = self.settings.zen_model
        used_model_fallback = self.settings.fallback_model
        zen_timeout = timeout if timeout is not None else _ZEN_DEFAULT_TIMEOUT
        fallback_timeout = timeout if timeout is not None else _FALLBACK_DEFAULT_TIMEOUT

        # Phase 1: try zen (Sprint 32.5: 冒烟测试标记 False 时跳过, 不浪费 45s*3 重试)
        # Sprint 32.8: _should_try_zen 已集成动态健康状态 (中途故障自动跳过)
        if self._should_try_zen():
            zen_client = self._get_zen_client(timeout=zen_timeout)
            if zen_client is not None:
                for attempt in range(self.settings.llm_max_retries + 1):
                    try:
                        zen_payload = {**payload, "model": used_model_zen, "timeout": zen_timeout}
                        # Sprint 32.9: wall-clock 总超时兜底 (慢速流绕过 read timeout)
                        resp = _call_with_wallclock(
                            lambda p=zen_payload: zen_client.chat.completions.create(**p)
                        )
                        self._zen_consecutive_failures = 0
                        self._record_provider_ok("zen")
                        return _parse_response(resp, used_model_zen)
                    except Exception as e:
                        status_code = getattr(e, "status_code", None)
                        if status_code is not None and 500 <= status_code < 600:
                            self._zen_consecutive_failures += 1
                            if self._zen_consecutive_failures >= 3:
                                self._zen_skip_until = time.monotonic() + 60.0
                            break
                        if attempt == self.settings.llm_max_retries:
                            self._zen_consecutive_failures += 1
                            if self._zen_consecutive_failures >= 5:
                                self._zen_skip_until = time.monotonic() + 60.0
                            break
                        continue
                # zen 尝试完毕且失败 → 记录动态故障
                self._record_provider_fail("zen")

        # Phase 2: fallback (如果启用) — Sprint 21: 失败重试 llm_max_retries 次,
        # 避免单次网络抖动直接抛异常导致整题 0 步失败 (NSS #2263 复盘)
        # Sprint 32.8: 冒烟测试标记 False 或动态故障跳过期 → 跳过 fallback, 直接进 pro
        if not self._provider_healthy("flash_fallback"):
            last_err: Exception | None = None
        else:
            fallback_client = self._get_fallback_client()
            if fallback_client is None:
                last_err = RuntimeError("fallback 未配置 (FALLBACK_API_KEY 为空)")
            else:
                fb_payload = {**payload, "model": used_model_fallback, "timeout": fallback_timeout}
                last_err = None
                for attempt in range(self.settings.llm_max_retries + 1):
                    try:
                        # Sprint 32.9: wall-clock 总超时兜底 (慢速流绕过 read timeout)
                        resp = _call_with_wallclock(
                            lambda p=fb_payload: fallback_client.chat.completions.create(**p)
                        )
                        self._record_provider_ok("flash_fallback")
                        return _parse_response(resp, used_model_fallback)
                    except Exception as e:  # noqa: BLE001
                        last_err = e
                        if attempt == self.settings.llm_max_retries:
                            break
                        time.sleep(2)
                # fallback 全部失败 → 记录动态故障, 进入跳过期
                self._record_provider_fail("flash_fallback")

        # Phase 3 (Sprint 32.8): pro 兜底 — fallback 也失败时降级到 pro, 而非直接抛异常.
        # 长期全自动运行的关键: 中途某 provider 故障不能整题 0 步失败.
        if self._provider_healthy("pro"):
            try:
                return self._call_pro(payload, timeout)
            except Exception as e:
                self._record_provider_fail("pro")
                last_err = e
        if last_err is not None:
            raise last_err
        raise RuntimeError("所有 LLM provider 均不可用 (zen/fallback/pro)")

    def _call_pro(self, payload: dict[str, Any], timeout: float | None) -> ChatResult:
        """直接调用 pro 模型 (Sprint 19)."""
        # Sprint 32.5: 冒烟测试标记 False 时快速失败
        # Sprint 32.8: 动态健康状态叠加 (中途故障也跳过)
        if not self._provider_healthy("pro"):
            raise RuntimeError("pro 不可用 (api_smoke: pro=False 或中途故障)")
        pro_client = self._get_pro_client(timeout or _PRO_DEFAULT_TIMEOUT)
        if pro_client is None:
            raise ValueError("PRO_API_KEY 未配置，无法使用 pro 模型")
        pro_model = self.settings.pro_model
        pro_payload = {**payload, "model": pro_model}
        # Sprint 32.9: wall-clock 总超时兜底 (慢速流绕过 read timeout)
        resp = _call_with_wallclock(
            lambda p=pro_payload: pro_client.chat.completions.create(**p),
            timeout=max(timeout or _PRO_DEFAULT_TIMEOUT, _CALL_WALLCLOCK),
        )
        return _parse_response(resp, pro_model)

    def chat(
        self,
        messages: list[Message] | list[MessageDict] | list[dict[str, str]],
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        timeout: float | None = None,
        extra: dict[str, Any] | None = None,
        model_tier: str = "flash",
    ) -> ChatResult:
        """同步 chat completion, 带路由.

        Args:
            model_tier: "flash" (default) | "pro" (skip flash) | "pro_only"
                ⚠️ pro/pro_only Sprint 26 起已 deprecated, 默认不推荐使用
            extra: 可包含 "reasoning_effort" (high/max) 按难度指定思考强度;
                其他键作为透传参数. 仅当 enable_thinking_mode=True 时 reasoning_effort 生效.
        """
        payload: dict[str, Any] = {
            "messages": _normalize_messages(messages),
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

        # Sprint 26: 思考模式注入 (deepseek-v4-flash thinking_mode)
        # 官方文档: reasoning_effort 支持 high/max; 需同时传 extra_body={"thinking": {"type": "enabled"}}
        # 思考模式不支持 temperature (设置不报错但不生效), 保留 temperature 传递仅为兼容, 实际被忽略
        extra = dict(extra) if extra else {}
        if self.settings.enable_thinking_mode:
            # effort 优先级: extra 显式传入 > settings 默认
            effort = extra.pop("reasoning_effort", None) or self.settings.thinking_effort_default
            payload["reasoning_effort"] = effort
            # thinking 参数必须放在 extra_body (deepseek 扩展, 非 OpenAI 标准字段)
            existing_extra_body = extra.pop("extra_body", None) or {}
            payload["extra_body"] = {**existing_extra_body, "thinking": {"type": "enabled"}}

        # 合并剩余 extra (透传参数, 如 timeout 等)
        if extra:
            payload.update(extra)

        # Sprint 19: pro_only 直接调用 pro (Sprint 26 deprecated)
        if model_tier == "pro_only":
            return self._call_pro(payload, timeout)

        # Sprint 19: pro 模式先试 flash (含 zen), 失败后跳 pro (Sprint 26 deprecated)
        if model_tier == "pro":
            try:
                return self._call_flash(payload, timeout)
            except Exception:
                # flash 异常 (含 5xx / 超时 / 推理失败), 降级到 pro
                pass
            return self._call_pro(payload, timeout)

        # 默认: flash 模式
        return self._call_flash(payload, timeout)


__all__ = ["RoutedLLMClient"]
