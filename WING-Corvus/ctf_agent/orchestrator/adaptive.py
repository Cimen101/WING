"""Sprint 18/27: 动态熔断器 (强化 + 动态扩展).

设计:
- Sprint 27: 拉高步数上限, 适配长操作链 (如 KeePass+RAR+嵌套隐写)
  - BASE_STEPS 50→60, HARD_MAX_STEPS 150→200
  - medium 1.2→1.5 (60→90步), hard 2.0→2.5 (60→150步)
- Sprint 27: 动态扩展机制 — 达到上限后, 巡查指导器判断方向正确则自动 +20 步
- AdaptiveBreaker 根据 challenge_type + difficulty 动态决定实际 max_steps
"""
from __future__ import annotations

from ctf_agent.orchestrator.breaker import CircuitBreaker


# 难度 → 步数倍率 (Sprint 27: 拉高, 适配长操作链)
# Sprint 21.1: easy 0.8 → 1.0
# Sprint 27: medium 1.2→1.5, hard 2.0→2.5 (实测 #2428 60步不够)
_DIFFICULTY_MULTIPLIER = {
    "easy": 1.0,
    "medium": 1.5,   # Sprint 27: 1.2→1.5 (90步, 适配嵌套解密链)
    "hard": 2.5,     # Sprint 27: 2.0→2.5 (150步, 适配复杂逆向/取证)
}

# 类型 → 步数倍率 (覆盖难度倍率)
_TYPE_MULTIPLIER = {
    "pwn": 1.5,      # 写 exploit 需更多步
    "reverse": 1.2,  # 逆向需更多分析
    "crypto": 0.8,   # 通常脚本即可
    "web": 1.0,      # 标准
    "forensics": 1.2, # 二进制解析需更多
    "misc": 1.2,     # Sprint 27: 1.0→1.2 (misc 常有嵌套解密链, #2428 实测 60步不够)
    "osint": 1.0,
}

# Sprint 27: 硬性上限 200 (easy 60 / medium 90 / hard 150)
HARD_MAX_STEPS = 200  # 硬性上限, 任何情况不可超越
BASE_STEPS = 60       # Sprint 27: 50→60 (基准提高)

# Sprint 27: 动态扩展配置
EXTEND_STEPS = 20     # 每次扩展步数
# Sprint 36 复盘: 2→3 — 攻击实施阶段 (写 exploit/LLL/故障注入) 步数需求大,
# linx/threshold/faulty_mayo 均在 120-160 步撞顶; 方向正确的扩展更积极,
# 总计可加 60 步 (crypto hard 120→180, pwn hard 200 硬顶不变)
MAX_EXTENSIONS = 3    # 最多扩展次数 (总计可加 60 步)


def compute_max_steps(
    challenge_type: str | None = None,
    challenge_difficulty: str | None = None,
) -> int:
    """根据题型+难度计算实际 max_steps."""
    steps = BASE_STEPS
    if challenge_difficulty:
        steps = int(steps * _DIFFICULTY_MULTIPLIER.get(challenge_difficulty.lower(), 1.0))
    if challenge_type:
        steps = int(steps * _TYPE_MULTIPLIER.get(challenge_type.lower(), 1.0))
    return min(steps, HARD_MAX_STEPS)


class AdaptiveBreaker(CircuitBreaker):
    """动态熔断器: 按题目类型+难度调整 max_steps 和 max_seconds.

    Sprint 27: 支持动态扩展 max_steps (达到上限后, 巡查指导器判断方向正确则 +20 步)
    """

    def __init__(
        self,
        *,
        challenge_type: str | None = None,
        challenge_difficulty: str | None = None,
        max_seconds: float = 1800.0,
        max_cost_usd: float = 1.5,
        **kwargs,
    ) -> None:
        dynamic_max = compute_max_steps(challenge_type, challenge_difficulty)
        # Sprint 18: hard 题 max_seconds 默认 1800s 偏短, 提升到 2700s (45min)
        # Sprint 32.4 修复 (#2501 Blast 复盘): 之前 medium 分支 `min(max(x,1200),1200)`
        # 恒等于 1200s, 无视调用方 (NSS executor) 显式传入的合理时间 (如 1500s),
        # 导致方向正确、进展正常 (第47步刚发现关键线索) 时被时间熔断误杀.
        # 现改为: 尊重调用方传入值, 难度只做下限兜底 (防传值过小).
        if (challenge_difficulty or "").lower() == "hard":
            max_seconds = max(max_seconds, 2700.0)
        elif (challenge_difficulty or "").lower() == "medium":
            max_seconds = max(max_seconds, 1200.0)  # 下限 20min, 不压上限
        else:
            max_seconds = max(max_seconds, 900.0)   # 下限 15min, 不压上限
        # Pwn/Forensics/Reverse hard 进一步提到 3000s
        if challenge_difficulty and challenge_difficulty.lower() == "hard" and challenge_type in ("pwn", "forensics", "reverse"):
            max_seconds = max(max_seconds, 3000.0)
        super().__init__(
            max_steps=dynamic_max,
            max_seconds=max_seconds,
            max_cost_usd=max_cost_usd,
            **kwargs,
        )
        self._challenge_type = challenge_type
        self._challenge_difficulty = challenge_difficulty
        self._dynamic_max_steps = dynamic_max
        self._extensions_used = 0  # Sprint 27: 已使用的扩展次数

    def extend_steps(self, additional: int = EXTEND_STEPS) -> bool:
        """Sprint 27: 动态扩展 max_steps.

        达到上限后, 巡查指导器判断方向正确时调用此方法.
        每次扩展 EXTEND_STEPS 步, 最多 MAX_EXTENSIONS 次.

        Returns:
            True 如果扩展成功, False 如果已达最大扩展次数或硬性上限
        """
        if self._extensions_used >= MAX_EXTENSIONS:
            return False
        new_max = min(self.max_steps + additional, HARD_MAX_STEPS)
        if new_max <= self.max_steps:
            return False  # 已达硬性上限
        self.max_steps = new_max
        self._extensions_used += 1
        return True


__all__ = ["AdaptiveBreaker", "compute_max_steps", "HARD_MAX_STEPS", "BASE_STEPS", "EXTEND_STEPS", "MAX_EXTENSIONS"]
