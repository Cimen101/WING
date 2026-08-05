"""短期记忆实现：滑动窗口保留最近 N 轮 ReAct 交互.

依据 README §3.3.1：
- 短期记忆存储当前 ReAct 循环的最近 10 轮交互
- 存储于内存中
- 直接拼入 System Prompt（实际实现为拼入 messages 列表头部）

设计：
- system_prompt 与 task 永久保留（不裁剪）
- 中间的 (assistant, observation) 轮次按滑动窗口裁剪
- 当总轮数 <= max_rounds 时，等价于不裁剪
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ctf_agent.llm import Message


@dataclass
class ShortTermMemory:
    """短期记忆：管理 ReAct 循环的消息历史.

    消息结构：
        [system, task, (assistant_1, observation_1), (assistant_2, observation_2), ...]
    当轮次超过 max_rounds 时，丢弃最早的 (assistant, observation) 对。

    Attributes:
        system_prompt: 系统提示词（永久保留）
        task: 任务描述（永久保留，作为第一个 user 消息）
        max_rounds: 保留的最大交互轮次（默认 10，依据 README §3.3.1）
    """

    system_prompt: str
    task: str
    max_rounds: int = 10
    _system_msg: Message = field(init=False)
    _task_msg: Message = field(init=False)
    _rounds: list[tuple[Message, Message]] = field(default_factory=list, init=False)
    _extra_user_messages: list[Message] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        self._system_msg = Message(role="system", content=self.system_prompt)
        self._task_msg = Message(role="user", content=self.task)

    def update_system_prompt(self, new_system_prompt: str) -> None:
        """更新 system prompt（用于动态注入中期记忆的关键事实）.

        Args:
            new_system_prompt: 新的 system prompt 全文
        """
        self.system_prompt = new_system_prompt
        self._system_msg = Message(role="system", content=new_system_prompt)

    def add_user_message(self, content: str) -> None:
        """添加一条额外的 user 消息 (如巡查指导/Skill 注入).

        消息追加到消息列表末尾, 在下一次 LLM 调用时可见.
        用完即清 (由调用方负责清空, 避免重复注入).
        """
        self._extra_user_messages.append(Message(role="user", content=content))

    def add_round(self, assistant_content: str, observation_content: str) -> None:
        """添加一轮交互：LLM 输出 + Observation 回灌.

        Args:
            assistant_content: LLM 的原始输出（Thought + Action 或 Final Answer）
            observation_content: 工具执行结果或格式错误提示
        """
        assistant_msg = Message(role="assistant", content=assistant_content)
        observation_msg = Message(role="user", content=observation_content)
        self._rounds.append((assistant_msg, observation_msg))

        # 滑动窗口裁剪
        if len(self._rounds) > self.max_rounds:
            # 保留最近 max_rounds 轮
            self._rounds = self._rounds[-self.max_rounds:]

    def get_messages(self) -> list[Message]:
        """返回当前记忆中的全部消息（已应用滑动窗口）."""
        messages: list[Message] = [self._system_msg, self._task_msg]
        for assistant_msg, observation_msg in self._rounds:
            messages.append(assistant_msg)
            messages.append(observation_msg)
        # 追加额外 user 消息 (巡查指导/Skill 注入), 用完即清
        if self._extra_user_messages:
            messages.extend(self._extra_user_messages)
            self._extra_user_messages.clear()
        return messages

    @property
    def round_count(self) -> int:
        """当前保留的交互轮数."""
        return len(self._rounds)

    @property
    def total_message_count(self) -> int:
        """当前消息总数（system + task + 2 * round_count）."""
        return 2 + 2 * len(self._rounds)

    def clear(self) -> None:
        """清空交互历史（保留 system 与 task）."""
        self._rounds.clear()
