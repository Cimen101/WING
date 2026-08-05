"""SSH-Kali 沙箱连接器（L6 基础设施层）.

依据 README §3.1，提供与 Kali Linux 沙箱的 SSH 通信能力。
"""

from ctf_agent.ssh.client import CmdResult, SSHClient, ssh_client_from_settings

__all__ = ["CmdResult", "SSHClient", "ssh_client_from_settings"]
