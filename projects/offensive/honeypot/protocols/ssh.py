"""
protocols/ssh.py
================
SSH honeypot handler using paramiko.

Presents a realistic OpenSSH banner, captures credential attempts,
and provides a fake interactive shell.
"""

from __future__ import annotations

import logging as _logging
import os
import socket
import threading
import uuid

from protocols.base import ProtocolHandler, register

# Suppress paramiko's verbose logging
_logging.getLogger("paramiko").setLevel(_logging.CRITICAL)

try:
    import paramiko

    _HAS_PARAMIKO = True
    _ServerInterfaceBase = paramiko.ServerInterface
except ImportError:
    _HAS_PARAMIKO = False

    class _ServerInterfaceBase:
        """Stand-in base so this module still imports without paramiko.

        SSHHandler.start() bails out early when _HAS_PARAMIKO is False, so
        no method on the subclass is ever reached in that case.
        """

# Fake shell responses (shared with telnet, but SSH-specific extras)
_SHELL_RESPONSES: dict[str, str] = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "uname": "Linux",
    "uname -a": "Linux honeypot 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "hostname": "web-prod-01",
    "pwd": "/root",
    "ls": "Desktop  Documents  Downloads  .bash_history  .bashrc  .ssh",
    "ls -la": (
        "total 32\n"
        "drwx------  5 root root 4096 Jan 15 09:23 .\n"
        "drwxr-xr-x 18 root root 4096 Jan 10 14:00 ..\n"
        "-rw-------  1 root root  512 Jan 15 09:23 .bash_history\n"
        "-rw-r--r--  1 root root 3106 Dec  5  2024 .bashrc\n"
        "drwx------  2 root root 4096 Jan 10 14:22 .ssh\n"
        "drwxr-xr-x  2 root root 4096 Jan 12 10:15 Desktop\n"
        "drwxr-xr-x  2 root root 4096 Jan 13 08:30 Documents"
    ),
    "cat /etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"
    ),
    "ifconfig": (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 10.10.10.150  netmask 255.255.255.0  broadcast 10.10.10.255\n"
        "        ether 00:0c:29:ab:cd:ef  txqueuelen 1000  (Ethernet)"
    ),
    "ip addr": (
        "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 state UP\n"
        "    inet 10.10.10.150/24 brd 10.10.10.255 scope global eth0"
    ),
    "uptime": " 09:23:15 up 42 days,  3:10,  1 user,  load average: 0.08, 0.03, 0.01",
    "w": " 09:23:15 up 42 days,  3:10,  1 user,  load average: 0.08, 0.03, 0.01\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nroot     pts/0    10.10.10.100     09:20    0.00s  0.03s  0.01s w",
    "cat /etc/shadow": "cat: /etc/shadow: Permission denied",
    "ps aux": (
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root         1  0.0  0.1 169432 11552 ?        Ss   Jan15   0:05 /sbin/init\n"
        "root       412  0.0  0.0  72296  5520 ?        Ss   Jan15   0:00 /usr/sbin/sshd\n"
        "www-data   821  0.0  0.2 274816 18432 ?        S    Jan15   0:12 /usr/sbin/apache2\n"
        "root      1205  0.0  0.0  15452  2048 pts/0    R+   09:23   0:00 ps aux"
    ),
}

# Path to the generated RSA host key
_HOST_KEY_PATH = os.path.join(os.path.dirname(__file__), "..", ".ssh_host_key")


def _get_host_key() -> paramiko.RSAKey:
    """Load or generate an RSA host key."""
    if os.path.exists(_HOST_KEY_PATH):
        return paramiko.RSAKey.from_private_key_file(_HOST_KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(_HOST_KEY_PATH)
    return key


class _SSHServer(_ServerInterfaceBase):
    """Paramiko server interface that accepts any credentials."""

    def __init__(
        self,
        handler: SSHHandler,
        session_id: str,
        addr: tuple[str, int],
    ) -> None:
        self._handler = handler
        self._session_id = session_id
        self._addr = addr
        self._event = threading.Event()

    def _log_auth(self, username: str, password: str, method: str) -> None:
        """Emit a credential_attempt through the owning handler."""
        ip, port = self._addr
        self._handler._emit(self._handler._make_event(
            ip, port, "credential_attempt",
            credentials={"username": username, "password": password},
            session_id=self._session_id,
            metadata={"auth_method": method},
        ))

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        self._log_auth(username, password, "password")
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key) -> int:
        self._log_auth(username, "", "publickey")
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_channel_shell_request(self, channel) -> bool:
        self._event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pxwidth, pxheight, modes) -> bool:
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        self._event.set()
        return True


@register
class SSHHandler(ProtocolHandler):
    """SSH honeypot using paramiko's ServerInterface."""

    PROTOCOL_NAME = "ssh"

    def start(self) -> None:
        if not _HAS_PARAMIKO:
            print("[!] paramiko not installed — SSH honeypot disabled")
            return

        host_key = _get_host_key()
        sock = self._bind_server()

        while not self._stop_event.is_set():
            try:
                conn, addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            t = threading.Thread(
                target=self._handle_client,
                args=(conn, addr, host_key),
                daemon=True,
            )
            t.start()

    def _handle_client(
        self,
        conn: socket.socket,
        addr: tuple[str, int],
        host_key: paramiko.RSAKey,
    ) -> None:
        ip, port = addr
        session_id = uuid.uuid4().hex[:10]

        self._emit(self._make_event(ip, port, "connection", session_id=session_id))

        transport = None
        try:
            transport = paramiko.Transport(conn)
            transport.local_version = self._config.banner or "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
            transport.add_server_key(host_key)

            server = _SSHServer(self, session_id, addr)
            transport.start_server(server=server)

            chan = transport.accept(timeout=20)
            if chan is None:
                return

            # Wait for shell request
            server._event.wait(timeout=10)
            if not server._event.is_set():
                return

            # Send shell prompt and interact
            chan.sendall(b"Last login: Mon Jan 15 09:20:11 2026 from 10.10.10.100\r\n")
            self._shell_loop(chan, ip, port, session_id)

        except (paramiko.SSHException, OSError, EOFError):
            pass
        finally:
            self._emit(self._make_event(ip, port, "disconnect", session_id=session_id))
            if transport:
                try:
                    transport.close()
                except (paramiko.SSHException, OSError):
                    pass
            conn.close()

    def _shell_loop(self, chan, ip: str, port: int, session_id: str) -> None:
        """Interactive fake shell over SSH channel."""
        buf = b""
        chan.sendall(b"root@web-prod-01:~# ")

        for _ in range(50):  # max iterations
            try:
                data = chan.recv(1024)
            except (paramiko.SSHException, OSError, EOFError):
                break
            if not data:
                break

            buf += data
            # Process on newline
            if b"\n" not in buf and b"\r" not in buf:
                continue

            cmd = buf.decode("utf-8", errors="ignore").strip()
            buf = b""

            if not cmd:
                chan.sendall(b"root@web-prod-01:~# ")
                continue

            self._emit(self._make_event(
                ip, port, "command", payload=cmd, session_id=session_id,
            ))

            if cmd in ("exit", "quit", "logout"):
                chan.sendall(b"logout\r\n")
                break

            response = _SHELL_RESPONSES.get(cmd, f"-bash: {cmd}: command not found")
            chan.sendall(f"{response}\r\n".encode())
            chan.sendall(b"root@web-prod-01:~# ")
