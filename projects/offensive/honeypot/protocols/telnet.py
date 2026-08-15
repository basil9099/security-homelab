"""
protocols/telnet.py
===================
Telnet honeypot handler.

Presents a realistic login prompt and fake shell to capture
credentials and post-login commands.
"""

from __future__ import annotations

import socket
import threading
import uuid

from protocols.base import ProtocolHandler, register

# Fake shell responses
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
}


@register
class TelnetHandler(ProtocolHandler):
    """Telnet honeypot emulating a Linux login prompt and shell."""

    PROTOCOL_NAME = "telnet"

    def start(self) -> None:
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
                args=(conn, addr),
                daemon=True,
            )
            t.start()

    def _handle_client(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        ip, port = addr
        session_id = uuid.uuid4().hex[:10]
        conn.settimeout(30)

        self._emit(self._make_event(
            ip, port, "connection", session_id=session_id,
        ))

        try:
            # Login sequence
            banner = self._config.banner or "Ubuntu 22.04 LTS"
            conn.sendall(f"\r\n{banner}\r\n".encode())

            username = self._prompt(conn, "login: ")
            if not username:
                return
            password = self._prompt(conn, "Password: ")
            if password is None:
                return

            self._emit(self._make_event(
                ip, port, "credential_attempt",
                credentials={"username": username, "password": password},
                session_id=session_id,
            ))

            # Fake shell
            conn.sendall(b"\r\nLast login: Mon Jan 15 09:20:11 2026 from 10.10.10.100\r\n")
            self._shell_loop(conn, ip, port, session_id)

        except (TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            self._emit(self._make_event(ip, port, "disconnect", session_id=session_id))
            conn.close()

    def _prompt(self, conn: socket.socket, prompt: str) -> str | None:
        conn.sendall(prompt.encode())
        try:
            data = conn.recv(1024)
            if not data:
                return None
            return data.decode("utf-8", errors="ignore").strip()
        except (TimeoutError, OSError):
            return None

    def _shell_loop(self, conn: socket.socket, ip: str, port: int, session_id: str) -> None:
        for _ in range(20):  # max commands per session
            conn.sendall(b"root@web-prod-01:~# ")
            try:
                data = conn.recv(1024)
            except (TimeoutError, OSError):
                break
            if not data:
                break

            cmd = data.decode("utf-8", errors="ignore").strip()
            if not cmd:
                continue

            self._emit(self._make_event(
                ip, port, "command", payload=cmd, session_id=session_id,
            ))

            if cmd in ("exit", "quit", "logout"):
                conn.sendall(b"logout\r\n")
                break

            response = _SHELL_RESPONSES.get(cmd, f"-bash: {cmd}: command not found")
            conn.sendall(f"{response}\r\n".encode())
