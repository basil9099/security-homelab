"""
protocols/telnet.py
===================
Telnet honeypot handler.

Presents a realistic login prompt and fake shell to capture
credentials and post-login commands.
"""

from __future__ import annotations

import socket
import uuid

from protocols.base import SHELL_RESPONSES, ProtocolHandler


class TelnetHandler(ProtocolHandler):
    """Telnet honeypot emulating a Linux login prompt and shell."""

    PROTOCOL_NAME = "telnet"

    def start(self) -> None:
        self._accept_loop(self._handle_client)

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

            response = SHELL_RESPONSES.get(cmd, f"-bash: {cmd}: command not found")
            conn.sendall(f"{response}\r\n".encode())
