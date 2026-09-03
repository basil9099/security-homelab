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

from protocols.base import SHELL_RESPONSES, ProtocolHandler

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
        self._handler._emit(
            self._handler._make_event(
                ip,
                port,
                "credential_attempt",
                credentials={"username": username, "password": password},
                session_id=self._session_id,
                metadata={"auth_method": method},
            )
        )

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

    def check_channel_pty_request(
        self, channel, term, width, height, pxwidth, pxheight, modes
    ) -> bool:
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        self._event.set()
        return True


class SSHHandler(ProtocolHandler):
    """SSH honeypot using paramiko's ServerInterface."""

    PROTOCOL_NAME = "ssh"

    def bind(self) -> None:
        """Refuse to claim the port when SSH emulation cannot actually run.

        Reported to the caller before it announces the service, rather than
        printed from inside the listener thread after the fact.
        """
        if not _HAS_PARAMIKO:
            raise RuntimeError("paramiko not installed — SSH honeypot unavailable")
        super().bind()

    def start(self) -> None:
        if not _HAS_PARAMIKO:
            print("[!] paramiko not installed — SSH honeypot disabled")
            return

        host_key = _get_host_key()
        self._accept_loop(lambda conn, addr: self._handle_client(conn, addr, host_key))

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
            transport.local_version = (
                self._config.banner or "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
            )
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

            self._emit(
                self._make_event(
                    ip,
                    port,
                    "command",
                    payload=cmd,
                    session_id=session_id,
                )
            )

            if cmd in ("exit", "quit", "logout"):
                chan.sendall(b"logout\r\n")
                break

            response = SHELL_RESPONSES.get(cmd, f"-bash: {cmd}: command not found")
            chan.sendall(f"{response}\r\n".encode())
            chan.sendall(b"root@web-prod-01:~# ")
