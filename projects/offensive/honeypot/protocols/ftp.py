"""
protocols/ftp.py
================
FTP honeypot handler.

Implements a minimal FTP state machine to capture credentials
and observe attacker command sequences.
"""

from __future__ import annotations

import socket
import uuid

from protocols.base import ProtocolHandler

# Fake directory listing
_FAKE_LISTING = (
    "-rw-r--r--   1 root  root      2048 Jan 10 14:22 backup.tar.gz\n"
    "-rw-r--r--   1 root  root       512 Jan 12 10:15 config.yml\n"
    "drwxr-xr-x   2 root  root      4096 Jan 13 08:30 data\n"
    "-rw-------   1 root  root      1024 Jan 14 16:45 credentials.txt\n"
    "-rwxr-xr-x   1 root  root      8192 Jan 15 09:00 deploy.sh\n"
)


class FTPHandler(ProtocolHandler):
    """FTP honeypot emulating a ProFTPD server."""

    PROTOCOL_NAME = "ftp"

    def start(self) -> None:
        self._accept_loop(self._handle_client)

    def _handle_client(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        ip, port = addr
        session_id = uuid.uuid4().hex[:10]
        conn.settimeout(30)

        self._emit(self._make_event(ip, port, "connection", session_id=session_id))

        try:
            banner = self._config.banner or "220 ProFTPD 1.3.5 Server ready."
            if not banner.startswith("220"):
                banner = f"220 {banner}"
            conn.sendall(f"{banner}\r\n".encode())

            username = ""

            for _ in range(30):  # max commands per session
                try:
                    data = conn.recv(1024)
                except (TimeoutError, OSError):
                    break
                if not data:
                    break

                line = data.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue

                parts = line.split(None, 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                self._emit(
                    self._make_event(
                        ip,
                        port,
                        "command",
                        payload=line,
                        session_id=session_id,
                    )
                )

                response = self._handle_command(cmd, arg, username)

                # Track state
                if cmd == "USER":
                    username = arg
                elif cmd == "PASS" and username:
                    self._emit(
                        self._make_event(
                            ip,
                            port,
                            "credential_attempt",
                            credentials={"username": username, "password": arg},
                            session_id=session_id,
                        )
                    )

                conn.sendall(f"{response}\r\n".encode())

                if cmd == "QUIT":
                    break

        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            self._emit(self._make_event(ip, port, "disconnect", session_id=session_id))
            conn.close()

    def _handle_command(self, cmd: str, arg: str, username: str) -> str:
        """Return the FTP response string for a given command."""
        responses: dict[str, str] = {
            "USER": f"331 Password required for {arg}",
            "PASS": "230 Login successful." if username else "503 Login with USER first.",
            "SYST": "215 UNIX Type: L8",
            "FEAT": "211-Features:\r\n PASV\r\n UTF8\r\n211 End",
            "PWD": '257 "/" is the current directory',
            "CWD": "250 Directory changed.",
            "TYPE": "200 Type set to I." if arg.upper() == "I" else "200 Type set to A.",
            "PASV": "227 Entering Passive Mode (10,10,10,150,19,136).",
            "LIST": f"150 Opening data connection.\r\n{_FAKE_LISTING}226 Transfer complete.",
            "RETR": "550 Permission denied.",
            "STOR": "550 Permission denied.",
            "DELE": "550 Permission denied.",
            "MKD": "550 Permission denied.",
            "RMD": "550 Permission denied.",
            "QUIT": "221 Goodbye.",
            "NOOP": "200 NOOP ok.",
            "HELP": "214 The following commands are recognized: USER PASS SYST QUIT LIST PWD CWD",
        }
        return responses.get(cmd, f"502 Command '{cmd}' not implemented.")
