"""
protocols/base.py
=================
Abstract base class for honeypot protocol handlers.

Adding a new protocol is a single-file operation:
  1. Create protocols/myproto.py
  2. Subclass ProtocolHandler, set PROTOCOL_NAME
  3. Add it to the HANDLERS map in protocols/__init__.py
"""

from __future__ import annotations

import socket
import threading
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable

from config import ProtocolConfig
from models import HoneypotEvent

# ---------------------------------------------------------------------------
# Fake shell responses, shared by the SSH and Telnet handlers
# ---------------------------------------------------------------------------

SHELL_RESPONSES: dict[str, str] = {
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


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class ProtocolHandler(ABC):
    """Base class for all honeypot protocol emulators.

    Each handler runs a blocking listener in its own daemon thread.
    Events are pushed to the central logger via ``_emit``.
    """

    PROTOCOL_NAME: str = ""

    def __init__(
        self,
        config: ProtocolConfig,
        event_callback: Callable[[HoneypotEvent], None],
    ) -> None:
        self._config = config
        self._emit = event_callback
        self._stop_event = threading.Event()
        self._server_socket: socket.socket | None = None

    # ---- lifecycle --------------------------------------------------------

    @abstractmethod
    def start(self) -> None:
        """Start listening. Runs in its own thread. Must be blocking until
        ``_stop_event`` is set."""
        ...

    def stop(self) -> None:
        """Signal the handler to shut down gracefully."""
        self._stop_event.set()
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass

    # ---- helpers ----------------------------------------------------------

    def _make_event(
        self,
        src_ip: str,
        src_port: int,
        event_type: str,
        payload: str = "",
        credentials: dict | None = None,
        session_id: str = "",
        metadata: dict | None = None,
    ) -> HoneypotEvent:
        """Construct a HoneypotEvent with common fields pre-filled."""
        return HoneypotEvent(
            protocol=self.PROTOCOL_NAME,
            src_ip=src_ip,
            src_port=src_port,
            dst_port=self._config.port,
            event_type=event_type,
            payload=payload,
            credentials=credentials,
            session_id=session_id or uuid.uuid4().hex[:10],
            metadata=metadata or {},
        )

    def bind_address(self) -> tuple[str, int]:
        """The (host, port) this handler listens on.

        Single source of truth for every listener so no protocol can quietly
        bind a wider interface than the configuration asked for.
        """
        return (self._config.bind_host, self._config.port)

    def bind(self) -> None:
        """Claim the listening address.

        Call this from the main thread *before* starting the handler's thread:
        a bind that fails inside the thread kills it silently, and the caller
        goes on to report a service that is not listening. Raises OSError when
        the address is unavailable (in use, privileged, or not local).
        """
        self._bind_server()

    def _bind_server(self) -> socket.socket:
        """Create, bind, and return a listening TCP socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)  # allow periodic stop-event checks
        sock.bind(self.bind_address())
        sock.listen(5)
        self._server_socket = sock
        return sock

    def _accept_loop(
        self,
        handle: Callable[[socket.socket, tuple[str, int]], None],
    ) -> None:
        """Accept until stopped, dispatching each client to *handle*.

        Uses the socket bind() already claimed, binding here only if the caller
        skipped that step.
        """
        sock = self._server_socket or self._bind_server()
        while not self._stop_event.is_set():
            try:
                conn, addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
