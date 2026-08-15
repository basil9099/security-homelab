"""
protocols/base.py
=================
Abstract base class and registry for honeypot protocol handlers.

Adding a new protocol is a single-file operation:
  1. Create protocols/myproto.py
  2. Subclass ProtocolHandler, set PROTOCOL_NAME
  3. Apply the @register decorator
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
# Protocol handler registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, type[ProtocolHandler]] = {}


def register(cls: type[ProtocolHandler]) -> type[ProtocolHandler]:
    """Class decorator — registers a protocol handler by its PROTOCOL_NAME."""
    _REGISTRY[cls.PROTOCOL_NAME] = cls
    return cls


def get_handler(name: str) -> type[ProtocolHandler]:
    return _REGISTRY[name]


def available_protocols() -> list[str]:
    return list(_REGISTRY.keys())


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

    def _bind_server(self) -> socket.socket:
        """Create, bind, and return a listening TCP socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)  # allow periodic stop-event checks
        sock.bind(("0.0.0.0", self._config.port))
        sock.listen(5)
        self._server_socket = sock
        return sock
