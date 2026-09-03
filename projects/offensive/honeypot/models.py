"""
models.py
=========
Core data models for the honeypot system.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime


@dataclass
class HoneypotEvent:
    """A single event captured by a honeypot protocol handler."""

    protocol: str
    src_ip: str
    src_port: int
    dst_port: int
    event_type: str  # connection, credential_attempt, command, request, disconnect
    payload: str = ""
    credentials: dict | None = None
    session_id: str = ""
    metadata: dict = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


# ---------------------------------------------------------------------------
# Credential display helpers
#
# Capturing attacker credentials is the point of the honeypot, so the full
# value is always written to the JSONL record. Live views (console + dashboard)
# route through mask_password() instead: those outputs end up in scrollback,
# screen recordings and committed screenshots, where a plaintext password is a
# leak waiting to happen.
# ---------------------------------------------------------------------------

_PASSWORD_MASK = "********"  # fixed width: reveals nothing about the real length


def mask_password(password: str) -> str:
    """Return a masked stand-in for *password* (empty stays empty)."""
    return _PASSWORD_MASK if password else ""


def format_credentials(credentials: dict | None, *, mask: bool = True) -> str:
    """Render ``username:password`` for display. Masks the password by default."""
    if not credentials:
        return ""
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    shown = mask_password(password) if mask else password
    if not username and not shown:
        return ""
    return f"{username}:{shown}"
