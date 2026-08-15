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
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())
