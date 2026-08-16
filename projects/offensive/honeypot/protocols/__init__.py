"""
protocols
=========
Honeypot protocol handler registry.

Importing this package auto-discovers all built-in handlers so
they register themselves via the ``@register`` decorator.
"""

# Auto-import built-in handlers to trigger registration.
from protocols import ftp, http, ssh, telnet
from protocols.base import (
    ProtocolHandler,
    available_protocols,
    get_handler,
    register,
)

__all__ = [
    "ProtocolHandler",
    "register",
    "get_handler",
    "available_protocols",
]
