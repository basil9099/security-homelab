"""
protocols
=========
Honeypot protocol handlers, keyed by the name used in config and on the CLI.
"""

from protocols.base import ProtocolHandler
from protocols.ftp import FTPHandler
from protocols.http import HTTPHandler
from protocols.ssh import SSHHandler
from protocols.telnet import TelnetHandler

HANDLERS: dict[str, type[ProtocolHandler]] = {
    "ssh": SSHHandler,
    "http": HTTPHandler,
    "ftp": FTPHandler,
    "telnet": TelnetHandler,
}

__all__ = ["HANDLERS", "ProtocolHandler"]
