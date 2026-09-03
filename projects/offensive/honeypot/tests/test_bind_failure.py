"""Tests that a listener which fails to bind is reported as failed.

The bind used to happen inside the listener thread, while main.py printed
"listening on ..." immediately after Thread.start(). A refused bind — port in
use, privileged port, bad address — killed the thread silently and the banner
still claimed the service was up.
"""

import socket
import threading

import pytest
from config import ProtocolConfig
from protocols.ftp import FTPHandler
from protocols.http import HTTPHandler

# RFC 5737 TEST-NET-1: guaranteed not to be a local address, so bind() fails
# the same way on Linux and Windows.
UNBINDABLE = "192.0.2.1"


def _noop(event):
    pass


def test_bind_raises_when_the_address_cannot_be_assigned():
    handler = FTPHandler(ProtocolConfig(port=2121, bind_host=UNBINDABLE), _noop)
    with pytest.raises(OSError):
        handler.bind()


def test_http_bind_raises_when_the_address_cannot_be_assigned():
    handler = HTTPHandler(ProtocolConfig(port=8080, bind_host=UNBINDABLE), _noop)
    with pytest.raises(OSError):
        handler.bind()


def test_successful_bind_exposes_a_listening_socket():
    handler = FTPHandler(ProtocolConfig(port=0, bind_host="127.0.0.1"), _noop)
    try:
        handler.bind()
        host, port = handler._server_socket.getsockname()
        assert host == "127.0.0.1"
        assert port > 0
    finally:
        handler.stop()


def test_start_handlers_reports_failures_instead_of_claiming_success():
    import main

    class Failing:
        PROTOCOL_NAME = "ftp"

        def bind(self):
            raise OSError(98, "Address already in use")

        def start(self):
            raise AssertionError("must not start a handler that failed to bind")

    class Working:
        PROTOCOL_NAME = "telnet"

        def __init__(self):
            self.started = threading.Event()

        def bind(self):
            pass

        def bind_address(self):
            return ("127.0.0.1", 2323)

        def start(self):
            self.started.set()

    working = Working()
    threads, failures = main.start_handlers([Failing(), working])

    assert [name for name, _ in failures] == ["ftp"]
    assert "Address already in use" in failures[0][1]
    assert len(threads) == 1
    assert working.started.wait(timeout=2.0), "working handler should have started"


def test_ssh_bind_fails_loudly_when_paramiko_is_missing(monkeypatch):
    from protocols import ssh

    monkeypatch.setattr(ssh, "_HAS_PARAMIKO", False)
    handler = ssh.SSHHandler(ProtocolConfig(port=2222), _noop)

    with pytest.raises(RuntimeError, match="paramiko"):
        handler.bind()


def test_bound_port_is_actually_connectable():
    # A successful bind must mean the port is really accepting connections
    # before we report it as listening.
    handler = FTPHandler(ProtocolConfig(port=0, bind_host="127.0.0.1"), _noop)
    handler.bind()
    _, port = handler._server_socket.getsockname()
    threading.Thread(target=handler.start, daemon=True).start()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0):
            pass
    finally:
        handler.stop()
