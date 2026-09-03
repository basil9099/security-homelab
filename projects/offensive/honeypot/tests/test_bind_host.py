"""Tests for the listener bind address.

A honeypot that binds every interface the moment it starts is a liability on a
workstation or a lab box with a routable address, so loopback is the default
and exposure has to be asked for explicitly.
"""

import textwrap

from config import HoneypotConfig, ProtocolConfig
from protocols.ftp import FTPHandler
from protocols.http import HTTPHandler


def _noop(event):
    pass


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_protocol_config_defaults_to_loopback():
    assert ProtocolConfig().bind_host == "127.0.0.1"


def test_default_config_binds_every_protocol_to_loopback():
    cfg = HoneypotConfig.default()
    assert all(p.bind_host == "127.0.0.1" for p in cfg.protocols.values())


def test_global_bind_host_opts_every_protocol_into_exposure(tmp_path):
    yaml_file = tmp_path / "hp.yaml"
    yaml_file.write_text(
        textwrap.dedent(
            """
            network:
              bind_host: "0.0.0.0"
            """
        )
    )
    cfg = HoneypotConfig.from_yaml(yaml_file)
    assert all(p.bind_host == "0.0.0.0" for p in cfg.protocols.values())


def test_per_protocol_bind_host_overrides_the_global(tmp_path):
    yaml_file = tmp_path / "hp.yaml"
    yaml_file.write_text(
        textwrap.dedent(
            """
            network:
              bind_host: "0.0.0.0"
            protocols:
              ssh:
                bind_host: "127.0.0.1"
            """
        )
    )
    cfg = HoneypotConfig.from_yaml(yaml_file)
    assert cfg.protocols["ssh"].bind_host == "127.0.0.1"
    assert cfg.protocols["http"].bind_host == "0.0.0.0"


def test_yaml_without_network_section_stays_on_loopback(tmp_path):
    yaml_file = tmp_path / "hp.yaml"
    yaml_file.write_text("protocols:\n  ssh:\n    port: 9999\n")
    cfg = HoneypotConfig.from_yaml(yaml_file)
    assert cfg.protocols["ssh"].bind_host == "127.0.0.1"


# ---------------------------------------------------------------------------
# Handlers actually use it
# ---------------------------------------------------------------------------


def test_bind_address_pairs_configured_host_with_port():
    handler = FTPHandler(ProtocolConfig(port=2121), _noop)
    assert handler.bind_address() == ("127.0.0.1", 2121)

    exposed = FTPHandler(ProtocolConfig(port=2121, bind_host="0.0.0.0"), _noop)
    assert exposed.bind_address() == ("0.0.0.0", 2121)


def test_socket_listener_binds_the_configured_host_not_all_interfaces(monkeypatch):
    bound = []

    class FakeSocket:
        def setsockopt(self, *a):
            pass

        def settimeout(self, *a):
            pass

        def bind(self, address):
            bound.append(address)

        def listen(self, *a):
            pass

    monkeypatch.setattr("protocols.base.socket.socket", lambda *a, **k: FakeSocket())

    FTPHandler(ProtocolConfig(port=2121), _noop)._bind_server()

    assert bound == [("127.0.0.1", 2121)]


def test_http_listener_binds_the_configured_host_not_all_interfaces(monkeypatch):
    bound = []

    class FakeHTTPServer:
        def __init__(self, address, handler_cls):
            bound.append(address)

        def server_close(self):
            pass

    monkeypatch.setattr("protocols.http.HTTPServer", FakeHTTPServer)

    handler = HTTPHandler(ProtocolConfig(port=8080), _noop)
    handler.stop()  # pre-set the stop flag so start() falls straight through
    handler.start()

    assert bound == [("127.0.0.1", 8080)]
