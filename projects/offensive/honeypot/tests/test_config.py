"""Unit tests for honeypot configuration loading (config.py)."""

import textwrap

from config import HoneypotConfig, ProtocolConfig


def test_default_has_four_protocols():
    cfg = HoneypotConfig.default()
    assert set(cfg.protocols) == {"ssh", "http", "ftp", "telnet"}
    assert all(isinstance(p, ProtocolConfig) for p in cfg.protocols.values())
    # Ports default to unprivileged values so no root is required.
    assert cfg.protocols["ssh"].port == 2222
    assert cfg.protocols["http"].port == 8080
    assert all(p.port > 1024 for p in cfg.protocols.values())


def test_default_scalars():
    cfg = HoneypotConfig.default()
    assert cfg.log_file.endswith(".jsonl")
    assert cfg.log_to_console is True


def test_from_yaml_missing_file_returns_default(tmp_path):
    cfg = HoneypotConfig.from_yaml(tmp_path / "does-not-exist.yaml")
    # Falls back to defaults rather than raising.
    assert set(cfg.protocols) == {"ssh", "http", "ftp", "telnet"}


def test_from_yaml_overrides_merge_onto_defaults(tmp_path):
    yaml_file = tmp_path / "hp.yaml"
    yaml_file.write_text(
        textwrap.dedent(
            """
            protocols:
              ssh:
                port: 9999
                enabled: false
            logging:
              file: custom.jsonl
              console: false
            demo:
              duration: 5
            """
        )
    )
    cfg = HoneypotConfig.from_yaml(yaml_file)

    # Overridden values are applied...
    assert cfg.protocols["ssh"].port == 9999
    assert cfg.protocols["ssh"].enabled is False
    assert cfg.log_file == "custom.jsonl"
    assert cfg.log_to_console is False
    assert cfg.demo_duration == 5

    # ...while untouched keys keep their defaults.
    assert cfg.protocols["http"].port == 8080
    assert "OpenSSH" in cfg.protocols["ssh"].banner  # banner not overridden
