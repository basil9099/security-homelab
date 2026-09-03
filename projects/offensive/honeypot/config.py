"""
config.py
=========
Configuration loading for the honeypot system.

Reads from a YAML file when available, otherwise uses sensible defaults.
All ports default to high (unprivileged) values so no root is required, and
listeners bind loopback only — exposing the honeypot to the network is an
explicit opt-in via the `network.bind_host` key.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ProtocolConfig:
    """Configuration for a single protocol handler."""

    enabled: bool = True
    port: int = 0
    banner: str = ""
    # Loopback by default: a honeypot that grabs every interface the moment it
    # starts is a liability on a workstation or any box with a routable address.
    # Set network.bind_host (or a per-protocol bind_host) to expose it.
    bind_host: str = "127.0.0.1"


@dataclass
class HoneypotConfig:
    """Top-level honeypot configuration."""

    protocols: dict[str, ProtocolConfig] = field(default_factory=dict)
    log_file: str = "honeypot_events.jsonl"
    log_to_console: bool = True
    dashboard_refresh: float = 0.5
    demo_duration: int = 60
    demo_rate: float = 2.0

    # -----------------------------------------------------------------
    # Factory helpers
    # -----------------------------------------------------------------

    @classmethod
    def default(cls) -> HoneypotConfig:
        """Return a configuration with sensible defaults."""
        return cls(
            protocols={
                "ssh": ProtocolConfig(
                    port=2222,
                    banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
                ),
                "http": ProtocolConfig(
                    port=8080,
                    banner="Apache/2.4.41 (Ubuntu)",
                ),
                "ftp": ProtocolConfig(
                    port=2121,
                    banner="220 ProFTPD 1.3.5 Server ready.",
                ),
                "telnet": ProtocolConfig(
                    port=2323,
                    banner="Ubuntu 22.04 LTS",
                ),
            },
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> HoneypotConfig:
        """Load configuration from a YAML file.

        Falls back to defaults for any missing keys.
        """
        try:
            import yaml
        except ImportError:
            print("[!] pyyaml not installed — using default configuration")
            return cls.default()

        path = Path(path)
        if not path.exists():
            return cls.default()

        with open(path) as fh:
            raw = yaml.safe_load(fh) or {}

        cfg = cls.default()

        # Network section — global bind host, overridable per protocol.
        global_bind = raw.get("network", {}).get("bind_host", ProtocolConfig.bind_host)
        for proto in cfg.protocols.values():
            proto.bind_host = global_bind

        # Protocols section
        for name, proto_data in raw.get("protocols", {}).items():
            if not isinstance(proto_data, dict):
                continue
            existing = cfg.protocols.get(name, ProtocolConfig())
            existing.enabled = proto_data.get("enabled", existing.enabled)
            existing.port = proto_data.get("port", existing.port)
            existing.banner = proto_data.get("banner", existing.banner)
            existing.bind_host = proto_data.get("bind_host", global_bind)
            cfg.protocols[name] = existing

        # Logging section
        log_cfg = raw.get("logging", {})
        cfg.log_file = log_cfg.get("file", cfg.log_file)
        cfg.log_to_console = log_cfg.get("console", cfg.log_to_console)

        # Dashboard section
        dash_cfg = raw.get("dashboard", {})
        cfg.dashboard_refresh = dash_cfg.get("refresh_rate", cfg.dashboard_refresh)

        # Demo section
        demo_cfg = raw.get("demo", {})
        cfg.demo_duration = demo_cfg.get("duration", cfg.demo_duration)
        cfg.demo_rate = demo_cfg.get("rate", cfg.demo_rate)

        return cfg
