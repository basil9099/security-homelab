"""
main.py
=======
CLI entry point for the multi-protocol honeypot system.

Usage examples:
  # Start all protocol handlers
  python main.py

  # Start with live dashboard
  python main.py --dashboard

  # Run in demo mode with simulated attacks
  python main.py --demo --dashboard

  # Only enable specific protocols
  python main.py --protocols ssh http

  # Custom config file
  python main.py --config /path/to/honeypot.yaml
"""

from __future__ import annotations

import argparse
import signal
import threading

from config import HoneypotConfig
from event_logger import EventLogger

# ANSI colours — handled natively by Windows 10+ consoles and every POSIX terminal.
CYAN, GREEN, YELLOW, RESET = "\033[36m", "\033[32m", "\033[33m", "\033[0m"


def _print_banner() -> None:
    print(f"\n{CYAN}            [ Multi-Protocol Honeypot ]")
    print(f"        SSH  |  HTTP  |  FTP  |  Telnet{RESET}\n")


def _print_disclaimer() -> None:
    print(
        f"{YELLOW}[!] LEGAL DISCLAIMER: This tool is intended for authorized security "
        "testing and educational purposes only. Unauthorized use against "
        f"systems you do not own or have explicit permission to test is illegal.{RESET}\n"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Multi-protocol honeypot system for cybersecurity home labs.",
    )
    parser.add_argument(
        "--config", "-c",
        default="honeypot.yaml",
        help="Path to YAML config file (default: honeypot.yaml)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run with simulated attack traffic instead of real listeners",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Enable live terminal dashboard",
    )
    parser.add_argument(
        "--protocols",
        nargs="+",
        metavar="PROTO",
        help="Only enable specific protocols (e.g. ssh http)",
    )
    parser.add_argument(
        "--log-file",
        help="Override log file path",
    )
    parser.add_argument(
        "--duration",
        type=int,
        help="Run for N seconds then exit (useful for demo mode)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print events as JSON to stdout (ignored with --dashboard)",
    )
    return parser


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _install_signal_handlers(stop: threading.Event) -> None:
    """Set SIGINT/SIGTERM to trip *stop* instead of raising."""
    def _handler(sig, frame):
        stop.set()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


def _run_live(
    cfg: HoneypotConfig,
    logger: EventLogger,
    enabled_protocols: list[str],
    dashboard: bool,
    duration: int | None,
) -> None:
    """Start real protocol handlers and optionally the dashboard."""
    from protocols import HANDLERS

    handlers = []
    for name in enabled_protocols:
        if name not in HANDLERS:
            print(f"[!] Unknown protocol: {name} (available: {list(HANDLERS)})")
            continue
        proto_cfg = cfg.protocols.get(name)
        if not proto_cfg:
            continue
        handlers.append(HANDLERS[name](proto_cfg, logger.log))

    if not handlers:
        print("[!] No protocol handlers to start. Exiting.")
        return

    # Start each handler in its own daemon thread
    threads: list[threading.Thread] = []
    for h in handlers:
        t = threading.Thread(target=h.start, name=f"proto-{h.PROTOCOL_NAME}", daemon=True)
        t.start()
        threads.append(t)
        print(
            f"  {GREEN}[+]{RESET} {h.PROTOCOL_NAME.upper():8s} "
            f"listening on port {h._config.port}"
        )

    print()

    stop = threading.Event()
    _install_signal_handlers(stop)

    if dashboard:
        _run_dashboard(logger, cfg.dashboard_refresh, stop, duration)
    else:
        if not duration:
            print("[*] Honeypot running. Press Ctrl+C to stop.\n")
        stop.wait(timeout=duration)  # timeout=None blocks until signalled

    # Graceful shutdown
    print("\n[*] Shutting down handlers...")
    for h in handlers:
        h.stop()
    for t in threads:
        t.join(timeout=3)
    print("[*] Honeypot stopped.")


def _run_demo(
    cfg: HoneypotConfig,
    logger: EventLogger,
    dashboard: bool,
    duration: int | None,
) -> None:
    """Run the attack traffic simulator."""
    from demo.simulator import AttackSimulator

    dur = duration or cfg.demo_duration
    print(f"[*] Demo mode: generating simulated attacks for {dur}s at {cfg.demo_rate} events/s\n")

    sim = AttackSimulator(event_callback=logger.log, rate=cfg.demo_rate)

    stop = threading.Event()
    _install_signal_handlers(stop)

    sim_thread = threading.Thread(target=sim.run, args=(dur, stop), daemon=True)
    sim_thread.start()

    if dashboard:
        _run_dashboard(logger, cfg.dashboard_refresh, stop, dur)
    else:
        stop.wait(timeout=dur)

    stop.set()
    sim_thread.join(timeout=3)

    stats = logger.get_stats()
    print(f"\n[*] Demo complete. Total events generated: {stats['total']}")
    print(f"    Log file: {cfg.log_file}")


def _run_dashboard(
    logger: EventLogger,
    refresh_rate: float,
    stop: threading.Event,
    duration: int | None,
) -> None:
    """Start the Rich live dashboard, or just wait if rich is unavailable."""
    try:
        from dashboard.live import Dashboard
    except ImportError:
        print("[!] 'rich' is not installed — falling back to console output")
        stop.wait(timeout=duration)
        return

    Dashboard(logger, refresh_rate=refresh_rate).run(stop, duration)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = _build_parser().parse_args()

    _print_banner()
    _print_disclaimer()

    # Load config
    cfg = HoneypotConfig.from_yaml(args.config)
    if args.log_file:
        cfg.log_file = args.log_file

    # Echoing to stdout would corrupt the dashboard's rendering, so it is
    # suppressed whenever the dashboard is running. --json wins over the
    # config's human-readable console echo.
    can_echo = not args.dashboard
    logger = EventLogger(
        log_file=cfg.log_file,
        echo_json=args.json and can_echo,
        echo_console=cfg.log_to_console and not args.json and can_echo,
    )

    # Determine which protocols to enable
    if args.protocols:
        enabled = [p.lower() for p in args.protocols]
    else:
        enabled = [name for name, pc in cfg.protocols.items() if pc.enabled]

    if args.demo:
        _run_demo(cfg, logger, args.dashboard, args.duration)
    else:
        _run_live(cfg, logger, enabled, args.dashboard, args.duration)


if __name__ == "__main__":
    main()
