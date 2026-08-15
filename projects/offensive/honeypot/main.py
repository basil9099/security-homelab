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
from event_logging.event_logger import EventLogger

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER = r"""
            [ Multi-Protocol Honeypot ]
        SSH  |  HTTP  |  FTP  |  Telnet
"""

# ---------------------------------------------------------------------------
# ANSI colours (graceful fallback)
# ---------------------------------------------------------------------------

try:
    from colorama import Fore, Style
    from colorama import init as _colorama_init

    _colorama_init(autoreset=True)
    _COLORS = True
except ImportError:
    _COLORS = False


def _c(text: str, color: str) -> str:
    if not _COLORS:
        return text
    return f"{color}{text}{Style.RESET_ALL}"


def _print_banner() -> None:
    if _COLORS:
        print(f"{Fore.CYAN}{_BANNER}{Style.RESET_ALL}")
    else:
        print(_BANNER)


def _print_disclaimer() -> None:
    msg = (
        "[!] LEGAL DISCLAIMER: This tool is intended for authorized security "
        "testing and educational purposes only. Unauthorized use against "
        "systems you do not own or have explicit permission to test is illegal."
    )
    if _COLORS:
        print(f"{Fore.YELLOW}{msg}{Style.RESET_ALL}\n")
    else:
        print(msg + "\n")


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
        help="Print events as JSON to stdout",
    )
    return parser


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _run_live(
    cfg: HoneypotConfig,
    logger: EventLogger,
    enabled_protocols: list[str],
    dashboard: bool,
    duration: int | None,
) -> None:
    """Start real protocol handlers and optionally the dashboard."""
    from protocols import available_protocols, get_handler

    handlers = []
    for name in enabled_protocols:
        if name not in available_protocols():
            print(f"[!] Unknown protocol: {name} (available: {available_protocols()})")
            continue
        proto_cfg = cfg.protocols.get(name)
        if not proto_cfg:
            continue
        handler_cls = get_handler(name)
        handler = handler_cls(proto_cfg, logger.log)
        handlers.append(handler)

    if not handlers:
        print("[!] No protocol handlers to start. Exiting.")
        return

    # Start each handler in its own daemon thread
    threads: list[threading.Thread] = []
    for h in handlers:
        t = threading.Thread(target=h.start, name=f"proto-{h.PROTOCOL_NAME}", daemon=True)
        t.start()
        threads.append(t)
        if _COLORS:
            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {h.PROTOCOL_NAME.upper():8s} listening on port {h._config.port}")
        else:
            print(f"  [+] {h.PROTOCOL_NAME.upper():8s} listening on port {h._config.port}")

    print()

    # Shutdown coordination
    stop = threading.Event()

    def _signal_handler(sig, frame):
        stop.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    if dashboard:
        _run_dashboard(logger, cfg.dashboard_refresh, stop, duration)
    else:
        if duration:
            stop.wait(timeout=duration)
        else:
            print("[*] Honeypot running. Press Ctrl+C to stop.\n")
            stop.wait()

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

    def _signal_handler(sig, frame):
        stop.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    sim_thread = threading.Thread(target=sim.run, args=(dur, stop), daemon=True)
    sim_thread.start()

    if dashboard:
        _run_dashboard(logger, cfg.dashboard_refresh, stop, dur)
    else:
        if dur:
            stop.wait(timeout=dur)
        else:
            stop.wait()

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
    """Start the Rich live dashboard."""
    try:
        from dashboard.live import Dashboard
        dash = Dashboard(logger, refresh_rate=refresh_rate)
        dash.run(stop, duration)
    except ImportError:
        print("[!] 'rich' is not installed — falling back to console output")
        if duration:
            stop.wait(timeout=duration)
        else:
            stop.wait()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    _print_banner()
    _print_disclaimer()

    # Load config
    cfg = HoneypotConfig.from_yaml(args.config)
    if args.log_file:
        cfg.log_file = args.log_file

    logger = EventLogger(log_file=cfg.log_file)

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
