#!/usr/bin/env python3
"""
LLM prompt-injection red-team framework
=======================================

Runs garak and a set of native probe packs against a deliberately-vulnerable LLM
application at three hardening tiers, then reports how much each tier's controls
actually reduced attack success.

    python main.py serve   --tier naive
    python main.py scan    --all-tiers --suite injection
    python main.py analyze runs/<timestamp>
    python main.py report  runs/<timestamp> --format all
    python main.py list    suites

Only ever point this at the bundled target application, or at a system you are
authorised to test.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import config
from modules import garak_runner, mapping, native_runner, parser, probes, reporter
from modules.scoring import defence_deltas, score_reports
from rich.console import Console
from rich.table import Table
from target.app import create_app
from target.backends import build_backend
from target.tiers import POLICIES, get_policy

console = Console()


# ---------------------------------------------------------------------------
# Serving
# ---------------------------------------------------------------------------


def _free_port(host: str, preferred: int) -> int:
    """Return ``preferred`` if it is free, otherwise an ephemeral port.

    Scanning three tiers in one run means binding three times in quick
    succession; falling back keeps a lingering TIME_WAIT socket from killing the
    scan half way through.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, preferred))
        except OSError:
            probe.bind((host, 0))
        return int(probe.getsockname()[1])


@contextmanager
def serve_in_thread(app, host: str, port: int) -> Iterator[str]:
    """Run ``app`` in a background thread for the duration of the block."""
    import uvicorn

    server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.monotonic() + 30
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError(f"target failed to start on {host}:{port}")

    try:
        yield f"http://{host}:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def build_target_app(tier: str, backend_name: str, canary: str):
    backend = build_backend(
        backend_name, config.OLLAMA_MODEL, config.OLLAMA_URL, config.OLLAMA_TIMEOUT
    )
    return create_app(tier=tier, backend=backend, canary=canary)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    canary = config.canary_token()
    app = build_target_app(args.tier, args.backend, canary)
    policy = get_policy(args.tier)

    console.print(f"[bold green]{config.TOOL_NAME}[/] target — tier [bold]{args.tier}[/]")
    console.print(f"  backend  : {args.backend}")
    console.print(f"  controls : {', '.join(policy.controls)}")
    console.print(f"  canary   : {canary}")
    console.print(f"  endpoint : http://{args.host}:{args.port}/chat\n")

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    suite = config.resolve_suite(args.suite)
    tiers = list(config.TIERS) if args.all_tiers else [args.tier]
    for tier in tiers:
        get_policy(tier)  # validate before doing any work

    run_dir = Path(args.out) if args.out else config.RUNS_DIR / _stamp()
    run_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold green]{config.TOOL_NAME}[/] scan")
    console.print(f"  suite    : {args.suite}")
    console.print(f"  tiers    : {', '.join(tiers)}")
    console.print(f"  backend  : {args.backend}")
    console.print(f"  garak    : {', '.join(suite['garak']) or 'none'}")
    console.print(f"  native   : {', '.join(suite['native']) or 'none'}")
    console.print(f"  output   : {run_dir}\n")

    use_garak = bool(suite["garak"]) and not args.no_garak
    if use_garak and not args.dry_run and not garak_runner.garak_available():
        console.print(
            f"[yellow]garak not found on PATH — skipping {len(suite['garak'])} garak "
            "families. Install with `pip install -r requirements-scan.txt`.[/]\n"
        )

    for tier in tiers:
        _scan_tier(tier, suite, run_dir, args, use_garak)

    if args.dry_run:
        console.print("[yellow]Dry run — no probes were sent.[/]")
        return 0

    return _analyse_and_report(run_dir, args.backend, formats=args.format)


def _scan_tier(
    tier: str,
    suite: dict[str, list[str]],
    run_dir: Path,
    args: argparse.Namespace,
    use_garak: bool,
) -> None:
    out_dir = run_dir / tier / args.suite
    out_dir.mkdir(parents=True, exist_ok=True)

    canary = config.canary_token()
    app = build_target_app(tier, args.backend, canary)

    console.print(f"[bold]▸ {tier}[/] — {', '.join(get_policy(tier).controls)}")

    if args.dry_run:
        if use_garak:
            option_file = garak_runner.write_rest_config(
                out_dir / "rest-config.json", f"http://{args.host}:{args.port}", tier
            )
            _run_garak(suite["garak"], option_file, out_dir, args)
    elif use_garak:
        # garak needs a real socket. The native engine is happy either way, so
        # both share one server and one canary.
        port = _free_port(args.host, args.port)
        with serve_in_thread(app, args.host, port) as base_url:
            option_file = garak_runner.write_rest_config(
                out_dir / "rest-config.json", base_url, tier
            )
            _run_native(suite["native"], native_runner.HttpTarget(base_url), canary, tier, out_dir, args)
            _run_garak(suite["garak"], option_file, out_dir, args)
    else:
        _run_native(suite["native"], native_runner.LocalTarget(app), canary, tier, out_dir, args)

    console.print("")


def _run_native(
    packs: list[str],
    client: native_runner.TargetClient,
    canary: str,
    tier: str,
    out_dir: Path,
    args: argparse.Namespace,
) -> None:
    def run(probe_list, filename):
        return native_runner.run_native(
            probe_list, client, canary, tier, out_dir / filename, args.generations, args.backend
        )

    if packs:
        result = run(probes.resolve_packs(packs), "native.report.jsonl")
        console.print(
            f"    native  {', '.join(packs)}: {result.hits}/{result.attempts} attempts hit"
        )

    # The benign control group always runs — utility is meaningless without it.
    control = run(probes.BENIGN, "benign.report.jsonl")
    console.print(
        f"    benign  control group: {control.attempts - control.hits}/{control.attempts} answered"
    )


def _run_garak(
    families: list[str], option_file: Path, out_dir: Path, args: argparse.Namespace
) -> None:
    runs = garak_runner.run_suite(
        families, option_file, out_dir, generations=args.generations, dry_run=args.dry_run
    )
    for run in runs:
        if args.dry_run:
            console.print(f"    [dim]$ {' '.join(run.command)}[/]")
        elif run.ok:
            console.print(f"    garak   {run.probe}: {run.report_path.name}")
        else:
            console.print(f"    [yellow]garak   {run.probe}: skipped — {run.reason}[/]")


def cmd_analyze(args: argparse.Namespace) -> int:
    return _analyse_and_report(Path(args.run_dir), args.backend, formats=None)


def cmd_report(args: argparse.Namespace) -> int:
    return _analyse_and_report(Path(args.run_dir), args.backend, formats=args.format)


def _analyse_and_report(run_dir: Path, backend: str, formats: str | None) -> int:
    if not run_dir.is_dir():
        console.print(f"[red]no such run directory: {run_dir}[/]")
        return 1

    reports = parser.parse_run_dir(run_dir)
    if not reports:
        console.print(f"[red]no .report.jsonl files under {run_dir}[/]")
        return 1

    backend = backend or next(
        (str(r.meta["backend"]) for r in reports if r.meta.get("backend")), ""
    )
    tiers = score_reports(reports)
    deltas = defence_deltas(tiers, config.BASELINE_TIER)
    _print_summary(tiers, deltas)

    if formats is None:
        return 0

    profile = reporter.build_profile(tiers, deltas, reports, run_dir, backend)
    console.print("")
    for name, path in reporter.write_reports(profile, run_dir, formats).items():
        console.print(f"  [green]{name:9}[/] {path}")
    return 0


def _print_summary(tiers, deltas) -> None:
    table = Table(title="Tier summary (ASR: lower is better)", title_justify="left")
    table.add_column("Tier")
    table.add_column("Attempts", justify="right")
    table.add_column("Hits", justify="right")
    table.add_column("Macro", justify="right")
    table.add_column("Pooled", justify="right")
    table.add_column("Utility", justify="right")
    table.add_column("Contained", justify="right")
    table.add_column("Δ Macro", justify="right")

    ordered = [t for t in config.TIERS if t in tiers] + [
        t for t in sorted(tiers) if t not in config.TIERS
    ]
    for name in ordered:
        score = tiers[name]
        delta = deltas.get(name)
        table.add_row(
            name,
            str(score.attempts),
            str(score.hits),
            f"{score.macro_asr * 100:.0f}%",
            f"{score.asr * 100:.0f}%",
            f"{score.utility * 100:.0f}%",
            str(score.contained),
            "baseline" if delta is None else f"{delta.overall * 100:+.0f} pts",
        )
    console.print("")
    console.print(table)

    matrix = Table(title="Attack success rate by probe family", title_justify="left")
    matrix.add_column("Family")
    matrix.add_column("OWASP")
    for name in ordered:
        matrix.add_column(name, justify="right")

    families = sorted({f for score in tiers.values() for f in score.families})
    for family in families:
        mapped = mapping.lookup(family)
        cells = []
        for name in ordered:
            score = tiers[name].families.get(family)
            cells.append("—" if score is None else f"{score.asr * 100:.0f}%")
        matrix.add_row(family, mapped.owasp_id or "—", *cells)
    console.print("")
    console.print(matrix)


def cmd_list(args: argparse.Namespace) -> int:
    if args.what == "suites":
        table = Table(title="Probe suites", title_justify="left")
        table.add_column("Suite")
        table.add_column("garak families")
        table.add_column("Native packs")
        for name, suite in config.SUITES.items():
            table.add_row(name, ", ".join(suite["garak"]) or "—", ", ".join(suite["native"]) or "—")
        console.print(table)

    elif args.what == "probes":
        table = Table(title="Native probes", title_justify="left")
        table.add_column("Pack")
        table.add_column("Probe")
        table.add_column("Detector")
        table.add_column("Doc")
        for pack, items in probes.PACKS.items():
            for probe in items:
                table.add_row(pack, probe.name, probe.detector, probe.doc_id or "—")
        for probe in probes.BENIGN:
            table.add_row("benign", probe.name, probe.detector, probe.doc_id or "—")
        console.print(table)

    elif args.what == "tiers":
        table = Table(title="Hardening tiers", title_justify="left")
        table.add_column("Tier")
        table.add_column("Controls")
        table.add_column("Description")
        for name, policy in POLICIES.items():
            table.add_row(name, ", ".join(policy.controls), policy.description)
        console.print(table)

    elif args.what == "mappings":
        table = Table(title="Framework mappings", title_justify="left")
        table.add_column("Family")
        table.add_column("OWASP")
        table.add_column("MITRE ATLAS")
        table.add_column("Severity")
        for family in mapping.known_families():
            mapped = mapping.lookup(family)
            table.add_row(
                family,
                mapped.owasp,
                ", ".join(mapped.atlas) or "—",
                mapped.severity,
            )
        console.print(table)

    return 0


# ---------------------------------------------------------------------------


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="llm-red-team",
        description="LLM prompt-injection red-team framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Use only against the bundled target or systems you are authorised to test.",
    )
    subs = root.add_subparsers(dest="command", required=True)

    def add_common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "--backend",
            choices=config.BACKENDS,
            default=config.DEFAULT_BACKEND,
            help="model backend (default: %(default)s)",
        )
        sub.add_argument("--host", default=config.DEFAULT_HOST)
        sub.add_argument("--port", type=int, default=config.DEFAULT_PORT)

    serve = subs.add_parser("serve", help="run the target application")
    serve.add_argument("--tier", choices=config.TIERS, default="naive")
    add_common(serve)
    serve.set_defaults(func=cmd_serve)

    scan = subs.add_parser("scan", help="run a probe suite against the target")
    group = scan.add_mutually_exclusive_group()
    group.add_argument("--tier", choices=config.TIERS, default="naive")
    group.add_argument("--all-tiers", action="store_true", help="scan every tier and compare them")
    scan.add_argument("--suite", choices=list(config.SUITES), default="quick")
    scan.add_argument(
        "--generations",
        type=int,
        default=config.GARAK_GENERATIONS,
        help="attempts per probe (default: %(default)s)",
    )
    scan.add_argument(
        "--no-garak", action="store_true", help="native packs only, even if garak is installed"
    )
    scan.add_argument(
        "--dry-run", action="store_true", help="print the garak commands without sending anything"
    )
    scan.add_argument("--out", help="write the run here instead of runs/<timestamp>")
    scan.add_argument("--format", choices=["json", "markdown", "html", "all"], default="all")
    add_common(scan)
    scan.set_defaults(func=cmd_scan)

    analyze = subs.add_parser("analyze", help="summarise a completed run")
    analyze.add_argument("run_dir")
    analyze.add_argument("--backend", default="")
    analyze.set_defaults(func=cmd_analyze)

    report = subs.add_parser("report", help="write reports for a completed run")
    report.add_argument("run_dir")
    report.add_argument("--format", choices=["json", "markdown", "html", "all"], default="all")
    report.add_argument("--backend", default="")
    report.set_defaults(func=cmd_report)

    listing = subs.add_parser("list", help="show suites, probes, tiers or mappings")
    listing.add_argument("what", choices=["suites", "probes", "tiers", "mappings"])
    listing.set_defaults(func=cmd_list)

    return root


def main(argv: list[str] | None = None) -> int:
    # Console output uses box-drawing and Greek glyphs that the legacy Windows
    # code page cannot encode; without this the tool dies mid-scan on cp1252.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (ValueError, RuntimeError) as exc:
        console.print(f"[red]error:[/] {exc}")
        return 1
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
