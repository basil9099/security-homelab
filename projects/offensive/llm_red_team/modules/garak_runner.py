"""
garak engine
------------
Drives the ``garak`` CLI as an external tool, one invocation per probe family, and
collects each run's ``.report.jsonl`` into the scan directory.

Shelling out rather than importing garak keeps its dependency tree (torch and
friends) out of this project's ``requirements.txt`` and out of CI. If garak is
not installed, scans still run: the garak families are skipped with a reason and
the native engine carries on.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import config

#: garak has been renaming "model" to "target" one flag at a time, so the two
#: halves are not in sync: 0.16 accepts ``--target_type`` but still calls the
#: options file ``--generator_option_file``. Rather than pin a version, try the
#: combinations in order and keep the first that is not a usage error.
#: Verified against garak 0.16.0.
FLAG_CANDIDATES: tuple[tuple[str, str], ...] = (
    ("--target_type", "--generator_option_file"),  # garak 0.16
    ("--model_type", "--generator_option_file"),  # pre-rename
)

_USAGE_ERROR_MARKERS = ("unrecognized arguments", "invalid choice", "no such option")


@dataclass
class GarakRun:
    probe: str
    command: list[str] = field(default_factory=list)
    report_path: Path | None = None
    returncode: int | None = None
    skipped: bool = False
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.report_path is not None and self.report_path.is_file()


def garak_available() -> bool:
    return shutil.which(config.GARAK_BIN) is not None


def write_rest_config(path: Path, base_url: str, tier: str, timeout: int | None = None) -> Path:
    """Write the ``rest`` generator options that point garak at the target.

    Driving the target over REST rather than talking to a model directly is
    deliberate: garak then exercises the *application* — system prompt,
    retrieval, tool layer, output scanner — instead of a bare model. Those
    layers are where the findings that matter live.
    """
    options = {
        "rest": {
            "RestGenerator": {
                "name": f"target-{tier}",
                "uri": f"{base_url.rstrip('/')}/chat",
                "method": "post",
                "headers": {"Content-Type": "application/json"},
                # $INPUT is JSON-escaped by garak before substitution.
                "req_template_json_object": {"prompt": "$INPUT"},
                "response_json": True,
                "response_json_field": "response",
                "request_timeout": timeout or config.OLLAMA_TIMEOUT,
            }
        }
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(options, indent=2), encoding="utf-8")
    return path


def build_command(
    probe: str,
    option_file: Path,
    report_prefix: str,
    generations: int = config.GARAK_GENERATIONS,
    variant: int = 0,
) -> list[str]:
    type_flag, option_flag = FLAG_CANDIDATES[variant]
    return [
        config.GARAK_BIN,
        type_flag,
        "rest",
        option_flag,
        # Absolute: garak is invoked with cwd set to the run's output directory,
        # so a relative path here would be resolved against the wrong root and
        # every family would fail with FileNotFoundError.
        str(Path(option_file).resolve()),
        "--probes",
        probe,
        "--generations",
        str(generations),
        "--report_prefix",
        report_prefix,
    ]


def run_suite(
    probes: list[str],
    option_file: Path,
    out_dir: Path,
    generations: int = config.GARAK_GENERATIONS,
    dry_run: bool = False,
    timeout: int = 3600,
) -> list[GarakRun]:
    """Run each probe family and place its report in ``out_dir``."""
    runs: list[GarakRun] = []
    if not probes:
        return runs

    out_dir.mkdir(parents=True, exist_ok=True)
    available = garak_available()

    for probe in probes:
        prefix = f"garak-{probe.replace('.', '_')}"
        run = GarakRun(probe=probe, command=build_command(probe, option_file, prefix, generations))

        if dry_run:
            run.skipped = True
            run.reason = "dry run"
            runs.append(run)
            continue

        if not available:
            run.skipped = True
            run.reason = (
                f"{config.GARAK_BIN} not on PATH — install with "
                "`pip install -r requirements-scan.txt`"
            )
            runs.append(run)
            continue

        _execute(run, out_dir, prefix, option_file, generations, timeout)
        runs.append(run)

    return runs


def _execute(
    run: GarakRun,
    out_dir: Path,
    prefix: str,
    option_file: Path,
    generations: int,
    timeout: int,
) -> None:
    last_stderr = ""
    for variant in range(len(FLAG_CANDIDATES)):
        run.command = build_command(run.probe, option_file, prefix, generations, variant=variant)
        started = time.time()
        try:
            completed = subprocess.run(
                run.command,
                cwd=out_dir,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                # garak prints emoji in its progress output. Without this the
                # child inherits the legacy Windows code page and dies with
                # UnicodeEncodeError before writing a report.
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                encoding="utf-8",
                errors="replace",
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            run.skipped = True
            run.reason = f"garak invocation failed: {exc}"
            return

        run.returncode = completed.returncode
        last_stderr = (completed.stderr or "").strip()

        # A usage error means this build spells the flags differently; anything
        # else is a real result and we stop here.
        if any(marker in last_stderr.lower() for marker in _USAGE_ERROR_MARKERS):
            continue

        run.report_path = _collect_report(prefix, out_dir, newer_than=started)
        if run.report_path is None:
            run.skipped = True
            run.reason = (
                f"garak exited {completed.returncode} without producing a report "
                f"(is {run.probe!r} a probe family this garak version has? "
                f"check `garak --list_probes`); stderr: {last_stderr[-200:] or 'empty'}"
            )
        return

    run.skipped = True
    run.reason = f"no supported garak flag combination; stderr: {last_stderr[-200:] or 'empty'}"


def _collect_report(prefix: str, out_dir: Path, newer_than: float = 0.0) -> Path | None:
    """Find the report garak just wrote and make sure it lands in ``out_dir``.

    garak resolves ``--report_prefix`` against its own configured report
    directory, which varies by version and platform, so look in the likely places
    rather than assuming.

    ``newer_than`` guards against a stale hit: the prefix is reused for the same
    probe family across tiers, so a run that produced nothing would otherwise
    collect the *previous* tier's report and silently mis-attribute it.
    """
    for directory in _candidate_dirs(out_dir):
        matches = [
            path
            for path in directory.glob(f"{prefix}*.report.jsonl")
            # A second of slack: mtime granularity varies by filesystem.
            if path.stat().st_mtime >= newer_than - 1
        ]
        if not matches:
            continue
        found = max(matches, key=lambda p: p.stat().st_mtime)
        if found.parent == out_dir:
            return found
        destination = out_dir / found.name
        shutil.copy2(found, destination)
        return destination
    return None


def _candidate_dirs(out_dir: Path) -> list[Path]:
    dirs = [out_dir]
    data_home = os.environ.get("XDG_DATA_HOME")
    if data_home:
        dirs.append(Path(data_home) / "garak" / "garak_runs")
    dirs.append(Path.home() / ".local" / "share" / "garak" / "garak_runs")
    return [d for d in dirs if d.is_dir()]
