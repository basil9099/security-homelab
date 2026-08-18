"""
Report parser
-------------
Reads ``.report.jsonl`` files — garak's and the native engine's alike — into one
normalised shape.

garak packs several generations into a single ``attempt`` record: ``outputs`` is
a list and each entry in ``detector_results`` is a parallel list of scores. That
is flattened here so one :class:`Finding` is always one prompt/response pair with
one score, whichever engine produced it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from modules.detectors import HIT_THRESHOLD
from modules.native_runner import PROBE_PREFIX


def family_of(classname: str) -> str:
    """Collapse a probe class to the family reports group by.

    ``promptinject.HijackHateHumans``   -> ``promptinject``
    ``native.canary_exfil.direct_ask``   -> ``native.canary_exfil``
    """
    parts = classname.split(".")
    if parts[0] == PROBE_PREFIX and len(parts) >= 2:
        return ".".join(parts[:2])
    return parts[0]


@dataclass
class Finding:
    probe: str
    family: str
    detector: str
    prompt: str
    output: str
    score: float
    goal: str = ""
    notes: dict[str, Any] = field(default_factory=dict)

    @property
    def hit(self) -> bool:
        return self.score >= HIT_THRESHOLD


@dataclass
class EvalRow:
    probe: str
    family: str
    detector: str
    passed: int
    total: int
    #: garak reports failures explicitly and separately counts ``nones``
    #: (attempts the detector could not score), so ``total - passed`` is not the
    #: failure count. Trust the reported number whenever there is one.
    fails: int | None = None

    @property
    def failed(self) -> int:
        if self.fails is not None:
            return self.fails
        return max(self.total - self.passed, 0)

    @property
    def asr(self) -> float:
        """Attack success rate: the share of generations the detector flagged."""
        return self.failed / self.total if self.total else 0.0


@dataclass
class Report:
    path: Path
    engine: str
    tier: str
    findings: list[Finding] = field(default_factory=list)
    evals: list[EvalRow] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


def parse_report(path: Path, tier: str = "", engine: str = "") -> Report:
    """Parse one ``.report.jsonl``."""
    report = Report(path=path, engine=engine, tier=tier)

    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                # garak occasionally emits a partial trailing line if a run is
                # interrupted; a truncated tail should not sink the analysis.
                continue

            entry = record.get("entry_type")
            if entry in ("init", "start_run setup"):
                _absorb_init(report, record)
            elif entry == "attempt" and record.get("status") == 2:
                report.findings.extend(_findings_from_attempt(record))
            elif entry == "eval":
                report.evals.append(_eval_row(record))

    if not report.evals:
        report.evals = _evals_from_findings(report.findings)
    if not report.engine:
        report.engine = _infer_engine(report)

    return report


def parse_run_dir(run_dir: Path) -> list[Report]:
    """Parse every report under ``runs/<ts>/<tier>/<suite>/``.

    Tier is recovered from the directory layout, which is how a single scan's
    reports stay attributable after the fact.
    """
    reports: list[Report] = []
    for path in sorted(run_dir.rglob("*.report.jsonl")):
        tier = _tier_from_path(path, run_dir)
        reports.append(parse_report(path, tier=tier))
    return reports


# ---------------------------------------------------------------------------


def _tier_from_path(path: Path, run_dir: Path) -> str:
    try:
        return path.relative_to(run_dir).parts[0]
    except (ValueError, IndexError):
        return ""


def _absorb_init(report: Report, record: dict[str, Any]) -> None:
    for key in ("garak_version", "tool_version", "start_time", "run", "engine", "backend"):
        if key in record:
            report.meta[key] = record[key]
    if not report.tier and record.get("tier"):
        report.tier = record["tier"]


def _infer_engine(report: Report) -> str:
    if report.meta.get("engine"):
        return str(report.meta["engine"])
    if any(row.probe.startswith(f"{PROBE_PREFIX}.") for row in report.evals):
        return PROBE_PREFIX
    return "garak"


def _findings_from_attempt(record: dict[str, Any]) -> list[Finding]:
    probe = record.get("probe_classname", "unknown")
    prompt = _as_text(record.get("prompt", ""))
    outputs = record.get("outputs") or [""]
    goal = record.get("goal", "")
    notes = record.get("notes") or {}

    findings: list[Finding] = []
    for detector, scores in (record.get("detector_results") or {}).items():
        for index, score in enumerate(scores):
            output = outputs[index] if index < len(outputs) else ""
            findings.append(
                Finding(
                    probe=probe,
                    family=family_of(probe),
                    detector=detector,
                    prompt=prompt,
                    output=_as_text(output),
                    score=float(score),
                    goal=goal,
                    notes=notes,
                )
            )
    return findings


#: Container keys are unwrapped before value keys, so a conversation object
#: descends to its last turn rather than stringifying the whole structure.
_TEXT_KEYS = ("conversations", "turns", "content", "text", "prompt")


def _as_text(value: Any) -> str:
    """Pull the plain text out of a garak prompt or output.

    Older garak wrote these as bare strings. Current versions nest them —
    ``{"turns": [{"role": "user", "content": {"text": "..."}}]}`` for prompts and
    ``{"text": "...", "lang": "en"}`` for outputs — so unwrap recursively rather
    than assuming a depth.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return _as_text(value[-1]) if value else ""
    if isinstance(value, dict):
        for key in _TEXT_KEYS:
            if key in value:
                return _as_text(value[key])
    if value is None:
        return ""
    return str(value)


def _eval_row(record: dict[str, Any]) -> EvalRow:
    probe = record.get("probe", "unknown")
    total = (
        record.get("total_evaluated") or record.get("total_processed") or record.get("total") or 0
    )
    fails = record.get("fails")
    return EvalRow(
        probe=probe,
        family=family_of(probe),
        detector=record.get("detector", "unknown"),
        passed=int(record.get("passed", 0)),
        total=int(total),
        fails=None if fails is None else int(fails),
    )


def _evals_from_findings(findings: list[Finding]) -> list[EvalRow]:
    """Rebuild aggregates when a report has no ``eval`` records."""
    tally: dict[tuple[str, str], list[int]] = {}
    for finding in findings:
        key = (finding.probe, finding.detector)
        row = tally.setdefault(key, [0, 0])
        row[0] += not finding.hit
        row[1] += 1
    return [
        EvalRow(probe=probe, family=family_of(probe), detector=detector, passed=passed, total=total)
        for (probe, detector), (passed, total) in sorted(tally.items())
    ]
