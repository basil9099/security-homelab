"""
Native engine
-------------
Fires the packs in :mod:`modules.probes` at the target and writes results in
**garak's** ``.report.jsonl`` shape — ``init`` / ``attempt`` / ``eval`` records
with the same field names and the same score polarity.

Matching garak's format rather than inventing one means :mod:`modules.parser`,
:mod:`modules.scoring` and :mod:`modules.reporter` never learn which engine
produced a finding. Adding a probe pack costs nothing downstream.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import config

from modules import detectors
from modules.probes import Probe

PROBE_PREFIX = config.ENGINE_NAME


class TargetClient(Protocol):
    """Anything that can send one turn to the target application."""

    def chat(
        self, prompt: str, doc_id: str | None = None, confirmed: bool = False
    ) -> dict[str, Any]: ...


class HttpTarget:
    """Talks to a running instance over HTTP — the same surface garak drives."""

    def __init__(self, base_url: str, timeout: int = 120) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def chat(
        self, prompt: str, doc_id: str | None = None, confirmed: bool = False
    ) -> dict[str, Any]:
        import requests

        response = requests.post(
            f"{self.base_url}/chat",
            json={"prompt": prompt, "doc_id": doc_id, "confirmed": confirmed},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()


class LocalTarget:
    """In-process target. No socket, no server — what the tests use."""

    def __init__(self, app: Any) -> None:
        from fastapi.testclient import TestClient

        self._client = TestClient(app)

    def chat(
        self, prompt: str, doc_id: str | None = None, confirmed: bool = False
    ) -> dict[str, Any]:
        response = self._client.post(
            "/chat", json={"prompt": prompt, "doc_id": doc_id, "confirmed": confirmed}
        )
        response.raise_for_status()
        return response.json()


@dataclass
class NativeResult:
    report_path: Path
    attempts: int
    hits: int


def probe_classname(probe: Probe) -> str:
    return f"{PROBE_PREFIX}.{probe.pack}.{probe.name}"


def detector_name(probe: Probe) -> str:
    return f"{PROBE_PREFIX}.{probe.detector}"


def run_native(
    probes: Iterable[Probe],
    client: TargetClient,
    canary: str,
    tier: str,
    report_path: Path,
    generations: int = 1,
    backend: str = "",
) -> NativeResult:
    """Fire every probe ``generations`` times and write a garak-shaped report."""
    probes = list(probes)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    run_id = str(uuid.uuid4())
    # (probe, detector) -> [passed, total]
    tally: dict[tuple[str, str], list[int]] = {}
    total_hits = 0
    seq = 0

    with report_path.open("w", encoding="utf-8") as handle:
        _write(
            handle,
            {
                "entry_type": "init",
                "engine": PROBE_PREFIX,
                "tool_version": config.VERSION,
                "start_time": datetime.now(UTC).isoformat(),
                "run": run_id,
                "tier": tier,
                # Recorded so `analyze`/`report` can name the backend later
                # without being told again on the command line.
                "backend": backend,
            },
        )

        for probe in probes:
            classname = probe_classname(probe)
            det_name = detector_name(probe)
            key = (classname, det_name)
            tally.setdefault(key, [0, 0])

            for _ in range(generations):
                payload = client.chat(probe.prompt, doc_id=probe.doc_id)
                attempt = detectors.Attempt(
                    probe=probe,
                    response=payload.get("response", ""),
                    canary=canary,
                    blocked=payload.get("blocked", False),
                    tool_calls=payload.get("tool_calls", []),
                    meta=payload.get("meta", {}),
                )
                score = detectors.run_detector(probe.detector, attempt)
                hit = detectors.is_hit(score)
                total_hits += hit
                tally[key][1] += 1
                tally[key][0] += not hit

                _write(
                    handle,
                    {
                        "entry_type": "attempt",
                        "uuid": str(uuid.uuid4()),
                        "seq": seq,
                        "status": 2,
                        "probe_classname": classname,
                        "probe_params": {"pack": probe.pack, "doc_id": probe.doc_id},
                        "targets": [],
                        "prompt": probe.prompt,
                        "outputs": [attempt.response],
                        "detector_results": {det_name: [score]},
                        "goal": probe.goal,
                        "notes": {
                            "tier": tier,
                            "blocked": attempt.blocked,
                            "tool_calls": attempt.tool_calls,
                            "raw_leak": attempt.meta.get("raw_leak"),
                            "delivered_leak": attempt.meta.get("delivered_leak"),
                            "injection_score": attempt.meta.get("injection_score"),
                            "injection_labels": attempt.meta.get("injection_labels"),
                            "output_scan": attempt.meta.get("output_scan"),
                        },
                    },
                )
                seq += 1

        for (classname, det_name), (passed, total) in tally.items():
            _write(
                handle,
                {
                    "entry_type": "eval",
                    "probe": classname,
                    "detector": det_name,
                    "passed": passed,
                    "total": total,
                },
            )

    return NativeResult(report_path=report_path, attempts=seq, hits=total_hits)


def _write(handle: Any, record: dict[str, Any]) -> None:
    handle.write(json.dumps(record) + "\n")
