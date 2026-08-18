"""
Framework mapping
-----------------
Turns probe families into control-framework language: OWASP Top 10 for LLM
Applications 2025 and MITRE ATLAS.

A raw garak run answers "did probe X fire". A report has to answer "which class
of risk is this, how bad, and what do we change" — that translation lives in
``mappings.yaml`` so adding a probe family is a data edit, not a code edit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cache, lru_cache

import config
import yaml

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class FamilyMapping:
    family: str
    title: str
    owasp_id: str
    owasp_name: str
    severity: str
    description: str
    remediation: str
    #: Rendered "AML.Txxxx Technique name" strings.
    atlas: tuple[str, ...] = field(default_factory=tuple)

    @property
    def owasp(self) -> str:
        if not self.owasp_id:
            return "unmapped"
        return f"{self.owasp_id} {self.owasp_name}"

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


@lru_cache(maxsize=1)
def _load() -> tuple[dict[str, dict], dict]:
    path = config.MAPPINGS_FILE
    if not path.is_file():
        raise FileNotFoundError(f"mapping table not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data.get("families", {}), data.get("default", {})


def _build(family: str, row: dict) -> FamilyMapping:
    return FamilyMapping(
        family=family,
        title=row.get("title", family),
        owasp_id=row.get("owasp_id", ""),
        owasp_name=row.get("owasp_name", ""),
        severity=row.get("severity", "medium"),
        description=(row.get("description") or "").strip(),
        remediation=(row.get("remediation") or "").strip(),
        atlas=tuple(
            " ".join(filter(None, (item.get("id", ""), item.get("name", ""))))
            for item in row.get("atlas") or []
        ),
    )


@cache
def lookup(family: str) -> FamilyMapping:
    """Map a probe family, falling back to the table's ``default`` row."""
    families, default = _load()
    if family in families:
        return _build(family, families[family])

    # garak probe classes occasionally arrive fully qualified
    # (``garak.probes.dan``); match on the trailing module name too.
    tail = family.split(".")[-1]
    if tail in families:
        return _build(family, families[tail])

    return _build(family, default)


def known_families() -> list[str]:
    families, _ = _load()
    return sorted(families)


def owasp_rollup(family_asr: dict[str, float]) -> dict[str, dict[str, object]]:
    """Aggregate per-family attack success rates up to OWASP categories.

    The category's rate is the worst of its families — a category is only as
    strong as the attack that got furthest through it, and averaging would let a
    long tail of low-scoring probes mask one critical hit.
    """
    rollup: dict[str, dict[str, object]] = {}
    for family, asr in family_asr.items():
        mapped = lookup(family)
        entry = rollup.setdefault(
            mapped.owasp,
            {
                "owasp_id": mapped.owasp_id,
                "owasp_name": mapped.owasp_name,
                "families": [],
                "asr": 0.0,
                "severity": mapped.severity,
            },
        )
        families_list = entry["families"]
        assert isinstance(families_list, list)
        families_list.append(family)
        entry["asr"] = max(float(entry["asr"]), asr)
        if mapped.severity_rank < SEVERITY_ORDER.get(str(entry["severity"]), 99):
            entry["severity"] = mapped.severity

    return dict(
        sorted(
            rollup.items(),
            key=lambda item: (-float(item[1]["asr"]), str(item[1]["owasp_id"])),
        )
    )
