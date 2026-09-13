"""Discovery and parsing of detection rules.

Every rule is a directory under `rules/` containing detection.yml, search.spl,
savedsearches.conf and an events/ directory of JSONL fixtures. This module is
the only place that knows that layout; both test layers go through it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "rules"


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _parse_conf(text: str) -> dict[str, dict[str, str]]:
    """Parse a Splunk .conf file.

    configparser is not used: Splunk continues a long value with a trailing
    backslash, which configparser does not understand (it expects indented
    continuation lines). Joining those continuations is the whole job here.
    """
    stanzas: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    key: str | None = None

    for raw in text.splitlines():
        line = raw.rstrip("\n")
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        if key is not None and current is not None:
            # Previous line ended with a backslash: this line continues it.
            current[key] += " " + stripped.removesuffix("\\").strip()
            key = key if stripped.endswith("\\") else None
            continue

        if stripped.startswith("[") and stripped.endswith("]"):
            current = {}
            stanzas[stripped[1:-1]] = current
            continue

        if "=" in stripped and current is not None:
            name, _, value = stripped.partition("=")
            name = name.strip()
            value = value.strip()
            current[name] = value.removesuffix("\\").strip()
            key = name if value.endswith("\\") else None

    return stanzas


@dataclass(frozen=True)
class Rule:
    path: Path
    meta: dict
    spl: str

    @property
    def id(self) -> str:
        return self.path.name

    @cached_property
    def true_positive_events(self) -> list[dict]:
        return _read_jsonl(self.path / "events" / "true_positive.jsonl")

    @cached_property
    def benign_events(self) -> list[dict]:
        return _read_jsonl(self.path / "events" / "benign.jsonl")

    @cached_property
    def savedsearch(self) -> dict[str, str]:
        conf = self.path / "savedsearches.conf"
        if not conf.exists():
            return {}
        stanzas = _parse_conf(conf.read_text(encoding="utf-8"))
        if len(stanzas) != 1:
            raise ValueError(f"{self.id}: expected exactly one stanza, found {len(stanzas)}")
        return next(iter(stanzas.values()))


def load_rules(rules_dir: Path = RULES_DIR) -> list[Rule]:
    rules = []
    for rule_dir in sorted(p for p in rules_dir.iterdir() if p.is_dir()):
        meta = yaml.safe_load((rule_dir / "detection.yml").read_text(encoding="utf-8"))
        spl = (rule_dir / "search.spl").read_text(encoding="utf-8").strip()
        rules.append(Rule(path=rule_dir, meta=meta, spl=spl))
    return rules


def normalise_spl(text: str) -> str:
    """Collapse a search to one whitespace-normalised line for comparison."""
    return " ".join(text.replace("\\\n", " ").split())


INDEX_RE = re.compile(r"\bindex\s*=\s*(\S+)")


def substitute_index(spl: str, index: str) -> str:
    """Point a rule's search at a test index.

    The rule names the production index; fixtures load into a per-rule test
    index. Asserting there is exactly one `index=` term means the rewrite can
    neither miss a second one nor silently apply twice.
    """
    matches = INDEX_RE.findall(spl)
    if len(matches) != 1:
        raise ValueError(f"expected exactly one index= term, found {len(matches)}: {matches}")
    return INDEX_RE.sub(f"index={index}", spl, count=1)


# Field extraction is a heuristic, not an SPL parser. It recognises the four
# shapes these detections use to read a field, then subtracts every name the
# search creates with `AS`. Case deliberately plays no part in deciding what is
# a field: Windows event fields happen to be capitalised, but a lowercase name
# such as `src_ip` must be reported like any other. Splunk's default fields and
# search arguments are excluded by name instead.
_FILTER_RE = re.compile(r"\b([A-Za-z_]\w*)\s*=(?!=)")
_AGG_RE = re.compile(r"\b(?:dc|values|count|min|max|latest|earliest)\(\s*([^)]*?)\s*\)")
_MATCH_RE = re.compile(r"\bmatch\(\s*(\w+)\s*,")
_CLAUSE_RE = re.compile(r"\b(?:BY|table)\s+([^|]+)", re.IGNORECASE)
_CREATED_RE = re.compile(r"\bAS\s+(\w+)", re.IGNORECASE)
_IDENTIFIER_RE = re.compile(r"[A-Za-z_]\w*")

# Read by every search and never declared per detection.
_NOT_DECLARED = {"_time", "index", "sourcetype", "source", "host", "span", "earliest", "latest"}
_KEYWORDS = {"AS", "BY", "NOT", "AND", "OR"}


def spl_field_references(spl: str) -> set[str]:
    """Field names a search reads but does not itself create."""
    found: set[str] = set(_FILTER_RE.findall(spl)) | set(_MATCH_RE.findall(spl))

    for group in _AGG_RE.findall(spl) + _CLAUSE_RE.findall(spl):
        found.update(t for t in re.split(r"[,\s]+", group) if _IDENTIFIER_RE.fullmatch(t))

    created = set(_CREATED_RE.findall(spl))
    return {f for f in found - created if f not in _NOT_DECLARED and f.upper() not in _KEYWORDS}
