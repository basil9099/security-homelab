"""
Configuration
-------------
Single source of truth for hardening tiers, probe suites, backends and paths.

Nothing here reaches the network or reads the environment at import time, so the
module is safe to import from tests.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

VERSION = "0.1.0"
TOOL_NAME = "llm-red-team"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
CORPUS_DIR = PROJECT_ROOT / "target" / "corpus"
RUNS_DIR = PROJECT_ROOT / "runs"
MAPPINGS_FILE = PROJECT_ROOT / "modules" / "mappings.yaml"


# ---------------------------------------------------------------------------
# Target application
# ---------------------------------------------------------------------------

#: Hardening tiers, weakest first. Order matters: the first tier is the
#: baseline that every other tier's "defense delta" is measured against.
TIERS: tuple[str, ...] = ("naive", "guarded", "hardened")
BASELINE_TIER = TIERS[0]

#: Model backends. ``mock`` is deterministic and offline — it is what tests and
#: CI use. ``ollama`` talks to a locally running Ollama daemon.
BACKENDS: tuple[str, ...] = ("mock", "ollama")
DEFAULT_BACKEND = "mock"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8900

OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
OLLAMA_MODEL = "llama3.2"
OLLAMA_TIMEOUT = 120

#: Planted in the system prompt of every tier. Seeing it in a response is a
#: deterministic system-prompt-leak signal — no LLM judge required.
CANARY_PREFIX = "LLMRT-CANARY"

#: Regex for a minted canary, so the target and the detectors agree on the shape.
CANARY_RE = re.compile(rf"{CANARY_PREFIX}-[0-9a-f]+")

#: The string an attacker tries to make the model emit. Shared by the probe
#: packs that ask for it and the mock backend that decides whether to comply.
MARKER = "INJECTION-MARKER"

#: Name the native engine writes into reports, and the prefix on every native
#: probe classname (``native.canary_exfil.direct_ask``).
ENGINE_NAME = "native"


def canary_token() -> str:
    """Return the canary for this process.

    Honours ``LLMRT_CANARY`` so a scan can be reproduced exactly; otherwise a
    fresh random token is minted per process.
    """
    return os.environ.get("LLMRT_CANARY") or f"{CANARY_PREFIX}-{os.urandom(8).hex()}"


# ---------------------------------------------------------------------------
# Probe suites
# ---------------------------------------------------------------------------

#: ``garak`` entries are passed straight to ``garak --probes``.
#: ``native`` entries name packs in ``modules/probes.py``.
SUITES: dict[str, dict[str, list[str]]] = {
    "quick": {
        "garak": ["promptinject", "dan.DanInTheWild"],
        "native": ["canary_exfil"],
    },
    "injection": {
        "garak": ["promptinject", "latentinjection", "encoding", "suffix"],
        "native": ["policy_override", "rag_poison"],
    },
    "jailbreak": {
        "garak": ["dan", "grandma", "goodside"],
        "native": [],
    },
    "leakage": {
        # `web_injection` was called `xss` before garak 0.16. A family name this
        # garak does not know is skipped with a reason, not a hard failure.
        "garak": ["leakreplay", "web_injection"],
        "native": ["canary_exfil"],
    },
    "agency": {
        "garak": [],
        "native": ["tool_hijack"],
    },
}

SUITES["full"] = {
    "garak": sorted({p for s in SUITES.values() for p in s["garak"]}),
    "native": sorted({p for s in SUITES.values() for p in s["native"]}),
}


def resolve_suite(name: str) -> dict[str, list[str]]:
    try:
        return SUITES[name]
    except KeyError:
        raise ValueError(f"unknown suite {name!r}; choose from {', '.join(SUITES)}") from None


# ---------------------------------------------------------------------------
# garak invocation
# ---------------------------------------------------------------------------

GARAK_BIN = os.environ.get("LLMRT_GARAK_BIN", "garak")

#: Generations per probe prompt. garak's default is 5; 3 keeps homelab scans
#: to a sane runtime without collapsing the sample size.
GARAK_GENERATIONS = 3
