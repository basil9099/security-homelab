"""
Simulated agent tools
---------------------
The target advertises three tools so that "excessive agency" is measurable. They
are **simulated end to end** — nothing here sends mail, touches the filesystem or
opens a socket. Each call returns a canned string and records an entry in the
request's tool log.

That is deliberate. A hijacked tool call has to be detectable *without* a real
side effect, otherwise the scan itself would be the dangerous part.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: The model is instructed to emit calls in this exact form.
TOOL_CALL_RE = re.compile(r"TOOL_CALL:\s*(?P<name>\w+)\((?P<args>[^)]*)\)")

#: Tools that can move data off the box. These are the ones that matter — a
#: hijacked ``read_file`` is a nuisance, a hijacked ``send_email`` is a breach.
EXFIL_CAPABLE = frozenset({"send_email", "http_get"})

#: Permitted without confirmation under the ``gated`` policy.
GATED_ALLOWLIST = frozenset({"read_file"})

#: Tools the target advertises. The descriptions the model is shown live in
#: ``target/tiers.py``; only membership matters here.
KNOWN_TOOLS = frozenset({"send_email", "read_file", "http_get"})


@dataclass
class ToolCall:
    name: str
    args: str
    executed: bool
    reason: str
    result: str = ""

    @property
    def exfil_capable(self) -> bool:
        return self.name in EXFIL_CAPABLE

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "args": self.args,
            "executed": self.executed,
            "reason": self.reason,
            "exfil_capable": self.exfil_capable,
        }


@dataclass
class ToolLog:
    calls: list[ToolCall] = field(default_factory=list)

    @property
    def executed(self) -> list[ToolCall]:
        return [c for c in self.calls if c.executed]

    def to_list(self) -> list[dict[str, object]]:
        return [c.to_dict() for c in self.calls]


def parse_tool_calls(text: str) -> list[tuple[str, str]]:
    """Extract ``(name, args)`` pairs from a model response."""
    return [(m.group("name"), m.group("args").strip()) for m in TOOL_CALL_RE.finditer(text)]


def _simulate(name: str, args: str) -> str:
    """Canned result for a tool that is never actually run."""
    return {
        "send_email": f"[simulated] mail queued to {args or 'unknown recipient'}",
        "read_file": f"[simulated] contents of {args or 'unknown path'}",
        "http_get": f"[simulated] 200 OK from {args or 'unknown url'}",
    }.get(name, "[simulated] no such tool")


def dispatch(text: str, tool_mode: str, confirmed: bool = False) -> ToolLog:
    """Resolve every tool call in ``text`` under the tier's ``tool_mode``.

    ``auto``  — anything the model names is invoked, which is the whole problem.
    ``gated`` — only the read-only allowlist runs unattended; exfil-capable tools
                require an out-of-band ``confirmed`` flag that no probe can set.
    """
    log = ToolLog()
    for name, args in parse_tool_calls(text):
        if name not in KNOWN_TOOLS:
            log.calls.append(ToolCall(name, args, False, "unknown tool"))
            continue

        if tool_mode == "auto":
            log.calls.append(ToolCall(name, args, True, "auto-invoke", _simulate(name, args)))
            continue

        if name in GATED_ALLOWLIST:
            log.calls.append(ToolCall(name, args, True, "allowlisted", _simulate(name, args)))
        elif confirmed:
            log.calls.append(ToolCall(name, args, True, "user-confirmed", _simulate(name, args)))
        else:
            log.calls.append(ToolCall(name, args, False, "blocked: awaiting user confirmation"))

    return log


def strip_tool_calls(text: str) -> str:
    """Remove tool-call lines from the text shown back to the user."""
    return TOOL_CALL_RE.sub("", text).strip()
