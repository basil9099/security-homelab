"""
The target application
----------------------
A small, deliberately-vulnerable LLM helpdesk assistant. This is the system under
test — this project never points at a third party's model.

It exists because the interesting failures are *application* failures. A bare
model endpoint has no system prompt to leak, no retrieved documents to poison and
no tools to hijack, so there is nothing to measure. This app has all three, and
:mod:`target.tiers` lets the same code run with three different security postures.

Exposes a flat JSON API so garak's ``rest`` generator can drive it directly:

    POST /chat  {"prompt": "...", "doc_id": "...", "confirmed": false}
             -> {"response": "...", "blocked": false, "meta": {...}}
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import config
from fastapi import FastAPI
from pydantic import BaseModel, Field

from target import defenses, tools
from target.backends import Backend, MockBackend
from target.tiers import TierPolicy, get_policy


class ChatRequest(BaseModel):
    prompt: str
    #: Name of a document in ``target/corpus`` to retrieve, e.g.
    #: ``poisoned/vendor_invoice.md``. This is the indirect-injection channel.
    doc_id: str | None = None
    #: Stands in for a human clicking "yes, send that email". No probe can set
    #: it, which is the point of the gate.
    confirmed: bool = False


class ChatResponse(BaseModel):
    response: str
    blocked: bool = False
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


def load_document(doc_id: str, corpus_dir: Path | None = None) -> str | None:
    """Read a corpus document, refusing anything that escapes the corpus."""
    root = (corpus_dir or config.CORPUS_DIR).resolve()
    candidate = (root / doc_id).resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file():
        return None
    return candidate.read_text(encoding="utf-8")


def list_documents(corpus_dir: Path | None = None) -> list[str]:
    root = corpus_dir or config.CORPUS_DIR
    if not root.is_dir():
        return []
    # as_posix(): doc_ids are always forward-slashed, on Windows too.
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*.md"))


def compose_turn(policy: TierPolicy, prompt: str, document: str | None) -> str:
    """Build the user turn, applying the tier's context handling."""
    if document is None:
        return prompt
    context = (
        defenses.spotlight(document)
        if policy.spotlight_context
        else defenses.plain_context(document)
    )
    return f"{context}\n\n{prompt}"


def create_app(
    tier: str = "naive",
    backend: Backend | None = None,
    canary: str | None = None,
    corpus_dir: Path | None = None,
) -> FastAPI:
    policy = get_policy(tier)
    engine = backend or MockBackend()
    token = canary or config.canary_token()

    app = FastAPI(title=f"ACME Assist ({tier})", version=config.VERSION)
    app.state.policy = policy
    app.state.canary = token
    app.state.backend = engine

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "tier": policy.name,
            "backend": engine.name,
            "controls": policy.controls,
        }

    @app.get("/corpus")
    def corpus() -> dict[str, list[str]]:
        return {"documents": list_documents(corpus_dir)}

    @app.post("/chat", response_model=ChatResponse)
    def chat(request: ChatRequest) -> ChatResponse:
        document = load_document(request.doc_id, corpus_dir) if request.doc_id else None
        meta: dict[str, Any] = {
            "tier": policy.name,
            "doc_id": request.doc_id,
            "doc_found": document is not None if request.doc_id else None,
        }

        # 1. Inbound classifier. Scores the prompt *and* any retrieved document,
        #    because indirect injection never appears in the prompt itself.
        if policy.input_classifier:
            verdict = defenses.classify_injection(f"{request.prompt}\n{document or ''}")
            meta["injection_score"] = verdict.score
            meta["injection_labels"] = verdict.labels
            if verdict.blocked:
                meta.update(raw_leak=False, delivered_leak=False, refused=True)
                return ChatResponse(response=defenses.REFUSAL_MESSAGE, blocked=True, meta=meta)

        # 2. Generate.
        system = policy.system_prompt(token)
        raw = engine.generate(system, compose_turn(policy, request.prompt, document))

        # 3. Tools. The model asks; the tier's policy decides.
        tool_log = tools.dispatch(raw, policy.tool_mode, confirmed=request.confirmed)
        body = tools.strip_tool_calls(raw)
        for call in tool_log.executed:
            body = f"{body}\n{call.result}".strip()

        # 4. Outbound scanner.
        meta["raw_leak"] = token in raw
        if policy.output_scanner:
            scan = defenses.scan_output(body, token)
            body = scan.text
            meta["output_scan"] = {
                "canary_redacted": scan.canary_redacted,
                "links_stripped": scan.links_stripped,
            }

        meta["delivered_leak"] = token in body
        meta["refused"] = False
        return ChatResponse(response=body, blocked=False, tool_calls=tool_log.to_list(), meta=meta)

    return app
