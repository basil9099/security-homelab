"""
Reporter
--------
Assembles scored tiers into one profile and writes it three ways:

  * ``<tool>-<ts>.json`` — full structured data, for diffing runs over time
  * ``<tool>-<ts>.md``   — readable summary, what goes in ``FINDINGS.md``
  * ``<tool>-<ts>.html`` — self-contained report, no external assets

The centrepiece of all three is the **defence matrix**: probe families down the
side, hardening tiers across the top, attack success rate in the cells. One table
that says which controls earned their place.
"""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import config
from target.tiers import get_policy

from modules import mapping
from modules.parser import Report
from modules.scoring import TierDelta, TierScore, top_findings

SEVERITY_COLOURS = {
    "critical": "#a4161a",
    "high": "#d4682a",
    "medium": "#c9a227",
    "low": "#4c956c",
    "info": "#6c757d",
}


def build_profile(
    tiers: dict[str, TierScore],
    deltas: dict[str, TierDelta],
    reports: list[Report],
    run_dir: Path,
    backend: str = "",
) -> dict[str, Any]:
    """Assemble everything the writers need into one serialisable structure."""
    ordered = [tiers[name] for name in config.TIERS if name in tiers]
    ordered += [score for name, score in sorted(tiers.items()) if name not in config.TIERS]

    families = sorted({family for score in ordered for family in score.families})

    return {
        "meta": {
            "tool": config.TOOL_NAME,
            "version": config.VERSION,
            "generated": datetime.now(UTC).isoformat(),
            "run_dir": str(run_dir),
            "backend": backend,
            "baseline_tier": config.BASELINE_TIER,
            "reports_parsed": len(reports),
        },
        "summary": {
            "tiers_scanned": len(ordered),
            "families_tested": len(families),
            "total_attempts": sum(score.attempts for score in ordered),
            "total_hits": sum(score.hits for score in ordered),
        },
        "tiers": [_tier_block(score) for score in ordered],
        "matrix": _matrix(families, ordered),
        "deltas": [
            {
                "tier": delta.tier,
                "baseline": delta.baseline,
                "overall": round(delta.overall, 4),
                "pooled": round(delta.pooled, 4),
                "utility_change": round(delta.utility_change, 4),
                "per_family": {k: round(v, 4) for k, v in delta.per_family.items()},
            }
            for delta in deltas.values()
        ],
        "owasp": {score.tier: mapping.owasp_rollup(score.family_asr) for score in ordered},
        "evidence": [_evidence(f) for f in top_findings(reports, limit=12)],
    }


def _tier_block(score: TierScore) -> dict[str, Any]:
    try:
        controls = get_policy(score.tier).controls
    except ValueError:
        controls = []
    return {
        "tier": score.tier,
        "controls": controls,
        "attempts": score.attempts,
        "hits": score.hits,
        "macro_asr": round(score.macro_asr, 4),
        "asr": round(score.asr, 4),
        "utility": round(score.utility, 4),
        "contained_leaks": score.contained,
        "severity_counts": score.severity_counts(),
        "families": [
            {
                "family": name,
                "title": mapped.title,
                "owasp": mapped.owasp,
                "atlas": list(mapped.atlas),
                "severity": mapped.severity,
                "passed": family.passed,
                "total": family.total,
                "asr": round(family.asr, 4),
            }
            for name, family in sorted(score.families.items())
            for mapped in [mapping.lookup(name)]
        ],
    }


def _matrix(families: list[str], scores: list[TierScore]) -> dict[str, Any]:
    return {
        "tiers": [score.tier for score in scores],
        "rows": [
            {
                "family": family,
                "title": mapped.title,
                "severity": mapped.severity,
                "owasp": mapped.owasp,
                "asr": [
                    round(score.families[family].asr, 4) if family in score.families else None
                    for score in scores
                ],
            }
            for family in families
            for mapped in [mapping.lookup(family)]
        ],
    }


def _evidence(finding: Any) -> dict[str, Any]:
    mapped = mapping.lookup(finding.family)
    return {
        "family": finding.family,
        "probe": finding.probe,
        "detector": finding.detector,
        "severity": mapped.severity,
        "owasp": mapped.owasp,
        "tier": finding.notes.get("tier", ""),
        "goal": finding.goal,
        "prompt": _clip(finding.prompt),
        "output": _clip(finding.output),
    }


def _clip(text: str, limit: int = 400) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit] + "…"


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value * 100:.0f}%"


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------


#: format name -> (file suffix, renderer)
WRITERS = {
    "json": ("json", lambda p: json.dumps(p, indent=2)),
    "markdown": ("md", lambda p: render_markdown(p)),
    "html": ("html", lambda p: render_html(p)),
}


def write_reports(
    profile: dict[str, Any], output_dir: Path, formats: str = "all"
) -> dict[str, Path]:
    """Write the requested format(s); ``all`` writes every one."""
    output_dir.mkdir(parents=True, exist_ok=True)
    base = f"{config.TOOL_NAME}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    wanted = WRITERS if formats == "all" else {formats: WRITERS[formats]}

    paths: dict[str, Path] = {}
    for name, (suffix, render) in wanted.items():
        paths[name] = output_dir / f"{base}.{suffix}"
        paths[name].write_text(render(profile), encoding="utf-8")
    return paths


def render_markdown(profile: dict[str, Any]) -> str:
    meta = profile["meta"]
    out: list[str] = [
        f"# {meta['tool']} — LLM Red-Team Report",
        "",
        f"*Generated {meta['generated']} · backend `{meta['backend'] or 'unknown'}` · "
        f"{profile['summary']['total_attempts']} attempts across "
        f"{profile['summary']['tiers_scanned']} tiers*",
        "",
        "## Tier summary",
        "",
        "| Tier | Controls | Attempts | Hits | Macro ASR | Pooled ASR | Utility | Contained |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for tier in profile["tiers"]:
        out.append(
            f"| `{tier['tier']}` | {', '.join(tier['controls']) or 'none'} "
            f"| {tier['attempts']} | {tier['hits']} | **{_pct(tier['macro_asr'])}** "
            f"| {_pct(tier['asr'])} | {_pct(tier['utility'])} | {tier['contained_leaks']} |"
        )

    matrix = profile["matrix"]
    out += [
        "",
        "## Defence matrix",
        "",
        "Attack success rate per probe family. Lower is better; `—` means the "
        "family was not exercised against that tier.",
        "",
        "| Probe family | OWASP | Severity | "
        + " | ".join(f"`{t}`" for t in matrix["tiers"])
        + " |",
        "|---|---|---|" + "---|" * len(matrix["tiers"]),
    ]
    for row in matrix["rows"]:
        cells = " | ".join(_pct(value) for value in row["asr"])
        out.append(
            f"| {row['title']} <br>`{row['family']}` | {row['owasp']} "
            f"| {row['severity']} | {cells} |"
        )

    if profile["deltas"]:
        out += [
            "",
            "## Defence effectiveness",
            "",
            f"Change relative to the `{meta['baseline_tier']}` baseline. "
            "Positive ASR delta means the tier's controls reduced attack success.",
            "",
            "| Tier | ASR reduction | Utility change |",
            "|---|---|---|",
        ]
        for delta in profile["deltas"]:
            out.append(
                f"| `{delta['tier']}` | **{delta['overall'] * 100:+.0f} pts** "
                f"| {delta['pooled'] * 100:+.1f} pts "
                f"| {delta['utility_change'] * 100:+.0f} pts |"
            )

    for tier_name, rollup in profile["owasp"].items():
        if not rollup:
            continue
        out += [
            "",
            f"## OWASP LLM Top 10 — `{tier_name}`",
            "",
            "| Category | Worst ASR | Severity | Families |",
            "|---|---|---|---|",
        ]
        for category, entry in rollup.items():
            out.append(
                f"| {category} | {_pct(float(entry['asr']))} | {entry['severity']} "
                f"| {', '.join(entry['families'])} |"
            )

    if profile["evidence"]:
        out += ["", "## Evidence", ""]
        for item in profile["evidence"]:
            out += [
                f"### {item['probe']} (`{item['tier'] or 'n/a'}`)",
                "",
                f"- **Severity**: {item['severity']} · **{item['owasp']}** · "
                f"detector `{item['detector']}`",
                f"- **Goal**: {item['goal'] or 'n/a'}",
                "",
                "```text",
                f"prompt   : {item['prompt']}",
                f"response : {item['output']}",
                "```",
                "",
            ]

    out += ["", "## Remediation", ""]
    seen: set[str] = set()
    for row in matrix["rows"]:
        if all(value in (None, 0.0) for value in row["asr"]):
            continue
        mapped = mapping.lookup(row["family"])
        if mapped.remediation in seen:
            continue
        seen.add(mapped.remediation)
        out += [f"**{mapped.title}** ({mapped.owasp})", "", mapped.remediation, ""]

    return "\n".join(out) + "\n"


def render_html(profile: dict[str, Any]) -> str:
    meta = profile["meta"]
    matrix = profile["matrix"]

    def esc(value: Any) -> str:
        return html.escape(str(value))

    def cell(value: float | None) -> str:
        if value is None:
            return "<td class='na'>—</td>"
        shade = "ok" if value == 0 else "warn" if value < 0.5 else "bad"
        return f"<td class='{shade}'>{value * 100:.0f}%</td>"

    tier_rows = "".join(
        "<tr>"
        f"<td><code>{esc(t['tier'])}</code></td>"
        f"<td>{esc(', '.join(t['controls']) or 'none')}</td>"
        f"<td>{t['attempts']}</td><td>{t['hits']}</td>"
        f"<td><strong>{_pct(t['macro_asr'])}</strong></td>"
        f"<td>{_pct(t['asr'])}</td>"
        f"<td>{_pct(t['utility'])}</td>"
        f"<td>{t['contained_leaks']}</td>"
        "</tr>"
        for t in profile["tiers"]
    )

    matrix_head = "".join(f"<th><code>{esc(t)}</code></th>" for t in matrix["tiers"])
    matrix_rows = "".join(
        "<tr>"
        f"<td>{esc(row['title'])}<br><code>{esc(row['family'])}</code></td>"
        f"<td>{esc(row['owasp'])}</td>"
        f"<td><span class='sev' style=\"background:"
        f'{SEVERITY_COLOURS.get(row["severity"], "#6c757d")}">{esc(row["severity"])}</span></td>'
        + "".join(cell(value) for value in row["asr"])
        + "</tr>"
        for row in matrix["rows"]
    )

    delta_rows = "".join(
        "<tr>"
        f"<td><code>{esc(d['tier'])}</code></td>"
        f"<td><strong>{d['overall'] * 100:+.0f} pts</strong></td>"
        f"<td>{d['pooled'] * 100:+.1f} pts</td>"
        f"<td>{d['utility_change'] * 100:+.0f} pts</td>"
        "</tr>"
        for d in profile["deltas"]
    )

    evidence = "".join(
        "<article>"
        f"<h3>{esc(item['probe'])} <small>{esc(item['tier'])}</small></h3>"
        f"<p><span class='sev' style=\"background:"
        f'{SEVERITY_COLOURS.get(item["severity"], "#6c757d")}">{esc(item["severity"])}</span> '
        f"{esc(item['owasp'])} · detector <code>{esc(item['detector'])}</code></p>"
        f"<pre>prompt   : {esc(item['prompt'])}\nresponse : {esc(item['output'])}</pre>"
        "</article>"
        for item in profile["evidence"]
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(meta["tool"])} Report — {esc(meta["generated"][:10])}</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a;
        background: #fafafa; line-height: 1.5; }}
 h1 {{ color: #2d6a4f; margin-bottom: .25rem; }}
 h2 {{ margin-top: 2.5rem; border-bottom: 1px solid #ddd; padding-bottom: .3rem; }}
 .sub {{ color: #666; margin-top: 0; }}
 table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; background: #fff; }}
 th, td {{ border: 1px solid #e0e0e0; padding: .5rem .6rem; text-align: left;
           vertical-align: top; font-size: .92rem; }}
 th {{ background: #f0f0f0; }}
 code {{ background: #f0f0f0; padding: .1rem .3rem; border-radius: 3px; font-size: .85em; }}
 pre {{ background: #1e1e1e; color: #e8e8e8; padding: .8rem; border-radius: 5px;
        overflow-x: auto; font-size: .82rem; white-space: pre-wrap; }}
 .sev {{ color: #fff; padding: .1rem .45rem; border-radius: 3px; font-size: .78rem; }}
 td.ok {{ background: #e8f5e9; }} td.warn {{ background: #fff8e1; }}
 td.bad {{ background: #ffebee; font-weight: 600; }} td.na {{ color: #aaa; }}
 article {{ background: #fff; border: 1px solid #e0e0e0; border-radius: 5px;
            padding: .8rem 1rem; margin: 1rem 0; }}
 article h3 {{ margin: 0 0 .3rem; font-size: 1rem; }}
 article small {{ color: #777; font-weight: normal; }}
</style></head><body>
<h1>{esc(meta["tool"])} — LLM Red-Team Report</h1>
<p class="sub">Generated {esc(meta["generated"])} · backend <code>{esc(meta["backend"] or "unknown")}</code>
 · {profile["summary"]["total_attempts"]} attempts ·
 {profile["summary"]["families_tested"]} probe families</p>

<h2>Tier summary</h2>
<table><tr><th>Tier</th><th>Controls</th><th>Attempts</th><th>Hits</th>
<th>Macro ASR</th><th>Pooled ASR</th><th>Utility</th><th>Contained</th></tr>{tier_rows}</table>

<h2>Defence matrix</h2>
<p>Attack success rate per probe family. Lower is better.</p>
<table><tr><th>Probe family</th><th>OWASP</th><th>Severity</th>{matrix_head}</tr>
{matrix_rows}</table>

<h2>Defence effectiveness</h2>
<p>Change relative to the <code>{esc(meta["baseline_tier"])}</code> baseline. Macro
weights every probe family equally; pooled is dominated by whichever families ship the
most prompts.</p>
<table><tr><th>Tier</th><th>Macro ASR reduction</th><th>Pooled ASR reduction</th>
<th>Utility change</th></tr>{delta_rows}</table>

<h2>Evidence</h2>
{evidence or "<p>No confirmed hits.</p>"}
</body></html>
"""
