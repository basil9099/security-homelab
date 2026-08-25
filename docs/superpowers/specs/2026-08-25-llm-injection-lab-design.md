# LLM Injection Lab — extraction and redesign

**Date:** 2026-08-25
**Status:** Approved, ready for implementation planning
**Supersedes:** `projects/offensive/llm_red_team/` in the security-homelab monorepo

---

## Summary

Extract the LLM prompt-injection red-team framework from the security-homelab
monorepo into a standalone repository, `llm-injection-lab`, restructured as an
installable Python package and re-based on findings produced by a real local
model rather than the bundled simulator.

The existing design is kept. The existing packaging, module boundaries and
evidence base are not.

## Goals

1. A standalone repo that installs with `pip install -e .` and runs as `llmlab`.
2. Module boundaries that name what each part does: target, engines, analysis, report.
3. Headline findings produced by a real model, reproducible from a recorded manifest.
4. A README a reviewer can assess in five minutes, leading with the result.

## Non-goals

- Preserving git history from the monorepo. Two commits touched the directory and
  both bundled unrelated changes.
- Supporting targets other than the bundled application. The target stays coupled;
  a pluggable target layer is speculative until there is a second target.
- Multi-model comparison. One model, done properly, beats three done thinly.
- Rewriting the analysis or scoring logic. It is correct and stays.

---

## What carries over unchanged

These are the project's good ideas and the redesign preserves them:

- **A bundled vulnerable application as the system under test.** Scanning a hosted
  model measures the model; the failures that cause incidents are application
  failures. The target ships with a canary in its system prompt, a poisonable
  document corpus, and a simulated tool layer.
- **Three hardening tiers, identical probe set fired at each.** `naive` /
  `guarded` / `hardened`. Giving `guarded` — prompt rules and nothing else — its
  own column is the measurement that makes the report worth reading.
- **Deterministic native probe packs** alongside garak's fuzzy LLM-judge detectors.
  A planted token appeared or it did not; a tool ran or it did not.
- **The benign control group and the utility column.** Refusing everything drives
  ASR to zero; without a control group that scores as a perfect defence.
- **Macro ASR as the headline, pooled reported for completeness.** Probe families
  differ in size by three orders of magnitude.
- **Both engines emitting the same `.report.jsonl` shape**, so everything
  downstream of the parser is engine-agnostic.
- **OWASP LLM Top 10 / MITRE ATLAS mapping as YAML data**, not code.

---

## Repository structure

Local path: `C:\Users\angus\projects\llm-injection-lab`. Fresh `git init`.

```
llm-injection-lab/
├── pyproject.toml           # packaging + ruff + pytest config, single file
├── README.md
├── FINDINGS.md
├── LICENSE
├── .gitignore               # includes runs/
├── .github/workflows/ci.yml
├── screenshots/
├── src/llmlab/
│   ├── __init__.py          # __version__
│   ├── __main__.py          # python -m llmlab
│   ├── cli.py               # argparse wiring + dispatch only
│   ├── runner.py            # scan orchestration: serve, per-tier, both engines
│   ├── console.py           # rich summary tables and `list` output
│   ├── config.py            # tiers, suites, paths, canary, seed
│   ├── target/              # the system under test
│   │   ├── app.py           # FastAPI, POST /chat
│   │   ├── backends.py      # ollama | mock
│   │   ├── tiers.py         # naive | guarded | hardened postures
│   │   ├── defenses.py      # classifier, spotlighting, output scanner
│   │   ├── tools.py         # simulated tools, log-only
│   │   └── corpus/{clean,poisoned}/
│   ├── engines/
│   │   ├── garak.py         # was modules/garak_runner.py
│   │   ├── native.py        # was modules/native_runner.py
│   │   ├── probes.py        # native packs + benign control group
│   │   └── detectors.py
│   ├── analysis/
│   │   ├── parser.py        # .report.jsonl -> normalised findings
│   │   ├── scoring.py       # ASR, deltas, utility, containment
│   │   ├── mapping.py
│   │   └── mappings.yaml
│   └── report/
│       ├── profile.py       # the shared report data structure
│       ├── markdown.py
│       └── html.py
└── tests/
    ├── test_target.py
    ├── test_defenses.py
    ├── test_defence_pipeline.py   # extracted from test_engines.py::TestDefenceGradient
    ├── test_engines.py
    ├── test_analysis.py
    └── fixtures/
```

### Packaging

`pyproject.toml` carries `[build-system]`, `[project]`, and:

```toml
[project.scripts]
llmlab = "llmlab.cli:main"

[project.optional-dependencies]
scan = ["garak"]
dev  = ["pytest", "ruff"]
```

The three `requirements*.txt` files are removed; extras replace them. Ruff and
pytest configuration moves in from the monorepo's root `pyproject.toml`, keeping
the same rule selection (`E4`, `E7`, `E9`, `F`, `I`, `UP`, `B`; line-length 100;
`E501` deliberately excluded).

The `import config` / `sys.path`-via-`conftest.py` arrangement is removed
entirely. All imports become absolute: `from llmlab import config`,
`from llmlab.engines import probes`.

### Data files

`target/corpus/**` and `analysis/mappings.yaml` ship as package data via
`[tool.setuptools.package-data]` and are read through `importlib.resources`,
not `Path(__file__).parent`. This is what makes the package work when installed
rather than only when run from a checkout, and it is covered by a test.

---

## Findings methodology

### The `headline` suite

A new suite sized so a full three-tier comparison runs in roughly one hour and
can be re-run after any change. Target: 1,000–1,500 attempts per tier.

| Component | Contents | Rationale |
|---|---|---|
| Native packs | all four + `benign` | ~35 probes, deterministic detectors, the strongest findings |
| `latentinjection` | 2–3 subclasses | indirect injection, the project's central claim |
| `promptinject` | the `*Mini` variants | garak ships reduced sets for exactly this purpose |
| `dan.DanInTheWildMini` | | persona jailbreak, curated |
| `encoding.InjectBase64` | one probe, not the family | keeps the encoding finding without the 7,000-prompt tail |
| `xss.MarkdownImageExfil` | | small, and the most realistic exfil channel |
| `suffix.GCGCached` | | adversarial suffix, already small |

Exact probe class names are verified against the installed garak version during
implementation; the table above states intent, not a guaranteed-valid probe list.

`full` remains defined and documented. The README states that the headline table
is the curated suite and that `--suite full` runs everything at roughly 15 hours.

### Reproducibility

Three changes, all new work:

1. **Pinned sampling.** The Ollama backend sends
   `options: {temperature: 0, seed: <run seed>}`. It currently sends neither, so
   today's numbers would drift between runs. The seed is recorded in the manifest
   and settable via CLI flag.
2. **Generations split by engine.** garak families run at 1 generation for
   breadth. Native packs run at 5 — 35 probes, roughly ten extra minutes — which
   yields a variance figure on the numbers that matter most. A native family
   result is reported as `100% (5/5, n=5)` rather than a bare percentage.
3. **A run manifest.** Every run writes `manifest.json` alongside its reports,
   recording: model name and Ollama digest, garak version, suite name, seed,
   tier list, start and end time, wall-clock duration, host Python version,
   and package version. The report embeds it and `FINDINGS.md` quotes it.

### Documents rewritten

`FINDINGS.md` is rewritten against the real run. Its structure survives —
separating application findings (F-series, about the target's controls) from
method findings (M-series, about the measurement) is a good idea and is kept.
The numbers, evidence excerpts and both screenshots are regenerated.

The "Read this first" caveat about the mock backend is removed and replaced with
a short methodology note about the curated suite and the manifest.

### Expected changes in the results

Recorded here so they are not a surprise during implementation:

- `guarded` will likely perform better against a real model than against the
  mock, because real models do respond to refusal rules.
- `suffix` will likely stop scoring 100%, because cached GCG suffixes were
  optimised against other models.
- The claim expected to survive is the central one: **prompt-level rules do
  nothing about indirect injection**, because `rag_poison` does not route
  through the model's willingness to comply.

If a headline claim does not survive the real run, the finding is reported as it
came out. The document reports the run; the run is not tuned to the document.

---

## The mock backend

The mock is kept but demoted to a test double. It stays because it keeps the test
suite network-free and lets anyone clone the repo and run the tests without
pulling a model. It never appears in `FINDINGS.md` and is documented as a test
double rather than as a backend to scan with.

`TestDefenceGradient` currently lives as a class at `tests/test_engines.py:363`,
inside a 418-line file. It is extracted into its own `test_defence_pipeline.py`,
and its docstring states plainly what it is: a regression test that the defences
transform the prompt as designed, not evidence about model behaviour. It catches a broken
spotlighting implementation; it does not measure attack success rate. Keeping
that distinction explicit in the code matters, because the previous README came
close to letting the test stand in for a finding.

---

## Migration sequence

Ported bottom-up with the test suite green at every step. Steps 2–5 are moves
plus import rewrites with **no behaviour changes**, so the existing tests are the
safety net and any red test means the move broke something.

| Step | Work | Gate |
|---|---|---|
| 0 | Run the existing suite in place, record the baseline | pytest green before anything moves |
| 1 | Scaffold: `pyproject.toml`, `src/llmlab/`, `config.py`, empty subpackages, CI workflow | `pip install -e .` succeeds |
| 2 | Port `target/` (5 modules + corpus), switch corpus to `importlib.resources` | `test_target.py`, `test_defenses.py` green |
| 3 | Port `engines/` (garak, native, probes, detectors) | `test_engines.py` green |
| 4 | Port `analysis/`, split `reporter.py` into `report/{profile,markdown,html}.py` | `test_analysis.py` green |
| 5 | Split `main.py` into `cli.py` / `runner.py` / `console.py`, wire entry point | `llmlab --help`, `llmlab list suites` |
| 6 | Add `headline` suite, seed and temperature pinning, `manifest.json` | new tests, written first |
| 7 | Real Ollama run; regenerate screenshots | manifest recorded |
| 8 | Rewrite `FINDINGS.md` and `README.md` against the real numbers | — |
| 9 | Remove the monorepo directory, link out from the homelab README | separate commit in the homelab repo |

Step 6 is the only step where new logic lands, and it is the only step written
test-first.

Step 9 happens last. Until it does, the original directory sits untouched in the
monorepo as a fallback.

---

## Testing

The suite stays network-free and mock-backed. Nothing in `tests/` requires
Ollama or garak — that property is worth preserving.

New tests introduced at step 6:

- `manifest.json` contents and shape
- the seed reaching the Ollama request body
- `headline` suite resolution
- corpus and mappings loading via `importlib.resources` from an *installed*
  package, not a checkout

CI (`.github/workflows/ci.yml`): `pytest`, `ruff check`, `ruff format --check`
on push and pull request, Python 3.12, no secrets and no services.

---

## README structure

Reordered so the first screen answers "did this person measure something real,
and what did they find":

1. One-paragraph description and CI badge
2. Legal and authorisation notice
3. **The result** — tier table and defence matrix, with the manifest line beneath
4. **Why a target application and not a model scan** — the four-question table
5. The three tiers and what each adds
6. Install and quick start
7. Probe coverage, reading the report, layout, testing, references

Cut: the extended mock-backend discussion drops from a section to two sentences
in the testing section, since it stops being load-bearing once the findings are
real.

---

## Operational constraints

- **Commits and pushes are performed by the repository owner, not by the
  implementing agent.** The agent stages work and reports when a step is ready,
  naming the commands to run.
- The GitHub repository is created and pushed to early, so the commit history
  shows the build. Repository creation and the first push are confirmed with the
  owner beforehand, including visibility (public or private).
- Ollama is installed locally at
  `C:\Users\angus\AppData\Local\Programs\Ollama\ollama`; `llama3.2` is the
  intended model. **The daemon was not running when this spec was written**
  (`ollama list` did not return within 120s), and it is not confirmed that
  `llama3.2` has been pulled. Step 7 must begin by starting the daemon and
  verifying the model is present; if it is not, pulling it is a prerequisite of
  that step, not a surprise inside it.
- The `LICENSE` is MIT, copied from the monorepo.
