# LLM Injection Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the LLM prompt-injection red-team framework from the security-homelab monorepo into a standalone, installable repository with real-model findings.

**Architecture:** Port bottom-up from `projects/offensive/llm_red_team/` into `C:\Users\angus\projects\llm-injection-lab` as a `src/llmlab/` package with four subpackages (`target`, `engines`, `analysis`, `report`). Tasks 2–7 are pure moves plus import rewrites with no behaviour changes, so the existing test suite is the safety net. Tasks 8–11 add the only new logic and are written test-first. Tasks 12–14 produce the evidence and clean up.

**Tech Stack:** Python 3.12, FastAPI, uvicorn, pydantic, requests, PyYAML, rich, pytest, ruff, NVIDIA garak (optional extra), Ollama.

**Spec:** `docs/superpowers/specs/2026-08-25-llm-injection-lab-design.md`

## Global Constraints

- **The repository owner performs all `git commit` and `git push` commands.** Never run them. Each task ends by reporting what is staged and printing the command for the owner to run.
- **Creating the GitHub remote and the first push require explicit confirmation from the owner**, including repository visibility (public or private).
- Target Python: **3.12**. Package name `llmlab`, distribution name `llm-injection-lab`, console script `llmlab`.
- Ruff config, copied verbatim from the monorepo root: `target-version = "py311"`, `line-length = 100`, `select = ["E4", "E7", "E9", "F", "I", "UP", "B"]`, per-file-ignores `"**/__init__.py" = ["F401"]`. `E501` is deliberately excluded.
- Pinned dependency versions, copied verbatim from `requirements.txt`: `fastapi==0.115.6`, `uvicorn==0.34.0`, `pydantic==2.10.4`, `requests==2.32.3`, `httpx==0.28.1`, `PyYAML==6.0.2`, `rich==13.9.4`. Dev: `pytest>=8.0.0`, `ruff>=0.8.0`. Scan extra: `garak>=0.10.0`.
- **All imports become absolute `llmlab.*`.** No `sys.path` manipulation. `tests/conftest.py` from the old repo is deleted, not ported.
- The test suite stays **network-free**: no test may require Ollama or garak.
- The mock backend is a **test double**. It must never produce a number quoted in `FINDINGS.md`.
- The old directory `projects/offensive/llm_red_team/` stays untouched until Task 14.

---

### Task 0: Establish the baseline

Nothing is installed on this machine — there is no virtualenv and `fastapi`, `rich` and `garak` are all absent. The existing suite has to be proven green before anything moves, otherwise a red test later cannot be attributed.

**Files:**
- Create: `projects/offensive/llm_red_team/.venv/` (gitignored, throwaway)
- Modify: none

- [ ] **Step 1: Create a virtualenv in the old project**

```bash
cd /c/Users/angus/security-homelab/projects/offensive/llm_red_team && python -m venv .venv
```

- [ ] **Step 2: Install the runtime and dev dependencies**

```bash
cd /c/Users/angus/security-homelab/projects/offensive/llm_red_team && .venv/Scripts/python.exe -m pip install -r requirements-dev.txt
```

- [ ] **Step 3: Run the existing suite and record the baseline**

```bash
cd /c/Users/angus/security-homelab/projects/offensive/llm_red_team && .venv/Scripts/python.exe -m pytest tests -q
```

Expected: all tests pass. **Record the exact pass count** — it is the number every later port task must reproduce. If any test fails here, stop and report; do not begin the migration against a red baseline.

- [ ] **Step 4: Record the ruff baseline**

```bash
cd /c/Users/angus/security-homelab/projects/offensive/llm_red_team && .venv/Scripts/python.exe -m ruff check . && .venv/Scripts/python.exe -m ruff format --check .
```

Expected: clean. If not, record the existing violations so they are not mistaken for migration damage.

- [ ] **Step 5: Report the baseline to the owner**

No commit. Report the pass count and ruff status.

---

### Task 1: Scaffold the new repository

**Files:**
- Create: `C:\Users\angus\projects\llm-injection-lab\pyproject.toml`
- Create: `C:\Users\angus\projects\llm-injection-lab\.gitignore`
- Create: `C:\Users\angus\projects\llm-injection-lab\LICENSE`
- Create: `C:\Users\angus\projects\llm-injection-lab\.github\workflows\ci.yml`
- Create: `C:\Users\angus\projects\llm-injection-lab\src\llmlab\__init__.py`
- Create: `C:\Users\angus\projects\llm-injection-lab\src\llmlab\config.py`
- Create: `C:\Users\angus\projects\llm-injection-lab\src\llmlab\target\__init__.py`
- Create: `C:\Users\angus\projects\llm-injection-lab\src\llmlab\engines\__init__.py`
- Create: `C:\Users\angus\projects\llm-injection-lab\src\llmlab\analysis\__init__.py`
- Create: `C:\Users\angus\projects\llm-injection-lab\src\llmlab\report\__init__.py`
- Test: `C:\Users\angus\projects\llm-injection-lab\tests\test_packaging.py`

**Interfaces:**
- Produces: `llmlab.__version__` (str); `llmlab.config` with `TIERS`, `BACKENDS`, `SUITES`, `CORPUS_DIR`, `MAPPINGS_FILE`, `RUNS_DIR`, `canary_token()`, `resolve_suite()`.

- [ ] **Step 1: Create the directory and initialise git**

```bash
mkdir -p /c/Users/angus/projects/llm-injection-lab/src/llmlab/{target,engines,analysis,report} /c/Users/angus/projects/llm-injection-lab/tests/fixtures /c/Users/angus/projects/llm-injection-lab/.github/workflows /c/Users/angus/projects/llm-injection-lab/screenshots && cd /c/Users/angus/projects/llm-injection-lab && git init
```

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "llm-injection-lab"
version = "0.1.0"
description = "A prompt-injection red-team harness measuring LLM application defences across three hardening tiers"
readme = "README.md"
requires-python = ">=3.12"
license = { file = "LICENSE" }
authors = [{ name = "Angus Dawson" }]
dependencies = [
    "fastapi==0.115.6",
    "uvicorn==0.34.0",
    "pydantic==2.10.4",
    "requests==2.32.3",
    "httpx==0.28.1",
    "PyYAML==6.0.2",
    "rich==13.9.4",
]

[project.optional-dependencies]
scan = ["garak>=0.10.0"]
dev = ["pytest>=8.0.0", "ruff>=0.8.0"]

[project.scripts]
llmlab = "llmlab.cli:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
llmlab = ["target/corpus/**/*.md", "analysis/*.yaml"]

[tool.ruff]
target-version = "py311"
line-length = 100

[tool.ruff.lint]
select = ["E4", "E7", "E9", "F", "I", "UP", "B"]

[tool.ruff.lint.per-file-ignores]
"**/__init__.py" = ["F401"]

[tool.pytest.ini_options]
addopts = "-ra"
testpaths = ["tests"]
python_files = ["test_*.py"]
python_functions = ["test_*"]
```

- [ ] **Step 3: Write `.gitignore`**

```gitignore
__pycache__/
*.py[cod]
.venv/
venv/
*.egg-info/
build/
dist/
.pytest_cache/
.ruff_cache/
runs/
```

- [ ] **Step 4: Copy the MIT licence across**

```bash
cp /c/Users/angus/security-homelab/LICENSE /c/Users/angus/projects/llm-injection-lab/LICENSE
```

- [ ] **Step 5: Write `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install
        run: pip install -e ".[dev]"
      - name: Lint
        run: |
          ruff check .
          ruff format --check .
      - name: Test
        run: pytest tests -q
```

- [ ] **Step 6: Write `src/llmlab/__init__.py`**

```python
"""A prompt-injection red-team harness for LLM applications."""

__version__ = "0.1.0"
```

- [ ] **Step 7: Write the four empty subpackage `__init__.py` files**

```bash
cd /c/Users/angus/projects/llm-injection-lab/src/llmlab && for pkg in target engines analysis report; do printf '' > "$pkg/__init__.py"; done
```

- [ ] **Step 8: Port `config.py` with corrected paths**

Copy `projects/offensive/llm_red_team/config.py` to `src/llmlab/config.py`, then replace the Paths block. The old block used `PROJECT_ROOT = Path(__file__).resolve().parent` for all three paths. Two things change: package data is resolved via `importlib.resources`, and **`RUNS_DIR` moves to the current working directory** — the old value would write scan output inside `site-packages` once the package is installed.

Replace this:

```python
PROJECT_ROOT = Path(__file__).resolve().parent
CORPUS_DIR = PROJECT_ROOT / "target" / "corpus"
RUNS_DIR = PROJECT_ROOT / "runs"
MAPPINGS_FILE = PROJECT_ROOT / "modules" / "mappings.yaml"
```

with this:

```python
#: Package data, resolved through importlib.resources so the paths are correct
#: whether the package is installed or run from a checkout.
PACKAGE_ROOT = Path(str(files("llmlab")))
CORPUS_DIR = PACKAGE_ROOT / "target" / "corpus"
MAPPINGS_FILE = PACKAGE_ROOT / "analysis" / "mappings.yaml"

#: Scan output is *not* package data — it belongs to the invocation, not the
#: install. Writing it relative to the package would put run artifacts inside
#: site-packages.
RUNS_DIR = Path.cwd() / "runs"
```

and add to the imports at the top of the file:

```python
from importlib.resources import files
```

Leave `TIERS`, `BACKENDS`, `SUITES`, `CANARY_PREFIX`, `CANARY_RE`, `MARKER`, `ENGINE_NAME`, `canary_token()` and `resolve_suite()` exactly as they are.

- [ ] **Step 9: Write the failing packaging test**

Create `tests/test_packaging.py`:

```python
"""The package installs, imports, and resolves its data files correctly."""

import llmlab
from llmlab import config


def test_version_is_exposed():
    assert llmlab.__version__ == "0.1.0"


def test_corpus_dir_resolves_to_a_real_directory():
    assert config.CORPUS_DIR.is_dir()


def test_mappings_file_resolves_to_a_real_file():
    assert config.MAPPINGS_FILE.is_file()


def test_runs_dir_is_not_inside_the_package():
    assert config.PACKAGE_ROOT not in config.RUNS_DIR.parents
```

- [ ] **Step 10: Create a venv and install the package editable**

```bash
cd /c/Users/angus/projects/llm-injection-lab && python -m venv .venv && .venv/Scripts/python.exe -m pip install -e ".[dev]"
```

Expected: install succeeds.

- [ ] **Step 11: Run the packaging test**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests/test_packaging.py -v
```

Expected: `test_version_is_exposed` and `test_runs_dir_is_not_inside_the_package` PASS. The two data-file tests FAIL — the corpus and mappings arrive in Tasks 2 and 5. This is the expected intermediate state; note it and move on.

A caveat worth knowing: an editable install exercises the `importlib.resources` path meaningfully — the `src/` layout means `llmlab` is not importable from the working directory, so the resolution is genuine — but it is not identical to a built wheel. Proving that would need a `pip wheel` build and an install into a throwaway venv, which is not worth a task here. The `src/` layout is what catches the common failure.

- [ ] **Step 12: Report to the owner for commit and remote creation**

Report that the scaffold is ready. **Ask the owner whether to create the GitHub remote now and at what visibility** — do not create it unprompted. Commands for the owner:

```bash
cd /c/Users/angus/projects/llm-injection-lab && git add -A && git commit -m "Scaffold llm-injection-lab package"
```

---

### Task 2: Port the target application

**Files:**
- Create: `src/llmlab/target/{app,backends,tiers,defenses,tools}.py`
- Create: `src/llmlab/target/corpus/{clean,poisoned}/*.md`
- Test: `tests/test_target.py`, `tests/test_defenses.py`

**Interfaces:**
- Consumes: `llmlab.config` (Task 1).
- Produces: `llmlab.target.app.create_app(tier, backend, canary)`, `load_document(doc_id, corpus_dir=None)`, `list_documents(corpus_dir=None)`, `compose_turn(policy, prompt, document)`; `llmlab.target.backends.build_backend(name, model, url, timeout)`, `Backend` protocol with `generate(system, user) -> str`, `MockBackend`, `OllamaBackend`; `llmlab.target.tiers.get_policy(tier) -> TierPolicy`, `POLICIES`, `TOOL_MODES`; `llmlab.target.defenses` with `normalise`, `spotlight`, `UNTRUSTED_OPEN`, `UNTRUSTED_CLOSE`; `llmlab.target.tools`.

- [ ] **Step 1: Copy the five modules and the corpus**

```bash
OLD=/c/Users/angus/security-homelab/projects/offensive/llm_red_team && NEW=/c/Users/angus/projects/llm-injection-lab && cp $OLD/target/{app,backends,tiers,defenses,tools}.py $NEW/src/llmlab/target/ && cp -r $OLD/target/corpus $NEW/src/llmlab/target/corpus
```

- [ ] **Step 2: Rewrite the imports in the copied modules**

```bash
cd /c/Users/angus/projects/llm-injection-lab/src/llmlab/target && sed -i 's/^import config$/from llmlab import config/; s/^from target import /from llmlab.target import /; s/^from target\./from llmlab.target./' *.py
```

- [ ] **Step 3: Verify no stale imports remain**

```bash
cd /c/Users/angus/projects/llm-injection-lab/src/llmlab/target && grep -n "^import config\|^from target\|^from modules" *.py || echo "clean"
```

Expected: `clean`.

- [ ] **Step 4: Copy the two test files and rewrite their imports**

```bash
OLD=/c/Users/angus/security-homelab/projects/offensive/llm_red_team && NEW=/c/Users/angus/projects/llm-injection-lab && cp $OLD/tests/{test_target.py,test_defenses.py} $NEW/tests/ && cd $NEW/tests && sed -i 's/^import config$/from llmlab import config/; s/^from target import /from llmlab.target import /; s/^from target\./from llmlab.target./; s/^from modules import /from llmlab.engines import /; s/^from modules\./from llmlab.engines./' test_target.py test_defenses.py
```

Note: `tests/conftest.py` is **not** copied. The `sys.path` hack it existed for is gone.

- [ ] **Step 5: Run the target tests**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests/test_target.py tests/test_defenses.py tests/test_packaging.py -v
```

Expected: all PASS, including `test_corpus_dir_resolves_to_a_real_directory` which was failing in Task 1. If an import error names `modules`, a test still references the engines layer — note which, and defer that specific test to Task 3 with an `xfail` marker rather than editing the assertion.

- [ ] **Step 6: Lint**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m ruff check . && .venv/Scripts/python.exe -m ruff format --check .
```

- [ ] **Step 7: Report for commit**

```bash
cd /c/Users/angus/projects/llm-injection-lab && git add -A && git commit -m "Port target application and corpus"
```

---

### Task 3: Port the probe engines

**Files:**
- Create: `src/llmlab/engines/garak.py` (from `modules/garak_runner.py`)
- Create: `src/llmlab/engines/native.py` (from `modules/native_runner.py`)
- Create: `src/llmlab/engines/probes.py`, `src/llmlab/engines/detectors.py`
- Test: `tests/test_engines.py`, `tests/fixtures/*.jsonl`

**Interfaces:**
- Consumes: `llmlab.config`, `llmlab.target.*` (Tasks 1–2).
- Produces: `llmlab.engines.garak.garak_available()`, `write_rest_config(path, base_url, tier, timeout=None)`, `build_command(probe, option_file, prefix, generations, variant=None)`, `run_suite(...)`, `GarakRun`; `llmlab.engines.native.run(probe_list, client, canary, tier, out_path, generations, backend)`; `llmlab.engines.probes.Probe` dataclass and the pack constants; `llmlab.engines.detectors`.

- [ ] **Step 1: Copy the four modules under their new names**

```bash
OLD=/c/Users/angus/security-homelab/projects/offensive/llm_red_team && NEW=/c/Users/angus/projects/llm-injection-lab && cp $OLD/modules/garak_runner.py $NEW/src/llmlab/engines/garak.py && cp $OLD/modules/native_runner.py $NEW/src/llmlab/engines/native.py && cp $OLD/modules/probes.py $OLD/modules/detectors.py $NEW/src/llmlab/engines/
```

- [ ] **Step 2: Rewrite imports across the engines package**

```bash
cd /c/Users/angus/projects/llm-injection-lab/src/llmlab/engines && sed -i 's/^import config$/from llmlab import config/; s/^from modules import garak_runner/from llmlab.engines import garak/; s/^from modules import native_runner/from llmlab.engines import native/; s/^from modules import /from llmlab.engines import /; s/^from modules\.garak_runner import /from llmlab.engines.garak import /; s/^from modules\.native_runner import /from llmlab.engines.native import /; s/^from modules\.parser import /from llmlab.analysis.parser import /; s/^from modules\.scoring import /from llmlab.analysis.scoring import /; s/^from modules\.mapping import /from llmlab.analysis.mapping import /; s/^from modules\./from llmlab.engines./; s/^from target import /from llmlab.target import /; s/^from target\./from llmlab.target./' *.py
```

- [ ] **Step 3: Check for stale references, including in docstrings**

```bash
cd /c/Users/angus/projects/llm-injection-lab/src/llmlab/engines && grep -n "modules\.\|modules/\|garak_runner\|native_runner" *.py || echo "clean"
```

Any hit inside a docstring is a **documentation** fix: `modules/probes.py` becomes `llmlab/engines/probes.py`, `:mod:\`modules.detectors\`` becomes `:mod:\`llmlab.engines.detectors\``. Fix each by hand — these are the stale-path comments the old repo already had a history of.

- [ ] **Step 4: Copy the engine tests and fixtures**

```bash
OLD=/c/Users/angus/security-homelab/projects/offensive/llm_red_team && NEW=/c/Users/angus/projects/llm-injection-lab && cp $OLD/tests/test_engines.py $NEW/tests/ && cp $OLD/tests/fixtures/*.jsonl $NEW/tests/fixtures/ && cd $NEW/tests && sed -i 's/^import config$/from llmlab import config/; s/^from modules import garak_runner/from llmlab.engines import garak as garak_runner/; s/^from modules import native_runner/from llmlab.engines import native as native_runner/; s/^from modules import /from llmlab.engines import /; s/^from modules\.garak_runner import /from llmlab.engines.garak import /; s/^from modules\.native_runner import /from llmlab.engines.native import /; s/^from modules\./from llmlab.engines./; s/^from target import /from llmlab.target import /; s/^from target\./from llmlab.target./' test_engines.py
```

The `as garak_runner` aliases keep the body of the test file unchanged, so this step stays a pure move.

- [ ] **Step 5: Run the engine tests**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests/test_engines.py -v
```

Expected: all PASS, including `TestDefenceGradient` which still lives in this file. It moves in Task 4.

- [ ] **Step 6: Lint and report for commit**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m ruff check . && .venv/Scripts/python.exe -m ruff format --check .
```

```bash
cd /c/Users/angus/projects/llm-injection-lab && git add -A && git commit -m "Port probe engines"
```

---

### Task 4: Extract and reframe the defence-pipeline test

`TestDefenceGradient` currently sits at `tests/test_engines.py:363`, inside a 418-line file, and the old README presented it as if it corroborated the findings. It does not — it runs against the mock. This task moves it out and says so in the docstring.

**Files:**
- Create: `tests/test_defence_pipeline.py`
- Modify: `tests/test_engines.py` (remove the class)

- [ ] **Step 1: Read the class to be moved**

```bash
cd /c/Users/angus/projects/llm-injection-lab && sed -n '355,418p' tests/test_engines.py
```

Note the exact line the class starts at and any imports it alone uses.

- [ ] **Step 2: Create `tests/test_defence_pipeline.py` with the reframing docstring**

The file header must be exactly this, followed by the imports the class needs and the class body moved verbatim:

```python
"""Regression tests for the defence pipeline.

These assert that each tier's controls transform the prompt as designed — that
spotlighting wraps retrieved content, that the classifier fires, that the output
scanner redacts the canary. Every assertion here runs against the **mock
backend**, which is a test double and not a language model.

That makes this a regression test, not evidence. It catches "someone broke
spotlighting". It does not measure attack success rate, and no number produced
here belongs in FINDINGS.md — those come from a real model via `llmlab scan
--backend ollama`. See the methodology note in FINDINGS.md.
"""
```

- [ ] **Step 3: Remove the class from `test_engines.py`**

Delete the `TestDefenceGradient` class from `tests/test_engines.py`, and remove any import that is now unused in that file.

- [ ] **Step 4: Run both files and confirm the total count is unchanged**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests/test_engines.py tests/test_defence_pipeline.py -v
```

Expected: PASS, and the combined test count equals the count `test_engines.py` had alone in Task 3. A drop means a test was lost in the move.

- [ ] **Step 5: Lint and report for commit**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m ruff check . && .venv/Scripts/python.exe -m ruff format --check .
```

```bash
cd /c/Users/angus/projects/llm-injection-lab && git add -A && git commit -m "Extract defence-pipeline regression test and state what it is not"
```

---

### Task 5: Port the analysis layer

**Files:**
- Create: `src/llmlab/analysis/{parser,scoring,mapping}.py`, `src/llmlab/analysis/mappings.yaml`
- Test: `tests/test_analysis.py`

**Interfaces:**
- Consumes: `llmlab.config`.
- Produces: `llmlab.analysis.parser.parse_report(path, tier="", engine="")`, `parse_run_dir(run_dir) -> list[Report]`, `family_of(classname)`, dataclasses `Finding`, `EvalRow`, `Report`; `llmlab.analysis.scoring.score_reports(reports) -> dict[str, TierScore]`, `defence_deltas(tiers, baseline) -> dict[str, TierDelta]`, `top_findings(reports, limit=10)`, dataclasses `FamilyScore`, `TierScore`, `TierDelta`; `llmlab.analysis.mapping.FamilyMapping`, `SEVERITY_ORDER`.

- [ ] **Step 1: Copy the three modules and the YAML table**

```bash
OLD=/c/Users/angus/security-homelab/projects/offensive/llm_red_team && NEW=/c/Users/angus/projects/llm-injection-lab && cp $OLD/modules/{parser,scoring,mapping}.py $OLD/modules/mappings.yaml $NEW/src/llmlab/analysis/
```

- [ ] **Step 2: Rewrite imports**

```bash
cd /c/Users/angus/projects/llm-injection-lab/src/llmlab/analysis && sed -i 's/^import config$/from llmlab import config/; s/^from modules\.parser import /from llmlab.analysis.parser import /; s/^from modules\.scoring import /from llmlab.analysis.scoring import /; s/^from modules\.mapping import /from llmlab.analysis.mapping import /; s/^from modules import /from llmlab.analysis import /; s/^from modules\./from llmlab.analysis./' *.py
```

- [ ] **Step 3: Check for stale references**

```bash
cd /c/Users/angus/projects/llm-injection-lab/src/llmlab/analysis && grep -n "modules\.\|modules/" *.py || echo "clean"
```

Fix docstring paths by hand: `modules/mappings.yaml` becomes `llmlab/analysis/mappings.yaml`.

- [ ] **Step 4: Confirm the mappings file now resolves**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests/test_packaging.py -v
```

Expected: all four packaging tests PASS now, including `test_mappings_file_resolves_to_a_real_file`.

- [ ] **Step 5: Copy `test_analysis.py` and rewrite imports**

```bash
OLD=/c/Users/angus/security-homelab/projects/offensive/llm_red_team && NEW=/c/Users/angus/projects/llm-injection-lab && cp $OLD/tests/test_analysis.py $NEW/tests/ && cd $NEW/tests && sed -i 's/^import config$/from llmlab import config/; s/^from modules import reporter/from llmlab.report import profile as reporter/; s/^from modules\.parser import /from llmlab.analysis.parser import /; s/^from modules\.scoring import /from llmlab.analysis.scoring import /; s/^from modules\.mapping import /from llmlab.analysis.mapping import /; s/^from modules import /from llmlab.analysis import /; s/^from modules\./from llmlab.analysis./' test_analysis.py
```

- [ ] **Step 6: Run, expecting reporter tests to fail**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests/test_analysis.py -v
```

Expected: parser, scoring and mapping tests PASS. Any test touching `reporter` FAILS with an import or attribute error — the report layer arrives in Task 6. **Record exactly which tests fail**; Task 6 must turn all of them green.

- [ ] **Step 7: Report for commit**

```bash
cd /c/Users/angus/projects/llm-injection-lab && git add -A && git commit -m "Port analysis layer"
```

---

### Task 6: Split the reporter into the report package

`modules/reporter.py` is 404 lines doing three jobs. It splits at its existing seams: profile-building (lines 39–160), Markdown rendering (190–296), HTML rendering (296–404).

**Files:**
- Create: `src/llmlab/report/profile.py` — `build_profile` and its private helpers `_tier_block`, `_matrix`, `_evidence`, `_clip`, `_pct`
- Create: `src/llmlab/report/markdown.py` — `render_markdown(profile) -> str`
- Create: `src/llmlab/report/html.py` — `render_html(profile) -> str`
- Modify: `src/llmlab/report/__init__.py` — re-export the public API and host `write_reports`
- Test: `tests/test_report.py` (extracted from `tests/test_analysis.py`)

**Interfaces:**
- Consumes: `llmlab.analysis.scoring.TierScore`, `llmlab.analysis.mapping`, `llmlab.config`.
- Produces: `llmlab.report.build_profile(...)`, `llmlab.report.render_markdown(profile)`, `llmlab.report.render_html(profile)`, `llmlab.report.write_reports(...)`. All four importable from `llmlab.report` directly, so callers need not know about the split.

- [ ] **Step 1: Read the source file and confirm the seams**

```bash
cd /c/Users/angus/security-homelab/projects/offensive/llm_red_team && grep -n "^def \|^# ---" modules/reporter.py
```

Confirm the line ranges before splitting; if they have drifted from the numbers above, use the actual ones.

- [ ] **Step 2: Create `profile.py`**

Move the module docstring, the imports, `build_profile`, `_tier_block`, `_matrix`, `_evidence`, `_clip` and `_pct` verbatim. Rewrite imports to `from llmlab import config`, `from llmlab.analysis.mapping import ...`, `from llmlab.analysis.scoring import TierScore`.

- [ ] **Step 3: Create `markdown.py`**

Move `render_markdown` verbatim. It consumes only the `profile` dict, so its imports are whatever it uses directly — check with `grep -n "_pct\|_clip" ` on the moved body and import those from `llmlab.report.profile` if referenced:

```bash
cd /c/Users/angus/projects/llm-injection-lab/src/llmlab/report && grep -n "_pct\|_clip\|_matrix\|_evidence" markdown.py html.py
```

Any hit means that helper must be imported from `.profile`.

- [ ] **Step 4: Create `html.py`**

Move `render_html` verbatim, with the same helper-import treatment.

- [ ] **Step 5: Write `report/__init__.py`**

```python
"""Turning scored findings into artifacts: JSON, Markdown and self-contained HTML."""

from llmlab.report.html import render_html
from llmlab.report.markdown import render_markdown
from llmlab.report.profile import build_profile

__all__ = ["build_profile", "render_html", "render_markdown", "write_reports"]
```

Then move `write_reports` (old lines 175–190) into this file verbatim, adjusting it to call the now-imported `render_markdown` and `render_html`.

- [ ] **Step 6: Extract the reporter tests into `tests/test_report.py`**

Move every test recorded as failing in Task 5 Step 6 out of `tests/test_analysis.py` into a new `tests/test_report.py`, changing only their imports to `from llmlab import report`. Give the file this docstring:

```python
"""Report rendering: profile structure, Markdown and HTML output."""
```

- [ ] **Step 7: Run the full suite so far**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests -v
```

Expected: everything PASSES. The combined count across `test_analysis.py` and `test_report.py` must equal the Task 5 count for `test_analysis.py` alone.

- [ ] **Step 8: Lint and report for commit**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m ruff check . && .venv/Scripts/python.exe -m ruff format --check .
```

```bash
cd /c/Users/angus/projects/llm-injection-lab && git add -A && git commit -m "Split reporter into report package"
```

---

### Task 7: Split the CLI and wire the entry point

`main.py` is 452 lines doing three jobs: argparse wiring, scan orchestration, and rich console output.

**Files:**
- Create: `src/llmlab/cli.py` — `build_parser()`, `main(argv=None)`, and the `cmd_*` dispatch functions
- Create: `src/llmlab/runner.py` — `_free_port`, `serve_in_thread`, `build_target_app`, `_scan_tier`, `_run_native`, `_run_garak`, `_stamp`
- Create: `src/llmlab/console.py` — `_print_summary` and the `list` output tables
- Create: `src/llmlab/__main__.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: everything from Tasks 1–6.
- Produces: `llmlab.cli.main(argv: list[str] | None = None) -> int`; `llmlab.runner.serve_in_thread(app, host, port)` (context manager yielding a base URL str), `build_target_app(tier, backend_name, canary)`, `scan_tier(...)`; `llmlab.console.print_summary(tiers, deltas)`.

Note the rename: the private `_scan_tier` and `_print_summary` become public `scan_tier` and `print_summary`, because they now cross a module boundary.

- [ ] **Step 1: Copy `main.py` as the basis for the three files**

```bash
OLD=/c/Users/angus/security-homelab/projects/offensive/llm_red_team && cp $OLD/main.py /c/Users/angus/projects/llm-injection-lab/src/llmlab/cli.py
```

- [ ] **Step 2: Move the orchestration functions into `runner.py`**

Cut `_free_port` (line 49), `serve_in_thread` (66), `build_target_app` (87), `_scan_tier` (150), `_run_native` (187), `_run_garak` (213) and `_stamp` (365) out of `cli.py` and into a new `runner.py`. Rename `_scan_tier` to `scan_tier`. Header:

```python
"""Scan orchestration: stand the target up, fire both engines at it, collect reports."""
```

- [ ] **Step 3: Move the console output into `console.py`**

Cut `_print_summary` (line 263) and the table-building parts of `cmd_list` (311) into `console.py`, renaming `_print_summary` to `print_summary`. The `console = Console()` singleton moves here and is imported by the other two modules. Header:

```python
"""Terminal output: summary tables and `list` command rendering."""
```

- [ ] **Step 4: Rewrite imports in all three files**

Each file needs `from llmlab import config`, plus:
- `from llmlab.engines import garak, native, probes`
- `from llmlab.analysis import mapping, parser`
- `from llmlab.analysis.scoring import defence_deltas, score_reports`
- `from llmlab import report`
- `from llmlab.target.app import create_app`
- `from llmlab.target.backends import build_backend`
- `from llmlab.target.tiers import POLICIES, get_policy`

Note the module renames: `garak_runner` is now `garak`, `native_runner` is now `native`, and `reporter` is now the `report` package.

- [ ] **Step 5: Write `__main__.py`**

```python
"""Entry point for `python -m llmlab`."""

import sys

from llmlab.cli import main

if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 6: Write the failing CLI test**

Create `tests/test_cli.py`:

```python
"""The CLI parses, dispatches, and lists without touching the network."""

import pytest

from llmlab.cli import build_parser, main


def test_parser_builds():
    parser = build_parser()
    args = parser.parse_args(["scan", "--suite", "quick"])
    assert args.suite == "quick"


def test_list_suites_exits_zero(capsys):
    assert main(["list", "suites"]) == 0
    assert "quick" in capsys.readouterr().out


def test_unknown_suite_is_rejected():
    with pytest.raises(SystemExit):
        main(["scan", "--suite", "nonexistent"])
```

- [ ] **Step 7: Run it**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests/test_cli.py -v
```

Expected: PASS. If `test_unknown_suite_is_rejected` fails because `resolve_suite` raises `ValueError` rather than exiting, adjust the test to `pytest.raises(ValueError)` — match the existing behaviour rather than changing it, since this task is a move.

- [ ] **Step 8: Verify the console script works**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/llmlab.exe --help && .venv/Scripts/llmlab.exe list suites && .venv/Scripts/llmlab.exe list probes
```

Expected: all three produce output and exit 0.

- [ ] **Step 9: Run the whole suite and lint**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests -q && .venv/Scripts/python.exe -m ruff check . && .venv/Scripts/python.exe -m ruff format --check .
```

Expected: the pass count now meets or exceeds the Task 0 baseline (it will exceed it, by the packaging and CLI tests added along the way). **This is the gate that says the migration preserved behaviour.**

- [ ] **Step 10: Report for commit**

```bash
cd /c/Users/angus/projects/llm-injection-lab && git add -A && git commit -m "Split CLI into cli, runner and console modules"
```

---

### Task 8: Add the headline suite

First task with new logic — written test-first. The garak probe names in the spec are *intent*, not verified; this task verifies them against the installed garak before committing to them.

**Files:**
- Modify: `src/llmlab/config.py` (the `SUITES` dict)
- Test: `tests/test_suites.py`

**Interfaces:**
- Produces: `config.SUITES["headline"]` with `garak` and `native` key lists.

- [ ] **Step 1: Install garak**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pip install -e ".[scan]"
```

This pulls torch and is slow — expect several minutes and a large download. It is needed only to verify probe names.

- [ ] **Step 2: List the real probe names**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m garak --list_probes 2>&1 | grep -iE "latentinjection|promptinject|dan\.|encoding\.InjectBase64|xss|web_injection|suffix"
```

**Record the exact names that exist.** The spec's guesses — `dan.DanInTheWildMini`, `promptinject.*Mini`, `encoding.InjectBase64`, `xss.MarkdownImageExfil`, `suffix.GCGCached` — must each be confirmed or replaced with the real equivalent. Note that `xss` was renamed `web_injection` in garak 0.16, which `config.SUITES["leakage"]` already comments on.

- [ ] **Step 3: Write the failing suite test**

Create `tests/test_suites.py`:

```python
"""The headline suite is well-formed and sized for a re-runnable comparison."""

import pytest

from llmlab import config


def test_headline_suite_exists():
    assert "headline" in config.SUITES


def test_headline_resolves():
    suite = config.resolve_suite("headline")
    assert set(suite) == {"garak", "native"}


def test_headline_includes_every_native_pack_and_the_control_group():
    native = config.resolve_suite("headline")["native"]
    for pack in ("canary_exfil", "policy_override", "tool_hijack", "rag_poison"):
        assert pack in native, f"headline must include {pack}"


def test_headline_garak_families_are_a_curated_subset():
    headline = set(config.resolve_suite("headline")["garak"])
    full = set(config.resolve_suite("full")["garak"])
    assert headline, "headline must include some garak coverage"
    assert headline != full, "headline must be narrower than full"


def test_full_suite_still_contains_everything():
    full = config.resolve_suite("full")
    assert len(full["garak"]) > len(config.resolve_suite("headline")["garak"])


@pytest.mark.parametrize("name", ["quick", "injection", "jailbreak", "leakage", "agency", "full"])
def test_existing_suites_are_untouched(name):
    assert name in config.SUITES
```

- [ ] **Step 4: Run to verify it fails**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests/test_suites.py -v
```

Expected: FAIL — `"headline" in config.SUITES` is False.

- [ ] **Step 5: Add the suite to `config.py`**

Insert into the `SUITES` dict, **before** the `SUITES["full"] = ...` line so `full` still absorbs everything. Substitute the probe names confirmed in Step 2:

```python
    #: The suite behind FINDINGS.md. Sized so a three-tier comparison against a
    #: real model finishes in about an hour and can be re-run after any change.
    #: `full` exists for completeness and takes roughly fifteen.
    "headline": {
        "garak": [
            # Names verified against the installed garak in Task 8 Step 2.
            "latentinjection",
            "promptinject.HijackHateHumansMini",
            "dan.DanInTheWildMini",
            "encoding.InjectBase64",
            "web_injection",
            "suffix.GCGCached",
        ],
        "native": ["canary_exfil", "policy_override", "tool_hijack", "rag_poison"],
    },
```

- [ ] **Step 6: Run the test again**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests/test_suites.py -v
```

Expected: PASS.

- [ ] **Step 7: Dry-run the suite to confirm garak accepts every name**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/llmlab.exe scan --all-tiers --suite headline --dry-run
```

Expected: prints the garak commands without sending anything. Any family garak does not recognise is reported as skipped-with-a-reason rather than a crash — if one is skipped, go back to Step 2 and correct the name.

- [ ] **Step 8: Report for commit**

```bash
cd /c/Users/angus/projects/llm-injection-lab && git add -A && git commit -m "Add curated headline suite"
```

---

### Task 9: Split generations per engine

`main.py:399` defines a single `--generations` flag used for both engines (`main.py:197` for native, `main.py:217` for garak). The spec calls for garak at 1 for breadth and native at 5, so the small deterministic packs carry a sample size.

**Files:**
- Modify: `src/llmlab/config.py`, `src/llmlab/cli.py`, `src/llmlab/runner.py`
- Test: `tests/test_suites.py`

**Interfaces:**
- Consumes: `runner.scan_tier` (Task 7).
- Produces: `config.GARAK_GENERATIONS = 1`, `config.NATIVE_GENERATIONS = 5`; CLI flags `--generations` and `--native-generations`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_suites.py`:

```python
def test_generations_defaults_differ_by_engine():
    assert config.GARAK_GENERATIONS == 1
    assert config.NATIVE_GENERATIONS == 5


def test_cli_exposes_a_separate_native_generations_flag():
    from llmlab.cli import build_parser

    args = build_parser().parse_args(["scan", "--suite", "headline"])
    assert args.generations == config.GARAK_GENERATIONS
    assert args.native_generations == config.NATIVE_GENERATIONS


def test_native_generations_is_overridable():
    from llmlab.cli import build_parser

    args = build_parser().parse_args(["scan", "--native-generations", "3"])
    assert args.native_generations == 3
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests/test_suites.py -v -k generations
```

Expected: FAIL — `GARAK_GENERATIONS` is currently 3 and `NATIVE_GENERATIONS` does not exist.

- [ ] **Step 3: Update `config.py`**

Replace the existing `GARAK_GENERATIONS = 3` and its comment with:

```python
#: Generations per garak probe prompt. One, because garak's families are large
#: and their job here is breadth — the sample size that matters is in the native
#: packs, which are small enough to repeat.
GARAK_GENERATIONS = 1

#: Generations per native probe. The four native packs total ~35 probes, so five
#: repeats cost about ten minutes and give the deterministic detectors — the
#: findings the report leans on hardest — a real hit-count rather than a coin flip.
NATIVE_GENERATIONS = 5
```

- [ ] **Step 4: Add the CLI flag**

In `cli.py`, beside the existing `--generations` argument, add:

```python
    scan.add_argument(
        "--native-generations",
        type=int,
        default=config.NATIVE_GENERATIONS,
        help=f"repeats per native probe (default: {config.NATIVE_GENERATIONS})",
    )
```

and change the existing `--generations` default to `config.GARAK_GENERATIONS`, updating its help text to say it applies to garak families only.

- [ ] **Step 5: Use the new flag in `runner.py`**

In `_run_native`, change the generations argument passed through from `args.generations` to `args.native_generations`. `_run_garak` keeps `args.generations`.

- [ ] **Step 6: Run the tests**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests -q
```

Expected: PASS.

- [ ] **Step 7: Show the hit count in the report**

In `src/llmlab/report/markdown.py`, the defence-matrix cells currently render a bare percentage via `_pct`. Change the per-family cells to render `f"{_pct(rate)} ({hits}/{attempts})"` using the `FamilyScore.hits` and `FamilyScore.attempts` fields that `llmlab.analysis.scoring` already populates. This is what turns `100%` into `100% (5/5)`, which is the point of raising native generations.

- [ ] **Step 8: Run the report tests**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests/test_report.py -v
```

If a test asserts on the old bare-percentage cell text, update that assertion to the new format — this is an intended output change, not a regression.

- [ ] **Step 9: Lint and report for commit**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m ruff check . && .venv/Scripts/python.exe -m ruff format --check .
```

```bash
cd /c/Users/angus/projects/llm-injection-lab && git add -A && git commit -m "Split generations per engine and show hit counts in the matrix"
```

---

### Task 10: Pin Ollama sampling

`OllamaBackend.generate` currently sends no `options` block, so temperature and seed are whatever the daemon defaults to and results drift between runs. A finding that cannot be re-derived is not a finding.

**Files:**
- Modify: `src/llmlab/target/backends.py`, `src/llmlab/config.py`, `src/llmlab/cli.py`, `src/llmlab/runner.py`
- Test: `tests/test_target.py`

**Interfaces:**
- Produces: `OllamaBackend(model, url, timeout, seed=None, temperature=0.0)`; `build_backend(name, model, url, timeout, seed=None)`; `config.DEFAULT_SEED = 20260825`; CLI flag `--seed`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_target.py`:

```python
def test_ollama_backend_sends_pinned_sampling_options(monkeypatch):
    """Temperature and seed must reach the daemon, or runs are not reproducible."""
    captured = {}

    class _Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": "ok"}}

    def _fake_post(url, json, timeout):
        captured.update(json)
        return _Response()

    import requests

    monkeypatch.setattr(requests, "post", _fake_post)

    from llmlab.target.backends import OllamaBackend

    backend = OllamaBackend("llama3.2", "http://x/api/chat", 120, seed=4242)
    assert backend.generate("sys", "user") == "ok"

    assert captured["options"]["temperature"] == 0.0
    assert captured["options"]["seed"] == 4242


def test_ollama_backend_omits_seed_when_unset(monkeypatch):
    captured = {}

    class _Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": "ok"}}

    def _fake_post(url, json, timeout):
        captured.update(json)
        return _Response()

    import requests

    monkeypatch.setattr(requests, "post", _fake_post)

    from llmlab.target.backends import OllamaBackend

    OllamaBackend("llama3.2", "http://x/api/chat", 120).generate("sys", "user")
    assert "seed" not in captured["options"]
    assert captured["options"]["temperature"] == 0.0
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests/test_target.py -v -k ollama
```

Expected: FAIL with `KeyError: 'options'`.

- [ ] **Step 3: Update `OllamaBackend`**

Change `__init__` to accept the new arguments and `generate` to send them:

```python
    def __init__(
        self, model: str, url: str, timeout: int, seed: int | None = None, temperature: float = 0.0
    ) -> None:
        self.model = model
        self.url = url
        self.timeout = timeout
        self.seed = seed
        self.temperature = temperature
```

and in `generate`, add an `options` key to the posted JSON:

```python
        options: dict[str, float | int] = {"temperature": self.temperature}
        if self.seed is not None:
            options["seed"] = self.seed
```

then include `"options": options` in the `json=` dict alongside `model`, `stream` and `messages`.

- [ ] **Step 4: Thread the seed through `build_backend`**

Add a `seed: int | None = None` parameter to `build_backend` and pass it to `OllamaBackend`. `MockBackend` ignores it — it takes no sampling parameters and must keep its current signature.

- [ ] **Step 5: Add `DEFAULT_SEED` to config**

```python
#: Default sampling seed. Recorded in every run manifest so a published result
#: can be re-derived, and overridable with --seed.
DEFAULT_SEED = 20260825
```

- [ ] **Step 6: Add the `--seed` CLI flag and thread it to the backend**

In `cli.py`:

```python
    scan.add_argument(
        "--seed",
        type=int,
        default=config.DEFAULT_SEED,
        help=f"sampling seed for the ollama backend (default: {config.DEFAULT_SEED})",
    )
```

In `runner.py`, `build_target_app` gains a `seed: int | None = None` parameter and passes it to `build_backend`. Its callers pass `args.seed`.

- [ ] **Step 7: Run the tests**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests -q
```

Expected: PASS.

- [ ] **Step 8: Lint and report for commit**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m ruff check . && .venv/Scripts/python.exe -m ruff format --check .
```

```bash
cd /c/Users/angus/projects/llm-injection-lab && git add -A && git commit -m "Pin ollama temperature and seed for reproducible runs"
```

---

### Task 11: Write a run manifest

**Files:**
- Create: `src/llmlab/manifest.py`
- Modify: `src/llmlab/runner.py`, `src/llmlab/report/profile.py`, `src/llmlab/report/markdown.py`
- Test: `tests/test_manifest.py`

**Interfaces:**
- Consumes: `llmlab.engines.garak.garak_available()` (Task 3), `runner.scan_tier` (Task 7), `report.build_profile` (Task 6).
- Produces: `llmlab.manifest.build_manifest(...) -> dict`, `llmlab.manifest.finish(data) -> dict`, `llmlab.manifest.write_manifest(run_dir, data) -> Path`, `llmlab.manifest.read_manifest(run_dir) -> dict | None`, `llmlab.manifest.ollama_digest(model, url) -> str | None`; `llmlab.engines.garak.garak_version() -> str | None`; `build_profile` gains a `manifest: dict | None = None` keyword.

- [ ] **Step 1: Write the failing test**

Create `tests/test_manifest.py`:

```python
"""Every run records what produced it, so a published number can be re-derived."""

import json

from llmlab import manifest


def _sample(tmp_path):
    return manifest.build_manifest(
        run_dir=tmp_path,
        backend="ollama",
        model="llama3.2",
        model_digest="sha256:abc123",
        garak_version="0.16.0",
        suite="headline",
        tiers=["naive", "guarded", "hardened"],
        seed=20260825,
        garak_generations=1,
        native_generations=5,
    )


def test_manifest_records_every_reproducibility_field(tmp_path):
    data = _sample(tmp_path)
    for key in (
        "backend",
        "model",
        "model_digest",
        "garak_version",
        "suite",
        "tiers",
        "seed",
        "garak_generations",
        "native_generations",
        "started_at",
        "python_version",
        "llmlab_version",
    ):
        assert key in data, f"manifest is missing {key}"


def test_manifest_round_trips_to_disk(tmp_path):
    data = _sample(tmp_path)
    path = manifest.write_manifest(tmp_path, data)
    assert path.name == "manifest.json"
    assert json.loads(path.read_text(encoding="utf-8"))["suite"] == "headline"
    assert manifest.read_manifest(tmp_path)["seed"] == 20260825


def test_read_manifest_returns_none_when_absent(tmp_path):
    assert manifest.read_manifest(tmp_path) is None


def test_finish_records_duration(tmp_path):
    data = _sample(tmp_path)
    finished = manifest.finish(data)
    assert "finished_at" in finished
    assert finished["duration_seconds"] >= 0
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests/test_manifest.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'llmlab.manifest'`.

- [ ] **Step 3: Write `src/llmlab/manifest.py`**

```python
"""Run manifest.

A published attack-success rate is only worth as much as the reader's ability to
re-derive it. Every run records the model, its digest, the garak version, the
suite, the seed and the generation counts, so the numbers in FINDINGS.md can be
checked rather than taken on trust.
"""

from __future__ import annotations

import json
import platform
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import llmlab

MANIFEST_NAME = "manifest.json"


def build_manifest(
    *,
    run_dir: Path,
    backend: str,
    model: str | None,
    model_digest: str | None,
    garak_version: str | None,
    suite: str,
    tiers: list[str],
    seed: int | None,
    garak_generations: int,
    native_generations: int,
) -> dict[str, Any]:
    """Capture everything needed to reproduce this run."""
    return {
        "run_dir": str(run_dir),
        "backend": backend,
        "model": model,
        "model_digest": model_digest,
        "garak_version": garak_version,
        "suite": suite,
        "tiers": list(tiers),
        "seed": seed,
        "garak_generations": garak_generations,
        "native_generations": native_generations,
        "started_at": datetime.now(UTC).isoformat(),
        "_started_monotonic": time.monotonic(),
        "python_version": platform.python_version(),
        "llmlab_version": llmlab.__version__,
    }


def finish(data: dict[str, Any]) -> dict[str, Any]:
    """Stamp the end time and wall-clock duration onto a manifest."""
    started = data.pop("_started_monotonic", time.monotonic())
    data["finished_at"] = datetime.now(UTC).isoformat()
    data["duration_seconds"] = round(time.monotonic() - started, 1)
    return data


def write_manifest(run_dir: Path, data: dict[str, Any]) -> Path:
    path = Path(run_dir) / MANIFEST_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {k: v for k, v in data.items() if not k.startswith("_")}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def read_manifest(run_dir: Path) -> dict[str, Any] | None:
    path = Path(run_dir) / MANIFEST_NAME
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def ollama_digest(model: str, url: str) -> str | None:
    """Ask the Ollama daemon for the model's digest.

    Returns None rather than raising: a missing digest degrades the manifest, it
    does not invalidate the run.
    """
    import requests

    try:
        response = requests.post(
            url.replace("/api/chat", "/api/show"), json={"model": model}, timeout=10
        )
        response.raise_for_status()
        return response.json().get("details", {}).get("parent_model") or response.json().get(
            "digest"
        )
    except Exception:
        return None
```

- [ ] **Step 4: Run the tests**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests/test_manifest.py -v
```

Expected: PASS.

- [ ] **Step 5: Call it from the scan command**

First add the version helper to `src/llmlab/engines/garak.py`, directly beneath the existing `garak_available()`:

```python
def garak_version() -> str | None:
    """Return the installed garak's version, or None if garak is absent.

    Mirrors ``garak_available``: a missing scanner is a documented condition
    here, not an error.
    """
    import subprocess

    try:
        result = subprocess.run(
            [config.GARAK_BIN, "--version"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None
```

Then in `runner.py`, at the start of a scan build the manifest and after the last tier finishes call `finish` and `write_manifest` into the run directory:

```python
    run_manifest = manifest.build_manifest(
        run_dir=run_dir,
        backend=args.backend,
        model=config.OLLAMA_MODEL if args.backend == "ollama" else None,
        model_digest=(
            manifest.ollama_digest(config.OLLAMA_MODEL, config.OLLAMA_URL)
            if args.backend == "ollama"
            else None
        ),
        garak_version=garak.garak_version(),
        suite=args.suite,
        tiers=tiers,
        seed=args.seed if args.backend == "ollama" else None,
        garak_generations=args.generations,
        native_generations=args.native_generations,
    )
```

and after the tier loop completes:

```python
    manifest.write_manifest(run_dir, manifest.finish(run_manifest))
```

- [ ] **Step 6: Surface it in the report**

In `report/profile.py`, `build_profile` gains a `manifest: dict | None = None` parameter and puts it in the profile under a `"manifest"` key. In `report/markdown.py`, render a single line beneath the headline table when a manifest is present:

```
> Run: `{suite}` suite, backend `{backend}`, model `{model}` ({model_digest}), garak {garak_version}, seed {seed}, {duration_seconds}s — {started_at}
```

When no manifest is present, render nothing — old run directories must still analyse.

- [ ] **Step 7: Verify with an offline scan**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/llmlab.exe scan --all-tiers --suite quick --backend mock --no-garak
```

Then confirm the manifest landed:

```bash
cd /c/Users/angus/projects/llm-injection-lab && cat runs/*/manifest.json
```

Expected: valid JSON with every field populated (`model` and `model_digest` will be null for the mock backend, which is correct).

- [ ] **Step 8: Full suite, lint, report for commit**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests -q && .venv/Scripts/python.exe -m ruff check . && .venv/Scripts/python.exe -m ruff format --check .
```

```bash
cd /c/Users/angus/projects/llm-injection-lab && git add -A && git commit -m "Record a manifest for every run"
```

---

### Task 12: Produce the real run

**Files:**
- Create: `runs/<timestamp>/` (gitignored), `screenshots/01_report-defence-matrix.png`, `screenshots/02_report-evidence.png`

- [ ] **Step 1: Ask the owner to start Ollama**

The daemon was confirmed off. Ask the owner to run:

```bash
ollama serve
```

- [ ] **Step 2: Confirm the model is present**

```bash
ollama list
```

If `llama3.2` is absent, ask the owner to pull it — this is a large download and their call to make:

```bash
ollama pull llama3.2
```

- [ ] **Step 3: Time a single tier before committing to all three**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/llmlab.exe scan --tier naive --suite headline --backend ollama
```

**Record the wall-clock from the manifest.** If one tier takes materially longer than ~20 minutes, stop and report to the owner before running all three — the suite needs narrowing rather than a surprise overnight run.

- [ ] **Step 4: Run the full comparison**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/llmlab.exe scan --all-tiers --suite headline --backend ollama --format all
```

- [ ] **Step 5: Read the results**

```bash
cd /c/Users/angus/projects/llm-injection-lab && cat runs/*/manifest.json && ls runs/*/
```

Record the macro ASR, pooled ASR and utility per tier, and the full defence matrix. **Report the numbers as they came out.** If a headline claim from the old FINDINGS did not survive, that is the finding — do not re-run with different settings to recover it.

- [ ] **Step 6: Capture the two screenshots**

Open the generated HTML report and capture the defence-matrix section as `screenshots/01_report-defence-matrix.png` and the evidence section as `screenshots/02_report-evidence.png`, replacing the old images.

- [ ] **Step 7: Report for commit**

```bash
cd /c/Users/angus/projects/llm-injection-lab && git add screenshots && git commit -m "Add report screenshots from the real headline run"
```

---

### Task 13: Rewrite FINDINGS.md and README.md

**Files:**
- Create: `FINDINGS.md`, `README.md`

- [ ] **Step 1: Rewrite `FINDINGS.md` against the real numbers**

Keep the structure that works: the headline table, the defence matrix, application findings as an **F-series** (about the target's controls) kept separate from method findings as an **M-series** (about the measurement), evidence per finding, and a Reproducing section.

Two changes from the old document:
- The "Read this first" section about the mock backend is **removed**. Replace it with a short methodology note: which suite ran, why it is curated rather than exhaustive, and the manifest line identifying the model, digest, garak version and seed.
- Every table is regenerated from the Task 12 run. No number survives from the old document.

- [ ] **Step 2: Rewrite `README.md` in the reviewer-first order**

Sections, in this order:

1. One-paragraph description and the CI badge
2. Legal and authorisation notice
3. **The result** — tier table and defence matrix, with the manifest line beneath
4. **Why a target application and not a model scan** — port the four-question table from the old README verbatim, it is the strongest argument in the document
5. The three hardening tiers and what each adds
6. Install and quick start — `pip install -e .`, `llmlab scan`, not `python main.py`
7. Probe coverage, reading the report, layout, testing, references

The mock backend drops from a section to two sentences in the testing section: it is a test double that keeps the suite network-free, and it produces no number in this repo.

- [ ] **Step 3: Update the layout tree**

Replace the old `modules/` tree with the `src/llmlab/` structure from this plan. Every path in the README must reflect the new package.

- [ ] **Step 4: Check every command in the README actually runs**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/llmlab.exe list suites && .venv/Scripts/llmlab.exe list probes && .venv/Scripts/llmlab.exe list mappings && .venv/Scripts/llmlab.exe --help
```

Every command block in the README must be executed and confirmed. A portfolio README with a command that errors is worse than one without the command.

- [ ] **Step 5: Report for commit**

```bash
cd /c/Users/angus/projects/llm-injection-lab && git add -A && git commit -m "Rewrite README and FINDINGS against the real headline run"
```

---

### Task 14: Retire the monorepo copy

Last, and only once the new repo is green with real findings recorded.

**Files:**
- Delete: `projects/offensive/llm_red_team/`
- Modify: `README.md` (security-homelab root)

- [ ] **Step 1: Confirm the new repo stands on its own**

```bash
cd /c/Users/angus/projects/llm-injection-lab && .venv/Scripts/python.exe -m pytest tests -q && .venv/Scripts/python.exe -m ruff check .
```

Expected: green. Do not proceed otherwise.

- [ ] **Step 2: Confirm nothing else in the monorepo references the directory**

```bash
cd /c/Users/angus/security-homelab && grep -rn "llm_red_team" --include="*.md" --include="*.toml" --include="*.yml" . | grep -v "docs/superpowers"
```

Every hit must be updated in Step 4. Spec and plan documents under `docs/superpowers/` are historical records and stay as they are.

- [ ] **Step 3: Remove the directory**

```bash
cd /c/Users/angus/security-homelab && git rm -r projects/offensive/llm_red_team
```

- [ ] **Step 4: Link out from the homelab README**

In the **Offensive** table of `README.md`, replace the removed row (or add one if absent) with a row pointing at the new repository, matching the existing three-column format:

```markdown
| [LLM Injection Lab](https://github.com/<owner>/llm-injection-lab) | Prompt-injection red-team harness measuring LLM application defences across three hardening tiers | Python, garak, Ollama, FastAPI |
```

Substitute the real GitHub owner and URL confirmed when the remote was created in Task 1.

- [ ] **Step 5: Report for commit**

Two repositories, two commits. For the homelab:

```bash
cd /c/Users/angus/security-homelab && git add -A && git commit -m "Move llm_red_team out to its own repository"
```

---

## Notes for the executor

- **Tasks 2–7 are moves.** If a test fails in one of them, the move broke something — fix the move. Do not change an assertion to match new behaviour, because there should be no new behaviour.
- **Tasks 8–11 are the only new logic** and each is written test-first.
- The `sed` commands rewrite `import` lines only. Docstrings and comments carrying old paths are caught by the explicit grep steps and fixed by hand.
- If a task's gate cannot be met, stop and report rather than working around it. The Task 0 baseline exists so "was this already broken?" is always answerable.
