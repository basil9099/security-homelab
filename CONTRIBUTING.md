# Contributing

This repository is a monorepo of independent security tools and labs. Each
project under `projects/{offensive,defensive,hardware}/<name>/` is self-contained
with its own `requirements.txt`, README, and (where applicable) tests.

## Repository layout

```
projects/
├── offensive/   # red-team tools & exercises
├── defensive/   # blue-team tools & infrastructure
└── hardware/    # physical-security tooling
```

There is intentionally no top-level Python package. The root `pyproject.toml`
exists only to give **ruff** and **pytest** a single shared configuration.

## Development setup

Work inside the project you're changing, using a virtual environment:

```bash
cd projects/<area>/<project>
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt   # falls back to requirements.txt if no -dev file
```

## Linting & formatting

Linting and formatting are handled by [ruff](https://github.com/astral-sh/ruff),
configured in the root `pyproject.toml`. Install the git hooks so both run
automatically on commit:

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files   # run against the whole tree on demand
```

Or run ruff directly:

```bash
ruff check .      # lint
ruff format .     # auto-format
```

## Tests

Tested projects keep their tests in a `tests/` directory with a `conftest.py`
that puts the project root on `sys.path`, so imports match how the tool runs.
Run them from within the project:

```bash
cd projects/<area>/<project>
pytest tests -q
```

Tests must be **deterministic and network-free** — mock or guard any HTTP,
DNS, or socket calls so the suite passes in CI without external services.

## Continuous integration

`.github/workflows/ci.yml` runs two jobs on every push and pull request:

- **lint** — `ruff check` over the projects currently under CI.
- **test** — a matrix of `{project} × {Python 3.11, 3.12}`; each cell installs
  the project's `requirements-dev.txt` and runs its tests.

To bring a new project under CI:

1. Add a `tests/` directory (with `conftest.py`) and a `requirements-dev.txt`.
2. Add the project's path to the `ruff check` list in the **lint** job.
3. Add the project's path to the `project` list in the **test** matrix.

## Commit & PR conventions

- Keep commit messages imperative and scoped (e.g. `Add tests for honeypot event logger`).
- Never commit secrets, real capture files, or malware samples — see
  `.gitignore`, which already blocks binaries, samples, and runtime artifacts.
- Open a pull request against `main`; CI must be green before merge.
