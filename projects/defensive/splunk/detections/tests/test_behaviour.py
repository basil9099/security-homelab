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
    try:
        container.start()
        yield container
    finally:
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
