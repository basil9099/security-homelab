"""Layer C: metadata validation. Pure Python, no Splunk, no Docker."""

import json

import jsonschema
import pytest
from lib.loader import (
    INDEX_RE,
    PROJECT_ROOT,
    load_rules,
    normalise_spl,
    spl_field_references,
    substitute_index,
)

SCHEMA = json.loads((PROJECT_ROOT / "schema.json").read_text(encoding="utf-8"))


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


@pytest.mark.parametrize("rule", load_rules(), ids=lambda r: r.id)
def test_detection_metadata_matches_schema(rule):
    jsonschema.validate(
        instance=rule.meta, schema=SCHEMA, format_checker=jsonschema.FormatChecker()
    )


@pytest.mark.parametrize("rule", load_rules(), ids=lambda r: r.id)
def test_status_is_validated_offline(rule):
    # No detection here has seen live lab data. Saying otherwise in a portfolio
    # repo is the exact overstatement this project exists to remove.
    assert rule.meta["status"] == "validated-offline"


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


def test_field_references_catch_lowercase_names_in_by_and_aggregations():
    # A lowercase field name such as `src_ip` must be reported like any other:
    # case plays no part in deciding what is a field.
    spl = "index=x EventCode=1 | stats dc(src_user) AS users BY _time, src_ip"
    assert spl_field_references(spl) == {"EventCode", "src_user", "src_ip"}


def test_field_references_catch_lowercase_filters_but_not_splunk_arguments():
    spl = 'index=wineventlog sourcetype="x" logon_type=3 | bucket _time span=15m'
    assert spl_field_references(spl) == {"logon_type"}


@pytest.mark.parametrize("rule", load_rules(), ids=lambda r: r.id)
def test_every_search_can_be_pointed_at_a_test_index(rule):
    # The behaviour tests load each rule's fixtures into their own index and
    # rewrite the search's index= term to match. Prove that rewrite works for
    # every real rule, and that it is the only edit made to the search.
    original = INDEX_RE.search(rule.spl).group(0)
    rewritten = substitute_index(rule.spl, "test_idx")
    assert "index=test_idx" in rewritten
    assert rewritten.replace("index=test_idx", original, 1) == rule.spl


def test_index_substitution_refuses_ambiguous_searches():
    # Exactly one index= term, or the rewrite could miss one or apply twice and
    # let fixtures leak between tests.
    with pytest.raises(ValueError):
        substitute_index("sourcetype=x EventCode=1", "test_idx")
    with pytest.raises(ValueError):
        substitute_index("index=a EventCode=1 OR index=b", "test_idx")
