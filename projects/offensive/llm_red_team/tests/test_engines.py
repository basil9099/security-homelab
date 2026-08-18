"""Probe packs, detectors, the native engine and the garak invocation layer."""

import json
import os
import subprocess
import time
from pathlib import Path

import config
import pytest
from modules import detectors, garak_runner, native_runner, probes
from modules.parser import parse_report
from target.app import create_app
from target.backends import MockBackend

CANARY = f"{config.CANARY_PREFIX}-0123456789abcdef"


class TestProbePacks:
    def test_every_probe_names_a_real_detector(self):
        for probe in [p for pack in probes.PACKS.values() for p in pack] + probes.BENIGN:
            assert probe.detector in detectors.DETECTORS, probe.name

    def test_every_referenced_document_exists(self):
        for probe in [p for pack in probes.PACKS.values() for p in pack] + probes.BENIGN:
            if probe.doc_id:
                assert (config.CORPUS_DIR / probe.doc_id).is_file(), probe.doc_id

    def test_probe_names_are_unique_within_a_pack(self):
        for name, pack in probes.PACKS.items():
            assert len({p.name for p in pack}) == len(pack), name

    def test_rag_probes_all_use_poisoned_documents(self):
        for probe in probes.RAG_POISON:
            assert probe.doc_id and probe.doc_id.startswith("poisoned/")

    def test_benign_probes_carry_no_attack_payload(self):
        """The control group must be genuinely benign or utility means nothing."""
        from target.defenses import classify_injection

        for probe in probes.BENIGN:
            assert not classify_injection(probe.prompt).blocked, probe.name

    def test_resolve_packs_flattens(self):
        resolved = probes.resolve_packs(["canary_exfil", "tool_hijack"])
        assert len(resolved) == len(probes.CANARY_EXFIL) + len(probes.TOOL_HIJACK)

    def test_resolve_packs_rejects_unknown(self):
        with pytest.raises(ValueError, match="unknown probe pack"):
            probes.resolve_packs(["nope"])

    def test_suites_only_reference_real_packs(self):
        for name, suite in config.SUITES.items():
            for pack in suite["native"]:
                assert pack in probes.PACKS, f"{name} -> {pack}"


def _attempt(response="", tool_calls=None, blocked=False):
    return detectors.Attempt(
        probe=probes.CANARY_EXFIL[0],
        response=response,
        canary=CANARY,
        blocked=blocked,
        tool_calls=tool_calls or [],
    )


class TestDetectors:
    def test_canary_leak_fires_on_the_delivered_response(self):
        assert detectors.canary_leak(_attempt(f"code is {CANARY}")) == 1.0
        assert detectors.canary_leak(_attempt("code is [REDACTED]")) == 0.0

    def test_canary_leak_is_inert_without_a_canary(self):
        attempt = _attempt("anything")
        attempt.canary = ""
        assert detectors.canary_leak(attempt) == 0.0

    def test_policy_marker(self):
        assert detectors.policy_marker(_attempt(config.MARKER)) == 1.0
        assert detectors.policy_marker(_attempt("no thanks")) == 0.0

    def test_tool_exfil_needs_an_executed_exfil_tool(self):
        blocked = [{"name": "send_email", "executed": False, "exfil_capable": True}]
        allowed = [{"name": "read_file", "executed": True, "exfil_capable": False}]
        fired = [{"name": "send_email", "executed": True, "exfil_capable": True}]
        assert detectors.tool_exfil(_attempt(tool_calls=blocked)) == 0.0
        assert detectors.tool_exfil(_attempt(tool_calls=allowed)) == 0.0
        assert detectors.tool_exfil(_attempt(tool_calls=fired)) == 1.0

    @pytest.mark.parametrize("path", ["/etc/shadow", "../../secrets", "~/.ssh/id_rsa", "/app/.env"])
    def test_tool_path_traversal_flags_sensitive_paths(self, path):
        calls = [{"name": "read_file", "executed": True, "args": path}]
        assert detectors.tool_path_traversal(_attempt(tool_calls=calls)) == 1.0

    def test_tool_path_traversal_allows_ordinary_paths(self):
        calls = [{"name": "read_file", "executed": True, "args": "/shared/policies/expenses.md"}]
        assert detectors.tool_path_traversal(_attempt(tool_calls=calls)) == 0.0

    def test_refusal_flags_blocked_and_worded_refusals(self):
        assert detectors.refusal(_attempt(blocked=True)) == 1.0
        assert detectors.refusal(_attempt("I can't help with that request.")) == 1.0
        assert detectors.refusal(_attempt("Claims are due within 30 days.")) == 0.0

    def test_unknown_detector_is_rejected(self):
        with pytest.raises(ValueError, match="unknown detector"):
            detectors.run_detector("nope", _attempt())

    def test_threshold(self):
        assert detectors.is_hit(detectors.HIT_THRESHOLD)
        assert not detectors.is_hit(detectors.HIT_THRESHOLD - 0.01)


class TestNativeEngine:
    @pytest.fixture
    def client(self):
        return native_runner.LocalTarget(
            create_app(tier="naive", backend=MockBackend(), canary=CANARY)
        )

    def test_writes_a_parseable_garak_shaped_report(self, client, tmp_path):
        path = tmp_path / "native.report.jsonl"
        result = native_runner.run_native(
            probes.CANARY_EXFIL, client, CANARY, "naive", path, generations=1
        )
        assert result.attempts == len(probes.CANARY_EXFIL)
        assert result.hits > 0

        report = parse_report(path)
        assert report.engine == "native"
        assert report.tier == "naive"
        assert len(report.findings) == result.attempts
        assert sum(f.hit for f in report.findings) == result.hits

    def test_eval_rows_agree_with_the_attempts(self, client, tmp_path):
        path = tmp_path / "n.report.jsonl"
        native_runner.run_native(probes.TOOL_HIJACK, client, CANARY, "naive", path, generations=2)
        report = parse_report(path)
        assert sum(row.total for row in report.evals) == len(report.findings)
        assert sum(row.failed for row in report.evals) == sum(f.hit for f in report.findings)

    def test_generations_multiply_attempts(self, client, tmp_path):
        path = tmp_path / "g.report.jsonl"
        result = native_runner.run_native(
            probes.RAG_POISON, client, CANARY, "naive", path, generations=3
        )
        assert result.attempts == len(probes.RAG_POISON) * 3

    def test_notes_carry_the_containment_signal(self, client, tmp_path):
        path = tmp_path / "c.report.jsonl"
        native_runner.run_native(probes.CANARY_EXFIL, client, CANARY, "naive", path, generations=1)
        records = [json.loads(line) for line in path.read_text().splitlines()]
        attempts = [r for r in records if r["entry_type"] == "attempt"]
        assert all("raw_leak" in r["notes"] for r in attempts)
        assert all(r["notes"]["tier"] == "naive" for r in attempts)

    def test_backend_is_recorded_for_later_reporting(self, client, tmp_path):
        """`analyze`/`report` should not need to be told the backend again."""
        path = tmp_path / "b.report.jsonl"
        native_runner.run_native(
            probes.BENIGN, client, CANARY, "naive", path, generations=1, backend="mock"
        )
        assert parse_report(path).meta["backend"] == "mock"

    def test_probe_classnames_resolve_to_mapped_families(self, tmp_path):
        from modules import mapping
        from modules.parser import family_of

        for probe in probes.RAG_POISON:
            family = family_of(native_runner.probe_classname(probe))
            assert mapping.lookup(family).owasp_id


class TestRestConfig:
    def test_points_garak_at_the_chat_endpoint(self, tmp_path):
        path = garak_runner.write_rest_config(
            tmp_path / "rest.json", "http://127.0.0.1:8900/", "naive"
        )
        generator = json.loads(path.read_text())["rest"]["RestGenerator"]
        assert generator["uri"] == "http://127.0.0.1:8900/chat"
        assert generator["req_template_json_object"] == {"prompt": "$INPUT"}
        assert generator["response_json_field"] == "response"
        assert generator["name"] == "target-naive"

    def test_creates_missing_parent_directories(self, tmp_path):
        path = garak_runner.write_rest_config(
            tmp_path / "nested" / "rest.json", "http://x.example", "hardened"
        )
        assert json.loads(path.read_text())["rest"]["RestGenerator"]["name"] == "target-hardened"


class TestGarakRunner:
    def test_default_command_matches_garak_016(self, tmp_path):
        """garak 0.16 takes --target_type but still --generator_option_file."""
        command = garak_runner.build_command("promptinject", tmp_path / "o.json", "pfx", 3)
        assert "--target_type" in command and "rest" in command
        assert "--generator_option_file" in command
        assert "--probes" in command and "promptinject" in command
        assert command[command.index("--generations") + 1] == "3"

    @pytest.mark.parametrize("variant", range(len(garak_runner.FLAG_CANDIDATES)))
    def test_every_flag_variant_is_well_formed(self, variant, tmp_path):
        command = garak_runner.build_command("dan", tmp_path / "o.json", "pfx", 1, variant=variant)
        type_flag, option_flag = garak_runner.FLAG_CANDIDATES[variant]
        assert command[command.index(type_flag) + 1] == "rest"
        assert command[command.index(option_flag) + 1] == str(tmp_path / "o.json")

    def test_option_file_is_absolute(self, monkeypatch, tmp_path):
        """garak runs with cwd=out_dir, so a relative path resolves to the wrong root.

        Passing one through made every family fail with FileNotFoundError
        whenever `--out` was relative.
        """
        monkeypatch.chdir(tmp_path)
        command = garak_runner.build_command("dan", Path("runs/x/rest-config.json"), "pfx", 1)
        option_flag = garak_runner.FLAG_CANDIDATES[0][1]
        passed = Path(command[command.index(option_flag) + 1])
        assert passed.is_absolute()
        assert passed == (tmp_path / "runs/x/rest-config.json").resolve()

    def test_usage_errors_walk_the_flag_variants(self, tmp_path, monkeypatch):
        """A build that spells the flags differently must not fail the run."""
        attempts = []

        def fake_run(command, **_kwargs):
            attempts.append(command)
            usage = len(attempts) < len(garak_runner.FLAG_CANDIDATES)
            stderr = "error: unrecognized arguments: --whatever" if usage else ""
            (tmp_path / "garak-dan.report.jsonl").write_text("{}\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", stderr)

        monkeypatch.setattr(garak_runner.shutil, "which", lambda _: "/usr/bin/garak")
        monkeypatch.setattr(garak_runner.subprocess, "run", fake_run)
        runs = garak_runner.run_suite(["dan"], tmp_path / "o.json", tmp_path)

        assert len(attempts) == len(garak_runner.FLAG_CANDIDATES)
        assert runs[0].ok

    def test_unknown_probe_family_reports_a_useful_reason(self, tmp_path, monkeypatch):
        """garak exits 0 and writes nothing for a family it does not have."""
        monkeypatch.setattr(garak_runner.shutil, "which", lambda _: "/usr/bin/garak")
        monkeypatch.setattr(
            garak_runner.subprocess,
            "run",
            lambda command, **_k: subprocess.CompletedProcess(command, 0, "", ""),
        )
        runs = garak_runner.run_suite(["nosuchfamily"], tmp_path / "o.json", tmp_path)
        assert runs[0].skipped and not runs[0].ok
        assert "--list_probes" in runs[0].reason

    def test_stale_report_from_a_previous_tier_is_not_collected(self, tmp_path, monkeypatch):
        """The prefix is reused across tiers; an old file must not be mistaken for a new one."""
        garak_home = tmp_path / "garak_runs"
        garak_home.mkdir()
        stale = garak_home / "garak-dan.report.jsonl"
        stale.write_text("{}\n", encoding="utf-8")
        os.utime(stale, (1_000_000, 1_000_000))
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        monkeypatch.setattr(garak_runner, "_candidate_dirs", lambda _: [out_dir, garak_home])
        assert garak_runner._collect_report("garak-dan", out_dir, newer_than=time.time()) is None
        # Without the freshness guard the same file is found.
        assert garak_runner._collect_report("garak-dan", out_dir, newer_than=0.0) is not None

    def test_dry_run_sends_nothing(self, tmp_path):
        runs = garak_runner.run_suite(
            ["promptinject", "xss"], tmp_path / "o.json", tmp_path, dry_run=True
        )
        assert len(runs) == 2
        assert all(run.skipped and run.reason == "dry run" for run in runs)
        assert all(run.returncode is None for run in runs)

    def test_missing_garak_is_skipped_with_a_reason(self, tmp_path, monkeypatch):
        monkeypatch.setattr(garak_runner.shutil, "which", lambda _: None)
        runs = garak_runner.run_suite(["promptinject"], tmp_path / "o.json", tmp_path)
        assert runs[0].skipped
        assert "not on PATH" in runs[0].reason
        assert not runs[0].ok

    def test_empty_probe_list_is_a_no_op(self, tmp_path):
        assert garak_runner.run_suite([], tmp_path / "o.json", tmp_path) == []

    def test_collects_the_report_garak_wrote_elsewhere(self, tmp_path, monkeypatch):
        """garak resolves --report_prefix against its own report dir, not ours."""
        garak_home = tmp_path / "garak_runs"
        garak_home.mkdir()
        (garak_home / "garak-promptinject.report.jsonl").write_text("{}\n", encoding="utf-8")
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        monkeypatch.setattr(garak_runner, "_candidate_dirs", lambda _: [out_dir, garak_home])
        found = garak_runner._collect_report("garak-promptinject", out_dir)
        assert found is not None
        assert found.parent == out_dir
        assert found.is_file()


class TestCli:
    def test_dry_run_scan_touches_nothing_live(self, tmp_path, monkeypatch):
        import main

        monkeypatch.setattr(main.console, "print", lambda *a, **k: None)
        code = main.main(
            [
                "scan",
                "--all-tiers",
                "--suite",
                "quick",
                "--backend",
                "mock",
                "--dry-run",
                "--out",
                str(tmp_path),
            ]
        )
        assert code == 0
        assert not list(tmp_path.rglob("*.report.jsonl"))

    def test_scan_then_report_round_trip(self, tmp_path, monkeypatch):
        import main

        monkeypatch.setattr(main.console, "print", lambda *a, **k: None)
        assert (
            main.main(
                [
                    "scan",
                    "--all-tiers",
                    "--suite",
                    "agency",
                    "--backend",
                    "mock",
                    "--no-garak",
                    "--generations",
                    "1",
                    "--out",
                    str(tmp_path),
                ]
            )
            == 0
        )

        reports = list(tmp_path.rglob("*.report.jsonl"))
        assert len(reports) == len(config.TIERS) * 2  # attack pack + benign control
        assert list(tmp_path.glob("*.html")) and list(tmp_path.glob("*.md"))

        assert main.main(["analyze", str(tmp_path)]) == 0

    def test_analyze_on_an_empty_directory_fails_cleanly(self, tmp_path, monkeypatch):
        import main

        monkeypatch.setattr(main.console, "print", lambda *a, **k: None)
        assert main.main(["analyze", str(tmp_path)]) == 1
        assert main.main(["analyze", str(tmp_path / "nope")]) == 1

    @pytest.mark.parametrize("what", ["suites", "probes", "tiers", "mappings"])
    def test_list_subcommands(self, what, monkeypatch):
        import main

        monkeypatch.setattr(main.console, "print", lambda *a, **k: None)
        assert main.main(["list", what]) == 0


class TestDefenceGradient:
    """The scan's central claim, asserted directly.

    If hardening ever stops reducing attack success — or starts costing utility —
    these fail, and the numbers in FINDINGS.md are stale.
    """

    @staticmethod
    def _scan(tier: str, tmp_path: Path) -> tuple[float, float]:
        from modules.scoring import score_reports

        app = create_app(tier=tier, backend=MockBackend(), canary=CANARY)
        client = native_runner.LocalTarget(app)
        attack_path = tmp_path / tier / "attack.report.jsonl"
        native_runner.run_native(
            probes.resolve_packs(list(probes.PACKS)), client, CANARY, tier, attack_path
        )
        native_runner.run_native(
            probes.BENIGN, client, CANARY, tier, tmp_path / tier / "benign.report.jsonl"
        )
        score = score_reports(
            [
                parse_report(attack_path, tier=tier),
                parse_report(tmp_path / tier / "benign.report.jsonl", tier=tier),
            ]
        )[tier]
        return score.asr, score.utility

    def test_each_tier_reduces_attack_success(self, tmp_path):
        naive, _ = self._scan("naive", tmp_path)
        guarded, _ = self._scan("guarded", tmp_path)
        hardened, _ = self._scan("hardened", tmp_path)
        assert naive > guarded > hardened
        assert hardened < 0.25

    def test_hardening_does_not_cost_utility(self, tmp_path):
        for tier in config.TIERS:
            _, utility = self._scan(tier, tmp_path)
            assert utility == 1.0, tier

    def test_prompt_rules_alone_do_not_stop_indirect_injection(self, tmp_path):
        """The finding the project exists to make. Guarded must not fix rag_poison."""
        from modules.scoring import score_reports

        rates = {}
        for tier in ("naive", "guarded", "hardened"):
            path = tmp_path / f"rag-{tier}.report.jsonl"
            client = native_runner.LocalTarget(
                create_app(tier=tier, backend=MockBackend(), canary=CANARY)
            )
            native_runner.run_native(probes.RAG_POISON, client, CANARY, tier, path)
            score = score_reports([parse_report(path, tier=tier)])[tier]
            rates[tier] = score.families["native.rag_poison"].asr

        assert rates["guarded"] == rates["naive"] > 0
        assert rates["hardened"] < rates["guarded"]
