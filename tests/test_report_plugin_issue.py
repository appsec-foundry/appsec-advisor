"""Opt-in reporting: current evidence, minimal payload, exact consent, safe failures."""

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest
import report_plugin_issue as support
import runtime_cleanup


def write(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.delenv("APPSEC_HEADLESS", raising=False)
    output = tmp_path / "results"
    output.mkdir()
    repo = tmp_path / "private-project"
    repo.mkdir()
    issue = {"id": "ISSUE-001", "title": "PRIVATE TITLE", "severity": "error", "category": "tool_error"}
    issues = {"schema_version": 1, "generated": "2026-09-17T10:00:00Z", "run_status": "errors", "issues": [issue]}
    diagnosis = {
        "schema_version": 1,
        "generated": "2026-09-17T10:01:00Z",
        "source_generated": issues["generated"],
        "issues_total": 1,
        "issues_examined": 1,
        "summary": {"plugin_bug": 1, "environment": 0, "expected": 0, "inconclusive": 0},
        "diagnoses": [
            {
                "issue_id": issue["id"],
                "issue_title": issue["title"],
                "verdict": "plugin_bug",
                "confidence": "high",
                "rationale": "PRIVATE RATIONALE",
                "evidence": ["PRIVATE SOURCE"],
                "root_cause": {
                    "location": "scripts/diagnostic_bundle.py:1",
                    "description": "PRIVATE CAUSE",
                    "causal_path": "PRIVATE PATH",
                },
            }
        ],
    }
    source = {
        "schema_version": 1,
        "issue_id": issue["id"],
        "source_generated": issues["generated"],
        "title": "A required output key is omitted",
        "expected": "Every emitted item contains its required key.",
        "actual": "An empty item reaches the consumer and is rejected.",
        "cause": "The producer has an unchecked branch that omits the required key.",
        "verification": {
            "method": "source_trace",
            "evidence": "The empty branch reaches the writer; the consumer requires the missing key.",
        },
    }
    write(output / ".run-issues.json", issues)
    write(output / ".run-bugs.json", diagnosis)
    write(output / support.INPUT, source)
    (output / ".agent-run.log").write_text("PRIVATE LOG with secret values")
    return SimpleNamespace(output=output, repo=repo, issues=issues, diagnosis=diagnosis, source=source)


def test_prepare_excludes_original_diagnostics_and_requires_review(run, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("prepare must stay offline"))
    draft = support.prepare(run.output, run.repo)
    assert "PRIVATE" not in draft["body"]
    assert "not independently reproduced" in draft["body"]
    assert "diagnostic_bundle.py:1" in draft["body"]
    preview = support.preview(run.output)
    assert draft["body"] in preview and draft["title"] in preview
    assert support._digest(draft) in preview
    assert "account remains visible" in preview


@pytest.mark.parametrize("verdict", ["environment", "expected", "inconclusive"])
def test_non_plugin_verdicts_cannot_publish(run, verdict):
    run.diagnosis["diagnoses"][0]["verdict"] = verdict
    run.diagnosis["summary"].update(plugin_bug=0, **{verdict: 1})
    write(run.output / ".run-bugs.json", run.diagnosis)
    with pytest.raises(ValueError, match="high-confidence"):
        support.prepare(run.output, run.repo)


@pytest.mark.parametrize("damage", ["snapshot", "confidence", "counts", "duplicate", "schema", "run_start"])
def test_unverified_or_stale_diagnosis_is_rejected(run, damage):
    if damage == "snapshot":
        run.diagnosis["source_generated"] = "another run"
    elif damage == "confidence":
        run.diagnosis["diagnoses"][0]["confidence"] = "low"
    elif damage == "counts":
        run.diagnosis["summary"]["plugin_bug"] = 0
    elif damage == "duplicate":
        run.diagnosis["diagnoses"] *= 2
    elif damage == "schema":
        run.diagnosis["extra"] = True
    else:
        (run.output / ".scan-start-epoch").write_text("2000000000")
    write(run.output / ".run-bugs.json", run.diagnosis)
    with pytest.raises(ValueError):
        support.prepare(run.output, run.repo)


@pytest.mark.parametrize(
    "secret",
    [
        "/opt/customer/source",
        "C:\\Users\\client",
        "user@corp.invalid",
        "https://internal.invalid",
        "HTTPS://internal.invalid",
        "private-project",
        "10.8.2.4",
        "q" * 40,
        "![tracking](https://internal.invalid)",
        "<details>hidden</details>",
        "terminal escape \x1b[31m",
    ],
)
def test_public_payload_rejects_common_disclosures(run, secret):
    run.source["actual"] += " " + secret
    write(run.output / support.INPUT, run.source)
    with pytest.raises(ValueError, match="public text"):
        support.prepare(run.output, run.repo)


@pytest.mark.parametrize(
    "location", ["../outside.py", "/tmp/example.py", "scripts/missing.py", "scripts/diagnostic_bundle.py:999999"]
)
def test_root_cause_cannot_select_external_or_invented_source(run, location):
    run.diagnosis["diagnoses"][0]["root_cause"]["location"] = location
    write(run.output / ".run-bugs.json", run.diagnosis)
    with pytest.raises(ValueError):
        support.prepare(run.output, run.repo)


@pytest.mark.parametrize(
    "location", ["config.json:1", ".claude-plugin/plugin.json:1", "docs/internal/contracts/schema-invariants.md:1"]
)
def test_plugin_configuration_and_contract_causes_are_reportable(run, location):
    run.diagnosis["diagnoses"][0]["root_cause"]["location"] = location
    write(run.output / ".run-bugs.json", run.diagnosis)
    assert location in support.prepare(run.output, run.repo)["body"]


def test_neutral_variant_and_reproduction_method(run):
    renamed = run.repo.with_name("another-private-service")
    run.repo.rename(renamed)
    run.source["title"] = "Missing branch output fails consumer validation"
    run.source["verification"] = {
        "method": "reproduced",
        "evidence": "Synthetic item alpha fails validation; item beta with the required key passes.",
    }
    write(run.output / support.INPUT, run.source)
    draft = support.prepare(run.output, renamed)
    assert "Neutral local reproduction executed" in draft["body"]
    assert renamed.name not in draft["body"]


def fake_github(monkeypatch, calls, *, failure=False):
    monkeypatch.setattr(support.shutil, "which", lambda name: "/usr/bin/gh")

    def invoke(argv, **kwargs):
        calls.append((argv, kwargs))
        if failure:
            raise subprocess.TimeoutExpired(argv, 60)
        return SimpleNamespace(
            stdout=json.dumps({"html_url": "https://github.com/appsec-foundry/appsec-advisor/issues/42"})
        )

    monkeypatch.setattr(subprocess, "run", invoke)


def test_publish_sends_only_exact_approved_payload_once(run, monkeypatch):
    calls = []
    fake_github(monkeypatch, calls)
    draft = support.prepare(run.output, run.repo)
    digest = support._digest(draft)
    url = support.publish(run.output, run.repo, digest)
    assert url.endswith("/42")
    assert support.publish(run.output, run.repo, digest) == url
    assert len(calls) == 1
    argv, options = calls[0]
    assert argv[1:] == [
        "api",
        "--hostname",
        "github.com",
        "repos/appsec-foundry/appsec-advisor/issues",
        "--method",
        "POST",
        "--input",
        "-",
    ]
    assert json.loads(options["input"]) == {"title": draft["title"], "body": draft["body"]}
    assert not options.get("shell")


@pytest.mark.parametrize("change", ["approval", "body", "input", "diagnosis", "headless", "lock"])
def test_changes_after_preview_never_send(run, monkeypatch, change):
    calls = []
    fake_github(monkeypatch, calls)
    draft = support.prepare(run.output, run.repo)
    digest = support._digest(draft)
    if change == "approval":
        digest = "0" * 64
    elif change == "body":
        draft["body"] += "Changed after review"
        write(run.output / support.DRAFT, draft)
    elif change == "input":
        run.source["title"] = "A different issue title after review"
        write(run.output / support.INPUT, run.source)
    elif change == "diagnosis":
        run.diagnosis["diagnoses"][0]["rationale"] += " changed"
        write(run.output / ".run-bugs.json", run.diagnosis)
    elif change == "headless":
        monkeypatch.setenv("APPSEC_HEADLESS", "true")
    else:
        (run.output / ".appsec-lock").touch()
    with pytest.raises(ValueError):
        support.publish(run.output, run.repo, digest)
    assert calls == []


def test_uncertain_submission_does_not_retry(run, monkeypatch):
    calls = []
    fake_github(monkeypatch, calls, failure=True)
    digest = support._digest(support.prepare(run.output, run.repo))
    with pytest.raises(ValueError, match="uncertain"):
        support.publish(run.output, run.repo, digest)
    with pytest.raises(ValueError, match="prior submission"):
        support.publish(run.output, run.repo, digest)
    assert len(calls) == 1


def test_missing_cli_keeps_draft_without_submission_receipt(run, monkeypatch):
    monkeypatch.setattr(support.shutil, "which", lambda name: None)
    draft = support.prepare(run.output, run.repo)
    with pytest.raises(ValueError, match="unavailable"):
        support.publish(run.output, run.repo, support._digest(draft))
    assert (run.output / support.DRAFT).exists()
    assert not list(run.output.glob(".plugin-issue-*.receipt.json"))


def test_no_consent_cli_fails_before_network(run, monkeypatch, capsys):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("no consent"))
    assert support.main(["publish", "--output-dir", str(run.output), "--repo-root", str(run.repo)]) == 2
    assert "explicit" in capsys.readouterr().err


@pytest.mark.parametrize("condition", ["eligible", "clean", "expected", "headless", "lock", "stale"])
def test_offer_only_for_current_actionable_interactive_run(run, monkeypatch, condition):
    if condition == "clean":
        run.issues["issues"] = []
    elif condition == "expected":
        run.issues["issues"][0]["severity"] = "info"
    elif condition == "headless":
        monkeypatch.setenv("APPSEC_HEADLESS", "1")
    elif condition == "lock":
        (run.output / ".appsec-lock").touch()
    elif condition == "stale":
        (run.output / ".scan-start-epoch").write_text("2000000000")
    write(run.output / ".run-issues.json", run.issues)
    assert support.offer(run.output)["offer"] == (condition == "eligible")


def test_schema_rejects_additional_public_data(run):
    run.source["logs"] = "do not send"
    write(run.output / support.INPUT, run.source)
    with pytest.raises(jsonschema.ValidationError):
        support.prepare(run.output, run.repo)


def test_prior_run_neutral_prose_cannot_be_reused(run):
    run.source["source_generated"] = "an earlier run"
    write(run.output / support.INPUT, run.source)
    with pytest.raises(ValueError, match="different run"):
        support.prepare(run.output, run.repo)


def test_cli_preview_and_approved_submission_with_offline_github_stub(run, tmp_path):
    """Exercise the command boundary without credentials or a public issue."""
    executable = tmp_path / "bin"
    executable.mkdir()
    payload_path = tmp_path / "sent.json"
    stub = executable / "gh"
    stub.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        "from pathlib import Path\n"
        f"Path({str(payload_path)!r}).write_text(sys.stdin.read())\n"
        "print(json.dumps({'html_url': 'https://github.com/appsec-foundry/appsec-advisor/issues/7'}))\n"
    )
    stub.chmod(0o700)
    env = {**os.environ, "PATH": f"{executable}{os.pathsep}{os.environ['PATH']}", "APPSEC_HEADLESS": "0"}
    args = ["--output-dir", str(run.output), "--repo-root", str(run.repo)]
    command = [sys.executable, support.__file__]
    prepared = subprocess.run([*command, "prepare", *args], env=env, capture_output=True, text=True)
    assert prepared.returncode == 0, prepared.stderr
    assert not payload_path.exists()
    digest = prepared.stdout.split("Approval SHA-256: ")[1].strip()
    declined = subprocess.run([*command, "publish", *args], env=env, capture_output=True, text=True)
    assert declined.returncode == 2
    assert not payload_path.exists()
    accepted = subprocess.run(
        [*command, "publish", *args, "--approved-sha256", digest], env=env, capture_output=True, text=True
    )
    assert accepted.returncode == 0, accepted.stderr
    assert accepted.stdout.strip().endswith("/issues/7")
    payload = json.loads(payload_path.read_text())
    assert payload["title"] in prepared.stdout and payload["body"] in prepared.stdout


def test_symlink_write_is_rejected(run, tmp_path):
    outside = tmp_path / "unrelated.txt"
    outside.write_text("keep me")
    (run.output / support.DRAFT).symlink_to(outside)
    with pytest.raises(OSError):
        support.prepare(run.output, run.repo)
    assert outside.read_text() == "keep me"


def test_normal_cleanup_preserves_support_draft_and_deferred_input(run):
    support.prepare(run.output, run.repo)
    write(run.output / ".qa-status.json", {"status": "pass"})
    runtime_cleanup.run_cleanup(
        run.output, stage="post-qa", keep_runtime_files=False, force=False, keep_run_issues=True
    )
    assert (run.output / ".run-issues.json").exists()
    assert (run.output / support.INPUT).exists()
    assert (run.output / support.DRAFT).exists()


def test_skill_wires_two_consents_and_failure_offer():
    root = Path(support.__file__).resolve().parent.parent
    skill = (root / "skills/report-error/SKILL.md").read_text()
    assert "REPORT_ERROR_CONSENT=true" in skill
    assert "wait_agent_calls.py" in skill
    assert "Repeat the identical command on exit 75" in skill
    assert "On exit 1 or any other error, stop" in skill
    assert "Earlier investigation consent does not answer this question" in skill
    assert "--approved-sha256 <digest-from-approved-preview>" in skill
    assert "never diagnose, prompt, or publish" in skill
    completion = (root / "skills/create-threat-model/SKILL-thin-completion.md").read_text()
    assert "--stage post-qa --keep-run-issues" in completion
    assert "After termination, follow the same `report-error --offer`" in completion
