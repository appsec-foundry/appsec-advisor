"""The repair agent's eligibility rule, exercised as code rather than as YAML.

The rule is deliberately narrow, and every widening of it costs real money and
real risk: the agent runs a live session and opens a PR. It may act on a run
only when BOTH hold:

  * the run finished — exit 0 for a fixture run, a rendered threat-model.md for
    a threat-model run. An aborted run (bad credentials, failed checkout, a
    mid-pipeline crash) never wrote the structured diagnosis the agent reads,
    so it would be guessing;
  * the run recorded errors or auto-recovered failures. That is the actual
    subject: a green report resting on a runtime workaround — retries, compose
    re-runs, auto-repair — with the producer defect still in place.

An oracle recall miss (exit 4) finished but stays excluded on purpose: whether
the plugin under-detected or the oracle over-claims is not machine-decidable,
and an agent told to "fix" recall optimises against the oracle.

The logic under test lives inside the workflow's `Triage failures` step, so it
is extracted from the YAML and executed. Testing a paraphrase of it here would
pin nothing.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "repair-agent.yml"


def _triage_source() -> str:
    """Pull the heredoc body out of the Triage failures step."""
    workflow = yaml.safe_load(WORKFLOW.read_text())
    steps = workflow["jobs"]["repair"]["steps"]
    triage = next(s for s in steps if s.get("name") == "Triage failures")
    body = triage["run"]
    assert "<<'PY'" in body, "triage step no longer embeds a python heredoc"
    return body.split("<<'PY'", 1)[1].rsplit("PY", 1)[0]


def _seed(root: Path, name: str, *, result: dict | None, issues: dict | None, report: bool = False):
    run_dir = root / "e2e-artifacts" / name
    run_dir.mkdir(parents=True)
    if result is not None:
        (run_dir / "e2e-result.json").write_text(json.dumps(result))
    if issues is not None:
        (run_dir / ".run-issues.json").write_text(json.dumps(issues))
    if report:
        (run_dir / "threat-model.md").write_text("# report\n")


def _run_triage(tmp_path: Path) -> dict[str, str]:
    script = tmp_path / "triage.py"
    script.write_text(_triage_source())
    outputs = tmp_path / "outputs.txt"
    outputs.touch()
    summary = tmp_path / "summary.md"
    summary.touch()

    proc = subprocess.run(
        [sys.executable, str(script)],
        cwd=tmp_path,
        env={
            "PATH": "/usr/bin:/bin",
            "GITHUB_OUTPUT": str(outputs),
            "GITHUB_STEP_SUMMARY": str(summary),
        },
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr

    parsed = dict(line.split("=", 1) for line in outputs.read_text().splitlines() if "=" in line)
    parsed["_summary"] = summary.read_text()
    parsed["_stdout"] = proc.stdout
    return parsed


def _issues(errors: int = 0, recovery: int = 0, warnings: int = 0) -> dict:
    """Shape written by aggregate_run_issues.py."""
    return {
        "run_status": "issues" if (errors or recovery or warnings) else "clean",
        "summary": {"errors": errors, "recovery_events": recovery, "warnings": warnings},
    }


ELIGIBLE = [
    pytest.param(
        {"result": {"exit_code": 0, "fixture": "f"}, "issues": _issues(errors=2)},
        id="fixture-passed-with-errors",
    ),
    pytest.param(
        {"result": {"exit_code": 0, "fixture": "f"}, "issues": _issues(recovery=3)},
        id="fixture-passed-but-auto-recovered",
    ),
    pytest.param(
        {"result": None, "issues": _issues(errors=1), "report": True},
        id="threat-model-rendered-with-errors",
    ),
]

REJECTED = [
    pytest.param(
        {"result": {"exit_code": 2, "fixture": "f", "failure_kind": "pipeline"}, "issues": None},
        id="aborted-mid-pipeline-no-diagnosis",
    ),
    pytest.param(
        {
            "result": {"exit_code": 4, "fixture": "f", "failure_kind": "oracle"},
            "issues": _issues(errors=4, recovery=1),
        },
        id="oracle-recall-miss-stays-a-humans-call",
    ),
    pytest.param(
        {"result": {"exit_code": 0, "fixture": "f"}, "issues": _issues(warnings=5)},
        id="passed-with-warnings-only-is-not-a-defect",
    ),
    pytest.param(
        {"result": {"exit_code": 0, "fixture": "f"}, "issues": _issues()},
        id="passed-clean",
    ),
    pytest.param(
        {"result": None, "issues": _issues(errors=9, recovery=9)},
        id="threat-model-aborted-before-rendering",
    ),
]


@pytest.mark.parametrize("seed", ELIGIBLE)
def test_eligible_runs_are_offered_to_the_agent(tmp_path, seed):
    _seed(tmp_path, "run", **seed)
    assert _run_triage(tmp_path)["repairable"] == "true"


@pytest.mark.parametrize("seed", REJECTED)
def test_ineligible_runs_are_skipped(tmp_path, seed):
    _seed(tmp_path, "run", **seed)
    result = _run_triage(tmp_path)
    assert result["repairable"] == "false"
    assert result["label"] == ""
    assert "skipping repair" in result["_stdout"]


def test_a_mixed_matrix_offers_only_the_qualifying_fixtures(tmp_path):
    """`fixture: all` can produce every outcome at once; each is judged alone."""
    _seed(tmp_path, "good", result={"exit_code": 0, "fixture": "good"}, issues=_issues(errors=1))
    _seed(tmp_path, "broke", result={"exit_code": 2, "fixture": "broke"}, issues=None)
    _seed(
        tmp_path,
        "recall",
        result={"exit_code": 4, "fixture": "recall", "failure_kind": "oracle"},
        issues=_issues(errors=3),
    )

    result = _run_triage(tmp_path)
    assert result["repairable"] == "true"
    assert result["label"] == "good"


def test_the_summary_does_not_call_an_oracle_miss_an_abort(tmp_path):
    """Exit 4 finished; reporting it as an abort would misdirect the reader."""
    _seed(
        tmp_path,
        "recall",
        result={"exit_code": 4, "fixture": "recall", "failure_kind": "oracle"},
        issues=_issues(errors=3),
    )
    summary = _run_triage(tmp_path)["_summary"]
    assert "missed oracle recall" in summary
    assert "aborted" not in summary


def test_unreadable_diagnosis_does_not_qualify(tmp_path):
    """A corrupt sidecar must not read as 'no issues' OR crash the job."""
    _seed(tmp_path, "run", result={"exit_code": 0, "fixture": "f"}, issues=None)
    (tmp_path / "e2e-artifacts" / "run" / ".run-issues.json").write_text("{ not json")
    assert _run_triage(tmp_path)["repairable"] == "false"
