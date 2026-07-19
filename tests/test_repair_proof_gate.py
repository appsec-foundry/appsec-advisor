"""The repair agent's fix must be proven, not asserted.

A file under `tests/` in the diff is a shape check: an always-green test
satisfies it, and so does a test written to match whatever the code happens to
do after the edit. The `Prove the regression test reproduces the defect` step
turns that into evidence — it runs the agent's own test against the ORIGINAL
code (must fail) and then against the patched code (must pass), rebuilding the
working tree from HEAD in between. Only a change that clears both becomes a PR.

These tests execute the real step from the workflow against a throwaway git
repository containing a real defect, because the step is shell and its failure
modes are environmental. One of them was found this way: with
`return n + 2` -> `return n * 2` the source keeps its size, both pytest runs
land in the same second, and CPython's mtime+size .pyc validation happily
serves the stale bytecode of the unfixed module — so a genuine fix was reported
as unproven. Hence PYTHONDONTWRITEBYTECODE, and hence the genuine-fix case
below uses an equal-length edit on purpose.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "repair-agent.yml"

# Equal length on both sides — see the module docstring.
BUGGY_SOURCE = "def double(n):\n    return n + 2\n"
FIXED_SOURCE = "def double(n):\n    return n * 2\n"

REPRODUCING_TEST = "import calc\n\n\ndef test_double():\n    assert calc.double(3) == 6\n"
ALWAYS_GREEN_TEST = "def test_nothing():\n    assert True\n"
NEVER_GREEN_TEST = "import calc\n\n\ndef test_double():\n    assert calc.double(3) == 99\n"
NO_TESTS_AT_ALL = "# this file collects nothing\n"


def _proof_script() -> str:
    """The step as it will actually run, minus the dependency install."""
    workflow = yaml.safe_load(WORKFLOW.read_text())
    steps = workflow["jobs"]["repair"]["steps"]
    step = next(s for s in steps if s["name"].startswith("Prove"))

    env = "".join(f"export {k}={v}\n" for k, v in (step.get("env") or {}).items())
    body = "\n".join(line for line in step["run"].splitlines() if "pip install" not in line)
    return env + body


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _run_proof(tmp_path: Path, *, test_source: str, apply_fix: bool) -> dict[str, str]:
    repo = tmp_path / "repo"
    # RUNNER_TEMP must live OUTSIDE the repo: the step runs `git clean -fd`.
    runner_temp = tmp_path / "runner-temp"
    (repo / "tests").mkdir(parents=True)
    runner_temp.mkdir()

    _git(repo, "init", "-q", ".")
    _git(repo, "config", "user.email", "ci@example.invalid")
    _git(repo, "config", "user.name", "ci")
    (repo / "calc.py").write_text(BUGGY_SOURCE)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")

    # What the agent left behind.
    (repo / "tests" / "test_calc.py").write_text(test_source)
    if apply_fix:
        (repo / "calc.py").write_text(FIXED_SOURCE)

    script = tmp_path / "prove.sh"
    script.write_text(_proof_script())
    outputs = runner_temp / "github_output"
    summary = runner_temp / "github_summary"
    outputs.touch()
    summary.touch()

    proc = subprocess.run(
        ["bash", str(script)],
        cwd=repo,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "HOME": str(tmp_path),
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_OUTPUT": str(outputs),
            "GITHUB_STEP_SUMMARY": str(summary),
        },
        capture_output=True,
        text=True,
    )

    parsed = dict(line.split("=", 1) for line in outputs.read_text().splitlines() if "=" in line)
    parsed["_log"] = proc.stdout + proc.stderr
    return parsed


pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("git") is None,
    reason="needs bash and git",
)


def test_a_genuine_fix_is_proven(tmp_path):
    """Fails before, passes after — the only combination that ships."""
    result = _run_proof(tmp_path, test_source=REPRODUCING_TEST, apply_fix=True)
    assert result["verdict"] == "proven", result["_log"]


def test_an_always_green_test_proves_nothing(tmp_path):
    """The shape check's blind spot: a test that never reproduced anything."""
    result = _run_proof(tmp_path, test_source=ALWAYS_GREEN_TEST, apply_fix=True)
    assert result["verdict"] == "unproven"
    assert "does not reproduce the defect" in result["_log"]


def test_a_test_still_failing_after_the_fix_is_rejected(tmp_path):
    result = _run_proof(tmp_path, test_source=NEVER_GREEN_TEST, apply_fix=True)
    assert result["verdict"] == "unproven"
    assert "still fails with the fix applied" in result["_log"]


def test_a_test_file_that_collects_nothing_is_rejected(tmp_path):
    """pytest exit 5 would otherwise read as a tidy 'failure' and count as proof."""
    result = _run_proof(tmp_path, test_source=NO_TESTS_AT_ALL, apply_fix=True)
    assert result["verdict"] == "unproven"
    assert "collected no tests" in result["_log"]


def test_a_test_without_any_fix_is_rejected(tmp_path):
    """No production change means the defect is reported, not repaired."""
    result = _run_proof(tmp_path, test_source=REPRODUCING_TEST, apply_fix=False)
    assert result["verdict"] == "unproven"


def test_an_equal_length_fix_is_not_masked_by_stale_bytecode(tmp_path):
    """Regression: mtime+size .pyc validation served the unfixed module.

    Both pytest runs land in the same second and the edit preserves file size,
    so without PYTHONDONTWRITEBYTECODE the second run imports the cached
    bytecode of the ORIGINAL code and a real fix is refused.
    """
    assert len(BUGGY_SOURCE) == len(FIXED_SOURCE), "the regression needs equal-length sources"
    result = _run_proof(tmp_path, test_source=REPRODUCING_TEST, apply_fix=True)
    assert result["verdict"] == "proven", result["_log"]


def test_the_pr_step_requires_the_proof_verdict():
    """The gate is only worth something if the PR step actually consults it."""
    workflow = yaml.safe_load(WORKFLOW.read_text())
    steps = {s.get("name"): s for s in workflow["jobs"]["repair"]["steps"]}

    pr_condition = str(steps["Open repair PR"].get("if", ""))
    assert "steps.proof.outputs.verdict == 'proven'" in pr_condition, (
        "a PR must require the proven verdict, not merely the shape check"
    )

    fail_condition = str(steps["Fail on refused change"].get("if", ""))
    assert "unproven" in fail_condition, "an unproven change must turn the job red"
