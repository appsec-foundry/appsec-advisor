"""Keep all compatibility checks while measuring coverage only once in CI."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _workflow():
    return yaml.safe_load((ROOT / ".github/workflows/tests.yml").read_text())


def _enabled(step, version):
    condition = step.get("if")
    if not condition:
        return True
    match = re.fullmatch(r"matrix.python-version (==|!=) '([\d.]+)'", condition)
    assert match, f"unexpected test-step condition: {condition}"
    return (version == match[2]) == (match[1] == "==")


def test_every_python_version_runs_exactly_one_full_suite_and_only_one_measures_coverage():
    job = _workflow()["jobs"]["pytest"]
    versions = job["strategy"]["matrix"]["python-version"]
    assert versions == ["3.10", "3.11", "3.12"]
    steps = [s for s in job["steps"] if "run_tests.py" in s.get("run", "") or "make test-full" in s.get("run", "")]
    measured = []
    for version in versions:
        commands = [step["run"] for step in steps if _enabled(step, version)]
        assert len(commands) == 1
        command = commands[0]
        assert "run_tests.py all " in command or "make test-full" in command
        assert "--cov-fail-under" not in command
        if "--cov=scripts" in command:
            measured.append(version)
            assert "--cov-report=xml" in command
    assert measured == ["3.12"]
    uploads = [step for step in job["steps"] if "codecov/" in step.get("uses", "")]
    assert len(uploads) == 1
    assert [v for v in versions if _enabled(uploads[0], v)] == measured


def test_static_checks_run_once_and_gate_existing_pytest_jobs():
    jobs = _workflow()["jobs"]
    assert jobs["pytest"]["needs"] == "checks"
    checks = jobs["checks"]
    assert "strategy" not in checks
    commands = [step.get("run", "") for step in checks["steps"]]
    assert "make lint validate PYTHON=python" in commands
    assert any("check_specs.py --changed-against" in command for command in commands)
    assert not any("ruff" in step.get("run", "") for step in jobs["pytest"]["steps"])


def test_shared_validator_target_retains_all_drift_guards():
    result = subprocess.run(["make", "--dry-run", "validate"], cwd=ROOT, capture_output=True, text=True, check=True)
    for script in ("validate_config.py", "check_fragment_registry.py", "check_target_specificity.py", "check_specs.py"):
        assert f"scripts/{script}" in result.stdout
    assert "pytest" not in result.stdout


def test_workflow_keeps_checks_for_all_changed_paths():
    workflow = _workflow()
    triggers = workflow.get("on", workflow.get(True))
    for event in ("push", "pull_request"):
        assert set(triggers[event]["branches"]) == {"main", "dev"}
        assert "paths" not in triggers[event]
        assert "paths-ignore" not in triggers[event]
