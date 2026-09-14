"""Exercise group selection and the real CLI without recursively running pytest."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
import run_tests as runner


@pytest.mark.parametrize("group", runner.GROUPS)
def test_shipped_groups_resolve_to_existing_unique_test_files(group):
    paths = runner.select_tests(group)
    assert paths
    assert len(paths) == len(set(paths))
    assert all(path.startswith("tests/test_") and path.endswith(".py") for path in paths)
    assert all((runner.ROOT / path).is_file() for path in paths)
    assert "tests/test_full_run_e2e.py" not in paths


def test_report_group_includes_section_presence_and_fragment_consumers():
    assert {
        "tests/test_section_condition_wiring.py",
        "tests/test_section_integrity.py",
        "tests/test_fragment_invariant_parity.py",
        "tests/test_e2e_pipeline.py",
    } <= set(runner.select_tests("report"))


@pytest.mark.parametrize("family", ["sample", "alternate"])
def test_group_includes_new_family_members_and_deduplicates(tmp_path, monkeypatch, family):
    (tmp_path / "tests").mkdir()
    first = f"tests/test_{family}.py"
    added = f"tests/test_{family}_extra.py"
    (tmp_path / first).touch()
    (tmp_path / added).touch()
    (tmp_path / "tests/test_unrelated.py").touch()
    monkeypatch.setitem(runner.GROUPS, "example", (f"tests/test_{family}*.py", first))
    assert runner.select_tests("example", tmp_path) == [first, added]


def test_stale_selector_fails_even_when_other_files_match(tmp_path, monkeypatch):
    (tmp_path / "test_present.py").touch()
    monkeypatch.setitem(runner.GROUPS, "example", ("test_present.py", "test_missing*.py"))
    with pytest.raises(ValueError, match="test_missing"):
        runner.select_tests("example", tmp_path)


def test_stale_group_returns_error_without_launching_pytest(monkeypatch, capsys):
    monkeypatch.setitem(runner.GROUPS, "example", ("tests/test_nonexistent_group_member.py",))
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **kw: pytest.fail("pytest must not run"))
    assert runner.main(["example"]) == 2
    assert "no files matching" in capsys.readouterr().err


@pytest.fixture
def fake_pytest_env(tmp_path):
    """Capture the child invocation with a stand-in for python -m pytest."""
    for dependency in ("yaml", "jinja2", "jsonschema", "pytest_cov"):
        (tmp_path / f"{dependency}.py").touch()
    (tmp_path / "pytest.py").write_text(
        "import json, os, sys\n"
        "if __name__ == '__main__':\n"
        "    print(json.dumps({'args': sys.argv[1:], 'cwd': os.getcwd()}))\n"
        "    sys.exit(int(os.environ.get('TEST_CHILD_STATUS', '0')))\n"
    )
    return {**os.environ, "PYTHONPATH": str(tmp_path), "PIP_NO_INDEX": "1"}


def _cli(*args, env=None, cwd=None):
    return subprocess.run(
        [sys.executable, str(runner.ROOT / "scripts/run_tests.py"), *args],
        env=env,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("status", [0, 1, 2, 5])
def test_cli_preserves_arguments_working_directory_and_pytest_exit_status(fake_pytest_env, tmp_path, status):
    fake_pytest_env["TEST_CHILD_STATUS"] = str(status)
    result = _cli("e2e", "-k", "golden or schema", "-q", env=fake_pytest_env, cwd=tmp_path)
    assert result.returncode == status
    invocation = json.loads(result.stdout)
    assert invocation == {
        "args": ["tests/test_e2e_pipeline.py", "-k", "golden or schema", "-q"],
        "cwd": str(runner.ROOT),
    }


def test_default_cli_runs_the_complete_suite_without_coverage(fake_pytest_env):
    result = _cli(env=fake_pytest_env)
    assert result.returncode == 0
    assert json.loads(result.stdout)["args"] == ["tests/"]


def test_unknown_group_fails_instead_of_silently_running_a_subset(fake_pytest_env):
    result = _cli("rpeort", env=fake_pytest_env)
    assert result.returncode == 2
    assert "invalid choice" in result.stderr
    assert not result.stdout


def test_list_does_not_launch_pytest(fake_pytest_env):
    fake_pytest_env["TEST_CHILD_STATUS"] = "99"
    result = _cli("--list", "quick", env=fake_pytest_env)
    assert result.returncode == 0
    assert result.stdout.splitlines() == runner.select_tests("quick")


@pytest.mark.parametrize("args", [("quick",), ("group", "report"), ("coverage",), ("golden or schema",)])
def test_shell_wrapper_routes_groups_coverage_and_legacy_patterns(fake_pytest_env, args):
    result = subprocess.run(
        ["bash", str(runner.ROOT / "scripts/run-tests.sh"), *args, "-q"],
        env=fake_pytest_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    actual = json.loads(result.stdout)["args"]
    if args[0] == "coverage":
        assert actual[0] == "tests/"
        assert "--cov=scripts" in actual
    elif args[0] == "golden or schema":
        assert actual == ["tests/", "-k", "golden or schema", "-v", "-q"]
    else:
        assert actual == [*runner.select_tests(args[-1]), "-q"]


def test_make_targets_use_the_shared_runner():
    result = subprocess.run(
        ["make", "--dry-run", "test-quick", "test-group", "GROUP=report", "test-full", "test-incremental"],
        cwd=runner.ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    for group in ("quick", '"report"', "all", "incremental"):
        assert f"scripts/run_tests.py {group} " in result.stdout
    assert "--cov" not in result.stdout
