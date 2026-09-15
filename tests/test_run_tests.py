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
def test_exact_group_rejects_partial_rename_and_inventory_detects_addition(tmp_path, monkeypatch, family):
    (tmp_path / "tests").mkdir()
    first = f"tests/test_{family}.py"
    added = f"tests/test_{family}_extra.py"
    (tmp_path / first).touch()
    (tmp_path / added).touch()
    monkeypatch.setattr(runner, "GROUPS", {"example": (first, added)})
    monkeypatch.setattr(runner, "MANUAL_TESTS", {})
    monkeypatch.setattr(runner, "SOURCE_GROUPS", {})
    assert runner.select_tests("example", tmp_path) == [first, added]
    assert runner.group_problems(tmp_path) == []
    (tmp_path / "tests/test_unrelated.py").touch()
    assert "tests/test_unrelated.py" in "\n".join(runner.group_problems(tmp_path))
    assert runner.select_tests("example", tmp_path) == [first, added]
    (tmp_path / first).rename(tmp_path / "tests/test_renamed.py")
    with pytest.raises(ValueError, match="missing or unsafe"):
        runner.select_tests("example", tmp_path)


def test_stale_selector_fails_even_when_other_files_match(tmp_path, monkeypatch):
    (tmp_path / "test_present.py").touch()
    monkeypatch.setitem(runner.GROUPS, "example", ("test_present.py", "test_missing.py"))
    with pytest.raises(ValueError, match="test_missing"):
        runner.select_tests("example", tmp_path)


def test_stale_group_returns_error_without_launching_pytest(monkeypatch, capsys):
    monkeypatch.setitem(runner.GROUPS, "example", ("tests/test_nonexistent_group_member.py",))
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **kw: pytest.fail("pytest must not run"))
    assert runner.main(["example"]) == 2
    assert "missing or unsafe" in capsys.readouterr().err


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


def test_wrapper_requires_a_name_after_group(fake_pytest_env):
    result = subprocess.run(
        ["bash", str(runner.ROOT / "scripts/run-tests.sh"), "group"],
        env=fake_pytest_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "group name" in result.stderr
    assert not result.stdout


def test_every_test_has_an_explicit_group_or_manual_role():
    grouped = {path for group in runner.GROUPS for path in runner.select_tests(group)}
    discovered = {path.relative_to(runner.ROOT).as_posix() for path in (runner.ROOT / "tests").rglob("test_*.py")}
    assert discovered == grouped | {"tests/test_full_run_e2e.py"}


def test_scanner_group_includes_architecture_producers_and_bridge():
    assert {
        "tests/test_route_inventory.py",
        "tests/test_architecture_coverage_checks.py",
        "tests/test_arch_coverage_bridge.py",
        "tests/test_repo_scan.py",
    } <= set(runner.select_tests("scanner"))


def test_report_group_includes_qa_and_diagram_consumers():
    assert {
        "tests/test_qa_checks.py",
        "tests/test_figure1_svg.py",
        "tests/test_walkthrough_renderer.py",
    } <= set(runner.select_tests("report"))


def test_shipped_inventory_and_source_routes_are_valid():
    assert runner.group_problems() == []


@pytest.fixture
def selection_repo(tmp_path, monkeypatch):
    groups = {
        "quick": ("tests/test_contract.py",),
        "producer": ("tests/test_emitter.py",),
        "consumer": ("tests/test_reader.py",),
        "unrelated": ("tests/test_elsewhere.py",),
    }
    sources = {"scripts/emitter.py": ("producer", "consumer")}
    for path in [*(p for paths in groups.values() for p in paths), *sources]:
        target = tmp_path / path
        target.parent.mkdir(exist_ok=True)
        target.touch()
    monkeypatch.setattr(runner, "GROUPS", groups)
    monkeypatch.setattr(runner, "MANUAL_TESTS", {})
    monkeypatch.setattr(runner, "SOURCE_GROUPS", sources)
    monkeypatch.setattr(runner, "requirement_tests", lambda paths, root: [])
    return tmp_path


@pytest.mark.parametrize("name", ["emitter", "converter"])
def test_changed_source_selects_producer_consumer_and_base_without_unrelated(selection_repo, monkeypatch, name):
    root = selection_repo
    source = f"scripts/{name}.py"
    (root / source).touch()
    monkeypatch.setattr(runner, "SOURCE_GROUPS", {source: ("producer", "consumer")})
    result = runner.select_changed([source], root)
    assert set(result.paths) == {
        "tests/test_contract.py",
        "tests/test_emitter.py",
        "tests/test_reader.py",
    }
    assert any("producer, consumer" in reason for reason in result.reasons)


def test_changed_test_selects_its_group_and_base(selection_repo):
    result = runner.select_changed(["tests/test_elsewhere.py"], selection_repo)
    assert set(result.paths) == {"tests/test_contract.py", "tests/test_elsewhere.py"}


def test_changed_selection_adds_requirement_guards(selection_repo, monkeypatch):
    monkeypatch.setattr(runner, "requirement_tests", lambda paths, root: ["tests/test_elsewhere.py"])
    result = runner.select_changed(["scripts/emitter.py"], selection_repo)
    assert "tests/test_elsewhere.py" in result.paths
    assert any("requirement guard" in reason for reason in result.reasons)


@pytest.mark.parametrize(
    "path",
    [
        "scripts/unknown.py",
        "schemas/shared.json",
        "templates/report.j2",
        "agents/reviewer.md",
        "skills/sample/SKILL.md",
        "tests/conftest.py",
        "tests/fixtures/input.json",
        "pyproject.toml",
        "data/shared.yaml",
    ],
)
def test_unknown_and_shared_paths_fall_back_to_all(selection_repo, path):
    target = selection_repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.touch()
    result = runner.select_changed([path], selection_repo)
    assert result.paths == ("tests/",)
    assert "no reviewed" in result.reasons[0]


def test_multiple_source_modules_require_full_suite(selection_repo, monkeypatch):
    (selection_repo / "scripts/second.py").touch()
    monkeypatch.setitem(runner.SOURCE_GROUPS, "scripts/second.py", ("consumer",))
    result = runner.select_changed(["scripts/emitter.py", "scripts/second.py"], selection_repo)
    assert result.paths == ("tests/",)
    assert "multiple" in result.reasons[0]


def test_deleted_source_requires_full_suite(selection_repo):
    (selection_repo / "scripts/emitter.py").unlink()
    assert runner.select_changed(["scripts/emitter.py"], selection_repo).paths == ("tests/",)


def test_new_test_requires_inventory_review(selection_repo):
    (selection_repo / "tests/test_new.py").touch()
    result = runner.select_changed(["tests/test_new.py"], selection_repo)
    assert result.paths == ("tests/",)
    assert any("test_new.py" in reason for reason in result.reasons)


def test_empty_diff_still_runs_base_guards(selection_repo):
    assert runner.select_changed([], selection_repo).paths == ("tests/test_contract.py",)


def test_escaped_test_symlink_is_rejected(selection_repo, tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.touch()
    path = selection_repo / "tests/test_reader.py"
    path.unlink()
    path.symlink_to(outside)
    with pytest.raises(ValueError, match="unsafe"):
        runner.select_tests("consumer", selection_repo)
    assert runner.select_changed(["scripts/emitter.py"], selection_repo).paths == ("tests/",)


def test_invalid_route_and_duplicate_membership_are_reported(selection_repo, monkeypatch):
    monkeypatch.setitem(runner.SOURCE_GROUPS, "scripts/emitter.py", ("unknown",))
    monkeypatch.setitem(runner.GROUPS, "quick", ("tests/test_contract.py", "tests/test_contract.py"))
    problems = runner.group_problems(selection_repo)
    assert any("duplicate" in problem for problem in problems)
    assert any("invalid source route" in problem for problem in problems)


def test_make_changed_targets_share_runner_and_validate_inventory():
    result = subprocess.run(
        ["make", "--dry-run", "test-plan", "test-changed", "validate", "BASE=dev"],
        cwd=runner.ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert 'scripts/run_tests.py --list --changed-against "dev"' in result.stdout
    assert 'scripts/run_tests.py --changed-against "dev" all -q' in result.stdout
    assert "scripts/run_tests.py --check-groups" in result.stdout


def test_explicit_pattern_retains_name_filter(fake_pytest_env):
    result = subprocess.run(
        ["bash", str(runner.ROOT / "scripts/run-tests.sh"), "pattern", "scanner", "-q"],
        env=fake_pytest_env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout)["args"] == ["tests/", "-k", "scanner", "-q"]


def _git(root, *args):
    return subprocess.run(
        ["git", "-c", "user.name=Selection Test", "-c", "user.email=selection@example.invalid", *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


@pytest.fixture
def git_repo(tmp_path):
    _git(tmp_path, "init", "-b", "dev")
    for name in ("committed", "staged", "unstaged", "deleted", "renamed", "cancelled", "untouched"):
        (tmp_path / name).write_text("initial\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "Initial neutral fixture")
    return tmp_path, _git(tmp_path, "rev-parse", "HEAD")


def test_git_selection_includes_each_change_state_and_both_rename_paths(git_repo):
    root, base = git_repo
    (root / "committed").write_text("committed change\n")
    _git(root, "add", "committed")
    _git(root, "commit", "-m", "Branch change")
    for name in ("staged", "cancelled"):
        (root / name).write_text("staged change\n")
        _git(root, "add", name)
    (root / "cancelled").write_text("initial\n")
    (root / "unstaged").write_text("local change\n")
    (root / "deleted").unlink()
    _git(root, "mv", "renamed", "name with spaces")
    (root / "new\nfile.py").touch()
    assert set(runner.changed_paths(base, root)) == {
        "committed",
        "staged",
        "unstaged",
        "deleted",
        "renamed",
        "name with spaces",
        "cancelled",
        "new\nfile.py",
    }


def test_git_selection_uses_merge_base_and_excludes_upstream_only_changes(git_repo):
    root, base = git_repo
    _git(root, "checkout", "-b", "upstream")
    (root / "upstream-only").touch()
    _git(root, "add", ".")
    _git(root, "commit", "-m", "Upstream advance")
    _git(root, "checkout", "dev")
    (root / "committed").write_text("branch change\n")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "Local branch change")
    assert runner.changed_paths("upstream", root) == ["committed"]


def test_git_selection_rejects_invalid_reference_and_clean_repo_is_empty(git_repo):
    root, base = git_repo
    assert runner.changed_paths(base, root) == []
    with pytest.raises(ValueError, match="cannot determine"):
        runner.changed_paths("--invalid-reference", root)


def test_changed_cli_lists_reasons_without_running_pytest(selection_repo, monkeypatch, capsys):
    monkeypatch.setattr(runner, "changed_paths", lambda base: ["scripts/emitter.py"])
    original = runner.select_changed
    monkeypatch.setattr(runner, "select_changed", lambda paths: original(paths, selection_repo))
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **kw: pytest.fail("pytest must not run"))
    assert runner.main(["--list", "--changed-against", "dev"]) == 0
    output = capsys.readouterr()
    assert "tests/test_reader.py" in output.out
    assert "producer, consumer" in output.err


def test_changed_cli_preserves_pytest_status(selection_repo, monkeypatch):
    monkeypatch.setattr(runner, "changed_paths", lambda base: [])
    original = runner.select_changed
    monkeypatch.setattr(runner, "select_changed", lambda paths: original(paths, selection_repo))
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 5)

    monkeypatch.setattr(runner.subprocess, "run", run)
    assert runner.main(["--changed-against", "dev", "all", "-q"]) == 5
    assert calls == [[sys.executable, "-m", "pytest", "tests/test_contract.py", "-q"]]


def test_requirement_routes_load_real_bindings():
    guards = runner.requirement_tests(["scripts/merge_threats.py"])
    assert "tests/test_merge_threats.py" in guards
    assert all("::" not in path and (runner.ROOT / path).is_file() for path in guards)


@pytest.mark.parametrize("guard", ["tests/test_missing.py", "../escaped.py", "scripts/emitter.py"])
def test_unusable_requirement_guard_requires_full_suite(selection_repo, monkeypatch, guard):
    monkeypatch.setattr(runner, "requirement_tests", lambda paths, root: [guard])
    result = runner.select_changed(["scripts/emitter.py"], selection_repo)
    assert result.paths == ("tests/",)
    assert "requirement guard" in result.reasons[0]


@pytest.mark.parametrize("document", ["requirements: [", "{}"])
def test_invalid_requirement_bindings_are_rejected(tmp_path, document):
    (tmp_path / "data").mkdir()
    (tmp_path / "schemas").mkdir()
    (tmp_path / "data/requirement-bindings.yaml").write_text(document)
    schema = "schemas/requirement-bindings.schema.yaml"
    (tmp_path / schema).write_text((runner.ROOT / schema).read_text())
    with pytest.raises(ValueError, match="invalid requirement bindings"):
        runner.requirement_tests(["scripts/example.py"], tmp_path)


def test_changed_wrapper_forwards_reference_and_pytest_options(tmp_path, fake_pytest_env):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "run-tests.sh").write_text((runner.ROOT / "scripts/run-tests.sh").read_text())
    (scripts / "run_tests.py").write_text("import json, sys\nprint(json.dumps(sys.argv[1:]))\n")
    result = subprocess.run(
        ["bash", str(scripts / "run-tests.sh"), "changed", "dev", "-q", "-x"],
        env=fake_pytest_env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout) == ["--changed-against", "dev", "all", "-q", "-x"]


def test_invalid_base_stops_cli_before_pytest(monkeypatch, capsys):
    def invalid(base):
        raise ValueError("cannot determine changed paths: invalid base")

    monkeypatch.setattr(runner, "changed_paths", invalid)
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **kw: pytest.fail("pytest must not run"))
    assert runner.main(["--changed-against", "absent"]) == 2
    assert "invalid base" in capsys.readouterr().err


def test_group_validator_cli_stops_on_inventory_drift(monkeypatch, capsys):
    monkeypatch.setattr(runner, "group_problems", lambda: ["unassigned test"])
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **kw: pytest.fail("pytest must not run"))
    assert runner.main(["--check-groups"]) == 2
    assert "unassigned test" in capsys.readouterr().err


@pytest.mark.parametrize(
    "source, required",
    [
        (
            "scripts/config_iac_scanner.py",
            {"tests/test_config_iac_scanner.py", "tests/test_agent_config_checks.py", "tests/test_merge_threats.py"},
        ),
        (
            "scripts/export_sarif.py",
            {"tests/test_export_sarif.py", "tests/test_threat_fixture.py", "tests/test_build_threat_model_yaml.py"},
        ),
        (
            "scripts/figure2_svg.py",
            {"tests/test_compose_threat_model.py", "tests/test_qa_checks.py"},
        ),
        (
            "scripts/repo_scan.py",
            {"tests/test_repo_scan.py", "tests/test_route_inventory.py", "tests/test_architecture_coverage_checks.py"},
        ),
    ],
)
def test_shipped_source_routes_include_reviewed_producers_and_consumers(source, required):
    selection = runner.select_changed([source])
    assert required <= set(selection.paths)
    assert "tests/test_run_tests.py" in selection.paths
    assert "tests/test_full_run_e2e.py" not in selection.paths


def test_all_shipped_source_routes_remain_selective():
    for source in runner.SOURCE_GROUPS:
        selection = runner.select_changed([source])
        assert selection.paths != ("tests/",), (source, selection.reasons)


def test_required_selection_commands_stay_in_agent_and_maintainer_guidance():
    for filename in ("AGENTS.md", "CONTRIBUTING.md"):
        document = (runner.ROOT / filename).read_text()
        assert "make test-plan BASE=origin/dev" in document
        assert "make validate test-changed BASE=origin/dev" in document
        assert "scripts/run_tests.py" in document
