"""A one-repository controller run reports into its checkout (MR-6) as a single-repository model (MR-8)."""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from orchestrator import orchestration_controller as controller
from runtime import multi_repo_scope
from shared.assessment_sources import model_file_is_portable
from validators import review_threat_model
from validators.validate_intermediate import validate_threat_model_output

from tests.test_multi_repo_assessment import FullHost, _assess
from tests.test_multi_repo_controller import checkout


@pytest.mark.parametrize("name", ["solo", "records-service"])
def test_one_repository_assessment_publishes_a_version_1_model(tmp_path, monkeypatch, name):
    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    outcome, _, out = _assess(tmp_path, monkeypatch, (name,), ("--no-pdf",))
    assert outcome["status"] == "complete"
    text = (out / "threat-model.yaml").read_text()
    model = yaml.safe_load(text)
    assert model["meta"]["schema_version"] == 1
    assert "source_inventory" not in model
    assert "repository_id" not in text
    assert "repository_root" not in model["meta"] and "output_dir" not in model["meta"]
    paths = [path for component in model["components"] for path in component["paths"]]
    assert "app.py" in paths and not any(path.startswith(f"{name}/") for path in paths)
    assert validate_threat_model_output(model)[0]


def test_two_repositories_keep_the_qualified_version_2_model(tmp_path, monkeypatch):
    outcome, _, out = _assess(tmp_path, monkeypatch, ("frontend", "backend"), ("--no-pdf",))
    assert outcome["status"] == "complete"
    model = yaml.safe_load((out / "threat-model.yaml").read_text())
    assert model["meta"]["schema_version"] == 2
    assert len(model["source_inventory"]["repositories"]) == 2
    assert model_file_is_portable(out / "threat-model.yaml")


def test_follow_on_tools_accept_a_one_repository_controller_model(tmp_path, monkeypatch):
    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    _, _, out = _assess(tmp_path, monkeypatch, ("solo",), ("--no-pdf",))
    # The shared refusal of publish, review, eval, baseline and analyst context.
    assert not model_file_is_portable(out / "threat-model.yaml")
    loaded = review_threat_model._load_model(out)
    assert loaded["threats"]


def _checkout_with_reports(root):
    checkout(root)
    reports = root / "docs" / "security"
    reports.mkdir(parents=True)
    (reports / "business-context.md").write_text("# Business context\n\nRecords of paying customers.\n")
    (reports / "threat-model.md").write_text("# Legacy report\n")
    (reports / ".run-issues.json").write_text("{}\n")
    return reports


@pytest.mark.parametrize("name", ["solo", "records-service"])
def test_sole_repository_output_in_docs_security_is_excluded_from_the_source_view(tmp_path, name):
    root = tmp_path / name
    reports = _checkout_with_reports(root)
    scope = multi_repo_scope.admit([str(root)], str(reports), minimum=1)
    assert scope.output_in_checkout()
    files = set(scope.repositories[0].files)
    assert "app.py" in files and "docs/security/business-context.md" in files
    assert not {"docs/security/threat-model.md", "docs/security/.run-issues.json"} & files
    # Files the run writes into its report directory leave the admitted state unchanged.
    (reports / ".assessment-work").mkdir()
    (reports / ".assessment-work" / "draft.md").write_text("draft\n")
    (reports / "threat-model.md").write_text("# New report\n")
    scope.verify_unchanged()
    # A changed input is still a changed source state.
    (reports / "business-context.md").write_text("# Business context\n\nChanged.\n")
    with pytest.raises(multi_repo_scope.ScopeError, match="changed"):
        scope.verify_unchanged()


def test_combined_output_inside_a_checkout_is_still_rejected(tmp_path):
    for name in ("frontend", "backend"):
        checkout(tmp_path / name)
    with pytest.raises(multi_repo_scope.ScopeError, match="separate"):
        multi_repo_scope.admit(
            [str(tmp_path / "frontend"), str(tmp_path / "backend")], str(tmp_path / "frontend" / "docs" / "security")
        )
    # Any other directory of a sole checkout stays rejected as well.
    with pytest.raises(multi_repo_scope.ScopeError, match="separate"):
        multi_repo_scope.admit([str(tmp_path / "backend")], str(tmp_path / "backend" / "reports"), minimum=1)


def test_docs_security_keeps_foreign_files_and_overwrites_a_legacy_report(tmp_path, monkeypatch):
    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    root = tmp_path / "solo"
    reports = _checkout_with_reports(root)
    real_admit = multi_repo_scope.admit
    host = FullHost()

    def admit(selections, output, **options):
        host.scope = real_admit(selections, output, **options)
        return host.scope

    monkeypatch.setattr(multi_repo_scope, "admit", admit)
    monkeypatch.setattr(controller, "_assessment_runtime_fingerprint", lambda: "a" * 64)
    argv = ["--repo", str(root), "--output", str(reports), "--hard-budget", "5", "--trust-mode", "trusted"]
    argv += ["--model", "haiku", "--no-pdf"]
    outcome = controller.assess_repositories(argv, host_factory=host.factory, progress=lambda text: None)
    assert outcome["status"] == "complete"
    assert (reports / "threat-model.md").read_text() != "# Legacy report\n"
    assert yaml.safe_load((reports / "threat-model.yaml").read_text())["meta"]["schema_version"] == 1
    assert (reports / "business-context.md").read_text().startswith("# Business context")
    assert (reports / ".run-issues.json").is_file()
    # A rebuild removes only the controller's own files and keeps the rest.
    outcome = controller.assess_repositories([*argv, "--rebuild"], host_factory=host.factory, progress=lambda t: None)
    assert outcome["status"] == "complete"
    assert (reports / "business-context.md").is_file() and (reports / ".run-issues.json").is_file()


def _budget(argv):
    ns, rest = controller._assessment_argument_parser().parse_known_args(["--repo", "r", "--output", "o", *argv])
    return controller._assessment_budget(ns, rest).max_usd


@pytest.mark.parametrize(
    ("argv", "usd"),
    [
        ([], 20.0),
        (["--quick"], 10.0),
        (["--assessment-depth", "thorough"], 40.0),
        (["--assessment-depth=quick"], 10.0),
    ],
)
def test_interactive_launch_derives_the_hard_budget_from_depth(argv, usd):
    assert _budget(["--interactive-launch", *argv]) == usd


def test_explicit_budget_replaces_the_depth_default():
    assert _budget(["--interactive-launch", "--thorough", "--hard-budget", "7"]) == 7.0
    assert _budget(["--interactive-launch", "--soft-budget", "8"]) == 10.0
    # Without the interactive launch a budget flag stays mandatory.
    with pytest.raises(controller.CallError, match="requires --soft-budget or --hard-budget"):
        _budget(["--thorough"])
    with pytest.raises(controller.CallError, match="invalid --assessment-depth"):
        _budget(["--interactive-launch", "--assessment-depth", "deep"])
