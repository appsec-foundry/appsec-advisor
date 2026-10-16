"""A one-repository controller run reports into its checkout (MR-6) as a single-repository model (MR-8)."""

import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

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


def _answer(reports, text="Records of paying customers for invoicing."):
    raw = reports / ".business-context-raw.md"
    raw.write_text(f"## Business purpose\n\n**Question:** What is the use case?\n**Answer:** {text}\n")
    return raw


@pytest.mark.parametrize("name", ["solo", "records-service"])
def test_dialog_answers_reach_the_checkout_context_without_a_session_run(tmp_path, name):
    root = tmp_path / name
    checkout(root)
    action = controller.assess_context_preview(str(root))
    reports = root / "docs" / "security"
    assert Path(action["preview"]).is_file() and Path(action["output_dir"]) == reports
    # The dialog belongs to this skill and names only the launch helpers' own save command.
    instructions = Path(action["instruction_file"])
    assert instructions.parent == controller.PLUGIN_ROOT / "skills" / "create-threat-model2"
    commands = set(re.findall(r"orchestration_controller\.py\" ([a-z-]+)", instructions.read_text()))
    assert commands == {"assess-context-save"}
    _answer(reports)
    saved = controller.assess_context_save(
        str(root), context_answer="answered", impact_choice=None, use_case_choice="confirmed"
    )
    assert saved["action"] == "context_saved"
    assert "paying customers for invoicing" in (reports / "business-context.md").read_text()
    assert not (reports / ".business-context-raw.md").exists() and not Path(action["preview"]).exists()


def test_dialog_save_refuses_inconsistent_or_foreign_state(tmp_path):
    root = tmp_path / "solo"
    reports = _checkout_with_reports(root)
    before = (reports / "business-context.md").read_text()
    with pytest.raises(controller.CallError, match="impact choice requires"):
        controller.assess_context_save(
            str(root), context_answer="skip", impact_choice="declared-harm", use_case_choice=None
        )
    _answer(reports, "api_key = 'sk-live-0123456789abcdefghijklmnop'")
    with pytest.raises(controller.CallError, match="rejected"):
        controller.assess_context_save(str(root), context_answer="answered", impact_choice=None, use_case_choice=None)
    assert (reports / "business-context.md").read_text() == before
    # A live run holding the directory keeps it to itself.
    controller.acquire_lock._write_lock(reports / ".appsec-lock", os.getpid(), int(time.time()), "another-run")
    with pytest.raises(controller.CallError, match="another live run"):
        controller.assess_context_preview(str(root))


def test_a_linked_report_directory_is_refused_before_any_write(tmp_path):
    root = tmp_path / "solo"
    checkout(root)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (root / "docs").mkdir()
    (root / "docs" / "security").symlink_to(elsewhere)
    with pytest.raises(controller.CallError, match="real directory"):
        controller.assess_context_preview(str(root))
    assert not any(elsewhere.iterdir())


def _running(reports, pid, *, run_id="assessment-0123", age=0):
    reports.mkdir(parents=True, exist_ok=True)
    (reports / ".assessment-state.json").write_text(json.dumps({"status": "running", "run_id": run_id}))
    controller.acquire_lock._write_lock(reports / ".appsec-lock", pid, int(time.time()) - age, run_id)


def test_stop_signals_only_the_running_controller_assessment(tmp_path):
    reports = tmp_path / "solo" / "docs" / "security"
    target = subprocess.Popen(["sleep", "30"])
    try:
        _running(reports, target.pid)
        assert controller.assess_stop(reports)["action"] == "stopping"
        assert target.wait(timeout=10) == -signal.SIGTERM
        assert (reports / ".assessment-stop").read_text() == "assessment-0123\n"
    finally:
        target.kill()


def test_stop_reaches_a_run_whose_process_it_cannot_see(tmp_path):
    """A sandboxed command sees no process outside its PID namespace; the run still gets the request."""
    reports = tmp_path / "solo" / "docs" / "security"
    gone = subprocess.Popen(["true"])
    gone.wait()
    _running(reports, gone.pid)
    action = controller.assess_stop(reports)
    assert action["action"] == "stopping" and "next checkpoint" in action["reason"]
    assert (reports / ".assessment-stop").read_text() == "assessment-0123\n"


@pytest.mark.parametrize("planted", ["stale", "foreign-run", "finished"])
def test_stop_never_signals_through_a_stale_or_planted_lock(tmp_path, planted):
    reports = tmp_path / "solo" / "docs" / "security"
    target = subprocess.Popen(["sleep", "30"])
    try:
        _running(reports, target.pid, age=86_400 if planted == "stale" else 0)
        if planted == "foreign-run":
            controller.acquire_lock._write_lock(reports / ".appsec-lock", target.pid, int(time.time()), "other")
        if planted == "finished":
            (reports / ".assessment-state.json").write_text(
                json.dumps({"status": "complete", "run_id": "assessment-0123"})
            )
        with pytest.raises(controller.CallError):
            controller.assess_stop(reports)
        assert target.poll() is None
        assert not (reports / ".assessment-stop").exists()
    finally:
        target.kill()


def test_pause_after_stops_at_the_phase_boundary_and_resume_reuses_its_jobs(tmp_path, monkeypatch):
    from runtime.assessment_state import AssessmentPaused

    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    steps, host = [], FullHost()
    with pytest.raises(AssessmentPaused) as paused:
        _assess(tmp_path, monkeypatch, ("solo",), ("--no-pdf", "--pause-after", "2"), progress=steps.append, host=host)
    assert (paused.value.number, paused.value.phase) == (2, "Architecture")
    assert not any(step.startswith("Measuring the boundary source context") for step in steps)
    out = tmp_path / "out"
    assert json.loads((out / ".assessment-state.json").read_text())["status"] == "interrupted"
    assert not (out / "threat-model.md").exists()
    calls = len(host.roles)
    argv = ["--repo", str(tmp_path / "solo"), "--output", str(out), "--hard-budget", "5", "--trust-mode", "trusted"]
    argv += ["--model", "haiku", "--no-pdf", "--resume"]
    outcome = controller.assess_repositories(argv, host_factory=host.factory, progress=lambda text: None)
    assert outcome["status"] == "complete"
    # Accepted jobs of the paused phases are reused, not requested again.
    assert "architecture_analyst" in host.roles[:calls]
    assert "architecture_analyst" not in host.roles[calls:]


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGHUP, signal.SIGINT])
def test_terminate_becomes_the_runs_own_cancellation(signum):
    """assess-stop, a closed terminal and Ctrl-C all stop the jobs and their model processes."""
    state = SimpleNamespace(cancelled=False)
    previous = signal.getsignal(signum)
    with controller._stop_on_terminate(state):
        os.kill(os.getpid(), signum)
        time.sleep(0.05)
    assert state.cancelled
    assert signal.getsignal(signum) is previous


def test_a_second_ctrl_c_interrupts_at_once():
    state = SimpleNamespace(cancelled=False)
    with pytest.raises(KeyboardInterrupt), controller._stop_on_terminate(state):
        os.kill(os.getpid(), signal.SIGINT)
        time.sleep(0.05)
        os.kill(os.getpid(), signal.SIGINT)
        time.sleep(0.05)


def test_a_failed_best_effort_scanner_is_a_run_warning(tmp_path, monkeypatch):
    """A report built without a scanner's checks must say so, not look complete."""
    real = controller._run_script

    def run_script(name, args, *rest, **kwargs):
        if name == "analyzers/source_auth_scanner.py":
            raise controller.ControllerError("scanner crashed", exit_code=1)
        return real(name, args, *rest, **kwargs)

    monkeypatch.setattr(controller, "_run_script", run_script)
    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    outcome, _, _ = _assess(tmp_path, monkeypatch, ("solo",), ("--no-pdf",))
    assert outcome["status"] == "complete"
    assert any("analyzers/source_auth_scanner.py failed" in warning for warning in outcome["warnings"])


def test_requested_exports_and_slug_are_published(tmp_path, monkeypatch):
    """Every export flag the session runtime accepted still produces its deliverable, stamped copies included."""
    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    real = controller._run_script

    # The PDF exporter needs a browser the test environment may not grant; its
    # own tests cover the conversion, this one the controller's wiring.
    def run_script(name, args, *rest, **kwargs):
        if name == "exporters/export_pdf.py":
            Path(args[args.index("--output") + 1]).write_bytes(b"%PDF-1.7\n")
            return None
        return real(name, args, *rest, **kwargs)

    monkeypatch.setattr(controller, "_run_script", run_script)
    outcome, _, out = _assess(
        tmp_path,
        monkeypatch,
        ("solo",),
        ("--yaml", "--sarif", "--threatdragon", "--pdf", "--pentest-tasks", "--slug", "probe"),
    )
    assert outcome["status"] == "complete"
    expected = (
        "threat-model.md",
        "threat-model.yaml",
        "threat-model.sarif.json",
        "threat-model.threatdragon.json",
        "threat-model.pdf",
        "pentest-tasks.yaml",
    )
    for name in expected:
        assert (out / name).is_file(), name
        stamped = controller.stamp_threat_model._stamped_name(name, "probe")
        assert (out / stamped).is_file(), stamped
    assert json.loads((out / "threat-model.sarif.json").read_text())["runs"]
    assert yaml.safe_load((out / "pentest-tasks.yaml").read_text())


def test_a_failed_export_publishes_nothing_and_leaves_the_earlier_report(tmp_path, monkeypatch):
    """RB-5: deliverables are staged, so an export failure never leaves a new model beside an old report."""
    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    real = controller._run_script

    def run_script(name, args, *rest, **kwargs):
        if name == "exporters/export_sarif.py":
            raise controller.ControllerError("sarif exporter crashed", exit_code=1)
        return real(name, args, *rest, **kwargs)

    monkeypatch.setattr(controller, "_run_script", run_script)
    with pytest.raises(controller.ControllerError, match="sarif exporter crashed"):
        _assess(tmp_path, monkeypatch, ("solo",), ("--no-pdf", "--sarif"))
    assert not [path.name for path in (tmp_path / "out").iterdir() if path.name.startswith("threat-model")]


def _assess_into_checkout(tmp_path, monkeypatch, root):
    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    host = FullHost()
    real_admit = multi_repo_scope.admit

    def admit(selections, output, **options):
        host.scope = real_admit(selections, output, **options)
        return host.scope

    monkeypatch.setattr(multi_repo_scope, "admit", admit)
    monkeypatch.setattr(controller, "_assessment_runtime_fingerprint", lambda: "a" * 64)
    argv = ["--repo", str(root), "--output", str(root / "docs" / "security"), "--hard-budget", "5"]
    argv += ["--trust-mode", "trusted", "--model", "haiku", "--no-pdf"]
    return controller.assess_repositories(argv, host_factory=host.factory, progress=lambda text: None)


@pytest.mark.parametrize("name", ["solo", "records-service"])
def test_a_first_report_in_the_checkout_gets_an_ignore_rule(tmp_path, monkeypatch, name):
    root = tmp_path / name
    checkout(root)
    assert _assess_into_checkout(tmp_path, monkeypatch, root)["status"] == "complete"
    assert "docs/security/**" in (root / ".gitignore").read_text().splitlines()


def test_a_report_outside_any_checkout_writes_no_ignore_rule(tmp_path, monkeypatch):
    outcome, _, _ = _assess(tmp_path, monkeypatch, ("solo",), ("--no-pdf",))
    assert outcome["status"] == "complete"
    assert not (tmp_path / ".gitignore").exists() and not (tmp_path / "solo" / ".gitignore").exists()


def test_a_one_repository_refusal_does_not_call_itself_multi_repository(tmp_path):
    root = tmp_path / "solo"
    checkout(root)
    argv = ["--repo", str(root), "--output", str(tmp_path / "out"), "--hard-budget", "5", "--incremental"]
    with pytest.raises(controller.CallError) as refused:
        controller.assess_repositories(argv, host_factory=lambda *args: pytest.fail("no model may be called"))
    assert "--incremental is not supported" in str(refused.value)
    assert "multi-repository" not in str(refused.value)
