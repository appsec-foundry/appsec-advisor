"""Assessment ownership, unchanged-state resume and retained cost reservations."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runtime import acquire_lock
from runtime.analyst_host import HostCancelled, HostReply
from runtime.assessment_host import ExchangeError
from runtime.assessment_jobs import AssessmentBudget, AssessmentJobs
from runtime.assessment_state import AssessmentState
from runtime.multi_repo_scope import AssessmentScope, ScopeError, admit


@pytest.fixture
def scope(tmp_path):
    roots = []
    for label in ("frontend", "backend"):
        root = tmp_path / label
        root.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
        (root / "app.py").write_text("print('neutral fixture')\n")
        subprocess.run(["git", "-C", str(root), "add", "app.py"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-qm",
                "Fixture",
            ],
            check=True,
        )
        roots.append(str(root))
    return admit(roots, str(tmp_path / "reports"))


def lifecycle(scope, **overrides):
    options = {
        "configuration": {"stride_model": "haiku"},
        "runtime_sha256": "a" * 64,
        "budget": AssessmentBudget(1.0, 0.05, 10, 60),
    }
    options.update(overrides)
    return AssessmentState(scope, **options)


def stored(scope):
    return json.loads((scope.output / ".assessment-state.json").read_text())


def test_interrupted_session_releases_lock_and_resumes_same_identity(scope):
    initial = lifecycle(scope)
    with initial.hold():
        assert acquire_lock.read_run_id(initial.lock) == initial.state["run_id"]
        initial.budget.calls, initial.budget.spent_usd = 2, 0.03
        initial.checkpoint()
    assert not initial.lock.exists()
    assert stored(scope)["status"] == "interrupted"
    resumed = lifecycle(scope, resume=True)
    with resumed.hold():
        assert resumed.state["run_id"] == initial.state["run_id"]
        assert resumed.budget.calls == 2 and resumed.budget.spent_usd == 0.03
        assert resumed.budget.deadline <= initial.budget.deadline + 1


def test_complete_session_binds_deliverables_and_detects_later_changes(scope):
    state = lifecycle(scope)
    with state.hold():
        (scope.output / "threat-model.yaml").write_text("version: 2\n")
        state.complete(["threat-model.yaml"])
    assert stored(scope)["status"] == "complete"
    with lifecycle(scope, resume=True).hold() as resumed:
        assert resumed.state["status"] == "complete"
    (scope.output / "threat-model.yaml").write_text("version: modified\n")
    with pytest.raises(ExchangeError, match="changed after completion"):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Altered deliverables must not be accepted")


@pytest.mark.parametrize("field,value", [("configuration", {"stride_model": "sonnet"}), ("runtime_sha256", "b" * 64)])
def test_changed_settings_or_runtime_reject_resume(scope, field, value):
    with lifecycle(scope).hold():
        pass
    with pytest.raises(ExchangeError, match="unchanged"):
        with lifecycle(scope, resume=True, **{field: value}).hold():
            pytest.fail("Changed request must not resume")


def test_changed_source_cannot_resume_or_complete(scope):
    with lifecycle(scope).hold() as state:
        (scope.repositories[0].root / "app.py").write_text("print('changed')\n")
        (scope.output / "threat-model.yaml").write_text("version: 2\n")
        with pytest.raises(ScopeError, match="changed"):
            state.complete(["threat-model.yaml"])
    with pytest.raises(ScopeError, match="changed"):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Changed source must not resume")


def test_cost_reservation_is_durable_before_dispatch_and_unknown_cost_blocks_resume(scope):
    state = lifecycle(scope)

    class BrokenHost:
        def invoke(self, *args):
            assert stored(scope)["accounting"] == {"calls": 1, "spent_usd": 0.05, "unavailable": True}
            raise RuntimeError("backend failed")

    with pytest.raises(RuntimeError, match="backend failed"):
        with state.hold():
            jobs = AssessmentJobs(
                scope,
                state.directory / "jobs",
                state.budget,
                lambda role, ceiling: BrokenHost(),
                state.should_stop,
                state.checkpoint,
            )
            jobs.execute(
                role="recon_scanner",
                selector="one",
                instructions="trusted",
                context={},
                schema={"type": "object"},
                allowed_sources=frozenset(),
                validate=lambda a, r: None,
            )
    assert stored(scope)["status"] == "failed"
    assert stored(scope)["accounting"]["unavailable"] is True
    with pytest.raises(ExchangeError, match="unfinished cost reservation"):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Unknown costs must not be refunded")


def test_validated_cached_job_survives_resume_without_dispatch_or_extra_cost(scope):
    state = lifecycle(scope)
    schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["ok"],
        "properties": {"ok": {"const": True}},
    }
    kwargs = dict(
        role="recon_scanner",
        selector="one",
        instructions="trusted",
        context={},
        schema=schema,
        allowed_sources=frozenset(),
        validate=lambda a, r: None,
    )

    class Host:
        def invoke(self, *args):
            return HostReply({"action": "complete", "reads": [], "artifact": {"ok": True}}, 0.01)

    with state.hold():
        jobs = AssessmentJobs(
            scope,
            state.directory / "jobs",
            state.budget,
            lambda role, ceiling: Host(),
            state.should_stop,
            state.checkpoint,
        )
        assert jobs.execute(**kwargs) == {"ok": True}

    def no_host(role, ceiling):
        pytest.fail("Accepted job must resume without another dispatch")

    with lifecycle(scope, resume=True).hold() as resumed:
        jobs = AssessmentJobs(
            scope, resumed.directory / "jobs", resumed.budget, no_host, resumed.should_stop, resumed.checkpoint
        )
        assert jobs.execute(**kwargs) == {"ok": True}
        assert resumed.budget.calls == 1 and resumed.budget.spent_usd == pytest.approx(0.01)


def test_existing_user_files_are_preserved_and_block_fresh_assessment(scope):
    scope.output.mkdir()
    original = scope.output / "notes.txt"
    original.write_text("preserve")
    with pytest.raises(ExchangeError, match="empty output"):
        with lifecycle(scope).hold():
            pytest.fail("Fresh assessment must not erase unrelated output")
    assert original.read_text() == "preserve"
    assert not (scope.output / ".assessment-state.json").exists()


def test_live_ordinary_lock_blocks_multi_repo_assessment(scope):
    scope.output.mkdir()
    acquire_lock._write_lock(scope.output / ".appsec-lock", os.getpid(), int(time.time()), "ordinary-run")
    with pytest.raises(ExchangeError, match="another live run"):
        with lifecycle(scope).hold():
            pytest.fail("Output already has a live owner")


def test_held_multi_repo_guard_blocks_ordinary_cli_and_concurrent_controller(scope):
    with lifecycle(scope).hold():
        result = subprocess.run(
            [sys.executable, str(acquire_lock.__file__), str(scope.output / ".appsec-lock"), "--run-id=other"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 1 and "LOCK_BLOCKED" in result.stdout
        with pytest.raises(acquire_lock.LockBusy):
            with lifecycle(scope, resume=True).hold():
                pytest.fail("Concurrent controller must not enter")


@pytest.mark.parametrize("target", [".appsec-lock", ".appsec-lock.guard"])
def test_external_links_are_rejected_without_modifying_target(scope, tmp_path, target):
    scope.output.mkdir()
    original = tmp_path / "external"
    original.write_text("preserve")
    (scope.output / target).symlink_to(original)
    with pytest.raises((ExchangeError, acquire_lock.LockBusy)):
        with lifecycle(scope).hold():
            pytest.fail("Linked lock must not confer ownership")
    assert original.read_text() == "preserve"


@pytest.mark.parametrize("target", [".appsec-lock", ".appsec-lock.guard"])
def test_hard_linked_locks_cannot_modify_an_external_file(scope, tmp_path, target):
    scope.output.mkdir()
    original = tmp_path / "external"
    original.write_text("preserve")
    os.link(original, scope.output / target)
    with pytest.raises((ExchangeError, acquire_lock.LockBusy)):
        with lifecycle(scope).hold():
            pytest.fail("Hard-linked locks must not confer ownership")
    assert original.read_text() == "preserve"


def test_symlinked_work_directory_cannot_resume(scope, tmp_path):
    with lifecycle(scope).hold() as initial:
        pass
    initial.directory.rmdir()
    initial.directory.symlink_to(tmp_path)
    with pytest.raises(ExchangeError, match="non-directory or link"):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Work directory must remain private")


def test_expired_resume_does_not_restart_time_budget(scope):
    with lifecycle(scope).hold():
        pass
    state = stored(scope)
    state["expires_at"] = int(time.time()) - 1
    state["started_at"] = state["expires_at"] - 60
    (scope.output / ".assessment-state.json").write_text(json.dumps(state))
    with pytest.raises(ExchangeError, match="budget is exhausted"):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Resume must not grant another timeout")


@pytest.mark.parametrize("change", ["nonfinite", "extended-deadline", "extra-field"])
def test_malformed_accounting_or_lifecycle_cannot_resume(scope, change):
    with lifecycle(scope).hold():
        pass
    state = stored(scope)
    if change == "nonfinite":
        state["accounting"]["spent_usd"] = float("nan")
    elif change == "extended-deadline":
        state["expires_at"] += 60
    else:
        state["model_selected_command"] = "ignored-command"
    (scope.output / ".assessment-state.json").write_text(json.dumps(state))
    with pytest.raises(ExchangeError):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Invalid lifecycle input must not reach a host")


def test_cancellation_records_interruption_and_releases_output(scope):
    with pytest.raises(HostCancelled):
        with lifecycle(scope).hold() as state:
            state.cancelled = True
            assert state.should_stop() is True
            raise HostCancelled("cancelled")
    assert stored(scope)["status"] == "interrupted"
    assert not (scope.output / ".appsec-lock").exists()


@pytest.mark.parametrize("name", ["../source.py", "/tmp/outside", ".hidden", "model\n.yaml"])
def test_untrusted_deliverable_names_cannot_select_paths(scope, name):
    with lifecycle(scope).hold() as state:
        with pytest.raises(ExchangeError, match="controller-selected basename"):
            state.complete([name])


def test_missing_deliverables_cannot_mark_complete(scope):
    with lifecycle(scope).hold() as state:
        with pytest.raises(ExchangeError, match="gated deliverables"):
            state.complete([])
        assert state.state["status"] == "running"


def test_output_ancestor_link_is_rejected(scope, tmp_path):
    link = tmp_path / "output-link"
    link.symlink_to(tmp_path, target_is_directory=True)
    untrusted = AssessmentScope(scope.repositories, link / "report")
    with pytest.raises(ExchangeError, match="non-directory or link"):
        with lifecycle(untrusted).hold():
            pytest.fail("Linked output ancestry must not be admitted")
