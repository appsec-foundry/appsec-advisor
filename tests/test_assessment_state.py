"""Assessment ownership, unchanged-state resume and retained cost reservations."""

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runtime import acquire_lock
from runtime.analyst_host import HostCancelled, HostReply, TransportError
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


@pytest.mark.parametrize(
    "field,value,named",
    [
        ("configuration", {"stride_model": "sonnet"}, "the assessment settings changed"),
        ("runtime_sha256", "b" * 64, "the plugin version changed"),
        ("budget", AssessmentBudget(2.0, 0.05, 10, 60), "the budget or time limits changed"),
    ],
)
def test_changed_settings_or_runtime_reject_resume_and_name_the_change(scope, field, value, named):
    with lifecycle(scope).hold():
        pass
    with pytest.raises(ExchangeError, match=f"cannot resume: {named} .*new scan is required") as caught:
        with lifecycle(scope, resume=True, **{field: value}).hold():
            pytest.fail("Changed request must not resume")
    assert "source code" not in str(caught.value)


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


def test_a_refused_call_with_a_reported_cost_leaves_the_run_resumable(scope):
    state = lifecycle(scope)

    class RefusingHost:
        def invoke(self, *args):
            raise TransportError("host call failed: authentication_failed", reason="authentication_failed", usd=0.0)

    with pytest.raises(TransportError, match="--resume"):
        with state.hold():
            AssessmentJobs(
                scope,
                state.directory / "jobs",
                state.budget,
                lambda role, ceiling: RefusingHost(),
                state.should_stop,
                state.checkpoint,
            ).execute(
                role="recon_scanner",
                selector="one",
                instructions="trusted",
                context={},
                schema={"type": "object"},
                allowed_sources=frozenset(),
                validate=lambda a, r: None,
            )
    assert stored(scope)["status"] == "failed"
    assert stored(scope)["accounting"] == {"calls": 1, "spent_usd": 0.0, "unavailable": False}
    with lifecycle(scope, resume=True).hold() as resumed:
        assert resumed.budget.calls == 1 and resumed.budget.spent_usd == 0.0


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


def _fail(state):
    with pytest.raises(RuntimeError):
        with state.hold():
            (state.directory / "jobs").mkdir()
            (state.directory / "jobs" / "job-000000000000000000000000.json").write_text("{}")
            (state.directory / "context").mkdir()
            raise RuntimeError("stage failed")


@pytest.mark.parametrize("finish", ["failed", "interrupted"])
def test_fresh_start_clears_an_unfinished_run_but_keeps_its_job_cache(scope, finish):
    """Accepted jobs stay reusable; the job layer rechecks each against its new request."""
    first = lifecycle(scope)
    if finish == "failed":
        _fail(first)
    else:
        with first.hold():
            pass
    assert stored(scope)["status"] == finish
    with lifecycle(scope).hold() as fresh:
        assert fresh.state["run_id"] != first.state["run_id"]
        assert fresh.state["accounting"]["calls"] == 0
        assert not (fresh.directory / "context").exists()
        if finish == "failed":
            assert (fresh.directory / "jobs" / "job-000000000000000000000000.json").exists()


@pytest.mark.parametrize("extra", ["completed", "user-file", "malformed-state"])
def test_fresh_start_still_refuses_a_report_or_foreign_files(scope, extra):
    _fail(lifecycle(scope))
    preserved = scope.output / ".assessment-state.json"
    if extra == "completed":
        with lifecycle(scope, resume=True).hold() as state:
            (scope.output / "threat-model.md").write_text("report\n")
            state.complete(["threat-model.md"])
        (scope.output / "threat-model.md").unlink()
    elif extra == "user-file":
        preserved = scope.output / "notes.txt"
        preserved.write_text("preserve")
    else:
        preserved.write_text("not json")
    before = preserved.read_bytes()
    with pytest.raises(ExchangeError, match="choose another --output or empty this one"):
        with lifecycle(scope).hold():
            pytest.fail("A fresh start must not erase a report or foreign file")
    assert preserved.read_bytes() == before
    assert (scope.output / ".assessment-work").is_dir()


def test_fresh_start_does_not_follow_a_linked_work_directory(scope, tmp_path):
    first = lifecycle(scope)
    _fail(first)
    target = tmp_path / "external"
    target.mkdir()
    (target / "keep.txt").write_text("preserve")
    shutil.rmtree(first.directory)
    first.directory.symlink_to(target)
    with pytest.raises(ExchangeError, match="non-directory or link"):
        with lifecycle(scope).hold():
            pytest.fail("A linked work directory must not be cleared")
    assert (target / "keep.txt").read_text() == "preserve"


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


def _accept_job(scope, selector="one", usd=0.01):
    """Run one accepted job and return its receipt path."""

    class Host:
        def invoke(self, *args):
            return HostReply({"action": "complete", "reads": [], "artifact": {"ok": True}}, usd)

    with lifecycle(scope).hold() as state:
        jobs = AssessmentJobs(
            scope,
            state.directory / "jobs",
            state.budget,
            lambda role, ceiling: Host(),
            state.should_stop,
            state.checkpoint,
        )
        jobs.execute(
            role="recon_scanner",
            selector=selector,
            instructions="trusted",
            context={},
            schema={"type": "object"},
            allowed_sources=frozenset(),
            validate=lambda a, r: None,
        )
    (receipt,) = (state.directory / "jobs").glob("*.receipt.json")
    return receipt


def _rewrite_accounting(scope, calls, spent):
    state = stored(scope)
    state["accounting"].update(calls=calls, spent_usd=spent)
    (scope.output / ".assessment-state.json").write_text(json.dumps(state))


@pytest.mark.parametrize(("selector", "calls", "spent"), [("one", 0, 0.0), ("one", 1, 0.0), ("renamed", 0, 0.02)])
def test_resume_rejects_accounting_below_accepted_receipts(scope, selector, calls, spent):
    _accept_job(scope, selector, usd=0.02)
    _rewrite_accounting(scope, calls, spent)
    with pytest.raises(ExchangeError, match="below its accepted job receipts"):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Lowered accounting must not refund accepted calls")


@pytest.mark.parametrize("change", ["unreadable", "foreign-scope", "renamed-job", "link"])
def test_resume_rejects_unreadable_or_foreign_receipts(scope, tmp_path, change):
    receipt = _accept_job(scope)
    document = json.loads(receipt.read_text())
    if change == "unreadable":
        receipt.write_text("{not json")
    elif change == "foreign-scope":
        document["scope_sha256"] = "0" * 64
        receipt.write_text(json.dumps(document))
    elif change == "renamed-job":
        receipt.rename(receipt.with_name("job-" + "f" * 24 + ".receipt.json"))
    else:
        outside = tmp_path / "outside.json"
        outside.write_text(json.dumps(document))
        receipt.unlink()
        receipt.symlink_to(outside)
    with pytest.raises(ExchangeError):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Unverifiable receipts must not resume")


def test_resume_accepts_accounting_that_retains_extra_reservations(scope):
    _accept_job(scope, usd=0.01)
    # A failed call's reservation stays in state without a receipt.
    _rewrite_accounting(scope, 3, 0.11)
    with lifecycle(scope, resume=True).hold() as resumed:
        assert resumed.budget.calls == 3 and resumed.budget.spent_usd == pytest.approx(0.11)


def _completed(scope, **changes):
    with lifecycle(scope, **changes).hold() as state:
        (scope.output / "threat-model.md").write_text("report\n")
        state.complete(["threat-model.md"])


@pytest.mark.parametrize(
    "field,value,named",
    [
        ("runtime_sha256", "b" * 64, "the plugin version"),
        ("configuration", {"stride_model": "sonnet"}, "the assessment settings"),
    ],
)
def test_a_report_that_cannot_continue_names_why_a_new_scan_is_required(scope, field, value, named):
    _completed(scope)
    with pytest.raises(
        ExchangeError, match=f"cannot be continued because {named} changed.*new scan is required.*--rebuild"
    ):
        with lifecycle(scope, **{field: value}).hold():
            pytest.fail("A fresh start must not replace a report without --rebuild")
    assert (scope.output / "threat-model.md").read_text() == "report\n"
    # An unchanged completed run has nothing to continue either.
    with pytest.raises(ExchangeError, match="completed combined assessment.*--rebuild"):
        with lifecycle(scope).hold():
            pytest.fail("A fresh start must not replace a report without --rebuild")


def test_rebuild_replaces_only_an_earlier_run_that_owns_every_file(scope):
    _completed(scope)
    with lifecycle(scope, runtime_sha256="b" * 64, replace=True).hold() as fresh:
        assert fresh.state["status"] == "running"
        assert not (scope.output / "threat-model.md").exists()
        assert not (fresh.directory / "jobs").exists()


@pytest.mark.parametrize("extra", ["edited-report", "user-file"])
def test_rebuild_keeps_a_directory_with_edited_or_foreign_files(scope, extra):
    _completed(scope)
    kept = scope.output / ("threat-model.md" if extra == "edited-report" else "notes.txt")
    kept.write_text("mine\n")
    with pytest.raises(ExchangeError, match="did not write or that changed"):
        with lifecycle(scope, replace=True).hold():
            pytest.fail("--rebuild must not erase a user's file")
    assert kept.read_text() == "mine\n" and (scope.output / ".assessment-state.json").exists()
