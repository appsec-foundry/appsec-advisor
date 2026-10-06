"""The on-demand threat analysis and full assessments never touch each other's state."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from contexts import build_analyst_snapshot as snap  # noqa: E402
from runtime import analyst_state as st  # noqa: E402
from runtime.runtime_cleanup import run_cleanup  # noqa: E402

GIT_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}
SHA = "b" * 64


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env={**os.environ, **GIT_ENV})


def tree(path: Path) -> dict[str, str]:
    return {
        str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(path.rglob("*"))
        if p.is_file() and ".git" not in p.relative_to(path).parts
    }


@pytest.fixture
def workspace(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A repository with a live assessment output directory and an analyst state root."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "app.js").write_text("const a = 1;\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    assessment = repo / "threat-model-output"
    (assessment / ".progress").mkdir(parents=True)
    (assessment / ".fragments").mkdir()
    (assessment / ".appsec-lock").write_text(f"{os.getpid()} 1791100000 run-1\n")
    (assessment / "threat-model.yaml").write_text("meta: {}\n")
    (assessment / ".skill-config.json").write_text("{}\n")
    (assessment / ".progress" / "C-01.json").write_text("{}\n")
    (assessment / ".fragments" / "s1.md").write_text("fragment\n")
    return repo, assessment, tmp_path / "state"


def state(job_id: str, name: str, reason: str | None = None) -> dict:
    return {
        "schema_version": 1,
        "job_id": job_id,
        "state": name,
        "input_fingerprint": SHA,
        "counters": {"host_calls": 0, "evidence_rounds": 0, "question_rounds": 0, "transport_retries": 0},
        "pending_questions": [],
        "terminal_reason": reason,
        "updated_at": st.utc_now(),
    }


def request(job: st.Job, repo: Path, out: Path) -> dict:
    return {
        "schema_version": 1,
        "job_id": job.job_id,
        "mode": "review",
        "scope": {"kind": "worktree"},
        "repository": {"root": str(repo)},
        "output_dir": str(out),
        "packages": [],
        "limits": {
            "job_seconds": 900,
            "call_seconds": 300,
            "host_calls": 4,
            "evidence_rounds": 2,
            "question_rounds": 2,
            "transport_retries": 1,
            "admitted_files": 50,
            "file_kib": 64,
            "job_kib": 400,
            "response_kib": 64,
            "selected_questions": 40,
            "answer_hours": 72,
        },
        "plugin_version": "0.9.0",
        "requested_at": st.utc_now(),
    }


def test_analyst_jobs_leave_a_concurrent_assessment_untouched(workspace, tmp_path):
    repo, assessment, state_root = workspace
    (repo / "app.js").write_text("const a = 2;\n")
    before = tree(assessment)

    finished = st.create_job(repo, state_root)
    st.write_artifact(finished, "request.json", request(finished, repo, tmp_path / "out"))
    st.transition(finished, state(finished.job_id, "prepared"))
    snap.capture(request(finished, repo, tmp_path / "out"), finished)
    st.transition(finished, state(finished.job_id, "analyzing"))
    st.transition(finished, state(finished.job_id, "complete", "analysis_complete"))
    st.cleanup_temporaries(finished)

    cancelled = st.create_job(repo, state_root)
    st.transition(cancelled, state(cancelled.job_id, "prepared"))
    st.request_cancel(cancelled.root)
    st.transition(cancelled, state(cancelled.job_id, "cancelled", "cancelled_by_user"))
    st.discard_job(cancelled)

    crashed = st.create_job(repo, state_root)
    st.transition(crashed, state(crashed.job_id, "prepared"))
    st.release(crashed)
    assert st.recover_stale(repo, state_root) == [crashed.job_id]

    assert tree(assessment) == before
    assert state_root.resolve() not in repo.resolve().parents
    assert not any(p.name.startswith("aj-") for p in repo.rglob("*"))


def test_assessment_cleanup_cannot_remove_analyst_state(workspace):
    repo, assessment, state_root = workspace
    job = st.create_job(repo, state_root)
    st.transition(job, state(job.job_id, "prepared"))
    st.write_artifact(job, "result.md", "result\n")
    before = tree(job.root)

    report = run_cleanup(assessment, "all", keep_runtime_files=False, force=True)

    assert not (assessment / ".skill-config.json").exists(), report
    assert not (assessment / ".progress").exists(), report
    assert tree(job.root) == before
    assert st.read_artifact(job.root, "state.json")["state"] == "prepared"


def test_analyst_output_cannot_land_in_assessment_state(workspace):
    repo, assessment, state_root = workspace
    for target in (assessment, assessment / "analysis", assessment / ".progress"):
        assert any("assessment output" in error for error in st.check_output_dir(target, repo, state_root))


def test_importing_the_analyst_modules_creates_no_job(tmp_path):
    env = {**os.environ, "XDG_STATE_HOME": str(tmp_path / "xdg")}
    code = "import contexts.build_analyst_snapshot, runtime.analyst_state, validators.validate_analyst"
    subprocess.run([sys.executable, "-c", code], cwd=ROOT / "scripts", env=env, check=True)
    assert not (tmp_path / "xdg").exists()


def test_plugin_hooks_never_activate_the_analyst():
    hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    assert "analyst" not in json.dumps(hooks).lower()
