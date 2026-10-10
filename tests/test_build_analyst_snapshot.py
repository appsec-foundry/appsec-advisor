"""Frozen source views of the on-demand threat analysis."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from contexts import build_analyst_snapshot as snap  # noqa: E402
from runtime import analyst_state as st  # noqa: E402

GIT_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}
SECRET_LINE = "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"


def git(repo: Path, *args: str) -> str:
    env = {**os.environ, **GIT_ENV}
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env
    ).stdout.strip()


def commit(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "app.js").write_text("const a = 1;\n")
    (repo / "old.js").write_text("module.exports = 'rename me';\n")
    (repo / "gone.js").write_text("delete me\n")
    (repo / ".gitignore").write_text("ignored/\n*.log\n")
    commit(repo, "base")
    return repo


@pytest.fixture
def state_root(tmp_path: Path) -> Path:
    return tmp_path / "state"


def limits(**overrides) -> dict:
    values = {
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
    }
    values.update(overrides)
    return values


def request(job: st.Job, repo: Path, scope: dict, **limit_overrides) -> dict:
    return {
        "schema_version": 1,
        "job_id": job.job_id,
        "mode": "design" if scope["kind"] == "design" else "review",
        "scope": scope,
        "repository": {"root": str(repo)},
        "output_dir": str(repo.parent / "out"),
        "packages": [],
        "limits": limits(**limit_overrides),
        "plugin_version": "0.9.0",
        "requested_at": st.utc_now(),
    }


def admitted(snapshot: dict) -> dict[tuple[str, str], dict]:
    return {(e["side"], e["path"]): e for e in snapshot["admitted"]}


def excluded(snapshot: dict) -> dict[str, str]:
    return {e["path"]: e["reason"] for e in snapshot["excluded"] if "path" in e}


def captured(job: st.Job, side: str, path: str) -> bytes:
    return (job.root / "source" / side / path).read_bytes()


def test_commit_range_uses_the_merge_base_and_records_every_object(repo, state_root):
    git(repo, "checkout", "-q", "-b", "feature")
    (repo / "app.js").write_text("const a = 2;\n")
    (repo / "new.js").write_text("export const n = 1;\n")
    git(repo, "mv", "old.js", "renamed.js")
    (repo / "gone.js").unlink()
    head = commit(repo, "feature")
    git(repo, "checkout", "-q", "main")
    (repo / "main-only.js").write_text("later on main\n")
    base = commit(repo, "main moves on")
    fork = git(repo, "merge-base", base, head)

    job = st.create_job(repo, state_root)
    req = request(job, repo, {"kind": "commits", "base": "main", "head": "feature", "comparison": "merge_base"})
    snapshot = snap.capture(req, job)

    assert snapshot["objects"] == {"head": head, "base": base, "merge_base": fork}
    entries = admitted(snapshot)
    assert entries[("proposed", "app.js")]["change"] == "modified"
    assert captured(job, "baseline", "app.js") == b"const a = 1;\n"
    assert captured(job, "proposed", "app.js") == b"const a = 2;\n"
    assert entries[("proposed", "new.js")]["change"] == "added"
    assert entries[("baseline", "gone.js")]["change"] == "deleted"
    assert entries[("proposed", "renamed.js")]["previous_path"] == "old.js"
    assert ("proposed", "main-only.js") not in entries and ("baseline", "main-only.js") not in entries


def test_exact_comparison_includes_changes_on_the_base_branch(repo, state_root):
    git(repo, "checkout", "-q", "-b", "feature")
    (repo / "app.js").write_text("feature\n")
    commit(repo, "feature")
    git(repo, "checkout", "-q", "main")
    (repo / "main-only.js").write_text("later on main\n")
    commit(repo, "main")
    job = st.create_job(repo, state_root)
    req = request(job, repo, {"kind": "commits", "base": "main", "head": "feature", "comparison": "exact"})
    snapshot = snap.capture(req, job)
    assert "merge_base" not in snapshot["objects"]
    assert admitted(snapshot)[("baseline", "main-only.js")]["change"] == "deleted"


def test_staged_scope_reads_the_index_not_the_worktree(repo, state_root):
    (repo / "app.js").write_text("staged\n")
    git(repo, "add", "app.js")
    (repo / "app.js").write_text("unstaged\n")
    (repo / "untracked.js").write_text("not staged\n")
    job = st.create_job(repo, state_root)
    snapshot = snap.capture(request(job, repo, {"kind": "staged"}), job)
    assert captured(job, "proposed", "app.js") == b"staged\n"
    assert ("proposed", "untracked.js") not in admitted(snapshot)


def test_worktree_scope_covers_untracked_and_deleted_files_and_never_admits_ignored(repo, state_root):
    (repo / "app.js").write_text("unstaged change\n")
    (repo / "fresh.js").write_text("untracked addition\n")
    (repo / "gone.js").unlink()
    (repo / "ignored").mkdir()
    (repo / "ignored" / "secret.txt").write_text("never read\n")
    (repo / "debug.log").write_text("never read\n")
    job = st.create_job(repo, state_root)
    snapshot = snap.capture(request(job, repo, {"kind": "worktree"}), job)
    entries = admitted(snapshot)
    assert captured(job, "proposed", "app.js") == b"unstaged change\n"
    assert entries[("proposed", "fresh.js")]["change"] == "added"
    assert entries[("baseline", "gone.js")]["change"] == "deleted"
    assert not any("ignored" in p or p.endswith(".log") for _, p in entries)
    assert {"reason": "ignored", "count": 2} in snapshot["excluded"]
    assert not any("secret.txt" in e.get("path", "") or "debug.log" in e.get("path", "") for e in snapshot["excluded"])


def test_sensitive_binary_large_symlinked_and_nested_content_is_excluded(repo, state_root, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("outside the repository\n")
    (repo / ".env").write_text("TOKEN=x\n")
    (repo / "config.js").write_text(SECRET_LINE)
    (repo / "blob.bin").write_bytes(b"\0\1\2binary")
    (repo / "big.js").write_text("x" * (65 * 1024))
    (repo / "escape.js").symlink_to(outside)
    nested = repo / "vendor"
    nested.mkdir()
    git(nested, "init", "-q")
    (nested / "lib.js").write_text("nested\n")
    job = st.create_job(repo, state_root)
    snapshot = snap.capture(request(job, repo, {"kind": "worktree"}), job)
    assert excluded(snapshot) == {
        ".env": "sensitive",
        "blob.bin": "binary",
        "big.js": "too_large",
        "escape.js": "symlink",
        "vendor": "nested_repository",
    }
    assert not any(p for _, p in admitted(snapshot) if p in excluded(snapshot))
    assert admitted(snapshot)[("proposed", "config.js")]["redacted_lines"] == [1]
    assert "wJalrXUtnFEMI" not in str(snapshot)
    assert b"wJalrXUtnFEMI" not in captured(job, "proposed", "config.js")
    assert not (job.root / "source" / "proposed" / "escape.js").exists()


PEM_BODY = "MIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8\n"
PEM = "-----BEGIN RSA PRIVATE KEY-----\n" + PEM_BODY * 3 + "-----END RSA PRIVATE KEY-----"


@pytest.mark.parametrize(
    ("name", "body", "key_line"),
    [
        (
            "lib/signing.ts",
            "import jwt from 'jsonwebtoken'\nconst privateKey = `"
            + PEM
            + "`\nexport const sign = (claims) => jwt.sign(claims, privateKey, { algorithm: 'RS256' })\n",
            2,
        ),
        (
            "server/keys.py",
            'import jwt\n\nSIGNING_KEY = """'
            + PEM
            + '"""\n\n\ndef sign(claims):\n    return jwt.encode(claims, SIGNING_KEY, algorithm="RS256")\n',
            3,
        ),
    ],
)
def test_a_secret_value_is_redacted_and_the_surrounding_code_is_admitted(repo, state_root, name, body, key_line):
    """The code that uses a hard-coded key stays readable at its original line
    numbers; only the key itself never reaches the job."""
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
    (repo / name).write_text(body)
    job = st.create_job(repo, state_root)
    snapshot = snap.capture(request(job, repo, {"kind": "worktree"}), job)
    entry = admitted(snapshot)[("proposed", name)]
    text = captured(job, "proposed", name).decode()
    assert PEM_BODY.strip() not in text and "PRIVATE KEY" not in text
    assert text.count("\n") == body.count("\n")
    assert text.splitlines()[-1] == body.splitlines()[-1]
    assert entry["redacted_lines"][0] == key_line
    assert entry["sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert name not in excluded(snapshot)


def test_a_file_without_secrets_is_admitted_unchanged(repo, state_root):
    body = "const password = user.password?.replace(/./g, '*')\nexport default password\n"
    (repo / "mask.js").write_text(body)
    job = st.create_job(repo, state_root)
    snapshot = snap.capture(request(job, repo, {"kind": "worktree"}), job)
    assert "redacted_lines" not in admitted(snapshot)[("proposed", "mask.js")]
    assert captured(job, "proposed", "mask.js").decode() == body


def test_a_secret_the_redactor_cannot_remove_excludes_the_file(repo, state_root, monkeypatch):
    (repo / "config.js").write_text(SECRET_LINE)
    monkeypatch.setattr(snap, "_redact_secrets", lambda content: (None, []))
    job = st.create_job(repo, state_root)
    snapshot = snap.capture(request(job, repo, {"kind": "worktree"}), job)
    assert excluded(snapshot)["config.js"] == "sensitive"
    assert ("proposed", "config.js") not in admitted(snapshot)


def test_submodules_are_reported_not_followed(repo, state_root):
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{git(repo, 'rev-parse', 'HEAD')},sub")
    job = st.create_job(repo, state_root)
    snapshot = snap.capture(request(job, repo, {"kind": "staged"}), job)
    assert excluded(snapshot) == {"sub": "submodule"}


def test_limits_turn_further_files_into_recorded_exclusions(repo, state_root):
    for i in range(3):
        (repo / f"f{i}.js").write_text(f"file {i}\n")
    job = st.create_job(repo, state_root)
    snapshot = snap.capture(request(job, repo, {"kind": "worktree"}, admitted_files=2), job)
    assert len(snapshot["admitted"]) == 2
    assert list(excluded(snapshot).values()) == ["limit_reached"]


def test_repository_configuration_cannot_run_commands_during_capture(repo, state_root, tmp_path):
    marker = tmp_path / "marker"
    script = tmp_path / "hook.sh"
    script.write_text(f"#!/bin/sh\ntouch {marker}\ncat\n")
    script.chmod(0o755)
    for key, value in (
        ("diff.external", str(script)),
        ("core.fsmonitor", str(script)),
        ("core.hooksPath", str(tmp_path)),
        ("filter.evil.clean", str(script)),
        ("filter.evil.smudge", str(script)),
        ("diff.evil.textconv", str(script)),
    ):
        git(repo, "config", key, value)
    for hook in ("post-checkout", "post-index-change", "reference-transaction"):
        (tmp_path / hook).symlink_to(script)
    (repo / ".gitattributes").write_text("*.js filter=evil diff=evil\n")
    commit(repo, "attributes")
    (repo / "app.js").write_text("changed\n")
    git(repo, "add", "app.js")
    (repo / "app.js").write_text("changed again\n")
    marker.unlink(missing_ok=True)
    for scope in (
        {"kind": "worktree"},
        {"kind": "staged"},
        {"kind": "commits", "base": "HEAD~1", "head": "HEAD", "comparison": "exact"},
    ):
        job = st.create_job(repo, state_root)
        snap.capture(request(job, repo, scope), job)
    assert not marker.exists()
    git(repo, "diff")  # control: an unhardened read does run the configured command
    assert marker.exists()


def test_capture_leaves_the_repository_unchanged(repo, state_root):
    (repo / "app.js").write_text("changed\n")
    before = {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()}
    job = st.create_job(repo, state_root)
    snap.capture(request(job, repo, {"kind": "worktree"}), job)
    assert {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize(
    ("scope", "message"),
    [
        ({"kind": "commits", "base": "-oProxyCommand=x", "head": "HEAD", "comparison": "exact"}, "must not start"),
        ({"kind": "commits", "base": "does-not-exist", "head": "HEAD", "comparison": "exact"}, "rev-parse failed"),
    ],
)
def test_invalid_revisions_fail_visibly(repo, state_root, scope, message):
    job = st.create_job(repo, state_root)
    with pytest.raises(snap.SnapshotError, match=message):
        snap.capture(request(job, repo, scope), job)


def test_unrelated_histories_fail_instead_of_falling_back(repo, state_root):
    git(repo, "checkout", "-q", "--orphan", "island")
    (repo / "island.js").write_text("island\n")
    commit(repo, "island")
    job = st.create_job(repo, state_root)
    scope = {"kind": "commits", "base": "main", "head": "island", "comparison": "merge_base"}
    with pytest.raises(snap.SnapshotError, match="share no history"):
        snap.capture(request(job, repo, scope), job)


def test_a_file_changing_during_capture_rejects_the_snapshot(repo, state_root, monkeypatch):
    (repo / "app.js").write_text("first state\n")
    real = snap._read_worktree

    def racing(repository, path):
        (repository / path).write_text("second state\n")
        return real(repository, path)

    monkeypatch.setattr(snap, "_read_worktree", racing)
    job = st.create_job(repo, state_root)
    with pytest.raises(snap.SnapshotError, match="changed during capture"):
        snap.capture(request(job, repo, {"kind": "worktree"}), job)


def test_design_scopes_bind_the_exact_content(repo, state_root, tmp_path):
    text = "Support staff export customer data."
    digest = hashlib.sha256(text.encode()).hexdigest()
    job = st.create_job(repo, state_root)
    snapshot = snap.capture(
        request(job, repo, {"kind": "design", "source": "text", "content_sha256": digest}), job, text
    )
    assert snapshot["objects"] == {"design_sha256": digest} and snapshot["admitted"] == []
    job = st.create_job(repo, state_root)
    with pytest.raises(snap.SnapshotError, match="does not match"):
        snap.capture(
            request(job, repo, {"kind": "design", "source": "text", "content_sha256": digest}), job, text + "!"
        )
    real = tmp_path / "design.md"
    real.write_text(text)
    (tmp_path / "link.md").symlink_to(real)
    job = st.create_job(repo, state_root)
    scope = {"kind": "design", "source": "file", "content_sha256": digest, "design_path": str(tmp_path / "link.md")}
    with pytest.raises(OSError):
        snap.capture(request(job, repo, scope), job)


def test_context_admission_reads_only_the_frozen_view(repo, state_root):
    (repo / "app.js").write_text("changed\n")
    job = st.create_job(repo, state_root)
    req = request(job, repo, {"kind": "worktree"})
    snapshot = snap.capture(req, job)
    updated = snap.admit_context(req, job, snapshot, "old.js")
    assert admitted(updated)[("proposed", "old.js")]["change"] == "context"
    with pytest.raises(snap.SnapshotError, match="already admitted"):
        snap.admit_context(req, job, updated, "old.js")
    with pytest.raises(snap.SnapshotError, match="outside the captured view"):
        snap.admit_context(req, job, updated, "../etc/passwd")
    (repo / "gone.js").write_text("edited after capture\n")
    with pytest.raises(snap.SnapshotError, match="changed since capture"):
        snap.admit_context(req, job, updated, "gone.js")


def test_committed_context_comes_from_the_head_commit(repo, state_root):
    git(repo, "checkout", "-q", "-b", "feature")
    (repo / "app.js").write_text("feature\n")
    commit(repo, "feature")
    (repo / "old.js").write_text("uncommitted worktree edit\n")
    job = st.create_job(repo, state_root)
    req = request(job, repo, {"kind": "commits", "base": "main", "head": "feature", "comparison": "merge_base"})
    snapshot = snap.admit_context(req, job, snap.capture(req, job), "old.js")
    assert captured(job, "proposed", "old.js") == b"module.exports = 'rename me';\n"
    assert admitted(snapshot)[("proposed", "old.js")]["change"] == "context"


@pytest.mark.parametrize("path", ["../x", "/etc/passwd", "a/../../b", "./a", "a\nb", ""])
def test_paths_from_git_are_never_trusted_for_writes(path):
    assert not snap._safe_path(path)
    assert snap._safe_path("src/app.js")


def test_design_input_is_bounded_and_scanned(repo, state_root):
    secret = "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    job = st.create_job(repo, state_root)
    scope = {"kind": "design", "source": "text", "content_sha256": hashlib.sha256(secret.encode()).hexdigest()}
    with pytest.raises(snap.SnapshotError, match="secret"):
        snap.capture(request(job, repo, scope), job, secret)
    big = "x" * (65 * 1024)
    job = st.create_job(repo, state_root)
    scope = {"kind": "design", "source": "text", "content_sha256": hashlib.sha256(big.encode()).hexdigest()}
    with pytest.raises(snap.SnapshotError, match="size limit"):
        snap.capture(request(job, repo, scope), job, big)


@pytest.mark.parametrize("folder", ["service", "modules/api"])
def test_hypothesis_snapshot_reads_only_selected_commit_paths(repo, state_root, folder):
    selected = repo / folder
    selected.mkdir(parents=True)
    (selected / "route.py").write_text("return records.read()\n")
    revision = commit(repo, "selected code")
    (selected / "route.py").write_text("uncommitted change\n")
    (selected / "untracked.py").write_text("not committed\n")
    job = st.create_job(repo, state_root)
    try:
        req = request(job, repo, {"kind": "hypothesis", "revision": revision, "paths": [folder]})
        req.update(mode="hypothesis", hypothesis="Can records escape their owner?")
        result = snap.capture(req, job)
        assert result["objects"] == {"head": revision}
        assert set(admitted(result)) == {("proposed", f"{folder}/route.py")}
        assert captured(job, "proposed", f"{folder}/route.py") == b"return records.read()\n"
        with pytest.raises(snap.SnapshotError, match="outside the captured view"):
            snap.admit_context(req, job, result, "app.js")
    finally:
        st.release(job)


def test_hypothesis_snapshot_excludes_unsafe_and_oversized_sources(repo, state_root):
    area = repo / "area"
    area.mkdir()
    (area / "ok.py").write_text("return record\n")
    (area / "link").symlink_to("../app.js")
    (area / "large.py").write_text("x" * 2048)
    (area / "binary").write_bytes(b"\x00binary")
    (area / ".env").write_text("PRIVATE_CONFIGURATION=synthetic\n")
    revision = commit(repo, "admission cases")
    job = st.create_job(repo, state_root)
    try:
        req = request(job, repo, {"kind": "hypothesis", "revision": revision, "paths": ["area"]}, file_kib=1)
        req.update(mode="hypothesis", hypothesis="Check access to records.")
        result = snap.capture(req, job)
        assert set(admitted(result)) == {("proposed", "area/ok.py")}
        assert excluded(result) == {
            "area/link": "symlink",
            "area/large.py": "too_large",
            "area/binary": "binary",
            "area/.env": "sensitive",
        }
    finally:
        st.release(job)
