"""Secure-by-default .gitignore for the assessment output directory.

The narrow redaction allowlist in redact_known_secrets depends on
intermediates never being published. Nothing established that default, so a first assessment left artifacts such as
.recon-summary.md — which can carry a credential in cleartext — fully
committable.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from runtime.ensure_output_gitignore import ensure  # noqa: E402

DELIVERABLES = ("threat-model.md", "threat-model.yaml")
INTERMEDIATES = (
    ".recon-summary.md",
    ".threat-modeling-context.md",
    ".agent-run.log",
    ".stride-backend-api.json",
)


def _repo(tmp_path: Path, gitignore: str | None = None) -> tuple[Path, Path]:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True)
    for name in DELIVERABLES:
        (out / name).write_text("deliverable")
    for name in INTERMEDIATES:
        (out / name).write_text("raw credential")
    if gitignore is not None:
        (tmp_path / ".gitignore").write_text(gitignore)
    return tmp_path, out


def _ignored(repo: Path, rel: str) -> bool:
    return subprocess.run(["git", "-C", str(repo), "check-ignore", "-q", rel]).returncode == 0


def test_fresh_repo_ignores_the_output_directory(tmp_path):
    repo, out = _repo(tmp_path)
    assert ensure(out) is not None
    for name in INTERMEDIATES:
        assert _ignored(repo, f"docs/security/{name}"), name


@pytest.mark.parametrize("parts", [("docs", "security"), ("reports", "appsec", "latest")])
def test_an_output_directory_that_does_not_exist_yet_is_ignored(tmp_path, parts):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    assert ensure(tmp_path.joinpath(*parts))
    assert "/".join(parts) + "/**" in (tmp_path / ".gitignore").read_text().splitlines()
    assert not tmp_path.joinpath(*parts).exists()


def test_is_idempotent(tmp_path):
    repo, out = _repo(tmp_path)
    ensure(out)
    assert ensure(out) is None
    assert (repo / ".gitignore").read_text().count("docs/security/") == 1


def test_an_existing_user_rule_is_left_alone(tmp_path):
    repo, out = _repo(tmp_path, "docs/security/\n")
    assert ensure(out) is None
    assert (repo / ".gitignore").read_text() == "docs/security/\n"


def test_a_published_repo_is_not_re_ignored(tmp_path):
    """A negation means the user published deliberately. Appending the base rule
    after it would silently un-publish those files, because later rules win."""
    content = "docs/security/**\n!docs/security/threat-model.md\n"
    repo, out = _repo(tmp_path, content)
    assert ensure(out) is None
    assert (repo / ".gitignore").read_text() == content
    assert not _ignored(repo, "docs/security/threat-model.md")


def test_outside_a_git_work_tree_it_does_nothing(tmp_path):
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True)
    assert ensure(out) is None
    assert not (tmp_path / ".gitignore").exists()


def test_unrelated_rules_are_preserved(tmp_path):
    repo, out = _repo(tmp_path, "node_modules/\n*.log\n")
    ensure(out)
    text = (repo / ".gitignore").read_text()
    assert "node_modules/" in text and "*.log" in text


def test_uses_the_form_that_keeps_negations_working(tmp_path):
    """git cannot re-include a file whose parent directory is excluded, so the
    plain "docs/security/" form would disable an earlier publication's negations."""
    repo, out = _repo(tmp_path)
    ensure(out)
    lines = [ln.strip() for ln in (repo / ".gitignore").read_text().splitlines()]
    assert "docs/security/**" in lines
    assert "docs/security/" not in lines


LEGACY_PARTIAL = """\
# AppSec plugin intermediate files (auto-added by appsec-context-resolver)
docs/security/.stride-*.json
docs/security/.threat-modeling-context.md
docs/security/.appsec-lock
docs/security/.agent-run.log
"""


def test_a_partial_legacy_denylist_does_not_count_as_covered(tmp_path):
    """Earlier versions had the context-resolver agent append a fixed partial
    list. It never covered .recon-summary.md, which can hold a credential in
    cleartext, so it must not suppress the directory-wide default."""
    repo, out = _repo(tmp_path, LEGACY_PARTIAL)
    assert not _ignored(repo, "docs/security/.recon-summary.md")

    assert ensure(out) is not None
    assert _ignored(repo, "docs/security/.recon-summary.md")
    # the user's existing lines survive
    assert "docs/security/.stride-*.json" in (repo / ".gitignore").read_text()


def test_partial_rules_for_other_directories_are_ignored(tmp_path):
    repo, out = _repo(tmp_path, "docs/other/**\nbuild/\n")
    assert ensure(out) is not None
    assert _ignored(repo, "docs/security/.recon-summary.md")
