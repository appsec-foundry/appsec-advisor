"""Secure-by-default .gitignore for the assessment output directory.

publish-threat-model calls itself "the deliberate counterpart to the
secure-by-default .gitignore", and the narrow redaction allowlist in
redact_known_secrets depends on intermediates never being published. Nothing
established that default, so a first assessment left artifacts such as
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

from ensure_output_gitignore import ensure  # noqa: E402
from publish_threat_model import patch_gitignore  # noqa: E402

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
    plain "docs/security/" form would disable every negation publish writes."""
    repo, out = _repo(tmp_path)
    ensure(out)
    lines = [ln.strip() for ln in (repo / ".gitignore").read_text().splitlines()]
    assert "docs/security/**" in lines
    assert "docs/security/" not in lines


def test_publish_can_lift_deliverables_out_of_the_default(tmp_path):
    """End-to-end: assessment ignores everything, publish makes exactly the
    named deliverables visible, intermediates stay ignored."""
    repo, out = _repo(tmp_path)
    ensure(out)
    assert _ignored(repo, "docs/security/threat-model.md")

    patch_gitignore(repo / ".gitignore", out, [out / name for name in DELIVERABLES])

    for name in DELIVERABLES:
        assert not _ignored(repo, f"docs/security/{name}"), f"{name} should be publishable"
    for name in INTERMEDIATES:
        assert _ignored(repo, f"docs/security/{name}"), f"{name} must stay ignored"

    subprocess.run(["git", "-C", str(repo), "add", "docs/security/"], check=True)
    staged = subprocess.run(
        ["git", "-C", str(repo), "diff", "--cached", "--name-only"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert sorted(staged) == sorted(f"docs/security/{n}" for n in DELIVERABLES)


@pytest.mark.parametrize("name", DELIVERABLES)
def test_publish_negations_carry_no_trailing_comment(tmp_path, name):
    """git only honours "#" as a comment at the start of a line. A trailing
    "  # published <date>" became part of the pattern, so the negation matched
    nothing and publishing silently did nothing."""
    repo, out = _repo(tmp_path)
    ensure(out)
    patch_gitignore(repo / ".gitignore", out, [out / name])
    for line in (repo / ".gitignore").read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("!") or (stripped and not stripped.startswith("#")):
            assert "#" not in stripped, f"pattern carries an inline comment: {line!r}"


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


def test_publish_honours_a_custom_output_directory(tmp_path):
    """patch_gitignore hardcoded "docs/security", so a run with --output wrote
    negations for a path that did not exist while the real output directory
    stayed ignored — leaving no way to publish at all."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    out = tmp_path / "reports" / "appsec"
    out.mkdir(parents=True)
    (out / "threat-model.md").write_text("deliverable")
    (out / ".recon-summary.md").write_text("raw credential")

    ensure(out)
    patch_gitignore(tmp_path / ".gitignore", out, [out / "threat-model.md"])

    assert not _ignored(tmp_path, "reports/appsec/threat-model.md")
    assert _ignored(tmp_path, "reports/appsec/.recon-summary.md")
    assert "docs/security" not in (tmp_path / ".gitignore").read_text()
