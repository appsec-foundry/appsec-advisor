"""Tests for the deterministic §7.11 supply-chain scorecard.

Focus: the ecosystem-parametric false-negative bugfixes (F1 GitLab pinning,
F6 uv.lock, F7 Java Gradle locking/verification) from
docs/analysis-supply-chain-coverage-improvement.md. Before the fix, each of
these scored MISSING despite a *good* posture.
"""
from __future__ import annotations

import assess_supply_chain_controls as asc


# --- F6: uv.lock is a valid lockfile -----------------------------------------

def test_uv_lock_credited_as_lockfile(tmp_path):
    (tmp_path / "uv.lock").write_text("# uv lockfile\n", encoding="utf-8")
    result = asc._eval_lockfile("", str(tmp_path))
    assert result["effectiveness"] == asc.ADEQUATE


def test_requirements_lock_credited(tmp_path):
    (tmp_path / "requirements.lock").write_text("flask==3.0.0\n", encoding="utf-8")
    assert asc._eval_lockfile("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


# --- F7: Java Gradle locking / verification ----------------------------------

def test_gradle_lockfile_credited(tmp_path):
    (tmp_path / "gradle.lockfile").write_text("org.foo:bar:1.0\n", encoding="utf-8")
    assert asc._eval_lockfile("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


def test_gradle_verification_metadata_credited(tmp_path):
    gdir = tmp_path / "gradle"
    gdir.mkdir()
    (gdir / "verification-metadata.xml").write_text(
        "<verification-metadata/>", encoding="utf-8")
    assert asc._eval_lockfile("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


def test_gradle_verify_locks_is_deterministic_ci_install():
    recon = "CI runs: ./gradlew build --verify-locks"
    assert asc._eval_ci_install(recon)["effectiveness"] == asc.ADEQUATE


def test_maven_strict_checksums_is_deterministic_ci_install():
    recon = "CI runs: mvn --strict-checksums verify"
    assert asc._eval_ci_install(recon)["effectiveness"] == asc.ADEQUATE


def test_no_lockfile_still_missing(tmp_path):
    assert asc._eval_lockfile("", str(tmp_path))["effectiveness"] == asc.MISSING


# --- F1: GitLab CI image digest-pinning --------------------------------------

def test_gitlab_digest_pinned_image_adequate(tmp_path):
    digest = "a" * 64
    (tmp_path / ".gitlab-ci.yml").write_text(
        f"build:\n  image: node@sha256:{digest}\n  script: [make]\n",
        encoding="utf-8")
    result = asc._eval_action_pinning("", str(tmp_path))
    assert result["effectiveness"] == asc.ADEQUATE


def test_gitlab_mutable_tag_image_missing(tmp_path):
    (tmp_path / ".gitlab-ci.yml").write_text(
        "build:\n  image: node:18\n  script: [make]\n", encoding="utf-8")
    result = asc._eval_action_pinning("", str(tmp_path))
    assert result["effectiveness"] == asc.MISSING


def test_gitlab_mixed_images_partial(tmp_path):
    digest = "b" * 64
    (tmp_path / ".gitlab-ci.yml").write_text(
        f"a:\n  image: node@sha256:{digest}\nb:\n  image: python:3.12\n",
        encoding="utf-8")
    result = asc._eval_action_pinning("", str(tmp_path))
    assert result["effectiveness"] == asc.PARTIAL


def test_no_ci_references_missing(tmp_path):
    result = asc._eval_action_pinning("", str(tmp_path))
    assert result["effectiveness"] == asc.MISSING
    assert "GitLab" in result["reason"]


# --- regression: GitHub Actions path still graded ----------------------------

def test_github_sha_pinned_still_adequate(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sha = "c" * 40
    (wf / "ci.yml").write_text(
        f"jobs:\n  b:\n    steps:\n      - uses: actions/checkout@{sha}\n",
        encoding="utf-8")
    assert asc._eval_action_pinning("", str(tmp_path))["effectiveness"] == asc.ADEQUATE


def test_github_mutable_tag_still_missing(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8")
    assert asc._eval_action_pinning("", str(tmp_path))["effectiveness"] == asc.MISSING
