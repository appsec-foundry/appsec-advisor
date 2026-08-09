"""Tests for the shared recon-summary Markdown contract validator."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts import validate_recon_summary as validator

SCRIPT = Path(__file__).parent.parent / "scripts" / "validate_recon_summary.py"


def _valid_summary() -> str:
    return "\n".join(validator.required_headings()) + "\n"


def test_accepts_canonical_heading_sequence(tmp_path: Path):
    summary = tmp_path / ".recon-summary.md"
    summary.write_text(_valid_summary(), encoding="utf-8")

    assert validator.validate_recon_summary(summary) == len(validator.required_headings())


def test_rejects_missing_late_security_heading(tmp_path: Path):
    summary = tmp_path / ".recon-summary.md"
    summary.write_text(_valid_summary().replace("### 7.29 docker-compose Security\n", ""), encoding="utf-8")

    with pytest.raises(validator.ReconSummaryValidationError, match=r"security section 7\.29"):
        validator.validate_recon_summary(summary)


def test_rejects_old_cat_28_heading_in_canonical_7_28_slot(tmp_path: Path):
    summary = tmp_path / ".recon-summary.md"
    summary.write_text(
        _valid_summary().replace("### 7.28 Container Runtime Hardening", "### 7.28 AI Coding Assistant Configurations"),
        encoding="utf-8",
    )

    with pytest.raises(validator.ReconSummaryValidationError, match=r"security section 7\.28"):
        validator.validate_recon_summary(summary)


def test_rejects_reordered_security_headings(tmp_path: Path):
    summary = tmp_path / ".recon-summary.md"
    text = _valid_summary()
    text = text.replace(
        "### 7.29 docker-compose Security\n### 7.30 Artifact Signing & Provenance",
        "### 7.30 Artifact Signing & Provenance\n### 7.29 docker-compose Security",
    )
    summary.write_text(text, encoding="utf-8")

    with pytest.raises(validator.ReconSummaryValidationError, match=r"security section 7\.30"):
        validator.validate_recon_summary(summary)


def test_rejects_oversized_summary(tmp_path: Path):
    summary = tmp_path / ".recon-summary.md"
    summary.write_text(_valid_summary(), encoding="utf-8")

    with pytest.raises(validator.ReconSummaryValidationError, match="3-byte cap"):
        validator.validate_recon_summary(summary, max_bytes=3)


def test_rejects_excess_line_count(tmp_path: Path):
    summary = tmp_path / ".recon-summary.md"
    summary.write_text(_valid_summary(), encoding="utf-8")

    with pytest.raises(validator.ReconSummaryValidationError, match="1-line cap"):
        validator.validate_recon_summary(summary, max_lines=1)


def test_cli_reports_valid_and_invalid(tmp_path: Path):
    summary = tmp_path / ".recon-summary.md"
    summary.write_text(_valid_summary(), encoding="utf-8")
    valid = subprocess.run([sys.executable, str(SCRIPT), str(summary)], capture_output=True, text=True)
    assert valid.returncode == 0
    assert "VALID: recon-summary-markdown-v1" in valid.stdout

    summary.write_text("# Reconnaissance Summary\n", encoding="utf-8")
    invalid = subprocess.run([sys.executable, str(SCRIPT), str(summary)], capture_output=True, text=True)
    assert invalid.returncode == 1
    assert "INVALID: recon-summary-markdown-v1" in invalid.stderr


def test_repository_gate_accepts_existing_key_file_lines(tmp_path: Path):
    repo = tmp_path / "repo"
    source = repo / "routes" / "login.ts"
    source.parent.mkdir(parents=True)
    source.write_text("first\nsecond\n", encoding="utf-8")
    summary = tmp_path / ".recon-summary.md"
    summary.write_text(_valid_summary() + "**Key files:** routes/login.ts:2\n", encoding="utf-8")

    assert validator.validate_recon_summary(summary, repo_root=repo) == len(summary.read_text().splitlines())


def test_repository_gate_accepts_extensionless_root_file_and_none_text(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    summary = tmp_path / ".recon-summary.md"
    summary.write_text(
        _valid_summary() + "**Key files:** Dockerfile:1\n**Key files:** none detected\n",
        encoding="utf-8",
    )

    validator.validate_recon_summary(summary, repo_root=repo)


def test_repository_gate_rejects_unobserved_key_file(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    summary = tmp_path / ".recon-summary.md"
    summary.write_text(_valid_summary() + "**Key files:** routes/invented.ts:1\n", encoding="utf-8")

    with pytest.raises(validator.ReconSummaryValidationError, match="names a missing file"):
        validator.validate_recon_summary(summary, repo_root=repo)


def test_repository_gate_rejects_path_claim_without_line(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / "routes").mkdir(parents=True)
    (repo / "routes" / "login.ts").write_text("first\n", encoding="utf-8")
    summary = tmp_path / ".recon-summary.md"
    summary.write_text(_valid_summary() + "**Key files:** routes/login.ts\n", encoding="utf-8")

    with pytest.raises(validator.ReconSummaryValidationError, match="must be exactly one observed"):
        validator.validate_recon_summary(summary, repo_root=repo)


def test_repository_gate_rejects_out_of_range_key_file_line(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / "routes").mkdir(parents=True)
    (repo / "routes" / "login.ts").write_text("first\n", encoding="utf-8")
    summary = tmp_path / ".recon-summary.md"
    summary.write_text(_valid_summary() + "**Key files:** routes/login.ts:2\n", encoding="utf-8")

    with pytest.raises(validator.ReconSummaryValidationError, match="exceeds the file"):
        validator.validate_recon_summary(summary, repo_root=repo)


@pytest.mark.parametrize(
    "entry",
    [
        "routes/login.ts:1-2",
        "routes/login.ts:1 (login handler)",
        "routes/",
    ],
)
def test_repository_gate_rejects_non_exact_key_file_entries(tmp_path: Path, entry: str):
    repo = tmp_path / "repo"
    source = repo / "routes" / "login.ts"
    source.parent.mkdir(parents=True)
    source.write_text("first\nsecond\n", encoding="utf-8")
    summary = tmp_path / ".recon-summary.md"
    summary.write_text(_valid_summary() + f"**Key files:** {entry}\n", encoding="utf-8")

    with pytest.raises(validator.ReconSummaryValidationError, match="must be exactly one observed"):
        validator.validate_recon_summary(summary, repo_root=repo)


def test_key_file_normalizer_keeps_only_exact_existing_file_lines(tmp_path: Path):
    repo = tmp_path / "repo"
    source = repo / "routes" / "login.ts"
    source.parent.mkdir(parents=True)
    source.write_text("first\nsecond\n", encoding="utf-8")
    summary = tmp_path / ".recon-summary.md"
    summary.write_text(
        _valid_summary()
        + "**Key files:** `routes/login.ts:2`, `routes/login.ts:1-2`, `routes/`, `routes/missing.ts:1`\n"
        + "**Key files:** `routes/login.ts`\n",
        encoding="utf-8",
    )

    assert validator.normalize_key_file_references(summary, repo) == 2
    assert summary.read_text(encoding="utf-8").endswith(
        "**Key files:** `routes/login.ts:2`\n**Key files:** none detected\n"
    )
    validator.validate_recon_summary(summary, repo_root=repo)


def test_cli_key_file_normalizer_requires_repo_root(tmp_path: Path):
    summary = tmp_path / ".recon-summary.md"
    summary.write_text(_valid_summary(), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(summary), "--normalize-key-files"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "--normalize-key-files requires --repo-root" in result.stderr
