"""Tests for scripts/publish_threat_model.py."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import publish_threat_model as ptm


# ---------------------------------------------------------------------------
# Secret scanning
# ---------------------------------------------------------------------------

class TestScanForSecrets:
    def test_no_hits_on_clean_content(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("# Threat Model\n\nNo secrets here.\n")
        assert ptm.scan_for_secrets(md) == []

    def test_detects_password_assignment(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("config: password=supersecret123\n")
        hits = ptm.scan_for_secrets(md)
        assert len(hits) >= 1
        assert any("password" in h.lower() for h in hits)

    def test_detects_private_key_header(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("-----BEGIN RSA PRIVATE KEY-----\nABCDEF\n-----END RSA PRIVATE KEY-----\n")
        hits = ptm.scan_for_secrets(md)
        assert len(hits) >= 1

    def test_missing_file_returns_empty(self, tmp_path):
        assert ptm.scan_for_secrets(tmp_path / "nonexistent.md") == []


# ---------------------------------------------------------------------------
# .gitignore patching
# ---------------------------------------------------------------------------

class TestPatchGitignore:
    def _make_gitignore(self, tmp_path: Path, content: str) -> Path:
        gi = tmp_path / ".gitignore"
        gi.write_text(content)
        return gi

    def test_adds_negation_after_docs_security_line(self, tmp_path):
        gi = self._make_gitignore(tmp_path, "node_modules/\ndocs/security/\n")
        files = [tmp_path / "threat-model.md", tmp_path / "threat-model.yaml"]
        ptm.patch_gitignore(gi, tmp_path, files)
        text = gi.read_text()
        assert "!docs/security/threat-model.md" in text
        assert "!docs/security/threat-model.yaml" in text
        # negations appear after the ignore line, not before
        idx_ignore = text.index("docs/security/\n")
        idx_neg = text.index("!docs/security/threat-model.md")
        assert idx_neg > idx_ignore

    def test_idempotent(self, tmp_path):
        gi = self._make_gitignore(tmp_path, "docs/security/\n")
        files = [tmp_path / "threat-model.md"]
        ptm.patch_gitignore(gi, tmp_path, files)
        first = gi.read_text()
        ptm.patch_gitignore(gi, tmp_path, files)
        second = gi.read_text()
        assert first == second

    def test_never_publish_guards_added_once(self, tmp_path):
        gi = self._make_gitignore(tmp_path, "docs/security/\n")
        ptm.patch_gitignore(gi, tmp_path, [tmp_path / "threat-model.md"])
        text = gi.read_text()
        assert "never-publish guards" in text
        assert text.count("never-publish guards") == 1

    def test_pentest_tasks_always_in_never_list(self, tmp_path):
        gi = self._make_gitignore(tmp_path, "docs/security/\n")
        ptm.patch_gitignore(gi, tmp_path, [])
        text = gi.read_text()
        assert "pentest-tasks.yaml" in text

    def test_creates_gitignore_when_missing(self, tmp_path):
        gi = tmp_path / ".gitignore"
        ptm.patch_gitignore(gi, tmp_path, [tmp_path / "threat-model.md"])
        assert gi.exists()
        assert "!docs/security/threat-model.md" in gi.read_text()

    def test_returns_false_when_already_up_to_date(self, tmp_path):
        gi = self._make_gitignore(
            tmp_path,
            "docs/security/\n"
            "!docs/security/threat-model.md  # published 2026-01-01\n"
            "# appsec-advisor: never-publish guards (do not remove)\n"
            + "\n".join(f"docs/security/{n}  # never publish" for n in ptm.NEVER_PUBLISH)
            + "\n"
        )
        result = ptm.patch_gitignore(gi, tmp_path, [tmp_path / "threat-model.md"])
        assert result is False


# ---------------------------------------------------------------------------
# Commit message
# ---------------------------------------------------------------------------

class TestBuildCommitMessage:
    def _make_yaml(self, tmp_path: Path, threats: list[dict]) -> Path:
        import yaml  # type: ignore
        data = {
            "meta": {"version": "1.3", "schema_version": 1},
            "threats": threats,
            "mitigations": [],
            "components": [],
        }
        p = tmp_path / "threat-model.yaml"
        p.write_text(yaml.dump(data))
        return p

    def test_subject_contains_version_and_counts(self, tmp_path):
        yaml_path = self._make_yaml(tmp_path, [
            {"t_id": "T-001", "title": "SQL Injection", "risk": "Critical"},
            {"t_id": "T-002", "title": "SSRF", "risk": "High"},
        ])
        msg = ptm.build_commit_message(tmp_path, yaml_path, [tmp_path / "threat-model.md"])
        subject = msg.splitlines()[0]
        assert "v1.3" in subject
        assert "Critical" in subject
        assert "2 threats" in subject

    def test_body_mentions_related_repos(self, tmp_path):
        yaml_path = self._make_yaml(tmp_path, [])
        msg = ptm.build_commit_message(tmp_path, yaml_path, [])
        assert "related-repos.yaml" in msg

    def test_handles_missing_yaml_gracefully(self, tmp_path):
        msg = ptm.build_commit_message(tmp_path, tmp_path / "nonexistent.yaml", [])
        assert "security: publish threat model" in msg


# ---------------------------------------------------------------------------
# Repo visibility
# ---------------------------------------------------------------------------

class TestCheckRepoVisibility:
    def test_private_repo_no_warning(self, tmp_path, monkeypatch):
        def fake_run(cmd, **kwargs):
            r = subprocess.CompletedProcess(cmd, returncode=0, stdout="true\n", stderr="")
            return r
        monkeypatch.setattr(subprocess, "run", fake_run)
        is_public, msg = ptm.check_repo_visibility(tmp_path)
        assert not is_public
        assert msg == ""

    def test_public_repo_returns_warning(self, tmp_path, monkeypatch):
        def fake_run(cmd, **kwargs):
            r = subprocess.CompletedProcess(cmd, returncode=0, stdout="false\n", stderr="")
            return r
        monkeypatch.setattr(subprocess, "run", fake_run)
        is_public, msg = ptm.check_repo_visibility(tmp_path)
        assert is_public
        assert "PUBLIC" in msg

    def test_gh_unavailable_silent(self, tmp_path, monkeypatch):
        def fake_run(cmd, **kwargs):
            raise FileNotFoundError("gh not found")
        monkeypatch.setattr(subprocess, "run", fake_run)
        is_public, msg = ptm.check_repo_visibility(tmp_path)
        assert not is_public
        assert msg == ""
