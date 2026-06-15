"""Tests for scripts/publish_threat_model.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

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
            + "\n",
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
        yaml_path = self._make_yaml(
            tmp_path,
            [
                {"t_id": "T-001", "title": "SQL Injection", "risk": "Critical"},
                {"t_id": "T-002", "title": "SSRF", "risk": "High"},
            ],
        )
        msg = ptm.build_commit_message(tmp_path, yaml_path, [tmp_path / "threat-model.md"])
        subject = msg.splitlines()[0]
        assert "v1.3" in subject
        assert "Critical" in subject
        assert "2 threats" in subject

    def test_metadata_top_uses_canonical_id(self, tmp_path):
        """Top-finding commit lines must come from canonical `id`, not legacy
        `t_id` — the final threat-model.yaml has no `t_id`, so the prior
        `t.get("t_id")` made these lines dead in every real run (TG-1, audit
        2026-06-11). Only Critical/High findings appear, capped at 2."""
        yaml_path = self._make_yaml(
            tmp_path,
            [
                {"id": "T-001", "title": "SQL Injection", "risk": "Critical"},
                {"id": "T-002", "title": "SSRF", "risk": "High"},
                {"id": "T-003", "title": "Verbose error", "risk": "Low"},
            ],
        )
        meta = ptm.extract_commit_metadata(yaml_path)
        assert meta["top"] == ["T-001 SQL Injection", "T-002 SSRF"]  # Low excluded

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

    def test_gh_nonzero_returncode_silent(self, tmp_path, monkeypatch):
        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="not a repo")

        monkeypatch.setattr(subprocess, "run", fake_run)
        is_public, msg = ptm.check_repo_visibility(tmp_path)
        assert not is_public
        assert msg == ""


# ---------------------------------------------------------------------------
# _git_root
# ---------------------------------------------------------------------------


class TestGitRoot:
    def test_returns_toplevel_on_success(self, tmp_path, monkeypatch):
        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="/repo/root\n", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert ptm._git_root(tmp_path) == Path("/repo/root")

    def test_returns_none_on_nonzero(self, tmp_path, monkeypatch):
        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, returncode=128, stdout="", stderr="not a git repo")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert ptm._git_root(tmp_path) is None

    def test_returns_none_when_git_missing(self, tmp_path, monkeypatch):
        def fake_run(cmd, **kwargs):
            raise FileNotFoundError("git not found")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert ptm._git_root(tmp_path) is None


# ---------------------------------------------------------------------------
# _print_results
# ---------------------------------------------------------------------------


class TestPrintResults:
    def _base(self):
        return {
            "blockers": [],
            "warnings": [],
            "files_to_publish": [],
            "gitignore_patched": False,
            "committed": False,
            "commit_message": "",
        }

    def test_json_output(self, capsys):
        results = self._base()
        results["files_to_publish"] = ["/x/threat-model.md"]
        ptm._print_results(results, as_json=True)
        out = capsys.readouterr().out
        import json

        parsed = json.loads(out)
        assert parsed["files_to_publish"] == ["/x/threat-model.md"]

    def test_blockers_printed(self, capsys):
        results = self._base()
        results["blockers"] = ["secrets detected"]
        ptm._print_results(results, as_json=False)
        out = capsys.readouterr().out
        assert "Publish blocked" in out
        assert "secrets detected" in out

    def test_warnings_and_files_and_patched(self, capsys):
        results = self._base()
        results["warnings"] = ["⚠ public repo"]
        results["files_to_publish"] = ["/x/threat-model.md"]
        results["gitignore_patched"] = True
        ptm._print_results(results, as_json=False)
        out = capsys.readouterr().out
        assert "public repo" in out
        assert "Files to publish" in out
        assert ".gitignore updated" in out

    def test_already_up_to_date_and_committed(self, capsys):
        results = self._base()
        results["gitignore_patched"] = False
        results["committed"] = True
        results["commit_message"] = "security: publish threat model v1.0\n\nbody"
        ptm._print_results(results, as_json=False)
        out = capsys.readouterr().out
        assert "already up-to-date" in out
        assert "Committed to git" in out
        assert "security: publish threat model v1.0" in out


# ---------------------------------------------------------------------------
# main() — full CLI flow
# ---------------------------------------------------------------------------


class TestMain:
    def _args(self, output_dir, repo_root, **flags):
        import argparse

        ns = argparse.Namespace(
            output_dir=Path(output_dir),
            repo_root=Path(repo_root),
            check_only=flags.get("check_only", False),
            commit=flags.get("commit", False),
            json_out=flags.get("json_out", False),
        )
        return ns

    def _patch_args(self, monkeypatch, ns):
        monkeypatch.setattr(ptm.argparse.ArgumentParser, "parse_args", lambda self: ns)

    def _write_yaml(self, output_dir):
        import yaml  # type: ignore

        data = {"meta": {"version": "1.0"}, "threats": [{"id": "T-001", "title": "X", "risk": "High"}]}
        (output_dir / "threat-model.yaml").write_text(yaml.dump(data))

    def test_missing_yaml_blocks(self, tmp_path, monkeypatch, capsys):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        # only md present, no yaml
        (out_dir / "threat-model.md").write_text("clean\n")
        ns = self._args(out_dir, tmp_path, json_out=True)
        self._patch_args(monkeypatch, ns)
        rc = ptm.main()
        assert rc == 1
        parsed = __import__("json").loads(capsys.readouterr().out)
        assert any("threat-model.yaml not found" in b for b in parsed["blockers"])

    def test_missing_md_blocks(self, tmp_path, monkeypatch, capsys):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        self._write_yaml(out_dir)
        ns = self._args(out_dir, tmp_path, json_out=True)
        self._patch_args(monkeypatch, ns)
        rc = ptm.main()
        assert rc == 1
        parsed = __import__("json").loads(capsys.readouterr().out)
        assert any("threat-model.md not found" in b for b in parsed["blockers"])

    def test_secret_in_md_blocks(self, tmp_path, monkeypatch, capsys):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        self._write_yaml(out_dir)
        (out_dir / "threat-model.md").write_text("password=supersecret123\n")
        ns = self._args(out_dir, tmp_path, json_out=True)
        self._patch_args(monkeypatch, ns)
        # avoid invoking real gh
        monkeypatch.setattr(ptm, "check_repo_visibility", lambda r: (False, ""))
        rc = ptm.main()
        assert rc == 1
        parsed = __import__("json").loads(capsys.readouterr().out)
        assert any("secrets detected" in b for b in parsed["blockers"])

    def test_check_only_returns_zero_and_lists_files(self, tmp_path, monkeypatch, capsys):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        self._write_yaml(out_dir)
        (out_dir / "threat-model.md").write_text("clean content\n")
        (out_dir / "threat-model.sarif.json").write_text("{}")
        ns = self._args(out_dir, tmp_path, check_only=True, json_out=True)
        self._patch_args(monkeypatch, ns)
        monkeypatch.setattr(ptm, "check_repo_visibility", lambda r: (False, ""))
        rc = ptm.main()
        assert rc == 0
        parsed = __import__("json").loads(capsys.readouterr().out)
        names = [Path(f).name for f in parsed["files_to_publish"]]
        assert "threat-model.md" in names
        assert "threat-model.yaml" in names
        assert "threat-model.sarif.json" in names
        # check-only must not patch
        assert parsed["gitignore_patched"] is False

    def test_warning_appended_for_public_repo(self, tmp_path, monkeypatch, capsys):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        self._write_yaml(out_dir)
        (out_dir / "threat-model.md").write_text("clean\n")
        ns = self._args(out_dir, tmp_path, check_only=True, json_out=True)
        self._patch_args(monkeypatch, ns)
        monkeypatch.setattr(ptm, "check_repo_visibility", lambda r: (True, "⚠ PUBLIC repo"))
        rc = ptm.main()
        assert rc == 0
        parsed = __import__("json").loads(capsys.readouterr().out)
        assert any("PUBLIC" in w for w in parsed["warnings"])

    def test_patches_gitignore_no_commit(self, tmp_path, monkeypatch, capsys):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        self._write_yaml(out_dir)
        (out_dir / "threat-model.md").write_text("clean\n")
        (tmp_path / ".gitignore").write_text("docs/security/\n")
        ns = self._args(out_dir, tmp_path, json_out=True)
        self._patch_args(monkeypatch, ns)
        monkeypatch.setattr(ptm, "check_repo_visibility", lambda r: (False, ""))
        # force git_root resolution to fall back to repo_root
        monkeypatch.setattr(ptm, "_git_root", lambda p: None)
        rc = ptm.main()
        assert rc == 0
        parsed = __import__("json").loads(capsys.readouterr().out)
        assert parsed["gitignore_patched"] is True
        assert parsed["committed"] is False
        assert "!docs/security/threat-model.md" in (tmp_path / ".gitignore").read_text()

    def test_commit_success(self, tmp_path, monkeypatch, capsys):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        self._write_yaml(out_dir)
        (out_dir / "threat-model.md").write_text("clean\n")
        (tmp_path / ".gitignore").write_text("docs/security/\n")
        ns = self._args(out_dir, tmp_path, commit=True, json_out=True)
        self._patch_args(monkeypatch, ns)
        monkeypatch.setattr(ptm, "check_repo_visibility", lambda r: (False, ""))
        monkeypatch.setattr(ptm, "_git_root", lambda p: None)

        calls = []

        def fake_run(cmd, cwd, check=True):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(ptm, "_run", fake_run)
        rc = ptm.main()
        assert rc == 0
        parsed = __import__("json").loads(capsys.readouterr().out)
        assert parsed["committed"] is True
        assert parsed["commit_message"].startswith("security: publish threat model")
        # git add + git commit were invoked
        assert any(c[:2] == ["git", "add"] for c in calls)
        assert any(c[:2] == ["git", "commit"] for c in calls)

    def test_commit_failure_returns_3(self, tmp_path, monkeypatch, capsys):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        self._write_yaml(out_dir)
        (out_dir / "threat-model.md").write_text("clean\n")
        (tmp_path / ".gitignore").write_text("docs/security/\n")
        ns = self._args(out_dir, tmp_path, commit=True, json_out=True)
        self._patch_args(monkeypatch, ns)
        monkeypatch.setattr(ptm, "check_repo_visibility", lambda r: (False, ""))
        monkeypatch.setattr(ptm, "_git_root", lambda p: None)

        def fake_run(cmd, cwd, check=True):
            if cmd[:2] == ["git", "commit"]:
                raise subprocess.CalledProcessError(1, cmd, stderr="nothing to commit")
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(ptm, "_run", fake_run)
        rc = ptm.main()
        assert rc == 3
        parsed = __import__("json").loads(capsys.readouterr().out)
        assert any("git commit failed" in b for b in parsed["blockers"])

    def test_non_json_text_output_path(self, tmp_path, monkeypatch, capsys):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        self._write_yaml(out_dir)
        (out_dir / "threat-model.md").write_text("clean\n")
        (tmp_path / ".gitignore").write_text("docs/security/\n")
        ns = self._args(out_dir, tmp_path, json_out=False)
        self._patch_args(monkeypatch, ns)
        monkeypatch.setattr(ptm, "check_repo_visibility", lambda r: (False, ""))
        monkeypatch.setattr(ptm, "_git_root", lambda p: None)
        rc = ptm.main()
        assert rc == 0
        out = capsys.readouterr().out
        assert "Files to publish" in out
