"""
Tests for scripts/security_relevance_filter.py

Tests the three-tier classification logic:
  Tier 1 — path/extension-based (no diff needed)
  Tier 2 — diff content pattern matching
  Tier 3 — structural signals in diff content

Also tests the CLI entry point and the classify_files aggregation.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).parent.parent
PLUGIN = ROOT

sys.path.insert(0, str(PLUGIN / "scripts"))
import security_relevance_filter as srf  # noqa: E402
from security_relevance_filter import (
    classify_by_diff,
    classify_by_path,
    classify_files,
    main,
)

# =========================================================================
# Tier 1: Path-based classification
# =========================================================================


class TestClassifyByPath:
    """Tests for extension/filename/path-segment classification."""

    # --- Irrelevant by extension ---

    @pytest.mark.parametrize(
        "path",
        [
            "src/components/Button.css",
            "docs/README.md",
            "CHANGELOG.txt",
            "locales/en.po",
            "src/app.scss",
            "assets/logo.png",
            "fonts/Inter.woff2",
            "src/snapshot.snap",
        ],
    )
    def test_irrelevant_extensions(self, path: str):
        decision, reasons = classify_by_path(path)
        assert decision is False, f"{path} should be irrelevant"
        # Accept the legacy ext:/name: reasons or the new scan_excludes
        # reason emitted by the centralised loader (Sprint 1 Item F).
        assert any(r.startswith("ext:") or r.startswith("name:") or r == "scan_excludes" for r in reasons), (
            f"no recognised reason in {reasons!r}"
        )

    # --- Irrelevant by exact name ---

    @pytest.mark.parametrize(
        "path",
        [
            "LICENSE",
            ".editorconfig",
            ".prettierrc",
            ".gitignore",
            "jest.config.js",
        ],
    )
    def test_irrelevant_names(self, path: str):
        decision, reasons = classify_by_path(path)
        assert decision is False, f"{path} should be irrelevant"

    # --- Irrelevant: test files ---

    @pytest.mark.parametrize(
        "path",
        [
            "test_auth.py",
            "src/auth.test.js",
            "tests/integration/test_login.py",
            "spec/auth.spec.ts",
            "__tests__/Login.test.tsx",
        ],
    )
    def test_irrelevant_test_files(self, path: str):
        decision, reasons = classify_by_path(path)
        assert decision is False, f"{path} should be irrelevant (test file)"

    # --- Always relevant: manifests ---

    @pytest.mark.parametrize(
        "path",
        [
            "package.json",
            "backend/requirements.txt",
            "services/auth/Dockerfile",
            "deploy/Dockerfile.prod",
            "go.mod",
        ],
    )
    def test_relevant_manifests(self, path: str):
        decision, reasons = classify_by_path(path)
        assert decision is True, f"{path} should be relevant"

    # --- Always relevant: IaC & workflows ---

    @pytest.mark.parametrize(
        "path",
        [
            "terraform/main.tf",
            "k8s/deployment.yaml",
            ".github/workflows/deploy.yml",
            "docker-compose.yml",
            "ansible/playbook.yaml",
        ],
    )
    def test_relevant_iac_workflows(self, path: str):
        decision, reasons = classify_by_path(path)
        assert decision is True, f"{path} should be relevant"

    # --- Always relevant: env files ---

    def test_relevant_env_file(self):
        decision, reasons = classify_by_path(".env.production")
        assert decision is True

    def test_relevant_key_extension_and_workflow_reason(self):
        decision, reasons = classify_by_path("certs/server.pem")
        assert decision is True
        assert "ext:.pem" in reasons

        decision, reasons = classify_by_path(".github/workflows/deploy.yml")
        assert decision is True
        assert reasons == ["iac:.github/workflows/deploy.yml"]

    def test_scan_excludes_whitelist_and_error_fallback(self, monkeypatch):
        monkeypatch.setattr(srf, "_SCAN_EXCLUDES_AVAILABLE", True)
        monkeypatch.setattr(srf, "_scan_is_always_included", lambda _path: True)
        monkeypatch.setattr(srf, "_scan_is_excluded", lambda _path: False)
        assert classify_by_path("docs/security-notes.adoc") == (True, ["whitelist:security-notes.adoc"])

        def boom(_path):
            raise RuntimeError("bad exclude config")

        monkeypatch.setattr(srf, "_scan_is_always_included", boom)
        monkeypatch.setattr(srf, "_scan_is_excluded", boom)
        assert classify_by_path(".vscode/settings.json") == (False, ["ide_dir:.vscode"])

    # --- Always relevant: security path segments ---

    @pytest.mark.parametrize(
        "path",
        [
            "src/auth/login.py",
            "lib/security/validator.js",
            "pkg/crypto/aes.go",
            "app/middleware/cors.ts",
            "src/permissions/check.py",
        ],
    )
    def test_relevant_path_segments(self, path: str):
        decision, reasons = classify_by_path(path)
        assert decision is True, f"{path} should be relevant (security path segment)"

    # --- Undecided: needs diff analysis ---

    @pytest.mark.parametrize(
        "path",
        [
            "src/server.py",
            "lib/utils.js",
            "app/controllers/user.go",
            "src/api/handler.ts",
        ],
    )
    def test_undecided_needs_diff(self, path: str):
        decision, _ = classify_by_path(path)
        assert decision is None, f"{path} should be undecided (needs diff)"

    def test_test_directory_fallback_when_scan_excludes_disabled(self, monkeypatch):
        monkeypatch.setattr(srf, "_SCAN_EXCLUDES_AVAILABLE", False)
        assert classify_by_path("tests/helpers/factory.py") == (False, ["test_dir"])


# =========================================================================
# Tier 2+3: Diff content classification
# =========================================================================


class TestClassifyByDiff:
    """Tests for diff content pattern matching."""

    def test_auth_pattern(self):
        diff = "+    if user.authenticate(password):\n+        return create_token(user)"
        relevant, reasons = classify_by_diff(diff)
        assert relevant is True
        assert any("auth" in r for r in reasons)

    def test_sql_pattern(self):
        diff = '+    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        relevant, reasons = classify_by_diff(diff)
        assert relevant is True
        assert any("sql" in r or "db_access" in r for r in reasons)

    def test_crypto_pattern(self):
        diff = "+    encrypted = aes.encrypt(plaintext, key)"
        relevant, reasons = classify_by_diff(diff)
        assert relevant is True
        assert any("crypto" in r for r in reasons)

    def test_route_pattern(self):
        diff = '+    @app.route("/api/users", methods=["POST"])'
        relevant, reasons = classify_by_diff(diff)
        assert relevant is True
        assert any("route" in r for r in reasons)

    def test_cors_pattern(self):
        diff = "+    response.headers['Access-Control-Allow-Origin'] = '*'"
        relevant, reasons = classify_by_diff(diff)
        assert relevant is True

    def test_env_var_structural(self):
        diff = "+    db_url = os.environ['DATABASE_URL']"
        relevant, reasons = classify_by_diff(diff)
        assert relevant is True
        assert any("structural:" in r for r in reasons)

    def test_middleware_structural(self):
        diff = "+    app.use(helmet())"
        relevant, reasons = classify_by_diff(diff)
        assert relevant is True

    def test_security_import_structural(self):
        diff = "+from cryptography.fernet import Fernet"
        relevant, reasons = classify_by_diff(diff)
        assert relevant is True
        assert any("structural:" in r for r in reasons)

    def test_pure_comment_irrelevant(self):
        diff = "+    # This function handles user display preferences\n+    # Updated formatting for readability"
        relevant, reasons = classify_by_diff(diff)
        assert relevant is False

    def test_pure_logging_irrelevant(self):
        diff = '+    logger.info("Processing batch job %d", batch_id)\n+    print(f"Done: {count} items")'
        relevant, reasons = classify_by_diff(diff)
        assert relevant is False

    def test_empty_diff(self):
        relevant, reasons = classify_by_diff("")
        assert relevant is False

    def test_only_removed_lines(self):
        diff = "--- a/src/app.py\n+++ b/src/app.py\n-    old_code()\n-    more_old()"
        relevant, reasons = classify_by_diff(diff)
        assert relevant is False
        assert "no_added_lines" in reasons

    def test_ui_text_change_irrelevant(self):
        diff = "+    return <h1>Welcome to our updated platform</h1>"
        relevant, reasons = classify_by_diff(diff)
        assert relevant is False

    def test_xss_pattern(self):
        diff = "+    element.innerHTML = userInput;"
        relevant, reasons = classify_by_diff(diff)
        assert relevant is True
        assert any("xss" in r for r in reasons)

    def test_file_upload_pattern(self):
        diff = "+    const uploaded = await uploadFile(req.file);"
        relevant, reasons = classify_by_diff(diff)
        assert relevant is True

    def test_permission_check(self):
        diff = '+    if not user.has_permission("admin"):'
        relevant, reasons = classify_by_diff(diff)
        assert relevant is True


# =========================================================================
# Git helpers and semantic-diff helpers
# =========================================================================


class _RunResult:
    def __init__(self, stdout: str = "", returncode: int = 0):
        self.stdout = stdout
        self.returncode = returncode


class TestGitHelpers:
    def test_get_diff_for_file_combines_baseline_and_worktree_diffs(self, monkeypatch):
        calls: list[list[str]] = []
        results = [_RunResult("baseline diff\n"), _RunResult("worktree diff\n")]

        def fake_run(cmd, **_kwargs):
            calls.append(cmd)
            return results.pop(0)

        monkeypatch.setattr(srf.subprocess, "run", fake_run)

        assert srf.get_diff_for_file("/repo", "abc123", "src/app.py") == "baseline diff\n\nworktree diff\n"
        assert calls[0][4] == "abc123..HEAD"
        assert calls[1][4] == "HEAD"

    def test_get_diff_for_file_and_git_show_are_conservative_on_errors(self, monkeypatch):
        def timeout(*_args, **_kwargs):
            raise subprocess.TimeoutExpired(cmd="git", timeout=10)

        monkeypatch.setattr(srf.subprocess, "run", timeout)

        assert srf.get_diff_for_file("/repo", None, "src/app.py") == ""
        assert srf._git_show_blob("/repo", "HEAD", "src/app.py") is None

    def test_git_show_blob_returns_stdout_and_none_on_nonzero(self, monkeypatch):
        monkeypatch.setattr(srf.subprocess, "run", lambda *_args, **_kwargs: _RunResult("content", 0))
        assert srf._git_show_blob("/repo", "HEAD", "package.json") == "content"

        monkeypatch.setattr(srf.subprocess, "run", lambda *_args, **_kwargs: _RunResult("", 1))
        assert srf._git_show_blob("/repo", "HEAD", "missing.txt") is None

    def test_get_changed_files_merges_baseline_and_worktree(self, monkeypatch):
        results = [_RunResult("a.py\nb.py\n"), _RunResult("b.py\nc.py\n")]

        def fake_run(*_args, **_kwargs):
            return results.pop(0)

        monkeypatch.setattr(srf.subprocess, "run", fake_run)

        assert srf.get_changed_files("/repo", "abc123") == ["a.py", "b.py", "c.py"]

    def test_get_changed_files_ignores_git_errors(self, monkeypatch):
        monkeypatch.setattr(srf.subprocess, "run", lambda *_args, **_kwargs: _RunResult("ignored.py\n", 1))
        assert srf.get_changed_files("/repo", None) == []

        def boom(*_args, **_kwargs):
            raise OSError("git unavailable")

        monkeypatch.setattr(srf.subprocess, "run", boom)
        assert srf.get_changed_files("/repo", "abc123") == []

    def test_whitespace_only_diff_handles_baseline_and_errors(self, monkeypatch):
        results = [_RunResult("", 0), _RunResult("", 0)]
        monkeypatch.setattr(srf.subprocess, "run", lambda *_args, **_kwargs: results.pop(0))
        assert srf._whitespace_only_diff("/repo", "abc123", "src/app.py") is True

        monkeypatch.setattr(srf.subprocess, "run", lambda *_args, **_kwargs: _RunResult("", 1))
        assert srf._whitespace_only_diff("/repo", "abc123", "src/app.py") is False

        results = [_RunResult("real baseline diff", 0)]
        monkeypatch.setattr(srf.subprocess, "run", lambda *_args, **_kwargs: results.pop(0))
        assert srf._whitespace_only_diff("/repo", "abc123", "src/app.py") is False

        monkeypatch.setattr(srf.subprocess, "run", lambda *_args, **_kwargs: _RunResult("real diff", 0))
        assert srf._whitespace_only_diff("/repo", None, "src/app.py") is False

        monkeypatch.setattr(srf.subprocess, "run", lambda *_args, **_kwargs: _RunResult("", 1))
        assert srf._whitespace_only_diff("/repo", None, "src/app.py") is False

        def boom(*_args, **_kwargs):
            raise OSError("git unavailable")

        monkeypatch.setattr(srf.subprocess, "run", boom)
        assert srf._whitespace_only_diff("/repo", None, "src/app.py") is False


class TestSemanticDiffHelpers:
    def test_package_json_security_key_details(self):
        before = json.dumps(
            {
                "name": "app",
                "dependencies": {"a": "1", "b": "1", "old": "1"},
                "scripts": {"start": "node app.js"},
            }
        )
        after = json.dumps(
            {
                "name": "renamed",
                "dependencies": {"a": "2", "b": "1", "c": "1", "d": "1", "e": "1", "f": "1"},
                "scripts": {"start": "node server.js"},
            }
        )

        verdict, details = srf._has_security_relevant_package_json_change(before, after)

        assert verdict is True
        assert any(d.startswith("dependencies:") for d in details)
        assert "scripts:~start" in details

    def test_package_json_metadata_only_and_parse_fallbacks(self):
        before = json.dumps({"name": "app", "version": "1.0.0"})
        after = json.dumps({"name": "app2", "version": "1.0.1"})
        assert srf._has_security_relevant_package_json_change(before, after) == (False, [])
        assert srf._has_security_relevant_package_json_change(None, after) == (None, [])
        assert srf._has_security_relevant_package_json_change("{bad", after) == (None, [])
        assert srf._has_security_relevant_package_json_change("[]", "[]") == (None, [])
        assert srf._has_security_relevant_package_json_change(
            json.dumps({"type": "commonjs"}),
            json.dumps({"type": "module"}),
        ) == (True, ["type"])

    def test_dockerfile_normalization_and_security_change_details(self):
        before = "# comment\nfrom node:20\nRUN echo old \\\n  && true\n"
        after = "\nFROM node:20\nRUN echo new \\\n  && true\nCOPY . /app\n"

        assert srf._normalize_dockerfile(before).startswith("FROM node:20")
        assert srf._normalize_dockerfile("RUN echo pending \\\n") == "RUN echo pending"
        verdict, details = srf._has_security_relevant_dockerfile_change(before, after)
        assert verdict is True
        assert "+COPY" in details
        assert any(d in details for d in ["+RUN", "-RUN"])

    def test_dockerfile_comment_only_and_fallbacks(self, monkeypatch):
        before = "FROM node:20\n# old\n"
        after = "# new\nFROM node:20\n"
        assert srf._has_security_relevant_dockerfile_change(before, after) == (False, [])
        assert srf._has_security_relevant_dockerfile_change(None, after) == (None, [])

        monkeypatch.setattr(srf, "_normalize_dockerfile", lambda _text: (_ for _ in ()).throw(RuntimeError("boom")))
        assert srf._has_security_relevant_dockerfile_change(before, after) == (None, [])

    def test_has_semantic_diff_package_json_true_false_and_fallback(self, tmp_path, monkeypatch):
        repo = tmp_path
        path = repo / "package.json"

        monkeypatch.setattr(srf, "_git_show_blob", lambda *_args: json.dumps({"name": "app"}))
        path.write_text(json.dumps({"name": "renamed"}), encoding="utf-8")
        assert srf.has_semantic_diff(str(repo), None, "package.json") == (False, [])

        monkeypatch.setattr(srf, "_git_show_blob", lambda *_args: json.dumps({"dependencies": {"a": "1"}}))
        path.write_text(json.dumps({"dependencies": {"a": "2"}}), encoding="utf-8")
        semantic, details = srf.has_semantic_diff(str(repo), None, "package.json")
        assert semantic is True
        assert details == ["dependencies:~a"]

        monkeypatch.setattr(srf, "_git_show_blob", lambda *_args: "{bad")
        monkeypatch.setattr(srf, "_whitespace_only_diff", lambda *_args: True)
        assert srf.has_semantic_diff(str(repo), None, "package.json") == (False, [])

    def test_has_semantic_diff_dockerfile_true_false(self, tmp_path, monkeypatch):
        repo = tmp_path
        path = repo / "Dockerfile"

        monkeypatch.setattr(srf, "_git_show_blob", lambda *_args: "FROM node:20\n# old\n")
        path.write_text("# new\nFROM node:20\n", encoding="utf-8")
        assert srf.has_semantic_diff(str(repo), None, "Dockerfile") == (False, [])

        monkeypatch.setattr(srf, "_git_show_blob", lambda *_args: "FROM node:20\n")
        path.write_text("FROM node:20\nRUN npm ci\n", encoding="utf-8")
        semantic, details = srf.has_semantic_diff(str(repo), None, "Dockerfile")
        assert semantic is True
        assert "+RUN" in details

        path.unlink()
        monkeypatch.setattr(srf, "_whitespace_only_diff", lambda *_args: False)
        assert srf.has_semantic_diff(str(repo), None, "Dockerfile") == (True, [])


# =========================================================================
# classify_files aggregation
# =========================================================================


class TestClassifyFiles:
    """Tests for the full classification pipeline."""

    def test_all_irrelevant(self):
        """Pure styling changes → verdict irrelevant."""
        with patch("security_relevance_filter.get_diff_for_file", return_value=""):
            result = classify_files(
                "/tmp/repo",
                None,
                [
                    "src/styles.css",
                    "README.md",
                    "docs/guide.txt",
                ],
            )
        assert result["verdict"] == "irrelevant"
        assert len(result["relevant_files"]) == 0

    def test_mixed_with_relevant(self):
        """Auth file makes the verdict relevant even with irrelevant files."""
        with patch("security_relevance_filter.get_diff_for_file", return_value=""):
            result = classify_files(
                "/tmp/repo",
                None,
                [
                    "src/styles.css",
                    "src/auth/login.py",  # relevant by path segment
                    "README.md",
                ],
            )
        assert result["verdict"] == "relevant"
        assert "src/auth/login.py" in result["relevant_files"]

    def test_manifest_always_relevant(self):
        """package.json is always relevant regardless of diff content."""
        with patch("security_relevance_filter.get_diff_for_file", return_value=""):
            result = classify_files("/tmp/repo", None, ["package.json"])
        assert result["verdict"] == "relevant"

    def test_tier1_semantic_downgrade_for_manifest_noise(self):
        with patch("security_relevance_filter.has_semantic_diff", return_value=(False, [])):
            result = classify_files("/tmp/repo", None, ["package.json"])

        assert result["verdict"] == "irrelevant"
        assert result["files"]["package.json"]["reasons"] == ["name:package.json", "no_semantic_diff"]

    def test_tier1_semantic_details_are_appended_for_manifest_changes(self):
        with patch("security_relevance_filter.has_semantic_diff", return_value=(True, ["dependencies:+express"])):
            result = classify_files("/tmp/repo", None, ["package.json"])

        assert result["verdict"] == "relevant"
        assert result["files"]["package.json"]["reasons"] == ["name:package.json", "diff:dependencies:+express"]

    def test_env_file_is_relevant_without_semantic_downgrade(self):
        assert srf._is_tier1_downgradeable([]) is False

        with patch("security_relevance_filter.has_semantic_diff", side_effect=AssertionError("should not be called")):
            result = classify_files("/tmp/repo", None, [".env.production"])

        assert result["verdict"] == "relevant"
        assert result["files"][".env.production"]["reasons"] == ["env_file:.env.production"]

    def test_code_file_with_security_diff(self):
        """A .py file with auth patterns in the diff → relevant."""
        mock_diff = "+    token = jwt.encode(payload, SECRET_KEY)"
        with patch("security_relevance_filter.get_diff_for_file", return_value=mock_diff):
            result = classify_files("/tmp/repo", "abc123", ["src/utils.py"])
        assert result["verdict"] == "relevant"
        assert result["files"]["src/utils.py"]["relevant"] is True

    def test_code_file_without_security_diff(self):
        """A .py file with only cosmetic changes → irrelevant."""
        mock_diff = "+    # Refactored for readability\n+    x = compute_total(items)"
        with patch("security_relevance_filter.get_diff_for_file", return_value=mock_diff):
            result = classify_files("/tmp/repo", "abc123", ["src/utils.py"])
        assert result["verdict"] == "irrelevant"
        assert result["files"]["src/utils.py"]["relevant"] is False

    def test_no_diff_available_conservative(self):
        """When diff can't be retrieved, file is conservatively marked relevant."""
        with patch("security_relevance_filter.get_diff_for_file", return_value=""):
            result = classify_files("/tmp/repo", "abc123", ["src/server.py"])
        assert result["verdict"] == "relevant"
        assert result["files"]["src/server.py"]["relevant"] is True
        assert "no_diff_available" in result["files"]["src/server.py"]["reasons"]

    def test_empty_file_list(self):
        result = classify_files("/tmp/repo", None, [])
        assert result["verdict"] == "irrelevant"

    def test_summary_format(self):
        with patch("security_relevance_filter.get_diff_for_file", return_value=""):
            result = classify_files(
                "/tmp/repo",
                None,
                [
                    "README.md",
                    "src/auth/handler.py",
                ],
            )
        assert "/" in result["summary"]  # contains fraction like "1/2"


# =========================================================================
# CLI entry point
# =========================================================================


class TestCLI:
    """Tests for the main() CLI function."""

    def test_exit_code_relevant(self):
        """Exit code 0 when relevant files found."""
        with patch("security_relevance_filter.get_changed_files", return_value=["src/auth/login.py"]):
            with patch("security_relevance_filter.get_diff_for_file", return_value=""):
                code = main(["--repo-root", "/tmp", "--files", "src/auth/login.py"])
        assert code == 0

    def test_exit_code_irrelevant(self):
        """Exit code 1 when all files irrelevant."""
        with patch("security_relevance_filter.get_changed_files", return_value=["README.md"]):
            with patch("security_relevance_filter.get_diff_for_file", return_value=""):
                code = main(["--repo-root", "/tmp", "--files", "README.md"])
        assert code == 1

    def test_exit_code_no_files(self):
        """Exit code 1 when no files changed."""
        with patch("security_relevance_filter.get_changed_files", return_value=[]):
            code = main(["--repo-root", "/tmp"])
        assert code == 1

    def test_invalid_repo_root(self):
        code = main(["--repo-root", "/nonexistent/path/xyz"])
        assert code == 2
