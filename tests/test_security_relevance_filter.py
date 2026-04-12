"""
Tests for plugin/scripts/security_relevance_filter.py

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
PLUGIN = ROOT / "plugin"

sys.path.insert(0, str(PLUGIN / "scripts"))
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

    @pytest.mark.parametrize("path", [
        "src/components/Button.css",
        "docs/README.md",
        "CHANGELOG.txt",
        "locales/en.po",
        "src/app.scss",
        "assets/logo.png",
        "fonts/Inter.woff2",
        "src/snapshot.snap",
    ])
    def test_irrelevant_extensions(self, path: str):
        decision, reasons = classify_by_path(path)
        assert decision is False, f"{path} should be irrelevant"
        assert any(r.startswith("ext:") or r.startswith("name:") for r in reasons)

    # --- Irrelevant by exact name ---

    @pytest.mark.parametrize("path", [
        "LICENSE",
        ".editorconfig",
        ".prettierrc",
        ".gitignore",
        "jest.config.js",
    ])
    def test_irrelevant_names(self, path: str):
        decision, reasons = classify_by_path(path)
        assert decision is False, f"{path} should be irrelevant"

    # --- Irrelevant: test files ---

    @pytest.mark.parametrize("path", [
        "test_auth.py",
        "src/auth.test.js",
        "tests/integration/test_login.py",
        "spec/auth.spec.ts",
        "__tests__/Login.test.tsx",
    ])
    def test_irrelevant_test_files(self, path: str):
        decision, reasons = classify_by_path(path)
        assert decision is False, f"{path} should be irrelevant (test file)"

    # --- Always relevant: manifests ---

    @pytest.mark.parametrize("path", [
        "package.json",
        "backend/requirements.txt",
        "services/auth/Dockerfile",
        "deploy/Dockerfile.prod",
        "go.mod",
    ])
    def test_relevant_manifests(self, path: str):
        decision, reasons = classify_by_path(path)
        assert decision is True, f"{path} should be relevant"

    # --- Always relevant: IaC & workflows ---

    @pytest.mark.parametrize("path", [
        "terraform/main.tf",
        "k8s/deployment.yaml",
        ".github/workflows/deploy.yml",
        "docker-compose.yml",
        "ansible/playbook.yaml",
    ])
    def test_relevant_iac_workflows(self, path: str):
        decision, reasons = classify_by_path(path)
        assert decision is True, f"{path} should be relevant"

    # --- Always relevant: env files ---

    def test_relevant_env_file(self):
        decision, reasons = classify_by_path(".env.production")
        assert decision is True

    # --- Always relevant: security path segments ---

    @pytest.mark.parametrize("path", [
        "src/auth/login.py",
        "lib/security/validator.js",
        "pkg/crypto/aes.go",
        "app/middleware/cors.ts",
        "src/permissions/check.py",
    ])
    def test_relevant_path_segments(self, path: str):
        decision, reasons = classify_by_path(path)
        assert decision is True, f"{path} should be relevant (security path segment)"

    # --- Undecided: needs diff analysis ---

    @pytest.mark.parametrize("path", [
        "src/server.py",
        "lib/utils.js",
        "app/controllers/user.go",
        "src/api/handler.ts",
    ])
    def test_undecided_needs_diff(self, path: str):
        decision, _ = classify_by_path(path)
        assert decision is None, f"{path} should be undecided (needs diff)"


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
        diff = '+    return <h1>Welcome to our updated platform</h1>'
        relevant, reasons = classify_by_diff(diff)
        assert relevant is False

    def test_xss_pattern(self):
        diff = '+    element.innerHTML = userInput;'
        relevant, reasons = classify_by_diff(diff)
        assert relevant is True
        assert any("xss" in r for r in reasons)

    def test_file_upload_pattern(self):
        diff = '+    const uploaded = await uploadFile(req.file);'
        relevant, reasons = classify_by_diff(diff)
        assert relevant is True

    def test_permission_check(self):
        diff = '+    if not user.has_permission("admin"):'
        relevant, reasons = classify_by_diff(diff)
        assert relevant is True


# =========================================================================
# classify_files aggregation
# =========================================================================

class TestClassifyFiles:
    """Tests for the full classification pipeline."""

    def test_all_irrelevant(self):
        """Pure styling changes → verdict irrelevant."""
        with patch("security_relevance_filter.get_diff_for_file", return_value=""):
            result = classify_files("/tmp/repo", None, [
                "src/styles.css",
                "README.md",
                "docs/guide.txt",
            ])
        assert result["verdict"] == "irrelevant"
        assert len(result["relevant_files"]) == 0

    def test_mixed_with_relevant(self):
        """Auth file makes the verdict relevant even with irrelevant files."""
        with patch("security_relevance_filter.get_diff_for_file", return_value=""):
            result = classify_files("/tmp/repo", None, [
                "src/styles.css",
                "src/auth/login.py",  # relevant by path segment
                "README.md",
            ])
        assert result["verdict"] == "relevant"
        assert "src/auth/login.py" in result["relevant_files"]

    def test_manifest_always_relevant(self):
        """package.json is always relevant regardless of diff content."""
        with patch("security_relevance_filter.get_diff_for_file", return_value=""):
            result = classify_files("/tmp/repo", None, ["package.json"])
        assert result["verdict"] == "relevant"

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
            result = classify_files("/tmp/repo", None, [
                "README.md",
                "src/auth/handler.py",
            ])
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
