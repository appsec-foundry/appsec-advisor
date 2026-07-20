"""Regression tests for deterministic local-password lifecycle checks.

The rules deliberately target only high-confidence source patterns.  They are
run by ``source_auth_scanner.py`` in its default pre-pass and become normal
source-scan threats through ``merge_threats.py``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
CATALOG = REPO_ROOT / "data" / "credential-lifecycle-checks.yaml"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import merge_threats as M  # noqa: E402
import source_auth_scanner as S  # noqa: E402
import validate_intermediate as VI  # noqa: E402


def _write(tmp_path: Path, name: str, body: str) -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")


def _ids(tmp_path: Path) -> set[str]:
    findings = S.scan_repo(tmp_path, S.load_checks(CATALOG))
    return {finding.check_id for finding in findings}


def test_security_question_password_reset_is_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "password_reset.js",
        "function resetPassword(req, user) {\n"
        "  if (req.body.securityAnswer === user.securityAnswer) {\n"
        "    return setPassword(user, req.body.newPassword);\n"
        "  }\n"
        "}\n",
    )

    assert "AUTHN-001" in _ids(tmp_path)


def test_security_question_with_out_of_band_factor_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "password_reset.js",
        "function resetPassword(req, user) {\n"
        "  if (req.body.securityAnswer !== user.securityAnswer) return deny();\n"
        "  return verifyResetToken(req.body.resetToken, user)\n"
        "    .then(() => setPassword(user, req.body.newPassword));\n"
        "}\n",
    )

    assert "AUTHN-001" not in _ids(tmp_path)


def test_password_policy_below_eight_characters_is_flagged_in_javascript(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "registration.js",
        "function register(password) {\n"
        "  if (password.length < 7) throw new Error('too short');\n"
        "}\n",
    )

    assert "AUTHN-002" in _ids(tmp_path)


def test_password_policy_below_eight_characters_is_flagged_in_python(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "registration.py",
        "def register(password):\n"
        "    if len(password) <= 6:\n"
        "        raise ValueError('too short')\n",
    )

    assert "AUTHN-002" in _ids(tmp_path)


def test_eight_character_password_policy_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "registration.js",
        "function register(password) {\n"
        "  if (password.length < 8) throw new Error('too short');\n"
        "}\n",
    )

    assert "AUTHN-002" not in _ids(tmp_path)


def test_default_scanner_loads_lifecycle_catalog_and_writes_findings(tmp_path: Path) -> None:
    """The new catalog must be live in the normal pre-pass, not test-only."""
    _write(
        tmp_path,
        "password_reset.js",
        "function resetPassword(req, user) {\n"
        "  if (req.body.securityAnswer === user.securityAnswer) {\n"
        "    return setPassword(user, req.body.newPassword);\n"
        "  }\n"
        "}\n",
    )
    output_dir = tmp_path / "out"

    assert S.main(["--repo-root", str(tmp_path), "--output-dir", str(output_dir), "--quiet"]) == 0
    doc = json.loads((output_dir / ".source-auth-findings.json").read_text(encoding="utf-8"))
    ok, errors = VI.validate_source_auth_findings(doc)
    assert ok, errors
    assert any(finding["check_id"] == "AUTHN-001" for finding in doc["findings"])


def test_lifecycle_findings_keep_authentication_stride_and_category() -> None:
    threat = M._source_auth_finding_to_threat(
        {
            "local_id": "SAF-001",
            "check_id": "AUTHN-002",
            "finding_type_id": "FT-034",
            "source_type": "nodejs_source",
            "file": "routes/register.js",
            "line": 2,
            "title": "Password policy permits credentials shorter than eight characters",
            "scenario": "The registration handler accepts seven-character passwords.",
            "severity": "Medium",
            "cwe": ["CWE-521"],
            "recommended_mitigation_title": "Require at least eight characters",
            "breach_vector": "Internet Anon",
        }
    )

    assert threat["stride"] == "Spoofing"
    assert threat["threat_category_id"] == "TH-02"
    assert threat["finding_type_id"] == "FT-034"
