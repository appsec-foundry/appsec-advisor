"""Unit tests for scripts/enforce_control_taxonomy.py — RC-1 + RC-6 (2026-05)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "enforce_control_taxonomy.py"


def _load():
    if "enforce_control_taxonomy" in sys.modules:
        return sys.modules["enforce_control_taxonomy"]
    spec = importlib.util.spec_from_file_location("enforce_control_taxonomy", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["enforce_control_taxonomy"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ect = _load()


def _make_yaml(controls: list[dict]) -> dict:
    return {
        "schema_version": 1,
        "meta": {"generated": "2026-05-24T07:00:00Z"},
        "components": [],
        "threats": [],
        "mitigations": [],
        "assets": [],
        "attack_surface": [],
        "trust_boundaries": [],
        "security_controls": controls,
    }


def _write_yaml(tmp_path: Path, controls: list[dict]) -> Path:
    yaml_path = tmp_path / "threat-model.yaml"
    yaml_path.write_text(yaml.safe_dump(_make_yaml(controls), sort_keys=False), encoding="utf-8")
    return yaml_path


# ---------------------------------------------------------------------------
# RC-1 — name canonicalisation
# ---------------------------------------------------------------------------


class TestNameCanonicalisation:
    def test_jwt_rs256_authentication_rewritten(self):
        # 2026-05 reconciliation: JWT is a §7.3 session-token primitive, not a
        # §7.2 mechanism — all JWT-"authentication" shapes canonicalise to the
        # SessionMgmt validation primitive (mirrors architectural-controls.yaml).
        assert ect._canonicalize_name("JWT RS256 Authentication") == "Session Token Validation (JWT Based)"

    def test_jwt_hs256_authentication_rewritten(self):
        # The check is alg-token-agnostic: HS256, ES256, PS256 must also match.
        assert ect._canonicalize_name("JWT HS256 Authentication") == "Session Token Validation (JWT Based)"
        assert ect._canonicalize_name("JWT ES256 Authentication") == "Session Token Validation (JWT Based)"

    def test_jwt_signing_rewritten(self):
        assert ect._canonicalize_name("JWT RS256 Signing") == "Session Token Signing (JWT Based)"

    def test_jwt_verification_rewritten(self):
        assert ect._canonicalize_name("JWT HS256 Verification") == "Session Token Validation (JWT Based)"

    def test_already_canonical_returns_none(self):
        # "JWT Bearer Authentication" is no longer a canonical form — it is a
        # legacy §7.2-mechanism name and now canonicalises to the SessionMgmt
        # validation primitive (2026-05 reconciliation).
        assert ect._canonicalize_name("JWT Bearer Authentication") == "Session Token Validation (JWT Based)"
        assert ect._canonicalize_name("Session Token Validation (JWT Based)") is None
        assert ect._canonicalize_name("Password Login") is None

    def test_unknown_name_returns_none(self):
        assert ect._canonicalize_name("Custom Magic Auth") is None

    def test_empty_returns_none(self):
        assert ect._canonicalize_name("") is None
        assert ect._canonicalize_name("   ") is None


# ---------------------------------------------------------------------------
# RC-6 — domain inference
# ---------------------------------------------------------------------------


class TestDomainInference:
    def test_rate_limiting_routes_to_iam(self):
        assert ect._infer_domain("Rate limiting on password reset + 2FA") == \
            "Identity and Authentication Controls"

    def test_password_login_routes_to_iam(self):
        assert ect._infer_domain("Password Login") == "Identity and Authentication Controls"

    def test_jwt_routes_to_session_token_controls(self):
        """2026-05 reconciliation: JWT is a session-token primitive, so any
        JWT-named control routes to §7.3 Session and Token Controls, NOT §7.2."""
        assert ect._infer_domain("JWT Bearer Authentication") == \
            "Session and Token Controls"
        assert ect._infer_domain("Session Token Validation (JWT Based)") == \
            "Session and Token Controls"

    def test_token_storage_routes_to_session(self):
        assert ect._infer_domain("JWT Token Storage") == "Session and Token Controls"

    def test_websocket_routes_to_realtime(self):
        assert ect._infer_domain("WebSocket message validation") == \
            "Real-time and Not Applicable Controls"

    def test_cors_routes_to_browser(self):
        assert ect._infer_domain("CORS strict origin policy") == \
            "Browser and Cross-Origin Controls"

    def test_unknown_name_returns_none(self):
        assert ect._infer_domain("Mystery Control XYZ") is None

    def test_multi_word_match_beats_single_word(self):
        """Longest tuple wins — `(password, login)` > `(rate, limiting)` when
        both apply. Tests the specificity sort in _infer_domain."""
        # "Password Login Rate Limiting" contains both. Should prefer IAM
        # via the more specific tuple (both options land in IAM, but the
        # multi-word match must not be overridden by a single-word later entry).
        result = ect._infer_domain("Password Login Rate Limiting")
        assert result == "Identity and Authentication Controls"


# ---------------------------------------------------------------------------
# End-to-end via enforce()
# ---------------------------------------------------------------------------


class TestEnforceEndToEnd:
    def test_sc011_real_juiceshop_bug_fixed(self, tmp_path):
        """The exact production drift: SC-011 'Rate limiting on password
        reset + 2FA' parked in §7.12 must move to §7.2 IAM."""
        data = _make_yaml([
            {"id": "SC-011", "domain": "Real-time and Not Applicable Controls",
             "control": "Rate limiting on password reset + 2FA", "verdict": "Adequate"},
        ])
        _, names, domains = ect.enforce(data)
        assert names == []
        assert len(domains) == 1
        assert domains[0]["id"] == "SC-011"
        assert domains[0]["from"] == "Real-time and Not Applicable Controls"
        assert domains[0]["to"] == "Identity and Authentication Controls"

    def test_sc001_jwt_rs256_canonicalised_and_rerouted_to_session(self, tmp_path):
        """2026-05 reconciliation: SC-001 'JWT RS256 Authentication' is renamed
        to the SessionMgmt validation primitive AND re-routed §7.2 IAM → §7.3
        Session and Token Controls (JWT is a session-token primitive, not a
        §7.2 mechanism). The targeted 'Session Token …' reroute exception fires
        even though IAM and Session are normally not shuffled."""
        data = _make_yaml([
            {"id": "SC-001", "domain": "Identity and Authentication Controls",
             "control": "JWT RS256 Authentication", "verdict": "Weak"},
        ])
        out, names, domains = ect.enforce(data)
        assert len(names) == 1
        assert names[0]["to"] == "Session Token Validation (JWT Based)"
        assert len(domains) == 1
        assert domains[0]["from"] == "Identity and Authentication Controls"
        assert domains[0]["to"] == "Session and Token Controls"
        # post-state confirms
        assert out["security_controls"][0]["domain"] == "Session and Token Controls"
        assert out["security_controls"][0]["control"] == "Session Token Validation (JWT Based)"

    def test_short_form_domain_normalised(self, tmp_path):
        """'Identity and Authentication' (without 'Controls' suffix) must be
        treated as the canonical '... Controls' form, not semantically
        re-routed. Uses a genuine IAM mechanism ('Password Login') so the test
        isolates suffix-normalisation from the JWT→§7.3 reroute."""
        data = _make_yaml([
            {"id": "SC-001", "domain": "Identity and Authentication",
             "control": "Password Login", "verdict": "Weak"},
        ])
        out, names, domains = ect.enforce(data)
        # Password Login is already canonical — no name rewrite.
        assert names == []
        # domain gets suffix normalised, not semantically re-routed
        assert any(
            d["from"] == "Identity and Authentication"
            and d["to"] == "Identity and Authentication Controls"
            for d in domains
        )
        # final domain is the canonical form
        assert out["security_controls"][0]["domain"] == "Identity and Authentication Controls"

    def test_real_websocket_control_stays_in_realtime(self, tmp_path):
        """A genuine real-time control in §7.12 must NOT be re-routed."""
        data = _make_yaml([
            {"id": "SC-099", "domain": "Real-time and Not Applicable Controls",
             "control": "WebSocket message validation", "verdict": "Missing"},
        ])
        out, names, domains = ect.enforce(data)
        assert names == []
        assert domains == []
        assert out["security_controls"][0]["domain"] == "Real-time and Not Applicable Controls"

    def test_idempotent(self, tmp_path):
        data = _make_yaml([
            {"id": "SC-001", "domain": "Identity and Authentication",
             "control": "JWT RS256 Authentication", "verdict": "Weak"},
            {"id": "SC-011", "domain": "Real-time and Not Applicable Controls",
             "control": "Rate limiting on password reset + 2FA", "verdict": "Adequate"},
        ])
        # First pass mutates.
        out1, n1, d1 = ect.enforce(data)
        assert n1 and d1
        # Second pass is a no-op against the OUTPUT of the first pass.
        _, n2, d2 = ect.enforce(out1)
        assert n2 == []
        assert d2 == []

    def test_unknown_domain_re_routed(self, tmp_path):
        """A typo / unknown domain string gets re-routed based on token-match."""
        data = _make_yaml([
            {"id": "SC-100", "domain": "BogusDomain",
             "control": "CORS strict origin policy", "verdict": "Adequate"},
        ])
        out, names, domains = ect.enforce(data)
        assert names == []
        assert len(domains) == 1
        assert domains[0]["to"] == "Browser and Cross-Origin Controls"


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------


class TestCLI:
    def test_cli_writes_yaml(self, tmp_path):
        _write_yaml(tmp_path, [
            {"id": "SC-001", "domain": "Real-time and Not Applicable Controls",
             "control": "Rate limiting on password reset + 2FA", "verdict": "Adequate"},
        ])
        rc = ect.main([str(tmp_path)])
        assert rc == 0
        data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
        assert data["security_controls"][0]["domain"] == "Identity and Authentication Controls"

    def test_cli_report_only_no_write(self, tmp_path):
        yaml_path = _write_yaml(tmp_path, [
            {"id": "SC-001", "domain": "Real-time and Not Applicable Controls",
             "control": "Rate limiting on password reset + 2FA", "verdict": "Adequate"},
        ])
        before = yaml_path.read_text()
        rc = ect.main([str(tmp_path), "--report-only"])
        assert rc == 0
        assert yaml_path.read_text() == before, "--report-only must not write"

    def test_cli_missing_yaml_returns_1(self, tmp_path):
        rc = ect.main([str(tmp_path)])
        assert rc == 1


# ---------------------------------------------------------------------------
# Fix F (2026-05-25) — CONTROL_TAXONOMY_DRIFT is logged at INFO (not WARN).
# These drifts are deterministic alias-map normalisations (Stage-1 LLM emits
# 'Identity and Authentication', canonical is 'Identity and Authentication
# Controls'). Logging as WARN produced 4-8 false alarms per run in the audit
# trail; INFO keeps the audit signal without the alarm tone.
# ---------------------------------------------------------------------------


class TestLogLevelInfoNotWarn:
    def test_drift_logged_as_info(self, tmp_path):
        """When a domain rename fires, the .agent-run.log line is INFO-level."""
        _write_yaml(tmp_path, [
            # Domain that needs renaming: legacy alias →
            # canonical "Identity and Authentication Controls" for
            # password-reset rate limiting (per architectural-controls.yaml).
            {"id": "SC-001", "domain": "Real-time and Not Applicable Controls",
             "control": "Rate limiting on password reset + 2FA", "verdict": "Adequate"},
        ])
        rc = ect.main([str(tmp_path)])
        assert rc == 0
        log_path = tmp_path / ".agent-run.log"
        assert log_path.is_file(), "expected an audit-log entry for the rename"
        log_lines = [
            ln for ln in log_path.read_text(encoding="utf-8").splitlines()
            if "CONTROL_TAXONOMY_DRIFT" in ln
        ]
        assert log_lines, "expected at least one CONTROL_TAXONOMY_DRIFT entry"
        for line in log_lines:
            assert " INFO " in line, (
                f"taxonomy drift must be INFO-level (routine normalisation), got: {line!r}"
            )
            assert " WARN " not in line, (
                f"taxonomy drift must NOT be WARN-level, got: {line!r}"
            )
