"""Unit tests for scripts/enforce_control_taxonomy.py — RC-1 + RC-6 (2026-05)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

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

    def test_canonicalize_strips_trailing_tech_qualifier(self):
        # Regression (juice-shop 2026-06-01): Stage 1 appends a `(library/tech)`
        # qualifier the §7.2 scaffold strips when rendering the heading. The
        # rewrite rules must match the qualifier-stripped form, otherwise a
        # real name like "JWT Authentication (express-jwt + jsonwebtoken)"
        # slips past every rule and the scaffold emits a forbidden §7.2 heading.
        assert (
            ect._canonicalize_name("JWT Authentication (express-jwt + jsonwebtoken)")
            == "Session Token Validation (JWT Based)"
        )
        assert (
            ect._canonicalize_name("JWT RS256 Authentication (lib/insecurity.ts)")
            == "Session Token Validation (JWT Based)"
        )

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
        assert ect._infer_domain("Rate limiting on password reset + 2FA") == "Identity and Authentication Controls"

    def test_password_login_routes_to_iam(self):
        assert ect._infer_domain("Password Login") == "Identity and Authentication Controls"

    def test_jwt_routes_to_session_token_controls(self):
        """2026-05 reconciliation: JWT is a session-token primitive, so any
        JWT-named control routes to §7.3 Session and Token Controls, NOT §7.2."""
        assert ect._infer_domain("JWT Bearer Authentication") == "Session and Token Controls"
        assert ect._infer_domain("Session Token Validation (JWT Based)") == "Session and Token Controls"

    def test_token_storage_routes_to_session(self):
        assert ect._infer_domain("JWT Token Storage") == "Session and Token Controls"

    def test_password_hashing_routes_to_crypto(self):
        """Password hashing is a crypto-storage primitive (§7.9), NOT a §7.2
        auth mechanism — the §7.2 auth_method_decomposition gate hard-forbids a
        `#### Password Hashing` heading. juice-shop 2026-06-01 §7.2 residual."""
        assert ect._infer_domain("Password Hashing") == "Cryptography Secrets and Data Protection"
        assert ect._infer_domain("Password Storage") == "Cryptography Secrets and Data Protection"

    def test_enforce_reroutes_password_hashing_out_of_iam(self):
        """A standalone Password Hashing control Stage 1 parked in §7.2 IAM
        must be re-routed to §7.9 even though §7.2 is a KNOWN domain (the
        conservative don't-shuffle-known-domains guard must not block it)."""
        data = {
            "security_controls": [
                {
                    "id": "SC-1",
                    "control": "Password Hashing",
                    "domain": "Identity and Authentication Controls",
                    "effectiveness": "Weak",
                },
            ]
        }
        _, _names, domain_changes = ect.enforce(data)
        assert data["security_controls"][0]["domain"] == "Cryptography Secrets and Data Protection"
        assert any(ch["to"] == "Cryptography Secrets and Data Protection" for ch in domain_changes)

    def test_websocket_routes_to_realtime(self):
        assert ect._infer_domain("WebSocket message validation") == "Real-time and Not Applicable Controls"

    def test_cors_routes_to_browser(self):
        assert ect._infer_domain("CORS strict origin policy") == "Browser and Cross-Origin Controls"

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
        data = _make_yaml(
            [
                {
                    "id": "SC-011",
                    "domain": "Real-time and Not Applicable Controls",
                    "control": "Rate limiting on password reset + 2FA",
                    "verdict": "Adequate",
                },
            ]
        )
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
        data = _make_yaml(
            [
                {
                    "id": "SC-001",
                    "domain": "Identity and Authentication Controls",
                    "control": "JWT RS256 Authentication",
                    "verdict": "Weak",
                },
            ]
        )
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
        data = _make_yaml(
            [
                {
                    "id": "SC-001",
                    "domain": "Identity and Authentication",
                    "control": "Password Login",
                    "verdict": "Weak",
                },
            ]
        )
        out, names, domains = ect.enforce(data)
        # Password Login is already canonical — no name rewrite.
        assert names == []
        # domain gets suffix normalised, not semantically re-routed
        assert any(
            d["from"] == "Identity and Authentication" and d["to"] == "Identity and Authentication Controls"
            for d in domains
        )
        # final domain is the canonical form
        assert out["security_controls"][0]["domain"] == "Identity and Authentication Controls"

    def test_real_websocket_control_stays_in_realtime(self, tmp_path):
        """A genuine real-time control in §7.12 must NOT be re-routed."""
        data = _make_yaml(
            [
                {
                    "id": "SC-099",
                    "domain": "Real-time and Not Applicable Controls",
                    "control": "WebSocket message validation",
                    "verdict": "Missing",
                },
            ]
        )
        out, names, domains = ect.enforce(data)
        assert names == []
        assert domains == []
        assert out["security_controls"][0]["domain"] == "Real-time and Not Applicable Controls"

    def test_idempotent(self, tmp_path):
        data = _make_yaml(
            [
                {
                    "id": "SC-001",
                    "domain": "Identity and Authentication",
                    "control": "JWT RS256 Authentication",
                    "verdict": "Weak",
                },
                {
                    "id": "SC-011",
                    "domain": "Real-time and Not Applicable Controls",
                    "control": "Rate limiting on password reset + 2FA",
                    "verdict": "Adequate",
                },
            ]
        )
        # First pass mutates.
        out1, n1, d1 = ect.enforce(data)
        assert n1 and d1
        # Second pass is a no-op against the OUTPUT of the first pass.
        _, n2, d2 = ect.enforce(out1)
        assert n2 == []
        assert d2 == []

    def test_unknown_domain_re_routed(self, tmp_path):
        """A typo / unknown domain string gets re-routed based on token-match."""
        data = _make_yaml(
            [
                {
                    "id": "SC-100",
                    "domain": "BogusDomain",
                    "control": "CORS strict origin policy",
                    "verdict": "Adequate",
                },
            ]
        )
        out, names, domains = ect.enforce(data)
        assert names == []
        assert len(domains) == 1
        assert domains[0]["to"] == "Browser and Cross-Origin Controls"


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------


class TestCLI:
    def test_cli_writes_yaml(self, tmp_path):
        _write_yaml(
            tmp_path,
            [
                {
                    "id": "SC-001",
                    "domain": "Real-time and Not Applicable Controls",
                    "control": "Rate limiting on password reset + 2FA",
                    "verdict": "Adequate",
                },
            ],
        )
        rc = ect.main([str(tmp_path)])
        assert rc == 0
        data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
        assert data["security_controls"][0]["domain"] == "Identity and Authentication Controls"

    def test_cli_report_only_no_write(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            [
                {
                    "id": "SC-001",
                    "domain": "Real-time and Not Applicable Controls",
                    "control": "Rate limiting on password reset + 2FA",
                    "verdict": "Adequate",
                },
            ],
        )
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
        _write_yaml(
            tmp_path,
            [
                # Domain that needs renaming: legacy alias →
                # canonical "Identity and Authentication Controls" for
                # password-reset rate limiting (per architectural-controls.yaml).
                {
                    "id": "SC-001",
                    "domain": "Real-time and Not Applicable Controls",
                    "control": "Rate limiting on password reset + 2FA",
                    "verdict": "Adequate",
                },
            ],
        )
        rc = ect.main([str(tmp_path)])
        assert rc == 0
        log_path = tmp_path / ".agent-run.log"
        assert log_path.is_file(), "expected an audit-log entry for the rename"
        log_lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if "CONTROL_TAXONOMY_DRIFT" in ln]
        assert log_lines, "expected at least one CONTROL_TAXONOMY_DRIFT entry"
        for line in log_lines:
            assert " INFO " in line, f"taxonomy drift must be INFO-level (routine normalisation), got: {line!r}"
            assert " WARN " not in line, f"taxonomy drift must NOT be WARN-level, got: {line!r}"


# ---------------------------------------------------------------------------
# RC-6 — JWT domain reroute (juice-shop 2026-06-03 §7.2 auth_method_decomposition)
# ---------------------------------------------------------------------------


class TestJwtDomainReroute:
    """A bare `JWT …` control that Stage 1 parked in §7.2 IAM must reroute to
    §7.3 Session and Token Controls even when its name does NOT match a
    _canonicalize_name rule (e.g. "JWT signing key management"). Before the fix
    the reroute guard only fired for names already canonicalised to
    "Session Token …", so the unmatched name kept its IAM domain and tripped
    the §7.2 auth_method_decomposition contract gate."""

    def test_jwt_signing_key_management_reroutes_to_session(self):
        data, _names, domains = ect.enforce(
            _make_yaml(
                [
                    {
                        "id": "SC-1",
                        "control": "JWT signing key management",
                        "domain": "Identity and Authentication Controls",
                    },
                ]
            )
        )
        assert data["security_controls"][0]["domain"] == "Session and Token Controls"
        assert any(d["to"] == "Session and Token Controls" for d in domains)

    def test_non_jwt_iam_mechanism_stays_in_72(self):
        data, _n, _d = ect.enforce(
            _make_yaml(
                [
                    {"id": "SC-1", "control": "Password-Based Login", "domain": "Identity and Authentication Controls"},
                    {"id": "SC-2", "control": "TOTP 2FA", "domain": "Identity and Authentication Controls"},
                ]
            )
        )
        assert data["security_controls"][0]["domain"] == "Identity and Authentication Controls"
        assert data["security_controls"][1]["domain"] == "Identity and Authentication Controls"

    def test_jwt_reroute_is_idempotent(self):
        controls = [
            {"id": "SC-1", "control": "JWT signing key management", "domain": "Identity and Authentication Controls"}
        ]
        data, _, _ = ect.enforce(_make_yaml(controls))
        # second pass over the already-rerouted yaml must be a no-op
        data2, _, domains2 = ect.enforce(data)
        assert data2["security_controls"][0]["domain"] == "Session and Token Controls"
        assert domains2 == []


# ---------------------------------------------------------------------------
# Branch coverage for helper edge cases + CLI error paths (coverage campaign).
# Pin current behaviour only — no producer edits.
# ---------------------------------------------------------------------------


class TestHelperEdgeCases:
    def test_canonicalize_non_str_returns_none(self):
        # line 112: non-str input short-circuits.
        assert ect._canonicalize_name(None) is None
        assert ect._canonicalize_name(123) is None

    def test_canonicalize_already_canonical_via_rule(self):
        # line 130: name matches a rule AND stripped == canonical → None
        # (no rewrite needed because it is already in canonical form). The
        # session-validation canonical form is itself produced by no rule
        # whose RHS equals it after a match, so construct via a name that the
        # rule matches and equals its own canonical: feed the exact canonical
        # string of a signing rule that the signing regex matches.
        # "Session Token Signing (JWT Based)" is NOT matched by any rule, so
        # instead exercise the equality branch directly: the bare-form rules
        # rewrite to "Session Token Validation (JWT Based)"; passing that exact
        # string does not match any rule (returns None at line 132). To hit
        # line 130 we need a name that matches a rule whose canonical == name.
        # No rule's canonical is itself matched by its own pattern, so line 130
        # is structurally near-dead; assert the realistic equivalent path.
        assert ect._canonicalize_name("Session Token Validation (JWT Based)") is None

    def test_infer_domain_non_str(self):
        # line 263: non-str / empty control name → None
        assert ect._infer_domain(None) is None
        assert ect._infer_domain("") is None
        assert ect._infer_domain("   ") is None

    def test_infer_domain_punctuation_only_no_tokens(self):
        # line 266: a non-empty string that tokenises to an empty set.
        assert ect._infer_domain("!!! --- ???") is None


class TestEnforceGuards:
    def test_enforce_no_controls_key(self):
        # line 289: security_controls missing / not a list → early return.
        data = {"meta": {}}
        out, names, domains = ect.enforce(data)
        assert names == [] and domains == []
        assert out is data

    def test_enforce_empty_controls_list(self):
        # line 289: empty list also early-returns.
        out, names, domains = ect.enforce({"security_controls": []})
        assert names == [] and domains == []

    def test_enforce_skips_non_dict_control(self):
        # line 296: a non-dict entry in the list is skipped.
        data = {
            "security_controls": [
                "not-a-dict",
                {"id": "SC-1", "control": "CORS strict origin policy", "domain": "BogusDomain"},
            ]
        }
        out, names, domains = ect.enforce(data)
        assert len(domains) == 1
        assert domains[0]["id"] == "SC-1"


class TestCLIErrorPaths:
    def test_main_no_args_usage(self, capsys):
        # lines 449-450: empty argv → usage + exit 2.
        rc = ect.main([])
        assert rc == 2
        assert "Usage" in capsys.readouterr().err

    def test_main_malformed_yaml(self, tmp_path, capsys):
        # lines 459-461: YAMLError during parse → return 1.
        (tmp_path / "threat-model.yaml").write_text("key: [unclosed\n", encoding="utf-8")
        rc = ect.main([str(tmp_path)])
        assert rc == 1
        assert "could not parse" in capsys.readouterr().err

    def test_main_yaml_not_a_mapping(self, tmp_path, capsys):
        # lines 463-464: yaml parses to a list, not a dict → return 1.
        (tmp_path / "threat-model.yaml").write_text("- a\n- b\n", encoding="utf-8")
        rc = ect.main([str(tmp_path)])
        assert rc == 1
        assert "did not parse to a mapping" in capsys.readouterr().err

    def test_main_no_drift_clean_message(self, tmp_path, capsys):
        # line 500: clean yaml → "no taxonomy drift" message.
        _write_yaml(
            tmp_path,
            [{"id": "SC-1", "control": "Password Login", "domain": "Identity and Authentication Controls"}],
        )
        rc = ect.main([str(tmp_path)])
        assert rc == 0
        assert "no taxonomy drift" in capsys.readouterr().out

    def test_main_name_change_summary_details(self, tmp_path, capsys):
        # lines 482, 493-494: a name change produces the name-detail summary
        # and the name-change log loop.
        _write_yaml(
            tmp_path,
            [{"id": "SC-1", "control": "JWT RS256 Authentication", "domain": "Session and Token Controls"}],
        )
        rc = ect.main([str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "canonicalised 1 name(s)" in out
        assert "[names:" in out
        log = (tmp_path / ".agent-run.log").read_text(encoding="utf-8")
        assert "name SC-1" in log

    def test_log_oserror_swallowed(self, tmp_path, monkeypatch):
        # lines 443-444: _log swallows OSError when the log file cannot open.
        def _boom(*a, **k):
            raise OSError("disk full")

        monkeypatch.setattr(Path, "open", _boom)
        # Should not raise.
        ect._log(tmp_path, "test message")
