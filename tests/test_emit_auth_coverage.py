"""Tests for emit_auth_coverage — §7.2 auth-mechanism coverage backfill.

Guards the 2026-06-06 juice-shop regression: OAuth social login, user
registration, and password reset were all present in code (two anchoring
Critical findings) yet uncataloged, so §7.2 listed only Password + MFA.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import emit_auth_coverage as eac  # noqa: E402


def _routes(*pairs):
    return [{"method": m, "path": p} for (m, p) in pairs]


def _yaml(controls=None, threats=None):
    return {"security_controls": controls or [], "threats": threats or []}


def _ctrl(name):
    return {"domain": "Identity and Authentication", "control": name, "effectiveness": "Weak"}


class TestDetectionAndRating:
    def test_detected_registration_with_critical_finding_is_unsafe(self):
        data = _yaml(
            controls=[_ctrl("Password-Based Authentication")],
            threats=[{"id": "T-007", "title": "Mass Assignment via Role Field",
                      "risk": "Critical", "evidence": {"file": "server.ts"}}],
        )
        routes = _routes(("POST", "/api/Users"))
        adds, _ = eac.build_auth_coverage(data, routes, None)
        reg = [a for a in adds if a["control"] == "User Registration"]
        assert reg, "registration must be backfilled"
        assert reg[0]["kind"] == "mechanism"
        assert reg[0]["effectiveness"] == "Unsafe"
        assert reg[0]["linked_threats"] == ["T-007"]
        assert reg[0]["auto_source"] == "auth-coverage"

    def test_detected_without_finding_is_partial(self):
        data = _yaml(controls=[_ctrl("Password-Based Authentication")])
        routes = _routes(("POST", "/rest/user/reset-password"))
        adds, _ = eac.build_auth_coverage(data, routes, None)
        rst = [a for a in adds if a["control"] == "Password Reset"]
        assert rst and rst[0]["effectiveness"] == "Partial"
        assert rst[0]["kind"] == "mechanism"
        assert "linked_threats" not in rst[0]

    def test_social_login_detected_via_repo_glob(self, tmp_path):
        # OAuth in a SPA has no server route — must be found via repo files.
        (tmp_path / "frontend" / "src" / "app" / "oauth").mkdir(parents=True)
        (tmp_path / "frontend" / "src" / "app" / "oauth" / "oauth.component.ts").write_text("x")
        data = _yaml(
            controls=[_ctrl("Password-Based Authentication")],
            threats=[{"id": "T-003", "title": "OAuth implicit flow weakness",
                      "risk": "Critical", "evidence": {"file": "oauth.component.ts"}}],
        )
        adds, _ = eac.build_auth_coverage(data, [], tmp_path)
        soc = [a for a in adds if "Social Login" in a["control"]]
        assert soc, "social login must be detected from repo files"
        assert soc[0]["effectiveness"] == "Unsafe"
        assert soc[0]["linked_threats"] == ["T-003"]


class TestLifecycleAndOptional:
    def test_lifecycle_required_absent_under_password_is_missing(self):
        # Password login present, but no reset endpoint anywhere → Missing gap.
        data = _yaml(controls=[_ctrl("Password-Based Authentication")])
        routes = _routes(("POST", "/rest/user/login"))
        adds, _ = eac.build_auth_coverage(data, routes, None)
        rst = [a for a in adds if a["control"] == "Password Reset"]
        assert rst and rst[0]["effectiveness"] == "Missing"
        assert rst[0]["kind"] == "lifecycle"

    def test_optional_variant_absent_is_not_fabricated(self):
        # No OAuth/MFA anywhere and no password reset route, but password present.
        data = _yaml(controls=[_ctrl("Password-Based Authentication")])
        routes = _routes(("POST", "/rest/user/login"))
        adds, _ = eac.build_auth_coverage(data, routes, None)
        names = {a["control"] for a in adds}
        assert "Social Login (OAuth / OIDC)" not in names  # optional, absent → skip
        assert "Multi-Factor Authentication" not in names

    def test_lifecycle_not_missing_when_no_password_auth(self):
        # No password auth at all → do not flag registration/reset as Missing.
        data = _yaml(controls=[])
        adds, _ = eac.build_auth_coverage(data, [], None)
        assert not any(a["effectiveness"] == "Missing" for a in adds)


class TestCoverageAndIdempotency:
    def test_already_cataloged_not_duplicated(self):
        data = _yaml(controls=[
            _ctrl("Password-Based Authentication"),
            _ctrl("Multi-Factor Authentication"),
            _ctrl("User Registration Flow"),
        ])
        routes = _routes(("POST", "/api/Users"), ("POST", "/2fa/verify"), ("POST", "/login"))
        adds, _ = eac.build_auth_coverage(data, routes, None)
        names = {a["control"] for a in adds}
        assert "User Registration" not in names  # "User Registration Flow" covers it
        assert "Multi-Factor Authentication" not in names

    def test_apply_is_idempotent(self, tmp_path):
        import yaml
        y = {
            "security_controls": [_ctrl("Password-Based Authentication")],
            "threats": [{"id": "T-007", "title": "Mass Assignment", "risk": "Critical",
                         "evidence": {"file": "server.ts"}}],
        }
        (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(y))
        inv = {"routes": [{"method": "POST", "path": "/api/Users"}]}
        (tmp_path / ".route-inventory.json").write_text(__import__("json").dumps(inv))

        eac.apply(tmp_path, None)
        first = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
        n1 = sum(1 for c in first["security_controls"] if c.get("auto_source") == "auth-coverage")
        eac.apply(tmp_path, None)
        second = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
        n2 = sum(1 for c in second["security_controls"] if c.get("auto_source") == "auth-coverage")
        assert n1 == n2 and n1 >= 1  # re-run does not duplicate
