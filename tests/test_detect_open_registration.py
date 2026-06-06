"""Tests for detect_open_registration — open user self-registration detection.

Covers the attack_surface[] primary path, the .route-inventory.json fallback
(2026-06-06 juice-shop regression: POST /api/Users present in the 112-route
inventory but absent from the curated 23-row attack_surface[]), and the
admin-create-user false-positive guards.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from detect_open_registration import detect  # noqa: E402


def _route(path, method="POST", authn="unknown", authz="unknown", mgmt=False):
    return {
        "method": method,
        "path": path,
        "authn_signal": authn,
        "authz_signal": authz,
        "management_surface": mgmt,
    }


class TestAttackSurfacePrimary:
    def test_unauthenticated_registration_entry(self):
        data = {"attack_surface": [{"entry_point": "POST /register", "auth_required": False}]}
        ok, reason = detect(data)
        assert ok is True
        assert "registration" in reason

    def test_authenticated_registration_entry_ignored(self):
        data = {"attack_surface": [{"entry_point": "POST /register", "auth_required": True}]}
        ok, _ = detect(data)
        assert ok is False

    def test_pinned_override_wins(self):
        data = {
            "meta": {"open_user_registration_pinned": False},
            "attack_surface": [{"entry_point": "POST /register", "auth_required": False}],
        }
        ok, reason = detect(data)
        assert ok is False
        assert "pinned" in reason


class TestRouteInventoryFallback:
    def test_post_api_users_from_inventory(self):
        # The juice-shop case: not in attack_surface, present in inventory with
        # authn_signal=middleware_present (registerAdminChallenge) — must still
        # be detected as open registration.
        data = {"attack_surface": []}
        routes = [_route("/api/Users", authn="middleware_present")]
        ok, reason = detect(data, routes)
        assert ok is True
        assert "/api/Users" in reason

    def test_fallback_not_used_when_attack_surface_has_entry(self):
        data = {"attack_surface": [{"entry_point": "POST /signup", "auth_required": False}]}
        routes = [_route("/api/Users")]
        ok, reason = detect(data, routes)
        assert ok is True
        assert "attack_surface" not in reason.lower() or "/signup" in reason

    def test_signup_and_register_paths_match(self):
        for p in ("/auth/register", "/rest/user/register", "/signup", "/accounts"):
            ok, _ = detect({"attack_surface": []}, [_route(p)])
            assert ok is True, p


class TestFalsePositiveGuards:
    def test_management_surface_excluded(self):
        # An admin create-user endpoint must NOT count as self-registration.
        routes = [_route("/api/users", mgmt=True)]
        ok, _ = detect({"attack_surface": []}, routes)
        assert ok is False

    def test_explicit_authz_gate_excluded(self):
        routes = [_route("/api/users", authz="decorator_present")]
        ok, _ = detect({"attack_surface": []}, routes)
        assert ok is False

    def test_non_post_method_excluded(self):
        routes = [_route("/api/users", method="GET")]
        ok, _ = detect({"attack_surface": []}, routes)
        assert ok is False

    def test_non_registration_path_excluded(self):
        routes = [_route("/api/orders")]
        ok, _ = detect({"attack_surface": []}, routes)
        assert ok is False

    def test_no_routes_no_surface(self):
        ok, reason = detect({"attack_surface": []}, [])
        assert ok is False
        assert "no unauthenticated registration route" in reason
