"""Tests for detect_open_registration — open user self-registration detection.

Covers the attack_surface[] primary path, the .route-inventory.json fallback
(2026-06-06 juice-shop regression: POST /api/Users present in the 112-route
inventory but absent from the curated 23-row attack_surface[]), and the
admin-create-user false-positive guards.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import detect_open_registration as D  # noqa: E402

detect = D.detect


def _route(path, method="POST", authn="unknown", authz="unknown", mgmt=False):
    return {
        "method": method,
        "path": path,
        "authn_signal": authn,
        "authz_signal": authz,
        "management_surface": mgmt,
    }


def _write_yaml(output_dir: Path, data) -> None:
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _read_yaml(output_dir: Path):
    return yaml.safe_load((output_dir / "threat-model.yaml").read_text(encoding="utf-8"))


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

    def test_non_dict_attack_surface_entries_are_ignored(self):
        ok, reason = detect({"attack_surface": ["not-an-entry"]})
        assert ok is False
        assert "no unauthenticated registration route" in reason


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


class TestMatcherEdges:
    def test_empty_and_non_post_entries_do_not_match(self):
        assert D._is_registration_entry("") is False
        assert D._is_registration_entry("GET /register") is False
        assert D._is_registration_entry("POST /users/create") is True


class TestCli:
    def test_usage_missing_yaml_parse_error_and_non_mapping_yaml(self, tmp_path, capsys):
        assert D.main([]) == 2
        assert "Usage:" in capsys.readouterr().err

        assert D.main([str(tmp_path)]) == 1
        assert "no yaml" in capsys.readouterr().err

        (tmp_path / "threat-model.yaml").write_text("attack_surface: [\n", encoding="utf-8")
        assert D.main([str(tmp_path)]) == 1
        assert "parse failed" in capsys.readouterr().err

        _write_yaml(tmp_path, ["not-a-mapping"])
        assert D.main([str(tmp_path)]) == 1

    def test_main_uses_route_inventory_and_repairs_non_dict_meta(self, tmp_path, capsys):
        _write_yaml(tmp_path, {"meta": "not-a-dict", "attack_surface": []})
        (tmp_path / ".route-inventory.json").write_text(
            json.dumps({"routes": [_route("/api/Users", authn="middleware_present")]}),
            encoding="utf-8",
        )

        assert D.main([str(tmp_path)]) == 0

        data = _read_yaml(tmp_path)
        assert data["meta"] == {"open_user_registration": True}
        assert "open_user_registration=True" in capsys.readouterr().out

    def test_main_ignores_unreadable_route_inventory(self, tmp_path, capsys):
        _write_yaml(tmp_path, {"attack_surface": []})
        (tmp_path / ".route-inventory.json").write_text("{not-json", encoding="utf-8")

        assert D.main([str(tmp_path)]) == 0

        data = _read_yaml(tmp_path)
        assert data["meta"]["open_user_registration"] is False
        assert "open_user_registration=False" in capsys.readouterr().out
