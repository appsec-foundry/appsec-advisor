"""Tests for scripts/check_skill_enabled.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_skill_enabled.py"


def _load_module():
    if "check_skill_enabled" in sys.modules:
        return sys.modules["check_skill_enabled"]
    spec = importlib.util.spec_from_file_location("check_skill_enabled", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["check_skill_enabled"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


cse = _load_module()


def _write_effective(tmp_path: Path, toggles: dict, active: bool = True) -> Path:
    payload = {
        "org_profile": {"active": active, "id": "acme"},
        "preset": {"name": "ci-standard", "base_mode": "standard"},
        "skill_toggles": toggles,
    }
    (tmp_path / ".org-profile-effective.json").write_text(json.dumps(payload))
    return tmp_path


def test_no_effective_file_returns_enabled(tmp_path):
    rc, _ = cse.check("export-threat-model", tmp_path, False)
    assert rc == cse.EXIT_ENABLED


def test_inactive_profile_returns_enabled(tmp_path):
    _write_effective(tmp_path, {"export-threat-model": False}, active=False)
    rc, _ = cse.check("export-threat-model", tmp_path, False)
    assert rc == cse.EXIT_ENABLED


def test_enabled_skill_passes(tmp_path):
    _write_effective(tmp_path, {"export-threat-model": {"enabled": True}})
    rc, _ = cse.check("export-threat-model", tmp_path, False)
    assert rc == cse.EXIT_ENABLED


def test_disabled_user_skill_hard(tmp_path):
    _write_effective(tmp_path, {"export-threat-model": {"enabled": False, "reason": "central"}})
    rc, msg = cse.check("export-threat-model", tmp_path, False)
    assert rc == cse.EXIT_DISABLED_HARD
    assert "central" in msg


def test_disabled_operational_skill_soft(tmp_path):
    _write_effective(tmp_path, {"status": {"enabled": False, "reason": "shh"}})
    rc, msg = cse.check("status", tmp_path, False)
    assert rc == cse.EXIT_DISABLED_SOFT


def test_help_only_disabled_returns_help_code(tmp_path):
    _write_effective(tmp_path, {"export-threat-model": {"enabled": False, "reason": "central"}})
    rc, _ = cse.check("export-threat-model", tmp_path, True)
    assert rc == cse.EXIT_DISABLED_HELP_OK


def test_bool_shorthand_true(tmp_path):
    _write_effective(tmp_path, {"export-threat-model": True})
    rc, _ = cse.check("export-threat-model", tmp_path, False)
    assert rc == cse.EXIT_ENABLED


def test_bool_shorthand_false_treated_as_disabled(tmp_path):
    _write_effective(tmp_path, {"export-threat-model": False})
    rc, _ = cse.check("export-threat-model", tmp_path, False)
    assert rc == cse.EXIT_DISABLED_HARD
