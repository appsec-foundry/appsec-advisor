"""Tests for scripts/check_skill_enabled.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

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


@pytest.fixture(autouse=True)
def _empty_packaged_config(tmp_path, monkeypatch):
    """Point the packaged-config fallback at a build that declares no policy.

    Without this every case would read the repository's own config.json — and a
    developer's git-ignored config.local.json — so the result would depend on
    the machine rather than on the case.
    """
    root = tmp_path / "_plugin"
    root.mkdir()
    (root / "config.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(root))
    return root


def _write_packaged(root: Path, toggles: dict, local: bool = False) -> Path:
    name = "config.local.json" if local else "config.json"
    (root / name).write_text(json.dumps({"skill_toggles": toggles}), encoding="utf-8")
    return root


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


# ---------------------------------------------------------------------------
# The packaged policy — the gate before any run has happened
# ---------------------------------------------------------------------------


def test_packaged_policy_blocks_without_any_effective_file(tmp_path, _empty_packaged_config):
    """The gap this closes: the effective profile is written by a scan into its
    output directory, so before the first scan there was no policy to find and
    every skill ran, while `status` reported it as disabled."""
    _write_packaged(_empty_packaged_config, {"export-threat-model": {"enabled": False, "reason": "central"}})
    rc, msg = cse.check("export-threat-model", tmp_path, False)
    assert rc == cse.EXIT_DISABLED_HARD
    assert "packaged build" in msg
    assert "central" in msg


def test_packaged_policy_applies_with_no_output_dir_at_all(_empty_packaged_config):
    _write_packaged(_empty_packaged_config, {"export-threat-model": {"enabled": False, "reason": "central"}})
    rc, _ = cse.check("export-threat-model", None, False)
    assert rc == cse.EXIT_DISABLED_HARD


def test_a_resolved_run_outranks_the_packaged_policy(tmp_path, _empty_packaged_config):
    """The run knows what the preset and CLI resolved; the build cannot."""
    _write_packaged(_empty_packaged_config, {"export-threat-model": {"enabled": False, "reason": "central"}})
    _write_effective(tmp_path, {"export-threat-model": {"enabled": True}})
    rc, msg = cse.check("export-threat-model", tmp_path, False)
    assert rc == cse.EXIT_ENABLED
    assert "org profile" in msg


def test_an_inactive_profile_falls_back_to_the_packaged_policy(tmp_path, _empty_packaged_config):
    _write_packaged(_empty_packaged_config, {"export-threat-model": {"enabled": False, "reason": "central"}})
    _write_effective(tmp_path, {}, active=False)
    rc, _ = cse.check("export-threat-model", tmp_path, False)
    assert rc == cse.EXIT_DISABLED_HARD


def test_packaged_policy_keeps_the_operational_soft_rule(tmp_path, _empty_packaged_config):
    """A recovery skill must stay reachable however the policy arrived."""
    _write_packaged(_empty_packaged_config, {"status": {"enabled": False, "reason": "shh"}})
    rc, _ = cse.check("status", tmp_path, False)
    assert rc == cse.EXIT_DISABLED_SOFT


def test_config_local_wins_over_config(tmp_path, _empty_packaged_config):
    _write_packaged(_empty_packaged_config, {"export-threat-model": {"enabled": False, "reason": "packaged"}})
    _write_packaged(_empty_packaged_config, {"export-threat-model": {"enabled": True}}, local=True)
    rc, _ = cse.check("export-threat-model", tmp_path, False)
    assert rc == cse.EXIT_ENABLED


def test_a_damaged_config_does_not_block_a_skill(tmp_path, _empty_packaged_config):
    """Fail open: a broken config must not deny what nobody restricted."""
    (_empty_packaged_config / "config.json").write_text("{not json", encoding="utf-8")
    rc, _ = cse.check("export-threat-model", tmp_path, False)
    assert rc == cse.EXIT_ENABLED


def test_upstream_config_declares_no_policy():
    """The upstream build must gate nothing — the block is added by packaging."""
    config = json.loads((REPO_ROOT / "config.json").read_text(encoding="utf-8"))
    assert "skill_toggles" not in config


# ---------------------------------------------------------------------------
# _load_effective edge cases (lines 47, 53-54)
# ---------------------------------------------------------------------------


def test_load_effective_none_output_dir():
    assert cse._load_effective(None) is None


def test_load_effective_missing_file(tmp_path):
    assert cse._load_effective(tmp_path) is None


def test_load_effective_malformed_json(tmp_path):
    (tmp_path / ".org-profile-effective.json").write_text("{ not valid json")
    assert cse._load_effective(tmp_path) is None


# ---------------------------------------------------------------------------
# check() — toggle present but no explicit enabled key (line 65, 72)
# ---------------------------------------------------------------------------


def test_skill_toggle_absent_enabled_by_profile(tmp_path):
    # active profile, skill_toggles present but does NOT list this skill
    _write_effective(tmp_path, {"other-skill": {"enabled": False}})
    rc, msg = cse.check("export-threat-model", tmp_path, False)
    assert rc == cse.EXIT_ENABLED
    assert "enabled (org profile)" in msg


def test_cfg_enabled_default_true_when_key_missing(tmp_path):
    # cfg dict with no "enabled" key → defaults to True (enabled)
    _write_effective(tmp_path, {"export-threat-model": {"reason": "n/a"}})
    rc, _ = cse.check("export-threat-model", tmp_path, False)
    assert rc == cse.EXIT_ENABLED


def test_disabled_no_reason_uses_placeholder(tmp_path):
    _write_effective(tmp_path, {"export-threat-model": {"enabled": False}})
    rc, msg = cse.check("export-threat-model", tmp_path, False)
    assert rc == cse.EXIT_DISABLED_HARD
    assert "no reason provided" in msg


# ---------------------------------------------------------------------------
# main() / CLI dispatch (lines 84-107)
# ---------------------------------------------------------------------------


def test_main_enabled_prints_message(tmp_path, capsys):
    rc = cse.main(["export-threat-model", "--output-dir", str(tmp_path)])
    assert rc == cse.EXIT_ENABLED
    out = capsys.readouterr().out
    assert "no skill policy in effect" in out


def test_main_quiet_suppresses_output(tmp_path, capsys):
    rc = cse.main(["export-threat-model", "--output-dir", str(tmp_path), "--quiet"])
    assert rc == cse.EXIT_ENABLED
    assert capsys.readouterr().out == ""


def test_main_disabled_hard_exit_code(tmp_path):
    _write_effective(tmp_path, {"export-threat-model": {"enabled": False, "reason": "central"}})
    rc = cse.main(["export-threat-model", "--output-dir", str(tmp_path)])
    assert rc == cse.EXIT_DISABLED_HARD


def test_main_help_only_flag(tmp_path):
    _write_effective(tmp_path, {"export-threat-model": {"enabled": False, "reason": "central"}})
    rc = cse.main(["export-threat-model", "--output-dir", str(tmp_path), "--help-only"])
    assert rc == cse.EXIT_DISABLED_HELP_OK


def test_main_output_dir_from_env(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    rc = cse.main(["export-threat-model"])
    assert rc == cse.EXIT_ENABLED
    assert "no skill policy in effect" in capsys.readouterr().out


def test_main_no_output_dir_falls_through_enabled(tmp_path, monkeypatch):
    monkeypatch.delenv("OUTPUT_DIR", raising=False)
    rc = cse.main(["export-threat-model"])
    assert rc == cse.EXIT_ENABLED
