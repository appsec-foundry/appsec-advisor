"""Tests for scripts/resolve_requirements_source.py."""

from __future__ import annotations

import json
from pathlib import Path

import resolve_requirements_source as rrs

REPO_ROOT = Path(__file__).parent.parent


PROFILE_RS = {
    "requirements_yaml_url": "https://security.example.test/x.yaml",
    "label": "Acme",
    "human_source_url": "https://wiki.example.test/x",
    "fail_mode": "cache_fallback",
    "cache": True,
    "create_threat_model": {"default_active": True, "quick_default_active": False},
    "standalone_audit": {"enabled": True},
}
EFFECTIVE = {"requirements_source": PROFILE_RS}
LEGACY = {"requirements_source": {"enabled": False, "requirements_yaml_url": None}}


def test_load_effective_missing_invalid_and_valid(tmp_path):
    assert rrs._load_effective(None) is None
    assert rrs._load_effective(tmp_path / "missing.json") is None

    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    assert rrs._load_effective(invalid) is None

    valid = tmp_path / "effective.json"
    valid.write_text(json.dumps({"requirements_source": {"requirements_yaml_url": "https://x/reqs.yaml"}}), encoding="utf-8")
    assert rrs._load_effective(valid)["requirements_source"]["requirements_yaml_url"] == "https://x/reqs.yaml"


def test_load_legacy_default_missing_invalid_and_valid(tmp_path):
    assert rrs._load_legacy_default(tmp_path) == {}

    cfg = tmp_path / "skills" / "audit-security-requirements"
    cfg.mkdir(parents=True)
    (cfg / "config.json").write_text("{", encoding="utf-8")
    assert rrs._load_legacy_default(tmp_path) == {}

    (cfg / "config.json").write_text(
        json.dumps({"requirements_source": {"requirements_yaml_url": "https://legacy/reqs.yaml"}}),
        encoding="utf-8",
    )
    assert rrs._load_legacy_default(tmp_path)["requirements_source"]["requirements_yaml_url"] == "https://legacy/reqs.yaml"


def test_cli_url_wins():
    result = rrs.resolve(
        "https://cli.example.test/y.yaml",
        False,
        "standard",
        "create-threat-model",
        EFFECTIVE,
        LEGACY,
    )
    assert result["enabled"] is True
    assert result["url"] == "https://cli.example.test/y.yaml"
    assert result["source"] == "cli"


def test_no_requirements_wins_over_profile():
    result = rrs.resolve(None, True, "standard", "create-threat-model", EFFECTIVE, LEGACY)
    assert result["enabled"] is False
    assert result["source"] == "disabled"


def test_profile_used_when_no_cli_override():
    result = rrs.resolve(None, False, "standard", "create-threat-model", EFFECTIVE, LEGACY)
    assert result["enabled"] is True
    assert result["source"] == "org-profile"
    assert result["url"] == PROFILE_RS["requirements_yaml_url"]


def test_quick_default_inactive_disables_for_quick_mode():
    result = rrs.resolve(None, False, "quick", "create-threat-model", EFFECTIVE, LEGACY)
    assert result["enabled"] is False
    assert result["source"] == "org-profile"
    # URL stays present so status output can still show where it would
    # have come from; only enabled is gated.
    assert result["url"] == PROFILE_RS["requirements_yaml_url"]


def test_quick_default_active_enables_when_profile_allows():
    effective = {
        "requirements_source": {
            **PROFILE_RS,
            "create_threat_model": {"default_active": True, "quick_default_active": True},
        }
    }
    result = rrs.resolve(None, False, "quick", "create-threat-model", effective, LEGACY)
    assert result["enabled"] is True


def test_standalone_audit_respects_toggle():
    effective = {"requirements_source": {**PROFILE_RS, "standalone_audit": {"enabled": False}}}
    result = rrs.resolve(None, False, None, "audit-security-requirements", effective, LEGACY)
    assert result["enabled"] is False


def test_org_profile_defaults_and_verify_caller_are_enabled():
    effective = {"requirements_source": {"requirements_yaml_url": "https://security.example.test/minimal.yaml"}}

    result = rrs.resolve(None, False, "quick", "verify-requirements", effective, LEGACY)

    assert result["source"] == "org-profile"
    assert result["enabled"] is True
    assert result["fail_mode"] == "cache_fallback"
    assert result["cache"] is True


def test_org_profile_cache_false_is_preserved():
    effective = {"requirements_source": {**PROFILE_RS, "cache": False}}

    result = rrs.resolve(None, False, "standard", "create-threat-model", effective, LEGACY)

    assert result["source"] == "org-profile"
    assert result["cache"] is False


def test_legacy_fallback_when_no_profile_active():
    result = rrs.resolve(None, False, "standard", "create-threat-model", None, LEGACY)
    assert result["source"] == "legacy"
    assert result["enabled"] is False


def test_legacy_url_source_is_enabled_by_default():
    legacy = {"requirements_source": {"requirements_yaml_url": "https://legacy.example/reqs.yaml"}}

    result = rrs.resolve(None, False, "standard", "create-threat-model", None, legacy)

    assert result["source"] == "legacy"
    assert result["enabled"] is True
    assert result["url"] == "https://legacy.example/reqs.yaml"


def test_legacy_terminal_fallback_can_enable_without_url():
    legacy = {"requirements_source": {"enabled": True, "requirements_yaml_url": None}}

    result = rrs.resolve(None, False, "standard", "create-threat-model", None, legacy)

    assert result["source"] == "legacy"
    assert result["enabled"] is True
    assert result["url"] is None


# ---------------------------------------------------------------------------
# new precedence tiers: demo / local repo file / remembered sidecar
# ---------------------------------------------------------------------------
def test_demo_wins_over_profile():
    result = rrs.resolve(
        None, False, "standard", "audit-security-requirements", EFFECTIVE, LEGACY, demo_path="/p/examples/ex.yaml"
    )
    assert result["source"] == "demo"
    assert result["demo"] is True
    assert result["url"] == "/p/examples/ex.yaml"
    assert result["fail_mode"] == "fail_closed"


def test_local_repo_file_beats_org_profile():
    result = rrs.resolve(
        None, False, None, "audit-security-requirements", EFFECTIVE, LEGACY, local_path="/repo/docs/security/requirements.yaml"
    )
    assert result["source"] == "local"
    assert result["surfaced"] is True
    assert result["url"] == "/repo/docs/security/requirements.yaml"
    assert result["fail_mode"] == "fail_closed"


def test_cli_still_beats_local_and_demo():
    result = rrs.resolve(
        "https://cli/y.yaml", False, None, "audit-security-requirements", EFFECTIVE, LEGACY,
        demo_path="/p/ex.yaml", local_path="/repo/requirements.yaml",
    )
    assert result["source"] == "cli"


def test_remembered_used_when_nothing_else_and_audit():
    remembered = {"url": "https://security.example/x", "label": "ASR"}
    result = rrs.resolve(
        None, False, None, "audit-security-requirements", None, LEGACY, remembered=remembered
    )
    assert result["source"] == "remembered"
    assert result["url"] == "https://security.example/x"
    assert result["enabled"] is True


def test_remembered_not_auto_enabled_for_threat_model():
    remembered = {"url": "https://security.example/x"}
    result = rrs.resolve(None, False, "standard", "create-threat-model", None, LEGACY, remembered=remembered)
    assert result["source"] == "remembered"
    assert result["enabled"] is False  # leftover sidecar must not switch CTM on


def test_org_profile_beats_remembered():
    remembered = {"url": "https://security.example/x"}
    result = rrs.resolve(None, False, "standard", "create-threat-model", EFFECTIVE, LEGACY, remembered=remembered)
    assert result["source"] == "org-profile"


# ---------------------------------------------------------------------------
# governance: org standalone_audit:false signal (org_audit_disabled)
# ---------------------------------------------------------------------------
DISABLED_EFFECTIVE = {"requirements_source": {**PROFILE_RS, "standalone_audit": {"enabled": False}}}


def test_org_audit_disabled_signal_set_for_audit():
    result = rrs.resolve(None, False, None, "audit-security-requirements", DISABLED_EFFECTIVE, LEGACY)
    assert result["org_audit_disabled"] is True


def test_org_audit_disabled_survives_local_override():
    """A local repo catalog wins the source, but the governance signal persists
    so the skill can still block per the org policy."""
    result = rrs.resolve(
        None, False, None, "audit-security-requirements", DISABLED_EFFECTIVE, LEGACY,
        local_path="/repo/docs/security/requirements.yaml",
    )
    assert result["source"] == "local"
    assert result["org_audit_disabled"] is True


def test_org_audit_disabled_bypassed_by_cli_and_demo():
    cli = rrs.resolve("https://cli/y.yaml", False, None, "audit-security-requirements", DISABLED_EFFECTIVE, LEGACY)
    assert cli["source"] == "cli" and cli["org_audit_disabled"] is True
    demo = rrs.resolve(None, False, None, "audit-security-requirements", DISABLED_EFFECTIVE, LEGACY, demo_path="/p/ex.yaml")
    assert demo["source"] == "demo" and demo["org_audit_disabled"] is True


def test_org_audit_disabled_false_when_enabled():
    result = rrs.resolve(None, False, None, "audit-security-requirements", EFFECTIVE, LEGACY)
    assert result["org_audit_disabled"] is False


def test_org_audit_disabled_not_set_for_threat_model_caller():
    result = rrs.resolve(None, False, "standard", "create-threat-model", DISABLED_EFFECTIVE, LEGACY)
    assert result["org_audit_disabled"] is False


# ---------------------------------------------------------------------------
# CLI glue
# ---------------------------------------------------------------------------


def test_main_resolves_local_repo_catalog_and_prints_json(tmp_path, capsys):
    (tmp_path / "requirements.yaml").write_text("categories: []\n", encoding="utf-8")
    (tmp_path / ".org-profile-effective.json").write_text(json.dumps(EFFECTIVE), encoding="utf-8")

    assert rrs.main(["--output-dir", str(tmp_path)]) == 0

    out = json.loads(capsys.readouterr().out)
    assert out["source"] == "local"
    assert out["surfaced"] is True
    assert out["url"] == str(tmp_path / "requirements.yaml")


def test_main_uses_demo_path_when_requested(tmp_path, capsys):
    assert rrs.main(["--output-dir", str(tmp_path), "--demo", "--plugin-root", str(REPO_ROOT)]) == 0

    out = json.loads(capsys.readouterr().out)
    assert out["source"] == "demo"
    assert out["demo"] is True
    assert out["url"].endswith("examples/appsec-requirements-example.yaml")


def test_main_reads_remembered_sidecar_from_cache_path(tmp_path, capsys):
    cache = tmp_path / "cache" / "requirements.yaml"
    cache.parent.mkdir()
    (cache.parent / "requirements.source.json").write_text(
        json.dumps({"url": "https://remembered.example/reqs.yaml", "label": "Remembered"}),
        encoding="utf-8",
    )

    assert (
        rrs.main(
            [
                "--output-dir",
                str(tmp_path),
                "--caller",
                "audit-security-requirements",
                "--cache-path",
                str(cache),
            ]
        )
        == 0
    )

    out = json.loads(capsys.readouterr().out)
    assert out["source"] == "remembered"
    assert out["enabled"] is True
    assert out["label"] == "Remembered"
