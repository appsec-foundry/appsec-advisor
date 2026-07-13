"""Tests for scripts/validate_org_profile.py.

Validates the bundled fixture profile, then exercises each semantic rule
through tiny mutations on a deep-copied dict instead of writing many YAML
fixtures by hand.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "validate_org_profile.py"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "org-profiles" / "acme"
FIXTURE_PATH = FIXTURE_DIR / "org-profile.yaml"


def _load_module():
    if "validate_org_profile" in sys.modules:
        return sys.modules["validate_org_profile"]
    spec = importlib.util.spec_from_file_location("validate_org_profile", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["validate_org_profile"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


vop = _load_module()


@pytest.fixture
def acme_profile() -> dict:
    return vop._load_yaml(FIXTURE_PATH)


def test_valid_org_profile_fixture_passes(acme_profile):
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert errors == [], errors


def test_default_preset_must_exist(acme_profile):
    acme_profile["default_preset"] = "no-such-preset"
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("default_preset" in e for e in errors), errors


def test_unknown_top_level_key_fails(acme_profile):
    acme_profile["surprise_block"] = {"any": "value"}
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("surprise_block" in e for e in errors), errors


def test_unknown_preset_key_fails(acme_profile):
    acme_profile["presets"]["ci-standard"]["mystery"] = True
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("mystery" in e for e in errors), errors


def test_branding_block_validates(acme_profile):
    acme_profile["branding"] = {
        "report_title": "Security Assessment",
        "contact_name": "Jane Doe",
        "contact_email": "jane@acme.io",
        "logo": "https://acme.io/logo.png",
    }
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert errors == [], errors


def test_branding_unknown_key_fails(acme_profile):
    acme_profile["branding"] = {"tagline": "nope"}
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("tagline" in e for e in errors), errors


def test_context_path_must_stay_under_profile_dir(acme_profile):
    acme_profile["llm_context"]["documents"][0]["path"] = "../../../etc/passwd"
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("outside" in e for e in errors), errors


def test_context_absolute_path_rejected(acme_profile):
    acme_profile["llm_context"]["documents"][0]["path"] = "/etc/passwd"
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("relative" in e for e in errors), errors


def test_context_symlink_escape_fails(tmp_path, acme_profile):
    # Copy fixture into a tmp dir, then plant a symlink that points
    # outside it and reference it from llm_context.documents.
    profile_dir = tmp_path / "profile"
    (profile_dir / "context").mkdir(parents=True)
    (profile_dir / "context" / "leak.md").symlink_to("/etc/hostname")
    acme_profile["llm_context"]["documents"].append({"id": "leak", "path": "context/leak.md", "purpose": "other"})
    errors = vop.validate(acme_profile, profile_dir)
    assert any("symlink" in e or "outside" in e for e in errors), errors


def test_preset_context_document_ids_must_exist(acme_profile):
    acme_profile["presets"]["appsec-verification"]["context"]["document_ids"].append("ghost")
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("ghost" in e for e in errors), errors


def test_target_profile_default_requires_repo_path(acme_profile):
    acme_profile["presets"]["release-review"]["target"] = {"repo": "profile_default"}
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("profile_default" in e for e in errors), errors


def test_output_dir_unknown_token_rejected(acme_profile):
    acme_profile["presets"]["appsec-verification"]["target"]["output_dir"] = "../{secret_token}"
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("secret_token" in e for e in errors), errors


def test_output_dir_with_git_component_rejected(acme_profile):
    acme_profile["presets"]["release-review"]["target"]["output_dir"] = ".git/something"
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any(".git" in e for e in errors), errors


def test_requirements_url_with_credentials_rejected(acme_profile):
    acme_profile["requirements"]["source"]["requirements_yaml_url"] = "https://user:secret@example.test/x.yaml"
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("credentials" in e for e in errors), errors


def test_skill_toggle_unknown_skill_rejected(acme_profile):
    acme_profile["skill_toggles"]["not-a-skill"] = True
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("not-a-skill" in e for e in errors), errors


def test_skill_toggle_disabled_requires_reason(acme_profile):
    acme_profile["skill_toggles"]["export-threat-model"] = {"enabled": False}
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("reason" in e for e in errors), errors


def test_compatibility_accepts_current_plugin_version(acme_profile):
    # Fixture uses ">=0.0 <999.0" which always accepts the local plugin.
    errors = vop.validate(acme_profile, FIXTURE_DIR, plugin_version="0.4.0-beta")
    assert errors == [], errors


def test_compatibility_rejects_unsupported_core(acme_profile):
    acme_profile["compatibility"]["core"] = ">=99.0"
    errors = vop.validate(acme_profile, FIXTURE_DIR, plugin_version="0.4.0-beta")
    assert any("compatibility" in e for e in errors), errors


def test_api_version_const_enforced(acme_profile):
    # v1 and v2 are the supported api_versions; anything outside the enum
    # (here a hypothetical v3) must be rejected against the api_version field.
    acme_profile["api_version"] = "appsec-advisor.org-profile/v3"
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("api_version" in e for e in errors), errors


def test_validator_returns_nonzero_on_errors(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("api_version: wrong\n")
    rc = vop.main([str(bad)])
    assert rc == 1


def test_validator_returns_zero_on_success():
    rc = vop.main([str(FIXTURE_PATH), "--plugin-version", "0.4.0-beta"])
    assert rc == 0


# ---------------------------------------------------------------------------
# abuse_cases block (added with the §9 Abuse Cases feature)
# ---------------------------------------------------------------------------


def test_abuse_cases_block_with_defaults_passes(acme_profile):
    acme_profile["abuse_cases"] = {"inherit_defaults": True, "disable": ["AC-T-002"]}
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert errors == [], errors


def test_abuse_cases_disable_pattern_enforced(acme_profile):
    acme_profile["abuse_cases"] = {"disable": ["not-an-id"]}
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("abuse_cases" in e or "disable" in e for e in errors), errors


def test_abuse_cases_unknown_key_rejected(acme_profile):
    acme_profile["abuse_cases"] = {"mystery": True}
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("mystery" in e for e in errors), errors


def test_abuse_cases_absent_skips_resolution(acme_profile):
    # No abuse_cases block → no abuse-case resolution errors leak in.
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert not any("abuse_cases" in e for e in errors), errors


# ---------------------------------------------------------------------------
# mcp block (org MCP endpoints emitted into the packaged plugin's .mcp.json)
# ---------------------------------------------------------------------------


def test_mcp_http_server_passes(acme_profile):
    acme_profile["mcp"] = {
        "servers": {
            "acme-sast": {
                "type": "http",
                "url": "${ACME_SAST_MCP_URL}",
                "headers": {"Authorization": "Bearer ${ACME_SAST_TOKEN}"},
            }
        }
    }
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert errors == [], errors


def test_mcp_stdio_server_passes(acme_profile):
    acme_profile["mcp"] = {"servers": {"acme-sca": {"command": "${CLAUDE_PLUGIN_ROOT}/bin/sca", "args": ["--json"]}}}
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert errors == [], errors


def test_mcp_server_without_url_or_command_fails(acme_profile):
    acme_profile["mcp"] = {"servers": {"empty": {"type": "http"}}}
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("url" in e and "command" in e for e in errors), errors


def test_mcp_url_with_credentials_rejected(acme_profile):
    acme_profile["mcp"] = {"servers": {"acme-sast": {"url": "https://user:secret@sast.acme.test/mcp"}}}
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("credentials" in e for e in errors), errors


def test_mcp_unknown_server_key_rejected(acme_profile):
    acme_profile["mcp"] = {"servers": {"acme-sast": {"url": "https://sast.acme.test/mcp", "mystery": 1}}}
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("mystery" in e for e in errors), errors


def test_mcp_invalid_server_name_rejected(acme_profile):
    acme_profile["mcp"] = {"servers": {"Bad Name": {"url": "https://sast.acme.test/mcp"}}}
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("mcp" in e.lower() or "servers" in e for e in errors), errors


def test_mcp_absent_skips_check(acme_profile):
    assert vop._check_mcp(acme_profile) == []


# ---------------------------------------------------------------------------
# Coverage: unit-level branches for the semantic helpers + CLI paths
# ---------------------------------------------------------------------------


def test_schema_errors_missing_jsonschema(monkeypatch):
    """When jsonschema is unimportable, _schema_errors returns the install hint."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "jsonschema":
            raise ImportError("no jsonschema")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    out = vop._schema_errors({}, {})
    assert out == ["jsonschema package not installed; cannot validate profile schema"]


def test_check_abuse_cases_resolver_load_failure(acme_profile, monkeypatch):
    """If the abuse-case resolver module cannot be loaded, surface the error."""
    acme_profile["abuse_cases"] = {"inherit_defaults": True}

    def boom():
        raise ImportError("cannot import resolver")

    monkeypatch.setattr(vop, "_rac_module", boom)
    errors = vop._check_abuse_cases(acme_profile, FIXTURE_DIR)
    assert errors and "cannot load resolver" in errors[0]


def test_resolve_under_empty_path():
    path, err = vop._resolve_under(FIXTURE_DIR, "")
    assert path is None
    assert err == "path is empty"


def test_resolve_under_symlink_traversal(tmp_path):
    profile_dir = tmp_path / "profile"
    (profile_dir / "sub").mkdir(parents=True)
    # symlink a directory inside the profile dir, pointing elsewhere-but-still-inside
    real = profile_dir / "real"
    real.mkdir()
    (real / "note.md").write_text("hi")
    link = profile_dir / "linkdir"
    link.symlink_to(real)
    path, err = vop._resolve_under(profile_dir, "linkdir/note.md")
    assert path is None
    assert "symlink" in err


def test_check_llm_context_duplicate_doc_id(acme_profile):
    docs = acme_profile["llm_context"]["documents"]
    docs.append({"id": docs[0]["id"], "path": "context/sso.md", "purpose": "dup"})
    errors = vop._check_llm_context_paths(acme_profile, FIXTURE_DIR)
    assert any("duplicate document id" in e for e in errors), errors


def test_check_requirements_url_bad_scheme(acme_profile):
    acme_profile["requirements"]["source"]["requirements_yaml_url"] = "ftp://example.test/x.yaml"
    errors = vop._check_requirements_url(acme_profile)
    assert any("scheme" in e and "ftp" in e for e in errors), errors


def test_parse_version_non_numeric_and_empty_chunks():
    # leading empty chunk (".5") skips; "1.x" stops at the non-numeric chunk.
    assert vop._parse_version(".5") == (5,)
    assert vop._parse_version("1.x.3") == (1,)
    assert vop._parse_version("abc") == (0,)


def test_check_compatibility_empty_spec_ok():
    assert vop._check_compatibility({"compatibility": {"core": ""}}, "1.0.0") == []
    assert vop._check_compatibility({}, "1.0.0") == []


def test_check_compatibility_unparseable_token():
    errors = vop._check_compatibility({"compatibility": {"core": "~=1.0"}}, "1.0.0")
    assert errors and "not understood" in errors[0]


def test_read_plugin_version_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(vop, "PLUGIN_ROOT", tmp_path)
    assert vop._read_plugin_version() == "0.0.0"


def test_read_plugin_version_bad_json(monkeypatch, tmp_path):
    meta_dir = tmp_path / ".claude-plugin"
    meta_dir.mkdir()
    (meta_dir / "plugin.json").write_text("{not json")
    monkeypatch.setattr(vop, "PLUGIN_ROOT", tmp_path)
    assert vop._read_plugin_version() == "0.0.0"


def test_read_plugin_version_ok(monkeypatch, tmp_path):
    meta_dir = tmp_path / ".claude-plugin"
    meta_dir.mkdir()
    (meta_dir / "plugin.json").write_text('{"version": "9.9.9"}')
    monkeypatch.setattr(vop, "PLUGIN_ROOT", tmp_path)
    assert vop._read_plugin_version() == "9.9.9"


def test_validate_schema_file_missing(monkeypatch, acme_profile, tmp_path):
    missing = tmp_path / "no-schema.yaml"
    monkeypatch.setattr(vop, "SCHEMA_PATH", missing)
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert errors and errors[0].startswith("schema file missing")


def test_main_file_not_found(tmp_path, capsys):
    rc = vop.main([str(tmp_path / "nope.yaml")])
    assert rc == 2
    assert "file not found" in capsys.readouterr().err


def test_main_yaml_parse_error(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("key: [unterminated\n")
    rc = vop.main([str(bad)])
    assert rc == 2
    assert "failed to parse YAML" in capsys.readouterr().err


def test_main_json_output_valid(capsys):
    rc = vop.main([str(FIXTURE_PATH), "--plugin-version", "0.4.0-beta", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["valid"] is True
    assert payload["errors"] == []


def test_main_json_output_invalid(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("api_version: wrong\n")
    rc = vop.main([str(bad), "--json"])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["valid"] is False
    assert payload["errors"]


def test_module_runs_as_script():
    import subprocess

    res = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), str(FIXTURE_PATH), "--plugin-version", "0.4.0-beta"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "VALID" in res.stdout
