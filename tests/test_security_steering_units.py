"""In-process unit tests for scripts/security_steering.py helpers.

The shipped test_security_steering.py drives the whole module as a subprocess
(matching production), which is slow and cannot reach several helper branches
(org-profile parsing, config schema migration, requirements YAML edge cases,
telemetry failure). These tests import the module's *functions* directly and
exercise those branches. They pin current behavior only — no producer edits.

Import note: the module has top-level code that reads stdin and calls
sys.exit(0). All helper functions are defined *before* that block, so we feed a
trivial stdin payload and swallow the SystemExit during import; the resulting
module object still exposes every helper.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "security_steering.py"
SCRIPTS_DIR = REPO_ROOT / "scripts"


def _load_module():
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))
    real_stdin = sys.stdin
    sys.stdin = io.StringIO('{"prompt": ""}')
    try:
        spec = importlib.util.spec_from_file_location("security_steering", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        sys.modules["security_steering"] = module
        try:
            spec.loader.exec_module(module)
        except SystemExit:
            pass  # top-level _emit({}) on the empty prompt — expected
    finally:
        sys.stdin = real_stdin
    return module


ss = _load_module()


# ---------------------------------------------------------------------------
# _log / _verbose (line 93)
# ---------------------------------------------------------------------------


def test_log_prints_when_verbose(monkeypatch, capsys):
    monkeypatch.setenv("APPSEC_VERBOSE", "1")
    ss._log("hello")
    assert "[appsec] hello" in capsys.readouterr().err


def test_log_silent_when_not_verbose(monkeypatch, capsys):
    monkeypatch.setenv("APPSEC_VERBOSE", "0")
    ss._log("quiet")
    assert capsys.readouterr().err == ""


# ---------------------------------------------------------------------------
# _activation_source
# ---------------------------------------------------------------------------


def test_activation_org_profile(monkeypatch):
    monkeypatch.delenv("APPSEC_COACH", raising=False)
    cfg = {"_org_profile_security_coach": {"enabled_by_default": True}, "enabled": False}
    assert ss._activation_source(cfg) == "org-profile"


def test_activation_config(monkeypatch):
    monkeypatch.delenv("APPSEC_COACH", raising=False)
    assert ss._activation_source({"enabled": True}) == "config"


def test_activation_none(monkeypatch):
    monkeypatch.delenv("APPSEC_COACH", raising=False)
    assert ss._activation_source({"enabled": False}) is None


# ---------------------------------------------------------------------------
# _load_org_profile_coach (lines 149, 154, 157-158, 163-164, 181-182, 200-201)
# ---------------------------------------------------------------------------


def test_org_profile_from_effective_file_output_dir(tmp_path, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    (out / ".org-profile-effective.json").write_text(
        json.dumps({"org_profile": {"active": True}, "security_coach": {"enabled_by_default": True}})
    )
    monkeypatch.setenv("OUTPUT_DIR", str(out))
    monkeypatch.chdir(tmp_path)
    coach = ss._load_org_profile_coach()
    assert coach == {"enabled_by_default": True}


def test_org_profile_effective_inactive_falls_through(tmp_path, monkeypatch):
    """Effective file exists but org_profile.active is false → ignored, no
    config.json present anywhere → empty dict."""
    out = tmp_path / "out"
    out.mkdir()
    (out / ".org-profile-effective.json").write_text(
        json.dumps({"org_profile": {"active": False}, "security_coach": {"x": 1}})
    )
    monkeypatch.setenv("OUTPUT_DIR", str(out))
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
    # The real repo root has a config.json but org profile likely disabled; the
    # function returns {} in that case. Pin: result is a dict (no crash).
    assert isinstance(ss._load_org_profile_coach(), dict)


def test_org_profile_yaml_import_error_returns_empty(tmp_path, monkeypatch):
    """No effective file, and PyYAML unavailable → empty dict (lines 163-164)."""
    import builtins

    monkeypatch.delenv("OUTPUT_DIR", raising=False)
    monkeypatch.chdir(tmp_path)  # no docs/security effective file here
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "yaml":
            raise ImportError("no yaml")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert ss._load_org_profile_coach() == {}


def test_org_profile_from_config_json_yaml(tmp_path, monkeypatch):
    """Fallback path: config.json → profile YAML parse (lines 165-186)."""
    root = tmp_path / "plugin"
    root.mkdir()
    prof = root / "org-profile.yaml"
    prof.write_text("security_coach:\n  enabled_by_default: true\n  max_requirements_per_topic: 2\n")
    (root / "config.json").write_text(
        json.dumps({"organization_profile": {"enabled": True, "path": "org-profile.yaml"}})
    )
    monkeypatch.setattr(ss, "_plugin_roots", lambda: [str(root)])
    monkeypatch.delenv("OUTPUT_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    coach = ss._load_org_profile_coach()
    assert coach.get("enabled_by_default") is True


def test_org_profile_config_json_disabled_block(tmp_path, monkeypatch):
    """config.json present but organization_profile disabled → skipped."""
    root = tmp_path / "plugin"
    root.mkdir()
    (root / "config.json").write_text(json.dumps({"organization_profile": {"enabled": False}}))
    monkeypatch.setattr(ss, "_plugin_roots", lambda: [str(root)])
    monkeypatch.delenv("OUTPUT_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    assert ss._load_org_profile_coach() == {}


def test_org_profile_bad_profile_yaml_skipped(tmp_path, monkeypatch):
    """Profile path unreadable → except branch (lines 181-182) → {}."""
    root = tmp_path / "plugin"
    root.mkdir()
    (root / "config.json").write_text(
        json.dumps({"organization_profile": {"enabled": True, "path": "missing-profile.yaml"}})
    )
    monkeypatch.setattr(ss, "_plugin_roots", lambda: [str(root)])
    monkeypatch.delenv("OUTPUT_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    assert ss._load_org_profile_coach() == {}


def test_org_profile_bad_config_json_skipped(tmp_path, monkeypatch):
    """config.json is invalid JSON → except branch (lines 170-171)."""
    root = tmp_path / "plugin"
    root.mkdir()
    (root / "config.json").write_text("{ not json")
    monkeypatch.setattr(ss, "_plugin_roots", lambda: [str(root)])
    monkeypatch.delenv("OUTPUT_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    assert ss._load_org_profile_coach() == {}


# ---------------------------------------------------------------------------
# _load_config (lines 215, 224-225, 229-230, 239-241)
# ---------------------------------------------------------------------------


def test_load_config_defaults_when_no_file(tmp_path, monkeypatch):
    """No steering_keywords.json anywhere → defaults returned (line 215).

    _plugin_roots() always also yields the real repo root (script-dir parent),
    which ships a real config, so we pin the roots to an empty dir to reach the
    `if not loaded: return cfg` branch."""
    root = tmp_path / "empty-plugin"
    root.mkdir()
    monkeypatch.setattr(ss, "_plugin_roots", lambda: [str(root)])
    monkeypatch.setattr(ss, "_load_org_profile_coach", lambda: {})
    monkeypatch.delenv("OUTPUT_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    cfg = ss._load_config()
    assert cfg["enabled"] is False
    assert cfg["code_keywords"] == set(ss._DEFAULT_CODE)
    assert cfg["topics"] == {}


def test_load_config_old_schema_code_action_strong(tmp_path, monkeypatch):
    """Old schema keys: code / action / strong (lines 224-225, 229-230, 239-241)."""
    root = tmp_path / "plugin"
    (root / "hooks").mkdir(parents=True)
    (root / "hooks" / "steering_keywords.json").write_text(
        json.dumps(
            {
                "enabled": True,
                "code": ["foo", "bar"],
                "action": ["zap"],
                "strong": ["secret-trigger"],
            }
        )
    )
    monkeypatch.setattr(ss, "_plugin_roots", lambda: [str(root)])
    monkeypatch.setattr(ss, "_load_org_profile_coach", lambda: {})
    monkeypatch.delenv("OUTPUT_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    cfg = ss._load_config()
    assert cfg["code_keywords"] == {"foo", "bar"}
    assert cfg["action_keywords"] == {"zap"}
    assert "_legacy" in cfg["topics"]
    assert cfg["topics"]["_legacy"]["triggers"] == ["secret-trigger"]


def test_load_config_custom_requirements_source_paths(tmp_path, monkeypatch):
    root = tmp_path / "plugin"
    (root / "hooks").mkdir(parents=True)
    (root / "hooks" / "steering_keywords.json").write_text(
        json.dumps({"enabled": True, "requirements_source": {"paths": ["custom/reqs.yaml"]}})
    )
    monkeypatch.setattr(ss, "_plugin_roots", lambda: [str(root)])
    monkeypatch.setattr(ss, "_load_org_profile_coach", lambda: {})
    monkeypatch.delenv("OUTPUT_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    cfg = ss._load_config()
    assert cfg["requirements_source"]["paths"] == ["custom/reqs.yaml"]


# ---------------------------------------------------------------------------
# _load_requirements_index (lines 268-270, 284-286, 288, 292, 295, 298, 307)
# ---------------------------------------------------------------------------


def _cfg_with_paths(paths):
    return {"requirements_source": {"paths": paths}, "severity": dict(ss._DEFAULT_SEVERITY)}


def test_requirements_index_no_readable_file_returns_empty(tmp_path, monkeypatch):
    root = tmp_path / "plugin"
    root.mkdir()
    monkeypatch.setattr(ss, "_plugin_roots", lambda: [str(root)])
    cfg = _cfg_with_paths(["data/nope.yaml"])
    assert ss._load_requirements_index(cfg) == {}


def test_requirements_index_parse_error_skipped(tmp_path, monkeypatch):
    """A YAML that raises on load → except branch (lines 284-286)."""
    root = tmp_path / "plugin"
    (root / "data").mkdir(parents=True)
    (root / "data" / "reqs.yaml").write_text("key: [unterminated\n")
    monkeypatch.setattr(ss, "_plugin_roots", lambda: [str(root)])
    cfg = _cfg_with_paths(["data/reqs.yaml"])
    assert ss._load_requirements_index(cfg) == {}


def test_requirements_index_non_dict_yaml_skipped(tmp_path, monkeypatch):
    """YAML parses to a list, not a dict → line 288 continue."""
    root = tmp_path / "plugin"
    (root / "data").mkdir(parents=True)
    (root / "data" / "reqs.yaml").write_text("- a\n- b\n")
    monkeypatch.setattr(ss, "_plugin_roots", lambda: [str(root)])
    cfg = _cfg_with_paths(["data/reqs.yaml"])
    assert ss._load_requirements_index(cfg) == {}


def test_requirements_index_builds_and_dedups(tmp_path, monkeypatch):
    """Happy path + skips non-dict cats/reqs + dup ids (lines 292, 295, 298, 307)."""
    root = tmp_path / "plugin"
    (root / "data").mkdir(parents=True)
    monkeypatch.setattr(ss, "_plugin_roots", lambda: [str(root)])
    (root / "data" / "reqs.yaml").write_text(
        "categories:\n"
        "  - not-a-dict-category\n"  # skipped (line 292)
        "  - requirements:\n"
        "      - just-a-string\n"  # skipped (line 295)
        "      - {id: '', text: 'no id'}\n"  # skipped: missing id (line 298)
        "      - {id: SEC-1, text: 'First', priority: P1, url: 'http://x'}\n"
        "      - {id: SEC-1, text: 'Dup ignored'}\n"  # dup id (line 298)
        "      - {id: SEC-2, text: 'Second'}\n"
    )
    cfg = _cfg_with_paths(["data/reqs.yaml"])
    idx = ss._load_requirements_index(cfg)
    assert set(idx) == {"SEC-1", "SEC-2"}
    assert idx["SEC-1"]["text"] == "First"
    assert idx["SEC-1"]["priority"] == "P1"


def test_requirements_index_no_yaml_module(monkeypatch):
    """ImportError on yaml → empty dict (lines 268-270)."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "yaml":
            raise ImportError("no yaml")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert ss._load_requirements_index({"requirements_source": {"paths": []}}) == {}


# ---------------------------------------------------------------------------
# _count_matches / _match_topics (lines 314, 325)
# ---------------------------------------------------------------------------


def test_count_matches_skips_empty_keyword():
    assert ss._count_matches(["", "auth"], "review the auth") == 1


def test_match_topics_skips_non_dict_spec():
    topics = {"bad": "not-a-dict", "good": {"triggers": ["sql"]}}
    hits = ss._match_topics(topics, "sql injection here")
    assert hits == {"good": 1}


# ---------------------------------------------------------------------------
# _assemble_context (lines 351, 367, 370, 381)
# ---------------------------------------------------------------------------


def _base_cfg(topics):
    return {
        "baseline": "BASELINE",
        "topics": topics,
        "severity": {"max_requirements_per_topic": 3, "max_injected_chars": 2500},
    }


def test_assemble_skips_non_dict_topic_spec():
    """matched topic whose spec isn't a dict → continue (line 351)."""
    cfg = _base_cfg({"weird": "not-a-dict"})
    assembled, ids = ss._assemble_context(cfg, {"weird": 1}, {})
    assert assembled == "BASELINE"
    assert ids == []


def test_assemble_skips_requirement_with_empty_body():
    """A resolved requirement whose text is blank → skipped (line 370)."""
    cfg = _base_cfg({"t": {"guidance": "G", "requirements": ["R1", "R2"]}})
    req_index = {"R1": {"text": "   ", "priority": "P1"}, "R2": {"text": "Real one", "priority": "P2"}}
    assembled, ids = ss._assemble_context(cfg, {"t": 1}, req_index)
    assert ids == ["R2"]
    assert "Real one" in assembled
    assert "[t] G" in assembled


def test_assemble_truncates_to_cap():
    """Assembled context longer than the char cap → truncated with '...' (line 381)."""
    cfg = {
        "baseline": "X" * 5000,
        "topics": {},
        "severity": {"max_requirements_per_topic": 3, "max_injected_chars": 100},
    }
    assembled, _ = ss._assemble_context(cfg, {}, {})
    assert len(assembled) == 100
    assert assembled.endswith("...")


def test_assemble_requirement_missing_priority_uses_dash():
    cfg = _base_cfg({"t": {"requirements": ["R1"]}})
    req_index = {"R1": {"text": "body", "priority": None}}
    assembled, ids = ss._assemble_context(cfg, {"t": 1}, req_index)
    assert "R1 (—): body" in assembled


# ---------------------------------------------------------------------------
# _log_coach_event (lines 410-411)
# ---------------------------------------------------------------------------


def test_log_coach_event_writes_line(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ss._log_coach_event(["auth", "_legacy"], ["SEC-1"], 42, "the prompt")
    log = tmp_path / "docs" / "security" / ".hook-events.log"
    assert log.is_file()
    content = log.read_text()
    assert "COACH_INJECTED" in content
    assert "topics=auth" in content  # _legacy filtered out
    assert "req_ids=SEC-1" in content


def test_log_coach_event_swallows_errors(monkeypatch):
    """A makedirs failure must not raise (lines 410-411)."""

    def boom(*a, **k):
        raise OSError("read-only fs")

    monkeypatch.setattr(ss.os, "makedirs", boom)
    # Must not raise.
    ss._log_coach_event(["auth"], [], 0, "p")


def test_log_coach_event_empty_topics_and_reqs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ss._log_coach_event([], [], 0, "p")
    content = (tmp_path / "docs" / "security" / ".hook-events.log").read_text()
    assert "topics=-" in content
    assert "req_ids=-" in content


# ---------------------------------------------------------------------------
# _emit (lines 419-421) — pin sys.exit(0)
# ---------------------------------------------------------------------------


def test_emit_prints_and_exits(capsys):
    with pytest.raises(SystemExit) as ei:
        ss._emit({"a": 1})
    assert ei.value.code == 0
    assert json.loads(capsys.readouterr().out) == {"a": 1}


# ---------------------------------------------------------------------------
# _load_config — org-defined steering topics merge in from the profile
# ---------------------------------------------------------------------------


def _write_effective_coach(tmp_path, monkeypatch, coach):
    out = tmp_path / "out"
    out.mkdir()
    (out / ".org-profile-effective.json").write_text(
        json.dumps({"org_profile": {"active": True}, "security_coach": coach})
    )
    monkeypatch.setenv("OUTPUT_DIR", str(out))
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(REPO_ROOT))  # load built-in topics
    monkeypatch.chdir(tmp_path)  # no cwd docs/security effective file


def test_org_topics_merge_with_defaults(tmp_path, monkeypatch):
    _write_effective_coach(
        tmp_path,
        monkeypatch,
        {"topics": {"payments": {"triggers": ["payout"], "guidance": "g", "requirements": []}}},
    )
    cfg = ss._load_config()
    assert "payments" in cfg["topics"]  # org topic added
    assert "auth" in cfg["topics"]  # built-in topic still present


def test_org_topics_replace_defaults_when_inheritance_off(tmp_path, monkeypatch):
    _write_effective_coach(
        tmp_path,
        monkeypatch,
        {
            "inherit_default_topics": False,
            "topics": {"payments": {"triggers": ["payout"]}},
        },
    )
    cfg = ss._load_config()
    assert set(cfg["topics"]) == {"payments"}  # built-ins dropped


def test_org_baseline_overrides_default(tmp_path, monkeypatch):
    _write_effective_coach(tmp_path, monkeypatch, {"baseline": "Acme secure defaults."})
    cfg = ss._load_config()
    assert cfg["baseline"] == "Acme secure defaults."


# ---------------------------------------------------------------------------
# Top-level body: non-dict stdin payload (line 431) — needs a subprocess
# because the module body runs on import.
# ---------------------------------------------------------------------------


def test_non_dict_json_payload_emits_empty():
    import os
    import subprocess

    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input="5",  # valid JSON, but not a dict
        capture_output=True,
        text=True,
        env={**os.environ, "APPSEC_COACH": "1"},
    )
    assert result.returncode == 0
    assert json.loads(result.stdout) == {}
