"""Unit tests for ``appsec_status.py`` — the non-live status-dump paths.

The ``--live`` snapshot machinery is covered in ``test_appsec_status_live.py``.
This file targets the plugin/config/fast-path/org-profile/render/main code
paths, monkeypatching ``_run_helper`` so the deterministic logic is exercised
without spawning the real helper scripts.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "appsec_status.py"


@pytest.fixture
def appsec_status():
    spec = importlib.util.spec_from_file_location("appsec_status", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["appsec_status"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# _emit_table (lines 43-49)
# ---------------------------------------------------------------------------


class TestEmitTable:
    def test_basic_table(self, appsec_status):
        out = appsec_status._emit_table("Title", [("key", "val"), ("longerkey", "v2")])
        assert "Title" in out
        assert "-----" in out  # underline
        assert "key" in out and "val" in out
        # keys padded to max width
        assert "longerkey" in out

    def test_empty_rows(self, appsec_status):
        out = appsec_status._emit_table("Empty", [])
        assert "Empty" in out


# ---------------------------------------------------------------------------
# _run_helper (lines 52-62)
# ---------------------------------------------------------------------------


class TestRunHelper:
    def test_runs_real_script(self, appsec_status):
        # check_skill_enabled prints a message and exits 0 with no profile
        code, out, err = appsec_status._run_helper("check_skill_enabled.py", "status")
        assert code == 0
        assert "status" in out

    def test_missing_script_returns_error_tuple(self, appsec_status, monkeypatch):
        import subprocess

        def boom(*a, **k):
            raise FileNotFoundError("nope")

        monkeypatch.setattr(subprocess, "run", boom)
        code, out, err = appsec_status._run_helper("does_not_exist.py")
        assert code == 2
        assert "nope" in err

    def test_timeout_returns_error_tuple(self, appsec_status, monkeypatch):
        import subprocess

        def boom(*a, **k):
            raise subprocess.TimeoutExpired(cmd="x", timeout=15)

        monkeypatch.setattr(subprocess, "run", boom)
        code, out, err = appsec_status._run_helper("slow.py")
        assert code == 2


# ---------------------------------------------------------------------------
# _load_plugin_json / _load_json (lines 65-79)
# ---------------------------------------------------------------------------


class TestLoaders:
    def test_load_plugin_json_real(self, appsec_status):
        data = appsec_status._load_plugin_json()
        assert isinstance(data, dict)
        # the real plugin.json has a version
        assert "version" in data

    def test_load_json_missing(self, appsec_status, tmp_path):
        assert appsec_status._load_json(tmp_path / "nope.json") is None

    def test_load_json_valid(self, appsec_status, tmp_path):
        p = tmp_path / "x.json"
        p.write_text(json.dumps({"a": 1}))
        assert appsec_status._load_json(p) == {"a": 1}

    def test_load_json_malformed(self, appsec_status, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json")
        assert appsec_status._load_json(p) is None

    def test_load_plugin_json_malformed(self, appsec_status, monkeypatch, tmp_path):
        bad = tmp_path / "plugin.json"
        bad.write_text("{broken")
        # Point PLUGIN_ROOT at a dir whose .claude-plugin/plugin.json is bad
        pdir = tmp_path / ".claude-plugin"
        pdir.mkdir()
        (pdir / "plugin.json").write_text("{broken")
        monkeypatch.setattr(appsec_status, "PLUGIN_ROOT", tmp_path)
        assert appsec_status._load_plugin_json() == {}


# ---------------------------------------------------------------------------
# _skill_exists (line 82-83)
# ---------------------------------------------------------------------------


class TestSkillExists:
    def test_real_skill_present(self, appsec_status):
        assert appsec_status._skill_exists("create-threat-model") is True

    def test_unknown_skill_absent(self, appsec_status):
        assert appsec_status._skill_exists("no-such-skill-xyz") is False


# ---------------------------------------------------------------------------
# _hook_id (lines 86-91)
# ---------------------------------------------------------------------------


class TestHookId:
    def test_non_scripts_command_returns_none(self, appsec_status):
        assert appsec_status._hook_id("echo hello") is None

    def test_known_mapping(self, appsec_status):
        cmd = "python3 $ROOT/scripts/agent_logger.py --foo"
        assert appsec_status._hook_id(cmd) == "agent-logger"

    def test_security_steering_mapping(self, appsec_status):
        cmd = "python3 /x/scripts/security_steering.py"
        assert appsec_status._hook_id(cmd) == "security-coach"

    def test_unknown_script_derives_stem(self, appsec_status):
        cmd = "python3 /x/scripts/my_custom_hook.py --a"
        assert appsec_status._hook_id(cmd) == "my-custom-hook"

    def test_windows_path_separators(self, appsec_status):
        cmd = "python3 C:\\plugin\\scripts\\agent_logger.py"
        assert appsec_status._hook_id(cmd) == "agent-logger"


# ---------------------------------------------------------------------------
# _registered_hook_ids (lines 94-111)
# ---------------------------------------------------------------------------


class TestRegisteredHookIds:
    def test_parses_real_hooks_json(self, appsec_status):
        ids = appsec_status._registered_hook_ids()
        assert isinstance(ids, set)

    def test_handles_malformed_structure(self, appsec_status, monkeypatch):
        # hooks list contains non-dict / missing keys → ignored without error
        fake = {
            "hooks": {
                "PreToolUse": [
                    "not-a-dict",
                    {"hooks": ["not-a-dict", {"command": 123}, {"command": "x/scripts/agent_logger.py"}]},
                ],
                "Bad": "not-a-list",
            }
        }
        monkeypatch.setattr(appsec_status, "_load_json", lambda p: fake)
        ids = appsec_status._registered_hook_ids()
        assert "agent-logger" in ids


# ---------------------------------------------------------------------------
# _org_profile_status (lines 114-155)
# ---------------------------------------------------------------------------


class TestOrgProfileStatus:
    def test_active_profile(self, appsec_status, tmp_path):
        eff = {
            "org_profile": {
                "active": True,
                "id": "acme",
                "version": "1.0",
                "path": "/p",
                "source": "git",
            },
            "preset": {"name": "ci-standard", "base_mode": "standard"},
            "requirements_source": {"label": "ACME", "requirements_yaml_url": "http://x"},
            "llm_context_documents": [
                {"id": "doc1", "loaded": True},
                {"id": "doc2", "loaded": False},
            ],
            "skill_toggles": {
                "export-threat-model": {"enabled": False},
                "status": {"enabled": True},
                "raw-bool": True,
            },
        }
        (tmp_path / ".org-profile-effective.json").write_text(json.dumps(eff))
        res = appsec_status._org_profile_status(tmp_path)
        assert res["active"] is True
        assert res["id"] == "acme"
        assert res["preset"] == "ci-standard"
        assert res["context_documents"] == ["doc1"]
        assert res["disabled_skills"] == ["export-threat-model"]

    def test_falls_back_to_config_pointer(self, appsec_status, tmp_path, monkeypatch):
        # no effective file → read config.json organization_profile block
        cfg = {"organization_profile": {"enabled": True, "path": "/org/p", "default_preset": "std"}}
        root = tmp_path / "root"
        root.mkdir()
        (root / "config.json").write_text(json.dumps(cfg))
        monkeypatch.setattr(appsec_status, "PLUGIN_ROOT", root)
        res = appsec_status._org_profile_status(tmp_path)
        assert res == {
            "active": False,
            "configured": True,
            "path": "/org/p",
            "default_preset": "std",
            "note": "configured via config.json — run create-threat-model to resolve",
        }

    def test_not_configured(self, appsec_status, tmp_path, monkeypatch):
        root = tmp_path / "root"
        root.mkdir()
        (root / "config.json").write_text(json.dumps({"organization_profile": {"enabled": False}}))
        monkeypatch.setattr(appsec_status, "PLUGIN_ROOT", root)
        res = appsec_status._org_profile_status(tmp_path)
        assert res == {"active": False, "configured": False}

    def test_config_json_unreadable(self, appsec_status, tmp_path, monkeypatch):
        root = tmp_path / "root"
        root.mkdir()
        (root / "config.json").write_text("{broken")
        monkeypatch.setattr(appsec_status, "PLUGIN_ROOT", root)
        res = appsec_status._org_profile_status(tmp_path)
        assert res == {"active": False, "configured": False}

    def test_inactive_effective_falls_through(self, appsec_status, tmp_path, monkeypatch):
        (tmp_path / ".org-profile-effective.json").write_text(
            json.dumps({"org_profile": {"active": False}})
        )
        root = tmp_path / "root"
        root.mkdir()
        (root / "config.json").write_text(json.dumps({"organization_profile": {"enabled": False}}))
        monkeypatch.setattr(appsec_status, "PLUGIN_ROOT", root)
        res = appsec_status._org_profile_status(tmp_path)
        assert res == {"active": False, "configured": False}


# ---------------------------------------------------------------------------
# _coach_status (lines 158-173)
# ---------------------------------------------------------------------------


class TestCoachStatus:
    def test_not_packaged(self, appsec_status, monkeypatch):
        monkeypatch.setattr(appsec_status, "_registered_hook_ids", lambda: set())
        state, note = appsec_status._coach_status()
        assert state == "not packaged"

    def test_env_truthy(self, appsec_status, monkeypatch):
        monkeypatch.setattr(appsec_status, "_registered_hook_ids", lambda: {"security-coach"})
        monkeypatch.setenv("APPSEC_COACH", "1")
        state, note = appsec_status._coach_status()
        assert state == "active"
        assert "environment variable" in note

    def test_env_falsy(self, appsec_status, monkeypatch):
        monkeypatch.setattr(appsec_status, "_registered_hook_ids", lambda: {"security-coach"})
        monkeypatch.setenv("APPSEC_COACH", "off")
        state, note = appsec_status._coach_status()
        assert state == "inactive"
        assert "forced off" in note

    def test_cfg_enabled(self, appsec_status, monkeypatch):
        monkeypatch.setattr(appsec_status, "_registered_hook_ids", lambda: {"security-coach"})
        monkeypatch.delenv("APPSEC_COACH", raising=False)
        monkeypatch.setattr(appsec_status, "_load_json", lambda p: {"enabled": True})
        state, note = appsec_status._coach_status()
        assert state == "active"
        assert "steering_keywords.json" in note

    def test_opt_in_default(self, appsec_status, monkeypatch):
        monkeypatch.setattr(appsec_status, "_registered_hook_ids", lambda: {"security-coach"})
        monkeypatch.delenv("APPSEC_COACH", raising=False)
        monkeypatch.setattr(appsec_status, "_load_json", lambda p: {"enabled": False})
        state, note = appsec_status._coach_status()
        assert state == "inactive"
        assert "opt-in" in note


# ---------------------------------------------------------------------------
# _config_summary (lines 176-214)
# ---------------------------------------------------------------------------


class TestConfigSummary:
    def _patch_common(self, appsec_status, monkeypatch, *, skill=True, coach=True):
        monkeypatch.setattr(appsec_status, "_skill_exists", lambda s: skill)
        ids = {"security-coach"} if coach else set()
        monkeypatch.setattr(appsec_status, "_registered_hook_ids", lambda: ids)

    def test_external_context_endpoint(self, appsec_status, tmp_path, monkeypatch):
        self._patch_common(appsec_status, monkeypatch)
        plug = tmp_path / "plugin-config.json"
        plug.write_text(json.dumps({"external_context": {"enabled": True, "rest_url": "http://ctx"}}))
        req = tmp_path / "req.json"
        req.write_text(json.dumps({"requirements_source": {"requirements_yaml_url": "http://r", "enabled": True}}))
        rows = appsec_status._config_summary(req, plug)
        d = dict(rows)
        assert "REST endpoint -> http://ctx" in d["External context"]
        assert "auto-load" in d["Requirements YAML"]

    def test_external_context_disabled(self, appsec_status, tmp_path, monkeypatch):
        self._patch_common(appsec_status, monkeypatch)
        plug = tmp_path / "p.json"
        plug.write_text(json.dumps({"external_context": {"enabled": False}}))
        req = tmp_path / "r.json"
        req.write_text(json.dumps({}))
        rows = dict(appsec_status._config_summary(req, plug))
        assert rows["External context"] == "disabled"

    def test_external_context_unset(self, appsec_status, tmp_path, monkeypatch):
        self._patch_common(appsec_status, monkeypatch)
        plug = tmp_path / "p.json"
        plug.write_text(json.dumps({}))
        req = tmp_path / "r.json"
        req.write_text(json.dumps({}))
        rows = dict(appsec_status._config_summary(req, plug))
        assert "not configured" in rows["External context"]

    def test_requirements_not_packaged(self, appsec_status, tmp_path, monkeypatch):
        self._patch_common(appsec_status, monkeypatch, skill=False)
        plug = tmp_path / "p.json"
        plug.write_text(json.dumps({}))
        req = tmp_path / "r.json"
        req.write_text(json.dumps({}))
        rows = dict(appsec_status._config_summary(req, plug))
        assert "not packaged" in rows["Requirements YAML"]

    def test_requirements_baseline_fallback(self, appsec_status, tmp_path, monkeypatch):
        self._patch_common(appsec_status, monkeypatch)
        plug = tmp_path / "p.json"
        plug.write_text(json.dumps({}))
        req = tmp_path / "r.json"
        req.write_text(json.dumps({"requirements_source": {"enabled": False}}))  # no url
        rows = dict(appsec_status._config_summary(req, plug))
        # real PLUGIN_ROOT/data/...baseline.yaml present → "present"
        assert "vendor-neutral baseline" in rows["Requirements YAML"]

    def test_steering_not_packaged(self, appsec_status, tmp_path, monkeypatch):
        self._patch_common(appsec_status, monkeypatch, coach=False)
        plug = tmp_path / "p.json"
        plug.write_text(json.dumps({}))
        req = tmp_path / "r.json"
        req.write_text(json.dumps({}))
        rows = dict(appsec_status._config_summary(req, plug))
        assert "not packaged" in rows["Steering topics"]

    def test_steering_topic_count(self, appsec_status, tmp_path, monkeypatch):
        self._patch_common(appsec_status, monkeypatch)

        # steering_keywords.json loaded via _load_json on a specific path
        def fake_load(p):
            if p.name == "steering_keywords.json":
                return {"topics": {"a": 1, "b": 2}}
            return {}

        monkeypatch.setattr(appsec_status, "_load_json", fake_load)
        plug = tmp_path / "p.json"
        plug.write_text(json.dumps({}))
        req = tmp_path / "r.json"
        req.write_text(json.dumps({}))
        rows = dict(appsec_status._config_summary(req, plug))
        assert rows["Steering topics"] == "2 configured"


# ---------------------------------------------------------------------------
# _auto_clean_state (lines 217-236)
# ---------------------------------------------------------------------------


class TestAutoCleanState:
    def test_helper_nonzero(self, appsec_status, monkeypatch, tmp_path):
        monkeypatch.setattr(appsec_status, "_run_helper", lambda *a: (1, "", "err"))
        assert appsec_status._auto_clean_state(tmp_path) == {"removed": [], "skipped": False}

    def test_helper_ok_with_removed(self, appsec_status, monkeypatch, tmp_path):
        payload = json.dumps({"clean": {"removed": ["a", "b"], "skipped": False}})
        monkeypatch.setattr(appsec_status, "_run_helper", lambda *a: (0, payload, ""))
        res = appsec_status._auto_clean_state(tmp_path)
        assert res == {"removed": ["a", "b"], "skipped": False}

    def test_helper_bad_json(self, appsec_status, monkeypatch, tmp_path):
        monkeypatch.setattr(appsec_status, "_run_helper", lambda *a: (0, "not json", ""))
        assert appsec_status._auto_clean_state(tmp_path) == {"removed": [], "skipped": False}


# ---------------------------------------------------------------------------
# _last_run_info (lines 295-307)
# ---------------------------------------------------------------------------


class TestLastRunInfo:
    def test_helper_nonzero(self, appsec_status, monkeypatch, tmp_path):
        monkeypatch.setattr(appsec_status, "_run_helper", lambda *a: (1, "", ""))
        assert appsec_status._last_run_info(tmp_path) == {"has_baseline": False}

    def test_helper_ok(self, appsec_status, monkeypatch, tmp_path):
        payload = json.dumps({"has_baseline": True, "plugin_version": "0.4"})
        monkeypatch.setattr(appsec_status, "_run_helper", lambda *a: (0, payload, ""))
        res = appsec_status._last_run_info(tmp_path)
        assert res["has_baseline"] is True

    def test_helper_bad_json(self, appsec_status, monkeypatch, tmp_path):
        monkeypatch.setattr(appsec_status, "_run_helper", lambda *a: (0, "garbage", ""))
        assert appsec_status._last_run_info(tmp_path) == {"has_baseline": False}


# ---------------------------------------------------------------------------
# _fast_path_preview (lines 239-292)
# ---------------------------------------------------------------------------


class TestFastPathPreview:
    def test_no_baseline_returns_none(self, appsec_status, tmp_path):
        assert appsec_status._fast_path_preview(tmp_path, tmp_path) is None

    def test_check_changes_bad_json(self, appsec_status, tmp_path, monkeypatch):
        (tmp_path / "threat-model.yaml").write_text("x: 1")
        monkeypatch.setattr(appsec_status, "_run_helper", lambda *a: (1, "not json", ""))
        assert appsec_status._fast_path_preview(tmp_path, tmp_path) is None

    def test_exit_zero_no_dirty_refine(self, appsec_status, tmp_path, monkeypatch):
        (tmp_path / "threat-model.yaml").write_text("x: 1")
        monkeypatch.setattr(
            appsec_status, "_run_helper", lambda *a: (0, json.dumps({"baseline_sha": "abc"}), "")
        )
        res = appsec_status._fast_path_preview(tmp_path, tmp_path)
        assert res["exit"] == 0
        assert "dirty_set" not in res

    def test_exit_one_with_relevant_files_refines(self, appsec_status, tmp_path, monkeypatch):
        (tmp_path / "threat-model.yaml").write_text("x: 1")
        calls = []

        def fake(script, *args):
            calls.append((script, args))
            if "check-changes" in args:
                return 1, json.dumps({"security_relevant_changes": ["src/a.py"]}), ""
            # dirty-set
            return 0, json.dumps({"dirty_component_ids": ["comp-a"]}), ""

        monkeypatch.setattr(appsec_status, "_run_helper", fake)
        res = appsec_status._fast_path_preview(tmp_path, tmp_path)
        assert res["exit"] == 1
        assert res["dirty_set"] == {"dirty_component_ids": ["comp-a"]}
        assert res["dirty_set_exit"] == 0

    def test_exit_one_no_relevant_files(self, appsec_status, tmp_path, monkeypatch):
        (tmp_path / "threat-model.yaml").write_text("x: 1")
        monkeypatch.setattr(
            appsec_status,
            "_run_helper",
            lambda *a: (1, json.dumps({"security_relevant_changes": []}), ""),
        )
        res = appsec_status._fast_path_preview(tmp_path, tmp_path)
        assert res["dirty_set"] is None
        assert res["dirty_set_exit"] is None

    def test_dirty_set_bad_json(self, appsec_status, tmp_path, monkeypatch):
        (tmp_path / "threat-model.yaml").write_text("x: 1")

        def fake(script, *args):
            if "check-changes" in args:
                return 1, json.dumps({"security_relevant_changes": ["src/a.py"]}), ""
            return 2, "not json", ""

        monkeypatch.setattr(appsec_status, "_run_helper", fake)
        res = appsec_status._fast_path_preview(tmp_path, tmp_path)
        assert res["dirty_set"] is None
        assert res["dirty_set_exit"] == 2


# ---------------------------------------------------------------------------
# render_text (lines 310-466)
# ---------------------------------------------------------------------------


def _base_data():
    return {
        "plugin": {"plugin_version": "0.4", "analysis_version": "3"},
        "paths": {"plugin_root": "/p", "repo_root": "/r", "output_dir": "/o"},
        "capsules": {
            "coach": {"state": "inactive", "note": "opt-in"},
            "threat_assessment": {"command": "/appsec-advisor:create-threat-model"},
            "requirements_audit": {"command": "/appsec-advisor:audit-security-requirements"},
        },
        "last_run": {"has_baseline": False},
        "config": [("External context", "not configured")],
        "fast_path": None,
        "auto_clean": {"removed": []},
        "org_profile": {"active": False, "configured": False},
    }


class TestRenderText:
    def test_minimal_no_baseline(self, appsec_status):
        out = appsec_status.render_text(_base_data())
        assert "AppSec Plugin v0.4" in out
        assert "no baseline — first run" in out
        assert "no baseline yet — not applicable" in out
        assert "[--help]" in out

    def test_auto_clean_banner(self, appsec_status):
        data = _base_data()
        data["auto_clean"] = {"removed": [".appsec-lock", ".stale"]}
        out = appsec_status.render_text(data)
        assert "Stale run-state cleaned automatically" in out

    def test_capsules_not_packaged(self, appsec_status):
        data = _base_data()
        data["capsules"] = {"coach": {"state": "inactive", "note": "x"}}
        out = appsec_status.render_text(data)
        assert "not packaged" in out

    def test_last_run_with_baseline(self, appsec_status):
        data = _base_data()
        data["last_run"] = {
            "has_baseline": True,
            "plugin_version": "0.4",
            "analysis_version": "3",
            "commit_sha": "abcdef1234567890",
            "last_run_at": "2026-05-01",
        }
        out = appsec_status.render_text(data)
        assert "abcdef123456" in out  # truncated to 12

    def test_org_profile_active(self, appsec_status):
        data = _base_data()
        data["org_profile"] = {
            "active": True,
            "id": "acme",
            "version": "1.0",
            "path": "/p",
            "preset": "ci-standard",
            "base_mode": "standard",
            "requirements_label": "ACME reqs",
            "context_documents": ["doc1", "doc2"],
            "disabled_skills": ["export-threat-model"],
        }
        out = appsec_status.render_text(data)
        assert "Org Profile" in out
        assert "acme" in out
        assert "doc1, doc2" in out
        assert "export-threat-model" in out

    def test_org_profile_configured(self, appsec_status):
        data = _base_data()
        data["org_profile"] = {
            "active": False,
            "configured": True,
            "path": "/org",
            "default_preset": "std",
            "note": "configured",
        }
        out = appsec_status.render_text(data)
        assert "configured (not yet resolved)" in out

    @pytest.mark.parametrize(
        "fp_extra,needle",
        [
            ({"exit": 0}, "fast-abort — no source changes"),
            ({"exit": 2}, "only noise/non-security"),
            ({"exit": 10, "plugin_version": {"tier": "major"}}, "STRONGLY recommend"),
            ({"exit": 10, "plugin_version": {"tier": "minor"}}, "recommend --full"),
            (
                {"exit": 1, "dirty_set_exit": 0, "dirty_set": {"dirty_component_ids": ["c1", "c2"]}},
                "2 component(s) dirty",
            ),
            ({"exit": 1, "dirty_set_exit": 2}, "only top-level globals"),
            (
                {"exit": 1, "dirty_set_exit": 3, "dirty_set": {"unmapped_files": ["x/y.py"]}},
                "unmapped: x/y.py",
            ),
            ({"exit": 1, "dirty_set_exit": None}, "incremental run will re-analyze"),
            ({"exit": 99}, "unknown"),
        ],
    )
    def test_fast_path_decisions(self, appsec_status, fp_extra, needle):
        data = _base_data()
        fp = {
            "baseline_sha": "abcdef1234567890",
            "head_sha": "1234567890abcdef",
            "committed_change_count": 2,
            "working_tree_change_count": 1,
            "fingerprint_match": False,
            "plugin_version": {"tier": "patch"},
            "excluded_pre_filter_count": 3,
            "security_relevant_change_count": 4,
            "noise_only_changes": ["a", "b"],
        }
        fp.update(fp_extra)
        # plugin_version may be overridden by fp_extra
        data["fast_path"] = fp
        out = appsec_status.render_text(data)
        assert needle in out
        assert "Excluded" in out
        assert "4 relevant, 2 noise" in out

    def test_fast_path_fingerprint_match(self, appsec_status):
        data = _base_data()
        data["fast_path"] = {
            "baseline_sha": "a" * 16,
            "head_sha": "b" * 16,
            "fingerprint_match": True,
            "plugin_version": {"tier": "patch"},
            "exit": 0,
        }
        out = appsec_status.render_text(data)
        assert "match" in out


# ---------------------------------------------------------------------------
# main() — full (non-live) and error/JSON paths (lines 673-736)
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_json_full(self, appsec_status, tmp_path, monkeypatch, capsys):
        # Stub the subprocess-backed helpers so no real scripts run.
        monkeypatch.setattr(appsec_status, "_auto_clean_state", lambda od: {"removed": []})
        monkeypatch.setattr(appsec_status, "_last_run_info", lambda od: {"has_baseline": False})
        monkeypatch.setattr(appsec_status, "_fast_path_preview", lambda od, rr: None)
        rc = appsec_status.main(["--repo-root", str(tmp_path), "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert "plugin" in data
        assert data["paths"]["repo_root"] == str(tmp_path.resolve())

    def test_main_text_full(self, appsec_status, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(appsec_status, "_auto_clean_state", lambda od: {"removed": []})
        monkeypatch.setattr(appsec_status, "_last_run_info", lambda od: {"has_baseline": False})
        monkeypatch.setattr(appsec_status, "_fast_path_preview", lambda od, rr: None)
        rc = appsec_status.main(["--repo-root", str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "AppSec Plugin" in out

    def test_main_output_dir_override(self, appsec_status, tmp_path, monkeypatch, capsys):
        captured = {}

        def _capture(od):
            captured["od"] = od
            return {"removed": []}

        monkeypatch.setattr(appsec_status, "_auto_clean_state", _capture)
        monkeypatch.setattr(appsec_status, "_last_run_info", lambda od: {"has_baseline": False})
        monkeypatch.setattr(appsec_status, "_fast_path_preview", lambda od, rr: None)
        target = tmp_path / "custom-out"
        rc = appsec_status.main(["--repo-root", str(tmp_path), "--output-dir", str(target), "--json"])
        assert rc == 0
        assert captured["od"] == target.resolve()

    def test_main_live_json(self, appsec_status, tmp_path, capsys):
        rc = appsec_status.main(["--repo-root", str(tmp_path), "--live", "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["has_run"] is False

    def test_main_live_text(self, appsec_status, tmp_path, capsys):
        rc = appsec_status.main(["--repo-root", str(tmp_path), "--live"])
        assert rc == 0
        assert "no run in progress" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# _live_snapshot / _render_live smoke coverage of the populated path
# (the detailed assertions live in test_appsec_status_live.py; here we just
# drive the populated branches so this file stands alone above threshold).
# ---------------------------------------------------------------------------


import time as _time


def _seed_live(tmp_path: Path) -> None:
    (tmp_path / ".appsec-lock").write_text(f"123\n{int(_time.time())}\n")
    (tmp_path / ".appsec-checkpoint").write_text("phase=9 status=started timestamp=2026-05-04T00:00:00Z")
    (tmp_path / ".skill-config.json").write_text(json.dumps({"assessment_depth": "thorough"}))
    (tmp_path / ".appsec-progress.json").write_text(
        json.dumps(
            {
                "event": "STEP_START",
                "agent": "threat-analyst",
                "phase": "9",
                "phase_total": "11",
                "step": 2,
                "step_total": 5,
                "label": "scanning auth",
            }
        )
    )
    pdir = tmp_path / ".progress"
    pdir.mkdir()
    (pdir / "auth.json").write_text(
        json.dumps({"component_name": "Auth", "step": 4, "total": 9, "label": "running"})
    )
    adir = tmp_path / ".active-tool-calls"
    adir.mkdir()
    (adir / "toolu.json").write_text(
        json.dumps(
            {
                "tool_use_id": "toolu",
                "agent": "stride-analyzer",
                "tool": "Bash",
                "started_at": int(_time.time()) - 5,
                "input_summary": "grep JWT",
            }
        )
    )
    (tmp_path / ".stride-auth.json").write_text("{}")


class TestLiveSnapshotSmoke:
    def test_populated_snapshot(self, appsec_status, tmp_path):
        _seed_live(tmp_path)
        snap = appsec_status._live_snapshot(tmp_path)
        assert snap["has_run"] is True
        assert snap["checkpoint"]["phase"] == "9"
        assert snap["stride_files"] == 1
        assert any(p["component"] == "Auth" for p in snap["progress"])
        assert snap["active_tool_calls"][0]["agent"] == "stride-analyzer"

    def test_stale_active_call_filtered(self, appsec_status, tmp_path):
        _seed_live(tmp_path)
        # overwrite the active call with a very old started_at → filtered out
        (tmp_path / ".active-tool-calls" / "toolu.json").write_text(
            json.dumps(
                {
                    "tool_use_id": "toolu",
                    "agent": "x",
                    "tool": "Bash",
                    "started_at": 1,  # epoch → age huge → filtered
                    "input_summary": "y",
                }
            )
        )
        snap = appsec_status._live_snapshot(tmp_path)
        assert snap["active_tool_calls"] == []

    def test_malformed_progress_and_active_skipped(self, appsec_status, tmp_path):
        _seed_live(tmp_path)
        (tmp_path / ".progress" / "broken.json").write_text("{not json")
        (tmp_path / ".active-tool-calls" / "broken.json").write_text("{not json")
        snap = appsec_status._live_snapshot(tmp_path)
        # broken entries skipped, valid ones remain
        assert all("broken" not in (p.get("component") or "") for p in snap["progress"])

    def test_render_live_populated(self, appsec_status, tmp_path):
        _seed_live(tmp_path)
        snap = appsec_status._live_snapshot(tmp_path)
        out = appsec_status._render_live(snap)
        assert "Phase 9" in out
        assert "Auth" in out
        assert "stride-analyzer" in out

    def test_render_live_no_run(self, appsec_status):
        out = appsec_status._render_live({"has_run": False})
        assert "no run in progress" in out

    def test_render_live_progress_without_active(self, appsec_status):
        snap = {
            "has_run": True,
            "checkpoint": {"phase": "9", "status": "started"},
            "lock": {"heartbeat_age": 12},
            "threshold_seconds": 300,
            "stride_files": 0,
            "current": {},
            "progress": [{"component": "auth", "step": 1, "total": 9, "label": "go", "age_s": 3}],
            "active_tool_calls": [],
        }
        out = appsec_status._render_live(snap)
        assert "no live tool-use markers" in out
