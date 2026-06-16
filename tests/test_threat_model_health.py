"""Unit tests for scripts/threat_model_health.py.

Covers the freshness decision tree, artifact tiering, orchestration,
exit-code mapping, text rendering, and the CLI entrypoint.
"""

from __future__ import annotations

import json
from pathlib import Path

import threat_model_health as tmh

# ---------------------------------------------------------------------------
# _run_baseline
# ---------------------------------------------------------------------------


class _FakeProc:
    def __init__(self, returncode: int, stdout: str) -> None:
        self.returncode = returncode
        self.stdout = stdout


def test_run_baseline_parses_json(monkeypatch):
    monkeypatch.setattr(tmh.subprocess, "run", lambda *a, **k: _FakeProc(1, '{"a": 1}'))
    exit_code, payload = tmh._run_baseline(["check-changes"])
    assert exit_code == 1
    assert payload == {"a": 1}


def test_run_baseline_empty_stdout(monkeypatch):
    monkeypatch.setattr(tmh.subprocess, "run", lambda *a, **k: _FakeProc(0, "   "))
    exit_code, payload = tmh._run_baseline(["x"])
    assert exit_code == 0
    assert payload == {}


def test_run_baseline_bad_json(monkeypatch):
    monkeypatch.setattr(tmh.subprocess, "run", lambda *a, **k: _FakeProc(2, "not json{"))
    exit_code, payload = tmh._run_baseline(["x"])
    assert exit_code == 2
    assert payload == {}


def test_run_baseline_timeout(monkeypatch):
    def _boom(*a, **k):
        raise tmh.subprocess.TimeoutExpired(cmd="baseline", timeout=30)

    monkeypatch.setattr(tmh.subprocess, "run", _boom)
    exit_code, payload = tmh._run_baseline(["x"])
    assert exit_code == 4
    assert payload == {}


def test_run_baseline_oserror(monkeypatch):
    def _boom(*a, **k):
        raise OSError("exec failed")

    monkeypatch.setattr(tmh.subprocess, "run", _boom)
    exit_code, payload = tmh._run_baseline(["x"])
    assert exit_code == 4
    assert payload == {}


# ---------------------------------------------------------------------------
# check_freshness — NO_MODEL branches (no subprocess needed)
# ---------------------------------------------------------------------------


def test_freshness_no_yaml_no_md(tmp_path):
    res = tmh.check_freshness(tmp_path, tmp_path)
    assert res["verdict"] == "NO_MODEL"
    assert res["recommend"] == "full"
    assert "no threat-model.yaml" in res["reason"]


def test_freshness_legacy_md_only(tmp_path):
    (tmp_path / "threat-model.md").write_text("legacy")
    res = tmh.check_freshness(tmp_path, tmp_path)
    assert res["verdict"] == "NO_MODEL"
    assert "legacy" in res["reason"]
    assert res["recommend"] == "full"


# ---------------------------------------------------------------------------
# check_freshness — check-changes exit branches (mock _run_baseline)
# ---------------------------------------------------------------------------


def _yaml_dir(tmp_path: Path) -> Path:
    (tmp_path / "threat-model.yaml").write_text("meta: {}")
    return tmp_path


def _patch_baseline(monkeypatch, *responses):
    """Queue (exit, payload) tuples; each _run_baseline call pops the next."""
    calls = list(responses)

    def _fake(args):
        return calls.pop(0)

    monkeypatch.setattr(tmh, "_run_baseline", _fake)


def test_freshness_unchanged_exit0(tmp_path, monkeypatch):
    d = _yaml_dir(tmp_path)
    _patch_baseline(monkeypatch, (0, {}))
    res = tmh.check_freshness(d, tmp_path)
    assert res["verdict"] == "FRESH"
    assert res["recommend"] == "noop"


def test_freshness_noise_only_exit2(tmp_path, monkeypatch):
    d = _yaml_dir(tmp_path)
    _patch_baseline(monkeypatch, (2, {"noise_only_changes": ["a", "b"]}))
    res = tmh.check_freshness(d, tmp_path)
    assert res["verdict"] == "FRESH"
    assert "2 noise-only" in res["reason"]


def test_freshness_plugin_drift_exit10(tmp_path, monkeypatch):
    d = _yaml_dir(tmp_path)
    _patch_baseline(
        monkeypatch,
        (10, {"plugin_version": {"baseline": "1", "current": "2", "tier": "minor"}}),
    )
    res = tmh.check_freshness(d, tmp_path)
    assert res["verdict"] == "STALE"
    assert res["recommend"] == "full"
    assert "1 → 2" in res["reason"]


def test_freshness_exit3_unknown(tmp_path, monkeypatch):
    d = _yaml_dir(tmp_path)
    _patch_baseline(monkeypatch, (3, {"reason": "no baseline"}))
    res = tmh.check_freshness(d, tmp_path)
    assert res["verdict"] == "UNKNOWN"
    assert res["reason"] == "no baseline"
    assert res["recommend"] == "none"


def test_freshness_unexpected_exit(tmp_path, monkeypatch):
    d = _yaml_dir(tmp_path)
    _patch_baseline(monkeypatch, (99, {}))
    res = tmh.check_freshness(d, tmp_path)
    assert res["verdict"] == "UNKNOWN"
    assert "unexpected exit 99" in res["reason"]


def test_freshness_exit1_empty_relevant(tmp_path, monkeypatch):
    d = _yaml_dir(tmp_path)
    _patch_baseline(monkeypatch, (1, {"security_relevant_changes": []}))
    res = tmh.check_freshness(d, tmp_path)
    assert res["verdict"] == "UNKNOWN"
    assert "empty relevant list" in res["reason"]


# ---------------------------------------------------------------------------
# check_freshness — exit1 then dirty-set branches
# ---------------------------------------------------------------------------


def test_freshness_dirty_components_exit0(tmp_path, monkeypatch):
    d = _yaml_dir(tmp_path)
    _patch_baseline(
        monkeypatch,
        (1, {"security_relevant_changes": ["src/x.py"]}),
        (0, {"dirty_component_ids": ["c1", "c2"]}),
    )
    res = tmh.check_freshness(d, tmp_path)
    assert res["verdict"] == "STALE"
    assert res["recommend"] == "incremental"
    assert "2 component(s) dirty" in res["reason"]
    assert "c1, c2" in res["reason"]


def test_freshness_globals_only_exit2(tmp_path, monkeypatch):
    d = _yaml_dir(tmp_path)
    _patch_baseline(
        monkeypatch,
        (1, {"security_relevant_changes": ["pkg.json", "lock"]}),
        (2, {}),
    )
    res = tmh.check_freshness(d, tmp_path)
    assert res["verdict"] == "FRESH"
    assert res["recommend"] == "noop"
    assert "map to no component" in res["reason"]


def test_freshness_unmapped_exit3(tmp_path, monkeypatch):
    d = _yaml_dir(tmp_path)
    _patch_baseline(
        monkeypatch,
        (1, {"security_relevant_changes": ["src/new.py"]}),
        (3, {"unmapped_files": ["src/new.py"]}),
    )
    res = tmh.check_freshness(d, tmp_path)
    assert res["verdict"] == "STALE"
    assert res["recommend"] == "incremental"
    assert "possible new component" in res["reason"]


def test_freshness_dirtyset_unexpected_exit(tmp_path, monkeypatch):
    d = _yaml_dir(tmp_path)
    _patch_baseline(
        monkeypatch,
        (1, {"security_relevant_changes": ["src/x.py"]}),
        (7, {}),
    )
    res = tmh.check_freshness(d, tmp_path)
    assert res["verdict"] == "STALE"
    assert "unexpected exit 7" in res["reason"]
    assert res["recommend"] == "incremental"


# ---------------------------------------------------------------------------
# _scan_artifacts
# ---------------------------------------------------------------------------


def test_scan_artifacts_not_a_dir(tmp_path):
    missing = tmp_path / "nope"
    assert tmh._scan_artifacts(missing) == {"tier1": [], "tier2": []}


def test_scan_artifacts_tier1(output_dir):
    (output_dir / ".appsec-lock").write_text("")
    (output_dir / ".skill-watchdog.tick").write_text("")
    (output_dir / "threat-model.yaml").write_text("")  # required state, ignored
    res = tmh._scan_artifacts(output_dir)
    assert res["tier1"] == [".appsec-lock", ".skill-watchdog.tick"]
    assert res["tier2"] == []


def test_scan_artifacts_tier2_files_and_dirs(output_dir, monkeypatch):
    # Inject deterministic tier-2 inventory so the test is independent of
    # runtime_cleanup's exact contents.
    monkeypatch.setattr(tmh, "_TIER2_FILES", frozenset({"debris.json"}))
    monkeypatch.setattr(tmh, "_TIER2_DIRS", frozenset({".stride-work"}))
    (output_dir / "debris.json").write_text("{}")
    (output_dir / ".stride-work").mkdir()
    (output_dir / "keep.txt").write_text("x")  # unknown content, ignored
    res = tmh._scan_artifacts(output_dir)
    assert res["tier2"] == [".stride-work/", "debris.json"]
    assert res["tier1"] == []


def test_scan_artifacts_oserror(output_dir, monkeypatch):
    def _boom(self):
        raise OSError("cannot list")

    monkeypatch.setattr(Path, "iterdir", _boom)
    assert tmh._scan_artifacts(output_dir) == {"tier1": [], "tier2": []}


# ---------------------------------------------------------------------------
# collect
# ---------------------------------------------------------------------------


def test_collect_active_short_circuits(tmp_path, monkeypatch):
    monkeypatch.setattr(tmh, "_classify_run", lambda od: {"state": "active", "reasons": ["lock held"]})
    out = tmh.collect(tmp_path, tmp_path)
    assert out["active_run"]["state"] == "active"
    assert "freshness" not in out
    assert "artifacts" not in out


def test_collect_clean_runs_all_checks(tmp_path, monkeypatch):
    monkeypatch.setattr(tmh, "_classify_run", lambda od: {"state": "clean"})
    monkeypatch.setattr(tmh, "_run_baseline", lambda args: (0, {}))
    (tmp_path / "threat-model.yaml").write_text("meta: {}")
    out = tmh.collect(tmp_path, tmp_path)
    assert out["active_run"]["state"] == "clean"
    assert out["freshness"]["verdict"] == "FRESH"
    assert "artifacts" in out
    assert out["output_dir"] == str(tmp_path)


def test_collect_classify_raises(tmp_path, monkeypatch):
    def _boom(od):
        raise RuntimeError("boom")

    monkeypatch.setattr(tmh, "_classify_run", _boom)
    monkeypatch.setattr(tmh, "_run_baseline", lambda args: (0, {}))
    out = tmh.collect(tmp_path, tmp_path)
    assert out["active_run"]["state"] == "error"
    assert "boom" in out["active_run"]["reasons"][0]


def test_collect_classify_none(tmp_path, monkeypatch):
    monkeypatch.setattr(tmh, "_classify_run", None)
    monkeypatch.setattr(tmh, "_CLASSIFY_IMPORT_ERR", "no module")
    monkeypatch.setattr(tmh, "_run_baseline", lambda args: (0, {}))
    out = tmh.collect(tmp_path, tmp_path)
    assert out["active_run"]["state"] == "error"
    assert "no module" in out["active_run"]["reasons"][0]


# ---------------------------------------------------------------------------
# exit_code_for
# ---------------------------------------------------------------------------


def test_exit_code_active():
    assert tmh.exit_code_for({"active_run": {"state": "active"}}) == 3


def test_exit_code_error():
    assert tmh.exit_code_for({"active_run": {"state": "error"}}) == 4


def test_exit_code_unknown_freshness():
    p = {"active_run": {"state": "clean"}, "freshness": {"verdict": "UNKNOWN"}}
    assert tmh.exit_code_for(p) == 4


def test_exit_code_stale():
    p = {"active_run": {"state": "clean"}, "freshness": {"verdict": "STALE"}}
    assert tmh.exit_code_for(p) == 1


def test_exit_code_no_model():
    p = {"active_run": {"state": "clean"}, "freshness": {"verdict": "NO_MODEL"}}
    assert tmh.exit_code_for(p) == 1


def test_exit_code_debris():
    p = {
        "active_run": {"state": "clean"},
        "freshness": {"verdict": "FRESH"},
        "artifacts": {"tier1": [".appsec-lock"], "tier2": []},
    }
    assert tmh.exit_code_for(p) == 2


def test_exit_code_clean():
    p = {
        "active_run": {"state": "clean"},
        "freshness": {"verdict": "FRESH"},
        "artifacts": {"tier1": [], "tier2": []},
    }
    assert tmh.exit_code_for(p) == 0


def test_exit_code_empty_payload_defaults_unknown():
    # No active_run, no freshness → verdict defaults UNKNOWN → 4.
    assert tmh.exit_code_for({}) == 4


# ---------------------------------------------------------------------------
# render_text
# ---------------------------------------------------------------------------


def test_render_active():
    p = {
        "repo_root": "/r",
        "output_dir": "/o",
        "active_run": {"state": "active", "reasons": ["lock", "hb", "cp", "extra"]},
    }
    out = tmh.render_text(p)
    assert "RUNNING" in out
    assert "Checks 1 + 2 skipped" in out
    # only first 3 reasons rendered
    assert "extra" not in out


def test_render_clean_fresh_no_artifacts():
    p = {
        "repo_root": "/r",
        "output_dir": "/o",
        "active_run": {"state": "clean"},
        "freshness": {
            "verdict": "FRESH",
            "reason": "no source changes",
            "recommend": "noop",
        },
        "artifacts": {"tier1": [], "tier2": []},
    }
    out = tmh.render_text(p)
    assert "[3] Active run        : no" in out
    assert "✓ FRESH" in out
    assert "up to date" in out
    assert "[2] Artifacts         : ✓ none" in out


def test_render_error_state():
    p = {
        "active_run": {"state": "error", "reasons": ["import boom", "x", "y"]},
        "freshness": {"verdict": "UNKNOWN", "recommend": "none"},
        "artifacts": {},
    }
    out = tmh.render_text(p)
    assert "UNKNOWN (check_state error)" in out
    assert "import boom" in out
    assert "? UNKNOWN" in out


def test_render_needs_stage2_state():
    p = {
        "active_run": {"state": "incomplete", "needs_stage2": True},
        "freshness": {"verdict": "STALE", "recommend": "incremental"},
        "artifacts": {},
    }
    out = tmh.render_text(p)
    assert "[3] Active run        : incomplete" in out
    assert "pass --resume" in out
    assert "⚠ STALE" in out


def test_render_files_and_dirty_and_artifacts():
    p = {
        "active_run": {"state": "clean"},
        "freshness": {
            "verdict": "STALE",
            "reason": "stuff",
            "recommend": "full",
            "check_changes": {
                "security_relevant_change_count": 3,
                "noise_only_changes": ["n1"],
                "excluded_pre_filter_count": 2,
            },
            "dirty_set": {"dirty_component_ids": ["comp-a", "comp-b"]},
        },
        "artifacts": {
            "tier1": [f"t1-{i}" for i in range(8)],
            "tier2": [f"t2-{i}" for i in range(8)],
        },
    }
    out = tmh.render_text(p)
    assert "3 relevant / 1 noise / 2 excluded" in out
    assert "Dirty components: comp-a, comp-b" in out
    assert "8 tier-1 / 8 tier-2" in out
    assert "clean-run-state to reap" in out
    assert "runtime_cleanup.py --stage all" in out
    # truncation ellipsis present (>6 items)
    assert "…" in out


def test_render_no_model_icon():
    p = {
        "active_run": {"state": "clean"},
        "freshness": {"verdict": "NO_MODEL", "recommend": "full"},
        "artifacts": {},
    }
    out = tmh.render_text(p)
    assert "✗ NO_MODEL" in out


# ---------------------------------------------------------------------------
# CLI (main) via subprocess
# ---------------------------------------------------------------------------


def test_cli_missing_repo_root(run_plugin_script, tmp_path):
    res = run_plugin_script(
        "threat_model_health.py",
        "--repo-root",
        str(tmp_path / "does-not-exist"),
        "--output-dir",
        str(tmp_path),
        check=False,
    )
    assert res.returncode == 4
    assert "repo root not found" in res.stderr


def test_cli_json_no_model(run_plugin_script, tmp_path):
    # repo_root exists, output_dir has no yaml → NO_MODEL → exit 1.
    out = tmp_path / "out"
    out.mkdir()
    res = run_plugin_script(
        "threat_model_health.py",
        "--repo-root",
        str(tmp_path),
        "--output-dir",
        str(out),
        "--json",
        check=False,
    )
    assert res.returncode == 1
    payload = json.loads(res.stdout)
    assert payload["exit_code"] == 1
    assert payload["freshness"]["verdict"] == "NO_MODEL"


def test_cli_text_no_model(run_plugin_script, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    res = run_plugin_script(
        "threat_model_health.py",
        "--repo-root",
        str(tmp_path),
        "--output-dir",
        str(out),
        check=False,
    )
    assert res.returncode == 1
    assert "Threat Model State" in res.stdout
    assert "NO_MODEL" in res.stdout


def test_main_direct_json(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(tmh, "_classify_run", lambda od: {"state": "clean"})
    monkeypatch.setattr(tmh, "_run_baseline", lambda args: (0, {}))
    (tmp_path / "threat-model.yaml").write_text("meta: {}")
    code = tmh.main(["--repo-root", str(tmp_path), "--output-dir", str(tmp_path), "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["exit_code"] == 0
    assert payload["freshness"]["verdict"] == "FRESH"
