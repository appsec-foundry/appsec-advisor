"""Tests for scripts/plugin_meta.py — version metadata helper.

Pins current behavior of load_meta, classify_compat, classify_plugin_version,
the semver parser, and the CLI subcommands (get / print / check-compat /
compare-plugin-versions). In-process so coverage is collected.
"""

from __future__ import annotations

import json

import plugin_meta as pm
import pytest

# --- _find_plugin_json / load_meta -----------------------------------------


def _write_plugin_json(root, data):
    p = root / ".claude-plugin" / "plugin.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_find_via_env_root(tmp_path, monkeypatch):
    _write_plugin_json(tmp_path, {"version": "1.2.3", "analysis_version": 5})
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
    found = pm._find_plugin_json()
    assert found == tmp_path / ".claude-plugin" / "plugin.json"


def test_env_root_missing_falls_back_to_walk(tmp_path, monkeypatch):
    # env root set but no plugin.json there -> walk up from this file finds repo
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
    found = pm._find_plugin_json()
    assert found is not None
    assert found.name == "plugin.json"


def test_load_meta_real_repo(monkeypatch):
    monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
    meta = pm.load_meta()
    assert "plugin_version" in meta
    assert isinstance(meta["analysis_version"], int)
    assert isinstance(meta["compatible_analysis_versions"], list)


def test_load_meta_not_found(monkeypatch):
    # Point env root at a dir without plugin.json AND patch _find to None
    monkeypatch.setattr(pm, "_find_plugin_json", lambda: None)
    meta = pm.load_meta()
    assert meta == {
        "plugin_version": "unknown",
        "analysis_version": 0,
        "compatible_analysis_versions": [],
    }


def test_load_meta_bad_json(tmp_path, monkeypatch):
    p = tmp_path / ".claude-plugin" / "plugin.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{not valid json", encoding="utf-8")
    monkeypatch.setattr(pm, "_find_plugin_json", lambda: p)
    meta = pm.load_meta()
    assert meta["plugin_version"] == "unknown"
    assert meta["analysis_version"] == 0


def test_load_meta_fields_coerced(tmp_path, monkeypatch):
    p = _write_plugin_json(
        tmp_path,
        {"version": 4, "analysis_version": "7", "compatible_analysis_versions": (1, 2)},
    )
    monkeypatch.setattr(pm, "_find_plugin_json", lambda: p)
    meta = pm.load_meta()
    assert meta["plugin_version"] == "4"
    assert meta["analysis_version"] == 7
    assert meta["compatible_analysis_versions"] == [1, 2]


# --- classify_compat -------------------------------------------------------


def test_classify_compat_baseline_missing():
    code, msg = pm.classify_compat(None, {"analysis_version": 3, "compatible_analysis_versions": []})
    assert code == pm.EXIT_BASELINE_MISSING
    assert "no analysis_version" in msg


def test_classify_compat_equal():
    code, msg = pm.classify_compat(3, {"analysis_version": 3, "compatible_analysis_versions": []})
    assert code == pm.EXIT_COMPAT_EQUAL


def test_classify_compat_recommend_full():
    code, msg = pm.classify_compat(2, {"analysis_version": 3, "compatible_analysis_versions": [2]})
    assert code == pm.EXIT_COMPAT_RECOMMEND_FULL


def test_classify_compat_incompat():
    code, msg = pm.classify_compat(1, {"analysis_version": 3, "compatible_analysis_versions": [2]})
    assert code == pm.EXIT_INCOMPAT


# --- _parse_semver ---------------------------------------------------------


@pytest.mark.parametrize(
    "v,expected",
    [
        ("1.2.3", (1, 2, 3)),
        ("1.2.3-beta", (1, 2, 3)),
        ("1.2.3+build", (1, 2, 3)),
        ("1.2.3-beta+build", (1, 2, 3)),
        ("0.4.0-beta", (0, 4, 0)),
    ],
)
def test_parse_semver_ok(v, expected):
    assert pm._parse_semver(v) == expected


@pytest.mark.parametrize("v", ["", "1.2", "abc", "x.y.z", None, 123])
def test_parse_semver_bad(v):
    assert pm._parse_semver(v) is None


# --- classify_plugin_version ----------------------------------------------


def test_classify_plugin_version_baseline_unknown():
    tier, _ = pm.classify_plugin_version(None, "1.2.3")
    assert tier == pm.PLUGIN_VERSION_TIER_UNKNOWN
    tier, _ = pm.classify_plugin_version("unknown", "1.2.3")
    assert tier == pm.PLUGIN_VERSION_TIER_UNKNOWN


def test_classify_plugin_version_current_unknown():
    tier, _ = pm.classify_plugin_version("1.2.3", None)
    assert tier == pm.PLUGIN_VERSION_TIER_UNKNOWN
    tier, _ = pm.classify_plugin_version("1.2.3", "unknown")
    assert tier == pm.PLUGIN_VERSION_TIER_UNKNOWN


def test_classify_plugin_version_equal():
    tier, _ = pm.classify_plugin_version("1.2.3", "1.2.3")
    assert tier == pm.PLUGIN_VERSION_TIER_EQUAL


def test_classify_plugin_version_not_semver():
    tier, msg = pm.classify_plugin_version("devbuild", "shatag")
    assert tier == pm.PLUGIN_VERSION_TIER_UNKNOWN
    assert "not semver" in msg


def test_classify_plugin_version_major():
    tier, _ = pm.classify_plugin_version("1.2.3", "2.0.0")
    assert tier == pm.PLUGIN_VERSION_TIER_MAJOR


def test_classify_plugin_version_minor():
    tier, _ = pm.classify_plugin_version("1.2.3", "1.3.0")
    assert tier == pm.PLUGIN_VERSION_TIER_MINOR


def test_classify_plugin_version_patch():
    tier, _ = pm.classify_plugin_version("1.2.3", "1.2.9")
    assert tier == pm.PLUGIN_VERSION_TIER_PATCH


# --- CLI: cmd_get ----------------------------------------------------------


def _stub_meta(monkeypatch, meta):
    monkeypatch.setattr(pm, "load_meta", lambda: meta)


def test_cmd_get_scalar(monkeypatch, capsys):
    _stub_meta(monkeypatch, {"plugin_version": "1.2.3", "analysis_version": 4, "compatible_analysis_versions": [1, 2]})
    assert pm.main(["get", "plugin_version"]) == 0
    assert capsys.readouterr().out.strip() == "1.2.3"


def test_cmd_get_list(monkeypatch, capsys):
    _stub_meta(monkeypatch, {"plugin_version": "1.2.3", "analysis_version": 4, "compatible_analysis_versions": [1, 2]})
    assert pm.main(["get", "compatible_analysis_versions"]) == 0
    assert capsys.readouterr().out.strip() == "1,2"


def test_cmd_get_unknown_key(monkeypatch, capsys):
    _stub_meta(monkeypatch, {"plugin_version": "1.2.3", "analysis_version": 4, "compatible_analysis_versions": []})
    assert pm.main(["get", "nope"]) == pm.EXIT_ERROR
    assert "unknown key" in capsys.readouterr().err


# --- CLI: cmd_print --------------------------------------------------------


def test_cmd_print(monkeypatch, capsys):
    _stub_meta(monkeypatch, {"plugin_version": "1.2.3", "analysis_version": 4, "compatible_analysis_versions": [1]})
    assert pm.main(["print"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["plugin_version"] == "1.2.3"


# --- CLI: cmd_check_compat -------------------------------------------------


def test_cmd_check_compat_equal(monkeypatch, capsys):
    _stub_meta(monkeypatch, {"analysis_version": 3, "compatible_analysis_versions": []})
    assert pm.main(["check-compat", "--baseline-version", "3"]) == pm.EXIT_COMPAT_EQUAL
    assert "COMPAT_CHECK" in capsys.readouterr().out


def test_cmd_check_compat_missing(monkeypatch, capsys):
    _stub_meta(monkeypatch, {"analysis_version": 3, "compatible_analysis_versions": []})
    # empty string -> None via the type lambda
    assert pm.main(["check-compat", "--baseline-version", ""]) == pm.EXIT_BASELINE_MISSING
    assert "COMPAT_CHECK" in capsys.readouterr().err


def test_cmd_check_compat_negative(monkeypatch, capsys):
    _stub_meta(monkeypatch, {"analysis_version": 3, "compatible_analysis_versions": []})
    assert pm.main(["check-compat", "--baseline-version", "-1"]) == pm.EXIT_ERROR
    assert ">= 0" in capsys.readouterr().err


def test_cmd_check_compat_default_none(monkeypatch, capsys):
    _stub_meta(monkeypatch, {"analysis_version": 3, "compatible_analysis_versions": []})
    assert pm.main(["check-compat"]) == pm.EXIT_BASELINE_MISSING


# --- CLI: cmd_compare_plugin_versions -------------------------------------


def test_cmd_compare_equal(monkeypatch, capsys):
    assert pm.main(["compare-plugin-versions", "--baseline", "1.2.3", "--current", "1.2.3"]) == 0
    assert "tier=equal" in capsys.readouterr().out


def test_cmd_compare_patch(capsys):
    assert pm.main(["compare-plugin-versions", "--baseline", "1.2.3", "--current", "1.2.9"]) == 0


def test_cmd_compare_minor(capsys):
    assert pm.main(["compare-plugin-versions", "--baseline", "1.2.3", "--current", "1.3.0"]) == 10


def test_cmd_compare_major(capsys):
    assert pm.main(["compare-plugin-versions", "--baseline", "1.2.3", "--current", "2.0.0"]) == 20


def test_cmd_compare_unknown(capsys):
    assert pm.main(["compare-plugin-versions", "--baseline", "devtag", "--current", "shatag"]) == 30


def test_cmd_compare_current_defaults_to_meta(monkeypatch, capsys):
    _stub_meta(monkeypatch, {"plugin_version": "1.2.3", "analysis_version": 0, "compatible_analysis_versions": []})
    assert pm.main(["compare-plugin-versions", "--baseline", "1.2.3"]) == 0
    assert "tier=equal" in capsys.readouterr().out


# --- argparse: no subcommand required --------------------------------------


def test_no_subcommand_exits(capsys):
    with pytest.raises(SystemExit):
        pm.main([])


# --- main uses sys.argv when argv is None ---------------------------------


def test_main_reads_sys_argv(monkeypatch, capsys):
    _stub_meta(monkeypatch, {"plugin_version": "9.9.9", "analysis_version": 0, "compatible_analysis_versions": []})
    monkeypatch.setattr("sys.argv", ["plugin_meta.py", "get", "plugin_version"])
    assert pm.main() == 0
    assert capsys.readouterr().out.strip() == "9.9.9"
