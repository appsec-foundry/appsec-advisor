from __future__ import annotations

import json
from pathlib import Path

import emit_known_bad_libs as kbl


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _plugin_root(tmp_path: Path) -> Path:
    root = tmp_path / "plugin"
    _write(
        root / "data" / "known-bad-libs.yaml",
        """
version: 1
known_bad:
  - ecosystem: npm
    package: node-serialize
    reason: unsafe deserialization RCE; never patched
    category: unfixed_critical_cve
    severity: Critical
  - ecosystem: npm
    package: request
    reason: deprecated and unmaintained
    category: deprecated_abandoned
    severity: Medium
""".lstrip(),
    )
    return root


def _findings(output_dir: Path) -> list[dict]:
    data = json.loads((output_dir / ".known-bad-libs-findings.json").read_text(encoding="utf-8"))
    return data["findings"]


def test_manifest_match_emits_known_bad_lib_finding(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    _write(repo / "package.json", '{"dependencies": {"request": "^2.88.2"}}\n')

    assert kbl.run(repo, out, "T2", _plugin_root(tmp_path)) == 0

    findings = _findings(out)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["source"] == "known-bad-libs"
    assert finding["category"] == "Insufficient Patch Management"
    assert finding["severity"] == "Medium"
    assert finding["evidence"] == [{"file": "package.json", "line": 1}]
    assert finding["derived_from"] == []


def test_asset_tier_caps_known_bad_lib_severity(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    _write(repo / "package.json", '{"dependencies": {"node-serialize": "0.0.4"}}\n')

    assert kbl.run(repo, out, "Tier 4 - Prototype", _plugin_root(tmp_path)) == 0

    findings = _findings(out)
    assert len(findings) == 1
    assert findings[0]["severity"] == "Medium"


def test_unknown_library_emits_empty_sidecar(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    _write(repo / "package.json", '{"dependencies": {"left-pad": "1.3.0"}}\n')

    assert kbl.run(repo, out, "T2", _plugin_root(tmp_path)) == 0

    assert _findings(out) == []


def test_duplicate_direct_dependencies_report_once(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    _write(
        repo / "package.json",
        '{"dependencies": {"request": "^2.88.2"}, "devDependencies": {"request": "^2.88.2"}}\n',
    )

    assert kbl.run(repo, out, "T2", _plugin_root(tmp_path)) == 0

    findings = _findings(out)
    assert len(findings) == 1
    assert "request" in findings[0]["title"]


# --- _load_db ----------------------------------------------------------------


def test_load_db_missing_file_returns_empty(tmp_path: Path) -> None:
    assert kbl._load_db(tmp_path) == {"known_bad": []}


def test_load_db_malformed_yaml_returns_empty(tmp_path: Path) -> None:
    _write(tmp_path / "data" / "known-bad-libs.yaml", "this: : : not valid: [")
    assert kbl._load_db(tmp_path) == {"known_bad": []}


def test_load_db_empty_yaml_returns_default(tmp_path: Path) -> None:
    _write(tmp_path / "data" / "known-bad-libs.yaml", "")
    assert kbl._load_db(tmp_path) == {"known_bad": []}


# --- _build_index ------------------------------------------------------------


def test_build_index_skips_non_dict_and_incomplete_entries() -> None:
    db = {
        "known_bad": [
            "not-a-dict",
            {"ecosystem": "npm"},  # no package
            {"package": "foo"},  # no ecosystem
            {"ecosystem": " npm ", "package": " request ", "severity": "High"},
        ]
    }
    idx = kbl._build_index(db)
    assert list(idx.keys()) == [("npm", "request")]


def test_build_index_none_known_bad() -> None:
    assert kbl._build_index({"known_bad": None}) == {}


# --- _cap_by_tier ------------------------------------------------------------


def test_cap_by_tier_t3_caps_critical_to_high() -> None:
    assert kbl._cap_by_tier("Critical", "T3") == "High"


def test_cap_by_tier_t4_caps_high_to_medium() -> None:
    assert kbl._cap_by_tier("High", "T4") == "Medium"


def test_cap_by_tier_below_cap_unchanged() -> None:
    assert kbl._cap_by_tier("Low", "T4") == "Low"


def test_cap_by_tier_t1_no_cap() -> None:
    assert kbl._cap_by_tier("Critical", "T1") == "Critical"


# --- _normalize_tier ---------------------------------------------------------


def test_normalize_tier_none_defaults_t2() -> None:
    assert kbl._normalize_tier(None) == "T2"


def test_normalize_tier_parses_word_form() -> None:
    assert kbl._normalize_tier("Tier 3 - Internal") == "T3"


def test_normalize_tier_unparseable_defaults_t2() -> None:
    assert kbl._normalize_tier("garbage") == "T2"


# --- run() empty index -------------------------------------------------------


def test_run_empty_db_writes_empty_sidecar(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    plugin = tmp_path / "plugin"  # no data file → empty index
    assert kbl.run(repo, out, "T2", plugin) == 0
    assert _findings(out) == []


# --- main() ------------------------------------------------------------------


def test_main_happy_path(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    _write(repo / "package.json", '{"dependencies": {"request": "^2.88.2"}}\n')
    plugin = _plugin_root(tmp_path)
    rc = kbl.main(
        [
            "--repo-root",
            str(repo),
            "--output-dir",
            str(out),
            "--asset-tier",
            "T2",
            "--plugin-root",
            str(plugin),
        ]
    )
    assert rc == 0
    assert len(_findings(out)) == 1


def test_main_repo_root_not_dir(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    rc = kbl.main(["--repo-root", str(tmp_path / "nope"), "--output-dir", str(out)])
    assert rc == 2


def test_main_output_dir_not_dir(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    rc = kbl.main(["--repo-root", str(repo), "--output-dir", str(tmp_path / "nope")])
    assert rc == 2


def test_main_defaults_plugin_root(tmp_path: Path) -> None:
    # No --plugin-root → falls back to real plugin data dir; should still exit 0.
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    _write(repo / "package.json", '{"dependencies": {"left-pad": "1.0.0"}}\n')
    rc = kbl.main(["--repo-root", str(repo), "--output-dir", str(out)])
    assert rc == 0
    assert "findings" in json.loads((out / ".known-bad-libs-findings.json").read_text(encoding="utf-8"))
