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
