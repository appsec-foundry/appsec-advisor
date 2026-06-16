"""Coverage extension for scripts/arch_coverage_to_threats.py.

Targets helper edge branches, skip paths, persist edge cases and CLI subcommands.
Pins current behavior (test-files-only campaign). No producer edits.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "arch_coverage_to_threats.py"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import arch_coverage_to_threats as bridge  # noqa: E402


# --- helper edge branches --------------------------------------------------


def test_component_for_evidence_none_returns_architecture():
    assert bridge._component_for_evidence(None) == ("architecture", "Architecture")


def test_component_for_evidence_empty_file_returns_architecture():
    assert bridge._component_for_evidence([{"file": "   "}]) == (
        "architecture",
        "Architecture",
    )


def test_evidence_for_threat_none():
    assert bridge._evidence_for_threat(None) is None


def test_evidence_for_threat_bad_line_coerces_to_none():
    ev = bridge._evidence_for_threat([{"file": "a.ts", "line": "not-int"}])
    assert ev == {"file": "a.ts", "line": None}


def test_evidence_for_threat_empty_file_returns_none():
    assert bridge._evidence_for_threat([{"file": "", "line": 3}]) is None


# --- select_and_build skip branches ---------------------------------------


def test_select_skips_critical_severity_cap():
    cov = {
        "anti_pattern_candidates": [
            {
                "rule_id": "ARCH-X",
                "confidence": "high",
                "severity_cap": "Critical",
                "evidence": [{"file": "a.ts", "line": 1}],
            }
        ]
    }
    threats, skipped = bridge.select_and_build(cov)
    assert threats == []
    assert skipped[0]["reason"].startswith("severity_cap=Critical")


def test_select_skips_low_confidence_hypothesis():
    cov = {
        "threat_hypotheses": [
            {
                "hypothesis_id": "H-1",
                "rule_id": "ARCH-X",
                "proof_state": "confirmed",
                "confidence": "medium",
            }
        ]
    }
    threats, skipped = bridge.select_and_build(cov)
    assert threats == []
    assert "confidence=medium" in skipped[0]["reason"]


# --- merge_into: non-dict root (line 260) ---------------------------------


def test_merge_into_rejects_non_dict_root(tmp_path: Path):
    p = tmp_path / "merged.json"
    p.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(ValueError, match="root must be a JSON object"):
        bridge.merge_into(p, [])


# --- _build_yaml_hypothesis: positive_signals branches (334, 339, 342-343) -


def test_build_yaml_hypothesis_signal_branches():
    hyp = {
        "hypothesis_id": "H-1",
        "rule_id": "ARCH-XSS-001",
        "positive_signals": [
            "not-a-dict",  # line 334: skip non-dict
            {"line": 5},  # line 339: missing file -> skip
            {"file": "a.ts", "line": "bad"},  # 342-343: bad line -> 0
            {"file": "b.ts", "line": 9, "signal": "s"},
        ],
    }
    out = bridge._build_yaml_hypothesis(hyp, "HYP-001", None)
    assert out["domain"] == "FrontendSec"  # _domain_for_rule mapping
    assert out["evidence"] == [
        {"file": "a.ts", "line": 0, "signal": ""},
        {"file": "b.ts", "line": 9, "signal": "s"},
    ]


# --- persist_hypotheses: promoted_map skip branches (403, 405) ------------


def test_persist_promoted_map_skips_non_dict_and_wrong_source(tmp_path: Path):
    yaml_path = tmp_path / "tm.yaml"
    cov = {
        "threat_hypotheses": [
            {"hypothesis_id": "H-1", "rule_id": "ARCH-XSS-001"},
        ]
    }
    merged = {
        "threats": [
            "not-a-dict",  # line 403 skip
            {"source": "stride", "hypothesis_id": "H-1", "t_id": "T-001"},  # 405 skip
        ]
    }
    res = bridge.persist_hypotheses(cov, yaml_path, merged)
    assert res["appended"] == ["HYP-001"]
    import yaml as _yaml

    doc = _yaml.safe_load(yaml_path.read_text())
    # No promotion linkage since the matching threat had wrong source.
    assert doc["threat_hypotheses"][0]["promoted_threat_id"] is None


# --- persist_hypotheses: existing yaml not a mapping (line 414) -----------


def test_persist_rejects_non_mapping_yaml(tmp_path: Path):
    yaml_path = tmp_path / "tm.yaml"
    yaml_path.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(ValueError, match="root must be a mapping"):
        bridge.persist_hypotheses({"threat_hypotheses": []}, yaml_path, None)


# --- persist_hypotheses: threat_hypotheses not a list (line 420) ----------


def test_persist_rejects_non_list_threat_hypotheses(tmp_path: Path):
    yaml_path = tmp_path / "tm.yaml"
    yaml_path.write_text("threat_hypotheses: notalist\n", encoding="utf-8")
    with pytest.raises(ValueError, match="threat_hypotheses must be a list"):
        bridge.persist_hypotheses({"threat_hypotheses": []}, yaml_path, None)


# --- persist_hypotheses: non-dict hyp in coverage (line 434) --------------


def test_persist_skips_non_dict_hypothesis(tmp_path: Path):
    yaml_path = tmp_path / "tm.yaml"
    cov = {"threat_hypotheses": ["not-a-dict", {"hypothesis_id": "H-1", "rule_id": "R"}]}
    res = bridge.persist_hypotheses(cov, yaml_path, None)
    assert res["appended"] == ["HYP-001"]


# --- CLI: input not found (lines 495-496) ---------------------------------


def test_cli_input_not_found(tmp_path: Path, capsys):
    rc = bridge._main(["emit", "--input", str(tmp_path / "nope.json"), "--output-dir", str(tmp_path)])
    assert rc == 1
    assert "input not found" in capsys.readouterr().err


# --- CLI emit (lines 502-519) --------------------------------------------


def _write_cov(tmp_path: Path) -> Path:
    cov = {
        "anti_pattern_candidates": [
            {
                "rule_id": "ARCH-CORS-001",
                "confidence": "high",
                "severity_cap": "Medium",
                "title": "CORS misconfig",
                "evidence": [{"file": "src/app.ts", "line": 12}],
            }
        ]
    }
    p = tmp_path / "cov.json"
    p.write_text(json.dumps(cov), encoding="utf-8")
    return p


def test_cli_emit_writes_file(tmp_path: Path, capsys):
    cov = _write_cov(tmp_path)
    out_dir = tmp_path / "out"
    rc = bridge._main(["emit", "--input", str(cov), "--output-dir", str(out_dir)])
    assert rc == 0
    target = out_dir / ".arch-coverage-threats.json"
    assert target.is_file()
    data = json.loads(target.read_text())
    assert data["version"] == 1
    assert len(data["threats"]) == 1
    assert capsys.readouterr().out.strip().endswith(".arch-coverage-threats.json")


# --- CLI merge-into: target missing (lines 524-525) -----------------------


def test_cli_merge_into_target_missing(tmp_path: Path, capsys):
    cov = _write_cov(tmp_path)
    rc = bridge._main(
        ["merge-into", "--input", str(cov), "--threats-merged", str(tmp_path / "absent.json")]
    )
    assert rc == 1
    assert "threats-merged not found" in capsys.readouterr().err


def test_cli_merge_into_success(tmp_path: Path, capsys):
    cov = _write_cov(tmp_path)
    merged = tmp_path / "merged.json"
    merged.write_text(json.dumps({"threats": []}), encoding="utf-8")
    rc = bridge._main(["merge-into", "--input", str(cov), "--threats-merged", str(merged)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["merged"]["appended"] == ["T-001"]


# --- CLI persist-hypotheses (lines 535-542) -------------------------------


def test_cli_persist_with_merged(tmp_path: Path, capsys):
    cov = {
        "threat_hypotheses": [
            {
                "hypothesis_id": "H-1",
                "rule_id": "ARCH-XSS-001",
                "title": "XSS",
            }
        ]
    }
    cov_path = tmp_path / "cov.json"
    cov_path.write_text(json.dumps(cov), encoding="utf-8")
    yaml_path = tmp_path / "tm.yaml"
    merged = tmp_path / "merged.json"
    merged.write_text(
        json.dumps(
            {"threats": [{"source": "threat-hypothesis", "hypothesis_id": "H-1", "t_id": "T-007"}]}
        ),
        encoding="utf-8",
    )
    rc = bridge._main(
        [
            "persist-hypotheses",
            "--input",
            str(cov_path),
            "--threat-model",
            str(yaml_path),
            "--threats-merged",
            str(merged),
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["persisted"]["appended"] == ["HYP-001"]
    import yaml as _yaml

    doc = _yaml.safe_load(yaml_path.read_text())
    assert doc["threat_hypotheses"][0]["promoted_threat_id"] == "T-007"


def test_cli_persist_merged_path_absent_is_ignored(tmp_path: Path, capsys):
    # --threats-merged points at a non-existent file: branch where mp.is_file()
    # is False, so merged_data stays None (line 536 false).
    cov = {"threat_hypotheses": [{"hypothesis_id": "H-1", "rule_id": "R", "title": "t"}]}
    cov_path = tmp_path / "cov.json"
    cov_path.write_text(json.dumps(cov), encoding="utf-8")
    yaml_path = tmp_path / "tm.yaml"
    rc = bridge._main(
        [
            "persist-hypotheses",
            "--input",
            str(cov_path),
            "--threat-model",
            str(yaml_path),
            "--threats-merged",
            str(tmp_path / "nope.json"),
        ]
    )
    assert rc == 0


# --- CLI persist-hypotheses RuntimeError branch (lines 540-542) -----------


def test_cli_persist_runtime_error(tmp_path: Path, monkeypatch, capsys):
    cov = {"threat_hypotheses": []}
    cov_path = tmp_path / "cov.json"
    cov_path.write_text(json.dumps(cov), encoding="utf-8")

    def boom(*a, **k):
        raise RuntimeError("PyYAML required")

    monkeypatch.setattr(bridge, "persist_hypotheses", boom)
    rc = bridge._main(
        ["persist-hypotheses", "--input", str(cov_path), "--threat-model", str(tmp_path / "tm.yaml")]
    )
    assert rc == 1
    assert "PyYAML required" in capsys.readouterr().err


# --- __main__ guard (line 549) --------------------------------------------


def test_module_runpy_main_guard(tmp_path: Path):
    import runpy

    cov = _write_cov(tmp_path)
    out_dir = tmp_path / "rp_out"
    argv = sys.argv
    sys.argv = [
        "arch_coverage_to_threats.py",
        "emit",
        "--input",
        str(cov),
        "--output-dir",
        str(out_dir),
    ]
    sys.modules.pop("arch_coverage_to_threats", None)
    try:
        with pytest.raises(SystemExit) as ei:
            runpy.run_path(str(SCRIPT_PATH), run_name="__main__")
        assert ei.value.code == 0
    finally:
        sys.argv = argv
