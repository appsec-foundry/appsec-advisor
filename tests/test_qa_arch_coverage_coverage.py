"""Coverage-focused tests for scripts/qa_arch_coverage.py.

Targets non-dict skip branches, _load_json / _load_yaml error paths, the
CLI output-dir-not-found and skip-JSON branches, and the human FAIL print
loop. Pins CURRENT behavior — no producer edits.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import qa_arch_coverage as qa  # noqa: E402


# ---------- non-dict skip branches (73, 92, 103, 128, 169, 195) ----------


def test_security_controls_non_dict_skipped():
    assert qa._rule_ids_in_security_controls({"security_controls": ["str", 1, None]}) == set()


def test_threat_hypotheses_non_dict_skipped():
    assert qa._rule_ids_in_threat_hypotheses({"threat_hypotheses": ["str", 2]}) == set()


def test_threats_merged_non_dict_skipped():
    assert qa._rule_ids_in_threats_merged({"threats": ["str", 3]}) == set()


def test_completeness_rule_not_dict_skipped():
    coverage = {"rules_evaluated": ["str", {"applies": True, "status": "missing"}]}
    # second rule has no rule_id (line 136 path) → skipped, first is non-dict (128)
    issues = qa.check_completeness(coverage, {}, {})
    assert issues == []


def test_completeness_rule_id_not_str():
    coverage = {"rules_evaluated": [{"applies": True, "status": "missing", "rule_id": 7}]}
    assert qa.check_completeness(coverage, {}, {}) == []


def test_semantics_non_dict_threats_and_hypotheses_skipped():
    tm = {"threat_hypotheses": ["str", None]}
    merged = {"threats": ["str", None]}
    assert qa.check_semantics(tm, merged) == []


# ---------- _load_json / _load_yaml (226-227, 233-236) -------------------


def test_load_json_missing(tmp_path):
    assert qa._load_json(tmp_path / "nope.json") is None


def test_load_json_malformed(tmp_path):
    f = tmp_path / "x.json"
    f.write_text("{bad", encoding="utf-8")
    assert qa._load_json(f) is None


def test_load_yaml_missing(tmp_path):
    assert qa._load_yaml(tmp_path / "nope.yaml") is None


def test_load_yaml_malformed(tmp_path):
    f = tmp_path / "x.yaml"
    f.write_text("a: [: broken : yaml", encoding="utf-8")
    assert qa._load_yaml(f) is None


# ---------- CLI paths -----------------------------------------------------


def test_main_output_dir_not_found(tmp_path, capsys):
    rc = qa._main([str(tmp_path / "nope")])
    assert rc == 2
    assert "output-dir not found" in capsys.readouterr().err


def test_main_skip_no_coverage_json(tmp_path, capsys):
    rc = qa._main([str(tmp_path)])
    assert rc == 0
    assert "SKIP" in capsys.readouterr().out


def test_main_skip_no_coverage_json_json(tmp_path, capsys):
    rc = qa._main([str(tmp_path), "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["skipped"] is True


def test_main_ok_human(tmp_path, capsys):
    (tmp_path / ".architecture-coverage.json").write_text(
        json.dumps({"version": 1, "rules_evaluated": []}), encoding="utf-8"
    )
    rc = qa._main([str(tmp_path)])
    assert rc == 0
    assert "OK" in capsys.readouterr().out


def test_main_fail_human_print_loop(tmp_path, capsys):
    """Completeness + semantic violations → FAIL print loop (lines 280-284)."""
    (tmp_path / ".architecture-coverage.json").write_text(
        json.dumps(
            {
                "version": 1,
                "rules_evaluated": [
                    {"rule_id": "ARCH-CORS-001", "applies": True, "status": "missing"}
                ],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".threats-merged.json").write_text(
        json.dumps(
            {
                "threats": [
                    {
                        "source": "architecture-coverage",
                        "rule_id": "ARCH-OTHER-001",
                        "cvss_v4": "CVSS:4.0/...",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    rc = qa._main([str(tmp_path)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "invisible_downstream" in out
    assert "cvss_on_arch_source" in out


def test_main_json_payload(tmp_path, capsys):
    (tmp_path / ".architecture-coverage.json").write_text(
        json.dumps({"version": 1, "rules_evaluated": []}), encoding="utf-8"
    )
    rc = qa._main([str(tmp_path), "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["total"] == 0
