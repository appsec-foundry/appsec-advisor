"""Tests for scripts/render_run_diagnosis.py.

Covers the contract the SKILL layer relies on: a valid sidecar renders the
developer block, an invalid or absent one degrades to silence, and no input
shape can make the script exit non-zero (it runs after the deliverable is
already written and must never fail a run).
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

import render_run_diagnosis as rrd  # noqa: E402

PLUGIN_ROOT = Path(__file__).parent.parent


def _diagnosis(**overrides) -> dict:
    data = {
        "schema_version": 1,
        "generated": "2026-07-28T10:00:00Z",
        "issues_total": 4,
        "issues_examined": 4,
        "examination_cap": None,
        "summary": {"plugin_bug": 1, "environment": 1, "expected": 2, "inconclusive": 0},
        "diagnoses": [
            {
                "issue_id": "ISSUE-001",
                "issue_title": "MAX_TURNS: appsec-stride-analyzer exhausted its budget",
                "verdict": "plugin_bug",
                "confidence": "high",
                "rationale": "The dispatch manifest grants 8 turns to a component with 41 source files.",
                "evidence": ["scripts/build_stride_dispatch_manifest.py:210", ".agent-run.log:812"],
                "root_cause": {
                    "location": "scripts/build_stride_dispatch_manifest.py:210",
                    "component": "stride dispatch",
                    "description": "The cheap-stride target check classifies the component as spare.",
                    "causal_path": "Spare classification pins max_turns to 8, the analyzer stops mid-category.",
                },
                "suggested_fix": "Keep components above the file-count floor out of the spare tier.",
            },
            {
                "issue_id": "ISSUE-002",
                "issue_title": "TOOL_ERROR: mermaid renderer could not open a socket",
                "verdict": "environment",
                "confidence": "high",
                "rationale": "Chrome's socket() call is blocked by the Bash sandbox, not by plugin code.",
                "evidence": [".hook-events.log:44"],
                "root_cause": None,
                "suggested_fix": None,
            },
        ],
    }
    data.update(overrides)
    return data


def _write(tmp_path: Path, data) -> Path:
    (tmp_path / ".run-bugs.json").write_text(json.dumps(data), encoding="utf-8")
    return tmp_path


class TestLoad:
    def test_absent_file_is_not_an_error(self, tmp_path):
        data, err = rrd.load_diagnosis(tmp_path)
        assert data is None and err is None

    def test_malformed_json_reports_an_error(self, tmp_path):
        (tmp_path / ".run-bugs.json").write_text("{not json", encoding="utf-8")
        data, err = rrd.load_diagnosis(tmp_path)
        assert data is None
        assert err and "unreadable" in err

    def test_non_object_payload_reports_an_error(self, tmp_path):
        _write(tmp_path, ["a", "list"])
        data, err = rrd.load_diagnosis(tmp_path)
        assert data is None
        assert err and "not a JSON object" in err


class TestValidate:
    def test_valid_payload_has_no_problems(self):
        assert rrd.validate(_diagnosis(), PLUGIN_ROOT) == []

    def test_unknown_verdict_is_rejected(self):
        data = _diagnosis()
        data["diagnoses"][1]["verdict"] = "probably_fine"
        assert rrd.validate(data, PLUGIN_ROOT)

    def test_plugin_bug_without_root_cause_is_rejected(self):
        """The whole point of the feature — a bug claim must name its cause."""
        data = _diagnosis()
        data["diagnoses"][0]["root_cause"] = None
        assert rrd.validate(data, PLUGIN_ROOT)

    def test_missing_top_level_key_is_rejected(self):
        data = _diagnosis()
        del data["summary"]
        assert rrd.validate(data, PLUGIN_ROOT)

    def test_evidence_must_not_be_empty(self):
        data = _diagnosis()
        data["diagnoses"][0]["evidence"] = []
        assert rrd.validate(data, PLUGIN_ROOT)

    def test_structural_fallback_catches_the_same_shapes(self, monkeypatch):
        """Without jsonschema installed the fallback must still reject a bad verdict."""
        monkeypatch.setitem(sys.modules, "jsonschema", None)
        data = _diagnosis()
        data["diagnoses"][0]["verdict"] = "nope"
        problems = rrd.validate(data, PLUGIN_ROOT)
        assert any("unknown verdict" in p for p in problems)


class TestRender:
    def test_block_names_the_root_cause(self, tmp_path):
        out = "\n".join(rrd.render(_diagnosis(), tmp_path))
        assert "-- Plugin Diagnosis (APPSEC_PLUGIN_DEV) --" in out
        assert "4 of 4 examined" in out
        assert "1 plugin bug" in out and "1 environment" in out and "2 expected" in out
        assert "inconclusive" not in out  # zero counts are omitted
        assert "[ISSUE-001]" in out and "(high confidence)" in out
        assert "scripts/build_stride_dispatch_manifest.py:210" in out
        assert "Causal path" in out and "Suggested fix" in out

    def test_non_bug_verdicts_are_counted_not_detailed(self, tmp_path):
        out = "\n".join(rrd.render(_diagnosis(), tmp_path))
        assert "[ISSUE-002]" not in out
        assert "(1 issue(s) not classified as plugin bugs" in out

    def test_clean_diagnosis_still_reports_the_verdict(self, tmp_path):
        data = _diagnosis()
        data["summary"] = {"plugin_bug": 0, "environment": 1, "expected": 1, "inconclusive": 0}
        data["diagnoses"] = [d for d in data["diagnoses"] if d["verdict"] != "plugin_bug"]
        out = "\n".join(rrd.render(data, tmp_path))
        assert "no plugin bug identified" in out
        assert "Artifact" not in out

    def test_examination_cap_gap_is_surfaced(self, tmp_path):
        data = _diagnosis(issues_total=20, issues_examined=2, examination_cap=12)
        out = "\n".join(rrd.render(data, tmp_path))
        assert "18 lower-severity issue(s) (cap 12)" in out

    def test_empty_diagnoses_render_nothing(self, tmp_path):
        assert rrd.render(_diagnosis(diagnoses=[]), tmp_path) == []

    def test_overlong_fields_are_clipped(self, tmp_path):
        """Only the artifact path may exceed the console width — everything the
        agent authored is clipped or wrapped so a verbose diagnosis cannot
        destroy the block's alignment."""
        data = _diagnosis()
        data["diagnoses"][0]["issue_title"] = "x" * 200
        data["diagnoses"][0]["evidence"] = ["scripts/some_very_long_module_name.py:1234"] * 5
        data["diagnoses"][0]["root_cause"]["description"] = "word " * 120
        out = rrd.render(data, Path("/out"))
        assert "…" in "\n".join(out)
        overlong = [line for line in out if len(line) > 90 and ".run-bugs.json" not in line]
        assert not overlong, overlong


class TestMain:
    @pytest.mark.parametrize(
        "payload",
        [None, "{broken", json.dumps({"schema_version": 1}), json.dumps(_diagnosis())],
        ids=["absent", "malformed", "schema-violation", "valid"],
    )
    def test_never_exits_non_zero(self, tmp_path, payload, capsys):
        if payload is not None:
            (tmp_path / ".run-bugs.json").write_text(payload, encoding="utf-8")
        rc = rrd.main(["--output-dir", str(tmp_path), "--plugin-root", str(PLUGIN_ROOT)])
        assert rc == 0
        capsys.readouterr()

    def test_valid_payload_prints_to_stdout(self, tmp_path, capsys):
        _write(tmp_path, _diagnosis())
        rrd.main(["--output-dir", str(tmp_path), "--plugin-root", str(PLUGIN_ROOT)])
        assert "Plugin Diagnosis" in capsys.readouterr().out

    def test_schema_violation_warns_on_stderr_only(self, tmp_path, capsys):
        _write(tmp_path, {"schema_version": 1, "diagnoses": []})
        rrd.main(["--output-dir", str(tmp_path), "--plugin-root", str(PLUGIN_ROOT)])
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "failed schema validation" in captured.err
