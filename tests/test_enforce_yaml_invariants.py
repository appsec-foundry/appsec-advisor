"""Unit tests for scripts/enforce_yaml_invariants.py (RC.G.3/RC.K gate)."""

from __future__ import annotations

import json
from pathlib import Path

import enforce_yaml_invariants as eyi
import yaml


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _write(output_dir: Path, ydoc: dict | str, mdoc: dict | str | None) -> None:
    yaml_path = output_dir / "threat-model.yaml"
    if isinstance(ydoc, str):
        yaml_path.write_text(ydoc, encoding="utf-8")
    else:
        yaml_path.write_text(yaml.safe_dump(ydoc, sort_keys=False), encoding="utf-8")
    if mdoc is not None:
        merged_path = output_dir / ".threats-merged.json"
        if isinstance(mdoc, str):
            merged_path.write_text(mdoc, encoding="utf-8")
        else:
            merged_path.write_text(json.dumps(mdoc), encoding="utf-8")


# ---------------------------------------------------------------------------
# _evidence_tuples
# ---------------------------------------------------------------------------
class TestEvidenceTuples:
    def test_dict_evidence(self):
        t = {"evidence": {"file": " a.js ", "line": "12"}}
        assert eyi._evidence_tuples(t, prefer_dict=True) == [("a.js", 12)]

    def test_dict_evidence_no_line(self):
        t = {"evidence": {"file": "a.js"}}
        assert eyi._evidence_tuples(t, prefer_dict=True) == [("a.js", None)]

    def test_dict_evidence_bad_line(self):
        t = {"evidence": {"file": "a.js", "line": "nope"}}
        assert eyi._evidence_tuples(t, prefer_dict=True) == [("a.js", None)]

    def test_dict_evidence_empty_file_dropped(self):
        t = {"evidence": {"file": "", "line": 1}}
        assert eyi._evidence_tuples(t, prefer_dict=True) == []

    def test_list_evidence(self):
        t = {"evidence": [{"file": "a.js", "line": 1}, {"file": "b.js", "line": 2}]}
        assert eyi._evidence_tuples(t, prefer_dict=False) == [("a.js", 1), ("b.js", 2)]

    def test_list_evidence_skips_non_dict(self):
        t = {"evidence": ["junk", {"file": "a.js", "line": 1}]}
        assert eyi._evidence_tuples(t, prefer_dict=False) == [("a.js", 1)]

    def test_list_evidence_bad_line(self):
        t = {"evidence": [{"file": "a.js", "line": "x"}]}
        assert eyi._evidence_tuples(t, prefer_dict=False) == [("a.js", None)]

    def test_no_evidence(self):
        assert eyi._evidence_tuples({}, prefer_dict=True) == []


# ---------------------------------------------------------------------------
# _merged_by_tid
# ---------------------------------------------------------------------------
class TestMergedByTid:
    def test_prefers_t_id(self):
        doc = {"threats": [{"t_id": "T-001", "id": "X"}]}
        assert "T-001" in eyi._merged_by_tid(doc)

    def test_falls_back_to_id(self):
        doc = {"threats": [{"id": "T-002"}]}
        assert "T-002" in eyi._merged_by_tid(doc)

    def test_skips_non_dict_and_no_tid(self):
        doc = {"threats": ["junk", {"foo": "bar"}, {"t_id": "T-003"}]}
        out = eyi._merged_by_tid(doc)
        assert list(out) == ["T-003"]

    def test_empty(self):
        assert eyi._merged_by_tid({}) == {}


# ---------------------------------------------------------------------------
# _now / _log
# ---------------------------------------------------------------------------
def test_now_format():
    s = eyi._now()
    assert s.endswith("Z") and "T" in s and len(s) == 20


def test_log_writes(output_dir):
    eyi._log(output_dir, "hello")
    log = (output_dir / ".agent-run.log").read_text(encoding="utf-8")
    assert "YAML_INVARIANT_DRIFT" in log and "hello" in log


def test_log_best_effort_on_oserror(tmp_path):
    # point output_dir at a path whose .agent-run.log cannot be opened
    bad = tmp_path / "nope"  # not a directory -> open(a) raises, swallowed
    bad.write_text("file-not-dir")
    eyi._log(bad, "msg")  # must not raise


# ---------------------------------------------------------------------------
# enforce — error paths
# ---------------------------------------------------------------------------
class TestEnforceErrors:
    def test_missing_yaml(self, output_dir, capsys):
        count, drifts = eyi.enforce(output_dir, report_only=False)
        assert count == -1 and drifts == []
        assert "no yaml" in capsys.readouterr().err

    def test_missing_merged(self, output_dir, capsys):
        (output_dir / "threat-model.yaml").write_text("threats: []", encoding="utf-8")
        count, drifts = eyi.enforce(output_dir, report_only=False)
        assert count == -1 and drifts == []
        assert "no merged file" in capsys.readouterr().err

    def test_parse_error(self, output_dir, capsys):
        _write(output_dir, "threats: [unterminated", "{not json")
        count, drifts = eyi.enforce(output_dir, report_only=False)
        assert count == -1
        assert "parse error" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# enforce — no drift
# ---------------------------------------------------------------------------
class TestEnforceNoDrift:
    def test_lockstep(self, output_dir):
        threat = {"id": "T-001", "stride": "S", "cwe": "CWE-79"}
        _write(output_dir, {"threats": [threat]}, {"threats": [dict(threat, t_id="T-001")]})
        count, drifts = eyi.enforce(output_dir, report_only=False)
        assert count == 0 and drifts == []

    def test_both_none_not_drift(self, output_dir):
        y = {"id": "T-001", "stride": None, "cwe": None}
        m = {"t_id": "T-001"}
        _write(output_dir, {"threats": [y]}, {"threats": [m]})
        count, _ = eyi.enforce(output_dir, report_only=False)
        assert count == 0

    def test_unmatched_threat_skipped(self, output_dir):
        _write(output_dir, {"threats": [{"id": "T-999", "stride": "S"}]}, {"threats": [{"t_id": "T-001", "stride": "T"}]})
        count, _ = eyi.enforce(output_dir, report_only=False)
        assert count == 0

    def test_non_dict_threat_skipped(self, output_dir):
        _write(output_dir, {"threats": ["junk", {"id": "T-001", "stride": "S"}]},
               {"threats": [{"t_id": "T-001", "stride": "S"}]})
        count, _ = eyi.enforce(output_dir, report_only=False)
        assert count == 0


# ---------------------------------------------------------------------------
# enforce — drift detect + repair
# ---------------------------------------------------------------------------
class TestEnforceRepair:
    def test_stride_drift_repaired(self, output_dir):
        y = {"id": "T-001", "stride": "WRONG", "cwe": "CWE-79"}
        m = {"t_id": "T-001", "stride": "S", "cwe": "CWE-79"}
        _write(output_dir, {"threats": [y]}, {"threats": [m]})
        count, drifts = eyi.enforce(output_dir, report_only=False)
        assert count == 1
        assert drifts[0]["threat_id"] == "T-001"
        assert "stride" in drifts[0]["fields"]
        # rewritten yaml carries repaired value + audit trail
        out = yaml.safe_load((output_dir / "threat-model.yaml").read_text())
        rt = out["threats"][0]
        assert rt["stride"] == "S"
        assert "yaml_invariant_drift" in rt["evidence_flags"]
        assert rt["invariant_repaired"][0]["fields"] == ["stride"]
        # log line emitted
        assert "T-001 drift" in (output_dir / ".agent-run.log").read_text()

    def test_cwe_drift_repaired(self, output_dir):
        y = {"id": "T-001", "stride": "S", "cwe": "CWE-1"}
        m = {"t_id": "T-001", "stride": "S", "cwe": "CWE-2"}
        _write(output_dir, {"threats": [y]}, {"threats": [m]})
        count, _ = eyi.enforce(output_dir, report_only=False)
        assert count == 1
        out = yaml.safe_load((output_dir / "threat-model.yaml").read_text())
        assert out["threats"][0]["cwe"] == "CWE-2"

    def test_evidence_drift_dict_to_list(self, output_dir):
        # yaml lost evidence rows that merged carries
        y = {"id": "T-001", "stride": "S", "evidence": {"file": "a.js", "line": 1}}
        m = {"t_id": "T-001", "stride": "S",
             "evidence": [{"file": "a.js", "line": 1}, {"file": "b.js", "line": 2}]}
        _write(output_dir, {"threats": [y]}, {"threats": [m]})
        count, drifts = eyi.enforce(output_dir, report_only=False)
        assert count == 1
        assert "evidence" in drifts[0]["fields"]
        out = yaml.safe_load((output_dir / "threat-model.yaml").read_text())
        ev = out["threats"][0]["evidence"]
        files = {e["file"] for e in ev}
        assert files == {"a.js", "b.js"}

    def test_evidence_drift_list_to_list_appends(self, output_dir):
        # yaml evidence is already a list missing one merged row -> append branch
        y = {"id": "T-001", "stride": "S", "evidence": [{"file": "a.js", "line": 1}]}
        m = {"t_id": "T-001", "stride": "S",
             "evidence": [{"file": "a.js", "line": 1}, {"file": "b.js", "line": 2}]}
        _write(output_dir, {"threats": [y]}, {"threats": [m]})
        count, _ = eyi.enforce(output_dir, report_only=False)
        assert count == 1
        out = yaml.safe_load((output_dir / "threat-model.yaml").read_text())
        files = {e["file"] for e in out["threats"][0]["evidence"]}
        assert files == {"a.js", "b.js"}

    def test_evidence_recovered_when_yaml_had_none(self, output_dir):
        y = {"id": "T-001", "stride": "S"}  # no evidence key
        m = {"t_id": "T-001", "stride": "S", "evidence": [{"file": "b.js", "line": 2}]}
        _write(output_dir, {"threats": [y]}, {"threats": [m]})
        count, _ = eyi.enforce(output_dir, report_only=False)
        assert count == 1
        out = yaml.safe_load((output_dir / "threat-model.yaml").read_text())
        assert out["threats"][0]["evidence"] == [{"file": "b.js", "line": 2}]

    def test_evidence_extra_in_yaml_not_flagged(self, output_dir):
        # yaml has MORE evidence than merged -> no drift (allowed enrichment)
        y = {"id": "T-001", "stride": "S",
             "evidence": [{"file": "a.js", "line": 1}, {"file": "extra.js", "line": 9}]}
        m = {"t_id": "T-001", "stride": "S", "evidence": [{"file": "a.js", "line": 1}]}
        _write(output_dir, {"threats": [y]}, {"threats": [m]})
        count, _ = eyi.enforce(output_dir, report_only=False)
        assert count == 0

    def test_idempotent(self, output_dir):
        y = {"id": "T-001", "stride": "WRONG", "cwe": "CWE-1"}
        m = {"t_id": "T-001", "stride": "S", "cwe": "CWE-1"}
        _write(output_dir, {"threats": [y]}, {"threats": [m]})
        c1, _ = eyi.enforce(output_dir, report_only=False)
        assert c1 == 1
        c2, _ = eyi.enforce(output_dir, report_only=False)
        assert c2 == 0

    def test_merged_none_not_overwritten(self, output_dir):
        # drift where merged cwe is None: yaml differs but repair skips None
        y = {"id": "T-001", "stride": "WRONG"}
        m = {"t_id": "T-001", "stride": "S", "cwe": None}
        _write(output_dir, {"threats": [y]}, {"threats": [m]})
        count, _ = eyi.enforce(output_dir, report_only=False)
        assert count == 1
        out = yaml.safe_load((output_dir / "threat-model.yaml").read_text())
        assert out["threats"][0]["stride"] == "S"


# ---------------------------------------------------------------------------
# enforce — report-only
# ---------------------------------------------------------------------------
class TestEnforceReportOnly:
    def test_report_only_no_rewrite(self, output_dir):
        y = {"id": "T-001", "stride": "WRONG", "cwe": "CWE-1"}
        m = {"t_id": "T-001", "stride": "S", "cwe": "CWE-1"}
        _write(output_dir, {"threats": [y]}, {"threats": [m]})
        before = (output_dir / "threat-model.yaml").read_text()
        count, drifts = eyi.enforce(output_dir, report_only=True)
        assert count == 1
        assert (output_dir / "threat-model.yaml").read_text() == before


# ---------------------------------------------------------------------------
# main / CLI
# ---------------------------------------------------------------------------
class TestMain:
    def test_main_lockstep(self, output_dir, capsys):
        threat = {"id": "T-001", "stride": "S"}
        _write(output_dir, {"threats": [threat]}, {"threats": [dict(threat, t_id="T-001")]})
        rc = eyi.main([str(output_dir)])
        assert rc == 0
        assert "lock-step" in capsys.readouterr().out

    def test_main_repaired_returns_0(self, output_dir, capsys):
        y = {"id": "T-001", "stride": "WRONG"}
        m = {"t_id": "T-001", "stride": "S"}
        _write(output_dir, {"threats": [y]}, {"threats": [m]})
        rc = eyi.main([str(output_dir)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "repaired" in out and "T-001" in out

    def test_main_report_only_returns_1(self, output_dir, capsys):
        y = {"id": "T-001", "stride": "WRONG"}
        m = {"t_id": "T-001", "stride": "S"}
        _write(output_dir, {"threats": [y]}, {"threats": [m]})
        rc = eyi.main([str(output_dir), "--report-only"])
        assert rc == 1
        assert "reported (no rewrite)" in capsys.readouterr().out

    def test_main_io_error_returns_2(self, output_dir, capsys):
        rc = eyi.main([str(output_dir)])  # no files present
        assert rc == 2

    def test_main_many_drifts_truncated(self, output_dir, capsys):
        ythreats = [{"id": f"T-{i:03d}", "stride": "WRONG"} for i in range(1, 9)]
        mthreats = [{"t_id": f"T-{i:03d}", "stride": "S"} for i in range(1, 9)]
        _write(output_dir, {"threats": ythreats}, {"threats": mthreats})
        rc = eyi.main([str(output_dir)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "and 2 more" in out


def test_cli_subprocess(run_plugin_script, output_dir):
    threat = {"id": "T-001", "stride": "S"}
    _write(output_dir, {"threats": [threat]}, {"threats": [dict(threat, t_id="T-001")]})
    res = run_plugin_script("enforce_yaml_invariants.py", str(output_dir), check=False)
    assert res.returncode == 0
    assert "lock-step" in res.stdout
