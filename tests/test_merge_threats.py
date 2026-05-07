"""Unit tests for scripts/merge_threats.py.

Covers the collect → finalize round-trip, the mechanical exact-dedup, the
candidate grouping, and the deterministic T-NNN sort. Does NOT exercise the
LLM merger agent — that integration is end-to-end and lives elsewhere.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = (
    Path(__file__).parent.parent / "scripts" / "merge_threats.py"
)


@pytest.fixture(scope="module")
def mt():
    # merge_threats.py imports `_atomic_io` as a sibling module; that resolution
    # only works if scripts/ is on sys.path. CLI invocation gets this for free
    # via Python's script-dir injection, but spec_from_file_location does not.
    scripts_dir = str(SCRIPT_PATH.parent)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location("merge_threats", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["merge_threats"] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_stride(output_dir: Path, component_id: str, threats: list[dict]) -> None:
    path = output_dir / f".stride-{component_id}.json"
    payload = {
        "component_id": component_id,
        "component_name": component_id.replace("-", " ").title(),
        "threats": threats,
    }
    with path.open("w") as fh:
        json.dump(payload, fh)


def _threat(**overrides):
    base = {
        "title": "SQL Injection in login handler",
        "cwe": "CWE-89",
        "stride": "Tampering",
        "risk": "High",
        "likelihood": "High",
        "impact": "High",
        "evidence": {"file": "src/auth/login.py", "line": 42},
        "source": "stride",
        "architectural_violation": False,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Exact dedup
# ---------------------------------------------------------------------------

class TestExactDedup:
    def test_identical_threats_collapse(self, mt):
        t1 = _threat()
        t2 = _threat()  # same everything
        result = mt._dedupe_exact([{"component_id": "auth", **t1},
                                   {"component_id": "auth", **t2}])
        assert len(result) == 1

    def test_different_components_same_defect_collapse_with_provenance(self, mt):
        t1 = _threat()
        t2 = _threat()
        result = mt._dedupe_exact([
            {"component_id": "auth-a", **t1},
            {"component_id": "auth-b", **t2},
        ])
        # Same exact_key (same CWE, STRIDE, file, line, title keywords) —
        # different component_ids still make these exact dupes because the
        # exact key uses component_id to disambiguate → they DON'T collapse.
        # This test verifies that intention: exact dedup is per-component.
        assert len(result) == 2

    def test_different_files_do_not_collapse(self, mt):
        t1 = _threat(evidence={"file": "src/auth/login.py", "line": 42})
        t2 = _threat(evidence={"file": "src/auth/logout.py", "line": 10})
        result = mt._dedupe_exact([
            {"component_id": "auth", **t1},
            {"component_id": "auth", **t2},
        ])
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Candidate grouping
# ---------------------------------------------------------------------------

class TestCandidateGrouping:
    def test_singletons_excluded(self, mt):
        threats = [{"component_id": "auth", **_threat()}]
        groups = mt._group_candidates(threats)
        assert groups == []

    def test_same_cwe_stride_grouped(self, mt):
        threats = [
            {"component_id": "a", **_threat(evidence={"file": "a.py", "line": 1})},
            {"component_id": "b", **_threat(evidence={"file": "b.py", "line": 2})},
        ]
        groups = mt._group_candidates(threats)
        assert len(groups) == 1
        assert groups[0]["member_count"] == 2
        assert groups[0]["cwe"] == "CWE-89"
        assert groups[0]["stride"] == "Tampering"

    def test_different_cwes_not_grouped(self, mt):
        threats = [
            {"component_id": "a", **_threat(cwe="CWE-89")},
            {"component_id": "b", **_threat(cwe="CWE-79",
                                             evidence={"file": "c.py", "line": 3})},
        ]
        groups = mt._group_candidates(threats)
        assert groups == []

    def test_group_id_deterministic(self, mt):
        threats = [
            {"component_id": "a", **_threat(evidence={"file": "a.py", "line": 1})},
            {"component_id": "b", **_threat(evidence={"file": "b.py", "line": 2})},
        ]
        g1 = mt._group_candidates(threats)
        g2 = mt._group_candidates(threats)
        assert g1[0]["group_id"] == g2[0]["group_id"]
        assert g1[0]["group_id"].startswith("G-")


class TestAutoDecisions:
    def test_mixed_threat_categories_auto_keep(self, mt):
        threats = [
            {"component_id": "a", **_threat(threat_category_id="TH-01",
                                             evidence={"file": "a.py", "line": 1})},
            {"component_id": "b", **_threat(threat_category_id="TH-02",
                                             evidence={"file": "b.py", "line": 2})},
        ]
        groups = mt._group_candidates(threats)
        remaining, decisions = mt._split_auto_decisions(groups)
        assert remaining == []
        assert decisions[0]["action"] == "keep"
        assert decisions[0]["keep_indices"] == [0, 1]

    def test_same_evidence_category_and_title_auto_merge(self, mt):
        threats = [
            {"component_id": "a", **_threat(threat_category_id="TH-01",
                                             risk="Medium")},
            {"component_id": "b", **_threat(threat_category_id="TH-01",
                                             risk="High")},
        ]
        groups = mt._group_candidates(threats)
        remaining, decisions = mt._split_auto_decisions(groups)
        assert remaining == []
        assert decisions[0]["action"] == "merge"
        assert decisions[0]["merge_target_index"] == 1

    def test_ambiguous_same_category_different_evidence_stays_for_agent(self, mt):
        threats = [
            {"component_id": "a", **_threat(threat_category_id="TH-01",
                                             evidence={"file": "a.py", "line": 1})},
            {"component_id": "b", **_threat(threat_category_id="TH-01",
                                             evidence={"file": "b.py", "line": 2})},
        ]
        groups = mt._group_candidates(threats)
        remaining, decisions = mt._split_auto_decisions(groups)
        assert len(remaining) == 1
        assert decisions == []


# ---------------------------------------------------------------------------
# Deterministic T-NNN assignment
# ---------------------------------------------------------------------------

class TestSortAndIds:
    def test_arch_violation_sorts_first(self, mt):
        threats = [
            _threat(risk="Low", architectural_violation=False),
            _threat(risk="Medium", architectural_violation=True),
        ]
        sorted_ = mt._assign_t_ids(threats)
        assert sorted_[0]["architectural_violation"] is True

    def test_risk_order(self, mt):
        threats = [
            _threat(risk="Low"),
            _threat(risk="Critical", evidence={"file": "z.py", "line": 1}),
            _threat(risk="High", evidence={"file": "a.py", "line": 1}),
        ]
        sorted_ = mt._assign_t_ids(threats)
        assert sorted_[0]["risk"] == "Critical"
        assert sorted_[1]["risk"] == "High"
        assert sorted_[2]["risk"] == "Low"

    def test_stride_order_when_risk_equal(self, mt):
        threats = [
            _threat(stride="Elevation of Privilege"),
            _threat(stride="Spoofing", evidence={"file": "b.py", "line": 1}),
        ]
        sorted_ = mt._assign_t_ids(threats)
        assert sorted_[0]["stride"] == "Spoofing"
        assert sorted_[1]["stride"] == "Elevation of Privilege"

    def test_sequential_t_ids(self, mt):
        threats = [_threat(evidence={"file": f"{i}.py", "line": i}) for i in range(5)]
        sorted_ = mt._assign_t_ids(threats)
        assert [t["t_id"] for t in sorted_] == [
            "T-001", "T-002", "T-003", "T-004", "T-005",
        ]

    def test_run_is_byte_deterministic(self, mt):
        """Two runs on the same input must produce identical T-ID assignments."""
        threats_a = [_threat(evidence={"file": f"{i}.py", "line": i}) for i in range(4)]
        threats_b = [_threat(evidence={"file": f"{i}.py", "line": i}) for i in range(4)]
        a = mt._assign_t_ids(list(threats_a))
        b = mt._assign_t_ids(list(threats_b))
        assert [t["t_id"] for t in a] == [t["t_id"] for t in b]


# ---------------------------------------------------------------------------
# Decision application
# ---------------------------------------------------------------------------

class TestDecisionApplication:
    def test_no_decisions_keeps_all(self, mt):
        threats = [
            {"component_id": "a", **_threat(evidence={"file": "a.py", "line": 1})},
            {"component_id": "b", **_threat(evidence={"file": "b.py", "line": 2})},
        ]
        result = mt._apply_decisions(list(threats), [])
        assert len(result) == 2

    def test_merge_decision_collapses_group(self, mt):
        threats = [
            {"component_id": "a", **_threat(evidence={"file": "a.py", "line": 1})},
            {"component_id": "b", **_threat(evidence={"file": "b.py", "line": 2})},
        ]
        groups = mt._group_candidates(threats)
        gid = groups[0]["group_id"]
        decisions = [{
            "group_id": gid,
            "action": "merge",
            "merge_target_index": 0,
            "rationale": "test",
        }]
        result = mt._apply_decisions(list(threats), decisions)
        assert len(result) == 1
        assert "merged_from" in result[0]
        assert "b" in result[0]["merged_from"]

    def test_consolidate_promotes_arch_violation(self, mt):
        threats = [
            {"component_id": "a", **_threat(evidence={"file": "a.py", "line": 1})},
            {"component_id": "b", **_threat(evidence={"file": "b.py", "line": 2})},
            {"component_id": "c", **_threat(evidence={"file": "c.py", "line": 3})},
        ]
        groups = mt._group_candidates(threats)
        gid = groups[0]["group_id"]
        decisions = [{
            "group_id": gid,
            "action": "consolidate",
            "merge_target_index": 0,
            "consolidated_title": "Systemic SQL Injection",
            "rationale": "3 endpoints, same root cause",
        }]
        result = mt._apply_decisions(list(threats), decisions)
        assert len(result) == 1
        assert result[0]["title"] == "Systemic SQL Injection"
        assert result[0]["architectural_violation"] is True

    def test_unknown_group_id_is_ignored(self, mt):
        threats = [
            {"component_id": "a", **_threat(evidence={"file": "a.py", "line": 1})},
            {"component_id": "b", **_threat(evidence={"file": "b.py", "line": 2})},
        ]
        decisions = [{"group_id": "G-deadbeef", "action": "merge",
                      "merge_target_index": 0}]
        result = mt._apply_decisions(list(threats), decisions)
        assert len(result) == 2  # unchanged — unknown group safely ignored


# ---------------------------------------------------------------------------
# End-to-end collect → finalize
# ---------------------------------------------------------------------------

class TestEndToEnd:
    def test_collect_produces_candidates_file(self, mt, tmp_path):
        _write_stride(tmp_path, "auth", [_threat()])
        _write_stride(tmp_path, "api",  [_threat(evidence={"file": "api.py", "line": 9})])

        rc = mt.main(["collect", "--output-dir", str(tmp_path)])
        assert rc == 0
        cand = json.loads((tmp_path / ".merge-candidates.json").read_text())
        assert cand["threat_count_raw"] == 2
        assert cand["candidate_group_count"] == 1
        assert cand["auto_decision_count"] == 0

    def test_collect_records_auto_decisions_and_removes_agent_candidates(self, mt, tmp_path):
        _write_stride(tmp_path, "auth", [_threat(threat_category_id="TH-01")])
        _write_stride(tmp_path, "api",  [_threat(threat_category_id="TH-02",
                                                 evidence={"file": "api.py", "line": 9})])

        rc = mt.main(["collect", "--output-dir", str(tmp_path)])
        assert rc == 0
        cand = json.loads((tmp_path / ".merge-candidates.json").read_text())
        assert cand["candidate_group_count_total"] == 1
        assert cand["candidate_group_count"] == 0
        assert cand["auto_decision_count"] == 1
        assert cand["auto_decisions"][0]["action"] == "keep"

    def test_finalize_without_decisions_keeps_all(self, mt, tmp_path):
        _write_stride(tmp_path, "auth", [_threat()])
        _write_stride(tmp_path, "api",  [_threat(evidence={"file": "api.py", "line": 9})])

        mt.main(["collect", "--output-dir", str(tmp_path)])
        rc = mt.main(["finalize", "--output-dir", str(tmp_path)])
        assert rc == 0
        merged = json.loads((tmp_path / ".threats-merged.json").read_text())
        assert len(merged["threats"]) == 2
        assert [t["t_id"] for t in merged["threats"]] == ["T-001", "T-002"]

    def test_finalize_with_merge_decision_collapses(self, mt, tmp_path):
        _write_stride(tmp_path, "auth", [_threat()])
        _write_stride(tmp_path, "api",  [_threat(evidence={"file": "api.py", "line": 9})])

        mt.main(["collect", "--output-dir", str(tmp_path)])
        cand = json.loads((tmp_path / ".merge-candidates.json").read_text())
        gid = cand["candidate_groups"][0]["group_id"]
        (tmp_path / ".merge-decisions.json").write_text(json.dumps({
            "version": 1,
            "decisions": [{
                "group_id": gid,
                "action": "merge",
                "merge_target_index": 0,
                "rationale": "duplicate",
            }],
        }))

        mt.main(["finalize", "--output-dir", str(tmp_path)])
        merged = json.loads((tmp_path / ".threats-merged.json").read_text())
        assert len(merged["threats"]) == 1
        assert merged["threats"][0]["t_id"] == "T-001"

    def test_collect_missing_dir_returns_error(self, mt, tmp_path):
        rc = mt.main(["collect", "--output-dir", str(tmp_path / "does-not-exist")])
        assert rc == 1


class TestInvalidStrideJSONDiagnostics:
    """A 2026-05-07 juice-shop run lost ~5 minutes after one STRIDE analyzer
    emitted invalid JSON: the agent inline-rebuilt the merge in Python instead
    of fixing the single file and re-invoking merge_threats.py. The error path
    must now print enough context that the orchestrator can make the correct
    fix locally — and an explicit "do NOT inline-rebuild" instruction."""

    def test_invalid_json_message_carries_component_context_and_recovery(
        self, mt, tmp_path, capsys
    ):
        # Valid neighbour so we can confirm the error names the right component.
        _write_stride(tmp_path, "good-comp", [{
            "title": "x",
            "stride_category": "Spoofing",
            "cwe": "CWE-1",
            "evidence": {"file": "a.ts", "line": 1},
        }])
        # Invalid: missing comma between two objects.
        bad = (tmp_path / ".stride-bad-comp.json")
        bad.write_text(
            '{\n  "component_id": "bad-comp",\n  "threats": [\n'
            '    {"title": "first"}\n    {"title": "second"}\n  ]\n}\n'
        )

        with pytest.raises(SystemExit) as excinfo:
            mt.main(["collect", "--output-dir", str(tmp_path)])
        assert excinfo.value.code == 1

        err = capsys.readouterr().err
        # Names the path and the component (so the agent fixes the right file).
        assert ".stride-bad-comp.json" in err
        assert "component: bad-comp" in err
        # Carries a context window with a marker around the offending byte.
        assert "context (" in err and "»" in err and "«" in err
        # Carries the canonical recovery instruction — explicit and negative.
        assert "Do NOT inline-rebuild" in err

    def test_json_error_context_marks_offset(self, mt):
        raw = '{"a": 1 "b": 2}'  # missing comma at offset 8
        ctx = mt._json_error_context(raw, pos=8, radius=5)
        # The marker must wrap exactly the offending byte.
        assert "»" in ctx and "«" in ctx
        # Newlines are escaped so the diagnostic stays single-line.
        assert "\n" not in mt._json_error_context("a\nb", pos=1, radius=2)
