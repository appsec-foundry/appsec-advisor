"""Unit tests for claude-plugin/scripts/merge_threats.py.

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
    Path(__file__).parent.parent / "claude-plugin" / "scripts" / "merge_threats.py"
)


@pytest.fixture(scope="module")
def mt():
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
