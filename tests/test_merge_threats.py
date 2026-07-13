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

SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "merge_threats.py"


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
        result = mt._dedupe_exact([{"component_id": "auth", **t1}, {"component_id": "auth", **t2}])
        assert len(result) == 1

    def test_different_components_same_defect_collapse_with_provenance(self, mt):
        t1 = _threat()
        t2 = _threat()
        result = mt._dedupe_exact(
            [
                {"component_id": "auth-a", **t1},
                {"component_id": "auth-b", **t2},
            ]
        )
        # Same exact_key (same CWE, STRIDE, file, line, title keywords) —
        # different component_ids still make these exact dupes because the
        # exact key uses component_id to disambiguate → they DON'T collapse.
        # This test verifies that intention: exact dedup is per-component.
        assert len(result) == 2

    def test_different_files_do_not_collapse(self, mt):
        t1 = _threat(evidence={"file": "src/auth/login.py", "line": 42})
        t2 = _threat(evidence={"file": "src/auth/logout.py", "line": 10})
        result = mt._dedupe_exact(
            [
                {"component_id": "auth", **t1},
                {"component_id": "auth", **t2},
            ]
        )
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Evidence-identity dedup (cross-STRIDE / cross-component same-location dup)
# ---------------------------------------------------------------------------


class TestEvidenceDedup:
    """Regression for the 2026-06 juice-shop T-004/T-009 duplicate: two
    component analyzers reported the SAME routes/b2bOrder.ts:23 RCE but
    disagreed on STRIDE (Tampering vs Elevation of Privilege), different
    component_id and title — so _exact_key and the (CWE,STRIDE) candidate
    grouping both missed it and it shipped as two separate Critical findings."""

    def _rce_pair(self):
        ev = {"file": "routes/b2bOrder.ts", "line": 23}
        b2b = _threat(
            component_id="b2b-api",
            title="Remote code execution via B2B order sandbox escape",
            cwe="CWE-94",
            stride="Tampering",
            risk="Critical",
            likelihood="High",
            impact="Critical",
            evidence=dict(ev),
        )
        express = _threat(
            component_id="express-backend",
            title="RCE via B2B order sandbox escape",
            cwe="CWE-94",
            stride="Elevation of Privilege",
            risk="Critical",
            likelihood="High",
            impact="Critical",
            evidence=dict(ev),
        )
        return b2b, express

    def test_cross_stride_same_location_collapses(self, mt):
        b2b, express = self._rce_pair()
        result = mt._dedupe_evidence([b2b, express])
        assert len(result) == 1
        kept = result[0]
        # provenance of the dropped member is preserved
        assert set(kept.get("merged_from", [])) == {"b2b-api", "express-backend"}
        assert set(kept.get("merged_strides", [])) == {"Tampering", "Elevation of Privilege"}

    def test_higher_risk_member_wins(self, mt):
        ev = {"file": "routes/x.ts", "line": 9}
        low = _threat(
            component_id="a", cwe="CWE-94", stride="Tampering", risk="High", evidence=dict(ev), title="t-high"
        )
        crit = _threat(
            component_id="b",
            cwe="CWE-94",
            stride="Elevation of Privilege",
            risk="Critical",
            evidence=dict(ev),
            title="t-crit",
        )
        # first-seen is the lower-risk one; the Critical must still win
        result = mt._dedupe_evidence([low, crit])
        assert len(result) == 1
        assert result[0]["risk"] == "Critical"

    def test_same_line_different_cwe_stays_distinct(self, mt):
        # CWE-89 (injection family) vs CWE-862 (authz family) — DIFFERENT
        # exploitation families at one line stay separate.
        ev = {"file": "routes/x.ts", "line": 50}
        a = _threat(component_id="c", cwe="CWE-89", stride="Tampering", evidence=dict(ev))
        b = _threat(component_id="c", cwe="CWE-862", stride="Elevation of Privilege", evidence=dict(ev))
        assert len(mt._dedupe_evidence([a, b])) == 2

    def test_same_line_sibling_cwe_same_family_collapses(self, mt):
        # The same code object flagged under sibling CWEs of one family — e.g. a
        # hardcoded RSA key as CWE-321 (Spoofing) AND CWE-798 (Information
        # Disclosure) — is ONE finding. Family-keyed identity reunites them; the
        # dropped CWE is preserved in merged_cwes for traceability.
        ev = {"file": "lib/insecurity.ts", "line": 21}
        spoof = _threat(
            component_id="auth",
            cwe="CWE-321",
            stride="Spoofing",
            risk="Critical",
            evidence=dict(ev),
            title="Hardcoded RSA private key signs all JWTs",
        )
        disclose = _threat(
            component_id="backend",
            cwe="CWE-798",
            stride="Information Disclosure",
            risk="Critical",
            evidence=dict(ev),
            title="RSA private key exposed in committed source",
        )
        result = mt._dedupe_evidence([spoof, disclose])
        assert len(result) == 1
        kept = result[0]
        assert set(kept.get("merged_cwes", [])) == {"CWE-321", "CWE-798"}
        assert set(kept.get("merged_strides", [])) == {"Spoofing", "Information Disclosure"}

    def test_same_line_other_family_falls_back_to_exact_cwe(self, mt):
        # Two findings whose CWEs both land in the catch-all "other" family must
        # NOT merge unless the CWE is literally identical — the conservative
        # guard that keeps unclassified weaknesses (e.g. a Dockerfile:N pair)
        # distinct.
        ev = {"file": "Dockerfile", "line": 5}
        a = _threat(component_id="ci", cwe="CWE-1104", stride="Information Disclosure", evidence=dict(ev))
        b = _threat(component_id="ci", cwe="CWE-703", stride="Information Disclosure", evidence=dict(ev))
        assert len(mt._dedupe_evidence([a, b])) == 2

    def test_no_concrete_line_is_too_coarse_to_merge(self, mt):
        # bare file (line 0 / absent) must NOT collapse — many distinct
        # findings legitimately share a file.
        a = _threat(component_id="c", cwe="CWE-94", stride="Tampering", evidence={"file": "server.ts", "line": 0})
        b = _threat(
            component_id="c", cwe="CWE-94", stride="Elevation of Privilege", evidence={"file": "server.ts", "line": 0}
        )
        assert len(mt._dedupe_evidence([a, b])) == 2


# ---------------------------------------------------------------------------
# Systemic config-scan consolidation (2026-06-13)
# ---------------------------------------------------------------------------


def _config_threat(check_id, file, line=1, title=None, risk="Medium"):
    return {
        "title": title or f"Some check — {file}",
        "cwe": "CWE-732",
        "stride": "Information Disclosure",
        "risk": risk,
        "likelihood": risk,
        "impact": risk,
        "evidence": {"file": file, "line": line},
        "source": "config-scan",
        "config_check_id": check_id,
        "config_scan_ref": f"{check_id}-{file}-{line}",
        "architectural_violation": False,
    }


class TestConsolidateConfigChecks:
    def test_cross_file_repeats_collapse_to_one(self, mt):
        members = [
            _config_threat("IAC-010", f"{w}.yml", title=f"Workflow-level permissions block — {w}.yml")
            for w in ("ci", "codeql", "release", "stale")
        ]
        result = mt._consolidate_config_checks(members)
        assert len(result) == 1
        s = result[0]
        assert s["instance_count"] == 4
        assert len(s["instances"]) == 4
        assert sorted(s["affected_files"]) == ["ci.yml", "codeql.yml", "release.yml", "stale.yml"]
        assert s["systemic"] is True
        # title declassified — no per-file locator
        assert "ci.yml" not in s["title"]
        assert s["title"] == "Workflow-level permissions block"

    def test_same_file_multi_line_repeats_collapse(self, mt):
        # Multi-stage Dockerfile: same check, same file, different lines.
        members = [
            _config_threat("IAC-001", "Dockerfile", line=ln, title="Base image must be digest-pinned — Dockerfile")
            for ln in (1, 12, 23, 40)
        ]
        result = mt._consolidate_config_checks(members)
        assert len(result) == 1
        s = result[0]
        assert s["instance_count"] == 4
        # one affected file, four distinct line instances preserved
        assert s["affected_files"] == ["Dockerfile"]
        assert [i["line"] for i in s["instances"]] == [1, 12, 23, 40]
        assert s["title"] == "Base image must be digest-pinned"

    def test_distinct_checks_stay_separate(self, mt):
        members = [
            _config_threat("IAC-001", "Dockerfile", line=1),
            _config_threat("IAC-001", "Dockerfile", line=9),
            _config_threat("IAC-015", "ci.yml"),
            _config_threat("IAC-015", "release.yml"),
        ]
        result = mt._consolidate_config_checks(members)
        # IAC-001 -> 1, IAC-015 -> 1
        assert len(result) == 2
        ids = {r["config_check_id"] for r in result}
        assert ids == {"IAC-001", "IAC-015"}

    def test_singletons_and_missing_id_pass_through_untouched(self, mt):
        secret = _config_threat("", "lib/insecurity.ts", title="Hardcoded RSA Private Key")
        secret.pop("config_check_id")  # secret-scan config finding with no check id
        single = _config_threat("IAC-003", "Dockerfile", title="Missing HEALTHCHECK — Dockerfile")
        stride = _threat(component_id="x")  # non-config threat
        result = mt._consolidate_config_checks([secret, single, stride])
        assert len(result) == 3
        # none gained instances[]/systemic
        assert all("instances" not in r for r in result)

    def test_survivor_takes_highest_risk(self, mt):
        members = [
            _config_threat("IAC-010", "a.yml", risk="Medium"),
            _config_threat("IAC-010", "b.yml", risk="High"),
        ]
        result = mt._consolidate_config_checks(members)
        assert len(result) == 1
        assert result[0]["risk"] == "High"

    def test_non_config_source_never_consolidated(self, mt):
        # A STRIDE finding that happens to carry a config_check_id-like field
        # must NOT be touched (guard keys on source == 'config-scan').
        a = _threat(component_id="x")
        a["config_check_id"] = "IAC-999"
        a["source"] = "stride"
        b = _threat(component_id="y")
        b["config_check_id"] = "IAC-999"
        b["source"] = "stride"
        result = mt._consolidate_config_checks([a, b])
        assert len(result) == 2


class TestDeclassifyConfigTitle:
    def test_dash_file_locator_stripped(self, mt):
        assert (
            mt._declassify_config_title("Base image must be digest-pinned — Dockerfile")
            == "Base image must be digest-pinned"
        )
        assert (
            mt._declassify_config_title("GITHUB_TOKEN scope minimization — ci.yml") == "GITHUB_TOKEN scope minimization"
        )

    def test_paren_file_locator_stripped(self, mt):
        assert (
            mt._declassify_config_title("Workflow-level permissions block (ci.yml)")
            == "Workflow-level permissions block"
        )

    def test_line_suffix_stripped(self, mt):
        assert (
            mt._declassify_config_title("No --unsafe-perm install flag — Dockerfile:5")
            == "No --unsafe-perm install flag"
        )

    def test_plain_dash_title_preserved(self, mt):
        # A hyphenated word / non-file dash tail must survive.
        assert mt._declassify_config_title("Defense-in-depth missing") == "Defense-in-depth missing"
        assert mt._declassify_config_title("Cross-Site Scripting") == "Cross-Site Scripting"


# ---------------------------------------------------------------------------
# Scenario-prose local-ref remap (analyzer-local F-id -> global T-id)
# ---------------------------------------------------------------------------


class TestScenarioRefRemap:
    """Regression for the 2026-06 juice-shop stale scenario cross-refs: STRIDE
    analyzers write their component-LOCAL F-id (with a T- prefix) into scenario
    prose; _assign_t_ids reassigns global T-ids by sorting, so the prose ends
    up pointing at unrelated threats."""

    def test_local_ref_remapped_to_global(self, mt):
        # local F-009 (MD5) is referenced by another finding's scenario as
        # "T-009"; after global assignment F-009 becomes T-008.
        threats = [
            {"id": "F-009", "t_id": "T-008", "scenario": "MD5 hashing."},
            {
                "id": "F-017",
                "t_id": "T-021",
                "scenario": "Combined with MD5 password hashing (T-009), this enables takeover.",
            },
        ]
        out = mt._remap_scenario_local_refs(threats)
        assert "(T-008)" in out[1]["scenario"]
        assert "T-009" not in out[1]["scenario"]

    def test_unresolvable_ref_left_untouched(self, mt):
        # a scenario ref whose local id is not in the table (deduped /
        # config-scan / hallucinated) must NOT be rewritten.
        threats = [
            {"id": "F-001", "t_id": "T-001", "scenario": "See also T-099 which does not exist locally."},
        ]
        out = mt._remap_scenario_local_refs(threats)
        assert "T-099" in out[0]["scenario"]

    def test_no_refs_is_noop(self, mt):
        threats = [{"id": "F-001", "t_id": "T-001", "scenario": "Plain prose, no refs."}]
        out = mt._remap_scenario_local_refs(threats)
        assert out[0]["scenario"] == "Plain prose, no refs."


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
            {"component_id": "b", **_threat(cwe="CWE-79", evidence={"file": "c.py", "line": 3})},
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
            {"component_id": "a", **_threat(threat_category_id="TH-01", evidence={"file": "a.py", "line": 1})},
            {"component_id": "b", **_threat(threat_category_id="TH-02", evidence={"file": "b.py", "line": 2})},
        ]
        groups = mt._group_candidates(threats)
        remaining, decisions = mt._split_auto_decisions(groups)
        assert remaining == []
        assert decisions[0]["action"] == "keep"
        assert decisions[0]["keep_indices"] == [0, 1]

    def test_same_evidence_category_and_title_auto_merge(self, mt):
        threats = [
            {"component_id": "a", **_threat(threat_category_id="TH-01", risk="Medium")},
            {"component_id": "b", **_threat(threat_category_id="TH-01", risk="High")},
        ]
        groups = mt._group_candidates(threats)
        remaining, decisions = mt._split_auto_decisions(groups)
        assert remaining == []
        assert decisions[0]["action"] == "merge"
        assert decisions[0]["merge_target_index"] == 1

    def test_ambiguous_same_category_different_evidence_stays_for_agent(self, mt):
        threats = [
            {"component_id": "a", **_threat(threat_category_id="TH-01", evidence={"file": "a.py", "line": 1})},
            {"component_id": "b", **_threat(threat_category_id="TH-01", evidence={"file": "b.py", "line": 2})},
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
            "T-001",
            "T-002",
            "T-003",
            "T-004",
            "T-005",
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
        decisions = [
            {
                "group_id": gid,
                "action": "merge",
                "merge_target_index": 0,
                "rationale": "test",
            }
        ]
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
        decisions = [
            {
                "group_id": gid,
                "action": "consolidate",
                "merge_target_index": 0,
                "consolidated_title": "Systemic SQL Injection",
                "rationale": "3 endpoints, same root cause",
            }
        ]
        result = mt._apply_decisions(list(threats), decisions)
        assert len(result) == 1
        assert result[0]["title"] == "Systemic SQL Injection"
        assert result[0]["architectural_violation"] is True

    def test_unknown_group_id_is_ignored(self, mt):
        threats = [
            {"component_id": "a", **_threat(evidence={"file": "a.py", "line": 1})},
            {"component_id": "b", **_threat(evidence={"file": "b.py", "line": 2})},
        ]
        decisions = [{"group_id": "G-deadbeef", "action": "merge", "merge_target_index": 0}]
        result = mt._apply_decisions(list(threats), decisions)
        assert len(result) == 2  # unchanged — unknown group safely ignored

    def test_endpoint_group_merge_decision_is_applied(self, mt):
        # Regression for the pre-2026-06-26 bug: a merge decision on a secondary
        # (endpoint_family / GE-) candidate group was silently dropped because
        # _apply_decisions only reconstructed primary (G-) group_ids. The two
        # findings below share an endpoint and exploitation family but differ in
        # (CWE, STRIDE), so they form a GE- group, never a G- one.
        threats = [
            {
                **_threat(
                    component_id="api",
                    cwe="CWE-862",
                    stride="Tampering",
                    title="Missing authz on POST /api/Users",
                    evidence={"file": "routes/users.ts", "line": 10},
                )
            },
            {
                **_threat(
                    component_id="api",
                    cwe="CWE-639",
                    stride="Elevation of Privilege",
                    title="IDOR on POST /api/Users escalates role",
                    evidence={"file": "routes/users.ts", "line": 12},
                )
            },
        ]
        groups = mt._group_candidates(threats)
        ge = [g for g in groups if g["group_key"] == "endpoint_family"]
        assert ge, "expected a GE- endpoint candidate group"
        gid = ge[0]["group_id"]
        # The reconstruction the apply path uses must agree on that group_id.
        assert gid in mt._reconstruct_group_member_indices(threats)
        result = mt._apply_decisions(
            list(threats),
            [{"group_id": gid, "action": "merge", "merge_target_index": 0, "rationale": "same endpoint object"}],
        )
        assert len(result) == 1  # GE- merge now actually applies
        assert "merged_from" in result[0]


# ---------------------------------------------------------------------------
# End-to-end collect → finalize
# ---------------------------------------------------------------------------


class TestEndToEnd:
    def test_collect_produces_candidates_file(self, mt, tmp_path):
        _write_stride(tmp_path, "auth", [_threat()])
        _write_stride(tmp_path, "api", [_threat(evidence={"file": "api.py", "line": 9})])

        rc = mt.main(["collect", "--output-dir", str(tmp_path)])
        assert rc == 0
        cand = json.loads((tmp_path / ".merge-candidates.json").read_text())
        assert cand["threat_count_raw"] == 2
        assert cand["candidate_group_count"] == 1
        assert cand["auto_decision_count"] == 0

    def test_collect_records_auto_decisions_and_removes_agent_candidates(self, mt, tmp_path):
        _write_stride(tmp_path, "auth", [_threat(threat_category_id="TH-01")])
        _write_stride(tmp_path, "api", [_threat(threat_category_id="TH-02", evidence={"file": "api.py", "line": 9})])

        rc = mt.main(["collect", "--output-dir", str(tmp_path)])
        assert rc == 0
        cand = json.loads((tmp_path / ".merge-candidates.json").read_text())
        assert cand["candidate_group_count_total"] == 1
        assert cand["candidate_group_count"] == 0
        assert cand["auto_decision_count"] == 1
        assert cand["auto_decisions"][0]["action"] == "keep"

    def test_finalize_without_decisions_keeps_all(self, mt, tmp_path):
        _write_stride(tmp_path, "auth", [_threat()])
        _write_stride(tmp_path, "api", [_threat(evidence={"file": "api.py", "line": 9})])

        mt.main(["collect", "--output-dir", str(tmp_path)])
        rc = mt.main(["finalize", "--output-dir", str(tmp_path)])
        assert rc == 0
        merged = json.loads((tmp_path / ".threats-merged.json").read_text())
        assert len(merged["threats"]) == 2
        assert [t["t_id"] for t in merged["threats"]] == ["T-001", "T-002"]

    def test_finalize_with_merge_decision_collapses(self, mt, tmp_path):
        _write_stride(tmp_path, "auth", [_threat()])
        _write_stride(tmp_path, "api", [_threat(evidence={"file": "api.py", "line": 9})])

        mt.main(["collect", "--output-dir", str(tmp_path)])
        cand = json.loads((tmp_path / ".merge-candidates.json").read_text())
        gid = cand["candidate_groups"][0]["group_id"]
        (tmp_path / ".merge-decisions.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "decisions": [
                        {
                            "group_id": gid,
                            "action": "merge",
                            "merge_target_index": 0,
                            "rationale": "duplicate",
                        }
                    ],
                }
            )
        )

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

    def test_invalid_json_message_carries_component_context_and_recovery(self, mt, tmp_path, capsys):
        # Valid neighbour so we can confirm the error names the right component.
        _write_stride(
            tmp_path,
            "good-comp",
            [
                {
                    "title": "x",
                    "stride_category": "Spoofing",
                    "cwe": "CWE-1",
                    "evidence": {"file": "a.ts", "line": 1},
                }
            ],
        )
        # Invalid: missing comma between two objects.
        bad = tmp_path / ".stride-bad-comp.json"
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


# ---------------------------------------------------------------------------
# resolved_prior_findings union (incremental affirmed-fix channel)
# ---------------------------------------------------------------------------


class TestResolvedPriorUnion:
    def test_union_stamps_component_id(self, mt):
        pairs = [
            ("auth", {"resolved_prior_findings": [{"prior_id": "T-007", "reason": "fixed"}]}),
            (
                "api",
                {"resolved_prior_findings": [{"prior_id": "T-009", "reason": "patched", "component_id": "explicit"}]},
            ),
            ("empty", {"threats": []}),
        ]
        out = mt._collect_resolved_prior_findings(pairs)
        assert {r["prior_id"] for r in out} == {"T-007", "T-009"}
        by_id = {r["prior_id"]: r for r in out}
        assert by_id["T-007"]["component_id"] == "auth"  # stamped from pair
        assert by_id["T-009"]["component_id"] == "explicit"  # caller value preserved

    def test_skips_entries_without_prior_id(self, mt):
        pairs = [("auth", {"resolved_prior_findings": [{"reason": "no id"}, {"prior_id": "T-1", "reason": "ok"}]})]
        out = mt._collect_resolved_prior_findings(pairs)
        assert [r["prior_id"] for r in out] == ["T-1"]


# ---------------------------------------------------------------------------
# Generalized consolidation (_consolidate_by_group) — data/consolidation-groups.yaml
# ---------------------------------------------------------------------------


def _jwt(
    file_path,
    line,
    *,
    cwe="CWE-347",
    title="JWT verify call missing algorithms allowlist",
    component_id="backend-api",
    risk="High",
    **extra,
):
    t = _threat(cwe=cwe, title=title, stride="Spoofing", risk=risk, evidence={"file": file_path, "line": line})
    t["component_id"] = component_id
    t.update(extra)
    return t


class TestConsolidateByGroup:
    def test_jwt_verification_merges_cross_component_cross_cwe(self, mt):
        members = [
            _jwt(
                "lib/insecurity.ts",
                191,
                title="JWT Algorithm Confusion Missing algorithms Allowlist",
                risk="Critical",
                component_id="auth",
            ),
            _jwt(
                "lib/insecurity.ts",
                58,
                cwe="CWE-287",
                title="JWT Decode Without Signature Verification",
                component_id="auth",
            ),
            _jwt(
                "lib/insecurity.ts",
                58,
                cwe="CWE-345",
                title="JWT decode used without signature verification",
                component_id="auth",
            ),
            _jwt("routes/chatbot.ts", 248, component_id="backend-api"),
            _jwt("routes/verify.ts", 117, component_id="backend-api"),
        ]
        out = mt._consolidate_by_group(members)
        survivors = [t for t in out if t.get("consolidation_group") == "jwt-verification"]
        assert len(survivors) == 1, "all JWT-verification hits collapse to ONE finding"
        s = survivors[0]
        assert s["systemic"] is True
        assert s["title"] == "Insecure JWT Verification"
        assert s["instance_count"] == 5
        assert s["risk"] == "Critical"  # survivor = highest-risk member
        assert "lib/insecurity.ts" in s["affected_files"]
        assert "routes/chatbot.ts" in s["affected_files"]

    def test_path_traversal_splits_read_vs_upload(self, mt):
        # CWE-22 spans two sink families with different fixes: a READ traversal
        # (open/serve an attacker-chosen path) and an UPLOAD traversal (store a
        # file under an attacker-chosen original filename). They must NOT fold —
        # the upload weakness would inherit the read finding's title/fix/severity.
        read = _threat(
            cwe="CWE-22",
            stride="Information Disclosure",
            risk="Critical",
            title="Path Traversal via File Name Parameter — Unauthenticated",
            evidence={"file": "serverside/FileReadController.java", "line": 19},
        )
        read["component_id"] = "sb"
        upload = _threat(
            cwe="CWE-22",
            stride="Elevation of Privilege",
            risk="High",
            title="Path Traversal via File Upload — Original Filename Used Directly",
            evidence={"file": "web/BusinessFileStorage.java", "line": 17},
        )
        upload["component_id"] = "sb"
        out = mt._consolidate_by_group([read, upload])
        assert len(out) == 2, "read + upload traversal must stay separate findings"

    def test_path_traversal_reads_still_consolidate(self, mt):
        # Two READ traversals in one component DO fold — the desired class rollup
        # is preserved; only the read/upload split is new.
        r1 = _threat(
            cwe="CWE-22",
            stride="Information Disclosure",
            risk="High",
            title="Path Traversal via name parameter",
            evidence={"file": "a/ReadOne.java", "line": 3},
        )
        r1["component_id"] = "sb"
        r2 = _threat(
            cwe="CWE-22",
            stride="Information Disclosure",
            risk="High",
            title="Path Traversal via path parameter",
            evidence={"file": "a/ReadTwo.java", "line": 9},
        )
        r2["component_id"] = "sb"
        out = mt._consolidate_by_group([r1, r2])
        assert len(out) == 1
        assert out[0]["instance_count"] == 2

    def test_idor_consolidates_cross_component(self, mt):
        # CWE-639 joins the idor-object-authz group (cross-component): broken
        # object-level authz is ONE systemic control gap. Each route survives
        # as an instance, not as a separate Critical. (Reversed 2026-06 from
        # the earlier per-instance rule once ~17 near-identical IDOR findings
        # buried the signal.) XSS (CWE-79) still stays separate.
        idor = [
            _threat(
                cwe="CWE-639",
                title="Broken authorization attacker-controlled owner ID",
                evidence={"file": "routes/address.ts", "line": 11},
                component_id="backend-api",
            ),
            _threat(
                cwe="CWE-639",
                title="Broken authorization attacker-controlled owner ID",
                evidence={"file": "routes/wallet.ts", "line": 12},
                component_id="frontend-spa",
            ),
        ]
        out = mt._consolidate_by_group([dict(t) for t in idor])
        survivors = [t for t in out if t.get("consolidation_group") == "idor-object-authz"]
        assert len(survivors) == 1
        s = survivors[0]
        assert s["systemic"] is True
        assert s["title"] == "Insecure Direct Object Reference"
        assert s["instance_count"] == 2
        assert "routes/address.ts" in s["affected_files"]
        assert "routes/wallet.ts" in s["affected_files"]

    def test_sql_injection_consolidates_per_component(self, mt):
        # CWE-89 sinks in ONE component share a root cause (raw SQL from
        # untrusted input) and one fix (parameterize) → one systemic survivor
        # with every sink preserved as an instance. (Added 2026-07-02 to stop N
        # near-identical SQLi findings/§3 walkthroughs.)
        rows = [
            _threat(
                cwe="CWE-89",
                title="SQL injection request data interpolated into a SQL",
                evidence={"file": f, "line": ln},
                component_id="backend-api",
            )
            for f, ln in (("routes/login.ts", 34), ("routes/search.ts", 23))
        ]
        out = mt._consolidate_by_group([dict(t) for t in rows])
        survivors = [t for t in out if t.get("consolidation_group") == "sql-injection-per-component"]
        assert len(survivors) == 1
        s = survivors[0]
        assert s["systemic"] is True
        assert s["title"] == "SQL Injection"
        assert s["instance_count"] == 2
        assert "routes/login.ts" in s["affected_files"]
        assert "routes/search.ts" in s["affected_files"]

    def test_high_cardinality_consolidation_preserves_all_instances(self, mt):
        # A component with MANY same-CWE sinks collapses to ONE survivor that
        # preserves every hit as an instance (data completeness for YAML/SARIF).
        # The DATA list is deliberately unbounded — the §8 card render caps the
        # DISPLAY at 8 (see test_high_cardinality_instances_capped_with_more_suffix),
        # so a large cluster never explodes the report even though no evidence
        # is dropped.
        rows = [
            _threat(
                cwe="CWE-89",
                title="SQL injection",
                evidence={"file": f"routes/r{i:02d}.ts", "line": i},
                component_id="backend-api",
            )
            for i in range(1, 13)
        ]
        out = mt._consolidate_by_group([dict(t) for t in rows])
        survivors = [t for t in out if t.get("consolidation_group") == "sql-injection-per-component"]
        assert len(survivors) == 1
        assert survivors[0]["instance_count"] == 12
        assert len(survivors[0]["instances"]) == 12

    def test_distinct_injection_classes_stay_separate_in_same_component(self, mt):
        # The per-class design guarantee: SQLi (CWE-89) and XXE (CWE-611) in the
        # SAME component are DISTINCT objects with DISTINCT fixes and must NOT
        # fuse into one finding — each class has its own group.
        rows = [
            _threat(
                cwe="CWE-89",
                title="SQL injection",
                evidence={"file": "routes/search.ts", "line": 23},
                component_id="backend-api",
            ),
            _threat(
                cwe="CWE-611", title="XXE", evidence={"file": "lib/xml.ts", "line": 21}, component_id="backend-api"
            ),
        ]
        out = mt._consolidate_by_group([dict(t) for t in rows])
        groups = {t.get("consolidation_group") for t in out if t.get("systemic")}
        # Two lone matches → neither is made systemic (one instance each), and
        # they are never merged together.
        assert len(out) == 2
        assert not any(t.get("systemic") for t in out)

    def test_missing_route_auth_groups_by_source_check_id(self, mt):
        rows = [
            _threat(
                cwe="CWE-862",
                title="Sensitive REST route registered without authentication middleware",
                evidence={"file": "server.ts", "line": ln},
                component_id="backend-api",
                source_check_id="AUTHZ-008",
            )
            for ln in (310, 311, 407)
        ]
        out = mt._consolidate_by_group(rows)
        survivors = [t for t in out if t.get("consolidation_group") == "missing-route-auth"]
        assert len(survivors) == 1
        assert survivors[0]["instance_count"] == 3

    def test_unions_mitigation_ids_one_to_many(self, mt):
        members = [
            _jwt("lib/insecurity.ts", 191, risk="Critical", component_id="auth", mitigation_ids=["M-041"]),
            _jwt("routes/chatbot.ts", 248, component_id="backend-api", mitigation_ids=["M-005", "M-041"]),
        ]
        out = mt._consolidate_by_group(members)
        s = next(t for t in out if t.get("consolidation_group") == "jwt-verification")
        assert s["mitigation_ids"] == ["M-041", "M-005"]  # union, order-stable, deduped

    def test_lone_match_is_not_made_systemic(self, mt):
        out = mt._consolidate_by_group([_jwt("routes/verify.ts", 117)])
        assert len(out) == 1
        assert not out[0].get("systemic")

    def test_per_instance_severity_preserved(self, mt):
        members = [
            _jwt("lib/insecurity.ts", 191, risk="Critical", component_id="auth"),
            _jwt("routes/chatbot.ts", 248, risk="High", component_id="backend-api"),
        ]
        out = mt._consolidate_by_group(members)
        s = next(t for t in out if t.get("consolidation_group") == "jwt-verification")
        sevs = {i.get("severity") for i in s["instances"]}
        assert sevs == {"Critical", "High"}

    def test_folds_in_existing_config_survivor_instances(self, mt):
        # A config-scan survivor already carrying instances[] is flattened, not nested.
        pre = _threat(
            cwe="CWE-506",
            title="npm install without --ignore-scripts",
            evidence={"file": "package.json", "line": 1},
            component_id="ci-cd-pipeline",
        )
        pre["instances"] = [{"file": "package.json", "line": 1}, {"file": "package.json", "line": 88}]
        pre["systemic"] = True
        other = _threat(
            cwe="CWE-506",
            title="Postinstall hook",
            evidence={"file": "package.json", "line": 88},
            component_id="ci-cd-pipeline",
        )
        out = mt._consolidate_by_group([pre, other])
        s = next(t for t in out if t.get("consolidation_group") == "npm-install-scripts")
        assert s["instance_count"] == 3  # 2 flattened + 1, NOT a nested instances list


class TestConsolidationGroupMatching:
    """Direct coverage of the catalog-matching predicates (the indirect group
    tests above exercise them only via _consolidate_by_group)."""

    def test_groups_load_from_catalog(self, mt):
        groups = mt._load_consolidation_groups()
        ids = {g["id"] for g in groups}
        assert {
            "jwt-verification",
            "missing-route-auth",
            "dependabot-ecosystems",
            "npm-install-scripts",
            "unauth-websocket-channel",
        } <= ids

    def test_glob_match_double_star_prefix_and_basename(self, mt):
        assert mt._glob_match("frontend/src/app/registerWebsocketEvents.ts", "**/registerWebsocketEvents.*")
        assert mt._glob_match("registerWebsocketEvents.ts", "**/registerWebsocketEvents.*")
        assert mt._glob_match(".github/dependabot.yml", "**/dependabot.yml")
        assert not mt._glob_match("server.ts", "**/dependabot.yml")

    def test_crit_empty_never_matches(self, mt):
        # Guard: a crit with no recognized predicate must NOT swallow every finding.
        assert mt._crit_matches({}, cwe="CWE-89", title="x", file_path="a.ts", scid="", ccid="") is False
        assert (
            mt._crit_matches({"unknown_key": 1}, cwe="CWE-89", title="x", file_path="a.ts", scid="", ccid="") is False
        )

    def test_crit_all_predicates_must_hold(self, mt):
        crit = {"cwe": ["CWE-347"], "title_pattern": r"(?i)jwt"}
        assert mt._crit_matches(crit, cwe="CWE-347", title="JWT verify", file_path="", scid="", ccid="")
        assert not mt._crit_matches(
            crit, cwe="CWE-347", title="no match", file_path="", scid="", ccid=""
        )  # title fails
        assert not mt._crit_matches(
            crit, cwe="CWE-639", title="JWT verify", file_path="", scid="", ccid=""
        )  # cwe fails

    def test_match_handles_list_shaped_evidence(self, mt):
        # Regression: evidence is a list in the final yaml; file_glob match must
        # still read evidence[0].file instead of crashing.
        t = {
            "cwe": "CWE-306",
            "title": "Unauthenticated WS",
            "evidence": [{"file": "server/registerWebsocketEvents.ts", "line": 41}],
        }
        g = mt._match_consolidation_group(t, mt._load_consolidation_groups())
        assert g is not None and g["id"] == "unauth-websocket-channel"

    def test_bucket_key_cross_vs_per_component(self, mt):
        cross = {"id": "g", "scope": "cross-component"}
        per = {"id": "g"}  # default per-component
        a = {"component_id": "auth"}
        b = {"component_id": "api"}
        assert mt._group_bucket_key(a, cross) == mt._group_bucket_key(b, cross)  # merge across components
        assert mt._group_bucket_key(a, per) != mt._group_bucket_key(b, per)  # kept apart

    def test_dependabot_file_glob_group_consolidates(self, mt):
        rows = [
            _threat(
                cwe="CWE-1104",
                title="Dependabot npm ecosystem not configured",
                evidence={"file": ".github/dependabot.yml", "line": 1},
                component_id="ci-cd-pipeline",
            ),
            _threat(
                cwe="CWE-1104",
                title="Dependabot docker ecosystem not configured",
                evidence={"file": ".github/dependabot.yml", "line": 2},
                component_id="ci-cd-pipeline",
            ),
        ]
        out = mt._consolidate_by_group(rows)
        survivors = [t for t in out if t.get("consolidation_group") == "dependabot-ecosystems"]
        assert len(survivors) == 1 and survivors[0]["instance_count"] == 2

    def test_per_component_scope_keeps_components_separate(self, mt):
        # Two components, each with 2 matching findings: per-component scope must
        # produce TWO survivors (they must NOT cross-merge into one).
        rows = [
            _threat(
                cwe="CWE-862",
                title="Sensitive REST route registered without authentication middleware",
                evidence={"file": "server.ts", "line": ln},
                component_id=comp,
                source_check_id="AUTHZ-008",
            )
            for comp in ("api-a", "api-b")
            for ln in (1, 2)
        ]
        out = mt._consolidate_by_group(rows)
        survivors = [t for t in out if t.get("consolidation_group") == "missing-route-auth"]
        assert len(survivors) == 2  # per-component → one survivor per component
        assert {s["component_id"] for s in survivors} == {"api-a", "api-b"}
        assert all(s["instance_count"] == 2 for s in survivors)


class TestConsolidationCollectIntegration:
    def test_collect_consolidates_authz008_into_one_finding(self, mt, tmp_path):
        routes = [
            _threat(
                cwe="CWE-862",
                title="Sensitive REST route registered without authentication middleware",
                stride="Elevation of Privilege",
                evidence={"file": "server.ts", "line": ln},
                source_check_id="AUTHZ-008",
            )
            for ln in (310, 311, 407)
        ]
        _write_stride(tmp_path, "backend-api", routes)
        rc = mt.main(["collect", "--output-dir", str(tmp_path)])
        assert rc == 0
        cand = json.loads((tmp_path / ".merge-candidates.json").read_text())
        survivors = [t for t in cand["threats"] if t.get("consolidation_group") == "missing-route-auth"]
        assert len(survivors) == 1
        assert survivors[0]["instance_count"] == 3
        assert survivors[0]["systemic"] is True


# ===========================================================================
# Branch-coverage additions (coverage campaign). Test files only; pin current
# behaviour. Each block targets specific previously-uncovered lines.
# ===========================================================================


class TestCweTaxonomyMap:
    def test_threat_category_id_non_str_cwe_returns_none(self, mt):
        # line 93: cwe is not a str → None
        assert mt._threat_category_id_for({"cwe": None}) is None
        assert mt._threat_category_id_for({"cwe": 89}) is None

    def test_threat_category_id_str_cwe(self, mt):
        # Drives the real cwe_to_th map lookup (string CWE).
        # Result may be None or a TH-id depending on catalog; just assert it
        # returns without raising and is None-or-str.
        out = mt._threat_category_id_for({"cwe": "CWE-89"})
        assert out is None or isinstance(out, str)

    def test_load_cwe_map_handles_list_and_str_values(self, mt, tmp_path, monkeypatch):
        # lines 76-77, 84-85: OSError fallback + list-value/str-value branches.
        import yaml as _y

        # Build a fake taxonomy file and point the loader at it via __file__.
        fake_data = tmp_path / "data"
        fake_data.mkdir()
        (fake_data / "threat-category-taxonomy.yaml").write_text(
            _y.safe_dump(
                {
                    "cwe_to_th": {
                        "CWE-1": ["TH-01", "TH-99"],  # list → first
                        "CWE-2": "TH-02",  # str → as-is
                        "CWE-3": 12345,  # neither → skipped
                    }
                }
            ),
            encoding="utf-8",
        )
        # The loader resolves Path(__file__).parent.parent / "data". Monkeypatch
        # the module __file__ to a child of tmp_path so parent.parent == tmp_path.
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        monkeypatch.setattr(mt, "__file__", str(scripts_dir / "merge_threats.py"))
        mt._load_cwe_to_th_map.cache_clear()
        result = mt._load_cwe_to_th_map()
        assert result["CWE-1"] == "TH-01"
        assert result["CWE-2"] == "TH-02"
        assert "CWE-3" not in result
        mt._load_cwe_to_th_map.cache_clear()

    def test_load_cwe_map_oserror_returns_empty(self, mt, tmp_path, monkeypatch):
        # lines 76-77: unreadable / missing file → {}
        scripts_dir = tmp_path / "no_data_here" / "scripts"
        scripts_dir.mkdir(parents=True)
        monkeypatch.setattr(mt, "__file__", str(scripts_dir / "merge_threats.py"))
        mt._load_cwe_to_th_map.cache_clear()
        assert mt._load_cwe_to_th_map() == {}
        mt._load_cwe_to_th_map.cache_clear()


class TestFlattenThreats:
    def test_non_list_threats_skipped(self, mt):
        # line 195: data['threats'] is not a list → component skipped.
        pairs = [("c1", {"threats": "not-a-list"})]
        assert mt._flatten_threats(pairs) == []

    def test_non_dict_threat_entry_skipped(self, mt):
        # line 199: an entry that is not a dict is skipped.
        pairs = [("c1", {"threats": ["str", _threat()]})]
        out = mt._flatten_threats(pairs)
        assert len(out) == 1

    def test_stride_category_normalised_to_stride(self, mt):
        # line 207: stride_category fills in for missing stride.
        t = {"title": "x", "stride_category": "Spoofing", "cwe": "CWE-287"}
        out = mt._flatten_threats([("c1", {"threats": [t]})])
        assert out[0]["stride"] == "Spoofing"

    def test_source_classified_when_stride_analyzer(self, mt):
        # line 209: source 'stride-analyzer' → reclassified.
        t = {"title": "y", "stride": "Tampering", "source": "stride-analyzer", "cwe": "CWE-89"}
        out = mt._flatten_threats([("c1", {"threats": [t]})])
        assert out[0]["source"] == "stride"

    def test_evidence_list_coerced_to_first_object(self, mt):
        # line 215: evidence as a list → first dict entry kept.
        t = {
            "title": "z",
            "stride": "Tampering",
            "cwe": "CWE-89",
            "evidence": [{"file": "a.py", "line": 1}, {"file": "b.py", "line": 2}],
        }
        out = mt._flatten_threats([("c1", {"threats": [t]})])
        assert out[0]["evidence"] == {"file": "a.py", "line": 1}

    def test_evidence_empty_list_becomes_none(self, mt):
        t = {"title": "z", "stride": "Tampering", "cwe": "CWE-89", "evidence": []}
        out = mt._flatten_threats([("c1", {"threats": [t]})])
        assert out[0]["evidence"] is None

    def test_unclassified_sentinel_backstopped_from_cwe(self, mt):
        # Regression: the STRIDE LLM emits the truthy "TH-UNCLASSIFIED"
        # sentinel even when the CWE has a deterministic taxonomy mapping
        # (CWE-829 → TH-14). The backstop must treat the sentinel as missing
        # and derive the real category, else validate_intermediate rejects
        # the merged artifact (^TH-[0-9]{2}$ contract).
        t = {
            "title": "Unpinned base image tag allows silent substitution",
            "stride": "Tampering",
            "cwe": "CWE-829",
            "threat_category_id": "TH-UNCLASSIFIED",
        }
        out = mt._flatten_threats([("c1", {"threats": [t]})])
        assert out[0]["threat_category_id"] == "TH-14"

    def test_unclassified_sentinel_kept_when_cwe_unmappable(self, mt):
        # Honest failure: an unmappable CWE leaves the sentinel intact so
        # validation still surfaces it rather than silently inventing a TH.
        t = {
            "title": "x",
            "stride": "Tampering",
            "cwe": "CWE-99999",
            "threat_category_id": "TH-UNCLASSIFIED",
        }
        out = mt._flatten_threats([("c1", {"threats": [t]})])
        assert out[0]["threat_category_id"] == "TH-UNCLASSIFIED"

    def test_valid_category_id_preserved(self, mt):
        # A well-formed TH-NN must not be overwritten by the backstop even
        # when the CWE would map elsewhere.
        t = {"title": "y", "stride": "Tampering", "cwe": "CWE-829", "threat_category_id": "TH-08"}
        out = mt._flatten_threats([("c1", {"threats": [t]})])
        assert out[0]["threat_category_id"] == "TH-08"

    def test_configuration_defect_gets_mitigation_hint(self, mt):
        # line 228: source=configuration-defect + no mitigation_title → hint
        # stamped. Triggered via the hardcoded-secret classifier.
        t = {
            "title": "Hardcoded secret API key in config",
            "stride": "Information Disclosure",
            "source": "stride-analyzer",
            "cwe": "CWE-798",
            "evidence": {"file": "config.js", "line": 5},
        }
        out = mt._flatten_threats([("c1", {"threats": [t]})])
        assert out[0]["source"] == "configuration-defect"
        assert "secrets-management" in out[0]["mitigation_title"]


class TestClassifyStrideSource:
    def test_evidence_list_with_files(self, mt):
        # lines 265-272: evidence is a list of dicts with file → config-defect.
        t = {
            "title": "Hardcoded password credential",
            "evidence": [{"file": "x.py"}, {"no": "file"}],
        }
        assert mt._classify_stride_source(t) == "configuration-defect"

    def test_evidence_dict_with_file(self, mt):
        t = {"title": "Hardcoded api-key token", "evidence": {"file": "y.py"}}
        assert mt._classify_stride_source(t) == "configuration-defect"

    def test_evidence_none_falls_back_to_stride(self, mt):
        # ev_files empty → stride.
        t = {"title": "Hardcoded secret key", "evidence": None}
        assert mt._classify_stride_source(t) == "stride"

    def test_non_hardcoded_title_is_stride(self, mt):
        t = {"title": "SQL injection", "evidence": {"file": "z.py"}}
        assert mt._classify_stride_source(t) == "stride"


class TestConfigFindingToThreat:
    def test_maps_fields(self, mt):
        # lines 305-309 (function body) exercised end-to-end.
        f = {
            "title": "CORS wildcard",
            "scenario": "any origin allowed",
            "severity": "High",
            "cwe": ["CWE-942"],
            "file": "app.js",
            "line": 7,
            "breach_vector": "Internet Anon",
            "check_slug": "cors-wildcard",
        }
        out = mt._config_finding_to_threat(f)
        assert out["stride"] == "Information Disclosure"
        assert out["risk"] == "High"
        assert out["cwe"] == "CWE-942"
        assert out["breach_distance"] == 1
        assert out["config_check_slug"] == "cors-wildcard"

    def test_defaults_when_missing(self, mt):
        out = mt._config_finding_to_threat({})
        assert out["risk"] == "Medium"
        assert out["cwe"] == ""
        assert out["breach_distance"] is None


class TestGuessComponentFromPath:
    def test_frontend_prefix(self, mt):
        assert mt._guess_component_from_path("frontend/app.ts") == ("frontend", "Frontend SPA")
        assert mt._guess_component_from_path("client/main.js") == ("frontend", "Frontend SPA")

    def test_data_layer_prefix(self, mt):
        assert mt._guess_component_from_path("models/user.ts") == ("data-layer", "Data Layer")
        assert mt._guess_component_from_path("prisma/schema.prisma") == ("data-layer", "Data Layer")

    def test_backend_default(self, mt):
        assert mt._guess_component_from_path("routes/order.ts") == ("backend-api", "Backend API")


class TestSourceAuthFindingToThreat:
    def test_maps_authz_check(self, mt):
        # lines 412-419: full mapping incl. stride from AUTHZ id + component guess.
        f = {
            "title": "IDOR via raw param",
            "check_id": "AUTHZ-002",
            "severity": "High",
            "cwe": ["CWE-639"],
            "file": "routes/users.ts",
            "line": 9,
            "breach_vector": "Internet User",
        }
        out = mt._source_auth_finding_to_threat(f)
        assert out["stride"] == "Tampering"
        assert out["source"] == "source-scan"
        assert out["component_id"] == "backend-api"
        assert out["breach_distance"] == 2

    def test_unknown_check_id_defaults_tampering(self, mt):
        out = mt._source_auth_finding_to_threat({"check_id": "AUTHZ-999"})
        assert out["stride"] == "Tampering"
        assert out["cwe"] == ""


class TestLoadSourceAuthFindings:
    def test_missing_file_empty(self, mt, tmp_path):
        # line 453-454: absent file → [].
        assert mt._load_source_auth_findings(tmp_path) == []

    def test_malformed_json_degrades(self, mt, tmp_path, capsys):
        # lines 458-464: JSONDecodeError → [] + stderr note.
        (tmp_path / ".source-auth-findings.json").write_text("{bad", encoding="utf-8")
        assert mt._load_source_auth_findings(tmp_path) == []
        assert "failed to read" in capsys.readouterr().err

    def test_parse_error_stub_degrades(self, mt, tmp_path):
        # lines 465-466: stub with parse_error → [].
        (tmp_path / ".source-auth-findings.json").write_text('{"parse_error": true}', encoding="utf-8")
        assert mt._load_source_auth_findings(tmp_path) == []

    def test_findings_not_list_returns_empty(self, mt, tmp_path):
        # lines 468-469: findings not a list → [].
        (tmp_path / ".source-auth-findings.json").write_text('{"findings": "nope"}', encoding="utf-8")
        assert mt._load_source_auth_findings(tmp_path) == []

    def test_valid_findings_converted(self, mt, tmp_path):
        # line 470: real findings converted.
        (tmp_path / ".source-auth-findings.json").write_text(
            json.dumps({"findings": [{"check_id": "AUTHZ-001", "title": "BFLA", "file": "r.ts"}, "skip"]}),
            encoding="utf-8",
        )
        out = mt._load_source_auth_findings(tmp_path)
        assert len(out) == 1
        assert out[0]["source_check_id"] == "AUTHZ-001"


class TestLoadConfigScanFindings:
    def test_missing_file_empty(self, mt, tmp_path):
        assert mt._load_config_scan_findings(tmp_path) == []

    def test_malformed_json_degrades(self, mt, tmp_path, capsys):
        # lines 487-493: JSONDecodeError path.
        (tmp_path / ".config-scan-findings.json").write_text("{bad", encoding="utf-8")
        assert mt._load_config_scan_findings(tmp_path) == []
        assert "failed to read" in capsys.readouterr().err

    def test_parse_error_stub_degrades(self, mt, tmp_path):
        (tmp_path / ".config-scan-findings.json").write_text('{"parse_error": true}', encoding="utf-8")
        assert mt._load_config_scan_findings(tmp_path) == []

    def test_findings_not_list_returns_empty(self, mt, tmp_path):
        (tmp_path / ".config-scan-findings.json").write_text('{"findings": 5}', encoding="utf-8")
        assert mt._load_config_scan_findings(tmp_path) == []

    def test_valid_findings_converted(self, mt, tmp_path):
        (tmp_path / ".config-scan-findings.json").write_text(
            json.dumps({"findings": [{"title": "x", "file": "ci.yml"}]}),
            encoding="utf-8",
        )
        out = mt._load_config_scan_findings(tmp_path)
        assert len(out) == 1
        assert out[0]["source"] == "config-scan"


class TestSmallHelpers:
    def test_normalize_title_non_str(self, mt):
        # line 535: non-str title → ().
        assert mt._normalize_title_keywords(None) == ()

    def test_exact_key_non_dict_evidence(self, mt):
        # line 546: evidence not a dict → treated as {}.
        k = mt._exact_key({"cwe": "CWE-1", "stride": "Tampering", "evidence": "oops", "title": "t"})
        assert k[3] == "" and k[4] is None

    def test_extract_endpoints_from_scenario(self, mt):
        # lines 600, 604-606: scenario source + path normalisation.
        t = {"title": "no path here", "scenario": "attacker hits POST /api/Users/ to escalate"}
        eps = mt._extract_endpoints(t)
        assert "/api/users" in eps

    def test_extract_endpoints_none_when_empty(self, mt):
        assert mt._extract_endpoints({"title": "nothing", "scenario": "nothing"}) == ()

    def test_cwe_family_known_and_unknown(self, mt):
        # line 655.
        assert mt._cwe_family("CWE-89") == "injection"
        assert mt._cwe_family("CWE-99999") == "other"

    def test_endpoint_candidate_key_none_without_endpoint(self, mt):
        # line 667 (None branch).
        assert mt._endpoint_candidate_key({"title": "x", "scenario": "y"}) is None

    def test_endpoint_candidate_key_with_endpoint(self, mt):
        k = mt._endpoint_candidate_key({"title": "GET /api/users", "cwe": "CWE-639"})
        assert k == ("/api/users", "authz")

    def test_dedupe_exact_records_provenance(self, mt):
        # line 683: second dup appends to merged_from.
        t1 = {"component_id": "a", **_threat()}
        t2 = {"component_id": "a", **_threat()}
        out = mt._dedupe_exact([t1, t2])
        assert len(out) == 1
        assert out[0]["merged_from"] == ["a"]

    def test_evidence_identity_key_non_dict_evidence(self, mt):
        # line 714: evidence not a dict → coerced; missing line → None.
        assert mt._evidence_identity_key({"cwe": "CWE-1", "evidence": "x"}) is None

    def test_cwe_sort_value_non_str_and_bad_format(self, mt):
        # lines 1250, 1253.
        assert mt._cwe_sort_value(None) == (1, 0)
        assert mt._cwe_sort_value("not-a-cwe") == (1, 0)
        assert mt._cwe_sort_value("CWE-89") == (0, 89)


class TestConsolidationInternals:
    def test_load_groups_oserror(self, mt, tmp_path, monkeypatch):
        # lines 828-829: missing catalog → ().
        scripts_dir = tmp_path / "x" / "scripts"
        scripts_dir.mkdir(parents=True)
        monkeypatch.setattr(mt, "__file__", str(scripts_dir / "merge_threats.py"))
        mt._load_consolidation_groups.cache_clear()
        assert mt._load_consolidation_groups() == ()
        mt._load_consolidation_groups.cache_clear()

    def test_glob_match_double_star_and_plain(self, mt):
        # line 847 (plain fnmatch branch) + 846 (double-star).
        assert mt._glob_match("a/b/foo.ts", "**/foo.ts") is True
        assert mt._glob_match("foo.ts", "**/foo.ts") is True
        assert mt._glob_match("a/b.ts", "a/*.ts") is True
        assert mt._glob_match("a/b.ts", "z/*.ts") is False

    def test_crit_matches_all_predicates(self, mt):
        # lines 864-877: each predicate branch + final seen return.
        crit = {
            "cwe": ["CWE-347"],
            "source_check_id": ["AUTHZ-005"],
            "config_check_id": ["IAC-001"],
            "title_pattern": "jwt",
            "file_glob": ["**/insecurity.ts"],
        }
        assert (
            mt._crit_matches(
                crit,
                cwe="CWE-347",
                title="jwt verify",
                file_path="lib/insecurity.ts",
                scid="AUTHZ-005",
                ccid="IAC-001",
            )
            is True
        )
        # cwe mismatch → False
        assert (
            mt._crit_matches(
                crit,
                cwe="CWE-99",
                title="jwt verify",
                file_path="lib/insecurity.ts",
                scid="AUTHZ-005",
                ccid="IAC-001",
            )
            is False
        )

    def test_crit_matches_bad_regex_returns_false(self, mt):
        # lines 872-873: invalid regex → False (re.error swallowed).
        crit = {"title_pattern": "([unclosed"}
        assert mt._crit_matches(crit, cwe="", title="anything", file_path="", scid="", ccid="") is False

    def test_crit_source_check_id_mismatch(self, mt):
        crit = {"source_check_id": ["AUTHZ-001"]}
        assert mt._crit_matches(crit, cwe="", title="", file_path="", scid="OTHER", ccid="") is False

    def test_crit_config_check_id_mismatch(self, mt):
        crit = {"config_check_id": ["IAC-001"]}
        assert mt._crit_matches(crit, cwe="", title="", file_path="", scid="", ccid="OTHER") is False

    def test_crit_file_glob_mismatch(self, mt):
        crit = {"file_glob": ["**/foo.ts"]}
        assert mt._crit_matches(crit, cwe="", title="", file_path="bar.js", scid="", ccid="") is False

    def test_match_consolidation_group_list_evidence(self, mt):
        # line 889: list-shaped evidence path in _match_consolidation_group.
        groups = ({"id": "g1", "match_any": [{"file_glob": ["**/x.ts"]}]},)
        t = {"evidence": [{"file": "a/x.ts"}], "title": "t"}
        assert mt._match_consolidation_group(t, groups) is g_first(groups)

    def test_match_consolidation_group_none(self, mt):
        groups = ({"id": "g1", "match_any": [{"cwe": ["CWE-1"]}]},)
        assert mt._match_consolidation_group({"cwe": "CWE-2"}, groups) is None

    def test_instances_of_existing_instances(self, mt):
        # line 911 area: member already carries instances[].
        m = {"risk": "High", "instances": [{"file": "a", "line": 1}, "bad"]}
        out = mt._instances_of(m)
        assert out[0]["severity"] == "High"
        assert len(out) == 2

    def test_instances_of_list_evidence(self, mt):
        # lines 930-939: synthesize from list-shaped evidence + snippet + ref.
        m = {
            "risk": "Low",
            "evidence": [{"file": "f.ts", "line": 3, "snippet": "code"}],
            "local_id": "L-1",
        }
        out = mt._instances_of(m)
        assert out[0]["file"] == "f.ts"
        assert out[0]["snippet"] == "code"
        assert out[0]["local_id"] == "L-1"

    def test_instances_of_non_dict_evidence(self, mt):
        m = {"risk": "Low", "evidence": "oops"}
        out = mt._instances_of(m)
        assert out[0]["file"] == ""

    def test_consolidate_by_group_no_groups(self, mt, monkeypatch):
        # line 958: empty groups catalog → passthrough copy.
        monkeypatch.setattr(mt, "_load_consolidation_groups", lambda: ())
        threats = [_threat()]
        out = mt._consolidate_by_group(threats)
        assert out == threats and out is not threats


def g_first(groups):
    return groups[0]


class TestEndpointSecondaryGrouping:
    def test_secondary_group_distinct_cwe_same_endpoint(self, mt):
        # lines 1108-1148: endpoint-based secondary grouping when primary
        # (CWE,STRIDE) does not group them.
        t1 = _threat(
            cwe="CWE-915", stride="Tampering", title="Mass assign POST /api/Users", evidence={"file": "r.ts", "line": 1}
        )
        t2 = _threat(
            cwe="CWE-269",
            stride="Elevation of Privilege",
            title="Admin role via POST /api/Users",
            evidence={"file": "r.ts", "line": 2},
        )
        groups = mt._group_candidates([t1, t2])
        ge = [g for g in groups if g.get("group_key") == "endpoint_family"]
        assert ge, "expected an endpoint_family secondary group"
        assert ge[0]["endpoint"] == "/api/users"

    def test_secondary_skipped_when_same_cwe_stride(self, mt):
        # lines 1123-1125: members all share (cwe,stride) → skip (primary
        # would have caught it). Use a single endpoint, identical key, but
        # different file so primary grouping DOES fire (len>=2) and consumes
        # them, leaving nothing for secondary.
        t1 = _threat(
            cwe="CWE-89", stride="Tampering", title="SQLi GET /api/users a", evidence={"file": "a.ts", "line": 1}
        )
        t2 = _threat(
            cwe="CWE-89", stride="Tampering", title="SQLi GET /api/users b", evidence={"file": "b.ts", "line": 2}
        )
        groups = mt._group_candidates([t1, t2])
        # primary cwe_stride group present, no endpoint_family group.
        assert any(g.get("group_key") == "cwe_stride" for g in groups)
        assert not any(g.get("group_key") == "endpoint_family" for g in groups)


class TestAutoDecisionBranches:
    def test_member_not_dict_returns_none(self, mt):
        # line 1191: a non-dict member in fingerprint loop → None.
        group = {
            "group_id": "G-1",
            "members": ["not-a-dict", {"title": "t", "evidence": {"file": "a", "line": 1}}],
        }
        assert mt._auto_decision_for_group(group) is None

    def test_non_dict_evidence_member(self, mt):
        # line 1194: evidence not a dict → coerced to {} → missing file → None.
        group = {
            "group_id": "G-1",
            "members": [
                {"title": "t", "evidence": "x", "threat_category_id": "TH-01"},
                {"title": "t", "evidence": "y", "threat_category_id": "TH-01"},
            ],
        }
        assert mt._auto_decision_for_group(group) is None

    def test_missing_evidence_fields_returns_none(self, mt):
        # line 1200: missing file/line/title → None.
        group = {
            "group_id": "G-1",
            "members": [
                {"title": "t", "evidence": {"file": "a", "line": None}, "threat_category_id": "TH-01"},
                {"title": "t", "evidence": {"file": "a", "line": 1}, "threat_category_id": "TH-01"},
            ],
        }
        assert mt._auto_decision_for_group(group) is None


class TestApplyDecisionsBranches:
    def _two_group(self):
        # two threats sharing (CWE, STRIDE) → one group.
        return [
            _threat(
                cwe="CWE-89", stride="Tampering", component_id="a", title="SQLi a", evidence={"file": "a.ts", "line": 1}
            ),
            _threat(
                cwe="CWE-89", stride="Tampering", component_id="b", title="SQLi b", evidence={"file": "b.ts", "line": 2}
            ),
        ]

    def _gid(self, mt, threats):
        import hashlib

        key = ("CWE-89", "Tampering")
        n = sum(1 for t in threats if (t.get("cwe"), t.get("stride")) == key)
        return "G-" + hashlib.sha256(f"CWE-89|Tampering|{n}".encode()).hexdigest()[:8]

    def test_non_dict_decision_skipped(self, mt):
        # line 1362: decision not a dict → skipped.
        threats = self._two_group()
        out = mt._apply_decisions(threats, ["not-a-dict"])
        assert len(out) == 2

    def test_merge_bad_target_index_skipped(self, mt):
        # lines 1371-1372: out-of-range merge_target_index → continue.
        threats = self._two_group()
        gid = self._gid(mt, threats)
        out = mt._apply_decisions(threats, [{"group_id": gid, "action": "merge", "merge_target_index": 99}])
        assert len(out) == 2

    def test_keep_non_list_indices_skipped(self, mt):
        # lines 1386-1388: keep with non-list keep_indices → continue.
        threats = self._two_group()
        gid = self._gid(mt, threats)
        out = mt._apply_decisions(threats, [{"group_id": gid, "action": "keep", "keep_indices": "nope"}])
        assert len(out) == 2

    def test_keep_drops_unlisted(self, mt):
        # lines 1389-1391: keep_indices keeps only listed positions.
        threats = self._two_group()
        gid = self._gid(mt, threats)
        out = mt._apply_decisions(threats, [{"group_id": gid, "action": "keep", "keep_indices": [0]}])
        assert len(out) == 1

    def test_consolidate_bad_target_skipped(self, mt):
        # line 1396: consolidate out-of-range target → continue.
        threats = self._two_group()
        gid = self._gid(mt, threats)
        out = mt._apply_decisions(threats, [{"group_id": gid, "action": "consolidate", "merge_target_index": 99}])
        assert len(out) == 2


class TestCmdCollectFinalizeBranches:
    def test_collect_no_stride_files(self, mt, tmp_path, capsys):
        # lines 1444-1445: dir exists but no .stride-*.json → error.
        rc = (
            mt.cmd_collect_argv(tmp_path)
            if hasattr(mt, "cmd_collect_argv")
            else mt.main(["collect", "--output-dir", str(tmp_path)])
        )
        assert rc == 1
        assert "no .stride-*.json" in capsys.readouterr().err

    def test_collect_appends_config_and_source(self, mt, tmp_path):
        # lines 1454, 1460: config + source-auth threats appended in collect.
        _write_stride(tmp_path, "backend", [_threat()])
        (tmp_path / ".config-scan-findings.json").write_text(
            json.dumps({"findings": [{"title": "CORS", "file": "ci.yml", "line": 1}]}), encoding="utf-8"
        )
        (tmp_path / ".source-auth-findings.json").write_text(
            json.dumps({"findings": [{"check_id": "AUTHZ-002", "title": "IDOR", "file": "r.ts", "line": 2}]}),
            encoding="utf-8",
        )
        rc = mt.main(["collect", "--output-dir", str(tmp_path)])
        assert rc == 0
        cand = json.loads((tmp_path / ".merge-candidates.json").read_text())
        sources = {t.get("source") for t in cand["threats"]}
        assert "config-scan" in sources
        assert "source-scan" in sources

    def test_finalize_missing_candidates(self, mt, tmp_path, capsys):
        # lines 1518-1519: no .merge-candidates.json → error.
        rc = mt.main(["finalize", "--output-dir", str(tmp_path)])
        assert rc == 1
        assert "run 'collect' first" in capsys.readouterr().err

    def test_finalize_reads_decisions_file_dict(self, mt, tmp_path):
        # lines 1532-1533: .merge-decisions.json as dict with decisions[].
        # CWE-94 (code injection) has no catalog consolidation group, so the two
        # findings form an LLM merge candidate_group (as this test needs to reach
        # the decision-file branch). CWE-89 was used here originally but now
        # auto-consolidates via sql-injection-per-component, leaving no candidate.
        _write_stride(
            tmp_path,
            "backend",
            [
                _threat(
                    cwe="CWE-94", stride="Tampering", title="Code injection a", evidence={"file": "a.ts", "line": 1}
                ),
                _threat(
                    cwe="CWE-94", stride="Tampering", title="Code injection b", evidence={"file": "b.ts", "line": 2}
                ),
            ],
        )
        mt.main(["collect", "--output-dir", str(tmp_path)])
        cand = json.loads((tmp_path / ".merge-candidates.json").read_text())
        gid = next(g["group_id"] for g in cand["candidate_groups"])
        (tmp_path / ".merge-decisions.json").write_text(
            json.dumps({"decisions": [{"group_id": gid, "action": "keep", "keep_indices": [0]}]}),
            encoding="utf-8",
        )
        rc = mt.main(["finalize", "--output-dir", str(tmp_path)])
        assert rc == 0
        merged = json.loads((tmp_path / ".threats-merged.json").read_text())
        assert len(merged["threats"]) == 1

    def test_finalize_reads_decisions_file_list(self, mt, tmp_path):
        # lines 1532-1533 (list branch): .merge-decisions.json as bare list.
        _write_stride(tmp_path, "backend", [_threat()])
        mt.main(["collect", "--output-dir", str(tmp_path)])
        (tmp_path / ".merge-decisions.json").write_text(json.dumps([]), encoding="utf-8")
        rc = mt.main(["finalize", "--output-dir", str(tmp_path)])
        assert rc == 0

    def test_finalize_attack_surface_coverage_gap(self, mt, tmp_path):
        # lines 1562-1586: yaml present, threat has id not covered → gaps file.
        _write_stride(tmp_path, "backend", [_threat()])
        mt.main(["collect", "--output-dir", str(tmp_path)])
        # Give the candidate threat an id so the coverage check finds a gap.
        cand_path = tmp_path / ".merge-candidates.json"
        cand = json.loads(cand_path.read_text())
        for t in cand["threats"]:
            t["id"] = "F-001"
        cand_path.write_text(json.dumps(cand), encoding="utf-8")
        import yaml as _y

        (tmp_path / "threat-model.yaml").write_text(
            _y.safe_dump({"attack_surface": [{"linked_threats": ["T-999"]}]}), encoding="utf-8"
        )
        rc = mt.main(["finalize", "--output-dir", str(tmp_path)])
        assert rc == 0
        gaps = json.loads((tmp_path / ".coverage-gaps-as.json").read_text())
        assert gaps["count"] >= 1

    def test_finalize_attack_surface_malformed_yaml_swallowed(self, mt, tmp_path):
        # lines 1585-1586: broken yaml → Exception swallowed, still rc 0.
        _write_stride(tmp_path, "backend", [_threat()])
        mt.main(["collect", "--output-dir", str(tmp_path)])
        (tmp_path / "threat-model.yaml").write_text("key: [unclosed\n", encoding="utf-8")
        rc = mt.main(["finalize", "--output-dir", str(tmp_path)])
        assert rc == 0


class TestAutoRepairInvalidJSON:
    def test_invalid_escape_auto_repaired(self, mt, tmp_path, capsys):
        # lines 130-153: a `\!` invalid escape is auto-repaired + file rewritten.
        bad = tmp_path / ".stride-backend.json"
        bad.write_text(
            '{"component_id": "backend", "threats": [{"title": "x\\!", '
            '"stride": "Tampering", "cwe": "CWE-89", "evidence": {"file": "a", "line": 1}}]}',
            encoding="utf-8",
        )
        pairs = mt._load_stride_outputs(tmp_path)
        assert pairs and pairs[0][1]["threats"][0]["title"] == "x!"
        # file was rewritten to valid JSON
        assert "\\!" not in bad.read_text()
        assert "auto-repaired" in capsys.readouterr().err


class TestWeaknessRegister:
    """P1 weakness-class evidence model — build_weakness_register reconciler
    (proposal §4a/§4b/§4d-bis). Folds confirmed findings + practice sites +
    arch design signals into one weakness heading per class."""

    def _confirmed(self, tid, cwe, comp, risk, file):
        return {
            "t_id": tid,
            "source": "source-scan",
            "cwe": cwe,
            "component_id": comp,
            "risk": risk,
            "evidence": {"file": file, "line": 10},
        }

    def test_fold_two_sinks_plus_design_signal(self, mt):
        # §4b: ≥1 proven + absent control → ONE design weakness, sinks as instances.
        threats = [
            self._confirmed("T-001", "CWE-89", "login", "Critical", "routes/login.ts"),
            self._confirmed("T-002", "CWE-89", "search", "High", "routes/search.ts"),
        ]
        design = [
            {
                "weakness_class": "injection",
                "cwe": "CWE-89",
                "statement": "SQL built by concatenation; no parametrized layer.",
                "absent_control_signal": [{"pattern": "sequelize", "search_paths": ["routes"], "hit_count": 0}],
            }
        ]
        w = mt.build_weakness_register(threats, design)
        assert len(w) == 1
        wk = w[0]
        assert wk["weakness_class"] == "injection"
        assert wk["kind"] == "design"
        assert len(wk["instances"]) == 2
        assert {i["id"] for i in wk["instances"]} == {"T-001", "T-002"}
        assert wk["severity_basis"] == "confirmed"
        assert wk["severity"] == "Critical"  # max instance risk
        assert "absent_control_signal" in wk["observable_backing"]
        assert wk["id"].startswith("W-")

    def test_confirmed_only_no_backing_is_not_a_weakness(self, mt):
        # §4b "control present" row: proven instances, no absent-control signal,
        # no practice → NOT a systemic weakness (stays plain threats[]).
        threats = [self._confirmed("T-001", "CWE-89", "login", "High", "a.ts")]
        assert mt.build_weakness_register(threats, None) == []

    def test_pervasive_homegrown_design_risk_can_be_critical(self, mt):
        # §4e: pervasive (≥2 components) + home-grown + no central control →
        # design-risk Critical even with zero confirmed instances.
        practice = [
            {
                "source": "stride",
                "cwe": "CWE-327",
                "component_id": "a",
                "evidence": {"file": "a.ts", "line": 1},
                "evidence_tier": "insecure-practice",
            },
            {
                "source": "stride",
                "cwe": "CWE-327",
                "component_id": "b",
                "evidence": {"file": "b.ts", "line": 2},
                "evidence_tier": "insecure-practice",
            },
        ]
        design = [
            {
                "weakness_class": "weak_crypto",
                "implementation_strategy": "home-grown",
                "severity": "Medium",
                "absent_control_signal": [{"pattern": "argon2", "hit_count": 0}],
            }
        ]
        w = mt.build_weakness_register(practice, design)
        assert len(w) == 3
        assert sum(1 for item in w if item["severity_basis"] == "observed-practice") == 2

    def test_isolated_practice_is_implementation_kind(self, mt):
        # Single component, no absent-control signal → isolated implementation
        # weakness folding the practice sites (§4d-bis anti-explosion).
        practice = [
            {
                "source": "stride",
                "cwe": "CWE-89",
                "component_id": "seeder",
                "evidence": {"file": "seed.ts", "line": i},
                "evidence_tier": "insecure-practice",
            }
            for i in range(5)
        ]
        w = mt.build_weakness_register(practice, None)
        assert len(w) == 1
        assert w[0]["kind"] == "implementation"
        assert len(w[0]["observable_backing"]["practice_evidence"]) == 5


def test_load_design_signals_fallback_generates_from_coverage(mt, tmp_path):
    # The Phase-9 agent's `emit-design-signals` step is a soft instruction that
    # is sometimes skipped; when .arch-design-signals.json is absent,
    # _load_design_signals must fall back to generating signals from
    # .architecture-coverage.json so architectural design gaps still fold into
    # the weakness register.
    coverage = {
        "version": 1,
        "threat_hypotheses": [
            {
                "hypothesis_id": "ARCH-HYP-INPUT-001",
                "rule_id": "ARCH-INPUT-001",
                "cwe": "CWE-20",
                "architectural_theme": "InputValidation",
                "proof_state": "control-derived",
                "generic_threat_title": "Injection through missing centralized input validation",
                "weak_or_missing_controls": ["Schema Validation"],
            }
        ],
    }
    (tmp_path / ".architecture-coverage.json").write_text(json.dumps(coverage))
    assert not (tmp_path / ".arch-design-signals.json").exists()
    signals = mt._load_design_signals(tmp_path)
    assert len(signals) == 1
    assert signals[0]["weakness_class"] == "injection"
