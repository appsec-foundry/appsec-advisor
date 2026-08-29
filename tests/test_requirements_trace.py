"""Guards for the shared requirement-traceability and blueprint-selection rules
in ``scripts/requirements_trace.py`` and the surfaces bound by them.

Both rules previously had one implementation per surface and drifted:

  * ``mitigations[].fulfills_requirements`` in ``threat-model.yaml`` and the
    §10 "Fulfills Requirements" block named different — sometimes disjoint —
    requirement sets for the same mitigation.
  * The §10 Blueprint block picked whichever blueprint the *first* fulfilled
    requirement happened to belong to, ranking only the sections inside that
    group, and asserted it governed the fix even when nothing connected them.

The assertions here are against the rules, not against numbers from any one
run: a report list must be a subset of the model's, the winning blueprint must
be the best-scoring one available, and a selection with no shared wording must
report itself as ungrounded.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import requirements_trace as rt  # noqa: E402


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


# A catalog whose shape exercises the cases a real one mixes: two blueprints
# prescribing the same requirement, a section on a different page from its
# blueprint, a section with no URL of its own, and `references` in both the
# mapping and the bare-string form.
CATALOG = {
    "categories": [
        {
            "id": "CAT-AC",
            "title": "Access Control",
            "context": "Applies to protected operations.",
            "requirements": [
                {"id": "AC-002", "priority": "MUST", "text": "Authorize every protected operation.", "url": "u/ac"},
                {"id": "IV-001", "priority": "MUST", "text": "Validate external input.", "url": "u/iv"},
                {"id": "LM-001", "priority": "SHOULD", "text": "Log security events.", "url": "u/lm"},
            ],
        }
    ],
    "blueprints": [
        {
            "id": "BP-AUTHZ",
            "title": "Authorization",
            "url": "https://example.test/authz.html",
            "sections": [
                {
                    "title": "Method-Level Authorization",
                    "url": "https://example.test/access-control.html",
                    "content": "Check role or scope claims on each protected route.",
                    "references": [{"id": "AC-002"}],
                },
                {
                    "title": "Resource-Level Authorization",
                    "content": "Verify the caller owns the resource identifier.",
                    "references": ["AC-002"],
                },
            ],
        },
        {
            "id": "BP-VALIDATION",
            "title": "Input Validation",
            "url": "https://example.test/validation.html",
            "sections": [
                {
                    "title": "Unexpected Field Handling",
                    "url": "https://example.test/validation.html",
                    "content": "Reject input fields that are not in the approved schema; allowlist fields.",
                    "references": [{"id": "IV-001"}, {"id": "AC-002"}],
                }
            ],
        },
    ],
}


class TestCatalogParsing:
    def test_section_keeps_its_own_page_and_falls_back_to_the_blueprint(self):
        """A quoted section must link where the text lives, not the landing page.

        26 of 38 blueprint blocks in a measured run linked the blueprint's own
        URL under a section quoted from a different cheat sheet.
        """
        by_req = rt.sections_by_requirement(CATALOG)
        titles = {s.title: s for s in by_req["AC-002"]}
        assert titles["Method-Level Authorization"].url == "https://example.test/access-control.html"
        assert titles["Method-Level Authorization"].blueprint_url == "https://example.test/authz.html"
        # No section URL — fall back to the blueprint's, never to empty.
        assert titles["Resource-Level Authorization"].url == "https://example.test/authz.html"

    def test_references_accept_both_the_mapping_and_the_bare_string_form(self):
        by_req = rt.sections_by_requirement(CATALOG)
        assert {s.title for s in by_req["AC-002"]} == {
            "Method-Level Authorization",
            "Resource-Level Authorization",
            "Unexpected Field Handling",
        }

    @pytest.mark.parametrize(
        "catalog",
        [
            {},
            {"blueprints": []},
            {"blueprints": None},
            {"blueprints": ["not-a-mapping"]},
            {"blueprints": [{"title": "no id"}]},
            {"blueprints": [{"id": "BP-X", "sections": None}]},
            {"blueprints": [{"id": "BP-X", "sections": [{"title": "T", "references": []}]}]},
        ],
        ids=["empty", "no-blueprints", "null", "not-mapping", "no-id", "no-sections", "no-references"],
    )
    def test_degenerate_catalogs_yield_no_guidance_instead_of_raising(self, catalog):
        assert rt.sections_by_requirement(catalog) == {}

    def test_missing_catalog_file_is_not_an_error(self, tmp_path):
        assert rt.load_catalog(tmp_path) == {}
        (tmp_path / ".requirements.yaml").write_text("{{ not yaml", encoding="utf-8")
        assert rt.load_catalog(tmp_path) == {}

    def test_excerpt_never_ends_mid_word(self):
        text = "word " * 200
        out = rt.section_excerpt(text, limit=40)
        assert len(out) <= 41  # limit plus the ellipsis
        assert not out.rstrip("…").endswith("wor")


class TestBlueprintSelection:
    def _select(self, requirement_ids, title, scenario=""):
        return rt.select_blueprint(
            rt.sections_by_requirement(CATALOG),
            requirement_ids,
            rt.RankContext(primary=title, secondary=scenario),
        )

    def test_the_best_matching_blueprint_wins_over_the_first_listed(self):
        """The rule: the group that fits the fix wins, not the group of the
        first fulfilled requirement.

        A mass-assignment fix fulfils AC-002 before IV-001, and AC-002 belongs
        to the authorization blueprint. The validation blueprint's
        "Unexpected Field Handling" section is what prescribes this fix.
        """
        sel = self._select(["AC-002", "IV-001"], "Allowlist client-controlled fields")
        assert sel is not None
        assert sel.blueprint_id == "BP-VALIDATION"
        assert sel.sections[0].title == "Unexpected Field Handling"
        assert "BP-AUTHZ" in sel.other_blueprint_ids

    def test_the_chosen_blueprint_scores_at_least_as_high_as_every_alternative(self):
        """Generic form of the rule above — no candidate may outscore the winner."""
        by_req = rt.sections_by_requirement(CATALOG)
        for title in (
            "Allowlist client-controlled fields",
            "Enforce object-level ownership authorization",
            "Check the role claim on each admin route",
        ):
            ctx = rt.RankContext(primary=title)
            sel = rt.select_blueprint(by_req, ["AC-002", "IV-001"], ctx)
            assert sel is not None
            primary, secondary = ctx.terms()
            for candidate in {s.blueprint_id for s in by_req["AC-002"] + by_req["IV-001"]}:
                best = max(
                    rt._section_score(s, primary, secondary)
                    for reqs in (by_req["AC-002"], by_req["IV-001"])
                    for s in reqs
                    if s.blueprint_id == candidate
                )
                assert sel.score >= best, f"{title}: {candidate} scored {best} > winner {sel.score}"

    def test_sections_within_the_winner_are_ranked_too(self):
        sel = self._select(["AC-002"], "Enforce resource ownership on the order identifier")
        assert sel is not None
        assert sel.sections[0].title == "Resource-Level Authorization"

    def test_a_selection_with_no_shared_wording_reports_itself_ungrounded(self):
        """Without this flag the report calls an arbitrary pick "governing"."""
        sel = self._select(["AC-002"], "Zzz qqq")
        assert sel is not None
        assert sel.score == 0
        assert sel.is_grounded is False

    def test_no_blueprint_for_the_requirement_returns_none(self):
        assert self._select(["LM-001"], "Add security audit logging") is None
        assert self._select([], "anything") is None

    def test_empty_context_keeps_catalog_order(self):
        sel = self._select(["AC-002"], "")
        assert sel is not None
        assert sel.sections[0].title == "Method-Level Authorization"


class TestRequirementIdsForThreat:
    KNOWN = {"AC-002": "u/ac", "IV-001": "u/iv"}

    def test_all_three_sources_are_unioned_in_order(self):
        threat = {
            "violated_requirements": ["AC-002"],
            "requirement_id": "IV-001",
            "remediation": {"reference": "CWE-915"},
        }
        assert rt.requirement_ids_for_threat(threat, self.KNOWN) == ["AC-002", "IV-001"]

    @pytest.mark.parametrize(
        "reference",
        ["[IV-001](u/iv)", "[IV-001]", "see IV-001 for details", "IV-001"],
        ids=["linked", "bracketed", "bare-inline", "bare-only"],
    )
    def test_a_requirement_parked_in_the_reference_is_recovered(self, reference):
        threat = {"remediation": {"reference": reference}}
        assert rt.requirement_ids_for_threat(threat, self.KNOWN) == ["IV-001"]

    def test_non_requirement_references_are_never_matched(self):
        threat = {"remediation": {"reference": "CWE-89: https://cwe.mitre.org/data/definitions/89.html"}}
        assert rt.requirement_ids_for_threat(threat, self.KNOWN) == []

    def test_an_undeclared_id_is_dropped_when_a_catalog_is_loaded(self):
        threat = {"violated_requirements": ["AC-002", "MADE-UP-9"]}
        assert rt.requirement_ids_for_threat(threat, self.KNOWN) == ["AC-002"]

    def test_without_a_catalog_declared_ids_are_taken_as_given(self):
        threat = {"violated_requirements": ["ANY-001"], "remediation": {"reference": "OTHER-002"}}
        # No catalog: the array is honoured, but nothing is mined from the
        # reference — there is no declared-ID set to match against.
        assert rt.requirement_ids_for_threat(threat, None) == ["ANY-001"]

    def test_partial_id_matches_do_not_count(self):
        threat = {"remediation": {"reference": "IV-0011 and IV-001X"}}
        assert rt.requirement_ids_for_threat(threat, self.KNOWN) == []


class TestModelAndReportAgree:
    """The report's requirement list must be a VIEW of the model's, never a
    different set. It may show fewer (the §7b status filter), never others."""

    def test_the_yaml_derivation_covers_every_threat_side_source(self, tmp_path):
        build_yaml = _load_module("build_threat_model_yaml", REPO_ROOT / "scripts" / "build_threat_model_yaml.py")
        (tmp_path / ".requirements.yaml").write_text(yaml.safe_dump(CATALOG), encoding="utf-8")
        threats = [
            {"id": "T-001", "title": "Mass assignment", "scenario": "attacker sets role", "mitigation_ids": ["M-001"]},
            {"id": "T-002", "requirement_id": "IV-001", "title": "Unvalidated body", "mitigation_ids": ["M-001"]},
        ]
        threats[0]["violated_requirements"] = ["AC-002"]
        mitigations = [{"id": "M-001", "title": "Allowlist client-controlled fields", "threat_ids": ["T-001", "T-002"]}]
        build_yaml.annotate_requirements_and_blueprints(threats, mitigations, tmp_path)
        # Both sources reach the model, not just `violated_requirements`.
        assert set(mitigations[0]["fulfills_requirements"]) == {"AC-002", "IV-001"}
        # …and the blueprint is chosen from the completed list.
        assert mitigations[0]["blueprint"]["id"] == "BP-VALIDATION"
        assert mitigations[0]["blueprint"]["grounded"] is True
        assert mitigations[0]["blueprint"]["section_url"] == "https://example.test/validation.html"

    def test_a_run_without_a_catalog_gets_neither_field(self, tmp_path):
        build_yaml = _load_module("build_threat_model_yaml", REPO_ROOT / "scripts" / "build_threat_model_yaml.py")
        threats = [{"id": "T-001", "violated_requirements": ["AC-002"], "mitigation_ids": ["M-001"]}]
        mitigations = [{"id": "M-001", "title": "Fix it", "threat_ids": ["T-001"]}]
        build_yaml.annotate_requirements_and_blueprints(threats, mitigations, tmp_path)
        assert "blueprint" not in mitigations[0]
        # Without a catalog no ID can be validated, so the declared array stands.
        assert mitigations[0]["fulfills_requirements"] == ["AC-002"]

    def test_sidecar_authored_requirements_are_extended_not_replaced(self, tmp_path):
        build_yaml = _load_module("build_threat_model_yaml", REPO_ROOT / "scripts" / "build_threat_model_yaml.py")
        (tmp_path / ".requirements.yaml").write_text(yaml.safe_dump(CATALOG), encoding="utf-8")
        threats = [{"id": "T-001", "violated_requirements": ["AC-002"], "mitigation_ids": ["M-001"]}]
        mitigations = [{"id": "M-001", "title": "Fix it", "threat_ids": ["T-001"], "fulfills_requirements": ["IV-001"]}]
        build_yaml.annotate_requirements_and_blueprints(threats, mitigations, tmp_path)
        assert mitigations[0]["fulfills_requirements"] == ["IV-001", "AC-002"]


class TestAnalystSlice:
    """The prescribed implementation has to reach the analyst that writes the
    remediation steps, not only the renderer that prints them."""

    def test_each_requirement_carries_the_section_that_prescribes_it(self):
        contexts = _load_module("build_requirements_contexts", REPO_ROOT / "scripts" / "build_requirements_contexts.py")
        rows = contexts.build_rows(CATALOG)
        by_id = {r["id"]: r for row in rows for r in row["requirements"]}
        assert by_id["IV-001"]["blueprint_guidance"][0]["blueprint"] == "BP-VALIDATION"
        assert "allowlist" in by_id["IV-001"]["blueprint_guidance"][0]["guidance"].lower()
        # A requirement no blueprint prescribes carries no empty placeholder.
        assert "blueprint_guidance" not in by_id["LM-001"]

    def test_guidance_never_pushes_a_row_past_the_projection_cap(self):
        contexts = _load_module("build_requirements_contexts", REPO_ROOT / "scripts" / "build_requirements_contexts.py")
        # A category whose requirements each attract guidance, sized so the
        # unsplit row would exceed the cap the projection truncates at.
        catalog = json.loads(json.dumps(CATALOG))
        catalog["categories"][0]["requirements"] = [
            {"id": f"AC-{n:03d}", "priority": "MUST", "text": "x" * 400} for n in range(2, 40)
        ]
        catalog["blueprints"][0]["sections"][0]["references"] = [{"id": f"AC-{n:03d}"} for n in range(2, 40)]
        for row in contexts.build_rows(catalog):
            assert contexts._row_chars(row) <= contexts.MAX_ROW_CHARS

    def test_a_catalog_without_blueprints_produces_the_same_rows_as_before(self):
        contexts = _load_module("build_requirements_contexts", REPO_ROOT / "scripts" / "build_requirements_contexts.py")
        catalog = {"categories": CATALOG["categories"]}
        for row in contexts.build_rows(catalog):
            for req in row["requirements"]:
                assert "blueprint_guidance" not in req


class TestPostComposeRequirementsExport:
    def _run(self, tmp_path: Path, monkeypatch, *, fragment: str | None) -> tuple[object, Path]:
        emitter = _load_module(
            "emit_requirement_trace_to_model_test",
            REPO_ROOT / "scripts" / "emit_requirement_trace_to_model.py",
        )
        (tmp_path / ".requirements.yaml").write_text(yaml.safe_dump(CATALOG), encoding="utf-8")
        if fragment is not None:
            (tmp_path / ".fragments").mkdir()
            (tmp_path / ".fragments" / "requirements-compliance.md").write_text(fragment, encoding="utf-8")
        yaml_path = tmp_path / "threat-model.yaml"
        yaml_path.write_text("mitigations: []\nthreats: []\n", encoding="utf-8")
        monkeypatch.setattr(emitter, "validate_threat_model_output", lambda _doc: (True, []))
        return emitter, yaml_path

    def test_complete_stage2_assessment_is_persisted_in_the_yaml(self, tmp_path, monkeypatch):
        fragment = """\
| Requirement | Status | Priority | Evidence |
| --- | --- | --- | --- |
| `AC-002`: Authorization | ✅ PASS | MUST | server guard |
| `IV-001`: Validation | ❌ FAIL | MUST | F-001 |
| `LM-001`: Logging | ❓ UNVERIFIABLE | SHOULD | not observed |
"""
        emitter, yaml_path = self._run(tmp_path, monkeypatch, fragment=fragment)
        assert "written" in emitter.emit(tmp_path)
        compliance = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))["requirements_compliance"]
        assert compliance["total"] == 3
        assert compliance["requirements"][1]["finding_ids"] == ["F-001"]

    def test_complete_stage2_assessment_persists_provenance(self, tmp_path, monkeypatch):
        fragment = """\
| Requirement | Status | Priority | Evidence |
| --- | --- | --- | --- |
| `AC-002`: Authorization | ✅ PASS | MUST | server guard |
| `IV-001`: Validation | ❌ FAIL | MUST | F-001 |
| `LM-001`: Logging | ❓ UNVERIFIABLE | SHOULD | not observed |
"""
        emitter, yaml_path = self._run(tmp_path, monkeypatch, fragment=fragment)
        (tmp_path / ".requirements-resolution.json").write_text(
            json.dumps(
                {
                    "source_kind": "org-profile",
                    "label": "Corporate baseline",
                    "url": "https://internal.example/secret-path/catalog.yaml",
                    "cache_path": "/private/cache/catalog.yaml",
                    "disposition": "fetched",
                    "fetched_at": "2026-08-28T00:00:00Z",
                    "generated": "2026-08-20T00:00:00Z",
                    "freshness": {"known": True, "stale": False, "age_days": 9},
                }
            ),
            encoding="utf-8",
        )

        emitter.emit(tmp_path)

        provenance = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))["requirements_provenance"]
        assert provenance["source_kind"] == "org-profile"
        assert provenance["source_label"] == "Corporate baseline"
        assert provenance["count"] == 3
        assert len(provenance["catalog_sha256"]) == 64
        assert "url" not in provenance and "cache_path" not in provenance

    def test_missing_stage2_assessment_fails_without_rewriting_yaml(self, tmp_path, monkeypatch):
        emitter, yaml_path = self._run(tmp_path, monkeypatch, fragment=None)
        before = yaml_path.read_bytes()
        with pytest.raises(emitter.RequirementsComplianceError, match="no Stage-2 compliance assessment"):
            emitter.emit(tmp_path)
        assert yaml_path.read_bytes() == before

    def test_schema_failure_fails_without_rewriting_yaml(self, tmp_path, monkeypatch):
        fragment = """\
| Requirement | Status | Priority | Evidence |
| --- | --- | --- | --- |
| `AC-002`: Authorization | ✅ PASS | MUST | server guard |
| `IV-001`: Validation | ❌ FAIL | MUST | F-001 |
| `LM-001`: Logging | ✅ PASS | SHOULD | audit log |
"""
        emitter, yaml_path = self._run(tmp_path, monkeypatch, fragment=fragment)
        before = yaml_path.read_bytes()
        monkeypatch.setattr(emitter, "validate_threat_model_output", lambda _doc: (False, ["bad contract"]))
        with pytest.raises(emitter.RequirementsComplianceError, match="bad contract"):
            emitter.emit(tmp_path)
        assert yaml_path.read_bytes() == before
