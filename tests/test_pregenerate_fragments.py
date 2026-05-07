"""Unit tests for scripts/pregenerate_fragments.py.

The pre-generator produces 7 deterministic structural fragments from
threat-model.yaml. Tests verify per-generator output shape (heading
match, required sub-sections, required patterns) plus the CLI driver's
idempotency, --force, --only, and --dry-run flags.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "pregenerate_fragments.py"


def _load_module():
    if "pregenerate_fragments" in sys.modules:
        return sys.modules["pregenerate_fragments"]
    spec = importlib.util.spec_from_file_location("pregenerate_fragments", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["pregenerate_fragments"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


pf = _load_module()


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def minimal_yaml_data():
    """A complete-enough yaml shape that all 6 generators succeed."""
    return {
        "meta": {
            "project": {
                "name": "TestApp",
                "description": "Test application for unit tests",
                "runtime": "Node.js 20",
                "repository": "https://example.com/repo",
            },
            "scope": {
                "out_of_scope": ["DNS infra", "End-user devices"],
            },
        },
        "components": [
            {"id": "rest-api", "name": "REST API", "paths": ["server.ts"], "threat_ids": ["F-001", "F-002"]},
            {"id": "frontend-spa", "name": "Frontend SPA", "paths": ["frontend/**"], "threat_ids": ["F-003"]},
            {"id": "nosql-data-layer", "name": "NoSQL Layer", "paths": ["data/**"], "threat_ids": []},
        ],
        "trust_boundaries": [
            {"id": "TB-001", "name": "Internet", "description": "Public", "enforcement": "WAF"},
            {"id": "TB-002", "name": "Auth Zone", "description": "JWT", "enforcement": "express-jwt"},
        ],
        "assets": [
            {"id": "A-001", "name": "User credentials", "classification": "Critical",
             "description": "Email + hash"},
        ],
        "attack_surface": {
            "unauthenticated": [
                {"method": "GET", "route": "/api/foo", "auth_required": False, "notes": "Public"},
            ],
            "authenticated": [
                {"method": "POST", "route": "/api/bar", "auth_required": True, "notes": "JWT-protected"},
            ],
        },
        "security_controls": [
            {"domain": "Identity & Access Management", "control": "JWT auth",
             "implementation": "express-jwt", "effectiveness": "weak", "notes": "outdated"},
            {"domain": "Input Validation", "control": "Sanitization",
             "implementation": "manual", "effectiveness": "missing", "notes": "no validator"},
        ],
    }


@pytest.fixture
def output_dir(tmp_path, minimal_yaml_data):
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True)
    (out / "threat-model.yaml").write_text(yaml.safe_dump(minimal_yaml_data))
    return out


# ---------------------------------------------------------------------------
# Per-generator output-shape tests
# ---------------------------------------------------------------------------

class TestSystemOverview:
    def test_starts_with_correct_heading(self, minimal_yaml_data):
        md = pf.gen_system_overview(minimal_yaml_data)
        assert md.startswith("## 1. System Overview\n")

    def test_lists_all_components(self, minimal_yaml_data):
        md = pf.gen_system_overview(minimal_yaml_data)
        assert "REST API" in md
        assert "Frontend SPA" in md
        assert "NoSQL Layer" in md

    def test_includes_out_of_scope(self, minimal_yaml_data):
        md = pf.gen_system_overview(minimal_yaml_data)
        assert "DNS infra" in md
        assert "End-user devices" in md


class TestArchitectureDiagrams:
    def test_starts_with_correct_heading(self, minimal_yaml_data):
        md = pf.gen_architecture_diagrams(minimal_yaml_data)
        assert md.startswith("## 2. Architecture Diagrams\n")

    def test_has_all_four_required_subsections(self, minimal_yaml_data):
        md = pf.gen_architecture_diagrams(minimal_yaml_data)
        assert "### 2.1 System Context" in md
        assert "### 2.2 Container Architecture" in md
        assert "### 2.3 Components" in md
        assert "### 2.4 Technology Architecture" in md

    def test_contains_at_least_one_mermaid_block(self, minimal_yaml_data):
        md = pf.gen_architecture_diagrams(minimal_yaml_data)
        assert "```mermaid" in md
        # At least 3 — one per C4 level + boundary diagram
        assert md.count("```mermaid") >= 3

    def test_no_forbidden_section_25(self, minimal_yaml_data):
        md = pf.gen_architecture_diagrams(minimal_yaml_data)
        # Per contract, "### 2.5 Security Architecture Assessment" is forbidden
        assert "### 2.5 Security Architecture" not in md

    def test_components_table_present(self, minimal_yaml_data):
        md = pf.gen_architecture_diagrams(minimal_yaml_data)
        assert "| Component ID |" in md
        assert "| rest-api |" in md


class TestAssets:
    def test_starts_with_correct_heading(self, minimal_yaml_data):
        md = pf.gen_assets(minimal_yaml_data)
        assert md.startswith("## 4. Assets\n")

    def test_contains_asset_table(self, minimal_yaml_data):
        md = pf.gen_assets(minimal_yaml_data)
        # Contract requires "| Asset |" header
        assert "| Asset |" in md
        assert "| User credentials |" in md

    def test_handles_empty_assets(self):
        md = pf.gen_assets({"assets": []})
        assert md.startswith("## 4. Assets\n")
        assert "_No assets enumerated" in md


class TestAttackSurface:
    def test_starts_with_correct_heading(self, minimal_yaml_data):
        md = pf.gen_attack_surface(minimal_yaml_data)
        assert md.startswith("## 5. Attack Surface\n")

    def test_has_required_subsections(self, minimal_yaml_data):
        md = pf.gen_attack_surface(minimal_yaml_data)
        # Contract requires 5.1 + 5.2 patterns; we use the canonical wording
        assert re.search(r"^### 5\.1 Unauthenticated", md, re.MULTILINE)
        assert re.search(r"^### 5\.2 Authenticated", md, re.MULTILINE)

    def test_lists_routes(self, minimal_yaml_data):
        md = pf.gen_attack_surface(minimal_yaml_data)
        assert "/api/foo" in md
        assert "/api/bar" in md

    # M3.2 — schema-tolerance regression tests. The 2026-04-26 19:55 run
    # crashed pregenerate_fragments.py with `'str' object has no attribute
    # 'get'` because the orchestrator emitted attack_surface as a
    # dict-with-entries (v1.1 schema) rather than a flat list. These tests
    # lock in tolerance for all three valid shapes plus an explicit
    # rejection of bare strings inside lists.

    def test_dict_with_entries_v1_1_shape(self):
        """attack_surface.{unauthenticated,authenticated}.{count, entries: [...]}"""
        data = {
            "attack_surface": {
                "unauthenticated": {
                    "count": 2,
                    "entries": [
                        {"endpoint": "POST /rest/login", "method": "POST",
                         "auth_required": False, "linked_threats": ["T-001"]},
                        {"endpoint": "GET /metrics", "method": "GET",
                         "auth_required": False, "linked_threats": ["T-002"]},
                    ],
                },
                "authenticated": {
                    "count": 1,
                    "entries": [
                        {"endpoint": "POST /api/orders", "method": "POST",
                         "auth_required": True, "linked_threats": ["T-003"]},
                    ],
                },
            }
        }
        md = pf.gen_attack_surface(data)
        assert "/rest/login" in md
        assert "/metrics" in md
        assert "/api/orders" in md
        # Linked-threat IDs render as link cells.
        # P4 — visible label normalised T-NNN → F-NNN (anchor stays valid
        # via the dual-anchor emission in compose._render_threat_register).
        assert "[F-001](#f-001)" in md
        assert "[F-003](#f-003)" in md

    def test_flat_list_v0_shape(self):
        """attack_surface = [ {path, requires_auth, threats}, ... ]"""
        data = {
            "attack_surface": [
                {"path": "POST /a", "method": "POST", "requires_auth": False, "threats": ["T-1"]},
                {"path": "GET /b", "method": "GET", "requires_auth": True, "threats": ["T-2"]},
            ]
        }
        md = pf.gen_attack_surface(data)
        assert "/a" in md
        assert "/b" in md

    def test_string_entries_silently_dropped_no_crash(self):
        """Defensive: string mixed in with dicts must not crash the renderer."""
        data = {
            "attack_surface": {
                "unauthenticated": [
                    {"endpoint": "GET /ok", "method": "GET", "linked_threats": ["T-1"]},
                    "POST /bare-string-entry-from-bad-llm-output",  # ← was the crash
                ]
            }
        }
        md = pf.gen_attack_surface(data)  # must not raise
        assert "/ok" in md
        # Bare string was silently dropped — count reflects the surviving entries.
        assert "(1)" in md  # "Unauthenticated Entry Points (1)"

    def test_endpoint_field_name_priority(self):
        """endpoint > path > route — exercises the three field-name aliases."""
        data = {
            "attack_surface": {
                "unauthenticated": [
                    {"endpoint": "GET /e1", "method": "GET"},
                    {"path": "GET /e2", "method": "GET"},
                    {"route": "GET /e3", "method": "GET"},
                ]
            }
        }
        md = pf.gen_attack_surface(data)
        assert "/e1" in md
        assert "/e2" in md
        assert "/e3" in md

    def test_method_prefix_stripped_from_route(self):
        data = {
            "attack_surface": {
                "unauthenticated": [
                    {"endpoint": "POST /rest/login", "method": "POST"},
                ]
            }
        }
        md = pf.gen_attack_surface(data)
        # Method already has its own column; route column should NOT
        # prepend it again.
        assert "POST /rest/login" not in md
        assert "/rest/login" in md


# ---------------------------------------------------------------------------
# M3.3 / D1 — §2 + §7 substance enrichments
# ---------------------------------------------------------------------------


class TestArchitectureDataFlows:
    """The §2.2 mermaid block must read data_flows[] when populated."""

    def test_data_flow_edges_render_when_yaml_populates_flows(self):
        data = {
            "meta": {"project": {"name": "TestApp"}},
            "components": [
                {"id": "spa",     "name": "SPA",     "paths": ["frontend/**"]},
                {"id": "api",     "name": "API",     "paths": ["server.ts"]},
                {"id": "db",      "name": "DB",      "paths": ["models/**"]},
            ],
            "data_flows": [
                {"id": "df-1", "from": "spa", "to": "api",
                 "label": "REST", "protocol": "HTTPS",
                 "data_classification": "JWT-bearing"},
                {"id": "df-2", "from": "api", "to": "db",
                 "label": "ORM", "protocol": "JDBC",
                 "data_classification": "Confidential"},
            ],
            "trust_boundaries": [],
        }
        md = pf.gen_architecture_diagrams(data)
        # D1.5: edge label is `<protocol> · <classification>` (without
        # explicit `label` field, the protocol-only head is used).
        assert "spa -->|HTTPS · JWT-bearing| api" in md
        assert "api -->|JDBC · Confidential| db" in md
        # Legacy fallback edge MUST NOT appear when explicit flows render.
        assert "HTTPS REST" not in md  # legacy hard-coded label

    def test_falls_back_to_tier_heuristic_when_data_flows_empty(self):
        data = {
            "meta": {"project": {"name": "TestApp"}},
            "components": [
                {"id": "spa", "name": "SPA", "paths": ["frontend/**"]},
                {"id": "api", "name": "API", "paths": ["server.ts"]},
                {"id": "db",  "name": "DB",  "paths": ["models/**"]},
            ],
            "data_flows": [],
            "trust_boundaries": [],
        }
        md = pf.gen_architecture_diagrams(data)
        # Legacy edges expected
        assert "HTTPS REST" in md
        assert "driver" in md

    def test_string_entries_in_data_flows_are_dropped(self):
        """Defensive: bare strings in data_flows must not crash."""
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [
                {"id": "a", "name": "A", "paths": ["a"]},
                {"id": "b", "name": "B", "paths": ["b"]},
            ],
            "data_flows": [
                "garbage string entry",
                {"from": "a", "to": "b", "label": "ok"},
            ],
            "trust_boundaries": [],
        }
        md = pf.gen_architecture_diagrams(data)  # must not raise
        assert "a -->|ok| b" in md

    def test_unknown_component_ids_silently_skipped(self):
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [{"id": "a", "name": "A", "paths": ["a"]}],
            "data_flows": [
                {"from": "a", "to": "nonexistent", "label": "broken"},
            ],
            "trust_boundaries": [],
        }
        md = pf.gen_architecture_diagrams(data)
        # Edge to nonexistent component must NOT render.
        assert "broken" not in md


class TestEnforcementColumn:
    """§2.4 Trust Boundaries Enforcement column must populate via fallback."""

    def test_explicit_enforcement_field_used_directly(self):
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [],
            "trust_boundaries": [
                {"id": "tb-1", "name": "Public", "trust_level": "untrusted",
                 "enforcement": "TLS 1.3 + WAF (Cloudflare)"},
            ],
        }
        md = pf.gen_architecture_diagrams(data)
        assert "TLS 1.3 + WAF (Cloudflare)" in md

    def test_derived_enforcement_for_internet_boundary(self):
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [],
            "trust_boundaries": [
                {"id": "tb-1", "name": "Public Internet",
                 "description": "External browsers", "trust_level": "untrusted"},
            ],
        }
        md = pf.gen_architecture_diagrams(data)
        # Heuristic detects 'internet' / 'browser' → TLS · WAF
        assert "TLS" in md or "WAF" in md

    def test_derived_enforcement_for_data_tier(self):
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [],
            "trust_boundaries": [
                {"id": "data-tier", "name": "Database",
                 "description": "Persistence layer", "trust_level": "restricted"},
            ],
        }
        md = pf.gen_architecture_diagrams(data)
        assert "ORM" in md or "driver" in md


class TestSecurityArchitectureCWEMapping:
    """§7 must surface threats by CWE when no controls cataloged."""

    def _data(self, threats):
        return {
            "meta": {"project": {"name": "x"}},
            "components": [{"id": "c1", "name": "C1", "paths": ["a"]}],
            "security_controls": [
                # IAM control present so §7.3 is the only "controls cataloged" section
                {"control": "JWT Auth", "domain": "Identity & Access Management",
                 "implementation": "express-jwt", "effectiveness": "weak"},
            ],
            "threats": threats,
        }

    def test_websocket_threats_surface_in_7_8_via_title(self):
        threats = [
            {"id": "T-100", "cwe": "CWE-306",
             "title": "Socket.IO Events Lack Authentication",
             "scenario": "WebSocket events bypass auth.",
             "risk": "High"},
        ]
        md = pf.gen_security_architecture(self._data(threats))
        # §7.8 should reference T-100 (rendered as F-100 visible label
        # after P4 normalisation; anchor stays valid via dual-anchor
        # emission in compose._render_threat_register).
        sec_7_8 = md.split("### 7.8")[1].split("### 7.9")[0]
        assert "T-100" in sec_7_8 or "F-100" in sec_7_8

    def test_input_validation_threats_surface_in_7_5_via_cwe(self):
        threats = [
            {"id": "T-200", "cwe": "CWE-79", "title": "Stored XSS",
             "scenario": "...", "risk": "High"},
        ]
        md = pf.gen_security_architecture(self._data(threats))
        # §7.5 has IAM control too? Actually the data has only an IAM
        # control. §7.5 has no controls → falls back to threat-mapping.
        # P4 normalises T-NNN → F-NNN visible label.
        sec_7_5 = md.split("### 7.5")[1].split("### 7.6")[0]
        assert "T-200" in sec_7_5 or "F-200" in sec_7_5

    def test_unrelated_threat_does_not_match_7_8(self):
        """Regression: 'allows' / 'answers' must NOT trigger 'ws ' substring match."""
        threats = [
            {"id": "T-300", "cwe": "CWE-79",
             "title": "XSS that allows script execution",
             "scenario": "Script execution allows attacker to steal tokens.",
             "risk": "Critical"},
        ]
        md = pf.gen_security_architecture(self._data(threats))
        sec_7_8 = md.split("### 7.8")[1].split("### 7.9")[0]
        assert "T-300" not in sec_7_8, \
            "T-300 has nothing to do with WebSockets — must not appear in §7.8"


class TestControlNotesFallback:
    """_control_notes must fall through notes → effectiveness_reason → gaps[0]."""

    def test_notes_field_takes_precedence(self):
        c = {"notes": "primary", "effectiveness_reason": "secondary",
             "gaps": ["tertiary"]}
        assert pf._control_notes(c) == "primary"

    def test_falls_back_to_effectiveness_reason(self):
        c = {"effectiveness_reason": "this is the reason",
             "gaps": ["a gap"]}
        assert pf._control_notes(c) == "this is the reason"

    def test_falls_back_to_first_gap(self):
        c = {"gaps": ["first concrete gap", "second gap"]}
        assert pf._control_notes(c) == "first concrete gap"

    def test_returns_empty_when_nothing_present(self):
        assert pf._control_notes({}) == ""
        assert pf._control_notes({"notes": ""}) == ""

    def test_safe_on_non_dict_input(self):
        assert pf._control_notes("not a dict") == ""
        assert pf._control_notes(None) == ""


class TestSystemContextDiagram:
    """§2.1 mermaid is now derived from yaml actors / surface / threats."""

    def _data(self, **overrides):
        base = {
            "meta": {"project": {"name": "TestApp"}},
            "components": [],
            "trust_boundaries": [],
            "attack_surface": {},
            "threats": [],
            "security_controls": [],
        }
        base.update(overrides)
        return base

    def test_falls_back_to_user_plus_attacker_when_no_actors(self):
        md = pf.gen_architecture_diagrams(self._data())
        assert "USER[" in md
        assert "ATTACKER[" in md

    def test_authenticated_user_appears_when_auth_surface_populated(self):
        data = self._data(attack_surface={
            "authenticated": [
                {"endpoint": "GET /api/orders", "method": "GET"},
            ]
        })
        md = pf.gen_architecture_diagrams(data)
        assert "AUTHED[" in md

    def test_admin_actor_appears_when_threats_mention_admin(self):
        data = self._data(threats=[
            {"id": "T-1", "title": "Admin panel SQL injection", "risk": "High"},
        ])
        md = pf.gen_architecture_diagrams(data)
        assert "ADMIN[" in md

    def test_external_services_appear_for_ssrf_threats(self):
        data = self._data(threats=[
            {"id": "T-1", "cwe": "CWE-918", "title": "SSRF via image fetcher",
             "risk": "High"},
        ])
        md = pf.gen_architecture_diagrams(data)
        assert "EXTERNAL[" in md
        # D1.5: when the SSRF heuristic fires, the auto-added external
        # node carries protocol "HTTPS" so the edge reads "outbound · HTTPS".
        assert "outbound" in md

    def test_attacker_uses_dotted_arrow(self):
        md = pf.gen_architecture_diagrams(self._data())
        assert "ATTACKER -.->" in md  # dashed arrow distinguishes attacker

    def test_actors_yaml_takes_priority(self):
        data = self._data(meta={
            "project": {"name": "x"},
            "actors": [
                {"id": "qa", "name": "QA Engineer", "role": "user"},
                {"id": "auditor", "name": "Compliance Auditor", "role": "admin"},
            ],
        })
        md = pf.gen_architecture_diagrams(data)
        assert "QA Engineer" in md
        assert "Compliance Auditor" in md


class TestComponentsDiagram:
    """§2.3 Components — attack edges from external actors to internal tiers.

    Verifies the post-2026-05 fix that closed two bugs:
      * REPO_READ orphan node (selector looked for css_class="external" but
        repo-read was reclassed to "threat" for §1.4 heatmap parity).
      * Missing client-tier attack edge (only one edge from attacker → app
        was emitted, regardless of whether a client tier existed).
    """

    def _data(self, **overrides):
        base = {
            "meta": {"project": {"name": "TestApp"}},
            "components": [
                {"id": "spa",     "name": "Frontend",   "tier": "client",
                 "paths": ["frontend/**"]},
                {"id": "backend", "name": "API",        "tier": "application",
                 "paths": ["server.ts"]},
                {"id": "db",      "name": "Database",   "tier": "data",
                 "paths": ["models/**"]},
            ],
            "trust_boundaries": [],
            "attack_surface": {},
            "threats": [],
            "security_controls": [],
        }
        base.update(overrides)
        return base

    def _section_2_3(self, md: str) -> str:
        # Isolate the §2.3 mermaid block.
        head = md.split("### 2.3")[1]
        return head.split("###")[0]

    def test_internet_anon_attacks_application_tier(self):
        block = self._section_2_3(pf.gen_architecture_diagrams(self._data()))
        # Existing baseline: attacker reaches the application tier.
        assert "INTERNET_ANON -.->" in block
        assert "injection · auth bypass · RCE" in block

    def test_internet_anon_also_attacks_client_tier(self):
        block = self._section_2_3(pf.gen_architecture_diagrams(self._data()))
        # Regression guard for the missing client-tier attack edge.
        assert 'INTERNET_ANON -.->|"XSS · client tampering · token theft"' in block

    def test_repo_read_attacks_application_tier(self):
        block = self._section_2_3(pf.gen_architecture_diagrams(self._data()))
        # Regression guard for the orphan REPO_READ node bug.
        assert 'REPO_READ -.->|"leaked credentials · auth bypass"' in block

    def test_no_client_edge_when_no_client_tier(self):
        # Pure backend service — no SPA. Attacker must not get a client-tier
        # edge to a non-existent node.
        data = self._data(components=[
            {"id": "backend", "name": "API", "tier": "application",
             "paths": ["server.ts"]},
            {"id": "db", "name": "Database", "tier": "data",
             "paths": ["models/**"]},
        ])
        block = self._section_2_3(pf.gen_architecture_diagrams(data))
        assert 'XSS · client tampering · token theft' not in block
        # But the application-tier edge still renders.
        assert 'injection · auth bypass · RCE' in block

    def test_no_repo_edge_when_no_application_tier(self):
        # Hypothetical client-only architecture. The repo edge target is the
        # application tier — no app, no edge.
        data = self._data(components=[
            {"id": "spa", "name": "Frontend", "tier": "client",
             "paths": ["frontend/**"]},
        ])
        block = self._section_2_3(pf.gen_architecture_diagrams(data))
        assert 'leaked credentials · auth bypass' not in block

    def test_linkstyle_attack_indices_match_edge_count(self):
        # 3 legit edges (victim → client → app → data) + 3 attack edges
        # (anon→app, anon→client, repo→app) → linkStyle indices 3,4,5.
        block = self._section_2_3(pf.gen_architecture_diagrams(self._data()))
        assert "linkStyle 0,1,2 stroke:#2e7d32" in block
        assert "linkStyle 3,4,5 stroke:#b71c1c" in block

    def test_node_count_within_contract_cap(self):
        # data/sections-contract.yaml → diagram_compactness."2.3 Components"
        # caps total nodes at 8. With 3 actors + 3 tier nodes = 6 nodes, the
        # patch must not push over the cap.
        block = self._section_2_3(pf.gen_architecture_diagrams(self._data()))
        # Count distinct node declarations: lines like `NAME[...]` or
        # `NAME([...])` or `NAME[(...)]` inside subgraphs.
        import re as _re
        nodes = _re.findall(r'^\s+([A-Z][A-Z0-9_]*)\[', block, _re.MULTILINE)
        assert len(set(nodes)) <= 8, f"node count exceeds contract cap: {sorted(set(nodes))}"


class TestActorIdBySlug:
    """Helper that resolves a §2.3 actor's mermaid node id from its canonical
    slug. Mirrors the slug→id transform used inside the actor builder."""

    def test_resolves_known_slug(self):
        actors = [
            {"id": "INTERNET_ANON",   "label": "x", "css_class": "threat"},
            {"id": "VICTIM_REQUIRED", "label": "x", "css_class": "legit"},
            {"id": "REPO_READ",       "label": "x", "css_class": "threat"},
        ]
        assert pf._actor_id_by_slug(actors, "internet-anon") == "INTERNET_ANON"
        assert pf._actor_id_by_slug(actors, "repo-read") == "REPO_READ"
        assert pf._actor_id_by_slug(actors, "victim-required") == "VICTIM_REQUIRED"

    def test_returns_none_when_slug_absent(self):
        actors = [{"id": "INTERNET_ANON", "label": "x", "css_class": "threat"}]
        assert pf._actor_id_by_slug(actors, "repo-read") is None

    def test_returns_none_for_empty_actor_list(self):
        assert pf._actor_id_by_slug([], "internet-anon") is None


class TestTechnologyArchitectureDiagram:
    """§2.4 mermaid uses trust_level → tier mapping (M3.3 / D1)."""

    def _data(self):
        return {
            "meta": {"project": {"name": "x"}},
            "components": [
                {"id": "spa",     "name": "SPA",     "tier": "client",
                 "paths": ["frontend/**"]},
                {"id": "api",     "name": "API",     "tier": "application",
                 "paths": ["server.ts"]},
                {"id": "service", "name": "Service", "tier": "application",
                 "paths": ["lib/**"]},
                {"id": "db",      "name": "DB",      "tier": "data",
                 "paths": ["models/**"]},
            ],
            "trust_boundaries": [
                {"id": "public",  "name": "Public Internet",
                 "trust_level": "untrusted"},
                {"id": "app-process", "name": "Application Process",
                 "trust_level": "trusted"},
                {"id": "data-tier", "name": "Data Tier",
                 "trust_level": "restricted"},
            ],
            "data_flows": [
                {"from": "spa", "to": "api", "label": "REST",
                 "protocol": "HTTPS", "data_classification": "JWT-bearing"},
                {"from": "api", "to": "db", "label": "ORM",
                 "protocol": "Sequelize", "data_classification": "Confidential"},
            ],
        }

    def test_each_boundary_renders_a_subgraph(self):
        md = pf.gen_architecture_diagrams(self._data())
        # The §2.4 mermaid is the second mermaid block (§2.1 is the first).
        sec_2_4 = md.split("### 2.4")[1].split("##")[0]
        assert 'subgraph PUBLIC[' in sec_2_4
        assert 'subgraph APP_PROCESS[' in sec_2_4
        assert 'subgraph DATA_TIER[' in sec_2_4

    def test_application_components_placed_in_trusted_boundary(self):
        md = pf.gen_architecture_diagrams(self._data())
        sec_2_4 = md.split("### 2.4")[1].split("##")[0]
        # api + service inside app-process subgraph
        # The check is structural: between APP_PROCESS subgraph open and
        # its closing 'end', api and service should appear.
        app_subgraph = sec_2_4.split("APP_PROCESS")[1].split("end")[0]
        assert 'api[' in app_subgraph
        assert 'service[' in app_subgraph

    def test_client_component_placed_in_untrusted_boundary(self):
        md = pf.gen_architecture_diagrams(self._data())
        sec_2_4 = md.split("### 2.4")[1].split("##")[0]
        public_sg = sec_2_4.split("PUBLIC")[1].split("end")[0]
        assert 'spa[' in public_sg

    def test_data_component_placed_in_restricted_boundary(self):
        md = pf.gen_architecture_diagrams(self._data())
        sec_2_4 = md.split("### 2.4")[1].split("##")[0]
        data_sg = sec_2_4.split("DATA_TIER")[1].split("end")[0]
        assert 'db[' in data_sg

    def test_cross_boundary_edges_rendered_thick(self):
        md = pf.gen_architecture_diagrams(self._data())
        sec_2_4 = md.split("### 2.4")[1].split("##")[0]
        # spa→api crosses untrusted → trusted, must be thick (==>)
        assert "spa ==>" in sec_2_4

    def test_falls_back_to_stub_when_no_boundaries(self):
        data = self._data()
        data["trust_boundaries"] = []
        md = pf.gen_architecture_diagrams(data)
        sec_2_4 = md.split("### 2.4")[1].split("##")[0]
        # Legacy stub markers
        assert "TB1" in sec_2_4
        assert "TB2" in sec_2_4
        assert "TB3" in sec_2_4


class TestIamFlowSequence:
    """§7.3.1 IAM Flow chooses template based on control name + impl."""

    def test_jwt_template_chosen_for_jwt_control(self):
        seq = pf._iam_flow_sequence("JWT RS256 Authentication",
                                     "express-jwt + jsonwebtoken", [])
        text = "\n".join(seq)
        assert "Browser / SPA" in text
        assert "Express Backend" in text
        assert "JWT Signing Key" in text
        # Should be auto-numbered for clarity.
        assert "autonumber" in text

    def test_oauth_template_chosen_for_oauth_control(self):
        seq = pf._iam_flow_sequence("OAuth 2.0", "passport-oauth2", [])
        text = "\n".join(seq)
        assert "OAuth/OIDC Provider" in text
        assert "code_challenge" in text

    def test_basic_auth_template_chosen(self):
        seq = pf._iam_flow_sequence("Basic Authentication", "express-basic-auth", [])
        text = "\n".join(seq)
        assert "Basic base64" in text
        assert "bcrypt" in text

    def test_generic_fallback_when_no_match(self):
        seq = pf._iam_flow_sequence("Some Other Method", "custom impl", [])
        text = "\n".join(seq)
        # Generic stub markers
        assert "Identity Store" in text
        assert "credentials / token" in text

    def test_jwt_attack_annotations_fire_when_threats_match(self):
        threats = [
            {"id": "T-X", "cwe": "CWE-347", "title": "alg:none"},
            {"id": "T-Y", "cwe": "CWE-321", "title": "Hardcoded RSA key"},
            {"id": "T-Z", "cwe": "CWE-922", "title": "Token in localStorage"},
        ]
        seq = pf._iam_flow_sequence("JWT RS256 Authentication", "jsonwebtoken", threats)
        text = "\n".join(seq)
        assert "alg:none" in text  # alg-confusion note
        assert "hardcoded" in text.lower()  # credential-theft note
        assert "localStorage" in text  # session-hijack note

    def test_jwt_no_annotations_when_no_relevant_threats(self):
        seq = pf._iam_flow_sequence("JWT RS256", "jwt", [
            {"id": "T-1", "cwe": "CWE-79", "title": "Stored XSS unrelated"},
        ])
        text = "\n".join(seq)
        # None of the warning notes should appear
        assert "alg:none accepted" not in text
        assert "Private key hardcoded" not in text


# ---------------------------------------------------------------------------
# D1.5 — refined diagram enrichments (C/D/E/F/G/J/L/A/B)
# ---------------------------------------------------------------------------


class TestD15AuthMethodOnEdges:
    """D — auth_method renders alongside protocol on data_flow edges."""

    def test_auth_method_appended_to_protocol_on_2_2_edge(self):
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [
                {"id": "spa", "name": "SPA", "paths": ["frontend/**"]},
                {"id": "api", "name": "API", "paths": ["server.ts"]},
                {"id": "db",  "name": "DB",  "paths": ["models/**"]},
            ],
            "data_flows": [
                {"from": "spa", "to": "api", "protocol": "HTTPS",
                 "auth_method": "Bearer JWT",
                 "data_classification": "JWT-bearing"},
            ],
            "trust_boundaries": [],
        }
        md = pf.gen_architecture_diagrams(data)
        sec = md.split("### 2.2")[1].split("### 2.3")[0]
        assert "HTTPS / Bearer JWT" in sec

    def test_no_auth_method_falls_back_to_protocol_only(self):
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [
                {"id": "spa", "name": "SPA", "paths": ["a"]},
                {"id": "api", "name": "API", "paths": ["b"]},
            ],
            "data_flows": [
                {"from": "spa", "to": "api", "protocol": "HTTPS",
                 "data_classification": "Public"},
            ],
            "trust_boundaries": [],
        }
        md = pf.gen_architecture_diagrams(data)
        sec = md.split("### 2.2")[1].split("### 2.3")[0]
        assert "spa -->|HTTPS|" in sec  # public is dropped, no auth_method
        assert " / " not in sec.split("```mermaid")[1].split("```")[0]


class TestD15AsyncArrows:
    """E — Async protocols use dashed arrow."""

    def test_websocket_uses_dashed_arrow(self):
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [
                {"id": "spa", "name": "SPA", "paths": ["a"]},
                {"id": "ws",  "name": "WS",  "paths": ["b"]},
            ],
            "data_flows": [
                {"from": "spa", "to": "ws", "protocol": "WebSocket",
                 "data_classification": "Internal"},
            ],
            "trust_boundaries": [],
        }
        md = pf.gen_architecture_diagrams(data)
        sec = md.split("### 2.2")[1].split("### 2.3")[0]
        assert "spa -.->" in sec  # async dashed arrow
        assert "spa -->" not in sec  # NOT solid arrow

    def test_rest_uses_solid_arrow(self):
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [
                {"id": "spa", "name": "SPA", "paths": ["a"]},
                {"id": "api", "name": "API", "paths": ["b"]},
            ],
            "data_flows": [
                {"from": "spa", "to": "api", "protocol": "HTTPS",
                 "data_classification": "Public"},
            ],
            "trust_boundaries": [],
        }
        md = pf.gen_architecture_diagrams(data)
        sec = md.split("### 2.2")[1].split("### 2.3")[0]
        assert "spa -->" in sec
        assert "spa -.->" not in sec


class TestD15CriticalHighlight:
    """L — classDef critical/warning based on threat counts per component."""

    def _data_with_threats(self, threats):
        return {
            "meta": {"project": {"name": "x"}},
            "components": [
                {"id": "hot",  "name": "Hot",  "paths": ["a"]},
                {"id": "warm", "name": "Warm", "paths": ["b"]},
                {"id": "cold", "name": "Cold", "paths": ["c"]},
            ],
            "data_flows": [],
            "trust_boundaries": [],
            "threats": threats,
        }

    def test_three_or_more_critical_marks_critical(self):
        threats = [
            {"id": f"T-{i}", "component_id": "hot", "risk": "Critical"}
            for i in range(3)
        ]
        md = pf.gen_architecture_diagrams(self._data_with_threats(threats))
        sec = md.split("### 2.2")[1].split("### 2.3")[0]
        assert "class hot critical" in sec
        # cold has no threats — must NOT appear in any class line
        assert "class cold critical" not in sec
        assert "class cold warning" not in sec

    def test_two_or_more_high_marks_warning(self):
        threats = [
            {"id": f"T-{i}", "component_id": "warm", "risk": "High"}
            for i in range(2)
        ]
        md = pf.gen_architecture_diagrams(self._data_with_threats(threats))
        sec = md.split("### 2.2")[1].split("### 2.3")[0]
        assert "class warm warning" in sec
        assert "class warm critical" not in sec

    def test_critical_dominates_high(self):
        threats = (
            [{"id": f"T-c{i}", "component_id": "hot", "risk": "Critical"} for i in range(3)]
            + [{"id": f"T-h{i}", "component_id": "hot", "risk": "High"} for i in range(5)]
        )
        md = pf.gen_architecture_diagrams(self._data_with_threats(threats))
        sec = md.split("### 2.2")[1].split("### 2.3")[0]
        assert "class hot critical" in sec
        assert "class hot warning" not in sec  # critical wins over warning


class TestD15FilesystemFill:
    """F — Filesystem subgraph fills with path-stem ghost nodes."""

    def test_fs_paths_render_as_ghost_nodes(self):
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [
                {"id": "api", "name": "API", "paths": ["server.ts"]},
            ],
            "trust_boundaries": [
                {"id": "app", "name": "App Process", "trust_level": "trusted"},
                {"id": "filesystem", "name": "Server Filesystem",
                 "trust_level": "restricted"},
            ],
            "data_flows": [],
            "attack_surface": {
                "unauthenticated": [
                    {"endpoint": "GET /ftp/foo.bak", "method": "GET"},
                    {"endpoint": "GET /encryptionkeys/key.pem", "method": "GET"},
                ],
            },
        }
        md = pf.gen_architecture_diagrams(data)
        sec = md.split("### 2.4")[1]
        # Stems with see-§5.1 cross-reference
        assert "/ftp/* (see §5.1)" in sec
        assert "/encryptionkeys/* (see §5.1)" in sec
        # Round-shape mermaid syntax for ghost nodes
        assert '(["' in sec

    def test_no_fs_paths_when_no_fs_boundary(self):
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [
                {"id": "api", "name": "API", "paths": ["server.ts"]},
            ],
            "trust_boundaries": [
                {"id": "app", "name": "App Process", "trust_level": "trusted"},
            ],
            "data_flows": [],
            "attack_surface": {
                "unauthenticated": [{"endpoint": "GET /ftp/x", "method": "GET"}],
            },
        }
        md = pf.gen_architecture_diagrams(data)
        sec = md.split("### 2.4")[1]
        assert "/ftp/* (see §5.1)" not in sec


class TestD15EngineAnnotation:
    """G — engine annotation only when not already in component name."""

    def test_engine_appears_when_not_in_name(self):
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [
                {"id": "db", "name": "Order DB", "tier": "data",
                 "engine": "PostgreSQL 15", "paths": ["models/**"]},
            ],
            "data_flows": [],
            "trust_boundaries": [],
        }
        md = pf.gen_architecture_diagrams(data)
        sec = md.split("### 2.2")[1].split("### 2.3")[0]
        assert "Order DB<br/>PostgreSQL 15" in sec

    def test_engine_skipped_when_already_in_name(self):
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [
                {"id": "db", "name": "PostgreSQL 15 Cluster", "tier": "data",
                 "engine": "PostgreSQL 15", "paths": ["models/**"]},
            ],
            "data_flows": [],
            "trust_boundaries": [],
        }
        md = pf.gen_architecture_diagrams(data)
        sec = md.split("### 2.2")[1].split("### 2.3")[0]
        # The name is rendered unchanged; no `<br/>` duplicating the engine.
        assert "PostgreSQL 15 Cluster<br/>PostgreSQL 15" not in sec


class TestD15Legend:
    """J — Legend is emitted once, only when the conventions are used."""

    def test_legend_present_when_flows_exist(self):
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [
                {"id": "a", "name": "A", "paths": ["x"]},
                {"id": "b", "name": "B", "paths": ["y"]},
            ],
            "data_flows": [
                {"from": "a", "to": "b", "protocol": "HTTPS"},
            ],
            "trust_boundaries": [],
        }
        md = pf.gen_architecture_diagrams(data)
        assert "**Legend:**" in md
        assert "synchronous" in md.lower()

    def test_legend_appears_only_once(self):
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [
                {"id": "a", "name": "A", "paths": ["x"]},
                {"id": "b", "name": "B", "paths": ["y"]},
            ],
            "data_flows": [
                {"from": "a", "to": "b", "protocol": "HTTPS"},
            ],
            "trust_boundaries": [],
        }
        md = pf.gen_architecture_diagrams(data)
        assert md.count("**Legend:**") == 1

    def test_legend_omitted_when_no_diagrams_to_explain(self):
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [],
            "data_flows": [],
            "trust_boundaries": [],
        }
        md = pf.gen_architecture_diagrams(data)
        assert "**Legend:**" not in md

    def test_legend_includes_async_when_async_flows_present(self):
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [
                {"id": "a", "name": "A", "paths": ["x"]},
                {"id": "b", "name": "B", "paths": ["y"]},
            ],
            "data_flows": [
                {"from": "a", "to": "b", "protocol": "WebSocket"},
            ],
            "trust_boundaries": [],
        }
        md = pf.gen_architecture_diagrams(data)
        assert "asynchronous" in md.lower()


class TestD15ExternalServicesCategorised:
    """A — meta.external_services[] categorised by direction."""

    def test_inbound_external_renders_with_inbound_edge(self):
        data = {
            "meta": {
                "project": {"name": "x"},
                "external_services": [
                    {"id": "google-sso", "name": "Google SSO",
                     "direction": "inbound", "protocol": "OIDC"},
                ],
            },
            "components": [],
            "trust_boundaries": [],
            "data_flows": [],
            "threats": [],
            "attack_surface": {},
            "security_controls": [],
        }
        md = pf.gen_architecture_diagrams(data)
        sec = md.split("### 2.1")[1].split("### 2.2")[0]
        assert "Google SSO" in sec
        # inbound edge points TO system
        assert "GOOGLE_SSO -->" in sec

    def test_outbound_external_renders_with_outbound_edge(self):
        data = {
            "meta": {
                "project": {"name": "x"},
                "external_services": [
                    {"id": "stripe", "name": "Stripe",
                     "direction": "outbound", "protocol": "HTTPS",
                     "category": "payment"},
                ],
            },
            "components": [],
            "trust_boundaries": [],
            "data_flows": [],
            "threats": [],
            "attack_surface": {},
            "security_controls": [],
        }
        md = pf.gen_architecture_diagrams(data)
        sec = md.split("### 2.1")[1].split("### 2.2")[0]
        assert "Stripe" in sec
        assert "SYSTEM -->|outbound · HTTPS| STRIPE" in sec

    def test_external_db_renders_with_extdb_classDef(self):
        data = {
            "meta": {
                "project": {"name": "x"},
                "external_services": [
                    {"id": "rds", "name": "Order DB (RDS)",
                     "direction": "bidirectional", "protocol": "PostgreSQL",
                     "category": "database"},
                ],
            },
            "components": [],
            "trust_boundaries": [],
            "data_flows": [],
            "threats": [],
            "attack_surface": {},
            "security_controls": [],
        }
        md = pf.gen_architecture_diagrams(data)
        sec = md.split("### 2.1")[1].split("### 2.2")[0]
        assert "Order DB (RDS)" in sec
        assert "class RDS extdb" in sec


class TestD15RuntimeColumn:
    """C — Runtime column in §2.3 Components table (compose-side)."""

    def test_compose_runtime_helpers_exist(self):
        """Compose-level wiring is verified via the threat-model.md
        re-render in tests/test_compose_threat_model.py — here we just
        assert the renderer recognizes the new field by writing it
        through pregenerate (which doesn't produce §2.3, but verifies
        no crash on yamls carrying the new field)."""
        data = {
            "meta": {"project": {"name": "x"}},
            "components": [
                {"id": "api", "name": "API", "paths": ["server.ts"],
                 "runtime": "Node.js 18 · Express 4.x"},
            ],
            "data_flows": [],
            "trust_boundaries": [],
        }
        # Should not crash — pregenerate doesn't render runtime in §2.3 (compose does).
        md = pf.gen_architecture_diagrams(data)
        assert "API" in md


class TestSecurityArchitecture:
    def test_starts_with_correct_heading(self, minimal_yaml_data):
        md = pf.gen_security_architecture(minimal_yaml_data)
        assert md.startswith("## 7. Security Architecture\n")

    def test_has_all_14_subsections(self, minimal_yaml_data):
        md = pf.gen_security_architecture(minimal_yaml_data)
        for n in range(1, 15):
            # Match "### 7.N <title>" — title varies but the prefix is fixed
            assert re.search(rf"^### 7\.{n}\s", md, re.MULTILINE), f"Missing ### 7.{n} sub-section"

    def test_secret_management_marked_cross_cutting(self, minimal_yaml_data):
        md = pf.gen_security_architecture(minimal_yaml_data)
        assert "### 7.13 Secret Management *(cross-cutting)*" in md

    def test_defense_in_depth_marked_cross_cutting(self, minimal_yaml_data):
        md = pf.gen_security_architecture(minimal_yaml_data)
        assert "### 7.14 Defense-in-Depth Assessment *(cross-cutting)*" in md

    def test_iam_subsection_includes_matched_control(self, minimal_yaml_data):
        md = pf.gen_security_architecture(minimal_yaml_data)
        # JWT auth control should land in 7.3 IAM
        iam_section = re.search(r"### 7\.3 .+?(?=### 7\.4 )", md, re.DOTALL)
        assert iam_section is not None
        assert "JWT auth" in iam_section.group(0)

    def test_iam_section_has_per_method_sub_blocks(self, minimal_yaml_data):
        """§7.3 IAM must include `#### 7.3.N <Name> Flow` sub-blocks per
        contract auth_method_decomposition rule. Without these the
        compose --strict pre-render gate hard-fails."""
        md = pf.gen_security_architecture(minimal_yaml_data)
        iam_section = re.search(r"### 7\.3 .+?(?=### 7\.4 )", md, re.DOTALL)
        assert iam_section is not None
        body = iam_section.group(0)
        # At least one #### sub-block (one per IAM control row)
        sub_blocks = re.findall(r"^#### 7\.3\.\d+\s+.+\s+Flow\s*$", body, re.MULTILINE)
        assert len(sub_blocks) >= 1, (
            f"§7.3 must contain at least one '#### 7.3.N <Name> Flow' sub-block; "
            f"found: {sub_blocks!r}"
        )

    def test_iam_section_contains_sequence_diagram(self, minimal_yaml_data):
        """§7.3 IAM must include at least one ```mermaid sequenceDiagram block
        per contract domain_required_patterns rule."""
        md = pf.gen_security_architecture(minimal_yaml_data)
        iam_section = re.search(r"### 7\.3 .+?(?=### 7\.4 )", md, re.DOTALL)
        assert iam_section is not None
        body = iam_section.group(0)
        assert "```mermaid" in body, "§7.3 missing required mermaid block"
        assert "sequenceDiagram" in body, "§7.3 missing required sequenceDiagram"

    def test_iam_sub_blocks_have_required_trailers(self, minimal_yaml_data):
        """Per the auth_method_decomposition rule, each #### sub-block must
        carry **Risk assessment:** and **Findings in this flow:** trailers."""
        md = pf.gen_security_architecture(minimal_yaml_data)
        iam_section = re.search(r"### 7\.3 .+?(?=### 7\.4 )", md, re.DOTALL)
        assert iam_section is not None
        body = iam_section.group(0)
        # Each sub-block needs both trailers
        n_subblocks = len(re.findall(r"^#### 7\.3\.\d+", body, re.MULTILINE))
        assert n_subblocks >= 1
        n_risk = body.count("**Risk assessment:**")
        n_findings = body.count("**Findings in this flow:**")
        assert n_risk >= n_subblocks, (
            f"Each of {n_subblocks} sub-blocks needs **Risk assessment:** trailer; "
            f"found {n_risk}"
        )
        assert n_findings >= n_subblocks, (
            f"Each of {n_subblocks} sub-blocks needs **Findings in this flow:** trailer; "
            f"found {n_findings}"
        )

    def test_iam_with_no_controls_emits_placeholder_subblock(self):
        """M3.1: when there are no IAM controls cataloged, §7.3 still emits
        ONE placeholder ``#### 7.3.1 ... Flow`` block to satisfy the
        sections-contract auth_method_decomposition rule. Without this,
        compose_threat_model.py --strict would hard-fail and force the
        Stage 2 (Composition) LLM to author the §7 fragment from scratch
        (proximate cause of the 2026-04-26 7-min Phase-11 stall)."""
        md = pf.gen_security_architecture({
            "components": [], "security_controls": [],
        })
        iam_section = re.search(r"### 7\.3 .+?(?=### 7\.4 )", md, re.DOTALL)
        assert iam_section is not None
        body = iam_section.group(0)
        # The "no controls cataloged" prose still appears in the table area.
        assert "_No controls cataloged" in body
        # AND a placeholder sub-block must be emitted for the contract gate.
        assert re.search(r"^#### 7\.3\.1\s+.+\s+Flow$", body, re.MULTILINE), (
            "Empty IAM section must still emit one placeholder sub-block "
            "to satisfy the sections-contract auth_method_decomposition rule"
        )
        # And the placeholder block must contain a sequenceDiagram.
        assert "sequenceDiagram" in body


class TestGapSummary:
    """Deterministic Gap-Summary block at top of §7.

    Replaces the historical `<!-- GAP_SUMMARY_PLACEHOLDER -->` LLM slot —
    these tests pin down ordering, grouping, and the regression guard
    that the placeholder is gone.
    """

    @staticmethod
    def _data():
        return {
            "components": [],
            "meta": {},
            "security_controls": [
                # Highest impact: 4 threats (2x Critical, 2x High) = 14
                {"domain": "Input Validation", "control": "Parameterised SQL",
                 "effectiveness": "Missing",
                 "linked_threats": ["T-001", "T-002", "T-017"]},
                {"domain": "input validation", "control": "NoSQL operator allowlist",
                 "effectiveness": "Missing",
                 "linked_threats": ["T-032"]},
                # Mid impact: 3 threats (2x Critical, 1x High) = 11
                {"domain": "Secret Management", "control": "Externalise crypto secrets",
                 "effectiveness": "Missing",
                 "linked_threats": ["T-003", "T-013", "T-018"]},
                # Lower impact: 4 threats (2x High, 2x Medium) = 10
                {"domain": "Output Encoding", "control": "DomSanitizer enforcement",
                 "effectiveness": "Weak",
                 "linked_threats": ["T-022", "T-023", "T-024", "T-025"]},
                # Excluded — Adequate effectiveness must not enter the summary
                {"domain": "Logging", "control": "Structured logs",
                 "effectiveness": "Adequate", "linked_threats": []},
                # Excluded — Weak but no linked threats: cannot meaningfully
                # populate the Linked Threats column
                {"domain": "Configuration", "control": "Security headers",
                 "effectiveness": "Weak", "linked_threats": []},
            ],
            "threats": [
                {"id": "T-001", "risk": "Critical", "title": "SQLi auth bypass",
                 "evidence": [{"file": "routes/login.ts", "line": 34}]},
                {"id": "T-002", "risk": "Critical", "title": "SQLi product search",
                 "evidence": [{"file": "routes/search.ts", "line": 24}]},
                {"id": "T-017", "risk": "High",     "title": "NoSQLi mass update"},
                {"id": "T-032", "risk": "High",     "title": "MarsDB $where"},
                {"id": "T-003", "risk": "Critical", "title": "Hardcoded RSA key",
                 "evidence": [{"file": "lib/insecurity.ts", "line": 23}]},
                {"id": "T-013", "risk": "Critical", "title": "JWT alg:none"},
                {"id": "T-018", "risk": "High",     "title": "JWT key disclosure"},
                {"id": "T-022", "risk": "High",     "title": "Stored XSS product"},
                {"id": "T-023", "risk": "High",     "title": "Reflected XSS search"},
                {"id": "T-024", "risk": "Medium",   "title": "Stored XSS last-IP"},
                {"id": "T-025", "risk": "Medium",   "title": "Stored XSS feedback"},
            ],
        }

    def test_placeholder_is_gone(self):
        """Regression guard: the LLM-authored GAP_SUMMARY_PLACEHOLDER must
        not appear in the rendered scaffold any more — the table is now
        generated deterministically."""
        md = pf.gen_security_architecture(self._data())
        assert "GAP_SUMMARY_PLACEHOLDER" not in md

    def test_emits_three_rows_in_severity_order(self):
        """Highest cumulative severity comes first; ordering is stable."""
        md = pf.gen_security_architecture(self._data())
        gap_section = md.split("**Gap summary**", 1)[1].split("### 7.1", 1)[0]
        idx_input  = gap_section.find("Input Validation —")
        idx_secret = gap_section.find("Secret Management —")
        idx_output = gap_section.find("Output Encoding —")
        assert -1 < idx_input < idx_secret < idx_output

    def test_groups_same_domain_under_primary_control(self):
        """Two Missing controls in 'Input Validation' must collapse into one
        row with the highest-impact control as the title and a `(+ N related)`
        annotation. Domain comparison is case-insensitive so the second
        control's lower-cased domain still groups."""
        md = pf.gen_security_architecture(self._data())
        assert "Input Validation — Parameterised SQL *(+ 1 related)*" in md
        # Three data rows total — the second InputValidation control is folded
        # in. Count by looking for the leading-cell domain text only (excludes
        # the header row `| Gap | …` and the `|---|` separator).
        gap_section = md.split("**Gap summary**", 1)[1].split("### 7.1", 1)[0]
        data_rows = [ln for ln in gap_section.splitlines()
                     if ln.startswith(("| Input ", "| Secret ", "| Output "))]
        assert len(data_rows) == 3

    def test_threat_links_use_lowercase_anchor_and_label(self):
        """Format: `[T-NNN](#t-nnn) — <title>` — same convention as §4/§5."""
        md = pf.gen_security_architecture(self._data())
        assert "[T-001](#t-001) — SQLi auth bypass" in md
        assert "[T-018](#t-018) — JWT key disclosure" in md

    def test_threats_inside_cell_sorted_by_severity(self):
        """Within Secret Management: T-003 (Critical) and T-013 (Critical)
        must precede T-018 (High)."""
        md = pf.gen_security_architecture(self._data())
        secret_row = next(
            ln for ln in md.splitlines() if "Secret Management —" in ln
        )
        i003 = secret_row.find("T-003")
        i013 = secret_row.find("T-013")
        i018 = secret_row.find("T-018")
        assert i003 != -1 and i013 != -1 and i018 != -1
        assert max(i003, i013) < i018

    def test_evidence_cell_dedupes_and_caps(self):
        """Evidence column collects file:line from threats in the bucket,
        deduped, capped at 3."""
        md = pf.gen_security_architecture(self._data())
        input_row = next(
            ln for ln in md.splitlines() if "Input Validation —" in ln
        )
        assert "`routes/login.ts:34`" in input_row
        assert "`routes/search.ts:24`" in input_row

    def test_excludes_adequate_and_unlinked_controls(self):
        """Adequate-effectiveness controls and weak/missing controls without
        any linked_threats must NOT appear in the gap summary."""
        md = pf.gen_security_architecture(self._data())
        gap_section = md.split("**Gap summary**", 1)[1].split("### 7.1", 1)[0]
        assert "Logging" not in gap_section
        assert "Configuration" not in gap_section

    def test_block_omitted_when_no_weak_controls(self):
        """No weak/missing controls ⇒ the Gap-Summary block (intro line +
        table) is suppressed entirely. The §7.1 header still appears."""
        data = {"components": [], "meta": {}, "threats": [],
                "security_controls": [
                    {"domain": "Logging", "control": "Logs",
                     "effectiveness": "Adequate"},
                ]}
        md = pf.gen_security_architecture(data)
        assert "**Gap summary**" not in md
        assert "### 7.1 Overview" in md

    def test_block_omitted_when_weak_controls_have_no_threats(self):
        """Weak controls with empty linked_threats are excluded — if every
        weak control has no threats, the block is suppressed."""
        data = {"components": [], "meta": {}, "threats": [],
                "security_controls": [
                    {"domain": "Configuration", "control": "Headers",
                     "effectiveness": "Weak", "linked_threats": []},
                ]}
        md = pf.gen_security_architecture(data)
        assert "**Gap summary**" not in md

    def test_top_k_cap(self):
        """More than 3 distinct domains ⇒ only the top 3 by cumulative
        severity appear; the rest are dropped."""
        data = {
            "components": [], "meta": {},
            "threats": [
                {"id": f"T-00{i}", "risk": "Critical", "title": f"t{i}"}
                for i in range(1, 6)
            ],
            "security_controls": [
                {"domain": f"Dom{i}", "control": f"Ctl{i}",
                 "effectiveness": "Missing",
                 "linked_threats": [f"T-00{i}"]}
                for i in range(1, 6)
            ],
        }
        md = pf.gen_security_architecture(data)
        gap_section = md.split("**Gap summary**", 1)[1].split("### 7.1", 1)[0]
        # 3 data rows under the header; check by counting "| Dom" prefixes.
        assert sum(1 for ln in gap_section.splitlines()
                   if ln.startswith("| Dom")) == 3


class TestOutOfScope:
    def test_starts_with_correct_heading(self, minimal_yaml_data):
        md = pf.gen_out_of_scope(minimal_yaml_data)
        assert md.startswith("## 10. Out of Scope\n")

    def test_uses_meta_scope_when_present(self, minimal_yaml_data):
        md = pf.gen_out_of_scope(minimal_yaml_data)
        assert "DNS infra" in md
        assert "End-user devices" in md

    def test_falls_back_to_default_when_meta_empty(self):
        md = pf.gen_out_of_scope({"meta": {}})
        assert md.startswith("## 10. Out of Scope\n")
        assert "Third-party hosted dependencies" in md  # default


# ---------------------------------------------------------------------------
# Tier classification (helper used by §2 + §7)
# ---------------------------------------------------------------------------

class TestTierClassification:
    @pytest.mark.parametrize("comp,expected", [
        ({"id": "frontend-spa", "name": "Angular Frontend", "paths": []}, "client"),
        ({"id": "nosql-data-layer", "name": "Mongo", "paths": []}, "data"),
        ({"id": "auth-module", "name": "Auth", "paths": []}, "application"),
        ({"id": "rest-api", "name": "API", "paths": []}, "application"),
        ({"id": "db-store", "name": "Postgres", "paths": []}, "data"),
        ({"id": "ui-component", "name": "Browser UI", "paths": []}, "client"),
    ])
    def test_classify_tier(self, comp, expected):
        assert pf._classify_tier(comp) == expected


# ---------------------------------------------------------------------------
# CLI driver behaviour
# ---------------------------------------------------------------------------

def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


class TestCli:
    def test_writes_all_six_fragments(self, output_dir):
        result = _run_cli(str(output_dir))
        assert result.returncode == 0, f"stderr={result.stderr}"
        frag_dir = output_dir / ".fragments"
        assert frag_dir.is_dir()
        for name in pf.GENERATORS:
            assert (frag_dir / name).is_file(), f"{name} not written"

    def test_idempotent_skips_existing(self, output_dir):
        # First run writes all 6 (use_cases retired 2026-05).
        _run_cli(str(output_dir))
        # Second run should skip all
        result = _run_cli(str(output_dir))
        assert result.returncode == 0
        assert "skipped 6" in result.stdout

    def test_force_overwrites(self, output_dir):
        _run_cli(str(output_dir))
        # Mutate a file
        target = output_dir / ".fragments" / "system-overview.md"
        target.write_text("MUTATED\n")
        # --force should overwrite
        result = _run_cli(str(output_dir), "--force")
        assert result.returncode == 0
        assert "wrote 6" in result.stdout
        assert "MUTATED" not in target.read_text()

    def test_only_filters(self, output_dir):
        result = _run_cli(str(output_dir), "--only", "assets.md,out-of-scope.md")
        assert result.returncode == 0
        frag_dir = output_dir / ".fragments"
        assert (frag_dir / "assets.md").is_file()
        assert (frag_dir / "out-of-scope.md").is_file()
        assert not (frag_dir / "system-overview.md").exists()

    def test_only_rejects_unknown(self, output_dir):
        result = _run_cli(str(output_dir), "--only", "bogus.md")
        assert result.returncode == 2
        assert "unknown fragment name" in result.stderr

    def test_dry_run_writes_nothing(self, output_dir):
        result = _run_cli(str(output_dir), "--dry-run")
        assert result.returncode == 0
        # Files NOT created on disk
        frag_dir = output_dir / ".fragments"
        for name in pf.GENERATORS:
            assert not (frag_dir / name).exists()

    def test_missing_yaml_exits_one(self, tmp_path):
        out = tmp_path / "empty"
        out.mkdir()
        result = _run_cli(str(out))
        assert result.returncode == 1
        assert "threat-model.yaml not found" in result.stderr

    def test_missing_output_dir_exits_two(self, tmp_path):
        nope = tmp_path / "does-not-exist"
        result = _run_cli(str(nope))
        assert result.returncode == 2

    def test_lock_step_with_check_inline_shortcut(self, output_dir):
        """Pre-gen + check_inline_shortcut: after pre-gen, the only
        remaining issues should be ms-verdict.json + ms-architecture-
        assessment.json missing (LLM fragments) and threats-merged /
        triage-flags missing (Phase 9/10b outputs). Pre-gen alone is NOT
        sufficient to make the gate pass."""
        # Simulate inline-shortcut state: threat-model.md present, but
        # neither fragments nor merge outputs.
        (output_dir / "threat-model.md").write_text("# inline-authored\n")
        # Run pre-gen
        _run_cli(str(output_dir))
        # Hard gate must still trip on the 2 LLM fragments + Phase-9/10b artifacts
        gate = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "check_inline_shortcut.py"),
             str(output_dir)],
            capture_output=True, text=True,
        )
        assert gate.returncode == 2
        # Specifically: the structural fragments should NOT be in the issue list
        for structural in pf.GENERATORS:
            assert f".fragments/{structural}" not in gate.stderr, (
                f"{structural} should have been generated, but gate still complains"
            )
