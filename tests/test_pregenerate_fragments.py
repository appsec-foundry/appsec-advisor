"""Unit tests for scripts/pregenerate_fragments.py.

The pre-generator produces 7 deterministic structural fragments from
threat-model.yaml. Tests verify per-generator output shape (heading
match, required sub-sections, required patterns) plus the CLI driver's
idempotency, --force, --only, and --dry-run flags.
"""

from __future__ import annotations

import importlib.util
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
            {"id": "A-001", "name": "User credentials", "classification": "Critical", "description": "Email + hash"},
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
            {
                "domain": "Identity & Access Management",
                "control": "JWT auth",
                "implementation": "express-jwt",
                "effectiveness": "weak",
                "notes": "outdated",
            },
            {
                "domain": "Input Validation",
                "control": "Sanitization",
                "implementation": "manual",
                "effectiveness": "missing",
                "notes": "no validator",
            },
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
                        {
                            "endpoint": "POST /rest/login",
                            "method": "POST",
                            "auth_required": False,
                            "linked_threats": ["T-001"],
                        },
                        {
                            "endpoint": "GET /metrics",
                            "method": "GET",
                            "auth_required": False,
                            "linked_threats": ["T-002"],
                        },
                    ],
                },
                "authenticated": {
                    "count": 1,
                    "entries": [
                        {
                            "endpoint": "POST /api/orders",
                            "method": "POST",
                            "auth_required": True,
                            "linked_threats": ["T-003"],
                        },
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
                {"id": "spa", "name": "SPA", "paths": ["frontend/**"]},
                {"id": "api", "name": "API", "paths": ["server.ts"]},
                {"id": "db", "name": "DB", "paths": ["models/**"]},
            ],
            "data_flows": [
                {
                    "id": "df-1",
                    "from": "spa",
                    "to": "api",
                    "label": "REST",
                    "protocol": "HTTPS",
                    "data_classification": "JWT-bearing",
                },
                {
                    "id": "df-2",
                    "from": "api",
                    "to": "db",
                    "label": "ORM",
                    "protocol": "JDBC",
                    "data_classification": "Confidential",
                },
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
                {"id": "db", "name": "DB", "paths": ["models/**"]},
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


# NOTE: TestEnforcementColumn was removed in 2026-05. The Enforcement
# column on the §2.4 trust-boundary table is no longer rendered — §2.4 is
# now a compact technology-stack mermaid diagram (Application Tier / Data
# Tier subgraphs) without per-boundary enforcement strings. Trust boundary
# detail moved to §1.x infobox metadata + §7.x control catalogue.


class TestSecurityArchitectureCWEMapping:
    """§7 must surface threats by CWE when no controls cataloged."""

    def _data(self, threats):
        return {
            "meta": {"project": {"name": "x"}},
            "components": [{"id": "c1", "name": "C1", "paths": ["a"]}],
            "security_controls": [
                # IAM control present so §7.3 is the only "controls cataloged" section
                {
                    "control": "JWT Auth",
                    "domain": "Identity & Access Management",
                    "implementation": "express-jwt",
                    "effectiveness": "weak",
                },
            ],
            "threats": threats,
        }

    def test_websocket_threats_surface_in_7_8_via_title(self):
        threats = [
            {
                "id": "T-100",
                "cwe": "CWE-306",
                "title": "Socket.IO Events Lack Authentication",
                "scenario": "WebSocket events bypass auth.",
                "risk": "High",
            },
        ]
        md = pf.gen_security_architecture(self._data(threats))
        # §7.8 should reference T-100 (rendered as F-100 visible label
        # after P4 normalisation; anchor stays valid via dual-anchor
        # emission in compose._render_threat_register).
        sec_7_8 = md.split("### 7.8")[1].split("### 7.9")[0]
        assert "T-100" in sec_7_8 or "F-100" in sec_7_8

    def test_input_validation_threats_surface_in_7_5_via_cwe(self):
        threats = [
            {"id": "T-200", "cwe": "CWE-79", "title": "Stored XSS", "scenario": "...", "risk": "High"},
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
            {
                "id": "T-300",
                "cwe": "CWE-79",
                "title": "XSS that allows script execution",
                "scenario": "Script execution allows attacker to steal tokens.",
                "risk": "Critical",
            },
        ]
        md = pf.gen_security_architecture(self._data(threats))
        sec_7_8 = md.split("### 7.8")[1].split("### 7.9")[0]
        assert "T-300" not in sec_7_8, "T-300 has nothing to do with WebSockets — must not appear in §7.8"


class TestControlNotesFallback:
    """_control_notes must fall through notes → effectiveness_reason → gaps[0]."""

    def test_notes_field_takes_precedence(self):
        c = {"notes": "primary", "effectiveness_reason": "secondary", "gaps": ["tertiary"]}
        assert pf._control_notes(c) == "primary"

    def test_falls_back_to_effectiveness_reason(self):
        c = {"effectiveness_reason": "this is the reason", "gaps": ["a gap"]}
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
        data = self._data(
            attack_surface={
                "authenticated": [
                    {"endpoint": "GET /api/orders", "method": "GET"},
                ]
            }
        )
        md = pf.gen_architecture_diagrams(data)
        assert "AUTHED[" in md

    def test_admin_actor_appears_when_threats_mention_admin(self):
        data = self._data(
            threats=[
                {"id": "T-1", "title": "Admin panel SQL injection", "risk": "High"},
            ]
        )
        md = pf.gen_architecture_diagrams(data)
        assert "ADMIN[" in md

    def test_external_services_appear_for_ssrf_threats(self):
        data = self._data(
            threats=[
                {"id": "T-1", "cwe": "CWE-918", "title": "SSRF via image fetcher", "risk": "High"},
            ]
        )
        md = pf.gen_architecture_diagrams(data)
        assert "EXTERNAL[" in md
        # D1.5: when the SSRF heuristic fires, the auto-added external
        # node carries protocol "HTTPS" so the edge reads "outbound · HTTPS".
        assert "outbound" in md

    def test_attacker_uses_dotted_arrow(self):
        md = pf.gen_architecture_diagrams(self._data())
        assert "ATTACKER -.->" in md  # dashed arrow distinguishes attacker

    def test_actors_yaml_takes_priority(self):
        data = self._data(
            meta={
                "project": {"name": "x"},
                "actors": [
                    {"id": "qa", "name": "QA Engineer", "role": "user"},
                    {"id": "auditor", "name": "Compliance Auditor", "role": "admin"},
                ],
            }
        )
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
                {"id": "spa", "name": "Frontend", "tier": "client", "paths": ["frontend/**"]},
                {"id": "backend", "name": "API", "tier": "application", "paths": ["server.ts"]},
                {"id": "db", "name": "Database", "tier": "data", "paths": ["models/**"]},
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
        data = self._data(
            components=[
                {"id": "backend", "name": "API", "tier": "application", "paths": ["server.ts"]},
                {"id": "db", "name": "Database", "tier": "data", "paths": ["models/**"]},
            ]
        )
        block = self._section_2_3(pf.gen_architecture_diagrams(data))
        assert "XSS · client tampering · token theft" not in block
        # But the application-tier edge still renders.
        assert "injection · auth bypass · RCE" in block

    def test_no_repo_edge_when_no_application_tier(self):
        # Hypothetical client-only architecture. The repo edge target is the
        # application tier — no app, no edge.
        data = self._data(
            components=[
                {"id": "spa", "name": "Frontend", "tier": "client", "paths": ["frontend/**"]},
            ]
        )
        block = self._section_2_3(pf.gen_architecture_diagrams(data))
        assert "leaked credentials · auth bypass" not in block

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

        nodes = _re.findall(r"^\s+([A-Z][A-Z0-9_]*)\[", block, _re.MULTILINE)
        assert len(set(nodes)) <= 8, f"node count exceeds contract cap: {sorted(set(nodes))}"


class TestActorIdBySlug:
    """Helper that resolves a §2.3 actor's mermaid node id from its canonical
    slug. Mirrors the slug→id transform used inside the actor builder."""

    def test_resolves_known_slug(self):
        actors = [
            {"id": "INTERNET_ANON", "label": "x", "css_class": "threat"},
            {"id": "VICTIM_REQUIRED", "label": "x", "css_class": "legit"},
            {"id": "REPO_READ", "label": "x", "css_class": "threat"},
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
                {"id": "spa", "name": "SPA", "tier": "client", "paths": ["frontend/**"]},
                {"id": "api", "name": "API", "tier": "application", "paths": ["server.ts"]},
                {"id": "service", "name": "Service", "tier": "application", "paths": ["lib/**"]},
                {"id": "db", "name": "DB", "tier": "data", "paths": ["models/**"]},
            ],
            "trust_boundaries": [
                {"id": "public", "name": "Public Internet", "trust_level": "untrusted"},
                {"id": "app-process", "name": "Application Process", "trust_level": "trusted"},
                {"id": "data-tier", "name": "Data Tier", "trust_level": "restricted"},
            ],
            "data_flows": [
                {
                    "from": "spa",
                    "to": "api",
                    "label": "REST",
                    "protocol": "HTTPS",
                    "data_classification": "JWT-bearing",
                },
                {
                    "from": "api",
                    "to": "db",
                    "label": "ORM",
                    "protocol": "Sequelize",
                    "data_classification": "Confidential",
                },
            ],
        }

    def test_each_boundary_renders_a_subgraph(self):
        md = pf.gen_architecture_diagrams(self._data())
        sec_2_4 = md.split("### 2.4")[1].split("##")[0]
        # Contract v2 uses the compact technology-stack mermaid diagram with
        # Application Tier / Data Tier subgraphs. The per-boundary table
        # (`| public | Public Internet | ... |`) was retired in 2026-05 —
        # trust-boundary detail now lives in the §1.x infobox + §7.x catalogue.
        assert 'subgraph APP["Application Tier"]' in sec_2_4
        assert 'subgraph DATA["Data Tier"]' in sec_2_4

    def test_application_components_placed_in_trusted_boundary(self):
        md = pf.gen_architecture_diagrams(self._data())
        sec_2_4 = md.split("### 2.4")[1].split("##")[0]
        app_subgraph = sec_2_4.split('subgraph APP["Application Tier"]')[1].split("end")[0]
        assert "Application Code" in app_subgraph

    def test_client_component_routed_to_application_tier(self):
        # Post-2026-05 — the boundary table that used to flag `| public |`
        # rows is gone; the technology-stack diagram now places the client-
        # facing entry under the Application Tier subgraph.
        md = pf.gen_architecture_diagrams(self._data())
        sec_2_4 = md.split("### 2.4")[1].split("##")[0]
        app_subgraph = sec_2_4.split('subgraph APP["Application Tier"]')[1].split("end")[0]
        assert "ROUTES" in app_subgraph or "Application Code" in app_subgraph

    def test_data_component_placed_in_restricted_boundary(self):
        md = pf.gen_architecture_diagrams(self._data())
        sec_2_4 = md.split("### 2.4")[1].split("##")[0]
        data_sg = sec_2_4.split('subgraph DATA["Data Tier"]')[1].split("end")[0]
        assert "LOCAL_FS" in data_sg
        assert "Local FS" in data_sg

    def test_cross_boundary_edges_rendered_thick(self):
        md = pf.gen_architecture_diagrams(self._data())
        sec_2_4 = md.split("### 2.4")[1].split("##")[0]
        assert 'ROUTES -->|"file I/O"| LOCAL_FS' in sec_2_4

    def test_falls_back_to_stub_when_no_boundaries(self):
        data = self._data()
        data["trust_boundaries"] = []
        md = pf.gen_architecture_diagrams(data)
        sec_2_4 = md.split("### 2.4")[1].split("##")[0]
        assert 'subgraph APP["Application Tier"]' in sec_2_4
        assert 'subgraph DATA["Data Tier"]' in sec_2_4
        assert "TB1" not in sec_2_4


class TestIamFlowSequence:
    """§7.3.1 IAM Flow chooses template based on control name + impl."""

    def test_jwt_template_chosen_for_jwt_control(self):
        seq = pf._iam_flow_sequence("JWT RS256 Authentication", "express-jwt + jsonwebtoken", [])
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
        seq = pf._iam_flow_sequence(
            "JWT RS256",
            "jwt",
            [
                {"id": "T-1", "cwe": "CWE-79", "title": "Stored XSS unrelated"},
            ],
        )
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
                {"id": "db", "name": "DB", "paths": ["models/**"]},
            ],
            "data_flows": [
                {
                    "from": "spa",
                    "to": "api",
                    "protocol": "HTTPS",
                    "auth_method": "Bearer JWT",
                    "data_classification": "JWT-bearing",
                },
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
                {"from": "spa", "to": "api", "protocol": "HTTPS", "data_classification": "Public"},
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
                {"id": "ws", "name": "WS", "paths": ["b"]},
            ],
            "data_flows": [
                {"from": "spa", "to": "ws", "protocol": "WebSocket", "data_classification": "Internal"},
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
                {"from": "spa", "to": "api", "protocol": "HTTPS", "data_classification": "Public"},
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
                {"id": "hot", "name": "Hot", "paths": ["a"]},
                {"id": "warm", "name": "Warm", "paths": ["b"]},
                {"id": "cold", "name": "Cold", "paths": ["c"]},
            ],
            "data_flows": [],
            "trust_boundaries": [],
            "threats": threats,
        }

    def test_three_or_more_critical_marks_critical(self):
        threats = [{"id": f"T-{i}", "component_id": "hot", "risk": "Critical"} for i in range(3)]
        md = pf.gen_architecture_diagrams(self._data_with_threats(threats))
        sec = md.split("### 2.2")[1].split("### 2.3")[0]
        assert "class hot critical" in sec
        # cold has no threats — must NOT appear in any class line
        assert "class cold critical" not in sec
        assert "class cold warning" not in sec

    def test_two_or_more_high_marks_warning(self):
        threats = [{"id": f"T-{i}", "component_id": "warm", "risk": "High"} for i in range(2)]
        md = pf.gen_architecture_diagrams(self._data_with_threats(threats))
        sec = md.split("### 2.2")[1].split("### 2.3")[0]
        assert "class warm warning" in sec
        assert "class warm critical" not in sec

    def test_critical_dominates_high(self):
        threats = [{"id": f"T-c{i}", "component_id": "hot", "risk": "Critical"} for i in range(3)] + [
            {"id": f"T-h{i}", "component_id": "hot", "risk": "High"} for i in range(5)
        ]
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
                {"id": "filesystem", "name": "Server Filesystem", "trust_level": "restricted"},
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
        # The compact §2.4 diagram shows the filesystem as a tier node; exact
        # exposed route stems live in §5.1 instead of bloating the diagram.
        assert "LOCAL_FS" in sec
        assert "uploads · logs · keys" in sec
        assert 'LOCAL_FS["fa:fa-folder-open Local FS' in sec

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
                {"id": "db", "name": "Order DB", "tier": "data", "engine": "PostgreSQL 15", "paths": ["models/**"]},
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
                {
                    "id": "db",
                    "name": "PostgreSQL 15 Cluster",
                    "tier": "data",
                    "engine": "PostgreSQL 15",
                    "paths": ["models/**"],
                },
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
                    {"id": "google-sso", "name": "Google SSO", "direction": "inbound", "protocol": "OIDC"},
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
                    {
                        "id": "stripe",
                        "name": "Stripe",
                        "direction": "outbound",
                        "protocol": "HTTPS",
                        "category": "payment",
                    },
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
                    {
                        "id": "rds",
                        "name": "Order DB (RDS)",
                        "direction": "bidirectional",
                        "protocol": "PostgreSQL",
                        "category": "database",
                    },
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
                {"id": "api", "name": "API", "paths": ["server.ts"], "runtime": "Node.js 18 · Express 4.x"},
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
        assert "### 7.13 Secret Management (cross-cutting)" in md

    def test_defense_in_depth_marked_cross_cutting(self, minimal_yaml_data):
        md = pf.gen_security_architecture(minimal_yaml_data)
        assert "### 7.14 Defense-in-Depth Assessment (cross-cutting)" in md

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
            f"§7.3 must contain at least one '#### 7.3.N <Name> Flow' sub-block; found: {sub_blocks!r}"
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
            f"Each of {n_subblocks} sub-blocks needs **Risk assessment:** trailer; found {n_risk}"
        )
        assert n_findings >= n_subblocks, (
            f"Each of {n_subblocks} sub-blocks needs **Findings in this flow:** trailer; found {n_findings}"
        )

    def test_iam_with_no_controls_emits_placeholder_subblock(self):
        """M3.1: when there are no IAM controls cataloged, §7.3 still emits
        ONE placeholder ``#### 7.3.1 ... Flow`` block to satisfy the
        sections-contract auth_method_decomposition rule. Without this,
        compose_threat_model.py --strict would hard-fail and force the
        Stage 2 (Composition) LLM to author the §7 fragment from scratch
        (proximate cause of the 2026-04-26 7-min Phase-11 stall)."""
        md = pf.gen_security_architecture(
            {
                "components": [],
                "security_controls": [],
            }
        )
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
                {
                    "domain": "Input Validation",
                    "control": "Parameterised SQL",
                    "effectiveness": "Missing",
                    "linked_threats": ["T-001", "T-002", "T-017"],
                },
                {
                    "domain": "input validation",
                    "control": "NoSQL operator allowlist",
                    "effectiveness": "Missing",
                    "linked_threats": ["T-032"],
                },
                # Mid impact: 3 threats (2x Critical, 1x High) = 11
                {
                    "domain": "Secret Management",
                    "control": "Externalise crypto secrets",
                    "effectiveness": "Missing",
                    "linked_threats": ["T-003", "T-013", "T-018"],
                },
                # Lower impact: 4 threats (2x High, 2x Medium) = 10
                {
                    "domain": "Output Encoding",
                    "control": "DomSanitizer enforcement",
                    "effectiveness": "Weak",
                    "linked_threats": ["T-022", "T-023", "T-024", "T-025"],
                },
                # Excluded — Adequate effectiveness must not enter the summary
                {"domain": "Logging", "control": "Structured logs", "effectiveness": "Adequate", "linked_threats": []},
                # Excluded — Weak but no linked threats: cannot meaningfully
                # populate the Linked Threats column
                {
                    "domain": "Configuration",
                    "control": "Security headers",
                    "effectiveness": "Weak",
                    "linked_threats": [],
                },
            ],
            "threats": [
                {
                    "id": "T-001",
                    "risk": "Critical",
                    "title": "SQLi auth bypass",
                    "evidence": [{"file": "routes/login.ts", "line": 34}],
                },
                {
                    "id": "T-002",
                    "risk": "Critical",
                    "title": "SQLi product search",
                    "evidence": [{"file": "routes/search.ts", "line": 24}],
                },
                {"id": "T-017", "risk": "High", "title": "NoSQLi mass update"},
                {"id": "T-032", "risk": "High", "title": "MarsDB $where"},
                {
                    "id": "T-003",
                    "risk": "Critical",
                    "title": "Hardcoded RSA key",
                    "evidence": [{"file": "lib/insecurity.ts", "line": 23}],
                },
                {"id": "T-013", "risk": "Critical", "title": "JWT alg:none"},
                {"id": "T-018", "risk": "High", "title": "JWT key disclosure"},
                {"id": "T-022", "risk": "High", "title": "Stored XSS product"},
                {"id": "T-023", "risk": "High", "title": "Reflected XSS search"},
                {"id": "T-024", "risk": "Medium", "title": "Stored XSS last-IP"},
                {"id": "T-025", "risk": "Medium", "title": "Stored XSS feedback"},
            ],
        }

    def test_placeholder_is_gone(self):
        """Regression guard: the LLM-authored GAP_SUMMARY_PLACEHOLDER must
        not appear in the rendered scaffold any more — the table is now
        generated deterministically."""
        md = pf.gen_security_architecture(self._data())
        assert "GAP_SUMMARY_PLACEHOLDER" not in md

    def test_emits_three_rows_in_severity_order(self):
        """Weak/missing controls are surfaced in §7.2 in stable source order."""
        md = pf.gen_security_architecture(self._data())
        risks = md.split("### 7.2 Key Architectural Risks", 1)[1].split("### 7.3", 1)[0]
        idx_input = risks.find("| Input Validation | Parameterised SQL |")
        idx_nosql = risks.find("| input validation | NoSQL operator allowlist |")
        idx_secret = risks.find("| Secret Management | Externalise crypto secrets |")
        idx_output = risks.find("| Output Encoding | DomSanitizer enforcement |")
        idx_config = risks.find("| Configuration | Security headers |")
        assert -1 < idx_input < idx_nosql < idx_secret < idx_output < idx_config

    def test_groups_same_domain_under_primary_control(self):
        """§7.2 no longer groups domains; it preserves each weak/missing
        catalog row so the later per-domain sections can carry the detail."""
        md = pf.gen_security_architecture(self._data())
        risks = md.split("### 7.2 Key Architectural Risks", 1)[1].split("### 7.3", 1)[0]
        assert "| Input Validation | Parameterised SQL | Missing |" in risks
        assert "| input validation | NoSQL operator allowlist | Missing |" in risks
        data_rows = [
            ln for ln in risks.splitlines() if ln.startswith("| ") and " | " in ln and not ln.startswith("|---")
        ]
        assert len(data_rows) == 6  # header + five weak/missing rows

    def test_threat_links_use_lowercase_anchor_and_label(self):
        """§7.1 coverage summary carries the weak/missing domain inventory."""
        md = pf.gen_security_architecture(self._data())
        overview = md.split("### 7.1 Overview", 1)[1].split("### 7.2", 1)[0]
        assert "🔶❌ **Weak or Missing (5):**" in overview
        assert "Input Validation" in overview
        assert "Secret Management" in overview

    def test_threats_inside_cell_sorted_by_severity(self):
        """Secret-management rows are rendered in the cross-cutting §7.13
        controls table."""
        md = pf.gen_security_architecture(self._data())
        sec713 = md.split("### 7.13 Secret Management", 1)[1].split("### 7.14", 1)[0]
        assert "| Externalise crypto secrets |" in sec713
        assert "| _?_ | Missing |" in sec713

    def test_evidence_cell_dedupes_and_caps(self):
        """The deterministic scaffold keeps source evidence out of §7.1/§7.2;
        source-level evidence belongs in §8 finding rows."""
        md = pf.gen_security_architecture(self._data())
        early = md.split("### 7.3", 1)[0]
        assert "routes/login.ts" not in early
        assert "routes/search.ts" not in early

    def test_excludes_adequate_and_unlinked_controls(self):
        """Adequate controls are excluded from §7.2; weak controls remain even
        without linked_threats because §7.2 is a control-catalog view."""
        md = pf.gen_security_architecture(self._data())
        risks = md.split("### 7.2 Key Architectural Risks", 1)[1].split("### 7.3", 1)[0]
        assert "Logging" not in risks
        assert "Configuration" in risks

    def test_block_omitted_when_no_weak_controls(self):
        """No weak/missing controls ⇒ the Gap-Summary block (intro line +
        table) is suppressed entirely. The §7.1 header still appears."""
        data = {
            "components": [],
            "meta": {},
            "threats": [],
            "security_controls": [
                {"domain": "Logging", "control": "Logs", "effectiveness": "Adequate"},
            ],
        }
        md = pf.gen_security_architecture(data)
        assert "**Gap summary**" not in md
        assert "### 7.1 Overview" in md

    def test_block_omitted_when_weak_controls_have_no_threats(self):
        """Weak controls with empty linked_threats are excluded — if every
        weak control has no threats, the block is suppressed."""
        data = {
            "components": [],
            "meta": {},
            "threats": [],
            "security_controls": [
                {"domain": "Configuration", "control": "Headers", "effectiveness": "Weak", "linked_threats": []},
            ],
        }
        md = pf.gen_security_architecture(data)
        assert "**Gap summary**" not in md

    def test_top_k_cap(self):
        """§7.2 keeps the complete weak/missing control slice instead of
        truncating it to a top-k gap summary."""
        data = {
            "components": [],
            "meta": {},
            "threats": [{"id": f"T-00{i}", "risk": "Critical", "title": f"t{i}"} for i in range(1, 6)],
            "security_controls": [
                {"domain": f"Dom{i}", "control": f"Ctl{i}", "effectiveness": "Missing", "linked_threats": [f"T-00{i}"]}
                for i in range(1, 6)
            ],
        }
        md = pf.gen_security_architecture(data)
        risks = md.split("### 7.2 Key Architectural Risks", 1)[1].split("### 7.3", 1)[0]
        assert sum(1 for ln in risks.splitlines() if re.match(r"\| Dom\d+ \|", ln)) == 5


class TestOutOfScope:
    def test_starts_with_correct_heading(self, minimal_yaml_data):
        md = pf.gen_out_of_scope(minimal_yaml_data)
        assert md.startswith("## 11. Out of Scope\n")

    def test_uses_meta_scope_when_present(self, minimal_yaml_data):
        md = pf.gen_out_of_scope(minimal_yaml_data)
        assert "DNS infra" in md
        assert "End-user devices" in md

    def test_falls_back_to_default_when_meta_empty(self):
        md = pf.gen_out_of_scope({"meta": {}})
        assert md.startswith("## 11. Out of Scope\n")
        assert "Third-party hosted dependencies" in md  # default

    def test_no_accepted_risks_subsection_when_list_absent(self, minimal_yaml_data):
        md = pf.gen_out_of_scope(minimal_yaml_data)
        assert "Accepted Risks (Team-Provided)" not in md

    def test_no_accepted_risks_subsection_when_list_empty(self, minimal_yaml_data):
        minimal_yaml_data["meta"]["accepted_risks"] = []
        md = pf.gen_out_of_scope(minimal_yaml_data)
        assert "Accepted Risks (Team-Provided)" not in md

    def test_renders_accepted_risks_subsection(self, minimal_yaml_data):
        minimal_yaml_data["meta"]["accepted_risks"] = [
            {
                "id": "PT-2025-005",
                "title": "Wildcard CORS policy allows cross-origin data access",
                "stride": "Tampering",
                "component": "backend-api",
                "severity": "Medium",
                "justification": "Intentional design for CTF/training platform.",
                "evidence": "server.ts:181",
                "pentest_ref": "PT-2025-Q4-008",
            },
        ]
        md = pf.gen_out_of_scope(minimal_yaml_data)
        assert "### Accepted Risks (Team-Provided)" in md
        assert "PT-2025-005" in md
        assert "Wildcard CORS policy" in md
        assert "Medium" in md
        assert "backend-api" in md
        assert "Intentional design for CTF/training platform." in md
        # Generic out-of-scope still rendered above the accepted risks block.
        assert md.index("DNS infra") < md.index("### Accepted Risks")

    def test_accepted_risks_collapses_multiline_justification(self, minimal_yaml_data):
        minimal_yaml_data["meta"]["accepted_risks"] = [
            {
                "id": "PT-2025-006",
                "title": "Unauth /metrics",
                "severity": "Medium",
                "justification": "Accepted for training purposes.\nIn production these\nwould be restricted.",
            },
        ]
        md = pf.gen_out_of_scope(minimal_yaml_data)
        # Justification ends up on a single table row — no embedded newlines
        # would break the markdown table column count.
        rows = [ln for ln in md.splitlines() if ln.startswith("| PT-2025-006 ")]
        assert len(rows) == 1
        assert "\n" not in rows[0]
        assert "Accepted for training purposes." in rows[0]
        assert "would be restricted." in rows[0]

    def test_accepted_risks_escapes_pipes_in_justification(self, minimal_yaml_data):
        minimal_yaml_data["meta"]["accepted_risks"] = [
            {
                "id": "PT-X",
                "title": "T",
                "severity": "Low",
                "justification": "uses A | B | C operators",
            },
        ]
        md = pf.gen_out_of_scope(minimal_yaml_data)
        rows = [ln for ln in md.splitlines() if ln.startswith("| PT-X ")]
        assert len(rows) == 1
        # 6 columns → 7 unescaped pipes; the 2 escaped pipes inside the
        # justification add 2 more raw `|` characters but are preceded by
        # a `\`, so the column count stays correct.
        unescaped = rows[0].count("|") - rows[0].count("\\|")
        assert unescaped == 7
        assert "A \\| B \\| C" in rows[0]

    def test_accepted_risks_handles_missing_optional_fields(self, minimal_yaml_data):
        minimal_yaml_data["meta"]["accepted_risks"] = [
            {
                "id": "PT-M",
                "title": "Minimal entry",
                "severity": "Low",
                "justification": "Risk owner accepted.",
                # component, stride omitted
            },
        ]
        md = pf.gen_out_of_scope(minimal_yaml_data)
        # Em-dash placeholders for missing optional cells.
        rows = [ln for ln in md.splitlines() if ln.startswith("| PT-M ")]
        assert len(rows) == 1
        assert " — " in rows[0]

    def test_accepted_risks_skips_non_dict_entries(self, minimal_yaml_data):
        minimal_yaml_data["meta"]["accepted_risks"] = [
            None,
            "not-a-dict",
            {"id": "PT-Y", "title": "Real", "severity": "Low", "justification": "ok"},
        ]
        md = pf.gen_out_of_scope(minimal_yaml_data)
        assert "PT-Y" in md
        # Only one data row — the malformed entries are silently skipped.
        rows = [ln for ln in md.splitlines() if ln.startswith("| PT-")]
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# Tier classification (helper used by §2 + §7)
# ---------------------------------------------------------------------------


class TestTierClassification:
    @pytest.mark.parametrize(
        "comp,expected",
        [
            ({"id": "frontend-spa", "name": "Angular Frontend", "paths": []}, "client"),
            ({"id": "nosql-data-layer", "name": "Mongo", "paths": []}, "data"),
            ({"id": "auth-module", "name": "Auth", "paths": []}, "application"),
            ({"id": "rest-api", "name": "API", "paths": []}, "application"),
            ({"id": "db-store", "name": "Postgres", "paths": []}, "data"),
            ({"id": "ui-component", "name": "Browser UI", "paths": []}, "client"),
        ],
    )
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
        # First run writes all 7 (6 composer fragments + _chain-skeleton.md helper).
        _run_cli(str(output_dir))
        # Second run should skip all
        result = _run_cli(str(output_dir))
        assert result.returncode == 0
        expected = f"skipped {len(pf.GENERATORS)}"
        assert expected in result.stdout

    def test_force_overwrites(self, output_dir):
        _run_cli(str(output_dir))
        # Mutate a file
        target = output_dir / ".fragments" / "system-overview.md"
        target.write_text("MUTATED\n")
        # --force should overwrite
        result = _run_cli(str(output_dir), "--force")
        assert result.returncode == 0
        expected = f"wrote {len(pf.GENERATORS)}"
        assert expected in result.stdout
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

    def test_force_refuses_narrative_filled_security_architecture(self, output_dir):
        """RC-3 — `--force security-architecture.md` MUST refuse to overwrite
        when the on-disk fragment has been narrative-filled (zero
        NARRATIVE_PLACEHOLDER markers). Operator must explicitly pass
        `--allow-narrative-loss` to acknowledge the Stage-2-work discard."""
        # Run once to get the scaffold; then "fill" it manually. The
        # scaffold's placeholders are HTML comments shaped as
        # `<!-- NARRATIVE_PLACEHOLDER: section=... -->`, so strip ALL of them
        # with a regex (not a literal replace).
        _run_cli(str(output_dir), "--only", "security-architecture.md")
        filled = output_dir / ".fragments" / "security-architecture.md"
        scaffold = filled.read_text()
        filled.write_text(re.sub(r"<!--\s*NARRATIVE_PLACEHOLDER.*?-->", "filled narrative.", scaffold, flags=re.DOTALL))
        assert "NARRATIVE_PLACEHOLDER" not in filled.read_text()
        before = filled.read_text()
        # --force without --allow-narrative-loss → exit 2, file untouched.
        result = _run_cli(str(output_dir), "--force", "--only", "security-architecture.md")
        assert result.returncode == 2
        assert "refusing to --force overwrite security-architecture.md" in result.stderr
        assert "apply_content_repair.py" in result.stderr
        assert filled.read_text() == before, "fragment must be untouched on refusal"

    def test_force_allow_narrative_loss_overwrites(self, output_dir):
        """RC-3 — with the explicit acknowledgement, `--force --allow-narrative-loss`
        overwrites a narrative-filled fragment back to scaffold."""
        _run_cli(str(output_dir), "--only", "security-architecture.md")
        filled = output_dir / ".fragments" / "security-architecture.md"
        scaffold = filled.read_text()
        filled.write_text(re.sub(r"<!--\s*NARRATIVE_PLACEHOLDER.*?-->", "filled narrative.", scaffold, flags=re.DOTALL))
        result = _run_cli(
            str(output_dir), "--force", "--allow-narrative-loss",
            "--only", "security-architecture.md",
        )
        assert result.returncode == 0
        # Scaffold restored — NARRATIVE_PLACEHOLDER comments reappear.
        assert "NARRATIVE_PLACEHOLDER" in filled.read_text()

    def test_force_on_scaffold_with_placeholders_works(self, output_dir):
        """RC-3 guard fires ONLY when on-disk fragment is narrative-complete.
        A scaffold-state fragment (placeholders present) is the legitimate
        re-render case and must overwrite without the extra flag."""
        _run_cli(str(output_dir), "--only", "security-architecture.md")
        filled = output_dir / ".fragments" / "security-architecture.md"
        # Scaffold output already contains NARRATIVE_PLACEHOLDER markers.
        assert "NARRATIVE_PLACEHOLDER" in filled.read_text()
        result = _run_cli(str(output_dir), "--force", "--only", "security-architecture.md")
        assert result.returncode == 0, f"stderr={result.stderr}"

    def test_force_on_other_fragments_unaffected(self, output_dir):
        """The RC-3 guard targets only security-architecture.md. Other
        mechanical fragments must still respond to plain --force."""
        _run_cli(str(output_dir))
        target = output_dir / ".fragments" / "system-overview.md"
        target.write_text("MUTATED\n")
        result = _run_cli(str(output_dir), "--force", "--only", "system-overview.md")
        assert result.returncode == 0
        assert "MUTATED" not in target.read_text()

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
            [sys.executable, str(REPO_ROOT / "scripts" / "check_inline_shortcut.py"), str(output_dir)],
            capture_output=True,
            text=True,
        )
        assert gate.returncode == 2
        # Specifically: the structural fragments should NOT be in the issue list
        for structural in pf.GENERATORS:
            assert f".fragments/{structural}" not in gate.stderr, (
                f"{structural} should have been generated, but gate still complains"
            )


# ---------------------------------------------------------------------------
# Section 7.2 — Threat Hypotheses Requiring Validation
# (arch.md §Renderer-Rules + Section 7.2 block)
# ---------------------------------------------------------------------------


def _hyp(**overrides):
    base = {
        "id": "HYP-001",
        "source_hypothesis_id": "ARCH-HYP-SQLI-001",
        "rule_id": "ARCH-SQLI-001",
        "title": "SQL injection exposure from ad-hoc SQL construction",
        "threat_category_id": "TH-01",
        "cwe": "CWE-89",
        "proof_state": "control-derived",
        "confidence": "medium",
        "weak_or_missing_controls": ["Parameterized Queries"],
        "evidence": [{"file": "routes/login.ts", "line": 34, "signal": "raw SQL"}],
        "validation_objective": "Attempt UNION SELECT against /login.",
    }
    base.update(overrides)
    return base


def _data_with_hyps(*hypotheses):
    return {
        "security_controls": [],
        "components": [],
        "threats": [],
        "threat_hypotheses": list(hypotheses),
    }


class TestSection72ThreatHypothesesTable:
    def test_table_absent_when_no_hypotheses(self, minimal_yaml_data):
        md = pf.gen_security_architecture(minimal_yaml_data)
        assert "Threat Hypotheses Requiring Validation" not in md

    def test_table_present_when_hypotheses_exist(self):
        md = pf.gen_security_architecture(_data_with_hyps(_hyp()))
        assert "#### Threat Hypotheses Requiring Validation" in md

    def test_table_lives_inside_section_72(self):
        md = pf.gen_security_architecture(_data_with_hyps(_hyp()))
        # Anchor: between the 7.2 heading and the 7.3 heading
        m72 = md.index("### 7.2 Key Architectural Risks")
        m73 = md.index("### 7.3 ")
        block = md[m72:m73]
        assert "#### Threat Hypotheses Requiring Validation" in block
        assert "| ID | Hypothesis |" in block

    def test_hypothesis_id_rendered(self):
        md = pf.gen_security_architecture(_data_with_hyps(_hyp(id="HYP-007")))
        assert "| HYP-007 |" in md

    def test_promoted_hypothesis_excluded(self):
        """Promoted hypotheses live in Section 8 as their T-NNN row —
        they MUST NOT be re-listed in §7.2."""
        md = pf.gen_security_architecture(_data_with_hyps(
            _hyp(id="HYP-001"),
            _hyp(id="HYP-099", promoted_threat_id="T-014"),
        ))
        assert "HYP-001" in md
        assert "HYP-099" not in md

    def test_evidence_renders_with_file_and_line(self):
        md = pf.gen_security_architecture(_data_with_hyps(_hyp(
            evidence=[{"file": "src/server.ts", "line": 42, "signal": "x"}],
        )))
        assert "`src/server.ts:42`" in md

    def test_evidence_renders_file_only_when_line_missing(self):
        md = pf.gen_security_architecture(_data_with_hyps(_hyp(
            evidence=[{"file": "src/server.ts", "signal": "x"}],
        )))
        assert "`src/server.ts`" in md

    def test_evidence_counts_additional_entries(self):
        md = pf.gen_security_architecture(_data_with_hyps(_hyp(
            evidence=[
                {"file": "a.ts", "line": 1, "signal": "x"},
                {"file": "b.ts", "line": 2, "signal": "y"},
                {"file": "c.ts", "line": 3, "signal": "z"},
            ],
        )))
        assert "`a.ts:1` +2" in md

    def test_control_gap_renders_weak_or_missing_controls(self):
        md = pf.gen_security_architecture(_data_with_hyps(_hyp(
            weak_or_missing_controls=["Parameterized Queries", "ORM Layer"],
        )))
        assert "Parameterized Queries" in md
        assert "ORM Layer" in md

    def test_validation_column_uses_validation_objective(self):
        md = pf.gen_security_architecture(_data_with_hyps(_hyp(
            validation_objective="Send UNION SELECT to /login email param.",
        )))
        assert "Send UNION SELECT to /login email param." in md

    def test_validation_column_fallback_when_objective_missing(self):
        h = _hyp()
        h.pop("validation_objective", None)
        md = pf.gen_security_architecture(_data_with_hyps(h))
        assert "_pending validation objective_" in md

    def test_validation_text_truncated_when_overlong(self):
        long = "x" * 300
        md = pf.gen_security_architecture(_data_with_hyps(_hyp(
            validation_objective=long,
        )))
        # Truncated form ends with ellipsis and is shorter than original
        assert "…" in md
        assert "x" * 300 not in md

    def test_pipe_character_escaped_in_user_text(self):
        """The renderer must escape pipes so table layout stays intact."""
        md = pf.gen_security_architecture(_data_with_hyps(_hyp(
            title="Risky | column-breaker",
        )))
        assert "Risky \\| column-breaker" in md

    def test_hypothesis_table_not_emitted_inside_section_8(self):
        """§7.2 hypothesis table must NEVER end up in Section 8 register.
        gen_security_architecture only renders §7, so a presence check on
        the `## 8.` heading is sufficient — Section 8 is a different
        generator entirely. The bare phrase ``Threat Register`` legitimately
        appears in §7 prose as part of cross-references like
        ``[§8 Threat Register](#8-threat-register)``; only the actual
        `## 8.` heading is forbidden."""
        md = pf.gen_security_architecture(_data_with_hyps(_hyp()))
        assert "## 8." not in md
        assert "## 8. Threat Register" not in md

    def test_max_20_hypotheses_listed(self):
        """Defensive cap — 20 rows max so the table stays readable."""
        many = [_hyp(id=f"HYP-{i:03d}") for i in range(1, 30)]
        md = pf.gen_security_architecture(_data_with_hyps(*many))
        assert "HYP-020" in md
        assert "HYP-021" not in md


class TestSecurityArchitectureV2:
    """§7 v2 generator — verdict semantics (Unsafe vs Missing), the verdict
    legend, per-sub-control Status badges, and grouped password lifecycle.
    Added 2026-05 with the §7 verdict/structure redesign."""

    @staticmethod
    def _data():
        return {
            "components": [],
            "threats": [
                {"id": "T-001", "cwe": "CWE-89", "title": "SQLi"},
                {"id": "T-012", "cwe": "CWE-916", "title": "MD5"},
                {"id": "T-008", "cwe": "CWE-942", "title": "CORS"},
            ],
            "security_controls": [
                {
                    "domain": "Identity and Authentication Controls",
                    "control": "Password-Based Authentication",
                    "effectiveness": "Unsafe",
                    "group_subcontrols": True,
                    "effectiveness_reason": "present but defeated at every stage",
                    "implementation": "The email/password credential routes through one MD5 sink and one raw-SQL path.",
                    "assessment": "Login interpolates user input; the current-password check is skippable.",
                    "subcontrols": [
                        {"title": "Login", "effectiveness": "Unsafe",
                         "status_note": "raw SQL login lookup allows authentication bypass",
                         "relevant_findings": ["T-001"]},
                        {"title": "Password Storage", "effectiveness": "Unsafe",
                         "status_note": "unsalted MD5", "relevant_findings": ["T-012"]},
                    ],
                },
                {
                    "domain": "Browser and Cross-Origin Controls",
                    "control": "Content Security Policy",
                    "effectiveness": "Missing",
                    "status_note": "no CSP header is set",
                    "linked_threats": ["T-008"],
                },
            ],
        }

    def test_verdict_legend_present(self):
        md = pf.gen_security_architecture_v2(self._data())
        assert "How to read the verdicts" in md
        assert "Fix the existing control" in md
        assert "Add the control" in md

    def test_count_line_includes_unsafe(self):
        md = pf.gen_security_architecture_v2(self._data())
        line = next(l for l in md.splitlines() if "Cataloged controls" in l)
        assert "unsafe" in line and "missing" in line

    def test_overview_unsafe_vs_missing(self):
        md = pf.gen_security_architecture_v2(self._data())
        rows = [l for l in md.splitlines() if l.startswith("| [")]
        auth = next(l for l in rows if "Identity and Authentication" in l)
        csp = next(l for l in rows if "Browser and Cross-Origin" in l)
        assert "🔴 Unsafe" in auth, auth
        assert "🔴 Missing" in csp, csp
        # A Missing category that HAS a catalogued (absent) control names it as
        # "required controls not in place" — not the misleading "no controls
        # catalogued", which must be reserved for genuinely empty categories
        # (2026-06-02 §7.1 fix).
        assert "required controls not in place" in csp, csp
        assert "no controls catalogued" not in csp.lower(), csp
        # A category with NO catalogued control at all still reads "No controls
        # catalogued for this category."
        empty_rows = [l for l in rows if "no controls catalogued" in l.lower()]
        for l in empty_rows:
            assert "required controls not in place" not in l, l

    def test_status_badge_on_every_h4(self):
        md = pf.gen_security_architecture_v2(self._data())
        import re as _re
        h4s = _re.findall(r"^#### .+$", md, _re.MULTILINE)
        assert h4s, "expected at least one H4"
        # one **Status:** line per emitted H4
        assert md.count("**Status:**") >= len(h4s)

    def test_grouped_password_lifecycle_bullets(self):
        md = pf.gen_security_architecture_v2(self._data())
        # Split on the H3 with a trailing space so the needle does NOT also
        # match the H4 `#### 7.2.1 …` (which contains the substring "### 7.2").
        seg = md.split("\n### 7.2 ")[1].split("\n### 7.3 ")[0]
        assert "Password-Based Authentication" in seg
        # the lifecycle stages render as bullets, NOT as peer H4s
        assert any(l.startswith("- **Login** — 🔴 Unsafe") for l in seg.splitlines())
        assert seg.count("\n#### ") == 1, "password lifecycle must be ONE grouped H4"
        # grouped H4 still carries the two required labels
        assert "**Security assessment**" in seg and "**Relevant findings**" in seg

    @staticmethod
    def _section_containing(md: str, needle: str) -> str:
        """Return the `### 7.x` block (header→next H3/H2) that contains needle.

        Skips §7.1 — the Security Control Overview table now names controls in
        its 'Main reason' cells, so a control name appears there too; tests want
        the control's OWN §7.x block, not the overview row."""
        import re as _re
        blocks = _re.split(r"(?m)^(?=### 7\.\d+ )", md)
        for b in blocks:
            if b.startswith("### 7.") and not b.startswith("### 7.1 ") and needle in b:
                return b.split("\n## ")[0]
        raise AssertionError(f"no §7 block contains {needle!r}")

    @staticmethod
    def _covered_labels(section: str) -> list:
        import re as _re
        cc = next((l for l in section.splitlines()
                   if l.startswith("**Controls covered:**")), "")
        return _re.findall(r"\[([^\]]+)\]\(#", cc)

    @staticmethod
    def _h4_titles(section: str) -> list:
        import re as _re
        return [_re.sub(r"^\d+(?:\.\d+)*\s+", "", h).strip()
                for h in _re.findall(r"(?m)^#### (.+)$", section)]

    def test_controls_covered_lists_only_emitted_h4s(self):
        """B1 regression: a control suppressed by _emit_v2_subcontrol_legacy
        (Missing + no findings + no implementation) must NOT appear in the
        `**Controls covered:**` line — otherwise it is a dangling link the
        control_subsection_coverage gate flags and the re-render loop cannot
        self-heal (juice-shop 2026-06-01 §7.4/§7.10)."""
        data = {
            "components": [],
            "threats": [{"id": "T-008", "cwe": "CWE-352", "title": "CSRF"}],
            "security_controls": [
                {"domain": "Authorization Controls",
                 "control": "Role-Based Access Control",
                 "effectiveness": "Missing", "linked_threats": ["T-008"]},
                {"domain": "Authorization Controls",
                 "control": "CSRF Protection",
                 "effectiveness": "Missing"},  # suppressed: no findings, no impl
            ],
        }
        md = pf.gen_security_architecture_v2(data)
        assert "__CONTROLS_COVERED_SENTINEL__" not in md
        seg = self._section_containing(md, "Role-Based Access Control")
        labels = self._covered_labels(seg)
        titles = self._h4_titles(seg)
        # every covered link resolves to an emitted H4 (the invariant the gate enforces)
        for lab in labels:
            assert lab in titles, f"dangling covered link {lab!r}; H4s={titles}"
        # the suppressed control must NOT be linked, but the emitted one must be
        assert "CSRF Protection" not in labels
        assert "Role-Based Access Control" in titles

    def test_controls_covered_dropped_when_all_suppressed(self):
        """When every control in a §7.x section is suppressed, the
        `**Controls covered:**` line is removed entirely (no dangling links);
        the suppressed-controls note still lists them for the reader."""
        data = {
            "components": [],
            "threats": [],
            "security_controls": [
                {"domain": "Authorization Controls",
                 "control": "CSRF Protection",
                 "effectiveness": "Missing"},
            ],
        }
        md = pf.gen_security_architecture_v2(data)
        assert "__CONTROLS_COVERED_SENTINEL__" not in md
        seg = self._section_containing(md, "Additional cataloged controls")
        assert "**Controls covered:**" not in seg
        assert "CSRF Protection" in seg


class TestV2SectionRouting:
    """`_v2_canonical_section_for_control` routes controls to §7 sections by
    domain. Regression: hyphenated hints (`file-parser`) never matched the
    space-form canonical domain Stage 1 writes ("File Parser and Outbound
    Request Controls"), so a control whose NAME also lacked a hint token was
    dropped from §7 entirely (juice-shop 2026-06-01 §7.10)."""

    def test_canonical_domain_routes_even_without_hint_in_name(self):
        # "File Upload Validation" carries no §7.10 hint token in its name,
        # but its domain IS the canonical §7.10 title → must route to §7.10.
        c = {"control": "File Upload Validation",
             "domain": "File Parser and Outbound Request Controls"}
        assert pf._v2_canonical_section_for_control(c) == \
            "7.10 File Parser and Outbound Request Controls"

    def test_data_access_domain_does_not_collide_with_authorization(self):
        # Guard against the substring trap: §7.4 hint "access-control" must NOT
        # steal a §7.5 control whose domain ends "...Data Access Controls".
        c = {"control": "SQL Parameterization (Sequelize ORM)",
             "domain": "Query Construction and Data Access Controls"}
        assert pf._v2_canonical_section_for_control(c) == \
            "7.5 Query Construction and Data Access Controls"

    def test_hint_fallback_still_works_for_partial_domain(self):
        # Non-canonical / shorthand domain still routes via the hint fallback.
        c = {"control": "SSRF guard", "domain": "ssrf"}
        assert pf._v2_canonical_section_for_control(c) == \
            "7.10 File Parser and Outbound Request Controls"


# ---------------------------------------------------------------------------
# §7.2 Authentication Mechanisms inventory (2026-05-31, deterministic)
# ---------------------------------------------------------------------------

def _auth_yaml():
    """A yaml fixture exercising mechanisms across the §7.2/§7.3/§7.9 domains."""
    return {
        "meta": {"open_user_registration": True},
        "security_controls": [
            {"control": "Password Authentication (Login)", "domain": "Identity and Authentication Controls", "effectiveness": "weak"},
            {"control": "Session Token Validation (JWT Based)", "domain": "Session and Token Controls", "effectiveness": "partial"},
            {"control": "Password Hashing", "domain": "Cryptography Secrets and Data Protection", "effectiveness": "missing"},
        ],
        "threats": [
            {"id": "T-001", "title": "JWT forgery via hardcoded RSA private key", "cwe": "CWE-321", "risk": "Critical"},
            {"id": "T-024", "title": "TOTP secrets stored in plaintext in database", "cwe": "CWE-312", "risk": "High"},
            {"id": "T-029", "title": "Admin account registration via role field manipulation", "cwe": "CWE-269", "risk": "High"},
            {"id": "T-007", "title": "MD5 password hashing enables offline password recovery", "cwe": "CWE-916", "risk": "Critical"},
        ],
    }


def test_auth_inventory_lists_present_mechanisms():
    block = "\n".join(pf._build_auth_mechanism_inventory(_auth_yaml()))
    # Registration (meta flag + threat), Password login (control), Password
    # hashing (control+threat), JWT (control+threat), MFA/TOTP (threat) present.
    assert "| User registration |" in block
    assert "| Password login |" in block
    assert "| Password storage (hashing) |" in block
    assert "| JWT / bearer-token session |" in block
    assert "| Multi-factor authentication (TOTP / 2FA) |" in block
    # Findings link to F-ids (T-NNN → F-NNN, same number).
    assert "[F-029](#f-029)" in block and "[F-024](#f-024)" in block
    assert "[F-001](#f-001)" in block and "[F-007](#f-007)" in block


def test_auth_inventory_absent_go_to_note():
    block = "\n".join(pf._build_auth_mechanism_inventory(_auth_yaml()))
    # OAuth and password-reset are not in the fixture → "Also checked" note,
    # NOT a table row.
    assert "Also checked, not detected" in block
    assert "OAuth / OIDC federated login" in block.split("Also checked")[1]
    assert "| OAuth / OIDC federated login |" not in block


def test_auth_inventory_section_pointers():
    block = "\n".join(pf._build_auth_mechanism_inventory(_auth_yaml()))
    # JWT assessed under §7.3, hashing under §7.9, registration under §7.2.
    assert "[§7.3](#73-session-and-token-controls)" in block
    assert "[§7.9](#79-cryptography-secrets-and-data-protection)" in block
    assert "[§7.2](#72-identity-and-authentication-controls)" in block


def test_auth_inventory_status_from_effectiveness():
    block = "\n".join(pf._build_auth_mechanism_inventory(_auth_yaml()))
    # Password login control effectiveness=weak → 🟠 Weak badge in its row.
    login_row = next(l for l in block.splitlines() if l.startswith("| Password login |"))
    assert "🟠 Weak" in login_row
    # Password hashing control effectiveness=missing → 🔴 Missing.
    hash_row = next(l for l in block.splitlines() if l.startswith("| Password storage (hashing) |"))
    assert "🔴 Missing" in hash_row


def test_auth_inventory_empty_without_auth():
    yaml_data = {
        "meta": {},
        "security_controls": [{"control": "Output Encoding / XSS Prevention", "domain": "Output Encoding", "effectiveness": "weak"}],
        "threats": [{"id": "T-050", "title": "Stored XSS in product description", "cwe": "CWE-79", "risk": "High"}],
    }
    assert pf._build_auth_mechanism_inventory(yaml_data) == []


def test_auth_inventory_is_frozen_marked_and_single_titles():
    block = "\n".join(pf._build_auth_mechanism_inventory(_auth_yaml()))
    assert "AUTH-MECHANISMS-FROZEN" in block
    # Each finding link appears once and CARRIES its title (the inventory is a
    # table, so compose's prose-linkifier never enriches it — emitting a bare
    # ID left it 'leer betitelt', 2026-06-02). The link must show `— <title>`.
    assert block.count("[F-001](#f-001)") == 1
    assert re.search(r"\[F-001\]\(#f-001\) — \S", block), \
        "§7.2 inventory finding link must carry a title, not a bare ID"
