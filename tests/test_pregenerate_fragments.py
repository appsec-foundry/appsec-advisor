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
                "domain": "Identity and Authentication Controls",
                "control": "Password-Based Authentication",
                "implementation": "Express password login",
                "effectiveness": "weak",
                "notes": "outdated",
            },
            {
                "domain": "Input Boundary Validation Controls",
                "control": "Validation Approach",
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

    def test_each_section_2_diagram_has_key_takeaway(self, minimal_yaml_data):
        """Bug #2 regression: QA Check 8.0 requires a `**Key takeaway:**` after
        every §2 Mermaid block. The generator must emit one for each of
        §2.1–§2.4 so the check passes by construction (no placeholder)."""
        md = pf.gen_architecture_diagrams(minimal_yaml_data)
        assert md.count("**Key takeaway:**") == 4
        # The placeholder the QA reviewer inserts when the takeaway is missing
        # must never appear in the generated baseline.
        assert "QA: missing" not in md

    def test_key_takeaway_immediately_follows_each_mermaid_fence(self, minimal_yaml_data):
        """Each `**Key takeaway:**` must appear shortly after a closing mermaid
        fence (the QA check looks just past the fence), not floating elsewhere."""
        lines = pf.gen_architecture_diagrams(minimal_yaml_data).splitlines()
        fence_idxs = [i for i, ln in enumerate(lines) if ln.strip() == "```"]
        takeaway_idxs = [i for i, ln in enumerate(lines) if ln.startswith("**Key takeaway:**")]
        assert takeaway_idxs, "no key takeaway lines emitted"
        for ti in takeaway_idxs:
            # A closing fence must precede this takeaway within a few lines.
            assert any(0 < ti - fi <= 3 for fi in fence_idxs), (
                f"key takeaway at line {ti} not preceded by a nearby mermaid fence"
            )


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


class TestAiExposure:
    """Deterministic ms-ai-exposure.json generator (gen_ai_exposure)."""

    _LLM_YAML = {
        "components": [
            {"id": "express-api", "name": "Express API Server"},
            {"id": "llm-chatbot", "name": "LLM Chatbot Service"},
        ],
        "threats": [
            {
                "id": "T-026",
                "title": "Prompt Injection — routes/chat.ts:179",
                "component": "llm-chatbot",
                "effective_severity": "High",
            },
            {
                "id": "T-035",
                "title": "Confidential System Prompt Extractable — routes/chat.ts:104",
                "component": "llm-chatbot",
                "risk": "High",
            },
            {
                "id": "T-043",
                "title": "Unbounded LLM API Consumption on Chat Endpoint — server.ts",
                "component": "express-api",
                "effective_severity": "High",
            },
            # noise — must NOT be categorised as an LLM risk:
            {
                "id": "T-025",
                "title": "NoSQL Injection — routes/chat.ts:149",
                "component": "llm-chatbot",
                "effective_severity": "Critical",
            },
            {
                "id": "T-041",
                "title": "Unbounded In-Memory Token Store — lib/insecurity.ts:70",
                "component": "auth",
                "risk": "High",
            },
        ],
    }

    def test_returns_none_without_llm_surface(self):
        d = {
            "components": [{"id": "api", "name": "API Server"}],
            "threats": [
                {"id": "T-001", "title": "SQL Injection — routes/login.ts", "component": "api", "risk": "Critical"}
            ],
        }
        assert pf.gen_ai_exposure(d) is None

    def test_returns_none_when_llm_component_has_no_llm_risk(self):
        d = {
            "components": [{"id": "llm-chatbot", "name": "LLM Chatbot Service"}],
            "threats": [
                {"id": "T-002", "title": "NoSQL Injection — routes/chat.ts", "component": "llm-chatbot", "risk": "High"}
            ],
        }
        assert pf.gen_ai_exposure(d) is None

    def test_categorises_and_excludes_noise(self):
        out = pf.gen_ai_exposure(self._LLM_YAML)
        assert out is not None
        data = json.loads(out)
        ids = {r["owasp_llm_id"] for r in data["ai_risks"]}
        assert "LLM01" in ids  # prompt injection
        assert "LLM07" in ids  # system prompt leakage
        assert "LLM10" in ids  # unbounded LLM consumption (has LLM context)
        refs = {f["ref"] for r in data["ai_risks"] for f in r["findings"]}
        assert "T-025" not in refs  # NoSQL injection is not an LLM risk
        assert "T-041" not in refs  # unbounded token store has no LLM context

    def test_output_is_schema_valid(self):
        out = pf.gen_ai_exposure(self._LLM_YAML)
        data = json.loads(out)
        assert 1 <= len(data["ai_risks"]) <= 10
        for r in data["ai_risks"]:
            assert 4 <= len(r["name"]) <= 60
            assert 40 <= len(r["description"]) <= 400
            assert 1 <= len(r["findings"]) <= 6
            for f in r["findings"]:
                assert re.match(r"^[FTM]-\d{3,4}$", f["ref"])
                assert 5 <= len(f["label"]) <= 80
            for c in r.get("affected_components", []):
                assert re.match(r"^C-\d{2,}$", c)
        assert 20 <= len(data.get("summary", "")) <= 300

    def test_role_confusion_title_categorised_as_prompt_injection(self):
        """Regression (juice-shop 2026-07-02): a client-supplied message-array/
        role-confusion finding is a Prompt Injection variant even when its
        title never says "prompt injection" literally."""
        d = {
            "components": [{"id": "llm-chatbot", "name": "AI Chatbot"}],
            "threats": [
                {
                    "id": "T-028",
                    "title": "Client-Supplied Message Array Accepted Without Role — routes/chat.ts:191",
                    "component": "llm-chatbot",
                    "risk": "High",
                    "evidence_summary": "routes/chat.ts:191 assigns req.body?.messages directly with no role check.",
                    "impact_description": "Attacker-controlled role fields let the client override or fabricate "
                    "system/tool context, defeating the server-authored system prompt's guardrails.",
                },
            ],
        }
        out = pf.gen_ai_exposure(d)
        assert out is not None
        data = json.loads(out)
        by_id = {r["owasp_llm_id"]: r for r in data["ai_risks"]}
        assert "LLM01" in by_id
        assert "T-028" in {f["ref"] for f in by_id["LLM01"]["findings"]}

    def test_llm_context_found_in_impact_description_not_just_title(self):
        """Regression (juice-shop 2026-07-02): T-040 lived on the generic
        "backend-api" component (not the LLM component) and its title said
        "Chat Endpoint", not "chatbot"/"llm"/"prompt" — only the impact prose
        ("...a metered external LLM API...") carried the LLM-context signal
        the weak-rule gate needs. Scanning title alone dropped it entirely."""
        d = {
            "components": [
                {"id": "backend-api", "name": "Backend REST API"},
                {"id": "llm-chatbot", "name": "AI Chatbot"},
            ],
            "threats": [
                {
                    "id": "T-040",
                    "title": "Unauthenticated Rate-Unlimited Chat Endpoint — server.ts:638",
                    "component": "backend-api",
                    "risk": "High",
                    "evidence_summary": "server.ts:638 registers /rest/chat with no rateLimit() middleware.",
                    "impact_description": "Unbounded, unauthenticated calls to a metered external LLM API can "
                    "exhaust budget/rate limits and degrade or deny the chat feature for legitimate customers.",
                },
            ],
        }
        out = pf.gen_ai_exposure(d)
        assert out is not None
        data = json.loads(out)
        refs = {f["ref"] for r in data["ai_risks"] for f in r["findings"]}
        assert "T-040" in refs

    def test_precisely_titled_threat_not_stolen_by_generic_prompt_injection_match(self):
        """Regression caught in review (juice-shop 2026-07-03): widening the
        keyword-match scan to evidence/impact text caused a threat titled
        "LLM Tool-Calling Guardrail Bypass" (Excessive Agency) to fall under the
        generic LLM01 Prompt Injection bucket instead, because its impact
        sentence names "prompt injection" as the underlying attack technique.
        Categorization must stay title-scoped; only the weak-rule context gate
        reads the wider blob."""
        d = {
            "components": [{"id": "llm-chatbot", "name": "AI Chatbot"}],
            "threats": [
                {
                    "id": "T-045",
                    "title": "LLM Tool-Calling Guardrail Bypass — routes/chat.ts:184",
                    "component": "llm-chatbot",
                    "risk": "High",
                    "evidence_summary": "chat.ts:181-185 calls security.generateCoupon(discount) with the "
                    "model-supplied discount value with no server-side upper-bound check.",
                    "impact_description": "A successful prompt injection can mint discount coupons up to 100% "
                    "off, directly enabling unbounded free-product fraud through an unauthenticated chat interface.",
                },
            ],
        }
        out = pf.gen_ai_exposure(d)
        data = json.loads(out)
        by_id = {r["owasp_llm_id"]: r for r in data["ai_risks"]}
        assert "LLM06" in by_id
        assert "T-045" in {f["ref"] for f in by_id["LLM06"]["findings"]}
        assert "LLM01" not in by_id

    def test_no_asi_id_without_agentic_surface(self):
        """A plain LLM call-and-return (no tools/memory/multi-agent/autonomy in
        any threat or component) must NOT be tagged with an Agentic-Top-10 id —
        the LLM→ASI crosswalk is gated on a real agentic surface."""
        out = pf.gen_ai_exposure(self._LLM_YAML)
        data = json.loads(out)
        assert all("owasp_asi_id" not in r for r in data["ai_risks"])

    def test_asi_crosswalk_on_agentic_surface(self):
        """When a threat evidences an agentic surface (here: tool-calling /
        excessive agency), the deterministic backstop tags the crosswalked
        Agentic-Top-10 id alongside the LLM id (LLM06 → ASI02)."""
        d = {
            "components": [{"id": "llm-chatbot", "name": "AI Chatbot"}],
            "threats": [
                {
                    "id": "T-045",
                    "title": "LLM Tool-Calling Guardrail Bypass — routes/chat.ts:184",
                    "component": "llm-chatbot",
                    "risk": "High",
                    "evidence_summary": "chat.ts:181-185 invokes a tool with model-supplied args, no allow-list.",
                    "impact_description": "Excessive agency: the model can call a coupon-minting tool autonomously.",
                },
            ],
        }
        out = pf.gen_ai_exposure(d)
        data = json.loads(out)
        by_id = {r["owasp_llm_id"]: r for r in data["ai_risks"]}
        assert "LLM06" in by_id
        assert by_id["LLM06"].get("owasp_asi_id") == "ASI02"

    def test_ai_exposure_schema_declares_asi_enum(self):
        """The ai-exposure fragment schema must accept owasp_asi_id ASI01..ASI10
        (contract guard: producer above emits it, schema must permit it)."""
        schema = json.loads(
            (REPO_ROOT / "schemas" / "fragments" / "ai-exposure.schema.json").read_text(encoding="utf-8")
        )
        enum = schema["properties"]["ai_risks"]["items"]["properties"]["owasp_asi_id"]["enum"]
        assert enum == [f"ASI{n:02d}" for n in range(1, 11)]


class TestCriticalAttackTree:
    """Deterministic ms-critical-attack-tree.json generator
    (gen_critical_attack_tree). Root-cause fix for the juice-shop 2026-06-27
    contract gap: the MANDATORY-at-≥2-Critical section was only LLM-authored and
    got skipped at quick depth (compose soft-warn vs section_integrity hard-fail).
    """

    _CRIT_YAML = {
        "threats": [
            {
                "id": "T-001",
                "title": "JWT in localStorage — interceptor.ts:13",
                "risk": "Critical",
                "stride": "Information Disclosure",
            },
            {
                "id": "T-006",
                "title": "SQL Injection in Login — routes/login.ts:34",
                "risk": "Critical",
                "stride": "Tampering",
            },
            {
                "id": "T-012",
                "title": "Remote Code Execution — routes/b2bOrder.ts:23",
                "risk": "Critical",
                "stride": "Elevation of Privilege",
            },
            {
                "id": "T-020",
                "title": "MD5 password hashing — lib/insecurity.ts:41",
                "risk": "High",
                "stride": "Information Disclosure",
            },
        ]
    }

    def test_returns_none_below_two_criticals(self):
        # 1 Critical → section is out of scope (has_multi_critical is >=2).
        d = {"threats": [{"id": "T-001", "title": "X — a.ts:1", "risk": "Critical", "stride": "Tampering"}]}
        assert pf.gen_critical_attack_tree(d) is None

    def test_gates_on_risk_not_effective_severity(self):
        # Mirror compose._severity_counts EXACTLY: only `risk`/`severity` counts,
        # NOT effective_severity. Two effective-critical-but-risk-High threats
        # must NOT trip the section (compose would mark it out of scope).
        d = {
            "threats": [
                {
                    "id": "T-1",
                    "title": "A — a.ts:1",
                    "risk": "High",
                    "effective_severity": "Critical",
                    "stride": "Tampering",
                },
                {
                    "id": "T-2",
                    "title": "B — b.ts:1",
                    "risk": "High",
                    "effective_severity": "Critical",
                    "stride": "Spoofing",
                },
            ]
        }
        assert pf.gen_critical_attack_tree(d) is None

    def test_emits_tree_for_two_plus_criticals(self):
        out = pf.gen_critical_attack_tree(self._CRIT_YAML)
        assert out is not None
        data = json.loads(out)
        nodes = data["mermaid"]["nodes"]
        leaves = [n for n in nodes if n["class"] == "leaf"]
        # 3 risk=Critical threats → 3 leaves; the risk=High one is excluded.
        assert len(leaves) == 3
        leaf_ids = {n["id"] for n in leaves}
        assert leaf_ids == {"T001", "T006", "T012"}
        # Every leaf label carries its T-NNN token so compose's findings-pointer
        # deriver (keyed on `[FT]-\d{3,4}` AND class == "leaf") picks it up — the
        # exact bug a class:"crit" hand-authored fragment hit (empty pointer).
        for n in leaves:
            assert re.search(r"T-\d{3}", n["label"])

    def test_output_is_schema_valid(self):
        import jsonschema

        schema_path = (
            Path(__file__).resolve().parent.parent / "schemas" / "fragments" / "critical-attack-tree.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        data = json.loads(pf.gen_critical_attack_tree(self._CRIT_YAML))
        jsonschema.validate(data, schema)
        # Node ids must satisfy the schema pattern ^[A-Z][A-Z0-9_]*$.
        for n in data["mermaid"]["nodes"]:
            assert re.match(r"^[A-Z][A-Z0-9_]*$", n["id"])

    def test_capabilities_in_canonical_stride_order(self):
        data = json.loads(pf.gen_critical_attack_tree(self._CRIT_YAML))
        caps = [n["id"] for n in data["mermaid"]["nodes"] if n["class"] == "or_node"]
        # Tampering before Information Disclosure before Elevation of Privilege.
        assert caps == ["CAP_TAMPER", "CAP_INFO", "CAP_EOP"]


class TestVerdict:
    """Deterministic ms-verdict.json FLOOR generator (gen_verdict). Root-cause
    fix for the juice-shop 2026-07-16 gap: ms-verdict.json is the only MANDATORY
    Management-Summary fragment with no deterministic backstop, and compose
    HARD-fails without it — so an abnormal MS-renderer cutoff (SESSION_STOP
    stop_reason=unknown before its first Write) forced a full re-dispatch.
    """

    _YAML = {
        "threats": [
            {"id": "T-001", "title": "SQL Injection — routes/login.ts:34", "risk": "Critical", "stride": "Tampering"},
            {
                "id": "T-002",
                "title": "JWT in localStorage — interceptor.ts:13",
                "risk": "Critical",
                "stride": "Information Disclosure",
            },
            {
                "id": "T-003",
                "title": "RCE — routes/b2bOrder.ts:23",
                "risk": "Critical",
                "stride": "Elevation of Privilege",
            },
            {"id": "T-004", "title": "Weak login — routes/login.ts:9", "risk": "High", "stride": "Spoofing"},
            {"id": "T-005", "title": "No audit log — server.ts:1", "risk": "Medium", "stride": "Repudiation"},
        ]
    }

    def _schema(self):
        return json.loads((REPO_ROOT / "schemas" / "fragments" / "verdict.schema.json").read_text(encoding="utf-8"))

    def test_output_is_schema_valid(self):
        import jsonschema

        data = json.loads(pf.gen_verdict(self._YAML))
        jsonschema.validate(data, self._schema())

    def test_red_posture_when_critical_present(self):
        data = json.loads(pf.gen_verdict(self._YAML))
        assert data["severity"] == "red"
        assert data["opening"].startswith("Not production-ready")

    def test_yellow_posture_when_high_no_critical(self):
        y = {
            "threats": [
                {"id": "T-001", "title": "A — a.ts:1", "risk": "High", "stride": "Spoofing"},
                {"id": "T-002", "title": "B — b.ts:1", "risk": "Medium", "stride": "Tampering"},
            ]
        }
        data = json.loads(pf.gen_verdict(y))
        assert data["severity"] == "yellow"

    def test_green_posture_when_no_high_or_critical(self):
        y = {
            "threats": [
                {"id": "T-001", "title": "A — a.ts:1", "risk": "Medium", "stride": "Tampering"},
                {"id": "T-002", "title": "B — b.ts:1", "risk": "Low", "stride": "Spoofing"},
            ]
        }
        data = json.loads(pf.gen_verdict(y))
        assert data["severity"] == "green"

    def test_bullets_carry_valid_refs_grouped_by_stride(self):
        data = json.loads(pf.gen_verdict(self._YAML))
        # 5 threats across 5 distinct STRIDE classes → 5 scenario bullets.
        assert len(data["bullets"]) == 5
        seen_refs = set()
        for b in data["bullets"]:
            assert 1 <= len(b["refs"]) <= 5
            for r in b["refs"]:
                assert re.match(r"^[FT]-\d{3,4}$", r)
                seen_refs.add(r)
        assert {"T-001", "T-002", "T-003", "T-004", "T-005"} <= seen_refs

    def test_worst_severity_scenario_leads(self):
        # A Critical Tampering finding must surface its scenario before a Medium.
        data = json.loads(pf.gen_verdict(self._YAML))
        assert data["bullets"][0]["title"] == "Business data read or altered"

    def test_synthesises_second_bullet_when_single_scenario(self):
        # One finding → one STRIDE scenario, but the schema needs >=2 bullets.
        y = {"threats": [{"id": "T-001", "title": "X — a.ts:1", "risk": "Critical", "stride": "Tampering"}]}
        import jsonschema

        data = json.loads(pf.gen_verdict(y))
        jsonschema.validate(data, self._schema())
        assert len(data["bullets"]) == 2

    def test_returns_none_for_threatless_model(self):
        assert pf.gen_verdict({"threats": []}) is None
        assert pf.gen_verdict({}) is None

    def test_idempotent_preserves_llm_version(self, tmp_path):
        # The driver must never overwrite an existing (LLM-authored) verdict.
        (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(self._YAML), encoding="utf-8")
        frags = tmp_path / ".fragments"
        frags.mkdir()
        sentinel = '{"severity":"red","opening":"SENTINEL","bullets":[]}'
        (frags / "ms-verdict.json").write_text(sentinel, encoding="utf-8")
        subprocess.run(
            [sys.executable, str(SCRIPT), str(tmp_path), "--only", "ms-verdict.json"],
            check=True,
            capture_output=True,
            text=True,
        )
        assert (frags / "ms-verdict.json").read_text(encoding="utf-8") == sentinel

    def test_backstop_fills_missing_fragment(self, tmp_path):
        (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(self._YAML), encoding="utf-8")
        (tmp_path / ".fragments").mkdir()
        subprocess.run(
            [sys.executable, str(SCRIPT), str(tmp_path), "--only", "ms-verdict.json"],
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads((tmp_path / ".fragments" / "ms-verdict.json").read_text(encoding="utf-8"))
        assert data["severity"] == "red"


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

    def test_large_inventory_collapses_no_finding_rows_with_total_hint(self):
        """A large route inventory lists only finding-linked rows individually;
        the rest are summarised with an explicit total + inventory pointer
        (2026-06-04 request — keep §5 scannable while staying complete)."""
        unauth = [{"endpoint": f"GET /noise/{i}", "method": "GET"} for i in range(40)]
        unauth.append({"endpoint": "GET /sqli", "method": "GET", "linked_threats": ["T-1"]})
        data = {
            "attack_surface": [{**e, "auth_required": False} for e in unauth],
            "threats": [{"id": "T-1", "risk": "Critical"}],
        }
        md = pf.gen_attack_surface(data)
        # Header carries the full count.
        assert "Unauthenticated Entry Points (41)" in md
        # The finding-linked row is shown; the 40 noise rows are not listed.
        assert "/sqli" in md
        assert "/noise/0" not in md
        # The omission is acknowledged with the total.
        assert "40 further entry point(s)" in md
        assert "41 total" in md
        assert ".route-inventory.json" in md

    def test_collapse_keeps_relevance_tagged_finding_free_rows(self):
        """A finding-free route with a relevance tag (auth/registration/management/
        suspect) stays individually listed even in a large, collapsing inventory —
        a plain finding-free route is still summarised (2026-06-11 request)."""
        entries = [{"endpoint": f"GET /noise/{i}", "method": "GET", "auth_required": False} for i in range(40)]
        entries.append(
            {
                "endpoint": "POST /rest/user/login",
                "method": "POST",
                "auth_required": False,
                "relevance_tags": ["authentication"],
            }
        )
        entries.append(
            {
                "endpoint": "PUT /rest/wallet/balance",
                "method": "PUT",
                "auth_required": False,
                "relevance_tags": ["missing-auth"],
            }
        )
        data = {"attack_surface": entries}
        md = pf.gen_attack_surface(data)
        # Relevance-tagged finding-free rows are shown with their review chip.
        assert "/rest/user/login" in md
        assert "/rest/wallet/balance" in md
        assert "⚑ Review: auth/token endpoint" in md
        assert "⚑ Review: no auth guard detected" in md
        # Plain noise rows are still collapsed.
        assert "/noise/0" not in md
        assert "40 further entry point(s)" in md

    def test_small_inventory_lists_every_row(self):
        """Below the cap, no rows are omitted and no total-hint note appears."""
        data = {
            "attack_surface": [
                {"endpoint": "GET /a", "method": "GET", "auth_required": False},
                {"endpoint": "GET /b", "method": "GET", "auth_required": False},
            ]
        }
        md = pf.gen_attack_surface(data)
        assert "/a" in md and "/b" in md
        assert "further entry point(s)" not in md


# ---------------------------------------------------------------------------
# M3.3 / D1 — §2 + §6 substance enrichments
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
# detail moved to §1.x infobox metadata + §6.x control catalogue.


class TestSecurityArchitectureCWEMapping:
    """§6 v2 must surface threats by contract CWE routing when no controls are cataloged."""

    @staticmethod
    def _h3_section(md: str, start: str, end: str) -> str:
        match = re.search(rf"(?ms)^### {re.escape(start)}\b.*?(?=^### {re.escape(end)}\b)", md)
        assert match is not None
        return match.group(0)

    def _data(self, threats):
        return {
            "meta": {"project": {"name": "x"}},
            "components": [{"id": "c1", "name": "C1", "paths": ["a"]}],
            "security_controls": [
                # Auth control present so §6.2 is the only cataloged-control section.
                {
                    "control": "Password-Based Authentication",
                    "domain": "Identity and Authentication Controls",
                    "implementation": "Express password login",
                    "effectiveness": "weak",
                },
            ],
            "threats": threats,
        }

    def test_ssrf_threats_surface_in_7_10_via_cwe(self):
        threats = [
            {
                "id": "T-100",
                "cwe": "CWE-918",
                "title": "SSRF via image fetcher",
                "scenario": "Outbound image fetch reaches internal hosts.",
                "risk": "High",
            },
        ]
        md = pf.gen_security_architecture(self._data(threats))
        sec_7_10 = self._h3_section(md, "6.10", "6.11")
        assert "F-100" in sec_7_10

    def test_query_construction_threats_surface_in_7_5_via_cwe(self):
        threats = [
            {"id": "T-200", "cwe": "CWE-89", "title": "SQL injection", "scenario": "...", "risk": "High"},
        ]
        md = pf.gen_security_architecture(self._data(threats))
        sec_7_5 = self._h3_section(md, "6.5", "6.6")
        assert "F-200" in sec_7_5

    def test_unrelated_threat_does_not_match_7_12(self):
        """Regression guard: title text alone must not route into the real-time bucket."""
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
        sec_7_12 = self._h3_section(md, "6.12", "6.13")
        assert "F-300" not in sec_7_12, "F-300 has nothing to do with real-time controls"


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
        # trust-boundary detail now lives in the §1.x infobox + §6.x catalogue.
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
        assert md.startswith("## 6. Security Architecture\n")

    def test_has_all_13_v2_subsections(self, minimal_yaml_data):
        md = pf.gen_security_architecture(minimal_yaml_data)
        for heading, _hint, _tier in pf._V2_SUBSECTIONS:
            assert f"### {heading}" in md, f"Missing ### {heading}"
        assert "### 6.14 " not in md

    def test_crypto_secrets_live_in_79(self, minimal_yaml_data):
        md = pf.gen_security_architecture(minimal_yaml_data)
        assert "### 6.9 Cryptography Secrets and Data Protection" in md

    def test_defense_in_depth_is_713(self, minimal_yaml_data):
        md = pf.gen_security_architecture(minimal_yaml_data)
        assert "### 6.13 Defense-in-Depth Summary" in md

    def test_identity_subsection_includes_matched_control(self, minimal_yaml_data):
        md = pf.gen_security_architecture(minimal_yaml_data)
        identity_section = re.search(r"### 6\.2 .+?(?=### 6\.3 )", md, re.DOTALL)
        assert identity_section is not None
        assert "Password-Based Authentication" in identity_section.group(0)

    def test_identity_section_has_subcontrol_block(self, minimal_yaml_data):
        """§6.2 decomposes discovered authentication mechanisms into H4 blocks."""
        md = pf.gen_security_architecture(minimal_yaml_data)
        identity_section = re.search(r"### 6\.2 .+?(?=### 6\.3 )", md, re.DOTALL)
        assert identity_section is not None
        body = identity_section.group(0)
        assert re.search(r"^#### 6\.2\.\d+\s+Password-Based Authentication\s*$", body, re.MULTILINE)
        assert "**Security assessment**" in body
        assert "**Relevant findings**" in body

    def test_empty_control_catalog_keeps_required_auth_session_flow_scaffolds(self):
        """v2 still emits §6.2/§6.3 flow anchors when the catalog is empty.

        The Composer enforces schema_v2.domain_required_patterns for these
        sections, so the pregenerator must provide a fillable scaffold instead
        of a not-applicable stub.
        """
        md = pf.gen_security_architecture(
            {
                "components": [],
                "security_controls": [],
            }
        )
        identity_section = re.search(r"### 6\.2 .+?(?=### 6\.3 )", md, re.DOTALL)
        assert identity_section is not None
        identity_body = identity_section.group(0)
        assert "#### 6.2.1 Password Login" in identity_body
        assert "sequenceDiagram" in identity_body

        session_section = re.search(r"### 6\.3 .+?(?=### 6\.4 )", md, re.DOTALL)
        assert session_section is not None
        session_body = session_section.group(0)
        assert "#### 6.3.1 JWT Session Issuance and Verification" in session_body
        assert "sequenceDiagram" in session_body

    def test_section_73_with_non_flow_controls_still_gets_diagram(self):
        """Regression (2026-06-16): §6.3 populated with storage/cookie/revocation
        controls (non-flow-like names) took the per-subcontrol path whose diagram
        is gated on flow-like naming, so no sequenceDiagram landed and
        compose --strict failed the §6.3 domain_required_pattern. The
        section-scoped guarantee must inject one regardless of control naming."""
        md = pf.gen_security_architecture(
            {
                "components": [],
                "security_controls": [
                    {
                        "domain": "6.3 Session and Token Controls",
                        "control": "JWT storage",
                        "effectiveness": "Unsafe",
                        "cwe": "CWE-922",
                    },
                    {
                        "domain": "6.3 Session and Token Controls",
                        "control": "Token revocation",
                        "effectiveness": "Missing",
                        "cwe": "CWE-613",
                    },
                    {
                        "domain": "6.3 Session and Token Controls",
                        "control": "Cookie attributes",
                        "effectiveness": "Weak",
                        "cwe": "CWE-1004",
                    },
                ],
            }
        )
        session_section = re.search(r"### 6\.3 .+?(?=### 6\.4 )", md, re.DOTALL)
        assert session_section is not None
        assert "sequenceDiagram" in session_section.group(0)


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

    def test_no_components_subsection_without_selection(self, minimal_yaml_data):
        md = pf.gen_out_of_scope(minimal_yaml_data)
        assert "Components Not Individually Analyzed" not in md

    def test_renders_excluded_components_subsection(self, minimal_yaml_data):
        minimal_yaml_data["meta"]["component_selection"] = {
            "analyzed": 2,
            "total": 3,
            "excluded": [
                {"id": "worker", "name": "Background Worker", "reason": "out-of-scope at depth=quick"},
            ],
        }
        md = pf.gen_out_of_scope(minimal_yaml_data)
        assert "### Components Not Individually Analyzed" in md
        assert "2 of 3 components analyzed" in md
        assert "| worker | Background Worker | out-of-scope at depth=quick |" in md

    def test_excluded_components_reason_pipe_escaped(self, minimal_yaml_data):
        minimal_yaml_data["meta"]["component_selection"] = {
            "excluded": [{"id": "w", "name": "W", "reason": "a | b"}],
        }
        md = pf.gen_out_of_scope(minimal_yaml_data)
        assert "a \\| b" in md

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
# Tier classification (helper used by §2 + §6)
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
            # Conditional generators are written ONLY when their gate fires,
            # which the minimal (threat-free) fixture does not trip:
            #   • ms-ai-exposure.json     — needs an LLM/AI surface
            #   • ms-critical-attack-tree.json — needs ≥2 Critical findings
            #   • ms-verdict.json         — needs ≥1 citable threat (fixture has none)
            if name in ("ms-ai-exposure.json", "ms-critical-attack-tree.json", "ms-verdict.json"):
                assert not (frag_dir / name).exists(), f"{name} must not be written when its gate is not tripped"
                continue
            assert (frag_dir / name).is_file(), f"{name} not written"

    def test_idempotent_skips_existing(self, output_dir):
        # First run writes all 7 (6 composer fragments + _chain-skeleton.md helper).
        _run_cli(str(output_dir))
        # Second non-force run skips every MECHANICAL fragment. The one
        # exception is the still-UNFILLED security-architecture.md scaffold,
        # which self-heals against the current yaml (stale-scaffold fix
        # 2026-06-16) — so exactly one fragment regenerates and the rest skip.
        result = _run_cli(str(output_dir))
        assert result.returncode == 0
        expected = f"skipped {len(pf.GENERATORS) - 1}"
        assert expected in result.stdout
        # Once narrative-filled, security-architecture.md is preserved too →
        # a subsequent non-force run skips ALL fragments.
        frag = output_dir / ".fragments" / "security-architecture.md"
        frag.write_text("### 6.2 Identity\nfilled, no placeholders\n")
        result2 = _run_cli(str(output_dir))
        assert result2.returncode == 0
        assert f"skipped {len(pf.GENERATORS)}" in result2.stdout

    def test_force_overwrites(self, output_dir):
        _run_cli(str(output_dir))
        # Mutate a file
        target = output_dir / ".fragments" / "system-overview.md"
        target.write_text("MUTATED\n")
        # --force should overwrite
        result = _run_cli(str(output_dir), "--force")
        assert result.returncode == 0
        # The conditional generators (ms-ai-exposure.json — no LLM surface;
        # ms-critical-attack-tree.json — <2 Criticals; ms-verdict.json — no
        # citable threat) are not part of the written set even with --force,
        # because their gate is not tripped by the minimal (threat-free) fixture.
        conditional = {"ms-ai-exposure.json", "ms-critical-attack-tree.json", "ms-verdict.json"}
        unconditional = [n for n in pf.GENERATORS if n not in conditional]
        expected = f"wrote {len(unconditional)}"
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
            str(output_dir),
            "--force",
            "--allow-narrative-loss",
            "--only",
            "security-architecture.md",
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

    def test_unfilled_scaffold_regenerates_without_force(self, output_dir):
        """Stale-scaffold self-heal (2026-06-16): a NON-force pregen of an
        UNFILLED security-architecture.md scaffold must regenerate it from the
        CURRENT yaml — otherwise a scaffold written early (Analyst-A, before
        emit_auth_coverage backfills auth mechanisms) survives stale into Stage 2
        and §6.2/§6.3 lose the new mechanisms' flow blocks. A narrative-FILLED
        fragment is still preserved (separate test below)."""
        frag = output_dir / ".fragments" / "security-architecture.md"
        # 1. Early scaffold (no §6.2 auth-mechanism controls yet).
        _run_cli(str(output_dir), "--only", "security-architecture.md")
        assert "NARRATIVE_PLACEHOLDER" in frag.read_text()
        assert "Password-Based Login" not in frag.read_text()
        # 2. emit_auth_coverage-style backfill: add §6.2 mechanism control.
        ydata = yaml.safe_load((output_dir / "threat-model.yaml").read_text())
        ydata.setdefault("security_controls", []).append(
            {
                "domain": "6.2 Identity and Authentication Controls",
                "control": "Password-Based Login",
                "kind": "mechanism",
                "effectiveness": "Unsafe",
                "cwe": "CWE-287",
            }
        )
        (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(ydata))
        # 3. NON-force pregen → must regenerate and pick up the new mechanism.
        result = _run_cli(str(output_dir), "--only", "security-architecture.md")
        assert result.returncode == 0
        assert "Password-Based Login" in frag.read_text()

    def test_filled_scaffold_preserved_without_force(self, output_dir):
        """The self-heal must NOT clobber a narrative-filled fragment on a
        non-force pregen (no NARRATIVE_PLACEHOLDER markers → preserve)."""
        frag = output_dir / ".fragments" / "security-architecture.md"
        _run_cli(str(output_dir), "--only", "security-architecture.md")
        frag.write_text("### 6.2 Identity\nFILLED-SENTINEL — no placeholders\n")
        result = _run_cli(str(output_dir), "--only", "security-architecture.md")
        assert result.returncode == 0
        assert "FILLED-SENTINEL" in frag.read_text()

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
# Section 6.2 — Threat Hypotheses Requiring Validation
# (arch.md §Renderer-Rules + Section 6.2 block)
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
    """ "Threat Hypotheses Requiring Validation" is disabled in the report
    (juice-shop 2026-07-03 user request): every row read Evidence/Validation
    from the wrong field name (`evidence`/`validation_objective` instead of
    the actual `positive_signals[]`), so it always rendered "_?_" placeholders
    regardless of how much real evidence a hypothesis had — no value in this
    form. `_render_threat_hypotheses_table` is still defined for whenever it's
    redesigned; `gen_security_architecture` no longer calls it, so these tests
    lock in that it stays absent from the rendered report. See
    docs/internal/analysis/proposal-threat-hypotheses-promotion.md for what
    re-enabling it actually requires (linked Findings, not a bare hypothesis
    list) before removing these "stays absent" assertions."""

    def test_table_absent_when_no_hypotheses(self, minimal_yaml_data):
        md = pf.gen_security_architecture(minimal_yaml_data)
        assert "Threat Hypotheses Requiring Validation" not in md

    def test_table_absent_even_when_hypotheses_exist(self):
        md = pf.gen_security_architecture(_data_with_hyps(_hyp()))
        assert "Threat Hypotheses Requiring Validation" not in md
        assert "HYP-001" not in md

    def test_controls_covered_bullet_list_has_no_dangling_link(self):
        """The mechanically-derived '**Controls covered:**' list scans the H4
        headings actually emitted — with the table disabled, it must never
        link to the now-nonexistent hypotheses heading."""
        md = pf.gen_security_architecture(_data_with_hyps(_hyp()))
        assert "#threat-hypotheses-requiring-validation" not in md


class TestSecurityArchitectureV2:
    """§6 v2 generator — verdict semantics (Unsafe vs Missing), the verdict
    legend, per-sub-control Status badges, and grouped password lifecycle.
    Added 2026-05 with the §6 verdict/structure redesign."""

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
                        {
                            "title": "Login",
                            "effectiveness": "Unsafe",
                            "status_note": "raw SQL login lookup allows authentication bypass",
                            "relevant_findings": ["T-001"],
                        },
                        {
                            "title": "Password Storage",
                            "effectiveness": "Unsafe",
                            "status_note": "unsalted MD5",
                            "relevant_findings": ["T-012"],
                        },
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
        # (2026-06-02 §6.1 fix).
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
        # match the H4 `#### 6.2.1 …` (which contains the substring "### 6.2").
        seg = md.split("\n### 6.2 ")[1].split("\n### 6.3 ")[0]
        assert "Password-Based Authentication" in seg
        # the lifecycle stages render as bullets, NOT as peer H4s
        assert any(l.startswith("- **Login** — 🔴 Unsafe") for l in seg.splitlines())
        assert seg.count("\n#### ") == 1, "password lifecycle must be ONE grouped H4"
        # grouped H4 still carries the two required labels
        assert "**Security assessment**" in seg and "**Relevant findings**" in seg

    @staticmethod
    def _section_containing(md: str, needle: str) -> str:
        """Return the `### 6.x` block (header→next H3/H2) that contains needle.

        Skips §6.1 — the Security Control Overview table now names controls in
        its 'Main reason' cells, so a control name appears there too; tests want
        the control's OWN §6.x block, not the overview row."""
        import re as _re

        blocks = _re.split(r"(?m)^(?=### 6\.\d+ )", md)
        for b in blocks:
            if b.startswith("### 6.") and not b.startswith("### 6.1 ") and needle in b:
                return b.split("\n## ")[0]
        raise AssertionError(f"no §6 block contains {needle!r}")

    @staticmethod
    def _covered_labels(section: str) -> list:
        import re as _re

        cc = next((l for l in section.splitlines() if l.startswith("**Controls covered:**")), "")
        return _re.findall(r"\[([^\]]+)\]\(#", cc)

    @staticmethod
    def _h4_titles(section: str) -> list:
        import re as _re

        return [_re.sub(r"^\d+(?:\.\d+)*\s+", "", h).strip() for h in _re.findall(r"(?m)^#### (.+)$", section)]

    def test_controls_covered_lists_only_emitted_h4s(self):
        """B1 regression: a control suppressed by _emit_v2_subcontrol_legacy
        (Missing + no findings + no implementation) must NOT appear in the
        `**Controls covered:**` line — otherwise it is a dangling link the
        control_subsection_coverage gate flags and the re-render loop cannot
        self-heal (juice-shop 2026-06-01 §6.4/§6.10)."""
        data = {
            "components": [],
            "threats": [{"id": "T-008", "cwe": "CWE-352", "title": "CSRF"}],
            "security_controls": [
                {
                    "domain": "Authorization Controls",
                    "control": "Role-Based Access Control",
                    "effectiveness": "Missing",
                    "linked_threats": ["T-008"],
                },
                {
                    "domain": "Authorization Controls",
                    "control": "CSRF Protection",
                    "effectiveness": "Missing",
                },  # suppressed: no findings, no impl
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

    def test_all_suppressed_section_still_emits_h4_blocks(self):
        """A §6.x section whose controls would ALL be suppressed must still
        emit them as H4 blocks rather than shipping empty.

        Previously this case dropped the `**Controls covered:**` line and left
        the section with zero `####` blocks. That avoided dangling links but
        produced the one shape qa_checks.check_control_subsection_coverage
        rejects as BLOCKING: the section HAS catalogued controls, so the
        `_Not applicable_` exemption does not apply and "no #### control
        subsections found" fails the gate — an unwinnable repair loop, because
        the only content that could satisfy it is what was just dropped
        (insecure-ai-app §6.3, 2026-07-19). The no-dangling-link guarantee is
        preserved by emitting the H4s so every link resolves.
        """
        data = {
            "components": [],
            "threats": [],
            "security_controls": [
                {"domain": "Authorization Controls", "control": "CSRF Protection", "effectiveness": "Missing"},
            ],
        }
        md = pf.gen_security_architecture_v2(data)
        assert "__CONTROLS_COVERED_SENTINEL__" not in md
        seg = self._section_containing(md, "CSRF Protection")

        # The gate's hard requirement: at least one H4 in the section.
        titles = [re.sub(r"^\d+(?:\.\d+)*\s+", "", t).strip() for t in re.findall(r"^#### (.+)$", seg, re.M)]
        assert titles, "section shipped with zero #### blocks — control_subsection_coverage would fail"
        assert "CSRF Protection" in titles

        # Original intent retained: every covered link resolves to an emitted H4.
        assert "**Controls covered:**" in seg
        covered_line = seg.split("**Controls covered:**", 1)[1].split("\n", 1)[0]
        for lab in re.findall(r"\[([^\]]+)\]\(#[^)]+\)", covered_line):
            assert lab in titles, f"dangling covered link {lab!r}; H4s={titles}"

        # The suppressed-controls note lists controls that were actually
        # dropped; nothing was dropped here, so it must not appear.
        assert "Additional cataloged controls" not in seg


class TestV2SectionRouting:
    """`_v2_canonical_section_for_control` routes controls to §6 sections by
    domain. Regression: hyphenated hints (`file-parser`) never matched the
    space-form canonical domain Stage 1 writes ("File Parser and Outbound
    Request Controls"), so a control whose NAME also lacked a hint token was
    dropped from §6 entirely (juice-shop 2026-06-01 §6.10)."""

    def test_canonical_domain_routes_even_without_hint_in_name(self):
        # "File Upload Validation" carries no §6.10 hint token in its name,
        # but its domain IS the canonical §6.10 title → must route to §6.10.
        c = {"control": "File Upload Validation", "domain": "File Parser and Outbound Request Controls"}
        assert pf._v2_canonical_section_for_control(c) == "6.10 File Parser and Outbound Request Controls"

    def test_data_access_domain_does_not_collide_with_authorization(self):
        # Guard against the substring trap: §6.4 hint "access-control" must NOT
        # steal a §6.5 control whose domain ends "...Data Access Controls".
        c = {"control": "SQL Parameterization (Sequelize ORM)", "domain": "Query Construction and Data Access Controls"}
        assert pf._v2_canonical_section_for_control(c) == "6.5 Query Construction and Data Access Controls"

    def test_hint_fallback_still_works_for_partial_domain(self):
        # Non-canonical / shorthand domain still routes via the hint fallback.
        c = {"control": "SSRF guard", "domain": "ssrf"}
        assert pf._v2_canonical_section_for_control(c) == "6.10 File Parser and Outbound Request Controls"


# ---------------------------------------------------------------------------
# §6.2 Authentication Mechanisms inventory (2026-05-31, deterministic)
# ---------------------------------------------------------------------------


def _auth_yaml():
    """A yaml fixture exercising mechanisms across the §6.2/§6.3/§6.9 domains."""
    return {
        "meta": {"open_user_registration": True},
        "security_controls": [
            {
                "control": "Password Authentication (Login)",
                "domain": "Identity and Authentication Controls",
                "effectiveness": "weak",
            },
            {
                "control": "Session Token Validation (JWT Based)",
                "domain": "Session and Token Controls",
                "effectiveness": "partial",
            },
            {
                "control": "Password Hashing",
                "domain": "Cryptography Secrets and Data Protection",
                "effectiveness": "missing",
            },
        ],
        "threats": [
            {"id": "T-001", "title": "JWT forgery via hardcoded RSA private key", "cwe": "CWE-321", "risk": "Critical"},
            {"id": "T-024", "title": "TOTP secrets stored in plaintext in database", "cwe": "CWE-312", "risk": "High"},
            {
                "id": "T-029",
                "title": "Admin account registration via role field manipulation",
                "cwe": "CWE-269",
                "risk": "High",
            },
            {
                "id": "T-007",
                "title": "MD5 password hashing enables offline password recovery",
                "cwe": "CWE-916",
                "risk": "Critical",
            },
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
    # JWT assessed under §6.3, hashing under §6.9, registration under §6.2.
    assert "[§6.3](#63-session-and-token-controls)" in block
    assert "[§6.9](#69-cryptography-secrets-and-data-protection)" in block
    assert "[§6.2](#62-identity-and-authentication-controls)" in block


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
        "security_controls": [
            {"control": "Output Encoding / XSS Prevention", "domain": "Output Encoding", "effectiveness": "weak"}
        ],
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
    assert re.search(r"\[F-001\]\(#f-001\) — \S", block), (
        "§6.2 inventory finding link must carry a title, not a bare ID"
    )


class TestAttackSurfaceLinkPrecision:
    """§5 attack-surface auto-linker precision (2026-06-04 regression).

    The substring scorer used to award the +3 evidence bonus on a coincidental
    shared generic token (`order` ⊂ `b2bOrder`, `login` ⊂ `saveLoginIp`),
    attaching Critical findings (notevil RCE, login SQLi) to unrelated routes
    once the route inventory expanded §5 to dozens of paths. The fix scores +3
    only on a route↔handler signal that survives camelCase word splitting.
    """

    def _threat(self, tid, evfile, title="x", text="x"):
        return {
            "id": tid,
            "title": title,
            "scenario": text,
            "description": text,
            "evidence": [{"file": evfile, "line": 1}],
        }

    def test_word_set_splits_camelcase_and_separators(self):
        # "b2b" splits into b/2/b (each < 3 chars, dropped) → only "order" survives;
        # that is enough — order-history shares just {order} with b2bOrder.
        assert pf._word_set("b2bOrder") == {"order"}
        assert pf._word_set("/rest/order-history") == {"order", "history"}
        assert pf._word_set("profileImageUrlUpload") == {"profile", "image", "url", "upload"}
        assert pf._word_set("/rest/user/login") == {"user", "login"}

    def test_generic_shared_token_no_longer_links(self):
        # order-history must NOT match a b2bOrder finding (shared word: "order").
        b2b = self._threat("T-005", "routes/b2bOrder.ts")
        assert pf._score_threat_path_match(b2b, "/rest/order-history") < 3
        # saveLoginIp must NOT match login.ts (login ⊂ saveLoginIp).
        login = self._threat("T-006", "routes/login.ts")
        assert pf._score_threat_path_match(login, "/rest/saveLoginIp") < 3

    def test_genuine_route_handler_matches_still_link(self):
        # Segment-name match: /rest/track-order ↔ trackOrder.ts.
        assert pf._score_threat_path_match(self._threat("T-013", "routes/trackOrder.ts"), "/rest/track-order/:id") >= 3
        # Segment-name match: /rest/user/login ↔ login.ts.
        assert pf._score_threat_path_match(self._threat("T-006", "routes/login.ts"), "/rest/user/login") >= 3
        # Hyphen↔camel whole-name match: /file-upload ↔ fileUpload.ts.
        assert pf._score_threat_path_match(self._threat("T-009", "routes/fileUpload.ts"), "/file-upload") >= 3
        # ≥2 shared words: /profile/image/url ↔ profileImageUrlUpload.ts.
        assert (
            pf._score_threat_path_match(self._threat("T-022", "routes/profileImageUrlUpload.ts"), "/profile/image/url")
            >= 3
        )

    def test_derive_drops_spurious_keeps_real_on_mixed_set(self):
        threats = [
            self._threat("T-005", "routes/b2bOrder.ts", "notevil RCE", "vm sandbox order"),
            self._threat("T-013", "routes/trackOrder.ts", "$where", "nosql track order"),
        ]
        # track-order keeps its own finding, not the b2bOrder one.
        links = pf._derive_attack_surface_links({"entry_point": "GET /rest/track-order/:id"}, threats)
        assert "T-013" in links and "T-005" not in links
        # order-history matches neither.
        assert pf._derive_attack_surface_links({"entry_point": "GET /rest/order-history"}, threats) == []


class TestWrappableRoute:
    """Long attack-surface routes get zero-width break opportunities so they
    wrap instead of forcing the Route column unreadably wide (user 2026-06)."""

    def test_short_route_untouched(self):
        assert pf._wrappable_route("/rest/user/login") == "/rest/user/login"

    def test_long_route_gets_zwsp_after_separators(self):
        route = "/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked"
        out = pf._wrappable_route(route)
        assert "​" in out
        # ZWSP is invisible — stripping it returns the original route verbatim.
        assert out.replace("​", "") == route
        # A break opportunity after every slash.
        assert out.count("​") >= route.count("/")


def test_system_overview_renders_component_selection_transparency():
    mod = _load_module()
    comps = [
        {"id": "web", "name": "Web Frontend"},
        {"id": "auth", "name": "Auth Service"},
        {"id": "worker", "name": "Worker"},
        {"id": "db", "name": "Database"},
    ]
    cs = {
        "mode": "criteria",
        "analyzed": 2,
        "total": 4,
        "selected": [
            {"id": "web", "name": "Web Frontend", "reasons": ["frontend attack surface (mandatory)"]},
            {"id": "auth", "name": "Auth Service", "reasons": ["auth (M3.4 mandatory)"]},
        ],
        "excluded": [
            {"id": "worker", "name": "Worker", "reason": "out-of-scope at depth=standard"},
            {"id": "db", "name": "Database", "reason": "out-of-scope at depth=standard"},
        ],
    }
    yaml_data = {"meta": {"project": {"name": "Acme"}, "component_selection": cs}, "components": comps}
    out = mod.gen_system_overview(yaml_data)
    assert "**2 of 4**" in out
    assert "not individually analyzed" in out
    assert "Worker" in out and "Database" in out
    assert "Selection criteria" in out


def test_system_overview_no_selection_falls_back_to_plain_scope():
    mod = _load_module()
    comps = [{"id": "a", "name": "A"}]
    out = mod.gen_system_overview({"meta": {"project": {"name": "X"}}, "components": comps})
    assert "covers 1 component of X" in out


# ---------------------------------------------------------------------------
# Coverage campaign additions (2026-06-14)
# Target the large uncovered blocks: legacy boundary-driven §2.4 mermaid,
# filesystem ghost-nodes, layer tables (per-layer split), the v2 control
# emitters (grouped / subcontrol / legacy), heading verdicts, and the
# §6.2 auth-mechanism inventory.
# ---------------------------------------------------------------------------


class TestTechnologyArchitectureMermaidLegacy:
    """`_technology_architecture_mermaid` boundary-driven path (only reached
    when the contract has NO `diagram_compactness."2.4 ..."` opt-in). We
    monkeypatch `_load_diagram_compactness` to {} so the legacy builder runs."""

    @pytest.fixture(autouse=True)
    def _no_compact(self, monkeypatch):
        monkeypatch.setattr(pf, "_load_diagram_compactness", lambda: {})

    def test_stub_when_no_boundaries(self):
        out = pf._technology_architecture_mermaid({}, [], [])
        # Falls back to the TB1/TB2/TB3 stub.
        assert out == pf._technology_architecture_stub()
        assert any("Public Internet" in l for l in out)

    def test_boundary_subgraphs_and_cross_boundary_edge(self):
        components = [
            {"id": "spa", "name": "Angular SPA", "tier": "client"},
            {"id": "api", "name": "Express API", "tier": "application"},
            {"id": "db", "name": "SQLite", "tier": "data"},
        ]
        boundaries = [
            {"id": "TB-INTERNET", "name": "Public Internet", "trust_level": "untrusted"},
            {"id": "TB-APP", "name": "App Process", "trust_level": "trusted"},
            {"id": "TB-DATA", "name": "Data Tier", "trust_level": "restricted"},
        ]
        yaml_data = {
            "components": components,
            "trust_boundaries": boundaries,
            "data_flows": [
                {"from": "spa", "to": "api", "protocol": "https", "auth_method": "JWT", "data_classification": "PII"},
                {"from": "api", "to": "db", "protocol": "websocket"},
            ],
            "threats": [
                {"id": "T-1", "component_id": "api", "risk": "critical"},
                {"id": "T-2", "component_id": "api", "risk": "critical"},
                {"id": "T-3", "component_id": "api", "risk": "critical"},
                {"id": "T-4", "component_id": "db", "risk": "high"},
                {"id": "T-5", "component_id": "db", "risk": "high"},
            ],
        }
        out = pf._technology_architecture_mermaid(yaml_data, components, boundaries)
        joined = "\n".join(out)
        assert out[0] == "```mermaid"
        assert "subgraph" in joined
        # untrusted→trusted crossing uses the thick arrow
        assert "==>|" in joined
        # async (websocket) crossing between trusted/data uses the dashed arrow
        assert "-.->|" in joined
        # critical/warning classDefs emitted (api has 3 critical, db has 2 high)
        assert "classDef critical" in joined
        assert "class" in joined

    def test_no_cross_boundary_flows_emits_comment(self):
        components = [{"id": "api", "name": "API", "tier": "application"}]
        boundaries = [{"id": "TB-APP", "name": "App", "trust_level": "trusted"}]
        out = pf._technology_architecture_mermaid(
            {"components": components, "trust_boundaries": boundaries}, components, boundaries
        )
        assert any("No cross-boundary data flows" in l for l in out)

    def test_filesystem_ghost_nodes_rendered(self):
        components = [{"id": "api", "name": "API", "tier": "application"}]
        boundaries = [
            {"id": "TB-APP", "name": "App", "trust_level": "trusted"},
            {"id": "TB-FS", "name": "Filesystem Storage", "trust_level": "restricted"},
        ]
        # Use a real fs-prefix so a ghost node is derived.
        prefixes = pf._load_fs_route_prefixes()
        yaml_data = {"components": components, "trust_boundaries": boundaries}
        if prefixes:
            ep = prefixes[0] + "/secret.bak"
            yaml_data["attack_surface"] = {"unauthenticated": [{"endpoint": "GET " + ep}]}
        out = pf._technology_architecture_mermaid(yaml_data, components, boundaries)
        joined = "\n".join(out)
        # filesystem subgraph present
        assert "Filesystem Storage" in joined
        if prefixes:
            assert "see §5.1" in joined

    def test_component_engine_annotation_and_name_dedup(self):
        components = [
            {"id": "db", "name": "Data Store", "tier": "data", "engine": "PostgreSQL"},
            {"id": "db2", "name": "Redis cache", "tier": "data", "engine": "Redis"},
        ]
        boundaries = [{"id": "TB-DATA", "name": "Data Tier", "trust_level": "restricted"}]
        out = pf._technology_architecture_mermaid(
            {"components": components, "trust_boundaries": boundaries}, components, boundaries
        )
        joined = "\n".join(out)
        # engine not in name → appended on its own line
        assert "PostgreSQL" in joined
        # engine already in name (case-insensitive) → not duplicated
        assert joined.count("Redis") == 1


class TestFilesystemPathsPerBoundary:
    def test_no_fs_boundary_returns_empty(self):
        boundaries = [{"id": "TB-APP", "name": "App Process"}]
        assert pf._filesystem_paths_per_boundary({}, boundaries) == {}

    def test_no_matching_routes_returns_empty(self):
        boundaries = [{"id": "TB-FS", "name": "Filesystem"}]
        yaml_data = {"attack_surface": {"unauthenticated": [{"endpoint": "GET /api/users"}]}}
        assert pf._filesystem_paths_per_boundary(yaml_data, boundaries) == {}

    def test_matching_prefix_yields_stem(self):
        prefixes = pf._load_fs_route_prefixes()
        if not prefixes:
            pytest.skip("no fs prefixes configured")
        boundaries = [{"id": "TB-FS", "name": "Filesystem Storage"}]
        ep = prefixes[0].rstrip("/") + "/dump.bak"
        yaml_data = {"attack_surface": {"unauthenticated": [{"path": ep}]}}
        result = pf._filesystem_paths_per_boundary(yaml_data, boundaries)
        assert "TB-FS" in result
        assert result["TB-FS"], "expected at least one stem"

    def test_unauth_dict_with_entries_key(self):
        prefixes = pf._load_fs_route_prefixes()
        if not prefixes:
            pytest.skip("no fs prefixes configured")
        boundaries = [{"id": "TB-DISK", "name": "disk store"}]
        ep = prefixes[0].rstrip("/") + "/x"
        yaml_data = {"attack_surface": {"unauthenticated": {"entries": [{"route": ep}]}}}
        result = pf._filesystem_paths_per_boundary(yaml_data, boundaries)
        assert "TB-DISK" in result


class TestLoadFsRoutePrefixes:
    def test_returns_tuple_of_slash_prefixes(self):
        prefixes = pf._load_fs_route_prefixes()
        assert isinstance(prefixes, tuple)
        for p in prefixes:
            assert p.startswith("/")


class TestRenderLayerTables:
    """`_render_layer_tables` — consolidated (≤5 comps) and per-layer (>5)."""

    def _comp(self, cid, tier, threat_ids=None):
        return {"id": cid, "name": cid.upper(), "tier": tier, "threat_ids": threat_ids or []}

    def test_consolidated_when_few_components(self):
        comps = [self._comp("a", "client"), self._comp("b", "application")]
        yaml_data = {"components": comps, "threats": []}
        out = pf._render_layer_tables(yaml_data, comps)
        joined = "\n".join(out)
        # consolidated layout has the single 'Layer' header, not per-layer H4s
        assert "| Component | Layer | Linked Threats | Risk |" in joined
        assert "#### 2.4.1" not in joined

    def test_per_layer_split_when_many_components(self):
        comps = [
            self._comp("c1", "client", ["T-1"]),
            self._comp("c2", "client"),
            self._comp("a1", "application", ["T-2"]),
            self._comp("a2", "application"),
            self._comp("d1", "data"),
            self._comp("d2", "data"),
        ]
        threats = [
            {"id": "T-1", "title": "Client XSS", "severity": "high", "cwe": "CWE-79"},
            {"id": "T-2", "title": "Auth bypass", "severity": "critical", "cwe": "CWE-287"},
        ]
        yaml_data = {"components": comps, "threats": threats}
        out = pf._render_layer_tables(yaml_data, comps)
        joined = "\n".join(out)
        assert "#### 2.4.1 Layer 1 Client" in joined
        assert "#### 2.4.4 Layer 4 Data" in joined
        # linked threats rendered with finding-label links + risk emoji
        assert "🟠 High" in joined or "🔴 Critical" in joined

    def test_forward_index_fallback_when_no_reverse_links(self):
        # components carry no threat_ids; threats reference component via field.
        comps = [self._comp("api", "application")]
        threats = [{"id": "T-009", "title": "SQLi", "severity": "critical", "component": "api"}]
        yaml_data = {"components": comps, "threats": threats}
        out = pf._render_layer_tables(yaml_data, comps)
        joined = "\n".join(out)
        # T-009 normalises to the canonical visible F-009 label.
        assert "F-009" in joined

    def test_empty_layer_placeholder_in_split_view(self):
        # 6 comps all in one tier → other layers render the placeholder row.
        comps = [self._comp(f"a{i}", "application") for i in range(6)]
        yaml_data = {"components": comps, "threats": []}
        out = pf._render_layer_tables(yaml_data, comps)
        joined = "\n".join(out)
        assert "_no components in this layer_" in joined


class TestControlVerdictForHeading:
    def test_empty_when_no_control_no_threat(self):
        assert pf._control_verdict_for_heading("6.2 X", {}, []) == ""

    def test_status_and_severity_combined(self):
        heading = "6.2 Identity and Authentication Controls"
        threats_by_section = {heading: [{"severity": "critical"}, {"severity": "low"}]}
        controls = [{"domain": "Identity and Authentication Controls", "effectiveness": "missing"}]
        out = pf._control_verdict_for_heading(heading, threats_by_section, controls)
        assert "Missing" in out
        assert "🔴" in out and "Critical" in out

    def test_threats_without_mapped_control_default_weak(self):
        heading = "6.5 Data Controls"
        threats_by_section = {heading: [{"risk": "high"}]}
        out = pf._control_verdict_for_heading(heading, threats_by_section, [])
        assert "Weak" in out
        assert "🟠" in out and "High" in out

    def test_status_only_when_no_threats(self):
        heading = "6.9 Crypto"
        controls = [{"domain": "Crypto", "effectiveness": "partial"}]
        out = pf._control_verdict_for_heading(heading, {}, controls)
        assert out == " — Partial"


class TestV2StatusLine:
    def test_unknown_effectiveness_full_placeholder(self):
        line = pf._v2_status_line("", "")
        assert line.startswith("**Status:**")
        assert "NARRATIVE_PLACEHOLDER" in line

    def test_known_with_note_is_deterministic(self):
        line = pf._v2_status_line("unsafe", "defeated by alg:none")
        assert line == "**Status:** 🔴 Unsafe — defeated by alg:none"

    def test_known_without_note_has_clause_placeholder(self):
        line = pf._v2_status_line("adequate")
        assert "🟢 Adequate" in line
        assert "NARRATIVE_PLACEHOLDER" in line


class TestV2LifecycleBullets:
    def test_bullets_carry_status_note_and_findings(self):
        subs = [
            {
                "title": "Login",
                "effectiveness": "unsafe",
                "status_note": "raw SQL. extra.",
                "relevant_findings": ["T-001"],
            },
            {"title": "Storage", "effectiveness": "weak"},
        ]
        out = pf._v2_lifecycle_bullets(subs, [], "6.2 Auth")
        assert any(l.startswith("- **Login** — 🔴 Unsafe.") for l in out)
        # note truncated to first clause + period
        assert any("raw SQL." in l for l in out)
        # finding link appended
        assert any("[F-001](#f-001)" in l for l in out)
        # missing note → placeholder
        assert any("NARRATIVE_PLACEHOLDER" in l for l in out)


class TestEmitV2GroupedControl:
    def test_grouped_block_with_diagram_and_findings(self):
        lines: list[str] = []
        c = {
            "control": "Password-Based Authentication",
            "effectiveness": "unsafe",
            "effectiveness_reason": "broken everywhere",
            "implementation": "Login routes through one MD5 sink.",
            "assessment": "Shared root cause in hashing.",
            "sequence_diagram": "sequenceDiagram\n  A->>B: login",
        }
        subs = [
            {"title": "Login", "effectiveness": "unsafe", "relevant_findings": ["T-001"]},
            {"title": "Storage", "effectiveness": "unsafe", "relevant_findings": [{"id": "T-002"}]},
        ]
        pf._emit_v2_grouped_control(lines, c, subs, [], "6.2 Identity", section_id="6.2", idx=1)
        joined = "\n".join(lines)
        assert "#### 6.2.1 Token-Based" not in joined  # name is the family, not friendly-mapped here
        assert "**Security assessment**" in joined
        assert "**Relevant findings**" in joined
        assert "```mermaid" in joined
        assert "[F-001](#f-001)" in joined and "[F-002](#f-002)" in joined

    def test_grouped_block_placeholders_when_minimal(self):
        lines: list[str] = []
        c = {"control": "Password-Based Authentication", "effectiveness": "missing"}
        subs = [{"title": "Login", "effectiveness": "missing"}]
        threats = [{"id": "T-005", "cwe": "CWE-287", "title": "bypass"}]
        pf._emit_v2_grouped_control(lines, c, subs, threats, "6.2 Identity and Authentication Controls")
        joined = "\n".join(lines)
        # bare heading (no section_id/idx)
        assert joined.startswith("#### ")
        assert "NARRATIVE_PLACEHOLDER" in joined  # impl + assessment + diagram placeholders
        # CWE-routed fallback finding link present
        assert "[F-005](#f-005)" in joined

    def test_grouped_block_no_findings_anywhere(self):
        lines: list[str] = []
        c = {"control": "Some Control", "effectiveness": "weak"}
        subs = [{"title": "Stage", "effectiveness": "weak"}]
        pf._emit_v2_grouped_control(lines, c, subs, [], "6.6 Misc")
        joined = "\n".join(lines)
        assert "No dedicated finding routed in this assessment." in joined


class TestEmitV2SubcontrolBlock:
    def test_full_block_all_fields(self):
        lines: list[str] = []
        sub = {
            "title": "JWT authentication",
            "effectiveness": "unsafe",
            "status_note": "alg:none accepted",
            "implementation": "Tokens verified with express-jwt.",
            "sequence_diagram": "sequenceDiagram\n A->>B: token",
            "assessment": "RS256 not pinned.",
            "code_excerpt": "jwt.verify(t)",
            "code_language": "ts",
            "relevant_findings": [{"id": "T-001", "rationale": "alg confusion"}, "T-002"],
        }
        pf._emit_v2_subcontrol_block(lines, sub, [], "6.3 Session", section_id="6.3", idx=2)
        joined = "\n".join(lines)
        assert "#### 6.3.2 Token-Based Session Authentication (JWT)" in joined
        assert '<a id="' in joined
        assert "```mermaid" in joined
        assert "```ts" in joined
        assert "[F-001](#f-001) - alg confusion" in joined
        assert "[F-002](#f-002)" in joined

    def test_flow_type_diagram_placeholder(self):
        lines: list[str] = []
        sub = {"title": "Login", "type": "flow"}
        pf._emit_v2_subcontrol_block(lines, sub, [], "6.2 Identity and Authentication Controls")
        joined = "\n".join(lines)
        assert joined.startswith("#### Login")
        # missing impl/assessment + flow diagram placeholder
        assert joined.count("NARRATIVE_PLACEHOLDER") >= 2

    def test_string_relevant_findings_and_cwe_fallback(self):
        lines: list[str] = []
        sub = {"title": "Validation", "effectiveness": "weak", "relevant_findings": "T-007"}
        pf._emit_v2_subcontrol_block(lines, sub, [], "6.6 Input")
        joined = "\n".join(lines)
        assert "[F-007](#f-007)" in joined

    def test_no_findings_fallback_line(self):
        lines: list[str] = []
        sub = {"title": "X", "effectiveness": "adequate", "assessment": "ok"}
        pf._emit_v2_subcontrol_block(lines, sub, [], "6.11 Logging")
        joined = "\n".join(lines)
        assert "No dedicated finding routed in this assessment." in joined


class TestEmitV2SubcontrolLegacy:
    def test_suppressed_missing_no_threats(self):
        lines: list[str] = []
        c = {"effectiveness": "missing"}
        emitted = pf._emit_v2_subcontrol_legacy(lines, c, "CSRF Protection", [], "6.4 Authorization")
        assert emitted is False
        assert lines == []

    def test_emitted_with_linked_threats(self):
        lines: list[str] = []
        c = {"effectiveness": "weak", "linked_threats": ["T-003"], "implementation": "Uses helmet."}
        emitted = pf._emit_v2_subcontrol_legacy(
            lines, c, "Login", "irrelevant", "6.2 Identity", section_id="6.2", idx=1
        )
        assert emitted is True
        joined = "\n".join(lines)
        assert "#### 6.2.1 Login" in joined
        assert "Uses helmet." in joined
        assert "[F-003](#f-003)" in joined
        # flow-like name (login) → sequenceDiagram placeholder + code-excerpt placeholder
        assert "sequenceDiagram" in joined

    def test_emitted_missing_but_routed_finding(self):
        lines: list[str] = []
        c = {"effectiveness": "missing"}
        threats = [{"id": "T-008", "cwe": "CWE-862", "title": "missing authz"}]
        emitted = pf._emit_v2_subcontrol_legacy(lines, c, "Generic Control", threats, "6.4 Authorization Controls")
        assert emitted is True
        joined = "\n".join(lines)
        assert "NARRATIVE_PLACEHOLDER" in joined  # impl + assessment placeholders


class TestAuthMechanismInventory:
    def test_empty_when_no_mechanism(self):
        assert pf._build_auth_mechanism_inventory({"threats": [], "security_controls": []}) == []

    def test_inventory_table_with_status_and_absent_note(self):
        yaml_data = {
            "security_controls": [
                {"control": "Password Login", "domain": "Identity", "effectiveness": "weak"},
            ],
            "threats": [
                {"id": "T-12", "title": "MD5 password hash", "cwe": "CWE-916", "risk": "high"},
            ],
            "meta": {"open_user_registration": True},
        }
        out = pf._build_auth_mechanism_inventory(yaml_data)
        joined = "\n".join(out)
        assert "Authentication mechanisms (at a glance)" in joined
        assert "| Mechanism | Status | Assessed in | Findings |" in joined
        assert "Password login" in joined
        # registration present via meta flag
        assert "User registration" in joined
        # hashing present via threat keyword, badged by risk
        assert "Password storage (hashing)" in joined
        # mechanisms not detected listed in trailing note
        assert "Also checked, not detected" in joined

    def test_present_only_status_when_no_eff_no_risk(self):
        yaml_data = {
            "security_controls": [{"control": "OAuth adapter", "domain": "Identity", "effectiveness": ""}],
            "threats": [],
        }
        out = pf._build_auth_mechanism_inventory(yaml_data)
        joined = "\n".join(out)
        assert "✅ Present" in joined


class TestAuthMechFindingLink:
    def test_none_when_no_number(self):
        assert pf._auth_mech_finding_link({"id": "no-digits"}) is None

    def test_link_with_title(self):
        out = pf._auth_mech_finding_link({"id": "T-7", "title": "JWT forgery"})
        assert out == "[F-007](#f-007) — JWT forgery"

    def test_link_without_title(self):
        out = pf._auth_mech_finding_link({"t_id": "T-3"})
        assert out == "[F-003](#f-003)"


class TestFriendlySubcontrolTitle:
    def test_strips_trailing_parenthetical(self):
        assert pf._friendly_subcontrol_title("X Control (express-jwt / lib)") == "X Control"

    def test_maps_known_terse_name(self):
        assert pf._friendly_subcontrol_title("Query Construction") == "Database Query Construction"

    def test_empty_passthrough(self):
        assert pf._friendly_subcontrol_title("") == ""


class TestNormalizeSecurityControls:
    def test_string_control_synthesized(self):
        out = pf._normalize_security_controls(["input_validation"])
        assert len(out) == 1
        assert out[0]["_synthesized_from_string"] is True
        assert out[0]["domain"] == "input_validation"

    def test_dict_passthrough_and_blank_skipped(self):
        out = pf._normalize_security_controls([{"domain": "X"}, "", None])
        assert out == [{"domain": "X"}]


class TestDeriveEnforcement:
    def test_internet_boundary_tls(self):
        assert pf._derive_enforcement({"name": "Public Internet"}) == "TLS"

    def test_process_boundary(self):
        assert pf._derive_enforcement({"name": "Express Process"}) == "Process isolation"

    def test_data_boundary(self):
        assert pf._derive_enforcement({"description": "sqlite database tier"}) == "ORM / driver-only access"

    def test_filesystem_boundary(self):
        assert pf._derive_enforcement({"name": "filesystem"}) == "OS file permissions"

    def test_trust_level_fallback(self):
        assert pf._derive_enforcement({"trust_level": "trusted"}) == "Network ACL / runtime"

    def test_non_dict_returns_empty(self):
        assert pf._derive_enforcement("nope") == ""


class TestThreatCountsPerComponent:
    def test_counts_critical_and_high(self):
        yaml_data = {
            "threats": [
                {"component_id": "a", "risk": "critical"},
                {"component": "a", "severity": "high"},
                {"component_id": "b", "risk": "low"},
                {"risk": "critical"},  # no component → dropped
            ]
        }
        crit, high = pf._threat_counts_per_component(yaml_data)
        assert crit == {"a": 1}
        assert high == {"a": 1}


class TestIsAsyncProtocol:
    def test_websocket_is_async(self):
        assert pf._is_async_protocol("WebSocket") is True

    def test_https_is_sync(self):
        assert pf._is_async_protocol("https") is False


class TestV2GroupedAndSubcontrolViaGenerator:
    """Drive gen_security_architecture_v2 through the subcontrols (non-grouped)
    path so _emit_v2_subcontrol_block is exercised end-to-end."""

    def test_subcontrols_emitted_as_peer_h4s(self):
        data = {
            "components": [],
            "threats": [{"id": "T-1", "cwe": "CWE-89", "title": "SQLi"}],
            "security_controls": [
                {
                    "domain": "Identity and Authentication Controls",
                    "control": "Authentication",
                    "effectiveness": "weak",
                    "subcontrols": [
                        {
                            "title": "Login",
                            "effectiveness": "weak",
                            "implementation": "x",
                            "relevant_findings": ["T-1"],
                        },
                        {"title": "Logout", "effectiveness": "adequate", "implementation": "y"},
                    ],
                },
            ],
        }
        md = pf.gen_security_architecture_v2(data)
        assert "#### 6.2.1" in md
        assert "#### 6.2.2" in md

    def test_quick_depth_skips_empty_sections(self):
        data = {"components": [], "threats": [], "security_controls": []}
        md = pf.gen_security_architecture_v2(data, depth="quick")
        # still emits the chapter heading + overview
        assert md.startswith("## 6. Security Architecture")


class TestOverviewVerdictBranches:
    """Exercise the §6.1 overview verdict/reason branches: partial, adequate,
    weak-no-controls."""

    def test_partial_verdict_row(self):
        data = {
            "components": [],
            "threats": [],
            "security_controls": [
                {"domain": "Identity and Authentication Controls", "control": "Login", "effectiveness": "partial"},
            ],
        }
        md = pf.gen_security_architecture_v2(data)
        row = next(l for l in md.splitlines() if l.startswith("| [") and "Identity and Authentication" in l)
        assert "🟡 Partial" in row
        assert "leave gaps" in row

    def test_adequate_verdict_row(self):
        data = {
            "components": [],
            "threats": [],
            "security_controls": [
                {"domain": "Identity and Authentication Controls", "control": "Login", "effectiveness": "adequate"},
            ],
        }
        md = pf.gen_security_architecture_v2(data)
        row = next(l for l in md.splitlines() if l.startswith("| [") and "Identity and Authentication" in l)
        assert "🟢 Adequate" in row
        assert "no routed findings" in row

    def test_weak_no_controls_routed_finding(self):
        # A finding routes to §6.4 (CWE-862 authz) but no control catalogued there.
        data = {
            "components": [],
            "threats": [{"id": "T-1", "cwe": "CWE-862", "title": "BOLA"}],
            "security_controls": [],
        }
        md = pf.gen_security_architecture_v2(data)
        rows = [l for l in md.splitlines() if l.startswith("| [")]
        weak = [l for l in rows if "🟠 Weak" in l]
        assert weak, "expected a weak-from-routed-finding row"
        assert any("no compensating controls catalogued" in l for l in weak)


class TestClassifyTierBoundary:
    """`_classify_tier` must match hints at a token boundary, not as bare
    substrings. Regression for the §2.2 9-node diagram_compactness trip: the
    `ui` hint false-matched `b·ui·ld/**` and `j·ui·ceshop.sqlite`, pulling the
    backend and data components into the `client` tier, emptying the data tier,
    and emitting a redundant fallback `DATA` node (8 real components + 1 fallback
    = 9 > max 8).
    """

    def test_ui_hint_does_not_match_build_path(self):
        comp = {"id": "express-backend", "name": "Express Backend API", "paths": ["server.ts", "routes/**", "build/**"]}
        assert pf._classify_tier(comp) == "application"

    def test_ui_hint_does_not_match_juiceshop_sqlite(self):
        comp = {"id": "data-layer", "name": "Data Layer", "paths": ["models/**", "data/juiceshop.sqlite"]}
        assert pf._classify_tier(comp) == "data"

    def test_prefix_hints_still_match(self):
        # mongo→mongodb and sql→sqlite must still resolve to the data tier.
        assert pf._classify_tier({"id": "x", "name": "x", "paths": ["data/mongodb.ts"]}) == "data"
        assert pf._classify_tier({"id": "y", "name": "y", "paths": ["store/cache.sqlite"]}) == "data"

    def test_spa_still_client(self):
        assert pf._classify_tier({"id": "angular-spa", "name": "Angular SPA", "paths": ["frontend/src/**"]}) == "client"

    def test_eight_components_no_fallback_data_node(self):
        # 8 real components with one genuine data-tier component must yield a
        # diagram with no synthetic BROWSER/APP/DATA fallback node (≤8 nodes).
        data = {
            "meta": {"project": {"name": "JS"}},
            "components": [
                {"id": "angular-spa", "name": "Angular SPA", "paths": ["frontend/src/**"]},
                {"id": "express-backend", "name": "Express Backend", "paths": ["server.ts", "build/**"]},
                {"id": "file-upload-service", "name": "File Upload", "paths": ["routes/fileUpload.ts"]},
                {"id": "b2b-api", "name": "B2B API", "paths": ["routes/b2bOrder.ts"]},
                {"id": "auth", "name": "Auth", "paths": ["lib/insecurity.ts"]},
                {"id": "ci-cd-pipeline", "name": "CI/CD", "paths": [".github/workflows/**"]},
                {"id": "realtime-channel", "name": "Realtime", "paths": ["lib/startup/registerWebsocketEvents.ts"]},
                {"id": "data-layer", "name": "Data Layer", "paths": ["models/**", "data/juiceshop.sqlite"]},
            ],
            "threats": [],
        }
        frag = pf.gen_architecture_diagrams(data)
        block = re.search(r"### 2\.2 Container Architecture.*?```mermaid(.*?)```", frag, re.S).group(1)
        node_ids = set(re.findall(r"^\s*([A-Za-z0-9_]+)[\[(]", block, re.M))
        assert "DATA" not in node_ids and "APP" not in node_ids and "BROWSER" not in node_ids
        assert len(node_ids) <= 8, f"expected ≤8 nodes, got {sorted(node_ids)}"


class TestContainerDiagramNodeCap:
    """Regression (2026-07-18 juice-shop): `gen_architecture_diagrams` emitted
    one §2.2 node per component with NO ceiling, so a 9-component model shipped
    a `diagram_compactness` violation that no re-render could clear — the repair
    plan's own "regenerate from the Pre-Generator, it obeys the limits by
    construction" remedy reproduced the violation verbatim.
    """

    @staticmethod
    def _yaml(n_app: int, threats: list | None = None) -> dict:
        comps = [
            {"id": "angular-spa", "name": "Angular SPA", "paths": ["frontend/src/**"]},
            {"id": "data-layer", "name": "Data Layer", "paths": ["models/**", "data/app.sqlite"]},
        ]
        comps += [{"id": f"svc-{i}", "name": f"Service {i}", "paths": [f"routes/svc{i}.ts"]} for i in range(n_app)]
        return {"meta": {"project": {"name": "JS"}}, "components": comps, "threats": threats or []}

    @staticmethod
    def _block(frag: str) -> str:
        return re.search(r"### 2\.2 Container Architecture.*?```mermaid(.*?)```", frag, re.S).group(1)

    def test_twelve_components_capped_to_contract_maximum(self):
        frag = pf.gen_architecture_diagrams(self._yaml(n_app=10))
        node_ids = set(re.findall(r"^\s*([A-Za-z0-9_]+)[\[(]", self._block(frag), re.M))
        assert len(node_ids) <= 8, f"expected ≤8 nodes, got {sorted(node_ids)}"

    def test_every_tier_keeps_at_least_one_node(self):
        block = self._block(pf.gen_architecture_diagrams(self._yaml(n_app=10)))
        node_ids = set(re.findall(r"^\s*([A-Za-z0-9_]+)[\[(]", block, re.M))
        # Client and data tiers must survive the trim — the layered topology is
        # the point of the diagram.
        assert "angular_spa" in node_ids
        assert "data_layer" in node_ids

    def test_highest_risk_components_survive_the_trim(self):
        threats = [{"component_id": "svc-9", "risk": "critical"} for _ in range(4)]
        frag = pf.gen_architecture_diagrams(self._yaml(n_app=10, threats=threats))
        node_ids = set(re.findall(r"^\s*([A-Za-z0-9_]+)[\[(]", self._block(frag), re.M))
        assert "svc_9" in node_ids, "the component carrying 4 Criticals must not be trimmed"

    def test_no_class_line_references_a_trimmed_node(self):
        threats = [{"component_id": "svc-9", "risk": "critical"} for _ in range(4)]
        block = self._block(pf.gen_architecture_diagrams(self._yaml(n_app=10, threats=threats)))
        declared = set(re.findall(r"^\s*([A-Za-z0-9_]+)[\[(]", block, re.M))
        classed = set(re.findall(r"^\s*class\s+([A-Za-z0-9_]+)\s", block, re.M))
        assert classed <= declared, f"class lines reference undeclared nodes: {sorted(classed - declared)}"

    def test_no_edge_references_a_trimmed_node(self):
        block = self._block(pf.gen_architecture_diagrams(self._yaml(n_app=10)))
        declared = set(re.findall(r"^\s*([A-Za-z0-9_]+)[\[(]", block, re.M))
        edges = re.findall(r"^\s*([A-Za-z0-9_]+)\s*[-.=]+>\s*\|[^|]*\|\s*([A-Za-z0-9_]+)", block, re.M)
        referenced = {n for edge in edges for n in edge}
        assert referenced <= declared, f"edges reference trimmed nodes: {sorted(referenced - declared)}"

    def test_trimmed_components_are_named_not_silently_dropped(self):
        frag = pf.gen_architecture_diagrams(self._yaml(n_app=10))
        assert "Not shown" in frag
        assert "#23-components" in frag

    def test_small_model_is_untouched_and_carries_no_note(self):
        frag = pf.gen_architecture_diagrams(self._yaml(n_app=3))
        node_ids = set(re.findall(r"^\s*([A-Za-z0-9_]+)[\[(]", self._block(frag), re.M))
        assert len(node_ids) == 5
        assert "Not shown" not in frag

    def test_cap_helper_keeps_one_per_tier_when_budget_is_tighter_than_tiers(self):
        by_tier = {
            "client": [{"id": "c1"}, {"id": "c2"}],
            "application": [{"id": "a1"}, {"id": "a2"}],
            "data": [{"id": "d1"}],
        }
        capped, dropped = pf._cap_container_tiers(by_tier, {}, {}, max_nodes=2)
        assert [len(capped[t]) for t in ("client", "application", "data")] == [1, 1, 1]
        assert len(dropped) == 2


# ---------------------------------------------------------------------------
# RC-2 (2026-06-21 juice-shop): a §6.x section with routed findings but NO
# catalogued controls must ship a `**Controls covered:**` line that matches its
# fallback #### heading, so check_control_subsection_coverage passes WITHOUT an
# LLM repair pass. Previously the empty-controls branch emitted a free
# placeholder that baited the renderer into inventing mismatched control links.
# ---------------------------------------------------------------------------


def _load_qa():
    if "qa_checks" in sys.modules:
        return sys.modules["qa_checks"]
    spec = importlib.util.spec_from_file_location("qa_checks", REPO_ROOT / "scripts" / "qa_checks.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["qa_checks"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TestControlCoverageSparseFallback:
    def _yaml(self):
        # CWE-352 routes to §6.8 "Browser and Cross-Origin Controls".
        # Empty security_controls[] forces the empty-controls fallback path.
        return {
            "meta": {"project": {"name": "T", "description": "d"}},
            "components": [{"id": "frontend-spa", "name": "SPA", "paths": ["frontend/**"]}],
            "assets": [],
            "trust_boundaries": [],
            "attack_surface": {"unauthenticated": [], "authenticated": []},
            "security_controls": [],
            "threats": [
                {"id": "T-001", "cwe": "CWE-352", "title": "CSRF on state-changing route", "severity": "high"},
            ],
        }

    def test_78_fallback_emits_matching_controls_covered(self):
        md = pf.gen_security_architecture_v2(self._yaml(), "standard")
        assert "### 6.8 Browser and Cross-Origin Controls" in md
        sec = md.split("### 6.8", 1)[1].split("\n### ", 1)[0]
        assert "**Controls covered:**" in sec, "§6.8 fallback must keep a Controls-covered line"
        # The free placeholder that baited the LLM into inventing links is gone.
        assert "NARRATIVE_PLACEHOLDER: list concrete subcontrols" not in sec
        assert "####" in sec, "§6.8 fallback must emit at least one #### heading"

    def test_78_passes_real_control_coverage_gate(self, tmp_path):
        qa = _load_qa()
        md = pf.gen_security_architecture_v2(self._yaml(), "standard")
        p = tmp_path / "threat-model.md"
        p.write_text(md, encoding="utf-8")
        report = qa.check_control_subsection_coverage(p)
        flagged = [i for i in report.issues if "6.8" in i]
        assert not flagged, f"§6.8 still trips control_subsection_coverage: {flagged}"
