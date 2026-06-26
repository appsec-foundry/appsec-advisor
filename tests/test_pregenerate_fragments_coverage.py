"""Coverage-extension tests for scripts/pregenerate_fragments.py.

Focus: in-process exercise of main() (the CLI driver) plus helper /
render branches that the subprocess-based suite in
test_pregenerate_fragments.py cannot reach for line-coverage purposes.

All tests pin CURRENT behaviour. No producer edits.
"""

from __future__ import annotations

import importlib.util
import json
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
# Rich yaml fixture — exercises many helper branches in one pass.
# ---------------------------------------------------------------------------


@pytest.fixture
def rich_yaml_data():
    return {
        "meta": {
            "project": {
                "name": "RichApp",
                "description": "Rich application for coverage tests",
                "runtime": "Node.js 20",
                "repository": "https://example.com/repo",
            },
            "scope": {"out_of_scope": ["DNS infra", "End-user devices"]},
            "externals": [
                {"id": "stripe", "name": "Stripe", "category": "payment", "direction": "outbound"},
                {"id": "auth0", "name": "Auth0", "category": "identity provider", "direction": "inbound"},
                {"id": "webhook-x", "name": "WebhookX", "category": "webhook", "direction": "bidirectional"},
                {"id": "obj-store", "name": "S3", "category": "storage", "direction": "out"},
            ],
        },
        "components": [
            {
                "id": "rest-api",
                "name": "REST API",
                "type": "application",
                "description": "Node.js/TypeScript Express app server",
                "paths": ["server.ts", "routes/**"],
                "threat_ids": ["F-001", "F-002"],
            },
            {
                "id": "auth-mw",
                "name": "Auth Middleware",
                "type": "middleware",
                "description": "express-jwt middleware chain CORS rate-limit",
                "paths": ["middleware/auth.ts"],
                "threat_ids": ["F-003"],
            },
            {
                "id": "frontend-spa",
                "name": "Frontend SPA",
                "type": "client",
                "description": "Angular SPA browser frontend",
                "paths": ["frontend/**"],
                "threat_ids": [],
            },
            {
                "id": "data-layer",
                "name": "Data Layer",
                "type": "data",
                "description": "SQLite3 via Sequelize ORM persistence",
                "paths": ["models/**"],
                "threat_ids": ["F-004"],
            },
            {
                "id": "marsdb",
                "name": "MarsDB Store",
                "type": "data",
                "description": "MarsDB in-process store",
                "paths": ["data/marsdb.ts"],
                "threat_ids": [],
            },
            {
                "id": "ci-cd",
                "name": "CI/CD Pipeline",
                "type": "infrastructure",
                "description": "GitHub Actions build pipeline",
                "paths": [".github/workflows/ci.yml"],
                "threat_ids": [],
            },
        ],
        "trust_boundaries": [
            {"id": "TB-001", "name": "Public Internet", "description": "external user browser", "enforcement": "WAF"},
            {"id": "TB-002", "name": "SPA to REST API", "description": "rest api process boundary", "enforcement": ""},
            {"id": "TB-003", "name": "Data Tier", "description": "database persistence sqlite", "enforcement": "ORM"},
        ],
        "assets": [
            {
                "id": "A-001",
                "name": "User credentials",
                "classification": "Critical",
                "description": "Email + hash",
                "linked_threats": ["T-001", "F-002"],
            },
            {
                "name": "Session tokens",
                "classification": "High",
                "description": "JWT tokens",
            },
            {"id": "A-003", "name": "Config", "classification": "Low", "description": "app config"},
        ],
        "attack_surface": {
            "unauthenticated": [
                {
                    "method": "GET",
                    "route": "/api/products",
                    "auth_required": False,
                    "notes": "Public listing (T-001)",
                    "linked_threats": ["T-001"],
                },
                {"entry_point": "POST /api/login", "auth_required": False, "notes": "login"},
            ],
            "authenticated": [
                {
                    "method": "DELETE",
                    "route": "/api/users/:id",
                    "auth_required": True,
                    "notes": "admin only",
                    "threats": ["F-002"],
                },
            ],
        },
        "threats": [
            {
                "id": "T-001",
                "title": "SQL Injection in product search — server.ts:42",
                "cwe": "CWE-89",
                "severity": "High",
                "component": "rest-api",
                "evidence": {
                    "file": "server.ts",
                    "line": 42,
                    "file_references": [{"file": "routes/products.ts"}],
                },
            },
            {
                "id": "T-002",
                "title": "Broken auth on admin route",
                "cwe": "CWE-287",
                "severity": "Critical",
                "component": "auth-mw",
                "evidence": {"file": "middleware/auth.ts", "line": 10},
            },
            {
                "id": "T-003",
                "title": "Missing rate limit",
                "cwe": "CWE-770",
                "severity": "Medium",
                "component": "rest-api",
                "evidence": [],
            },
            {
                "id": "T-004",
                "title": "XSS in product name",
                "cwe": "CWE-79",
                "severity": "High",
                "component": "frontend-spa",
            },
        ],
        "threat_hypotheses": [
            {
                "id": "H-001",
                "title": "Possible IDOR on user endpoint",
                "linked_control_ids": ["SC-001"],
                "evidence": [{"file": "routes/users.ts", "line": 88}, {"file": "routes/users.ts"}],
                "validation_objective": "Confirm authorization check exists on the /api/users/:id route handler before returning user data.",
            },
            {
                "id": "H-002",
                "title": "Mass assignment",
                "gaps": ["No whitelist"],
                "evidence": [],
                "validation_objective": "x" * 200,
            },
        ],
        "security_controls": [
            {
                "domain": "Identity and Authentication Controls",
                "control": "Password-Based Authentication",
                "implementation": "Express password login src/auth.ts",
                "effectiveness": "weak",
                "notes": "outdated bcrypt rounds",
            },
            {
                "domain": "Input Boundary Validation Controls",
                "control": "Validation Approach",
                "implementation": "manual checks",
                "effectiveness": "missing",
                "notes": "no validator",
            },
            {
                "domain": "Authorization and Access Control",
                "control": "Role-Based Access Control",
                "implementation": "middleware/rbac.ts",
                "effectiveness": "adequate",
                "notes": "",
            },
            {
                "domain": "Cryptography and Secrets Management",
                "control": "Encryption at Rest",
                "implementation": "n/a",
                "effectiveness": "strong",
                "notes": "AES-256",
            },
        ],
    }


@pytest.fixture
def rich_dir(tmp_path, rich_yaml_data):
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True)
    (out / "threat-model.yaml").write_text(yaml.safe_dump(rich_yaml_data))
    return out


# ---------------------------------------------------------------------------
# In-process main() — covers the CLI driver lines (5253-5400).
# ---------------------------------------------------------------------------


class TestMainInProcess:
    def test_clean_run_writes_all_fragments(self, rich_dir, capsys):
        rc = pf.main([str(rich_dir)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "pre-generate: wrote" in out
        frag_dir = rich_dir / ".fragments"
        assert frag_dir.is_dir()
        assert (frag_dir / "assets.md").is_file()
        assert (frag_dir / "security-architecture.md").is_file()

    def test_second_run_idempotent_skips(self, rich_dir, capsys):
        pf.main([str(rich_dir)])
        capsys.readouterr()
        rc = pf.main([str(rich_dir)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "already exists" in out

    def test_force_overwrites(self, rich_dir, capsys):
        pf.main([str(rich_dir)])
        capsys.readouterr()
        rc = pf.main([str(rich_dir), "--force", "--allow-narrative-loss"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "wrote" in out

    def test_dry_run_writes_nothing(self, rich_dir, capsys):
        rc = pf.main([str(rich_dir), "--dry-run"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "dry-run" in out
        assert not (rich_dir / ".fragments" / "assets.md").exists()

    def test_only_selects_subset(self, rich_dir, capsys):
        rc = pf.main([str(rich_dir), "--only", "assets.md,out-of-scope.md"])
        assert rc == 0
        frag = rich_dir / ".fragments"
        assert (frag / "assets.md").is_file()
        assert not (frag / "system-overview.md").exists()

    def test_only_unknown_fragment_returns_2(self, rich_dir, capsys):
        rc = pf.main([str(rich_dir), "--only", "bogus.md"])
        assert rc == 2
        err = capsys.readouterr().err
        assert "unknown fragment" in err

    def test_missing_output_dir_returns_2(self, tmp_path, capsys):
        nope = tmp_path / "nope"
        rc = pf.main([str(nope)])
        assert rc == 2
        assert "does not exist" in capsys.readouterr().err

    def test_missing_yaml_returns_1(self, tmp_path, capsys):
        d = tmp_path / "d"
        d.mkdir()
        rc = pf.main([str(d)])
        assert rc == 1
        assert "threat-model.yaml not found" in capsys.readouterr().err

    def test_malformed_yaml_returns_1(self, tmp_path, capsys):
        d = tmp_path / "d"
        d.mkdir()
        (d / "threat-model.yaml").write_text("a: [unbalanced\n  : :")
        rc = pf.main([str(d)])
        assert rc == 1
        assert "could not parse" in capsys.readouterr().err

    def test_non_dict_yaml_returns_1(self, tmp_path, capsys):
        d = tmp_path / "d"
        d.mkdir()
        (d / "threat-model.yaml").write_text("- just\n- a\n- list\n")
        rc = pf.main([str(d)])
        assert rc == 1
        assert "did not parse to a dict" in capsys.readouterr().err

    def test_depth_explicit_quick(self, rich_dir, capsys):
        rc = pf.main([str(rich_dir), "--depth", "quick"])
        assert rc == 0

    def test_depth_from_skill_config(self, rich_dir):
        (rich_dir / ".skill-config.json").write_text(json.dumps({"assessment_depth": "thorough"}))
        rc = pf.main([str(rich_dir)])
        assert rc == 0

    def test_depth_from_bad_skill_config_falls_back(self, rich_dir):
        (rich_dir / ".skill-config.json").write_text("{not json")
        rc = pf.main([str(rich_dir)])
        assert rc == 0

    def test_depth_unknown_value_falls_back_to_standard(self, rich_dir):
        (rich_dir / ".skill-config.json").write_text(json.dumps({"assessment_depth": "weird"}))
        rc = pf.main([str(rich_dir)])
        assert rc == 0

    def test_force_security_arch_refuses_without_allow_flag(self, rich_dir, capsys):
        # First produce the scaffold, then strip NARRATIVE_PLACEHOLDER markers
        # to simulate a Stage-2-filled fragment.
        pf.main([str(rich_dir), "--only", "security-architecture.md"])
        frag = rich_dir / ".fragments" / "security-architecture.md"
        text = frag.read_text(encoding="utf-8").replace("NARRATIVE_PLACEHOLDER", "filled")
        frag.write_text(text, encoding="utf-8")
        capsys.readouterr()
        rc = pf.main([str(rich_dir), "--force", "--only", "security-architecture.md"])
        assert rc == 2
        assert "refusing to --force overwrite" in capsys.readouterr().err

    def test_force_security_arch_with_allow_flag_overwrites(self, rich_dir, capsys):
        pf.main([str(rich_dir), "--only", "security-architecture.md"])
        frag = rich_dir / ".fragments" / "security-architecture.md"
        text = frag.read_text(encoding="utf-8").replace("NARRATIVE_PLACEHOLDER", "filled")
        frag.write_text(text, encoding="utf-8")
        capsys.readouterr()
        rc = pf.main([str(rich_dir), "--force", "--allow-narrative-loss", "--only", "security-architecture.md"])
        assert rc == 0

    def test_force_security_arch_still_with_placeholders_overwrites(self, rich_dir):
        # Scaffold still has NARRATIVE_PLACEHOLDER markers -> --force allowed.
        pf.main([str(rich_dir), "--only", "security-architecture.md"])
        rc = pf.main([str(rich_dir), "--force", "--only", "security-architecture.md"])
        assert rc == 0

    def test_generator_exception_returns_1(self, rich_dir, monkeypatch, capsys):
        def boom(yaml_data):
            raise RuntimeError("kaboom")

        monkeypatch.setitem(pf.GENERATORS, "assets.md", boom)
        rc = pf.main([str(rich_dir), "--only", "assets.md"])
        assert rc == 1
        assert "kaboom" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Generators against the rich fixture — exercises many helper branches.
# ---------------------------------------------------------------------------


class TestGeneratorsRich:
    def test_all_generators_run(self, rich_yaml_data):
        for name, fn in pf.GENERATORS.items():
            if name == "security-architecture.md":
                out = fn(rich_yaml_data, "standard")
            else:
                out = fn(rich_yaml_data)
            if name == "ms-ai-exposure.json":
                # Opt-out generator: returns None ("write nothing") when the
                # model has no LLM/AI surface. The rich fixture has none, so a
                # None here is the contract, not a failure.
                assert out is None or (isinstance(out, str) and out)
            else:
                assert isinstance(out, str) and out

    def test_system_overview_rich(self, rich_yaml_data):
        md = pf.gen_system_overview(rich_yaml_data)
        assert "RichApp" in md

    def test_architecture_diagrams_rich(self, rich_yaml_data):
        md = pf.gen_architecture_diagrams(rich_yaml_data)
        assert "## 2. Architecture Diagrams" in md

    def test_assets_with_linked_threats_column(self, rich_yaml_data):
        md = pf.gen_assets(rich_yaml_data)
        assert "Linked Threats" in md
        # auto-id fallback for the asset without an id
        assert "A-002" in md

    def test_attack_surface_rich(self, rich_yaml_data):
        md = pf.gen_attack_surface(rich_yaml_data)
        assert "/api/products" in md

    def test_security_architecture_v2_thorough(self, rich_yaml_data):
        md = pf.gen_security_architecture_v2(rich_yaml_data, "thorough")
        assert "## 7" in md or "Security Architecture" in md

    def test_security_architecture_v2_quick(self, rich_yaml_data):
        md = pf.gen_security_architecture_v2(rich_yaml_data, "quick")
        assert isinstance(md, str) and md

    def test_attack_walkthroughs_skeleton_rich(self, rich_yaml_data):
        md = pf.gen_attack_walkthroughs_skeleton(rich_yaml_data)
        assert isinstance(md, str) and md


# ---------------------------------------------------------------------------
# Targeted helper branch tests.
# ---------------------------------------------------------------------------


class TestHelperBranches:
    def test_to_canonical_finding_label_variants(self):
        assert pf._to_canonical_finding_label("T-007") == "F-007"
        assert pf._to_canonical_finding_label("F-009") == "F-009"
        assert pf._to_canonical_finding_label("not-an-id") == "not-an-id"
        # non-str passthrough
        assert pf._to_canonical_finding_label(123) == 123  # type: ignore[arg-type]

    def test_truncate_title_balanced(self):
        assert pf._truncate_title_balanced("short") == "short"
        long = "word `code spanning here but" + " x" * 40
        out = pf._truncate_title_balanced(long, max_len=20)
        assert out.endswith("…")
        # balanced backticks (even count) after truncation
        assert out.count("`") % 2 == 0

    def test_truncate_title_balanced_non_str(self):
        assert pf._truncate_title_balanced(None) == ""  # type: ignore[arg-type]

    def test_truncate_label_line(self):
        assert pf._truncate_label_line("hello", 10) == "hello"
        assert pf._truncate_label_line("hello world this is long", 8).endswith("…")
        assert pf._truncate_label_line(None, 5) == ""  # type: ignore[arg-type]

    def test_safe_node_id(self):
        out = pf._safe_node_id("My Service-Name.io")
        assert " " not in out

    def test_attack_surface_method(self):
        assert pf._attack_surface_method({"method": "post"}) == "post"
        assert pf._attack_surface_method({"entry_point": "DELETE /x"}) == "DELETE"
        assert pf._attack_surface_method({"entry_point": "weird thing"}) == "?"
        assert pf._attack_surface_method({}) == "?"

    def test_attack_surface_notes_combines(self):
        out = pf._attack_surface_notes({"notes": "see (T-001)", "linked_threats": ["T-001"]})
        assert "F-001" in out

    def test_attack_surface_notes_non_dict(self):
        assert pf._attack_surface_notes("nope") == ""  # type: ignore[arg-type]

    def test_count_routings_by_section(self):
        threats = [
            {"cwe": "CWE-89"},
            {"cwe": ""},
            {"cwe": "CWE-99999"},
            "not-a-dict",
        ]
        counts = pf._count_routings_by_section(threats)
        assert isinstance(counts, dict)

    def test_classify_tier(self):
        assert isinstance(pf._classify_tier({"type": "client"}), str)
        assert isinstance(pf._classify_tier({"type": "data"}), str)

    def test_components_by_tier(self):
        comps = [{"id": "a", "type": "client"}, {"id": "b", "type": "data"}]
        out = pf._components_by_tier(comps)
        assert isinstance(out, dict)

    def test_detect_tech_stack_rich(self, rich_yaml_data):
        out = pf._detect_tech_stack(rich_yaml_data, rich_yaml_data["components"])
        assert isinstance(out, dict)

    def test_v2_canonical_section_for_control_empty(self):
        assert pf._v2_canonical_section_for_control({}) == ""

    def test_v2_canonical_section_for_control_match(self):
        out = pf._v2_canonical_section_for_control(
            {"control": "Password Authentication", "name": "auth", "implementation": "login"}
        )
        assert isinstance(out, str)

    def test_chain_label_for_threat(self):
        assert pf._chain_label_for_threat({"title": ""}) == "—"
        out = pf._chain_label_for_threat({"title": "The SQL Injection in the search box — server.ts:42"})
        assert isinstance(out, str) and out != "—"

    def test_render_threat_hypotheses_table(self, rich_yaml_data):
        lines = pf._render_threat_hypotheses_table(rich_yaml_data)
        assert isinstance(lines, list)
        joined = "\n".join(lines)
        assert "H-001" in joined or "H-002" in joined

    def test_normalize_security_controls(self, rich_yaml_data):
        out = pf._normalize_security_controls(rich_yaml_data["security_controls"])
        assert isinstance(out, list)

    def test_proportional_separator(self):
        sep = pf._proportional_separator(20, 6, 12)
        assert sep.startswith("|")

    def test_load_diagram_compactness(self):
        out = pf._load_diagram_compactness()
        assert isinstance(out, dict)

    def test_load_posture_actor_labels(self):
        out = pf._load_posture_actor_labels_for_pregen()
        assert isinstance(out, dict)
