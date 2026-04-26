"""Unit tests for scripts/pregenerate_fragments.py.

The pre-generator produces 6 deterministic structural fragments from
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
        assert "[T-001](#t-001)" in md
        assert "[T-003](#t-003)" in md

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
        # First run writes all 6
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
