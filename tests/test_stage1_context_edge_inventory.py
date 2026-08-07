"""Drift guards for the frozen pre-catalog Stage-1 context inventory."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import orchestration_controller as controller  # noqa: E402

INVENTORY = REPO_ROOT / "docs/internal/analysis/analysis-context-routing-control-plane-2026-08-07.md"


def _inventory_text() -> str:
    return INVENTORY.read_text(encoding="utf-8")


def _inventory_rows(prefix: str) -> dict[str, str]:
    rows: dict[str, str] = {}
    pattern = re.compile(rf"^\| `{re.escape(prefix)}:([^`]+)` \|.*$", re.MULTILINE)
    for match in pattern.finditer(_inventory_text()):
        key = match.group(1)
        assert key not in rows, f"duplicate {prefix} inventory row: {key}"
        rows[key] = match.group(0)
    return rows


def test_inventory_names_every_current_stage1_semantic_consumer():
    rows = _inventory_rows("consumer")
    assert set(rows) == set(controller.SEMANTIC_ROLE_REGISTRY) | {"abuse_case_verifier"}


def test_inventory_pins_declared_and_implicit_semantic_deliveries():
    rows = _inventory_rows("consumer")
    expected_markers = {
        "context_resolver": (".skill-config.json", ".requirements.yaml", "docs/related-repos.yaml"),
        "recon_scanner": (".skill-config.json", ".recon-patterns.json", "recon template"),
        "config_scanner": (".skill-config.json", "data/config-iac-checks.yaml", "direct-source"),
        "actor_discoverer": (".actors-merged-static.json", ".recon-summary.md", ".recon-signals.json"),
        "architecture_analyst": (".recon-summary.md", ".route-inventory.json", ".actors-resolved.json"),
        "trust_boundary_analyst": (".trust-boundary-assessment-input.json", "exact-byte receipt"),
        "control_analyst": (".components.json", ".trust-boundaries.json", ".architecture-coverage.json"),
        "stride_analyzer": ("evidence bundle", "taxonomy slice", "repository registry", "fixed lenses"),
        "threat_merger": (".merge-context/candidates.json", "64 groups", "full-source hash"),
        "evidence_verifier": (".threats-merged.json", "direct-source", "sample cap"),
        "triage_validator": (".threats-merged.json", ".triage-flags.json", ".recon-summary.md"),
        "post_stride_synthesizer": (".threats-merged.json", ".triage-flags.json", "synthesis keys"),
        "abuse_case_verifier": (".abuse-case-matches.json", "direct-source", "candidate IDs"),
    }
    for consumer, markers in expected_markers.items():
        for marker in markers:
            assert marker in rows[consumer], f"{consumer} inventory lost {marker}"


def test_inventory_pins_every_current_deterministic_stage1_edge():
    assert set(_inventory_rows("edge")) == {
        "preflight_run_config",
        "preflight_repository_signals",
        "requirements_resolution",
        "recon_projection",
        "related_repository_projection",
        "actor_resolution",
        "architecture_finalization",
        "boundary_promotion",
        "stride_dispatch_projection",
        "stride_merge_projection",
        "evidence_and_posture",
        "triage_and_synthesis",
        "stage1_yaml_handoff",
        "abuse_case_projection",
    }


def test_inventory_hidden_edges_still_exist_in_consumer_contracts():
    prompt_markers = {
        "agents/appsec-context-resolver.md": (
            ".requirements.yaml",
            "docs/known-threats.yaml",
            "docs/related-repos.yaml",
        ),
        "agents/appsec-recon-scanner.md": (
            ".recon-patterns.json",
            "data/scan-excludes.yaml",
            "agents/shared/recon-output-template.md",
        ),
        "agents/appsec-config-scanner.md": ("data/config-iac-checks.yaml",),
        "agents/appsec-actor-discoverer.md": (".recon-signals.json",),
        "agents/appsec-control-analyst.md": ("Requirements violations",),
        "agents/appsec-stride-analyzer-v2.md": ("path_routing.focus_paths", "path_routing.exclude_paths"),
        "agents/appsec-triage-validator.md": (".recon-summary.md", "data/critical-criteria.yaml"),
        "agents/appsec-abuse-case-verifier.md": ("MATCH_RESULT_PATH",),
    }
    for relative, markers in prompt_markers.items():
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        for marker in markers:
            assert marker in text, f"{relative} no longer contains inventoried edge {marker}"


def test_inventory_records_known_pre_catalog_gaps_without_claiming_migration():
    text = _inventory_text()
    for marker in (
        "Action `input_artifacts` do not describe all semantic inputs",
        "does not yet own every slice producer",
        "Stage 1d uses candidate IDs and prompt aliases",
        "catalog first runs in shadow mode",
    ):
        assert marker in text
