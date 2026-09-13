"""
Characterization tests for scripts/auto_emitter_pass.sh (P3, 2026-06-20).

The auto-emitter pass is the controller-owned deterministic enrichment tail.
These tests pin its ordering and invocation contract:

  * the script runs the SAME fixed sequence of deterministic emitters, in order;
  * it honours the DRY_RUN=false guard and the tee-to-.agent-run.log contract;
  * the compact controller calls the script instead of inlining the block.

The emitters themselves are unit-tested elsewhere; here we only verify the
orchestration wrapper (sequence, guard, logging, exit code) is intact.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).parent.parent
SCRIPT = PLUGIN_ROOT / "scripts" / "auto_emitter_pass.sh"
CONTROLLER = PLUGIN_ROOT / "scripts" / "orchestration_controller.py"

# The exact emitter sequence lifted from the inline block — order is contractual
# (comments in the script explain each "runs AFTER/BEFORE" dependency).
EXPECTED_SEQUENCE = [
    "validate_evidence_lines.py",
    "emit_meta_findings.py",
    "emit_review_mitigations.py",
    "emit_config_scan_mitigations.py",
    "emit_finding_fix_mitigations.py",
    "emit_clean_finding_titles.py",
    "emit_general_mitigation_titles.py",
    "hydrate_mitigation_details.py",
    "sanitize_perimeter_claims.py",
    "reclassify_components.py",
    "enforce_control_taxonomy.py",
    "emit_auth_coverage.py",
    "emit_threat_vektors.py",
    "emit_severity_rationale.py",
    "detect_open_registration.py",
    "detect_public_repo.py",
    "enrich_asset_links.py",
    "secret_scan.py",
]

MINIMAL_YAML = "meta: {}\nthreats: []\nsecurity_controls: []\nassets: []\nmitigations: []\n"


def test_script_exists_with_shebang():
    assert SCRIPT.exists(), "auto_emitter_pass.sh must exist"
    assert SCRIPT.read_text(encoding="utf-8").startswith("#!/usr/bin/env bash")


def test_emitter_sequence_preserved_in_order():
    """The extracted script must run every emitter the inline block did, in the
    same order — that is what makes the extraction byte-for-byte behaviour."""
    body = SCRIPT.read_text(encoding="utf-8")
    positions = []
    for name in EXPECTED_SEQUENCE:
        idx = body.find(name)
        assert idx != -1, f"{name} missing from auto_emitter_pass.sh"
        positions.append(idx)
    assert positions == sorted(positions), "emitter calls are out of order vs the inline original"


def test_dry_run_guard_and_tee_contract_present():
    body = SCRIPT.read_text(encoding="utf-8")
    assert 'if [ "$DRY_RUN" = "false" ]; then' in body, "DRY_RUN=false guard must be preserved"
    assert 'tee -a "$OUTPUT_DIR/.agent-run.log"' in body, "tee-to-log contract must be preserved"
    assert "AUTO_EMITTER_START" in body and "AUTO_EMITTER_END" in body


def test_controller_calls_script_not_inline():
    """The active context-v2 finalizer must retain the deterministic pass."""
    controller = CONTROLLER.read_text(encoding="utf-8")
    assert 'str(SCRIPT_DIR / "auto_emitter_pass.sh")' in controller
    assert "_run_auto_emitter_pass(output_dir, cfg, receipts)" in controller
    assert '"emit_meta_findings.py"' not in controller


def test_smoke_run_logs_markers_and_preserves_yaml(tmp_path):
    """Golden-input smoke: a minimal valid yaml runs clean (exit 0), both markers
    land in .agent-run.log, and the yaml still parses afterwards (best-effort
    emitters never corrupt it)."""
    yaml = pytest.importorskip("yaml")
    (tmp_path / "threat-model.yaml").write_text(MINIMAL_YAML, encoding="utf-8")
    res = subprocess.run(
        ["bash", str(SCRIPT), str(tmp_path), str(tmp_path), str(PLUGIN_ROOT), "false"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"script must exit 0 (best-effort); stderr:\n{res.stderr}"
    log = (tmp_path / ".agent-run.log").read_text(encoding="utf-8")
    assert "AUTO_EMITTER_START" in log and "AUTO_EMITTER_END" in log
    # yaml is still loadable — no emitter corrupted it.
    assert yaml.safe_load((tmp_path / "threat-model.yaml").read_text(encoding="utf-8")) is not None


def test_refuted_candidate_is_removed_before_emitters_derive_links(tmp_path):
    """The active YAML never retains a refuted finding or its review card."""
    yaml = pytest.importorskip("yaml")
    data = yaml.safe_load(MINIMAL_YAML)
    data["threats"] = [
        {
            "id": "T-001",
            "title": "Refuted SQL injection",
            "risk": "High",
            "cwe": "CWE-89",
            "source": "stride",
            "component": "api",
            "evidence": [{"file": "missing.ts", "line": 1}],
            "evidence_check": "refuted",
        }
    ]
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    res = subprocess.run(
        ["bash", str(SCRIPT), str(tmp_path), str(tmp_path), str(PLUGIN_ROOT), "false"],
        capture_output=True,
        text=True,
    )

    assert res.returncode == 0, res.stderr
    written = yaml.safe_load((tmp_path / "threat-model.yaml").read_text(encoding="utf-8"))
    assert written["threats"] == []
    assert not any(m.get("auto_source") == "evidence-check-refuted" for m in written["mitigations"])


def test_smoke_dry_run_is_noop(tmp_path):
    """DRY_RUN=true must skip the whole pass — no markers, no log."""
    (tmp_path / "threat-model.yaml").write_text(MINIMAL_YAML, encoding="utf-8")
    res = subprocess.run(
        ["bash", str(SCRIPT), str(tmp_path), str(tmp_path), str(PLUGIN_ROOT), "true"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    log_path = tmp_path / ".agent-run.log"
    log = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
    assert "AUTO_EMITTER_START" not in log, "DRY_RUN=true must not run the emitter pass"


@pytest.mark.parametrize("route", ["/register", "/auth/signup"])
def test_repeated_pass_does_not_duplicate_cards_or_controls(tmp_path, route):
    import json

    import yaml
    from enrichment_pass import valid_receipt

    data = yaml.safe_load(MINIMAL_YAML)
    data["threats"] = [
        {
            "id": "T-001",
            "title": "Missing request validation",
            "risk": "High",
            "cwe": "CWE-20",
            "mitigation_title": "Validate request fields",
            "source": "stride",
            "remediation": {
                "steps": ["Validate incoming fields against the request schema."],
                "verification": "Submit an unexpected field and confirm rejection.",
            },
        }
    ]
    sidecar = {"routes": [{"method": "POST", "path": route}]}
    inv_path = tmp_path / ".route-inventory.json"
    inv_path.write_text(json.dumps(sidecar))
    path = tmp_path / "threat-model.yaml"
    path.write_text(yaml.safe_dump(data))
    models = []
    for _ in range(2):
        result = subprocess.run(
            ["bash", str(SCRIPT), str(tmp_path), str(tmp_path), str(PLUGIN_ROOT), "false"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        models.append(yaml.safe_load(path.read_text()))
        assert valid_receipt(models[-1])
    for key in ("threats", "mitigations", "security_controls"):
        assert len(models[0][key]) == len(models[1][key])
    assert models[1]["threats"][0]["vektor"]
    assert json.loads(inv_path.read_text()) == sidecar
