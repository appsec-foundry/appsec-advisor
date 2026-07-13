"""
Characterization tests for scripts/auto_emitter_pass.sh (P3, 2026-06-20).

The Auto-emitter pass was a 139-line inline Bash block in SKILL-impl.md. P3
extracts it verbatim into a script. These tests pin the extraction so it stays a
1:1 behaviour-preserving move:

  * the script runs the SAME fixed sequence of deterministic emitters, in order;
  * it honours the DRY_RUN=false guard and the tee-to-.agent-run.log contract;
  * SKILL-impl.md now calls the script instead of inlining the block.

The emitters themselves are unit-tested elsewhere; here we only verify the
orchestration wrapper (sequence, guard, logging, exit code) is intact.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).parent.parent
SCRIPT = PLUGIN_ROOT / "scripts" / "auto_emitter_pass.sh"
SKILL_IMPL = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md"

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


def test_skill_impl_calls_script_not_inline():
    """Drift guard: SKILL-impl.md must call the script and no longer inline the
    emitter sequence in its resident body."""
    impl = SKILL_IMPL.read_text(encoding="utf-8")
    assert "scripts/auto_emitter_pass.sh" in impl, "SKILL-impl.md must call auto_emitter_pass.sh"
    # The first emitter no longer appears as an inline python3 call in the skill body.
    assert 'emit_meta_findings.py" "$OUTPUT_DIR"' not in impl, (
        "the emitter sequence must live in the script, not inline in SKILL-impl.md"
    )


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
