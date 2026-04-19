"""Tests for plugin/scripts/compose_threat_model.py — the contract-driven renderer.

These tests pin the invariants that make LLM structural drift impossible:

  * render() is deterministic — identical inputs produce byte-identical output
  * the canonical Management Summary section order is enforced
  * the Management Summary heading is unnumbered
  * a malformed verdict fragment raises a schema-validation error (hard gate)
  * a missing required fragment raises FragmentError
  * the Top Findings table column schema is exactly the contract's 7 columns
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT    = Path(__file__).parent.parent
SCRIPT_PATH  = REPO_ROOT / "plugin" / "scripts" / "compose_threat_model.py"
CONTRACT     = REPO_ROOT / "plugin" / "data"    / "sections-contract.yaml"
FIXTURE      = Path(__file__).parent / "fixtures" / "compose"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass introspection can resolve the module.
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


compose = _load_module("compose_threat_model", SCRIPT_PATH)


def _prepare_output_dir(tmp_path: Path) -> Path:
    """Copy the fixture into a temp dir so tests don't mutate tests/fixtures/."""
    out = tmp_path / "output"
    shutil.copytree(FIXTURE, out)
    return out


# ---------------------------------------------------------------------------
# Core rendering
# ---------------------------------------------------------------------------

def test_render_produces_canonical_ms_structure(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, warnings = compose.render(CONTRACT, out)

    assert warnings == [], f"unexpected warnings: {warnings}"

    # Management Summary must be unnumbered.
    assert "## Management Summary\n" in rendered
    assert "## 1. Management Summary" not in rendered

    # The five canonical sub-sections must appear, in order.
    expected_order = [
        "### Verdict",
        "### Top Findings",
        "### Architecture Assessment",
        "### Mitigations",
        "### Operational Strengths",
    ]
    positions = [rendered.find(h) for h in expected_order]
    assert all(p > 0 for p in positions), f"missing MS subsection(s): {expected_order} at {positions}"
    assert positions == sorted(positions), f"MS subsections out of order: {positions}"

    # No forbidden legacy headings anywhere in MS.
    ms_slice = rendered.split("## Management Summary", 1)[1].split("\n## ", 1)[0]
    for forbidden in ("### 1.1", "### Executive Overview", "### Risk Distribution",
                      "### Top Threats", "### Immediate Actions"):
        assert forbidden not in ms_slice, f"forbidden MS heading leaked: {forbidden!r}"


def test_render_is_deterministic(tmp_path: Path) -> None:
    """Identical fragments + yaml must produce byte-identical output."""
    out1 = _prepare_output_dir(tmp_path / "a")
    out2 = _prepare_output_dir(tmp_path / "b")
    r1, _ = compose.render(CONTRACT, out1)
    r2, _ = compose.render(CONTRACT, out2)
    assert r1 == r2


def test_render_is_deterministic_across_reruns(tmp_path: Path) -> None:
    """Re-rendering the same output dir twice yields identical text."""
    out = _prepare_output_dir(tmp_path)
    r1, _ = compose.render(CONTRACT, out)
    r2, _ = compose.render(CONTRACT, out)
    assert r1 == r2


def test_verdict_renders_red_blockquote(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    assert 'border-left: 3px solid #dc2626' in rendered
    # At least one F/T-NNN linkified citation inside the blockquote.
    assert "*([T-002](#t-002))*" in rendered or "*([T-001](#t-001))*" in rendered


def test_top_findings_has_seven_columns(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    # Locate the Top Findings header row.
    header = "| # | Criticality | Finding | Component | Threat | Vektor | Primary Mitigations |"
    assert header in rendered, "Top Findings must use exactly the 7 canonical columns"


def test_architecture_assessment_has_three_columns(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    assert "| Defect | Description | Key Findings |" in rendered


def test_operational_strengths_has_five_columns(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    header = "| Architectural Control | Implementation | Effectiveness | Gap | Mitigates |"
    assert header in rendered


def test_attack_chain_overview_in_section_3(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    # Reference layout: the cross-chain diagram lives as ### 3.1 Attack Chain
    # Overview inside §3 — NOT as a standalone `## Critical Attack Chain`.
    assert "## Critical Attack Chain\n" not in rendered
    assert "### 3.1 Attack Chain Overview" in rendered
    # §3.1 must carry a graph (LR|TD|TB) Mermaid block.
    assert re.search(r"```mermaid\s*\n\s*graph (LR|TD|TB)", rendered), (
        "§3.1 must contain a `graph LR/TD/TB` Mermaid block"
    )
    assert "**Key takeaway:**" in rendered
    # Must have at least one subgraph cluster.
    assert "subgraph" in rendered, "§3.1 must have at least one subgraph cluster"


def test_threat_register_is_category_grouped(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    # Header is present with Risk + STRIDE + Category lines.
    assert "**Risk Distribution:** 🔴 Critical: 3 · 🟠 High: 1 · " in rendered
    assert "**STRIDE Coverage:**" in rendered
    assert "**Category Distribution:**" in rendered
    # §8 is category-grouped, not severity-grouped.
    assert "### 8.A Categories at a glance" in rendered
    assert "### 8.B Critical Categories" in rendered
    # Per-TH sub-section anchors are emitted (TH-01 Injection + TH-03 Crypto Failures present in fixture).
    assert 'id="th-01"' in rendered or 'id="th-03"' in rendered
    # Every threat anchor is still emitted inside per-TH finding tables.
    for tid in ("t-001", "t-002", "t-003", "t-010"):
        assert f'<a id="{tid}"></a>' in rendered


def test_mitigation_register_derived_from_yaml(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    for mid in ("m-001", "m-002", "m-003"):
        assert f'<a id="{mid}"></a>' in rendered


# ---------------------------------------------------------------------------
# Hard-gate failure modes
# ---------------------------------------------------------------------------

def test_missing_required_fragment_raises(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    (out / ".fragments" / "ms-verdict.json").unlink()
    with pytest.raises(compose.FragmentError) as exc:
        compose.render(CONTRACT, out)
    assert "verdict" in str(exc.value)


def test_schema_violation_raises(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    # Emit a verdict with severity not in enum.
    bad = {
        "severity": "catastrophic",      # not in enum
        "opening": "x" * 80,
        "bullets": [],                    # violates minItems=2
        "closing": "y" * 80,
    }
    (out / ".fragments" / "ms-verdict.json").write_text(json.dumps(bad))
    with pytest.raises(compose.FragmentError) as exc:
        compose.render(CONTRACT, out)
    # Error message mentions the schema-invalid field.
    assert "severity" in str(exc.value) or "bullets" in str(exc.value)


def test_missing_yaml_raises(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    (out / "threat-model.yaml").unlink()
    with pytest.raises(compose.FragmentError) as exc:
        compose.render(CONTRACT, out)
    assert "threat-model.yaml" in str(exc.value)


def test_markdown_fragment_must_start_with_correct_heading(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    # Corrupt system-overview.md: wrong heading level.
    (out / ".fragments" / "system-overview.md").write_text("### 1. System Overview\n\nwrong level\n")
    with pytest.raises(compose.FragmentError) as exc:
        compose.render(CONTRACT, out)
    assert "system_overview" in str(exc.value)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
    )


def test_cli_writes_threat_model_md(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    result = _run_cli(["--output-dir", str(out)])
    assert result.returncode == 0, result.stderr
    md = (out / "threat-model.md").read_text(encoding="utf-8")
    assert "## Management Summary\n" in md


def test_cli_exit_1_on_missing_fragment(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    (out / ".fragments" / "ms-verdict.json").unlink()
    result = _run_cli(["--output-dir", str(out)])
    assert result.returncode == 1
    assert "RENDER_FAILED" in result.stderr
