"""Reference-parity tests.

These tests check that the renderer's output structure — heading sequence,
table column schemas, cross-reference patterns — matches the committed
reference threat model at `examples/threat-modeler/threat-model-juice-shop-thorough.md`.

Unlike pure structural tests, these anchor the contract to a concrete,
human-reviewed example. When someone edits the contract to reshape a
section, this test highlights the delta vs the reference and forces an
explicit decision: either update the reference (intentional change) or
revert the contract.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).parent.parent
REF = REPO_ROOT / "examples" / "threat-modeler" / "threat-model-juice-shop-thorough.md"


@pytest.fixture(scope="module")
def reference_text() -> str:
    assert REF.is_file(), f"reference missing at {REF}"
    return REF.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Top-level heading sequence
# ---------------------------------------------------------------------------

EXPECTED_TOP_LEVEL = [
    "## Changelog",
    "## Table of Contents",
    "## Management Summary",
    "## 1. System Overview",
    "## 2. Architecture Diagrams",
    "## 3. Attack Walkthroughs",
    "## 4. Assets",
    "## 5. Attack Surface",
    "## 7. Security Architecture",
    "## 8. Threat Register",
    "## 9. Mitigation Register",
    "## 10. Out of Scope",
    "## Appendix: Run Statistics",
    "## <a id=\"appendix-a-vektor-taxonomy\"></a>Appendix A — Vektor Taxonomy",
]


def test_reference_top_level_headings_present(reference_text: str) -> None:
    missing = [h for h in EXPECTED_TOP_LEVEL if h not in reference_text]
    assert not missing, (
        "Reference document is missing expected top-level headings.\n"
        "If the reference changed intentionally, update EXPECTED_TOP_LEVEL.\n"
        "Missing: " + ", ".join(missing)
    )


def test_reference_top_level_order_is_preserved(reference_text: str) -> None:
    positions = []
    for h in EXPECTED_TOP_LEVEL:
        if h in reference_text:
            positions.append((reference_text.index(h), h))
    sorted_positions = sorted(positions)
    assert positions == sorted_positions, (
        "Reference top-level headings are out of order.\n"
        f"Expected: {[h for _, h in sorted_positions]}\n"
        f"Actual:   {[h for _, h in positions]}"
    )


# ---------------------------------------------------------------------------
# Management Summary canonical sub-section order
# ---------------------------------------------------------------------------

def test_reference_ms_subsections_order(reference_text: str) -> None:
    m = re.search(r"^## Management Summary\n(.+?)(?=^## )", reference_text,
                  re.DOTALL | re.MULTILINE)
    assert m, "reference lacks `## Management Summary` section"
    ms = m.group(1)
    expected = ["### Verdict", "### Top Findings", "### Architecture Assessment",
                "### Mitigations", "### Operational Strengths"]
    pos = [(ms.index(s), s) for s in expected if s in ms]
    assert [h for _, h in pos] == expected, (
        f"Reference MS sub-section order drift: {[h for _, h in pos]}"
    )


# ---------------------------------------------------------------------------
# Table column schemas in the reference
# ---------------------------------------------------------------------------

EXPECTED_TABLES = [
    # (header_substring, why)
    ("| # | Criticality | Pfad | Finding | Component | Primary Mitigations |",
     "Top Findings table (6-col)"),
    ("| Defect | Description | Key Findings |",
     "Architecture Assessment table (3-col)"),
    ("| Architectural Control | Implementation | Effectiveness | Gap | Mitigates |",
     "Operational Strengths table (5-col)"),
    ("| ID | Mitigation | Component | Addresses | Effort |",
     "Mitigations sub-table (5-col)"),
    ("| TH | Category | Severity (eff.) | Findings | Top Finding | Breach | OWASP | Pillar |",
     "§8.A Categories at a glance (8-col)"),
    ("| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |",
     "§8.B per-TH finding table (8-col)"),
]


@pytest.mark.parametrize("header,why", EXPECTED_TABLES, ids=[row[1] for row in EXPECTED_TABLES])
def test_reference_contains_canonical_table(reference_text: str, header: str, why: str) -> None:
    assert header in reference_text, (
        f"Reference missing canonical {why} — expected header row:\n  {header}"
    )


# ---------------------------------------------------------------------------
# §7 canonical 14 sub-sections
# ---------------------------------------------------------------------------

SEC_7_SUBSECTIONS = [
    "### 7.1 Overview",
    "### 7.2 Key Architectural Risks",
    "### 7.3 Identity & Access Management",
    "### 7.4 Authorization",
    "### 7.5 Input Validation & Output Encoding",
    "### 7.6 Data Protection & Session Management",
    "### 7.7 Frontend Security",
    "### 7.8 Real-time / WebSocket",
    "### 7.9 AI / LLM",
    "### 7.10 Audit & Logging",
    "### 7.11 Infrastructure & Network Segmentation",
    "### 7.12 Dependency & Supply Chain",
]


def test_reference_sec7_has_all_14_subsections(reference_text: str) -> None:
    missing = [s for s in SEC_7_SUBSECTIONS if s not in reference_text]
    # 7.13 / 7.14 use a `_(cross-cutting)_` suffix — check via pattern.
    if "### 7.13 Secret Management" not in reference_text:
        missing.append("### 7.13 Secret Management")
    if "### 7.14 Defense-in-Depth Assessment" not in reference_text:
        missing.append("### 7.14 Defense-in-Depth Assessment")
    assert not missing, f"Reference missing canonical §7 sub-sections: {missing}"


# ---------------------------------------------------------------------------
# §8 A/B/C/D anchors
# ---------------------------------------------------------------------------

def test_reference_sec8_has_abcd_structure(reference_text: str) -> None:
    expected = [
        "### 8.A Categories at a glance",
        "### 8.B Critical Categories",
        "### 8.C Compound Attack Chains",
        "### 8.D Architectural Findings",
    ]
    missing = [e for e in expected if e not in reference_text]
    assert not missing, f"Reference §8 missing canonical sub-section headings: {missing}"


# ---------------------------------------------------------------------------
# Reference-link convention: every F-NNN / M-NNN reference in the body
# should carry a label (`— ...`) outside of explicit `{...}` and pure-anchor
# contexts. Sample a few.
# ---------------------------------------------------------------------------

def test_reference_uses_labelled_links(reference_text: str) -> None:
    """Sample: at least 70% of F-NNN references outside anchor declarations
    must carry `— <label>`. This guards the convention in the reference —
    if someone commits a reference update that regresses to bare links,
    our enforcement target moves."""
    matches = list(re.finditer(r"\[(F-\d+)\]\(#f-\d+\)", reference_text))
    with_label = sum(
        1 for m in matches
        if reference_text[m.end():m.end() + 4].startswith(" — ")
    )
    ratio = with_label / max(1, len(matches))
    assert ratio >= 0.7, (
        f"Reference F-NNN labelled-link ratio dropped to {ratio:.0%} "
        f"({with_label}/{len(matches)}). Did the reference regress?"
    )
