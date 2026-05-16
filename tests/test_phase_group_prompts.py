"""Content tests for the phase-group-*.md orchestrator prompts.

These tests protect a small number of structural guidance blocks from silent
erosion. They do not validate every paragraph — just the markers that are
mirrored by deterministic contract checks in `sections-contract.yaml` and
enforced by `scripts/qa_checks.py`. If a marker is removed from the prompt,
the QA rule loses its author-side counterpart and starts failing on freshly
generated threat models; this test catches that at plugin-unit-test time
instead of at full-run time.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
FINALIZATION_PROMPT = REPO_ROOT / "agents" / "phases" / "phase-group-finalization.md"


@pytest.fixture(scope="module")
def finalization_text() -> str:
    assert FINALIZATION_PROMPT.is_file(), f"expected phase-group prompt at {FINALIZATION_PROMPT}"
    return FINALIZATION_PROMPT.read_text(encoding="utf-8")


class TestAuthMethodDecompositionGuidance:
    """Verify that the §7.3 per-auth-method decomposition guidance the
    renderer depends on is still present in the finalization prompt.

    The `auth_method_decomposition` rule in `sections-contract.yaml` expects
    the agent to emit, per distinct authentication method:

      * a `#### <Method Name> Flow` subsection,
      * with its own Mermaid `sequenceDiagram` block,
      * ending with a bold `**Findings in this flow:**` trailer,
      * whose T-IDs are a subset of the controls-table row's `Linked Threats`
        cell (bidirectional consistency).

    Each of these four points has a dedicated marker below.
    """

    def test_mentions_per_auth_method_decomposition(self, finalization_text):
        assert (
            "per-auth-method decomposition" in finalization_text or "Per-auth-method decomposition" in finalization_text
        ), (
            "phase-group-finalization.md no longer describes §7.3 "
            "per-auth-method decomposition — the contract rule has no "
            "author-side counterpart; either restore the guidance or "
            "retire the rule."
        )

    def test_mentions_one_subsection_per_controls_row(self, finalization_text):
        # The guidance now uses numbered `#### 7.3.N <Method> Flow` headings
        # (see Fix 7 — structured auth-method blocks). Accept both the
        # current wording and the legacy un-numbered variant so in-flight
        # refactors don't break the gate.
        assert (
            "One `#### 7.3.N <Method Name> Flow` sub-subsection per row" in finalization_text
            or "One `#### <Method Name> Flow` sub-subsection per row" in finalization_text
        ), "guidance that every Control-column row needs a matching `####` sub-subsection is missing"

    def test_requires_sequencediagram_per_subsection(self, finalization_text):
        # The new prompt embeds the sequenceDiagram requirement inside the
        # five-element structural list (element (b)). Accept either the
        # legacy single-sentence form or the new list item.
        assert (
            "MUST contain its own Mermaid `sequenceDiagram`" in finalization_text
            or "A Mermaid `sequenceDiagram`." in finalization_text
        ), "guidance that each §7.3 `####` block needs its own sequenceDiagram is missing"

    def test_requires_findings_trailer(self, finalization_text):
        assert "**Findings in this flow:**" in finalization_text, (
            "mandatory `**Findings in this flow:**` trailer marker is missing from the §7.3 guidance"
        )

    def test_requires_bidirectional_tid_consistency(self, finalization_text):
        assert "Bidirectional T-ID consistency" in finalization_text, (
            "guidance on bidirectional T-ID consistency between the "
            "`**Findings in this flow:**` trailer and the `Linked Threats` "
            "cell is missing"
        )

    def test_requires_numbered_subsection_headings(self, finalization_text):
        # Fix 7 inverted the previous rule: `#### 7.3.N <Name> Flow`
        # numbering is now REQUIRED so the auth-method blocks are easily
        # navigable from the TOC. Keep a dedicated marker so anyone who
        # removes this guidance notices the test failure.
        assert (
            "#### 7.3.N <Method Name> Flow" in finalization_text
            or "`#### 7.3.1 Password Login Flow`" in finalization_text
        ), "guidance requiring numbered `#### 7.3.N` headings is missing (Fix 7 — structured auth-method blocks)"

    def test_requires_risk_assessment_trailer(self, finalization_text):
        # Each auth-method block must end with a bold `**Risk assessment:**`
        # trailer plus a `**Residual risk:**` line — see Fix 7 mini-report shape.
        assert "**Risk assessment:**" in finalization_text, (
            "`**Risk assessment:**` trailer guidance missing from §7.3 block"
        )
        assert "**Residual risk:**" in finalization_text, "`**Residual risk:**` line guidance missing from §7.3 block"
