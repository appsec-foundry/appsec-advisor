from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_REFERENCE = "shared/completion-contract.md"


def test_every_pipeline_agent_has_a_compact_completion_receipt_contract():
    """Agent returns stay receipt-sized because the parent keeps them resident."""
    agent_names = (
        "appsec-abuse-case-verifier",
        "appsec-actor-discoverer",
        "appsec-architect-reviewer",
        "appsec-config-scanner",
        "appsec-context-resolver",
        "appsec-evidence-verifier",
        "appsec-fragment-fixer",
        "appsec-qa-reviewer",
        "appsec-recon-scanner",
        "appsec-stride-analyzer",
        "appsec-threat-analyst",
        "appsec-threat-merger",
        "appsec-threat-renderer",
        "appsec-triage-validator",
    )
    for name in agent_names:
        text = (ROOT / "agents" / f"{name}.md").read_text(encoding="utf-8")
        assert CONTRACT_REFERENCE in text, name
