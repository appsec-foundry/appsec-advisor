"""Regression contract for compact Stage-1 dispatch wiring."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parent.parent
RUNTIME = ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage1-v2.md"
CTX_AGENT = ROOT / "agents" / "appsec-context-resolver.md"
RECON_AGENT = ROOT / "agents" / "appsec-recon-scanner.md"


# ---------------------------------------------------------------------------
# Fix 1 — foreground concurrent recon dispatch (no background / yield)
# ---------------------------------------------------------------------------


class TestCompactDispatch:
    def test_jobs_are_dispatched_together_without_background_recursion(self):
        text = RUNTIME.read_text(encoding="utf-8")
        flat = " ".join(text.split())
        assert "Send foreground `dispatch_jobs[]` together" in flat
        assert "Pass no `run_in_background`" in text
        assert "Never re-dispatch an agent that already returned" in text
        assert "Do not end your turn after dispatching" in text


# ---------------------------------------------------------------------------
# Fix 2 — truthful MODEL_ID in recon agents + dispatch prompts
# ---------------------------------------------------------------------------


class TestReconModelBanner:
    def test_agent_bodies_do_not_hardcode_sonnet(self):
        for agent in (CTX_AGENT, RECON_AGENT):
            text = agent.read_text(encoding="utf-8")
            assert "runs on `sonnet`. Use that as `MODEL_ID`" not in text, (
                f"{agent.name} still hardcodes MODEL_ID=sonnet — banner will lie under sonnet-economy haiku routing"
            )
            assert "passed via the Agent-tool `model` parameter" in text, (
                f"{agent.name} must read its model from the dispatch parameter"
            )

    def test_dispatch_prompts_pass_model_id(self):
        text = RUNTIME.read_text(encoding="utf-8")
        assert "model=dispatch_jobs[].model" in text
        assert "MODEL_ID=<bare model alias you passed as the Agent model>" in text
