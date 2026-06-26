"""Regression contract for the recon-phase (Phases 1/2/2.5) dispatch wiring.

Both guards trace to the 2026-06-11 juice-shop run:

  Fix 1 — the analyst background-dispatched the context-resolver / recon-scanner
  / config-scanner and yielded its turn ("waiting for completion notifications"),
  expecting SendMessage continuation. In a harness without SendMessage that
  strands the run. The recon trio MUST be dispatched as concurrent FOREGROUND
  Agent calls in a single message (all results return in the same turn). The
  Phase-9 STRIDE background dispatch (rescued by wait_stride_progress.py) is a
  separate path and MUST stay background.

  Fix 2 — context-resolver / recon-scanner bodies hardcoded
  "runs on `sonnet`. Use that as `MODEL_ID`", so their startup banners reported
  sonnet regardless of the sonnet-economy → haiku routing. The bodies must read
  MODEL_ID from the prompt, and the three dispatch prompts must pass MODEL_ID.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parent.parent
RECON = ROOT / "agents" / "phases" / "phase-group-recon.md"
ANALYST = ROOT / "agents" / "appsec-threat-analyst.md"
CTX_AGENT = ROOT / "agents" / "appsec-context-resolver.md"
RECON_AGENT = ROOT / "agents" / "appsec-recon-scanner.md"


# ---------------------------------------------------------------------------
# Fix 1 — foreground concurrent recon dispatch (no background / yield)
# ---------------------------------------------------------------------------


class TestReconForegroundDispatch:
    def test_recon_dispatch_bullets_are_foreground(self):
        text = RECON.read_text(encoding="utf-8")
        # No per-agent dispatch bullet may set run_in_background: true.
        assert "- `run_in_background`: `true`" not in text, (
            "a recon dispatch bullet still backgrounds the agent — it would "
            "strand the run on a SendMessage-less harness"
        )
        # All three recon agents must be dispatched concurrently in the foreground.
        assert text.count("concurrent foreground") >= 3, (
            "expected the context/recon/config dispatch bullets to be marked concurrent foreground"
        )

    def test_recon_section_explains_no_background(self):
        text = RECON.read_text(encoding="utf-8")
        assert "SINGLE message" in text
        # The rationale (why background is forbidden) must be documented so the
        # behaviour is not "fixed" back to background by a future edit.
        assert "cannot resume a backgrounded agent" in text or "SendMessage" in text

    def test_analyst_recon_flow_is_foreground(self):
        text = ANALYST.read_text(encoding="utf-8")
        assert "concurrent FOREGROUND Agent calls" in text
        # The retired state-matrix wording that backgrounded the trio is gone.
        assert "all `true`" not in text, "analyst dispatch matrix still backgrounds all recon agents"
        assert "both `true`" not in text, "analyst dispatch matrix still backgrounds the recon pair"
        assert "all `false` (concurrent foreground)" in text

    def test_phase9_stride_background_is_preserved(self):
        """The fix is scoped to recon — Phase 9 STRIDE legitimately uses
        background dispatch rescued by the wait_stride_progress.py waiter, which
        keeps the orchestrator turn alive without SendMessage. Do not regress it."""
        text = ANALYST.read_text(encoding="utf-8")
        assert "run_in_background: true" in text, "Phase-9 STRIDE background dispatch was removed"
        assert "wait_stride_progress.py" in text, "Phase-9 progress waiter was removed"


# ---------------------------------------------------------------------------
# Fix 3 — no second dispatch of recon-scanner / context-resolver
#
# 2026-06-25 juice-shop standard run: after a 509s model/API stall recovered,
# the orchestrator rechecked the recon/context output files, saw them as
# "missing", and re-spawned BOTH agents ("Re-run … to write output file") —
# re-paying full context prefill for zero new analysis (~$1-2 waste). The
# contract already forbids re-dispatch (step 4 + the inline-fallback rule); the
# wording was hardened so a missing-after-stall file routes to the fallback,
# never a second Agent call.
# ---------------------------------------------------------------------------


class TestReconNoReDispatch:
    def test_no_second_dispatch_rule_present(self):
        text = RECON.read_text(encoding="utf-8")
        assert "Never re-dispatch the context-resolver or recon-scanner" in text, (
            "the explicit no-second-dispatch rule was removed — the orchestrator "
            "will re-spawn recon/context agents on stalled runs again"
        )
        assert "contract violation" in text

    def test_no_second_dispatch_names_the_observed_waste_pattern(self):
        text = RECON.read_text(encoding="utf-8")
        # The exact wasteful AGENT_SPAWN label seen in the field must be named so
        # the rule is unmistakable to the orchestrator LLM.
        assert "Re-run … to write output file" in text
        # The missing-after-stall case must route to the fallback, not a re-spawn.
        assert "after a model/API stall recovers" in text


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
        text = RECON.read_text(encoding="utf-8")
        assert "MODEL_ID=$CONTEXT_RESOLVER_MODEL" in text
        assert "MODEL_ID=$RECON_SCANNER_MODEL" in text
        assert "MODEL_ID=$CONFIG_SCANNER_MODEL" in text
