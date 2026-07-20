"""Regression contract for the Level-0 Stage-1 (Analyst-A/B) dispatch wiring.

This is the Level-0 sibling of ``test_recon_dispatch_contract.py``. The same
failure recurred one level up on 2026-07-19: the orchestrator backgrounded
Analyst-A and ended its turn ("Analyst-A (Phases 1-8) is running. Waiting for
it to complete before building the STRIDE dispatch manifest."), expecting a
continuation that this harness cannot deliver on the parallel-STRIDE path --
that path has no Monitor and no completion-notification handler, both of which
exist only in the ``LIVE_PHASE`` variant.

Consequence: headless ``claude -p`` hard-killed the process at its
background-task ceiling before any ``threat-model.yaml`` was written, which
also defeats the compose backstop in ``run-headless.sh`` (gated on that yaml).
Fixture-e2e runs 29696937786 / 29700135164 / 29704358601 all died at wall-time
767-775s; run 29697943011 -- same commit 9b51762, same fixture, same depth --
passed in 46m39s. Workload was not the variable; dispatch compliance was.

Root cause was an instruction-strength gap between the three Stage-1 dispatch
variants: the serial and live-phase variants state their backgrounding rule
imperatively, while the parallel-STRIDE variant -- the DEFAULT for full/rebuild
-- only described itself as "Foreground/blocking." in trailing prose. These
guards pin the imperative form so it cannot erode back.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parent.parent
SKILL_IMPL = ROOT / "skills" / "create-threat-model" / "SKILL-impl.md"


def _impl() -> str:
    return SKILL_IMPL.read_text(encoding="utf-8")


class TestParallelStrideAnalystIsForeground:
    def test_dispatch_states_run_in_background_false_imperatively(self):
        """The default path must ORDER foreground dispatch, not merely describe it."""
        text = _impl()
        assert "Set `run_in_background: false` on this Agent call" in text, (
            "the parallel-STRIDE Analyst-A dispatch lost its explicit "
            "run_in_background: false instruction — a backgrounded Analyst-A "
            "strands the run on this Monitor-less path"
        )

    def test_dispatch_forbids_ending_the_turn(self):
        """Backgrounding and turn-yielding are separate failure modes; the
        observed run did both. Forbid both explicitly."""
        text = _impl()
        assert "do NOT end your turn after dispatching it" in text, (
            "the 'do not end your turn' guard for Analyst-A was removed"
        )

    def test_rationale_is_documented_so_it_is_not_re_optimised_away(self):
        """Without the why, a future edit 'optimises' this back to background."""
        text = _impl()
        assert "no Monitor and no completion-notification handler" in text, (
            "the rationale explaining why this path cannot resume was removed"
        )


class TestOtherStage1VariantsUnchanged:
    """The fix is scoped to the parallel-STRIDE variant. The serial variant was
    already imperative and the LIVE_PHASE variant legitimately backgrounds --
    it pairs the background dispatch with a Monitor plus a completion-
    notification handler. Neither may be collaterally flipped."""

    def test_serial_variant_still_blocking(self):
        text = _impl()
        assert "Do **not** set `run_in_background` — this is a blocking inline call." in text

    def test_live_phase_variant_still_backgrounds_with_monitor(self):
        text = _impl()
        assert "Set **`run_in_background: true`**" in text, "the LIVE_PHASE variant's background dispatch was removed"
        assert "**End your turn immediately after dispatching.**" in text
