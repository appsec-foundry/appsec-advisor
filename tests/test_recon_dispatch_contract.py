"""Regression contract for compact Stage-1 dispatch wiring."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parent.parent
RUNTIME = ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage1-v2.md"
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
