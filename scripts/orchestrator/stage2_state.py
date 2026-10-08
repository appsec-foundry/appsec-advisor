"""Persisted Stage-2 retry and recovery state used by the controller."""

from __future__ import annotations

import json
from pathlib import Path

# Written by prepare-stage2 once a renderer is about to be dispatched; its
# presence is what makes a later Stage-2 entry a retry.
_STAGE2_DISPATCH_MARKER = ".stage2-dispatched"


def _fragment_repair_is_actionable(output_dir: Path, plan_name: str = ".pre-render-repair-plan.json") -> bool:
    """True when a gate left a plan a fragment-fixer can execute.

    A plan with ``actionable: false`` names no fragment whose edit survives
    recompose — its defects belong to deterministic producers, not to an LLM
    repair pass.
    """
    try:
        plan = json.loads((output_dir / plan_name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(plan, dict) and bool(plan.get("actionable")) and bool(plan.get("actions"))


def _stage2_attempt_counts(path: Path) -> dict[str, int]:
    """Read the per-cause Stage-2 attempt ledger, tolerating the legacy scalar."""
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError:
        return {}
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {}
    if isinstance(parsed, int) and not isinstance(parsed, bool):
        # A run that started before the ledger wrote a bare integer total, which
        # is itself valid JSON. Carry it as one unattributed cause so upgrading
        # mid-flight cannot hand the run a fresh budget.
        return {"unknown": parsed} if parsed > 0 else {}
    if not isinstance(parsed, dict):
        return {}
    return {str(key): int(value) for key, value in parsed.items() if isinstance(value, int) and value > 0}


def _clear_stage2_recovery_state(output_dir: Path) -> None:
    """Retire render-recovery markers after compose no longer needs a retry."""
    for name in (
        ".inline-shortcut-retry-count",
        ".inline-shortcut-repair-plan.json",
        ".compose-blocked.json",
        _STAGE2_DISPATCH_MARKER,
    ):
        try:
            (output_dir / name).unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
