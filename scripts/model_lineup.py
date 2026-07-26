#!/usr/bin/env python3
"""One-line summary of every model a run will use, and what each one drives.

`run-headless.sh` used to print only `Model: claude-sonnet-4-6` — the *session*
model. That reads as "the whole assessment runs on 4.6", which is wrong: the
session model drives orchestration, while STRIDE, triage, merge, rendering,
abuse verification and the cheap recon/config phases each resolve separately
from the reasoning tier and depth. The distinction matters because the session
model is the dominant cost lever while contributing least to analysis depth —
exactly the confusion this line exists to prevent.

Roles are grouped by model rather than listed per role: the operator is deciding
about cost, and cost is per model, not per role.

Usage:
    model_lineup.py --session <model> [--reasoning <tier>] [--depth <depth>]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Display order: analysis-critical roles first, cheap support phases last.
_ROLE_LABELS = [
    ("session", "session/orchestrator"),
    ("stride_model", "STRIDE"),
    ("triage_model", "triage"),
    ("merger_model", "merge"),
    ("renderer_model", "render"),
    ("abuse_verifier_model", "abuse"),
    ("evidence_verifier_model", "evidence"),
    ("qa_content_model", "QA-content"),
    ("qa_routine_model", "QA-routine"),
    ("recon_scanner_model", "recon"),
    ("config_scanner_model", "config"),
    ("context_resolver_model", "context"),
]


def lineup(session_model: str, reasoning: str = "sonnet-economy", depth: str = "standard") -> str:
    """Return `model (roles) · model (roles)` ordered by first appearance."""
    try:
        import resolve_config as rc
    except Exception:
        return session_model

    resolved: dict[str, str] = {"session": session_model}
    try:
        ns = argparse.Namespace(
            reasoning_model=reasoning,
            stride_model=None,
            triage_model=None,
            merger_model=None,
        )
        resolved.update(rc.resolve_reasoning_model(ns, depth))
        resolved.update(rc.resolve_extended_models(reasoning, depth))
    except Exception:
        return session_model

    # The `sonnet` alias means "inherit the session model" for agent dispatch;
    # printing it verbatim next to a concrete id would imply a different model.
    grouped: dict[str, list[str]] = {}
    for key, label in _ROLE_LABELS:
        model = resolved.get(key)
        if not model:
            continue
        if model == "sonnet":
            model = session_model
        grouped.setdefault(model, []).append(label)

    return " · ".join(f"{model} ({', '.join(roles)})" for model, roles in grouped.items())


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--session", required=True)
    p.add_argument("--reasoning", default="sonnet-economy")
    p.add_argument("--depth", default="standard")
    args = p.parse_args(argv)
    print(lineup(args.session, args.reasoning, args.depth))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
