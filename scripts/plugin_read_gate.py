#!/usr/bin/env python3
"""Hook that keeps the orchestrator out of the plugin's implementation at runtime.

Why this exists
---------------
In the 2026-08-16 juice-shop run the §3 walkthrough selection dropped a Critical
the QA gate demanded. The orchestrator did not surface the repair plan; it went
looking for the cause. It read ``walkthrough_renderer.py`` at three offsets,
grepped it twice, ran four ad-hoc ``python3 -c`` probes against ``scripts/``, and
then edited the resolved run configuration on the strength of what it had read.
Eighteen minutes and roughly seven dollars produced nineteen seconds of work,
two context compactions, and a configuration change that did not fix anything.

Implementation source is not a contract, and reading it is not diagnosis. When a
deterministic step fails, the run has a repair plan to act on and a contract to
consult; the code behind them is neither, and pulling it into the orchestrator's
context is what forces the compaction that makes the rest of the run expensive.

Unlike ``plugin_write_gate.py`` this is not a security boundary — a read changes
nothing. It is a cost and behaviour guard, and it fails open for the same reason
that one does: a payload it cannot positively identify is the harness's shape,
not an attacker's, and denying real work on it buys nothing.

Scope
-----
Only ``scripts/`` is closed, because only ``scripts/`` is implementation. The
directories the pipeline legitimately reads stay open: ``agents/`` and
``skills/`` are lazy-loaded at phase boundaries by design, and ``data/`` and
``schemas/`` carry the contracts an agent is told to consult. No prompt in this
repository instructs anyone to read a file under ``scripts/`` — they invoke
those files, and invocation is untouched.

``APPSEC_PLUGIN_DEV=1`` lifts it, matching the write gate: a developer checkout
is the one place where reading the implementation is the work.

Residual gap: a shell command can still read a script (``grep``, ``cat``,
``python3 -c``). Gating Bash would mean parsing arbitrary command lines, which
fails open far more often than it holds. The tool-level block covers the vector
that carried the cost — whole-file Reads — and leaves the rest to the prompt.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Tool → the input field naming what it reads.
_PATH_FIELDS = {
    "Read": "file_path",
    "Grep": "path",
    "Glob": "path",
}

# The one subtree that carries implementation rather than contract.
_PROTECTED_DIR = "scripts"

_REASON = (
    "Blocked: {target} is appsec-advisor's implementation, not a contract, and "
    "reading it mid-run is what fills the orchestrator's context and forces a "
    "compaction. A deterministic step that failed has already written its repair "
    "plan — act on that, or surface the failure and stop. The behaviour it "
    "implements is described in data/, schemas/ and docs/internal/contracts/. "
    "Set APPSEC_PLUGIN_DEV=1 when the plugin itself is the work."
)


def plugin_root() -> Path:
    """The plugin checkout, canonicalized. Env first, this file's parent as fallback."""
    env = os.environ.get("CLAUDE_PLUGIN_ROOT")
    candidate = Path(env) if env else Path(__file__).resolve().parent.parent
    return Path(os.path.realpath(candidate))


def protects(root: Path, target: Path) -> bool:
    """Whether ``target`` resolves inside the plugin's ``scripts/`` subtree.

    Both sides are canonicalized first, so ``..`` segments and symlinks cannot
    walk into the subtree behind the check.
    """
    resolved = Path(os.path.realpath(target))
    try:
        rel = resolved.relative_to(root)
    except ValueError:
        return False
    return bool(rel.parts) and rel.parts[0] == _PROTECTED_DIR


def decide(payload: dict) -> dict | None:
    """Return the hook response that blocks this call, or None to allow it."""
    if os.environ.get("APPSEC_PLUGIN_DEV") == "1":
        return None
    if payload.get("hook_event_name") != "PreToolUse":
        return None
    field = _PATH_FIELDS.get(payload.get("tool_name") or "")
    if not field:
        return None
    target = (payload.get("tool_input") or {}).get(field)
    if not isinstance(target, str) or not target:
        return None
    if not protects(plugin_root(), Path(target)):
        return None
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": _REASON.format(target=target),
        }
    }


def main() -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        response = decide(payload) if isinstance(payload, dict) else None
    except Exception:  # noqa: BLE001 — allow on anything unexpected
        return 0
    if response:
        print(json.dumps(response))
    return 0


if __name__ == "__main__":
    sys.exit(main())
