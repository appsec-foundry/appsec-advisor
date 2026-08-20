#!/usr/bin/env python3
"""PreToolUse hook: hold decisions and surface product requirements on edits.

This hook is for developing appsec-advisor, not for running it. It is wired in
this repository's `.claude/settings.json` and is deliberately absent from
`hooks/hooks.json`, which ships to users — nothing here should reach an install.

The decision register cannot change without the operator. The separate
`spec_guard.py` owns approval for the normative requirements catalog. For every
other directly edited file, this hook joins the product catalog with
`data/requirement-bindings.yaml` and puts applicable requirements in front of
the agent while the edit can still change.

It allows on anything it cannot positively identify, because a malformed
payload must not block real work.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_specs import (  # noqa: E402
    BINDINGS,
    CATALOG,
    REGISTER,
    ROOT,
    applicable,
    load_binding_document,
    parse,
    parse_bindings,
    render,
)

_PATH_FIELDS = {
    "Edit": "file_path",
    "Write": "file_path",
    "MultiEdit": "file_path",
    "NotebookEdit": "notebook_path",
}

# A shell command that names a held file and could write to it. Deliberately
# broad: an allow-list of two files is worth over-blocking a read that happens
# to redirect, and the alternative is a gate `cat > file` walks straight past.
_WRITE_HINT_RE = re.compile(
    r">|\btee\b|\bsed\b|\bawk\b|\bcp\b|\bmv\b|\brm\b|\btouch\b|\binstall\b"
    r"|\bln\b|\brsync\b|\btruncate\b|\bdd\b|\bpatch\b|<<"
    r"|\bgit\s+(?:apply|checkout|restore|mv|rm)\b"
    r"|\b(?:python3?|perl|ruby|node)\b"
)

_HELD_PATH = REGISTER.relative_to(ROOT).as_posix()

_REASON = (
    "Approval required: {target} states what development may not deviate from. "
    "Show the operator the proposed wording, why it changes, and which test guards "
    "it. Apply the change only if the operator approves this tool call."
)


def relative(target: str) -> str:
    """``target`` as a repository-relative posix path, or empty when it lies outside."""
    path = Path(target)
    if not path.is_absolute():
        path = ROOT / path
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except (ValueError, OSError):
        return ""


def ask(target: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": _REASON.format(target=target),
        }
    }


def held_in_command(command: str) -> str:
    """The held file a shell command could write to, or empty when none can."""
    if not _WRITE_HINT_RE.search(command):
        return ""
    return _HELD_PATH if _HELD_PATH in command else ""


def decide(payload: dict) -> dict | None:
    if payload.get("hook_event_name") != "PreToolUse":
        return None
    tool = payload.get("tool_name") or ""
    if tool == "Bash":
        command = (payload.get("tool_input") or {}).get("command")
        if not isinstance(command, str):
            return None
        target = held_in_command(command)
        return ask(target) if target else None

    field = _PATH_FIELDS.get(tool)
    if not field:
        return None
    target = (payload.get("tool_input") or {}).get(field)
    if not isinstance(target, str) or not target:
        return None
    wanted = relative(target)
    if not wanted:
        return None

    if wanted == _HELD_PATH:
        return ask(wanted)

    if not CATALOG.exists() or not BINDINGS.exists():
        return None
    entries = parse(CATALOG.read_text(encoding="utf-8"))
    bindings = parse_bindings(load_binding_document())
    hits = applicable(entries, bindings, wanted)
    if not hits:
        return None
    body = "\n".join(render(entry, binding) for entry, binding in hits)
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": f"Requirements governing {wanted}:\n{body}",
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
