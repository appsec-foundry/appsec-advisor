#!/usr/bin/env python3
"""PreToolUse hook: hold the requirements catalog, and surface it where it applies.

This hook is for developing appsec-advisor, not for running it. It is wired in
this repository's `.claude/settings.json` and is deliberately absent from
`hooks/hooks.json`, which ships to users — nothing here should reach an install.

Two behaviors, one reason. `specs/requirements.md` and
`docs/internal/decisions.md` say what development may not deviate from, so an
agent must not be the one to change them: the write is denied and the change
goes to the operator. For every other file, the hook looks up which
requirements govern it and puts them in front of the agent at the moment it
edits that file — the only moment they can still change the edit. A rule read
at session start is a rule the model can forget; this one arrives with the
edit.

It allows on anything it cannot positively identify, because a malformed
payload must not block real work.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_specs import CATALOG, HELD_PATHS, ROOT, applicable, parse, render  # noqa: E402

_PATH_FIELDS = {"Edit": "file_path", "Write": "file_path", "NotebookEdit": "notebook_path"}

# A shell command that names a held file and could write to it. Deliberately
# broad: an allow-list of two files is worth over-blocking a read that happens
# to redirect, and the alternative is a gate `cat > file` walks straight past.
_WRITE_HINT_RE = re.compile(
    r">|\btee\b|\bsed\b|\bcp\b|\bmv\b|\brm\b|\btruncate\b|\bdd\b|\bpatch\b|<<"
    r"|\bgit\s+(?:apply|checkout|restore|mv|rm)\b"
    r"|\b(?:python3?|perl|ruby|node)\b"
)

_REASON = (
    "Blocked: {target} states what development may not deviate from, so it is not "
    "yours to edit. Propose the change to the operator — what should hold, why, and "
    "which test would guard it — and let them apply it. Set APPSEC_SPEC_EDIT=1 only "
    "if they ask you to write it for them."
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


def deny(target: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": _REASON.format(target=target),
        }
    }


def held_in_command(command: str) -> str:
    """The held file a shell command could write to, or empty when none can."""
    if not _WRITE_HINT_RE.search(command):
        return ""
    return next((path for path in HELD_PATHS if path in command), "")


def decide(payload: dict) -> dict | None:
    if payload.get("hook_event_name") != "PreToolUse":
        return None
    tool = payload.get("tool_name") or ""
    released = os.environ.get("APPSEC_SPEC_EDIT") == "1"

    if tool == "Bash":
        command = (payload.get("tool_input") or {}).get("command")
        if released or not isinstance(command, str):
            return None
        target = held_in_command(command)
        return deny(target) if target else None

    field = _PATH_FIELDS.get(tool)
    if not field:
        return None
    target = (payload.get("tool_input") or {}).get(field)
    if not isinstance(target, str) or not target:
        return None
    wanted = relative(target)
    if not wanted:
        return None

    if wanted in HELD_PATHS and not released:
        return deny(wanted)

    if not CATALOG.exists():
        return None
    hits = applicable(parse(CATALOG.read_text()), wanted)
    if not hits:
        return None
    body = "\n".join(render(entry) for entry in hits)
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
