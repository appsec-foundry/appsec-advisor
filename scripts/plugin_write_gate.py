#!/usr/bin/env python3
"""Hook that blocks writes to the plugin's own source unless developer mode is on.

Why a hook and not the instruction already in the skill
------------------------------------------------------
``skills/fix-run-issues/SKILL.md`` resolves ``WRITE_ALLOWED`` from
``APPSEC_PLUGIN_DEV`` and then instructs the model never to apply a fix while it
is 0. That is a rule written in prose, and a rule the model reads is a rule the
model can skip. The permission it would need is granted unconditionally
(``data/required-permissions.yaml`` → ``Edit(${PLUGIN_ROOT}/**)``) and the skill
ships to end users (``package_internal_plugin.py`` → ``UTILITY_SKILLS``), so
nothing outside the prompt stood between a user install and a modified plugin.
This hook is that something: it runs outside the model on every write.

Unlike ``skill_policy_gate.py``, this *is* a security boundary — self-modification
of an installed plugin is not a business rule. It still allows on anything it
cannot positively identify as a plugin-source write, because the alternative
denies real work on a malformed payload while buying nothing: the payload shape
is the harness's, not an attacker's.

What counts as plugin source
----------------------------
Only the directories that carry executable or contractual plugin content, plus
the two root config files. ``docs/`` is deliberately absent: a run scanning the
plugin's own checkout writes its deliverable to ``docs/security/``, and a
developer checkout is the one place where PLUGIN_ROOT and the scanned repository
are the same directory. Blocking there would break the self-scan to protect
nothing.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Tool → the input field naming the file it writes.
_PATH_FIELDS = {
    "Edit": "file_path",
    "Write": "file_path",
    "NotebookEdit": "notebook_path",
}

# Plugin-source subtrees, relative to PLUGIN_ROOT.
_PROTECTED_DIRS = (
    ".claude-plugin",
    "agents",
    "data",
    "hooks",
    "schemas",
    "scripts",
    "skills",
    "templates",
)

_PROTECTED_FILES = ("config.json",)

_REASON = (
    "Blocked: {target} is appsec-advisor's own source, and plugin self-modification "
    "is a development-only behavior. APPSEC_PLUGIN_DEV is not set to 1, so this "
    "install is read-only against the plugin. To report the problem instead, run "
    "/appsec-advisor:report-error — it builds a local anonymised bundle and sends "
    "nothing."
)


def plugin_root() -> Path:
    """The plugin checkout, canonicalized. Env first, this file's parent as fallback."""
    env = os.environ.get("CLAUDE_PLUGIN_ROOT")
    candidate = Path(env) if env else Path(__file__).resolve().parent.parent
    return Path(os.path.realpath(candidate))


def protects(root: Path, target: Path) -> str:
    """The protected subtree ``target`` falls into, or empty when it falls into none.

    Both sides are canonicalized first, so ``..`` segments and symlinks cannot
    walk into the plugin behind the check.
    """
    resolved = Path(os.path.realpath(target))
    try:
        rel = resolved.relative_to(root)
    except ValueError:
        return ""
    parts = rel.parts
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0] if parts[0] in _PROTECTED_FILES else ""
    return parts[0] if parts[0] in _PROTECTED_DIRS else ""


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
