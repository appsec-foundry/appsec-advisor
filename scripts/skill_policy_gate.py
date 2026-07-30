#!/usr/bin/env python3
"""Hook that enforces the organization's skill policy.

Why a hook and not a check inside each skill
--------------------------------------------
``check_skill_enabled.py`` was designed to be called from the top of every
``SKILL.md``. Nothing ever called it, and wiring twenty-one heterogeneous prompt
files would have bought a control the model can skip: a gate written as prose is
an instruction, and an instruction is not an enforcement point. A hook runs
outside the model, on every invocation, and cannot be talked out of it.

Two events, because a skill is reached two ways:

* ``PreToolUse`` with ``tool_name == "Skill"`` — Claude decided to invoke it.
* ``UserPromptExpansion`` — a person typed ``/<plugin>:<skill>``. The documented
  purpose of this event is exactly this: blocking a command from direct
  invocation.

The decision itself is not reimplemented here. ``check_skill_enabled.check``
owns it, so the hook, the CLI and any future caller agree on what "disabled"
means — including the softer treatment of recovery skills, which stay reachable
so a broken state can still be repaired.

Matching, and why it is narrow
------------------------------
The plugin namespace is read from ``plugin.json`` rather than written as a
literal, so a packaged build matches its own name without a rewrite step.

A typed command is only recognised at the *start* of a field. That restriction
is the whole safety argument: the expansion payload can carry the expanded
prompt, which is the skill's own body — and skill bodies mention other commands
(``install-baseline`` names ``/appsec-advisor:verify-baseline`` twice). Scanning
anywhere in any field would block a skill because a different skill's
documentation mentioned it. Anchoring to the start matches what a person typed
and nothing else.

Failure is permission
---------------------
Every unexpected condition — unparseable input, unknown event, missing plugin
name, a damaged config — allows the call. A hook that fails closed would make a
broken config look like a policy and lock a team out of its own tooling. The
policy is a business rule, not a security boundary: it is applied where the
organization can see it, not relied on to contain an attacker.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_skill_enabled as gate  # noqa: E402

# ``/<plugin>:<skill>`` at the very start of a field, and nothing looser.
_COMMAND_RE = re.compile(r"^\s*/([A-Za-z0-9][A-Za-z0-9_-]*):([A-Za-z0-9][A-Za-z0-9_-]*)")

# Fields an expansion payload may carry the typed command in. Kept to a short
# list on purpose — an unknown field means the hook allows rather than guesses.
_COMMAND_FIELDS = ("command", "prompt", "user_prompt", "expanded_prompt", "text", "input")


def _plugin_root() -> Path:
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if root:
        return Path(root)
    return Path(__file__).resolve().parent.parent


def plugin_namespace() -> str:
    """This build's command namespace, from its own manifest.

    Read rather than written as a literal: a packaged build is renamed to the
    organization's namespace, and reading the manifest matches it without the
    rewrite step that printed command strings need.
    """
    try:
        with open(_plugin_root() / ".claude-plugin" / "plugin.json", encoding="utf-8") as fh:
            name = json.load(fh).get("name")
    except Exception:  # noqa: BLE001
        return ""
    return name if isinstance(name, str) else ""


def skill_from_tool_call(payload: dict) -> str:
    """The skill name of a ``Skill`` tool call, or empty when this is not one."""
    if payload.get("tool_name") != "Skill":
        return ""
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return ""
    name = tool_input.get("skill")
    if not isinstance(name, str) or not name:
        return ""
    # Plugin skills are addressed as ``plugin:skill``; the policy keys are bare
    # skill names.
    namespace = plugin_namespace()
    if ":" in name:
        prefix, _, bare = name.partition(":")
        return bare if prefix == namespace else ""
    return name


def skill_from_typed_command(payload: dict, namespace: str) -> str:
    """The skill name of a typed ``/<plugin>:<skill>`` command, or empty.

    Only the documented command-carrying fields are read, and only their start,
    so a command mentioned inside an expanded skill body never matches.
    """
    if not namespace:
        return ""
    for field in _COMMAND_FIELDS:
        value = payload.get(field)
        if not isinstance(value, str):
            continue
        match = _COMMAND_RE.match(value)
        if match and match.group(1) == namespace:
            return match.group(2)
    return ""


def decide(payload: dict) -> dict | None:
    """Return the hook response that blocks this call, or None to allow it."""
    event = payload.get("hook_event_name")
    if event == "PreToolUse":
        skill = skill_from_tool_call(payload)
    elif event in ("UserPromptExpansion", "UserPromptSubmit"):
        skill = skill_from_typed_command(payload, plugin_namespace())
    else:
        return None
    if not skill:
        return None

    output_dir = os.environ.get("OUTPUT_DIR")
    code, message = gate.check(skill, Path(output_dir) if output_dir else None, help_only=False)
    # Only a hard disable blocks. A recovery skill returns the soft code and is
    # allowed through: blocking one would strand a user with a broken run and no
    # way to clean it up.
    if code != gate.EXIT_DISABLED_HARD:
        return None

    if event == "PreToolUse":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": message,
            }
        }
    return {"decision": "block", "reason": message}


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
