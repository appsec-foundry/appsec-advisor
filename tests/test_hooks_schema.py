"""Schema tests for plugin/hooks/hooks.json and steering_keywords.json.

These config files are not exercised by the existing pytest suite; a typo or
missing key would only surface at runtime when Claude Code loads the plugin.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

HOOKS_DIR = Path(__file__).parent.parent / "plugin" / "hooks"
HOOKS_JSON = HOOKS_DIR / "hooks.json"
KEYWORDS_JSON = HOOKS_DIR / "steering_keywords.json"

# Hook events the plugin currently registers. New events MUST also be added
# here so missing wiring is caught.
EXPECTED_HOOK_EVENTS = {
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "Stop",
    "SubagentStop",
}


# ---------------------------------------------------------------------------
# hooks.json structure
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def hooks_data():
    assert HOOKS_JSON.exists(), f"{HOOKS_JSON} not found"
    with HOOKS_JSON.open() as fh:
        return json.load(fh)


class TestHooksJson:
    def test_has_root_hooks_key(self, hooks_data):
        assert "hooks" in hooks_data, "hooks.json must have top-level 'hooks' key"
        assert isinstance(hooks_data["hooks"], dict)

    def test_all_expected_events_registered(self, hooks_data):
        present = set(hooks_data["hooks"].keys())
        missing = EXPECTED_HOOK_EVENTS - present
        assert not missing, (
            f"hooks.json is missing event registrations for: {sorted(missing)}"
        )

    def test_no_unexpected_events(self, hooks_data):
        present = set(hooks_data["hooks"].keys())
        extra = present - EXPECTED_HOOK_EVENTS
        assert not extra, (
            f"hooks.json registers unexpected events: {sorted(extra)} — "
            "update EXPECTED_HOOK_EVENTS in test_hooks_schema.py if intentional"
        )

    @pytest.mark.parametrize("event", sorted(EXPECTED_HOOK_EVENTS))
    def test_event_entries_well_formed(self, hooks_data, event):
        entries = hooks_data["hooks"][event]
        assert isinstance(entries, list) and entries, (
            f"hooks.{event} must be a non-empty list"
        )
        for outer in entries:
            assert "hooks" in outer and isinstance(outer["hooks"], list), (
                f"hooks.{event}[*] must contain a 'hooks' list"
            )
            for h in outer["hooks"]:
                assert h.get("type") == "command", (
                    f"hooks.{event}[*].hooks[*].type must be 'command'"
                )
                cmd = h.get("command", "")
                assert isinstance(cmd, str) and cmd.strip(), (
                    f"hooks.{event}[*].hooks[*].command must be a non-empty string"
                )
                # Plugin scripts must be invoked via $CLAUDE_PLUGIN_ROOT
                assert "${CLAUDE_PLUGIN_ROOT}" in cmd or "$CLAUDE_PLUGIN_ROOT" in cmd, (
                    f"hooks.{event} command does not use $CLAUDE_PLUGIN_ROOT — "
                    f"plugin would be unportable: {cmd!r}"
                )

    def test_referenced_scripts_exist(self, hooks_data):
        """Every hook command must reference a script that actually exists."""
        plugin_root = Path(__file__).parent.parent / "plugin"
        for event, entries in hooks_data["hooks"].items():
            for outer in entries:
                for h in outer["hooks"]:
                    cmd = h["command"]
                    # Extract path after $CLAUDE_PLUGIN_ROOT
                    parts = cmd.split("${CLAUDE_PLUGIN_ROOT}")
                    if len(parts) < 2:
                        parts = cmd.split("$CLAUDE_PLUGIN_ROOT")
                    if len(parts) < 2:
                        continue
                    rel = parts[1].strip().split()[0].lstrip("/")
                    script_path = plugin_root / rel
                    assert script_path.exists(), (
                        f"hooks.{event} references missing script: {script_path}"
                    )


# ---------------------------------------------------------------------------
# steering_keywords.json structure
# ---------------------------------------------------------------------------

REQUIRED_KEYWORD_GROUPS = {"strong", "code", "action"}
REQUIRED_THRESHOLDS = {
    "strong_min",
    "code_min",
    "code_action_code_min",
    "code_action_action_min",
}


@pytest.fixture(scope="module")
def keywords_data():
    assert KEYWORDS_JSON.exists(), f"{KEYWORDS_JSON} not found"
    with KEYWORDS_JSON.open() as fh:
        return json.load(fh)


class TestSteeringKeywordsJson:
    @pytest.mark.parametrize("group", sorted(REQUIRED_KEYWORD_GROUPS))
    def test_keyword_group_present(self, keywords_data, group):
        assert group in keywords_data, (
            f"steering_keywords.json missing required group '{group}'"
        )
        items = keywords_data[group]
        assert isinstance(items, list) and items, (
            f"steering_keywords.json '{group}' must be a non-empty list"
        )
        for item in items:
            assert isinstance(item, str) and item == item.lower() and item.strip(), (
                f"keyword '{item}' in group '{group}' must be a non-empty lowercase string"
            )

    def test_thresholds_present_and_positive(self, keywords_data):
        thresholds = keywords_data.get("thresholds")
        assert isinstance(thresholds, dict), "'thresholds' object missing"
        missing = REQUIRED_THRESHOLDS - set(thresholds.keys())
        assert not missing, f"thresholds missing keys: {sorted(missing)}"
        for k, v in thresholds.items():
            assert isinstance(v, int) and v >= 1, (
                f"threshold '{k}' must be an integer ≥ 1, got {v!r}"
            )

    def test_no_duplicate_keywords_within_group(self, keywords_data):
        for group in REQUIRED_KEYWORD_GROUPS:
            items = keywords_data.get(group, [])
            dupes = [k for k in set(items) if items.count(k) > 1]
            assert not dupes, f"duplicate keywords in '{group}': {dupes}"

    def test_no_keyword_in_multiple_groups(self, keywords_data):
        """A keyword classified into more than one bucket would create
        ambiguous matching weights."""
        seen: dict[str, str] = {}
        conflicts = []
        for group in REQUIRED_KEYWORD_GROUPS:
            for kw in keywords_data.get(group, []):
                if kw in seen and seen[kw] != group:
                    conflicts.append(f"'{kw}' in both '{seen[kw]}' and '{group}'")
                seen[kw] = group
        assert not conflicts, "keyword classified into multiple groups: " + ", ".join(conflicts)
