"""Schema tests for hooks/hooks.json and steering_keywords.json.

These config files are not exercised by the existing pytest suite; a typo or
missing key would only surface at runtime when Claude Code loads the plugin.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

HOOKS_DIR = Path(__file__).parent.parent / "hooks"
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
        assert not missing, f"hooks.json is missing event registrations for: {sorted(missing)}"

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
        assert isinstance(entries, list) and entries, f"hooks.{event} must be a non-empty list"
        for outer in entries:
            assert "hooks" in outer and isinstance(outer["hooks"], list), (
                f"hooks.{event}[*] must contain a 'hooks' list"
            )
            for h in outer["hooks"]:
                assert h.get("type") == "command", f"hooks.{event}[*].hooks[*].type must be 'command'"
                cmd = h.get("command", "")
                assert isinstance(cmd, str) and cmd.strip(), (
                    f"hooks.{event}[*].hooks[*].command must be a non-empty string"
                )
                # Plugin scripts must be invoked via $CLAUDE_PLUGIN_ROOT
                assert "${CLAUDE_PLUGIN_ROOT}" in cmd or "$CLAUDE_PLUGIN_ROOT" in cmd, (
                    f"hooks.{event} command does not use $CLAUDE_PLUGIN_ROOT — plugin would be unportable: {cmd!r}"
                )

    def test_referenced_scripts_exist(self, hooks_data):
        """Every hook command must reference a script that actually exists."""
        plugin_root = Path(__file__).parent.parent
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
                    assert script_path.exists(), f"hooks.{event} references missing script: {script_path}"


# ---------------------------------------------------------------------------
# steering_keywords.json structure
# ---------------------------------------------------------------------------

REQUIRED_FLAT_KEYWORD_GROUPS = {"code_keywords", "action_keywords"}
REQUIRED_THRESHOLDS = {
    "code_min",
    "code_action_code_min",
    "code_action_action_min",
}
REQUIRED_TOPICS = {"general", "auth", "injection", "crypto", "xss_csrf"}


@pytest.fixture(scope="module")
def keywords_data():
    assert KEYWORDS_JSON.exists(), f"{KEYWORDS_JSON} not found"
    with KEYWORDS_JSON.open() as fh:
        return json.load(fh)


class TestSteeringKeywordsJson:
    @pytest.mark.parametrize("group", sorted(REQUIRED_FLAT_KEYWORD_GROUPS))
    def test_keyword_group_present(self, keywords_data, group):
        assert group in keywords_data, f"steering_keywords.json missing required group '{group}'"
        items = keywords_data[group]
        assert isinstance(items, list) and items, f"steering_keywords.json '{group}' must be a non-empty list"
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
            assert isinstance(v, int) and v >= 1, f"threshold '{k}' must be an integer >= 1, got {v!r}"

    def test_baseline_present(self, keywords_data):
        baseline = keywords_data.get("baseline")
        assert isinstance(baseline, str) and baseline.strip(), (
            "steering_keywords.json must define a non-empty 'baseline' string"
        )

    def test_topics_present(self, keywords_data):
        topics = keywords_data.get("topics")
        assert isinstance(topics, dict), "'topics' object missing"
        missing = REQUIRED_TOPICS - set(topics.keys())
        assert not missing, f"steering_keywords.json missing topics: {sorted(missing)}"

    @pytest.mark.parametrize("topic", sorted(REQUIRED_TOPICS))
    def test_topic_has_non_empty_triggers(self, keywords_data, topic):
        spec = keywords_data["topics"][topic]
        triggers = spec.get("triggers")
        assert isinstance(triggers, list) and triggers, f"topics.{topic}.triggers must be a non-empty list"
        for t in triggers:
            assert isinstance(t, str) and t == t.lower() and t.strip(), (
                f"trigger '{t}' in topics.{topic} must be a non-empty lowercase string"
            )

    def test_no_duplicate_triggers_within_topic(self, keywords_data):
        for name, spec in keywords_data.get("topics", {}).items():
            triggers = spec.get("triggers", [])
            dupes = [k for k in set(triggers) if triggers.count(k) > 1]
            assert not dupes, f"duplicate triggers in topic '{name}': {dupes}"

    def test_no_duplicate_keywords_within_flat_groups(self, keywords_data):
        for group in REQUIRED_FLAT_KEYWORD_GROUPS:
            items = keywords_data.get(group, [])
            dupes = [k for k in set(items) if items.count(k) > 1]
            assert not dupes, f"duplicate keywords in '{group}': {dupes}"

    def test_topic_requirement_ids_are_nonempty_strings(self, keywords_data):
        """Requirement IDs are opaque strings — the naming scheme is org-defined
        and varies per company catalog, so NO prefix (SEC-, BP-, ACME-, …) is
        enforced. The company-vs-best-practices distinction comes from the
        catalog's `source` field, not from the id. Only structural hygiene is
        checked here."""
        bad = []
        for name, spec in keywords_data.get("topics", {}).items():
            for rid in spec.get("requirements") or []:
                if not (isinstance(rid, str) and rid.strip()):
                    bad.append(f"{name}:{rid!r}")
        assert not bad, "topic requirement ids must be non-empty strings: " + ", ".join(bad)

    def test_shipped_topic_requirements_resolve_in_a_bundled_catalog(self, keywords_data):
        """Typo guard for the SHIPPED defaults only (scheme-agnostic): every id
        the bundled steering_keywords.json references must exist in at least one
        bundled catalog (the sample company catalog or the best-practices
        baseline), whatever its naming scheme. Orgs that customise this file with
        their own catalog own their own ids — this only protects our defaults."""
        import yaml

        root = Path(__file__).parent.parent / "data"
        known: set[str] = set()
        for fname in ("appsec-requirements-fallback.yaml", "appsec-bestpractices-baseline.yaml"):
            data = yaml.safe_load((root / fname).read_text(encoding="utf-8")) or {}
            for cat in data.get("categories") or []:
                for req in cat.get("requirements") or []:
                    if isinstance(req, dict) and req.get("id"):
                        known.add(req["id"])
        unresolved = []
        for name, spec in keywords_data.get("topics", {}).items():
            for rid in spec.get("requirements") or []:
                if isinstance(rid, str) and rid not in known:
                    unresolved.append(f"{name}:{rid}")
        assert not unresolved, "shipped steering topic ids not found in any bundled catalog (typo?): " + ", ".join(
            unresolved
        )
