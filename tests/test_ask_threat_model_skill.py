"""Drift guards for the read-only ask-threat-model skill contract."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parent.parent
SKILL = ROOT / "skills" / "ask-threat-model" / "SKILL.md"


def test_ask_skill_requires_host_supplied_plugin_root() -> None:
    text = SKILL.read_text(encoding="utf-8")
    assert "find /root /home /opt" not in text
    assert '"$CLAUDE_PLUGIN_ROOT/.claude-plugin/plugin.json"' in text
    assert '"$CLAUDE_PLUGIN_ROOT/scripts/query_threat_model.py"' in text


def test_ask_skill_uses_quoted_argument_array_and_exposes_targeted_filters() -> None:
    text = SKILL.read_text(encoding="utf-8")
    assert 'QUERY_ARGS=(--output-dir "$OUTPUT_DIR" --repo-root "$REPO_ROOT")' in text
    assert '"${QUERY_ARGS[@]}"' in text
    for flag in ("--severity <level>", "--component <name>", "--evidence-state <state>"):
        assert flag in text
