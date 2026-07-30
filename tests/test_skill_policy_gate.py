"""Tests for scripts/skill_policy_gate.py — enforcing the org skill policy.

Two properties carry the weight.

*It blocks what the policy disables*, on both paths a skill is reached: Claude
calling the ``Skill`` tool, and a person typing ``/<plugin>:<skill>``.

*It never blocks anything else.* The expansion payload can carry an expanded
skill body, and skill bodies mention other commands — ``install-baseline``'s own
text names ``/appsec-advisor:verify-baseline``. A match anywhere in any field
would block a skill because a different skill documented it, so the matcher is
anchored to the start of a short list of fields. The cases below pin that.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "skill_policy_gate.py"
sys.path.insert(0, str(SCRIPT.parent))

import skill_policy_gate as spg  # noqa: E402

DISABLED = {"publish-threat-model": {"enabled": False, "reason": "Release job only."}}


@pytest.fixture
def build(tmp_path, monkeypatch):
    """A packaged plugin root named ``acme-appsec`` with a policy."""
    root = tmp_path / "acme-appsec"
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": "acme-appsec"}), encoding="utf-8")
    (root / "config.json").write_text(json.dumps({"skill_toggles": DISABLED}), encoding="utf-8")
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(root))
    monkeypatch.delenv("OUTPUT_DIR", raising=False)
    return root


def tool_call(skill: str) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": "Skill", "tool_input": {"skill": skill}}


def typed(command: str, field: str = "command") -> dict:
    return {"hook_event_name": "UserPromptExpansion", field: command}


# ---------- it blocks what the policy disables ----------------------------


def test_blocks_a_disabled_skill_invoked_by_claude(build):
    response = spg.decide(tool_call("acme-appsec:publish-threat-model"))
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "Release job only." in response["hookSpecificOutput"]["permissionDecisionReason"]


def test_blocks_a_disabled_skill_typed_by_a_person(build):
    response = spg.decide(typed("/acme-appsec:publish-threat-model --pdf"))
    assert response["decision"] == "block"
    assert "Release job only." in response["reason"]


def test_a_bare_skill_name_is_matched(build):
    """Not every caller spells the namespace."""
    assert spg.decide(tool_call("publish-threat-model")) is not None


def test_an_enabled_skill_passes(build):
    assert spg.decide(tool_call("acme-appsec:review-threat-model")) is None


def test_a_recovery_skill_is_never_blocked(build):
    """Blocking one would strand a user with a broken run and no way to clean up."""
    (build / "config.json").write_text(
        json.dumps({"skill_toggles": {"clean-run-state": {"enabled": False, "reason": "no"}}}), encoding="utf-8"
    )
    assert spg.decide(tool_call("clean-run-state")) is None


# ---------- it never blocks anything else --------------------------------


def test_a_command_mentioned_inside_an_expanded_body_is_not_blocked(build):
    """The real payload risk: a skill's own text naming another command."""
    body = (
        "You are installing a secure-coding baseline.\n\n"
        "Related: /acme-appsec:publish-threat-model — publishes the report.\n"
    )
    assert spg.decide(typed(body, field="prompt")) is None


def test_a_command_for_a_different_plugin_is_ignored(build):
    assert spg.decide(typed("/other-plugin:publish-threat-model")) is None


def test_a_tool_call_for_a_different_plugin_is_ignored(build):
    assert spg.decide(tool_call("other-plugin:publish-threat-model")) is None


def test_a_non_skill_tool_call_is_ignored(build):
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}}
    assert spg.decide(payload) is None


def test_an_unknown_event_is_ignored(build):
    assert spg.decide({"hook_event_name": "PostToolUse", "tool_name": "Skill"}) is None


def test_an_unknown_field_is_not_scanned(build):
    assert (
        spg.decide({"hook_event_name": "UserPromptExpansion", "mystery": "/acme-appsec:publish-threat-model"}) is None
    )


def test_prose_mentioning_the_command_mid_sentence_is_ignored(build):
    assert spg.decide(typed("please run /acme-appsec:publish-threat-model for me")) is None


def test_no_policy_allows_everything(build):
    (build / "config.json").write_text("{}", encoding="utf-8")
    assert spg.decide(tool_call("publish-threat-model")) is None


def test_a_damaged_config_allows(build):
    """Fail open: a broken config must not read as a policy."""
    (build / "config.json").write_text("{not json", encoding="utf-8")
    assert spg.decide(tool_call("publish-threat-model")) is None


def test_a_missing_manifest_allows(build):
    (build / ".claude-plugin" / "plugin.json").unlink()
    assert spg.decide(typed("/acme-appsec:publish-threat-model")) is None


def test_malformed_tool_input_allows(build):
    assert spg.decide({"hook_event_name": "PreToolUse", "tool_name": "Skill", "tool_input": "oops"}) is None


# ---------- the process contract -----------------------------------------


def run_hook(build: Path, payload: dict) -> tuple[int, str]:
    done = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "CLAUDE_PLUGIN_ROOT": str(build)},
    )
    return done.returncode, done.stdout


def test_process_emits_a_deny_payload(build):
    code, out = run_hook(build, tool_call("publish-threat-model"))
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_process_stays_silent_when_allowing(build):
    code, out = run_hook(build, tool_call("review-threat-model"))
    assert code == 0
    assert out.strip() == ""


def test_process_survives_garbage_on_stdin(build):
    done = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input="not json at all",
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "CLAUDE_PLUGIN_ROOT": str(build)},
    )
    assert done.returncode == 0
    assert done.stdout.strip() == ""


def test_registered_for_both_invocation_paths():
    """A skill is reached two ways; missing one leaves the policy half-applied."""
    hooks = json.loads((REPO_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    pre = [
        entry for entry in hooks["PreToolUse"] if any("skill_policy_gate.py" in h["command"] for h in entry["hooks"])
    ]
    assert pre and pre[0]["matcher"] == "Skill"
    assert any("skill_policy_gate.py" in h["command"] for entry in hooks["UserPromptExpansion"] for h in entry["hooks"])
