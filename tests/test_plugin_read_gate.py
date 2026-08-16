"""Tests for scripts/plugin_read_gate.py.

The gate exists because a prompt-level rule did not hold: the orchestrator read
`walkthrough_renderer.py` mid-run, filled its context, and compacted twice. So
the cases that matter are the ones a prompt would miss — a read reached through
`..` or a symlink — plus the boundary that keeps the pipeline working: the
directories it is *supposed* to read must stay open.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import plugin_read_gate as gate  # noqa: E402

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "plugin_read_gate.py"


def _payload(path: str, tool: str = "Read", event: str = "PreToolUse") -> dict:
    field = "file_path" if tool == "Read" else "path"
    return {"hook_event_name": event, "tool_name": tool, "tool_input": {field: path}}


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in ("agents", "scripts", "skills", "data", "schemas", "docs/security"):
        (tmp_path / name).mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
    monkeypatch.delenv("APPSEC_PLUGIN_DEV", raising=False)
    return Path(os.path.realpath(tmp_path))


class TestDenies:
    def test_reading_an_implementation_file_is_blocked(self, root: Path):
        response = gate.decide(_payload(str(root / "scripts" / "walkthrough_renderer.py")))
        assert response is not None
        decision = response["hookSpecificOutput"]
        assert decision["permissionDecision"] == "deny"
        assert "repair plan" in decision["permissionDecisionReason"]

    @pytest.mark.parametrize("tool", ["Read", "Grep", "Glob"])
    def test_every_read_shaped_tool_is_covered(self, root: Path, tool: str):
        assert gate.decide(_payload(str(root / "scripts" / "qa_checks.py"), tool=tool)) is not None

    def test_a_traversal_path_cannot_walk_back_in(self, root: Path):
        sneaky = str(root / "agents" / ".." / "scripts" / "qa_checks.py")
        assert gate.decide(_payload(sneaky)) is not None

    def test_a_symlink_into_scripts_cannot_evade_the_check(self, root: Path):
        target = root / "scripts" / "compose_threat_model.py"
        target.write_text("x\n", encoding="utf-8")
        link = root / "agents" / "shortcut.py"
        link.symlink_to(target)
        assert gate.decide(_payload(str(link))) is not None


class TestAllows:
    @pytest.mark.parametrize(
        "rel", ["agents/appsec-qa-reviewer.md", "skills/x/SKILL.md", "data/x.yaml", "schemas/x.json"]
    )
    def test_the_directories_the_pipeline_lazy_loads_stay_open(self, root: Path, rel: str):
        """Blocking these would break phase-boundary loading and contract reads."""
        assert gate.decide(_payload(str(root / rel))) is None

    def test_a_file_outside_the_plugin_is_untouched(self, root: Path, tmp_path: Path):
        assert gate.decide(_payload(str(tmp_path.parent / "elsewhere" / "scripts" / "a.py"))) is None

    def test_developer_mode_lifts_the_gate(self, root: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("APPSEC_PLUGIN_DEV", "1")
        assert gate.decide(_payload(str(root / "scripts" / "qa_checks.py"))) is None

    def test_a_write_tool_is_not_this_gate_s_business(self, root: Path):
        assert gate.decide(_payload(str(root / "scripts" / "qa_checks.py"), tool="Edit")) is None

    def test_a_non_pretooluse_event_is_ignored(self, root: Path):
        payload = _payload(str(root / "scripts" / "qa_checks.py"), event="PostToolUse")
        assert gate.decide(payload) is None


class TestFailsOpen:
    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"hook_event_name": "PreToolUse"},
            {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {}},
        ],
    )
    def test_a_payload_it_cannot_read_is_allowed(self, root: Path, payload: dict):
        assert gate.decide(payload) is None

    def test_the_process_allows_on_malformed_stdin(self):
        result = subprocess.run([sys.executable, str(SCRIPT)], input="not json", capture_output=True, text=True)
        assert result.returncode == 0
        assert result.stdout.strip() == ""


def test_end_to_end_through_the_process(root: Path):
    """The hook is invoked as a subprocess, so the wiring has to work there too."""
    env = {**os.environ, "CLAUDE_PLUGIN_ROOT": str(root)}
    env.pop("APPSEC_PLUGIN_DEV", None)
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(_payload(str(root / "scripts" / "qa_checks.py"))),
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
