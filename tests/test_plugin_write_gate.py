"""Tests for scripts/plugin_write_gate.py.

The gate's whole value is that it holds when the prompt does not, so the cases
that matter are the ones a prompt-level rule would miss: a write reached through
``..``, a write reached through a symlink, and a write the model attempts while
developer mode is off.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import plugin_write_gate as gate  # noqa: E402

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "plugin_write_gate.py"


def _payload(path: str, tool: str = "Edit", event: str = "PreToolUse") -> dict:
    field = "notebook_path" if tool == "NotebookEdit" else "file_path"
    return {"hook_event_name": event, "tool_name": tool, "tool_input": {field: path}}


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake plugin checkout with the protected and unprotected subtrees."""
    for name in ("agents", "scripts", "skills", "data", "docs/security", "tests"):
        (tmp_path / name).mkdir(parents=True, exist_ok=True)
    (tmp_path / "config.json").write_text("{}\n")
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
    monkeypatch.delenv("APPSEC_PLUGIN_DEV", raising=False)
    return Path(os.path.realpath(tmp_path))


class TestDenies:
    @pytest.mark.parametrize(
        "rel",
        [
            "agents/appsec-run-diagnostician.md",
            "scripts/merge_threats.py",
            "skills/fix-run-issues/SKILL.md",
            "data/severity-caps.yaml",
            "config.json",
        ],
    )
    def test_plugin_source_is_blocked(self, root: Path, rel: str):
        response = gate.decide(_payload(str(root / rel)))
        assert response is not None
        decision = response["hookSpecificOutput"]
        assert decision["permissionDecision"] == "deny"
        assert "report-error" in decision["permissionDecisionReason"]

    @pytest.mark.parametrize("tool", ["Edit", "Write", "NotebookEdit"])
    def test_every_writing_tool_is_covered(self, root: Path, tool: str):
        assert gate.decide(_payload(str(root / "scripts/x.py"), tool=tool)) is not None

    def test_dot_dot_traversal_cannot_walk_in(self, root: Path):
        sneaky = str(root / "docs" / ".." / "scripts" / "merge_threats.py")
        assert gate.decide(_payload(sneaky)) is not None

    def test_symlink_cannot_walk_in(self, root: Path, tmp_path: Path):
        link = tmp_path.parent / "link-to-scripts"
        link.symlink_to(root / "scripts")
        assert gate.decide(_payload(str(link / "merge_threats.py"))) is not None


class TestAllows:
    def test_developer_mode_allows_everything(self, root: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("APPSEC_PLUGIN_DEV", "1")
        assert gate.decide(_payload(str(root / "scripts/merge_threats.py"))) is None

    @pytest.mark.parametrize("value", ["0", "", "true", "yes"])
    def test_only_the_literal_1_opens_the_gate(self, root: Path, monkeypatch: pytest.MonkeyPatch, value: str):
        monkeypatch.setenv("APPSEC_PLUGIN_DEV", value)
        assert gate.decide(_payload(str(root / "scripts/merge_threats.py"))) is not None

    def test_the_deliverable_stays_writable(self, root: Path):
        """PLUGIN_ROOT == scanned repo in a dev checkout; the run must still work."""
        assert gate.decide(_payload(str(root / "docs/security/threat-model.md"))) is None

    def test_paths_outside_the_plugin_are_untouched(self, root: Path, tmp_path: Path):
        outside = tmp_path.parent / "some-target-repo" / "scripts" / "app.py"
        assert gate.decide(_payload(str(outside))) is None

    def test_root_adjacent_prefix_is_not_inside(self, root: Path):
        """`<root>-backup/` shares a string prefix with the root but is not in it."""
        assert gate.decide(_payload(f"{root}-backup/scripts/x.py")) is None

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"hook_event_name": "PostToolUse", "tool_name": "Edit", "tool_input": {"file_path": "/x"}},
            {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "/x"}},
            {"hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_input": {}},
            {"hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_input": {"file_path": 7}},
        ],
    )
    def test_unrecognized_payloads_allow(self, root: Path, payload: dict):
        assert gate.decide(payload) is None


class TestCLI:
    def _run(self, payload: str, env: dict) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=payload,
            capture_output=True,
            text=True,
            env={**os.environ, **env},
        )

    def test_deny_is_printed_as_json(self, root: Path):
        result = self._run(
            json.dumps(_payload(str(root / "scripts/x.py"))),
            {"CLAUDE_PLUGIN_ROOT": str(root), "APPSEC_PLUGIN_DEV": "0"},
        )
        assert result.returncode == 0
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_allow_prints_nothing(self, root: Path):
        result = self._run(
            json.dumps(_payload(str(root / "docs/security/threat-model.md"))),
            {"CLAUDE_PLUGIN_ROOT": str(root), "APPSEC_PLUGIN_DEV": "0"},
        )
        assert result.returncode == 0
        assert result.stdout.strip() == ""

    def test_malformed_input_allows(self, root: Path):
        result = self._run("not json", {"CLAUDE_PLUGIN_ROOT": str(root)})
        assert result.returncode == 0
        assert result.stdout.strip() == ""
