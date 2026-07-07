"""Tests for scripts/detect_session_model.py.

The detector is a fail-safe transparency helper: it must ALWAYS exit 0 and print
either a model id or an empty string, and must survive missing dirs, missing
sessions, and malformed transcript lines without raising.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "detect_session_model.py"


def _load_module():
    if "detect_session_model" in sys.modules:
        return sys.modules["detect_session_model"]
    spec = importlib.util.spec_from_file_location("detect_session_model", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["detect_session_model"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


dsm = _load_module()


def _write_transcript(path: Path, lines: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(o) for o in lines), encoding="utf-8")


def _asst(model: str, sidechain: bool = False) -> dict:
    return {"type": "assistant", "isSidechain": sidechain, "message": {"model": model}}


def _make_session(home: Path, sid: str, lines: list[dict]) -> Path:
    proj = home / ".claude" / "projects" / "-some-project"
    proj.mkdir(parents=True, exist_ok=True)
    f = proj / f"{sid}.jsonl"
    _write_transcript(f, lines)
    return f


def test_last_non_sidechain_assistant_model(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _make_session(
        tmp_path,
        "sid-1",
        [
            {"type": "user", "message": {"content": "hi"}},
            _asst("claude-sonnet-4-6"),
            _asst("claude-haiku-4-5", sidechain=True),  # sub-agent — must be skipped
            _asst("claude-opus-4-8"),
        ],
    )
    assert dsm.detect_session_model("sid-1") == "claude-opus-4-8"


def test_sidechain_only_yields_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _make_session(tmp_path, "sid-2", [_asst("claude-haiku-4-5", sidechain=True)])
    assert dsm.detect_session_model("sid-2") == ""


def test_missing_session_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert dsm.detect_session_model("does-not-exist") == ""


def test_no_projects_dir_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert dsm.detect_session_model("anything") == ""


def test_malformed_lines_tolerated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    proj = tmp_path / ".claude" / "projects" / "-p"
    proj.mkdir(parents=True)
    (proj / "sid-3.jsonl").write_text(
        "{not json\n" + json.dumps(_asst("claude-sonnet-4-6")) + "\n{also bad",
        encoding="utf-8",
    )
    assert dsm.detect_session_model("sid-3") == "claude-sonnet-4-6"


def test_env_session_id_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "sid-env")
    monkeypatch.delenv("CLAUDE_SESSION_ID", raising=False)
    _make_session(tmp_path, "sid-env", [_asst("claude-opus-4-8")])
    # No explicit id → resolves from $CLAUDE_CODE_SESSION_ID.
    assert dsm.detect_session_model() == "claude-opus-4-8"


def test_newest_transcript_fallback_when_no_sid(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("CLAUDE_CODE_SESSION_ID", raising=False)
    monkeypatch.delenv("CLAUDE_SESSION_ID", raising=False)
    old = _make_session(tmp_path, "old", [_asst("claude-sonnet-4-6")])
    new = _make_session(tmp_path, "new", [_asst("claude-opus-4-8")])
    import os

    os.utime(old, (1000, 1000))
    os.utime(new, (2000, 2000))
    # No id anywhere → newest transcript wins.
    assert dsm.detect_session_model() == "claude-opus-4-8"


class TestCLI:
    def _run(self, *argv, env=None):
        return subprocess.run(
            [sys.executable, str(SCRIPT_PATH), *argv],
            capture_output=True,
            text=True,
            env=env,
        )

    def test_always_exit_zero_on_miss(self, tmp_path, monkeypatch):
        import os

        env = dict(os.environ)
        env["HOME"] = str(tmp_path)
        env.pop("CLAUDE_CODE_SESSION_ID", None)
        env.pop("CLAUDE_SESSION_ID", None)
        r = self._run("--session-id", "nope", env=env)
        assert r.returncode == 0
        assert r.stdout == ""

    def test_prints_model_id(self, tmp_path):
        import os

        _make_session(tmp_path, "sid-cli", [_asst("claude-opus-4-8")])
        env = dict(os.environ)
        env["HOME"] = str(tmp_path)
        r = self._run("--session-id", "sid-cli", env=env)
        assert r.returncode == 0
        assert r.stdout == "claude-opus-4-8"
