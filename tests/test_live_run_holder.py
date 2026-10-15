"""Tests for scripts/runtime/live_run_holder.py."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from runtime import live_run_holder  # noqa: E402


def _output(tmp_path: Path) -> Path:
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True)
    return out


def _lock(out: Path, heartbeat: int, run_id: str = "assessment-abc") -> None:
    (out / ".appsec-lock").write_text(f"999999\n{heartbeat}\n{run_id}\n", encoding="utf-8")


def test_no_lock_is_free(tmp_path: Path):
    assert live_run_holder.holder(_output(tmp_path)) is None


def test_fresh_heartbeat_names_the_run(tmp_path: Path):
    out = _output(tmp_path)
    now = int(time.time())
    _lock(out, now - 5)
    (out / ".assessment-state.json").write_text(json.dumps({"started_at": now - 600}), encoding="utf-8")
    found = live_run_holder.holder(out, now=now)
    assert found is not None
    assert found.startswith("live run_id=assessment-abc started=")
    assert found.endswith("heartbeat_age=5s")


def test_stale_heartbeat_is_free(tmp_path: Path):
    out = _output(tmp_path)
    _lock(out, int(time.time()) - 3600)
    assert live_run_holder.holder(out) is None


def test_cli_exit_codes(tmp_path: Path, capsys):
    out = _output(tmp_path)
    assert live_run_holder.main(["--output", str(out)]) == 0
    assert capsys.readouterr().out.strip() == "free"
    _lock(out, int(time.time()))
    assert live_run_holder.main(["--output", str(out)]) == 3
    assert capsys.readouterr().out.startswith("live run_id=assessment-abc")
