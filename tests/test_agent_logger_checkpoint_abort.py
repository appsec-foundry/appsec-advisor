"""Unit tests for scripts/agent_logger.py: Stop-hook checkpoint-abort logic."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "agent_logger.py"


@pytest.fixture
def agent_logger(tmp_path, monkeypatch):
    """Import agent_logger with OUTPUT_DIR pointed at the tmp dir."""
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))

    spec = importlib.util.spec_from_file_location("agent_logger", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_logger"] = module
    assert spec.loader is not None
    # Swallow stdin-JSON warning that fires at import time
    import contextlib
    import io

    with contextlib.redirect_stderr(io.StringIO()):
        spec.loader.exec_module(module)
    return module


def _write_checkpoint(tmp_path: Path, content: str) -> Path:
    cp = tmp_path / ".appsec-checkpoint"
    cp.write_text(content)
    return cp


# ---------------------------------------------------------------------------
# No-op paths
# ---------------------------------------------------------------------------


def test_no_checkpoint_no_op(tmp_path: Path, agent_logger):
    agent_logger._mark_checkpoint_aborted_if_dirty("unknown")
    assert not (tmp_path / ".appsec-checkpoint").exists()


def test_clean_stop_reason_noop(tmp_path: Path, agent_logger):
    cp = _write_checkpoint(tmp_path, "phase=5 status=started timestamp=x\n")
    agent_logger._mark_checkpoint_aborted_if_dirty("end_turn")
    assert "status=started" in cp.read_text()


def test_stop_sequence_also_clean(tmp_path: Path, agent_logger):
    cp = _write_checkpoint(tmp_path, "phase=5 status=started\n")
    agent_logger._mark_checkpoint_aborted_if_dirty("stop_sequence")
    assert "status=started" in cp.read_text()


def test_already_completed_never_overwritten(tmp_path: Path, agent_logger):
    cp = _write_checkpoint(tmp_path, "phase=11 status=completed timestamp=x\n")
    agent_logger._mark_checkpoint_aborted_if_dirty("unknown")
    assert "status=completed" in cp.read_text()
    assert "status=aborted" not in cp.read_text()


def test_already_aborted_not_double_rewritten(tmp_path: Path, agent_logger):
    """If a prior Stop already stamped aborted, a later Stop must not change it."""
    cp = _write_checkpoint(
        tmp_path,
        "phase=5 status=aborted reason=unknown aborted_at=2026-04-24T12:00:00Z\n",
    )
    agent_logger._mark_checkpoint_aborted_if_dirty("max_turns")
    text = cp.read_text()
    # First reason is preserved
    assert "reason=unknown" in text
    assert "reason=max_turns" not in text


# ---------------------------------------------------------------------------
# Active rewrite path
# ---------------------------------------------------------------------------


def test_unclean_stop_rewrites_started_to_aborted(tmp_path: Path, agent_logger):
    cp = _write_checkpoint(tmp_path, "phase=5 status=started timestamp=x\n")
    agent_logger._mark_checkpoint_aborted_if_dirty("max_turns")
    text = cp.read_text()
    assert "status=aborted" in text
    assert "reason=max_turns" in text
    assert "phase=5" in text
    assert "aborted_at=" in text


def test_unknown_reason_is_preserved_verbatim(tmp_path: Path, agent_logger):
    cp = _write_checkpoint(tmp_path, "phase=3 status=started\n")
    agent_logger._mark_checkpoint_aborted_if_dirty("cancelled_by_user")
    assert "reason=cancelled_by_user" in cp.read_text()


def test_phase_number_is_carried_over(tmp_path: Path, agent_logger):
    cp = _write_checkpoint(tmp_path, "phase=9 status=started\n")
    agent_logger._mark_checkpoint_aborted_if_dirty("unknown")
    assert "phase=9 status=aborted" in cp.read_text()


def test_missing_phase_field_uses_question_mark(tmp_path: Path, agent_logger):
    cp = _write_checkpoint(tmp_path, "status=started\n")
    agent_logger._mark_checkpoint_aborted_if_dirty("unknown")
    assert "phase=?" in cp.read_text()


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


def test_empty_checkpoint_is_left_alone(tmp_path: Path, agent_logger):
    cp = _write_checkpoint(tmp_path, "")
    agent_logger._mark_checkpoint_aborted_if_dirty("unknown")
    assert cp.read_text() == ""


def test_never_raises_on_missing_dir(tmp_path: Path, monkeypatch):
    """Called from a hook — must be exception-safe."""
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path / "does-not-exist"))
    spec = importlib.util.spec_from_file_location("agent_logger", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_logger"] = module
    import contextlib
    import io

    with contextlib.redirect_stderr(io.StringIO()):
        spec.loader.exec_module(module)
    # No exception even though dir is missing
    module._mark_checkpoint_aborted_if_dirty("unknown")
