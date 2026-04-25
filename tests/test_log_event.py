"""Tests for scripts/log_event.py — the unified phase/step event emitter.

Pins the dual-write contract:
  * canonical log entry appended to .agent-run.log (same format as legacy raw echoes)
  * compact human-readable line mirrored to stderr (always — not gated on --verbose)
  * elapsed-time prefix auto-computed from .phase-epoch when available
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import time
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "log_event.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("log_event", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


log_event = _load_module()


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )


# ---------------------------------------------------------------------------
# Mirror line formatting — the part the user actually sees on stderr
# ---------------------------------------------------------------------------

class TestMirrorLine:
    def test_phase_start_formats_phase_and_arrow(self):
        line = log_event._mirror_line(
            "phase-start", "[Phase 3/11] ▶ Architecture Modeling", elapsed="2m15s",
        )
        assert "▶" in line
        assert "Phase 3/11" in line
        assert "2m15s" in line
        # The duplicated "[Phase …]" prefix must be stripped from the detail.
        assert "[Phase 3/11]" not in line

    def test_step_start_shows_k_of_n(self):
        line = log_event._mirror_line(
            "step-start", "[Phase 11] [4/7] Writing fragments…", elapsed="1m02s",
        )
        assert "↳" in line
        assert "step 4/7" in line
        assert "1m02s" in line
        assert "Writing fragments" in line

    def test_info_form_has_no_elapsed_when_absent(self):
        # `info` kind does not auto-add elapsed; the mirror line stays tight.
        line = log_event._mirror_line("info", "FILE_WRITE_COMPLETED", elapsed="")
        assert "FILE_WRITE_COMPLETED" in line
        # No empty "( )" from a blank elapsed.
        assert "()" not in line


# ---------------------------------------------------------------------------
# CLI end-to-end: log entry + stderr mirror + elapsed from .phase-epoch
# ---------------------------------------------------------------------------

class TestCliBehaviour:
    def test_writes_canonical_log_line_and_mirrors_to_stderr(self, tmp_path: Path):
        out = tmp_path / "output"
        out.mkdir()
        res = _run([str(out), "step-start", "[Phase 11] [4/7] Writing fragments…"], tmp_path)

        assert res.returncode == 0, res.stderr

        # File side: canonical log entry present.
        log = (out / ".agent-run.log").read_text(encoding="utf-8")
        assert "STEP_START" in log
        assert "[Phase 11] [4/7] Writing fragments…" in log
        # Timestamp format: 2026-04-24T18:30:00Z
        import re as _re
        assert _re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", log)

        # Stderr side: compact mirror with the ↳ step glyph and "step 4/7".
        assert "↳" in res.stderr
        assert "step 4/7" in res.stderr

    def test_phase_start_uses_phase_epoch_for_elapsed(self, tmp_path: Path):
        out = tmp_path / "output"
        out.mkdir()
        # Simulate a phase started 125 seconds ago.
        (out / ".phase-epoch").write_text(str(int(time.time()) - 125))
        res = _run([str(out), "phase-start", "[Phase 9/11] ▶ STRIDE"], tmp_path)

        assert res.returncode == 0
        # Allow for a 2-second jitter on slow CI boxes.
        assert "+2m0" in res.stderr or "+2m1" in res.stderr, \
            f"expected a +~2m elapsed prefix in stderr, got: {res.stderr!r}"

    def test_missing_phase_epoch_omits_elapsed(self, tmp_path: Path):
        out = tmp_path / "output"
        out.mkdir()
        res = _run([str(out), "step-start", "[Phase 11] [1/7] kicking off…"], tmp_path)
        assert res.returncode == 0
        # No "(+..)" prefix — elapsed omitted cleanly.
        assert "(+" not in res.stderr
        # But the step number is still there.
        assert "step 1/7" in res.stderr

    def test_info_form_accepts_custom_event_name(self, tmp_path: Path):
        out = tmp_path / "output"
        out.mkdir()
        res = _run([str(out), "info", "CUSTOM_EVENT", "something happened"], tmp_path)
        assert res.returncode == 0
        log = (out / ".agent-run.log").read_text(encoding="utf-8")
        assert "CUSTOM_EVENT" in log
        assert "something happened" in log
        assert "something happened" in res.stderr

    def test_unknown_kind_is_usage_error(self, tmp_path: Path):
        out = tmp_path / "output"
        out.mkdir()
        res = _run([str(out), "bogus-kind", "detail"], tmp_path)
        assert res.returncode == 2
        assert "unknown kind" in res.stderr

    def test_stderr_mirror_is_not_gated_on_verbose_env(self, tmp_path: Path, monkeypatch):
        """The user must see progress lines even without APPSEC_VERBOSE — that's
        the whole point of log_event.py vs. the legacy echo+hook path."""
        monkeypatch.delenv("APPSEC_VERBOSE", raising=False)
        out = tmp_path / "output"
        out.mkdir()
        res = _run([str(out), "step-start", "[Phase 11] [4/7] Writing fragments…"], tmp_path)
        assert res.returncode == 0
        assert res.stderr.strip(), "stderr mirror must fire even without verbose"
