"""Tests for scripts/log_event.py — the unified phase/step event emitter.

Pins the dual-write contract:
  * canonical log entry appended to .agent-run.log (same format as legacy raw echoes)
  * compact human-readable line mirrored to stderr (always — not gated on --verbose)
  * elapsed-time prefix auto-computed from .phase-epoch when available
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import time
from pathlib import Path

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
            "phase-start",
            "[Phase 3/11] ▶ Architecture Modeling",
            elapsed="2m15s",
        )
        assert "▶" in line
        assert "Phase 3/11" in line
        assert "2m15s" in line
        # The duplicated "[Phase …]" prefix must be stripped from the detail.
        assert "[Phase 3/11]" not in line

    def test_step_start_shows_k_of_n(self):
        line = log_event._mirror_line(
            "step-start",
            "[Phase 11] [4/7] Writing fragments…",
            elapsed="1m02s",
        )
        assert "↳" in line
        assert "step 4/7" in line
        assert "1m02s" in line
        assert "Writing fragments" in line

    def test_step_start_with_phase_total_strips_prefixes_cleanly(self):
        line = log_event._mirror_line(
            "step-start",
            "[Phase 9/11] [2/5] Watching analyzers",
            elapsed="",
        )
        assert "Phase 9/11" in line
        assert "step 2/5" in line
        assert "Watching analyzers" in line
        assert "2/5]" not in line

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

        progress = json.loads((out / ".appsec-progress.json").read_text(encoding="utf-8"))
        assert progress["event"] == "STEP_START"
        assert progress["phase"] == "11"
        assert progress["step"] == 4
        assert progress["step_total"] == 7
        assert progress["status"] == "step_started"
        assert "Writing fragments" in progress["label"]

    def test_phase_start_uses_phase_epoch_for_elapsed(self, tmp_path: Path):
        out = tmp_path / "output"
        out.mkdir()
        # Simulate a phase started 125 seconds ago.
        (out / ".phase-epoch").write_text(str(int(time.time()) - 125))
        res = _run([str(out), "phase-start", "[Phase 9/11] ▶ STRIDE"], tmp_path)

        assert res.returncode == 0
        # Allow for a 2-second jitter on slow CI boxes.
        assert "+2m0" in res.stderr or "+2m1" in res.stderr, (
            f"expected a +~2m elapsed prefix in stderr, got: {res.stderr!r}"
        )

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
        progress = json.loads((out / ".appsec-progress.json").read_text(encoding="utf-8"))
        assert progress["event"] == "CUSTOM_EVENT"
        assert progress["status"] == "info"

    def test_agent_flag_sets_log_and_progress_agent(self, tmp_path: Path):
        out = tmp_path / "output"
        out.mkdir()
        res = _run([str(out), "phase-start", "[Phase 11/11] Finalization", "--agent", "threat-renderer"], tmp_path)
        assert res.returncode == 0
        log = (out / ".agent-run.log").read_text(encoding="utf-8")
        # Canonical format pads the component column (event_log.format_line),
        # so the agent name precedes the event with column padding between.
        assert re.search(r"\bthreat-renderer\s+PHASE_START\b", log)
        progress = json.loads((out / ".appsec-progress.json").read_text(encoding="utf-8"))
        assert progress["agent"] == "threat-renderer"

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


# ---------------------------------------------------------------------------
# In-process unit tests for branch/error coverage (no subprocess overhead)
# ---------------------------------------------------------------------------


class TestElapsedClamp:
    def test_future_phase_epoch_clamps_to_zero(self, tmp_path: Path):
        # .phase-epoch in the future -> negative elapsed clamped to 0 (line 91).
        (tmp_path / ".phase-epoch").write_text(str(int(time.time()) + 500))
        assert log_event._elapsed_str(tmp_path) == "+0m00s"

    def test_invalid_phase_epoch_returns_none(self, tmp_path: Path):
        (tmp_path / ".phase-epoch").write_text("not-a-number")
        assert log_event._phase_epoch(tmp_path) is None
        assert log_event._elapsed_str(tmp_path) == ""


class TestMirrorLineHeadOnly:
    def test_head_only_no_clean_detail(self):
        # phase present but detail collapses to empty -> head-only branch (126).
        line = log_event._mirror_line("phase-start", "[Phase 3/11]", elapsed="1m00s")
        assert "Phase 3/11" in line
        assert "·" not in line  # no " · clean" suffix
        assert "(1m00s)" in line

    def test_clean_only_no_head(self):
        # no phase/step/elapsed -> glyph + clean only (line 127).
        line = log_event._mirror_line("info", "raw detail", elapsed="")
        assert line.strip().endswith("raw detail")


class TestProgressPayloadStatuses:
    def test_phase_end_status(self):
        p = log_event._progress_payload("phase-end", "PHASE_END", "[Phase 3/11] done", "a")
        assert p["status"] == "phase_completed"

    def test_step_end_status(self):
        p = log_event._progress_payload("step-end", "STEP_END", "[Phase 3] [4/7] done", "a")
        assert p["status"] == "step_completed"


class TestWriteErrorBranches:
    def test_append_log_oserror_swallowed(self, tmp_path: Path, monkeypatch):
        # open() raises OSError -> best-effort pass (lines 140-141).
        def boom(*a, **k):
            raise OSError("disk full")

        monkeypatch.setattr("builtins.open", boom)
        # Must not raise.
        log_event._append_log(tmp_path, "STEP_START", "x", "agent")

    def test_append_log_hook_mirror_oserror_swallowed(self, tmp_path: Path, monkeypatch):
        # First open (agent-run.log) succeeds, second (hook log) raises (150-151).
        real_open = open
        calls = {"n": 0}

        def flaky(path, *a, **k):
            calls["n"] += 1
            if str(path).endswith(".hook-events.log"):
                raise OSError("nope")
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", flaky)
        log_event._append_log(tmp_path, "PHASE_START", "[Phase 1/2] go", "agent")
        # agent-run.log still written.
        assert (tmp_path / ".agent-run.log").exists()

    def test_write_progress_oserror_swallowed(self, tmp_path: Path, monkeypatch):
        def boom(*a, **k):
            raise OSError("ro fs")

        monkeypatch.setattr(Path, "write_text", boom)
        log_event._write_progress(tmp_path, {"event": "X"})  # no raise


class TestMainArgErrors:
    def test_agent_flag_missing_value(self, capsys):
        rc = log_event.main(["log_event.py", "--agent"])
        assert rc == 2
        assert "--agent requires a value" in capsys.readouterr().err

    def test_too_few_args(self, capsys):
        rc = log_event.main(["log_event.py", "outdir", "phase-start"])
        assert rc == 2
        assert "usage:" in capsys.readouterr().err

    def test_info_requires_event_and_detail(self, capsys, tmp_path):
        rc = log_event.main(["log_event.py", str(tmp_path), "info", "ONLY_EVENT"])
        assert rc == 2
        assert "`info` requires" in capsys.readouterr().err

    def test_stderr_write_oserror_swallowed(self, tmp_path, monkeypatch):
        # main reaches stderr.write which raises OSError -> swallowed (239-240).
        def boom(*a, **k):
            raise OSError("broken pipe")

        monkeypatch.setattr(sys.stderr, "write", boom)
        rc = log_event.main(["log_event.py", str(tmp_path), "phase-start", "[Phase 1/2] go"])
        assert rc == 0
