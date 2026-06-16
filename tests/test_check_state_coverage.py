"""Supplemental coverage tests for scripts/check_state.py.

Targets the rendering branches (needs_stage2, crash vs residue, auto-clean
short-circuit), the phase-aware threshold sidecar, clean() OSError handling,
and the CLI surfaces not already exercised by test_check_state.py /
test_check_state_hung_aborted.py. Test-file-only; pins current behaviour.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
SCRIPT_PATH = SCRIPTS / "check_state.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_state", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_state"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


cs = _load()


def _dead_pid() -> int:
    return 99_999_999


# ---------------------------------------------------------------------------
# _read_checkpoint
# ---------------------------------------------------------------------------


def test_read_checkpoint_absent(tmp_path: Path):
    assert cs._read_checkpoint(tmp_path) is None


def test_read_checkpoint_parses_tokens(tmp_path: Path):
    (tmp_path / ".appsec-checkpoint").write_text("phase=9 status=started junk timestamp=x\n")
    cp = cs._read_checkpoint(tmp_path)
    assert cp["phase"] == "9"
    assert cp["status"] == "started"
    assert "junk" not in cp  # token without '=' ignored
    assert cp["timestamp"] == "x"


def test_read_checkpoint_unreadable_returns_path_only(tmp_path: Path, monkeypatch):
    ckpt = tmp_path / ".appsec-checkpoint"
    ckpt.write_text("phase=1 status=started\n")

    orig_read = Path.read_text

    def boom(self, *a, **k):
        if self.name == ".appsec-checkpoint":
            raise OSError("nope")
        return orig_read(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", boom)
    cp = cs._read_checkpoint(tmp_path)
    assert cp == {"path": str(ckpt)}


# ---------------------------------------------------------------------------
# _read_lock OSError on stat (age None)
# ---------------------------------------------------------------------------


def test_read_lock_stat_oserror(tmp_path: Path, monkeypatch):
    (tmp_path / ".appsec-lock").write_text(f"{os.getpid()}\n")
    orig_stat = Path.stat
    state = {"n": 0}

    def boom(self, *a, **k):
        # First stat (from .exists()) succeeds; the mtime stat fails so age=None.
        if self.name == ".appsec-lock":
            state["n"] += 1
            if state["n"] >= 2:
                raise OSError("stat fail")
        return orig_stat(self, *a, **k)

    monkeypatch.setattr(Path, "stat", boom)
    info = cs._read_lock(tmp_path)
    assert info["age"] is None


def test_read_lock_malformed_heartbeat_line(tmp_path: Path):
    # Second line present but not an int -> heartbeat parsed as None.
    (tmp_path / ".appsec-lock").write_text(f"{os.getpid()}\nnot-a-ts\n")
    info = cs._read_lock(tmp_path)
    assert info["pid"] == os.getpid()
    assert info["heartbeat"] is None


def test_file_mtime_age_present_and_absent(tmp_path: Path):
    f = tmp_path / ".phase-epoch"
    f.write_text("1\n")
    age = cs._file_mtime_age(tmp_path, ".phase-epoch")
    assert age is not None and age >= 0
    assert cs._file_mtime_age(tmp_path, ".missing") is None


def test_classify_dead_pid_stale_heartbeat_lists_dead_and_hung(tmp_path: Path):
    # Dead PID + stale heartbeat -> is_hung True and alive False -> hits the
    # "not running and heartbeat is Ns old" reason.
    (tmp_path / ".appsec-lock").write_text(f"{_dead_pid()}\n{int(time.time()) - 5000}\n")
    rep = cs.classify(tmp_path)
    assert rep["state"] == "stale"
    joined = " ".join(rep["reasons"])
    assert "not running and heartbeat is" in joined


def test_read_lock_read_oserror(tmp_path: Path, monkeypatch):
    (tmp_path / ".appsec-lock").write_text(f"{os.getpid()}\n")
    orig_read = Path.read_text

    def boom(self, *a, **k):
        if self.name == ".appsec-lock":
            raise OSError("read fail")
        return orig_read(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", boom)
    info = cs._read_lock(tmp_path)
    assert info["pid"] is None


# ---------------------------------------------------------------------------
# _pid_alive OSError branch
# ---------------------------------------------------------------------------


def test_pid_alive_generic_oserror(monkeypatch):
    def boom(pid, sig):
        raise OSError("weird")

    monkeypatch.setattr(cs.os, "kill", boom)
    assert cs._pid_alive(1234) is False


def test_pid_alive_permission_error_means_alive(monkeypatch):
    def boom(pid, sig):
        raise PermissionError

    monkeypatch.setattr(cs.os, "kill", boom)
    assert cs._pid_alive(1234) is True


# ---------------------------------------------------------------------------
# _resolve_threshold — phase + skill-config sidecar
# ---------------------------------------------------------------------------


def test_resolve_threshold_default_no_sidecar(tmp_path: Path):
    t = cs._resolve_threshold(tmp_path, None)
    assert isinstance(t, int) and t > 0


def test_resolve_threshold_reads_skill_config(tmp_path: Path):
    (tmp_path / ".skill-config.json").write_text(json.dumps({"assessment_depth": "quick"}))
    t = cs._resolve_threshold(tmp_path, {"phase": "3"})
    assert isinstance(t, int) and t > 0


def test_resolve_threshold_bad_skill_config(tmp_path: Path):
    (tmp_path / ".skill-config.json").write_text("{broken")
    t = cs._resolve_threshold(tmp_path, {"phase": "10b"})
    assert isinstance(t, int) and t > 0


def test_resolve_threshold_skill_config_non_string_depth(tmp_path: Path):
    (tmp_path / ".skill-config.json").write_text(json.dumps({"assessment_depth": 5}))
    t = cs._resolve_threshold(tmp_path, {"phase": "3"})
    assert isinstance(t, int) and t > 0


# ---------------------------------------------------------------------------
# classify — needs_stage2
# ---------------------------------------------------------------------------


def test_classify_needs_stage2(tmp_path: Path):
    (tmp_path / ".appsec-checkpoint").write_text(
        "phase=10b status=completed need_render=true\n"
    )
    rep = cs.classify(tmp_path)
    assert rep["needs_stage2"] is True
    # completed checkpoint without lock and no started/aborted -> residue orphaned
    assert rep["state"] == "orphaned"


def test_classify_needs_stage2_false_when_md_present(tmp_path: Path):
    (tmp_path / ".appsec-checkpoint").write_text(
        "phase=10b status=completed need_render=true\n"
    )
    (tmp_path / "threat-model.md").write_text("# done\n")
    rep = cs.classify(tmp_path)
    assert rep["needs_stage2"] is False


# ---------------------------------------------------------------------------
# _render_text branches
# ---------------------------------------------------------------------------


def test_render_text_residue_auto_cleaned(tmp_path: Path):
    report = {
        "state": "orphaned",
        "reasons": ["leftover transient files"],
        "checkpoint": None,
        "files": [".phase-epoch"],
        "needs_stage2": False,
    }
    clean_result = {"skipped": False, "removed": [".phase-epoch"], "reason": None}
    out = cs._render_text(report, clean_result)
    assert "Cleaned up 1 leftover file" in out


def test_render_text_crash_recovery_header(tmp_path: Path):
    report = {
        "state": "orphaned",
        "reasons": ["crash"],
        "checkpoint": {"status": "started", "phase": "5"},
        "files": [],
        "needs_stage2": False,
    }
    out = cs._render_text(report, None)
    assert "crash recovery" in out


def test_render_text_residue_header_no_autoclean(tmp_path: Path):
    report = {
        "state": "orphaned",
        "reasons": ["residue"],
        "checkpoint": {"status": "completed"},
        "files": [".phase-epoch"],
        "needs_stage2": False,
    }
    out = cs._render_text(report, None)
    assert "leftover from prior run" in out


def test_render_text_needs_stage2_banner(tmp_path: Path):
    report = {
        "state": "stale",
        "reasons": ["dead pid"],
        "checkpoint": {"phase": "10b", "status": "completed"},
        "files": [],
        "needs_stage2": True,
    }
    out = cs._render_text(report, None)
    assert "Stage 1 is complete" in out
    assert "--resume" in out


def test_render_text_clean_skipped(tmp_path: Path):
    report = {"state": "active", "reasons": ["live"], "checkpoint": None, "files": [], "needs_stage2": False}
    clean_result = {"skipped": True, "removed": [], "reason": "active run holds lock"}
    out = cs._render_text(report, clean_result)
    assert "Cleanup skipped" in out


def test_render_text_clean_removed(tmp_path: Path):
    report = {"state": "stale", "reasons": ["dead"], "checkpoint": None, "files": [], "needs_stage2": False}
    clean_result = {"skipped": False, "removed": [".appsec-lock"], "reason": None}
    out = cs._render_text(report, clean_result)
    assert "Removed 1 stale file" in out


def test_render_text_nothing_to_clean(tmp_path: Path):
    report = {"state": "clean", "reasons": ["nothing"], "checkpoint": None, "files": [], "needs_stage2": False}
    clean_result = {"skipped": False, "removed": [], "reason": None}
    out = cs._render_text(report, clean_result)
    assert "Nothing to clean" in out


# ---------------------------------------------------------------------------
# clean() OSError tolerance
# ---------------------------------------------------------------------------


def test_clean_tolerates_unlink_oserror(tmp_path: Path, monkeypatch):
    (tmp_path / ".appsec-lock").write_text(f"{_dead_pid()}\n")
    (tmp_path / ".phase-epoch").write_text("1\n")

    orig_unlink = Path.unlink

    def flaky(self, *a, **k):
        if self.name == ".appsec-lock":
            raise OSError("busy")
        return orig_unlink(self, *a, **k)

    monkeypatch.setattr(Path, "unlink", flaky)
    result = cs.clean(tmp_path)
    assert result["skipped"] is False
    # lock failed to delete, but phase-epoch removed
    assert ".phase-epoch" in result["removed"]
    assert ".appsec-lock" not in result["removed"]


# ---------------------------------------------------------------------------
# CLI: missing dir, json needs_stage2, resume-guard missing dir
# ---------------------------------------------------------------------------


def test_main_missing_output_dir_is_clean(tmp_path: Path, capsys):
    code = cs.main([str(tmp_path / "nope")])
    assert code == 0
    assert "clean" in capsys.readouterr().out


def test_main_missing_output_dir_json(tmp_path: Path, capsys):
    code = cs.main([str(tmp_path / "nope"), "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["report"]["state"] == "clean"


def test_main_resume_guard_missing_dir_text(tmp_path: Path, capsys):
    code = cs.main([str(tmp_path / "nope"), "--resume-guard"])
    assert code == 0
    assert "allowed" in capsys.readouterr().out


def test_main_resume_guard_missing_dir_json(tmp_path: Path, capsys):
    code = cs.main([str(tmp_path / "nope"), "--resume-guard", "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["allow"] is True


def test_main_resume_guard_allowed_json(tmp_path: Path, capsys):
    (tmp_path / ".appsec-checkpoint").write_text("phase=11 status=completed\n")
    code = cs.main([str(tmp_path), "--resume-guard", "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["allow"] is True
    assert payload["exit_code"] == 0


def test_main_resume_guard_text_marker(tmp_path: Path, capsys):
    (tmp_path / ".appsec-checkpoint").write_text("phase=11 status=completed\n")
    code = cs.main([str(tmp_path), "--resume-guard"])
    assert code == 0
    assert "✓" in capsys.readouterr().out  # check mark


def test_main_clean_json_includes_needs_stage2(tmp_path: Path, capsys):
    (tmp_path / ".appsec-checkpoint").write_text(
        "phase=10b status=completed need_render=true\n"
    )
    code = cs.main([str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["report"]["needs_stage2"] is True


def test_main_orphaned_text_render(tmp_path: Path, capsys):
    (tmp_path / ".appsec-checkpoint").write_text("phase=5 status=started\n")
    code = cs.main([str(tmp_path)])
    assert code == 1
    out = capsys.readouterr().out
    assert "orphaned" in out


def test_main_auto_clean_returns_0_on_clean(tmp_path: Path, capsys):
    code = cs.main([str(tmp_path), "--auto-clean"])
    assert code == 0


# ---------------------------------------------------------------------------
# _resume_guard_result — checkpoint stat OSError
# ---------------------------------------------------------------------------


def test_resume_guard_checkpoint_stat_oserror(tmp_path: Path, monkeypatch):
    cp = tmp_path / ".appsec-checkpoint"
    cp.write_text("phase=5 status=started\n")
    orig_stat = Path.stat
    state = {"n": 0}

    def boom(self, *a, **k):
        # Let the existence/is_file probes (stat #1, #2) succeed; fail the
        # mtime stat (#3) so age becomes inf -> refuse.
        if self.name == ".appsec-checkpoint":
            state["n"] += 1
            if state["n"] >= 3:
                raise OSError("nope")
        return orig_stat(self, *a, **k)

    monkeypatch.setattr(Path, "stat", boom)
    # age becomes float('inf') (stat failed) -> the refuse branch formats
    # int(age), which currently raises OverflowError on infinity. Pin that
    # current behaviour (do NOT fix the producer here).
    with pytest.raises(OverflowError):
        cs._resume_guard_result(tmp_path, 900)


def test_resume_guard_legacy_live_pid_refuses(tmp_path: Path):
    # v1 lock (no heartbeat) with our own live PID -> active -> refuse
    (tmp_path / ".appsec-lock").write_text(f"{os.getpid()}\n")
    code, msg = cs._resume_guard_result(tmp_path, 900)
    assert code == 3
    assert "live PID" in msg
