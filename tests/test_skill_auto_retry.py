"""Integration tests for bounded Stage-2 retry artifacts and cleanup."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = PLUGIN_ROOT / "scripts"


# ---------------------------------------------------------------------------
# Recovery scripts — exist and are runnable
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "script_name",
    [
        "merge_threats.py",
        "triage_validate_ratings.py",
        "pregenerate_fragments.py",
        "check_inline_shortcut.py",
    ],
)
def test_recovery_script_exists(script_name):
    path = SCRIPTS_DIR / script_name
    assert path.is_file(), f"{script_name} not found in {SCRIPTS_DIR}"


@pytest.mark.parametrize(
    "script_name",
    [
        "merge_threats.py",
        "triage_validate_ratings.py",
        "pregenerate_fragments.py",
        "check_inline_shortcut.py",
    ],
)
def test_recovery_script_runnable(script_name):
    """Each recovery script must respond to --help (or invocation) without
    raising an unhandled exception."""
    path = SCRIPTS_DIR / script_name
    result = subprocess.run(
        [sys.executable, str(path), "--help"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    # Some scripts (merge_threats, qa_checks) don't accept --help at the
    # top level — they expect a subcommand. Either way, the process must
    # not crash with an unhandled traceback.
    assert "Traceback" not in result.stderr, f"{script_name} crashed:\n{result.stderr[:500]}"


# ---------------------------------------------------------------------------
# check_inline_shortcut.py --write-repair-plan — schema for retry consumer
# ---------------------------------------------------------------------------


def _make_failing_state(tmp_path: Path) -> Path:
    """Output dir with threat-model.md but no fragments, no merge, no triage."""
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True)
    (out / "threat-model.md").write_text("# inline\n")
    return out


def test_repair_plan_is_valid_json(tmp_path):
    out = _make_failing_state(tmp_path)
    subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "check_inline_shortcut.py"), str(out), "--write-repair-plan"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    plan_path = out / ".inline-shortcut-repair-plan.json"
    assert plan_path.is_file()
    plan = json.loads(plan_path.read_text())  # raises on malformed JSON
    assert plan["status"] == "fail"
    assert plan["kind"] == "inline_shortcut"


def test_repair_plan_carries_indicators_and_missing_list(tmp_path):
    out = _make_failing_state(tmp_path)
    subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "check_inline_shortcut.py"), str(out), "--write-repair-plan"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    plan = json.loads((out / ".inline-shortcut-repair-plan.json").read_text())
    assert isinstance(plan.get("indicators"), list) and len(plan["indicators"]) >= 1
    assert isinstance(plan.get("missing_fragments"), list)
    # Schema version stable for the retry consumer
    assert plan["schema_version"] == 1


# ---------------------------------------------------------------------------
# runtime_cleanup.py — knows about the new bookkeeping files
# ---------------------------------------------------------------------------


def _load_runtime_cleanup():
    if "runtime_cleanup" in sys.modules:
        return sys.modules["runtime_cleanup"]
    spec = importlib.util.spec_from_file_location("runtime_cleanup", SCRIPTS_DIR / "runtime_cleanup.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["runtime_cleanup"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_runtime_cleanup_reaps_retry_counter():
    rc = _load_runtime_cleanup()
    # Per M2.13: bookkeeping lives in POST_QA_FILES_IF_PASS so it is only
    # reaped when QA passed cleanly (the same condition under which the
    # auto-retry loop has succeeded).
    assert ".inline-shortcut-retry-count" in rc.POST_QA_FILES_IF_PASS, (
        "Retry counter must be reaped on successful QA completion"
    )


def test_runtime_cleanup_reaps_repair_plan():
    rc = _load_runtime_cleanup()
    assert ".inline-shortcut-repair-plan.json" in rc.POST_QA_FILES_IF_PASS, (
        "Inline-shortcut repair plan must be reaped on successful QA completion"
    )


def test_runtime_cleanup_actually_removes_them(tmp_path):
    rc = _load_runtime_cleanup()
    out = tmp_path
    # runtime_cleanup has a safety gate: it refuses to clean when
    # threat-model.md is missing AND it only reaps post-qa files if
    # qa-status.json shows a pass.
    (out / "threat-model.md").write_text("# stub\n")
    (out / ".qa-status.json").write_text(json.dumps({"status": "pass"}))
    (out / ".qa-repair-plan.json").write_text(json.dumps({"issue_count": 0}))
    (out / ".inline-shortcut-retry-count").write_text("2\n")
    (out / ".inline-shortcut-repair-plan.json").write_text("{}\n")
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "runtime_cleanup.py"), str(out), "--stage", "post-qa"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert "skipped" not in result.stdout, f"cleanup was skipped: {result.stdout}"
    assert not (out / ".inline-shortcut-retry-count").exists()
    assert not (out / ".inline-shortcut-repair-plan.json").exists()


def test_runtime_cleanup_preserves_them_on_qa_failure(tmp_path):
    """When QA did not pass, the bookkeeping files must NOT be deleted —
    the skill exit-2 path relies on them surviving for user inspection."""
    out = tmp_path
    (out / "threat-model.md").write_text("# stub\n")
    (out / ".qa-status.json").write_text(json.dumps({"status": "repair_required"}))
    (out / ".inline-shortcut-retry-count").write_text("2\n")
    (out / ".inline-shortcut-repair-plan.json").write_text("{}\n")
    subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "runtime_cleanup.py"), str(out), "--stage", "post-qa"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert (out / ".inline-shortcut-retry-count").exists(), (
        "Retry counter should survive when QA failed — user needs to see it"
    )
    assert (out / ".inline-shortcut-repair-plan.json").exists()
