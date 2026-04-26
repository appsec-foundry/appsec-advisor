"""Doc-drift + integration tests for the M2.13 auto-retry loop.

The retry loop itself runs inside the skill body (Bash + Agent calls),
which we cannot exercise from pure pytest. These tests instead verify:

  * SKILL-impl.md documents the contract (max retries, recovery sequence,
    exhausted-retries banner, exit codes)
  * The recovery-sequence scripts referenced exist and are runnable
  * runtime_cleanup.py knows about the new bookkeeping files
  * check_inline_shortcut.py --write-repair-plan keeps producing the
    schema the skill consumes

Behavioural execution is covered by the end-to-end run against juice-shop
(out of pytest scope).
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).parent.parent
SKILL_IMPL = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md"
SCRIPTS_DIR = PLUGIN_ROOT / "scripts"


@pytest.fixture(scope="module")
def skill_impl_text() -> str:
    return SKILL_IMPL.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# SKILL-impl.md — auto-retry contract
# ---------------------------------------------------------------------------

def test_skill_documents_max_inline_retries(skill_impl_text):
    assert "MAX_INLINE_RETRIES" in skill_impl_text
    # The default of 2 must be in the spec
    assert "MAX_INLINE_RETRIES=2" in skill_impl_text


def test_skill_documents_retry_counter_file(skill_impl_text):
    assert ".inline-shortcut-retry-count" in skill_impl_text


def test_skill_documents_repair_plan_consumption(skill_impl_text):
    # The skill instructs check_inline_shortcut.py --write-repair-plan
    assert "--write-repair-plan" in skill_impl_text
    # And the resulting plan path is the one the user should inspect
    assert ".inline-shortcut-repair-plan.json" in skill_impl_text


def test_skill_documents_recovery_sequence_scripts(skill_impl_text):
    """All three recovery scripts must be referenced and ordered correctly
    inside the auto-retry recovery sequence."""
    assert "merge_threats.py" in skill_impl_text
    assert "triage_validate_ratings.py" in skill_impl_text
    assert "pregenerate_fragments.py" in skill_impl_text
    # The recovery sequence is the bash block immediately following
    # "**Recovery sequence**" — anchored on that prose marker so the
    # ASCII pipeline diagram (which mentions all three scripts in a
    # different order for visual readability) does not get matched.
    block_start = skill_impl_text.find("**Recovery sequence**")
    assert block_start != -1, "Recovery sequence prose marker missing"
    # The recovery bash block is bounded by the next numbered list item
    # (`2. **Re-dispatch Stage 2**`) which marks the end of step 1.
    block_end = skill_impl_text.find("2. **Re-dispatch", block_start)
    assert block_end != -1, "Re-dispatch step 2 marker missing after recovery block"
    block = skill_impl_text[block_start:block_end]
    idx_merge   = block.find("merge_threats.py")
    idx_triage  = block.find("triage_validate_ratings.py")
    idx_pregen  = block.find("pregenerate_fragments.py")
    assert idx_merge != -1, "merge_threats.py missing from recovery block"
    assert idx_triage != -1, "triage_validate_ratings.py missing from recovery block"
    assert idx_pregen != -1, "pregenerate_fragments.py missing from recovery block"
    assert idx_merge < idx_triage < idx_pregen, (
        f"Recovery sequence order wrong: merge={idx_merge}, "
        f"triage={idx_triage}, pregen={idx_pregen}"
    )


def test_skill_documents_exhausted_retries_banner(skill_impl_text):
    assert "auto-retry exhausted" in skill_impl_text
    # Banner must instruct the user where to look
    assert "Inspect the final repair plan" in skill_impl_text
    assert "/appsec-advisor:create-threat-model --rebuild" in skill_impl_text


def test_skill_documents_exit_code_2_on_exhaustion(skill_impl_text):
    # The exit must be deterministic — exit 2 (same as gate trip)
    assert "exit 2" in skill_impl_text


def test_skill_documents_marker_cleanup_on_failure(skill_impl_text):
    """Even on auto-retry exhaustion, verbose/tracing markers must be cleaned."""
    # The exhausted-retries branch runs the same rm -f as other exit paths
    assert ".appsec-verbose-$(id -u)" in skill_impl_text
    assert ".appsec-tracing-$(id -u)" in skill_impl_text


def test_skill_documents_counter_cleanup_on_success(skill_impl_text):
    """Successful retry → counter file is unlinked."""
    # The cleanup line targets both the counter and the repair plan
    assert "rm -f \"$OUTPUT_DIR/.inline-shortcut-retry-count\"" in skill_impl_text


def test_skill_uses_idempotent_recovery(skill_impl_text):
    """Recovery sequence must be safe to re-run — explicitly documented."""
    # All three recovery scripts must be guarded so they never touch good state
    assert "idempotent" in skill_impl_text.lower()


# ---------------------------------------------------------------------------
# Recovery scripts — exist and are runnable
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("script_name", [
    "merge_threats.py",
    "triage_validate_ratings.py",
    "pregenerate_fragments.py",
    "check_inline_shortcut.py",
])
def test_recovery_script_exists(script_name):
    path = SCRIPTS_DIR / script_name
    assert path.is_file(), f"{script_name} not found in {SCRIPTS_DIR}"


@pytest.mark.parametrize("script_name", [
    "merge_threats.py",
    "triage_validate_ratings.py",
    "pregenerate_fragments.py",
    "check_inline_shortcut.py",
])
def test_recovery_script_runnable(script_name):
    """Each recovery script must respond to --help (or invocation) without
    raising an unhandled exception."""
    path = SCRIPTS_DIR / script_name
    result = subprocess.run(
        [sys.executable, str(path), "--help"],
        capture_output=True, text=True, timeout=15,
    )
    # Some scripts (merge_threats, qa_checks) don't accept --help at the
    # top level — they expect a subcommand. Either way, the process must
    # not crash with an unhandled traceback.
    assert "Traceback" not in result.stderr, (
        f"{script_name} crashed:\n{result.stderr[:500]}"
    )


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
        [sys.executable, str(SCRIPTS_DIR / "check_inline_shortcut.py"),
         str(out), "--write-repair-plan"],
        capture_output=True, text=True, timeout=30,
    )
    plan_path = out / ".inline-shortcut-repair-plan.json"
    assert plan_path.is_file()
    plan = json.loads(plan_path.read_text())  # raises on malformed JSON
    assert plan["status"] == "fail"
    assert plan["kind"] == "inline_shortcut"


def test_repair_plan_carries_indicators_and_missing_list(tmp_path):
    out = _make_failing_state(tmp_path)
    subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "check_inline_shortcut.py"),
         str(out), "--write-repair-plan"],
        capture_output=True, text=True, timeout=30,
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
    spec = importlib.util.spec_from_file_location(
        "runtime_cleanup", SCRIPTS_DIR / "runtime_cleanup.py"
    )
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
        [sys.executable, str(SCRIPTS_DIR / "runtime_cleanup.py"),
         str(out), "--stage", "post-qa"],
        capture_output=True, text=True, timeout=15,
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
        [sys.executable, str(SCRIPTS_DIR / "runtime_cleanup.py"),
         str(out), "--stage", "post-qa"],
        capture_output=True, text=True, timeout=15,
    )
    assert (out / ".inline-shortcut-retry-count").exists(), (
        "Retry counter should survive when QA failed — user needs to see it"
    )
    assert (out / ".inline-shortcut-repair-plan.json").exists()
