"""Unit tests for scripts/check_stride_dispatch.py.

The hard gate is invoked as a subprocess from skills/create-threat-model/
SKILL-impl.md (Phase-10b precondition gate) and is expected to:

  * exit 0 when STRIDE was dispatched (every real .stride-<id>.json has a
    matching .progress/<id>.json)
  * exit 0 when every .stride-<id>.json is a trivial-skip stub or empty
  * exit 0 when --incremental is passed (carry-forward — gate N/A)
  * exit 2 when a real .stride-<id>.json has no .progress/<id>.json
    (orchestrator inlined the analysis instead of dispatching)
  * exit 3 on tool error (bad path)
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_stride_dispatch.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _real_stride(threat_count: int = 3) -> dict:
    return {
        "threats": [
            {
                "title": f"SQL injection in route {i}",
                "description": "Untrusted input reaches a raw query.",
                "cwe": "CWE-89",
            }
            for i in range(threat_count)
        ]
    }


def _stub_stride() -> dict:
    return {
        "threats": [
            {
                "title": "Trivial-component — no detailed STRIDE performed",
                "description": "trivial-component, no detailed STRIDE performed",
                "severity": "low",
            }
        ]
    }


def _write_stride(output_dir: Path, cid: str, payload: dict) -> None:
    (output_dir / f".stride-{cid}.json").write_text(json.dumps(payload), encoding="utf-8")


def _write_progress(output_dir: Path, cid: str) -> None:
    pdir = output_dir / ".progress"
    pdir.mkdir(exist_ok=True)
    (pdir / f"{cid}.json").write_text(json.dumps({"component_id": cid, "step": 4}), encoding="utf-8")


def _write_manifest(output_dir: Path, *cids: str, generated_at: str | None = None) -> None:
    manifest = {
        "schema_version": 1,
        "components": [{"component_id": c} for c in cids],
    }
    if generated_at is not None:
        manifest["generated_at"] = generated_at
    (output_dir / ".stride-dispatch-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def _write_spawns(output_dir: Path, count: int, *, day: str = "2026-06-05") -> None:
    """Append `count` dispatched-analyzer AGENT_SPAWN lines to the hook log.

    `day` controls the leading ISO date so tests can place spawns before/after
    a manifest's `generated_at` (the current-run time bound).
    """
    lines = "".join(
        f"{day}T10:00:0{i}Z  [sess]  INFO  AGENT_SPAWN  "
        f"appsec-advisor:appsec-stride-analyzer  model=sonnet  STRIDE: c{i}\n"
        for i in range(count)
    )
    with (output_dir / ".hook-events.log").open("a", encoding="utf-8") as fh:
        fh.write(lines)


def _run(output_dir: Path, *extra: str) -> int:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(output_dir), *extra],
        capture_output=True,
        text=True,
    ).returncode


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_dispatched_run_passes(tmp_path):
    """Real stride files each with a matching progress file → clean."""
    for cid in ("frontend-spa", "backend-api", "data-persistence"):
        _write_stride(tmp_path, cid, _real_stride())
        _write_progress(tmp_path, cid)
    assert _run(tmp_path) == 0


def test_inlined_run_trips(tmp_path):
    """Real stride files, empty .progress/ → inline detected (exit 2)."""
    (tmp_path / ".progress").mkdir()
    for cid in ("frontend-spa", "backend-api", "b2b-api"):
        _write_stride(tmp_path, cid, _real_stride())
    assert _run(tmp_path) == 2


def test_inlined_run_trips_without_progress_dir(tmp_path):
    """Real stride files, no .progress/ dir at all → inline detected."""
    _write_stride(tmp_path, "backend-api", _real_stride())
    assert _run(tmp_path) == 2


def test_manifest_with_full_spawn_evidence_passes(tmp_path):
    """Full-M1 clean run: real stride files, NO .progress, but the hook log
    shows >= one dispatched analyzer per manifest component → fan-out proven,
    not inlined (agent_progress may no-op when OUTPUT_DIR is not env-exported)."""
    for cid in ("frontend-spa", "backend-api"):
        _write_stride(tmp_path, cid, _real_stride())
    _write_manifest(tmp_path, "frontend-spa", "backend-api")
    _write_spawns(tmp_path, 2)  # one spawn per planned component
    assert _run(tmp_path) == 0


def test_manifest_built_but_stride_inlined_trips(tmp_path):
    """THE inline-collapse: step 3b built the manifest, but the orchestrator
    inlined STRIDE instead of fanning out (0 analyzer spawns, no .progress).
    The manifest must NOT suppress — this is the 23-min-freeze failure mode
    the gate exists to catch, and pre-2026-06-05 it slipped through."""
    for cid in ("frontend-spa", "backend-api"):
        _write_stride(tmp_path, cid, _real_stride())
    _write_manifest(tmp_path, "frontend-spa", "backend-api")
    # no AGENT_SPAWN lines, no .progress/ → collapse
    assert _run(tmp_path) == 2


def test_manifest_partial_spawns_falls_through_to_progress(tmp_path):
    """Manifest with fewer spawns than planned does NOT globally suppress, but a
    genuinely-dispatched run is still saved by its per-component .progress files
    (no false-positive when hooks under-log but analyzers wrote progress)."""
    for cid in ("frontend-spa", "backend-api"):
        _write_stride(tmp_path, cid, _real_stride())
        _write_progress(tmp_path, cid)
    _write_manifest(tmp_path, "frontend-spa", "backend-api")
    _write_spawns(tmp_path, 1)  # under-count, but .progress covers both
    assert _run(tmp_path) == 0


def test_manifest_partial_spawns_and_missing_progress_trips(tmp_path):
    """Under-count spawns AND a real stride file with no .progress → the
    uncovered component is flagged (partial fan-out / partial inline)."""
    _write_stride(tmp_path, "frontend-spa", _real_stride())
    _write_progress(tmp_path, "frontend-spa")
    _write_stride(tmp_path, "backend-api", _real_stride())  # inlined, no progress
    _write_manifest(tmp_path, "frontend-spa", "backend-api")
    _write_spawns(tmp_path, 1)
    assert _run(tmp_path) == 2


def test_stale_spawns_before_manifest_do_not_suppress(tmp_path):
    """Append-only hook log: a PRIOR clean run's stride spawns linger. A current
    --rebuild that inlines (no fresh spawns, no .progress) must still trip — the
    stale spawns predate the manifest's generated_at and are excluded."""
    for cid in ("frontend-spa", "backend-api"):
        _write_stride(tmp_path, cid, _real_stride())
    _write_spawns(tmp_path, 2, day="2026-06-01")  # last run's spawns, still in log
    _write_manifest(tmp_path, "frontend-spa", "backend-api", generated_at="2026-06-05T10:00:00Z")
    # no fresh (>= generated_at) spawns, no .progress → collapse, must trip
    assert _run(tmp_path) == 2


def test_fresh_spawns_after_manifest_pass_with_time_bound(tmp_path):
    """Same setup but the spawns are from the current run (after generated_at)
    → counted, fan-out proven, exit 0."""
    for cid in ("frontend-spa", "backend-api"):
        _write_stride(tmp_path, cid, _real_stride())
    _write_spawns(tmp_path, 2, day="2026-06-01")  # stale, excluded
    _write_manifest(tmp_path, "frontend-spa", "backend-api", generated_at="2026-06-05T10:00:00Z")
    _write_spawns(tmp_path, 2, day="2026-06-05")  # this run's spawns, counted
    assert _run(tmp_path) == 0


def test_agent_spawn_hook_evidence_suppresses_false_positive(tmp_path):
    """Real stride files, no .progress, but the hook log shows a dispatched
    appsec-stride-analyzer → NOT inlined."""
    _write_stride(tmp_path, "backend-api", _real_stride())
    (tmp_path / ".hook-events.log").write_text(
        "2026-06-04T10:00:00Z  [sess]  INFO  AGENT_SPAWN  appsec-advisor:appsec-stride-analyzer  model=sonnet\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == 0


def test_agent_invoke_evidence_suppresses_false_positive(tmp_path):
    """The 2026-06-12 juice-shop false positive: a genuinely-parallel 4-way
    fan-out where the harness logged only 1 AGENT_SPAWN but 4 AGENT_INVOKE
    (one per dispatched analyzer, each carrying COMPONENT_ID), and 2 analyzers
    did not write a .progress file. Counting both event types deduped by
    COMPONENT_ID proves all 4 were dispatched → NOT inlined."""
    cids = ("backend-api", "frontend-spa", "file-upload-service", "b2b-api")
    for cid in cids:
        _write_stride(tmp_path, cid, _real_stride())
    # progress for only 2 of 4 (the original FP condition)
    _write_progress(tmp_path, "b2b-api")
    _write_progress(tmp_path, "file-upload-service")
    _write_manifest(tmp_path, *cids, generated_at="2026-06-12T14:43:00Z")
    log = (
        "2026-06-12T14:46:41Z  [sess]  INFO  AGENT_SPAWN   "
        "appsec-advisor:appsec-stride-analyzer  model=sonnet  STRIDE: backend-api  "
        "[REPO_ROOT=/r  COMPONENT_ID=backend-api]\n"
    )
    for ts, cid in (
        ("14:50:15", "backend-api"),
        ("14:54:10", "b2b-api"),
        ("14:54:16", "frontend-spa"),
        ("14:54:42", "file-upload-service"),
    ):
        log += (
            f"2026-06-12T{ts}Z  [sess]  INFO  AGENT_INVOKE  "
            f"appsec-advisor:appsec-stride-analyzer  model=sonnet  STRIDE: {cid}  "
            f"[REPO_ROOT=/r  COMPONENT_ID={cid}]\n"
        )
    (tmp_path / ".hook-events.log").write_text(log, encoding="utf-8")
    assert _run(tmp_path) == 0


def test_invoke_only_evidence_without_component_id_uses_max(tmp_path):
    """No manifest, real stride file, no .progress, but an AGENT_INVOKE line
    (no COMPONENT_ID) → max(spawn,invoke) fallback still proves a dispatch."""
    _write_stride(tmp_path, "backend-api", _real_stride())
    (tmp_path / ".hook-events.log").write_text(
        "2026-06-04T10:00:00Z  [sess]  INFO  AGENT_INVOKE  appsec-advisor:appsec-stride-analyzer  model=sonnet\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == 0


def test_partial_inline_trips(tmp_path):
    """One dispatched component, one inlined → trips on the inlined one."""
    _write_stride(tmp_path, "frontend-spa", _real_stride())
    _write_progress(tmp_path, "frontend-spa")
    _write_stride(tmp_path, "backend-api", _real_stride())  # no progress
    assert _run(tmp_path) == 2


def test_all_trivial_stubs_pass(tmp_path):
    """Trivial-skip stubs are written inline by design → no trip."""
    for cid in ("static-assets", "docs-site"):
        _write_stride(tmp_path, cid, _stub_stride())
    assert _run(tmp_path) == 0


def test_empty_threats_pass(tmp_path):
    """An empty/partial wrap-up has no real work to attribute → no trip."""
    _write_stride(tmp_path, "queue-consumer", {"threats": [], "partial": True})
    assert _run(tmp_path) == 0


def test_no_stride_files_pass(tmp_path):
    """Phase 9 not reached / nothing to check → clean."""
    assert _run(tmp_path) == 0


def test_incremental_skips_gate(tmp_path):
    """Carry-forward makes progress-file absence ambiguous → gate N/A."""
    _write_stride(tmp_path, "backend-api", _real_stride())  # no progress
    assert _run(tmp_path, "--incremental") == 0


def test_bad_path_errors(tmp_path):
    assert _run(tmp_path / "does-not-exist") == 3
