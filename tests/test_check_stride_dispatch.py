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
    (output_dir / f".stride-{cid}.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


def _write_progress(output_dir: Path, cid: str) -> None:
    pdir = output_dir / ".progress"
    pdir.mkdir(exist_ok=True)
    (pdir / f"{cid}.json").write_text(
        json.dumps({"component_id": cid, "step": 4}), encoding="utf-8"
    )


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


def test_dispatch_manifest_suppresses_false_positive(tmp_path):
    """Full-M1: real stride files, NO .progress, but a dispatch manifest exists
    → NOT inlined (the parallel fan-out is proven; agent_progress may no-op when
    OUTPUT_DIR is not env-exported in the analyzer)."""
    for cid in ("frontend-spa", "backend-api"):
        _write_stride(tmp_path, cid, _real_stride())
    (tmp_path / ".stride-dispatch-manifest.json").write_text(
        json.dumps({"schema_version": 1, "components": [{"component_id": "backend-api"}]}),
        encoding="utf-8",
    )
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
