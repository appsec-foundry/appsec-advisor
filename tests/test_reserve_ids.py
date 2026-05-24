"""Unit tests for scripts/reserve_ids.py — atomic ID counter assignment."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "reserve_ids.py"


def _load():
    spec = importlib.util.spec_from_file_location("reserve_ids", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["reserve_ids"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


reserve_ids = _load()


def test_first_reservation_creates_baseline(tmp_path: Path):
    """First call with no baseline.json yet should create it with the counter set."""
    ids = reserve_ids.reserve(tmp_path, "mitigation", 1)
    assert ids == ["M-001"]
    state = json.loads((tmp_path / ".appsec-cache" / "baseline.json").read_text())
    assert state["id_counters"]["next_mitigation_id"] == 2


def test_sequential_reservations_increment(tmp_path: Path):
    assert reserve_ids.reserve(tmp_path, "mitigation", 3) == ["M-001", "M-002", "M-003"]
    assert reserve_ids.reserve(tmp_path, "mitigation", 2) == ["M-004", "M-005"]


def test_independent_counters_per_type(tmp_path: Path):
    assert reserve_ids.reserve(tmp_path, "mitigation", 1) == ["M-001"]
    assert reserve_ids.reserve(tmp_path, "asset", 1) == ["A-001"]
    assert reserve_ids.reserve(tmp_path, "meta_finding", 1) == ["MF-001"]
    assert reserve_ids.reserve(tmp_path, "hyp", 1) == ["HYP-001"]
    state = json.loads((tmp_path / ".appsec-cache" / "baseline.json").read_text())
    assert state["id_counters"]["next_mitigation_id"] == 2
    assert state["id_counters"]["next_asset_id"] == 2
    assert state["id_counters"]["next_meta_finding_id"] == 2
    assert state["id_counters"]["next_hyp_id"] == 2


def test_prefixed_string_counter_carry_over(tmp_path: Path):
    """Legacy baselines stored counter as 'M-008' string — must still work."""
    (tmp_path / ".appsec-cache").mkdir()
    (tmp_path / ".appsec-cache" / "baseline.json").write_text(
        json.dumps({"id_counters": {"next_mitigation_id": "M-008"}})
    )
    assert reserve_ids.reserve(tmp_path, "mitigation", 2) == ["M-008", "M-009"]


def test_integer_counter_continues(tmp_path: Path):
    (tmp_path / ".appsec-cache").mkdir()
    (tmp_path / ".appsec-cache" / "baseline.json").write_text(
        json.dumps({"id_counters": {"next_threat_id": 35}})
    )
    assert reserve_ids.reserve(tmp_path, "threat", 2) == ["T-035", "T-036"]


def test_preserves_other_baseline_fields(tmp_path: Path):
    """A reservation must not clobber recon_fingerprint, stride_files, etc."""
    (tmp_path / ".appsec-cache").mkdir()
    (tmp_path / ".appsec-cache" / "baseline.json").write_text(json.dumps({
        "schema_version": 1,
        "mode": "full",
        "recon_fingerprint": {"a.json": "deadbeef"},
        "stride_files": [{"path": "x.json", "sha256": "abc"}],
        "id_counters": {"next_threat_id": 5},
    }))
    reserve_ids.reserve(tmp_path, "mitigation", 1)
    state = json.loads((tmp_path / ".appsec-cache" / "baseline.json").read_text())
    assert state["schema_version"] == 1
    assert state["mode"] == "full"
    assert state["recon_fingerprint"] == {"a.json": "deadbeef"}
    assert state["stride_files"] == [{"path": "x.json", "sha256": "abc"}]
    assert state["id_counters"]["next_threat_id"] == 5
    assert state["id_counters"]["next_mitigation_id"] == 2


def test_corrupted_baseline_refuses(tmp_path: Path):
    """Malformed JSON in baseline must NOT be silently wiped."""
    (tmp_path / ".appsec-cache").mkdir()
    (tmp_path / ".appsec-cache" / "baseline.json").write_text("{ this is not JSON")
    try:
        reserve_ids.reserve(tmp_path, "mitigation", 1)
    except RuntimeError as exc:
        assert "malformed JSON" in str(exc)
        return
    raise AssertionError("expected RuntimeError, got nothing")


def test_invalid_count(tmp_path: Path):
    for bad in (0, -1, -100):
        try:
            reserve_ids.reserve(tmp_path, "mitigation", bad)
        except ValueError as exc:
            assert "count" in str(exc)
            continue
        raise AssertionError(f"expected ValueError for count={bad}")


def test_invalid_type(tmp_path: Path):
    try:
        reserve_ids.reserve(tmp_path, "bogus_type", 1)
    except ValueError as exc:
        assert "unknown id_type" in str(exc)
        return
    raise AssertionError("expected ValueError for unknown type")


def test_parallel_subprocess_atomicity(tmp_path: Path):
    """20 parallel subprocesses × 5 IDs each = 100 unique IDs.

    Uses real subprocesses (not threads) so the fcntl lock is exercised
    cross-process — same scenario as parallel phase dispatch.
    """
    n_procs = 20
    per_proc = 5

    def call_once(_i: int) -> list[str]:
        out = subprocess.run(
            [sys.executable, str(SCRIPT_PATH),
             "mitigation", "--count", str(per_proc),
             "--output-dir", str(tmp_path)],
            capture_output=True, text=True, check=True,
        )
        return json.loads(out.stdout.strip())

    # Threads spawn subprocesses concurrently; subprocesses contend on flock.
    with ThreadPoolExecutor(max_workers=n_procs) as pool:
        results = list(pool.map(call_once, range(n_procs)))

    all_ids = [mid for batch in results for mid in batch]
    assert len(all_ids) == n_procs * per_proc
    assert len(set(all_ids)) == len(all_ids), "duplicate IDs reserved across processes"
    final = json.loads((tmp_path / ".appsec-cache" / "baseline.json").read_text())
    assert final["id_counters"]["next_mitigation_id"] == n_procs * per_proc + 1


def test_cli_stdout_format(tmp_path: Path):
    """Stdout must be JSON list, parseable by shell consumers."""
    out = subprocess.run(
        [sys.executable, str(SCRIPT_PATH),
         "asset", "--count", "3", "--output-dir", str(tmp_path)],
        capture_output=True, text=True, check=True,
    )
    parsed = json.loads(out.stdout.strip())
    assert parsed == ["A-001", "A-002", "A-003"]
