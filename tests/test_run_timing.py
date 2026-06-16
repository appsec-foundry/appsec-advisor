"""Tests for scripts/run_timing.py — net-vs-wall with standby isolation."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "run_timing.py"


def _load():
    spec = importlib.util.spec_from_file_location("run_timing", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["run_timing"] = mod
    spec.loader.exec_module(mod)
    return mod


rt = _load()


def _write(out: Path, records: list[dict], wall: int | None = None) -> None:
    (out / ".stage-stats.jsonl").write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    if wall is not None:
        (out / ".scan-wall-seconds").write_text(str(wall), encoding="utf-8")


class TestStandbyIsolation:
    def test_large_stage_gap_classed_as_standby(self, tmp_path: Path):
        # Stage 2 sat 148 min in standby (wall 9017s, compute 130s).
        _write(
            tmp_path,
            [
                {"stage": 1, "duration_ms": 3_403_000, "wall_secs_observed": 3853},
                {"stage": 2, "duration_ms": 130_000, "wall_secs_observed": 9017},
            ],
            wall=14567,
        )
        t = rt.compute_timing(tmp_path)
        assert t["net_compute_secs"] == 3533  # 3403 + 130
        assert t["standby_secs"] == 9017 - 130  # the Stage-2 gap
        assert t["has_standby"] is True
        # net_wall strips standby: 14567 - 8887 = 5680
        assert t["net_wall_secs"] == 5680
        s2 = next(s for s in t["stages"] if s["stage"] == 2)
        assert s2["is_standby"] is True

    def test_normal_run_has_no_standby(self, tmp_path: Path):
        # Small per-stage gaps (API latency) stay below the 600s threshold.
        _write(
            tmp_path,
            [
                {"stage": 1, "duration_ms": 1_500_000, "wall_secs_observed": 1560},
                {"stage": 2, "duration_ms": 180_000, "wall_secs_observed": 200},
            ],
            wall=2000,
        )
        t = rt.compute_timing(tmp_path)
        assert t["standby_secs"] == 0
        assert t["has_standby"] is False
        # No standby → net_wall equals the full wall.
        assert t["net_wall_secs"] == 2000

    def test_threshold_boundary(self, tmp_path: Path):
        # Exactly 600s gap is NOT standby (strictly greater than).
        _write(
            tmp_path,
            [{"stage": 1, "duration_ms": 60_000, "wall_secs_observed": 660}],  # 600s gap
            wall=700,
        )
        t = rt.compute_timing(tmp_path)
        assert t["standby_secs"] == 0


class TestWallFallback:
    def test_missing_wall_marker_uses_stage_walls(self, tmp_path: Path):
        _write(
            tmp_path,
            [
                {"stage": 1, "duration_ms": 600_000, "wall_secs_observed": 650},
                {"stage": 2, "duration_ms": 120_000, "wall_secs_observed": 130},
            ],
        )  # no .scan-wall-seconds
        t = rt.compute_timing(tmp_path)
        assert t["wall_secs"] is None
        # net_wall = net_compute + non-standby idle = 720 + (50 + 10) = 780
        assert t["net_wall_secs"] == 780

    def test_empty_dir_is_zeroed(self, tmp_path: Path):
        t = rt.compute_timing(tmp_path)
        assert t["net_compute_secs"] == 0
        assert t["net_wall_secs"] == 0
        assert t["stages"] == []


class TestCLI:
    def test_net_wall_seconds_flag(self, tmp_path: Path):
        _write(
            tmp_path,
            [
                {"stage": 1, "duration_ms": 3_403_000, "wall_secs_observed": 3853},
                {"stage": 2, "duration_ms": 130_000, "wall_secs_observed": 9017},
            ],
            wall=14567,
        )
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "--output-dir", str(tmp_path), "--net-wall-seconds"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert r.returncode == 0
        assert r.stdout.strip() == "5680"

    def test_net_wall_seconds_empty_when_no_data(self, tmp_path: Path):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "--output-dir", str(tmp_path), "--net-wall-seconds"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_json_output(self, tmp_path: Path):
        _write(tmp_path, [{"stage": 1, "duration_ms": 600_000, "wall_secs_observed": 650}], wall=700)
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "--output-dir", str(tmp_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert data["net_compute_secs"] == 600
        assert "stages" in data


def _write_hook_log(out: Path, epoch_offsets: list[int], base_iso: str = "2026-06-16T05:00:00Z") -> None:
    """Write a .hook-events.log with one event per offset (seconds from base)."""
    from datetime import datetime, timedelta, timezone

    base = datetime.strptime(base_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    lines = []
    for off in epoch_offsets:
        ts = (base + timedelta(seconds=off)).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines.append(f"{ts}  [abcd1234]  INFO   AGENT_SPAWN  appsec-advisor:appsec-stride-analyzer  model=sonnet")
    (out / ".hook-events.log").write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestEventGapStandby:
    """The 2026-06-16 regression: a multi-dispatch Stage 1 under-records
    duration_ms, so wall−compute is large — but the machine was busy the whole
    time. Real-gap detection over the event log must NOT call that standby."""

    def test_undercounted_compute_is_not_standby_when_log_is_continuous(self, tmp_path: Path):
        # Stage 1 wall_obs=3810s but only Analyst-B's 1001s recorded as compute
        # → wall−compute = 2809s, which the OLD heuristic flagged as standby.
        _write(
            tmp_path,
            [{"stage": 1, "duration_ms": 1_001_000, "wall_secs_observed": 3810}],
            wall=4354,
        )
        # Event log streams steadily every ~4 min across the whole stage → no
        # real gap exceeds the 600s threshold.
        _write_hook_log(tmp_path, list(range(0, 3900, 240)))  # 0,240,...,3840
        t = rt.compute_timing(tmp_path)
        assert t["standby_secs"] == 0
        assert t["has_standby"] is False
        assert t["stages"][0]["is_standby"] is False
        # idle is still surfaced as the raw wall−compute for the row…
        assert t["stages"][0]["idle_secs"] == 2809
        # …but other_idle (wall − compute − standby) carries it, not standby.
        assert t["other_idle_secs"] == 4354 - 1001 - 0

    def test_real_gap_in_log_is_classed_as_standby(self, tmp_path: Path):
        _write(
            tmp_path,
            [{"stage": 1, "duration_ms": 600_000, "wall_secs_observed": 3000}],
            wall=3000,
        )
        # Steady events, then a 30-min (1800s) hole, then resume → 1800s standby.
        offs = [0, 200, 400, 600, 600 + 1800, 600 + 1800 + 200]
        _write_hook_log(tmp_path, offs)
        t = rt.compute_timing(tmp_path)
        assert t["standby_secs"] == 1800
        assert t["has_standby"] is True

    def test_falls_back_to_heuristic_without_log(self, tmp_path: Path):
        # No hook log → legacy wall−compute proxy still applies (back-compat).
        _write(
            tmp_path,
            [{"stage": 1, "duration_ms": 130_000, "wall_secs_observed": 9017}],
            wall=9100,
        )
        t = rt.compute_timing(tmp_path)
        assert t["standby_secs"] == 9017 - 130
        assert t["has_standby"] is True

    def test_post_run_gap_excluded_from_standby(self, tmp_path: Path):
        # A gap that occurs AFTER the run window (operator inspecting artifacts
        # post-completion) must not be counted — the 2026-06-16 over-count.
        from datetime import datetime, timezone

        base_iso = "2026-06-16T05:00:00Z"
        base_epoch = int(datetime.strptime(base_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
        _write(tmp_path, [{"stage": 1, "duration_ms": 800_000, "wall_secs_observed": 950}], wall=1000)
        (tmp_path / ".scan-start-epoch").write_text(str(base_epoch), encoding="utf-8")
        # In-run events stream 0..900 (no gap); a lone post-run event at +2500
        # sits past the window (start + wall(1000) + slack(600) = 1600).
        _write_hook_log(tmp_path, list(range(0, 950, 100)) + [2500], base_iso=base_iso)
        t = rt.compute_timing(tmp_path)
        assert t["standby_secs"] == 0
        assert t["has_standby"] is False
