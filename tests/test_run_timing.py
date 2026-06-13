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
    (out / ".stage-stats.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
    )
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
