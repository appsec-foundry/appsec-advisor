"""Tests for scripts/record_component_durations.py.

Pins where a per-component STRIDE duration may come from. The measurement the
controller stamps outranks anything the measured agent reports about itself.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "record_component_durations.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("record_component_durations", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


durations_mod = _load_module()


def _spawn(ts: str, component: str) -> str:
    return (
        f"{ts}  [aa40ceb8]  INFO   stride-analyzer-v2  AGENT_SPAWN         "
        f"agent_call_id=toolu_x  agent_type=appsec-advisor:appsec-stride-analyzer-v2  "
        f"model=sonnet  background=false  job_id=stride:{component}:attempt-1  "
        f"component_id={component}  attempt=1  analysis_depth=full  "
        f"description=STRIDE (full): {component}\n"
    )


def _usage(ts: str, component: str) -> str:
    return (
        f"{ts}  [aa40ceb8]  INFO   stride-analyzer-v2  AGENT_USAGE         "
        f"agent_call_id=toolu_x  component_id={component}  attempt=1  "
        f"in=48  out=67284  cache_write=133025  cache_read=2126193  tool_uses=33\n"
    )


def _dispatch_only(ts: str, component: str) -> str:
    """AGENT_DONE fires at dispatch, one second after the spawn — not completion."""
    return (
        f"{ts}  [aa40ceb8]  INFO   stride-analyzer-v2  AGENT_DONE          "
        f"agent_call_id=toolu_x  component_id={component}  attempt=1\n"
    )


def _write_log(output: Path, body: str) -> Path:
    log = output / ".agent-run.log"
    log.write_text(
        "2026-08-16T07:00:00Z  [aa40ceb8]  INFO   threat-analyst      "
        "PHASE_START         [Phase 9/11] Threat analysis\n" + body,
        encoding="utf-8",
    )
    return log


def _write_stride_output(output: Path, component: str, started: str, analyzed: str) -> None:
    (output / f".stride-{component}.json").write_text(
        json.dumps({"started_at": started, "analyzed_at": analyzed, "threats": []}),
        encoding="utf-8",
    )


class TestControllerDurations:
    def test_spawn_to_usage_span_is_measured_per_component(self, tmp_path: Path):
        log = _write_log(
            tmp_path,
            _spawn("2026-08-16T07:02:59Z", "web-frontend")
            + _spawn("2026-08-16T07:03:27Z", "api-server")
            + _usage("2026-08-16T07:13:50Z", "api-server")
            + _usage("2026-08-16T07:16:20Z", "web-frontend"),
        )
        assert durations_mod._controller_dispatch_durations(log) == {
            "web-frontend": 801,
            "api-server": 623,
        }

    def test_dispatch_events_are_not_treated_as_completion(self, tmp_path: Path):
        """AGENT_DONE lands a second after the spawn; without usage there is no span."""
        log = _write_log(
            tmp_path,
            _spawn("2026-08-16T07:02:59Z", "web-frontend") + _dispatch_only("2026-08-16T07:03:00Z", "web-frontend"),
        )
        assert durations_mod._controller_dispatch_durations(log) == {}

    def test_a_component_still_running_is_omitted(self, tmp_path: Path):
        log = _write_log(
            tmp_path,
            _spawn("2026-08-16T07:02:59Z", "web-frontend")
            + _spawn("2026-08-16T07:03:27Z", "api-server")
            + _usage("2026-08-16T07:13:50Z", "api-server"),
        )
        assert durations_mod._controller_dispatch_durations(log) == {"api-server": 623}

    def test_absurd_span_is_dropped(self, tmp_path: Path):
        log = _write_log(
            tmp_path,
            _spawn("2026-08-16T07:00:00Z", "web-frontend") + _usage("2026-08-16T10:00:00Z", "web-frontend"),
        )
        assert durations_mod._controller_dispatch_durations(log) == {}

    def test_missing_log_returns_empty(self, tmp_path: Path):
        assert durations_mod._controller_dispatch_durations(tmp_path / "absent.log") == {}


class TestSourcePriority:
    def test_model_authored_timestamps_never_outrank_the_measurement(self, tmp_path: Path):
        """The regression: an agent cannot read a clock, so its numbers are invented.

        Reproduces the 2026-08-16 run, where auth-service self-reported a 4500 s
        analysis that actually took 927 s and web-frontend reported 60 s for 801 s.
        """
        _write_log(
            tmp_path,
            _spawn("2026-08-16T07:02:59Z", "web-frontend")
            + _spawn("2026-08-16T07:03:52Z", "auth-service")
            + _usage("2026-08-16T07:16:20Z", "web-frontend")
            + _usage("2026-08-16T07:19:19Z", "auth-service"),
        )
        _write_stride_output(tmp_path, "web-frontend", "2026-08-16T00:00:00Z", "2026-08-16T00:01:00Z")
        _write_stride_output(tmp_path, "auth-service", "2026-08-16T00:00:00Z", "2026-08-16T01:15:00Z")

        assert durations_mod._stride_durations(tmp_path, 0) == {
            "web-frontend": 801,
            "auth-service": 927,
        }

    def test_self_reported_values_still_serve_a_log_without_controller_events(self, tmp_path: Path):
        _write_log(tmp_path, "")
        _write_stride_output(tmp_path, "web-frontend", "2026-08-16T07:02:59Z", "2026-08-16T07:16:20Z")

        assert durations_mod._stride_durations(tmp_path, 0) == {"web-frontend": 801}


class TestMain:
    def test_durations_are_merged_into_the_baseline(self, tmp_path: Path):
        _write_log(
            tmp_path,
            _spawn("2026-08-16T07:02:59Z", "web-frontend") + _usage("2026-08-16T07:16:20Z", "web-frontend"),
        )
        _write_stride_output(tmp_path, "web-frontend", "2026-08-16T00:00:00Z", "2026-08-16T00:01:00Z")

        assert durations_mod.main([str(tmp_path)]) == 0
        baseline = json.loads((tmp_path / ".appsec-cache" / "baseline.json").read_text(encoding="utf-8"))
        assert baseline["component_durations"] == {"web-frontend": 801}

    def test_missing_output_directory_is_a_usage_error(self, tmp_path: Path):
        assert durations_mod.main([str(tmp_path / "absent")]) == 2
