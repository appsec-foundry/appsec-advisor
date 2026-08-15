"""Tests for scripts/live_canary.py — the cheap host-integration probe.

Only ``check`` is tested here, which is the point of the run/check split: the
properties the canary asserts are read from artifacts, so they can be pinned
without spending anything on a live run.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import budget_watchdog as budget  # noqa: E402
import live_canary  # noqa: E402
from event_log import format_line  # noqa: E402

AGENT = "appsec-advisor:appsec-recon-scanner"


def _line(event: str, detail: str) -> str:
    # Built through the canonical formatter: a hand-rolled column layout here
    # would test a shape no emitter produces.
    return format_line(event, detail, sid="b0ba1e2f")


def _spawn(call_id: str, background: bool = False) -> str:
    return _line("AGENT_SPAWN", f"agent_call_id={call_id}  agent_type={AGENT}  background={str(background).lower()}")


def _usage(call_id: str, out: int) -> str:
    return _line("AGENT_USAGE", f"agent_call_id={call_id}  agent_type={AGENT}  in=100000  out={out}")


def _done(call_id: str) -> str:
    return _line("AGENT_DONE", f"agent_call_id={call_id}  agent_type={AGENT}")


def _healthy_log() -> str:
    return "".join(
        [
            _spawn("toolu_fg"),
            _usage("toolu_fg", 700),
            _done("toolu_fg"),
            _spawn("toolu_p1", background=True),
            _spawn("toolu_p2", background=True),
            _usage("toolu_p1", 400),
            _done("toolu_p1"),
            _usage("toolu_p2", 500),
            _done("toolu_p2"),
        ]
    )


def _write(output_dir: Path, log: str) -> Path:
    (output_dir / live_canary.HOOK_LOG).write_text(log, encoding="utf-8")
    return output_dir


def _results(output_dir: Path) -> dict[str, bool]:
    return {name: passed for name, passed, _ in live_canary.check(output_dir)}


def test_a_healthy_run_passes_every_property(tmp_path: Path) -> None:
    _write(tmp_path, _healthy_log())
    assert all(_results(tmp_path).values())
    assert live_canary.main(["check", "--output", str(tmp_path)]) == 0


def test_an_empty_run_fails_every_property_it_can_observe(tmp_path: Path) -> None:
    _write(tmp_path, "")
    results = _results(tmp_path)
    assert results["foreground child completed"] is False
    assert results["bounded parallel pair"] is False
    assert results["completed child reported usage"] is False
    # Nothing ran, so nothing is unretired or left behind.
    assert results["turn budgets retired"] is True
    assert results["live markers cleared"] is True


def test_serialized_background_calls_are_not_a_parallel_pair(tmp_path: Path) -> None:
    """Each closes before the next opens — that is exactly the serial dispatch
    the canary has to be able to tell apart from a wave."""
    _write(
        tmp_path,
        "".join(
            [
                _spawn("toolu_fg"),
                _usage("toolu_fg", 700),
                _done("toolu_fg"),
                _spawn("toolu_p1", background=True),
                _done("toolu_p1"),
                _spawn("toolu_p2", background=True),
                _done("toolu_p2"),
            ]
        ),
    )
    assert _results(tmp_path)["bounded parallel pair"] is False


def test_a_completion_without_usage_fails(tmp_path: Path) -> None:
    """The postfix6 signature: the call closed but no child usage reached it."""
    _write(tmp_path, _spawn("toolu_fg") + _done("toolu_fg"))
    assert _results(tmp_path)["completed child reported usage"] is False
    assert _results(tmp_path)["foreground child completed"] is True


def test_an_unretired_budget_entry_fails(tmp_path: Path) -> None:
    _write(tmp_path, _healthy_log())
    (tmp_path / budget.STATE_FILENAME).write_text(
        json.dumps(
            {
                "schema_version": budget.STATE_SCHEMA_VERSION,
                "calls": {
                    "toolu_fg": {
                        "agent_call_id": "toolu_fg",
                        "sid": "b0ba1e2f",
                        "agent": "recon-scanner",
                        "agent_type": AGENT,
                        "turns": 12,
                        "max_turns": 36,
                        "warn_emitted": False,
                        "critical_emitted": False,
                        "max_emitted": False,
                        "first_seen": 1,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    assert _results(tmp_path)["turn budgets retired"] is False
    assert live_canary.main(["check", "--output", str(tmp_path)]) == 1


def test_a_leftover_live_marker_fails(tmp_path: Path) -> None:
    _write(tmp_path, _healthy_log())
    markers = tmp_path / live_canary.ACTIVE_CALLS
    markers.mkdir()
    (markers / "toolu_fg.json").write_text("{}", encoding="utf-8")
    assert _results(tmp_path)["live markers cleared"] is False


def test_the_synthetic_repository_the_canary_runs_against_exists() -> None:
    assert (live_canary.SYNTHETIC_REPO / "package.json").is_file()
