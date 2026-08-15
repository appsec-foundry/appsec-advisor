#!/usr/bin/env python3
"""A cheap live run that proves the host integration before a paid one.

Repository gates validate code and deterministic fixtures. They cannot prove
the installed Claude Code version's hook payloads, background scheduling, or
signal propagation — and today the first thing that exercises those is a full
scan, so the gap surfaces only after recon and later roles have been paid for.

The canary runs the pipeline against the bundled synthetic repository under a
short wall-time cap and then checks five properties of what the host actually
produced:

* one foreground child completed;
* at least one bounded parallel pair overlapped;
* a completed child reported non-zero usage;
* every terminal call's turn budget was retired;
* live-call markers were cleared.

``run`` and ``check`` are separate on purpose. ``check`` reads only artifacts,
so it is fully testable without spending anything, and can also be pointed at
an earlier run's directory.

  python3 live_canary.py run   --output <dir> [--max-duration 600]
  python3 live_canary.py check --output <dir>
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PLUGIN_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

import budget_watchdog  # noqa: E402
from event_log import parse_line  # noqa: E402

SYNTHETIC_REPO = PLUGIN_ROOT / "tests" / "fixtures" / "e2e" / "synthetic-repo"
HOOK_LOG = ".hook-events.log"
ACTIVE_CALLS = ".active-tool-calls"
DEFAULT_MAX_DURATION_S = 900


def _kv(detail: str, key: str) -> str:
    for token in detail.split():
        name, _, value = token.partition("=")
        if name == key:
            return value
    return ""


def _events(output_dir: Path) -> list[tuple[str, str]]:
    """(event, detail) for every parseable line, in order."""
    try:
        raw = (output_dir / HOOK_LOG).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out = []
    for line in raw.splitlines():
        parsed = parse_line(line)
        if parsed is not None:
            out.append((parsed.event, parsed.detail))
    return out


def _open_budget_calls(output_dir: Path) -> set[str]:
    try:
        state = json.loads((output_dir / budget_watchdog.STATE_FILENAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    calls = state.get("calls") if isinstance(state, dict) else None
    return set(calls) if isinstance(calls, dict) else set()


def check(output_dir: Path) -> list[tuple[str, bool, str]]:
    """Return (property, passed, evidence) for each canary property."""
    events = _events(output_dir)
    spawned: dict[str, bool] = {}
    order: list[str] = []
    terminal: dict[str, str] = {}
    usage: dict[str, int] = {}
    for event, detail in events:
        call_id = _kv(detail, "agent_call_id")
        if not call_id:
            continue
        if event == "AGENT_SPAWN" and call_id not in spawned:
            spawned[call_id] = _kv(detail, "background") == "true"
            order.append(call_id)
        elif event in ("AGENT_DONE", "AGENT_FAILED"):
            terminal.setdefault(call_id, event)
            order.append(call_id)
        elif event == "AGENT_USAGE":
            try:
                usage[call_id] = int(_kv(detail, "out") or 0)
            except ValueError:
                usage[call_id] = 0

    done = [call for call, event in terminal.items() if event == "AGENT_DONE"]
    foreground_done = [call for call in done if spawned.get(call) is False]

    # A pair is bounded-parallel when both were spawned before either closed.
    parallel: list[str] = []
    live: list[str] = []
    for call_id in order:
        if call_id in terminal and call_id in live:
            live.remove(call_id)
            continue
        if spawned.get(call_id):
            live.append(call_id)
            if len(live) >= 2 and not parallel:
                parallel = live[:2]

    charged = [call for call in done if usage.get(call, 0) > 0]
    unretired = sorted(_open_budget_calls(output_dir) & set(terminal))
    markers = output_dir / ACTIVE_CALLS
    marker_files = sorted(p.name for p in markers.glob("*.json")) if markers.is_dir() else []

    return [
        (
            "foreground child completed",
            bool(foreground_done),
            f"{len(foreground_done)} of {len(done)} completed calls ran in the foreground",
        ),
        (
            "bounded parallel pair",
            bool(parallel),
            f"overlapping background calls: {', '.join(parallel) or 'none observed'}",
        ),
        (
            "completed child reported usage",
            bool(charged),
            f"{len(charged)} completed call(s) with non-zero output tokens",
        ),
        (
            "turn budgets retired",
            not unretired,
            f"open budget entries for terminal calls: {', '.join(unretired) or 'none'}",
        ),
        (
            "live markers cleared",
            not marker_files,
            f"remaining markers: {', '.join(marker_files) or 'none'}",
        ),
    ]


def run(output_dir: Path, max_duration: int) -> int:
    """Launch the canary scan against a private copy of the synthetic repo."""
    if not SYNTHETIC_REPO.is_dir():
        print(f"canary: no synthetic repository at {SYNTHETIC_REPO}", file=sys.stderr)
        return 2
    output_dir.mkdir(parents=True, exist_ok=True)
    repo = output_dir / "repo"
    if repo.exists():
        shutil.rmtree(repo)
    # `docs/security` in the fixture is captured artifact data from an earlier
    # run; copying it would seed the canary with someone else's telemetry.
    shutil.copytree(SYNTHETIC_REPO, repo, ignore=shutil.ignore_patterns("docs"))
    command = [
        str(SCRIPT_DIR / "run-headless.sh"),
        "--repo",
        str(repo),
        "--output",
        str(output_dir / "run"),
        "--assessment-depth",
        "quick",
        "--rebuild",
        "--keep-runtime-files",
        # The wrapper's own clock, not the skill's: it bounds what the canary
        # can spend even if the run never reaches a phase boundary.
        "--max-duration",
        str(max_duration),
    ]
    print("canary: " + " ".join(command))
    completed = subprocess.run(command, check=False, env={**os.environ, "APPSEC_TELEMETRY_STRICT": "1"})
    print(f"canary: wrapper exited {completed.returncode}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    runner = sub.add_parser("run", help="launch the canary scan")
    runner.add_argument("--output", required=True, help="directory for the canary repo copy and its run")
    runner.add_argument("--max-duration", type=int, default=DEFAULT_MAX_DURATION_S)
    checker = sub.add_parser("check", help="check what a canary run produced")
    checker.add_argument("--output", required=True, help="the canary run's OUTPUT_DIR")

    args = parser.parse_args(argv)
    if args.command == "run":
        return run(Path(args.output), args.max_duration)

    results = check(Path(args.output))
    width = max(len(name) for name, _, _ in results)
    for name, passed, evidence in results:
        print(f"{'PASS' if passed else 'FAIL'}  {name.ljust(width)}  {evidence}")
    failed = [name for name, passed, _ in results if not passed]
    if failed:
        print(f"\ncanary failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    print("\ncanary passed: the host integration behaves as the pipeline assumes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
