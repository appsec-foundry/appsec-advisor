#!/usr/bin/env python3
"""Conversation lines for a controller assessment that runs in the background.

Usage:
  python3 runtime/assessment_console.py follow --progress-file <FILE> [--from-end] [--output <OUTPUT_DIR>]
  python3 runtime/assessment_console.py close --output <OUTPUT_DIR> --exit-code <N> [--log <FILE>]

``follow`` reads the controller's ``--progress-file`` as it grows and prints
one finished line per milestone: the run header, each phase's start and end,
each finished survey component and verification job, and each warning. It exits after the run's ``end``
record, or with ``--output`` once the run that held that directory released it
without one. ``--from-end`` skips the records already written, for a watcher that
resumes an earlier one. ``close`` prints the run's closing block once the
command has exited: the controller's summary after a completed run, otherwise
the outcome and the last lines of the command's output.

The skill relays these lines verbatim, so wording, rounding and the order of
fields are decided here and not by a model. Component and finding names never
appear: they come from repository files and model output.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path

# Longest text taken from one record field.
_FIELD_MAX = 300
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
# A finished survey component and a finished verification job; engines before
# the survey/verification steps write the component count without its prefix.
_FINISHED = re.compile(r"(?:Survey: )?(\d+)/(\d+|\?) components done\b")
_VERIFIED = re.compile(r"Verify: (\d+)/(\d+) jobs done\b(?:.* · no result \((budget|failure)\))?")
# Lines of the command's output shown when no summary exists.
LOG_LINES = 40

OUTCOMES = {
    0: "■ Assessment complete.",
    20: "■ Assessment complete, but the --fail-on gate failed.",
    3: "■ Assessment paused or stopped. Its accepted steps stay for --resume.",
    130: "■ Assessment interrupted. Its accepted steps stay for --resume.",
}


def _text(value) -> str:
    """One printable line of at most ``_FIELD_MAX`` characters; a fence cannot be closed by it."""
    text = _ANSI.sub("", str(value if value is not None else ""))
    text = "".join(char if char.isprintable() else " " for char in text).replace("```", "'''")
    return text[:_FIELD_MAX].strip()


def _run_state(record: dict) -> str:
    """The run's share, elapsed and remaining time; the remaining time is marked as an estimate."""
    parts = []
    progress = _text(record.get("progress"))
    if progress and progress != "planning":
        parts.append(f"{progress} done")
    if _text(record.get("elapsed")):
        parts.append(f"{_text(record.get('elapsed'))} elapsed")
    if _text(record.get("left")):
        parts.append(f"{_text(record.get('left'))} left (rough estimate)")
    return f"  ({' · '.join(parts)})" if parts else ""


def _phase(record: dict) -> str:
    number, total = record.get("number"), record.get("total")
    position = f"{number}/{total}" if isinstance(number, int) and isinstance(total, int) else "?"
    return f"Phase {position} — {_text(record.get('phase'))}"


def render(record: dict) -> list[str]:
    """The conversation lines of one progress record; records nobody needs to see give none."""
    event = record.get("event")
    if event == "run_start":
        lines = [_text(line) for line in record.get("lines") or [] if _text(line)]
        return ["```", *lines, "```"] if lines else []
    if event == "phase_start":
        return [f"▶ {_phase(record)}{_run_state(record)}"]
    if event == "phase_done":
        detail = _text(record.get("detail"))
        return [f"✓ {_phase(record)}" + (f": {detail}" if detail else "")]
    if event in ("component_done", "warning") and (verified := _VERIFIED.match(_text(record.get("detail")))):
        # A verification job's line names its component, so only its counts are relayed.
        result = f", one without a result ({verified[3]})" if verified[3] else ""
        return [f"  · Verify: {verified[1]}/{verified[2]} jobs finished{result}{_run_state(record)}"]
    if event == "component_done":
        finished = _FINISHED.match(_text(record.get("detail")))
        if not finished:
            return []
        return [f"  · Survey: {finished[1]}/{finished[2]} components analyzed{_run_state(record)}"]
    if event == "warning":
        detail = _text(record.get("detail"))
        return [f"⚠ {detail}"] if detail else []
    return []


def records(
    path: Path,
    from_end: bool = False,
    sleep: Callable[[float], None] = time.sleep,
    poll: float = 0.5,
    running: Callable[[], bool] | None = None,
) -> Iterator[dict]:
    """Each complete record of ``path`` as it is appended, until the run's ``end`` record.

    The file may not exist yet, may hold a half-written line, and is replaced
    when a new run starts; a replaced file is read from its beginning. With
    ``running``, reading also stops once a run that was seen live has released
    its directory and the file has nothing left: a run that died before writing
    ``end`` must not keep the watcher open until it times out.
    """
    offset, pending, seen_live = None, b"", False
    while True:
        try:
            size = path.stat().st_size
        except OSError:
            size = None
        if size is not None and offset is None:
            offset = size if from_end else 0
        if size is not None and size < offset:
            offset, pending = 0, b""
        if size is None or size == offset:
            if running is not None:
                if running():
                    seen_live = True
                elif seen_live:
                    return
            sleep(poll)
            continue
        with path.open("rb") as stream:
            stream.seek(offset)
            pending += stream.read(size - offset)
        offset = size
        *complete, pending = pending.split(b"\n")
        for raw in complete:
            try:
                record = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                continue
            if not isinstance(record, dict):
                continue
            yield record
            if record.get("event") == "end":
                return


def follow(
    path: Path,
    from_end: bool = False,
    out=None,
    sleep: Callable[[float], None] = time.sleep,
    running: Callable[[], bool] | None = None,
) -> None:
    out = out or sys.stdout
    for record in records(path, from_end, sleep, running=running):
        for line in render(record):
            # One flush per line: the watcher turns each written line into an event.
            out.write(line + "\n")
            out.flush()


def _tail(path: Path, count: int) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return [_ANSI.sub("", line).replace("```", "'''") for line in lines[-count:]]


def closing(output: Path, code: int, log: Path | None = None) -> list[str]:
    """The block shown once the command exited: the summary after completion, otherwise outcome and output."""
    summary = output / ".assessment-work" / "summary.txt"
    if code in (0, 20):
        try:
            text = summary.read_text(encoding="utf-8")
        except OSError:
            text = ""
        if text.strip():
            block = ["```", *(_ANSI.sub("", line).replace("```", "'''") for line in text.rstrip().splitlines()), "```"]
            return block + ([OUTCOMES[20]] if code == 20 else [])
    lines = [OUTCOMES.get(code, f"■ Assessment failed (exit {code}).")]
    shown = _tail(log, LOG_LINES) if log else []
    return lines + (["```", *shown, "```"] if shown else [])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    watch = commands.add_parser("follow")
    watch.add_argument("--progress-file", required=True, type=Path)
    watch.add_argument("--from-end", action="store_true")
    watch.add_argument("--output", type=Path)
    close = commands.add_parser("close")
    close.add_argument("--output", required=True, type=Path)
    close.add_argument("--exit-code", required=True, type=int)
    close.add_argument("--log", type=Path)
    args = parser.parse_args(argv)
    if args.command == "follow":
        running = None
        if args.output:
            sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
            from runtime.live_run_holder import holder

            running = lambda: holder(args.output) is not None  # noqa: E731
        follow(args.progress_file, args.from_end, running=running)
    else:
        print("\n".join(closing(args.output, args.exit_code, args.log)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
