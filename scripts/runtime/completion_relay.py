"""Show the reader the completion summary the run printed, exactly once.

``renderers/render_completion_summary.py`` prints the summary into a Bash tool
result, which the host collapses. Asking the orchestrator to reproduce it did
not hold: runs rewrote it into headings and tables of their own, and a Stop
hook that returned the turn on any dropped line made every partial relay a full
second copy. The plugin therefore delivers the summary itself and the
orchestrator never repeats it. Three surfaces are bound here:

* ``persist`` — the summary script records what it printed, bound to the run
  that holds the lock. Without a held lock it records nothing: a manual
  invocation has no hook that would take the record, and it must never surface
  in an unrelated session.
* ``hook_notice`` — ``runtime/agent_logger.py`` turns the record into a hook
  ``systemMessage``. The host renders that in full, uncollapsed. The
  ``PostToolUse`` of the Bash call that printed the summary takes it, so it
  appears before the closing message and before any report-error dialog; the
  outermost ``Stop`` takes a record that is still left. Sub-agent events never
  take it, and neither does a headless session, whose output carries no
  ``systemMessage``.
* ``main`` — ``run-headless.sh`` prints the record after the session's result
  text, through the same ``take``.

``take`` deletes the record as it returns it, so whichever surface comes first
is the only one that shows it. A record of another run is left for that run.
``runtime/runtime_cleanup.py`` deliberately leaves the record alone, because
the hook that takes it fires after cleanup; the next run's preflight removes a
record that a crashed session left behind.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import json
import os
import sys
from pathlib import Path

from shared._atomic_io import atomic_write_text

from runtime.acquire_lock import lock_is_owned_by_this_run, read_run_id, run_id_matches

RECORD = ".completion-summary.json"
_LOCK = ".appsec-lock"


def persist(output_dir: Path, summary: str) -> None:
    """Record the printed summary for this run's hooks. Never raises."""
    lock = Path(output_dir) / _LOCK
    try:
        if lock_is_owned_by_this_run(lock):
            atomic_write_text(
                Path(output_dir) / RECORD,
                json.dumps({"run_id": read_run_id(lock), "summary": summary}),
            )
    except OSError:
        pass  # without a record nothing is shown twice; the deliverables stand


def take(output_dir: Path | str, session_id: str = "") -> str:
    """Return this run's recorded summary once and delete the record, else ``""``.

    A record of another run stays for that run. A malformed one is discarded.
    """
    path = Path(output_dir) / RECORD
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return ""
    except (OSError, ValueError):
        record = None
    if isinstance(record, dict) and not run_id_matches(str(record.get("run_id") or ""), session_id):
        return ""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        return ""  # a record that cannot be consumed must not be shown again and again
    summary = record.get("summary") if isinstance(record, dict) else None
    return summary if isinstance(summary, str) else ""


def hook_notice(output_dir: Path | str, session_id: str, agent_id: str = "") -> dict | None:
    """The hook output that shows this run's summary, or ``None``.

    ``agent_id`` marks an event from inside a sub-agent, which is not the
    reader's view. A headless session leaves the record to ``main``.
    """
    if agent_id or os.environ.get("APPSEC_HEADLESS") == "1":
        return None
    if not (Path(output_dir) / RECORD).exists():
        return None  # the per-tool-call path: one stat, nothing else
    summary = take(output_dir, session_id)
    return {"systemMessage": summary.rstrip("\n")} if summary.strip() else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print this run's completion summary once.")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    summary = take(args.output_dir)
    if summary.strip():
        sys.stdout.write(summary if summary.endswith("\n") else summary + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
