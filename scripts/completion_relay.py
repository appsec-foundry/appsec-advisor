"""Hold the run's closing message to the completion summary it printed.

``render_completion_summary.py`` prints the summary into a Bash tool result,
which the host collapses: the reader sees the orchestrator's closing message
instead. The completion runtime tells the orchestrator to emit that stdout
verbatim (``skills/create-threat-model/SKILL-thin-completion.md``), and runs
rewrote it anyway into headings and tables of their own, dropping Next Steps,
the team questions, run issues and log paths. Wording alone does not hold, so
two surfaces are bound here:

* ``persist`` — the summary script records what it printed, bound to the run
  that holds the lock. Without a held lock it records nothing: a manual
  invocation has no closing Stop, and its record must never send an unrelated
  session back.
* ``review_final_message`` — the outermost ``Stop`` in ``agent_logger.py``
  compares the closing message with the record. A missing line returns the
  turn once. The record remembers that, so a retry that still drops lines ends
  the session instead of looping, whether or not the host reports
  ``stop_hook_active``.

A printed line counts as reproduced when it appears in printed order with only
its whitespace changed. Anything the message adds around the lines, such as a
code fence or a lead-in, is allowed. The review deletes the record once it has
decided. ``runtime_cleanup.py`` deliberately leaves the record alone, because
the closing Stop fires after cleanup; the next run's preflight removes a record
that a crashed session left behind.
"""

from __future__ import annotations

import json
from pathlib import Path

from _atomic_io import atomic_write_text
from acquire_lock import lock_is_owned_by_this_run, read_run_id, run_id_matches

RECORD = ".completion-summary.json"
_LOCK = ".appsec-lock"

#: What the returned turn is told. The summary is the latest tool output in the
#: orchestrator's context, so the reason names it instead of repeating it.
RETRY_INSTRUCTION = (
    "Your closing message did not reproduce the completion summary. Reply again with the stdout "
    "of the last render_completion_summary.py run exactly as printed: every line, in order, "
    "without headings, tables, or wording of your own."
)


def persist(output_dir: Path, summary: str) -> None:
    """Record the printed summary for this run's closing Stop. Never raises."""
    lock = Path(output_dir) / _LOCK
    try:
        if lock_is_owned_by_this_run(lock):
            atomic_write_text(
                Path(output_dir) / RECORD,
                json.dumps({"run_id": read_run_id(lock), "summary": summary}),
            )
    except OSError:
        pass  # without a record the review is skipped; the deliverables stand


def _lines(text: str) -> list[str]:
    return [" ".join(line.split()) for line in text.splitlines() if line.strip()]


def missing_lines(summary: str, message: str) -> list[str]:
    """Printed summary lines the message does not reproduce in printed order."""
    reproduced = _lines(message)
    position = 0
    missing: list[str] = []
    for line in _lines(summary):
        try:
            position = reproduced.index(line, position) + 1
        except ValueError:
            missing.append(line)
    return missing


def final_message(transcript_path: str) -> str:
    """The assistant text after the session's last tool call or user turn.

    Fallback for a host whose Stop payload carries no ``last_assistant_message``.
    A headless session persists no transcript and yields ``""``.
    """
    closing: list[str] = []
    try:
        with open(transcript_path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                try:
                    record = json.loads(raw)
                except ValueError:
                    continue
                message = record.get("message") if isinstance(record, dict) else None
                if not isinstance(message, dict):
                    continue
                if message.get("role") == "user":
                    closing = []  # a tool result, a new prompt, or hook feedback starts over
                    continue
                if message.get("role") != "assistant":
                    continue
                content = message.get("content")
                blocks = [{"type": "text", "text": content}] if isinstance(content, str) else content
                for block in blocks if isinstance(blocks, list) else []:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_use":
                        closing = []
                    elif block.get("type") == "text":
                        closing.append(str(block.get("text") or ""))
    except OSError:
        return ""
    return "\n".join(closing)


def review_final_message(output_dir: Path | str, session_id: str, message: str, *, retry: bool) -> list[str]:
    """Return the printed lines the closing message dropped; ``[]`` lets the session stop.

    ``retry`` is the host's ``stop_hook_active``. A record of another run is left
    for that run's session. Every other outcome decides the record: it is
    deleted, or, when lines are missing for the first time, marked as returned.
    """
    path = Path(output_dir) / RECORD
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError):
        record = None
    if isinstance(record, dict) and not run_id_matches(str(record.get("run_id") or ""), session_id):
        return []
    summary = record.get("summary") if isinstance(record, dict) else None
    missing: list[str] = []
    if isinstance(summary, str) and message and not retry and not record.get("returned"):
        missing = missing_lines(summary, message)
    if missing:
        atomic_write_text(path, json.dumps({**record, "returned": True}))
    else:
        path.unlink(missing_ok=True)
    return missing
