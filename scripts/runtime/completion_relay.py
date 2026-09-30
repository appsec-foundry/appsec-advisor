"""Hold the run's closing message to the completion summary it printed.

``renderers/render_completion_summary.py`` prints the summary into a Bash tool result,
which the host collapses: the reader sees the orchestrator's closing message
instead. The completion runtime tells the orchestrator to emit that stdout
verbatim (``skills/create-threat-model/SKILL-thin-completion.md``), and runs
rewrote it anyway into headings and tables of their own, dropping Next Steps,
run issues and log paths. Wording alone does not hold, so
two surfaces are bound here:

* ``persist`` — the summary script records what it printed, bound to the run
  that holds the lock. Without a held lock it records nothing: a manual
  invocation has no closing Stop, and its record must never send an unrelated
  session back.
* ``review_final_message`` — the outermost ``Stop`` in ``runtime/agent_logger.py``
  compares the closing message with the record. A missing line returns the
  turn once. The record remembers that, so a retry that still drops lines ends
  the session instead of looping, whether or not the host reports
  ``stop_hook_active``.

A printed line counts as reproduced when it appears in printed order with only
its whitespace changed. A lead-in before the summary and code fences are
allowed; text after its last line is not, because an appended note repeats or
contradicts what the summary already says (it prints its own re-export
commands). Any assistant text of the closing turn may carry the reproduction:
one delivered before a later tool call is not demanded again, since a repeat
shows the reader the summary twice. The review deletes the record once it has decided. ``runtime/runtime_cleanup.py`` deliberately leaves the record alone, because
the closing Stop fires after cleanup; the next run's preflight removes a record
that a crashed session left behind.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import json
from pathlib import Path

from shared._atomic_io import atomic_write_text

from runtime.acquire_lock import lock_is_owned_by_this_run, read_run_id, run_id_matches

RECORD = ".completion-summary.json"
_LOCK = ".appsec-lock"

#: What the returned turn is told. The summary is the latest tool output in the
#: orchestrator's context, so the reason names it instead of repeating it.
RETRY_INSTRUCTION = (
    "Your closing message did not reproduce the completion summary. Reply again with the stdout "
    "of the last renderers/render_completion_summary.py run exactly as printed: every line, in order, "
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


def trailing_lines(summary: str, message: str) -> list[str]:
    """Message lines after the reproduced summary's last line, code fences aside."""
    printed = _lines(summary)
    reproduced = _lines(message)
    if not printed or printed[-1] not in reproduced:
        return []
    end = len(reproduced) - reproduced[::-1].index(printed[-1])
    return [line for line in reproduced[end:] if not line.startswith("```")]


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


def _genuine_prompt(content: object) -> bool:
    """A user record that starts a turn, unlike a tool result inside one."""
    if isinstance(content, str):
        return True
    return isinstance(content, list) and not any(
        isinstance(block, dict) and block.get("type") == "tool_result" for block in content
    )


def turn_texts(transcript_path: str) -> list[str]:
    """Every assistant text block since the turn's prompt, in order.

    The reader sees each of them, so a summary reproduced before a later tool
    call has been delivered. ``""`` paths and unreadable transcripts yield ``[]``.
    """
    texts: list[str] = []
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
                content = message.get("content")
                if message.get("role") == "user":
                    if _genuine_prompt(content):
                        texts = []
                    continue
                if message.get("role") != "assistant":
                    continue
                blocks = [{"type": "text", "text": content}] if isinstance(content, str) else content
                for block in blocks if isinstance(blocks, list) else []:
                    if isinstance(block, dict) and block.get("type") == "text" and block.get("text"):
                        texts.append(str(block["text"]))
    except (OSError, TypeError):
        return []
    return texts


def _reproduces(summary: str, text: str) -> bool:
    return not missing_lines(summary, text) and not trailing_lines(summary, text)


def review_final_message(
    output_dir: Path | str, session_id: str, message: str, *, retry: bool, earlier: list[str] | None = None
) -> list[str]:
    """Return the printed lines the closing message dropped, else the lines it appended; ``[]`` lets the session stop.

    ``retry`` is the host's ``stop_hook_active``. ``earlier`` holds the turn's
    other assistant texts: a verbatim summary among them was already delivered,
    so later tool calls or a short closing line do not force a repeat. A record
    of another run is left for that run's session. Every other outcome decides
    the record: it is deleted, or, when lines are missing for the first time,
    marked as returned.
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
    delivered = isinstance(summary, str) and any(_reproduces(summary, text) for text in [*(earlier or []), message])
    if isinstance(summary, str) and message and not retry and not record.get("returned") and not delivered:
        missing = missing_lines(summary, message) or trailing_lines(summary, message)
    if missing:
        atomic_write_text(path, json.dumps({**record, "returned": True}))
    else:
        path.unlink(missing_ok=True)
    return missing
