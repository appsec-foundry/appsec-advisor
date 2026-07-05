#!/usr/bin/env python3
"""Detect the host Claude Code session (main-loop) model from the live transcript.

**Fail-safe by contract.** This script ALWAYS exits 0 and prints EITHER a model
id OR an empty string — it must never raise, never block, never print a
traceback. It is a transparency helper only (warn on a Sonnet-4.6 host, render
the effective-routing table); a scan must run identically whether or not the
detection succeeds. Every failure path degrades to empty stdout + exit 0.

**Why the transcript.** No model env var is exposed to skill Bash, but the
Claude Code transcript at ``~/.claude/projects/<slug>/<session-id>.jsonl``
records ``.message.model`` on every assistant message. The LAST non-sidechain
assistant model is the model the host main loop is currently running — which is
what the alias ``"sonnet"`` resolves to for the renderer, orchestrator,
abuse-verifier and qa_content. Sidechain (``isSidechain: true``) entries are
sub-agent messages and are skipped: a sub-agent may run on Haiku and would
otherwise mask the host model.

**Session-id resolution order:**
  1. ``--session-id`` CLI arg
  2. ``$CLAUDE_CODE_SESSION_ID``
  3. ``$CLAUDE_SESSION_ID``
  4. (no id) newest ``*.jsonl`` under ``~/.claude/projects/*/`` — the live
     session is the file being appended to right now.

Usage:
    detect_session_model.py [--session-id ID]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _resolve_session_id(cli_id: str | None) -> str:
    return (cli_id or os.environ.get("CLAUDE_CODE_SESSION_ID") or os.environ.get("CLAUDE_SESSION_ID") or "").strip()


def _candidate_transcripts(session_id: str) -> list[Path]:
    """Return transcript paths, most-likely first.

    With a session id: every ``<projects>/*/<sid>.jsonl`` match. Without one:
    the single newest ``*.jsonl`` (the session being written to now).
    """
    root = Path.home() / ".claude" / "projects"
    if not root.is_dir():
        return []
    if session_id:
        return sorted(root.glob(f"*/{session_id}.jsonl"))
    # Fallback: newest transcript across all projects.
    all_jsonl = list(root.glob("*/*.jsonl"))
    if not all_jsonl:
        return []
    newest = max(all_jsonl, key=lambda p: p.stat().st_mtime)
    return [newest]


def _extract_model(obj: object) -> str:
    """Model id from a transcript line if it is a non-sidechain assistant msg."""
    if not isinstance(obj, dict):
        return ""
    if obj.get("type") != "assistant":
        return ""
    if obj.get("isSidechain"):
        return ""
    msg = obj.get("message")
    if isinstance(msg, dict) and msg.get("model"):
        return str(msg["model"])
    if obj.get("model"):
        return str(obj["model"])
    return ""


def _last_model(path: Path) -> str:
    """Last non-sidechain assistant model in one transcript ('' on any miss).

    Single forward pass, O(1) memory per line; cheap-skips lines without a
    ``"model"`` token before attempting a JSON parse.
    """
    last = ""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if '"model"' not in line:
                continue
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            model = _extract_model(obj)
            if model:
                last = model
    return last


def detect_session_model(session_id: str | None = None) -> str:
    """Return the host session model id, or '' if it cannot be determined."""
    try:
        sid = _resolve_session_id(session_id)
        for path in _candidate_transcripts(sid):
            model = _last_model(path)
            if model:
                return model
    except Exception:
        return ""
    return ""


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session-id", default=None)
    # Never let arg-parse errors escape the fail-safe contract.
    try:
        ns = parser.parse_args(argv)
        session_id = ns.session_id
    except SystemExit:
        session_id = None
    sys.stdout.write(detect_session_model(session_id))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
