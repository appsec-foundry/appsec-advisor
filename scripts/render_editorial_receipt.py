#!/usr/bin/env python3
"""render_editorial_receipt.py — what Stage 4 actually did, on disk and on screen.

Stage 4 rewrites prose through a plan and a deterministic applier. Until this
script runs, the outcome exists only in an agent's return value, which does not
survive the session: the run has no record of which blocks were rewritten, which
actions were rejected, or whether the guard rolled the pass back.

Reads the projection, the plan, and the applier and guard reports, then:

  * writes ``.architect-status.json`` — the artifact the controller's Stage-4
    gate and the completion summary already read, so no other consumer changes;
  * appends one ``EDITORIAL_PASS`` line to ``.agent-run.log``;
  * prints a short receipt for the console.

The log line is what survives the run. ``.architect-status.json`` is in
``runtime_cleanup``'s ``POST_ARCH_FILES_IF_PASS``, and the status below is
always ``pass``, so a completed run reaps it; ``.dispatch-context/`` goes with
the ALWAYS wave. Without the log line every count here would be gone by the
time anyone asks how the pass performed — the exact gap this script exists to
close. ``.agent-run.log`` is in ``runtime_cleanup``'s ``NEVER`` set.

The status is ``pass`` whenever the stage completed, including when the pass
rewrote nothing or the guard reverted it. Stage 4 no longer judges the report,
so it has nothing to fail it on; a genuine defect is a blocking gate's business,
not this stage's.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _atomic_io import atomic_write_json  # noqa: E402
from event_log import format_line  # noqa: E402

CONTEXT_DIR = ".dispatch-context/editorial"
STATUS_NAME = ".architect-status.json"
PRE_PASS_NAME = ".architect-pre-pass.json"
LOG_NAME = ".agent-run.log"


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _advisory_findings(pre_pass: Any) -> list[str]:
    """Warning titles from the deterministic structural checks.

    They used to reach only `.architect-review.md`, which no deliverable reads,
    so the same observations recurred run after run. Surfacing the titles here
    is what makes them actionable.
    """
    if not isinstance(pre_pass, dict):
        return []
    out = []
    for section in pre_pass.values():
        if not isinstance(section, dict):
            continue
        for finding in section.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            if str(finding.get("severity") or "").lower() != "warning":
                continue
            title = str(finding.get("title") or finding.get("kind") or finding.get("type") or "").strip()
            if title:
                out.append(title)
    return out


def build_status(output_dir: Path) -> dict:
    context = output_dir / CONTEXT_DIR
    projection = _load(context / "blocks.json") or {}
    plan = _load(context / "plan.json") or {}
    apply_report = _load(context / "apply-report.json") or {}
    guard_report = _load(context / "guard-report.json") or {}
    advisories = _advisory_findings(_load(output_dir / PRE_PASS_NAME))

    reverted = bool(guard_report.get("restored")) or guard_report.get("status") == "violations"
    applied = 0 if reverted else int(apply_report.get("applied_count") or 0)

    return {
        "status": "pass",
        "source": "editorial-pass",
        "generated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "blocks_offered": int((projection.get("selection") or {}).get("blocks_total") or 0),
        "edits_proposed": len(plan.get("actions") or []),
        "edits_applied": applied,
        "edits_rejected": int(apply_report.get("rejected_count") or 0),
        "guard_violations": int(guard_report.get("violation_count") or 0),
        "reverted": reverted,
        "files_touched": [] if reverted else list(apply_report.get("files_touched") or []),
        "advisory_findings": advisories,
    }


def render(status: dict) -> str:
    lines = ["", "Stage 4 — editorial pass"]
    if status["reverted"]:
        lines.append(
            f"  Reverted: {status['guard_violations']} invariant violation(s); the report keeps its original wording"
        )
    elif status["edits_applied"]:
        files = ", ".join(status["files_touched"]) or "—"
        lines.append(f"  Rewrote {status['edits_applied']} of {status['blocks_offered']} blocks in {files}")
    else:
        lines.append(f"  No rewrite needed across {status['blocks_offered']} blocks")
    if status["edits_rejected"]:
        lines.append(f"  Rejected: {status['edits_rejected']} action(s) — stale or off-list, reported by the applier")

    advisories = status["advisory_findings"]
    if advisories:
        lines.append(f"  Structural warnings ({len(advisories)}, advisory — nothing in this stage repairs them):")
        for title in advisories[:5]:
            lines.append(f"    · {title}")
        if len(advisories) > 5:
            lines.append(f"    · … {len(advisories) - 5} more in {PRE_PASS_NAME}")
    return "\n".join(lines)


def log_detail(status: dict) -> str:
    """The counts a later diagnosis needs, as one flat key=value detail."""
    return (
        f"offered={status['blocks_offered']} "
        f"proposed={status['edits_proposed']} "
        f"applied={status['edits_applied']} "
        f"rejected={status['edits_rejected']} "
        f"guard_violations={status['guard_violations']} "
        f"reverted={str(status['reverted']).lower()} "
        f"advisory_warnings={len(status['advisory_findings'])}"
    )


def append_log(output_dir: Path, status: dict) -> None:
    """Best-effort — a failed log write never fails the stage."""
    try:
        with open(output_dir / LOG_NAME, "a", encoding="utf-8") as fh:
            fh.write(format_line("EDITORIAL_PASS", log_detail(status), component="architect-reviewer"))
    except OSError:
        pass


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="render_editorial_receipt.py", description=__doc__)
    parser.add_argument("output_dir")
    parser.add_argument("--no-print", action="store_true", help="write the status file, print nothing")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    if not output_dir.is_dir():
        print(f"render_editorial_receipt.py: output dir not found: {output_dir}", file=sys.stderr)
        return 2

    status = build_status(output_dir)
    try:
        atomic_write_json(output_dir / STATUS_NAME, status)
    except OSError as exc:
        print(f"render_editorial_receipt.py: cannot write {STATUS_NAME}: {exc}", file=sys.stderr)
        return 2
    append_log(output_dir, status)

    if not args.no_print:
        print(render(status))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
