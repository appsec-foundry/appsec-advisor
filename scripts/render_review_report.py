#!/usr/bin/env python3
"""render_review_report.py — turn a verify-requirements verdict into Markdown.

Deterministic renderer for the `appsec-reviewer` CLI: reads a
`.requirements-verification.json` verdict (schema:
requirements-verification.schema.json) and writes a developer-facing Markdown
report (the `--output security-review.md` artifact). No LLM — the agent already
produced the structured findings; this just presents them. Keeping the final
artifact deterministic is the AGENTS.md "prefer Python for final artifacts" rule.

Shows open (in-scope FAIL/PARTIAL) requirements with finding + code-aware fix +
effort. PASS / UNVERIFIABLE / NOT_APPLICABLE are summarised in the header only.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_DOT = {"FAIL": "🔴", "PARTIAL": "🟡", "PASS": "🟢", "UNVERIFIABLE": "⚪", "NOT_APPLICABLE": "⚫"}
_PRIO_RANK = {"MUST": 3, "SHOULD": 2, "MAY": 1}


def _sort_key(r: dict) -> tuple:
    status_rank = {"FAIL": 0, "PARTIAL": 1}.get(r.get("status"), 2)
    return (status_rank, -_PRIO_RANK.get(r.get("priority", ""), 0), r.get("id", ""))


def render(verdict: dict) -> str:
    s = verdict.get("summary", {})
    src = verdict.get("requirements_source") or "unknown"
    catalog_kind = "built-in best-practices baseline" if "bestpractice" in str(src).lower() else src
    results = [r for r in verdict.get("results", []) if isinstance(r, dict)]
    open_reqs = sorted(
        [r for r in results if r.get("in_scope") and r.get("status") in ("FAIL", "PARTIAL")],
        key=_sort_key,
    )

    out: list[str] = []
    out.append("# Security Review — change verification")
    out.append("")
    out.append("| Field | Value |")
    out.append("|-------|-------|")
    out.append(f"| Generated | {verdict.get('generated_at', '—')} |")
    out.append(f"| Base ref | `{verdict.get('base_ref', '—')}` |")
    out.append(f"| Checked against | {catalog_kind} |")
    out.append(f"| Files changed | {s.get('changed_files', '—')} |")
    out.append(f"| In-scope requirements | {s.get('in_scope', 0)} of {s.get('candidates', 0)} candidates |")
    out.append(
        f"| Result | 🔴 {s.get('fail', 0)} fail · 🟡 {s.get('partial', 0)} partial · "
        f"🟢 {s.get('pass', 0)} pass · ⚪ {s.get('unverifiable', 0)} unverifiable |"
    )
    out.append("")

    if not open_reqs:
        out.append("✅ **No open requirements on this change.** "
                   "Everything in scope passed (or was not applicable).")
        out.append("")
        return "\n".join(out)

    out.append("## What to fix")
    out.append("")
    out.append("| Status | Priority | ID | Requirement | Effort |")
    out.append("|--------|----------|----|-------------|--------|")
    for r in open_reqs:
        dot = _DOT.get(r.get("status"), "")
        out.append(
            f"| {dot} {r.get('status')} | {r.get('priority', '—')} | {r.get('id', '')} "
            f"| {r.get('finding', '')[:60]} | {r.get('effort', '—')} |"
        )
    out.append("")

    for r in open_reqs:
        dot = _DOT.get(r.get("status"), "")
        out.append(f"### {dot} {r.get('status')} · {r.get('priority', '—')} · {r.get('id', '')}")
        out.append("")
        if r.get("finding"):
            out.append(f"{r['finding']}")
            out.append("")
        ev = r.get("evidence") or []
        if ev:
            locs = ", ".join(
                f"`{e.get('file')}{':' + str(e['line']) if e.get('line') else ''}`" for e in ev if e.get("file")
            )
            if locs:
                out.append(f"**Evidence:** {locs}")
                out.append("")
        if r.get("fix"):
            out.append(f"**Fix:** {r['fix']}")
            out.append("")
        if r.get("url"):
            out.append(f"**Reference:** {r['url']}")
            out.append("")

    out.append("---")
    out.append("*Effort: S = under 1 hour · M = about half a day · L = multi-day or architectural change.*")
    out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Render a verify-requirements verdict as Markdown.")
    p.add_argument("--verdict", required=True, help="Path to .requirements-verification.json")
    p.add_argument("--output", required=True, help="Markdown file to write")
    args = p.parse_args(argv)

    vp = Path(args.verdict)
    if not vp.exists():
        print(f"render-review: verdict not found: {vp}", file=sys.stderr)
        return 2
    try:
        verdict = json.loads(vp.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"render-review: cannot read verdict: {exc}", file=sys.stderr)
        return 2

    Path(args.output).write_text(render(verdict), encoding="utf-8")
    print(f"render-review: wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
