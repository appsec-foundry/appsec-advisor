#!/usr/bin/env python3
"""renderers/render_analyst_report.py — Markdown view of a validated analyst result.

Renders only a result that passes ``validate_result``. Every model-authored
string is escaped for its Markdown context: inline text cannot open links,
images, HTML, headings, or emphasis, and excerpts sit in a code fence longer
than any backtick run they contain. The report states its coverage and never
claims security approval.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import re

from validators.validate_analyst import validate_result

_INLINE_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|~>])")
ADVISORY = "Advisory analysis. It is not a security approval, and its coverage is limited to what is listed below."
RELATIONSHIP = {
    "introduced": "introduced by the change",
    "worsened": "worsened by the change",
    "mitigated": "mitigated by the change",
    "unchanged_preexisting": "pre-existing, relied on by the change",
    "unknown": "relationship to the change unknown",
}


class RenderError(Exception):
    """The result is not valid for publication."""


def inline(text: object) -> str:
    """Escape untrusted text for one Markdown line."""
    flat = " ".join(str(text).split())
    flat = flat.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _INLINE_SPECIAL.sub(r"\\\1", flat)


def code(text: str) -> str:
    """Inline code span that the content cannot terminate."""
    run = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * (run + 1)
    return f"{fence} {text} {fence}" if run else f"{fence}{text}{fence}"


def block(text: str) -> str:
    run = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, run + 1)
    return f"{fence}text\n{text.rstrip()}\n{fence}"


def _location(loc: dict) -> str:
    where = f"{loc['path']}:{loc['line_start']}" + (
        f"-{loc['line_end']}" if loc["line_end"] != loc["line_start"] else ""
    )
    return f"- {loc['side']}: {code(where)}\n\n{block(loc['excerpt'])}"


def render(result: dict) -> str:
    errors = validate_result(result)
    if errors:
        raise RenderError("; ".join(errors))
    out = [f"# Threat analysis {code(result['job_id'])}", "", f"> {ADVISORY}", ""]
    out += [
        f"- State: **{result['state']}** ({inline(result['terminal_reason'])})",
        f"- Mode: {result['mode']}",
        f"- Input fingerprint: {code(result['input_fingerprint'])}",
        "",
        "## Summary",
        "",
        inline(result["summary"]) or "No summary.",
        "",
    ]
    if result["mode"] == "hypothesis":
        out += ["## Hypothesis", "", inline(result["hypothesis"]), ""]
        out += [f"Revision: {code(result['objects'].get('head', 'unavailable'))}", ""]
        out += ["Selected paths: " + ", ".join(code(p) for p in result["scope"]["paths"]), ""]
        assessment = result.get("hypothesis_assessment")
        if assessment:
            labels = {
                "supported": "Supported by code",
                "not_confirmed": "Not confirmed in the inspected scope",
                "unresolved": "Unresolved",
            }
            out += [f"**{labels[assessment['status']]}**", "", inline(assessment["explanation"]), ""]
            out += [_location(loc) for loc in assessment["evidence"]]
            out += ["", "Next action: " + inline(assessment["next_action"]), ""]
        else:
            out += ["Unresolved: no validated conclusion is available.", ""]
        out += ["Not confirmed does not mean disproved or safe. Conclusions apply only to the inspected scope.", ""]
    if result["findings"]:
        out += ["## Findings", ""]
        for f in result["findings"]:
            out += [
                f"### {f['id']} {inline(f['title'])}",
                "",
                f"Severity: **{f['severity']}**. "
                + (
                    "Observed in the inspected revision."
                    if result["mode"] == "hypothesis"
                    else RELATIONSHIP[f["change_relationship"]] + "."
                ),
                "",
            ]
            out += [inline(f["explanation"]), "", "Evidence:", ""]
            out += [_location(loc) for loc in f["evidence"] + f.get("comparison", [])]
            out += ["", f"Next action: {inline(f['next_action'])}", ""]
            if f.get("requirement_refs"):
                out += ["Requirements: " + ", ".join(code(r) for r in f["requirement_refs"]), ""]
    if result["scenarios"]:
        out += ["## Scenarios", ""]
        for s in result["scenarios"]:
            out += [
                f"- **{s['id']} {inline(s['title'])}.** {inline(s['description'])} Next action: {inline(s['next_action'])}"
            ]
        out.append("")
    if result["assumptions"]:
        out += ["## Assumptions", ""]
        out += [f"- {a['id']} ({a['status']}): {inline(a['statement'])}" for a in result["assumptions"]]
        out.append("")
    if result["questions"]:
        out += ["## Open questions", ""]
        for q in result["questions"]:
            need = "required" if q["required"] else "optional"
            out += [
                f"- **{q['id']}** ({need}): {inline(q['asks'])} Why: {inline(q['why'])} Affects: {inline(q['affects'])}"
            ]
        out.append("")
    if result["requirement_observations"]:
        out += ["## Requirement observations", ""]
        out += [
            f"- {code(o['requirement_ref'])}: {inline(o['observation'])}" for o in result["requirement_observations"]
        ]
        out.append("")
    if result["methodology_observations"]:
        out += ["## Methodology observations", ""]
        out += [f"- {code(o['criterion_ref'])}: {inline(o['observation'])}" for o in result["methodology_observations"]]
        out.append("")
    cov = result["coverage"]
    out += ["## Coverage", "", f"- Admitted files: {cov['admitted_files']}"]
    out += [
        f"- Excluded: {e['count']} × {e['reason']}" + (f" ({code(e['path'])})" if "path" in e else "")
        for e in cov["excluded"]
    ]
    out += [
        f"- Redacted secret value: {code(e['path'])} line(s) {', '.join(str(n) for n in e['lines'])}"
        for e in cov.get("redacted", [])
    ]
    out += [f"- Source {s['kind']} ({inline(s['label'])}): {s['status']}" for s in cov["sources"]]
    out += [f"- Question not considered: {code(q['ref'])} ({inline(q['reason'])})" for q in cov["omitted_questions"]]
    out += [f"- Required coverage complete: {'yes' if cov['required_complete'] else 'no'}", ""]
    for e in cov.get("evidence_requests", []):
        out += [
            f"- Evidence {code(e['path'])}: {e['status']}. {inline(e['detail'])} Requested because: {inline(e['reason'])}"
        ]
    if cov.get("evidence_requests"):
        out.append("")
    out += ["## Packages", ""]
    out += [
        f"- {code(p['id'])} {p['version']} ({p['authority']}), source: {inline(p['provenance']['source'])}, revision {inline(p['provenance']['revision'])}"
        for p in result["packages"]
    ]
    if result["limitations"]:
        out += ["", "## Limitations", ""] + [f"- {inline(item)}" for item in result["limitations"]]
    return "\n".join(out).rstrip() + "\n"
