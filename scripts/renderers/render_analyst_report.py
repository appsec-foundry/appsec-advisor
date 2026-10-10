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


MODE_TITLE = {"design": "design analysis", "review": "change review", "hypothesis": "hypothesis check"}
CONCLUSION = {
    "supported": ("SUPPORTED", "the checked files contain code that supports the threat."),
    "not_confirmed": (
        "NOT CONFIRMED",
        "the checked files do not show the threat; files outside them were not read. This is not a safe result.",
    ),
    "unresolved": (
        "NOT SETTLED",
        "the checked files cannot decide it; see what is still open. This is not a safe result.",
    ),
}
_ABUSE_CASE_LINE = re.compile(r"^Abuse case ([A-Z][A-Z0-9-]{1,40}) \(")
STATE = {
    "complete": "Analysis complete",
    "incomplete": "Analysis incomplete",
    "failed": "Analysis failed",
    "awaiting_answers": "Waiting for your answers",
    "cancelled": "Analysis cancelled",
    "rejected": "Request rejected",
}
SIDE = {"baseline": "before the change", "proposed": "after the change"}
NOT_SAFE = "Not confirmed does not mean disproved or safe. Conclusions apply only to the inspected scope."


def _where(loc: dict) -> str:
    return f"{loc['path']}:{loc['line_start']}" + (
        f"-{loc['line_end']}" if loc["line_end"] != loc["line_start"] else ""
    )


def _location(loc: dict, mode: str) -> str:
    side = f" ({SIDE[loc['side']]})" if mode == "review" else ""
    return f"- {code(_where(loc))}{side}\n\n{block(loc['excerpt'])}"


def _lines(spans: list[tuple[int, int]]) -> str:
    return ", ".join(str(a) if a == b else f"{a}-{b}" for a, b in sorted(set(spans)))


def _file_overview(result: dict) -> list[str]:
    """One line per file: where the result cites it, or that nothing in it was cited."""
    cited: dict[str, dict] = {}

    def note(loc: dict, label: str) -> None:
        entry = cited.setdefault(loc["path"], {"spans": [], "labels": []})
        entry["spans"].append((loc["line_start"], loc["line_end"]))
        if label not in entry["labels"]:
            entry["labels"].append(label)

    assessment = result.get("hypothesis_assessment") or {}
    for loc in assessment.get("evidence", []):
        note(loc, "conclusion")
    for step in assessment.get("steps") or []:
        for loc in step["evidence"]:
            note(loc, f"step {step['step']}")
    for f in result["findings"]:
        for loc in f["evidence"] + f.get("comparison", []):
            note(loc, f["id"])
    cov = result["coverage"]
    redacted = {e["path"]: e["lines"] for e in cov.get("redacted", [])}
    out = []
    for path in sorted(cited):
        entry = cited[path]
        line = f"- {code(path)} — cited at line {_lines(entry['spans'])} ({', '.join(entry['labels'])})"
        if path in redacted:
            line += f"; secret value redacted at line {_lines([(n, n) for n in redacted[path]])}"
        out.append(line)
    selected = result["scope"].get("paths", []) if result["mode"] == "hypothesis" else []
    for path in selected:
        if path in cited:
            continue
        inside = [c for c in cited if c.startswith(path + "/")]
        if inside:
            out.append(f"- {code(path + '/')} — no other file in it is cited")
        else:
            out.append(f"- {code(path)} — read; nothing in it is cited for this question")
    for path, lines in sorted(redacted.items()):
        if path not in cited:
            out.append(f"- {code(path)} — read; secret value redacted at line {_lines([(n, n) for n in lines])}")
    for e in cov["excluded"]:
        out.append(
            f"- Not read: {e['count']} × {e['reason'].replace('_', ' ')}"
            + (f" ({code(e['path'])})" if "path" in e else "")
        )
    return out


def _step_titles(hypothesis: str) -> dict[int, str]:
    """Step number -> its short title, from the ``- Step N: Title. Detail`` lines."""
    titles = {}
    for match in re.finditer(r"^- Step (\d+): (.+)$", hypothesis, re.M):
        titles[int(match.group(1))] = match.group(2).split(". ")[0].rstrip(".")
    return titles


def _source(result: dict, kind: str) -> str:
    found = [s for s in result["coverage"]["sources"] if s["kind"] == kind]
    return found[0]["status"] if found else "not used"


def render(result: dict) -> str:
    errors = validate_result(result)
    if errors:
        raise RenderError("; ".join(errors))
    mode = result["mode"]
    assessment = result.get("hypothesis_assessment")
    out = [f"# Threat analysis: {MODE_TITLE[mode]}", ""]
    if mode == "hypothesis":
        label, meaning = CONCLUSION[assessment["status"]] if assessment else CONCLUSION["unresolved"]
    else:
        count = len(result["findings"])
        label = f"{count} FINDING" + ("" if count == 1 else "S")
        meaning = "each finding cites the code it is based on."
    out += [f"**RESULT: {label}** — {meaning}", ""]
    settled_open = bool(assessment) and assessment["status"] == "unresolved"
    if result["state"] != "complete" and not settled_open:
        out += [
            f"{STATE.get(result['state'], result['state'])}: {inline(result['terminal_reason'].replace('_', ' '))}.",
            "",
        ]
    out += [inline(result["summary"]) or "No summary.", "", f"> {ADVISORY}", ""]

    out += ["## What it checks" if mode == "hypothesis" else "## What was checked", ""]
    if mode == "hypothesis":
        out += [
            f"- {inline(line.strip().removeprefix('- '))}"
            for line in str(result["hypothesis"]).splitlines()
            if line.strip()
        ]
        out += [f"- Revision: {code(result['objects'].get('head', 'unavailable'))}"]
    out += [f"- Threat model: {_source(result, 'threat_model')}"]
    out += [f"- Requirements: {_source(result, 'requirements')}", ""]

    files = _file_overview(result)
    if files:
        out += ["## Where", ""] + files + [""]

    if mode == "hypothesis":
        steps = sorted((assessment or {}).get("steps") or [], key=lambda st: st["step"])
        if steps:
            titles = _step_titles(str(result["hypothesis"]))
            out += ["## Steps", "", "| # | Result | Step | Where | Note |", "|---|---|---|---|---|"]
            for st in steps:
                where = ", ".join(code(_where(loc)) for loc in st["evidence"]) or "no code cited"
                out.append(
                    f"| {st['step']} | {CONCLUSION[st['status']][0]} | {inline(titles.get(st['step'], ''))} "
                    f"| {where} | {inline(st['note'])} |"
                )
            out.append("")
        out += ["## Why", ""]
        if assessment:
            out += [inline(assessment["explanation"]), ""]
            out += [_location(loc, mode) for loc in assessment["evidence"]]
            out += ["", f"Next step: {inline(assessment['next_action'])}", ""]
        else:
            out += ["Unresolved: no validated conclusion is available.", ""]
        out += [NOT_SAFE, ""]

    if result["findings"]:
        out += ["## Findings", ""]
        for f in result["findings"]:
            where = (
                "observed in the inspected revision" if mode == "hypothesis" else RELATIONSHIP[f["change_relationship"]]
            )
            out += [f"### {f['id']} {inline(f['title'])}", "", f"Severity: **{f['severity']}**, {where}.", ""]
            out += [inline(f["explanation"]), ""]
            out += [_location(loc, mode) for loc in f["evidence"] + f.get("comparison", [])]
            out += ["", f"Fix: {inline(f['next_action'])}", ""]
            if f.get("requirement_refs"):
                out += ["Requirements: " + ", ".join(code(r) for r in f["requirement_refs"]), ""]

    cov = result["coverage"]
    still_open = [f"- {inline(a['statement'])}" for a in result["assumptions"] if a["status"] == "unresolved"]
    still_open += [f"- {inline(item)}" for item in result["limitations"]]
    still_open += [
        f"- Requested file {code(e['path'])} was {e['status'].replace('_', ' ')}: {inline(e['detail'])} "
        f"Requested because: {inline(e['reason'])}"
        for e in cov.get("evidence_requests", [])
        if e["status"] != "admitted"
    ]
    if result["questions"]:
        for q in result["questions"]:
            need = "required" if q["required"] else "optional"
            still_open += [
                f"- **{q['id']}** ({need}): {inline(q['asks'])} Why: {inline(q['why'])} Affects: {inline(q['affects'])}"
            ]
    if still_open:
        out += ["## Still open", ""] + still_open + [""]

    if mode == "hypothesis":
        cases = [m.group(1) for line in str(result["hypothesis"]).splitlines() if (m := _ABUSE_CASE_LINE.match(line))]
        nxt = ["- Read more files: run the check again with `--path <file or directory>`."]
        for cid in cases:
            nxt.append(f"- Result of a full run: {code('/appsec-advisor:abuse-cases ' + cid)}")
        if _source(result, "threat_model") != "delivered":
            nxt.append(f"- Use earlier findings as context: {code('/appsec-advisor:create-threat-model')}")
        out += ["## Next", ""] + nxt + [""]

    background = [
        f"- Scenario {s['id']}, {inline(s['title'])}: {inline(s['description'])} Next step: {inline(s['next_action'])}"
        for s in result["scenarios"]
    ]
    background += [
        f"- Assumption {a['id']} ({a['status']}): {inline(a['statement'])}"
        for a in result["assumptions"]
        if a["status"] != "unresolved"
    ]
    background += [
        f"- Requirement {code(o['requirement_ref'])}: {inline(o['observation'])}"
        for o in result["requirement_observations"]
    ]
    background += [
        f"- Criterion {code(o['criterion_ref'])}: {inline(o['observation'])}"
        for o in result["methodology_observations"]
    ]
    if background:
        out += ["## Background", ""] + background + [""]

    out += ["## Technical details", ""]
    out += [
        f"- Job: {code(result['job_id'])}",
        f"- State: {result['state']} ({inline(result['terminal_reason'])})",
        f"- Input fingerprint: {code(result['input_fingerprint'])}",
        f"- Admitted files: {cov['admitted_files']}",
        f"- Required coverage complete: {'yes' if cov['required_complete'] else 'no'}",
    ]
    out += [f"- Source {s['kind']} ({inline(s['label'])}): {s['status']}" for s in cov["sources"]]
    out += [f"- Question not considered: {code(q['ref'])} ({inline(q['reason'])})" for q in cov["omitted_questions"]]
    out += [
        f"- Evidence {code(e['path'])}: {e['status']}. {inline(e['detail'])}"
        for e in cov.get("evidence_requests", [])
        if e["status"] == "admitted"
    ]
    out += [
        f"- Package {code(p['id'])} {p['version']} ({p['authority']}), source: {inline(p['provenance']['source'])}, revision {inline(p['provenance']['revision'])}"
        for p in result["packages"]
    ]
    return "\n".join(out).rstrip() + "\n"
