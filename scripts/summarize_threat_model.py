#!/usr/bin/env python3
"""Render a human-facing overview of an existing ``threat-model.yaml``.

Powers ``/appsec-advisor:show-threat-model``. Read-only: it parses the
committed semantic model and prints a compact at-a-glance summary —
project + scan identity, the report's verdict, the "worst case if nothing
changes" scenarios, severity breakdown, remediation backlog by priority +
mitigation coverage, top-Critical findings, mitigation/control counts, and
the report path. No LLM judgement, no network, no writes; output is
byte-stable for a given input.

Everything here must be findable in ``threat-model.md``. Three rules keep
that true, because each was broken at some point:

* Findings are cited by the id the report shows (``F-NNN``), never the yaml
  ``T-NNN`` — see ``_severity_rollup.display_id``.
* Severity is the register basis (``risk``), not ``effective_severity``.
* The verdict and its worst-case scenarios are read verbatim from the
  persisted ``verdict`` block; when the model has none, the block is omitted
  rather than reconstructed.

Freshness is NOT computed here. The skill obtains the freshness verdict
from ``threat_model_health.py --json`` (which wraps
``baseline_state.py check-changes`` + ``dirty-set`` — the SAME change
detection that decides whether an incremental scan is needed) and pipes
that JSON in via ``--health-json``. Folding it here keeps the final
rendered block deterministic instead of LLM-assembled.

Usage:
    summarize_threat_model.py --output-dir PATH [--repo-root PATH]
        [--all] [--json] [--health-json PATH|-]

Flags:
    --output-dir PATH    Directory holding ``threat-model.yaml``.
    --repo-root PATH     Repo root (only used for the header path display).
    --all                List every threat grouped by severity, not just
                         the top Critical findings.
    --json               Emit the structured summary as JSON.
    --health-json PATH   Read a ``threat_model_health.py --json`` payload
                         (``-`` for stdin) and fold its freshness verdict
                         into the rendered Status line.

Exit codes:
    0  threat model present, summary rendered
    1  no threat model found at <output-dir>/threat-model.yaml
    2  error (unreadable / unparseable YAML)
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

import _severity_rollup

_SEVERITY_ORDER = _severity_rollup.SEVERITY_ORDER
_EFFECTIVENESS_ORDER = {"Missing": 0, "Weak": 1, "Partial": 2, "Adequate": 3}


# ---------------------------------------------------------------------------
# Field extraction (defensive — shapes vary across schema/fixture versions)
# ---------------------------------------------------------------------------


def _severity_label(threat: dict | None) -> str:
    """Canonical severity for a threat, on the §8 Findings Register basis
    (``risk → severity``). Deliberately NOT ``effective_severity``: that
    carries abuse-chain elevation and drives §9 and the mitigation ranking,
    not the finding inventory. Ranking the overview by it made this block
    disagree with every severity the report shows — see ``_severity_rollup``."""
    return _severity_rollup.register_severity(threat)


def _threat_title(threat: dict | None) -> str:
    if not threat:
        return ""
    title = (threat.get("title") or threat.get("name") or "").strip()
    if title:
        return title
    scenario = (threat.get("scenario") or threat.get("description") or "").strip()
    return scenario[:80].rstrip()


def _threat_id(threat: dict) -> str:
    """The id the reader can find in the report: ``F-NNN``, not the yaml
    ``T-NNN``. The composer rewrites the visible label, so a ``T-NNN``
    citation here matches nothing the reader can look up — the only visible
    ``T-`` family in the report is ``AC-T-NNN`` (abuse cases)."""
    return _severity_rollup.display_id((threat.get("t_id") or threat.get("id") or "").strip())


def _project(data: dict) -> dict:
    """Return {name, version} tolerating top-level or meta-nested project."""
    candidates = [data.get("project"), (data.get("meta") or {}).get("project")]
    name, version = "", ""
    for cand in candidates:
        if isinstance(cand, dict):
            name = name or (cand.get("name") or "").strip()
            version = version or (cand.get("version") or "").strip()
        elif isinstance(cand, str) and cand.strip():
            name = name or cand.strip()
    return {"name": name or "(unnamed project)", "version": version}


def _short_sha(sha: str) -> str:
    return (sha or "").strip()[:7]


def _severity_counts(data: dict) -> dict:
    """The report's own headline tally, keyed by canonical label.

    Delegates to the Management-Summary basis so the histogram reproduces the
    ``**Risk distribution:**`` line in ``threat-model.md`` exactly: folded
    insecure-practice sites excluded, each design-risk weakness added once."""
    raw = _severity_rollup.risk_distribution_counts(data)
    return {
        "Critical": raw["critical"],
        "High": raw["high"],
        "Medium": raw["medium"],
        "Low": raw["low"],
        "Informational": raw["info"],
    }


_PRIORITY_BANDS = ("P1", "P2", "P3")


def _backlog_by_priority(mitigations: list) -> dict:
    """Remediation backlog sized by mitigation priority — the same P1→P2→P3 spine
    the review-threat-model triage console uses, but severity-independent so it
    never contradicts the risk-based severity histogram above it."""
    counts = {p: 0 for p in _PRIORITY_BANDS}
    for m in mitigations:
        if not isinstance(m, dict):
            continue
        p = str(m.get("priority") or "").strip().upper()
        if p in counts:
            counts[p] += 1
    return counts


def _coverage(threats: list) -> dict:
    """How many findings the model proposes a mitigation for (keyed on
    ``mitigation_ids`` — the same signal review-threat-model uses). Uncovered
    findings have no proposed fix and most need a human decision."""
    with_m = sum(1 for t in threats if t.get("mitigation_ids"))
    return {"with_mitigation": with_m, "uncovered": len(threats) - with_m}


def _verdict(data: dict) -> dict | None:
    """The report's `### Verdict` block, read verbatim from ``verdict``.

    Written by the composer after a successful render (the LLM fragment it
    comes from is deleted by cleanup). Absent on models composed before the
    field existed — callers degrade rather than invent a verdict."""
    v = data.get("verdict")
    if not isinstance(v, dict) or not (v.get("opening") or "").strip():
        return None
    bullets = [
        {
            "title": str(b.get("title") or "").strip(),
            "body": str(b.get("body") or "").strip(),
            "findings": [str(f).strip() for f in (b.get("findings") or []) if str(f).strip()],
            "verified_attack_path": bool(b.get("verified_attack_path")),
        }
        for b in (v.get("bullets") or [])
        if isinstance(b, dict) and str(b.get("title") or "").strip()
    ]
    return {
        "severity": str(v.get("severity") or "").strip(),
        "opening": str(v.get("opening") or "").strip(),
        "bullets": bullets,
        "closing": str(v.get("closing") or "").strip(),
    }


def _worst_case(threats: list, mitigations: list, critical_findings: list | None, limit: int = 3) -> list:
    """Fallback "if you do nothing" list for models with no persisted verdict.

    Joins the model's ``critical_findings[]`` to severity / component /
    mitigation priority, severity-ranked and capped, and degrades to the top
    Critical/High titles when the model curated none. This is a weak
    substitute: ``critical_findings[].summary`` is frequently just a copy of
    the threat title, so the result reads as a list of weakness labels rather
    than outcomes. The real worst case is ``verdict.bullets``, which the
    renderer authors in business language; prefer it whenever present."""
    by_id = {_threat_id(t): t for t in threats if _threat_id(t)}
    mit_by_id = {str(m.get("id")).strip(): m for m in mitigations if isinstance(m, dict) and m.get("id")}
    out: list = []
    for c in critical_findings or []:
        if not isinstance(c, dict):
            continue
        tid = _severity_rollup.display_id(str(c.get("threat_id") or "").strip())
        t = by_id.get(tid)
        if not t:
            continue
        # Prefer the threat's OWN first mitigation over the curated entry's
        # denormalized copy. The auto-emitter pass relinks threats[] after the
        # builder wrote critical_findings[], so the copy can be stale (observed:
        # every entry wrong in two real models). The threat we just joined is
        # the authoritative link; the curated id is only a fallback.
        own = [str(x).strip() for x in (t.get("mitigation_ids") or []) if str(x).strip()]
        mid = own[0] if own else str(c.get("mitigation_id") or "").strip()
        m = mit_by_id.get(mid)
        out.append(
            {
                "id": tid,
                "severity": _severity_label(t),
                "component": (t.get("component") or "").strip(),
                "summary": str(c.get("summary") or "").strip() or _threat_title(t),
                "mitigation_id": str(m.get("id")).strip() if m else "",
                "priority": (str(m.get("priority") or "").strip() if m else ""),
            }
        )
    if not out:  # no curated worst-case — degrade to the top Critical/High findings
        for t in threats:
            if _SEVERITY_ORDER.get(_severity_label(t), 9) > 1:
                continue
            out.append(
                {
                    "id": _threat_id(t),
                    "severity": _severity_label(t),
                    "component": (t.get("component") or "").strip(),
                    "summary": _threat_title(t),
                    "mitigation_id": "",
                    "priority": "",
                }
            )
    out.sort(key=lambda w: (_SEVERITY_ORDER.get(w["severity"], 9), w["id"]))
    return out[:limit]


def _normalize_domain(raw: str) -> str:
    """Clean display name for a control domain — mirrors
    review_threat_model._normalize_domain so Authentication / Authorization show
    under stable canonical names (and their label variants merge) here too."""
    r = raw.strip()
    low = r.lower()
    if "authorization" in low or "access control" in low:
        return "Authorization"
    if "authentication" in low or "identity" in low:
        return "Authentication"
    return r[: -len(" Controls")].strip() if low.endswith("controls") else r


def _control_posture(controls: list) -> dict:
    """Compact control-effectiveness roll-up for the overview: overall counts,
    plus the domains whose weakest control is Missing/Weak. Read verbatim from
    security_controls[] — a rating, never a re-score. Mirrors the per-domain
    ranking in review_threat_model.build_control_posture (incl. domain naming)."""
    eff_counts: collections.Counter = collections.Counter()
    worst_by_domain: dict = {}
    for c in controls:
        if not isinstance(c, dict):
            continue
        eff = str(c.get("effectiveness") or "").strip()
        eff_counts[eff or "Unknown"] += 1
        domain = _normalize_domain(str(c.get("domain") or "").strip())
        if domain:
            rank = _EFFECTIVENESS_ORDER.get(eff, 9)
            if domain not in worst_by_domain or rank < worst_by_domain[domain]:
                worst_by_domain[domain] = rank
    weak = sorted((d for d, r in worst_by_domain.items() if r <= 1), key=lambda d: (worst_by_domain[d], d))
    return {"effectiveness_counts": dict(eff_counts), "weak_domains": weak}


def build_summary(data: dict, output_dir: Path) -> dict:
    """Reduce raw YAML to the structured summary the renderer consumes."""
    meta = data.get("meta") or {}
    git = meta.get("git") or {}
    # Listed findings come from the §8 register (every non-refuted threat) so
    # each one is a card the reader can open. The histogram above them is the
    # Management-Summary tally, which folds practice sites and adds design-risk
    # weaknesses — the render notes the delta rather than hiding findings.
    threats = _severity_rollup.register_threats(data)
    components = data.get("components") or []
    mitigations = data.get("mitigations") or []
    controls = data.get("security_controls") or []

    counts = _severity_counts(data)

    def _sort_key(t: dict) -> tuple:
        return (_SEVERITY_ORDER.get(_severity_label(t), 9), _threat_id(t))

    threats_sorted = sorted(threats, key=_sort_key)
    criticals = [t for t in threats_sorted if _severity_label(t) == "Critical"]

    proj = _project(data)
    return {
        "project": proj,
        "scan": {
            "generated": meta.get("generated", ""),
            "commit_sha": _short_sha(git.get("commit_sha", "")),
            "branch": git.get("branch", ""),
            "model": meta.get("model", ""),
            "assessment_depth": meta.get("assessment_depth", ""),
            "mode": meta.get("mode", ""),
        },
        "totals": {
            "threats": len(threats),
            "components": len(components),
            "mitigations": len(mitigations),
            "controls": len(controls),
        },
        "severity_counts": counts,
        "verdict": _verdict(data),
        "backlog": _backlog_by_priority(mitigations),
        "coverage": _coverage(threats),
        "control_posture": _control_posture(controls),
        "worst_case": _worst_case(threats, mitigations, data.get("critical_findings")),
        "criticals": [
            {
                "id": _threat_id(t),
                "title": _threat_title(t),
                "component": (t.get("component") or "").strip(),
                "vektor": (t.get("vektor") or "").strip(),
            }
            for t in criticals
        ],
        "threats_by_severity": [
            {
                "id": _threat_id(t),
                "title": _threat_title(t),
                "severity": _severity_label(t),
                "component": (t.get("component") or "").strip(),
                "vektor": (t.get("vektor") or "").strip(),
            }
            for t in threats_sorted
        ],
        "report": str(output_dir / "threat-model.md"),
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_VERDICT_ICON = {"FRESH": "✓", "STALE": "⚠", "NO_MODEL": "✗", "UNKNOWN": "?"}
_RECOMMEND_TEXT = {
    "noop": "no re-scan needed — model is up to date",
    "incremental": "next /appsec-advisor:create-threat-model runs incremental",
    "full": "re-scan recommended: /appsec-advisor:create-threat-model --full",
    "rebuild": "rebuild recommended: /appsec-advisor:create-threat-model --rebuild",
    "none": "",
}

# This overview is the FIXED fact set. Any question needing an arbitrary subset
# of the model (a specific finding, "does it cover X?", what to fix first) is
# ask-threat-model's job. Skill routing between the two is description-based and
# will never be perfect, so the overview names the other lane itself — a
# deterministic, zero-cost correction when the router lands here by mistake.
_NEXT_STEP_LINES = [
    "Ask        a question about a specific finding, coverage, or what to fix first",
    "           → /appsec-advisor:ask-threat-model",
    "Act        on the findings → /appsec-advisor:review-threat-model",
]

# Posture flag of the report's `### Verdict`, in the report's own colours.
_POSTURE_ICON = {"red": "🔴", "yellow": "🟡", "green": "🟢"}
_POSTURE_LABEL = {
    "red": "not production-ready",
    "yellow": "acceptable with caveats",
    "green": "production-ready",
}

_WRAP_WIDTH = 92
_INDENT = " " * 11


def _wrap(text: str, indent: str = _INDENT, width: int = _WRAP_WIDTH) -> list[str]:
    """Wrap prose to the block's text column. Verbatim content, never edited —
    only line-broken so a terminal reader sees the whole sentence."""
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        candidate = f"{cur} {w}".strip()
        if cur and len(indent) + len(candidate) > width:
            lines.append(indent + cur)
            cur = w
        else:
            cur = candidate
    if cur:
        lines.append(indent + cur)
    return lines


def _render_verdict_block(verdict: dict | None) -> list[str]:
    """The report's own conclusion, printed verbatim.

    This is the sentence the Management Summary leads with and the one a
    product owner acts on. Omitted entirely — never substituted — when the
    model carries no verdict (composed before the field existed)."""
    if not verdict:
        return []
    sev = (verdict.get("severity") or "").strip().lower()
    icon = _POSTURE_ICON.get(sev, "•")
    label = _POSTURE_LABEL.get(sev, "")
    head = f"Verdict    {icon} {label}" if label else f"Verdict    {icon}"
    out = [head]
    out.extend(_wrap(verdict["opening"]))
    if verdict.get("closing"):
        out.append("")
        out.extend(_wrap(verdict["closing"]))
    out.append("")
    return out


def _render_worst_case_block(summary: dict) -> list[str]:
    """Worst-case scenarios — the verdict's own bullets when the model carries
    them, otherwise the weaker ``critical_findings[]`` fallback."""
    verdict = summary.get("verdict") or {}
    bullets = verdict.get("bullets") or []
    if bullets:
        out = ["Worst case if nothing changes"]
        for b in bullets:
            head = f"  ⚠ {b['title']}"
            if b.get("verified_attack_path"):
                head += "   ✓ verified attack path"
            out.append(head)
            out.extend(_wrap(b["body"], indent=" " * 6))
            if b.get("findings"):
                out.append(" " * 6 + " · ".join(b["findings"]))
        out.append("")
        return out

    worst = summary.get("worst_case") or []
    if not worst:
        return []
    out = ["Worst case if nothing changes"]
    for w in worst:
        line = f"  ⚠ {w['id']:<7} {w['severity']} · {w['component']} · {w['summary']}"
        if w["mitigation_id"]:
            tail = f"{w['mitigation_id']} ({w['priority']})" if w["priority"] else w["mitigation_id"]
            line += f"   → {tail}"
        out.append(line)
    out.append("")
    return out


def _bar(count: int, peak: int, width: int = 24) -> str:
    if peak <= 0 or count <= 0:
        return ""
    filled = max(1, round(count / peak * width))
    return "█" * filled


def render_status_line(freshness: dict) -> list[str]:
    verdict = (freshness.get("verdict") or "UNKNOWN").strip()
    icon = _VERDICT_ICON.get(verdict, "?")
    reason = (freshness.get("reason") or "").strip()
    head = f"Status     {icon} {verdict}"
    if reason:
        head += f" — {reason}"
    out = [head]
    rec = _RECOMMEND_TEXT.get((freshness.get("recommend") or "none").strip(), "")
    if rec:
        out.append(f"           {rec}")
    return out


def render_text(summary: dict, freshness: dict | None, show_all: bool) -> str:
    proj = summary["project"]
    scan = summary["scan"]
    totals = summary["totals"]
    counts = summary["severity_counts"]
    buf: list[str] = []

    name = proj["name"]
    if proj["version"]:
        name += f" ({proj['version']})"
    buf.append(f"Threat Model — {name}")

    # Scan identity line — only non-empty fields.
    bits = []
    if scan["generated"]:
        bits.append(scan["generated"][:10])
    if scan["commit_sha"]:
        sha = f"commit {scan['commit_sha']}"
        if scan["branch"]:
            sha += f" ({scan['branch']})"
        bits.append(sha)
    if scan["model"]:
        bits.append(f"model {scan['model']}")
    if scan["assessment_depth"]:
        depth = f"depth {scan['assessment_depth']}"
        if scan["mode"]:
            depth += f" ({scan['mode']})"
        bits.append(depth)
    if bits:
        buf.append("Scanned    " + " · ".join(bits))
    buf.append("")

    if freshness is not None:
        buf.extend(render_status_line(freshness))
        buf.append("")

    # The lane pointers sit here, not at the foot of the block: this overview is
    # a FIXED fact set, and a reader whose actual question it cannot answer needs
    # to know that before scrolling 40 lines of numbers.
    buf.extend(_NEXT_STEP_LINES)
    buf.append("")

    buf.extend(_render_verdict_block(summary.get("verdict")))
    buf.extend(_render_worst_case_block(summary))

    # The report's headline tally. It can differ from the number of cards in §8
    # (practice sites fold into the weakness register, design-risk weaknesses
    # are added once); say so instead of letting the reader find the gap.
    total_findings = sum(counts.values())
    buf.append(f"Findings   {total_findings} findings across {totals['components']} components")
    if totals["threats"] != total_findings:
        buf.append(
            f"           §8 register lists {totals['threats']}"
            " — the headline folds practice sites into the weakness register"
        )
    if total_findings == 0 and totals["threats"] == 0:
        buf.append("           no findings recorded — run /appsec-advisor:create-threat-model to (re)scan")
        buf.append("")
        buf.append(f"Report     {summary['report']}")
        return "\n".join(buf) + "\n"
    peak = max(counts.values()) if counts else 0
    for sev in ("Critical", "High", "Medium", "Low", "Informational"):
        n = counts.get(sev, 0)
        if sev == "Informational" and n == 0:
            continue
        buf.append(f"  {sev:<13} {n:>3}   {_bar(n, peak)}")
    buf.append("")

    if show_all:
        for sev in ("Critical", "High", "Medium", "Low", "Informational"):
            group = [t for t in summary["threats_by_severity"] if t["severity"] == sev]
            if not group:
                continue
            buf.append(f"{sev} ({len(group)})")
            for t in group:
                buf.append(_threat_row(t))
            buf.append("")
    else:
        crit = summary["criticals"]
        if crit:
            buf.append(f"Top Critical ({len(crit)})")
            for t in crit:
                buf.append(_threat_row(t))
            buf.append("")

    buf.append(f"Mitigations {totals['mitigations']} defined · Controls {totals['controls']} in place")
    backlog = summary.get("backlog") or {}
    if sum(backlog.values()):
        bands = " · ".join(f"{backlog[p]}× {p}" for p in ("P1", "P2", "P3") if backlog.get(p))
        buf.append(f"Backlog    {bands}")
    cov = summary.get("coverage") or {}
    if totals["threats"]:
        buf.append(
            f"Coverage   {cov.get('with_mitigation', 0)}/{totals['threats']} findings have a mitigation"
            f" · {cov.get('uncovered', 0)} without"
        )
    posture = summary.get("control_posture") or {}
    ec = posture.get("effectiveness_counts") or {}
    if ec:
        bits = " · ".join(f"{k} {ec[k]}" for k in ("Missing", "Weak", "Partial", "Adequate") if ec.get(k))
        if bits:
            buf.append(f"Controls   {sum(ec.values())} assessed · {bits}")
        weak = posture.get("weak_domains") or []
        if weak:
            buf.append(f"Weakest    {' · '.join(weak[:4])}")
    buf.append(f"Report     {summary['report']}")
    return "\n".join(buf) + "\n"


def _threat_row(t: dict) -> str:
    tid = t.get("id", "")
    title = t.get("title", "")
    comp = t.get("component", "")
    vektor = t.get("vektor", "")
    row = f"  {tid:<7} {title}"
    tail = "   ".join(x for x in (comp, vektor) if x)
    if tail:
        row += f"   [{tail}]"
    return row


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load_health(arg: str | None) -> dict | None:
    """Return the ``freshness`` sub-object from a health --json payload."""
    if not arg:
        return None
    try:
        raw = sys.stdin.read() if arg == "-" else Path(arg).read_text(encoding="utf-8")
        payload = json.loads(raw) if raw.strip() else {}
    except (OSError, json.JSONDecodeError):
        return None
    fresh = payload.get("freshness")
    return fresh if isinstance(fresh, dict) else None


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="summarize_threat_model.py", description=__doc__)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--repo-root", default=None)
    p.add_argument("--all", action="store_true", help="List every threat grouped by severity.")
    p.add_argument("--json", action="store_true", help="Emit structured JSON.")
    p.add_argument("--health-json", default=None, help="health --json payload path, or '-' for stdin.")
    return p.parse_args(argv)


def _emit_no_model(output_dir: Path, as_json: bool) -> None:
    """Uniform 'no usable model' response — used for a missing file and for a
    present-but-empty one (an empty YAML is not a usable model). Points the user
    at create-threat-model rather than showing an empty overview."""
    if as_json:
        print(json.dumps({"verdict": "NO_MODEL", "output_dir": str(output_dir)}, indent=2, sort_keys=True))
    else:
        print(f"No threat model found at {output_dir / 'threat-model.yaml'}.")
        print("Run /appsec-advisor:create-threat-model to generate one.")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    output_dir = Path(args.output_dir).resolve()
    yaml_path = output_dir / "threat-model.yaml"

    if not yaml_path.is_file():
        _emit_no_model(output_dir, args.json)
        return 1

    try:
        import yaml as _yaml

        data = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — surface any parse failure as exit 2
        print(f"Error: could not parse {yaml_path}: {exc}", file=sys.stderr)
        return 2
    if data is None:  # present but empty file — no usable model, treat as missing
        _emit_no_model(output_dir, args.json)
        return 1
    if not isinstance(data, dict):
        print(f"Error: {yaml_path} is not a mapping.", file=sys.stderr)
        return 2

    summary = build_summary(data, output_dir)
    freshness = _load_health(args.health_json)

    if args.json:
        payload = dict(summary)
        if freshness is not None:
            payload["freshness"] = freshness
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_text(summary, freshness, args.all), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
