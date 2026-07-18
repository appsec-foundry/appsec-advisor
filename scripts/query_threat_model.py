#!/usr/bin/env python3
"""Emit a compact, LLM-friendly facts index of an existing ``threat-model.yaml``.

Powers ``/appsec-advisor:ask-threat-model`` — the free-form "ask my threat
model a question" surface. Read-only: it parses the committed semantic model
and prints a compact digest (identity, severity counts, a one-line record per
finding + weakness, and the mitigation index) that the skill loads *once* and
then answers the user's actual question against — grounded, with citations,
never invented.

Three query modes:
  * default        — the full compact digest (answer anything).
  * ``--grep TERM``  — topic filter (a vuln class, a component, a keyword).
  * ``--id ID``      — precise lookup of ONE identifier with its cross-links
                       (``F-003`` → the finding + its mitigations + parent
                       weaknesses; ``M-001`` → the fix + covered findings;
                       ``W-002`` → the weakness + its instance findings). This
                       is what catches "what is F-003?" style questions.

This is deliberately NOT ``summarize_threat_model.py`` (that renders a fixed
human overview for ``show-threat-model``). This tool exists so an LLM can answer
arbitrary questions from a small, greppable representation instead of loading
the multi-thousand-line rendered report and guessing.

Citations use the SAME id the user sees in the rendered report: findings are
``F-NNN`` (the composer maps the yaml's ``T-NNN`` → ``F-NNN`` by prefix swap —
see ``compose_threat_model.py``). The raw ``T-NNN`` is kept alongside for trace.
Mitigations are ``M-NNN``; design/implementation weaknesses are ``W-NNN``.

No LLM judgement, no network, no writes; output is byte-stable for a given
input. Severity uses the composer's ``effective_severity → risk → severity``
precedence — a read of stored values, never a re-score.

Usage:
    query_threat_model.py --output-dir PATH [--repo-root PATH]
        [--grep TERM | --id ID] [--json]

Exit codes:
    0  threat model present, facts emitted (an unknown --id is a valid, empty
       answer, not an error)
    1  no threat model found at <output-dir>/threat-model.yaml
    2  error (unreadable / unparseable YAML)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _requirements_gate import load_requirements, violated_requirements  # noqa: E402

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
_KNOWN_SEVERITIES = set(_SEVERITY_ORDER)
_SCENARIO_TRIM = 200
_ID_RE = re.compile(r"^([TFMW])-0*(\d+)$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Identifier handling
# ---------------------------------------------------------------------------


def _display_id(raw: str) -> str:
    """The id the user sees in the rendered report. The composer maps a yaml
    ``T-NNN`` to ``F-NNN`` (``"F-" + tid[2:]``). Mirror that so citations match
    what the reader has in front of them. Non ``T-`` ids pass through unchanged."""
    if len(raw) > 2 and raw[0] in "Tt" and raw[1] == "-":
        return "F-" + raw[2:]
    return raw


def _id_key(s: str) -> tuple[str, int] | None:
    """Canonical (prefix, number) key for an identifier, tolerant of casing and
    zero-padding (``f-3`` == ``F-003``). ``T-`` collapses to ``F-`` because they
    denote the same finding. Returns None when ``s`` is not an id."""
    m = _ID_RE.match(s.strip())
    if not m:
        return None
    prefix = m.group(1).upper()
    if prefix == "T":
        prefix = "F"
    return prefix, int(m.group(2))


# ---------------------------------------------------------------------------
# Field extraction (defensive — shapes vary across schema/fixture versions)
# ---------------------------------------------------------------------------


def _severity_label(node: dict) -> str:
    """Canonical severity, using the composer's precedence
    ``effective_severity → risk → severity`` (documented in
    ``build_threat_model_yaml.py``). Unknown/blank values pass through as-is."""
    return (node.get("effective_severity") or node.get("risk") or node.get("severity") or "").strip()


def _raw_id(threat: dict) -> str:
    return str(threat.get("t_id") or threat.get("id") or "").strip()


def _location(node: dict) -> str:
    """First ``file[:line]`` from the evidence list — the concrete code site.
    Empty when the finding cites no file (e.g. missing CSP, outdated dep)."""
    for ev in node.get("evidence") or []:
        if isinstance(ev, dict) and ev.get("file"):
            file = str(ev["file"]).strip()
            line = ev.get("line")
            return f"{file}:{line}" if line else file
    return ""


def _trim(text: str) -> str:
    raw = (text or "").strip().replace("\n", " ")
    if len(raw) > _SCENARIO_TRIM:
        raw = raw[: _SCENARIO_TRIM - 1].rstrip() + "…"
    return raw


def _project(data: dict) -> tuple[str, str]:
    for cand in (data.get("project"), (data.get("meta") or {}).get("project")):
        if isinstance(cand, str) and cand.strip():
            return cand.strip(), ""
        if isinstance(cand, dict):
            name = (cand.get("name") or "").strip()
            version = (cand.get("version") or "").strip()
            if name or version:
                return name, version
    return "", ""


# Curated provenance / governance scalars from `meta`, in render order. Answers
# "how / when / by what was this generated?" and "who owns it / what scope?".
# (label, field). Only scalar values that are present and non-empty surface.
_PROVENANCE_FIELDS = [
    ("Plugin", "plugin_version"),
    ("Scan mode", "mode"),
    ("Reasoning model", "reasoning_model"),
    ("STRIDE model", "stride_model"),
    ("Analyst", "analyst"),
    ("Scope", "scope"),
    ("Repo", "repo_url"),
    ("Owner", "team_owner"),
    ("Asset class", "asset_classification"),
    ("Compliance", "compliance_scope"),
    ("Requirements checked", "check_requirements"),
]


def _provenance(meta: dict) -> dict:
    """Curated scalar meta fields, keyed by field name. Booleans render as
    yes/no; lists and empty values are skipped (kept out of the answer surface)."""
    out: dict[str, str] = {}
    for _label, key in _PROVENANCE_FIELDS:
        v = meta.get(key)
        if isinstance(v, bool):
            out[key] = "yes" if v else "no"
        elif isinstance(v, str) and v.strip():
            out[key] = v.strip()
        elif isinstance(v, (int, float)):
            out[key] = str(v)
    return out


# ---------------------------------------------------------------------------
# Record builders
# ---------------------------------------------------------------------------


def _finding_record(threat: dict) -> dict:
    raw = _raw_id(threat)
    return {
        "id": _display_id(raw),
        "raw_id": raw,
        "severity": _severity_label(threat),
        "stride": (threat.get("stride") or "").strip(),
        "component": (threat.get("component") or "").strip(),
        "cwe": (threat.get("cwe") or "").strip(),
        "title": (threat.get("title") or "").strip(),
        "location": _location(threat),
        "evidence_check": (threat.get("evidence_check") or "").strip(),
        "mitigation_ids": [str(m).strip() for m in (threat.get("mitigation_ids") or []) if str(m).strip()],
        # Custom requirements this finding breaks. Filtered against the declared
        # catalog in build_facts — a raw id here may predate the current catalog.
        "violated_requirements": violated_requirements(threat),
        "scenario": _trim(threat.get("scenario") or threat.get("description") or ""),
    }


def _mitigation_record(m: dict) -> dict:
    return {
        "id": str(m.get("id") or "").strip(),
        "priority": str(m.get("priority") or "").strip().upper(),
        "title": (m.get("title") or m.get("name") or "").strip(),
        "description": _trim(m.get("description") or ""),
    }


def _weakness_record(w: dict) -> dict:
    instances = [
        _display_id(str(i.get("id")).strip()) for i in (w.get("instances") or []) if isinstance(i, dict) and i.get("id")
    ]
    return {
        "id": str(w.get("id") or "").strip(),
        "severity": _severity_label(w),
        "kind": (w.get("kind") or "").strip(),
        "weakness_class": (w.get("weakness_class") or "").strip(),
        "title": (w.get("title") or "").strip(),
        "statement": _trim(w.get("statement") or ""),
        "severity_basis": (w.get("severity_basis") or "").strip(),
        "affected_components": [str(c).strip() for c in (w.get("affected_components") or []) if str(c).strip()],
        "instances": instances,
    }


# ---------------------------------------------------------------------------
# Facts assembly
# ---------------------------------------------------------------------------


def _matches(text_fields: list[str], term: str) -> bool:
    low = term.lower()
    return any(low in (f or "").lower() for f in text_fields)


def _worst_case(findings: list[dict], critical: list, limit: int = 3) -> list[dict]:
    """The model's own "worst case if nothing changes" — its curated
    ``critical_findings`` (threat_id/summary/mitigation_id) joined to the finding
    records. This is the quick verdict. Falls back to the top severity-ranked
    findings when the model curated none. Never authors new text."""
    by_raw = {f["raw_id"]: f for f in findings}
    out: list[dict] = []
    for c in critical:
        if not isinstance(c, dict):
            continue
        f = by_raw.get(str(c.get("threat_id") or "").strip())
        if not f:
            continue
        out.append(
            {
                "id": f["id"],
                "severity": f["severity"],
                "summary": str(c.get("summary") or "").strip() or f["title"],
                "mitigation_id": str(c.get("mitigation_id") or "").strip(),
            }
        )
    if not out:  # no curated worst-case — degrade to the top findings
        out = [
            {"id": f["id"], "severity": f["severity"], "summary": f["title"], "mitigation_id": ""}
            for f in findings[:limit]
        ]
    out.sort(key=lambda w: (_SEVERITY_ORDER.get(w["severity"], 9), w["id"]))
    return out[:limit]


def build_facts(data: dict, grep: str | None = None, output_dir: Path | None = None) -> dict:
    meta = data.get("meta") or {}
    git = meta.get("git") or {}
    name, version = _project(data)

    threats = [t for t in (data.get("threats") or []) if isinstance(t, dict)]
    findings = [_finding_record(t) for t in threats]
    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9), f["id"]))

    mitigations = [_mitigation_record(m) for m in (data.get("mitigations") or []) if isinstance(m, dict)]
    mit_by_id = {m["id"]: m for m in mitigations if m["id"]}

    weaknesses = [_weakness_record(w) for w in (data.get("weaknesses") or []) if isinstance(w, dict)]
    weaknesses.sort(key=lambda w: (_SEVERITY_ORDER.get(w["severity"], 9), w["id"]))

    # Severity histogram over ALL findings (independent of any grep filter).
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    total_findings = sum(counts.values())

    # Worst-case / quick verdict is computed over ALL findings, before any grep
    # filter narrows the list — the verdict is global, not scoped to a topic.
    worst_case = _worst_case(findings, data.get("critical_findings") or [])

    if grep:
        matched_mit_ids: set[str] = set()
        kept_f = []
        for f in findings:
            fields = [
                f["id"],
                f["raw_id"],
                f["title"],
                f["scenario"],
                f["component"],
                f["stride"],
                f["cwe"],
                f["location"],
                # Without this a `--grep REQ-AUTH-01` silently returned zero
                # findings even when one violated exactly that requirement —
                # a false "no findings match", not an empty result.
                " ".join(f["violated_requirements"]),
            ]
            mit_hit = any(
                mid in mit_by_id and _matches([mit_by_id[mid]["title"], mit_by_id[mid]["description"]], grep)
                for mid in f["mitigation_ids"]
            )
            if _matches(fields, grep) or mit_hit:
                kept_f.append(f)
                matched_mit_ids.update(f["mitigation_ids"])
        findings = kept_f
        mitigations = [
            m for m in mitigations if m["id"] in matched_mit_ids or _matches([m["title"], m["description"]], grep)
        ]
        weaknesses = [
            w
            for w in weaknesses
            if _matches([w["id"], w["title"], w["statement"], w["weakness_class"], w["kind"]], grep)
        ]

    controls = [c for c in (data.get("security_controls") or []) if isinstance(c, dict)]

    # Custom requirements, when the team wired up their own catalog. Computed
    # over ALL findings (like the histogram), so a grep-narrowed read still
    # reports compliance truthfully. Only ids the catalog actually declares are
    # counted as violations — a stale id on a finding is not a live breach.
    reqs = load_requirements(output_dir, meta) if output_dir else {}
    requirements: dict = {
        "integrated": False,
        "declared": 0,
        "violated": [],
        "url_by_id": {},
        # `checked` without `integrated` means the run ran the bundled OWASP
        # baseline (or a skipped stub), NOT the team's own catalog. Silence
        # there reads as "checked, nothing violated" — a false compliance claim.
        "checked": bool(reqs.get("checked")),
        "source": reqs.get("source") or "",
    }
    # A finding may carry requirement ids from an earlier scan whose catalog is
    # no longer active. Without this filter the digest renders "violates: REQ-X"
    # with no catalog behind it — an orphaned compliance claim.
    declared: set = reqs.get("ids") or set() if reqs.get("integrated") else set()
    for f in findings:
        f["violated_requirements"] = [r for r in f["violated_requirements"] if r in declared]

    if reqs.get("integrated"):
        by_req: dict[str, list[str]] = {}
        for f in findings if not grep else [_finding_record(t) for t in threats]:
            for rid in f["violated_requirements"]:
                if rid in reqs["ids"]:
                    by_req.setdefault(rid, []).append(f["id"])
        requirements.update(
            {
                "integrated": True,
                "declared": len(reqs["ids"]),
                "violated": [{"id": rid, "findings": by_req[rid]} for rid in sorted(by_req)],
                "url_by_id": {rid: reqs["url_by_id"].get(rid, "") for rid in sorted(by_req)},
            }
        )

    return {
        "verdict": "OK",
        "project": {"name": name, "version": version},
        "scan": {
            "commit_sha": (git.get("commit_sha") or "")[:8],
            "branch": (git.get("branch") or "").strip(),
            "model": (meta.get("model") or "").strip(),
            "assessment_depth": (meta.get("assessment_depth") or "").strip(),
            "generated": (meta.get("generated") or "").strip(),
        },
        "provenance": _provenance(meta),
        "worst_case": worst_case,
        "totals": {
            "findings": total_findings,
            "by_severity": counts,
            "mitigations": len(mit_by_id),
            "weaknesses": len(data.get("weaknesses") or []),
            "controls": len(controls),
        },
        "requirements": requirements,
        "grep": grep or "",
        "matched_findings": len(findings),
        "findings": findings,
        "mitigations": mitigations,
        "weaknesses": weaknesses,
    }


# ---------------------------------------------------------------------------
# Precise identifier lookup (--id)
# ---------------------------------------------------------------------------


def lookup_id(facts: dict, wanted: str) -> dict:
    """Resolve ONE identifier against the FULL (ungrepped) facts and return a
    focused view with cross-links. ``found`` is False when nothing matches —
    a valid, useful answer ("no such finding"), never an error."""
    key = _id_key(wanted)
    result: dict = {"query": wanted, "kind": None, "found": False}
    if key is None:
        return result
    prefix, num = key

    if prefix == "F":
        f = next((x for x in facts["findings"] if _id_key(x["id"]) == key), None)
        if f:
            mits = [m for m in facts["mitigations"] if m["id"] in f["mitigation_ids"]]
            parents = [w for w in facts["weaknesses"] if any(_id_key(i) == key for i in w["instances"])]
            result.update(kind="finding", found=True, finding=f, mitigations=mits, parent_weaknesses=parents)
    elif prefix == "M":
        m = next((x for x in facts["mitigations"] if _id_key(x["id"]) == key), None)
        if m:
            covers = [f for f in facts["findings"] if any(_id_key(mid) == key for mid in f["mitigation_ids"])]
            result.update(kind="mitigation", found=True, mitigation=m, covers=covers)
    elif prefix == "W":
        w = next((x for x in facts["weaknesses"] if _id_key(x["id"]) == key), None)
        if w:
            inst = [f for f in facts["findings"] if any(_id_key(i) == _id_key(f["id"]) for i in w["instances"])]
            result.update(kind="weakness", found=True, weakness=w, instances=inst)
    return result


# ---------------------------------------------------------------------------
# Text rendering
# ---------------------------------------------------------------------------


def _severity_bits(counts: dict) -> str:
    return " · ".join(
        f"{s} {counts[s]}" for s in ("Critical", "High", "Medium", "Low", "Informational") if counts.get(s)
    )


def _finding_line(f: dict) -> list[str]:
    meta_bits = " · ".join(x for x in (f["component"], f["stride"], f["cwe"], f["evidence_check"]) if x)
    fix = ("fix: " + ", ".join(f["mitigation_ids"])) if f["mitigation_ids"] else "no proposed fix"
    head = f"  {f['id']:<7} {f['title'] or '(untitled)'}"
    if f["location"]:
        head += f"  @ {f['location']}"
    out = [head]
    violates = ("violates: " + ", ".join(f["violated_requirements"])) if f["violated_requirements"] else ""
    tail = "   ".join(x for x in (meta_bits, fix, violates) if x)
    if tail:
        out.append(f"          {tail}")
    if f["scenario"]:
        out.append(f"          Scenario: {f['scenario']}")
    return out


def render_text(facts: dict) -> str:
    proj, scan, totals = facts["project"], facts["scan"], facts["totals"]
    buf: list[str] = []

    ident = " ".join(x for x in (proj["name"], proj["version"]) if x) or "(unnamed)"
    buf.append(f"THREAT MODEL — {ident}")
    scan_bits = " · ".join(
        x
        for x in (
            (f"{scan['commit_sha']} on {scan['branch']}".strip() if scan["commit_sha"] else ""),
            scan["assessment_depth"],
            scan["model"],
            scan["generated"],
        )
        if x
    )
    if scan_bits:
        buf.append(f"Scan        {scan_bits}")
    buf.append(
        f"Findings    {totals['findings']} total"
        + (f" · {_severity_bits(totals['by_severity'])}" if totals["by_severity"] else "")
    )
    buf.append(
        f"Mitigations {totals['mitigations']} proposed · "
        f"Weaknesses {totals['weaknesses']} · Controls {totals['controls']} assessed"
    )

    reqs = facts.get("requirements") or {}
    if reqs.get("integrated"):
        viol = reqs.get("violated") or []
        buf.append("")
        buf.append(f"REQUIREMENTS — {reqs['declared']} custom requirement(s) checked in this scan")
        if not viol:
            buf.append("  No finding breaks a declared requirement.")
            buf.append("  (Not the same as 'compliant' — only checked requirements can be broken.)")
        for v in viol:
            url = (reqs.get("url_by_id") or {}).get(v["id"]) or ""
            buf.append(f"  {v['id']:<16} violated by {', '.join(v['findings'])}" + (f"  ({url})" if url else ""))
    elif reqs.get("checked"):
        # meta says the check ran, but against no custom catalog. Saying nothing
        # here would read as "checked, nothing violated".
        why = {
            "bundled-bestpractices": "the bundled OWASP best-practices baseline, not a custom catalog",
            "skipped": "a skipped stub — no requirements were loaded",
        }.get(reqs.get("source") or "", "no usable requirement catalog")
        buf.append("")
        buf.append("REQUIREMENTS — this scan verified NO custom requirements")
        buf.append(f"  The run used {why}.")
        buf.append("  Do not report compliance with any custom requirement from this model.")

    worst = facts.get("worst_case") or []
    if worst:
        buf.append("")
        buf.append("TOP RISK — worst case if nothing changes (the quick verdict)")
        for w in worst:
            fix = w["mitigation_id"] or "no proposed fix"
            buf.append(f"  {w['id']:<7} [{w['severity'] or 'Unrated'}] {w['summary']}  → {fix}")

    prov = facts.get("provenance") or {}
    if prov:
        buf.append("")
        buf.append("META (how this model was generated)")
        for label, key in _PROVENANCE_FIELDS:
            if key in prov:
                buf.append(f"  {label + ':':<22} {prov[key]}")

    if facts["grep"]:
        buf.append("")
        buf.append(f"MATCHES for '{facts['grep']}' — {facts['matched_findings']} finding(s)")

    buf.append("")
    buf.append("FINDINGS (cite these F-ids — they match the rendered report)")
    if not facts["findings"]:
        buf.append("  (none)")
    else:
        current = None
        for f in facts["findings"]:
            if f["severity"] != current:
                current = f["severity"]
                buf.append(f"[{current or 'Unrated'}]")
            buf.extend(_finding_line(f))

    if facts["weaknesses"]:
        buf.append("")
        buf.append("WEAKNESSES (design/implementation — cite these W-ids)")
        for w in facts["weaknesses"]:
            klass = " · ".join(x for x in (w["kind"], w["weakness_class"], w["severity"]) if x)
            head = f"  {w['id']:<7} {w['title'] or '(untitled)'}"
            if klass:
                head += f"   [{klass}]"
            buf.append(head)
            if w["instances"]:
                buf.append(f"          instances: {', '.join(w['instances'])}")

    if facts["mitigations"]:
        buf.append("")
        buf.append("MITIGATIONS")
        for m in sorted(facts["mitigations"], key=lambda m: (m["priority"], m["id"])):
            prio = f"{m['priority']:<3}" if m["priority"] else "   "
            buf.append(f"  {m['id']:<7} {prio} {m['title'] or '(untitled)'}")

    return "\n".join(buf) + "\n"


def render_detail(focus: dict) -> str:
    if not focus["found"]:
        key = _id_key(focus["query"])
        if key is None:
            return f"'{focus['query']}' is not a recognizable id (expected F-/T-/M-/W-NNN).\n"
        return f"No {focus['query']} in this threat model.\n"

    buf: list[str] = []
    if focus["kind"] == "finding":
        f = focus["finding"]
        buf.append(f"{f['id']} ({f['raw_id']}) — {f['severity'] or 'Unrated'}")
        buf.append(f"  {f['title'] or '(untitled)'}")
        for label, val in (
            ("Component", f["component"]),
            ("STRIDE", f["stride"]),
            ("CWE", f["cwe"]),
            ("Location", f["location"]),
            ("Evidence", f["evidence_check"]),
            ("Violates", ", ".join(f["violated_requirements"])),
        ):
            if val:
                buf.append(f"  {label}: {val}")
        if f["scenario"]:
            buf.append(f"  Scenario: {f['scenario']}")
        if focus["mitigations"]:
            buf.append("  Fix(es):")
            for m in focus["mitigations"]:
                buf.append(f"    {m['id']} [{m['priority'] or '—'}] {m['title']}")
        else:
            buf.append("  Fix(es): none proposed — needs a human decision.")
        if focus["parent_weaknesses"]:
            buf.append("  Part of weakness(es): " + ", ".join(w["id"] for w in focus["parent_weaknesses"]))
    elif focus["kind"] == "mitigation":
        m = focus["mitigation"]
        buf.append(f"{m['id']} — remediation priority {m['priority'] or '—'}")
        buf.append(f"  {m['title'] or '(untitled)'}")
        if m["description"]:
            buf.append(f"  {m['description']}")
        buf.append("  Covers: " + (", ".join(f["id"] for f in focus["covers"]) or "(no findings link to it)"))
    elif focus["kind"] == "weakness":
        w = focus["weakness"]
        klass = " · ".join(x for x in (w["kind"], w["weakness_class"], w["severity_basis"]) if x)
        buf.append(f"{w['id']} — {w['severity'] or 'Unrated'}" + (f" [{klass}]" if klass else ""))
        buf.append(f"  {w['title'] or '(untitled)'}")
        if w["statement"]:
            buf.append(f"  {w['statement']}")
        if w["affected_components"]:
            buf.append("  Affects: " + ", ".join(w["affected_components"]))
        buf.append("  Instances: " + (", ".join(f["id"] for f in focus["instances"]) or "(none)"))
    return "\n".join(buf) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="query_threat_model.py", description="Compact facts index of a threat model.")
    p.add_argument("--output-dir", required=True)
    p.add_argument("--repo-root", default=None)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--grep", default=None, help="Case-insensitive topic filter.")
    g.add_argument("--id", dest="id_query", default=None, help="Precise F-/T-/M-/W-NNN lookup.")
    p.add_argument("--json", action="store_true", help="Emit structured JSON.")
    return p.parse_args(argv)


def _emit_no_model(output_dir: Path, as_json: bool) -> None:
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

    if args.id_query:
        focus = lookup_id(build_facts(data, None, output_dir), args.id_query)
        print(
            json.dumps(focus, indent=2, sort_keys=True) if args.json else render_detail(focus),
            end="" if not args.json else "\n",
        )
        return 0

    grep = (args.grep or "").strip() or None
    facts = build_facts(data, grep, output_dir)
    print(
        json.dumps(facts, indent=2, sort_keys=True) if args.json else render_text(facts),
        end="" if not args.json else "\n",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
