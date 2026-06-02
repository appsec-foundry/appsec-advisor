#!/usr/bin/env python3
"""match_abuse_cases.py — deterministic abuse-case matcher + verdict finalizer.

No LLM. Runs in Phase 10b before the abuse-case verifier agents are dispatched.

Subcommands
-----------
  match            Match each active abuse case against the merged findings.
                   Writes <output-dir>/.abuse-case-matches.json.
  list-candidates  Print the ids of cases whose structural verdict is
                   `candidate` or `partial_candidate` (one per line) — the set
                   the verifier dispatcher should spawn an agent for.
  finalize         Fold per-step verifier verdicts into a chain verdict per
                   case. Reads .abuse-case-matches.json + .abuse-case-verdicts.json,
                   writes .abuse-case-verdicts.json (enriched, in place).

Matching algorithm (per case)
-----------------------------
  * scope_qualifier — when a recon signals set is supplied, every
    `required_signals` entry must be present, else the case is `not_applicable`.
    When no signals file is given, scope is treated as satisfied (the matcher
    never produces a false negative from a missing signals source).
  * per step — `probe.sink_patterns` (regex) are matched against each finding's
    searchable text (title + scenario + cwe + component + evidence excerpt).
    The first matching finding is the step's `matched_finding_id`.
    `probe.control_patterns` matched against the finding's controls text mark a
    step as control-guarded.
  * structural verdict:
      all required steps matched  -> candidate
      no required step matched     -> not_applicable
      some required steps matched  -> partial_candidate
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

PLUGIN_ROOT = Path(__file__).resolve().parent.parent


def _rac():
    spec = importlib.util.spec_from_file_location(
        "resolve_abuse_cases", Path(__file__).resolve().parent / "resolve_abuse_cases.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Finding loading + searchable-text projection
# ---------------------------------------------------------------------------


def _finding_id(finding: dict) -> str:
    return (finding.get("f_id") or finding.get("t_id") or finding.get("id") or "").strip()


def _finding_text(finding: dict) -> str:
    """Concatenate the fields a sink/control pattern can legitimately match."""
    parts = [
        finding.get("title", ""),
        finding.get("scenario", ""),
        finding.get("cwe", ""),
        finding.get("component", ""),
        finding.get("component_id", ""),
    ]
    ev = finding.get("evidence") or {}
    if isinstance(ev, dict):
        parts += [str(ev.get("file", "")), str(ev.get("excerpt", "")), str(ev.get("snippet", ""))]
    return "\n".join(p for p in parts if p)


def _controls_text(finding: dict) -> str:
    parts = [finding.get("controls_in_place", "")]
    parts.append(str(finding.get("controls_absent_evidence", "")))
    return "\n".join(p for p in parts if p)


def load_findings(path: Path) -> list[dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(doc, dict):
        return doc.get("findings") or doc.get("threats") or []
    return doc if isinstance(doc, list) else []


def _compile(patterns: list[str]) -> list[re.Pattern]:
    out = []
    for p in patterns or []:
        try:
            out.append(re.compile(p, re.IGNORECASE))
        except re.error:
            # Treat an invalid regex as a literal substring match.
            out.append(re.compile(re.escape(p), re.IGNORECASE))
    return out


# ---------------------------------------------------------------------------
# Step + case matching
# ---------------------------------------------------------------------------


def match_step(step: dict, findings: list[dict]) -> dict:
    probe = step.get("probe") or {}
    sinks = _compile(probe.get("sink_patterns") or [])
    controls = _compile(probe.get("control_patterns") or [])

    matched_id = None
    matched_evidence = None
    controls_found: list[str] = []
    for finding in findings:
        text = _finding_text(finding)
        if any(rx.search(text) for rx in sinks):
            matched_id = _finding_id(finding)
            ev = finding.get("evidence") or {}
            matched_evidence = {
                "file": ev.get("file") if isinstance(ev, dict) else None,
                "line": ev.get("line") if isinstance(ev, dict) else None,
            }
            ctext = _controls_text(finding)
            controls_found = [rx.pattern for rx in controls if rx.search(ctext)]
            break

    return {
        "step": step.get("step"),
        "label": step.get("label"),
        "required": step.get("required", True),
        "grants": step.get("grants"),
        "requires": step.get("requires"),
        "matched": matched_id is not None,
        "matched_finding_id": matched_id,
        "evidence": matched_evidence,
        "controls_found": controls_found,
    }


def _scope_ok(case: dict, signals: set[str] | None) -> bool:
    if signals is None:
        return True  # no signals source → cannot disprove applicability
    required = (case.get("scope_qualifier") or {}).get("required_signals") or []
    return all(sig in signals for sig in required)


def match_case(case: dict, findings: list[dict], signals: set[str] | None) -> dict:
    applicable = _scope_ok(case, signals)
    step_matches = [match_step(s, findings) for s in case.get("chain") or []]
    required = [m for m in step_matches if m["required"]]
    required_hit = [m for m in required if m["matched"]]

    # Capture WHY a case is not a candidate so the §9 renderer can show the
    # generic catalog with a short relevant/not-relevant reason instead of
    # silently dropping every evaluated-but-not-applicable case.
    unmet_signals: list[str] = []
    reason: str | None = None
    if not applicable:
        req_sigs = (case.get("scope_qualifier") or {}).get("required_signals") or []
        unmet_signals = [s for s in req_sigs if signals is not None and s not in signals]
        verdict = "not_applicable"
        reason = (
            "required precondition(s) absent in this codebase: "
            + ", ".join(unmet_signals)
            if unmet_signals
            else "scope preconditions not met for this codebase"
        )
    elif required and len(required_hit) == len(required):
        verdict = "candidate"
    elif not required_hit:
        verdict = "not_applicable"
        reason = "no finding matched the required chain step(s) for this scenario"
    else:
        verdict = "partial_candidate"
        reason = "only some required chain steps have a matching finding"

    return {
        "abuse_case_id": case.get("id"),
        "title": case.get("title"),
        "source": case.get("source"),
        "applicable": applicable,
        "structural_verdict": verdict,
        "reason": reason,
        "unmet_signals": unmet_signals or None,
        "matched_finding_ids": [m["matched_finding_id"] for m in step_matches if m["matched"]],
        "step_matches": step_matches,
    }


# ---------------------------------------------------------------------------
# Chain-verdict finalisation (folds verifier step verdicts → chain verdict)
# ---------------------------------------------------------------------------

_CONFIRMED = "confirmed"
_BLOCKED = "blocked"
_INCONCLUSIVE = "inconclusive"


def finalize_verdict(case_match: dict, step_verdicts: list[dict]) -> str:
    """Compute the chain verdict from per-step verifier verdicts.

      all required steps confirmed, no controls        -> fully_viable
      >=1 required confirmed AND >=1 step has a control -> partially_blocked
      all required steps blocked                        -> mitigated
      any required step inconclusive (and not viable)   -> inconclusive
    """
    by_step = {v.get("step"): v for v in step_verdicts}
    required_steps = [s for s in case_match.get("step_matches", []) if s.get("required", True)]
    if not required_steps:
        return "not_applicable"

    verdicts = []
    any_control = False
    for s in required_steps:
        v = by_step.get(s.get("step")) or {}
        verdicts.append(v.get("verdict", _INCONCLUSIVE))
        if v.get("controls_found") or s.get("controls_found"):
            any_control = True
    # non-required steps can still contribute a control observation
    for s in case_match.get("step_matches", []):
        if not s.get("required", True):
            v = by_step.get(s.get("step")) or {}
            if v.get("controls_found") or s.get("controls_found"):
                any_control = True

    if all(v == _BLOCKED for v in verdicts):
        return "mitigated"
    if any(v == _INCONCLUSIVE for v in verdicts):
        return "inconclusive"
    confirmed = [v == _CONFIRMED for v in verdicts]
    if all(confirmed):
        return "partially_blocked" if any_control else "fully_viable"
    # mix of confirmed + blocked, none inconclusive
    if any(confirmed):
        return "partially_blocked"
    return "inconclusive"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load_signals(path: str | None) -> set[str] | None:
    if not path:
        return None
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(doc, dict):
        # accept {signal: true/false} or {signals: [...]}
        if "signals" in doc and isinstance(doc["signals"], list):
            return set(doc["signals"])
        return {k for k, v in doc.items() if v}
    if isinstance(doc, list):
        return set(doc)
    return None


def cmd_match(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir)
    findings_path = Path(args.findings) if args.findings else out_dir / ".threats-merged.json"
    findings = load_findings(findings_path)
    signals = _load_signals(args.signals)

    profile = None
    profile_dir = None
    if args.org_profile:
        rac = _rac()
        p = Path(args.org_profile)
        profile = rac._load_yaml(p)
        profile_dir = p.parent
    repo_root = Path(args.repo_root) if getattr(args, "repo_root", None) else None
    cases, errors = _rac().resolve_abuse_cases(profile, profile_dir, PLUGIN_ROOT, repo_root)
    if errors:
        for e in errors:
            sys.stderr.write(f"ERROR: {e}\n")
        return 1

    matches = [match_case(c, findings, signals) for c in cases]
    result = {"schema_version": 1, "matches": matches}
    (out_dir / ".abuse-case-matches.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    n_cand = sum(1 for m in matches if m["structural_verdict"] in ("candidate", "partial_candidate"))
    sys.stderr.write(f"MATCH: {len(matches)} cases, {n_cand} candidate(s)\n")
    return 0


def cmd_list_candidates(args: argparse.Namespace) -> int:
    matches_path = Path(args.output_dir) / ".abuse-case-matches.json"
    if not matches_path.exists():
        return 0
    doc = json.loads(matches_path.read_text(encoding="utf-8"))
    for m in doc.get("matches", []):
        if m.get("structural_verdict") in ("candidate", "partial_candidate"):
            print(m["abuse_case_id"])
    return 0


def cmd_list_inconclusive(args: argparse.Namespace) -> int:
    """Print AC-IDs whose chain verdict is `inconclusive` and that the matcher
    rated a real candidate — i.e. worth a second look by a stronger model.

    Run AFTER `finalize` (needs `chain_verdict`). Output is the escalation
    work-list for the skill's sonnet re-verify pass. Capped at `--max` so the
    escalation cost stays bounded; the cap drop is logged to stderr.
    """
    out_dir = Path(args.output_dir)
    verdicts_path = out_dir / ".abuse-case-verdicts.json"
    if not verdicts_path.exists():
        return 0
    try:
        vdoc = json.loads(verdicts_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    verdicts = vdoc.get("verdicts") if isinstance(vdoc, dict) else vdoc

    # Only escalate cases the matcher considered plausible (candidate /
    # partial_candidate) — don't spend a strong model re-checking weak matches.
    candidates: set[str] = set()
    matches_path = out_dir / ".abuse-case-matches.json"
    if matches_path.exists():
        try:
            mdoc = json.loads(matches_path.read_text(encoding="utf-8"))
            candidates = {
                m["abuse_case_id"]
                for m in mdoc.get("matches", [])
                if m.get("structural_verdict") in ("candidate", "partial_candidate")
            }
        except (OSError, json.JSONDecodeError, KeyError):
            candidates = set()

    inconclusive = sorted(
        v.get("abuse_case_id")
        for v in (verdicts or [])
        if v.get("chain_verdict") == _INCONCLUSIVE
        and v.get("abuse_case_id")
        and (not candidates or v.get("abuse_case_id") in candidates)
    )

    cap = max(0, int(getattr(args, "max", 5) or 0))
    if cap and len(inconclusive) > cap:
        sys.stderr.write(
            f"ESCALATE: {len(inconclusive)} inconclusive, capping to {cap} "
            f"(dropped: {', '.join(inconclusive[cap:])})\n"
        )
        inconclusive = inconclusive[:cap]

    for cid in inconclusive:
        print(cid)
    return 0


def cmd_finalize(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir) if args.output_dir else None
    matches_path = (
        Path(args.matches)
        if args.matches
        else (out_dir / ".abuse-case-matches.json")
    )
    verdicts_path = (
        Path(args.verdicts)
        if args.verdicts
        else (out_dir / ".abuse-case-verdicts.json")
    )
    matches = {
        m["abuse_case_id"]: m
        for m in json.loads(matches_path.read_text(encoding="utf-8")).get("matches", [])
    }
    vdoc = json.loads(verdicts_path.read_text(encoding="utf-8"))
    verdicts = vdoc.get("verdicts") if isinstance(vdoc, dict) else vdoc

    for v in verdicts:
        cid = v.get("abuse_case_id")
        case_match = matches.get(cid, {"step_matches": []})
        v["chain_verdict"] = finalize_verdict(case_match, v.get("step_verdicts") or [])

    out = {"schema_version": 1, "verdicts": verdicts}
    target = verdicts_path
    target.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic abuse-case matcher / finalizer.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("match", help="match abuse cases against findings")
    m.add_argument("--output-dir", required=True)
    m.add_argument("--findings", help="path to .threats-merged.json (default: <output-dir>/.threats-merged.json)")
    m.add_argument("--org-profile", default=None)
    m.add_argument("--repo-root", default=None, help="target repo root; loads <repo>/.appsec/abuse-cases/*.yaml")
    m.add_argument("--signals", default=None, help="recon signals json (optional)")
    m.set_defaults(func=cmd_match)

    lc = sub.add_parser("list-candidates", help="print candidate ids")
    lc.add_argument("--output-dir", required=True)
    lc.set_defaults(func=cmd_list_candidates)

    fz = sub.add_parser("finalize", help="fold step verdicts into chain verdicts")
    fz.add_argument("--output-dir", default=None)
    fz.add_argument("--matches", default=None)
    fz.add_argument("--verdicts", default=None)
    fz.set_defaults(func=cmd_finalize)

    li = sub.add_parser("list-inconclusive", help="print candidate ids whose chain verdict is inconclusive (escalation work-list)")
    li.add_argument("--output-dir", required=True)
    li.add_argument("--max", type=int, default=5, help="cap the escalation work-list (default 5; 0 = no cap)")
    li.set_defaults(func=cmd_list_inconclusive)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
