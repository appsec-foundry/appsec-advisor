#!/usr/bin/env python3
"""render_abuse_cases.py — deterministic §9 Abuse Cases fragment renderer.

Reads the verified abuse-case verdicts (`.abuse-case-verdicts.json`, produced
by the verifier fan-out + `match_abuse_cases.py finalize`), the abuse-case
definitions (standard library + org profile), and `threat-model.yaml` (for
finding titles/severities and mitigation metadata), and writes:

  * `<output-dir>/.fragments/abuse-cases.md`   — inlined verbatim by compose
  * `<output-dir>/.fragments/abuse-cases.json` — machine-readable sidecar

The composer's `_render_abuse_cases` handler inlines the `.md`; when this
script writes nothing (no applicable case), the composer emits its placeholder
line so §8 → §10 numbering stays contiguous.

Nothing here is rated by an LLM: the chain verdict and per-step status icons
are derived deterministically from the verifier's step verdicts, which makes
§9 auditable and diff-stable between runs.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import yaml

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
HEADING = "## 9. Abuse Cases"

# Chain verdict → (icon, label) for the summary table + per-case header.
_CHAIN_VERDICT = {
    "fully_viable": ("⚠", "Fully viable"),
    "partially_blocked": ("◐", "Partially blocked"),
    "mitigated": ("✓", "Mitigated"),
    "inconclusive": ("?", "Inconclusive"),
}

# Combined-risk level → emoji.
_RISK_EMOJI = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Informational": "⚪"}
_SEV_ORDER = ["Low", "Medium", "High", "Critical"]

# initial_access enum → report prose.
_ACCESS_PROSE = {
    "unauthenticated": "unauthenticated external attacker",
    "authenticated_low_priv": "authenticated low-privilege user",
    "authenticated_high_priv": "authenticated high-privilege user",
    "physical": "attacker with physical access",
}


def _rac():
    spec = importlib.util.spec_from_file_location(
        "resolve_abuse_cases", Path(__file__).resolve().parent / "resolve_abuse_cases.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# threat-model.yaml projections
# ---------------------------------------------------------------------------


def _norm_fid(raw: str | None) -> str:
    """Normalise a finding id to the report's visible F-NNN form (dual-anchored
    with t-NNN in §8, so either anchor resolves; F is the canonical label)."""
    if not raw:
        return ""
    rid = raw.strip().upper()
    if rid.startswith("T-"):
        return "F-" + rid[2:]
    return rid


def _anchor(fid: str) -> str:
    return "#" + fid.lower()


def _findings_index(tm: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for t in tm.get("threats") or tm.get("findings") or []:
        for key in (t.get("f_id"), t.get("t_id"), t.get("id")):
            if key:
                out[_norm_fid(key)] = t
    return out


def _mitigations_index(tm: dict) -> list[dict]:
    return tm.get("mitigations") or []


def _severity(finding: dict) -> str:
    sev = (finding.get("risk") or finding.get("severity") or "").strip().capitalize()
    return sev if sev in _SEV_ORDER else ""


def _combined_risk(matched: list[dict], chain_verdict: str) -> str:
    """Highest matched-finding severity, escalated one notch when the chain is
    fully viable (the whole point of an abuse case: the chain exceeds the
    individual ratings)."""
    sevs = [s for s in (_severity(f) for f in matched) if s]
    if not sevs:
        base = "High"
    else:
        base = max(sevs, key=lambda s: _SEV_ORDER.index(s))
    if chain_verdict == "fully_viable":
        idx = min(_SEV_ORDER.index(base) + 1, len(_SEV_ORDER) - 1)
        return _SEV_ORDER[idx]
    return base


def _step_status_icon(verdict: str, controls_found: list) -> str:
    if verdict == "blocked":
        return "✓"
    if verdict == "confirmed":
        return "◐" if controls_found else "⚠"
    return "?"  # inconclusive / unknown


# ---------------------------------------------------------------------------
# Per-case rendering
# ---------------------------------------------------------------------------


def _actor_label(case: dict) -> str:
    attacker = case.get("attacker") or {}
    aid = attacker.get("actor_id", "attacker")
    prose = _ACCESS_PROSE.get(attacker.get("initial_access", ""), "")
    return f"{aid} — {prose}" if prose else aid


def _blocking_mitigations(matched_ids: list[str], step_of_fid: dict[str, int], mitigations: list[dict]) -> list[dict]:
    out = []
    matched_set = set(matched_ids)
    for m in mitigations:
        # §10 Mitigation Register keys anchors off `m_id` (falling back to `id`);
        # mirror that exactly so blocking-mitigation links resolve to #m-nnn.
        mid = (m.get("m_id") or m.get("id") or "").upper()
        addressed = [
            _norm_fid(x)
            for x in (m.get("finding_ids") or m.get("threat_ids") or m.get("addresses") or [])
        ]
        hit = [a for a in addressed if a in matched_set]
        if not hit:
            continue
        breaks_at = min((step_of_fid.get(a, 99) for a in hit), default=99)
        out.append(
            {
                "id": mid,
                "title": m.get("title", ""),
                "priority": m.get("priority", ""),
                "addresses": hit,
                "breaks_at_step": breaks_at,
            }
        )
    out.sort(key=lambda x: (x["breaks_at_step"], x["id"]))
    return out


def render_case(case: dict, verdict: dict, findings_idx: dict, mitigations: list[dict],
                match_steps: dict | None = None) -> dict:
    """Build the structured render model for one abuse case (used for both the
    markdown block and the JSON sidecar).

    Finding links are sourced with a fallback chain: the verifier's per-step
    ``matched_finding_id`` (authoritative — it confirmed the step against the
    code) FALLS BACK to the deterministic matcher's ``step_matches`` from
    ``.abuse-case-matches.json``. The matcher always binds a finding to every
    matched step (that is how the case became a candidate in the first place),
    so even when a verifier sub-agent was cut off and wrote no verdict file,
    the chain still renders its real findings instead of "_no matching
    finding_". This keeps abuse cases provably *derived from findings*, and the
    per-step status icon stays honest ("?" when unverified, ⚠/◐/✓ once a
    verifier verdict exists). RC-2026-06.
    """
    cid = case["id"]
    chain_verdict = verdict.get("chain_verdict", "inconclusive")
    sv_by_step = {s.get("step"): s for s in verdict.get("step_verdicts") or []}
    match_steps = match_steps or {}

    rows = []
    matched_findings: list[dict] = []
    step_of_fid: dict[str, int] = {}
    for step in case.get("chain") or []:
        n = step.get("step")
        sv = sv_by_step.get(n, {})
        mm = match_steps.get(n, {})
        # Verifier finding id is authoritative; fall back to the matcher's
        # deterministic binding so an unfinished verifier never erases the link.
        fid = _norm_fid(sv.get("matched_finding_id") or mm.get("matched_finding_id"))
        finding = findings_idx.get(fid, {})
        if finding:
            matched_findings.append(finding)
            step_of_fid.setdefault(fid, n)
        ev = sv.get("evidence") or mm.get("evidence") or {}
        loc = ""
        if ev.get("file"):
            loc = f"{ev['file']}:{ev['line']}" if ev.get("line") else str(ev["file"])
        rows.append(
            {
                "step": n,
                "fid": fid,
                "finding_title": finding.get("title", ""),
                "finding_sev": _severity(finding),
                "evidence": loc,
                "outcome": step.get("description") or step.get("grants") or "",
                "status_icon": _step_status_icon(sv.get("verdict", ""), sv.get("controls_found") or []),
            }
        )

    matched_ids = [r["fid"] for r in rows if r["fid"]]
    combined = _combined_risk(matched_findings, chain_verdict)
    blocking = _blocking_mitigations(matched_ids, step_of_fid, mitigations)

    return {
        "id": cid,
        "title": case.get("title", ""),
        "source": case.get("source", "discovered"),
        "actor_label": _actor_label(case),
        "goal": case.get("goal", ""),
        "prerequisite": (case.get("attacker") or {}).get("prerequisite", ""),
        "combined_risk": combined,
        "chain_verdict": chain_verdict,
        "rows": rows,
        "matched_finding_ids": matched_ids,
        "combined_risk_rationale": case.get("combined_risk_rationale", ""),
        "blocking_mitigations": blocking,
    }


def _case_markdown(m: dict) -> str:
    icon, label = _CHAIN_VERDICT.get(m["chain_verdict"], ("?", "Inconclusive"))
    risk_emoji = _RISK_EMOJI.get(m["combined_risk"], "")
    src = "mandatory" if m["source"] == "mandatory" else "analysis-discovered"
    cid = m["id"]
    out: list[str] = []
    out.append(f'### <a id="{cid.lower()}"></a>{cid} — {m["title"]}')
    out.append("")
    out.append(
        f"> **Source:** {src} · **Actor:** {m['actor_label']} · "
        f"**Combined Risk:** {risk_emoji} {m['combined_risk']} · "
        f"**Verdict:** {icon} {label}"
    )
    out.append("")
    out.append(f"**Goal:** {m['goal']}")
    out.append("")
    if m["prerequisite"]:
        out.append(f"**Prerequisite:** {m['prerequisite']}")
        out.append("")
    out.append("**Attack chain**")
    out.append("")
    # Evidence is folded into the Finding cell on its own `<br/>` line (keeps
    # the table to three columns so the Finding column is not crushed by a
    # wide path column); the per-step Status icon is dropped — the overall
    # chain Verdict in the header block conveys the outcome (2026-06-02 user
    # request: merge Evidence into Finding, delete Status column).
    out.append("| Step | Finding | Outcome |")
    out.append("|------|---------|---------|")
    for r in m["rows"]:
        if r["fid"]:
            # Severity dot — keep abuse-case finding links consistent with the
            # dotted finding-links in §4 / §5 / Top Mitigations (user-reported
            # 2026-06: §9 was the only place F-NNN links rendered bare).
            dot = _RISK_EMOJI.get(r.get("finding_sev", ""), "")
            prefix = f"{dot} " if dot else ""
            finding_cell = f"{prefix}[{r['fid']}]({_anchor(r['fid'])}) — {r['finding_title']}"
        else:
            finding_cell = "_no matching finding_"
        # Only append the per-step evidence reference when it points at a
        # DIFFERENT file than the one the finding title already names — the
        # title carries `(file:line)` per the finding-title contract, so an
        # evidence line for the same file is the same code reference repeated.
        # A cross-file evidence line (e.g. the token-storage sink in a chain
        # whose finding title names the XSS sink) still adds information and
        # is kept. (2026-06-02 user request: one code reference per finding.)
        if r["evidence"]:
            # Compare on basename so a title carrying `(wallet.ts:12)` also
            # suppresses an evidence line of `routes/wallet.ts:12` (same file,
            # path-prefix only differs).
            ev_base = r["evidence"].rsplit(":", 1)[0].rsplit("/", 1)[-1]
            if ev_base and ev_base not in r["finding_title"]:
                finding_cell += f"<br/>`{r['evidence']}`"
        out.append(f"| {r['step']} | {finding_cell} | {r['outcome']} |")
    out.append("")
    if m["combined_risk_rationale"]:
        out.append("**Why combined risk exceeds individual ratings**")
        out.append("")
        out.append(m["combined_risk_rationale"])
        out.append("")
    if m["blocking_mitigations"]:
        out.append("**Blocking mitigations**")
        out.append("")
        out.append(
            "Implementing any single mitigation below severs the chain at the "
            "named step, so the end-to-end abuse can no longer complete:"
        )
        out.append("")
        # Map each finding id to its title so the "Addresses" links carry a
        # short title rather than a bare ID (2026-06-02 user request).
        fid_title = {r["fid"]: r["finding_title"] for r in m["rows"] if r["fid"]}
        fid_sev = {r["fid"]: r.get("finding_sev", "") for r in m["rows"] if r["fid"]}
        for b in m["blocking_mitigations"]:
            mid = b["id"]
            label_m = f"[{mid}](#{mid.lower()}) — {b['title']}"
            if b["priority"]:
                label_m += f" (**{b['priority']}**)"
            addr = ", ".join(
                (f"{_RISK_EMOJI[fid_sev[a]]} " if fid_sev.get(a) and fid_sev[a] in _RISK_EMOJI else "")
                + f"[{a}]({_anchor(a)})"
                + (f" — {fid_title[a]}" if fid_title.get(a) else "")
                for a in b["addresses"]
            )
            out.append(
                f"- {label_m}: remediating {addr} breaks the chain at "
                f"**Step {b['breaks_at_step']}**, removing the link the rest of "
                f"the chain depends on."
            )
        out.append("")
    return "\n".join(out).rstrip()


def _summary_table(models: list[dict]) -> str:
    out = ["| # | Scenario | Actor | Combined Risk | Verdict |", "|---|----------|-------|---------------|---------|"]
    for m in models:
        icon, label = _CHAIN_VERDICT.get(m["chain_verdict"], ("?", "Inconclusive"))
        emoji = _RISK_EMOJI.get(m["combined_risk"], "")
        actor_short = m["actor_label"].split(" — ")[0]
        out.append(
            f"| [{m['id']}](#{m['id'].lower()}) | {m['title']} | {actor_short} | "
            f"{emoji} {m['combined_risk']} | {icon} {label} |"
        )
    return "\n".join(out)


_INTRO = (
    "_Abuse cases describe end-to-end attack scenarios that chain individual "
    "findings into an exploitation path. Each case is **mandatory** — defined in "
    "the org profile / plugin library and evaluated against every repository. "
    "Every chain step references a finding from "
    "[§8 Findings Register](#8-findings-register); each step is code-confirmed "
    "against the repository and the chain verdict is folded deterministically "
    "from the per-step results, never rated by hand._"
)

_LEGEND = (
    "_Verdict: ⚠ Fully viable — no effective control blocks this chain · "
    "◐ Partially blocked — at least one step has a compensating control but the "
    "chain is not fully closed · ✓ Mitigated — chain is broken at a verified step · "
    "? Inconclusive — could not be verified end-to-end._"
)


def _catalog_table(rows: list[dict]) -> str:
    """Compact 'generic catalog evaluated, not applicable' table so the reader
    sees WHICH common abuse-case scenarios were checked and why each was ruled
    out for this codebase — not just the viable ones."""
    out = [
        "### Generic catalog — evaluated, not applicable",
        "",
        "_These common abuse-case scenarios from the standard library were "
        "checked against this codebase and did not apply. They are listed so "
        "the assessment's abuse-case coverage is explicit, not silent._",
        "",
        "| Scenario | Source | Why not applicable |",
        "|----------|--------|--------------------|",
    ]
    for r in rows:
        out.append(
            f"| {r['title']} | {r.get('source') or 'library'} | {r['reason']} |"
        )
    return "\n".join(out)


def render_fragment(models: list[dict], catalog_rows: list[dict] | None = None) -> str:
    parts: list[str] = [HEADING, ""]
    if models:
        parts += [_INTRO, "", _summary_table(models), "", _LEGEND, ""]
        for m in models:
            parts.append("---")
            parts.append("")
            parts.append(_case_markdown(m))
            parts.append("")
    else:
        parts += [
            "_No abuse-case chain was verified end-to-end on this codebase. "
            "The generic catalog evaluation below records which standard "
            "scenarios were checked._",
            "",
        ]
    if catalog_rows:
        if models:
            parts.append("---")
            parts.append("")
        parts.append(_catalog_table(catalog_rows))
        parts.append("")
    return "\n".join(parts).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def build_models(output_dir: Path, org_profile: str | None, repo_root: str | None = None) -> list[dict]:
    verdicts_path = output_dir / ".abuse-case-verdicts.json"
    if not verdicts_path.exists():
        return []
    vdoc = json.loads(verdicts_path.read_text(encoding="utf-8"))
    verdicts = {v["abuse_case_id"]: v for v in (vdoc.get("verdicts") or [])}

    rac = _rac()
    profile = None
    profile_dir = None
    if org_profile:
        p = Path(org_profile)
        profile = rac._load_yaml(p)
        profile_dir = p.parent
    cases, _ = rac.resolve_abuse_cases(
        profile, profile_dir, PLUGIN_ROOT, Path(repo_root) if repo_root else None
    )
    case_by_id = {c["id"]: c for c in cases}

    tm_path = output_dir / "threat-model.yaml"
    tm = yaml.safe_load(tm_path.read_text(encoding="utf-8")) if tm_path.exists() else {}
    findings_idx = _findings_index(tm)
    mitigations = _mitigations_index(tm)

    # Matcher step bindings — the deterministic fallback for finding links when
    # a verifier sub-agent produced no (or partial) step verdicts. Keyed by
    # abuse_case_id → {step_number: step_match}.
    matches_by_id: dict[str, dict] = {}
    matches_path = output_dir / ".abuse-case-matches.json"
    if matches_path.exists():
        try:
            mdoc = json.loads(matches_path.read_text(encoding="utf-8"))
            for m in mdoc.get("matches", []):
                matches_by_id[m.get("abuse_case_id")] = {
                    sm.get("step"): sm for sm in m.get("step_matches", [])
                }
        except (OSError, json.JSONDecodeError):
            matches_by_id = {}

    models = []
    # Stable order: by id.
    for cid in sorted(verdicts):
        verdict = verdicts[cid]
        case = case_by_id.get(cid)
        if not case:
            continue
        cv = verdict.get("chain_verdict", "inconclusive")
        if cv == "not_applicable":
            continue
        models.append(
            render_case(case, verdict, findings_idx, mitigations, matches_by_id.get(cid))
        )
    return models


def build_catalog_evaluation(output_dir: Path) -> list[dict]:
    """Rows for library abuse cases that were structurally evaluated but did
    NOT become viable scenarios (matcher verdict `not_applicable`). Source =
    `.abuse-case-matches.json`; rendered as the compact 'checked, not relevant'
    table so the generic catalog coverage is explicit (user request 2026-06)."""
    matches_path = output_dir / ".abuse-case-matches.json"
    if not matches_path.exists():
        return []
    try:
        mdoc = json.loads(matches_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    rows = []
    for m in mdoc.get("matches", []):
        if m.get("structural_verdict") == "not_applicable":
            rows.append({
                "id": m.get("abuse_case_id"),
                "title": m.get("title") or m.get("abuse_case_id"),
                "source": m.get("source"),
                "reason": m.get("reason") or "scope preconditions not met for this codebase",
            })
    return sorted(rows, key=lambda r: r["id"] or "")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render the §9 Abuse Cases fragment.")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--org-profile", default=None)
    parser.add_argument("--repo-root", default=None, help="target repo root; loads <repo>/.appsec/abuse-cases/*.yaml")
    parser.add_argument("--fragments-subdir", default=".fragments")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    models = build_models(output_dir, args.org_profile, args.repo_root)
    catalog_rows = build_catalog_evaluation(output_dir)

    frag_dir = output_dir / args.fragments_subdir
    frag_dir.mkdir(parents=True, exist_ok=True)
    md_path = frag_dir / "abuse-cases.md"
    json_path = frag_dir / "abuse-cases.json"

    if not models and not catalog_rows:
        # Nothing evaluated at all (Phase 10c never ran) — remove any stale
        # fragment so compose falls back to its placeholder and the §9 heading
        # still appears (numbering stays put).
        for p in (md_path, json_path):
            if p.exists():
                p.unlink()
        sys.stderr.write("RENDER_ABUSE_CASES: no abuse-case evaluation on disk — placeholder will render\n")
        return 0

    md_path.write_text(render_fragment(models, catalog_rows), encoding="utf-8")
    json_path.write_text(
        json.dumps(
            {"schema_version": 1, "abuse_cases": models, "catalog_evaluated": catalog_rows},
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    sys.stderr.write(
        f"RENDER_ABUSE_CASES: wrote {len(models)} viable + {len(catalog_rows)} "
        f"not-applicable case(s) to {md_path}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
