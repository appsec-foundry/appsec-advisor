#!/usr/bin/env python3
"""Deterministic `threats[].severity_rationale` for ratings ABOVE baseline.

A Critical rating is sometimes *higher than the usual standard* for a
weakness class, and the reason is contextual rather than intrinsic:

  * A hardcoded key / secret (CWE-321/798/312/…) is individually capped at
    High (``never_individual_critical``), but becomes Critical when the
    secret is committed to a **public source repo** — anyone who clones the
    repo can extract it, so exploitation needs no prior access.
  * A mass assignment (CWE-915) or missing-auth (CWE-306) is High on its own
    but Critical when it reaches a privileged field / admin operation on an
    **unauthenticated endpoint** (the always-critical context threshold).
  * Any individually-capped CWE that reaches Critical did so as an
    **attack-chain keystone**.

When the report shows such a finding as Critical without saying *why it is
above the usual baseline*, the rating reads as arbitrary or alarmist. This
emitter writes a short, scannable ``severity_rationale`` that the composer
renders inline on the §8 Story-Card Severity line.

Only findings whose Critical rating is genuinely above their class baseline
get a note — naturally-Critical classes (SQL injection CWE-89, RCE CWE-94)
get none, because Critical is their expected rating and a note would be noise.

Idempotent: auto-written notes are recomputed every run (a downgrade clears a
stale note); a hand-authored ``severity_rationale_manual: true`` is preserved.

Usage:
    python3 emit_severity_rationale.py <output_dir>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

_CRITERIA_PATH = Path(__file__).resolve().parent.parent / "data" / "critical-criteria.yaml"

_SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_rank(label: str) -> int:
    return _SEV_ORDER.get((label or "").strip().lower(), 0)


# always_critical CWEs whose Critical rating is CONTEXTUAL (only Critical on an
# unauthenticated / low-distance endpoint) rather than intrinsic. These warrant
# a "why above baseline" note; SQLi/RCE/deserialization/command-injection do not.
_CONTEXT_PROMOTED_CWES = {"CWE-915", "CWE-306"}

_REPO_READ_NOTE = "secret committed to the public source repo — extractable on clone, no prior access needed"
_UNAUTH_NOTE = "reaches a privileged operation on an unauthenticated endpoint"
_KEYSTONE_NOTE = "elevated as an attack-chain keystone (individual baseline: High)"


def _load_baseline_high_cwes() -> set[str]:
    """The `never_individual_critical` CWE set — these are individually capped
    below Critical, so a Critical rating is always above their baseline."""
    try:
        crit = yaml.safe_load(_CRITERIA_PATH.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError):
        return set()
    out: set[str] = set()
    for entry in crit.get("never_individual_critical") or []:
        if isinstance(entry, dict) and entry.get("cwe"):
            out.add(str(entry["cwe"]).strip().upper())
        elif isinstance(entry, str):
            out.add(entry.strip().upper())
    return out


def _load_abuse_case_titles(output_dir: Path) -> dict[str, str]:
    """Map AC-ID → human title from the abuse-case matcher sidecar.

    Returns {} when the sidecar is absent (abuse-case verification was skipped
    — e.g. quick depth or --no-abuse-cases — so there are no chains to name).
    """
    titles: dict[str, str] = {}
    for name in (".abuse-case-matches.json", ".abuse-case-verdicts.json"):
        path = output_dir / name
        if not path.is_file():
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for key in ("matches", "verdicts"):
            for entry in doc.get(key) or []:
                if not isinstance(entry, dict):
                    continue
                cid = (entry.get("abuse_case_id") or entry.get("id") or "").strip()
                title = (entry.get("title") or entry.get("name") or "").strip()
                if cid and title:
                    titles.setdefault(cid, title)
    return titles


def _chain_rationale(t: dict, ac_titles: dict[str, str]) -> str:
    """Provenance note documenting the role a verified abuse chain played in
    this finding's assessment.

    Fires whenever the finding is a keystone/contributor in at least one
    code-verified (``fully_viable``) abuse chain — ``triage_compute_ranking``
    only writes ``verified_chain_ids`` for such chains. The wording adapts to
    whether the chain *raised* the rating (effective_severity above raw) or
    merely *confirmed* an already-high rating end-to-end; either way the
    reader sees exactly which attack chain the finding anchors, with a §9
    back-reference.
    """
    role = (t.get("chain_role") or "").strip().lower()
    # Preserve order, drop duplicates (the matcher can list an AC-ID twice).
    seen: set[str] = set()
    chains: list[str] = []
    for c in t.get("verified_chain_ids") or []:
        c = (c or "").strip()
        if c and c not in seen:
            seen.add(c)
            chains.append(c)
    if role not in ("keystone", "contributor") or not chains:
        return ""
    named: list[str] = []
    for cid in chains[:2]:
        title = ac_titles.get(cid)
        named.append(f"{cid} ({title})" if title else cid)
    chain_str = ", ".join(named)
    if len(chains) > 2:
        chain_str += f", +{len(chains) - 2} more"

    elevated = _sev_rank(t.get("effective_severity") or "") > _sev_rank(t.get("risk") or t.get("severity") or "")
    if elevated:
        eff_label = (t.get("effective_severity") or "").strip() or "a higher rating"
        return f"elevated to {eff_label} as a verified attack-chain {role} in {chain_str}; see §9"
    return f"verified attack-chain {role} in {chain_str}; see §9"


def _intrinsic_rationale(t: dict, baseline_high: set[str]) -> str:
    """The pre-existing 'why above class baseline' note (CWE/vektor heuristics).
    Only applies to Critical findings."""
    sev = (t.get("effective_severity") or t.get("risk") or t.get("severity") or "").strip().lower()
    if sev != "critical":
        return ""
    cwe = (t.get("cwe") or "").strip().upper()
    vektor = (t.get("vektor") or "").strip().lower()
    if vektor == "repo-read":
        return _REPO_READ_NOTE
    if cwe in _CONTEXT_PROMOTED_CWES and vektor == "internet-anon":
        return _UNAUTH_NOTE
    if cwe in baseline_high:
        return _KEYSTONE_NOTE
    return ""


def _rationale_for(t: dict, baseline_high: set[str], ac_titles: dict[str, str]) -> str:
    """Compose the §8 Story-Card severity-line rationale.

    A code-verified abuse-chain note is the evidence-backed provenance the
    user wants surfaced; the intrinsic CWE/vektor note explains why the rating
    is above the class baseline. When both apply they are combined (intrinsic
    first, chain provenance second) so neither signal is lost.
    """
    chain = _chain_rationale(t, ac_titles)
    intrinsic = _intrinsic_rationale(t, baseline_high)
    if chain and intrinsic:
        # The generic CWE keystone note is subsumed by the precise chain note.
        if intrinsic == _KEYSTONE_NOTE:
            return chain
        return f"{intrinsic}; {chain}"
    return chain or intrinsic


def emit(output_dir: Path) -> tuple[int, int]:
    """Returns (total_threats, annotated)."""
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"emit_severity_rationale: no yaml at {yaml_path}", file=sys.stderr)
        return (0, 0)
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        print(f"emit_severity_rationale: parse failed: {exc}", file=sys.stderr)
        return (0, 0)
    if not isinstance(data, dict):
        return (0, 0)

    baseline_high = _load_baseline_high_cwes()
    ac_titles = _load_abuse_case_titles(output_dir)
    threats = data.get("threats") or []
    annotated = 0
    changed = False
    for t in threats:
        if not isinstance(t, dict):
            continue
        if t.get("severity_rationale_manual"):
            annotated += 1
            continue
        note = _rationale_for(t, baseline_high, ac_titles)
        prior = t.get("severity_rationale")
        if note:
            if prior != note:
                t["severity_rationale"] = note
                changed = True
            annotated += 1
        elif prior is not None:
            # stale auto-note (e.g. finding was downgraded) — clear it.
            t.pop("severity_rationale", None)
            changed = True

    if changed:
        yaml_path.write_text(
            yaml.safe_dump(
                data,
                sort_keys=False,
                allow_unicode=True,
                width=4096,
                default_flow_style=False,
            ),
            encoding="utf-8",
        )
    return (len(threats), annotated)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: emit_severity_rationale.py <output_dir>", file=sys.stderr)
        return 2
    total, annotated = emit(Path(argv[0]))
    print(f"emit_severity_rationale: total={total} annotated={annotated}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
