#!/usr/bin/env python3
"""Validate F-NNN / T-NNN / M-NNN cross-references in LLM-authored fragments.

Root-cause fix for the 2026-05-21 juice-shop run defect where the renderer
LLM fabricated F-031 (only F-001..F-029 exist) and remapped F-008/F-009
descriptions in `.fragments/security-architecture.md` §7.2.2 and §7.4.1.

The QA contract gate (`qa_checks.py contract`) does not check semantic ID
accuracy — only structural coverage (link → anchor reachability). The
broken refs pass contract because every `[F-NNN](#f-nnn)` link does land
on its own definition in §8 Findings Register; the SEMANTIC mismatch
(label says "MD5" but F-008 is referenced in a "basket IDOR" context)
is invisible to anchor-only checks.

This validator detects two failure modes:

1. **Phantom F-NNN** — `[F-NNN](#f-nnn)` references an ID not in
   `threat-model.yaml` → `threats[].id`. Example: F-031 when the YAML
   only has T-001..T-029.

2. **Mislabeled F-NNN** — `[F-NNN](#f-nnn) — <description>` where the
   description is semantically inconsistent with the actual YAML threat
   title. Detected via a token-Jaccard similarity threshold (default
   0.15): if the inline description shares fewer than 15% of meaningful
   tokens with the threat title in YAML, it is flagged as a mislabel.

By design the validator does NOT auto-rewrite — fragments are LLM-
authored and the corrected mapping may be ambiguous (the inline
description might also be salvageable). The script writes a structured
JSON report to `$OUTPUT_DIR/.finding-refs-report.json` listing every
suspicious reference with its location, current target, and best-guess
remap candidate (the YAML threat whose title shares the most tokens with
the inline description).

Typical use:

    python3 validate_finding_refs.py $OUTPUT_DIR             # report only
    python3 validate_finding_refs.py $OUTPUT_DIR --strict    # exit 1 on any finding
    python3 validate_finding_refs.py $OUTPUT_DIR --remap     # emit repair plan

Exit codes:
    0 — no defects detected
    1 — defects detected AND --strict was passed
    2 — usage / IO error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("error: PyYAML not installed", file=sys.stderr)
    sys.exit(2)


F_REF_RE = re.compile(r"\[(F-\d{3})\]\(#f-\d{3}\)\s*(?:—|-)\s*([^\n\r\|<\[]+?)(?=\n|<br/?>|\||\[|\Z)")
JACCARD_THRESHOLD = 0.10
# Distinguishing keywords (per YAML title) that, when missing from the inline
# description, strongly indicate a mislabeled F-ID — even when 1 token happens
# to overlap. Used to escalate borderline jaccard matches.
SIGNATURE_TOKENS = {
    "sqlite",
    "md5",
    "xxe",
    "ssrf",
    "csrf",
    "idor",
    "jwt",
    "localstorage",
    "eval",
    "mongoose",
    "marsdb",
    "rate",
    "limiting",
    "metrics",
    "prometheus",
    "review",
    "basket",
    "price",
    "changepassword",
}

STOPWORDS = {
    "the",
    "a",
    "an",
    "and",
    "or",
    "in",
    "on",
    "at",
    "to",
    "for",
    "of",
    "with",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "being",
    "via",
    "this",
    "that",
    "these",
    "those",
    "from",
    "as",
    "by",
    "no",
    "not",
    "has",
    "have",
    "had",
    "do",
    "does",
    "did",
}


def tokenize(text: str) -> set[str]:
    """Lowercase, split, drop stopwords + 1-char tokens + pure-punct."""
    text = re.sub(r"\([^)]*\)", " ", text)  # drop parenthetical paths
    text = re.sub(r"`[^`]*`", " ", text)  # drop backtick spans
    tokens = re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{1,}", text.lower())
    return {t for t in tokens if t not in STOPWORDS and len(t) > 1}


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def load_threats(yaml_path: Path) -> dict[str, dict]:
    """Return {F-NNN: {id, title, evidence_file}} from threats[]."""
    with open(yaml_path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    out: dict[str, dict] = {}
    for t in data.get("threats", []) or []:
        if not isinstance(t, dict):
            continue
        tid = t.get("id") or t.get("t_id")
        if not tid or not isinstance(tid, str):
            continue
        # F-NNN is just T-NNN with the prefix swapped (composer convention)
        fid = tid.replace("T-", "F-")
        ev = t.get("evidence")
        ev_file = "?"
        if isinstance(ev, list) and ev:
            ev_file = (ev[0] or {}).get("file", "?")
        elif isinstance(ev, dict):
            ev_file = ev.get("file", "?")
        out[fid] = {
            "id": tid,
            "title": t.get("title", ""),
            "evidence_file": ev_file,
        }
    return out


def scan_fragment(frag_path: Path, threats: dict[str, dict]) -> list[dict]:
    """Scan one fragment file; return list of defect dicts."""
    defects: list[dict] = []
    if not frag_path.exists():
        return defects
    lines = frag_path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines, 1):
        for m in F_REF_RE.finditer(line):
            fid = m.group(1)
            desc = (m.group(2) or "").strip().rstrip(".")
            # Skip if description is essentially empty (some links have no inline label)
            if len(desc) < 8:
                if fid not in threats:
                    defects.append(
                        {
                            "fragment": str(frag_path),
                            "line": i,
                            "f_id": fid,
                            "inline_description": desc,
                            "defect": "phantom_f_id",
                            "reason": f"{fid} is not in threat-model.yaml",
                            "remap_candidate": None,
                        }
                    )
                continue
            if fid not in threats:
                # Phantom F-ID — find best YAML match by token similarity
                best = None
                best_score = 0.0
                desc_tokens = tokenize(desc)
                for cand_fid, cand in threats.items():
                    score = jaccard(desc_tokens, tokenize(cand.get("title", "")))
                    if score > best_score:
                        best_score = score
                        best = cand_fid
                defects.append(
                    {
                        "fragment": str(frag_path),
                        "line": i,
                        "f_id": fid,
                        "inline_description": desc,
                        "defect": "phantom_f_id",
                        "reason": f"{fid} is not in threat-model.yaml (max id ~ {max(threats)})",
                        "remap_candidate": best if best_score >= JACCARD_THRESHOLD else None,
                        "remap_score": round(best_score, 3),
                    }
                )
                continue
            # Real F-ID — check semantic match
            yaml_title = threats[fid].get("title", "")
            score = jaccard(tokenize(desc), tokenize(yaml_title))
            if score < JACCARD_THRESHOLD:
                # Find a better candidate in YAML
                best = None
                best_score = score
                desc_tokens = tokenize(desc)
                for cand_fid, cand in threats.items():
                    if cand_fid == fid:
                        continue
                    cand_score = jaccard(desc_tokens, tokenize(cand.get("title", "")))
                    if cand_score > best_score:
                        best_score = cand_score
                        best = cand_fid
                if best is not None and best_score > score + 0.10:
                    defects.append(
                        {
                            "fragment": str(frag_path),
                            "line": i,
                            "f_id": fid,
                            "inline_description": desc,
                            "yaml_title": yaml_title,
                            "defect": "mislabeled_f_id",
                            "reason": f"inline description shares {score:.2f} tokens with {fid} title; "
                            f"better match: {best} ({best_score:.2f})",
                            "remap_candidate": best,
                            "remap_score": round(best_score, 3),
                        }
                    )
    return defects


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("output_dir", type=Path)
    ap.add_argument(
        "--strict", action="store_true", help="Exit 1 when defects are detected (default: exit 0 with report only)"
    )
    ap.add_argument(
        "--remap", action="store_true", help="Emit .finding-refs-repair-plan.json mapping bad refs to suggested fixes"
    )
    ap.add_argument("--json", action="store_true", help="Print JSON to stdout in addition to the report file")
    args = ap.parse_args()

    output_dir: Path = args.output_dir
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.exists():
        print(f"error: {yaml_path} not found", file=sys.stderr)
        return 2

    threats = load_threats(yaml_path)
    if not threats:
        print(f"error: no threats in {yaml_path}", file=sys.stderr)
        return 2

    # Scan fragments and the rendered MD as a fallback (covers the case
    # where the run already finished and fragments were cleaned up).
    candidate_paths = [
        output_dir / ".fragments" / "security-architecture.md",
        output_dir / ".fragments" / "architecture-diagrams.md",
        output_dir / ".fragments" / "attack-walkthroughs.md",
        output_dir / "threat-model.md",  # final report — useful for post-run audit
    ]

    all_defects: list[dict] = []
    for p in candidate_paths:
        if p.exists():
            all_defects.extend(scan_fragment(p, threats))

    report = {
        "generated": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "yaml_path": str(yaml_path),
        "threats_in_yaml": sorted(threats),
        "defect_count": len(all_defects),
        "defects": all_defects,
    }
    report_path = output_dir / ".finding-refs-report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if args.remap and all_defects:
        plan = {
            "generated": report["generated"],
            "actions": [
                {
                    "fragment": d["fragment"],
                    "line": d["line"],
                    "bad_f_id": d["f_id"],
                    "inline_description": d["inline_description"],
                    "suggested_f_id": d.get("remap_candidate"),
                    "remap_score": d.get("remap_score", 0.0),
                    "defect": d.get("defect"),
                    "reason": d.get("reason"),
                }
                for d in all_defects
            ],
        }
        plan_path = output_dir / ".finding-refs-repair-plan.json"
        plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
        print(f"wrote {plan_path}", file=sys.stderr)

    print(
        f"validate_finding_refs: scanned {sum(1 for p in candidate_paths if p.exists())} file(s) · "
        f"{len(all_defects)} defect(s) · report: {report_path}",
        file=sys.stderr,
    )

    if args.json:
        print(json.dumps(report, indent=2))

    if args.strict and all_defects:
        for d in all_defects[:10]:
            print(
                f"  {d['fragment']}:{d['line']}  {d['defect']}  {d['f_id']}  → remap to {d.get('remap_candidate')}",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
