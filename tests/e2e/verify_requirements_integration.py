#!/usr/bin/env python3
"""Ad-hoc verifier for the requirements+blueprints integration E2E.

Given a completed run's output dir (--out) and the requirements source that was
fed in (--source), assert that the provided requirements/blueprints actually
flowed into findings, measures and the management summary — and that the LLM did
NOT invent requirement/blueprint IDs that contradict the provided set.

Exit 0 = all checks passed, 1 = a check failed.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml


def _provided_ids(source: Path) -> tuple[set[str], set[str]]:
    d = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    req_ids = {
        (r.get("id") or "").strip()
        for c in d.get("categories", []) or []
        for r in (c.get("requirements", []) or [])
        if isinstance(r, dict) and (r.get("id") or "").strip()
    }
    bp_ids = {
        (b.get("id") or "").strip()
        for b in d.get("blueprints", []) or []
        if isinstance(b, dict) and (b.get("id") or "").strip()
    }
    return req_ids, bp_ids


def _threat_req_ids(t: dict) -> list[str]:
    out: list[str] = []
    for rid in t.get("violated_requirements") or []:
        if rid:
            out.append(str(rid).strip())
    if t.get("requirement_id"):
        out.append(str(t["requirement_id"]).strip())
    rem = t.get("remediation") if isinstance(t.get("remediation"), dict) else {}
    ref = rem.get("reference") if isinstance(rem, dict) else None
    if isinstance(ref, str):
        out += [tok.strip() for tok in re.findall(r"\[([^\]]+)\]", ref)]
    return out


def _threat_blueprint_ids(t: dict) -> list[str]:
    rem = t.get("remediation") if isinstance(t.get("remediation"), dict) else {}
    bp = rem.get("blueprint") if isinstance(rem, dict) else None
    if isinstance(bp, str):
        return [tok.strip() for tok in re.findall(r"\b(BP-[A-Z0-9-]+)\b", bp)]
    if isinstance(bp, dict) and bp.get("id"):
        return [str(bp["id"]).strip()]
    return []


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--source", required=True)
    a = ap.parse_args()
    out = Path(a.out)
    req_ids, bp_ids = _provided_ids(Path(a.source))

    checks: list[tuple[str, bool, str]] = []

    def chk(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, ok, detail))

    # --- artifacts present
    tm_yaml = out / "threat-model.yaml"
    tm_md = out / "threat-model.md"
    reqs_file = out / ".requirements.yaml"
    comp_frag = out / ".fragments" / "requirements-compliance.md"
    chk("threat-model.yaml exists", tm_yaml.is_file())
    chk("threat-model.md exists", tm_md.is_file())
    chk(".requirements.yaml written", reqs_file.is_file())
    chk("requirements-compliance fragment exists", comp_frag.is_file())
    if not tm_yaml.is_file():
        return _report(checks)

    data = yaml.safe_load(tm_yaml.read_text(encoding="utf-8")) or {}

    # --- gate flag
    chk("meta.check_requirements is True",
        data.get("meta", {}).get("check_requirements") is True,
        f"got {data.get('meta', {}).get('check_requirements')!r}")

    # --- the written source matches what we fed in (same req-id universe)
    if reqs_file.is_file():
        w_req, w_bp = _provided_ids(reqs_file)
        chk("written .requirements.yaml == provided source (req ids)",
            w_req == req_ids, f"written={len(w_req)} provided={len(req_ids)}")

    # --- referenced ids across threats + mitigations
    threats = data.get("threats", []) or []
    referenced_reqs: set[str] = set()
    referenced_bps: set[str] = set()
    threats_with_req = 0
    for t in threats:
        ids = [i for i in _threat_req_ids(t) if i]
        # keep only tokens that look like our provided ID shape OR are declared
        ids = [i for i in ids if i in req_ids] + [i for i in ids if re.match(r"^[A-Z]{2,4}-\d{3}$", i) and i not in req_ids]
        rid_hits = [i for i in _threat_req_ids(t) if i in req_ids]
        if rid_hits:
            threats_with_req += 1
        referenced_reqs.update(_threat_req_ids(t))
        referenced_bps.update(_threat_blueprint_ids(t))
    for m in data.get("mitigations", []) or []:
        if isinstance(m, dict):
            referenced_reqs.update((r or "").strip() for r in (m.get("fulfills_requirements") or []))

    # restrict requirement-looking tokens (avoid CWE/OWASP bracket noise):
    req_shaped = {r for r in referenced_reqs if re.match(r"^[A-Z]{2,4}-\d{3}$", r)}
    bp_shaped = {b for b in referenced_bps if b.startswith("BP-")}

    chk("at least one finding references a provided requirement",
        threats_with_req > 0, f"{threats_with_req} threats carry a provided req id")

    # --- CONTRADICTION checks: every requirement-shaped / blueprint id the LLM
    #     referenced must be in the provided set (no invented IDs).
    unknown_reqs = sorted(req_shaped - req_ids)
    unknown_bps = sorted(bp_shaped - bp_ids)
    chk("no invented requirement IDs (referenced ⊆ provided)",
        not unknown_reqs, f"unknown={unknown_reqs}")
    chk("no invented blueprint IDs (referenced ⊆ provided)",
        not unknown_bps, f"unknown={unknown_bps}")

    # --- markdown integration: compliance section + management summary
    md = tm_md.read_text(encoding="utf-8") if tm_md.is_file() else ""
    chk("md mentions a provided requirement id",
        any(r in md for r in req_ids), "")
    chk("md has a requirements/compliance section",
        bool(re.search(r"(?i)requirement|compliance", md)), "")
    # management summary block references requirements
    ms_match = re.search(r"(?is)(management\s+summary|zusammenfassung).{0,8000}", md)
    ms_ok = bool(ms_match) and any(r in ms_match.group(0) for r in req_ids)
    chk("management summary references a provided requirement (or compliance)",
        ms_ok or bool(re.search(r"(?is)(management\s+summary|zusammenfassung).{0,8000}(requirement|compliance|anforderung)", md)),
        "")

    # --- evidence dump
    print("\n── evidence ──────────────────────────────────────────────")
    print(f"  provided: {len(req_ids)} requirement ids, {len(bp_ids)} blueprint ids")
    print(f"  threats total: {len(threats)}  | threats citing a provided req: {threats_with_req}")
    print(f"  referenced requirement-shaped ids: {sorted(req_shaped)[:20]}")
    print(f"  referenced blueprint ids:          {sorted(bp_shaped)}")
    if unknown_reqs:
        print(f"  ⚠ INVENTED requirement ids: {unknown_reqs}")
    if unknown_bps:
        print(f"  ⚠ INVENTED blueprint ids:   {unknown_bps}")

    return _report(checks)


def _report(checks: list[tuple[str, bool, str]]) -> int:
    print("\n── checks ────────────────────────────────────────────────")
    failed = 0
    for name, ok, detail in checks:
        mark = "✓" if ok else "✗"
        line = f"  {mark} {name}"
        if detail and not ok:
            line += f"   [{detail}]"
        print(line)
        if not ok:
            failed += 1
    print("──────────────────────────────────────────────────────────")
    print(f"  {'PASS' if failed == 0 else 'FAIL'}: {len(checks)-failed}/{len(checks)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
