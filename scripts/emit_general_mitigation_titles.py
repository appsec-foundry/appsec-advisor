#!/usr/bin/env python3
"""Rewrite mitigation TITLES into clear, general remediation labels.

Problem
-------
Stage-1 authors ``threats[].mitigation_title`` as a detailed remediation
*instruction* — "Replace `.decode(token)` with `.verify(token, key, {
algorithms: [...] })` and gate authorization on the verified payload only.",
"Add HEALTHCHECK CMD curl -f http://localhost:3000/...". ``build_mitigations``
copies that verbatim into ``mitigations[].title``, so the §10 register and its
index read like fragments pulled out of the fix body — code tokens, file
paths, specific values — instead of titles (user report 2026-06-12).

The detailed, actionable remediation is NOT lost by generalizing the title:
the §10 block body renders ``how`` / harvested ``remediation.steps`` /
``code_example`` from the addressed threats. The title is only a label, so we
replace it with a general, class-level remediation title derived from the
finding CWE (keyword-disambiguated where one CWE spans two distinct fixes —
e.g. CWE-347 = JWT-signature vs release-artifact signing). When a mitigation's
addressed threats carry NO structured remediation (so the block would have no
``How:`` detail), the original instruction is preserved into ``how`` first.

Idempotent: the original title is stashed in ``_title_source`` on first run and
re-derived from it on every subsequent run, so the canonical title never drifts
and re-running never double-generalizes.

Title style — THE mitigation-title contract (read before extending the map)
---------------------------------------------------------------------------
Unlike finding titles, mitigation titles are NOT LLM-authored — the displayed
title is fully DERIVED from the addressed CWE by ``_GENERAL_TITLE_BY_CWE`` here.
So there is no ``agents/shared`` authoring contract (that would guide an author
whose text is discarded); THIS map IS the contract. When adding a CWE / class,
keep the voice consistent:

1. **Imperative action + object** — start with a verb ("Use", "Enforce",
   "Disable", "Move", "Validate", "Pin"); name the control, not the bug.
   GOOD "Use parameterized database queries"; BAD "SQL injection in login".
2. **General / class-level** — the title is a label for a whole finding class,
   not one finding. No file paths, parameters, payloads, code identifiers,
   library names, versions, or specific values. Those live in the §10 block body
   (``how`` / harvested ``remediation.steps`` / ``code_example``).
3. **One clause, ~3-7 words, no trailing period.** It must read cleanly in the
   compact §10 Mitigations-index chip.
4. **Disambiguate collision CWEs** via ``_DISAMBIGUATE`` (regex on the lowered
   original title) when ONE CWE spans two genuinely different fixes — e.g.
   CWE-347 = JWT-signature vs release-artifact signing; CWE-400 = event-loop
   blocking vs parser/decompression limits. Add the more-specific regex first.
5. **Unmapped CWEs** fall through to ``_generalize_fallback`` (strips locality /
   code / URLs from the original) — acceptable but imperfect; prefer a curated
   map entry. Update ``tests/test_emit_general_mitigation_titles.py`` alongside.

Usage
-----
    python3 scripts/emit_general_mitigation_titles.py <output-dir> [--report-only]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

# Class-level remediation titles keyed on the addressed finding's CWE. Each is a
# clear, general "what to do" — the per-finding specifics live in the block body.
_GENERAL_TITLE_BY_CWE: dict[str, str] = {
    "CWE-89": "Use parameterized database queries",
    "CWE-564": "Use parameterized database queries",
    "CWE-943": "Use parameterized database queries",
    "CWE-79": "Encode output instead of bypassing the framework sanitizer",
    "CWE-80": "Encode output instead of bypassing the framework sanitizer",
    "CWE-94": "Remove server-side evaluation of untrusted input",
    "CWE-95": "Remove server-side evaluation of untrusted input",
    "CWE-1336": "Remove server-side evaluation of untrusted input",
    "CWE-611": "Disable XML external entity (XXE) resolution",
    "CWE-776": "Bound parser resource consumption",
    "CWE-918": "Validate and allowlist outbound request targets",
    "CWE-22": "Constrain file paths to a safe base directory",
    "CWE-23": "Constrain file paths to a safe base directory",
    "CWE-73": "Constrain file paths to a safe base directory",
    "CWE-798": "Move secrets to a managed secret store",
    "CWE-321": "Move cryptographic keys to a managed secret store",
    "CWE-312": "Stop storing sensitive data in cleartext",
    "CWE-540": "Remove secrets from source code",
    "CWE-922": "Store session tokens in HttpOnly, Secure cookies",
    "CWE-345": "Verify token signatures before trusting claims",
    "CWE-287": "Harden the authentication flow",
    "CWE-384": "Rotate the session identifier on authentication",
    "CWE-639": "Enforce object-level (ownership) authorization",
    "CWE-862": "Enforce server-side authorization on every endpoint",
    "CWE-863": "Enforce correct server-side authorization",
    "CWE-285": "Enforce server-side authorization",
    "CWE-732": "Apply least-privilege permissions",
    "CWE-269": "Apply least-privilege permissions",
    "CWE-307": "Rate-limit and lock out repeated authentication attempts",
    "CWE-829": "Pin third-party dependencies to immutable versions",
    "CWE-1104": "Pin the container base image to an immutable digest",
    "CWE-506": "Disable untrusted package install scripts",
    "CWE-250": "Drop unnecessary privileges in build and runtime",
    "CWE-778": "Add security audit logging",
    "CWE-223": "Add security audit logging",
    "CWE-209": "Return generic error messages to clients",
    "CWE-200": "Stop exposing internal information to clients",
    "CWE-601": "Validate redirect targets against an allowlist",
    "CWE-352": "Add anti-CSRF protection to state-changing requests",
    "CWE-916": "Hash passwords with a strong, salted algorithm",
    "CWE-327": "Replace the weak cryptographic algorithm",
    "CWE-703": "Add a container healthcheck",
    "CWE-1021": "Add framing and clickjacking protections",
}

# Disambiguators — one CWE, two genuinely different fixes. (regex on the lowered
# original title) → title. Checked before the plain CWE map.
_DISAMBIGUATE: dict[str, list[tuple[str, str]]] = {
    "CWE-347": [
        (r"cosign|provenance|attest|sigstore|release|image|artifact|workflow|supply",
         "Sign and verify release artifacts"),
        (r"jwt|token|alg|expressjwt|rs256|hs256|decode|verify",
         "Enforce JWT signature and algorithm verification"),
    ],
    "CWE-400": [
        (r"yaml|alias|anchor|xml|entity|bomb|zip|decompress|billion",
         "Bound parser and decompression resource limits"),
        (r"event loop|worker|cpu|vm\b|runincontext|thread|timeout|synchronous",
         "Offload CPU-bound work and bound execution time"),
    ],
    "CWE-770": [
        (r"yaml|alias|anchor|xml|entity|bomb|zip|decompress",
         "Bound parser and decompression resource limits"),
        (r"rate|login|auth|lockout|captcha",
         "Rate-limit and lock out repeated authentication attempts"),
    ],
}


def _first_cwe(m: dict, threats_by_id: dict) -> str:
    """Resolve the primary CWE for a mitigation from its addressed findings."""
    explicit = m.get("prevents_cwes") or m.get("cwes") or []
    for c in explicit:
        if c:
            return _norm_cwe(c)
    for ref in (m.get("threat_ids") or m.get("addresses") or []):
        t = threats_by_id.get((ref or "").strip().upper()) or {}
        c = (t.get("cwe") or "").strip()
        if c:
            return _norm_cwe(c)
    return ""


def _norm_cwe(c: str) -> str:
    c = (c or "").strip().upper()
    if not c:
        return ""
    return c if c.startswith("CWE-") else f"CWE-{c}"


_TRAIL_LOCALITY_RE = re.compile(
    r"\s+(?:in|at|within|inside|under|for|across)\s+"
    r"(?:the\s+|every\s+|all\s+)?[`'\"]?[\w./:\-]+(?:\s+(?:handler|route|endpoint|"
    r"middleware|file|component|module|call|calls|clause|step|pipeline|workflow))?"
    r"[`'\"]?\s*$",
    re.IGNORECASE,
)


def _generalize_fallback(title: str) -> str:
    """Best-effort cleaner for a CWE with no curated title: strip implementation
    locality / code / URLs so the leftover reads as a label rather than an
    instruction. Conservative — returns the original when it cannot improve it."""
    s = (title or "").strip().rstrip(".")
    if not s:
        return s
    # Drop a parenthetical aside ("(or equivalent …)").
    s = re.sub(r"\s*\([^()]*\)", "", s)
    # Drop trailing URL.
    s = re.sub(r"\s+https?://\S+\s*$", "", s)
    # Drop a trailing "in <file>/at <route>/…" locality clause.
    prev = None
    while prev != s:
        prev = s
        s = _TRAIL_LOCALITY_RE.sub("", s).rstrip(" .;,")
    # Collapse whitespace.
    s = re.sub(r"\s{2,}", " ", s).strip()
    return s or title.strip()


def _addressed_threats_have_detail(m: dict, threats_by_id: dict) -> bool:
    """True when at least one addressed threat carries structured remediation, so
    the §10 block already renders actionable detail beyond the title."""
    if (m.get("how") or "").strip() or m.get("how_code") or m.get("steps") or m.get("code_example"):
        return True
    for ref in (m.get("threat_ids") or m.get("addresses") or []):
        t = threats_by_id.get((ref or "").strip().upper()) or {}
        rem = t.get("remediation")
        if isinstance(rem, dict) and (rem.get("steps") or rem.get("code_example") or rem.get("summary")):
            return True
    return False


def generalize_title(original: str, cwe: str) -> str:
    """Return the general title for one mitigation (or the cleaned original)."""
    for pat, title in _DISAMBIGUATE.get(cwe, []):
        if re.search(pat, original.lower()):
            return title
    if cwe in _GENERAL_TITLE_BY_CWE:
        return _GENERAL_TITLE_BY_CWE[cwe]
    return _generalize_fallback(original)


def apply(data: dict) -> int:
    """Rewrite mitigation titles in place. Returns the number changed."""
    mitigations = data.get("mitigations") or []
    threats_by_id = {
        (t.get("t_id") or t.get("id") or "").strip().upper(): t
        for t in (data.get("threats") or [])
        if isinstance(t, dict)
    }
    changed = 0
    for m in mitigations:
        if not isinstance(m, dict):
            continue
        # Idempotency: the canonical basis is the FIRST title we ever saw.
        original = (m.get("_title_source") or m.get("title") or m.get("mitigation_title") or "").strip()
        if not original:
            continue
        cwe = _first_cwe(m, threats_by_id)
        general = generalize_title(original, cwe)
        if not general or general == (m.get("title") or "").strip():
            # Still stash the source so a later run with a better map can re-derive.
            m.setdefault("_title_source", original)
            continue
        # Preserve the detailed instruction in the body when the block would
        # otherwise have nothing actionable to show.
        if not _addressed_threats_have_detail(m, threats_by_id):
            m["how"] = original
        m["_title_source"] = original
        m["title"] = general
        changed += 1
    return changed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="emit_general_mitigation_titles.py")
    ap.add_argument("output_dir", type=Path)
    ap.add_argument("--report-only", action="store_true", help="Print intended changes; do not write.")
    ns = ap.parse_args(argv)

    yaml_path = ns.output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"emit_general_mitigation_titles: no threat-model.yaml in {ns.output_dir}", file=sys.stderr)
        return 0
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001
        print(f"emit_general_mitigation_titles: unreadable yaml ({exc})", file=sys.stderr)
        return 0

    if ns.report_only:
        threats_by_id = {
            (t.get("t_id") or t.get("id") or "").strip().upper(): t
            for t in (data.get("threats") or [])
            if isinstance(t, dict)
        }
        for m in data.get("mitigations") or []:
            if not isinstance(m, dict):
                continue
            original = (m.get("_title_source") or m.get("title") or "").strip()
            cwe = _first_cwe(m, threats_by_id)
            print(f"{m.get('id')}: [{cwe or '—'}] {original!r} -> {generalize_title(original, cwe)!r}")
        return 0

    n = apply(data)
    if n:
        tmp = yaml_path.with_suffix(".yaml.tmp")
        tmp.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096), encoding="utf-8")
        tmp.replace(yaml_path)
    print(f"emit_general_mitigation_titles: generalized {n} mitigation title(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
