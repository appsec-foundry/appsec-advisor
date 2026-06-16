#!/usr/bin/env python3
"""Normalise finding TITLES to ``<weakness class> — <file[:line]>``.

Problem
-------
Stage-1 authors verbose, code-laden finding titles that then render in every
cross-reference cell (§2 Top-Threats, §4 Assets, §2.3 Components, §8 register):

    "Stored XSS via DomSanitizer.trust HTML bypass in last-login-ip.component.html:10"
    "Server-Side Template Injection via eval (routes/userProfile.ts:62)"
    "Vm sandbox escape via notevil routes/b2bOrder.ts:23"

and the compact xref label appends ``(file, "param")`` on top — so a cell reads
``F-017 — Stored XSS via DomSanitizer.trust HTML bypass in last-login-ip…
(frontend/src/app/…/last-login-ip.component.html, "lastLoginIp (bound via
[innerHTML])")``. The title contract (``agents`` finding-title rule) is
``<weakness class> — <file[:line]>`` ONLY — no payloads, parameters, or code.

This emitter rewrites ``threats[].title`` to that clean form: a normalised
weakness phrase (implementation mechanism after ``via`` removed, embedded file
tokens / parentheticals stripped) plus a single compact ``file:line`` locator.
The full file path, parameter, and remediation detail remain available in the
§8 card's Location / Evidence / How rows and the YAML evidence block.

Idempotent: the original title is stashed in ``_title_source`` and re-derived
from it each run, so the canonical title never drifts.

Usage
-----
    python3 scripts/emit_clean_finding_titles.py <output-dir> [--report-only]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

# A file token must end in a KNOWN source/config extension (or be a bare
# `Dockerfile`), else code identifiers like `DomSanitizer.trust`,
# `vm.runInContext`, `yaml.load` get mis-parsed as files. Optional `:line` or
# `:line-range`.
_FILE_EXT = (
    r"ts|tsx|js|jsx|mjs|cjs|json|ya?ml|html?|xml|md|py|rb|go|java|php|sh|sql|"
    r"env|toml|ini|cfg|conf|lock|gradle|properties|css|scss|vue|svelte"
)
_FILE_TOKEN_RE = re.compile(
    r"[`'\"]?("
    r"(?:[\w./\\-]+/)?[\w.-]+\.(?:" + _FILE_EXT + r")"
    r"|Dockerfile(?:\.[\w-]+)?"
    r")(:\d+(?:-\d+)?)?[`'\"]?",
    re.IGNORECASE,
)
# Common acronyms whose Stage-1 casing drifts ("Vm" → "VM").
_ACRONYM_FIX = {
    r"\bVm\b": "VM",
    r"\bXss\b": "XSS",
    r"\bSqli\b": "SQLi",
    r"\bSsrf\b": "SSRF",
    r"\bXxe\b": "XXE",
    r"\bIdor\b": "IDOR",
    r"\bJwt\b": "JWT",
    r"\bRce\b": "RCE",
    r"\bCsrf\b": "CSRF",
}


def _basename_loc(token: str) -> str:
    """`frontend/src/app/x/last-login-ip.component.html:10` ->
    `last-login-ip.component.html:10`; keep an already-short `routes/login.ts:34`
    relative path as-is (one directory segment reads fine and disambiguates)."""
    if token.count("/") <= 1:
        return token
    base = token.rsplit("/", 1)[-1]
    return base


def _evidence_loc(threat: dict) -> str:
    ev = threat.get("evidence")
    if isinstance(ev, dict):
        ev = [ev]
    elif not isinstance(ev, list):
        ev = []
    if ev and isinstance(ev[0], dict):
        f = (ev[0].get("file") or "").strip()
        ln = ev[0].get("line")
        if f:
            return f"{f}:{ln}" if ln else f
    return ""


def clean_weakness(raw_title: str) -> str:
    """Extract the clean weakness-class phrase from a verbose finding title."""
    s = (raw_title or "").strip()
    if not s:
        return s
    # Drop the leading "F-NNN — " / "T-NNN — " prefix if present.
    s = re.sub(r"^[FT]-\d+\s*[—–-]\s*", "", s)
    # Drop parenthetical asides (file / param / payload).
    s = re.sub(r"\s*\([^()]*\)\s*", " ", s)
    # Drop the implementation mechanism after `via` / `using` / `through`
    # ("via eval", "via DomSanitizer.trust HTML bypass", "using notevil").
    s = re.sub(r"\s+(?:via|using|through)\s+.*$", "", s, flags=re.IGNORECASE)
    # Drop any embedded file token (`routes/fileUpload.ts:45`, `Dockerfile:5`).
    s = _FILE_TOKEN_RE.sub("", s)
    # Drop a trailing truncation fragment the author left ("… no Depend…").
    s = re.sub(r"\s*…\S*$", "", s)
    # Drop a now-dangling trailing preposition (was "… in <file>" before strip).
    s = re.sub(r"\s+(?:in|at|for|inside|within|on|of)\s*$", "", s, flags=re.IGNORECASE)
    # Tidy whitespace and dangling separators.
    s = re.sub(r"\s{2,}", " ", s).strip(" -—–:,.")
    for pat, repl in _ACRONYM_FIX.items():
        s = re.sub(pat, repl, s)
    if s and s[0].islower():
        s = s[0].upper() + s[1:]
    return s


# Schema ceiling for threats[].title (schemas/threat-model.output.schema.yaml).
# emit_clean_finding_titles is the single point responsible for producing
# schema-clean titles, so it MUST enforce this — otherwise a verbose source
# (e.g. the source-auth scanner's "Class — qualifier clause" check names) ships
# a >80-char title that fails validate_intermediate.
_MAX_TITLE_LEN = 80


def _truncate_to_words(text: str, budget: int) -> str:
    """Trim ``text`` to at most ``budget`` chars on a word boundary, with no
    trailing ellipsis or separator (keeps the schema title pattern happy)."""
    text = text.strip()
    if len(text) <= budget:
        return text
    cut = text[:budget]
    # Back up to the last whitespace so we never split a word.
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut.strip(" -—–:,.")


def build_clean_title(raw_title: str, threat: dict) -> str:
    weakness = clean_weakness(raw_title)
    if not weakness:
        return (raw_title or "").strip()
    # Source-auth / config check names arrive as "Weakness class — qualifying
    # clause" (their own em-dash). The canonical title carries only the weakness
    # CLASS; the qualifier is detail that belongs in the §8 card, not the title.
    # clean_weakness has already stripped any trailing file token, so an em-dash
    # remaining here is the check-name's internal "class — qualifier" separator.
    weakness = re.split(r"\s+[—–-]\s+", weakness, maxsplit=1)[0].strip()
    # The authoritative locator is the evidence file:line (the title-embedded
    # token is often a truncated / basename-only echo). Compact it to a basename
    # when it is a deep path.
    loc = _basename_loc(_evidence_loc(threat))
    if not loc:
        m = _FILE_TOKEN_RE.search(raw_title or "")
        loc = _basename_loc((m.group(1) + (m.group(2) or "")) if m else "")
    # Hard length enforcement: a weakness class that is still too long (verbose
    # check name with no em-dash to split on) is truncated on a word boundary so
    # the rendered "<weakness> — <loc>" fits the schema's 80-char ceiling.
    if loc:
        budget = _MAX_TITLE_LEN - len(loc) - len(" — ")
        if len(weakness) > budget:
            weakness = _truncate_to_words(weakness, max(budget, 24))
        title = f"{weakness} — {loc}"
        if len(title) > _MAX_TITLE_LEN:  # loc alone is huge — last-resort guard
            title = _truncate_to_words(title, _MAX_TITLE_LEN)
        return title
    return _truncate_to_words(weakness, _MAX_TITLE_LEN)


def apply(data: dict) -> int:
    changed = 0
    for t in data.get("threats") or []:
        if not isinstance(t, dict):
            continue
        original = (t.get("_title_source") or t.get("title") or "").strip()
        if not original:
            continue
        new = build_clean_title(original, t)
        if new and new != (t.get("title") or "").strip():
            t["_title_source"] = original
            t["title"] = new
            changed += 1
        else:
            t.setdefault("_title_source", original)
    return changed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="emit_clean_finding_titles.py")
    ap.add_argument("output_dir", type=Path)
    ap.add_argument("--report-only", action="store_true")
    ns = ap.parse_args(argv)

    yaml_path = ns.output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"emit_clean_finding_titles: no threat-model.yaml in {ns.output_dir}", file=sys.stderr)
        return 0
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001
        print(f"emit_clean_finding_titles: unreadable yaml ({exc})", file=sys.stderr)
        return 0

    if ns.report_only:
        for t in data.get("threats") or []:
            if not isinstance(t, dict):
                continue
            original = (t.get("_title_source") or t.get("title") or "").strip()
            print(f"{t.get('id')}: {original!r} -> {build_clean_title(original, t)!r}")
        return 0

    n = apply(data)
    if n:
        tmp = yaml_path.with_suffix(".yaml.tmp")
        tmp.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096), encoding="utf-8")
        tmp.replace(yaml_path)
    print(f"emit_clean_finding_titles: cleaned {n} finding title(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
