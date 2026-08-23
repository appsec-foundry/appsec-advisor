#!/usr/bin/env python3
"""Normalise finding TITLES to a weakness class plus a single-location suffix.

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

This emitter rewrites ``threats[].title`` to a normalised weakness phrase
(implementation mechanism after ``via`` removed, embedded file tokens /
parentheticals stripped). A single-location finding adds one compact
``file:line`` locator; a consolidated multi-location finding stays class-only.
Its full location set remains available in the §8 Instances row and YAML.

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


def _has_multiple_instance_locations(threat: dict) -> bool:
    """Whether a consolidated finding has more than one distinct location."""
    locations: set[tuple[str, int | None]] = set()
    for instance in threat.get("instances") or []:
        if not isinstance(instance, dict):
            continue
        file = (instance.get("file") or "").strip()
        if not file:
            continue
        line = instance.get("line")
        locations.add((file, line if isinstance(line, int) and line > 0 else None))
    return len(locations) > 1


def clean_weakness(raw_title: str) -> str:
    """Extract the clean weakness-class phrase from a verbose finding title."""
    s = (raw_title or "").strip()
    if not s:
        return s
    # Drop the leading "F-NNN — " / "T-NNN — " prefix if present.
    s = re.sub(r"^[FT]-\d+\s*[—–-]\s*", "", s)
    # Drop parenthetical asides (file / param / payload).
    s = re.sub(r"\s*\([^()]*\)\s*", " ", s)
    # Drop single-quoted literal values / payloads (e.g. 'pass****', 'none').
    s = re.sub(r"\s*'[^']*'\s*", " ", s)
    # Drop the implementation mechanism after `via` / `using` / `through`
    # ("via eval", "via DomSanitizer.trust HTML bypass", "using notevil").
    s = re.sub(r"\s+(?:via|using|through)\s+.*$", "", s, flags=re.IGNORECASE)
    # Drop any embedded file token (`routes/fileUpload.ts:45`, `Dockerfile:5`).
    s = _FILE_TOKEN_RE.sub("", s)
    # Drop " on:<line>" line-reference artefacts (e.g. "on:6") — placed after the
    # file-token strip so that "— SymmetricAlgoKeys.json:6" is already gone and a
    # bare "on:6" remainder is cleaned up here too.
    s = re.sub(r"\s+on:\d+", "", s)
    # Drop a trailing truncation fragment the author left ("… no Depend…").
    s = re.sub(r"\s*…\S*$", "", s)
    # Drop a now-dangling trailing preposition (was "… in <file>" before strip).
    s = re.sub(r"\s+(?:in|at|for|inside|within|on|of)\s*$", "", s, flags=re.IGNORECASE)
    # Tidy whitespace and dangling separators.
    s = re.sub(r"\s{2,}", " ", s).strip(" -—–:,.")
    for pat, repl in _ACRONYM_FIX.items():
        s = re.sub(pat, repl, s)
    return _force_pattern_lead(s)


def _force_pattern_lead(s: str) -> str:
    """Guarantee the schema's ``^[A-Z]`` lead on the derived title.

    This module declares itself the single point responsible for schema-clean
    titles, but enforced only the *lower-case* half: ``s[0].islower()`` is
    False for a digit, path, quote or underscore, and ``.upper()`` is the
    identity on all of them. Because the title is re-derived from the stashed
    original on every run, a ``14 Named Accounts …`` source came back **after**
    the schema gate had passed, leaving an invalid yaml on disk with nothing
    downstream to catch it (2026-08-21,
    ``analysis-title-contract-abort-2026-08-21.md``).

    Sibling of ``build_threat_model_yaml._ensure_pattern_lead``, which owns the
    same rule before the gate and additionally reports when the repair costs
    information; here that loss is already accounted for upstream.
    """
    s = (s or "").strip()
    if not s or s[0].isupper():
        return s
    if s[0].isalpha():
        return s[0].upper() + s[1:]
    match = re.search(r"[A-Za-z]", s)
    if not match:
        return s
    kept = s[match.start() :].strip()
    if kept.count('"') % 2:
        kept = kept.replace('"', "").strip()
    return (kept[0].upper() + kept[1:]) if kept else s


# Constraints for threats[].title, read from the schema that actually gates the
# run rather than restated here. This module is the single point responsible for
# producing schema-clean titles, so it MUST enforce ALL of them — restating one
# constraint at a time is how the same abort kept recurring: the >80-char cap and
# the ``^[A-Z]`` lead were each added after a run died on them, and `minLength`
# was still missing until an "SSRF via <detail>" source reduced to a 4-char
# weakness class and aborted context-v2-finalize (2026-08-22). Every acronym in
# ``_ACRONYM_FIX`` sits below that floor, so the gap was structural, not a
# one-off. Deriving the set from the schema keeps them in lockstep.
_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "threat-model.output.schema.yaml"


def _load_title_constraints() -> tuple[int, int, re.Pattern[str] | None, tuple[re.Pattern[str], ...]]:
    """Return (minLength, maxLength, pattern, forbidden) for threats[].title.

    Falls back to the historical literals when the schema cannot be read, so a
    packaging accident degrades to today's behaviour instead of crashing the
    emitter mid-pipeline.
    """
    try:
        spec = yaml.safe_load(_SCHEMA_PATH.read_text(encoding="utf-8")) or {}
        title = spec["properties"]["threats"]["items"]["properties"]["title"]
    except (OSError, yaml.YAMLError, KeyError, TypeError):
        return 10, 80, None, ()
    raw_pattern = title.get("pattern")
    forbidden = tuple(
        re.compile(entry["pattern"])
        for entry in (title.get("not") or {}).get("anyOf") or []
        if isinstance(entry, dict) and entry.get("pattern")
    )
    return (
        int(title.get("minLength", 10)),
        int(title.get("maxLength", 80)),
        re.compile(raw_pattern) if raw_pattern else None,
        forbidden,
    )


_MIN_TITLE_LEN, _MAX_TITLE_LEN, _TITLE_PATTERN, _TITLE_FORBIDDEN = _load_title_constraints()


def _schema_ok(title: str) -> bool:
    """Whether ``title`` satisfies every threats[].title constraint."""
    if not title or not (_MIN_TITLE_LEN <= len(title) <= _MAX_TITLE_LEN):
        return False
    if _TITLE_PATTERN is not None and not _TITLE_PATTERN.match(title):
        return False
    return not any(bad.search(title) for bad in _TITLE_FORBIDDEN)


def _sanitize_for_schema(title: str) -> str:
    """Strip what the title pattern and payload blocklist forbid.

    Only ever applied to a candidate that already failed ``_schema_ok`` — a
    valid title is returned untouched by ``build_clean_title`` and never reaches
    this function.
    """
    s = re.sub(r"[@`]", "", title or "")
    for bad in _TITLE_FORBIDDEN:
        s = bad.sub("", s)
    # The pattern permits at most one trailing parenthetical; keep the last
    # (the locator) and drop earlier asides.
    parenthesised = re.findall(r"\([^()]*\)", s)
    if len(parenthesised) > 1:
        body = re.sub(r"\([^()]*\)", "", s).strip()
        s = f"{body} {parenthesised[-1]}"
    # Removing a mechanism token can leave the connector that introduced it.
    s = re.sub(r"\s+(?:via|using|through)\s*\(", " (", s, flags=re.IGNORECASE)
    s = re.sub(r"\s+(?:via|using|through)\s*$", "", s, flags=re.IGNORECASE)
    s = re.sub(r"\s{2,}", " ", s).strip(" -—–:,.")
    return _force_pattern_lead(_truncate_to_words(s, _MAX_TITLE_LEN))


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


def _derive_title(raw_title: str, threat: dict) -> str:
    """The canonical derivation: weakness class plus at most one locator."""
    weakness = clean_weakness(raw_title)
    if not weakness:
        return (raw_title or "").strip()
    # Source-auth / config check names arrive as "Weakness class — qualifying
    # clause" (their own em-dash). The canonical title carries only the weakness
    # CLASS; the qualifier is detail that belongs in the §8 card, not the title.
    # clean_weakness has already stripped any trailing file token, so an em-dash
    # remaining here is the check-name's internal "class — qualifier" separator.
    weakness = re.split(r"\s+[—–-]\s+", weakness, maxsplit=1)[0].strip()
    # Consolidated findings own several concrete locations. A representative
    # path in their title looks authoritative while hiding the rest, so only a
    # single-location finding gets the compact locator suffix.
    loc = ""
    if not _has_multiple_instance_locations(threat):
        # The authoritative locator is the evidence file:line (the
        # title-embedded token is often a truncated / basename-only echo).
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


def build_clean_title(raw_title: str, threat: dict) -> str:
    """Canonical title for one threat, enforced against the output schema.

    The derivation above is authoritative whenever it already satisfies the
    schema, so a well-formed source keeps exactly the title it had. Only a
    candidate that would abort the run falls through to progressively less
    normalised alternatives — the bare weakness class, then the original title —
    each also tried with the forbidden characters and payload tokens removed.

    A short weakness class is the recurring trigger: stripping "via <detail>"
    from "SSRF via Unvalidated URL Parameter" yields a correct class that is
    below ``minLength``, and a multi-instance finding gets no locator suffix to
    carry it over the floor. Falling back to the raw title fixes that case but
    not the sibling cases, because the raw title is precisely where the blocked
    payload tokens live — hence the candidate chain rather than one fallback.
    """
    primary = _derive_title(raw_title, threat)
    if _schema_ok(primary):
        return primary
    for candidate in (
        primary,
        _truncate_to_words(clean_weakness(raw_title), _MAX_TITLE_LEN),
        _truncate_to_words((raw_title or "").strip(), _MAX_TITLE_LEN),
    ):
        for variant in (candidate, _sanitize_for_schema(candidate)):
            if _schema_ok(variant):
                return variant
    # Nothing satisfied the schema. Return the canonical derivation so the
    # invalid title stays visible to the validator instead of being masked by a
    # worse-but-passing string; main() reports it by id.
    return primary


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
    # Name what this module could not bring into contract. Without this the
    # only signal is a schema abort several stages later, pointing at an array
    # index rather than at the title that caused it.
    unresolved = [
        f"{t.get('id')}: {t.get('title')!r}"
        for t in data.get("threats") or []
        if isinstance(t, dict) and t.get("title") and not _schema_ok(str(t["title"]))
    ]
    for entry in unresolved:
        print(f"emit_clean_finding_titles: title violates threats[].title schema — {entry}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
