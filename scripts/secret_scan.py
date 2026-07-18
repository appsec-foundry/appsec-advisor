#!/usr/bin/env python3
"""Detect raw, unmasked secrets in rendered threat-model artifacts.

Single source of truth used by both:
  - scripts/qa_checks.py            (mandatory per-run QA gate)
  - scripts/publish_threat_model.py (publish-time gate)

A hit means the value still looks like a raw, reusable secret. Values that
contain any masking marker (``****``, ``[REDACTED]``, ``<…>``, ``XXXX``,
``MASKED``) are treated as already-masked and skipped, so properly redacted
snippets like ``AIza****`` or ``password=**** (12 chars)`` do not trigger.

Run as a script for ad-hoc scans:

    python scripts/secret_scan.py path/to/threat-model.md
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

# Markers that indicate a value has already been masked / redacted.
# A loose-pattern match whose captured value contains any of these is skipped.
_MASKING_MARKERS = (
    "****",
    "[REDACTED]",
    "<REDACTED>",
    "<...>",
    "<…>",
    "MASKED",
    "XXXX",
    "xxxx",
    "…",
)


@dataclass(frozen=True)
class _Pattern:
    name: str
    regex: re.Pattern[str]
    # strict=True: the regex enforces an exact format (length, charset). A
    # match is a real leak regardless of nearby masking markers, because the
    # format would not survive a partial mask.
    strict: bool


_PATTERNS: list[_Pattern] = [
    # --- Strict format patterns (a match = real leak) -----------------------
    _Pattern("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), True),
    _Pattern("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), True),
    _Pattern("github_oauth", re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), True),
    _Pattern("github_app", re.compile(r"\bghs_[A-Za-z0-9]{36}\b"), True),
    _Pattern("github_refresh", re.compile(r"\bghr_[A-Za-z0-9]{36}\b"), True),
    _Pattern("github_finegrained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"), True),
    _Pattern("google_api_key", re.compile(r"\bAIza[A-Za-z0-9_\-]{35}\b"), True),
    _Pattern("slack_token", re.compile(r"\bxox[bpoars]-[A-Za-z0-9-]{10,}\b"), True),
    _Pattern("stripe_live_secret", re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"), True),
    _Pattern("stripe_test_secret", re.compile(r"\bsk_test_[A-Za-z0-9]{24,}\b"), True),
    _Pattern(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        True,
    ),
    _Pattern(
        "pem_private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
        True,
    ),
    # --- Loose key/value patterns (mask-marker exempts) ---------------------
    # Examples flagged:
    #   password = "admin123"
    #   API_KEY: sk_abcdef1234
    #   secret='hunter2longer'
    # Examples ignored (mask marker present):
    #   password = "****"
    #   API_KEY: AIza****
    #   secret="**** (12 chars)"
    _Pattern(
        "generic_credential_assignment",
        re.compile(
            r"(?ix)"
            r"\b(?P<kw>password|passwd|pwd|secret|api[_-]?key|access[_-]?key|bearer|token|auth)"
            r"\s*(?P<op>[=:])\s*"
            r"(?P<q>['\"])?(?P<val>[A-Za-z0-9_\-+/=\.]{8,})"
        ),
        False,
    ),
]


# An unquoted credential-assignment value that is a code-identifier reference
# (camelCase / PascalCase / dotted attribute path, no digits) — e.g.
# ``secret: publicKey`` or ``password: security.hash`` — is a reference to a
# variable in a code excerpt, not a literal secret value, and must not be
# flagged. Quoted values and opaque/digit-bearing strings (``abcdefghijklmnop``,
# ``deadbeef1234``) are NOT excluded — those stay flagged.
_CODE_REFERENCE_RE = re.compile(
    r"^(?:"
    r"[A-Za-z_]+(?:\.[A-Za-z_]+)+"  # dotted path:  security.hash
    r"|[a-z]+[A-Z][A-Za-z]*"  # camelCase:    publicKey
    r"|[A-Z][a-z]+[A-Z][A-Za-z]*"  # PascalCase:   PublicKey
    r")$"
)


def _looks_like_code_reference(value: str) -> bool:
    return bool(_CODE_REFERENCE_RE.match(value))


def _is_keyword_echo_value(value: str, keyword: str | None, quoted: bool) -> bool:
    """An unquoted loose-pattern value that echoes its OWN credential keyword —
    ``password=password``, ``secret=secret``, ``token=token`` — is a tautological
    documentation placeholder, never a reusable secret. Skipping it is not merely
    cosmetic: the exact-value pass in redact_known_secrets does a blind
    ``text.replace(value, mask)`` over every artifact, and these keyword words
    (``password``, ``secret``, ``token``, ``auth`` …) are exactly the terms that
    saturate a security report's prose and its anchor slugs. Observed on the
    2026-07-16 insecure-spring-app run: ``password=password`` in the README
    collapsed 942 occurrences to ``pass**** (8 chars)``, breaking the §6.2
    ``#password-based-authentication`` anchor. A genuine secret is never the
    literal echo of its keyword, so this can never hide a real leak. Quoted
    values stay flagged (an intentional literal is masked in place, not blindly
    replaced document-wide)."""
    if quoted or not keyword:
        return False
    norm = lambda s: s.lower().replace("-", "").replace("_", "")  # noqa: E731
    return norm(value) == norm(keyword)


# A plain lowercase English word (no digits, no separators) — e.g. "existing",
# "required", "rotated". On its own this is not enough to skip (a weak password
# could be a lowercase word), so it is only honoured in prose context below.
_PROSE_WORD_RE = re.compile(r"^[a-z]{4,}$")


def _is_prose_credential_false_positive(value: str, op: str | None, quoted: bool, text: str, start: int) -> bool:
    """A credential keyword appearing mid-sentence in prose is not an
    assignment. Example false positive that blocked a release on the
    2026-06-05 juice-shop run::

        - 'Rotate the secret: existing SecurityAnswers rows are invalidated…'

    Here ``secret: existing`` is an English sentence, not ``secret = <literal>``.
    The guard is deliberately narrow so a genuine literal can never slip
    through — ALL of the following must hold:

    * unquoted value (a quoted value stays flagged),
    * the operator is ``:`` (prose uses a colon; ``=`` is assignment syntax),
    * the value is a plain lowercase word (a real secret carries digits / mixed
      case / token shape, which fails ``_PROSE_WORD_RE``),
    * the keyword is preceded on the same line by a word + whitespace, i.e. it
      sits inside a sentence rather than at a key / assignment position
      (``  secret: x`` as a YAML key is preceded by indent only and stays
      flagged).
    """
    if quoted or op != ":":
        return False
    if not _PROSE_WORD_RE.match(value):
        return False
    line_start = text.rfind("\n", 0, start) + 1
    before = text[line_start:start]
    return bool(re.search(r"[A-Za-z]{2,}\s+$", before))


def _is_identifier_suffix_keyword(text: str, start: int, op_start: int) -> bool:
    """A credential keyword that is the trailing segment of a SCREAMING-KEBAB
    identifier — e.g. ``SEC-USER-AUTH: Authenticate users…`` in a requirements
    table — is an ID label, not a ``password = <literal>`` assignment.

    The 2026-06-18 e2e run masked the requirement-title word "Authenticate"
    because ``-AUTH:`` matched the ``auth`` keyword and the value (a capitalised
    English word) escaped both the code-reference and prose-word guards. Guard:
    the keyword is immediately preceded by a hyphen AND carries an uppercase
    letter. Real config keys are lowercase (``client-secret``, ``api_key``,
    ``x-auth``), so a genuine ``client-secret: <literal>`` stays flagged.
    """
    if start == 0 or text[start - 1] != "-":
        return False
    keyword = text[start:op_start]
    return any(c.isupper() for c in keyword)


@dataclass(frozen=True)
class SecretHit:
    pattern: str
    snippet: str
    line: int
    value: str = ""  # the raw secret value (for exact-match redaction)

    def render(self) -> str:
        return f"line {self.line}: [{self.pattern}] {self.snippet!r}"


def _value_is_masked(value: str) -> bool:
    return any(marker in value for marker in _MASKING_MARKERS)


def _line_lookup(text: str):
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)

    def line_of(pos: int) -> int:
        # Binary search — large reports can be tens of thousands of lines.
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    return line_of


def scan_text(text: str) -> list[SecretHit]:
    """Return list of SecretHits — empty list means clean."""
    if not text:
        return []
    line_of = _line_lookup(text)
    hits: list[SecretHit] = []
    for pat in _PATTERNS:
        for m in pat.regex.finditer(text):
            matched = m.group(0)
            groups = m.groupdict() or {}
            value = m.group("val") if "val" in groups else matched
            if not pat.strict:
                if _value_is_masked(value):
                    continue
                # Unquoted code-identifier reference (variable name in an
                # excerpt), not a literal secret — skip. Quoted values flag.
                if not groups.get("q") and _looks_like_code_reference(value):
                    continue
                # Credential keyword used mid-sentence in prose (e.g.
                # "Rotate the secret: existing rows…") — not an assignment.
                if _is_prose_credential_false_positive(value, groups.get("op"), bool(groups.get("q")), text, m.start()):
                    continue
                # Screaming-kebab identifier suffix (requirement IDs like
                # SEC-USER-AUTH:) — an ID label, not a credential assignment.
                if "op" in groups and _is_identifier_suffix_keyword(text, m.start(), m.start("op")):
                    continue
                # Keyword-echo placeholder (``password=password``) — a doc
                # sample, not a reusable secret. Skipping it keeps the exact-value
                # redactor from corrupting prose/anchors document-wide.
                if _is_keyword_echo_value(value, groups.get("kw"), bool(groups.get("q"))):
                    continue
            snippet = matched[:80].replace("\n", " ")
            hits.append(SecretHit(pattern=pat.name, snippet=snippet, line=line_of(m.start()), value=value))
    return hits


def scan_file(path: Path) -> list[SecretHit]:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return []
    return scan_text(text)


def _mask_match(pat: _Pattern, m: re.Match[str]) -> str:
    """Return the redacted replacement for a single secret match, following
    agents/shared/secret-handling.md: PEM markers fully redacted, strict token
    formats keep their first 4 chars + ``****``, credential assignments keep the
    key/operator/quote prefix and replace only the value with ``**** (N chars)``.
    The replacement always contains a masking marker so the value can never be
    re-flagged by scan_text()."""
    matched = m.group(0)
    if pat.name == "pem_private_key":
        return "[PEM PRIVATE KEY — REDACTED]"
    if pat.strict:
        # Token formats (AWS/GitHub/Google/Slack/Stripe/JWT/…). Keeping the
        # first 4 chars preserves provider identification while breaking the
        # strict format regex so the leak is neutralised.
        return matched[:4] + "****"
    # generic_credential_assignment — mask only the captured value, preserve the
    # key + operator + opening quote so the line stays readable and valid.
    value = m.group("val")
    prefix = matched[: m.start("val") - m.start(0)]
    return f"{prefix}**** ({len(value)} chars)"


def mask_text(text: str) -> tuple[str, list[str]]:
    """Redact every secret that scan_text() would flag — the masking twin of
    the detector. Because both walk the SAME ``_PATTERNS`` with the SAME skip
    rules (already-masked markers, unquoted code-identifier references), any
    document passed through mask_text() is guaranteed to pass the
    unmasked_secrets gate. Returns ``(masked_text, applied_pattern_names)``.

    This is the single masking source of truth shared by the composer (rendered
    markdown) and scripts/mask_secrets.py (threat-model.yaml evidence excerpts),
    so detection and redaction can never drift apart again."""
    if not text:
        return text, []
    applied: list[str] = []
    for pat in _PATTERNS:

        def _repl(m: re.Match[str], _pat: _Pattern = pat) -> str:
            groups = m.groupdict() or {}
            value = m.group("val") if "val" in groups else m.group(0)
            if not _pat.strict:
                if _value_is_masked(value):
                    return m.group(0)
                if not groups.get("q") and _looks_like_code_reference(value):
                    return m.group(0)
                # Mirror the detector's prose guard so masking never corrupts a
                # remediation sentence like "Rotate the secret: existing rows…".
                if _is_prose_credential_false_positive(value, groups.get("op"), bool(groups.get("q")), text, m.start()):
                    return m.group(0)
                # Mirror the detector's identifier-suffix guard so masking never
                # corrupts a requirements row like "SEC-USER-AUTH: Authenticate…".
                if "op" in groups and _is_identifier_suffix_keyword(text, m.start(), m.start("op")):
                    return m.group(0)
                # Mirror the detector's keyword-echo guard so masking never
                # corrupts a doc example like "password=password".
                if _is_keyword_echo_value(value, groups.get("kw"), bool(groups.get("q"))):
                    return m.group(0)
            applied.append(_pat.name)
            return _mask_match(_pat, m)

        text = pat.regex.sub(_repl, text)
    # de-dup while preserving first-seen order
    seen: dict[str, None] = {}
    for name in applied:
        seen.setdefault(name, None)
    return text, list(seen.keys())


def mask_file(path: Path) -> list[str]:
    """Mask secrets in ``path`` in place. Returns the applied pattern names
    (empty list when nothing changed). Best-effort: unreadable files no-op."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    masked, applied = mask_text(text)
    if applied and masked != text:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(masked, encoding="utf-8")
        tmp.replace(path)
    return applied


def main(argv: list[str]) -> int:
    args = argv[1:]
    do_mask = False
    if args and args[0] == "--mask":
        do_mask = True
        args = args[1:]
    if not args:
        print("usage: secret_scan.py [--mask] <file> [<file>...]", file=sys.stderr)
        return 2
    if do_mask:
        # In-place redaction mode — masks every secret the scanner would flag so
        # the unmasked_secrets gate cannot subsequently trip on these files.
        for arg in args:
            applied = mask_file(Path(arg))
            if applied:
                print(f"{arg}: masked {', '.join(applied)}")
        return 0
    any_hit = False
    for arg in args:
        for hit in scan_file(Path(arg)):
            print(f"{arg}:{hit.render()}")
            any_hit = True
    return 1 if any_hit else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
