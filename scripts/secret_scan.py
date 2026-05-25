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
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
        ),
        True,
    ),
    _Pattern(
        "pem_private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
        ),
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
            r"\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|bearer|token|auth)"
            r"\s*[=:]\s*"
            r"['\"]?(?P<val>[A-Za-z0-9_\-+/=\.]{8,})['\"]?"
        ),
        False,
    ),
]


@dataclass(frozen=True)
class SecretHit:
    pattern: str
    snippet: str
    line: int

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
            value = m.group("val") if "val" in (m.groupdict() or {}) else matched
            if not pat.strict and _value_is_masked(value):
                continue
            snippet = matched[:80].replace("\n", " ")
            hits.append(SecretHit(pattern=pat.name, snippet=snippet, line=line_of(m.start())))
    return hits


def scan_file(path: Path) -> list[SecretHit]:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return []
    return scan_text(text)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: secret_scan.py <file> [<file>...]", file=sys.stderr)
        return 2
    any_hit = False
    for arg in argv[1:]:
        for hit in scan_file(Path(arg)):
            print(f"{arg}:{hit.render()}")
            any_hit = True
    return 1 if any_hit else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
