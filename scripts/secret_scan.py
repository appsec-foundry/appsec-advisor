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

import base64
import binascii
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

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

# The credential keywords that make a nearby literal look like a credential.
# Named because redact_known_secrets reuses it to decide whether an occurrence
# sits in credential context; a second hand-maintained copy there would drift
# out of sync with this one.
CREDENTIAL_KEYWORDS = r"password|passwd|pwd|secret|api[_-]?key|access[_-]?key|bearer|token|auth"


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
            # ``(?<=_)`` admits the keyword as the tail of an env-style
            # identifier — ``DB_PASSWORD=``, ``MYSQL_ROOT_PASSWORD:``,
            # ``X_AUTH_TOKEN=`` — which a bare ``\b`` rejects because ``_`` is a
            # word character. Those are the canonical shapes in .env files,
            # docker-compose, and k8s manifests, so a report quoting one used to
            # pass the release gate with the credential in cleartext.
            #
            # Only ``_`` is admitted. Dropping ``\b`` outright would also match
            # a keyword ending any word, re-opening the false-positive class the
            # guards below exist for: a heading like ``## OAuth: Configuration``
            # would be masked as a secret.
            #
            # The operator padding is ``[ \t]*`` and not ``\s*`` because an
            # assignment is a single-line construct: the keyword, the operator
            # and the value stand on one line. ``\s*`` crossed the line break,
            # so a line ENDING in the operator captured the next line's first
            # token as its value — an entry point ``GET /api/audit?token=``
            # followed by ``  protocol: HTTP`` masked the YAML KEY into
            # ``  **** (8 chars): HTTP``, and the unparseable threat-model.yaml
            # aborted the run at the controller gate (2026-09-05
            # insecure-python-app). Structured artifacts are rewritten by this
            # masker, so a match that spans lines destroys their shape. A
            # two-line k8s ``name:``/``value:`` pair is out of reach by the same
            # rule, as is a secret placed on the line below its key.
            r"(?:\b|(?<=_))(?P<kw>" + CREDENTIAL_KEYWORDS + r")"
            r"[ \t]*(?P<op>[=:])[ \t]*"
            # The value charset must cover password punctuation. It previously
            # stopped at the first character outside [A-Za-z0-9_\-+/=.], so a
            # credential like ``'J6aVjTgOpRs@?5l!…'`` matched only its 11-char
            # alnum head — and _mask_match() then replaced just that head,
            # shipping the remaining 19 characters in cleartext right after the
            # ``**** (11 chars)`` marker (2026-07-25 juice-shop run). Because
            # scan_text() re-checks with this same regex, the residual tail no
            # longer sits behind a credential keyword and the release gate
            # reported zero issues on a leaking document. Only alnum passwords
            # masked correctly; every password with a special character leaked
            # its tail.
            #
            # Whitespace, quotes, backticks, backslash, ``:``, ``<>``, ``{}``
            # and the markdown-active characters ``*()~&^`` stay OUT: the value
            # is consumed by redact_known_secrets' blind document-wide
            # ``text.replace(value, mask)``, so a capture that can swallow a
            # sentence, a URL (``:``), or markdown emphasis would corrupt the
            # report — the failure mode already recorded in
            # _is_keyword_echo_value below.
            r"(?P<q>['\"])?(?P<val>[A-Za-z0-9_\-+/=\.!@#$%?]{8,})"
        ),
        False,
    ),
]


# An unquoted credential-assignment value that is a code-identifier reference
# (camelCase / PascalCase / snake_case / dotted attribute path, no digits) — e.g.
# ``secret: publicKey`` or ``password: security.hash`` — is a reference to a
# variable in a code excerpt, not a literal secret value, and must not be
# flagged. Quoted values and opaque/digit-bearing strings (``abcdefghijklmnop``,
# ``deadbeef1234``) are NOT excluded — those stay flagged.
_CODE_REFERENCE_RE = re.compile(
    r"^(?:"
    r"[A-Za-z_]+(?:\.[A-Za-z_]+)+"  # dotted path:  security.hash
    r"|[a-z]+[A-Z][A-Za-z]*"  # camelCase:    publicKey
    r"|[A-Z][a-z]+[A-Z][A-Za-z]*"  # PascalCase:   PublicKey
    r"|[a-z]+(?:_[a-z]+)+"  # snake_case:   read_unsigned_jwt_claims
    r"|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"  # env/template: $DB_PASS, ${DB_PASS}
    r"|#[A-Za-z0-9][A-Za-z0-9-]*"  # markdown anchor: #section-anchor
    r")$"
)


# A ```mermaid fenced block. Diagram labels (``participant Auth as "auth.py:84"``)
# routinely match the loose credential-assignment shape; see scan_text().
_MERMAID_FENCE_RE = re.compile(r"^[ \t]*```[ \t]*mermaid\b.*?^[ \t]*```", re.S | re.M)


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


# Trailing sentence punctuation the loose value charclass swallows but that is
# never part of a credential. scan_text() and mask_text() MUST strip the same
# set before consulting the false-positive guards: while only the detector did,
# the guards saw ``presence`` and stayed silent while the masker saw
# ``presence.``, failed _PROSE_WORD_RE on the full stop, and rewrote the
# sentence to ``#access_token= **** (9 chars)`` — a corrupted evidence line in
# every rendered report, with a clean scan afterwards to hide it (juice-shop
# 2026-08-20). Sharing one constant is what keeps the twins in step.
_VALUE_PUNCTUATION = ".,;:!?"

# A natural-language word: letters only, optionally hyphenated ("existing",
# "Authorization", "attacker-controlled"). Every segment is capped at 13 chars
# because that is the longest word a threat model plausibly writes after a
# credential keyword; a longer alphabetic run is more likely a passphrase than
# prose. On its own this is not enough to skip (a weak password could be a
# lowercase word), so it is only honoured in prose context below.
_PROSE_WORD_RE = re.compile(r"^[A-Za-z]{1,13}(?:-[A-Za-z]{1,13})*$")

# At least one vowel — a letters-only run without any is far more likely to be
# an encoded literal ("bcdfghjklmnp") than an English word.
_PROSE_VOWEL_RE = re.compile(r"[aeiouyAEIOUY]")

# The characters that can glue a credential keyword into a larger prose token:
# `#access_token=`, `?api_key=`, `x-auth-token:`. The keyword match itself may
# start mid-token, so sentence position must be measured from the token's left
# edge, not from the keyword.
_TOKEN_CHAR_RE = re.compile(r"[A-Za-z0-9_\-#?&/.]")

# A prose sentence can open a line behind punctuation instead of a word: the
# quote of a JSON/YAML string scalar, a list bullet, a comment marker, a
# blockquote. The backward "a word precedes the keyword" test reads all of
# these as a key position and keeps the line flagged, which is how the prose
# `"LLM_API_KEY: referenced in routes/chat.ts:111 …"` inside a prior run's
# artifact yielded "referenced" as a 10-char credential (juice-shop
# 2026-08-28). Pure indentation is deliberately NOT a lead-in — that is what a
# real `  secret: changeme` YAML key looks like — so at least one marker
# character is required and no alphanumeric may appear before the keyword.
# Relief here only reaches the mid-sentence test; the forward
# sentence-continuation test below still has to pass, and it is what keeps a
# line-final config value flagged.
_PROSE_LEAD_IN_RE = re.compile(r"^\s*[\"'`\-*+#/;>|]+\s*$")

# "The prose sentence continues past the value": another word follows, or the
# clause ends. A clause terminator counts as sentence-shaped only when nothing
# but whitespace, the line end, or a SERIALIZATION WRAPPER follows it.
#
# The wrapper alternative is what makes the guard format-independent. scan_text
# runs over raw bytes, but the same evidence sentence is serialized differently
# per artifact: PyYAML wraps a scalar in `'…'`, JSON/SARIF in `"…"`, an HTML
# cell appends `<br>`, markdown may close a backtick or a parenthesis. Without
# it, only unwrapped markdown reached this test and every other artifact class
# fell through to a false positive — `…routes on #access_token= presence.'`
# masked the English word "presence" as a 9-character credential and blocked
# the release gate on threat-model.yaml (juice-shop 2026-08-20). Because the
# guard still requires an unquoted plain-word value (`_PROSE_WORD_RE`) preceded
# by an English word, tolerating a closing delimiter cannot admit a real
# literal: a credential carries digits or separators and fails that test first.
_SENTENCE_CONTINUES_RE = re.compile(
    r"""(?x)
      \s+[A-Za-z]                            # another word follows
    | [.,;]                                  # or the clause ends, followed by
      (?: \s | $ | ['"`)\]}|] | <br\s*/?> )  # space, EOL, or a wrapper
    """
)


def _is_prose_credential_false_positive(value: str, op: str | None, quoted: bool, text: str, start: int) -> bool:
    """A credential keyword appearing mid-sentence in prose is not an
    assignment. Two false positives that blocked a release::

        - 'Rotate the secret: existing SecurityAnswers rows are invalidated…'
        - 'a URL carrying an attacker-supplied #access_token= fragment; the …'

    Here ``secret: existing`` and ``token= fragment`` are English sentences, not
    ``secret = <literal>``. The second shape is structural for this document
    class: a threat model describes credential handling for a living, so any
    OAuth/JWT/API-key finding risks having the next English word of the sentence
    read as the assigned value.

    The guard is deliberately narrow so a genuine literal can never slip
    through — ALL of the following must hold:

    * unquoted value (a quoted value stays flagged),
    * the value is a natural-language word: letters and inner hyphens only, each
      segment ≤ 13 chars, containing a vowel (a real secret carries digits /
      separators / token shape, which fails ``_PROSE_WORD_RE``),
    * the keyword sits inside a sentence rather than at a key / assignment
      position — measured from the left edge of the whole token, so that
      ``#access_token`` counts as mid-sentence while a bare ``  secret: x``
      YAML key, preceded by indent only, stays flagged,
    * the sentence continues after the value — another word, or a clause-ending
      ``.,;`` followed by whitespace, the line end, or the serialization
      wrapper the artifact happens to use (``'``/``"`` for YAML/JSON scalars,
      ``<br>`` for an HTML cell, a closing backtick or bracket). A config value
      is line-final,
    * the operator is ``:``, or ``=`` **with** whitespace before the value. No
      URL, env file, or query string ever puts a space after ``=``, so this is
      what separates ``token= fragment`` in prose from ``token=<literal>``.
    """
    if quoted:
        return False
    if op not in (":", "="):
        return False
    if not _PROSE_WORD_RE.match(value) or not _PROSE_VOWEL_RE.search(value):
        return False

    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end]
    offset = start - line_start

    # `=` is assignment syntax unless a space separates it from the value.
    if op == "=":
        eq = line.find("=", offset)
        if eq == -1 or not line[eq + 1 : eq + 2].isspace():
            return False

    # Expand left over token characters so a keyword glued into a larger token
    # is judged by where that token sits, not where the keyword does.
    token_start = offset
    while token_start > 0 and _TOKEN_CHAR_RE.match(line[token_start - 1]):
        token_start -= 1
    lead_in = line[:token_start]
    if not re.search(r"[A-Za-z]{2,}\s+$", lead_in) and not _PROSE_LEAD_IN_RE.match(lead_in):
        return False

    # The sentence has to keep going; a config value ends its line.
    after = line[line.find(value, offset) + len(value) :]
    if _SENTENCE_CONTINUES_RE.match(after):
        return True

    # Nothing follows on THIS line — but a serializer that folds long scalars
    # puts the rest of the same sentence on the next one, and the value only
    # looks line-final because of where the fold landed. `yaml.safe_dump(…,
    # width=120)` in build_threat_model_yaml.py does exactly that, so whether an
    # evidence sentence passed this guard depended on its character offset: the
    # same finding blocked the release gate in threat-model.yaml and passed in
    # threat-model.md (juice-shop 2026-08-21). Consult the folded continuation
    # so the verdict is about the sentence, not about the column it broke at.
    return _folded_sentence_continues(text, line_end) if not after.strip() else False


def _folded_sentence_continues(text: str, line_end: int) -> bool:
    """True when the next physical line continues a folded prose sentence.

    Only a continuation is admitted, never a new mapping entry: a folded scalar
    resumes with an ordinary lowercase word (``from an implicit-flow redirect``)
    whereas the next YAML key is ``name:``/``name=`` shaped. Keeping that
    distinction is what stops the unfold from excusing a genuine config value,
    which ends its line with the following key beneath it.
    """
    if line_end >= len(text):
        return False
    next_end = text.find("\n", line_end + 1)
    nxt = text[line_end + 1 : next_end if next_end != -1 else len(text)].strip()
    first = nxt.split(" ", 1)[0] if nxt else ""
    if not first or not first[:1].islower():
        return False
    return not first.rstrip(",.;").endswith((":", "="))


# A JWT header segment that decodes to ``{"alg":"none"}``. An unsigned token
# carries NO signature and therefore no secret material — anyone can mint one
# from scratch, which is the entire point of quoting it. See
# ``_is_non_secret_demo_payload``.
_JWT_SEGMENT_RE = re.compile(r"^eyJ[A-Za-z0-9_\-]+")

# A SQL-injection tautology, percent-decoded: ``' OR '1'='1``, ``" OR 1=1--``,
# ``') OR ('a'='a``. An attack payload, never a credential.
_SQLI_TAUTOLOGY_RE = re.compile(
    r"""(?ix)
    ['"\)\s]                # payload boundary: quote / paren / space
    \s*(?:OR|AND)\s+        # the tautology conjunction
    (?:
        ['"]?[A-Za-z0-9]{1,8}['"]?\s*=\s*['"]?[A-Za-z0-9]{1,8}['"]?
      | \d+\s*=\s*\d+
    )
    """
)


def _is_non_secret_demo_payload(value: str) -> bool:
    """A value that is provably NOT secret material, only demonstrated attacker input.

    The abuse-case walkthroughs and per-finding verification steps quote the
    exact request that reproduces a finding, and those requests carry
    ``token=``/``password=`` query parameters — the loose credential-assignment
    shape — without ever carrying a credential. Masking them is not a harmless
    over-reaction: it destroys the one value the reader needs. On the 2026-07-25
    insecure-spring-app run the gate hard-failed (exit 2, and in headless mode
    the whole run aborts with no remediation path), and masking to satisfy it
    left ``?username=x&password=**** (21 chars)`` in both the §3 walkthrough and
    the finding's Verification line — a reproduction step that no longer
    reproduces anything.

    Both shapes below are decided structurally, not by context, so this can never
    hide a real leak:

    * **Unsigned JWT** — the header decodes to ``alg: none``. Such a token has no
      signature by construction; it is forgeable by anyone and proves the
      *absence* of signing, so it holds no secret. A signed JWT (any other
      ``alg``) is untouched and still caught by the strict ``jwt`` pattern.
    * **SQL-injection tautology** — percent-decoded, the value is an ``OR 1=1``
      style predicate. That is attacker input, not a credential.
    """
    if not value:
        return False

    seg = _JWT_SEGMENT_RE.match(value)
    if seg:
        header = seg.group(0)
        # urlsafe_b64decode needs the padding the JWT encoding strips.
        padded = header + "=" * (-len(header) % 4)
        try:
            claims = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", "replace"))
        except (ValueError, binascii.Error):
            claims = None
        if isinstance(claims, dict) and str(claims.get("alg", "")).strip().lower() == "none":
            return True

    decoded = unquote_plus(value)
    return bool(_SQLI_TAUTOLOGY_RE.search(decoded))


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


def _mermaid_fence_spans(text: str) -> list[tuple[int, int]]:
    """Return ``(start, end)`` offsets of every ```mermaid fenced block.

    Only mermaid is collected — a secret inside a ```python or ```yaml block is
    a genuine leak and must stay in scope for every pattern.
    """
    return [(m.start(), m.end()) for m in _MERMAID_FENCE_RE.finditer(text)]


def _in_mermaid_fence(spans: list[tuple[int, int]], pos: int) -> bool:
    return any(start <= pos < end for start, end in spans)


def scan_text(text: str) -> list[SecretHit]:
    """Return list of SecretHits — empty list means clean."""
    if not text:
        return []
    line_of = _line_lookup(text)
    mermaid_spans = _mermaid_fence_spans(text)
    hits: list[SecretHit] = []
    for pat in _PATTERNS:
        for m in pat.regex.finditer(text):
            matched = m.group(0)
            groups = m.groupdict() or {}
            value = m.group("val") if "val" in groups else matched
            if not pat.strict:
                # Mermaid is a diagram DSL, not code: ``participant Auth as …``
                # and ``Auth->>Auth: base64-decode`` match the credential-
                # assignment shape without ever carrying a literal. Strict token
                # formats (JWT/AWS/PEM/…) still scan these blocks, so a real
                # secret pasted into a diagram label is still caught.
                if _in_mermaid_fence(mermaid_spans, m.start()):
                    continue
                # Trailing sentence punctuation is not part of the value. The
                # loose charclass includes ``.``, so prose like
                # ``Password: password.`` captured ``password.`` — one character
                # that defeated the keyword-echo guard below (``'password.' !=
                # 'password'``) and let the exact-value redactor rewrite every
                # ``password``-prefixed token in the document, corrupting prose
                # and code samples alike (2026-07-19 insecure-python-app run).
                value = value.rstrip(_VALUE_PUNCTUATION)
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
                # Demonstrated attacker input (unsigned alg:none JWT, SQLi
                # tautology) quoted in a walkthrough / verification step — an
                # attack payload, never secret material.
                if _is_non_secret_demo_payload(value):
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
    # Trailing sentence punctuation is not part of the value (the loose
    # charclass includes ``.``), so it is carried through rather than swallowed:
    # masking a sentence-final value used to delete the full stop and report a
    # length one character too long.
    value = m.group("val")
    stripped = value.rstrip(_VALUE_PUNCTUATION)
    tail = value[len(stripped) :]
    prefix = matched[: m.start("val") - m.start(0)]
    return f"{prefix}**** ({len(stripped)} chars){tail}"


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
                # Same normalization as scan_text(), in the same position — every
                # guard below must judge the value the detector judges, or the
                # twins disagree and the masker corrupts what the scan then
                # reports as clean.
                value = value.rstrip(_VALUE_PUNCTUATION)
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
                # Mirror the detector's demo-payload guard so masking never
                # destroys the reproduction step in a walkthrough / verification
                # line ("?username=x&password=' OR '1'='1").
                if _is_non_secret_demo_payload(value):
                    return m.group(0)
            applied.append(_pat.name)
            return _mask_match(_pat, m)

        text = pat.regex.sub(_repl, text)
    # de-dup while preserving first-seen order
    seen: dict[str, None] = {}
    for name in applied:
        seen.setdefault(name, None)
    return text, list(seen.keys())


def mask_structure(node: Any) -> tuple[Any, list[str]]:
    """Mask every string INSIDE a decoded document, before it is serialized.

    The masking twin of mask_text() for the data layer. Use this — never
    mask_text() — on anything that will be written as YAML or JSON.

    Text-level masking of a serialized document is not safe. The credential
    replacement is ``**** (N chars)``, and a value that starts with ``*`` at the
    head of a plain YAML scalar is an alias indicator: rewriting the unquoted
    ``api_key: aB3xK9mQ7zR2pL5w`` into ``api_key: **** (16 chars)`` produces a
    document PyYAML can no longer parse, i.e. a corrupt canonical model that the
    completeness gate then blocks on. Masking the decoded strings instead leaves
    quoting to the serializer, which quotes exactly when it has to, so the
    corruption class cannot occur regardless of where the value sits.

    Keys are left alone — a mapping key is structure, not analyst prose, and
    rewriting one would silently drop a field. They are still READ: the loose
    credential-assignment pattern needs ``keyword <op> value`` in one string, and
    decoding splits exactly that shape across a key and its value, so
    ``{"api_key": "aB3x…"}`` would otherwise be invisible to a masker that only
    ever sees the bare value. Each string value is therefore also probed once in
    the context of its own key. Returns
    ``(masked_node, applied_pattern_names)``."""
    applied: list[str] = []

    def _mask_leaf(value: str, key: Any) -> str:
        masked, names = mask_text(value)
        if names:
            applied.extend(names)
            return masked
        if isinstance(key, str) and key:
            # Reunite key and value so `keyword: value` can match, then take the
            # value side back. Only an exact prefix match is trusted, so a
            # rewrite that touched the key can never be folded into the value.
            prefix = f"{key}: "
            probed, probe_names = mask_text(prefix + value)
            if probe_names and probed.startswith(prefix):
                applied.extend(probe_names)
                return probed[len(prefix) :]
        return value

    def _walk(value: Any, key: Any = None) -> Any:
        if isinstance(value, str):
            return _mask_leaf(value, key)
        if isinstance(value, dict):
            return {k: _walk(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [_walk(v, key) for v in value]
        if isinstance(value, tuple):
            return tuple(_walk(v, key) for v in value)
        return value

    masked_node = _walk(node)
    seen: dict[str, None] = {}
    for name in applied:
        seen.setdefault(name, None)
    return masked_node, list(seen.keys())


_STRUCTURED_SUFFIXES = frozenset({".yaml", ".yml", ".json"})


def _mask_structured_text(text: str, suffix: str) -> tuple[str, list[str]]:
    """Mask a serialized YAML/JSON document through its decoded form.

    Routes ``mask_file`` to mask_structure() so the rule that docstring states
    is enforced at the choke point instead of asked of every caller. The YAML
    dump options match ``build_threat_model_yaml``, so re-serializing the
    canonical model reproduces its own formatting.

    An undecodable document is returned untouched: blind text masking is what
    corrupts a structured artifact, and a leak that survives here is still
    caught by the unmasked_secrets gate, which fails the run closed."""
    import json

    import yaml

    try:
        doc = json.loads(text) if suffix == ".json" else yaml.safe_load(text)
    except (ValueError, yaml.YAMLError):
        return text, []
    masked_doc, applied = mask_structure(doc)
    if not applied:
        return text, []
    if suffix == ".json":
        return json.dumps(masked_doc, indent=2, ensure_ascii=False) + "\n", applied
    return yaml.safe_dump(masked_doc, sort_keys=False, allow_unicode=True, default_flow_style=False, width=120), applied


def mask_file(path: Path) -> list[str]:
    """Mask secrets in ``path`` in place. Returns the applied pattern names
    (empty list when nothing changed). Best-effort: unreadable files no-op.

    Text-level for markdown and HTML; YAML and JSON are decoded and masked with
    mask_structure() instead — see its docstring for why serialized documents
    cannot be masked as text."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if path.suffix.lower() in _STRUCTURED_SUFFIXES:
        masked, applied = _mask_structured_text(text, path.suffix.lower())
    else:
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
