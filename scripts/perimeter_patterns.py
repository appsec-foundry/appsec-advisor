"""Shared deployment-perimeter absence patterns.

Source-tree assessment can only prove repository-configured controls. Absence
claims for deployment-time controls such as WAF, IDS/IPS, API gateways, or
secret-scanning services are therefore unfounded unless positive repo evidence
exists. Keep the regex set here so QA, YAML sanitizing, and post-compose prose
touch-ups stay aligned.
"""

from __future__ import annotations

import re


PERIMETER_ABSENCE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("WAF", re.compile(r"\b(?:no|missing|absent|without|lacks?|lacking)\s+(?:a\s+|any\s+)?WAF\b", re.IGNORECASE)),
    ("WAF", re.compile(r"\bWAF\s+(?:is\s+)?(?:not\s+(?:present|configured|in\s+place|deployed)|missing|absent)\b", re.IGNORECASE)),
    ("WAF", re.compile(r"\bno\s+web\s+application\s+firewall\b", re.IGNORECASE)),
    ("network firewall", re.compile(r"\b(?:no|missing|absent|without)\s+(?:network\s+)?firewall\b", re.IGNORECASE)),
    ("IDS/IPS", re.compile(r"\b(?:no|missing|absent|without)\s+(?:IDS|IPS|IDS/IPS|intrusion\s+detection)\b", re.IGNORECASE)),
    ("API gateway", re.compile(r"\b(?:no|missing|absent|without)\s+(?:API\s+gateway|api-gateway)\b", re.IGNORECASE)),
    ("reverse proxy", re.compile(r"\b(?:no|missing|absent|without)\s+reverse\s+proxy\b", re.IGNORECASE)),
    ("secret scanning", re.compile(r"\b(?:no|missing|absent|without)\s+secret\s+scanning\b", re.IGNORECASE)),
    ("DDoS", re.compile(r"\b(?:no|missing|absent|without)\s+DDoS(?:\s+protection)?\b", re.IGNORECASE)),
    (
        "database activity monitoring",
        re.compile(r"\b(?:no|missing|absent|without)\s+(?:database\s+activity\s+monitoring|DAM)\b", re.IGNORECASE),
    ),
    ("EDR/SIEM", re.compile(r"\b(?:no|missing|absent|without)\s+(?:EDR|SIEM)\b", re.IGNORECASE)),
)

_PERIMETER_SENTENCE_RE = re.compile(r"(?:^|(?<=[.!?]\s))[^.!?\n]*(?:[.!?]|$)")


def strip_perimeter_absence_sentences(line: str) -> tuple[str, list[str]]:
    """Remove full prose sentences that contain perimeter-absence claims.

    Returns ``(new_line, removed_tokens)``. The function is deliberately
    sentence-level instead of field-level; it is used after Markdown compose,
    where replacing a whole sentence is safer than trying to rewrite clauses.
    """
    if not isinstance(line, str) or not line.strip():
        return line, []

    removed: list[str] = []

    def repl(match: re.Match[str]) -> str:
        sentence = match.group(0)
        for token, pattern in PERIMETER_ABSENCE_PATTERNS:
            if pattern.search(sentence):
                removed.append(token)
                return ""
        return sentence

    new = _PERIMETER_SENTENCE_RE.sub(repl, line)
    if not removed:
        return line, []

    m = re.match(r"^(\s*)(.*?)$", new, re.DOTALL)
    if m:
        new = m.group(1) + re.sub(r" {2,}", " ", m.group(2)).rstrip()
    return new, removed
