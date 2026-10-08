"""shared/_register_titles.py — the one length rule for titles that become headings.

A mitigation title is rendered as the register heading ``M-NNN — <title>`` and
``qa_checks.check_heading_hygiene`` blocks any heading above
``HEADING_HARD_MAX`` characters. Several emitters write mitigation titles
straight into ``threat-model.yaml``; each one calls ``clamp_mitigation_title``
and the composer applies ``clamp_heading_title`` as the backstop, so a long
title is shortened by one rule instead of failing the release gate.
"""

from __future__ import annotations

import re

HEADING_HARD_MAX = 100
HEADING_SOFT_MAX = 80

_ID_SEPARATOR = " — "
# Widest register id the composer emits ("M-NNNN"); a shorter id only frees room.
_WIDEST_MITIGATION_ID = "M-0000"
MITIGATION_TITLE_MAX = HEADING_HARD_MAX - len(_WIDEST_MITIGATION_ID + _ID_SEPARATOR)

_ELLIPSIS = "…"
# Words that cannot end a shortened label without leaving it mid-phrase.
_DANGLING_WORDS = frozenset(
    "a an the of to in on at by for from with and or but via into onto as is are was be that which "
    "through without within against per than no not".split()
)
_TRAILING_LOCATOR_RE = re.compile(r"\s+(?:[—-]\s+)?\(?[\w./-]+:\d+\)?\s*$")


def _cut_at_word(text: str, limit: int) -> str:
    cut = text[:limit].rstrip()
    if len(text) > limit and not text[limit].isspace():
        space = cut.rfind(" ")
        if space > 0:
            cut = cut[:space]
    words = cut.rstrip(" .,;:—-(").split(" ")
    while len(words) > 1 and words[-1].lower().strip(" .,;:—-(") in _DANGLING_WORDS:
        words.pop()
    return " ".join(words).rstrip(" .,;:—-(")


def clamp_title(title: str, limit: int) -> str:
    """Return ``title`` unchanged when it fits, else a word-boundary cut ending in "…".

    A trailing ``file.ext:line`` locator is kept and the body is shortened
    instead, and the cut never ends on a dangling article or preposition.
    """
    title = " ".join((title or "").split())
    if len(title) <= limit:
        return title
    match = _TRAILING_LOCATOR_RE.search(title)
    if match:
        tail = title[match.start() :].strip()
        room = limit - len(tail) - len(_ELLIPSIS) - 1
        if room >= 8:
            return f"{_cut_at_word(title[: match.start()], room)}{_ELLIPSIS} {tail}"
    return _cut_at_word(title, limit - len(_ELLIPSIS)) + _ELLIPSIS


def clamp_mitigation_title(title: str) -> str:
    """Shorten a mitigation title so its ``M-NNN — `` heading stays within the hard limit."""
    return clamp_title(title, MITIGATION_TITLE_MAX)


def clamp_heading_title(heading_id: str, title: str) -> str:
    """Shorten ``title`` so the heading ``<heading_id> — <title>`` stays within the hard limit."""
    return clamp_title(title, HEADING_HARD_MAX - len(f"{heading_id}{_ID_SEPARATOR}"))
