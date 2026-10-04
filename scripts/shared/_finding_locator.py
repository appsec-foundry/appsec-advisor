"""shared/_finding_locator.py — the one rule for code locators in reader-facing titles.

Finding and mitigation titles arrive with their evidence pointer glued on in
several shapes: ``Title (routes/login.ts:34)``, ``Title — Dockerfile:1``,
``Title lib/insecurity.ts:56``. A reader-facing reference shows the title only;
the location belongs to the finding itself (decision RA-4). Every producer that
derives a display title from a stored one calls ``strip_trailing_locator`` or
``title_without_locator``, and the composer's reference normalizer and the
reference-format linter share ``ENDING_LOCATOR_RE`` to decide when a locator
ends a reference.

A token is a locator only when it is unmistakably code: it carries a path
separator, a ``:line`` suffix, a known source/config extension, or names an
extensionless build file. Brand names such as ``Socket.IO``, ``Node.js`` or
``lodash.merge`` and prose such as ``(e.g.)`` or ``(1.2.3)`` stay.
"""

from __future__ import annotations

import re

CODE_EXTENSIONS = frozenset(
    "ts tsx js jsx mjs cjs py pyi rb go java kt kts scala groovy gradle cs vb fs rs php sh bash zsh ps1 bat "
    "c h cc cpp hpp m mm swift dart ex exs erl lua pl pm r jl vue svelte html htm jsp aspx cshtml erb hbs pug "
    "ejs css scss sass less sql graphql gql proto yml yaml json jsonc toml ini cfg conf config env properties "
    "xml plist tf tfvars hcl lock mod sum txt md csv".split()
)
NOEXT_CODE_FILES = frozenset(
    {
        "dockerfile",
        "containerfile",
        "makefile",
        "jenkinsfile",
        "procfile",
        "gemfile",
        "rakefile",
        "vagrantfile",
        "brewfile",
        "gulpfile",
        "gruntfile",
    }
)
_TOKEN_RE = re.compile(r"^(?:[A-Za-z]:)?[\w/\\.@-]+?(?P<line>:\d+(?:-\d+)?)?$")
_PARENS_TAIL_RE = re.compile(r"\s*\(\s*`?([^()\s`]+)`?\s*\)\s*$")
_DASH_TAIL_RE = re.compile(r"\s*—\s*`?([^\s`]+)`?\s*$")
_SPACE_TAIL_RE = re.compile(r"\s+`?([^\s`]+)`?\s*$")
# A bare-space tail leaves its preposition behind ("Weak hash in lib/x.ts").
_DANGLING_PREPOSITION_RE = re.compile(r"\s+(?:in|at|of|from|via|on|within|inside)$", re.IGNORECASE)

# A parenthesised locator, captured without backticks.
PARENS_LOCATOR = r"\(\s*`?([^()\s`]+)`?\s*\)"
# A locator ends a reference when only closing punctuation separates it from
# the end of the line, a table cell, a `<br>` or the next reference.
ENDING_LOOKAHEAD = r"(?=[ \t]*[.,;]?[ \t]*(?:$|\||<br|\[))"


def is_code_locator(token: str) -> bool:
    """True for a file, ``file:line``, path, route path or extensionless build file."""
    token = token.strip().strip("`")
    m = _TOKEN_RE.match(token)
    if not m:
        return False
    path = token[: m.start("line")] if m.group("line") else token
    name = re.split(r"[\\/]", path)[-1]
    if name.lower() in NOEXT_CODE_FILES:
        return True
    if "/" in path or "\\" in path:
        return True
    stem, dot, ext = name.rpartition(".")
    if dot and stem and ext.lower() in CODE_EXTENSIONS:
        return True
    return bool(m.group("line")) and bool(dot and stem)


def _strip_one(s: str) -> str:
    for pattern in (_PARENS_TAIL_RE, _DASH_TAIL_RE):
        m = pattern.search(s)
        if m and is_code_locator(m.group(1)) and s[: m.start()].strip():
            return s[: m.start()].rstrip()
    m = _SPACE_TAIL_RE.search(s)
    if m and is_code_locator(m.group(1)) and re.search(r"[\\/]|:\d", m.group(1)):
        head = _DANGLING_PREPOSITION_RE.sub("", s[: m.start()]).rstrip()
        if head.strip():
            return head
    return s


def strip_trailing_locator(label: str) -> str:
    """Remove every trailing code locator from ``label``; idempotent.

    Titles can carry two tails (``Title (a.ts:3) — a.ts:3``), so the strip
    repeats until nothing changes. A label that is only a locator is kept.
    """
    if not label:
        return label
    s = label.rstrip()
    while True:
        stripped = _strip_one(s)
        if stripped == s:
            return s
        s = stripped


def title_without_locator(label: str) -> str:
    """``strip_trailing_locator``, but "" when the label is nothing but a locator."""
    s = strip_trailing_locator((label or "").strip())
    return "" if is_code_locator(s.strip("()")) else s
