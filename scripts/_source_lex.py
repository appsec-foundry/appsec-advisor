"""Bounded lexical helpers for passive scanners; preserve source offsets."""

from __future__ import annotations

import re


def without_comments(text: str, *, python: bool = False) -> str:
    """Blank comments, retaining strings, newlines, and character positions."""
    out = list(text)
    i = 0
    quote = ""
    while i < len(text):
        if quote:
            if text[i] == "\\":
                i += 2
            elif text.startswith(quote, i):
                i += len(quote)
                quote = ""
            else:
                i += 1
            continue
        if text[i] in "\"'`":
            quote = text[i]
            if python and text.startswith(quote * 3, i):
                quote *= 3
            i += len(quote)
            continue
        line_comment = text[i] == "#" if python else text.startswith("//", i)
        block_comment = not python and text.startswith("/*", i)
        if line_comment or block_comment:
            end = text.find("*/", i + 2) + 2 if block_comment else text.find("\n", i)
            if end < (i + 2 if block_comment else i):
                end = len(text)
            for pos in range(i, end):
                if text[pos] not in "\r\n":
                    out[pos] = " "
            i = end
        else:
            i += 1
    return "".join(out)


def code_only(text: str) -> str:
    """Blank quoted literals for brace counting, not for security matching."""
    return re.sub(r"""(["'`])(?:\\.|(?!\1)[\s\S])*?\1""", lambda m: re.sub(r"[^\n]", " ", m[0]), text)


def call_end(text: str, opening: int) -> int:
    """Offset just after a balanced call, or end of incomplete local text."""
    depth = 0
    for offset, char in enumerate(code_only(text[opening:]), start=opening):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return offset + 1
    return len(text)


def rejecting_check(line: str) -> bool:
    """Recognize a local conditional that visibly rejects invalid input."""
    return bool(re.search(r"\b(?:if|unless)\b", line) and re.search(r"\b(?:throw|raise|return)\b", line))
