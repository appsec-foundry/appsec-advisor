"""The confirmed use case: record it once in the dialog, state it in the report.

The early dialog proposes the application's purpose in one sentence ("I
understand this application as … Is that the use case to assess?") and the user
confirms it or replaces it with their own description. That statement is the
one piece of business context a reader needs to judge the whole report, so the
Management Summary repeats it.

Surfaces bound by this rule:

- ``orchestration_controller.complete_preflight`` passes the operator's
  ``--use-case-choice`` to :func:`annotate`, which marks the purpose section of
  the saved business context.
- ``build_threat_model_yaml.build_business_context_trace`` stores
  :func:`confirmed_use_case` of the effective source as
  ``business_context_trace.confirmed_use_case``.
- ``pregenerate_fragments.assessment_intro`` states it in the Management
  Summary opening.

Only a marked section yields a use case: a confirmed proposal, or the user's
replacement text. A bare "No", an unmarked or hand-written context file, and a
skipped dialog yield none. The text is user-confirmed but derived from
untrusted repository content, so it is reduced to plain words (no markup,
links, URLs or control characters) and capped at :data:`MAX_USE_CASE_CHARS`.
The marker never changes a severity or a finding.
"""

from __future__ import annotations

import re

CHOICES = ("confirmed", "corrected")
PURPOSE_HEADING = "## Business purpose"
MAX_USE_CASE_CHARS = 200

_MARKER_RE = re.compile(r"<!--\s*appsec-advisor:\s*use-case\s+choice=(?P<choice>[a-z-]+)\s*-->")
_QUESTION_RE = re.compile(r"^\s*(?:\*\*)?question(?:\*\*)?\s*:(?:\*\*)?\s*(?P<rest>.*)$", re.IGNORECASE)
_ANSWER_RE = re.compile(r"^\s*(?:\*\*)?answer(?:\*\*)?\s*:(?:\*\*)?\s*(?P<rest>.*)$", re.IGNORECASE)
_PROPOSAL_RE = re.compile(r"\bI understand this application as\s+(?P<proposal>.+?)\.\s+Is that the use case\b", re.I)
_CORRECTION_LABEL_RE = re.compile(r"^\s*no,\s*a different use case\s*[—–:\-]*\s*", re.IGNORECASE)
_URL_RE = re.compile(r"(?:https?|ftp)://\S+|www\.\S+", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]*>")
_UNSAFE_RE = re.compile(r"[\x00-\x1f\x7f\[\]()<>`*_|\\#{}]")


def _purpose_sections(text: str) -> list[tuple[int, int]]:
    lines = text.splitlines()
    sections = []
    for index, line in enumerate(lines):
        if line.strip().lower() == PURPOSE_HEADING.lower():
            end = next((j for j in range(index + 1, len(lines)) if lines[j].lstrip().startswith("## ")), len(lines))
            sections.append((index, end))
    return sections


def _field(lines: list[str], pattern: re.Pattern[str]) -> str:
    """One labelled paragraph ("Question:" / "Answer:"), whitespace-collapsed."""
    for index, line in enumerate(lines):
        match = pattern.match(line)
        if not match:
            continue
        parts = [match.group("rest")]
        for follow in lines[index + 1 :]:
            if (
                not follow.strip()
                or follow.lstrip().startswith("#")
                or _QUESTION_RE.match(follow)
                or _ANSWER_RE.match(follow)
            ):
                break
            parts.append(follow)
        return " ".join(" ".join(parts).split())
    return ""


def _plain(text: str) -> str:
    text = _UNSAFE_RE.sub("", _URL_RE.sub("", _TAG_RE.sub("", text)))
    text = " ".join(text.split()).strip(" .;,:—–-")
    if len(text) > MAX_USE_CASE_CHARS:
        cut = text[:MAX_USE_CASE_CHARS].rstrip()
        text = (cut[: cut.rfind(" ")] if " " in cut else cut).rstrip(" .;,:—–-")
    return text


def _use_case(choice: str, body: list[str]) -> str:
    if choice == "confirmed":
        if not _field(body, _ANSWER_RE).lower().startswith("yes"):
            return ""
        match = _PROPOSAL_RE.search(_field(body, _QUESTION_RE))
        return _plain(match.group("proposal")) if match else ""
    answer = _field(body, _ANSWER_RE)
    if answer.lower().startswith("yes"):
        return ""
    return _plain(_CORRECTION_LABEL_RE.sub("", answer))


def annotate(answer_text: str, choice: str) -> str:
    """Return the dialog answer with the use-case marker in its purpose section.

    Raises ``ValueError`` for an unknown choice. When the section or a usable
    use case is missing, the text is returned unchanged: the use case is
    reader context, and its absence must not stop the run.
    """
    if choice not in CHOICES:
        raise ValueError(f"unknown use-case choice {choice!r}")
    sections = _purpose_sections(answer_text)
    if not sections:
        return answer_text
    lines = answer_text.splitlines()
    start, end = sections[-1]
    if not _use_case(choice, lines[start + 1 : end]):
        return answer_text
    lines.insert(start + 1, f"<!-- appsec-advisor: use-case choice={choice} -->")
    return "\n".join(lines) + ("\n" if answer_text.endswith("\n") else "")


def confirmed_use_case(text: str) -> str:
    """The last marked use case in a business-context document, in plain words, or ""."""
    lines = text.splitlines()
    for start, end in reversed(_purpose_sections(text)):
        body = lines[start + 1 : end]
        match = next((m for m in map(_MARKER_RE.search, body) if m), None)
        if match is None or match.group("choice") not in CHOICES:
            continue
        use_case = _use_case(match.group("choice"), body)
        if use_case:
            return use_case
    return ""
