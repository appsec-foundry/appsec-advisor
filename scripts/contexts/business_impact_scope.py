"""Application-wide business impact: record it once, apply it to every runtime component.

The early dialog asks one question about the whole application ("what would be
the worst plausible consequence … if the application were compromised"). Its
answer therefore has application scope. The control analyst distributes context
per component and may leave components out; an application-wide answer must not
depend on that choice.

Surfaces bound by this rule:

- ``orchestration_controller.complete_preflight`` validates the operator's
  ``--impact-choice`` against the answer and writes :func:`annotate` 's marker
  into the impact section of the saved business context.
- ``orchestration_controller.context_v2_prepare_stride`` reads the marker from
  the effective business-context source (:func:`application_impact`) and calls
  :func:`propagate` before the STRIDE manifest is built.

Propagation only fills a missing impact. A component whose analyst entry already
states ``impact_if_compromised`` keeps it, so narrower declarations (an
organization heading with ``Applies to components``, harm declared for one
named asset) stay authoritative. Build and delivery components are excluded
unless the answer names them: a compromised pipeline reaches downstream
consumers, which a statement about the application's own data does not cover.
A free-text answer carries no marker and stays with the analyst. Context files
without a marker keep the previous behavior.

The marker is declared context like the surrounding text: it weights findings
and never sets a severity (FE-7).
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable

CHOICES = ("no-material-harm", "declared-harm")
IMPACT_HEADING = "## Impact if compromised"
MAX_IMPACT_CHARS = 1000

_MARKER_RE = re.compile(r"<!--\s*appsec-advisor:\s*impact\s+scope=application\s+choice=(?P<choice>[a-z-]+)\s*-->")
_NO_HARM_RE = re.compile(r"\bno material (?:business )?harm\b", re.IGNORECASE)
_ANSWER_RE = re.compile(r"^\s*(?:\*\*)?answer(?:\*\*)?\s*:(?:\*\*)?\s*(?P<rest>.*)$", re.IGNORECASE)


def _impact_sections(text: str) -> list[tuple[int, int]]:
    """Line ranges [start, end) of every impact section, heading included."""
    lines = text.splitlines()
    sections = []
    for index, line in enumerate(lines):
        if line.strip().lower() == IMPACT_HEADING.lower():
            end = next(
                (j for j in range(index + 1, len(lines)) if lines[j].lstrip().startswith("## ")),
                len(lines),
            )
            sections.append((index, end))
    return sections


def _answer(lines: list[str]) -> str:
    """The answer paragraph of one impact section, whitespace-collapsed."""
    for index, line in enumerate(lines):
        match = _ANSWER_RE.match(line)
        if not match:
            continue
        parts = [match.group("rest")]
        for follow in lines[index + 1 :]:
            if not follow.strip() or follow.lstrip().startswith("#") or _ANSWER_RE.match(follow):
                break
            parts.append(follow)
        return " ".join(" ".join(parts).split())
    return ""


def annotate(answer_text: str, choice: str) -> str:
    """Return the dialog answer with the application-scope marker in its impact section.

    Raises ``ValueError`` when the choice is unknown, the impact section or its
    answer is missing or too long, or the choice contradicts the answer.
    """
    if choice not in CHOICES:
        raise ValueError(f"unknown impact choice {choice!r}")
    lines = answer_text.splitlines()
    sections = _impact_sections(answer_text)
    if not sections:
        raise ValueError(f"impact choice given but the answer has no '{IMPACT_HEADING}' section")
    start, end = sections[-1]
    answer = _answer(lines[start + 1 : end])
    if not answer:
        raise ValueError("impact choice given but the impact section has no 'Answer:' line")
    if len(answer) > MAX_IMPACT_CHARS:
        raise ValueError(f"impact answer exceeds {MAX_IMPACT_CHARS} characters; record it as free text")
    if (choice == "no-material-harm") != bool(_NO_HARM_RE.search(answer)):
        raise ValueError(f"impact choice {choice!r} does not match the recorded answer")
    marker = f"<!-- appsec-advisor: impact scope=application choice={choice} -->"
    lines.insert(start + 1, marker)
    return "\n".join(lines) + ("\n" if answer_text.endswith("\n") else "")


def application_impact(text: str) -> dict[str, Any] | None:
    """The last marked application-wide impact in a business-context document, or None."""
    lines = text.splitlines()
    for start, end in reversed(_impact_sections(text)):
        body = lines[start + 1 : end]
        match = next((m for m in map(_MARKER_RE.search, body) if m), None)
        if match is None or match.group("choice") not in CHOICES:
            continue
        answer = _answer(body)
        if not answer or len(answer) > MAX_IMPACT_CHARS:
            continue
        return {
            "choice": match.group("choice"),
            "scope": "application",
            "impact_if_compromised": answer,
            "impact_is_material": match.group("choice") == "declared-harm",
        }
    return None


def _named(text: str, component: dict[str, Any]) -> bool:
    from contexts.load_business_context import declared_names

    names = [str(component.get(key) or "") for key in ("id", "name")]
    return bool(declared_names(text, [name for name in names if name]))


def propagate(
    analyst: dict[str, Any],
    components: Iterable[dict[str, Any]],
    impact: dict[str, Any],
    is_build: Callable[[dict[str, Any]], bool],
) -> list[str]:
    """Fill the impact into every runtime component lacking one; return their ids."""
    changed = []
    for component in components:
        cid = component.get("id")
        if not isinstance(cid, str) or cid.startswith("_"):
            continue
        if is_build(component) and not _named(impact["impact_if_compromised"], component):
            continue
        entry = analyst.setdefault(cid, {})
        context = entry.setdefault("business_context", {})
        if context.get("impact_if_compromised"):
            continue
        context["impact_if_compromised"] = impact["impact_if_compromised"]
        context["impact_is_material"] = impact["impact_is_material"]
        changed.append(cid)
    return changed
