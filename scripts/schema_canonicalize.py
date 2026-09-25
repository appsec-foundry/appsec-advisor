"""Lossless repairs of schema-invalid agent output, shared by every agent-output gate.

Two rewrites only: ``null`` on an optional property that does not admit null is
removed, and an off-enum string is replaced by the one member it equals after
normalising case and separators. A rewrite is kept only if it removes schema
errors without adding any, so required fields and ambiguous spellings stay fatal.
"""

from __future__ import annotations

import copy
import re
from typing import Any, NamedTuple

_MAX_ROUNDS = 64
_SEPARATORS = re.compile(r"[\s_-]+")


class Change(NamedTuple):
    path: str
    before: Any
    after: Any  # None means the property was removed

    def __str__(self) -> str:
        if self.after is None:
            return f"{self.path}: null removed"
        return f"{self.path}: {self.before} -> {self.after}"


def _normalise(token: str) -> str:
    return _SEPARATORS.sub("_", token.strip().lower())


def _format_path(path: list) -> str:
    out = ""
    for part in path:
        out += f"[{part}]" if isinstance(part, int) else (f".{part}" if out else str(part))
    return out or "<root>"


def _signatures(errors) -> set[str]:
    return {f"{list(e.absolute_path)}|{e.validator}|{e.message}" for e in errors}


def _leaf_errors(errors):
    for error in errors:
        yield error
        if error.context:
            yield from _leaf_errors(error.context)


def _candidate(error) -> tuple[list, Any] | None:
    """The single edit that could repair this error losslessly, if any."""
    path = list(error.absolute_path)
    if error.validator == "type" and error.instance is None and path and isinstance(path[-1], str):
        return path, None
    if error.validator == "enum" and isinstance(error.instance, str) and path:
        wanted = _normalise(error.instance)
        members = {m for m in error.validator_value if isinstance(m, str) and _normalise(m) == wanted}
        if len(members) == 1:
            return path, members.pop()
    return None


def _apply(document: Any, path: list, value: Any) -> bool:
    node = document
    for part in path[:-1]:
        try:
            node = node[part]
        except (KeyError, IndexError, TypeError):
            return False
    last = path[-1]
    if value is None:
        if not isinstance(node, dict) or last not in node:
            return False
        del node[last]
        return True
    try:
        node[last] = value
    except (KeyError, IndexError, TypeError):
        return False
    return True


def canonicalize_lossless(document: Any, validator) -> list[Change]:
    """Apply the lossless rewrites in place; return what changed, in order."""
    changes: list[Change] = []
    if not isinstance(document, (dict, list)):
        return changes
    for _ in range(_MAX_ROUNDS):
        errors = list(validator.iter_errors(document))
        if not errors:
            break
        before = _signatures(errors)
        progressed = False
        for error in _leaf_errors(errors):
            candidate = _candidate(error)
            if candidate is None:
                continue
            path, value = candidate
            trial = copy.deepcopy(document)
            if not _apply(trial, path, value):
                continue
            if _signatures(validator.iter_errors(trial)) < before:
                _apply(document, path, value)
                changes.append(Change(_format_path(path), error.instance, value))
                progressed = True
                break
        if not progressed:
            break
    return changes
