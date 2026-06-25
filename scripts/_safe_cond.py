"""Deterministic condition resolver for sections-contract.yaml.

Replaces the previous ``eval()``-based approach in
``compose_threat_model.eval_condition`` and ``qa_checks._safe_eval_cond``.
Supports only three explicit patterns; everything else raises
``ContractError`` (or its qa_checks equivalent via ``SafeCondError``).

Supported grammar (case-sensitive)::

    expr   := name | "not" name | name ("in" | "not" "in") "[" item ("," item)* "]"
    name   := identifier
    item   := identifier | quoted-string  # bare items become implicit string literals

Numeric comparisons, arithmetic, ``and``/``or`` chains and function calls
are intentionally **not** supported. Express such logic as a pre-computed
bool in the ``eval_context`` instead.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["SafeCondError", "referenced_names", "resolve_condition"]


class SafeCondError(ValueError):
    """Raised when an expression does not match any supported pattern."""


_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_RE_BARE = re.compile(rf"^\s*({_NAME})\s*$")
_RE_NOT_BARE = re.compile(rf"^\s*not\s+({_NAME})\s*$")
_RE_MEMBERSHIP = re.compile(
    rf"^\s*({_NAME})\s+(not\s+in|in)\s*\[\s*(.*?)\s*\]\s*$",
    re.DOTALL,
)
_RE_ITEM = re.compile(rf"""^\s*(?:({_NAME})|'([^']*)'|"([^"]*)")\s*$""")


def _coerce_item(token: str) -> str:
    m = _RE_ITEM.match(token)
    if not m:
        raise SafeCondError(f"unsupported list item: {token!r}")
    bare, sq, dq = m.groups()
    if bare is not None:
        return bare
    return sq if sq is not None else dq


def referenced_names(expr: str) -> set[str]:
    """Return the ``eval_context`` variable names a condition expression reads.

    The supported grammar references exactly one variable — the leading name
    in each pattern (``name``, ``not name``, ``name in [...]``). List items are
    string literals, never variables, so they are not returned.

    Returns an empty set for falsy / non-string input (an absent condition
    references nothing). Raises ``SafeCondError`` for unsupported grammar,
    mirroring :func:`resolve_condition` — so callers that walk a contract can
    assert both "expression is valid" and "every variable it reads is provided"
    from one source of truth.
    """
    if not expr or not isinstance(expr, str):
        return set()
    for rx in (_RE_BARE, _RE_NOT_BARE, _RE_MEMBERSHIP):
        m = rx.match(expr)
        if m:
            return {m.group(1)}
    raise SafeCondError(f"unsupported condition expression: {expr!r}")


def resolve_condition(expr: str, env: dict[str, Any]) -> bool:
    """Evaluate ``expr`` against ``env``.

    Returns False for falsy/empty input. Raises ``SafeCondError`` for any
    expression that does not match a supported pattern.
    """
    if not expr or not isinstance(expr, str):
        return bool(expr)

    m = _RE_BARE.match(expr)
    if m:
        return bool(env.get(m.group(1)))

    m = _RE_NOT_BARE.match(expr)
    if m:
        return not bool(env.get(m.group(1)))

    m = _RE_MEMBERSHIP.match(expr)
    if m:
        name, op, items_raw = m.groups()
        value = env.get(name)
        items = [_coerce_item(tok) for tok in items_raw.split(",") if tok.strip()]
        contained = value in items
        return (not contained) if op.startswith("not") else contained

    raise SafeCondError(f"unsupported condition expression: {expr!r}")
