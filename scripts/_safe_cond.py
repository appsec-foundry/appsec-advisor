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

__all__ = ["SafeCondError", "resolve_condition"]


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
