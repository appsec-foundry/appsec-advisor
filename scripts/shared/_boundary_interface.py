"""shared/_boundary_interface.py — single source of truth for "is this boundary
row an internal interface rather than a trust boundary?".

An in-process call with no trust transition (an app → embedded-database pair
inside one process) is an enforcement interface. RA-15 keeps it out of
Figure 1's boundary lines; the §1 catalogue labels it "enforcement interface,
no trust transition"; §2.2 names it apart from the trust boundaries it could
not draw. All three call this predicate so they cannot disagree.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

_SURFACES = frozenset({"network", "in-process", "build-pipeline"})


def is_internal_interface(row: dict) -> bool:
    """True for an in-process crossing without a trust transition.

    Explicit surface/transition axes take precedence; legacy rows that carry
    only ``kind`` count as an interface when the kind is ``process``.
    """
    if row.get("surface") in _SURFACES and isinstance(row.get("transition"), list):
        return row["surface"] == "in-process" and not row["transition"]
    return row.get("kind") == "process"
