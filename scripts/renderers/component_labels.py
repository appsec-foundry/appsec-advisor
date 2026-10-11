"""Reader-facing names for the component identifiers that boundaries and flows name.

Component identifiers are lookup keys: readable in a single-repository model,
opaque hashes in a combined one. Report text and figures show the component's
name instead; the identifier stays in anchors and in the model itself.
"""

from __future__ import annotations

from typing import Any


def component_names(model: dict[str, Any]) -> dict[str, str]:
    """`{component id: name}` for every named component of the model."""
    names: dict[str, str] = {}
    for component in model.get("components") or []:
        if not isinstance(component, dict) or not component.get("id"):
            continue
        name = " ".join(str(component.get("name") or "").split())
        if name:
            names[str(component["id"])] = name
    return names


def endpoint_label(names: dict[str, str], endpoint: Any) -> str:
    """The name of a component endpoint; any other endpoint (such as `external`) as written."""
    value = str(endpoint or "").strip()
    return names.get(value, value)


def crossing_text(boundary: dict[str, Any], names: dict[str, str]) -> str:
    """`<from> → <to>` with component names, or "" when an endpoint is missing."""
    source = str(boundary.get("from") or "").strip()
    target = str(boundary.get("to") or "").strip()
    if not (source and target):
        return ""
    return f"{endpoint_label(names, source)} → {endpoint_label(names, target)}"
