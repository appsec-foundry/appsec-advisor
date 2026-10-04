"""Which findings declared business context reaches, for presentation order.

Declared context never changes a severity or a priority tier (FE-7). Within a
tier it puts the work on declared business-critical assets first and names the
asset that put it there, so a reader can see why a measure leads.

A finding counts when the control analyst mapped declared context to its
component (`business_context_basis`, robust to renamed assets), or when it
reaches an asset the context names (`business_context_trace.declared_asset_names`).
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import re

import model.build_plane as build_plane

import renderers._severity_rollup as _severity_rollup

_UNSAFE_NAME_CHARS_RE = re.compile(r"[\x00-\x1f\x7f\[\]()<>`*_|\\]")
_MAX_NAMED_ASSETS = 2
UNNAMED_CONTEXT_NOTE = "Declared business context"


def no_harm_components(yaml_data: dict) -> set[str]:
    """Component ids whose applied business context explicitly declares no material harm.

    An explicit no-harm declaration is distinct from unknown impact
    (REQ-BIZ-003): only ``impact_is_material is False`` counts.
    """
    trace = yaml_data.get("business_context_trace") or {}
    if not isinstance(trace, dict) or trace.get("status") != "applied":
        return set()
    return {
        str(row["component_id"])
        for row in trace.get("component_coverage") or []
        if isinstance(row, dict) and row.get("impact_is_material") is False and row.get("component_id")
    }


def declared_asset_names(yaml_data: dict) -> set[str]:
    """Asset names the applied business context names explicitly."""
    trace = yaml_data.get("business_context_trace") or {}
    if not isinstance(trace, dict) or trace.get("status") != "applied":
        return set()
    return {name for name in trace.get("declared_asset_names") or [] if isinstance(name, str)}


def relevant_findings(yaml_data: dict) -> dict[str, tuple[str, ...]]:
    """Finding id → declared asset names it reaches; an empty tuple means the
    context applies to its component without naming an asset. Both the raw and
    the display id are keys."""
    trace = yaml_data.get("business_context_trace") or {}
    if not isinstance(trace, dict) or trace.get("status") != "applied":
        return {}
    declared = declared_asset_names(yaml_data)
    no_harm = no_harm_components(yaml_data)
    names_by_finding: dict[str, list[str]] = {}
    for asset in yaml_data.get("assets") or []:
        if not isinstance(asset, dict) or asset.get("name") not in declared:
            continue
        for ref in asset.get("linked_threats") or []:
            names_by_finding.setdefault(_severity_rollup.display_id(str(ref)), []).append(str(asset["name"]))
    relevant: dict[str, tuple[str, ...]] = {}
    for threat in yaml_data.get("threats") or []:
        tid = threat.get("id") or threat.get("t_id") if isinstance(threat, dict) else None
        if not tid:
            continue
        display = _severity_rollup.display_id(str(tid))
        names = tuple(dict.fromkeys(names_by_finding.get(display, [])))
        if (threat.get("component") or threat.get("component_id")) in no_harm and not threat.get(
            "business_context_basis"
        ):
            continue
        if names or threat.get("business_context_basis"):
            relevant[str(tid)] = names
            relevant[display] = names
    return relevant


def mitigation_note(finding_ids: list, relevant: dict[str, tuple[str, ...]]) -> str:
    """One-line reason a measure leads its tier, or "" when no context applies."""
    hits = [relevant[str(fid)] for fid in finding_ids if str(fid) in relevant]
    if not hits:
        return ""
    names = [" ".join(_UNSAFE_NAME_CHARS_RE.sub("", n).split())[:60] for group in hits for n in group]
    names = [n for n in dict.fromkeys(names) if n]
    if not names:
        return UNNAMED_CONTEXT_NOTE
    shown = ", ".join(names[:_MAX_NAMED_ASSETS])
    more = len(names) - _MAX_NAMED_ASSETS
    return f"Business-critical: {shown}" + (f" +{more}" if more > 0 else "")


def verdict_context_note(yaml_data: dict) -> str:
    """Disclose declared no-harm scope without changing technical concern levels."""
    rows = [c for c in yaml_data.get("components") or [] if isinstance(c, dict) and c.get("id")]
    components = {c["id"] for c in rows}
    covered = no_harm_components(yaml_data) & components
    if not covered:
        return ""
    # The impact answer is given for the application. Build components only
    # take it when the answer names them (business_impact_scope.propagate), so
    # "7 of 8 components" read as an unexplained exception: say what it covers.
    uncovered_build = [c for c in rows if c["id"] not in covered and build_plane.is_build_component(c)]
    if covered | {c["id"] for c in uncovered_build} == components:
        scope = "for the application under the stated use-case assumptions"
        if uncovered_build:
            names = ", ".join(
                " ".join(_UNSAFE_NAME_CHARS_RE.sub("", str(c.get("name") or c["id"])).split())[:60]
                for c in uncovered_build
            )
            scope += f"; it does not extend to the build and delivery pipeline ({names})"
    else:
        scope = f"for {len(covered)} of {len(components)} modeled components under the stated use-case assumptions"
    return (
        f"Declared business impact: no material harm {scope}. Finding severities and the verdict "
        "retain their technical security concern levels; evidence of consequences outside those "
        "assumptions still requires review."
    )
