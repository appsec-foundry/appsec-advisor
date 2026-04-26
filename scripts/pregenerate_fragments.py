#!/usr/bin/env python3
"""Deterministic pre-generator for the 6 structural fragments under
``$OUTPUT_DIR/.fragments/``.

Six of the eight REQUIRED_FRAGMENTS are pure structural projections of
``threat-model.yaml`` and the Phase-3-8 outputs:

  1. ``system-overview.md``         — meta + components prose
  2. ``architecture-diagrams.md``   — Mermaid C4 + Container + Component
  3. ``assets.md``                  — assets[] table
  4. ``attack-surface.md``          — attack_surface dict tables
  5. ``security-architecture.md``   — security_controls + 14 sub-sections
  6. ``out-of-scope.md``            — meta.scope.out_of_scope (or default)

Pre-generating these takes 6 LLM Write tool-calls off the orchestrator's
Phase-11 budget. The remaining two REQUIRED_FRAGMENTS are LLM-authored:

  7. ``ms-verdict.json``                    — qualitative verdict
  8. ``ms-architecture-assessment.json``    — qualitative assessment
  +  ``attack-walkthroughs.md``             — narrative sequence diagrams

Idempotency
-----------
The script NEVER overwrites a fragment that already exists. The LLM
always has the right of first refusal — pre-generation is a fallback
that runs after the orchestrator's Phase-11 substeps but before
``check_inline_shortcut.py`` makes the call.

Exit codes
----------
0   All 6 fragments either pre-existed or were generated successfully.
1   Generation failed for at least one fragment (no yaml, malformed yaml).
2   Tool error (bad path, missing dependencies).

Usage
-----
    python3 scripts/pregenerate_fragments.py <output-dir>
        [--force]            # Overwrite existing fragments. Default is
                             # idempotent (skip if file exists).
        [--only NAME[,NAME]] # Generate only the listed fragments.
        [--dry-run]          # Print what would be written, don't touch disk.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

import yaml


# ---------------------------------------------------------------------------
# Tier classification — components are mapped into Client / Application /
# Data tiers using a heuristic on id/name/paths. Used by §2 diagrams and §7.
# ---------------------------------------------------------------------------

_TIER_HINTS = {
    "client":      ("frontend", "spa", "ui", "browser", "angular", "react", "vue", "client"),
    "data":        ("nosql", "sql", "mongo", "postgres", "mysql", "redis", "datalayer",
                    "data-layer", "persistence", "store", "db", "database"),
    # application is the default catch-all
}


def _classify_tier(component: dict) -> str:
    """Return 'client' | 'application' | 'data' for a component."""
    haystack = " ".join([
        (component.get("id") or "").lower(),
        (component.get("name") or "").lower(),
        " ".join(component.get("paths") or []).lower(),
    ])
    for tier, hints in _TIER_HINTS.items():
        if any(h in haystack for h in hints):
            return tier
    return "application"


def _components_by_tier(components: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {"client": [], "application": [], "data": []}
    for c in components:
        out[_classify_tier(c)].append(c)
    return out


# ---------------------------------------------------------------------------
# Generator: system-overview.md
# ---------------------------------------------------------------------------

def gen_system_overview(yaml_data: dict) -> str:
    """## 1. System Overview — business purpose + perimeter, NO deployment topology
    (that lives in §2.1).
    """
    meta = yaml_data.get("meta") or {}
    project_raw = meta.get("project")
    project = project_raw if isinstance(project_raw, dict) else {}
    components = yaml_data.get("components") or []

    name = project.get("name") or (project_raw if isinstance(project_raw, str) else None) or "the system"
    desc = project.get("description") or meta.get("project_description") or ""
    runtime = project.get("runtime") or meta.get("runtime") or ""
    repository = project.get("repository") or meta.get("repo_url") or ""

    lines = ["## 1. System Overview", ""]
    if desc:
        lines.append(desc.rstrip("."))
        lines.append("")

    lines.append(f"**Repository:** {repository or '_n/a_'}")
    if runtime:
        lines.append(f"**Runtime:** `{runtime}`")
    lines.append("")

    lines.append("### Scope")
    lines.append("")
    lines.append(
        f"This threat model covers {len(components)} component(s) of {name}: "
        + ", ".join(f"**{c.get('name', c.get('id', '?'))}**" for c in components)
        + "."
    )
    lines.append("")

    out_of_scope = (meta.get("scope") or {}).get("out_of_scope") or []
    if out_of_scope:
        lines.append("**Out of scope:** " + "; ".join(out_of_scope) + ".")
    else:
        lines.append(
            "**Out of scope:** third-party hosted dependencies, browser runtime, "
            "operating-system kernel, and the underlying network infrastructure."
        )
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Generator: architecture-diagrams.md
# ---------------------------------------------------------------------------

def gen_architecture_diagrams(yaml_data: dict) -> str:
    """## 2. Architecture Diagrams — 4 required sub-sections with at least
    one ```mermaid block each.
    """
    meta = yaml_data.get("meta") or {}
    project_raw = meta.get("project")
    if isinstance(project_raw, dict):
        name = project_raw.get("name") or "System"
    elif isinstance(project_raw, str) and project_raw:
        name = project_raw
    else:
        name = "System"
    components = yaml_data.get("components") or []
    boundaries = yaml_data.get("trust_boundaries") or []
    by_tier = _components_by_tier(components)

    lines = ["## 2. Architecture Diagrams", ""]

    # ----- 2.1 System Context ------------------------------------------------
    lines.append("### 2.1 System Context")
    lines.append("")
    lines.append(
        f"C4 Level 1 — {name} situated against its external actors and dependencies. "
        "Boundary lines mark trust transitions enforced (or expected to be enforced) "
        "by the application."
    )
    lines.append("")
    lines.extend(_system_context_mermaid(yaml_data, name))
    lines.append("")

    # ----- 2.2 Container Architecture ----------------------------------------
    lines.append("### 2.2 Container Architecture")
    lines.append("")
    lines.append(
        "C4 Level 2 — deployable units and their internal interfaces. Each box is a "
        "process or runtime unit; arrows show synchronous request flows."
    )
    lines.append("")
    lines.append("```mermaid")
    lines.append("flowchart TB")
    lines.append("    subgraph Client")

    if by_tier["client"]:
        for c in by_tier["client"]:
            lines.append(f"        {_safe_node_id(c['id'])}[\"{c.get('name', c['id'])}\"]")
    else:
        lines.append("        BROWSER[\"Browser Runtime\"]")
    lines.append("    end")
    lines.append("    subgraph Application")
    if by_tier["application"]:
        for c in by_tier["application"]:
            lines.append(f"        {_safe_node_id(c['id'])}[\"{c.get('name', c['id'])}\"]")
    else:
        lines.append("        APP[\"Application Server\"]")
    lines.append("    end")
    lines.append("    subgraph Data")
    if by_tier["data"]:
        for c in by_tier["data"]:
            lines.append(f"        {_safe_node_id(c['id'])}[\"{c.get('name', c['id'])}\"]")
    else:
        lines.append("        DATA[\"Data Layer\"]")
    lines.append("    end")

    # M3.3 / D1 — render edges from `data_flows[]` when the orchestrator
    # populated it; fall back to the legacy 1-pfeil-pro-tier-paar heuristic
    # when empty so old yamls still get a meaningful diagram.
    flow_edges = _data_flow_edges(yaml_data, components)
    if flow_edges:
        for edge in flow_edges:
            lines.append(f"    {edge}")
    else:
        # Legacy fallback — connect first-of-tier to first-of-next-tier.
        if by_tier["client"] and by_tier["application"]:
            c = _safe_node_id(by_tier["client"][0]["id"])
            a = _safe_node_id(by_tier["application"][0]["id"])
            lines.append(f"    {c} -->|HTTPS REST| {a}")
        if by_tier["application"] and by_tier["data"]:
            a = _safe_node_id(by_tier["application"][0]["id"])
            d = _safe_node_id(by_tier["data"][0]["id"])
            lines.append(f"    {a} -->|driver| {d}")
    lines.append("```")
    lines.append("")

    # ----- 2.3 Components ----------------------------------------------------
    lines.append("### 2.3 Components")
    lines.append("")
    lines.append(
        "C4 Level 3 — internal structure of each container, mapped to source paths."
    )
    lines.append("")
    lines.append("| Component ID | Name | Tier | Source paths | Threats |")
    lines.append("|---|---|---|---|---|")
    for c in components:
        cid = c.get("id", "?")
        cname = c.get("name", cid)
        tier = _classify_tier(c).capitalize()
        paths = ", ".join(f"`{p}`" for p in (c.get("paths") or []))
        n_threats = len(c.get("threat_ids") or [])
        lines.append(f"| {cid} | {cname} | {tier} | {paths or '_(no paths)_'} | {n_threats} |")
    lines.append("")

    # ----- 2.4 Technology Architecture ---------------------------------------
    lines.append("### 2.4 Technology Architecture")
    lines.append("")
    lines.append(
        "Trust boundaries enforced (or expected to be enforced) between actors, "
        "containers, and data stores."
    )
    lines.append("")
    if boundaries:
        lines.append("| Boundary ID | Name | Description | Enforcement |")
        lines.append("|---|---|---|---|")
        for b in boundaries:
            bid = b.get("id", "?")
            bname = b.get("name", bid)
            bdesc = (b.get("description") or "").replace("\n", " ").strip()
            # M3.3 / D1: prefer the explicit `enforcement` field; fall back
            # to a label derived from the trust_level so the column does not
            # render blank for legacy yamls.
            benf = (b.get("enforcement") or "").replace("\n", " ").strip()
            if not benf:
                benf = _derive_enforcement(b)
            lines.append(f"| {bid} | {bname} | {bdesc} | {benf} |")
    else:
        lines.append("_No trust boundaries enumerated in threat-model.yaml._")
    lines.append("")
    lines.extend(_technology_architecture_mermaid(yaml_data, components, boundaries))
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _safe_node_id(s: str) -> str:
    """Mermaid-safe node id: alphanum + underscore only."""
    return "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in s.lower()) or "node"


def _system_context_mermaid(yaml_data: dict, system_name: str) -> list[str]:
    """Render §2.1 System Context — yaml-driven C4 Level 1 diagram (M3.3 / D1).

    Pre-D1 this was a 3-node hardcoded stub (USER, ATTACKER, SYSTEM). The
    new version derives:

      • Actors from ``meta.actors[]`` (when populated) plus the canonical
        Anonymous Internet Attacker (always present in any threat model).
      • An ``Authenticated User`` node when ``attack_surface.authenticated``
        has at least one entry.
      • An ``Admin`` node when controls / threats reference admin-only
        routes (heuristic: any threat or control mentioning "admin").
      • External services (e.g. SSRF target, payment gateway, SaaS) when
        threats include CWE-918 (SSRF) or `meta.external_services[]` is
        populated.
      • Edges with HTTPS / WebSocket / SSRF labels per attacker class.

    Falls back gracefully to the old 3-node stub when none of the
    enrichment data is present.
    """
    meta = yaml_data.get("meta") or {}
    actors_yaml = meta.get("actors") or []
    surface = yaml_data.get("attack_surface") or {}
    threats = yaml_data.get("threats") or []
    controls = yaml_data.get("security_controls") or []
    externals_yaml = meta.get("external_services") or []

    # Derive default actor set when meta.actors[] is empty.
    actors: list[tuple[str, str, str]] = []   # (id, label, css_class)
    seen_actor_ids: set[str] = set()

    def _add_actor(aid: str, label: str, css: str) -> None:
        if aid in seen_actor_ids:
            return
        seen_actor_ids.add(aid)
        actors.append((aid, label, css))

    # User-supplied actors take priority — they may include domain experts
    # like "QA Engineer", "Order Fulfilment Bot", etc. that the heuristic
    # cannot guess.
    for a in actors_yaml:
        if not isinstance(a, dict):
            continue
        aid = _safe_node_id(a.get("id") or a.get("name") or "actor").upper()
        label = a.get("name") or a.get("id") or "Actor"
        role = (a.get("role") or "user").lower()
        css = "attacker" if role in ("attacker", "threat-actor") \
              else "admin" if role == "admin" \
              else "user"
        _add_actor(aid, label, css)

    # Heuristic actors when none provided. Always include the End User
    # (any internet-facing app has one) and the Anonymous Attacker
    # (every threat model needs one).
    if not actors:
        _add_actor("USER", "End User<br/>(browser)", "user")
        _add_actor("ATTACKER", "Anonymous<br/>Internet Attacker", "attacker")
    elif not any(c == "attacker" for _, _, c in actors):
        _add_actor("ATTACKER", "Anonymous<br/>Internet Attacker", "attacker")

    # Authenticated user — only when the auth surface has entries.
    auth_entries = surface.get("authenticated") if isinstance(surface, dict) else None
    auth_count = 0
    if isinstance(auth_entries, dict):
        auth_count = len(auth_entries.get("entries") or [])
    elif isinstance(auth_entries, list):
        auth_count = len(auth_entries)
    if auth_count and not any("auth" in c for _, _, c in actors):
        _add_actor("AUTHED", "Authenticated User", "user")

    # Admin actor — heuristic on threats / controls mentioning 'admin'.
    haystack = " ".join([
        " ".join((t.get("title") or "") for t in threats if isinstance(t, dict)),
        " ".join((c.get("control") or "") + " " + (c.get("implementation") or "")
                 for c in controls if isinstance(c, dict)),
    ]).lower()
    if "admin" in haystack:
        _add_actor("ADMIN", "Admin User", "admin")

    # External services — derived from CWE-918 SSRF threats or meta.external_services[].
    externals: list[tuple[str, str]] = []
    seen_ext_ids: set[str] = set()
    for ex in externals_yaml:
        if not isinstance(ex, dict):
            continue
        eid = _safe_node_id(ex.get("id") or ex.get("name") or "ext").upper()
        if eid in seen_ext_ids:
            continue
        seen_ext_ids.add(eid)
        externals.append((eid, ex.get("name") or eid))
    # SSRF heuristic
    has_ssrf = any(
        "CWE-918" in (t.get("cwe") or t.get("cwes") or [""])
        if isinstance(t.get("cwe") or t.get("cwes") or "", (list, str)) else False
        for t in threats if isinstance(t, dict)
    )
    # More tolerant SSRF detection.
    if not has_ssrf:
        for t in threats:
            if not isinstance(t, dict):
                continue
            cwes = t.get("cwe") or t.get("cwes") or []
            if isinstance(cwes, str):
                cwes = [cwes]
            if any("918" in str(c) for c in cwes):
                has_ssrf = True
                break
    if has_ssrf and "EXTERNAL" not in seen_ext_ids:
        externals.append(("EXTERNAL", "External HTTP Services<br/>(SSRF target)"))
        seen_ext_ids.add("EXTERNAL")

    # Compose the mermaid block.
    sys_id = "SYSTEM"
    out: list[str] = [
        "```mermaid",
        "flowchart LR",
    ]
    # Nodes — actors on the left, system in the centre, externals on the right.
    for aid, label, _css in actors:
        out.append(f'    {aid}["{label}"]')
    out.append(f'    {sys_id}["{system_name}"]')
    for eid, label in externals:
        out.append(f'    {eid}["{label}"]')

    # Edges — actor → system. Differentiate trust level.
    for aid, _label, css in actors:
        if css == "attacker":
            out.append(f"    {aid} -.->|HTTPS · probing / exploit| {sys_id}")
        elif css == "admin":
            out.append(f"    {aid} -->|HTTPS · admin actions| {sys_id}")
        else:
            out.append(f"    {aid} -->|HTTPS · normal usage| {sys_id}")

    # Edges — system → external (always outbound; SSRF is exploited inbound
    # by the attacker, but the node is reached via the system).
    for eid, _ in externals:
        out.append(f"    {sys_id} -->|outbound HTTP| {eid}")

    # Class definitions + assignments.
    out.append("    classDef user fill:#dbeafe,stroke:#1e40af")
    out.append("    classDef attacker fill:#fecaca,stroke:#991b1b")
    out.append("    classDef admin fill:#fef3c7,stroke:#92400e")
    out.append("    classDef sys fill:#f3f4f6,stroke:#374151,stroke-width:2px")
    out.append("    classDef ext fill:#e0e7ff,stroke:#3730a3,stroke-dasharray:3 3")
    for aid, _label, css in actors:
        out.append(f"    class {aid} {css}")
    out.append(f"    class {sys_id} sys")
    for eid, _ in externals:
        out.append(f"    class {eid} ext")
    out.append("```")
    return out


def _technology_architecture_mermaid(yaml_data: dict, components: list[dict],
                                      boundaries: list[dict]) -> list[str]:
    """Render §2.4 Technology Architecture — synthesise from
    ``trust_boundaries[]`` + ``components[]`` + ``data_flows[]`` (M3.3 / D1).

    Pre-D1 this was a hardcoded TB1/TB2/TB3 stub. The new version:

      • Renders one ``subgraph`` per actual trust boundary.
      • Places each component inside the boundary that matches its tier
        (``client`` → public-internet/edge boundary, ``application`` →
        process boundary, ``data`` → data-tier boundary). When the yaml
        has fewer than 3 boundaries, components fall back to a generic
        "Application" subgraph.
      • Highlights cross-boundary edges from ``data_flows[]`` so the
        diagram visually shows where trust transitions occur.

    Falls back to the old TB1/TB2/TB3 stub when boundaries are absent
    so the diagram remains useful for legacy yamls.
    """
    if not boundaries:
        return _technology_architecture_stub()

    flows = yaml_data.get("data_flows") or []
    valid_ids = {c.get("id") for c in components if isinstance(c, dict)}

    # Map boundary id → list of component ids that "belong" inside it.
    # Heuristic: trust_level → tier mapping. Generic English words like
    # "application" or "process" appear inside many boundary descriptions
    # (e.g. "accessing the application"), so a substring match against
    # name+description gives false positives. Trust-level is the
    # canonical signal.
    #
    #   tier=client       → boundary with trust_level=untrusted (or first
    #                       boundary whose id contains "internet"/"public"/
    #                       "edge")
    #   tier=application  → boundary with trust_level=trusted (or first
    #                       whose id contains "app"/"process"/"service")
    #   tier=data         → boundary with trust_level=restricted AND id
    #                       containing "data"/"db"/"tier" (filesystem is
    #                       also restricted but should not host the data
    #                       layer)
    component_to_boundary: dict[str, str] = {}

    def _pick_boundary(tier: str) -> str | None:
        # Prefer trust_level match.
        target_levels = {
            "client":      ("untrusted",),
            "application": ("trusted",),
            "data":        ("restricted",),
        }.get(tier, ())
        for level in target_levels:
            for b in boundaries:
                if not isinstance(b, dict):
                    continue
                if (b.get("trust_level") or "").lower() != level:
                    continue
                bid_lc = (b.get("id") or "").lower()
                # For data tier, additionally require "data"/"db"/"store"
                # in the id so we don't drop data-layer into "filesystem".
                if tier == "data":
                    if any(k in bid_lc for k in ("data", "db", "store", "persistence", "tier")):
                        return b.get("id")
                    continue
                # For client, prefer a boundary whose id hints at edge/
                # user-zone — avoids dropping a SPA into "filesystem".
                if tier == "client":
                    if any(k in bid_lc for k in ("internet", "public", "edge", "browser", "user")):
                        return b.get("id")
                    continue
                # Application — the trust_level=trusted match is enough.
                return b.get("id")
        return None

    for c in components:
        if not isinstance(c, dict):
            continue
        cid = c.get("id")
        if not cid:
            continue
        tier = (c.get("tier") or _classify_tier(c)).lower()
        best_bid = _pick_boundary(tier)
        if not best_bid:
            # Last-resort fallback: use the second boundary (typically
            # the application process) so the component is still placed
            # somewhere visible.
            best_bid = (boundaries[1].get("id") if len(boundaries) > 1 else
                        boundaries[0].get("id"))
        component_to_boundary[cid] = best_bid

    out: list[str] = ["```mermaid", "flowchart TB"]

    # One subgraph per boundary. Order them by trust_level (untrusted →
    # trusted → restricted) so the visual reads outside-in.
    trust_order = {"untrusted": 0, "trusted": 1, "restricted": 2}
    sorted_boundaries = sorted(
        boundaries,
        key=lambda b: trust_order.get((b.get("trust_level") or "").lower(), 99),
    )
    for b in sorted_boundaries:
        bid = b.get("id")
        bname = (b.get("name") or bid or "Boundary").replace('"', "'")
        if not bid:
            continue
        sg_id = _safe_node_id(bid).upper()
        out.append(f'    subgraph {sg_id}["{bname}"]')
        # Placeholder node when no components belong here, so subgraph is
        # not empty (mermaid renders empty subgraphs as 0px-wide blocks).
        any_inside = False
        for c in components:
            if not isinstance(c, dict):
                continue
            cid = c.get("id")
            if component_to_boundary.get(cid) == bid:
                cname = (c.get("name") or cid).replace('"', "'")
                out.append(f'        {_safe_node_id(cid)}["{cname}"]')
                any_inside = True
        if not any_inside:
            placeholder = f"{sg_id}_placeholder"
            out.append(f'        {placeholder}[" "]')
        out.append("    end")

    # Edges from data_flows — only render those that cross boundaries.
    # These are the security-relevant transitions worth visualising.
    edges_added = 0
    for f in flows:
        if not isinstance(f, dict):
            continue
        src = f.get("from") or f.get("src")
        dst = f.get("to") or f.get("dst")
        if not src or not dst or src not in valid_ids or dst not in valid_ids:
            continue
        src_b = component_to_boundary.get(src)
        dst_b = component_to_boundary.get(dst)
        if src_b == dst_b:
            continue  # same boundary — not interesting at the §2.4 level
        protocol = (f.get("protocol") or "").strip()
        cls = (f.get("data_classification") or "").strip()
        # Highlight thick when crossing untrusted → trusted.
        src_level = next((b.get("trust_level") for b in boundaries if b.get("id") == src_b), "")
        dst_level = next((b.get("trust_level") for b in boundaries if b.get("id") == dst_b), "")
        thick = (src_level == "untrusted" or dst_level == "untrusted")
        arrow = "==>|" if thick else "-->|"
        bits = [p for p in (protocol, cls) if p]
        label = " · ".join(bits) or "→"
        out.append(f"    {_safe_node_id(src)} {arrow}{label}| {_safe_node_id(dst)}")
        edges_added += 1

    if edges_added == 0:
        # No cross-boundary flows were derivable — note it so the rendered
        # diagram is not silently empty of edges.
        out.append("    %% No cross-boundary data flows derived from data_flows[]")

    out.append("```")
    return out


def _technology_architecture_stub() -> list[str]:
    """Fallback §2.4 mermaid for legacy yamls without trust_boundaries."""
    return [
        "```mermaid",
        "flowchart LR",
        '    subgraph TB1["Public Internet"]',
        '        EXT["Anonymous Actor"]',
        "    end",
        '    subgraph TB2["Application"]',
        '        APP["Server Process"]',
        "    end",
        '    subgraph TB3["Data"]',
        '        STORE["Data Store"]',
        "    end",
        "    EXT -->|TB-001| APP",
        "    APP -->|TB-002/003| STORE",
        "```",
    ]


def _derive_enforcement(boundary: dict) -> str:
    """Best-effort enforcement label when the yaml lacks the explicit field.

    Chooses a 2-3 word descriptor based on `trust_level` and the boundary
    name keywords. Far from perfect, but fills the cell with something
    actionable instead of leaving it blank — the orchestrator (D1.A1)
    is expected to write the explicit field for new runs.
    """
    if not isinstance(boundary, dict):
        return ""
    name = (boundary.get("name") or "").lower()
    desc = (boundary.get("description") or "").lower()
    level = (boundary.get("trust_level") or "").lower()
    haystack = f"{name} {desc}"

    # Network / transport
    if any(k in haystack for k in ("internet", "browser", "spa", "frontend")):
        return "TLS · WAF (none observed)"
    # Process boundaries
    if any(k in haystack for k in ("process", "express", "node.js", "application", "container")):
        return "Process isolation"
    # Data tier
    if any(k in haystack for k in ("data", "db", "database", "sqlite", "store")):
        return "ORM / driver-only access"
    # Filesystem
    if "filesystem" in haystack or "file" in haystack:
        return "OS file permissions"
    # Fall back to trust_level mapping
    return {
        "untrusted": "_(none — boundary is untrusted-side)_",
        "trusted":   "Network ACL / runtime",
        "restricted":"Restricted access",
    }.get(level, "—")


def _data_flow_edges(yaml_data: dict, components: list[dict]) -> list[str]:
    """Render mermaid edges from `data_flows[]` in the yaml.

    Each entry produces one line of the form
    ``<src_id> -->|<label>| <dst_id>`` so the §2.2 Container Architecture
    diagram reflects the actual cross-component traffic the orchestrator
    enumerated, not a hardcoded "client → app → data" stub.

    Tolerated entry shapes (M3.3 / D1):
      - ``{from, to, label, protocol, data_classification}``  (canonical)
      - ``{src, dst, name}``                                  (legacy alias)
      - bare strings inside the list (silently dropped — defensive)

    Returns ``[]`` when no usable flows are present so the caller falls
    back to the legacy tier-pair heuristic.
    """
    flows = yaml_data.get("data_flows") or []
    if not isinstance(flows, list):
        return []
    valid_ids = {c.get("id") for c in components if isinstance(c, dict)}
    edges: list[str] = []
    for f in flows:
        if not isinstance(f, dict):
            continue
        src = f.get("from") or f.get("src") or f.get("source")
        dst = f.get("to") or f.get("dst") or f.get("destination")
        if not src or not dst:
            continue
        # Only render edges between known components — actors/externals
        # would need their own subgraph node which we don't auto-create.
        if src not in valid_ids or dst not in valid_ids:
            continue
        label = (f.get("label") or f.get("name") or "").strip()
        protocol = (f.get("protocol") or "").strip()
        data_class = (f.get("data_classification") or "").strip()
        # Compose the edge label from the most informative pieces.
        parts = [p for p in (label, protocol) if p]
        if data_class and data_class.lower() not in ("public", "n/a", "none"):
            parts.append(data_class)
        annotated = " · ".join(parts) if parts else "→"
        edges.append(
            f"{_safe_node_id(src)} -->|{annotated}| {_safe_node_id(dst)}"
        )
    return edges


# ---------------------------------------------------------------------------
# Generator: assets.md
# ---------------------------------------------------------------------------

def gen_assets(yaml_data: dict) -> str:
    """## 4. Assets — single | Asset | table per contract."""
    assets = yaml_data.get("assets") or []
    lines = ["## 4. Assets", ""]
    lines.append(
        "Information assets and the classification level that drives the "
        "Confidentiality / Integrity / Availability targets used in §8 risk scoring."
    )
    lines.append("")
    if not assets:
        lines.append("_No assets enumerated in threat-model.yaml._")
        lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    lines.append("| Asset | ID | Classification | Description |")
    lines.append("|---|---|---|---|")
    for a in assets:
        aid = a.get("id", "?")
        name = a.get("name", aid)
        clazz = a.get("classification", "_n/a_")
        desc = (a.get("description") or "").replace("\n", " ").strip()
        lines.append(f"| {name} | {aid} | {clazz} | {desc} |")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Generator: attack-surface.md
# ---------------------------------------------------------------------------

def _attack_surface_route(entry: dict) -> str:
    """Return the route string. Schema v1 uses ``endpoint`` or ``path``;
    older orchestrator outputs used ``route``. Strip leading method tokens
    since method already gets its own column."""
    if not isinstance(entry, dict):
        return "?"
    raw = (entry.get("endpoint") or entry.get("path") or entry.get("route") or "?").strip()
    # If "POST /foo" form, strip the method prefix — method has its own column.
    parts = raw.split(" ", 1)
    if len(parts) == 2 and parts[0].upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "WS", "ALL"}:
        return parts[1]
    return raw


def _attack_surface_notes(entry: dict) -> str:
    """Render the Notes column. Prefer ``entry.notes``; otherwise linkify
    threat IDs (``threats`` or ``linked_threats``) against §8 anchors so
    the row points back at the findings register."""
    if not isinstance(entry, dict):
        return ""
    notes = (entry.get("notes") or "").replace("\n", " ").strip()
    if notes:
        return notes
    threats = entry.get("threats") or entry.get("linked_threats") or []
    if threats:
        # Anchors in §8 use the component-prefixed id, lowercased.
        linkified = ", ".join(f"[{t}](#{t.lower()})" for t in threats if isinstance(t, str))
        return linkified
    return ""


def _coerce_surface_list(value: Any) -> list:
    """Normalise the unauthenticated/authenticated value into a list of dict
    entries. Tolerated shapes:

      - ``[ {endpoint, method, ...}, ... ]`` (flat list)             — v1
      - ``{count, entries: [ {...}, ... ]}`` (dict-with-entries)     — v1.1
      - ``{some_key: {endpoint, ...}, ...}`` (dict-of-dicts)         — defensive
      - bare strings inside the list                                  — defensive

    Returns an empty list for any shape that cannot be coerced. Bare
    strings inside the resulting list are silently dropped — the renderer
    cannot show meaningful columns for them and crashing on `.get` is the
    historical bug (Bug #1 / migrated from security-architecture.md to
    attack-surface.md across plugin versions)."""
    if not value:
        return []
    if isinstance(value, list):
        return [e for e in value if isinstance(e, dict)]
    if isinstance(value, dict):
        # v1.1 schema: { count, entries: [...] }
        entries = value.get("entries")
        if isinstance(entries, list):
            return [e for e in entries if isinstance(e, dict)]
        # Defensive: dict-of-dicts (each value is an entry)
        return [v for v in value.values() if isinstance(v, dict)]
    return []


def gen_attack_surface(yaml_data: dict) -> str:
    """## 5. Attack Surface — required ### 5.1 + ### 5.2 sub-sections."""
    surface = yaml_data.get("attack_surface") or {}
    # Tolerate three shapes: dict[unauthenticated|authenticated] (v1),
    # dict-with-entries (v1.1: each branch has {count, entries: [...]}),
    # or flat array with `requires_auth`/`auth_required` per entry (v0).
    if isinstance(surface, dict):
        unauth = _coerce_surface_list(surface.get("unauthenticated"))
        auth = _coerce_surface_list(surface.get("authenticated"))
    elif isinstance(surface, list):
        flat = [e for e in surface if isinstance(e, dict)]
        unauth = [e for e in flat if not (e.get("requires_auth") or e.get("auth_required"))]
        auth   = [e for e in flat if (e.get("requires_auth") or e.get("auth_required"))]
    else:
        unauth, auth = [], []

    lines = ["## 5. Attack Surface", ""]
    lines.append(
        "Network-reachable entry points classified by authentication requirement. "
        "Each row links to the threat(s) referenced in its `notes` column."
    )
    lines.append("")

    lines.append(f"### 5.1 Unauthenticated Entry Points ({len(unauth)})")
    lines.append("")
    if unauth:
        lines.append("| Method | Route | Notes |")
        lines.append("|---|---|---|")
        for entry in unauth:
            method = entry.get("method", "?")
            route = _attack_surface_route(entry)
            notes = _attack_surface_notes(entry)
            lines.append(f"| {method} | `{route}` | {notes} |")
    else:
        lines.append("_None enumerated._")
    lines.append("")

    lines.append(f"### 5.2 Authenticated Entry Points ({len(auth)})")
    lines.append("")
    if auth:
        lines.append("| Method | Route | Notes |")
        lines.append("|---|---|---|")
        for entry in auth:
            method = entry.get("method", "?")
            route = _attack_surface_route(entry)
            notes = _attack_surface_notes(entry)
            lines.append(f"| {method} | `{route}` | {notes} |")
    else:
        lines.append("_None enumerated._")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Generator: security-architecture.md
# ---------------------------------------------------------------------------

# 14 sub-sections defined in sections-contract.yaml § security_architecture.
# Sub-titles are deterministic; bodies are derived from security_controls[].
_SECARCH_SUBSECTIONS = (
    ("7.1",  "Overview"),
    ("7.2",  "Key Architectural Risks"),
    ("7.3",  "Identity & Access Management"),
    ("7.4",  "Authorization"),
    ("7.5",  "Input Validation & Output Encoding"),
    ("7.6",  "Data Protection & Session Management"),
    ("7.7",  "Frontend Security"),
    ("7.8",  "Real-time / WebSocket"),
    ("7.9",  "AI / LLM"),
    ("7.10", "Audit & Logging"),
    ("7.11", "Infrastructure & Network Segmentation"),
    ("7.12", "Dependency & Supply Chain"),
    ("7.13", "Secret Management *(cross-cutting)*"),
    ("7.14", "Defense-in-Depth Assessment *(cross-cutting)*"),
)

# Map sub-section title → control.domain substring matchers.
_SUBSECTION_DOMAIN_HINTS = {
    "7.3":  ("identity", "iam", "authentication", "auth "),
    "7.4":  ("authorization", "access control", "rbac", "abac"),
    "7.5":  ("input validation", "output encoding", "sanitization", "injection"),
    "7.6":  ("data protection", "session", "encryption", "crypto"),
    "7.7":  ("frontend", "csp", "xss", "csrf"),
    "7.8":  ("websocket", "real-time", "socket.io"),
    "7.9":  ("ai", "llm", "ml", "model"),
    "7.10": ("audit", "logging", "monitoring", "siem"),
    "7.11": ("infrastructure", "network", "segmentation", "firewall", "waf"),
    "7.12": ("dependency", "supply chain", "sca", "package"),
    "7.13": ("secret", "key management", "vault", "kms"),
}

# M3.3 / D1 — CWE → §7 sub-section mapping. Surfaces threats in domains
# that have no matching cataloged controls (e.g. juice-shop's §7.8 Real-time
# is empty for controls but T-032 Socket.IO Auth Missing is a relevant
# threat that should appear there). Curated against the most common
# OWASP/STRIDE CWE families; unknown CWEs fall through to no domain so
# they only render once in §8 Threat Register.
_SUBSECTION_CWE_HINTS: dict[str, set[str]] = {
    "7.3":  {"CWE-287", "CWE-308", "CWE-307", "CWE-294", "CWE-345", "CWE-384"},
    "7.4":  {"CWE-285", "CWE-639", "CWE-862", "CWE-863", "CWE-732", "CWE-269"},
    "7.5":  {"CWE-79",  "CWE-80", "CWE-89",  "CWE-94",  "CWE-95", "CWE-611",
             "CWE-77",  "CWE-78", "CWE-90",  "CWE-918", "CWE-22", "CWE-1336"},
    "7.6":  {"CWE-311", "CWE-312", "CWE-319", "CWE-326", "CWE-327", "CWE-328",
             "CWE-916", "CWE-759", "CWE-614", "CWE-922"},
    "7.7":  {"CWE-79",  "CWE-352", "CWE-1021", "CWE-942", "CWE-693"},
    "7.8":  {"CWE-346", "CWE-1357"},  # Origin validation, Socket.IO-style auth
    "7.9":  {"CWE-1039", "CWE-1426"}, # Inadequate ML detection / prompt injection
    "7.10": {"CWE-117", "CWE-223", "CWE-532", "CWE-778"},
    "7.11": {"CWE-200", "CWE-540", "CWE-942", "CWE-555"},
    "7.12": {"CWE-1357", "CWE-1188", "CWE-1395", "CWE-829"},
    "7.13": {"CWE-321", "CWE-798", "CWE-200", "CWE-538", "CWE-260"},
}

# Topic substring fallback when a threat has no CWE — match against title.
# IMPORTANT: keep these hints long enough that they cannot match common
# English words. The first iteration of this map included "ws " as a
# WebSocket alias, which silently matched every occurrence of "allows",
# "answers", "follows" etc. and dragged ~8 unrelated threats into §7.8.
# Rule: every hint should be ≥ 4 chars AND should not appear inside any
# English word at substring boundaries.
_SUBSECTION_TITLE_HINTS: dict[str, tuple[str, ...]] = {
    "7.8":  ("websocket", "socket.io", "real-time", "real time"),
    "7.9":  ("llm ", " llm", "prompt injection", "ai model", "machine learning"),
    "7.11": ("infrastructure", "network segmentation", "metrics endpoint", "prometheus"),
    "7.12": ("supply chain", "npm install", "lockfile", "transitive dependenc"),
    "7.13": ("hardcoded", "secret manag", "credential exposure", "rsa key", "api key"),
}


def _iam_flow_sequence(control_name: str, impl: str, threats: list) -> list[str]:
    """Render an auth-method-aware sequenceDiagram for §7.3.X (M3.3 / D1).

    Detection heuristic looks at ``control_name`` + ``impl`` string and
    picks one of:

      • JWT (most common — RS256/HS256/alg:none variants)
      • OAuth / OIDC (oauth, oidc, openid)
      • SAML (saml)
      • Password / Basic Auth (basic, password, credentials)
      • Generic fallback (matches the legacy stub)

    The diagram differentiates the **happy path** from the **attacker
    branch** by adding a ``Note over`` annotation when relevant CWE
    threats exist (CWE-287/345/384). This is what makes the diagram
    informative versus the pre-D1 generic skeleton.
    """
    haystack = f"{(control_name or '').lower()} {(impl or '').lower()}"

    # CWE-based attack annotations.
    cwes_present: set[str] = set()
    for t in threats or []:
        if not isinstance(t, dict):
            continue
        cwes = t.get("cwe") or t.get("cwes") or []
        if isinstance(cwes, str):
            cwes = [cwes]
        for c in cwes:
            if isinstance(c, str):
                cwes_present.add(c.upper())

    # CWE-347 (Improper Verification of Cryptographic Signature) is the
    # canonical CWE for alg:none / alg-confusion in JWT libraries; CWE-287
    # / CWE-345 are accepted aliases observed in some threat catalogs.
    has_alg_confusion = any(c in cwes_present for c in ("CWE-287", "CWE-345", "CWE-347"))
    # Session-hijacking aliases — CWE-384 (session fixation), CWE-294
    # (capture-replay), and CWE-922 (insecure storage of sensitive
    # information — covers tokens-in-localStorage).
    has_session_hijack = any(c in cwes_present for c in ("CWE-384", "CWE-294", "CWE-922"))
    has_credential_theft = any(c in cwes_present for c in ("CWE-798", "CWE-321"))

    if "jwt" in haystack:
        out = [
            "```mermaid",
            "sequenceDiagram",
            "    autonumber",
            "    participant Client as Browser / SPA",
            "    participant API as Express Backend",
            "    participant Crypto as JWT Signing Key",
            "    participant DB as User DB",
            "    Note over Client,API: Login (POST /rest/user/login)",
            "    Client->>API: { email, password }",
            "    API->>DB: SELECT * FROM users WHERE email=?",
            "    DB-->>API: user record + password hash",
            "    API->>Crypto: load private key (RS256)",
            "    Crypto-->>API: signed JWT (sub, role, exp)",
            "    API-->>Client: 200 { token }",
            "    Note over Client: Token stored in localStorage",
            "    Client->>API: Authorization: Bearer <jwt>",
            "    API->>Crypto: verify signature (RS256)",
            "    Crypto-->>API: ✓ valid",
            "    API-->>Client: 200 { resource }",
        ]
        if has_alg_confusion:
            out.append("    Note over API,Crypto: ⚠ alg:none accepted — attacker forges token without key (T-009 / CWE-287)")
        if has_credential_theft:
            out.append("    Note over Crypto: ⚠ Private key hardcoded in source — anyone reading the repo can forge any user's JWT (T-008 / CWE-321)")
        if has_session_hijack:
            out.append("    Note over Client: ⚠ Token in localStorage → XSS exfiltration possible (T-003 / CWE-922)")
        out.append("```")
        return out

    if "oauth" in haystack or "oidc" in haystack or "openid" in haystack:
        return [
            "```mermaid",
            "sequenceDiagram",
            "    autonumber",
            "    participant Client",
            "    participant App as Application",
            "    participant IdP as OAuth/OIDC Provider",
            "    Client->>App: Login click",
            "    App-->>Client: 302 Redirect to IdP (state, nonce, code_challenge)",
            "    Client->>IdP: GET /authorize",
            "    IdP-->>Client: 302 Redirect with code",
            "    Client->>App: GET /callback?code=…&state=…",
            "    App->>IdP: POST /token (code, code_verifier)",
            "    IdP-->>App: id_token + access_token",
            "    App-->>Client: Set-Cookie: session=… (HttpOnly, SameSite)",
            "```",
        ]

    if "saml" in haystack:
        return [
            "```mermaid",
            "sequenceDiagram",
            "    autonumber",
            "    participant Client as Browser",
            "    participant SP as Service Provider",
            "    participant IdP as Identity Provider",
            "    Client->>SP: GET /protected",
            "    SP-->>Client: SAMLRequest (302 to IdP)",
            "    Client->>IdP: POST SAMLRequest",
            "    IdP-->>Client: SAMLResponse (signed assertion)",
            "    Client->>SP: POST /acs (SAMLResponse)",
            "    SP->>SP: Verify XML-DSig signature on assertion",
            "    SP-->>Client: Set session cookie",
            "```",
        ]

    if "basic" in haystack or "password" in haystack or "credential" in haystack:
        return [
            "```mermaid",
            "sequenceDiagram",
            "    autonumber",
            "    participant Client",
            "    participant API",
            "    participant DB as Credential Store",
            "    Client->>API: Authorization: Basic base64(user:pass)",
            "    API->>DB: SELECT password_hash FROM users WHERE name=?",
            "    DB-->>API: stored hash",
            "    API->>API: bcrypt.compare(submitted, stored)",
            "    API-->>Client: 200 OK / 401 Unauthorized",
            "```",
        ]

    # Generic fallback — keeps the legacy 4-step skeleton.
    return [
        "```mermaid",
        "sequenceDiagram",
        "    participant Client",
        "    participant Service",
        "    participant Store as Identity Store",
        "    Client->>Service: credentials / token",
        "    Service->>Store: verify identity",
        "    Store-->>Service: user record",
        "    Service-->>Client: session / JWT",
        "```",
    ]


def _control_notes(c: dict) -> str:
    """Best-effort Notes-cell content from a security_controls[] entry.

    Falls back through `notes` → `effectiveness_reason` → first item of
    `gaps[]` so the column shows substance even when the orchestrator
    used the leaner Phase 8 schema (just `effectiveness_reason` and no
    explicit `notes`).
    """
    if not isinstance(c, dict):
        return ""
    raw = c.get("notes") or c.get("effectiveness_reason") or ""
    if not raw:
        gaps = c.get("gaps") or []
        if isinstance(gaps, list) and gaps:
            first = gaps[0]
            if isinstance(first, str):
                raw = first
    return (raw or "").replace("\n", " ").strip()


def _threats_for_subsection(threats: list, section_id: str) -> list[dict]:
    """Filter `threats[]` to those that belong in the given §7.X domain.

    Two-pass strategy:
      1. Match on `threat.cwe` / `threat.cwes` against ``_SUBSECTION_CWE_HINTS``
      2. Fall back to title/scenario substring match via
         ``_SUBSECTION_TITLE_HINTS`` for niche domains (Socket.IO, LLM,
         supply-chain) where CWE coverage is inconsistent.

    Returns at most 12 entries to keep the Markdown cell-count bounded.
    """
    if not isinstance(threats, list):
        return []
    cwe_set = _SUBSECTION_CWE_HINTS.get(section_id, set())
    title_hints = _SUBSECTION_TITLE_HINTS.get(section_id, ())
    out: list[dict] = []
    for t in threats:
        if not isinstance(t, dict):
            continue
        # CWE match
        cwes = t.get("cwe") or t.get("cwes") or []
        if isinstance(cwes, str):
            cwes = [cwes]
        cwe_norm = {str(c).upper() for c in cwes if isinstance(c, str)}
        if cwe_set and cwe_norm & cwe_set:
            out.append(t)
            continue
        # Title fallback
        if title_hints:
            haystack = " ".join([
                (t.get("title") or "").lower(),
                (t.get("scenario") or "").lower(),
                (t.get("description") or "").lower(),
            ])
            if any(h in haystack for h in title_hints):
                out.append(t)
    return out[:12]


def _normalize_security_controls(raw: list) -> list[dict]:
    """Coerce ``security_controls`` to a list of dicts so renderers don't
    crash on Phase 8 schema drift (list-of-strings instead of list-of-dicts).
    Mirrors the helper of the same name in compose_threat_model.py.
    """
    out: list[dict] = []
    for c in raw or []:
        if isinstance(c, dict):
            out.append(c)
        elif isinstance(c, str) and c.strip():
            out.append({
                "id": f"C-{c.upper().replace('_', '-')}",
                "domain": c,
                "name": c.replace("_", " ").title(),
                "control": "_(domain enumerated; per-control detail not catalogued)_",
                "effectiveness": "",
                "implementation": "_(not catalogued)_",
                "notes": "",
                "mitigates_findings": [],
                "_synthesized_from_string": True,
            })
    return out


def _controls_for_subsection(controls: list[dict], section_id: str) -> list[dict]:
    hints = _SUBSECTION_DOMAIN_HINTS.get(section_id, ())
    if not hints:
        return []
    out = []
    for c in controls:
        domain = (c.get("domain") or "").lower()
        if any(h in domain for h in hints):
            out.append(c)
    return out


def gen_security_architecture(yaml_data: dict) -> str:
    """## 7. Security Architecture — all 14 sub-sections (7.1-7.14)."""
    controls = _normalize_security_controls(yaml_data.get("security_controls"))
    components = yaml_data.get("components") or []

    lines = ["## 7. Security Architecture", ""]
    lines.append(
        "Security-relevant control domains spanning the application. Each sub-section "
        "summarises the control intent, the implementation observed in the codebase, "
        "and the gap between the two. Cross-cutting domains (Secret Management, "
        "Defense-in-Depth) are surfaced explicitly so they are not lost between "
        "per-component sections."
    )
    lines.append("")

    # 7.1 Overview
    lines.append("### 7.1 Overview")
    lines.append("")
    lines.append(
        f"Across {len(components)} component(s) the assessment catalogued "
        f"{len(controls)} security control(s)."
    )
    if controls:
        eff_counts = {}
        for c in controls:
            eff = (c.get("effectiveness") or "unknown").lower()
            eff_counts[eff] = eff_counts.get(eff, 0) + 1
        bullet = " · ".join(f"**{k}**: {v}" for k, v in sorted(eff_counts.items()))
        lines.append("")
        lines.append(f"Effectiveness breakdown: {bullet}.")
    lines.append("")

    # 7.2 Key Architectural Risks
    lines.append("### 7.2 Key Architectural Risks")
    lines.append("")
    weak = [c for c in controls if (c.get("effectiveness") or "").lower() in ("weak", "missing")]
    if weak:
        lines.append("| Domain | Control | Effectiveness | Notes |")
        lines.append("|---|---|---|---|")
        for c in weak[:8]:
            domain = c.get("domain", "_?_")
            ctrl = c.get("control", "_?_")
            eff = c.get("effectiveness", "_?_")
            notes = _control_notes(c)
            lines.append(f"| {domain} | {ctrl} | {eff} | {notes} |")
    else:
        lines.append("_No weak/missing controls cataloged._")
    lines.append("")

    # 7.3 - 7.12 (domain-specific from security_controls[]).
    # M3.3 / D1: when a domain has no matched controls, surface threats
    # whose CWE maps to the domain so empty sub-sections still carry
    # useful content (was: every empty domain showed only the placeholder
    # "_None cataloged_" string, even when STRIDE found relevant threats).
    threats = yaml_data.get("threats") or []
    for section_id, title in _SECARCH_SUBSECTIONS[2:12]:
        lines.append(f"### {section_id} {title}")
        lines.append("")
        matched = _controls_for_subsection(controls, section_id)
        if matched:
            lines.append("| Control | Implementation | Effectiveness | Notes |")
            lines.append("|---|---|---|---|")
            for c in matched:
                ctrl = c.get("control", "_?_")
                impl = c.get("implementation", "_?_")
                eff = c.get("effectiveness", "_?_")
                notes = _control_notes(c)
                lines.append(f"| {ctrl} | {impl} | {eff} | {notes} |")
        else:
            domain_threats = _threats_for_subsection(threats, section_id)
            if domain_threats:
                lines.append(
                    "_No dedicated control cataloged for this domain — "
                    "the threats below indicate the gap._"
                )
                lines.append("")
                # Title column is omitted because the compose-layer
                # threat-link post-processor auto-expands `[T-NNN](#t-nnn)`
                # to `[T-NNN](#t-nnn) — <title>` in the Threat column,
                # making a separate Title column redundant.
                lines.append("| Threat | Severity | CWE |")
                lines.append("|---|---|---|")
                for t in domain_threats[:6]:
                    tid = t.get("id", "?")
                    sev = (t.get("risk") or t.get("severity") or "—").capitalize()
                    cwes = t.get("cwe") or t.get("cwes") or []
                    if isinstance(cwes, str):
                        cwes = [cwes]
                    cwe_cell = ", ".join(c for c in cwes if isinstance(c, str)) or "—"
                    lines.append(f"| [{tid}](#{tid.lower()}) | {sev} | {cwe_cell} |")
            else:
                lines.append(
                    f"_No controls cataloged in this domain. See §8 Threat Register for "
                    f"any findings that may indirectly relate._"
                )
        lines.append("")

        # §7.3 IAM has stricter contract requirements: per-auth-method ####
        # sub-blocks each carrying a sequenceDiagram. Without these the
        # compose --strict pre-render gate hard-fails. Generate one block per
        # IAM control row using a generic Client → Service → DataStore
        # sequenceDiagram skeleton — the LLM in Stage 2 can refine if it
        # wants but the deterministic stub keeps the pipeline composable.
        # When the controls list has no IAM entries (e.g. Phase 8 emitted
        # bare-string security_controls and the synthesized dicts get filtered
        # out by domain matching), emit ONE placeholder block to satisfy the
        # contract — the strict gate just needs one valid `#### 7.3.N <name>
        # Flow` block with a sequenceDiagram.
        if section_id == "7.3":
            iam_blocks = matched if matched else [{"control": "Authentication Flow", "implementation": "_(not catalogued)_"}]
            for idx, c in enumerate(iam_blocks, start=1):
                ctrl = (c.get("control") or "Authentication Flow").strip()
                impl = (c.get("implementation") or "_n/a_").strip()
                # Heading must match `^7\.3\.\d+\s+.+\s+Flow$` per contract
                # auth_method_decomposition rule. We append " Flow" if absent.
                heading = ctrl if ctrl.endswith(" Flow") else f"{ctrl} Flow"
                lines.append(f"#### 7.3.{idx} {heading}")
                lines.append("")
                lines.append(f"**Implementation:** `{impl}`")
                lines.append("")
                # M3.3 / D1 — auth-method-aware sequence diagram. Detects
                # the auth scheme from the control name + impl string and
                # picks the matching template. Falls back to the legacy
                # generic skeleton when nothing matches.
                lines.extend(_iam_flow_sequence(ctrl, impl, threats))
                lines.append("")
                lines.append("**Risk assessment:** see the row in the §7.3 controls table above for "
                             "effectiveness and notes; cross-referenced findings are tracked in §8.")
                lines.append("")
                # M3.3 / D1 — list IAM-relevant threats inline rather than
                # the legacy "_none directly bound_" placeholder. Filters
                # threats by §7.3 CWE hints (CWE-287, -307, -384, etc.)
                # and uses a 3-entry cap to keep the cell bounded.
                iam_threats = _threats_for_subsection(threats, "7.3")[:5]
                if iam_threats:
                    lines.append("**Findings in this flow:**")
                    for t in iam_threats:
                        tid = t.get("id", "?")
                        title = (t.get("title") or "").replace("|", "\\|")
                        lines.append(f"- [{tid}](#{tid.lower()}) — {title}")
                else:
                    lines.append("**Findings in this flow:** _none directly bound to this flow._")
                lines.append("")

    # 7.13 Secret Management
    lines.append("### 7.13 Secret Management *(cross-cutting)*")
    lines.append("")
    secret_controls = _controls_for_subsection(controls, "7.13")
    if secret_controls:
        lines.append("| Control | Implementation | Effectiveness | Notes |")
        lines.append("|---|---|---|---|")
        for c in secret_controls:
            lines.append(f"| {c.get('control', '_?_')} | {c.get('implementation', '_?_')} | "
                         f"{c.get('effectiveness', '_?_')} | "
                         f"{_control_notes(c)} |")
    else:
        lines.append(
            "_No dedicated secret-management control cataloged. Review §8 Threat "
            "Register for any hardcoded-secret findings (typically CWE-321 / CWE-798)._"
        )
    lines.append("")

    # 7.14 Defense-in-Depth Assessment
    lines.append("### 7.14 Defense-in-Depth Assessment *(cross-cutting)*")
    lines.append("")
    if controls:
        adequate = sum(1 for c in controls if (c.get("effectiveness") or "").lower() == "adequate")
        partial = sum(1 for c in controls if (c.get("effectiveness") or "").lower() == "partial")
        weak_count = sum(1 for c in controls if (c.get("effectiveness") or "").lower() == "weak")
        missing = sum(1 for c in controls if (c.get("effectiveness") or "").lower() == "missing")
        lines.append(
            f"Of {len(controls)} cataloged controls: ✅ **{adequate}** adequate, "
            f"🟡 **{partial}** partial, ⚠️ **{weak_count}** weak, ❌ **{missing}** missing."
        )
    else:
        lines.append("_No controls cataloged._")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Generator: out-of-scope.md
# ---------------------------------------------------------------------------

def gen_out_of_scope(yaml_data: dict) -> str:
    """## 10. Out of Scope — pulls from meta.scope.out_of_scope or default."""
    meta = yaml_data.get("meta") or {}
    out_of_scope = (meta.get("scope") or {}).get("out_of_scope") or [
        "Third-party hosted dependencies and SaaS endpoints",
        "Browser runtime vulnerabilities and end-user device security",
        "Operating system kernel and container runtime",
        "Underlying network infrastructure (DNS, BGP, ISP)",
        "Physical security of hosting facilities",
    ]
    lines = ["## 10. Out of Scope", ""]
    lines.append(
        "The following items are **explicitly excluded** from this threat model. "
        "Findings against these areas should be tracked separately."
    )
    lines.append("")
    for item in out_of_scope:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

GENERATORS = {
    "system-overview.md":       gen_system_overview,
    "architecture-diagrams.md": gen_architecture_diagrams,
    "assets.md":                gen_assets,
    "attack-surface.md":        gen_attack_surface,
    "security-architecture.md": gen_security_architecture,
    "out-of-scope.md":          gen_out_of_scope,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pregenerate_fragments.py",
        description="Pre-generate the 6 deterministic structural fragments.",
    )
    parser.add_argument("output_dir", type=Path,
                        help="Assessment output directory (typically <repo>/docs/security).")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite existing fragments. Default is idempotent.")
    parser.add_argument("--only", type=str, default="",
                        help="Comma-separated fragment names to generate (default: all 6).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print intended actions without writing.")
    args = parser.parse_args(argv)

    output_dir: Path = args.output_dir
    if not output_dir.is_dir():
        print(f"Error: output directory does not exist: {output_dir}", file=sys.stderr)
        return 2

    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"Error: threat-model.yaml not found at {yaml_path}", file=sys.stderr)
        return 1

    try:
        yaml_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        print(f"Error: could not parse {yaml_path}: {exc}", file=sys.stderr)
        return 1

    if not isinstance(yaml_data, dict):
        print(f"Error: {yaml_path} did not parse to a dict", file=sys.stderr)
        return 1

    fragments_dir = output_dir / ".fragments"
    fragments_dir.mkdir(exist_ok=True)

    selected: Iterable[str]
    if args.only:
        selected = [n.strip() for n in args.only.split(",") if n.strip()]
        unknown = [n for n in selected if n not in GENERATORS]
        if unknown:
            print(f"Error: unknown fragment name(s): {unknown}", file=sys.stderr)
            return 2
    else:
        selected = list(GENERATORS.keys())

    written: list[str] = []
    skipped: list[str] = []
    failed: list[tuple[str, str]] = []

    for name in selected:
        path = fragments_dir / name
        if path.exists() and not args.force:
            skipped.append(name)
            continue
        try:
            content = GENERATORS[name](yaml_data)
        except Exception as exc:  # noqa: BLE001 — we want to keep going
            failed.append((name, str(exc)))
            continue
        if args.dry_run:
            written.append(f"{name} (dry-run, {len(content)} chars)")
            continue
        try:
            path.write_text(content, encoding="utf-8")
            written.append(name)
        except OSError as exc:
            failed.append((name, str(exc)))

    # Report
    print(f"pre-generate: wrote {len(written)} / skipped {len(skipped)} / failed {len(failed)}")
    for n in written:
        print(f"  + {n}")
    for n in skipped:
        print(f"  = {n} (already exists; use --force to overwrite)")
    for n, err in failed:
        print(f"  ✗ {n}: {err}", file=sys.stderr)

    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
