#!/usr/bin/env python3
"""Deterministic pre-generator for the 7 structural fragments under
``$OUTPUT_DIR/.fragments/``.

Seven of the nine REQUIRED_FRAGMENTS are pure structural projections of
``threat-model.yaml`` and the Phase-3-8 outputs:

  1. ``system-overview.md``         — meta + components prose
  2. ``architecture-diagrams.md``   — Mermaid C4 + Container + Component
  3. ``assets.md``                  — assets[] table
  4. ``attack-surface.md``          — attack_surface dict tables
  5. ``use-cases.md``               — use_cases[] (conditional: only when YAML has entries)
  6. ``security-architecture.md``   — security_controls + 14 sub-sections
  7. ``out-of-scope.md``            — meta.scope.out_of_scope (or default)

Pre-generating these takes 7 LLM Write tool-calls off the orchestrator's
Phase-11 budget. The remaining two REQUIRED_FRAGMENTS are LLM-authored:

  8. ``ms-verdict.json``                    — qualitative verdict
  9. ``ms-architecture-assessment.json``    — qualitative assessment
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
    top_project = yaml_data.get("project") or {}
    repository = (project.get("repository") or top_project.get("repository")
                  or meta.get("repo_url") or "")

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
    # M3.3 / D1.5 (G) — DB-engine annotation when not already in name.
    def _component_label(c: dict) -> str:
        nm = (c.get("name") or c.get("id") or "?").replace('"', "'")
        engine = (c.get("engine") or "").strip()
        if engine and engine.lower() not in nm.lower():
            return f'{nm}<br/>{engine}'
        return nm

    # M3.3 / D1.5 (L) — pre-compute Critical / High threat counts per
    # component so the mermaid block can apply classDef highlighting.
    crit_counts, high_counts = _threat_counts_per_component(yaml_data)

    lines.append("```mermaid")
    lines.append("flowchart TB")
    lines.append("    subgraph Client")

    if by_tier["client"]:
        for c in by_tier["client"]:
            lines.append(f"        {_safe_node_id(c['id'])}[\"{_component_label(c)}\"]")
    else:
        lines.append("        BROWSER[\"Browser Runtime\"]")
    lines.append("    end")
    lines.append("    subgraph Application")
    if by_tier["application"]:
        for c in by_tier["application"]:
            lines.append(f"        {_safe_node_id(c['id'])}[\"{_component_label(c)}\"]")
    else:
        lines.append("        APP[\"Application Server\"]")
    lines.append("    end")
    lines.append("    subgraph Data")
    if by_tier["data"]:
        for c in by_tier["data"]:
            lines.append(f"        {_safe_node_id(c['id'])}[\"{_component_label(c)}\"]")
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

    # M3.3 / D1.5 (L) — Critical-path classDef. Components with ≥3 Critical
    # threats get a thick red border; ≥2 High get a thinner amber border.
    # Subgraph IDs are excluded — the highlight is a *component* visual cue.
    crit_class_lines = []
    warn_class_lines = []
    for c in components:
        if not isinstance(c, dict):
            continue
        cid = c.get("id")
        if not cid:
            continue
        node = _safe_node_id(cid)
        if crit_counts.get(cid, 0) >= 3:
            crit_class_lines.append(node)
        elif high_counts.get(cid, 0) >= 2:
            warn_class_lines.append(node)
    if crit_class_lines or warn_class_lines:
        lines.append("    classDef critical stroke:#dc2626,stroke-width:3px,fill:#fef2f2")
        lines.append("    classDef warning  stroke:#d97706,stroke-width:2px,fill:#fffbeb")
        for n in crit_class_lines:
            lines.append(f"    class {n} critical")
        for n in warn_class_lines:
            lines.append(f"    class {n} warning")

    lines.append("```")
    lines.append("")

    # ----- 2.3 Components ----------------------------------------------------
    lines.append("### 2.3 Components")
    lines.append("")
    lines.append(
        "C4 Level 3 — internal structure of each container, mapped to source paths."
    )
    lines.append("")

    # Component diagram — one node per component, grouped by tier.
    # Node label shows component name + threat count so reviewers can see
    # where risk concentrates at a glance.
    lines.append("```mermaid")
    lines.append("flowchart TB")
    _tier_labels = {"client": "Client Tier", "application": "Application Tier", "data": "Data Tier"}
    for tier_key, tier_label in _tier_labels.items():
        tier_components = by_tier[tier_key]
        if not tier_components:
            continue
        lines.append(f"    subgraph {tier_key.capitalize()}[\"{tier_label}\"]")
        for c in tier_components:
            cid_node = _safe_node_id(c.get("id", "?"))
            cname = (c.get("name") or c.get("id") or "?").replace('"', "'")
            n_threats = len(c.get("threat_ids") or [])
            label = f"{cname}<br/>({n_threats} threats)"
            lines.append(f"        {cid_node}[\"{label}\"]")
        lines.append("    end")

    # Tier-to-tier edges (same logic as §2.2 but between tiers, not components)
    if by_tier["client"] and by_tier["application"]:
        src = _safe_node_id(by_tier["client"][0]["id"])
        dst = _safe_node_id(by_tier["application"][0]["id"])
        lines.append(f"    {src} -->|API calls| {dst}")
    if by_tier["application"] and by_tier["data"]:
        src = _safe_node_id(by_tier["application"][0]["id"])
        dst = _safe_node_id(by_tier["data"][0]["id"])
        lines.append(f"    {src} -->|queries| {dst}")

    # Reuse the same classDef colour scheme as §2.2
    if crit_class_lines or warn_class_lines:
        lines.append("    classDef critical stroke:#dc2626,stroke-width:3px,fill:#fef2f2")
        lines.append("    classDef warning  stroke:#d97706,stroke-width:2px,fill:#fffbeb")
        for n in crit_class_lines:
            lines.append(f"    class {n} critical")
        for n in warn_class_lines:
            lines.append(f"    class {n} warning")

    lines.append("```")
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

    # M3.3 / D1.5 (J) — Legend footnote at the end of §2 covering all
    # three diagrams (system context, container architecture, technology
    # architecture). Single block so we don't repeat the legend three
    # times. Only emit when the diagrams actually use the relevant
    # conventions — avoids cluttering small/legacy yamls.
    legend_lines = _maybe_render_legend(yaml_data, components)
    if legend_lines:
        lines.extend(legend_lines)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _maybe_render_legend(yaml_data: dict, components: list[dict]) -> list[str]:
    """M3.3 / D1.5 (J) — Build a context-aware legend block.

    Each entry is included only when the corresponding convention is
    actually present in the rendered diagrams, so the legend remains
    relevant. Order: edge styles first (from most → least common),
    severity highlight last.
    """
    flows = yaml_data.get("data_flows") or []
    has_async = any(
        isinstance(f, dict) and _is_async_protocol(f.get("protocol", ""))
        for f in flows
    )
    has_flows = bool([
        f for f in flows
        if isinstance(f, dict)
        and (f.get("from") or f.get("src"))
        and (f.get("to") or f.get("dst"))
    ])
    boundaries = yaml_data.get("trust_boundaries") or []
    has_cross_boundary = bool(boundaries) and has_flows
    crit_counts, high_counts = _threat_counts_per_component(yaml_data)
    has_highlight = (
        any(v >= 3 for v in crit_counts.values())
        or any(v >= 2 for v in high_counts.values())
    )

    # Skip the legend entirely when nothing it would explain is rendered.
    if not (has_flows or has_cross_boundary or has_highlight):
        return []

    bullets: list[str] = []
    if has_flows:
        bullets.append("`-->` synchronous request/response (REST, HTTPS, gRPC)")
    if has_async:
        bullets.append("`-.->` asynchronous / event-driven (WebSocket, queue, pub-sub)")
    if has_cross_boundary:
        bullets.append("`==>` crosses an untrusted trust boundary (security-critical)")
    if has_highlight:
        bullets.append(
            "**red border** ≥ 3 Critical threats on the component · "
            "**amber border** ≥ 2 High threats"
        )

    if not bullets:
        return []

    out = ["> **Legend:** " + " · ".join(bullets)]
    return out


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
    # Skip when an admin actor was already supplied via meta.actors[].
    if not any(c == "admin" for _, _, c in actors):
        haystack = " ".join([
            " ".join((t.get("title") or "") for t in threats if isinstance(t, dict)),
            " ".join((c.get("control") or "") + " " + (c.get("implementation") or "")
                     for c in controls if isinstance(c, dict)),
        ]).lower()
        if "admin" in haystack:
            _add_actor("ADMIN", "Admin User", "admin")

    # M3.3 / D1.5 (A + B) — External services categorised by direction:
    #   external_in: SaaS that calls in (Auth provider OAuth/OIDC redirect,
    #                webhooks like Stripe → app)
    #   external_out: SaaS the system calls out (Sentry, S3, Stripe-API, …)
    #   external_db: data stores running as a separate process / over a
    #                network (RDS, Cloud SQL, Redis as a service)
    # Each goes in its own visual lane: inbound on the left side of SYSTEM,
    # outbound on the right, external DB on the bottom.
    ext_in: list[tuple[str, str, str]] = []   # (id, label, protocol)
    ext_out: list[tuple[str, str, str]] = []
    ext_db: list[tuple[str, str, str]] = []
    seen_ext_ids: set[str] = set()

    def _classify_external(ex: dict) -> str:
        """Classify by `category` first (semantic), then by `direction`.

        Category dominates because the visual lane (inbound/outbound/db)
        is determined by the **kind** of external service, not by the
        traffic direction. A bidirectional database is still a database
        and belongs in the extdb lane.
        """
        category = (ex.get("category") or ex.get("type") or "").lower()
        if any(k in category for k in ("datastore", "db ", "database", "rds", "cache")):
            return "db"
        if any(k in category for k in ("auth", "oidc", "saml", "sso", "idp")):
            return "in"  # IdP redirects user *to* the system
        if any(k in category for k in ("webhook", "partner", "callback")):
            return "in"

        direction = (ex.get("direction") or "").lower()
        if direction in ("inbound", "in"):
            return "in"
        if direction in ("outbound", "out"):
            return "out"
        if direction == "bidirectional":
            return "out"  # render once on outbound side (no DB hint)
        return "out"  # safest default — most SaaS deps are outbound

    for ex in externals_yaml:
        if not isinstance(ex, dict):
            continue
        eid = _safe_node_id(ex.get("id") or ex.get("name") or "ext").upper()
        if eid in seen_ext_ids:
            continue
        seen_ext_ids.add(eid)
        label = ex.get("name") or eid
        protocol = (ex.get("protocol") or "").strip()
        bucket = _classify_external(ex)
        if bucket == "in":
            ext_in.append((eid, label, protocol))
        elif bucket == "db":
            ext_db.append((eid, label, protocol))
        else:
            ext_out.append((eid, label, protocol))

    # SSRF heuristic — only fires when meta.external_services[] doesn't
    # already contain something matching. Adds a generic SSRF-target node
    # so §2.1 surfaces the threat shape even without explicit external listing.
    has_ssrf = False
    for t in threats:
        if not isinstance(t, dict):
            continue
        cwes = t.get("cwe") or t.get("cwes") or []
        if isinstance(cwes, str):
            cwes = [cwes]
        if any("918" in str(c) for c in cwes):
            has_ssrf = True
            break
    if has_ssrf and "EXTERNAL" not in seen_ext_ids and not ext_out:
        ext_out.append(("EXTERNAL", "External HTTP Services<br/>(SSRF target)", "HTTPS"))
        seen_ext_ids.add("EXTERNAL")

    # Compose the mermaid block.
    sys_id = "SYSTEM"
    out: list[str] = [
        "```mermaid",
        "flowchart LR",
    ]
    # Inbound externals (left).
    for eid, label, _proto in ext_in:
        out.append(f'    {eid}["{label}"]')
    # Actors.
    for aid, label, _css in actors:
        out.append(f'    {aid}["{label}"]')
    # System.
    out.append(f'    {sys_id}["{system_name}"]')
    # Outbound externals (right).
    for eid, label, _proto in ext_out:
        out.append(f'    {eid}["{label}"]')
    # External DB (bottom).
    for eid, label, _proto in ext_db:
        out.append(f'    {eid}["{label}"]')

    # Edges — actor → system. Differentiate trust level.
    for aid, _label, css in actors:
        if css == "attacker":
            out.append(f"    {aid} -.->|HTTPS · probing / exploit| {sys_id}")
        elif css == "admin":
            out.append(f"    {aid} -->|HTTPS · admin actions| {sys_id}")
        else:
            out.append(f"    {aid} -->|HTTPS · normal usage| {sys_id}")

    # Edges — inbound external → system. Show the protocol when known
    # (e.g. "OIDC redirect" for Google SSO, "HMAC-signed POST" for Stripe webhook).
    for eid, _label, proto in ext_in:
        edge_label = proto or "inbound HTTPS"
        out.append(f"    {eid} -->|{edge_label}| {sys_id}")

    # Edges — system → outbound external.
    for eid, _label, proto in ext_out:
        edge_label = (f"outbound · {proto}" if proto else "outbound HTTP")
        out.append(f"    {sys_id} -->|{edge_label}| {eid}")

    # Edges — system → external DB (bidirectional in protocol but the
    # convention is: app initiates, hence one-way arrow).
    for eid, _label, proto in ext_db:
        edge_label = proto or "DB protocol"
        out.append(f"    {sys_id} -->|{edge_label}| {eid}")

    # Class definitions + assignments.
    out.append("    classDef user fill:#dbeafe,stroke:#1e40af")
    out.append("    classDef attacker fill:#fecaca,stroke:#991b1b")
    out.append("    classDef admin fill:#fef3c7,stroke:#92400e")
    out.append("    classDef sys fill:#f3f4f6,stroke:#374151,stroke-width:2px")
    out.append("    classDef ext fill:#e0e7ff,stroke:#3730a3,stroke-dasharray:3 3")
    out.append("    classDef extdb fill:#dcfce7,stroke:#15803d,stroke-dasharray:3 3")
    for aid, _label, css in actors:
        out.append(f"    class {aid} {css}")
    out.append(f"    class {sys_id} sys")
    for eid, _, _ in ext_in:
        out.append(f"    class {eid} ext")
    for eid, _, _ in ext_out:
        out.append(f"    class {eid} ext")
    for eid, _, _ in ext_db:
        out.append(f"    class {eid} extdb")
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
        # Step 1 — prefer explicit trust_level field.
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
                if tier == "data":
                    if any(k in bid_lc for k in ("data", "db", "store", "persistence", "tier")):
                        return b.get("id")
                    continue
                if tier == "client":
                    if any(k in bid_lc for k in ("internet", "public", "edge", "browser", "user")):
                        return b.get("id")
                    continue
                return b.get("id")

        # Step 2 — name/description substring match (handles yamls without
        # trust_level, e.g. when the orchestrator emits only id/name/description).
        # Hints are ordered most-specific first; a boundary must NOT also
        # match another tier's stronger hints (exclusion check below).
        _name_hints: dict[str, tuple[str, ...]] = {
            # "internet"/"public"/"external" only appear in the outermost boundary.
            "client":      ("internet", "public internet", "external user",
                            "browser", "angular spa", "react spa", "vue spa",
                            "frontend"),
            # "spa to rest"/"api" disambiguates from generic "application" text.
            "application": ("spa to", "spa → rest", "rest api", "express api",
                            "app server", "process boundary", "service mesh"),
            # "data tier"/"data layer"/"db"/"sqlite" are unambiguous.
            "data":        ("data tier", "data layer", "database", "sqlite",
                            "marsdb", "persistence", "storage tier"),
        }
        hints = _name_hints.get(tier, ())
        for b in boundaries:
            if not isinstance(b, dict):
                continue
            haystack = " ".join([
                (b.get("id") or "").lower(),
                (b.get("name") or "").lower(),
                (b.get("description") or "").lower(),
            ])
            if any(h in haystack for h in hints):
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

    # M3.3 / D1.5 (L) — pre-compute threat counts for highlight pass below.
    crit_counts, high_counts = _threat_counts_per_component(yaml_data)

    # M3.3 / D1.5 (G) — engine annotation when not already in component name.
    def _component_label(c: dict) -> str:
        nm = (c.get("name") or c.get("id") or "?").replace('"', "'")
        engine = (c.get("engine") or "").strip()
        if engine and engine.lower() not in nm.lower():
            return f'{nm}<br/>{engine}'
        return nm

    # M3.3 / D1.5 (F) — filesystem-subgraph ghost-nodes for exposed paths.
    # When a boundary's id/name suggests "filesystem" / "storage" and the
    # attack_surface lists routes whose path matches an exposed-fs pattern,
    # render path stems as ghost boxes inside that subgraph. The full
    # route detail stays in §5.1 — we only show stems here so the visual
    # answers "what gets exposed via the FS" without duplicating §5.1.
    fs_paths_by_boundary = _filesystem_paths_per_boundary(yaml_data, boundaries)

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
                out.append(f'        {_safe_node_id(cid)}["{_component_label(c)}"]')
                any_inside = True
        # M3.3 / D1.5 (F) — fill filesystem subgraph with exposed path stems
        # when the boundary maps to one (avoids the empty-placeholder look).
        for stem in fs_paths_by_boundary.get(bid, []):
            stem_id = _safe_node_id(f"fs_{stem}")
            out.append(f'        {stem_id}(["{stem} (see §5.1)"])')
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
        auth = (f.get("auth_method") or "").strip()
        cls = (f.get("data_classification") or "").strip()
        # Highlight thick when crossing untrusted → trusted.
        src_level = next((b.get("trust_level") for b in boundaries if b.get("id") == src_b), "")
        dst_level = next((b.get("trust_level") for b in boundaries if b.get("id") == dst_b), "")
        crosses_untrusted = (src_level == "untrusted" or dst_level == "untrusted")

        # M3.3 / D1.5 (E) — arrow style chain. Cross-untrusted always wins
        # (==> thick) because the boundary-crossing concern dominates the
        # async signal at §2.4 level. Async-only crossings between trusted
        # tiers use the dashed (-.->) form.
        if crosses_untrusted:
            arrow = "==>|"
        elif _is_async_protocol(protocol):
            arrow = "-.->|"
        else:
            arrow = "-->|"

        # M3.3 / D1.5 (D) — auth on edge: `<protocol> / <auth>`
        head = " / ".join(p for p in (protocol, auth) if p)
        bits = [b for b in (head, cls) if b]
        label = " · ".join(bits) or "→"
        out.append(f"    {_safe_node_id(src)} {arrow}{label}| {_safe_node_id(dst)}")
        edges_added += 1

    if edges_added == 0:
        # No cross-boundary flows were derivable — note it so the rendered
        # diagram is not silently empty of edges.
        out.append("    %% No cross-boundary data flows derived from data_flows[]")

    # M3.3 / D1.5 (L) — Critical-path classDef in §2.4 too. Same threshold
    # as §2.2 (≥3 Critical → critical, ≥2 High → warning).
    crit_nodes: list[str] = []
    warn_nodes: list[str] = []
    for c in components:
        if not isinstance(c, dict):
            continue
        cid = c.get("id")
        if not cid:
            continue
        node = _safe_node_id(cid)
        if crit_counts.get(cid, 0) >= 3:
            crit_nodes.append(node)
        elif high_counts.get(cid, 0) >= 2:
            warn_nodes.append(node)
    if crit_nodes or warn_nodes:
        out.append("    classDef critical stroke:#dc2626,stroke-width:3px,fill:#fef2f2")
        out.append("    classDef warning  stroke:#d97706,stroke-width:2px,fill:#fffbeb")
        for n in crit_nodes:
            out.append(f"    class {n} critical")
        for n in warn_nodes:
            out.append(f"    class {n} warning")

    out.append("```")
    return out


def _filesystem_paths_per_boundary(yaml_data: dict, boundaries: list[dict]) -> dict[str, list[str]]:
    """M3.3 / D1.5 (F) — derive a tiny per-boundary list of filesystem
    path stems to render as ghost-nodes inside the §2.4 mermaid.

    Identifies boundaries that look filesystem-related (id/name match)
    and matches `attack_surface.unauthenticated[].endpoint` paths against
    a known set of filesystem-exposing route prefixes. Only **path stems**
    are returned — the full route detail (method, threats, notes) stays
    in §5.1 so this enrichment does not duplicate that table.

    Returns ``{boundary_id: [unique_stem, ...]}``. Empty dict when no
    filesystem boundary is present.
    """
    fs_boundary_ids: list[str] = []
    for b in boundaries or []:
        if not isinstance(b, dict):
            continue
        haystack = " ".join([
            (b.get("id") or "").lower(),
            (b.get("name") or "").lower(),
        ])
        if any(k in haystack for k in ("filesystem", "file system", "storage", "disk", "fs")):
            fs_boundary_ids.append(b.get("id"))
    if not fs_boundary_ids:
        return {}

    # Known prefixes for filesystem-exposing routes. Conservative — only
    # patterns that historically appear in the §5.1 surface table for
    # juice-shop-style apps. A path that doesn't match any prefix below
    # is treated as a regular HTTP route, not a filesystem ghost-node.
    fs_prefixes = ("/ftp", "/encryptionkeys", "/support/logs", "/files",
                   "/uploads", "/static", "/public/files")

    surface = yaml_data.get("attack_surface") or {}
    unauth = (surface.get("unauthenticated")
              if isinstance(surface, dict) else None) or []
    if isinstance(unauth, dict):
        unauth = unauth.get("entries") or []
    stems: list[str] = []
    seen: set[str] = set()
    for entry in unauth or []:
        if not isinstance(entry, dict):
            continue
        ep = (entry.get("endpoint") or entry.get("path") or entry.get("route") or "").strip()
        if not ep:
            continue
        # Strip the method prefix.
        parts = ep.split(" ", 1)
        if len(parts) == 2 and parts[0].upper() in {"GET", "POST", "PUT",
                                                     "PATCH", "DELETE",
                                                     "OPTIONS", "HEAD"}:
            ep = parts[1]
        for prefix in fs_prefixes:
            if ep.startswith(prefix):
                # Reduce the path to its stem (e.g. /ftp/foo.bak → /ftp/*).
                stem = prefix + ("/*" if "*" not in prefix else "")
                if stem not in seen:
                    seen.add(stem)
                    stems.append(stem)
                break

    if not stems:
        return {}
    # Map every fs-boundary to the same list — usually only one matches.
    return {bid: list(stems) for bid in fs_boundary_ids}


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


def _threat_counts_per_component(yaml_data: dict) -> tuple[dict[str, int], dict[str, int]]:
    """M3.3 / D1.5 (L) — Tally Critical / High threats per component_id.

    Walk threats[] once and group by `component_id` (or `component`).
    Threats without an explicit component reference are silently dropped
    — they would not contribute to per-component highlighting anyway.
    Returns ``(critical_counts, high_counts)``.
    """
    crit: dict[str, int] = {}
    high: dict[str, int] = {}
    for t in yaml_data.get("threats") or []:
        if not isinstance(t, dict):
            continue
        cid = t.get("component_id") or t.get("component")
        if not cid:
            continue
        risk = (t.get("risk") or t.get("severity") or "").lower()
        if risk == "critical":
            crit[cid] = crit.get(cid, 0) + 1
        elif risk == "high":
            high[cid] = high.get(cid, 0) + 1
    return crit, high


def _is_async_protocol(protocol: str) -> bool:
    """M3.3 / D1.5 (E) — classify a protocol as async/event-driven for
    arrow-style differentiation. Synchronous request/response protocols
    use a solid arrow; async/event-driven ones use a dashed arrow so the
    reader can distinguish a fire-and-forget WebSocket emit from a
    REST call at a glance."""
    p = (protocol or "").lower()
    return any(k in p for k in (
        "websocket", "socket.io", "ws ", "amqp", "kafka", "rabbit",
        "sqs", "sns", "pubsub", "queue", "event", "stream", "mqtt",
        "nats", "redis pub",
    ))


def _data_flow_edges(yaml_data: dict, components: list[dict]) -> list[str]:
    """Render mermaid edges from `data_flows[]` in the yaml.

    Each entry produces one line of the form
    ``<src_id> -->|<label>| <dst_id>`` so the §2.2 Container Architecture
    diagram reflects the actual cross-component traffic the orchestrator
    enumerated, not a hardcoded "client → app → data" stub.

    Tolerated entry shapes (M3.3 / D1.5):
      - ``{from, to, label, protocol, auth_method, data_classification}``  (canonical)
      - ``{src, dst, name}``                                  (legacy alias)
      - bare strings inside the list (silently dropped — defensive)

    Edge label format (D1.5):
      ``<protocol> / <auth_method> · <data_classification>``
    falling back to ``<protocol> · <data_classification>`` then to
    ``<label>`` then to ``→``.

    Arrow style (D1.5 / E):
      ``-->|`` for sync (REST/HTTPS/gRPC)
      ``-.->|`` for async (WebSocket / queue / event-bus)

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
        auth = (f.get("auth_method") or "").strip()
        data_class = (f.get("data_classification") or "").strip()

        # M3.3 / D1.5 (D) — Auth-method renders as `<protocol> / <auth>`
        # because the auth mechanism is what an attacker has to bypass,
        # not the data classification (which describes *what* but not *how*).
        head = " / ".join(p for p in (protocol, auth) if p) or label
        parts = [head] if head else []
        if data_class and data_class.lower() not in ("public", "n/a", "none"):
            parts.append(data_class)
        annotated = " · ".join(parts) if parts else "→"

        arrow = "-.->|" if _is_async_protocol(protocol) else "-->|"
        edges.append(
            f"{_safe_node_id(src)} {arrow}{annotated}| {_safe_node_id(dst)}"
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
    for idx, a in enumerate(assets, start=1):
        # Auto-assign A-NNN deterministically when the yaml-writer omitted
        # the id field (LLM schema-drift: some orchestrator runs produce
        # assets with name/classification/description but no id). Renderers
        # downstream depend on the ID column being non-"?" — fall back to
        # positional A-NNN so the column is usable.
        aid = a.get("id") or f"A-{idx:03d}"
        name = a.get("name", aid)
        clazz = a.get("classification", "_n/a_")
        desc = (a.get("description") or "").replace("\n", " ").strip()
        lines.append(f"| {name} | {aid} | {clazz} | {desc} |")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Generator: attack-surface.md
# ---------------------------------------------------------------------------

_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "WS", "ALL"}


def _attack_surface_route(entry: dict) -> str:
    """Return the route string. Schema v1 uses ``endpoint`` or ``path``;
    older orchestrator outputs used ``route`` or ``entry_point`` (the latter
    typically combines method + path, e.g. ``"POST /rest/user/login"``).
    Strip leading method tokens since method already gets its own column."""
    if not isinstance(entry, dict):
        return "?"
    raw = (entry.get("endpoint") or entry.get("path")
           or entry.get("route") or entry.get("entry_point") or "?").strip()
    # If "POST /foo" form, strip the method prefix — method has its own column.
    parts = raw.split(" ", 1)
    if len(parts) == 2 and parts[0].upper() in _HTTP_METHODS:
        return parts[1]
    return raw


def _attack_surface_method(entry: dict) -> str:
    """Return the HTTP method. Prefer the explicit ``method`` field; fall
    back to the leading token of ``entry_point`` (legacy schema where
    method+path are concatenated, e.g. ``"POST /rest/user/login"``)."""
    if not isinstance(entry, dict):
        return "?"
    explicit = (entry.get("method") or "").strip()
    if explicit:
        return explicit
    raw = (entry.get("entry_point") or "").strip()
    if raw:
        head = raw.split(" ", 1)[0].upper()
        if head in _HTTP_METHODS:
            return head
    return "?"


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
        # Stack with <br/> so each finding sits on its own line in the
        # rendered table cell — comma-joining 3+ links is unreadable. The
        # downstream linkifier appends the per-finding title as " — Title".
        linkified = "<br/>".join(f"[{t}](#{t.lower()})" for t in threats if isinstance(t, str))
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
        unauth = [e for e in flat if not (e.get("requires_auth") or e.get("auth_required")
                                          or e.get("authenticated"))]
        auth   = [e for e in flat if (e.get("requires_auth") or e.get("auth_required")
                                      or e.get("authenticated"))]
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
            method = _attack_surface_method(entry)
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
            method = _attack_surface_method(entry)
            route = _attack_surface_route(entry)
            notes = _attack_surface_notes(entry)
            lines.append(f"| {method} | `{route}` | {notes} |")
    else:
        lines.append("_None enumerated._")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Generator: use-cases.md
# ---------------------------------------------------------------------------

def gen_use_cases(yaml_data: dict) -> str:
    """## 6. Use Cases — one sub-section per use_case[] entry in the YAML."""
    use_cases = yaml_data.get("use_cases") or []
    components_map = {
        c["id"]: c.get("name", c["id"])
        for c in (yaml_data.get("components") or [])
        if isinstance(c, dict) and "id" in c
    }
    threats_map = {
        t["id"]: t.get("title", t["id"])
        for t in (yaml_data.get("threats") or [])
        if isinstance(t, dict) and "id" in t
    }

    lines = ["## 6. Use Cases", ""]
    if not use_cases:
        lines.append(
            "_No use cases defined in `threat-model.yaml`. "
            "Add entries to `use_cases[]` to populate this section._"
        )
        lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    lines.append(
        "Primary user-facing workflows documented for threat coverage analysis. "
        "Each use case lists the actors, components, and threat IDs that apply."
    )
    lines.append("")

    for uc in use_cases:
        if not isinstance(uc, dict):
            continue
        uid = uc.get("id", "UC-?")
        name = uc.get("name", uid)
        desc = uc.get("description", "")
        actors = uc.get("actors") or []
        comp_ids = uc.get("components") or []
        threat_ids = uc.get("threat_ids") or []

        lines.append(f"### {uid} — {name}")
        lines.append("")
        if desc:
            lines.append(desc)
            lines.append("")

        # Actors
        if actors:
            lines.append(f"**Actors:** {', '.join(str(a) for a in actors)}")
            lines.append("")

        # Components table
        if comp_ids:
            lines.append("**Components involved:**")
            lines.append("")
            lines.append("| Component | Description |")
            lines.append("|---|---|")
            for cid in comp_ids:
                cname = components_map.get(cid, cid)
                lines.append(f"| {cid} | {cname} |")
            lines.append("")

        # Linked threats
        if threat_ids:
            lines.append("**Linked threats:**")
            lines.append("")
            for tid in threat_ids:
                tlabel = threats_map.get(tid, tid)
                lines.append(f"- [{tid}](#{tid.lower()}) — {tlabel}")
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
    ("7.11", "Container & Runtime Security"),
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
    "7.9":  ("ai / llm", "artificial intelligence", "llm", "prompt injection", "ml model"),
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
    "7.3":  {"CWE-287", "CWE-308", "CWE-307", "CWE-294", "CWE-345", "CWE-384",
             "CWE-347", "CWE-916"},   # CWE-347 sig-verify, CWE-916 weak password hash
    "7.4":  {"CWE-285", "CWE-639", "CWE-862", "CWE-863", "CWE-732", "CWE-269",
             "CWE-915"},              # CWE-915 mass assignment / over-permissive PATCH
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


# ---------------------------------------------------------------------------
# Deterministic Gap Summary (replaces the LLM-authored GAP_SUMMARY_PLACEHOLDER).
# Produces a Markdown table grouped by control domain — the top-K weak/missing
# control clusters ranked by the cumulative severity of their linked threats.
# Owns its own data extraction so the §7 scaffold can drop the placeholder
# entirely; the LLM no longer composes this paragraph and cannot drift it
# into a free-prose "First, … Second, … Third, …" wall.
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _threat_index(threats: list) -> dict[str, dict]:
    """Build {T-NNN-upper: threat-dict} index. Tolerates legacy ``t_id`` field."""
    idx: dict[str, dict] = {}
    for t in threats or []:
        if not isinstance(t, dict):
            continue
        tid = (t.get("id") or t.get("t_id") or "").strip().upper()
        if tid:
            idx[tid] = t
    return idx


def _threat_label(t: dict) -> str:
    """Short threat label for the Linked Threats column.
    Mirrors the fallback chain qa_checks.linkify_anchors uses (title →
    scenario_short → first-clause-of-scenario → ID-only)."""
    if not isinstance(t, dict):
        return ""
    label = (t.get("title") or t.get("scenario_short") or "").strip()
    if label:
        return label
    scen = (t.get("scenario") or "").strip()
    if scen:
        # First clause up to the first sentence boundary, capped at 80 chars.
        # Manual split keeps us out of the `re` module (kept stdlib-light to
        # match the rest of pregenerate_fragments.py).
        cut = len(scen)
        for sep in (". ", "! ", "? "):
            i = scen.find(sep)
            if i != -1 and i < cut:
                cut = i + 1   # include the punctuation, drop the trailing space
        return scen[:cut][:80].rstrip()
    return ""


def _threat_evidence_files(t: dict, max_files: int = 2) -> list[str]:
    """Return up to `max_files` ``file:line`` strings from a threat's evidence."""
    if not isinstance(t, dict):
        return []
    out: list[str] = []
    for ev in (t.get("evidence") or []):
        if not isinstance(ev, dict):
            continue
        f = (ev.get("file") or "").strip()
        if not f:
            continue
        line = ev.get("line")
        out.append(f"{f}:{line}" if line else f)
        if len(out) >= max_files:
            break
    return out


def _build_gap_summary(controls: list[dict], threats: list, k: int = 3) -> list[dict]:
    """Group weak/missing controls by domain, rank by cumulative threat
    severity, return the top-K gaps each with title, evidence and threat list.

    Output shape per gap:
        {
            "title":    "<Domain> — <primary control>",
            "evidence": "<file:line> · <file:line>",  # deduped, max 3
            "threats":  [(tid, label), ...],          # deduped, severity-sorted
            "score":    int,                           # cumulative severity
        }

    Empty list when no weak/missing control has cross-linked threats — the
    renderer then suppresses the entire Gap-Summary block (better than
    showing an empty table).
    """
    if not controls:
        return []
    t_idx = _threat_index(threats)

    # Bucket controls by lowercase-trimmed domain so case-drift in the YAML
    # does not split logically identical groups.
    by_domain: dict[str, dict] = {}
    for c in controls:
        eff = (c.get("effectiveness") or "").lower()
        if eff not in ("weak", "missing"):
            continue
        domain = (c.get("domain") or "").strip()
        key = domain.lower() or "_uncategorised"
        bucket = by_domain.setdefault(key, {
            "domain":   domain or "Uncategorised",
            "controls": [],
            "tids":     [],   # preserves first-seen order for deterministic output
            "score":    0,
        })
        bucket["controls"].append(c)
        for tid in (c.get("linked_threats") or []):
            tid_u = str(tid).strip().upper()
            if tid_u and tid_u not in bucket["tids"]:
                bucket["tids"].append(tid_u)
                t = t_idx.get(tid_u)
                if t is not None:
                    sev = (t.get("risk") or t.get("severity") or "").lower()
                    bucket["score"] += _SEVERITY_WEIGHT.get(sev, 0)

    # Drop buckets with zero linked threats — they cannot meaningfully
    # populate the Linked Threats column and would render as visual noise.
    candidates = [b for b in by_domain.values() if b["tids"]]
    # Tie-break: higher score first, then more linked threats, then more
    # weak/missing controls in the domain, then domain name (alphabetical)
    # for full determinism.
    candidates.sort(key=lambda b: (
        -b["score"], -len(b["tids"]), -len(b["controls"]), b["domain"].lower()
    ))

    gaps: list[dict] = []
    for bucket in candidates[:k]:
        # Primary control = the one whose linked_threats sum to the highest
        # severity score within the bucket. Falls back to first listed.
        def _ctrl_score(c: dict) -> int:
            return sum(
                _SEVERITY_WEIGHT.get(
                    (t_idx.get(str(tid).strip().upper(), {}).get("risk")
                     or "").lower(), 0)
                for tid in (c.get("linked_threats") or [])
            )
        primary = max(bucket["controls"], key=_ctrl_score)
        ctrl_name = (primary.get("control") or "").strip() or "(unspecified control)"
        n_extra = len(bucket["controls"]) - 1
        title = f"{bucket['domain']} — {ctrl_name}"
        if n_extra > 0:
            title += f" *(+ {n_extra} related)*"

        # Dedup evidence files across all threats in the bucket, cap at 3.
        ev_seen: list[str] = []
        for tid in bucket["tids"]:
            for f in _threat_evidence_files(t_idx.get(tid, {})):
                if f not in ev_seen:
                    ev_seen.append(f)
                if len(ev_seen) >= 3:
                    break
            if len(ev_seen) >= 3:
                break
        evidence = " · ".join(f"`{f}`" for f in ev_seen) or "_(no file evidence)_"

        # Sort threats inside the cell by severity descending so the most
        # important one is read first; preserve first-seen order on ties.
        def _tid_rank(tid: str) -> int:
            sev = (t_idx.get(tid, {}).get("risk")
                   or t_idx.get(tid, {}).get("severity") or "").lower()
            return -_SEVERITY_WEIGHT.get(sev, 0)
        sorted_tids = sorted(bucket["tids"], key=_tid_rank)
        thr_pairs = [(tid, _threat_label(t_idx.get(tid, {}))) for tid in sorted_tids]

        gaps.append({
            "title":    title,
            "evidence": evidence,
            "threats":  thr_pairs,
            "score":    bucket["score"],
        })
    return gaps


def _render_gap_summary_block(gaps: list[dict]) -> list[str]:
    """Render the Gap-Summary table as Markdown lines (no trailing newline).
    Returns an empty list when there are no gaps — caller should then skip
    emitting the block entirely."""
    if not gaps:
        return []
    n = len(gaps)
    plural = "s" if n != 1 else ""
    intro = (
        f"**Gap summary** — the {n} control gap{plural} below account for the "
        "majority of Critical / High findings. Each row groups a control domain "
        "with its cross-linked threats, ranked by cumulative severity."
    )
    lines = [intro, ""]
    lines.append("| Gap | Evidence | Linked Threats |")
    lines.append("|---|---|---|")
    for g in gaps:
        if g["threats"]:
            cells = []
            for tid, label in g["threats"]:
                anchor = tid.lower()
                # Pipe-escape inside the cell so a `|` in a label does not
                # break the row.
                lbl = (label or "").replace("|", "\\|")
                cells.append(f"[{tid}](#{anchor}) — {lbl}" if lbl
                             else f"[{tid}](#{anchor})")
            threats_cell = "<br/>".join(cells)
        else:
            threats_cell = "_(no cross-linked threats)_"
        lines.append(f"| {g['title']} | {g['evidence']} | {threats_cell} |")
    return lines


def gen_security_architecture(yaml_data: dict) -> str:
    """## 7. Security Architecture — structural scaffold for the Phase-11 agent.

    This function generates a SCAFFOLD, not a finished document. The Phase-11
    agent fills the narrative content (domain assessments, gap summary, flow
    introductions, findings-in-flow lists) using the instructions in
    phase-group-finalization.md §§558-718.

    Design contract:
    - Every required heading (7.1-7.14) is emitted so the pre-render gate passes.
    - Each domain section includes:
        * A NARRATIVE_PLACEHOLDER comment the agent replaces with its assessment.
        * A machine-derived controls table as a data anchor the agent can reference.
        * For 7.3 IAM: per-auth-method #### blocks with sequenceDiagram stubs and
          a FINDINGS_PLACEHOLDER the agent replaces with correct finding links.
    - Sections 7.8/7.9 are suppressed when the catalog has zero matching controls
      AND zero matching threats — they are not applicable to the assessed system.
    - 7.13 and 7.14 always emit (cross-cutting, always relevant).
    - The Gap-Summary block at the top of §7 is rendered deterministically
      from `security_controls[]` + `threats[]` via `_build_gap_summary` —
      no LLM placeholder, no free-prose drift.
    """
    controls = _normalize_security_controls(yaml_data.get("security_controls"))
    components = yaml_data.get("components") or []
    threats = yaml_data.get("threats") or []

    # Pre-compute effectiveness counts for catalog totals line.
    eff_counts: dict[str, int] = {}
    for c in controls:
        eff = (c.get("effectiveness") or "unknown").lower()
        eff_counts[eff] = eff_counts.get(eff, 0) + 1
    n_adequate = eff_counts.get("adequate", 0)
    n_partial   = eff_counts.get("partial", 0)
    n_weak      = eff_counts.get("weak", 0)
    n_missing   = eff_counts.get("missing", 0)

    lines = ["## 7. Security Architecture", ""]
    lines.append(
        "This section consolidates the architectural narrative with the canonical "
        "control catalog. Each domain contains an assessment of how well the control "
        "is implemented and references to the concrete findings that exploit its gaps."
    )
    lines.append("")
    lines.append(
        f"**Catalog totals:** ✅ {n_adequate} Adequate · ⚠️ {n_partial} Partial · "
        f"🔶 {n_weak} Weak · ❌ {n_missing} Missing · {len(controls)} controls tracked."
    )
    lines.append("")
    # Deterministic Gap Summary — replaces the LLM-authored prose paragraph
    # that historically drifted into "First, … Second, … Third, …" walls of
    # comma-separated bare T-IDs (qa_checks.summary_bullets only catches the
    # `(1) … (2) …` variant, not the prose-numbering form). Built from the
    # same security_controls[] + threats[] data the LLM would have used.
    gap_block = _render_gap_summary_block(
        _build_gap_summary(controls, threats, k=3)
    )
    if gap_block:
        lines.extend(gap_block)
        lines.append("")

    # -------------------------------------------------------------------------
    # 7.1 Overview
    # -------------------------------------------------------------------------
    lines.append("### 7.1 Overview")
    lines.append("")
    lines.append(
        f"Across {len(components)} component(s) the assessment catalogued "
        f"{len(controls)} security control(s)."
    )
    if controls:
        eff_bullet = " · ".join(
            f"**{k}**: {v}" for k, v in sorted(eff_counts.items()) if k != "unknown"
        )
        lines.append("")
        lines.append(f"Effectiveness breakdown: {eff_bullet}.")
    lines.append("")

    # -------------------------------------------------------------------------
    # 7.2 Key Architectural Risks — scaffold table from weak/missing controls
    # The agent should expand this with a prose intro per finalization.md §591.
    # -------------------------------------------------------------------------
    lines.append("### 7.2 Key Architectural Risks")
    lines.append("")
    lines.append("<!-- NARRATIVE_PLACEHOLDER: domain=KeyRisks — add 1-2 sentence intro before table. -->")
    lines.append("")
    weak_controls = [c for c in controls if (c.get("effectiveness") or "").lower() in ("weak", "missing")]
    if weak_controls:
        lines.append("| Domain | Control | Effectiveness | Notes |")
        lines.append("|---|---|---|---|")
        for c in weak_controls[:8]:
            domain = c.get("domain", "_?_")
            ctrl   = c.get("control", "_?_")
            eff    = c.get("effectiveness", "_?_")
            notes  = _control_notes(c)
            lines.append(f"| {domain} | {ctrl} | {eff} | {notes} |")
    else:
        lines.append("_No weak/missing controls cataloged._")
    lines.append("")

    # -------------------------------------------------------------------------
    # 7.3 – 7.12: per-domain sections
    # Sections 7.8 (Real-time/WebSocket) and 7.9 (AI/LLM) are suppressed when
    # neither controls nor threats map to them — emitting empty AI/LLM sections
    # for repos with no AI surface is misleading noise.
    # -------------------------------------------------------------------------
    for section_id, title in _SECARCH_SUBSECTIONS[2:12]:
        matched = _controls_for_subsection(controls, section_id)
        domain_threats = _threats_for_subsection(threats, section_id)

        # §7.8 and §7.9 are required by sections-contract.yaml even when empty.
        # Emit a "Not applicable" stub rather than suppressing so the pre-render
        # gate passes. The agent may replace it with real content if relevant.
        if section_id in ("7.8", "7.9") and not matched and not domain_threats:
            lines.append(f"### {section_id} {title}")
            lines.append("")
            _not_applicable_body = {
                "7.8": "Real-time / WebSocket",
                "7.9": "AI / LLM",
            }
            topic = _not_applicable_body.get(section_id, title)
            lines.append(
                f"_Not applicable — no {topic} usage detected by recon-scanner "
                f"and no controls or threats mapped to this domain._"
            )
            lines.append("")
            continue

        lines.append(f"### {section_id} {title}")
        lines.append("")
        # Agent replaces this with the domain assessment narrative.
        lines.append(
            f"<!-- NARRATIVE_PLACEHOLDER: domain={section_id} — replace with 2-4 sentence "
            f"assessment: overall control posture for this domain, key implementation "
            f"references (file:line), and which threats directly exploit the gaps. -->"
        )
        lines.append("")

        if matched:
            lines.append("| Control | Implementation | Effectiveness | Notes |")
            lines.append("|---|---|---|---|")
            for c in matched:
                ctrl  = c.get("control", "_?_")
                impl  = c.get("implementation", "_?_")
                eff   = c.get("effectiveness", "_?_")
                notes = _control_notes(c)
                lines.append(f"| {ctrl} | {impl} | {eff} | {notes} |")
        else:
            if domain_threats:
                lines.append(
                    "_No dedicated control cataloged for this domain — "
                    "the findings below indicate the gap._"
                )
                lines.append("")
                lines.append("| Finding | Severity | CWE |")
                lines.append("|---------|----------|-----|")
                for t in domain_threats[:6]:
                    tid     = t.get("id", "?")
                    sev     = (t.get("risk") or t.get("severity") or "—").capitalize()
                    cwes    = t.get("cwe") or t.get("cwes") or []
                    if isinstance(cwes, str):
                        cwes = [cwes]
                    cwe_cell = ", ".join(c for c in cwes if isinstance(c, str)) or "—"
                    lines.append(f"| [{tid}](#{tid.lower()}) | {sev} | {cwe_cell} |")
            else:
                lines.append(
                    "_No controls cataloged and no findings mapped to this domain. "
                    "If applicable to this system, note the absence explicitly._"
                )
        lines.append("")

        # §7.3 IAM: per-auth-method #### sub-blocks (contract requirement).
        # The agent fills (a) flow intro, (b) sequenceDiagram content,
        # (c) risk assessment narrative, and (d) findings-in-flow links.
        # The stubs here satisfy the pre-render gate while giving the agent
        # concrete anchors to work from.
        if section_id == "7.3":
            iam_blocks = matched if matched else [
                {"control": "Authentication Flow", "implementation": "_(not catalogued)_"}
            ]
            for idx, c in enumerate(iam_blocks, start=1):
                ctrl    = (c.get("control") or "Authentication Flow").strip()
                impl    = (c.get("implementation") or "_n/a_").strip()
                heading = ctrl if ctrl.endswith(" Flow") else f"{ctrl} Flow"
                lines.append(f"#### 7.3.{idx} {heading}")
                lines.append("")
                # Agent replaces this with a 2-3 sentence intro naming endpoint
                # paths, implementation files, crypto primitives, TTL, rate-limit.
                lines.append(
                    f"<!-- NARRATIVE_PLACEHOLDER: flow=7.3.{idx} — replace with 2-3 sentence "
                    f"intro: endpoint path(s), implementation file:line, crypto primitives "
                    f"or libraries, token TTL, rate-limiting status. -->"
                )
                lines.append("")
                lines.append(f"**Implementation:** `{impl}`")
                lines.append("")
                lines.extend(_iam_flow_sequence(ctrl, impl, threats))
                lines.append("")
                # Agent replaces with 2-4 sentences: worst outcome, attacker
                # positions, compounding weaknesses, residual risk rating.
                lines.append(
                    "**Risk assessment:** "
                    "<!-- replace with 2-4 sentence assessment ending with: "
                    "**Residual risk:** Critical|High|Medium|Low — justification. -->"
                )
                lines.append("")
                # Pre-filter §7.3 threats to those most likely relevant to
                # this specific flow, using control-name keyword matching.
                # The agent prunes / adds as needed — this is a starting hint,
                # not a definitive assignment.
                ctrl_lower = ctrl.lower()
                iam_threats = _threats_for_subsection(threats, "7.3")
                # Keyword sets per control type — a threat is "likely relevant"
                # to this flow when its title contains any keyword, OR when it
                # has a CWE that matches the flow's primary concern.
                _flow_keywords: dict[str, tuple[str, ...]] = {
                    "jwt":      ("jwt", "alg", "token", "bearer", "signing", "rs256", "hs256"),
                    "oauth":    ("oauth", "oidc", "openid", "social", "google", "facebook"),
                    "password": ("password", "md5", "hash", "bcrypt", "credential", "login",
                                 "brute", "sql inject"),
                    "2fa":      ("2fa", "totp", "otp", "mfa", "multi-factor"),
                    "rbac":     ("role", "rbac", "authoriz", "privilege", "admin", "permission"),
                    "session":  ("session", "cookie", "logout", "fixation"),
                }
                # Pick the best matching keyword set for this control.
                flow_hints: tuple[str, ...] = ()
                for key, kws in _flow_keywords.items():
                    if any(k in ctrl_lower for k in kws):
                        flow_hints = kws
                        break

                def _threat_likely_for_flow(t: dict) -> bool:
                    if not flow_hints:
                        return True  # no hints → include all
                    t_title = (t.get("title") or "").lower()
                    return any(k in t_title for k in flow_hints)

                relevant_threats = [t for t in iam_threats if _threat_likely_for_flow(t)]
                # Fall back to all §7.3 threats when filter is too aggressive.
                if not relevant_threats:
                    relevant_threats = iam_threats

                if relevant_threats:
                    lines.append("**Findings in this flow:**")
                    lines.append("<!-- FINDINGS_PLACEHOLDER: replace the list below with only the "
                                 "findings that apply to THIS specific auth flow, not all IAM threats. -->")
                    for t in relevant_threats[:5]:
                        tid   = t.get("id", "?")
                        title = (t.get("title") or "").replace("|", "\\|")
                        lines.append(f"- [{tid}](#{tid.lower()}) — {title}")
                else:
                    lines.append("**Findings in this flow:** — none")
                lines.append("")

    # -------------------------------------------------------------------------
    # 7.13 Secret Management (cross-cutting — always emitted)
    # -------------------------------------------------------------------------
    lines.append("### 7.13 Secret Management *(cross-cutting)*")
    lines.append("")
    lines.append("<!-- NARRATIVE_PLACEHOLDER: domain=SecretMgmt — replace with 2-3 sentence "
                 "assessment of how secrets (keys, credentials, tokens) are managed: "
                 "env vars vs. hardcoded, rotation capability, leakage paths. -->")
    lines.append("")
    secret_controls = _controls_for_subsection(controls, "7.13")
    if secret_controls:
        lines.append("| Control | Implementation | Effectiveness | Notes |")
        lines.append("|---|---|---|---|")
        for c in secret_controls:
            lines.append(
                f"| {c.get('control', '_?_')} | {c.get('implementation', '_?_')} | "
                f"{c.get('effectiveness', '_?_')} | {_control_notes(c)} |"
            )
    else:
        lines.append(
            "_No dedicated secret-management control cataloged. See §8 for "
            "hardcoded-secret findings (CWE-321 / CWE-798)._"
        )
    lines.append("")

    # -------------------------------------------------------------------------
    # 7.14 Defense-in-Depth Assessment (cross-cutting — always emitted)
    # -------------------------------------------------------------------------
    lines.append("### 7.14 Defense-in-Depth Assessment *(cross-cutting)*")
    lines.append("")
    lines.append("<!-- NARRATIVE_PLACEHOLDER: domain=DefenseInDepth — replace with a layered "
                 "evaluation: which defensive layers (WAF/gateway, rate-limiting, CSP, "
                 "logging/alerting) exist and which are missing. -->")
    lines.append("")
    if controls:
        lines.append(
            f"Of {len(controls)} cataloged controls: ✅ **{n_adequate}** adequate, "
            f"⚠️ **{n_partial}** partial, 🔶 **{n_weak}** weak, ❌ **{n_missing}** missing."
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
    "use-cases.md":             gen_use_cases,
    "security-architecture.md": gen_security_architecture,
    "out-of-scope.md":          gen_out_of_scope,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pregenerate_fragments.py",
        description="Pre-generate the deterministic structural fragments.",
    )
    parser.add_argument("output_dir", type=Path,
                        help="Assessment output directory (typically <repo>/docs/security).")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite existing fragments. Default is idempotent.")
    parser.add_argument("--only", type=str, default="",
                        help="Comma-separated fragment names to generate (default: all).")
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
