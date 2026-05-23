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

(``use-cases.md`` was retired in 2026-05; the §6 numbering gap is intentional.)

Pre-generating these takes 6 LLM Write tool-calls off the orchestrator's
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
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

import yaml

# Sibling module — deterministic §3 walkthrough renderer. Imported here
# (and not lazily) so its GENERATORS entry below resolves at import time.
from walkthrough_renderer import gen_attack_walkthroughs

# ---------------------------------------------------------------------------
# Contract-driven compactness rules. The data lives in
# `data/sections-contract.yaml → sections.architecture_diagrams.diagram_compactness`
# (post-2026-05). Pre-Gen reads the rules at import time and applies them
# verbatim — we never re-implement a limit in Python; if a number needs to
# change, it changes in the contract.
# ---------------------------------------------------------------------------

_CONTRACT_PATH = Path(__file__).resolve().parent.parent / "data" / "sections-contract.yaml"
_DIAGRAM_COMPACTNESS_CACHE: dict | None = None
_ARCH_CONTROLS_PATH = Path(__file__).resolve().parent.parent / "data" / "architectural-controls.yaml"
_ARCH_CONTROLS_CACHE: dict | None = None


def _load_diagram_compactness() -> dict:
    """Return the `diagram_compactness:` map from the sections contract.
    Cached after first read. Returns an empty dict when the contract does
    not declare the block (legacy contracts) so callers fall back to their
    pre-2026-05 behaviour."""
    global _DIAGRAM_COMPACTNESS_CACHE
    if _DIAGRAM_COMPACTNESS_CACHE is not None:
        return _DIAGRAM_COMPACTNESS_CACHE
    try:
        contract = yaml.safe_load(_CONTRACT_PATH.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        contract = {}
    arch = (contract.get("sections") or {}).get("architecture_diagrams") or {}
    _DIAGRAM_COMPACTNESS_CACHE = arch.get("diagram_compactness") or {}
    return _DIAGRAM_COMPACTNESS_CACHE


def _load_posture_actor_labels_for_pregen() -> dict:
    """Read `data/posture-actor-labels.yaml` so the §2.3 generator can
    project external actors from the same canonical source the heatmap
    uses. Falls back silently when the file is unreadable — §2.3 then
    omits the EXT subgraph rather than failing."""
    path = Path(__file__).resolve().parent.parent / "data" / "posture-actor-labels.yaml"
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}


# ---------------------------------------------------------------------------
# Tier classification — components are mapped into Client / Application /
# Data tiers using a heuristic on id/name/paths. Used by §2 diagrams and §7.
# ---------------------------------------------------------------------------

_TIER_HINTS = {
    "client": ("frontend", "spa", "ui", "browser", "angular", "react", "vue", "client"),
    "data": (
        "nosql",
        "sql",
        "mongo",
        "postgres",
        "mysql",
        "redis",
        "datalayer",
        "data-layer",
        "persistence",
        "store",
        "db",
        "database",
    ),
    # application is the default catch-all
}


def _classify_tier(component: dict) -> str:
    """Return 'client' | 'application' | 'data' for a component."""
    haystack = " ".join(
        [
            (component.get("id") or "").lower(),
            (component.get("name") or "").lower(),
            " ".join(component.get("paths") or []).lower(),
        ]
    )
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

    # Fall back to package.json when meta.project is a plain string (no desc/runtime sub-fields).
    # The output schema stores meta.project as a string, so the LLM never writes a dict —
    # reading package.json directly is the only way to populate these fields.
    # Walk from CWD (the repo root when called as
    #   python3 .../pregenerate_fragments.py <output_dir>)
    # rather than from __file__ (which is inside the plugin, not the repo).
    if not desc or not runtime:
        try:
            search_root = Path.cwd()
            for _ in range(6):
                candidate = search_root / "package.json"
                if candidate.is_file():
                    pkg = json.loads(candidate.read_text(encoding="utf-8"))
                    # Skip the plugin's own package.json (has no "description" field
                    # that makes sense as a system overview, or can be detected by name)
                    pkg_name = pkg.get("name", "")
                    if "appsec" in pkg_name or "advisor" in pkg_name:
                        search_root = search_root.parent
                        continue
                    if not desc:
                        desc = (pkg.get("description") or "").strip()
                    if not runtime:
                        engines = pkg.get("engines") or {}
                        node_ver = engines.get("node", "")
                        if node_ver:
                            runtime = f"Node.js {node_ver}"
                    break
                search_root = search_root.parent
        except Exception:  # noqa: BLE001
            pass
    top_project = yaml_data.get("project") or {}
    repository = project.get("repository") or top_project.get("repository") or meta.get("repo_url") or ""
    if not repository:
        try:
            result = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                repository = result.stdout.strip()
        except Exception:  # noqa: BLE001
            pass

    lines = ["## 1. System Overview", ""]
    if desc:
        lines.append(desc.rstrip("."))
        lines.append("")

    lines.append(f"**Repository:** {repository or '_n/a_'}")
    if runtime:
        # Runtime values like "Node.js 20 - 24" are product/version labels,
        # not code. Render in normal prose weight. The dot-TLD safety pass
        # in compose has an allowlist that prevents Node.js, Vue.js, etc.
        # from being re-wrapped.
        lines.append(f"**Runtime:** {runtime}")
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
        f"Who interacts with {name} from the outside, and through which channels. "
        "Solid arrows show normal usage; dashed red arrows mark unauthenticated "
        "probing or exploit paths (C4 Level 1)."
    )
    lines.append("")
    lines.extend(_system_context_mermaid(yaml_data, name))
    lines.append("")

    # ----- 2.2 Container Architecture ----------------------------------------
    lines.append("### 2.2 Container Architecture")
    lines.append("")
    lines.append(
        "How the system decomposes into deployable units. Each box is a separate "
        "runtime process or service container; arrows show synchronous request "
        "paths between them. Components with ≥3 Critical findings carry a red "
        "border, ≥2 High amber (C4 Level 2)."
    )
    lines.append("")

    # M3.3 / D1.5 (G) — DB-engine annotation when not already in name.
    def _component_label(c: dict) -> str:
        nm = (c.get("name") or c.get("id") or "?").replace('"', "'")
        engine = (c.get("engine") or "").strip()
        if engine and engine.lower() not in nm.lower():
            return f"{nm}<br/>{engine}"
        return nm

    # M3.3 / D1.5 (L) — pre-compute Critical / High threat counts per
    # component so the mermaid block can apply classDef highlighting.
    crit_counts, high_counts = _threat_counts_per_component(yaml_data)

    lines.append("```mermaid")
    lines.append("flowchart TB")
    lines.append("    subgraph Client")

    if by_tier["client"]:
        for c in by_tier["client"]:
            lines.append(f'        {_safe_node_id(c["id"])}["{_component_label(c)}"]')
    else:
        lines.append('        BROWSER["Browser Runtime"]')
    lines.append("    end")
    lines.append("    subgraph Application")
    if by_tier["application"]:
        for c in by_tier["application"]:
            lines.append(f'        {_safe_node_id(c["id"])}["{_component_label(c)}"]')
    else:
        lines.append('        APP["Application Server"]')
    lines.append("    end")
    lines.append("    subgraph Data")
    if by_tier["data"]:
        for c in by_tier["data"]:
            lines.append(f'        {_safe_node_id(c["id"])}[("{_component_label(c)}")]')
    else:
        lines.append('        DATA[("Data Layer")]')
    lines.append("    end")

    # M3.3 / D1 — render edges from `data_flows[]` when the orchestrator
    # populated it; fall back to the legacy 1-pfeil-pro-tier-paar heuristic
    # when empty so old yamls still get a meaningful diagram.
    flow_edges = _data_flow_edges(yaml_data, components)
    if flow_edges:
        for edge in flow_edges:
            lines.append(f"    {edge}")
    else:
        # Legacy fallback — connect every component to the next tier so
        # multi-component application tiers don't leave nodes stranded
        # without edges. The first application-tier component is treated
        # as the "primary" entry point (single inbound from each client
        # node + single outbound to each data-tier node); secondary
        # application-tier components are connected back to the primary
        # via in-process call edges so they show up as part of the
        # application cluster instead of floating freely.
        primary_app = _safe_node_id(by_tier["application"][0]["id"]) if by_tier["application"] else None
        if by_tier["client"] and primary_app:
            for c_comp in by_tier["client"]:
                c = _safe_node_id(c_comp["id"])
                lines.append(f"    {c} -->|HTTPS REST| {primary_app}")
        if primary_app and by_tier["data"]:
            for d_comp in by_tier["data"]:
                d = _safe_node_id(d_comp["id"])
                lines.append(f"    {primary_app} -->|driver| {d}")
        elif primary_app:
            # No data-tier components in YAML, but the fallback DATA node was
            # rendered (line above). Emit the edge so the node is not an island.
            lines.append(f"    {primary_app} -->|driver| DATA")
        # Secondary application components — connect back to the primary
        # so they appear within the application cluster rather than as
        # stranded nodes (file-upload-service, b2b-api, etc. are typically
        # in-process modules of the primary backend).
        for extra in by_tier["application"][1:]:
            extra_id = _safe_node_id(extra["id"])
            lines.append(f"    {primary_app} -->|in-process| {extra_id}")

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
        lines.append("    classDef critical fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:3px")
        lines.append("    classDef warning  fill:#fef3c7,stroke:#b45309,color:#78350f,stroke-width:2px")
        for n in crit_class_lines:
            lines.append(f"    class {n} critical")
        for n in warn_class_lines:
            lines.append(f"    class {n} warning")

    lines.append("```")
    lines.append("")

    # ----- 2.3 Components ----------------------------------------------------
    # Compact 4-tier layout (post-2026-05) per
    # `data/sections-contract.yaml → diagram_compactness."2.3 Components"`.
    # Layout: `flowchart TD`, 4 tier-subgraphs (EXT/CLIENT/APP/DATA), max
    # 8 nodes total, max 3 label lines / 60 chars per line. Sub-components
    # within a tier are aggregated into the parent node label as bullets
    # so the diagram stays at one component per tier even for multi-
    # service decompositions. The detailed source-path inventory moves to
    # the table below the diagram (which also satisfies the threat-
    # traceability check).
    lines.append("### 2.3 Components")
    lines.append("")
    lines.append(
        "Who reaches each component, and through which trust zone. Four "
        "columns map external actors to the internal tiers (Client / "
        "Application / Data); solid green arrows show legitimate data flow, "
        "dashed red arrows mark intrusion vectors. The component table "
        "directly below holds source paths and linked threats per `C-NN`; "
        "per-tech defects are itemised in the §2.4.1–§2.4.4 layer tables."
    )
    lines.append("")
    lines.extend(_components_diagram_compact(yaml_data, by_tier))
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
    # Compact tier-stack layout (post-2026-05) per
    # `data/sections-contract.yaml → diagram_compactness."2.4 Technology Architecture"`.
    # Flowchart-TD only — trust-boundary table and §2.4.1–§2.4.4 layer
    # tables were removed (2026-05): the trust boundaries duplicated content
    # available in `threat-model.yaml → trust_boundaries[]`, and the layer
    # tables duplicated the §2.3 component table and §8 Threat Register
    # without adding new signal. §2.4 is now pure technology-stack overview.
    lines.append("### 2.4 Technology Architecture")
    lines.append("")
    lines.append(
        "The technology stack the system is built on. Each box names the "
        "framework or runtime that fills that role; per-component findings "
        "live in the §2.3 component table above, and the full per-finding "
        "catalogue is in [§8 Threat Register](#8-threat-register)."
    )
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
    has_async = any(isinstance(f, dict) and _is_async_protocol(f.get("protocol", "")) for f in flows)
    has_flows = bool(
        [f for f in flows if isinstance(f, dict) and (f.get("from") or f.get("src")) and (f.get("to") or f.get("dst"))]
    )
    boundaries = yaml_data.get("trust_boundaries") or []
    has_cross_boundary = bool(boundaries) and has_flows
    crit_counts, high_counts = _threat_counts_per_component(yaml_data)
    has_highlight = any(v >= 3 for v in crit_counts.values()) or any(v >= 2 for v in high_counts.values())

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
        bullets.append("**red border** ≥ 3 Critical threats on the component · **amber border** ≥ 2 High threats")

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
    actors: list[tuple[str, str, str]] = []  # (id, label, css_class)
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
        css = "attacker" if role in ("attacker", "threat-actor") else "admin" if role == "admin" else "user"
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
        haystack = " ".join(
            [
                " ".join((t.get("title") or "") for t in threats if isinstance(t, dict)),
                " ".join(
                    (c.get("control") or "") + " " + (c.get("implementation") or "")
                    for c in controls
                    if isinstance(c, dict)
                ),
            ]
        ).lower()
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
    ext_in: list[tuple[str, str, str]] = []  # (id, label, protocol)
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
        edge_label = f"outbound · {proto}" if proto else "outbound HTTP"
        out.append(f"    {sys_id} -->|{edge_label}| {eid}")

    # Edges — system → external DB (bidirectional in protocol but the
    # convention is: app initiates, hence one-way arrow).
    for eid, _label, proto in ext_db:
        edge_label = proto or "DB protocol"
        out.append(f"    {sys_id} -->|{edge_label}| {eid}")

    # Class definitions + assignments. Audit palette (post-2026-05) — see
    # phase-group-finalization.md → "Architecture Diagrams (§2)" for the
    # color contract. The earlier C4-ish palette (`#dbeafe`, `#fecaca`,
    # `#dcfce7`, etc.) clashed visually with the heatmap and printed
    # poorly in B/W audit packs.
    # Only emit classDef entries that are actually referenced. Earlier
    # versions emitted `ext` and `extdb` unconditionally even when no
    # external service / external DB was present, which left dead classDef
    # lines in the §2.1 mermaid block (render bloat — picked up by
    # diagram-compactness audits).
    used_classes: set[str] = {css for _, _, css in actors}
    used_classes.add("sys")
    if ext_in:
        used_classes.add("ext")
    if ext_out:
        used_classes.add("ext")
    if ext_db:
        used_classes.add("extdb")
    classdef_map = {
        "user": "fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:1.5px",
        "attacker": "fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:2px",
        "admin": "fill:#fef3c7,stroke:#b45309,color:#78350f,stroke-width:1.5px",
        "sys": "fill:#f2f2f2,stroke:#424242,color:#111,stroke-width:1.5px",
        "ext": "fill:#f2f2f2,stroke:#9e9e9e,color:#424242,stroke-dasharray:3 3,stroke-width:1px",
        "extdb": "fill:#f2f2f2,stroke:#424242,color:#111,stroke-dasharray:3 3,stroke-width:1.5px",
    }
    for css_name, css_value in classdef_map.items():
        if css_name in used_classes:
            out.append(f"    classDef {css_name:8s} {css_value}")
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


# ===========================================================================
# Compact diagram builders (§2.3 / §2.4) — contract-driven (post-2026-05).
#
# Both builders share these properties:
#   * Read structural rules from `data/sections-contract.yaml →
#     diagram_compactness.<heading>` (max_subgraphs, max_nodes_total,
#     required_subgraphs, required_classdefs, edge_convention).
#   * Emit `flowchart TD` with at most max_subgraphs subgraphs.
#   * Keep node labels at ≤max_label_lines lines, each ≤max_label_chars.
#   * Aggregate sub-components into bullet lists in the parent label so
#     a tier with 5 components still renders as 1 main node.
#   * Emit the contract-defined classDef block at the bottom of the
#     mermaid block.
#   * Emit linkStyle entries that follow the contract's edge_convention.
# ===========================================================================


def _truncate_title_balanced(text: str, max_len: int = 60) -> str:
    """Truncate ``text`` to ≤ ``max_len`` chars while keeping inline-code
    spans (`` ` `` … `` ` ``) balanced.

    The naive ``text[:max_len-3] + "…"`` cut leaves an unclosed backtick
    when the cut falls between an opening and closing pair — e.g.
    ``Stored XSS via `bypassSecurityTrustHtml()` in `about.com`` … `` →
    truncated to ``Stored XSS via `bypassSecurityTrustHtml()` in `about.com``
    leaves three backticks (open, close, open). Downstream regex-based
    post-processors (``compose_threat_model._escape_dot_tld_identifiers``)
    then mis-parse the cell, mistaking later text as part of a new
    code-span and wrapping ``ts`` in extra backticks.

    This helper keeps the count of `` ` `` even after truncation:
    if the truncated slice has an odd number of backticks, drop back to
    the position immediately BEFORE the last opening backtick (so the
    code-span is excluded entirely). Then append the ellipsis.
    """
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    cut = max(1, max_len - 1)
    sliced = text[:cut].rstrip()
    # Backtick balance — odd count means an unclosed span.
    if sliced.count("`") % 2 == 1:
        last_tick = sliced.rfind("`")
        if last_tick > 0:
            sliced = sliced[:last_tick].rstrip(",; :—–-`")
    return sliced + "…"


def _truncate_label_line(text: str, max_chars: int) -> str:
    """Trim `text` to `max_chars` characters with an ellipsis when shortened."""
    if not isinstance(text, str):
        return ""
    text = text.strip()
    if len(text) <= max_chars:
        return text
    return text[: max(1, max_chars - 1)].rstrip() + "…"


def _actor_id_by_slug(actors: list[dict], slug: str) -> str | None:
    """Look up a §2.3 actor's mermaid node id by canonical slug.

    Mirrors the slug→id transform used in `_entry()` inside
    `_select_external_actors_for_diagram` so a future slug rename in
    posture-actor-labels.yaml flows through here automatically. Used by
    the §2.3 attack-edge builder, which historically selected actors by
    their `css_class` — that broke for `repo-read` once it was reclassed
    from `external` → `threat` for visual parity with the §1.4 heatmap.
    """
    node_id = slug.upper().replace("-", "_")
    return next((a["id"] for a in actors if a["id"] == node_id), None)


def _select_external_actors_for_diagram(actor_labels: dict, attack_paths_data: dict | None = None) -> list[dict]:
    """Pick up to 3 external actors (1 attacker + 1 victim + 1 supply-
    chain repo when present) for the §2.3 EXT subgraph. Slugs come from
    `posture-actor-labels.yaml`; the heatmap uses the same data so the
    two views stay consistent.

    Returns a list of dicts with keys: id (mermaid node id),
    label (`fa:fa-... Name`), css_class (`threat`/`legit`/`external`).
    """
    actors_dict = (actor_labels or {}).get("actors") or {}
    if not actors_dict:
        return []

    def _entry(slug: str, css: str) -> dict | None:
        meta = actors_dict.get(slug)
        if not isinstance(meta, dict):
            return None
        icon = meta.get("fa_icon") or "fa:fa-user"
        name = meta.get("label") or slug
        node = slug.upper().replace("-", "_")
        # Actor labels render plain — bold is reserved for diagram column
        # headers (e.g. HDR_A/T/I in the heatmap). Component / actor /
        # technology nodes are de-bolded so the visual hierarchy reads
        # "header > nodes" instead of "everything bold".
        return {"id": node, "label": f"{icon} {name}", "css_class": css}

    out: list[dict] = []
    # 1 — attacker. Prefer "internet-anon" for the main entry point.
    atk = _entry("internet-anon", "threat")
    if atk:
        out.append(atk)
    # 2 — victim/customer. Use "victim-required" if present in the labels
    # file (it is in the canonical set), else fall back to silently
    # omitting the legitimate actor — the diagram remains useful.
    vict = _entry("victim-required", "legit")
    if vict:
        out.append(vict)
    # 3 — supply-chain repo. The "repo-read" actor exists when the
    # threat register references repository-readable secrets. Per the
    # heatmap classification (`posture-actor-labels.yaml: severity_class:
    # actorAnon`), repo-read IS an attacker actor, not a neutral external
    # service. Use `:::threat` (red) for visual consistency with the
    # heatmap, not `:::external` (gray).
    repo = _entry("repo-read", "threat")
    if repo:
        out.append(repo)
    return out


def _components_diagram_compact(yaml_data: dict, by_tier: dict[str, list[dict]]) -> list[str]:
    """§2.3 Components — compact 4-tier `flowchart TD` per the contract.

    Layout: 4 subgraphs (EXT / CLIENT / APP / DATA), one main node per
    tier, sub-components aggregated as bullets in the main node's label.
    """
    rules = _load_diagram_compactness().get("2.3 Components") or {}
    layout = rules.get("layout_keyword", "flowchart TD")
    max_lines = int(rules.get("max_label_lines", 3))
    max_chars = int(rules.get("max_label_chars_per_line", 60))
    classdefs = rules.get("required_classdefs") or {}
    legit_arrow = (rules.get("edge_convention", {}).get("legit", {}) or {}).get("arrow", "-->")
    attack_arrow = (rules.get("edge_convention", {}).get("attack", {}) or {}).get("arrow", "-.->")
    legit_style = (rules.get("edge_convention", {}).get("legit", {}) or {}).get(
        "linkstyle", "stroke:#2e7d32,stroke-width:1.5px"
    )
    attack_style = (rules.get("edge_convention", {}).get("attack", {}) or {}).get(
        "linkstyle", "stroke:#b71c1c,stroke-width:2.5px,stroke-dasharray:6 4"
    )

    actor_labels = _load_posture_actor_labels_for_pregen()
    ext_actors = _select_external_actors_for_diagram(actor_labels)

    # Tier-icon defaults (shared with §2.4 in `_TIER_ICON`-equivalent).
    TIER_ICON = {
        "client": "fa:fa-window-restore",
        "application": "fa:fa-server",
        "data": "fa:fa-database",
    }
    TIER_TITLE = {
        "client": "Client Tier",
        "application": "Application Tier",
        "data": "Data Tier",
    }

    def _tier_main_node(tier_key: str) -> tuple[str, str, str] | None:
        """Return (mermaid_node_id, label, css_class) for the tier's main
        component. Sub-components are appended as `<br/>+ C-NN <name>`
        bullets in the label."""
        comps = by_tier.get(tier_key) or []
        if not comps:
            return None
        primary = comps[0]
        cid = (primary.get("id") or "").strip()
        cname = (primary.get("name") or cid or "?").strip()
        n_threats = len(primary.get("threat_ids") or [])
        node_id = _safe_node_id(cid)
        icon = TIER_ICON.get(tier_key, "fa:fa-cube")
        # Headline — strip embedded plain-text id when name already starts
        # with the id (avoids `C-01 C-01 Express Backend` redundancy).
        head_text = cname if cname.lower().startswith(cid.lower()) else f"{cid} {cname}"
        # Plain head — bold reserved for diagram column headers. See parallel
        # change in compose._build_tier_cards (components_line) and
        # security-posture-diagram.md.j2 (actor + tier labels).
        head = f"{icon} {head_text}"
        threats_line = f"<i>{n_threats} threats</i>" if n_threats else ""
        # Sub-component bullets — show ID only (not full name) so the
        # aggregated line fits within max_chars even with 3+ subs.
        bullets: list[str] = []
        for extra in comps[1:]:
            ecid = (extra.get("id") or "?").strip()
            bullets.append(f"+ {ecid}")
        # Compose label — head + (bullets joined) + threats_line. Cap to
        # max_lines lines AND every line ≤ max_chars (truncate per line).
        label_lines = [head]
        if bullets:
            joined = " ".join(bullets)
            label_lines.append(_truncate_label_line(joined, max_chars))
        if threats_line and len(label_lines) < max_lines:
            label_lines.append(threats_line)
        label_lines = [_truncate_label_line(ln, max_chars) for ln in label_lines[:max_lines]]
        label = "<br/>".join(label_lines)
        return (node_id, label, "risk")

    lines: list[str] = []
    lines.append("```mermaid")
    lines.append(layout)

    # ---- Subgraphs in the contract-declared order ----
    # 1) EXT — external actors projected from posture-actor-labels.yaml.
    if ext_actors:
        lines.append('    subgraph EXT["Untrusted Zone - Internet"]')
        for actor in ext_actors:
            lines.append(f'        {actor["id"]}["{actor["label"]}"]:::{actor["css_class"]}')
        lines.append("    end")

    # 2) CLIENT
    client_node = _tier_main_node("client")
    if client_node:
        nid, lbl, css = client_node
        lines.append(f'    subgraph CLIENT["{TIER_TITLE["client"]}"]')
        lines.append(f'        {nid}["{lbl}"]:::{css}')
        lines.append("    end")

    # 3) APP
    app_node = _tier_main_node("application")
    if app_node:
        nid, lbl, css = app_node
        lines.append(f'    subgraph APP["{TIER_TITLE["application"]}"]')
        lines.append(f'        {nid}["{lbl}"]:::{css}')
        lines.append("    end")

    # 4) DATA — cylinder shape per audit actor convention.
    data_node = _tier_main_node("data")
    if data_node:
        nid, lbl, css = data_node
        lines.append(f'    subgraph DATA["{TIER_TITLE["data"]}"]')
        lines.append(f'        {nid}[("{lbl}")]:::{css}')
        lines.append("    end")

    # ---- Edges ----
    legit_edges: list[str] = []
    attack_edges: list[str] = []
    # Legit data flow: victim → CLIENT → APP → DATA.
    victim = next((a["id"] for a in ext_actors if a["css_class"] == "legit"), None)
    if victim and client_node:
        legit_edges.append(f'    {victim} {legit_arrow}|"HTTPS · TLS"| {client_node[0]}')
    if client_node and app_node:
        legit_edges.append(f'    {client_node[0]} {legit_arrow}|"REST · JWT Bearer"| {app_node[0]}')
    if app_node and data_node:
        legit_edges.append(f'    {app_node[0]} {legit_arrow}|"ORM · queries"| {data_node[0]}')
    # Attack edges. Selectors use the actor slug (→ deterministic node id)
    # rather than css_class because css_class was intentionally changed for
    # repo-read (see `_select_external_actors_for_diagram` line 821 comment),
    # which broke the legacy `css_class == "external"` lookup and left
    # REPO_READ as an orphan node. Labels describe the typical baseline
    # attack class for the destination tier; per-project specificity comes
    # from the linked threats in the §2.3 component table below the diagram.
    attacker = _actor_id_by_slug(ext_actors, "internet-anon")
    repo = _actor_id_by_slug(ext_actors, "repo-read")
    if attacker and app_node:
        attack_edges.append(f'    {attacker} {attack_arrow}|"injection · auth bypass · RCE"| {app_node[0]}')
    if attacker and client_node:
        attack_edges.append(f'    {attacker} {attack_arrow}|"XSS · client tampering · token theft"| {client_node[0]}')
    if repo and app_node:
        attack_edges.append(f'    {repo} {attack_arrow}|"leaked credentials · auth bypass"| {app_node[0]}')

    for e in legit_edges:
        lines.append(e)
    for e in attack_edges:
        lines.append(e)

    # ---- classDef block (verbatim from contract) ----
    lines.append("")
    for css_name, css_value in classdefs.items():
        lines.append(f"    classDef {css_name} {css_value}")

    # ---- linkStyle block — first N legit, then M attack edges ----
    n_legit = len(legit_edges)
    n_attack = len(attack_edges)
    if n_legit:
        idx_legit = ",".join(str(i) for i in range(n_legit))
        lines.append(f"    linkStyle {idx_legit} {legit_style}")
    if n_attack:
        idx_attack = ",".join(str(n_legit + i) for i in range(n_attack))
        lines.append(f"    linkStyle {idx_attack} {attack_style}")

    lines.append("```")
    return lines


def _render_layer_tables(yaml_data: dict, components: list[dict]) -> list[str]:
    """Emit §2.4.1–§2.4.4 Layer Tables — the threat-traceability spine
    that the contract's `require_threat_traceability` rule consumes.

    Layout (per layer):

        #### 2.4.<N> Layer <N> – <Title>
        Brief intro line.
        | Component | Tier | Linked Threats | Risk |
        |---|---|---|---|

    Rows are sourced from `components[]` (one row per component, plus a
    fall-back "_No components in this layer_" row when the tier is
    empty). The Linked-Threats column carries every T-NNN whose
    `components[]` cell references this row's component id; the Risk
    column emits 🔴/🟠/🟡/🟢 based on max severity across linked threats.

    Phase-11 enrichment MAY add columns (Version, Defect, Notes) AFTER
    these but MUST NOT remove the Linked-Threats column.
    """
    threats = yaml_data.get("threats") or []
    threats_by_id: dict[str, dict] = {(t.get("id") or "").strip(): t for t in threats if isinstance(t, dict)}
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    sev_label = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}

    # Build threats_by_component from `components[].threat_ids[]` (canonical
    # direction). When that index is absent (Phase 11 didn't populate it), fall
    # back to the forward index `threats[].component` so Linked-Threats cells
    # never render `—` solely because of a missing reverse-link.
    threats_by_component: dict[str, list[dict]] = {}
    for c in yaml_data.get("components") or []:
        if not isinstance(c, dict):
            continue
        cid = (c.get("id") or "").strip()
        if not cid:
            continue
        for tid in c.get("threat_ids") or []:
            tid = (tid or "").strip()
            t = threats_by_id.get(tid)
            if t:
                threats_by_component.setdefault(cid, []).append(t)
    # Fallback: if the reverse index produced nothing, derive from forward field.
    if not any(threats_by_component.values()):
        for t in threats:
            if not isinstance(t, dict):
                continue
            cid = (t.get("component_id") or t.get("component") or "").strip()
            if cid:
                threats_by_component.setdefault(cid, []).append(t)

    by_tier_local = _components_by_tier(components)

    # Middleware-class CWEs: cross-cutting policy enforcement that runs
    # on every request (CORS / authn / rate-limit / logging / cookie).
    # Application-logic CWEs: per-route business logic + helpers.
    # The partition is best-effort — for monolithic apps where one
    # component carries both kinds of threats, Layer 2 shows the
    # middleware-class subset and Layer 3 the application-class subset.
    MIDDLEWARE_CWES = {
        "CWE-352",  # CSRF
        "CWE-285",
        "CWE-862",  # Authz / Missing authorization (route guards)
        "CWE-307",  # Improper restriction of excessive auth attempts
        "CWE-942",  # CORS misconfiguration
        "CWE-346",  # Origin validation error (CORS)
        "CWE-1004",  # Cookie without secure attribute
        "CWE-287",  # Improper Authentication
        "CWE-294",  # Auth bypass
        "CWE-303",  # Bad auth implementation
        "CWE-347",  # Improper signature verification (JWT alg:none)
        "CWE-778",  # Insufficient logging
        "CWE-532",  # Insertion of sensitive info into log file
    }

    def _partition_threats(tlist, predicate):
        return [t for t in tlist if predicate(t)]

    def _is_middleware_threat(t):
        cwe = (t.get("cwe") or "").strip().upper()
        if cwe in MIDDLEWARE_CWES:
            return True
        for c in t.get("cwes") or []:
            if (c or "").strip().upper() in MIDDLEWARE_CWES:
                return True
        return False

    LAYER_DEFS = [
        ("1", "Client", "client", None, "Browser-side runtime, storage mechanisms, and client-held secrets."),
        (
            "2",
            "Middleware",
            "application",
            "middleware",
            "Cross-cutting Express pipeline — policy enforcement that runs on every request (auth, CORS, rate-limit, logging, cookies).",
        ),
        (
            "3",
            "Application Logic",
            "application",
            "application",
            "Feature code that runs after the pipeline has accepted the request: route handlers, long-lived subsystems, security helpers.",
        ),
        ("4", "Data & Storage", "data", None, "Persistent and in-process data stores reachable from Layer 3."),
    ]

    # When the component count is small (≤5), a single consolidated table
    # is more readable than 4 sparse per-layer sub-sections. The layer-split
    # view only adds value when each layer has ≥2 rows.
    _total_comps = sum(len(by_tier_local.get(t, [])) for _, _, t, _, _ in LAYER_DEFS)
    _use_consolidated = _total_comps <= 5

    def _build_row(c: dict, tier: str, partition_key) -> tuple[str, str]:
        """Return (markdown_row, max_sev) for component c in the given tier/partition."""
        cid = (c.get("id") or "?").strip()
        cname = (c.get("name") or cid).strip()
        tlist_full = threats_by_component.get(cid) or []
        if partition_key == "middleware":
            tlist = _partition_threats(tlist_full, _is_middleware_threat)
        elif partition_key == "application":
            tlist = _partition_threats(tlist_full, lambda t: not _is_middleware_threat(t))
        else:
            tlist = tlist_full
        cells = []
        max_sev_rank = 0
        max_sev = ""
        for t in tlist:
            tid = _to_canonical_finding_label((t.get("id") or "").strip())
            title_short = _truncate_title_balanced((t.get("title") or "").strip(), max_len=60)
            if tid:
                if title_short:
                    cells.append(f"[{tid}](#{tid.lower()}) — {title_short}")
                else:
                    cells.append(f"[{tid}](#{tid.lower()})")
            sev = (t.get("severity") or t.get("risk") or "").strip().lower()
            if sev_rank.get(sev, 0) > max_sev_rank:
                max_sev_rank = sev_rank[sev]
                max_sev = sev
        tlist_cell = "<br/>".join(cells) if cells else "—"
        # Risk cell carries emoji + severity label (e.g. "🔴 Critical") for
        # consistency with §8 Threat Register and the Top Findings table.
        # An emoji-only cell forces the reader to map the colour to the
        # severity word every time.
        if cells:
            emoji = sev_emoji.get(max_sev, "🟢")
            label = sev_label.get(max_sev, "Low")
            risk_cell = f"{emoji} {label}"
        else:
            risk_cell = "—"
        return f"| {cid} {cname} | Layer {tier.capitalize()} | {tlist_cell} | {risk_cell} |", max_sev

    out: list[str] = []

    if _use_consolidated:
        out.append("| Component | Layer | Linked Threats | Risk |")
        out.append("|---|---|---|---|")
        # Track which (component_id, partition_key) pairs have already been
        # emitted. LAYER_DEFS has two application-tier entries (middleware and
        # application-logic). When a component has no middleware-class threats
        # its middleware row would be an empty duplicate of its app-logic row,
        # so we skip rows whose Linked Threats cell is "—" for the middleware
        # partition and emit just the combined app-logic row instead.
        seen_component_empty: set[str] = set()
        for n, _title, tier, partition_key, _intro in LAYER_DEFS:
            tier_comps = by_tier_local.get(tier) or []
            if not tier_comps:
                continue
            for c in tier_comps:
                row, _ = _build_row(c, tier, partition_key)
                cid = (c.get("id") or "").strip()
                # Skip the middleware-partition row when it carries no threats
                # (i.e. the cell is "—"). The app-logic row for the same
                # component will appear in the next LAYER_DEFS iteration.
                if partition_key == "middleware" and "| — |" in row:
                    seen_component_empty.add(cid)
                    continue
                out.append(row)
        out.append("")
    else:
        for n, title, tier, partition_key, intro in LAYER_DEFS:
            # Heading uses spaces (not " - ") as separator between "Layer N"
            # and the title so the GitHub-style slug matches the bare-text
            # "§2.4.N" auto-linker target in compose_threat_model.py. When
            # the slash-hyphen separator " - " was present the heading
            # produced a triple-hyphen slug (`241-layer-1---client`) that
            # did NOT match the single-hyphen slug emitted by the linker
            # (`241-layer-1-client`), breaking 4 of every 4 §2.4.x links.
            # See SKILL-impl.md → "§2.4 layer references" repair history.
            sanitized_title = title.replace(" & ", " ").replace("&", "")
            out.append(f"#### 2.4.{n} Layer {n} {sanitized_title}")
            out.append("")
            out.append(intro)
            out.append("")
            out.append("| Component | Tier | Linked Threats | Risk |")
            out.append("|---|---|---|---|")

            # Layer 2 "Middleware" doesn't have its own tier entry in
            # components (middleware is internal to the Application tier),
            # so we route a synthetic "Middleware Pipeline" row that
            # aggregates threats whose components include the application
            # tier's primary component AND whose vector is auth/session
            # related — a heuristic rather than a strict mapping.
            tier_comps = by_tier_local.get(tier) or []
            if not tier_comps:
                out.append(f"| _no components in this layer_ | {tier.capitalize()} | — | — |")
                out.append("")
                continue

            for c in tier_comps:
                row, _ = _build_row(c, tier, partition_key)
                out.append(row)
            out.append("")

    return out


# Tech-token registry — drives the §2.4 heuristic technology detection.
# Each entry maps a search-token (matched case-insensitive against the full
# yaml dump) to a (tier, mermaid-node-id, fa-icon, headline, descriptor)
# tuple. The first matching token per tier emits a node; duplicates within
# a tier are deduplicated by node-id. Order matters — higher-priority
# tokens come first so e.g. `node` matches before `express` (they are
# typically named together but Node.js is the runtime).
#
# Adding a token here is the standard extension path for new languages /
# frameworks. The contract does not pin a specific list — only the
# overall node count (`max_nodes_total`) and label-shape rules.
_TECH_TOKEN_REGISTRY: list[tuple[str, str, str, str, str, str]] = [
    # (tier, search_token, node_id, fa_icon, headline, descriptor)
    # CLIENT tier — UI frameworks
    ("client", "angular", "FE_ANGULAR", "fa:fa-window-restore", "Angular SPA", "browser runtime"),
    ("client", "react", "FE_REACT", "fa:fa-window-restore", "React", "browser runtime"),
    ("client", "vue", "FE_VUE", "fa:fa-window-restore", "Vue.js", "browser runtime"),
    ("client", "svelte", "FE_SVELTE", "fa:fa-window-restore", "Svelte", "browser runtime"),
    # APP tier — runtimes + middleware + frameworks
    ("app", "node.js", "RUNTIME", "fa:fa-server", "Node.js", "JS runtime"),
    ("app", "express", "EXPRESS", "fa:fa-server", "Express", "HTTP framework"),
    ("app", "express-jwt", "AUTH_MW", "fa:fa-shield-halved", "express-jwt · helmet · CORS", "auth middleware"),
    ("app", "passport", "AUTH_MW", "fa:fa-shield-halved", "Passport.js", "auth middleware"),
    ("app", "fastify", "FASTIFY", "fa:fa-server", "Fastify", "HTTP framework"),
    ("app", "django", "DJANGO", "fa:fa-server", "Django", "Python framework"),
    ("app", "flask", "FLASK", "fa:fa-server", "Flask", "Python framework"),
    ("app", "spring", "SPRING", "fa:fa-server", "Spring Boot", "Java framework"),
    ("app", "socket.io", "REALTIME", "fa:fa-plug", "Socket.IO", "WebSocket"),
    # DATA tier — relational + nosql + storage
    ("data", "sequelize", "ORM", "fa:fa-database", "Sequelize ORM", "object-relational mapper"),
    ("data", "sqlite", "SQLITE", "fa:fa-database", "SQLite", "embedded relational DB"),
    ("data", "postgres", "POSTGRES", "fa:fa-database", "PostgreSQL", "relational DB"),
    ("data", "mysql", "MYSQL", "fa:fa-database", "MySQL", "relational DB"),
    # MarsDB: niche library, mostly seen in deliberately-vulnerable training apps.
    ("data", "marsdb", "MARSDB", "fa:fa-database", "MarsDB", "in-memory NoSQL"),
    ("data", "mongodb", "MONGO", "fa:fa-database", "MongoDB", "document DB"),
    ("data", "mongo", "MONGO", "fa:fa-database", "MongoDB", "document DB"),
    ("data", "redis", "REDIS", "fa:fa-database", "Redis", "in-memory cache"),
    # INFRA cross-cutting — runtime container + supply chain + CI
    ("infra", "distroless", "INFRA_RUN", "fa:fa-cube", "Docker (distroless)", "container runtime"),
    ("infra", "docker", "INFRA_RUN", "fa:fa-cube", "Docker", "container runtime"),
    ("infra", "kubernetes", "INFRA_RUN", "fa:fa-cube", "Kubernetes", "container runtime"),
    ("infra", "github", "INFRA_SCM", "fa:fa-code-branch", "GitHub (public)", "source supply chain"),
    ("infra", "gitlab", "INFRA_SCM", "fa:fa-code-branch", "GitLab", "source supply chain"),
]


def _detect_tech_stack(yaml_data: dict, components: list[dict]) -> dict[str, list[dict]]:
    """Token-scan the yaml_data + components for known tech tokens, return
    a per-tier dict of node-specs the §2.4 builder consumes.

    Each value is a list of dicts: {node_id, fa_icon, headline, descriptor}.
    Deduplicated by node_id (so e.g. both `docker` and `distroless` end up
    on a single INFRA_RUN node, but the headline of the FIRST match wins —
    see registry ordering above).
    """
    # Build the search haystack from STRUCTURAL fields only. Free-form
    # prose (threat scenarios, mitigation steps, severity rationales)
    # routinely mentions unrelated tech families (e.g. "MongoDB-style
    # injection" in a NoSQL-injection T-NNN that actually targets
    # MarsDB) — those mentions are false positives for a deployment
    # signal. Limiting the haystack to the structural fields below
    # eliminates that noise.
    parts: list[str] = []
    # Meta — project metadata, tech_stack hints, project description.
    parts.append(yaml.safe_dump(yaml_data.get("meta") or {}, default_flow_style=False))
    # Components — name + engine + paths only (skip free-form
    # description / scenario fields that mix unrelated tech families).
    for c in yaml_data.get("components") or []:
        if not isinstance(c, dict):
            continue
        parts.append(str(c.get("name") or ""))
        parts.append(str(c.get("engine") or ""))
        parts.append(str(c.get("type") or ""))
        for p in c.get("paths") or []:
            parts.append(str(p))
    # Threats — `evidence.file` paths only (these point at real
    # deployment artifacts: package.json, Dockerfile, source files
    # that import a specific framework). Threat title / scenario /
    # description live in prose and are NOT scanned.
    for t in yaml_data.get("threats") or []:
        if not isinstance(t, dict):
            continue
        evidence = t.get("evidence") or {}
        if isinstance(evidence, dict):
            parts.append(str(evidence.get("file") or ""))
            for ref in evidence.get("file_references") or []:
                if isinstance(ref, dict):
                    parts.append(str(ref.get("file") or ""))
    # Security controls — implementation field (file paths and class
    # names anchored in real deployment artifacts).
    for c in yaml_data.get("security_controls") or []:
        if not isinstance(c, dict):
            continue
        parts.append(str(c.get("implementation") or ""))
    haystack = "\n".join(parts).lower()

    by_tier: dict[str, dict[str, dict]] = {"client": {}, "app": {}, "data": {}, "infra": {}}
    for tier, token, node_id, icon, headline, descriptor in _TECH_TOKEN_REGISTRY:
        # Word-boundary match — substring search like `"mongo" in "marsdb"`
        # is fine, but we want to avoid e.g. `"mongo"` matching `"mongoose"`-
        # style false positives that appear in mitigation suggestions for
        # unrelated stacks. The pattern allows any non-alphanumeric on
        # either side (so e.g. "Node.js", "express-jwt", "socket.io" still
        # match because dots / hyphens count as word boundaries).
        token_lc = token.lower()
        # Build a compact word-boundary regex. The token may itself contain
        # punctuation (".", "-", " "), which the regex treats literally.
        pat = re.compile(r"(?:^|[^a-z0-9])" + re.escape(token_lc) + r"(?:[^a-z0-9]|$)")
        if not pat.search(haystack):
            continue
        # First match per node_id wins — keeps registry ordering intent.
        if node_id in by_tier[tier]:
            continue
        by_tier[tier][node_id] = {
            "node_id": node_id,
            "fa_icon": icon,
            "headline": headline,
            "descriptor": descriptor,
        }
    return {tier: list(nodes.values()) for tier, nodes in by_tier.items()}


def _technology_architecture_compact_mermaid(yaml_data: dict, components: list[dict]) -> list[str]:
    """§2.4 Technology Architecture — compact 4-tier `flowchart TD` with
    heuristic tech-stack detection (post-2026-05-05).

    The diagram is built data-driven from the yaml: the registry above
    declares which tokens map to which mermaid nodes. Each tier shows
    the technologies that are actually referenced anywhere in the
    threat model (meta / components / threats / controls). A tier with
    zero matches falls back to a single generic node so the topology
    stays intact.

    Limits:
      * Layout: `flowchart TD` (forbids `graph LR` which overflows wide).
      * max_subgraphs: 4 (CLIENT / APP / DATA / INFRA).
      * max_nodes_total: 10.
      * max_label_lines: 2 (tech name + 1 descriptor).
    """
    rules = _load_diagram_compactness().get("2.4 Technology Architecture") or {}
    layout = rules.get("layout_keyword", "flowchart TD")
    max_lines = int(rules.get("max_label_lines", 2))
    max_chars = int(rules.get("max_label_chars_per_line", 60))
    max_nodes = int(rules.get("max_nodes_total", 10))
    classdefs = rules.get("required_classdefs") or {
        "risk": "fill:#fef2f2,stroke:#991b1b,color:#111,stroke-width:2.5px",
        "ok": "fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:1.5px",
    }
    legit_arrow = (rules.get("edge_convention", {}).get("legit", {}) or {}).get("arrow", "-->")
    supply_arrow = (rules.get("edge_convention", {}).get("supply_chain", {}) or {}).get("arrow", "-.->")
    legit_style = (rules.get("edge_convention", {}).get("legit", {}) or {}).get(
        "linkstyle", "stroke:#424242,stroke-width:1.5px"
    )
    supply_style = (rules.get("edge_convention", {}).get("supply_chain", {}) or {}).get(
        "linkstyle", "stroke:#9e9e9e,stroke-width:1px,stroke-dasharray:3 3"
    )

    def _label(icon: str, headline: str, descriptor: str = "") -> str:
        # Plain head — bold reserved for diagram column headers (HDR_A/T/I
        # in the heatmap). Tech-stack node labels render plain.
        head = f"{icon} {_truncate_label_line(headline, max_chars)}"
        if descriptor and max_lines >= 2:
            desc = f"<i>{_truncate_label_line(descriptor, max_chars)}</i>"
            return f"{head}<br/>{desc}"
        return head

    detected = _detect_tech_stack(yaml_data, components)

    # Local FS is always added (most server apps touch the filesystem).
    # Add it BEFORE the trim so the global node-count cap accounts for it.
    if not any(n["node_id"] == "LOCAL_FS" for n in detected["data"]):
        detected["data"].append(
            {
                "node_id": "LOCAL_FS",
                "fa_icon": "fa:fa-folder-open",
                "headline": "Local FS",
                "descriptor": "uploads · logs · keys",
            }
        )

    # Apply the global max_nodes ceiling. We prefer to keep at least one
    # node per non-empty tier so the topology still tells the layered
    # story. When the budget is tight, the data tier and infra tier
    # surrender extra nodes first (LOCAL_FS is preserved as the
    # filesystem-anchor; we trim DB engines before it because the
    # primary-engine information is preserved in the §2.4.4 Layer table).
    node_total = sum(len(detected[t]) for t in ("client", "app", "data", "infra"))
    if node_total > max_nodes:
        for tier in ("data", "infra"):
            while node_total > max_nodes and len(detected[tier]) > 1:
                # Drop the last non-LOCAL_FS node (data) or any extra
                # (infra). LOCAL_FS sits in detected["data"]; preserve it
                # by removing from the front when LOCAL_FS is at the end.
                if tier == "data":
                    # Pop the last DB-engine node (not LOCAL_FS).
                    for idx in range(len(detected[tier]) - 1, -1, -1):
                        if detected[tier][idx]["node_id"] != "LOCAL_FS":
                            detected[tier].pop(idx)
                            node_total -= 1
                            break
                    else:
                        break
                else:
                    detected[tier].pop()
                    node_total -= 1
        while node_total > max_nodes and len(detected["app"]) > 1:
            detected["app"].pop()
            node_total -= 1

    # ---- Build the mermaid ----
    lines: list[str] = []
    lines.append("```mermaid")
    lines.append(layout)

    def _emit_subgraph(
        sg_id: str, title: str, nodes: list[dict], cylinder_for_data: bool = False, css: str = "risk"
    ) -> None:
        if not nodes:
            return
        lines.append(f'    subgraph {sg_id}["{title}"]')
        for n in nodes:
            label = _label(n["fa_icon"], n["headline"], n["descriptor"])
            shape_open, shape_close = ("[", "]")
            if cylinder_for_data and "DB" in n["descriptor"].upper().split() + n["descriptor"].upper().split(" "):
                shape_open, shape_close = ('[("', '")]')
            elif cylinder_for_data:
                # Heuristic: any node in DATA tier whose headline is a
                # database engine renders as a cylinder.
                hl_low = n["headline"].lower()
                if any(kw in hl_low for kw in ("sqlite", "postgre", "mysql", "mongo", "marsdb", "redis", "dynamo")):
                    shape_open, shape_close = ('[("', '")]')
            if shape_open == "[":
                lines.append(f'        {n["node_id"]}["{label}"]:::{css}')
            else:
                lines.append(f"        {n['node_id']}{shape_open}{label}{shape_close}:::{css}")
        lines.append("    end")

    _emit_subgraph("CLIENT", "Client Tier", detected["client"], css="risk")

    # Application tier — fall back to a single generic ROUTES node when
    # nothing matched (keeps the diagram structurally complete).
    app_nodes = detected["app"]
    if not app_nodes:
        app_nodes = [
            {
                "node_id": "ROUTES",
                "fa_icon": "fa:fa-server",
                "headline": "Application Code",
                "descriptor": "request handlers",
            }
        ]
    _emit_subgraph("APP", "Application Tier", app_nodes, css="risk")

    # Data tier — already includes Local FS via the trim-aware injector
    # in `_detect_tech_stack` consumer above.
    data_nodes = list(detected["data"])
    _emit_subgraph("DATA", "Data Tier", data_nodes, cylinder_for_data=True, css="risk")

    # INFRA cross-cutting — only when the heuristic actually detected
    # container runtime or SCM. Empty INFRA stays out so we don't
    # render a placeholder subgraph.
    infra_nodes = detected["infra"]
    if infra_nodes:
        # INFRA_RUN goes to ok-class (defense-in-depth), SCM stays risk.
        # Annotate per-node so the renderer applies the right class.
        lines.append('    subgraph INFRA["Cross-Cutting"]')
        for n in infra_nodes:
            label = _label(n["fa_icon"], n["headline"], n["descriptor"])
            css = "ok" if n["node_id"] == "INFRA_RUN" else "risk"
            lines.append(f'        {n["node_id"]}["{label}"]:::{css}')
        lines.append("    end")

    # ---- Edges ----
    legit_edges: list[str] = []
    supply_edges: list[str] = []

    # Client → APP entry point. When AUTH_MW is present, the client
    # request hits the auth middleware first (logically — the JWT-auth
    # gate runs before route handlers). Otherwise client → routes
    # directly. This avoids the "AUTH_MW receives requests from somewhere
    # invisible" anti-pattern where the auth-middleware appears as a
    # source-only node with no inbound traffic.
    first_client = detected["client"][0]["node_id"] if detected["client"] else None
    first_app = app_nodes[0]["node_id"]
    has_auth_mw = any(n["node_id"] == "AUTH_MW" for n in app_nodes)
    has_routes = any(n["node_id"] in ("EXPRESS", "ROUTES") for n in app_nodes)
    routes_target = next(
        (n["node_id"] for n in app_nodes if n["node_id"] in ("EXPRESS", "ROUTES")),
        first_app,
    )
    if first_client:
        if has_auth_mw:
            # Browser → middleware → routes is the actual request path.
            legit_edges.append(f'    {first_client} {legit_arrow}|"HTTPS · JWT"| AUTH_MW')
            legit_edges.append(f'    AUTH_MW {legit_arrow}|"middleware chain"| {routes_target}')
        else:
            legit_edges.append(f'    {first_client} {legit_arrow}|"HTTPS · JWT"| {first_app}')
    elif has_auth_mw and has_routes:
        # No client tier — still chain middleware → routes for clarity.
        legit_edges.append(f'    AUTH_MW {legit_arrow}|"middleware chain"| {routes_target}')

    # APP → DATA: emit one edge per DB engine present (not just the
    # first one). Without this, secondary stores (MarsDB alongside
    # SQLite, Redis alongside Postgres) appear as stranded nodes.
    db_nodes = [
        n for n in data_nodes if n["node_id"] in ("ORM", "SQLITE", "POSTGRES", "MYSQL", "MARSDB", "MONGO", "REDIS")
    ]
    for db in db_nodes:
        legit_edges.append(f'    {routes_target} {legit_arrow}|"DB driver"| {db["node_id"]}')
    # APP → Local FS (always present).
    legit_edges.append(f'    {routes_target} {legit_arrow}|"file I/O"| LOCAL_FS')

    # INFRA edges — supply chain. The "runs" edge points at the routes
    # target (the actual application code) rather than the first APP
    # node, which may be the auth middleware in a multi-node tier.
    if infra_nodes:
        scm = next((n["node_id"] for n in infra_nodes if n["node_id"] == "INFRA_SCM"), None)
        run = next((n["node_id"] for n in infra_nodes if n["node_id"] == "INFRA_RUN"), None)
        if scm and run:
            supply_edges.append(f'    {scm} {supply_arrow}|"build"| {run}')
        if run:
            supply_edges.append(f'    {run} {supply_arrow}|"runs"| {routes_target}')
        elif scm:
            supply_edges.append(f'    {scm} {supply_arrow}|"clone · extract secrets"| {routes_target}')

    for e in legit_edges:
        lines.append(e)
    for e in supply_edges:
        lines.append(e)

    # classDef block
    lines.append("")
    for css_name, css_value in classdefs.items():
        lines.append(f"    classDef {css_name} {css_value}")

    # linkStyle block
    n_legit = len(legit_edges)
    n_supply = len(supply_edges)
    if n_legit:
        idx_l = ",".join(str(i) for i in range(n_legit))
        lines.append(f"    linkStyle {idx_l} {legit_style}")
    if n_supply:
        idx_s = ",".join(str(n_legit + i) for i in range(n_supply))
        lines.append(f"    linkStyle {idx_s} {supply_style}")

    lines.append("```")
    return lines


def _technology_architecture_mermaid(yaml_data: dict, components: list[dict], boundaries: list[dict]) -> list[str]:
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

    Post-2026-05: when the contract declares
    `diagram_compactness."2.4 Technology Architecture"`, route to the
    contract-driven compact builder instead. The boundary-driven layout
    below is preserved for legacy yamls / contracts that have not opted in.

    Falls back to the old TB1/TB2/TB3 stub when boundaries are absent
    so the diagram remains useful for legacy yamls.
    """
    # Contract-driven compact path (post-2026-05). Default ON when the
    # `diagram_compactness."2.4 Technology Architecture"` block exists.
    if _load_diagram_compactness().get("2.4 Technology Architecture"):
        return _technology_architecture_compact_mermaid(yaml_data, components)

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
            "client": ("untrusted",),
            "application": ("trusted",),
            "data": ("restricted",),
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
            "client": (
                "internet",
                "public internet",
                "external user",
                "browser",
                "angular spa",
                "react spa",
                "vue spa",
                "frontend",
            ),
            # "spa to rest"/"api" disambiguates from generic "application" text.
            "application": (
                "spa to",
                "spa → rest",
                "rest api",
                "express api",
                "app server",
                "process boundary",
                "service mesh",
            ),
            # "data tier"/"data layer"/"db"/"sqlite" are unambiguous.
            "data": ("data tier", "data layer", "database", "sqlite", "marsdb", "persistence", "storage tier"),
        }
        hints = _name_hints.get(tier, ())
        for b in boundaries:
            if not isinstance(b, dict):
                continue
            haystack = " ".join(
                [
                    (b.get("id") or "").lower(),
                    (b.get("name") or "").lower(),
                    (b.get("description") or "").lower(),
                ]
            )
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
            best_bid = boundaries[1].get("id") if len(boundaries) > 1 else boundaries[0].get("id")
        component_to_boundary[cid] = best_bid

    out: list[str] = ["```mermaid", "flowchart TB"]

    # M3.3 / D1.5 (L) — pre-compute threat counts for highlight pass below.
    crit_counts, high_counts = _threat_counts_per_component(yaml_data)

    # M3.3 / D1.5 (G) — engine annotation when not already in component name.
    def _component_label(c: dict) -> str:
        nm = (c.get("name") or c.get("id") or "?").replace('"', "'")
        engine = (c.get("engine") or "").strip()
        if engine and engine.lower() not in nm.lower():
            return f"{nm}<br/>{engine}"
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
        crosses_untrusted = src_level == "untrusted" or dst_level == "untrusted"

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
        out.append("    classDef critical fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:3px")
        out.append("    classDef warning  fill:#fef3c7,stroke:#b45309,color:#78350f,stroke-width:2px")
        for n in crit_nodes:
            out.append(f"    class {n} critical")
        for n in warn_nodes:
            out.append(f"    class {n} warning")

    out.append("```")
    return out


def _load_fs_route_prefixes() -> tuple[str, ...]:
    """Load filesystem-route-exposure path prefixes from
    ``data/filesystem-route-prefixes.yaml``. Returns an empty tuple when
    the file is missing, so ghost-node rendering degrades silently."""
    path = Path(__file__).resolve().parent.parent / "data" / "filesystem-route-prefixes.yaml"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        return ()
    prefixes = data.get("prefixes") or []
    return tuple(p for p in prefixes if isinstance(p, str) and p.startswith("/"))


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
        haystack = " ".join(
            [
                (b.get("id") or "").lower(),
                (b.get("name") or "").lower(),
            ]
        )
        if any(k in haystack for k in ("filesystem", "file system", "storage", "disk", "fs")):
            fs_boundary_ids.append(b.get("id"))
    if not fs_boundary_ids:
        return {}

    # Filesystem-exposing route prefixes are loaded from
    # data/filesystem-route-prefixes.yaml so the list can be tuned without
    # code changes. A path that doesn't match any prefix is treated as a
    # regular HTTP route, not a filesystem ghost-node.
    fs_prefixes = _load_fs_route_prefixes()

    surface = yaml_data.get("attack_surface") or {}
    unauth = (surface.get("unauthenticated") if isinstance(surface, dict) else None) or []
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
        if len(parts) == 2 and parts[0].upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
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
        # WAF presence is an environment / deployment concern that cannot be
        # determined from a source-tree scan. Don't claim "WAF (none observed)"
        # for every repo that isn't shipping a WAF config — most aren't, and
        # the absence is not a defect at the application-source layer.
        return "TLS"
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
        "trusted": "Network ACL / runtime",
        "restricted": "Restricted access",
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
    return any(
        k in p
        for k in (
            "websocket",
            "socket.io",
            "ws ",
            "amqp",
            "kafka",
            "rabbit",
            "sqs",
            "sns",
            "pubsub",
            "queue",
            "event",
            "stream",
            "mqtt",
            "nats",
            "redis pub",
        )
    )


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
        edges.append(f"{_safe_node_id(src)} {arrow}{annotated}| {_safe_node_id(dst)}")
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
        "Confidentiality / Integrity / Availability targets used in [§8 Threat Register](#8-threat-register) risk scoring."
    )
    lines.append("")
    if not assets:
        lines.append("_No assets enumerated in threat-model.yaml._")
        lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    # Check whether any asset has linked_threats to decide if the column is needed
    any_linked = any(a.get("linked_threats") for a in assets)
    if any_linked:
        lines.append("| Asset | ID | Classification | Description | Linked Threats |")
        lines.append("|---|---|---|---|---|")
    else:
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
        if any_linked:
            lt = [_to_canonical_finding_label(t) for t in (a.get("linked_threats") or [])]
            lt_cell = "<br/>".join(f"[{t}](#{t.lower()})" for t in lt) if lt else "—"
            lines.append(f"| {name} | {aid} | {clazz} | {desc} | {lt_cell} |")
        else:
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
    raw = (entry.get("endpoint") or entry.get("path") or entry.get("route") or entry.get("entry_point") or "?").strip()
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


def _to_canonical_finding_label(ref: str) -> str:
    """Convert T-NNN → F-NNN for visible labels (anchor stays same form).

    The renderer's dual-anchor emission and post-render F-bridge make both
    ``#t-NNN`` and ``#f-NNN`` valid link targets, but the qa-reviewer
    contract names F-NNN as the canonical visible form. Auto-derived
    threat refs (which come from yaml ``threats[].id`` = ``T-NNN``) need
    this normalisation so §5 / §4 cells render consistently with the
    Verdict / Architecture-Assessment cells.
    """
    if not isinstance(ref, str):
        return ref
    m = re.match(r"^T-(\d+)$", ref.strip())
    if m:
        return f"F-{m.group(1)}"
    return ref


def _attack_surface_notes(entry: dict) -> str:
    """Render the Notes column.

    P4 update: when both ``notes`` and ``linked_threats`` are populated, emit
    BOTH — linked_threats first (clickable, downstream-linkified to
    ``[F-NNN](#f-nnn) — Title``), notes after on a separate line as
    supplementary context. Pre-P4 the function preferred ``notes`` and
    silently dropped the linked-threats column whenever notes was non-empty,
    which left §5 cells as plain text without finding back-references.

    When ``linked_threats`` is empty (the common case in current production
    yamls — the STRIDE merger doesn't yet populate the field), the caller's
    auto-derive heuristic in ``_derive_attack_surface_links`` populates it
    before this function runs. The fallback chain stays intact for legacy
    inputs.

    Visible IDs are normalised to F-NNN via ``_to_canonical_finding_label``.
    """
    if not isinstance(entry, dict):
        return ""
    notes = (entry.get("notes") or "").replace("\n", " ").strip()
    threats = entry.get("threats") or entry.get("linked_threats") or []
    threats = [_to_canonical_finding_label(t) for t in threats if isinstance(t, str)]

    # Strip redundant `(T-NNN)` / `(F-NNN)` parentheticals from notes when the
    # same threat is already represented in linked_threats — the linkified
    # head line above already cites it; a plain-text parenthetical produces
    # duplicate refs (`[F-013](#f-013) — Title<br/>Raw SQL … (T-013)`). The
    # author-prompt guidance forbids ID tokens in `notes` (see
    # phase-group-architecture.md §"Phase 6 yaml schema") but legacy yamls and
    # LLM drift still leak them through. This is the deterministic rendering
    # safeguard.
    if notes and threats:
        threat_digits = {re.sub(r"^[TF]-", "", t).zfill(3) for t in threats}
        notes = (
            re.sub(
                r"\s*[—–-]?\s*\(\s*[TF]-(\d+)\s*\)",
                lambda m: "" if m.group(1).zfill(3) in threat_digits else m.group(0),
                notes,
            )
            .rstrip(" ,;:—–-")
            .strip()
        )

    if threats and notes:
        linkified = "<br/>".join(f"[{t}](#{t.lower()})" for t in threats)
        return f"{linkified}<br/>{notes}"
    if notes:
        return notes
    if threats:
        return "<br/>".join(f"[{t}](#{t.lower()})" for t in threats)
    return ""


# ---------------------------------------------------------------------------
# P4 — Auto-derive linked_threats for attack-surface entries (heuristic)
# ---------------------------------------------------------------------------

_PATH_PARAM_RE = re.compile(r"/?:[a-zA-Z][a-zA-Z0-9_]*")
_PATH_TOKEN_SPLIT = re.compile(r"[/_\-:]")
_NORMALIZE_NON_ALNUM = re.compile(r"[^a-z0-9]")
_FILE_EXT_STRIP = re.compile(r"\.(?:ts|js|jsx|tsx|py|rb|go|java|cs|kt|swift)$", re.IGNORECASE)


def _strip_path_params(path: str) -> str:
    """``/ftp/:file`` → ``/ftp``; ``/api/Users/:id`` → ``/api/Users``."""
    return _PATH_PARAM_RE.sub("", path or "").rstrip("/") or "/"


def _normalize_token(s: str) -> str:
    """Lowercase + strip everything but [a-z0-9]. Useful for camelCase /
    hyphenated comparisons like ``fileUpload`` vs ``file-upload``."""
    return _NORMALIZE_NON_ALNUM.sub("", (s or "").lower())


def _score_threat_path_match(threat: dict, raw_path: str) -> int:
    """Heuristic score: how strongly does ``threat`` mention the endpoint
    path ``raw_path``? Higher = better match. ≥ 3 is treated as a hit by
    ``_derive_attack_surface_links``.

    Signals (cumulative):

      * +5 — the cleaned path (``:param`` placeholders stripped) appears
        verbatim in the threat's scenario / title / description.
      * +1 per — each path token (length ≥ 4, excluding stop-words like
        ``rest`` / ``api``) appears anywhere in the threat's text.
      * +3 — any of the threat's evidence-file basenames (without
        extension, normalised) is a substring of the normalised path,
        or vice versa. Catches e.g. ``routes/fileUpload.ts`` matching
        ``/file-upload`` (both normalise to ``fileupload``).
    """
    if not isinstance(threat, dict) or not raw_path:
        return 0
    full_text = " ".join(
        [
            threat.get("scenario") or "",
            threat.get("title") or "",
            threat.get("description") or "",
        ]
    ).lower()
    path_clean = _strip_path_params(raw_path).lower()

    score = 0
    if len(path_clean) >= 3 and path_clean in full_text:
        score += 5

    path_tokens = [
        tok
        for tok in _PATH_TOKEN_SPLIT.split(raw_path.lower())
        if len(tok) >= 4 and tok not in {"rest", "api", "http", "https"}
    ]
    for tok in path_tokens:
        if tok in full_text:
            score += 1

    # Evidence-file basename match.
    # B1/B2/B3 fix — restrict the +3 evidence bonus to files that LIVE in
    # a route-handler-style directory (routes/, controllers/, handlers/,
    # api/, endpoints/). Models, schemas, and general source files like
    # `models/user.ts` were previously matching every path that contained
    # the model name as a segment (e.g. `models/user.ts` -> +3 on every
    # `/rest/user/...` route), attaching the Role Mass Assignment finding
    # (F-011) to /rest/user/login, /rest/user/data-export, /api/Users.
    # The route-handler directory gate eliminates that whole class of
    # false positive without losing the legitimate matches (the SQL-on-
    # login finding's evidence is `routes/login.ts`, the SSRF finding's
    # is `routes/profileImageUrlUpload.ts`, etc.).
    _ROUTE_DIRS = ("routes/", "controllers/", "handlers/", "api/", "endpoints/", "rest/")
    if len(path_clean) >= 3:
        path_tokens_norm = {
            _normalize_token(tok)
            for tok in _PATH_TOKEN_SPLIT.split(path_clean.lower())
            if len(tok) >= 3
        }
        for ev in threat.get("evidence") or []:
            if not isinstance(ev, dict):
                continue
            ev_file = (ev.get("file") or "").lstrip("/").lower()
            # Require the evidence file to live in a route-handler-style
            # directory. Without this gate, generic model files match
            # any path containing the model name.
            if not any(seg in ev_file for seg in _ROUTE_DIRS):
                continue
            base = (ev.get("file") or "").split("/")[-1]
            base_no_ext = _FILE_EXT_STRIP.sub("", base)
            base_norm = _normalize_token(base_no_ext)
            if len(base_norm) < 4:
                continue
            if base_norm in path_tokens_norm:
                # Exact whole-token match (e.g. evidence basename
                # "fileUpload" -> normalised "fileupload" -> matches
                # the "file-upload" token in /file-upload, or
                # "login" -> "login" in /rest/user/login).
                score += 3
                break
            # Substring match in either direction for longer basenames
            # like profileImageUrlUpload <-> /profile/image/url.
            matched = False
            for tok in path_tokens_norm:
                if len(tok) >= 5 and (tok in base_norm or base_norm in tok):
                    score += 3
                    matched = True
                    break
            if matched:
                break
    return score


def _derive_attack_surface_links(entry: dict, threats: list, max_links: int = 3) -> list[str]:
    """Return a list of T-NNN/F-NNN ids that plausibly relate to the given
    attack-surface entry. Capped at ``max_links`` so the rendered cell
    stays readable. Empty list when the score threshold isn't met.

    The yaml's ``attack_surface[].linked_threats`` field is intentionally
    populated by the STRIDE merger when it has direct evidence (route file
    matches threat evidence). When that signal is absent — as in current
    production yamls — this heuristic provides a best-effort fallback so
    the §5 Attack Surface table stops rendering as bare plain-text notes.

    Threshold: score ≥ 3. A pure path-token hit (+1) without any other
    signal is too weak; we want either a verbatim path mention (+5),
    multiple token hits (+1 ×N), or an evidence-file basename match (+3).
    """
    if not isinstance(entry, dict) or not threats:
        return []
    raw_path = entry.get("entry_point") or entry.get("path") or entry.get("route") or ""
    # Strip leading "METHOD " from common entry_point format.
    m = re.match(r"^[A-Z]+\s+(\S+)", raw_path)
    if m:
        raw_path = m.group(1)
    if not raw_path:
        return []

    scored: list[tuple[str, int]] = []
    for t in threats:
        if not isinstance(t, dict):
            continue
        tid = (t.get("t_id") or t.get("id") or "").strip()
        if not tid:
            continue
        sc = _score_threat_path_match(t, raw_path)
        if sc >= 3:
            scored.append((tid, sc))
    scored.sort(key=lambda x: (-x[1], x[0]))
    return [tid for tid, _ in scored[:max_links]]


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
        unauth = [e for e in flat if not (e.get("requires_auth") or e.get("auth_required") or e.get("authenticated"))]
        auth = [e for e in flat if (e.get("requires_auth") or e.get("auth_required") or e.get("authenticated"))]
    else:
        unauth, auth = [], []

    # P4 — auto-derive linked_threats when the yaml entry has none. The
    # STRIDE merger does not currently populate this field so the §5
    # Notes column rendered as bare plain text without finding back-
    # references. The path-vs-threat heuristic in
    # ``_derive_attack_surface_links`` recovers ~70 % of the linkage
    # without any upstream changes.
    threats_list = yaml_data.get("threats") or []
    for entry in unauth + auth:
        if not isinstance(entry, dict):
            continue
        existing = entry.get("linked_threats") or entry.get("threats") or []
        existing = [t for t in existing if isinstance(t, str)]
        if existing:
            continue  # respect explicit upstream linkage
        derived = _derive_attack_surface_links(entry, threats_list)
        if derived:
            entry["linked_threats"] = derived

    # F2.1 — Build threat-severity index so we can derive a Risk column
    # per entry. Severity hierarchy follows the standard 4-tier mapping;
    # the highest severity across an entry's linked_threats wins.
    _sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0, "Unknown": 0}
    _sev_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
    threat_by_id = {
        (t.get("t_id") or t.get("id") or "").upper(): t
        for t in (yaml_data.get("threats") or [])
        if isinstance(t, dict)
    }

    def _entry_risk(entry: dict) -> str:
        """Highest severity across the entry's linked threats. `—` when none."""
        linked = entry.get("linked_threats") or entry.get("threats") or []
        worst_name = ""
        worst_rank = -1
        for ref in linked:
            if not isinstance(ref, str):
                continue
            t = threat_by_id.get(ref.strip().upper()) or {}
            sev = (t.get("risk") or t.get("severity") or t.get("impact") or "").strip().title()
            rank = _sev_rank.get(sev, -1)
            if rank > worst_rank:
                worst_rank = rank
                worst_name = sev
        if not worst_name:
            return "—"
        emoji = _sev_emoji.get(worst_name, "")
        return f"{emoji} {worst_name}".strip()

    def _entry_auth(entry: dict, default: str) -> str:
        """Authentication-required label (entries already partitioned)."""
        # Honour an explicit `auth_mechanism` field when present, else the
        # partition default (`Yes` for §5.2 buckets, `No` for §5.1).
        mech = (entry.get("auth_mechanism") or entry.get("auth") or "").strip()
        if mech:
            return mech
        return default

    lines = ["## 5. Attack Surface", ""]
    lines.append(
        "Network-reachable entry points classified by authentication requirement. "
        "Each row links to the threat(s) referenced in its **Notes** column. The "
        "**Risk** column reflects the highest-severity linked finding."
    )
    lines.append("")

    def _emit_table(bucket_entries: list, auth_default: str) -> None:
        # Five columns (Method | Route | Auth | Risk | Notes). Backward-
        # compatible with the prior 3-col layout — readers/tools that
        # parsed the old table by column index will see Notes shift but
        # the column headings remain explicit.
        lines.append("| Method | Route | Auth | Risk | Notes |")
        lines.append("|---|---|---|---|---|")
        for entry in bucket_entries:
            method = _attack_surface_method(entry)
            route = _attack_surface_route(entry)
            auth_lbl = _entry_auth(entry, auth_default)
            risk_lbl = _entry_risk(entry)
            notes = _attack_surface_notes(entry)
            lines.append(f"| {method} | `{route}` | {auth_lbl} | {risk_lbl} | {notes} |")

    lines.append(f"### 5.1 Unauthenticated Entry Points ({len(unauth)})")
    lines.append("")
    if unauth:
        _emit_table(unauth, "No")
    else:
        lines.append("_None enumerated._")
    lines.append("")

    lines.append(f"### 5.2 Authenticated Entry Points ({len(auth)})")
    lines.append("")
    if auth:
        _emit_table(auth, "Yes")
    else:
        lines.append("_None enumerated._")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# §6 Use Cases generator removed 2026-05. The numbering gap (§5 → §7) is
# intentional. Restoration would also need to revert the corresponding
# block in data/sections-contract.yaml and the dispatcher entry in
# scripts/compose_threat_model.py (FRAGMENT_PATHS / sections registry).
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Generator: security-architecture.md
# ---------------------------------------------------------------------------

# 14 sub-sections defined in sections-contract.yaml § security_architecture.
# Sub-titles are deterministic; bodies are derived from security_controls[].
_SECARCH_SUBSECTIONS = (
    ("7.1", "Overview"),
    ("7.2", "Key Architectural Risks"),
    ("7.3", "Identity & Access Management"),
    ("7.4", "Authorization"),
    ("7.5", "Input Validation & Output Encoding"),
    ("7.6", "Data Protection & Session Management"),
    ("7.7", "Frontend Security"),
    ("7.8", "Real-time / WebSocket"),
    ("7.9", "AI / LLM"),
    ("7.10", "Audit & Logging"),
    ("7.11", "Container & Runtime Security"),
    ("7.12", "Dependency & Supply Chain"),
    ("7.13", "Secret Management (cross-cutting)"),
    ("7.14", "Defense-in-Depth Assessment (cross-cutting)"),
)

# Map sub-section title → control.domain substring matchers.
_SUBSECTION_DOMAIN_HINTS = {
    "7.3": ("identity", "iam", "authentication", "auth "),
    "7.4": ("authorization", "access control", "rbac", "abac"),
    "7.5": ("input validation", "output encoding", "sanitization", "injection"),
    "7.6": ("data protection", "session", "encryption", "crypto"),
    "7.7": ("frontend", "csp", "xss", "csrf"),
    "7.8": ("websocket", "real-time", "socket.io"),
    "7.9": ("ai / llm", "artificial intelligence", "llm", "prompt injection", "ml model"),
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
    "7.3": {
        "CWE-287",
        "CWE-308",
        "CWE-307",
        "CWE-294",
        "CWE-345",
        "CWE-384",
        "CWE-347",
        "CWE-916",
    },  # CWE-347 sig-verify, CWE-916 weak password hash
    "7.4": {
        "CWE-285",
        "CWE-639",
        "CWE-862",
        "CWE-863",
        "CWE-732",
        "CWE-269",
        "CWE-915",
    },  # CWE-915 mass assignment / over-permissive PATCH
    "7.5": {
        "CWE-79",
        "CWE-80",
        "CWE-89",
        "CWE-94",
        "CWE-95",
        "CWE-611",
        "CWE-77",
        "CWE-78",
        "CWE-90",
        "CWE-918",
        "CWE-22",
        "CWE-1336",
    },
    "7.6": {
        "CWE-311",
        "CWE-312",
        "CWE-319",
        "CWE-326",
        "CWE-327",
        "CWE-328",
        "CWE-916",
        "CWE-759",
        "CWE-614",
        "CWE-922",
    },
    "7.7": {"CWE-79", "CWE-352", "CWE-1021", "CWE-942", "CWE-693"},
    "7.8": {"CWE-346", "CWE-1357"},  # Origin validation, Socket.IO-style auth
    "7.9": {"CWE-1039", "CWE-1426"},  # Inadequate ML detection / prompt injection
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
    "7.8": ("websocket", "socket.io", "real-time", "real time"),
    "7.9": ("llm ", " llm", "prompt injection", "ai model", "machine learning"),
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
            "    actor Client as Browser / SPA",
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
            out.append(
                "    Note over API,Crypto: ⚠ alg:none accepted — attacker forges token without key (T-009 / CWE-287)"
            )
        if has_credential_theft:
            out.append(
                "    Note over Crypto: ⚠ Private key hardcoded in source — anyone reading the repo can forge any user's JWT (T-008 / CWE-321)"
            )
        if has_session_hijack:
            out.append("    Note over Client: ⚠ Token in localStorage → XSS exfiltration possible (T-003 / CWE-922)")
        out.append("```")
        return out

    if "oauth" in haystack or "oidc" in haystack or "openid" in haystack:
        return [
            "```mermaid",
            "sequenceDiagram",
            "    autonumber",
            "    actor Client",
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
            "    actor Client as Browser",
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
            "    actor Client",
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
        "    actor Client",
        "    participant Service",
        "    participant Store as Identity Store",
        "    Client->>Service: credentials / token",
        "    Service->>Store: verify identity",
        "    Store-->>Service: user record",
        "    Service-->>Client: session / JWT",
        "```",
    ]


def _control_notes(c: dict, yaml_data: Optional[dict] = None) -> str:
    """Best-effort Notes-cell content from a security_controls[] entry.

    Falls back through `notes` → `effectiveness_reason` → first item of
    `gaps[]` so the column shows substance even when the orchestrator
    used the leaner Phase 8 schema (just `effectiveness_reason` and no
    explicit `notes`).

    M-5: When `yaml_data` is provided AND every threat linked to this
    control has `source ∈ {dep-scan, configuration-defect}`, append a
    pointer "See [MF-NNN] for the cross-cutting process gap." so the
    reader understands the Effectiveness rating reflects implementation
    defects, not an architectural weakness.
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
    note = (raw or "").replace("\n", " ").strip()

    if isinstance(yaml_data, dict):
        suffix = _meta_finding_pointer_for_control(c, yaml_data)
        if suffix:
            sep = " " if note and not note.endswith(("…", ".", "?", "!")) else " "
            note = (note + sep + suffix).strip() if note else suffix
    return note


_IMPL_ONLY_SOURCES = frozenset({"dep-scan", "configuration-defect"})


def _meta_finding_pointer_for_control(c: dict, yaml_data: dict) -> str:
    """M-5: Compose a "See [MF-NNN]" pointer when ALL linked threats of a
    control are implementation-only (`dep-scan` / `configuration-defect`).

    Returns an empty string when no meta-finding applies — never overrides
    the LLM's `effectiveness` rating; the pointer is annotation only.
    """
    linked: list[str] = []
    raw = c.get("linked_threats") or []
    if isinstance(raw, list):
        linked = [t for t in raw if isinstance(t, str) and t.startswith("T-")]
    if not linked:
        return ""

    threats_by_id: dict[str, dict] = {}
    for t in yaml_data.get("threats") or []:
        if isinstance(t, dict):
            tid = (t.get("id") or "").strip()
            if tid:
                threats_by_id[tid] = t

    if not all(
        threats_by_id.get(tid, {}).get("source") in _IMPL_ONLY_SOURCES
        for tid in linked
    ):
        return ""

    # Find the matching meta-finding (one whose derived_from intersects
    # the control's linked threats).
    meta_findings = yaml_data.get("meta_findings") or []
    if not isinstance(meta_findings, list):
        return ""
    linked_set = set(linked)
    for mf in meta_findings:
        if not isinstance(mf, dict):
            continue
        derived = mf.get("derived_from") or []
        if not isinstance(derived, list):
            continue
        if linked_set & set(derived):
            mfid = (mf.get("id") or "").strip()
            if mfid:
                return (
                    f"_See [{mfid}](#{mfid.lower()}) — "
                    f"{mf.get('title', 'cross-cutting process gap')}._"
                )
    return ""


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
            haystack = " ".join(
                [
                    (t.get("title") or "").lower(),
                    (t.get("scenario") or "").lower(),
                    (t.get("description") or "").lower(),
                ]
            )
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
            out.append(
                {
                    "id": f"C-{c.upper().replace('_', '-')}",
                    "domain": c,
                    "name": c.replace("_", " ").title(),
                    "control": "_(domain enumerated; per-control detail not catalogued)_",
                    "effectiveness": "",
                    "implementation": "_(not catalogued)_",
                    "notes": "",
                    "mitigates_findings": [],
                    "_synthesized_from_string": True,
                }
            )
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


def _section_id_for_control_domain(domain: str) -> Optional[str]:
    """Reverse-lookup: control.domain string → §7.x section id.

    Returns the FIRST section id whose `_SUBSECTION_DOMAIN_HINTS` substring
    matches the control's domain. Returns None when no hint matches —
    typically for cross-cutting domains (Rate Limiting, Defense-in-Depth)
    that the LLM authored without a clear §7.x slot.
    """
    if not domain:
        return None
    needle = domain.lower()
    for section_id, hints in _SUBSECTION_DOMAIN_HINTS.items():
        if any(h in needle for h in hints):
            return section_id
    return None


def _format_linked_threats_for_control(
    control: dict, all_threats: list, max_links: int = 3
) -> str:
    """M-7: Render the `Linked Threats` cell for a §7.2 control row.

    Priority:
      1. `security_controls[].linked_threats` populated by Stage 1 → use as-is.
      2. Derive from `control.domain → _SUBSECTION_DOMAIN_HINTS → section_id`
         and `_threats_for_subsection(threats, section_id)`. Mark the cell
         with a trailing `(derived)` italic note so reviewers can spot it.

    Cell links to the §8 Threat Register anchors (`[T-NNN](#t-nnn)`).
    Returns `—` when nothing can be derived.
    """
    # Priority 1 — explicit population.
    explicit = control.get("linked_threats") or []
    if isinstance(explicit, list) and explicit:
        ids = [t for t in explicit if isinstance(t, str) and t.strip()]
        if ids:
            rendered = ", ".join(
                f"[{tid}](#{tid.lower()})" for tid in ids[:max_links]
            )
            if len(ids) > max_links:
                rendered += f" (+{len(ids) - max_links})"
            return rendered

    # Priority 2 — derivation via domain → section_id → threats-by-CWE.
    domain = (control.get("domain") or "").strip()
    section_id = _section_id_for_control_domain(domain)
    if not section_id or not isinstance(all_threats, list):
        return "—"
    derived = _threats_for_subsection(all_threats, section_id)
    if not derived:
        return "—"
    ids = [
        (t.get("id") or "").strip()
        for t in derived
        if isinstance(t, dict) and (t.get("id") or "").strip()
    ]
    ids = ids[:max_links]
    if not ids:
        return "—"
    rendered = ", ".join(f"[{tid}](#{tid.lower()})" for tid in ids)
    return f"{rendered} _(derived)_"


# ---------------------------------------------------------------------------
# kind discriminator (mechanism | primitive | cross-cutting)
#
# §7.3 IAM in the rendered threat model emits one `#### 7.3.N <name> Flow`
# sub-block per IAM control. Without a kind discriminator that produces a
# Flow block for primitives ("Password Hashing Flow", "Rate Limiting Flow")
# and for token formats ("JWT RS256 Signing Flow") in place of the actual
# authentication mechanism — the regression observed on the 2026-04-27
# juice-shop run.
#
# Resolution order for a given security_controls[] row:
#   1. row's own `kind` field (explicit Phase 8 emission, post-M-X).
#   2. canonical lookup by name/alias against architectural-controls.yaml
#      `controls[].kind`.
#   3. heuristic on the control name — names containing mechanism keywords
#      (login, oauth, mtls, webhook, role, …) default to `mechanism`;
#      everything else defaults to `primitive`.
# ---------------------------------------------------------------------------


def _load_architectural_controls() -> dict:
    """Return the parsed architectural-controls.yaml. Cached after first read.
    Falls back to an empty dict so callers stay safe when the file is
    missing or malformed."""
    global _ARCH_CONTROLS_CACHE
    if _ARCH_CONTROLS_CACHE is not None:
        return _ARCH_CONTROLS_CACHE
    try:
        _ARCH_CONTROLS_CACHE = yaml.safe_load(_ARCH_CONTROLS_PATH.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        _ARCH_CONTROLS_CACHE = {}
    return _ARCH_CONTROLS_CACHE


def _normalize_token(s: str) -> str:
    return "".join(ch.lower() for ch in (s or "") if ch.isalnum())


_ARCH_KIND_INDEX_CACHE: dict[str, str] | None = None


def _arch_kind_index() -> dict[str, str]:
    """Return {normalised_name_or_alias → kind} for fast lookups."""
    global _ARCH_KIND_INDEX_CACHE
    if _ARCH_KIND_INDEX_CACHE is not None:
        return _ARCH_KIND_INDEX_CACHE
    idx: dict[str, str] = {}
    for entry in _load_architectural_controls().get("controls") or []:
        if not isinstance(entry, dict):
            continue
        kind = (entry.get("kind") or "").strip().lower()
        if kind not in ("mechanism", "primitive", "cross-cutting"):
            continue
        for key in [entry.get("name")] + list(entry.get("aliases") or []):
            tok = _normalize_token(key)
            if tok:
                idx[tok] = kind
    _ARCH_KIND_INDEX_CACHE = idx
    return idx


# Heuristic fallback when both the row and the canonical vocabulary are
# silent. Mechanism keywords: end-to-end ways identity is established.
_KIND_MECHANISM_KEYWORDS: tuple[str, ...] = (
    "login",
    "sign in",
    "signin",
    "sign-in",
    "authentication flow",
    "oauth",
    "oidc",
    "openid",
    "saml",
    "sso",
    "passkey",
    "webauthn",
    "magic link",
    "magic-link",
    "passwordless",
    "password reset",
    "forgot password",
    "mtls",
    "mutual tls",
    "client certificate",
    "client cert",
    "webhook hmac",
    "webhook signature",
    "signed webhook",
    "api key",
    "bearer token",
    "static token",
    "iam role",
    "assume role",
    "service account",
    "managed identity",
    "workload identity",
    "irsa",
    "spiffe",
    "spire",
    "anonymous access",
    "no authentication",
    "session cookie",
    "cookie authentication",
    "two-factor",
    "second-factor",
    "multi-factor",
    "2fa",
    "totp",
    "mfa",
)
_KIND_PRIMITIVE_KEYWORDS: tuple[str, ...] = (
    "hashing",
    "hash",
    "signature verification",
    "signature check",
    "rate limit",
    "rate-limit",
    "throttling",
    "lockout",
    "cookie flag",
    "session revocation",
    "token blocklist",
    "token storage",
    "token validation",
    "jwt validation",
    "jwt verification",
)


def _control_kind(c: dict) -> str:
    """Return 'mechanism' | 'primitive' | 'cross-cutting' for a control row."""
    raw = (c.get("kind") or "").strip().lower()
    if raw in ("mechanism", "primitive", "cross-cutting"):
        return raw
    name = c.get("architectural_control") or c.get("control") or c.get("name") or ""
    canonical = _arch_kind_index().get(_normalize_token(name))
    if canonical:
        return canonical
    n = name.lower()
    for kw in _KIND_PRIMITIVE_KEYWORDS:
        if kw in n:
            return "primitive"
    for kw in _KIND_MECHANISM_KEYWORDS:
        if kw in n:
            return "mechanism"
    # Conservative default: treat as primitive so it stays in the controls
    # table and does NOT spawn a §7.3.N Flow sub-block. Better to under-emit
    # Flow blocks than to drown §7.3 in implementation-detail headings.
    return "primitive"


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
                cut = i + 1  # include the punctuation, drop the trailing space
        return scen[:cut][:80].rstrip()
    return ""


def _threat_evidence_files(t: dict, max_files: int = 2) -> list[str]:
    """Return up to `max_files` ``file:line`` strings from a threat's evidence."""
    if not isinstance(t, dict):
        return []
    out: list[str] = []
    for ev in t.get("evidence") or []:
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
        bucket = by_domain.setdefault(
            key,
            {
                "domain": domain or "Uncategorised",
                "controls": [],
                "tids": [],  # preserves first-seen order for deterministic output
                "score": 0,
            },
        )
        bucket["controls"].append(c)
        for tid in c.get("linked_threats") or []:
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
    candidates.sort(key=lambda b: (-b["score"], -len(b["tids"]), -len(b["controls"]), b["domain"].lower()))

    gaps: list[dict] = []
    for bucket in candidates[:k]:
        # Primary control = the one whose linked_threats sum to the highest
        # severity score within the bucket. Falls back to first listed.
        def _ctrl_score(c: dict) -> int:
            return sum(
                _SEVERITY_WEIGHT.get((t_idx.get(str(tid).strip().upper(), {}).get("risk") or "").lower(), 0)
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
            sev = (t_idx.get(tid, {}).get("risk") or t_idx.get(tid, {}).get("severity") or "").lower()
            return -_SEVERITY_WEIGHT.get(sev, 0)

        sorted_tids = sorted(bucket["tids"], key=_tid_rank)
        thr_pairs = [(tid, _threat_label(t_idx.get(tid, {}))) for tid in sorted_tids]

        gaps.append(
            {
                "title": title,
                "evidence": evidence,
                "threats": thr_pairs,
                "score": bucket["score"],
            }
        )
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
                cells.append(f"[{tid}](#{anchor}) — {lbl}" if lbl else f"[{tid}](#{anchor})")
            threats_cell = "<br/>".join(cells)
        else:
            threats_cell = "_(no cross-linked threats)_"
        lines.append(f"| {g['title']} | {g['evidence']} | {threats_cell} |")
    return lines


def gen_security_architecture(yaml_data: dict, depth: str = "standard") -> str:
    """## 7. Security Architecture — structural scaffold for the Phase-11 agent.

    This function generates a SCAFFOLD, not a finished document. The Phase-11
    agent fills the narrative content (domain assessments, flow introductions,
    findings-in-flow lists) using the instructions in
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
    - The deprecated Gap-Summary block is not emitted. Its information lives in
      the structured §7.1 Overview bullets and the §7.2 Key Architectural Risks
      table, so §7 has no third duplicated summary location.

    Depth-aware behaviour (P2 — A5):
    - ``depth="quick"`` strips NARRATIVE_PLACEHOLDER comments from §7.4-§7.12
      so the LLM has no expansion-bait there. The required headings still emit
      (contract gate passes), but their bodies stay terse — just the
      machine-derived controls/threats table when matched, or a one-line
      "no findings" note when not. §7.1, §7.2, §7.3 (IAM with per-auth-method
      flow blocks), §7.13, §7.14 keep their placeholders since those are the
      five high-value sections at every depth.
    - ``depth="standard"`` and ``depth="thorough"`` emit the full placeholder
      set as before — the LLM's narrative expansion adds genuine signal there.
    """
    quick_depth = (depth or "").strip().lower() == "quick"
    controls = _normalize_security_controls(yaml_data.get("security_controls"))
    components = yaml_data.get("components") or []
    threats = yaml_data.get("threats") or []

    # Pre-compute effectiveness counts for catalog totals line.
    eff_counts: dict[str, int] = {}
    for c in controls:
        eff = (c.get("effectiveness") or "unknown").lower()
        eff_counts[eff] = eff_counts.get(eff, 0) + 1
    n_adequate = eff_counts.get("adequate", 0)
    n_partial = eff_counts.get("partial", 0)
    n_weak = eff_counts.get("weak", 0)
    n_missing = eff_counts.get("missing", 0)

    lines = ["## 7. Security Architecture", ""]
    lines.append(
        f"**Catalog totals:** ✅ {n_adequate} Adequate · ⚠️ {n_partial} Partial · "
        f"🔶 {n_weak} Weak · ❌ {n_missing} Missing · {len(controls)} controls tracked."
    )
    lines.append("")
    # Gap Summary block intentionally removed (post-2026-05): the prose
    # paragraph form drifted toward repeating top-finding lists, and the
    # tabular form duplicated §7.2 "Key Architectural Risks". The
    # information now lives EXCLUSIVELY in the structured §7.1 Overview
    # bullets below + the §7.2 risk table — no third location.

    # -------------------------------------------------------------------------
    # 7.1 Overview — STRUCTURED BULLETS (no prose paragraphs).
    # The previous version emitted three free-prose paragraphs that the LLM
    # then expanded further during ENRICH_ARCH_FRAGMENTS. The result was a
    # 4-paragraph wall of text without scannable structure. The bullet-based
    # scaffold below is the canonical form: domain inventory + top themes +
    # defense-in-depth posture, each as a bulleted list. The Phase-11 agent
    # MAY expand individual bullets but MUST NOT replace the bullet
    # structure with running prose.
    # -------------------------------------------------------------------------
    lines.append("### 7.1 Overview")
    lines.append("")
    lines.append(
        f"Across {len(components)} component(s) the assessment catalogued {len(controls)} security control(s)."
    )
    lines.append("")
    if controls:
        # Domain inventory — group adequate vs. weak-or-missing so the
        # reader sees at a glance which control domains have meaningful
        # coverage and which are gaps.
        adequate_ctrls = [c for c in controls if (c.get("effectiveness") or "").lower() in ("adequate",)]
        partial_ctrls = [c for c in controls if (c.get("effectiveness") or "").lower() in ("partial",)]
        weak_ctrls = [c for c in controls if (c.get("effectiveness") or "").lower() in ("weak", "missing")]

        lines.append("**Control coverage:**")
        lines.append("")
        if adequate_ctrls:
            domains = sorted({c.get("domain", "?") for c in adequate_ctrls})
            lines.append(f"- ✅ **Adequate ({len(adequate_ctrls)}):** {', '.join(domains)}")
        if partial_ctrls:
            domains = sorted({c.get("domain", "?") for c in partial_ctrls})
            lines.append(f"- ⚠️ **Partial ({len(partial_ctrls)}):** {', '.join(domains)}")
        if weak_ctrls:
            domains = sorted({c.get("domain", "?") for c in weak_ctrls})
            lines.append(f"- 🔶❌ **Weak or Missing ({len(weak_ctrls)}):** {', '.join(domains)}")
        lines.append("")

    # NARRATIVE_PLACEHOLDER for the Phase-11 agent: structured top-themes
    # bullets + defense-in-depth bullet, NOT free prose. The agent prompt in
    # phase-group-finalization.md (§ "Authoring `security-architecture.md`")
    # requires the bullets stay bulleted.
    lines.append(
        "<!-- NARRATIVE_PLACEHOLDER: section=7.1 — top architectural risk themes (3 bullets) and defense-in-depth posture (1 bullet). Each bullet ≤2 sentences. NO prose paragraphs. -->"
    )
    lines.append("")

    # -------------------------------------------------------------------------
    # 7.2 Key Architectural Risks — scaffold table from weak/missing controls
    # The agent should expand this with a prose intro per finalization.md §591.
    # -------------------------------------------------------------------------
    lines.append("### 7.2 Key Architectural Risks")
    lines.append("")
    # F1.1 — At quick depth (LLM enrichment off) we emit a deterministic
    # 1-sentence intro derived from the weak/missing-control inventory.
    # At standard/thorough we keep the NARRATIVE_PLACEHOLDER so the LLM
    # writes the richer prose intro.
    weak_controls = [c for c in controls if (c.get("effectiveness") or "").lower() in ("weak", "missing")]
    if quick_depth:
        weak_domains = sorted({c.get("domain", "?") for c in weak_controls if c.get("domain")})
        if weak_domains:
            domain_phrase = ", ".join(weak_domains[:4])
            if len(weak_domains) > 4:
                domain_phrase += f", +{len(weak_domains) - 4} more"
            lines.append(
                f"The following {len(weak_controls)} control(s) across "
                f"{domain_phrase} are rated **Weak** or **Missing** and "
                f"drive the highest-leverage structural risks. Each row is "
                f"sourced from §7.3-§7.14 below."
            )
        else:
            lines.append(
                "No Weak or Missing controls were cataloged — see §7.3-§7.14 "
                "for the per-domain control-effectiveness ratings."
            )
    else:
        lines.append("<!-- NARRATIVE_PLACEHOLDER: domain=KeyRisks — add 1-2 sentence intro before table. -->")
    lines.append("")
    if weak_controls:
        # M-7 (refined): 5-col table with Linked Threats column. When the
        # YAML carries explicit `security_controls[].linked_threats`, use it
        # verbatim. Otherwise derive from the control's domain → §7.x section
        # mapping + per-section CWE hints. Derived links are marked with a
        # trailing italic `(derived)` so reviewers can spot them.
        threats_all = yaml_data.get("threats") or []
        lines.append("| Domain | Control | Effectiveness | Linked Threats | Notes |")
        lines.append("|---|---|---|---|---|")
        for c in weak_controls[:8]:
            domain = c.get("domain", "_?_")
            ctrl = c.get("control", "_?_")
            eff = c.get("effectiveness", "_?_")
            notes = _control_notes(c)
            linked_cell = _format_linked_threats_for_control(c, threats_all)
            lines.append(f"| {domain} | {ctrl} | {eff} | {linked_cell} | {notes} |")
    else:
        lines.append("_No weak/missing controls cataloged._")
    lines.append("")

    # ---------------------------------------------------------------------
    # 7.2 — Threat Hypotheses Requiring Validation (arch.md §Renderer-Rules)
    # Deterministic block. Only renders when threat_hypotheses[] is populated;
    # unconfirmed hypotheses (no promoted_threat_id) are listed here so
    # Section 8 Threat Register is NOT polluted with unproven entries.
    # Promoted hypotheses (proof_state=confirmed, with promoted_threat_id)
    # live in Section 8 as the corresponding T-NNN and are NOT re-listed here.
    # ---------------------------------------------------------------------
    hypotheses = yaml_data.get("threat_hypotheses") or []
    unpromoted = [h for h in hypotheses if isinstance(h, dict) and not h.get("promoted_threat_id")]
    if unpromoted:
        lines.append("#### Threat Hypotheses Requiring Validation")
        lines.append("")
        lines.append(
            "_Architecture- and control-derived bedrohungen. "
            "Plausible aber noch nicht source-to-sink belegt. Sie sind keine "
            "Findings; jeder Eintrag braucht eine `validate-or-refute` Pentest-Probe._"
        )
        lines.append("")
        lines.append("| ID | Hypothesis | Control Gap | Evidence | Validation |")
        lines.append("|---|---|---|---|---|")
        for h in unpromoted[:20]:
            hid = h.get("id") or "_?_"
            title = (h.get("title") or "_?_").replace("|", "\\|")
            gaps = h.get("weak_or_missing_controls") or []
            if not gaps and isinstance(h.get("linked_control_ids"), list):
                gaps = [str(c) for c in h.get("linked_control_ids") or []]
            gap_text = ", ".join(str(g).replace("|", "\\|") for g in gaps[:3]) or "_?_"
            evidence_entries = h.get("evidence") or []
            if evidence_entries:
                first = evidence_entries[0]
                if isinstance(first, dict):
                    f = str(first.get("file") or "?").replace("|", "\\|")
                    ln = first.get("line")
                    evidence_text = f"`{f}:{ln}`" if ln else f"`{f}`"
                    if len(evidence_entries) > 1:
                        evidence_text += f" +{len(evidence_entries) - 1}"
                else:
                    evidence_text = "_?_"
            else:
                evidence_text = "_?_"
            validation = (h.get("validation_objective") or "_pending validation objective_").replace("|", "\\|")
            if len(validation) > 160:
                validation = validation[:157].rstrip() + "…"
            lines.append(f"| {hid} | {title} | {gap_text} | {evidence_text} | {validation} |")
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
        # P2 (A5) — At quick depth, §7.4-§7.12 NARRATIVE_PLACEHOLDERs are stripped
        # so the LLM has no expansion bait there. The required heading still
        # emits (contract gate passes) and the controls/threats table below
        # carries the machine-derived signal. Standard/thorough keep the
        # placeholder so the LLM's narrative expansion adds real value.
        # §7.3 (IAM, with per-auth-method flow blocks) is excluded from the
        # strip — its narrative is high-value at every depth.
        if not (quick_depth and section_id != "7.3"):
            # Agent replaces this with the structured three-block domain
            # narrative (post-2026-05). The labels are anchors the QA
            # reviewer greps for — write them verbatim.
            lines.append(
                f"<!-- NARRATIVE_PLACEHOLDER: domain={section_id} — replace with the "
                f"three-block narrative. Block 1: '**What this control does.**' "
                f"(1-2 vendor-neutral, concept-level sentences, no file:line, no "
                f"CWE/T-NNN refs). Block 2: '**How it is implemented here.**' "
                f"(1-3 sentences naming libraries, layers, IaC resources, manifest "
                f"keys, and at least one verifiable artifact). Block 3: "
                f"'**Where it falls short.**' (1-3 sentences interpreting the gap "
                f"with linked T-NNN refs). When the domain is genuinely Not "
                f"Applicable, replace all three blocks with a single italic line: "
                f"`_Not applicable — <one-line reason citing recon evidence>._` "
                f"See phase-group-finalization.md 'Worked-example library — domain "
                f"narratives' (Examples D and E) for full templates. -->"
            )
            lines.append("")

        if matched:
            # §7.3 IAM additionally requires a `Linked Threats` column per the
            # `auth_method_decomposition` contract rule (data/sections-contract.yaml
            # → security_architecture.domain_required_rules → 7.3 IAM →
            # required_body_elements). Other §7.X domains keep the legacy
            # 4-column format so existing fragments don't drift.
            include_linked_col = section_id == "7.3"
            if include_linked_col:
                lines.append("| Control | Implementation | Effectiveness | Linked Threats | Notes |")
                lines.append("|---|---|---|---|---|")
            else:
                lines.append("| Control | Implementation | Effectiveness | Notes |")
                lines.append("|---|---|---|---|")
            for c in matched:
                ctrl = c.get("control", "_?_")
                impl = c.get("implementation", "_?_")
                eff = c.get("effectiveness", "_?_")
                notes = _control_notes(c, yaml_data)
                if include_linked_col:
                    raw_links = c.get("linked_threats") or []
                    if isinstance(raw_links, str):
                        raw_links = [raw_links]
                    linked_cell = ", ".join(t for t in raw_links if isinstance(t, str)) or "—"
                    lines.append(f"| {ctrl} | {impl} | {eff} | {linked_cell} | {notes} |")
                else:
                    lines.append(f"| {ctrl} | {impl} | {eff} | {notes} |")
        else:
            if domain_threats:
                lines.append("_No dedicated control cataloged for this domain — the findings below indicate the gap._")
                lines.append("")
                lines.append("| Finding | Severity | CWE |")
                lines.append("|---------|----------|-----|")
                for t in domain_threats[:6]:
                    tid = _to_canonical_finding_label(t.get("id", "?"))
                    sev = (t.get("risk") or t.get("severity") or "—").capitalize()
                    cwes = t.get("cwe") or t.get("cwes") or []
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

        # §7.3 IAM: per-auth-mechanism #### sub-blocks (contract requirement).
        # The agent fills (a) flow intro, (b) sequenceDiagram content,
        # (c) risk assessment narrative, and (d) findings-in-flow links.
        # The stubs here satisfy the pre-render gate while giving the agent
        # concrete anchors to work from.
        #
        # Filter `matched` (all IAM controls) to only `kind: mechanism` rows.
        # Primitives (Password Hashing, Rate Limiting, JWT Signature
        # Verification) and cross-cutting controls (Secret Management) appear
        # ONLY in the controls table above — they MUST NOT spawn their own
        # Flow sub-block. This is what stops the regression where
        # "Password Hashing Flow" / "JWT RS256 Signing Flow" replaced the
        # real authentication mechanism (Password Login, OAuth, mTLS, …).
        if section_id == "7.3":
            mechanisms = [c for c in matched if _control_kind(c) == "mechanism"]
            if mechanisms:
                iam_blocks = mechanisms
            elif matched:
                # Legacy YAML — Phase 8 emitted only primitives (e.g. only
                # `JWT Authentication`, `Password Hashing`, `Rate Limiting`).
                # We refuse to fabricate per-primitive Flow blocks; instead
                # we emit a single stub that signals the gap to the agent.
                iam_blocks = [
                    {
                        "control": "Authentication Flow",
                        "implementation": (
                            "_Phase 8 emitted only primitive controls "
                            "(see table above); no `kind: mechanism` row was "
                            "catalogued. Agent: enumerate the actual auth "
                            "mechanisms used by this app (Password Login, OAuth, "
                            "mTLS, Webhook HMAC, IAM Role, etc.) and replace this "
                            "block with one `#### 7.3.N <name> Flow` per mechanism._"
                        ),
                    }
                ]
            else:
                iam_blocks = [{"control": "Authentication Flow", "implementation": "_(not catalogued)_"}]
            for idx, c in enumerate(iam_blocks, start=1):
                ctrl = (c.get("control") or "Authentication Flow").strip()
                impl = (c.get("implementation") or "_n/a_").strip()
                heading = ctrl if ctrl.endswith(" Flow") else f"{ctrl} Flow"
                lines.append(f"#### 7.3.{idx} {heading}")
                lines.append("")
                # Agent replaces this with the flow-level three-block narrative.
                # Block 1 (concept) MUST come BEFORE the file:line refs in
                # block 2 — a reader must understand WHAT the mechanism is
                # before they can evaluate HOW it is implemented.
                lines.append(
                    f"<!-- NARRATIVE_PLACEHOLDER: flow=7.3.{idx} — replace with two "
                    f"labelled blocks. Block 1: '**What this flow does.**' (1-2 "
                    f"vendor-neutral sentences naming the mechanism — Password Login, "
                    f"OAuth, mTLS, AWS IAM Role, Webhook HMAC, etc. — no file refs). "
                    f"Block 2: '**How it is implemented here.**' (1-3 sentences: "
                    f"endpoint path(s), implementation file:line, libraries / SDKs / "
                    f"mesh resources, token or session TTL, rate-limiting status). "
                    f"Do NOT modify the Mermaid sequenceDiagram or the controls "
                    f"table that follow. See phase-group-finalization.md 'Worked-"
                    f"example library — three architectures' (Examples A/B/C). -->"
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
                    "jwt": ("jwt", "alg", "token", "bearer", "signing", "rs256", "hs256"),
                    "oauth": ("oauth", "oidc", "openid", "social", "google", "facebook"),
                    "password": ("password", "md5", "hash", "bcrypt", "credential", "login", "brute", "sql inject"),
                    "2fa": ("2fa", "totp", "otp", "mfa", "multi-factor"),
                    "rbac": ("role", "rbac", "authoriz", "privilege", "admin", "permission"),
                    "session": ("session", "cookie", "logout", "fixation"),
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
                    lines.append(
                        "<!-- FINDINGS_PLACEHOLDER: replace the list below with only the "
                        "findings that apply to THIS specific auth flow, not all IAM threats. -->"
                    )
                    for t in relevant_threats[:5]:
                        tid = _to_canonical_finding_label(t.get("id", "?"))
                        title = (t.get("title") or "").replace("|", "\\|")
                        lines.append(f"- [{tid}](#{tid.lower()}) — {title}")
                else:
                    lines.append("**Findings in this flow:** — none")
                lines.append("")

    # -------------------------------------------------------------------------
    # 7.13 Secret Management (cross-cutting — always emitted)
    # -------------------------------------------------------------------------
    lines.append("### 7.13 Secret Management (cross-cutting)")
    lines.append("")
    lines.append(
        "<!-- NARRATIVE_PLACEHOLDER: domain=SecretMgmt — replace with 2-3 sentence "
        "assessment of how secrets (keys, credentials, tokens) are managed: "
        "env vars vs. hardcoded, rotation capability, leakage paths. Every "
        "F-NNN / T-NNN / M-NNN reference MUST be written as `[ID](#id) — "
        "Short Title` (full title from the threat register). Bare IDs are "
        "auto-linkified by qa_checks but a missing title yields a tombstone "
        "link, so write the title inline. Do NOT mention the absence of a "
        "secret-scanning service, vault product, or KMS — those are "
        "deployment-environment concerns and a source-tree scan has no "
        "signal on them. Only mention such tooling when the repo actually "
        "configures or references it (e.g. a CI step running trufflehog, "
        "a terraform vault block). -->"
    )
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
            "_No dedicated secret-management control cataloged. See [§8 Threat Register](#8-threat-register) for "
            "hardcoded-secret findings (CWE-321 / CWE-798)._"
        )
    lines.append("")

    # -------------------------------------------------------------------------
    # 7.14 Defense-in-Depth Assessment (cross-cutting — always emitted)
    # -------------------------------------------------------------------------
    lines.append("### 7.14 Defense-in-Depth Assessment (cross-cutting)")
    lines.append("")
    lines.append(
        "<!-- NARRATIVE_PLACEHOLDER: domain=DefenseInDepth — replace with a layered "
        "evaluation of the defensive layers that ARE evidenced in the repository "
        "(rate-limiting middleware, CSP headers, logging, input-validation libs, "
        "etc.) and the gaps among them. **Do NOT mention the absence of** "
        "deployment-time / runtime-environment controls — WAF, API gateway, "
        "reverse proxy, IDS/IPS, network firewall, secret-scanning service, "
        "database activity monitoring (DAM), EDR/SIEM. A source-tree scan has "
        "no signal on whether these layers exist in the deployment environment, "
        "so claims about their absence are unfounded. Mention such tooling "
        "**only in the positive** when the repo actually configures or "
        "references one (terraform AWS WAF block, nginx modsecurity ruleset, "
        "CI step with trufflehog, etc.). Every F-NNN / T-NNN / M-NNN reference "
        "MUST be written as `[ID](#id) — Short Title`. -->"
    )
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
    """## 10. Out of Scope — pulls from meta.scope.out_of_scope or default,
    plus team-provided accepted risks from meta.accepted_risks (sourced from
    docs/known-threats.yaml entries with status: accepted)."""
    meta = yaml_data.get("meta") or {}
    out_of_scope = (meta.get("scope") or {}).get("out_of_scope") or [
        "Third-party hosted dependencies and SaaS endpoints",
        "Browser runtime vulnerabilities and end-user device security",
        "Operating system kernel and container runtime",
        "Underlying network infrastructure (DNS, BGP, ISP)",
        "Physical security of hosting facilities",
    ]
    accepted_risks = meta.get("accepted_risks") or []

    lines = ["## 10. Out of Scope", ""]
    lines.append(
        "The following items are **explicitly excluded** from this threat model. "
        "Findings against these areas should be tracked separately."
    )
    lines.append("")
    for item in out_of_scope:
        lines.append(f"- {item}")
    lines.append("")

    if accepted_risks:
        lines.append("### Accepted Risks (Team-Provided)")
        lines.append("")
        lines.append(
            "Risks below were declared as `status: accepted` in "
            "`docs/known-threats.yaml`. They are documented here for traceability "
            "and are intentionally not raised as new findings during STRIDE "
            "analysis. Each entry preserves the team's justification verbatim."
        )
        lines.append("")
        lines.append("| ID | Title | Severity | Component | STRIDE | Justification |")
        lines.append("|----|-------|----------|-----------|--------|---------------|")
        for r in accepted_risks:
            if not isinstance(r, dict):
                continue
            rid = str(r.get("id") or "—").strip()
            title = str(r.get("title") or "—").strip()
            severity = str(r.get("severity") or "—").strip()
            component = str(r.get("component") or "—").strip()
            stride = str(r.get("stride") or "—").strip()
            just_raw = str(r.get("justification") or "—").strip()
            # Collapse multi-line justification to a single line; pipes in the
            # text would break the markdown table column count.
            just = " ".join(just_raw.split()).replace("|", "\\|")
            lines.append(f"| {rid} | {title} | {severity} | {component} | {stride} | {just} |")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Attack-walkthroughs chain-overview helper (Fix-F).
#
# Emits a deterministic `_chain-skeleton.md` reference fragment with the
# §3.1 Attack Chain Overview block fully formed: canonical `### 3.1 Attack
# Chain Overview` heading, ≤3 `#### Chain N — <title>` blocks, each carrying
# the required classDef pair and at least one T-NNN reference whose node
# label derives directly from `threats[].title`. The renderer agent reads
# this file as input and copies §3.1 verbatim, then authors the per-finding
# `sequenceDiagram` blocks in §3.2+. Without this helper the agent fabulates
# chain labels that fail `qa_checks.py → chain_tid_consistency`.
#
# Leading underscore signals to the composer that this is a helper artefact
# (not a composed section). The composer's REQUIRED_FRAGMENTS list ignores
# `_*.md` so it never becomes a contract-required input on its own.
# ---------------------------------------------------------------------------

_CHAIN_TITLE_STOPWORDS = frozenset(
    {
        "the", "a", "an", "of", "in", "on", "at", "to", "for", "by", "via",
        "and", "or", "but", "with", "from", "into", "is", "be", "are", "was",
        "this", "that", "these", "those",
    }
)


def _chain_label_for_threat(t: dict) -> str:
    """Build a short, content-keyword chain-graph node label for a threat.

    The label MUST share at least one keyword with `threats[].title` so the
    `chain_tid_consistency` checker accepts it. We do this by taking the
    first 4-5 non-stopword tokens from the title.
    """
    title = str(t.get("title") or "").strip()
    if not title:
        return "—"
    # Strip any "— file:line" suffix.
    head = title.split(" — ")[0]
    tokens = [w for w in head.split() if w.lower() not in _CHAIN_TITLE_STOPWORDS]
    short = " ".join(tokens[:5])
    return short or head


def gen_attack_walkthroughs_skeleton(yaml_data: dict) -> str:
    """Deterministic full-§3 skeleton.

    Replaces the prior minimal-skeleton form (intros + bare chain graphs)
    with a complete §3 scaffold the renderer agent fills in by adding
    repo-specific narrative inside pre-labelled labelled-form blocks.

    Produces:
      * §3 intro (chain-aware, enumerates the chains that follow + the
        per-finding §3.x walkthroughs that follow §3.1).
      * §3.1 Attack Chain Overview with:
          - Visual-schema explanation paragraph.
          - "Chains in this section:" enumerated list (chain N → actor → impact).
          - One `#### Chain N — <name>` block per chain, with:
              * Intro paragraph (template prose ready for repo-specific fill).
              * `graph LR` block (classDef + risk-class line).
              * `**Key takeaway:**` one-sentence summary.
      * §3.2+ per-finding walkthroughs (one per Critical, then fill with
        High up to a cap). Each walkthrough is a labelled-form block:
          - Heading: `### 3.N <canonical title>`
          - **Attacker Profile** paragraph.
          - **Prerequisites** bullets.
          - **Attack Steps** numbered list (3-5 items).
          - **Sequence Diagram** with mandatory `alt Current state` /
            `else After mitigation` block.
          - **Business Impact** paragraph.
          - **Detection Signals** bullets.
          - **Defense in Depth** bullets linking to mitigation IDs.
          - **Cross-references** bullets (links into §3.1, §8, related §3.x).

    The renderer agent reads this skeleton and replaces every
    `<!-- WALKTHROUGH_FILL: ... -->` placeholder with repo-specific prose.
    The headings, bullet markers, and Mermaid scaffolding stay verbatim.
    """
    threats = yaml_data.get("threats") or []
    if not isinstance(threats, list):
        threats = []

    def _risk_rank(t: dict) -> int:
        rk = str(t.get("risk") or t.get("severity") or "").strip().lower()
        return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(rk, 4)

    ranked = sorted(
        (t for t in threats if isinstance(t, dict) and t.get("id")),
        key=_risk_rank,
    )
    # Cap §3.1 chain blocks at 5 per contract chain_compactness.max_blocks=5.
    chain_picks = ranked[:5]
    # §3.2+ — one walkthrough per Critical finding; fill from High up to
    # a total of 8 sections so the document stays navigable. The contract's
    # per_critical_subsection requirement still drives the lower bound.
    crit_only = [t for t in ranked if _risk_rank(t) == 0]
    high_only = [t for t in ranked if _risk_rank(t) == 1]
    walkthrough_picks = crit_only + high_only[: max(0, 8 - len(crit_only))]

    out: list[str] = []
    out.append("## 3. Attack Walkthroughs")
    out.append("")
    out.append(
        "This section reconstructs how the most-impactful findings actually "
        "play out as attacks against this codebase. It is the narrative core "
        "of the threat model — every chain ties one or more §8 Threat-Register "
        "findings into an end-to-end exploitation sequence with attacker "
        "actor, prerequisites, runtime mechanics, business impact, and the "
        "controls that would have broken the chain."
    )
    out.append("")
    out.append("**Structure of this section:**")
    out.append("")
    out.append(
        "- **§3.1 Attack Chain Overview** — a small Mermaid diagram per "
        "kill-chain showing how the attacker moves through the application "
        "to reach business impact. Read these first to understand which "
        "findings interlock."
    )
    out.append(
        "- **§3.2 onward** — one labelled-form walkthrough per Critical "
        "finding (and a small number of representative High findings) "
        "covering Attacker Profile, Prerequisites, Attack Steps (with "
        "rationale), Sequence Diagram, Business Impact, Detection Signals, "
        "Defense in Depth, and Cross-references."
    )
    out.append("")
    out.append(
        "Medium- and Low-severity findings are not walked through here — "
        "they are documented in [§8 Threat Register](#8-threat-register) "
        "with the same Story-Card structure but without the kill-chain "
        "narrative."
    )
    out.append("")

    # -- §3.1 ---------------------------------------------------------------
    out.append("### 3.1 Attack Chain Overview")
    out.append("")
    out.append(
        "Each chain below is one realistic path from an entry point to a "
        "business-impact outcome. Nodes coloured red are attacker-controlled "
        "states or actions; nodes coloured dark are impact outcomes. The "
        "arrows encode causality, not timing. A chain typically covers 2–4 "
        "findings — every individual finding keeps its detailed write-up "
        "in [§8 Threat Register](#8-threat-register) and is linked back "
        "from there to the chain that uses it."
    )
    out.append("")

    if chain_picks:
        out.append("**Chains in this section:**")
        out.append("")
        for i, t in enumerate(chain_picks, start=1):
            tid = str(t.get("id") or "").strip()
            label = _chain_label_for_threat(t)
            head_tokens = label.split()[:4]
            head_short = " ".join(head_tokens) or label
            out.append(
                f"{i}. **Chain {i} — {head_short}** — anchored by "
                f"`{tid}`. <!-- WALKTHROUGH_FILL: actor → step → impact in ≤1 line -->"
            )
        out.append("")
    else:
        out.append(
            "_No Critical or High findings present — the chain overview is "
            "empty for this assessment._"
        )
        out.append("")
        return "\n".join(out) + "\n"

    # Per-chain blocks.
    for i, t in enumerate(chain_picks, start=1):
        tid = str(t.get("id") or "").strip()
        label = _chain_label_for_threat(t)
        head_tokens = label.split()[:4]
        head_short = " ".join(head_tokens) or label

        out.append(f"#### Chain {i} — {head_short}")
        out.append("")
        out.append(
            "<!-- WALKTHROUGH_FILL: 2-3 sentence intro — who is the attacker, "
            "what's the entry point, what's the business outcome at the "
            f"end of this chain? Anchor finding: `{tid}` ({label}). -->"
        )
        out.append("")
        out.append("```mermaid")
        out.append("graph LR")
        out.append(f"    A[Anonymous attacker]:::risk --> B[{tid}: {label}]:::risk")
        out.append("    B --> C[Privileged access]:::impact")
        out.append("    classDef risk fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:2px")
        out.append("    classDef impact fill:#0f172a,stroke:#000,color:#fff,stroke-width:2px")
        out.append("```")
        out.append("")
        out.append(
            "**Key takeaway:** <!-- WALKTHROUGH_FILL: one sentence summarising "
            "this chain's exposure (what an attacker walks away with). -->"
        )
        out.append("")

    # -- §3.2+ per-finding walkthroughs ------------------------------------
    for idx, t in enumerate(walkthrough_picks, start=2):
        tid = str(t.get("id") or "").strip()
        # Build a visible F-NNN form if the id is T-NNN.
        m = re.match(r"^T-(\d+)$", tid)
        vid = f"F-{m.group(1)}" if m else tid
        # Title — canonical short form derived from CWE + evidence.
        # Mirrors `_canonical_finding_title` in compose_threat_model.py but
        # the pregenerator stays self-contained.
        cwe_raw = (t.get("cwe") or "").strip()
        cwe_norm = cwe_raw if cwe_raw.upper().startswith("CWE-") else (
            f"CWE-{cwe_raw}" if cwe_raw.isdigit() else cwe_raw
        )
        weak_label = _PREGEN_CWE_CLASS_NAMES.get(cwe_norm.upper(), "")
        if not weak_label:
            head = _chain_label_for_threat(t)
            weak_label = head or (t.get("title") or vid)
        ev = t.get("evidence") or {}
        ev_file = ""
        ev_line = None
        if isinstance(ev, dict):
            ev_file = (ev.get("file") or "").strip()
            ev_line = ev.get("line")
        loc_suffix = ""
        if ev_file:
            loc_suffix = f" — `{ev_file}" + (f":{ev_line}" if ev_line else "") + "`"
        out.append(f"### 3.{idx} {vid} — {weak_label}{loc_suffix}")
        out.append("")

        # Attacker Profile.
        out.append("**Attacker Profile**")
        out.append("")
        out.append(
            "<!-- WALKTHROUGH_FILL: 2-3 sentences describing the attacker "
            "(actor category: anonymous internet user / authenticated user / "
            "B2B partner / insider; capability: HTTP-only / auth required / "
            "repo read; goal: takeover / data theft / DoS / etc.). Name the "
            "attacker's starting position and what tooling they need. -->"
        )
        out.append("")

        # Prerequisites.
        out.append("**Prerequisites**")
        out.append("")
        out.append(
            "<!-- WALKTHROUGH_FILL: bullet list of 2-5 prerequisites — "
            "auth state, network reachability, prior chain steps, "
            "application data state. One per bullet. -->"
        )
        out.append("- ")
        out.append("- ")
        out.append("- ")
        out.append("")

        # Attack Steps.
        out.append("**Attack Steps**")
        out.append("")
        out.append(
            "<!-- WALKTHROUGH_FILL: 3-5 numbered steps. Each step states "
            "the attacker action + the response that confirms success + "
            "WHY the step works (which property of the code is being "
            "abused). Cite `file:line` for the code element exercised. -->"
        )
        out.append("1. ")
        out.append("2. ")
        out.append("3. ")
        out.append("")

        # Sequence Diagram.
        out.append("**Sequence Diagram**")
        out.append("")
        out.append(
            "The diagram contrasts the current vulnerable behaviour with "
            "the post-mitigation state:"
        )
        out.append("")
        out.append("```mermaid")
        out.append("sequenceDiagram")
        out.append("    autonumber")
        out.append("    actor Attacker")
        out.append("    participant App as Application")
        out.append("")
        out.append("    alt Current state")
        out.append("        Attacker->>App: <!-- WALKTHROUGH_FILL: request payload -->")
        out.append("        App-->>Attacker: <!-- WALKTHROUGH_FILL: response that confirms exploit -->")
        out.append("    else After mitigation")
        out.append("        Attacker->>App: <!-- WALKTHROUGH_FILL: same request -->")
        out.append("        App-->>Attacker: <!-- WALKTHROUGH_FILL: rejected response -->")
        out.append("    end")
        out.append("```")
        out.append("")

        # Business Impact.
        out.append("**Business Impact**")
        out.append("")
        out.append(
            "<!-- WALKTHROUGH_FILL: 2-3 sentences naming the CONCRETE "
            "impact — number of records / sessions / dollars at risk, "
            "downstream blast radius (lateral movement, data loss, "
            "regulatory exposure), confidentiality vs integrity vs "
            "availability dimension. Avoid generic phrases like "
            "\"sensitive data exposed\". -->"
        )
        out.append("")

        # Detection Signals.
        out.append("**Detection Signals**")
        out.append("")
        out.append(
            "<!-- WALKTHROUGH_FILL: 2-4 bullets — concrete log lines, "
            "anomaly patterns, metric spikes, SIEM queries that would "
            "catch this attack in production. Each bullet must name a "
            "specific signal, not a generic category. -->"
        )
        out.append("- ")
        out.append("- ")
        out.append("")

        # Defense in Depth.
        out.append("**Defense in Depth**")
        out.append("")
        out.append(
            "<!-- WALKTHROUGH_FILL: 3-5 bullets. First bullet = primary "
            "mitigation `[M-NNN](#m-nnn)` (must match the finding's "
            "mitigations[] field in yaml). Remaining bullets = OTHER "
            "mitigations (often in different defensive layers) that "
            "would have broken the chain at intermediate steps. -->"
        )
        out.append("- ")
        out.append("- ")
        out.append("")

        # Cross-references.
        out.append("**Cross-references**")
        out.append("")
        out.append(
            f"- [§8 Threat Register entry for {vid}](#{vid.lower()}) — "
            "evidence, classification, full mitigation list."
        )
        out.append(
            "- <!-- WALKTHROUGH_FILL: §3.1 chain that uses this finding "
            "(e.g. `[Chain 2](#chain-2-...)`) -->"
        )
        out.append(
            "- <!-- WALKTHROUGH_FILL: related §3.x walkthroughs that "
            "share findings or actors -->"
        )
        out.append("")

    return "\n".join(out) + "\n"


# Lightweight CWE → class label table for the pregenerator. Kept in sync
# manually with `_CWE_CLASS_NAMES` in scripts/compose_threat_model.py.
_PREGEN_CWE_CLASS_NAMES = {
    "CWE-22":   "Path Traversal",
    "CWE-23":   "Path Traversal",
    "CWE-78":   "OS Command Injection",
    "CWE-79":   "Cross-Site Scripting",
    "CWE-87":   "Cross-Site Scripting",
    "CWE-89":   "SQL Injection",
    "CWE-94":   "Code Injection",
    "CWE-95":   "Server-Side Template Injection",
    "CWE-200":  "Information Disclosure",
    "CWE-269":  "Improper Privilege Management",
    "CWE-285":  "Improper Authorization",
    "CWE-287":  "Improper Authentication",
    "CWE-290":  "Authentication Bypass by Spoofing",
    "CWE-294":  "Authentication Bypass by Capture-Replay",
    "CWE-307":  "Missing Rate Limiting (Brute-Force)",
    "CWE-312":  "Cleartext Storage of Sensitive Data",
    "CWE-321":  "Hardcoded Cryptographic Key",
    "CWE-327":  "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-328":  "Use of Weak Hash",
    "CWE-345":  "Insufficient Verification of Data Authenticity",
    "CWE-347":  "Improper Verification of Cryptographic Signature",
    "CWE-352":  "Cross-Site Request Forgery (CSRF)",
    "CWE-400":  "Uncontrolled Resource Consumption",
    "CWE-434":  "Unrestricted File Upload",
    "CWE-548":  "Directory Listing Exposure",
    "CWE-601":  "Open Redirect",
    "CWE-611":  "XML External Entity (XXE)",
    "CWE-620":  "Unverified Password Change",
    "CWE-639":  "Insecure Direct Object Reference (IDOR)",
    "CWE-693":  "Missing Defense-in-Depth Control",
    "CWE-798":  "Hardcoded Credentials",
    "CWE-862":  "Missing Authorization",
    "CWE-863":  "Incorrect Authorization",
    "CWE-918":  "Server-Side Request Forgery (SSRF)",
    "CWE-922":  "Insecure Storage of Sensitive Information",
    "CWE-942":  "Permissive Cross-Origin (CORS) Policy",
    "CWE-943":  "NoSQL Injection",
    "CWE-1021": "Improper Restriction of UI Rendering Layers (Clickjacking)",
    "CWE-1104": "Use of Unmaintained Third-Party Components",
    "CWE-1321": "Prototype Pollution",
}


# ---------------------------------------------------------------------------
# Schema v2 — 13-section §7 control-category layout
# ---------------------------------------------------------------------------

_V2_SUBSECTIONS: tuple[tuple[str, str, str], ...] = (
    # (heading, narrative_hint_for_llm, tier). Tier is retained for backward
    # compatibility with older composer logic; current v2 emits every section.
    ("7.1 Security Control Overview",
     "Overview matrix: Control category, Verdict, Main reason. No control IDs "
     "and no finding-ID columns.", "a"),
    ("7.2 Identity and Authentication Controls",
     "Registration, password login, OAuth/OIDC adapters, MFA/TOTP, JWT issuance "
     "and verification, password reset/change.", "a"),
    ("7.3 Session and Token Controls",
     "Browser token storage, request propagation, token lifetime, revocation, "
     "cookie/session boundary.", "a"),
    ("7.4 Authorization Controls",
     "Route middleware, role checks, object-level authorization, client-side "
     "guards versus server-side enforcement.", "a"),
    ("7.5 Query Construction and Data Access Controls",
     "SQL/NoSQL query construction, ORM usage, parameter binding, selector and "
     "object ownership boundaries.", "a"),
    ("7.6 Input Boundary Validation Controls",
     "Request schemas, parser limits, upload constraints, URL/path validation, "
     "business-rule boundaries.", "a"),
    ("7.7 Output Encoding and Rendering Controls",
     "Template escaping, DOM sinks, sanitizer bypasses, HTML rendering contexts.", "a"),
    ("7.8 Browser and Cross-Origin Controls",
     "CSP, CORS, CSRF, Helmet/header hardening, browser-side request policy.", "a"),
    ("7.9 Cryptography Secrets and Data Protection",
     "Signing keys, HMAC/cookie secrets, password storage, data-at-rest protection.", "a"),
    ("7.10 File Parser and Outbound Request Controls",
     "Uploads, archives, XML parsing, unsafe interpreters, SSRF, redirects, "
     "static or management-surface exposure.", "a"),
    ("7.11 Operations Runtime and Supply Chain Controls",
     "Audit logging, runtime/container hardening, dependency determinism, CI "
     "workflow permissions, package-install controls.", "a"),
    ("7.12 Real-time and Not Applicable Controls",
     "WebSocket/real-time channels plus compact absent-domain statements.", "a"),
    ("7.13 Defense-in-Depth Summary",
     "Cross-cutting summary of layered controls and residual architecture risk.", "a"),
)


# M5b — Default H4 mechanism name per §7.X. Used by the fallback branch
# in `gen_security_architecture_v2` when a section has no catalogued
# security_controls[] but DOES carry routed findings. Names match the
# reference threat-model.md so generated reports converge on the same
# vocabulary. The pregenerator falls back to a heading-derived noun phrase
# (`heading.split(" ", 1)[1]`) when a section is not listed here.
_V2_DEFAULT_MECHANISM: dict[str, str] = {
    "7.2 Identity and Authentication Controls": "Identity and Authentication Mechanisms",
    "7.3 Session and Token Controls": "Browser Token Storage and Request Propagation",
    "7.4 Authorization Controls": "Route and Object Authorization",
    "7.5 Query Construction and Data Access Controls": "Query Construction",
    "7.6 Input Boundary Validation Controls": "Input Boundary Validation",
    "7.7 Output Encoding and Rendering Controls": "Output Encoding and Client-Side Rendering",
    "7.8 Browser and Cross-Origin Controls": "Browser Security Headers and CORS/CSRF Posture",
    "7.9 Cryptography Secrets and Data Protection": "Secret Management and Data Protection",
    "7.10 File Parser and Outbound Request Controls": "File Parser and Outbound Request Handling",
    "7.11 Operations Runtime and Supply Chain Controls": "Logging, Runtime and Supply Chain Posture",
    "7.12 Real-time and Not Applicable Controls": "Real-time WebSocket Channel",
}


# CWE → §7.X routing table — mirrors sections-contract.yaml schema_v2
# finding_routing. Kept here as a static map so the pregenerator does not
# need to parse the YAML contract.
_V2_CWE_ROUTING: dict[str, str] = {
    "CWE-287": "7.2 Identity and Authentication Controls",
    "CWE-307": "7.2 Identity and Authentication Controls",
    "CWE-294": "7.2 Identity and Authentication Controls",
    "CWE-345": "7.2 Identity and Authentication Controls",
    "CWE-347": "7.2 Identity and Authentication Controls",
    "CWE-620": "7.2 Identity and Authentication Controls",
    "CWE-640": "7.2 Identity and Authentication Controls",
    "CWE-916": "7.2 Identity and Authentication Controls",
    "CWE-922": "7.3 Session and Token Controls",
    "CWE-384": "7.3 Session and Token Controls",
    "CWE-613": "7.3 Session and Token Controls",
    "CWE-1004": "7.3 Session and Token Controls",
    "CWE-285": "7.4 Authorization Controls",
    "CWE-639": "7.4 Authorization Controls",
    "CWE-269": "7.4 Authorization Controls",
    "CWE-862": "7.4 Authorization Controls",
    "CWE-863": "7.4 Authorization Controls",
    "CWE-732": "7.4 Authorization Controls",
    "CWE-352-authz": "7.4 Authorization Controls",
    "CWE-602": "7.4 Authorization Controls",
    "CWE-915": "7.4 Authorization Controls",
    "CWE-89": "7.5 Query Construction and Data Access Controls",
    "CWE-943": "7.5 Query Construction and Data Access Controls",
    "CWE-20": "7.6 Input Boundary Validation Controls",
    "CWE-1284": "7.6 Input Boundary Validation Controls",
    "CWE-1287": "7.6 Input Boundary Validation Controls",
    "CWE-400": "7.6 Input Boundary Validation Controls",
    "CWE-79": "7.7 Output Encoding and Rendering Controls",
    "CWE-80": "7.7 Output Encoding and Rendering Controls",
    "CWE-87": "7.7 Output Encoding and Rendering Controls",
    "CWE-116": "7.7 Output Encoding and Rendering Controls",
    "CWE-1021": "7.8 Browser and Cross-Origin Controls",
    "CWE-942": "7.8 Browser and Cross-Origin Controls",
    "CWE-693": "7.8 Browser and Cross-Origin Controls",
    "CWE-358": "7.8 Browser and Cross-Origin Controls",
    "CWE-352": "7.8 Browser and Cross-Origin Controls",
    "CWE-321": "7.9 Cryptography Secrets and Data Protection",
    "CWE-798": "7.9 Cryptography Secrets and Data Protection",
    "CWE-327": "7.9 Cryptography Secrets and Data Protection",
    "CWE-326": "7.9 Cryptography Secrets and Data Protection",
    "CWE-329": "7.9 Cryptography Secrets and Data Protection",
    "CWE-330": "7.9 Cryptography Secrets and Data Protection",
    "CWE-312": "7.9 Cryptography Secrets and Data Protection",
    "CWE-538": "7.9 Cryptography Secrets and Data Protection",
    "CWE-759": "7.9 Cryptography Secrets and Data Protection",
    "CWE-611": "7.10 File Parser and Outbound Request Controls",
    "CWE-22": "7.10 File Parser and Outbound Request Controls",
    "CWE-23": "7.10 File Parser and Outbound Request Controls",
    "CWE-409": "7.10 File Parser and Outbound Request Controls",
    "CWE-776": "7.10 File Parser and Outbound Request Controls",
    "CWE-94": "7.10 File Parser and Outbound Request Controls",
    "CWE-95": "7.10 File Parser and Outbound Request Controls",
    "CWE-918": "7.10 File Parser and Outbound Request Controls",
    "CWE-601": "7.10 File Parser and Outbound Request Controls",
    "CWE-441": "7.10 File Parser and Outbound Request Controls",
    "CWE-548": "7.10 File Parser and Outbound Request Controls",
    "CWE-552": "7.10 File Parser and Outbound Request Controls",
    "CWE-749": "7.10 File Parser and Outbound Request Controls",
    "CWE-200": "7.10 File Parser and Outbound Request Controls",
    "CWE-117": "7.11 Operations Runtime and Supply Chain Controls",
    "CWE-223": "7.11 Operations Runtime and Supply Chain Controls",
    "CWE-209": "7.11 Operations Runtime and Supply Chain Controls",
    "CWE-532": "7.11 Operations Runtime and Supply Chain Controls",
    "CWE-778": "7.11 Operations Runtime and Supply Chain Controls",
    "CWE-1104": "7.11 Operations Runtime and Supply Chain Controls",
    "CWE-1395": "7.11 Operations Runtime and Supply Chain Controls",
    "CWE-937": "7.11 Operations Runtime and Supply Chain Controls",
    "CWE-829": "7.11 Operations Runtime and Supply Chain Controls",
    "CWE-250": "7.11 Operations Runtime and Supply Chain Controls",
    "CWE-15": "7.11 Operations Runtime and Supply Chain Controls",
    "CWE-260": "7.11 Operations Runtime and Supply Chain Controls",
    "CWE-1385": "7.12 Real-time and Not Applicable Controls",
}


def _count_routings_by_section(threats: list[dict]) -> dict[str, int]:
    """Return {heading -> finding_count} using the static CWE map.
    Threats without a CWE or with a CWE outside the map contribute zero."""
    counts: dict[str, int] = {}
    for t in threats or []:
        if not isinstance(t, dict):
            continue
        cwe = (t.get("cwe") or "").strip().upper()
        if not cwe:
            continue
        section = _V2_CWE_ROUTING.get(cwe)
        if section:
            counts[section] = counts.get(section, 0) + 1
    return counts


# Severity rank — used by the Heading-verdict suffix
_STATUS_RANK = {"missing": 4, "weak": 3, "partial": 2, "adequate": 1}


def _control_verdict_for_heading(
    heading: str,
    threats_by_section: dict[str, list[dict]],
    controls: list[dict],
) -> str:
    """Compose the trailing " — <Verdict>" suffix for a §7.X heading.

    Reads `security_controls[].effectiveness` for any control whose `domain`
    matches the section heading, picks the worst-case status, and pairs it
    with the highest-severity routed finding. When the section has neither
    a mapped control nor a routed finding, the suffix is omitted entirely
    and the LLM is free to author its own verdict.
    """
    section_threats = threats_by_section.get(heading) or []
    # Pick worst severity routed here.
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    worst_sev = ""
    for t in section_threats:
        r = (t.get("risk") or t.get("severity") or "").strip().lower()
        if sev_order.get(r, 0) > sev_order.get(worst_sev, 0):
            worst_sev = r
    # Pick worst control status for this domain.
    worst_status = ""
    for c in controls or []:
        if not isinstance(c, dict):
            continue
        dom = (c.get("domain") or "").strip()
        if not dom or dom not in heading:
            continue
        eff = (c.get("effectiveness") or "").strip().lower()
        if _STATUS_RANK.get(eff, 0) > _STATUS_RANK.get(worst_status, 0):
            worst_status = eff
    if not worst_status and not worst_sev:
        return ""
    status_label = {
        "missing": "Missing", "weak": "Weak",
        "partial": "Partial", "adequate": "Adequate",
    }.get(worst_status, worst_status.title() if worst_status else "")
    if not status_label and section_threats:
        # Threats present but no control mapped — clearly weak at minimum.
        status_label = "Weak"
    sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(worst_sev, "")
    if status_label and sev_emoji:
        return f" — {status_label} · {sev_emoji} {worst_sev.title()}"
    if status_label:
        return f" — {status_label}"
    return ""


def _v2_slug(title: str) -> str:
    """Anchor slug used by the v2 §7 scaffold.

    Delegates to `scripts/_slug.py::github_slug` so the pregenerator,
    composer, and qa_checks emit byte-identical slugs. The previous
    inline `[^a-z0-9]+` collapse silently produced different slugs than
    the GitHub renderer for headings containing `&`, `@`, `+`, `(`, `)`,
    which was the proximate cause of the §7 `#h4-*` TOC drift bug.
    """
    from _slug import github_slug as _gh
    slug = _gh(title or "")
    return slug or "control"


_V2_CONTROL_HINTS: dict[str, tuple[str, ...]] = {
    # 2026-05 R-6/R-7 fix — hints sharpened so they are mutually exclusive
    # when matched against `control.domain`. Previously "auth" appeared in
    # §7.2 and matched both `authentication` and `authorization` domains,
    # leaking authorization controls into §7.2. Likewise "management" in
    # §7.10 matched "secrets-management" leaking secrets controls into §7.10.
    "7.2 Identity and Authentication Controls": (
        "identity", "iam", "authentication", "identity-auth", "login", "password-login",
        "jwt-issu", "oauth-adapter", "oidc-adapter", "totp", "mfa", "2fa", "registration",
    ),
    "7.3 Session and Token Controls": (
        "session", "token-storage", "cookie", "localstorage", "browser-storage",
    ),
    "7.4 Authorization Controls": (
        "authorization", "access-control", "rbac", "object-level", "ownership",
    ),
    "7.5 Query Construction and Data Access Controls": (
        "query", "sql", "nosql", "orm", "data-access",
    ),
    "7.6 Input Boundary Validation Controls": (
        "input-validation", "schema-validation", "upload-validation", "request-body",
        "parser-limit", "rate-limiting",
    ),
    "7.7 Output Encoding and Rendering Controls": (
        "output-encoding", "render", "xss", "sanit", "dom-sanit",
    ),
    "7.8 Browser and Cross-Origin Controls": (
        "browser", "csp", "cors", "csrf", "helmet", "security-headers", "cors-csrf",
    ),
    "7.9 Cryptography Secrets and Data Protection": (
        "crypto", "cryptography", "secret-manag", "secrets-manag", "key-manag", "kms",
        "hash", "password-storage", "password hashing", "encryption", "data-protection",
    ),
    "7.10 File Parser and Outbound Request Controls": (
        "file-security", "file-parser", "xml-parser", "archive", "ssrf", "redirect-allow",
    ),
    "7.11 Operations Runtime and Supply Chain Controls": (
        "audit", "logging-monitor", "logging-monitoring", "runtime", "container", "dependency",
        "supply-chain", "ci-cd",
    ),
    "7.12 Real-time and Not Applicable Controls": (
        "websocket", "real-time", "socket.io", "ai-llm", "llm", "graphql", "grpc",
    ),
}


_V2_HEADING_ORDER: tuple[str, ...] = tuple(h for h, _ in (_V2_CONTROL_HINTS.items()))


def _v2_canonical_section_for_control(c: dict) -> str:
    """Return the SINGLE canonical §7 heading a control belongs to.

    2026-05 R-6/R-7 fix: hint matching is non-exclusive (e.g. a control with
    `domain=secrets-management` matched both §7.9 (`secret`) and §7.10
    (`management`), so the same H4 block was emitted in two sections — with
    identical `<a id="…">` anchors → duplicate-anchor warnings, controls
    duplicated across §7 categories, and inconsistent verdict-counting).

    Resolution priority:
      1. Explicit ``section`` / ``v2_section`` field on the control.
      2. Match against the control's ``domain`` field FIRST (specific —
         "cryptography" cleanly resolves to §7.9, not §7.2 via "password"
         leakage). Domain is the Stage-1-authored canonical taxonomy slot.
      3. Fall back to the broader haystack (control/name/implementation)
         only when domain matched nothing — preserves backward-compat for
         older yamls that omit ``domain``.
    """
    if not isinstance(c, dict):
        return ""
    explicit = (c.get("section") or c.get("v2_section") or "").strip()
    if explicit and explicit in _V2_CONTROL_HINTS:
        return explicit
    domain = (c.get("domain") or "").strip().lower()
    if domain:
        for heading in _V2_HEADING_ORDER:
            hints = _V2_CONTROL_HINTS.get(heading, ())
            if any(h in domain for h in hints):
                return heading
    haystack = " ".join(
        str(c.get(k) or "").lower()
        for k in ("control", "name", "implementation")
    )
    if not haystack.strip():
        return ""
    for heading in _V2_HEADING_ORDER:
        hints = _V2_CONTROL_HINTS.get(heading, ())
        if any(h in haystack for h in hints):
            return heading
    return ""


def _v2_controls_for_heading(controls: list[dict], heading: str) -> list[dict]:
    """Return the subset of controls whose canonical §7 section is ``heading``.

    Each control resolves to AT MOST one heading via
    ``_v2_canonical_section_for_control``; this guarantees that the same
    sub-control title never appears in two different §7 categories.
    """
    if heading not in _V2_CONTROL_HINTS:
        return []
    return [c for c in (controls or [])
            if isinstance(c, dict) and _v2_canonical_section_for_control(c) == heading]


def _v2_finding_links(threats: list[dict], section: str, max_links: int = 5) -> list[str]:
    """Return CWE-routed F-NNN markdown links — bare, no title trailer.

    R-S10 — historically this function appended ` - {title}` for context.
    Titles already encode `<class> — file:line`, so when Stage 2 enriches
    the bullet with its own one-sentence rationale (per the renderer
    example), the result becomes
    `[F-009](#f-009) - Persistent XSS — file:line - Persistent XSS — file:line`.
    The pregenerator now emits only the bare link; Stage 2 owns the
    trailing rationale sentence in the form `- [F-NNN](#f-nnn) — <one
    sentence about what this finding proves about the control>.`
    """
    links: list[str] = []
    for t in threats or []:
        if not isinstance(t, dict):
            continue
        if _V2_CWE_ROUTING.get((t.get("cwe") or "").strip().upper()) != section:
            continue
        tid = _to_canonical_finding_label(t.get("id", "?"))
        links.append(f"[{tid}](#{tid.lower()})")
        if len(links) >= max_links:
            break
    return links


# Friendlier replacements for a handful of terse / overly-technical control
# names that Stage 1 sometimes emits as H4 headings. The replacement adds
# context (what kind of construction, what kind of management) without
# losing the underlying term. Anything not in this map is passed through —
# the goal is to fix the worst offenders, not to retitle every control.
_FRIENDLY_SUBCONTROL_TITLE: dict[str, str] = {
    # Aligns terse Stage-1 names with the canonical security-engineering
    # vocabulary used in OWASP ASVS v4 / NIST SP 800-63B. Entries are added
    # ONLY when the raw name is ambiguous or non-standard — controls already
    # named in their canonical form pass through unchanged.
    "Query Construction":     "Database Query Construction",
    "Output Encoding":        "Output Encoding and Escaping",
    "Container Hardening":    "Container Runtime Hardening",
    "Secret Management":      "Secret and Key Management",
    "Input Validation":       "Request Input Validation",
    # 2026-05 (user-request point 4): align §7 H4 titles with OWASP ASVS
    # vocabulary so that "JWT authentication" reads as the token-mechanism
    # it actually is, and "Route-level auth middleware" disambiguates as
    # Authorization (the Z) rather than Authentication. Each replacement
    # keeps the original term in parens so existing cross-refs that grep
    # for "JWT" / "DomSanitizer" / etc. still find their target.
    "JWT authentication":                  "Token-Based Session Authentication (JWT)",
    "JWT authentication (RS256)":          "Token-Based Session Authentication (JWT, RS256)",
    "Password hashing":                    "Password Hashing and Credential Storage",
    "Route-level auth middleware":         "Route-Level Authorization Middleware",
    "Route-level auth middleware (isAuthorized)": "Route-Level Authorization Middleware (isAuthorized)",
    "ORM parameterized queries":           "Parameterized ORM Queries",
    "Request body validation":             "Request Body Schema Validation",
    "Request rate limiting":               "Authentication Rate Limiting",
    "Angular DomSanitizer":                "Client-Side Output Sanitization (Angular DomSanitizer)",
    "HTTP security headers":               "HTTP Security Headers (Helmet)",
    "HTTP security headers (Helmet)":      "HTTP Security Headers (Helmet)",
    "Cross-origin resource sharing policy": "Cross-Origin Resource Sharing (CORS) Policy",
    "Access logging":                      "Application Access Logging",
    "JWT stored in localStorage":          "JWT Storage in Browser localStorage",
    "Secrets and key management":          "Secret and Key Management",
    "File upload validation and safe extraction": "File Upload Validation and Safe Archive Extraction",
}


def _friendly_subcontrol_title(name: str) -> str:
    """Return a more reader-friendly version of a §7 H4 subcontrol title.

    Two transforms, both renderer-side, never written to YAML:
      1. Strip trailing parenthetical tech-specifics like
         ``"X (express-jwt / jsonwebtoken)"`` → ``"X"`` — Stage 1 occasionally
         leaks library inventories into the title, which belongs in the
         security-assessment paragraph below the H4, not the heading.
      2. Apply ``_FRIENDLY_SUBCONTROL_TITLE`` so a small set of known-terse
         names gain context (``"Query Construction"`` → ``"Database Query
         Construction"``). The map is intentionally short — most catalogued
         control names are already understandable.
    """
    if not name:
        return name
    cleaned = re.sub(r"\s*\([^()]*\)\s*$", "", name).strip()
    return _FRIENDLY_SUBCONTROL_TITLE.get(cleaned, cleaned)


def _emit_v2_subcontrol_block(lines: list, sub: dict, threats: list, heading: str,
                              section_id: str = "", idx: int = 0) -> None:
    """Emit one §7.x #### block from a `security_controls[].subcontrols[]` entry.

    R9 / R12 — Reference-style block carries (in order):
      1. `#### <title>` heading using canonical industry terminology
      2. `<implementation>` paragraph — positive-case description of HOW the
         mechanism works in this app (which routes/components/libraries).
         The Stage-1 prompt is responsible for writing positive-case prose.
      3. Optional ```mermaid sequenceDiagram``` showing the positive flow.
      4. `**Security assessment**` label + multi-sentence narrative.
      5. Optional ```ts/```js code excerpt (3-5 lines).
      6. `**Relevant findings**` bullet list, one [F-NNN](#f-nnn) per bullet
         with a per-finding rationale sentence.

    Missing fields are tolerated — the block degrades gracefully:
      * No `implementation` → NARRATIVE_PLACEHOLDER asking for positive-case intro.
      * No `sequence_diagram` → mermaid block omitted (the LLM can add one
        in the renderer pass if useful).
      * No `code_excerpt` → omitted (not all controls have a usable snippet).
      * No `relevant_findings` → falls back to CWE-routed defaults.
    """
    original_title = (sub.get("title") or "Control").strip()
    title = _friendly_subcontrol_title(original_title)
    # Number the H4 as `7.X.N <title>` so deep links and PDF TOC outline
    # mirror the §2.4 / §7.3 convention (the latter has had numbered H4 for
    # IAM flow blocks since the schema-v2 contract; the rest of §7 was a
    # legacy gap). When section_id/idx are not provided (older call sites),
    # fall back to bare `#### <title>` so behaviour stays compatible.
    #
    # Side anchors are emitted with BOTH the original-name slug AND the
    # friendly-title slug, so links built upstream from either spelling
    # resolve. The numbered heading itself slugifies to e.g.
    # `#721-jwt-authentication` (which would not match `**Controls
    # covered:**` link targets); the side anchors close that gap.
    if section_id and idx:
        anchors = {_v2_slug(original_title), _v2_slug(title)}
        for slug in sorted(anchors):
            lines.append(f'<a id="{slug}"></a>')
        lines.append(f"#### {section_id}.{idx} {title}")
    else:
        lines.append(f"#### {title}")
    lines.append("")
    impl = (sub.get("implementation") or "").strip()
    if impl:
        lines.append(impl)
    else:
        lines.append(
            "<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. "
            "First sentence: what protection this control provides for the "
            "user, in business terms — no library, file, or route names. "
            "Second sentence: how the application implements it, naming the "
            "user-facing surface (e.g. 'authenticated endpoints', 'shopping "
            "basket routes', 'user profile pages') rather than file paths. "
            "Library / middleware / vendor names belong in the security-"
            "assessment block below, NOT in this implementation paragraph. "
            "POSITIVE-CASE only — what the mechanism does, not what is "
            "missing. -->"
        )
    lines.append("")
    diag = (sub.get("sequence_diagram") or "").strip()
    if diag:
        lines.append("```mermaid")
        lines.append(diag)
        lines.append("```")
        lines.append("")
    elif (sub.get("type") or "").lower() == "flow":
        lines.append(
            "<!-- NARRATIVE_PLACEHOLDER: positive-flow ```mermaid sequenceDiagram``` "
            "showing the intended successful path through this mechanism. "
            "Required for flow-like controls (login, OAuth, OIDC, TOTP, "
            "JWT issuance, password reset, mTLS handshake, webhook HMAC). "
            "See agents/appsec-threat-renderer.md → Mermaid templates. -->"
        )
        lines.append("")
    lines.append("**Security assessment**")
    lines.append("")
    assess = (sub.get("assessment") or "").strip()
    if assess:
        lines.append(assess)
    else:
        lines.append(
            "<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. State the mechanism "
            "in this codebase (what library, which route), then the concrete "
            "defects with file:line evidence. Avoid generic phrases ('an "
            "attacker could'), avoid rhetorical severity ('catastrophic'), "
            "avoid banned vocabulary (see prose-style.md → Rule 2). -->"
        )
    lines.append("")
    code = (sub.get("code_excerpt") or "").strip()
    if code:
        # Infer fence language: default to `ts` for our typical Node stack.
        fence_lang = (sub.get("code_language") or "ts").strip()
        lines.append(f"```{fence_lang}")
        lines.append(code)
        lines.append("```")
        lines.append("")
    lines.append("**Relevant findings**")
    lines.append("")
    raw_findings = sub.get("relevant_findings") or []
    if isinstance(raw_findings, str):
        raw_findings = [raw_findings]
    bullet_links: list[str] = []
    for entry in raw_findings[:6]:
        if isinstance(entry, dict):
            tid = (entry.get("id") or entry.get("ref") or "").strip()
            rationale = (entry.get("rationale") or entry.get("note") or "").strip()
        elif isinstance(entry, str):
            tid = entry.strip()
            rationale = ""
        else:
            continue
        if not tid:
            continue
        fid = _to_canonical_finding_label(tid)
        if rationale:
            bullet_links.append(f"[{fid}](#{fid.lower()}) - {rationale}")
        else:
            bullet_links.append(f"[{fid}](#{fid.lower()})")
    if not bullet_links:
        # Heuristic fallback: route findings by CWE → §7.x → take top 3.
        for link in _v2_finding_links(threats, heading, max_links=3):
            bullet_links.append(link)
    if bullet_links:
        for link in bullet_links:
            lines.append(f"- {link}")
    else:
        lines.append("- No dedicated finding routed in this assessment.")
    lines.append("")


# Flow-like mechanism tokens — if the control name matches one of these,
# the scaffold inserts a sequenceDiagram placeholder. Kept in sync with
# `sections-contract.yaml → schema_v2.domain_required_rules → '7.2' →
# auth_method_decomposition.method_whitelist` (R1).
_FLOW_LIKE_TOKENS = frozenset({
    "registration", "login", "oauth", "oidc", "openid", "saml", "sso",
    "totp", "2fa", "mfa", "passkey", "webauthn", "reset", "change",
    "issuance", "verification", "magic-link", "magic", "mtls",
    "webhook", "handshake", "ceremony",
})


def _is_flow_like_control(name: str) -> bool:
    """Token-match a control name against the flow-like mechanism set."""
    tokens = set(re.findall(r"[a-z0-9]+", (name or "").lower()))
    return bool(tokens & _FLOW_LIKE_TOKENS)


def _emit_v2_subcontrol_legacy(lines: list, c: dict, name: str, threats: list, heading: str,
                               section_id: str = "", idx: int = 0) -> bool:
    """Legacy single-block-per-control shape — used when subcontrols[] is empty.

    Pre-R9 Stage-1 outputs emit one row per control without subcontrol
    decomposition. We keep this fallback so older yaml inputs still
    produce a valid §7 fragment. The block still benefits from the
    expanded placeholder set (positive-case intro + sequenceDiagram for
    flow-like names + assessment + bullet findings) so the LLM has the
    same depth target as the subcontrol pathway.

    Returns ``True`` when an H4 block was emitted, ``False`` when the
    control was suppressed (effectiveness=Missing AND no linked threats —
    nothing meaningful to anchor a paragraph to; the parent §7.x
    Assessment block can summarise the absence in one sentence).
    """
    # Fix 5 — suppress H4 when the control has nothing important to
    # explain. "Missing" effectiveness with zero linked threats means the
    # whole block would degrade into "this control is not implemented in
    # this codebase" filler. The controls table at the top of the parent
    # §7.x section already lists the control as Missing; an additional
    # H4 below adds zero information.
    eff = (c.get("effectiveness") or "").strip().lower()
    linked = c.get("linked_threats") or []
    if isinstance(linked, str):
        linked = [linked]
    impl_text = (c.get("implementation") or "").strip()
    if eff == "missing" and not linked and not impl_text:
        return False

    title = _friendly_subcontrol_title(name)
    # Emit BOTH the original-name slug AND the friendly-title slug as side
    # anchors so links from `**Controls covered:**` resolve regardless of
    # which spelling the upstream link-builder chose. The numbered heading
    # itself slugifies differently (e.g. `#721-jwt-authentication`); the
    # side anchors close that gap.
    if section_id and idx:
        anchors = {_v2_slug(name), _v2_slug(title)}
        for slug in sorted(anchors):
            lines.append(f'<a id="{slug}"></a>')
        lines.append(f"#### {section_id}.{idx} {title}")
    else:
        lines.append(f"#### {title}")
    lines.append("")
    if impl_text:
        # Stage 1 supplied an implementation paragraph — use it verbatim;
        # the LLM does not need to author a placeholder.
        lines.append(impl_text)
    else:
        lines.append(
            "<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. "
            "First sentence: what protection this control provides for the "
            "user, in business terms — no library, file, or route names. "
            "Second sentence: how the application implements it, naming the "
            "user-facing surface (e.g. 'authenticated endpoints', 'shopping "
            "basket routes', 'user profile pages') rather than file paths. "
            "Library / middleware / vendor names belong in the security-"
            "assessment block below, NOT in this implementation paragraph. "
            "POSITIVE-CASE only — what the mechanism does, not what is "
            "missing. -->"
        )
    lines.append("")
    if _is_flow_like_control(name):
        lines.append(
            "<!-- NARRATIVE_PLACEHOLDER: positive-flow ```mermaid sequenceDiagram``` "
            "showing the intended successful path through this mechanism. "
            "Required for flow-like controls (login, OAuth, OIDC, TOTP, "
            "JWT issuance, password reset, mTLS handshake, webhook HMAC). "
            "See agents/appsec-threat-renderer.md → Mermaid templates. -->"
        )
        lines.append("")
    lines.append("**Security assessment**")
    lines.append("")
    lines.append(
        "<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one sentence "
        "in plain language describing what this codebase actually does or "
        "fails to do, then the concrete defects with file:line evidence. "
        "Library / middleware / vendor names are allowed here (this is the "
        "technical block), but should appear in the middle or end of the "
        "narrative, not as the first words. Multi-sentence prose — not a "
        "one-line inline tag like '**Security assessment:** ❌ Missing - …'. "
        "Avoid generic phrases ('an attacker could'); avoid rhetorical "
        "severity ('catastrophic'). -->"
    )
    lines.append("")
    if _is_flow_like_control(name):
        lines.append(
            "<!-- NARRATIVE_PLACEHOLDER (optional): ```ts code excerpt```, "
            "3-5 lines from the canonical evidence file showing the "
            "vulnerable or hardened pattern. Skip when no concise snippet "
            "is available. -->"
        )
        lines.append("")
    lines.append("**Relevant findings**")
    lines.append("")
    links = []
    raw_links = c.get("linked_threats") or []
    if isinstance(raw_links, str):
        raw_links = [raw_links]
    for tid in raw_links[:5]:
        if isinstance(tid, str) and tid.strip():
            fid = _to_canonical_finding_label(tid)
            links.append(f"[{fid}](#{fid.lower()})")
    if not links:
        links = _v2_finding_links(threats, heading, max_links=3)
    if links:
        for link in links:
            lines.append(f"- {link}")
    else:
        lines.append("- No dedicated finding routed in this assessment.")
    lines.append("")
    return True


def gen_security_architecture_v2(yaml_data: dict, depth: str = "standard") -> str:
    """13-section §7 scaffold for the v2 security-architecture contract.

    The scaffold follows the rendered v2 shape: a control-category overview,
    then one section per security-control category. Domain sections use
    Verdict / Controls covered / Implemented controls / Assessment labels and
    H4 subcontrols with Security assessment + Relevant findings blocks.
    """
    quick_depth = (depth or "").strip().lower() == "quick"
    controls = _normalize_security_controls(yaml_data.get("security_controls"))
    threats = yaml_data.get("threats") or []

    eff_counts: dict[str, int] = {}
    for c in controls:
        eff = (c.get("effectiveness") or "unknown").lower()
        eff_counts[eff] = eff_counts.get(eff, 0) + 1
    n_adequate = eff_counts.get("adequate", 0)
    n_partial = eff_counts.get("partial", 0)
    n_weak = eff_counts.get("weak", 0)
    n_missing = eff_counts.get("missing", 0)

    threats_by_section: dict[str, list[dict]] = {}
    for t in threats:
        if not isinstance(t, dict):
            continue
        sec = _V2_CWE_ROUTING.get((t.get("cwe") or "").strip().upper())
        if sec:
            threats_by_section.setdefault(sec, []).append(t)

    lines = ["## 7. Security Architecture", ""]
    lines.append(
        "This chapter is organized by security-control category. The architecture "
        "section avoids artificial control IDs and finding-ID columns in overview "
        "tables. Findings are listed only where the affected control is described."
    )
    lines.append("")
    lines.append(
        f"_§7 schema v2 (13-section control-category layout). Cataloged "
        f"controls: {len(controls)} total — {n_adequate} adequate, "
        f"{n_partial} partial, {n_weak} weak, {n_missing} missing. "
        f"Linked threats: {len(threats)}._"
    )
    lines.append("")

    overview_rows = [h for h, _, _ in _V2_SUBSECTIONS[1:]]
    lines.append("### 7.1 Security Control Overview")
    lines.append("")
    # R5 / LOCKED — §7.1 is mechanically derived from security_controls[] +
    # threats_by_section[]. Pregenerator owns it; the LLM renderer MUST NOT
    # re-author this block. The HTML comment markers below are inspected by
    # the renderer prompt and by qa_checks.check_section_71_locked (when
    # active) to verify the block survived round-trips.
    lines.append("<!-- §7.1 MECHANICAL-FROZEN — DO NOT EDIT (overview table is pregenerator-owned) -->")
    lines.append("")
    lines.append("| Control category | Verdict | Main reason |")
    lines.append("|---|---|---|")
    for h in overview_rows:
        matched_controls = _v2_controls_for_heading(controls, h)
        routed = threats_by_section.get(h) or []
        if any((c.get("effectiveness") or "").lower() == "missing" for c in matched_controls):
            verdict = "🔴 Missing"
        elif any((c.get("effectiveness") or "").lower() == "weak" for c in matched_controls) or routed:
            verdict = "🟠 Weak"
        elif any((c.get("effectiveness") or "").lower() == "partial" for c in matched_controls):
            verdict = "🟡 Partial"
        elif matched_controls:
            verdict = "🟢 Adequate"
        else:
            verdict = "—"
        # M5.2 (2026-05) — Main reason cell is a single narrative clause built
        # from CANONICAL CONTROL NAMES (architectural-controls.yaml) and the
        # routed finding count. The cell MUST NOT contain `lib@version`
        # strings, payload phrases (`alg:none`, `noent:true`,
        # `bypassSecurityTrustHtml`), or function-call literals — those
        # belong in the §7.X prose, not in the overview row. The renderer
        # prompt repeats this rule under "No code in finding titles, Top-
        # Findings cells, or §7.1 Main reason cells".
        n_controls = len(matched_controls)
        n_routed = len(routed)
        control_names = [
            (c.get("name") or c.get("control") or "").strip()
            for c in matched_controls
        ]
        control_names = [n for n in control_names if n][:2]  # at most 2 examples
        example_clause = (
            f" (e.g. {', '.join(control_names)})" if control_names else ""
        )
        if verdict.startswith("🔴 Missing"):
            reason = (
                f"{n_routed} routed finding(s); no controls catalogued for this category."
                if n_routed
                else "No controls catalogued for this category."
            )
        elif verdict.startswith("🟠 Weak"):
            if n_controls:
                reason = (
                    f"{n_routed} routed finding(s); catalogued controls are weak{example_clause}."
                )
            else:
                reason = (
                    f"{n_routed} routed finding(s); no compensating controls catalogued."
                )
        elif verdict.startswith("🟡 Partial"):
            reason = (
                f"{n_routed} routed finding(s); {n_controls} partial control(s){example_clause} leave gaps."
            )
        elif verdict.startswith("🟢 Adequate"):
            reason = (
                f"{n_controls} adequate control(s){example_clause}; no routed findings in this category."
            )
        else:
            reason = "No controls or findings routed to this category."
        lines.append(f"| [{h.split(' ', 1)[1]}](#{_v2_slug(h)}) | {verdict} | {reason} |")
    lines.append("")
    lines.append("<!-- §7.1 MECHANICAL-FROZEN END -->")
    lines.append("")

    for heading, hint, _tier in _V2_SUBSECTIONS[1:]:
        lines.append(f"### {heading}")
        lines.append("")

        if heading.startswith("7.13 "):
            # R7 — §7.13 is prose-only. Two paragraphs:
            #   (a) what individual controls exist + the strongest positive
            #       control if any (e.g. distroless runtime image)
            #   (b) which boundary repairs would restore layered defense
            # Forbidden: tables (the layer-mapping table is the dominant
            # drift pattern and recurrently carries speculative perimeter
            # claims like "No WAF in source" that `sanitize_perimeter_claims`
            # then has to scrub).
            lines.append("**Verdict:** <!-- NARRATIVE_PLACEHOLDER: one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. -->")
            lines.append("")
            lines.append("<!-- §7.13 FORMAT — prose-only, NEVER a table. Two short paragraphs: (1) name the individual controls that exist and the strongest positive control if any (e.g. distroless runtime image, RS256 algorithm choice); (2) name which control-boundary repairs would restore layered defense (e.g. parameterized queries, runtime-injected secrets, strict JWT verification). Do NOT emit a Markdown table — `| header |` lines under §7.13 are a contract violation. Do NOT make speculative perimeter-absence claims (`No WAF`, `No firewall`, `No DAM`) — only positive evidence from the recon scan. -->")
            lines.append("")
            lines.append(f"<!-- NARRATIVE_PLACEHOLDER: §{heading} — {hint} (prose paragraphs only) -->")
            lines.append("")
            continue

        # Fix 1 — §7.12 Not-Applicable stub. The section is reserved for
        # real-time / WebSocket controls AND a catch-all for absent domains
        # (AI/LLM, GraphQL, gRPC) the report should explicitly acknowledge.
        # When no findings route to §7.12 via the CWE mapping, the section
        # has nothing real to say — even if a control was mis-routed here
        # (e.g. Container Hardening mapping to §7.12 instead of §7.11), it
        # belongs in its primary domain section, not in a category about
        # real-time channels. Emit a single italic line and skip the rest
        # so the rendered report does not carry filler prose like "No
        # dedicated WebSocket security finding was derived". The mirror
        # logic already exists for §7.8 / §7.9 in the v1 path at line
        # ~3657; this is the v2 equivalent.
        if heading.startswith("7.12 "):
            domain_links = _v2_finding_links(threats, heading, max_links=1)
            if not domain_links:
                # LOCKED marker is the renderer agent's signal to leave the
                # stub alone. Without it, the LLM tends to "improve" the
                # one-liner by acknowledging tools it sees in recon (e.g.
                # socket.io in package.json), which defeats the whole point
                # of collapsing this section to one line.
                lines.append(
                    "<!-- §7.12 LOCKED — mechanically derived from absence "
                    "of real-time findings. Renderer must not rewrite the "
                    "line below. -->"
                )
                lines.append(
                    "_Not applicable — no real-time / WebSocket findings "
                    "routed to this category, and no AI/LLM, GraphQL, or "
                    "gRPC surfaces detected by the recon scan. Controls "
                    "catalogued elsewhere (container hardening, dependency "
                    "determinism) are covered in their primary §7 sections._"
                )
                lines.append("")
                continue

        section_controls = _v2_controls_for_heading(controls, heading)
        control_names = [
            (c.get("control") or c.get("name") or c.get("domain") or "").strip()
            for c in section_controls
        ]
        control_names = [name for name in control_names if name]
        implemented = [
            (c.get("implementation") or "").strip()
            for c in section_controls
            if (c.get("implementation") or "").strip()
        ]

        lines.append("**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->")
        lines.append("")
        if control_names:
            # R5 — `**Controls covered:**` is mechanically derived from
            # security_controls[].control + the H4 subcontrol headings.
            # LLM authoring tends to drop the markdown link wrapper or
            # invent new subcontrol names; the LOCKED marker is a sentinel
            # for QA + renderer prompt: do not re-author this line.
            #
            # Use the FRIENDLY title (same as the H4 heading text below) for
            # both the link text and the anchor slug so the QA
            # control_subsection_coverage check sees a clean match. The side
            # anchor emitted above each H4 carries the un-friendly slug too,
            # so older external references like `#input-validation` continue
            # to resolve.
            linked_controls = ", ".join(
                f"[{_friendly_subcontrol_title(name)}](#{_v2_slug(_friendly_subcontrol_title(name))})"
                for name in control_names[:8]
            )
            lines.append("<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->")
            lines.append(f"**Controls covered:** {linked_controls}.")
        else:
            lines.append("**Controls covered:** <!-- NARRATIVE_PLACEHOLDER: list concrete subcontrols as markdown links to H4 headings. -->")
        lines.append("")
        # R12 — `**Implemented controls:**` MUST open with a positive
        # inventory ("X, Y, Z are present.") and never with a negative
        # framing ("None adequately implemented" / "Missing"). Concrete
        # gaps belong in the Assessment block below. The pregenerator
        # builds this line from `security_controls[].implementation`
        # strings — the Stage-1 prompt is responsible for filling those
        # with positive descriptions. Empty inventory falls back to a
        # placeholder; the LLM must replace it with a positive inventory
        # line, NOT with a negative summary.
        if implemented:
            lines.append(f"**Implemented controls:** {'; '.join(implemented[:5])}.")
        else:
            lines.append("**Implemented controls:** <!-- NARRATIVE_PLACEHOLDER: positive inventory only — name the controls that ARE in place (e.g. \"Angular template escaping, Helmet noSniff/frameguard, multer file-size limit\"). Forbidden openers: \"None\", \"No \", \"Missing\", \"Not implemented\". Concrete gaps belong in the Assessment block. -->")
        lines.append("")
        lines.append(f"**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §{heading} — {hint} -->")
        lines.append("")

        if quick_depth and not control_names:
            continue

        if control_names:
            # Section-id for §7.X.N H4 numbering. `heading` is "7.X <Title>";
            # the first token gives the dotted section number used in the
            # H4 prefix `#### 7.X.N <subcontrol-title>`.
            section_id = heading.split(" ", 1)[0]
            # Track emitted H4 ordinal independently from the iteration index
            # so suppression (Fix 5 — _emit_v2_subcontrol_legacy returning
            # False) does not leave a gap in the numbering sequence.
            h4_idx = 0
            suppressed_names: list[str] = []
            for c, name in zip(section_controls[:8], control_names[:8]):
                # R9 — subcontrols[] expansion. When the security_controls[]
                # row carries subcontrols[] (Stage 1 populates these for
                # flow-like mechanisms — see phase-group-architecture.md
                # → "Subcontrols — required for flow-like mechanisms"),
                # emit one #### block per subcontrol with the canonical
                # reference-style depth:
                #
                #   #### 7.X.N <subcontrol.title>
                #   <implementation paragraph — plain language, positive case>
                #   ```mermaid sequenceDiagram ...
                #   **Security assessment**
                #   <assessment paragraph>
                #   ```ts code excerpt```
                #   **Relevant findings**
                #   - [F-NNN](#f-nnn)
                #
                # When subcontrols[] is empty, fall back to the legacy
                # single-block-per-control shape so older Stage-1 outputs
                # still produce a valid fragment. The legacy emitter returns
                # False to signal H4 suppression (effectiveness=Missing AND
                # no linked threats — nothing meaningful to anchor).
                subs = c.get("subcontrols") or []
                if subs:
                    for sub in subs[:9]:
                        h4_idx += 1
                        _emit_v2_subcontrol_block(
                            lines, sub, threats, heading,
                            section_id=section_id, idx=h4_idx,
                        )
                else:
                    next_idx = h4_idx + 1
                    emitted = _emit_v2_subcontrol_legacy(
                        lines, c, name, threats, heading,
                        section_id=section_id, idx=next_idx,
                    )
                    if emitted:
                        h4_idx = next_idx
                    else:
                        suppressed_names.append(name)
            if suppressed_names:
                # Surface the suppressed control names as a single line so
                # the user can see that the §7.x catalog item exists but
                # had no anchor-worthy detail.
                joined = ", ".join(suppressed_names)
                lines.append(
                    f"_Additional cataloged controls without a dedicated "
                    f"subsection (no implementation prose and no linked "
                    f"findings): {joined}._"
                )
                lines.append("")
        else:
            # M5b — Replace the generic "#### Controls To Confirm" fallback.
            # Reference §7 never carries an unnamed catch-all H4. Two cases:
            #   (a) no routed findings either → emit a single Not-applicable
            #       line and skip the H4 entirely (mirrors the reference's
            #       compact §7.12 "absent domain" handling);
            #   (b) findings routed but no security_controls[] catalogued →
            #       emit one H4 named after the section's principal mechanism
            #       so the reader sees what should have been there. The
            #       LLM is responsible for the positive intro paragraph and
            #       the security assessment via the placeholders below.
            links = _v2_finding_links(threats, heading, max_links=5)
            if not links:
                lines.append(
                    f"_Not applicable for this codebase — no controls or "
                    f"findings are routed to {heading}._"
                )
                lines.append("")
                continue
            default_mech_raw = _V2_DEFAULT_MECHANISM.get(heading, heading.split(" ", 1)[1])
            default_mech = _friendly_subcontrol_title(default_mech_raw)
            section_id = heading.split(" ", 1)[0]
            # Emit BOTH the un-friendly slug AND the friendly slug as side
            # anchors so `**Controls covered:**` link variants (LLM-filled
            # placeholder vs. mechanical) both resolve to this H4.
            for slug in sorted({_v2_slug(default_mech_raw), _v2_slug(default_mech)}):
                lines.append(f'<a id="{slug}"></a>')
            lines.append(f"#### {section_id}.1 {default_mech}")
            lines.append("")
            lines.append(
                "<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences in plain language. "
                "First sentence: what protection this control provides for the "
                "user, in business terms — no library, file, or route names. "
                "Second sentence: how the application implements it, naming the "
                "user-facing surface (e.g. 'authenticated endpoints', 'shopping "
                "basket routes', 'user profile pages') rather than file paths. "
                "Library / middleware / vendor names belong in the security-"
                "assessment block below, NOT in this implementation paragraph. "
                "POSITIVE-CASE only — what the mechanism does, not what is "
                "missing. -->"
            )
            lines.append("")
            lines.append("**Security assessment**")
            lines.append("")
            lines.append(
                "<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences. Open with one "
                "sentence in plain language describing what this codebase "
                "actually does or fails to do, then the concrete defects "
                "with file:line evidence. Library / middleware / vendor "
                "names are allowed here (this is the technical block), but "
                "should appear in the middle or end of the narrative, not "
                "as the first words. -->"
            )
            lines.append("")
            lines.append("**Relevant findings**")
            lines.append("")
            for link in links:
                lines.append(f"- {link}")
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

GENERATORS = {
    "system-overview.md": gen_system_overview,
    "architecture-diagrams.md": gen_architecture_diagrams,
    "assets.md": gen_assets,
    "attack-surface.md": gen_attack_surface,
    # use-cases.md retired 2026-05 — §6 gap intentional.
    "security-architecture.md": gen_security_architecture,
    "out-of-scope.md": gen_out_of_scope,
    # §3 Attack Walkthroughs — rendered deterministically from yaml + per-CWE
    # templates by `scripts/walkthrough_renderer.py`. The Stage 2 renderer
    # agent does NOT author this fragment any more; the §3 repair loop was
    # collapsed because the contract is now satisfied by construction.
    "attack-walkthroughs.md": gen_attack_walkthroughs,
    # Kept for one release as a deprecated transitional artifact — the
    # legacy renderer prompt has a fallback path that reads it. Removed in
    # the release after the deterministic flip lands.
    "_chain-skeleton.md": gen_attack_walkthroughs_skeleton,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pregenerate_fragments.py",
        description="Pre-generate the deterministic structural fragments.",
    )
    parser.add_argument("output_dir", type=Path, help="Assessment output directory (typically <repo>/docs/security).")
    parser.add_argument("--force", action="store_true", help="Overwrite existing fragments. Default is idempotent.")
    parser.add_argument(
        "--only", type=str, default="", help="Comma-separated fragment names to generate (default: all)."
    )
    parser.add_argument("--dry-run", action="store_true", help="Print intended actions without writing.")
    parser.add_argument(
        "--depth",
        type=str,
        default="",
        choices=["", "quick", "standard", "thorough"],
        help="Assessment depth (default: read from .skill-config.json or 'standard'). "
        "Quick depth strips NARRATIVE_PLACEHOLDERs from §7.4-§7.12 in "
        "security-architecture.md so the LLM has no expansion bait there.",
    )
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

    # Resolve depth: explicit --depth wins; otherwise read from
    # .skill-config.json so the skill propagates `--quick` automatically;
    # fall back to "standard" when neither is available.
    depth = (args.depth or "").strip().lower()
    # v2 13-section security-architecture layout is DEFAULT.
    # Resolution order:
    #   1. APPSEC_SECURITY_SCHEMA env-var (explicit override)
    #   2. APPSEC_SCHEMA_V1=1 env-var (legacy opt-out shortcut)
    #   3. .skill-config.json → security_schema
    #   4. default v2
    import os as _os
    _forced_schema = (_os.environ.get("APPSEC_SECURITY_SCHEMA") or "").strip().lower()
    if _forced_schema in {"v1", "v2"}:
        security_schema = _forced_schema
    elif _os.environ.get("APPSEC_SCHEMA_V1", "").strip() in ("1", "true", "yes", "on"):
        security_schema = "v1"
    else:
        security_schema = "v2"
    if not depth:
        cfg_path = output_dir / ".skill-config.json"
        if cfg_path.is_file():
            try:
                import json as _json

                cfg = _json.loads(cfg_path.read_text(encoding="utf-8"))
                depth = (cfg.get("assessment_depth") or "").strip().lower()
                # Only consult skill-config schema when env-var didn't already decide.
                if _forced_schema not in {"v1", "v2"} and not _os.environ.get("APPSEC_SCHEMA_V1", "").strip():
                    cfg_schema = (cfg.get("security_schema") or "").strip().lower()
                    if cfg_schema in {"v1", "v2"}:
                        security_schema = cfg_schema
            except (OSError, ValueError):
                depth = ""
    if depth not in {"quick", "standard", "thorough"}:
        depth = "standard"
    if security_schema not in {"v1", "v2"}:
        security_schema = "v2"

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
            # security-architecture takes a depth parameter (P2 — A5);
            # other generators have a (yaml_data) signature. When v2 is
            # active, dispatch to the 13-section control-category generator.
            if name == "security-architecture.md":
                if security_schema == "v2":
                    content = gen_security_architecture_v2(yaml_data, depth)
                else:
                    content = GENERATORS[name](yaml_data, depth)
            else:
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
