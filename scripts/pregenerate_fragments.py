#!/usr/bin/env python3
"""Deterministic pre-generator for the 6 structural fragments under
``$OUTPUT_DIR/.fragments/``.

Six of the eight REQUIRED_FRAGMENTS are pure structural projections of
``threat-model.yaml`` and the Phase-3-8 outputs:

  1. ``system-overview.md``         — meta + components prose
  2. ``architecture-diagrams.md``   — Mermaid C4 + Container + Component
  3. ``assets.md``                  — assets[] table
  4. ``attack-surface.md``          — attack_surface dict tables
  5. ``security-architecture.md``   — security_controls + 13 v2 sub-sections
  6. ``out-of-scope.md``            — meta.scope.out_of_scope (or default)

(``use-cases.md`` was retired in 2026-05; the §6 numbering gap is intentional.)

Pre-generating these takes 6 LLM Write tool-calls off the orchestrator's
Phase-11 budget. The remaining REQUIRED_FRAGMENTS are LLM-authored:

  8. ``ms-verdict.json``          — qualitative verdict
  +  ``attack-walkthroughs.md``   — narrative sequence diagrams

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
    cs = meta.get("component_selection") if isinstance(meta.get("component_selection"), dict) else None
    excluded = (cs or {}).get("excluded") or []
    if cs and excluded:
        # Components were narrowed to a STRIDE-analyzed subset — make the coverage
        # and the selection rationale explicit instead of implying every modeled
        # component was assessed equally.
        total = cs.get("total") or len(components)
        analyzed = cs.get("analyzed") or 0
        sel_names = [s.get("name") or s.get("id") for s in (cs.get("selected") or [])]
        exc_names = [e.get("name") or e.get("id") for e in excluded]
        # Distinct selection criteria actually triggered (truthful — only mention
        # ci-cd / crown-jewel etc. if a selected component matched on it).
        crit = []
        for s in cs.get("selected") or []:
            for r in s.get("reasons") or []:
                head = r.split(" (")[0].strip()
                if head and head not in crit:
                    crit.append(head)
        crit_clause = (" Selection criteria: " + "; ".join(crit) + ".") if crit else ""
        lines.append(
            f"{name} comprises **{total}** modeled components. This threat model applied full "
            f"STRIDE threat analysis to **{analyzed} of {total}** — the components on the "
            f"externally-reachable, authentication-bearing, and business-critical surface: "
            + ", ".join(f"**{n}**" for n in sel_names)
            + f".{crit_clause}"
        )
        lines.append("")
        lines.append(
            f"The remaining **{len(exc_names)}** component(s) were **not individually analyzed** at this "
            f"assessment depth (lower-priority / internal surface): "
            + ", ".join(exc_names)
            + ". Re-run at a higher `--assessment-depth` to extend STRIDE coverage to them."
        )
        lines.append("")
    else:
        lines.append(
            f"This threat model covers {len(components)} {'component' if len(components) == 1 else 'components'} of {name}: "
            + ", ".join(f"**{c.get('name', c.get('id', '?'))}**" for c in components)
            + "."
        )
        if cs and not excluded:
            lines.append("")
            lines.append(
                f"All {cs.get('total') or len(components)} modeled components received full STRIDE threat analysis."
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


def _arch_diagram_takeaways(
    name: str,
    components: list[dict],
    by_tier: dict[str, list[dict]],
    crit_counts: dict[str, int],
    high_counts: dict[str, int],
) -> dict[str, str]:
    """Deterministic, yaml-derived `**Key takeaway:**` sentences for each §2
    diagram (2.1–2.4).

    QA reviewer Check 8.0 requires every §2 Mermaid block to be followed by a
    `**Key takeaway:**` line. Historically the generator emitted none, so the
    check fired on every run and inserted a `_(QA: missing …)_` placeholder —
    which then either shipped verbatim (when the content-repair applier was
    broken) or required an LLM pass. Emitting a grounded baseline sentence here
    makes the check pass by construction; LLM enrichment may still overwrite
    these with richer prose.

    Sentences are grounded only in counts/threat tallies (no speculative
    control-absence claims, per the threat-model prose rules).
    """

    def _tc(c: dict) -> int:
        return len(c.get("threat_ids") or [])

    n_client = len(by_tier.get("client") or [])
    n_app = len(by_tier.get("application") or [])
    n_data = len(by_tier.get("data") or [])
    total_threats = sum(_tc(c) for c in components if isinstance(c, dict))

    top = max(
        (c for c in components if isinstance(c, dict)),
        key=_tc,
        default=None,
    )
    top_name = (top.get("name") or top.get("id")) if top else name
    top_n = _tc(top) if top else 0

    total_crit = sum(crit_counts.values()) if crit_counts else 0
    top_crit_id = max(crit_counts, key=crit_counts.get) if crit_counts else None
    top_crit_name = None
    if top_crit_id:
        top_crit_name = next(
            ((c.get("name") or c.get("id")) for c in components if isinstance(c, dict) and c.get("id") == top_crit_id),
            top_crit_id,
        )
    top_crit_n = crit_counts.get(top_crit_id, 0) if top_crit_id else 0

    # --- 2.1 System Context ---
    t21 = (
        f"Every actor in the context interacts with {name} through its external "
        "interface, so authentication and input validation at that edge govern "
        "the entire attack surface."
    )

    # --- 2.2 Container Architecture ---
    decomposition = f"{n_client} client, {n_app} application and {n_data} data unit(s)"
    if total_crit and top_crit_name:
        t22 = (
            f"The system decomposes into {decomposition}; {top_crit_name} carries "
            f"the most Critical findings ({top_crit_n}) and bounds the worst-case "
            "blast radius."
        )
    else:
        t22 = f"The system decomposes into {decomposition} connected by synchronous request paths."

    # --- 2.3 Components ---
    if top and top_n:
        t23 = (
            f"{top_name} concentrates the most findings ({top_n} of {total_threats} "
            "across all components); the table below maps each component to its "
            "source paths and linked threats."
        )
    else:
        t23 = "The table below maps each component to its source paths and linked threats."

    # --- 2.4 Technology Architecture ---
    if n_data:
        t24 = (
            f"The stack spans {n_data} data-tier store(s) behind the application "
            "tier; injection and data-at-rest exposure track the data tier, "
            "detailed per finding in [§8 Findings Register](#8-findings-register)."
        )
    else:
        t24 = (
            "The technology stack is consolidated in the application tier; "
            "per-finding detail is in [§8 Findings Register](#8-findings-register)."
        )

    return {"2.1": t21, "2.2": t22, "2.3": t23, "2.4": t24}


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
    # Pre-compute per-component Critical/High tallies once so both the §2.2
    # classDef highlighting and the per-diagram Key takeaway sentences share
    # the same source of truth.
    crit_counts, high_counts = _threat_counts_per_component(yaml_data)
    takeaways = _arch_diagram_takeaways(name, components, by_tier, crit_counts, high_counts)

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
    lines.append(f"**Key takeaway:** {takeaways['2.1']}")
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

    # crit_counts / high_counts pre-computed at the top of the function so the
    # classDef highlighting below and the §2 Key takeaways share one tally.

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
    lines.append(f"**Key takeaway:** {takeaways['2.2']}")
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
        "per-finding evidence is in [§8 Findings Register](#8-findings-register)."
    )
    lines.append("")
    lines.extend(_components_diagram_compact(yaml_data, by_tier))
    lines.append("")
    lines.append(f"**Key takeaway:** {takeaways['2.3']}")
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
    # tables duplicated the §2.3 component table and §8 Findings Register
    # without adding new signal. §2.4 is now pure technology-stack overview.
    lines.append("### 2.4 Technology Architecture")
    lines.append("")
    lines.append(
        "The technology stack the system is built on. Each box names the "
        "framework or runtime that fills that role; per-component findings "
        "live in the §2.3 component table above, and the full per-finding "
        "catalogue is in [§8 Findings Register](#8-findings-register)."
    )
    lines.append("")
    lines.extend(_technology_architecture_mermaid(yaml_data, components, boundaries))
    lines.append("")
    lines.append(f"**Key takeaway:** {takeaways['2.4']}")
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


def _select_external_actors_for_diagram(
    actor_labels: dict,
    attack_paths_data: dict | None = None,
    public_source_repo: bool = False,
) -> list[dict]:
    """Pick up to 3 external actors (1 attacker + 1 victim + 1 supply-
    chain repo when present) for the §2.3 EXT subgraph. Slugs come from
    `posture-actor-labels.yaml`; the heatmap uses the same data so the
    two views stay consistent.

    When ``public_source_repo`` is True the ``repo-read`` (Internal Developer)
    actor is folded away — anyone can clone public source, so the repo reader
    IS the anonymous internet attacker (mirrors
    ``compose_threat_model._collapse_public_repo_actors`` for the heatmap so
    both diagrams agree). 2026-05-31 actor-model decision.

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
    # heatmap, not `:::external` (gray). On a PUBLIC source repo it folds
    # into internet-anon (omitted here) so the §2.3 view matches the heatmap.
    if not public_source_repo:
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
    _public_repo = bool((yaml_data.get("meta") or {}).get("public_source_repo"))
    ext_actors = _select_external_actors_for_diagram(actor_labels, public_source_repo=_public_repo)

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
        # consistency with §8 Findings Register and the Top Findings table.
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
    ("data", "sqlite3", "SQLITE", "fa:fa-database", "SQLite", "embedded relational DB"),
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
        # Component `description` is curated architecture prose ("SQLite3 via
        # Sequelize ORM", "Node.js/TypeScript Express") and is the only place
        # the real engine/runtime/ORM is named for many repos — without it §2.4
        # collapses to ~4 generic nodes (2026-05-30 user report). It is safer
        # to scan than free-form threat scenarios: the compat-qualifier guard
        # in the matcher below rejects the "MongoDB-compatible / -style" noise.
        parts.append(str(c.get("description") or ""))
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
        # punctuation (".", "-", " "), which the regex treats literally. The
        # trailing negative lookahead rejects compatibility / vuln-class
        # qualifiers ("MongoDB-compatible", "MongoDB-style injection",
        # "Redis-like") so a description that merely *compares* to a tech
        # family does not emit a deployment node for it.
        pat = re.compile(
            r"(?:^|[^a-z0-9])"
            + re.escape(token_lc)
            + r"(?![a-z0-9])"
            + r"(?!\s*[-–]?\s*(?:compatible|style|like|based|inspired|esque|injection))"
        )
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


def _proportional_separator(*widths: int) -> str:
    """Build a GFM table separator row whose dash-runs encode RELATIVE column
    widths. GitHub ignores the run length (all columns content-sized), but
    Pandoc — the converter that produces the HTML/PDF deliverable — turns the
    relative dash lengths into explicit `<col style="width:N%">` so wide,
    link-stacked columns (Linked Threats / Notes) stop getting squished next
    to a long Description column (2026-05-30 user request)."""
    return "|" + "|".join("-" * max(3, w) for w in widths) + "|"


def gen_assets(yaml_data: dict) -> str:
    """## 4. Assets — single | Asset | table per contract."""
    assets = yaml_data.get("assets") or []
    lines = ["## 4. Assets", ""]
    lines.append(
        "Information assets and the classification level that drives the "
        "Confidentiality / Integrity / Availability targets used in [§8 Findings Register](#8-findings-register) risk scoring."
    )
    lines.append("")
    if not assets:
        lines.append("_No assets enumerated in threat-model.yaml._")
        lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    # Sort rows by data-classification severity (2026-05-31 user request) so the
    # most-sensitive assets lead the table, regardless of A-NNN allocation order.
    # Stable within a class — preserves the yaml/ID order for ties.
    def _classification_rank(a: dict) -> int:
        c = re.sub(r"[`*_]", "", (a.get("classification") or "")).strip().lower()
        order = {
            "restricted": 0,
            "secret": 0,
            "top secret": 0,
            "confidential": 1,
            "pii": 1,
            "sensitive": 1,
            "internal": 2,
            "private": 2,
            "public": 3,
        }
        for key, rank in order.items():
            if key in c:
                return rank
        return 4  # unknown / n/a sorts last

    assets = sorted(assets, key=_classification_rank)

    # Check whether any asset has linked_threats to decide if the column is needed
    any_linked = any(a.get("linked_threats") for a in assets)
    if any_linked:
        lines.append("| Asset | ID | Classification | Description | Linked Threats |")
        # Linked Threats ships `·`-joined BARE `[F-NNN](#f-nnn)` chips here;
        # compose's `_enrich_linked_id_cells` rewrites them to the canonical
        # `[F-NNN](#f-nnn) — title` stacked form (2026-06-02 user request —
        # supersedes the earlier bare-chip-only preference). Emitting bare IDs
        # keeps the short-title as a single source of truth in compose.
        lines.append(_proportional_separator(20, 6, 12, 40, 22))
    else:
        lines.append("| Asset | ID | Classification | Description |")
        lines.append(_proportional_separator(18, 6, 14, 40))
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
            # `·`-joined bare chips; compose's `_enrich_linked_id_cells` adds
            # the `— title` labels (2026-06-02 user request).
            lt_cell = " · ".join(f"[{t}](#{t.lower()})" for t in lt) if lt else "—"
            lines.append(f"| {name} | {aid} | {clazz} | {desc} | {lt_cell} |")
        else:
            lines.append(f"| {name} | {aid} | {clazz} | {desc} |")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Generator: attack-surface.md
# ---------------------------------------------------------------------------

_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "WS", "ALL"}


def _wrappable_route(route: str) -> str:
    """Insert zero-width break opportunities (U+200B) after URL separators so a
    long route wraps at sensible points inside its monospace table cell instead
    of forcing the Route column unreadably wide (user report 2026-06:
    `/this/page/is/hidden/behind/an/incredibly/high/paywall/…` blew the table
    out and crushed the more-important Findings column).

    ZWSP is invisible and a valid soft-wrap point in `white-space: normal` /
    `pre-wrap` — i.e. markdown previews, GFM, and the PDF/HTML export (whose
    print.css sets `td code{overflow-wrap:anywhere}`). Short routes are left
    untouched. The visible characters are unchanged; only break hints are added.
    """
    if len(route) <= 28:
        return route
    out: list[str] = []
    for ch in route:
        out.append(ch)
        if ch in "/.-_=&?:":
            out.append("\u200b")  # ZWSP soft-wrap point
    return "".join(out)


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


_CAMEL_WORD_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")
_WORD_SET_STOP = {"rest", "api", "http", "https", "ts", "js", "the"}


def _word_set(s: str) -> set[str]:
    """Split an identifier or path into its lowercase *words*, breaking on
    separators (``/ _ . : -``) AND camelCase boundaries, keeping words ≥ 3
    chars and dropping routing stop-words.

    ``b2bOrder`` → ``{b2b, order}``; ``/rest/order-history`` →
    ``{order, history}``; ``profileImageUrlUpload`` →
    ``{profile, image, url, upload}``. Word-level set comparison is what lets
    the attack-surface linker tell a genuine route↔handler match (``file-upload``
    ↔ ``fileUpload`` share both words) from a coincidental shared generic token
    (``order-history`` vs ``b2bOrder`` share only ``order``)."""
    if not s:
        return set()
    out: set[str] = set()
    for part in re.split(r"[/_.:\-]", s):
        for w in _CAMEL_WORD_RE.findall(part):
            wl = w.lower()
            if len(wl) >= 3 and wl not in _WORD_SET_STOP:
                out.add(wl)
    return out


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
        # Word-level signals (not raw substring). The previous substring branch
        # (`len(tok) >= 5 and (tok in base_norm or base_norm in tok)`) produced
        # the §5 false-positive class observed on 2026-06-04 juice-shop:
        #   `order`  ⊂ `b2bOrder`     → /rest/order-history → notevil RCE finding
        #   `login`  ⊂ `saveLoginIp`  → /rest/saveLoginIp   → login SQL-injection
        # A coincidental shared generic token was scoring the full +3. We now
        # award +3 only on a route↔handler signal that survives camelCase
        # splitting:
        #   (i)  the evidence basename names a whole route SEGMENT
        #        (`trackOrder.ts` ↔ `/rest/track-order`, `login.ts` ↔
        #         `/rest/user/login`, `fileUpload.ts` ↔ `/file-upload`), or
        #   (ii) the basename and the path share ≥ 2 independent words
        #        (`profileImageUrlUpload.ts` ↔ `/profile/image/url`).
        # `order-history` vs `b2bOrder` share only {order} and neither names the
        # other's segment → no bonus, the spurious link disappears.
        path_words = _word_set(path_clean)
        path_segs_norm = {_normalize_token(seg) for seg in path_clean.split("/") if len(_normalize_token(seg)) >= 4}
        for ev in threat.get("evidence") or []:
            if not isinstance(ev, dict):
                continue
            ev_file = (ev.get("file") or "").lstrip("/").lower()
            # Require the evidence file to live in a route-handler-style
            # directory. Without this gate, generic model files match
            # any path containing the model name.
            if not any(seg in ev_file for seg in _ROUTE_DIRS):
                continue
            base_no_ext = _FILE_EXT_STRIP.sub("", (ev.get("file") or "").split("/")[-1])
            base_norm = _normalize_token(base_no_ext)
            if len(base_norm) < 4:
                continue
            if base_norm in path_segs_norm or len(_word_set(base_no_ext) & path_words) >= 2:
                score += 3
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


# Human labels for the route-inventory `relevance_tags` (route_inventory.py).
# `management` is omitted on purpose — the Notes column already carries the
# "Management surface" token for those rows, so repeating it in the chip would
# duplicate. The tag is still used for the keep-decision below.
_RELEVANCE_LABELS = {
    "registration": "registration flow",
    "authentication": "auth/token endpoint",
    "missing-auth": "no auth guard detected",
    "missing-authz": "no authz guard detected",
}


def _entry_relevance_tags(entry: dict) -> list[str]:
    """The route-inventory display-relevance tags carried onto a §5 entry."""
    if not isinstance(entry, dict):
        return []
    return [t for t in (entry.get("relevance_tags") or []) if isinstance(t, str)]


def _relevance_chip(entry: dict) -> str:
    """A short '⚑ Review: …' note explaining why a finding-free row is listed.
    Empty string when the entry carries no displayable relevance reason."""
    labels: list[str] = []
    for t in _entry_relevance_tags(entry):
        lbl = _RELEVANCE_LABELS.get(t)
        if lbl and lbl not in labels:
            labels.append(lbl)
    if not labels:
        return ""
    return "⚑ Review: " + ", ".join(labels)


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
        (t.get("t_id") or t.get("id") or "").upper(): t for t in (yaml_data.get("threats") or []) if isinstance(t, dict)
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

    def _entry_rank(entry: dict) -> int:
        """Numeric highest-severity rank across linked threats (for sorting)."""
        worst = -1
        for ref in entry.get("linked_threats") or entry.get("threats") or []:
            if not isinstance(ref, str):
                continue
            t = threat_by_id.get(ref.strip().upper()) or {}
            sev = (t.get("risk") or t.get("severity") or t.get("impact") or "").strip().title()
            worst = max(worst, _sev_rank.get(sev, -1))
        return worst

    lines = ["## 5. Attack Surface", ""]
    lines.append(
        "Network-reachable entry points classified by authentication requirement. "
        "Each row links to the threat(s) referenced in its **Notes** column. The "
        "**Risk** column reflects the highest-severity linked finding. Entry points "
        "with no linked finding are still listed when they sit on a sensitive surface "
        "(authentication, registration, management) or look like a missing-auth/authz "
        "suspect — marked **⚑ Review** in Notes."
    )
    lines.append("")

    # When the deterministic route inventory feeds §5 (.route-inventory.json),
    # a real app can carry dozens-to-hundreds of entry points. Listing every
    # finding-free route bloats the report with low-signal rows. Above this
    # threshold we list only the entry points that carry a linked finding and
    # summarise the remainder with an explicit total — the full inventory still
    # ships in `.route-inventory.json` and (when exported) `pentest-tasks.yaml`.
    _SURFACE_ROW_CAP = 15

    def _emit_table(bucket_entries: list) -> None:
        # Four columns (Method | Route | Risk | Notes). The Auth requirement
        # is NOT a column — it is already stated by the §5.1 Unauthenticated /
        # §5.2 Authenticated subsection the table sits in, so a per-row Auth
        # cell would be 100% redundant (every §5.1 row "No", every §5.2 "Yes").
        #
        # Sort by risk descending, then relevance-flagged finding-free rows
        # before plain ones, then by route (contract §5 rule) so the highest-
        # signal entry points read first (2026-05-30 / 2026-06-11 requests).
        bucket_entries = sorted(
            bucket_entries,
            key=lambda e: (-_entry_rank(e), 0 if _entry_relevance_tags(e) else 1, _attack_surface_route(e).lower()),
        )
        # Large-inventory collapse: show finding-linked rows individually, AND
        # finding-free rows that carry a route-inventory relevance tag (auth /
        # registration / management / missing-auth/authz) — these are exactly
        # the "no finding yet, still worth a look" entry points a reader needs
        # to see (2026-06-11 request). Everything else is summarised as a total.
        keep = [e for e in bucket_entries if _entry_rank(e) >= 0 or _entry_relevance_tags(e)]
        collapse = len(bucket_entries) > _SURFACE_ROW_CAP and len(keep) < len(bucket_entries)
        shown = keep if collapse else bucket_entries

        if shown:
            lines.append("| Method | Route | Risk | Notes |")
            # Narrow Method/Risk; give Route some room and Notes (stacked finding
            # links + prose) the widest allocation so it reads cleanly.
            lines.append(_proportional_separator(7, 24, 9, 44))
            for entry in shown:
                method = _attack_surface_method(entry)
                route = _attack_surface_route(entry)
                risk_lbl = _entry_risk(entry)
                notes = _attack_surface_notes(entry)
                # For a finding-free row, append the review chip so the reader
                # knows WHY a row with no linked finding is listed.
                if _entry_rank(entry) < 0:
                    chip = _relevance_chip(entry)
                    if chip:
                        notes = f"{notes}<br/>_{chip}_" if notes else f"_{chip}_"
                lines.append(f"| {method} | `{_wrappable_route(route)}` | {risk_lbl} | {notes} |")

        omitted = len(bucket_entries) - len(shown)
        if omitted > 0:
            if shown:
                lines.append("")
            lines.append(
                f"_{omitted} further entry point(s) in this category carry no linked finding "
                f"and no elevated review signal, and are not listed individually "
                f"({len(bucket_entries)} total). The complete route inventory is available in "
                f"`.route-inventory.json` and, when exported, `pentest-tasks.yaml`._"
            )

    lines.append(f"### 5.1 Unauthenticated Entry Points ({len(unauth)})")
    lines.append("")
    if unauth:
        _emit_table(unauth)
    else:
        lines.append("_None enumerated._")
    lines.append("")

    lines.append(f"### 5.2 Authenticated Entry Points ({len(auth)})")
    lines.append("")
    if auth:
        _emit_table(auth)
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
# Generator: out-of-scope.md
# ---------------------------------------------------------------------------


def gen_out_of_scope(yaml_data: dict) -> str:
    """## 11. Out of Scope — pulls from meta.scope.out_of_scope or default,
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

    lines = ["## 11. Out of Scope", ""]
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
        "the",
        "a",
        "an",
        "of",
        "in",
        "on",
        "at",
        "to",
        "for",
        "by",
        "via",
        "and",
        "or",
        "but",
        "with",
        "from",
        "into",
        "is",
        "be",
        "are",
        "was",
        "this",
        "that",
        "these",
        "those",
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

    NOTE (§3.1 retired): the §3.1 Attack Chain Overview was removed — the
    cross-finding view is the `## Critical Attack Tree`. §3 is now produced
    deterministically by `gen_attack_walkthroughs` (per-Critical walkthroughs
    only) and no agent consumes `_chain-skeleton.md` any more. This helper now
    mirrors the deterministic generator so it can never reintroduce §3.1; the
    legacy chain-skeleton body below is retained, unreachable, for history.
    """
    return gen_attack_walkthroughs(yaml_data)

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
        "they are documented in [§8 Findings Register](#8-findings-register) "
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
        "in [§8 Findings Register](#8-findings-register) and is linked back "
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
        out.append("_No Critical or High findings present — the chain overview is empty for this assessment._")
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
        cwe_norm = (
            cwe_raw if cwe_raw.upper().startswith("CWE-") else (f"CWE-{cwe_raw}" if cwe_raw.isdigit() else cwe_raw)
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
        out.append("The diagram contrasts the current vulnerable behaviour with the post-mitigation state:")
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
            '"sensitive data exposed". -->'
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
            f"- [§8 Findings Register entry for {vid}](#{vid.lower()}) — "
            "evidence, classification, full mitigation list."
        )
        out.append("- <!-- WALKTHROUGH_FILL: §3.1 chain that uses this finding (e.g. `[Chain 2](#chain-2-...)`) -->")
        out.append("- <!-- WALKTHROUGH_FILL: related §3.x walkthroughs that share findings or actors -->")
        out.append("")

    return "\n".join(out) + "\n"


# Lightweight CWE → class label table for the pregenerator. Kept in sync
# manually with `_CWE_CLASS_NAMES` in scripts/compose_threat_model.py.
_PREGEN_CWE_CLASS_NAMES = {
    "CWE-22": "Path Traversal",
    "CWE-23": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting",
    "CWE-87": "Cross-Site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Server-Side Template Injection",
    "CWE-200": "Information Disclosure",
    "CWE-269": "Improper Privilege Management",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-290": "Authentication Bypass by Spoofing",
    "CWE-294": "Authentication Bypass by Capture-Replay",
    "CWE-307": "Missing Rate Limiting (Brute-Force)",
    "CWE-312": "Cleartext Storage of Sensitive Data",
    "CWE-321": "Hardcoded Cryptographic Key",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-328": "Use of Weak Hash",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-434": "Unrestricted File Upload",
    "CWE-548": "Directory Listing Exposure",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-620": "Unverified Password Change",
    "CWE-639": "Insecure Direct Object Reference (IDOR)",
    "CWE-693": "Missing Defense-in-Depth Control",
    "CWE-798": "Hardcoded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-922": "Insecure Storage of Sensitive Information",
    "CWE-942": "Permissive Cross-Origin (CORS) Policy",
    "CWE-943": "NoSQL Injection",
    "CWE-1021": "Improper Restriction of UI Rendering Layers (Clickjacking)",
    "CWE-1104": "Use of Unmaintained Third-Party Components",
    "CWE-1321": "Prototype Pollution",
}


def _normalize_security_controls(raw: list) -> list[dict]:
    """Coerce ``security_controls`` to dictionaries for §7 rendering."""
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


# ---------------------------------------------------------------------------
# Schema v2 — 13-section §7 control-category layout
# ---------------------------------------------------------------------------

_V2_SUBSECTIONS: tuple[tuple[str, str, str], ...] = (
    # (heading, narrative_hint_for_llm, tier). Tier is retained for backward
    # compatibility with older composer logic; current v2 emits every section.
    (
        "7.1 Security Control Overview",
        "Overview matrix: Control category, Verdict, Main reason. No control IDs and no finding-ID columns.",
        "a",
    ),
    (
        "7.2 Identity and Authentication Controls",
        "Registration, password login, OAuth/OIDC adapters, MFA/TOTP, JWT issuance "
        "and verification, password reset/change.",
        "a",
    ),
    (
        "7.3 Session and Token Controls",
        "Browser token storage, request propagation, token lifetime, revocation, cookie/session boundary.",
        "a",
    ),
    (
        "7.4 Authorization Controls",
        "Route middleware, role checks, object-level authorization, client-side guards versus server-side enforcement.",
        "a",
    ),
    (
        "7.5 Query Construction and Data Access Controls",
        "SQL/NoSQL query construction, ORM usage, parameter binding, selector and object ownership boundaries.",
        "a",
    ),
    (
        "7.6 Input Boundary Validation Controls",
        "Request schemas, parser limits, upload constraints, URL/path validation, business-rule boundaries.",
        "a",
    ),
    (
        "7.7 Output Encoding and Rendering Controls",
        "Template escaping, DOM sinks, sanitizer bypasses, HTML rendering contexts.",
        "a",
    ),
    (
        "7.8 Browser and Cross-Origin Controls",
        "CSP, CORS, CSRF, Helmet/header hardening, browser-side request policy.",
        "a",
    ),
    (
        "7.9 Cryptography Secrets and Data Protection",
        "Signing keys, HMAC/cookie secrets, password storage, data-at-rest protection.",
        "a",
    ),
    (
        "7.10 File Parser and Outbound Request Controls",
        "Uploads, archives, XML parsing, unsafe interpreters, SSRF, redirects, static or management-surface exposure.",
        "a",
    ),
    (
        "7.11 Operations Runtime and Supply Chain Controls",
        "Audit logging, runtime/container hardening, dependency determinism, CI "
        "workflow permissions, package-install controls.",
        "a",
    ),
    (
        "7.12 Real-time and Not Applicable Controls",
        "WebSocket/real-time channels plus compact absent-domain statements.",
        "a",
    ),
    ("7.13 Defense-in-Depth Summary", "Cross-cutting summary of layered controls and residual architecture risk.", "a"),
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
    "7.6 Input Boundary Validation Controls": "Validation Approach",
    "7.7 Output Encoding and Rendering Controls": "Output Encoding and Client-Side Rendering",
    "7.8 Browser and Cross-Origin Controls": "Browser Security Headers and CORS/CSRF Posture",
    "7.9 Cryptography Secrets and Data Protection": "Secret Management and Data Protection",
    "7.10 File Parser and Outbound Request Controls": "File Parser and Outbound Request Handling",
    "7.11 Operations Runtime and Supply Chain Controls": "Logging, Runtime and Supply Chain Posture",
    "7.12 Real-time and Not Applicable Controls": "Real-time WebSocket Channel",
}


# §7.6 general validation-approach heading detector. Mirrors the contract's
# `validation_approach_first.approach_heading_patterns` so the pregenerator
# does not double-inject when Stage-1 already supplied an approach-named row.
_V2_APPROACH_FIRST_RE = re.compile(
    r"(?i)\b(validation approach|validation strategy"
    r"|(input )?validation (model|architecture|posture)"
    r"|(central|centralized|centralised|schema)[- ]?based validation"
    r"|schema validation)\b"
)


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


def _render_threat_hypotheses_table(yaml_data: dict) -> list[str]:
    """Render the §7.2 validation table for unpromoted architecture hypotheses."""
    hypotheses = yaml_data.get("threat_hypotheses") or []
    unpromoted = [h for h in hypotheses if isinstance(h, dict) and not h.get("promoted_threat_id")]
    if not unpromoted:
        return []

    lines: list[str] = [
        "#### Threat Hypotheses Requiring Validation",
        "",
        (
            "_Architecture- and control-derived threats. Plausible but not yet "
            "source-to-sink proven; each entry needs a `validate-or-refute` "
            "pentest probe before it becomes a finding._"
        ),
        "",
        "| ID | Hypothesis | Control Gap | Evidence | Validation |",
        "|---|---|---|---|---|",
    ]
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
    return lines


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
        "missing": "Missing",
        "weak": "Weak",
        "partial": "Partial",
        "adequate": "Adequate",
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
        "identity",
        "iam",
        "authentication",
        "identity-auth",
        "login",
        "password-login",
        "jwt-issu",
        "oauth-adapter",
        "oidc-adapter",
        "totp",
        "mfa",
        "2fa",
        "registration",
    ),
    "7.3 Session and Token Controls": (
        "session",
        "token-storage",
        "cookie",
        "localstorage",
        "browser-storage",
    ),
    "7.4 Authorization Controls": (
        "authorization",
        "access-control",
        "rbac",
        "object-level",
        "ownership",
    ),
    "7.5 Query Construction and Data Access Controls": (
        "query",
        "sql",
        "nosql",
        "orm",
        "data-access",
    ),
    "7.6 Input Boundary Validation Controls": (
        "input-validation",
        "schema-validation",
        "upload-validation",
        "request-body",
        "parser-limit",
        "rate-limiting",
    ),
    "7.7 Output Encoding and Rendering Controls": (
        "output-encoding",
        "render",
        "xss",
        "sanit",
        "dom-sanit",
    ),
    "7.8 Browser and Cross-Origin Controls": (
        "browser",
        "csp",
        "cors",
        "csrf",
        "helmet",
        "security-headers",
        "cors-csrf",
    ),
    "7.9 Cryptography Secrets and Data Protection": (
        "crypto",
        "cryptography",
        "secret-manag",
        "secrets-manag",
        "key-manag",
        "kms",
        "hash",
        "password-storage",
        "password hashing",
        "encryption",
        "data-protection",
    ),
    "7.10 File Parser and Outbound Request Controls": (
        "file-security",
        "file-parser",
        "xml-parser",
        "archive",
        "ssrf",
        "redirect-allow",
    ),
    "7.11 Operations Runtime and Supply Chain Controls": (
        "audit",
        "logging-monitor",
        "logging-monitoring",
        "runtime",
        "container",
        "dependency",
        "supply-chain",
        "ci-cd",
    ),
    "7.12 Real-time and Not Applicable Controls": (
        "websocket",
        "real-time",
        "socket.io",
        "ai-llm",
        "llm",
        "graphql",
        "grpc",
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
        # Exact canonical-title match FIRST. Stage 1 writes the §7 section's
        # human-readable title verbatim as the control's domain (e.g. "File
        # Parser and Outbound Request Controls"); match it against each
        # heading minus its "7.X " number prefix. This is collision-free,
        # unlike the hyphenated hint substrings — `_V2_CONTROL_HINTS` uses
        # tokens like `file-parser` / `upload-validation` that never match a
        # space-form domain, so a control whose NAME also carries no hint
        # token (e.g. "File Upload Validation") used to route to NO section
        # and was dropped from §7 entirely (juice-shop 2026-06-01 §7.10 "no
        # #### found"). It also avoids the substring trap where the §7.4 hint
        # `access-control` matches the §7.5 domain "...Data Access Controls".
        for heading in _V2_HEADING_ORDER:
            title = re.sub(r"^\d+(?:\.\d+)*\s+", "", heading).strip().lower()
            if title and title == domain:
                return heading
        # Fall back to hint substring matching for partial / non-canonical
        # domains (older yamls, shorthand). Unchanged space-form behaviour.
        for heading in _V2_HEADING_ORDER:
            hints = _V2_CONTROL_HINTS.get(heading, ())
            if any(h in domain for h in hints):
                return heading
    haystack = " ".join(str(c.get(k) or "").lower() for k in ("control", "name", "implementation"))
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
    return [c for c in (controls or []) if isinstance(c, dict) and _v2_canonical_section_for_control(c) == heading]


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
    "Query Construction": "Database Query Construction",
    "Output Encoding": "Output Encoding and Escaping",
    "Container Hardening": "Container Runtime Hardening",
    "Secret Management": "Secret and Key Management",
    "Input Validation": "Request Input Validation",
    # 2026-05 (user-request point 4): align §7 H4 titles with OWASP ASVS
    # vocabulary so that "JWT authentication" reads as the token-mechanism
    # it actually is, and "Route-level auth middleware" disambiguates as
    # Authorization (the Z) rather than Authentication. Each replacement
    # keeps the original term in parens so existing cross-refs that grep
    # for "JWT" / "DomSanitizer" / etc. still find their target.
    "JWT authentication": "Token-Based Session Authentication (JWT)",
    "JWT authentication (RS256)": "Token-Based Session Authentication (JWT, RS256)",
    "Password hashing": "Password Hashing and Credential Storage",
    "Route-level auth middleware": "Route-Level Authorization Middleware",
    "Route-level auth middleware (isAuthorized)": "Route-Level Authorization Middleware (isAuthorized)",
    "ORM parameterized queries": "Parameterized ORM Queries",
    "Request body validation": "Request Body Schema Validation",
    "Request rate limiting": "Authentication Rate Limiting",
    "Angular DomSanitizer": "Client-Side Output Sanitization (Angular DomSanitizer)",
    "HTTP security headers": "HTTP Security Headers (Helmet)",
    "HTTP security headers (Helmet)": "HTTP Security Headers (Helmet)",
    "Cross-origin resource sharing policy": "Cross-Origin Resource Sharing (CORS) Policy",
    "Access logging": "Application Access Logging",
    "JWT stored in localStorage": "JWT Storage in Browser localStorage",
    "Secrets and key management": "Secret and Key Management",
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


_V2_STATUS_TOKENS = {
    "adequate": "🟢 Adequate",
    "partial": "🟡 Partial",
    "weak": "🟠 Weak",
    "unsafe": "🔴 Unsafe",
    "missing": "🔴 Missing",
    "not_applicable": "—",
    "na": "—",
    "n/a": "—",
}


def _v2_status_line(eff: str, note: str = "") -> str:
    """Build the per-sub-control `**Status:**` badge line for §7 H4 blocks.

    The badge is the reader's at-a-glance verdict — it answers "is this
    sub-control a positive or a negative finding?" without making them read
    the whole assessment. `eff` is the control/subcontrol effectiveness;
    `note` is an optional one-clause bottom line.

      * `eff` unknown  → the LLM fills the whole line (icon + clause).
      * `eff` known, no note → the LLM fills only the trailing clause.
      * `eff` + note → fully deterministic.

    The line is placed immediately under the H4 heading; `check_section7_h4_
    positive_intro` skips a leading `**Status:**` line so the positive intro
    paragraph that follows is still the one validated.
    """
    token = _V2_STATUS_TOKENS.get((eff or "").strip().lower())
    if not token:
        return (
            "**Status:** <!-- NARRATIVE_PLACEHOLDER: choose one of "
            "`🟢 Adequate` / `🟡 Partial` / `🟠 Weak` / `🔴 Unsafe` / "
            "`🔴 Missing`, then add one clause stating the bottom line. "
            "present-but-broken → Unsafe; never-built → Missing. -->"
        )
    if note:
        return f"**Status:** {token} — {note}"
    return (
        f"**Status:** {token} — <!-- NARRATIVE_PLACEHOLDER: one clause — the "
        f"bottom line for this sub-control (what holds, or what is defeated "
        f"and how). -->"
    )


def _v2_lifecycle_bullets(subs: list, threats: list, heading: str) -> list[str]:
    """Render a grouped control's lifecycle stages as scannable bullets.

    Each stage bullet leads with the stage name in bold, its own Status
    token, a one-clause note, and the routed finding links — so a reader
    sees every stage's verdict in one pass before the prose assessment.
    """
    out: list[str] = []
    for sub in subs[:9]:
        name = (sub.get("title") or sub.get("name") or "Stage").strip()
        eff = (sub.get("effectiveness") or sub.get("status") or "").strip().lower()
        token = _V2_STATUS_TOKENS.get(eff, "")
        note = (sub.get("status_note") or sub.get("assessment") or "").strip()
        # Keep the bullet to a single clause — full prose belongs in the
        # control-level Security assessment block below the bullets.
        if note:
            note = note.split(". ")[0].rstrip(".") + "."
        raw_findings = sub.get("relevant_findings") or []
        if isinstance(raw_findings, str):
            raw_findings = [raw_findings]
        flinks = []
        for entry in raw_findings[:4]:
            tid = entry.get("id") if isinstance(entry, dict) else entry
            if isinstance(tid, str) and tid.strip():
                fid = _to_canonical_finding_label(tid)
                flinks.append(f"[{fid}](#{fid.lower()})")
        tail = f" → {', '.join(flinks)}" if flinks else ""
        prefix = f"**{name}** — {token}." if token else f"**{name}** —"
        body = (
            f" {note}"
            if note
            else (" <!-- NARRATIVE_PLACEHOLDER: one clause: what this stage does / where it breaks. -->")
        )
        out.append(f"- {prefix}{body}{tail}")
    return out


def _emit_v2_grouped_control(
    lines: list, c: dict, subs: list, threats: list, heading: str, section_id: str = "", idx: int = 0
) -> None:
    """Emit ONE H4 that folds a control's lifecycle stages into bullets.

    Used when a `security_controls[]` row sets `group_subcontrols: true`
    (or `kind: lifecycle`) — e.g. "Password-Based Authentication" with its
    Login / Registration / Reset / Change / Storage stages. The stages
    render as a bulleted lifecycle under one heading rather than as peer
    H4s, which is the structure the `auth_method_decomposition` gate itself
    recommends (fold aspects as bullets, not peer headings) and which keeps
    the shared root cause (one hashing primitive, one query path) visible in
    one place.
    """
    name = (c.get("control") or c.get("name") or c.get("domain") or "Control").strip()
    title = _friendly_subcontrol_title(name)
    if section_id and idx:
        lines.append("".join(f'<a id="{s}"></a>' for s in sorted({_v2_slug(name), _v2_slug(title)})))
        lines.append(f"#### {section_id}.{idx} {title}")
    else:
        lines.append(f"#### {title}")
    lines.append("")
    lines.append(
        _v2_status_line(
            (c.get("effectiveness") or "").strip(),
            (c.get("effectiveness_reason") or c.get("status_note") or "").strip(),
        )
    )
    lines.append("")
    impl = (c.get("implementation") or "").strip()
    if impl:
        lines.append(impl)
    else:
        lines.append(
            "<!-- NARRATIVE_PLACEHOLDER: 1-2 sentences naming the shared "
            "mechanism this control family routes through (e.g. one hashing "
            "primitive, one query path) — POSITIVE-CASE, no gaps yet. The "
            "lifecycle bullets below carry the per-stage verdicts. -->"
        )
    lines.append("")
    # Per-flow diagram — the grouped block represents a multi-step auth flow
    # (e.g. the password login path). The schema_v2 auth_method_decomposition
    # gate (flow_methods_require_diagram) requires a `sequenceDiagram` on any
    # §7.2 flow block, and "Password-Based Authentication" matches the
    # `password-based` flow token. Emit the diagram from Stage-1 data when
    # present, else a fill-me placeholder so the scaffold satisfies the gate.
    diag = (c.get("sequence_diagram") or "").strip()
    if diag:
        lines.append("The diagram shows the primary login flow for this mechanism:")
        lines.append("")
        lines.append("```mermaid")
        lines.append(diag)
        lines.append("```")
        lines.append("")
    elif heading.startswith("7.2 "):
        lines.append(
            "<!-- NARRATIVE_PLACEHOLDER: precede with one sentence ending in "
            "`:` then a positive-flow ```mermaid sequenceDiagram``` of the "
            "primary login path (User → App → credential store → session "
            "issuance). One diagram for the whole lifecycle is enough — the "
            "per-stage detail stays in the bullets below. -->"
        )
        lines.append("")
    bullets = _v2_lifecycle_bullets(subs, threats, heading)
    if bullets:
        lines.extend(bullets)
        lines.append("")
    lines.append("**Security assessment**")
    lines.append("")
    assess = (c.get("assessment") or "").strip()
    if assess:
        lines.append(assess)
    else:
        lines.append(
            "<!-- NARRATIVE_PLACEHOLDER: 2-4 sentences (or a short bullet "
            "list when there are ≥2 discrete weaknesses). Name the shared "
            "root cause and the most important code paths with file:line "
            "evidence. The per-stage detail is in the bullets above. -->"
        )
    lines.append("")
    lines.append("**Relevant findings**")
    lines.append("")
    # Aggregate findings across stages, de-duplicated, preserving order.
    seen: set[str] = set()
    agg: list[str] = []
    for sub in subs:
        raw = sub.get("relevant_findings") or []
        if isinstance(raw, str):
            raw = [raw]
        for entry in raw:
            tid = entry.get("id") if isinstance(entry, dict) else entry
            if isinstance(tid, str) and tid.strip():
                fid = _to_canonical_finding_label(tid)
                if fid not in seen:
                    seen.add(fid)
                    agg.append(f"[{fid}](#{fid.lower()})")
    if not agg:
        agg = _v2_finding_links(threats, heading, max_links=4)
    if agg:
        for link in agg:
            lines.append(f"- {link}")
    else:
        lines.append("- No dedicated finding routed in this assessment.")
    lines.append("")


def _emit_v2_subcontrol_block(
    lines: list, sub: dict, threats: list, heading: str, section_id: str = "", idx: int = 0
) -> None:
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
        # All anchors on ONE line: stacked empty <a id> lines render with
        # inconsistent vertical gaps before a heading (1 vs 2 anchors → uneven
        # whitespace, 2026-05-30 user "Freiräume" fix).
        lines.append("".join(f'<a id="{s}"></a>' for s in sorted(anchors)))
        lines.append(f"#### {section_id}.{idx} {title}")
    else:
        lines.append(f"#### {title}")
    lines.append("")
    lines.append(
        _v2_status_line(
            (sub.get("effectiveness") or sub.get("status") or "").strip(),
            (sub.get("status_note") or sub.get("effectiveness_reason") or "").strip(),
        )
    )
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
_FLOW_LIKE_TOKENS = frozenset(
    {
        "registration",
        "login",
        "oauth",
        "oidc",
        "openid",
        "saml",
        "sso",
        "totp",
        "2fa",
        "mfa",
        "passkey",
        "webauthn",
        "reset",
        "change",
        "issuance",
        "verification",
        "magic-link",
        "magic",
        "mtls",
        "webhook",
        "handshake",
        "ceremony",
    }
)


def _is_flow_like_control(name: str) -> bool:
    """Token-match a control name against the flow-like mechanism set."""
    tokens = set(re.findall(r"[a-z0-9]+", (name or "").lower()))
    return bool(tokens & _FLOW_LIKE_TOKENS)


def _emit_v2_subcontrol_legacy(
    lines: list, c: dict, name: str, threats: list, heading: str, section_id: str = "", idx: int = 0
) -> bool:
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
    # A "Missing" control whose OWN linked_threats is empty is still worth an
    # H4 when findings route to this §7 category via CWE: the reader needs to
    # see the absent control next to the findings it would have blocked, and
    # qa_checks.check_control_subsection_coverage requires a #### per populated
    # category (a category with catalogued controls but zero H4 trips the
    # strict gate → the recurring §7 REPAIR_MODE loop). Only suppress when
    # there is genuinely nothing to anchor — no own links, no implementation
    # prose, AND no CWE-routed finding for this section.
    routed_here = _v2_finding_links(threats, heading, max_links=1)
    if eff == "missing" and not linked and not impl_text and not routed_here:
        return False

    title = _friendly_subcontrol_title(name)
    # Emit BOTH the original-name slug AND the friendly-title slug as side
    # anchors so links from `**Controls covered:**` resolve regardless of
    # which spelling the upstream link-builder chose. The numbered heading
    # itself slugifies differently (e.g. `#721-jwt-authentication`); the
    # side anchors close that gap.
    if section_id and idx:
        anchors = {_v2_slug(name), _v2_slug(title)}
        # All anchors on ONE line: stacked empty <a id> lines render with
        # inconsistent vertical gaps before a heading (1 vs 2 anchors → uneven
        # whitespace, 2026-05-30 user "Freiräume" fix).
        lines.append("".join(f'<a id="{s}"></a>' for s in sorted(anchors)))
        lines.append(f"#### {section_id}.{idx} {title}")
    else:
        lines.append(f"#### {title}")
    lines.append("")
    lines.append(
        _v2_status_line(
            eff,
            (c.get("effectiveness_reason") or c.get("status_note") or "").strip(),
        )
    )
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


# ---------------------------------------------------------------------------
# §7.2 Authentication Mechanisms inventory (2026-05-31 — deterministic).
#
# schema_v2 catalogues controls by domain — identity/login → §7.2,
# session/token (JWT) → §7.3, password hashing → §7.9 — so the §7.2 section
# only ever decomposes the control(s) Stage-1 filed under the identity domain
# (usually just "Password Login"). That made §7.2 read "ausgedünnt": OAuth /
# JWT / MFA were either elsewhere or absent. This inventory is a DETERMINISTIC
# table emitted at the top of §7.2 that reconstructs the COMPLETE authentication
# surface from the yaml (controls + threats + meta) — status, where it is
# assessed (§7.2/§7.3/§7.9), and linked findings — independent of the LLM
# scaffold-fill. Mechanisms checked but absent are named in a trailing note so
# "no OAuth" is explicit, not silent. Built from data + frozen → an LLM author
# cannot thin it out on a later run. That is the whole point.
# ---------------------------------------------------------------------------

# `section` = the §7 subsection where the mechanism's controls are catalogued
# (drives the "Assessed in" link). `control_kw` / `threat_kw` are lowercase
# substrings matched against control name+domain / threat title+cwe. `meta_flag`
# marks the mechanism present from a meta boolean alone.
_AUTH_MECHANISM_SPECS: list[dict] = [
    {
        "name": "User registration",
        "section": "7.2",
        "control_kw": ["registration", "sign-up", "signup"],
        "threat_kw": [
            "registration",
            "register",
            "sign-up",
            "signup",
            "role field",
            "mass assignment",
            "mass-assignment",
        ],
        "meta_flag": "open_user_registration",
    },
    {
        "name": "Password login",
        "section": "7.2",
        "control_kw": ["password authentication", "password-based", "password login", "login"],
        "threat_kw": [
            "login authentication bypass",
            "credential stuffing",
            "brute force",
            "brute-force",
            "authentication bypass",
        ],
    },
    {
        "name": "Password reset / change",
        "section": "7.2",
        "control_kw": ["password reset", "password change", "forgot password"],
        "threat_kw": [
            "password reset",
            "reset-password",
            "reset password",
            "password change",
            "forgot password",
            "security question",
            "security-question",
        ],
    },
    {
        "name": "Password storage (hashing)",
        "section": "7.9",
        "control_kw": ["password hashing", "credential storage", "hashing"],
        "threat_kw": ["md5", "password hash", "unsalted", "bcrypt", "scrypt", "argon2"],
    },
    {
        "name": "JWT / bearer-token session",
        "section": "7.3",
        "control_kw": ["jwt", "session token validation", "bearer", "token validation"],
        "threat_kw": ["jwt", "json web token", "bearer token", "alg:none", "algorithm confusion", "token forgery"],
    },
    {
        "name": "Session-token storage",
        "section": "7.3",
        "control_kw": ["session token storage", "token storage"],
        "threat_kw": ["localstorage", "local storage", "session theft", "token stored", "httponly"],
    },
    {
        "name": "Multi-factor authentication (TOTP / 2FA)",
        "section": "7.2",
        "control_kw": ["totp", "2fa", "mfa", "multi-factor", "multi factor", "two-factor", "two factor"],
        "threat_kw": ["totp", "2fa", "two-factor", "two factor", "mfa", "multi-factor", "one-time password"],
    },
    {
        "name": "OAuth / OIDC federated login",
        "section": "7.2",
        "control_kw": ["oauth", "oidc", "openid", "sso", "saml", "federated", "social login"],
        "threat_kw": ["oauth", "oidc", "openid", "saml", "single sign-on", "social login"],
    },
]

_AUTH_INV_SECTION_TITLES = {
    "7.2": "7.2 Identity and Authentication Controls",
    "7.3": "7.3 Session and Token Controls",
    "7.9": "7.9 Cryptography Secrets and Data Protection",
}

_AUTH_INV_EFFECTIVENESS_BADGE = {
    "adequate": "🟢 Adequate",
    "partial": "🟡 Partial",
    "weak": "🟠 Weak",
    "unsafe": "🔴 Unsafe",
    "missing": "🔴 Missing",
}
_AUTH_INV_EFFECTIVENESS_RANK = {"adequate": 0, "partial": 1, "weak": 2, "unsafe": 3, "missing": 3}
_AUTH_INV_RISK_BADGE = {"critical": "🔴 Critical", "high": "🟠 High", "medium": "🟡 Medium", "low": "🟢 Low"}
_AUTH_INV_RISK_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _auth_mech_finding_link(threat: dict) -> str | None:
    raw = (threat.get("id") or threat.get("t_id") or "").strip()
    m = re.search(r"(\d+)$", raw)
    if not m:
        return None
    n = int(m.group(1))
    # Carry the finding TITLE, not a bare ID — the §7.2 inventory is a table,
    # so compose's prose-linkifier never enriches it, leaving "leer betitelt"
    # links (2026-06-02 user report). Per the no-bare-ID rule every F-ref must
    # show a short title. Use the finding's own title (already concise:
    # "<weakness> via <surface>").
    title = (threat.get("title") or "").strip()
    link = f"[F-{n:03d}](#f-{n:03d})"
    return f"{link} — {title}" if title else link


def _build_auth_mechanism_inventory(yaml_data: dict) -> list[str]:
    """Deterministic §7.2 'Authentication mechanisms' inventory block (markdown
    lines). Returns [] when no auth mechanism is present at all."""
    threats = yaml_data.get("threats") or []
    controls = _normalize_security_controls(yaml_data.get("security_controls"))
    meta = yaml_data.get("meta") or {}

    def _ctrl_blob(c: dict) -> str:
        return f"{c.get('control') or c.get('name') or ''} {c.get('domain') or ''}".lower()

    def _threat_blob(t: dict) -> str:
        return f"{t.get('title') or ''} {t.get('cwe') or ''}".lower()

    rows: list[tuple] = []
    absent: list[str] = []
    for spec in _AUTH_MECHANISM_SPECS:
        m_ctrls = [c for c in controls if any(k in _ctrl_blob(c) for k in spec["control_kw"])]
        m_threats = [t for t in threats if any(k in _threat_blob(t) for k in spec["threat_kw"])]
        meta_present = bool(spec.get("meta_flag") and meta.get(spec["meta_flag"]))
        if not (m_ctrls or m_threats or meta_present):
            absent.append(spec["name"])
            continue
        status = ""
        if m_ctrls:
            worst = max(
                ((c.get("effectiveness") or "").strip().lower() for c in m_ctrls),
                key=lambda e: _AUTH_INV_EFFECTIVENESS_RANK.get(e, -1),
                default="",
            )
            status = _AUTH_INV_EFFECTIVENESS_BADGE.get(worst, "")
        if not status and m_threats:
            worst_r = max(
                ((t.get("risk") or t.get("severity") or "").strip().lower() for t in m_threats),
                key=lambda r: _AUTH_INV_RISK_RANK.get(r, -1),
                default="",
            )
            status = _AUTH_INV_RISK_BADGE.get(worst_r, "⚠️ At risk")
        if not status:
            status = "✅ Present"
        seen: set[str] = set()
        flinks: list[str] = []
        for t in m_threats:
            lk = _auth_mech_finding_link(t)
            if lk and lk not in seen:
                seen.add(lk)
                flinks.append(lk)
        findings = "<br/>".join(flinks[:6]) if flinks else "—"
        sec = spec["section"]
        assessed = f"[§{sec}](#{_v2_slug(_AUTH_INV_SECTION_TITLES.get(sec, sec))})"
        rows.append((spec["name"], status, assessed, findings))

    if not rows:
        return []

    sec73 = _v2_slug(_AUTH_INV_SECTION_TITLES["7.3"])
    sec79 = _v2_slug(_AUTH_INV_SECTION_TITLES["7.9"])
    out: list[str] = []
    out.append("<!-- §7.2 AUTH-MECHANISMS-FROZEN — deterministic inventory, pregenerator-owned. DO NOT EDIT. -->")
    out.append(
        "**Authentication mechanisms (at a glance).** Every authentication mechanism "
        "detected on the application, its effective status, where it is assessed, and its "
        "linked findings. Controls are catalogued by domain, so JWT/session handling is "
        f"assessed under [§7.3 Session and Token Controls](#{sec73}) and password hashing "
        f"under [§7.9 Cryptography Secrets and Data Protection](#{sec79})."
    )
    out.append("")
    out.append("| Mechanism | Status | Assessed in | Findings |")
    out.append("|---|---|---|---|")
    for name, status, assessed, findings in rows:
        out.append(f"| {name} | {status} | {assessed} | {findings} |")
    out.append("")
    if absent:
        out.append("_Also checked, not detected on this codebase: " + ", ".join(absent) + "._")
        out.append("")
    out.append("<!-- §7.2 AUTH-MECHANISMS-FROZEN END -->")
    out.append("")
    return out


# Placeholder line for the `**Controls covered:**` link list inside
# gen_security_architecture_v2. It is rewritten from the H4 headings actually
# emitted in each §7.x block AFTER the subcontrol loop runs, so a suppressed
# control can never leave a dangling link in the covered-list.
_COVERED_SENTINEL = "<!-- __CONTROLS_COVERED_SENTINEL__ -->"


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
    n_unsafe = eff_counts.get("unsafe", 0)
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
        f"{n_partial} partial, {n_weak} weak, {n_unsafe} unsafe, "
        f"{n_missing} missing. Linked threats: {len(threats)}._"
    )
    lines.append("")
    # Verdict legend — the two red verdicts are not interchangeable, and the
    # distinction tells the reader whether to FIX an existing control or ADD a
    # new one. Emitted once, deterministically, so every §7 reader has the key.
    lines.append(
        "**How to read the verdicts.** Every control category (and every "
        "sub-control below it) carries exactly one status. The two red "
        "verdicts do **not** mean the same thing — this is the distinction "
        "that decides what you have to do about a finding:"
    )
    lines.append("")
    lines.append("| Status | Meaning | What it asks of you |")
    lines.append("|---|---|---|")
    lines.append("| 🟢 Adequate | Control is present and sound | Nothing — keep it |")
    lines.append("| 🟡 Partial | Present, but with meaningful gaps | Close the gap |")
    lines.append("| 🟠 Weak | Present, but has exploitable gaps | Strengthen it |")
    lines.append(
        "| 🔴 Unsafe | **Present and relied upon, but defeated / trivially bypassable** | **Fix the existing control** |"
    )
    lines.append("| 🔴 Missing | **Control was never built** | **Add the control** |")
    lines.append("| — | Not applicable to this codebase | — |")
    lines.append("")
    lines.append(
        'So "🔴 Unsafe" on a control category does *not* mean the control is '
        "absent — it means the control exists but does not hold (e.g. an MD5 "
        'password hash, a raw-SQL query path, a hardcoded signing key). "🔴 '
        'Missing" is reserved for controls that were never built (e.g. no '
        "Content-Security-Policy header)."
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
        if any((c.get("effectiveness") or "").lower() == "unsafe" for c in matched_controls):
            # Present-but-broken takes the headline over absent: a control the
            # app relies on but that does not hold is the more urgent message.
            verdict = "🔴 Unsafe"
        elif any((c.get("effectiveness") or "").lower() == "missing" for c in matched_controls):
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
        control_names = [(c.get("name") or c.get("control") or "").strip() for c in matched_controls]
        control_names = [n for n in control_names if n][:2]  # at most 2 examples
        example_clause = f" (e.g. {', '.join(control_names)})" if control_names else ""
        if verdict.startswith("🔴 Unsafe"):
            if n_routed:
                reason = (
                    f"{n_routed} routed {'finding' if n_routed == 1 else 'findings'}; "
                    f"catalogued controls are present but defeated{example_clause}."
                )
            else:
                reason = f"Catalogued controls are present but defeated{example_clause}."
        elif verdict.startswith("🔴 Missing"):
            # Distinguish "controls ARE catalogued but every one is rated
            # Missing (absent / never built)" from "the category has no
            # catalogued control at all" — the old text said "no controls
            # catalogued" in BOTH cases, which read as an empty catalog even
            # when several required controls were listed as Missing
            # (2026-06-02: §7.1 showed it on every category).
            if n_controls:
                lead = f"{n_routed} routed {'finding' if n_routed == 1 else 'findings'}; " if n_routed else ""
                reason = f"{lead}required controls not in place{example_clause}."
                if not lead:
                    reason = reason[0].upper() + reason[1:]
            else:
                reason = (
                    f"{n_routed} routed {'finding' if n_routed == 1 else 'findings'}; no controls catalogued for this category."
                    if n_routed
                    else "No controls catalogued for this category."
                )
        elif verdict.startswith("🟠 Weak"):
            if n_controls:
                reason = f"{n_routed} routed {'finding' if n_routed == 1 else 'findings'}; catalogued controls are weak{example_clause}."
            else:
                reason = f"{n_routed} routed {'finding' if n_routed == 1 else 'findings'}; no compensating controls catalogued."
        elif verdict.startswith("🟡 Partial"):
            reason = (
                f"{n_routed} routed {'finding' if n_routed == 1 else 'findings'}; "
                f"{n_controls} partial {'control' if n_controls == 1 else 'controls'}{example_clause} leave gaps."
            )
        elif verdict.startswith("🟢 Adequate"):
            reason = (
                f"{n_controls} adequate {'control' if n_controls == 1 else 'controls'}{example_clause}; "
                f"no routed findings in this category."
            )
        else:
            reason = "No controls or findings routed to this category."
        # Link text carries the section number (e.g. "7.2 Identity and
        # Authentication Controls") so the overview reads as a numbered map.
        lines.append(f"| [{h}](#{_v2_slug(h)}) | {verdict} | {reason} |")
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
            lines.append(
                "**Verdict:** <!-- NARRATIVE_PLACEHOLDER: one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. -->"
            )
            lines.append("")
            lines.append(
                "<!-- §7.13 FORMAT — prose-only, NEVER a table. Two short paragraphs: (1) name the individual controls that exist and the strongest positive control if any (e.g. distroless runtime image, RS256 algorithm choice); (2) name which control-boundary repairs would restore layered defense (e.g. parameterized queries, runtime-injected secrets, strict JWT verification). Do NOT emit a Markdown table — `| header |` lines under §7.13 are a contract violation. Do NOT make speculative perimeter-absence claims (`No WAF`, `No firewall`, `No DAM`) — only positive evidence from the recon scan. -->"
            )
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
        control_names = [(c.get("control") or c.get("name") or c.get("domain") or "").strip() for c in section_controls]
        control_names = [name for name in control_names if name]
        implemented = [
            (c.get("implementation") or "").strip() for c in section_controls if (c.get("implementation") or "").strip()
        ]

        # §7.6 must OPEN with a general validation-approach block before the
        # specific boundary sub-blocks (contract: validation_approach_first).
        # Inject a synthetic FIRST subcontrol so the scaffold satisfies the
        # gate deterministically and the renderer fills the strategy prose
        # instead of running against the gate. Skipped when Stage-1 already
        # supplied an approach-named row as the first §7.6 control.
        if heading.startswith("7.6 ") and not (control_names and _V2_APPROACH_FIRST_RE.search(control_names[0])):
            section_controls = [
                {
                    "control": "Validation Approach",
                    "name": "Validation Approach",
                    "effectiveness": "",
                    "implementation": "",
                    "subcontrols": [],
                }
            ] + list(section_controls)
            control_names = ["Validation Approach"] + control_names

        lines.append(
            "**Verdict:** <!-- NARRATIVE_PLACEHOLDER: choose one of `🟢 Adequate` · `🟡 Partial` · `🟠 Weak` · `🔴 Unsafe` · `🔴 Missing`. Tokens come from `data/sections-contract.yaml → verdict_icons`. -->"
        )
        lines.append("")
        # R5 — `**Controls covered:**` is mechanically derived from
        # security_controls[].control + the H4 subcontrol headings.
        # LLM authoring tends to drop the markdown link wrapper or invent
        # new subcontrol names; the LOCKED marker is a sentinel for QA +
        # renderer prompt: do not re-author this line.
        #
        # The line MUST list only controls that actually get a `#### ...`
        # H4 emitted below. `_emit_v2_subcontrol_legacy` suppresses the H4
        # for an effectiveness=Missing control with no linked findings and
        # no implementation prose; listing such a control here produces a
        # dangling `**Controls covered:**` link that
        # qa_checks.check_control_subsection_coverage flags ("links to X but
        # no matching #### X subsection exists") and that
        # apply_prose_fixes._rewrite_controls_covered_anchors cannot self-heal
        # when the §7.x block ends up with ZERO H4s (it skips heading-less
        # blocks). We therefore emit a SENTINEL here and rewrite it AFTER the
        # H4 loop below from the headings actually emitted — so the line is
        # correct by construction. (juice-shop 2026-06-01 §7.10 all-suppressed
        # case + the enriched-path dangling-link repair loop.)
        covered_idx: int | None = None
        if control_names:
            lines.append(
                "<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->"
            )
            covered_idx = len(lines)
            lines.append(_COVERED_SENTINEL)
        else:
            lines.append(
                "**Controls covered:** <!-- NARRATIVE_PLACEHOLDER: list concrete subcontrols as markdown links to H4 headings. -->"
            )
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
            lines.append(
                '**Implemented controls:** <!-- NARRATIVE_PLACEHOLDER: positive inventory only — name the controls that ARE in place (e.g. "Angular template escaping, Helmet noSniff/frameguard, multer file-size limit"). Forbidden openers: "None", "No ", "Missing", "Not implemented". Concrete gaps belong in the Assessment block. -->'
            )
        lines.append("")
        lines.append(f"**Assessment:** <!-- NARRATIVE_PLACEHOLDER: §{heading} — {hint} -->")
        lines.append("")

        # §7.2 — deterministic Authentication Mechanisms inventory at the top of
        # the section so the COMPLETE auth surface (incl. mechanisms catalogued
        # under §7.3/§7.9) is always rendered, independent of LLM scaffold-fill.
        if heading.startswith("7.2 "):
            inv = _build_auth_mechanism_inventory(yaml_data)
            if inv:
                lines.extend(inv)
            lines.extend(_render_threat_hypotheses_table(yaml_data))

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
                grouped = bool(c.get("group_subcontrols")) or (c.get("kind") or "").strip().lower() == "lifecycle"
                if subs and grouped:
                    # Fold the lifecycle stages into ONE H4 with bulleted
                    # sub-points (e.g. Password-Based Authentication →
                    # Login / Registration / Reset / Change / Storage).
                    h4_idx += 1
                    _emit_v2_grouped_control(
                        lines,
                        c,
                        subs,
                        threats,
                        heading,
                        section_id=section_id,
                        idx=h4_idx,
                    )
                elif subs:
                    for sub in subs[:9]:
                        h4_idx += 1
                        _emit_v2_subcontrol_block(
                            lines,
                            sub,
                            threats,
                            heading,
                            section_id=section_id,
                            idx=h4_idx,
                        )
                else:
                    next_idx = h4_idx + 1
                    emitted = _emit_v2_subcontrol_legacy(
                        lines,
                        c,
                        name,
                        threats,
                        heading,
                        section_id=section_id,
                        idx=next_idx,
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

            # Rewrite the `**Controls covered:**` sentinel from the H4
            # headings ACTUALLY emitted in this section so a suppressed
            # control can never leave a dangling link. Labels drop the
            # `7.X.N` numeric prefix (the gate tolerates it either way) and
            # the anchor uses the same _v2_slug the H4 side-anchors carry.
            if covered_idx is not None:
                emitted_titles: list[str] = []
                for ln in lines[covered_idx + 1 :]:
                    m_h4 = re.match(r"^####\s+(.+?)\s*$", ln)
                    if m_h4:
                        title = re.sub(r"^\d+(?:\.\d+)*\s+", "", m_h4.group(1)).strip()
                        if title:
                            emitted_titles.append(title)
                if emitted_titles:
                    linked_controls = ", ".join(f"[{t}](#{_v2_slug(t)})" for t in emitted_titles)
                    lines[covered_idx] = f"**Controls covered:** {linked_controls}."
                else:
                    # Every control was suppressed (no H4 emitted). Drop the
                    # LOCKED comment + sentinel + trailing blank so no dangling
                    # `**Controls covered:**` link survives; the suppressed-
                    # controls note above still lists them for the reader.
                    del lines[covered_idx - 1 : covered_idx + 2]
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
                lines.append(f"_Not applicable for this codebase — no controls or findings are routed to {heading}._")
                lines.append("")
                continue
            default_mech_raw = _V2_DEFAULT_MECHANISM.get(heading, heading.split(" ", 1)[1])
            default_mech = _friendly_subcontrol_title(default_mech_raw)
            section_id = heading.split(" ", 1)[0]
            # Emit BOTH the un-friendly slug AND the friendly slug as side
            # anchors so `**Controls covered:**` link variants (LLM-filled
            # placeholder vs. mechanical) both resolve to this H4.
            lines.append(
                "".join(f'<a id="{s}"></a>' for s in sorted({_v2_slug(default_mech_raw), _v2_slug(default_mech)}))
            )
            lines.append(f"#### {section_id}.1 {default_mech}")
            lines.append("")
            lines.append(_v2_status_line(""))
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


def gen_security_architecture(yaml_data: dict, depth: str = "standard") -> str:
    """Render the current §7 security-architecture scaffold.

    Schema v2 is the only supported §7 layout. Keep this public wrapper for
    tests and older integrations that import ``gen_security_architecture``.
    """
    return gen_security_architecture_v2(yaml_data, depth)


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
        "--allow-narrative-loss",
        action="store_true",
        help="Acknowledge that --force on security-architecture.md will discard "
        "any LLM-authored NARRATIVE_PLACEHOLDER fills from Stage 2. Without "
        "this flag, --force refuses to overwrite security-architecture.md "
        "when the on-disk version has no remaining NARRATIVE_PLACEHOLDER markers "
        "(i.e. Stage 2 already filled it). The right tool for surgical updates "
        "to a Stage-2-filled fragment is scripts/apply_content_repair.py.",
    )
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
    if not depth:
        cfg_path = output_dir / ".skill-config.json"
        if cfg_path.is_file():
            try:
                import json as _json

                cfg = _json.loads(cfg_path.read_text(encoding="utf-8"))
                depth = (cfg.get("assessment_depth") or "").strip().lower()
            except (OSError, ValueError):
                depth = ""
    if depth not in {"quick", "standard", "thorough"}:
        depth = "standard"

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
        # RC-3 guard: --force on security-architecture.md must not silently
        # discard LLM-authored narratives. A fragment whose NARRATIVE_PLACEHOLDER
        # count has dropped to zero has been filled by Stage 2 and represents
        # ~3-8 min of LLM work; --force would replay that work on the next
        # Stage 2 dispatch. Require --allow-narrative-loss as an explicit
        # acknowledgement. Operators wanting to update mechanical fields
        # (table rows, "Controls covered:" lines, anchors) without losing
        # narrative should use scripts/apply_content_repair.py with the
        # heading_rename_cascade operator instead.
        if args.force and name == "security-architecture.md" and path.exists() and not args.allow_narrative_loss:
            try:
                existing = path.read_text(encoding="utf-8")
            except OSError:
                existing = ""
            if existing and "NARRATIVE_PLACEHOLDER" not in existing:
                print(
                    f"Error: refusing to --force overwrite {name} — the on-disk "
                    f"fragment has been narrative-filled (no NARRATIVE_PLACEHOLDER "
                    f"markers remain). Overwriting would discard ~3-8 min of "
                    f"Stage 2 LLM work and require re-dispatching the renderer.\n"
                    f"  • For surgical updates (heading rename, control name change), "
                    f"use scripts/apply_content_repair.py with a heading_rename_cascade "
                    f"operation — preserves narratives.\n"
                    f"  • To deliberately wipe and regenerate the scaffold, re-run "
                    f"with --allow-narrative-loss (the operator acknowledges the "
                    f"narrative work will be lost).",
                    file=sys.stderr,
                )
                return 2
        try:
            # security-architecture takes a depth parameter (P2 — A5);
            # other generators have a (yaml_data) signature.
            if name == "security-architecture.md":
                content = gen_security_architecture_v2(yaml_data, depth)
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
