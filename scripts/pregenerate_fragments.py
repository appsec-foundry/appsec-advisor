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
Phase-11 budget. The remaining REQUIRED_FRAGMENTS are normally LLM-authored
by the Stage-2 renderer, but three of them now carry a deterministic
backstop generator here so a renderer cutoff cannot leave a MANDATORY
fragment missing (idempotent — a richer LLM version already on disk wins):

  +  ``ms-verdict.json``          — Management-Summary verdict (mandatory; compose
                                    HARD-fails without it → gen_verdict is its floor)
  +  ``ms-ai-exposure.json``      — AI/LLM Exposure callout (self-gates: no LLM surface → none)
  +  ``ms-critical-attack-tree.json`` — Critical Attack Tree (self-gates: <2 Criticals → none)
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
from _severity_rollup import register_severity
from load_business_context import RUN_ONLY_NAME

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
# Data tiers using a heuristic on id/name/paths. Used by §2 diagrams and §6.
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


_TIER_VALUES = ("client", "application", "data")


def _classify_tier(component: dict) -> str:
    """Return 'client' | 'application' | 'data' for a component.

    An explicit ``tier`` / ``kind`` / ``type`` on the component wins. The §2.3
    component table renders that field verbatim, so deriving the diagram tier
    from id/name/paths instead put the same component in two places: a
    server-side module living under a ``.../landscape/client/`` package landed
    in the browser-client zone while the table called it ``application``.
    The heuristic below is the fallback for components that carry no tier.

    Hints match at a token-start boundary (``(?<![a-z0-9])``), not as bare
    substrings. A bare ``h in haystack`` lets a short hint false-match the
    middle of an unrelated path token — ``ui`` inside ``b·ui·ld`` and
    ``j·ui·ceshop.sqlite`` pulled ``express-backend`` and ``data-layer`` into
    the ``client`` tier, left the data tier empty, and made §2.2 emit a
    redundant fallback ``DATA`` node that pushed the diagram to 9 nodes and
    tripped ``diagram_compactness``. Boundary-anchoring keeps legitimate prefix
    matches (``mongo``→``mongodb``, ``sql``→``sqlite``) while dropping the
    mid-token hits.
    """
    declared = (component.get("tier") or component.get("kind") or component.get("type") or "").strip().lower()
    if declared in _TIER_VALUES:
        return declared
    haystack = " ".join(
        [
            (component.get("id") or "").lower(),
            (component.get("name") or "").lower(),
            " ".join(component.get("paths") or []).lower(),
        ]
    )
    for tier, hints in _TIER_HINTS.items():
        if any(re.search(r"(?<![a-z0-9])" + re.escape(h), haystack) for h in hints):
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


def component_coverage(meta: dict) -> dict | None:
    """Full-depth, screened and excluded rows of `meta.component_selection`, or None without one.

    The one coverage rule behind §1 Scope, the Management Summary scope line and
    the §2.3 Scope column: a screening-depth component received all six STRIDE
    categories without verification, so it never counts as full analysis. The
    completion summary's "STRIDE-analyzed" count deliberately includes screened
    components, because a screening pass is a STRIDE pass.
    """
    cs = meta.get("component_selection") if isinstance(meta, dict) else None
    if not isinstance(cs, dict):
        return None
    selected = [e for e in cs.get("selected") or [] if isinstance(e, dict)]
    excluded = [e for e in cs.get("excluded") or [] if isinstance(e, dict)]
    return {
        "total": cs.get("total") or len(selected) + len(excluded),
        "full": [e for e in selected if e.get("analysis_depth") != "screening"],
        "screened": [e for e in selected if e.get("analysis_depth") == "screening"],
        "excluded": excluded,
    }


METHOD_SENTENCE = (
    "An automated, AI-assisted threat model built from the repository's source code and configuration — "
    "static analysis only, no dynamic or penetration testing."
)

METHOD_SHORT = "Automated static analysis of code and configuration, not a pentest or a team threat-modeling session"


def _component_names(rows: list[dict], bold: bool) -> str:
    names = [str(e.get("name") or e.get("id")) for e in rows]
    if bold:
        names = [f"**{n}**" for n in names]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def screening_clause(screened: list[dict], bold: bool = False) -> str:
    """`<names> was/were only screened, …` — the plain wording for screening-depth components.

    A screening pass covers all six STRIDE categories in a short turn budget and
    skips the follow-up code searches that confirm each finding; its findings
    still cite code evidence, so the clause never calls them unverified.
    """
    verb = "was" if len(screened) == 1 else "were"
    return f"{_component_names(screened, bold)} {verb} only screened, a shorter pass without follow-up code checks per finding"


def business_context_clause(meta: dict) -> str | None:
    """The business-context source as the report states it: one of two fixed labels, never a raw path."""
    source = meta.get("business_context_source") if isinstance(meta, dict) else None
    if not source:
        return None
    if source == RUN_ONLY_NAME:
        return "Business context supplied for this run was used"
    return f"Business context was taken from `{source}`"


def limits_statement(meta: dict) -> str:
    """What the method cannot establish; names the business-context source when one was supplied."""
    context = business_context_clause(meta)
    lead = "It does not replace a threat-modeling session with the team"
    tail = "and each finding still needs confirmation in the deployed system."
    if context:
        return (
            f"{lead}. {context}; design intent, runtime behaviour and production configuration are not covered, {tail}"
        )
    return f"{lead}: business context, design intent, runtime behaviour and production configuration are not covered, {tail}"


def method_and_limits(meta: dict) -> str:
    """The one-sentence Management Summary method line; §1 carries coverage, §11 the itemised limits."""
    coverage = component_coverage(meta)
    gaps = []
    if coverage:
        for key, state in (("screened", "only screened"), ("excluded", "not analysed")):
            if coverage[key]:
                verb = "was" if len(coverage[key]) == 1 else "were"
                gaps.append(f"{_component_names(coverage[key], False)} {verb} {state}")
    # §1 carries the coverage detail only when a component selection exists; a §1
    # fragment without one need not have a Scope anchor, so the link follows it.
    details = (
        "[§1 Scope](#scope) and [§11 Out of Scope](#11-out-of-scope)"
        if coverage
        else "[§11 Out of Scope](#11-out-of-scope)"
    )
    return f"**Method and limits:** {'; '.join([METHOD_SHORT, *gaps])} — see {details}."


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
    coverage = component_coverage(meta)
    excluded = (coverage or {}).get("excluded") or []
    screened = (coverage or {}).get("screened") or []
    if cs and excluded:
        # Components were narrowed to a STRIDE-analyzed subset — make the coverage
        # and the selection rationale explicit instead of implying every modeled
        # component was assessed equally.
        total = coverage["total"] or len(components)
        analyzed = len(coverage["full"])
        sel_names = [s.get("name") or s.get("id") for s in coverage["full"]]
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
            f"{name} comprises **{total}** modeled components; **{analyzed} of {total}** were analysed "
            "with full STRIDE: " + ", ".join(f"**{n}**" for n in sel_names) + f".{crit_clause}"
        )
        lines.append("")
        if screened:
            lines.append(screening_clause(screened, bold=True) + ".")
            lines.append("")
        lines.append(
            "Not analysed at this depth: " + ", ".join(exc_names) + "; a higher `--assessment-depth` covers them."
        )
        lines.append("")
    else:
        lines.append(
            f"This threat model covers {len(components)} {'component' if len(components) == 1 else 'components'} of {name}: "
            + ", ".join(f"**{c.get('name', c.get('id', '?'))}**" for c in components)
            + "."
        )
        if cs and screened:
            lines.append("")
            lines.append(
                f"**{len(coverage['full'])} of {coverage['total'] or len(components)}** modeled components "
                "were analysed with full STRIDE; " + screening_clause(screened, bold=True) + "."
            )
        elif cs:
            lines.append("")
            lines.append(f"All {cs.get('total') or len(components)} modeled components were analysed with full STRIDE.")
        lines.append("")

    out_of_scope = (meta.get("scope") if isinstance(meta.get("scope"), dict) else {}).get("out_of_scope") or []
    if out_of_scope:
        lines.append("**Out of scope:** " + "; ".join(out_of_scope) + ".")
    else:
        lines.append(
            "**Out of scope:** third-party hosted dependencies, browser runtime, "
            "operating-system kernel, and the underlying network infrastructure."
        )
    lines.append("")
    # Method boundary next to the system boundary: the line above names the parts
    # of the system that are excluded, this one names what kind of model this is.
    # §11 → "Not Covered by This Method" carries the itemised version.
    lines.append(f"**Basis:** {METHOD_SENTENCE} It describes the system as built, not as designed.")
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
    diagram (2.2–2.3); §2.1 builds its own from the actors it draws.

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

    return {"2.2": t22, "2.3": t23}


_CONTAINER_TIERS = ("client", "application", "data")


# ---------------------------------------------------------------------------
# Trust boundaries in the §2 diagrams
#
# A boundary the model RESOLVED is part of the architecture, so the
# architecture diagrams must show it — a §2 that draws components and arrows
# but no boundary tells the reader the system has none. Mermaid's native device
# for "everything in here is one trust zone" is a `subgraph`, so each drawn
# boundary becomes a labelled subgraph around the side it protects.
#
# Only resolved boundaries are drawn (never an inferred or unresolved one), the
# labels name the crossing as `from → to` with the tb-id as the locator into
# §1, and every builder degrades to its pre-boundary output when the model has
# no resolved boundary at all.
# ---------------------------------------------------------------------------

_TB_TITLE_MAX_GROUPS = 2  # crossings named in a subgraph title before "+N more"
_TB_NOTE_MAX = 4  # crossings named in the §2.2 caption before "+N more"
_TB_EDGE_MAX_IDS = 2  # boundary ids named on a §2.3 edge label before "+N"


def _resolved_boundaries(yaml_data: dict) -> list[dict]:
    """Resolved trust boundaries carrying an id, in model order."""
    return [
        tb
        for tb in (yaml_data.get("trust_boundaries") or [])
        if isinstance(tb, dict) and tb.get("resolution_status") == "resolved" and (tb.get("id") or "")
    ]


def _tb_crossing(tb: dict) -> str:
    """`from → to` for a boundary, or "" when the endpoints are unknown."""
    src = (tb.get("from") or "").strip()
    dst = (tb.get("to") or "").strip()
    return f"{src} → {dst}" if src and dst else ""


def _tb_entries(boundaries: list[dict]) -> list[str]:
    """`external → backend-api (tb-1, tb-6)` per crossing — ids of the same
    crossing collapse into one entry (two enforcement points, one crossing)."""
    order: list[str] = []
    ids: dict[str, list[str]] = {}
    for tb in boundaries:
        key = _tb_crossing(tb) or str(tb.get("id"))
        if key not in ids:
            ids[key] = []
            order.append(key)
        ids[key].append(str(tb.get("id")))
    return [f"{key} ({', '.join(ids[key])})" if _has_ids(key, ids[key]) else key for key in order]


def _has_ids(key: str, ids: list[str]) -> bool:
    """False when the "crossing" IS the id (unknown endpoints) — avoids the
    stutter `tb-1 (tb-1)`."""
    return not (len(ids) == 1 and ids[0] == key)


def _container_boundaries(yaml_data: dict, components: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """Split resolved boundaries into what §2.2 can draw and what it cannot.

    Returns ``(into_server, application_to_data, other)``:
      * ``into_server`` — crossings from the untrusted side (the internet or a
        client-tier component) into the application or data tier. This is the
        perimeter of the deployable system and the one §2.2 draws.
      * ``application_to_data`` — the application→data crossing; drawn only
        when there is no ingress crossing to draw (four-subgraph cap).
      * ``other`` — egress and intra-tier crossings, which a container diagram
        of tiers cannot place without inventing a zone. Named in the caption.
    """
    tier_by_id = {
        (c.get("id") or "").strip(): _classify_tier(c) for c in components if isinstance(c, dict) and c.get("id")
    }
    into_server: list[dict] = []
    app_to_data: list[dict] = []
    other: list[dict] = []
    for tb in _resolved_boundaries(yaml_data):
        src = (tb.get("from") or "").strip()
        dst = (tb.get("to") or "").strip()
        src_tier = "external" if src.lower() == "external" else tier_by_id.get(src)
        dst_tier = "external" if dst.lower() == "external" else tier_by_id.get(dst)
        if src_tier in ("external", "client") and dst_tier in ("application", "data"):
            into_server.append(tb)
        elif src_tier == "application" and dst_tier == "data":
            app_to_data.append(tb)
        else:
            other.append(tb)
    return into_server, app_to_data, other


def _components_crossings(yaml_data: dict, by_tier: dict[str, list[dict]]) -> list[dict]:
    """Resolved boundaries the §2.3 diagram marks as an edge crossing.

    §2.3 draws four zone columns but has no subgraph slot left for a boundary
    (all four are taken by EXT/CLIENT/APP/DATA), so the crossing is marked on
    the EDGES instead. Which edges qualify follows from the model, not from
    the drawing: the browser client executes on the user's device, so CLIENT
    sits in the SAME untrusted zone as EXT — the `external → …` and
    `client → …` crossings both land on the edges that enter the application
    tier, and the EXT → CLIENT edge crosses nothing. That is the identical
    partition ``_container_boundaries`` computes for §2.2, reused verbatim so
    the two diagrams cannot disagree about where trust changes.

    ONLY that untrusted-zone exit is marked. `_container_boundaries` also
    returns the application → data crossing, but the §2 legend defines `==>`
    as "crosses an UNTRUSTED trust boundary" and an internal app→data
    enforcement point is not one; marking it too would spend the diagram's one
    emphasis on every boundary alike and blur the answer to the question the
    reader is actually asking here. §1 and §2.2 carry the internal crossings.

    Empty when the model has no resolved boundary, or when the application
    tier has no node in this diagram — an edge is only marked when it is
    actually drawn.
    """
    if not (by_tier.get("application") or []):
        return []
    into_server, _app_to_data, _other = _container_boundaries(yaml_data, yaml_data.get("components") or [])
    return into_server


def _tb_edge_note(boundaries: list[dict], max_chars: int) -> str:
    """`trust boundary · tb-1, tb-6` — the crossing marker on an edge label.

    The ids are the locator into §1, so they are what survives truncation; at
    most ``_TB_EDGE_MAX_IDS`` are named and the rest are declared as `+N`.
    Empty string when no boundary carries an id, which makes the caller fall
    back to the plain legit/attack edge.
    """
    ids: list[str] = []
    for tb in boundaries:
        tb_id = str(tb.get("id") or "").strip()
        if tb_id and tb_id not in ids:
            ids.append(tb_id)
    if not ids:
        return ""
    shown = ids[:_TB_EDGE_MAX_IDS]
    rest = len(ids) - len(shown)
    tail = f" +{rest}" if rest else ""
    return _truncate_label_line(f"trust boundary · {', '.join(shown)}{tail}", max_chars)


def _tb_caption(boundaries: list[dict], max_entries: int = _TB_NOTE_MAX, lead: str = "not drawn above") -> str:
    """Italic caption naming boundaries the diagram could not draw, with a link
    into the §1 register. Empty when there are none."""
    if not boundaries:
        return ""
    return _tb_caption_from_entries(_tb_entries(boundaries), max_entries, lead)


def _tb_caption_from_entries(entries: list[str], max_entries: int = _TB_NOTE_MAX, lead: str = "not drawn above") -> str:
    """Caption body for callers that already grouped their entries — §2.1 has to
    subtract the crossings its subgraph title already named."""
    if not entries:
        return ""
    shown = entries[:max_entries]
    rest = len(entries) - len(shown)
    tail = f", +{rest} more" if rest else ""
    return (
        f"*Trust boundaries {lead}: {', '.join(shown)}{tail} — "
        f"every boundary is listed in [§1 Trust Boundaries](#trust-boundaries).*"
    )


def _tb_title_line(entry: str, limit: int) -> str:
    """Fit one `crossing (ids)` entry into `limit` chars, sacrificing the
    crossing text before the ids — the ids are the locator into §1."""
    if len(entry) <= limit:
        return entry
    m = re.match(r"^(.*) \((.*)\)$", entry)
    if not m:
        return entry[: max(1, limit - 1)] + "…"
    crossing, ids = m.group(1), m.group(2)
    room = limit - len(ids) - 4
    if room < 8:
        return entry[: max(1, limit - 1)] + "…"
    return f"{crossing[: room - 1]}… ({ids})"


def _tb_subgraph_title(boundaries: list[dict], max_groups: int = _TB_TITLE_MAX_GROUPS) -> str:
    """Subgraph caption naming the boundaries whose zone this subgraph is.

    One crossing per `<br/>` line, at most three lines and 60 characters each:
    that is the label budget `data/sections-contract.yaml →
    diagram_compactness` enforces on every quoted label in a §2 block, and a
    one-line caption of several crossings blows straight through it. Quotes are
    stripped rather than escaped — a stray `"` inside a `subgraph ID["…"]`
    header ends the label and breaks the block. Truncation is declared
    (`+N more`); the §2.2 caption and §1 carry the rest.
    """
    entries = _tb_entries(boundaries)
    shown = entries[:max_groups]
    rest = len(entries) - len(shown)
    lines = ["Trust boundary · " + _tb_title_line(shown[0], 43)] if shown else ["Trust boundary"]
    lines += [_tb_title_line(e, 60) for e in shown[1:]]
    if rest:
        lines.append(f"+{rest} more")
    return "<br/>".join(lines).replace('"', "'")


def _cap_container_tiers(
    by_tier: dict[str, list[dict]],
    crit_counts: dict[str, int],
    high_counts: dict[str, int],
    max_nodes: int,
) -> tuple[dict[str, list[dict]], list[dict]]:
    """Trim §2.2 container nodes down to the contract's ``max_nodes_total``.

    `data/sections-contract.yaml → diagram_compactness."2.2 Container
    Architecture"` caps the diagram at 8 nodes, but this generator emitted one
    node per component with no ceiling. Any model with more components than the
    cap therefore shipped a `diagram_compactness` violation that NO re-render
    could clear — the repair plan's own remedy ("regenerate from the
    deterministic Pre-Generator, it obeys the limits by construction")
    reproduced the violation verbatim (juice-shop 2026-07-18: 9 components,
    max 8).

    Trimming preserves what the diagram is for:
      * every non-empty tier keeps at least one node, so the layered topology
        survives;
      * the largest tier surrenders nodes first;
      * within a tier the LOWEST-risk component goes first (fewest Critical,
        then fewest High findings, then name for determinism) — the red/amber
        risk borders are the reason this diagram exists, so the risky
        containers are the last to go.

    Returns ``(capped_by_tier, dropped)``. The caller names the dropped
    components under the diagram; they stay fully inventoried in the §2.3
    component table, which is exactly where the contract's remediation text
    says per-container detail belongs.
    """
    capped = {tier: list(by_tier.get(tier) or []) for tier in _CONTAINER_TIERS}
    dropped: list[dict] = []
    if max_nodes <= 0:
        return capped, dropped

    def _risk(c: dict) -> tuple[int, int, str]:
        cid = c.get("id") or ""
        return (crit_counts.get(cid, 0), high_counts.get(cid, 0), str(c.get("name") or cid))

    while sum(len(capped[tier]) for tier in _CONTAINER_TIERS) > max_nodes:
        # Only tiers that can spare a node — never empty a tier entirely.
        spare = [tier for tier in _CONTAINER_TIERS if len(capped[tier]) > 1]
        if not spare:
            break
        tier = max(spare, key=lambda t: len(capped[t]))
        victim = min(capped[tier], key=_risk)
        capped[tier].remove(victim)
        dropped.append(victim)
    return capped, dropped


def _edge_endpoints_kept(edge: str, kept: set[str]) -> bool:
    """True when both endpoints of a ``a -->|label| b`` edge survived the cap.

    An edge pointing at a trimmed container would make Mermaid render the node
    anyway — silently re-introducing the node the cap just removed (and putting
    it outside every subgraph). An unrecognised edge shape is left alone.
    """
    m = re.match(
        r"^\s*([A-Za-z][A-Za-z0-9_]*)\s*[-.=]+>\s*\|[^|]*\|\s*([A-Za-z][A-Za-z0-9_]*)",
        edge,
    )
    if not m:
        return True
    return m.group(1) in kept and m.group(2) in kept


_DETAIL_FIGURE_INTROS = {
    "2.2": (
        "Where {name} runs and what it is built on: the deployment environment the repository declares, the container, "
        "runtime and frameworks each component runs in, and the pipelines that build and publish it. Findings per "
        "component are in Figure 1."
    ),
    "2.3": (
        "How each component is reached, what it handles, how many threats hit it, and how effective the controls "
        "evidenced on it are. The component table below holds source paths and linked threats per `C-NN`; "
        "per-finding evidence is in [§8 Findings Register](#8-findings-register)."
    ),
}


def _detail_figure_block(key: str, name: str, figure: dict) -> list[str]:
    """Intro, detail view (figure image or Markdown table) and takeaway rendered by the composer."""
    return [
        _DETAIL_FIGURE_INTROS[key].format(name=name),
        "",
        figure.get("markdown") or figure["image"],
        "",
        f"**Key takeaway:** {figure['takeaway']}",
        "",
    ]


def gen_architecture_diagrams(yaml_data: dict, figures: dict | None = None, people: list[dict] | None = None) -> str:
    """## 2. Architecture Diagrams — 3 required sub-sections. §2.2 and §2.3
    show the composer's detail view when ``figures`` carries one
    (``{"2.2": {"image": "![Figure 3 - …](….svg)" | "markdown": table, "takeaway": …}}``),
    otherwise a ```mermaid block. ``people`` is the Figure 1 actor set that
    §2.1 draws; without it §2.1 shows the modelled roles only.
    """
    figures = figures or {}
    meta = yaml_data.get("meta") or {}
    project_raw = meta.get("project")
    display = yaml_data.get("project") if isinstance(yaml_data.get("project"), dict) else {}
    if display.get("name"):
        name = display["name"]  # the name Figure 1 shows, when the composer resolved it
    elif isinstance(project_raw, dict):
        name = project_raw.get("name") or "System"
    elif isinstance(project_raw, str) and project_raw:
        name = project_raw
    else:
        name = "System"
    components = yaml_data.get("components") or []
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
        f"Who uses and attacks {name}, and which external systems it exchanges data with. Solid arrows name the data "
        "a flow carries; dashed red arrows are attack routes. Actors carry the names Figure 1 uses (C4 Level 1)."
    )
    lines.append("")
    context_people = _context_people(yaml_data) if people is None else people
    lines.extend(_system_context_mermaid(yaml_data, name, context_people))
    lines.append("")
    externals = [
        e
        for e in yaml_data.get("external_entities") or []
        if isinstance(e, dict) and e.get("id") and e.get("kind") != "legitimate-role"
    ]
    lines.append(f"**Key takeaway:** {_system_context_takeaway(name, context_people, externals)}")
    lines.append("")

    # ----- 2.2 Container Architecture ----------------------------------------
    lines.append("### 2.2 Container Architecture")
    lines.append("")
    mark_22 = len(lines)
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

    # Enforce the contract node ceiling — the SoT is
    # `diagram_compactness."2.2 Container Architecture".max_nodes_total`.
    # Without this the generator emitted one node per component and produced a
    # permanently-failing advisory on any model above the cap (see
    # `_cap_container_tiers`).
    c22_rules = _load_diagram_compactness().get("2.2 Container Architecture") or {}
    c22_max_nodes = int(c22_rules.get("max_nodes_total", 8))
    by_tier_22, dropped_22 = _cap_container_tiers(by_tier, crit_counts, high_counts, c22_max_nodes)
    kept_22 = [c for tier in _CONTAINER_TIERS for c in by_tier_22[tier]]
    kept_node_ids = {_safe_node_id(c["id"]) for c in kept_22 if c.get("id")}
    # Fallback nodes stand in for an empty tier and are legitimate endpoints.
    for tier, fallback in (("client", "BROWSER"), ("application", "APP"), ("data", "DATA")):
        if not by_tier_22[tier]:
            kept_node_ids.add(fallback)

    # Trust-boundary grouping. The contract caps §2.2 at four subgraphs
    # (Client / Application / Data + one), so exactly ONE boundary subgraph is
    # drawn: the ingress into the server side when the model resolved one —
    # that is the crossing an attacker traverses — otherwise the
    # application→data boundary. Whatever is not drawn is named in the caption
    # below the diagram, never dropped.
    srv_bounds, data_bounds, other_bounds = _container_boundaries(yaml_data, components)
    wrap_server = bool(srv_bounds)
    wrap_data = bool(data_bounds) and not wrap_server
    undrawn = (data_bounds if wrap_server else []) + other_bounds

    lines.append("```mermaid")
    lines.append("flowchart TB")
    lines.append("    subgraph Client")

    if by_tier_22["client"]:
        for c in by_tier_22["client"]:
            lines.append(f'        {_safe_node_id(c["id"])}["{_component_label(c)}"]')
    else:
        lines.append('        BROWSER["Browser Runtime"]')
    lines.append("    end")
    if wrap_server:
        lines.append(f'    subgraph TBSERVER["{_tb_subgraph_title(srv_bounds)}"]')
    lines.append("    subgraph Application")
    if by_tier_22["application"]:
        for c in by_tier_22["application"]:
            lines.append(f'        {_safe_node_id(c["id"])}["{_component_label(c)}"]')
    else:
        lines.append('        APP["Application Server"]')
    lines.append("    end")
    if wrap_data:
        lines.append(f'    subgraph TBDATA["{_tb_subgraph_title(data_bounds)}"]')
    lines.append("    subgraph Data")
    if by_tier_22["data"]:
        for c in by_tier_22["data"]:
            lines.append(f'        {_safe_node_id(c["id"])}[("{_component_label(c)}")]')
    else:
        lines.append('        DATA[("Data Layer")]')
    lines.append("    end")
    if wrap_data:
        lines.append("    end")
    if wrap_server:
        lines.append("    end")

    # M3.3 / D1 — render edges from `data_flows[]` when the orchestrator
    # populated it; fall back to the legacy 1-pfeil-pro-tier-paar heuristic
    # when empty so old yamls still get a meaningful diagram.
    # Edges to capped-away containers are dropped with them — Mermaid would
    # otherwise re-materialise the node outside every subgraph.
    flow_edges = [e for e in _data_flow_edges(yaml_data, components) if _edge_endpoints_kept(e, kept_node_ids)]
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
        primary_app = _safe_node_id(by_tier_22["application"][0]["id"]) if by_tier_22["application"] else None
        if by_tier_22["client"] and primary_app:
            for c_comp in by_tier_22["client"]:
                c = _safe_node_id(c_comp["id"])
                lines.append(f"    {c} -->|HTTPS REST| {primary_app}")
        if primary_app and by_tier_22["data"]:
            for d_comp in by_tier_22["data"]:
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
        for extra in by_tier_22["application"][1:]:
            extra_id = _safe_node_id(extra["id"])
            lines.append(f"    {primary_app} -->|in-process| {extra_id}")

    # M3.3 / D1.5 (L) — Critical-path classDef. Components with ≥3 Critical
    # threats get a thick red border; ≥2 High get a thinner amber border.
    # Subgraph IDs are excluded — the highlight is a *component* visual cue.
    # Only nodes that survived the cap — a `class <id>` line for a trimmed
    # container references an undeclared node and breaks the Mermaid block.
    crit_class_lines = []
    warn_class_lines = []
    for c in kept_22:
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
    # Never drop containers silently — name what the cap removed and point at
    # the table that still inventories them in full.
    if dropped_22:
        omitted = ", ".join(str(c.get("name") or c.get("id")) for c in dropped_22)
        lines.append(
            f"*Not shown (diagram capped at {c22_max_nodes} containers): {omitted} — "
            f"every component is inventoried in [§2.3 Components](#23-components).*"
        )
        lines.append("")
    # Same rule as the container cap: what the diagram cannot show is named,
    # not dropped.
    tb_caption = _tb_caption(undrawn)
    if tb_caption:
        lines.append(tb_caption)
        lines.append("")
    lines.append(f"**Key takeaway:** {takeaways['2.2']}")
    lines.append("")
    if "2.2" in figures:  # the detail figure replaces the Mermaid diagram and its captions
        del lines[mark_22:]
        lines.extend(_detail_figure_block("2.2", name, figures["2.2"]))

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
    mark_23 = len(lines)
    lines.append(
        "Who reaches each component, and through which trust zone. Browser "
        "code runs on the user's device, so the client column is part of the "
        "untrusted zone, not a zone of its own — trust changes only where "
        "traffic enters the Application tier. Solid green arrows show "
        "legitimate data flow, dashed red arrows mark intrusion vectors. The "
        "component table directly below holds source paths and linked threats "
        "per `C-NN`; per-finding evidence is in "
        "[§8 Findings Register](#8-findings-register)."
    )
    lines.append("")
    _c23_diagram, _c23_folded_out = _components_diagram_compact(yaml_data, by_tier, people)
    lines.extend(_c23_diagram)
    lines.append("")
    # Same rule as the §2.2 container cap: a component the tier node could not
    # name is named here, not dropped.
    if _c23_folded_out:
        _folded = ", ".join(
            f"{c.get('name') or c.get('id')} (`{c.get('id')}`)" for c in _c23_folded_out if isinstance(c, dict)
        )
        lines.append(
            f"*Also folded into the tier nodes above, unnamed there for space: {_folded} — "
            f"every component is in the table below.*"
        )
        lines.append("")
    # Resolve the `tb-N` ids the crossing edges carry into §1. Gated on a
    # crossing arrow actually appearing in the rendered block — a boundary the
    # diagram could not place (no node at either end) must not be announced as
    # drawn, and a model without resolved boundaries keeps the pre-boundary
    # output unchanged.
    _c23_cross_arrow = (
        ((_load_diagram_compactness().get("2.3 Components") or {}).get("edge_convention", {}) or {}).get(
            "boundary_crossing", {}
        )
        or {}
    ).get("arrow", "==>")
    if any(_c23_cross_arrow in ln for ln in _c23_diagram):
        _c23_caption = _tb_caption_from_entries(
            _tb_entries(_components_crossings(yaml_data, by_tier)),
            lead=f"crossed by the `{_c23_cross_arrow}` edges above",
        )
        if _c23_caption:
            lines.append(_c23_caption)
            lines.append("")
    lines.append(f"**Key takeaway:** {takeaways['2.3']}")
    lines.append("")
    if "2.3" in figures:  # the component table below stays either way
        del lines[mark_23:]
        lines.extend(_detail_figure_block("2.3", name, figures["2.3"]))

    lines.append("| Component ID | Name | Tier | Source paths | Threats |")
    lines.append("|---|---|---|---|---|")
    for c in components:
        cid = c.get("id", "?")
        cname = c.get("name", cid)
        # AI function labels share Figure 1's vocabulary, never its risk or
        # topology inference. Existing models retain their component table.
        ai_capabilities = {
            "rag-retrieval",
            "rag-ingestion",
            "agent-memory",
            "agent-delegation",
            "mcp-client",
            "mcp-server",
        }
        evidenced = {
            item.get("capability")
            for item in c.get("capabilities") or []
            if isinstance(item, dict) and item.get("evidence")
        }
        if evidenced & ai_capabilities:
            vocabulary = yaml.safe_load(
                (Path(__file__).resolve().parents[1] / "data/security-capabilities.yaml").read_text()
            )["component_capabilities"]
            labels = [entry["label"] for value, entry in vocabulary.items() if value in evidenced & ai_capabilities]
            cname = str(cname) + " — " + ", ".join(labels)
        tier = _classify_tier(c).capitalize()
        paths = ", ".join(f"`{p}`" for p in (c.get("paths") or []))
        n_threats = len(c.get("threat_ids") or [])
        lines.append(f"| {cid} | {cname} | {tier} | {paths or '_(no paths)_'} | {n_threats} |")
    lines.append("")

    # M3.3 / D1.5 (J) — Legend footnote at the end of §2 covering every
    # Mermaid diagram above. Single block so we don't repeat the legend per
    # diagram. Only emit when the diagrams actually use the relevant
    # conventions — avoids cluttering small/legacy yamls.
    # §2.1 explains its own arrows (data flow vs attack route) in its intro, so the
    # shared legend covers only the diagrams from §2.2 on.
    rendered = "\n".join(lines)
    legend_lines = _maybe_render_legend(yaml_data, components, rendered.split("### 2.2 ", 1)[-1])
    if legend_lines:
        lines.extend(legend_lines)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


_MERMAID_BLOCK_RE = re.compile(r"```mermaid\n(.*?)```", re.DOTALL)


def _diagram_arrow_tokens(rendered: str) -> set[str]:
    """Arrow conventions actually emitted inside the rendered ```mermaid blocks.

    Scoped to fenced mermaid blocks on purpose: the surrounding §2 prose carries
    HTML comments (``<!-- ... -->``) and backticked literals that would otherwise
    register as edge styles.
    """
    tokens: set[str] = set()
    for block in _MERMAID_BLOCK_RE.findall(rendered or ""):
        for token in ("==>", "-.->", "-->"):
            if token in block:
                tokens.add(token)
    return tokens


def _maybe_render_legend(
    yaml_data: dict,
    components: list[dict],
    rendered_diagrams: str | None = None,
) -> list[str]:
    """M3.3 / D1.5 (J) — Build a context-aware legend block.

    Each entry is included only when the corresponding convention is
    actually present in the rendered diagrams, so the legend remains
    relevant. Order: edge styles first (from most → least common),
    severity highlight last.

    When ``rendered_diagrams`` is supplied the edge-style and border entries are
    gated on the ACTUAL emitted mermaid text rather than on model shape: a model
    can call for a convention that no rendered diagram draws (a detail view
    replaces the diagram, or no edge qualifies), and the legend must not
    explain what the reader cannot see.
    """
    flows = yaml_data.get("data_flows") or []
    has_async = any(isinstance(f, dict) and _is_async_protocol(f.get("protocol", "")) for f in flows)
    has_flows = bool(
        [f for f in flows if isinstance(f, dict) and (f.get("from") or f.get("src")) and (f.get("to") or f.get("dst"))]
    )
    boundaries = yaml_data.get("trust_boundaries") or []
    has_cross_boundary = bool(boundaries) and has_flows
    if rendered_diagrams is not None:
        # Restrictive only — never permissive. The model decides whether a
        # convention is IN SCOPE; the rendered text decides whether it was
        # actually drawn. Letting the text alone switch a bullet on would make
        # an empty model emit a legend for its placeholder diagrams.
        emitted = _diagram_arrow_tokens(rendered_diagrams)
        has_flows = has_flows and "-->" in emitted
        has_async = has_async and "-.->" in emitted
        has_cross_boundary = has_cross_boundary and "==>" in emitted
    crit_counts, high_counts = _threat_counts_per_component(yaml_data)
    has_highlight = any(v >= 3 for v in crit_counts.values()) or any(v >= 2 for v in high_counts.values())
    if rendered_diagrams is not None:
        # Only the §2.2 container diagram draws these borders; a detail view in its place draws none.
        has_highlight = has_highlight and any(
            f"classDef {name}" in block
            for block in _MERMAID_BLOCK_RE.findall(rendered_diagrams)
            for name in ("critical", "warning")
        )

    # Skip the legend entirely when nothing it would explain is rendered.
    if not (has_flows or has_async or has_cross_boundary or has_highlight):
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


_CONTEXT_ATTACK_ROUTE = {
    "build-time": "via build pipeline",
    "repo-read": "via source repository",
    "insider": "via internal access",
}


def _context_label(text: str, max_chars: int = 40, max_lines: int = 3) -> str:
    """Mermaid-safe label wrapped into at most ``max_lines`` lines."""
    words = str(text or "").replace('"', "'").replace("|", "/").replace("[", "(").replace("]", ")").split()
    lines: list[str] = []
    for word in words:
        if lines and len(lines[-1]) + 1 + len(word) <= max_chars:
            lines[-1] += " " + word
        else:
            lines.append(word)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = _truncate_label_line(lines[-1] + " …", max_chars)
    return "<br/>".join(lines)


def _context_flow_label(flows: list[dict], fallback: str) -> str:
    """Name what the flows carry, with the protocol in parentheses when known."""
    labels = list(
        dict.fromkeys(
            str(f.get("diagram_label") or f.get("label") or "").strip()
            for f in flows
            if not f.get("interaction") and (f.get("diagram_label") or f.get("label"))
        )
    )
    protocols = list(dict.fromkeys(str(f.get("protocol") or "").strip() for f in flows if f.get("protocol")))
    text = " · ".join(labels[:2]) if labels else fallback
    return f"{text} ({', '.join(protocols[:2])})" if protocols else text


def _context_people(yaml_data: dict) -> list[dict]:
    """The Figure 1 role cards when the composer did not pass the full actor set (no attack paths yet)."""
    from figure1_dfd import legitimate_role_people

    return legitimate_role_people(yaml_data)


def _system_context_mermaid(yaml_data: dict, system_name: str, people: list[dict] | None = None) -> list[str]:
    """§2.1 System Context (C4 Level 1): the Figure 1 actors, the system and its external systems.

    ``people`` is the Figure 1 actor set (``figure1_dfd.overview_people``), so
    the context names exactly the attackers and roles Figure 1 draws. External
    systems are the modelled ``external_entities``; each edge names what its
    data flows carry.
    """
    people = _context_people(yaml_data) if people is None else people
    entities = [e for e in yaml_data.get("external_entities") or [] if isinstance(e, dict) and e.get("id")]
    externals = [e for e in entities if e.get("kind") != "legitimate-role"]
    flows = [f for f in yaml_data.get("data_flows") or [] if isinstance(f, dict)]
    sys_id = "SYSTEM"
    out = ["```mermaid", "flowchart LR"]
    nodes, edges, classes = [], [], []
    for index, person in enumerate(people):
        attacker = person["kind"] == "attacker"
        node = f"{'A' if attacker else 'R'}{index}"
        nodes.append(f'    {node}["{_context_label(person["name"])}"]')
        if attacker:
            route = _CONTEXT_ATTACK_ROUTE.get(person.get("slug") or "", "via public interface")
            edges.append(f'    {node} -.->|"{route}"| {sys_id}')
            classes.append(f"    class {node} attacker")
            continue
        own = [f for f in flows if f.get("id") in set(person.get("flow_ids") or [])]
        edges.append(f'    {node} -->|"{_context_label(_context_flow_label(own, "Uses the application"))}"| {sys_id}')
        classes.append(f"    class {node} {'admin' if person.get('privileged') else 'user'}")
    ingress = [
        tb
        for tb in _resolved_boundaries(yaml_data)
        if (tb.get("from") or "").strip().lower() == "external" and (tb.get("to") or "").strip().lower() != "external"
    ]
    system = f'{sys_id}["{_context_label(system_name)}"]'
    # Actors and external systems sit outside the boundary, so each edge into the system visibly crosses it;
    # the §1 catalogue names the boundaries.
    nodes += ['    subgraph TBEDGE["Trust boundary"]', f"        {system}", "    end"] if ingress else [f"    {system}"]
    for index, entity in enumerate(externals):
        node = f"E{index}"
        nodes.append(f'    {node}["{_context_label(entity.get("name") or entity["id"])}"]')
        outbound = [f for f in flows if f.get("to") == "external" and f.get("to_entity") == entity["id"]]
        inbound = [f for f in flows if f.get("from") == "external" and f.get("from_entity") == entity["id"]]
        if outbound:
            edges.append(f'    {sys_id} -->|"{_context_label(_context_flow_label(outbound, "Requests"))}"| {node}')
        if inbound:
            edges.append(f'    {node} -->|"{_context_label(_context_flow_label(inbound, "Requests"))}"| {sys_id}')
        if not (outbound or inbound):
            edges.append(f"    {sys_id} --- {node}")
        classes.append(f"    class {node} ext")
    classdef_map = {
        "user": "fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:1.5px",
        "attacker": "fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:2px",
        "admin": "fill:#fef3c7,stroke:#b45309,color:#78350f,stroke-width:1.5px",
        "sys": "fill:#f2f2f2,stroke:#424242,color:#111,stroke-width:1.5px",
        "ext": "fill:#f2f2f2,stroke:#9e9e9e,color:#424242,stroke-dasharray:3 3,stroke-width:1px",
    }
    used = {line.rsplit(" ", 1)[1] for line in classes} | {"sys"}
    out += nodes + edges
    out += [f"    classDef {name:8s} {style}" for name, style in classdef_map.items() if name in used]
    out += classes + [f"    class {sys_id} sys", "```"]
    return out


def _system_context_takeaway(name: str, people: list[dict], externals: list[dict]) -> str:
    """One sentence built from what §2.1 draws."""

    def listing(items: list[str]) -> str:
        return " and ".join([", ".join(items[:-1]), items[-1]] if len(items) > 1 else items)

    roles = [p["name"] for p in people if p["kind"] == "role"]
    attackers = [p["name"] for p in people if p["kind"] == "attacker"]
    systems = [str(e.get("name") or e.get("id")) for e in externals]
    parts = [f"{name} serves {listing(roles)}" if roles else f"{name} has no modelled user role"]
    parts.append(f"depends on {listing(systems)}" if systems else "depends on no modelled external system")
    sentence = " and ".join(parts)
    if attackers:
        sentence += f"; {listing(attackers)} attack{'s' if len(attackers) == 1 else ''} it"
    return sentence + "."


# ===========================================================================
# Compact diagram builder (§2.3) — contract-driven (post-2026-05).
#
# The builder has these properties:
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


def _align_actors_with_people(ext_actors: list[dict], people: list[dict]) -> list[dict]:
    """Rename §2.3 actor nodes to the Figure 1 actor set and drop any it does not draw."""
    attackers = {p["slug"]: p["name"] for p in people if p.get("kind") == "attacker"}
    internet = next((attackers[s] for s in ("internet-anon", "internet-user") if s in attackers), None)
    victim = next((p["name"] for p in people if p.get("kind") == "role" and not p.get("privileged")), None)
    names = {"INTERNET_ANON": internet, "REPO_READ": attackers.get("repo-read"), "VICTIM_REQUIRED": victim}
    out = []
    for actor in ext_actors:
        name = names.get(actor["id"])
        if name:
            icon = actor["label"].split(" ", 1)[0]
            out.append({**actor, "label": f"{icon} {name}"})
    return out


def _components_diagram_compact(
    yaml_data: dict, by_tier: dict[str, list[dict]], people: list[dict] | None = None
) -> tuple[list[str], list[dict]]:
    """§2.3 Components — compact 4-tier `flowchart TD` per the contract.

    Layout: 4 subgraphs (EXT / CLIENT / APP / DATA), one main node per
    tier, sub-components aggregated as bullets in the main node's label.

    All four subgraph slots are taken, so a resolved trust boundary cannot be
    drawn as its own zone here (that device is §2.1/§2.2's). It is marked on
    the edges instead — see `_components_crossings` for which edges qualify.

    Returns ``(mermaid_lines, folded_out)``; ``folded_out`` holds the
    components a tier node could not name in its label, for the caller to list
    under the diagram.
    """
    rules = _load_diagram_compactness().get("2.3 Components") or {}
    layout = rules.get("layout_keyword", "flowchart TD")
    max_lines = int(rules.get("max_label_lines", 3))
    max_chars = int(rules.get("max_label_chars_per_line", 60))
    classdefs = rules.get("required_classdefs") or {}
    legit_arrow = (rules.get("edge_convention", {}).get("legit", {}) or {}).get("arrow", "-->")
    attack_arrow = (rules.get("edge_convention", {}).get("attack", {}) or {}).get("arrow", "-.->")
    cross_arrow = (rules.get("edge_convention", {}).get("boundary_crossing", {}) or {}).get("arrow", "==>")
    legit_style = (rules.get("edge_convention", {}).get("legit", {}) or {}).get(
        "linkstyle", "stroke:#2e7d32,stroke-width:1.5px"
    )
    attack_style = (rules.get("edge_convention", {}).get("attack", {}) or {}).get(
        "linkstyle", "stroke:#b71c1c,stroke-width:2.5px,stroke-dasharray:6 4"
    )
    cross_style = (rules.get("edge_convention", {}).get("boundary_crossing", {}) or {}).get(
        "linkstyle", "stroke:#ef6c00,stroke-width:3px"
    )
    # Subgraph titles come from the contract (`required_subgraphs`) — it is the
    # SoT for them, and the CLIENT title in particular carries trust semantics
    # ("Untrusted Zone - …") that must not be re-stated here where it could
    # drift out of sync.
    sg_titles = {
        str((r or {}).get("id") or ""): str((r or {}).get("title") or "")
        for r in (rules.get("required_subgraphs") or [])
        if isinstance(r, dict)
    }
    ingress_tbs = _components_crossings(yaml_data, by_tier)

    actor_labels = _load_posture_actor_labels_for_pregen()
    _public_repo = bool((yaml_data.get("meta") or {}).get("public_source_repo"))
    ext_actors = _select_external_actors_for_diagram(actor_labels, public_source_repo=_public_repo)
    if people:
        ext_actors = _align_actors_with_people(ext_actors, people)

    # Tier-icon defaults.
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

    def _tier_main_node(tier_key: str) -> tuple[str, str, str, list[dict]] | None:
        """Return (mermaid_node_id, label, css_class, omitted) for the tier's
        main component. Sub-components are folded into the label as
        `<br/>+ <id>` bullets; those that no longer fit the line budget come
        back as ``omitted`` so the caller can name them under the diagram.

        The threat count covers EVERY component folded into the node, not just
        the primary — the node stands for the whole tier, so counting one
        component understated the tier a reader sees."""
        comps = by_tier.get(tier_key) or []
        if not comps:
            return None
        primary = comps[0]
        cid = (primary.get("id") or "").strip()
        cname = (primary.get("name") or cid or "?").strip()
        n_threats = sum(len(c.get("threat_ids") or []) for c in comps)
        node_id = _safe_node_id(cid)
        icon = TIER_ICON.get(tier_key, "fa:fa-cube")
        # Headline — strip embedded plain-text id when name already starts
        # with the id (avoids `C-01 C-01 Express Backend` redundancy).
        # A bare space runs the two identifiers together — `web-ui Thymeleaf Web
        # UI Templates` reads as one long phrase with no visible boundary, and
        # the icon prefix in front of it makes that worse. Separate them.
        head_text = cname if cname.lower().startswith(cid.lower()) else f"{cid} · {cname}"
        # Plain head — bold reserved for diagram column headers. See parallel
        # change in compose._build_tier_cards (components_line) and
        # security-posture-diagram.md.j2 (actor + tier labels).
        head = f"{icon} {head_text}"
        threats_line = f"<i>{n_threats} {'threat' if n_threats == 1 else 'threats'}</i>" if n_threats else ""
        # Sub-component bullets — show ID only (not full name) so the
        # aggregated line fits within max_chars even with 3+ subs. Fill the
        # line component by component instead of truncating a joined string:
        # a mid-id ellipsis leaves the reader unable to tell which components
        # the node covers, and the ones that do not fit must be nameable.
        bullets: list[str] = []
        omitted: list[dict] = []
        for extra in comps[1:]:
            ecid = (extra.get("id") or "?").strip()
            chunk = f"+ {ecid}"
            if omitted or len(" ".join([*bullets, chunk])) > max_chars:
                omitted.append(extra)
                continue
            bullets.append(chunk)
        # Compose label — head + (bullets joined) + threats_line. Cap to
        # max_lines lines AND every line ≤ max_chars (truncate per line).
        label_lines = [head]
        if bullets:
            label_lines.append(" ".join(bullets))
        if threats_line and len(label_lines) < max_lines:
            label_lines.append(threats_line)
        label_lines = [_truncate_label_line(ln, max_chars) for ln in label_lines[:max_lines]]
        label = "<br/>".join(label_lines)
        return (node_id, label, "risk", omitted)

    lines: list[str] = []
    lines.append("```mermaid")
    lines.append(layout)

    # ---- Subgraphs in the contract-declared order ----
    # 1) EXT — external actors projected from posture-actor-labels.yaml.
    if ext_actors:
        lines.append(f'    subgraph EXT["{sg_titles.get("EXT") or "Untrusted Zone - Internet"}"]')
        for actor in ext_actors:
            lines.append(f'        {actor["id"]}["{actor["label"]}"]:::{actor["css_class"]}')
        lines.append("    end")

    # 2) CLIENT — titled as part of the untrusted zone (browser code runs on
    # the user's device); the contract carries the wording and the reason.
    folded_out: list[dict] = []
    client_node = _tier_main_node("client")
    if client_node:
        nid, lbl, css, _omitted = client_node
        folded_out.extend(_omitted)
        lines.append(f'    subgraph CLIENT["{sg_titles.get("CLIENT") or TIER_TITLE["client"]}"]')
        lines.append(f'        {nid}["{lbl}"]:::{css}')
        lines.append("    end")

    # 3) APP
    app_node = _tier_main_node("application")
    if app_node:
        nid, lbl, css, _omitted = app_node
        folded_out.extend(_omitted)
        lines.append(f'    subgraph APP["{sg_titles.get("APP") or TIER_TITLE["application"]}"]')
        lines.append(f'        {nid}["{lbl}"]:::{css}')
        lines.append("    end")

    # 4) DATA — cylinder shape per audit actor convention.
    data_node = _tier_main_node("data")
    if data_node:
        nid, lbl, css, _omitted = data_node
        folded_out.extend(_omitted)
        lines.append(f'    subgraph DATA["{sg_titles.get("DATA") or TIER_TITLE["data"]}"]')
        lines.append(f'        {nid}[("{lbl}")]:::{css}')
        lines.append("    end")

    # ---- Edges ----
    # Each edge is kept with the convention it is drawn in ("legit" / "attack"
    # / "crossing") so the linkStyle block below can address the three groups
    # by index. Emission order stays legit-then-attack, so a model with no
    # resolved boundary produces byte-identical output to the pre-boundary
    # renderer.
    edges: list[tuple[str, str]] = []

    def _add_edge(src: str, kind: str, label: str, dst: str, tbs: list[dict]) -> None:
        """Append one edge, upgraded to a boundary crossing when `tbs` names
        the resolved boundaries this edge crosses."""
        arrow = attack_arrow if kind == "attack" else legit_arrow
        note = _tb_edge_note(tbs, max_chars) if tbs else ""
        if note:
            arrow, kind, label = cross_arrow, "crossing", f"{label}<br/>{note}"
        edges.append((f'    {src} {arrow}|"{label}"| {dst}', kind))

    # Legit data flow: victim → CLIENT → APP → DATA. The victim → CLIENT hop
    # stays a plain edge on purpose: both ends sit in the untrusted zone, so
    # it crosses nothing — that is the whole point of the CLIENT title.
    victim = next((a["id"] for a in ext_actors if a["css_class"] == "legit"), None)
    if victim and client_node:
        _add_edge(victim, "legit", "HTTPS · TLS", client_node[0], [])
    if client_node and app_node:
        _add_edge(client_node[0], "legit", "REST · JWT Bearer", app_node[0], ingress_tbs)
    # APP → DATA stays a plain legit edge — an internal enforcement point is
    # not the untrusted-zone exit this diagram marks (see _components_crossings).
    if app_node and data_node:
        _add_edge(app_node[0], "legit", "ORM · queries", data_node[0], [])
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
        _add_edge(attacker, "attack", "injection · auth bypass · RCE", app_node[0], ingress_tbs)
    # Attacker → CLIENT is intra-zone: the browser is already on the attacker's
    # side of every server control, so this edge crosses no boundary.
    if attacker and client_node:
        _add_edge(attacker, "attack", "XSS · client tampering · token theft", client_node[0], [])
    if repo and app_node:
        _add_edge(repo, "attack", "leaked credentials · auth bypass", app_node[0], ingress_tbs)

    for edge_line, _kind in edges:
        lines.append(edge_line)

    # ---- classDef block (verbatim from contract) ----
    lines.append("")
    for css_name, css_value in classdefs.items():
        lines.append(f"    classDef {css_name} {css_value}")

    # ---- linkStyle block — one directive per convention, in edge order ----
    for kind, style in (("legit", legit_style), ("attack", attack_style), ("crossing", cross_style)):
        idxs = [i for i, (_line, k) in enumerate(edges) if k == kind]
        if idxs:
            lines.append(f"    linkStyle {','.join(str(i) for i in idxs)} {style}")

    lines.append("```")
    return lines, folded_out


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
    # Several flows between the same pair collapse onto one label here, because
    # the label carries protocol and classification but not each flow's
    # `diagram_label`. Emitting the duplicate draws a second identical line that
    # adds no information (VulnerableApp: login and password-reset both render
    # `client-ui -->|HTTP · Confidential| auth`). One line says the same thing.
    return list(dict.fromkeys(edges))


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
    # No ID column: the A-NNN ids are an internal yaml key with no in-document
    # cross-reference (nothing links to `#a-NNN`), so they are omitted from the
    # rendered table per the agent-prompt layout. compose's _drop_asset_id_column
    # also strips a stray ID column from LLM-authored fragments, so the table
    # shape is 4-col (or 3-col without Linked Threats) everywhere.
    if any_linked:
        lines.append("| Asset | Classification | Description | Linked Threats |")
        # Linked Threats ships `·`-joined BARE `[F-NNN](#f-nnn)` chips here;
        # compose's `_enrich_linked_id_cells` rewrites them to the canonical
        # `[F-NNN](#f-nnn) — title` stacked form (2026-06-02 user request —
        # supersedes the earlier bare-chip-only preference). Emitting bare IDs
        # keeps the short-title as a single source of truth in compose.
        lines.append(_proportional_separator(22, 13, 43, 22))
    else:
        lines.append("| Asset | Classification | Description |")
        lines.append(_proportional_separator(20, 20, 60))
    for idx, a in enumerate(assets, start=1):
        # Auto-assign A-NNN deterministically when the yaml-writer omitted
        # the id field (LLM schema-drift: some orchestrator runs produce
        # assets with name/classification/description but no id) so the name
        # fallback below is always usable, even though the id is no longer a
        # rendered column.
        aid = a.get("id") or f"A-{idx:03d}"
        name = a.get("name", aid)
        clazz = a.get("classification", "_n/a_")
        desc = (a.get("description") or "").replace("\n", " ").strip()
        if any_linked:
            lt = [_to_canonical_finding_label(t) for t in (a.get("linked_threats") or [])]
            # `·`-joined bare chips; compose's `_enrich_linked_id_cells` adds
            # the `— title` labels (2026-06-02 user request).
            lt_cell = " · ".join(f"[{t}](#{t.lower()})" for t in lt) if lt else "—"
            lines.append(f"| {name} | {clazz} | {desc} | {lt_cell} |")
        else:
            lines.append(f"| {name} | {clazz} | {desc} |")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Generator: attack-surface.md
# ---------------------------------------------------------------------------

_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "WS", "ALL", "GRAPHQL"}


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
    # the canonical architecture artifact schema) but legacy yamls and
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
    "graphql-mutation": "GraphQL write/stream operation",
    "graphql-object-access": "GraphQL object lookup",
    "missing-auth": "no auth guard detected",
    "missing-authz": "no authz guard detected",
    "llm": "model/prompt endpoint",
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

    def _displayed_severity(threat: dict) -> str:
        """The severity the reader sees beside a finding link.

        The §8 register basis every finding dot uses
        (`RenderContext._build_severity_index`, RA-20); a second basis here made
        the Risk column contradict the dot in its own row.
        """
        return register_severity(threat) or str(threat.get("impact") or "").strip().title()

    def _entry_risk(entry: dict) -> str:
        """Highest severity across the entry's linked threats. `—` when none."""
        worst_name = ""
        worst_rank = -1
        for ref in entry.get("linked_threats") or entry.get("threats") or []:
            if not isinstance(ref, str):
                continue
            sev = _displayed_severity(threat_by_id.get(ref.strip().upper()) or {})
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
            worst = max(worst, _sev_rank.get(_displayed_severity(threat_by_id.get(ref.strip().upper()) or {}), -1))
        return worst

    # The Notes cell stacks one severity-dotted link per linked finding, so it
    # has to read worst-first. `_derive_attack_surface_links` ranks by how well
    # a finding matches the route — the right question for WHICH findings
    # belong on the row, the wrong one for the order they are shown in, and the
    # cap it applies makes an unordered cell able to hide a Critical.
    def _link_sort_key(ref: str) -> tuple[int, str]:
        sev = _displayed_severity(threat_by_id.get(str(ref).strip().upper()) or {})
        return (-_sev_rank.get(sev, -1), str(ref))

    for entry in unauth + auth:
        if not isinstance(entry, dict):
            continue
        for key in ("linked_threats", "threats"):
            refs = entry.get(key)
            if isinstance(refs, list) and len(refs) > 1 and all(isinstance(r, str) for r in refs):
                entry[key] = sorted(refs, key=_link_sort_key)

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
# §6 Use Cases generator removed 2026-05. The numbering gap (§5 → §6) is
# intentional. Restoration would also need to revert the corresponding
# block in data/sections-contract.yaml and the dispatcher entry in
# scripts/compose_threat_model.py (FRAGMENT_PATHS / sections registry).
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Generator: out-of-scope.md
# ---------------------------------------------------------------------------


def gen_out_of_scope(yaml_data: dict) -> str:
    """## 11. Out of Scope — pulls from meta.scope.out_of_scope or default,
    plus opt-in actor classes the run did not assess (meta.opt_in_actors_not_enabled)
    and team-provided accepted risks from meta.accepted_risks (sourced from
    docs/known-threats.yaml entries with status: accepted)."""
    meta = yaml_data.get("meta") or {}
    out_of_scope = (meta.get("scope") if isinstance(meta.get("scope"), dict) else {}).get("out_of_scope") or [
        "Third-party hosted dependencies and SaaS endpoints",
        "Browser runtime vulnerabilities and end-user device security",
        "Operating system kernel and container runtime",
        "Underlying network infrastructure (DNS, BGP, ISP)",
        "Physical security of hosting facilities",
    ]
    accepted_risks = meta.get("accepted_risks") or []

    lines = ["## 11. Out of Scope", ""]
    # Two different boundaries live in this section. This first block is the
    # method boundary — it holds regardless of the target repository and of the
    # assessment depth, so it is emitted unconditionally and stated before the
    # system-specific exclusions below.
    lines.append("### Not Covered by This Method")
    lines.append("")
    lines.append(f"{METHOD_SENTENCE} It models the system as built rather than as designed. {limits_statement(meta)}")
    lines.append("")
    lines.append(
        "- Design intent and the reasoning behind it — no design documents, ADRs or workshop context are read."
    )
    lines.append(
        "- Business processes and user journeys beyond the supplied business context."
        if business_context_clause(meta)
        else "- Business processes and user journeys that leave the code."
    )
    lines.append("- Runtime behaviour, deployment topology and production-only configuration.")
    lines.append("- External and organizational controls.")
    lines.append("")
    lines.append("Treat this report as review input, not sign-off.")
    lines.append("")
    lines.append("### Excluded from This Assessment")
    lines.append("")
    lines.append(
        "The following items are **explicitly excluded** from this threat model. "
        "Findings against these areas should be tracked separately."
    )
    lines.append("")
    for item in out_of_scope:
        lines.append(f"- {item}")
    not_enabled = [row["scope_note"] for row in meta.get("opt_in_actors_not_enabled") or []]
    if not_enabled:
        notes = [note[:1].lower() + note[1:] for note in dict.fromkeys(not_enabled)]
        lines.append(
            f"- Opt-in threat actors, not assessed: {'; '.join(notes)}. "
            "Enable them with `enable:` in `.appsec/actors.yaml`."
        )
    lines.append("")

    # Components enumerated in the architecture inventory but NOT given a
    # dedicated STRIDE pass at this assessment depth — listed for completeness
    # so the reader knows which components were deliberately not analyzed (and
    # why), sourced deterministically from meta.component_selection.excluded
    # (.stride-selection.json), not LLM prose.
    component_selection = meta.get("component_selection")
    excluded_components = component_selection.get("excluded") or [] if isinstance(component_selection, dict) else []
    if excluded_components:
        analyzed = component_selection.get("analyzed")
        total = component_selection.get("total")
        lines.append("### Components Not Individually Analyzed")
        lines.append("")
        intro = (
            "These components were enumerated in the architecture inventory but did not "
            "receive a dedicated STRIDE pass at this assessment depth"
        )
        if isinstance(analyzed, int) and isinstance(total, int):
            intro += f" ({analyzed} of {total} components analyzed)"
        intro += ". Re-run at a deeper depth to analyze them individually."
        lines.append(intro)
        lines.append("")
        lines.append("| ID | Component | Reason not analyzed |")
        lines.append("|----|-----------|---------------------|")
        for e in excluded_components:
            if not isinstance(e, dict):
                continue
            cid = str(e.get("id") or "—").strip()
            name = str(e.get("name") or cid).strip()
            reason = " ".join(str(e.get("reason") or "not selected at this depth").split()).replace("|", "\\|")
            lines.append(f"| {cid} | {name} | {reason} |")
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
    """Coerce ``security_controls`` to dictionaries for §6 rendering."""
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
# Schema v2 — 13-section §6 control-category layout
# ---------------------------------------------------------------------------

_V2_SUBSECTIONS: tuple[tuple[str, str, str], ...] = (
    # (heading, narrative_hint_for_llm, tier). Tier is retained for backward
    # compatibility with older composer logic; current v2 emits every section.
    (
        "6.1 Security Control Overview",
        "Overview matrix: Control category, Verdict, Main reason. No control IDs and no finding-ID columns.",
        "a",
    ),
    (
        "6.2 Identity and Authentication Controls",
        "Registration, password login, OAuth/OIDC adapters, MFA/TOTP, JWT issuance "
        "and verification, password reset/change.",
        "a",
    ),
    (
        "6.3 Session and Token Controls",
        "Browser token storage, request propagation, token lifetime, revocation, cookie/session boundary.",
        "a",
    ),
    (
        "6.4 Authorization Controls",
        "Route middleware, role checks, object-level authorization, client-side guards versus server-side enforcement.",
        "a",
    ),
    (
        "6.5 Query Construction and Data Access Controls",
        "SQL/NoSQL query construction, ORM usage, parameter binding, selector and object ownership boundaries.",
        "a",
    ),
    (
        "6.6 Input Boundary Validation Controls",
        "Request schemas, parser limits, upload constraints, URL/path validation, business-rule boundaries.",
        "a",
    ),
    (
        "6.7 Output Encoding and Rendering Controls",
        "Template escaping, DOM sinks, sanitizer bypasses, HTML rendering contexts.",
        "a",
    ),
    (
        "6.8 Browser and Cross-Origin Controls",
        "CSP, CORS, CSRF, Helmet/header hardening, browser-side request policy.",
        "a",
    ),
    (
        "6.9 Cryptography Secrets and Data Protection",
        "Signing keys, HMAC/cookie secrets, password storage, data-at-rest protection.",
        "a",
    ),
    (
        "6.10 File Parser and Outbound Request Controls",
        "Uploads, archives, XML parsing, unsafe interpreters, SSRF, redirects, static or management-surface exposure.",
        "a",
    ),
    (
        "6.11 Operations Runtime and Supply Chain Controls",
        "Audit logging, runtime/container hardening, dependency determinism, CI "
        "workflow permissions, package-install controls.",
        "a",
    ),
    (
        "6.12 Real-time and Not Applicable Controls",
        "WebSocket/real-time channels plus compact absent-domain statements.",
        "a",
    ),
    ("6.13 Defense-in-Depth Summary", "Cross-cutting summary of layered controls and residual architecture risk.", "a"),
)


# M5b — Default H4 mechanism name per §6.X. Used by the fallback branch
# in `gen_security_architecture_v2` when a section has no catalogued
# security_controls[] but DOES carry routed findings. Names match the
# reference threat-model.md so generated reports converge on the same
# vocabulary. The pregenerator falls back to a heading-derived noun phrase
# (`heading.split(" ", 1)[1]`) when a section is not listed here.
_V2_DEFAULT_MECHANISM: dict[str, str] = {
    "6.2 Identity and Authentication Controls": "Identity and Authentication Mechanisms",
    "6.3 Session and Token Controls": "Browser Token Storage and Request Propagation",
    "6.4 Authorization Controls": "Route and Object Authorization",
    "6.5 Query Construction and Data Access Controls": "Query Construction",
    "6.6 Input Boundary Validation Controls": "Validation Approach",
    "6.7 Output Encoding and Rendering Controls": "Output Encoding and Client-Side Rendering",
    "6.8 Browser and Cross-Origin Controls": "Browser Security Headers and CORS/CSRF Posture",
    "6.9 Cryptography Secrets and Data Protection": "Secret Management and Data Protection",
    "6.10 File Parser and Outbound Request Controls": "File Parser and Outbound Request Handling",
    "6.11 Operations Runtime and Supply Chain Controls": "Logging, Runtime and Supply Chain Posture",
    "6.12 Real-time and Not Applicable Controls": "Real-time WebSocket Channel",
}


# §6.6 general validation-approach heading detector. Mirrors the contract's
# `validation_approach_first.approach_heading_patterns` so the pregenerator
# does not double-inject when Stage-1 already supplied an approach-named row.
_V2_APPROACH_FIRST_RE = re.compile(
    r"(?i)\b(validation approach|validation strategy"
    r"|(input )?validation (model|architecture|posture)"
    r"|(central|centralized|centralised|schema)[- ]?based validation"
    r"|schema validation)\b"
)


# CWE → §6.X routing table — mirrors sections-contract.yaml schema_v2
# finding_routing. Kept here as a static map so the pregenerator does not
# need to parse the YAML contract.
_V2_CWE_ROUTING: dict[str, str] = {
    "CWE-287": "6.2 Identity and Authentication Controls",
    "CWE-307": "6.2 Identity and Authentication Controls",
    "CWE-294": "6.2 Identity and Authentication Controls",
    "CWE-345": "6.2 Identity and Authentication Controls",
    "CWE-347": "6.2 Identity and Authentication Controls",
    "CWE-620": "6.2 Identity and Authentication Controls",
    "CWE-640": "6.2 Identity and Authentication Controls",
    "CWE-916": "6.2 Identity and Authentication Controls",
    "CWE-922": "6.3 Session and Token Controls",
    "CWE-384": "6.3 Session and Token Controls",
    "CWE-613": "6.3 Session and Token Controls",
    "CWE-1004": "6.3 Session and Token Controls",
    "CWE-285": "6.4 Authorization Controls",
    "CWE-639": "6.4 Authorization Controls",
    "CWE-269": "6.4 Authorization Controls",
    "CWE-862": "6.4 Authorization Controls",
    "CWE-863": "6.4 Authorization Controls",
    "CWE-732": "6.4 Authorization Controls",
    "CWE-352-authz": "6.4 Authorization Controls",
    "CWE-602": "6.4 Authorization Controls",
    "CWE-915": "6.4 Authorization Controls",
    "CWE-89": "6.5 Query Construction and Data Access Controls",
    "CWE-943": "6.5 Query Construction and Data Access Controls",
    "CWE-20": "6.6 Input Boundary Validation Controls",
    "CWE-1284": "6.6 Input Boundary Validation Controls",
    "CWE-1287": "6.6 Input Boundary Validation Controls",
    "CWE-400": "6.6 Input Boundary Validation Controls",
    "CWE-79": "6.7 Output Encoding and Rendering Controls",
    "CWE-80": "6.7 Output Encoding and Rendering Controls",
    "CWE-87": "6.7 Output Encoding and Rendering Controls",
    "CWE-116": "6.7 Output Encoding and Rendering Controls",
    "CWE-1021": "6.8 Browser and Cross-Origin Controls",
    "CWE-942": "6.8 Browser and Cross-Origin Controls",
    "CWE-693": "6.8 Browser and Cross-Origin Controls",
    "CWE-358": "6.8 Browser and Cross-Origin Controls",
    "CWE-352": "6.8 Browser and Cross-Origin Controls",
    "CWE-321": "6.9 Cryptography Secrets and Data Protection",
    "CWE-798": "6.9 Cryptography Secrets and Data Protection",
    "CWE-327": "6.9 Cryptography Secrets and Data Protection",
    "CWE-326": "6.9 Cryptography Secrets and Data Protection",
    "CWE-329": "6.9 Cryptography Secrets and Data Protection",
    "CWE-330": "6.9 Cryptography Secrets and Data Protection",
    "CWE-312": "6.9 Cryptography Secrets and Data Protection",
    "CWE-538": "6.9 Cryptography Secrets and Data Protection",
    "CWE-759": "6.9 Cryptography Secrets and Data Protection",
    "CWE-611": "6.10 File Parser and Outbound Request Controls",
    "CWE-22": "6.10 File Parser and Outbound Request Controls",
    "CWE-23": "6.10 File Parser and Outbound Request Controls",
    "CWE-409": "6.10 File Parser and Outbound Request Controls",
    "CWE-776": "6.10 File Parser and Outbound Request Controls",
    "CWE-94": "6.10 File Parser and Outbound Request Controls",
    "CWE-95": "6.10 File Parser and Outbound Request Controls",
    "CWE-918": "6.10 File Parser and Outbound Request Controls",
    "CWE-601": "6.10 File Parser and Outbound Request Controls",
    "CWE-441": "6.10 File Parser and Outbound Request Controls",
    "CWE-548": "6.10 File Parser and Outbound Request Controls",
    "CWE-552": "6.10 File Parser and Outbound Request Controls",
    "CWE-749": "6.10 File Parser and Outbound Request Controls",
    "CWE-200": "6.10 File Parser and Outbound Request Controls",
    "CWE-117": "6.11 Operations Runtime and Supply Chain Controls",
    "CWE-223": "6.11 Operations Runtime and Supply Chain Controls",
    "CWE-209": "6.11 Operations Runtime and Supply Chain Controls",
    "CWE-532": "6.11 Operations Runtime and Supply Chain Controls",
    "CWE-778": "6.11 Operations Runtime and Supply Chain Controls",
    "CWE-1104": "6.11 Operations Runtime and Supply Chain Controls",
    "CWE-1395": "6.11 Operations Runtime and Supply Chain Controls",
    "CWE-937": "6.11 Operations Runtime and Supply Chain Controls",
    "CWE-829": "6.11 Operations Runtime and Supply Chain Controls",
    "CWE-250": "6.11 Operations Runtime and Supply Chain Controls",
    "CWE-15": "6.11 Operations Runtime and Supply Chain Controls",
    "CWE-260": "6.11 Operations Runtime and Supply Chain Controls",
    "CWE-1385": "6.12 Real-time and Not Applicable Controls",
    # 2026-07-19 — routing gaps found while diagnosing the recurring §6 repair
    # loop. An unrouted CWE contributes nothing to `routed_here`, which is one
    # of the guards deciding whether a Missing control still earns an H4 block;
    # on an AI/LLM codebase 17 of 49 findings landed here (CWE-1336 x5, CWE-74
    # x4, ...), so whole §6 sections saw zero routed findings. Each entry below
    # is placed with its existing siblings: injection-to-RCE classes join
    # CWE-94/95 in §6.10, missing/spoofed authn joins CWE-287 in §6.2,
    # resource-exhaustion joins CWE-400 in §6.6.
    "CWE-306": "6.2 Identity and Authentication Controls",
    "CWE-290": "6.2 Identity and Authentication Controls",
    "CWE-284": "6.4 Authorization Controls",
    "CWE-74": "6.6 Input Boundary Validation Controls",
    "CWE-770": "6.6 Input Boundary Validation Controls",
    "CWE-78": "6.10 File Parser and Outbound Request Controls",
    "CWE-502": "6.10 File Parser and Outbound Request Controls",
    "CWE-1336": "6.10 File Parser and Outbound Request Controls",
    "CWE-359": "6.10 File Parser and Outbound Request Controls",
    "CWE-494": "6.11 Operations Runtime and Supply Chain Controls",
}


def _render_threat_hypotheses_table(yaml_data: dict) -> list[str]:
    """Render the §6.2 validation table for unpromoted architecture hypotheses."""
    hypotheses = yaml_data.get("threat_hypotheses") or []
    unpromoted = [h for h in hypotheses if isinstance(h, dict) and not h.get("promoted_threat_id")]
    if not unpromoted:
        return []

    # Emit the explicit name-slug anchor the §6.2 "Controls covered" bullet
    # links to. Real controls get this <a id> from _emit_v2_grouped_control;
    # this pseudo-control heading previously had none, so its Controls-covered
    # bullet `[Threat Hypotheses Requiring Validation](#threat-hypotheses-requiring-validation)`
    # dangled (juice-shop 2026-07-02).
    lines: list[str] = [
        f'<a id="{_v2_slug("Threat Hypotheses Requiring Validation")}"></a>',
        "#### Threat Hypotheses Requiring Validation",
        "",
        "**Status:** 🟡 Partial — architecture-derived control gaps not yet source-to-sink proven; treat as leads requiring a validate-or-refute pentest probe before promotion to a finding.",
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
    """Compose the trailing " — <Verdict>" suffix for a §6.X heading.

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


_V2_ANCHOR_ID_RE = re.compile(r'<a id="([^"]+)"></a>')


def _v2_anchor_ids(lines: list, *slugs: str) -> list[str]:
    """Side-anchor ids for one §6 H4, minus any already emitted into `lines`.

    Two controls whose names differ only by a trailing parenthetical collapse
    to the same friendly title — `JWT Verification (Legacy / Unsigned)` and
    `JWT Verification (Signed / SignedJwtService)` both become
    `JWT Verification` — so the friendly side anchor was emitted twice and
    `qa_checks.check_toc_contract` reported `duplicate explicit anchor id:
    #jwt-verification appears 2 times` (2026-08-21 insecure-large-spring-app).

    The name-derived slug is unique per control and always survives; only the
    already-taken duplicate is dropped. The first block therefore keeps the
    short link target and no anchor upstream links depend on is lost.
    """
    emitted = {a for line in lines for a in _V2_ANCHOR_ID_RE.findall(line)}
    return sorted({s for s in slugs if s} - emitted)


def _v2_slug(title: str) -> str:
    """Anchor slug used by the v2 §6 scaffold.

    Delegates to `scripts/_slug.py::github_slug` so the pregenerator,
    composer, and qa_checks emit byte-identical slugs. The previous
    inline `[^a-z0-9]+` collapse silently produced different slugs than
    the GitHub renderer for headings containing `&`, `@`, `+`, `(`, `)`,
    which was the proximate cause of the §6 `#h4-*` TOC drift bug.
    """
    from _slug import github_slug as _gh

    slug = _gh(title or "")
    return slug or "control"


_V2_CONTROL_HINTS: dict[str, tuple[str, ...]] = {
    # 2026-05 R-6/R-7 fix — hints sharpened so they are mutually exclusive
    # when matched against `control.domain`. Previously "auth" appeared in
    # §6.2 and matched both `authentication` and `authorization` domains,
    # leaking authorization controls into §6.2. Likewise "management" in
    # §6.10 matched "secrets-management" leaking secrets controls into §6.10.
    "6.2 Identity and Authentication Controls": (
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
    "6.3 Session and Token Controls": (
        "session",
        "token-storage",
        "cookie",
        "localstorage",
        "browser-storage",
    ),
    "6.4 Authorization Controls": (
        "authorization",
        "access-control",
        "rbac",
        "object-level",
        "ownership",
    ),
    "6.5 Query Construction and Data Access Controls": (
        "query",
        "sql",
        "nosql",
        "orm",
        "data-access",
    ),
    "6.6 Input Boundary Validation Controls": (
        "input-validation",
        "schema-validation",
        "upload-validation",
        "request-body",
        "parser-limit",
        "rate-limiting",
    ),
    "6.7 Output Encoding and Rendering Controls": (
        "output-encoding",
        "render",
        "xss",
        "sanit",
        "dom-sanit",
    ),
    "6.8 Browser and Cross-Origin Controls": (
        "browser",
        "csp",
        "cors",
        "csrf",
        "helmet",
        "security-headers",
        "cors-csrf",
    ),
    "6.9 Cryptography Secrets and Data Protection": (
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
    "6.10 File Parser and Outbound Request Controls": (
        "file-security",
        "file-parser",
        "xml-parser",
        "archive",
        "ssrf",
        "redirect-allow",
    ),
    "6.11 Operations Runtime and Supply Chain Controls": (
        "audit",
        "logging-monitor",
        "logging-monitoring",
        "runtime",
        "container",
        "dependency",
        "supply-chain",
        "ci-cd",
    ),
    "6.12 Real-time and Not Applicable Controls": (
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
    """Return the SINGLE canonical §6 heading a control belongs to.

    2026-05 R-6/R-7 fix: hint matching is non-exclusive (e.g. a control with
    `domain=secrets-management` matched both §6.9 (`secret`) and §6.10
    (`management`), so the same H4 block was emitted in two sections — with
    identical `<a id="…">` anchors → duplicate-anchor warnings, controls
    duplicated across §6 categories, and inconsistent verdict-counting).

    Resolution priority:
      1. Explicit ``section`` / ``v2_section`` field on the control.
      2. Match against the control's ``domain`` field FIRST (specific —
         "cryptography" cleanly resolves to §6.9, not §6.2 via "password"
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
        # Exact canonical-title match FIRST. Stage 1 writes the §6 section's
        # human-readable title verbatim as the control's domain (e.g. "File
        # Parser and Outbound Request Controls"); match it against each
        # heading minus its "7.X " number prefix. This is collision-free,
        # unlike the hyphenated hint substrings — `_V2_CONTROL_HINTS` uses
        # tokens like `file-parser` / `upload-validation` that never match a
        # space-form domain, so a control whose NAME also carries no hint
        # token (e.g. "File Upload Validation") used to route to NO section
        # and was dropped from §6 entirely (juice-shop 2026-06-01 §6.10 "no
        # #### found"). It also avoids the substring trap where the §6.4 hint
        # `access-control` matches the §6.5 domain "...Data Access Controls".
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
    """Return the subset of controls whose canonical §6 section is ``heading``.

    Each control resolves to AT MOST one heading via
    ``_v2_canonical_section_for_control``; this guarantees that the same
    sub-control title never appears in two different §6 categories.
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
    # 2026-05 (user-request point 4): align §6 H4 titles with OWASP ASVS
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
    """Return a more reader-friendly version of a §6 H4 subcontrol title.

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


# `implementation` is meant to be the block's prose paragraph, but the control
# analyst fills it with a file-reference list on most rows (16 of 20 controls,
# juice-shop 2026-08-27). Emitting that verbatim put a bare `lib/insecurity.ts`
# where a sentence belongs; the renderer then wrote its own paragraph naming the
# same file directly below, because the scaffold is preserved and it had no
# placeholder to fill. The reference shipped twice — 8 orphan lines and 2
# comma-runs of up to eleven paths in one report. Route a reference list to the
# narrative placeholder instead, which asks for exactly the missing sentence.
#
# Deliberately strict: a space anywhere makes it prose, so "Implemented in
# lib/insecurity.ts" and "See routes/login.ts" pass through untouched. Callers
# must keep using the raw field for suppression decisions — this only governs
# whether the value is emitted AS the paragraph.
_V2_FILE_REF_RE = re.compile(r"^\.?[\w.-]+(?:/[\w.-]+)*\.[A-Za-z]\w{0,9}(?::\d+(?:[-,]\d+)*)?$")


def _v2_is_file_ref_list(text: str) -> bool:
    """True when `text` is only comma-separated file references, not prose."""
    parts = [p.strip() for p in text.split(",")]
    return bool(parts) and all(p and _V2_FILE_REF_RE.fullmatch(p) for p in parts)


def _v2_status_line(eff: str, note: str = "") -> str:
    """Build the per-sub-control `**Status:**` badge line for §6 H4 blocks.

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
    if impl and not _v2_is_file_ref_list(impl):
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
    # §6.2 flow block, and "Password-Based Authentication" matches the
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
    elif heading.startswith("6.2 "):
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
    """Emit one §6.x #### block from a `security_controls[].subcontrols[]` entry.

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
    # mirror the §2.4 / §6.3 convention (the latter has had numbered H4 for
    # IAM flow blocks since the schema-v2 contract; the rest of §6 was a
    # legacy gap). When section_id/idx are not provided (older call sites),
    # fall back to bare `#### <title>` so behaviour stays compatible.
    #
    # Side anchors are emitted with BOTH the original-name slug AND the
    # friendly-title slug, so links built upstream from either spelling
    # resolve. The numbered heading itself slugifies to e.g.
    # `#721-jwt-authentication` (which would not match `**Controls
    # covered:**` link targets); the side anchors close that gap.
    if section_id and idx:
        anchors = _v2_anchor_ids(lines, _v2_slug(original_title), _v2_slug(title))
        # All anchors on ONE line: stacked empty <a id> lines render with
        # inconsistent vertical gaps before a heading (1 vs 2 anchors → uneven
        # whitespace, 2026-05-30 user "spacing" fix).
        if anchors:
            lines.append("".join(f'<a id="{s}"></a>' for s in anchors))
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
    if impl and not _v2_is_file_ref_list(impl):
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
        # Heuristic fallback: route findings by CWE → §6.x → take top 3.
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
# `sections-contract.yaml → schema_v2.domain_required_rules → '6.2' →
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
    lines: list,
    c: dict,
    name: str,
    threats: list,
    heading: str,
    section_id: str = "",
    idx: int = 0,
    force: bool = False,
) -> bool:
    """Legacy single-block-per-control shape — used when subcontrols[] is empty.

    Pre-R9 Stage-1 outputs emit one row per control without subcontrol
    decomposition. We keep this fallback so older yaml inputs still
    produce a valid §6 fragment. The block still benefits from the
    expanded placeholder set (positive-case intro + sequenceDiagram for
    flow-like names + assessment + bullet findings) so the LLM has the
    same depth target as the subcontrol pathway.

    Returns ``True`` when an H4 block was emitted, ``False`` when the
    control was suppressed (effectiveness=Missing AND no linked threats —
    nothing meaningful to anchor a paragraph to; the parent §6.x
    Assessment block can summarise the absence in one sentence).
    """
    # Fix 5 — suppress H4 when the control has nothing important to
    # explain. "Missing" effectiveness with zero linked threats means the
    # whole block would degrade into "this control is not implemented in
    # this codebase" filler. The controls table at the top of the parent
    # §6.x section already lists the control as Missing; an additional
    # H4 below adds zero information.
    eff = (c.get("effectiveness") or "").strip().lower()
    linked = c.get("linked_threats") or []
    if isinstance(linked, str):
        linked = [linked]
    impl_text = (c.get("implementation") or "").strip()
    # A "Missing" control whose OWN linked_threats is empty is still worth an
    # H4 when findings route to this §6 category via CWE: the reader needs to
    # see the absent control next to the findings it would have blocked, and
    # qa_checks.check_control_subsection_coverage requires a #### per populated
    # category (a category with catalogued controls but zero H4 trips the
    # strict gate → the recurring §6 REPAIR_MODE loop). Only suppress when
    # there is genuinely nothing to anchor — no own links, no implementation
    # prose, AND no CWE-routed finding for this section.
    #
    # `force=True` is the caller's "this block is structurally required"
    # override: the §6.x section would otherwise ship ZERO H4 blocks (see the
    # all-suppressed re-emit below), which trips the coverage gate the
    # paragraph above is trying to stay clear of. Structural coverage wins
    # over the anti-filler heuristic.
    routed_here = _v2_finding_links(threats, heading, max_links=1)
    if not force and eff == "missing" and not linked and not impl_text and not routed_here:
        return False

    title = _friendly_subcontrol_title(name)
    # Emit BOTH the original-name slug AND the friendly-title slug as side
    # anchors so links from `**Controls covered:**` resolve regardless of
    # which spelling the upstream link-builder chose. The numbered heading
    # itself slugifies differently (e.g. `#721-jwt-authentication`); the
    # side anchors close that gap.
    if section_id and idx:
        anchors = _v2_anchor_ids(lines, _v2_slug(name), _v2_slug(title))
        # All anchors on ONE line: stacked empty <a id> lines render with
        # inconsistent vertical gaps before a heading (1 vs 2 anchors → uneven
        # whitespace, 2026-05-30 user "spacing" fix).
        if anchors:
            lines.append("".join(f'<a id="{s}"></a>' for s in anchors))
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
    if impl_text and not _v2_is_file_ref_list(impl_text):
        # Stage 1 supplied an implementation paragraph — use it verbatim;
        # the LLM does not need to author a placeholder. A bare file-reference
        # list is not that paragraph and falls through to the placeholder.
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
# §6.2 Authentication Mechanisms inventory (2026-05-31 — deterministic).
#
# schema_v2 catalogues controls by domain — identity/login → §6.2,
# session/token (JWT) → §6.3, password hashing → §6.9 — so the §6.2 section
# only ever decomposes the control(s) Stage-1 filed under the identity domain
# (usually just "Password Login"). That made §6.2 read "thinned out": OAuth /
# JWT / MFA were either elsewhere or absent. This inventory is a DETERMINISTIC
# table emitted at the top of §6.2 that reconstructs the COMPLETE authentication
# surface from the yaml (controls + threats + meta) — status, where it is
# assessed (§6.2/§6.3/§6.9), and linked findings — independent of the LLM
# scaffold-fill. Mechanisms checked but absent are named in a trailing note so
# "no OAuth" is explicit, not silent. Built from data + frozen → an LLM author
# cannot thin it out on a later run. That is the whole point.
# ---------------------------------------------------------------------------

# `section` = the §6 subsection where the mechanism's controls are catalogued
# (drives the "Assessed in" link). `control_kw` / `threat_kw` are lowercase
# substrings matched against control name+domain / threat title+cwe. `meta_flag`
# marks the mechanism present from a meta boolean alone.
_AUTH_MECHANISM_SPECS: list[dict] = [
    {
        "name": "User registration",
        "section": "6.2",
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
        "section": "6.2",
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
        "section": "6.2",
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
        "section": "6.9",
        "control_kw": ["password hashing", "credential storage", "hashing"],
        "threat_kw": ["md5", "password hash", "unsalted", "bcrypt", "scrypt", "argon2"],
    },
    {
        "name": "JWT / bearer-token session",
        "section": "6.3",
        "control_kw": ["jwt", "session token validation", "bearer", "token validation"],
        "threat_kw": ["jwt", "json web token", "bearer token", "alg:none", "algorithm confusion", "token forgery"],
    },
    {
        "name": "Session-token storage",
        "section": "6.3",
        "control_kw": ["session token storage", "token storage"],
        "threat_kw": ["localstorage", "local storage", "session theft", "token stored", "httponly"],
    },
    {
        "name": "Multi-factor authentication (TOTP / 2FA)",
        "section": "6.2",
        "control_kw": ["totp", "2fa", "mfa", "multi-factor", "multi factor", "two-factor", "two factor"],
        "threat_kw": ["totp", "2fa", "two-factor", "two factor", "mfa", "multi-factor", "one-time password"],
    },
    {
        "name": "OAuth / OIDC federated login",
        "section": "6.2",
        "control_kw": ["oauth", "oidc", "openid", "sso", "saml", "federated", "social login"],
        "threat_kw": ["oauth", "oidc", "openid", "saml", "single sign-on", "social login"],
    },
]

_AUTH_INV_SECTION_TITLES = {
    "6.2": "6.2 Identity and Authentication Controls",
    "6.3": "6.3 Session and Token Controls",
    "6.9": "6.9 Cryptography Secrets and Data Protection",
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


def _auth_mech_finding_sort_key(threat: dict) -> tuple[int, int]:
    """Order findings worst-severity first, then by numeric id."""
    sev = register_severity(threat).lower()
    m = re.search(r"(\d+)$", (threat.get("id") or threat.get("t_id") or "").strip())
    return (-_AUTH_INV_RISK_RANK.get(sev, 0), int(m.group(1)) if m else 10**6)


def _auth_mech_finding_link(threat: dict) -> str | None:
    raw = (threat.get("id") or threat.get("t_id") or "").strip()
    m = re.search(r"(\d+)$", raw)
    if not m:
        return None
    n = int(m.group(1))
    # Carry the finding TITLE, not a bare ID — the §6.2 inventory is a table,
    # so compose's prose-linkifier never enriches it, leaving "leer betitelt"
    # links (2026-06-02 user report). Per the no-bare-ID rule every F-ref must
    # show a short title. Use the finding's own title (already concise:
    # "<weakness> via <surface>").
    title = (threat.get("title") or "").strip()
    link = f"[F-{n:03d}](#f-{n:03d})"
    return f"{link} — {title}" if title else link


def _build_auth_mechanism_inventory(yaml_data: dict) -> list[str]:
    """Deterministic §6.2 'Authentication mechanisms' inventory block (markdown
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
        # Worst first — the cell is capped at 6 links, so id order both reads
        # as an unsorted mix of severity circles and can hide a Critical
        # behind six lower-severity findings.
        for t in sorted(m_threats, key=_auth_mech_finding_sort_key):
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

    sec73 = _v2_slug(_AUTH_INV_SECTION_TITLES["6.3"])
    sec79 = _v2_slug(_AUTH_INV_SECTION_TITLES["6.9"])
    out: list[str] = []
    out.append("<!-- §6.2 AUTH-MECHANISMS-FROZEN — deterministic inventory, pregenerator-owned. DO NOT EDIT. -->")
    out.append(
        "**Authentication mechanisms (at a glance).** Every authentication mechanism "
        "detected on the application, its effective status, where it is assessed, and its "
        "linked findings. Controls are catalogued by domain, so JWT/session handling is "
        f"assessed under [§6.3 Session and Token Controls](#{sec73}) and password hashing "
        f"under [§6.9 Cryptography Secrets and Data Protection](#{sec79})."
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
    out.append("<!-- §6.2 AUTH-MECHANISMS-FROZEN END -->")
    out.append("")
    return out


# Placeholder line for the `**Controls covered:**` link list inside
# gen_security_architecture_v2. It is rewritten from the H4 headings actually
# emitted in each §6.x block AFTER the subcontrol loop runs, so a suppressed
# control can never leave a dangling link in the covered-list.
_COVERED_SENTINEL = "<!-- __CONTROLS_COVERED_SENTINEL__ -->"

_V2_REALTIME_HINTS = ("websocket", "web socket", "socket.io", "socketio", "real-time", "realtime")
_V2_RPC_SURFACES = (("graphql", "GraphQL API Security"), ("grpc", "gRPC Service Security"))


def _v2_special_surfaces(yaml_data: dict) -> list[str]:
    """Name the real-time, LLM, GraphQL and gRPC surfaces the model contains.

    §6.12 used to collapse to "Not applicable … no AI/LLM surfaces detected"
    whenever no finding routed there by CWE, contradicting a report with a
    Socket.IO server and LLM findings (juice-shop 2026-09-11). A modelled
    component or an LLM-tagged finding is a surface; a recon-only mention such
    as a package.json dependency is not.
    """
    components = [c for c in yaml_data.get("components") or [] if isinstance(c, dict)]
    threats = [t for t in yaml_data.get("threats") or [] if isinstance(t, dict)]
    blobs = [" ".join(str(c.get(key) or "") for key in ("id", "name", "framework")).lower() for c in components]
    surfaces = []
    if any(hint in blob for blob in blobs for hint in _V2_REALTIME_HINTS):
        surfaces.append("Real-Time Channel Security")
    if any(_is_llm_component(c) for c in components) or any(t.get("owasp_llm_ids") for t in threats):
        surfaces.append("LLM Integration Security")
    surfaces.extend(label for hint, label in _V2_RPC_SURFACES if any(hint in blob for blob in blobs))
    return surfaces


def gen_security_architecture_v2(yaml_data: dict, depth: str = "standard") -> str:
    """13-section §6 scaffold for the v2 security-architecture contract.

    The scaffold follows the rendered v2 shape: a control-category overview,
    then one section per security-control category. Domain sections use
    Verdict / Controls covered / Implemented controls / Assessment labels and
    H4 subcontrols with Security assessment + Relevant findings blocks.
    """
    quick_depth = (depth or "").strip().lower() == "quick"
    controls = _normalize_security_controls(yaml_data.get("security_controls"))
    threats = yaml_data.get("threats") or []
    special_surfaces = _v2_special_surfaces(yaml_data)

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

    lines = ["## 6. Security Architecture", ""]
    lines.append(
        "This chapter is organized by security-control category. The architecture "
        "section avoids artificial control IDs and finding-ID columns in overview "
        "tables. Findings are listed only where the affected control is described."
    )
    lines.append("")
    lines.append(
        f"_§6 schema v2 (13-section control-category layout). Cataloged "
        f"controls: {len(controls)} total — {n_adequate} adequate, "
        f"{n_partial} partial, {n_weak} weak, {n_unsafe} unsafe, "
        f"{n_missing} missing. Linked threats: {len(threats)}._"
    )
    lines.append("")
    # Verdict legend — the two red verdicts are not interchangeable, and the
    # distinction tells the reader whether to FIX an existing control or ADD a
    # new one. Emitted once, deterministically, so every §6 reader has the key.
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
    lines.append("### 6.1 Security Control Overview")
    lines.append("")
    # R5 / LOCKED — §6.1 is mechanically derived from security_controls[] +
    # threats_by_section[]. Pregenerator owns it; the LLM renderer MUST NOT
    # re-author this block. The HTML comment markers below are inspected by
    # the renderer prompt and by qa_checks.check_section_71_locked (when
    # active) to verify the block survived round-trips.
    lines.append("<!-- §6.1 MECHANICAL-FROZEN — DO NOT EDIT (overview table is pregenerator-owned) -->")
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
        # belong in the §6.X prose, not in the overview row. The renderer
        # prompt repeats this rule under "No code in finding titles, Top-
        # Findings cells, or §6.1 Main reason cells".
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
            # (2026-06-02: §6.1 showed it on every category).
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
        # Link text carries the section number (e.g. "6.2 Identity and
        # Authentication Controls") so the overview reads as a numbered map.
        lines.append(f"| [{h}](#{_v2_slug(h)}) | {verdict} | {reason} |")
    lines.append("")
    lines.append("<!-- §6.1 MECHANICAL-FROZEN END -->")
    lines.append("")

    for heading, hint, _tier in _V2_SUBSECTIONS[1:]:
        lines.append(f"### {heading}")
        lines.append("")
        # Index where THIS section's body begins — used by the section-scoped
        # sequenceDiagram guarantee at the end of the loop body.
        section_start = len(lines)

        if heading.startswith("6.13 "):
            # R7 — §6.13 is prose-only. Two paragraphs:
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
                "<!-- §6.13 FORMAT — prose-only, NEVER a table. Two short paragraphs: (1) name the individual controls that exist and the strongest positive control if any (e.g. distroless runtime image, RS256 algorithm choice); (2) name which control-boundary repairs would restore layered defense (e.g. parameterized queries, runtime-injected secrets, strict JWT verification). Do NOT emit a Markdown table — `| header |` lines under §6.13 are a contract violation. Do NOT make speculative perimeter-absence claims (`No WAF`, `No firewall`, `No DAM`) — only positive evidence from the recon scan. -->"
            )
            lines.append("")
            lines.append(f"<!-- NARRATIVE_PLACEHOLDER: §{heading} — {hint} (prose paragraphs only) -->")
            lines.append("")
            continue

        # Fix 1 — §6.12 Not-Applicable stub. The section is reserved for
        # real-time / WebSocket controls AND a catch-all for absent domains
        # (AI/LLM, GraphQL, gRPC) the report should explicitly acknowledge.
        # When no finding routes to §6.12 via the CWE mapping AND the model
        # has none of those surfaces (`_v2_special_surfaces`), the section
        # has nothing real to say — even if a control was mis-routed here
        # (e.g. Container Hardening mapping to §6.12 instead of §6.11), it
        # belongs in its primary domain section, not in a category about
        # real-time channels. Emit a single italic line and skip the rest
        # so the rendered report does not carry filler prose like "No
        # dedicated WebSocket security finding was derived". The mirror
        # logic already exists for §6.8 / §6.9 in the v1 path at line
        # ~3657; this is the v2 equivalent.
        if heading.startswith("6.12 "):
            domain_links = _v2_finding_links(threats, heading, max_links=1)
            if not domain_links and not special_surfaces:
                # LOCKED marker is the renderer agent's signal to leave the
                # stub alone. Without it, the LLM tends to "improve" the
                # one-liner by acknowledging tools it sees in recon (e.g.
                # socket.io in package.json), which defeats the whole point
                # of collapsing this section to one line.
                lines.append(
                    "<!-- §6.12 LOCKED — mechanically derived: no routed finding "
                    "and no real-time, LLM, GraphQL, or gRPC component in the "
                    "model. Renderer must not rewrite the line below. -->"
                )
                lines.append(
                    "_Not applicable — no finding routed to this category, and "
                    "the architecture model contains no real-time / WebSocket, "
                    "AI/LLM, GraphQL, or gRPC component. Controls catalogued "
                    "elsewhere (container hardening, dependency determinism) "
                    "are covered in their primary §6 sections._"
                )
                lines.append("")
                continue

        section_controls = _v2_controls_for_heading(controls, heading)
        control_names = [(c.get("control") or c.get("name") or c.get("domain") or "").strip() for c in section_controls]
        control_names = [name for name in control_names if name]
        implemented = [
            (c.get("implementation") or "").strip() for c in section_controls if (c.get("implementation") or "").strip()
        ]

        # §6.2 and §6.3 carry domain_required_patterns in schema_v2: each
        # section must contain a `sequenceDiagram`. Minimal fixtures and sparse
        # Stage-1 outputs can legitimately have no catalog row yet, but the
        # scaffold must still give the renderer a structurally valid flow block
        # to fill instead of composing a fragment that fails before repair.
        if heading.startswith("6.2 ") and not control_names:
            section_controls = [
                {
                    "control": "Password Login",
                    "name": "Password Login",
                    "effectiveness": "",
                    "implementation": "",
                    "subcontrols": [],
                }
            ]
            control_names = ["Password Login"]
        elif heading.startswith("6.3 ") and not control_names:
            section_controls = [
                {
                    "control": "JWT Session Issuance and Verification",
                    "name": "JWT Session Issuance and Verification",
                    "effectiveness": "",
                    "implementation": "",
                    "subcontrols": [],
                }
            ]
            control_names = ["JWT Session Issuance and Verification"]
        elif heading.startswith("6.12 ") and not control_names and special_surfaces:
            # One block per modelled surface, so the renderer describes the
            # controls the collapsed stub used to deny.
            section_controls = [
                {"control": name, "name": name, "effectiveness": "", "implementation": "", "subcontrols": []}
                for name in special_surfaces
            ]
            control_names = list(special_surfaces)

        # §6.6 must OPEN with a general validation-approach block before the
        # specific boundary sub-blocks (contract: validation_approach_first).
        # Inject a synthetic FIRST subcontrol so the scaffold satisfies the
        # gate deterministically and the renderer fills the strategy prose
        # instead of running against the gate. Skipped when Stage-1 already
        # supplied an approach-named row as the first §6.6 control.
        if heading.startswith("6.6 ") and not (control_names and _V2_APPROACH_FIRST_RE.search(control_names[0])):
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
        # when the §6.x block ends up with ZERO H4s (it skips heading-less
        # blocks). We therefore emit a SENTINEL here and rewrite it AFTER the
        # H4 loop below from the headings actually emitted — so the line is
        # correct by construction. (juice-shop 2026-06-01 §6.10 all-suppressed
        # case + the enriched-path dangling-link repair loop.)
        covered_idx: int | None = None
        if control_names:
            lines.append(
                "<!-- The line below is mechanically derived from the controls table — LLM must not re-author it. -->"
            )
            covered_idx = len(lines)
            lines.append(_COVERED_SENTINEL)
        else:
            # Empty security_controls[] for this §6.x. When findings ARE routed
            # (the case-(b) fallback below emits a single
            # `#### {section}.1 {default_mech}` block), emit a MECHANICAL, LOCKED
            # `**Controls covered:**` line linking to exactly that heading so the
            # link↔heading pair is consistent by construction. The old free-form
            # NARRATIVE_PLACEHOLDER here invited the renderer to invent control
            # links (CORS/CSRF/CSP) with no matching #### blocks, which trips
            # qa_checks.check_control_subsection_coverage (§6.8 RC, 2026-06-21
            # juice-shop run). When NO findings are routed (case a) the section
            # ships a `_Not applicable_` stub the gate skips, and at quick depth
            # the section is dropped entirely at the `quick_depth` guard below —
            # both keep the legacy placeholder (harmless, never gate-checked).
            _fb_links = _v2_finding_links(threats, heading, max_links=5)
            if _fb_links and not quick_depth:
                _fb_mech_raw = _V2_DEFAULT_MECHANISM.get(heading, heading.split(" ", 1)[1])
                _fb_mech = _friendly_subcontrol_title(_fb_mech_raw)
                lines.append(
                    "<!-- The line below is mechanically derived from the section's "
                    "default mechanism — LLM must not re-author it. -->"
                )
                lines.append(f"**Controls covered:** [{_fb_mech}](#{_v2_slug(_fb_mech)}).")
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

        # §6.2 — deterministic Authentication Mechanisms inventory at the top of
        # the section so the COMPLETE auth surface (incl. mechanisms catalogued
        # under §6.3/§6.9) is always rendered, independent of LLM scaffold-fill.
        if heading.startswith("6.2 "):
            inv = _build_auth_mechanism_inventory(yaml_data)
            if inv:
                lines.extend(inv)
            # "Threat Hypotheses Requiring Validation" table disabled (juice-shop
            # 2026-07-03 user request): every row read Evidence/Validation from
            # `h.get("evidence")` / `h.get("validation_objective")`, but the
            # actual threat_hypotheses[] entries carry that content under
            # `positive_signals[]` — a field-name mismatch that made every row
            # render "_?_" / "_pending validation objective_" regardless of how
            # much real evidence the hypothesis actually had.
            #
            # The fix is bigger than renaming the field, though — the user's
            # bar is: unpromoted hypotheses must not appear in the report as a
            # disconnected "maybe" list at all. Each one needs a real Finding
            # derived from it and linked in before this table is report-ready
            # again. See docs/internal/analysis/proposal-threat-hypotheses-
            # promotion.md for the resume-work record (what "done" means, which
            # existing promotion machinery in arch_coverage_to_threats.py to
            # build on, open design questions). _render_threat_hypotheses_table
            # is left defined, just uncalled, until that's done. The "Controls
            # covered" bullet list below is mechanically derived from the H4 headings
            # actually emitted, so removing this call also removes it from
            # there automatically — no dangling link.

        if quick_depth and not control_names:
            continue

        if control_names:
            # Section-id for §6.X.N H4 numbering. `heading` is "7.X <Title>";
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
                # flow-like mechanisms — see data/sections-contract.yaml
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
            if suppressed_names and h4_idx == 0:
                # EVERY control in this section was suppressed, so the section
                # would ship with zero H4 blocks. That is the one shape the
                # coverage gate cannot accept: the section HAS catalogued
                # controls, so the `_Not applicable_` exemption in
                # qa_checks.check_control_subsection_coverage does not apply,
                # and "no #### control subsections found" fails BLOCKING. The
                # sibling no-controls path below handles its empty case by
                # emitting a `_Not applicable_` stub; this branch had no
                # equivalent, so it fell into the gap and forced an LLM repair
                # pass that could only re-add exactly what we dropped here
                # (insecure-ai-app §6.3, 2026-07-19 — both Session/Conversation
                # Ownership and Agent State Serialization Security suppressed
                # because no repo CWE routes to §6.3 at all).
                #
                # Re-emit the controls as real H4 blocks. A "Missing" control
                # with no linked findings still deserves a subsection here:
                # the reader needs to see the absent control named, and
                # suppressing it is what made the gap invisible.
                suppressed_names = []
                for c, name in zip(section_controls[:8], control_names[:8]):
                    h4_idx += 1
                    _emit_v2_subcontrol_legacy(
                        lines,
                        c,
                        name,
                        threats,
                        heading,
                        section_id=section_id,
                        idx=h4_idx,
                        force=True,
                    )
            if suppressed_names:
                # Surface the suppressed control names as a single line so
                # the user can see that the §6.x catalog item exists but
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
            # Reference §6 never carries an unnamed catch-all H4. Two cases:
            #   (a) no routed findings either → emit a single Not-applicable
            #       line and skip the H4 entirely (mirrors the reference's
            #       compact §6.12 "absent domain" handling);
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

        # Section-scoped sequenceDiagram guarantee (sections-contract.yaml
        # domain_required_patterns: §6.2 AND §6.3 each MUST contain at least one
        # `sequenceDiagram`). Flow-like §6.2 mechanisms and the §6.3 empty-control
        # fallback usually emit one, but a §6.3 populated with storage/cookie/
        # revocation-named controls (e.g. "JWT storage", "Token revocation")
        # takes the per-subcontrol path whose diagram is gated on flow-like
        # naming, so no diagram lands and compose --strict fails the §6.3
        # domain_required_pattern (juice-shop 2026-06-16). This catch-all injects
        # a positive-flow placeholder when the emitted section has no diagram —
        # the renderer fills it, and the literal token satisfies the deterministic
        # (no-enrich) path too. Section-scoped per the contract: a diagram
        # anywhere under the heading suffices.
        if heading.startswith(("6.2 ", "6.3 ")) and "sequenceDiagram" not in "\n".join(lines[section_start:]):
            lines.append(
                "<!-- NARRATIVE_PLACEHOLDER: precede with one sentence ending in "
                "`:` then a positive-flow ```mermaid sequenceDiagram``` of the "
                "primary flow for this section (for §6.3: JWT/session issuance → "
                "browser storage → Bearer presentation → server verification). "
                "One diagram for the section satisfies the requirement; per-stage "
                "detail stays in the H4 sub-blocks above. -->"
            )
            lines.append("")

    return "\n".join(lines)


def gen_security_architecture(yaml_data: dict, depth: str = "standard") -> str:
    """Render the current §6 security-architecture scaffold.

    Schema v2 is the only supported §6 layout. Keep this public wrapper for
    tests and older integrations that import ``gen_security_architecture``.
    """
    return gen_security_architecture_v2(yaml_data, depth)


# ---------------------------------------------------------------------------
# ms-ai-exposure.json — deterministic AI/LLM Exposure MS fragment
# ---------------------------------------------------------------------------
#
# The "### AI / LLM Exposure" Management-Summary callout used to be authored
# ONLY at the renderer LLM's discretion. That made it non-deterministic: it
# appeared on some runs of a repo and silently vanished on others (e.g. a quick
# scan emitted it but the standard scan of the SAME repo did not). Deriving it
# from threat-model.yaml makes it reproducible — present whenever, and only
# when, the model actually has an LLM/AI surface with ≥1 LLM-categorizable
# threat. Used as an idempotent backstop after Stage 2: if the renderer
# authored a richer version, that file is preserved; if it skipped it, this
# guarantees the section still appears.

# OWASP Top-10 for LLM Applications (2025) mapping rules. Each rule:
#   (llm_id, canonical_name, severity_default, [title keywords], description, strong)
# ``strong`` keywords are unambiguous LLM risks and match wherever they occur.
# Non-strong (weak) keywords are broad words ("unbounded", "data leak") that
# also appear on non-LLM threats, so they only count when the threat carries an
# LLM context (lives on an LLM component or names an LLM in its title). Rule
# order is the scan precedence — the first matching rule wins per threat.
_LLM_TOP10_RULES = [
    (
        "LLM01",
        "Prompt Injection",
        [
            "prompt injection",
            "prompt-injection",
            "jailbreak",
            # Role-confusion is a prompt-injection VARIANT — a client-supplied
            # "system"/"assistant" role message overrides the server's own
            # system prompt without ever touching the literal phrase "prompt
            # injection" (juice-shop 2026-07-02: "Client-Supplied Message
            # Array Accepted Without Role" fell through every rule).
            "without role",
            "message array",
            "role field",
            "role spoofing",
            "role confusion",
            "role injection",
            "fabricate system",
            "override system",
        ],
        "Untrusted user input reaches the LLM prompt/context without sufficient "
        "trust separation, letting an attacker override system instructions, "
        "redirect tool calls, or coerce unintended model behaviour.",
        True,
    ),
    (
        "LLM07",
        "System Prompt Leakage",
        ["system prompt", "prompt leak", "prompt disclosure", "prompt extract"],
        "The system prompt — carrying internal policy, tool rules, or secrets — "
        "is extractable through conversational manipulation, exposing the tool "
        "capability surface and internal business logic encoded in it.",
        True,
    ),
    (
        "LLM06",
        "Excessive Agency",
        [
            "excessive agency",
            "assistant-role",
            "conversation history",
            "unauthorized tool",
            "tool-call",
            "tool calling",
            "tool invocation",
        ],
        "The LLM is granted tool/function-calling authority without a secondary "
        "authorization boundary, so a manipulated model turn can invoke "
        "privileged actions on the user's behalf.",
        True,
    ),
    (
        "LLM05",
        "Improper Output Handling",
        ["improper output", "insecure output", "output handling", "output encoding"],
        "LLM-generated output flows into a downstream sink (browser, shell, "
        "query, eval) without validation or encoding, turning a model "
        "completion into an injection vector.",
        True,
    ),
    (
        "LLM04",
        "Data and Model Poisoning",
        ["data poisoning", "model poisoning", "training data"],
        "Untrusted content can influence the model's training, fine-tuning, or "
        "retrieval corpus, allowing an attacker to bias or backdoor model "
        "behaviour.",
        True,
    ),
    (
        "LLM08",
        "Vector and Embedding Weaknesses",
        ["vector database", "embedding", "retrieval-augmented", "rag pipeline"],
        "Retrieval/embedding inputs are not isolated by trust, letting injected "
        "documents or queries steer retrieval-augmented responses or leak "
        "indexed content.",
        True,
    ),
    (
        "LLM09",
        "Misinformation",
        ["misinformation", "hallucination", "overreliance"],
        "The system relies on LLM output without verification, so hallucinated "
        "or manipulated completions can drive incorrect or harmful downstream "
        "decisions.",
        True,
    ),
    (
        "LLM03",
        "Supply Chain",
        ["model supply chain", "model provenance", "third-party model"],
        "The model, its provider SDK, or plugins enter the system from third "
        "parties without provenance or integrity controls, exposing a "
        "supply-chain compromise path.",
        True,
    ),
    (
        "LLM10",
        "Unbounded Consumption",
        [
            "unbounded",
            "resource exhaustion",
            "model denial",
            "rate limit",
            # Hyphenated / negated spellings the space-separated "rate limit"
            # keyword missed — e.g. "Unrate-Limited LLM Chat Proxy" (T-037,
            # juice-shop 2026-07-02) dropped out of the AI-exposure map entirely.
            "rate-limit",
            "rate limiting",
            "unrate-limited",
            "no rate limit",
            "unlimited",
            "provider cost",
        ],
        "The LLM endpoint imposes no authentication, rate, or quota boundary, so "
        "any client can drive unbounded model invocations — uncontrolled "
        "provider cost and denial of service for legitimate users.",
        False,  # weak: "unbounded"/"rate limit" also hit non-LLM threats
    ),
    (
        "LLM02",
        "Sensitive Information Disclosure",
        ["sensitive information disclosure", "information disclosure", "data leak"],
        "The LLM surface can return sensitive data — internal secrets, other "
        "users' data, or privileged context — to an attacker who crafts the "
        "right conversational input.",
        False,  # weak: generic disclosure language
    ),
]

_LLM_COMPONENT_HINTS = ("llm", "chatbot", "ai-agent", "ai agent", "genai", "copilot")

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}

# LLM Top-10 → Agentic Top-10 (ASI) crosswalk. Only applied when the model has a
# genuine AGENTIC surface (see `_AGENTIC_KEYWORDS`), so a plain LLM call-and-return
# is never mislabelled as agentic. ASI03/ASI07/ASI10 have no LLM analog and are
# only authored by the analyst-driven fragment, not this deterministic backstop.
_LLM_TO_ASI_CROSSWALK = {
    "LLM01": "ASI01",  # Prompt Injection      → Agent Goal Hijack
    "LLM06": "ASI02",  # Excessive Agency      → Tool Misuse & Exploitation
    "LLM03": "ASI04",  # Model Supply Chain    → Agentic Supply Chain
    "LLM05": "ASI05",  # Improper Output       → Unexpected Code Execution
    "LLM04": "ASI06",  # Data & Model Poisoning→ Memory & Context Poisoning
    "LLM08": "ASI06",  # Vector & Embedding    → Memory & Context Poisoning
    "LLM09": "ASI09",  # Misinformation        → Human-Agent Trust Exploitation
    "LLM10": "ASI08",  # Unbounded Consumption → Cascading Agent Failures
}
_ASI_RISK_DETAILS = {
    "ASI01": ("Agent Goal Hijack", "Untrusted context can redirect the agent's multi-step goal or plan."),
    "ASI02": (
        "Tool Misuse & Exploitation",
        "Model-controlled tool use can exceed the intended authorization boundary.",
    ),
    "ASI03": (
        "Agent Identity & Privilege Abuse",
        "The agent can act with an over-broad or inherited identity instead of scoped delegation.",
    ),
    "ASI04": (
        "Agentic Supply Chain",
        "Tools, MCP servers, plugins, or personas lack sufficient provenance and integrity controls.",
    ),
    "ASI05": (
        "Unexpected Code Execution",
        "Agent-generated code or commands can reach execution sinks without an adequate sandbox.",
    ),
    "ASI06": (
        "Memory & Context Poisoning",
        "Persistent memory or shared retrieval context can be poisoned and reused across runs or tenants.",
    ),
    "ASI07": (
        "Insecure Inter-Agent Communication",
        "Peer-agent messages are trusted without sufficient authentication, integrity, or validation.",
    ),
    "ASI08": (
        "Cascading Agent Failures",
        "Unbounded loops or tool chains can amplify a single failure into a wider outage or cost event.",
    ),
    "ASI09": (
        "Human-Agent Trust Exploitation",
        "High-impact agent output or actions can be mistaken for authoritative human or system decisions.",
    ),
    "ASI10": (
        "Rogue Agents",
        "Standing agent privileges, monitoring, or revocation controls do not bound a compromised agent's blast radius.",
    ),
}
# Substrings that mark a genuine agentic surface (tools/memory/multi-agent/autonomy)
# in a threat's title+evidence+impact blob. Word-anchored where the token is short.
_AGENTIC_KEYWORDS = (
    "agentic",
    "agent framework",
    "multi-agent",
    "tool-calling",
    "tool calling",
    "tool use",
    "tool-use",
    "function call",
    "excessive agency",
    "autonomous agent",
    "mcp server",
    "react agent",
    "agentexecutor",
    "crewai",
    "autogen",
    "langgraph",
)


def _llm_severity_glyph(sev_rank: int) -> str:
    if sev_rank >= 2:
        return "red"
    if sev_rank == 1:
        return "yellow"
    return "green"


def _is_llm_component(comp: dict) -> bool:
    if any(
        isinstance(row, dict)
        and row.get("evidence")
        and row.get("capability") in {"llm-calls", "llm-tools", "agent-delegation"}
        for row in comp.get("capabilities") or []
    ):
        return True
    blob = (str(comp.get("id", "")) + " " + str(comp.get("name", ""))).lower()
    return any(h in blob for h in _LLM_COMPONENT_HINTS)


def _clean_finding_label(title: str) -> str:
    """Reduce a finding title to a short weakness-class label for the MS list
    (the schema caps labels at 80 chars). Strips the ``— file:line`` tail and
    any trailing dash artifacts, then truncates."""
    label = (title or "").split(" — ")[0].strip().rstrip("—-– ").strip()
    if not label:
        label = (title or "").strip()
    if len(label) > 80:
        label = label[:77].rstrip() + "…"
    if len(label) < 5:  # schema floor — pad defensively (titles are rarely this short)
        label = (label + " (LLM risk)")[:80]
    return label


# Phrases that place a threat's own prose on an LLM surface. Word-bounded and
# LLM-specific: a bare "prompt" also names download, password and command
# prompts, and put an open-redirect finding into the untagged-LLM diagnostic.
_LLM_SURFACE_RE = re.compile(
    r"\b(?:llms?|language models?|chatbots?|prompt[- ]injections?|system prompts?"
    r"|prompt templates?|model api|jailbreaks?)\b"
)


def gen_ai_exposure(yaml_data: dict):
    """Deterministically emit ms-ai-exposure.json when the model has an LLM/AI
    surface, else return ``None`` (→ no file written, section renders nothing).

    Detection is yaml-derived (an LLM component and/or LLM-categorizable threat
    titles), so the section is reproducible across depths and runs instead of
    depending on the renderer LLM's discretion."""
    import json

    components = yaml_data.get("components") or []
    threats = yaml_data.get("threats") or []
    if not threats:
        return None

    # Positional C-NN map (matches compose_threat_model.py component numbering).
    cmap = {c.get("id"): "C-%02d" % (i + 1) for i, c in enumerate(components) if c.get("id")}
    llm_component_ids = {c.get("id") for c in components if _is_llm_component(c)}
    llm_component_names = [c.get("name") for c in components if _is_llm_component(c) and c.get("name")]

    def _llm_context(threat: dict, blob_lc: str) -> bool:
        if threat.get("component") in llm_component_ids:
            return True
        return bool(_LLM_SURFACE_RE.search(blob_lc))

    # First-match-wins categorization of each threat into an LLM Top-10 bucket.
    # Categorization itself stays TITLE-scoped: many threats' impact/evidence
    # prose mentions "prompt injection" as the underlying ATTACK TECHNIQUE even
    # when the finding is really about a more specific risk (T-045's title is
    # "LLM Tool-Calling Guardrail Bypass" — Excessive Agency — but its impact
    # sentence says "A successful prompt injection can mint discount coupons",
    # which would wrongly steal it into the generic LLM01 bucket if the keyword
    # scan read impact text too; regression caught in review, juice-shop
    # 2026-07-03). Only the WEAK-rule `_llm_context` gate — which just vetoes
    # an already-title-matched weak keyword, never decides categorization —
    # reads the wider title+evidence+impact blob, so a title like
    # "Unauthenticated Rate-Unlimited Chat Endpoint" (no "llm"/"chatbot") can
    # still pass the gate via its impact prose ("...a metered external LLM
    # API...") once its OWN title already matched a keyword (juice-shop
    # 2026-07-02: T-040 lived on the generic "backend-api" component).
    buckets: dict[str, dict] = {}
    untagged_llm_threats: list[str] = []
    llm_rules_by_id = {rule[0]: rule for rule in _LLM_TOP10_RULES}

    def add_llm_bucket(llm_id: str, threat: dict) -> None:
        rule = llm_rules_by_id.get(llm_id)
        if rule is None:
            return
        _, name, _, description, _ = rule
        bucket = buckets.setdefault(llm_id, {"name": name, "description": description, "threats": [], "sev_rank": -1})
        if threat not in bucket["threats"]:
            bucket["threats"].append(threat)
        sev = register_severity(threat).lower()
        bucket["sev_rank"] = max(bucket["sev_rank"], _SEVERITY_RANK.get(sev, 1))

    for th in threats:
        title = th.get("title", "") or ""
        title_lc = title.lower()
        context_blob_lc = " ".join(
            str(th.get(f, "") or "") for f in ("title", "evidence_summary", "impact_description")
        ).lower()
        explicit_ids = th.get("owasp_llm_ids")
        if isinstance(explicit_ids, list) and explicit_ids:
            for llm_id in explicit_ids:
                if isinstance(llm_id, str):
                    add_llm_bucket(llm_id, th)
            continue
        for llm_id, name, keywords, description, strong in _LLM_TOP10_RULES:
            if not any(kw in title_lc for kw in keywords):
                continue
            if not strong and not _llm_context(th, context_blob_lc):
                continue
            add_llm_bucket(llm_id, th)
            break
        else:
            # Talks about the LLM surface, carries no `owasp_llm_ids`, and its
            # title matched no rule — so it is analysed but absent from this
            # section. REPORT it rather than widening the keyword scan into the
            # body: the TITLE-scoped rule above is deliberate (see the comment
            # there), and reading impact prose re-introduces the 2026-07-03
            # mis-categorization. The analyzer is contractually required to tag
            # what this lens produced; a hit here means it did not.
            #
            # Keyed on the threat's OWN prose, NOT on `_llm_context`: that gate
            # also accepts "lives on an LLM component", which in a monolith is
            # every route — on juice-shop it flagged 14 threats including SQL
            # injection and IDOR. A diagnostic with that many false positives
            # gets ignored, which is worse than having none.
            if _LLM_SURFACE_RE.search(context_blob_lc):
                untagged_llm_threats.append(str(th.get("id") or th.get("title") or "?"))

    if untagged_llm_threats:
        print(
            "pre-generate: ms-ai-exposure — "
            f"{len(untagged_llm_threats)} LLM-component threat(s) carry no owasp_llm_ids "
            f"and matched no title rule, so they are absent from the AI/LLM Exposure "
            f"section: {', '.join(untagged_llm_threats[:8])}",
            file=sys.stderr,
        )

    # Classify each finding before grouping. An unrelated agent (or a second
    # route on the same backend) cannot establish this finding's execution path.
    grouped: dict[tuple[str, str], list[dict]] = {}
    paired: set[tuple[str, str]] = set()
    for llm_id, bucket in buckets.items():
        for threat in bucket["threats"]:
            asi_ids = [value for value in threat.get("owasp_asi_ids") or [] if value in _ASI_RISK_DETAILS]
            if not asi_ids:
                blob = " ".join(
                    str(threat.get(key) or "").lower() for key in ("title", "evidence_summary", "impact_description")
                )
                # Compatibility only: MCP, retrieval and memory alone are not
                # agency; ordinary resource consumption is not a cascade.
                agentic = any(kw in blob for kw in _AGENTIC_KEYWORDS if kw != "mcp server")
                cascade = any(kw in blob for kw in ("cascad", "recursive", "recursion", "agent loop", "retry loop"))
                inferred = _LLM_TO_ASI_CROSSWALK.get(llm_id) if agentic and (llm_id != "LLM10" or cascade) else None
                asi_ids = [inferred] if inferred else []
            for asi_id in asi_ids or [""]:
                grouped.setdefault((llm_id, asi_id), []).append(threat)
                if asi_id:
                    paired.add((str(threat.get("id")), asi_id))
    for threat in threats:
        for asi_id in threat.get("owasp_asi_ids") or []:
            if asi_id in _ASI_RISK_DETAILS and (str(threat.get("id")), asi_id) not in paired:
                grouped.setdefault(("", asi_id), []).append(threat)

    ai_risks = []
    for (llm_id, asi_id), group in grouped.items():
        group_sorted = sorted(
            group, key=lambda t: (-_SEVERITY_RANK.get(register_severity(t).lower(), 1), str(t.get("id", "")))
        )
        by_id = {t["id"]: t for t in group_sorted if t.get("id")}
        if not by_id:
            continue
        if llm_id:
            _, name, _, description, _ = llm_rules_by_id[llm_id]
        else:
            name, description = _ASI_RISK_DETAILS[asi_id]
        severity = max(_SEVERITY_RANK.get(register_severity(t).lower(), 1) for t in group)
        risk = {
            "name": name,
            "description": description,
            "severity": _llm_severity_glyph(severity),
            "findings": [
                {"ref": ref, "label": _clean_finding_label(t.get("title", ""))} for ref, t in list(by_id.items())[:6]
            ],
        }
        if llm_id:
            risk["owasp_llm_id"] = llm_id
        if asi_id:
            risk["owasp_asi_id"] = asi_id
        affected = list(dict.fromkeys(cmap[t["component"]] for t in group_sorted if t.get("component") in cmap))
        if affected:
            risk["affected_components"] = affected[:8]
        ai_risks.append((severity, llm_id + ":" + asi_id, risk))

    if not ai_risks:
        return None

    # Most severe first, then stable by LLM id; cap at the schema max (10).
    ai_risks.sort(key=lambda x: (-x[0], x[1]))
    payload = {"ai_risks": [r for _, _, r in ai_risks][:10]}

    surface = llm_component_names[0] if llm_component_names else "an LLM/AI integration"
    summary = (
        f"This system embeds an LLM/AI surface ({surface}); the risks below are "
        "architectural — they follow from how untrusted input reaches the model's "
        "prompt, tools, and outputs."
    )
    if len(ai_risks) > 10:
        summary = f"Showing 10 of {len(ai_risks)} AI risk groups by severity; the Findings Register retains the complete findings."
    if 20 <= len(summary) <= 300:
        payload = {"summary": summary, **payload}

    return json.dumps(payload, indent=2) + "\n"


# ---------------------------------------------------------------------------
# Critical Attack Tree (`ms-critical-attack-tree.json`)
# ---------------------------------------------------------------------------
# Root cause it fixes (juice-shop 2026-06-27): the unnumbered "## Critical Attack
# Tree" section is MANDATORY whenever critical_count >= 2 (compose's
# has_multi_critical gate + section_integrity's required-section check), but it
# was only ever LLM-authored by the Stage-2 renderer — which skipped it at quick
# depth and rationalised the skip as "expected at quick depth". compose then only
# SOFT-warns on the missing fragment (back-compat guard for legacy fixtures)
# while section_integrity HARD-fails (RC=2), so the gap surfaced as a late
# hard-gate failure instead of being filled at authoring time. Generating it
# deterministically here removes the renderer dependency entirely — the same
# pattern as ms-ai-exposure.json (idempotent: an LLM-authored richer fragment
# already on disk is preserved).

# Canonical STRIDE order → (match-needles, node-id, capability label). The
# Criticals are grouped under their STRIDE class so the tree's middle layer is
# the attacker's capability decomposition, derived deterministically (no LLM).
_ATTACK_TREE_STRIDE_CAPABILITIES: list[tuple[tuple[str, ...], str, str]] = [
    (("spoof",), "CAP_SPOOF", "Spoofing — identity & auth bypass"),
    (("tamper", "inject"), "CAP_TAMPER", "Tampering — injection & data manipulation"),
    (("repudiat",), "CAP_REPUD", "Repudiation — audit & accountability gaps"),
    (("information", "disclos", "info"), "CAP_INFO", "Information Disclosure — secret & data exposure"),
    (("denial", "dos", "availab"), "CAP_DOS", "Denial of Service — availability loss"),
    (("elevation", "privilege", "eop", "rce", "execution"), "CAP_EOP", "Elevation of Privilege — escalation & RCE"),
]
_ATTACK_TREE_CANONICAL_CAPS = [c for _, c, _ in _ATTACK_TREE_STRIDE_CAPABILITIES] + ["CAP_OTHER"]


def _attack_tree_capability_for_stride(stride: str) -> tuple[str, str]:
    """Map a threat's STRIDE class to its (capability-node-id, label). Falls back
    to a generic 'Other' capability for unknown/missing STRIDE so every Critical
    lands under exactly one capability node."""
    s = (stride or "").strip().lower()
    for needles, node_id, label in _ATTACK_TREE_STRIDE_CAPABILITIES:
        if any(n in s for n in needles):
            return node_id, label
    return "CAP_OTHER", "Other attack capabilities"


def gen_critical_attack_tree(yaml_data: dict):
    """Deterministically emit ms-critical-attack-tree.json when ≥2 Critical
    findings exist, else return ``None`` (no file → the conditional section
    renders nothing).

    The Critical set mirrors compose_threat_model.py's ``_severity_counts``
    EXACTLY (``risk`` → ``severity``, NOT ``effective_severity``) so the fragment
    is generated precisely when the composer marks the section in-scope
    (``has_multi_critical = severity_counts["critical"] >= 2``). Keying on
    effective_severity here would over-/under-generate relative to the gate.
    """
    threats = yaml_data.get("threats") or []
    crits = [t for t in threats if str(t.get("risk") or t.get("severity") or "").strip().lower() == "critical"]
    if len(crits) < 2:
        # Section is conditional on has_multi_critical (>=2). With <2 Criticals
        # the composer skips it, so a fragment here would be dead weight.
        return None

    # Stable ordering by finding id so the tree is reproducible run-to-run.
    def _id_key(t: dict) -> tuple:
        m = re.search(r"(\d+)", str(t.get("id") or ""))
        return (int(m.group(1)) if m else 1_000_000, str(t.get("id") or ""))

    crits = sorted(crits, key=_id_key)

    # Schema caps `nodes` at 30. Reserve 1 goal + up to 7 capabilities; cap the
    # leaves so a pathological Critical count never overflows the schema. The
    # Criticals are id-sorted, so an over-cap run keeps the lowest ids (the rare
    # dropped tail is still fully visible in §8 Findings Register).
    _MAX_LEAVES = 22

    cap_label: dict[str, str] = {}
    cap_members: dict[str, list[dict]] = {}
    for t in crits[:_MAX_LEAVES]:
        cap_id, label = _attack_tree_capability_for_stride(t.get("stride"))
        cap_label.setdefault(cap_id, label)
        cap_members.setdefault(cap_id, []).append(t)

    # Order capability nodes by the canonical STRIDE sequence, not first-seen.
    cap_order = sorted(
        cap_members,
        key=lambda c: _ATTACK_TREE_CANONICAL_CAPS.index(c) if c in _ATTACK_TREE_CANONICAL_CAPS else 99,
    )

    nodes: list[dict] = [{"id": "GOAL", "label": "Full application compromise", "class": "goal"}]
    edges: list[dict] = []
    for cap_id in cap_order:
        nodes.append({"id": cap_id, "label": cap_label[cap_id], "class": "or_node"})
        edges.append({"from": "GOAL", "to": cap_id})
        for t in cap_members[cap_id]:
            tid = str(t.get("id") or "").strip()
            # Node id must match ^[A-Z][A-Z0-9_]*$ — "T-001" → "T001".
            leaf_id = re.sub(r"[^A-Z0-9_]", "", tid.upper().replace("-", "")) or f"N{len(nodes)}"
            if not re.match(r"^[A-Z]", leaf_id):
                leaf_id = "N" + leaf_id
            # Leaf label MUST carry the id token (`_derive_attack_tree_findings`
            # in compose keys the §8 Findings pointer off `[FT]-\d{3,4}` in the
            # label, and only on `class == "leaf"` nodes). The composer strips
            # the id + truncates the title at render, so the full short title is
            # safe here.
            short = _clean_finding_label(t.get("title", ""))
            nodes.append({"id": leaf_id, "label": f"{tid} {short}".strip(), "class": "leaf"})
            edges.append({"from": cap_id, "to": leaf_id})

    payload = {
        "root_goal": "Full application compromise via chained Critical defects",
        "mermaid": {"orientation": "TD", "nodes": nodes, "edges": edges},
    }
    return json.dumps(payload, indent=2) + "\n"


# ---------------------------------------------------------------------------
# Management Summary Verdict (`ms-verdict.json`)
# ---------------------------------------------------------------------------
# Root cause it fixes (juice-shop 2026-07-16): ms-verdict.json is the ONLY
# MANDATORY Management-Summary fragment without a deterministic backstop — unlike
# its siblings ms-ai-exposure.json and ms-critical-attack-tree.json, which both
# got gen_* generators to remove the Stage-2-renderer dependency. It is also the
# most fragile: compose HARD-fails (`RENDER_FAILED: ms-verdict.json not found`)
# when it is absent, whereas the siblings self-gate to "render nothing". So a
# single abnormal MS-renderer cutoff (observed: SESSION_STOP stop_reason=unknown
# mid-exploration, before the agent's first Write) left the fragment missing and
# forced a full renderer re-dispatch. This backstop derives a schema-valid
# verdict from threat-model.yaml so compose always has a floor. Idempotent (no
# --force): a richer LLM-authored verdict already on disk is preserved — this
# only fires when the fragment is genuinely missing.
#
# The prose is deliberately generic and technology-free: verdict.schema.json
# forbids finding IDs (`[FT]-\d{3,4}`) in opening/bullets_intro/closing/titles/
# bodies and its field descriptions forbid acronyms, CWE numbers, file paths,
# and attack-class names. A deterministic generator cannot match the LLM's
# per-repo eloquence, so it aims only for a valid, honest floor.

# Posture → (opening, closing) templates. Management-altitude prose only.
_VERDICT_OPENING = {
    "red": (
        "Not production-ready: this assessment confirmed weaknesses that let "
        "attackers reach customer data and core application functions without the "
        "safeguards a live system requires."
    ),
    "yellow": (
        "Production-ready with reservations: the assessment found weaknesses that "
        "should be resolved before launch, though none hand an attacker unrestricted "
        "access on their own."
    ),
    "green": (
        "Production-ready: the assessment found no weakness that gives an attacker "
        "meaningful access to customer data or core functions."
    ),
}
# The line rendered in bold directly above the blockquote. It is the sentence
# that says what the bullets ARE, so `opening` no longer ends on a forward
# pointer of its own ("The scenarios below summarise…") — saying "look below"
# twice in a row is what the reader saw before.
#
# Posture-keyed, because one fixed frame cannot serve all three. On green the
# opening states that no weakness gives an attacker meaningful access, so
# announcing what an attacker can do would contradict it one line later; green
# frames the same bullets as residual risk. Neither variant asserts an access
# level — the per-bullet precondition stays in `body` (see the renderer
# contract's "must not assert a precondition the bullets do not all share").
# Nor an order: nothing sorts the bullets by severity (RA-14).
_VERDICT_BULLETS_INTRO = {
    "red": "What an attacker can do today:",
    "yellow": "What an attacker can do today:",
    "green": "Residual risks worth monitoring:",
}
_VERDICT_CLOSING = {
    "red": (
        "Prioritising the fixes behind the scenarios above will close the most "
        "dangerous exposures before they can be used against customers."
    ),
    "yellow": ("Resolving the items above before launch will bring the application to a solid security baseline."),
    "green": (
        "Maintaining the current controls and monitoring the residual risks will "
        "keep the application on a sound footing."
    ),
}

# STRIDE class → (business-outcome title, business-outcome body). Deliberately
# generic and technology-free so the deterministic fallback stays within the
# verdict schema's management-language constraints. Canonical STRIDE order.
_VERDICT_STRIDE_SCENARIOS: list[tuple[tuple[str, ...], str, str]] = [
    (
        ("spoof",),
        "Accounts accessed by impostors",
        "An attacker can impersonate legitimate customers or staff and act with "
        "their permissions, because the application does not reliably confirm who "
        "is making a request.",
    ),
    (
        ("tamper", "inject"),
        "Business data read or altered",
        "Crafted input can read or change records a user should not be able to "
        "touch, putting the accuracy and confidentiality of stored data at risk.",
    ),
    (
        ("repudiat",),
        "Malicious actions cannot be traced",
        "Important events are not reliably recorded, so harmful or mistaken actions "
        "cannot be attributed or investigated after the fact.",
    ),
    (
        ("information", "disclos", "info"),
        "Confidential information exposed",
        "Sensitive data such as customer records or internal secrets can be read by "
        "people who should not have access to it.",
    ),
    (
        ("denial", "dos", "availab"),
        "Service taken offline",
        "An attacker can disrupt or exhaust the service so that legitimate customers are unable to use it.",
    ),
    (
        ("elevation", "privilege", "eop", "rce", "execution"),
        "Full system takeover",
        "An attacker can gain administrator-level control or run their own commands "
        "on the server, taking command of the application and the data it holds.",
    ),
]
_VERDICT_GENERIC_SCENARIO = (
    "Protections bypassed",
    "Weaknesses let an attacker sidestep protections the application relies on to "
    "keep customer data and core functions safe.",
)
_VERDICT_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _verdict_scenario_for_stride(stride: str) -> tuple[str, str]:
    """Map a threat's STRIDE class to its (title, body) business scenario. Falls
    back to a generic scenario for unknown/missing STRIDE."""
    s = (stride or "").strip().lower()
    for needles, title, body in _VERDICT_STRIDE_SCENARIOS:
        if any(n in s for n in needles):
            return title, body
    return _VERDICT_GENERIC_SCENARIO


def gen_verdict(yaml_data: dict):
    """Deterministically emit a schema-valid ms-verdict.json floor.

    Posture (severity) is a conservative reading of the risk distribution: any
    Critical → red, else any High → yellow, else green. Bullets are one
    business-language scenario per STRIDE class present, ordered by the severity
    of the finding that first surfaced the class (so the exec summary reads
    worst-first). Returns ``None`` only when no citable finding exists (a
    degenerate model where the verdict has nothing to reference); compose's own
    empty-model handling then applies.
    """
    threats = [t for t in (yaml_data.get("threats") or []) if isinstance(t, dict) and t.get("id")]
    if not threats:
        return None

    def _sev(t: dict) -> str:
        return str(t.get("risk") or t.get("severity") or "").strip().lower()

    sevs = {_sev(t) for t in threats}
    if "critical" in sevs:
        severity = "red"
    elif "high" in sevs:
        severity = "yellow"
    else:
        severity = "green"

    # Severity-then-numeric-id ordering so the highest-impact scenario leads.
    def _id_key(t: dict) -> tuple:
        m = re.search(r"(\d+)", str(t.get("id") or ""))
        return (_VERDICT_SEV_RANK.get(_sev(t), 5), int(m.group(1)) if m else 1_000_000, str(t.get("id")))

    ranked = sorted(threats, key=_id_key)

    # Group by scenario (dict preserves first-seen = severity order). Each bullet
    # collects up to 5 supporting refs (schema maxItems).
    grouped: dict[tuple[str, str], list[str]] = {}
    for t in ranked:
        tid = str(t.get("id") or "").strip()
        if not re.match(r"^[FT]-\d{3,4}$", tid):
            continue
        scenario = _verdict_scenario_for_stride(t.get("stride"))
        refs = grouped.setdefault(scenario, [])
        if tid not in refs and len(refs) < 5:
            refs.append(tid)

    bullets: list[dict] = []
    for (title, body), refs in grouped.items():
        if not refs:
            continue
        bullets.append({"title": title, "body": body, "refs": refs})
        if len(bullets) >= 6:  # schema max 8; keep the exec summary tight
            break

    # Schema requires >= 2 bullets. If only one scenario surfaced, synthesise a
    # distinct second bullet from the top citable finding so the floor is valid.
    if len(bullets) < 2:
        top_ref = next(
            (str(t.get("id")).strip() for t in ranked if re.match(r"^[FT]-\d{3,4}$", str(t.get("id") or "").strip())),
            None,
        )
        if top_ref is None:
            return None  # no citable finding → cannot build a valid verdict
        if not bullets:
            gt, gb = _VERDICT_GENERIC_SCENARIO
            bullets.append({"title": gt, "body": gb, "refs": [top_ref]})
        bullets.append(
            {
                "title": "Layered defences missing",
                "body": (
                    "Several safeguards a live system depends on are absent or "
                    "ineffective, leaving customer data and core functions exposed "
                    "if a single control is bypassed."
                ),
                "refs": [top_ref],
            }
        )

    payload = {
        "severity": severity,
        "opening": _VERDICT_OPENING[severity],
        "bullets_intro": _VERDICT_BULLETS_INTRO[severity],
        "bullets": bullets[:8],
        "closing": _VERDICT_CLOSING[severity],
    }
    return json.dumps(payload, indent=2) + "\n"


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
    # ms-ai-exposure.json — deterministic "AI / LLM Exposure" MS callout.
    # Returns None (no file) on repos without an LLM/AI surface, so non-LLM
    # repos pay zero cost and the section renders nothing.
    "ms-ai-exposure.json": gen_ai_exposure,
    # ms-critical-attack-tree.json — deterministic "## Critical Attack Tree".
    # Returns None when <2 Critical findings (the section's has_multi_critical
    # gate), so it self-gates exactly like the composer's scope decision. This
    # removes the Stage-2 renderer dependency that left the MANDATORY section
    # empty at quick depth (compose soft-warn vs section_integrity hard-fail).
    "ms-critical-attack-tree.json": gen_critical_attack_tree,
    # ms-verdict.json — deterministic Management-Summary verdict FLOOR. Unlike
    # its two siblings above this fragment is MANDATORY and compose HARD-fails
    # without it, so an abnormal MS-renderer cutoff before the first Write used
    # to force a full re-dispatch. Idempotent (no --force): a richer LLM verdict
    # already on disk is preserved; this only fills a genuine gap. Returns None
    # only for a threat-free model (nothing to reference).
    "ms-verdict.json": gen_verdict,
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
        "Quick depth strips NARRATIVE_PLACEHOLDERs from §6.4-§6.12 in "
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
            # Stale-scaffold self-heal (juice-shop 2026-06-16): an UNFILLED
            # security-architecture.md scaffold (still carrying
            # NARRATIVE_PLACEHOLDER markers) holds no LLM narrative to preserve.
            # Skipping it lets a scaffold generated EARLY (Analyst-A, Phase 1-8)
            # survive past later yaml mutations — notably emit_auth_coverage's
            # auth-mechanism backfill — so §6.2/§6.3 never receive the new
            # mechanisms' flow sub-blocks / sequenceDiagrams and compose --strict
            # fails the §6.3 domain_required_pattern. Regenerate it from the
            # CURRENT yaml in that case. A NARRATIVE-FILLED fragment (no
            # placeholders) is still skipped/preserved, exactly as before.
            if name == "security-architecture.md":
                try:
                    existing_scaffold = path.read_text(encoding="utf-8")
                except OSError:
                    existing_scaffold = ""
                if existing_scaffold and "NARRATIVE_PLACEHOLDER" in existing_scaffold:
                    pass  # fall through → regenerate the stale, unfilled scaffold
                else:
                    skipped.append(name)
                    continue
            else:
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
        if content is None:
            # Generator opted out (e.g. ms-ai-exposure.json on a repo with no
            # LLM/AI surface). Not a failure — there is simply nothing to write,
            # and the optional section then renders nothing.
            skipped.append(f"{name} (not applicable)")
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
