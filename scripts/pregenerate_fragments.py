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
    project = meta.get("project") or {}
    components = yaml_data.get("components") or []

    name = project.get("name") or "the system"
    desc = project.get("description") or ""
    runtime = project.get("runtime") or ""
    repository = project.get("repository") or ""

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
    project = meta.get("project") or {}
    name = project.get("name") or "System"
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
    lines.append("```mermaid")
    lines.append("flowchart LR")
    lines.append("    USER[\"End User<br/>(browser)\"]")
    lines.append("    ATTACKER[\"Anonymous<br/>Internet Attacker\"]")
    lines.append(f"    SYSTEM[\"{name}\"]")
    lines.append("    USER -->|HTTPS| SYSTEM")
    lines.append("    ATTACKER -.->|HTTPS / probing| SYSTEM")
    lines.append("    classDef user fill:#dbeafe,stroke:#1e40af")
    lines.append("    classDef attacker fill:#fecaca,stroke:#991b1b")
    lines.append("    classDef sys fill:#f3f4f6,stroke:#374151,stroke-width:2px")
    lines.append("    class USER user")
    lines.append("    class ATTACKER attacker")
    lines.append("    class SYSTEM sys")
    lines.append("```")
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

    # Connect tiers (synchronous request flow)
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
            benf = (b.get("enforcement") or "").replace("\n", " ").strip()
            lines.append(f"| {bid} | {bname} | {bdesc} | {benf} |")
    else:
        lines.append("_No trust boundaries enumerated in threat-model.yaml._")
    lines.append("")
    lines.append("```mermaid")
    lines.append("flowchart LR")
    lines.append("    subgraph TB1[\"Public Internet\"]")
    lines.append("        EXT[\"Anonymous Actor\"]")
    lines.append("    end")
    lines.append("    subgraph TB2[\"Application\"]")
    lines.append("        APP[\"Server Process\"]")
    lines.append("    end")
    lines.append("    subgraph TB3[\"Data\"]")
    lines.append("        STORE[\"Data Store\"]")
    lines.append("    end")
    lines.append("    EXT -->|TB-001| APP")
    lines.append("    APP -->|TB-002/003| STORE")
    lines.append("```")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _safe_node_id(s: str) -> str:
    """Mermaid-safe node id: alphanum + underscore only."""
    return "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in s.lower()) or "node"


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

def gen_attack_surface(yaml_data: dict) -> str:
    """## 5. Attack Surface — required ### 5.1 + ### 5.2 sub-sections."""
    surface = yaml_data.get("attack_surface") or {}
    unauth = surface.get("unauthenticated") or []
    auth = surface.get("authenticated") or []

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
            route = entry.get("route", "?")
            notes = (entry.get("notes") or "").replace("\n", " ").strip()
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
            route = entry.get("route", "?")
            notes = (entry.get("notes") or "").replace("\n", " ").strip()
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
    controls = yaml_data.get("security_controls") or []
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
            notes = (c.get("notes") or "").replace("\n", " ").strip()
            lines.append(f"| {domain} | {ctrl} | {eff} | {notes} |")
    else:
        lines.append("_No weak/missing controls cataloged._")
    lines.append("")

    # 7.3 - 7.12 (domain-specific from security_controls[])
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
                notes = (c.get("notes") or "").replace("\n", " ").strip()
                lines.append(f"| {ctrl} | {impl} | {eff} | {notes} |")
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
        # sequenceDiagram skeleton — the LLM in Stage 1b can refine if it
        # wants but the deterministic stub keeps the pipeline composable.
        if section_id == "7.3" and matched:
            for c in matched:
                ctrl = (c.get("control") or "Authentication Flow").strip()
                impl = (c.get("implementation") or "_n/a_").strip()
                # Heading must match `^7\.3\.\d+\s+.+\s+Flow$` per contract
                # auth_method_decomposition rule. We append " Flow" if absent.
                heading = ctrl if ctrl.endswith(" Flow") else f"{ctrl} Flow"
                lines.append(f"#### 7.3.{matched.index(c) + 1} {heading}")
                lines.append("")
                lines.append(f"**Implementation:** `{impl}`")
                lines.append("")
                lines.append("```mermaid")
                lines.append("sequenceDiagram")
                lines.append("    participant Client")
                lines.append("    participant Service")
                lines.append("    participant Store as Identity Store")
                lines.append("    Client->>Service: credentials / token")
                lines.append("    Service->>Store: verify identity")
                lines.append("    Store-->>Service: user record")
                lines.append("    Service-->>Client: session / JWT")
                lines.append("```")
                lines.append("")
                lines.append("**Risk assessment:** see the row in the §7.3 controls table above for "
                             "effectiveness and notes; cross-referenced findings are tracked in §8.")
                lines.append("")
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
                         f"{(c.get('notes') or '').replace(chr(10), ' ').strip()} |")
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
