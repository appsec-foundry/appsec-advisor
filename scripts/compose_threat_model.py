#!/usr/bin/env python3
"""Contract-driven renderer for ``threat-model.md``.

This is the central component of the "LLM cannot deviate from structure"
architecture. It reads:

    1. ``data/sections-contract.yaml`` — declarative document shape.
    2. ``<output>/threat-model.yaml`` — canonical structured baseline (threats,
       mitigations, components, security_controls, meta, changelog).
    3. ``<output>/.triage-flags.json`` — triage ranking v2+ (optional).
    4. ``<output>/.fragments/*.json`` and ``*.md`` — LLM-authored data and
       prose fragments for sections the LLM is allowed to supply content
       for (verdict, architecture-assessment, critical-attack-tree, prose
       sections like system-overview). Architecture diagrams are regenerated
       directly from the canonical YAML at this composition boundary.

And emits ``<output>/threat-model.md`` deterministically. Identical inputs
produce byte-identical output. The LLM never writes Markdown directly — it
only writes schema-validated JSON data and, for pure-prose sections, verified
Markdown fragments.

Previously the orchestrator composed the Markdown in four ~20 KB Write calls
(Part A–D). Multiple production runs drifted from the canonical structure
(numbered Management Summary sub-sections, wrong column counts, missing
Verdict blockquote). Moving composition here eliminates that failure mode.

Exit codes:
    0 — rendered successfully (Markdown on disk)
    1 — required fragment missing or schema-invalid
    2 — usage / contract error
    3 — IO error

Module map (coarse — line ranges drift; refresh via the section dividers below):
    L105–173   Exceptions
    L174–395   RenderContext + helper utilities
    L396–413   eval_condition adapter (delegates to scripts/_safe_cond.py)
    L414–623   Jinja environment + custom filters
    L624–1067  YAML helpers — derivations from threat-model.yaml
    L1068–1129 Fragment loading + schema validation
    L1130–1797 Section renderers — one per section id or fragment_type
               (manifest readers moved to scripts/_manifest_readers.py — Phase A2)
    L1798–4635 Diagram-data assembly (pure functions feeding Jinja templates)
    L4636–4955 Threat / Mitigation registers (computed from yaml)
    L4956–5318 Inline-code helpers for §9 Mitigation prose
    L5319–5359 Dispatcher
    L5360–5973 Top-level orchestration
    L5974–6174 CLI
    L6175–6591 .compose-stats.json observability (M2.14)
"""

from __future__ import annotations

import argparse
import base64
import functools
import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import _safe_cond
import jinja2
import yaml
from _atomic_io import atomic_write_text
from _manifest_readers import (
    derive_homepage as _derive_homepage,
)
from _manifest_readers import (
    derive_runtime as _derive_runtime,
)
from _manifest_readers import (
    extract_repo_url as _extract_repo_url,
)
from _manifest_readers import (
    format_author as _format_author,
)
from _manifest_readers import (
    read_license_file as _read_license_file,
)
from _manifest_readers import (
    read_package_json as _read_package_json,
)
from _manifest_readers import (
    read_project_manifest as _read_project_manifest,
)
from _manifest_readers import (
    read_readme_tags as _read_readme_tags,
)

# P1: single-source weakness-class map, shared with merge_threats.py.
# `_MULTI_MATCH_WARNED` is re-exported so existing call sites/tests keep
# mutating the shared warned-CWE set.
from build_posture_verdict import build_posture_verdict as _build_posture_verdict  # P4: systemic verdict
from pregenerate_fragments import gen_architecture_diagrams
from weakness_classifier import MULTI_MATCH_WARNED as _MULTI_MATCH_WARNED  # noqa: F401
from weakness_classifier import classify_threat as _wc_classify_threat
from weakness_classifier import load_weakness_classes as _wc_load_weakness_classes

try:
    import jsonschema

    _JSONSCHEMA_OK = True
except ImportError:
    _JSONSCHEMA_OK = False


PLUGIN_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONTRACT = PLUGIN_ROOT / "data" / "sections-contract.yaml"
TEMPLATES_DIR = PLUGIN_ROOT / "templates" / "fragments"
SCHEMAS_DIR = PLUGIN_ROOT / "schemas" / "fragments"

# CSafeLoader is ~11× faster than pure-Python SafeLoader on large YAML files
# (300 KB threat-model.yaml: 0.447 s vs 0.039 s measured). Identical output
# for the safe subset all plugin documents use. Mirrors the same pattern in
# scripts/qa_checks.py _fast_yaml_load.
_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def _fast_yaml_load(text: str):
    return yaml.load(text, Loader=_YAML_LOADER)  # noqa: S506


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ContractError(Exception):
    """Raised when the contract file is malformed."""


class FragmentError(Exception):
    """Raised when an LLM-authored fragment is missing, malformed, or fails
    schema validation."""

    def __init__(self, section_id: str, detail: str) -> None:
        super().__init__(f"[{section_id}] {detail}")
        self.section_id = section_id
        self.detail = detail


# Single source of truth: section id → fragment path that drives it. Mirrors
# CONTRACT_SECTION_FRAGMENTS in scripts/qa_checks.py (kept in sync by
# scripts/check_fragment_registry.py). Used by the pre-render repair-plan writer
# to point the orchestrator at the exact file to edit when compose aborts
# with a FragmentError — eliminates the fix-loop where the agent re-writes
# the wrong fragment (e.g. architecture-diagrams.md instead of the offending
# security-architecture.md).
_SECTION_FRAGMENT_MAP: dict[str, list[str]] = {
    "verdict": [".fragments/ms-verdict.json"],
    "architectural_anti_patterns": [".fragments/ms-anti-patterns.json"],
    "ai_exposure_ms": [".fragments/ms-ai-exposure.json"],
    "operational_strengths": [".fragments/operational-strengths-overrides.json"],
    "system_overview": [".fragments/system-overview.md"],
    "identified_actors": [],  # computed — no LLM fragment (actors.md §14)
    "architecture_diagrams": [".fragments/architecture-diagrams.md"],
    "attack_walkthroughs": [".fragments/attack-walkthroughs.md"],
    "assets": [".fragments/assets.md"],
    "attack_surface": [".fragments/attack-surface.md"],
    # §6 use_cases removed 2026-05; gap intentional (see sections-contract.yaml).
    "security_posture_at_a_glance": [".fragments/security-posture-attack-paths.json"],
    "security_architecture": [".fragments/security-architecture.md"],
    "requirements_compliance": [".fragments/requirements-compliance.md"],
    "threat_register": [".fragments/compound-chains.json"],
    "critical_attack_tree": [".fragments/ms-critical-attack-tree.json"],
    "out_of_scope": [".fragments/out-of-scope.md"],
}

_KNOWN_JSON_FRAGMENT_SCHEMAS: dict[str, tuple[str, str]] = {
    "ms-verdict.json": ("verdict", "verdict.schema.json"),
    "ms-critical-attack-tree.json": (
        "critical_attack_tree",
        "critical-attack-tree.schema.json",
    ),
    "compound-chains.json": ("threat_register", "compound-chains.schema.json"),
    "operational-strengths-overrides.json": (
        "operational_strengths",
        "operational-strengths-overrides.schema.json",
    ),
    "security-posture-attack-paths.json": (
        "security_posture_attack_paths",
        "security-posture-attack-paths.schema.json",
    ),
    "ms-anti-patterns.json": (
        "architectural_anti_patterns",
        "anti-patterns.schema.json",
    ),
}

# Known JSON fragments whose section renderer can deterministically rebuild the
# content from yaml when the LLM-authored fragment is absent or schema-invalid.
# For these, the strict pre-render validation (`_validate_known_json_fragments`)
# degrades to a warning + deterministic fallback instead of aborting compose.
# Currently only the attack-paths fragment qualifies — `_load_attack_paths_fragment`
# falls back to `_derive_attack_paths_fallback` (CWE→attack-class derivation).
_FRAGMENTS_WITH_FALLBACK: frozenset[str] = frozenset({"security-posture-attack-paths.json"})


# ---------------------------------------------------------------------------
# Render context
# ---------------------------------------------------------------------------


@dataclass
class RenderContext:
    """Everything the renderer needs to know for one run."""

    output_dir: Path
    contract: dict[str, Any]
    yaml_data: dict[str, Any]
    triage: dict[str, Any]
    fragments_dir: Path
    # When True, Figure 1 is ALSO embedded inline in the Markdown as a
    # base64 data:image URI (self-contained md) in addition to writing
    # figure1.svg. Default False = a plain relative-file reference (the only
    # form GitHub renders; data: URIs are stripped by GitHub's sanitiser).
    embed_figures: bool = False
    # Basename of the Figure 1 SVG written next to the rendered Markdown and
    # referenced from it. Derived from the output md stem (`<stem>.figure1.svg`)
    # so several threat models can share one output directory without their
    # figure files colliding. Defaults to the legacy `figure1.svg`.
    figure_basename: str = "figure1.svg"
    severity_taxonomy: dict[str, dict[str, str]] = field(default_factory=dict)
    effectiveness_taxonomy: dict[str, dict[str, Any]] = field(default_factory=dict)
    category_taxonomy: dict[str, dict[str, Any]] = field(default_factory=dict)
    eval_context: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    # M2.14 — Sprint 6 observability. Free-form structured warnings list
    # populated by section renderers; persisted to .compose-stats.json on
    # successful render and surfaced via the §Composition Notes appendix
    # (when non-empty) in threat-model.md plus the Composition Health block
    # in the completion summary.
    structured_warnings: list[dict[str, str]] = field(default_factory=list)
    # Per-section retry counts populated by the _PRE_RENDER_REPAIR_MAX_ATTEMPTS
    # loop in main(). Keyed by section_id, value = number of compose attempts
    # that had to run for that section to converge (1 = first try).
    section_retry_counts: dict[str, int] = field(default_factory=dict)
    # Per-section render-outcome manifest — one dict per entry in document.order,
    # populated by the render loop. Persisted to .render-integrity.json so the
    # completion summary can show "Report integrity: N%" and aggregate_run_issues
    # / the QA agent can react deterministically when an in-scope section
    # rendered degraded or empty (a structurally broken model) instead of
    # re-checking prose. Each entry: {id, in_scope, outcome, expected_fragments,
    # present_fragments}.
    render_manifest: list[dict[str, Any]] = field(default_factory=list)
    # Quick-mode §7 override resolved at ctx-setup time:
    #   None      — render §7 from the regular fragment (depth != quick).
    #   ""        — skip §7 entirely (depth = quick, no rich prior).
    #   <string>  — use this verbatim Markdown for §7 (rich prior preserved).
    security_arch_override: Optional[str] = None
    # Built lazily on first `lookup_label` call. Maps upper-cased ref
    # (T-NNN, F-NNN alias, M-NNN, C-NN raw + canonical, TH-NN) → resolved
    # label. Pre-synthesised once per threat at build time, so the scenario
    # fallback runs O(threats) instead of O(threats × lookups).
    _label_index: Optional[dict[str, str]] = None
    # Built lazily on first `severity_for_ref` call. Maps upper-cased finding
    # ref (T-NNN + F-NNN alias) → effective_severity (fallback risk/severity).
    # Backs the leading criticality dot that `linkify_with_label` prepends to
    # finding links so the reader sees a finding's severity at every reference.
    _severity_index: Optional[dict[str, str]] = None
    # Built lazily on first `priority_for_ref` call. Maps upper-cased mitigation
    # ref (M-NNN) → rollout priority key (p1..p4). Backs the leading `P1 · `
    # priority tag that `linkify_with_label` prepends to mitigation links — the
    # measures analogue of the finding severity dot, but colourless (a text
    # tag, no colour circle) per the 2026-06-03 Variant-A decision.
    _priority_index: Optional[dict[str, str]] = None
    # Built lazily on first `location_for_ref` call. Maps every finding ref
    # (T-/F-NNN) and mitigation ref (M-NNN) → its full `file:line` locator
    # string. Backs the trailing `(`file:line`)` locator that the canonical
    # reference form appends — basename:line inline, full path in the Findings
    # index (the `full_path` flag). RC-2026-06-29.
    _location_index: Optional[dict[str, str]] = None

    def severity_emoji(self, key: str) -> str:
        k = (key or "").strip().lower()
        return self.severity_taxonomy.get(k, {}).get("emoji", "")

    def severity_label(self, key: str) -> str:
        k = (key or "").strip().lower()
        return self.severity_taxonomy.get(k, {}).get("label", key or "")

    def effectiveness_badge(self, key: str) -> str:
        k = (key or "").strip().lower()
        entry = self.effectiveness_taxonomy.get(k, {})
        if not entry:
            return key or ""
        return f"{entry['emoji']} {entry['label']}"

    # ---- ID lookups ------------------------------------------------------
    # These back the `linkify_with_label` filter which is the canonical way
    # to render any cross-reference. Every call site (tables, bullet lists,
    # defects blocks, compound chains) must go through this helper — bare
    # `[F-009](#f-009)` emissions are a generator defect.

    def _build_label_index(self) -> dict[str, str]:
        """Pre-resolve every cross-referenceable ID → label once.

        Supports F-NNN / T-NNN (findings + threats — both directions of the
        F↔T alias are registered so `_enrich_linked_id_cells` can re-process
        already-rendered F-NNN links), M-NNN (mitigations, with legacy
        `mitigation_title` / `name` fallback), C-NN (components, both raw
        ``id`` and synthesised ``_canonical_id``), TH-NN (threat categories
        from taxonomy).

        For threats without a `title`, the scenario synthesis runs once at
        build time — same string contract as the previous per-call version
        (safe for table cells: no unclosed backticks, no mid-word truncation,
        no markdown link artefacts).
        """
        idx: dict[str, str] = {}
        data = self.yaml_data or {}

        for t in data.get("threats", []) or []:
            tid = (t.get("t_id") or t.get("id") or "").strip().upper()
            if not tid:
                continue
            label = _strip_trailing_locator(
                _strip_embedded_evidence_file((t.get("title") or t.get("scenario_short") or "").strip(), t)
            )
            if not label:
                sc = (t.get("scenario") or t.get("description") or "").strip()
                if sc:
                    label = _synthesise_label(sc)
            idx.setdefault(tid, label)
            # Register the F↔T alias so a caller passing the rendered F-NNN
            # form still resolves (`_enrich_linked_id_cells` does this).
            if tid.startswith("T-"):
                idx.setdefault("F-" + tid[2:], label)
            elif tid.startswith("F-"):
                idx.setdefault("T-" + tid[2:], label)

        for m in data.get("mitigations", []) or []:
            mid = (m.get("m_id") or m.get("id") or "").strip().upper()
            if not mid:
                continue
            label = _strip_trailing_locator(
                (m.get("title") or m.get("mitigation_title") or m.get("name") or "").strip()
            )
            idx.setdefault(mid, label)

        for c in data.get("components", []) or []:
            name = (c.get("name") or "").strip()
            for key in ("id", "_canonical_id"):
                cid = (c.get(key) or "").strip().upper()
                if cid:
                    idx.setdefault(cid, name)

        for k, v in (self.category_taxonomy or {}).items():
            ku = (k or "").strip().upper()
            if ku and isinstance(v, dict):
                idx.setdefault(ku, (v.get("title") or "").strip())

        return idx

    def lookup_label(self, ref: str) -> str:
        """Resolve a short business-language label for an ID.

        Backed by `_label_index` (built lazily on first call). Supports
        F-NNN / T-NNN (with F↔T alias), M-NNN, C-NN (raw + canonical),
        TH-NN. Returns "" for unknown refs.
        """
        if not ref:
            return ""
        if self._label_index is None:
            self._label_index = self._build_label_index()
        return _codify_label_locator(self._label_index.get(ref.strip().upper(), ""))

    def _build_severity_index(self) -> dict[str, str]:
        """Map every finding ref (T-NNN + F-NNN alias) → its rated severity.

        Prefers ``effective_severity`` (the post-triage rating that drives the
        §8 grouping, including abuse-chain elevation) and falls back to
        ``risk`` / ``severity``. Only findings are indexed — mitigations,
        components, and threat categories carry no criticality dot.
        """
        idx: dict[str, str] = {}
        for t in (self.yaml_data or {}).get("threats", []) or []:
            tid = (t.get("t_id") or t.get("id") or "").strip().upper()
            if not tid:
                continue
            sev = (t.get("effective_severity") or t.get("risk") or t.get("severity") or "").strip()
            if not sev:
                continue
            idx.setdefault(tid, sev)
            if tid.startswith("T-"):
                idx.setdefault("F-" + tid[2:], sev)
            elif tid.startswith("F-"):
                idx.setdefault("T-" + tid[2:], sev)
        return idx

    def severity_for_ref(self, ref: str) -> str:
        """Rated severity for a finding ref (T-/F-NNN), or "" when unknown."""
        if not ref:
            return ""
        if self._severity_index is None:
            self._severity_index = self._build_severity_index()
        return self._severity_index.get(ref.strip().upper(), "")

    def _build_priority_index(self) -> dict[str, str]:
        """Map every mitigation ref (M-NNN) → its rollout priority key (p1..p4).

        The measures analogue of `_build_severity_index`. Prefers an explicit
        ``priority`` field (``P1``..``P4``, or a severity word the orchestrator
        sometimes emits in its place). Falls back to the highest severity among
        the findings the mitigation addresses, mapped onto the P-scale
        (Critical→P1 … Low→P4). This mirrors the §9 Mitigations-index derivation
        exactly, so a mitigation's prefix tag, its §9 index chip, and the §9
        register bucket it lands in all agree.
        """
        threats = (self.yaml_data or {}).get("threats", []) or []
        sev_by_num = _severity_by_finding_num(threats)
        sev_to_prio = {"critical": "p1", "high": "p2", "medium": "p3", "low": "p4"}
        idx: dict[str, str] = {}
        for m in (self.yaml_data or {}).get("mitigations", []) or []:
            mid = (m.get("m_id") or m.get("id") or "").strip().upper()
            if not mid:
                continue
            raw = (m.get("priority") or "").strip().lower()
            if raw in _PRIO_ICON_TBL:  # already a p1..p4 key
                idx.setdefault(mid, raw)
                continue
            if raw in sev_to_prio:  # severity word in the priority slot
                idx.setdefault(mid, sev_to_prio[raw])
                continue
            best = 9
            for a in m.get("threat_ids") or m.get("addresses") or []:
                am = re.search(r"(\d+)$", str(a))
                if am:
                    best = min(best, _SEV_RANK_TBL.get(sev_by_num.get(int(am.group(1)), ""), 9))
            sev_word = next((s for s, r in _SEV_RANK_TBL.items() if r == best), "")
            idx.setdefault(mid, sev_to_prio.get(sev_word, "p3"))
        return idx

    def priority_for_ref(self, ref: str) -> str:
        """Rollout priority key (p1..p4) for a mitigation ref (M-NNN), else ""."""
        if not ref:
            return ""
        if self._priority_index is None:
            self._priority_index = self._build_priority_index()
        return self._priority_index.get(ref.strip().upper(), "")

    def _build_location_index(self) -> dict[str, str]:
        """Map every finding ref (T-/F-NNN) and mitigation ref (M-NNN) → its full
        ``file:line`` locator string.

        Findings source their locator from ``evidence.file[:line]``; mitigations
        from their own ``file``/``location`` field, falling back to the first
        finding they address. The locator is stored at FULL path; callers choose
        basename-vs-full at lookup time (``location_for_ref(full_path=…)``).
        """
        threats = (self.yaml_data or {}).get("threats", []) or []
        idx: dict[str, str] = {}
        for t in threats:
            tid = (t.get("t_id") or t.get("id") or "").strip().upper()
            if not tid:
                continue
            loc = _evidence_locator(t)
            if not loc:
                continue
            idx.setdefault(tid, loc)
            if tid.startswith("T-"):
                idx.setdefault("F-" + tid[2:], loc)
            elif tid.startswith("F-"):
                idx.setdefault("T-" + tid[2:], loc)
        t_by_id = {(t.get("t_id") or t.get("id") or "").strip().upper(): t for t in threats}
        for m in (self.yaml_data or {}).get("mitigations", []) or []:
            mid = (m.get("m_id") or m.get("id") or "").strip().upper()
            if not mid:
                continue
            loc = _mitigation_locator(m, t_by_id)
            if loc:
                idx.setdefault(mid, loc)
        return idx

    def location_for_ref(self, ref: str, full_path: bool = False) -> str:
        """Locator for a finding/mitigation ref, or "" when unknown.

        Default returns ``basename:line`` (inline references stay short);
        ``full_path=True`` returns the full ``path/file:line`` (used only by the
        Findings index, which has the horizontal room).
        """
        if not ref:
            return ""
        if self._location_index is None:
            self._location_index = self._build_location_index()
        loc = self._location_index.get(ref.strip().upper(), "")
        if not loc:
            return ""
        return loc if full_path else _basename_locator(loc)

    @staticmethod
    def _synthesise_label_noop() -> None:
        """Placeholder — kept so downstream imports do not break if they
        referenced the old split-on-dot behaviour. The real logic lives in
        the module-level helper ``_synthesise_label`` below."""

    def linkify_with_short_label(self, ref: str, label_override: str | None = None) -> str:
        """Inline-prose form of cross-references: `[ID](#anchor) (short_label)`.

        Use this in chain takeaways, walkthrough bullets, and any other
        inline-prose context where the full `[ID](#anchor) — title — file`
        form (emitted by `linkify_with_label`) reads as a torn-link
        construct because `_normalize_emdashes` mid-line eats the em-dash
        separator AND the title carries its own ` — <file>` suffix.

        Short-label rule handles BOTH title forms produced by upstream
        processing — without this, `_normalize_title_to_paren_form`
        (M-10c, runs during compose's per-threat title rewrite) would
        leave the file segment INSIDE the parens span and we'd render
        the visually broken nested-parens form
        `[F-005](#f-005) (Reflected XSS (search-result.component.ts))`:

          - ``<weakness> — <file>``   (raw Stage-1 LLM form)
            → split on ` — `, take leading segment
          - ``<weakness> (<file>)``   (post-_normalize_title_to_paren_form)
            → strip trailing ``(…)`` group

        When neither separator is present, the whole label is used.
        Empty label degrades to ``[ID](#anchor)`` (no parens), same as
        ``linkify_with_label``.
        """
        if not ref:
            return ""
        r = ref.strip()
        if not r:
            return ""
        m = re.match(r"^T-(\d+)$", r)
        if m:
            r = f"F-{m.group(1)}"
        anchor = r.lower()
        label = (label_override or self.lookup_label(r) or "").strip()
        # Strip the file-path tail in either em-dash or parens form.
        short = label.split(" — ", 1)[0].strip()
        short = re.sub(r"\s*\([^()]*\)\s*$", "", short).strip()
        if short:
            # Escape unescaped `$` so a token like `$where` does not open a
            # KaTeX/LaTeX math span in math-enabled markdown viewers (which then
            # swallows everything up to the next `$`/`#` and throws a parse
            # error). `\$` renders as a literal `$` in plain markdown too.
            short = re.sub(r"(?<!\\)\$", r"\\$", short)
            return f"[{r}](#{anchor}) ({short})"
        return f"[{r}](#{anchor})"

    def linkify_with_label(
        self,
        ref: str,
        label_override: str | None = None,
        compact: bool = False,
        full_path: bool = False,
    ) -> str:
        """Emit the canonical reference form for a finding/threat/mitigation.

        Two shapes, and ONLY these two (enforced by the §reference-format linter
        test):

          * **Full (default):** ``<glyph> [ID](#id) — <label> (`file:line`)`` —
            ID linked once, class label, basename:line locator backticked in
            parens (full path when ``full_path=True``, used by the Findings
            index). The locator is appended ONLY when the label was resolved
            here (``label_override is None``); an explicit override is trusted
            verbatim so a caller can still pass a fully-formed label.
          * **Short (`compact=True`):** ``<glyph> [ID](#id)`` — ID only, still
            linked. For the deliberately narrow contexts (Verdict "Dominant
            Attack Paths", measure chips, narrow Addresses columns).

        Visible label normalisation (P4): when ``ref`` is T-NNN we expose
        F-NNN as the user-visible label and link to the F-anchor. Both
        anchors exist (the dual-anchor emission in
        ``_render_threat_register`` and the post-render F-bridge guarantee
        it). The qa-reviewer canonical contract names F-NNN as the
        rendered finding ID — using a single visible form across §4 / §5 /
        §7 / §8 / Verdict / Architecture-Assessment makes the document
        read consistently. Non-T-NNN refs (M-NNN, C-NN, AF-NNN, TH-NN)
        pass through unchanged.
        """
        if not ref:
            return ""
        r = ref.strip()
        if not r:
            return ""
        # Normalise T-NNN visible label → F-NNN. The link target uses the
        # F-anchor for symmetry with the visible label.
        m = re.match(r"^T-(\d+)$", r)
        if m:
            r = f"F-{m.group(1)}"
        anchor = r.lower()
        label = "" if compact else (label_override or self.lookup_label(r) or "").strip()
        # Leading criticality glyph: findings carry a coloured severity dot,
        # mitigations a monochrome circled rollout-priority digit. Components
        # (C-NN) and threat categories (TH-NN) carry no glyph. The glyph sits
        # OUTSIDE the markdown link so `_enrich_linked_id_cells` (which extracts
        # `[ID](#anchor)` and re-linkifies) regenerates exactly one glyph — never
        # doubles it. Empty/unknown severity or priority → no glyph.
        dot = ""
        if re.match(r"^F-\d+$", r):
            emoji = self.severity_emoji(self.severity_for_ref(r))
            if emoji:
                dot = f"{emoji} "
        elif re.match(r"^M-\d+$", r):
            # Measures analogue of the finding severity dot: a single colourless
            # fill-ramp circle whose fill IS the rollout priority (● P1 … ○ P4),
            # Variant B (2026-06-04). It sits OUTSIDE the markdown link for the
            # same reason the severity dot does: `_enrich_linked_id_cells`
            # extracts `[ID](#…)` and re-linkifies, so the prefix is regenerated
            # exactly once. Mirrors the finding form `🔴 [F-NNN] — title`.
            digit = _PRIO_RAMP_TBL.get(self.priority_for_ref(r), "")
            if digit:
                dot = f"{digit} "
        if compact:
            return f"{dot}[{r}](#{anchor})"
        # Any locator embedded in the label (raw YAML titles / fragment labels
        # sometimes carry `(file)` or `— file:line`) is STRIPPED, then the
        # canonical `(`file:line`)` is appended from the location index — so the
        # locator is always present exactly once and always backticked, no
        # matter how the caller sourced the label.
        if label:
            label = _strip_trailing_locator(label)
        loc = ""
        loc_raw = self.location_for_ref(r, full_path=full_path)
        if loc_raw:
            loc = f" (`{loc_raw}`)"
        if label:
            # Escape unescaped `$` (see linkify_with_short_label) so a `$where`-
            # style token cannot open a KaTeX math span in math-enabled viewers.
            label = re.sub(r"(?<!\\)\$", r"\\$", label)
            return f"{dot}[{r}](#{anchor}) — {label}{loc}"
        return f"{dot}[{r}](#{anchor}){loc}"


# ---------------------------------------------------------------------------
# Label synthesis helper — last-resort fallback when a threat yaml entry is
# missing both `title` and `scenario_short`. Must produce a string safe to
# embed in table cells and prose headings.
# ---------------------------------------------------------------------------

_LABEL_MAX_CHARS = 80


def _synthesise_label(scenario: str) -> str:
    """Produce a short, table-safe label from a long threat scenario.

    Guarantees:
      * No unclosed backticks — if a backtick opens inside the kept window,
        we drop from the last opening backtick onward.
      * No markdown link fragments — we strip `[text](url)` down to just
        `text` first.
      * No mid-word truncation — we cut at the last whitespace before the
        char limit rather than slicing blindly.
      * No spurious splits on `ClassName.java:NN` — we split on sentence
        terminators (`. ` or `! ` or `? `) rather than any dot.
    """
    if not scenario:
        return ""
    s = scenario.strip()
    # Reduce markdown links to their visible text.
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
    # Sentence split — a dot/bang/question must be followed by whitespace to
    # count as a terminator. This keeps `CommandInjection.java:45` intact.
    m = re.search(r"[.!?]\s", s)
    if m:
        s = s[: m.start()].strip()
    # Normalise whitespace (newlines, tabs → single space).
    s = re.sub(r"\s+", " ", s)
    if len(s) <= _LABEL_MAX_CHARS:
        return _close_backticks(s)
    # Cut at the last whitespace before the limit so we never truncate a word.
    cut = s.rfind(" ", 0, _LABEL_MAX_CHARS)
    if cut < _LABEL_MAX_CHARS // 2:
        # No reasonable break point — fall back to hard slice + ellipsis.
        cut = _LABEL_MAX_CHARS - 1
    out = s[:cut].rstrip(",; :—–-")
    return _close_backticks(out) + "…"


def _close_backticks(s: str) -> str:
    """If the string contains an unclosed backtick, drop from the last
    opening backtick onward. Prevents broken `code` spans from bleeding
    into surrounding markdown."""
    if s.count("`") % 2 == 0:
        return s
    last = s.rfind("`")
    return s[:last].rstrip(",; :—–-")


# ---------------------------------------------------------------------------
# Condition evaluator — a tiny, safe subset of Python boolean expressions
# ---------------------------------------------------------------------------


def eval_condition(expr: str, env: dict[str, Any]) -> bool:
    """Evaluate a sections-contract condition expression against ``env``.

    Thin adapter over ``_safe_cond.resolve_condition`` — supports only
    bare-name lookups, ``not <name>`` and ``<name> [not] in [..]`` membership.
    See ``scripts/_safe_cond.py`` for the full grammar.
    """
    try:
        return _safe_cond.resolve_condition(expr, env)
    except _safe_cond.SafeCondError as e:
        raise ContractError(str(e)) from e


# ---------------------------------------------------------------------------
# Jinja environment with custom filters
# ---------------------------------------------------------------------------


def _build_jinja_env(ctx: RenderContext) -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=False,
        trim_blocks=False,
        lstrip_blocks=False,
        keep_trailing_newline=True,
    )

    env.globals["severity_emoji"] = ctx.severity_emoji
    env.globals["severity_label"] = ctx.severity_label
    env.globals["effectiveness_badge"] = ctx.effectiveness_badge
    env.globals["linkify_with_label"] = ctx.linkify_with_label

    def linkify_refs(refs: list[str]) -> str:
        """Convert `["F-009"]` → `[F-009](#f-009)` (bare link — used inside
        contexts that already carry the label in surrounding prose, e.g. the
        Verdict blockquote bullets `- **Full DB theft** — …  *([F-009](#f-009))*`).

        For contexts that need the `— <label>` suffix (table cells, defect
        blocks, Addresses lists), use `linkify_with_label` directly or the
        dedicated filter `format_*` helpers below.

        P4 label normalisation: T-NNN refs are rendered as F-NNN visible
        labels (and link to the F-anchor) so the document is consistent
        with the qa-reviewer canonical contract.
        """
        if not refs:
            return ""
        out = []
        for r in refs:
            r = r.strip()
            if not r:
                continue
            m = re.match(r"^T-(\d+)$", r)
            if m:
                r = f"F-{m.group(1)}"
            # Leading severity dot for finding refs (mirrors `linkify_with_label`)
            # so the Verdict blockquote finding list is annotated like every
            # other linked-findings context. Sits OUTSIDE the markdown link.
            dot = ""
            if re.match(r"^F-\d+$", r):
                emoji = ctx.severity_emoji(ctx.severity_for_ref(r))
                if emoji:
                    dot = f"{emoji} "
            out.append(f"{dot}[{r}](#{r.lower()})")
        return ", ".join(out)

    def format_id_list(refs: list[str]) -> str:
        """Convert a list of IDs (T-NNN, M-NNN, F-NNN) to `<br/>`-stacked
        labelled links — used in multi-ref table cells so each entry is on its
        own line instead of comma-joined.  Single-item lists skip the `<br/>`.
        """
        # Defensive: a scalar string (e.g. a singular `mitigation: "M-002"`
        # field rendered through this list filter, as in
        # templates/fragments/critical-attack-tree.md.j2 →
        # `mitigation_breakpoints[].mitigation`) must be treated as ONE id, not
        # iterated character-by-character — otherwise "M-002" renders as
        # `[M](#m)<br/>[-](#-)<br/>[0](#0)<br/>[0](#0)<br/>[2](#2)`, which also
        # spawns bogus #m / #- / #0 anchors that break toc_closure.
        if isinstance(refs, str):
            refs = [refs]
        if not refs:
            return "—"
        parts = [ctx.linkify_with_label(r.strip()) for r in refs]
        return "<br/>".join(parts)

    def format_mitigations(items: list[dict[str, Any]]) -> str:
        if not items:
            return "—"
        rendered = []
        for it in items:
            mid = it["id"]
            action = it.get("action", "").strip()
            kind = (it.get("kind") or "").strip().lower()
            # M-RCA-2026-05: render per-kind glyph (🔧/🔍/🧭/🛈) so a
            # reviewer can scan the column and triage at a glance. `fix`
            # is the default and renders unprefixed to preserve pre-2026-05
            # MD output for the common case.
            glyph = {
                "review": "🔍 ",
                "investigate": "🧭 ",
                "accept_risk": "🛈 ",
            }.get(kind, "")
            if mid:
                # Variant B (2026-06-04): lead with the monochrome priority
                # prefix (`● ` for P1) — same as every other linked measure —
                # then the action-kind glyph (orthogonal signal). Supersedes the
                # old trailing `(P1)` token.
                line = f"{_measure_prio_prefix(ctx, mid)}{glyph}[{mid}](#{mid.lower()})"
            else:
                # Synthesized review-hint (M-14) — no M-NNN anchor; the
                # `action` field already carries "Manual review at <file>"
                # plus its own anchor link.
                line = f"{glyph}{action}"
                action = ""  # already consumed
            if action:
                line += f" — {action}"
            rendered.append(line)
        return "<br/>".join(rendered)

    def format_weakness_findings(items: list[dict[str, Any]], sep: str = "<br/>") -> str:
        # `sep` defaults to <br/> for the Architecture-Assessment table cells
        # (vertical stacking inside one cell); pass ", " for inline prose
        # contexts (e.g. the Anti-Patterns sub-bullets) so links flow on one
        # line instead of forcing a literal <br/> mid-sentence.
        if not items:
            return "—"
        rendered = []
        for it in items:
            # Canonical reference form (ID — label (`file:line`)); the curated
            # fragment label, if any, overrides the indexed title but the locator
            # is still normalised by linkify_with_label.
            rendered.append(ctx.linkify_with_label(it["ref"], label_override=(it.get("label") or "").strip() or None))
        return sep.join(rendered)

    def format_one_finding(item: dict[str, Any]) -> str:
        """Render a single {ref, label?} findings dict as a markdown link string.

        Used by ai-exposure.md.j2 to loop over findings individually so each
        can be emitted as a proper indented sub-list item (``  - ↳ link``)
        rather than inline via ``<br/>↳`` within the parent bullet.
        Applies the same T-NNN → F-NNN normalisation as format_weakness_findings.
        """
        return ctx.linkify_with_label(
            (item.get("ref") or "").strip(), label_override=(item.get("label") or "").strip() or None
        )

    # Back-compat alias: callers in older templates still use the legacy
    # `format_defect_findings` name. New code uses `format_weakness_findings`.
    format_defect_findings = format_weakness_findings

    def format_weakness_components(items: list[dict[str, Any]] | list[str], sep: str = "<br/>") -> str:
        """Render `affected_components[]` as linked component names.

        Accepts either a list of `{id, name}` dicts (preferred) or bare
        component-id strings (legacy). `sep` defaults to <br/> for table
        cells; pass ", " for inline prose contexts (Anti-Patterns sub-bullets).
        """
        if not items:
            return "—"
        parts = []
        for it in items:
            if isinstance(it, str):
                cid = it
                name = ""
            else:
                cid = (it.get("id") or "").strip()
                name = (it.get("name") or "").strip()
            if cid and name:
                parts.append(f"[{cid}](#{cid.lower()}) — {name}")
            elif cid:
                parts.append(f"[{cid}](#{cid.lower()})")
            elif name:
                parts.append(name)
        return sep.join(parts) if parts else "—"

    def format_component_list(items: list[dict[str, Any]] | str) -> str:
        if isinstance(items, str):
            return items
        if not items:
            return "—"
        parts = []
        for it in items:
            cid = it.get("id", "")
            name = it.get("name", "")
            if cid and name:
                parts.append(f"[{cid}](#{cid.lower()}) — {name}")
            elif name:
                parts.append(name)
            elif cid:
                parts.append(f"[{cid}](#{cid.lower()})")
        return "<br/>".join(parts)

    def _normalize_finding_label(ref: str) -> str:
        # P4 — visible-label normalisation. T-NNN → F-NNN; other ID classes
        # (M-, C-, AF-, TH-, CC-) pass through unchanged. Uses the dual-
        # anchor emission from `_render_threat_register` so the F-anchor
        # always resolves.
        if not isinstance(ref, str):
            return ref
        m_t = re.match(r"^T-(\d+)$", ref.strip())
        if m_t:
            return f"F-{m_t.group(1)}"
        return ref

    def format_mitigation_addresses(items: list[dict[str, Any]]) -> str:
        if not items:
            return "—"
        # Canonical full form (ID — label (`file:line`)), consistent with every
        # other Addresses/Findings column; linkify_with_label normalises the
        # locator from the curated fragment label.
        parts = [
            ctx.linkify_with_label(
                it.get("ref") or it.get("id", ""), label_override=(it.get("label") or "").strip() or None
            )
            for it in items
        ]
        return "<br/>".join(parts)

    def format_strengths_mitigates(items: list[dict[str, Any]] | list[str]) -> str:
        if not items:
            # The renderer decides whether to emit the Mitigates column at
            # all (see `_render_operational_strengths`); when the column is
            # present but a single row has no mapped findings, emit a bare
            # dash rather than a hard-coded explanatory sentence — repeated
            # across rows the sentence becomes table noise that hides the
            # real per-row content.
            return "—"
        parts = []
        for it in items:
            if isinstance(it, dict):
                # Cluster-mode overflow marker: render as italic plain text
                # so the reader knows the list was capped without thinking
                # it is a missing link.
                if it.get("_overflow"):
                    label = (it.get("label") or "").strip()
                    if label:
                        parts.append(f"_{label}_")
                    continue
                ref = _normalize_finding_label(it.get("ref") or it.get("id", ""))
                label = (it.get("label") or "").strip()
                # Trim long titles to keep cluster-mode Mitigates cells
                # readable — full titles live in §8.
                if label and len(label) > 60:
                    label = label[:57].rstrip(" ,;") + "…"
                # Route through linkify_with_label so the locator is normalised
                # (stripped from the curated label, re-appended backticked).
                parts.append(ctx.linkify_with_label(ref, label_override=label or None))
            else:
                parts.append(ctx.linkify_with_label(str(it)))
        return "<br/>".join(parts)

    env.filters["linkify_refs"] = linkify_refs
    env.filters["format_id_list"] = format_id_list
    env.filters["format_mitigations"] = format_mitigations
    env.filters["format_defect_findings"] = format_defect_findings  # back-compat alias
    env.filters["format_weakness_findings"] = format_weakness_findings
    env.filters["format_one_finding"] = format_one_finding
    env.filters["format_weakness_components"] = format_weakness_components
    env.filters["format_component_list"] = format_component_list
    env.filters["format_mitigation_addresses"] = format_mitigation_addresses
    env.filters["format_strengths_mitigates"] = format_strengths_mitigates
    env.filters["bullet_list"] = bullet_list
    env.globals["pluralize"] = pluralize

    return env


def pluralize(n: int, singular: str, plural: str | None = None) -> str:
    """Return "{n} singular" or "{n} plural" depending on count.

    Eliminates the "(s)"-suffix anti-pattern ("5 component(s)",
    "1 item(s)") that surfaces across the rendered report. English
    pluralisation is naive but covers the cases that actually appear in
    output: default plural is `singular + "s"`; pass `plural` explicitly
    for irregulars (`pluralize(n, "finding", "findings")` is the same as
    default, but `pluralize(n, "category", "categories")` needs the
    explicit form).
    """
    if plural is None:
        plural = singular + "s"
    return f"{n} {singular if n == 1 else plural}"


def bullet_list(items: list, *, prefix: str = "- ") -> str:
    """Render a list of strings or ``{label, ref, href}`` dicts as a GitHub-
    flavored Markdown bullet list, one item per line.

    Intended for contexts where the contract specifies ``render: bullet_list``
    (for example the Gap Summary block inside ``security-architecture.md``).
    Avoids the run-on ``(1) … (2) …`` prose pattern that the LLM otherwise
    defaults to when writing summary blocks by hand.

    - Plain strings are emitted verbatim (``- foo``).
    - Dicts with a ``label`` / ``text`` field and optional ``ref``/``href``
      are rendered as ``- **<label>** — …`` or ``- [label](href) — …``.
    - Empty or missing lists return an empty string (callers decide how
      to handle the "nothing to show" case).

    Declared at module level so callers (tests, future contract-computed
    sections) can use it without building a full Jinja environment.
    """
    if not items:
        return ""
    lines: list[str] = []
    for it in items:
        if isinstance(it, str):
            lines.append(f"{prefix}{it.strip()}")
            continue
        if not isinstance(it, dict):
            lines.append(f"{prefix}{it}")
            continue
        label = (it.get("label") or it.get("text") or "").strip()
        ref = (it.get("ref") or it.get("id") or "").strip()
        href = (it.get("href") or "").strip()
        extra = (it.get("detail") or it.get("description") or "").strip()
        parts: list[str] = []
        if href:
            parts.append(f"[{label or href}]({href})")
        elif ref:
            parts.append(f"[{label or ref}](#{ref.lower()})")
        elif label:
            parts.append(f"**{label}**")
        if extra:
            parts.append(f"— {extra}" if parts else extra)
        lines.append(prefix + " ".join(parts))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# YAML helpers — derivations from threat-model.yaml
# ---------------------------------------------------------------------------


def _severity_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get((sev or "").strip().lower(), 99)


def _effort_rank(effort: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get((effort or "").strip().lower(), 99)


def _effectiveness_rank(eff: str) -> int:
    return {"adequate": 0, "partial": 1, "weak": 2, "missing": 3}.get((eff or "").strip().lower(), 99)


def _component_lookup(ctx: RenderContext) -> dict[str, dict[str, Any]]:
    """Return components keyed by their canonical C-NN id.

    The canonical reference format uses `C-01`, `C-02`, … anchors. When
    threat-model.yaml carries a non-canonical id (e.g. `auth-service`), we
    synthesise a C-NN based on the order in the array and also index by the
    original id so lookups from `threat.component_id = "auth-service"` still
    resolve. This keeps the rendered markdown stable across runs even when
    the orchestrator used slug-style component IDs.
    """
    out: dict[str, dict[str, Any]] = {}
    for idx, c in enumerate(ctx.yaml_data.get("components") or [], start=1):
        if not isinstance(c, dict):
            continue
        raw = (c.get("id") or "").strip()
        c.setdefault("_original_id", raw)
        if re.match(r"^C-\d+$", raw):
            canonical = raw
        else:
            canonical = f"C-{idx:02d}"
            c.setdefault("_canonical_id", canonical)
        out[canonical] = c
        if raw and raw != canonical:
            out[raw] = c  # alias so `threats[].component_id = "auth-service"` resolves
    return out


def _component_slug_to_cnn_map(ctx: RenderContext) -> dict[str, str]:
    """Build a lower-cased {component-id-or-slug → canonical C-NN} lookup.

    The C-NN assignment (``C-{idx:02d}`` by component array order) is identical
    to ``_component_lookup`` so anchors stay consistent across the document.
    """
    cmap: dict[str, str] = {}
    for idx, c in enumerate(ctx.yaml_data.get("components") or [], start=1):
        if not isinstance(c, dict):
            continue
        raw = (c.get("id") or "").strip()
        canonical = raw if re.match(r"^C-\d+$", raw) else f"C-{idx:02d}"
        if raw:
            cmap[raw.lower()] = canonical
        cmap[canonical.lower()] = canonical
    return cmap


def _normalize_affected_component_refs(refs: Any, cmap: dict[str, str]) -> tuple[Any, bool]:
    """Return (normalised refs, changed?) for an ``affected_components`` list.

    Accepts both the bare-string form (``"backend-api"``) and the ``{id, name}``
    dict form the schemas permit. An already-canonical or unknown ref is left
    untouched so the schema still catches genuine garbage.
    """
    if not isinstance(refs, list):
        return refs, False
    new_refs: list[Any] = []
    changed = False
    for r in refs:
        if isinstance(r, str):
            canon = cmap.get(r.strip().lower())
            if canon and canon != r:
                new_refs.append(canon)
                changed = True
                continue
        elif isinstance(r, dict) and isinstance(r.get("id"), str):
            canon = cmap.get(r["id"].strip().lower())
            if canon and canon != r["id"]:
                r = {**r, "id": canon}
                changed = True
        new_refs.append(r)
    return new_refs, changed


def _normalize_fragment_component_refs(ctx: RenderContext, filename: str, list_key: str) -> None:
    """Rewrite ``affected_components`` slug ids → canonical C-NN in one MS fragment.

    Shared engine for ms-anti-patterns.json (``anti_patterns[]``) and
    ms-ai-exposure.json (``ai_risks[]``). Both fragment schemas require the
    canonical ``^C-\\d{2,}$`` form, but the threat-renderer (RENDER_ROLE=ms)
    sometimes writes the raw component slug it reads from ``threat-model.yaml``
    (e.g. ``ai-chatbot-service``) instead — a HARD ``--strict`` compose abort
    (observed: anti-patterns 2026-06-12, ai-exposure 2026-06-21 juice-shop).
    Normalising here — once, before BOTH validation sites — makes the fragment
    schema-valid and any derived anchor resolvable. Idempotent.
    """
    path = ctx.fragments_dir / filename
    if not path.is_file():
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return  # malformed JSON is the validator's problem, not ours
    items = data.get(list_key)
    if not isinstance(items, list):
        return
    cmap = _component_slug_to_cnn_map(ctx)
    changed = False
    for it in items:
        if not isinstance(it, dict):
            continue
        new_refs, item_changed = _normalize_affected_component_refs(it.get("affected_components"), cmap)
        if item_changed:
            it["affected_components"] = new_refs
            changed = True
    if changed:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _normalize_anti_pattern_component_refs(ctx: RenderContext) -> None:
    """Normalise ms-anti-patterns.json ``affected_components`` slug ids → C-NN.

    Thin wrapper over ``_normalize_fragment_component_refs`` retained as a stable
    public entry point (referenced by ``tests/test_fragment_authoring_fidelity``).
    """
    _normalize_fragment_component_refs(ctx, "ms-anti-patterns.json", "anti_patterns")


def _normalize_ms_component_refs(ctx: RenderContext) -> None:
    """Normalise component refs across every MS fragment that carries them.

    Covers both ms-anti-patterns.json (``anti_patterns[]``) and
    ms-ai-exposure.json (``ai_risks[]``) so a slug in EITHER fragment is rewritten
    to its canonical C-NN before validation. Previously only anti-patterns was
    normalised, so an ai-exposure slug hard-failed ``compose --strict`` with no
    recovery (RC-1, 2026-06-21 juice-shop run).
    """
    _normalize_fragment_component_refs(ctx, "ms-anti-patterns.json", "anti_patterns")
    _normalize_fragment_component_refs(ctx, "ms-ai-exposure.json", "ai_risks")


def _threat_lookup(ctx: RenderContext) -> dict[str, dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for t in ctx.yaml_data.get("threats", []):
        if isinstance(t, dict):
            tid = t.get("t_id") or t.get("id") or ""
            if tid:
                by_id[tid] = t
    return by_id


def _mitigation_lookup(ctx: RenderContext) -> dict[str, dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for m in ctx.yaml_data.get("mitigations", []):
        if isinstance(m, dict):
            mid = m.get("m_id") or m.get("id") or ""
            if mid:
                by_id[mid] = m
    return by_id


# P4 — Curated domain → CWE map for control auto-derivation.
# Mirrors `_SUBSECTION_CWE_HINTS` in pregenerate_fragments.py at the
# §7 sub-section level (key change: keyed by control.domain free-text
# fragments, not by section number, since the yaml exposes domain
# labels). Each domain matches via a substring check on the lowercased
# control.domain field; multiple matches union their CWE sets.
_CONTROL_DOMAIN_CWE_MAP: list[tuple[tuple[str, ...], frozenset[str]]] = [
    # (domain-substring tuple, matching CWE set)
    (
        ("identity", "iam", "authentication", "auth "),
        frozenset(
            {
                "CWE-287",
                "CWE-294",
                "CWE-307",
                "CWE-308",
                "CWE-345",
                "CWE-347",
                "CWE-384",
                "CWE-916",
                "CWE-613",
                "CWE-640",
            }
        ),
    ),
    (
        ("authorization", "access control", "rbac", "abac"),
        frozenset({"CWE-285", "CWE-639", "CWE-862", "CWE-863", "CWE-732", "CWE-269", "CWE-915"}),
    ),
    (
        ("input validation", "output encoding", "sanitization", "injection"),
        frozenset(
            {
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
                "CWE-643",
                "CWE-943",
            }
        ),
    ),
    (
        ("data protection", "session", "encryption", "crypto"),
        frozenset(
            {
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
                "CWE-321",
                "CWE-798",
            }
        ),
    ),
    (("frontend", "csp", "xss", "csrf"), frozenset({"CWE-79", "CWE-352", "CWE-1021", "CWE-942", "CWE-693"})),
    (("websocket", "real-time", "socket.io"), frozenset({"CWE-346", "CWE-1357"})),
    (
        ("ai / llm", "artificial intelligence", "llm", "prompt injection", "ml model"),
        frozenset({"CWE-1039", "CWE-1426"}),
    ),
    (("audit", "logging", "monitoring", "siem"), frozenset({"CWE-117", "CWE-223", "CWE-532", "CWE-778"})),
    (
        ("infrastructure", "network", "segmentation", "firewall", "waf", "container & runtime", "container", "runtime"),
        frozenset({"CWE-200", "CWE-540", "CWE-942", "CWE-555"}),
    ),
    (("dependency", "supply chain", "sca", "package"), frozenset({"CWE-1357", "CWE-1188", "CWE-1395", "CWE-829"})),
    (("secret", "key management", "vault", "kms"), frozenset({"CWE-321", "CWE-798", "CWE-200", "CWE-538", "CWE-260"})),
]


# CWE -> required control-name keywords. When a candidate CWE is in this
# map, the matched control MUST have at least one of the listed tokens
# in its name; otherwise the match is rejected. This is the C1 fix:
# previously "2FA" and "Brute-force protection" both have domain=IAM and
# therefore matched CWE-916 (password hashing) -- their candidate-finding
# list claimed they mitigate the MD5 finding, which is wrong (rate
# limiting on login does not protect leaked password hashes from offline
# cracking). With this gate, only a control whose name contains
# "hash"/"password"/"bcrypt"/"argon" can claim CWE-916 as mitigated.
_CWE_REQUIRES_NAME_TOKEN: dict[str, frozenset[str]] = {
    "CWE-916": frozenset({"hash", "hashing", "password", "bcrypt", "argon", "scrypt", "pbkdf2"}),
    "CWE-759": frozenset({"hash", "salt", "password", "bcrypt", "argon"}),
    "CWE-760": frozenset({"hash", "salt", "password", "bcrypt", "argon"}),
    "CWE-328": frozenset({"hash", "password", "bcrypt", "argon"}),
    "CWE-321": frozenset(
        {"key", "secret", "kms", "vault", "rotation", "rotate", "manager", "externalize", "externaliz"}
    ),
    "CWE-798": frozenset(
        {"credential", "secret", "key", "kms", "vault", "rotation", "rotate", "externalize", "externaliz"}
    ),
    "CWE-352": frozenset({"csrf", "samesite", "double-submit", "anti-csrf", "csurf"}),
    "CWE-918": frozenset({"ssrf", "allowlist", "egress", "url"}),
    "CWE-922": frozenset({"storage", "cookie", "httponly", "localstorage", "session"}),
    "CWE-915": frozenset({"mass-assignment", "mass", "whitelist", "allowlist", "schema", "binding"}),
    "CWE-639": frozenset({"ownership", "object", "idor", "authorization", "scope"}),
    "CWE-347": frozenset({"signature", "algorithm", "jwt", "verify", "whitelist", "allowlist"}),
    "CWE-94": frozenset({"eval", "sandbox", "parser", "schema", "input"}),
    "CWE-611": frozenset({"xxe", "xml", "entity", "noent"}),
}


def _derive_control_mitigates(control: dict[str, Any], threats: list[dict[str, Any]]) -> list[str]:
    """Heuristic: derive a control's mitigated-findings list when the yaml
    `mitigates_findings` field is empty.

    Two signals (cumulative scoring, threshold = match):

      1. **Domain → CWE membership.** The control's `domain` field maps to
         a curated CWE set via ``_CONTROL_DOMAIN_CWE_MAP``. Every threat
         whose CWE belongs to that set is a candidate.
      2. **Control-name keyword match.** Tokens of length ≥ 4 from the
         control's `control` / `name` field that appear in the threat's
         scenario / title raise the candidate's score.
      3. **Required-token gate (C1).** For CWEs with a strong-mitigation
         signature (password hashing, CSRF token, key rotation, etc.)
         the control's name MUST contain at least one of the required
         tokens. This drops false-positives like "2FA mitigates MD5
         hashing" that the domain-only filter let through.

    Returns at most 5 finding refs, ordered by descending score then by
    severity (Critical/High first). Returns an empty list when the domain
    isn't catalogued or no threat scores high enough — preferable to
    emitting wrong references just to fill a cell.
    """
    if not isinstance(control, dict) or not threats:
        return []

    domain = (control.get("domain") or "").lower()
    if not domain:
        return []

    # Determine the candidate CWE set from domain substrings.
    cwe_set: set[str] = set()
    for substrings, cwes in _CONTROL_DOMAIN_CWE_MAP:
        if any(s in domain for s in substrings):
            cwe_set |= set(cwes)
    if not cwe_set:
        return []

    # Tokens from the control's name for the keyword bonus AND the C1
    # required-token gate below.
    name_text = " ".join(
        [
            (control.get("control") or ""),
            (control.get("name") or ""),
            (control.get("canonical_name") or ""),
            (control.get("implementation") or ""),
        ]
    ).lower()
    name_tokens = {tok.strip("`'\"-*_") for tok in re.split(r"[\s/,.;:!?\\(){}\[\]<>|]+", name_text) if len(tok) >= 3}

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    scored: list[tuple[str, int, int]] = []  # (tid, score, sev_rank)
    for t in threats:
        if not isinstance(t, dict):
            continue
        tid = (t.get("t_id") or t.get("id") or "").strip()
        if not tid:
            continue
        cwe = (t.get("cwe") or t.get("cwe_id") or "").strip().upper()
        if not cwe.startswith("CWE-"):
            cwe = "CWE-" + cwe.lstrip("0") if cwe else ""
        if cwe not in cwe_set:
            continue
        # C1 — required-token gate. A control may only claim to mitigate
        # a CWE in this map if its name contains at least one of the
        # listed tokens. Otherwise the domain match is rejected as a
        # false positive (the classic 2FA-mitigates-MD5 case).
        required = _CWE_REQUIRES_NAME_TOKEN.get(cwe)
        if required and not any(rt in tok for rt in required for tok in name_tokens):
            # No substring of any control-name token matches a required
            # signature token. The control is in the right domain but
            # does not actually address this CWE.
            continue
        score = 1  # base for CWE membership
        full_text = " ".join(
            [
                t.get("scenario") or "",
                t.get("title") or "",
                t.get("description") or "",
            ]
        ).lower()
        for tok in name_tokens:
            if tok in full_text:
                score += 1
        sev = (t.get("risk") or t.get("severity") or "low").lower()
        scored.append((tid, score, sev_rank.get(sev, 99)))

    # Sort: highest score first, then lowest severity-rank (Critical first).
    scored.sort(key=lambda x: (-x[1], x[2], x[0]))
    return [tid for tid, _, _ in scored[:5]]


def _normalize_security_controls(raw: list) -> list[dict[str, Any]]:
    """Coerce ``security_controls`` to a list of dicts so renderers don't
    crash on intermittent LLM schema drift.

    The canonical schema (schemas/threat-model.output.schema.yaml) defines
    ``security_controls`` as ``array<object>`` with required ``[domain,
    control, effectiveness]``. Phase 8 occasionally emits a degenerate
    list of bare domain identifiers (``['iam', 'authorization', ...]``)
    that crashes downstream ``c.get(...)`` calls. We normalise both shapes
    here and let the SCHEMA_DRIFT signal in validate_intermediate.py
    surface the regression to the user without aborting the render.
    """
    out: list[dict[str, Any]] = []
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
        # Anything else (None, int) is silently dropped
    return out


def _severity_counts(ctx: RenderContext) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for t in ctx.yaml_data.get("threats", []):
        sev = (t.get("risk") or t.get("severity") or "").strip().lower()
        # Normalise the schema-enum value "Informational" to the internal
        # counter key "info" (used by `_SEV_RANK_TBL` / `_SEV_ICON_TBL` /
        # `severity_taxonomy`). Without this the new Informational enum
        # value (schema enum extended in M-RCA-2026-05) would silently
        # vanish from the severity counts even though the rendering
        # stack is otherwise info-aware.
        if sev == "informational":
            sev = "info"
        if sev in counts:
            counts[sev] += 1
    return counts


def _resolve_security_arch_override(
    output_dir: Path,
    current_depth: str,
    current_threats: Optional[list] = None,
) -> Optional[str]:
    """Decide whether §7 should render in quick mode, and with what content.

    Returns
    -------
    None
        Render normally — current depth is standard/thorough or unknown, so
        the regular fragment-driven render path applies.
    "" (empty string)
        Skip §7 entirely — current depth is quick AND no rich prior content
        exists (no prior MD, prior depth was also quick, or §7 could not be
        extracted). The section composer drops empty-body sections from
        output and the TOC builder respects the `render_security_architecture`
        flag, so neither body nor TOC entry is emitted.
    <verbatim markdown>
        Preserve §7 from the prior threat-model.md verbatim — current depth
        is quick AND the prior run was standard/thorough. Avoids destroying
        the rich per-domain narrative when the user re-runs at quick depth.

    The prior depth is read from `.appsec-cache/baseline.json.last_run_depth`
    which is updated by the skill AFTER compose, so during compose it still
    reflects the previous run.
    """
    if (current_depth or "").strip().lower() != "quick":
        return None

    # Preferred source (2026-06-26): the run-start snapshot in
    # .appsec-cache/preserved-sections/, captured by snapshot_preserved_sections.py
    # BEFORE the orchestrator overwrites threat-model.md. The prior depth comes
    # from the snapshot manifest's `origin_depth`. This replaces the two
    # unreliable inputs that made the preserve silently fail: the live (already
    # clobbered) threat-model.md and baseline.json.last_run_depth (often never
    # persisted). Falls back to the legacy live-md + baseline.json path so older
    # output dirs without a snapshot still behave as before.
    snap_dir = output_dir / ".appsec-cache" / "preserved-sections"
    manifest_path = snap_dir / "manifest.json"
    snap_md_path = snap_dir / "prior-report.md"

    prior_depth = ""
    prior_date = ""
    prior_md_path = None
    if manifest_path.is_file() and snap_md_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            prior_depth = (manifest.get("origin_depth") or "").strip().lower()
            prior_date = (manifest.get("origin_date") or "").strip()
            prior_md_path = snap_md_path
        except (OSError, ValueError, json.JSONDecodeError):
            prior_depth = ""
            prior_md_path = None

    if prior_md_path is None:
        # Legacy fallback: baseline.json depth + live md.
        baseline_path = output_dir / ".appsec-cache" / "baseline.json"
        if baseline_path.is_file():
            try:
                prior_depth = (
                    (json.loads(baseline_path.read_text(encoding="utf-8")).get("last_run_depth", "") or "")
                    .strip()
                    .lower()
                )
            except (OSError, ValueError, json.JSONDecodeError):
                prior_depth = ""
        live_md = output_dir / "threat-model.md"
        prior_md_path = live_md if live_md.is_file() else None

    if prior_depth not in ("standard", "thorough"):
        return ""  # quick → quick (or first run): skip §7 entirely.

    if prior_md_path is None or not prior_md_path.is_file():
        return ""  # claimed prior depth but no MD to preserve from — skip rather than fake

    try:
        prior_md = prior_md_path.read_text(encoding="utf-8")
    except OSError:
        return ""

    extracted = _extract_section_verbatim(prior_md, top_level_number=7)
    if not extracted:
        return ""  # prior MD didn't actually carry §7 — skip

    # F-NNN stability gate: `merge_threats._assign_t_ids` reassigns T-IDs
    # every run from a deterministic sort key (severity, CWE, file, line,
    # title). A re-sort can move a given F-NNN slot to a different threat,
    # which would silently corrupt the verbatim-preserved §7 prose where it
    # cites F-NNN by number. If any F-NNN cited in the prior §7 no longer
    # resolves to the same title in the current threat register, drop the
    # verbatim and skip §7 — better absent than wrong.
    if not _verbatim_fnnn_refs_match(extracted, prior_md, current_threats or []):
        return ""

    # Provenance (2026-06-26): §7 is being CARRIED FORWARD from a deeper prior
    # run, not analysed this run. Record it and prepend a visible banner so the
    # reader is never misled into thinking this shallow run produced §7. The
    # banner is inserted right after the "## 7. …" heading line.
    _record_carried_section(output_dir, prior_depth, prior_date, "security_architecture")
    banner = _carried_forward_banner(prior_depth, prior_date)
    lines = extracted.split("\n", 1)
    if len(lines) == 2 and lines[0].startswith("## "):
        extracted = lines[0] + "\n\n" + banner + "\n" + lines[1]
    else:
        extracted = banner + "\n\n" + extracted
    return extracted


def _carried_forward_banner(origin_depth: str, origin_date: str) -> str:
    """A single blockquote line marking a section as carried forward from a
    prior deeper run (not re-analysed this run)."""
    when = f"the {origin_date} " if origin_date else "a previous "
    dpth = f"{origin_depth} " if origin_depth else "deeper "
    return (
        f"> ℹ️ _Carried forward from {when}{dpth}assessment — this section was "
        f"not re-analysed in the current (quick) run; its content reflects the "
        f"earlier deeper scan._"
    )


def _record_carried_section(output_dir: Path, origin_depth: str, origin_date: str, section_id: str) -> None:
    """Record a carried section into .preserved-provenance.json (shared writer in
    restore_preserved_sections.record_provenance)."""
    try:
        import restore_preserved_sections as _rps

        _rps.record_provenance(output_dir, origin_depth, origin_date, [section_id])
    except Exception:
        pass


def _extract_section_verbatim(md: str, *, top_level_number: int) -> str:
    """Return the slice of ``md`` from the line ``## <N>. `` (inclusive) to
    the next ``## `` heading (exclusive), trimmed. Empty string if not found.
    """
    pattern = re.compile(
        r"^## " + re.escape(str(top_level_number)) + r"\. ",
        re.MULTILINE,
    )
    match = pattern.search(md)
    if not match:
        return ""
    start = match.start()
    rest = md[match.end() :]
    nxt = re.search(r"^## ", rest, re.MULTILINE)
    end = match.end() + (nxt.start() if nxt else len(rest))
    return md[start:end].rstrip()


# Matches a §8 Findings Register row in a rendered threat-model.md. Two arms
# to handle both the legacy 9-column layout and the 4-column Story-Card
# layout (2026-05) — both arms capture (digit-suffix, title):
#   * arm A — new: `<a id="f-NNN"></a>F-NNN | **<Bold Title>**<br>…`
#   * arm B — old: `<a id="f-NNN"></a>F-NNN | <Bare Title> | …`
# Title group goes into group(2) [new] or group(4) [old]; digits into
# group(1) or group(3). Use `_extract_fnnn_row(match)` to coalesce.
_FNNN_REGISTER_ROW = re.compile(
    r'<a id="f-(\d+)"></a>F-\d+\s*\|\s*\*\*([^*\n]+?)\*\*'  # arm A — table, bold title
    r'|<a id="f-(\d+)"></a>F-\d+\s*\|\s*([^|\n]+?)\s*\|'  # arm B — table, bare title
    r'|<a id="f-(\d+)"></a>\s*\n#### F-\d+ · ([^\n]+)'  # arm C — card heading (2026-05)
)


def _extract_fnnn_row(match: re.Match[str]) -> tuple[str, str]:
    """Return ``(digit_suffix, title)`` from an ``_FNNN_REGISTER_ROW`` match."""
    digits = match.group(1) or match.group(3) or match.group(5) or ""
    title = (match.group(2) or match.group(4) or match.group(6) or "").strip()
    return digits, title


def _normalize_register_title(title: str) -> str:
    """Strip the trailing ``(file.ext:line)`` suffix that pre-2026-05 YAML
    titles still carry — the 4-column Story-Card layout moves that info into
    its own location row, so titles compare semantically across both formats.
    """
    return re.sub(r"\s*\([^()]*:\d+\)\s*$", "", title or "").strip()


# Canonical CWE → weakness-class label map. Lifted from the inline copy in
# _render_mitigations so both §8 title canonicalisation and §9 CWE-name
# decoration use the SAME vocabulary.
_CWE_CLASS_NAMES = {
    "CWE-22": "Path Traversal",
    "CWE-23": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting",
    "CWE-87": "Cross-Site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Server-Side Template Injection",
    "CWE-116": "Improper Output Encoding",
    "CWE-200": "Information Disclosure",
    "CWE-209": "Error Message Disclosure",
    "CWE-269": "Improper Privilege Management",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-290": "Authentication Bypass by Spoofing",
    "CWE-294": "Authentication Bypass by Capture-Replay",
    "CWE-306": "Missing Authentication",
    "CWE-307": "Missing Rate Limiting (Brute-Force)",
    "CWE-310": "Cryptographic Weakness",
    "CWE-312": "Cleartext Storage of Sensitive Data",
    "CWE-321": "Hardcoded Cryptographic Key",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-328": "Use of Weak Hash",
    "CWE-329": "Predictable IV / Nonce",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-346": "Origin Validation Error",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-359": "Exposure of Private Personal Information",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-434": "Unrestricted File Upload",
    "CWE-441": "Unintended Proxy or Intermediary (Confused Deputy)",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-532": "Sensitive Data in Log Files",
    "CWE-538": "Insertion of Sensitive Information into Externally-Accessible File",
    "CWE-548": "Directory Listing Exposure",
    "CWE-552": "Files / Directories Accessible to External Parties",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-620": "Unverified Password Change",
    "CWE-639": "Insecure Direct Object Reference (IDOR)",
    "CWE-640": "Weak Password Recovery Mechanism",
    "CWE-674": "Uncontrolled Recursion",
    "CWE-693": "Missing Defense-in-Depth Control",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-749": "Exposed Dangerous Method or Function",
    "CWE-770": "Allocation of Resources without Limits",
    "CWE-778": "Insufficient Logging",
    "CWE-798": "Hardcoded Credentials",
    "CWE-834": "Excessive Iteration",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-916": "Password Hash with Insufficient Effort",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-922": "Insecure Storage of Sensitive Information",
    "CWE-942": "Permissive Cross-Origin (CORS) Policy",
    "CWE-943": "NoSQL Injection",
    "CWE-1004": "Sensitive Cookie without HttpOnly",
    "CWE-1021": "Improper Restriction of UI Rendering Layers (Clickjacking)",
    "CWE-1104": "Use of Unmaintained Third-Party Components",
    "CWE-1321": "Prototype Pollution",
    "CWE-1395": "Vulnerable Third-Party Component",
}


def _evidence_locator(t: dict) -> str:
    """Full ``file[:line]`` locator from a finding's evidence, or "" when none.

    Accepts evidence as a dict or a list-of-dicts (first entry wins), mirroring
    the two shapes ``_canonical_finding_title`` already handles."""
    ev = t.get("evidence") or {}
    if isinstance(ev, list):
        ev = ev[0] if ev and isinstance(ev[0], dict) else {}
    if not isinstance(ev, dict):
        return ""
    f = (ev.get("file") or "").strip()
    if not f:
        return ""
    ln = ev.get("line")
    return f"{f}:{ln}" if ln is not None else f


def _mitigation_locator(m: dict, threats_by_id: dict[str, dict]) -> str:
    """Full ``file[:line]`` locator for a mitigation. Prefers its own
    ``file``/``location`` field; falls back to the first finding it addresses so
    a measure still carries a code anchor when its yaml omits one."""
    raw = (m.get("file") or m.get("location") or "").strip()
    if raw:
        mm = re.search(r"([\w./\-]+\.[A-Za-z0-9]{1,6}(?::\d+(?:-\d+)?)?)", raw)
        if mm:
            return mm.group(1)
    for a in m.get("threat_ids") or m.get("addresses") or []:
        t = threats_by_id.get(str(a).strip().upper())
        if t:
            loc = _evidence_locator(t)
            if loc:
                return loc
    return ""


def _basename_locator(loc: str) -> str:
    """``path/to/file.ts:76`` → ``file.ts:76`` (basename, line kept)."""
    if not loc:
        return ""
    path, sep, line = loc.partition(":")
    base = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return f"{base}:{line}" if sep else base


# A trailing file locator token: `path/file.ext[:line[-line]]`, optionally
# backticked. Requires a real extension or a `:line` so prose words / acronyms
# like "(IDOR)" are never mistaken for a locator. The `(?:-\d+)?` range branch
# lets a `file.ts:20-25` tail be recognised (and stripped) as one unit.
_TRAILING_LOC_TOKEN = r"`?[\w./\\-]+\.[A-Za-z0-9]{1,6}(?::\d+(?:-\d+)?)?`?"


def _strip_trailing_locator(label: str) -> str:
    """Remove a trailing file locator from a label in ANY form it ships:
    ``… (`a/b.ts:12`)``, ``… (a/b.ts:12)``, ``… — a/b.ts:12``, or ``… a/b.ts:12``.

    The canonical reference form (``linkify_with_label``) appends its own
    ``(`file:line`)`` from the location index, so the label itself must carry no
    locator or it would double. Leaves prose and non-locator parentheticals
    (``(IDOR)``) untouched. Idempotent."""
    if not label:
        return label
    s = label.rstrip()
    for pat in (
        rf"\s*\(\s*{_TRAILING_LOC_TOKEN}\s*\)\s*$",  # (file) / (`file`)
        rf"\s*—\s*{_TRAILING_LOC_TOKEN}\s*$",  # — file:line
        rf"\s+{_TRAILING_LOC_TOKEN}\s*$",  # bare-space-glued file:line
    ):
        s2 = re.sub(pat, "", s)
        if s2 != s and s2.strip():
            return s2.rstrip()
    return s


def _distinct_instance_locations(t: dict) -> list[tuple[str, int | None, str]]:
    """Return unique consolidated locations in their producer-defined order."""
    locations: list[tuple[str, int | None, str]] = []
    seen: set[tuple[str, int | None]] = set()
    for instance in t.get("instances") or []:
        if not isinstance(instance, dict):
            continue
        file = (instance.get("file") or "").strip()
        if not file:
            continue
        line = instance.get("line")
        line = line if isinstance(line, int) and line > 0 else None
        key = (file, line)
        if key in seen:
            continue
        seen.add(key)
        locations.append((file, line, (instance.get("severity") or "").strip().lower()))
    return locations


def _canonical_finding_title(t: dict) -> str:
    """Return a canonical finding title with a locator only for one instance.

    Inputs (in priority order):
      1. ``t['cwe']`` → look up in `_CWE_CLASS_NAMES` for the class label.
      2. ``t['evidence'].file:line`` → append as the trailing `— file:line`
         token only when the finding has at most one distinct instance.
      3. ``t['title']`` (legacy narrative form) → used only when CWE is
         unmapped, in which case the first 5 non-stopword tokens of the
         existing title are kept as the class label so the result is
         still a short noun phrase.

    Returns the empty string when no input yields a non-trivial label
    (caller decides on a placeholder).
    """
    # Prefer the curated register title's weakness-class label so §8's Findings
    # index + cards stay consistent with §2/§5 and the register summary, which
    # render ``t['title']`` verbatim. Deriving a *separate* label from the CWE
    # class name here made §8 diverge (e.g. "Improper Verification of
    # Cryptographic Signature" vs the register's "Insecure JWT Verification")
    # — 2026-07-02 user report. The upstream emit_clean_finding_titles enforces
    # the short title contract; strip any trailing "— file:line" the title may
    # carry (the yaml threat has it, the merged threat does not) so the evidence
    # suffix is re-appended uniformly below and BOTH call sites agree. Falls
    # back to the CWE-class derivation only when no usable short title exists.
    curated_class = re.sub(r"\s+—\s+.*$", "", (t.get("title") or "").strip()).strip()
    # A curated title with a leaked code constant (FOO_BAR / DEFAULT_FULL_SCHEMA)
    # is not a clean class label — fall through to the CWE/token derivation,
    # which additionally strips package names and over-long token runs. Legit
    # security acronyms (IDOR, MD5, XXE, SSRF) have no underscore, so they are
    # preserved and stay consistent with the register.
    _noisy = re.search(r"[A-Za-z0-9]+_[A-Za-z0-9]", curated_class)
    class_label = curated_class if (0 < len(curated_class) <= 80 and not _noisy) else ""

    if not class_label:
        cwe_raw = (t.get("cwe") or "").strip()
        cwe_norm = (
            cwe_raw if cwe_raw.upper().startswith("CWE-") else (f"CWE-{cwe_raw}" if cwe_raw.isdigit() else cwe_raw)
        )
        class_label = _CWE_CLASS_NAMES.get(cwe_norm.upper(), "")
    if not class_label:
        # Fallback — derive a short noun phrase from the existing title
        # by stripping the file-suffix and keeping ≤5 non-stopword tokens.
        raw = _normalize_register_title(t.get("title") or t.get("scenario_short") or "")
        # Drop trailing file-form `— …` if present.
        raw = re.sub(r"\s+—\s+[A-Za-z0-9_./\-]+(?::\d+)?\s*$", "", raw)
        stopwords = {
            "a",
            "an",
            "the",
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
        }

        def _is_noise_token(tok: str) -> bool:
            # ALL_CAPS_UNDERSCORE constants (e.g. DEFAULT_FULL_SCHEMA, NODE_ENV)
            if re.match(r"^[A-Z][A-Z0-9_]{2,}$", tok):
                return True
            # npm/pip package names with hyphens or dots (e.g. js-yaml, socket.io)
            if re.match(r"^[a-z][a-z0-9]*[-\.][a-z][a-z0-9\-\.]*$", tok):
                return True
            return False

        tokens = [w for w in raw.split() if w.lower() not in stopwords and not _is_noise_token(w)]
        class_label = " ".join(tokens[:5]).strip(" ,;:.")
    if not class_label:
        return ""

    # Evidence file:line suffix. Consolidated findings deliberately retain
    # only the weakness class: §8 renders their complete location set as
    # Instances, and a representative path in the title is misleading.
    ev = t.get("evidence") or {}
    ev_file = ""
    ev_line = None
    if isinstance(ev, dict):
        ev_file = (ev.get("file") or "").strip()
        ev_line = ev.get("line")
    elif isinstance(ev, list) and ev:
        first = ev[0] if isinstance(ev[0], dict) else {}
        ev_file = (first.get("file") or "").strip()
        ev_line = first.get("line")

    if ev_file and len(_distinct_instance_locations(t)) <= 1:
        loc = f"{ev_file}:{ev_line}" if ev_line else ev_file
        return f"{class_label} — `{loc}`"
    return class_label


def _verbatim_fnnn_refs_match(extracted_section: str, prior_md: str, current_threats: list) -> bool:
    """True iff every ``F-NNN`` reference inside ``extracted_section`` still
    resolves to the same title in the current threat register as it did in
    ``prior_md``.

    ``merge_threats._assign_t_ids`` reassigns T-IDs every run from a
    deterministic sort key. A re-sort can move a given F-NNN slot to a
    different threat — carried-forward markdown that cites F-NNN by number
    therefore needs validation before reuse. Returns False on any drift
    (F-NNN missing in current, or title mismatch); the caller should fall
    back to omitting §7 rather than render a verbatim block whose links
    silently point to the wrong findings.
    """
    refs = set(re.findall(r"\bF-(\d+)\b", extracted_section))
    if not refs:
        return True  # nothing to validate — verbatim is safe to keep

    prior_titles: dict[str, str] = {}
    for m in _FNNN_REGISTER_ROW.finditer(prior_md):
        digits, title = _extract_fnnn_row(m)
        if not digits:
            continue
        # Normalise digits by stripping leading zeros so "001" and "1" match.
        prior_titles[digits.lstrip("0") or "0"] = _normalize_register_title(title)

    curr_titles: dict[str, str] = {}
    for t in current_threats or []:
        if not isinstance(t, dict):
            continue
        tid = (t.get("t_id") or t.get("id") or "").strip()
        m = re.match(r"^T-(\d+)$", tid)
        if not m:
            continue
        curr_titles[m.group(1).lstrip("0") or "0"] = _normalize_register_title(t.get("title") or "")

    for digits in refs:
        norm = digits.lstrip("0") or "0"
        prior_t = prior_titles.get(norm)
        curr_t = curr_titles.get(norm)
        if not prior_t or not curr_t or prior_t != curr_t:
            return False
    return True


_SECTION7_DEAD_LINK_PATTERNS: tuple[re.Pattern[str], ...] = (
    # operational-strengths.md.j2 truncation footnote.
    re.compile(
        r"\n*_\+\d+ additional controls — see "
        r"\[Section 7\]\(#7-security-architecture\)\._\s*\n",
        re.MULTILINE,
    ),
    # operational-strengths.md.j2 introductory sentence — full sentence form
    # (with both "filtered view of" and "lives in Section 7" trailers).
    re.compile(
        r" This table is a filtered view of "
        r"\[Section 7\]\(#7-security-architecture\)"
        r" — rows with effectiveness ≥ Weak\."
        r"(?: The full catalog, including ❌ Missing controls, lives in Section 7\.)?",
    ),
)


def _strip_section7_crossrefs(md: str) -> str:
    """Remove dead `(#7-security-architecture)` cross-references from MS
    templates when §7 was skipped at compose-time.

    This is intentionally conservative — only the three exact sentences the
    Jinja templates emit are matched. Anything else is left intact so the
    rendered Markdown stays close to the template author's intent.
    """
    for pat in _SECTION7_DEAD_LINK_PATTERNS:
        md = pat.sub("", md)
    # Tighten any double-blanks introduced by deletion.
    md = re.sub(r"\n{3,}", "\n\n", md)
    return md


# ---------------------------------------------------------------------------
# Fragment loading + schema validation
# ---------------------------------------------------------------------------


def _load_fragment(ctx: RenderContext, section_id: str, fragment_name: str) -> Any:
    """Load a data (.json) or prose (.md) fragment from the output fragments
    dir. Returns the parsed object (dict for JSON, str for MD), or raises
    FragmentError when missing.
    """
    path = ctx.fragments_dir / fragment_name
    if not path.is_file():
        raise FragmentError(section_id, f"required fragment not found: {path}")
    text = path.read_text(encoding="utf-8")
    if fragment_name.endswith(".json"):
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise FragmentError(section_id, f"JSON parse error in {path}: {e}")
    # Deterministic §7 structural floor (post-enrichment normalizer). The
    # LLM-enriched security-architecture.md routinely drops the three §7
    # structural contract rules (validation_approach_first,
    # flow_methods_require_diagram, control_subsection_coverage); re-asserting
    # them here — in-memory, at the single compose chokepoint — makes the
    # composed §7 pass the contract gate by construction on every compose path
    # (initial, REPAIR_MODE, export) without a Stage-1 repair round-trip.
    # Idempotent and best-effort: a normalizer failure must never break compose.
    if fragment_name.endswith("security-architecture.md"):
        try:
            from normalize_security_architecture import normalize_text

            text, _changes = normalize_text(text)
        except Exception:
            pass
    return text


def _validate_fragment(section_id: str, data: Any, schema_name: str) -> None:
    if not _JSONSCHEMA_OK:
        return
    schema_path = SCHEMAS_DIR / schema_name
    if not schema_path.is_file():
        raise ContractError(f"schema file not found: {schema_path}")
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ContractError(f"schema {schema_path} is not valid JSON: {e}")
    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as e:
        path = "/".join(str(p) for p in e.absolute_path) or "<root>"
        raise FragmentError(
            section_id,
            f"schema violation at {path}: {e.message}",
        )


def _validate_known_json_fragments(ctx: RenderContext) -> None:
    """Validate every known JSON fragment present on disk before rendering.

    Some structured fragments are advisory or dormant for a given renderer path,
    but they are still LLM-authored contract artifacts. If one is present and
    schema-invalid, fail before composing so bad fragments cannot sit unnoticed
    in the run directory.

    Exception: fragments in ``_FRAGMENTS_WITH_FALLBACK`` are rebuilt by their
    section renderer from yaml when absent/invalid (see
    ``_load_attack_paths_fragment`` → ``_derive_attack_paths_fallback``). For
    those a malformed LLM fragment is a WARNING, not a fatal compose abort —
    otherwise this strict pre-pass kills the whole document over content the
    renderer can deterministically regenerate.
    """
    for path in sorted(ctx.fragments_dir.glob("*.json")):
        entry = _KNOWN_JSON_FRAGMENT_SCHEMAS.get(path.name)
        if entry is None:
            continue
        section_id, schema_name = entry
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            _validate_fragment(section_id, data, schema_name)
        except (json.JSONDecodeError, FragmentError, ContractError) as e:
            if path.name in _FRAGMENTS_WITH_FALLBACK:
                ctx.warnings.append(
                    f"{path.name} is schema-invalid ({type(e).__name__}); "
                    f"falling back to deterministic derivation at render time"
                )
                continue
            if isinstance(e, json.JSONDecodeError):
                raise FragmentError(section_id, f"JSON parse error in {path}: {e}")
            raise


# ---------------------------------------------------------------------------
# Section renderers — one per section id or fragment_type
# ---------------------------------------------------------------------------


def _render_infobox(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    project = ctx.yaml_data.get("project") or {}
    meta = ctx.yaml_data.get("meta") or {}
    remote_url = (meta.get("git") or {}).get("remote_url") or meta.get("repo_url") or ""

    # Enrich from repo-local manifest files when the yaml omitted the field.
    # `_read_project_manifest` is polyglot — it tries package.json,
    # build.gradle / settings.gradle, pom.xml, pyproject.toml, go.mod,
    # Cargo.toml, and (as a last resort) README.md — and returns a normalised
    # dict with the same key names the infobox template expects.
    pkg = _read_project_manifest(ctx)

    def derive_name() -> str:
        p = project if isinstance(project, dict) else {}
        if p.get("name"):
            return p["name"]
        for key in ("project_name",):
            if ctx.yaml_data.get(key) or meta.get(key):
                return ctx.yaml_data.get(key) or meta.get(key)
        if pkg.get("name"):
            # Capitalise the repo slug for display: `juice-shop` → `Juice Shop`.
            return pkg["name"].replace("-", " ").replace("_", " ").title() if "/" not in pkg["name"] else pkg["name"]
        if remote_url:
            m = re.search(r"[/:]([^/]+?)(?:\.git)?/?$", remote_url)
            if m:
                return m.group(1)
        try:
            return ctx.output_dir.parent.name or "Unknown Project"
        except Exception:
            return "Unknown Project"

    if not isinstance(project, dict) or not project:
        project = {}
    project.setdefault("name", derive_name())
    project.setdefault("version", pkg.get("version") or meta.get("project_version"))
    project.setdefault("description", pkg.get("description") or ctx.yaml_data.get("project_description"))
    project.setdefault("author", _format_author(pkg.get("author")) or ctx.yaml_data.get("project_author"))
    # License: manifest first, then LICENSE file at repo root. Covers Gradle/Maven/Go
    # projects where the manifest typically does not carry a license string.
    project.setdefault("license", pkg.get("license") or ctx.yaml_data.get("project_license") or _read_license_file(ctx))
    project.setdefault(
        "repository", remote_url or _extract_repo_url(pkg.get("repository")) or ctx.yaml_data.get("project_repository")
    )
    # Homepage: manifest first, then derived from git remote (OSS convention).
    project.setdefault("homepage", _derive_homepage(remote_url, pkg) or ctx.yaml_data.get("project_homepage"))
    project.setdefault("runtime", ctx.yaml_data.get("project_runtime") or pkg.get("runtime") or _derive_runtime(pkg))
    # Tags: manifest keywords, explicit yaml tags, then README frontmatter / .github/topics.
    project.setdefault("tags", pkg.get("keywords") or ctx.yaml_data.get("project_tags") or _read_readme_tags(ctx))

    # Normalise tags to a list. Historical yaml snapshots sometimes carried
    # `project.tags` as a pre-joined string ("web, owasp, pentest") because
    # an earlier schema revision accepted either shape. The infobox
    # template pipes the value through `| join(', ')`, which would then
    # iterate the string character-by-character and emit "w, e, b, ,, ..."
    # instead of the intended tag list. Coerce here so both shapes render
    # correctly regardless of upstream source.
    tags = project.get("tags")
    if isinstance(tags, str):
        project["tags"] = [t.strip() for t in tags.split(",") if t.strip()]
    elif tags is None:
        project["tags"] = []

    # Cover-page contact (optional, org-profile / CLI branding).
    branding = _load_branding(ctx)
    contact = {
        "name": _clean_cell(branding.get("contact_name")),
        "email": _clean_cell(branding.get("contact_email")),
    }

    tpl = env.get_template(section.get("template", "infobox.md.j2"))
    return tpl.render(project=project, contact=contact).rstrip() + "\n"


def _render_changelog(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    changelog = ctx.yaml_data.get("changelog") or []

    # Drop malformed/out-of-contract entries (2026-06-26). The deterministic
    # build_changelog always sets delta_basis, threat_count, and
    # assessment_depth. An entry with ALL THREE missing is a hand-written stub
    # (e.g. a noise-only no-op that wrote a changelog row out of contract — the
    # no-op path is supposed to write none). Such an entry renders as
    # "incremental | - | -" with a truncated prose note and poisons the
    # baseline framing of the next real run. Filter them at render so a stray
    # entry can't surface even if it slipped into the yaml.
    def _is_wellformed(e: dict) -> bool:
        if not isinstance(e, dict):
            return False
        # An entry carrying real identity (version + date/mode) is well-formed
        # even if it predates the delta-accounting fields — legacy,
        # carried-forward, and v1 initial entries legitimately lack
        # delta_basis/threat_count/assessment_depth and must NOT be dropped
        # (that would silently delete real changelog history on the first run
        # after upgrade). Only an identity-less stub is out of contract.
        if e.get("version") is not None and (e.get("date") or e.get("mode")):
            return True
        return any(e.get(k) is not None for k in ("delta_basis", "threat_count", "assessment_depth"))

    dropped = [e for e in changelog if not _is_wellformed(e)]
    if dropped:
        changelog = [e for e in changelog if _is_wellformed(e)]
        sys.stderr.write(
            f"  changelog: {len(dropped)} malformed/out-of-contract entr"
            f"{'y' if len(dropped) == 1 else 'ies'} dropped at render "
            "(missing delta_basis/threat_count/assessment_depth)\n"
        )
    if not changelog:
        return ""  # conditional — skip when empty
    # Contract-driven style selection:
    #   render_style: "table"   → compact one-row-per-version layout (default)
    #   render_style: "bullets" → legacy per-version H3 + delta bullets
    # An explicit `template:` field overrides both styles when it is a custom
    # filename that the composer does not recognise.
    explicit_template = section.get("template")
    style = (section.get("render_style") or "table").lower()
    if explicit_template and explicit_template not in (
        "changelog.md.j2",
        "changelog-table.md.j2",
    ):
        template_name = explicit_template
    elif style == "bullets":
        template_name = "changelog.md.j2"
    else:
        template_name = "changelog-table.md.j2"
    tpl = env.get_template(template_name)
    # Build a T-ID → title lookup so the per-bullet detail block can
    # render `[T-NNN](#t-nnn) - <title>` instead of bare ID links.
    # Falls back to the empty string when a threat has no title (legacy
    # yaml shape); the template handles that case by emitting just the
    # link.
    threats_by_id: dict[str, str] = {}
    for t in ctx.yaml_data.get("threats") or []:
        if not isinstance(t, dict):
            continue
        tid = (t.get("id") or t.get("t_id") or "").strip()
        if tid:
            threats_by_id[tid] = (t.get("title") or "").strip()
    return tpl.render(changelog=changelog, threats_by_id=threats_by_id).rstrip() + "\n"


def _render_quick_mode_notice(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """Render the Quick-depth transparency banner.

    Conditioned on `is_quick_depth` in eval_context. The banner explains
    what the Quick profile materially reduces so the reader does not
    mistake a Quick report for a full assessment.

    The content is deterministic — no template file — to keep this in
    sync with the resolver's `QUICK_STRIDE_PROFILE` and the DEPTH_PARAMS
    table in `scripts/resolve_config.py`.
    """
    if not ctx.eval_context.get("is_quick_depth"):
        return ""
    skip_walk = bool(ctx.eval_context.get("skip_attack_walkthroughs"))
    # The analyzed-component count is emergent (criteria-selected at quick depth:
    # frontend + auth + internet-exposed + exposure-unknown), so report the actual
    # number of components that received a STRIDE pass rather than a hard-coded cap.
    components = ctx.yaml_data.get("components") or []
    meta = ctx.yaml_data.get("meta") or {}
    cs = meta.get("component_selection") if isinstance(meta.get("component_selection"), dict) else None
    if cs and cs.get("total"):
        # Authoritative count from .stride-selection.json: N analyzed of M modeled.
        comp_clause = f"**{cs.get('analyzed', 0)} of {cs.get('total')} components**"
    else:
        analyzed = sum(1 for c in components if c.get("threat_ids"))
        comp_clause = (
            f"**{analyzed} component{'s' if analyzed != 1 else ''}**" if analyzed else "**A reduced component set**"
        )
    lines = [
        "> ⚠ **Quick depth — reduced-scope assessment.**",
        "> ",
        "> This report ran with intentionally narrower depth to keep wall-time short:",
        "> ",
        f"> - {comp_clause} under full STRIDE analysis (criteria-selected: frontend, auth, and internet-exposed components only)",
        "> - **Max 2 threats per STRIDE category** per component (vs. unlimited at standard/thorough)",
        "> - **No CVSS vectors**, no per-finding evidence excerpts",
    ]
    # §3 bullet conditional on `skip_attack_walkthroughs`. When skipped,
    # §3 is dropped entirely (heading, body, TOC, cross-refs) — naming it
    # in the quick-mode notice would leak a broken §3 reference. When not
    # skipped (rare at quick — operator must explicitly request walkthroughs),
    # the bullet explains the chain-overview-only reduction. See
    # `data/sections-contract.yaml` for the §3 conditional gate.
    if skip_walk:
        lines.append("> - **No §3 Attack Walkthroughs** (entirely skipped at `--quick`)")
    else:
        lines.append("> - **§3 Attack Walkthroughs** limited to Critical findings")
    # Incremental depth-downgrade transparency: prior threats re-injected by the
    # reconciler (build_threat_model_yaml.reconcile_incremental_threats) because
    # this shallower quick run could not re-confirm them. Surface the count once
    # (not per-threat in §8) so the reader knows these were not re-verified here.
    carried = sum(
        1
        for t in (ctx.yaml_data.get("threats") or [])
        if (t.get("evidence_check") or "") == "carried-unverified-shallower-depth"
    )
    if carried:
        lines.append(
            f"> - **{carried} prior finding{'s' if carried != 1 else ''} carried forward "
            "without re-verification** (preserved from a prior deeper scan that this quick "
            "run was too shallow to re-confirm — re-run at the prior depth to re-verify)"
        )
    # Carried-forward SECTIONS (2026-06-26): deep-only sections (§7, AI posture)
    # preserved verbatim from a prior deeper run rather than re-analysed here.
    # Surface them once so the reader knows which sections this quick run did not
    # produce itself. Each carried section also carries its own inline banner.
    prov = _carried_provenance(ctx.output_dir)
    if prov:
        _SECTION_LABELS = {
            "security_architecture": "§7 Security Architecture",
            "ai_exposure_ms": "AI/LLM Exposure callout",
            "abuse_cases": "§9 Abuse Cases",
        }
        names = [_SECTION_LABELS.get(s, s) for s in prov.get("sections", [])]
        if names:
            when = f"the {prov['origin_date']} " if prov.get("origin_date") else "a prior "
            dpth = f"{prov['origin_depth']} " if prov.get("origin_depth") else "deeper "
            lines.append(
                f"> - **Carried forward from {when}{dpth}assessment (not re-analysed here):** " + ", ".join(names)
            )
    lines.extend(
        [
            "> - **No LLM-enriched §7 architecture narrative** (scaffold + control tables only)",
            "> - **No QA reviewer pass**, no architect-level review",
            "> ",
            "> Re-run with `--standard` (≈ +30 min) for full STRIDE coverage and QA, or",
            "> `--thorough` (≈ +90 min) for architect review and enriched architecture sections.",
        ]
    )
    return "\n".join(lines) + "\n"


def _render_skipped_sections_placeholder(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """Emit a one-line italic notice between §5 and §8 when §6 (Use Cases)
    is permanently removed AND §7 (Security Architecture) is suppressed
    at quick depth. Without this notice the document numbering jumps from
    §5 straight to §8 and the reader has to guess whether the gap is a
    rendering bug or a deliberate omission.
    """
    # Defensive: only emit at quick depth. The condition gate in the
    # contract already filters on `not render_security_architecture`,
    # so this is belt-and-suspenders.
    if not ctx.eval_context.get("is_quick_depth"):
        return ""
    return (
        "_§6 Use Cases and §7 Security Architecture are omitted at "
        "`--quick` depth. Re-run with `--standard` (≈ +30 min) or "
        "`--thorough` (≈ +90 min) to render the per-domain analysis._\n"
    )


def _compute_toc_entries(ctx: RenderContext) -> list[dict[str, Any]]:
    """Build TOC entries from the contract's document.order list.

    Each top-level numbered entry also carries `children` — the §N.M sub-section
    entries — computed from:
      * sections[sid].required_subsections  (contract, with §7 schema_v2 overlay)
      * sections[sid].sub_sections         (contract, for threat register)
      * live scan of the matching fragment markdown (for prose sections like
        attack_walkthroughs where §3.N depends on which Critical findings
        exist).
    """
    entries: list[dict[str, Any]] = []
    sections = ctx.contract["sections"]

    for raw in ctx.contract["document"]["order"]:
        sid, cond = (raw, None) if isinstance(raw, str) else (raw["id"], raw.get("condition"))
        if sid in ("infobox", "changelog", "quick_mode_notice", "toc", "skipped_sections_placeholder"):
            continue
        if cond and not eval_condition(cond, ctx.eval_context):
            continue
        sec = sections.get(sid)
        if not sec:
            continue
        heading = sec.get("heading") or ""
        clean_heading = heading.lstrip("#").strip()
        # Extract the section's own §-number from the heading (`## 7. Security
        # Architecture` → `"7"`). When present, use it as the TOC number so
        # the TOC matches the rendered body. Unnumbered sections (Management
        # Summary, Appendix: Run Statistics, etc.) get `""` and the template
        # renders them as a hyphen bullet instead of `N.`.
        # Also handles alphanumeric suffixes like `7b.` (Requirements Compliance).
        num_match = re.match(r"^(\d+[a-z]?(?:\.\d+)?)\.\s+", clean_heading, re.IGNORECASE)
        section_number = num_match.group(1) if num_match else ""
        # Strip the §-prefix from the display title since the number column
        # carries it now (avoids `7. 7. Security Architecture` doubling).
        display_title = re.sub(r"^\s*\d+[a-z]?(?:\.\d+)?\.\s+", "", clean_heading, flags=re.IGNORECASE)
        # The TOC carries no inline code — strip backticks a heading locator may
        # have left in the title (e.g. `### 3.1 SQL Injection (`search.ts:42`)`).
        display_title = _strip_label_code(display_title)
        anchor = sec.get("anchor") or _anchor_from_heading(heading)
        children = _toc_children_for_section(ctx, sid, sec)
        # Identified Actors renders as an unnumbered `### Identified Actors`
        # subsection of §1 System Overview (peer of "### Scope"). Nest it under
        # the preceding system_overview ToC entry instead of emitting a
        # top-level bullet with a half-step "1.5" number that reads as a gap.
        if sid == "identified_actors" and entries and entries[-1].get("_sid") == "system_overview":
            entries[-1]["children"].append({"title": display_title, "anchor": anchor})
            continue
        entries.append(
            {
                "number": section_number,
                "title": display_title,
                "anchor": anchor,
                "children": children,
                "_sid": sid,
            }
        )
    return entries


def _toc_children_for_section(ctx: RenderContext, sid: str, sec: dict[str, Any]) -> list[dict[str, str]]:
    """Return a list of {title, anchor} pairs for the §N.M sub-sections of
    a top-level section.

    Source precedence:
      1. Contract `required_subsections` (explicit titles).
      2. Contract `sub_sections` (used by threat_register).
      3. Live scan of the prose fragment file under `<output>/.fragments/`.
    """
    children: list[dict[str, str]] = []

    # 1. Explicit required_subsections in the contract.
    # Each entry is either a string (ID of another contract section — used by
    # management_summary) or a dict with `title` / `title_pattern`. Strings
    # referring to contract-defined sub-sections are NOT emitted as ToC
    # children — the MS sub-sections (Verdict, Top Findings, …) are not
    # numbered and would add noise to a short-form ToC.
    #
    # For each child, the anchor MUST be derived from the full heading
    # (including the "N.M " prefix, because that's how GitHub slugifies the
    # H3 in the rendered document). The display TITLE keeps the N.M prefix
    # because the reference ToC also carries it (e.g. "2.1 System Context").
    #
    required_subsections = sec.get("required_subsections", []) or []
    if sid == "security_architecture" and ctx.eval_context.get("security_schema") == "v2":
        v2_subs = (sec.get("schema_v2") or {}).get("required_subsections")
        if isinstance(v2_subs, list) and v2_subs:
            required_subsections = v2_subs

    # Older v2 drafts marked §7.X entries with `tier: a | b`; keep the
    # presence filter so old contracts remain readable, but the current v2
    # 13-section layout emits every subsection.
    fragment_titles_present: set[str] | None = None
    fragment_name_for_v2 = sec.get("fragment")
    if fragment_name_for_v2:
        fp_for_v2 = ctx.fragments_dir / fragment_name_for_v2
        if fp_for_v2.is_file():
            try:
                # Collect every `### …` title in the actual fragment.
                fragment_titles_present = set()
                for line in fp_for_v2.read_text(encoding="utf-8").splitlines():
                    if line.startswith("### "):
                        # Strip any " — Verdict" suffix the pregenerator
                        # adds so the title-match is robust against it.
                        body = line[4:].strip()
                        body = re.sub(r"\s+—\s+.*$", "", body)
                        fragment_titles_present.add(body)
            except OSError:
                fragment_titles_present = None
    for sub in required_subsections:
        if isinstance(sub, str):
            continue
        if not isinstance(sub, dict):
            continue
        title = sub.get("title")
        if not title:
            continue
        # Cut 1: Tier-B entries only appear in the TOC when the fragment
        # actually carries them. Tier-A always appears regardless.
        if sub.get("tier") == "b" and fragment_titles_present is not None:
            if title not in fragment_titles_present:
                continue
        children.append(
            {
                "title": _strip_label_code(title),
                "anchor": _anchor_from_heading(f"### {title}"),
            }
        )

    # 2. threat_register's sub_sections (8.A/8.B/8.C/8.D).
    # Each sub-section may carry a `conditional:` expression (e.g. the
    # 8.B Low Categories block is rendered only when low_category_count > 0).
    # Evaluate against ctx.eval_context so the TOC doesn't link to anchors
    # that will not exist in the body.
    for sub in sec.get("sub_sections", []) or []:
        cond = sub.get("conditional")
        if cond and not eval_condition(cond, ctx.eval_context):
            continue
        heading = sub.get("heading") or ""
        # Heading may contain `{count}` placeholder — strip for TOC.
        clean = re.sub(r"\(\{count\}\)", "", heading).strip()
        title = clean.lstrip("#").strip()
        if title:
            children.append({"title": title, "anchor": _anchor_from_heading(f"## {title}")})

    # 2b. required_subsection_patterns — entries declared via regex in the
    # contract (legacy v1 used this for cross-cutting §7 headings whose
    # parenthetical suffix did not fit a fixed `title:` field). Strategy: scan the
    # actual fragment markdown, collect any `### …` heading whose text matches
    # one of the patterns. This both catches the heading exactly as written
    # by the LLM (with the parenthetical suffix intact) and silently drops
    # the section when the pattern is unsatisfied (no false-positive TOC link).
    patterns = sec.get("required_subsection_patterns", []) or []
    fragment_name_for_patterns = sec.get("fragment")
    if patterns and fragment_name_for_patterns:
        pat_fp = ctx.fragments_dir / fragment_name_for_patterns
        if pat_fp.is_file():
            try:
                pat_body = pat_fp.read_text(encoding="utf-8")
            except OSError:
                pat_body = ""
            already = {c["title"] for c in children}
            for pat in patterns:
                if not isinstance(pat, dict):
                    continue
                level = pat.get("level", 3)
                regex = pat.get("pattern")
                if not regex:
                    continue
                hashes = "#" * level
                heading_re = re.compile(rf"^{hashes}\s+(.+?)\s*$", re.MULTILINE)
                content_re = re.compile(regex)
                for hm in heading_re.finditer(pat_body):
                    title_text = hm.group(1).strip()
                    if not content_re.match(title_text):
                        continue
                    if title_text in already:
                        continue
                    children.append(
                        {
                            "title": title_text,
                            "anchor": _anchor_from_heading(f"{hashes} {title_text}"),
                        }
                    )
                    already.add(title_text)

    # 3. Prose-fragment scan — when the LLM authors §N.M titles that the
    #    contract does not enumerate (e.g. §3.N walkthroughs vary per run).
    fragment_name = sec.get("fragment")
    if fragment_name and not children:
        fp = ctx.fragments_dir / fragment_name
        if fp.is_file():
            try:
                for line in fp.read_text(encoding="utf-8").splitlines():
                    m = re.match(r"^###\s+(.+?)\s*$", line)
                    if m:
                        title = m.group(1).strip()
                        # Strip any embedded markdown links so the TOC entry
                        # doesn't contain nested `[..](..)` syntax when wrapped
                        # in its own outer `[...](...)`. Without this, a heading
                        # like `### 3.2 Foo ([T-001](#t-001))` renders as
                        # `[3.2 Foo ([T-001](#t-001))](#...)` — broken markdown.
                        title = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", title)
                        # Clean up residual empty parens left behind by the
                        # reduction above: `Foo ([T-001](#t-001))` → `Foo (T-001)`,
                        # but `Foo ()` (if the link text was empty) → `Foo`.
                        title = re.sub(r"\(\s*\)", "", title)
                        title = re.sub(r"\s{2,}", " ", title).strip()
                        children.append(
                            {
                                "title": title,
                                "anchor": _anchor_from_heading(f"## {title}"),
                            }
                        )
            except OSError:
                pass

    return children


from _slug import github_render_slug as _slug_github_render_slug  # noqa: E402  (link targets → GitHub-rendered anchor)
from _slug import github_slug as _slug_github_slug  # noqa: E402  (R8 — single source of truth)


def _anchor_from_heading(heading: str) -> str:
    """Compute the GitHub-slug anchor for a Markdown heading.

    Delegates to `scripts/_slug.py::github_slug` so qa_checks, pregenerator,
    composer, and export_sarif all use byte-identical slug logic. Drift in
    this function used to cause the historic 2026-05 broken-`#h4-*` TOC bug
    (26 unresolved anchors) because the pregenerator and the renderer-side
    slug differed by one character class.
    """
    h = _slug_github_slug(heading)
    return h


def _render_toc(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    entries = _compute_toc_entries(ctx)
    tpl = env.get_template("toc.md.j2")
    out = tpl.render(entries=entries).rstrip() + "\n"
    # Numbering-gap note (2026-05-31). §6 (Use Cases) was retired in 2026-05 and
    # sections are intentionally NOT renumbered (the §7.x subsection numbers are
    # semantic contract keys; renumbering is a coupled, all-repo change). A bare
    # 5→7 jump reads as a rendering bug ("Wo ist Kapitel 6?"), so name the gap
    # explicitly instead. Generic: fires for any missing top-level integer.
    _nums = sorted(
        {
            int(e["number"])
            for e in entries
            if e.get("number") and "." not in str(e["number"]) and str(e["number"]).isdigit()
        }
    )
    if _nums:
        _missing = [n for n in range(_nums[0], _nums[-1] + 1) if n not in _nums]
        if _missing:
            # Distinguish PERMANENTLY retired sections (§6 Use Cases, removed
            # 2026-05) from sections merely DEPTH-SUPPRESSED on this run (§3
            # Attack Walkthroughs and §7 Security Architecture are skipped at
            # --quick and return at standard/thorough). Lumping them all as
            # "retired in a prior revision" wrongly tells the reader recoverable
            # content is gone forever and masks the depth-downgrade behaviour.
            _RETIRED = {6}  # genuinely removed from the contract
            _DEPTH_SUPPRESSED = {3, 7}  # absent at quick, re-introduced deeper
            retired = [n for n in _missing if n in _RETIRED]
            suppressed = [n for n in _missing if n in _DEPTH_SUPPRESSED]
            other = [n for n in _missing if n not in _RETIRED and n not in _DEPTH_SUPPRESSED]
            notes = []
            if retired:
                _g = ", ".join(f"§{n}" for n in retired)
                notes.append(f"{_g} {'was' if len(retired) == 1 else 'were'} retired in a prior revision")
            if suppressed:
                _g = ", ".join(f"§{n}" for n in suppressed)
                notes.append(
                    f"{_g} {'is' if len(suppressed) == 1 else 'are'} omitted at the current "
                    f"(quick) depth and return at `--standard`/`--thorough`"
                )
            if other:
                _g = ", ".join(f"§{n}" for n in other)
                notes.append(f"{_g} {'is' if len(other) == 1 else 'are'} not present in this report")
            out += (
                f"\n> _Section numbering is non-contiguous: "
                f"{'; '.join(notes)}. The remaining sections keep their original "
                f"numbers so existing cross-references stay valid._\n"
            )
    return out


def _weakness_basis_breakdown(yaml_data: dict) -> tuple[int, int, int, int] | None:
    """Return evidence and weakness counts without treating W as findings.

    Returns ``(total, confirmed, implementation, design)`` or ``None`` when the
    weakness register is empty (pre-P1 data → caller keeps legacy behaviour).

    `confirmed` counts register findings that are NOT folded insecure-practice
    sites. `implementation` / `design` count W-records. The legacy total is
    retained for callers that need a combined assessment count, but the report
    must never label it as a finding count.
    """
    weaknesses = yaml_data.get("weaknesses") or []
    if not weaknesses:
        return None
    # Design-level threats (architecture-coverage, coverage-gap,
    # requirements-compliance, …) carry NO evidence_tier and must NOT inflate the
    # confirmed tally — they are represented by their `design` weakness heading.
    # Folded insecure-practice sites are likewise excluded. A code threat without
    # a tier (legacy / added post-register) still counts as a confirmed finding.
    # Keep in sync with _shared_sources.DESIGN_LEVEL_SOURCES.
    _design_src = {
        "requirements-compliance",
        "known-threats",
        "architecture-coverage",
        "threat-hypothesis",
        "architectural-anti-pattern",
        "coverage-gap",
    }
    confirmed = sum(
        1
        for t in (yaml_data.get("threats") or [])
        if (t.get("evidence_tier") or "confirmed-exploitable") != "insecure-practice"
        and (t.get("source") or "").strip() not in _design_src
        # RC.P2a: unverifiable/refuted evidence is not "confirmed-exploitable".
        and (t.get("evidence_check") or "").strip() not in ("ambiguous", "refuted")
    )
    implementation = sum(1 for w in weaknesses if w.get("kind") == "implementation")
    design = sum(1 for w in weaknesses if w.get("kind") == "design")
    return (confirmed + implementation + design, confirmed, implementation, design)


def _risk_distribution_counts(yaml_data: dict) -> dict[str, int]:
    """Severity tally for the verdict's Risk-distribution line.

    Folded insecure-practice sites are excluded (they live under a weakness's
    practice_evidence, not as standalone findings). A `design-risk` weakness is
    added once at its heading severity: it has NO confirmed instance in
    threats[], so a design-risk Critical (which may rank #1 per §9.3) would
    otherwise be invisible here. `confirmed` weaknesses are already represented
    by their instances in threats[] and are NOT re-added (no double-count).
    """
    fold_practice = _weakness_basis_breakdown(yaml_data) is not None
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for t in yaml_data.get("threats") or []:
        if fold_practice and (t.get("evidence_tier") == "insecure-practice"):
            continue
        sev = (t.get("risk") or t.get("severity") or "").strip().lower()
        if sev in counts:
            counts[sev] += 1
        elif sev in ("informational", "information"):
            counts["info"] += 1
    if fold_practice:
        for w in yaml_data.get("weaknesses") or []:
            if (w.get("severity_basis") or "") != "design-risk":
                continue
            sev = (w.get("severity") or "").strip().lower()
            if sev in counts:
                counts[sev] += 1
    return counts


def _render_verdict(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    data = _load_fragment(ctx, "verdict", section["fragment"])
    _validate_fragment("verdict", data, section["schema"])
    # Deterministic severity tally injected under the opening. The LLM verdict
    # prose must NOT cite exact counts (they drift — a 2026-05 run claimed
    # "eleven High" when there were 17); this authoritative line is computed
    # from threats[] so the Critical/High/Medium/Low breakdown is always exact.
    # P1.4: when the weakness register is populated, folded insecure-practice
    # sites live under their weakness (practice_evidence) and are NOT standalone
    # findings, so exclude them from the severity tally to keep Total honest.
    _breakdown = _weakness_basis_breakdown(ctx.yaml_data)
    counts = _risk_distribution_counts(ctx.yaml_data)
    total = sum(counts.values())
    rd_parts = [
        f"🔴 Critical: {counts['critical']}",
        f"🟠 High: {counts['high']}",
        f"🟡 Medium: {counts['medium']}",
        f"🟢 Low: {counts['low']}",
    ]
    if counts["info"] > 0:
        rd_parts.append(f"⚪ Info: {counts['info']}")
    risk_distribution = "**Risk distribution:** " + " · ".join(rd_parts) + f" · **Total: {total}**"
    if _breakdown is not None:
        _combined_assessment_count, confirmed, impl, design = _breakdown
        risk_distribution += (
            f"<br/>**Assessment evidence:** {confirmed} confirmed-exploitable finding(s) · "
            f"{impl} implementation weakness(es) · {design} design weakness(es)"
        )
    # Deterministic scope-coverage line — PL-facing. States how many components
    # were analyzed in depth vs. modeled, computed from meta.component_selection
    # (.stride-selection.json), so the executive verdict never implies the whole
    # system was assessed when only a criteria-selected subset was.
    scope_coverage = ""
    cs = (ctx.yaml_data.get("meta") or {}).get("component_selection")
    if isinstance(cs, dict) and (cs.get("excluded") or []):
        analyzed = cs.get("analyzed", 0)
        total_comp = cs.get("total", analyzed)
        n_exc = len(cs.get("excluded") or [])
        scope_coverage = (
            f"**Scope:** {analyzed} of {total_comp} components received full STRIDE analysis — "
            f"the externally-reachable, authentication-bearing, and business-critical surface. "
            f"The other {n_exc} (lower-priority / internal) were not individually assessed at this depth "
            f"(see [§1 Scope](#scope))."
        )
    # Badge worst-case bullets whose findings anchor a code-verified
    # (fully_viable) abuse chain. Data-level (per bullet.refs) — no fuzzy
    # markdown parsing. Empty suffix when no viable chain / abuse skipped.
    fmap = _verified_chain_map(ctx)
    verified_suffixes = [_verdict_bullet_badge(b.get("refs") or [], fmap) for b in (data.get("bullets") or [])]
    tpl = env.get_template(section["template"])
    return (
        tpl.render(
            data=data,
            risk_distribution=risk_distribution,
            scope_coverage=scope_coverage,
            verified_suffixes=verified_suffixes,
        ).rstrip()
        + "\n"
    )


# ---------------------------------------------------------------------------
# Security Posture at a Glance — contract v2 hybrid renderer.
# See data/sections-contract.yaml → security_posture_at_a_glance.
#
# v2 layout: 4-column Mermaid (ACTORS / TIERS / IMPACT) with attack arrows
# (① ② … ⑦, one per non-empty class in data/attack-class-taxonomy.yaml),
# header-alignment edges that pin the three column headers on one Y line,
# and consequence arrows from each tier into the business impacts it
# enables. Below the diagram: a threat-actor intro + 1–7 numbered
# attack-class bullets (one per non-empty class) with sub-bullets for
# Architectural-root-cause / Findings / Attack-chain / Impact.
#
# The diagram is computed deterministically from threat-model.yaml + the
# three taxonomies (attack-class, business-impact, posture-actor-labels).
# The 1-sentence per-class description plus the AF / chain links come
# from an LLM-authored fragment validated by
# schemas/fragments/security-posture-attack-paths.schema.json. When the
# fragment is missing, the renderer falls back to a deterministic
# CWE → class assignment using attack-class-taxonomy.yaml.
# ---------------------------------------------------------------------------

# Canonical vektor (threat-actor) labels — preserved verbatim because
# §8 Findings Register and Appendix A still resolve actor slugs through
# this map.
_VEKTOR_LABEL: dict[str, str] = {
    "internet-anon": "Internet Anon",
    "internet-user": "Internet User",
    "internet-priv-user": "Internet Priv User",
    "victim-required": "Victim-Required",
    "build-time": "Build-Time",
    "repo-read": "Repo-Read",
    "n-a": "n/a",
    "n/a": "n/a",
}

# Layer heuristic for contract v2. Tiers are CLIENT / APPLICATION / DATA
# (renamed from the v1 EDGE / SERVER / DATA). The classifier accepts
# both the new and legacy `layer` field values.
_LAYER_CLIENT_KEYWORDS = (
    "frontend",
    "spa",
    "ui",
    "angular",
    "react",
    "vue",
    "svelte",
    "browser",
    "client",
    "edge",
    "cdn",
    "gateway",
)
_LAYER_DATA_KEYWORDS = (
    "database",
    "store",
    "storage",
    "db",
    "sqlite",
    "postgres",
    "mongo",
    "marsdb",
    "data-layer",
    "persistent",
    "file-storage",
    "object",
    "cache",
    "redis",
)


def _classify_component_layer(comp: dict[str, Any]) -> str:
    """Return one of ``client`` / ``application`` / ``data``.

    Priority order:
      1. Explicit ``layer`` field on the component (handles both legacy
         "edge"/"server" and new "client"/"application").
         Also accepts ``tier`` as a synonym (LLM output uses both names).
      2. Keyword match on **id + name only**. ``description`` is excluded
         because it frequently references cross-tier nouns (e.g. an
         express-backend description "serving the Angular SPA" would
         false-positive match `angular` → client). See Bug E in the
         2026-05 tier-routing analysis for the full failure mode.
      3. Fallback: ``application`` — the safest default for back-end services.
    """
    layer = (comp.get("layer") or comp.get("tier") or "").strip().lower()
    if layer in ("client", "edge", "frontend", "ui", "browser"):
        return "client"
    if layer in ("data", "storage", "persistence", "datastore"):
        return "data"
    if layer in ("application", "server", "backend", "api", "service"):
        return "application"
    blob = " ".join(
        (
            (comp.get("name") or ""),
            (comp.get("id") or ""),
        )
    ).lower()
    for kw in _LAYER_CLIENT_KEYWORDS:
        if kw in blob:
            return "client"
    for kw in _LAYER_DATA_KEYWORDS:
        if kw in blob:
            return "data"
    return "application"


def _component_max_severity(
    component_id: str, threats_by_component: dict[str, list[dict]]
) -> tuple[str, dict[str, int]]:
    """Return (max_sev_key, counts_by_sev) for the component.

    ``counts_by_sev`` has the keys ``critical, high, medium, low, none``.
    ``max_sev_key`` is the highest severity present, or ``"none"`` when
    the component has no linked threats.

    PRESERVED FROM v1 — also used by the Findings Register row renderer.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    for t in threats_by_component.get(component_id, []):
        sev = (t.get("risk") or t.get("severity") or "").strip().lower()
        if sev in counts:
            counts[sev] += 1
    for key in ("critical", "high", "medium", "low"):
        if counts[key] > 0:
            return key, counts
    return "none", counts


def _group_threats_by_component(threats: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group findings by their `component_id` field. PRESERVED FROM v1.

    Falls back to `t["component"]` when `component_id` is missing.
    Some yaml shapes (Phase-10b output from quick-depth runs) write only
    `component:` (the slug/id) without back-filling `component_id`; the
    reverse-index enrichment at render-start handles most paths but a
    safety net here keeps the lookup honest.
    """
    by_comp: dict[str, list[dict[str, Any]]] = {}
    for t in threats:
        cid = (t.get("component_id") or t.get("component") or "").strip()
        if not cid:
            continue
        by_comp.setdefault(cid, []).append(t)
    return by_comp


def _format_finding_link(finding: dict | None, fid: str = "") -> str:
    """Single source-of-truth for the canonical Finding link format.

    Returns ``[F-NNN — Title](#f-nnn)`` when a title is available, falling
    back to ``[F-NNN](#f-nnn)`` for the rare case of a title-less finding.
    The em dash (`—`, U+2014) separates F-ID from title — same glyph used
    in §8 Findings Register, so cross-references render consistently.

    PRESERVED FROM v1 — also used by the Findings Register row renderer.
    """
    if finding is None:
        finding = {}
    fid = (fid or finding.get("id") or finding.get("t_id") or "").strip()
    if not fid:
        return ""
    title = (finding.get("title") or finding.get("scenario_short") or "").strip()
    title = title.replace("|", "\\|").replace("\n", " ")
    anchor = fid.lower()
    if title:
        return f"[{fid} — {title}](#{anchor})"
    return f"[{fid}](#{anchor})"


# ---------------------------------------------------------------------------
# Taxonomy loaders — module-level cache; the three YAML files are read at
# most once per Python process.
# ---------------------------------------------------------------------------

_TAXONOMY_CACHE: dict[str, dict] = {}


def _load_taxonomy(filename: str) -> dict:
    """Load and cache one of the posture taxonomies from data/."""
    if filename not in _TAXONOMY_CACHE:
        path = PLUGIN_ROOT / "data" / filename
        try:
            _TAXONOMY_CACHE[filename] = _fast_yaml_load(path.read_text(encoding="utf-8")) or {}
        except (FileNotFoundError, yaml.YAMLError):
            _TAXONOMY_CACHE[filename] = {}
    return _TAXONOMY_CACHE[filename]


def _load_attack_class_taxonomy() -> dict:
    return _load_taxonomy("attack-class-taxonomy.yaml")


def _load_business_impact_taxonomy() -> dict:
    return _load_taxonomy("business-impact-taxonomy.yaml")


def _load_posture_actor_labels() -> dict:
    return _load_taxonomy("posture-actor-labels.yaml")


# ---------------------------------------------------------------------------
# Attack-class assignment — used both by the LLM-fragment fallback path
# and (optionally) by QA cross-checks of LLM-supplied class labels.
# ---------------------------------------------------------------------------


def _classify_finding_class(threat: dict, taxonomy: dict) -> str | None:
    """Return the attack-class slug a finding belongs to, or ``None``.

    First-match wins on the ``cwes`` list of each class in
    ``data/attack-class-taxonomy.yaml`` — so ``injection`` beats
    ``remote-code-execution`` for CWE-94 (Code Injection) because
    ``injection`` is listed first in the taxonomy file.

    Lookup order for the threat's CWE:
      1. ``threat.cwe`` (canonical, if the merger / analyzer populated it).
      2. ``threat.cwes[]`` (plural variant).
      3. First ``CWE-NNN`` token found in ``threat.scenario`` /
         ``threat.description`` text. STRIDE analyzers commonly cite CWE
         IDs inline at the end of the scenario instead of in a structured
         field, and without this fallback every quick-depth assessment
         renders the Security Posture diagram with empty attack arrows /
         impact cards / attack-paths bullets.
    """
    cwes_to_check: list[str] = []
    cwe_single = (threat.get("cwe") or "").strip().upper()
    if cwe_single:
        cwes_to_check.append(cwe_single)
    cwe_list = threat.get("cwes") or []
    if isinstance(cwe_list, list):
        for c in cwe_list:
            if isinstance(c, str) and c.strip():
                cwes_to_check.append(c.strip().upper())
    if not cwes_to_check:
        text = threat.get("scenario") or threat.get("description") or ""
        if isinstance(text, str) and text:
            cwes_to_check.extend(re.findall(r"CWE-\d+", text.upper()))
    if not cwes_to_check:
        return None
    classes = taxonomy.get("classes") or []
    for cwe in cwes_to_check:
        normalised = cwe if cwe.startswith("CWE-") else f"CWE-{cwe.lstrip('CWE-')}"
        for cls in classes:
            if normalised in (cls.get("cwes") or []):
                return cls.get("id")
    return None


def _derive_attack_paths_fallback(threats: list[dict], taxonomy: dict) -> dict:
    """Synthesise an ``attack_paths`` fragment from CWE → class membership.

    Used when ``.fragments/security-posture-attack-paths.json`` is missing.
    The result has the exact shape of the validated schema fragment so
    downstream code can treat it identically.

    Architectural-root-cause and attack-chain links are NOT derivable from
    CWE membership alone — those need LLM judgement — so the fallback
    leaves them empty. The per-class description and impact list come
    straight from the taxonomy defaults.
    """
    findings_by_class: dict[str, list[str]] = {}
    actors_present: set[str] = set()
    for t in threats:
        slug = _classify_finding_class(t, taxonomy)
        if not slug:
            continue
        fid = (t.get("id") or t.get("t_id") or "").strip()
        if fid:
            findings_by_class.setdefault(slug, []).append(fid)

    attack_paths: list[dict] = []
    for cls in taxonomy.get("classes") or []:
        slug = cls.get("id")
        fids = findings_by_class.get(slug) or []
        if not fids:
            continue
        actor = cls.get("default_actor") or "internet-anon"
        actors_present.add(actor)
        attack_paths.append(
            {
                "class": slug,
                "actor": actor,
                "target": cls.get("default_target_tier") or "application",
                "description": " ".join((cls.get("description") or "").split()),
                "findings": sorted(fids),
                "attack_chains": [],
                "impact": list(cls.get("default_impacts") or []),
            }
        )

    if not actors_present:
        actors_present.add("internet-anon")
    # Always keep victim-required first when present (matches
    # posture-actor-labels.yaml `order:` list).
    actor_order = _load_posture_actor_labels().get("order") or []
    actors_sorted = [a for a in actor_order if a in actors_present]

    return {
        "schema_version": 1,
        "actors": actors_sorted,
        "attack_paths": attack_paths,
    }


def _has_client_tier(ctx: RenderContext) -> bool:
    """True when any yaml component classifies into the client/browser tier."""
    return any(
        _classify_component_layer(c) == "client" for c in (ctx.yaml_data.get("components") or []) if isinstance(c, dict)
    )


def _drop_victim_paths_without_client_tier(ctx: RenderContext, data: dict) -> None:
    """Root-cause guard for the whole posture section (T2/G3 + E5).

    A victim-targeting attack path (CSRF/XSS — ``actor == victim-required`` or
    ``target == victim``) delivers its payload *through a client/browser tier*.
    On a server-only / CLI product that has no client-tier component, such a
    path — whether LLM-authored or added by the M-11 gap-filler
    (``_reconcile_attack_path_membership``, e.g. CSRF via CWE-942) — has no tier
    to originate from. Rendered anyway it forces a bare undeclared ``BROWSER``
    node in the heatmap (E5 / ``posture_unknown``) and an orphan glyph in the
    Top Threats table with no matching diagram arrow (T2/G3).

    Filtering here, at the single data-loading boundary every consumer shares
    (heatmap arrows, actor legend, consequence arrows, Top Threats table, Top
    Findings ``Pfad`` column), keeps all of them consistent by construction —
    instead of a per-renderer guard that must be kept in sync at N call sites.
    """
    if not isinstance(data, dict) or _has_client_tier(ctx):
        return
    data["attack_paths"] = [
        ap
        for ap in (data.get("attack_paths") or [])
        if not (
            (ap.get("target") or "application").lower() == "victim"
            or (ap.get("actor") or "internet-anon").lower() == "victim-required"
        )
    ]
    if isinstance(data.get("actors"), list):
        data["actors"] = [a for a in data["actors"] if a != "victim-required"]


def _load_attack_paths_fragment(ctx: RenderContext, taxonomy: dict, threats: list[dict]) -> dict:
    """Load the attack-paths fragment and apply the shared victim-path guard.

    Delegates to :func:`_load_attack_paths_fragment_impl` for the raw load /
    validation / reconciliation, then drops victim-targeting paths when the
    product has no client tier (see
    :func:`_drop_victim_paths_without_client_tier`) so every downstream
    consumer sees the same filtered set.
    """
    data = _load_attack_paths_fragment_impl(ctx, taxonomy, threats)
    _drop_victim_paths_without_client_tier(ctx, data)
    return data


def _load_attack_paths_fragment_impl(ctx: RenderContext, taxonomy: dict, threats: list[dict]) -> dict:
    """Load the LLM-authored fragment if present and well-formed; else
    fall back to the deterministic CWE-derived fragment.

    The renderer never raises on a malformed fragment — falling back to
    deterministic data is preferable to a missing section.

    M-2-Refit (M-RCA-2026-05): After schema-validation, each attack_path's
    `target` field is reconciled against the authoritative
    `attack-class-taxonomy.yaml → classes[].default_target_tier`. The LLM
    routinely classifies attacks by impact-tier ("injection ATTACKS data")
    rather than control-tier ("injection IS a missing application control"),
    so a value that disagrees with the taxonomy is overwritten with a
    warning logged to `.reconcile-log.json`. This mirrors the enforcement
    already applied in `_build_tier_cards` for the heatmap dot routing.
    """
    frag_dir = getattr(ctx, "fragments_dir", None) or (ctx.output_dir / ".fragments")
    frag_path = frag_dir / "security-posture-attack-paths.json"
    if frag_path.is_file():
        try:
            data = json.loads(frag_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("attack_paths"), list):
                # Schema-validate before trusting LLM-authored content.
                # An LLM that hallucinates a different schema (different per-path
                # field names, missing top-level `actors`) produces a syntactically
                # valid JSON the renderer can't consume, resulting in an empty
                # heatmap. Validation catches that and falls back to derived data.
                try:
                    _validate_fragment(
                        "security_posture_attack_paths",
                        data,
                        "security-posture-attack-paths.schema.json",
                    )
                except (FragmentError, ContractError):
                    return _derive_attack_paths_fallback(threats, taxonomy)
                # Preserve the LLM's original (impact-tier) target before the
                # control-tier reconciliation below overwrites it. Figure 1
                # (architecture data-flow) routes by impact — injection shown
                # reaching the DB — while Figure 2 (control responsibility) uses
                # the reconciled control tier. This mirrors the reference design,
                # where the same class sits on the app tier in the heatmap but
                # flows into the data tier in the architecture diagram.
                for _ap in data.get("attack_paths") or []:
                    if isinstance(_ap, dict):
                        _ap.setdefault("_llm_target", (_ap.get("target") or "").strip().lower())
                # M-2-Refit: reconcile LLM-authored `target` against the
                # canonical attack-class-taxonomy.default_target_tier.
                _reconcile_attack_path_targets(data, taxonomy, ctx)
                # M-11: gap-fill missing attack-class entries that the LLM
                # omitted despite having matching findings in yaml.threats.
                _reconcile_attack_path_membership(data, taxonomy, threats, ctx)
                # Augment with default actors list when the fragment omits
                # it (the schema requires it, but we are defensive).
                data.setdefault("actors", [])
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return _derive_attack_paths_fallback(threats, taxonomy)


def _reconcile_attack_path_targets(data: dict, taxonomy: dict, ctx: RenderContext) -> None:
    """M-2-Refit: Override each attack_path's `target` with the canonical
    `default_target_tier` from `attack-class-taxonomy.yaml`. Drift is
    appended to `.reconcile-log.json` under `ctx.output_dir` for audit.

    Classes whose taxonomy entry has no `default_target_tier` (or explicitly
    sets it to `null` / `by_component`) are left untouched — those are
    legitimately tier-spanning.
    """
    classes_by_id: dict[str, dict] = {}
    for cls in taxonomy.get("classes") or []:
        cid = (cls.get("id") or "").strip().lower()
        if cid:
            classes_by_id[cid] = cls

    drift_log: list[dict] = []
    for ap in data.get("attack_paths") or []:
        if not isinstance(ap, dict):
            continue
        cls_id = (ap.get("class") or "").strip().lower()
        cls = classes_by_id.get(cls_id)
        if not cls:
            continue
        canonical_tier = cls.get("default_target_tier")
        if not canonical_tier or canonical_tier == "by_component":
            continue
        actual = (ap.get("target") or "").strip().lower()
        if actual and actual != canonical_tier:
            drift_log.append(
                {
                    "class": cls_id,
                    "llm_target": actual,
                    "canonical_target": canonical_tier,
                    "source": "attack-class-taxonomy.default_target_tier",
                }
            )
            ap["target"] = canonical_tier

    if drift_log:
        try:
            log_path = ctx.output_dir / ".reconcile-log.json"
            existing: dict = {}
            if log_path.is_file():
                try:
                    existing = json.loads(log_path.read_text(encoding="utf-8")) or {}
                except (json.JSONDecodeError, OSError):
                    existing = {}
            existing.setdefault("attack_path_target_overrides", []).extend(drift_log)
            log_path.write_text(
                json.dumps(existing, indent=2, sort_keys=False) + "\n",
                encoding="utf-8",
            )
        except OSError:
            # Best-effort — drift logging is observability, never fatal.
            pass


def _reconcile_attack_path_membership(data: dict, taxonomy: dict, threats: list[dict], ctx: RenderContext) -> None:
    """M-11: Ensure every taxonomy cluster that has ≥1 matching finding in
    ``yaml.threats`` appears in ``attack_paths[]``. The LLM frequently omits
    low-severity classes (e.g. CSRF with a single Medium finding), even
    though `agents/phases/phase-group-finalization.md:544` mandates "≥ 1
    matching finding ⇒ one entry".

    Algorithm:
      1. Classify every threat into a cluster via `_classify_finding_class`.
      2. Aggregate finding-ids per cluster.
      3. For each cluster with ≥1 finding NOT already in ``data["attack_paths"]``,
         append a new entry built the same way `_derive_attack_paths_fallback`
         builds them (so the fields are schema-compliant by construction).
      4. Re-sort ``attack_paths[]`` per taxonomy declaration order so glyph
         assignment ① ② … stays stable across runs.
      5. Log each gap-fill to ``.reconcile-log.json``.

    Idempotent — re-running adds nothing when nothing is missing.
    """
    classes_by_id: dict[str, dict] = {}
    for cls in taxonomy.get("classes") or []:
        cid = (cls.get("id") or "").strip()
        if cid:
            classes_by_id[cid] = cls

    findings_by_class: dict[str, list[str]] = {}
    for t in threats or []:
        if not isinstance(t, dict):
            continue
        slug = _classify_finding_class(t, taxonomy)
        if not slug:
            continue
        # Prefer the legacy F-NNN identifier so generated entries match the
        # rest of the fragment's id-namespace (the LLM also writes F-NNN).
        fid = (t.get("original_id") or "").strip() or (t.get("id") or "").strip() or (t.get("t_id") or "").strip()
        if fid:
            findings_by_class.setdefault(slug, []).append(fid)

    path_by_slug: dict[str, dict] = {}
    for ap in data.get("attack_paths") or []:
        if isinstance(ap, dict):
            s = (ap.get("class") or "").strip()
            if s and s not in path_by_slug:
                path_by_slug[s] = ap
    existing_slugs = set(path_by_slug)

    gap_log: list[dict] = []
    appended: list[dict] = []
    merged_any = False
    # (3) Union missing findings into EXISTING class paths. The LLM-authored
    # injection path lists e.g. SQL/NoSQL findings but routinely omits other
    # same-class findings (XXE CWE-611 is an `injection`-class finding on the
    # file-upload service); without this merge they exist in §8 but never get a
    # glyph/edge in Figures 1 & 2 or the Top-Threats table. We add only findings
    # that classify into the SAME class as the existing path, so the merge never
    # mis-attributes a finding to an unrelated attack class.
    for slug, fids in findings_by_class.items():
        ap = path_by_slug.get(slug)
        if ap is None:
            continue
        cur = [f for f in (ap.get("findings") or []) if isinstance(f, str)]
        cur_set = set(cur)
        missing = [f for f in sorted(set(fids)) if f not in cur_set]
        if missing:
            ap["findings"] = sorted(cur_set | set(missing))
            merged_any = True
            gap_log.append(
                {
                    "class": slug,
                    "merged_findings": missing[:8],
                    "merged_count": len(missing),
                    "source": "(3) attack-paths same-class finding merge",
                    "reason": (
                        f"{len(missing)} finding(s) classify as {slug!r} but were "
                        f"missing from the LLM-authored path's findings[]"
                    ),
                }
            )

    for slug, fids in findings_by_class.items():
        if slug in existing_slugs:
            continue
        cls = classes_by_id.get(slug)
        if not cls:
            continue
        actor = cls.get("default_actor") or "internet-anon"
        new_entry = {
            "class": slug,
            "actor": actor,
            "target": cls.get("default_target_tier") or "application",
            "description": " ".join((cls.get("description") or "").split()),
            "findings": sorted(set(fids)),
            "attack_chains": [],
            "impact": list(cls.get("default_impacts") or []),
        }
        appended.append(new_entry)
        gap_log.append(
            {
                "class": slug,
                "missing_finding_count": len(new_entry["findings"]),
                "appended_findings": new_entry["findings"][:5],
                "source": "M-11 attack-paths gap-filler",
                "reason": (
                    f"taxonomy cluster {slug!r} has {len(new_entry['findings'])} "
                    f"matching finding(s) in threats[] but no entry in LLM-authored "
                    f"attack_paths"
                ),
            }
        )

    if not appended:
        if merged_any:
            # Findings were merged into existing paths but no new class added —
            # persist the merge log and return without re-sorting.
            try:
                log_path = ctx.output_dir / ".reconcile-log.json"
                existing_log: dict = {}
                if log_path.is_file():
                    try:
                        existing_log = json.loads(log_path.read_text(encoding="utf-8")) or {}
                    except (json.JSONDecodeError, OSError):
                        existing_log = {}
                existing_log.setdefault("attack_path_gap_fills", []).extend(gap_log)
                log_path.write_text(
                    json.dumps(existing_log, indent=2, sort_keys=False) + "\n",
                    encoding="utf-8",
                )
            except OSError:
                pass
        return

    # Re-sort attack_paths per taxonomy declaration order so ① ② … stays
    # deterministic across runs.
    taxonomy_order = [
        (cls.get("id") or "").strip()
        for cls in (taxonomy.get("classes") or [])
        if isinstance(cls, dict) and cls.get("id")
    ]
    combined = list(data.get("attack_paths") or []) + appended
    data["attack_paths"] = sorted(
        combined,
        key=lambda ap: (
            taxonomy_order.index((ap.get("class") or "").strip())
            if (ap.get("class") or "").strip() in taxonomy_order
            else 999
        ),
    )

    try:
        log_path = ctx.output_dir / ".reconcile-log.json"
        existing: dict = {}
        if log_path.is_file():
            try:
                existing = json.loads(log_path.read_text(encoding="utf-8")) or {}
            except (json.JSONDecodeError, OSError):
                existing = {}
        existing.setdefault("attack_path_gap_fills", []).extend(gap_log)
        log_path.write_text(
            json.dumps(existing, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
    except OSError:
        pass


def _build_finding_to_path_map(
    attack_paths_data: dict, threats: list[dict] | None = None
) -> dict[str, tuple[str, str]]:
    """Map finding-id (upper-case) → (glyph, anchor-slug) using the
    *rendered* attack_paths order. Glyphs ① ② … are assigned positionally
    to non-empty entries — the same rule the heatmap diagram applies — so
    the Top Findings ``Pfad`` column always agrees with the bullets in
    Security Posture at a Glance.

    A finding may legitimately appear in multiple paths (e.g. F-002 SQLi
    classified under both ``injection`` and ``auth-bypass``). We keep the
    FIRST occurrence — matching the order in which the heatmap bullets are
    rendered (attack-class-taxonomy.yaml order).

    M-9: When ``threats`` is supplied, register BOTH F-NNN and T-NNN keys
    for every finding via the ``id`` / ``t_id`` / ``original_id`` alias on
    each threat. Without this, the Top Findings ``Pfad`` cell looked up the
    T-NNN of a threat but the attack_paths fragment carried F-NNN keys
    (the schema accepts either — see schemas/fragments/
    security-posture-attack-paths.schema.json), so every lookup missed and
    the cell rendered as a literal em-dash.
    """
    glyphs = ["①", "②", "③", "④", "⑤", "⑥", "⑦"]
    out: dict[str, tuple[str, str]] = {}

    # M-9: Build a bidirectional F↔T alias from threats so both namespaces
    # resolve to the same path entry.
    #
    # Auto-derive the T↔F sibling for every observed id. _compute_top_findings_rows
    # rewrites the visible label from T-NNN to F-NNN (see `finding_id_visible`)
    # and uses the original T-NNN for the lookup, but the attack_paths fragment
    # may carry either form. Without the auto-derived alias, threats whose YAML
    # carries only a single `id:` field never enter the alias map (len==1) and
    # the Pfad cell falls back to em-dash. Mirroring the existing T→F label
    # transformation here keeps the lookup symmetric.
    alias: dict[str, set[str]] = {}
    if threats:
        for t in threats:
            if not isinstance(t, dict):
                continue
            keys: set[str] = set()
            for key_name in ("id", "t_id", "original_id"):
                v = (t.get(key_name) or "").strip().upper()
                if v.startswith(("F-", "T-")):
                    keys.add(v)
            for v in list(keys):
                m_t = re.match(r"^T-(\d+)$", v)
                m_f = re.match(r"^F-(\d+)$", v)
                if m_t:
                    keys.add(f"F-{m_t.group(1)}")
                elif m_f:
                    keys.add(f"T-{m_f.group(1)}")
            if len(keys) > 1:
                for k in keys:
                    alias[k] = keys

    for idx, ap in enumerate(attack_paths_data.get("attack_paths") or []):
        if idx >= len(glyphs):
            break
        glyph = glyphs[idx]
        slug = ap.get("class") or ""
        anchor = f"path-{slug}" if slug else ""
        for fid in ap.get("findings") or []:
            primary = (fid or "").upper()
            if not primary:
                continue
            # Register all known aliases (F-NNN + T-NNN) under the same glyph.
            # Fragment-side T↔F derivation handles the case where the fragment
            # references an id not present in the threats list (alias miss).
            sibling_keys = set(alias.get(primary, {primary}))
            m_t = re.match(r"^T-(\d+)$", primary)
            m_f = re.match(r"^F-(\d+)$", primary)
            if m_t:
                sibling_keys.add(f"F-{m_t.group(1)}")
            elif m_f:
                sibling_keys.add(f"T-{m_f.group(1)}")
            for k in sibling_keys:
                out.setdefault(k, (glyph, anchor))
    return out


def _build_finding_to_chain_map(ctx: RenderContext) -> dict[str, tuple[str, str]]:
    """Map finding-id (F-NNN / T-NNN) → (link_label, anchor_slug) for §3
    Attack Walkthroughs back-links.

    Parses ``.fragments/attack-walkthroughs.md`` for the §3.1+
    ``### 3.N Title`` per-finding walkthrough sub-sections (the §3.1 Attack
    Chain Overview was retired — the cross-finding view is the Critical
    Attack Tree).

    For each block, every ``F-NNN`` / ``T-NNN`` reference in the body is
    registered under both id forms. Anchors are derived via the canonical
    ``_slug.github_slug`` so they match what GitHub / Pandoc / MkDocs
    auto-generate — no explicit ``<a id="…">`` markers required in the
    fragment.

    Returns ``{}`` when the fragment is missing — caller treats as no-op
    (no walkthrough link rendered in the §8 Story Card).
    """
    frag = ctx.fragments_dir / "attack-walkthroughs.md"
    if not frag.is_file():
        return {}
    try:
        text = frag.read_text(encoding="utf-8")
    except OSError:
        return {}

    out: dict[str, tuple[str, str]] = {}

    # §3.1+ per-finding walkthroughs: `### 3.N Title`.
    # ONLY the primary T-NNN/F-NNN named in the heading is registered for
    # this walkthrough — cross-references inside the body (e.g. "Sibling
    # findings: T-005" in T-001's walkthrough) MUST NOT overwrite the
    # mapping of those other findings. The historic bug here matched all
    # `[FT]-NNN` in the body and called `out[k] = (label, anchor)`
    # unconditionally, so §3.13 (T-012, mentions T-011) clobbered T-011's
    # correct §3.12 mapping, §3.11 (T-010, mentions T-002+T-003) clobbered
    # those, etc. — the Story Card "Walkthrough §3.N" back-link then
    # pointed at the wrong walkthrough.
    sec_re = re.compile(r"^###\s+3\.(\d+)\s+(.+?)\s*$", re.M)
    sec_matches = list(sec_re.finditer(text))
    for i, m in enumerate(sec_matches):
        sub_n = m.group(1)
        title = m.group(2).strip()
        heading_text = f"3.{sub_n} {title}"
        anchor = _anchor_from_heading(heading_text)
        label = f"Walkthrough §3.{sub_n}"
        # Determine the owning finding. The deterministic renderer keeps the
        # heading short and T-NNN-free (check_heading_hygiene) and names the
        # owner on the `**Source:** [T-NNN]` line, so read that line first;
        # fall back to a T-NNN in the heading title for legacy fragments.
        # Either way ONLY the owner is registered — body cross-references
        # (e.g. "Sibling findings: T-005") MUST NOT overwrite other findings'
        # mappings.
        block_start = m.end()
        block_end = sec_matches[i + 1].start() if i + 1 < len(sec_matches) else len(text)
        block = text[block_start:block_end]
        # `[^\[\n]*` tolerates the severity dot the walkthrough renderer emits
        # between the label and the ref (`**Source:** 🔴 [F-003]`, see
        # walkthrough_renderer._source_line) — a plain `\s*` did NOT match the
        # emoji, so the owner never resolved and the §8 back-link silently never
        # rendered in production (masked by dotless test fixtures).
        src_match = re.search(r"\*\*Source:\*\*[^\[\n]*\[[FT]-(\d+)\]", block)
        owner = src_match or re.search(r"\b[FT]-(\d+)\b", title)
        if not owner:
            continue
        digits = owner.group(1)
        out[f"F-{digits}"] = (label, anchor)
        out[f"T-{digits}"] = (label, anchor)

    return out


# ---------------------------------------------------------------------------
# Diagram-data assembly — pure functions that return Jinja2-template input.
# ---------------------------------------------------------------------------


# CWE -> short architectural-defect phrase used to derive
# `tier_root_causes` deterministically when the orchestrator did not
# author them. Phrases are <= 80 chars (heatmap budget) and describe
# the structural defect, not the vulnerability instance.
_CWE_TO_ROOT_CAUSE: dict[str, str] = {
    "CWE-89": "missing input neutralization on raw SQL paths",
    "CWE-943": "NoSQL operators reachable from user input",
    "CWE-79": "untrusted HTML rendered via bypassed sanitizer",
    "CWE-94": "user input reaches eval() / sandbox sinks",
    "CWE-95": "dynamic code construction from request data",
    "CWE-611": "XML parser accepts external entities",
    "CWE-91": "XML injection via unvalidated content",
    "CWE-798": "hardcoded credentials in source code",
    "CWE-321": "hardcoded cryptographic key in source code",
    "CWE-259": "default / hardcoded password in code",
    "CWE-327": "weak or deprecated cryptographic primitives",
    "CWE-916": "weak password hashing algorithm",
    "CWE-759": "password hash without per-user salt",
    "CWE-760": "predictable salt used in password hash",
    "CWE-347": "missing or bypassable token signature checks",
    "CWE-862": "missing authorization on protected endpoints",
    "CWE-284": "missing access control on protected endpoints",
    "CWE-863": "incorrect authorization decisions on resources",
    "CWE-639": "missing ownership checks on resource access",
    "CWE-918": "unrestricted outbound HTTP from server",
    "CWE-352": "no CSRF protection on state-changing requests",
    "CWE-434": "file uploads accepted without type/content validation",
    "CWE-22": "user input concatenated into filesystem paths",
    "CWE-23": "user input concatenated into filesystem paths",
    "CWE-200": "sensitive endpoints exposed without authentication",
    "CWE-209": "internal errors leaked to clients",
    "CWE-922": "session token in JavaScript-readable storage",
    "CWE-312": "sensitive data persisted in cleartext",
    "CWE-538": "internal files reachable on public routes",
    "CWE-307": "no brute-force protection on authentication",
    "CWE-400": "unbounded resource consumption paths",
    "CWE-770": "missing rate limits on expensive operations",
    "CWE-1104": "unmaintained or vulnerable npm dependencies",
    "CWE-829": "unverified third-party code loaded at runtime",
    "CWE-346": "missing origin checks on cross-origin requests",
    "CWE-601": "open redirect via unvalidated URL parameter",
    "CWE-915": "mass assignment exposes privileged attributes",
    "CWE-269": "privilege checks performed only on the client",
    "CWE-1188": "default-on-by-default insecure configuration",
    "CWE-778": "insufficient audit logging of security events",
}


# Per-CWE deterministic Mitigation snippets used as the quick-depth
# backstop when the orchestrator did not author a code example. Keep
# each snippet short (5-12 lines) and idiomatic: TypeScript / JavaScript
# unless the CWE is specific to another stack. The `verification` line
# is a single-sentence check that proves the fix landed.
_MITIGATION_CWE_SNIPPETS: dict[str, dict[str, str]] = {
    "CWE-89": {
        "lang": "typescript",
        "code": (
            "// Reject string interpolation; use parameter binding.\n"
            "await sequelize.query(\n"
            "  'SELECT * FROM Users WHERE email = :email AND password = :password',\n"
            "  { replacements: { email, password: hash(password) }, type: QueryTypes.SELECT }\n"
            ")"
        ),
        "verification": (
            "Submit `' OR 1=1 --` in the affected field and confirm the request returns 401 "
            "(or zero rows) instead of an authenticated session."
        ),
    },
    "CWE-943": {
        "lang": "javascript",
        "code": (
            "// Reject `$where` and operator keys from user-controlled input.\n"
            "function safeQuery(filter) {\n"
            "  for (const k of Object.keys(filter)) {\n"
            "    if (k.startsWith('$')) throw new Error('operator not allowed')\n"
            "  }\n"
            "  return collection.find(filter)\n"
            "}"
        ),
        "verification": (
            'Send `{ "$where": "sleep(5000) || true" }` and confirm the request is rejected '
            "(HTTP 400) within 100 ms instead of taking ~5 s."
        ),
    },
    "CWE-79": {
        "lang": "typescript",
        "code": (
            "// Never call bypassSecurityTrust*; let Angular sanitize.\n"
            '// template:  <div [innerHTML]="product.description"></div>\n'
            "// component: no DomSanitizer.bypassSecurityTrustHtml(...)\n"
            "this.product.description = raw  // bound directly; Angular escapes"
        ),
        "verification": (
            "Insert `<img src=x onerror=alert(1)>` via the affected field and confirm the "
            "browser renders the escaped text, not an alert dialog."
        ),
    },
    "CWE-94": {
        "lang": "javascript",
        "code": (
            "// Replace `eval()` / sandbox with a strict whitelist parser.\n"
            "import { evaluate } from 'mathjs'\n"
            "const allowed = /^[\\d+\\-*/().\\s]+$/\n"
            "if (!allowed.test(expr)) throw new Error('invalid expression')\n"
            "return evaluate(expr)"
        ),
        "verification": (
            "POST `require('child_process').exec('id')` to the affected endpoint and confirm "
            "HTTP 400 instead of OS command execution."
        ),
    },
    "CWE-611": {
        "lang": "javascript",
        "code": (
            "// libxmljs2 — disable external entities and network fetch.\n"
            "const doc = libxmljs.parseXml(xmlBuf, { noent: false, nonet: true, recover: false })\n"
            "if (doc.errors.length) throw new Error('xml rejected')"
        ),
        "verification": (
            "Upload a SYSTEM-entity payload referencing `file:///etc/passwd` and confirm the "
            "parser rejects it instead of resolving the entity."
        ),
    },
    "CWE-321": {
        "lang": "typescript",
        "code": (
            "// Load the RSA private key from an environment variable / KMS — never\n"
            "// the source tree. Rotate the prior key and revoke outstanding tokens.\n"
            "const privateKey = process.env.JWT_PRIVATE_KEY\n"
            "if (!privateKey) throw new Error('JWT_PRIVATE_KEY not set')\n"
            "const token = jwt.sign(claims, privateKey, { algorithm: 'RS256' })"
        ),
        "verification": ("`git grep -- 'BEGIN RSA PRIVATE KEY'` returns no matches in the working tree."),
    },
    "CWE-798": {
        "lang": "typescript",
        "code": (
            "// Read secrets from env / vault, not the source.\n"
            "const hmacKey = process.env.ORDER_HMAC_KEY\n"
            "if (!hmacKey) throw new Error('ORDER_HMAC_KEY not set')\n"
            "const sig = createHmac('sha256', hmacKey).update(payload).digest('hex')"
        ),
        "verification": (
            "Run a secret-scanner (trufflehog / git-secrets) on HEAD and confirm zero hits in `lib/` and `routes/`."
        ),
    },
    "CWE-327": {
        "lang": "typescript",
        "code": (
            "// jsonwebtoken@9+: pin algorithm whitelist; reject `alg:none`.\n"
            "jwt.verify(token, publicKey, { algorithms: ['RS256'] })"
        ),
        "verification": (
            "Submit a token with `alg:none` (no signature) and confirm `jwt.verify()` "
            "throws instead of returning the decoded claims."
        ),
    },
    "CWE-916": {
        "lang": "typescript",
        "code": (
            "// Replace md5/sha1 password hashes with bcrypt or argon2.\n"
            "import bcrypt from 'bcrypt'\n"
            "const hash = await bcrypt.hash(plaintext, 12)\n"
            "const ok = await bcrypt.compare(plaintext, storedHash)"
        ),
        "verification": (
            "`select password from Users limit 1;` returns a `$2b$12$...` bcrypt prefix, not a 32-hex md5 string."
        ),
    },
    "CWE-347": {
        "lang": "typescript",
        "code": (
            "// Always verify on the public key; never trust the unsigned header.\n"
            "const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] })"
        ),
        "verification": ("Tamper one byte in a valid token's payload and confirm `jwt.verify()` throws."),
    },
    "CWE-862": {
        "lang": "typescript",
        "code": (
            "// Add server-side role check on every admin route.\n"
            "router.use('/admin/*', (req, res, next) => {\n"
            "  if (req.user?.role !== 'admin') return res.status(403).end()\n"
            "  next()\n"
            "})"
        ),
        "verification": ("Hit `/admin/...` with a non-admin JWT and confirm 403 (not 200)."),
    },
    "CWE-284": {
        "lang": "typescript",
        "code": (
            "// Centralize access decisions in a single middleware.\n"
            "function requireRole(role: 'admin' | 'user') {\n"
            "  return (req, res, next) =>\n"
            "    req.user?.role === role ? next() : res.status(403).end()\n"
            "}"
        ),
        "verification": ("Cross-check every `/api/*` route for an explicit `requireRole(...)` call; gaps fail CI."),
    },
    "CWE-639": {
        "lang": "typescript",
        "code": (
            "// Ownership check before touching a resource.\n"
            "const basket = await Basket.findByPk(req.params.id)\n"
            "if (!basket || basket.UserId !== req.user.id) return res.status(403).end()"
        ),
        "verification": ("Authenticate as user A; request `/api/Baskets/<B's id>` and confirm 403."),
    },
    "CWE-918": {
        "lang": "typescript",
        "code": (
            "// Allowlist external image hosts; block private IP ranges.\n"
            "const ALLOWED_HOSTS = new Set(['images.example.com', 'cdn.example.com'])\n"
            "const url = new URL(input)\n"
            "if (!ALLOWED_HOSTS.has(url.hostname)) throw new Error('host not allowed')\n"
            "if (/^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.)/.test(url.hostname))\n"
            "  throw new Error('private range blocked')"
        ),
        "verification": ("POST a URL pointing at `http://169.254.169.254/` and confirm HTTP 400."),
    },
    "CWE-352": {
        "lang": "typescript",
        "code": (
            "// Use double-submit cookie / SameSite=Strict for state-changing routes.\n"
            "app.use(csrf({ cookie: { sameSite: 'strict', httpOnly: true, secure: true } }))"
        ),
        "verification": ("Replay a state-changing POST without the CSRF token from a foreign origin and confirm 403."),
    },
    "CWE-434": {
        "lang": "typescript",
        "code": (
            "// Validate MIME, extension, and magic bytes; cap size.\n"
            "const ALLOWED = new Set(['image/png', 'image/jpeg'])\n"
            "if (!ALLOWED.has(file.mimetype)) throw new Error('mime not allowed')\n"
            "if (file.size > 2 * 1024 * 1024) throw new Error('too large')"
        ),
        "verification": ("Upload a `.html` file with `image/png` mimetype and confirm rejection."),
    },
    "CWE-922": {
        "lang": "typescript",
        "code": (
            "// Move the JWT out of localStorage into an httpOnly cookie.\n"
            "res.cookie('session', token, {\n"
            "  httpOnly: true, secure: true, sameSite: 'lax', maxAge: 3600_000\n"
            "})"
        ),
        "verification": ("Open browser DevTools, run `localStorage.getItem('token')` and confirm `null`."),
    },
    "CWE-200": {
        "lang": "typescript",
        "code": (
            "// Remove directory-listing middleware; require auth on management endpoints.\n"
            "// app.use('/ftp', serveIndex(...))   // delete\n"
            "app.use('/metrics', requireRole('admin'), promBundle())"
        ),
        "verification": ("Unauthenticated `GET /metrics` returns 401; `GET /ftp/` returns 404."),
    },
    "CWE-1104": {
        "lang": "bash",
        "code": (
            "# Pin and audit dependencies; fail CI on known vulns.\n"
            "npm audit --omit=dev --audit-level=high\n"
            "# Upgrade unmaintained packages in package.json, then:\n"
            "npm install && npm test"
        ),
        "verification": ("`npm audit --omit=dev --audit-level=high` exits 0."),
    },
    "CWE-915": {
        "lang": "typescript",
        "code": (
            "// Whitelist mutable fields server-side; never trust the body.\n"
            "const ALLOWED = ['email', 'username'] as const\n"
            "const patch = Object.fromEntries(\n"
            "  Object.entries(req.body).filter(([k]) => ALLOWED.includes(k as any))\n"
            ")\n"
            "await user.update(patch)"
        ),
        "verification": (
            'POST `{ "role": "admin" }` to the register/update endpoint; confirm the stored row keeps the default role.'
        ),
    },
    "CWE-307": {
        "lang": "typescript",
        "code": (
            "// Per-IP + per-account rate limiting on auth endpoints.\n"
            "import rateLimit from 'express-rate-limit'\n"
            "app.use('/rest/user/login',\n"
            "  rateLimit({ windowMs: 60_000, max: 5, standardHeaders: true }))"
        ),
        "verification": ("Send 10 invalid login attempts from one IP and confirm the 6th returns 429."),
    },
    "CWE-778": {
        "lang": "typescript",
        "code": (
            "// Log authn / authz outcomes with stable correlation ids.\n"
            "logger.info({ event: 'auth.login.fail', userId, ip: req.ip, reqId })\n"
            "logger.info({ event: 'authz.deny', userId, route: req.path, reqId })"
        ),
        "verification": ("A failed admin probe leaves an `authz.deny` line in the central log within 1 s."),
    },
}


_TIER_RC_SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 8,
    "high": 4,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _derive_tier_root_causes(
    threats: list[dict],
    *,
    attack_class_cwes: set[str] | None = None,
) -> list[str]:
    """Aggregate the CWE classes of `threats` into a short, ordered list
    of architectural-defect phrases used by the Security Posture heatmap
    when the yaml `tier_root_causes` is not authored.

    Selection (revised — A3):
      - Map each threat's `cwe` (or first `cwe_ids[]`) to a phrase via
        `_CWE_TO_ROOT_CAUSE`. Skip unknown CWEs.
      - Score each phrase by SUM(severity weight) across its findings,
        not raw count. A single Critical finding (weight 8) outranks
        seven Low findings (weight 1 each) - this corrects the previous
        frequency-only ranking that pushed hardcoded-secret and RBAC
        defects out of the top-3 in favour of dependency hygiene.
      - When ``attack_class_cwes`` is non-empty, only phrases whose
        source CWE is in that set survive. This anchors the root-cause
        line to the same attack arrows that the diagram actually shows
        entering the tier, preventing root causes that have no visible
        arrow (e.g. supply-chain CI/CD when no supply-chain arrow is
        drawn) from drowning out impact-class defects.
      - Order: by total weight desc, then first-seen order.
      - Cap at 3 phrases so the heatmap card stays scannable.
    """
    if not threats:
        return []
    weight: dict[str, int] = {}
    order: list[str] = []
    for t in threats:
        # Read CWE from either single-string or list shape.
        raw = (t.get("cwe") or "").strip()
        if not raw:
            cwe_ids = t.get("cwe_ids") or []
            if isinstance(cwe_ids, list) and cwe_ids:
                raw = (cwe_ids[0] or "").strip()
        if not raw:
            continue
        # Normalise to "CWE-NN" uppercase prefix.
        if not raw.upper().startswith("CWE-"):
            raw = f"CWE-{raw.lstrip('Cc').lstrip('Ww').lstrip('Ee').lstrip('-')}"
        cwe = raw.upper()
        if attack_class_cwes is not None and cwe not in attack_class_cwes:
            # Filter to CWEs whose attack class actually reaches this tier
            # via a rendered arrow. Drops "supply-chain dependencies" when
            # no supply-chain arrow exists in the diagram, leaving room
            # for impact-class defects that do.
            continue
        phrase = _CWE_TO_ROOT_CAUSE.get(cwe)
        if not phrase:
            continue
        sev = (t.get("risk") or t.get("severity") or "").strip().lower()
        w = _TIER_RC_SEVERITY_WEIGHT.get(sev, 1)
        if phrase not in weight:
            order.append(phrase)
        weight[phrase] = weight.get(phrase, 0) + w
    if not weight:
        return []
    # Sort by total weight desc, then first-seen order.
    sorted_phrases = sorted(order, key=lambda p: (-weight[p], order.index(p)))
    return sorted_phrases[:3]


# Tier display names + canonical Mermaid node ids.
_TIER_DISPLAY: dict[str, tuple[str, str, str, str]] = {
    # Tier icons follow the audit actor convention: window-restore for the
    # browser/client tier (visually a browser window), server for the
    # application tier, database for the data tier. fa:fa-desktop was
    # used previously but reads as a generic computer rather than a
    # browser sandbox.
    "client": ("Client Tier", "BROWSER", "tierClient", "fa:fa-window-restore"),
    "application": ("Application Tier", "SERVER", "tierApp", "fa:fa-server"),
    "data": ("Data Tier", "DATA", "tierData", "fa:fa-database"),
}


def _build_tier_cards(
    components: list[dict],
    threats_by_component: dict[str, list[dict]],
    tier_root_causes: dict,
    *,
    attack_paths_data: dict | None = None,
    attack_taxonomy: dict | None = None,
) -> list[dict]:
    """For each non-empty tier (client / application / data), build the
    Jinja-input dict the diagram template expects.

    The card rendering is structured as four lines:

      1. Bold tier name (rendered via the template).
      2. Root-causes line: ``⚠ <causes joined by " · ">``.
      3. Components line: bold component-id list joined by " · ".
      4. Severity-counts line: ``🔴 N Critical · 🟠 N High · 🟡 N Medium``.
         Low-severity findings are intentionally omitted (per contract v2
         ``tier_severity_floor: medium``).
    """
    by_layer: dict[str, list[dict]] = {"client": [], "application": [], "data": []}
    for c in components:
        by_layer[_classify_component_layer(c)].append(c)

    # M3.11 — Build a `threats_by_target_tier` lookup that respects each
    # cluster's `preferred_tier` from data/weakness-classes.yaml. This is
    # the routing layer that prevents the same weakness cluster (e.g.
    # "Injection") from appearing in BOTH the Application and Data tier
    # boxes — a single cluster always lands in its canonical tier.
    #
    # Routing rule per threat:
    #   1. Classify threat into a cluster (CWE → cluster.id).
    #   2. Look up cluster.preferred_tier:
    #      - "client" / "application" / "data" → force-route to that tier
    #      - "by_component" → use the threat's component → tier mapping
    #                         (fallback for legitimately tier-spanning clusters
    #                         like sensitive_disclosure)
    #   3. Stash threat under that target-tier key.
    # The legacy `threats_by_component` lookup is preserved for the
    # severity-count line + components line (they need component-level
    # accuracy); only the cluster-line builder uses the routed view.
    _vocab = _load_weakness_classes()
    threats_by_target_tier: dict[str, list[dict]] = {"client": [], "application": [], "data": []}
    # Re-derive component → tier index now (it was populated below the loop
    # in the legacy flow; we need it here for routing).
    _component_tier_index: dict[str, str] = {}
    for _tier_key, _comps in by_layer.items():
        for _c in _comps:
            _cid = (_c.get("id") or "").strip()
            if _cid:
                _component_tier_index[_cid] = _tier_key
    for cid_local, tlist in threats_by_component.items():
        comp_tier = _component_tier_index.get(cid_local, "application")
        for t in tlist:
            cluster_id = _classify_threat_cluster(t, _vocab)
            target_tier = _tier_for_cluster(cluster_id, comp_tier, _vocab)
            if target_tier not in threats_by_target_tier:
                target_tier = comp_tier
            threats_by_target_tier[target_tier].append(t)

    component_tier_index: dict[str, str] = {}
    for tier_key, comps in by_layer.items():
        for c in comps:
            cid = (c.get("id") or "").strip()
            if cid:
                component_tier_index[cid] = tier_key

    # Pre-compute per-tier CWE allow-sets from rendered attack arrows.
    # The diagram shows arrows of class X reaching tier T whenever the
    # attack_paths entry for X has `target == T`. The deterministic root-
    # cause fallback uses these allow-sets to ensure the bullet line
    # describes the same defects the visible arrows point at, instead of
    # dependency-hygiene defects that have no matching arrow.
    cwe_allow_by_tier: dict[str, set[str]] = {"client": set(), "application": set(), "data": set()}
    if attack_paths_data and attack_taxonomy:
        classes_by_id = {c.get("id"): c for c in (attack_taxonomy.get("classes") or [])}
        for ap in attack_paths_data.get("attack_paths") or []:
            cls = classes_by_id.get(ap.get("class") or "")
            if not cls:
                continue
            actor_slug = (ap.get("actor") or "").lower()
            target = (ap.get("target") or cls.get("default_target_tier") or "application").lower()
            # Victim-targeting classes deliver the attack to the client
            # tier (arrow points at the victim sitting above the client).
            if actor_slug == "victim-required" or target == "victim":
                target = "client"
            if target not in cwe_allow_by_tier:
                continue
            for cwe in cls.get("cwes") or []:
                cwe_allow_by_tier[target].add((cwe or "").upper().strip())

    cards: list[dict] = []
    for key in ("client", "application", "data"):
        comps_in_tier = by_layer[key]
        if not comps_in_tier:
            continue
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        comp_ids: list[str] = []
        for c in comps_in_tier:
            cid = (c.get("id") or "").strip()
            comp_ids.append(cid)
            for t in threats_by_component.get(cid, []):
                sev = (t.get("risk") or t.get("severity") or "").strip().lower()
                if sev in sev_counts:
                    sev_counts[sev] += 1
        # Severity-counts line — Low excluded per contract v2 floor.
        sev_parts: list[str] = []
        if sev_counts["critical"]:
            sev_parts.append(f"🔴 {sev_counts['critical']} Critical")
        if sev_counts["high"]:
            sev_parts.append(f"🟠 {sev_counts['high']} High")
        if sev_counts["medium"]:
            sev_parts.append(f"🟡 {sev_counts['medium']} Medium")
        # Defer sev_line composition until after rcs is resolved so the
        # "(no findings)" fallback only fires when neither severity
        # counts NOR root-cause bullets are available. Previously the
        # heatmap rendered a contradiction: root-cause bullets like
        # "MD5 used for password hashing…" above a "(no findings)" tag.
        rcs = (tier_root_causes or {}).get(key) or []
        # Legacy yaml may use "edge"/"server" keys; map them onto the new
        # tier vocabulary.
        if not rcs and key == "client":
            rcs = (tier_root_causes or {}).get("edge") or []
        if not rcs and key == "application":
            rcs = (tier_root_causes or {}).get("server") or []
        # Deterministic fallback: when the orchestrator did not author
        # `tier_root_causes` for this tier (common at quick depth where
        # Phase 11 narrative is reduced), derive short architectural
        # defect phrases from the CWE classes of the tier's threats.
        # Ranking is severity-weighted; the phrase pool is constrained
        # to CWEs whose attack class actually reaches this tier per the
        # rendered arrows (A3 — keeps root causes consistent with the
        # diagram).
        if not rcs:
            tier_threats: list[dict] = []
            for c in comps_in_tier:
                cid_local = (c.get("id") or "").strip()
                tier_threats.extend(threats_by_component.get(cid_local, []) or [])
            allow = cwe_allow_by_tier.get(key) or None
            # Empty allow-set (no arrows hit this tier) falls back to the
            # legacy unconstrained behaviour - some component without a
            # visible arrow is better than no root-cause line at all.
            if allow == set():
                allow = None
            rcs = _derive_tier_root_causes(tier_threats, attack_class_cwes=allow)
        rc_line = ("⚠ " + " · ".join(rcs)) if rcs else "⚠ (no root causes documented)"
        # Compose sev_line now that rcs is final. Suppress the
        # "(no findings)" fallback when rcs is non-empty — the root-cause
        # bullets already convey tier-level posture and the fallback
        # would contradict them.
        if sev_parts:
            sev_line = " · ".join(sev_parts)
        elif rcs:
            sev_line = ""
        else:
            sev_line = "(no findings)"
        # Components line. Reference form (2026-05): list the tier's components
        # as `C-NN Name` (global C-NN order), matching Figure 2 in
        # docs/analysis-top-threats-merge.md where each tier box simply lists
        # the components it contains. Component IDs are emitted plain (no <b>)
        # — bold is reserved for the column-header HDR_A/T/I cells.
        _cnn = {(_c.get("id") or "").strip(): f"C-{_i:02d}" for _i, _c in enumerate(components, start=1)}
        if comps_in_tier:
            comp_line = " · ".join(
                f"{_cnn.get((c.get('id') or '').strip(), '')} {(c.get('name') or c.get('id') or '').strip()}".strip()
                for c in comps_in_tier
            )
        else:
            comp_line = "(no components)"
        display_name, node_id, css_class, tier_icon = _TIER_DISPLAY[key]
        cards.append(
            {
                "key": key,
                "node_id": node_id,
                "name": display_name,
                "fa_icon": tier_icon,
                "root_causes_line": rc_line,
                "components_line": comp_line,
                "severity_counts_line": sev_line,
                "css_class": css_class,
                "components": comp_ids,
                # M3.9 — weakness-cluster rows for the tier box. Each row is
                # `<icon> <cluster-label>[ (<variants>)] — T-NNN[, T-NNN]…`.
                # Source-of-truth vocabulary lives in
                # `data/weakness-classes.yaml`. The template prefers
                # `cluster_label_lines` over the legacy three-line layout
                # (root_causes / components / severity_counts) when present;
                # legacy fields stay populated for backward compatibility
                # with any template variant that hasn't migrated yet.
                # Header summary count = routed-tier finding count (so the
                # `· N findings` matches what the cluster_label_lines below
                # actually represent). The legacy per-component sum is
                # intentionally not used here — a "data" tier whose
                # injection threats route to "application" would otherwise
                # show inflated counts.
                # Bracket-component list MUST reflect the routed threats, not
                # the static `component.tier == key` set. The Heat-Map box's
                # count (`· N findings`) is routed-based, so the bracket
                # has to be routed-based too — otherwise readers see
                # "Data Tier (data-layer) · 2 findings" while T-014 actually
                # comes from express-backend. See Bug C verification in the
                # 2026-05 tier-routing analysis. The legacy `comp_ids` is
                # preserved for the legacy `components_line` fallback below.
                "header_summary": _tier_header_summary(
                    display_name,
                    _bracket_components_for_tier(
                        threats_by_target_tier.get(key, []),
                        comp_ids,
                    ),
                    len(threats_by_target_tier.get(key, [])),
                ),
                # Reference form (2026-05): tier boxes list their COMPONENTS
                # only (see comp_line above), not weakness-cluster bullets, to
                # match Figure 2 in docs/analysis-top-threats-merge.md. The
                # legacy cluster bullets are intentionally suppressed (empty
                # list → template uses the name + components_line branch). The
                # per-class weakness detail lives in the Top Threats table and
                # §7/§8. `_build_tier_cluster_lines` is retained for reference
                # but no longer wired into the heatmap.
                "cluster_label_lines": [],
            }
        )
    return cards


# ---------------------------------------------------------------------------
# Weakness-cluster vocabulary loader (data/weakness-classes.yaml).
# ---------------------------------------------------------------------------

_STRENGTH_CLUSTERS_CACHE: dict[str, Any] | None = None


# M-10c: File-path extension allowlist. The trailing segment of an em-dash-
# separated title is treated as a file path when it (a) contains a `/` OR
# (b) ends with one of these extensions. The list mirrors the source file
# types the threat-analyzer actually emits — keep it tight; "ext-shaped"
# tokens (e.g. ".md" in prose) inside non-file phrases shouldn't trigger.
_FILE_PATH_EXTENSIONS = frozenset(
    {
        "ts",
        "tsx",
        "js",
        "jsx",
        "json",
        "yaml",
        "yml",
        "py",
        "go",
        "rs",
        "java",
        "kt",
        "rb",
        "php",
        "cs",
        "c",
        "h",
        "cpp",
        "hpp",
        "swift",
        "scala",
        "md",
        "html",
        "css",
        "scss",
        "sql",
        "sh",
        "bash",
        "ps1",
        "lock",  # package-lock.json, Cargo.lock etc.
    }
)

# Compiled regex: a "file-shaped" segment is either dotted with a known
# extension (with optional :line suffix) OR contains a forward-slash path.
_FILE_LIKE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_./-]+\.(?:" + "|".join(_FILE_PATH_EXTENSIONS) + r")(?::\d+)?$")
_PATH_LIKE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_./-]+/[A-Za-z0-9_./-]+$")


def _looks_like_file_path(segment: str) -> bool:
    """True when ``segment`` plausibly identifies a source-tree file.
    Returns False for prose, version markers, CVE tokens, etc."""
    s = (segment or "").strip()
    if not s:
        return False
    if " " in s:
        return False  # prose, never a file path
    if s.upper().startswith("CVE-"):
        return False
    return bool(_FILE_LIKE_SEGMENT_RE.match(s) or _PATH_LIKE_SEGMENT_RE.match(s))


_TITLE_EM_DASH_RE = re.compile(r"\s+—\s+")


def _normalize_title_to_paren_form(raw_title: str) -> str:
    """M-10c: Convert ``"<weakness> — <file>"`` into ``"<weakness> (<file>)"``.

    Handles five corner cases observed in production output:
      • Last segment is a file path  → wrap in parens.
      • Last segment is prose ("XSS accessible") → leave as-is.
      • Multi-em-dash with file at end ("A — B — file.ts") → wrap only the
        trailing file segment: ``"A — B (file.ts)"``.
      • Already-paren form → idempotent no-op.
      • R-8 fix (2026-05) — Last segment is "<prose-word> <filepath>"
        ("basket coupon.ts:18"): split on last space; if right half is a
        file path, treat the left half as a qualifier and move BOTH into the
        paren tail: ``"IDOR (basket coupon.ts:18)"``. Keeps the qualifier
        with the file context where it semantically belongs.

    Title is also Title-Cased on the leading word ONLY when it starts with
    a lowercase letter — preserves the user-memory convention.
    """
    if not isinstance(raw_title, str):
        return raw_title
    text = raw_title.strip()
    if not text or "—" not in text:
        return text
    segments = _TITLE_EM_DASH_RE.split(text)
    # Strip pure-whitespace segments produced by leading/trailing dashes.
    segments = [s.strip() for s in segments if s.strip()]
    if len(segments) < 2:
        return text
    tail = segments[-1]
    # R-8 fix: try the "<qualifier> <filepath>" pattern when the tail
    # contains a space and isn't a pure file path on its own.
    if not _looks_like_file_path(tail) and " " in tail:
        idx = tail.rfind(" ")
        candidate_path = tail[idx + 1 :].strip()
        if _looks_like_file_path(candidate_path):
            # Whole tail (qualifier + filepath) goes inside the parens — the
            # qualifier provides reading context that gets lost if we strip it.
            head = " — ".join(segments[:-1]).strip()
            if head and not head.endswith(")"):
                return f"{head} ({tail})"
            return text
    if not _looks_like_file_path(tail):
        return text  # last segment is prose — leave the title alone
    head = " — ".join(segments[:-1]).strip()
    if not head:
        return text
    # Don't re-wrap when head already ends with a paren-group (idempotent).
    if head.endswith(")"):
        return text
    return f"{head} ({tail})"


def _normalize_titles_paren_form(yaml_data: dict, output_dir: Path) -> None:
    """M-10c orchestration helper: rewrite every threat's ``title`` field
    in-memory and log per-threat normalisations to ``.reconcile-log.json``.

    Mitigations and critical_findings share the same convention; both are
    normalised here for consistency.
    """
    if not isinstance(yaml_data, dict):
        return
    normalised: list[dict] = []

    def _walk(items: list, kind: str, id_key: str) -> None:
        if not isinstance(items, list):
            return
        for entry in items:
            if not isinstance(entry, dict):
                continue
            raw = entry.get("title")
            new = _normalize_title_to_paren_form(raw)
            if isinstance(raw, str) and new != raw:
                entry["title"] = new
                normalised.append(
                    {
                        "kind": kind,
                        "id": entry.get(id_key) or entry.get("id"),
                        "from": raw,
                        "to": new,
                    }
                )

    _walk(yaml_data.get("threats") or [], "threat", "id")
    _walk(yaml_data.get("mitigations") or [], "mitigation", "id")
    _walk(yaml_data.get("critical_findings") or [], "critical_finding", "threat_id")

    if not normalised:
        return
    try:
        log_path = output_dir / ".reconcile-log.json"
        existing: dict = {}
        if log_path.is_file():
            try:
                existing = json.loads(log_path.read_text(encoding="utf-8")) or {}
            except (json.JSONDecodeError, OSError):
                existing = {}
        existing.setdefault("title_normalisations", []).extend(normalised)
        log_path.write_text(
            json.dumps(existing, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
    except OSError:
        pass


def _first_evidence_file(threat: dict) -> tuple[str, int | None]:
    """Return ``(file, line)`` of the first evidence entry, or ``('', None)``.

    Tolerates both list-shaped and dict-shaped ``evidence`` (legacy yamls).
    """
    ev = threat.get("evidence") or []
    first: dict[str, Any] = {}
    if isinstance(ev, list) and ev:
        first = ev[0] if isinstance(ev[0], dict) else {}
    elif isinstance(ev, dict):
        first = ev
    f = (first.get("file") or "").strip()
    ln = first.get("line") if isinstance(first.get("line"), int) else None
    return f, ln


def _format_manual_review_hint(threat: dict, tid: str) -> dict[str, str] | None:
    """M-14: Build a ``{action, kind}`` cell synthesising a manual-review
    suggestion when a finding has no linked mitigation.

    The hint targets the first evidence ``file[:line]`` and links to the §8
    row anchor (``#t-NNN`` / ``#f-NNN``) so the reviewer lands on the full
    finding context. Returns ``None`` when no evidence file exists — in that
    case the cell stays as ``—`` (the deterministic fallback prefers
    silence over a meaningless ``Manual review at ?``).
    """
    f, ln = _first_evidence_file(threat)
    if not f:
        return None
    target = f"{f}:{ln}" if ln else f
    # Anchor: prefer the F-NNN form since the §8 register renders both
    # anchors but the visible label is F-NNN (compose:6964-6970).
    m = re.match(r"^T-(\d+)$", tid or "")
    anchor = f"f-{m.group(1)}" if m else (tid or "").lower()
    return {
        "id": "",
        # `action` becomes the whole cell text; format_mitigations skips the
        # `[mid](#mid)` prefix when id is empty.
        "action": f"Manual review at [`{target}`](#{anchor})",
        "priority": "",
        "kind": "review",
    }


def _shorten_title_for_xref(raw_title: str, threat: dict | None = None, *, compact: bool = False) -> str:
    """Return the cross-reference form of a threat title.

    Output format (M3.13 — post-2026-05 simplified):
        - With param + file: `<Weakness> in file <path> ("<name>")`
        - Without param, with file: `<Weakness> in file <path>`
        - With non-file path (directory): `<Weakness> in <path>`
        - Cross-cutting (no path, no param): `<Weakness>`

    ``compact=True`` switches to a parens form for table cells where a
    single mitigation row may stack 4-5 findings via `<br/>` — the
    "in file" form repeated per finding reads as bloat. Compact form:
        - With param + file: `<Weakness> (<path>, "<name>")`
        - Without param, with file: `<Weakness> (<path>)`
        - Cross-cutting: `<Weakness>` (unchanged)

    The bare `("<name>")` parameter token replaces the previous
    `(param "<name>")` form — the `param ` prefix added noise without
    information (the surrounding context already implies "this is the
    affected parameter"). See user feedback 2026-05-17.

    Examples:
        'SQL Injection in file routes/login.ts ("email")'
        'Hardcoded Cryptographic Key in file lib/insecurity.ts'
        'Insecure Token Storage in frontend/src/app/Services'
        'Cross-Site Request Forgery in file server.ts'

    Input form expected from yaml.title: "<Weakness> (<file[:line]>)" or
    "<Weakness> (<param>, <file[:line]>)" or bare "<Weakness>". The function
    also consults `threat.affected_parameter` + `threat.evidence[0].file`
    when the title alone is not enough.
    """
    raw_title = (raw_title or "").strip()
    if not raw_title:
        return raw_title

    threat = threat or {}
    param = (threat.get("affected_parameter") or "").strip() or None

    # Pull file path from evidence (first entry) as a fallback source.
    ev = threat.get("evidence")
    if isinstance(ev, dict):
        ev = [ev]
    elif not isinstance(ev, list):
        ev = []
    ev_file = ""
    if ev and isinstance(ev[0], dict):
        ev_file = (ev[0].get("file") or "").strip()

    # Parse current title to extract weakness + any existing parens content.
    parsed_path = ""
    parsed_param = None
    m = re.match(r"^(.*?)\s*\(([^()]+)\)\s*$", raw_title)
    if m:
        weakness = m.group(1).strip()
        inner = m.group(2).strip()
        # Tokens are comma-separated. Path token = contains "/" or ends
        # in ".ext"; the OTHER token (if any) is the parameter.
        for tok in (p.strip() for p in inner.split(",")):
            stripped = re.sub(r"(\.[A-Za-z0-9]{1,6}):\d+$", r"\1", tok)
            if "/" in stripped or re.search(r"\.[A-Za-z0-9]{1,6}$", stripped):
                parsed_path = parsed_path or stripped
            else:
                parsed_param = parsed_param or stripped
    else:
        weakness = raw_title

    # Resolve final path + param: yaml field wins, else parsed-from-title.
    path = parsed_path or re.sub(r"(\.[A-Za-z0-9]{1,6}):\d+$", r"\1", ev_file)
    final_param = param or parsed_param

    # Compose the new form. The affected PARAMETER is intentionally dropped —
    # the finding-title contract is `<weakness class> — <file[:line]>` only, no
    # payloads / parameters / code (user report 2026-06-12: cells read
    # `… (routes/login.ts, "email")`). `final_param` is still resolved above for
    # back-compat but never rendered into the label.
    _ = final_param  # noqa: F841 — resolved for parsing symmetry, deliberately unused
    if path:
        if compact:
            # Parens form for table-cell contexts (Top Mitigations).
            return f"{weakness} ({path})"
        # "in file <path>" when path looks like a file; "in <path>" otherwise.
        in_phrase = "in file" if re.search(r"\.[A-Za-z0-9]{1,6}$", path) else "in"
        return f"{weakness} {in_phrase} {path}"
    return weakness


def _strip_embedded_evidence_file(title: str, threat: dict | None) -> str:
    """Drop a trailing evidence-file token that upstream title generation
    appends to the weakness phrase.

    Stage-1 increasingly emits titles like
    ``"SQL injection authentication bypass routes/login.ts"`` — the file is
    glued onto the weakness with a bare space. Downstream renderers then add
    the file AGAIN (``_shorten_title_for_xref`` → ``… (routes/login.ts)``;
    the §8 Location cell; bare-ref linkifiers), producing the redundant
    ``… routes/login.ts (routes/login.ts)`` form the user flagged.

    Strip the trailing token ONLY when it matches — or is a truncated prefix
    of (the title may have been clipped at ~80 chars, leaving ``… administ…``)
    — one of the threat's ``evidence[].file`` paths, so genuine weakness words
    are never clipped. The file still reaches the reader via the evidence-
    derived suffixes that each renderer adds deliberately.
    """
    t = (title or "").strip()
    if not t or not isinstance(threat, dict):
        return t
    ev = threat.get("evidence")
    if isinstance(ev, dict):
        ev = [ev]
    elif not isinstance(ev, list):
        ev = []
    files = [(e.get("file") or "").strip() for e in ev if isinstance(e, dict)]
    files = [f for f in files if f]
    if not files:
        return t
    idx = t.rfind(" ")
    if idx < 0:
        return t
    tail = re.sub(r":\d+$", "", t[idx + 1 :].rstrip("…").strip())
    # Tail must look like a path (slash or dotted extension) to be a file
    # token — never strip a plain trailing word like "spa" or "exclusions".
    if not tail or ("/" not in tail and not re.search(r"\.[A-Za-z0-9]{1,6}$", tail)):
        return t
    for f in files:
        f_norm = re.sub(r":\d+$", "", f)
        if f_norm == tail or f_norm.startswith(tail):
            return t[:idx].rstrip(" —–-")
    return t


def _load_weakness_classes() -> dict[str, Any]:
    """Lazy-load and cache the weakness-classes vocabulary.

    Delegates to the canonical `weakness_classifier` module so the composer and
    the threat merger share one class map (P1 weakness-class evidence model).
    """
    return _wc_load_weakness_classes()


_ARCH_CONTROLS_CACHE: dict[str, Any] | None = None
_STRENGTHS_EXCLUDED_NAMES_CACHE: set[str] | None = None


def _load_architectural_controls() -> dict[str, Any]:
    """Lazy-load and cache `data/architectural-controls.yaml`.
    Falls back to an empty mapping when the file is absent/malformed."""
    global _ARCH_CONTROLS_CACHE
    if _ARCH_CONTROLS_CACHE is not None:
        return _ARCH_CONTROLS_CACHE
    here = Path(__file__).resolve()
    plugin_root = here.parent.parent
    candidate = plugin_root / "data" / "architectural-controls.yaml"
    if not candidate.exists():
        _ARCH_CONTROLS_CACHE = {}
        return _ARCH_CONTROLS_CACHE
    import yaml as _yaml

    try:
        _ARCH_CONTROLS_CACHE = _yaml.safe_load(candidate.read_text()) or {}
    except Exception:
        _ARCH_CONTROLS_CACHE = {}
    return _ARCH_CONTROLS_CACHE


def _strengths_excluded_names() -> set[str]:
    """Return normalised name+alias tokens of controls flagged
    `excluded_from_strengths: true` in architectural-controls.yaml.
    These are tactical/baseline-hardening controls (HTTP response
    headers, etc.) that must not appear in the Management Summary's
    Operational Strengths table — that table is reserved for
    architectural decisions.
    """
    global _STRENGTHS_EXCLUDED_NAMES_CACHE
    if _STRENGTHS_EXCLUDED_NAMES_CACHE is not None:
        return _STRENGTHS_EXCLUDED_NAMES_CACHE
    tokens: set[str] = set()
    for entry in _load_architectural_controls().get("controls") or []:
        if not isinstance(entry, dict) or not entry.get("excluded_from_strengths"):
            continue
        for key in [entry.get("name")] + list(entry.get("aliases") or []):
            tok = "".join(ch.lower() for ch in (key or "") if ch.isalnum())
            if tok:
                tokens.add(tok)
    _STRENGTHS_EXCLUDED_NAMES_CACHE = tokens
    return tokens


def _load_strength_clusters() -> dict[str, Any]:
    """Lazy-load and cache the strength-clusters vocabulary used by
    `_render_operational_strengths` to collapse fine-grained security
    controls (e.g. X-Frame-Options, X-Content-Type-Options) into
    categorical strength rows (e.g. "Hardened HTTP Stack")."""
    global _STRENGTH_CLUSTERS_CACHE
    if _STRENGTH_CLUSTERS_CACHE is not None:
        return _STRENGTH_CLUSTERS_CACHE
    here = Path(__file__).resolve()
    plugin_root = here.parent.parent
    candidate = plugin_root / "data" / "strength-clusters.yaml"
    if not candidate.exists():
        _STRENGTH_CLUSTERS_CACHE = {"clusters": []}
        return _STRENGTH_CLUSTERS_CACHE
    import yaml as _yaml

    try:
        _STRENGTH_CLUSTERS_CACHE = _yaml.safe_load(candidate.read_text()) or {"clusters": []}
    except Exception:
        _STRENGTH_CLUSTERS_CACHE = {"clusters": []}
    return _STRENGTH_CLUSTERS_CACHE


_EFFECTIVENESS_RANK = {"adequate": 0, "partial": 1, "weak": 2, "missing": 3}
_EFFECTIVENESS_ICON = {
    "adequate": "✅ Adequate",
    "partial": "⚠️ Partial",
    "weak": "🔶 Weak",
    "missing": "❌ Missing",
}


def _classify_control_into_cluster(control: dict, clusters_cfg: list[dict]) -> str:
    """Return the cluster `id` a single security_controls[] entry maps to.

    Two-pass match — domain match (exact) ALWAYS wins over keyword match
    so a control with domain="Rate Limiting" maps to http_stack cluster
    even though the auth_session cluster's name_keywords list happens to
    contain "2FA" and the control's impl text mentions 2FA endpoints.

    Pass 1 — exact domain match across ALL clusters (first hit wins).
    Pass 2 — keyword substring match across ALL clusters (first hit wins).
    Fallback: `_unmapped`.
    """
    dom = (control.get("domain") or "").strip().lower()
    hay_parts = []
    for k in ("architectural_control", "canonical_name", "name", "control"):
        v = control.get(k)
        if isinstance(v, str):
            hay_parts.append(v.lower())
    impl = control.get("implementation")
    if isinstance(impl, dict):
        impl = impl.get("description") or ""
    if isinstance(impl, str):
        hay_parts.append(impl.lower())
    haystack = " | ".join(hay_parts)

    # Pass 1 — exact domain match. Domain is the authoritative signal; if
    # the yaml carries a structured domain we trust it.
    if dom:
        for cluster in clusters_cfg:
            if cluster.get("id") == "_unmapped":
                continue
            for d in cluster.get("domains") or []:
                if dom == d.strip().lower():
                    return cluster["id"]

    # Pass 2 — keyword substring match across clusters in definition order.
    for cluster in clusters_cfg:
        if cluster.get("id") == "_unmapped":
            continue
        for kw in cluster.get("name_keywords") or []:
            if not kw:
                continue
            if kw.strip().lower() in haystack:
                return cluster["id"]
    return "_unmapped"


# Title-keyword bridge per strength cluster. Used as a secondary signal
# alongside CWE → weakness-class mapping. When a threat's CWE field is
# corrupted (e.g. a Stage-1 mis-assignment puts CWE-89 on a JWT-bypass
# threat), the title keywords keep the cluster routing honest. A threat
# only ranks as a "strong" bypass-example for a cluster when BOTH the
# CWE AND the title agree; weaker matches are still counted toward the
# effectiveness cap so the cap stays sensitive even on scrambled data,
# but displayed examples prefer strong matches.
_STRENGTH_TITLE_KEYWORDS: dict[str, list[str]] = {
    "input_handling": [
        "sql injection",
        "sqli",
        "nosql",
        "$where",
        "xxe",
        "ssti",
        "eval(",
        "eval ",
        "rce",
        "code execution",
        "path traversal",
        "command injection",
        "template injection",
        "deserial",
    ],
    "auth_session": [
        "jwt",
        "alg:none",
        "alg none",
        "auth bypass",
        "authentication",
        "privilege",
        "admin role",
        "rsa private key",
        "session",
        "token",
        "totp",
        "2fa",
        "mfa",
        "oauth",
        "saml",
        "login bypass",
        "credential",
        "idor",
    ],
    "crypto_hygiene": [
        "md5",
        " sha-1",
        " sha1",
        "hash",
        "bcrypt",
        "scrypt",
        "argon",
        "hardcoded key",
        "hardcoded credential",
        "private key",
        "weak crypto",
        "broken crypt",
    ],
    "http_stack": [
        "csrf",
        "cors",
        "csp",
        "content security policy",
        "wildcard cors",
        "open redirect",
        "header injection",
        "rate limit",
        "permissions-policy",
        "hsts",
    ],
    "frontend_resilience": [
        "xss",
        "dom xss",
        "sanitizer",
        "bypasssecuritytrust",
        "innerhtml",
        "trusthtml",
        "stored xss",
        "reflected xss",
        "client-side",
        "client side",
    ],
    "data_protection": [
        "disclosure",
        "exposure",
        "localstorage",
        "leak",
        "ftp directory",
        "directory listing",
        "encryption keys",
        "password hash",
        "pii",
        "sensitive file",
    ],
}


def _classify_threat_for_strength_cluster(
    threat: dict,
    cluster_cfg: dict,
    weakness_vocab: dict,
) -> str:
    """Return one of: "strong" | "cwe_only" | "title_only" | "none".

    The strength-cluster effectiveness cap treats both `strong` and
    `cwe_only` as bypasses (so a corrupted-CWE row that the title also
    contradicts still depresses the rating); `title_only` matches are
    used to PROMOTE bypass examples to the front of the displayed list
    so the rendered Gap cell carries unambiguous threats.
    """
    addressed_classes = set((s or "").strip().lower() for s in (cluster_cfg.get("addresses_weakness_classes") or []))
    addressed_cwes = set((s or "").strip().upper() for s in (cluster_cfg.get("addresses_cwes") or []))
    cwe_raw = (threat.get("cwe") or "").strip()
    cwe = cwe_raw if cwe_raw.upper().startswith("CWE-") else (f"CWE-{cwe_raw}" if cwe_raw.isdigit() else cwe_raw)
    cwe_match = False
    if cwe and cwe.upper() in addressed_cwes:
        cwe_match = True
    else:
        wcid = _classify_threat_cluster(threat, weakness_vocab)
        if wcid in addressed_classes:
            cwe_match = True

    title = (threat.get("title") or "").lower()
    cluster_id = cluster_cfg.get("id", "")
    title_kws = _STRENGTH_TITLE_KEYWORDS.get(cluster_id, [])
    name_kws = [k.lower() for k in (cluster_cfg.get("name_keywords") or [])]
    all_kws = [k for k in (title_kws + name_kws) if k]
    title_match = any(kw in title for kw in all_kws)

    if cwe_match and title_match:
        return "strong"
    if cwe_match:
        return "cwe_only"
    if title_match:
        return "title_only"
    return "none"


def _threats_for_strength_cluster(
    cluster_cfg: dict,
    all_threats: list[dict],
    weakness_vocab: dict,
) -> list[tuple[dict, str]]:
    """Return threats whose weakness class (CWE-mapped) or title-keyword
    bridge falls within the strength cluster's defensive remit.

    Each entry is ``(threat, match_kind)`` where match_kind is one of
    "strong" / "cwe_only" / "title_only". Both "strong" and "cwe_only"
    count toward effectiveness-cap math; the renderer surfaces "strong"
    matches first in the example list so a scrambled-CWE yaml does not
    produce confusingly-labelled examples.
    """
    addressed_classes = set((s or "").strip().lower() for s in (cluster_cfg.get("addresses_weakness_classes") or []))
    addressed_cwes = set((s or "").strip().upper() for s in (cluster_cfg.get("addresses_cwes") or []))
    if not addressed_classes and not addressed_cwes:
        return []
    matched: list[tuple[dict, str]] = []
    for t in all_threats:
        kind = _classify_threat_for_strength_cluster(t, cluster_cfg, weakness_vocab)
        if kind == "none":
            continue
        matched.append((t, kind))
    return matched


def _build_strength_clusters(
    controls: list[dict],
    threats_index: dict[str, dict] | None = None,
    all_threats: list[dict] | None = None,
) -> list[dict]:
    """Return ordered list of cluster dicts, each describing one row
    of the §1 Operational Strengths table.

    Cluster dict:
        {
          "id"             : cluster.id,
          "label"          : cluster.label,
          "description"    : 1-line cluster-purpose sentence (from yaml),
          "members"        : list[control_dict] — the constituent controls,
          "effectiveness"  : "adequate" | "partial" | "weak",
          "implementations": ["X (path)", "Y (path)", …]  — compact list,
          "mitigates"      : [{"ref": "T-NNN", "label": …}, …]   union,
          "gap"            : single short gap statement,
          "open_critical_count": int,   # for the contradiction-aware footer
          "open_high_count"    : int,
        }

    Contradiction-aware effectiveness (post-2026-05): a strength cluster
    that names SQL parameterisation as a member CANNOT report Partial
    when the threat catalogue carries 5 open SQL-injection Criticals.
    The renderer now caps each cluster's effectiveness by the open
    Critical/High threats whose CWE/weakness-class falls within the
    cluster's stated defensive remit (`addresses_weakness_classes` +
    `addresses_cwes` in strength-clusters.yaml):

        ≥1 open Critical  →  effectiveness capped at "weak"
        ≥1 open High      →  effectiveness capped at "partial"
        no open H/C       →  effectiveness reads as the member best-of
                              (the pre-2026-05 behaviour)

    The Gap and Mitigates columns are populated deterministically from
    the same threat lookup, so the table always carries (a) the prose
    purpose of the strength, (b) the controls actually present, (c) a
    numeric effectiveness band that is consistent with §8, (d) named
    findings that bypass the cluster, (e) named findings the cluster
    successfully addresses.
    """
    cfg = _load_strength_clusters().get("clusters") or []
    if not cfg:
        return []

    # Preload weakness-class vocab once for the threat-to-cluster bridge.
    weakness_vocab = _load_weakness_classes()
    threats_pool = list(all_threats or [])

    # Group controls by cluster id
    groups: dict[str, list[dict]] = {}
    for c in controls:
        cid = _classify_control_into_cluster(c, cfg)
        groups.setdefault(cid, []).append(c)

    cluster_order = [c["id"] for c in cfg]
    cfg_by_id = {c["id"]: c for c in cfg if c.get("id")}
    rendered: list[dict] = []
    for cid in cluster_order:
        members = groups.get(cid) or []
        if not members:
            continue
        # Effectiveness: best (lowest rank) among non-missing members.
        non_missing = [m for m in members if (m.get("effectiveness") or "").lower() != "missing"]
        if not non_missing:
            # Cluster has only missing controls — skip (those are §7 gaps).
            continue
        best_rank = min(_EFFECTIVENESS_RANK.get((m.get("effectiveness") or "partial").lower(), 9) for m in non_missing)
        eff = next((k for k, v in _EFFECTIVENESS_RANK.items() if v == best_rank), "partial")

        # ---- Contradiction-aware effectiveness cap ----------------------
        # A strength cluster cannot read Partial when the threat catalogue
        # holds open H/C findings of the kind it is supposed to prevent.
        # We treat all findings as "open" (no mitigation status field in
        # the post-Stage-2 yaml) — every threat the cluster addresses is
        # a bypass until a follow-up run records remediation.
        cluster_cfg = cfg_by_id.get(cid, {})
        matched = _threats_for_strength_cluster(cluster_cfg, threats_pool, weakness_vocab)
        # "addressed" for the cap = CWE-confirmed matches only ("strong"
        # or "cwe_only"). title_only matches are NOT used for the cap
        # because they may be unrelated threats whose title happened to
        # mention a keyword (false positive). For the displayed example
        # list we PROMOTE "strong" matches to the front so the reader
        # sees unambiguous examples first.
        addressed_for_cap = [t for (t, kind) in matched if kind in {"strong", "cwe_only"}]
        addressed_critical = [
            t for t in addressed_for_cap if (t.get("risk") or t.get("severity") or "").lower() == "critical"
        ]
        addressed_high = [t for t in addressed_for_cap if (t.get("risk") or t.get("severity") or "").lower() == "high"]
        cap_rank = _EFFECTIVENESS_RANK[eff]
        if addressed_critical:
            cap_rank = max(cap_rank, _EFFECTIVENESS_RANK["weak"])
        elif addressed_high:
            cap_rank = max(cap_rank, _EFFECTIVENESS_RANK["partial"])
        eff = next((k for k, v in _EFFECTIVENESS_RANK.items() if v == cap_rank), "partial")

        # Re-sort the example pool so "strong" (CWE+title agree) examples
        # render first, falling back to cwe_only when the cluster has no
        # strong matches. This keeps the Gap cell readable even when the
        # Stage-1 yaml carries scrambled CWE fields.
        strong_match_ids = {(t.get("id") or t.get("t_id") or "") for (t, kind) in matched if kind == "strong"}

        def _example_sort_key(t: dict) -> tuple[int, str]:
            tid_ = t.get("id") or t.get("t_id") or ""
            return (0 if tid_ in strong_match_ids else 1, tid_)

        addressed_critical = sorted(addressed_critical, key=_example_sort_key)
        addressed_high = sorted(addressed_high, key=_example_sort_key)

        # ---- Compact implementations list -------------------------------
        # The cell lists the control NAMES that make up the cluster — concise
        # and scannable. The free-text implementation detail (library@version,
        # flag soup) is deliberately NOT inlined here: it was unreadable in the
        # cell (multi-clause, mid-token "…" truncation, un-code-formatted tokens
        # — juice-shop 2026-06-29 screenshot). The full per-control
        # implementation lives in §7 control assessment, which the Gap column
        # already points readers to. Names are de-duplicated, order preserved.
        impls: list[str] = []
        for m in non_missing:
            name = m.get("architectural_control") or m.get("canonical_name") or m.get("name") or m.get("control") or "?"
            name = str(name).strip()
            if name and name not in impls:
                impls.append(name)

        # ---- Mitigates: addressed threats - bypassed ones ---------------
        # Pre-2026-05 this used the (often-empty) `mitigates_findings[]`
        # field on each control. We now derive it from the threat catalogue
        # directly: any addressed threat that is NOT in the open H/C
        # bypass list is, by negation, currently held by this strength.
        # That is a stronger statement than the YAML field because it
        # cross-checks against §8 instead of relying on the analyst to
        # populate a back-link.
        bypass_set = {(t.get("id") or t.get("t_id") or "") for t in (addressed_critical + addressed_high)}
        mitigates: list[dict] = []
        for t in addressed_for_cap:
            tid = (t.get("id") or t.get("t_id") or "").strip()
            if not tid or tid in bypass_set:
                continue
            mitigates.append({"ref": tid, "label": (t.get("title") or "").strip()})
        # Cap the displayed list at 5 names; if more are addressed, append
        # a "+N more" suffix so the cell stays scannable.
        mit_overflow = max(0, len(mitigates) - 5)
        mitigates = mitigates[:5]

        # ---- Gap: derive from the bypass list ---------------------------
        if addressed_critical or addressed_high:
            parts: list[str] = []
            if addressed_critical:
                parts.append(f"{len(addressed_critical)} Critical")
            if addressed_high:
                parts.append(f"{len(addressed_high)} High")
            sample_ids = [
                (t.get("id") or t.get("t_id") or "").strip() for t in (addressed_critical + addressed_high)[:3]
            ]
            # Stack the sample links with <br/> (not ", ") so the qa label pass
            # appends each finding's full title + file:line on its OWN line. A
            # comma-join leaves all 3 titles on a single ~250ch line whose
            # max-content dominates markdown-it's auto table layout, starving the
            # "What's in Place" column down to one-word-per-line (juice-shop
            # 2026-06-11 screenshot). `_softwrap_prose_table_cells` cannot rescue
            # it — that pass runs at compose time, before the titles are appended,
            # and skips any cell carrying a `](#` link. Pre-breaking here bounds
            # the cell's per-segment max-content instead.
            sample_links = "<br/>".join(f"[{re.sub(r'^T-', 'F-', s)}](#{s.lower()})" for s in sample_ids if s)
            gap = (
                f"Bypassed by {' + '.join(parts)} finding(s) of the kind this "
                f"cluster is supposed to prevent — e.g.<br/>{sample_links}."
                if sample_links
                else f"Bypassed by {' + '.join(parts)} finding(s) of the kind this cluster is supposed to prevent."
            )
        elif addressed_for_cap:
            gap = (
                f"{len(addressed_for_cap)} medium/low-severity finding(s) within the cluster's "
                f"remit remain open — see §8 Findings Register for details."
            )
        elif eff == "weak":
            gap = (
                "Implementation present but defensive depth not exercised — no "
                "Critical/High in this cluster's remit, so coverage is "
                "untested rather than confirmed."
            )
        elif eff == "partial":
            gap = "Coverage incomplete — see §7 control assessment."
        else:
            gap = "—"

        # ---- Description from yaml template (1-liner) -------------------
        desc_tpl = (cluster_cfg.get("description_template") or "").strip()
        # `{comp_summary}` is the only template var ever used and we don't
        # have a single representative component here, so substitute a
        # bland placeholder. Description is informational only.
        description = desc_tpl.format(comp_summary="this codebase") if desc_tpl else ""

        rendered.append(
            {
                "id": cid,
                "label": cluster_cfg.get("label", cid),
                "description": description,
                "members": non_missing,
                "effectiveness": eff,
                "implementations": impls,
                "mitigates": mitigates,
                "mitigates_overflow": mit_overflow,
                "gap": gap,
                "open_critical_count": len(addressed_critical),
                "open_high_count": len(addressed_high),
            }
        )

    # Sort: best-effectiveness clusters first, then deterministic by definition order
    rendered.sort(key=lambda x: (_EFFECTIVENESS_RANK.get(x["effectiveness"], 9), cluster_order.index(x["id"])))
    return rendered


_SEV_RANK_TBL = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_ICON_TBL = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}
# Priority circles for the §9 Mitigation Register index — mirrors the §8
# severity circles but keys on mitigation PRIORITY (P1 = before deployment …
# P4 = backlog) so the jump-list reflects remediation urgency, not finding
# severity (2026-05-31 user request).
_PRIO_ICON_TBL = {"p1": "🔴", "p2": "🟠", "p3": "🟡", "p4": "🟢"}
# Fill-ramp (2026-07-04 user request, restored): measures are annotated with a
# monochrome circle whose FILL encodes rollout priority as a dark→light gray tone
# (● P1 ship-now, full … ○ P4 backlog, empty). The tonal ramp reads as priority
# at a glance and needs no `P1` text tag. Chosen over the ❶❷❸❹ digit form (Variant
# B, 2026-06-04) which the user reverted. Medium-agnostic: the tone lives in the
# glyph fill, so it survives raw-markdown/GitHub (which strips colour spans) and
# the WeasyPrint PDF alike. All four glyphs are DejaVu-safe (U+25CF/25D5/25D1/25CB,
# verified). The mitigation §9 index (M-NNN) stays distinct from the §8 finding
# dots (🔴🟠🟡🟢) by section + ID prefix.
_PRIO_RAMP_TBL = {"p1": "●", "p2": "◕", "p3": "◑", "p4": "○"}

# §8 / §9 register jump-list helpers. The index lines used to be bare
# `[F-NNN](#f-nnn)` chips with no title or criticality, which is unreadable
# at 48 findings (2026-05-31 user report). Each chip now carries a leading
# severity circle and the short title.
_INDEX_PATH_TAIL_RE = re.compile(r"\s+—\s+(?:[\w.-]+/)*[\w.-]+\.\w+(?::\d+)?\s*$")


def _paragraphize_issue_card(issue_card: str, *, min_chars: int = 300, per_para: int = 2) -> str:
    """Break a long ``**Issue:** …`` narrative into ~``per_para``-sentence
    paragraphs (blank-line separated) so it reads as distinct beats instead of
    one dense block. No-op for short Issues or non-Issue input."""
    prefix = "**Issue:** "
    if not issue_card or not issue_card.startswith(prefix):
        return issue_card
    body = issue_card[len(prefix) :].strip()
    if len(body) <= min_chars:
        return issue_card
    sents = _safe_sentence_split(body)
    if len(sents) <= 2:
        return issue_card
    paras = [" ".join(sents[i : i + per_para]).strip() for i in range(0, len(sents), per_para)]
    paras = [p for p in paras if p]
    return prefix + "\n\n".join(paras)


def _escape_heading_placeholders(title: str) -> str:
    """Escape bare ``<placeholder>`` angle-bracket tokens in a heading title to
    HTML entities so they render literally instead of being parsed as an unknown
    HTML tag and silently dropped — ``#### M-007 — Pin base image to @sha256:``
    lost ``<digest>`` (user report 2026-06-12). Headings stay backtick-free (the
    title-exemption rule), so we escape rather than code-span. ``<br/>`` and any
    real inline HTML tag we emit are left untouched."""
    return re.sub(r"<(?!br\b)([A-Za-z][\w-]*)>", r"&lt;\1&gt;", title or "")


def _index_short_title(title: str, limit: int = 72) -> str:
    """Drop a trailing ` — file[:line]` tail and cap length for a jump-list chip.

    The truncation MUST keep backtick code spans balanced. The chips are joined
    into one `<br/>`-separated block, so a blind ``s[:limit]`` slice that lands
    INSIDE a code span leaves an unclosed backtick that bleeds into every
    following chip — markdown then renders M-018…M-025 as one giant code span
    swallowed by M-017 (the 2026-06-12 juice-shop §10 Mitigations-index break).
    We cut at a word boundary, close any dangling code span, and reduce stray
    `[text](url)` fragments to their visible text first.
    """
    s = _INDEX_PATH_TAIL_RE.sub("", title or "").strip()
    # Reduce markdown links to visible text so a cut never splits `[t](url)`.
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
    # Backtick bare `<placeholder>` tokens (e.g. `@sha256:<digest>`) so the
    # angle-bracket text is not parsed as an (unknown) HTML tag and dropped —
    # M-007 rendered "Pin base image to @sha256:" with `<digest>` silently
    # eaten (user report 2026-06-12). Skip `<br/>` (the chips' own separator).
    s = re.sub(r"(?<!`)<(?!br\b)([a-z][a-z0-9_-]*)>(?!`)", r"`<\1>`", s)
    if len(s) > limit:
        # Prefer a whitespace break point so we never slice mid-word / mid-token.
        cut = s.rfind(" ", 0, limit - 1)
        if cut < limit // 2:
            cut = limit - 1
        s = _close_backticks(s[:cut].rstrip(",; :—–-")) + "…"
    else:
        s = _close_backticks(s)
    return s


def _severity_by_finding_num(threats: list) -> dict:
    """Map finding number (the NNN in F-NNN / T-NNN) → severity key."""
    out: dict[int, str] = {}
    for t in threats or []:
        m = re.search(r"(\d+)$", (t.get("id") or t.get("t_id") or "").strip())
        if m:
            out[int(m.group(1))] = (
                (t.get("effective_severity") or t.get("risk") or t.get("severity") or "low").strip().lower()
            )
    return out


def _build_register_index(
    label: str,
    prefix: str,
    nums: list,
    title_by_num: dict,
    sev_by_num: dict,
    icon_tbl: dict | None = None,
    key_label_tbl: dict | None = None,
    show_icon: bool = True,
) -> str:
    """Render a `**<label>:**<br/>🔴 [P-NNN](#p-nnn) — <title><br/>…` jump list.

    ``icon_tbl`` defaults to the severity-circle table (§8 Findings index);
    pass ``_PRIO_ICON_TBL`` for the §9 Mitigations index so the circle keys
    on remediation priority (p1..p4) instead of finding severity.

    ``key_label_tbl`` (optional) renders an explicit text tag after the circle
    — e.g. ``{"p1": "P1", …}`` so the §9 Mitigations index reads
    ``🔴 P1 · [M-001](#m-001) — …``. Without it the circle is ambiguous with
    the §8 severity palette (both use 🔴/🟠/🟡); the tag disambiguates priority
    from severity at a glance.

    ``show_icon=False`` suppresses the leading colour circle and renders the
    text tag only — used by the §10 Mitigations index where the priority is
    the sole signal and the circle was visual noise (2026-06-02 user request:
    show only the priority, not the coloured circle).
    """
    icon_tbl = icon_tbl if icon_tbl is not None else _SEV_ICON_TBL
    chips = []
    for n in nums:
        key = sev_by_num.get(n, "")
        parts: list[str] = []
        if show_icon:
            parts.append(icon_tbl.get(key, "⚪"))
        if key_label_tbl:
            tag = key_label_tbl.get(key, "")
            if tag:
                parts.append(f"{tag} ·")
        ttl = _index_short_title(title_by_num.get(n, ""))
        link = f"[{prefix}-{n:03d}](#{prefix.lower()}-{n:03d})"
        if ttl:
            link += f" — {ttl}"
        parts.append(link)
        chips.append(" ".join(parts))
    return f"**{label}:**<br/>" + "<br/>".join(chips)


def _measure_prio_prefix(ctx: RenderContext, mid: str) -> str:
    """Fill-ramp priority prefix (`● ` for P1) for a BARE measure chip `[M-NNN]`.

    The full-label form (`[M-NNN](#m-nnn) — title`) gets this prefix from
    `linkify_with_label`; this helper is for the compact bare-chip cells
    (§2 Top-Threats Fix, §7b Requirements Traceability, Top-Findings measures)
    that deliberately omit the title but must still carry the same annotation.
    Returns "" when the priority is unknown (no prefix rather than a bare digit).
    """
    digit = _PRIO_RAMP_TBL.get(ctx.priority_for_ref(mid), "")
    return f"{digit} " if digit else ""


# `_MULTI_MATCH_WARNED` is imported from weakness_classifier at module top so
# the composer and merger share one warned-CWE set (P1). Tests mutate it.


def _classify_threat_cluster(threat: dict, vocab: dict | None = None) -> str:
    """Return the weakness-cluster id for a single threat (CWE-based).

    Delegates to the canonical `weakness_classifier` module (shared with the
    threat merger). First-match-by-file-order wins on an ambiguous CWE, and a
    one-time stderr warning surfaces the routing hazard; the warned-CWE set is
    the module-level `_MULTI_MATCH_WARNED` alias (tests mutate it directly).
    """
    return _wc_classify_threat(threat, vocab)


def _tier_for_cluster(cluster_id: str, fallback_tier: str, vocab: dict | None = None) -> str:
    """Resolve the tier a cluster routes to.

    `cluster.preferred_tier` is one of `client` / `application` / `data` /
    `by_component`. The latter means "use the threat's component-derived
    tier", which the caller passes as `fallback_tier`.
    """
    vocab = vocab or _load_weakness_classes()
    for c in vocab.get("clusters") or []:
        if c.get("id") == cluster_id:
            pt = (c.get("preferred_tier") or "by_component").strip().lower()
            if pt in ("client", "application", "data"):
                return pt
            return fallback_tier or "application"
    return fallback_tier or "application"


def _build_tier_cluster_lines(
    threats: list[dict],
    *,
    max_clusters: int = 4,
    arrow_cwe_allow: set[str] | None = None,
) -> list[str]:
    """Group `threats` by weakness cluster (per data/weakness-classes.yaml)
    and return a list of short Mermaid-safe label lines for one tier box.

    Format (M3.11):
      - N == 1:                       ``<icon> <label>``
      - N >= 2, all same variant:     ``<icon> Multiple <plural_label>``
      - N >= 2, mixed variants:       ``<icon> Multiple <plural_label> (e.g. <first variant>)``

    Threat IDs are NEVER rendered inside a heat-map line — the §8 register
    is one click away if the reader wants the per-finding detail. Variants
    list is capped to ONE representative example to keep the line under
    ~70 chars; the full variant breakdown also lives in §8.

    Excess clusters past `max_clusters` collapse to a single trailer. The
    cap was lowered from 6→4 in 2026-05 so the tier box stays scannable
    and focuses on the highest-criticality threats — the long tail is in
    §8. Sort order remains severity-first, count-desc.
    """
    vocab = _load_weakness_classes()
    clusters_cfg = vocab.get("clusters") or []
    cwe_to_cluster: dict[str, str] = {}
    cluster_meta: dict[str, dict] = {}
    for c in clusters_cfg:
        cid = c.get("id") or ""
        cluster_meta[cid] = c
        for cwe in c.get("cwes") or []:
            cwe_to_cluster[cwe.strip().upper()] = cid

    groups: dict[str, list[dict]] = {}
    for t in threats:
        cwe = (t.get("cwe") or "").strip().upper()
        # Arrow-consistency filter: when the caller supplied the set of
        # CWEs whose attack arrows actually point at *this* tier, skip
        # threats whose CWE is not in that set. Without this filter a
        # bullet can appear in a tier box that has no incoming arrow
        # for that class, producing the inconsistency users reported
        # ("the box says X but no arrow targets X"). When the allow-set
        # is None (legacy / pre-arrow path), the filter is a no-op so
        # the old behaviour is preserved.
        if arrow_cwe_allow is not None and cwe and cwe not in arrow_cwe_allow:
            continue
        cid = cwe_to_cluster.get(cwe, "_unmapped")
        groups.setdefault(cid, []).append(t)

    rendered: list[dict] = []
    for cid, ts in groups.items():
        meta = cluster_meta.get(cid, {})
        label = meta.get("label") or ("Other" if cid == "_unmapped" else cid)
        plural_label = meta.get("plural_label") or (label + "s")
        var_map = meta.get("variants_by_cwe") or {}
        seen_vars: list[str] = []
        for t in ts:
            v = var_map.get((t.get("cwe") or "").strip().upper())
            if v and v not in seen_vars:
                seen_vars.append(v)
        sev_max = min(
            (_SEV_RANK_TBL.get((t.get("risk") or t.get("severity") or "").lower(), 9) for t in ts),
            default=9,
        )
        icon = next((ic for s, ic in _SEV_ICON_TBL.items() if _SEV_RANK_TBL[s] == sev_max), "⚪")
        rendered.append(
            {
                "icon": icon,
                "label": label,
                "plural_label": plural_label,
                "variants": seen_vars,
                "count": len(ts),
                "sev_rank": sev_max,
            }
        )

    # Sort by severity (Critical first), then by count desc.
    rendered.sort(key=lambda x: (x["sev_rank"], -x["count"]))
    visible = rendered[:max_clusters]
    extra_n = sum(c["count"] for c in rendered[max_clusters:])

    lines: list[str] = []
    for c in visible:
        if c["count"] == 1:
            head = f"{c['icon']} {c['label']}"
        else:
            head = f"{c['icon']} Multiple {c['plural_label']}"
            # Add "(e.g. <first variant>)" only when at least 2 distinct
            # variants exist within this cluster's findings. A cluster
            # with all same variant doesn't need the parenthetical hint.
            if len(c["variants"]) >= 2:
                head += f" (e.g. {c['variants'][0]})"
        lines.append(head)
    if extra_n:
        lines.append(f"+{extra_n} more (see §8)")
    return lines


def _bracket_components_for_tier(
    routed_threats: list[dict],
    fallback_comp_ids: list[str],
    *,
    max_comps: int = 3,
) -> list[str]:
    """Return the ordered list of component IDs that should appear in the
    Heat-Map tier-box bracket.

    Sourced from the *routed threats* (not the static `component.tier == key`
    set) so the bracket reflects where the findings actually live. Order:

      1. Threats are walked in input order; their `component`/`component_id`
         is captured in first-seen sequence.
      2. Cap at ``max_comps``; overflow collapses into ``+N more``.
      3. When the routed list is empty (Phase-9 cut-off, hand-edited yaml,
         …), fall back to ``fallback_comp_ids`` — the legacy by-layer set —
         so the bracket is never empty for a non-empty tier.
    """
    seen: list[str] = []
    for t in routed_threats:
        cid = (t.get("component_id") or t.get("component") or "").strip()
        if cid and cid not in seen:
            seen.append(cid)
    if not seen:
        return list(fallback_comp_ids)
    if len(seen) > max_comps:
        return seen[:max_comps] + [f"+{len(seen) - max_comps} more"]
    return seen


def _tier_header_summary(display_name: str, comp_ids: list[str], n_findings: int) -> str:
    """Return the tier header label used by the new cluster-row layout."""
    comp_part = ", ".join(comp_ids) if comp_ids else ""
    return (
        f"{display_name} ({comp_part}) · {n_findings} findings"
        if comp_part
        else f"{display_name} · {n_findings} findings"
    )


def _collapse_open_registration_actors(attack_paths_data: dict) -> None:
    """Fold internet-user and internet-priv-user into internet-anon when
    the app exposes open self-registration. Mutates the dict in place.

    Reason: with `POST /register`-style routes available to anyone, the
    three-tier attacker spectrum (anon / authenticated / privileged) on
    the heatmap implies a reachability ladder that doesn't exist —
    every "authenticated" attack is one HTTP POST away from anonymous.
    The §8 Vektor column keeps its granularity; only the heatmap card
    column and the attack-arrow origins collapse.
    """
    collapse_from = {"internet-user", "internet-priv-user"}

    # 1. Rewrite the top-level `actors` array.
    actors = attack_paths_data.get("actors") or []
    new_actors: list[str] = []
    seen: set[str] = set()
    for slug in actors:
        target = "internet-anon" if slug in collapse_from else slug
        if target not in seen:
            seen.add(target)
            new_actors.append(target)
    # Ensure internet-anon is present whenever any collapse happened
    # (so the heatmap actually has an attacker card to point arrows from).
    if any(s in collapse_from for s in actors) and "internet-anon" not in seen:
        new_actors.insert(0, "internet-anon")
    attack_paths_data["actors"] = new_actors

    # 2. Rewrite each attack-path entry's actor slug.
    for ap in attack_paths_data.get("attack_paths") or []:
        if (ap.get("actor") or "") in collapse_from:
            ap["actor"] = "internet-anon"


def _collapse_public_repo_actors(attack_paths_data: dict) -> None:
    """Fold ``repo-read`` into ``internet-anon`` when the source repository is
    public. Mutates the dict in place.

    Reason: a secret committed to a PUBLIC repo (e.g. a hardcoded signing key)
    is readable by anyone who clones it — there is no privileged "internal
    developer" gate, so a distinct repo-reader actor overstates the access an
    attacker needs. The reader of committed secrets IS the anonymous internet
    attacker. (A malicious *contributor* who opens a pull request to inject
    malicious or insecure code is a different actor, mapped to ``build-time``
    and driven by repo visibility upstream — see recon 7.27a / the
    untrusted-external-contribution supply-chain pattern. That threat is NOT
    folded here: this collapse only touches ``repo-read`` (the secret-reader),
    so the contributor threat survives into the heatmap intact.)
    """
    collapse_from = {"repo-read"}

    actors = attack_paths_data.get("actors") or []
    new_actors: list[str] = []
    seen: set[str] = set()
    for slug in actors:
        target = "internet-anon" if slug in collapse_from else slug
        if target not in seen:
            seen.add(target)
            new_actors.append(target)
    if any(s in collapse_from for s in actors) and "internet-anon" not in seen:
        new_actors.insert(0, "internet-anon")
    attack_paths_data["actors"] = new_actors

    for ap in attack_paths_data.get("attack_paths") or []:
        if (ap.get("actor") or "") in collapse_from:
            ap["actor"] = "internet-anon"


def _build_actor_cards(
    attack_paths_data: dict,
    actor_labels: dict,
    taxonomy: dict | None = None,
    open_user_registration: bool = False,
) -> list[dict]:
    """One card per actor present in attack_paths_data.actors, ordered by
    the ``order:`` list in posture-actor-labels.yaml.

    The ``victim-required`` actor's subtitle is rewritten at composition
    time to enumerate the **actual** victim-targeting attack classes
    present in the heatmap. A report without CSRF findings must not
    claim CSRF coverage in the actor card; the static default subtitle
    is therefore a generic placeholder and the live list overrides it
    when ``taxonomy`` is supplied.

    When ``open_user_registration`` is True, the ``internet-anon`` card's
    subtitle is rewritten to make the collapse explicit ("any user — public
    registration is one POST away"). Callers must run
    ``_collapse_open_registration_actors`` on ``attack_paths_data`` BEFORE
    invoking this function so the upstream slug rewrite has happened.
    """
    actors_dict = actor_labels.get("actors") or {}
    order: list[str] = actor_labels.get("order") or []
    present = set(attack_paths_data.get("actors") or [])
    # Always include any actor referenced by an attack-path entry, even
    # if the top-level `actors` array forgot it.
    for ap in attack_paths_data.get("attack_paths") or []:
        a = ap.get("actor")
        if a:
            present.add(a)

    # Compute the victim-class label list (e.g. ["XSS"], ["XSS", "CSRF"]).
    # We use the short_label from the taxonomy for compactness inside the
    # actor card. When no taxonomy is passed (legacy callers / tests),
    # fall back to the actor's static default_subtitle.
    victim_labels: list[str] = []
    if taxonomy:
        classes_by_id = {c.get("id"): c for c in (taxonomy.get("classes") or [])}
        for ap in attack_paths_data.get("attack_paths") or []:
            actor_slug = (ap.get("actor") or "").lower()
            target = (ap.get("target") or "").lower()
            if actor_slug != "victim-required" and target != "victim":
                continue
            cls = classes_by_id.get(ap.get("class") or "")
            if not cls:
                continue
            label = cls.get("short_label") or cls.get("label") or ap.get("class")
            if label and label not in victim_labels:
                victim_labels.append(label)

    cards: list[dict] = []
    for slug in order:
        if slug not in present:
            continue
        meta = actors_dict.get(slug) or {}
        # Stable, predictable Mermaid node ids:
        if slug == "internet-anon":
            node_id = "ANON"
        elif slug == "victim-required":
            node_id = "SHOPUSER"
        else:
            node_id = slug.upper().replace("-", "_")
        subtitle = meta.get("default_subtitle") or ""
        if slug == "victim-required" and victim_labels:
            joined = " / ".join(victim_labels)
            subtitle = f"legitimate customer; target of {joined}"
        elif slug == "internet-anon" and open_user_registration:
            # Make the collapse explicit so the reader doesn't wonder
            # why there's no "Authenticated User" card despite many
            # findings on auth-required routes.
            subtitle = "any internet user — public registration is one POST away"
        cards.append(
            {
                "id": node_id,
                "slug": slug,
                "label": meta.get("label") or slug,
                "subtitle": subtitle,
                "severity_class": meta.get("severity_class") or "actorAnon",
                "role": meta.get("role") or "attacker",
                "fa_icon": meta.get("fa_icon") or "",
            }
        )
    return cards


def _build_impact_cards(attack_paths_data: dict, impact_taxonomy: dict) -> list[dict]:
    """Pick impacts referenced by any attack-path entry; emit one card per
    impact, in the order defined by business-impact-taxonomy.yaml.
    """
    used: set[str] = set()
    for ap in attack_paths_data.get("attack_paths") or []:
        for imp in ap.get("impact") or []:
            used.add(imp)
    sev_emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
    }
    cards: list[dict] = []
    for imp in impact_taxonomy.get("impacts") or []:
        slug = imp.get("id")
        if slug not in used:
            continue
        sev = (imp.get("severity_default") or "critical").lower()
        emoji = sev_emoji.get(sev, "🔴")
        node_id = (slug or "").upper().replace("-", "_")
        cards.append(
            {
                "node_id": node_id,
                "id": slug,
                "label": f"{emoji} {imp.get('label')}",
                "css_class": "impact",
            }
        )
    return cards


# Compact attack-class label overrides shared by Figure 1 (architecture diagram)
# and Figure 2 (risk-flow heatmap) so both NAME attacks identically. Only
# abbreviate genuinely-long labels, and never to a bare noun ("Secrets" reads as
# a thing, not an attack → keep "Secret Exposure"). Do NOT mutate the taxonomy
# `short_label` itself (other consumers depend on it) — this is render-only.
_POSTURE_LABEL_ABBREV = {
    "Privilege Escalation": "Priv-Esc",
    "Sensitive File & Secret Exposure": "Secret Exposure",
}


def _posture_short_label(name: str) -> str:
    """Render-only compact form of an attack-class label (see _POSTURE_LABEL_ABBREV)."""
    return _POSTURE_LABEL_ABBREV.get((name or "").strip(), name)


def _build_attack_arrows(
    attack_paths_data: dict,
    taxonomy: dict,
    actor_cards: list[dict],
    tier_cards: list[dict],
) -> tuple[list[dict], list[dict]]:
    """One arrow per attack-class entry. Returns (attack_arrows, relay_arrows).

    ``attack_arrows`` — one entry per attack-class, each with a unique glyph.
      * Direct-attack class: src = actor node, dst = tier node.
      * Victim-targeting class (XSS / CSRF — ``target == "victim"`` OR
        ``actor == "victim-required"``): src = attacker node, dst = client tier.
        This is the injection half; the delivery half goes into relay_arrows.

    ``relay_arrows`` — client-tier → victim-actor edges for victim-targeting
      classes. They share the same glyph as their parent attack arrow so they
      visually continue the numbered path, but they are kept separate so
      n_atk counts only unique glyphs. The template renders relay_arrows with
      the same red styling as attack_arrows (linkstyle_attacks covers both).
    """
    glyph_seq = taxonomy.get("glyph_sequence") or ["①", "②", "③", "④", "⑤", "⑥", "⑦"]
    actor_node_by_slug = {a["slug"]: a["id"] for a in actor_cards}
    tier_node_by_key = {t["key"]: t["node_id"] for t in tier_cards}
    classes_by_id = {c["id"]: c for c in (taxonomy.get("classes") or [])}

    # Pick the most-likely "primary attacker" actor for the injection
    # edge of victim-targeting classes. We prefer the most-privileged
    # adversary already present in the diagram so the edge originates
    # at a node the user actually sees.
    attacker_priority = ("internet-anon", "internet-user", "internet-priv-user", "build-time", "repo-read")
    attacker_for_injection: str | None = None
    for slug in attacker_priority:
        if slug in actor_node_by_slug and slug != "victim-required":
            attacker_for_injection = actor_node_by_slug[slug]
            break

    arrows: list[dict] = []
    relay_arrows: list[dict] = []
    for idx, ap in enumerate(attack_paths_data.get("attack_paths") or []):
        if idx >= len(glyph_seq):
            break
        cls = classes_by_id.get(ap.get("class") or "")
        if not cls:
            continue
        short = cls.get("short_label") or cls.get("label") or ap.get("class")
        # Use the taxonomy-reconciled `target` (the directly-attacked ENTRY
        # tier), NOT the LLM `_llm_target` ASSET. A SQL/NoSQL injection names
        # `data` as the compromised asset but ENTERS at the application endpoint
        # — the data layer (no network listener) is reached THROUGH the app, so
        # the arrow lands on SERVER, not a direct attacker arrow into DATA. The
        # data compromise surfaces via the consequence/impact edges instead.
        # (Mirrors Figure 1, which classifies a data-targeted path as a direct
        # application attack unless a data component is itself internet-exposed.)
        target = (ap.get("target") or "application").lower()
        actor_slug = (ap.get("actor") or "internet-anon").lower()
        glyph = glyph_seq[idx]

        # P3 (B2): a class is victim-targeting when EITHER target=="victim"
        # (LLM-authored fragment shape) OR actor=="victim-required" (the
        # deterministic-fallback shape).
        is_victim_targeting = target == "victim" or actor_slug == "victim-required"

        if is_victim_targeting:
            # A victim path can only reach here when a client tier exists —
            # _drop_victim_paths_without_client_tier removed them otherwise.
            client_tier = tier_node_by_key.get("client") or "BROWSER"
            victim = actor_node_by_slug.get("victim-required") or "SHOPUSER"
            # Primary attack arrow: attacker → client tier. This is INDIRECT —
            # the attacker plants a payload the victim's browser later executes
            # (DOM/stored XSS, CSRF). Rendered as a dashed red edge so it is not
            # mislabelled a direct attack against the SPA.
            if attacker_for_injection and attacker_for_injection != victim:
                arrows.append(
                    {
                        "src": attacker_for_injection,
                        "glyph": glyph,
                        "label": short,
                        "dst": client_tier,
                        "indirect": True,
                    }
                )
            # Relay arrow: client tier → victim actor (delivery path).
            # Kept separate so n_atk == number of unique glyphs (no duplicates).
            relay_arrows.append(
                {
                    "src": client_tier,
                    "glyph": glyph,
                    "label": short,
                    "dst": victim,
                }
            )
        else:
            src = actor_node_by_slug.get(actor_slug) or "ANON"
            dst = tier_node_by_key.get(target) or "SERVER"
            arrows.append(
                {
                    "src": src,
                    "glyph": glyph,
                    "label": short,
                    "dst": dst,
                    "indirect": False,
                }
            )

    # Collapse the per-class arrows into ONE grouped arrow per (src, dst,
    # indirect), carrying that actor's glyphs as a bare, space-joined run
    # (e.g. "① ② ③") with no per-class text label. The class names live in the
    # §-narrative bullets and the intro range, keeping the heatmap edges compact.
    # `indirect` is part of the key so a victim-targeting (dashed) edge never
    # merges with a direct (solid) edge that happens to share src+dst.
    glyph_rank = {g: i for i, g in enumerate(glyph_seq)}
    grouped: dict[tuple[str, str, bool], list[str]] = {}
    order: list[tuple[str, str, bool]] = []
    for a in arrows:
        key = (a["src"], a["dst"], bool(a.get("indirect")))
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(a["glyph"])
    grouped_arrows = []
    for src, dst, indirect in order:
        glyphs = sorted(grouped[(src, dst, indirect)], key=lambda g: glyph_rank.get(g, 99))
        stacked = " ".join(glyphs)
        grouped_arrows.append({"src": src, "dst": dst, "glyph": stacked, "label": "", "indirect": indirect})
    # Relay (delivery) arrows keep their class short_label so the client→victim
    # delivery hop stays named (the grouped attack arrow it continues is bare).
    return grouped_arrows, relay_arrows


def _build_consequence_arrows(
    attack_paths_data: dict,
    impact_cards: list[dict],
    tier_cards: list[dict],
) -> list[dict]:
    """Dashed arrow per (source-tier, impact) pair found in attack_paths,
    de-duplicated. Source tier is:

      * ``client`` for victim-targeting classes (XSS, CSRF — flagged by
        either ``target == "victim"`` or ``actor == "victim-required"``;
        P3 — B2 mirrors the dual-form detection in
        ``_build_attack_arrows`` so consequence edges originate from the
        correct tier whether the attack-paths fragment was LLM-authored
        or fallback-derived).
      * ``ap.target`` otherwise.
    """
    impact_by_id = {i["id"]: i for i in impact_cards}
    tier_node_by_key = {t["key"]: t["node_id"] for t in tier_cards}

    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for ap in attack_paths_data.get("attack_paths") or []:
        target = (ap.get("target") or "application").lower()
        actor_slug = (ap.get("actor") or "internet-anon").lower()
        is_victim_targeting = target == "victim" or actor_slug == "victim-required"
        if is_victim_targeting:
            # Victim paths without a client tier were already dropped upstream
            # by _drop_victim_paths_without_client_tier.
            src = tier_node_by_key.get("client") or "BROWSER"
        else:
            src = tier_node_by_key.get(target) or "SERVER"
        for imp_slug in ap.get("impact") or []:
            imp = impact_by_id.get(imp_slug)
            if not imp:
                continue
            pair = (src, imp["node_id"])
            if pair in seen:
                continue
            seen.add(pair)
            pairs.append(pair)
    return [{"src": s, "dst": d} for s, d in pairs]


def _build_alignment_edges(actor_cards: list[dict], tier_cards: list[dict]) -> list[dict]:
    """Cross-subgraph edges that anchor the column headers and pin actor
    rows to their primary tier rows. Always:

      1. ``HDR_A --- HDR_T``
      2. ``HDR_T --- HDR_I``

    Plus, when applicable:

      3. ``victim --- BROWSER`` so XSS/CSRF reverse arrows route along
         the top edge of the diagram.
      4. ``ANON --- SERVER`` so the direct-attack arrows go horizontally
         and never cross the Client Tier rectangle.
    """
    edges: list[dict] = [
        {"src": "HDR_A", "dst": "HDR_T"},
        {"src": "HDR_T", "dst": "HDR_I"},
    ]
    actor_node_by_slug = {a["slug"]: a["id"] for a in actor_cards}
    tier_node_by_key = {t["key"]: t["node_id"] for t in tier_cards}
    if "victim-required" in actor_node_by_slug and "client" in tier_node_by_key:
        edges.append(
            {
                "src": actor_node_by_slug["victim-required"],
                "dst": tier_node_by_key["client"],
            }
        )
    if "internet-anon" in actor_node_by_slug and "application" in tier_node_by_key:
        edges.append(
            {
                "src": actor_node_by_slug["internet-anon"],
                "dst": tier_node_by_key["application"],
            }
        )
    return edges


_FIG1_TIER_ORDER = ["client", "application", "data"]
_FIG1_TIER_LABEL = {
    "client": "Client Tier — browser",
    "application": "Application Tier — Node / Express",
    "data": "Data Tier",
}
# Max component boxes drawn per tier (horizontal-width cap — see R2). A
# flowchart tier is a single horizontal row, so beyond this the figure stretches
# into an unreadable wide strip; the overflow collapses into the per-tier muted
# note (named, with badges → traceability preserved). 6 keeps a typical
# multi-service backend (juice-shop: 6 app boxes) fully drawn while bounding the
# row width — uniform fixed-width boxes (below) are wider than content-sized
# ones, so the cap is the primary lever that keeps a tier from scaling into a
# wide strip.
_FIG1_MAX_TIER_DRAW = 6
# Uniform component-box footprint so every C-NN box is the SAME size regardless
# of label length (user request: all the same size). Fixed width + height + flex
# centering. The height fits the worst case (2-line wrapped name + badge) — the
# box no longer carries a glyph chip, so a compact height never clips.
_FIG1_COMP_BOX_W = "182px"
_FIG1_COMP_BOX_H = "76px"
# Figure-1-specific actor label overrides. Kept as an extension point but
# intentionally empty: the repo-read actor renders as the canonical
# posture-actor-labels label ("Internal Developer"), the same name used by
# the Figure-2 heatmap card and the actor legend, so a single actor never
# appears under two different names across the section.
_FIG1_ACTOR_LABEL: dict[str, str] = {}


def _fig1_node_id(prefix: str, raw: str) -> str:
    """Mermaid-safe node id: ``<PREFIX>_<UPPER_ALNUM>``."""
    core = re.sub(r"[^A-Za-z0-9]+", "_", (raw or "").strip()).strip("_").upper()
    return f"{prefix}_{core}" if core else f"{prefix}_N"


def _fig1_label(text: str) -> str:
    """Escape a string for use inside a quoted Mermaid node/edge label."""
    s = " ".join((text or "").split())
    return s.replace("&", "&amp;").replace('"', "'")


def _figure_basename_for_md(md_name: str) -> str:
    """Derive the Figure 1 SVG filename from the output Markdown name:
    ``threat-model.md`` → ``threat-model.figure1.svg``,
    ``threat-model-juice-shop-quick.md`` → ``threat-model-juice-shop-quick.figure1.svg``.

    Tying the figure to the md stem lets several models share one output
    directory without their figure files colliding.
    """
    return f"{Path(md_name).stem}.figure1.svg"


def _render_figure1_svg(ctx: RenderContext, attack_paths_data: dict, attack_taxonomy: dict) -> str:
    """Build Figure 1 as a deterministic hand-built SVG (the PRIMARY renderer),
    write it next to threat-model.md, and return the image-reference markdown.

    Why SVG instead of the Mermaid builder below: Mermaid/ELK lays each tier out
    as one horizontal row and scatters disconnected nodes, so the figure could
    not wrap a busy tier into a grid and grew unboundedly wide. The SVG generator
    computes the layout itself (top-N grid that grows in height, multi-actor band,
    per-component internet-exposed markers, a straight direct-attack arrow). It
    emits plain primitives (rect/line/circle/text) which GitHub, VS Code and
    WeasyPrint all render natively — so the PDF export needs no Chrome for it.

    ``attack_paths_data`` is already actor-collapsed by the caller (public-repo /
    open-registration), so the SVG attribution matches Figure 2. Returns "" when
    there is nothing to draw or the generator is unavailable — the caller then
    falls back to the Mermaid builder and finally the LLM fragment.
    """
    components = ctx.yaml_data.get("components") or []
    if not components or not (attack_paths_data.get("attack_paths") or []):
        return ""
    try:
        from figure1_svg import build_figure1_svg
    except Exception:  # noqa: BLE001 — missing module must never break the section
        return ""
    actor_labels = (_load_posture_actor_labels() or {}).get("actors") or {}
    svg = build_figure1_svg(
        ctx.yaml_data,
        attack_paths_data,
        attack_taxonomy,
        meta=ctx.yaml_data.get("meta") or {},
        actor_labels=actor_labels,
    )
    if not (svg or "").strip():
        return ""
    # Always write the file (referenced by the published md / consumed by export).
    (ctx.output_dir / ctx.figure_basename).write_text(svg, encoding="utf-8")
    intro = (
        "Architecture tiers top-to-bottom (External Actors → Client → Application → Data) with the "
        "top threats per component. The in-figure legend on the right explains the attack scenarios, "
        "severity dots and symbols."
    )
    # Embed inline when the CLI flag is set OR the skill persisted the choice in
    # .skill-config.json — the latter lets `/create-threat-model --embed-figures`
    # work through the renderer/recompose paths without threading a flag to each.
    embed = bool(getattr(ctx, "embed_figures", False))
    if not embed:
        try:
            _sc = json.loads((ctx.output_dir / ".skill-config.json").read_text(encoding="utf-8"))
            embed = bool(_sc.get("embed_figures"))
        except (OSError, ValueError):
            embed = False
    if embed:
        # Inline as a base64 data URI → self-contained Markdown (renders in
        # VS Code / pandoc / PDF; NOT on GitHub, which strips data: URIs).
        b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
        src = f"data:image/svg+xml;base64,{b64}"
    else:
        src = ctx.figure_basename
    return f"{intro}\n\n![Figure 1 - Architecture & Top Threats]({src})"


def _figure2_basename(ctx: RenderContext) -> str:
    """Figure 2 SVG basename, derived from the Figure 1 basename so both figures
    share the md stem (`<stem>.figure1.svg` → `<stem>.figure2.svg`)."""
    base = ctx.figure_basename or "figure1.svg"
    if ".figure1." in base:
        return base.replace(".figure1.", ".figure2.")
    return "figure2.svg"


def _render_figure2_svg(ctx: RenderContext, diagram_data: dict) -> str:
    """Build Figure 2 (the risk-flow heatmap) as a deterministic hand-built SVG,
    write it next to threat-model.md, and return the image-reference markdown.

    Why SVG instead of the inline Mermaid heatmap: the Mermaid block declares the
    ELK renderer (nested `direction TB` inside three invisible subgraph columns).
    The plugin's PDF pipeline bundles ELK, but common Markdown viewers (GitHub,
    VS Code preview, Obsidian) do NOT — they silently fall back to dagre, which
    cannot honour the nested directions, so the 3-column layout collapses onto one
    flat row with floating arrows. The SVG generator computes the layout itself and
    emits plain primitives that render natively everywhere (mirrors Figure 1).

    Returns "" when the builder yields nothing (missing module, no actor/tier
    cards) — the caller then falls back to the inline Mermaid block.
    """
    try:
        from figure2_svg import build_figure2_svg
    except Exception:  # noqa: BLE001 — missing module must never break the section
        return ""
    try:
        svg = build_figure2_svg(diagram_data)
    except Exception:  # noqa: BLE001 — a builder failure falls back to Mermaid
        return ""
    if not (svg or "").strip():
        return ""
    basename = _figure2_basename(ctx)
    (ctx.output_dir / basename).write_text(svg, encoding="utf-8")
    # Embed logic mirrors Figure 1: inline as a base64 data URI when the skill
    # persisted `embed_figures` (self-contained md), else a plain relative ref.
    embed = bool(getattr(ctx, "embed_figures", False))
    if not embed:
        try:
            _sc = json.loads((ctx.output_dir / ".skill-config.json").read_text(encoding="utf-8"))
            embed = bool(_sc.get("embed_figures"))
        except (OSError, ValueError):
            embed = False
    if embed:
        b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
        src = f"data:image/svg+xml;base64,{b64}"
    else:
        src = basename
    return f"![Figure 2 - Risk Flow: Actor to Tier to Impact]({src})"


def _render_top_threats_architecture(ctx: RenderContext, attack_paths_data: dict, attack_taxonomy: dict) -> str:
    """Deterministically build **Figure 1 — Architecture & Top Threats**
    from ``threat-model.yaml`` + the *already-reconciled*
    ``attack_paths_data``.

    Layout: a ``flowchart TB`` with an actor band on top, then one subgraph
    per architecture tier (Client / Application / Data), each holding its
    ``C-NN`` components.

    RULES (enforced by construction — keep them; they are why the diagram is
    both structured and technically correct):

    Technical correctness
      T1. Every SOLID red edge originates at an ACTOR node. Built only via
          ``_add(attack_glyphs, actor_nid, …)`` where ``actor_nid`` always comes
          from ``_actor()`` → no component can ever be the source of an attack.
      T2. An attack class lands a SOLID edge on every DRAWN component in its
          TARGET TIER that actually hosts one of the class's findings — directly
          exposed APIs (file upload, B2B) are attacked directly, so each gets
          its own actor⇒component edge rather than one arrow collapsed onto the
          tier representative. Restricting hosts to the class's TARGET TIER is
          what prevents the historic "privilege-escalation ⇒ SPA" mis-draw (a
          client-tier finding of an application-target class does not pull the
          arrow into the client tier). Glyphs merge per (actor, component) pair
          (P2), so a component hit by several classes shows ONE edge carrying
          all their glyphs — no parallel-edge clutter. Falls back to the target
          tier's representative when the class has no drawn finding-host there.
      T3. No direct actor⇒data edge. Reaching the data tier is shown as a
          DOTTED propagation edge ``app rep ··> data rep`` (fires when the class
          targets data OR has any data-tier finding).
      T4. DOTTED ``client ··> Shop User`` (victim) only for victim-targeting
          (XSS/CSRF) classes — never for a class that merely has a client-tier
          finding (e.g. a client-side authz bypass).
      T5. Glyph assignment (① ② … ⑦) is positional over the same
          ``attack_paths`` order that drives Figure 2 and the Top Threats table,
          so the numbering agrees across all three.

    Presentation
      P1. Tiers stack top→down: Actors → Client → Application → Data.
      P2. At most ONE solid edge per (actor, component) pair — all glyphs going
          that way are merged into a single glyph-only label ("① ② ④ ⑤"),
          exactly like Figure 2. Never two parallel edges between a node pair
          (this is what keeps it from looking cluttered / overlapping).
      P3. At most ONE dotted edge per (component, target) pair — glyphs merged.
      P4. Solid red = attack; dotted red = propagation; grey = benign backbone.
      P5. Each component box carries a 🔴/🟠 finding-count badge; actors are
          red (attacker) / green (legitimate user-victim), all annotated.
      P6. Data is the bottom sink band, never a right-hand peer column. Every
          visible application node is connected to the data representative by a
          real App→Data edge or an invisible balancing edge, so ELK keeps the
          data tier centered under a wide application row.

    Returns an empty string when there is nothing to draw (no components or no
    attack paths).
    """
    components = ctx.yaml_data.get("components") or []
    threats = ctx.yaml_data.get("threats") or []
    attack_paths = attack_paths_data.get("attack_paths") or []
    if not components or not attack_paths:
        return ""

    glyph_seq = attack_taxonomy.get("glyph_sequence") or ["①", "②", "③", "④", "⑤", "⑥", "⑦"]
    cls_by_id = {c.get("id"): c for c in (attack_taxonomy.get("classes") or []) if isinstance(c, dict)}
    actor_labels = (_load_posture_actor_labels() or {}).get("actors") or {}

    # Actor collapse: when self-registration is open, an "authenticated" internet
    # attacker is one trivial POST away from an account, so it is not meaningfully
    # distinct from the anonymous attacker. Fold internet-user / internet-priv-user
    # into internet-anon and annotate the merged node. Driven by
    # meta.open_user_registration (set by detect_open_registration.py). Same
    # principle the Figure-2 heatmap uses, applied here so both figures agree.
    collapse_authed = bool((ctx.yaml_data.get("meta") or {}).get("open_user_registration"))
    _COLLAPSIBLE_AUTHED = {"internet-user", "internet-priv-user"}

    def _collapse_slug(slug: str) -> str:
        if collapse_authed and (slug or "").strip() in _COLLAPSIBLE_AUTHED:
            return "internet-anon"
        return slug

    # Threat count per component, taken from the threat list (the optional
    # ``threat_ids`` array is not always populated). Drives the representative
    # pick and the "omit clean components" filter below.
    comp_threat_count: dict[str, int] = {}
    comp_sev_count: dict[str, dict[str, int]] = {}
    for t in threats:
        if not isinstance(t, dict):
            continue
        comp = (t.get("component") or t.get("component_id") or "").strip()
        if comp:
            comp_threat_count[comp] = comp_threat_count.get(comp, 0) + 1
            sev = (t.get("risk") or t.get("severity") or t.get("impact") or "").strip().title()
            if sev in ("Critical", "High"):
                d = comp_sev_count.setdefault(comp, {"Critical": 0, "High": 0})
                d[sev] += 1

    # Component bookkeeping: canonical C-NN by the FULL component-array order
    # (so the numbering is stable), mermaid node id, tier. ALL components are
    # shown so the architecture is complete (2026-05-30 user request — several
    # application-tier components, e.g. file-upload / B2B, were being dropped).
    # A component with no findings simply renders as a box with no badge and no
    # attack edge — it is part of the architecture, just not (yet) a threat host.
    comp_node: dict[str, str] = {}
    comp_name_disp: dict[str, str] = {}
    comp_pure_name: dict[str, str] = {}
    comp_tier: dict[str, str] = {}
    comp_cnum: dict[str, str] = {}
    for idx, c in enumerate(components, start=1):
        cid = (c.get("id") or "").strip()
        if not cid:
            continue
        comp_cnum[cid] = f"C-{idx:02d}"
        tier = (c.get("tier") or "application").strip().lower()
        if tier not in _FIG1_TIER_ORDER:
            tier = "application"
        comp_node[cid] = _fig1_node_id("CMP", cid)
        # Display name ("C-01 · Angular SPA"); the 🔴/🟠 finding-count badge is
        # computed at emit time from comp_sev_count so the box can omit it cleanly
        # when there is none (boxes are content-sized, no uniform footprint).
        comp_name_disp[cid] = f"C-{idx:02d} · {_fig1_label(c.get('name') or cid)}"
        comp_pure_name[cid] = f"C-{idx:02d} {_fig1_label(c.get('name') or cid)}"
        comp_tier[cid] = tier
    if not comp_node:
        return ""
    comp_order = {cid: i for i, cid in enumerate(comp_node)}

    # finding-id (F-NNN/T-NNN, both aliases) → component id.
    fid_component: dict[str, str] = {}
    for t in threats:
        if not isinstance(t, dict):
            continue
        comp = (t.get("component") or "").strip()
        if not comp:
            continue
        keys: set[str] = set()
        for kn in ("id", "t_id", "original_id"):
            v = (t.get(kn) or "").strip().upper()
            if v.startswith(("F-", "T-")):
                keys.add(v)
        for v in list(keys):
            m = re.match(r"^[FT]-(\d+)$", v)
            if m:
                keys.add(f"F-{m.group(1)}")
                keys.add(f"T-{m.group(1)}")
        for k in keys:
            fid_component.setdefault(k, comp)

    # Actor nodes (created on demand, deduped).
    actor_node: dict[str, str] = {}
    actor_label: dict[str, str] = {}

    def _actor(slug: str) -> str:
        slug = (slug or "internet-anon").strip()
        if slug not in actor_node:
            meta = actor_labels.get(slug) or {}
            fa = meta.get("fa_icon") or "fa:fa-user-secret"
            lbl = _FIG1_ACTOR_LABEL.get(slug) or meta.get("label") or slug
            sub = meta.get("default_subtitle") or ""
            if collapse_authed and slug == "internet-anon":
                # The authenticated / privileged attacker folds into this node.
                sub = "incl. self-registered users — open registration makes authenticated ≈ anonymous"
            actor_node[slug] = _fig1_node_id("ACT", slug)
            txt = f"{fa} {_fig1_label(lbl)}"
            if sub:
                txt += f"<br/><i>{_fig1_label(sub)}</i>"
            actor_label[slug] = txt
        return actor_node[slug]

    client_comps = [cid for cid in comp_node if comp_tier[cid] == "client"]
    app_comps = [cid for cid in comp_node if comp_tier[cid] == "application"]
    data_comps = [cid for cid in comp_node if comp_tier[cid] == "data"]

    def _rep(cids: list[str]) -> str | None:
        if not cids:
            return None
        return sorted(cids, key=lambda cid: (-comp_threat_count.get(cid, 0), comp_order[cid]))[0]

    rep_app = _rep(app_comps)
    rep_client = _rep(client_comps)
    rep_data = _rep(data_comps)

    def _has_hi_badge(cid: str) -> bool:
        s = comp_sev_count.get(cid) or {}
        return bool(s.get("Critical") or s.get("High"))

    # R1 — Complexity budget (size-independent legibility). This is the
    # *Top-Threats* figure, not the full architecture inventory (that lives in
    # §2). Drawing every Critical/High component made the figure scale its box +
    # edge count with the model and become unreadable on large models (the
    # accumulated "show all components" heuristic). Instead we draw ONLY the
    # components that actually host a finding of one of the budgeted (top-N,
    # glyph-bearing) attack classes — i.e. the hosts the figure is about — plus
    # each tier's representative (reps anchor the backbone / propagation edges).
    # Everything else collapses into one muted "also assessed" note per tier.
    # Result: drawn-box count tracks the number of TOP THREATS, not the repo
    # size, so the figure stays legible whether the model has 3 or 30 components.
    budgeted_hosts: set[str] = set()
    comp_attack_count: dict[str, int] = {}
    for _ap in attack_paths[: len(glyph_seq)]:
        _hit: set[str] = set()
        for _f in _ap.get("findings") or []:
            _c = fid_component.get((_f or "").upper())
            if _c:
                budgeted_hosts.add(_c)
                _hit.add(_c)
        for _c in _hit:
            comp_attack_count[_c] = comp_attack_count.get(_c, 0) + 1
    _drawn: set[str] = {cid for cid in comp_node if cid in budgeted_hosts}
    for _r in (rep_app, rep_client, rep_data):
        if _r:
            _drawn.add(_r)

    # R2 — per-tier width cap (horizontal-scaling control). The complexity
    # budget (R1) bounds the figure to top-threat hosts, but a genuinely complex
    # app can still have many attacked components in ONE tier — and a flowchart
    # tier is a single horizontal row, so >~7 boxes stretch the figure into an
    # unreadable wide landscape strip. We therefore draw at most
    # ``_FIG1_MAX_TIER_DRAW`` boxes per tier (the most-attacked / most-severe,
    # ranked deterministically), and collapse the overflow into the per-tier
    # muted note — which NAMES them (with their 🔴/🟠 badge), so traceability is
    # preserved: the reader sees every attacked component, just not as a box in
    # an unreadable row. The tier representative is never capped (it anchors the
    # backbone/propagation edges); edges to a capped host fall back onto the
    # tier rep via the existing T2 host-not-drawn path.
    def _draw_rank(cid: str) -> tuple:
        sev = comp_sev_count.get(cid) or {}
        return (
            comp_attack_count.get(cid, 0),
            sev.get("Critical", 0),
            sev.get("High", 0),
            comp_threat_count.get(cid, 0),
            -comp_order[cid],
        )

    _reps = {rep_client, rep_app, rep_data}
    for _tier in _FIG1_TIER_ORDER:
        _tier_drawn = [cid for cid in _drawn if comp_tier[cid] == _tier]
        if len(_tier_drawn) <= _FIG1_MAX_TIER_DRAW:
            continue
        _keep = set(sorted(_tier_drawn, key=_draw_rank, reverse=True)[:_FIG1_MAX_TIER_DRAW])
        _keep |= {r for r in _reps if r and comp_tier.get(r) == _tier}
        for cid in _tier_drawn:
            if cid not in _keep:
                _drawn.discard(cid)

    def _target_tier(ap: dict, cls: dict) -> str:
        # Route by the IMPACT tier (the LLM's original target — where the attack
        # lands: injection ⇒ data) so Figure 1 distributes threats across the
        # components they hit, rather than the reconciled control tier (which
        # would pile every application-control failure onto one box). The victim
        # pseudo-tier is delivered through the client tier.
        tt = (
            (ap.get("_llm_target") or ap.get("target") or cls.get("default_target_tier") or "application")
            .strip()
            .lower()
        )
        if tt == "victim":
            tt = "client"
        return tt if tt in _FIG1_TIER_ORDER else "application"

    # Attacker flows use TWO edge styles so the diagram reads correctly:
    #   * SOLID red (==>)  — the attack itself. ALWAYS originates at a threat
    #     ACTOR and lands on the app/client component the attacker directly
    #     reaches. No component⇒component solid edge ever exists (that would read
    #     as "the API attacks the DB", which is wrong — components do not attack).
    #   * DOTTED red (-.->) — the consequence/propagation path. From the hit
    #     component onward to where the attack ultimately lands: into the DATA
    #     tier (injection reaches the DB THROUGH the app tier) or onto the VICTIM
    #     (Shop User) for XSS/CSRF. Dotted = "the attack continues here", not a
    #     fresh attack launched by the component. We still never draw a direct
    #     actor⇒data edge — data is always reached via the application tier.
    # Each red edge is labelled "<glyph> <short class name>" (e.g. "① Injection").
    # Attacker flows are collected as glyph LISTS keyed by edge, so that many
    # classes sharing one (source → target) render as a SINGLE edge labelled
    # with all their glyphs (e.g. "① ② ④ ⑤") — exactly like Figure 2. This is
    # the rule that keeps the diagram structured: never two parallel edges
    # between the same pair of nodes.
    #   attack_glyphs[(actor, comp)] → SOLID red  (the attack; src is ALWAYS an actor)
    #   prop_glyphs[(comp, target)]  → DOTTED red (propagation onto data tier / victim)
    attack_glyphs: dict[tuple[str, str], list[str]] = {}
    prop_glyphs: dict[tuple[str, str], list[str]] = {}
    victim_present = False
    victim_props: list[tuple[str, str]] = []  # (client node, glyph) → dotted ··> Shop User
    # Per-actor colour-coding (user request: attacks must clearly map to an
    # actor). Each malicious actor gets a colour used by its attack
    # arrows + its legend entry, so any attack traces to its actor by colour.
    # One attacker → one colour (juice-shop); more → distinct colours.
    actor_order: list[str] = []  # malicious actor slugs in first-seen order

    def _add(bucket: dict[tuple[str, str], list[str]], src: str, dst: str, glyph: str) -> None:
        if src and dst and src != dst:
            lst = bucket.setdefault((src, dst), [])
            if glyph not in lst:
                lst.append(glyph)

    for idx, ap in enumerate(attack_paths):
        if idx >= len(glyph_seq):
            break
        glyph = glyph_seq[idx]
        slug = (ap.get("class") or "").strip()
        cls = cls_by_id.get(slug) or {}
        actor_slug = _collapse_slug((ap.get("actor") or cls.get("default_actor") or "internet-anon").strip())
        if actor_slug == "victim-required":
            actor_slug = "internet-anon"
        actor_nid = _actor(actor_slug)
        if actor_slug not in actor_order:
            actor_order.append(actor_slug)
        tt = _target_tier(ap, cls)
        if tt in ("client", "victim"):
            victim_present = True

        # Which components do this class's findings actually touch? (used only
        # to decide whether a data-tier propagation edge is warranted).
        touches_data = any(
            comp_tier.get(fid_component.get((f or "").upper())) == "data" for f in (ap.get("findings") or [])
        )

        # T2 — SOLID targets = the DRAWN components in the class's TARGET TIER
        # that actually host one of this class's findings. Directly-exposed APIs
        # (file upload, B2B) are reached and attacked directly by the attacker,
        # so each gets its OWN solid actor⇒component edge — not one arrow
        # collapsed onto the tier representative. Restricting to the target tier
        # keeps a client-tier finding of an application-target class from pulling
        # the arrow into the client tier (the old "priv-esc ⇒ SPA" mis-draw).
        # Glyphs merge per (actor, component) pair (P2 / _add dedup), so a
        # component hit by several classes renders ONE edge with all glyphs.
        target_tier_name = "client" if tt in ("client", "victim") else "application"
        host_comps: list[str] = []
        for f in ap.get("findings") or []:
            c = fid_component.get((f or "").upper())
            if c and c in _drawn and comp_tier.get(c) == target_tier_name and c not in host_comps:
                host_comps.append(c)
        if not host_comps:
            # No drawn finding-host in the target tier → fall back to that tier's
            # representative so the class still shows a solid edge.
            _rep_fallback = rep_client if target_tier_name == "client" else rep_app
            _rep_fallback = _rep_fallback or rep_app or rep_client or next(iter(comp_node), None)
            if _rep_fallback:
                host_comps = [_rep_fallback]
        for _hc in host_comps:
            _add(attack_glyphs, actor_nid, comp_node[_hc], glyph)  # T1: src is an actor

        # T3 — dotted propagation into the data tier when the class reaches data
        # (declared data target OR a data-tier finding), drawn app rep ··> data rep.
        if (tt == "data" or touches_data) and rep_app and rep_data:
            _add(prop_glyphs, comp_node[rep_app], comp_node[rep_data], glyph)

        # T4 — dotted propagation onto the victim, ONLY for victim-targeting
        # (XSS/CSRF) classes (deferred until user_node is resolved below).
        if tt in ("client", "victim"):
            # Prefer the client representative. If a repo has no explicit
            # client-tier component, fall back to the application/data rep so a
            # victim-targeting class still renders a valid propagation edge
            # instead of crashing on an undefined placeholder.
            fallback_cid = rep_client or rep_app or rep_data or next(iter(comp_node), None)
            vsrc = comp_node.get(fallback_cid) if fallback_cid else None
            if vsrc:
                victim_props.append((vsrc, glyph))

    # Canonical glyph order (positional) — used to sort glyphs on the box chips
    # and on the victim node so the numbering reads ① ② ④ consistently.
    _glyph_pos = {g: i for i, g in enumerate(glyph_seq)}

    # Per-actor colour palette (deterministic by first-seen actor order). The
    # first/most-common attacker keeps the canonical attack-red so a single-actor
    # figure is unchanged; additional actors take distinct, accessible hues.
    _ACTOR_PALETTE = ["#b71c1c", "#1d4ed8", "#7c3aed", "#b45309", "#0f766e"]
    actor_color: dict[str, str] = {slug: _ACTOR_PALETTE[i % len(_ACTOR_PALETTE)] for i, slug in enumerate(actor_order)}

    # Attack classes are now NAMED directly on their (solid) actor⇒component
    # edges (e.g. "① Injection"), so the diagram is self-explanatory without a
    # decoder legend and the boxes no longer carry a glyph chip (2026-06-14 user
    # request — self-explanatory, without opening a table). The box stays a
    # plain name + 🔴/🟠 finding-count badge.

    # Grey legitimate-flow backbone (tier-ordered; corroborated by
    # trust_boundaries). The legitimate user IS the Shop User when a
    # victim-targeting class is present (same persona), so the node is
    # labelled accordingly and described in the actor legend below.
    user_node = "EXT_SHOPUSER" if victim_present else "EXT_USER"
    # Victim consequence is drawn as an explicit dotted edge from the client
    # component the malicious content is served through ONTO the Shop User
    # (2026-06-14 user request — "es fehlt ein Pfeil auf den Shop User der die
    # Angriffe gegen ihn zeigt"). The edge carries the victim-targeting class
    # name(s) so it reads on its own. It is emitted further below, once the
    # client representative node id is known.
    _victim_glyphs: list[str] = []
    for _cnode, _g in victim_props:
        if _g not in _victim_glyphs:
            _victim_glyphs.append(_g)
    _victim_glyphs.sort(key=lambda g: _glyph_pos.get(g, 99))
    if victim_present:
        user_label = "fa:fa-user Shop User<br/><i>legitimate customer · attack victim</i>"
    else:
        user_label = "fa:fa-user Legitimate User"
    # Only finding-bearing (drawn) components participate in the backbone; edges
    # to collapsed components are skipped (their node is never declared).
    _client_drawn = [cid for cid in client_comps if cid in _drawn]
    _data_drawn = [cid for cid in data_comps if cid in _drawn]
    benign_edges: list[tuple[str, str, str]] = []
    if _client_drawn:
        for cid in _client_drawn:
            benign_edges.append((user_node, comp_node[cid], " uses "))
        if rep_app:
            for cid in _client_drawn:
                benign_edges.append((comp_node[cid], comp_node[rep_app], " API calls "))
    elif rep_app:
        benign_edges.append((user_node, comp_node[rep_app], " uses "))
    if rep_app:
        for cid in _data_drawn:
            benign_edges.append((comp_node[rep_app], comp_node[cid], " reads/writes "))
    # Application-tier connectivity fallback. With T2 routing solid attack edges
    # to the actual finding-host components, a directly-attacked API (file
    # upload, B2B) now carries its own RED edge and needs no grey edge. But a
    # drawn app component that received NO solid attack edge (e.g. a sub-service
    # whose findings did not surface as a top attack class) would otherwise be an
    # orphan box. Wire only those from the rep with a grey backbone edge so every
    # drawn component has ≥1 edge — without drawing a misleading "internal
    # sub-service" grey edge onto a component the attacker actually hits directly.
    _attacked_nodes = {dst for (_src, dst) in attack_glyphs}
    if rep_app:
        for cid in app_comps:
            if cid in _drawn and cid != rep_app and comp_node[cid] not in _attacked_nodes:
                benign_edges.append((comp_node[rep_app], comp_node[cid], " routes to "))

    # ---- Emit the Mermaid block -------------------------------------------
    # Use the ELK layered renderer (same as Figure 2): its crossing-minimisation
    # routes the actor→tier and propagation edges with far fewer edge/box
    # crossings than the default dagre renderer (2026-05-30 request — arrows
    # should, where possible, not cross other boxes/arrows). ELK also
    # aligns same-rank nodes (the actor row, each tier's components) on one line.
    # NB Mermaid flowchart has no fixed node-width — box widths stay content-
    # driven; ELK only equalises their row placement, not their pixel size.
    lines: list[str] = [
        "```mermaid",
        # padding: internal label padding inside every node box (default 8) so
        #   the C-NN labels + badge line are not flush against the box border.
        # subGraphTitleMargin: small breathing room above/below each tier title
        #   ("Application Tier — Node / Express" etc.) so the cluster heading is
        #   not clamped against the subgraph border (2026-06-02 user request).
        '%%{init: {"flowchart": {"defaultRenderer": "elk", "curve": "basis", "nodeSpacing": 55, "rankSpacing": 78, "padding": 16, "subGraphTitleMargin": {"top": 22, "bottom": 10}}} }%%',
        "flowchart TB",
    ]
    # External actors are grouped into their OWN band (a subgraph, like every
    # architecture tier below) and laid out left-to-right so all actors sit on
    # one row at the same height. This replaces the loose top-level actor nodes,
    # which dagre ranked at different heights and rendered as a cramped, uneven
    # top edge (2026-05-30 request for a uniform, professional structure).
    actor_emit: list[str] = []
    if benign_edges:
        # The legitimate user / victim is a GOOD actor → green (2026-05-30).
        actor_emit.append(f'        {user_node}["{user_label}"]:::actorgood')
    for slug, nid in actor_node.items():
        # Colour malicious actors red, benign actors green by their catalogued
        # role (attacker → red; victim/legitimate → green).
        role = ((actor_labels.get(slug) or {}).get("role") or "attacker").strip().lower()
        cls = "actorgood" if role in ("victim", "legitimate", "user", "good") else "actorbad"
        actor_emit.append(f'        {nid}["{actor_label[slug]}"]:::{cls}')
    if actor_emit:
        lines.append('    subgraph ZONE_ACTORS["External Actors — Internet (untrusted)"]')
        lines.append("        direction LR")
        lines.extend(actor_emit)
        lines.append("    end")
    lines.append("")
    for tier in _FIG1_TIER_ORDER:
        tier_cids = [cid for cid in comp_node if comp_tier[cid] == tier]
        if not tier_cids:
            continue
        tier_drawn = [cid for cid in tier_cids if cid in _drawn]
        tier_hidden = [cid for cid in tier_cids if cid not in _drawn]
        if not tier_drawn and not tier_hidden:
            continue

        # R6 — deterministic intra-tier ordering: declare the most-attacked
        # components toward the CENTRE of the row (busiest in the middle, calmer
        # boxes at the edges). ELK lays a layer out roughly in declaration order,
        # so a center-out arrangement keeps the dominant attacker's edges short
        # and bundled instead of fanning diagonally across the whole row. Pure
        # function of (attack-class count, severity, stable order) → reproducible.
        def _attack_rank(cid: str) -> tuple:
            sev = comp_sev_count.get(cid) or {}
            return (comp_attack_count.get(cid, 0), sev.get("Critical", 0), sev.get("High", 0), -comp_order[cid])

        _ranked = sorted(tier_drawn, key=_attack_rank, reverse=True)
        sg = {"client": "CLIENT", "application": "APP", "data": "DATA"}[tier]
        # center-out: highest rank in the middle, next ones alternating outward
        # to the right then left, so the busiest box ends up centred. (A true
        # multi-ROW grid is not reproducible here: every app box is one hop from
        # the attacker, so ELK's layered ranking puts them all on one level and
        # ignores nested row-subgraphs; forcing rows needs invisible vertical
        # edges that produce long crossing diagonals — see the 2026-06-14 note.)
        from collections import deque

        _dq: deque[str] = deque()
        for _i, _cid in enumerate(_ranked):
            if _i % 2 == 0:
                _dq.append(_cid)
            else:
                _dq.appendleft(_cid)
        tier_drawn = list(_dq)

        def _box_line(cid: str) -> str:
            # Uniform-footprint box: fixed width + height + flex centering so all
            # C-NN boxes share one size regardless of label length (user request:
            # all the same size). The height fits the worst case (2-line wrapped name +
            # badge); content always fits and flex-centres, so nothing overflows
            # the border now that the box no longer carries a glyph chip.
            _sev = comp_sev_count.get(cid) or {}
            _badge = " ".join(
                p
                for p in (
                    f"🔴 {_sev['Critical']}" if _sev.get("Critical") else "",
                    f"🟠 {_sev['High']}" if _sev.get("High") else "",
                )
                if p
            )
            _badge_line = f"<br/><i>{_badge}</i>" if _badge else ""
            _box = (
                f"<div style='width:{_FIG1_COMP_BOX_W};height:{_FIG1_COMP_BOX_H};"
                f"box-sizing:border-box;display:flex;flex-direction:column;"
                f"justify-content:center;align-items:center;text-align:center;"
                f"white-space:normal;overflow-wrap:break-word'>"
                f"{comp_name_disp[cid]}{_badge_line}</div>"
            )
            return f'        {comp_node[cid]}["{_box}"]:::comp'

        # Prominent tier band — BOLD title (the trailing blank line reserves room
        # for the title so the first row sits below it, not under it).
        lines.append(f'    subgraph {sg}["<b>{_fig1_label(_FIG1_TIER_LABEL[tier])}</b><br/>&nbsp;"]')
        for cid in tier_drawn:
            lines.append(_box_line(cid))
        # Collapse no-finding components into ONE muted note node (2026-05-31)
        # so the tier acknowledges them without a box each. Never edge-linked.
        if tier_hidden:
            # Name the muted components (not just C-NN) so the reader knows
            # they were ASSESSED — just carried no Critical/High finding —
            # rather than skipped (2026-05-31 user request). The compmuted
            # classDef carries a reduced font-size so the legend never
            # competes visually with the real component boxes. Stack with
            # <br/> when more than one so a long tier list stays narrow.
            #
            # Two kinds of hidden component land here: (a) ones carrying a
            # Critical/High finding (either a budgeted top-threat host collapsed
            # by the R2 width cap, or a High finding that simply did not make the
            # top-N attack paths) and (b) genuinely low-signal ones with no
            # Critical/High finding. They get DIFFERENT note lines so the reader
            # is never told a Critical/High component "has no Critical/High
            # finding". The Crit/High ones keep their 🔴/🟠 badge + a "see §8
            # Register" pointer → full traceability without widening the row.
            def _badge_for(cid: str) -> str:
                s = comp_sev_count.get(cid) or {}
                b = " ".join(
                    p
                    for p in (
                        f"🔴 {s['Critical']}" if s.get("Critical") else "",
                        f"🟠 {s['High']}" if s.get("High") else "",
                    )
                    if p
                )
                nm = comp_pure_name.get(cid, comp_cnum.get(cid, "C-??"))
                return f"{nm} {b}".strip()

            _withfinding = [cid for cid in tier_hidden if _has_hi_badge(cid)]
            _clean = [cid for cid in tier_hidden if cid not in _withfinding]
            _segs: list[str] = []
            if _withfinding:
                _segs.append(
                    "Also assessed — Critical/High finding in §8 Register:<br/>"
                    + "<br/>".join(_badge_for(cid) for cid in _withfinding)
                )
            if _clean:
                _segs.append(
                    "Also assessed — no Critical/High finding:<br/>"
                    + "<br/>".join(comp_pure_name.get(cid, comp_cnum.get(cid, "C-??")) for cid in _clean)
                )
            _note = "<br/>".join(_segs)
            lines.append(f'        {sg}_OMITTED["{_fig1_label(_note)}"]:::compmuted')
        lines.append("    end")
    lines.append("")

    # Glyph → compact class-name map (positional order). Each attack class is
    # NAMED ONCE — on its (solid) actor-originated edge — and referenced by bare
    # number everywhere else (dotted propagation edges). Names use the shared
    # _posture_short_label() so Figure 1 and Figure 2 abbreviate identically.
    glyph_name: dict[str, str] = {}
    for i, ap in enumerate(attack_paths):
        if i >= len(glyph_seq):
            break
        c = cls_by_id.get((ap.get("class") or "").strip()) or {}
        nm = c.get("short_label") or c.get("label") or (ap.get("class") or "attack")
        glyph_name[glyph_seq[i]] = _fig1_label(_posture_short_label(nm))

    # Trust-boundary lookup (2026-06-14 user request — "trust boundaries
    # einbauen"). Map each yaml trust_boundaries[] entry (from→to component, or
    # "external") to the tier-pair it separates, so the grey backbone edge that
    # crosses it can carry a 🛡 marker + the boundary's short name. Real data.
    _node_to_tier = {comp_node[cid]: comp_tier[cid] for cid in comp_node}

    def _tier_of(node: str) -> str:
        return _node_to_tier.get(node, "external")

    _tb_name: dict[tuple[str, str], str] = {}
    for _tb in ctx.yaml_data.get("trust_boundaries") or []:
        if not isinstance(_tb, dict):
            continue
        _frm = (_tb.get("from") or "").strip()
        _to = (_tb.get("to") or "").strip()
        _ft = "external" if _frm in ("", "external") else comp_tier.get(_frm, "external")
        _tt = "external" if _to in ("", "external") else comp_tier.get(_to, "application")
        if _ft == _tt:
            continue
        _nm = _fig1_label((_tb.get("name") or _tb.get("id") or "").split("|")[0].strip())
        if _nm:
            _tb_name.setdefault((_ft, _tt), _nm)
            _tb_name.setdefault((_tt, _ft), _nm)

    # In-figure legend — a single light reference card. NOT wrapped in a
    # subgraph (that added an empty title bar + a second border — the "unnecessary
    # top border" the user flagged). Because the attack classes are NAMED on the
    # arrows, the legend only has to explain the line/colour key; it never makes
    # the reader decode numbers (2026-06-14 user request — legend clearly
    # understandable, not overloaded; self-explanatory).
    def _actor_name(slug: str) -> str:
        return _fig1_label(_FIG1_ACTOR_LABEL.get(slug) or (actor_labels.get(slug) or {}).get("label") or slug)

    _leg: list[str] = ["<b>Legend</b>"]
    # Line-style markers use em-dash (—) for a solid line and middle-dots (·) for
    # a dotted line; both glyphs are in the DejaVu Sans export font, whereas the
    # box-drawing chars (━ ┈ ─) are NOT and rendered as garbled "A==A==".
    if len(actor_order) > 1:
        # Several attackers → the line colour tells them apart; list the mapping.
        for slug in actor_order:
            col = actor_color.get(slug, "#b71c1c")
            _leg.append(f"<span style='color:{col}'>&#8212;&#8212;</span> attack — {_actor_name(slug)}")
    else:
        _leg.append("<span style='color:#b71c1c'>&#8212;&#8212;</span> attack (solid, from attacker)")
    _leg.append("<span style='color:#b71c1c'>&#183;&#183;&#183;&#183;</span> attack consequence (dotted)")
    _leg.append("<span style='color:#6b7280'>&#8212;&#8212;</span> legitimate request flow")
    if any(d.get("Critical") or d.get("High") for d in comp_sev_count.values()):
        _leg.append("🔴 Critical · 🟠 High (finding count on box)")
    _leg_html = "<div style='text-align:left;font-size:11px;line-height:1.6'>" + "<br/>".join(_leg) + "</div>"
    lines.append(f'    LEG["{_leg_html}"]:::legend')

    # actor mermaid-node-id → slug, to colour each attack edge by its actor.
    _nid_slug = {nid: slug for slug, nid in actor_node.items()}

    edge_idx = 0
    benign_idx: list[int] = []
    attack_styles: list[tuple[int, str]] = []  # (edge index, per-actor colour)
    if benign_edges:
        lines.append("    %% legitimate request flow")
        for src, dst, lbl in benign_edges:
            _b = _tb_name.get((_tier_of(src), _tier_of(dst)))
            _lbl = f"{lbl.strip()}<br/><i>trust boundary: {_b}</i>" if _b else lbl.strip()
            lines.append(f'    {src} -->|"{_lbl}"| {dst}')
            benign_idx.append(edge_idx)
            edge_idx += 1

    def _edge_label(glyphs: list[str]) -> str:
        # "① Injection<br/>② Auth Bypass" — glyph + class name, canonical order,
        # one class per line. Self-explanatory: no legend lookup required.
        _ord = sorted(glyphs, key=lambda g: _glyph_pos.get(g, 99))
        return "<br/>".join(f"{g} {glyph_name.get(g, '')}".strip() for g in _ord)

    if attack_glyphs:
        # Attack edges are SOLID arrows COLOURED per attacking actor AND labelled
        # directly with the attack class name(s) they carry, so the figure reads
        # on its own — no glyph decoder needed. A component hit by several classes
        # shows ONE arrow whose label stacks the names (P2: never parallel edges).
        lines.append("    %% attacks (solid) — coloured per actor, labelled with the class name(s)")
        for (src, dst), glyphs in attack_glyphs.items():
            lines.append(f'    {src} ==>|"{_edge_label(glyphs)}"| {dst}')
            attack_styles.append((edge_idx, actor_color.get(_nid_slug.get(src, ""), "#b71c1c")))
            edge_idx += 1
    prop_idx: list[int] = []
    if prop_glyphs:
        lines.append("    %% propagation (dotted) — consequence onto the data tier")
        for (src, dst), glyphs in prop_glyphs.items():
            lines.append(f'    {src} -.->|"{_edge_label(glyphs)}"| {dst}')
            prop_idx.append(edge_idx)
            edge_idx += 1
    if victim_props and benign_edges:
        # Explicit consequence edge ONTO the Shop User (victim): the payload the
        # attacker delivers through the client tier reaches the customer's
        # browser (XSS/CSRF). Merged per source, labelled with the class name(s)
        # so the "attack against the user" is shown as a real arrow, not buried in
        # the node text (2026-06-14 user request).
        _vmerge: dict[str, list[str]] = {}
        for _vsrc, _g in victim_props:
            _dst = _vmerge.setdefault(_vsrc, [])
            if _g not in _dst:
                _dst.append(_g)
        lines.append("    %% consequence onto the victim (Shop User)")
        for _vsrc, _gl in _vmerge.items():
            lines.append(f'    {_vsrc} -.->|"{_edge_label(_gl)}"| {user_node}')
            prop_idx.append(edge_idx)
            edge_idx += 1
    lines.append("")
    # Tier bands — all NEUTRAL slate (2026-06-14 user request: use red only for
    # attacks and attackers). The application tier kept a red band
    # before, which collided with red = attack; now every tier reads as the same
    # calm horizontal zone and the only red in the figure is the attacker node +
    # its attack arrows. The app tier keeps a marginally thicker stroke for a
    # subtle (non-colour) emphasis since it carries the most threats.
    for tier, sg in (("client", "CLIENT"), ("application", "APP"), ("data", "DATA")):
        if any(comp_tier[cid] == tier for cid in comp_node):
            width = "2.25px" if tier == "application" else "1.5px"
            lines.append(f"    style {sg} fill:#f1f5f9,stroke:#475569,stroke-width:{width}")
    if actor_emit:
        lines.append("    style ZONE_ACTORS fill:#f8fafc,stroke:#94a3b8,stroke-width:1.5px")
    lines.append("    classDef legend fill:#fbfbfd,stroke:#e2e8f0,color:#334155,stroke-width:1px")
    lines.append("    classDef comp fill:#eef2f7,stroke:#334155,color:#0f172a,stroke-width:1.5px")
    # Muted style for the per-tier "components without findings (not drawn)" note.
    lines.append("    classDef compmuted fill:#f8fafc,stroke:#cbd5e1,color:#64748b,stroke-width:1px,font-size:9px")
    lines.append("    classDef ext  fill:#ffffff,stroke:#94a3b8,color:#334155,stroke-width:1.5px")
    # Actor colouring: malicious red, benign/victim green (2026-05-30 request).
    lines.append("    classDef actorbad  fill:#fde8e8,stroke:#b71c1c,color:#7f0000,stroke-width:2px")
    lines.append("    classDef actorgood fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:1.5px")
    if benign_idx:
        lines.append(f"    linkStyle {','.join(str(i) for i in benign_idx)} stroke:#6b7280,stroke-width:1.5px")
    # Attack edges — one linkStyle PER edge so each carries its attacking actor's
    # colour (attribution by colour). Grouped by colour to keep the directive set
    # small when several edges share an actor.
    _by_color: dict[str, list[int]] = {}
    for _i, _col in attack_styles:
        _by_color.setdefault(_col, []).append(_i)
    for _col, _idxs in _by_color.items():
        lines.append(f"    linkStyle {','.join(str(i) for i in _idxs)} stroke:{_col},stroke-width:2.5px")
    if prop_idx:
        # Dotted, thinner — the consequence path, subordinate to the attacks.
        lines.append(
            f"    linkStyle {','.join(str(i) for i in prop_idx)} stroke:#b71c1c,stroke-width:1.5px,stroke-dasharray:5"
        )
    lines.append("```")

    # The legend lives inside the figure (a single light card, no subgraph box),
    # so the diagram is self-explanatory — every attack arrow is named with its
    # class, so no markdown decoder table is needed (2026-06-14 user request).
    intro = (
        "Components grouped by architecture tier (Client → Application → Data, top to bottom). "
        "Each red arrow is an attack labelled with its class and coloured by the attacking actor; "
        "dotted red arrows show where the attack propagates (data tier, victim). The 🔴/🟠 badge on "
        "a box counts its Critical/High findings."
    )
    body = intro + "\n\n" + "\n".join(lines) + "\n"
    return body


def _build_security_posture_actor_legend(attack_paths_data: dict, attack_taxonomy: dict) -> str:
    """Build the ``**Threat actors.**`` legend rendered below the two figures.

    Lists every actor present in ``attack_paths`` (attackers AND the
    victim-required Shop User), each with its subtitle and the numbered
    attack paths it drives / is targeted by. Glyphs use the same positional
    ①–⑦ order as the figures and the Top Threats table.
    """
    aps = attack_paths_data.get("attack_paths") or []
    if not aps:
        return ""
    glyph_seq = attack_taxonomy.get("glyph_sequence") or ["①", "②", "③", "④", "⑤", "⑥", "⑦"]
    cls_by_id = {c.get("id"): c for c in (attack_taxonomy.get("classes") or []) if isinstance(c, dict)}
    labels = _load_posture_actor_labels() or {}
    actor_meta = labels.get("actors") or {}
    order = labels.get("order") or []

    drives: dict[str, list[str]] = {}
    for idx, ap in enumerate(aps):
        if idx >= len(glyph_seq):
            break
        g = glyph_seq[idx]
        cls = cls_by_id.get((ap.get("class") or "").strip()) or {}
        title = cls.get("threat_label") or cls.get("label") or (ap.get("class") or "").strip()
        actor = (ap.get("actor") or "internet-anon").strip()
        drives.setdefault(actor, []).append(f"{g} {title}")
    if not drives:
        return ""

    present = [a for a in order if a in drives] + [a for a in drives if a not in order]
    # The victim-required (Shop User) actor is deliberately NOT drawn as a node
    # in Figure 2 — that figure is forward-only (actor → tier → impact) and the
    # victim's compromise is carried by the business-impact node instead (see
    # _render_security_posture_at_a_glance). Only mention the Shop User victim in
    # the legend when a victim-targeting path actually exists, and make the
    # figure representation explicit so a reader does not look for a missing
    # actor box.
    has_victim = "victim-required" in drives
    intro = "**Threat actors.** The actors below drive the numbered attack paths in the figures above."
    if has_victim:
        intro += (
            " The **Shop User** is the *victim* of client-side attacks (XSS / CSRF), "
            "not an attacker — in Figure 2 the compromise surfaces as the resulting "
            "business-impact node rather than as a separate actor box."
        )
    out = [intro, ""]
    for a in present:
        meta = actor_meta.get(a) or {}
        name = _FIG1_ACTOR_LABEL.get(a) or meta.get("label") or a
        sub = meta.get("default_subtitle") or ""
        is_victim = meta.get("role") == "victim" or a == "victim-required"
        verb = "target of" if is_victim else "drives"
        paths = ", ".join(drives[a])
        sub_part = f"{sub}; " if sub else ""
        out.append(f"- **{name}** — {sub_part}{verb} {paths}.")
    return "\n".join(out) + "\n"


def _build_ms_abuse_chain_line(ctx: RenderContext) -> str:
    """One deterministic line for the MS `Security Posture & Top Threats`
    section that surfaces the verified abuse-case chains and links §9.

    Read from the `.fragments/abuse-cases.json` sidecar produced by
    `render_abuse_cases.py` (chain verdicts are computed deterministically from
    per-step verification — never rated here). Only the ACTIONABLE verdicts
    (fully viable / partially blocked) are surfaced so the exec summary points
    at the chains that actually compose findings into an end-to-end exploit.
    Returns '' when no such chain exists (line omitted). The verdict block
    above must stay brief and ID-free (feedback_threat_model_verdict_brevity),
    so the abuse linkage lives here, alongside the other §-cross-references.
    """
    path = ctx.fragments_dir / "abuse-cases.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    cases = doc.get("abuse_cases") or []
    viable = [c for c in cases if c.get("chain_verdict") == "fully_viable"]
    partial = [c for c in cases if c.get("chain_verdict") == "partially_blocked"]
    if not viable and not partial:
        return ""

    def _links(items: list[dict]) -> str:
        return ", ".join(f"[{c.get('id')}](#{str(c.get('id', '')).lower()})" for c in items if c.get("id"))

    segs: list[str] = []
    if viable:
        segs.append(f"{len(viable)} fully viable ({_links(viable)})")
    if partial:
        segs.append(f"{len(partial)} partially blocked ({_links(partial)})")
    return (
        "**Verified attack chains.** " + "; ".join(segs) + ". These chains combine individual findings into end-to-end "
        "exploitation paths verified step-by-step against the code — see "
        "[§9 Abuse Cases](#9-abuse-cases) for the per-step breakdown and "
        "blocking mitigations."
    )


def _verified_chain_map(ctx: RenderContext) -> dict[str, list[str]]:
    """Map each finding id (canonical F-NNN) → the fully-viable abuse-case
    chain(s) it participates in, read from `.fragments/abuse-cases.json`.

    Only ``fully_viable`` chains qualify — the code-verified, end-to-end
    exploitable paths (``partially_blocked`` / ``inconclusive`` are excluded,
    matching ``triage_compute_ranking._detect_verified_abuse_chains``). Used to
    badge the worst-case bullets in the MS Verdict blockquote with the chain
    that proves the path end-to-end. Returns {} when the sidecar is missing
    (quick depth / ``--no-abuse-cases``) or holds no viable chain.
    """
    path = ctx.fragments_dir / "abuse-cases.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    fmap: dict[str, list[str]] = {}
    for c in doc.get("abuse_cases") or []:
        if c.get("chain_verdict") != "fully_viable":
            continue
        cid = str(c.get("id") or "").strip()
        if not cid:
            continue
        for raw in c.get("matched_finding_ids") or []:
            fid = str(raw).strip().upper()
            m = re.match(r"^T-(\d+)$", fid)
            if m:
                fid = f"F-{m.group(1)}"
            if not re.match(r"^F-\d+$", fid):
                continue
            fmap.setdefault(fid, [])
            if cid not in fmap[fid]:
                fmap[fid].append(cid)
    return fmap


def _verdict_bullet_badge(refs: list[str], fmap: dict[str, list[str]]) -> str:
    """Return a plain-language verification suffix for a Verdict bullet.

    Management-summary readers need the confidence signal, not an abuse-case ID
    or the technical chain mechanics. The underlying refs remain in the fragment
    for auditability; this presentation layer intentionally emits only a short
    ``verified attack path`` badge. T-NNN refs are normalised to F-NNN to match
    ``matched_finding_ids``.
    """
    if not fmap or not refs:
        return ""
    chains: list[str] = []
    for r in refs:
        fid = str(r).strip().upper()
        m = re.match(r"^T-(\d+)$", fid)
        if m:
            fid = f"F-{m.group(1)}"
        for cid in fmap.get(fid, []):
            if cid not in chains:
                chains.append(cid)
    return " — ✓ verified attack path" if chains else ""


def _render_security_posture_at_a_glance(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """Emit the `### Security Posture at a Glance` section per contract v2.

    The section is a hybrid of:

      1. A computed Mermaid heatmap (4 columns: ACTORS / TIERS / IMPACT;
         ELK renderer; header-alignment edges; up to 7 attack arrows ①–⑦
         and matching dashed consequence arrows). Built from
         ``threat-model.yaml`` plus the three taxonomies in ``data/``
         (attack-class-, business-impact-, posture-actor-labels).
      2. An LLM-authored attack-paths fragment (or deterministic
         CWE-derived fallback) rendered as 1–7 numbered bullets with
         sub-bullets for Architectural-root-cause / Findings /
         Attack-chain / Impact (comma-separated).

    Conditional rendering:
      * If the threat model has fewer than ``min_high_or_critical`` High+
        Critical findings, the section renders as an empty string so the
        Management Summary composer drops it cleanly.
    """
    components = ctx.yaml_data.get("components") or []
    threats = ctx.yaml_data.get("threats") or []
    tier_root_causes = ctx.yaml_data.get("tier_root_causes") or {}

    critical_high = sum(
        1 for t in threats if (t.get("risk") or t.get("severity") or "").strip().lower() in ("critical", "high")
    )
    min_required = int(section.get("min_high_or_critical", 3))
    if critical_high < min_required:
        return ""

    # Load taxonomies + the LLM-authored fragment (or deterministic fallback).
    attack_taxonomy = _load_attack_class_taxonomy()
    impact_taxonomy = _load_business_impact_taxonomy()
    actor_labels = _load_posture_actor_labels()
    attack_paths_data = _load_attack_paths_fragment(ctx, attack_taxonomy, threats)

    # When the app exposes open user self-registration, the heatmap actor
    # spectrum `internet-anon → internet-user → internet-priv-user` is
    # misleading — reaching the "authenticated" position is a single POST,
    # so distinct attacker cards for each tier paint a false picture of
    # reachability gates. Collapse the three slugs to `internet-anon` for
    # both the actor-card column and the attack-arrow origins. The §8
    # Vektor column (and the YAML field) keep their granularity — only
    # the at-a-glance heatmap collapses.
    open_user_registration = bool((ctx.yaml_data.get("meta") or {}).get("open_user_registration"))
    # 2026-05-31 actor-model decision: do NOT collapse the authenticated
    # internet tiers (`internet-user` / `internet-priv-user`) into `internet-anon`
    # on open registration. Registering is trivial, but an authenticated request
    # is still a distinct attack position (a post-login state-changing endpoint
    # is a different surface than an anonymous one), and collapsing it hid the
    # "Authenticated Internet Attacker" entirely. The `internet-anon` card is
    # still relabelled below (open_user_registration=True) to note registration
    # is one POST away, so the trivial-escalation insight is preserved without
    # erasing the authenticated tier. The legacy collapse helper
    # (_collapse_open_registration_actors) is retained but no longer called.
    #
    # A committed secret in a PUBLIC repo is readable by any anonymous attacker,
    # so the repo-reader vektor collapses into internet-anon (drops the
    # "Internal Developer" actor — anyone can clone public source). Gated on
    # meta.public_source_repo (set by Stage-1 context / the recon scanner).
    public_source_repo = bool((ctx.yaml_data.get("meta") or {}).get("public_source_repo"))
    if public_source_repo:
        _collapse_public_repo_actors(attack_paths_data)

    # Build the per-column input data.
    threats_by_component = _group_threats_by_component(threats)
    tier_cards = _build_tier_cards(
        components,
        threats_by_component,
        tier_root_causes,
        attack_paths_data=attack_paths_data,
        attack_taxonomy=attack_taxonomy,
    )

    actor_cards = _build_actor_cards(
        attack_paths_data,
        actor_labels,
        taxonomy=attack_taxonomy,
        open_user_registration=open_user_registration,
    )
    impact_cards = _build_impact_cards(attack_paths_data, impact_taxonomy)

    # Build the edge structure.
    attack_arrows, relay_arrows = _build_attack_arrows(attack_paths_data, attack_taxonomy, actor_cards, tier_cards)
    consequence_arrows = _build_consequence_arrows(attack_paths_data, impact_cards, tier_cards)
    alignment_edges = _build_alignment_edges(actor_cards, tier_cards)

    # Figure 2 is FORWARD-ONLY (actor → tier → impact): no edge ever returns
    # to the actor column. The victim outcome of XSS/CSRF is already carried
    # by the Customer-Session-Hijack IMPACT node (a forward consequence
    # arrow from the Client tier), so we drop the backward relay arrows
    # (client → victim), the victim actor card, and any alignment edge that
    # referenced it. This keeps every arrow horizontal and prevents the
    # relay hop from crossing a tier box.
    _victim_nodes = {c.get("id") for c in actor_cards if c.get("slug") == "victim-required"}
    if _victim_nodes:
        actor_cards = [c for c in actor_cards if c.get("slug") != "victim-required"]
        relay_arrows = []
        alignment_edges = [
            e for e in alignment_edges if e.get("src") not in _victim_nodes and e.get("dst") not in _victim_nodes
        ]

    # Continuous link-style index ranges. Mermaid numbers edges in the
    # order they appear in the source; we emit alignment edges first,
    # then attack arrows, then relay arrows (same red style), then consequence.
    # relay_arrows are the client→victim delivery hops for victim-targeting
    # classes (XSS/CSRF). They are separate from attack_arrows so n_atk equals
    # the number of unique glyphs, which keeps linkStyle indices correct.
    n_align = len(alignment_edges)
    n_atk = len(attack_arrows)
    n_relay = len(relay_arrows)
    n_conq = len(consequence_arrows)
    linkstyle_alignment = list(range(0, n_align))
    # Split the attack edges by directness. A single linkStyle without
    # `stroke-dasharray` would flatten the `-.->` indirect syntax back to a
    # SOLID line (mermaid's linkStyle wins over the edge-type dotting), erasing
    # the direct/indirect distinction. Direct attacks stay 3px solid red;
    # INDIRECT (victim-required, e.g. DOM XSS) attacks — and the relay/delivery
    # hops — render dashed red. Edge index = n_align + position-in-attack_arrows.
    linkstyle_attacks = [n_align + j for j, a in enumerate(attack_arrows) if not a.get("indirect")]
    linkstyle_attacks_indirect = [n_align + j for j, a in enumerate(attack_arrows) if a.get("indirect")] + list(
        range(n_align + n_atk, n_align + n_atk + n_relay)
    )
    linkstyle_consequences = list(range(n_align + n_atk + n_relay, n_align + n_atk + n_relay + n_conq))

    # Intro paragraph — one sentence + severity-emoji legend with an
    # explicit note that Low-severity findings are tracked in §8 but
    # omitted from the heatmap (per contract v2 tier_severity_floor).
    glyph_seq = attack_taxonomy.get("glyph_sequence") or ["①", "②", "③", "④", "⑤", "⑥", "⑦"]
    # Span the intro range to the highest INDIVIDUAL glyph actually drawn.
    # attack_arrows are grouped per (src,dst), so one arrow may carry several
    # space-joined glyphs (e.g. "① ③ ④ ⑤"); counting arrows would understate
    # the range. Split every arrow's glyph string (attack + relay edges) into
    # individual glyphs and take the max taxonomy position so the range ends
    # at the real last threat (①–⑥), not the number of grouped arrows.
    glyph_rank = {g: i for i, g in enumerate(glyph_seq)}
    glyphs_used = {g for a in (attack_arrows + relay_arrows) for g in (a.get("glyph") or "").split() if g in glyph_rank}
    if glyphs_used:
        last_idx = max(glyph_rank[g] for g in glyphs_used)
        glyph_range = f"①–{glyph_seq[last_idx]}"
    else:
        glyph_range = "①"
    intro_paragraph = (
        "Heatmap: **actors** (left) → **architecture tiers** (middle, "
        "Client → Application → Data) → **impact** (right). "
        f"Numbered red arrows {glyph_range} are the threats enumerated in the Top Threats table below."
    )
    if open_user_registration:
        intro_paragraph += (
            " Self-registration is open, so the **Authenticated Internet Attacker** "
            "tier is one POST away from anonymous — it is shown distinctly because a "
            "post-login endpoint is still a different attack surface."
        )

    diagram_data = {
        "intro_paragraph": intro_paragraph,
        "subgraph_actors": {
            "header_label": "Threat Actors",
            "cards": actor_cards,
        },
        "subgraph_tiers": {
            "header_label": "Architecture Tiers",
            "cards": tier_cards,
        },
        "subgraph_impact": {
            "header_label": "Business Impact",
            "cards": impact_cards,
        },
        "alignment_edges": alignment_edges,
        "attack_arrows": attack_arrows,
        "relay_arrows": relay_arrows,
        "consequence_arrows": consequence_arrows,
        "linkstyle_alignment": linkstyle_alignment,
        "linkstyle_attacks": linkstyle_attacks,
        "linkstyle_attacks_indirect": linkstyle_attacks_indirect,
        "linkstyle_consequences": linkstyle_consequences,
    }

    diagram_md = env.get_template("security-posture-diagram.md.j2").render(data=diagram_data)

    # Figure 2 PRIMARY renderer: a deterministic hand-built SVG (portable to
    # non-ELK Markdown viewers). Falls back to the inline Mermaid block above
    # (`diagram_md`) when the SVG builder yields nothing. When the SVG is used,
    # the intro paragraph (emitted inside `diagram_md` by the template) is
    # re-prepended so the caption text is preserved.
    figure2_svg_md = _render_figure2_svg(ctx, diagram_data)
    figure2_block = f"{intro_paragraph}\n\n{figure2_svg_md}" if figure2_svg_md else diagram_md

    # ---- Attack-paths bullet list -------------------------------------------
    # Prefix-tolerant lookup: the schema mandates F-NNN ids in the LLM-authored
    # `findings` arrays, but threats are stored with T-NNN ids in
    # threat-model.yaml. Build a second index keyed by the numeric suffix so
    # F-001 resolves to T-001 by digit-suffix match when the direct lookup
    # misses.
    threat_by_id: dict[str, dict] = {}
    threat_by_suffix: dict[str, dict] = {}
    for _t in threats:
        _tid = (_t.get("id") or _t.get("t_id") or "").strip()
        if not _tid:
            continue
        threat_by_id[_tid] = _t
        if "-" in _tid:
            _suffix = _tid.split("-", 1)[1].lstrip("0") or "0"
            threat_by_suffix[_suffix] = _t

    def _lookup_threat(fid: str) -> dict:
        t = threat_by_id.get(fid)
        if t:
            return t
        if "-" in fid:
            suffix = fid.split("-", 1)[1].lstrip("0") or "0"
            return threat_by_suffix.get(suffix) or {}
        return {}

    classes_by_id = {c["id"]: c for c in (attack_taxonomy.get("classes") or [])}
    impacts_by_id = {i["id"]: i for i in (impact_taxonomy.get("impacts") or [])}
    actor_card_by_slug = {a["slug"]: a for a in actor_cards}
    actors_dict = actor_labels.get("actors") or {}

    target_label_map = {
        "client": "Client Tier",
        "application": "Application Tier",
        "data": "Data Tier",
        "victim": "Shop User",
    }

    attack_paths_rendered: list[dict] = []
    for idx, ap in enumerate(attack_paths_data.get("attack_paths") or []):
        if idx >= len(glyph_seq):
            break
        cls = classes_by_id.get(ap.get("class") or "")
        if not cls:
            continue
        actor_slug = ap.get("actor") or "internet-anon"
        # For victim-targeting attacks the bullet header reads
        # "Client Tier → Shop User" (the rendering tier delivers the
        # payload to the victim). Direct attacks read "<Actor> → <Tier>".
        target = ap.get("target") or "application"
        if target == "victim":
            actor_for_bullet = "Client Tier"
            target_for_bullet = "Shop User"
        else:
            meta = actors_dict.get(actor_slug) or {}
            actor_for_bullet = actor_card_by_slug.get(actor_slug, {}).get("label") or meta.get("label") or actor_slug
            target_for_bullet = target_label_map.get(target, target)

        # Findings sub-list: { id, title }.
        # Post-2026-05-05: when the LLM-authored fragment omits per-path
        # `findings` (now optional in the schema), DERIVE the list from
        # `threats[]` via CWE → class membership in
        # `attack-class-taxonomy.yaml`. Without this fallback the bullets
        # render as "(Anonymous → Application Tier)" with no T-ID list,
        # which trips qa_checks `posture_structure B2`.
        finding_ids = list(ap.get("findings") or [])
        if not finding_ids:
            cls_id = ap.get("class") or ""
            if cls_id:
                # Walk threats[] and pick those whose CWE membership
                # matches the class. Same logic as
                # `_derive_attack_paths_fallback` uses for fallback
                # rendering — kept consistent for traceability.
                threats_list = ctx.yaml_data.get("threats") or []
                for t in threats_list:
                    if not isinstance(t, dict):
                        continue
                    if _classify_finding_class(t, attack_taxonomy) == cls_id:
                        fid = (t.get("id") or t.get("t_id") or "").strip()
                        if fid:
                            finding_ids.append(fid)
        finding_list = []
        for fid in finding_ids:
            t = _lookup_threat(fid)
            title = (t.get("title") or t.get("scenario_short") or "").strip()
            if not title:
                sc = (t.get("scenario") or "").strip()
                if sc:
                    parts = sc.split(". ", 1)
                    first_sentence = parts[0].strip() if parts[0].strip() else sc
                    title = first_sentence[:60]
            # P4 — normalise T-NNN visible label to F-NNN for consistency
            # with the qa-reviewer canonical contract.
            visible_fid = fid
            m_t = re.match(r"^T-(\d+)$", fid or "")
            if m_t:
                visible_fid = f"F-{m_t.group(1)}"
            finding_list.append(
                {
                    "id": visible_fid,
                    "title": title.replace("|", "\\|"),
                }
            )

        # Attack-chain sub-list: { id, id_label, title }.
        # `ch` is a canonical CC-NN slug (e.g. ``"cc-01"``) — same anchor
        # as §8.F Compound Attack Chains and §3.1 walkthroughs. We emit
        # the bullet as ``[CC-01](#cc-01)`` so cross-references resolve.
        chain_list = []
        for ch in ap.get("attack_chains") or []:
            id_label = ch.upper()  # cc-01 → CC-01
            chain_list.append(
                {
                    "id": ch,
                    "id_label": id_label,
                    "title": "",
                }
            )

        # Impact line — comma-separated labels resolved through the taxonomy.
        impact_labels = []
        for slug in ap.get("impact") or []:
            imp = impacts_by_id.get(slug)
            if imp:
                impact_labels.append(imp.get("label") or slug)
        impact_string = ", ".join(impact_labels) if impact_labels else "—"

        attack_paths_rendered.append(
            {
                "glyph": glyph_seq[idx],
                "class_slug": ap.get("class") or "",
                "class_label": cls.get("label") or ap.get("class"),
                "actor_label": actor_for_bullet,
                "target_label": target_for_bullet,
                "description": (ap.get("description") or " ".join((cls.get("description") or "").split())),
                "findings": finding_list,
                "attack_chains": chain_list,
                "impact_string": impact_string,
            }
        )

    # Build one bullet per visible actor for the "Threat actors" intro.
    # Each slug gets a distinct description — previously all non-victim actors
    # shared the "no account, no foothold" copy, making "Authenticated Internet
    # Attacker" read identically to "Anonymous Internet Attacker".
    _actor_prose: dict[str, str] = {
        "internet-anon": (
            "no account, no foothold; reaches every unauthenticated route, "
            "registers a throw-away account in seconds when needed, and can "
            "clone the public repository to obtain any committed secret offline. "
            "Initiates the outgoing attack arrows."
        ),
        "internet-user": (
            "owns a valid registered account and an active session; can reach "
            "all authenticated endpoints and exploit post-authentication "
            "vulnerabilities (IDOR, privilege escalation, SSTI, SSRF, stored "
            "XSS injection). Initiates the outgoing attack arrows."
        ),
        "internet-priv-user": (
            "holds elevated application privileges (admin or staff role); can "
            "reach management endpoints and perform privileged operations. "
            "Threat model considers this actor when privilege escalation from "
            "a lower-privilege account is in scope."
        ),
        "build-time": (
            "compromises a dependency, CI pipeline, or build artefact before "
            "the application reaches production; the attack surface is the "
            "dependency tree and the build environment, not the live endpoint."
        ),
        "repo-read": (
            "has source-repository access as an internal developer or through an exposed clone; "
            "extracts committed secrets, hardcoded keys, and algorithm details "
            "offline without touching the running service."
        ),
        "victim-required": (
            "legitimate registered customer whose session and PII are the "
            "actual target; receives the victim-targeting attack arrows "
            "as victim, not attacker."
        ),
    }
    actor_bullets: list[dict] = []
    for ac in actor_cards:
        body = _actor_prose.get(ac["slug"]) or (
            "legitimate user — see label for role details."
            if ac["role"] == "victim"
            else "reaches the application as described by the actor label above."
        )
        actor_bullets.append({"label": ac["label"], "body": body})

    # Compute the victim-targeting class labels actually rendered. Empty
    # list -> no victim actor present -> intro paragraph drops the
    # "browser-side attacks" clause entirely so we never promise CSRF
    # coverage when no CSRF finding exists.
    _victim_labels: list[str] = []
    _classes_by_id = {c.get("id"): c for c in (attack_taxonomy.get("classes") or [])}
    for ap in attack_paths_data.get("attack_paths") or []:
        actor_slug = (ap.get("actor") or "").lower()
        target = (ap.get("target") or "").lower()
        if actor_slug != "victim-required" and target != "victim":
            continue
        cls = _classes_by_id.get(ap.get("class") or "")
        if not cls:
            continue
        lab = cls.get("short_label") or cls.get("label") or ap.get("class")
        if lab and lab not in _victim_labels:
            _victim_labels.append(lab)
    n_actors = len(actor_cards)
    if _victim_labels:
        intro_para = (
            f"**Threat actors.** Attacker initiates every direct attack "
            f"class; one victim is targeted by browser-side attacks "
            f"({' / '.join(_victim_labels)})."
        )
    elif n_actors >= 2:
        intro_para = f"**Threat actors.** {n_actors} entities each initiate one or more direct attack classes."
    else:
        intro_para = "**Threat actors.** One entity initiates every direct attack class."

    paths_template_data = {
        "intro_paragraph": intro_para,
        "actor_bullets": actor_bullets,
        "attack_paths_header": "**Attack paths (numbered arrows in the diagram):**",
        "attack_paths": attack_paths_rendered,
    }

    # ---- Compose the merged "Security Posture & Top Threats" section --------
    # The standalone attack-path bullet list is no longer rendered: the
    # Top Threats table below carries the same per-class detail (general
    # architectural weakness + linked findings/components/mitigations). The
    # section now reads: heading → Figure 1 (optional architecture diagram)
    # → Figure 2 (the risk-flow heatmap above) → Top Threats table.
    _ = paths_template_data  # built above; intentionally not rendered as bullets

    # Figure 1 is built DETERMINISTICALLY from yaml + the SAME reconciled
    # attack_paths order that drives Figure 2's glyphs, so ①–⑦ agree across
    # both figures and the Top Threats table. The deterministic builder is the
    # AUTHORITATIVE source: it guarantees the agreed format every run — actor
    # band on top, Client→Application→Data tier stack, per-component finding
    # badges (🔴/🟠), red attackers / green users, no actor→data edges, and
    # in-range linkStyle indices. An LLM/operator-authored
    # `.fragments/top-threats-architecture.md` is consulted ONLY as a fallback
    # when the builder yields nothing (e.g. no attack_paths). This precedence
    # is intentional: when the LLM fragment was preferred it produced free-form
    # diagrams that ignored the prescribed structure and emitted out-of-range
    # `linkStyle` indices that crash Mermaid (2026-05-30 regression). Best-effort:
    # a builder failure must never break the section (Figure 2 + table still render).
    # PRIMARY: deterministic hand-built SVG (written next to threat-model.md).
    figure1_md = ""
    try:
        figure1_md = _render_figure1_svg(ctx, attack_paths_data, attack_taxonomy).strip()
    except Exception:  # noqa: BLE001 — Figure 1 is non-essential
        figure1_md = ""
    # FALLBACK 1: the legacy deterministic Mermaid builder (kept for robustness
    # if the SVG generator is unavailable or yields nothing).
    if not figure1_md:
        try:
            figure1_md = _render_top_threats_architecture(ctx, attack_paths_data, attack_taxonomy).strip()
        except Exception:  # noqa: BLE001 — Figure 1 is non-essential
            figure1_md = ""
    # FALLBACK 2: an LLM/operator-authored fragment.
    if not figure1_md:
        fig1_path = ctx.fragments_dir / "top-threats-architecture.md"
        try:
            if fig1_path.is_file():
                figure1_md = fig1_path.read_text(encoding="utf-8").strip()
        except OSError:
            figure1_md = ""

    table_md = _render_top_threats(ctx, env, {"template": "top-threats.md.j2"}).rstrip()

    parts: list[str] = ["### Security Posture & Top Threats", ""]
    if figure1_md:
        parts += ["**Figure 1 — Architecture & Top Threats**", "", figure1_md, ""]
    parts += [
        "**Figure 2 — Risk Flow: Actor → Tier → Impact**",
        "",
        figure2_block.rstrip(),
        "",
    ]
    legend_md = _build_security_posture_actor_legend(attack_paths_data, attack_taxonomy)
    if legend_md:
        parts += [legend_md.rstrip(), ""]
    parts += [table_md]
    abuse_line = _build_ms_abuse_chain_line(ctx)
    if abuse_line:
        parts += ["", abuse_line]
    return "\n".join(parts).rstrip() + "\n"


def _render_top_findings(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    rows, total_qualifying = _compute_top_findings_rows(ctx)
    tpl = env.get_template("top-findings.md.j2")
    return tpl.render(rows=rows, total_qualifying=total_qualifying).rstrip() + "\n"


def _compute_top_findings_rows(ctx: RenderContext) -> tuple[list[dict[str, Any]], int]:
    """Build the Top Findings table rows.

    Sort order priority:
      1. triage.ranking.views.top_findings.findings_ranked[] (authoritative).
      2. Fallback: severity desc → CVSS desc → T-ID asc.

    Ensures every cell carries a *resolvable* link:
      * Pfad     : `[①](#path-<class-slug>)` — links into the heatmap bullet
      * Finding  : `[F/T-NNN](#…) — <threat title>`
      * Component: `[C-NN](#c-nn) — <Component name>`   (canonical C-NN anchor)
      * Mitigations with `(P1)/(P2)/…` priority token.
    """
    components = _component_lookup(ctx)
    threats = _threat_lookup(ctx)
    mitigations = _mitigation_lookup(ctx)

    attack_taxonomy = _load_attack_class_taxonomy()
    attack_paths_data = _load_attack_paths_fragment(ctx, attack_taxonomy, list(threats.values()))
    # M-9: Pass threats so both F-NNN and T-NNN keys get registered.
    fid_to_path = _build_finding_to_path_map(attack_paths_data, list(threats.values()))

    ranking = (ctx.triage.get("ranking") or {}).get("views", {}).get("top_findings", {}).get("findings_ranked", [])
    if ranking:
        qualifying_ids = [
            r.get("id") for r in ranking if r.get("effective_severity", "").lower() in ("critical", "high")
        ]
    else:
        qualifying_threats = sorted(
            [
                t
                for t in ctx.yaml_data.get("threats", [])
                if (t.get("risk") or t.get("severity") or "").lower() in ("critical", "high")
            ],
            key=lambda t: (
                _severity_rank(t.get("risk") or t.get("severity")),
                -(t.get("cvss") or 0.0),
                t.get("t_id") or t.get("id") or "",
            ),
        )
        qualifying_ids = [t.get("t_id") or t.get("id") for t in qualifying_threats]

    def resolve_component(cid: str | None) -> tuple[str, str]:
        """Return (C-NN anchor id, display name). The `_component_lookup`
        helper already aliased non-canonical ids, so a direct lookup is
        usually enough. For bare-string components (e.g. `"Auth Service"`),
        fall back to name-lookup."""
        if not cid:
            return "C-00", "—"
        raw = cid.strip()
        if raw in components:
            comp = components[raw]
            canonical = (
                comp.get("_canonical_id") or raw if re.match(r"^C-\d+$", raw) else comp.get("_canonical_id", raw)
            )
            return canonical, (comp.get("name") or raw)
        for c_id, c in components.items():
            if re.match(r"^C-\d+$", c_id) and (c.get("name") or "").strip() == raw:
                return c_id, c.get("name") or c_id
        return "C-00", raw

    # Fallback matches the contract default. The contract value at
    # data/sections-contract.yaml:top_findings.table.rows.max is the
    # single source of truth — the literal here only kicks in when the
    # contract is missing/corrupt.
    max_rows = (ctx.contract["sections"].get("top_findings") or {}).get("table", {}).get("rows", {}).get("max", 5)
    # P1.4 — design-risk weaknesses (W-NNN) may enter findings_ranked (§9.3).
    # They have no threats[] row, so resolve them from the weakness register and
    # render a distinct design-risk row that links to the §8 Weakness Classes
    # anchor. Empty register → no W-NNN ids → this map is unused.
    _wk_by_id = {(w.get("id") or "").strip().upper(): w for w in (ctx.yaml_data.get("weaknesses") or []) if w.get("id")}
    _wk_labels = {c.get("id"): c.get("label") for c in (_load_weakness_classes().get("clusters") or []) if c.get("id")}
    rendered: list[dict[str, Any]] = []
    for idx, tid in enumerate(qualifying_ids[:max_rows], start=1):
        wk = _wk_by_id.get((tid or "").strip().upper())
        if wk is not None:
            # Design-risk weakness row — no CVSS / no proven exploit; the
            # "(design-risk)" tag keeps it visually distinct from confirmed rows.
            label = _wk_labels.get(wk.get("weakness_class")) or (wk.get("weakness_class") or "Weakness")
            wtitle = (wk.get("title") or f"{label} (design-risk)").strip()
            comps = wk.get("affected_components") or []
            wc_anchor, wc_name = resolve_component(comps[0] if comps else None)
            rendered.append(
                {
                    "rank": idx,
                    "criticality": (wk.get("severity") or "").lower(),
                    "path_glyph": "",
                    "path_anchor": "",
                    "finding_id": (tid or "").strip().upper(),
                    "finding_title": wtitle[:160],
                    "component_id": wc_anchor,
                    "component_name": wc_name,
                    "mitigations": [
                        {"id": "", "action": f"Introduce a central {label.lower()} control", "priority": "", "kind": ""}
                    ],
                }
            )
            continue
        t = threats.get(tid) or {}
        # Component cell: use the canonical C-NN anchor.
        c_anchor, c_name = resolve_component(t.get("component_id") or t.get("component"))
        # Pfad cell: glyph ①–⑦ + anchor into Security Posture bullet.
        path_glyph, path_anchor = fid_to_path.get((tid or "").upper(), ("", ""))
        # Mitigation cells: M-ID + action + priority token (P1/P2/…).
        mit_cells: list[dict[str, str]] = []
        _m_ids = t.get("mitigations") or []
        if not _m_ids:
            # Fallback: render free-text mitigation_title when no M-IDs exist yet.
            _mt = (t.get("mitigation_title") or "").strip()
            if _mt:
                mit_cells.append({"id": "", "action": _mt[:80], "priority": "", "kind": ""})
            else:
                # M-14: When the finding carries no mitigation at all, surface
                # an actionable "Manual review at <file:line>" hint instead of
                # the bare em-dash. The hint links to the §8 row anchor so the
                # reviewer can jump straight to the finding's full context.
                hint = _format_manual_review_hint(t, tid)
                if hint:
                    mit_cells.append(hint)
        for mid in _m_ids[:2]:
            m = mitigations.get(mid, {})
            mit_cells.append(
                {
                    "id": mid,
                    "action": (m.get("title") or "").strip(),
                    "priority": (m.get("priority") or "").strip(),
                    # M-RCA-2026-05: carry `kind` so format_mitigations can
                    # dispatch the per-kind glyph (🔧/🔍/🧭/🛈).
                    "kind": (m.get("kind") or "").strip(),
                }
            )
        # Finding title — canonical `<weakness class> — <file:line>` form
        # so the Top Findings row matches the §8 Findings Register row title.
        title = _canonical_finding_title(t)
        if not title:
            # Fallback chain matches `_build_finding_cell` for layout
            # consistency.
            title = (t.get("title") or t.get("scenario_short") or "").strip()
            if not title:
                sc = (t.get("scenario") or "").strip()
                if sc:
                    parts = sc.split(". ", 1)
                    first_sentence = parts[0].strip() if parts[0].strip() else sc
                    title = first_sentence[:80]
                else:
                    title = tid

        # Visible label form: F-NNN matches the qa-reviewer canonical
        # contract and the LLM-authored fragments (Verdict bullets, AA
        # defects). When tid is the T-NNN form, expose F-NNN as the
        # visible label so the Top Findings table reads consistently with
        # the rest of the document. The link target uses the F-anchor
        # (also emitted by `_render_threat_register`).
        m_tid = re.match(r"^T-(\d+)$", tid or "")
        finding_id_visible = f"F-{m_tid.group(1)}" if m_tid else tid

        rendered.append(
            {
                "rank": idx,
                "criticality": (t.get("risk") or t.get("severity") or "").lower(),
                "path_glyph": path_glyph,
                "path_anchor": path_anchor,
                "finding_id": finding_id_visible,
                "finding_title": title,
                "component_id": c_anchor,
                "component_name": c_name,
                "mitigations": mit_cells,
            }
        )

    # Top Findings is rendered as a Markdown pipe-table (contract-aligned with
    # qa_checks.py table_checks + tests/test_compose_threat_model.py); the
    # legacy HTML <table>+rowspan grouping was retired because pipe-tables
    # have no rowspan and apply_prose_fixes._URL_PATH_RE mangled the long
    # closing tags `</thead>`, `</tbody>`, `</table>`. The Component cell now
    # repeats per row — standard Markdown practice and equivalent across
    # GitHub, pandoc→PDF, and weasyprint.
    return rendered, len(qualifying_ids)


def _curate_top_mitigations(
    floor: list[dict[str, Any]],
    extras_sorted: list[dict[str, Any]],
    llm_order: list[str],
    mit_min: int,
    mit_max: int,
) -> list[dict[str, Any]]:
    """Select the §1 Top-Mitigations leader-board: Critical-floor + curation.

    `floor` (always shown, coverage guarantee) + the most important extras.
    Extras are ordered by the LLM `llm_order` first (valid + de-duped against
    the floor), then by the caller's deterministic `extras_sorted` so the soft
    minimum can always be met and the no-fragment fallback is deterministic.
    `mit_max` is a SOFT clamp — the floor is never truncated even if it alone
    exceeds `mit_max` (Critical coverage wins). Pure function — unit-tested.
    """
    floor_ids = {m["id"] for m in floor}
    extras_by_id = {m["id"]: m for m in extras_sorted}
    ordered: list[dict[str, Any]] = []
    seen: set[str] = set()
    for mid in llm_order:
        m = extras_by_id.get(mid)
        if m and mid not in seen and mid not in floor_ids:
            ordered.append(m)
            seen.add(mid)
    for m in extras_sorted:
        if m["id"] not in seen and m["id"] not in floor_ids:
            ordered.append(m)
            seen.add(m["id"])
    budget = max(0, mit_max - len(floor))
    display = list(floor) + ordered[:budget]
    for m in ordered[budget:]:
        if len(display) >= mit_min:
            break
        display.append(m)
    return display


def _render_mitigations(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """Render the §1.x Management Summary Mitigations block as a SINGLE
    table covering only the immediate-action (P1) items, with a `Component`
    column and a single linked-mitigation column. P2+ items live in §9
    Mitigation Register; the table footer points the reader there.

    Schema:
        | Mitigation | Component | Priority | Addresses | Effort |
        - Mitigation: `[M-NNN — <title>](#m-nnn)` (one column, one link).
        - Component:  comma-joined list of component IDs whose threats
                      this mitigation addresses (cross-cutting → multiple).
        - Addresses:  bare-ID `[F-NNN](#f-nnn)` links (titles live in §8 /
                      §9 — the MS table stays scannable).
        - Effort / Priority: unchanged.

    Sort: severity asc (Critical first) → effort asc (Low first) →
    component → mid.

    Cut-off rule: the MS shows only P1 items. When zero P1 mitigations
    exist (rare — small/early-stage report), fall back to the top 5
    mitigations by severity to keep the section informative. The full
    inventory is always available in §9 Mitigation Register.
    """
    mitigations = ctx.yaml_data.get("mitigations", []) or []
    threats = _threat_lookup(ctx)
    components = _component_lookup(ctx)

    def _derive_priority(max_sev_rank: int) -> str:
        # _severity_rank: critical=0, high=1, medium=2, low=3
        return {0: "P1", 1: "P2", 2: "P3", 3: "P4"}.get(max_sev_rank, "P4")

    def enrich(m: dict[str, Any]) -> dict[str, Any]:
        mid = m.get("m_id") or m.get("id") or ""
        addressed_ids = m.get("addresses") or m.get("threat_ids") or []
        addressed = []
        max_sev = 99
        for tid in addressed_ids:
            t = threats.get(tid, {})
            sev = _severity_rank(t.get("effective_severity") or t.get("risk") or t.get("severity"))
            max_sev = min(max_sev, sev)
            # M3.12 — short title KEEPS the trailing `(<param>, <file>)` /
            # `(<file>)` token. A bare "SQL Injection" cell is structurally
            # useless because the reader has no idea which endpoint it
            # refers to. Strip ONLY the `:line` from the path so the
            # trailing token stays compact (`routes/login.ts` rather than
            # `routes/login.ts:34`). The §8 register still carries the
            # full file:line for click-through detail.
            # Strip any evidence-file token the Stage-1 title already carries
            # so the compact form below does not render it twice
            # (`… routes/login.ts (routes/login.ts)`).
            raw_title = _strip_embedded_evidence_file((t.get("title") or t.get("scenario_short") or "").strip(), t)
            # compact=True — Top Mitigations Addresses cells stack 4-5
            # findings via `<br/>`; the parens form is more scannable
            # than 4 repeated "in file" phrases per row.
            short_label = _shorten_title_for_xref(raw_title, t, compact=True)
            # Criticality dot — the Addresses column lists findings and so
            # carries the same severity glyph as every other finding cross-ref
            # (§8 register, asset/component tables). Empty when severity unknown.
            dot = ctx.severity_emoji(ctx.severity_for_ref(tid))
            addressed.append({"ref": tid, "label": short_label, "dot": dot})
        comp_ids = m.get("components") or []
        if not comp_ids:
            seen: set[str] = set()
            for tid in addressed_ids:
                # Threats may carry the component reference under either
                # `component_id` (canonical) or `component` (the field name
                # actually emitted by the orchestrator's YAML writer pre-2026-05).
                # Support both forms so the per-component grouping in the MS
                # Top Mitigations table doesn't fall back to "Cross-cutting"
                # for every row.
                t_dict = threats.get(tid) or {}
                c = t_dict.get("component_id") or t_dict.get("component")
                if c and c not in seen:
                    comp_ids.append(c)
                    seen.add(c)
        component_list = [{"id": cid, "name": (components.get(cid) or {}).get("name", cid)} for cid in comp_ids]
        priority = (m.get("priority") or "").strip().upper()
        if priority not in ("P1", "P2", "P3", "P4"):
            priority = _derive_priority(max_sev)
        return {
            "id": mid,
            "title": (m.get("title") or m.get("mitigation_title") or "").strip(),
            "component_list": component_list,
            "primary_component_id": comp_ids[0] if comp_ids else "",
            "addresses": addressed,
            "effort": m.get("effort", "Medium"),
            "priority": priority,
            "max_sev_rank": max_sev,
            "addressed_count": len(addressed),
        }

    enriched = [enrich(m) for m in mitigations]

    def _priority_rank(p: str) -> int:
        return {"P1": 0, "P2": 1, "P3": 2, "P4": 3}.get(p, 99)

    def _sort_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            rows,
            key=lambda r: (
                r.get("max_sev_rank", 9),
                _effort_rank(r["effort"]),
                ",".join(c["id"] for c in r.get("component_list", [])),
                r["id"],
            ),
        )

    # ----------------------------------------------------------------------
    # MS Top Mitigations — single central table, sub-grouped by component
    # via divider rows (post-2026-05 layout per user request).
    #
    # All P1+P2 mitigations live in one table; each component-bucket is
    # introduced by a "divider row" whose first cell carries the bold
    # component name and whose remaining cells are empty. Within a bucket,
    # rows are sorted P1 → P2 → severity (Critical first) → effort (Low
    # first) → ID. Cross-cutting mitigations (no primary_component_id) land
    # in a synthetic "Cross-cutting" bucket rendered last.
    #
    # Each row dict carries `is_divider: True|False` — the j2 template
    # branches on it to render either a divider row or a data row.
    # ----------------------------------------------------------------------
    p12_rows = [m for m in enriched if m.get("priority") in ("P1", "P2")]
    if not p12_rows:
        # Fall-back: top 6 mitigations by severity → effort, single bucket.
        p12_rows = _sort_rows(enriched)[:6]

    # Component ordering: preserve YAML `components[]` order so the user
    # sees the same component sequence as in §2.3 and §8. Unknown components
    # (somehow not in the YAML) appear after the known ones alphabetically.
    yaml_component_order: dict[str, int] = {}
    for i, c in enumerate(ctx.yaml_data.get("components", []) or []):
        cid = (c.get("id") or "").strip()
        if cid:
            yaml_component_order[cid] = i

    def _component_sort_key(cid: str) -> tuple[int, str]:
        return (yaml_component_order.get(cid, 10_000), cid or "~cross-cutting")

    def _row_sort_key(r: dict[str, Any]) -> tuple[int, int, int, int, str]:
        # Sort order:
        #   1. priority           (P1 first)
        #   2. -addressed_count   (high-leverage mitigations first — closes
        #                          the historic "P1 fix addressing 1 finding
        #                          outranks P1 fix addressing 4 findings"
        #                          symmetry break)
        #   3. severity rank      (Critical first inside same leverage tier)
        #   4. effort             (Low first)
        #   5. id                 (stable tie-break)
        return (
            {"P1": 0, "P2": 1, "P3": 2, "P4": 3}.get(r.get("priority", "P4"), 9),
            -int(r.get("addressed_count") or 0),
            r.get("max_sev_rank", 9),
            _effort_rank(r.get("effort", "Medium")),
            r.get("id") or "",
        )

    # 2026-05 user-request: cap the Management-Summary mitigations list at
    # the contract-configured `rows.max` (default 10). Overflow drops into
    # §9 Mitigation Register which carries the full P1/P2/P3 catalogue with
    # `Why` / `How` / verification detail. Cap applied AFTER priority-sort
    # so the highest-priority + highest-leverage items always survive.
    mit_max = (ctx.contract["sections"].get("mitigations") or {}).get("table", {}).get("rows", {}).get("max", 5)
    mit_min = (ctx.contract["sections"].get("mitigations") or {}).get("table", {}).get("rows", {}).get("min", 3)
    p12_total_before_cap = len(p12_rows)

    # ── Top-Mitigations selection: Critical-floor + LLM curation ──────────
    # The Management-Summary leader-board is no longer a blind top-N cut.
    #   1. Critical-floor (deterministic, non-negotiable): every mitigation
    #      that fixes at least one Critical finding is ALWAYS shown, so no
    #      Critical is left without a surfaced remediation — even if the LLM
    #      curation omits it.
    #   2. LLM curation (optional `.fragments/ms-top-mitigations.json`,
    #      authored by the Stage-2 renderer): an ordered list of the most
    #      important *additional* mitigations + a one-line rationale. The
    #      composer honours the LLM order for the extras but validates the
    #      ids, drops unknowns/dupes, and clamps to `rows.max`.
    #   3. Fallback (no fragment, e.g. quick mode): extras are ordered by the
    #      deterministic `_row_sort_key` — byte-identical to the legacy
    #      behaviour except the Critical-floor guarantee is now explicit.
    threats_by_id = _threat_lookup(ctx)

    def _is_critical(tid: str) -> bool:
        t = threats_by_id.get(tid) or {}
        return (t.get("effective_severity") or t.get("risk") or t.get("severity") or "").strip().lower() == "critical"

    def _covers_critical(m: dict[str, Any]) -> bool:
        return any(_is_critical(a.get("ref")) for a in (m.get("addresses") or []))

    floor = sorted([m for m in p12_rows if _covers_critical(m)], key=_row_sort_key)
    extras = [m for m in p12_rows if not _covers_critical(m)]

    llm_order: list[str] = []
    curation_rationale = ""
    try:
        _sel = _load_fragment(ctx, "top_mitigations", "ms-top-mitigations.json")
        if isinstance(_sel, dict):
            llm_order = [s for s in (_sel.get("selected") or []) if isinstance(s, str)]
            curation_rationale = (_sel.get("rationale") or "").strip()
    except FragmentError:
        pass  # optional — fall back to deterministic extras ordering

    p12_rows = _curate_top_mitigations(floor, sorted(extras, key=_row_sort_key), llm_order, mit_min, mit_max)
    p12_curated = bool(llm_order)
    p12_dropped = max(0, p12_total_before_cap - len(p12_rows))

    # Canonical C-NN resolution for the linked Component column. `cid` is the
    # mitigation's primary_component_id, which may be a slug (`express-backend`)
    # or already-canonical (`C-01`); `_component_lookup` aliases both and carries
    # `_canonical_id`. The link target matches the §8 register and the
    # Architecture Assessment "Affected components" cell: `[C-NN](#c-nn) — Name`.
    comp_lookup = _component_lookup(ctx)

    def _component_cell_label(cid: str) -> str:
        if not cid:
            return "Cross-cutting"
        c = comp_lookup.get(cid) or {}
        name = (c.get("name") or cid).strip()
        if re.match(r"^C-\d+$", cid):
            canonical = cid
        else:
            canonical = (c.get("_canonical_id") or "").strip()
        if canonical:
            return f"[{canonical}](#{canonical.lower()}) — {name}"
        return name

    # 2026-05-30 user request: the leader-board is sorted PRIORITY-FIRST, THEN
    # by component — i.e. all P1 rows (across components, in canonical component
    # order) come before any P2 row, rather than grouping all of one component's
    # rows together. The Component value is therefore carried PER ROW (the
    # template falls back to the row-level `component_label` when the group has
    # none) instead of as a once-per-component group label.
    def _display_sort_key(r: dict[str, Any]) -> tuple[Any, ...]:
        return (
            {"P1": 0, "P2": 1, "P3": 2, "P4": 3}.get(r.get("priority", "P4"), 9),
            _component_sort_key(r.get("primary_component_id") or ""),
            -int(r.get("addressed_count") or 0),
            r.get("max_sev_rank", 9),
            _effort_rank(r.get("effort", "Medium")),
            r.get("id") or "",
        )

    group_rows: list[dict[str, Any]] = []
    _row_number = 0
    for r in sorted(p12_rows, key=_display_sort_key):
        r["is_divider"] = False
        _row_number += 1
        r["number"] = _row_number
        r["component_label"] = _component_cell_label(r.get("primary_component_id") or "")
        group_rows.append(r)
    groups: list[dict[str, Any]] = [
        {
            "header": None,
            # Group-level label is None now — the Component column is filled
            # per row (see `component_label` on each row) so priority-first
            # ordering can interleave components.
            "component_label": None,
            "divider_label": None,
            "include_affects_column": False,
            "mitigations": group_rows,
        }
    ]

    total_count = len(enriched)
    p1_count = sum(1 for r in p12_rows if r.get("priority") == "P1")
    p2_count = sum(1 for r in p12_rows if r.get("priority") == "P2")
    # `rest_count` = items NOT eligible for the P1/P2 leader-board (P3+).
    # Computed against the pre-cap P1/P2 total so the "capped" and
    # "backlog" footer counters are disjoint and don't double-count.
    rest_count = max(0, total_count - p12_total_before_cap)

    # 2026-05 user-request: surface BOTH (a) P3 backlog overflow and (b)
    # P1/P2 entries that did not fit under `rows.max`. The MS leader-board
    # is the most-impactful subset; the full inventory always lives in §9.
    overflow_p12 = p12_dropped
    overflow_p3 = rest_count
    _floor_n = sum(1 for r in p12_rows if _covers_critical(r))
    intro = (
        f"Highest-impact P1/P2 mitigations — {len(p12_rows)} of "
        f"{p12_total_before_cap} qualifying ({total_count} total). "
        f"Full detail in [§10 Mitigation Register](#10-mitigation-register)."
    )
    if _floor_n:
        intro += f" All {_floor_n} mitigation(s) that fix a Critical finding are always listed here" + (
            f"; the remaining entries are curated by impact: {curation_rationale}"
            if (p12_curated and curation_rationale)
            else "."
        )
    footer_parts: list[str] = []
    if overflow_p12:
        footer_parts.append(
            f"{pluralize(overflow_p12, 'additional P1/P2 mitigation', 'additional P1/P2 mitigations')} "
            f"capped from the leader-board"
        )
    if overflow_p3:
        footer_parts.append(f"{pluralize(overflow_p3, 'P3 backlog item')}")
    if footer_parts:
        footer = (
            "*"
            + " · ".join(footer_parts)
            + " in [§10 Mitigation Register](#10-mitigation-register). "
            + "Sorted by priority (P1 first), then component, then leverage "
            + "(most findings first), severity (Critical first), and effort "
            + "(Low first).*"
        )
    else:
        footer = None

    tpl = env.get_template("mitigations.md.j2")
    return tpl.render(groups=groups, intro=intro, footer=footer).rstrip() + "\n"


def _render_operational_strengths(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """Render the Management Summary Operational Strengths 5-column table.

    Every column MUST be populated (the 2026-04-19 audit found blank
    `Architectural Control`, `Gap`, and `Mitigates` cells on every row).
    Fallback strategy:

      * Architectural Control — `control.architectural_control`, then
        `control.canonical_name`, then `control.name`, then a synthesised
        title from the `domain` field. Never empty.
      * Gap — `control.gap`, then `control.limitation`, then the word
        "None identified" (for adequate controls) or "See Section 7 for
        cross-cutting structural gaps." as a sentinel.
      * Mitigates — `control.mitigates_findings[]` linkified with the
        threat-lookup title. When the list is empty the cell reads
        "_Broad defence-in-depth; no single finding directly addressed._"
        so reviewers see that absence is intentional.
    """
    controls = _normalize_security_controls(ctx.yaml_data.get("security_controls", []))
    threats = _threat_lookup(ctx)
    # Tactical-hygiene controls (HTTP response-header hardening, etc.)
    # flagged `excluded_from_strengths: true` in architectural-controls.yaml.
    # Operational Strengths is reserved for architectural decisions; per-row
    # `show_in_strengths_by_default: true` may override the exclusion.
    _excluded = _strengths_excluded_names()

    def _control_token(c: dict[str, Any]) -> str:
        for key in ("architectural_control", "canonical_name", "name", "control_name", "control"):
            v = (c.get(key) or "").strip()
            if v:
                return "".join(ch.lower() for ch in v if ch.isalnum())
        return ""

    def eligible(c: dict[str, Any]) -> bool:
        eff = (c.get("effectiveness") or "").lower()
        # Row-level override always wins. Default: shown unless missing.
        row_override = c.get("show_in_strengths_by_default")
        if row_override is True:
            shown = True
        elif row_override is False:
            shown = False
        else:
            tok = _control_token(c)
            if tok and tok in _excluded:
                shown = False
            else:
                shown = eff != "missing"
        return eff in ("adequate", "partial", "weak") and shown

    filtered = [c for c in controls if eligible(c)]
    filtered.sort(
        key=lambda c: (
            _effectiveness_rank(c.get("effectiveness")),
            -len(c.get("mitigates_findings", []) or []),
            (c.get("architectural_control") or c.get("canonical_name") or c.get("name") or ""),
        )
    )
    max_rows = (
        (ctx.contract["sections"].get("operational_strengths") or {}).get("table", {}).get("rows", {}).get("max", 8)
    )

    def arch_control_name(c: dict[str, Any]) -> str:
        # `control` is the minimum-schema field per
        # schemas/threat-model.output.schema.yaml — STRIDE analyzers that
        # emit only the required fields (domain/control/effectiveness) used
        # to collapse to the `domain` fallback, producing duplicate-looking
        # rows (e.g. "IAM" appears 3× when 3 IAM controls exist with
        # distinct `control` values). Including `control` in the lookup
        # chain restores per-control identity for those minimum-schema
        # outputs without disturbing the rich-schema case (where
        # `architectural_control` takes precedence and is preferred).
        for key in ("architectural_control", "canonical_name", "name", "control_name", "control"):
            v = (c.get(key) or "").strip()
            if v:
                return v
        dom = (c.get("domain") or "").strip()
        if dom:
            return dom.replace("_", " ").title()
        return "Security Control"

    # Sentinel returned when no per-control gap text is authored AND no
    # per-control fact can be derived. Used by `show_gap` to decide
    # whether the Gap column should be emitted at all - repeating the
    # same fallback sentence in every row buries the rows that DO carry
    # specific gap text in visual noise.
    _GAP_FALLBACK = "—"

    # Effectiveness -> generic gap statement when no per-control text is
    # available. These are deliberately short (<= 60 chars) and stop
    # making promises about §7 (which may not exist at quick depth).
    _GAP_BY_EFFECTIVENESS: dict[str, str] = {
        "adequate": "None identified",
        "partial": "Covers only part of the attack surface",
        "weak": "Implementation uses a weak primitive",
        "missing": "Control not implemented",
    }

    def gap_text(c: dict[str, Any], eff: str) -> str:
        # 1. Author-supplied gap text wins.
        for key in ("gap", "limitation", "residual_risk", "weakness"):
            v = (c.get(key) or "").strip()
            if v:
                return v
        # 2. Derive a one-sentence gap fact from the control body itself.
        #    The implementation string very often contains the gap inline
        #    (e.g. "express-rate-limit on /rest/user/login only" — the
        #    "only" is the gap). When the string mentions "only" or a
        #    qualifier word, surface the post-qualifier clause.
        impl = c.get("implementation") or ""
        if isinstance(impl, dict):
            impl = impl.get("description") or ""
        impl = (impl or "").strip()
        # Look for "only <X>" / "<X> only" / "limited to <X>" / etc.
        # Cap at 80 chars so the cell stays scannable.
        m = re.search(
            r"\b(only|limited to|except|except for|but not|missing|disabled|wildcard|commented out|opt-?in|not enforced)\b[^.\n]{0,80}",
            impl,
            flags=re.IGNORECASE,
        )
        if m:
            tail = m.group(0).strip().rstrip(",;:")
            return (tail[:1].upper() + tail[1:])[:100]
        # 3. Generic by-effectiveness fallback. No §7 link - that
        #    section may have been suppressed at quick depth.
        return _GAP_BY_EFFECTIVENESS.get(eff, _GAP_FALLBACK)

    def mitigates_cell(c: dict[str, Any]) -> list[dict[str, str]]:
        mits = c.get("mitigates_findings") or []
        # P4 — auto-derive when empty. The STRIDE merger does not yet
        # populate `mitigates_findings`; without this fallback the
        # Operational Strengths Mitigates column is `—` on every row,
        # which the renderer then suppresses entirely (`show_mitigates`
        # stays False) and the user loses the control-to-finding
        # back-reference. Derivation maps the control's `domain` field
        # to a curated CWE set and finds matching threats.
        if not mits:
            mits = _derive_control_mitigates(c, ctx.yaml_data.get("threats") or [])
        out = []
        for ref in mits:
            label = (threats.get(ref) or {}).get("title", "")
            out.append({"ref": ref, "label": label})
        return out

    # M3.10 — Cluster fine-grained controls into categorical strength rows.
    # The legacy per-control loop (one row per X-Frame-Options /
    # X-Content-Type-Options / Access logging / …) buried the executive
    # signal under header trivia. The new flow:
    #   1. Pass the filtered control list (effectiveness ∈ adequate/partial/weak)
    #      through `_build_strength_clusters` to get one cluster per row.
    #   2. Each cluster row aggregates its members' implementations into a
    #      `<br/>`-joined compact list; effectiveness is the BEST member
    #      (Adequate beats Partial beats Weak — a cluster reading "Partial"
    #      means at least one constituent is Partial-or-better).
    #   3. Gap and Mitigates merge across members; the renderer's
    #      show_gap / show_mitigates booleans still work unchanged.
    #
    # If clustering returns nothing (clusters.yaml unavailable, every
    # control unmapped), the renderer falls back to the legacy per-control
    # layout so the table never goes blank.
    # Pass `all_threats` so the cluster builder can compute the
    # contradiction-aware effectiveness cap + populate Gap/Mitigates
    # deterministically from §8 instead of relying on per-control
    # `mitigates_findings[]` back-links the analyst rarely fills.
    all_threats_list = list((ctx.yaml_data or {}).get("threats") or [])
    clusters = _build_strength_clusters(filtered, threats, all_threats=all_threats_list)
    rendered_rows: list[dict[str, Any]] = []
    if clusters:
        for cl in clusters:
            # Skip the `_unmapped` catch-all cluster (label
            # "Other Operational Controls"). The cluster exists so the
            # renderer can map every control somewhere internally, but
            # presenting it as a strength row reads as "uncategorised
            # leftover" rather than a categorical strength. The §7
            # per-control breakdown still lists every control with its
            # effectiveness — readers who need the detail go there.
            if cl.get("id") == "_unmapped":
                continue
            members = cl.get("members") or []
            eff = cl.get("effectiveness") or "partial"
            # "What's in Place" cell composition (post-2026-05):
            #   line 1 — _<cluster description>_   ← 1-line italic purpose
            #   line 2 — implementation 1
            #   line 3 — implementation 2
            # The description gives the reader the WHY of the cluster
            # before they read the WHAT. Skipped when no template prose
            # exists in strength-clusters.yaml for the cluster id.
            what_lines: list[str] = []
            desc = (cl.get("description") or "").strip()
            if desc:
                what_lines.append(f"_{desc}_")
            for line in cl.get("implementations") or []:
                what_lines.append(line)
            what_in_place = "<br/>".join(what_lines) if what_lines else "—"
            gap = cl.get("gap") or _GAP_BY_EFFECTIVENESS.get(eff, _GAP_FALLBACK)
            # Mitigates with overflow indicator.
            mit_list = list(cl.get("mitigates") or [])
            mit_overflow = cl.get("mitigates_overflow", 0)
            if mit_overflow > 0:
                mit_list.append({"ref": None, "label": f"+{mit_overflow} more", "_overflow": True})
            rendered_rows.append(
                {
                    "label": cl["label"],
                    "architectural_control": cl["label"],  # back-compat key
                    "what_in_place": what_in_place,
                    "implementation": what_in_place,  # back-compat key
                    "effectiveness": eff,
                    "gap": gap,
                    "mitigates": mit_list,
                    "members": members,
                    "open_critical_count": cl.get("open_critical_count", 0),
                    "open_high_count": cl.get("open_high_count", 0),
                }
            )
        overflow = 0  # clustering covers all eligible controls
    else:
        # Legacy fallback — preserves the old one-row-per-control layout.
        for c in filtered[:max_rows]:
            eff = (c.get("effectiveness") or "partial").lower()
            impl = c.get("implementation")
            if isinstance(impl, dict):
                impl = impl.get("description") or ""
            implementation = (impl or "") or (c.get("description") or "") or (c.get("evidence") or "") or "—"
            if not isinstance(implementation, str):
                implementation = str(implementation)
            rendered_rows.append(
                {
                    "label": arch_control_name(c),
                    "architectural_control": arch_control_name(c),
                    "what_in_place": implementation.strip(),
                    "implementation": implementation.strip(),
                    "effectiveness": eff,
                    "gap": gap_text(c, eff),
                    "mitigates": mitigates_cell(c),
                }
            )
        overflow = max(0, len(filtered) - max_rows)

    # ---------------------------------------------------------------------
    # Post-2026-05 — "Operational Strengths" filter.
    # Only clusters that genuinely rate as a strength (Adequate or Partial)
    # may appear in this section. A row labelled "Weak — Bypassed by 3
    # Criticals" is by definition NOT a strength; surfacing it under the
    # "Operational Strengths" heading is semantically wrong and was the
    # complaint that drove this filter. Demoted (Weak-capped) clusters
    # remain visible in §7 Security Architecture, where the section name
    # matches the content.
    #
    # We count how many clusters were demoted by the contradiction-aware
    # cap so the empty-state banner can name the count instead of going
    # silent.
    # ---------------------------------------------------------------------
    demoted_count = 0
    demoted_labels: list[str] = []
    if clusters:
        kept: list[dict[str, Any]] = []
        for r in rendered_rows:
            eff = (r.get("effectiveness") or "").lower()
            if eff in ("adequate", "partial"):
                kept.append(r)
            else:
                demoted_count += 1
                demoted_labels.append(r.get("label", "?"))
        rendered_rows = kept

    # Gap and Mitigates are populated deterministically by
    # `_build_strength_clusters` (Gap from open H/C in cluster remit,
    # Mitigates from addressed-and-not-bypassed threats), so the 5-column
    # layout always carries usable signal in cluster-mode. The legacy
    # show_gap/show_mitigates suppression remains for the per-control
    # fallback path where the YAML may not provide enough data.
    _GENERIC_GAPS = set(_GAP_BY_EFFECTIVENESS.values()) | {_GAP_FALLBACK, ""}
    if clusters and rendered_rows:
        show_gap = True
        show_mitigates = True
    else:
        show_gap = any((r["gap"] or "").strip() not in _GENERIC_GAPS for r in rendered_rows)
        show_mitigates = any(bool(r["mitigates"]) for r in rendered_rows)

    # Optional overrides from fragment
    overrides_path = ctx.fragments_dir / "operational-strengths-overrides.json"
    overrides: dict[str, Any] = {
        "intentionally_vulnerable_or_deficient": "structurally deficient",
        "bottom_line": (
            "These controls narrow specific attack surfaces but none eliminates a Critical finding on its own."
        ),
    }
    if overrides_path.is_file():
        try:
            ov = json.loads(overrides_path.read_text(encoding="utf-8"))
            _validate_fragment("operational_strengths", ov, "operational-strengths-overrides.schema.json")
            overrides.update({k: v for k, v in ov.items() if v is not None})
        except FragmentError as e:
            ctx.warnings.append(f"operational-strengths overrides ignored: {e.detail}")

    # ---------------------------------------------------------------------
    # Empty-state banner. When every cluster has been demoted below
    # Partial — i.e. open H/C findings exist in every defensive remit —
    # the section reads as a one-line factual statement rather than an
    # empty table. The banner names how many clusters were demoted so
    # the reader knows the section isn't silently broken.
    # ---------------------------------------------------------------------
    # §7 is omitted at quick depth (render_security_architecture=false); never
    # emit a [§7](#7-security-architecture) cross-ref there or it dangles
    # (qa_checks has no section-anchor target validation to catch it).
    section7_present = bool(ctx.eval_context.get("render_security_architecture", True))
    sec7_clause = (
        "See [§7 Security Architecture](#7-security-architecture) for the full per-control assessment and "
        if section7_present
        else "See "
    )
    empty_banner = ""
    if clusters and not rendered_rows:
        if demoted_count > 0:
            sample = ", ".join(demoted_labels[:3])
            extra = f" and {demoted_count - 3} more" if demoted_count > 3 else ""
            empty_banner = (
                f"_No defensive cluster currently rates above Weak. "
                f"{demoted_count} cluster(s) — {sample}{extra} — were demoted "
                f"because §8 holds open Critical/High findings of the kind "
                f"each cluster is supposed to prevent. {sec7_clause}"
                f"[§10 Mitigation Register](#10-mitigation-register) for the "
                f"prioritised fix list._"
            )
        elif section7_present:
            empty_banner = (
                "_No defensive cluster currently rates above Weak. See "
                "[§7 Security Architecture](#7-security-architecture) for "
                "the full per-control assessment._"
            )
        else:
            empty_banner = (
                "_No defensive cluster currently rates above Weak. Per-control "
                "posture is catalogued in `threat-model.yaml → security_controls[]`._"
            )

    show_intro = ctx.eval_context.get("verdict_severity") in ("yellow", "red") and bool(rendered_rows)
    tpl = env.get_template("operational-strengths.md.j2")
    return (
        tpl.render(
            rows=rendered_rows,
            overflow_count=overflow,
            overrides=overrides,
            show_intro=show_intro,
            show_gap=show_gap,
            show_mitigates=show_mitigates,
            section7_present=section7_present,
            empty_banner=empty_banner,
        ).rstrip()
        + "\n"
    )


def _known_requirement_ids(ctx: RenderContext) -> dict[str, str]:
    """Map of requirement ID → source URL declared in ``.requirements.yaml``
    (``categories[].requirements[].id`` / ``.url``).

    Used to recognise a requirement that a STRIDE analyzer parked in a threat's
    ``remediation.reference`` (e.g. ``[SEC-AUTH-1](url)``) rather than in the
    ``violated_requirements`` array the traceability table reads — the
    field-name split between §8 ``Violated:`` annotations and the §7b/§MS table.
    Returns an empty map when the file is absent or unparseable so every caller
    degrades to the array-only behaviour (and the unit tests, which use a bare
    tmp dir, see no change).
    """
    path = ctx.output_dir / ".requirements.yaml"
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    out: dict[str, str] = {}
    for cat in data.get("categories", []) or []:
        if not isinstance(cat, dict):
            continue
        for req in cat.get("requirements", []) or []:
            if not isinstance(req, dict):
                continue
            rid = (req.get("id") or "").strip()
            if rid and rid not in out:
                out[rid] = (req.get("url") or "").strip()
    return out


_REQ_VIOLATION_STATUSES = frozenset({"FAIL", "PARTIAL", "ANTI-PATTERN"})
_REQ_NON_VIOLATION_STATUSES = frozenset({"PASS", "N/A", "NA", "NOT APPLICABLE", "UNVERIFIABLE", "NOT OBSERVABLE"})
_REQ_HEADER_TOKENS = frozenset({"id", "requirement", "requirement id"})


def _normalise_requirement_status(raw: Any) -> str:
    """Return a stable compliance status token from a §7b table cell."""
    text = re.sub(r"<[^>]+>", " ", str(raw or ""))
    text = re.sub(r"[*_`]", "", text).upper()
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return ""
    if "ANTI" in text and "PATTERN" in text:
        return "ANTI-PATTERN"
    if "PARTIAL" in text:
        return "PARTIAL"
    if "FAIL" in text:
        return "FAIL"
    if "PASS" in text:
        return "PASS"
    if "UNVERIFIABLE" in text:
        return "UNVERIFIABLE"
    if "NOT OBSERVABLE" in text:
        return "NOT OBSERVABLE"
    if "NOT APPLICABLE" in text:
        return "NOT APPLICABLE"
    if re.search(r"\bN\s*/\s*A\b|\bNA\b", text):
        return "N/A"
    return text.split(" ", 1)[0]


def _extract_requirement_id_from_cell(cell: str, known_ids: set[str]) -> str:
    """Extract the declared requirement ID from a Markdown table cell."""
    text = re.sub(r"<br\s*/?>", " ", cell or "", flags=re.IGNORECASE)
    # Prefer exact declared IDs, longest first so SEC-1 does not pre-empt SEC-10.
    for rid in sorted(known_ids, key=len, reverse=True):
        if re.search(r"(?<![\w-])" + re.escape(rid) + r"(?![\w-])", text):
            return rid
    # Fallback for org-specific IDs in fragments when .requirements.yaml is absent.
    m = re.search(r"`([^`]+)`", text)
    if m:
        return m.group(1).strip()
    m = re.search(r"\[([A-Z][A-Z0-9_.:-]*-\d+[A-Z0-9_.:-]*)\]", text, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r"(?<![\w-])([A-Z][A-Z0-9_.:-]*-\d+[A-Z0-9_.:-]*)(?![\w-])", text, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _split_md_table_row(line: str) -> list[str]:
    """Split a simple Markdown table row into cells.

    The requirements fragment is generated by the model and uses ordinary
    pipe tables. This splitter respects escaped pipes, which is enough for the
    report tables without pulling in a full Markdown parser.
    """
    s = line.strip()
    if not s.startswith("|"):
        return []
    if s.endswith("|"):
        s = s[:-1]
    s = s[1:]
    cells: list[str] = []
    cur: list[str] = []
    escaped = False
    for ch in s:
        if escaped:
            cur.append(ch)
            escaped = False
            continue
        if ch == "\\":
            cur.append(ch)
            escaped = True
            continue
        if ch == "|":
            cells.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    cells.append("".join(cur).strip())
    return cells


def _requirements_status_map(ctx: RenderContext) -> dict[str, str]:
    """Requirement ID -> PASS/FAIL/PARTIAL/N/A status from authoritative outputs.

    Phase 8b's Markdown fragment is currently the only artifact that carries the
    full PASS/FAIL/N/A table. Threats can still contain stale requirement IDs, so
    the renderer uses this map as a guardrail: only FAIL/PARTIAL/ANTI-PATTERN
    rows are eligible for violated-requirement traceability and §10 Fulfills
    Requirements lines. `.phase-8b-violations.json`, when present, supplements
    the map but never overrides an explicit full-table status.
    """
    known_ids = set(_known_requirement_ids(ctx))
    out: dict[str, str] = {}

    frag_path = ctx.output_dir / ".fragments" / "requirements-compliance.md"
    if frag_path.is_file():
        try:
            lines = frag_path.read_text(encoding="utf-8").splitlines()
        except Exception:
            lines = []
        header: list[str] | None = None
        req_idx = status_idx = -1
        for line in lines:
            cells = _split_md_table_row(line)
            if not cells:
                continue
            lowered = [re.sub(r"[*_`]", "", c).strip().lower() for c in cells]
            if any(c in _REQ_HEADER_TOKENS for c in lowered) and "status" in lowered:
                header = lowered
                req_idx = next(
                    (i for i, c in enumerate(header) if c in _REQ_HEADER_TOKENS),
                    -1,
                )
                status_idx = header.index("status")
                continue
            if header is None:
                continue
            # Markdown delimiter row.
            if all(re.fullmatch(r":?-{3,}:?", c.strip()) for c in cells):
                continue
            if req_idx < 0 or status_idx < 0 or len(cells) <= max(req_idx, status_idx):
                continue
            rid = _extract_requirement_id_from_cell(cells[req_idx], known_ids)
            status = _normalise_requirement_status(cells[status_idx])
            if rid and status and (status in _REQ_VIOLATION_STATUSES or status in _REQ_NON_VIOLATION_STATUSES):
                out.setdefault(rid, status)

    phase8b = ctx.output_dir / ".phase-8b-violations.json"
    if phase8b.is_file():
        try:
            data = json.loads(phase8b.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        for item in data.get("violations", []) or []:
            if not isinstance(item, dict):
                continue
            rid = (item.get("requirement_id") or "").strip()
            status = _normalise_requirement_status(item.get("status"))
            if rid and status and (status in _REQ_VIOLATION_STATUSES or status in _REQ_NON_VIOLATION_STATUSES):
                out.setdefault(rid, status)

    return out


def _extract_finding_ids_from_cell(cell: str) -> list[str]:
    out: list[str] = []
    for prefix, num in re.findall(r"(?<![\w-])([FT])-(\d{1,4})(?![\w-])", cell or "", re.IGNORECASE):
        fid = f"F-{int(num):03d}" if len(num) <= 3 else f"F-{num}"
        if fid not in out:
            out.append(fid)
    return out


def _requirements_evidence_findings_map(ctx: RenderContext) -> dict[str, list[str]]:
    """Requirement ID -> finding IDs explicitly cited by the §7b compliance row."""
    known_ids = set(_known_requirement_ids(ctx))
    out: dict[str, list[str]] = {}
    frag_path = ctx.output_dir / ".fragments" / "requirements-compliance.md"
    if not frag_path.is_file():
        return out
    try:
        lines = frag_path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return out

    header: list[str] | None = None
    req_idx = -1
    evidence_indexes: list[int] = []
    for line in lines:
        cells = _split_md_table_row(line)
        if not cells:
            continue
        lowered = [re.sub(r"[*_`]", "", c).strip().lower() for c in cells]
        if any(c in _REQ_HEADER_TOKENS for c in lowered) and "status" in lowered:
            header = lowered
            req_idx = next((i for i, c in enumerate(header) if c in _REQ_HEADER_TOKENS), -1)
            evidence_indexes = [
                i for i, c in enumerate(header) if c in {"evidence", "linked threats", "linked findings", "findings"}
            ]
            continue
        if header is None:
            continue
        if all(re.fullmatch(r":?-{3,}:?", c.strip()) for c in cells):
            continue
        if req_idx < 0 or len(cells) <= req_idx:
            continue
        rid = _extract_requirement_id_from_cell(cells[req_idx], known_ids)
        if not rid:
            continue
        fids: list[str] = []
        for idx in evidence_indexes:
            if len(cells) <= idx:
                continue
            for fid in _extract_finding_ids_from_cell(cells[idx]):
                if fid not in fids:
                    fids.append(fid)
        if fids:
            out.setdefault(rid, fids)
    return out


def _requirement_is_traceable_violation(rid: str, status_map: dict[str, str]) -> bool:
    """True when a requirement should appear in violated-requirement traceability."""
    if not status_map:
        return True
    status = status_map.get((rid or "").strip())
    if not status:
        # Missing from the full table is suspicious, but preserving the legacy row
        # is safer than hiding a real finding. QA/prompt rules handle the drift.
        return True
    return status in _REQ_VIOLATION_STATUSES


def _format_requirement_link(rid: str, known_ids: dict[str, str]) -> str:
    url = (known_ids.get(rid) or "").strip()
    return f"[`{rid}`]({url})" if url else f"`{rid}`"


def _requirement_blueprints(ctx: RenderContext) -> dict[str, str]:
    """Map requirement ID → a rendered blueprint cell, derived deterministically
    from the requirements↔blueprint cross-reference in ``.requirements.yaml``.

    Each ``blueprints[].sections[].references[].id`` names a requirement that
    section addresses, so a violated requirement can be linked to the blueprint
    section that remediates it without depending on a STRIDE analyzer having set
    ``remediation.blueprint`` (the analyzers reliably attach requirement IDs but
    routinely skip the optional blueprint lookup). First section in file order to
    reference a requirement wins. Cell shape matches the analyzer's
    ``[{bp.id}]({section.url}) — {section.title}`` so §8 ``Violated:`` and the
    §7b/§MS table render identically whether the link came from the LLM or here.
    Returns ``{}`` when the file is absent/unparseable or carries no blueprints.
    """
    path = ctx.output_dir / ".requirements.yaml"
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    out: dict[str, str] = {}
    for bp in data.get("blueprints", []) or []:
        if not isinstance(bp, dict):
            continue
        bid = (bp.get("id") or "").strip()
        if not bid:
            continue
        for sec in bp.get("sections", []) or []:
            if not isinstance(sec, dict):
                continue
            url = (sec.get("url") or bp.get("url") or "").strip()
            title = (sec.get("title") or "").strip()
            for ref in sec.get("references", []) or []:
                rid = (ref.get("id") or "").strip() if isinstance(ref, dict) else ""
                if rid and rid not in out:
                    out[rid] = f"[{bid}]({url})" + (f" — {title}" if title else "")
    return out


def _requirement_ids_for_threat(t: dict[str, Any], known_ids: dict[str, str] | set[str]) -> list[str]:
    """Requirement IDs a threat evidences — order-preserving, de-duplicated.

    Sources, in order: the canonical ``violated_requirements[]`` array, the
    legacy singular ``requirement_id``, and — when ``known_ids`` is non-empty —
    any declared requirement ID found in ``remediation.reference``, whether the
    analyzer wrote it bracketed (``[ID]`` / ``[ID](url)``) or bare (``IF-002``).
    This closes the field-name split: STRIDE analyzers write a matched
    requirement into ``remediation.reference`` instead of the array, so the
    finding shows in §8 (``Violated:``) but was invisible to the §7b/§MS table.
    Matching against the declared-ID set keeps this prefix-agnostic and ignores
    OWASP/CWE references (they are not declared requirement IDs).
    """
    out: list[str] = []

    def _add(rid: Any) -> None:
        s = (rid or "").strip()
        if s and s not in out:
            out.append(s)

    for rid in t.get("violated_requirements") or []:
        _add(rid)
    if t.get("requirement_id"):
        _add(t["requirement_id"])
    if known_ids:
        rem = t.get("remediation") if isinstance(t.get("remediation"), dict) else {}
        ref = rem.get("reference") if isinstance(rem, dict) else None
        if isinstance(ref, str) and ref:
            # Bracketed tokens first (preserves reference order for `[ID](url)`).
            for tok in re.findall(r"\[([^\]]+)\]", ref):
                if tok.strip() in known_ids:
                    _add(tok)
            # Bare IDs: analyzers sometimes write `IF-002` without the brackets
            # the matcher above keys on. Recover any declared ID that appears as
            # a standalone token. Only IDs in known_ids match, so CWE/OWASP refs
            # never do; the word-boundary guard avoids partial hits (IF-0021).
            for kid in known_ids:
                if kid not in out and re.search(r"(?<![\w-])" + re.escape(kid) + r"(?![\w-])", ref):
                    _add(kid)
    return out


def _build_requirements_mapping_rows(ctx: RenderContext) -> list[dict[str, Any]]:
    """Deterministic requirement → finding → mitigation traceability.

    Reads `threat-model.yaml` threats[] (no fragment parsing). A requirement
    that FAILED in Phase 8b became a threat carrying `violated_requirements`
    (the requirement IDs it evidences) plus `mitigation_ids` (the measures that
    remediate it). Group those threats by requirement ID so each requirement
    maps to its findings (F-NNN), its mitigations (M-NNN), a blueprint (when a
    `architectural-anti-pattern` / `remediation.blueprint` threat supplied one),
    and the max severity across its findings. The measure set is also augmented
    via the reverse link `mitigation.fulfills_requirements` so a mitigation that
    declares the requirement is included even if no threat lists it.

    Rows are sorted critical → low, then by requirement ID. Returns [] when no
    requirement-linked threat exists (e.g. all requirements PASS).
    """
    threats = list((ctx.yaml_data or {}).get("threats", []) or [])
    known_ids = _known_requirement_ids(ctx)
    status_map = _requirements_status_map(ctx)
    evidence_fids = _requirements_evidence_findings_map(ctx)
    threat_by_visible: dict[str, dict[str, Any]] = {}
    for t in threats:
        tid = (t.get("t_id") or t.get("id") or "").strip().upper()
        m = re.match(r"^[TF]-(\d+)$", tid)
        visible = f"F-{m.group(1)}" if m else tid
        if visible:
            threat_by_visible.setdefault(visible, t)
    by_req: dict[str, dict[str, Any]] = {}
    for t in threats:
        reqs = _requirement_ids_for_threat(t, known_ids)
        if not reqs:
            continue
        tid = (t.get("t_id") or t.get("id") or "").strip().upper()
        m = re.match(r"^[TF]-(\d+)$", tid)
        visible = f"F-{m.group(1)}" if m else tid
        if not visible:
            continue
        risk = (t.get("risk") or t.get("severity") or "").strip().lower()
        mids = [mid for mid in (t.get("mitigation_ids") or t.get("mitigations") or []) if mid]
        rem = t.get("remediation") if isinstance(t.get("remediation"), dict) else {}
        blueprint = _format_blueprint_cell(rem.get("blueprint")) if rem else ""
        for rid in reqs:
            rid_s = (rid or "").strip()
            if not rid_s:
                continue
            if not _requirement_is_traceable_violation(rid_s, status_map):
                continue
            slot = by_req.setdefault(
                rid_s,
                {
                    "req_id": rid_s,
                    "status": status_map.get(rid_s, ""),
                    "findings": [],
                    "measures": [],
                    "blueprint": "",
                },
            )
            if not slot.get("status") and status_map.get(rid_s):
                slot["status"] = status_map[rid_s]
            if visible not in (f[0] for f in slot["findings"]):
                slot["findings"].append((visible, risk))
            for mid in mids:
                if mid not in slot["measures"]:
                    slot["measures"].append(mid)
            if blueprint and not slot["blueprint"]:
                slot["blueprint"] = blueprint

    # Augment measures via the reverse link: a mitigation may declare
    # `fulfills_requirements: [REQ-ID]` even when no threat names it in
    # `mitigation_ids`. Only enrich requirements that already have a finding
    # row (the table is violated-requirement scoped); append after the
    # threat-derived measures so ordering stays deterministic.
    if by_req:
        for m in (ctx.yaml_data or {}).get("mitigations", []) or []:
            if not isinstance(m, dict):
                continue
            mid = m.get("m_id") or m.get("id")
            if not mid:
                continue
            for rid in m.get("fulfills_requirements") or []:
                slot = by_req.get((rid or "").strip())
                if slot and mid not in slot["measures"]:
                    slot["measures"].append(mid)

    # When Phase 8b's human-facing compliance row explicitly cites findings,
    # treat that as the authoritative requirement->finding edge. This repairs
    # stale semantic matches where a threat kept an old `violated_requirements`
    # value even though the compliance table links the requirement to a different
    # finding. If the row cites no findings, fall back to the threat-derived edge.
    for rid, fids in evidence_fids.items():
        slot = by_req.get(rid)
        if not slot or not _requirement_is_traceable_violation(rid, status_map):
            continue
        findings: list[tuple[str, str]] = []
        measures: list[str] = []
        for fid in fids:
            threat = threat_by_visible.get(fid, {})
            risk = (threat.get("risk") or threat.get("severity") or "").strip().lower()
            if fid not in (f[0] for f in findings):
                findings.append((fid, risk))
            for mid in threat.get("mitigation_ids") or threat.get("mitigations") or []:
                if mid and mid not in measures:
                    measures.append(mid)
        if findings:
            slot["findings"] = findings
            slot["measures"] = measures

    # Re-apply reverse mitigation links after evidence-based finding correction:
    # a mitigation may declare `fulfills_requirements` without being listed on
    # the finding rows that Phase 8b cited.
    if by_req:
        for m in (ctx.yaml_data or {}).get("mitigations", []) or []:
            if not isinstance(m, dict):
                continue
            mid = m.get("m_id") or m.get("id")
            if not mid:
                continue
            for rid in m.get("fulfills_requirements") or []:
                slot = by_req.get((rid or "").strip())
                if slot and mid not in slot["measures"]:
                    slot["measures"].append(mid)

    # Deterministic blueprint fallback: when no STRIDE analyzer attached a
    # remediation.blueprint, derive each requirement's blueprint from the
    # requirements↔blueprint cross-reference in .requirements.yaml. Keeps the
    # Blueprint column populated from the loaded baseline even when the LLM
    # skipped the optional lookup (LLM-attached blueprints still take priority).
    if by_req:
        bp_map = _requirement_blueprints(ctx)
        if bp_map:
            for rid, slot in by_req.items():
                if not slot["blueprint"]:
                    cell = bp_map.get(rid)
                    if cell:
                        slot["blueprint"] = cell

    rows = list(by_req.values())
    for r in rows:
        best = min(r["findings"], key=lambda f: _severity_rank(f[1]), default=("", ""))
        r["risk_word"] = best[1]
        r["risk_rank"] = _severity_rank(best[1])
    rows.sort(key=lambda r: (r["risk_rank"], r["req_id"]))
    return rows


def _format_blueprint_cell(blueprint: Any) -> str:
    """Render a threat's `remediation.blueprint` value as a table cell.

    Accepts either the STRIDE-attached dict ({id, url, title, section}) or a
    pre-formatted string. Returns "" when absent so callers can fall back to a
    dash.
    """
    if not blueprint:
        return ""
    if isinstance(blueprint, str):
        return blueprint.strip()
    if isinstance(blueprint, dict):
        bid = (blueprint.get("id") or "").strip()
        url = (blueprint.get("url") or "").strip()
        title = (blueprint.get("section") or blueprint.get("title") or "").strip()
        label = bid or title or "blueprint"
        link = f"[{label}]({url})" if url else label
        if title and title != label:
            link = f"{link} · {title}"
        return link
    return ""


def _render_requirements_mapping_table(
    ctx: RenderContext, rows: list[dict[str, Any]], *, limit: int | None = None
) -> str:
    """Render the requirement→finding→mitigation rows as a Markdown table.

    Columns: Requirement · Status · Risk · Findings · Maßnahmen · Guidance. Finding
    cells link to §8 (`#f-nnn`); mitigation cells link to §9 (`#m-nnn`). The
    requirement ID links to its source URL from `.requirements.yaml` when known.
    Returns "" for an empty row set.
    """
    if not rows:
        return ""
    shown = rows[:limit] if limit else rows
    known_ids = _known_requirement_ids(ctx)
    lines = [
        "| Requirement | Status | Risk | Findings | Maßnahmen | Guidance |",
        "|-------------|--------|------|----------|-----------|----------|",
    ]
    for r in shown:
        risk_word = (r.get("risk_word") or "").strip()
        emoji = _TOP_THREATS_SEVERITY_EMOJI.get(risk_word.lower(), "")
        risk_cell = f"{emoji} {risk_word.title()}".strip() or "—"
        _status_raw = (r.get("status") or "FAIL").strip() or "FAIL"
        _status_emoji = {"FAIL": "❌", "PARTIAL": "⚠️", "ANTI-PATTERN": "⚠️"}.get(_status_raw, "")
        status_cell = f"{_status_emoji} {_status_raw}".strip() if _status_emoji else _status_raw

        # Per-item annotation (2026-06-04): findings carry their severity dot
        # and measures their Variant-B priority prefix — the same vocabulary as
        # every other linked ref. The row-level Risk column shows the requirement
        # aggregate; the per-finding dots disambiguate when findings differ.
        def _find_chip(fid: str) -> str:
            e = ctx.severity_emoji(ctx.severity_for_ref(fid))
            return f"{e} [{fid}](#{fid.lower()})" if e else f"[{fid}](#{fid.lower()})"

        find_cell = ", ".join(_find_chip(fid) for fid, _ in r["findings"]) or "—"
        meas_cell = (
            ", ".join(f"{_measure_prio_prefix(ctx, mid)}[{mid}](#{mid.lower()})" for mid in r["measures"]) or "—"
        )
        bp_cell = r.get("blueprint") or "—"
        req_cell = _format_requirement_link(r["req_id"], known_ids)
        lines.append(f"| {req_cell} | {status_cell} | {risk_cell} | {find_cell} | {meas_cell} | {bp_cell} |")
    out = "\n".join(lines)
    if limit and len(rows) > limit:
        out += (
            f"\n\n_{len(rows) - limit} further requirement(s) in "
            "[§7b — Requirements Compliance](#7b-requirements-compliance)._"
        )
    return out


def _render_requirements_scope_note(ctx: RenderContext) -> str:
    """Deterministic §7b scope note for requirement applicability.

    The LLM fragment owns the per-row evidence, but scope provenance should not
    depend on prose generation. This note makes explicit whether a real org
    profile/compliance scope was active or a generic baseline was applied.
    """
    req_path = ctx.output_dir / ".requirements.yaml"
    req_count = 0
    cat_count = 0
    bp_count = 0
    source_title = "configured requirements source"
    source_url = ""
    source_description = ""
    if req_path.is_file():
        try:
            data = yaml.safe_load(req_path.read_text(encoding="utf-8")) or {}
        except Exception:
            data = {}
        cats = [c for c in data.get("categories", []) or [] if isinstance(c, dict)]
        cat_count = len(cats)
        for cat in cats:
            req_count += len([r for r in cat.get("requirements", []) or [] if isinstance(r, dict)])
        bp_count = len([b for b in data.get("blueprints", []) or [] if isinstance(b, dict)])
        source_description = (data.get("description") or "").strip()
        for meta in data.get("sources_meta", []) or []:
            if isinstance(meta, dict) and meta.get("type") == "requirement":
                source_title = (meta.get("title") or source_title).strip()
                source_url = (meta.get("reference_url") or meta.get("crawl_url") or "").strip()
                break

    skill_path = ctx.output_dir / ".skill-config.json"
    skill_cfg: dict[str, Any] = {}
    if skill_path.is_file():
        try:
            skill_cfg = json.loads(skill_path.read_text(encoding="utf-8"))
        except Exception:
            skill_cfg = {}
    org_profile = skill_cfg.get("org_profile") if isinstance(skill_cfg.get("org_profile"), dict) else {}
    org_active = bool(org_profile.get("active"))
    compliance_scope = (ctx.yaml_data.get("meta", {}) or {}).get("compliance_scope") or []
    repo_scope = skill_cfg.get("scope") or (ctx.yaml_data.get("meta", {}) or {}).get("scope") or []

    source_label = f"[{source_title}]({source_url})" if source_url else source_title
    lines = ["### Requirement Scope", ""]
    if req_count:
        lines.append(
            f"- Source: {source_label}; {req_count} requirements in {cat_count} categories"
            + (f", plus {bp_count} blueprint guidance entries." if bp_count else ".")
        )
    else:
        lines.append(f"- Source: {source_label}.")
    if org_active:
        lines.append(
            "- Policy context: organization profile active; configured requirements are treated as the applicable policy set."
        )
    else:
        lines.append(
            "- Policy context: no organization profile is active; this is a generic baseline assessment, not a project-specific compliance attestation."
        )
    if compliance_scope:
        lines.append(f"- Compliance scope: {', '.join(str(x) for x in compliance_scope)}.")
    else:
        lines.append(
            "- Compliance scope: no explicit compliance_scope was configured; applicability is inferred from repository evidence."
        )
    if repo_scope:
        lines.append(f"- Repository scope filter: {', '.join(str(x) for x in repo_scope)}.")
    lines.append(
        "- Traceability rule: only FAIL, PARTIAL and ANTI-PATTERN rows are treated as violated requirements; PASS, N/A, NOT OBSERVABLE and UNVERIFIABLE rows are excluded from violation traceability."
    )
    if bp_count:
        lines.append(
            "- Blueprint entries are implementation guidance only; they do not add requirements or change PASS/FAIL counts."
        )
    if source_description and "generic baseline" in source_description.lower() and not org_active:
        lines.append(
            "- Baseline note: the loaded requirements file describes itself as generic; replace it with an organization-specific catalog for contractual reporting."
        )
    return "\n".join(lines) + "\n"


def _render_requirements_compliance(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """§7b — inline the LLM compliance narrative (status/priority/evidence,
    which the yaml does not carry) then append a deterministic Requirements
    Traceability table built from threat-model.yaml threats.

    The traceability table is built from threat-model.yaml and is therefore
    always available; the LLM narrative fragment is not. If the fragment is
    missing or invalid we still render the section with the deterministic table
    (and a one-line note) rather than soft-skipping the whole section — losing
    the requirement→finding→mitigation mapping is worse than losing the prose."""
    rows = _build_requirements_mapping_rows(ctx)
    table = _render_requirements_mapping_table(ctx, rows)
    try:
        body = _render_markdown_fragment(ctx, "requirements_compliance", section)
    except FragmentError:
        if not table:
            raise  # no fragment AND no mapping → genuinely nothing to show
        heading = (section.get("heading") or "## 7b. Requirements Compliance").strip()
        body = (
            f"{heading}\n\n"
            "> ⚠ The requirements compliance narrative fragment was not "
            "authored; the deterministic traceability table is shown below.\n"
        )
    scope_note = _render_requirements_scope_note(ctx)
    if scope_note:
        body = body.rstrip() + "\n\n" + scope_note
    if table:
        body = (
            body.rstrip()
            + "\n\n### Requirements Traceability\n\n"
            + "Deterministic mapping of each FAIL, PARTIAL or ANTI-PATTERN requirement "
            + "to the findings that evidence it and the mitigations that remediate it. "
            + "PASS, N/A, NOT OBSERVABLE and UNVERIFIABLE requirements are deliberately "
            + "excluded. Guidance links are non-normative blueprint references, not "
            + "additional requirements.\n\n"
            + table
            + "\n"
        )
    return body


def _enrich_affected_components(ctx: RenderContext, items: list[dict] | None) -> None:
    """Rewrite each item's ``affected_components[]`` into ``{id, name}`` dicts,
    resolving the display name from the SAME ``_component_lookup`` used by the
    structural-threats / Top Threats tables. The MS callout fragments
    (ms-anti-patterns.json, ms-ai-exposure.json) carry bare ``C-NN`` id strings;
    without this the callout links render as a bare ``[C-02](#c-02)`` while the
    same component reads ``[C-02](#c-02) — Python Analysis Script Engine``
    everywhere else. Resolving through the shared lookup guarantees the names
    are byte-identical across the whole report.
    """
    if not items:
        return
    components = _component_lookup(ctx)

    def _name_for(cid: str) -> str:
        comp = components.get(cid) or components.get(cid.upper()) or {}
        return (comp.get("name") or "").strip()

    for it in items:
        refs = it.get("affected_components")
        if not isinstance(refs, list):
            continue
        enriched: list[dict[str, str]] = []
        for r in refs:
            if isinstance(r, dict):
                cid = (r.get("id") or "").strip()
                name = (r.get("name") or "").strip() or _name_for(cid)
            elif isinstance(r, str):
                cid = r.strip()
                name = _name_for(cid)
            else:
                continue
            entry = {"id": cid} if cid else {}
            if name:
                entry["name"] = name
            if entry:
                enriched.append(entry)
        it["affected_components"] = enriched


def _render_architectural_anti_patterns(ctx: RenderContext, env: jinja2.Environment) -> str:
    """Render the optional '### Architectural Anti-Patterns' MS callout.

    Surfaces the named design-level defects the report already articulates in
    §7 prose (e.g. "SPA without BFF", "JWT in localStorage") at executive level.
    LLM-authored fragment `ms-anti-patterns.json` — OPTIONAL: the threat-renderer
    writes it only when ≥1 genuine architectural anti-pattern is present, so an
    absent file renders nothing (clean architectures stay uncluttered). Reuses
    the shared `format_weakness_*` filters so finding/component linkification
    matches the rest of the Management Summary.
    """
    if not (ctx.fragments_dir / "ms-anti-patterns.json").is_file():
        return ""
    data = _load_fragment(ctx, "architectural_anti_patterns", "ms-anti-patterns.json")
    _validate_fragment("architectural_anti_patterns", data, "anti-patterns.schema.json")
    if not (data.get("anti_patterns") or []):
        return ""
    _enrich_affected_components(ctx, data.get("anti_patterns"))
    tpl = env.get_template("anti-patterns.md.j2")
    return tpl.render(data=data)


def _render_ai_exposure(ctx: RenderContext, env: jinja2.Environment) -> str:
    """Render the optional '### AI / LLM Exposure' MS callout.

    Surfaces the architectural AI/LLM risks the report already articulates via the
    OWASP LLM Top-10 lens (prompt injection, excessive agency, model supply chain,
    …) at executive level, so the fact that the system embeds an LLM/agent — and
    its headline risks — is visible in the Management Summary instead of scattered
    across §7 control prose. LLM-authored fragment `ms-ai-exposure.json` —
    OPTIONAL: the threat-renderer writes it only when the system has an LLM/AI
    surface (KNOWN_LLM_PATTERNS != none), so an absent file renders nothing and a
    repo with no AI usage pays zero cost (no schema load, no template). Reuses the
    shared `format_weakness_*` filters so finding/component linkification matches
    the rest of the Management Summary.
    """
    if not (ctx.fragments_dir / "ms-ai-exposure.json").is_file():
        return ""
    data = _load_fragment(ctx, "ai_exposure_ms", "ms-ai-exposure.json")
    _validate_fragment("ai_exposure_ms", data, "ai-exposure.schema.json")
    if not (data.get("ai_risks") or []):
        return ""
    _enrich_affected_components(ctx, data.get("ai_risks"))
    tpl = env.get_template("ai-exposure.md.j2")
    section7_present = bool(ctx.eval_context.get("render_security_architecture", True))
    body = tpl.render(data=data, section7_present=section7_present)
    # Provenance (2026-06-26): if this AI callout was restored from a deeper
    # prior run (restore_preserved_sections recorded it), mark it as carried.
    prov = _carried_provenance(ctx.output_dir)
    if prov and "ai_exposure_ms" in prov.get("sections", []):
        banner = _carried_forward_banner(prov.get("origin_depth", ""), prov.get("origin_date", ""))
        body = banner + "\n\n" + body
    return body


def _carried_provenance(output_dir: Path) -> dict | None:
    """Read .preserved-provenance.json (which sections were carried forward from a
    deeper prior run on this shallow re-run). Returns None when absent."""
    path = output_dir / ".preserved-provenance.json"
    if not path.is_file():
        return None
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) and d.get("sections") else None
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def _render_requirements_compliance_ms(ctx: RenderContext) -> str:
    """Derive the ### Requirements Compliance MS subsection.

    Extracts the baseline link + PASS/FAIL/ANTI-PATTERN/PARTIAL summary line
    from the fragment when available, then appends a deterministic compact
    traceability table built from threat-model.yaml.

    Falls back gracefully when the fragment has been cleaned up (post-QA
    runtime_cleanup removes .fragments/): the baseline is derived from
    .requirements.yaml directly and the deterministic table from yaml threats.
    Returns empty string only when requirements checking was not enabled at all
    (no .requirements.yaml and no rows).
    """
    frag_path = ctx.output_dir / ".fragments" / "requirements-compliance.md"
    baseline = ""
    result_line = ""

    if frag_path.is_file():
        text = frag_path.read_text(encoding="utf-8")
        # --- Baseline URL from fragment ---
        baseline_m = re.search(
            r"from the \[([^\]]+)\]\(([^)]+)\) baseline",
            text,
        )
        if baseline_m:
            baseline = f"[{baseline_m.group(1)}]({baseline_m.group(2)})"
        else:
            baseline_m2 = re.search(r"from the ([^\n]+?) baseline", text)
            baseline = baseline_m2.group(1).strip() if baseline_m2 else ""
        # --- Summary line from fragment ---
        summary_m = re.search(r"\*\*Summary:\*\*\s*(.+?)(?:\n|$)", text)
        result_line = summary_m.group(1).strip() if summary_m else ""

    # Derive baseline from .requirements.yaml when fragment is absent or baseline empty.
    if not baseline:
        req_path = ctx.output_dir / ".requirements.yaml"
        if req_path.is_file():
            try:
                req_data = yaml.safe_load(req_path.read_text(encoding="utf-8")) or {}
            except Exception:
                req_data = {}
            for meta in req_data.get("sources_meta", []) or []:
                if isinstance(meta, dict) and meta.get("type") == "requirement":
                    title = (meta.get("title") or "").strip()
                    url = (meta.get("reference_url") or meta.get("crawl_url") or "").strip()
                    baseline = f"[{title}]({url})" if (title and url) else title or ""
                    if baseline:
                        break
        if not baseline:
            baseline = "configured baseline"

    # Deterministic compact traceability table (FAIL/PARTIAL/ANTI-PATTERN only,
    # highest-risk first, capped) built from threat-model.yaml.
    rows = _build_requirements_mapping_rows(ctx)

    # When the fragment is gone AND no rows exist in yaml, nothing to show.
    if not frag_path.is_file() and not rows:
        return ""

    # --- Compose the subsection ---
    lines: list[str] = ["### Requirements Compliance", ""]
    lines.append(f"**Baseline:** {baseline}")
    if result_line:
        lines.append(f"**Result:** {result_line}")
    lines.append("")

    table = _render_requirements_mapping_table(ctx, rows, limit=6)
    if table:
        lines.append("**Failed or partial requirements → findings & mitigations:**")
        lines.append("")
        lines.append(table)
        lines.append("")

    lines.append("→ *Full compliance details in [Section 7b — Requirements Compliance](#7b-requirements-compliance).*")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Top Threats — merged Management-Summary section (replaces Top Findings +
# Architecture Assessment). One row per attack-class (threat), threat-modeling
# altitude: each row carries the general architectural weakness + STRIDE, the
# concrete findings (linked, each with its component), the derived Risk &
# Impact, and the primary mitigation(s). All columns except the one-line
# class description are derived deterministically from threat-model.yaml +
# the attack-paths fragment, so the section never drifts.
# ---------------------------------------------------------------------------

# Trailing file/location token stripped from a finding title to produce the
# short Findings-cell label (e.g. "SQL Injection routes/login.ts:34" → "SQL
# Injection"). Matches a path ending in a known source extension, optionally
# followed by `:line` or `:start-end`.
_FINDING_LOCATION_RE = re.compile(
    r"\s+[\w./@+-]+\.(?:ts|tsx|js|jsx|mjs|cjs|json|ya?ml|html|py|java|go|rb|php|env|conf|xml|dockerfile)"
    r"(?::[0-9]+(?:-[0-9]+)?)?$",
    re.IGNORECASE,
)

_TOP_THREATS_SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


def _strip_finding_location(title: str) -> str:
    """Strip a trailing `path/file.ext[:line]` token from a finding title."""
    t = (title or "").strip()
    stripped = _FINDING_LOCATION_RE.sub("", t).strip()
    return stripped or t


def _compute_top_threats_rows(ctx: RenderContext) -> list[dict[str, Any]]:
    """Build the Top Threats rows — one per non-empty attack class.

    Joins the attack-paths fragment (class taxonomy → glyph, generic
    description, curated finding membership, business impacts) with the
    deterministic threat/mitigation/component data:

      * Glyph ①–⑦ + `#path-<class>` anchor — agrees with the heatmap and
        the Security Posture bullets (same positional rule as
        `_build_finding_to_path_map`).
      * Threat title + STRIDE — from `attack-class-taxonomy.yaml`
        (`threat_label` / `stride`).
      * Findings — each member finding rendered as `[F-NNN](#f-nnn) <short>
        → [C-NN](#c-nn)`, linking into §8 Findings Register and §2.3 Components.
      * Risk — the MAX severity across the class's member findings.
      * Impact — business-impact labels from the fragment.
      * Fix — the union of the member findings' mitigations, linked
        `[M-NNN](#m-nnn)`, with a `(P1)` / `(P1/P2)` priority token.
    """
    taxonomy = _load_attack_class_taxonomy()
    class_meta = {c.get("id"): c for c in taxonomy.get("classes", []) if isinstance(c, dict)}
    threats = _threat_lookup(ctx)
    mitigations = _mitigation_lookup(ctx)
    components = _component_lookup(ctx)
    impact_tax = _load_business_impact_taxonomy()
    impact_label = {
        i.get("id"): (i.get("label") or i.get("id")) for i in impact_tax.get("impacts", []) if isinstance(i, dict)
    }

    attack_paths_data = _load_attack_paths_fragment(ctx, taxonomy, list(threats.values()))
    paths = attack_paths_data.get("attack_paths") or []
    glyphs = ["①", "②", "③", "④", "⑤", "⑥", "⑦"]

    def resolve_component(slug: str | None) -> tuple[str, str]:
        if not slug:
            return "C-00", "—"
        raw = slug.strip()
        if raw in components:
            comp = components[raw]
            canonical = comp.get("_canonical_id") or (raw if re.match(r"^C-\d+$", raw) else raw)
            return canonical, (comp.get("name") or raw)
        for c_id, c in components.items():
            if re.match(r"^C-\d+$", c_id) and (c.get("name") or "").strip() == raw:
                return c_id, c.get("name") or c_id
        return "C-00", raw

    def lookup_threat(fid: str) -> tuple[str, dict[str, Any]]:
        """Return (visible F-NNN, threat dict) for a fragment finding id."""
        key = (fid or "").strip().upper()
        m = re.match(r"^[TF]-(\d+)$", key)
        digits = m.group(1) if m else None
        t = {}
        if digits:
            t = threats.get(f"T-{digits}") or threats.get(f"F-{digits}") or {}
        if not t:
            t = threats.get(key, {})
        visible = f"F-{digits}" if digits else key
        return visible, t

    rows: list[dict[str, Any]] = []
    for idx, ap in enumerate(paths):
        if idx >= len(glyphs):
            break
        cls = ap.get("class") or ""
        meta = class_meta.get(cls, {})
        glyph = glyphs[idx]
        anchor = f"path-{cls}" if cls else ""
        title = meta.get("threat_label") or meta.get("label") or cls
        stride = meta.get("stride") or ""
        description = (ap.get("description") or meta.get("description") or "").strip()

        finding_cells: list[str] = []
        member_threats: list[dict[str, Any]] = []
        seen_fids: set[str] = set()
        for fid in ap.get("findings") or []:
            visible, t = lookup_threat(fid)
            if not visible or visible in seen_fids:
                continue
            seen_fids.add(visible)
            member_threats.append(t)
            # Canonical label (class title, locator-free) + the backticked
            # basename:line locator, mirroring linkify_with_label's full form —
            # the cell keeps its severity span and `→ component` link, so it
            # composes the pieces by hand but uses the SAME label + location
            # sources so the format stays uniform (locator always backticked).
            short = ctx.lookup_label(visible) or _strip_trailing_locator(
                _strip_finding_location(
                    t.get("title") or t.get("scenario_short") or _canonical_finding_title(t) or visible
                )
            )
            _loc = ctx.location_for_ref(visible)
            _loc_suffix = f" (`{_loc}`)" if _loc else ""
            c_anchor, _c_name = resolve_component(t.get("component") or t.get("component_id"))
            # Keep the atomic units non-breaking — the bullet+finding id and the
            # `→ component` link — but let the title wrap on normal spaces so a
            # long finding name flows onto the next line instead of forcing the
            # whole Findings column wide (and never breaks inside an F-NNN id).
            # Use a ` — ` separator between the link and its title (not a bare
            # space): every downstream re-label pass (qa_checks linkify_anchors,
            # apply_prose_fixes relevant-findings-bullets, _linkify_bare_refs_in_prose)
            # keys "already labelled" on ` — `, so the em-dash form is what stops
            # them re-appending the title and doubling the cell (2026-05-31).
            # Per-finding severity circle so the reader sees each finding's
            # criticality inline (same 🔴/🟠/🟡/🟢 vocabulary as the §8/§9
            # indices). Keep it BEFORE the non-breaking link unit; the ` — `
            # title separator downstream passes key on is preserved.
            f_emoji = _TOP_THREATS_SEVERITY_EMOJI.get((t.get("risk") or t.get("severity") or "").strip().lower(), "")
            f_prefix = f"{f_emoji}&nbsp;" if f_emoji else ""
            # No leading `•` bullet — each finding sits on its own line (joined
            # by <br/> below); a bullet inside a table cell reads as clutter
            # (user request 2026-06). Keep the id+dot and the `→ component`
            # link non-breaking so an F-NNN / C-NN id never wraps mid-token;
            # the title between them still wraps on normal spaces.
            # Component link carries its NAME (not a bare ID) — consistent with
            # Top Mitigations / §2.3. The `→ [C-NN]` stays non-breaking; the name
            # sits OUTSIDE the span so it wraps with the rest of the cell.
            _c_suffix = f"&nbsp;{_c_name}" if _c_name and _c_name != c_anchor else ""
            finding_cells.append(
                f'<span style="white-space:nowrap">{f_prefix}[{visible}](#{visible.lower()})</span>'
                f" — {short}{_loc_suffix} "
                f'<span style="white-space:nowrap">→&nbsp;[{c_anchor}](#{c_anchor.lower()})</span>{_c_suffix}'
            )

        # Risk = max severity across member findings.
        if member_threats:
            top_t = min(member_threats, key=lambda t: _severity_rank(t.get("risk") or t.get("severity")))
            risk_word = (top_t.get("risk") or top_t.get("severity") or "").strip()
        else:
            risk_word = ""
        risk_emoji = _TOP_THREATS_SEVERITY_EMOJI.get(risk_word.lower(), "")

        # Fix = the member findings' primary mitigations, highest priority
        # first, capped at 2 (mirrors the Top Findings `[:2]` rule so the
        # summary stays a primary-action surface; the full set lives in §9).
        fix_ids: list[str] = []
        for t in member_threats:
            for mid in t.get("mitigation_ids") or t.get("mitigations") or []:
                if mid and mid not in fix_ids:
                    fix_ids.append(mid)

        def _prio_rank(mid: str) -> int:
            p = (mitigations.get(mid, {}).get("priority") or "").strip().upper()
            return {"P1": 0, "P2": 1, "P3": 2, "P4": 3}.get(p, 9)

        fix_ids.sort(key=_prio_rank)
        shown = fix_ids[:2]
        # Stack multi-mitigation Fix cells with <br/> (same convention as the
        # findings_cell below). A ", " join left two `[M-NNN](#…)` links on one
        # line, which the cell_format QA detector flags as "2 ID links with no
        # <br/> separator" (juice-shop 2026-06-03 §2 Top-Threats Fix column).
        # Variant B (2026-06-04): annotate each measure link inline with its
        # monochrome priority circle + P-tag (`● P1 · [M-NNN]`), the same prefix
        # `linkify_with_label` emits everywhere else, instead of a trailing
        # `(P1/P2)` token. Keeps every linked measure annotated consistently.
        # Wrap each fix link in a nowrap span so the priority circle + M-NNN id
        # never line-breaks (the narrow Fix column was stacking `❶ / M- / 007`
        # — IDs must never wrap; user request 2026-06).
        fix_links = "<br/>".join(
            f'<span style="white-space:nowrap">{_measure_prio_prefix(ctx, mid)}[{mid}](#{mid.lower()})</span>'
            for mid in shown
        )
        fix_cell = fix_links or "—"

        impacts = [impact_label.get(s, s) for s in (ap.get("impact") or [])]
        impact_str = " · ".join(impacts)

        rows.append(
            {
                # Emit the `path-<class>` anchor on the row itself (the heatmap
                # bullets that used to define it are gone in the merged section);
                # the glyph then agrees positionally with the Figure 2 arrows.
                "num_cell": f'<a id="{anchor}"></a>{glyph}' if anchor else glyph,
                "description_cell": (
                    f"**{title}** _({stride})_<br/>{description}" if stride else f"**{title}**<br/>{description}"
                ),
                "findings_cell": "<br/>".join(finding_cells) if finding_cells else "—",
                "risk_cell": (
                    f"{risk_emoji} **{risk_word}**<br/>{impact_str}".strip() if risk_word else (impact_str or "—")
                ),
                "fix_cell": fix_cell,
            }
        )
    return rows


def _render_top_threats(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    rows = _compute_top_threats_rows(ctx)
    tpl = env.get_template(section.get("template", "top-threats.md.j2"))
    return tpl.render(rows=rows).rstrip() + "\n"


_MS_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _abuse_chain_ms_note(ctx: RenderContext) -> str:
    """Deterministic Management-Summary sentence documenting the role
    code-verified abuse chains played in the finding ratings.

    Returns "" when no finding anchors a verified chain (e.g. abuse-case
    verification was skipped at quick depth / via --no-abuse-cases, or no
    chain was confirmed). Otherwise names the anchoring findings (with their
    criticality dots via ``linkify_with_label``) and points the reader at §9.
    """
    members: list[tuple[str, bool]] = []  # (finding_id, elevated_by_chain)
    all_chains: set[str] = set()
    for t in (ctx.yaml_data or {}).get("threats", []) or []:
        ids = [c.strip() for c in (t.get("verified_chain_ids") or []) if (c or "").strip()]
        if not ids:
            continue
        all_chains.update(ids)
        fid = (t.get("t_id") or t.get("id") or "").strip()
        if not fid:
            continue
        elevated = _MS_SEV_RANK.get((t.get("effective_severity") or "").strip().lower(), 0) > _MS_SEV_RANK.get(
            (t.get("risk") or t.get("severity") or "").strip().lower(), 0
        )
        members.append((fid, elevated))
    if not members or not all_chains:
        return ""
    n, m = len(members), len(all_chains)
    flinks = ", ".join(ctx.linkify_with_label(fid) for fid, _ in members)
    elev = sum(1 for _, e in members if e)
    note = (
        f"**Attack-chain analysis.** {n} finding{'s' if n != 1 else ''} "
        f"anchor {m} code-verified attack chain{'s' if m != 1 else ''} "
        f"(see §9 Abuse Cases): {flinks}."
    )
    if elev:
        note += (
            f" {elev} of these {'is' if elev == 1 else 'are'} rated above "
            f"{'its' if elev == 1 else 'their'} individual baseline as a "
            f"direct result of the verified chain."
        )
    else:
        note += (
            " Their Critical/High ratings reflect exploitability confirmed "
            "end-to-end across the chain, not the individual weakness alone."
        )
    return note


def _render_management_summary(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    # Explicit composition ensures the canonical subsection order is enforced.
    # `security_posture_at_a_glance` is rendered between `verdict` and
    # `top_findings` (see contract.sections.management_summary.required_subsections).
    # `requirements_compliance_ms` is inserted between `mitigations` and
    # `operational_strengths` when check_requirements=True (derived from
    # .fragments/requirements-compliance.md by _render_requirements_compliance_ms).
    parts = ["## Management Summary"]
    sections = ctx.contract["sections"]
    for sid in (
        "verdict",
        # architectural_anti_patterns — optional named-anti-pattern callout
        # right after the verdict (renders nothing when the LLM authored no
        # ms-anti-patterns.json). Placed before the heatmap so the reader sees
        # the structural design defects before the per-flow posture.
        "architectural_anti_patterns",
        # ai_exposure_ms — optional AI/LLM-exposure callout, right after the
        # anti-patterns block (renders nothing when the LLM authored no
        # ms-ai-exposure.json, i.e. the system has no LLM/AI surface).
        "ai_exposure_ms",
        # systemic_posture — the P4 "### Security Principles" verdict table
        # (VIOLATED/WEAK/ADEQUATE per principle), hoisted from §8 (2026-07-13) so
        # a systemically-violated principle is loud at executive level. Placed
        # before the heatmap so the reader sees the structural posture before the
        # per-flow view. Renders nothing when the weakness register is empty
        # (has_weakness_register).
        "systemic_posture",
        # security_posture_at_a_glance now renders the merged
        # "### Security Posture & Top Threats" section (Figure 1 + Figure 2
        # heatmap + the Top Threats table); the standalone top_threats child
        # was folded into it.
        "security_posture_at_a_glance",
        "mitigations",
        "requirements_compliance_ms",
        "operational_strengths",
    ):
        if sid == "requirements_compliance_ms":
            if ctx.eval_context.get("check_requirements"):
                req_ms = _render_requirements_compliance_ms(ctx)
                if req_ms.strip():
                    parts.append(req_ms.rstrip())
            continue
        if sid == "architectural_anti_patterns":
            ap_ms = _render_architectural_anti_patterns(ctx, env)
            if ap_ms.strip():
                parts.append(ap_ms.rstrip())
            continue
        if sid == "ai_exposure_ms":
            ai_ms = _render_ai_exposure(ctx, env)
            if ai_ms.strip():
                parts.append(ai_ms.rstrip())
            continue
        if sid == "systemic_posture":
            # P4 verdict table (computed, no LLM fragment) — rendered via the
            # special-case path (like the anti-patterns / AI-exposure callouts)
            # so a run with no weakness register demands no fragment and adds
            # nothing.
            sp_ms = _render_security_principles(ctx)
            if sp_ms.strip():
                parts.append(sp_ms.rstrip())
            continue
        sec = sections.get(sid)
        if sec is None:
            # Contract does not declare this MS subsection (e.g. older contract
            # without security_posture_at_a_glance) — skip silently.
            continue
        ftype = sec.get("fragment_type")
        if ftype in ("data", "computed", "hybrid"):
            # `hybrid` (contract v2): renderer composes a deterministic
            # block + consumes one LLM fragment. The dispatcher behaves
            # identically — the section's renderer function decides how
            # to combine the parts internally.
            body = _render_by_id(ctx, env, sid, sec)
        else:
            raise ContractError(f"unsupported fragment_type for MS subsection {sid}: {ftype}")
        # The generic "Attack-chain analysis" note (findings anchoring chains,
        # with F-NNN ids) was removed from the verdict block 2026-07-05: it
        # duplicated the abuse-case integration and violated verdict brevity
        # (no F-/T-NNN in the verdict). The abuse cases are now surfaced ONCE,
        # properly, by _build_ms_abuse_chain_line ("Verified attack chains …",
        # AC-T-NNN) in the Security Posture section below.
        if body.strip():
            parts.append(body.rstrip())
    return "\n\n".join(parts) + "\n"


# Only the four classes the tree actually uses (goal · capability AND/OR ·
# leaf). The retired overview/subtree split used to carry a full palette of
# unused classDefs — that boilerplate is gone with the single-diagram render.
# Palette aligned with Figures 1 & 2 (slate/navy + red): the goal node reuses
# the impact-node navy (#0f172a); intermediate AND/OR capability nodes use two
# slate shades (darker = AND/all-required, lighter = OR/alternatives) instead of
# the off-palette purple/blue; leaf (threat) nodes keep the attacker red.
_ATTACK_TREE_CLASSDEFS = (
    "    classDef goal fill:#0f172a,stroke:#000,color:#fff,stroke-width:3px\n"
    "    classDef and_node fill:#334155,stroke:#1e293b,color:#fff,stroke-width:2px\n"
    "    classDef or_node fill:#64748b,stroke:#334155,color:#fff,stroke-width:2px\n"
    "    classDef leaf fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:2px"
)


def _normalize_tid_to_fid(ref: str) -> str:
    """Merged-stage ``T-NNN`` id → the document-wide visible ``F-NNN`` id.

    Everywhere the reader can see — §8 Findings Register, the findings-pointer
    line under the tree, every linkified reference — uses ``F-NNN``; ``T-NNN``
    is the internal merge-stage id and has no visible anchor. The global
    post-compose annotator rewrites ``[T-NNN](#t-nnn)`` markdown LINKS to
    ``F-NNN``, but it cannot reach plain-text labels INSIDE a ```mermaid fence,
    so the attack-tree boxes shipped stale ``T-NNN`` ids the reader could not
    find (user report 2026-06). Normalising at generation time fixes that at
    the source. Non ``T-NNN`` tokens (already ``F-NNN``, or unrelated) pass
    through unchanged."""
    return re.sub(r"^T-(\d+)$", r"F-\1", (ref or "").strip())


def _attack_tree_node_label(node: dict[str, Any]) -> str:
    """Display label for a tree node. Leaf nodes show their finding id PLUS a
    short title (`F-NNN — <title>`) so the diagram is self-describing instead
    of a wall of bare IDs (2026-05-30 user request); the full title still lives
    in the Branch table below. The title is truncated so leaf boxes stay
    readable rather than ballooning. Goal/capability nodes keep their label.

    The leaf id is normalised T-NNN → F-NNN (see `_normalize_tid_to_fid`) so
    the box matches the F-NNN ids used everywhere else in the document."""
    label = node.get("label", node.get("id", ""))
    if node.get("class") == "leaf":
        m = re.search(r"[FT]-\d{3,}", label)
        if m:
            tid = _normalize_tid_to_fid(m.group(0))
            # Title = the label with the id (and any leading separators) removed.
            title = (label[: m.start()] + label[m.end() :]).strip(" -—:·\t")
            if not title:
                return tid
            _MAX = 32
            if len(title) > _MAX:
                title = title[: _MAX - 1].rstrip() + "…"
            # Leaf labels are emitted inside mermaid ["..."]; a literal double
            # quote would break the node declaration.
            title = title.replace('"', "'")
            return f"{tid} — {title}"
    return label


# AND/OR is a property of the *parent* node, not the individual edge: every
# child of an `or_node` is an OR-alternative, every child of an `and_node` is
# AND-required, and capabilities feeding the goal are OR-alternatives. Deriving
# the edge label from the destination node's class keeps the diagram internally
# consistent and immune to the LLM authoring a per-edge `refinement` that
# contradicts the parent's class (e.g. an `AND` edge into an `or_node`).
_ATTACK_TREE_EDGE_LABEL_BY_DST_CLASS = {"or_node": "OR", "and_node": "AND", "goal": "OR"}


def _attack_tree_edge_line(edge: dict[str, Any], nodes_by_id: dict[str, dict[str, Any]]) -> str:
    """Render one mermaid edge line, mirroring critical-attack-tree.md.j2. The
    AND/OR label is derived from the destination node's class (falling back to
    the authored `label`/`refinement` only for unclassed destinations)."""
    src, dst = edge.get("from"), edge.get("to")
    dst_class = (nodes_by_id.get(dst) or {}).get("class")
    label = _ATTACK_TREE_EDGE_LABEL_BY_DST_CLASS.get(dst_class) or edge.get("label") or edge.get("refinement")
    if label:
        return f'    {src} -->|"{label}"| {dst}'
    return f"    {src} --> {dst}"


def _attack_tree_block(
    orientation: str,
    node_ids: list[str],
    edges: list[dict[str, Any]],
    nodes_by_id: dict[str, dict[str, Any]],
) -> str:
    """Build a complete mermaid `graph` source (header + nodes + edges +
    classDefs) for the given node subset, preserving the fragment's node
    declaration order for stability."""
    lines = [f"graph {orientation}"]
    for nid in node_ids:
        n = nodes_by_id.get(nid)
        if not n:
            continue
        lines.append(f'    {nid}["{_attack_tree_node_label(n)}"]:::{n.get("class", "leaf")}')
    lines.append("")
    for e in edges:
        lines.append(_attack_tree_edge_line(e, nodes_by_id))
    lines.append("")
    lines.append(_ATTACK_TREE_CLASSDEFS)
    return "\n".join(lines)


def _build_attack_tree_blocks(data: dict[str, Any]) -> list[dict[str, str]]:
    """Render the critical-attack-tree fragment as a single mermaid block.

    The whole tree (goal ← capabilities ← leaves) renders as one `graph LR`
    diagram. Left-to-right is deliberate: sibling leaves stack *vertically*
    (natural document scroll) instead of spreading horizontally, so a single
    diagram stays readable no matter the fan-out. Combined with short leaf
    labels (`T-NNN` only), this retires the earlier overview + per-capability
    split — which kept each diagram narrow only by hiding the cross-branch
    convergence the tree exists to show. Orientation is forced here regardless
    of the fragment's authored `TD`/`TB` (the renderer owns layout).

    Returns a one-element ``[{"title": None, "src": <mermaid source>}]`` list
    so the template's existing block loop is unchanged.
    """
    mermaid = data.get("mermaid") or {}
    nodes = mermaid.get("nodes") or []
    edges = mermaid.get("edges") or []
    nodes_by_id = {n.get("id"): n for n in nodes if n.get("id")}
    order = [n.get("id") for n in nodes if n.get("id")]
    return [{"title": None, "src": _attack_tree_block("LR", order, edges, nodes_by_id)}]


def _derive_attack_tree_findings(data: dict[str, Any]) -> list[dict[str, str]]:
    """Ordered leaf-finding pointer for the compact line under the tree.

    The diagram shows only short `T-NNN` leaf boxes, so this tells the reader
    what each id is and links it to its §8 Findings Register row. One entry per
    leaf in tree-declaration order: ``{"id": "T-001", "title": "SQL injection
    login bypass", "anchor": "#t-001"}``. Title is the leaf label with its id
    prefix stripped; mitigations are intentionally NOT surfaced here (they live
    in §9) — this section only points at the findings.
    """
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for n in (data.get("mermaid") or {}).get("nodes") or []:
        if n.get("class") != "leaf":
            continue
        label = n.get("label", "")
        m = re.search(r"[FT]-\d{3,4}", label)
        fid = _normalize_tid_to_fid((m.group(0) if m else (n.get("finding_ref") or "")).strip())
        if not fid or fid in seen:
            continue
        seen.add(fid)
        title = (label[: m.start()] + label[m.end() :]).strip(" -—:·") if m else label.strip()
        out.append({"id": fid, "title": title, "anchor": "#" + fid.lower()})
    return out


def _render_critical_attack_tree(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    # Item 3 (2026-05-28): tree section is a soft-required fragment.
    # The renderer activation is in place, but legacy runs (and most of
    # the test fixtures) do not ship `.fragments/ms-critical-attack-tree.json`
    # yet. Soft-skip the section when the fragment is missing so the
    # contract activation does not regress any prior assessment artefact.
    # Once the Phase 11 substep-4 LLM authoring of this fragment is
    # mandated everywhere, this guard can be lifted and the missing
    # fragment will raise the normal FragmentError again.
    try:
        data = _load_fragment(ctx, "critical_attack_tree", section["fragment"])
    except FragmentError:
        # Soft-skip — log via the render-warning channel and return "".
        try:
            ctx.warnings.append(
                "critical_attack_tree: fragment missing — section soft-skipped. "
                "Once Phase 11 substep-4 authors `.fragments/ms-critical-attack-tree.json` "
                "consistently, lift the guard in _render_critical_attack_tree."
            )
        except Exception:
            pass
        return ""
    _validate_fragment("critical_attack_tree", data, section["schema"])
    blocks = _build_attack_tree_blocks(data)
    findings = _derive_attack_tree_findings(data)
    # Leading severity dot per finding so the compact pointer line under the
    # tree is annotated like every other linked-findings context (§2/§8).
    for f in findings:
        emoji = ctx.severity_emoji(ctx.severity_for_ref(f.get("id", "")))
        f["dot"] = f"{emoji} " if emoji else ""
    tpl = env.get_template(section["template"])
    return tpl.render(data=data, blocks=blocks, findings=findings).rstrip() + "\n"


def _subsection_drift_hint(md: str, section: dict, level: int) -> str:
    """For §7, produce a compact diff between present and expected level-3
    subsections so the FragmentError message pinpoints the numbering drift.

    Returns an empty string when there is no drift to report (only the
    straight-forward "missing" case). When drift is present, returns a
    ``" — present: [...]; expected: [...]"`` suffix.
    """
    prefix = "#" * level + " "
    present = [
        ln[len(prefix) :].strip()
        for ln in md.splitlines()
        if ln.startswith(prefix) and re.match(r"\d+\.\d+", ln[len(prefix) :])
    ]
    expected = [
        (sub.get("title") or "").strip() for sub in section.get("required_subsections", []) or [] if sub.get("title")
    ]
    # If no level-3 numbered subsections at all, fall back to just "missing".
    if not present or not expected:
        return ""
    present_short = [p.split(" ", 1)[0] for p in present][:16]
    expected_short = [e.split(" ", 1)[0] for e in expected][:16]
    if present_short == expected_short:
        return ""  # numbers line up — don't muddy the error
    return (
        f" — present: {present_short}; expected: {expected_short}. "
        "Likely a §7 numbering drift (most commonly: §7.8 Real-time / "
        "WebSocket and §7.9 AI / LLM are missing, shifting every later "
        "heading by 2)."
    )


def _render_markdown_fragment(ctx: RenderContext, section_id: str, section: dict) -> str:
    """Render a Markdown section and validate its structural constraints.

    Enrichments applied at render time (never by the LLM):
      * §2 architecture_diagrams — regenerate the complete fragment from YAML,
        then inject a `<a id="c-NN">` component anchor table underneath
        `### 2.3 Components`. LLM edits to the on-disk fragment are never a
        producer of final report content.

    Quick-mode override:
      * §7 security_architecture — when running at quick depth, the renderer
        skips the section entirely (TOC + body) unless a previous run at
        standard/thorough depth left a rich §7 in the prior threat-model.md;
        in that case the prior content is preserved verbatim. The decision is
        precomputed during ctx setup and exposed as ctx.security_arch_override
        + the eval_context flag `render_security_architecture`.
    """
    if section_id == "security_architecture":
        override = getattr(ctx, "security_arch_override", None)
        if override is not None:
            # Empty override means "skip" (filtered out earlier by the section
            # composer via the `render_security_architecture` condition);
            # non-empty override means the prior rich §7 should be preserved.
            return override or ""
    fragment_name = section["fragment"]
    if section_id == "architecture_diagrams":
        # §2 is structural data, not LLM prose. Keeping this at the final
        # composition chokepoint prevents a renderer from reintroducing extra
        # Mermaid nodes after the pre-generator has enforced compactness.
        md = gen_architecture_diagrams(ctx.yaml_data)
    else:
        md = _load_fragment(ctx, section_id, fragment_name)
    if not isinstance(md, str):
        raise FragmentError(section_id, f"expected Markdown text in {fragment_name}")

    expected = (section.get("heading") or "").strip()
    first_nonblank = next((ln.strip() for ln in md.splitlines() if ln.strip()), "")
    if expected and first_nonblank != expected:
        # Deterministic recovery: the LLM renderer occasionally drops or
        # mislabels ONLY the leading `## N. Title` H2 (e.g. replaces it with
        # the intro paragraph) while the body below is structurally intact.
        # Prepend the canonical contract heading rather than hard-failing the
        # whole run on a one-line, recoverable defect. A genuinely empty /
        # garbage fragment still fails the empty-body guard here, and a
        # cross-contaminated fragment (first line is a DIFFERENT section's
        # numbered H2) still hard-fails — that is a real authoring mixup.
        body_has_substance = len(md.strip()) >= 40 and "\n" in md.strip()
        # Only restore when the dropped heading was replaced by PROSE (the
        # observed defect: the LLM substituted the intro paragraph for the H2).
        # If the first line is itself a heading — a wrong level (`### 7.`) or a
        # different section's H2 (cross-contamination) — keep the hard fail:
        # that is a real authoring mixup, not a recoverable dropped heading.
        first_is_heading = first_nonblank.startswith("#")
        if body_has_substance and not first_is_heading:
            md = f"{expected}\n\n{md.lstrip()}"
            ctx.warnings.append(
                f"{section_id}: heading_autorestored — fragment first line "
                f"{first_nonblank!r} prefixed with canonical {expected!r}"
            )
        else:
            raise FragmentError(
                section_id,
                f"fragment must begin with '{expected}'; first heading is '{first_nonblank}'",
            )

    # `required_patterns` may carry a `required_patterns_condition` gate
    # (e.g. `"not skip_attack_walkthroughs"`). When the condition resolves
    # to False, the patterns are not enforced — this is how the quick-
    # depth attack-walkthroughs stub passes without the per-finding
    # sequenceDiagram blocks.
    rp_condition = section.get("required_patterns_condition")
    rp_enabled = True
    if rp_condition:
        try:
            rp_enabled = bool(eval_condition(rp_condition, ctx.eval_context))
        except Exception:
            rp_enabled = True  # conservative: enforce on parse failure
    if rp_enabled:
        for pat in section.get("required_patterns", []) or []:
            if not re.search(pat, md):
                raise FragmentError(
                    section_id,
                    f"fragment missing required pattern: {pat!r}",
                )

    # Like `required_patterns_condition` above, `required_subsections`
    # honours an optional `required_subsections_condition`. When the gate
    # resolves to False, the subsection checks are skipped - this is the
    # mechanism that lets the quick-depth §3 stub omit §3.1 entirely
    # without tripping a contract-validation FragmentError. The
    # subsequent post-processing passes (forbidden patterns, domain
    # patterns, linkify) still run on the rendered markdown.
    rs_condition = section.get("required_subsections_condition")
    rs_enabled = True
    if rs_condition:
        try:
            rs_enabled = bool(eval_condition(rs_condition, ctx.eval_context))
        except Exception:
            rs_enabled = True
    # schema_v2 overlay — prefer `section.schema_v2.required_subsections`
    # for §7. v2 is the only supported security-architecture layout.
    _required_subs_base = section.get("required_subsections") or []
    _required_subs = _required_subs_base
    if rs_enabled:
        _schema_v2 = False
        try:
            _schema_v2 = bool(ctx.eval_context.get("security_schema") == "v2")
        except Exception:
            _schema_v2 = False
        if _schema_v2 and section_id == "security_architecture":
            _v2_block = section.get("schema_v2") or {}
            _v2_subs = _v2_block.get("required_subsections")
            if isinstance(_v2_subs, list) and _v2_subs:
                _required_subs = _v2_subs
    else:
        _required_subs = []
    for sub in _required_subs:
        title = sub.get("title")
        level = sub.get("level", 3)
        pattern = sub.get("title_pattern")
        if title:
            needle = f"{'#' * level} {title}"
            if needle not in md:
                # For §7 specifically, show the present vs. expected heading
                # list so the orchestrator sees the exact numbering drift
                # (e.g. "fragment has 7.13 Defense-in-Depth; expected 7.14").
                hint_suffix = (
                    _subsection_drift_hint(md, {**section, "required_subsections": _required_subs}, level)
                    if section_id == "security_architecture"
                    else ""
                )
                raise FragmentError(
                    section_id,
                    f"required subsection missing: '{needle}'{hint_suffix}",
                )
        elif pattern:
            user_pat = pattern.lstrip("^")
            full_pat = r"^" + ("#" * level) + r"\s+" + user_pat
            if not re.search(full_pat, md, flags=re.MULTILINE):
                raise FragmentError(
                    section_id,
                    f"required subsection pattern missing: {pattern!r}",
                )

    # --- forbidden_subsection_patterns ----------------------------------
    # Catch subsection headings that are NOT permitted in this section —
    # e.g. §2 should NEVER carry `### 2.5 Security Architecture Assessment`,
    # because that content lives in §7. The renderer strips those headings
    # + their body content (until the next sibling heading) so the resulting
    # markdown stays canonical.
    forbidden = section.get("forbidden_subsection_patterns") or []
    if forbidden:
        # Scan each level-3 heading inside the fragment body.
        for line_match in list(re.finditer(r"^### (.+?)\s*$", md, re.MULTILINE)):
            title = line_match.group(1).strip()
            for pat in forbidden:
                if re.match(pat, title):
                    # Excise from the heading until the next `### ` or `## ` (or EOF).
                    start = line_match.start()
                    rest = md[line_match.end() :]
                    nxt = re.search(r"^(###? )", rest, re.MULTILINE)
                    end = line_match.end() + (nxt.start() if nxt else len(rest))
                    ctx.warnings.append(
                        f"§{section_id} stripped forbidden subsection: '### {title}' "
                        f"(matches pattern {pat!r} — content belongs in §7, not §2)"
                    )
                    md = md[:start] + md[end:]
                    break

    # --- domain_required_patterns ---------------------------------------
    # Per-subsection patterns, e.g. §7.3 MUST contain a sequenceDiagram.
    # Scoped: we only check the slice of the fragment that sits under the
    # named subsection heading until the next level-3 heading.
    domain_required_patterns = section.get("domain_required_patterns") or {}
    try:
        schema_v2_active = bool(ctx.eval_context.get("security_schema") == "v2")
    except Exception:
        schema_v2_active = False
    if schema_v2_active and section_id == "security_architecture":
        v2_patterns = (section.get("schema_v2") or {}).get("domain_required_patterns")
        if isinstance(v2_patterns, dict) and v2_patterns:
            domain_required_patterns = v2_patterns

    for domain_title, patterns in domain_required_patterns.items():
        m = re.search(r"^###\s+" + re.escape(domain_title) + r"\s*$", md, re.MULTILINE)
        if not m:
            continue  # subsection isn't present — already flagged above
        tail = md[m.end() :]
        nxt = re.search(r"^###\s+", tail, re.MULTILINE)
        domain_slice = tail[: nxt.start()] if nxt else tail
        for pat in patterns:
            if not re.search(pat, domain_slice):
                raise FragmentError(
                    section_id,
                    f"§{domain_title} missing required pattern {pat!r} "
                    f"(each authentication method / domain flow needs its own "
                    f"diagram or #### sub-block)",
                )

    # --- Post-processing enrichments --------------------------------------
    if section_id == "architecture_diagrams":
        md = _inject_components_table(ctx, md)
    elif section_id == "security_architecture":
        md = _inject_security_architecture_links(ctx, md)
    elif section_id == "attack_walkthroughs":
        md = _inject_attack_walkthroughs_intros(ctx, md)

    # Linkify bare CWE-NNN references in every prose fragment so they become
    # clickable links to the MITRE CWE entry.  Runs after the §7-specific
    # enrichment (which also calls _linkify_bare_cwes) so that code is
    # idempotent — already-linked CWEs are never double-wrapped.
    if section_id != "security_architecture":
        md = _linkify_bare_cwes(md)

    # Linkify every bare `[X-NNN](#x-nnn)` ref in the prose — except inside
    # fenced code blocks and `*(...)*` Verdict-style citations — so cross-
    # references never emit without a human-readable label.
    md = _linkify_bare_refs_in_prose(ctx, md)

    # Enrich pure ID-list cells in "Linked Threats" / "Mitigates" / etc.
    # columns: rewrite as `<br/>`-stacked `[ID](#id) — label` entries so
    # these markdown-fragment tables match the computed-section convention.
    md = _enrich_linked_id_cells(ctx, md)

    # Normalise the trailing locator on every finding/mitigation reference,
    # fragment-agnostic: an un-backticked `(path/file:line)` directly after an
    # `[ID](#id) — label` is backticked and basenamed in place. Already-
    # backticked locators (incl. the Findings index's deliberate full path) are
    # skipped. This is the catch-all for LLM-fragment-authored cross-references
    # (e.g. the §7 control tables) that never went through linkify_with_label.
    md = _normalize_reference_locators(md)

    # §5 Attack Surface + §7 Security Architecture author their finding
    # cross-references WITHOUT the severity dot (the §5 entry-point tables and
    # the §7 control tables / DiD bullets). Prefix each with its criticality
    # glyph so they match §8, the asset/component tables, and Top Mitigations.
    # Runs after enrich so any dot it already produced is seen (idempotent).
    # NOTE: §3 Attack Walkthroughs and §9 Abuse Cases are handled by the GLOBAL
    # retrofit pass at the end of render() instead — their F-refs are rewritten
    # from T-NNN → F-NNN AFTER this point, so a per-section pass here would miss
    # them. See `_prepend_finding_severity_dots` / `_prepend_mitigation_prio_circles`
    # call sites just before render() returns.
    if section_id in ("attack_surface", "security_architecture"):
        md = _prepend_finding_severity_dots(ctx, md)

    # Escape `$word` tokens (MongoDB `$where`/`$ne`, jQuery selectors, bash
    # vars) so KaTeX/MathJax-enabled renderers don't treat the `$` as math
    # mode and blow up on the next `#` inside `](#t-NNN)`. Runs last so the
    # linkify passes above see the raw text first.
    md = _escape_dollar_operators(md)
    # Fold whole code-signal string literals (SQL queries, concatenated
    # expressions) into one span BEFORE the ccTLD escape, so a column ref like
    # `u.id` is not mistaken for the `.id` ccTLD and backticked mid-string
    # (which would half-backtick the query — see _fold_code_strings_in_prose).
    md = _fold_code_strings_in_prose(md)
    md = _escape_dot_tld_identifiers(md)
    # `_escape_html_payloads_in_prose` is intentionally NOT called here —
    # markdown fragments are only one of several section types and the
    # §8 Findings Register (computed section) bypasses this wrapper. The
    # escape pass runs in the END-OF-RENDER pipeline (see `render()` near
    # the bottom of this file) so every section type is covered.

    return md.rstrip() + "\n"


_ATTACK_WALKTHROUGHS_DEFAULT_INTRO = (
    "This section reconstructs how each Critical finding would actually play "
    "out as an attack — one short walkthrough per finding, with attack steps "
    "and a sequence diagram contrasting current behaviour with the "
    "post-mitigation state. The cross-finding view (which weaknesses combine "
    "toward the worst-case goal, and where one fix severs several paths) is "
    "in the [Critical Attack Tree](#critical-attack-tree) above §1. Medium- "
    "and Low-severity findings are not walked through here — they are "
    "documented in [§8 Findings Register](#8-findings-register)."
)


def _inject_attack_walkthroughs_intros(ctx: RenderContext, md: str) -> str:
    """Ensure §3 carries a chapter intro paragraph even when the
    LLM-authored fragment skipped it.

    The compose step scaffolds a default intro from
    `_ATTACK_WALKTHROUGHS_DEFAULT_INTRO` when missing. An author-written
    intro is preserved as-is (the function detects existing prose between the
    heading and the next heading / mermaid block).

    Idempotent — a second invocation finds the intro already present and
    no-ops.
    """
    if not md:
        return md

    def _has_prose_before(heading_match: re.Match[str], text: str) -> bool:
        """Return True when there is at least one line of non-blank, non-fence,
        non-heading prose immediately after the heading and before the next
        structural element (another heading or a fenced block)."""
        tail = text[heading_match.end() :]
        for line in tail.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("```"):
                return False
            if stripped.startswith("#"):
                return False
            if stripped.startswith("<!--"):
                continue
            return True
        return False

    # §3 chapter intro
    chap = re.search(r"^## 3\.[ \t]+Attack Walkthroughs\s*$", md, re.MULTILINE)
    if chap and not _has_prose_before(chap, md):
        md = md[: chap.end()] + "\n\n" + _ATTACK_WALKTHROUGHS_DEFAULT_INTRO + "\n" + md[chap.end() :]

    return md


def _inject_components_table(ctx: RenderContext, md: str) -> str:
    """Post-process §2: ensure `### 2.3 Components` contains a C-NN anchor
    table rendered deterministically from `threat-model.yaml → components[]`.

    The deterministic renderer ALWAYS wins — any LLM-authored component table
    between `### 2.3 Components` and the next `### ` heading is stripped and
    replaced. This prevents the LLM from packing long threat titles into one
    comma-joined cell (unreadable) or drifting on the column set. Non-table
    prose before the LLM's table (e.g. an intro sentence and the Mermaid
    component diagram) is preserved.
    """
    components = ctx.yaml_data.get("components") or []
    if not components:
        return md

    m = re.search(r"^###\s+2\.3\s+Components\s*$", md, flags=re.MULTILINE)
    if not m:
        return md
    # Find the start of the next `### ` heading after §2.3.
    tail = md[m.end() :]
    nxt = re.search(r"^###\s+", tail, flags=re.MULTILINE)
    section_end = m.end() + (nxt.start() if nxt else len(tail))
    section_body = md[m.end() : section_end]

    # Strip any pre-existing Markdown table from the section body. A table
    # is a run of lines starting with `|`, possibly preceded by a separator
    # line with `|---|`. We only strip tables, NOT the mermaid block or
    # prose — mermaid lives inside ``` ``` fences and tables don't.
    def _strip_first_table(body: str) -> str:
        # Match a full table: header row + separator row + 1..N data rows.
        table_re = re.compile(
            r"(?:^\|[^\n]*\|\s*\n"  # header row
            r"\|[ \t:\-|]+\|\s*\n"  # separator row
            r"(?:\|[^\n]*\|\s*\n)+)",  # one or more data rows
            flags=re.MULTILINE,
        )
        # Strip ALL tables in the section body (defensive — LLM might emit
        # both a "quick summary" and a "detailed" table).
        return table_re.sub("", body)

    cleaned_body = _strip_first_table(section_body).rstrip() + "\n"

    # M3.3 / D1.5 — Optional `Runtime` column when ANY component carries a
    # populated `runtime` field. The column is hidden entirely when nothing
    # to show, so legacy yamls render with the original 5-column layout
    # and don't inherit a redundant em-dash column.
    has_runtime = any(isinstance(c, dict) and (c.get("runtime") or "").strip() for c in components)
    # Scope column — only when a criteria-based selection actually excluded some
    # components (meta.component_selection.excluded). Marks each row Analyzed vs
    # Out of scope so the reader can see which components received a STRIDE pass.
    # Absent in passthrough/legacy runs → original column layout is preserved.
    cs = (ctx.yaml_data.get("meta") or {}).get("component_selection")
    excluded_ids = set()
    if isinstance(cs, dict):
        excluded_ids = {
            (e.get("id") or "").strip()
            for e in (cs.get("excluded") or [])
            if isinstance(e, dict) and (e.get("id") or "").strip()
        }
    show_scope = bool(excluded_ids)
    scope_hdr = " Scope |" if show_scope else ""
    scope_sep = "-------|" if show_scope else ""
    if has_runtime:
        table_lines = [
            "",
            "| ID | Name | Type | Runtime | Key Paths | Linked Threats |" + scope_hdr,
            "|----|------|------|---------|-----------|----------------|" + scope_sep,
        ]
    else:
        table_lines = [
            "",
            "| ID | Name | Type | Key Paths | Linked Threats |" + scope_hdr,
            "|----|------|------|-----------|----------------|" + scope_sep,
        ]
    for idx, c in enumerate(components, start=1):
        raw = (c.get("id") or "").strip()
        if re.match(r"^C-\d+$", raw):
            canonical = raw
        else:
            canonical = f"C-{idx:02d}"
        name = c.get("name", canonical)
        # M3.3 — Type column fallback chain (D1):
        #   c.type / c.kind  →  c.tier  →  derived from id+name+paths heuristic.
        # The orchestrator currently writes neither type nor kind for many
        # components; falling back to the same tier-classifier the
        # diagram renderer uses keeps the column populated instead of
        # showing "—" for every row.
        kind = (c.get("kind") or c.get("type") or c.get("tier") or "").strip()
        if not kind:
            kind = _classify_component_tier(c).capitalize()
        runtime = (c.get("runtime") or "").strip() or "—"
        paths = c.get("paths") or []
        paths_cell = "<br/>".join(f"`{p}`" for p in paths[:5]) or "—"
        th_ids = c.get("threat_ids") or []
        # Render every linked threat with its title — we used to cap at 5
        # and suffix "+N more" to keep the cell visually short, but the cap
        # silently truncated real data on components with 6+ threats and
        # forced the reader to jump elsewhere to see the full set. With
        # `<br/>`-stacked formatting the cell grows vertically, not
        # horizontally, so rendering every threat is readable even at
        # 8–10 entries. For pathological cases (>15 threats on one
        # component) we drop the title to keep the cell narrow — still no
        # "+N more" stub.
        threats_by_id = {
            t.get("id") or t.get("t_id"): t for t in (ctx.yaml_data.get("threats") or []) if isinstance(t, dict)
        }
        include_titles = len(th_ids) <= 15

        def _format_threat_link(tid: str) -> str:
            # Canonical reference form: full (ID — label (`file:line`)) by
            # default, compact (ID only) for pathological 15+ -threat cells.
            # Routing through linkify_with_label keeps the locator backticked
            # and the label locator-free (no raw-title `(file)` leakage).
            return ctx.linkify_with_label(tid, compact=not include_titles)

        th_links = [_format_threat_link(t) for t in th_ids]
        # Stack threat links with <br/> so each sits on its own line in
        # rendered markdown — comma-joining 5 links per cell is unreadable.
        # The reference threat-model.md uses <br/> for every multi-ref cell
        # (see §8.G Mitigations column, §7 linked threats); we follow suit
        # for consistency across tables.
        th_cell = "<br/>".join(th_links) or "—"
        # Emit the canonical C-NN anchor AND the raw yaml id (if different) so
        # downstream `[raw](#raw)` references from the Mitigation table resolve.
        # Renderers elsewhere use the yaml id verbatim; the canonical id is used
        # in prose. Both must be valid anchor targets.
        anchors = [f'<a id="{canonical.lower()}"></a>']
        raw_slug = raw.lower()
        if raw_slug and raw_slug != canonical.lower():
            anchors.append(f'<a id="{raw_slug}"></a>')
        # Keep the visible C-NN id on one line — a narrow ID column (esp. in the
        # PDF/weasyprint layout) otherwise breaks at the hyphen (`C-\n01`), the
        # same defect the §4 Assets HTML conversion fixes via white-space:nowrap
        # (user report 2026-06-12). The empty `<a id>` anchors are unaffected.
        id_cell = f'{"".join(anchors)}<span style="white-space:nowrap">{canonical}</span>'
        if has_runtime:
            row = f"| {id_cell} | {name} | {kind} | {runtime} | {paths_cell} | {th_cell} |"
        else:
            row = f"| {id_cell} | {name} | {kind} | {paths_cell} | {th_cell} |"
        if show_scope:
            row += " Out of scope |" if raw in excluded_ids else " Analyzed |"
        table_lines.append(row)
    table_lines.append("")
    insertion = "\n".join(table_lines)
    # Replace the section body (between `### 2.3 …` and the next `### `) with
    # the cleaned prose/mermaid followed by the deterministic table.
    return md[: m.end()] + "\n" + cleaned_body.rstrip() + "\n" + insertion + md[section_end:]


def _inject_security_architecture_links(ctx: RenderContext, md: str) -> str:
    """Post-process §7: ensure every `**Linked threats:**` line inside a
    `### 7.x` subsection has its T-NNN / F-NNN refs linkified with labels.

    The reference convention emits multiple-reference blocks as BULLET LISTS
    (one `- [ID] — label` per line), not comma-separated inline. That is much
    easier to scan for reviewers. The post-processor rewrites the entire
    line + its trailing comma-separated refs into the bullet-list form.

    Also linkifies bare `CWE-NNN` references in the entire fragment to
    `[CWE-NNN](https://cwe.mitre.org/data/definitions/NNN.html)`, except
    inside fenced code blocks.
    """

    def linkify_line(m):
        prefix = m.group("prefix")
        refs_text = m.group("refs") or ""
        if not refs_text.strip() or refs_text.strip().lower() in ("(none)", "none", "n/a"):
            return prefix + " None identified."
        ids = list(dict.fromkeys(re.findall(r"\b([FTM]-\d{3,4})\b", refs_text)))
        if not ids:
            return m.group(0)
        if len(ids) == 1:
            return f"{prefix} {ctx.linkify_with_label(ids[0])}"
        # Multi-ref → bullet list (reference convention).
        bullets = "\n".join(f"- {ctx.linkify_with_label(r)}" for r in ids)
        return f"{prefix}\n\n{bullets}"

    md = re.sub(
        r"(?P<prefix>\*\*Linked threats?:\*\*)(?P<refs>[^\n]*)",
        linkify_line,
        md,
    )

    # Linkify bare CWE-NNN references outside fenced code blocks.
    md = _linkify_bare_cwes(md)

    # Surface the applicable systemic conclusions at the control boundary where
    # an architect will look for them.  The links point outward to W-entries;
    # this is context, not a second findings register.
    weaknesses = ctx.yaml_data.get("weaknesses") or []
    security_arch = (ctx.contract.get("sections") or {}).get("security_architecture") or {}
    routing = (security_arch.get("schema_v2") or {}).get("finding_routing") or {}
    if weaknesses and routing:
        threats_by_id = {
            (t.get("id") or t.get("t_id") or "").upper(): t
            for t in (ctx.yaml_data.get("threats") or []) if isinstance(t, dict)
        }
        for heading, rule in routing.items():
            allowed_cwes = {str(c).upper() for c in (rule.get("cwes") or [])}
            allowed_clusters = set(rule.get("clusters") or [])
            relevant = []
            for w in weaknesses:
                if not isinstance(w, dict) or not w.get("id"):
                    continue
                wc = w.get("weakness_class")
                wc_match = wc in allowed_clusters
                cwe_match = any(
                    (threats_by_id.get((i.get("id") or "").upper(), {}).get("cwe") or "").upper() in allowed_cwes
                    for i in (w.get("instances") or []) if isinstance(i, dict)
                )
                if wc_match or cwe_match:
                    relevant.append(w)
            if not relevant:
                continue
            links = ", ".join(
                f"[{w['id']}](#{str(w['id']).lower()})" for w in relevant
            )
            pattern = r"(^###\s+" + re.escape(heading) + r"\s*$)"
            md = re.sub(pattern, r"\1\n\n**Systemic weaknesses:** " + links, md, count=1, flags=re.MULTILINE)
    return md


def _section7_region_bounds(md_lines: list[str]) -> tuple[int, int]:
    """Return (start, end) line indices of the §7 Security Architecture chapter
    (start inclusive at the `## 7.` heading, end exclusive at the next `## `).
    Returns (-1, -1) when §7 is absent."""
    start = -1
    for i, ln in enumerate(md_lines):
        if re.match(r"^##\s+7\.\s+Security Architecture\b", ln):
            start = i
            break
    if start < 0:
        return -1, -1
    end = len(md_lines)
    for j in range(start + 1, len(md_lines)):
        if re.match(r"^##\s+(?!#)", md_lines[j]):
            end = j
            break
    return start, end


def _section7_number_and_bulletize(md: str) -> str:
    """§7 readability (2026-05-30 user request):
      * number each H4 control sub-control as `7.X.N <name>` (the QA gates
        already strip the numeric prefix before matching, so this is safe);
      * render the `**Controls covered:**` line as a bullet list.
    Scoped strictly to the §7 chapter so `#### M-001` (§9) etc. are untouched.
    Idempotent — already-numbered headings are left as-is."""
    lines = md.split("\n")
    start, end = _section7_region_bounds(lines)
    if start < 0:
        return md
    out_head = lines[:start]
    out_tail = lines[end:]
    body = lines[start:end]

    _h4_re = re.compile(r"^####\s+(.*\S)\s*$")
    _anchor_re = re.compile(r'<a\s+id="([a-z0-9-]+)"\s*></a>')
    _already_num_re = re.compile(r"^\d+(?:\.\d+)+\s")

    def _gh_slug(text: str) -> str:
        s = re.sub(r"[^\w\s-]", "", text.lower())
        return re.sub(r"\s+", "-", s.strip())

    # ---- Pass 1: assign 7.X.N numbers; map anchor + control-name → number. ----
    anchor_num: dict[str, str] = {}
    name_num: dict[str, str] = {}
    section_slug_num: dict[str, str] = {}  # §7.X heading slug → "7.X" (for §7.1 links)
    cur_section: str | None = None
    h4_n = 0
    in_fence = False
    pending_anchors: list[str] = []
    for line in body:
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        am = _anchor_re.search(line.strip())
        if am and line.strip().startswith("<a"):
            pending_anchors.append(am.group(1))
            continue
        m3 = re.match(r"^###\s+(7\.\d+)\b\s*(.*)$", line)
        if m3:
            cur_section = m3.group(1)
            section_slug_num[_gh_slug(f"{m3.group(1)} {m3.group(2)}".strip())] = m3.group(1)
            h4_n = 0
            pending_anchors = []
            continue
        m4 = _h4_re.match(line)
        if m4 and cur_section:
            name = m4.group(1).strip()
            h4_n += 1
            # Always use the sequentially-assigned number (not the fragment's
            # stale number) so that Pass-1 name_num matches Pass-2 renumbering.
            # An unnumbered H4 (e.g. "#### Threat Hypotheses Requiring
            # Validation") that precedes numbered siblings shifts all subsequent
            # fragment numbers by 1; Pass 2 re-assigns correctly, but if Pass 1
            # preserves the old fragment number the link-prefix lookup diverges.
            num = f"{cur_section}.{h4_n}"
            plain = re.sub(r"^\d+(?:\.\d+)+\s+", "", name).strip()
            name_num[plain.lower()] = num
            for a in pending_anchors:
                anchor_num[a] = num
            pending_anchors = []
            continue
        if line.strip():
            pending_anchors = []

    def _prefix_link(lk: str) -> str:
        """Prefix a `[name](#anchor)` control link with its 7.X.N number."""
        m = re.match(r"\[([^\]]+)\]\(#([a-z0-9-]+)\)", lk)
        if not m:
            return lk
        text, anchor = m.group(1).strip(), m.group(2)
        if _already_num_re.match(text):
            return lk  # already numbered
        num = anchor_num.get(anchor) or section_slug_num.get(anchor) or name_num.get(text.lower())
        if not num:
            return lk
        return f"[{num} {text}](#{anchor})"

    # ---- Pass 2: renumber headings + bulletize Controls covered. ----
    result: list[str] = []
    cur_section = None
    h4_n = 0
    in_fence = False
    for line in body:
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            result.append(line)
            continue
        if not in_fence:
            m3 = re.match(r"^###\s+(7\.\d+)\b", line)
            if m3:
                cur_section = m3.group(1)
                h4_n = 0
                result.append(line)
                continue
            m4 = _h4_re.match(line)
            if m4 and cur_section:
                name = m4.group(1).strip()
                h4_n += 1
                # Strip any existing N.N(.N) prefix and re-assign the number
                # sequentially so an injected un-numbered opener (normalize's
                # "#### Validation Approach" inserted ahead of an already-
                # numbered authored "#### 7.6.1 Input Validation…") cannot
                # collide into a DUPLICATE 7.6.1. Pass 2 is the single
                # authority for §7.X.N numbers. Still idempotent: a second
                # pass strips "7.6.1" then re-emits "7.6.1".
                name = re.sub(r"^\d+(?:\.\d+)+\s+", "", name)
                result.append(f"#### {cur_section}.{h4_n} {name}")
                continue
            mc = re.match(r"^(\s*)\*\*Controls covered:\*\*\s*(.+?)\s*$", line)
            if mc and cur_section:
                indent, inline = mc.group(1), mc.group(2)
                links = re.findall(r"\[[^\]]+\]\([^)]+\)", inline)
                if links and inline.lstrip()[:1] != "-":
                    result.append(f"{indent}**Controls covered:**")
                    result.append("")
                    for lk in links:
                        result.append(f"{indent}- {_prefix_link(lk)}")
                    continue
            # Already-bulletized Controls-covered list item → add the number.
            mb = re.match(r"^(\s*)-\s+(\[[^\]]+\]\(#[a-z0-9-]+\))\s*$", line)
            if mb and cur_section:
                result.append(f"{mb.group(1)}- {_prefix_link(mb.group(2))}")
                continue
            # §7.1 overview table rows — prefix the category link with its 7.X
            # section number (`[7.2 Identity and Authentication Controls](#…)`).
            if cur_section == "7.1" and line.lstrip().startswith("| ["):
                line = re.sub(
                    r"\[[^\]]+\]\(#[0-9][0-9a-z-]+\)",
                    lambda m: _prefix_link(m.group(0)),
                    line,
                    count=1,
                )
                result.append(line)
                continue
        result.append(line)

    return "\n".join(out_head + result + out_tail)


def _section7_inline_findings_id_only(ctx: RenderContext, md: str) -> str:
    """§7 readability (2026-05-30 user request): in §7 prose, reduce inline
    finding references to ID-only links — the titled enumeration already lives
    in each control's `**Relevant findings**` block, so repeating the title in
    the assessment is redundant. Lines that ARE finding bullets (`- [F-NNN]…`,
    the Relevant-findings list) keep their label. Only strips a suffix that
    exactly matches the finding's known short label, so legitimate parentheticals
    are never touched."""
    lines = md.split("\n")
    start, end = _section7_region_bounds(lines)
    if start < 0:
        return md

    # Collect every finding ref in §7 and its short label.
    region = "\n".join(lines[start:end])
    refs = set(re.findall(r"\[([FT]-\d{3,4})\]\(#[ft]-\d+\)", region))
    strip_map: dict[str, str] = {}
    for ref in refs:
        canon = re.sub(r"^T-", "F-", ref)
        label = (ctx.lookup_label(canon) or ctx.lookup_label(ref) or "").strip()
        short = label.split(" — ", 1)[0].strip()
        short = re.sub(r"\s*\([^()]*\)\s*$", "", short).strip()
        if short:
            strip_map[ref] = short
    if not strip_map:
        return md

    _bullet_re = re.compile(r"^\s*-\s*\[[FT]-\d")
    # Bare finding-id text (not already inside a link / code span) → ID-only
    # link. Matches `F-019` / `T-004` when NOT preceded by `[` or a word char
    # and NOT followed by `]` or a word char.
    _bare_id_re = re.compile(r"(?<![\[\w`/-])([FT]-\d{3,4})(?![\w\]`-])")

    def _bare_to_link(m: re.Match[str]) -> str:
        ref = m.group(1)
        anchor = re.sub(r"^t-", "f-", ref.lower())
        return f"[{ref}](#{anchor})"

    in_fence = False
    for i in range(start, end):
        line = lines[i]
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence or re.match(r"^\s{0,3}#{1,6}\s", line):
            continue
        if _bullet_re.match(line):
            continue  # Relevant-findings bullet — keep the title.
        if line.lstrip().startswith("|"):
            # §7 TABLE rows (e.g. the §7.2 Authentication-mechanisms inventory
            # 'Findings' column) are summary tables, not prose — their finding
            # links are meant to carry a short title (the no-bare-ID rule). The
            # ID-only reduction targets repetitive PROSE references only, so it
            # must not strip titles from table cells (2026-06-02 'leer betitelt').
            continue
        # 1. Strip the known-label suffix from any already-linked finding ref.
        if "](#f-" in line or "](#t-" in line:
            for ref, short in strip_map.items():
                link = f"[{ref}](#{ref.lower()})"
                if link not in line:
                    continue
                for sep in (f" ({short})", f" — {short}", f" - {short}"):
                    line = line.replace(link + sep, link)
        # 2. Linkify bare finding-id text → ID-only link (skip anchor decls).
        if "<a id=" not in line:
            line = _bare_id_re.sub(_bare_to_link, line)
        lines[i] = line
    return "\n".join(lines)


def _section7_title_relevant_findings(ctx: RenderContext, md: str) -> str:
    """§7 consistency (2026-07-02 user request): give every finding link inside
    a §7 bullet the same short register title used in §5/§8, so §7 references are
    never a bare ID or a rationale-sentence-only label.

    ``_section7_inline_findings_id_only`` deliberately SKIPS bullet lines
    ("keep the title") — but the LLM authors the ``**Relevant findings**``
    bullets as ``- 🔴 [F-NNN](#f-nnn) — <relevance rationale>`` with no title, so
    nothing actually titles them. This pass rewrites each bare-ID finding link in
    a §7 bullet to ``[F-NNN — <class title>](#f-nnn)`` and LEAVES the trailing
    rationale intact. Only bare-ID links match, so it is idempotent and never
    touches an already-titled link. Scoped strictly to the §7 chapter."""
    lines = md.split("\n")
    start, end = _section7_region_bounds(lines)
    if start < 0:
        return md
    region = "\n".join(lines[start:end])
    label_map: dict[str, str] = {}
    for ref in set(re.findall(r"\[(F-\d{3,4})\]\(#f-\d+\)", region)):
        label = (ctx.lookup_label(ref) or "").strip()
        short = label.split(" — ", 1)[0].strip()
        short = re.sub(r"\s*\([^()]*\)\s*$", "", short).strip()
        if short:
            label_map[ref] = short
    if not label_map:
        return md

    _bullet_re = re.compile(r"^\s*-\s")
    _bare_link_re = re.compile(r"\[(F-\d{3,4})\]\(#f-\d+\)")

    def _title_link(m: re.Match[str]) -> str:
        ref = m.group(1)
        short = label_map.get(ref)
        return f"[{ref} — {short}](#{ref.lower()})" if short else m.group(0)

    in_fence = False
    for i in range(start, end):
        line = lines[i]
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence or not _bullet_re.match(line):
            continue
        lines[i] = _bare_link_re.sub(_title_link, line)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Enrich markdown-fragment tables whose columns link Threat / Mitigation /
# Finding IDs. Prior LLM-authored fragments emitted bare `[T-003](#t-003)`
# (without a label) and often comma-joined a handful of IDs on one line. Both
# styles degrade readability compared to the stacked `id — label` form used
# throughout the computed sections (Top Findings, Mitigation Register,
# Operational Strengths). This post-processor harmonises them.
# ---------------------------------------------------------------------------

# Column headers that identify a Linked-ID cell. Matched case-insensitively
# and with trailing whitespace trimmed. New columns can be added here without
# regex changes elsewhere.
_LINKED_ID_COLUMN_HEADERS: frozenset[str] = frozenset(
    {
        "linked threats",
        "linked mitigations",
        "linked findings",
        "linked",
        "mitigates",
        "addresses",
        "covers",
        "primary mitigations",
        "key findings",
        # Singular "Mitigation" is the §8 Findings Register column header where
        # rows used to ship as bare `[M-NNN](#m-nnn)` because the cell builder
        # bypassed linkify_with_label. Including the singular form makes the
        # post-render enrichment a defense-in-depth net for any future call
        # site that emits bare M-NNN links into a column with this header.
        "mitigation",
    }
)

_ID_LINK_RE = re.compile(r"\[([FTMC]-\d{2,4}|TH-\d{2})\]\(#[a-z0-9-]+\)")
_MD_TABLE_ROW_RE = re.compile(r"^\|.*\|\s*$")
_MD_TABLE_SEP_RE = re.compile(r"^\|\s*:?-{3,}[\s:|-]*\|\s*$")
# Threat-register declaration anchors look like `<a id="t-003"></a>T-003` —
# they must never be rewritten into `[T-003](#t-003) — label` because that
# would turn a declaration into a cross-reference and break the anchor.
_DECLARATION_ANCHOR_RE = re.compile(r'<a\s+id="[a-z0-9-]+"\s*></a>')


def _iter_md_table_blocks(md: str):
    """Yield (header_line_idx, list_of_lines) for every GFM table found
    outside fenced code blocks.

    ``header_line_idx`` is the 0-based index into ``md.split("\\n")`` — the
    caller uses it to locate and rewrite body-row lines in the full
    document. Tracking the offset accurately across chunked splits is
    critical: a mis-count by one line means the body-row overwrite targets
    the wrong line and silently corrupts the document.
    """
    # Split on fences so we skip code-block tables.
    chunks = re.split(r"(```[^\n]*\n.*?\n```)", md, flags=re.DOTALL)
    offset = 0
    for chunk in chunks:
        if chunk.startswith("```"):
            # Code chunks contribute `count("\n")` full lines, then re.split
            # consumes no separator between chunks — so offset += count is
            # the correct accumulator.
            offset += chunk.count("\n")
            continue
        lines = chunk.split("\n")
        i = 0
        while i < len(lines) - 1:
            if _MD_TABLE_ROW_RE.match(lines[i]) and _MD_TABLE_SEP_RE.match(lines[i + 1]):
                start = i
                j = i + 2
                while j < len(lines) and _MD_TABLE_ROW_RE.match(lines[j]):
                    j += 1
                yield offset + start, lines[start:j]
                i = j
            else:
                i += 1
        # `split("\n")` returns N+1 parts for N separators. We advance the
        # offset by the number of separators (== newlines) the chunk itself
        # contributes to the document; the +1 "last fragment" belongs to the
        # NEXT chunk (its first fragment is the continuation after the last
        # newline). For an all-content chunk ending with \n, count("\n")
        # matches the advancement exactly.
        offset += chunk.count("\n")


def _split_table_row(row: str) -> list[str]:
    stripped = row.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    return [c.strip() for c in stripped.split("|")]


# ---------------------------------------------------------------------------
# General table column-width normalisation (2026-05-30 user request: "Tabellen
# kompakter, sinnvolle Verteilung der Spaltenbreiten, keine IDs brechen").
#
# GFM ignores the dash-run length of a separator row (all columns size to
# content), but Pandoc — the converter that produces the HTML/PDF deliverable —
# turns the RELATIVE dash lengths into explicit `<col style="width:N%">`. So a
# single post-pass that rewrites every table's separator with weights derived
# from the column's *role* (narrow ID/severity columns, generous finding/link
# columns, capped description columns) gives every table a sensible, compact
# layout without per-table tuning. Deterministic + idempotent.
# ---------------------------------------------------------------------------

# Per-role width BOUNDS (floor, cap). The actual width is the column's real
# content length clamped into its role's band — so a short Notes column stays
# compact and a long one gets room, but a Description never crowds out a
# finding/link column and an ID column never balloons. "sinnvolle Verteilung".
_TBL_ROLE_BOUNDS: dict[str, tuple[int, int]] = {
    # Caps are SPREAD so a long column lands at its role ceiling and the
    # ordering reads links > desc > default > medium > narrow — e.g. an
    # Assets table gives Linked-Threats the most room, Description second,
    # the short Asset/Classification/ID columns least (2026-05-30 tuning:
    # desc cap used to equal default cap, so a 193-char Description rendered
    # the same width as a 28-char Asset name).
    "narrow": (3, 8),  # #, id, auth, effort, priority, method
    "medium": (7, 14),  # risk, severity, classification, status, verdict, cwe
    "default": (8, 22),  # control, asset, component, implementation, …
    "path": (12, 40),  # route, path, endpoint, location, key paths — long
    # slash/dotted identifiers that wrap badly at the
    # default 22 cap (2026-06-02: /rest/.../:continueCode)
    "desc": (14, 36),  # description, notes, scenario, reason — capped < links
    "links": (16, 48),  # finding / threat / mitigation link columns (widest)
}
_TBL_W_MIN = 3
# Back-compat representative weights (role cap) — referenced by tests.
_TBL_W_NARROW = _TBL_ROLE_BOUNDS["narrow"][1]
_TBL_W_MEDIUM = _TBL_ROLE_BOUNDS["medium"][1]
_TBL_W_DESC = _TBL_ROLE_BOUNDS["desc"][1]
_TBL_W_LINKS = _TBL_ROLE_BOUNDS["links"][1]
_TBL_W_DEFAULT = _TBL_ROLE_BOUNDS["default"][1]


def _table_col_role(header: str) -> str:
    """Classify a table header into a width role. Description-type tokens are
    checked BEFORE link-type tokens so 'Threat Description' is a (narrower)
    description column, not a (wide) threats column."""
    h = re.sub(r"[`*_]", "", header or "").strip().lower()
    if not h:
        return "default"
    if h in {"#", "id", "ids", "auth", "effort", "priority", "protocol", "method", "factor", "level", "p", "sev"}:
        return "narrow"
    if h in {"risk", "severity", "cwe", "cwes", "status", "verdict", "classification", "required role", "role"}:
        return "medium"
    # Path/route/location columns hold long slash- or dot-separated identifiers
    # that wrap at the default 22 cap — checked before "desc" so "Key Paths"
    # is a path column, and before "links" so "Location"/"Route" never fall to
    # default. Excludes "evidence" (often file:line, but kept in desc-ish flow).
    if any(tok in h for tok in ("route", "endpoint", "location", "key path")) or h in {
        "path",
        "paths",
        "file",
        "files",
    }:
        return "path"
    if any(
        tok in h
        for tok in (
            "description",
            "notes",
            "scenario",
            "reason",
            "rationale",
            "details",
            "meaning",
            "impact",
            "assessment",
            "what it asks",
        )
    ):
        return "desc"
    if any(tok in h for tok in ("finding", "threat", "addresses", "mitigat", "covers", "linked")):
        return "links"
    return "default"


def _table_col_weight(header: str) -> int:
    """Representative (cap) width for a header's role — kept for tests."""
    return _TBL_ROLE_BOUNDS[_table_col_role(header)][1]


def _table_cell_visible_len(cell: str) -> int:
    """Approximate the widest rendered line in a table cell: split on <br/>,
    strip markdown link syntax / backticks / bold / html tags, return the max
    visible-segment length (so a `<br/>`-stacked link column is sized by its
    longest single entry, not the sum)."""
    longest = 0
    for seg in re.split(r"<br\s*/?>", cell or ""):
        s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", seg)  # [text](url) → text
        s = re.sub(r"<[^>]+>", "", s)  # strip html tags
        s = s.replace("`", "").replace("**", "").replace("*", "").replace("\u200b", "").strip()
        longest = max(longest, len(s))
    return longest


def _seg_visible_len(seg: str) -> int:
    """Visible length of a single (no-<br/>) cell segment — markdown stripped."""
    s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", seg)
    s = re.sub(r"<[^>]+>", "", s)
    return len(s.replace("`", "").replace("**", "").replace("*", "").replace("\u200b", "").strip())


def _wrap_segment_words(seg: str, width: int) -> str:
    """Word-wrap one segment to `width` visible chars, joining lines with <br/>.
    Never breaks inside a backtick code span (defers the break until the running
    line has balanced backticks)."""
    if _seg_visible_len(seg) <= width:
        return seg
    out: list[str] = []
    cur = ""
    for word in seg.split(" "):
        cand = f"{cur} {word}".strip() if cur else word
        if cur and _seg_visible_len(cand) > width and cur.count("`") % 2 == 0:
            out.append(cur)
            cur = word
        else:
            cur = cand
    if cur:
        out.append(cur)
    return "<br/>".join(out)


# Tables that qa autofix re-emits as fixed-layout HTML (`<table table-layout:
# fixed>` + colgroup). They must be EXEMPT from soft-wrapping: the fixed column
# reflows prose on its own, and the 44-char `<br/>` breaks soft-wrap would inject
# survive verbatim into the HTML cells as confusing mid-phrase line breaks
# (juice-shop §4 Assets Description, §1 Operational Strengths "What's in Place").
# Keep in sync with qa_checks `_FIXED_LAYOUT_SPECS`.
_FIXED_LAYOUT_TABLE_HEADERS = frozenset(
    {
        ("Method", "Route", "Risk", "Notes"),
        ("Asset", "Classification", "Description", "Linked Threats"),
        ("Strength", "What's in Place", "Effectiveness", "Gap", "Mitigates"),
    }
)


def _softwrap_prose_table_cells(md: str, width: int = 44) -> str:
    """Soft-wrap long PROSE table cells with `<br/>` so markdown-it (the VS Code
    preview / GitHub) — which auto-sizes columns by content and IGNORES the
    proportional separator widths Pandoc honours — does not hand a long
    Description / narrative column most of the table, squeezing the finding/link
    columns (2026-06-04 user report w/ screenshots: §4 Linked Threats clipped,
    §2 Threat Description ~half the table).

    Only `desc` / `default` / `path`-role columns are wrapped; `links` / `narrow`
    / `medium` columns and any cell containing a `](#` cross-reference link are
    left untouched (those size themselves via their own `<br/>` chip stacking).
    Idempotent (a cell already ≤ width is unchanged) and PDF-safe (Pandoc still
    applies the proportional `<col>` widths; the extra breaks fall near where the
    text would wrap anyway). Each existing `<br/>` segment is wrapped
    independently so an authored bold-name + narrative cell keeps its structure.
    """
    lines = md.split("\n")
    for header_idx, block in _iter_md_table_blocks(md):
        header_cells = _split_table_row(block[0])
        _hdr = tuple(h.strip() for h in header_cells)
        if _hdr in _FIXED_LAYOUT_TABLE_HEADERS:
            continue  # becomes fixed-layout HTML — reflows itself, don't inject <br/>
        # Structural-threats / security-posture table (`# | Threat Description |
        # …`): its Threat-Description cell is a `**title**<br/>_(stride)_<br/>prose`
        # composite. The 44-char soft-wrap chopped the prose into 4-5 stub lines
        # ("…server-side<br/>interpreter…<br/>OS<br/>shell…") that read as random
        # breaks in the PDF (user report 2026-06-12). It carries `<a id="path-*">`
        # anchors referenced by the §6 heatmap, so it can't be HTML-converted
        # safely — exempt it and let the PDF's proportional column widths wrap the
        # prose naturally. (markdown-it sizes it wider, but the Findings column's
        # `<br/>`-stacked links balance the row.)
        if _hdr[:2] == ("#", "Threat Description"):
            continue
        wrap_cols = {i for i, h in enumerate(header_cells) if _table_col_role(h) in ("desc", "default", "path")}
        if not wrap_cols:
            continue
        for body_off in range(2, len(block)):
            row_idx = header_idx + body_off
            if row_idx >= len(lines):
                break
            cells = _split_table_row(lines[row_idx])
            if len(cells) != len(header_cells):
                continue  # ragged row — leave it for the QA gate to flag
            changed = False
            for i in wrap_cols:
                cell = cells[i]
                if "](#" in cell:  # carries a cross-ref link — skip
                    continue
                if _table_cell_visible_len(cell) <= width:
                    continue
                wrapped = "<br/>".join(_wrap_segment_words(seg, width) for seg in re.split(r"<br\s*/?>", cell))
                if wrapped != cell:
                    cells[i] = wrapped
                    changed = True
            if changed:
                lines[row_idx] = "| " + " | ".join(cells) + " |"
    return "\n".join(lines)


def _normalize_table_column_widths(md: str) -> str:
    """Rewrite every GFM table separator with CONTENT-AWARE proportional widths:
    each column's real content length clamped into its role band. Separator-only
    change (cell content untouched); GitHub ignores it, Pandoc honours it as
    relative `<col>` widths. Idempotent."""
    lines = md.split("\n")
    for header_idx, block in _iter_md_table_blocks(md):
        sep_idx = header_idx + 1
        if sep_idx >= len(lines) or not _MD_TABLE_SEP_RE.match(lines[sep_idx]):
            continue
        header_cells = _split_table_row(block[0])
        ncol = len(header_cells)
        # Measure max visible content length per column (header + body rows).
        content = [_table_cell_visible_len(h) for h in header_cells]
        for row in block[2:]:
            cells = _split_table_row(row)
            for i in range(min(ncol, len(cells))):
                content[i] = max(content[i], _table_cell_visible_len(cells[i]))
        orig_cells = _split_table_row(lines[sep_idx])
        new_cells: list[str] = []
        for i, h in enumerate(header_cells):
            lo, hi = _TBL_ROLE_BOUNDS[_table_col_role(h)]
            w = max(_TBL_W_MIN, min(hi, max(lo, content[i])))
            oc = orig_cells[i] if i < len(orig_cells) else "---"
            left = oc.startswith(":")
            right = oc.endswith(":")
            new_cells.append((":" if left else "") + ("-" * w) + (":" if right else ""))
        lines[sep_idx] = "|" + "|".join(new_cells) + "|"
    return "\n".join(lines)


_REF_TRAILING_LOC_RE = re.compile(
    r"(\[[FTM]-\d+\]\(#[ftm]-\d+\)[^\n|\[<]*?)"  # a finding/mitigation link + its (locator-free) label
    r"\((?!`)([\w./\\-]+\.[A-Za-z0-9]{1,6}(?::\d+(?:-\d+)?)?)\)"  # an un-backticked (path/file[:line[-line]]) right after
)


def _normalize_reference_locators(md: str) -> str:
    """Backtick + basename an un-backticked locator that trails a finding/
    mitigation reference. Fragment-agnostic catch-all for cross-references that
    bypassed ``linkify_with_label`` (LLM-authored §7 control tables etc.).

    Already-backticked locators are skipped by the ``(?!`)`` guard, so the
    Findings index's deliberate full path is preserved. The gap between the link
    and the locator forbids ``[`` / ``<`` / ``|`` so a locator is never attached
    across a sibling reference, an HTML tag, or a table-cell boundary."""

    def _repl(m: re.Match[str]) -> str:
        return f"{m.group(1)}(`{_basename_locator(m.group(2))}`)"

    return _REF_TRAILING_LOC_RE.sub(_repl, md)


def _enrich_linked_id_cells(ctx: RenderContext, md: str) -> str:
    """Rewrite table cells in Linked-ID columns as stacked ``[ID](#id) — label``
    entries. Idempotent, fragment-type-agnostic.

    Scope:
      * Applies to every GFM table whose header row contains a column whose
        text (lowercased, trimmed) matches ``_LINKED_ID_COLUMN_HEADERS``.
      * For each body cell in such a column, extracts all ``[ID](#…)`` links
        found in the cell, resolves each to ``[ID](#id) — label`` via
        ``ctx.linkify_with_label``, and re-joins them with ``<br/>``.
      * Non-link text in the cell is discarded only when the cell would
        otherwise consist of nothing but IDs + separators (``, ``/``; ``/
        whitespace/``<br/>``). Cells with meaningful prose around the links
        are left alone — we only rewrite bare-list cells.

    Skipped cells:
      * The cell contains a declaration anchor (``<a id="…"></a>``) — this
        is the Findings Register / Mitigation Register `| <a id="t-003"></a>T-003 | …` style.
      * The cell contains zero ID-shaped links.
      * The cell contains exactly one link that already carries ``— label``.
    """
    out_lines = md.split("\n")
    for header_idx, block in _iter_md_table_blocks(md):
        header_cells = _split_table_row(block[0])
        # NOTE (2026-06-02): the §4 Assets table is no longer skipped. The user
        # reversed the earlier "bare chips" preference and now wants the §4
        # Linked-Threats cells to carry short titles, consistent with §8/§9.
        # The `·`-joined bare chips gen_assets emits qualify as a pure-ID list
        # (see the `·` separator handling in `_rewrite_linked_id_cell`) and are
        # rewritten here to the canonical `[F-NNN](#f-nnn) — title` stacked
        # form. The assets column-width tuning already gives Linked-Threats the
        # most room, so the wider cell does not crush the short ID column.
        # Map: column index → canonical header (if it matches a known label).
        enrichable: dict[int, str] = {}
        for ci, h in enumerate(header_cells):
            if h.strip().lower() in _LINKED_ID_COLUMN_HEADERS:
                enrichable[ci] = h.strip()
        if not enrichable:
            continue

        # Walk body rows (skip header + separator).
        for offset in range(2, len(block)):
            line_idx = header_idx + offset
            if line_idx >= len(out_lines):
                break
            row = out_lines[line_idx]
            if not _MD_TABLE_ROW_RE.match(row):
                continue
            cells = _split_table_row(row)
            if len(cells) != len(header_cells):
                continue
            changed = False
            for ci in enrichable:
                cell = cells[ci]
                new_cell = _rewrite_linked_id_cell(ctx, cell)
                if new_cell != cell:
                    cells[ci] = new_cell
                    changed = True
            if changed:
                out_lines[line_idx] = "| " + " | ".join(cells) + " |"
    return "\n".join(out_lines)


def _rewrite_linked_id_cell(ctx: RenderContext, cell: str) -> str:
    """Return the rewritten cell, or the original if nothing should change.

    Rules (see ``_enrich_linked_id_cells`` docstring for full spec):
      1. Skip if the cell carries a declaration anchor.
      2. Extract every ``[ID](#…)`` link in order, deduplicated.
      3. If the cell's non-ID-link content is only separators / whitespace
         (i.e. the cell is a pure ID list), rewrite as stacked labelled
         form. Otherwise leave alone.
      4. If exactly one link is present AND it already has ``— <text>``
         trailing, skip (already enriched).
    """
    if not cell or cell.strip() in ("", "—", "-", "None", "none", "N/A", "n/a"):
        return cell
    if _DECLARATION_ANCHOR_RE.search(cell):
        return cell
    ids = _ID_LINK_RE.findall(cell)
    if not ids:
        # Fall-back: the cell may carry bare-text IDs (`T-001, T-002`) that
        # the fragment author emitted without wrapping in `[...](#...)`.
        # Treat the cell as a candidate ID list iff every token left after
        # stripping the bare IDs is a separator/whitespace/break-tag. Same
        # safety check as below, just one branch up so we never rewrite
        # cells that carry prose around the IDs.
        bare_ids = re.findall(r"(?<!\[)\b([FTMC]-\d{2,4}|TH-\d{2})\b(?!\])", cell)
        if not bare_ids:
            return cell
        stripped_bare = re.sub(r"\b([FTMC]-\d{2,4}|TH-\d{2})\b", "", cell)
        residue_bare = re.sub(r"(<br/?>|·|[🔴🟠🟡🟢⚪]|[,;\s])+", "", stripped_bare).strip()
        if residue_bare:
            return cell
        seen_b: set[str] = set()
        ordered_b: list[str] = []
        for rid in bare_ids:
            if rid not in seen_b:
                seen_b.add(rid)
                ordered_b.append(rid)
        rendered_b = [ctx.linkify_with_label(rid) for rid in ordered_b]
        return "<br/>".join(rendered_b)

    # Strip every ID-link occurrence from the cell; what remains is the
    # "surrounding" text. If that residue is only separators/whitespace/
    # break tags, the cell is a pure ID list and we can rewrite freely.
    stripped = _ID_LINK_RE.sub("", cell)
    # Also strip `— <label>` trailers so single-already-enriched cells look
    # empty when separator-only.
    stripped = re.sub(r"—\s*[^,;<|]+", "", stripped)
    # Strip parens-form `(label)` trailers too — the §2.3 Components
    # Linked-Threats cell ships its titles as `[F-NNN](#f-nnn) (title)`, which
    # otherwise reads as prose here and skips enrichment, leaving the finding
    # links without their severity dot. Treating the parenthetical as a label
    # lets the cell qualify as a pure ID list and be re-linkified (with dot).
    stripped = re.sub(r"\([^()]*\)", "", stripped)
    residue = re.sub(r"(<br/?>|·|[🔴🟠🟡🟢⚪]|[,;\s])+", "", stripped).strip()
    if residue:
        # Cell has meaningful prose — do not touch it.
        return cell

    # Deduplicate while preserving order.
    seen: set[str] = set()
    ordered: list[str] = []
    for rid in ids:
        if rid not in seen:
            seen.add(rid)
            ordered.append(rid)

    rendered = [ctx.linkify_with_label(rid) for rid in ordered]
    new_cell = "<br/>".join(rendered)
    return new_cell


# ---------------------------------------------------------------------------
# Section cross-reference linkifier (`§N`, `§N.M`, `§N.M.K` → anchor links).
# ---------------------------------------------------------------------------

# Match bare section references like §7, §7.1, §7.3.2 (1-3 numeric levels).
# Negative-lookbehind excludes already-linked text (`[§…]`).
# Negative-lookahead excludes a following digit (so `§7` does not greedily
# split out of `§7.1`) — the alternation in the regex itself handles
# the level-by-level matching.
_SECTION_REF_RE = re.compile(r"(?<!\[)§(\d+(?:\.\d+(?:\.\d+)?)?)(?!\d)")


def _linkify_section_refs(md: str) -> str:
    """Linkify bare `§N` / `§N.M` / `§N.M.K` tokens in prose into clickable
    anchor links targeting the matching `## N` / `### N.M` / `#### N.M.K`
    heading.

    Scope:
      * Builds a number → slug map from headings in the rendered document
        (anything matching `^##{1,3} <number> <title>$`).
      * Substitutes `§N(.M(.K)?)?` in prose with `[§N(.M(.K)?)?](#slug)`.
      * The link covers ONLY the `§N` token plus its numeric suffix — any
        following descriptive prose (e.g. ` Overview - Key architectural
        risks above`) stays bare. This avoids ambiguity over where the
        heading title ends and the descriptive sentence begins.

    Skips:
      * Headings (`#` / `##` / `###` …) — never linkify a heading itself.
      * Fenced code blocks (``` … ```) and HTML comments.
      * Already-linked refs (`[§7.1](#…)` is left untouched via the
        negative-lookbehind `(?<!\\[)`).

    Returns the rewritten markdown.
    """
    # Pass 1: build slug map from headings. Match `## 1. Title`,
    # `### 2.4 Title`, `#### 7.3.1 Title Flow`, etc.
    slug_map: dict[str, str] = {}
    heading_re = re.compile(r"^(#{2,4})\s+(\d+(?:\.\d+(?:\.\d+)?)?)[\.\s]+(.+?)\s*$", re.MULTILINE)
    for m in heading_re.finditer(md):
        hashes, num, title = m.group(1), m.group(2), m.group(3)
        # Slug uses the FULL heading text (number + title). Build the LINK
        # TARGET with github_render_slug — the anchor GitHub/pandoc ACTUALLY
        # render — NOT github_slug (the collapsed generator form). The two
        # diverge for any heading carrying ` / `, ` & `, ` — ` (e.g.
        # `7.9.2 Secret / Key Management` → GitHub `#792-secret--key-management`
        # but github_slug `#792-secret-key-management`), so a github_slug target
        # dangled on every §N.M prose ref into such a subsection. toc_closure
        # already verifies with render_slug, so this makes generator and checker
        # agree. Non-divergent headings are byte-identical under both functions,
        # so no working link changes (juice-shop 2026-07-02).
        slug = _slug_github_render_slug(f"{hashes} {num} {title}")
        slug_map.setdefault(num, slug)

    if not slug_map:
        return md

    def _sub_ref(m: re.Match[str]) -> str:
        num = m.group(1)
        slug = slug_map.get(num)
        if not slug:
            # Try progressively shorter prefixes — `§7.3.99` falls back
            # to `§7.3` then `§7` if the leaf isn't a real heading.
            parts = num.split(".")
            while parts:
                parts.pop()
                if not parts:
                    break
                shorter = ".".join(parts)
                if shorter in slug_map:
                    return f"[§{num}](#{slug_map[shorter]})"
            return m.group(0)  # no resolution → leave bare
        return f"[§{num}](#{slug})"

    # Pass 2: walk the document line-by-line, skipping headings + fenced
    # code blocks, substituting in everything else. Section refs that
    # already sit INSIDE a markdown link label (`[…§3.3…](#…)`) MUST be
    # left alone — wrapping them would produce a nested `[outer [§3.3](#…) ](#…)`
    # link that breaks GitHub/Pandoc/most MD renderers. This is the
    # historical `toc_nested_link` defect: a Story Card back-link
    # `[Walkthrough §3.3](#33-…)` had its `§3.3` re-linkified by this pass.
    # apply_repair_plan.py used to scrub the nested result post-hoc; the
    # cleaner fix is to never produce it.
    def _sub_outside_link_labels(line: str) -> str:
        if "§" not in line:
            return line
        # Split the line into alternating "outside-link" / "inside-link-label"
        # spans. A markdown link label is `[label](target)`. We only
        # substitute §-refs in the outside-link spans. The inside-link-label
        # spans are passed through verbatim.
        out_parts: list[str] = []
        i = 0
        n = len(line)
        while i < n:
            # Find next `[` that opens a link label. A link label is `[X](Y)`
            # where the matching `]` is followed by `(`.
            j = line.find("[", i)
            if j < 0:
                out_parts.append(_SECTION_REF_RE.sub(_sub_ref, line[i:]))
                break
            # Scan for the matching `]` allowing nested `[]` (rare but possible).
            # Then require the next char to be `(` — otherwise this `[` does
            # not start a link, treat as ordinary text.
            depth = 1
            k = j + 1
            while k < n and depth > 0:
                if line[k] == "[":
                    depth += 1
                elif line[k] == "]":
                    depth -= 1
                if depth == 0:
                    break
                k += 1
            if k >= n or line[k] != "]" or (k + 1 < n and line[k + 1] != "("):
                # Not a real link label — substitute up to and including `[`
                # and continue.
                out_parts.append(_SECTION_REF_RE.sub(_sub_ref, line[i : j + 1]))
                i = j + 1
                continue
            # Find the closing `)` of the link target.
            close = line.find(")", k + 1)
            if close < 0:
                out_parts.append(_SECTION_REF_RE.sub(_sub_ref, line[i:]))
                break
            # Outside-link span: substitute. Link span: keep verbatim.
            out_parts.append(_SECTION_REF_RE.sub(_sub_ref, line[i:j]))
            out_parts.append(line[j : close + 1])
            i = close + 1
        return "".join(out_parts)

    # Repair ALREADY-linked section refs whose anchor is stale/wrong. An
    # LLM-authored fragment sometimes hand-writes `[§7.9.2](#792-secret-key-management)`
    # with its own (collapsed, or mis-numbered) anchor guess; the outside-link
    # substitution above deliberately skips inside-link spans, so such a link
    # would ship broken. This pass recomputes the anchor from the §-number in
    # the VISIBLE label (authoritative) against the same slug_map, but ONLY when
    # the label is exactly `§N(.M(.K)?)` — so it can never nest a link or touch a
    # titled link like `[§7.2 Identity …](#…)`. No-op when the anchor already
    # matches (juice-shop 2026-07-02).
    _PRELINKED_REF_RE = re.compile(r"\[§(\d+(?:\.\d+){0,2})\]\(#[^)]+\)")

    def _fix_prelinked(m: re.Match[str]) -> str:
        num = m.group(1)
        slug = slug_map.get(num)
        return f"[§{num}](#{slug})" if slug else m.group(0)

    out_lines: list[str] = []
    in_fence = False
    for chunk in re.split(r"(```[^\n]*\n.*?\n```|<!--.*?-->)", md, flags=re.DOTALL):
        if chunk.startswith("```") or chunk.startswith("<!--"):
            out_lines.append(chunk)
            continue
        lines = chunk.split("\n")
        for i, line in enumerate(lines):
            if re.match(r"^\s{0,3}#{1,6}\s", line):
                # Heading line — never linkify §-refs in headings
                continue
            line = _sub_outside_link_labels(line)
            lines[i] = _PRELINKED_REF_RE.sub(_fix_prelinked, line)
        out_lines.append("\n".join(lines))
    return "".join(out_lines)


def _linkify_bare_cwes(md: str) -> str:
    """Replace bare `CWE-NNN` with `[CWE-NNN](https://cwe.mitre.org/…)` outside
    fenced code blocks and already-linked occurrences.

    Skips:
    - CWEs already inside a Markdown link: `[CWE-NNN](…)`
    - CWEs inside fenced code blocks (``` … ```)
    - CWEs inside HTML comments
    """
    _CWE_BARE = re.compile(r"(?<!\[)\bCWE-(\d+)\b(?!\])")

    def _linkify(m: re.Match) -> str:
        num = m.group(1)
        return f"[CWE-{num}](https://cwe.mitre.org/data/definitions/{num}.html)"

    out_chunks: list[str] = []
    for chunk in re.split(r"(```[^\n]*\n.*?\n```|<!--.*?-->)", md, flags=re.DOTALL):
        if chunk.startswith("```") or chunk.startswith("<!--"):
            out_chunks.append(chunk)
        else:
            out_chunks.append(_CWE_BARE.sub(_linkify, chunk))
    return "".join(out_chunks)


_CWE_TAXONOMY_CACHE: dict[str, Any] | None = None


def _load_cwe_taxonomy() -> dict[str, Any]:
    """Lazy-load and cache the ``cwes`` map from ``data/cwe-taxonomy.yaml``
    (``{"CWE-798": {"title": …, "url": …}, …}``). Empty on absence/parse error
    — callers fall back to a title-less MITRE URL derived from the CWE number."""
    global _CWE_TAXONOMY_CACHE
    if _CWE_TAXONOMY_CACHE is not None:
        return _CWE_TAXONOMY_CACHE
    candidate = PLUGIN_ROOT / "data" / "cwe-taxonomy.yaml"
    try:
        data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
        _CWE_TAXONOMY_CACHE = data.get("cwes") or {}
    except Exception:
        _CWE_TAXONOMY_CACHE = {}
    return _CWE_TAXONOMY_CACHE


def _cwe_reference_link(num: str) -> str:
    """``798`` → ``[CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/…)``.
    Falls back to a title-less ``[CWE-798](url)`` when the CWE is not in the
    taxonomy (URL is always derivable from the number)."""
    entry = _load_cwe_taxonomy().get(f"CWE-{num}") or {}
    title = (entry.get("title") or "").strip()
    url = (entry.get("url") or "").strip() or f"https://cwe.mitre.org/data/definitions/{num}.html"
    label = f"CWE-{num}: {title}" if title else f"CWE-{num}"
    return f"[{label}]({url})"


# Short human-readable source tag per reference host, prefixed onto the derived
# link title so a bare URL renders as a titled, self-describing link.
_REFERENCE_HOST_SOURCE = {
    "cheatsheetseries.owasp.org": "OWASP Cheat Sheet",
    "genai.owasp.org": "OWASP GenAI",
    "owasp.org": "OWASP",
    "docs.github.com": "GitHub Docs",
    "docs.sigstore.dev": "Sigstore Docs",
}


def _humanize_url_slug(seg: str) -> str:
    """``SQL_Injection_Prevention_Cheat_Sheet`` → ``SQL Injection Prevention
    Cheat Sheet``; ``llm06-excessive-agency`` → ``LLM06 Excessive Agency``."""
    seg = re.sub(r"\.html?$", "", seg)
    seg = seg.replace("_", " ").replace("-", " ").strip()
    words: list[str] = []
    for w in seg.split():
        if re.fullmatch(r"llm\d+", w, re.IGNORECASE):
            words.append(w.upper())
        elif re.fullmatch(r"[A-Z0-9]{2,}", w):  # already an acronym (SQL, XSS, CI)
            words.append(w)
        else:
            words.append(w.capitalize())
    return " ".join(words)


def _reference_link_title(url: str) -> str:
    """Derive a human-readable link title from a bare reference URL. Uses the
    last meaningful path segment (fragment/query stripped), prefixed with a
    per-host source tag. Never empty — falls back to the host."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.netloc.lower()
    source = _REFERENCE_HOST_SOURCE.get(host, host)
    segs = [s for s in parsed.path.split("/") if s]
    # Skip a trailing generic segment ("overview", "index") in favour of a more
    # descriptive parent (…/cosign/signing/overview/ → "Signing").
    label = ""
    for seg in reversed(segs):
        cand = _humanize_url_slug(seg)
        if cand and cand.lower() not in {"overview", "index", "en", "latest", "main"}:
            label = cand
            break
    if not label:
        return source
    # Avoid stutter when the slug already leads with the source words.
    if label.lower().startswith(source.lower()):
        return label
    return f"{source}: {label}"


def _normalize_reference(ref: str) -> str:
    """Render a mitigation ``reference`` value as a consistent, titled Markdown
    link. Handles the two shapes the analyst ships raw: a bare ``CWE-NNN`` and a
    bare URL. Idempotent for values already containing a Markdown link; passes
    free-text through (linkifying any embedded bare CWEs)."""
    ref = (ref or "").strip()
    if not ref or "](" in ref:  # empty, or already a Markdown link
        return ref
    m = re.fullmatch(r"CWE-(\d+)", ref, re.IGNORECASE)
    if m:
        return _cwe_reference_link(m.group(1))
    if re.fullmatch(r"https?://\S+", ref):
        return f"[{_reference_link_title(ref)}]({ref})"
    return _linkify_bare_cwes(ref)


# ---------------------------------------------------------------------------
# Dollar-operator escape — wrap `$word` tokens (MongoDB operators like
# `$where`, `$ne`, `$regex`; jQuery selectors; bash-style variable references)
# in backticks so renderers with MathJax / KaTeX enabled (GitHub, VS Code's
# markdown preview, Obsidian, Quarto) do not treat the `$` as math-mode
# delimiters and choke on the `#` inside the next `](#t-NNN)` anchor.
# ---------------------------------------------------------------------------

# Pattern rationale:
#   (?<![`$\\])        — not already escaped or in a backtick context, not a
#                        double-`$$` pair (LaTeX math block), not a preceding
#                        backslash escape `\$`.
#   \$([A-Za-z_][A-Za-z0-9_]*)\b
#                      — `$` followed by an identifier (letter-start, word
#                        chars). Skips bare `$` alone, `$10` (USD amounts),
#                        and `$$` pairs.
_DOLLAR_OP_RE = re.compile(r"(?<![`$\\])\$([A-Za-z_][A-Za-z0-9_]*)\b")


_EMDASH_SPACED_RE = re.compile(r"(?<!\S)—(?!\S)")
_EMDASH_TIGHT_RE = re.compile(r"—")


def _normalize_emdashes(md: str) -> str:
    """Replace em dashes (U+2014) with ASCII hyphens outside fenced code blocks.

    Two cases:
      * `<sp>—<sp>` -> `<sp>-<sp>` (the common prose separator).
      * Any other em dash (tight, line start) -> `-` (same width, same shape).

    Inline backtick spans, HTML comments, and most fenced code blocks are
    preserved verbatim. The exception is ```mermaid blocks: em dashes are
    not syntactically significant in Mermaid, and node labels inside a
    diagram render to the user the same as prose text. Without
    normalising them too, a reader sees `Untrusted Zone — Internet`
    inside the rendered SVG even after the prose pass cleaned up
    everything else.
    """
    # Split into fenced-block chunks (``` … ``` / HTML comments only — NOT
    # inline backtick spans, because those are part of single lines and
    # splitting on them loses the heading / table-row context).
    out_chunks: list[str] = []
    for chunk in re.split(
        r"(```[^\n]*\n.*?\n```|<!--.*?-->)",
        md,
        flags=re.DOTALL,
    ):
        if chunk.startswith("```mermaid"):
            # Mermaid blocks: em dash is not syntactic; normalise node
            # labels inside so the rendered diagram stays consistent with
            # the prose. EXCEPTION: sequenceDiagram `alt`/`else` branch
            # labels follow the "Current state — T-NNN" / "After M-NNN — …"
            # convention (QA Check 8e) where the em-dash is the intended
            # visual separator. Blanket-normalising them to a hyphen makes
            # every §3 walkthrough diagram drift from its authored fragment,
            # so the QA reviewer re-flags it on every run. Preserve em-dashes
            # on those lines only.
            mermaid_lines = []
            for ln in chunk.split("\n"):
                if re.match(r"^\s*(?:alt|else)\s+\S", ln):
                    mermaid_lines.append(ln)
                else:
                    ln = _EMDASH_SPACED_RE.sub("-", ln)
                    ln = _EMDASH_TIGHT_RE.sub("-", ln)
                    mermaid_lines.append(ln)
            out_chunks.append("\n".join(mermaid_lines))
            continue
        if chunk.startswith("```") or chunk.startswith("<!--"):
            out_chunks.append(chunk)
            continue
        # Process line-by-line so heading / bullet / table-row context is
        # never lost. Within a single prose line, inline `…` code spans
        # are protected via _normalize_line_preserve_inline_code.
        lines = chunk.split("\n")
        processed_lines = []
        for line in lines:
            stripped = line.lstrip()
            if stripped.startswith("#"):
                # Heading line — preserve em dashes (contract checker requires them)
                processed_lines.append(line)
            elif (
                stripped.startswith("- **")
                or stripped.startswith("- <a id=")
                or stripped.startswith("- [F-")
                or stripped.startswith("- [T-")
                or stripped.startswith("- [M-")
            ) and " — " in line:
                # Actor/attack-path bullet or finding sub-bullet with em-dash — preserve
                processed_lines.append(line)
            elif stripped.startswith("|") and re.search(r"\]\(#[A-Za-z0-9_-]+\)\s+—\s", line):
                # GFM table row containing an anchor-link followed by ` — `
                # label separator. The em-dash here is STRUCTURAL (separates
                # `[F-NNN](#f-nnn)` from the visible label), not prose.
                # Normalising it to a regular hyphen would let downstream
                # label enrichers (qa_checks linkify_anchors Pass 2) match
                # the bare link again and double-label it. Preserve the row.
                processed_lines.append(line)
            elif re.search(r"\]\(#(?:f|t|m|th)-\d+\)\s+—\s", line):
                # Non-table line carrying a structural `[ID](#id) — Label`
                # separator: the §8/§9 register jump-lists
                # (`**Findings index:**<br/>🔴 [F-001](#f-001) — …`), the
                # emoji finding/mitigation bullets (`- 🔴 [F-001](#f-001) — …`)
                # and the §8 Fix lines (`→ [M-001](#m-001) — …`). Same rule as
                # the table-row case above — the em-dash is the link↔label
                # separator, NOT prose. Hyphenising it lets a downstream
                # re-label pass treat the link as bare and re-append the title,
                # producing the `[F-001](#f-001) — Title - Title` doubling seen
                # in the 2026-05-31 juice-shop run. Preserve the em-dash so the
                # idempotency guards (which all key on ` — `) stay effective.
                processed_lines.append(line)
            else:
                processed_lines.append(_normalize_line_preserve_inline_code(line))
        chunk = "\n".join(processed_lines)
        out_chunks.append(chunk)
    return "".join(out_chunks)


def _normalize_line_preserve_inline_code(line: str) -> str:
    """Normalise em dashes on a single line of prose, preserving inline
    backtick code spans. Inline spans `…` are passed through verbatim;
    everything else gets `—` → `-` substitution.
    """
    out_parts: list[str] = []
    for part in re.split(r"(`[^`\n]+`)", line):
        if part.startswith("`") and part.endswith("`"):
            out_parts.append(part)  # inline code span — preserve verbatim
            continue
        p = _EMDASH_SPACED_RE.sub("-", part)
        p = _EMDASH_TIGHT_RE.sub("-", p)
        out_parts.append(p)
    return "".join(out_parts)


# An `[ID](#anchor) <sep> Label <sep> Label <delim>` construct where the label
# is repeated verbatim. Produced when a re-label pass (qa_checks linkify_anchors,
# the renderer agent's own passes, apply_prose_fixes) appends a title to a link
# that already carried one — the 2026-05-31 juice-shop §8/§9/attack-path
# doubling. `_normalize_emdashes` preservation (above) closes the common vector,
# but this is the deterministic belt-and-suspenders net: it can NEVER ship a
# doubled label regardless of how upstream passes interleave. Conservative —
# only collapses an EXACT consecutive repeat of the whole label segment, so a
# label that legitimately contains a repeated word is untouched.
_DOUBLED_ID_LABEL_RE = re.compile(
    r"(\]\(#[A-Za-z0-9_-]+\)\s*[—-]\s*)"  # 1: ](#anchor) + first separator
    r"([^\n<|—]+?)"  # 2: label text (no newline / < / | / em-dash)
    r"(?:\s*[—-]\s*|\s+)"  # repeat separator: hyphen / em-dash / bare space
    r"\2"  # the SAME label again
    r"(?=\s*(?:<|\||→|$|\n))"  # followed by a cell/line delimiter
)


def _dedupe_doubled_id_labels(md: str) -> str:
    """Collapse `[ID](#id) — Label - Label` → `[ID](#id) — Label`. Idempotent."""
    return _DOUBLED_ID_LABEL_RE.sub(r"\1\2", md)


def _escape_dollar_operators(md: str) -> str:
    """Markdown-escape `$word` tokens so they survive KaTeX/MathJax-enabled
    renderers without picking up code formatting.

    Previously this wrapped each match in backticks (`` `$where` ``),
    which protects against math-mode interpretation but produces a
    visible monospace span in every renderer. Titles like
    "F-021 - NoSQL Injection via MarsDB $where" then read as "$where"
    in fixed-width font - a code style readers associate with literal
    source code, not the description of a database operator the
    surrounding prose is referring to.

    Switching to the canonical Markdown backslash-escape (`\\$where`)
    keeps the math-mode protection (KaTeX and MathJax both honor `\\$`
    as a literal dollar sign) while leaving the rendered text in the
    surrounding font weight. The trailing-context regex in
    ``_DOLLAR_OP_RE`` already excludes already-escaped (``\\$``),
    already-backticked (`` `$ ``) and `$$` math-block forms, so this
    pass is idempotent.

    Skips:
    - Fenced code blocks (``` ... ```)
    - Inline code spans (`...`)
    - HTML comments (<!-- ... -->)
    - Tokens already preceded by a backtick or backslash escape
    - Dollar amounts like $10 (no identifier following)
    - LaTeX-style $$...$$ blocks (lookbehind guard)
    """
    out_chunks: list[str] = []
    # Split on fenced code, inline code, and HTML comments so we only touch
    # prose/tables. Each alternative is captured so the surrounding chunks
    # survive the split.
    for chunk in re.split(
        r"(```[^\n]*\n.*?\n```|`[^`\n]+`|<!--.*?-->)",
        md,
        flags=re.DOTALL,
    ):
        if chunk.startswith("```") or chunk.startswith("`") or chunk.startswith("<!--"):
            out_chunks.append(chunk)
        else:
            out_chunks.append(_DOLLAR_OP_RE.sub(r"\\$\1", chunk))
    return "".join(out_chunks)


# Identifiers like `sanitizer.by` or `req.bo` are truncated forms of longer
# dotted names that collide with valid ccTLDs (.by = Belarus, .bo = Bolivia).
# GitHub Markdown and many other renderers auto-link these as bare URLs.
# Wrap them in backticks before the document is persisted.
#
# Lookbehind exclusions:
#   `        — already inside a backtick code span
#   [        — opening bracket of an existing markdown link
#   \w       — word character (would be part of a longer identifier)
#   /        — slash → token is part of a file path (e.g. routes/login.ts).
#              Without this, the path-fragment file extension `.ts`/`.js`
#              gets wrapped mid-path, producing `routes/`login.ts`:34`.
#
# TLD char class is case-insensitive ([A-Za-z]) post-2026-05 so capitalised
# brand spellings like `Socket.IO`, `Node.JS` also flow through the safety
# logic (whitelist → ZWSP, others → backtick). Lowercase-only was missing
# every CamelCase brand reference.
#   .        — leading/trailing dot → the token is one segment of a longer
#              dotted chain (`req.body.email`); wrapping just the 2-segment
#              head splits the identifier into `` `req.body`.email ``. Only a
#              STANDALONE `word.xx` (not mid-chain) is a ccTLD auto-link risk.
_DOT_IDENT_TLD_RE = re.compile(r"(?<![`\[\w/.])([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z]{2,4})\b(?![/\w.])")

# Source-file extensions that look like ccTLDs (.ts → Turkmenistan, .js → Jersey, etc.).
# When the TLD-shaped suffix matches one of these, the token is treated as a
# bare filename and left alone — GFM does not auto-link bare filenames the way
# it auto-links genuine TLD-shaped tokens.
_FILE_EXTENSION_SUFFIXES: frozenset[str] = frozenset(
    {
        # Code
        "ts",
        "tsx",
        "js",
        "jsx",
        "mjs",
        "cjs",
        "py",
        "rb",
        "go",
        "rs",
        "java",
        "kt",
        "kts",
        "scala",
        "cpp",
        "cc",
        "cxx",
        "hpp",
        "hxx",
        "hh",
        "cs",
        "fs",
        "vb",
        "swift",
        "m",
        "mm",
        "lua",
        "pl",
        "pm",
        "sh",
        "bash",
        "zsh",
        "fish",
        "php",
        "phtml",
        "dart",
        "ex",
        "exs",
        "erl",
        "hrl",
        "clj",
        "cljs",
        "edn",
        "ml",
        "mli",
        "r",
        "jl",
        "sql",
        # Config / data
        "yml",
        "yaml",
        "json",
        "toml",
        "ini",
        "cfg",
        "conf",
        "env",
        "xml",
        "csv",
        "tsv",
        "lock",
        # Markup / web
        "md",
        "rst",
        "txt",
        "rtf",
        "html",
        "htm",
        "css",
        "scss",
        "sass",
        "less",
        "svg",
        # Container / IaC
        "tf",
        "tfvars",
        # Notes: package.json, tsconfig.json, etc. already covered via
        # _DOT_TLD_KNOWN_NAMES but their general `.json` suffix is here too
        # for consistency. The known-name list takes precedence in the
        # whitelist branch; this set kicks in only as a generic fallback.
    }
)


# Identifiers that look like `word.xx` with xx a ccTLD but are well-known
# framework / language / tooling names. The auto-link wrap would put them
# in monospace -- e.g. "Node.js 20 - 24" rendering as "`Node.js` 20 - 24"
# -- which makes the System Overview Runtime row, prose sentences, and
# infobox cells read as code references rather than product names.
# Matched case-insensitively against the full `word.xx` token.
_DOT_TLD_KNOWN_NAMES: frozenset[str] = frozenset(
    {
        # JavaScript ecosystem
        "node.js",
        "vue.js",
        "next.js",
        "nest.js",
        "nuxt.js",
        "react.js",
        "express.js",
        "ember.js",
        "backbone.js",
        "angular.js",
        "meteor.js",
        "math.js",
        "moment.js",
        "lodash.js",
        "jquery.js",
        "three.js",
        "d3.js",
        "p5.js",
        "chart.js",
        "socket.io",
        # Backend frameworks
        "asp.net",
        "ruby.on",  # truncation guard
        # File-extension-style references that are common in prose
        "package.json",
        "tsconfig.json",
        "compose.yml",
        "docker.yml",
        ".npmrc",
        # Domain names that legitimately appear in prose
        "owasp.org",
        "github.io",
        "github.com",
        "mitre.org",
        "google.com",
    }
)


# ---------------------------------------------------------------------------
# _escape_html_payloads_in_prose — wrap unescaped attacker-payload HTML tags
# in inline backticks so the rendered HTML/PDF report does not interpret
# them as live `<script>` / `<img onerror=…>` / `<svg onload=…>` elements.
# Without this pass, prose like `q=<script>...</script>` ships RAW into the
# final document; pandoc / weasyprint then emit literal <script> elements
# that browsers execute. The threat report becomes its own XSS sink.
#
# Scope:
#   * Match every bare opening, closing, or self-closing form of the
#     dangerous-tag set below.
#   * Wrap each match in `` ` … ` `` so it renders as inline code.
#
# Forbidden zones (never rewritten):
#   * Fenced code blocks (``` ... ```)
#   * <details>...</details> blocks (Story Card collapsible code snippets)
#   * <pre>...</pre> and inline <code>...</code>
#   * Existing inline backtick spans (`...`) so the pass is idempotent
#   * HTML attribute values (`href="..."`, `id="..."`) — defensive: the only
#     tag in our document that uses these is the legitimate `<a id="t-NNN">`
#     anchor declaration, which is not in the dangerous-tag set anyway.
# ---------------------------------------------------------------------------
_DANGEROUS_HTML_TAG_RE = re.compile(
    # `code` included: Stage-1 prose occasionally writes a bare placeholder
    # like `#{<code>}` with no closing `</code>`. An unclosed inline `<code>`
    # element bleeds its formatting across the entire remainder of the
    # rendered document (the "everything is italic from §3.6 on" report).
    # Balanced `<code>…</code>` pairs are pulled into PROTECTED_RE below
    # first, so only the unbalanced/bare form reaches this substitution.
    r"</?(?:script|iframe|svg|object|embed|form|style|link|meta|code)\b[^>]*/?>"
    r"|<img\b[^>]*onerror\s*=[^>]*>"
    r"|<img\b[^>]*/?>"  # bare <img …> — payload context only since legit <img> never appears in our prose
    r"|<[A-Za-z][\w]*\s+(?:onerror|onload|onclick|onmouseover)\s*=[^>]*/?>",
    re.IGNORECASE,
)


def _escape_html_payloads_in_prose(md: str) -> str:
    """Wrap unescaped `<script>` / `<img onerror=…>` / similar payload tags
    in inline backticks so the rendered HTML/PDF report cannot execute them.

    Idempotent: tags already inside `` `…` ``, fenced code blocks,
    <details>/<pre>/<code> spans are skipped.
    """
    if not md:
        return md
    # Split into protected and unprotected chunks. Protected chunks are
    # passed through verbatim; unprotected chunks get the tag wrap.
    PROTECTED_RE = re.compile(
        r"(```[^\n]*\n.*?\n```"  # fenced code
        r"|<details\b.*?</details>"  # Story Card code blocks
        r"|<pre\b.*?</pre>"  # raw <pre>
        r"|<code\b.*?</code>"  # raw <code>
        r"|`[^`\n]+`)",  # inline code span
        flags=re.DOTALL,
    )
    out_chunks: list[str] = []
    for chunk in PROTECTED_RE.split(md):
        if not chunk:
            continue
        if (
            chunk.startswith("```")
            or chunk.startswith("<details")
            or chunk.startswith("<pre")
            or chunk.startswith("<code")
            or (chunk.startswith("`") and chunk.endswith("`"))
        ):
            out_chunks.append(chunk)
            continue
        out_chunks.append(_DANGEROUS_HTML_TAG_RE.sub(lambda m: f"`{m.group(0)}`", chunk))
    return "".join(out_chunks)


def _escape_dot_tld_identifiers(md: str) -> str:
    """Wrap word.xx patterns in backticks when xx is 2-4 chars (TLD-length)
    to prevent markdown renderers from auto-linking them as bare URLs.

    Skips fenced code blocks, existing inline code spans, HTML comments,
    and already-linked text so the substitution is idempotent.

    Three substitution branches (post-2026-05):
      1. Token in `_DOT_TLD_KNOWN_NAMES` (Socket.IO, Node.js, Vue.js, …)
         → insert a Zero-Width-Space between the word and the dot so the
         token still READS as prose (`Socket.IO`) but GFM cannot detect it
         as a URL. Previously these were left untouched, which made GitHub
         auto-link them as bare URLs.
      2. Token suffix in `_FILE_EXTENSION_SUFFIXES` (`.ts`, `.js`, `.py`, …)
         → leave alone. GFM does not auto-link bare file names like
         `login.ts`, and wrapping them in backticks splits source-path
         tokens (the historic `routes/`login.ts`:34` bug). The `/`
         lookbehind already prevents matching inside paths, but bare
         `login.ts` references in prose are also no-op.
      3. Everything else → backtick-wrap (the historic ccTLD-collision
         defense for tokens like `sanitizer.by`, `req.bo`, `myrandom.io`).
    """
    out_chunks: list[str] = []

    def _wrap_if_unknown(m: re.Match[str]) -> str:
        word, tld = m.group(1), m.group(2)
        full = f"{word}.{tld}"
        if full.lower() in _DOT_TLD_KNOWN_NAMES:
            # Known-safe brand / framework / product name (Node.js, Vue.js,
            # Socket.IO, …). These are PROSE, not code — they must NOT render
            # in backticks (the §1 System Overview Runtime row, infobox cells,
            # and narrative sentences should read "Node.js", not as a code
            # reference). Backslash-escape the dot instead: pandoc and GitHub
            # render `Node\.js` verbatim as "Node.js" while the backslash
            # breaks GFM's bare-URL auto-link heuristic. Retired approaches:
            # leaving it untouched (GFM auto-linked it as a URL) and ZWSP
            # (U+200B — fragile across PDF/HTML/RSS/IDE pipelines).
            return f"{word}\\.{tld}"
        if tld.lower() in _FILE_EXTENSION_SUFFIXES:
            # Bare file name (e.g. `login.ts`, `script.py`). GFM does not
            # auto-link these; backtick-wrap would corrupt path tokens
            # if any reached here. Leave alone.
            return full
        # ccTLD-shaped token of unknown identity (e.g. `req.bo`,
        # `sanitizer.by`, `myrandom.io`). Backtick-wrap to defeat
        # auto-link.
        return f"`{full}`"

    for chunk in re.split(
        r"(```[^\n]*\n.*?\n```|`[^`\n]+`|<!--.*?-->|\[[^\]]+\]\([^)]+\)|https?://[^\s<>()\]]+)",
        md,
        flags=re.DOTALL,
    ):
        if (
            chunk.startswith("```")
            or chunk.startswith("`")
            or chunk.startswith("<!--")
            or chunk.startswith("[")
            or chunk.startswith("http://")
            or chunk.startswith("https://")
        ):
            # Bare URLs (not just markdown-link syntax) are protected too —
            # a domain segment inside a plain `https://owasp-juice.shop` would
            # otherwise be treated as a standalone ccTLD-shaped token and
            # backtick-wrapped mid-URL, corrupting the link (juice-shop 2026-07-02).
            out_chunks.append(chunk)
        else:
            out_chunks.append(_DOT_IDENT_TLD_RE.sub(_wrap_if_unknown, chunk))
    return "".join(out_chunks)


def _linkify_bare_refs_in_prose(ctx: RenderContext, md: str) -> str:
    """Globally linkify every `[T-NNN](#t-nnn)` / `[M-NNN](#m-nnn)` /
    `[F-NNN](#f-nnn)` link that is NOT followed by ` — <label>`.

    Applies to prose fragments (§1, §2, §3, §4, §5, §7, §10). Skips:
      * Anchor declaration sites (`<a id="t-003">T-003` inside table cells).
      * The Verdict blockquote where bare refs are idiomatic
        (`*([F-009](#f-009))*` citation style).
      * Jinja template literals in computed sections (already handled).
    """
    # Build a cache of bare-ref → labelled-ref substitutions so we don't
    # re-lookup the same ID over and over. Keyed on (ref, table) because the
    # two contexts render the cross-reference differently (see resolve()).
    cache: dict[tuple[str, bool], str] = {}

    def resolve(ref: str, table: bool) -> str:
        # TABLE cells (§5 Attack-Surface Notes, etc.) use the CANONICAL em-dash
        # form `[F-NNN](#f-nnn) — Weakness (file:line)` so every finding link is
        # identical across §2 / §4 / §5 / §8 (user report 2026-06-12: §5 used a
        # parens short form `(Weakness)` while everywhere else used em-dash).
        # Genuine INLINE PROSE keeps the parens short form so a mid-sentence
        # citation reads `… [T-005](#t-005) (Reflected XSS) …` rather than a
        # double-em-dash torn-link construct.
        key = (ref, table)
        if key not in cache:
            cache[key] = ctx.linkify_with_label(ref) if table else ctx.linkify_with_short_label(ref)
        return cache[key]

    # Find every bare `[X-NNN](#x-nnn)` that is NOT followed by an existing
    # em-dash label OR an existing parens label — both are signs the link
    # has already been enriched and re-expanding would double-label.
    def make_sub(line_text: str, table: bool):
        def sub_ref(m: re.Match) -> str:
            ref = m.group(1)
            # Skip citation style `*([F-009](#f-009))*` — check surrounding chars
            # within THIS line (m.start() is line-relative).
            start = m.start()
            if line_text[max(0, start - 2) : start].endswith("*("):
                return m.group(0)
            return resolve(ref, table)

        return sub_ref

    # Skip fenced code blocks so refs inside ```javascript blocks stay literal.
    # Skip heading lines (leading `#` on a line) so labels are never injected
    # into `### 3.2 Foo ([T-001](#t-001))` — that breaks heading slug generation
    # and TOC anchor resolution. Headings stay short by design; a bare
    # `[T-001](#t-001)` in a heading is a citation, not a place for the label.
    out_chunks: list[str] = []
    for chunk in re.split(r"(```[^\n]*\n.*?\n```)", md, flags=re.DOTALL):
        if chunk.startswith("```"):
            out_chunks.append(chunk)
            continue
        # Process line-by-line so we can skip headings individually.
        lines = chunk.split("\n")
        in_assets_tbl = False
        for i, line in enumerate(lines):
            if re.match(r"^\s{0,3}#{1,6}\s", line):
                # Heading — do not expand refs.
                in_assets_tbl = False
                continue
            # §4 Assets guard — its Linked Threats cells ship COMPACT bare
            # `[F-NNN](#f-nnn)` chips on purpose (narrow ID column). Detect the
            # table header (Asset + Classification) and skip its body rows so
            # the `(title)` parens form is NOT appended here.
            _strip = line.lstrip()
            if _strip.startswith("|"):
                _cells = {c.strip().lower() for c in _strip.strip("|").split("|")}
                if "asset" in _cells and "classification" in _cells:
                    in_assets_tbl = True
                if in_assets_tbl:
                    continue
            else:
                in_assets_tbl = False
            lines[i] = re.sub(
                # Skip refs already followed by ` — <label>` (em-dash form,
                # produced by linkify_with_label in table cells / register
                # builders) AND refs already followed by ` (<label>)` (parens
                # form, produced by linkify_with_short_label in prose).
                r"\[([FTM]-\d{3,4})\]\(#[ftm]-\d+\)(?!\s+[—(])",
                make_sub(line, _strip.startswith("|")),
                line,
            )
        out_chunks.append("\n".join(lines))
    return "".join(out_chunks)


# A plain-text finding id (`F-012`) and a component-scoped analyst id
# (`auth-001`, `b2b-api-002`, `express-backend-016`) as they appear in
# LLM-authored prose. The component-scoped form requires a trailing `-NNN`.
_BARE_FNNN_RE = re.compile(r"(?<![\w/#-])(F-\d{2,4})(?![\w-])")
_BARE_LOCAL_ID_RE = re.compile(r"(?<![\w/#-])([a-z][a-z0-9]*(?:-[a-z0-9]+)*-\d{3})(?![\w-])")
# Opaque spans we must NOT rewrite inside: backtick code, full markdown links,
# link TEXT brackets, HTML tags/anchors.
_PROSE_MASK_RE = re.compile(r"`[^`]+`|\[[^\]]*\]\([^)]*\)|<[^>]+>")


def _linkify_bare_finding_refs(ctx: RenderContext, md: str) -> str:
    """Linkify finding references that LLM prose wrote as plain text:

      * a bare canonical id ``F-012`` → ``[F-012](#f-012)`` (the §3
        key-takeaway "F-012 is exploitable at …" lines), and
      * a bare component-scoped analyst id ``auth-001`` / ``chatbot-003`` /
        ``express-backend-016`` (the merge-time ``local_id`` of a finding) →
        the canonical ``[F-NNN](#f-nnn)`` it became, so "(see auth-001)" style
        cross-references resolve.

    No label is appended — these are mid-sentence citations; the severity-dot
    retrofit later prefixes the glyph. Skips code fences, headings, and any
    text already inside a backtick span / markdown link / HTML tag, so existing
    links and code are never touched. Runs once, globally, after the
    per-section label enrichment."""
    threats = (ctx.yaml_data or {}).get("threats") or []
    f_exists: set[str] = set()
    local_to_f: dict[str, str] = {}
    for t in threats:
        tid = (t.get("id") or t.get("t_id") or "").strip().upper()
        m = re.match(r"^[TF]-(\d+)$", tid)
        if not m:
            continue
        fid = f"F-{m.group(1)}"
        f_exists.add(fid)
        lv = (t.get("local_id") or "").strip().lower()
        if lv:
            local_to_f.setdefault(lv, fid)
        for cr in t.get("consolidated_refs") or []:
            if isinstance(cr, str) and cr.strip():
                local_to_f.setdefault(cr.strip().lower(), fid)
    if not f_exists:
        return md

    def _link(fid: str) -> str:
        return f"[{fid}](#{fid.lower()})"

    def _rewrite_run(run: str) -> str:
        run = _BARE_FNNN_RE.sub(lambda m: _link(m.group(1)) if m.group(1) in f_exists else m.group(0), run)
        run = _BARE_LOCAL_ID_RE.sub(
            lambda m: _link(local_to_f[m.group(1).lower()]) if m.group(1).lower() in local_to_f else m.group(0),
            run,
        )
        return run

    def _process_line(line: str) -> str:
        out: list[str] = []
        pos = 0
        for mm in _PROSE_MASK_RE.finditer(line):
            if mm.start() > pos:
                out.append(_rewrite_run(line[pos : mm.start()]))
            out.append(mm.group(0))  # opaque span — passthrough
            pos = mm.end()
        if pos < len(line):
            out.append(_rewrite_run(line[pos:]))
        return "".join(out)

    out_chunks: list[str] = []
    for chunk in re.split(r"(```[^\n]*\n.*?\n```)", md, flags=re.DOTALL):
        if chunk.startswith("```"):
            out_chunks.append(chunk)
            continue
        lines = chunk.split("\n")
        for i, line in enumerate(lines):
            if re.match(r"^\s{0,3}#{1,6}\s", line) or '<a id="' in line:
                continue  # headings + anchor-declaration rows untouched
            lines[i] = _process_line(line)
        out_chunks.append("\n".join(lines))
    return "".join(out_chunks)


def _fold_code_strings_in_prose(md: str) -> str:
    """Fold a whole code-signal quoted string literal (a SQL query, a
    concatenated expression) into ONE backtick span, across all prose.

    Runs BEFORE ``_escape_dot_tld_identifiers`` so that pass — which would
    otherwise mistake a column ref like ``u.id`` for the Indonesia ``.id``
    ccTLD and backtick it mid-string — sees the literal as an already-masked
    span and leaves its interior alone. Without this, the stray inner backtick
    then defeats the whole-literal fold and the per-token matchers half-backtick
    the query (``on `o.owner_id` = `u.id` where `u.email` = …``). Skips fenced
    blocks and heading lines; idempotent."""
    if not md:
        return md
    out_chunks: list[str] = []
    for chunk in re.split(r"(```[^\n]*\n.*?\n```)", md, flags=re.DOTALL):
        if chunk.startswith("```"):
            out_chunks.append(chunk)
            continue
        lines = chunk.split("\n")
        for i, line in enumerate(lines):
            if re.match(r"^\s{0,3}#{1,6}\s", line):
                continue  # heading
            lines[i] = _wrap_code_string_literals(line)
        out_chunks.append("\n".join(lines))
    return "".join(out_chunks)


def _codify_inline_code_in_prose(md: str) -> str:
    """Backtick un-marked inline code (member access, calls, dotted refs, file
    paths, UPPER_SNAKE env/secret names) across ALL prose — the §3 walkthrough
    steps and §8/§10 Issue/Evidence/Fix/How cards are LLM-authored and backtick
    code only inconsistently (juice-shop 2026-06-29 screenshots). Reuses the
    span-masking ``_codify_inline_identifiers`` so existing backtick spans,
    markdown links, and HTML tags are never touched; only adds the missing
    monospacing. Skips fenced code blocks and heading lines. Idempotent."""
    if not md:
        return md
    out_chunks: list[str] = []
    for chunk in re.split(r"(```[^\n]*\n.*?\n```)", md, flags=re.DOTALL):
        if chunk.startswith("```"):
            out_chunks.append(chunk)
            continue
        lines = chunk.split("\n")
        for i, line in enumerate(lines):
            if re.match(r"^\s{0,3}#{1,6}\s", line):
                continue  # heading
            lines[i] = _codify_inline_identifiers(line)
        out_chunks.append("\n".join(lines))
    return "".join(out_chunks)


_FINDING_DOT_REF_RE = re.compile(
    # The `dot` group tolerates a `&nbsp;` / bullet separator between the glyph
    # and the link (table cells emit `🔴&nbsp;[F-004]`, attack-path bullets emit
    # `•&nbsp;🔴&nbsp;[F-004]`) so the global retrofit pass recognises an
    # already-dotted ref and never double-prefixes it.
    #
    # Matches the `[F-NNN](#f-nnn)` link form only. T-NNN links are intentionally
    # NOT matched: the changelog and a few cross-refs cite `[T-NNN](#t-nnn)`
    # without a dot by design, and main()'s T→F display rewrite converts the
    # walkthrough `**Source:**` refs to F afterwards anyway. §3 walkthrough Source
    # lines instead carry their dot from walkthrough_renderer.py (emitted before
    # the T→F rewrite, preserved through it).
    r"(?P<dot>[🔴🟠🟡🟢⚪](?:\s|&nbsp;|•)*)?(?P<link>\[F-(?P<num>\d+)\]\(#f-\d+\))"
)


def _normalize_visible_threat_ids(md: str) -> str:
    """Rewrite every VISIBLE uppercase ``T-NNN`` threat id to its ``F-NNN``
    form across the whole document — link text, alt/else labels inside a
    ```mermaid fence, and bare prose alike.

    The visible threat id everywhere is ``F-NNN`` (the §8 Findings Register
    headings, the Critical Attack Tree, every cross-reference); ``T-NNN`` is the
    internal merge-stage id with no visible heading, so a stray ``T-NNN`` is an
    id the reader cannot resolve (user report 2026-06: the attack tree and the
    §3 walkthroughs showed ``T-NNN`` while everything below them used ``F-NNN``).
    Most refs are already ``F-NNN`` by the time they reach here (per-renderer
    normalisation + `_normalize_tid_to_fid` / `_to_fid`); this is the global
    backstop that also catches LLM-authored prose drift (e.g. a §7 paragraph
    that hand-wrote ``[T-003](#f-003)/T-004``).

    Two passes:
      1. Link form ``[T-NNN](#t-nnn)`` → ``[F-NNN](#f-nnn)`` — rewrites BOTH
         the visible text and the anchor together (the §8 register emits a dual
         ``<a id="t-nnn"></a><a id="f-nnn"></a>`` anchor, so ``#f-nnn``
         resolves). This is what the changelog / any markdown-link ref uses.
      2. Any remaining bare or prefixed visible ``T-NNN`` (prose, alt/else
         labels inside a ```mermaid fence, ``[§8 T-NNN]`` link text) → ``F-NNN``.

    Safe by construction:
      • Pass 2 matches only UPPERCASE ``T-NNN``; lowercase anchors/slugs
        (``#t-001``, ``id="t-001"``) are preserved, so the dual-anchor link
        targets still resolve.
      • ``AC-T-NNN`` abuse-case ids are excluded (pass-1 text starts ``[AC``,
        not ``[T``; pass-2 negative lookbehind rejects the ``-T`` after ``AC``).
      • Mermaid node identifiers like ``L_T003`` carry no hyphen and never
        match ``T-\\d``. ``TH-NN`` / ``CWE-NNN`` likewise do not match.
    """
    if not md:
        return md
    # Pass 1 — link form. Matches both [T-NNN](#t-nnn) (text+anchor T) AND
    # [F-NNN](#t-nnn) (text already F but anchor still the merge-stage #t-nnn,
    # emitted by the per-component "Linked Threats" cells). Both → [F-NNN](#f-nnn)
    # so the anchor is the canonical #f-nnn AND the downstream severity-dot pass
    # (which only matches `(#f-nnn)`) annotates them — without this, the C-03/C-04
    # component rows shipped finding links with NO criticality dot (user 2026-06).
    md = re.sub(r"\[[FT]-(\d+)\]\(#t-(\d+)\)", r"[F-\1](#f-\2)", md)
    md = re.sub(r"(?<![A-Za-z-])T-(\d{3,})\b", r"F-\1", md)
    return md


def _apply_outside_changelog(md: str, fn) -> str:
    """Apply ``fn`` to the document EXCEPT the ``## Changelog`` section.

    The Changelog is an append-only historical delta log (added/changed/
    resolved threats per run), not a severity-ranked findings list — so the
    severity-dot / priority-circle retrofit must not annotate its F-/M-refs
    (the annotation would be inconsistent: only threats still present in
    ``threats[]`` resolve a severity, so resolved-threat refs would stay bare
    while changed ones get a dot). Its ids are still normalised to F-NNN by
    `_normalize_visible_threat_ids`; only the glyph passes skip it.
    """
    if not md:
        return md
    m = re.search(r"(?m)^## Changelog\b", md)
    if not m:
        return fn(md)
    start = m.start()
    nxt = re.search(r"(?m)^## ", md[m.end() :])
    end = (m.end() + nxt.start()) if nxt else len(md)
    return fn(md[:start]) + md[start:end] + fn(md[end:])


def _prepend_finding_severity_dots(ctx: RenderContext, md: str) -> str:
    """Prefix every finding cross-reference ``[F-NNN](#f-nnn)`` with its
    severity glyph so §5 Attack Surface and §7 Security Architecture carry the
    same criticality dot the reader already sees in §8, the asset / component
    tables, and the Top Mitigations Addresses column.

    Idempotent — a ref already preceded by a severity emoji is left untouched.
    Skips fenced code blocks and inline code spans; heading lines never carry a
    `[F-NNN](#f-nnn)` link so they need no special guard.
    """
    if not md:
        return md

    def _sub(m: re.Match[str]) -> str:
        if m.group("dot"):
            return m.group(0)  # already dotted
        emoji = ctx.severity_emoji(ctx.severity_for_ref(f"F-{m.group('num')}"))
        return f"{emoji} {m.group('link')}" if emoji else m.group("link")

    out_chunks: list[str] = []
    for chunk in re.split(r"(```[^\n]*\n.*?\n```|`[^`\n]+`)", md, flags=re.DOTALL):
        if chunk.startswith("```") or (chunk.startswith("`") and chunk.endswith("`")):
            out_chunks.append(chunk)
        else:
            out_chunks.append(_FINDING_DOT_REF_RE.sub(_sub, chunk))
    return "".join(out_chunks)


_MITIGATION_CIRCLE_REF_RE = re.compile(
    # Same `&nbsp;` / bullet tolerance as _FINDING_DOT_REF_RE so an existing
    # `●&nbsp;[M-001]` / `→ ● [M-002]` prefix can be retained or normalized
    # without changing its separator. The class keeps the superseded ❶❷❸❹ digits
    # so a stale glyph from an older render is stripped and re-mapped to the ramp.
    r"(?P<circ>[●◕◑○❶❷❸❹❺❻❼❽❾](?:\s|&nbsp;|•)*)?(?P<link>\[M-(?P<num>\d+)\]\(#m-\d+\))"
)


def _prepend_mitigation_prio_circles(ctx: RenderContext, md: str) -> str:
    """Prefix every mitigation cross-reference ``[M-NNN](#m-nnn)`` with its
    rollout-priority circle (● for P1 … ○ for P4) — the colourless parallel to
    the finding severity dot. Brings §3 Attack Walkthroughs and §9 Abuse Cases
    in line with §1/§2/§8/§10, where the computed renderers already emit the
    circle inline via ``linkify_with_label`` / ``_measure_prio_prefix``.

    Idempotent — a ref already preceded by the correct circle is unchanged.
    A stale or incorrectly authored circle is replaced with the priority derived
    from the structured model. Skips fenced code blocks and inline code spans
    (same masking as the finding-dot pass).
    """
    if not md:
        return md

    def _sub(m: re.Match[str]) -> str:
        digit = _PRIO_RAMP_TBL.get(ctx.priority_for_ref(f"M-{m.group('num')}"), "")
        if not digit:
            return m.group(0)
        circ = m.group("circ") or ""
        if circ:
            # Preserve the original separator (` ` / `&nbsp;` / `•`) while
            # replacing a stale priority digit. `circ[0]` is one Unicode glyph.
            return f"{digit}{circ[1:]}{m.group('link')}"
        return f"{digit} {m.group('link')}"

    out_chunks: list[str] = []
    for chunk in re.split(r"(```[^\n]*\n.*?\n```|`[^`\n]+`)", md, flags=re.DOTALL):
        if chunk.startswith("```") or (chunk.startswith("`") and chunk.endswith("`")):
            out_chunks.append(chunk)
        else:
            out_chunks.append(_MITIGATION_CIRCLE_REF_RE.sub(_sub, chunk))
    return "".join(out_chunks)


# Patterns that look like secrets and must be masked before emitting markdown.
# Kept intentionally simple — the goal is to flag the obvious leaks, not to
# replicate a full DLP engine.
_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # RSA private key blob — full BEGIN...END block, across multiple lines.
    (
        r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----\n<REDACTED — key bytes masked>\n-----END RSA PRIVATE KEY-----",
        "rsa_privkey",
    ),
    # OpenSSH / generic PRIVATE KEY blocks.
    (
        r"-----BEGIN (OPENSSH|EC|DSA|PRIVATE) KEY-----[\s\S]+?-----END \1 KEY-----",
        "-----BEGIN \\1 KEY-----\n<REDACTED — key bytes masked>\n-----END \\1 KEY-----",
        "private_key",
    ),
    # AWS Access Key.
    (r"\bAKIA[0-9A-Z]{16}\b", "AKIA<REDACTED>", "aws_key"),
    # Google API key.
    (r"\bAIza[0-9A-Za-z_-]{35}\b", "AIza<REDACTED>", "google_api_key"),
    # Alchemy-style provider key (hex/base58 32+ chars after a known prefix).
    (r"wss://[^/]+/v2/[A-Za-z0-9_-]{20,}", "wss://<provider>/v2/<REDACTED>", "provider_wss_key"),
    # Bare API-token-style constants: a secret-like identifier on the left
    # AND a long base64url-ish value (≥24 chars) on the right. Defense-in-depth
    # fallback for tokens that escape the recon-scanner's Cat-12 redaction (e.g.
    # when an agent quotes a code snippet that still contains the literal value).
    (
        r"(?i)((?:api[_-]?key|apikey|secret|token|auth[_-]?token|access[_-]?key|client[_-]?secret)\s*[:=]\s*['\"])([A-Za-z0-9_+/=-]{24,})(['\"])",
        r"\1<REDACTED — token>\3",
        "generic_bare_token",
    ),
    # GitHub token.
    (r"\bghp_[A-Za-z0-9]{36,}\b", "ghp_<REDACTED>", "github_token"),
    # Long hex string (>= 48 chars) — potential bearer token / hmac secret.
    (r"\b[a-fA-F0-9]{48,}\b", "<REDACTED — long hex>", "long_hex"),
    # Lone / truncated PEM PRIVATE KEY marker — a BEGIN header without a
    # matching END (e.g. a code snippet that was cut mid-key by the §8
    # max-snippet length, or a prose excerpt like
    # `const privateKey = '-----BEGIN RSA PRIVATE KEY-----...'`). The
    # full-block patterns above only fire on a complete BEGIN...END pair, so
    # these slip through and trip the qa_checks `pem_private_key` gate (which
    # flags the bare BEGIN marker unconditionally). Consume the marker plus
    # any same-physical-line trailing key bytes (literal escaped \r/\n or
    # base64), stopping at the first real newline so the rest of a code block
    # is never swallowed. Runs last so masked full blocks above lose only
    # their (gate-flagged) BEGIN marker, not their key bytes.
    (
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----(?:\\[rn]|[A-Za-z0-9+/=])*",
        "[PEM PRIVATE KEY — REDACTED]",
        "pem_lone_marker",
    ),
]


_QUICK_MODE_NOTICE_QUICK = (
    "> ⓘ **Section narrative not rendered** — this section contains unfilled "
    "placeholders. At `--assessment-depth quick` this is by design. Re-run with "
    "`--standard` or `--thorough` to fill the per-domain narrative."
)

_QUICK_MODE_NOTICE_STANDARD = (
    "> ⚠ **Section narrative incomplete** — this section contains unfilled "
    "placeholders at standard/thorough depth, which means the Stage-2 fill "
    "step did not author them. Common causes: turn budget exhausted before "
    "§7 fill, or scaffold-fill instructions not loaded by the renderer agent. "
    "Check `.agent-run.log` for `BUDGET_CRITICAL` / `WRAP_UP_TRIGGERED` "
    "around the §7 substep, and `agents/phases/phase-group-finalization.md` "
    "→ scaffold-fill protocol."
)


# F3.1 — Mermaid edge-label safety. Auto-quote labels that contain characters
# mermaid's parser interprets specially (colon as style marker, `--` as edge
# delimiter, single/double quotes as string terminators). Without quoting,
# `A -->|reads lib/insecurity.ts:23| B` is fragile across mermaid versions —
# `:` flips parsing state in older releases and `'--` in Chain-2-style labels
# is the canonical break case.
#
# Idempotent: already-quoted labels (`|"…"|`) are left alone. Only edge labels
# in flowchart/graph blocks are touched; sequenceDiagram messages use a
# different syntax and are not affected.
_MERMAID_BLOCK_RE = re.compile(
    r"```mermaid\n(.*?)\n```",
    re.DOTALL,
)
_UNSAFE_EDGE_LABEL_RE = re.compile(
    # Match `|...|` where the content is NOT already wrapped in `"..."`.
    # The label payload (group 1) is what we test for unsafe chars. We
    # require non-empty content and forbid newlines inside the label.
    r"\|([^|\n\"][^|\n]*?)\|"
)
_UNSAFE_LABEL_CHARS_RE = re.compile(r"[:'\"\(\)]|--")


def _quote_mermaid_edge_labels(md: str) -> tuple[str, int]:
    """Auto-quote unsafe edge labels in mermaid flowchart/graph blocks.

    Returns the patched markdown and the number of labels rewritten. Quoted
    form is `|"original label"|` which renders identically across mermaid
    versions while neutralising tokenisation pitfalls.
    """
    rewrites = 0

    def _quote_inside_block(match: re.Match[str]) -> str:
        nonlocal rewrites
        block_body = match.group(1)
        header = block_body.split("\n", 1)[0].strip().lower()
        # Only flowchart/graph blocks have `|label|` edge-label syntax;
        # sequenceDiagram, classDiagram, gantt, etc. use different syntax
        # and may legitimately contain colons or quotes.
        if not (header.startswith("flowchart") or header.startswith("graph")):
            return match.group(0)

        def _rewrite(label_match: re.Match[str]) -> str:
            nonlocal rewrites
            payload = label_match.group(1)
            if not _UNSAFE_LABEL_CHARS_RE.search(payload):
                return label_match.group(0)
            # Strip leading/trailing spaces — wrap with quotes — restore.
            inner = payload.strip()
            # Escape any embedded `"` so the quoted form stays valid.
            inner = inner.replace('"', '\\"')
            rewrites += 1
            return f'|"{inner}"|'

        new_body = _UNSAFE_EDGE_LABEL_RE.sub(_rewrite, block_body)
        return "```mermaid\n" + new_body + "\n```"

    out = _MERMAID_BLOCK_RE.sub(_quote_inside_block, md)
    return out, rewrites


def _annotate_quick_mode_gaps(md: str, depth: str = "quick") -> str:
    """Inject a notice into any top-level section that still contains unfilled
    `<!-- NARRATIVE_PLACEHOLDER -->` HTML comments.

    Splits on `^## ` boundaries; for each chunk that carries placeholder
    comments, inserts the notice on a blank line right after the heading.
    Idempotent — chunks that already start with the notice are left alone.
    Section-level only; sub-section gaps roll up to their parent §N notice.
    """
    # Depth-aware banner selection. At quick depth, unfilled placeholders
    # are by design (LLM enrichment off for §7.4-§7.12). At standard /
    # thorough, the LLM scaffold-fill step is supposed to author them —
    # surviving placeholders signal an enrichment failure, not a config
    # choice. The banner text + emoji differ to make this distinction
    # visible to the reader.
    notice = _QUICK_MODE_NOTICE_QUICK if depth == "quick" else _QUICK_MODE_NOTICE_STANDARD
    lines = md.splitlines(keepends=False)
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # Top-level heading? "## " or "## N." (skip "### …" sub-sections).
        if line.startswith("## ") and not line.startswith("### "):
            # Collect this section's body up to (but not including) the next
            # top-level heading or end-of-doc.
            j = i + 1
            while j < len(lines) and not (lines[j].startswith("## ") and not lines[j].startswith("### ")):
                j += 1
            section_body = "\n".join(lines[i + 1 : j])
            has_gap = "<!-- NARRATIVE_PLACEHOLDER" in section_body
            already_noted = "Section narrative" in section_body[:400]
            out.append(line)
            if has_gap and not already_noted:
                # Insert one blank line + the notice + one blank line so the
                # callout stays visually separate from the heading and the
                # following body content.
                out.append("")
                out.append(notice)
            i += 1
        else:
            out.append(line)
            i += 1
    return "\n".join(out)


def _mask_secrets(md: str) -> tuple[str, list[str]]:
    """Redact credential-shaped strings from the rendered markdown.

    Returns (masked_md, list_of_mask_types_applied). Callers can log the
    mask list so reviewers know which redactions ran — even if no secret
    leaked into the document, the fact that the masking ran is visible.
    """
    applied: list[str] = []
    # Don't touch fenced code blocks — they are intentional "how to" examples
    # (e.g. `const privateKey = '-----BEGIN RSA PRIVATE KEY-----\\r\\nMII...'`).
    # In those blocks, the secret IS the example — but we still mask real key
    # BYTES if the block contains > 5 lines of base64. Err on the side of
    # caution: mask everywhere, let reviewers unmask intentionally by keeping
    # only `...` placeholders.
    for pat, repl, name in _SECRET_PATTERNS:
        regex = re.compile(pat, flags=re.MULTILINE)
        if regex.search(md):
            md = regex.sub(repl, md)
            applied.append(name)
    # Canonical pass — mask anything the unmasked_secrets gate (secret_scan.py)
    # would flag that the composer's own _SECRET_PATTERNS list does not cover.
    # The composer renders §8 evidence by reading the REAL source file, so
    # committed literals like `password: 'admin123'` (data/static/users.yml) end
    # up verbatim in the markdown; the gate caught them on the 2026-06-03 run.
    # Sharing secret_scan's pattern set guarantees detector⇔masker symmetry so
    # the gate can never trip on the rendered document again.
    try:
        import secret_scan  # sibling script; lazy import keeps module load cheap

        md, extra = secret_scan.mask_text(md)
        applied.extend(extra)
    except Exception:
        # Best-effort: a missing/broken sibling must never abort composition.
        pass
    return md, applied


def _render_appendix_run_statistics(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """Render Appendix: Run Statistics in the reference-canonical shape.

    Layout (matches the 2026-04-17 reference, §Appendix — Run Statistics):

        ## Appendix: Run Statistics

        | Field | Value |
        |-------|-------|
        | Invocation           | `<INVOCATION_ARGS>` |
        | Generated            | <ISO8601> |
        | Mode                 | <full/incremental/rebuild> |
        | Assessment depth     | <quick/standard/thorough> |
        | Plugin version       | <semver> (analysis v<N>) |
        | Orchestrator model   | <model-id> |
        | Repository           | <path> |
        | Output               | <path> |
        | Total duration       | <Xm YYs> |

        ### Per-Phase Duration Breakdown
        | Phase | Description | Agent (Model) | Duration |

        ### Coverage Summary
        | Metric | Value |

        ### Agent Dispatch Log
        | Agent | Model | Role | Phases |

        ### Tokens & Cost        (conditional — only when captured)
        bullets + scope warning blockquote
    """
    meta = ctx.yaml_data.get("meta") or {}
    stats = meta.get("run_statistics") or {}
    agents_yaml = stats.get("agents") or []
    tokens = stats.get("tokens") or {}
    cost = stats.get("cost") or {}

    invocation = meta.get("invocation") or "(not recorded)"
    # Generated timestamp - keep the canonical ISO8601 value in the YAML
    # but render a human-readable form ("2026-05-17 05:31 UTC") in the
    # appendix. Falls back to the raw value if the YAML didn't store an
    # ISO8601 string.
    generated_raw = meta.get("generated") or ""
    generated = _format_generated_timestamp(generated_raw) if generated_raw else "—"
    mode = meta.get("mode") or "—"
    depth = meta.get("assessment_depth") or "standard"
    # G3 — the threat-analyst agent occasionally writes a stale
    # plugin_version / analysis_version pair into meta:. Always prefer
    # the live values from plugin.json so the Run Statistics row reflects
    # the plugin that actually rendered this report.
    analysis_v = meta.get("analysis_version")
    plugin_v = meta.get("plugin_version")
    try:
        live_plugin_v, live_analysis_v = _read_live_plugin_meta()
        if live_plugin_v:
            plugin_v = live_plugin_v
        if live_analysis_v is not None:
            analysis_v = live_analysis_v
    except Exception:
        # Best-effort enrichment; fall through to whatever was in meta.
        pass
    orch_model = meta.get("model") or next(
        (a.get("model") for a in agents_yaml if (a.get("role") or "").lower().startswith("orchestrator")), "—"
    )
    # M3.3 — fall back to .skill-config.json when meta lacks repo/output paths.
    # The orchestrator does not currently emit `meta.repository_root` /
    # `meta.output_dir`; the skill-layer config has them. Without this
    # fallback the appendix shows "—" for paths that the user actually knows.
    skill_cfg = _read_skill_config(ctx.output_dir)
    repo = meta.get("repository_root") or skill_cfg.get("repo_root") or "—"
    out_dir = meta.get("output_dir") or skill_cfg.get("output_dir") or "—"
    # M3.3 — derive total duration from per-stage stats when meta lacks it.
    stage_rows = _read_stage_stats(ctx.output_dir)

    # Two DISTINCT quantities — never conflate them into one "duration":
    #   * wall clock    = real elapsed the user waited (net of machine standby)
    #   * agent compute = Σ per-stage duration_ms, which folds PARALLEL Stage-1
    #     dispatches serially and therefore OVERSTATES wall (juice-shop: ~98m
    #     compute vs ~83m wall). Labelling that sum "Total analysis duration"
    #     made the duration estimator look broken when it was actually correct.
    compute_secs: int | None = None
    if stage_rows:
        ms_sum = sum(r.get("duration_ms", 0) for r in stage_rows)
        if ms_sum:
            compute_secs = ms_sum // 1000
    # Authoritative wall comes from run_timing (single source of truth, shared
    # with the completion summary): net_wall = wall − standby, now clamped ≤ wall.
    wall_secs: int | None = None
    try:
        from run_timing import compute_timing  # sibling helper

        _t = compute_timing(ctx.output_dir)
        wall_secs = _t.get("net_wall_secs") or None
        if not compute_secs:
            compute_secs = _t.get("net_compute_secs") or None
    except Exception:
        pass
    # Fallback wall: the analyst's measured ELAPSED (Phase 1–11 wall).
    if not wall_secs:
        wall_secs = meta.get("analysis_duration_seconds") or None

    def _dur(s: int | None) -> str:
        return f"{int(s) // 60}m {int(s) % 60:02d}s" if s else "—"

    lines: list[str] = ["## Appendix: Run Statistics", ""]

    # --- Header field table -------------------------------------------------
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    # Exact invocation: meta first (survives runtime cleanup), skill-config
    # fallback (older runs / when meta lacks it). Shows the precise flags
    # (depth, reasoning tier, per-stage overrides, --stride-cap, …).
    invocation_cell = (
        invocation if invocation != "(not recorded)" else (skill_cfg.get("invocation_args") or "(not recorded)")
    )
    inv_prefix = (
        "/appsec-advisor:create-threat-model "
        if (invocation_cell != "(not recorded)" and not invocation_cell.startswith("/"))
        else ""
    )
    lines.append(f"| Invocation | `{inv_prefix}{invocation_cell}` |")
    lines.append(f"| Generated | {generated} |")
    lines.append(f"| Mode | {mode} |")
    lines.append(f"| Assessment depth | {depth} |")
    # Opt-in --stride-cap N transparency: disclose the per-category STRIDE cap so
    # a capped report is never mistaken for a full-depth one. Omitted when absent.
    stride_cap = meta.get("stride_per_category_cap")
    if stride_cap:
        lines.append(
            f"| STRIDE per-category cap | {stride_cap} threat(s) per category "
            f"per component (Critical-safe; `--stride-cap`) |"
        )
    plugin_cell = f"{plugin_v}" + (f" (analysis v{analysis_v})" if analysis_v else "")
    lines.append(f"| Plugin version | {plugin_cell or '—'} |")
    lines.append(f"| Orchestrator model | {orch_model} |")
    # Per-stage reasoning models. Surfaces per-stage overrides (e.g.
    # APPSEC_TRIAGE_MODEL=opus while STRIDE stays sonnet) that the tier name
    # alone hides, so a mixed-tier run is honestly disclosed. meta first,
    # skill-config fallback (meta omits these on older runs).
    _stride_m = meta.get("stride_model") or skill_cfg.get("stride_model")
    _triage_m = meta.get("triage_model") or skill_cfg.get("triage_model")
    _merger_m = meta.get("merger_model") or skill_cfg.get("merger_model")
    if _stride_m or _triage_m or _merger_m:
        _tier = meta.get("reasoning_model") or skill_cfg.get("reasoning_model")
        _tier_prefix = f"{_tier} — " if _tier else ""
        lines.append(
            f"| Reasoning models | {_tier_prefix}STRIDE {_stride_m or '—'}, "
            f"triage {_triage_m or '—'}, merger {_merger_m or '—'} |"
        )
    lines.append(f"| Repository | {repo} |")
    lines.append(f"| Output directory | {out_dir} |")
    # Show wall and compute separately. When only one is known, emit just that
    # one; when both equal (degenerate single-dispatch runs) the rows still read
    # correctly. Never present the inflated compute sum as elapsed duration.
    if wall_secs:
        lines.append(f"| Wall clock (active) | {_dur(wall_secs)} |")
    if compute_secs:
        lines.append(f"| Agent compute (Σ parallel dispatches) | {_dur(compute_secs)} |")
    if not wall_secs and not compute_secs:
        lines.append("| Total analysis duration | — |")
    lines.append("")

    # --- Per-Stage Breakdown (M3.3) ----------------------------------------
    # Reads `.stage-stats.jsonl` written by `record_stage_stats.py`. The
    # skill calls the helper after each Stage Agent dispatch returns, with
    # values extracted from the Agent tool's <usage> block. When the file
    # is absent (older runs, dry-run, partial failure), the section is
    # omitted entirely — no empty skeleton.
    if stage_rows:
        lines.append("### Per-Stage Breakdown")
        lines.append("")
        lines.append("| Stage | Description | Agent | Model | Duration | Tool calls | Tokens |")
        lines.append("|-------|-------------|-------|-------|----------|------------|--------|")
        total_ms = 0
        total_tools = 0
        total_tokens = 0
        for r in sorted(stage_rows, key=lambda d: d.get("stage", 0)):
            ms = r.get("duration_ms", 0)
            tools = r.get("tool_uses", 0)
            toks = r.get("tokens", 0)
            total_ms += ms
            total_tools += tools
            total_tokens += toks
            dur = _fmt_ms(ms)
            agent = (r.get("agent") or "—").split(":")[-1]  # strip namespace prefix
            lines.append(
                f"| {r.get('stage', '—')} | {r.get('name', '—')} | {agent} | "
                f"{r.get('model', '—')} | {dur} | {tools:,} | {toks:,} |"
            )
        lines.append(
            f"| **Total** | — | — | — | **{_fmt_ms(total_ms)}** | **{total_tools:,}** | **{total_tokens:,}** |"
        )
        lines.append("")

    # --- Per-Phase Duration Breakdown --------------------------------------
    lines.append("### Per-Phase Duration Breakdown")
    lines.append("")
    phase_rows = _scrape_phase_durations(ctx.output_dir)
    if phase_rows:
        lines.append("| Phase | Description | Agent (Model) | Duration |")
        lines.append("|-------|-------------|---------------|----------|")
        for r in phase_rows:
            lines.append(f"| {r['phase']} | {r['description']} | {r['agent']} | {r['duration']} |")
    else:
        lines.append("_No per-phase timing captured — `.agent-run.log` missing or unparseable._")
    lines.append("")

    # Coverage Summary intentionally removed. The same counters (threats by
    # severity, components, mitigations, security controls) already appear
    # in the Run Statistics header block, the §8 Findings Register risk-
    # distribution line, and the Verdict opening sentence. A third table
    # restating them in the appendix added length without information.

    # --- Agent Dispatch Log ------------------------------------------------
    # Suppress the section entirely when no row carries informative
    # Role or Phases content. The Per-Stage Breakdown above already lists
    # the agents that ran with their durations and tool counts, so a
    # second table that only repeats the agent names + models adds no
    # signal. Emit the table only when at least one row has Role or
    # Phases populated (i.e. the .agent-run.log scrape or the yaml
    # agents[] block produced something beyond name/model).
    dispatch_rows = _agent_dispatch_rows(ctx, agents_yaml)
    _dispatch_has_content = any(
        (a.get("role") or "—") not in ("—", "", None) or (a.get("phases") or "—") not in ("—", "", None)
        for a in dispatch_rows
    )
    if dispatch_rows and _dispatch_has_content:
        lines.append("### Agent Dispatch Log")
        lines.append("")
        lines.append("| Agent | Model | Role | Phases |")
        lines.append("|-------|-------|------|--------|")
        for a in dispatch_rows:
            lines.append(
                f"| {a.get('name', '—')} | {a.get('model', '—')} | {a.get('role', '—')} | {a.get('phases', '—')} |"
            )
        lines.append("")

    # --- Tokens & Cost ------------------------------------------------------
    if tokens or cost:
        lines.append("### Tokens & Cost")
        lines.append("")
        if tokens:
            lines.append(
                f"- **Tokens:** input={tokens.get('input', '—')} · "
                f"output={tokens.get('output', '—')} · "
                f"cache_read={tokens.get('cache_read', '—')} · "
                f"cache_write={tokens.get('cache_write', '—')} · "
                f"total={tokens.get('total', '—')}"
            )
        if cost:
            lines.append(f"- **Billing:** {cost.get('billing', '—')}")
            if cost.get("cache_savings_pct") is not None:
                lines.append(f"- **Cache savings:** {cost.get('cache_savings_pct')}%")
        lines.append("")
        lines.append(
            "> ⚠ **Scope:** host session only — sub-agent token spend "
            "is not captured by Claude Code's hook infrastructure."
        )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _agent_dispatch_rows(ctx: RenderContext, agents_yaml: list[dict]) -> list[dict[str, str]]:
    """Merge agent-dispatch metadata from yaml (stats.agents[]) with live
    scrapes from .agent-run.log (AGENT_INVOKE / AGENT_START lines) to cover
    the case where the yaml list is empty (e.g. resume runs).
    """
    by_name: dict[str, dict[str, str]] = {}
    for a in agents_yaml:
        name = a.get("name") or "—"
        by_name[name] = {
            "name": name,
            "model": a.get("model") or "—",
            "role": a.get("role") or "—",
            "phases": a.get("phases") or "—",
        }
    log = ctx.output_dir / ".agent-run.log"
    if not log.is_file():
        return list(by_name.values())
    # G2 - split regex into name+event vs. model. The original single
    # pattern used a lazy `.*?` before an optional `(?:model:...)?` group;
    # the lazy match greedily consumed zero characters and the optional
    # group never fired, leaving every Model column empty. Two passes
    # decouples the two captures and is easier to read.
    try:
        name_pat = re.compile(r"\s(?P<name>[\w-]+)\s+(?:AGENT_INVOKE|AGENT_START)\b")
        model_pat = re.compile(r"model:\s*(?P<model>[^,\s\)]+)")
        phase_pat = re.compile(r"\[Phase\s+(\d+[ab]?)/")
        seen_phases: dict[str, set[str]] = {}
        for line in log.read_text(encoding="utf-8").splitlines():
            nm = name_pat.search(line)
            if not nm:
                continue
            name = nm.group("name")
            mm = model_pat.search(line)
            model = mm.group("model") if mm else "—"
            pm = phase_pat.search(line)
            phase = pm.group(1) if pm else ""
            entry = by_name.setdefault(
                name,
                {
                    "name": name,
                    "model": model,
                    "role": "—",
                    "phases": "—",
                },
            )
            if entry["model"] in ("—", "") and model != "—":
                entry["model"] = model
            if phase:
                seen_phases.setdefault(name, set()).add(phase)
        for name, phases in seen_phases.items():
            if name in by_name and by_name[name]["phases"] in ("—", ""):
                by_name[name]["phases"] = ", ".join(sorted(phases))
    except OSError:
        pass
    return list(by_name.values())


# M3.3 / D1 — tier classifier (mirror of pregenerate_fragments._classify_tier)
# Used by the §2.3 Components-table post-processor to fill the "Type" column
# when the orchestrator yaml lacks an explicit `type`/`kind`/`tier` field.
_COMPONENT_TIER_HINTS = {
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
    # 'application' is the catch-all default
}


def _classify_component_tier(component: dict) -> str:
    """Return 'client' | 'application' | 'data' for a component dict."""
    haystack = " ".join(
        [
            (component.get("id") or "").lower(),
            (component.get("name") or "").lower(),
            " ".join(component.get("paths") or []).lower(),
        ]
    )
    for tier, hints in _COMPONENT_TIER_HINTS.items():
        if any(h in haystack for h in hints):
            return tier
    return "application"


def _read_stage_stats(output_dir: Path) -> list[dict]:
    """Read `.stage-stats.jsonl` written by ``record_stage_stats.py``.

    Returns the parsed records (empty list on absence/failure). Malformed
    lines are silently dropped so a partial-write at the line boundary
    does not poison the entire appendix.
    """
    path = output_dir / ".stage-stats.jsonl"
    if not path.is_file():
        return []
    out: list[dict] = []
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
    except OSError:
        return []
    return out


def _read_skill_config(output_dir: Path) -> dict:
    """Read `.skill-config.json` from $OUTPUT_DIR (best-effort).

    Provides fallback values for `repo_root` and `output_dir` when the
    orchestrator hasn't emitted them into `meta`. Returns ``{}`` on
    absence or parse error so callers can `.get(...)` safely.
    """
    path = output_dir / ".skill-config.json"
    if not path.is_file():
        return {}
    try:
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _resolve_security_schema(output_dir: Path) -> str:
    """Return the active §7 schema.

    The legacy v1 layout has been removed; v2 is the only supported
    security-architecture contract. ``output_dir`` remains in the signature
    because callers pass it as part of the render-context construction.
    """
    _ = output_dir
    return "v2"


def _fmt_ms(ms: int) -> str:
    """Format an integer millisecond duration as 'Xm YYs'."""
    if not ms or ms <= 0:
        return "—"
    secs = int(ms) // 1000
    return f"{secs // 60}m {secs % 60:02d}s"


def _scrape_phase_durations(output_dir: Path) -> list[dict[str, str]]:
    """Best-effort parse of `.agent-run.log` → per-phase duration table rows.

    Pairing strategy (M3.3):
      1. **Inline duration** — when PHASE_END includes `[Xm YYs]` / `[XmYYs]` /
         `[Xs]` suffix (canonical for Phase 2, 9, 10b), use that value
         directly.
      2. **Timestamp pairing** — when PHASE_END has no duration suffix
         (Phase 1, 3-8, 11), pair against the most-recent preceding
         PHASE_START for the same phase number and compute the wall-clock
         delta from the line timestamps. This keeps the appendix populated
         for every phase, not just the ones that happen to embed a
         `[duration]` literal.
    """
    log = output_dir / ".agent-run.log"
    if not log.is_file():
        return []
    line_ts_re = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)")
    phase_start_re = re.compile(r"PHASE_START\s+\[Phase\s+(\d+(?:b)?)/\d+\]\s+(.*)$")
    phase_end_inline_re = re.compile(r"PHASE_END\s+\[Phase\s+(\d+(?:b)?)/\d+\]\s+[✓]?\s*(.+?)\s*\[(\d+(?:m\s*\d+)?s)\]")
    phase_end_bare_re = re.compile(r"PHASE_END\s+\[Phase\s+(\d+(?:b)?)/\d+\]\s+[✓]?\s*(.+)$")
    agent_by_phase: dict[str, str] = {
        "1": "threat-analyst (sonnet-4-6)",
        "2": "recon-scanner (sonnet-4-6)",
        "3": "threat-analyst (sonnet-4-6)",
        "4": "threat-analyst (sonnet-4-6)",
        "5": "threat-analyst (sonnet-4-6)",
        "6": "threat-analyst (sonnet-4-6)",
        "7": "threat-analyst (sonnet-4-6)",
        "8": "threat-analyst (sonnet-4-6)",
        "9": "Nx stride-analyzer (sonnet-4-6)",
        "10": "threat-analyst (sonnet-4-6)",
        "10b": "appsec-triage-validator (sonnet-4-6)",
        "11": "threat-analyst (sonnet-4-6)",
    }

    def _parse_iso_to_epoch(ts: str) -> int | None:
        try:
            return int(datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            return None

    # Walk the log linearly, maintaining a per-phase stack of unmatched
    # PHASE_START timestamps so PHASE_END can compute deltas. Mirror of the
    # pairing algorithm in aggregate_run_issues._extract_phase_durations.
    open_starts: dict[str, list[int]] = {}
    rows: list[dict[str, str]] = []
    try:
        for raw in log.read_text(encoding="utf-8").splitlines():
            ts_match = line_ts_re.match(raw)
            ts_e = _parse_iso_to_epoch(ts_match.group(1)) if ts_match else None

            if ts_e is not None:
                m_start = phase_start_re.search(raw)
                if m_start:
                    phase = m_start.group(1)
                    open_starts.setdefault(phase, []).append(ts_e)
                    continue

            m_inline = phase_end_inline_re.search(raw)
            if m_inline:
                phase = m_inline.group(1)
                desc = m_inline.group(2).strip().rstrip("—").strip()
                desc = re.sub(r"\s+[A-Z]{5,}\s.*$", "", desc)
                duration = m_inline.group(3).replace("m ", "m ")
                # Pop matching open_start so a later bare PHASE_END for the
                # same phase doesn't double-count.
                if open_starts.get(phase):
                    open_starts[phase].pop()
                rows.append(
                    {
                        "phase": f"Phase {phase}",
                        "description": _truncate_with_ellipsis(desc, 90),
                        "agent": agent_by_phase.get(phase, "—"),
                        "duration": duration,
                    }
                )
                continue

            m_bare = phase_end_bare_re.search(raw)
            if m_bare and ts_e is not None:
                phase = m_bare.group(1)
                desc = m_bare.group(2).strip().rstrip("—").strip()
                desc = re.sub(r"\s+[A-Z]{5,}\s.*$", "", desc)
                stack = open_starts.get(phase) or []
                if not stack:
                    continue  # no matching START — skip silently
                start_ts = stack.pop()
                delta = max(ts_e - start_ts, 0)
                rows.append(
                    {
                        "phase": f"Phase {phase}",
                        "description": _truncate_with_ellipsis(desc, 90),
                        "agent": agent_by_phase.get(phase, "—"),
                        "duration": _fmt_seconds(delta),
                    }
                )
    except OSError:
        return []
    return rows


def _fmt_seconds(secs: int) -> str:
    """Format integer seconds as 'Xm YYs' or '<60s' when sub-minute."""
    if secs is None or secs < 0:
        return "—"
    if secs == 0:
        return "(inline)"
    if secs < 60:
        return f"{secs}s"
    return f"{secs // 60}m {secs % 60:02d}s"


def _format_generated_timestamp(raw: str) -> str:
    """Format an ISO8601 timestamp (`2026-05-17T05:31:44Z`) into a
    reader-friendly form (`2026-05-17 05:31 UTC`).

    Falls back to the input verbatim when the parser can't recognise it
    so non-ISO values aren't silently dropped.
    """
    if not isinstance(raw, str) or not raw.strip():
        return raw or "—"
    try:
        # Normalise the trailing `Z` to `+00:00` so fromisoformat accepts it.
        s = raw.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, AttributeError):
        return raw


def _read_live_plugin_meta() -> tuple[str | None, int | None]:
    """Return the (plugin_version, analysis_version) pair from the active
    plugin.json. Used by the Run Statistics appendix to overwrite stale
    pairs that an old Stage-1 run may have baked into meta:.
    """
    plugin_json = PLUGIN_ROOT / ".claude-plugin" / "plugin.json"
    if not plugin_json.is_file():
        return None, None
    try:
        data = json.loads(plugin_json.read_text(encoding="utf-8")) or {}
    except (OSError, json.JSONDecodeError):
        return None, None
    pv = data.get("version") or None
    av = data.get("analysis_version")
    if isinstance(av, str):
        try:
            av = int(av)
        except ValueError:
            av = None
    return pv, av if isinstance(av, int) else None


def _truncate_with_ellipsis(text: str, limit: int) -> str:
    """Cap ``text`` at ``limit`` chars; append `…` (single char) when
    truncation actually happens. Replaces the bare ``text[:60]`` slices in
    the per-phase duration scrape that were cutting mid-word and
    obscuring the captured counts.
    """
    if not isinstance(text, str):
        return ""
    s = text.strip()
    if len(s) <= limit:
        return s
    # Truncate at the limit-1 budget, then trim to the last word boundary
    # so the ellipsis lands cleanly instead of mid-token.
    head = s[: max(limit - 1, 1)].rstrip()
    if " " in head and len(head) > 20:
        head = head.rsplit(" ", 1)[0].rstrip(",;:-")
    return head + "…"


def _render_composition_notes(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """Render §Composition Notes — conditional appendix surfacing soft
    warnings, section retry counts, and skill-level auto-retry events from
    the prior compose iteration.

    Reads ``$OUTPUT_DIR/.compose-stats.json`` (written by
    ``_write_compose_stats()`` at the end of the prior compose run) plus
    ``.inline-shortcut-retry-count``. The section is only included in the
    rendered MD when the ``compose_warned`` eval-context flag is True (see
    contract: ``composition_notes.condition``).

    Goal: persist composition-pipeline health in the canonical artefact so
    PR reviewers can see what happened during render without reading the
    transient ``.agent-run.log``. The corresponding completion-summary
    block is emitted by ``render_completion_summary.py``.
    """
    stats = _read_compose_stats(ctx.output_dir) or {}
    auto_retries = _read_inline_retry_count(ctx.output_dir)

    warnings = stats.get("warnings") or []
    section_retries = stats.get("section_retries") or {}

    # R-13 fix — wording was self-contradicting ("completed cleanly … but
    # reported the following non-blocking issues"). Now we distinguish the
    # three cases explicitly: only warnings, only retries, both. The "satisfies
    # the contract" wording stays because by the time this appendix renders
    # the strict-contract gate has signed off — the warnings here are SOFT
    # (e.g. mermaid syntax hints, NARRATIVE_PLACEHOLDER leakage) that the
    # contract treats as informational, not as render failures.
    if warnings and (section_retries or auto_retries > 0):
        intro = (
            "The composition pipeline emitted soft warnings AND re-rendered one "
            "or more sections before reaching a contract-clean result. Details "
            "below are surfaced for transparency — the final rendered threat "
            "model satisfies the strict contract."
        )
    elif warnings:
        intro = (
            "The composition pipeline emitted the soft warnings listed below. "
            "These do not block release (the contract still passed) but they "
            "flag content the renderer could not fully validate — typically "
            "NARRATIVE_PLACEHOLDER leakage from Stage-2 incomplete authoring or "
            "Mermaid syntax that downstream parsers may reject."
        )
    elif section_retries or auto_retries > 0:
        intro = (
            "The composition pipeline re-rendered one or more sections before "
            "reaching a contract-clean result. The retry count is preserved "
            "below for plugin-health monitoring; the final rendered threat "
            "model satisfies the strict contract."
        )
    else:
        intro = "_The composition pipeline ran cleanly with no warnings or retries._"
    lines: list[str] = [
        '<a id="appendix-composition-notes"></a>',
        "## Appendix: Composition Notes",
        "",
        intro,
        "",
    ]

    if warnings:
        lines.append("### Soft Warnings")
        lines.append("")
        lines.append("| Section | Category | Detail |")
        lines.append("|---|---|---|")
        for w in warnings:
            sec = (w.get("section") or "(unspecified)").replace("|", "\\|")
            cat = (w.get("category") or "other").replace("|", "\\|")
            det = (w.get("detail") or "").replace("|", "\\|")
            # Truncate very long detail strings for table readability.
            if len(det) > 200:
                det = det[:197] + "…"
            lines.append(f"| {sec} | `{cat}` | {det} |")
        lines.append("")

    if section_retries:
        lines.append("### Section Retries")
        lines.append("")
        lines.append("| Section | Compose Attempts | Final |")
        lines.append("|---|---|---|")
        for sid, n in sorted(section_retries.items()):
            lines.append(f"| §{sid} | {n} / 3 | success |")
        lines.append("")
        lines.append(
            "_Each retry indicates the rendered fragment did not satisfy the "
            "contract on first try; the auto-repair loop in "
            "`compose_threat_model.py` regenerated it._"
        )
        lines.append("")

    if auto_retries > 0:
        lines.append("### Skill-Level Auto-Retries")
        lines.append("")
        lines.append(
            f"- Inline-shortcut hard gate triggered **{auto_retries}× recovery cycle"
            f"{'s' if auto_retries != 1 else ''}** "
            f"(see SKILL-impl.md M2.13). Final outcome: success."
        )
        lines.append("")
        lines.append(
            "_Each cycle ran the deterministic recovery sequence "
            "(`merge_threats.py` → `triage_validate_ratings.py` → "
            "`pregenerate_fragments.py`) followed by a fresh Stage-2 dispatch "
            "with a 120-turn budget. If you see this entry routinely, file a "
            "plugin bug — the orchestrator should produce all required fragments "
            "on its first attempt._"
        )
        lines.append("")

    if not warnings and not section_retries and not auto_retries:
        # The condition flag should have prevented this branch, but be
        # defensive — emit a brief "all clean" message rather than an
        # empty appendix that confuses readers.
        lines.append(
            "_The composition pipeline ran cleanly with no warnings or retries. "
            "(This appendix should normally be omitted in the clean case — its "
            "presence indicates a contract-evaluation drift.)_"
        )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _render_run_issues(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """Render §Run Issues — conditional appendix surfacing aggregated
    pipeline issues (errors, warnings, perf anomalies, recovery events)
    plus per-issue fix recommendations.

    Reads ``$OUTPUT_DIR/.run-issues.json`` (written by
    ``aggregate_run_issues.py`` + ``recommend_fixes.py`` at end of skill).
    Only included when the ``run_warned`` eval-context flag is True
    (see contract: ``run_issues.condition``). The MD-embedded form is the
    canonical persistence — it survives runtime_cleanup so PR reviewers
    and audit tooling see the full picture without log-grep.
    """
    data = _read_run_issues(ctx.output_dir) or {}
    issues = data.get("issues") or []
    summary = data.get("summary") or {}

    lines: list[str] = [
        '<a id="appendix-run-issues"></a>',
        "## Appendix: Run Issues",
        "",
        "This run produced a contract-clean threat model but the pipeline "
        "encountered the following issues. Each carries a structured fix "
        "recommendation; auto-applicable fixes can be applied via "
        "`/appsec-advisor:fix-run-issues`.",
        "",
        f"**Summary:** {summary.get('errors', 0)} error(s) · "
        f"{summary.get('warnings', 0)} warning(s) · "
        f"{summary.get('perf_anomalies', 0)} performance anomal{'y' if summary.get('perf_anomalies', 0) == 1 else 'ies'} · "
        f"{summary.get('recovery_events', 0)} recovery event(s) · "
        f"**{summary.get('auto_applicable_fixes', 0)} auto-applicable fix(es)**",
        "",
    ]

    if not issues:
        lines.append(
            "_No issues recorded. (This appendix should normally be omitted in the "
            "clean case — its presence indicates a contract-evaluation drift.)_"
        )
        lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    # Group by severity for readability.
    by_sev: dict[str, list[dict]] = {"error": [], "warning": [], "info": []}
    for i in issues:
        by_sev.setdefault(i.get("severity", "info"), []).append(i)

    sev_emoji = {"error": "🔴", "warning": "🟡", "info": "🔵"}

    for sev in ("error", "warning", "info"):
        bucket = by_sev.get(sev, [])
        if not bucket:
            continue
        emoji = sev_emoji.get(sev, "•")
        lines.append(f"### {emoji} {sev.capitalize()}{'s' if len(bucket) != 1 else ''} ({len(bucket)})")
        lines.append("")
        for issue in bucket:
            iid = issue.get("id", "?")
            cat = issue.get("category", "?")
            title = issue.get("title", "(no title)")
            ev = issue.get("evidence") or {}
            fr = issue.get("fix_recommendation") or {}

            lines.append(f"#### {iid} — {title}")
            lines.append("")
            lines.append(f"**Category:** `{cat}`")
            log_file = ev.get("log_file", "?")
            log_line = ev.get("log_line", "?")
            lines.append(f"**Evidence:** `{log_file}` line {log_line}")
            if ev.get("timestamp_iso"):
                lines.append(f"**Timestamp:** {ev['timestamp_iso']}")
            lines.append("")

            # Fix recommendation block.
            auto_badge = "✓ auto-applicable" if fr.get("auto_applicable") else "⚠ manual review"
            confidence = fr.get("confidence", "?")
            risk = fr.get("risk_level", "?")
            lines.append(
                f"**Recommended Fix** ({fr.get('category', '?')}, "
                f"confidence: {confidence}, risk: {risk}) — {auto_badge}"
            )
            lines.append("")
            if fr.get("summary"):
                lines.append(f"> {fr['summary']}")
                lines.append("")
            if fr.get("rationale"):
                lines.append(f"_Rationale:_ {fr['rationale']}")
                lines.append("")

            actions = fr.get("actions") or []
            if actions:
                lines.append("**Actions:**")
                lines.append("")
                for a in actions:
                    atype = a.get("type", "?")
                    target = a.get("target", "?")
                    if atype == "edit_file" and a.get("find") and a.get("replace"):
                        lines.append(f"- `edit_file` → `{target}`")
                        lines.append(f"  - find: `{a['find']}`")
                        lines.append(f"  - replace: `{a['replace']}`")
                    else:
                        details = a.get("details", "")
                        lines.append(f"- `{atype}` → `{target}`" + (f": {details}" if details else ""))
                lines.append("")

            verification = fr.get("verification") or []
            if verification:
                lines.append("**Verification:**")
                lines.append("")
                for v in verification:
                    lines.append(f"- `{v}`")
                lines.append("")

            lines.append("---")
            lines.append("")

    # Footer pointer to the fix skill.
    auto_n = summary.get("auto_applicable_fixes", 0)
    if auto_n > 0:
        lines.append(
            f"_{auto_n} of these fix(es) can be applied non-interactively via_ `/appsec-advisor:fix-run-issues`_._"
        )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _render_appendix_vektor_taxonomy(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    lines = [
        '<a id="appendix-a-vektor-taxonomy"></a>',
        "## Appendix A — Vektor Taxonomy",
        "",
        "This appendix defines the attacker-starting-position labels used in the "
        "Top Threats table and throughout [§8 Findings Register](#8-findings-register). Each label answers the "
        "question *what does the attacker need before the exploit begins?*",
        "",
    ]
    tax_path = PLUGIN_ROOT / "data" / "breach-vector-taxonomy.yaml"
    if not tax_path.is_file():
        return "\n".join(lines).rstrip() + "\n"
    try:
        tax = yaml.safe_load(tax_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return "\n".join(lines).rstrip() + "\n"
    # Support both schema keys: `vectors:` (canonical) or `vektors:` (legacy typo).
    entries = tax.get("vectors") or tax.get("vektors") or []
    for item in entries:
        vid = item.get("id", "")
        vlabel = item.get("label", vid)
        lines.append(f'<a id="vektor-{vid}"></a>')
        lines.append(f"### {vlabel}")
        lines.append("")
        bd = item.get("breach_distance")
        pos = item.get("attacker_position")
        if pos:
            lines.append(f"**Attacker position:** {pos}" + (f" · **Breach distance:** {bd}" if bd is not None else ""))
            lines.append("")
        preconds = item.get("preconditions") or []
        if preconds:
            lines.append("**Preconditions:**")
            lines.append("")
            for p in preconds:
                lines.append(f"- {p}")
            lines.append("")
        typ_cwes = item.get("typical_cwes") or []
        if typ_cwes:
            cwe_refs = " · ".join(f"[CWE-{c}](https://cwe.mitre.org/data/definitions/{c}.html)" for c in typ_cwes)
            lines.append(f"**Typical CWEs:** {cwe_refs}")
            lines.append("")
        typ_owasp = item.get("typical_owasp_top10") or []
        if typ_owasp:
            lines.append(f"**Typical OWASP Top 10:** {', '.join(typ_owasp)}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Threat register / Mitigation register — computed from yaml
# ---------------------------------------------------------------------------


# CWE → English one-sentence root-cause template. The §8 Story Card cell
# uses this to expose the *underlying anti-pattern* (not just the symptom)
# to non-developer readers. Coverage is intentionally CWE-focussed: any
# CWE not in this map falls back to scenario prose only — no fake
# generated text.
_CWE_ROOT_CAUSE: dict[str, str] = {
    "CWE-22": "Filesystem path constructed from user input without normalisation against an allow-listed root.",
    "CWE-79": "User input rendered into HTML without context-appropriate output encoding (or with the framework's escape mechanism explicitly bypassed).",
    "CWE-89": "User input concatenated into SQL strings instead of using parameterised queries.",
    "CWE-94": "Dynamic code construction (eval / Function / vm.runInContext) on attacker-influenced input.",
    "CWE-95": "Dynamic evaluation of an attacker-controlled expression instead of using a sandboxed expression evaluator.",
    "CWE-200": "Sensitive information exposed in API response, URL, or error message.",
    "CWE-306": "Privileged endpoint exposed without an authentication middleware in front of it.",
    "CWE-307": "No rate-limiting on a brute-force-able endpoint (login / password reset / token validation).",
    "CWE-319": "Sensitive data transmitted in clear-text (no TLS / plain-text protocol).",
    "CWE-321": "Hard-coded cryptographic key in source code instead of loading from a secret store at runtime.",
    "CWE-327": "Use of a broken or risky cryptographic primitive — defaults are not safe in the current threat model.",
    "CWE-345": "Security decision relies on a value that is not integrity-protected against the attacker.",
    "CWE-352": "State-changing request accepted without a CSRF token or equivalent same-origin guard.",
    "CWE-400": "Endpoint accepts unbounded input or runs an unbounded loop without resource caps.",
    "CWE-502": "Untrusted serialized data deserialised into live objects, allowing gadget-chain code execution.",
    "CWE-532": "Sensitive content (logs, key material) reachable through the public HTTP surface.",
    "CWE-540": "Source code or secrets included in the deployed artifact / served by the public file handler.",
    "CWE-552": "Sensitive files made reachable through the public HTTP surface without an auth gate.",
    "CWE-601": "Redirect target derived from user input without an allow-list, enabling phishing redirects.",
    "CWE-602": "Security decision implemented on the client; the trusted server-side check is missing.",
    "CWE-611": "XML parser configured to resolve external entities — XXE protection not enabled.",
    "CWE-639": "Object reference accepted from the request without an ownership / authorization check.",
    "CWE-778": "No audit logging on security-sensitive operations — incident reconstruction not possible.",
    "CWE-798": "Hard-coded credentials in source code instead of secret-store lookup.",
    "CWE-916": "Outdated / cryptographically broken password hashing algorithm in use (or no key-stretching at all).",
    "CWE-918": "Outbound HTTP request target derived from user input without an allow-list / DNS-pinning.",
    "CWE-922": "Sensitive data stored client-side in locations accessible to JavaScript (localStorage / sessionStorage).",
    "CWE-942": "CORS configuration accepts arbitrary origins (wildcard or reflective Allow-Origin).",
    "CWE-943": "User input interpolated into a NoSQL query expression instead of using the driver's parameter-binding API.",
    "CWE-1021": "Clickjacking-friendly framing policy (missing X-Frame-Options / frame-ancestors directive).",
}


def _root_cause_for_cwe(cwe: str | None) -> str | None:
    """Look up a one-sentence root-cause description for a CWE.

    Returns ``None`` when the CWE is unknown — callers must not synthesise
    text from nothing; the absence of a template means the renderer leaves
    the scenario prose untouched rather than fabricating an analysis.
    """
    if not cwe:
        return None
    key = cwe.strip().upper()
    if not key.startswith("CWE-"):
        key = f"CWE-{key}"
    return _CWE_ROOT_CAUSE.get(key)


def _read_evidence_snippet(repo_root: Path | None, file_path: str, line: int | None, context: int) -> str | None:
    """Read ``line ± context`` lines from ``<repo_root>/<file_path>``.

    Returns the raw multi-line slice (no HTML escaping, no header line —
    callers wrap it as needed). Returns ``None`` when the file is missing,
    the line is out-of-bounds, ``context`` is ≤ 0, or the resolved path
    escapes ``repo_root`` (path-traversal guard).
    """
    if not repo_root or not file_path or not line or context <= 0:
        return None
    try:
        repo_real = Path(repo_root).resolve()
        full = (repo_real / file_path).resolve()
        if not str(full).startswith(str(repo_real)):
            return None  # path traversal guard
        if not full.is_file():
            return None
        with full.open(encoding="utf-8", errors="replace") as fh:
            all_lines = fh.readlines()
    except (OSError, ValueError):
        return None
    if line < 1 or line > len(all_lines):
        return None
    lo = max(1, line - context)
    hi = min(len(all_lines), line + context)
    # Strip trailing newline / trim over-long lines so minified files never blow
    # up a cell. Trim at a WORD boundary (never mid-token) so a long source line
    # does not render as a broken code token (e.g. `plain: true` → `plain: tr`).
    # The cap is generous — the PDF soft-wraps long code lines. Preserve indent.
    snippet_lines = [_trim_code_line(all_lines[i].rstrip("\n")) for i in range(lo - 1, hi)]
    return "\n".join(snippet_lines)


_EVIDENCE_MAX_LINE = 400


def _trim_code_line(ln: str) -> str:
    """Trim an over-long code line at a word boundary (never mid-token)."""
    if len(ln) <= _EVIDENCE_MAX_LINE:
        return ln
    cut = ln.rfind(" ", 0, _EVIDENCE_MAX_LINE - 1)
    if cut < _EVIDENCE_MAX_LINE // 2:  # no sensible space → hard cut
        cut = _EVIDENCE_MAX_LINE - 1
    return ln[:cut].rstrip() + " …"


def _html_escape_for_pre(text: str) -> str:
    """HTML-escape so the text can sit inside ``<pre><code>…</code></pre>``."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _lang_class_for_file(file_path: str) -> str:
    """Return a Prism/highlight.js language class for a file extension."""
    if not file_path:
        return ""
    base = file_path.rsplit("/", 1)[-1].lower()
    if base == "dockerfile" or base.endswith(".dockerfile") or base.startswith("dockerfile."):
        return "language-dockerfile"
    ext = base.rsplit(".", 1)[-1] if "." in base else ""
    return {
        "ts": "language-typescript",
        "tsx": "language-typescript",
        "js": "language-javascript",
        "jsx": "language-javascript",
        "py": "language-python",
        "rb": "language-ruby",
        "go": "language-go",
        "rs": "language-rust",
        "java": "language-java",
        "sh": "language-bash",
        "yaml": "language-yaml",
        "yml": "language-yaml",
        "json": "language-json",
        "toml": "language-toml",
        "md": "language-markdown",
        "html": "language-html",
        "css": "language-css",
        "scss": "language-scss",
        "sql": "language-sql",
        "env": "language-bash",
    }.get(ext, "")


# Per-severity rendering depth knobs for the Story Card. The numbers are
# tuned for readability: Critical findings get a full case description plus
# evidence snippet; Low findings get a one-sentence root cause only.
_FINDING_DEPTH: dict[str, dict[str, int]] = {
    "critical": {"snippet_context": 3, "scenario_sentences": 4},
    "high": {"snippet_context": 2, "scenario_sentences": 3},
    "medium": {"snippet_context": 1, "scenario_sentences": 2},
    "low": {"snippet_context": 0, "scenario_sentences": 1},
}

# CWE classes where a code snippet does NOT add meaningful information beyond
# the title + scenario. These are configuration / absence findings — the
# defect is the absence of a control, not a specific buggy line of code, so
# the snippet would just show benign surrounding lines. Restricting snippets
# to CWEs where the bug IS the code yields ~30% narrower §8 cells without
# losing analytical signal. The check is best-effort: when the CWE is
# missing or not in either list we keep the snippet (legacy behaviour).
_FINDING_SKIP_SNIPPET_CWES: set[str] = {
    "CWE-352",  # CSRF — absence of token
    "CWE-693",  # Protection Mechanism Failure
    "CWE-1021",  # Restriction of Rendered UI (CSP missing)
    "CWE-942",  # Permissive CORS — config-class
    "CWE-922",  # Insecure Storage of Sensitive Information (localStorage)
    "CWE-602",  # Client-Side Enforcement of Server-Side Security
    "CWE-200",  # Generic information disclosure (often config / file-serve)
    "CWE-916",  # Use of Password Hash With Insufficient Computational Effort
    "CWE-326",  # Inadequate Encryption Strength
    "CWE-327",  # Use of a Broken or Risky Cryptographic Algorithm
    "CWE-321",  # Hard-coded Cryptographic Key (snippet redacted anyway)
    "CWE-400",  # Resource Consumption (DoS configuration)
}


def _first_n_sentences(text: str, n: int) -> str:
    """Return the first N sentence-ish chunks of ``text``.

    Naively splits on ``[.!?]`` followed by whitespace + a capital letter or
    a backtick / open-paren / quote — keeps URL-like ``a.b.c`` together
    because the lookahead requires capital/symbol after the space.
    """
    if not text or n <= 0:
        return ""
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z(`\"])", text.strip())
    return " ".join(parts[:n]).strip()


# CWE-class → one-sentence "what the code shows" template used by
# _build_finding_cell when the YAML carries no explicit `evidence_summary`.
# The synthesised claim is a structural statement about the code that the
# next-line snippet visually proves — it is NOT a CWE-template substitute
# for the Issue narrative. Each value names the dangerous code structure
# concretely so the reader sees `Evidence: <claim>` followed by `<code>`
# that obviously realises that claim. Keys are bare CWE numbers (no prefix).
_EVIDENCE_CWE_CLAIMS: dict[str, str] = {
    "22": "User-supplied path components are joined without traversal-safe canonicalisation",
    "78": "Untrusted input is concatenated into a shell-executed command string",
    "79": "User input is rendered as HTML without contextual output encoding",
    "89": "SQL is assembled via string concatenation/interpolation of untrusted input",
    "94": "User-supplied code is passed to a runtime evaluator without an allow-list of operations",
    "200": "Sensitive runtime values are served unauthenticated to any caller",
    "284": "A protected endpoint is reachable without an authentication or authorization check",
    "287": "The authentication path can be reached without verifying the supplied credential",
    "295": "External certificates are accepted without verifying the trust chain",
    "306": "A privileged operation is exposed without authentication",
    "311": "Sensitive data is persisted or transmitted without encryption-in-transit/at-rest",
    "319": "Credentials or session material cross the wire over a clear-text channel",
    "321": "A signing key is embedded as a literal constant in source",
    "327": "A broken or non-password cryptographic primitive is configured on this path",
    "338": "A predictable random source is used where cryptographic randomness is required",
    "352": "A state-changing request can be triggered cross-origin without a synchroniser token",
    "434": "Uploaded file content is written to disk without type or path validation",
    "502": "An untrusted serialised payload is deserialised into a live object graph",
    "522": "Credentials are persisted without an adaptive password-hashing function",
    "601": "A redirect target is derived from untrusted input without an allow-list",
    "611": "An XML parser is configured to expand external entities while processing untrusted input",
    "613": "Session lifetime is unbounded or revocation is impossible on logout",
    "639": "An object-identity parameter is trusted from the request without server-side ownership check",
    "640": "The password-reset path accepts an attacker-influenced binding without out-of-band verification",
    "693": "The control that would block this exposure is absent from the configured stack",
    "732": "A sensitive resource is created with permissive default permissions",
    "770": "Resource allocation is unbounded with respect to attacker-controlled input",
    "778": "Security-relevant events occur with no audit-log entry",
    "798": "A credential is committed in plaintext to version control",
    "862": "Route-level authorization middleware is missing on a mutating endpoint",
    "863": "An authorization decision is made against the wrong identity attribute",
    "915": "Mass assignment is enabled because the model accepts request fields wholesale",
    "916": "A non-iterating hash is used for password storage",
    "918": "An outbound request is issued to a URL derived from untrusted input without an allow-list",
    "1021": "An HTML response is served without an X-Frame-Options or CSP frame-ancestors directive",
}


# Abbreviations and dotted-identifier shapes that the naive
# `(?<=[.!?])\s+` splitter mis-handles, breaking the Story Card's
# Issue/Impact carve-out (review-recommendations §3.1 row d). When the
# splitter cuts inside `(e.g. …)`, `Node.js`, `child_process.exec()` or
# similar, the trailing payload fragment becomes the carved Impact, and
# the cell renders:
#
#     **Impact:** require('child_process').exec()).
#
# instead of a real consequence. `_safe_sentence_split` masks these
# shapes with a non-splitting unicode sentinel before splitting, then
# restores them. The masking is purely textual — we never rely on it for
# semantic disambiguation, only for the splitter's boundary decision.
_SENTENCE_DOT_PLACEHOLDER = " "
_SENTENCE_ABBREVIATIONS: tuple[str, ...] = (
    "e.g.",
    "i.e.",
    "cf.",
    "vs.",
    "etc.",
    "Inc.",
    "Ltd.",
    "Co.",
)


def _safe_sentence_split(text: str) -> list[str]:
    """Split ``text`` into sentences, but never inside common abbreviations
    or dotted identifiers (`Node.js`, `child_process.exec()`, hostnames).

    Returns a list of stripped sentence strings. Empty input → ``[]``.
    """
    if not text:
        return []
    masked = text
    # Mask common Latin abbreviations whole-word (case-sensitive — these
    # are the canonical forms).
    for abbr in _SENTENCE_ABBREVIATIONS:
        masked = masked.replace(abbr, abbr.replace(".", _SENTENCE_DOT_PLACEHOLDER))
    # Mask dotted identifiers / member expressions / file extensions /
    # hostnames: a dot that sits BETWEEN two word/identifier characters
    # is never a sentence boundary in this corpus. Mask all such dots.
    masked = re.sub(r"(?<=[\w\)\]])\.(?=\w)", _SENTENCE_DOT_PLACEHOLDER, masked)
    # Now split on terminal punctuation followed by whitespace.
    raw = re.split(r"(?<=[.!?])\s+", masked)
    return [s.replace(_SENTENCE_DOT_PLACEHOLDER, ".").strip() for s in raw if s.strip()]


def _synthesise_evidence_summary(t: dict, ev_file: str, ev_line: object) -> str:
    """Build a one-sentence `**Evidence:**` claim when the YAML lacks an
    explicit ``evidence_summary``.

    The claim is a structural statement about the code that the snippet
    below the line will visually prove. Sourced from the CWE-class
    template table; falls back to a generic claim when the CWE is
    unmapped or absent.
    """
    cwe_raw = (t.get("cwe") or "").strip()
    cwe_num = ""
    if cwe_raw:
        m = re.match(r"^(?:CWE-)?(\d+)$", cwe_raw, re.IGNORECASE)
        if m:
            cwe_num = m.group(1)
    claim = _EVIDENCE_CWE_CLAIMS.get(cwe_num, "")
    if not claim:
        # 2026-05 (review-recommendations §3.1 row c): the previous
        # generic fallback ("The implementation visible in the snippet
        # below realises the weakness described above") added zero
        # information — the <details> widget already says "Evidence code
        # · file:line". Return empty so the caller skips the **Evidence:**
        # prose line entirely and just renders the code widget.
        return ""
    # Append the file context so the reader knows the proof is local.
    if ev_file:
        loc = ev_file if not ev_line else f"{ev_file}:{ev_line}"
        return f"{claim} (`{loc}`)"
    return claim


# Item 8 (2026-05-28): CWE-class → one-sentence imperative fix action.
# Used by `_build_finding_cell` to prepend a generic remediation lead
# before the M-NNN mitigation link. Maps from canonical CWE numbers to
# a sentence so the Story Card's **Fix** field always carries actionable
# guidance even when the linked M-NNN block lives in §9.
_FIX_ACTION_LEADS: dict[str, str] = {
    "89": "Switch all SQL execution to parameterised queries or ORM-bound parameters",
    "564": "Switch all SQL execution to parameterised queries or ORM-bound parameters",
    "943": "Replace string concatenation in query operators with parameter binding",
    "78": "Replace shell invocations with an argv-list API and validate every input",
    "94": "Replace runtime code generation (eval/Function/template render) with a data-only execution path",
    "95": "Replace runtime code generation (eval/Function/template render) with a data-only execution path",
    "917": "Replace dynamic expression evaluation with safe template rendering or a static lookup",
    "79": "Output-encode untrusted strings at every sink and remove all `bypassSecurityTrustHtml` calls",
    "80": "Output-encode untrusted strings at every sink and remove all `bypassSecurityTrustHtml` calls",
    "611": "Disable external entity resolution on every XML parser and reject DOCTYPE declarations",
    "918": "Validate the URL scheme + host against an explicit allow-list before issuing outbound requests",
    "22": "Resolve and normalise every constructed path and reject anything that escapes the intended base directory",
    "23": "Resolve and normalise every constructed path and reject anything that escapes the intended base directory",
    "352": "Enforce a same-origin or signed CSRF token on every state-changing endpoint",
    "284": "Add explicit server-side authorisation checks on every protected route",
    "285": "Add explicit server-side authorisation checks on every protected route",
    "639": "Tie every object lookup to the requesting user's identity and reject cross-tenant references",
    "287": "Strengthen authentication: enforce a vetted JWT verifier with explicit algorithm, MFA where appropriate",
    "347": "Pin the signature algorithm explicitly and reject `alg:none` and unknown algorithms",
    "798": "Move the credential out of source control into a secret store and rotate it",
    "321": "Move the cryptographic key out of source control into a managed secret store and rotate it",
    "259": "Move the credential out of source control into a secret store and rotate it",
    "327": "Replace the broken algorithm with a vetted modern primitive (AES-GCM / Argon2id / Ed25519)",
    "328": "Replace the broken hash with a salted password-hashing function (bcrypt/Argon2id)",
    "916": "Replace the broken hash with a salted password-hashing function (bcrypt/Argon2id)",
    "330": "Switch to a cryptographically secure RNG (`crypto.randomBytes` / OS `/dev/urandom`)",
    "311": "Encrypt the data in transit and at rest with vetted primitives",
    "319": "Force TLS on every transport channel and reject downgrades",
    "521": "Enforce a length and complexity policy and reject reused / breached passwords",
    "307": "Apply rate limiting and lock-out thresholds on authentication endpoints",
    "770": "Bound the request rate and the per-request resource budget on this endpoint",
    "400": "Bound the request rate and the per-request resource budget on this endpoint",
    "434": "Validate uploaded file type, size, and storage path; never execute uploaded content",
    "502": "Use a strict allow-list deserialiser and never accept untrusted gadget chains",
    "532": "Strip secrets and PII from every log sink and rotate any token that already leaked",
    "200": "Restrict the response to the minimum fields needed and never echo secrets",
    "209": "Replace developer error pages with a generic message in production responses",
    "942": "Replace the wildcard CORS origin with an explicit allow-list",
    "1021": "Add a frame-ancestors directive to the Content Security Policy",
    "693": "Add the missing protection mechanism for this surface (CSP / CSRF token / headers)",
    "1004": "Set `HttpOnly` on every session cookie",
    "614": "Set `Secure` on every session cookie and enforce HTTPS-only delivery",
    "1275": "Set `SameSite=Lax` or `Strict` on every session cookie",
    "1104": "Replace the unmaintained dependency with a maintained equivalent or fork it under ownership",
    "1395": "Replace the unmaintained dependency with a maintained equivalent or fork it under ownership",
    "937": "Upgrade the dependency to a current, supported major version and pin via lockfile",
    "1035": "Upgrade the dependency to a current, supported major version and pin via lockfile",
}


def _fix_action_lead(cwe_norm: str) -> str:
    """Return a one-sentence imperative fix action for ``cwe_norm``
    (e.g. ``CWE-89``). Empty when no mapping exists — caller renders the
    M-NNN link only."""
    if not cwe_norm:
        return ""
    m = re.match(r"^(?:CWE-)?(\d+)$", cwe_norm.strip(), re.IGNORECASE)
    if not m:
        return ""
    return _FIX_ACTION_LEADS.get(m.group(1), "")


# Item 9 (2026-05-28): auto-wrap unmarked code identifiers in `backticks`
# so Issue/Impact prose renders file paths, function names, and config
# keys as code. Conservative — only wraps tokens that look strongly like
# code references (file extensions, function-call shape, env-var case)
# and never doubles existing backticks.
_CODE_FILE_RE = re.compile(
    r"(?<![`/\w])"  # not already in backticks or inside a path
    # `(?<!\\)` immediately before the extension-dot: a backslash there means
    # `_escape_dot_tld_identifiers` already deliberately escaped this token as
    # a known brand name (`Node\.js`) — do not re-match it as a fake ".js file"
    # and re-wrap it in backticks, which leaks the backslash in the rendered
    # code span (juice-shop 2026-07-02). Genuine paths (`bar.ts`) are unaffected
    # since the char right before their extension-dot is never a backslash.
    r"([A-Za-z_][A-Za-z0-9_./\\-]*(?<!\\)\.(?:ts|tsx|js|jsx|mjs|cjs|py|rb|go|rs|java|kt|"
    r"yml|yaml|json|xml|toml|ini|env|sh|sql|html|css|scss|md|conf)"
    r"(?::\d+(?:-\d+)?)?)"  # optional :line[-end]
    r"(?![`\w.])"
)
_CODE_CALL_RE = re.compile(
    r"(?<![`\w])"
    r"([A-Za-z_][A-Za-z0-9_]*"
    r"(?:\.[A-Za-z_][A-Za-z0-9_]*)+\(\))"  # foo.bar() / a.b.c()
    r"(?![`\w])"
)
_CODE_BARE_CALL_RE = re.compile(
    r"(?<![`\w])"
    r"([A-Za-z_][A-Za-z0-9_]{2,}\(\))"  # plain identifier()
    r"(?![`\w])"
)
_CODE_DOTTED_RE = re.compile(
    r"(?<![`\w/])"
    r"([a-z][a-zA-Z0-9_]*"
    # Inner segments may start uppercase so member chains ending in a
    # class/constant resolve fully: req.body.UserId, secrets.GITHUB_TOKEN,
    # process.env.LLM_API_KEY. They must start with a LETTER (not `_`) so a
    # markdown italic close — `… stay valid._` → `valid` + `._` — is never
    # mistaken for a dotted member. First segment stays lowercase-anchored so
    # prose like "U.S." is never wrapped.
    r"(?:\.[A-Za-z][a-zA-Z0-9_]*){1,3})"
    # Reject a continuation (`.word`, `(`, word char, backtick) but ALLOW a
    # trailing sentence period (`.` + space/end) so `… req.user.id.` matches.
    r"(?![`\w(]|\.\w)"
)
# UPPER_SNAKE environment / secret identifiers — GITHUB_TOKEN, NODE_ENV,
# ORG_ADMIN_TOKEN, LLM_API_KEY. Requires ≥1 underscore so prose acronyms
# (XSS, CSRF, SQL) are never wrapped. A leading `secrets.`/`process.env.`
# member is handled by _CODE_DOTTED_RE; this catches the bare token.
_CODE_ENV_RE = re.compile(r"(?<![`\w.])([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)(?![`\w])")


# --- Fail-closed guards for the two AMBIGUOUS matchers -------------------
# `_CODE_FILE_RE` (`Stem.js`) and `_CODE_DOTTED_RE` (`word.word`) match token
# *shapes* that also occur in product names (`Node.js`, `socket.io`,
# `Fastify.js`) and prose abbreviations (`e.g`, `i.e`). Wrapping those in
# backticks reads as a spurious code reference. The old defence subtracted a
# hand-maintained brand allowlist (`_DOT_TLD_KNOWN_NAMES`) — fail-open: any
# un-listed library (`engine.io`, `Fastify.js`) leaked. Instead require
# POSITIVE evidence the token is real code before wrapping; unknown-but-code-
# shaped prose stays prose.
#
# JS-ecosystem extensions whose `Stem.ext` form collides with library naming.
# `.ts`/`.tsx` are deliberately EXCLUDED — a bare Capitalised `App.tsx` is far
# more likely a real component file than a product name, and TS-named brands
# are rare. Brands overwhelmingly use `.js`.
_BRAND_RISK_EXT = frozenset({"js", "jsx", "mjs", "cjs"})
# Dotted-token last-segments that mark a PRODUCT / DOMAIN, not a method call:
# `socket.io`, `engine.io`, `evil.com`, `foo.dev`. A real API call ends in a
# method name (`socket.emit`, `restTemplate.getForObject`) whose last segment
# is none of these.
_DOTTED_NONCODE_SUFFIX = frozenset({"io", "js", "net", "org", "com", "dev", "ai", "co", "gg", "app", "xyz"})
# …unless a known code head precedes it (defensive; `req.io` etc. are code).
_DOTTED_CODE_HEADS = frozenset({"req", "res", "ctx", "this", "self", "process", "window", "document", "console"})


def _file_token_is_product_name(token: str) -> bool:
    """True when a ``_CODE_FILE_RE`` match is almost certainly a product name,
    not a file reference: a JS-ecosystem extension on a single Capitalised
    stem, with no path separator and no ``:line`` locator. Real file references
    in these reports carry a path (``routes/login.ts``) or a locator
    (``OrderLookupDao.java:22``); bare ``Fastify.js`` / ``Node.js`` do not."""
    if "/" in token or "\\" in token or ":" in token:
        return False  # has a path or a :line -> a real reference
    stem, _, rest = token.partition(".")
    ext = rest.rsplit(".", 1)[-1].lower()
    if ext not in _BRAND_RISK_EXT:
        return False
    # Single Capitalised word stem == product-shaped (Node, Vue, Fastify, Hapi).
    return bool(re.fullmatch(r"[A-Z][A-Za-z0-9]*", stem))


def _dotted_token_is_code(token: str) -> bool:
    """False for the two dotted shapes that are NOT code: prose abbreviations
    (``e.g``, ``i.e``, ``a.m`` — any single-letter segment) and product /
    domain names (``socket.io``, ``engine.io``, ``evil.com`` — a product/TLD
    last segment with no known code head). Everything else — real method calls
    (``socket.emit``, ``restTemplate.getForObject``) and member chains
    (``req.body.email``) — stays code."""
    segs = token.lower().split(".")
    if all(len(s) == 1 for s in segs):
        return False  # abbreviation: e.g / i.e / a.m / a.k.a
    if segs[-1] in _DOTTED_NONCODE_SUFFIX and segs[0] not in _DOTTED_CODE_HEADS:
        return False  # product / domain: socket.io, evil.com
    return True


# A quoted string literal that is really CODE (a SQL query, a concatenated
# expression) — wrap the WHOLE literal as one span so the per-token matchers
# never reach inside it and half-backtick a column ref (`o.owner_id`) while
# leaving the surrounding query as prose. The code-signal gate keeps ordinary
# prose apostrophes ("the attacker's request") out: they carry no SQL keyword
# and no `=`+operator combination.
_SQL_KW_RE = re.compile(
    r"\b(select|insert|update|delete|drop|union|from|where|join|values|"
    r"create|alter|exec)\b",
    re.I,
)
# Escape-aware so a Java/JS literal ending in a backslash-escaped quote
# (`'… = \''`) is captured whole instead of cut at the inner `\'`.
_CODE_STRING_RE = re.compile(r"(?<!`)('(?:[^'\n`\\]|\\.){6,240}'|\"(?:[^\"\n`\\]|\\.){6,240}\")(?!`)")


def _string_literal_is_code(inner: str) -> bool:
    # A real SQL statement co-occurs ≥2 distinct keywords (SELECT…FROM,
    # …JOIN…WHERE). A kebab-case slug / CSS class that merely CONTAINS one
    # keyword as a hyphen-delimited word is NOT code — `-` is a `\b` boundary,
    # so `\bupdate\b` fires spuriously inside an anchor id like
    # "dependency-update-posture" (and "create-account", "data-from-source"),
    # which then backtick-wrapped the whole `<a id="…">` and broke the anchor.
    kw = len({m.group(1).lower() for m in _SQL_KW_RE.finditer(inner)})
    if kw >= 2:
        return True
    # An assignment / concatenation expression — or a single-keyword query
    # fragment that also carries a query operator (`… where x = …`).
    return "=" in inner and ("+" in inner or "(" in inner or ";" in inner or kw >= 1)


def _wrap_code_string_literals(text: str) -> str:
    """Backtick a whole quoted string literal when it is unambiguously code."""

    def _repl(m: re.Match[str]) -> str:
        span = m.group(1)
        if not _string_literal_is_code(span[1:-1]):
            return span
        return f"`{span}`"

    return _CODE_STRING_RE.sub(_repl, text)


_CODE_SPAN_MASK_RE = re.compile(r"`[^`]+`|\]\([^)]+\)|<[^>]+>|&#\d+;")

# A finding/mitigation title carries its evidence pointer as a TRAILING
# parenthetical locator — `(routes/api/Users)`, `(updateProductReviews.ts:18)`,
# `(package.json:7)`, `(Dockerfile)`. The LLM backticks it inconsistently, so the
# same report shows `(`a.ts:18`)` next to `(routes/api/Users)`. These two helpers
# normalise it deterministically: code locators are ALWAYS monospaced in rendered
# labels, prose / STRIDE tags ((S·E), (I)) are never touched, and the Table of
# Contents strips the backticks entirely.
_LOCATOR_TOKEN_RE = re.compile(r"^[A-Za-z0-9_@][\w./\\@-]*(?::\d+(?:-\d+)?)?$")
_NOEXT_CODE_FILES = {
    "dockerfile",
    "makefile",
    "jenkinsfile",
    "procfile",
    "gemfile",
    "rakefile",
    "vagrantfile",
    "brewfile",
    "gulpfile",
    "gruntfile",
}


def _codify_label_locator(label: str) -> str:
    """Backtick the trailing ``(<locator>)`` of a finding/mitigation label when it
    is a code locator (file path, file:line, route path, or an extensionless
    config filename like Dockerfile). Idempotent; leaves prose, STRIDE tags, and
    already-backticked locators untouched. Only the locator is wrapped."""
    if not label or "(" not in label:
        return label
    m = re.search(r"\(([^()]+)\)\s*$", label)
    if not m:
        return label
    inner = m.group(1).strip()
    if "`" in inner:  # already formatted → idempotent
        return label
    looks_like_code = bool(_LOCATOR_TOKEN_RE.match(inner)) and (
        "." in inner or "/" in inner or "\\" in inner or ":" in inner or inner.lower() in _NOEXT_CODE_FILES
    )
    if not looks_like_code:
        return label
    return f"{label[: m.start()]}(`{inner}`){label[m.end() :]}"


def _strip_label_code(label: str) -> str:
    """Remove inline-code backticks from a label — for the TOC, which must carry
    no monospaced code (`updateProductReviews.ts:18` → updateProductReviews.ts:18)."""
    return label.replace("`", "") if label else label


def _code_token_is_embedded(seg: str, ms: int, me: int) -> bool:
    """True when the matched code token sits INSIDE a larger un-backticked
    expression / string literal / hyphenated word, where wrapping just this
    inner token produces broken partial formatting — e.g.
    ``btoa(...split('').`reverse()`.join(''))`` or ``admin@juice-`sh.op```.
    Such tokens stay plain prose (2026-06-02 user request — Story Card Issue
    code must not be half-backticked). Standalone tokens (space / paren-in-
    prose boundaries) are unaffected.
    """
    before = seg[ms - 1] if ms > 0 else " "
    after = seg[me] if me < len(seg) else " "
    # Preceded by a member-access dot, identifier underscore, or a hyphen that
    # joins it into a larger word/domain → it is a fragment, not a standalone.
    if before in "._-":
        return True
    # Wrapped in matching quotes → it is a string-literal fragment.
    if before in "'\"" and after in "'\"":
        return True
    return False


def _sub_outside_spans(pattern: re.Pattern[str], s: str, reject: Callable[[str], bool] | None = None) -> str:
    """Wrap `pattern` group(1) in backticks, but ONLY in the parts of `s`
    that are not already inside a backtick span / link target / HTML tag /
    entity. Prevents a later code matcher from re-wrapping a token inside a
    span an earlier matcher just created. Tokens that `_code_token_is_embedded`
    flags as mid-expression are left untouched (no partial backticking).

    ``reject`` is an optional fail-closed guard: when it returns True for a
    matched token, the token is left as prose (used to keep product names and
    prose abbreviations out of the ambiguous file / dotted matchers)."""

    def _wrap_seg(seg: str) -> str:
        def _repl(mm: re.Match[str]) -> str:
            if _code_token_is_embedded(seg, mm.start(1), mm.end(1)):
                return mm.group(0)
            if reject is not None and reject(mm.group(1)):
                return mm.group(0)
            return f"`{mm.group(1)}`"

        return pattern.sub(_repl, seg)

    out: list[str] = []
    pos = 0
    for m in _CODE_SPAN_MASK_RE.finditer(s):
        if m.start() > pos:
            out.append(_wrap_seg(s[pos : m.start()]))
        out.append(m.group(0))
        pos = m.end()
    if pos < len(s):
        out.append(_wrap_seg(s[pos:]))
    return "".join(out)


def _codify_inline_identifiers(text: str) -> str:
    """Wrap unmarked code identifiers (file paths, calls, dotted refs)
    in `backticks` so Story Card prose renders them as inline code.

    Skips text inside existing backticks and existing Markdown link
    targets so we never double-wrap or break links.
    """
    if not text:
        return text

    # Tokenise: keep already-quoted segments (backtick-spans and
    # parenthesised link targets) opaque, wrap only the prose runs in
    # between. This avoids double-wrapping `` `foo` `` → `` ``foo`` ``
    # and never edits a Markdown URL like `(https://example.com)`.
    parts: list[str] = []
    pos = 0
    span_re = re.compile(r"`[^`]+`|\]\([^)]+\)|<[^>]+>|&#\d+;")
    for m in span_re.finditer(text):
        if m.start() > pos:
            parts.append(text[pos : m.start()])  # prose run
            parts.append("\x00")  # marker
        parts.append(m.group(0))  # passthrough span
        pos = m.end()
    if pos < len(text):
        parts.append(text[pos:])
        parts.append("\x00")

    out_parts: list[str] = []
    for p in parts:
        if p == "\x00":
            continue
        if p.startswith("`") or p.startswith("](") or p.startswith("<") or p.startswith("&#"):
            out_parts.append(p)
            continue
        # Apply the four code matchers in priority order, but each one ONLY
        # outside spans already wrapped by an earlier matcher in this same
        # run. Without this, `_CODE_FILE_RE` wraps a full path
        # (`frontend/…/administration.component.html:26`) and then
        # `_CODE_DOTTED_RE` re-matches `component.html` INSIDE that fresh span,
        # producing mid-token backticks (`administration.`component.html`:26`).
        # The outer span mask only knows about backticks present before this
        # run; spans created here must be protected too.
        run = p
        # First fold whole code-signal string literals into one span so no
        # per-token matcher reaches inside a SQL query / concatenated
        # expression and half-backticks a column ref.
        run = _wrap_code_string_literals(run)
        # Two matchers are ambiguous and run fail-closed (positive-evidence
        # guard); the other three shapes are unambiguously code.
        run = _sub_outside_spans(_CODE_FILE_RE, run, reject=_file_token_is_product_name)
        run = _sub_outside_spans(_CODE_CALL_RE, run)
        run = _sub_outside_spans(_CODE_BARE_CALL_RE, run)
        run = _sub_outside_spans(_CODE_DOTTED_RE, run, reject=lambda t: not _dotted_token_is_code(t))
        run = _sub_outside_spans(_CODE_ENV_RE, run)
        out_parts.append(run)
    # Final pass: absorb un-backticked code that FLANKS an inline span the
    # author only partially wrapped (e.g. `foo.forEach((x) => { `bar(x)` })`).
    # The per-token matchers above deliberately skip non-empty-paren calls and
    # arrow functions, so a multi-statement expression would otherwise render
    # half-monospaced (juice-shop 2026-06-24 user report). `_balance_code_spans`
    # merges the whole balanced expression into one span.
    return _balance_code_spans("".join(out_parts))


_BRACKET_OPENERS = {"(": ")", "[": "]", "{": "}"}
_BRACKET_CLOSERS = {")": "(", "]": "[", "}": "{"}
# A flank between an inline span and the surrounding expression may carry only
# code-shaped characters; a natural-language word (≥2 letters, space-bounded on
# both sides and not glued to `.`/`(`/etc.) blocks the merge.
_FLANK_CODE_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") | set(
    ".(){}[]_$@/\\:'\"=>,;+-*%&|!? \t"
)
_FLANK_WORD_RE = re.compile(r"[A-Za-z][A-Za-z]+")
_FLANK_CALL_HEAD_RE = re.compile(r"[A-Za-z_$][\w$.]*\(")


def _flank_is_standalone_word(text: str, start: int, end: int) -> bool:
    """True when ``text[start:end]`` is an alphabetic word bounded by non-glue
    context on BOTH sides — i.e. prose, not a code identifier attached to
    ``.`` / ``(`` / ``)`` / ``_`` etc."""
    glue = set(".(){}[]_$@/\\:")
    before = text[start - 1] if start > 0 else " "
    after = text[end] if end < len(text) else " "
    return before not in glue and after not in glue


def _flank_balance(s: str) -> int:
    """Net unclosed-opener depth of ``s`` (positive = more openers), ignoring
    brackets inside single/double quotes."""
    depth = 0
    quote = None
    for ch in s:
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
        elif ch in _BRACKET_OPENERS:
            depth += 1
        elif ch in _BRACKET_CLOSERS:
            depth -= 1
    return depth


def _flank_boundary_left(text: str, end: int) -> int:
    """Leftmost index of the contiguous code flank ending at ``end`` (exclusive):
    walk left over code-shaped chars, then cut to just after the last standalone
    prose word so a sentence prefix is never swallowed."""
    i = end
    while i > 0 and text[i - 1] in _FLANK_CODE_CHARS:
        i -= 1
    cut = i
    for m in _FLANK_WORD_RE.finditer(text, i, end):
        if _flank_is_standalone_word(text, m.start(), m.end()):
            cut = m.end()
    while cut < end and text[cut] in " \t-:":
        cut += 1
    return cut


def _flank_boundary_right(text: str, start: int) -> int:
    """Exclusive end index of the contiguous code flank beginning at ``start``:
    walk right over code-shaped chars, then cut before the first standalone
    prose word so trailing narration is never swallowed."""
    i = start
    n = len(text)
    while i < n and text[i] in _FLANK_CODE_CHARS:
        i += 1
    end = i
    for m in _FLANK_WORD_RE.finditer(text, start, end):
        if _flank_is_standalone_word(text, m.start(), m.end()):
            cut = m.start()
            while cut > start and text[cut - 1] in " \t":
                cut -= 1
            return cut
    return end


def _balance_code_spans(text: str) -> str:
    """Absorb un-backticked code FLANKING an inline ``code`` span into one span
    when the author only partially wrapped a single bracketed expression — e.g.
    ``foo.forEach((x) => { `bar(x)` })`` → ``` `foo.forEach((x) => { bar(x) })` ```.

    Conservative + idempotent: fires only when the left flank opens brackets
    (and carries a call/arrow head) that the right flank closes around the span,
    so balanced standalone spans and ordinary prose are left untouched.
    """
    if text.count("`") < 2:
        return text
    spans = [(m.start(), m.end()) for m in re.finditer(r"`[^`]+`", text)]
    # Right-to-left so earlier indices stay valid as we splice.
    for a, b in reversed(spans):
        left_start = _flank_boundary_left(text, a)
        right_end = _flank_boundary_right(text, b)
        left = text[left_start:a]
        right = text[b:right_end]
        ld = _flank_balance(left)
        rd = _flank_balance(right)
        # Partial-wrap signature: left opens net brackets, right closes exactly
        # those, and the left flank is real code (a call/arrow head), not prose.
        if ld <= 0 or (ld + rd) != 0 or not _FLANK_CALL_HEAD_RE.search(left):
            continue
        inner = text[a + 1 : b - 1]
        merged = "`" + left.rstrip() + (" " if left.endswith(" ") else "") + inner + right.rstrip() + "`"
        trail = right[len(right.rstrip()) :]
        text = text[:left_start] + merged + trail + text[right_end:]
    return text


def _build_threat_card(
    t: dict,
    sev: str,
    taxonomy: dict[str, dict],
    components: dict,
    repo_root: Path | None,
    ctx: RenderContext,
    fid_to_walkthrough: dict[str, tuple[str, str]] | None = None,
    attack_taxonomy: dict | None = None,
) -> str:
    """Build the Story Card for the §8 ``Finding`` cell.

    Layout (single MD line — `<br>` separators inside, `&#124;` for `|`).
    Reflects the user-adopted security-finding template (R-7, 2026-05):

        **<Title — canonical weakness class + file:line>**
        **Component:** [C-NN](#c-nn) — <Component Name>
        **Location:** `<file:line>` · evidence: verified
        **Issue:** <attack narrative — 1-2 sentences, plain prose>
        **Attack Walkthrough:** [Walkthrough §3.N](#3n-…)          (Critical/High only; omitted when §3 is skipped)
        **Evidence:** <one-sentence prose summary of what the snippet shows>
        <details><summary>Evidence code · file:line</summary><pre>…</pre></details>
        **Impact:** <one-sentence consequence>                      (always rendered for Critical/High)
        **Fix:** [M-NNN](#m-nnn) — <mitigation title>
        **Classification:** [TH-NN — …](#th-nn) · [CWE-NNN](…) · [OWASP A0X:2021](…)

    Design choices (R-7 — replaces the R-5 / R-6 sequence):

      * **Component** is BOTH a labelled field at the top of the cell AND
        a separate table column. The duplication is intentional — the
        column gives at-a-glance scan; the in-cell label gives a stable
        anchor for the structured form that matches the user's reference
        template. R-6 removed the in-cell Component label; the user
        reverted that with R-7 and re-introduced it.
      * The legacy **Vektor** field was removed from the cell entirely.
        Reachability information (Repo-Read / Internet-Anon / …) still
        exists in `Appendix A — Vektor Taxonomy`; per-finding vektor data
        survives in the YAML for SARIF / pentest-tasks export. Inside the
        cell it added a fourth labelled row without changing remediation
        priority and pushed the Issue line below the fold.
      * **Evidence** now renders TWICE: once as a one-sentence prose
        summary that explains WHAT the snippet demonstrates, and once as
        the collapsible code excerpt. When the YAML carries an explicit
        ``evidence_summary`` / ``evidence_prose`` field, that text is
        used verbatim; otherwise the renderer synthesises a one-sentence
        fallback from the finding scenario. The fallback never invents
        content — it paraphrases the existing Issue prose so the reader
        sees `Evidence: <claim>` followed by the proof in the snippet.
      * **Impact** is ALWAYS rendered for Critical and High severity (the
        R-5 substring-dedup against Issue was producing empty Impact for
        ~90% of findings). At Medium/Low the dedup still applies because
        an empty Impact column is acceptable for lower-priority findings
        where the Issue text already conveys the consequence.
      * **Classification** uses the `**Classification:** TH-NN · CWE ·
        OWASP` LABEL form (R-7) — was italic-only `_TH · CWE · OWASP_`
        in R-5. The label keeps the line readable as part of the
        structured form rather than a citation footer.
      * Code snippets remain CWE-gated (``_FINDING_SKIP_SNIPPET_CWES``)
        and severity-gated (Critical/High by default; Medium opt-in via
        ``important_snippet: true``).
      * Title strips the redundant ``(file.ext)`` suffix — the file lives in
        the **Location** row immediately below; repeating it in the title
        is noise.
      * Scenario is sanitised before render: trailing ``[CWE-NNN](…)`` and
        ``[OWASP …](…)`` link tokens removed (those live in the
        Classification line), and the first N sentences are kept depending
        on severity.
      * The legacy ``**Root cause:**`` block was a CWE-template fallback
        that read as filler when accurate and as outright misinformation
        when the YAML carried a corrupt CWE field. Replaced by
        ``**Evidence:**``.
      * Old blockquote (``> ``) markers are dropped — Markdown blockquotes
        do not render inside table cells on GitHub, Pandoc PDF, or most
        VS-Code previewers.
    """
    depth = _FINDING_DEPTH.get(sev, _FINDING_DEPTH["medium"])

    # -- 1. Title — canonical `<weakness class> — <file:line>` form -------
    # Per user feedback (feedback_threat_model_finding_titles.md): titles
    # MUST be `<weakness class> — <file[:line]>` only — no library names,
    # payload snippets, or narrative fragments. `_canonical_finding_title`
    # looks up the threat's CWE in `_CWE_CLASS_NAMES` and combines it with
    # the evidence file:line. If CWE is unmapped, falls back to a short
    # noun phrase derived from the legacy narrative title (kept on a
    # best-effort basis so unmapped findings still render something).
    raw_title = _canonical_finding_title(t)
    if not raw_title:
        # Last-resort fallback — preserve old behaviour on findings with
        # neither CWE nor a usable existing title (extremely rare).
        raw_title = (t.get("title") or t.get("scenario_short") or "").strip()
        raw_title = _normalize_register_title(raw_title)
        if not raw_title:
            scenario_full = t.get("scenario") or ""
            raw_title = scenario_full.split(". ", 1)[0][:80] if scenario_full else "—"
    ec = (t.get("evidence_check") or "").strip().lower()

    # -- 1b. Component labelled row (R-7 — 2026-05 user request) ----------
    # The Component is BOTH a column AND an in-cell labelled field. The
    # duplication is intentional: the column gives at-a-glance scan; the
    # in-cell label is required so the cell reads as a complete structured
    # form matching the user's reference template. R-6 had removed the
    # in-cell label; R-7 reverts that and reintroduces it as the first
    # body field below the title.
    component_line = ""
    comp_id_raw = (t.get("component_id") or t.get("component") or "").strip()
    if comp_id_raw:
        # Resolve the canonical C-NN identifier so the in-cell link matches
        # the Component column (line 8767+) instead of leaking the raw slug.
        # Without this normalisation the cell renders
        # `[express-backend](#express-backend)` while the column carries
        # `[C-01 — Express.js Backend API](#c-01)` — two different anchors
        # for the same component.
        comp_meta = (components or {}).get(comp_id_raw) or {}
        canonical_id = comp_id_raw
        if re.match(r"^C-\d+$", comp_id_raw):
            pass  # already canonical
        elif comp_meta:
            canonical_id = comp_meta.get("_canonical_id") or comp_id_raw
        else:
            for cid_k, c in (components or {}).items():
                if re.match(r"^C-\d+$", cid_k) and (
                    c.get("_original_id") == comp_id_raw or (c.get("name") or "").strip() == comp_id_raw
                ):
                    canonical_id = cid_k
                    comp_meta = c
                    break
        comp_name = (comp_meta.get("name") or "").strip() if comp_meta else ""
        # 2026-05-29 (supersedes Item 5 / 2026-05-28): ALL Story-Card field
        # labels render in uniform **bold** — Component / Location / Issue /
        # Attack Walkthrough / Evidence / Impact / Fix / Classification. The
        # earlier mixed scheme (italic metadata + bold actionable fields) read
        # as inconsistent/unstructured; uniform bold matches the §8 intro
        # element list and the §9 Mitigation Register label style, giving the
        # cell a single, predictable visual grammar.
        if comp_name:
            component_line = f"**Component:** [{canonical_id}](#{canonical_id.lower()}) — {comp_name}"
        else:
            component_line = f"**Component:** [{canonical_id}](#{canonical_id.lower()})"

    # -- 2. Location labelled row -----------------------------------------
    # **Location:** stays as a labelled row (file:line).
    # **Evidence verdict** stays attached to **Location:** so the verified /
    # ambiguous status sits next to the file it applies to.
    # R-7 (2026-05): Vektor field removed from the cell entirely — it was
    # adding a fourth labelled row without changing remediation priority.
    # Vektor still exists in the YAML for SARIF / pentest-tasks export and
    # is documented in `Appendix A — Vektor Taxonomy`.
    ev = t.get("evidence") or {}
    ev_file = ""
    ev_line = None
    if isinstance(ev, dict):
        ev_file = (ev.get("file") or "").strip()
        ev_line = ev.get("line")
    elif isinstance(ev, list) and ev:
        first = ev[0] if isinstance(ev[0], dict) else {}
        ev_file = (first.get("file") or "").strip()
        ev_line = first.get("line")

    # Card layout: the evidence verdict renders as a glyph in the **Evidence:**
    # field (built below from ``ec``); the location is the meta line's
    # **Location:** part built from ``ev_file``/``ev_line``. No separate
    # location/status line is assembled here.

    # -- 2b. Attack walkthrough back-link (Critical/High only) ------------
    # When §3 Attack Walkthroughs covers this finding (via a chain in §3.1
    # or a per-finding sequenceDiagram in §3.2+), surface a direct link
    # back to the walkthrough. The map is built once per §8 render in
    # `_render_threat_register` and passed in via ``fid_to_walkthrough``.
    # Suppressed for Medium/Low because their findings are rarely covered
    # by walkthroughs (which target Critical/High kill-chains) — a missing
    # link would just be noise.
    walkthrough_line = ""
    if sev in ("critical", "high") and fid_to_walkthrough:
        fid_raw = (t.get("id") or t.get("t_id") or "").strip().upper()
        keys: list[str] = [fid_raw] if fid_raw else []
        m_t = re.match(r"^T-(\d+)$", fid_raw)
        m_f = re.match(r"^F-(\d+)$", fid_raw)
        if m_t:
            keys.append(f"F-{m_t.group(1)}")
        if m_f:
            keys.append(f"T-{m_f.group(1)}")
        for k in keys:
            hit = fid_to_walkthrough.get(k)
            if hit:
                label, anchor = hit
                walkthrough_line = f"**Attack Walkthrough:** [{label}](#{anchor})"
                break

    # -- 3. What the attacker does — cleaned scenario ---------------------
    # Three cleanups applied in order:
    #   1) strip trailing CWE/OWASP citation tokens (those duplicate the
    #      Refs line below);
    #   2) strip redundant `at <ev_file>:<line>` and leading `<ev_file>:N`
    #      patterns (the LOC line above already names the file);
    #   3) keep the first N sentences per severity depth.
    def _strip_inline_citations(text: str) -> str:
        text = re.sub(r"\s*\[CWE-\d+\]\([^)]*\)\s*", " ", text)
        text = re.sub(r"\s*\[OWASP\s+A?\d+[^\]]*\]\([^)]*\)\s*", " ", text)
        text = re.sub(r"(?<![A-Z])\bCWE-\d+\b\s*\.?", "", text)
        text = re.sub(r"\s{2,}", " ", text)
        return text.strip(" ,;.")

    def _strip_redundant_filepath(text: str, ev_file_arg: str) -> str:
        """Remove ``at <file>:<line>`` and leading ``<file>:<line>``
        patterns when they reference the evidence file already named in
        the LOC row. Conservative — only strips when the prefix matches
        the evidence file exactly (full path or basename)."""
        if not ev_file_arg:
            return text
        base = ev_file_arg.split("/")[-1]
        full_quoted = re.escape(ev_file_arg)
        base_quoted = re.escape(base)
        candidates = [full_quoted, base_quoted] if base != ev_file_arg else [full_quoted]
        for f_pat in candidates:
            # `at <file>:<line>` mid-sentence
            text = re.sub(
                rf"\s+at\s+{f_pat}(?::\d+)?(?=[\s,.;]|$)",
                "",
                text,
            )
            # Leading `<file>:<line> calls/uses/parses ...`
            text = re.sub(
                rf"^\s*{f_pat}(?::\d+)?\s+(calls|uses|parses|invokes|reads|writes|exposes|allows|passes|stores|returns|hardcodes|configures)\b",
                lambda m: m.group(1).capitalize(),
                text,
                count=1,
            )
        text = re.sub(r"\s{2,}", " ", text)
        return text.strip(" ,;.")

    scenario_full = (t.get("scenario") or "").strip()
    scenario_clean = _strip_inline_citations(scenario_full)
    scenario_clean = _strip_redundant_filepath(scenario_clean, ev_file)

    # Issue 1 (2026-05-28 follow-up): strip LLM-authored "Evidence: ..."
    # tails from the scenario. The STRIDE analyzer sometimes appends an
    # `Evidence: file:line (...), file:line (...)` clause at the end of
    # the scenario for traceability. The renderer's `impact_carve` logic
    # then picks the tail as Impact, producing useless rows like
    # `**Impact:** Evidence: lib/insecurity.ts:22 (private key literal),
    # ...`. The Evidence claim already renders in the **Evidence** line
    # above the code snippet; carrying it through the scenario is pure
    # duplication.
    #
    # Sentence-aware stripping is unreliable because the Evidence clause
    # routinely contains file paths with `.` that prematurely terminate
    # any naive `[^.!?]+\.` regex (e.g. `lib/insecurity.ts:22`). Strip
    # from the first `Evidence:` token to the end of the scenario
    # instead — anything after the marker is provenance, not narrative.
    _ev_strip_idx = re.search(r"(?:^|\s)Evidence:\s", scenario_clean, flags=re.IGNORECASE)
    if _ev_strip_idx:
        scenario_clean = scenario_clean[: _ev_strip_idx.start()].rstrip(" ,;.")
        if scenario_clean and not scenario_clean.endswith((".", "!", "?")):
            scenario_clean += "."

    # Split scenario into sentences so Issue and Impact draw from disjoint
    # slices. Without this carve-out the Impact line below picks the last
    # sentence of `scenario_clean`, and Issue (which keeps the first N
    # sentences per `scenario_sentences`) usually already contains it —
    # the cell then renders the same sentence twice under two labels.
    def _is_link_only_local(s: str) -> bool:
        stripped = re.sub(r"\[[^\]]+\]\([^)]+\)", "", s).strip(" .,;:!?-—·`*_")
        return len(stripped) < 10

    scenario_sentences = _safe_sentence_split(scenario_clean)
    has_explicit_impact = bool((t.get("impact_description") or t.get("impact_summary") or "").strip())
    impact_carve = ""
    if not has_explicit_impact and sev in ("critical", "high") and len(scenario_sentences) >= 2:
        for idx in range(len(scenario_sentences) - 1, 0, -1):
            cand = scenario_sentences[idx]
            if _is_link_only_local(cand):
                continue
            if len(cand.strip(" .,;:!?")) >= 12:
                impact_carve = cand
                scenario_sentences = scenario_sentences[:idx]
                break

    n_issue = max(1, depth["scenario_sentences"] - (1 if impact_carve else 0))
    issue_text = " ".join(scenario_sentences[:n_issue]).strip()
    scenario = issue_text
    if scenario and not scenario.endswith((".", "!", "?")):
        scenario += "."
    # Item 9 (2026-05-28): auto-wrap inline code identifiers in
    # backticks so file paths, function names, and dotted references
    # render as inline code instead of plain prose.
    scenario = _codify_inline_identifiers(scenario)
    issue_line = ""
    if scenario:
        issue_line = f"**Issue:** {scenario}"

    # -- 4. Evidence summary line + (optional) explicit root_cause --------
    # R-7 (2026-05): the **Evidence:** prose line is now ALWAYS rendered
    # for Critical/High severity findings that have an evidence file. The
    # text is a one-sentence prose summary describing WHAT the snippet
    # demonstrates — distinct from the **Issue:** attack narrative.
    #
    # Source priority:
    #   1. Explicit ``evidence_summary`` / ``evidence_prose`` YAML field
    #      (operator-authored; preserved verbatim).
    #   2. CWE-class fallback — a deterministic short claim derived from
    #      the CWE category (e.g. "Raw SQL string concatenation with
    #      user-controlled input is configured on this endpoint."). This
    #      is NOT CWE-template prose for the Issue field — it's a single
    #      claim about the code structure that the snippet visually proves.
    #
    # The R-5 rationale ("never synthesise from CWE templates") applied
    # to the legacy `**Root cause:**` block, which was a multi-sentence
    # narrative substitute. The R-7 fallback is a one-sentence proof
    # statement; it explicitly references the code structure visible in
    # the snippet on the next line.
    evidence_summary_explicit = (t.get("evidence_summary") or t.get("evidence_prose") or "").strip()
    evidence_line = ""
    if evidence_summary_explicit:
        text = _codify_inline_identifiers(evidence_summary_explicit)
        if not text.endswith((".", "!", "?")):
            text += "."
        evidence_line = f"**Evidence:** {text}"
    elif sev in ("critical", "high") and ev_file:
        # Synthesise a one-sentence claim from CWE class + file context.
        # The next-line snippet is the proof for this claim.
        fallback = _synthesise_evidence_summary(t, ev_file, ev_line)
        if fallback:
            if not fallback.endswith((".", "!", "?")):
                fallback += "."
            evidence_line = f"**Evidence:** {fallback}"

    # Explicit YAML ``root_cause`` (legacy schema) — used as the card's Root
    # cause fallback below when the attack-class lookup yields nothing.
    root_cause_explicit = (t.get("root_cause") or "").strip()

    # -- 5. Impact one-liner ----------------------------------------------
    # Sources, in order: explicit `impact_description` / `impact_summary`
    # field → last narrative sentence of full scenario that is not just a
    # citation token. Tokens-only sentences (e.g. "[CWE-693](…)") are
    # rejected so we never emit "**Impact:** [CWE-693]".
    def _is_link_only(s: str) -> bool:
        stripped = re.sub(r"\[[^\]]+\]\([^)]+\)", "", s).strip(" .,;:!?-—·`*_")
        return len(stripped) < 10

    impact_text = (t.get("impact_description") or t.get("impact_summary") or "").strip()
    if not impact_text and impact_carve:
        # Sentence we already carved out of `scenario` so Impact is the
        # consequence and Issue is the narrative, without overlap.
        impact_text = impact_carve
    if not impact_text:
        sentences = _safe_sentence_split(scenario_clean)
        for s in reversed(sentences):
            if _is_link_only(s):
                continue
            if len(s.strip(" .,;:!?")) >= 12:
                impact_text = s.strip()
                break
    impact_line = ""
    if impact_text:
        impact_text = _strip_inline_citations(impact_text)
        impact_text = re.sub(r"^[•\-\*]\s*", "", impact_text).strip(" ,;")
        # Issue 1 (2026-05-28 follow-up): reject impact candidates that
        # are clearly evidence prose, not consequence prose. An impact
        # line should answer "what does this enable for the attacker /
        # cost the defender", not enumerate evidence locations.
        if re.match(r"^\s*Evidence:\s+", impact_text, re.IGNORECASE):
            impact_text = ""
        # Item 9: auto-wrap inline code identifiers in backticks.
        if impact_text:
            impact_text = _codify_inline_identifiers(impact_text)

        # R-7 (2026-05): Impact is ALWAYS rendered for Critical/High,
        # even when it overlaps with the Issue prose. The R-5/iter-2
        # substring-dedup was eliminating Impact for ~90% of findings on
        # a typical assessment because LLM-authored `scenario` fields
        # tend to include the consequence inline. The user-adopted
        # template requires Impact as a separate structured field so the
        # reader sees `Issue:` (what happens) and `Impact:` (consequence)
        # as discrete signals. The dedup still applies for Medium/Low
        # severities because lower-priority findings can afford a more
        # compact cell — there `Issue` already implies the consequence
        # and a duplicated Impact line is noise.
        def _norm_cmp(s: str) -> str:
            return re.sub(r"\s+", " ", s.lower().strip(" .,;:!?-—·"))

        had_explicit_impact = bool((t.get("impact_description") or t.get("impact_summary") or "").strip())
        if impact_text and len(impact_text) >= 12:
            norm_impact = _norm_cmp(impact_text)
            norm_scenario = _norm_cmp(scenario)
            is_dup = False
            # Dedup applies (a) for Medium/Low impacts that overlap the
            # scenario — the original R-5 dedup, and (b) for ALL
            # severities when impact is *exactly* equal to issue.
            # Issue 2 (2026-05-28 follow-up): findings like CORS or FTP
            # directory listing were rendering Issue and Impact as the
            # same single sentence — pure duplication. The R-5 dedup
            # carved Critical/High out to keep Impact always rendering
            # for high-severity rows, but that left "Issue == Impact"
            # exact-duplicates running, which is the worst of both
            # worlds. Exact equality means the Impact line carries no
            # additional information at any severity.
            if sev not in ("critical", "high") and not had_explicit_impact:
                if norm_impact == norm_scenario or norm_impact in norm_scenario:
                    is_dup = True
            if not is_dup and norm_impact == norm_scenario:
                is_dup = True
            if is_dup:
                impact_line = ""
            else:
                if not impact_text.endswith((".", "!", "?")):
                    impact_text += "."
                impact_line = f"**Impact:** {impact_text}"

    # -- 6. CWE + mitigation links (used by the card's Fix + Classification) --
    # The card's **Fix:** line is assembled later (plain remediation lead via
    # `_fix_action_lead` → mitigation link); here we only normalise the CWE and
    # resolve the mitigation links.
    cwe_raw = (t.get("cwe") or "").strip()
    cwe_norm = cwe_raw if cwe_raw.upper().startswith("CWE-") else (f"CWE-{cwe_raw}" if cwe_raw.isdigit() else cwe_raw)
    mit_ids = t.get("mitigation_ids") or t.get("mitigations") or []
    mit_links = [ctx.linkify_with_label(mid) for mid in mit_ids[:2]]

    # -- 7. Classification (TH-NN · CWE · OWASP) --------------------------
    # R-5 (2026-05 user request): renamed from the legacy italicised
    # ``_TH · CWE · OWASP_`` reference line to a labelled
    # ``**Classification:**`` row so it reads as part of the structured
    # form rather than a citation footer. The links themselves are
    # unchanged.
    cat_id = t.get("_category", "") or ""
    cat_meta = taxonomy.get(cat_id, {})
    cat_title = cat_meta.get("title") or ""
    refs_parts: list[str] = []
    # Item 7 (2026-05-28): the TH-NN identifier + anchor link were noisy
    # filler — the threat-category anchors are dead targets, and the
    # `[TH-03 — Cryptographic Failures](#th-03)` form bolted a useless
    # ID onto an otherwise descriptive label. We keep the classification
    # NAME (the part the reader actually needs) and drop the bracket
    # link + ID prefix. CWE and OWASP links remain — those point to
    # external authoritative pages.
    if cat_id:
        if cat_title:
            refs_parts.append(cat_title)
        # else: omit — no useful text left without an anchor target.
    if cwe_norm:
        cwe_num = cwe_norm.split("-", 1)[-1] if "-" in cwe_norm else cwe_norm
        refs_parts.append(f"[CWE-{cwe_num}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)")
    owasp_ref = cat_meta.get("owasp_top10_2021") or ""
    if owasp_ref:
        refs_parts.append(f"[OWASP {owasp_ref}:2021](https://owasp.org/Top10/{owasp_ref}_2021/)")
    classification_line = ""
    if refs_parts:
        # Item 5: classification label is italic, not bold — the
        # actionable triad (Issue / Impact / Fix) carries bold weight;
        # reference citations sit one notch quieter.
        classification_line = "**Classification:** " + " · ".join(refs_parts)

    # -- 8. Code snippet — collapsed in <details> -------------------------
    # Severity-tier policy (post-2026-05):
    #   Critical / High   → snippet on (subject to CWE skip-list)
    #   Medium            → snippet only when YAML opts in via
    #                       `important_snippet: true` — most Medium findings
    #                       are configuration / boundary issues where 3-5
    #                       lines of surrounding code add noise, not signal
    #   Low               → snippet off (already gated by snippet_context=0)
    important_snippet = bool(t.get("important_snippet"))
    snippet_severity_ok = sev in ("critical", "high") or important_snippet
    snippet_relevant = (
        depth["snippet_context"] > 0
        and bool(ev_file)
        and bool(ev_line)
        and bool(repo_root)
        and cwe_norm.upper() not in _FINDING_SKIP_SNIPPET_CWES
        and snippet_severity_ok
    )
    # Card layout: the evidence proof renders as a normal fenced code block
    # (a few lines, not a <details> fold — see threatdemo.md). No table-cell
    # `&#10;` encoding is needed since a card is a markdown block, not a cell.
    snippet_block = ""
    if snippet_relevant:
        snippet_text = _read_evidence_snippet(repo_root, ev_file, ev_line, depth["snippet_context"])
        if snippet_text:
            lang = (_lang_class_for_file(ev_file) or "").replace("language-", "")
            snippet_block = f"```{lang}\n// {ev_file}:{ev_line}\n{snippet_text}\n```"

    # ---- Assemble the card (threatdemo.md layout) -----------------------
    # Fixed field order, every card identical:
    #   #### F-NNN · Title
    #   **Severity:** … · **Component:** … · **Location:** …
    #   **Issue:** …
    #   **Root cause:** …
    #   **Evidence:** <glyph> <status> — … (+ fenced snippet)
    #   **Fix:** <plain remediation> → [M-NNN]
    #   **Classification:** Category · [CWE](…) · [OWASP](…) [· walkthrough]
    tid = (t.get("t_id") or t.get("id") or "-").strip()
    m_id = re.match(r"^T-(\d+)$", tid, re.IGNORECASE)
    digits = m_id.group(1) if m_id else None
    visible_id = f"F-{digits}" if digits else tid
    anchors = f'<a id="{tid.lower()}"></a>' + (f'<a id="f-{digits}"></a>' if digits else "")

    # Heading title = canonical class label without a single-location suffix
    # (multi-instance findings already have no suffix). Refuted candidates are
    # removed before composition and never render in the active register.
    head_title = re.sub(r"\s+—\s+\S.*$", "", raw_title).strip() or raw_title
    heading = f"#### {visible_id} · {_escape_heading_placeholders(head_title)}"

    # Meta line — Severity · Component · Location.
    sev_disp = f"{ctx.severity_emoji(sev)} {ctx.severity_label(sev)}".strip()
    # Optional in-place rationale when the rating sits ABOVE the usual class
    # baseline — e.g. a hardcoded key elevated to Critical because it is
    # committed to a public repo, or a mass-assignment promoted to Critical
    # because it reaches a privileged field on an unauthenticated endpoint.
    # Populated deterministically by emit_severity_rationale.py; kept short so
    # the meta line stays scannable. Gated on presence → no-op when absent.
    _sev_rat = (t.get("severity_rationale") or "").strip()
    if _sev_rat:
        sev_disp += f" — {_sev_rat}"
    if (t.get("impact") or "").strip().lower() == "critical" and sev != "critical":
        sev_disp += " _(raw Critical)_"
    comp_part = component_line[len("**Component:** ") :] if component_line.startswith("**Component:** ") else "—"
    # A consolidated finding has no canonical representative location. Its
    # Instances row below is the complete location evidence; naming the first
    # evidence hit here duplicates and over-emphasises it.
    _instance_pairs = _distinct_instance_locations(t)
    if len(_instance_pairs) > 1:
        loc_part = f"Multiple locations ({len(_instance_pairs)})"
    else:
        # Keep file AND line inside ONE code span (`lib/insecurity.ts:58`) — the
        # earlier form ``` `file`:line ``` left the line number bare outside the
        # backticks (user report 2026-06-12).
        loc_part = (f"`{ev_file}" + (f":{ev_line}" if ev_line else "") + "`") if ev_file else "—"
    meta_line = f"**Severity:** {sev_disp}  ·  **Component:** {comp_part}  ·  **Location:** {loc_part}"

    # Instances — for a systemic finding consolidated from N per-file / per-stage
    # hits of one config check (see merge_threats._consolidate_config_checks),
    # surface every hit so the single card still names all affected locations.
    instances_card = ""
    if len(_instance_pairs) > 1:
        if _instance_pairs:
            _distinct_sevs = {severity for _, _, severity in _instance_pairs if severity}
            _mixed = len(_distinct_sevs) > 1
            _cap = 8
            _shown_pairs = _instance_pairs[:_cap]
            _shown = [
                (
                    f"{_SEV_ICON_TBL.get(severity, '')} "
                    f"`{file}:{line}`".strip()
                    if _mixed and severity
                    else (f"`{file}:{line}`" if line else f"`{file}`")
                )
                for file, line, severity in _shown_pairs
            ]
            _tail = f" … (+{len(_instance_pairs) - _cap} more)" if len(_instance_pairs) > _cap else ""
            instances_card = f"**Instances ({len(_instance_pairs)}):** " + ", ".join(_shown) + _tail

    # Root cause — Option 3 (2026-07-13): the attack-class taxonomy description
    # is TIER-GENERIC — the identical sentence repeats across every finding of a
    # class (in the reference report, 5 distinct strings across 38 findings) and
    # carries no finding-specific information; worse, the tier bucket sometimes
    # mismatches the finding (a plaintext-logging finding stamped with the
    # SSRF/path-handling sentence). It is dropped. Only a finding-authored
    # ``root_cause`` (specific by construction) survives.
    root_cause = root_cause_explicit
    if root_cause:
        root_cause = root_cause[0].upper() + root_cause[1:]
    root_card = f"**Root cause:** {root_cause}" if root_cause else ""

    # Evidence — status glyph + one-sentence prose; the fenced snippet (if any)
    # follows on its own lines.
    ev_glyph = {
        "verified": "✓",
        "verified-prior": "✓",
        "ambiguous": "◌",
        "carried-unverified-shallower-depth": "↻",
    }.get(ec, "")
    ev_word = {
        "verified": "verified",
        "verified-prior": "verified",
        "ambiguous": "ambiguous",
        "carried-unverified-shallower-depth": "carried, unverified at this depth",
    }.get(ec, "")
    ev_prose = evidence_line[len("**Evidence:** ") :] if evidence_line.startswith("**Evidence:** ") else ""
    # The Location is already in the meta line — drop any redundant
    # `(\`file:line\`)` parenthetical the evidence summary appended.
    ev_prose = re.sub(r"\s*\(`[^`]*`\)", "", ev_prose).strip()
    ev_parts: list[str] = []
    if ev_glyph:
        ev_parts.append(f"{ev_glyph} {ev_word}")
    # Option 3 (2026-07-13): when a code snippet follows, the snippet IS the
    # proof — restating it as a SYNTHESISED Evidence sentence (a paraphrase of
    # Issue derived from the CWE class) only adds length, so it is dropped and
    # only the one-line verdict glyph (a confidence signal, not redundant)
    # remains. Operator-authored ``evidence_summary`` is intentional content and
    # is preserved even with a snippet; findings without a snippet keep whatever
    # prose they have, since it is then the only evidence text.
    if ev_prose and (not snippet_block or evidence_summary_explicit):
        ev_parts.append(ev_prose)
    evidence_card = ("**Evidence:** " + " — ".join(ev_parts)) if ev_parts else ""

    # Fix — remediation in a few plain words, then the mitigation link(s).
    _lead_raw = _fix_action_lead(cwe_norm)
    lead = _codify_inline_identifiers(_lead_raw) if _lead_raw else ""
    if mit_links:
        fix_card = "**Fix:** " + (f"{lead} → " if lead else "") + " · ".join(mit_links)
    elif lead:
        fix_card = f"**Fix:** {lead} → _not yet mapped ([§10](#10-mitigation-register))_"
    else:
        fix_card = "**Fix:** _no mitigation mapped — see [§10](#10-mitigation-register)_"

    # Classification — category + external CWE/OWASP links + optional
    # walkthrough tail (classification_line already carries the linked refs).
    classification_card = classification_line
    if walkthrough_line.startswith("**Attack Walkthrough:** "):
        wt = walkthrough_line[len("**Attack Walkthrough:** ") :]
        classification_card = (classification_card or "**Classification:**") + f" · walkthrough {wt}"

    # The card has no separate Impact field — fold the carved consequence
    # back into the Issue line so it is never lost (see threatdemo.md).
    issue_card = issue_line
    if impact_line.startswith("**Impact:** "):
        imp_txt = impact_line[len("**Impact:** ") :].strip()
        if imp_txt and imp_txt.rstrip(" .").lower() not in (issue_card or "").lower():
            if issue_card:
                if not issue_card.rstrip().endswith((".", "!", "?")):
                    issue_card = issue_card.rstrip() + "."
                issue_card = f"{issue_card} {imp_txt}"
            else:
                issue_card = f"**Issue:** {imp_txt}"

    # Readability (2026-06-12): a long Issue narrative crammed into one ~1000-char
    # paragraph is hard to follow. Break it into ~2-sentence paragraphs so the
    # mechanism / consequence / impact read as distinct beats. Blank-line
    # separated (same paragraph mechanic the fields use below), so it survives
    # GFM / Pandoc / weasyprint. No-op for short Issues.
    issue_card = _paragraphize_issue_card(issue_card)

    # Each field is a separate paragraph (blank-line separated), exactly like
    # the §9 Mitigation-Register blocks. A single newline would NOT survive
    # CommonMark / Pandoc / weasyprint (the PDF path) — soft breaks there
    # collapse adjacent lines into one paragraph. Blank lines render correctly
    # in GFM, Pandoc and weasyprint alike.
    fields = [meta_line]
    if instances_card:
        fields.append(instances_card)
    if issue_card:
        fields.append(issue_card)
    if root_card:
        fields.append(root_card)
    if evidence_card:
        fields.append(evidence_card)
    if snippet_block:
        fields.append(snippet_block)
    if fix_card:
        fields.append(fix_card)
    if classification_card:
        fields.append(classification_card)
    return f"{anchors}\n{heading}\n\n" + "\n\n".join(fields)


# Signals live in the recon signal-set; the self-registration state, however, is
# resolved into `meta` (detect_open_registration.py), not emitted as a signal.
# The Identified Actors table folds on meta, so alias the rule's condition_signal
# to its meta key here. Keep in sync with the reach_equivalence_rules note in
# data/actors/default-library.yaml.
_ACTOR_FOLD_SIGNAL_TO_META = {"has_open_self_registration": "open_user_registration"}


def _actor_fold_map(active_ids: set[str], meta: dict) -> tuple[dict[str, str], dict[str, str]]:
    """Map non-primary active actors → their primary per default-library
    reach_equivalence_rules, so the Identified Actors table lists each trust
    position once and stays consistent with the collapsed Figure.

    A rule folds when `always: true` or when the meta flag aliased from its
    `condition_signal` is truthy. Both the primary and the child must be active
    for the fold to apply (a disabled/inactive actor is never a fold target).

    Returns (folded_into, fold_reason): child_id → primary_id and child_id → reason.
    """
    lib_path = PLUGIN_ROOT / "data" / "actors" / "default-library.yaml"
    try:
        rules = (yaml.safe_load(lib_path.read_text(encoding="utf-8")) or {}).get("reach_equivalence_rules") or []
    except (OSError, yaml.YAMLError):
        return {}, {}
    folded: dict[str, str] = {}
    reason: dict[str, str] = {}
    for rule in rules:
        fires = bool(rule.get("always"))
        if not fires:
            meta_key = _ACTOR_FOLD_SIGNAL_TO_META.get(rule.get("condition_signal"), rule.get("condition_signal"))
            fires = bool(meta.get(meta_key))
        if not fires:
            continue
        ids = rule.get("actor_ids") or []
        primary = rule.get("primary_actor") or (ids[0] if ids else None)
        if not primary or primary not in active_ids:
            continue
        for aid in ids:
            if aid == primary or aid not in active_ids:
                continue
            # Resolve to the root primary in case rules chain (A→B, B→C).
            root, guard = primary, set()
            while root in folded and root not in guard:
                guard.add(root)
                root = folded[root]
            folded[aid] = root
            reason[aid] = rule.get("collapse_reason") or ""
    return folded, reason


def _render_identified_actors(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """Threat Actors — §1 table over the SAME consolidated actor taxonomy the
    Management Summary uses (the posture actors that drive the numbered attack
    paths), NOT the raw ACT-* discovery library.

    The set is derived from each finding's ``vektor`` — identical to the MS
    "Threat actors" legend by construction — and the public-repo collapse
    (``repo-read`` → ``internet-anon``, mirroring ``_collapse_public_repo_actors``)
    is applied the same way, so §1 and the Management Summary never disagree on
    who the actors are. Per-actor finding counts and components add the detail
    the MS legend omits.

    The earlier ACT-* library table (2026-07-05 user request) is gone: it
    introduced actors absent from the MS (insider-dev / supply-chain /
    physical-device) and carried process-only sub-subsections (Consolidated /
    Disabled / proposed / flagged) that were noise in a delivered report.
    Renders nothing when no finding carries a vektor (legacy runs).
    """
    threats = ctx.yaml_data.get("threats") or []
    public_repo = bool((ctx.yaml_data.get("meta") or {}).get("public_source_repo"))

    counts: dict[str, int] = {}
    components: dict[str, set[str]] = {}
    for t in threats:
        if not isinstance(t, dict):
            continue
        vek = (t.get("vektor") or "").strip()
        if not vek:
            continue
        # A committed secret in a PUBLIC repo is readable by any anonymous
        # attacker, so the repo-reader folds into internet-anon — the same
        # collapse the MS figures apply (_collapse_public_repo_actors).
        if public_repo and vek == "repo-read":
            vek = "internet-anon"
        counts[vek] = counts.get(vek, 0) + 1
        comp = (t.get("component") or "").strip()
        if comp:
            components.setdefault(vek, set()).add(comp)

    if not counts:
        return ""

    labels = _load_posture_actor_labels() or {}
    actor_meta = labels.get("actors") or {}
    order = labels.get("order") or []
    present = [a for a in order if a in counts] + sorted(a for a in counts if a not in order)

    lines: list[str] = ['<a id="identified-actors"></a>', "### Identified Actors", ""]
    lines.append(
        "The consolidated threat actors that drive this model — the same set named "
        "in the Management Summary. Each row aggregates the findings reachable from "
        "that actor's position; the **Shop User** appears as the *victim* of "
        "client-side attacks, not an attacker."
    )
    lines.append("")
    lines.append("| Actor | Role | Reach | Findings | Components |")
    lines.append("|---|---|---|---|---|")
    for a in present:
        m = actor_meta.get(a) or {}
        name = m.get("label") or _FIG1_ACTOR_LABEL.get(a) or a
        role = "victim" if (m.get("role") == "victim" or a == "victim-required") else "attacker"
        reach = m.get("default_subtitle") or "—"
        comps = ", ".join(sorted(components.get(a, set()))) or "—"
        lines.append(f"| {name} | {role} | {reach} | {counts.get(a, 0)} | {comps} |")
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


_POSTURE_VERDICT_EMOJI = {"VIOLATED": "🔴", "WEAK": "🟠", "ADEQUATE": "🟢"}


def _render_security_principles(ctx: RenderContext) -> str:
    """P4 — the systemic posture verdict: per security principle a deterministic
    VIOLATED / WEAK / ADEQUATE row fused from the weakness register + confirmed
    findings + implementation strategy (build_posture_verdict). Answers
    "incidental bugs vs. systemically broken".

    Hoisted 2026-07-13 from §8 into the Management Summary as the
    `### Security Principles` subsection, so a systemically-violated principle —
    e.g. Access Control or Input Validation — is loud at executive level even
    when no single concrete instance carries it; §8 keeps only a back-reference
    (see `_render_threat_register`). Gated on the weakness register: no register
    (pre-P1 data / clean repo) → "" → goldens unchanged.
    """
    # Gated on the weakness register: the systemic verdict is Layer-2 on top of
    # the two-type register. No register (pre-P1 data) → no table → goldens
    # unchanged.
    if not (ctx.yaml_data.get("weaknesses") or []):
        return ""
    try:
        rows = _build_posture_verdict(ctx.yaml_data)
    except Exception:  # noqa: BLE001 — never let the verdict crash the render
        rows = []
    if not rows:
        return ""
    out: list[str] = ["### Security Principles", ""]
    # Lead: name the systemically-VIOLATED principles up front so the executive
    # reader sees "Access Control is broken by design" without reading the table.
    violated = [str(r.get("label")) for r in rows if r.get("verdict") == "VIOLATED"]
    if violated:
        if len(violated) == 1:
            subj = f"**{violated[0]}** is"
        else:
            subj = ", ".join(f"**{v}**" for v in violated[:-1]) + f" and **{violated[-1]}** are"
        out.append(
            f"{subj} **systemically violated** — the weakness recurs across the "
            "architecture, not as an isolated finding. This is the report's "
            "**Systemic Posture**: each principle below is scored deterministically "
            "from the findings that exercise it."
        )
    else:
        out.append(
            "This is the report's **Systemic Posture**: each principle below is "
            "scored deterministically from the findings that exercise it — none "
            "is systemically violated."
        )
    out.append("")
    out.append(
        "**VIOLATED** = a confirmed exploit or a pervasive home-grown/absent "
        "control · **WEAK** = isolated deviations · **ADEQUATE** = no confirmed "
        "gap; a standard control in use. Evidence and scope are in the "
        "[Systemic Weaknesses](#systemic-weaknesses) chapter."
    )
    out.append("")
    out.append("| Principle | Verdict | Signal |")
    out.append("|---|---|---|")
    for r in rows:
        emoji = _POSTURE_VERDICT_EMOJI.get(r.get("verdict"), "")
        refs = ", ".join(f"[{wid}](#{str(wid).lower()})" for wid in (r.get("weakness_ids") or []))
        signal = " · ".join(r.get("drivers") or []) or "—"
        if refs:
            signal += f" · Weaknesses: {refs}"
        out.append(f"| {r.get('label')} | {emoji} {r.get('verdict')} | {signal} |")
    out.append("")
    return "\n".join(out)


def _render_systemic_weaknesses(ctx: RenderContext) -> str:
    """Render the central, evidence-backed W-register.

    Weaknesses are assessment conclusions, not duplicate finding cards.  They
    can be evidenced by confirmed findings, observed unsafe practice, or an
    absent architectural control; only the first kind represents an exploit.
    """
    weaknesses = ctx.yaml_data.get("weaknesses") or []
    if not weaknesses:
        return ""
    _basis_rank = {"design-risk": 0, "confirmed": 1}
    _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def _sort_key(w: dict) -> tuple:
        return (
            _sev_rank.get((w.get("severity") or "").strip().lower(), 9),
            _basis_rank.get((w.get("severity_basis") or "").strip().lower(), 9),
            w.get("id") or "",
        )

    out: list[str] = ["## Systemic Weaknesses", ""]
    out.append(
        "These are evidence-backed security-control conclusions. They do not "
        "duplicate the Findings Register: confirmed findings are one evidence "
        "type; observed unsafe practice and absent controls can establish a "
        "weakness without a confirmed exploit. Only confirmed findings may carry CVSS."
    )
    out.append("")
    for w in sorted(weaknesses, key=_sort_key):
        emoji = ctx.severity_emoji((w.get("severity") or "").strip().lower())
        kind = (w.get("kind") or "").strip()
        basis = (w.get("severity_basis") or "").strip()
        statement = (w.get("statement") or "").strip()
        # Anchor so a Top Findings design-risk row [W-NNN](#w-nnn) resolves here.
        wid = (w.get("id") or "").strip().lower()
        anchor = f'<a id="{wid}"></a>' if wid else ""
        strat = (w.get("implementation_strategy") or "").strip()
        facets = f"{kind} · {basis}" + (f" · {strat}" if strat else "")
        title = (w.get("title") or statement or "Security control weakness").strip()
        line = f"### {anchor}{emoji} {wid.upper()} — {title}"
        out.extend([line, "", f"**Assessment basis:** {facets}."])
        if statement and statement != title:
            out.extend(["", statement])
        inst_links = []
        for i in w.get("instances") or []:
            iid = (i.get("id") or "").strip().upper()
            m = re.search(r"(\d+)$", iid)
            if m:
                n = m.group(1)
                inst_links.append(f"[F-{n}](#f-{n})")
        tail: list[str] = []
        if inst_links:
            tail.append("**Confirmed findings:** " + ", ".join(inst_links))
        backing = w.get("observable_backing") or {}
        practice = backing.get("practice_evidence") or []
        if practice:
            locations = []
            for item in practice[:5]:
                if not isinstance(item, dict):
                    continue
                path = (item.get("file") or "").strip()
                line_no = item.get("line")
                if path:
                    locations.append(f"`{path}{f':{line_no}' if line_no else ''}`")
            shown = ", ".join(locations) or f"{len(practice)} site(s)"
            if len(practice) > 5:
                shown += f" (+{len(practice) - 5} more)"
            tail.append(f"**Observed practice:** {shown}")
        absent = backing.get("absent_control_signal") or []
        if absent:
            labels = []
            for item in absent[:4]:
                if isinstance(item, str):
                    labels.append(item)
                elif isinstance(item, dict):
                    labels.append(str(item.get("control") or item.get("pattern") or "control signal"))
            shown = ", ".join(labels) or f"{len(absent)} control signal(s)"
            if len(absent) > 4:
                shown += f" (+{len(absent) - 4} more)"
            tail.append(f"**Architecture evidence:** {shown}")
        comps = w.get("affected_components") or []
        if comps:
            tail.append("**Affected components:** " + ", ".join(comps))
        if tail:
            out.extend(["  ", "<br/>".join(tail)])
        out.append("")
    out.append("")
    return "\n".join(out)


def _render_threat_register(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """Render §8 Findings Register in the canonical 8.A/B/C/D layout.

    Structure:
      * Header: Risk Distribution + STRIDE Coverage + Category Distribution
      * 8.A Categories at a glance      — category-level summary table
      * 8.B Critical Categories (N)     — per-TH sub-sections with findings
      * 8.C High Categories (N)
      * 8.D Medium Categories (N)
      * 8.E Low Categories (N)          — only when non-empty
      * 8.F Compound Attack Chains      — from LLM fragment (conditional)
      * 8.G Architectural Findings      — from LLM fragment (conditional)

    The four severity tiers used to share a single ``8.B`` label, which
    produced duplicate-anchor headings (``#8b-critical-categories`` /
    ``#8b-high-categories`` / …) — the right-side TOC outlines could only
    distinguish them by suffix. Each tier now gets its own letter (B–E)
    and a unique anchor.
    """
    threats = ctx.yaml_data.get("threats") or []
    # Issue 3 (2026-05-28 follow-up): drop self-declared duplicate
    # threats whose scenario explicitly cross-references another
    # surviving threat (e.g. `"Duplicate of T-001 — config-scan
    # detection of hardcoded RSA key"`). These rows are config-scan
    # detections of the same root finding that the STRIDE analyzer
    # already authored; the threat-merger left them through because
    # its similarity scoring does not bridge stride↔config-scan sources
    # even when the same file:line is cited. Filtering at render time
    # is the conservative fix — the YAML still carries every threat
    # for SARIF/pentest-tasks downstream, but §8 shows each weakness
    # once.
    threat_ids = {(t.get("id") or t.get("t_id") or "").strip().upper() for t in threats}
    _dup_ref_re = re.compile(r"^\s*Duplicate of \[?(T-\d+)\]?", re.IGNORECASE)
    deduped: list[dict] = []
    for t in threats:
        scenario = (t.get("scenario") or "").strip()
        m = _dup_ref_re.match(scenario)
        if (
            m
            and m.group(1).upper() in threat_ids
            and m.group(1).upper() != ((t.get("id") or t.get("t_id") or "").strip().upper())
        ):
            continue
        deduped.append(t)
    threats = deduped
    # Coverage-gap entries are OWASP-category placeholders injected when no
    # STRIDE finding covers a category. They carry no code evidence and must
    # not appear as F-numbered findings in §8; they belong in the §10
    # coverage-gap section. Filter them out here so the §8 count and index
    # reflect only real, evidence-backed findings.
    _COVERAGE_GAP_SOURCES = {"coverage-gap", "architectural-anti-pattern"}
    threats = [t for t in threats if t.get("source") not in _COVERAGE_GAP_SOURCES]
    # P1.4 anti-duplication: an insecure-practice site folded under a weakness's
    # `practice_evidence` must NOT also render as a standalone §8 finding card
    # ("never three peers"). Drop those rows when the weakness register exists;
    # they remain visible under their weakness heading and in SARIF/pentest.
    if ctx.yaml_data.get("weaknesses"):
        threats = [t for t in threats if t.get("evidence_tier") != "insecure-practice"]
    # Tracks whether any row was carried forward from a prior deeper scan
    # without re-verification (incremental depth-downgrade). Drives a
    # depth-independent §8 footnote — unlike the quick-only banner line, this
    # surfaces carried findings on a standard re-scan that downgraded from
    # thorough too.
    has_carried_unverified = False
    # Load threat-category taxonomy once (via module-level cache).
    tax_raw = _load_taxonomy("threat-category-taxonomy.yaml")
    taxonomy: dict[str, dict] = {
        c["id"]: c for c in (tax_raw.get("categories") or []) if isinstance(c, dict) and c.get("id")
    }

    # Assign each threat a category (TH-NN) via the shared heuristic in
    # infer_threat_category — same routine used by Top Findings, so a given
    # threat always lands under the same TH-NN anchor in both places.
    for t in threats:
        t["_category"] = infer_threat_category(t, taxonomy)

    # §3 Attack-Walkthrough back-link map (built once per render). Maps
    # F-NNN / T-NNN → (link_label, anchor) so the §8 Story Card can surface
    # a direct link to the §3.1 chain or §3.2+ sequenceDiagram covering
    # that finding. Empty dict when `.fragments/attack-walkthroughs.md` is
    # missing — the cell just omits the line.
    fid_to_walkthrough = _build_finding_to_chain_map(ctx)

    # Severity + STRIDE aggregates.
    # `info` is canonical (severity-taxonomy.yaml key); `informational` is the
    # schema enum value (threat-model.output.schema.yaml). Alias them so the
    # §8 opener's Total matches the STRIDE Coverage sum below (the historic
    # 43-vs-41 invariants drift was Informational threats being silently
    # excluded from `counts` while still counted in stride_map).
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for t in threats:
        sev = (t.get("risk") or t.get("severity") or "").strip().lower()
        if sev == "informational":
            sev = "info"
        if sev in counts:
            counts[sev] += 1
    total = sum(counts.values())

    stride_map = {"spoofing": 0, "tampering": 0, "repudiation": 0, "info_disclosure": 0, "dos": 0, "elev_priv": 0}
    stride_aliases = {
        "spoofing": "spoofing",
        "tampering": "tampering",
        "repudiation": "repudiation",
        "information disclosure": "info_disclosure",
        "information_disclosure": "info_disclosure",
        "info disclosure": "info_disclosure",
        "denial of service": "dos",
        "denial_of_service": "dos",
        "elevation of privilege": "elev_priv",
        "elevation_of_privilege": "elev_priv",
    }
    for t in threats:
        s = (t.get("stride") or t.get("stride_category") or "").strip().lower()
        key = stride_aliases.get(s)
        if key:
            stride_map[key] += 1

    # Group threats by category (TH-NN).
    cats_active: dict[str, list] = {}
    for t in threats:
        cats_active.setdefault(t["_category"], []).append(t)

    # Compute effective severity per category = highest severity among findings.
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def cat_eff_severity(cat_id: str) -> str:
        bucket = cats_active.get(cat_id, [])
        if not bucket:
            return "low"
        return min(
            ((t.get("risk") or t.get("severity") or "low").lower() for t in bucket),
            key=lambda s: sev_rank.get(s, 99),
        )

    # Category Distribution line.
    cat_sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for cid in cats_active:
        s = cat_eff_severity(cid)
        if s in cat_sev_counts:
            cat_sev_counts[s] += 1
    cat_active_total = len(cats_active)
    cat_taxonomy_total = len(taxonomy) or cat_active_total

    # Build lookups.
    components = _component_lookup(ctx)
    mitigations = _mitigation_lookup(ctx)

    lines: list[str] = []
    lines.append(section["heading"])
    lines.append("")
    lines.append(
        "Findings are grouped by severity (Critical → High → Medium → Low); "
        "within a tier they are ordered by attack vektor (Repo-Read → "
        "Internet-Anon → Internet-User → Victim-Required). Each finding is a "
        "card with the same fixed fields, in order: **Severity · Component · "
        "Location** → **Issue** → **Root cause** → **Evidence** → **Fix** → "
        "**Classification** (with external CWE / OWASP links)."
    )
    lines.append("")
    # Risk Distribution: always show Critical/High/Medium/Low; show Info
    # only when at least one Informational threat is present (keeps the
    # opener tight for the common case while keeping the sum honest when
    # Info threats exist).
    rd_parts = [
        f"🔴 Critical: {counts['critical']}",
        f"🟠 High: {counts['high']}",
        f"🟡 Medium: {counts['medium']}",
        f"🟢 Low: {counts['low']}",
    ]
    if counts.get("info", 0) > 0:
        rd_parts.append(f"⚪ Info: {counts['info']}")
    lines.append("**Risk Distribution:** " + " · ".join(rd_parts) + f" · **Total findings: {total}**")
    lines.append(
        f"**STRIDE Coverage:** Spoofing: {stride_map['spoofing']} · "
        f"Tampering: {stride_map['tampering']} · Repudiation: {stride_map['repudiation']} · "
        f"Information Disclosure: {stride_map['info_disclosure']} · "
        f"Denial of Service: {stride_map['dos']} · Elevation of Privilege: {stride_map['elev_priv']}"
    )
    lines.append("")

    # ---- Systemic posture back-reference (P4) ----------------------------
    # The Security Principles verdict table (VIOLATED/WEAK/ADEQUATE per
    # principle) was hoisted to the Management Summary (2026-07-13) so the
    # systemic posture is loud at executive level; §8 keeps only this pointer
    # while the evidence-backed weakness chapter is shown near the Management
    # Summary, so the verdict is not shown twice.
    if ctx.yaml_data.get("weaknesses"):
        lines.append(
            "The systemic posture verdict (VIOLATED / WEAK / ADEQUATE per "
            "security principle) is in the **Security Principles** table of the "
            "Management Summary; evidence-backed weaknesses are documented in "
            "[Systemic Weaknesses](#systemic-weaknesses)."
        )
        lines.append("")

    # ---- Findings index (jump-list) --------------------------------------
    # A compact, ID-ordered list of every finding card in §8 so the reader can
    # jump straight to an entry instead of scrolling the severity groups
    # (2026-05-30 user request). Each chip targets the `<a id="f-NNN">` anchor
    # the Story Card below declares, so the link always resolves.
    _idx_nums = sorted(
        {int(m.group(1)) for t in threats if (m := re.search(r"(\d+)$", (t.get("id") or t.get("t_id") or "").strip()))}
    )
    if _idx_nums:
        # One entry per line (<br/>-stacked), each chip carrying a leading
        # severity circle and the short title so the index is scannable at
        # 48 findings (2026-05-31 user request — bare ID links were unreadable).
        _sev_by_num = _severity_by_finding_num(threats)
        _title_by_num = {
            int(m.group(1)): (_canonical_finding_title(t) or (t.get("title") or "").strip())
            for t in threats
            if (m := re.search(r"(\d+)$", (t.get("id") or t.get("t_id") or "").strip()))
        }
        lines.append(_build_register_index("Findings index", "F", _idx_nums, _title_by_num, _sev_by_num))
        lines.append("")

    # ---- Category anchors (invisible) ------------------------------------
    # Each TH-NN gets an `<a id="th-NN"></a>` anchor declared exactly once
    # at the top of §8 so that `[TH-NN — Title](#th-nn)` links inside the
    # Finding cell resolve. The pre-2026-05 layout also emitted a visible
    # "Categories at a glance:" catalogue line under these anchors — that
    # was removed (2026-05) per user request as it duplicated the
    # category links already inline in each Finding cell.
    active_cat_ids = sorted(cats_active.keys(), key=lambda c: (sev_rank.get(cat_eff_severity(c), 99), c))
    if active_cat_ids:
        anchor_block = "".join(f'<a id="{c.lower()}"></a>' for c in active_cat_ids)
        lines.append(anchor_block)
        lines.append("")

    # Build component lookup once (used in the per-row rendering below).
    components = _component_lookup(ctx)
    mitigations = _mitigation_lookup(ctx)

    # Resolve repository root for live evidence-snippet reads. Fallback chain:
    # threat-model.yaml meta → .skill-config.json → None (snippet rendering
    # skipped silently when no repo root resolves).
    meta = (ctx.yaml_data or {}).get("meta") or {}
    skill_cfg = _read_skill_config(ctx.output_dir)
    repo_root_raw = meta.get("repository_root") or skill_cfg.get("repo_root") or ""
    repo_root_path: Path | None
    try:
        repo_root_path = Path(repo_root_raw).resolve() if repo_root_raw else None
    except (OSError, ValueError):
        repo_root_path = None

    # ---- Findings as severity-grouped cards ------------------------------
    # 2026-05: the flat 4-column table (ID | Finding | Component | Criticality)
    # was replaced by one card per finding, grouped by severity — mirroring the
    # §9 Mitigation-Register block style (see threatdemo.md). Each card is built
    # by ``_build_threat_card`` with a fixed field skeleton:
    #   #### F-NNN · Title → Severity/Component/Location → Issue → Root cause →
    #   Evidence (+ fenced snippet) → Fix → Classification (external CWE/OWASP).
    attack_tax = _load_attack_class_taxonomy()

    # Vektor sort key — within a severity tier, scan dirtier paths first.
    vektor_order = {"repo-read": 0, "internet-anon": 1, "internet-user": 2, "victim-required": 3}
    all_threats_sorted = sorted(
        (
            threat
            for threat in threats
            if (threat.get("evidence_check") or "").strip().lower() != "refuted"
        ),
        key=lambda t: (
            sev_rank.get((t.get("risk") or t.get("severity") or "").lower(), 99),
            vektor_order.get((t.get("vektor") or "").strip().lower(), 99),
            t.get("t_id") or t.get("id") or "",
        ),
    )

    # Carried-forward footnote condition — detected up front so the footnote
    # below renders once. (The raw-Critical and evidence-drift footnotes were
    # removed 2026-07-05; their detection flags went with them.)
    for t in all_threats_sorted:
        if (t.get("evidence_check") or "").strip().lower() == "carried-unverified-shallower-depth":
            has_carried_unverified = True

    # Group by severity (desc) and emit a card per finding under a tier header.
    by_sev: dict[str, list[dict]] = {}
    for t in all_threats_sorted:
        s = (t.get("risk") or t.get("severity") or "").strip().lower()
        if s == "informational":
            s = "info"
        by_sev.setdefault(s, []).append(t)

    for sev_key, emoji, label in (
        ("critical", "🔴", "Critical"),
        ("high", "🟠", "High"),
        ("medium", "🟡", "Medium"),
        ("low", "🟢", "Low"),
        ("info", "⚪", "Informational"),
    ):
        bucket = by_sev.get(sev_key) or []
        if not bucket:
            continue
        lines.append(f"### {emoji} {label} ({len(bucket)})")
        lines.append("")
        for t in bucket:
            lines.append(
                _build_threat_card(
                    t,
                    sev_key,
                    taxonomy,
                    components,
                    repo_root_path,
                    ctx,
                    fid_to_walkthrough=fid_to_walkthrough,
                    attack_taxonomy=attack_tax,
                )
            )
            lines.append("")

    # §8 footnotes for the `(raw Critical)` severity-cap convention and the
    # `⚠/◌` evidence-check convention were removed per user request
    # (2026-07-05): the inline markers stay on the rows but the long
    # explanatory paragraphs are dropped. The carried-forward footnote below
    # is retained (it flags un-reverified incremental content, not a marker
    # legend).

    # ---- §8 footnote: carried-forward (incremental depth-downgrade) ------
    # Depth-independent so a standard re-scan that downgraded from thorough
    # discloses carried findings too — the quick-mode banner only fires at
    # quick depth.
    if has_carried_unverified:
        lines.append("---")
        lines.append("")
        lines.append(
            "_**Carried findings:** rows tagged `↻ carried, unverified at this "
            "depth` were preserved from a prior **deeper** scan that this "
            "shallower run could not re-confirm. Absence of re-confirmation at "
            "reduced depth is **not** evidence of a fix — re-run at the prior "
            "depth (or `--full`) to re-verify._"
        )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def sev_label_strict(sev_key: str) -> str:
    """Capitalized severity label used inside §8.F role markers."""
    return {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}.get(
        (sev_key or "").lower(), sev_key.title() if sev_key else ""
    )


# ---------------------------------------------------------------------------
# Inline-code helpers for §9 Mitigation prose (M-NNN how / verification).
# ---------------------------------------------------------------------------

# Pattern → matches code-shaped tokens that should be wrapped in backticks
# in mitigation `how` / `why` / `verification` / `steps[]` text.
#
# Conservative on purpose: each alternative has at least one unambiguous
# code marker (parens, slashes, `.ext`, `--flag`, `@version`, HTTP method
# literal, `process.env.X`). False positives prefer "leave alone" over
# "wrap a normal word as code".
# A single argument token: non-period/whitespace chunk, optionally
# followed by `.<chunk>` (file extension etc.). Excludes the
# sentence-final period that's followed by whitespace + uppercase.
# Used by all command-with-args alternates below.
# Local helper:  ARG = r"[^\s,;.]+(?:\.[^\s,;.]+)*"
_INLINE_CODE_PATTERNS: list[str] = [
    # Shell command + at least one argument. Argument tokens may include
    # `.` (filenames) and `/` (paths) but stop at sentence-final
    # punctuation (period+space, comma+space, etc.).
    r"(?:^|(?<=[\s(]))"  # start-of-line OR after whitespace/open-paren
    r"(?:npm (?:install|run|test|audit) [^\s,;.]+(?:\.[^\s,;.]+)*(?:\s+[^\s,;.]+(?:\.[^\s,;.]+)*)*"
    r"|openssl [a-z]+(?:\s+-[a-zA-Z]+(?:\s+[^\s,;.]+(?:\.[^\s,;.]+)*)?){1,4}"
    r"|grep -[a-zA-Z]+ [^\s]+(?:\s+[^\s,;.]+(?:\.[^\s,;.]+)*)*"
    r"|curl -[a-zA-Z]+ [^\s]+"
    r"|git [a-z]+(?:\s+[^\s,;.]+(?:\.[^\s,;.]+)*)*"
    r"|python3 [^\s]+(?:\s+[^\s,;.]+(?:\.[^\s,;.]+)*)*"
    r"|node [^\s]+(?:\s+[^\s,;.]+(?:\.[^\s,;.]+)*)*)",
    # HTTP method + path: `POST /rest/user/login`, `GET /api/Users`.
    r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) /[A-Za-z0-9_/\-{}.:?=&]+",
    # File path with extension, optionally followed by :line or :line-line:
    # `lib/insecurity.ts:23`, `frontend/src/app.module.ts`, `routes/x.ts:20-25`.
    # The range branch `(?:-\d+)?` keeps `file.ts:20-25` a single wrapped token —
    # without it the `\b` after `:20` splits the span, leaving `-25` un-backticked.
    r"\b[A-Za-z_][A-Za-z0-9_./\-]*\.(?:ts|tsx|js|jsx|py|rb|go|rs|java|sh|json|yaml|yml|toml|md|html|css|scss)(?::\d+(?:-\d+)?)?\b",
    # JS/TS expressions:
    #   `bcrypt.hash(password, 12)`, `crypto.createHash('md5')`,
    #   `process.env.JWT_PRIVATE_KEY`,
    #   `sanitizer.bypassSecurityTrustHtml(html)`, `models.sequelize.query()`,
    #   `DomSanitizer.sanitize(SecurityContext.HTML, html)`,
    #   `rateLimit({ windowMs: 15, max: 10 })` (function call without dot).
    r"\b(?:process\.env\.[A-Z_][A-Z0-9_]*"
    r"|(?:[a-zA-Z_][a-zA-Z0-9_]*\.)+[a-zA-Z_][a-zA-Z0-9_]*\([^()\n]{0,200}\)"
    r"|[a-zA-Z_][a-zA-Z0-9_]{2,}\((?:\{[^{}\n]{0,200}\}|[^()\n]{0,200})\))",
    # Bare camelCase identifiers (no dot/paren), e.g. `safeEval`, `imageUrl`,
    # `bypassSecurityTrustHtml`, `isRedirectAllowed`, `multi`. A lowercase start
    # with an internal uppercase is a code identifier — prose words almost never
    # carry a mid-word capital, so this stays code-only in §9 How/Why/steps.
    r"\b[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*\b",
    # Bare route / directory paths: `/ftp/`, `/support/logs/`, `/rest/user`.
    # The leading whitespace/paren lookbehind keeps prose `and/or`, `TLS/SSL`,
    # `input/output` out (no space before the slash there).
    r"(?<=[\s(])/[A-Za-z][A-Za-z0-9_\-]*(?:/[A-Za-z0-9_\-{}:.]+)*/?",
    # Config object literal carrying a key:value, e.g. `{ noent: true }`,
    # `{ multi: true }`, `{ windowMs: 900000 }`.
    r"\{[^{}\n]{0,80}:[^{}\n]{0,80}\}",
    # Long npm package@version: `express-jwt@0.1.3`, `@types/bcrypt`.
    r"@[a-z][a-z0-9-]*/[a-z][a-z0-9-]*"  # scoped package
    r"|\b[a-z][a-z0-9-]*@\d+(?:\.\d+){0,2}(?:[\-+][a-zA-Z0-9.]+)?\b",
]

_INLINE_CODE_RE = re.compile("|".join(_INLINE_CODE_PATTERNS))


def _wrap_inline_code(text: str) -> str:
    """Wrap code-shaped tokens with backticks while preserving existing
    fenced/inline code regions verbatim. Idempotent — running this twice
    produces the same output (already-wrapped tokens are skipped).
    """
    if not text:
        return text

    # Tokenize into "kept-verbatim" chunks (existing backticks, fenced code)
    # and "scannable" chunks. Only the scannable chunks go through the regex
    # so that already-wrapped code stays unchanged.
    chunks: list[tuple[str, str]] = []  # (kind, content); kind ∈ {keep, scan}
    cursor = 0
    skip_re = re.compile(r"`[^`\n]+`|```[\s\S]*?```", re.MULTILINE)
    for m in skip_re.finditer(text):
        if m.start() > cursor:
            chunks.append(("scan", text[cursor : m.start()]))
        chunks.append(("keep", m.group(0)))
        cursor = m.end()
    if cursor < len(text):
        chunks.append(("scan", text[cursor:]))

    def _wrap_one(mm: re.Match[str]) -> str:
        token = mm.group(0)
        # Push trailing sentence-end punctuation BACK out of the code span
        # so prose punctuation stays visible. `.` is excluded only when it
        # isn't required for a file extension (we keep `.ts` / `.js` etc.).
        trailing = ""
        while token and token[-1] in ".,;:!?":
            # Keep `.<ext>` inside the wrap when the wrap is exactly that.
            ch = token[-1]
            if ch == "." and re.search(
                r"\.(?:ts|tsx|js|jsx|py|rb|go|rs|java|sh|json|yaml|yml|"
                r"toml|md|html|css|scss)$",
                token[:-1] + ch,
            ):
                break
            trailing = ch + trailing
            token = token[:-1]
        if not token:
            return mm.group(0)
        return f"`{token}`{trailing}"

    out: list[str] = []
    for kind, content in chunks:
        if kind == "keep":
            out.append(content)
            continue
        out.append(_INLINE_CODE_RE.sub(_wrap_one, content))
    return "".join(out)


def _load_sibling_module(name: str):
    """Import a sibling ``scripts/<name>.py`` module by path.

    Used so compose can reuse another script's pure functions in-process
    (e.g. the §9 self-heal below) without spawning a subprocess. Raises on a
    missing/unloadable module — callers that want best-effort behaviour wrap
    the call in try/except.
    """
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parent / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load sibling module {name!r}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _heal_abuse_cases_fragment(ctx: RenderContext) -> str:
    """Regenerate the §9 fragment in-process from on-disk verdicts.

    The orchestrator normally runs ``scripts/render_abuse_cases.py`` to write
    ``.fragments/abuse-cases.md`` BEFORE compose. An interrupted or skipped
    Stage-1c run can leave ``.abuse-case-verdicts.json`` (and the matcher's
    ``.abuse-case-matches.json``) on disk with viable chains but no fragment —
    in which case the bare placeholder below would falsely claim "no abuse
    cases" even though the verified evidence is sitting right there. compose
    has the exact inputs the standalone renderer uses, so it rebuilds the
    fragment rather than silently dropping the data. RC-2026-06-29.

    Returns the fragment markdown (also persisted to ``.fragments/`` so the MS
    abuse-chain line and JSON sidecar stay consistent), or "" when there is
    genuinely no abuse-case evaluation on disk to recover.
    """
    verdicts = ctx.output_dir / ".abuse-case-verdicts.json"
    matches = ctx.output_dir / ".abuse-case-matches.json"
    if not verdicts.exists() and not matches.exists():
        return ""
    try:
        rac = _load_sibling_module("render_abuse_cases")
    except Exception:
        return ""
    skill_cfg = _read_skill_config(ctx.output_dir)
    repo_root = (ctx.yaml_data.get("meta") or {}).get("repository_root") or skill_cfg.get("repo_root") or None
    op = skill_cfg.get("org_profile") if isinstance(skill_cfg.get("org_profile"), dict) else {}
    org_profile = op.get("path") if op.get("active") else None
    try:
        models = rac.build_models(ctx.output_dir, org_profile, repo_root)
        catalog_rows = rac.build_catalog_evaluation(ctx.output_dir)
    except Exception:
        return ""
    if not models and not catalog_rows:
        return ""
    md = rac.render_fragment(models, catalog_rows)
    try:
        ctx.fragments_dir.mkdir(parents=True, exist_ok=True)
        (ctx.fragments_dir / "abuse-cases.md").write_text(md, encoding="utf-8")
        (ctx.fragments_dir / "abuse-cases.json").write_text(
            json.dumps(
                {"schema_version": 1, "abuse_cases": models, "catalog_evaluated": catalog_rows},
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    except OSError:
        pass
    return md.strip()


def _render_abuse_cases(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """Render §9 Abuse Cases.

    The section body is produced deterministically by
    ``scripts/render_abuse_cases.py`` (from ``.abuse-case-verdicts.json`` +
    ``threat-model.yaml``) and dropped at ``.fragments/abuse-cases.md``. This
    handler inlines that fragment verbatim when present. When it is absent the
    handler first attempts an in-process self-heal from on-disk verdicts (see
    ``_heal_abuse_cases_fragment`` — covers the orchestration gap where the
    render step was skipped); only when there is genuinely no abuse-case
    evaluation to recover does it emit a single italic placeholder so the §8 →
    §10 numbering stays contiguous (the contract hard-numbers §10 Mitigation
    Register / §11 Out of Scope).

    Like every markdown fragment, the first non-blank line must equal the
    contract heading, so a renderer/contract drift is caught here rather than
    surfacing as a malformed report.
    """
    heading = (section.get("heading") or "## 9. Abuse Cases").strip()
    frag = ctx.fragments_dir / "abuse-cases.md"
    try:
        md = frag.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        md = ""
    if not md:
        md = _heal_abuse_cases_fragment(ctx)
    if not md:
        return f"{heading}\n\n_No abuse cases were identified or mandated for this assessment._\n"
    first = next((ln.strip() for ln in md.splitlines() if ln.strip()), "")
    if first != heading:
        raise FragmentError(
            "abuse_cases",
            f"fragment must begin with '{heading}'; first heading is '{first}'",
        )
    # NOTE: §9's bare `[F-NNN]` / `[M-NNN]` chips (chain tables + "Blocking
    # mitigations" bullets) get their severity dot / priority circle from the
    # GLOBAL retrofit pass at the end of render() — see the call sites just
    # before render() returns. Doing it there (rather than here) keeps a single
    # source of truth and covers §3/§5/§7/§9 uniformly.
    # Provenance (2026-06-26): if §9 was carried forward from a deeper prior run
    # (restore_preserved_sections restored abuse-cases.md), mark it as carried.
    prov = _carried_provenance(ctx.output_dir)
    if prov and "abuse_cases" in prov.get("sections", []):
        banner = _carried_forward_banner(prov.get("origin_depth", ""), prov.get("origin_date", ""))
        body = md.rstrip()
        lines = body.split("\n", 1)
        if lines and lines[0].strip() == heading:
            rest = lines[1] if len(lines) == 2 else ""
            return lines[0] + "\n\n" + banner + "\n" + rest.rstrip() + "\n"
        return banner + "\n\n" + body + "\n"
    return md.rstrip() + "\n"


def _render_mitigation_register(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """Render §9 Mitigation Register.

    Each M-NNN entry carries the full detail block required by the reference:
        <a id="m-nnn"></a>M-NNN — Title
        **Addresses:** bulleted list of [F/T-NNN](#…) — label
        **Prevents CWEs:** (optional)
        **Priority:** **P1 — Immediate** / …
        **Severity:** 🔴 Critical / …
        **Effort:** Low/Medium/High
        **Why:** paragraph
        **How:** paragraph + optional ```lang code block
        **Verification:** paragraph
        **Reference:** (optional link)

    The `how_code` field (if present in yaml) is rendered as a fenced code
    block with `how_code_lang` (default `javascript`). Missing free-text
    fields default to a short auto-generated placeholder so every entry is
    visibly complete.
    """
    mitigations = ctx.yaml_data.get("mitigations") or []
    lines = [section["heading"], ""]
    # One-shot preamble that explains the per-M-NNN block contract. The
    # earlier renderer emitted ~3 boilerplate sentences PER mitigation
    # ("This mitigation closes the root-cause weakness underlying …"
    # / "Implement the change described above …"); with 25+ mitigations
    # that produced ~2 KB of repeated text. The same information now
    # lives once at the top of §9 and per-M-NNN blocks carry only
    # author-supplied content.
    lines.append(
        "Each mitigation block lists the findings it **Addresses**, the CWEs "
        "it **Prevents**, and the **Priority** (P1 = before deployment, "
        "P2 = current sprint, P3 = next quarter, P4 = backlog). The **Why** / "
        "**How** / **Verification** fields are populated only when authored; "
        "if a field is omitted, refer to the linked finding's *Evidence* line "
        "for file:line context and to the threat-category description in "
        "[§8 Findings Register](#8-findings-register) for the underlying weakness."
    )
    lines.append("")

    # ---- Mitigations index (jump-list) -----------------------------------
    # A compact, ID-ordered list of every M-NNN block so the reader can jump
    # straight to a mitigation instead of scrolling the priority buckets
    # (2026-05-30 user request). Each chip targets the `<a id="m-NNN">` anchor
    # the block below declares.
    _m_nums = sorted(
        {
            int(mm2.group(1))
            for mm in mitigations
            if (mm2 := re.search(r"(\d+)$", (mm.get("m_id") or mm.get("id") or "").strip()))
        }
    )
    if _m_nums:
        # Each chip carries the mitigation title plus a PRIORITY circle
        # (P1🔴 P2🟠 P3🟡 P4🟢) = the mitigation's own remediation urgency
        # (2026-05-31 user request: priority instead of criticality).
        # When a mitigation has no explicit priority, fall back to the
        # highest severity among the findings it addresses, mapped onto the
        # P-scale (Critical→P1 … Low→P4) so every chip still carries a circle.
        _sev_f = _severity_by_finding_num(ctx.yaml_data.get("threats") or [])
        _sev_to_prio = {"critical": "p1", "high": "p2", "medium": "p3", "low": "p4"}
        _m_title: dict[int, str] = {}
        _m_prio: dict[int, str] = {}
        for mm in mitigations:
            _mn = re.search(r"(\d+)$", (mm.get("m_id") or mm.get("id") or "").strip())
            if not _mn:
                continue
            _n = int(_mn.group(1))
            _m_title[_n] = (mm.get("title") or "").strip()
            _raw_prio = (mm.get("priority") or "").strip().lower()
            if _raw_prio in _PRIO_ICON_TBL:
                _m_prio[_n] = _raw_prio
                continue
            _best = 9
            for _a in mm.get("threat_ids") or mm.get("addresses") or []:
                _am = re.search(r"(\d+)$", str(_a))
                if _am:
                    _best = min(_best, _SEV_RANK_TBL.get(_sev_f.get(int(_am.group(1)), ""), 9))
            _sev_word = next((s for s, r in _SEV_RANK_TBL.items() if r == _best), "")
            _m_prio[_n] = _sev_to_prio.get(_sev_word, "p3")
        # Order by rollout priority (P1 first), then by M-ID within a bucket —
        # the priority is the actionable signal, so the index leads with what
        # must ship first instead of raw ID order (2026-06-02 user request).
        _PRIO_SORT = {"p1": 0, "p2": 1, "p3": 2, "p4": 3}
        _m_nums_by_prio = sorted(_m_nums, key=lambda n: (_PRIO_SORT.get(_m_prio.get(n, "p3"), 2), n))
        lines.append(
            _build_register_index(
                # Variant B (2026-06-04): a single MONOCHROME circled digit
                # (●◕◑○) whose fill is the priority — the colourless parallel
                # to the §8 Findings-index severity dots, self-explanatory so no
                # P-tag is needed (supersedes the fill-ramp+text form).
                "Mitigations index",
                "M",
                _m_nums_by_prio,
                _m_title,
                _m_prio,
                icon_tbl=_PRIO_RAMP_TBL,
                key_label_tbl=None,
                show_icon=True,
            )
        )
        lines.append("")

    # Requirements + blueprint provenance for the per-mitigation blocks below.
    # mitigations[] carries neither field, so derive from each mitigation's
    # addressed threats (violated_requirements / requirement_id /
    # remediation.reference for Fulfills; remediation.blueprint for the guidance
    # line). Gated on check_requirements so default runs stay byte-unchanged.
    _req_enabled = bool(ctx.eval_context.get("check_requirements"))
    _known_req_ids = _known_requirement_ids(ctx) if _req_enabled else {}
    _req_status_map = _requirements_status_map(ctx) if _req_enabled else {}
    _req_blueprints = _requirement_blueprints(ctx) if _req_enabled else {}
    _threats_by_id = {
        (t.get("t_id") or t.get("id") or "").strip().upper(): t for t in (ctx.yaml_data.get("threats") or [])
    }

    # Normalise severity-word priorities that the orchestrator sometimes
    # emits instead of P-values (e.g. "Critical" → "P1").
    _sev_to_prio = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}
    for prio in ("P1", "P2", "P3", "P4"):
        bucket = [
            m
            for m in mitigations
            if (_sev_to_prio.get((m.get("priority") or "").strip().lower()) or (m.get("priority") or "").strip())
            == prio
        ]
        bucket.sort(key=lambda m: m.get("m_id") or m.get("id") or "")
        sub_label = {"P1": "P1 — Immediate", "P2": "P2 — This Sprint", "P3": "P3 — Next Quarter", "P4": "P4 — Backlog"}[
            prio
        ]
        lines.append(f"### {sub_label}")
        lines.append("")
        if not bucket:
            lines.append(f"_No {prio} mitigations._")
            lines.append("")
            continue
        for m in bucket:
            mid = m.get("m_id") or m.get("id") or "-"
            title = (m.get("title") or m.get("mitigation_title") or "(untitled)").strip()
            lines.append(f'<a id="{mid.lower()}"></a>')
            lines.append(f"#### {mid} — {_escape_heading_placeholders(title)}")
            lines.append("")

            # Addresses as a bulleted list of linkified refs (reference layout).
            # M3.13 — each bullet is prefixed by the addressed FINDING's
            # severity emoji so per-finding severity is visible at the
            # point of reference; the mitigation block itself no longer
            # carries a standalone `**Severity:**` line further down.
            addressed = m.get("addresses") or m.get("threat_ids") or []
            if addressed:
                lines.append("**Addresses:**")
                lines.append("")
                for ref in addressed:
                    # linkify_with_label already prepends the effective-severity
                    # criticality dot for finding refs — emitting a manual badge
                    # here too would double it (and risk a raw-vs-effective
                    # mismatch). Single source of truth: linkify_with_label.
                    lines.append(f"- {ctx.linkify_with_label(ref)}")
                lines.append("")

            # Prevents CWEs — prefer explicit field; else derive from addressed findings.
            # Auto-derived CWEs are SUPPRESSED when the rest of the mitigation
            # block is sparse (no how_code/code_example/steps/verification). In
            # that case the CWE list dominates a block that has nothing else
            # actionable and reads as filler. An EXPLICIT prevents_cwes/cwes
            # field is always rendered (the author wanted it).
            explicit_cwes = m.get("prevents_cwes") or m.get("cwes") or []
            cwes = list(explicit_cwes)
            if not cwes and addressed:
                derived: list[str] = []
                seen_cwe: set[str] = set()
                threats_idx = {
                    (t.get("t_id") or t.get("id") or "").upper(): t for t in (ctx.yaml_data.get("threats") or [])
                }
                for ref in addressed:
                    tt = threats_idx.get((ref or "").strip().upper()) or {}
                    c = (tt.get("cwe") or "").strip()
                    if c and c not in seen_cwe:
                        derived.append(c)
                        seen_cwe.add(c)
                # Only render auto-derived CWEs when actionable content
                # (how_code / code_example / steps / verification) is also
                # present. Otherwise this block becomes the entire mitigation
                # body and the reader cannot tell that real content is missing.
                has_actionable = bool(
                    m.get("how_code")
                    or m.get("code_example")
                    or (isinstance(m.get("steps"), list) and m.get("steps"))
                    or (m.get("verification") or "").strip()
                )
                if has_actionable:
                    cwes = derived
            if cwes:
                # Render as a bullet list so the CWE name (if known) can be
                # appended — matches the reference threat model layout.
                _CWE_NAMES = {
                    "CWE-89": "SQL Injection",
                    "CWE-79": "Cross-site Scripting",
                    "CWE-94": "Code Injection",
                    "CWE-611": "XML External Entity (XXE)",
                    "CWE-798": "Use of Hard-coded Credentials",
                    "CWE-321": "Use of Hard-coded Cryptographic Key",
                    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
                    "CWE-347": "Improper Verification of Cryptographic Signature",
                    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
                    "CWE-918": "Server-Side Request Forgery (SSRF)",
                    "CWE-352": "Cross-Site Request Forgery (CSRF)",
                    "CWE-862": "Missing Authorization",
                    "CWE-284": "Improper Access Control",
                    "CWE-639": "Authorization Bypass Through User-Controlled Key (IDOR)",
                    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
                    "CWE-640": "Weak Password Recovery Mechanism",
                    "CWE-922": "Insecure Storage of Sensitive Information",
                    "CWE-943": "Special-Element Injection in Data Query",
                    "CWE-200": "Exposure of Sensitive Information",
                    "CWE-778": "Insufficient Logging",
                    "CWE-400": "Uncontrolled Resource Consumption",
                    "CWE-1104": "Use of Unmaintained Third-Party Components",
                    "CWE-346": "Origin Validation Error",
                }
                lines.append("**Prevents CWEs:**")
                lines.append("")
                for c in cwes:
                    key = c if c.upper().startswith("CWE-") else f"CWE-{c}"
                    num = key.split("-", 1)[-1]
                    nm = _CWE_NAMES.get(key.upper(), "")
                    # M3.13 — em-dash separator (was hyphen) for consistency
                    # with the rest of the report's id-to-label convention.
                    suffix = f" — {nm}" if nm else ""
                    lines.append(f"- [{key}](https://cwe.mitre.org/data/definitions/{num}.html){suffix}")
                lines.append("")

            # Fulfills Requirements + Blueprint guidance — only when
            # requirements are loaded. The §10 block template places both after
            # Prevents CWEs and before Priority. mitigations[] carries neither
            # field, so derive from the addressed threats here: this produces
            # the lines the QA reviewer demands but the renderer previously
            # dropped, and surfaces blueprint guidance that was otherwise
            # confined to the §7b traceability cell.
            if _req_enabled:
                _addr = m.get("addresses") or m.get("threat_ids") or []
                _fulfilled: list[str] = []
                _bp_cell = ""
                for _tid in _addr:
                    _tt = _threats_by_id.get((_tid or "").strip().upper()) or {}
                    for _rid in _requirement_ids_for_threat(_tt, _known_req_ids):
                        if not _requirement_is_traceable_violation(_rid, _req_status_map):
                            continue
                        if _rid not in _fulfilled:
                            _fulfilled.append(_rid)
                    if not _bp_cell:
                        _rem = _tt.get("remediation") if isinstance(_tt.get("remediation"), dict) else {}
                        _bp_cell = _format_blueprint_cell(_rem.get("blueprint")) if _rem else ""
                if not _bp_cell:
                    for _rid in _fulfilled:
                        if _req_blueprints.get(_rid):
                            _bp_cell = _req_blueprints[_rid]
                            break
                if _fulfilled:
                    lines.append("**Fulfills Requirements:**")
                    lines.append("")
                    for _rid in _fulfilled:
                        _u = _known_req_ids.get(_rid, "")
                        lines.append(f"- [{_rid}]({_u})" if _u else f"- `{_rid}`")
                    lines.append("")
                if _bp_cell:
                    lines.append(f"**Blueprint guidance:** {_bp_cell}")
                    lines.append("")

            # M3.13 — consolidate Priority + Effort + File on ONE line.
            # The standalone Severity row is REMOVED (severity is now shown
            # per-finding in the Addresses bullets above). File location
            # comes from the same resolution chain that previously produced
            # the German "Datei:" line — surfaced inline here.
            meta_parts: list[str] = [f"**Priority:** {sub_label}"]
            meta_parts.append(f"**Effort:** {m.get('effort', 'Medium')}")
            # Resolve file label inline (same resolution chain as below).
            _how_for_loc_inline = (m.get("how") or "").strip()
            file_line_inline = ""
            _expl = (m.get("file") or m.get("location") or "").strip()
            if _expl:
                file_line_inline = _expl
            elif _how_for_loc_inline:
                _fl_re_inline = re.compile(r"`?([\w./\-]+\.[a-zA-Z0-9]{1,6}:\d+)`?")
                _fmi = _fl_re_inline.search(_how_for_loc_inline)
                if _fmi:
                    file_line_inline = _fmi.group(1)
            if not file_line_inline and addressed:
                _t_idx = {(t.get("t_id") or t.get("id") or "").upper(): t for t in (ctx.yaml_data.get("threats") or [])}
                _first = _t_idx.get((addressed[0] or "").strip().upper()) or {}
                _ev = _first.get("evidence") or []
                if isinstance(_ev, dict):
                    _ev = [_ev]
                if _ev and isinstance(_ev[0], dict):
                    _f = (_ev[0].get("file") or "").strip()
                    _ln = _ev[0].get("line")
                    if _f and _ln is not None:
                        file_line_inline = f"{_f}:{_ln}"
                    elif _f:
                        file_line_inline = _f
            if file_line_inline:
                meta_parts.append(f"**File:** `{file_line_inline}`")
            lines.append(" · ".join(meta_parts))
            lines.append("")

            # M3.13 — the legacy standalone `**Datei:**` line was removed:
            # the File reference is now inline in the meta line above
            # ("**Priority:** P1 — Immediate · **Effort:** Low · **File:**
            # `routes/login.ts:34`"). Keeping both produced redundant
            # repetition of the same path.

            # Why / How / Verification are emitted ONLY when the yaml
            # carries authored content. Earlier versions of this renderer
            # synthesised boilerplate fallbacks for every empty field —
            # producing identical-looking sentences in 20+ mitigation
            # blocks that added length without information. The §9
            # preamble above tells the reader where to look when a field
            # is omitted.
            why = (m.get("why") or "").strip()
            if why:
                lines.append(f"**Why:** {_wrap_inline_code(why)}")
                lines.append("")

            how = (m.get("how") or "").strip()
            how_code = m.get("how_code")
            # `code_example` is the alternate field name the threat-merger
            # / Phase-10 yaml-builder populates today (a Markdown blob that
            # already contains its own ``` fence). Treat as a synonym for
            # `how_code` — emit verbatim when it carries fences, else wrap.
            code_example = m.get("code_example")
            how_lang = m.get("how_code_lang", "javascript")
            steps = m.get("steps") or []
            # Fallback: when the mitigation entry itself carries no `steps`
            # / `how` content, harvest from the addressed threats'
            # `remediation.steps` blocks. STRIDE analyzers populate
            # `threats[].remediation` with concrete per-finding remediation
            # but the merger only forwards `mitigation_title` to
            # `mitigations[]`, leaving the body empty unless Stage 2
            # explicitly authored it. Without this fallback the §9
            # Mitigation Register is just a list of titles + addresses.
            mitigation_reference = (m.get("reference") or "").strip()
            verification_field = (m.get("verification") or "").strip()
            # F4.5: per-field harvest from addressed threats' `remediation.*`
            # (previously the harvest only ran when ALL of steps/how/how_code/
            # code_example were empty, so the common case "how is a 1-sentence
            # placeholder" prevented us from pulling in the threat's
            # code_example / verification / steps). The per-field harvest
            # respects authored mitigation content — it only fills the
            # specific fields that are missing.
            if addressed:
                threats_idx_for_steps = {
                    (t.get("t_id") or t.get("id") or "").upper(): t for t in (ctx.yaml_data.get("threats") or [])
                }
                merged_steps: list[str] = []
                seen_steps: set[str] = set()
                harvested_code: str = ""
                harvested_verification: str = ""
                for ref in addressed:
                    tt = threats_idx_for_steps.get((ref or "").strip().upper()) or {}
                    rem = tt.get("remediation") or {}
                    # Threats may carry a TOP-LEVEL `code_example` field
                    # (older shape) instead of `remediation.code_example`.
                    threat_code = tt.get("code_example") or ""
                    if isinstance(rem, dict):
                        for st in rem.get("steps") or []:
                            s = (st or "").strip() if isinstance(st, str) else ""
                            if s and s not in seen_steps:
                                merged_steps.append(s)
                                seen_steps.add(s)
                        if not mitigation_reference:
                            r = (rem.get("reference") or "").strip() if isinstance(rem.get("reference"), str) else ""
                            # A `remediation.reference` that is actually a
                            # requirement ID (STRIDE analyzers park matched
                            # requirements there) is surfaced via Fulfills
                            # Requirements above — do NOT also render it as a
                            # cheatsheet `**Reference:**` line.
                            if (
                                r
                                and _known_req_ids
                                and any(tok.strip() in _known_req_ids for tok in re.findall(r"\[([^\]]+)\]", r))
                            ):
                                r = ""
                            if r:
                                mitigation_reference = r
                        if not harvested_code:
                            rc = rem.get("code_example") or ""
                            if isinstance(rc, str) and rc.strip():
                                harvested_code = rc.strip()
                        if not harvested_verification:
                            rv = rem.get("verification") or ""
                            if isinstance(rv, str) and rv.strip():
                                harvested_verification = rv.strip()
                    if not harvested_code and isinstance(threat_code, str) and threat_code.strip():
                        harvested_code = threat_code.strip()
                # Per-field fill — only overwrite mitigation fields that
                # the author left empty. authored values always win.
                if not steps and merged_steps:
                    steps = merged_steps
                if not code_example and not how_code and harvested_code:
                    code_example = harvested_code
                if not verification_field and harvested_verification:
                    verification_field = harvested_verification

            # Quick-depth content backstop — render the mitigation's
            # `description` as the **How:** paragraph when the orchestrator
            # did not author a richer `how` / `steps` / `code_example` block.
            # The yaml-builder always writes a one-sentence `description`,
            # so this turns the bare-skeleton entries (only Addresses /
            # Priority / Effort) into actionable guidance without burning
            # another agent dispatch. Authored content always wins.
            mit_description = (m.get("description") or "").strip()
            if mit_description and not how and not steps and not how_code and not code_example:
                how = mit_description

            # Quick-depth code-example backstop. E - Multi-CWE rendering.
            # Collect every distinct CWE across the addressed findings and
            # queue a snippet per CWE. The first snippet feeds the existing
            # `code_example` / `verification_field` slots; the rest are
            # emitted as extra fenced blocks under a CWE label so a
            # mitigation that spans, say, CWE-943 (NoSQL inj) + CWE-284
            # (improper access control) + CWE-400 (DoS) does not advertise
            # a single $where-filter snippet as the cure for all three.
            extra_cwe_snippets: list[tuple[str, dict]] = []
            if not how_code and not code_example:
                threats_idx_for_cwe = {
                    (t.get("t_id") or t.get("id") or "").upper(): t for t in (ctx.yaml_data.get("threats") or [])
                }
                seen_cwes: list[str] = []
                for ref in addressed:
                    tt = threats_idx_for_cwe.get((ref or "").strip().upper()) or {}
                    raw_cwe = (tt.get("cwe") or "").strip()
                    if not raw_cwe:
                        _cids = tt.get("cwe_ids") or []
                        if isinstance(_cids, list) and _cids:
                            raw_cwe = (_cids[0] or "").strip()
                    if not raw_cwe:
                        continue
                    norm = raw_cwe if raw_cwe.upper().startswith("CWE-") else f"CWE-{raw_cwe}"
                    norm = norm.upper()
                    if norm in seen_cwes:
                        continue
                    if norm in _MITIGATION_CWE_SNIPPETS:
                        seen_cwes.append(norm)
                if seen_cwes:
                    first = seen_cwes[0]
                    snip = _MITIGATION_CWE_SNIPPETS[first]
                    code_example = snip.get("code", "").rstrip()
                    if snip.get("lang"):
                        how_lang = snip["lang"]
                    if not verification_field:
                        verification_field = (snip.get("verification") or "").strip()
                    for c in seen_cwes[1:]:
                        extra_cwe_snippets.append((c, _MITIGATION_CWE_SNIPPETS[c]))
            if how:
                # Multi-line `how:` blobs frequently start with a numbered or
                # bulleted list ("1. Generate a key…\n2. Store it in env…").
                # When concatenated onto the `**How:**` label on the same
                # line, GitHub's Markdown engine no longer recognises it as
                # an ordered list — every step renders as a single soft-
                # wrapped paragraph. Detect that case (any newline OR a
                # leading list marker) and emit the label on its own line
                # so the steps render as the list the author intended.
                _list_re = re.compile(r"^\s*(?:\d+\.|[-*])\s")
                if "\n" in how or _list_re.match(how):
                    lines.append("**How:**")
                    lines.append("")
                    for hl in how.splitlines() or [how]:
                        lines.append(_wrap_inline_code(hl))
                else:
                    lines.append(f"**How:** {_wrap_inline_code(how)}")
                lines.append("")
            # `steps[]` is the canonical structured remediation list emitted
            # by the threat-merger. Each element is a single concrete action.
            # Render as a bullet list so the user sees an actionable plan
            # even when no free-prose `how` paragraph is authored. Both can
            # coexist — the prose `how` introduces the change, the `steps`
            # enumerate the actions.
            if isinstance(steps, list) and steps:
                if not how:
                    lines.append("**How:**")
                    lines.append("")
                # `steps[]` are sequential remediation actions — render as an
                # ORDERED list (1. 2. 3.) so the implied execution order is
                # explicit (2026-05-29 user request). A bullet list reads as an
                # unordered set; remediation is a procedure.
                _step_n = 0
                for step in steps:
                    s = (step or "").strip() if isinstance(step, str) else ""
                    if s:
                        # Inline-code-fence single-quotes that surround
                        # short identifiers so list items survive markdown
                        # renderers (some viewers eat unescaped backticks).
                        _step_n += 1
                        lines.append(f"{_step_n}. {_wrap_inline_code(s)}")
                lines.append("")
            # Introduce every code example with its source location and the
            # mitigation it demonstrates. A bare fenced block forces the reader
            # to infer both its file and purpose from surrounding prose; this
            # deterministic sentence keeps examples skimmable and makes clear
            # that the ordered steps, not a partial snippet, are authoritative.
            _has_guidance = bool(how) or bool(isinstance(steps, list) and steps)
            _caption_title = _escape_heading_placeholders(title)
            if file_line_inline:
                _code_caption = f"_Example implementation in `{file_line_inline}`: it applies **{_caption_title}**."
            else:
                _code_caption = f"_Example implementation for **{_caption_title}**:"
            if _has_guidance:
                _code_caption += " The ordered steps above remain authoritative._"
            else:
                _code_caption += "_"
            if how_code:
                lines.append(_code_caption)
                lines.append("")
                lines.append(f"```{how_lang}")
                lines.append(how_code.rstrip())
                lines.append("```")
                lines.append("")
            elif code_example:
                # `code_example` arrives as a Markdown blob authored by the
                # phase-10 yaml-builder. Two shapes are accepted:
                #   1. Already-fenced — starts with "```<lang>" and ends with
                #      "```". Emit verbatim (do NOT double-fence).
                #   2. Bare code without fences — wrap with how_code_lang.
                ce = code_example.strip() if isinstance(code_example, str) else ""
                if ce:
                    lines.append(_code_caption)
                    lines.append("")
                    if ce.startswith("```") and ce.rstrip().endswith("```"):
                        lines.append(ce)
                    else:
                        lines.append(f"```{how_lang}")
                        lines.append(ce)
                        lines.append("```")
                    lines.append("")

            # E - Extra per-CWE snippets when the mitigation spans multiple
            # CWE classes. Each block carries a single-line label so the
            # reader can see which class the snippet addresses.
            for extra_cwe, extra_snip in extra_cwe_snippets:
                cwe_num = extra_cwe.split("-", 1)[-1]
                _extra_loc = f" in `{file_line_inline}`" if file_line_inline else ""
                lines.append(f"_Additional example implementation{_extra_loc} for [{extra_cwe}](https://cwe.mitre.org/data/definitions/{cwe_num}.html):_")
                lines.append("")
                lines.append(f"```{extra_snip.get('lang') or how_lang}")
                lines.append(extra_snip.get("code", "").rstrip())
                lines.append("```")
                lines.append("")
                # If no verification line is set yet and this snippet has
                # one, attach it -- otherwise multiple snippets compete for
                # the single verification slot and the reader sees only
                # one. Concatenate when more than one snippet has a check.
                extra_ver = (extra_snip.get("verification") or "").strip()
                if extra_ver:
                    if not verification_field:
                        verification_field = extra_ver
                    elif extra_ver not in verification_field:
                        verification_field = f"{verification_field} Additionally: {extra_ver}"

            # F4.5: prefer the per-field-harvested value (set above when the
            # mitigation entry left this empty but an addressed threat carries
            # a `remediation.verification` string).
            ver = verification_field or (m.get("verification") or "").strip()
            if ver:
                lines.append(f"**Verification:** {_wrap_inline_code(ver)}")
                lines.append("")

            # Use the harvested fallback reference when the mitigation
            # entry itself has none (mitigation_reference was set by the
            # threats[].remediation fallback above).
            ref = _normalize_reference(m.get("reference") or mitigation_reference or "")
            if ref:
                lines.append(f"**Reference:** {ref}")
                lines.append("")

            lines.append("---")
            lines.append("")
    # Strip the trailing `---` separator that follows the last mitigation
    # block in the final bucket. The document-level section separator
    # already inserts one `---` between sections, so leaving the
    # per-block separator on the last entry produced a doubled rule
    # right above the next section heading (most visible above §10).
    out = "\n".join(lines).rstrip()
    out = re.sub(r"\n-{3,}\s*$", "", out)
    return out.rstrip() + "\n"


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


def _drop_asset_id_column(md: str) -> str:
    """Remove the ``ID`` column from the §4 Assets table.

    The asset ids (``A-NNN``) are an internal yaml key: the rendered document
    carries no ``#a-NNN`` anchor and nothing links to them, so the column is
    display-only noise. The agent prompt already specifies the 4-column layout
    ``| Asset | Classification | Description | Linked Threats |`` — but the LLM
    routinely re-adds an ``ID`` column, so we drop it deterministically here
    (prefer deterministic Python over trusting the fragment). Matched by header
    set (a table carrying both ``Asset`` and ``ID``) and dropped by header name,
    so it is order-independent and a no-op once the column is already absent.
    """
    lines = md.split("\n")
    for header_idx, block in _iter_md_table_blocks(md):
        header_cells = _split_table_row(block[0])
        norm = [h.strip().lower() for h in header_cells]
        if "asset" not in norm or "id" not in norm:
            continue
        drop_i = norm.index("id")
        for off in range(len(block)):
            row_idx = header_idx + off
            if row_idx >= len(lines):
                break
            cells = _split_table_row(lines[row_idx])
            if len(cells) != len(header_cells):
                continue  # ragged row — leave for the QA gate to flag
            del cells[drop_i]
            lines[row_idx] = "| " + " | ".join(cells) + " |"
    return "\n".join(lines)


def _render_assets(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """§4 Assets — LLM-authored fragment passthrough with the stray ``ID``
    column stripped deterministically (see :func:`_drop_asset_id_column`)."""
    return _drop_asset_id_column(_render_markdown_fragment(ctx, "assets", section))


def _render_by_id(ctx: RenderContext, env: jinja2.Environment, section_id: str, section: dict) -> str:
    dispatcher: dict[str, Any] = {
        "infobox": _render_infobox,
        "changelog": _render_changelog,
        "quick_mode_notice": _render_quick_mode_notice,
        "toc": _render_toc,
        "management_summary": _render_management_summary,
        "systemic_weaknesses": lambda ctx, _env, _section: _render_systemic_weaknesses(ctx),
        # Item 3 (2026-05-28): wired the dormant Critical Attack Tree
        # renderer into the dispatcher. Section is gated on
        # `critical_count >= 2` via sections-contract.yaml conditional.
        "critical_attack_tree": _render_critical_attack_tree,
        "verdict": _render_verdict,
        "identified_actors": _render_identified_actors,
        "assets": _render_assets,
        "security_posture_at_a_glance": _render_security_posture_at_a_glance,
        "skipped_sections_placeholder": _render_skipped_sections_placeholder,
        "top_findings": _render_top_findings,
        "top_threats": _render_top_threats,
        "mitigations": _render_mitigations,
        "operational_strengths": _render_operational_strengths,
        "threat_register": _render_threat_register,
        "abuse_cases": _render_abuse_cases,
        "mitigation_register": _render_mitigation_register,
        "requirements_compliance": _render_requirements_compliance,
        "appendix_run_statistics": _render_appendix_run_statistics,
        "composition_notes": _render_composition_notes,
        # M3.3 — `run_issues` no longer rendered into threat-model.md.
        # The renderer function `_render_run_issues` is preserved for
        # easy re-activation; un-comment the line below and add the
        # section def + document.order entry in sections-contract.yaml.
        # "run_issues":               _render_run_issues,
        "appendix_vektor_taxonomy": _render_appendix_vektor_taxonomy,
    }
    fn = dispatcher.get(section_id)
    if fn:
        return fn(ctx, env, section)

    ftype = section.get("fragment_type")
    if ftype == "markdown":
        return _render_markdown_fragment(ctx, section_id, section)
    if ftype == "template":
        tpl = env.get_template(section["template"])
        return tpl.render().rstrip() + "\n"
    raise ContractError(f"no renderer for section {section_id!r} with fragment_type={ftype!r}")


# ---------------------------------------------------------------------------
# Top-level orchestration
# ---------------------------------------------------------------------------


_ARCHITECTURE_SECTIONS = [
    "infobox",
    "toc",
    "system_overview",
    "architecture_diagrams",
    "attack_walkthroughs",
    "assets",
    "attack_surface",
    # §6 use_cases removed 2026-05; gap intentional (see sections-contract.yaml).
    "security_architecture",
    # requirements_compliance is included conditionally (check_requirements flag)
    {"id": "requirements_compliance", "condition": "check_requirements"},
]

_ARCHITECTURE_TOC_NOTE = (
    "> **Architecture Model** — this document covers Sections 1–7 "
    "(system overview, diagrams, assets, attack surface, security architecture). "
    "The full threat model including STRIDE findings and mitigations will be "
    "available in `threat-model.md` after the assessment completes."
)


def render(
    contract_path: Path,
    output_dir: Path,
    *,
    fragments_subdir: str = ".fragments",
    strict: bool = True,
    document: str = "full",
    emit_progress: bool = False,
    embed_figures: bool = False,
    figure_basename: str = "figure1.svg",
) -> tuple[str, list[str]]:
    """Render threat-model.md (full) or analysis-model.md (architecture) from
    contract + yaml + fragments.

    ``document='architecture'`` renders only Sections 1-7 and uses a non-fatal
    fragment policy (lenient=True equivalent) — missing threat data is expected
    since Phase 9 has not run yet.

    When ``emit_progress`` is true, prints a ``COMPOSE: [k/N] rendering §<id>``
    line to stderr before each section render. Off by default so test/library
    callers do not leak progress noise; ``main()`` flips it on for CLI runs
    so the user sees live progress during the ~15–30 s render pass.

    Returns (rendered_markdown, warnings). Raises FragmentError / ContractError
    on failures.
    """
    contract = _fast_yaml_load(contract_path.read_text(encoding="utf-8"))
    if not isinstance(contract, dict) or "sections" not in contract:
        raise ContractError("contract file is missing required 'sections' block")

    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        raise FragmentError("root", f"{yaml_path} not found — run Phase 11 YAML step first")
    yaml_data = _fast_yaml_load(yaml_path.read_text(encoding="utf-8")) or {}
    # Defense in depth for direct composer use or legacy artifacts: the
    # builder and evidence backstop remove refuted candidates before writing
    # the final YAML, but an active report must stay clean even if either step
    # was bypassed. The merged intermediate remains the audit record.
    if isinstance(yaml_data, dict) and isinstance(yaml_data.get("threats"), list):
        yaml_data["threats"] = [
            threat
            for threat in yaml_data["threats"]
            if not (isinstance(threat, dict) and (threat.get("evidence_check") or "").strip().lower() == "refuted")
        ]
    # M-10c: Normalize threats[].title from em-dash form to paren form
    # ("SQL injection — routes/login.ts" → "SQL Injection (routes/login.ts)").
    # In-memory only — the on-disk yaml is left untouched so the schema
    # tightening (M-10a, future) can be staged behind this.
    _normalize_titles_paren_form(yaml_data, output_dir)

    triage_path = output_dir / ".triage-flags.json"
    triage: dict[str, Any] = {}
    if triage_path.is_file():
        try:
            triage = json.loads(triage_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass  # tolerate — fallback sort kicks in

    fragments_dir = output_dir / fragments_subdir

    # --- Reverse-index enrichment ----------------------------------------
    # The orchestrator writes component.threat_ids[] and mitigation.addresses[]
    # but sometimes omits the reverse links threat.component_id and
    # threat.mitigations[]. Compute them once here so every downstream renderer
    # (Top Findings, Findings Register, Mitigation Register) can count on them.
    _threats = yaml_data.get("threats") or []
    _components = yaml_data.get("components") or []
    _mitigations = yaml_data.get("mitigations") or []

    # Build reverse indexes.
    # 2026-05 R-1 fix: `threats[].component` (path-derived, written by
    # reclassify_components.py) is the canonical source of truth. The legacy
    # `components[].threat_ids[]` field is built by Stage 1 from STRIDE source
    # files and reflects sequential T-ID slicing per analyzer, which does NOT
    # survive reclassification. We therefore build the forward index from
    # `threats[].component` first; only when a threat lacks both `component`
    # and `component_id` do we fall back to the reverse index.
    tid_to_component: dict[str, str] = {}
    # Forward pass — read truth from threats[].component / .component_id.
    for t in _threats:
        if not isinstance(t, dict):
            continue
        tid = t.get("t_id") or t.get("id") or ""
        cid = (t.get("component") or t.get("component_id") or "").strip()
        if tid and cid:
            tid_to_component[tid] = cid
    # Fallback pass — only for threats neither field set, use the legacy
    # reverse index from components[].threat_ids[].
    for c in _components:
        if not isinstance(c, dict):
            continue
        cid = c.get("id") or ""
        for tid in c.get("threat_ids") or []:
            tid_to_component.setdefault(tid, cid)

    # Build mitigations → threats reverse index (M-NNN -> list of F/T-IDs).
    # Accepts any of: `addresses`, `threat_ids`, `mitigation_ids` (legacy).
    tid_to_mitigations: dict[str, list[str]] = {}
    for m in _mitigations:
        if not isinstance(m, dict):
            continue
        mid = m.get("m_id") or m.get("id") or ""
        for tid in m.get("addresses") or m.get("threat_ids") or []:
            tid_to_mitigations.setdefault(tid, []).append(mid)

    for t in _threats:
        if not isinstance(t, dict):
            continue
        tid = t.get("t_id") or t.get("id") or ""
        # 2026-05 R-1 fix: only back-fill component_id when BOTH `component`
        # and `component_id` are empty. If `component` is already set, it's
        # the authoritative path-derived value — preserve it and back-fill
        # component_id via the slug match below, not from the legacy reverse
        # index which would override with stale STRIDE-source values.
        if not t.get("component_id") and not t.get("component") and tid in tid_to_component:
            t["component_id"] = tid_to_component[tid]
        # Also resolve by component NAME (yaml often stores component: "Auth Service")
        # OR by component SLUG/ID directly (Phase-10b quick-depth runs write
        # `component: "backend-api"` -- the id itself -- without back-filling
        # `component_id`). Slug match wins over name match because component IDs
        # are unique and unambiguous.
        if t.get("component") and not t.get("component_id"):
            raw = (t["component"] or "").strip()
            for c in _components:
                if isinstance(c, dict) and (c.get("id") or "").strip() == raw:
                    t["component_id"] = c.get("id") or ""
                    break
            if not t.get("component_id"):
                for c in _components:
                    if isinstance(c, dict) and (c.get("name") or "").strip() == raw:
                        t["component_id"] = c.get("id") or ""
                        break
        # `mitigation_ids` → canonical `mitigations` slot used by renderer.
        if not (t.get("mitigations") or []):
            inline = t.get("mitigation_ids") or []
            if inline:
                t["mitigations"] = list(dict.fromkeys(inline))
            elif tid in tid_to_mitigations:
                t["mitigations"] = list(dict.fromkeys(tid_to_mitigations[tid]))

    # 2026-05 R-1 fix: rebuild components[].threat_ids[] from the canonical
    # threats[].component_id so the §2.3 Components table and the per-component
    # Linked-Threats cells reflect the post-reclassify truth. Without this,
    # the table renderer (_inject_components_table) reads stale STRIDE-source
    # buckets and renders findings under the wrong component.
    forward_index: dict[str, list[str]] = {}
    for t in _threats:
        if not isinstance(t, dict):
            continue
        tid = t.get("t_id") or t.get("id") or ""
        cid = (t.get("component_id") or t.get("component") or "").strip()
        if tid and cid:
            forward_index.setdefault(cid, []).append(tid)

    def _sort_tid_key(tid: str) -> tuple[int, str]:
        try:
            return (int(tid.split("-", 1)[1]), tid)
        except (IndexError, ValueError):
            return (10**9, tid)

    if forward_index:
        for c in _components:
            if not isinstance(c, dict):
                continue
            cid = c.get("id") or ""
            if cid in forward_index:
                # Sort by T-NNN numeric order so the rendered table is stable.
                c["threat_ids"] = sorted(set(forward_index[cid]), key=_sort_tid_key)
            elif "threat_ids" in c:
                # Component has stale threat_ids and no current threats point
                # at it (e.g. all reassigned away by reclassify) — clear the
                # list rather than leaving stale references in the rendered
                # Linked-Threats cell.
                c["threat_ids"] = []

    # Reverse: ensure mitigations[].addresses is populated (some yamls only
    # have the mitigation_ids on the threat side).
    for m in _mitigations:
        if not isinstance(m, dict):
            continue
        if m.get("addresses"):
            continue
        mid = m.get("m_id") or m.get("id") or ""
        back = []
        for t in _threats:
            if mid in (t.get("mitigations") or []) or mid in (t.get("mitigation_ids") or []):
                back.append(t.get("t_id") or t.get("id") or "")
        if back:
            m["addresses"] = list(dict.fromkeys(back))

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for t in yaml_data.get("threats", []) or []:
        sev = (t.get("risk") or t.get("severity") or "").strip().lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Load threat-category taxonomy once so lookups are O(1) (via module-level cache).
    cat_tax_raw = _load_taxonomy("threat-category-taxonomy.yaml")
    category_taxonomy: dict[str, dict[str, Any]] = {
        c.get("id", ""): c for c in (cat_tax_raw.get("categories") or []) if isinstance(c, dict) and c.get("id")
    }

    # §3 Attack Walkthroughs gate. `skip_attack_walkthroughs` is the depth/
    # config flag; the contract evaluates it for the §3 section-presence gate.
    # The required `sequenceDiagram` pattern, however, is only present when
    # walkthrough_renderer.py actually authored per-Critical blocks — i.e. when
    # walkthroughs are NOT skipped AND at least one Critical finding exists
    # (`select_walkthrough_picks` returns Criticals + `MAX_HIGH_WALKTHROUGHS`
    # Highs, currently 0). A zero-Critical run renders an intro-only §3 stub
    # with no diagram. The contract grammar (scripts/_safe_cond.py) has no
    # `and`/numeric operators, so combine both into one precomputed boolean the
    # contract references as a bare name for `required_patterns_condition`
    # (mirrors `has_multi_critical`).
    _skip_attack_walkthroughs = bool(_read_skill_config(output_dir).get("skip_attack_walkthroughs")) or (
        ((yaml_data.get("meta") or {}).get("assessment_depth") or "").strip().lower() == "quick"
    )
    _has_authored_walkthroughs = (not _skip_attack_walkthroughs) and severity_counts["critical"] >= 1

    ctx = RenderContext(
        output_dir=output_dir,
        contract=contract,
        yaml_data=yaml_data,
        triage=triage,
        fragments_dir=fragments_dir,
        embed_figures=embed_figures,
        figure_basename=figure_basename,
        severity_taxonomy={
            k: {kk: str(vv) for kk, vv in v.items()} for k, v in (contract.get("severity_taxonomy") or {}).items()
        },
        effectiveness_taxonomy={k: dict(v) for k, v in (contract.get("effectiveness_taxonomy") or {}).items()},
        category_taxonomy=category_taxonomy,
        eval_context={
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"],
            # Item 3 (2026-05-28): precomputed bool flag for the
            # `critical_attack_tree` section conditional. The contract
            # grammar (`scripts/_safe_cond.py`) does not support
            # numeric comparisons (`critical_count >= 2`) — precompute
            # the gate here so the contract can reference it as a bare
            # boolean.
            "has_multi_critical": severity_counts["critical"] >= 2,
            # category-level counts (active TH categories grouped by
            # their effective-severity). Used by §8.B sub-section
            # conditionals (e.g. `low_category_count > 0`).
            "low_category_count": _category_count_by_severity(_threats, category_taxonomy, "low"),
            "medium_category_count": _category_count_by_severity(_threats, category_taxonomy, "medium"),
            "high_category_count": _category_count_by_severity(_threats, category_taxonomy, "high"),
            "critical_category_count": _category_count_by_severity(_threats, category_taxonomy, "critical"),
            "verdict_severity": _verdict_severity_from_fragment(fragments_dir),
            "check_requirements": bool(yaml_data.get("meta", {}).get("check_requirements")),
            # Optional MS "Security Principles" systemic-posture table — true when
            # the weakness register is populated (weaknesses[] non-empty). Gates
            # the hoisted P4 verdict table so pre-register runs / clean repos with
            # no register render nothing (goldens unchanged).
            "has_weakness_register": bool(yaml_data.get("weaknesses")),
            # Optional MS "Architectural Anti-Patterns" callout — true when the
            # threat-renderer authored ms-anti-patterns.json (gated on presence;
            # the renderer also self-gates defensively).
            "has_anti_patterns": (fragments_dir / "ms-anti-patterns.json").is_file(),
            # Optional MS "AI / LLM Exposure" callout — true when the
            # threat-renderer authored ms-ai-exposure.json (gated on presence,
            # mirroring has_anti_patterns). The section itself renders via the
            # file-presence special-case path in _render_management_summary, so
            # this flag makes the contract's `has_llm_surface` condition real
            # (it was referenced but never populated) and future-proofs any
            # move to the generic condition-gated loop.
            "has_llm_surface": (fragments_dir / "ms-ai-exposure.json").is_file(),
            "verbose_report": bool(yaml_data.get("meta", {}).get("verbose_report")),
            # §6 use_cases removed 2026-05. Conditional retained as False so
            # any stale config that still references `has_use_cases` evaluates
            # to "skip" instead of throwing on KeyError.
            "has_use_cases": False,
            "triage_has_warnings": bool(triage.get("warnings")),
            # M2.14 — Sprint 6 conditional. True when the prior compose run
            # (or skill-level auto-retry) reported soft warnings, section
            # retries, or auto-retry cycles. Drives the §Composition Notes
            # appendix include/skip decision.
            "compose_warned": _compose_warned_signal(output_dir),
            # M2.15 — Sprint 7 conditional. True when .run-issues.json
            # reports run_status != "clean" (any errors / warnings /
            # perf anomalies / recovery events). Drives the §Run Issues
            # appendix include/skip decision.
            "run_warned": _run_warned_signal(output_dir),
            # §1 Identified Actors gate. The section now renders the consolidated
            # posture-actor taxonomy derived from finding `vektor` values (the
            # same set the Management Summary uses), so it is in scope exactly
            # when at least one finding carries a vektor. Legacy runs without
            # vektor data gracefully skip the section instead of failing the
            # contract. (Was file-based on .actors-resolved.json before the
            # 2026-07-05 taxonomy switch.)
            "has_resolved_actors": any(
                (t.get("vektor") or "").strip() for t in (yaml_data.get("threats") or []) if isinstance(t, dict)
            ),
            # Quick-mode §7 gate. False suppresses §7 in both TOC and body
            # (resolver returned `""` — current depth is quick and no rich
            # prior content was found). True keeps §7 — either via the
            # regular fragment render path (depth != quick) or via a
            # verbatim copy of the prior rich §7 (resolver returned a
            # non-empty string and stored it on ctx.security_arch_override).
            "render_security_architecture": True,
            # Quick-mode transparency. Drives the `quick_mode_notice`
            # banner rendered between Changelog and TOC, plus inline
            # depth notes elsewhere in the document.
            "is_quick_depth": (
                ((yaml_data.get("meta") or {}).get("assessment_depth") or "").strip().lower() == "quick"
            ),
            # Quick-depth skip flags. Plumbed in so the §3 / §9 section-presence
            # gates ("not skip_attack_walkthroughs", etc.) can be evaluated by
            # `eval_condition`. Sourced from .skill-config.json with a
            # depth-based default so legacy configs without the explicit
            # flag still behave correctly.
            "skip_attack_walkthroughs": _skip_attack_walkthroughs,
            # §3 required-pattern gate — True iff §3 actually carries per-Critical
            # `sequenceDiagram` blocks (not skipped AND ≥1 Critical). See the
            # precompute above; drives `required_patterns_condition` so a clean
            # report with zero Criticals no longer fails the missing-pattern check.
            "has_authored_walkthroughs": _has_authored_walkthroughs,
            "skip_attack_paths_authoring": bool(_read_skill_config(output_dir).get("skip_attack_paths_authoring")),
            "skip_qa": bool(_read_skill_config(output_dir).get("skip_qa")),
            # 13-section schema_v2 — the only supported §7 contract.
            "security_schema": _resolve_security_schema(output_dir),
        },
    )

    # Resolve quick-mode §7 override BEFORE the contract-driven render loop.
    # We do this after ctx construction so the resolver can read the same
    # output_dir the renderer uses.
    ctx.security_arch_override = _resolve_security_arch_override(
        output_dir,
        (yaml_data.get("meta") or {}).get("assessment_depth", ""),
        yaml_data.get("threats") or [],
    )
    # Empty-string override = skip; any other value (None | non-empty str)
    # keeps §7 rendered.
    ctx.eval_context["render_security_architecture"] = ctx.security_arch_override != ""

    env = _build_jinja_env(ctx)

    # Select the section order based on the document set.
    # Prefer the contract's `document_sets` block if present; fall back to
    # the hardcoded constants so old contracts (without document_sets) still work.
    doc_sets = contract.get("document", {}).get("document_sets", {})
    doc_set_cfg = doc_sets.get(document, {}) if doc_sets else {}

    if document == "architecture":
        section_order = doc_set_cfg.get("order") or _ARCHITECTURE_SECTIONS
        # Architecture render is always lenient — threat data does not exist yet.
        strict = False
        preamble = doc_set_cfg.get("preamble") or _ARCHITECTURE_TOC_NOTE
        title_template_override = doc_set_cfg.get("title_template")

    else:
        section_order = doc_set_cfg.get("order") or contract["document"]["order"]
        preamble = None
        title_template_override = doc_set_cfg.get("title_template")

    has_systemic_weakness_section = any(
        (item == "systemic_weaknesses") or (isinstance(item, dict) and item.get("id") == "systemic_weaknesses")
        for item in section_order
    )

    # Render each section in contract order.
    rendered_parts: list[str] = []

    # Normalise LLM-authored component refs (slug→C-NN) across ALL MS fragments
    # that carry them — ms-anti-patterns.json AND ms-ai-exposure.json — before
    # BOTH validation sites (the strict pre-pass directly below and the section
    # renderers). The renderer documents C-NN ids but sometimes emits the yaml
    # slug, which fails the schema and breaks the anchor (anti-patterns
    # 2026-06-12; ai-exposure 2026-06-21 juice-shop compose aborts).
    _normalize_ms_component_refs(ctx)

    _validate_known_json_fragments(ctx)

    title = _render_title(ctx, title_template_override=title_template_override)
    rendered_parts.append(title)
    if preamble:
        rendered_parts.append(preamble.rstrip())

    # Pre-compute the effective section count (after condition gates) so the
    # progress prefix shows a stable `[k/N]` instead of jumping around.
    def _passes_cond(raw):
        _cond = None if isinstance(raw, str) else raw.get("condition")
        return (not _cond) or eval_condition(_cond, ctx.eval_context)

    total_sections = sum(1 for raw in section_order if _passes_cond(raw))
    progress_idx = 0
    ctx.render_manifest = []
    for raw in section_order:
        sid, cond = (raw, None) if isinstance(raw, str) else (raw["id"], raw.get("condition"))
        if cond and not eval_condition(cond, ctx.eval_context):
            # Condition false → section intentionally absent. Recorded as
            # out-of-scope so it never counts against report integrity.
            ctx.render_manifest.append(_manifest_entry(sid, in_scope=False, outcome="skipped_conditional"))
            continue
        section = contract["sections"].get(sid)
        if not section:
            if document == "architecture":
                ctx.warnings.append(f"architecture section {sid!r} not in contract — skipped")
                ctx.render_manifest.append(_manifest_entry(sid, in_scope=False, outcome="not_in_contract"))
                continue
            raise ContractError(f"document.order references unknown section id: {sid!r}")
        progress_idx += 1
        if emit_progress:
            try:
                sys.stderr.write(f"COMPOSE: [{progress_idx}/{total_sections}] rendering §{sid}\n")
                sys.stderr.flush()
            except OSError:
                pass
        degraded = False
        try:
            body = _render_by_id(ctx, env, sid, section)
        except FragmentError:
            if strict:
                raise
            body = (
                f"> ⚠ **Renderer:** Section `{sid}` could not be rendered. "
                f"Its data fragment is missing or schema-invalid.\n"
            )
            ctx.warnings.append(f"soft-skip section {sid}")
            degraded = True
        # Record the render outcome for .render-integrity.json. Classification
        # is driven by what actually reached the report, NOT by fragment
        # presence — `_SECTION_FRAGMENT_MAP` lists fragments a section *may*
        # consume, several of which are optional enrichments (e.g.
        # compound-chains.json enriches the otherwise yaml-computed threat
        # register). So a non-empty body is `rendered` even if an optional
        # fragment was absent. Outcomes:
        #   degraded — lenient soft-skip above (fragment missing / schema-invalid)
        #   empty    — in-scope section produced no body (a real content gap)
        #   fallback — body rendered via a sanctioned deterministic fallback
        #              for an absent fragment (still complete, but flagged)
        #   rendered — normal, content present
        expected, present, fallback_eligible = _section_fragment_status(ctx, sid)
        missing = [n for n in expected if n not in present]
        if degraded:
            outcome = "degraded"
        elif not body.strip():
            outcome = "empty"
        elif not _section_substance_ok(ctx, sid, body):
            # Section emitted only boilerplate (heading + preamble) despite
            # upstream data that should have produced content — a real gap the
            # byte check misses. Treat as empty so report_integrity_ok flips and
            # the QA repair loop fires. (2026-06-26)
            outcome = "empty"
            ctx.warnings.append(f"section {sid} rendered only boilerplate (no substance)")
        elif missing and fallback_eligible:
            outcome = "fallback"
        else:
            outcome = "rendered"
        ctx.render_manifest.append(
            _manifest_entry(sid, in_scope=True, outcome=outcome, expected=expected, present=present)
        )
        if body.strip():
            rendered_parts.append(body.rstrip())
            # Backward-compatible rendering for a persisted v4 contract. New
            # contracts declare this computed chapter explicitly in their order.
            if sid == "management_summary" and not has_systemic_weakness_section and document != "architecture":
                weakness_chapter = _render_systemic_weaknesses(ctx)
                if weakness_chapter:
                    rendered_parts.append(weakness_chapter.rstrip())

    separator = contract["document"].get("section_separator", "\n\n---\n\n")
    rendered = separator.join(rendered_parts).rstrip() + "\n"

    # Unfilled-placeholder notice — for any top-level section that still
    # carries unfilled `<!-- NARRATIVE_PLACEHOLDER -->` HTML comments,
    # prepend a one-line callout right after the heading so the reader
    # knows the gap exists and is not a renderer bug. Runs at ALL depths:
    # at quick depth this is by-design (placeholder strip only covers
    # §7.4-§7.12); at standard/thorough it signals an enrichment failure
    # (ENRICH_ARCH_FRAGMENTS was off or Stage 2 did not complete the fill).
    # HTML comments are kept (invisible in rendered output) so a re-run
    # with --enrich-arch can fill them in-place.
    depth_val = ((ctx.yaml_data.get("meta") or {}).get("assessment_depth") or "quick").lower()
    rendered = _annotate_quick_mode_gaps(rendered, depth=depth_val)

    # F1.4 — surface a compose-stats warning when any NARRATIVE_PLACEHOLDER
    # comment survived into the final render. _annotate_quick_mode_gaps
    # already adds a user-visible callout, but compose-stats / .compose-stats.json
    # had no signal — making this invisible to CI and to /appsec-advisor:status.
    # Only emit at standard/thorough depth; at quick the surviving placeholders
    # are by design (LLM enrichment off) and adding a warning there would be
    # noise rather than signal.
    if not ctx.eval_context.get("is_quick_depth"):
        surviving_placeholders = rendered.count("<!-- NARRATIVE_PLACEHOLDER")
        if surviving_placeholders:
            ctx.warnings.append(
                f"NARRATIVE_PLACEHOLDER: {surviving_placeholders} unfilled placeholder(s) "
                f"survived into final markdown — section narrative is incomplete "
                f"(Stage 2 did not fill; re-run with --enrich-arch or --thorough)"
            )

    # When §7 was skipped (quick depth, no rich prior), strip the MS template
    # cross-references that would otherwise emit dead links into a missing
    # section. The architecture-assessment and operational-strengths Jinja
    # templates hardcode "See [Section 7](#7-security-architecture)" and
    # "filtered view of [Section 7](...)" sentences; cleanest fix is to
    # remove them post-render rather than thread the flag through every
    # template.
    if not ctx.eval_context.get("render_security_architecture", True):
        rendered = _strip_section7_crossrefs(rendered)

    # F3.1 — Mermaid edge-label safety pass. Auto-quote unsafe edge labels
    # (containing :, --, ', ", parens) in flowchart/graph blocks so the
    # rendered diagrams parse consistently across mermaid versions. Runs
    # AFTER section composition so it sees the final block content, and
    # BEFORE secret masking so masked tokens are not split across labels.
    rendered, mermaid_rewrites = _quote_mermaid_edge_labels(rendered)
    if mermaid_rewrites:
        ctx.warnings.append(
            f"mermaid edge-label auto-quoted: {mermaid_rewrites} unsafe label(s) "
            f'wrapped with "..." to prevent parser ambiguity'
        )

    # Final secret-masking pass — redact credential-shaped strings before
    # the markdown leaves the renderer. This is defensive: the LLM should
    # not have emitted raw secrets in the first place, but hardcoded-key
    # discussions in mitigation `how` / `verification` fields sometimes
    # quote the literal bytes. The mask is idempotent — re-rendering a
    # masked document produces the same masked output.
    rendered, masks = _mask_secrets(rendered)
    if masks:
        ctx.warnings.append(
            f"secret-mask applied: {', '.join(sorted(set(masks)))} "
            f"— credential-shaped strings were redacted to <REDACTED> placeholders"
        )

    # Final dollar-operator escape — catch `$where`/`$ne`/etc. that arrived
    # via computed-section data (threat titles, mitigation labels). The
    # per-markdown-fragment pass only covers markdown fragments; computed
    # sections go through their own Jinja templates and bypass it.
    rendered = _escape_dollar_operators(rendered)

    # Wrap unescaped `<script>` / `<img onerror=…>` attacker-payload tags
    # in inline backticks so the rendered HTML/PDF report does not interpret
    # them as live HTML elements (the report would otherwise become its own
    # XSS sink — see _escape_html_payloads_in_prose for the full rationale).
    # MUST run at the global pipeline (not per-section) because the §8
    # Findings Register cells with attacker payloads live inside a computed
    # section that bypasses _render_markdown_fragment.
    rendered = _escape_html_payloads_in_prose(rendered)

    # Neutralise TLD-shaped brand tokens (Socket.IO, Node.js, …) across the
    # WHOLE document — not just markdown fragments. `_render_markdown_fragment`
    # already runs this per-fragment, but COMPUTED sections (the Mitigation
    # Register / Top Mitigations, component tables, …) bypass it, so a
    # mitigation title like "Attach JWT to Socket.IO handshake" shipped with
    # `Socket.IO` auto-linked by GFM (user report 2026-06). Idempotent — an
    # already-escaped `Socket\.IO` is not re-matched; fenced code/links/comments
    # are skipped.
    rendered = _apply_outside_changelog(rendered, _fold_code_strings_in_prose)
    rendered = _escape_dot_tld_identifiers(rendered)

    # Final em-dash normalization — convert " — " (U+2014 surrounded by
    # spaces) to " - " (ASCII hyphen) outside fenced code blocks. Em dashes
    # are the single most visible "this was AI-written" signal in the
    # rendered document; replacing them everywhere prose flows keeps tables,
    # link labels, callouts, and LLM-authored paragraphs in a consistent
    # style. Code fences are skipped so any em-dash that lives inside a
    # source snippet (rare, but possible for prose comments inside code)
    # is preserved verbatim.
    rendered = _normalize_emdashes(rendered)

    # §7 readability passes (2026-05-30 user request):
    #  - number the H4 control sub-controls (7.X.N) and render `Controls
    #    covered` as a bullet list;
    #  - reduce inline finding references in §7 prose to ID-only links (the
    #    titled enumeration stays in each control's `Relevant findings` block).
    rendered = _section7_number_and_bulletize(rendered)
    rendered = _section7_inline_findings_id_only(ctx, rendered)
    # Title the finding links inside §7 bullets (Relevant findings) so they
    # carry the same short register title as §5/§8 — must run AFTER the
    # id-only pass, which deliberately skips bullets expecting them titled.
    rendered = _section7_title_relevant_findings(ctx, rendered)

    # Section cross-reference linkifier — convert bare `§N` / `§N.M` / `§N.M.K`
    # tokens in prose into anchor-linked form so cross-references are clickable.
    # MUST run AFTER _section7_number_and_bulletize: that pass RENUMBERS the §7
    # H4 sub-controls (an un-numbered opener like "Threat Hypotheses Requiring
    # Validation" shifts the LLM-authored 7.2.1…7.2.N by one). Running the
    # linkifier earlier built its number→slug map from the stale pre-renumber
    # headings, so a prose `(§7.2.2)` linked to the fragment's 7.2.2 (OAuth)
    # while the final document renumbered 7.2.2 to Password-Based — a dangling,
    # mislabeled anchor (juice-shop 2026-07-02). Building the map here, after
    # renumbering, resolves both the number and the anchor correctly.
    rendered = _linkify_section_refs(rendered)

    # General table compaction — proportional column widths on every table so
    # description columns stop crowding out finding/link columns and short IDs
    # are not broken across lines. Runs last so it sees the final table set.
    rendered = _normalize_table_column_widths(rendered)

    # Soft-wrap long prose table cells so the markdown-it preview (VS Code /
    # GitHub) — which ignores the proportional separator widths above — stops
    # giving Description / narrative columns most of the table and clipping the
    # finding/link columns. PDF/HTML (Pandoc) keep the proportional `<col>`
    # widths; this only reshapes the raw-md preview.
    rendered = _softwrap_prose_table_cells(rendered)

    # Final safety net — collapse any `[ID](#id) — Label - Label` doubling that
    # an upstream re-label pass may have produced (see _dedupe_doubled_id_labels).
    rendered = _dedupe_doubled_id_labels(rendered)

    # GLOBAL annotation retrofit — prefix every `[F-NNN](#f-nnn)` with its
    # severity dot and every `[M-NNN](#m-nnn)` with its priority circle, across
    # the WHOLE document. Runs dead last so it sees the final ref forms after
    # all T-NNN → F-NNN rewrites and section-ref linkification — this is the only
    # point where §3 Attack Walkthroughs (`**Source:**` lines, rewritten from
    # [T-NNN] late) and §9 Abuse Cases (bare chips from render_abuse_cases.py)
    # carry their final `[F-NNN]` / `[M-NNN]` form. Idempotent: the regex `dot`
    # / `circ` groups tolerate `&nbsp;` / bullet separators, so already-annotated
    # refs in §1/§2/§8/§10 and the computed tables are left untouched.
    # Global backstop — normalise any stray visible T-NNN → F-NNN BEFORE the
    # dot retrofit, so the dots key off the final F-NNN link form and no
    # reader-facing T-NNN survives (link text, mermaid labels, or prose).
    rendered = _normalize_visible_threat_ids(rendered)
    # Linkify finding refs that LLM prose left as plain text (bare `F-012`,
    # component-scoped `auth-001`) BEFORE the dot retrofit so the new links get
    # their severity glyph too.
    rendered = _apply_outside_changelog(rendered, lambda s: _linkify_bare_finding_refs(ctx, s))
    rendered = _apply_outside_changelog(
        rendered,
        lambda s: _prepend_mitigation_prio_circles(ctx, _prepend_finding_severity_dots(ctx, s)),
    )
    # Backtick inline code the LLM left un-marked across all prose (after the
    # ref/dot passes so it never wraps a freshly-built link's anchor).
    rendered = _apply_outside_changelog(rendered, _codify_inline_code_in_prose)
    # Final, authoritative locator normalisation — runs AFTER every section
    # render, fragment injection, and T→F bridge, so any reference-trailing
    # `(path/file:line)` (incl. §3/§9 and MS leaderboard cells produced past the
    # per-section pass) ends up backticked + basenamed exactly once.
    rendered = _apply_outside_changelog(rendered, _normalize_reference_locators)

    # Report-integrity manifest: certify which sections rendered and which
    # fragments were wired, surfaced on the console and consumed by the QA
    # agent / aggregate_run_issues to react to a structurally broken model.
    integrity = _compute_integrity(ctx.render_manifest)
    _write_render_integrity(output_dir, integrity)
    _emit_render_integrity_marker(integrity)

    return rendered, ctx.warnings


_STRIDE_TO_TH_FALLBACK = {
    "tampering": "TH-01",
    "spoofing": "TH-02",
    "repudiation": "TH-16",
    "information disclosure": "TH-17",
    "denial of service": "TH-12",
    "elevation of privilege": "TH-06",
}

# Keyword → TH-NN heuristic. Used when the yaml doesn't carry an explicit
# `threat_category_id` field. ORDER MATTERS — the first match wins, so more
# specific keywords come before generic ones. This list MUST be the single
# source of truth; both _render_threat_register and _compute_top_findings_rows
# call `infer_threat_category` below to stay consistent.
_CATEGORY_KEYWORD_MAP: list[tuple[list[str], str]] = [
    (["sql injection", "nosql", "xxe", "injection", "template injection", "sandbox escape"], "TH-01"),
    (
        [
            "alg:none",
            "jwt bypass",
            "jwt algorithm",
            "algorithm confusion",
            "token forgery",
            "2fa",
            "totp",
            "authentication bypass",
        ],
        "TH-02",
    ),
    (
        [
            "md5",
            "bcrypt",
            "rsa private key",
            "hardcoded key",
            "hardcoded rsa",
            "weak hash",
            "cryptograph",
            "stored without encryption",
            "plaintext storage",
            "cleartext",
            "unencrypted storage",
        ],
        "TH-03",
    ),
    (["localstorage", "session storage"], "TH-04"),
    ([" rce ", "remote code execution", "vm.run", "notevil", "runinsandbox"], "TH-05"),
    (
        ["idor", "mass assignment", "mass update", "ownership bypass", "broken access", "admin role", "authorization"],
        "TH-06",
    ),
    (["file upload", "path traversal", "zip slip", "yaml bomb", "local file read", "file read via"], "TH-07"),
    (["ssrf", "server-side request forgery"], "TH-08"),
    (["/ftp", "/encryptionkeys", "/support/logs", "unauthenticated", "metrics endpoint"], "TH-09"),
    (["xss", "domsanitizer", "bypasssecuritytrust"], "TH-11"),
    (["denial of service", "rate limit", "rate-limit", "dos", "event loop"], "TH-12"),
    (["csrf"], "TH-15"),
    (["cors misconfiguration", "cors allows", "wildcard cors"], "TH-09"),
    (["supply chain", "dependabot", "outdated dep"], "TH-14"),
    (["audit", "logging", "security event"], "TH-16"),
    (["stack trace", "error response", "error disclos"], "TH-17"),
    (["redirect"], "TH-18"),
]


@functools.lru_cache(maxsize=1)
def _build_cwe_to_th_map() -> dict[str, str]:
    """Load the deterministic CWE → TH-NN mapping from the curated YAML data.

    Source of truth (in priority order):

      1. ``cwe_to_th:`` block at the top level of
         ``data/threat-category-taxonomy.yaml`` — the curated, hand-reviewed
         map maintained alongside the TH definitions. Each value is a list
         ``[primary_TH, secondary_TH, …]``; we take the **primary** (first
         entry) as the canonical category. This is the single source of
         truth that supersedes the OWASP-bridge heuristic.
      2. Fallback derivation from ``categories[].cwe_canonical`` + ``cwe_top25_members``
         when ``cwe_to_th:`` is absent or doesn't cover a CWE — used so a
         brand-new CWE added to a TH definition still maps without an
         explicit ``cwe_to_th`` entry.

    Used by ``infer_threat_category`` to assign TH-NN to a finding before
    any keyword heuristic. CWE-321 (hardcoded crypto key) → TH-03
    Cryptographic Failures, regardless of whether the title says "RSA
    private key" or "JWT signing secret".
    """
    cwe_to_th: dict[str, str] = {}
    th_path = PLUGIN_ROOT / "data" / "threat-category-taxonomy.yaml"
    try:
        th_raw = yaml.safe_load(th_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}

    # Step 1 — curated cwe_to_th block (primary, supersedes anything else).
    curated = th_raw.get("cwe_to_th") or {}
    if isinstance(curated, dict):
        for raw_cwe, th_list in curated.items():
            cwe_norm = _normalize_cwe(raw_cwe)
            if not cwe_norm:
                continue
            if isinstance(th_list, list) and th_list:
                primary = str(th_list[0]).strip().upper()
                if primary.startswith("TH-"):
                    cwe_to_th[cwe_norm] = primary
            elif isinstance(th_list, str):
                primary = th_list.strip().upper()
                if primary.startswith("TH-"):
                    cwe_to_th[cwe_norm] = primary

    # Step 2 — fill gaps from cwe_canonical / cwe_top25_members on each TH
    # category (so a new CWE added to a TH definition still maps when the
    # curator hasn't mirrored it into the cwe_to_th block yet). Uses
    # setdefault so curated entries always win.
    for cat in th_raw.get("categories") or []:
        if not isinstance(cat, dict):
            continue
        th_id = (cat.get("id") or "").strip().upper()
        if not th_id.startswith("TH-"):
            continue
        for k in ("cwe_canonical",):
            cwe = cat.get(k)
            if cwe:
                cwe_to_th.setdefault(_normalize_cwe(cwe), th_id)
        for cwe in cat.get("cwe_top25_members") or []:
            cwe_to_th.setdefault(_normalize_cwe(cwe), th_id)

    return cwe_to_th


def _normalize_cwe(value: object) -> str:
    """Normalize a CWE reference to canonical `CWE-NNN` form. Accepts integer,
    `321`, `CWE-321`, `cwe-321`. Empty/invalid → empty string."""
    if value is None:
        return ""
    s = str(value).strip()
    if not s:
        return ""
    if s.lower().startswith("cwe-"):
        s = s.split("-", 1)[1]
    s = s.lstrip("0") or "0"
    return f"CWE-{s}"


def infer_threat_category(t: dict, taxonomy: dict[str, dict]) -> str:
    """Map a threat record → canonical TH-NN. Shared between Top Findings and
    §8 Findings Register so the same threat always lands under the same
    category anchor.

    Resolution order:

      1. Explicit ``threat_category_id`` / ``category_id`` field in yaml.
      2. **CWE → TH lookup** (deterministic, from
         `threat-category-taxonomy.yaml` + `owasp-top10-cwes.yaml`). Replaces
         the old string-substring heuristic for the common case where a
         finding carries a CWE ID — CWE-321 always maps to TH-03 regardless
         of how the title is worded.
      3. Title-first keyword heuristic (legacy).
      4. Full-text keyword heuristic (legacy).
      5. STRIDE → TH fallback.
    """
    # CWE → TH deterministic lookup runs FIRST — the CWE is a precise,
    # authoritative classification; the stored ``threat_category_id`` is a
    # coarse LLM tag that is frequently wrong (observed: a CWE-89 SQLi tagged
    # TH-10 OAuth/OIDC, a CWE-611 XXE tagged TH-13). When a curated CWE→TH
    # entry exists it supersedes the stored id, so the ``**Classification:**``
    # label + OWASP mapping stay consistent with the CWE. CWE-321 (hardcoded
    # crypto key) → TH-03 regardless of how the title is worded.
    cwe_norm = _normalize_cwe(t.get("cwe") or t.get("cwe_id"))
    if cwe_norm:
        cwe_map = _build_cwe_to_th_map()
        mapped = cwe_map.get(cwe_norm)
        if mapped and (not taxonomy or mapped in taxonomy):
            return mapped
    # Stored category id — trusted only when the CWE is absent or unmapped.
    cid = t.get("threat_category_id") or t.get("category_id") or t.get("_category")
    if cid and cid in taxonomy:
        return cid
    # Title-first pass: match against the short title only to avoid spurious
    # category assignments caused by attack-vector references in the description
    # (e.g. "…exploitable via sql injection" in a crypto-failure finding).
    title_only = (t.get("title") or t.get("scenario_short") or "").lower()
    for keys, cat in _CATEGORY_KEYWORD_MAP:
        for k in keys:
            if k in title_only:
                return cat
    # Full-text pass: title + description together.
    haystack = " ".join(
        [
            (t.get("scenario") or t.get("description") or "").lower(),
            title_only,
        ]
    )
    for keys, cat in _CATEGORY_KEYWORD_MAP:
        for k in keys:
            if k in haystack:
                return cat
    stride = (t.get("stride") or t.get("stride_category") or "").strip().lower()
    return _STRIDE_TO_TH_FALLBACK.get(stride, "TH-01")


def _category_count_by_severity(
    threats: list[dict],
    taxonomy: dict[str, dict],
    severity: str,
) -> int:
    """Count the number of TH-NN categories whose *effective* severity equals
    `severity`. A category's effective severity is the highest severity
    among its member threats. Used by §8 TOC conditional evaluation."""
    if not threats:
        return 0
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    target = rank.get((severity or "").lower(), 99)
    by_cat: dict[str, int] = {}
    for t in threats:
        cat = infer_threat_category(t, taxonomy)
        sev = (t.get("risk") or t.get("severity") or "").lower()
        sr = rank.get(sev, 99)
        by_cat[cat] = min(by_cat.get(cat, 99), sr)
    return sum(1 for sr in by_cat.values() if sr == target)


def _verdict_severity_from_fragment(fragments_dir: Path) -> str:
    path = fragments_dir / "ms-verdict.json"
    if not path.is_file():
        return "yellow"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("severity", "yellow")
    except (OSError, json.JSONDecodeError):
        return "yellow"


_LOGO_EXTS = {".png", ".jpg", ".jpeg", ".svg", ".gif", ".webp"}
_BRANDING_LOGO_STEM = "branding-logo"
_LOGO_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB ceiling on a cover logo


def _load_branding(ctx: RenderContext) -> dict:
    """Read cover-branding fields the skill persisted in ``.skill-config.json``.

    Mirrors the ``embed_figures`` pattern: the renderer / recompose /
    fragment-fixer paths all read the resolved choice from the sidecar rather
    than threading a CLI flag through each call site. Returns an empty dict
    when the sidecar is absent or unreadable.
    """
    try:
        sc = json.loads((ctx.output_dir / ".skill-config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(sc, dict):
        return {}
    return {k: sc.get(k) for k in ("report_title", "contact_name", "contact_email", "logo")}


def _clean_cell(value: Any) -> str | None:
    """Normalise a config-supplied string for a Markdown table cell.

    Collapses whitespace and escapes the pipe so a stray ``|`` in a contact
    field cannot break the infobox table. Org-profile/CLI text is semi-trusted
    config, not scanned repo content, but this keeps the table well-formed.
    """
    if not value:
        return None
    s = " ".join(str(value).split()).replace("|", "\\|")
    return s or None


def _stage_branding_logo(ctx: RenderContext, logo: str | None) -> str | None:
    """Stage a cover logo into the output dir; return its relative filename.

    ``logo`` is an absolute local file path or an ``http(s)`` URL (relative
    paths are resolved to absolute by resolve_config / resolve_org_profile
    before they reach the sidecar). The asset lands at
    ``<output_dir>/branding-logo.<ext>`` — a sibling of ``figure1.svg`` — so
    ``export_pdf.stage_relative_images`` embeds it and the published Markdown
    references it relatively.

    Fail-safe: any copy/fetch error (offline, 404, oversized, unreadable)
    returns ``None`` and the cover renders without a logo rather than aborting
    the run.
    """
    if not logo or not str(logo).strip():
        return None
    logo = str(logo).strip()

    ext = Path(logo.split("?", 1)[0].split("#", 1)[0]).suffix.lower()
    if ext not in _LOGO_EXTS:
        ext = ".png"
    dest = ctx.output_dir / f"{_BRANDING_LOGO_STEM}{ext}"
    is_url = bool(re.match(r"^https?://", logo, re.IGNORECASE))

    try:
        if is_url:
            if dest.exists():
                return dest.name  # cached — avoid refetch on every compose pass
            # SSRF / cloud-metadata defence on the user-supplied logo URL —
            # same guard the requirements/related-repo fetchers use.
            from _url_guard import validate_target_url

            verdict = validate_target_url(logo)
            if not verdict.ok:
                return None
            import urllib.request

            req = urllib.request.Request(logo, headers={"User-Agent": "appsec-advisor"})
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 (scheme checked above)
                data = resp.read(_LOGO_MAX_BYTES + 1)
            if not data or len(data) > _LOGO_MAX_BYTES:
                return None
            dest.write_bytes(data)
        else:
            import shutil

            src = Path(logo).expanduser()
            if not src.is_file() or src.stat().st_size > _LOGO_MAX_BYTES:
                return None
            shutil.copy2(src, dest)  # local copy is cheap — always refresh
    except Exception:
        # Cosmetic asset: never let a logo failure fail the render.
        try:
            if dest.exists():
                dest.unlink()
        except OSError:
            pass
        return None
    return dest.name


def _render_title(ctx: RenderContext, *, title_template_override: str | None = None) -> str:
    """Render the document `# Threat Model — <Project Name>` header.

    Shares the project-name derivation with `_render_infobox` via
    `_derive_project_name()` so the title and the infobox never disagree.

    Emits a one-line italic subtitle directly under the H1 naming the
    plugin version that produced the report (e.g. `_Generated by
    appsec-advisor v0.4.0-beta (analysis v3)_`). The same value also
    appears in the §Appendix Run Statistics row, but readers shouldn't
    have to scroll to the bottom to learn which tool version emitted
    the artefact. Falls back to title-only when plugin.json is
    unreadable.
    """
    branding = _load_branding(ctx)
    report_title = (branding.get("report_title") or "").strip()
    project = ctx.yaml_data.get("project")
    if not isinstance(project, dict):
        project = {}
    project.setdefault("name", _derive_project_name(ctx))

    if report_title and title_template_override is None:
        # Keep the `— <Project Name>` suffix. Do NOT route the config-supplied
        # report_title through a Jinja template — treat it as data, not a
        # template (an embedded `{{ ... }}` must render literally).
        title = f"{report_title} — {project['name']}"
    else:
        title_tpl = title_template_override or ctx.contract["document"].get("title_template", "Threat Model")
        env = jinja2.Environment(autoescape=False)
        title = env.from_string(title_tpl).render(project=project)

    plugin_v: str | None = None
    analysis_v: int | None = None
    try:
        plugin_v, analysis_v = _read_live_plugin_meta()
    except Exception:
        pass
    if not plugin_v:
        meta = ctx.yaml_data.get("meta") or {}
        plugin_v = meta.get("plugin_version") or None
        if analysis_v is None:
            av = meta.get("analysis_version")
            if isinstance(av, int):
                analysis_v = av

    # Cover logo (optional). Placed inside the title block so export_pdf's
    # cover-page wrap (<h1>…<h2>) includes it; staged as a sibling asset.
    logo_rel = _stage_branding_logo(ctx, branding.get("logo"))
    logo_md = f"\n![]({logo_rel})\n" if logo_rel else ""

    if plugin_v:
        suffix = f" (analysis v{analysis_v})" if analysis_v else ""
        subtitle = f"_Generated by appsec-advisor v{plugin_v}{suffix}_\n"
        return f"# {title}\n\n{subtitle}{logo_md}"
    return f"# {title}\n{logo_md}"


def _derive_project_name(ctx: RenderContext) -> str:
    """Find a usable project name across yaml fields / package.json /
    git remote / output dir path. Prefer package.json over git-slug so the
    displayed name is a polished `Juice Shop` rather than the raw slug
    `juice-shop`.
    """
    p = ctx.yaml_data.get("project") if isinstance(ctx.yaml_data.get("project"), dict) else {}
    if p.get("name"):
        return p["name"]
    for key in ("project_name",):
        if ctx.yaml_data.get(key):
            return ctx.yaml_data[key]
    meta = ctx.yaml_data.get("meta") or {}
    if meta.get("project_name"):
        return meta["project_name"]
    pkg = _read_package_json(ctx)
    if pkg.get("name"):
        name = pkg["name"]
        if "/" in name:  # scoped package like @owasp/juice-shop — keep as-is
            return name
        return name.replace("-", " ").replace("_", " ").title()
    remote = (meta.get("git") or {}).get("remote_url") or ""
    if remote:
        m = re.search(r"[/:]([^/]+?)(?:\.git)?/?$", remote)
        if m:
            slug = m.group(1)
            return slug.replace("-", " ").replace("_", " ").title()
    try:
        return ctx.output_dir.parent.name or "Unknown Project"
    except Exception:
        return "Unknown Project"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="compose_threat_model.py",
        description="Contract-driven renderer for threat-model.md. "
        "Composes the final Markdown from threat-model.yaml + "
        "schema-validated data fragments, making LLM structural "
        "drift impossible.",
    )
    p.add_argument(
        "--contract",
        type=Path,
        default=DEFAULT_CONTRACT,
        help=f"Path to sections contract YAML (default: {DEFAULT_CONTRACT}).",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Assessment output directory containing threat-model.yaml and .fragments/.",
    )
    p.add_argument(
        "--fragments-subdir", default=".fragments", help="Sub-directory under --output-dir where LLM fragments live."
    )
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Where to write the rendered Markdown (default: <output-dir>/threat-model.md).",
    )
    p.add_argument(
        "--lenient",
        action="store_true",
        help="Do not abort on a missing fragment; emit a visible stub instead. "
        "Implies strict=False. Not recommended outside development.",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Abort on missing fragment or schema violation (default since M3.0). "
        "Accepted for explicit invocations (e.g. from .qa-repair-plan.json "
        "re_render_command). Ignored when --lenient is also set — --lenient "
        "always wins.",
    )
    p.add_argument("--dry-run", action="store_true", help="Write to stdout, do not touch the filesystem.")
    p.add_argument(
        "--embed-figures",
        action="store_true",
        help="Also embed Figure 1 inline in the Markdown as a base64 data:image URI "
        "(self-contained doc). figure1.svg is still written. Note: GitHub strips "
        "data: URIs, so the default file reference is best for GitHub-hosted models.",
    )
    p.add_argument(
        "--document",
        choices=["full", "architecture"],
        default="full",
        help="Which document set to render. 'full' renders the complete "
        "threat-model.md (default). 'architecture' renders only the "
        "architecture sections (1-7) as analysis-model.md — this is "
        "available after Phase 8, before STRIDE analysis completes.",
    )
    args = p.parse_args(argv)
    if args.lenient and args.strict:
        # --lenient wins; warn so an automation script sees the override.
        print("COMPOSE_WARN: both --strict and --lenient passed; --lenient wins", file=sys.stderr)
    return args


_SUBSECTION_MISSING_RE = re.compile(r"required subsection missing: '(.+?)'")


def _fragment_error_hint(err: FragmentError) -> str:
    """Turn a FragmentError into a short actionable hint.

    Pre-cooked for the common cases: missing required subsection (numbering
    drift), missing required pattern, fragment header mismatch. The hint is
    appended to stderr so a human reader (and the orchestrator's next turn)
    sees exactly which fragment to edit.
    """
    fragments = _SECTION_FRAGMENT_MAP.get(err.section_id, [])
    target = fragments[0] if fragments else ""
    missing = _SUBSECTION_MISSING_RE.search(err.detail)
    if missing and target:
        return (
            f"edit `{target}` so it contains the exact heading "
            f"{missing.group(1)!r}. Do NOT touch other fragments — "
            "the error is localised to this one."
        )
    if target:
        return f"edit `{target}` to address the issue; other fragments are not the cause."
    return ""


_PRE_RENDER_REPAIR_MAX_ATTEMPTS = 3


def _emit_pre_render_repair_plan(output_dir: Path, err: FragmentError) -> int:
    """Write `.pre-render-repair-plan.json` so the orchestrator knows exactly
    which fragment to fix when compose aborts.

    Mirrors the post-render `.qa-repair-plan.json` contract: a single
    `actions[]` entry with `type`, `section_id`, `fragments_to_rewrite`,
    `remediation`. Unlike the post-render plan, this one is emitted BEFORE
    any `threat-model.md` exists — it is the signal to the orchestrator's
    re-render loop that the fragment layer is where the fix goes.

    Returns the current attempt count. When the count exceeds
    `_PRE_RENDER_REPAIR_MAX_ATTEMPTS`, the plan's `status` is set to
    `exhausted` and the caller should exit with a non-recoverable code so
    the orchestrator escalates instead of looping on the same fragment
    forever. The attempt counter is read from any existing repair plan
    on disk (previous failed compose attempts), incremented, and written
    back — so repeated invocations with the same failure accumulate
    toward the cap.
    """
    import datetime as _dt
    import json as _json

    try:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return 0  # best-effort; silent on IO failure

    # Read attempt counter from any prior repair plan so successive compose
    # failures accumulate. A fresh run starts at attempt=1 because the
    # skill-level wipe removes stale repair plans before Phase 11.
    plan_path = output_dir / ".pre-render-repair-plan.json"
    prior_attempts = 0
    try:
        if plan_path.exists():
            prior = _json.loads(plan_path.read_text(encoding="utf-8"))
            prior_attempts = int(prior.get("attempt", 0) or 0)
    except (OSError, ValueError, _json.JSONDecodeError):
        prior_attempts = 0
    attempt = prior_attempts + 1

    fragments = _SECTION_FRAGMENT_MAP.get(err.section_id, [])
    missing = _SUBSECTION_MISSING_RE.search(err.detail)

    action: dict = {
        "raw_issue": err.detail,
        "section_id": err.section_id,
        "fragments_to_rewrite": fragments,
    }
    if missing:
        action["type"] = "required_subsection_missing"
        action["expected_heading"] = missing.group(1)
        action["remediation"] = (
            f"Open `{fragments[0] if fragments else '<fragment>'}` and add or "
            f"renumber the heading to `{missing.group(1)}` at the correct "
            "position. The heading text (including its section number) must "
            "match the contract verbatim — substring matches are NOT "
            "accepted. For §7 Security Architecture specifically, the "
            "fragment MUST contain all 13 schema-v2 subsections (7.1–7.13) "
            "in order when security_schema=v2. Do not reintroduce the old "
            "21-section intermediate scaffold or the legacy 14-section v1 headings. "
            "Re-run compose_threat_model.py after the edit."
        )
    else:
        action["type"] = "fragment_error"
        action["remediation"] = (
            "Address the issue reported in `raw_issue` inside the listed "
            "fragment(s). Re-run compose_threat_model.py afterwards. "
            "Do not modify other fragments — this error is local."
        )

    exhausted = attempt > _PRE_RENDER_REPAIR_MAX_ATTEMPTS
    plan = {
        "generated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "stage": "pre_render",
        "output_dir": str(output_dir),
        "status": "exhausted" if exhausted else "fail",
        "attempt": attempt,
        "max_attempts": _PRE_RENDER_REPAIR_MAX_ATTEMPTS,
        "issue_count": 1,
        "actions": [action],
        "re_render_command": (
            "python3 $CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py --output-dir $OUTPUT_DIR --strict"
        ),
    }
    try:
        atomic_write_text(
            plan_path,
            _json.dumps(plan, indent=2) + "\n",
        )
    except OSError:
        pass
    return attempt


def _delete_pre_render_repair_plan(output_dir: Path) -> None:
    """Remove the pre-render repair plan after a successful compose.

    Prevents a subsequent compose failure (e.g. post-QA re-render loop
    finding a different issue) from accidentally reading an outdated
    repair plan that points at the wrong fragment.
    """
    try:
        (Path(output_dir) / ".pre-render-repair-plan.json").unlink(missing_ok=True)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# M2.14 — Sprint 6 observability: .compose-stats.json
# ---------------------------------------------------------------------------

# Schema version of the .compose-stats.json file. Bump when the on-disk shape
# changes in a way that breaks downstream consumers (renderer + completion
# summary). Renderer reads this and ignores reports with a future version.
COMPOSE_STATS_SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
# Report-integrity manifest: .render-integrity.json
# ---------------------------------------------------------------------------

# Schema version of the .render-integrity.json file. Bump when the on-disk
# shape changes in a way that breaks downstream consumers (completion summary,
# aggregate_run_issues, the QA agent).
RENDER_INTEGRITY_SCHEMA_VERSION = 1


def _manifest_entry(
    sid: str,
    *,
    in_scope: bool,
    outcome: str,
    expected: list[str] | None = None,
    present: list[str] | None = None,
) -> dict[str, Any]:
    """One render-manifest record (see RenderContext.render_manifest)."""
    return {
        "id": sid,
        "in_scope": in_scope,
        "outcome": outcome,
        "expected_fragments": list(expected or []),
        "present_fragments": list(present or []),
    }


def _section_substance_ok(ctx: RenderContext, sid: str, body: str) -> bool:
    """Return False when a section that SHOULD carry substance rendered only
    boilerplate (heading + preamble) — a real content gap the byte-level
    ``not body.strip()`` check misses, because register sections always emit a
    heading and an intro paragraph. (2026-06-26)

    Only the register sections whose emptiness-given-data is a bug carry a
    substance signal; every other section returns True so the caller falls back
    to the byte check. The signal is gated on the relevant upstream data
    existing, so a model that legitimately has nothing (e.g. zero threats) is
    not flagged. This makes ``outcome == "empty"`` meaningful, which in turn
    makes ``report_integrity_ok`` real and lets the existing QA repair loop fire.
    """
    threats = ctx.yaml_data.get("threats") or []
    if sid == "mitigation_register":
        # Every threat should yield at least a fix mitigation; an empty register
        # over a non-empty threat list is the exact failure that shipped a
        # heading-only §10. A model with zero threats may legitimately have none.
        if not threats:
            return True
        return bool(re.search(r"(?m)^#{2,4}\s.*\bM-\d{2,}", body)) or '<a id="m-' in body.lower()
    if sid == "threat_register":
        if not threats:
            return True
        return bool(re.search(r"F-\d{2,}", body)) or '<a id="f-' in body.lower()
    if sid == "abuse_cases":
        # §9 renders a deterministic placeholder when no abuse-case evaluation
        # is on disk — legitimately empty for many repos, so no signal there.
        # But when the verifier DID leave viable verdicts on disk and §9 still
        # shows only the placeholder, the render step was skipped/failed and the
        # verified chains were silently dropped (juice-shop 2026-06-29). That is
        # a real content gap that previously still scored 100% integrity. Flag it
        # so `report_integrity_ok` flips and the QA repair loop fires. The
        # self-heal in `_render_abuse_cases` normally prevents this from ever
        # rendering as a placeholder; this is the independent detection backstop.
        if not _has_viable_abuse_verdicts(ctx.output_dir):
            return True
        return bool(re.search(r'(?i)id="ac-|\bAC-[A-Z]*-?\d', body))
    return True


def _has_viable_abuse_verdicts(output_dir: Path) -> bool:
    """True when ``.abuse-case-verdicts.json`` holds ≥1 chain that should render
    in §9 — i.e. a verdict whose ``chain_verdict`` is anything other than
    ``not_applicable`` (matching ``render_abuse_cases.build_models``, which only
    drops ``not_applicable`` chains). A verdict with no ``chain_verdict`` yet is
    treated as viable (the renderer self-heals the fold from its step verdicts).
    Best-effort: any read/parse error returns False so this never spuriously
    fails a clean render. RC-2026-06-29.
    """
    path = output_dir / ".abuse-case-verdicts.json"
    if not path.is_file():
        return False
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    for v in doc.get("verdicts") or []:
        if not isinstance(v, dict):
            continue
        if v.get("chain_verdict", "viable") != "not_applicable":
            return True
    return False


def _section_fragment_status(ctx: RenderContext, sid: str) -> tuple[list[str], list[str], bool]:
    """Return (expected, present, fallback_eligible) fragment basenames for a section.

    `expected` are the fragment files the contract maps to ``sid``; `present`
    are those that actually exist in the run's fragments dir; a section is
    fallback-eligible when any expected fragment has a sanctioned deterministic
    fallback (``_FRAGMENTS_WITH_FALLBACK``) so a missing fragment is degraded-
    but-acceptable rather than broken.
    """
    expected = [Path(f).name for f in _SECTION_FRAGMENT_MAP.get(sid, [])]
    present = [name for name in expected if (ctx.fragments_dir / name).is_file()]
    fallback_eligible = any(name in _FRAGMENTS_WITH_FALLBACK for name in expected)
    return expected, present, fallback_eligible


def _compute_integrity(manifest: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarise a render manifest into the .render-integrity.json payload.

    ``integrity_pct`` is the share of in-scope sections that rendered cleanly
    (including sanctioned fallbacks); out-of-scope (condition-false) sections
    are excluded from the denominator. ``report_integrity_ok`` is True only
    when no in-scope section was degraded or empty — the deterministic
    "model is not broken" signal the QA agent reacts to.
    """
    in_scope = [m for m in manifest if m.get("in_scope")]
    n = len(in_scope)

    def _cnt(outcome: str) -> int:
        return sum(1 for m in in_scope if m.get("outcome") == outcome)

    rendered = _cnt("rendered")
    fallback = _cnt("fallback")
    degraded = _cnt("degraded")
    empty = _cnt("empty")
    ok = rendered + fallback
    return {
        "schema_version": RENDER_INTEGRITY_SCHEMA_VERSION,
        "report_integrity_ok": degraded == 0 and empty == 0,
        "integrity_pct": 100 if n == 0 else round(100 * ok / n),
        "sections_in_scope": n,
        "sections_rendered": rendered,
        "sections_fallback": fallback,
        "sections_degraded": degraded,
        "sections_empty": empty,
        "sections_skipped_conditional": sum(1 for m in manifest if not m.get("in_scope")),
        "fragments_expected": sum(len(m.get("expected_fragments") or []) for m in in_scope),
        "fragments_wired": sum(len(m.get("present_fragments") or []) for m in in_scope),
        "broken_sections": [m["id"] for m in in_scope if m.get("outcome") in ("degraded", "empty")],
        "sections": manifest,
        "generated": _now_iso_z(),
    }


def _write_render_integrity(output_dir: Path, integrity: dict[str, Any]) -> None:
    """Persist .render-integrity.json — best-effort observability (never fatal)."""
    try:
        import json as _json

        atomic_write_text(
            Path(output_dir) / ".render-integrity.json",
            _json.dumps(integrity, indent=2) + "\n",
        )
    except OSError:
        pass


def _emit_render_integrity_marker(integrity: dict[str, Any]) -> None:
    """Print a one-line stderr marker (sibling to RENDERED:) for run-log capture."""
    ok = integrity["sections_rendered"] + integrity["sections_fallback"]
    broken = integrity.get("broken_sections") or []
    suffix = f"; broken: {', '.join(broken)}" if broken else ""
    try:
        sys.stderr.write(
            f"RENDER_INTEGRITY: {integrity['integrity_pct']}% "
            f"({ok}/{integrity['sections_in_scope']} sections, "
            f"{integrity['fragments_wired']} fragments wired{suffix})\n"
        )
        sys.stderr.flush()
    except OSError:
        pass


def _categorize_warning(warning_text: str) -> dict[str, str]:
    """Map a free-form warning string into a structured {section, category,
    detail} dict. Heuristic — used by _write_compose_stats(). Renderer-side
    code should not depend on the exact category strings; they are for human
    consumption in the §Composition Notes appendix and the Health block.
    """
    text = warning_text.strip()
    lower = text.lower()
    if "orphan" in lower and ("t-nnn" in lower or "t-" in lower):
        return {"section": "§8 Findings Register", "category": "orphan_link", "detail": text}
    if "operational-strengths overrides" in lower:
        return {"section": "Operational Strengths", "category": "schema_drift", "detail": text}
    if "soft-skip section" in lower:
        section = text.replace("soft-skip section", "").strip()
        return {"section": section or "(unknown)", "category": "soft_skip", "detail": text}
    if "not in contract" in lower:
        return {"section": "(unknown)", "category": "contract_mismatch", "detail": text}
    if "secret-mask applied" in lower:
        # Extract the pattern-name list emitted by _mask_secrets (e.g.
        # "secret-mask applied: generic_bare_token, rsa_pem — credential-…")
        # so the §Composition Notes appendix and the Health block surface
        # WHICH credential patterns matched instead of the generic
        # "(unspecified)" fallback.
        m = re.search(r"secret-mask applied:\s*([^—]+?)\s*—", text)
        patterns = m.group(1).strip() if m else "unknown"
        return {
            "section": "Global Secret-Mask Pass",
            "category": "secret_mask",
            "detail": text,
            "patterns": patterns,
        }
    return {"section": "(unspecified)", "category": "other", "detail": text}


def _write_compose_stats(
    output_dir: Path,
    warnings: list[str],
    section_retry_counts: dict[str, int],
) -> None:
    """Persist a structured compose stats summary to ``.compose-stats.json``.

    Called from the success path of ``main()``. The renderer's
    ``_render_composition_notes()`` reads this file on the *next* compose
    invocation (or via the QA re-render loop) and emits a §Composition Notes
    appendix when any non-clean signal is present.

    The file is also consumed by ``render_completion_summary.py`` for the
    Composition Health block and is reaped by ``runtime_cleanup.py`` at the
    end of the skill (post-qa whitelist) — the MD-embedded appendix is the
    canonical persistence.
    """
    structured = [_categorize_warning(w) for w in warnings]
    retries_over_one = {sid: n for sid, n in (section_retry_counts or {}).items() if n and n > 1}
    total_attempts = sum(retries_over_one.values())
    has_warnings = bool(structured)
    has_retries = bool(retries_over_one)
    status = "warned" if (has_warnings or has_retries) else "clean"
    stats = {
        "schema_version": COMPOSE_STATS_SCHEMA_VERSION,
        "compose_status": status,
        "warning_count": len(structured),
        "warnings": structured,
        "section_retries": retries_over_one,
        "total_retry_attempts": total_attempts,
        "compose_invocation_iso": _now_iso_z(),
    }
    try:
        import json as _json

        atomic_write_text(
            output_dir / ".compose-stats.json",
            _json.dumps(stats, indent=2) + "\n",
        )
    except OSError:
        pass  # Non-fatal — observability data is best-effort.


def _now_iso_z() -> str:
    """UTC ISO-8601 with 'Z' suffix (no microseconds)."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_compose_stats(output_dir: Path) -> dict | None:
    """Read .compose-stats.json or return None if absent / malformed.

    Used by both the §Composition Notes renderer (in this script) and the
    Composition Health block in render_completion_summary.py.
    """
    try:
        import json as _json

        path = Path(output_dir) / ".compose-stats.json"
        if not path.is_file():
            return None
        data = _json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        if data.get("schema_version") != COMPOSE_STATS_SCHEMA_VERSION:
            return None  # Forward-incompatible — skip silently.
        return data
    except (OSError, ValueError):
        return None


def _read_inline_retry_count(output_dir: Path) -> int:
    """Return the integer in .inline-shortcut-retry-count or 0 if absent."""
    try:
        path = Path(output_dir) / ".inline-shortcut-retry-count"
        if not path.is_file():
            return 0
        return int(path.read_text(encoding="utf-8").strip() or 0)
    except (OSError, ValueError):
        return 0


def _compose_warned_signal(output_dir: Path) -> bool:
    """Evaluate the `compose_warned` condition for the conditional
    §Composition Notes appendix.

    M3.3 threshold: emit the appendix only when there is something
    actionable to surface — at least 2 warnings OR any retry attempt OR
    a non-warned non-clean status (e.g. ``critical``). A single soft
    warning is now considered noise and surfaces only via stderr +
    .compose-stats.json without burdening the rendered MD.

    True when ANY of the following holds:
      - .compose-stats.json reports warning_count >= 2
      - .compose-stats.json reports compose_status not in {"clean", "warned"}
        (i.e. something more serious than a soft warning)
      - .inline-shortcut-retry-count is > 0 (auto-retry fired)
    """
    stats = _read_compose_stats(output_dir)
    if stats:
        wc = stats.get("warning_count") or 0
        if wc >= 2:
            return True
        status = stats.get("compose_status")
        if status not in (None, "clean", "warned"):
            return True
    if _read_inline_retry_count(output_dir) > 0:
        return True
    return False


def _read_run_issues(output_dir: Path) -> dict | None:
    """Read .run-issues.json (M2.15 — Sprint 7) or return None if absent
    or schema-incompatible."""
    try:
        import json as _json

        path = Path(output_dir) / ".run-issues.json"
        if not path.is_file():
            return None
        data = _json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            return None
        return data
    except (OSError, ValueError):
        return None


def _run_warned_signal(output_dir: Path) -> bool:
    """Evaluate the `run_warned` condition for the conditional §Run Issues
    appendix. True when .run-issues.json reports run_status != "clean"."""
    data = _read_run_issues(output_dir)
    return bool(data) and data.get("run_status") != "clean"


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    # Name the Figure 1 SVG after the output md stem (`<stem>.figure1.svg`) so
    # several models can coexist in one output directory without their figure
    # files colliding. Computed from the same default/--out logic used below.
    _default_filename = "analysis-model.md" if args.document == "architecture" else "threat-model.md"
    _out_name = (args.out or (args.output_dir / _default_filename)).name
    _figure_basename = _figure_basename_for_md(_out_name)
    try:
        rendered, warnings = render(
            args.contract,
            args.output_dir,
            fragments_subdir=args.fragments_subdir,
            strict=not args.lenient,
            document=args.document,
            emit_progress=not args.dry_run,  # CLI callers see live section progress
            embed_figures=args.embed_figures,
            figure_basename=_figure_basename,
        )
    except FragmentError as e:
        attempt = _emit_pre_render_repair_plan(args.output_dir, e)
        # Surface the retry counter to the user BEFORE the raw error so the
        # orientation ("am I in a fix-loop?") is clear at a glance. Stays
        # quiet for `attempt=1` which is just a first-time failure.
        if attempt > 1:
            print(
                f"RENDER_ATTEMPT: {attempt}/{_PRE_RENDER_REPAIR_MAX_ATTEMPTS} "
                f"on section {e.section_id!r} (see .pre-render-repair-plan.json)",
                file=sys.stderr,
            )
        print(f"RENDER_FAILED: {e}", file=sys.stderr)
        hint = _fragment_error_hint(e)
        if hint:
            print(f"RENDER_HINT: {hint}", file=sys.stderr)
        if attempt > _PRE_RENDER_REPAIR_MAX_ATTEMPTS:
            # Escalation signal — exit 4 means "auto-repair budget exhausted,
            # stop retrying within this Stage 1 dispatch and bubble up to the
            # skill's Re-Render Loop instead." The orchestrator's Phase 11
            # branch must not re-invoke compose after seeing exit 4.
            print(
                f"RENDER_EXHAUSTED: {attempt - 1} prior attempt(s) on the same "
                f"fragment did not converge. See .pre-render-repair-plan.json "
                f"(status=exhausted). Escalate to the skill-level repair loop "
                "instead of looping within this Stage 1 dispatch.",
                file=sys.stderr,
            )
            return 4
        return 1
    except ContractError as e:
        print(f"CONTRACT_ERROR: {e}", file=sys.stderr)
        return 2
    except (OSError, yaml.YAMLError) as e:
        print(f"IO_ERROR: {e}", file=sys.stderr)
        return 3

    # Strip any leaked '<!-- QA: ... -->' blocks before final write. The QA
    # reviewer should emit repair signals via `.qa-repair-plan.json`, not inline
    # HTML comments. If any slipped through (older agent build, manual edit),
    # we strip them defensively so the rendered document is contract-clean.
    _qa_comment_pat = re.compile(r"<!--\s*QA:.*?-->\s*\n?", flags=re.DOTALL)
    rendered, qa_stripped = _qa_comment_pat.subn("", rendered)
    if qa_stripped:
        warnings.append(
            f"stripped {qa_stripped} leaked '<!-- QA: ... -->' comments "
            f"before final write (these should flow via .qa-repair-plan.json)"
        )

    # T-NNN ↔ component-prefix bridge (M3.2). Architecture/walkthrough sections
    # historically cite findings as `[T-001](#t-001)` (1-indexed by threat order),
    # but §8 emits component-prefixed anchors (e.g. `<a id="auth-jwt-s-001"></a>`).
    # Without a bridge every T-NNN link is broken. Build a translation map from
    # the canonical yaml.threats[] order and rewrite each `[T-NNN](#t-nnn)` to
    # point at the actual anchor; if the same T-NNN target lacks a real anchor,
    # we ALSO inject `<a id="t-NNN"></a>` adjacent to the threat row so the
    # reference resolves both ways. The `RENDER_WARN: orphan T-NNN` warning is
    # only emitted when the translation could not be resolved (genuine bug).
    # Shared YAML for T-NNN and F-NNN bridges — read once, used by both passes.
    _bridge_yaml: dict = {}
    _bridge_yaml_pat = re.compile(r"\[(?:T|F)-(\d+)\]\(#(?:t|f)-\d+\)")
    if _bridge_yaml_pat.search(rendered):
        try:
            _bridge_yaml = _fast_yaml_load((args.output_dir / "threat-model.yaml").read_text(encoding="utf-8")) or {}
        except (FileNotFoundError, yaml.YAMLError, OSError):
            _bridge_yaml = {}

    _t_link_pat = re.compile(r"\[T-(\d+)\]\(#t-\d+\)")
    referenced_t = sorted(set(_t_link_pat.findall(rendered)))
    unresolved: list[str] = []
    if referenced_t:
        threats_ordered = _bridge_yaml.get("threats") or []
        # Build T-NNN → anchor map using the threat's stored id, NOT its
        # position in the array. The positional approach was wrong: LLM
        # fragments cite T-013 to mean threat id=T-013, never "position 13".
        # Using position caused wrong link targets AND duplicate anchors
        # (bridge injected t-003 alias into the T-013 row even though
        # _render_threat_register already emitted <a id="t-003"> on T-003's row).
        t_alias: dict[str, tuple[str, str]] = {}
        for t in threats_ordered:
            if not isinstance(t, dict):
                continue
            real_id = (t.get("t_id") or t.get("id") or "").strip()
            if not real_id:
                continue
            m_id = re.match(r"^T-(\d+)$", real_id, re.IGNORECASE)
            if m_id:
                # T-013 → key "013" → anchor "t-013"
                t_alias[m_id.group(1).zfill(3)] = (real_id, real_id.lower())

        # Pass 1: rewrite `[T-NNN](#t-nnn)` → `[T-NNN](#t-nnn)` — with id-based
        # lookup, the anchor is already correct (t-013 links to t-013), so this
        # pass is a no-op for well-formed T-NNN ids. It only corrects stale
        # references that point to the wrong number (e.g. component-prefixed schemas).
        def _rewrite(match: re.Match) -> str:
            tnnn = match.group(1)
            mapped = t_alias.get(tnnn)
            if mapped:
                return f"[T-{tnnn}](#{mapped[1]})"
            return match.group(0)

        rewritten = _t_link_pat.sub(_rewrite, rendered)

        # Pass 2: inject `<a id="t-NNN"></a>` aliases only when the threat row's
        # canonical anchor is NOT already t-NNN (component-prefixed schemas).
        # When the real anchor IS t-NNN, _render_threat_register already emitted
        # it — injecting again would produce a duplicate anchor.
        for tnnn, (_real, anchor) in t_alias.items():
            if tnnn not in referenced_t:
                continue
            alias_decl = f'<a id="t-{tnnn}"></a>'
            # Skip when the real anchor and the alias are identical — the row
            # already declares the correct anchor; no injection needed.
            if alias_decl == f'<a id="{anchor}"></a>':
                continue
            real_anchor_decl = f'<a id="{anchor}"></a>'
            if real_anchor_decl in rewritten:
                rewritten = rewritten.replace(
                    real_anchor_decl,
                    f"{alias_decl}{real_anchor_decl}",
                    1,
                )
            else:
                unresolved.append(tnnn)

        rendered = rewritten

    if unresolved:
        warnings.append(
            f"{len(unresolved)} orphan T-NNN link target(s) could not be bridged "
            f"({', '.join('T-' + x for x in unresolved[:5])}"
            f"{', …' if len(unresolved) > 5 else ''}). Threats may have been "
            "consolidated in Phase 9 — verify yaml.threats[] count matches the "
            "highest T-NNN reference in the source fragments."
        )

    # F-NNN bridge — parallel mechanism to the T-NNN bridge above. LLM-authored
    # fragments (verdict bullets in ms-verdict.json, asset Linked Threats cells,
    # attack-walkthroughs) historically cite findings as `[F-001](#f-001)` per
    # the qa-reviewer contract that names F-NNN as the canonical rendered ID.
    # _render_threat_register now emits an `<a id="f-NNN"></a>` alias next to
    # every `<a id="t-NNN"></a>` anchor (digit-suffix copy). The bridge below
    # only needs to handle the residual edge case: component-prefixed yaml
    # schemas where the threat row's canonical anchor is NOT `t-NNN` — there
    # we inject the f-NNN alias next to the canonical anchor so the original
    # `[F-NNN](#f-nnn)` link still resolves. Pass-1 rewrite (the destructive
    # rewrite that the T-NNN bridge does) is INTENTIONALLY OMITTED here so
    # the rendered display preserves the user-visible `[F-NNN](#f-nnn)` form
    # — the alias injection makes that target valid without any rewriting.
    _f_link_pat = re.compile(r"\[F-(\d+)\]\(#f-\d+\)")
    referenced_f = sorted(set(_f_link_pat.findall(rendered)))
    unresolved_f: list[str] = []
    if referenced_f:
        threats_for_f = _bridge_yaml.get("threats") or []
        f_alias: dict[str, tuple[str, str]] = {}
        for i, t in enumerate(threats_for_f, start=1):
            if not isinstance(t, dict):
                continue
            real_id = (t.get("t_id") or t.get("id") or "").strip()
            if not real_id:
                continue
            f_alias[f"{i:03d}"] = (real_id, real_id.lower())

        # For each referenced F-NNN, ensure the matching `<a id="f-NNN"></a>`
        # exists somewhere in the document. If `_render_threat_register`
        # already emitted it (the standard T-NNN case), nothing to do —
        # the link resolves directly. Otherwise (component-prefixed schemas)
        # inject the alias next to the canonical anchor.
        for fnnn, (_real, anchor) in f_alias.items():
            if fnnn not in referenced_f:
                continue
            alias_decl = f'<a id="f-{fnnn}"></a>'
            if alias_decl in rendered:
                continue  # standard path — alias already emitted inline
            real_anchor_decl = f'<a id="{anchor}"></a>'
            if real_anchor_decl in rendered:
                rendered = rendered.replace(
                    real_anchor_decl,
                    f"{alias_decl}{real_anchor_decl}",
                    1,
                )
            else:
                unresolved_f.append(fnnn)

    if unresolved_f:
        warnings.append(
            f"{len(unresolved_f)} orphan F-NNN link target(s) could not be bridged "
            f"({', '.join('F-' + x for x in unresolved_f[:5])}"
            f"{', …' if len(unresolved_f) > 5 else ''}). Verify yaml.threats[] count "
            "matches the highest F-NNN reference in the source fragments."
        )

    # R4 — Canonical visible-label normalisation (post-bridges).
    # User-facing convention: every cross-reference renders as `[F-NNN](#f-nnn)`.
    # The §8 Findings Register row emits the dual anchor `<a id="t-NNN"></a><a id="f-NNN"></a>`
    # with F-NNN as the visible label (compose:7263-7266). The F-bridge above
    # ensures `#f-NNN` resolves even on component-prefixed schemas. The only
    # remaining drift is LLM-authored fragments that cite `[T-NNN](#t-nnn)` —
    # rewrite them to the canonical visible form globally. The dual anchor
    # guarantees `#f-NNN` resolves; we never break a link with this pass.
    #
    # EXCLUSION: the row-anchor declaration site `<a id="t-NNN"></a>...T-NNN`
    # uses T-NNN as part of the anchor *declaration* — not as a link target.
    # Our regex only matches the link syntax `[T-NNN](#t-nnn)`, so anchor
    # declarations are untouched.
    rendered = re.sub(
        r"\[T-(\d{3,})\]\(#t-\1\)",
        r"[F-\1](#f-\1)",
        rendered,
    )

    default_filename = "analysis-model.md" if args.document == "architecture" else "threat-model.md"
    out_path = args.out or (args.output_dir / default_filename)
    if args.dry_run:
        sys.stdout.write(rendered)
    else:
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            # Atomic write — this is the canonical output. A crash mid-write
            # would leave a truncated threat-model.md on disk, breaking the
            # skill's post-run contract gate.
            atomic_write_text(out_path, rendered)
        except OSError as e:
            print(f"IO_ERROR: cannot write {out_path}: {e}", file=sys.stderr)
            return 3

    # R8 — Mermaid syntax check at compose time. Previously this lived in
    # Stage 3 QA (qa_checks.py:check_mermaid_syntax), which is skipped at
    # --quick depth. Lifting it here ensures broken Mermaid (e.g. alt/else/
    # end nesting bugs as observed in juice-shop --quick run, 2026-05-16)
    # is caught regardless of QA skip policy. Failures emit RENDER_WARN
    # lines but do NOT abort the render — the file is still written so the
    # user can inspect the issue. A future strict-strict mode could exit
    # non-zero, but parity with the current QA-side semantics (warn-only)
    # is the conservative choice.
    if not args.dry_run:
        try:
            import qa_checks as _qa_checks

            mer_report = _qa_checks.check_mermaid_syntax(out_path)
            for issue in mer_report.issues or []:
                warnings.append(f"mermaid: {issue}")
        except Exception as _qa_exc:  # pragma: no cover — defensive
            warnings.append(f"mermaid: check skipped — {_qa_exc}")

    for w in warnings:
        print(f"RENDER_WARN: {w}", file=sys.stderr)
    print(f"RENDERED: {out_path.name}  ({len(rendered.splitlines())} lines, {len(warnings)} warnings)")
    # M2.14 — Sprint 6: read the pre-render repair plan BEFORE deletion to
    # extract per-section retry counts. The plan accumulates `attempt` over
    # successive failures on the same section; if it's >1 here, that means
    # this section needed N-1 retries to converge. After capture we delete
    # the plan as before so a future failure doesn't read stale data.
    section_retries: dict[str, int] = {}
    plan_path = Path(args.output_dir) / ".pre-render-repair-plan.json"
    try:
        if plan_path.exists():
            import json as _json

            prior = _json.loads(plan_path.read_text(encoding="utf-8"))
            attempts = int(prior.get("attempt", 0) or 0)
            for action in prior.get("actions") or []:
                sid = (action.get("section_id") or "").strip()
                if sid and attempts > 0:
                    section_retries[sid] = attempts
    except (OSError, ValueError, _json.JSONDecodeError):
        pass
    _write_compose_stats(args.output_dir, warnings, section_retries)
    # On success, clear any stale repair plan from a prior failed compose so
    # a later re-render doesn't accidentally consume it as actionable.
    _delete_pre_render_repair_plan(args.output_dir)

    # Full, uncapped change-log audit export beside the report (threat-model.md's
    # own §Changelog is a 5-per-bucket window). Pure render of the yaml changelog;
    # never aborts the composed report. Only for the full threat-model document.
    if not args.dry_run and args.document != "architecture":
        try:
            import render_changelog_audit

            render_changelog_audit.write_audit(args.output_dir)
        except Exception as _audit_exc:  # pragma: no cover — defensive, never fatal
            print(f"RENDER_WARN: changelog audit export skipped — {_audit_exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
