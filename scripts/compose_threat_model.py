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
       sections like system-overview).

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
import functools
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

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

try:
    import jsonschema

    _JSONSCHEMA_OK = True
except ImportError:
    _JSONSCHEMA_OK = False


PLUGIN_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONTRACT = PLUGIN_ROOT / "data" / "sections-contract.yaml"
TEMPLATES_DIR = PLUGIN_ROOT / "templates" / "fragments"
SCHEMAS_DIR = PLUGIN_ROOT / "schemas" / "fragments"


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
# tests/test_qa_fragment_map.py). Used by the pre-render repair-plan writer
# to point the orchestrator at the exact file to edit when compose aborts
# with a FragmentError — eliminates the fix-loop where the agent re-writes
# the wrong fragment (e.g. architecture-diagrams.md instead of the offending
# security-architecture.md).
_SECTION_FRAGMENT_MAP: dict[str, list[str]] = {
    "verdict": [".fragments/ms-verdict.json"],
    "architecture_assessment": [".fragments/ms-architecture-assessment.json"],
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
    "out_of_scope": [".fragments/out-of-scope.md"],
}

_KNOWN_JSON_FRAGMENT_SCHEMAS: dict[str, tuple[str, str]] = {
    "ms-verdict.json": ("verdict", "verdict.schema.json"),
    "ms-architecture-assessment.json": (
        "architecture_assessment",
        "architecture-assessment.schema.json",
    ),
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
}


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
            label = (t.get("title") or t.get("scenario_short") or "").strip()
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
            label = (m.get("title") or m.get("mitigation_title") or m.get("name") or "").strip()
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
        return self._label_index.get(ref.strip().upper(), "")

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
            return f"[{r}](#{anchor}) ({short})"
        return f"[{r}](#{anchor})"

    def linkify_with_label(self, ref: str, label_override: str | None = None) -> str:
        """Emit `[ID](#id-lower) — label`. If label is empty or unknown,
        emit just `[ID](#id-lower)` (never a bare unlinked ID).

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
        label = (label_override or self.lookup_label(r) or "").strip()
        if label:
            return f"[{r}](#{anchor}) — {label}"
        return f"[{r}](#{anchor})"


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
            out.append(f"[{r}](#{r.lower()})")
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
            priority = it.get("priority", "").strip()
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
                line = f"{glyph}[{mid}](#{mid.lower()})"
            else:
                # Synthesized review-hint (M-14) — no M-NNN anchor; the
                # `action` field already carries "Manual review at <file>"
                # plus its own anchor link.
                line = f"{glyph}{action}"
                action = ""  # already consumed
            if action:
                line += f" — {action}"
            if priority:
                line += f" ({priority})"
            rendered.append(line)
        return "<br/>".join(rendered)

    def format_weakness_findings(items: list[dict[str, Any]]) -> str:
        if not items:
            return "—"
        rendered = []
        for it in items:
            ref = it["ref"]
            # P4 — normalise T-NNN visible label to F-NNN for consistency.
            m_t = re.match(r"^T-(\d+)$", ref or "")
            if m_t:
                ref = f"F-{m_t.group(1)}"
            label = it.get("label", "").strip()
            line = f"[{ref}](#{ref.lower()})"
            if label:
                line += f" — {label}"
            rendered.append(line)
        return "<br/>".join(rendered)

    # Back-compat alias: callers in older templates still use the legacy
    # `format_defect_findings` name. New code uses `format_weakness_findings`.
    format_defect_findings = format_weakness_findings

    def format_weakness_components(items: list[dict[str, Any]] | list[str]) -> str:
        """Render `affected_components[]` for Architecture Assessment.

        Accepts either a list of `{id, name}` dicts (preferred) or bare
        component-id strings (legacy). Component-id resolution against the
        components dict happens inside ``_render_architecture_assessment``
        before the template is invoked.
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
        return "<br/>".join(parts) if parts else "—"

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
        parts = []
        for it in items:
            ref = _normalize_finding_label(it.get("ref") or it.get("id", ""))
            label = it.get("label", "").strip()
            line = f"[{ref}](#{ref.lower()})"
            if label:
                line += f" — {label}"
            parts.append(line)
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
                if label:
                    parts.append(f"[{ref}](#{ref.lower()}) — {label}")
                else:
                    # Fall back to context lookup so we never emit a bare link.
                    parts.append(ctx.linkify_with_label(ref))
            else:
                parts.append(ctx.linkify_with_label(str(it)))
        return "<br/>".join(parts)

    env.filters["linkify_refs"] = linkify_refs
    env.filters["format_id_list"] = format_id_list
    env.filters["format_mitigations"] = format_mitigations
    env.filters["format_defect_findings"] = format_defect_findings   # back-compat alias
    env.filters["format_weakness_findings"] = format_weakness_findings
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
    "CWE-321": frozenset({"key", "secret", "kms", "vault", "rotation", "rotate", "manager", "externalize", "externaliz"}),
    "CWE-798": frozenset({"credential", "secret", "key", "kms", "vault", "rotation", "rotate", "externalize", "externaliz"}),
    "CWE-352": frozenset({"csrf", "samesite", "double-submit", "anti-csrf", "csurf"}),
    "CWE-918": frozenset({"ssrf", "allowlist", "egress", "url"}),
    "CWE-922": frozenset({"storage", "cookie", "httponly", "localstorage", "session"}),
    "CWE-915": frozenset({"mass-assignment", "mass", "whitelist", "allowlist", "schema", "binding"}),
    "CWE-639": frozenset({"ownership", "object", "idor", "authorization", "scope"}),
    "CWE-347": frozenset({"signature", "algorithm", "jwt", "verify", "whitelist", "allowlist"}),
    "CWE-94":  frozenset({"eval", "sandbox", "parser", "schema", "input"}),
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

    baseline_path = output_dir / ".appsec-cache" / "baseline.json"
    prior_depth = ""
    if baseline_path.is_file():
        try:
            prior_depth = (
                (json.loads(baseline_path.read_text(encoding="utf-8")).get("last_run_depth", "") or "").strip().lower()
            )
        except (OSError, ValueError, json.JSONDecodeError):
            prior_depth = ""

    if prior_depth not in ("standard", "thorough"):
        return ""  # quick → quick (or first run): skip §7 entirely.

    prior_md_path = output_dir / "threat-model.md"
    if not prior_md_path.is_file():
        return ""  # claimed prior depth but no MD on disk — skip rather than fake

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

    return extracted


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


# Matches a §8 Threat Register row in a rendered threat-model.md. Two arms
# to handle both the legacy 9-column layout and the 4-column Story-Card
# layout (2026-05) — both arms capture (digit-suffix, title):
#   * arm A — new: `<a id="f-NNN"></a>F-NNN | **<Bold Title>**<br>…`
#   * arm B — old: `<a id="f-NNN"></a>F-NNN | <Bare Title> | …`
# Title group goes into group(2) [new] or group(4) [old]; digits into
# group(1) or group(3). Use `_extract_fnnn_row(match)` to coalesce.
_FNNN_REGISTER_ROW = re.compile(
    r'<a id="f-(\d+)"></a>F-\d+\s*\|\s*\*\*([^*\n]+?)\*\*'   # arm A — bold title
    r'|<a id="f-(\d+)"></a>F-\d+\s*\|\s*([^|\n]+?)\s*\|'       # arm B — bare title
)


def _extract_fnnn_row(match: re.Match[str]) -> tuple[str, str]:
    """Return ``(digit_suffix, title)`` from an ``_FNNN_REGISTER_ROW`` match."""
    digits = match.group(1) or match.group(3) or ""
    title = (match.group(2) or match.group(4) or "").strip()
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
    "CWE-22":   "Path Traversal",
    "CWE-23":   "Path Traversal",
    "CWE-78":   "OS Command Injection",
    "CWE-79":   "Cross-Site Scripting",
    "CWE-87":   "Cross-Site Scripting",
    "CWE-89":   "SQL Injection",
    "CWE-94":   "Code Injection",
    "CWE-95":   "Server-Side Template Injection",
    "CWE-116":  "Improper Output Encoding",
    "CWE-200":  "Information Disclosure",
    "CWE-209":  "Error Message Disclosure",
    "CWE-269":  "Improper Privilege Management",
    "CWE-284":  "Improper Access Control",
    "CWE-285":  "Improper Authorization",
    "CWE-287":  "Improper Authentication",
    "CWE-290":  "Authentication Bypass by Spoofing",
    "CWE-294":  "Authentication Bypass by Capture-Replay",
    "CWE-306":  "Missing Authentication",
    "CWE-307":  "Missing Rate Limiting (Brute-Force)",
    "CWE-310":  "Cryptographic Weakness",
    "CWE-312":  "Cleartext Storage of Sensitive Data",
    "CWE-321":  "Hardcoded Cryptographic Key",
    "CWE-326":  "Inadequate Encryption Strength",
    "CWE-327":  "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-328":  "Use of Weak Hash",
    "CWE-329":  "Predictable IV / Nonce",
    "CWE-330":  "Use of Insufficiently Random Values",
    "CWE-345":  "Insufficient Verification of Data Authenticity",
    "CWE-346":  "Origin Validation Error",
    "CWE-347":  "Improper Verification of Cryptographic Signature",
    "CWE-352":  "Cross-Site Request Forgery (CSRF)",
    "CWE-359":  "Exposure of Private Personal Information",
    "CWE-400":  "Uncontrolled Resource Consumption",
    "CWE-434":  "Unrestricted File Upload",
    "CWE-441":  "Unintended Proxy or Intermediary (Confused Deputy)",
    "CWE-502":  "Deserialization of Untrusted Data",
    "CWE-532":  "Sensitive Data in Log Files",
    "CWE-538":  "Insertion of Sensitive Information into Externally-Accessible File",
    "CWE-548":  "Directory Listing Exposure",
    "CWE-552":  "Files / Directories Accessible to External Parties",
    "CWE-601":  "Open Redirect",
    "CWE-611":  "XML External Entity (XXE)",
    "CWE-620":  "Unverified Password Change",
    "CWE-639":  "Insecure Direct Object Reference (IDOR)",
    "CWE-640":  "Weak Password Recovery Mechanism",
    "CWE-674":  "Uncontrolled Recursion",
    "CWE-693":  "Missing Defense-in-Depth Control",
    "CWE-732":  "Incorrect Permission Assignment",
    "CWE-749":  "Exposed Dangerous Method or Function",
    "CWE-770":  "Allocation of Resources without Limits",
    "CWE-778":  "Insufficient Logging",
    "CWE-798":  "Hardcoded Credentials",
    "CWE-834":  "Excessive Iteration",
    "CWE-862":  "Missing Authorization",
    "CWE-863":  "Incorrect Authorization",
    "CWE-916":  "Password Hash with Insufficient Effort",
    "CWE-918":  "Server-Side Request Forgery (SSRF)",
    "CWE-922":  "Insecure Storage of Sensitive Information",
    "CWE-942":  "Permissive Cross-Origin (CORS) Policy",
    "CWE-943":  "NoSQL Injection",
    "CWE-1004": "Sensitive Cookie without HttpOnly",
    "CWE-1021": "Improper Restriction of UI Rendering Layers (Clickjacking)",
    "CWE-1104": "Use of Unmaintained Third-Party Components",
    "CWE-1321": "Prototype Pollution",
    "CWE-1395": "Vulnerable Third-Party Component",
}


def _canonical_finding_title(t: dict) -> str:
    """Return the canonical short title for a finding in `<weakness class>
    — <file:line>` form.

    Inputs (in priority order):
      1. ``t['cwe']`` → look up in `_CWE_CLASS_NAMES` for the class label.
      2. ``t['evidence'].file:line`` → append as the trailing `— file:line`
         token. Falls back to no suffix when evidence missing.
      3. ``t['title']`` (legacy narrative form) → used only when CWE is
         unmapped, in which case the first 5 non-stopword tokens of the
         existing title are kept as the class label so the result is
         still a short noun phrase.

    Returns the empty string when no input yields a non-trivial label
    (caller decides on a placeholder).
    """
    cwe_raw = (t.get("cwe") or "").strip()
    cwe_norm = cwe_raw if cwe_raw.upper().startswith("CWE-") else (
        f"CWE-{cwe_raw}" if cwe_raw.isdigit() else cwe_raw
    )
    class_label = _CWE_CLASS_NAMES.get(cwe_norm.upper(), "")
    if not class_label:
        # Fallback — derive a short noun phrase from the existing title
        # by stripping the file-suffix and keeping ≤5 non-stopword tokens.
        raw = _normalize_register_title(t.get("title") or t.get("scenario_short") or "")
        # Drop trailing file-form `— …` if present.
        raw = re.sub(r"\s+—\s+[A-Za-z0-9_./\-]+(?::\d+)?\s*$", "", raw)
        stopwords = {"a","an","the","of","in","on","at","to","for","by","via","and","or","but","with","from","into"}
        tokens = [w for w in raw.split() if w.lower() not in stopwords]
        class_label = " ".join(tokens[:5]).strip(" ,;:.")
    if not class_label:
        return ""

    # Evidence file:line suffix.
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

    if ev_file:
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
    # architecture-assessment.md.j2 closing reference (full sentence only;
    # do NOT consume preceding newlines — that strips inter-section blank
    # lines and concatenates the last table row with the next heading).
    re.compile(
        r"\n?See \*\*\[§7 Security Architecture\]\(#7-security-architecture\)"
        r"\*\* for the full per-domain breakdown and control catalog\.\s*\n",
        re.MULTILINE,
    ),
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
    """
    for path in sorted(ctx.fragments_dir.glob("*.json")):
        entry = _KNOWN_JSON_FRAGMENT_SCHEMAS.get(path.name)
        if entry is None:
            continue
        section_id, schema_name = entry
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise FragmentError(section_id, f"JSON parse error in {path}: {e}")
        _validate_fragment(section_id, data, schema_name)


# ---------------------------------------------------------------------------
# Section renderers — one per section id or fragment_type
# ---------------------------------------------------------------------------


def _render_infobox(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    project = ctx.yaml_data.get("project") or {}
    meta = ctx.yaml_data.get("meta") or {}
    remote_url = (meta.get("git") or {}).get("remote_url") or ""

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

    tpl = env.get_template(section.get("template", "infobox.md.j2"))
    return tpl.render(project=project).rstrip() + "\n"


def _render_changelog(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    changelog = ctx.yaml_data.get("changelog") or []
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
    meta = (ctx.yaml_data.get("meta") or {})
    cap = meta.get("max_stride_components") or 3
    skip_walk = bool(ctx.eval_context.get("skip_attack_walkthroughs"))
    lines = [
        "> ⚠ **Quick depth — reduced-scope assessment.**",
        "> ",
        "> This report ran with intentionally narrower depth to keep wall-time short:",
        "> ",
        f"> - **{cap}/8 components** under full STRIDE analysis (top-priority components only)",
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
        lines.append("> - **No per-finding sequence diagrams** in §3 (chain overview only)")
    lines.extend([
        "> - **No LLM-enriched §7 architecture narrative** (scaffold + control tables only)",
        "> - **No QA reviewer pass**, no architect-level review",
        "> ",
        "> Re-run with `--standard` (≈ +30 min) for full STRIDE coverage and QA, or",
        "> `--thorough` (≈ +90 min) for architect review and enriched architecture sections.",
    ])
    return "\n".join(lines) + "\n"


def _render_skipped_sections_placeholder(
    ctx: RenderContext, env: jinja2.Environment, section: dict
) -> str:
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
        num_match = re.match(r"^(\d+(?:\.\d+)?)\.\s+", clean_heading)
        section_number = num_match.group(1) if num_match else ""
        # Strip the §-prefix from the display title since the number column
        # carries it now (avoids `7. 7. Security Architecture` doubling).
        display_title = re.sub(r"^\s*\d+(?:\.\d+)?\.\s+", "", clean_heading)
        anchor = sec.get("anchor") or _anchor_from_heading(heading)
        children = _toc_children_for_section(ctx, sid, sec)
        entries.append(
            {
                "number": section_number,
                "title": display_title,
                "anchor": anchor,
                "children": children,
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
                "title": title,
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
    return tpl.render(entries=entries).rstrip() + "\n"


def _render_verdict(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    data = _load_fragment(ctx, "verdict", section["fragment"])
    _validate_fragment("verdict", data, section["schema"])
    tpl = env.get_template(section["template"])
    return tpl.render(data=data).rstrip() + "\n"


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
# §8 Threat Register and Appendix A still resolve actor slugs through
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

    PRESERVED FROM v1 — also used by the Threat Register row renderer.
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
    in §8 Threat Register, so cross-references render consistently.

    PRESERVED FROM v1 — also used by the Threat Register row renderer.
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
            _TAXONOMY_CACHE[filename] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
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


def _load_attack_paths_fragment(ctx: RenderContext, taxonomy: dict, threats: list[dict]) -> dict:
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
            drift_log.append({
                "class": cls_id,
                "llm_target": actual,
                "canonical_target": canonical_tier,
                "source": "attack-class-taxonomy.default_target_tier",
            })
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


def _reconcile_attack_path_membership(
    data: dict, taxonomy: dict, threats: list[dict], ctx: RenderContext
) -> None:
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
        fid = (
            (t.get("original_id") or "").strip()
            or (t.get("id") or "").strip()
            or (t.get("t_id") or "").strip()
        )
        if fid:
            findings_by_class.setdefault(slug, []).append(fid)

    existing_slugs = {
        (ap.get("class") or "").strip()
        for ap in (data.get("attack_paths") or [])
        if isinstance(ap, dict)
    }

    gap_log: list[dict] = []
    appended: list[dict] = []
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
        gap_log.append({
            "class": slug,
            "missing_finding_count": len(new_entry["findings"]),
            "appended_findings": new_entry["findings"][:5],
            "source": "M-11 attack-paths gap-filler",
            "reason": (
                f"taxonomy cluster {slug!r} has {len(new_entry['findings'])} "
                f"matching finding(s) in threats[] but no entry in LLM-authored "
                f"attack_paths"
            ),
        })

    if not appended:
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
        key=lambda ap: taxonomy_order.index(
            (ap.get("class") or "").strip()
        ) if (ap.get("class") or "").strip() in taxonomy_order else 999,
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


def _build_finding_to_chain_map(ctx: "RenderContext") -> dict[str, tuple[str, str]]:
    """Map finding-id (F-NNN / T-NNN) → (link_label, anchor_slug) for §3
    Attack Walkthroughs back-links.

    Parses ``.fragments/attack-walkthroughs.md`` for:
      * §3.1 ``#### Chain N — Title`` headings  (one entry per chain)
      * §3.2+ ``### 3.N Title`` per-finding sub-sections

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

    # §3.1 chains: `#### Chain N — Title`
    chain_re = re.compile(r"^####\s+Chain\s+(\d+)\s*[—\-:]\s*(.+?)\s*$", re.M)
    chain_matches = list(chain_re.finditer(text))
    for i, m in enumerate(chain_matches):
        n, title = m.group(1), m.group(2).strip()
        start = m.end()
        end = chain_matches[i + 1].start() if i + 1 < len(chain_matches) else len(text)
        body = text[start:end]
        heading_text = f"Chain {n} — {title}"
        anchor = _anchor_from_heading(heading_text)
        label = heading_text
        for digits in set(re.findall(r"\b[FT]-(\d+)\b", body)):
            out.setdefault(f"F-{digits}", (label, anchor))
            out.setdefault(f"T-{digits}", (label, anchor))

    # §3.2+ per-finding walkthroughs: `### 3.N Title` (skip 3.1)
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
        if sub_n == "1":
            continue  # 3.1 is Chain Overview, handled above
        title = m.group(2).strip()
        heading_text = f"3.{sub_n} {title}"
        anchor = _anchor_from_heading(heading_text)
        label = f"Walkthrough §3.{sub_n}"
        # Extract the primary T-NNN/F-NNN from the heading title only. The
        # heading shape produced by walkthrough_renderer.py is
        # `### 3.<n> T-NNN — <Title>` so the first match is the owner.
        head_match = re.search(r"\b[FT]-(\d+)\b", title)
        if not head_match:
            continue
        digits = head_match.group(1)
        # Per-finding walkthrough wins over the §3.1 chain link for its
        # OWN finding only. setdefault is intentional — if two §3.N
        # sections claim the same T-NNN (should not happen but defensive),
        # the first wins.
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
    "CWE-89":   "missing input neutralization on raw SQL paths",
    "CWE-943":  "NoSQL operators reachable from user input",
    "CWE-79":   "untrusted HTML rendered via bypassed sanitizer",
    "CWE-94":   "user input reaches eval() / sandbox sinks",
    "CWE-95":   "dynamic code construction from request data",
    "CWE-611":  "XML parser accepts external entities",
    "CWE-91":   "XML injection via unvalidated content",
    "CWE-798":  "hardcoded credentials in source code",
    "CWE-321":  "hardcoded cryptographic key in source code",
    "CWE-259":  "default / hardcoded password in code",
    "CWE-327":  "weak or deprecated cryptographic primitives",
    "CWE-916":  "weak password hashing algorithm",
    "CWE-759":  "password hash without per-user salt",
    "CWE-760":  "predictable salt used in password hash",
    "CWE-347":  "missing or bypassable token signature checks",
    "CWE-862":  "missing authorization on protected endpoints",
    "CWE-284":  "missing access control on protected endpoints",
    "CWE-863":  "incorrect authorization decisions on resources",
    "CWE-639":  "missing ownership checks on resource access",
    "CWE-918":  "unrestricted outbound HTTP from server",
    "CWE-352":  "no CSRF protection on state-changing requests",
    "CWE-434":  "file uploads accepted without type/content validation",
    "CWE-22":   "user input concatenated into filesystem paths",
    "CWE-23":   "user input concatenated into filesystem paths",
    "CWE-200":  "sensitive endpoints exposed without authentication",
    "CWE-209":  "internal errors leaked to clients",
    "CWE-922":  "session token in JavaScript-readable storage",
    "CWE-312":  "sensitive data persisted in cleartext",
    "CWE-538":  "internal files reachable on public routes",
    "CWE-307":  "no brute-force protection on authentication",
    "CWE-400":  "unbounded resource consumption paths",
    "CWE-770":  "missing rate limits on expensive operations",
    "CWE-1104": "unmaintained or vulnerable npm dependencies",
    "CWE-829":  "unverified third-party code loaded at runtime",
    "CWE-346":  "missing origin checks on cross-origin requests",
    "CWE-601":  "open redirect via unvalidated URL parameter",
    "CWE-915":  "mass assignment exposes privileged attributes",
    "CWE-269":  "privilege checks performed only on the client",
    "CWE-1188": "default-on-by-default insecure configuration",
    "CWE-778":  "insufficient audit logging of security events",
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
            "Send `{ \"$where\": \"sleep(5000) || true\" }` and confirm the request is rejected "
            "(HTTP 400) within 100 ms instead of taking ~5 s."
        ),
    },
    "CWE-79": {
        "lang": "typescript",
        "code": (
            "// Never call bypassSecurityTrust*; let Angular sanitize.\n"
            "// template:  <div [innerHTML]=\"product.description\"></div>\n"
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
        "verification": (
            "`git grep -- 'BEGIN RSA PRIVATE KEY'` returns no matches in the working tree."
        ),
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
            "Run a secret-scanner (trufflehog / git-secrets) on HEAD and confirm zero hits "
            "in `lib/` and `routes/`."
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
            "`select password from Users limit 1;` returns a `$2b$12$...` bcrypt prefix, "
            "not a 32-hex md5 string."
        ),
    },
    "CWE-347": {
        "lang": "typescript",
        "code": (
            "// Always verify on the public key; never trust the unsigned header.\n"
            "const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] })"
        ),
        "verification": (
            "Tamper one byte in a valid token's payload and confirm `jwt.verify()` throws."
        ),
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
        "verification": (
            "Hit `/admin/...` with a non-admin JWT and confirm 403 (not 200)."
        ),
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
        "verification": (
            "Cross-check every `/api/*` route for an explicit `requireRole(...)` call; gaps fail CI."
        ),
    },
    "CWE-639": {
        "lang": "typescript",
        "code": (
            "// Ownership check before touching a resource.\n"
            "const basket = await Basket.findByPk(req.params.id)\n"
            "if (!basket || basket.UserId !== req.user.id) return res.status(403).end()"
        ),
        "verification": (
            "Authenticate as user A; request `/api/Baskets/<B's id>` and confirm 403."
        ),
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
        "verification": (
            "POST a URL pointing at `http://169.254.169.254/` and confirm HTTP 400."
        ),
    },
    "CWE-352": {
        "lang": "typescript",
        "code": (
            "// Use double-submit cookie / SameSite=Strict for state-changing routes.\n"
            "app.use(csrf({ cookie: { sameSite: 'strict', httpOnly: true, secure: true } }))"
        ),
        "verification": (
            "Replay a state-changing POST without the CSRF token from a foreign origin "
            "and confirm 403."
        ),
    },
    "CWE-434": {
        "lang": "typescript",
        "code": (
            "// Validate MIME, extension, and magic bytes; cap size.\n"
            "const ALLOWED = new Set(['image/png', 'image/jpeg'])\n"
            "if (!ALLOWED.has(file.mimetype)) throw new Error('mime not allowed')\n"
            "if (file.size > 2 * 1024 * 1024) throw new Error('too large')"
        ),
        "verification": (
            "Upload a `.html` file with `image/png` mimetype and confirm rejection."
        ),
    },
    "CWE-922": {
        "lang": "typescript",
        "code": (
            "// Move the JWT out of localStorage into an httpOnly cookie.\n"
            "res.cookie('session', token, {\n"
            "  httpOnly: true, secure: true, sameSite: 'lax', maxAge: 3600_000\n"
            "})"
        ),
        "verification": (
            "Open browser DevTools, run `localStorage.getItem('token')` and confirm `null`."
        ),
    },
    "CWE-200": {
        "lang": "typescript",
        "code": (
            "// Remove directory-listing middleware; require auth on management endpoints.\n"
            "// app.use('/ftp', serveIndex(...))   // delete\n"
            "app.use('/metrics', requireRole('admin'), promBundle())"
        ),
        "verification": (
            "Unauthenticated `GET /metrics` returns 401; `GET /ftp/` returns 404."
        ),
    },
    "CWE-1104": {
        "lang": "bash",
        "code": (
            "# Pin and audit dependencies; fail CI on known vulns.\n"
            "npm audit --omit=dev --audit-level=high\n"
            "# Upgrade unmaintained packages in package.json, then:\n"
            "npm install && npm test"
        ),
        "verification": (
            "`npm audit --omit=dev --audit-level=high` exits 0."
        ),
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
            "POST `{ \"role\": \"admin\" }` to the register/update endpoint; confirm the "
            "stored row keeps the default role."
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
        "verification": (
            "Send 10 invalid login attempts from one IP and confirm the 6th returns 429."
        ),
    },
    "CWE-778": {
        "lang": "typescript",
        "code": (
            "// Log authn / authz outcomes with stable correlation ids.\n"
            "logger.info({ event: 'auth.login.fail', userId, ip: req.ip, reqId })\n"
            "logger.info({ event: 'authz.deny', userId, route: req.path, reqId })"
        ),
        "verification": (
            "A failed admin probe leaves an `authz.deny` line in the central log within 1 s."
        ),
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
    for cid_local, tlist in threats_by_component.items():
        comp_tier = component_tier_index.get(cid_local) if False else None  # late init below
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
        # Components line. Component IDs are emitted plain (no <b>) — bold
        # is reserved for the column-header HDR_A/T/I cells inside the heatmap
        # so headers and content render with distinguishable weights.
        if comp_ids:
            comp_line = " · ".join(comp_ids)
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
                # M3.11 — Use the cluster-routed threat list so each
                # cluster appears in exactly ONE tier box (Injection in
                # Application, Weak Crypto in Data, etc.).
                # 2026-05 — Also pass the per-tier arrow-CWE allow-set so
                # cluster bullets stay consistent with the arrows that
                # actually point at this tier; bullets without a matching
                # arrow are dropped (they're still in §8).
                "cluster_label_lines": _build_tier_cluster_lines(
                    threats_by_target_tier.get(key, []),
                    arrow_cwe_allow=(cwe_allow_by_tier.get(key) or None),
                ),
            }
        )
    return cards


# ---------------------------------------------------------------------------
# Weakness-cluster vocabulary loader (data/weakness-classes.yaml).
# ---------------------------------------------------------------------------

_WEAKNESS_CLASSES_CACHE: dict[str, Any] | None = None
_STRENGTH_CLUSTERS_CACHE: dict[str, Any] | None = None


# M-10c: File-path extension allowlist. The trailing segment of an em-dash-
# separated title is treated as a file path when it (a) contains a `/` OR
# (b) ends with one of these extensions. The list mirrors the source file
# types the threat-analyzer actually emits — keep it tight; "ext-shaped"
# tokens (e.g. ".md" in prose) inside non-file phrases shouldn't trigger.
_FILE_PATH_EXTENSIONS = frozenset({
    "ts", "tsx", "js", "jsx", "json", "yaml", "yml",
    "py", "go", "rs", "java", "kt", "rb", "php", "cs",
    "c", "h", "cpp", "hpp", "swift", "scala",
    "md", "html", "css", "scss", "sql",
    "sh", "bash", "ps1",
    "lock",  # package-lock.json, Cargo.lock etc.
})

# Compiled regex: a "file-shaped" segment is either dotted with a known
# extension (with optional :line suffix) OR contains a forward-slash path.
_FILE_LIKE_SEGMENT_RE = re.compile(
    r"^[A-Za-z0-9_./-]+\.(?:" + "|".join(_FILE_PATH_EXTENSIONS) + r")(?::\d+)?$"
)
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
        candidate_path = tail[idx + 1:].strip()
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


def _normalize_titles_paren_form(yaml_data: dict, output_dir: "Path") -> None:
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
                normalised.append({
                    "kind": kind,
                    "id": entry.get(id_key) or entry.get("id"),
                    "from": raw,
                    "to": new,
                })

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

    # Compose the new form.
    if path:
        if compact:
            # Parens form for table-cell contexts (Top Mitigations).
            if final_param:
                return f'{weakness} ({path}, "{final_param}")'
            return f"{weakness} ({path})"
        # "in file <path>" when path looks like a file; "in <path>" otherwise.
        in_phrase = "in file" if re.search(r"\.[A-Za-z0-9]{1,6}$", path) else "in"
        if final_param:
            return f'{weakness} {in_phrase} {path} ("{final_param}")'
        return f"{weakness} {in_phrase} {path}"
    if final_param:
        return f'{weakness} ("{final_param}")'
    return weakness


def _load_weakness_classes() -> dict[str, Any]:
    """Lazy-load and cache the weakness-classes vocabulary."""
    global _WEAKNESS_CLASSES_CACHE
    if _WEAKNESS_CLASSES_CACHE is not None:
        return _WEAKNESS_CLASSES_CACHE
    # Resolve plugin root from this file's location (scripts/compose_*.py).
    here = Path(__file__).resolve()
    plugin_root = here.parent.parent
    candidate = plugin_root / "data" / "weakness-classes.yaml"
    if not candidate.exists():
        # Empty fallback — every threat falls into the `_unmapped` cluster.
        _WEAKNESS_CLASSES_CACHE = {"clusters": []}
        return _WEAKNESS_CLASSES_CACHE
    import yaml as _yaml
    try:
        _WEAKNESS_CLASSES_CACHE = _yaml.safe_load(candidate.read_text()) or {"clusters": []}
    except Exception:
        _WEAKNESS_CLASSES_CACHE = {"clusters": []}
    return _WEAKNESS_CLASSES_CACHE


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
    for entry in (_load_architectural_controls().get("controls") or []):
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
    "partial":  "⚠️ Partial",
    "weak":     "🔶 Weak",
    "missing":  "❌ Missing",
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
            for d in (cluster.get("domains") or []):
                if dom == d.strip().lower():
                    return cluster["id"]

    # Pass 2 — keyword substring match across clusters in definition order.
    for cluster in clusters_cfg:
        if cluster.get("id") == "_unmapped":
            continue
        for kw in (cluster.get("name_keywords") or []):
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
        "sql injection", "sqli", "nosql", "$where", "xxe", "ssti",
        "eval(", "eval ", "rce", "code execution", "path traversal",
        "command injection", "template injection", "deserial",
    ],
    "auth_session": [
        "jwt", "alg:none", "alg none", "auth bypass", "authentication",
        "privilege", "admin role", "rsa private key", "session",
        "token", "totp", "2fa", "mfa", "oauth", "saml", "login bypass",
        "credential", "idor",
    ],
    "crypto_hygiene": [
        "md5", " sha-1", " sha1", "hash", "bcrypt", "scrypt", "argon",
        "hardcoded key", "hardcoded credential", "private key",
        "weak crypto", "broken crypt",
    ],
    "http_stack": [
        "csrf", "cors", "csp", "content security policy",
        "wildcard cors", "open redirect", "header injection",
        "rate limit", "permissions-policy", "hsts",
    ],
    "frontend_resilience": [
        "xss", "dom xss", "sanitizer", "bypasssecuritytrust",
        "innerhtml", "trusthtml", "stored xss", "reflected xss",
        "client-side", "client side",
    ],
    "data_protection": [
        "disclosure", "exposure", "localstorage", "leak",
        "ftp directory", "directory listing", "encryption keys",
        "password hash", "pii", "sensitive file",
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
    addressed_classes = set(
        (s or "").strip().lower()
        for s in (cluster_cfg.get("addresses_weakness_classes") or [])
    )
    addressed_cwes = set(
        (s or "").strip().upper()
        for s in (cluster_cfg.get("addresses_cwes") or [])
    )
    cwe_raw = (threat.get("cwe") or "").strip()
    cwe = cwe_raw if cwe_raw.upper().startswith("CWE-") else (
        f"CWE-{cwe_raw}" if cwe_raw.isdigit() else cwe_raw
    )
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
    addressed_classes = set(
        (s or "").strip().lower()
        for s in (cluster_cfg.get("addresses_weakness_classes") or [])
    )
    addressed_cwes = set(
        (s or "").strip().upper()
        for s in (cluster_cfg.get("addresses_cwes") or [])
    )
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
    controls: list[dict], threats_index: dict[str, dict] | None = None,
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
    cfg = (_load_strength_clusters().get("clusters") or [])
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
        best_rank = min(_EFFECTIVENESS_RANK.get((m.get("effectiveness") or "partial").lower(), 9)
                        for m in non_missing)
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
        addressed_critical = [t for t in addressed_for_cap
                              if (t.get("risk") or t.get("severity") or "").lower() == "critical"]
        addressed_high = [t for t in addressed_for_cap
                          if (t.get("risk") or t.get("severity") or "").lower() == "high"]
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
        strong_match_ids = {
            (t.get("id") or t.get("t_id") or "")
            for (t, kind) in matched if kind == "strong"
        }
        def _example_sort_key(t: dict) -> tuple[int, str]:
            tid_ = (t.get("id") or t.get("t_id") or "")
            return (0 if tid_ in strong_match_ids else 1, tid_)
        addressed_critical = sorted(addressed_critical, key=_example_sort_key)
        addressed_high = sorted(addressed_high, key=_example_sort_key)

        # ---- Compact implementations list -------------------------------
        impls: list[str] = []
        for m in non_missing:
            name = (m.get("architectural_control") or m.get("canonical_name")
                    or m.get("name") or m.get("control") or "?")
            impl = m.get("implementation")
            if isinstance(impl, dict):
                impl = impl.get("description") or ""
            impl = (impl or "").strip()
            # Trim long impl strings to 70 chars max for the cell.
            if len(impl) > 70:
                impl = impl[:67].rstrip(" ,;") + "…"
            if impl and impl.lower() != "none":
                impls.append(f"{name} — {impl}")
            else:
                impls.append(str(name))

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
                (t.get("id") or t.get("t_id") or "").strip()
                for t in (addressed_critical + addressed_high)[:3]
            ]
            sample_links = ", ".join(
                f"[{re.sub(r'^T-', 'F-', s)}](#{s.lower()})"
                for s in sample_ids if s
            )
            gap = (
                f"Bypassed by {' + '.join(parts)} finding(s) of the kind this "
                f"cluster is supposed to prevent — e.g. {sample_links}."
                if sample_links else
                f"Bypassed by {' + '.join(parts)} finding(s) of the kind this "
                f"cluster is supposed to prevent."
            )
        elif addressed_for_cap:
            gap = (
                f"{len(addressed_for_cap)} medium/low-severity finding(s) within the cluster's "
                f"remit remain open — see §8 Threat Register for details."
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

        rendered.append({
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
        })

    # Sort: best-effectiveness clusters first, then deterministic by definition order
    rendered.sort(key=lambda x: (_EFFECTIVENESS_RANK.get(x["effectiveness"], 9),
                                 cluster_order.index(x["id"])))
    return rendered


_SEV_RANK_TBL = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_ICON_TBL = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}


_MULTI_MATCH_WARNED: set[str] = set()


def _classify_threat_cluster(threat: dict, vocab: dict | None = None) -> str:
    """Return the weakness-cluster id for a single threat (CWE-based).

    When a CWE is listed in more than one cluster, the cluster appearing
    earliest in the YAML wins (deterministic per file order). A stderr
    warning is emitted on the FIRST encounter of each ambiguous CWE so
    operators see the routing hazard immediately — silent first-match
    was the root cause of Bug A (CWE-916 in both broken_auth and
    weak_crypto routed to whichever cluster came first).
    """
    vocab = vocab or _load_weakness_classes()
    cwe = (threat.get("cwe") or "").strip().upper()
    if not cwe:
        return "_unmapped"
    matches: list[str] = []
    for cluster in vocab.get("clusters") or []:
        if cluster.get("id") == "_unmapped":
            continue
        if cwe in {c.strip().upper() for c in (cluster.get("cwes") or [])}:
            matches.append(cluster["id"])
    if not matches:
        return "_unmapped"
    if len(matches) > 1 and cwe not in _MULTI_MATCH_WARNED:
        _MULTI_MATCH_WARNED.add(cwe)
        sys.stderr.write(
            f"compose_threat_model: WARNING — {cwe} matches multiple "
            f"weakness clusters {matches}; first-match wins ({matches[0]}). "
            f"Consider removing the CWE from all but one cluster in "
            f"data/weakness-classes.yaml to make the routing deterministic.\n"
        )
    return matches[0]


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
    threats: list[dict], *, max_clusters: int = 4,
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
        for cwe in (c.get("cwes") or []):
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
        rendered.append({
            "icon": icon, "label": label, "plural_label": plural_label,
            "variants": seen_vars, "count": len(ts), "sev_rank": sev_max,
        })

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
    return f"{display_name} ({comp_part}) · {n_findings} findings" if comp_part else f"{display_name} · {n_findings} findings"


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
        target = (ap.get("target") or "application").lower()
        actor_slug = (ap.get("actor") or "internet-anon").lower()
        glyph = glyph_seq[idx]

        # P3 (B2): a class is victim-targeting when EITHER target=="victim"
        # (LLM-authored fragment shape) OR actor=="victim-required" (the
        # deterministic-fallback shape).
        is_victim_targeting = target == "victim" or actor_slug == "victim-required"

        if is_victim_targeting:
            client_tier = tier_node_by_key.get("client") or "BROWSER"
            victim = actor_node_by_slug.get("victim-required") or "SHOPUSER"
            # Primary attack arrow: attacker → client tier (injection path).
            if attacker_for_injection and attacker_for_injection != victim:
                arrows.append(
                    {
                        "src": attacker_for_injection,
                        "glyph": glyph,
                        "label": short,
                        "dst": client_tier,
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
                }
            )
    return arrows, relay_arrows


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
    if open_user_registration:
        _collapse_open_registration_actors(attack_paths_data)

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
    # Attacks + relays share the same red styling (both carry numbered glyphs).
    linkstyle_attacks = list(range(n_align, n_align + n_atk + n_relay))
    linkstyle_consequences = list(range(n_align + n_atk + n_relay, n_align + n_atk + n_relay + n_conq))

    # Intro paragraph — one sentence + severity-emoji legend with an
    # explicit note that Low-severity findings are tracked in §8 but
    # omitted from the heatmap (per contract v2 tier_severity_floor).
    glyph_seq = attack_taxonomy.get("glyph_sequence") or ["①", "②", "③", "④", "⑤", "⑥", "⑦"]
    # Count UNIQUE glyphs (P3 — B2: multi-arrow victim-targeting classes
    # share a glyph between their injection and consequence edges; using
    # ``len(attack_arrows)`` would overcount and produce a broken intro
    # like "arrows ①–⑦" when only six numbered classes exist).
    glyphs_used = {a["glyph"] for a in attack_arrows if a.get("glyph")}
    n_glyphs = len(glyphs_used)
    if n_glyphs > 0:
        last_idx = min(n_glyphs, len(glyph_seq)) - 1
        glyph_range = f"①–{glyph_seq[last_idx]}"
    else:
        glyph_range = "①"
    intro_paragraph = (
        "Heatmap: **actors** (left) → **architecture tiers** (middle, "
        "Client → Application → Data) → **impact** (right). "
        f"Numbered red arrows {glyph_range} are the attack paths listed below."
    )
    if open_user_registration:
        intro_paragraph += (
            " Self-registration is open, so authenticated-only attacks "
            "still originate from the anonymous attacker."
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
            "header_label": "Impact",
            "cards": impact_cards,
        },
        "alignment_edges": alignment_edges,
        "attack_arrows": attack_arrows,
        "relay_arrows": relay_arrows,
        "consequence_arrows": consequence_arrows,
        "linkstyle_alignment": linkstyle_alignment,
        "linkstyle_attacks": linkstyle_attacks,
        "linkstyle_consequences": linkstyle_consequences,
    }

    diagram_md = env.get_template("security-posture-diagram.md.j2").render(data=diagram_data)

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
        intro_para = (
            f"**Threat actors.** {n_actors} entities each initiate one "
            f"or more direct attack classes."
        )
    else:
        intro_para = (
            "**Threat actors.** One entity initiates every direct attack class."
        )

    paths_template_data = {
        "intro_paragraph": intro_para,
        "actor_bullets": actor_bullets,
        "attack_paths_header": "**Attack paths (numbered arrows in the diagram):**",
        "attack_paths": attack_paths_rendered,
    }

    paths_md = env.get_template("security-posture-attack-paths.md.j2").render(data=paths_template_data)

    return diagram_md.rstrip() + "\n\n" + paths_md.rstrip() + "\n"


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
    rendered: list[dict[str, Any]] = []
    for idx, tid in enumerate(qualifying_ids[:max_rows], start=1):
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
        # so the Top Findings row matches the §8 Threat Register row title.
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


def _render_architecture_assessment(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """Render the §1 Architecture Assessment block.

    Schema migration (2026-05):

    The historical schema key was ``defects[]`` (each item: ``name`` /
    ``description`` / ``findings[]``). The current schema key is
    ``weaknesses[]`` (each item: ``category`` / ``description`` /
    ``affected_components[]`` / ``findings[]``). Per user request the
    section now leads with the general security-domain *category* (e.g.
    "Cryptography & Secret Management"), names the affected components
    explicitly in their own table column, and uses design-review prose
    (not SAST line citations) in the description.

    The composer auto-upgrades the legacy ``defects[]`` shape on load so
    a fragment authored by an older renderer still renders correctly:
    ``name`` is aliased to ``category`` and ``affected_components`` defaults
    to ``[]``. The template renders ``Defect`` as a column header only when
    no ``weaknesses[]`` key is present AND the legacy ``defects[]`` shape
    is detected — for the current schema the column reads "Weakness category".

    ``affected_components[]`` may be bare strings (component-ids) or
    ``{id, name}`` dicts; this helper enriches bare strings with the
    component's display name from ``ctx.yaml_data.components[]`` so the
    template can render the cell with ``[id](#id) — Name``.
    """
    data = _load_fragment(ctx, "architecture_assessment", section["fragment"])
    _validate_fragment("architecture_assessment", data, section["schema"])

    # Back-compat: lift `defects` → `weaknesses` if the fragment still
    # uses the legacy shape. Keep `defects` field for any external reader
    # that depends on it.
    if "weaknesses" not in data and "defects" in data:
        legacy = data.get("defects") or []
        weaknesses = []
        for item in legacy:
            if not isinstance(item, dict):
                continue
            weaknesses.append({
                "category": item.get("name") or item.get("category") or "",
                "description": item.get("description") or "",
                "affected_components": item.get("affected_components") or [],
                "findings": item.get("findings") or [],
            })
        data = dict(data)
        data["weaknesses"] = weaknesses

    # Enrich affected_components: resolve bare component-ids to {id, name}
    # using the components index from the canonical YAML so the column
    # renders with the display name.
    comp_lookup = _component_lookup(ctx)

    # Auto-derive `affected_components` when the Stage-2 LLM fragment left
    # them empty. We walk `weaknesses[].findings[].ref`, map each F-/T-NNN
    # back to its `threats[].component` via the YAML, and emit a unique
    # list. The fallback runs ONLY when the LLM-provided list is empty —
    # explicit author-set values are preserved.
    threats_by_id: dict[str, str] = {}
    for t in (ctx.yaml_data.get("threats") or []):
        tid = (t.get("t_id") or t.get("id") or "").strip().upper()
        comp = (t.get("component") or "").strip()
        if not tid or not comp:
            continue
        threats_by_id[tid] = comp
        # Register both T-NNN and F-NNN aliases so findings carrying either
        # form resolve cleanly.
        if tid.startswith("T-"):
            threats_by_id.setdefault("F-" + tid[2:], comp)
        elif tid.startswith("F-"):
            threats_by_id.setdefault("T-" + tid[2:], comp)

    for w in data.get("weaknesses") or []:
        raw = w.get("affected_components") or []
        if not raw:
            derived: list[str] = []
            for f in (w.get("findings") or []):
                ref = (f.get("ref") or "").strip().upper() if isinstance(f, dict) else ""
                cid = threats_by_id.get(ref)
                if cid and cid not in derived:
                    derived.append(cid)
            raw = derived
        enriched = []
        for entry in raw:
            if isinstance(entry, str):
                cid = entry.strip()
                if not cid:
                    continue
                meta = comp_lookup.get(cid) or {}
                enriched.append({"id": cid, "name": (meta.get("name") or cid)})
            elif isinstance(entry, dict):
                cid = (entry.get("id") or "").strip()
                name = (entry.get("name") or "").strip()
                if cid and not name:
                    meta = comp_lookup.get(cid) or {}
                    name = meta.get("name") or cid
                enriched.append({"id": cid, "name": name})
        w["affected_components"] = enriched

    tpl = env.get_template(section["template"])
    return tpl.render(data=data).rstrip() + "\n"


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
            sev = _severity_rank(t.get("risk") or t.get("severity"))
            max_sev = min(max_sev, sev)
            # M3.12 — short title KEEPS the trailing `(<param>, <file>)` /
            # `(<file>)` token. A bare "SQL Injection" cell is structurally
            # useless because the reader has no idea which endpoint it
            # refers to. Strip ONLY the `:line` from the path so the
            # trailing token stays compact (`routes/login.ts` rather than
            # `routes/login.ts:34`). The §8 register still carries the
            # full file:line for click-through detail.
            raw_title = (t.get("title") or t.get("scenario_short") or "").strip()
            # compact=True — Top Mitigations Addresses cells stack 4-5
            # findings via `<br/>`; the parens form is more scannable
            # than 4 repeated "in file" phrases per row.
            short_label = _shorten_title_for_xref(raw_title, t, compact=True)
            addressed.append({"ref": tid, "label": short_label})
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
    mit_max = (
        (ctx.contract["sections"].get("mitigations") or {})
        .get("table", {})
        .get("rows", {})
        .get("max", 5)
    )
    p12_total_before_cap = len(p12_rows)
    p12_rows = sorted(p12_rows, key=_row_sort_key)[:mit_max]
    p12_dropped = max(0, p12_total_before_cap - len(p12_rows))

    # Bucket rows by primary_component_id.
    buckets: dict[str, list[dict[str, Any]]] = {}
    for r in p12_rows:
        primary = r.get("primary_component_id") or ""
        buckets.setdefault(primary, []).append(r)

    # Flatten into one row list with divider markers between buckets.
    components_meta = {
        (c.get("id") or "").strip(): c
        for c in (ctx.yaml_data.get("components", []) or [])
    }
    # 2026-05 — per-component groups with a paragraph divider per group
    # (no `####` H4 sub-headers per prior user guidance; no in-table
    # divider rows because Markdown pipe-tables have no colspan and the
    # `| label | | | | |` form rendered as one cell + 4 empty cells.
    # The new layout emits one pipe-table per component bucket, separated
    # by a bold paragraph divider — visually the component label spans
    # the full table width because it sits OUTSIDE the table.
    groups: list[dict[str, Any]] = []
    _row_number = 0
    for cid in sorted(buckets.keys(), key=_component_sort_key):
        bucket = sorted(buckets[cid], key=_row_sort_key)
        if cid:
            comp_name = (components_meta.get(cid) or {}).get("name", cid)
            divider_label = f"↳ {comp_name} ({cid}) — {pluralize(len(bucket), 'item')}"
        else:
            divider_label = f"↳ Cross-cutting — {pluralize(len(bucket), 'item')}"
        # Continuous numbering across groups (1..N), so the # column reads
        # as a global leader-board rank rather than per-component 1..N.
        group_rows: list[dict[str, Any]] = []
        for r in bucket:
            r["is_divider"] = False
            _row_number += 1
            r["number"] = _row_number
            group_rows.append(r)
        groups.append({
            "header": None,
            "divider_label": divider_label,
            "include_affects_column": False,
            "mitigations": group_rows,
        })

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
    intro = (
        f"Highest-impact P1/P2 mitigations — {len(p12_rows)} of "
        f"{p12_total_before_cap} qualifying ({total_count} total). "
        f"Full detail in [§9 Mitigation Register](#9-mitigation-register)."
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
            "*" + " · ".join(footer_parts)
            + " in [§9 Mitigation Register](#9-mitigation-register). "
            + "Sorted within each component by priority (P1 first), then "
            + "severity (Critical first), then effort (Low first).*"
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
        "partial":  "Covers only part of the attack surface",
        "weak":     "Implementation uses a weak primitive",
        "missing":  "Control not implemented",
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
        impl = (c.get("implementation") or "")
        if isinstance(impl, dict):
            impl = impl.get("description") or ""
        impl = (impl or "").strip()
        # Look for "only <X>" / "<X> only" / "limited to <X>" / etc.
        # Cap at 80 chars so the cell stays scannable.
        m = re.search(
            r"\b(only|limited to|except|except for|but not|missing|disabled|wildcard|commented out|opt-?in|not enforced)\b[^.\n]{0,80}",
            impl, flags=re.IGNORECASE,
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
            for line in (cl.get("implementations") or []):
                what_lines.append(line)
            what_in_place = "<br/>".join(what_lines) if what_lines else "—"
            gap = cl.get("gap") or _GAP_BY_EFFECTIVENESS.get(eff, _GAP_FALLBACK)
            # Mitigates with overflow indicator.
            mit_list = list(cl.get("mitigates") or [])
            mit_overflow = cl.get("mitigates_overflow", 0)
            if mit_overflow > 0:
                mit_list.append({"ref": None, "label": f"+{mit_overflow} more", "_overflow": True})
            rendered_rows.append({
                "label": cl["label"],
                "architectural_control": cl["label"],  # back-compat key
                "what_in_place": what_in_place,
                "implementation": what_in_place,        # back-compat key
                "effectiveness": eff,
                "gap": gap,
                "mitigates": mit_list,
                "members": members,
                "open_critical_count": cl.get("open_critical_count", 0),
                "open_high_count": cl.get("open_high_count", 0),
            })
        overflow = 0  # clustering covers all eligible controls
    else:
        # Legacy fallback — preserves the old one-row-per-control layout.
        for c in filtered[:max_rows]:
            eff = (c.get("effectiveness") or "partial").lower()
            impl = c.get("implementation")
            if isinstance(impl, dict):
                impl = impl.get("description") or ""
            implementation = (
                (impl or "")
                or (c.get("description") or "")
                or (c.get("evidence") or "")
                or "—"
            )
            if not isinstance(implementation, str):
                implementation = str(implementation)
            rendered_rows.append({
                "label": arch_control_name(c),
                "architectural_control": arch_control_name(c),
                "what_in_place": implementation.strip(),
                "implementation": implementation.strip(),
                "effectiveness": eff,
                "gap": gap_text(c, eff),
                "mitigates": mitigates_cell(c),
            })
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
    empty_banner = ""
    if clusters and not rendered_rows:
        if demoted_count > 0:
            sample = ", ".join(demoted_labels[:3])
            extra = f" and {demoted_count - 3} more" if demoted_count > 3 else ""
            empty_banner = (
                f"_No defensive cluster currently rates above Weak. "
                f"{demoted_count} cluster(s) — {sample}{extra} — were demoted "
                f"because §8 holds open Critical/High findings of the kind "
                f"each cluster is supposed to prevent. See "
                f"[§7 Security Architecture](#7-security-architecture) for "
                f"the full per-control assessment and "
                f"[§9 Mitigation Register](#9-mitigation-register) for the "
                f"prioritised fix list._"
            )
        else:
            empty_banner = (
                f"_No defensive cluster currently rates above Weak. See "
                f"[§7 Security Architecture](#7-security-architecture) for "
                f"the full per-control assessment._"
            )

    show_intro = ctx.eval_context.get("verdict_severity") in ("yellow", "red") and bool(rendered_rows)
    section7_present = bool(ctx.eval_context.get("render_security_architecture", True))
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


def _render_requirements_compliance_ms(ctx: RenderContext) -> str:
    """Derive the ### Requirements Compliance MS subsection from the
    .fragments/requirements-compliance.md fragment.

    Extracts:
    - Baseline URL from the first "from the [name](url) baseline" line
    - Summary line (PASS/FAIL/ANTI-PATTERN/PARTIAL counts)
    - Up to 3 architectural violation bullets, ordered:
        ANTI-PATTERN MUST → ANTI-PATTERN SHOULD → FAIL architectural MUST
        → FAIL architectural SHOULD → FAIL MUST → FAIL SHOULD

    Returns empty string when the fragment is missing or malformed.
    """
    frag_path = ctx.output_dir / ".fragments" / "requirements-compliance.md"
    if not frag_path.is_file():
        return ""

    text = frag_path.read_text(encoding="utf-8")

    # --- Baseline URL ---
    baseline_m = re.search(
        r"from the \[([^\]]+)\]\(([^)]+)\) baseline",
        text,
    )
    if baseline_m:
        baseline = f"[{baseline_m.group(1)}]({baseline_m.group(2)})"
    else:
        # fall back to plain text when URL is missing
        baseline_m2 = re.search(r"from the ([^\n]+?) baseline", text)
        baseline = baseline_m2.group(1).strip() if baseline_m2 else "configured baseline"

    # --- Summary line ---
    summary_m = re.search(
        r"\*\*Summary:\*\*\s*(.+?)(?:\n|$)",
        text,
    )
    result_line = summary_m.group(1).strip() if summary_m else ""

    # --- Extract up to 3 architectural violation bullets ---
    # Parse the Architectural Violations table (if present).
    # Table rows: | [ID](url) — title | MUST/SHOULD | evidence | risk | linked |
    arch_rows: list[tuple[str, str, str]] = []  # (priority, id_link, evidence)
    in_arch_table = False
    for line in text.splitlines():
        if "### Architectural Violations" in line:
            in_arch_table = True
            continue
        if in_arch_table:
            if line.startswith("### "):
                break  # left the table section
            # Match table data rows (skip header and separator rows)
            row_m = re.match(
                r"\|\s*(\[.+?\]\(.+?\)(?:\s*—\s*.+?)?)\s*\|\s*(MUST|SHOULD|MAY)\s*\|(.+?)\|",
                line,
            )
            if row_m:
                id_cell = row_m.group(1).strip()
                priority = row_m.group(2).strip()
                evidence = row_m.group(3).strip()
                arch_rows.append((priority, id_cell, evidence))

    # Order: MUST first, then SHOULD, then MAY (stable sort preserves file order within tier)
    _priority_order = {"MUST": 0, "SHOULD": 1, "MAY": 2}
    arch_rows.sort(key=lambda r: _priority_order.get(r[0], 9))
    top3 = arch_rows[:3]

    # --- Compose the subsection ---
    lines: list[str] = ["### Requirements Compliance", ""]
    lines.append(f"**Baseline:** {baseline}")
    if result_line:
        lines.append(f"**Result:** {result_line}")
    lines.append("")
    if top3:
        for priority, id_cell, evidence in top3:
            lines.append(f"- **{id_cell} `{priority}`:** {evidence}")
        lines.append("")
    lines.append("→ *Full compliance details in [Section 7b — Requirements Compliance](#7b-requirements-compliance).*")
    return "\n".join(lines)


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
        "security_posture_at_a_glance",
        "top_findings",
        "architecture_assessment",
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
        if body.strip():
            parts.append(body.rstrip())
    return "\n\n".join(parts) + "\n"


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
    tpl = env.get_template(section["template"])
    return tpl.render(data=data).rstrip() + "\n"


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
    """Load a LLM-authored prose fragment (.md) and validate its structural
    constraints (first heading matches, required subsections present).

    Enrichments applied at render time (never by the LLM):
      * §2 architecture_diagrams — inject a `<a id="c-NN">` component anchor
        table underneath `### 2.3 Components` if the LLM fragment did not
        provide one. Without this anchor, every downstream C-NN reference in
        the Top Findings and Threat Register tables becomes a dead link.

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
    md = _load_fragment(ctx, section_id, fragment_name)
    if not isinstance(md, str):
        raise FragmentError(section_id, f"expected Markdown text in {fragment_name}")

    expected = (section.get("heading") or "").strip()
    first_nonblank = next((ln.strip() for ln in md.splitlines() if ln.strip()), "")
    if expected and first_nonblank != expected:
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
    # schema_v2 overlay — when the active skill-config
    # carries `security_schema: v2`, prefer `section.schema_v2.required_subsections`
    # over the legacy `section.required_subsections`. The yaml file keeps both
    # surfaces; this is a runtime swap based on the resolved config.
    _required_subs_v1 = section.get("required_subsections") or []
    _required_subs = _required_subs_v1
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
                    if section_id == "security_architecture" else ""
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
    for domain_title, patterns in (section.get("domain_required_patterns") or {}).items():
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

    # Escape `$word` tokens (MongoDB `$where`/`$ne`, jQuery selectors, bash
    # vars) so KaTeX/MathJax-enabled renderers don't treat the `$` as math
    # mode and blow up on the next `#` inside `](#t-NNN)`. Runs last so the
    # linkify passes above see the raw text first.
    md = _escape_dollar_operators(md)
    md = _escape_dot_tld_identifiers(md)
    # `_escape_html_payloads_in_prose` is intentionally NOT called here —
    # markdown fragments are only one of several section types and the
    # §8 Threat Register (computed section) bypasses this wrapper. The
    # escape pass runs in the END-OF-RENDER pipeline (see `render()` near
    # the bottom of this file) so every section type is covered.

    return md.rstrip() + "\n"


_ATTACK_WALKTHROUGHS_DEFAULT_INTRO = (
    "This section reconstructs how Critical and High findings would actually "
    "play out as attacks. It has two parts: §3.1 gives a high-level chain "
    "diagram showing how an attacker reaches impact across multiple findings, "
    "and §3.2+ walks through each individual Critical finding as a sequence "
    "diagram contrasting current behaviour with the post-mitigation state. "
    "Read §3.1 first to understand the kill-chains; drill into §3.2+ when "
    "you need the per-finding mechanics. Medium- and Low-severity findings "
    "are not walked through here — they are documented in [§8 Threat Register](#8-threat-register)."
)

_CHAIN_OVERVIEW_DEFAULT_INTRO = (
    "Each chain below is one realistic path from an entry point to a "
    "business-impact outcome. Nodes coloured red are attacker-controlled "
    "states or actions; nodes coloured dark are impact outcomes. The arrows "
    "encode causality, not timing. A chain typically covers 2–4 findings — "
    "every individual finding keeps its detailed write-up in §8 Threat "
    "Register and is linked from there back to the chain that uses it."
)


def _inject_attack_walkthroughs_intros(ctx: "RenderContext", md: str) -> str:
    """Ensure §3 / §3.1 carry intro paragraphs even when the LLM-authored
    fragment skipped them.

    2026-05 user-request fix (points 1, 2): the previous Stage-2 renderer
    sometimes wrote a fragment that opened directly with the §3.1 mermaid
    block, leaving §3 with no chapter intro and §3.1 with no explanation of
    what the chain diagram encodes. The compose step now scaffolds default
    intros from `_ATTACK_WALKTHROUGHS_DEFAULT_INTRO` and
    `_CHAIN_OVERVIEW_DEFAULT_INTRO` when missing. LLM-authored intros are
    preserved as-is (the function detects existing prose between the heading
    and the next heading / mermaid block).

    Idempotent — a second invocation finds the intros already present and
    no-ops.
    """
    if not md:
        return md

    def _has_prose_before(heading_match: "re.Match[str]", text: str) -> bool:
        """Return True when there is at least one line of non-blank, non-fence,
        non-heading prose immediately after the heading and before the next
        structural element (another heading or a fenced block)."""
        tail = text[heading_match.end():]
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
        md = md[:chap.end()] + "\n\n" + _ATTACK_WALKTHROUGHS_DEFAULT_INTRO + "\n" + md[chap.end():]

    # §3.1 Attack Chain Overview intro
    sub = re.search(r"^### 3\.1[ \t]+Attack Chain Overview\s*$", md, re.MULTILINE)
    if sub and not _has_prose_before(sub, md):
        md = md[:sub.end()] + "\n\n" + _CHAIN_OVERVIEW_DEFAULT_INTRO + "\n" + md[sub.end():]

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
    if has_runtime:
        table_lines = [
            "",
            "| ID | Name | Type | Runtime | Key Paths | Linked Threats |",
            "|----|------|------|---------|-----------|----------------|",
        ]
    else:
        table_lines = [
            "",
            "| ID | Name | Type | Key Paths | Linked Threats |",
            "|----|------|------|-----------|----------------|",
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
            th = threats_by_id.get(tid) if isinstance(threats_by_id, dict) else None
            title = (th or {}).get("title") if isinstance(th, dict) else None
            if not title:
                title = ctx.lookup_label(tid)  # synthesise from scenario when title: ""
            if include_titles and title:
                return f"[{tid}](#{tid.lower()}) — {title}"
            return f"[{tid}](#{tid.lower()})"

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
        if has_runtime:
            table_lines.append(
                f"| {''.join(anchors)}{canonical} | {name} | {kind} | {runtime} | {paths_cell} | {th_cell} |"
            )
        else:
            table_lines.append(f"| {''.join(anchors)}{canonical} | {name} | {kind} | {paths_cell} | {th_cell} |")
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
    return md


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
        # Singular "Mitigation" is the §8 Threat Register column header where
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
        is the Threat Register / Mitigation Register `| <a id="t-003"></a>T-003 | …` style.
      * The cell contains zero ID-shaped links.
      * The cell contains exactly one link that already carries ``— label``.
    """
    out_lines = md.split("\n")
    for header_idx, block in _iter_md_table_blocks(md):
        header_cells = _split_table_row(block[0])
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
        residue_bare = re.sub(r"(<br/?>|[,;\s])+", "", stripped_bare).strip()
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
    residue = re.sub(r"(<br/?>|[,;\s])+", "", stripped).strip()
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
        # Slug uses the FULL heading text (number + title) per
        # _anchor_from_heading semantics — the GFM convention.
        slug = _anchor_from_heading(f"{hashes} {num} {title}")
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
            lines[i] = _sub_outside_link_labels(line)
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
            # Mermaid blocks: em dash is not syntactic; normalise inside
            # so the rendered diagram stays consistent with the prose.
            chunk = _EMDASH_SPACED_RE.sub("-", chunk)
            chunk = _EMDASH_TIGHT_RE.sub("-", chunk)
            out_chunks.append(chunk)
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
            elif (stripped.startswith("- **") or stripped.startswith("- <a id=") or stripped.startswith("- [F-") or stripped.startswith("- [T-") or stripped.startswith("- [M-")) and " — " in line:
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
_DOT_IDENT_TLD_RE = re.compile(r"(?<![`\[\w/])([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z]{2,4})\b(?![/\w])")

# Source-file extensions that look like ccTLDs (.ts → Turkmenistan, .js → Jersey, etc.).
# When the TLD-shaped suffix matches one of these, the token is treated as a
# bare filename and left alone — GFM does not auto-link bare filenames the way
# it auto-links genuine TLD-shaped tokens.
_FILE_EXTENSION_SUFFIXES: frozenset[str] = frozenset(
    {
        # Code
        "ts", "tsx", "js", "jsx", "mjs", "cjs",
        "py", "rb", "go", "rs", "java", "kt", "kts", "scala",
        "cpp", "cc", "cxx", "hpp", "hxx", "hh",
        "cs", "fs", "vb",
        "swift", "m", "mm",
        "lua", "pl", "pm", "sh", "bash", "zsh", "fish",
        "php", "phtml",
        "dart", "ex", "exs", "erl", "hrl",
        "clj", "cljs", "edn",
        "ml", "mli",
        "r", "jl",
        "sql",
        # Config / data
        "yml", "yaml", "json", "toml", "ini", "cfg", "conf", "env",
        "xml", "csv", "tsv",
        "lock",
        # Markup / web
        "md", "rst", "txt", "rtf",
        "html", "htm", "css", "scss", "sass", "less",
        "svg",
        # Container / IaC
        "tf", "tfvars",
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
    r"</?(?:script|iframe|svg|object|embed|form|style|link|meta)\b[^>]*/?>"
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
        r"(```[^\n]*\n.*?\n```"        # fenced code
        r"|<details\b.*?</details>"    # Story Card code blocks
        r"|<pre\b.*?</pre>"            # raw <pre>
        r"|<code\b.*?</code>"          # raw <code>
        r"|`[^`\n]+`)",                # inline code span
        flags=re.DOTALL,
    )
    out_chunks: list[str] = []
    for chunk in PROTECTED_RE.split(md):
        if not chunk:
            continue
        if (chunk.startswith("```") or chunk.startswith("<details")
                or chunk.startswith("<pre") or chunk.startswith("<code")
                or (chunk.startswith("`") and chunk.endswith("`"))):
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
            # Known-safe brand / framework name. Backtick-wrap to defeat
            # GFM auto-link without inserting invisible characters. The
            # legacy ZWSP (U+200B) approach is retired — see
            # agents/appsec-threat-renderer.md §"Brand-token escape":
            # ZWSP is fragile across PDF/HTML/RSS/IDE renderer pipelines
            # and invisible to authors editing source. Backtick-wrap
            # renders unchanged in every downstream format.
            return f"`{full}`"
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
        r"(```[^\n]*\n.*?\n```|`[^`\n]+`|<!--.*?-->|\[[^\]]+\]\([^)]+\))",
        md,
        flags=re.DOTALL,
    ):
        if chunk.startswith("```") or chunk.startswith("`") or chunk.startswith("<!--") or chunk.startswith("["):
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
    # re-lookup the same ID over and over.
    cache: dict[str, str] = {}

    def resolve(ref: str) -> str:
        # Use parens form for inline prose so the rendered text reads as
        # `[T-005](#t-005) (Reflected XSS via search query parameter)`
        # rather than `… — Reflected XSS … — search-result.component.ts`
        # (the latter is a torn-link construct after _normalize_emdashes
        # converts the separator em-dash to a hyphen mid-line).
        if ref not in cache:
            cache[ref] = ctx.linkify_with_short_label(ref)
        return cache[ref]

    # Find every bare `[X-NNN](#x-nnn)` that is NOT followed by an existing
    # em-dash label OR an existing parens label — both are signs the link
    # has already been enriched and re-expanding would double-label.
    def sub_ref(m: re.Match) -> str:
        ref = m.group(1)
        # Skip citation style `*([F-009](#f-009))*` — check surrounding chars.
        start = m.start()
        prefix = md[max(0, start - 3) : start]
        if prefix.endswith("*(") or prefix.endswith("*("):
            return m.group(0)
        return resolve(ref)

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
        for i, line in enumerate(lines):
            if re.match(r"^\s{0,3}#{1,6}\s", line):
                # Heading — do not expand refs.
                continue
            lines[i] = re.sub(
                # Skip refs already followed by ` — <label>` (em-dash form,
                # produced by linkify_with_label in table cells / register
                # builders) AND refs already followed by ` (<label>)` (parens
                # form, produced by linkify_with_short_label in prose).
                r"\[([FTM]-\d{3,4})\]\(#[ftm]-\d+\)(?!\s+[—(])",
                sub_ref,
                line,
            )
        out_chunks.append("\n".join(lines))
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
    duration = meta.get("analysis_duration_seconds")
    if not duration and stage_rows:
        # Sum stage duration_ms; round to seconds.
        ms_sum = sum(r.get("duration_ms", 0) for r in stage_rows)
        if ms_sum:
            duration = ms_sum // 1000
    dur_fmt = f"{int(duration) // 60}m {int(duration) % 60:02d}s" if duration else "—"

    lines: list[str] = ["## Appendix: Run Statistics", ""]

    # --- Header field table -------------------------------------------------
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Invocation | `{invocation}` |")
    lines.append(f"| Generated | {generated} |")
    lines.append(f"| Mode | {mode} |")
    lines.append(f"| Assessment depth | {depth} |")
    plugin_cell = f"{plugin_v}" + (f" (analysis v{analysis_v})" if analysis_v else "")
    lines.append(f"| Plugin version | {plugin_cell or '—'} |")
    lines.append(f"| Orchestrator model | {orch_model} |")
    lines.append(f"| Repository | {repo} |")
    lines.append(f"| Output directory | {out_dir} |")
    lines.append(f"| Total analysis duration | {dur_fmt} |")
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
    # in the Run Statistics header block, the §8 Threat Register risk-
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
        (a.get("role") or "—") not in ("—", "", None)
        or (a.get("phases") or "—") not in ("—", "", None)
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
    """Resolve the active §7 schema (v1 vs v2).

    Priority (matches resolve_config.py + qa_checks._apply_schema_v2_overlay):
      1. APPSEC_SECURITY_SCHEMA env-var ("v1" or "v2") — explicit override
      2. APPSEC_SCHEMA_V1=1 env-var — legacy opt-out shortcut
      3. .skill-config.json → security_schema
      4. default "v2" (since 2026-05)
    """
    import os as _os
    forced = (_os.environ.get("APPSEC_SECURITY_SCHEMA") or "").strip().lower()
    if forced in {"v1", "v2"}:
        return forced
    if _os.environ.get("APPSEC_SCHEMA_V1", "").strip() in (
        "1", "true", "yes", "on"
    ):
        return "v1"
    cfg = _read_skill_config(output_dir).get("security_schema") or ""
    cfg = cfg.strip().lower() if isinstance(cfg, str) else ""
    if cfg in {"v1", "v2"}:
        return cfg
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
        intro = (
            "_The composition pipeline ran cleanly with no warnings or retries._"
        )
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
        "Top Findings table and throughout [§8 Threat Register](#8-threat-register). Each label answers the "
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
    "CWE-22":   "Filesystem path constructed from user input without normalisation against an allow-listed root.",
    "CWE-79":   "User input rendered into HTML without context-appropriate output encoding (or with the framework's escape mechanism explicitly bypassed).",
    "CWE-89":   "User input concatenated into SQL strings instead of using parameterised queries.",
    "CWE-94":   "Dynamic code construction (eval / Function / vm.runInContext) on attacker-influenced input.",
    "CWE-95":   "Dynamic evaluation of an attacker-controlled expression instead of using a sandboxed expression evaluator.",
    "CWE-200":  "Sensitive information exposed in API response, URL, or error message.",
    "CWE-306":  "Privileged endpoint exposed without an authentication middleware in front of it.",
    "CWE-307":  "No rate-limiting on a brute-force-able endpoint (login / password reset / token validation).",
    "CWE-319":  "Sensitive data transmitted in clear-text (no TLS / plain-text protocol).",
    "CWE-321":  "Hard-coded cryptographic key in source code instead of loading from a secret store at runtime.",
    "CWE-327":  "Use of a broken or risky cryptographic primitive — defaults are not safe in the current threat model.",
    "CWE-345":  "Security decision relies on a value that is not integrity-protected against the attacker.",
    "CWE-352":  "State-changing request accepted without a CSRF token or equivalent same-origin guard.",
    "CWE-400":  "Endpoint accepts unbounded input or runs an unbounded loop without resource caps.",
    "CWE-502":  "Untrusted serialized data deserialised into live objects, allowing gadget-chain code execution.",
    "CWE-532":  "Sensitive content (logs, key material) reachable through the public HTTP surface.",
    "CWE-540":  "Source code or secrets included in the deployed artifact / served by the public file handler.",
    "CWE-552":  "Sensitive files made reachable through the public HTTP surface without an auth gate.",
    "CWE-601":  "Redirect target derived from user input without an allow-list, enabling phishing redirects.",
    "CWE-602":  "Security decision implemented on the client; the trusted server-side check is missing.",
    "CWE-611":  "XML parser configured to resolve external entities — XXE protection not enabled.",
    "CWE-639":  "Object reference accepted from the request without an ownership / authorization check.",
    "CWE-778":  "No audit logging on security-sensitive operations — incident reconstruction not possible.",
    "CWE-798":  "Hard-coded credentials in source code instead of secret-store lookup.",
    "CWE-916":  "Outdated / cryptographically broken password hashing algorithm in use (or no key-stretching at all).",
    "CWE-918":  "Outbound HTTP request target derived from user input without an allow-list / DNS-pinning.",
    "CWE-922":  "Sensitive data stored client-side in locations accessible to JavaScript (localStorage / sessionStorage).",
    "CWE-942":  "CORS configuration accepts arbitrary origins (wildcard or reflective Allow-Origin).",
    "CWE-943":  "User input interpolated into a NoSQL query expression instead of using the driver's parameter-binding API.",
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


def _read_evidence_snippet(
    repo_root: Path | None, file_path: str, line: int | None, context: int
) -> str | None:
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
    # Strip trailing newline / cap each line to 200 chars so minified files
    # never blow up a cell. Preserve indentation.
    snippet_lines = [all_lines[i].rstrip("\n")[:200] for i in range(lo - 1, hi)]
    return "\n".join(snippet_lines)


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
        "ts": "language-typescript", "tsx": "language-typescript",
        "js": "language-javascript", "jsx": "language-javascript",
        "py": "language-python", "rb": "language-ruby",
        "go": "language-go", "rs": "language-rust",
        "java": "language-java", "sh": "language-bash",
        "yaml": "language-yaml", "yml": "language-yaml",
        "json": "language-json", "toml": "language-toml",
        "md": "language-markdown", "html": "language-html",
        "css": "language-css", "scss": "language-scss",
        "sql": "language-sql", "env": "language-bash",
    }.get(ext, "")


# Per-severity rendering depth knobs for the Story Card. The numbers are
# tuned for readability: Critical findings get a full case description plus
# evidence snippet; Low findings get a one-sentence root cause only.
_FINDING_DEPTH: dict[str, dict[str, int]] = {
    "critical": {"snippet_context": 3, "scenario_sentences": 4},
    "high":     {"snippet_context": 2, "scenario_sentences": 3},
    "medium":   {"snippet_context": 1, "scenario_sentences": 2},
    "low":      {"snippet_context": 0, "scenario_sentences": 1},
}

# CWE classes where a code snippet does NOT add meaningful information beyond
# the title + scenario. These are configuration / absence findings — the
# defect is the absence of a control, not a specific buggy line of code, so
# the snippet would just show benign surrounding lines. Restricting snippets
# to CWEs where the bug IS the code yields ~30% narrower §8 cells without
# losing analytical signal. The check is best-effort: when the CWE is
# missing or not in either list we keep the snippet (legacy behaviour).
_FINDING_SKIP_SNIPPET_CWES: set[str] = {
    "CWE-352",   # CSRF — absence of token
    "CWE-693",   # Protection Mechanism Failure
    "CWE-1021",  # Restriction of Rendered UI (CSP missing)
    "CWE-942",   # Permissive CORS — config-class
    "CWE-922",   # Insecure Storage of Sensitive Information (localStorage)
    "CWE-602",   # Client-Side Enforcement of Server-Side Security
    "CWE-200",   # Generic information disclosure (often config / file-serve)
    "CWE-916",   # Use of Password Hash With Insufficient Computational Effort
    "CWE-326",   # Inadequate Encryption Strength
    "CWE-327",   # Use of a Broken or Risky Cryptographic Algorithm
    "CWE-321",   # Hard-coded Cryptographic Key (snippet redacted anyway)
    "CWE-400",   # Resource Consumption (DoS configuration)
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
    "22":  "User-supplied path components are joined without traversal-safe canonicalisation",
    "78":  "Untrusted input is concatenated into a shell-executed command string",
    "79":  "User input is rendered as HTML without contextual output encoding",
    "89":  "SQL is assembled via string concatenation/interpolation of untrusted input",
    "94":  "User-supplied code is passed to a runtime evaluator without an allow-list of operations",
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
    "89":   "Switch all SQL execution to parameterised queries or ORM-bound parameters",
    "564":  "Switch all SQL execution to parameterised queries or ORM-bound parameters",
    "943":  "Replace string concatenation in query operators with parameter binding",
    "78":   "Replace shell invocations with an argv-list API and validate every input",
    "94":   "Replace runtime code generation (eval/Function/template render) with a data-only execution path",
    "95":   "Replace runtime code generation (eval/Function/template render) with a data-only execution path",
    "917":  "Replace dynamic expression evaluation with safe template rendering or a static lookup",
    "79":   "Output-encode untrusted strings at every sink and remove all `bypassSecurityTrustHtml` calls",
    "80":   "Output-encode untrusted strings at every sink and remove all `bypassSecurityTrustHtml` calls",
    "611":  "Disable external entity resolution on every XML parser and reject DOCTYPE declarations",
    "918":  "Validate the URL scheme + host against an explicit allow-list before issuing outbound requests",
    "22":   "Resolve and normalise every constructed path and reject anything that escapes the intended base directory",
    "23":   "Resolve and normalise every constructed path and reject anything that escapes the intended base directory",
    "352":  "Enforce a same-origin or signed CSRF token on every state-changing endpoint",
    "284":  "Add explicit server-side authorisation checks on every protected route",
    "285":  "Add explicit server-side authorisation checks on every protected route",
    "639":  "Tie every object lookup to the requesting user's identity and reject cross-tenant references",
    "287":  "Strengthen authentication: enforce a vetted JWT verifier with explicit algorithm, MFA where appropriate",
    "347":  "Pin the signature algorithm explicitly and reject `alg:none` and unknown algorithms",
    "798":  "Move the credential out of source control into a secret store and rotate it",
    "321":  "Move the cryptographic key out of source control into a managed secret store and rotate it",
    "259":  "Move the credential out of source control into a secret store and rotate it",
    "327":  "Replace the broken algorithm with a vetted modern primitive (AES-GCM / Argon2id / Ed25519)",
    "328":  "Replace the broken hash with a salted password-hashing function (bcrypt/Argon2id)",
    "916":  "Replace the broken hash with a salted password-hashing function (bcrypt/Argon2id)",
    "330":  "Switch to a cryptographically secure RNG (`crypto.randomBytes` / OS `/dev/urandom`)",
    "311":  "Encrypt the data in transit and at rest with vetted primitives",
    "319":  "Force TLS on every transport channel and reject downgrades",
    "521":  "Enforce a length and complexity policy and reject reused / breached passwords",
    "307":  "Apply rate limiting and lock-out thresholds on authentication endpoints",
    "770":  "Bound the request rate and the per-request resource budget on this endpoint",
    "400":  "Bound the request rate and the per-request resource budget on this endpoint",
    "434":  "Validate uploaded file type, size, and storage path; never execute uploaded content",
    "502":  "Use a strict allow-list deserialiser and never accept untrusted gadget chains",
    "532":  "Strip secrets and PII from every log sink and rotate any token that already leaked",
    "200":  "Restrict the response to the minimum fields needed and never echo secrets",
    "209":  "Replace developer error pages with a generic message in production responses",
    "942":  "Replace the wildcard CORS origin with an explicit allow-list",
    "1021": "Add a frame-ancestors directive to the Content Security Policy",
    "693":  "Add the missing protection mechanism for this surface (CSP / CSRF token / headers)",
    "1004": "Set `HttpOnly` on every session cookie",
    "614":  "Set `Secure` on every session cookie and enforce HTTPS-only delivery",
    "1275": "Set `SameSite=Lax` or `Strict` on every session cookie",
    "1104": "Replace the unmaintained dependency with a maintained equivalent or fork it under ownership",
    "1395": "Replace the unmaintained dependency with a maintained equivalent or fork it under ownership",
    "937":  "Upgrade the dependency to a current, supported major version and pin via lockfile",
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
    r"(?<![`/\w])"                                       # not already in backticks or inside a path
    r"([A-Za-z_][A-Za-z0-9_./\\-]*\.(?:ts|tsx|js|jsx|mjs|cjs|py|rb|go|rs|java|kt|"
    r"yml|yaml|json|xml|toml|ini|env|sh|sql|html|css|scss|md|conf)"
    r"(?::\d+(?:-\d+)?)?)"                                # optional :line[-end]
    r"(?![`\w.])"
)
_CODE_CALL_RE = re.compile(
    r"(?<![`\w])"
    r"([A-Za-z_][A-Za-z0-9_]*"
    r"(?:\.[A-Za-z_][A-Za-z0-9_]*)+\(\))"                 # foo.bar() / a.b.c()
    r"(?![`\w])"
)
_CODE_BARE_CALL_RE = re.compile(
    r"(?<![`\w])"
    r"([A-Za-z_][A-Za-z0-9_]{2,}\(\))"                    # plain identifier()
    r"(?![`\w])"
)
_CODE_DOTTED_RE = re.compile(
    r"(?<![`\w/])"
    r"([a-z][a-zA-Z0-9_]*"
    r"(?:\.[a-z][a-zA-Z0-9_]*){1,3})"                     # req.body / sequelize.query
    r"(?![`\w(.])"
)


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
            parts.append(text[pos:m.start()])      # prose run
            parts.append("\x00")                   # marker
        parts.append(m.group(0))                   # passthrough span
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
        run = p
        run = _CODE_FILE_RE.sub(lambda mm: f"`{mm.group(1)}`", run)
        run = _CODE_CALL_RE.sub(lambda mm: f"`{mm.group(1)}`", run)
        run = _CODE_BARE_CALL_RE.sub(lambda mm: f"`{mm.group(1)}`", run)
        run = _CODE_DOTTED_RE.sub(lambda mm: f"`{mm.group(1)}`", run)
        out_parts.append(run)
    return "".join(out_parts)


def _build_finding_cell(
    t: dict,
    sev: str,
    taxonomy: dict[str, dict],
    components: dict,
    repo_root: Path | None,
    ctx: "RenderContext",
    fid_to_walkthrough: dict[str, tuple[str, str]] | None = None,
) -> str:
    """Build the Story Card for the §8 ``Finding`` cell.

    Layout (single MD line — `<br>` separators inside, `&#124;` for `|`).
    Reflects the user-adopted security-finding template (R-7, 2026-05):

        **<Title — canonical weakness class + file:line>**
        **Component:** [C-NN](#c-nn) — <Component Name>
        **Location:** `<file:line>` · evidence: verified
        **Issue:** <attack narrative — 1-2 sentences, plain prose>
        **Attack Walkthrough:** [Chain N — …](#chain-…)            (Critical/High only; omitted when §3 is skipped)
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
    if ec == "refuted":
        title_md = f"**~~{raw_title}~~** ⚠ *(evidence refuted)*"
    else:
        title_md = f"**{raw_title}**"

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
                    c.get("_original_id") == comp_id_raw
                    or (c.get("name") or "").strip() == comp_id_raw
                ):
                    canonical_id = cid_k
                    comp_meta = c
                    break
        comp_name = (comp_meta.get("name") or "").strip() if comp_meta else ""
        # Item 5 (2026-05-28): de-bold redundant labels — Component/Location/
        # Walkthrough/Evidence/Classification render with italic labels so
        # the visual emphasis goes to Issue/Impact/Fix (the actionable
        # signals). Component remains a labelled in-cell field for
        # structural parity with the user's reference template, but only
        # Issue/Impact/Fix carry full bold weight.
        if comp_name:
            component_line = f"_Component:_ [{canonical_id}](#{canonical_id.lower()}) — {comp_name}"
        else:
            component_line = f"_Component:_ [{canonical_id}](#{canonical_id.lower()})"

    # -- 2. Location labelled row -----------------------------------------
    # **Location:** stays as a labelled row (file:line).
    # **Evidence verdict** stays attached to **Location:** so the verified /
    # ambiguous / refuted status sits next to the file it applies to.
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

    ev_status_token = ""
    if ec in {"verified", "verified-prior"}:
        ev_status_token = "evidence: verified"
    elif ec == "ambiguous":
        ev_status_token = "evidence: ambiguous ◌"
    elif ec == "refuted":
        ev_status_token = "evidence: refuted ⚠"
    elif ec:
        ev_status_token = f"evidence: {ec}"

    location_line = ""
    if ev_file:
        loc_inner = f"`{ev_file}`" + (f":{ev_line}" if ev_line else "")
        if ev_status_token:
            loc_inner += f" · {ev_status_token}"
        location_line = f"_Location:_ {loc_inner}"
    elif ev_status_token:
        # No `evidence.file` on the threat but the evidence verdict is
        # still worth surfacing — emit the location line with an em-dash
        # placeholder so the evidence: badge always renders.
        location_line = f"_Location:_ — · {ev_status_token}"

    # R-7 (2026-05): Vektor field is no longer assembled into the cell —
    # see "Design choices (R-7)" in the docstring. The variable below is
    # kept assigned but unused so any downstream helper that still imports
    # `vektor_line` does not break. Set to empty string so the assembly
    # phase treats it as "skip silently".
    vektor_line = ""

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
                walkthrough_line = f"_Walkthrough:_ [{label}](#{anchor})"
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
    has_explicit_impact = bool(
        (t.get("impact_description") or t.get("impact_summary") or "").strip()
    )
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
    evidence_summary_explicit = (
        t.get("evidence_summary") or t.get("evidence_prose") or ""
    ).strip()
    evidence_line = ""
    if evidence_summary_explicit:
        text = evidence_summary_explicit
        if not text.endswith((".", "!", "?")):
            text += "."
        evidence_line = f"_Evidence:_ {text}"
    elif sev in ("critical", "high") and ev_file:
        # Synthesise a one-sentence claim from CWE class + file context.
        # The next-line snippet is the proof for this claim.
        fallback = _synthesise_evidence_summary(t, ev_file, ev_line)
        if fallback:
            if not fallback.endswith((".", "!", "?")):
                fallback += "."
            evidence_line = f"_Evidence:_ {fallback}"

    # Back-compat: keep ``Root cause`` when the yaml carried it
    # explicitly (legacy schema) but only when distinct from Issue.
    root_cause_explicit = (t.get("root_cause") or "").strip()
    root_cause_line = ""
    if root_cause_explicit and root_cause_explicit.lower() not in scenario.lower():
        root_cause_line = f"_Root cause:_ {root_cause_explicit}"

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

    # -- 6. Fix block — explicit action -----------------------------------
    cwe_raw = (t.get("cwe") or "").strip()
    cwe_norm = cwe_raw if cwe_raw.upper().startswith("CWE-") else (
        f"CWE-{cwe_raw}" if cwe_raw.isdigit() else cwe_raw
    )
    fix_line = ""
    mit_ids = t.get("mitigation_ids") or t.get("mitigations") or []
    mit_links = [ctx.linkify_with_label(mid) for mid in mit_ids[:2]]
    if mit_links:
        # Item 8 (2026-05-28): prepend a CWE-class-derived one-sentence
        # imperative action so the **Fix** field carries actionable
        # guidance before the M-NNN link.  Falls back to a neutral
        # "Apply the remediation" lead when the CWE is unknown or
        # outside the curated map.
        lead = _fix_action_lead(cwe_norm)
        if lead:
            lead = _codify_inline_identifiers(lead)
            fix_line = (
                "**Fix:** "
                + lead
                + ". See "
                + " · ".join(mit_links)
                + "."
            )
        else:
            fix_line = "**Fix:** Apply the remediation in " + " · ".join(mit_links) + "."

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
        classification_line = "_Classification:_ " + " · ".join(refs_parts)

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
    snippet_html = ""
    if snippet_relevant:
        snippet_text = _read_evidence_snippet(
            repo_root, ev_file, ev_line, depth["snippet_context"]
        )
        if snippet_text:
            lang = _lang_class_for_file(ev_file)
            cls = f' class="{lang}"' if lang else ""
            header = f"// {ev_file}:{ev_line}"
            escaped = _html_escape_for_pre(f"{header}\n{snippet_text}")
            # Markdown table cells must occupy one physical line. Encode raw
            # LFs as `&#10;`; browsers decode the entity inside <pre>.
            escaped = escaped.replace("\n", "&#10;")
            # Compact-by-default disclosure widget. PDF rendering defaults
            # the widget to expanded, so audit-copy completeness survives.
            # R-5 (2026-05): summary text now says "Evidence code · …" to
            # match the labelled-field cell layout — the bare "Evidence" was
            # ambiguous now that there is also an explicit **Evidence:** prose
            # line above the disclosure widget.
            snippet_html = (
                f"<details><summary><i>Evidence code · {ev_file}:{ev_line}</i></summary>"
                f"<pre><code{cls}>{escaped}</code></pre></details>"
            )

    # -- Assemble — labelled-form layout (R-7, 2026-05) -------------------
    # Order follows the user-adopted security-finding template:
    #   Title → Component → Location → Issue → Attack Walkthrough → Evidence
    #   → <details> code → (legacy) Root cause → Impact → Fix → Classification
    # Component is BOTH a column AND a labelled in-cell field (R-7).
    # Vektor is dropped from the cell (R-7) — still in YAML + Appendix A.
    # Empty fields are skipped silently.
    # Single ``<br>`` between every rendered field — table parsers (GFM,
    # Pandoc, weasyprint) all honour it.
    blocks: list[str] = [title_md]
    if component_line:
        blocks.append(component_line)
    if location_line:
        blocks.append(location_line)
    if vektor_line:
        # vektor_line is intentionally empty since R-7; guard kept for
        # back-compat in case a future revision re-enables it.
        blocks.append(vektor_line)
    if issue_line:
        blocks.append(issue_line)
    if walkthrough_line:
        blocks.append(walkthrough_line)
    if evidence_line:
        blocks.append(evidence_line)
    if snippet_html:
        blocks.append(snippet_html)
    if root_cause_line:
        blocks.append(root_cause_line)
    if impact_line:
        blocks.append(impact_line)
    if fix_line:
        blocks.append(fix_line)
    if classification_line:
        blocks.append(classification_line)
    cell = "<br>".join(blocks)

    # Final pipe-escape so Markdown table parsers don't break the row.
    cell = cell.replace("|", "&#124;")
    return cell


def _render_identified_actors(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """§1.5 Identified Actors — table of resolved ACT-* actors with layer, status,
    finding counts, and per-component relevance (actors.md §14). Conditional on
    `has_resolved_actors`; gracefully renders empty on legacy / pre-Phase-2.7 runs.
    """
    resolved_path = ctx.output_dir / ".actors-resolved.json"
    if not resolved_path.is_file():
        return ""
    try:
        resolved = json.loads(resolved_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""

    actors = resolved.get("resolved_actors", []) or []
    threats = ctx.yaml_data.get("threats") or []

    # Tabulate per-actor finding counts and components.
    counts: dict[str, int] = {}
    components: dict[str, set[str]] = {}
    for t in threats:
        comp = t.get("component", "")
        for aid in (t.get("actor_ids") or []):
            counts[aid] = counts.get(aid, 0) + 1
            if comp:
                components.setdefault(aid, set()).add(comp)

    # Load discovery output for inputs_questioned (optional).
    inputs_questioned: list[dict] = []
    discovery_path = ctx.output_dir / ".actors-discovered.json"
    if discovery_path.is_file():
        try:
            disc = json.loads(discovery_path.read_text(encoding="utf-8"))
            inputs_questioned = disc.get("inputs_questioned", []) or []
        except (OSError, json.JSONDecodeError):
            pass

    lines: list[str] = ['<a id="identified-actors"></a>', "## 1.5 Identified Actors", ""]

    # Quick-mode transparency notice (actors.md §12).
    if (ctx.output_dir / ".discovery-skipped.json").is_file():
        lines.append(
            "> _Note: This run used the static actor library only. "
            "Re-run with `--standard` or `--thorough` to enable LLM-based actor discovery "
            "for repo-specific actor identification._"
        )
        lines.append("")

    active = [a for a in actors if (a.get("_provenance") or {}).get("active")]
    if active:
        lines.append("| ID | Label | Layer | Status | Findings | Relevant for |")
        lines.append("|---|---|---|---|---|---|")
        for a in sorted(active, key=lambda x: x.get("id", "")):
            aid = a.get("id", "?")
            label = a.get("label", "")
            prov = a.get("_provenance") or {}
            layer = prov.get("layer", "?")
            proposed = bool(prov.get("proposed"))
            status = "proposed" if proposed else "active"
            if prov.get("stale"):
                status += " (stale)"
            display_layer = f"{layer} (proposed)" if proposed else layer
            comps = sorted(components.get(aid, set()))
            comps_str = ", ".join(comps) if comps else "_(no findings)_"
            lines.append(f"| `{aid}` | {label} | {display_layer} | {status} | {counts.get(aid, 0)} | {comps_str} |")
        lines.append("")
    else:
        lines.append("_No actors resolved for this run._")
        lines.append("")

    proposed_actors = [a for a in active if (a.get("_provenance") or {}).get("proposed")]
    if proposed_actors:
        lines.append("### Newly identified actors — please confirm")
        lines.append("")
        lines.append(
            "The following actors were proposed by LLM discovery (Phase 2.7) and are "
            "active in this run. Promote them to `.appsec/actors.yaml` to stabilize "
            "them across re-runs (actors.md §8)."
        )
        lines.append("")
        for a in proposed_actors:
            aid = a.get("id", "?")
            label = a.get("label", "")
            rationale = a.get("rationale") or a.get("description", "")
            suffix = f" — {rationale}" if rationale else ""
            lines.append(f"- **`{aid}` ({label})**{suffix}")
        lines.append("")

    if inputs_questioned:
        lines.append("### Actors flagged for review")
        lines.append("")
        lines.append(
            "Discovery flagged these actors as questionable — recon shows no plausible "
            "reach for them in this repo. Consider disabling in your next run."
        )
        lines.append("")
        for q in inputs_questioned:
            qid = q.get("id", "?")
            reason = q.get("reason", "")
            rec = q.get("recommendation", "")
            tail = f" _(recommendation: {rec})_" if rec else ""
            lines.append(f"- **`{qid}`** — {reason}{tail}")
        lines.append("")

    disabled = [a for a in actors if (a.get("_provenance") or {}).get("disabled_by")]
    if disabled:
        lines.append("### Disabled actors")
        lines.append("")
        lines.append("| ID | Label | Disabled by | Reason |")
        lines.append("|---|---|---|---|")
        for a in sorted(disabled, key=lambda x: x.get("id", "")):
            aid = a.get("id", "?")
            label = a.get("label", "")
            prov = a.get("_provenance") or {}
            by = prov.get("disabled_by", "")
            reason = prov.get("disable_reason") or "_(no reason given)_"
            lines.append(f"| `{aid}` | {label} | {by} | {reason} |")
        lines.append("")

    dormant_threats = [t for t in threats if t.get("_status") == "dormant"]
    if dormant_threats:
        lines.append("### Dormant findings")
        lines.append("")
        lines.append(
            "Findings preserved across re-runs whose structurally-required actor was "
            "disabled (actors.md §10 Stable-ID Garantie Fall 3). Re-enable the actor "
            "in your next run to surface them as live findings again."
        )
        lines.append("")
        for t in dormant_threats:
            tid = t.get("id", "?")
            title = t.get("title", "")
            ca = (t.get("_provenance") or {}).get("created_by_actor", "?")
            lines.append(f"- **{tid}** — {title} _(was tagged: `{ca}`)_")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _render_threat_register(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """Render §8 Threat Register in the canonical 8.A/B/C/D layout.

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
        if m and m.group(1).upper() in threat_ids and m.group(1).upper() != (
            (t.get("id") or t.get("t_id") or "").strip().upper()
        ):
            continue
        deduped.append(t)
    threats = deduped
    # Tracks whether any finding row carries the `(raw Critical)`
    # annotation — set inside the per-row loop. When True we emit a
    # one-line footnote at the end of §8 explaining the convention.
    has_raw_downgrade = False
    # M3: tracks whether any row carries an evidence_check marker
    # (refuted or ambiguous). Drives the §8 evidence-check footnote.
    has_evidence_drift = False
    # Load threat-category taxonomy once.
    tax_path = PLUGIN_ROOT / "data" / "threat-category-taxonomy.yaml"
    try:
        tax_raw = yaml.safe_load(tax_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        tax_raw = {}
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
        "All findings are listed in one table sorted by criticality, then "
        "by attack vektor (Repo-Read → Internet-Anon → Internet-User → "
        "Victim-Required). Columns: **ID** (T-NNN/F-NNN dual anchor) · "
        "**Finding** (the Story Card — see element list below) · "
        "**Component** (link to the §2.3 component entry) · **Criticality**."
    )
    lines.append("")
    lines.append(
        "Each **Finding** cell is a structured Story Card with these "
        "labelled fields, in order:"
    )
    lines.append("")
    skip_walk_intro = bool(ctx.eval_context.get("skip_attack_walkthroughs"))
    intro_bullets: list[str] = [
        "**Component** — owning component (link to [§2.3](#23-components) entry).",
        "**Location** — `` `file:line` `` · evidence verdict (`verified` / `ambiguous` / `refuted`).",
        "**Issue** — one-to-two-sentence attack narrative.",
    ]
    if not skip_walk_intro:
        intro_bullets.append(
            "**Attack Walkthrough** — back-link into [§3](#3-attack-walkthroughs) (Critical/High only)."
        )
    intro_bullets.extend([
        "**Evidence** — one-sentence prose summary above a collapsible `Code · file:line` widget (Critical/High; gated by CWE class).",
        "**Impact** — concrete consequence line (always rendered for Critical/High).",
        "**Fix** — link to the mitigation in [§9](#9-mitigation-register).",
        "**Classification** — `**Classification:** TH-NN · CWE · OWASP Top 10` reference row.",
    ])
    for idx, body in enumerate(intro_bullets, 1):
        lines.append(f"{idx}. {body}")
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
    lines.append(
        f"**Risk Distribution:** " + " · ".join(rd_parts) + f" · **Total findings: {total}**"
    )
    lines.append(
        f"**STRIDE Coverage:** Spoofing: {stride_map['spoofing']} · "
        f"Tampering: {stride_map['tampering']} · Repudiation: {stride_map['repudiation']} · "
        f"Information Disclosure: {stride_map['info_disclosure']} · "
        f"Denial of Service: {stride_map['dos']} · Elevation of Privilege: {stride_map['elev_priv']}"
    )
    lines.append("")

    # ---- Category anchors (invisible) ------------------------------------
    # Each TH-NN gets an `<a id="th-NN"></a>` anchor declared exactly once
    # at the top of §8 so that `[TH-NN — Title](#th-nn)` links inside the
    # Finding cell resolve. The pre-2026-05 layout also emitted a visible
    # "Categories at a glance:" catalogue line under these anchors — that
    # was removed (2026-05) per user request as it duplicated the
    # category links already inline in each Finding cell.
    active_cat_ids = sorted(cats_active.keys(), key=lambda c: (
        sev_rank.get(cat_eff_severity(c), 99), c
    ))
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

    # ---- Single flat table — 4 columns, Story-Card layout ----------------
    # Pre-2026-05 layout had 9 columns (ID | Finding | Threat Category |
    # Component | Criticality | CVSS | Vektor | Mitigation | References).
    # CVSS was unused (always "—"), Threat Category / Component /
    # Mitigation / References were each a single ID link consuming a full
    # column — the Story-Card folds them inline so the description gets
    # room to actually explain *why* each finding matters.
    #
    # R-6 (2026-05 user request): swap the Vektor column for a Component
    # column so the table groups visually by where the finding lives.
    # Vektor moves into the Finding cell as a labelled **Vektor:** field
    # (same anchor target, same label resolution — just rendered inline).
    # Item 6 (2026-05-28): Actor column dropped — upstream STRIDE
    # analyzers do not populate `actor_ids` / `primary_actor`, so the
    # column rendered as 100% em-dashes and added noise without signal.
    # The Story Card already carries actor attribution inside the Issue
    # narrative when the LLM has it; rendering an empty structural column
    # was a deferred deletion from the actors.md §14 contract. When the
    # STRIDE prompt + threat-merger start populating `actor_ids` reliably,
    # reinstate the column via the `_render_threat_register` history.
    lines.append("| ID | Finding | Component | Criticality |")
    lines.append("|----|---------|-----------|-------------|")

    # Vektor sort key — sort dirtier paths first within a severity tier so
    # the reader scans Repo-Read criticals before Victim-Required ones.
    vektor_order = {
        "repo-read": 0,
        "internet-anon": 1,
        "internet-user": 2,
        "victim-required": 3,
    }
    all_threats_sorted = sorted(
        threats,
        key=lambda t: (
            sev_rank.get((t.get("risk") or t.get("severity") or "").lower(), 99),
            vektor_order.get((t.get("vektor") or "").strip().lower(), 99),
            t.get("t_id") or t.get("id") or "",
        ),
    )
    for t in all_threats_sorted:
        tid = t.get("t_id") or t.get("id") or "-"
        sev = (t.get("risk") or t.get("severity") or "").lower()
        impact = (t.get("impact") or "").lower()

        # Criticality cell (column 4) — emoji + label + optional raw-cap note.
        sev_cell = f"{ctx.severity_emoji(sev)} {ctx.severity_label(sev)}".strip()
        if impact == "critical" and sev != "critical":
            sev_cell += " *(raw Critical)*"
            has_raw_downgrade = True

        # Track evidence-drift for the §8 footnote.
        ec = (t.get("evidence_check") or "").strip().lower()
        if ec in {"refuted", "ambiguous"}:
            has_evidence_drift = True

        # Component cell (column 3) — `C-NN — Name` link, replaces the old
        # Vektor column. The vektor itself now appears as a labelled field
        # inside the Finding cell (see `_build_finding_cell`).
        raw_cid_for_col = (t.get("component") or t.get("component_id") or "").strip()
        comp_for_col = components.get(raw_cid_for_col, {})
        if comp_for_col and re.match(r"^C-\d+$", raw_cid_for_col):
            comp_id_col = raw_cid_for_col
        elif comp_for_col:
            comp_id_col = comp_for_col.get("_canonical_id") or raw_cid_for_col
        else:
            comp_id_col = ""
            for cid_k, c in components.items():
                if re.match(r"^C-\d+$", cid_k) and (
                    c.get("_original_id") == raw_cid_for_col
                    or (c.get("name") or "").strip() == raw_cid_for_col
                ):
                    comp_id_col = cid_k
                    comp_for_col = c
                    break
        comp_name_col = (comp_for_col.get("name") if comp_for_col else raw_cid_for_col) or ""
        if comp_id_col and comp_name_col:
            comp_cell = f"[{comp_id_col} — {comp_name_col}](#{comp_id_col.lower()})"
        elif comp_id_col:
            comp_cell = f"[{comp_id_col}](#{comp_id_col.lower()})"
        elif comp_name_col:
            comp_cell = comp_name_col
        else:
            comp_cell = "—"

        # Finding cell (column 2) — rich Story Card.
        finding_cell = _build_finding_cell(
            t, sev, taxonomy, components, repo_root_path, ctx,
            fid_to_walkthrough=fid_to_walkthrough,
        )

        # Item 6 (2026-05-28): Actor cell construction removed — see the
        # header-column commentary above for the rationale (data-gap, not
        # a design decision). actors.md §10 markers (`_dormant_`,
        # `_[obsolete-actor]_`) live in YAML provenance and surface via
        # `_render_identified_actors` in §1.5 when present.

        # ID cell (column 1) — dual T+F anchor, F-NNN visible label.
        # See pre-2026-05 commentary preserved further down in this file:
        # F-NNN is the canonical user-visible finding ID in LLM-authored
        # fragments (Verdict bullets, Architecture Assessment, Asset Linked-
        # Threats); T-NNN is the YAML-internal id. Emitting both anchors keeps
        # `[F-001](#f-001)` and `[T-001](#t-001)` resolving to this row.
        fid_alias = ""
        visible_id = tid
        m = re.match(r"^T-(\d+)$", tid)
        if m:
            digits = m.group(1)
            fid_alias = f'<a id="f-{digits}"></a>'
            visible_id = f"F-{digits}"
        lines.append(
            f'| <a id="{tid.lower()}"></a>{fid_alias}{visible_id} | '
            f"{finding_cell} | {comp_cell} | {sev_cell} |"
        )
    lines.append("")

    # ---- §8 footnote: raw-severity convention ----------------------------
    if has_raw_downgrade:
        lines.append("---")
        lines.append("")
        lines.append(
            "_**Severity annotation:** rows tagged `*(raw Critical)*` had a "
            "Critical-class impact that was capped to a lower effective severity "
            "by the triage stage (likelihood downgrade or `data/severity-caps.yaml` "
            "rule). The rendered severity is the **effective** severity used for "
            "ranking and prioritisation; the raw severity is preserved here so "
            "reviewers can re-evaluate the cap decision._"
        )
        lines.append("")

    # ---- §8 footnote: evidence-check convention (M3) ---------------------
    if has_evidence_drift:
        lines.append("---")
        lines.append("")
        lines.append(
            "_**Evidence verification:** rows tagged `⚠ (evidence refuted)` "
            "were re-checked by the Phase 10a evidence-verifier (see "
            "`.evidence-verification.json`) and the cited `file:line` did "
            "**not** show the claimed weakness. Their raw severity is preserved, "
            "but chain-elevation has been suppressed by the triage stage. "
            "Rows tagged `◌ (evidence ambiguous)` could not be confirmed or "
            "refuted from the cited snippet alone — a human reviewer should "
            "decide whether to keep, downgrade, or remove these findings._"
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
    # File path with extension, optionally followed by :line:
    # `lib/insecurity.ts:23`, `frontend/src/app.module.ts`, `routes/login.js`.
    r"\b[A-Za-z_][A-Za-z0-9_./\-]*\.(?:ts|tsx|js|jsx|py|rb|go|rs|java|sh|json|yaml|yml|toml|md|html|css|scss)(?::\d+)?\b",
    # JS/TS expressions:
    #   `bcrypt.hash(password, 12)`, `crypto.createHash('md5')`,
    #   `process.env.JWT_PRIVATE_KEY`,
    #   `sanitizer.bypassSecurityTrustHtml(html)`, `models.sequelize.query()`,
    #   `DomSanitizer.sanitize(SecurityContext.HTML, html)`,
    #   `rateLimit({ windowMs: 15, max: 10 })` (function call without dot).
    r"\b(?:process\.env\.[A-Z_][A-Z0-9_]*"
    r"|(?:[a-zA-Z_][a-zA-Z0-9_]*\.)+[a-zA-Z_][a-zA-Z0-9_]*\([^()\n]{0,200}\)"
    r"|[a-zA-Z_][a-zA-Z0-9_]{2,}\((?:\{[^{}\n]{0,200}\}|[^()\n]{0,200})\))",
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
        "[§8 Threat Register](#8-threat-register) for the underlying weakness."
    )
    lines.append("")
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
        bucket.sort(key=lambda m: (m.get("m_id") or m.get("id") or ""))
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
            lines.append(f"#### {mid} — {title}")
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
                threats_idx_local = {
                    (t.get("t_id") or t.get("id") or "").upper(): t
                    for t in (ctx.yaml_data.get("threats") or [])
                }
                for ref in addressed:
                    ref_u = (ref or "").strip().upper()
                    t_obj = threats_idx_local.get(ref_u) or {}
                    sev_raw = (t_obj.get("risk") or t_obj.get("severity") or "").lower()
                    badge = _SEV_ICON_TBL.get(sev_raw, "")
                    label_text = ctx.linkify_with_label(ref)
                    if badge:
                        lines.append(f"- {badge} {label_text}")
                    else:
                        lines.append(f"- {label_text}")
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
                _t_idx = {
                    (t.get("t_id") or t.get("id") or "").upper(): t
                    for t in (ctx.yaml_data.get("threats") or [])
                }
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
                    (t.get("t_id") or t.get("id") or "").upper(): t
                    for t in (ctx.yaml_data.get("threats") or [])
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
                for step in steps:
                    s = (step or "").strip() if isinstance(step, str) else ""
                    if s:
                        # Inline-code-fence single-quotes that surround
                        # short identifiers so list items survive markdown
                        # renderers (some viewers eat unescaped backticks).
                        lines.append(f"- {_wrap_inline_code(s)}")
                lines.append("")
            if how_code:
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
                lines.append(
                    f"_Additional pattern for [{extra_cwe}](https://cwe.mitre.org/data/definitions/{cwe_num}.html):_"
                )
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
            ref = (m.get("reference") or mitigation_reference or "").strip()
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


def _render_by_id(ctx: RenderContext, env: jinja2.Environment, section_id: str, section: dict) -> str:
    dispatcher: dict[str, Any] = {
        "infobox": _render_infobox,
        "changelog": _render_changelog,
        "quick_mode_notice": _render_quick_mode_notice,
        "toc": _render_toc,
        "management_summary": _render_management_summary,
        # Item 3 (2026-05-28): wired the dormant Critical Attack Tree
        # renderer into the dispatcher. Section is gated on
        # `critical_count >= 2` via sections-contract.yaml conditional.
        "critical_attack_tree": _render_critical_attack_tree,
        "verdict": _render_verdict,
        "identified_actors": _render_identified_actors,
        "security_posture_at_a_glance": _render_security_posture_at_a_glance,
        "skipped_sections_placeholder": _render_skipped_sections_placeholder,
        "top_findings": _render_top_findings,
        "architecture_assessment": _render_architecture_assessment,
        "mitigations": _render_mitigations,
        "operational_strengths": _render_operational_strengths,
        "threat_register": _render_threat_register,
        "mitigation_register": _render_mitigation_register,
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
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    if not isinstance(contract, dict) or "sections" not in contract:
        raise ContractError("contract file is missing required 'sections' block")

    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        raise FragmentError("root", f"{yaml_path} not found — run Phase 11 YAML step first")
    yaml_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
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
    # (Top Findings, Threat Register, Mitigation Register) can count on them.
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

    # Load threat-category taxonomy once so lookups are O(1).
    cat_tax_path = PLUGIN_ROOT / "data" / "threat-category-taxonomy.yaml"
    category_taxonomy: dict[str, dict[str, Any]] = {}
    try:
        if cat_tax_path.is_file():
            tax_raw = yaml.safe_load(cat_tax_path.read_text(encoding="utf-8")) or {}
            category_taxonomy = {
                c.get("id", ""): c for c in (tax_raw.get("categories") or []) if isinstance(c, dict) and c.get("id")
            }
    except (OSError, yaml.YAMLError):
        pass

    ctx = RenderContext(
        output_dir=output_dir,
        contract=contract,
        yaml_data=yaml_data,
        triage=triage,
        fragments_dir=fragments_dir,
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
            # §1.5 Identified Actors gate (actors.md §14). True iff Phase 2.7
            # produced .actors-resolved.json — legacy runs and pre-Phase-2.7
            # caches gracefully skip the section instead of failing the contract.
            "has_resolved_actors": (output_dir / ".actors-resolved.json").is_file(),
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
                ((yaml_data.get("meta") or {}).get("assessment_depth") or "")
                .strip()
                .lower()
                == "quick"
            ),
            # Quick-depth skip flags. Plumbed in so the
            # `required_patterns_condition` on §3 / §9 entries
            # ("not skip_attack_walkthroughs", etc.) can be evaluated by
            # `eval_condition`. Sourced from .skill-config.json with a
            # depth-based default so legacy configs without the explicit
            # flag still behave correctly.
            "skip_attack_walkthroughs": (
                bool(_read_skill_config(output_dir).get("skip_attack_walkthroughs"))
                or (
                    ((yaml_data.get("meta") or {}).get("assessment_depth") or "")
                    .strip()
                    .lower()
                    == "quick"
                )
            ),
            "skip_attack_paths_authoring": bool(
                _read_skill_config(output_dir).get("skip_attack_paths_authoring")
            ),
            "skip_qa": bool(_read_skill_config(output_dir).get("skip_qa")),
            # 13-section schema_v2 — DEFAULT since 2026-05.
            # Resolution order (matches resolve_config.py + qa_checks):
            #   1. APPSEC_SECURITY_SCHEMA env-var ("v1" or "v2")
            #   2. APPSEC_SCHEMA_V1=1 env-var (legacy opt-out)
            #   3. .skill-config.json → security_schema
            #   4. default v2
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

    # Render each section in contract order.
    rendered_parts: list[str] = []

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
    for raw in section_order:
        sid, cond = (raw, None) if isinstance(raw, str) else (raw["id"], raw.get("condition"))
        if cond and not eval_condition(cond, ctx.eval_context):
            continue
        section = contract["sections"].get(sid)
        if not section:
            if document == "architecture":
                ctx.warnings.append(f"architecture section {sid!r} not in contract — skipped")
                continue
            raise ContractError(f"document.order references unknown section id: {sid!r}")
        progress_idx += 1
        if emit_progress:
            try:
                sys.stderr.write(f"COMPOSE: [{progress_idx}/{total_sections}] rendering §{sid}\n")
                sys.stderr.flush()
            except OSError:
                pass
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
        if body.strip():
            rendered_parts.append(body.rstrip())

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
            f"wrapped with \"...\" to prevent parser ambiguity"
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

    # Section cross-reference linkifier — convert bare `§N` / `§N.M` /
    # `§N.M.K` tokens in prose into anchor-linked form so cross-references
    # to other sections are clickable. The linkifier scans the rendered
    # document for `##` / `###` / `####` headings, builds a number → slug
    # map, and rewrites `§N(.M(.K)?)?` in non-heading prose.
    rendered = _linkify_section_refs(rendered)

    # Wrap unescaped `<script>` / `<img onerror=…>` attacker-payload tags
    # in inline backticks so the rendered HTML/PDF report does not interpret
    # them as live HTML elements (the report would otherwise become its own
    # XSS sink — see _escape_html_payloads_in_prose for the full rationale).
    # MUST run at the global pipeline (not per-section) because the §8
    # Threat Register cells with attacker payloads live inside a computed
    # section that bypasses _render_markdown_fragment.
    rendered = _escape_html_payloads_in_prose(rendered)

    # Final em-dash normalization — convert " — " (U+2014 surrounded by
    # spaces) to " - " (ASCII hyphen) outside fenced code blocks. Em dashes
    # are the single most visible "this was AI-written" signal in the
    # rendered document; replacing them everywhere prose flows keeps tables,
    # link labels, callouts, and LLM-authored paragraphs in a consistent
    # style. Code fences are skipped so any em-dash that lives inside a
    # source snippet (rare, but possible for prose comments inside code)
    # is preserved verbatim.
    rendered = _normalize_emdashes(rendered)

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
    §8 Threat Register so the same threat always lands under the same
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
    cid = t.get("threat_category_id") or t.get("category_id") or t.get("_category")
    if cid and cid in taxonomy:
        return cid
    # CWE → TH deterministic lookup. Runs before keyword heuristics so a
    # well-classified finding (e.g. CWE-321 = hardcoded crypto key) lands in
    # TH-03 Cryptographic Failures even when its title contains words that
    # would otherwise match an earlier keyword bucket ("authentication",
    # "JWT key", etc.).
    cwe_norm = _normalize_cwe(t.get("cwe") or t.get("cwe_id"))
    if cwe_norm:
        cwe_map = _build_cwe_to_th_map()
        mapped = cwe_map.get(cwe_norm)
        if mapped and (not taxonomy or mapped in taxonomy):
            return mapped
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


def _render_title(ctx: RenderContext, *, title_template_override: str | None = None) -> str:
    """Render the document `# Threat Model — <Project Name>` header.

    Shares the project-name derivation with `_render_infobox` via
    `_derive_project_name()` so the title and the infobox never disagree.

    Emits a one-line italic subtitle directly under the H1 naming the
    plugin version that produced the report (e.g. `_Generated by
    appsec-advisor v0.4.0-beta (analysis v2)_`). The same value also
    appears in the §Appendix Run Statistics row, but readers shouldn't
    have to scroll to the bottom to learn which tool version emitted
    the artefact. Falls back to title-only when plugin.json is
    unreadable.
    """
    title_tpl = title_template_override or ctx.contract["document"].get("title_template", "Threat Model")
    project = ctx.yaml_data.get("project")
    if not isinstance(project, dict):
        project = {}
    project.setdefault("name", _derive_project_name(ctx))
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

    if plugin_v:
        suffix = f" (analysis v{analysis_v})" if analysis_v else ""
        subtitle = f"_Generated by appsec-advisor v{plugin_v}{suffix}_\n"
        return f"# {title}\n\n{subtitle}"
    return f"# {title}\n"


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


def _categorize_warning(warning_text: str) -> dict[str, str]:
    """Map a free-form warning string into a structured {section, category,
    detail} dict. Heuristic — used by _write_compose_stats(). Renderer-side
    code should not depend on the exact category strings; they are for human
    consumption in the §Composition Notes appendix and the Health block.
    """
    text = warning_text.strip()
    lower = text.lower()
    if "orphan" in lower and ("t-nnn" in lower or "t-" in lower):
        return {"section": "§8 Threat Register", "category": "orphan_link", "detail": text}
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
    try:
        rendered, warnings = render(
            args.contract,
            args.output_dir,
            fragments_subdir=args.fragments_subdir,
            strict=not args.lenient,
            document=args.document,
            emit_progress=not args.dry_run,  # CLI callers see live section progress
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
    _t_link_pat = re.compile(r"\[T-(\d+)\]\(#t-\d+\)")
    referenced_t = sorted(set(_t_link_pat.findall(rendered)))
    unresolved: list[str] = []
    if referenced_t:
        # Re-load yaml at this scope (ctx is internal to render()).
        try:
            with (args.output_dir / "threat-model.yaml").open(encoding="utf-8") as fh:
                _yaml_for_bridge = yaml.safe_load(fh) or {}
        except (FileNotFoundError, yaml.YAMLError, OSError):
            _yaml_for_bridge = {}
        threats_ordered = _yaml_for_bridge.get("threats") or []
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
        try:
            with (args.output_dir / "threat-model.yaml").open(encoding="utf-8") as fh:
                _yaml_for_f_bridge = yaml.safe_load(fh) or {}
        except (FileNotFoundError, yaml.YAMLError, OSError):
            _yaml_for_f_bridge = {}
        threats_for_f = _yaml_for_f_bridge.get("threats") or []
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
    # The §8 Threat Register row emits the dual anchor `<a id="t-NNN"></a><a id="f-NNN"></a>`
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
            for issue in (mer_report.issues or []):
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
