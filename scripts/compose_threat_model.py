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
       for (verdict, architecture-assessment, critical-attack-chain, prose
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
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jinja2
import yaml

from _atomic_io import atomic_write_text

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
    "verdict":                 [".fragments/ms-verdict.json"],
    "architecture_assessment": [".fragments/ms-architecture-assessment.json"],
    "operational_strengths":   [".fragments/operational-strengths-overrides.json"],
    "system_overview":         [".fragments/system-overview.md"],
    "architecture_diagrams":   [".fragments/architecture-diagrams.md"],
    "attack_walkthroughs":     [".fragments/attack-walkthroughs.md"],
    "assets":                  [".fragments/assets.md"],
    "attack_surface":          [".fragments/attack-surface.md"],
    "use_cases":               [".fragments/use-cases.md"],
    "security_architecture":   [".fragments/security-architecture.md"],
    "requirements_compliance": [".fragments/requirements-compliance.md"],
    "threat_register":         [".fragments/compound-chains.json",
                                ".fragments/architectural-findings.json"],
    "out_of_scope":            [".fragments/out-of-scope.md"],
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

    def lookup_label(self, ref: str) -> str:
        """Resolve a short business-language label for an ID.

        Supports F-NNN / T-NNN (findings + threats), M-NNN (mitigations),
        C-NN (components), TH-NN (threat categories from taxonomy).

        For threats, prefers `title`, falls back to `scenario_short`, then
        synthesises from the first sentence of `scenario` / `description`
        (capped at 80 chars). This matches the Top Findings column logic so
        every cross-reference emits a consistent label regardless of yaml
        schema vintage.
        """
        if not ref:
            return ""
        r = ref.strip().upper()
        data = getattr(self, "yaml_data", {}) or {}
        # Find in threats[].
        for t in data.get("threats", []) or []:
            if (t.get("t_id") or t.get("id") or "").upper() == r:
                label = (t.get("title") or t.get("scenario_short") or "").strip()
                if label:
                    return label
                # Fallback synthesis — only reached when the STRIDE analyzer
                # omitted the `title` field. The synthesis MUST produce a
                # string that is safe inside table cells and prose (no
                # unclosed backticks, no mid-word truncation, no markdown
                # link artefacts, no `ClassName.java:NN` splits).
                sc = (t.get("scenario") or t.get("description") or "").strip()
                if sc:
                    return _synthesise_label(sc)
                return ""
        # Find in mitigations[].
        for m in data.get("mitigations", []) or []:
            if (m.get("m_id") or m.get("id") or "").upper() == r:
                return (m.get("title") or m.get("name") or "").strip()
        # Find in components[] — also try the synthesised canonical id.
        for c in data.get("components", []) or []:
            if (c.get("id") or "").upper() == r:
                return (c.get("name") or "").strip()
            if (c.get("_canonical_id") or "").upper() == r:
                return (c.get("name") or "").strip()
        # Find in threat-category-taxonomy (TH-NN).
        tax = getattr(self, "category_taxonomy", {}) or {}
        if r in tax:
            return (tax[r].get("title") or "").strip()
        return ""

    @staticmethod
    def _synthesise_label_noop() -> None:
        """Placeholder — kept so downstream imports do not break if they
        referenced the old split-on-dot behaviour. The real logic lives in
        the module-level helper ``_synthesise_label`` below."""

    def linkify_with_label(self, ref: str, label_override: str | None = None) -> str:
        """Emit `[ID](#id-lower) — label`. If label is empty or unknown,
        emit just `[ID](#id-lower)` (never a bare unlinked ID)."""
        if not ref:
            return ""
        r = ref.strip()
        if not r:
            return ""
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

_COND_ALLOWED_NAMES = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_COND_SAFE_TOKENS = re.compile(r"^[\sA-Za-z0-9_\.\(\)\[\]'\",<>=!&|+\-]*$")


def eval_condition(expr: str, env: dict[str, Any]) -> bool:
    """Evaluate a contract condition expression against ``env``.

    Allowed: name lookups, numeric/string literals, comparison operators,
    ``and`` / ``or`` / ``not``, membership (``in`` / ``not in``), basic
    arithmetic. Everything else (attribute access, calls, subscripts of
    arbitrary objects) is blocked.
    """
    if not expr or not isinstance(expr, str):
        return bool(expr)
    if not _COND_SAFE_TOKENS.match(expr):
        raise ContractError(f"unsafe condition expression: {expr!r}")
    # Build a locals dict restricted to names present in env.
    names = set(_COND_ALLOWED_NAMES.findall(expr)) - {
        "and", "or", "not", "in", "True", "False", "None",
    }
    locals_: dict[str, Any] = {n: env.get(n) for n in names}
    try:
        return bool(eval(expr, {"__builtins__": {}}, locals_))  # noqa: S307
    except Exception as e:  # pragma: no cover — narrow path
        raise ContractError(f"condition evaluation failed for {expr!r}: {e}")


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
        """
        if not refs:
            return ""
        return ", ".join(f"[{r.strip()}](#{r.strip().lower()})" for r in refs)

    def format_id_list(refs: list[str]) -> str:
        """Convert a list of IDs (T-NNN, M-NNN, F-NNN) to `<br/>`-stacked
        labelled links — used in multi-ref table cells so each entry is on its
        own line instead of comma-joined.  Single-item lists skip the `<br/>`.
        """
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
            line = f"[{mid}](#{mid.lower()})"
            if action:
                line += f" — {action}"
            if priority:
                line += f" ({priority})"
            rendered.append(line)
        return "<br/>".join(rendered)

    def format_defect_findings(items: list[dict[str, Any]]) -> str:
        if not items:
            return "—"
        rendered = []
        for it in items:
            ref = it["ref"]
            label = it.get("label", "").strip()
            line = f"[{ref}](#{ref.lower()})"
            if label:
                line += f" — {label}"
            rendered.append(line)
        return "<br/>".join(rendered)

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
                parts.append(f"[{cid}](#{cid.lower()}) {name}")
            elif name:
                parts.append(name)
            elif cid:
                parts.append(f"[{cid}](#{cid.lower()})")
        return "<br/>".join(parts)

    def format_mitigation_addresses(items: list[dict[str, Any]]) -> str:
        if not items:
            return "—"
        parts = []
        for it in items:
            ref = it.get("ref") or it.get("id", "")
            label = it.get("label", "").strip()
            line = f"[{ref}](#{ref.lower()})"
            if label:
                line += f" — {label}"
            parts.append(line)
        return "<br/>".join(parts)

    def format_strengths_mitigates(items: list[dict[str, Any]] | list[str]) -> str:
        if not items:
            # An empty Mitigates cell is legitimate for broad-defence controls,
            # but a bare `—` is confusing. Call it out explicitly so reviewers
            # see that the blank is intentional.
            return "_Broad defence-in-depth; no single finding directly addressed._"
        parts = []
        for it in items:
            if isinstance(it, dict):
                ref = it.get("ref") or it.get("id", "")
                label = it.get("label", "").strip()
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
    env.filters["format_defect_findings"] = format_defect_findings
    env.filters["format_component_list"] = format_component_list
    env.filters["format_mitigation_addresses"] = format_mitigation_addresses
    env.filters["format_strengths_mitigates"] = format_strengths_mitigates
    env.filters["bullet_list"] = bullet_list

    return env


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
        ref   = (it.get("ref") or it.get("id") or "").strip()
        href  = (it.get("href") or "").strip()
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
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
        (sev or "").strip().lower(), 99
    )


def _effort_rank(effort: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get(
        (effort or "").strip().lower(), 99
    )


def _effectiveness_rank(eff: str) -> int:
    return {"adequate": 0, "partial": 1, "weak": 2, "missing": 3}.get(
        (eff or "").strip().lower(), 99
    )


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
        # Anything else (None, int) is silently dropped
    return out


def _severity_counts(ctx: RenderContext) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for t in ctx.yaml_data.get("threats", []):
        sev = (t.get("risk") or t.get("severity") or "").strip().lower()
        if sev in counts:
            counts[sev] += 1
    return counts


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
        raise FragmentError(
            section_id, f"required fragment not found: {path}"
        )
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
            return pkg["name"].replace("-", " ").replace("_", " ").title() \
                   if "/" not in pkg["name"] else pkg["name"]
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
    project.setdefault("name",        derive_name())
    project.setdefault("version",     pkg.get("version") or meta.get("project_version"))
    project.setdefault("description", pkg.get("description") or ctx.yaml_data.get("project_description"))
    project.setdefault("author",      _format_author(pkg.get("author")) or ctx.yaml_data.get("project_author"))
    # License: manifest first, then LICENSE file at repo root. Covers Gradle/Maven/Go
    # projects where the manifest typically does not carry a license string.
    project.setdefault("license",     pkg.get("license") or ctx.yaml_data.get("project_license") or _read_license_file(ctx))
    project.setdefault("repository",  remote_url or _extract_repo_url(pkg.get("repository")) or ctx.yaml_data.get("project_repository"))
    # Homepage: manifest first, then derived from git remote (OSS convention).
    project.setdefault("homepage",    _derive_homepage(remote_url, pkg) or ctx.yaml_data.get("project_homepage"))
    project.setdefault("runtime",     ctx.yaml_data.get("project_runtime") or pkg.get("runtime") or _derive_runtime(pkg))
    # Tags: manifest keywords, explicit yaml tags, then README frontmatter / .github/topics.
    project.setdefault("tags",        pkg.get("keywords") or ctx.yaml_data.get("project_tags") or _read_readme_tags(ctx))

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


def _read_package_json(ctx: RenderContext) -> dict[str, Any]:
    """Read package.json from the repository root for infobox enrichment."""
    for candidate in _repo_root_candidates(ctx):
        p = candidate / "package.json"
        if p.is_file():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
    return {}


def _repo_root_candidates(ctx: RenderContext) -> list[Path]:
    """Possible repo roots. Usually `OUTPUT_DIR.parent.parent` (when output
    is at `<repo>/docs/security/`), but we try a few levels up to be
    defensive about non-standard layouts."""
    try:
        p = ctx.output_dir
    except Exception:
        return []
    return [
        p.parent.parent,           # <repo>/docs/security → <repo>
        p.parent,                  # <repo>/docs → might hold the manifest
        p,                         # output dir itself, unlikely but cheap
    ]


def _read_project_manifest(ctx: RenderContext) -> dict[str, Any]:
    """Polyglot project-metadata reader.

    Returns a dict with a normalised shape that mirrors package.json's:
      { name, version, description, author, license, repository,
        homepage, keywords, runtime }
    Missing fields are omitted (caller uses `.get()` with fallbacks).

    Tries manifests in order of fidelity: package.json (full native support)
    → pyproject.toml → Cargo.toml → go.mod → pom.xml → build.gradle.
    Falls back to README.md for a description when no manifest listed one.
    """
    # 1. Node — richest source, stays canonical.
    pkg = _read_package_json(ctx)
    if pkg:
        return pkg

    # 2. Python — pyproject.toml (PEP 621).
    data = _read_pyproject_toml(ctx)
    if data:
        data.setdefault("description", _read_readme_description(ctx))
        return data

    # 3. Rust — Cargo.toml.
    data = _read_cargo_toml(ctx)
    if data:
        data.setdefault("description", _read_readme_description(ctx))
        return data

    # 4. Go — go.mod (module path only; description comes from README).
    data = _read_go_mod(ctx)
    if data:
        data.setdefault("description", _read_readme_description(ctx))
        return data

    # 5. Java (Maven) — pom.xml.
    data = _read_pom_xml(ctx)
    if data:
        data.setdefault("description", _read_readme_description(ctx))
        return data

    # 6. Java/Kotlin (Gradle) — build.gradle / build.gradle.kts.
    data = _read_gradle(ctx)
    if data:
        data.setdefault("description", _read_readme_description(ctx))
        return data

    # Last resort — nothing but the README.
    desc = _read_readme_description(ctx)
    return {"description": desc} if desc else {}


def _read_pyproject_toml(ctx: RenderContext) -> dict[str, Any]:
    """PEP 621 [project] block."""
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return {}
    for root in _repo_root_candidates(ctx):
        p = root / "pyproject.toml"
        if not p.is_file():
            continue
        try:
            data = tomllib.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        proj = data.get("project") or {}
        if not proj:
            # poetry convention lives under tool.poetry
            proj = (data.get("tool") or {}).get("poetry") or {}
        if not proj:
            continue
        authors = proj.get("authors") or []
        author = None
        if authors:
            first = authors[0]
            if isinstance(first, str):
                author = first
            elif isinstance(first, dict):
                name = first.get("name") or ""
                email = first.get("email") or ""
                author = f"{name} ({email})" if email else name
        license_ = proj.get("license")
        if isinstance(license_, dict):
            license_ = license_.get("text") or license_.get("file")
        urls = proj.get("urls") or {}
        runtime_parts: list[str] = []
        reqs = proj.get("requires-python")
        if reqs:
            runtime_parts.append(f"Python {reqs}")
        deps = proj.get("dependencies") or []
        for d in deps[:5]:
            if isinstance(d, str):
                name = re.split(r"[<>=~! ]", d, 1)[0].strip()
                if name:
                    runtime_parts.append(name)
        return {
            "name": proj.get("name"),
            "version": proj.get("version"),
            "description": proj.get("description"),
            "author": author,
            "license": license_,
            "repository": urls.get("Repository") or urls.get("Source"),
            "homepage": urls.get("Homepage"),
            "keywords": proj.get("keywords"),
            "runtime": ", ".join(runtime_parts) or None,
        }
    return {}


def _read_cargo_toml(ctx: RenderContext) -> dict[str, Any]:
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return {}
    for root in _repo_root_candidates(ctx):
        p = root / "Cargo.toml"
        if not p.is_file():
            continue
        try:
            data = tomllib.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        pkg = data.get("package") or {}
        if not pkg:
            continue
        authors = pkg.get("authors") or []
        author = authors[0] if authors else None
        rust_ver = pkg.get("rust-version")
        runtime = f"Rust {rust_ver}" if rust_ver else "Rust (Cargo)"
        return {
            "name": pkg.get("name"),
            "version": pkg.get("version"),
            "description": pkg.get("description"),
            "author": author,
            "license": pkg.get("license"),
            "repository": pkg.get("repository"),
            "homepage": pkg.get("homepage"),
            "keywords": pkg.get("keywords"),
            "runtime": runtime,
        }
    return {}


def _read_go_mod(ctx: RenderContext) -> dict[str, Any]:
    for root in _repo_root_candidates(ctx):
        p = root / "go.mod"
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            continue
        module_match = re.search(r"^module\s+(\S+)", text, re.MULTILINE)
        go_match = re.search(r"^go\s+(\S+)", text, re.MULTILINE)
        if not module_match:
            continue
        name = module_match.group(1).strip()
        return {
            "name": name.rsplit("/", 1)[-1],
            "repository": name if name.startswith("github.com") else None,
            "runtime": f"Go {go_match.group(1)}" if go_match else "Go",
        }
    return {}


def _read_pom_xml(ctx: RenderContext) -> dict[str, Any]:
    """Maven pom.xml — best-effort regex extraction (xml.etree avoids having
    to pull in lxml, but namespace-aware parsing via ElementTree works)."""
    for root in _repo_root_candidates(ctx):
        p = root / "pom.xml"
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            continue
        # Namespace-agnostic: strip xmlns to keep ElementTree simple.
        text_ns = re.sub(r'\sxmlns="[^"]+"', "", text, count=1)
        try:
            import xml.etree.ElementTree as ET
            root_el = ET.fromstring(text_ns)
        except ET.ParseError:
            continue

        def find_text(path: str) -> str | None:
            el = root_el.find(path)
            return (el.text or "").strip() if el is not None and el.text else None

        name = find_text("name") or find_text("artifactId")
        version = find_text("version")
        description = find_text("description")
        url = find_text("url")
        licenses = root_el.findall("licenses/license/name")
        license_ = licenses[0].text if licenses and licenses[0].text else None
        developers = root_el.findall("developers/developer/name")
        author = developers[0].text if developers and developers[0].text else None
        scm_url = find_text("scm/url")
        # Java version from properties, plus key deps.
        java_ver = find_text("properties/java.version") or \
                   find_text("properties/maven.compiler.source")
        deps = []
        for dep in root_el.findall("dependencies/dependency/artifactId")[:5]:
            if dep.text:
                deps.append(dep.text)
        runtime_parts: list[str] = []
        if java_ver:
            runtime_parts.append(f"Java {java_ver}")
        runtime_parts.extend(deps)
        return {
            "name": name,
            "version": version,
            "description": description,
            "author": author,
            "license": license_,
            "repository": scm_url or url,
            "homepage": url,
            "runtime": ", ".join(runtime_parts) or None,
        }
    return {}


def _read_gradle(ctx: RenderContext) -> dict[str, Any]:
    """Gradle / Kotlin Gradle build — regex-based because a full Groovy/KTS
    parser is out of scope. Extracts what's commonly declarative.

    Returns a dict with the normalised shape expected by the infobox:
      {name, version, description, author, license, homepage, runtime, keywords}.
    License / homepage / keywords are filled from sibling files (LICENSE,
    git remote, README frontmatter) because Gradle itself rarely declares
    them.
    """
    for root in _repo_root_candidates(ctx):
        for filename in ("build.gradle", "build.gradle.kts"):
            p = root / filename
            if not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except OSError:
                continue
            # Also peek at settings.gradle for the root project name.
            settings_path = root / ("settings.gradle.kts"
                                    if filename.endswith(".kts") else "settings.gradle")
            settings_text = ""
            if settings_path.is_file():
                try:
                    settings_text = settings_path.read_text(encoding="utf-8")
                except OSError:
                    settings_text = ""

            def first(pattern: str, haystack: str, flags: int = re.MULTILINE) -> str | None:
                # MULTILINE by default: Gradle build files rarely have `group = …`
                # or `version = …` on line 1 — they sit at file scope, indented,
                # anywhere in the script. Without MULTILINE the `^\s*` anchor
                # silently never matched and Author/Version were dropped.
                m = re.search(pattern, haystack, flags)
                return m.group(1).strip() if m else None

            name = first(r'rootProject\.name\s*=\s*[\'"]([^\'"]+)[\'"]', settings_text) \
                   or first(r'archivesBaseName\s*=\s*[\'"]([^\'"]+)[\'"]', text)
            version = first(r'^\s*version\s*=\s*[\'"]([^\'"]+)[\'"]', text)
            group = first(r'^\s*group\s*=\s*[\'"]([^\'"]+)[\'"]', text)
            description = first(r'description\s*=\s*[\'"]([^\'"]+)[\'"]', text, flags=0)
            java_ver = first(r'sourceCompatibility\s*=\s*[\'"]?([\d.]+)', text, flags=0) \
                       or first(r'JavaVersion\.VERSION_([\d_]+)', text, flags=0)
            spring_boot = first(r"id\s*\(?\s*[\'\"]org\.springframework\.boot[\'\"]\s*\)?"
                                r"\s*version\s*[\'\"]([^\'\"]+)", text, flags=0)
            runtime_parts: list[str] = []
            if java_ver:
                runtime_parts.append(f"Java {java_ver.replace('_', '.')}")
            if spring_boot:
                runtime_parts.append(f"Spring Boot {spring_boot}")
            # Pick a handful of `implementation '…:…:…'` declarations as hints.
            impl_deps = re.findall(
                r"\b(?:implementation|compile|api)\s*\(?\s*[\'\"]"
                r"([^\'\"]+):[^\'\"]+:[^\'\"]+[\'\"]",
                text,
            )
            libs: list[str] = []
            for d in impl_deps[:6]:
                libs.append(d.split(":")[-1])
            runtime_parts.extend(libs[:3])
            return {
                "name": name,
                "version": version,
                "author": group,
                "description": description,
                "runtime": ", ".join(runtime_parts) or None,
            }
    return {}


def _read_readme_description(ctx: RenderContext) -> str | None:
    """Extract a one-line description from README.md — the first non-empty
    paragraph after the H1 title, capped at ~200 chars.

    Used as the last-resort description when a manifest doesn't carry one.
    """
    for root in _repo_root_candidates(ctx):
        for filename in ("README.md", "README.rst", "Readme.md", "readme.md"):
            p = root / filename
            if not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            # Drop front-matter if any.
            text = re.sub(r"^---\n.*?\n---\n", "", text, count=1, flags=re.DOTALL)
            lines = text.splitlines()
            # Find the first prose line that is not a heading, not a badge
            # image, not a HTML comment, not empty.
            start = 0
            for i, line in enumerate(lines):
                if re.match(r"^#\s+\S", line):
                    start = i + 1
                    break
            for line in lines[start:]:
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.startswith(("#", "<!", "!", "[!", "<img",
                                         "[![", "```", ">", "|")):
                    continue
                # Strip inline markdown link syntax to plain text.
                stripped = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", stripped)
                stripped = re.sub(r"\*\*?([^*]+)\*\*?", r"\1", stripped)
                stripped = re.sub(r"`([^`]+)`", r"\1", stripped)
                if len(stripped) > 250:
                    stripped = stripped[:247].rstrip() + "…"
                return stripped
    return None


def _format_author(author: Any) -> str | None:
    """package.json 'author' may be a string ('Name <email> (url)') or an object.
    Gradle/Maven pass plain strings (groupId), pyproject may pass a list/dict.
    """
    if not author:
        return None
    if isinstance(author, str):
        return author.strip() or None
    if isinstance(author, dict):
        name = author.get("name") or ""
        email = f" ({author['email']})" if author.get("email") else ""
        return (name + email) if name else None
    if isinstance(author, list) and author:
        return _format_author(author[0])
    return None


def _read_license_file(ctx: RenderContext) -> str | None:
    """Parse a LICENSE file at the repo root and infer the SPDX identifier.

    Returns a short label like 'MIT', 'Apache-2.0', 'GPL-3.0', 'BSD-3-Clause',
    or the first non-empty line of the file when no well-known SPDX pattern
    matches. Used as a fallback when the project manifest does not declare
    a license (common for Gradle, Maven, Go, and hand-rolled builds).
    """
    for root in _repo_root_candidates(ctx):
        for filename in ("LICENSE", "LICENSE.md", "LICENSE.txt",
                          "LICENCE", "LICENCE.md", "LICENCE.txt",
                          "COPYING", "COPYING.md"):
            p = root / filename
            if not p.is_file():
                continue
            try:
                head = p.read_text(encoding="utf-8", errors="ignore")[:2000]
            except OSError:
                continue
            # Well-known SPDX fingerprints — order matters (longest/most-specific
            # first so "GNU LGPL" doesn't collide with "GNU GPL").
            tests: list[tuple[str, str]] = [
                (r"\bApache License,?\s+Version\s+2\.0\b", "Apache-2.0"),
                (r"\bMozilla Public License\s+Version\s+2\.0\b", "MPL-2.0"),
                (r"\bGNU AFFERO GENERAL PUBLIC LICENSE\b", "AGPL-3.0"),
                (r"\bGNU LESSER GENERAL PUBLIC LICENSE\b", "LGPL-3.0"),
                (r"\bGNU GENERAL PUBLIC LICENSE[\s\S]{0,50}?Version\s+3", "GPL-3.0"),
                (r"\bGNU GENERAL PUBLIC LICENSE[\s\S]{0,50}?Version\s+2", "GPL-2.0"),
                (r"\bBSD 3-Clause\b|New BSD License", "BSD-3-Clause"),
                (r"\bBSD 2-Clause\b|Simplified BSD", "BSD-2-Clause"),
                (r"\bISC License\b", "ISC"),
                (r"\bThe Unlicense\b", "Unlicense"),
                (r'Permission is hereby granted, free of charge[\s\S]{0,200}'
                 r'THE SOFTWARE IS PROVIDED "AS IS"', "MIT"),
                (r"\bMIT License\b", "MIT"),
            ]
            for pat, spdx in tests:
                if re.search(pat, head, flags=re.IGNORECASE):
                    return spdx
            # Fallback — first non-blank line, truncated.
            for line in head.splitlines():
                line = line.strip()
                if line and not line.startswith(("#", "<!")):
                    return line[:80]
    return None


def _derive_homepage(remote_url: str | None, pkg: dict[str, Any]) -> str | None:
    """Infer a project homepage.

    Order of preference:
      1. Explicit pkg['homepage'] (package.json, pyproject urls.Homepage, etc.)
      2. git remote URL, normalised (strip .git) — the repo is usually a
         reasonable fallback homepage for OSS projects.
    """
    if pkg and pkg.get("homepage"):
        return pkg["homepage"]
    if not remote_url:
        return None
    url = remote_url.strip()
    url = re.sub(r"^git\+", "", url)
    url = re.sub(r"\.git/?$", "", url)
    # Normalise SSH form (git@github.com:org/repo) to https.
    m = re.match(r"^git@([^:]+):(.+)$", url)
    if m:
        url = f"https://{m.group(1)}/{m.group(2)}"
    return url or None


def _read_readme_tags(ctx: RenderContext) -> list[str] | None:
    """Read topics/tags from README frontmatter or `.github/topics` manifest.

    Sources (first match wins):
      1. README.md YAML frontmatter with `tags:` or `topics:` (list).
      2. `.github/topics` or `.github/repo-topics.yml` (newline- or yaml-list).
      3. Heuristic: capitalised stand-alone words inside the first README
         paragraph that look like tech keywords (Java, Spring, Docker, OWASP,
         …) — only used when the project is obviously OSS-adjacent and other
         sources were silent.
    """
    for root in _repo_root_candidates(ctx):
        # 1. YAML frontmatter in README.
        for filename in ("README.md", "Readme.md", "readme.md"):
            p = root / filename
            if not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            fm = re.match(r"^---\s*\n([\s\S]*?)\n---\s*\n", text)
            if fm:
                try:
                    import yaml as _yaml  # late import — not always present
                    data = _yaml.safe_load(fm.group(1)) or {}
                    for key in ("tags", "topics", "keywords"):
                        v = data.get(key)
                        if isinstance(v, list) and v:
                            return [str(x) for x in v][:8]
                        if isinstance(v, str) and v.strip():
                            return [s.strip() for s in re.split(r"[,\s]+", v) if s.strip()][:8]
                except Exception:
                    pass
            break  # only the first README
        # 2. .github/topics.
        for filename in (".github/topics", ".github/repo-topics.yml",
                          ".github/repo-topics.yaml"):
            p = root / filename
            if not p.is_file():
                continue
            try:
                raw = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            parts = [ln.strip().lstrip("- ") for ln in raw.splitlines() if ln.strip()]
            parts = [p for p in parts if p and not p.startswith("#")]
            if parts:
                return parts[:8]
    return None


def _extract_repo_url(repo: Any) -> str | None:
    """package.json 'repository' may be a string or {type, url}."""
    if not repo:
        return None
    if isinstance(repo, str):
        return repo
    if isinstance(repo, dict) and repo.get("url"):
        url = repo["url"]
        # Normalise `git+https://…/foo.git` → `https://…/foo`.
        url = re.sub(r"^git\+", "", url)
        url = re.sub(r"\.git/?$", "", url)
        return url
    return None


def _derive_runtime(pkg: dict[str, Any]) -> str | None:
    """Synthesise a Runtime line from package.json engines + key dependencies."""
    if not pkg:
        return None
    parts: list[str] = []
    engines = pkg.get("engines") or {}
    if engines.get("node"):
        parts.append(f"`Node.js` {engines['node']}")
    deps = pkg.get("dependencies") or {}
    for key, label in [("express", "Express"), ("angular", "Angular"),
                      ("@angular/core", "Angular"), ("react", "React"),
                      ("vue", "Vue"), ("next", "Next.js")]:
        if deps.get(key):
            v = deps[key].lstrip("^~>=<")
            parts.append(f"{label} {v.split('.')[0]}")
            break
    return ", ".join(parts) if parts else None


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
    return tpl.render(changelog=changelog).rstrip() + "\n"


def _compute_toc_entries(ctx: RenderContext) -> list[dict[str, Any]]:
    """Build TOC entries from the contract's document.order list.

    Each top-level numbered entry also carries `children` — the §N.M sub-section
    entries — computed from:
      * sections[sid].required_subsections  (contract)
      * sections[sid].sub_sections         (contract, for threat register)
      * live scan of the matching fragment markdown (for prose sections like
        attack_walkthroughs where §3.N depends on which Critical findings
        exist).
    """
    entries: list[dict[str, Any]] = []
    number = 1
    sections = ctx.contract["sections"]

    for raw in ctx.contract["document"]["order"]:
        sid, cond = (raw, None) if isinstance(raw, str) else (raw["id"], raw.get("condition"))
        if sid in ("infobox", "changelog", "toc"):
            continue
        if cond and not eval_condition(cond, ctx.eval_context):
            continue
        sec = sections.get(sid)
        if not sec:
            continue
        heading = sec.get("heading") or ""
        # Strip leading `N. ` / `N.N. ` numeric prefix from the TOC display
        # title — the presentation-order number supplied by the renderer is
        # already shown as "1.", "2.", … so a duplicate "2. 1. System Overview"
        # would be confusing.
        display_title = re.sub(r"^\s*\d+(?:\.\d+)?\.\s+", "",
                               heading.lstrip("#").strip())
        anchor = sec.get("anchor") or _anchor_from_heading(heading)
        children = _toc_children_for_section(ctx, sid, sec)
        entries.append({
            "number": number,
            "title": display_title,
            "anchor": anchor,
            "children": children,
        })
        number += 1
    return entries


def _toc_children_for_section(
    ctx: RenderContext, sid: str, sec: dict[str, Any]
) -> list[dict[str, str]]:
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
    for sub in sec.get("required_subsections", []) or []:
        if isinstance(sub, str):
            continue
        if not isinstance(sub, dict):
            continue
        title = sub.get("title")
        if not title:
            continue
        children.append({
            "title": title,
            "anchor": _anchor_from_heading(f"### {title}"),
        })

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
                        children.append({
                            "title": title,
                            "anchor": _anchor_from_heading(f"## {title}"),
                        })
            except OSError:
                pass

    return children


def _anchor_from_heading(heading: str) -> str:
    """Compute the GitHub-slug anchor for a Markdown heading.

    GitHub's slug rule (which MkDocs, VS Code preview, and GitLab mirror):
      * lower-case
      * reduce `[label](url)` link syntax to just `label` (the visible text)
      * drop punctuation (`,`, `.`, `—`, `–`, `(`, `)`, `[`, `]`, `'`, `"`, `&`, `/`, `:`, `#`)
      * replace spaces with `-`, collapse multiple hyphens

    So `## 1. System Overview` → `#1-system-overview`, NOT `#system-overview`.
    `### 3.2 Foo ([T-001](#t-001))` → `#32-foo-t-001`, NOT `#32-foo-[t-001]#t-001`.
    """
    h = heading.lstrip("#").strip().lower()
    # Reduce markdown links `[text](url)` to just `text` before stripping
    # punctuation — otherwise the URL's `#id` leaks into the slug as literal `#`.
    h = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", h)
    # Drop punctuation GitHub treats as zero-width. Added `[`, `]`, `#`, `*`
    # to cover markdown-link syntax, anchors, and bold/italic decorators
    # (e.g. `*(cross-cutting)*` in headings that wrap parenthetical phrases).
    for ch in "—–,.()[]'\"&/:#*":
        h = h.replace(ch, "")
    # Collapse whitespace to hyphens, then collapse duplicate hyphens.
    h = re.sub(r"\s+", "-", h).strip("-")
    h = re.sub(r"-+", "-", h).strip("-")
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
    "internet-anon":      "Internet Anon",
    "internet-user":      "Internet User",
    "internet-priv-user": "Internet Priv User",
    "victim-required":    "Victim-Required",
    "build-time":         "Build-Time",
    "repo-read":          "Repo-Read",
    "n-a":                "n/a",
    "n/a":                "n/a",
}

# Layer heuristic for contract v2. Tiers are CLIENT / APPLICATION / DATA
# (renamed from the v1 EDGE / SERVER / DATA). The classifier accepts
# both the new and legacy `layer` field values.
_LAYER_CLIENT_KEYWORDS = ("frontend", "spa", "ui", "angular", "react", "vue",
                          "svelte", "browser", "client", "edge", "cdn", "gateway")
_LAYER_DATA_KEYWORDS   = ("database", "store", "storage", "db", "sqlite",
                          "postgres", "mongo", "marsdb", "data-layer",
                          "persistent", "file-storage", "object", "cache", "redis")


def _classify_component_layer(comp: dict[str, Any]) -> str:
    """Return one of ``client`` / ``application`` / ``data``.

    Priority order:
      1. Explicit ``layer`` field on the component (handles both legacy
         "edge"/"server" and new "client"/"application").
      2. Keyword match on name / id / description.
      3. Fallback: ``application`` — the safest default for back-end services.
    """
    layer = (comp.get("layer") or "").strip().lower()
    if layer in ("client", "edge", "frontend", "ui", "browser"):
        return "client"
    if layer in ("data", "storage", "persistence", "datastore"):
        return "data"
    if layer in ("application", "server", "backend", "api", "service"):
        return "application"
    blob = " ".join((
        (comp.get("name") or ""),
        (comp.get("id") or ""),
        (comp.get("description") or ""),
    )).lower()
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


def _group_threats_by_component(
    threats: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    """Group findings by their `component_id` field. PRESERVED FROM v1."""
    by_comp: dict[str, list[dict[str, Any]]] = {}
    for t in threats:
        cid = (t.get("component_id") or "").strip()
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
    """
    cwe = (threat.get("cwe") or "").strip().upper()
    if not cwe:
        return None
    if not cwe.startswith("CWE-"):
        cwe = f"CWE-{cwe.lstrip('CWE-')}"
    for cls in taxonomy.get("classes") or []:
        if cwe in (cls.get("cwes") or []):
            return cls.get("id")
    return None


def _derive_attack_paths_fallback(
    threats: list[dict], taxonomy: dict
) -> dict:
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
        attack_paths.append({
            "class":   slug,
            "actor":   actor,
            "target":  cls.get("default_target_tier") or "application",
            "description": " ".join((cls.get("description") or "").split()),
            "architectural_root_causes": [],
            "findings": sorted(fids),
            "attack_chains": [],
            "impact":  list(cls.get("default_impacts") or []),
        })

    if not actors_present:
        actors_present.add("internet-anon")
    # Always keep victim-required first when present (matches
    # posture-actor-labels.yaml `order:` list).
    actor_order = (_load_posture_actor_labels().get("order") or [])
    actors_sorted = [a for a in actor_order if a in actors_present]

    return {
        "schema_version": 1,
        "actors":         actors_sorted,
        "attack_paths":   attack_paths,
    }


def _load_attack_paths_fragment(
    ctx: RenderContext, taxonomy: dict, threats: list[dict]
) -> dict:
    """Load the LLM-authored fragment if present and well-formed; else
    fall back to the deterministic CWE-derived fragment.

    The renderer never raises on a malformed fragment — falling back to
    deterministic data is preferable to a missing section.
    """
    frag_dir = getattr(ctx, "fragments_dir", None) or (ctx.output_dir / ".fragments")
    frag_path = frag_dir / "security-posture-attack-paths.json"
    if frag_path.is_file():
        try:
            data = json.loads(frag_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("attack_paths"), list):
                # Augment with default actors list when the fragment omits
                # it (the schema requires it, but we are defensive).
                data.setdefault("actors", [])
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return _derive_attack_paths_fallback(threats, taxonomy)


def _build_finding_to_path_map(attack_paths_data: dict) -> dict[str, tuple[str, str]]:
    """Map finding-id (upper-case) → (glyph, anchor-slug) using the
    *rendered* attack_paths order. Glyphs ① ② … are assigned positionally
    to non-empty entries — the same rule the heatmap diagram applies — so
    the Top Findings ``Pfad`` column always agrees with the bullets in
    Security Posture at a Glance.

    A finding may legitimately appear in multiple paths (e.g. F-002 SQLi
    classified under both ``injection`` and ``auth-bypass``). We keep the
    FIRST occurrence — matching the order in which the heatmap bullets are
    rendered (attack-class-taxonomy.yaml order).
    """
    glyphs = ["①", "②", "③", "④", "⑤", "⑥", "⑦"]
    out: dict[str, tuple[str, str]] = {}
    for idx, ap in enumerate(attack_paths_data.get("attack_paths") or []):
        if idx >= len(glyphs):
            break
        glyph = glyphs[idx]
        slug = ap.get("class") or ""
        anchor = f"path-{slug}" if slug else ""
        for fid in ap.get("findings") or []:
            out.setdefault((fid or "").upper(), (glyph, anchor))
    return out


# ---------------------------------------------------------------------------
# Diagram-data assembly — pure functions that return Jinja2-template input.
# ---------------------------------------------------------------------------

# Tier display names + canonical Mermaid node ids.
_TIER_DISPLAY: dict[str, tuple[str, str, str]] = {
    "client":      ("Client Tier",      "BROWSER", "tierClient"),
    "application": ("Application Tier", "SERVER",  "tierApp"),
    "data":        ("Data Tier",        "DATA",    "tierData"),
}


def _build_tier_cards(
    components: list[dict],
    threats_by_component: dict[str, list[dict]],
    tier_root_causes: dict,
    architectural_findings: list[dict],
) -> list[dict]:
    """For each non-empty tier (client / application / data), build the
    Jinja-input dict the diagram template expects.

    The card rendering is structured as four lines:

      1. Bold tier name (rendered via the template).
      2. Root-causes line: ``⚠ <causes joined by " · ">``.
      3. Components line: bold component-id list joined by " · ".
      4. Severity-counts line: ``🔴 N Critical · 🟠 N High · 🟡 N Medium
         · ⚠ N architectural``. Low-severity findings are intentionally
         omitted (per contract v2 ``tier_severity_floor: medium``).
    """
    by_layer: dict[str, list[dict]] = {"client": [], "application": [], "data": []}
    for c in components:
        by_layer[_classify_component_layer(c)].append(c)

    # Pre-compute architectural findings per tier from the AF records.
    # Each AF aggregates findings belonging to one tier (inferred from
    # the components those findings target).
    af_by_tier: dict[str, int] = {"client": 0, "application": 0, "data": 0}
    component_tier_index: dict[str, str] = {}
    for tier_key, comps in by_layer.items():
        for c in comps:
            cid = (c.get("id") or "").strip()
            if cid:
                component_tier_index[cid] = tier_key
    for af in architectural_findings or []:
        # Heuristic: pick the modal tier across the AF's aggregated
        # findings. We look up each finding's component → tier.
        tiers_seen: dict[str, int] = {"client": 0, "application": 0, "data": 0}
        for f_ref in af.get("aggregates_findings") or []:
            # f_ref is typically the F-NNN string; the component for it
            # is resolved through threats_by_component.
            for cid, tlist in threats_by_component.items():
                for t in tlist:
                    if (t.get("id") or t.get("t_id") or "").strip() == f_ref:
                        tk = component_tier_index.get(cid)
                        if tk:
                            tiers_seen[tk] += 1
                        break
        chosen = max(tiers_seen, key=lambda k: tiers_seen[k])
        if tiers_seen[chosen] > 0:
            af_by_tier[chosen] += 1

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
        af_count = af_by_tier.get(key, 0)
        if af_count:
            sev_parts.append(f"⚠ {af_count} architectural")
        sev_line = " · ".join(sev_parts) if sev_parts else "(no findings)"
        # Root-causes line.
        rcs = (tier_root_causes or {}).get(key) or []
        # Legacy yaml may use "edge"/"server" keys; map them onto the new
        # tier vocabulary.
        if not rcs and key == "client":
            rcs = (tier_root_causes or {}).get("edge") or []
        if not rcs and key == "application":
            rcs = (tier_root_causes or {}).get("server") or []
        rc_line = "⚠ " + " · ".join(rcs) if rcs else "⚠ (no root causes documented)"
        # Components line.
        if comp_ids:
            comp_line = "<b>" + "</b> · <b>".join(comp_ids) + "</b>"
        else:
            comp_line = "(no components)"
        display_name, node_id, css_class = _TIER_DISPLAY[key]
        cards.append({
            "key":                  key,
            "node_id":              node_id,
            "name":                 display_name,
            "root_causes_line":     rc_line,
            "components_line":      comp_line,
            "severity_counts_line": sev_line,
            "css_class":            css_class,
            "components":           comp_ids,
        })
    return cards


def _build_actor_cards(
    attack_paths_data: dict, actor_labels: dict
) -> list[dict]:
    """One card per actor present in attack_paths_data.actors, ordered by
    the ``order:`` list in posture-actor-labels.yaml.
    """
    actors_dict = (actor_labels.get("actors") or {})
    order: list[str] = actor_labels.get("order") or []
    present = set(attack_paths_data.get("actors") or [])
    # Always include any actor referenced by an attack-path entry, even
    # if the top-level `actors` array forgot it.
    for ap in attack_paths_data.get("attack_paths") or []:
        a = ap.get("actor")
        if a:
            present.add(a)
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
        cards.append({
            "id":             node_id,
            "slug":           slug,
            "label":          meta.get("label") or slug,
            "subtitle":       meta.get("default_subtitle") or "",
            "severity_class": meta.get("severity_class") or "actorAnon",
            "role":           meta.get("role") or "attacker",
        })
    return cards


def _build_impact_cards(
    attack_paths_data: dict, impact_taxonomy: dict
) -> list[dict]:
    """Pick impacts referenced by any attack-path entry; emit one card per
    impact, in the order defined by business-impact-taxonomy.yaml.
    """
    used: set[str] = set()
    for ap in attack_paths_data.get("attack_paths") or []:
        for imp in ap.get("impact") or []:
            used.add(imp)
    sev_emoji = {
        "critical": "🔴",
        "high":     "🟠",
        "medium":   "🟡",
        "low":      "🟢",
    }
    cards: list[dict] = []
    for imp in impact_taxonomy.get("impacts") or []:
        slug = imp.get("id")
        if slug not in used:
            continue
        sev = (imp.get("severity_default") or "critical").lower()
        emoji = sev_emoji.get(sev, "🔴")
        node_id = (slug or "").upper().replace("-", "_")
        cards.append({
            "node_id":   node_id,
            "id":        slug,
            "label":     f"{emoji} <b>{imp.get('label')}</b>",
            "css_class": "impact",
        })
    return cards


def _build_attack_arrows(
    attack_paths_data: dict,
    taxonomy: dict,
    actor_cards: list[dict],
    tier_cards: list[dict],
) -> list[dict]:
    """One arrow per attack-class entry. Glyphs assigned in declaration
    order from the taxonomy's ``glyph_sequence``.

    Source / destination semantics:
      * ``target == "victim"``: source = Client Tier card, dst = victim
        actor card. (XSS / CSRF — the rendered content originates in the
        client tier; the victim is hit by what the browser renders.)
      * else: source = the actor's card, dst = the named tier card.
    """
    glyph_seq = taxonomy.get("glyph_sequence") or ["①","②","③","④","⑤","⑥","⑦"]
    actor_node_by_slug = {a["slug"]: a["id"] for a in actor_cards}
    tier_node_by_key = {t["key"]: t["node_id"] for t in tier_cards}
    classes_by_id = {c["id"]: c for c in (taxonomy.get("classes") or [])}

    arrows: list[dict] = []
    for idx, ap in enumerate(attack_paths_data.get("attack_paths") or []):
        if idx >= len(glyph_seq):
            break
        cls = classes_by_id.get(ap.get("class") or "")
        if not cls:
            continue
        short = cls.get("short_label") or cls.get("label") or ap.get("class")
        target = ap.get("target") or "application"
        if target == "victim":
            src = tier_node_by_key.get("client") or "BROWSER"
            dst = actor_node_by_slug.get("victim-required") or "SHOPUSER"
        else:
            src = actor_node_by_slug.get(ap.get("actor") or "internet-anon") or "ANON"
            dst = tier_node_by_key.get(target) or "SERVER"
        arrows.append({
            "src":   src,
            "glyph": glyph_seq[idx],
            "label": short,
            "dst":   dst,
        })
    return arrows


def _build_consequence_arrows(
    attack_paths_data: dict,
    impact_cards: list[dict],
    tier_cards: list[dict],
) -> list[dict]:
    """Dashed arrow per (source-tier, impact) pair found in attack_paths,
    de-duplicated. Source tier is:

      * ``client`` for ``target == "victim"`` classes (XSS, CSRF).
      * ``ap.target`` otherwise.
    """
    impact_by_id = {i["id"]: i for i in impact_cards}
    tier_node_by_key = {t["key"]: t["node_id"] for t in tier_cards}

    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for ap in attack_paths_data.get("attack_paths") or []:
        target = ap.get("target") or "application"
        if target == "victim":
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


def _build_alignment_edges(
    actor_cards: list[dict], tier_cards: list[dict]
) -> list[dict]:
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
        edges.append({
            "src": actor_node_by_slug["victim-required"],
            "dst": tier_node_by_key["client"],
        })
    if "internet-anon" in actor_node_by_slug and "application" in tier_node_by_key:
        edges.append({
            "src": actor_node_by_slug["internet-anon"],
            "dst": tier_node_by_key["application"],
        })
    return edges


def _render_security_posture_at_a_glance(
    ctx: RenderContext, env: jinja2.Environment, section: dict
) -> str:
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
    components            = ctx.yaml_data.get("components") or []
    threats               = ctx.yaml_data.get("threats") or []
    tier_root_causes      = ctx.yaml_data.get("tier_root_causes") or {}
    architectural_findings = ctx.yaml_data.get("architectural_findings") or []

    critical_high = sum(
        1 for t in threats
        if (t.get("risk") or t.get("severity") or "").strip().lower()
        in ("critical", "high")
    )
    min_required = int(section.get("min_high_or_critical", 3))
    if critical_high < min_required:
        return ""

    # Load taxonomies + the LLM-authored fragment (or deterministic fallback).
    attack_taxonomy = _load_attack_class_taxonomy()
    impact_taxonomy = _load_business_impact_taxonomy()
    actor_labels    = _load_posture_actor_labels()
    attack_paths_data = _load_attack_paths_fragment(ctx, attack_taxonomy, threats)

    # Build the per-column input data.
    threats_by_component = _group_threats_by_component(threats)
    tier_cards   = _build_tier_cards(
        components, threats_by_component, tier_root_causes, architectural_findings
    )
    actor_cards  = _build_actor_cards(attack_paths_data, actor_labels)
    impact_cards = _build_impact_cards(attack_paths_data, impact_taxonomy)

    # Build the edge structure.
    attack_arrows        = _build_attack_arrows(
        attack_paths_data, attack_taxonomy, actor_cards, tier_cards
    )
    consequence_arrows   = _build_consequence_arrows(
        attack_paths_data, impact_cards, tier_cards
    )
    alignment_edges      = _build_alignment_edges(actor_cards, tier_cards)

    # Continuous link-style index ranges. Mermaid numbers edges in the
    # order they appear in the source; we emit alignment edges first,
    # then attack arrows, then consequence arrows.
    n_align = len(alignment_edges)
    n_atk   = len(attack_arrows)
    n_conq  = len(consequence_arrows)
    linkstyle_alignment    = list(range(0, n_align))
    linkstyle_attacks      = list(range(n_align, n_align + n_atk))
    linkstyle_consequences = list(range(n_align + n_atk,
                                          n_align + n_atk + n_conq))

    # Intro paragraph — one sentence + severity-emoji legend with an
    # explicit note that Low-severity findings are tracked in §8 but
    # omitted from the heatmap (per contract v2 tier_severity_floor).
    glyph_seq = attack_taxonomy.get("glyph_sequence") or ["①","②","③","④","⑤","⑥","⑦"]
    if n_atk > 0:
        glyph_range = f"①–{glyph_seq[min(n_atk, len(glyph_seq)) - 1]}"
    else:
        glyph_range = "①"
    intro_paragraph = (
        "One-glance heatmap: **threat actors** on the left, "
        "**architectural tiers** stacked in the middle (Client → Application → Data), "
        "**impact** on the right. Each tier shows its missing controls, components, "
        "and severity counts (🔴 Critical · 🟠 High · 🟡 Medium · ⚠ architectural — "
        "Low-severity findings are tracked in §8 but omitted here). Numbered red "
        f"arrows {glyph_range} are resolved in the *Attack paths* list below."
    )

    diagram_data = {
        "intro_paragraph": intro_paragraph,
        "subgraph_actors": {
            "header_label": "Threat Actors",
            "cards":        actor_cards,
        },
        "subgraph_tiers": {
            "header_label": "Architecture Tiers",
            "cards":        tier_cards,
        },
        "subgraph_impact": {
            "header_label": "Impact",
            "cards":        impact_cards,
        },
        "alignment_edges":        alignment_edges,
        "attack_arrows":          attack_arrows,
        "consequence_arrows":     consequence_arrows,
        "linkstyle_alignment":    linkstyle_alignment,
        "linkstyle_attacks":      linkstyle_attacks,
        "linkstyle_consequences": linkstyle_consequences,
    }

    diagram_md = env.get_template(
        "security-posture-diagram.md.j2"
    ).render(data=diagram_data)

    # ---- Attack-paths bullet list -------------------------------------------
    threat_by_id = {(t.get("id") or t.get("t_id") or "").strip(): t for t in threats}
    af_by_id = {(af.get("id") or "").strip(): af for af in (architectural_findings or [])}
    classes_by_id = {c["id"]: c for c in (attack_taxonomy.get("classes") or [])}
    impacts_by_id = {i["id"]: i for i in (impact_taxonomy.get("impacts") or [])}
    actor_card_by_slug = {a["slug"]: a for a in actor_cards}
    actors_dict = (actor_labels.get("actors") or {})

    target_label_map = {
        "client":      "Client Tier",
        "application": "Application Tier",
        "data":        "Data Tier",
        "victim":      "Shop User",
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
            actor_for_bullet = (
                actor_card_by_slug.get(actor_slug, {}).get("label")
                or meta.get("label") or actor_slug
            )
            target_for_bullet = target_label_map.get(target, target)

        # Architectural-root-cause sub-list: { id, title }.
        arc_list = []
        for af_id in ap.get("architectural_root_causes") or []:
            af = af_by_id.get(af_id) or {}
            arc_list.append({
                "id":    af_id,
                "title": (af.get("title") or "").strip(),
            })

        # Findings sub-list: { id, title }.
        finding_list = []
        for fid in ap.get("findings") or []:
            t = threat_by_id.get(fid) or {}
            title = (t.get("title") or t.get("scenario_short") or "").strip()
            finding_list.append({
                "id":    fid,
                "title": title.replace("|", "\\|"),
            })

        # Attack-chain sub-list: { id, id_label, title }.
        # `ch` is a canonical CC-NN slug (e.g. ``"cc-01"``) — same anchor
        # as §8.F Compound Attack Chains and §3.1 walkthroughs. We emit
        # the bullet as ``[CC-01](#cc-01)`` so cross-references resolve.
        chain_list = []
        for ch in ap.get("attack_chains") or []:
            id_label = ch.upper()           # cc-01 → CC-01
            chain_list.append({
                "id":       ch,
                "id_label": id_label,
                "title":    "",
            })

        # Impact line — comma-separated labels resolved through the taxonomy.
        impact_labels = []
        for slug in ap.get("impact") or []:
            imp = impacts_by_id.get(slug)
            if imp:
                impact_labels.append(imp.get("label") or slug)
        impact_string = ", ".join(impact_labels) if impact_labels else "—"

        attack_paths_rendered.append({
            "glyph":        glyph_seq[idx],
            "class_slug":   ap.get("class") or "",
            "class_label":  cls.get("label") or ap.get("class"),
            "actor_label":  actor_for_bullet,
            "target_label": target_for_bullet,
            "description":  (ap.get("description")
                             or " ".join((cls.get("description") or "").split())),
            "architectural_root_causes": arc_list,
            "findings":      finding_list,
            "attack_chains": chain_list,
            "impact_string": impact_string,
        })

    # Build one bullet per visible actor for the "Threat actors" intro.
    actor_bullets: list[dict] = []
    for ac in actor_cards:
        if ac["role"] == "victim":
            body = ("legitimate registered customer whose session and PII are "
                    "the actual target; receives the victim-targeting attack "
                    "arrows (XSS, CSRF) as victim, not attacker.")
        else:
            body = ("no account, no foothold; reaches every unauthenticated "
                    "route, registers a throw-away account in seconds when "
                    "needed, and can clone the public repository to obtain any "
                    "committed secret offline. Initiates the outgoing attack "
                    "arrows.")
        actor_bullets.append({"label": ac["label"], "body": body})

    paths_template_data = {
        "intro_paragraph": (
            "**Threat actors.** Two entities sit on the left of the diagram — "
            "one attacker who initiates every direct attack class, and one "
            "victim who is the target of the browser-side attacks (XSS / CSRF)."
        ),
        "actor_bullets":       actor_bullets,
        "attack_paths_header": "**Attack paths (numbered arrows in the diagram):**",
        "attack_paths":        attack_paths_rendered,
    }

    paths_md = env.get_template(
        "security-posture-attack-paths.md.j2"
    ).render(data=paths_template_data)

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

    attack_taxonomy   = _load_attack_class_taxonomy()
    attack_paths_data = _load_attack_paths_fragment(
        ctx, attack_taxonomy, list(threats.values())
    )
    fid_to_path = _build_finding_to_path_map(attack_paths_data)

    ranking = (
        (ctx.triage.get("ranking") or {})
        .get("views", {})
        .get("top_findings", {})
        .get("findings_ranked", [])
    )
    if ranking:
        qualifying_ids = [
            r.get("id") for r in ranking
            if r.get("effective_severity", "").lower() in ("critical", "high")
        ]
    else:
        qualifying_threats = sorted(
            [
                t for t in ctx.yaml_data.get("threats", [])
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
            canonical = comp.get("_canonical_id") or raw if re.match(r"^C-\d+$", raw) else comp.get("_canonical_id", raw)
            return canonical, (comp.get("name") or raw)
        for c_id, c in components.items():
            if re.match(r"^C-\d+$", c_id) and (c.get("name") or "").strip() == raw:
                return c_id, c.get("name") or c_id
        return "C-00", raw

    max_rows = (
        (ctx.contract["sections"].get("top_findings") or {}).get("table", {}).get("rows", {}).get("max", 20)
    )
    rendered: list[dict[str, Any]] = []
    for idx, tid in enumerate(qualifying_ids[:max_rows], start=1):
        t = threats.get(tid) or {}
        # Component cell: use the canonical C-NN anchor.
        c_anchor, c_name = resolve_component(t.get("component_id") or t.get("component"))
        # Pfad cell: glyph ①–⑦ + anchor into Security Posture bullet.
        path_glyph, path_anchor = fid_to_path.get((tid or "").upper(), ("", ""))
        # Mitigation cells: M-ID + action + priority token (P1/P2/…).
        mit_cells: list[dict[str, str]] = []
        for mid in (t.get("mitigations") or [])[:2]:
            m = mitigations.get(mid, {})
            mit_cells.append({
                "id": mid,
                "action": (m.get("title") or "").strip(),
                "priority": (m.get("priority") or "").strip(),
            })
        # Finding title — never fallback to the ID itself.
        title = (t.get("title") or t.get("scenario_short") or "").strip()
        if not title:
            sc = (t.get("scenario") or "").strip()
            title = (sc.split(".")[0] if sc else tid)[:80]

        rendered.append({
            "rank": idx,
            "criticality": (t.get("risk") or t.get("severity") or "").lower(),
            "path_glyph":   path_glyph,
            "path_anchor":  path_anchor,
            "finding_id":   tid,
            "finding_title": title,
            "component_id": c_anchor,
            "component_name": c_name,
            "mitigations":  mit_cells,
        })
    return rendered, len(qualifying_ids)


def _render_architecture_assessment(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    data = _load_fragment(ctx, "architecture_assessment", section["fragment"])
    _validate_fragment("architecture_assessment", data, section["schema"])
    tpl = env.get_template(section["template"])
    return tpl.render(data=data).rstrip() + "\n"


def _render_mitigations(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    """Render the Mitigations section as **per-component tables** with a
    Priority column.

    Layout strategy (chosen by component count):
      * **≤ 5 components** → one table per component.
      * **6 – 10 components** → one table per architectural tier
        (Client / Application / Data) — each tier table aggregates the
        component-bucket mitigations belonging to that tier.
      * **> 10 components** → one flat "All Mitigations" table sorted by
        (component, priority, effort).

    Always emit a separate **Cross-Component Mitigations** table BEFORE
    the per-component tables for any mitigation whose `components` list
    has ≥ 2 entries — those don't have a single owning component, and
    duplicating them across N tables produces noisy redundancy.

    Sort within each table: ``(priority asc, effort asc, addressed_count
    desc, id asc)``.

    Each row exposes a Priority column (P1–P4). When the yaml carries an
    explicit ``mitigation.priority``, that wins; otherwise we derive it
    from the worst-severity finding the mitigation addresses (Critical →
    P1, High → P2, Medium → P3, Low → P4).
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
            addressed.append({
                "ref": tid,
                "label": (t.get("title") or t.get("scenario_short") or "").strip(),
            })
        comp_ids = m.get("components") or []
        if not comp_ids:
            seen: set[str] = set()
            for tid in addressed_ids:
                c = (threats.get(tid) or {}).get("component_id")
                if c and c not in seen:
                    comp_ids.append(c)
                    seen.add(c)
        component_list = [
            {"id": cid, "name": (components.get(cid) or {}).get("name", cid)}
            for cid in comp_ids
        ]
        priority = (m.get("priority") or "").strip().upper()
        if priority not in ("P1", "P2", "P3", "P4"):
            priority = _derive_priority(max_sev)
        return {
            "id":              mid,
            "title":           m.get("title", ""),
            "component_list":  component_list,
            "primary_component_id": comp_ids[0] if comp_ids else "",
            "addresses":       addressed,
            "effort":          m.get("effort", "Medium"),
            "priority":        priority,
            "max_sev_rank":    max_sev,
            "addressed_count": len(addressed),
        }

    enriched = [enrich(m) for m in mitigations]

    def _priority_rank(p: str) -> int:
        return {"P1": 0, "P2": 1, "P3": 2, "P4": 3}.get(p, 99)

    def _sort_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            rows,
            key=lambda r: (
                _priority_rank(r["priority"]),
                _effort_rank(r["effort"]),
                -r["addressed_count"],
                r["id"],
            ),
        )

    # ----------------------------------------------------------------------
    # Split: cross-component (≥2 components) vs. single-component.
    # ----------------------------------------------------------------------
    cross = [m for m in enriched if len(m["component_list"]) >= 2]
    single = [m for m in enriched if len(m["component_list"]) < 2]

    # ----------------------------------------------------------------------
    # Group single-component mitigations by their primary component, then
    # apply the consolidation rule based on how many DISTINCT components
    # appear across the mitigation set (cross + single — both contribute).
    # ----------------------------------------------------------------------
    distinct_components: list[str] = []
    seen_comp: set[str] = set()
    # Order: components in their threat-model.yaml order (preserves the
    # deterministic component listing in §2.3).
    for cid in components.keys():
        if cid not in seen_comp:
            distinct_components.append(cid)
            seen_comp.add(cid)
    n_components = len(distinct_components)

    by_component: dict[str, list[dict]] = {cid: [] for cid in distinct_components}
    for m in single:
        cid = m["primary_component_id"]
        if cid and cid in by_component:
            by_component[cid].append(m)
        else:
            # Fall back to a synthetic "(unattributed)" bucket — happens
            # when a mitigation has zero linked threats and no explicit
            # `components` field; rare but possible during early drafts.
            by_component.setdefault("(unattributed)", []).append(m)

    # Tier grouping helper.
    def _tier_for_component(cid: str) -> str:
        comp = components.get(cid) or {}
        return _classify_component_layer(comp)

    groups: list[dict] = []

    # 1. Cross-component first (always its own table when non-empty).
    if cross:
        groups.append({
            "header":                  f"Cross-Component Mitigations ({len(cross)})",
            "include_affects_column":  True,
            "mitigations":             _sort_rows(cross),
        })

    # 2. Per-component / per-tier / flat — depending on n_components.
    if n_components <= 5:
        # One table per non-empty component.
        for cid in distinct_components:
            rows = by_component.get(cid) or []
            if not rows:
                continue
            comp_name = (components.get(cid) or {}).get("name", cid)
            groups.append({
                "header":                  f"{comp_name} ({len(rows)})",
                "include_affects_column":  False,
                "mitigations":             _sort_rows(rows),
            })
    elif n_components <= 10:
        # One table per architectural tier.
        tier_order = ("client", "application", "data")
        tier_label = {
            "client":      "Client Tier",
            "application": "Application Tier",
            "data":        "Data Tier",
        }
        by_tier: dict[str, list[dict]] = {t: [] for t in tier_order}
        for cid, rows in by_component.items():
            if cid == "(unattributed)" or not rows:
                continue
            by_tier.setdefault(_tier_for_component(cid), []).extend(rows)
        for tier in tier_order:
            rows = by_tier.get(tier) or []
            if not rows:
                continue
            groups.append({
                "header":                  f"{tier_label[tier]} ({len(rows)})",
                "include_affects_column":  False,
                "mitigations":             _sort_rows(rows),
            })
    else:
        # Single flat table for very large component counts.
        flat = [m for cid in distinct_components for m in by_component.get(cid, [])]
        flat += by_component.get("(unattributed)", [])
        groups.append({
            "header":                  f"All Mitigations ({len(flat)})",
            "include_affects_column":  True,   # show component in this layout
            "mitigations":             _sort_rows(flat),
        })

    # Unattributed fallback (rare): emit a trailing table when the
    # consolidated layout didn't already pick it up.
    unattr = by_component.get("(unattributed)", [])
    if unattr and n_components <= 10:
        groups.append({
            "header":                  f"Unattributed ({len(unattr)})",
            "include_affects_column":  False,
            "mitigations":             _sort_rows(unattr),
        })

    intro = (
        "Mitigations below cover all open findings, **grouped by component** and "
        "sorted by priority (P1 first). Cross-component mitigations are listed "
        "once in a separate table — they affect more than one component, so "
        "duplicating them per-component would create redundant rows. Sort within "
        "each table: priority ascending, effort ascending, findings-addressed "
        "descending."
    )

    tpl = env.get_template("mitigations.md.j2")
    return tpl.render(groups=groups, intro=intro).rstrip() + "\n"


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

    def eligible(c: dict[str, Any]) -> bool:
        eff = (c.get("effectiveness") or "").lower()
        shown = c.get("show_in_strengths_by_default", eff != "missing")
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
        (ctx.contract["sections"].get("operational_strengths") or {})
        .get("table", {}).get("rows", {}).get("max", 8)
    )

    def arch_control_name(c: dict[str, Any]) -> str:
        for key in ("architectural_control", "canonical_name", "name", "control_name"):
            v = (c.get(key) or "").strip()
            if v:
                return v
        dom = (c.get("domain") or "").strip()
        if dom:
            return dom.replace("_", " ").title()
        return "Security Control"

    def gap_text(c: dict[str, Any], eff: str) -> str:
        for key in ("gap", "limitation", "residual_risk", "weakness"):
            v = (c.get(key) or "").strip()
            if v:
                return v
        if eff == "adequate":
            return "None identified"
        return "See §7 for the domain-level structural gaps."

    def mitigates_cell(c: dict[str, Any]) -> list[dict[str, str]]:
        mits = c.get("mitigates_findings") or []
        out = []
        for ref in mits:
            label = (threats.get(ref) or {}).get("title", "")
            out.append({"ref": ref, "label": label})
        return out

    rendered_rows = []
    for c in filtered[:max_rows]:
        eff = (c.get("effectiveness") or "partial").lower()
        rendered_rows.append({
            "architectural_control": arch_control_name(c),
            "implementation":        (c.get("implementation") or c.get("description") or "—").strip(),
            "effectiveness":         eff,
            "gap":                   gap_text(c, eff),
            "mitigates":             mitigates_cell(c),
        })
    overflow = max(0, len(filtered) - max_rows)

    # Optional overrides from fragment
    overrides_path = ctx.fragments_dir / "operational-strengths-overrides.json"
    overrides: dict[str, Any] = {
        "intentionally_vulnerable_or_deficient": "structurally deficient",
        "bottom_line": (
            "These controls narrow specific attack surfaces but none eliminates a "
            "Critical finding on its own."
        ),
    }
    if overrides_path.is_file():
        try:
            ov = json.loads(overrides_path.read_text(encoding="utf-8"))
            _validate_fragment("operational_strengths", ov, "operational-strengths-overrides.schema.json")
            overrides.update({k: v for k, v in ov.items() if v is not None})
        except FragmentError as e:
            ctx.warnings.append(f"operational-strengths overrides ignored: {e.detail}")

    show_intro = ctx.eval_context.get("verdict_severity") in ("yellow", "red")
    tpl = env.get_template("operational-strengths.md.j2")
    return tpl.render(
        rows=rendered_rows,
        overflow_count=overflow,
        overrides=overrides,
        show_intro=show_intro,
    ).rstrip() + "\n"


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
    lines.append(
        "→ *Full compliance details in "
        "[Section 7b — Requirements Compliance](#7b-requirements-compliance).*"
    )
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
    for sid in ("verdict", "security_posture_at_a_glance", "top_findings",
                "architecture_assessment", "mitigations",
                "requirements_compliance_ms",
                "operational_strengths"):
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


def _render_critical_attack_chain(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    data = _load_fragment(ctx, "critical_attack_chain", section["fragment"])
    _validate_fragment("critical_attack_chain", data, section["schema"])
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
        ln[len(prefix):].strip()
        for ln in md.splitlines()
        if ln.startswith(prefix) and re.match(r"\d+\.\d+", ln[len(prefix):])
    ]
    expected = [
        (sub.get("title") or "").strip()
        for sub in section.get("required_subsections", []) or []
        if sub.get("title")
    ]
    # If no level-3 numbered subsections at all, fall back to just "missing".
    if not present or not expected:
        return ""
    present_short = [p.split(" ", 1)[0] for p in present][:16]
    expected_short = [e.split(" ", 1)[0] for e in expected][:16]
    if present_short == expected_short:
        return ""                      # numbers line up — don't muddy the error
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
    """
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

    for pat in section.get("required_patterns", []) or []:
        if not re.search(pat, md):
            raise FragmentError(
                section_id,
                f"fragment missing required pattern: {pat!r}",
            )

    for sub in section.get("required_subsections", []) or []:
        title = sub.get("title")
        level = sub.get("level", 3)
        pattern = sub.get("title_pattern")
        if title:
            needle = f"{'#' * level} {title}"
            if needle not in md:
                # For §7 specifically, show the present vs. expected heading
                # list so the orchestrator sees the exact numbering drift
                # (e.g. "fragment has 7.13 Defense-in-Depth; expected 7.14").
                hint_suffix = _subsection_drift_hint(md, section, level) \
                    if section_id == "security_architecture" else ""
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
                    rest = md[line_match.end():]
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
        tail = md[m.end():]
        nxt = re.search(r"^###\s+", tail, re.MULTILINE)
        domain_slice = tail[:nxt.start()] if nxt else tail
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

    return md.rstrip() + "\n"


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
    tail = md[m.end():]
    nxt = re.search(r"^###\s+", tail, flags=re.MULTILINE)
    section_end = m.end() + (nxt.start() if nxt else len(tail))
    section_body = md[m.end():section_end]

    # Strip any pre-existing Markdown table from the section body. A table
    # is a run of lines starting with `|`, possibly preceded by a separator
    # line with `|---|`. We only strip tables, NOT the mermaid block or
    # prose — mermaid lives inside ``` ``` fences and tables don't.
    def _strip_first_table(body: str) -> str:
        # Match a full table: header row + separator row + 1..N data rows.
        table_re = re.compile(
            r"(?:^\|[^\n]*\|\s*\n"         # header row
            r"\|[ \t:\-|]+\|\s*\n"          # separator row
            r"(?:\|[^\n]*\|\s*\n)+)",       # one or more data rows
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
    has_runtime = any(
        isinstance(c, dict) and (c.get("runtime") or "").strip()
        for c in components
    )
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
            t.get("id") or t.get("t_id"): t
            for t in (ctx.yaml_data.get("threats") or [])
            if isinstance(t, dict)
        }
        include_titles = len(th_ids) <= 15
        def _format_threat_link(tid: str) -> str:
            th = threats_by_id.get(tid) if isinstance(threats_by_id, dict) else None
            title = (th or {}).get("title") if isinstance(th, dict) else None
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
                f'| {"".join(anchors)}{canonical} | {name} | {kind} | {runtime} | {paths_cell} | {th_cell} |'
            )
        else:
            table_lines.append(
                f'| {"".join(anchors)}{canonical} | {name} | {kind} | {paths_cell} | {th_cell} |'
            )
    table_lines.append("")
    insertion = "\n".join(table_lines)
    # Replace the section body (between `### 2.3 …` and the next `### `) with
    # the cleaned prose/mermaid followed by the deterministic table.
    return md[:m.end()] + "\n" + cleaned_body.rstrip() + "\n" + insertion + md[section_end:]


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
_LINKED_ID_COLUMN_HEADERS: frozenset[str] = frozenset({
    "linked threats",
    "linked mitigations",
    "linked findings",
    "linked",
    "mitigates",
    "addresses",
    "covers",
    "primary mitigations",
    "key findings",
})

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
        return cell

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


def _escape_dollar_operators(md: str) -> str:
    """Wrap `$word` tokens in backticks so they survive KaTeX/MathJax-enabled
    markdown renderers.

    Skips:
    - Fenced code blocks (``` … ```)
    - Inline code spans (`…`)
    - HTML comments (<!-- … -->)
    - Tokens already preceded by a backtick or backslash escape
    - Dollar amounts like `$10` (no identifier following)
    - LaTeX-style `$$…$$` blocks (lookbehind guard)
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
            out_chunks.append(_DOLLAR_OP_RE.sub(r"`$\1`", chunk))
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
        if ref not in cache:
            cache[ref] = ctx.linkify_with_label(ref)
        return cache[ref]

    # Find every bare `[X-NNN](#x-nnn)` that is NOT followed by em-dash label.
    # Use negative-lookahead `(?! — )`. Bullet-list lines `- [ID](#…) — label`
    # are NOT matched because they have the em-dash.
    def sub_ref(m: re.Match) -> str:
        ref = m.group(1)
        # Skip citation style `*([F-009](#f-009))*` — check surrounding chars.
        start = m.start()
        prefix = md[max(0, start - 3):start]
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
                r"\[([FTM]-\d{3,4})\]\(#[ftm]-\d+\)(?! — )",
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
    (r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----",
     "-----BEGIN RSA PRIVATE KEY-----\n<REDACTED — key bytes masked>\n-----END RSA PRIVATE KEY-----",
     "rsa_privkey"),
    # OpenSSH / generic PRIVATE KEY blocks.
    (r"-----BEGIN (OPENSSH|EC|DSA|PRIVATE) KEY-----[\s\S]+?-----END \1 KEY-----",
     "-----BEGIN \\1 KEY-----\n<REDACTED — key bytes masked>\n-----END \\1 KEY-----",
     "private_key"),
    # AWS Access Key.
    (r"\bAKIA[0-9A-Z]{16}\b", "AKIA<REDACTED>", "aws_key"),
    # Google API key.
    (r"\bAIza[0-9A-Za-z_-]{35}\b", "AIza<REDACTED>", "google_api_key"),
    # Alchemy-style provider key (hex/base58 32+ chars after a known prefix).
    (r"wss://[^/]+/v2/[A-Za-z0-9_-]{20,}", "wss://<provider>/v2/<REDACTED>", "provider_wss_key"),
    # Juice-Shop's hardcoded Alchemy token specifically.
    (r"FZDapFZSs1l6yhHW4VnQqsi18qSd-3GJ", "<REDACTED — Alchemy WebSocket key>", "juiceshop_alchemy"),
    # GitHub token.
    (r"\bghp_[A-Za-z0-9]{36,}\b", "ghp_<REDACTED>", "github_token"),
    # Long hex string (>= 48 chars) — potential bearer token / hmac secret.
    (r"\b[a-fA-F0-9]{48,}\b", "<REDACTED — long hex>", "long_hex"),
]


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
    generated  = meta.get("generated")  or "—"
    mode       = meta.get("mode")       or "—"
    depth      = meta.get("assessment_depth") or "standard"
    analysis_v = meta.get("analysis_version")
    plugin_v   = meta.get("plugin_version")
    orch_model = (meta.get("model") or
                  next((a.get("model") for a in agents_yaml
                        if (a.get("role") or "").lower().startswith("orchestrator")), "—"))
    # M3.3 — fall back to .skill-config.json when meta lacks repo/output paths.
    # The orchestrator does not currently emit `meta.repository_root` /
    # `meta.output_dir`; the skill-layer config has them. Without this
    # fallback the appendix shows "—" for paths that the user actually knows.
    skill_cfg = _read_skill_config(ctx.output_dir)
    repo       = (meta.get("repository_root")
                  or skill_cfg.get("repo_root")
                  or "—")
    out_dir    = (meta.get("output_dir")
                  or skill_cfg.get("output_dir")
                  or "—")
    # M3.3 — derive total duration from per-stage stats when meta lacks it.
    stage_rows = _read_stage_stats(ctx.output_dir)
    duration   = meta.get("analysis_duration_seconds")
    if not duration and stage_rows:
        # Sum stage duration_ms; round to seconds.
        ms_sum = sum(r.get("duration_ms", 0) for r in stage_rows)
        if ms_sum:
            duration = ms_sum // 1000
    dur_fmt    = f"{int(duration) // 60}m {int(duration) % 60:02d}s" if duration else "—"

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
                f"| {r.get('stage','—')} | {r.get('name','—')} | {agent} | "
                f"{r.get('model','—')} | {dur} | {tools:,} | {toks:,} |"
            )
        lines.append(
            f"| **Total** | — | — | — | **{_fmt_ms(total_ms)}** | "
            f"**{total_tools:,}** | **{total_tokens:,}** |"
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

    # --- Coverage Summary --------------------------------------------------
    lines.append("### Coverage Summary")
    lines.append("")
    n_threats = len(ctx.yaml_data.get("threats") or [])
    n_mits    = len(ctx.yaml_data.get("mitigations") or [])
    n_comps   = len(ctx.yaml_data.get("components") or [])
    n_ctrl    = len(ctx.yaml_data.get("security_controls") or [])
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for t in ctx.yaml_data.get("threats") or []:
        s = (t.get("risk") or t.get("severity") or "").strip().lower()
        if s in sev_counts:
            sev_counts[s] += 1
    eff_counts = {"adequate": 0, "partial": 0, "weak": 0, "missing": 0}
    for c in _normalize_security_controls(ctx.yaml_data.get("security_controls")):
        e = (c.get("effectiveness") or "").strip().lower()
        if e in eff_counts:
            eff_counts[e] += 1
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Components analyzed | {n_comps} |")
    lines.append(f"| Threats identified | {n_threats} "
                 f"(🔴 {sev_counts['critical']} · 🟠 {sev_counts['high']} · "
                 f"🟡 {sev_counts['medium']} · 🟢 {sev_counts['low']}) |")
    lines.append(f"| Mitigations prioritized | {n_mits} |")
    lines.append(f"| Security controls cataloged | {n_ctrl} "
                 f"(✅ {eff_counts['adequate']} · ⚠️ {eff_counts['partial']} · "
                 f"🔶 {eff_counts['weak']} · ❌ {eff_counts['missing']}) |")
    lines.append("")

    # --- Agent Dispatch Log ------------------------------------------------
    lines.append("### Agent Dispatch Log")
    lines.append("")
    dispatch_rows = _agent_dispatch_rows(ctx, agents_yaml)
    if dispatch_rows:
        lines.append("| Agent | Model | Role | Phases |")
        lines.append("|-------|-------|------|--------|")
        for a in dispatch_rows:
            lines.append(
                f"| {a.get('name','—')} | {a.get('model','—')} | "
                f"{a.get('role','—')} | {a.get('phases','—')} |"
            )
    else:
        lines.append("_No agent dispatch log available._")
    lines.append("")

    # --- Tokens & Cost ------------------------------------------------------
    if tokens or cost:
        lines.append("### Tokens & Cost")
        lines.append("")
        if tokens:
            lines.append(
                f"- **Tokens:** input={tokens.get('input','—')} · "
                f"output={tokens.get('output','—')} · "
                f"cache_read={tokens.get('cache_read','—')} · "
                f"cache_write={tokens.get('cache_write','—')} · "
                f"total={tokens.get('total','—')}"
            )
        if cost:
            lines.append(f"- **Billing:** {cost.get('billing', '—')}")
            if cost.get('cache_savings_pct') is not None:
                lines.append(f"- **Cache savings:** {cost.get('cache_savings_pct')}%")
        lines.append("")
        lines.append("> ⚠ **Scope:** host session only — sub-agent token spend "
                     "is not captured by Claude Code's hook infrastructure.")
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
            "name":   name,
            "model":  a.get("model") or "—",
            "role":   a.get("role") or "—",
            "phases": a.get("phases") or "—",
        }
    log = ctx.output_dir / ".agent-run.log"
    if not log.is_file():
        return list(by_name.values())
    try:
        pat = re.compile(
            r"(?P<name>[\w-]+)\s+(?:AGENT_INVOKE|AGENT_START)\s+.*?"
            r"(?:model:\s*(?P<model>[^,\s\)]+))?"
        )
        seen_phases: dict[str, set[str]] = {}
        for line in log.read_text(encoding="utf-8").splitlines():
            m = pat.search(line)
            if not m:
                continue
            name = m.group("name")
            model = m.group("model") or "—"
            phase_m = re.search(r"\[Phase\s+(\d+[ab]?)/", line)
            phase = phase_m.group(1) if phase_m else ""
            entry = by_name.setdefault(name, {
                "name": name, "model": model, "role": "—", "phases": "—",
            })
            if entry["model"] in ("—", ""):
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
    "client":      ("frontend", "spa", "ui", "browser", "angular", "react", "vue", "client"),
    "data":        ("nosql", "sql", "mongo", "postgres", "mysql", "redis", "datalayer",
                    "data-layer", "persistence", "store", "db", "database"),
    # 'application' is the catch-all default
}


def _classify_component_tier(component: dict) -> str:
    """Return 'client' | 'application' | 'data' for a component dict."""
    haystack = " ".join([
        (component.get("id") or "").lower(),
        (component.get("name") or "").lower(),
        " ".join(component.get("paths") or []).lower(),
    ])
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
    phase_start_re = re.compile(
        r"PHASE_START\s+\[Phase\s+(\d+(?:b)?)/\d+\]\s+(.*)$"
    )
    phase_end_inline_re = re.compile(
        r"PHASE_END\s+\[Phase\s+(\d+(?:b)?)/\d+\]\s+[✓]?\s*(.+?)\s*\[(\d+(?:m\s*\d+)?s)\]"
    )
    phase_end_bare_re = re.compile(
        r"PHASE_END\s+\[Phase\s+(\d+(?:b)?)/\d+\]\s+[✓]?\s*(.+)$"
    )
    agent_by_phase: dict[str, str] = {
        "1":  "threat-analyst (sonnet-4-6)",
        "2":  "recon-scanner (sonnet-4-6)",
        "3":  "threat-analyst (sonnet-4-6)",
        "4":  "threat-analyst (sonnet-4-6)",
        "5":  "threat-analyst (sonnet-4-6)",
        "6":  "threat-analyst (sonnet-4-6)",
        "7":  "threat-analyst (sonnet-4-6)",
        "8":  "threat-analyst (sonnet-4-6)",
        "9":  "Nx stride-analyzer (sonnet-4-6)",
        "10": "threat-analyst (sonnet-4-6)",
        "10b":"appsec-triage-validator (sonnet-4-6)",
        "11": "threat-analyst (sonnet-4-6)",
    }

    def _parse_iso_to_epoch(ts: str) -> int | None:
        try:
            return int(datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                       .replace(tzinfo=timezone.utc).timestamp())
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
                rows.append({
                    "phase": f"Phase {phase}",
                    "description": desc[:60],
                    "agent": agent_by_phase.get(phase, "—"),
                    "duration": duration,
                })
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
                rows.append({
                    "phase": f"Phase {phase}",
                    "description": desc[:60],
                    "agent": agent_by_phase.get(phase, "—"),
                    "duration": _fmt_seconds(delta),
                })
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

    lines: list[str] = [
        '<a id="appendix-composition-notes"></a>',
        "## Appendix: Composition Notes",
        "",
        "This run completed cleanly (the rendered threat model satisfies the "
        "contract) but the composition pipeline reported the following non-"
        "blocking issues. Listed here for transparency — none of them invalidate "
        "the threat model. See `CHANGELOG.md` (M2.14) for the design rationale.",
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
        lines.append("_No issues recorded. (This appendix should normally be omitted in the "
                     "clean case — its presence indicates a contract-evaluation drift.)_")
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
                        lines.append(f"- `{atype}` → `{target}`"
                                     + (f": {details}" if details else ""))
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
            f"_{auto_n} of these fix(es) can be applied non-interactively via_ "
            f"`/appsec-advisor:fix-run-issues`_._"
        )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _render_appendix_vektor_taxonomy(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    lines = [
        '<a id="appendix-a-vektor-taxonomy"></a>',
        '## Appendix A — Vektor Taxonomy',
        "",
        "This appendix defines the attacker-starting-position labels used in the "
        "Top Findings table and throughout §8 Threat Register. Each label answers the "
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
        lines.append(f'### {vlabel}')
        lines.append("")
        bd = item.get("breach_distance")
        pos = item.get("attacker_position")
        if pos:
            lines.append(f"**Attacker position:** {pos}"
                         + (f" · **Breach distance:** {bd}" if bd is not None else ""))
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
            cwe_refs = " · ".join(
                f"[CWE-{c}](https://cwe.mitre.org/data/definitions/{c}.html)" for c in typ_cwes
            )
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
    # Tracks whether any finding row carries the `(raw Critical)`
    # annotation — set inside the per-row loop. When True we emit a
    # one-line footnote at the end of §8 explaining the convention.
    has_raw_downgrade = False
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

    # Severity + STRIDE aggregates.
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for t in threats:
        sev = (t.get("risk") or t.get("severity") or "").strip().lower()
        if sev in counts:
            counts[sev] += 1
    total = sum(counts.values())

    stride_map = {"spoofing": 0, "tampering": 0, "repudiation": 0,
                  "info_disclosure": 0, "dos": 0, "elev_priv": 0}
    stride_aliases = {
        "spoofing": "spoofing", "tampering": "tampering", "repudiation": "repudiation",
        "information disclosure": "info_disclosure",
        "information_disclosure": "info_disclosure",
        "info disclosure": "info_disclosure",
        "denial of service": "dos", "denial_of_service": "dos",
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
        "The threat register is structured in two layers: **architectural categories** "
        "(TH-NN) group findings by the pattern they express; each category expands into "
        "the concrete code-level **findings** that instantiate it. Executives read the "
        "category summary; engineers read the finding table inside the category they own."
    )
    lines.append("")
    lines.append(
        f"**Risk Distribution:** 🔴 Critical: {counts['critical']} · 🟠 High: {counts['high']} · "
        f"🟡 Medium: {counts['medium']} · 🟢 Low: {counts['low']} · **Total findings: {total}**"
    )
    lines.append(
        f"**STRIDE Coverage:** Spoofing: {stride_map['spoofing']} · "
        f"Tampering: {stride_map['tampering']} · Repudiation: {stride_map['repudiation']} · "
        f"Information Disclosure: {stride_map['info_disclosure']} · "
        f"Denial of Service: {stride_map['dos']} · Elevation of Privilege: {stride_map['elev_priv']}"
    )
    lines.append(
        f"**Category Distribution:** {cat_active_total} of {cat_taxonomy_total} categories active — "
        f"Critical: {cat_sev_counts['critical']} · High: {cat_sev_counts['high']} · "
        f"Medium: {cat_sev_counts['medium']} · Low: {cat_sev_counts['low']}"
    )
    lines.append("")

    # ---- §8.A Categories at a glance -------------------------------------
    lines.append("### 8.A Categories at a glance")
    lines.append("")
    # The §8.F Compound-Attack-Chains link is conditional on the same
    # threshold the renderer uses to actually emit §8.F (≥ 2 Critical
    # findings). Without this guard, fixtures with < 2 Criticals end up
    # with a dangling link target — the chain section isn't rendered but
    # the §8.A intro still claims it exists.
    def _triage_chain_count() -> int:
        p = ctx.output_dir / ".triage-flags.json"
        if not p.is_file():
            return 0
        try:
            return len(json.loads(p.read_text(encoding="utf-8")).get("ranking", {}).get("views", {}).get("chains", {}).get("chains_ranked") or [])
        except Exception:
            return 0

    will_emit_8f = counts["critical"] >= 2 and (
        (ctx.fragments_dir / "compound-chains.json").is_file() or _triage_chain_count() > 0
    )
    if will_emit_8f:
        lines.append(
            "Architectural threat categories active in this project, sorted by the highest "
            "severity and finding count. See [§8.F Compound Attack Chains](#8f-compound-attack-chains) "
            "for role-scoped chain details."
        )
    else:
        lines.append(
            "Architectural threat categories active in this project, sorted by the "
            "highest severity and finding count."
        )
    lines.append("")
    lines.append("| TH | Category | Severity (eff.) | Findings | Top Finding | Breach | OWASP | Pillar |")
    lines.append("|----|----------|-----------------|----------|-------------|--------|-------|--------|")

    # Sort categories by (severity rank, -count).
    cat_ids_sorted = sorted(
        cats_active.keys(),
        key=lambda cid: (sev_rank.get(cat_eff_severity(cid), 99), -len(cats_active[cid]), cid),
    )
    for cid in cat_ids_sorted:
        bucket = cats_active[cid]
        meta = taxonomy.get(cid, {})
        title = meta.get("title") or cid
        eff_sev = cat_eff_severity(cid)
        sev_badge = f"{ctx.severity_emoji(eff_sev)} {ctx.severity_label(eff_sev)}".strip()
        # Top finding = most critical one, first by id.
        top = sorted(bucket, key=lambda t: (sev_rank.get((t.get("risk") or t.get("severity") or "").lower(), 99),
                                            t.get("t_id") or t.get("id") or ""))[0]
        top_id = top.get("t_id") or top.get("id") or "-"
        top_title = (top.get("title") or top.get("scenario_short") or top.get("scenario") or "")[:80]
        breach = top.get("breach_distance") or (1 if "anon" in (top.get("vektor") or "").lower() else 2)
        owasp = meta.get("owasp_top10_2021") or "—"
        if owasp and owasp != "—":
            owasp = f"[{owasp}](https://owasp.org/Top10/{owasp}_2021/)"
        pillar = meta.get("cwe_pillar") or "—"
        if pillar and pillar != "—":
            pillar_num = pillar.split("-", 1)[-1] if "-" in pillar else pillar
            pillar = f"[{pillar}](https://cwe.mitre.org/data/definitions/{pillar_num}.html)"
        lines.append(
            f"| [{cid}](#{cid.lower()}) | {title} | {sev_badge} | {len(bucket)} | "
            f"[{top_id}](#{top_id.lower()}) — {top_title} | {breach} | {owasp} | {pillar} |"
        )
    lines.append("")

    # ---- §8.B / §8.C / §8.D / §8.E severity-tier category sections -------
    # Each tier gets its own letter so the four headings have distinct
    # anchors (otherwise right-side TOC outlines see four `#8b-…`
    # entries and several markdown viewers strip the suffix).
    sev_letter = {"critical": "B", "high": "C", "medium": "D", "low": "E"}
    for sev_key, sev_label in (("critical", "Critical"), ("high", "High"),
                                ("medium", "Medium"), ("low", "Low")):
        cids = [cid for cid in cat_ids_sorted if cat_eff_severity(cid) == sev_key]
        if sev_key == "low" and not cids:
            continue  # low category block is conditional
        letter = sev_letter[sev_key]
        lines.append(f'<a id="8{letter.lower()}-{sev_key}-categories"></a>')
        lines.append(f"### 8.{letter} {sev_label} Categories ({len(cids)})")
        lines.append("")
        for cid in cids:
            meta = taxonomy.get(cid, {})
            # Anchor on its own line keeps right-side TOC renderers from
            # treating the inline <a> tag as part of the heading text.
            lines.append(f'<a id="{cid.lower()}"></a>')
            lines.append(f'#### {cid} — {meta.get("title", cid)}')
            lines.append("")
            desc = (meta.get("description") or "").strip().replace("\n", " ")
            if desc:
                lines.append(f"> {desc}")
                lines.append("")
            lines.append("**Findings in this category:**")
            lines.append("")
            lines.append("| ID | Finding | Component | Criticality | CVSS | Vektor | Mitigation | References |")
            lines.append("|----|---------|-----------|-------------|------|--------|------------|------------|")
            # Sort findings inside a category by severity → CVSS desc → id.
            bucket = sorted(
                cats_active[cid],
                key=lambda t: (
                    sev_rank.get((t.get("risk") or t.get("severity") or "").lower(), 99),
                    -(t.get("cvss") or 0.0),
                    t.get("t_id") or t.get("id") or "",
                ),
            )
            for t in bucket:
                tid = t.get("t_id") or t.get("id") or "-"
                title = (t.get("title") or t.get("scenario_short") or "").strip()
                if not title:
                    # Fallback: synthesise a title from the first sentence of
                    # the scenario, capped at 80 chars. Matches the cap used
                    # by the Top Findings composer (line ~829) so the same
                    # label appears in both the register and its references.
                    sc = (t.get("scenario") or "")
                    if sc:
                        first_sentence = sc.split(".")[0].strip()
                        title = first_sentence[:80] if first_sentence else "-"
                    else:
                        title = "-"
                # Component cell MUST use the canonical `C-NN` anchor — the raw
                # yaml id (e.g. `auth-service`) is not a valid anchor target
                # because §2.3 Components emits `<a id="c-01">` not
                # `<a id="auth-service">`. Bug repro: prior to this fix, §8
                # rendered `[auth-service](#auth-service) Authentication Service`,
                # which is a dangling link.
                raw_cid = (t.get("component_id") or t.get("component") or "").strip()
                comp = components.get(raw_cid, {})
                if comp and re.match(r"^C-\d+$", raw_cid):
                    comp_id = raw_cid
                elif comp:
                    comp_id = comp.get("_canonical_id") or raw_cid
                else:
                    # Fall back to position-based C-NN lookup.
                    comp_id = "C-00"
                    for cid, c in components.items():
                        if re.match(r"^C-\d+$", cid) and (c.get("_original_id") == raw_cid
                                                          or (c.get("name") or "").strip() == raw_cid):
                            comp_id = cid
                            comp = c
                            break
                comp_name = (comp.get("name") if comp else raw_cid) or "-"
                sev = (t.get("risk") or t.get("severity") or "").lower()
                impact = (t.get("impact") or "").lower()
                sev_cell = f"{ctx.severity_emoji(sev)} {ctx.severity_label(sev)}".strip()
                # Flag down-rated findings: impact was Critical but risk rendered
                # as High/Medium because likelihood knocked it down. Track the
                # presence so we can emit a one-time footnote at the end of §8.
                if impact == "critical" and sev != "critical":
                    sev_cell += " *(raw Critical)*"
                    has_raw_downgrade = True
                # CVSS — support both `cvss` (legacy flat) and `cvss_v4.base_score`
                # (current schema). The yaml writer emits `cvss_v4.base_score`,
                # but older fixtures store it as a flat number.
                cvss = t.get("cvss")
                if cvss is None:
                    cv4 = t.get("cvss_v4") or {}
                    cvss = cv4.get("base_score") if isinstance(cv4, dict) else None
                cvss_cell = f"{cvss:.1f}" if isinstance(cvss, (int, float)) else "—"
                # Vektor: yaml stores slug; Appendix A renders human label.
                # Slug→label map is the module-level `_VEKTOR_LABEL`.
                raw_vektor = (t.get("vektor") or "internet-user").strip()
                vektor_id = raw_vektor.lower().replace(" ", "-")
                vektor_label = (
                    (t.get("vektor_label") or "").strip()
                    or _VEKTOR_LABEL.get(vektor_id)
                    or raw_vektor.replace("-", " ").title()
                )
                vektor_cell = f"[{vektor_label}](#vektor-{vektor_id})"
                mit_ids = t.get("mitigations") or []
                # Bare M-NNN links — the canonical mitigation title lives in
                # §9 (per-M-NNN block + Management-Summary mitigations
                # table). Repeating the title here was duplicating the same
                # string up to three times across the document.
                mit_cell_parts = [f"[{mid}](#{mid.lower()})" for mid in mit_ids[:2]]
                mit_cell = " · ".join(mit_cell_parts) if mit_cell_parts else "—"
                cwe = t.get("cwe") or ""
                owasp_ref = meta.get("owasp_top10_2021") or ""
                refs = []
                if cwe:
                    cwe_num = cwe.split("-", 1)[-1] if "-" in cwe else cwe
                    refs.append(f"[CWE-{cwe_num}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)")
                if owasp_ref:
                    refs.append(f"[{owasp_ref}:2021](https://owasp.org/Top10/{owasp_ref}_2021/)")
                refs_cell = " · ".join(refs) if refs else "—"
                title_escaped = title.replace("|", "\\|")
                lines.append(
                    f'| <a id="{tid.lower()}"></a>{tid} | {title_escaped} | '
                    f'[{comp_id}](#{comp_id.lower()}) {comp_name} | {sev_cell} | {cvss_cell} | '
                    f'{vektor_cell} | {mit_cell} | {refs_cell} |'
                )
            lines.append("")
            lines.append("---")
            lines.append("")

    # ---- §8.F Compound Attack Chains (from fragment or triage fallback) -----
    # Primary source: .fragments/compound-chains.json (LLM-authored).
    # Fallback: ranking.views.chains in .triage-flags.json — always present
    # after Phase 10b, survives runtime_cleanup because triage files are kept.
    cc_path = ctx.fragments_dir / "compound-chains.json"
    triage_path = ctx.output_dir / ".triage-flags.json"

    def _chains_from_triage() -> list[dict]:
        """Extract chain records from .triage-flags.json as fallback."""
        if not triage_path.is_file():
            return []
        try:
            tf = json.loads(triage_path.read_text(encoding="utf-8"))
            return (tf.get("ranking") or {}).get("views", {}).get("chains", {}).get("chains_ranked") or []
        except Exception:
            return []

    if counts["critical"] >= 2:
        lines.append('<a id="8f-compound-attack-chains"></a>')
        lines.append("### 8.F Compound Attack Chains")
        lines.append("")
        if not cc_path.is_file():
            triage_chains = _chains_from_triage()
            if triage_chains:
                lines.append(
                    "Three compound attack chains were identified by the triage stage. "
                    "Each chain shows how individual findings combine into a higher-impact exploit path."
                )
                lines.append("")
                for chain in triage_chains:
                    cid = chain.get("id", "CC-??")
                    lines.append(f'<a id="{cid.lower()}"></a>')
                    lines.append(f'#### {cid} — {chain.get("name", "")}')
                    lines.append("")
                    lines.append("| | |")
                    lines.append("|---|---|")
                    sev = (chain.get("severity") or "High").lower()
                    lines.append(f'| **Compound severity** | {ctx.severity_emoji(sev)} {ctx.severity_label(sev)} |')
                    lines.append(f'| **Severity justification** | {chain.get("severity_justification", "—")} |')
                    lines.append(f'| **Breach distance** | {chain.get("breach_distance", "—")} |')
                    keystones = chain.get("keystones") or []
                    if keystones:
                        ks = "<br/>".join(f'[{k}](#{k.lower()})' for k in keystones)
                        lines.append(f'| **Keystones** | {ks} |')
                    contributors = chain.get("contributors") or []
                    if contributors:
                        cn = "<br/>".join(f'[{c}](#{c.lower()})' for c in contributors)
                        lines.append(f'| **Contributors** *(capped at High)* | {cn} |')
                    narrative = chain.get("narrative") or ""
                    if narrative:
                        lines.append("")
                        lines.append(narrative)
                    lines.append("")
                    lines.append("---")
                    lines.append("")
            else:
                lines.append("_No compound chains documented for this assessment._")
                lines.append("")
    if counts["critical"] >= 2 and cc_path.is_file():
        cc_data = json.loads(cc_path.read_text(encoding="utf-8"))
        _validate_fragment("compound_chains", cc_data, "compound-chains.schema.json")
        if cc_data:
            lines.append(cc_data["intro"])
            lines.append("")
            for chain in cc_data["chains"]:
                cid = chain["id"]
                lines.append(f'<a id="{cid.lower()}"></a>')
                lines.append(f'#### {cid} — {chain["title"]}')
                lines.append("")
                lines.append("| | |")
                lines.append("|---|---|")
                sev = chain["compound_severity"].lower()
                lines.append(f'| **Compound severity** | {ctx.severity_emoji(sev)} {ctx.severity_label(sev)} |')
                lines.append(f'| **Severity justification** | {chain["severity_justification"]} |')
                lines.append(f'| **Breach distance** | {chain["breach_distance"]} |')
                if chain.get("keystones"):
                    ks = "<br/>".join(
                        f'[{k["ref"]}](#{k["ref"].lower()}) — {k["label"]}' for k in chain["keystones"]
                    )
                    lines.append(f'| **Keystones** *(effective {sev_label_strict(sev)})* | {ks} |')
                if chain.get("contributors"):
                    cn = "<br/>".join(
                        f'[c["ref"]](#{c["ref"].lower()}) — {c["label"]}'.replace("c[\"ref\"]", c["ref"])
                        for c in chain["contributors"]
                    )
                    lines.append(f'| **Contributors** *(capped at High)* | {cn} |')
                lines.append(f'| **Mitigates by breaking** | {chain["mitigates_by_breaking"]} |')
                lines.append("")
                if chain.get("narrative"):
                    lines.append(chain["narrative"])
                    lines.append("")
                lines.append("---")
                lines.append("")

    # ---- §8.G Architectural Findings (from fragment) ---------------------
    # Same emission contract as §8.F: emit anchor + heading whenever the
    # contract condition fires, even when the LLM fragment is absent —
    # otherwise §8.A and the TOC link to a non-existent anchor.
    af_path = ctx.fragments_dir / "architectural-findings.json"
    if (counts["critical"] + counts["high"]) >= 3:
        lines.append('<a id="8g-architectural-findings"></a>')
        lines.append("### 8.G Architectural Findings")
        lines.append("")
        if not af_path.is_file():
            lines.append("_No architectural findings documented for this assessment._")
            lines.append("")
    if (counts["critical"] + counts["high"]) >= 3 and af_path.is_file():
        af_data = json.loads(af_path.read_text(encoding="utf-8"))
        _validate_fragment("architectural_findings", af_data, "architectural-findings.schema.json")
        if af_data:
            lines.append(af_data["intro"])
            lines.append("")
            for af in af_data["findings"]:
                aid = af["id"]
                lines.append(f'<a id="{aid.lower()}"></a>')
                lines.append(f'#### {aid} — {af["title"]}')
                lines.append("")
                lines.append(f"> {af['description']}")
                lines.append("")
                lines.append("| | |")
                lines.append("|---|---|")
                lines.append(f'| **Architectural theme** | {af["architectural_theme"]} |')
                lines.append(f'| **Severity** | {ctx.severity_emoji(af["severity"].lower())} {af["severity"]} |')
                if af.get("impact"):
                    lines.append(f'| **Impact** | {af["impact"]} |')
                lines.append(f'| **Structural defect** | {af["structural_defect"]} |')
                lines.append(f'| **Target architecture** | {af["target_architecture"]} |')
                lines.append(f'| **Remediation effort** | {af["remediation_effort"]} |')
                if af.get("aggregates_findings"):
                    ag = "<br/>".join(
                        f'[{f["ref"]}](#{f["ref"].lower()}) — {f["label"]}' for f in af["aggregates_findings"]
                    )
                    lines.append(f'| **Aggregates findings** | {ag} |')
                if af.get("primary_mitigations"):
                    pm = "<br/>".join(
                        f'[{m["ref"]}](#{m["ref"].lower()}) — {m["label"]}' for m in af["primary_mitigations"]
                    )
                    lines.append(f'| **Primary mitigations** | {pm} |')
                if af.get("derived_from"):
                    lines.append(f'| **Derived from** | {af["derived_from"]} |')
                lines.append("")
                lines.append("---")
                lines.append("")

    # ---- §8 footnote: raw-severity convention ----------------------------
    # Only emitted when at least one finding row carries the annotation.
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

    return "\n".join(lines).rstrip() + "\n"


def sev_label_strict(sev_key: str) -> str:
    """Capitalized severity label used inside §8.F role markers."""
    return {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}.get(
        (sev_key or "").lower(), sev_key.title() if sev_key else ""
    )


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
        "for file:line context and to the threat-category description in §8 "
        "for the underlying weakness."
    )
    lines.append("")
    for prio in ("P1", "P2", "P3", "P4"):
        bucket = [m for m in mitigations if (m.get("priority") or "").strip() == prio]
        bucket.sort(key=lambda m: (m.get("m_id") or m.get("id") or ""))
        sub_label = {"P1": "P1 — Immediate", "P2": "P2 — This Sprint",
                     "P3": "P3 — Next Quarter", "P4": "P4 — Backlog"}[prio]
        lines.append(f"### {sub_label}")
        lines.append("")
        if not bucket:
            lines.append(f"_No {prio} mitigations._")
            lines.append("")
            continue
        for m in bucket:
            mid = m.get("m_id") or m.get("id") or "-"
            title = (m.get("title") or "(untitled)").strip()
            lines.append(f'<a id="{mid.lower()}"></a>')
            lines.append(f'#### {mid} — {title}')
            lines.append("")

            # Addresses as a bulleted list of linkified refs (reference layout).
            addressed = m.get("addresses") or m.get("threat_ids") or []
            if addressed:
                lines.append("**Addresses:**")
                lines.append("")
                for ref in addressed:
                    lines.append(f"- {ctx.linkify_with_label(ref)}")
                lines.append("")

            # Prevents CWEs — prefer explicit field; else derive from addressed findings.
            cwes = m.get("prevents_cwes") or m.get("cwes") or []
            if not cwes and addressed:
                derived: list[str] = []
                seen_cwe: set[str] = set()
                threats_idx = {
                    (t.get("t_id") or t.get("id") or "").upper(): t
                    for t in (ctx.yaml_data.get("threats") or [])
                }
                for ref in addressed:
                    tt = threats_idx.get((ref or "").strip().upper()) or {}
                    c = (tt.get("cwe") or "").strip()
                    if c and c not in seen_cwe:
                        derived.append(c)
                        seen_cwe.add(c)
                cwes = derived
            if cwes:
                # Render as a bullet list so the CWE name (if known) can be
                # appended — matches the reference threat model layout.
                _CWE_NAMES = {
                    "CWE-89":  "SQL Injection",
                    "CWE-79":  "Cross-site Scripting",
                    "CWE-94":  "Code Injection",
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
                    suffix = f" — {nm}" if nm else ""
                    lines.append(f"- [{key}](https://cwe.mitre.org/data/definitions/{num}.html){suffix}")
                lines.append("")

            lines.append(f"**Priority:** **{sub_label}**")
            sev = m.get("severity") or m.get("max_severity") or ""
            if sev:
                lines.append(
                    f"**Severity:** {ctx.severity_emoji(sev)} {ctx.severity_label(sev)}".rstrip()
                )
            lines.append(f"**Effort:** {m.get('effort','Medium')}")
            lines.append("")

            # Why / How / Verification are emitted ONLY when the yaml
            # carries authored content. Earlier versions of this renderer
            # synthesised boilerplate fallbacks for every empty field —
            # producing identical-looking sentences in 20+ mitigation
            # blocks that added length without information. The §9
            # preamble above tells the reader where to look when a field
            # is omitted.
            why = (m.get("why") or "").strip()
            if why:
                lines.append(f"**Why:** {why}")
                lines.append("")

            how = (m.get("how") or "").strip()
            how_code = m.get("how_code")
            how_lang = m.get("how_code_lang", "javascript")
            if how:
                lines.append(f"**How:** {how}")
                lines.append("")
            if how_code:
                lines.append(f"```{how_lang}")
                lines.append(how_code.rstrip())
                lines.append("```")
                lines.append("")

            ver = (m.get("verification") or "").strip()
            if ver:
                lines.append(f"**Verification:** {ver}")
                lines.append("")

            ref = m.get("reference") or ""
            if ref:
                lines.append(f"**Reference:** {ref}")
                lines.append("")

            lines.append("---")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


def _render_by_id(ctx: RenderContext, env: jinja2.Environment, section_id: str, section: dict) -> str:
    dispatcher: dict[str, Any] = {
        "infobox":                 _render_infobox,
        "changelog":               _render_changelog,
        "toc":                     _render_toc,
        "management_summary":      _render_management_summary,
        "verdict":                 _render_verdict,
        "security_posture_at_a_glance": _render_security_posture_at_a_glance,
        "top_findings":            _render_top_findings,
        "architecture_assessment": _render_architecture_assessment,
        "mitigations":             _render_mitigations,
        "operational_strengths":   _render_operational_strengths,
        "threat_register":         _render_threat_register,
        "mitigation_register":     _render_mitigation_register,
        "appendix_run_statistics": _render_appendix_run_statistics,
        "composition_notes":        _render_composition_notes,
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
    raise ContractError(
        f"no renderer for section {section_id!r} with fragment_type={ftype!r}"
    )


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
    {"id": "use_cases", "condition": "has_use_cases"},
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
    tid_to_component: dict[str, str] = {}
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
        # Back-resolve component_id from components[].threat_ids.
        if not t.get("component_id") and tid in tid_to_component:
            t["component_id"] = tid_to_component[tid]
        # Also resolve by component NAME (yaml often stores component: "Auth Service").
        if t.get("component") and not t.get("component_id"):
            name = t["component"]
            for c in _components:
                if isinstance(c, dict) and (c.get("name") or "").strip() == name:
                    t["component_id"] = c.get("id") or ""
                    break
        # `mitigation_ids` → canonical `mitigations` slot used by renderer.
        if not (t.get("mitigations") or []):
            inline = t.get("mitigation_ids") or []
            if inline:
                t["mitigations"] = list(dict.fromkeys(inline))
            elif tid in tid_to_mitigations:
                t["mitigations"] = list(dict.fromkeys(tid_to_mitigations[tid]))

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
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
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
                c.get("id", ""): c
                for c in (tax_raw.get("categories") or [])
                if isinstance(c, dict) and c.get("id")
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
            k: {kk: str(vv) for kk, vv in v.items()}
            for k, v in (contract.get("severity_taxonomy") or {}).items()
        },
        effectiveness_taxonomy={
            k: dict(v) for k, v in (contract.get("effectiveness_taxonomy") or {}).items()
        },
        category_taxonomy=category_taxonomy,
        eval_context={
            "critical_count":      severity_counts["critical"],
            "high_count":          severity_counts["high"],
            "medium_count":        severity_counts["medium"],
            "low_count":           severity_counts["low"],
            # category-level counts (active TH categories grouped by
            # their effective-severity). Used by §8.B sub-section
            # conditionals (e.g. `low_category_count > 0`).
            "low_category_count":    _category_count_by_severity(_threats, category_taxonomy, "low"),
            "medium_category_count": _category_count_by_severity(_threats, category_taxonomy, "medium"),
            "high_category_count":   _category_count_by_severity(_threats, category_taxonomy, "high"),
            "critical_category_count": _category_count_by_severity(_threats, category_taxonomy, "critical"),
            "verdict_severity":    _verdict_severity_from_fragment(fragments_dir),
            "check_requirements":  bool(yaml_data.get("meta", {}).get("check_requirements")),
            "verbose_report":      bool(yaml_data.get("meta", {}).get("verbose_report")),
            "has_use_cases":       bool(yaml_data.get("use_cases")),
            "triage_has_warnings": bool(triage.get("warnings")),
            # M2.14 — Sprint 6 conditional. True when the prior compose run
            # (or skill-level auto-retry) reported soft warnings, section
            # retries, or auto-retry cycles. Drives the §Composition Notes
            # appendix include/skip decision.
            "compose_warned":      _compose_warned_signal(output_dir),
            # M2.15 — Sprint 7 conditional. True when .run-issues.json
            # reports run_status != "clean" (any errors / warnings /
            # perf anomalies / recovery events). Drives the §Run Issues
            # appendix include/skip decision.
            "run_warned":          _run_warned_signal(output_dir),
        },
    )

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
                sys.stderr.write(
                    f"COMPOSE: [{progress_idx}/{total_sections}] rendering §{sid}\n"
                )
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

    return rendered, ctx.warnings


_STRIDE_TO_TH_FALLBACK = {
    "tampering":             "TH-01",
    "spoofing":              "TH-02",
    "repudiation":           "TH-16",
    "information disclosure": "TH-17",
    "denial of service":     "TH-12",
    "elevation of privilege": "TH-06",
}

# Keyword → TH-NN heuristic. Used when the yaml doesn't carry an explicit
# `threat_category_id` field. ORDER MATTERS — the first match wins, so more
# specific keywords come before generic ones. This list MUST be the single
# source of truth; both _render_threat_register and _compute_top_findings_rows
# call `infer_threat_category` below to stay consistent.
_CATEGORY_KEYWORD_MAP: list[tuple[list[str], str]] = [
    (["sql injection", "nosql", "xxe", "injection", "template injection",
      "sandbox escape"], "TH-01"),
    (["alg:none", "jwt bypass", "jwt algorithm", "algorithm confusion",
      "token forgery", "2fa", "totp", "authentication bypass"], "TH-02"),
    (["md5", "bcrypt", "rsa private key", "hardcoded key", "hardcoded rsa",
      "weak hash", "cryptograph", "stored without encryption", "plaintext storage",
      "cleartext", "unencrypted storage"], "TH-03"),
    (["localstorage", "session storage"], "TH-04"),
    ([" rce ", "remote code execution", "vm.run", "notevil", "runinsandbox"], "TH-05"),
    (["idor", "mass assignment", "mass update", "ownership bypass",
      "broken access", "admin role", "authorization"], "TH-06"),
    (["file upload", "path traversal", "zip slip", "yaml bomb",
      "local file read", "file read via"], "TH-07"),
    (["ssrf", "server-side request forgery"], "TH-08"),
    (["/ftp", "/encryptionkeys", "/support/logs", "unauthenticated",
      "metrics endpoint"], "TH-09"),
    (["xss", "domsanitizer", "bypasssecuritytrust"], "TH-11"),
    (["denial of service", "rate limit", "rate-limit", "dos", "event loop"], "TH-12"),
    (["csrf"], "TH-15"),
    (["cors misconfiguration", "cors allows", "wildcard cors"], "TH-09"),
    (["supply chain", "dependabot", "outdated dep"], "TH-14"),
    (["audit", "logging", "security event"], "TH-16"),
    (["stack trace", "error response", "error disclos"], "TH-17"),
    (["redirect"], "TH-18"),
]


def infer_threat_category(t: dict, taxonomy: dict[str, dict]) -> str:
    """Map a threat record → canonical TH-NN. Shared between Top Findings and
    §8 Threat Register so the same threat always lands under the same
    category anchor."""
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
    haystack = " ".join([
        (t.get("scenario") or t.get("description") or "").lower(),
        title_only,
    ])
    for keys, cat in _CATEGORY_KEYWORD_MAP:
        for k in keys:
            if k in haystack:
                return cat
    stride = (t.get("stride") or t.get("stride_category") or "").strip().lower()
    return _STRIDE_TO_TH_FALLBACK.get(stride, "TH-01")


def _category_count_by_severity(
    threats: list[dict], taxonomy: dict[str, dict], severity: str,
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
    """
    title_tpl = (
        title_template_override
        or ctx.contract["document"].get("title_template", "Threat Model")
    )
    project = ctx.yaml_data.get("project")
    if not isinstance(project, dict):
        project = {}
    project.setdefault("name", _derive_project_name(ctx))
    env = jinja2.Environment(autoescape=False)
    title = env.from_string(title_tpl).render(project=project)
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
        if "/" in name:      # scoped package like @owasp/juice-shop — keep as-is
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
        prog="render_threat_model.py",
        description="Contract-driven renderer for threat-model.md. "
                    "Composes the final Markdown from threat-model.yaml + "
                    "schema-validated data fragments, making LLM structural "
                    "drift impossible.",
    )
    p.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT,
                   help=f"Path to sections contract YAML (default: {DEFAULT_CONTRACT}).")
    p.add_argument("--output-dir", type=Path, required=True,
                   help="Assessment output directory containing threat-model.yaml "
                        "and .fragments/.")
    p.add_argument("--fragments-subdir", default=".fragments",
                   help="Sub-directory under --output-dir where LLM fragments live.")
    p.add_argument("--out", type=Path, default=None,
                   help="Where to write the rendered Markdown "
                        "(default: <output-dir>/threat-model.md).")
    p.add_argument("--lenient", action="store_true",
                   help="Do not abort on a missing fragment; emit a visible stub instead. "
                        "Implies strict=False. Not recommended outside development.")
    p.add_argument("--strict", action="store_true",
                   help="Abort on missing fragment or schema violation (default since M3.0). "
                        "Accepted for explicit invocations (e.g. from .qa-repair-plan.json "
                        "re_render_command). Ignored when --lenient is also set — --lenient "
                        "always wins.")
    p.add_argument("--dry-run", action="store_true",
                   help="Write to stdout, do not touch the filesystem.")
    p.add_argument("--document", choices=["full", "architecture"], default="full",
                   help="Which document set to render. 'full' renders the complete "
                        "threat-model.md (default). 'architecture' renders only the "
                        "architecture sections (1-7) as analysis-model.md — this is "
                        "available after Phase 8, before STRIDE analysis completes.")
    args = p.parse_args(argv)
    if args.lenient and args.strict:
        # --lenient wins; warn so an automation script sees the override.
        print("COMPOSE_WARN: both --strict and --lenient passed; --lenient wins",
              file=sys.stderr)
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
        return 0                        # best-effort; silent on IO failure

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
        "raw_issue":     err.detail,
        "section_id":    err.section_id,
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
            "fragment MUST contain all 14 canonical subsections (7.1–7.14) "
            "in order; a common drift is omitting §7.8 Real-time / WebSocket "
            "and §7.9 AI / LLM, which shifts every later heading by 2. "
            "Re-run compose_threat_model.py after the edit."
        )
    else:
        action["type"] = "fragment_error"
        action["remediation"] = (
            f"Address the issue reported in `raw_issue` inside the listed "
            f"fragment(s). Re-run compose_threat_model.py afterwards. "
            f"Do not modify other fragments — this error is local."
        )

    exhausted = attempt > _PRE_RENDER_REPAIR_MAX_ATTEMPTS
    plan = {
        "generated":    _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "stage":        "pre_render",
        "output_dir":   str(output_dir),
        "status":       "exhausted" if exhausted else "fail",
        "attempt":      attempt,
        "max_attempts": _PRE_RENDER_REPAIR_MAX_ATTEMPTS,
        "issue_count":  1,
        "actions":      [action],
        "re_render_command": (
            "python3 $CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py "
            "--output-dir $OUTPUT_DIR --strict"
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
        return {"section": "§8 Threat Register", "category": "orphan_link",
                "detail": text}
    if "operational-strengths overrides" in lower:
        return {"section": "Operational Strengths", "category": "schema_drift",
                "detail": text}
    if "soft-skip section" in lower:
        section = text.replace("soft-skip section", "").strip()
        return {"section": section or "(unknown)", "category": "soft_skip",
                "detail": text}
    if "not in contract" in lower:
        return {"section": "(unknown)", "category": "contract_mismatch",
                "detail": text}
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
    retries_over_one = {sid: n for sid, n in (section_retry_counts or {}).items()
                        if n and n > 1}
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
            args.contract, args.output_dir,
            fragments_subdir=args.fragments_subdir,
            strict=not args.lenient,
            document=args.document,
            emit_progress=not args.dry_run,     # CLI callers see live section progress
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
    _qa_comment_pat = re.compile(r'<!--\s*QA:.*?-->\s*\n?', flags=re.DOTALL)
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
    _t_link_pat = re.compile(r'\[T-(\d+)\]\(#t-\d+\)')
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
        # Build T-NNN → (component-prefix-id, lowercased anchor) map
        t_alias: dict[str, tuple[str, str]] = {}
        for i, t in enumerate(threats_ordered, start=1):
            if not isinstance(t, dict):
                continue
            real_id = (t.get("t_id") or t.get("id") or "").strip()
            if not real_id:
                continue
            t_alias[f"{i:03d}"] = (real_id, real_id.lower())

        # Pass 1: rewrite `[T-NNN](#t-nnn)` → `[T-NNN](#real-id)` so the link
        # itself works. Keep the visible "T-NNN" text — readers expect it.
        def _rewrite(match: re.Match) -> str:
            tnnn = match.group(1)
            mapped = t_alias.get(tnnn)
            if mapped:
                return f"[T-{tnnn}](#{mapped[1]})"
            return match.group(0)
        rewritten = _t_link_pat.sub(_rewrite, rendered)

        # Pass 2: also inject `<a id="t-NNN"></a>` aliases at the row of the
        # mapped real id so the original `#t-nnn` form keeps working for other
        # consumers (incremental cross-refs from prior runs, external readers).
        for tnnn, (_real, anchor) in t_alias.items():
            if tnnn not in referenced_t:
                continue
            # Find the line that already declares `<a id="<anchor>">` and
            # prepend the t-NNN alias to that anchor list.
            real_anchor_decl = f'<a id="{anchor}"></a>'
            if real_anchor_decl in rewritten:
                rewritten = rewritten.replace(
                    real_anchor_decl,
                    f'<a id="t-{tnnn}"></a>{real_anchor_decl}',
                    1,
                )
            else:
                unresolved.append(tnnn)

        rendered = rewritten

    if unresolved:
        warnings.append(
            f"{len(unresolved)} orphan T-NNN link target(s) could not be bridged "
            f"({', '.join('T-'+x for x in unresolved[:5])}"
            f"{', …' if len(unresolved) > 5 else ''}). Threats may have been "
            "consolidated in Phase 9 — verify yaml.threats[] count matches the "
            "highest T-NNN reference in the source fragments."
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

    for w in warnings:
        print(f"RENDER_WARN: {w}", file=sys.stderr)
    print(f"RENDERED: {out_path.name}  ({len(rendered.splitlines())} lines, "
          f"{len(warnings)} warnings)")
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
            for action in (prior.get("actions") or []):
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
