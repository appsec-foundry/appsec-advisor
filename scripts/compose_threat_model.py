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
from pathlib import Path
from typing import Any

import jinja2
import yaml

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
    env.filters["format_mitigations"] = format_mitigations
    env.filters["format_defect_findings"] = format_defect_findings
    env.filters["format_component_list"] = format_component_list
    env.filters["format_mitigation_addresses"] = format_mitigation_addresses
    env.filters["format_strengths_mitigates"] = format_strengths_mitigates

    return env


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
    tpl = env.get_template(section.get("template", "changelog.md.j2"))
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
    # Drop punctuation GitHub treats as zero-width. Added `[`, `]`, `#` to cover
    # cases where heading text contained markdown-link syntax or anchors.
    for ch in "—–,.()[]'\"&/:#":
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
      * Finding  : `[F/T-NNN](#…) — <threat title>`
      * Component: `[C-NN](#c-nn) — <Component name>`   (canonical C-NN anchor)
      * Threat   : `[TH-NN](#th-nn) — <Category name>` (from taxonomy)
      * Vektor   : `[<label>](#vektor-<id>)`
      * Mitigations with `(P1)/(P2)/…` priority token.
    """
    components = _component_lookup(ctx)
    threats = _threat_lookup(ctx)
    mitigations = _mitigation_lookup(ctx)

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

    def resolve_threat_category(t: dict) -> tuple[str, str]:
        """Return (TH-NN, Category Name) for the threat-register link.
        Uses the shared `infer_threat_category` helper so Top Findings and
        §8 Threat Register always agree on which category a threat belongs to."""
        cid = infer_threat_category(t, ctx.category_taxonomy)
        title = (ctx.category_taxonomy.get(cid, {}) or {}).get("title", cid)
        return cid, title

    max_rows = (
        (ctx.contract["sections"].get("top_findings") or {}).get("table", {}).get("rows", {}).get("max", 20)
    )
    rendered: list[dict[str, Any]] = []
    for idx, tid in enumerate(qualifying_ids[:max_rows], start=1):
        t = threats.get(tid) or {}
        # Component cell: use the canonical C-NN anchor.
        c_anchor, c_name = resolve_component(t.get("component_id") or t.get("component"))
        # Threat cell: map STRIDE → TH-NN.
        th_id, th_name = resolve_threat_category(t)
        # Mitigation cells: M-ID + action + priority token (P1/P2/…).
        mit_cells: list[dict[str, str]] = []
        for mid in (t.get("mitigations") or [])[:2]:
            m = mitigations.get(mid, {})
            mit_cells.append({
                "id": mid,
                "action": (m.get("title") or "").strip(),
                "priority": (m.get("priority") or "").strip(),
            })
        # Vektor — yaml stores the kebab-case slug (`internet-anon`),
        # Appendix A defines the human label (`Internet Anon`). Render the
        # label, keep the slug for the anchor. Defensive: strip any stray
        # text the agent might have put in `vektor_label` (title/enum drift).
        _VEKTOR_LABEL = {
            "internet-anon": "Internet Anon",
            "internet-user": "Internet User",
            "internet-priv-user": "Internet Priv User",
            "victim-required": "Victim-Required",
            "build-time": "Build-Time",
            "repo-read": "Repo-Read",
            "n/a": "n/a",
        }
        raw_vektor = (t.get("vektor") or t.get("vektor_id") or "internet-user").strip()
        vektor_id = raw_vektor.lower().replace(" ", "-")
        vektor_label = (
            (t.get("vektor_label") or "").strip()
            or _VEKTOR_LABEL.get(vektor_id)
            or raw_vektor.replace("-", " ").title()
        )
        # Finding title — never fallback to the ID itself.
        title = (t.get("title") or t.get("scenario_short") or "").strip()
        if not title:
            sc = (t.get("scenario") or "").strip()
            title = (sc.split(".")[0] if sc else tid)[:80]

        rendered.append({
            "rank": idx,
            "criticality": (t.get("risk") or t.get("severity") or "").lower(),
            "finding_id":   tid,
            "finding_title": title,
            "component_id": c_anchor,
            "component_name": c_name,
            "threat_id":    th_id,
            "threat_name":  th_name,
            "vektor_id":    vektor_id,
            "vektor_label": vektor_label,
            "mitigations":  mit_cells,
        })
    return rendered, len(qualifying_ids)


def _render_architecture_assessment(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    data = _load_fragment(ctx, "architecture_assessment", section["fragment"])
    _validate_fragment("architecture_assessment", data, section["schema"])
    tpl = env.get_template(section["template"])
    return tpl.render(data=data).rstrip() + "\n"


def _render_mitigations(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    mitigations = ctx.yaml_data.get("mitigations", []) or []
    threats = _threat_lookup(ctx)
    components = _component_lookup(ctx)

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
        return {
            "id": mid,
            "title": m.get("title", ""),
            "component_list": component_list,
            "addresses": addressed,
            "effort": m.get("effort", "Medium"),
            "priority": m.get("priority", ""),
            "max_sev_rank": max_sev,
            "addressed_count": len(addressed),
        }

    enriched = [enrich(m) for m in mitigations]
    prioritized = [m for m in enriched if m["max_sev_rank"] <= 1]
    followup    = [m for m in enriched if m["max_sev_rank"] >  1]

    def _sort(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(rows, key=lambda r: (_effort_rank(r["effort"]), -r["addressed_count"], r["id"]))

    prioritized = _sort(prioritized)
    followup    = _sort(followup)

    prioritized_intro = (
        "The mitigations below address the Critical and High findings in the Top Findings "
        "table and must be completed before any production deployment. Entries are ordered "
        "by effort (lowest first), then by number of threats addressed (highest first)."
    )
    followup_intro = (
        "The mitigations below address the remaining High/Medium findings not covered above "
        "and should be scheduled within the current or next sprint. Same ordering rule "
        "applies (effort ascending, findings-addressed descending)."
    )
    tpl = env.get_template("mitigations.md.j2")
    return tpl.render(
        prioritized=prioritized,
        followup=followup,
        prioritized_intro=prioritized_intro,
        followup_intro=followup_intro,
    ).rstrip() + "\n"


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
    controls = ctx.yaml_data.get("security_controls", []) or []
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


def _render_management_summary(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    # Explicit composition ensures the 5-canonical-subsection order is enforced.
    parts = ["## Management Summary"]
    sections = ctx.contract["sections"]
    for sid in ("verdict", "top_findings", "architecture_assessment",
                "mitigations", "operational_strengths"):
        sec = sections[sid]
        ftype = sec.get("fragment_type")
        if ftype == "data":
            body = _render_by_id(ctx, env, sid, sec)
        elif ftype == "computed":
            body = _render_by_id(ctx, env, sid, sec)
        else:
            raise ContractError(f"unsupported fragment_type for MS subsection {sid}: {ftype}")
        parts.append(body.rstrip())
    return "\n\n".join(parts) + "\n"


def _render_critical_attack_chain(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    data = _load_fragment(ctx, "critical_attack_chain", section["fragment"])
    _validate_fragment("critical_attack_chain", data, section["schema"])
    tpl = env.get_template(section["template"])
    return tpl.render(data=data).rstrip() + "\n"


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
                raise FragmentError(
                    section_id,
                    f"required subsection missing: '{needle}'",
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

    # Linkify every bare `[X-NNN](#x-nnn)` ref in the prose — except inside
    # fenced code blocks and `*(...)*` Verdict-style citations — so cross-
    # references never emit without a human-readable label.
    md = _linkify_bare_refs_in_prose(ctx, md)

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
        kind = c.get("kind") or c.get("type") or "—"
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
        # (see §8.D Mitigations column, §7 linked threats); we follow suit
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

    return re.sub(
        r"(?P<prefix>\*\*Linked threats?:\*\*)(?P<refs>[^\n]*)",
        linkify_line,
        md,
    )


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
    repo       = meta.get("repository_root") or "—"
    out_dir    = meta.get("output_dir") or "—"
    duration   = meta.get("analysis_duration_seconds")
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
    for c in ctx.yaml_data.get("security_controls") or []:
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


def _scrape_phase_durations(output_dir: Path) -> list[dict[str, str]]:
    """Best-effort parse of `.agent-run.log` → per-phase duration table rows."""
    log = output_dir / ".agent-run.log"
    if not log.is_file():
        return []
    rows: list[dict[str, str]] = []
    phase_pattern = re.compile(
        r"PHASE_END\s+\[Phase\s+(\d+(?:b)?)/\d+\]\s+[✓]?\s*(.+?)\s*\[(\d+m\d+s)\]"
    )
    agent_pattern = re.compile(r"AGENT_INVOKE.*?([\w-]+)\s+\(model:\s*([^,\)]+)")
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
    try:
        for line in log.read_text(encoding="utf-8").splitlines():
            m = phase_pattern.search(line)
            if not m:
                continue
            phase = m.group(1)
            desc = m.group(2).strip().rstrip("—").strip()
            desc = re.sub(r"\s+[A-Z]{5,}\s.*$", "", desc)  # trim tail like "STRIDE — 35 threats …"
            duration = m.group(3)
            rows.append({
                "phase": f"Phase {phase}",
                "description": desc[:60],
                "agent": agent_by_phase.get(phase, "—"),
                "duration": duration,
            })
    except OSError:
        return []
    return rows


def _render_appendix_vektor_taxonomy(ctx: RenderContext, env: jinja2.Environment, section: dict) -> str:
    lines = [
        '## <a id="appendix-a-vektor-taxonomy"></a>Appendix A — Vektor Taxonomy',
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
        lines.append(f'### <a id="vektor-{vid}"></a>{vlabel}')
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
      * 8.A Categories at a glance (category-level summary table)
      * 8.B Critical Categories (N)   — per-TH sub-sections with findings tables
      * 8.B High Categories (N)
      * 8.B Medium Categories (N)
      * 8.B Low Categories (N)        — only when non-empty
      * 8.C Compound Attack Chains    — from LLM fragment (conditional)
      * 8.D Architectural Findings    — from LLM fragment (conditional)
    """
    threats = ctx.yaml_data.get("threats") or []
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
    lines.append(
        "Architectural threat categories active in this project, sorted by the highest "
        "severity and finding count. See [§8.C Compound Attack Chains](#8c-compound-attack-chains) "
        "for role-scoped chain details."
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

    # ---- §8.B Critical / High / Medium / Low Categories ------------------
    for sev_key, sev_label in (("critical", "Critical"), ("high", "High"),
                                ("medium", "Medium"), ("low", "Low")):
        cids = [cid for cid in cat_ids_sorted if cat_eff_severity(cid) == sev_key]
        if sev_key == "low" and not cids:
            continue  # low category block is conditional
        lines.append(f'<a id="8b-{sev_key}-categories"></a>')
        lines.append(f"### 8.B {sev_label} Categories ({len(cids)})")
        lines.append("")
        for cid in cids:
            meta = taxonomy.get(cid, {})
            lines.append(f'#### <a id="{cid.lower()}"></a>{cid} — {meta.get("title", cid)}')
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
                # as High/Medium because likelihood knocked it down.
                if impact == "critical" and sev != "critical":
                    sev_cell += " *(raw Critical)*"
                # CVSS — support both `cvss` (legacy flat) and `cvss_v4.base_score`
                # (current schema). The yaml writer emits `cvss_v4.base_score`,
                # but older fixtures store it as a flat number.
                cvss = t.get("cvss")
                if cvss is None:
                    cv4 = t.get("cvss_v4") or {}
                    cvss = cv4.get("base_score") if isinstance(cv4, dict) else None
                cvss_cell = f"{cvss:.1f}" if isinstance(cvss, (int, float)) else "—"
                # Vektor: yaml stores slug; Appendix A renders human label.
                _VEKTOR_LABEL = {
                    "internet-anon": "Internet Anon",
                    "internet-user": "Internet User",
                    "internet-priv-user": "Internet Priv User",
                    "victim-required": "Victim-Required",
                    "build-time": "Build-Time",
                    "repo-read": "Repo-Read",
                    "n/a": "n/a",
                }
                raw_vektor = (t.get("vektor") or "internet-user").strip()
                vektor_id = raw_vektor.lower().replace(" ", "-")
                vektor_label = (
                    (t.get("vektor_label") or "").strip()
                    or _VEKTOR_LABEL.get(vektor_id)
                    or raw_vektor.replace("-", " ").title()
                )
                vektor_cell = f"[{vektor_label}](#vektor-{vektor_id})"
                mit_ids = t.get("mitigations") or []
                mit_cell_parts = []
                for mid in mit_ids[:2]:
                    m = mitigations.get(mid, {})
                    mtitle = (m.get("title") or "").strip()
                    mit_cell_parts.append(f"[{mid}](#{mid.lower()})" + (f" — {mtitle}" if mtitle else ""))
                mit_cell = "<br/>".join(mit_cell_parts) if mit_cell_parts else "—"
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

    # ---- §8.C Compound Attack Chains (from fragment) ---------------------
    cc_path = ctx.fragments_dir / "compound-chains.json"
    if counts["critical"] >= 2 and cc_path.is_file():
        # Present-but-invalid is an error. Present-and-valid is the happy path.
        # Absent is fine — the section is conditional and simply skipped.
        cc_data = json.loads(cc_path.read_text(encoding="utf-8"))
        _validate_fragment("compound_chains", cc_data, "compound-chains.schema.json")
        if cc_data:
            lines.append('<a id="8c-compound-attack-chains"></a>')
            lines.append("### 8.C Compound Attack Chains")
            lines.append("")
            lines.append(cc_data["intro"])
            lines.append("")
            for chain in cc_data["chains"]:
                cid = chain["id"]
                lines.append(f'#### <a id="{cid.lower()}"></a>{cid} — {chain["title"]}')
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

    # ---- §8.D Architectural Findings (from fragment) ---------------------
    af_path = ctx.fragments_dir / "architectural-findings.json"
    if (counts["critical"] + counts["high"]) >= 3 and af_path.is_file():
        # Same policy as compound-chains: present-but-invalid fails the build.
        af_data = json.loads(af_path.read_text(encoding="utf-8"))
        _validate_fragment("architectural_findings", af_data, "architectural-findings.schema.json")
        if af_data:
            lines.append('<a id="8d-architectural-findings"></a>')
            lines.append("### 8.D Architectural Findings")
            lines.append("")
            lines.append(af_data["intro"])
            lines.append("")
            for af in af_data["findings"]:
                aid = af["id"]
                lines.append(f'#### <a id="{aid.lower()}"></a>{aid} — {af["title"]}')
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

    return "\n".join(lines).rstrip() + "\n"


def sev_label_strict(sev_key: str) -> str:
    """Capitalized severity label used inside §8.C role markers."""
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
            lines.append(f'#### <a id="{mid.lower()}"></a>{mid} — {title}')
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

            why = (m.get("why") or "").strip()
            if not why:
                # Synthesise a content-aware Why from the addressed findings.
                # Better than the pre-fix boilerplate because it names every
                # linked finding rather than claiming "the linked findings"
                # generically — useful when the reader scans the mitigation
                # body without opening the threat register.
                first = addressed[0] if addressed else ""
                first_label = ctx.lookup_label(first) if first else ""
                refs_inline = ", ".join(
                    f"[{r}](#{r.lower()})" for r in addressed
                ) or "the linked findings"
                why = (
                    f"This mitigation closes the root-cause weakness underlying "
                    f"{refs_inline}. Without it, "
                    f"{(first_label or 'the underlying issue').lower()} "
                    "remains directly exploitable and cannot be compensated for by "
                    "perimeter controls alone — the fix must be applied in code."
                )
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
                # Preserve existing line breaks; strip trailing whitespace.
                lines.append(how_code.rstrip())
                lines.append("```")
                lines.append("")
            elif not how:
                # Concrete-enough fallback: reference the mitigation title
                # itself as the remediation instruction and point at the
                # per-finding Evidence lines for file:line locations.
                title_phrase = (m.get("title") or "").strip()
                tail = f" (*{title_phrase}*)." if title_phrase else "."
                lines.append(
                    f"**How:** Implement the change described in the mitigation title above"
                    f"{tail} Locate the affected code via the **Evidence** lines on each linked "
                    "finding, apply the fix consistently across all occurrences, and remove any "
                    "ad-hoc workarounds (commented-out sanitizers, wrapper functions) that "
                    "re-introduce the unsafe pattern."
                )
                lines.append("")

            ver = (m.get("verification") or "").strip()
            if not ver:
                ver = (
                    "After the change, re-run the threat model and confirm every "
                    f"linked finding is either marked resolved or downgraded."
                )
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
        "top_findings":            _render_top_findings,
        "architecture_assessment": _render_architecture_assessment,
        "mitigations":             _render_mitigations,
        "operational_strengths":   _render_operational_strengths,
        "threat_register":         _render_threat_register,
        "mitigation_register":     _render_mitigation_register,
        "appendix_run_statistics": _render_appendix_run_statistics,
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


def render(
    contract_path: Path,
    output_dir: Path,
    *,
    fragments_subdir: str = ".fragments",
    strict: bool = True,
) -> tuple[str, list[str]]:
    """Render `threat-model.md` from contract + yaml + fragments.

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
            "triage_has_warnings": bool(triage.get("warnings")),
        },
    )

    env = _build_jinja_env(ctx)

    # Render each section in contract order.
    rendered_parts: list[str] = []
    title = _render_title(ctx)
    rendered_parts.append(title)

    for raw in contract["document"]["order"]:
        sid, cond = (raw, None) if isinstance(raw, str) else (raw["id"], raw.get("condition"))
        if cond and not eval_condition(cond, ctx.eval_context):
            continue
        section = contract["sections"].get(sid)
        if not section:
            raise ContractError(f"document.order references unknown section id: {sid!r}")
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
    (["alg:none", "jwt bypass", "2fa", "totp", "authentication bypass"], "TH-02"),
    (["md5", "bcrypt", "rsa private key", "hardcoded key", "hardcoded rsa",
      "weak hash", "cryptograph"], "TH-03"),
    (["localstorage", "session storage"], "TH-04"),
    (["rce", "remote code execution", "eval", "notevil"], "TH-05"),
    (["idor", "mass assignment", "broken access", "admin role",
      "authorization"], "TH-06"),
    (["file upload", "path traversal", "zip slip", "yaml bomb"], "TH-07"),
    (["ssrf"], "TH-08"),
    (["/ftp", "/encryptionkeys", "/support/logs", "unauthenticated",
      "metrics"], "TH-09"),
    (["xss", "domsanitizer", "bypasssecuritytrust"], "TH-11"),
    (["denial of service", "dos", "event loop"], "TH-12"),
    (["csrf"], "TH-15"),
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
    haystack = " ".join([
        (t.get("scenario") or t.get("description") or "").lower(),
        (t.get("title") or t.get("scenario_short") or "").lower(),
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


def _render_title(ctx: RenderContext) -> str:
    """Render the document `# Threat Model — <Project Name>` header.

    Shares the project-name derivation with `_render_infobox` via
    `_derive_project_name()` so the title and the infobox never disagree.
    """
    title_tpl = ctx.contract["document"].get("title_template", "Threat Model")
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
    args = p.parse_args(argv)
    if args.lenient and args.strict:
        # --lenient wins; warn so an automation script sees the override.
        print("COMPOSE_WARN: both --strict and --lenient passed; --lenient wins",
              file=sys.stderr)
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    try:
        rendered, warnings = render(
            args.contract, args.output_dir,
            fragments_subdir=args.fragments_subdir,
            strict=not args.lenient,
        )
    except FragmentError as e:
        print(f"RENDER_FAILED: {e}", file=sys.stderr)
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

    # Detect orphan T-NNN link targets. The register emits F-NNN anchors only;
    # T-NNN is an internal category code. Any `[T-NNN](#t-nnn)` link is broken
    # by construction. Agents should reference F-NNN in architecture tables
    # (see phase-group-architecture.md). We flag orphans so the QA gate catches
    # them on the next incremental run.
    _t_link_pat = re.compile(r'\[T-(\d+)\]\(#t-\d+\)')
    t_orphans = sorted(set(_t_link_pat.findall(rendered)))
    if t_orphans:
        warnings.append(
            f"{len(t_orphans)} orphan T-NNN link target(s) detected in rendered "
            f"document ({', '.join('T-'+x for x in t_orphans[:5])}"
            f"{', …' if len(t_orphans) > 5 else ''}). Architecture tables should "
            "cite F-NNN directly — T-NNN anchors do not exist in §8."
        )

    out_path = args.out or (args.output_dir / "threat-model.md")
    if args.dry_run:
        sys.stdout.write(rendered)
    else:
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")
        except OSError as e:
            print(f"IO_ERROR: cannot write {out_path}: {e}", file=sys.stderr)
            return 3

    for w in warnings:
        print(f"RENDER_WARN: {w}", file=sys.stderr)
    print(f"RENDERED: {out_path.name}  ({len(rendered.splitlines())} lines, "
          f"{len(warnings)} warnings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
