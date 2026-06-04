#!/usr/bin/env python3
"""Deterministic QA checks for the threat model output.

Replaces expensive agent turns with mechanical checks that can be run from a
single Bash call. Each subcommand prints a short human-readable report and
exits 0 when everything is clean or 1 when fixable issues were found. Fixable
issues are either auto-applied in place (Check 1 link repair, Check 10 anchor
linkification) or printed so the QA reviewer can address them.

Usage:
    qa_checks.py links         <threat-model.md> <repo-root>
    qa_checks.py xrefs         <threat-model.md>
    qa_checks.py anchors       <threat-model.md>
    qa_checks.py invariants    <threat-model.md>
    qa_checks.py ms_structure  <threat-model.md>
    qa_checks.py cell_format   <threat-model.md>
    qa_checks.py summary_bullets <threat-model.md>
    qa_checks.py fragments     <output-dir>
    qa_checks.py contract      <threat-model.md> [<sections-contract.yaml>]
    qa_checks.py repair_plan   <threat-model.md> <output-dir> [<sections-contract.yaml>]
    qa_checks.py evidence_integrity <output-dir> <repo-root>
    qa_checks.py unmasked_secrets <threat-model.md> [<output-dir>]
    qa_checks.py relevant_findings <threat-model.md> [<sections-contract.yaml>]
    qa_checks.py all           <threat-model.md> <repo-root>
    qa_checks.py autofix       <threat-model.md> <repo-root>

`autofix` runs only the five in-place mutating passes (links, anchors, MS
structure, cell-format, heading-attribute strip) without the detector battery
or pre-pass JSON — the fast-path mutation half of `all`.

`all` runs every check in sequence and applies in-place fixes for links,
anchors, and safe Management Summary structural repairs. It prints a JSON
summary at the end so the caller can parse it.

`repair_plan` runs the contract check and, when violations are found, writes
`$output-dir/.qa-repair-plan.json` with structured repair actions that the
orchestrator can consume in REPAIR_MODE to regenerate the offending fragments
and re-invoke compose_threat_model.py. Exit 0 means no repairs needed; exit
1 means a plan was written (caller must re-render); exit 2 means error.

`ms_structure` validates that `## Management Summary` is unnumbered and
contains exactly these sub-sections, in this order:

    ### Verdict (with a red HTML <blockquote …>)
    ### Top Findings
    ### Architecture Assessment
    ### Mitigations
    ### Operational Strengths

Safe auto-repairs (numeric-prefix strip, legacy-name rename) are applied in
place; missing or reordered canonical sub-sections are flagged and require a
Phase 11 Part A rerun.

Module map (coarse — line ranges drift; refresh by re-grepping the listed names):
    L136        class Report (per-check report dataclass)
    L260        check_links / link repair
    L305        check_xrefs (cross-reference suffix coverage)
    L482        linkify_anchors (single legal producer for §4a titles)
    L710        check_invariants (sections-contract presence)
    L833        check_ms_structure (Management Summary structural check)
    L1030       check_contract + repair-plan emission
    L1135       _safe_eval_cond adapter (delegates to scripts/_safe_cond.py)
    L1163       CONTRACT_SECTION_FRAGMENTS registry (see schema-invariants §4f)
    L2000       check_evidence_integrity
    L3142       check_diagram_compactness
    L3500       check_chain_compactness
    L4125       check_chain_tid_consistency
    L5013       check_cell_format
    Later lines hold the CLI dispatcher and helpers; line numbers drift, so
    rely on the symbol names above rather than the offsets.
"""

from __future__ import annotations

import json
import json as _json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import _safe_cond
from perimeter_patterns import PERIMETER_ABSENCE_PATTERNS as _PERIMETER_ABSENCE_PATTERNS
from secret_scan import scan_file as _scan_file_for_secrets

VSCODE_LINK_RE = re.compile(r"vscode://file/([^)\s]+?)(?::(\d+))?(?=[)\s])")
T_ID_RE = re.compile(r"\bT-(\d{3,4})\b")
M_ID_RE = re.compile(r"\bM-(\d{3,4})\b")
F_ID_RE = re.compile(r"\bF-(\d{3,4})\b")
TH_ID_RE = re.compile(r"\bTH-(\d{2,3})\b")
TABLE_ID_RE = re.compile(r"^\|\s*(?:<a id=\"[tm]-\d+\"></a>)?\s*([TM]-\d+)\s*\|", re.MULTILINE)
H3_MITIGATION_RE = re.compile(r"^###\s.*?\bM-(\d{3,4})\b", re.MULTILINE)
# Risk Distribution / STRIDE Coverage regexes are deliberately lenient:
# - severity emojis (🔴 🟠 🟡 🟢) may or may not prefix each label
# - the delimiter between entries may be `·`, `|`, or plain whitespace
# - "Total" may be wrapped in `**…**` or appear as plain text
_SEV_ICON = r"(?:[🔴🟠🟡🟢⚪])?\s*"
_DELIM = r"\s*[·\|]\s*"
RISK_DIST_RE = re.compile(
    r"\*\*Risk Distribution:\*\*\s*"
    + _SEV_ICON
    + r"Critical:\s*(\d+)"
    + _DELIM
    + _SEV_ICON
    + r"High:\s*(\d+)"
    + _DELIM
    + _SEV_ICON
    + r"Medium:\s*(\d+)"
    + _DELIM
    + _SEV_ICON
    + r"Low:\s*(\d+)"
    # Optional Info cell (only rendered when count > 0). Captured into
    # group(5); the rest of the parser must treat None as 0.
    + r"(?:" + _DELIM + _SEV_ICON + r"Info:\s*(\d+))?"
    # Both `**Total: N**` and `**Total findings: N**` accepted.
    + _DELIM
    + r"\**Total(?:\s+findings)?:\s*(\d+)\**"
)
CODE_FENCE_RE = re.compile(r"^```", re.MULTILINE)


@dataclass
class Report:
    check: str
    ok: int = 0
    issues: list[str] = field(default_factory=list)
    fixes: list[str] = field(default_factory=list)
    # Non-blocking informational notes that are surfaced in the summary but
    # do NOT count toward issue totals or trigger the Re-Render Loop.
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "ok": self.ok,
            "issue_count": len(self.issues),
            "issues": self.issues,
            "fix_count": len(self.fixes),
            "fixes": self.fixes,
            "warning_count": len(self.warnings),
            "warnings": self.warnings,
        }


_HTML_PRE_BLOCK_RE = re.compile(r"<pre\b[^>]*>.*?</pre>", re.DOTALL)


def _strip_code_fences(text: str) -> str:
    """Return ``text`` with fenced code blocks blanked out (same length).

    Strips both Markdown fenced blocks (``` … ```)
    and HTML ``<pre>…</pre>`` blocks. The §8 Findings Register Story-Card layout
    embeds evidence snippets as ``<pre><code>…</code></pre>`` (Markdown fences
    do not survive inside table cells), and downstream checks that scan for
    placeholders / rhetorical phrasing / etc. must not flag literal source
    code inside those snippets as document drift.

    The ``<pre>`` strip is **content-only** — surrounding text on the same
    line (e.g. the row anchor ``<a id="f-001">…</a>`` declared before the
    ``<pre>``) is preserved so anchor-based cross-references continue to
    resolve. Pre-2026-05 the snippets were always on dedicated lines, so a
    whole-line blanking was safe; the Story-Card layout puts ``<pre>…</pre>``
    inside the table-row line, which we must NOT blank wholesale.
    """
    # Step 1 — blank <pre>…</pre> content while preserving line slots. Any
    # internal `\n` becomes empty so line numbers stay aligned; surrounding
    # text on the same line is kept.
    def _blank_pre(m: re.Match[str]) -> str:
        inner = m.group(0)
        # Replace each newline with a real newline (preserve line count) and
        # every other char with empty so the slot is structurally there but
        # invisible to text-scanning checks. We keep only the opening "<pre"
        # token visually marked so downstream checks that explicitly want to
        # see a pre tag continue to do so without consuming content.
        return "\n" * inner.count("\n")
    text = _HTML_PRE_BLOCK_RE.sub(_blank_pre, text)

    # Step 2 — original Markdown fenced-block stripping (line-based).
    out: list[str] = []
    in_md_fence = False
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith("```"):
            in_md_fence = not in_md_fence
            out.append(line)
            continue
        if in_md_fence:
            out.append("\n" if line.endswith("\n") else "")
        else:
            out.append(line)
    return "".join(out)


# ---------------------------------------------------------------------------
# Pre-pass cache — shared input artifacts for the `all` subcommand.
#
# Earlier versions of this module re-read ``threat-model.md``, re-stripped
# code fences in 8 different checks, and re-loaded
# ``sections-contract.yaml`` 3× per `all` invocation. On a 90 KB document
# with ~15 active checks that's ~12 redundant file reads + ~8 redundant
# fence strips per QA pass.
#
# The cache below is module-level so a single ``all`` invocation re-uses
# the same parsed artifacts across every check function call. Individual
# check functions still accept the ``md_path`` parameter for backward
# compatibility (CLI subcommands continue to work standalone), but when
# ``_PrePass`` is primed they short-circuit through the cache.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Fast YAML loading
#
# PyYAML's pure-Python SafeLoader parses the ~90 KB ``threat-model.yaml`` in
# ~200 ms; libyaml's C loader (``CSafeLoader``) does it in ~20 ms. The QA
# ``repair_plan``/``all`` batteries parse that file 2–4× per run, so routing
# every parse through the C loader removes ~0.4–0.8 s of pure-Python YAML
# work per QA pass — the dominant cost on both paths. Output is identical for
# the safe subset these documents use; ``SafeLoader`` is the fallback when a
# PyYAML build lacks the libyaml extension.
# ---------------------------------------------------------------------------
_YAML_LOADER = None  # resolved lazily on first load


def _fast_yaml_load(text: str):
    global _YAML_LOADER
    import yaml as _yaml

    if _YAML_LOADER is None:
        _YAML_LOADER = getattr(_yaml, "CSafeLoader", _yaml.SafeLoader)
    return _yaml.load(text, Loader=_YAML_LOADER)


class _PrePass:
    """Shared, lazy-loaded artifacts for the QA `all` subcommand.

    Reset between `all` invocations via ``_PrePass.reset()``. Individual
    check functions consult this cache via the helper accessors
    ``_get_text(path)`` / ``_get_cleaned(path)`` / ``_get_contract(path)``
    rather than calling ``read_text()`` / ``_strip_code_fences()`` /
    ``yaml.safe_load()`` themselves. Cache hits are O(1).
    """

    _md_path: Path | None = None
    _md_text: str | None = None
    _md_cleaned: str | None = None
    _contract_path: Path | None = None
    _contract: dict | None = None

    @classmethod
    def reset(cls) -> None:
        cls._md_path = None
        cls._md_text = None
        cls._md_cleaned = None
        cls._contract_path = None
        cls._contract = None

    @classmethod
    def text(cls, md_path: Path) -> str:
        if cls._md_path != md_path or cls._md_text is None:
            cls._md_path = md_path
            cls._md_text = md_path.read_text(encoding="utf-8")
            cls._md_cleaned = None  # invalidate dependent cache
        return cls._md_text

    @classmethod
    def cleaned(cls, md_path: Path) -> str:
        # Ensure raw text is loaded; recompute cleaned-text only when the
        # raw text changed (or on first access).
        cls.text(md_path)
        if cls._md_cleaned is None:
            cls._md_cleaned = _strip_code_fences(cls._md_text or "")
        return cls._md_cleaned

    @classmethod
    def contract(cls, contract_path: Path) -> dict:
        if cls._contract_path != contract_path or cls._contract is None:
            cls._contract_path = contract_path
            import yaml as _yaml  # local — qa_checks doesn't import yaml at module scope

            try:
                cls._contract = _fast_yaml_load(contract_path.read_text(encoding="utf-8")) or {}
            except (OSError, _yaml.YAMLError):
                cls._contract = {}
            # schema_v2 — when active (.skill-config.json carries
            # `security_schema: v2`), swap the §7 contract surface with the
            # v2 layout/rules so downstream checks validate the rendered MD
            # against the current security-architecture model. The swap is
            # in-memory only; the YAML file on disk keeps both surfaces.
            cls._apply_schema_v2_overlay()
        return cls._contract

    @classmethod
    def _apply_schema_v2_overlay(cls) -> None:
        """Swap security_architecture §7 contract fields → schema_v2 fields
        when the active config selects v2 (default since 2026-05). Reads
        the schema from (in order):
          1. `APPSEC_SECURITY_SCHEMA` env-var (smoke-test / forced override)
          2. `.skill-config.json` next to the current MD
          3. default: v2
        Set `APPSEC_SCHEMA_V1=1` (or `APPSEC_SECURITY_SCHEMA=v1`) to
        keep the legacy 14-section layout — useful when QA-checking a
        threat-model that was rendered before the 2026-05 v2 default
        flip and has not yet been re-rendered.
        """
        if not isinstance(cls._contract, dict):
            return
        import os as _os
        # 1. Explicit env override wins (CI / smoke tests).
        schema = (_os.environ.get("APPSEC_SECURITY_SCHEMA") or "").strip().lower()
        if not schema and _os.environ.get("APPSEC_SCHEMA_V1", "").strip() in (
            "1", "true", "yes", "on"
        ):
            schema = "v1"
        # 2. Skill-config next to MD.
        if not schema and cls._md_path is not None:
            cfg = cls._md_path.parent / ".skill-config.json"
            if cfg.is_file():
                try:
                    import json as _json
                    cfg_data = _json.loads(cfg.read_text(encoding="utf-8"))
                    schema = (cfg_data.get("security_schema") or "").strip().lower()
                except (OSError, ValueError):
                    schema = ""
        # 3. Default — v2 since 2026-05.
        if schema not in {"v1", "v2"}:
            schema = "v2"
        if schema != "v2":
            return
        sec = (cls._contract.get("sections") or {}).get("security_architecture")
        if not isinstance(sec, dict):
            return
        v2 = sec.get("schema_v2") or {}
        v2_subs = v2.get("required_subsections")
        if isinstance(v2_subs, list) and v2_subs:
            sec["required_subsections"] = v2_subs
            # Drop v1 cross-cutting subsection patterns (those headings
            # are not part of the v2 §7 control-category model).
            sec["required_subsection_patterns"] = []
        v2_domain_patterns = v2.get("domain_required_patterns")
        if isinstance(v2_domain_patterns, dict):
            sec["domain_required_patterns"] = v2_domain_patterns
        v2_rules = v2.get("domain_required_rules")
        if isinstance(v2_rules, dict):
            sec["domain_required_rules"] = v2_rules


def _read_md(md_path: Path) -> str:
    """Read ``md_path`` once per `all` invocation via the pre-pass cache."""
    return _PrePass.text(md_path)


def _read_md_cleaned(md_path: Path) -> str:
    """Return the document with code fences stripped, cached."""
    return _PrePass.cleaned(md_path)


def _read_contract(contract_path: Path) -> dict:
    """Load ``sections-contract.yaml`` once per `all` invocation."""
    return _PrePass.contract(contract_path)


def check_links(md_path: Path, repo_root: Path) -> tuple[Report, str]:
    report = Report("links")
    text = md_path.read_text(encoding="utf-8")
    new_text = text
    seen: set[str] = set()
    for m in VSCODE_LINK_RE.finditer(text):
        raw_path = m.group(1)
        line_no = m.group(2)
        key = f"{raw_path}:{line_no or ''}"
        if key in seen:
            continue
        seen.add(key)
        candidates = [Path(raw_path)]
        if not Path(raw_path).is_absolute():
            candidates.append(repo_root / raw_path)
            # `vscode://file/home/...` is emitted by some renderers without
            # the double slash — recover the absolute path by prefixing `/`.
            candidates.append(Path("/" + raw_path))
        if any(c.exists() for c in candidates):
            report.ok += 1
            continue
        # Attempt basename-based repair.
        basename = os.path.basename(raw_path)
        matches = [
            p
            for p in repo_root.rglob(basename)
            if not any(part in {"node_modules", ".git", "vendor", "dist", "build"} for part in p.parts)
        ]
        if len(matches) == 1:
            new_abs = str(matches[0].resolve())
            new_link = f"vscode://file/{new_abs}"
            if line_no:
                old_link = f"vscode://file/{raw_path}:{line_no}"
                new_link_with_line = f"{new_link}:{line_no}"
                new_text = new_text.replace(old_link, new_link_with_line)
            else:
                new_text = new_text.replace(f"vscode://file/{raw_path}", new_link)
            report.fixes.append(f"repaired: {raw_path} -> {new_abs}")
        elif len(matches) > 1:
            report.issues.append(f"ambiguous: {basename} has {len(matches)} candidates")
        else:
            report.issues.append(f"missing: {raw_path}")
    return report, new_text


def check_xrefs(md_path: Path) -> Report:
    report = Report("xrefs")
    text = _read_md(md_path)
    stripped = _read_md_cleaned(md_path)
    t_ids = {f"T-{m.group(1).zfill(3)}" for m in T_ID_RE.finditer(stripped)}
    m_ids = {f"M-{m.group(1).zfill(3)}" for m in M_ID_RE.finditer(stripped)}
    # Mitigation headings define authoritative M-NNN set.
    defined_m = {f"M-{n.zfill(3)}" for n in H3_MITIGATION_RE.findall(text)}
    # Threat register row IDs define authoritative T-NNN set.
    defined_t = set()
    for match in TABLE_ID_RE.finditer(text):
        raw = match.group(1)
        if raw.startswith("T-"):
            defined_t.add(f"T-{raw.split('-')[1].zfill(3)}")
    orphan_m = sorted(m_ids - defined_m) if defined_m else []
    orphan_t = sorted(t_ids - defined_t) if defined_t else []
    for mid in orphan_m:
        report.issues.append(f"orphaned-mitigation-ref: {mid} referenced but no heading")
    for tid in orphan_t:
        report.issues.append(f"orphaned-threat-ref: {tid} referenced but no Findings Register row")
    report.ok = len(t_ids) + len(m_ids) - len(report.issues)
    return report


def _lowercase_anchor(prefix: str, num: str) -> str:
    return f"{prefix.lower()}-{num.zfill(3)}"


def _inject_row_anchors(lines: list[str]) -> tuple[list[str], int]:
    """Inject `<a id="t-nnn"></a>` / `<a id="m-nnn"></a>` anchors into Threat
    Register table rows and Mitigation headings so cross-links have valid targets.

    Returns (modified_lines, count_of_injections).
    """
    injected = 0
    in_fence = False
    in_section_8 = False
    in_section_10 = False
    for i, line in enumerate(lines):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if line.startswith("## "):
            in_section_8 = "8." in line[:10] or line.startswith("## 8 ")
            in_section_10 = "10." in line[:12] or line.startswith("## 10 ")
        # Findings Register rows: inject <a id="t-nnn"></a> before T-NNN
        if in_section_8 and line.startswith("|"):
            m = re.match(r"^(\|\s*)(T-(\d{3,4}))(\s*\|)", line)
            if m and '<a id="t-' not in line:
                tid_lower = f"t-{m.group(3).zfill(3)}"
                anchor = f'<a id="{tid_lower}"></a>'
                lines[i] = f"{m.group(1)}{anchor} {m.group(2)}{line[m.end(2) :]}"
                injected += 1
        # Mitigation headings: inject <a id="m-nnn"></a> before ### M-NNN
        if (in_section_10 or line.startswith("### ")) and not in_section_8:
            m = re.match(r"^(###\s+)(M-(\d{3,4}))\b", line)
            if m and '<a id="m-' not in line:
                mid_lower = f"m-{m.group(3).zfill(3)}"
                anchor = f'<a id="{mid_lower}"></a>'
                lines[i] = f"{m.group(1)}{anchor} {m.group(2)}{line[m.end(2) :]}"
                injected += 1
    return lines, injected


def _load_label_index(md_path: Path) -> dict[str, tuple[str, str]]:
    """Read sibling ``threat-model.yaml`` and build a {ID: short label} map.

    Used by ``linkify_anchors`` so that bare ``T-NNN`` / ``M-NNN`` references
    are converted directly to the canonical ``[ID](#id) — Label`` shape in a
    single pass (instead of leaving them as bare links for the compose-time
    label injector to find — which never re-runs after this step).

    Mitigations: accept both ``title`` (canonical) and ``mitigation_title``
    (legacy STRIDE-schema field) so transitional yamls still produce
    labelled links. Returns an empty dict when the yaml is absent or
    unparseable; the caller falls back to bare-link behaviour.
    """
    yaml_path = md_path.with_name("threat-model.yaml")
    if not yaml_path.is_file():
        return {}
    try:
        import yaml as _yaml

        data = _fast_yaml_load(yaml_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    # The index doubles as an alias map: {ID: (label, canonical_anchor)}.
    # canonical_anchor lets the linkifier emit `[T-001](#f-001) — Title`
    # (T-text routed to the F-anchor where the actual content lives) instead
    # of `[T-001](#t-001)` which has no target on rows where the row-anchor
    # injection skipped the T-alias. Keys are ALL aliases (canonical id +
    # original_id legacy id + F-NNN-by-numeric-suffix). Backwards-compat:
    # callers expecting a plain {ID: label} dict still see the same labels —
    # just an extra tuple unwrap.
    idx: dict[str, tuple[str, str]] = {}
    for t in data.get("threats", []) or []:
        if not isinstance(t, dict):
            continue
        tid = (t.get("t_id") or t.get("id") or "").strip().upper()
        if not tid:
            continue
        label = (t.get("title") or t.get("scenario_short") or "").strip()
        if not label:
            continue
        # Escape unescaped `$` so a `$where`-style title cannot open a KaTeX
        # math span when this label is re-emitted into a `— <title>` xref.
        label = re.sub(r"(?<!\\)\$", r"\\$", label)
        canonical_anchor = tid.lower()
        idx[tid] = (label, canonical_anchor)
        # F-NNN alias: every T-NNN threat is dual-anchored as `<a id="t-NNN">`
        # AND `<a id="f-NNN">` in the rendered §8 (same numeric suffix). Add
        # the F-alias so `[F-001](#f-001)` references in prose / tables /
        # bullet lists pick up the same title — closes the historical
        # half-coverage where F-NNN cross-refs (Mgmt Summary, §9 Addresses,
        # §5 Attack Surface) shipped without a `— Title` suffix.
        m_num = re.match(r"T-(\d+)$", tid)
        if m_num:
            f_alias = f"F-{m_num.group(1)}"
            # Don't overwrite an explicit F-NNN entry if one was authored.
            idx.setdefault(f_alias, (label, f"f-{m_num.group(1).zfill(3)}"))
        # Also map the legacy original_id (typically T-NNN) to the SAME
        # canonical anchor — so `T-001` references in prose translate to
        # `[T-001](#f-001) — Title`, where #f-001 is the row anchor that
        # actually exists in the rendered MD.
        oid = (t.get("original_id") or "").strip().upper()
        if oid and oid != tid:
            idx[oid] = (label, canonical_anchor)
    for m in data.get("mitigations", []) or []:
        if not isinstance(m, dict):
            continue
        mid = (m.get("m_id") or m.get("id") or "").strip().upper()
        if mid:
            label = (m.get("title") or m.get("mitigation_title") or m.get("name") or "").strip()
            if label:
                label = re.sub(r"(?<!\\)\$", r"\\$", label)
                idx[mid] = (label, mid.lower())
    return idx


# Pattern that matches the §8 / §7.2-style declaration line for a TH-NN
# threat-class anchor + its short title. The renderer writes one of the
# two forms below per category — the regex covers both:
#
#   `| <a id="th-01"></a>TH-01 — Injection | …`           (table cell)
#   `<a id="th-01"></a>TH-01 — Injection`                 (heading prose)
#
# Captured: (1) zero-padded numeric suffix, (2) human-readable title.
TH_DECL_RE = re.compile(r'<a\s+id="(th-\d{2,3})"\s*></a>\s*TH-\d{2,3}\s*[—–-]\s*([^|<\n]+?)(?=\s*[|<\n])')


def _load_th_label_index(md_text: str) -> dict[str, tuple[str, str]]:
    """Parse threat-class titles from rendered §8 / §7.2 prose.

    TH-NN labels do not live in `threat-model.yaml` — they are emitted by
    the renderer from `data/threat-class-taxonomy.yaml` (a plugin-internal
    catalogue) and only appear as `<a id="th-NN"></a>TH-NN — <Title>` in the
    rendered Markdown. To linkify bare TH-NN references with a `— <Title>`
    suffix, we read the labels back out of §8 itself. This is the same
    same-document round-trip pattern that the row-anchor injector uses.

    Returns ``{TH-NN: (Title, anchor)}`` keyed by the upper-case TH-NN form.
    Empty dict if no declarations found — caller falls back to bare-link
    behaviour without a — Label suffix.
    """
    idx: dict[str, tuple[str, str]] = {}
    for m in TH_DECL_RE.finditer(md_text):
        anchor = m.group(1).lower()
        title = m.group(2).strip()
        if not title:
            continue
        # Reconstruct the original TH-NN form from the anchor (th-01 → TH-01).
        suffix = anchor.split("-", 1)[1]
        key = f"TH-{suffix}"
        # Don't overwrite the first declaration found — multiple identical
        # declarations are tolerated, drift between them is not.
        idx.setdefault(key, (title, anchor))
    return idx


def linkify_anchors(md_path: Path) -> tuple[Report, str]:
    report = Report("anchors")
    text = md_path.read_text(encoding="utf-8")
    # Track fence state line-by-line so we skip code blocks.
    lines = text.splitlines(keepends=True)

    # Build a label index from the sibling yaml so we emit
    # `[ID](#id) — Label` in one pass.  Empty dict ⇒ legacy bare-link
    # behaviour (never breaks the call site if yaml is missing).
    label_idx = _load_label_index(md_path)
    # Merge the TH-NN label index parsed from the rendered MD itself —
    # TH-NN titles live in §8 / §7.2 declarations, not in the yaml.
    # Same {ID: (label, anchor)} shape so the suffix logic below stays
    # uniform across all four ID classes.
    th_idx = _load_th_label_index(text)
    for k, v in th_idx.items():
        label_idx.setdefault(k, v)

    # Pass 1: inject destination anchors into table rows and headings
    lines, anchor_count = _inject_row_anchors(lines)
    if anchor_count:
        report.fixes.append(f"injected {anchor_count} row/heading anchors")

    # Pass 2: linkify bare T-NNN / M-NNN references
    in_fence = False
    in_section_8 = False
    in_toc = False
    for i, line in enumerate(lines):
        stripped_lstrip = line.lstrip()
        if stripped_lstrip.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if line.startswith("## "):
            in_section_8 = line.startswith("## 8.") or line.startswith("## 8 ")
            # Track Table of Contents section to avoid linkifying bare T-NNN /
            # M-NNN references inside TOC list items — those bare IDs are part
            # of the TOC link label text and must remain as plain text. If they
            # were linkified they would create nested `[T-001](#t-001)` inside
            # the outer `[3.2 T-001 — ...](#slug)` TOC link, breaking rendering.
            in_toc = "Table of Contents" in line
        # Exit TOC when we hit the next top-level `## ` section that is not TOC.
        elif in_toc and line.startswith("## "):
            in_toc = False
        if in_toc:
            continue
        # Skip the Findings Register ID-column rows in Section 8 — they are anchor sources.
        if in_section_8 and line.startswith("|") and re.search(r"^\|\s*(?:<a id=\"t-\d+\"></a>)?\s*T-\d+\s*\|", line):
            continue
        # Skip ALL Markdown heading lines (## / ### / #### / …). Headings are
        # rendered as `<a id="…"></a>\n#### TH-01 — Title` (anchor on its own
        # line above the heading) — the heading text itself must NOT be
        # linkified, because in-heading links break right-side TOC outlines
        # AND trigger heading_hygiene's `[…]([…]) — <text>` rule.
        if stripped_lstrip.startswith("#"):
            continue
        new_line = line

        def _labelled(full: str, fallback_anchor: str) -> str:
            """Build `[ID](#anchor) — Label` when the YAML index has an entry
            for this ID, else `[ID](#fallback_anchor)`.

            When ``label_idx`` returns ``(label, canonical_anchor)``, the link
            target is ``canonical_anchor`` — this is how a bare ``T-001`` in
            prose gets routed to ``#f-001`` (the row anchor that actually
            exists in the rendered MD), avoiding tombstone links to
            non-existent ``#t-001`` anchors on rows where the row-injector
            skipped the T-alias.
            """
            entry = label_idx.get(full.upper())
            if entry:
                label, anchor = entry
                return f"[{full}](#{anchor}) — {label}"
            return f"[{full}](#{fallback_anchor})"

        # Linkify bare T-NNN not already part of a link or an anchor.
        # Post-2026-05-05: when the bare reference is immediately followed
        # by " — " (em-dash space), the author already wrote a description
        # on the same line — don't inject the YAML title because that
        # produces a doubled `[T-NNN](#t-nnn) — <yaml-title> — <author-text>`
        # pattern (observed in §3.x walkthrough headers `**Threat:** T-NNN
        # — <short>`).
        def sub_t(match: re.Match[str]) -> str:
            full = match.group(0)
            start = match.start()
            prefix = new_line[max(0, start - 2) : start]
            suffix = new_line[match.end() : match.end() + 2]
            if prefix.endswith("[") or suffix.startswith("]("):
                return full
            if '<a id="t-' in new_line[max(0, start - 30) : start + 10]:
                return full
            # Author-supplied em-dash description follows → just hyperlink,
            # don't inject YAML title.
            tail = new_line[match.end() : match.end() + 5]
            if tail.startswith(" — "):
                return f"[{full}](#{_lowercase_anchor('T', match.group(1))})"
            return _labelled(full, _lowercase_anchor("T", match.group(1)))

        def sub_m(match: re.Match[str]) -> str:
            full = match.group(0)
            start = match.start()
            prefix = new_line[max(0, start - 2) : start]
            suffix = new_line[match.end() : match.end() + 2]
            if prefix.endswith("[") or suffix.startswith("]("):
                return full
            if '<a id="m-' in new_line[max(0, start - 30) : start + 10]:
                return full
            tail = new_line[match.end() : match.end() + 5]
            if tail.startswith(" — "):
                return f"[{full}](#{_lowercase_anchor('M', match.group(1))})"
            return _labelled(full, _lowercase_anchor("M", match.group(1)))

        def sub_f(match: re.Match[str]) -> str:
            """Linkify bare F-NNN — symmetric with sub_t. F-NNN is the
            user-visible label form for threats; the F-anchor is what §8
            actually emits as a row anchor. Skip when already inside a
            link or directly after an F-anchor declaration on the same
            line, and respect the author-supplied em-dash convention.
            """
            full = match.group(0)
            start = match.start()
            prefix = new_line[max(0, start - 2) : start]
            suffix = new_line[match.end() : match.end() + 2]
            if prefix.endswith("[") or suffix.startswith("]("):
                return full
            if '<a id="f-' in new_line[max(0, start - 30) : start + 10]:
                return full
            tail = new_line[match.end() : match.end() + 5]
            if tail.startswith(" — "):
                return f"[{full}](#{_lowercase_anchor('F', match.group(1))})"
            return _labelled(full, _lowercase_anchor("F", match.group(1)))

        def sub_th(match: re.Match[str]) -> str:
            """Linkify bare TH-NN. Anchor target is `#th-NN` (zero-padded
            two-digit suffix). The label index is populated from §8 prose
            (see `_load_th_label_index`); when a TH-NN is referenced before
            §8 is parsed (rare — only happens in pre-§8 prose like the
            Mgmt Summary), fall back to a bare link without a — suffix.
            """
            full = match.group(0)
            start = match.start()
            prefix = new_line[max(0, start - 2) : start]
            suffix = new_line[match.end() : match.end() + 2]
            if prefix.endswith("[") or suffix.startswith("]("):
                return full
            if '<a id="th-' in new_line[max(0, start - 30) : start + 10]:
                return full
            tail = new_line[match.end() : match.end() + 5]
            anchor = f"th-{match.group(1).zfill(2)}"
            if tail.startswith(" — "):
                return f"[{full}](#{anchor})"
            return _labelled(full, anchor)

        new_line = T_ID_RE.sub(sub_t, new_line)
        new_line = M_ID_RE.sub(sub_m, new_line)
        new_line = F_ID_RE.sub(sub_f, new_line)
        new_line = TH_ID_RE.sub(sub_th, new_line)

        # Idempotent label-suffix pass: refs that were already linkified by
        # an upstream pass (e.g. ``compose_threat_model._linkify_bare_refs_in_prose``)
        # but lack the ``— Label`` suffix get one appended here.  The negative
        # lookahead ``(?! — )`` prevents double-labelling on re-runs.
        # Covers all four cross-reference ID classes (F, T, M, TH) by
        # accepting any matching anchor target ``#(?:th|[ftm])-N``.
        # The F-NNN inclusion is what closes the historical half-coverage
        # where Mgmt Summary / §9 Addresses / §5 Attack Surface shipped
        # `[F-001](#f-001)` without a `— Title` suffix.
        if label_idx:

            def sub_existing(match: re.Match[str]) -> str:
                ref = match.group(1).upper()
                entry = label_idx.get(ref)
                if not entry:
                    return match.group(0)
                # Isolated-cell guard: skip enrichment when the matched link
                # occupies an entire table cell on its own (`| [ID](#id) |`).
                # That layout is used by definition tables (§6 Mitigations,
                # §9 Mitigation Register) where the next column carries the
                # title — appending ` — <label>` here produces a double-title
                # because the rendered row would read `[M-001](#m-001) — Foo
                # | Foo | …`. Cells with multiple links or surrounding prose
                # are still enriched (pre/post don't both bracket with `|`).
                pre = new_line[max(0, match.start() - 3) : match.start()]
                post = new_line[match.end() : match.end() + 3]
                if pre.endswith("| ") and post.startswith(" |"):
                    return match.group(0)
                label, _ = entry
                return f"{match.group(0)} — {label}"

            # Two patterns because F/T/M ids are 3-4 digits while TH-NN
            # is 2-3 digits; one combined regex would lose the digit-count
            # distinction. Keep them separate for clarity + idempotency.
            #
            # Lookahead `(?!\s+[—(])` skips refs already followed by either
            # em-dash form (`[ID](#id) — Label`) OR parens form
            # (`[ID](#id) (short_label)` — produced by
            # `compose._linkify_bare_refs_in_prose` via
            # `linkify_with_short_label`). Without the `(` exclusion the
            # pass appends `— full_title — file` between the link and the
            # existing parens, producing the duplicate-title form
            # `[F-001](#f-001) — Title — file (Title)` flagged by
            # `check_section7_finding_link_duplicate`.
            new_line = re.sub(
                r"\[([FTM]-\d{3,4})\]\(#[ftm]-\d+\)(?!\s+[—(])",
                sub_existing,
                new_line,
            )
            new_line = re.sub(
                r"\[(TH-\d{2,3})\]\(#th-\d+\)(?!\s+[—(])",
                sub_existing,
                new_line,
            )

        if new_line != line:
            diff_count = (
                new_line.count("](#t-")
                - line.count("](#t-")
                + new_line.count("](#m-")
                - line.count("](#m-")
                + new_line.count("](#f-")
                - line.count("](#f-")
                + new_line.count("](#th-")
                - line.count("](#th-")
            )
            label_count = new_line.count(") — ") - line.count(") — ")
            parts = []
            if diff_count:
                parts.append(f"+{diff_count} cross-links")
            if label_count:
                parts.append(f"+{label_count} labels")
            if parts:
                report.fixes.append(f"line {i + 1}: " + ", ".join(parts))
        lines[i] = new_line
    new_text = "".join(lines)
    return report, new_text


# Operational Strengths is reserved for *architectural* strengths. Tactical
# baseline hygiene (HTTP response-header hardening, single-line middleware
# without a meaningful architectural commitment) must not appear there.
# Match against the row's first column (the canonical control name) — the
# row body sometimes mentions helmet to give context, that alone is OK.
_STRENGTHS_FORBIDDEN_CONTROL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bHTTP\s+Security\s+Headers\b", re.IGNORECASE),
    re.compile(r"\bResponse\s+Headers?\b", re.IGNORECASE),
    re.compile(r"\bSecurity\s+Headers?\b", re.IGNORECASE),
    re.compile(r"\bHelmet\b", re.IGNORECASE),
    re.compile(r"\bX-Frame-Options\b", re.IGNORECASE),
    re.compile(r"\bX-Content-Type-Options\b", re.IGNORECASE),
    re.compile(r"\bReferrer-Policy\b", re.IGNORECASE),
    re.compile(r"\bPermissions-Policy\b", re.IGNORECASE),
    re.compile(r"\bHSTS\b"),  # case-sensitive — avoid matching "hosts"
    re.compile(r"\bStrict-Transport-Security\b", re.IGNORECASE),
)


def check_strengths_row_quality(md_path: Path) -> Report:
    """Flag Operational Strengths rows that name tactical baseline hygiene
    (HTTP response-header hardening, etc.) instead of architectural
    strengths. The renderer filters these out via `excluded_from_strengths`
    in `architectural-controls.yaml`, but an LLM-authored override or a
    legacy fragment could still slip them in.
    """
    report = Report(check="strengths_row_quality")
    text = md_path.read_text(encoding="utf-8")
    # Locate the Operational Strengths section body.
    sec_start = text.find("### Operational Strengths")
    if sec_start == -1:
        report.ok = 1
        return report
    # End the section at the next `## ` or `### ` heading.
    rest = text[sec_start + len("### Operational Strengths"):]
    m = re.search(r"\n#{2,3}\s", rest)
    body = rest[: m.start()] if m else rest
    flagged = 0
    for line_no, line in enumerate(body.splitlines(), start=1):
        if not line.startswith("|"):
            continue
        # Skip the header row and the separator row.
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not cells or cells[0].lower().startswith(("architectural control", "strength", "control", "---")):
            continue
        if all(set(c) <= set("-:") for c in cells):  # markdown separator
            continue
        control_cell = cells[0]
        for pat in _STRENGTHS_FORBIDDEN_CONTROL_PATTERNS:
            if pat.search(control_cell):
                report.issues.append(
                    f"Operational Strengths row names tactical baseline "
                    f"hygiene (`{control_cell[:60]}`) instead of an "
                    f"architectural strength — drop this row. HTTP-header "
                    f"hardening is filtered by `excluded_from_strengths` "
                    f"in architectural-controls.yaml; do not override "
                    f"without architectural justification."
                )
                flagged += 1
                break
        if flagged >= 25:
            break
    if not flagged:
        report.ok = 1
    return report


def check_unmasked_secrets(md_path: Path, output_dir: Path | None = None) -> Report:
    """Hard QA gate — scan rendered artifacts for raw, unmasked secrets.

    Scans ``threat-model.md`` (always) plus ``threat-model.yaml`` (when an
    ``output_dir`` is given and the file exists). A hit blocks release.

    Masked values (``AIza****``, ``**** (12 chars)``, ``[REDACTED]``) are
    skipped — see ``scripts/secret_scan.py`` for the marker list.
    """
    report = Report(check="unmasked_secrets")
    targets: list[Path] = [md_path]
    if output_dir is not None:
        yaml_path = output_dir / "threat-model.yaml"
        if yaml_path.exists():
            targets.append(yaml_path)
    for target in targets:
        for hit in _scan_file_for_secrets(target):
            report.issues.append(
                f"{target.name}: {hit.render()} — mask the value "
                "(tokens: first 4 chars + ****; passwords: **** plus length only)"
            )
    if not report.issues:
        report.ok = 1
    return report


def check_unfounded_perimeter_claims(md_path: Path) -> Report:
    """Flag unfounded claims that a deployment-time / runtime-environment
    control is absent. A source-tree scan has no signal on whether a WAF,
    network firewall, IDS/IPS, API gateway, DDoS protection, secret scanning
    service, database activity monitoring, EDR/SIEM, or reverse proxy exists
    in front of the deployed application. Statements about their **absence**
    are therefore unfounded and must be reworded or removed. Positive
    identification (the repo configures or references one) is allowed and not
    flagged here.
    """
    report = Report(check="unfounded_perimeter_claims")
    text = md_path.read_text(encoding="utf-8")
    # Skip code fences — instructional examples inside fenced YAML/Markdown
    # blocks aren't user-facing prose.
    cleaned = _strip_code_fences(text)
    flagged: list[tuple[int, str, str]] = []
    for line_no, line in enumerate(cleaned.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("<!--"):
            continue
        for token, pat in _PERIMETER_ABSENCE_PATTERNS:
            if pat.search(line):
                flagged.append((line_no, token, stripped[:140]))
                break
    for line_no, token, snippet in flagged[:25]:
        report.issues.append(
            f"unfounded {token}-absence claim at line {line_no}: `{snippet}` — "
            f"source-tree scan cannot verify deployment-time perimeter controls; "
            f"mention only when positively configured in the repo."
        )
    if len(flagged) > 25:
        report.issues.append(f"…and {len(flagged) - 25} more unfounded perimeter-absence claims (truncated)")
    if not flagged:
        report.ok = 1
    return report


def check_invariants(md_path: Path) -> Report:
    report = Report("invariants")
    # The numeric Risk-Distribution / STRIDE-Coverage / §8 heading-count
    # invariants that used to run here are guaranteed by construction: the
    # composer renders all three from one `threats[]` grouping
    # (compose_threat_model.py -> _render_threat_register) and the output-schema
    # gate enums `stride`/`risk` before Stage 2, so a mismatch is unreachable.
    # They are pinned by a compose unit test instead. Only the PHASE_BURST log
    # diagnostic below remains live.

    # F4 — PHASE_BURST detection (moved here from phase-group-architecture.md
    # auto-repair block, which is skipped on inline-shortcut runs). Inspects
    # .agent-run.log for PHASE_START lines that share the same timestamp.
    # Legal inline batch: phases {4,5,6,7} (Attack Walkthroughs, Asset
    # Identification, Attack Surface Mapping, Trust Boundary Analysis —
    # authored together by the orchestrator in a single turn since 2026-05).
    # A burst that includes ANY phase outside that set, or grows beyond 4
    # phases, is a contract violation (look-ahead logging — see 2026-04-25
    # Run 1 where the orchestrator emitted PHASE_STARTs for Phases 3-8 in a
    # single second before doing any work).
    _LEGAL_INLINE_BURST = frozenset({"4", "5", "6", "7"})
    output_dir = md_path.parent
    agent_log = output_dir / ".agent-run.log"
    if agent_log.is_file():
        try:
            log_text = agent_log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            log_text = ""
        from collections import Counter

        ts_counts: Counter = Counter()
        for line in log_text.splitlines():
            if "PHASE_START" not in line:
                continue
            m = re.search(r"\[Phase ([3-8])/11\]", line)
            if not m:
                continue
            ts = line.split()[0] if line.split() else ""
            if ts:
                ts_counts[(ts, m.group(1))] += 1
        # Build a per-timestamp set of distinct phases that opened at it.
        per_ts: dict[str, set[str]] = {}
        for (ts, phase), _n in ts_counts.items():
            per_ts.setdefault(ts, set()).add(phase)
        for ts, phases in per_ts.items():
            # Legal: every burst phase is in {4,5,6,7} AND the burst stays
            # within that set (≤4 distinct phases). Anything else flags.
            if phases.issubset(_LEGAL_INLINE_BURST) and len(phases) <= 4:
                continue
            if len(phases) > 3:
                report.issues.append(
                    f"PHASE_BURST at {ts}: {len(phases)} distinct PHASE_START lines "
                    f"(phases {sorted(phases)}) — only {{4,5,6,7}} may legally share a "
                    f"timestamp; this is look-ahead logging (contract violation, "
                    f"makes silent-death diagnosis impossible)."
                )

    if not report.issues:
        report.ok = 1
    return report


# ---------------------------------------------------------------------------
# Management Summary structural check
# ---------------------------------------------------------------------------

# Required sub-section headings inside `## Management Summary`, in this exact
# order. Anything else (numbered, renamed, missing, reordered) is a structural
# defect the renderer must fix before releasing the file.
_MS_REQUIRED_SUBSECTIONS: tuple[str, ...] = (
    "Verdict",
    "Security Posture & Top Threats",
    "Top Mitigations",
    "Operational Strengths",
)

# Forbidden MS sub-section heading patterns — these were observed in drifted
# outputs (numbered 1.1–1.5 layout, legacy section names). We only flag; the
# auto-repair here is limited to stripping numeric prefixes off otherwise
# canonical headings. Full semantic rebuilds remain a regenerate-and-rerun
# decision (too destructive to do silently).
_NUMBERED_PREFIX_RE = re.compile(r"^(#{2,4})\s+\d+(?:\.\d+)?\s+(.+?)\s*$")

_MS_HEADING_RE = re.compile(r"^(#{2,4})\s+(.+?)\s*$")
_MS_TOP_HEADING_RE = re.compile(r"^##\s+(?:\d+\.\s*)?Management Summary\s*$", re.MULTILINE)
_SECTION_BOUNDARY_RE = re.compile(r"^##\s+(?!Management Summary)", re.MULTILINE)
_VERDICT_BLOCKQUOTE_RE = re.compile(
    r"<blockquote\s+style=\"[^\"]*border-left:\s*3px\s+solid\s+#dc2626[^\"]*\"",
    re.IGNORECASE,
)
# Matches the unnumbered promoted block above §1. Accepts both the canonical
# `## Critical Attack Tree` heading (post-2026-05 hybrid migration) and the
# legacy `## Critical Attack Chain` heading (auto-renamed by the QA reviewer).
_CRITICAL_CHAIN_RE = re.compile(r"^##\s+Critical Attack (?:Tree|Chain)\s*$", re.MULTILINE)


def _slice_management_summary(text: str) -> tuple[int, int, str] | None:
    """Locate the `## Management Summary` block.

    Returns (start_line_idx, end_line_idx_exclusive, heading_line) or None.
    """
    lines = text.splitlines()
    ms_start: int | None = None
    for i, line in enumerate(lines):
        if _MS_TOP_HEADING_RE.match(line):
            ms_start = i
            break
    if ms_start is None:
        return None
    ms_end = len(lines)
    for j in range(ms_start + 1, len(lines)):
        if lines[j].startswith("## ") and not _MS_TOP_HEADING_RE.match(lines[j]):
            ms_end = j
            break
    return (ms_start, ms_end, lines[ms_start])


def check_ms_structure(md_path: Path) -> tuple[Report, str]:
    """Validate (and auto-repair where safe) the Management Summary layout.

    Repairs performed in place:
        * Drop numeric prefixes on MS sub-section headings
          (e.g. `### 1.1 Verdict` → `### Verdict`).
        * Rename well-known legacy headings (`### Top Threats` →
          `### Top Findings`, `### Key Strengths` → `### Operational Strengths`,
          `### Follow-up Actions` → `### Mitigations`).
        * Remove numeric prefix on the `## Management Summary` heading
          itself (`## 1. Management Summary` → `## Management Summary`).

    Flagged but NOT auto-rewritten (too destructive — require a full rerun):
        * Missing required sub-sections from the canonical set.
        * Missing red HTML blockquote inside the Verdict section.
        * Missing `## Critical Attack Tree` section after MS when ≥2 Criticals.
    """
    report = Report("ms_structure")
    original = md_path.read_text(encoding="utf-8")
    text = original

    # --- Auto-repair #1: strip numeric prefix on the top MS heading itself.
    def _strip_ms_prefix(match: re.Match[str]) -> str:
        return "## Management Summary"

    stripped_top_re = re.compile(r"^##\s+\d+(?:\.\d+)?\.?\s+Management Summary\s*$", re.MULTILINE)
    if stripped_top_re.search(text):
        text = stripped_top_re.sub(_strip_ms_prefix, text)
        report.fixes.append("Stripped numeric prefix from '## Management Summary' heading")

    slice_info = _slice_management_summary(text)
    if slice_info is None:
        report.issues.append("Management Summary heading '## Management Summary' is missing — rerun Phase 11 Part A")
        return report, text

    ms_start, ms_end, _ = slice_info
    lines = text.splitlines()
    ms_block = lines[ms_start:ms_end]

    # --- Auto-repair #2: rename well-known legacy sub-section headings.
    # 2026-05 — the canonical merged section is "Security Posture & Top
    # Threats" (heatmap + the Top Threats table). It replaced the legacy
    # "Security Posture at a Glance" + "Top Findings" + "Architecture
    # Assessment" trio. Legacy heading names are folded into it.
    _LEGACY_RENAMES: dict[str, str] = {
        "Security Posture at a Glance": "Security Posture & Top Threats",
        "Top Threats": "Security Posture & Top Threats",
        "Top Findings": "Security Posture & Top Threats",
        "Architecture Assessment": "Security Posture & Top Threats",
        "Top Critical Findings": "Security Posture & Top Threats",
        "Top Risks": "Security Posture & Top Threats",
        "Critical Findings": "Security Posture & Top Threats",
        "Top Threats by Risk": "Security Posture & Top Threats",
        "Key Strengths": "Operational Strengths",
        "Follow-up Actions": "Mitigations",
        "Recommended Priority Actions": "Mitigations",
        "Immediate Actions": "Mitigations",
        "Immediate Actions Required": "Mitigations",
        "Immediate Actions Required (P1)": "Mitigations",
        "Risk Distribution": None,  # forbidden — strip entire heading
        "STRIDE Coverage": None,  # forbidden — strip entire heading
        "Critical Attack Tree": None,  # must be ## (promoted), not ### inside MS
        "Critical Attack Chain": None,  # legacy heading — must be ## (promoted), not ### inside MS
        "Overall Security Rating": None,  # Verdict already carries the rating
        "Executive Overview": "Verdict",  # narrative-only → rename, body usually works as Verdict prose
    }

    # --- Auto-repair #3: strip numeric prefixes on all MS sub-section headings.
    renamed_count = 0
    stripped_count = 0
    legacy_stripped = 0
    for i, line in enumerate(ms_block):
        m = _MS_HEADING_RE.match(line)
        if not m:
            continue
        hashes, title = m.group(1), m.group(2).strip()
        if hashes == "##":
            continue  # top MS heading, not a sub-section

        # Strip numeric prefix `1.1 ` / `1. ` from sub-section heading.
        pm = _NUMBERED_PREFIX_RE.match(line)
        if pm:
            new_line = f"{pm.group(1)} {pm.group(2).strip()}"
            ms_block[i] = new_line
            stripped_count += 1
            line = new_line
            m = _MS_HEADING_RE.match(line)
            title = m.group(2).strip() if m else title

        # Rename / drop legacy headings.
        if title in _LEGACY_RENAMES:
            target = _LEGACY_RENAMES[title]
            if target is None:
                # Forbidden heading — blank the line so downstream rebuild is obvious.
                ms_block[i] = f"<!-- QA-STRIPPED: forbidden MS sub-section '### {title}' -->"
                legacy_stripped += 1
            else:
                ms_block[i] = f"{hashes} {target}"
                renamed_count += 1

    if stripped_count:
        report.fixes.append(f"Stripped numeric prefix from {stripped_count} MS sub-section heading(s)")
    if renamed_count:
        report.fixes.append(f"Renamed {renamed_count} legacy MS sub-section heading(s) to canonical names")
    if legacy_stripped:
        report.fixes.append(
            f"Stripped {legacy_stripped} forbidden MS sub-section heading(s) (Risk Distribution / STRIDE Coverage / etc.)"
        )

    if stripped_count or renamed_count or legacy_stripped:
        lines[ms_start:ms_end] = ms_block
        text = "\n".join(lines)
        # preserve trailing newline if the original had one
        if original.endswith("\n") and not text.endswith("\n"):
            text += "\n"
        # Recompute slice after mutation — future checks must see the rewrites.
        slice_info = _slice_management_summary(text)
        if slice_info is not None:
            ms_start, ms_end, _ = slice_info
            ms_block = text.splitlines()[ms_start:ms_end]

    # --- Check 1: all five required sub-sections present, in correct order.
    subsection_headings: list[tuple[int, str]] = []
    for i, line in enumerate(ms_block):
        m = _MS_HEADING_RE.match(line)
        if m and m.group(1) == "###":
            subsection_headings.append((i, m.group(2).strip()))

    names = [h[1] for h in subsection_headings]
    for required in _MS_REQUIRED_SUBSECTIONS:
        if required not in names:
            report.issues.append(f"Management Summary missing required sub-section '### {required}' — rerun required")

    # --- Check 2: order of the required sub-sections matches canonical order.
    if all(r in names for r in _MS_REQUIRED_SUBSECTIONS):
        observed = [n for n in names if n in _MS_REQUIRED_SUBSECTIONS]
        if observed != list(_MS_REQUIRED_SUBSECTIONS):
            report.issues.append(
                f"Management Summary sub-section order is {observed}, expected {list(_MS_REQUIRED_SUBSECTIONS)}"
            )

    # --- Check 3: Verdict contains the red HTML blockquote.
    ms_text = "\n".join(ms_block)
    verdict_idx = next((i for (i, n) in subsection_headings if n == "Verdict"), None)
    next_idx = next(
        (i for (i, n) in subsection_headings if n != "Verdict" and (verdict_idx is None or i > verdict_idx)),
        len(ms_block),
    )
    if verdict_idx is not None:
        verdict_body = "\n".join(ms_block[verdict_idx:next_idx])
        if not _VERDICT_BLOCKQUOTE_RE.search(verdict_body):
            report.issues.append(
                "Verdict section is missing the red HTML <blockquote "
                'style="border-left: 3px solid #dc2626; …"> worst-case-scenarios block'
            )

    # --- Check 4: Critical Attack Tree is present.
    # The cross-finding/strategic view is the standalone `## Critical Attack
    # Tree` block between the Management Summary and §1 (the legacy
    # `## Critical Attack Chain` heading is also accepted; the §3.1 Attack
    # Chain Overview was retired). Skipped when .skill-config.json sets
    # SKIP_ATTACK_WALKTHROUGHS=true — a skip-notice stub is intentional then.
    rd = RISK_DIST_RE.search(text)
    critical_count = int(rd.group(1)) if rd else 0
    _skip_walkthroughs = False
    try:
        import json as _json_ck

        _cfg_path = md_path.parent / ".skill-config.json"
        if _cfg_path.is_file():
            _cfg = _json_ck.loads(_cfg_path.read_text(encoding="utf-8"))
            _skip_walkthroughs = bool(_cfg.get("SKIP_ATTACK_WALKTHROUGHS") or _cfg.get("skip_attack_walkthroughs"))
    except Exception:
        pass
    has_chain = bool(_CRITICAL_CHAIN_RE.search(text))
    if critical_count >= 2 and not has_chain and not _skip_walkthroughs:
        report.issues.append(
            "Critical Attack Tree missing — required when Critical count ≥ 2. "
            "Expected the `## Critical Attack Tree` section between the "
            "Management Summary and §1 (legacy `## Critical Attack Chain` "
            "heading also accepted)."
        )

    # --- Check 5: MS sub-sections should not carry numeric prefixes anymore.
    # (We auto-stripped above, but flag any residue — e.g. inside H4 sub-headers.)
    for i, line in enumerate(ms_block):
        if _NUMBERED_PREFIX_RE.match(line) and line.startswith("### "):
            report.issues.append(
                f"Residual numeric prefix on MS sub-heading (line {ms_start + i + 1}): {line.strip()!r}"
            )

    if not report.issues:
        report.ok = 1
    return report, text


# ---------------------------------------------------------------------------
# Contract-compliance check — compares the rendered markdown to
# sections-contract.yaml. Flags (never auto-repairs — if contract is broken
# the whole doc needs to be re-rendered from fragments).
# ---------------------------------------------------------------------------

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONTRACT_PATH = PLUGIN_ROOT / "data" / "sections-contract.yaml"


def check_contract(md_path: Path, contract_path: Path = DEFAULT_CONTRACT_PATH) -> Report:
    """Validate the rendered markdown against sections-contract.yaml.

    Checks:
      1. Every section listed in ``document.order`` produces its heading
         in the rendered output, in the declared order (respecting
         ``condition`` gates evaluated against simple counters).
      2. No forbidden_subsection_patterns appear under Management Summary.
      3. Required tables present the declared number of columns with the
         declared headers (Top Findings: 6 cols; Architecture Assessment:
         3 cols; Operational Strengths: 5 cols; Mitigations sub-tables:
         5 cols each).
    """

    report = Report("contract")
    contract = _read_contract(contract_path)
    if not isinstance(contract, dict) or not contract:
        report.issues.append(f"contract is not a mapping or empty: {contract_path}")
        return report

    text = _read_md(md_path)

    # 1. Section order + presence.
    rd = RISK_DIST_RE.search(text)
    critical_count = int(rd.group(1)) if rd else 0
    env = {
        "critical_count": critical_count,
        "high_count": int(rd.group(2)) if rd else 0,
        "medium_count": int(rd.group(3)) if rd else 0,
        "low_count": int(rd.group(4)) if rd else 0,
        "check_requirements": False,
        "verbose_report": False,  # matches renderer default (meta flag off)
        "triage_has_warnings": False,
        "has_out_of_scope": True,
        "render_security_architecture": True,
    }

    expected_headings: list[str] = []
    for raw in contract.get("document", {}).get("order", []):
        sid, cond = (raw, None) if isinstance(raw, str) else (raw.get("id"), raw.get("condition"))
        if cond and not _safe_eval_cond(cond, env):
            continue
        section = contract.get("sections", {}).get(sid) or {}
        heading = (section.get("heading") or "").strip()
        if not heading:
            continue
        expected_headings.append(heading)

    # Strip inline `<a id="…"></a>` anchors before comparing so headings like
    # `## <a id="appendix-a-vektor-taxonomy"></a>Appendix A — Vektor Taxonomy`
    # match the contract's `## Appendix A — Vektor Taxonomy`.
    stripped_text = re.sub(r'<a id="[^"]*"></a>', "", text)

    last_idx = -1
    for heading in expected_headings:
        match = re.search(
            rf"(?m)^{re.escape(heading)}[ \t]*$",
            stripped_text,
        )
        idx = match.start() if match else -1
        if idx < 0:
            report.issues.append(f"expected section missing: {heading!r}")
            continue
        if idx < last_idx:
            report.issues.append(
                f"section order violation — {heading!r} appears before a section that should come later"
            )
        last_idx = idx

    # 1b. Required sub-section presence + order within each top-level
    # section. Historically the §7 contract listed required_subsections but
    # check_contract only validated the parent `##` headings, so a renderer
    # could ship a stale §7 layout while the contract still passed.
    for raw in contract.get("document", {}).get("order", []):
        sid, cond = (raw, None) if isinstance(raw, str) else (raw.get("id"), raw.get("condition"))
        if cond and not _safe_eval_cond(cond, env):
            continue
        section = contract.get("sections", {}).get(sid) or {}
        parent_heading = (section.get("heading") or "").strip()
        required_subs = section.get("required_subsections") or []
        if not parent_heading or not required_subs:
            continue
        parent_match = re.search(rf"(?m)^{re.escape(parent_heading)}[ \t]*$", stripped_text)
        if not parent_match:
            continue
        parent_body_start = parent_match.end()
        next_h2 = re.search(r"(?m)^##\s+", stripped_text[parent_body_start:])
        parent_body = (
            stripped_text[parent_body_start: parent_body_start + next_h2.start()]
            if next_h2
            else stripped_text[parent_body_start:]
        )
        last_sub_idx = -1
        for sub in required_subs:
            if not isinstance(sub, dict):
                continue
            sub_cond = sub.get("condition")
            if sub_cond and not _safe_eval_cond(sub_cond, env):
                continue
            level = int(sub.get("level") or 3)
            title = (sub.get("title") or "").strip()
            pattern = (sub.get("pattern") or "").strip()
            if not title and not pattern:
                continue
            hashes = "#" * level
            if title:
                sub_re = re.compile(
                    rf"(?m)^{re.escape(hashes)}\s+{re.escape(title)}[ \t]*$"
                )
                display = f"{hashes} {title}"
            else:
                try:
                    sub_re = re.compile(rf"(?m)^{re.escape(hashes)}\s+{pattern}[ \t]*$")
                except re.error as err:
                    report.issues.append(
                        f"invalid required_subsection pattern under {parent_heading!r}: "
                        f"/{pattern}/ ({err})"
                    )
                    continue
                display = f"{hashes} /{pattern}/"
            sub_match = sub_re.search(parent_body)
            if not sub_match:
                report.issues.append(
                    f"required subsection missing under {parent_heading!r}: {display!r}"
                )
                continue
            if sub_match.start() < last_sub_idx:
                report.issues.append(
                    f"required subsection order violation under {parent_heading!r}: "
                    f"{display!r} appears before a subsection that should come earlier"
                )
            last_sub_idx = sub_match.start()

    # 2. Forbidden MS subsection patterns.
    ms_info = _slice_management_summary(text)
    if ms_info is not None:
        ms_start, ms_end, _ = ms_info
        ms_block = text.splitlines()[ms_start:ms_end]
        ms_sec = contract.get("sections", {}).get("management_summary") or {}
        for pat in ms_sec.get("forbidden_subsection_patterns", []) or []:
            compiled = re.compile(pat)
            for line in ms_block:
                m = _MS_HEADING_RE.match(line)
                if not m or m.group(1) == "##":
                    continue
                title = m.group(2).strip()
                if compiled.match(title):
                    report.issues.append(f"forbidden MS heading matches /{pat}/: {title!r}")

    # 3. Required table column schemas.
    # Each entry may carry one or MORE accepted header signatures (any-match
    # is OK). The Operational Strengths and Top Mitigations tables both
    # switched layouts in M3.10; the legacy form is intentionally NOT in
    # the accept-list so reports rendered by old code are flagged.
    table_checks = [
        # 2026-05 — Top Threats is the merged section that replaced Top
        # Findings + Architecture Assessment. One row per attack class.
        ("top_threats", "Top Threats", [
            "| # | Threat Description | Findings (→ Component) | Risk & Impact | Fix |",
        ]),
        ("operational_strengths", "Operational Strengths", [
            # M3.10 — categorical-cluster layout
            "| Strength | What's in Place | Effectiveness | Gap | Mitigates |",
            # 3-col fallback when Gap + Mitigates are suppressed (all rows generic)
            "| Strength | What's in Place | Effectiveness |",
            # Post-2026-05 empty-state — every cluster demoted to Weak, no
            # table rendered, only an italic explanatory banner. Accept the
            # banner's stable opener as evidence the section was authored.
            "No defensive cluster currently rates above Weak",
        ]),
        ("mitigations", "Top Mitigations", [
            # 2026-06-03 — Priority column dropped: the rollout priority now
            # rides on the linked mitigation as a leading prefix (2026-06-04
            # Variant B: a monochrome circled digit, `❶`…`❹`), so the
            # dedicated column is redundant.
            "| # | Component | Mitigation | Addresses | Effort |",
            # Post-2026-05-29 — numbered table with a dedicated Component
            # column (label printed once per group, blank on continuation
            # rows). Replaces the in-table divider-row form, which rendered
            # the component label displaced in the `#`/ID column.
            "| # | Priority | Component | Mitigation | Addresses | Effort |",
            # Post-2026-05 iteration 3 — numbered table. Sequential `#` column
            # added so each data row carries an at-a-glance position; divider
            # rows continue to carry the component label in the first cell.
            "| # | Priority | Mitigation | Addresses | Effort |",
            # Post-2026-05 iteration 1 — single central table, sub-grouped by
            # component via divider rows; Component column dropped.
            "| Priority | Mitigation | Addresses | Effort |",
            # M3.10 legacy — kept as accepted form so legacy reports are not
            # falsely flagged.
            "| Priority | Mitigation | Component | Addresses | Effort |",
        ]),
    ]
    for _sid, label, accepted_headers in table_checks:
        if label not in text:
            continue
        if not any(h in text for h in accepted_headers):
            report.issues.append(
                f"{label} table does not match contract column schema "
                f"(expected one of: {accepted_headers!r})"
            )

    if not report.issues:
        report.ok = 1
    return report


def _safe_eval_cond(expr: str, env: dict) -> bool:
    """Evaluate a contract condition safely.

    Thin adapter over ``_safe_cond.resolve_condition``. Unlike the
    composer's ``eval_condition`` (which raises on malformed input), this
    helper returns ``False`` so contract-violation reporting stays robust
    against typo'd conditions in user-facing YAML.
    """
    if not expr:
        return False
    try:
        return _safe_cond.resolve_condition(expr, env)
    except _safe_cond.SafeCondError:
        return False


# ---------------------------------------------------------------------------
# Repair-plan emission — machine-readable contract-violation report.
# Consumed by the threat-analyst orchestrator in REPAIR_MODE to regenerate
# the offending fragments and re-invoke compose_threat_model.py.
# ---------------------------------------------------------------------------

# Mapping from contract section id to the fragment file(s) that drive it.
# Used by build_repair_plan() to point the orchestrator at the files it has
# to re-write before the next compose_threat_model.py invocation. Section
# ids that are computed-only (100% derived from threat-model.yaml +
# triage) have an empty list — the repair action there is "re-render",
# not "re-write a fragment".
CONTRACT_SECTION_FRAGMENTS: dict[str, list[str]] = {
    "infobox": [],  # from yaml
    "changelog": [],  # from yaml
    "toc": [],  # computed
    "management_summary": [],  # container only
    "verdict": [".fragments/ms-verdict.json"],
    "top_findings": [],  # computed
    "architecture_assessment": [".fragments/ms-architecture-assessment.json"],
    "mitigations": [],  # computed
    "operational_strengths": [".fragments/operational-strengths-overrides.json"],
    "system_overview": [".fragments/system-overview.md"],
    "architecture_diagrams": [".fragments/architecture-diagrams.md"],
    "attack_walkthroughs": [".fragments/attack-walkthroughs.md"],
    "assets": [".fragments/assets.md"],
    "attack_surface": [".fragments/attack-surface.md"],
    "security_posture_at_a_glance": [".fragments/security-posture-attack-paths.json"],
    "security_architecture": [".fragments/security-architecture.md"],
    "requirements_compliance": [".fragments/requirements-compliance.md"],
    "threat_register": [".fragments/compound-chains.json"],
    "mitigation_register": [],  # from yaml mitigations[]
    "out_of_scope": [".fragments/out-of-scope.md"],
    "appendix_run_statistics": [],  # from yaml meta
    "appendix_vektor_taxonomy": [],  # from plugin data
}


# Label → contract section id mapping for table-schema-drift issues
# (Top Findings / Architecture Assessment / Operational Strengths /
# Prioritized Mitigations). Used to point the orchestrator at the
# correct fragment when a column schema does not match.
_TABLE_LABEL_TO_SECTION: dict[str, str] = {
    "Top Findings": "top_findings",
    "Architecture Assessment": "architecture_assessment",
    "Operational Strengths": "operational_strengths",
    "Prioritized Mitigations": "mitigations",
}


def _heading_to_section_id(heading: str, contract: dict) -> str | None:
    """Return the contract section id whose `heading` matches ``heading``."""
    for sid, section in (contract.get("sections") or {}).items():
        if not isinstance(section, dict):
            continue
        if (section.get("heading") or "").strip() == heading.strip():
            return sid
    return None


def build_repair_plan(
    md_path: Path,
    output_dir: Path,
    contract_path: Path = DEFAULT_CONTRACT_PATH,
) -> tuple[dict, Report]:
    """Translate ``check_contract`` issues into a structured repair plan.

    Returns the plan dict (always) and the underlying Report. Caller decides
    whether to write the plan to disk based on ``plan['issue_count'] > 0``.
    """
    import datetime as _dt

    report = check_contract(md_path, contract_path)
    contract = _read_contract(contract_path)
    if not isinstance(contract, dict):
        contract = {}

    # Structural / rendering checks that sit alongside the contract gate.
    # Their issues are appended to ``report.issues`` so the Re-Render Loop
    # fires for them as well, and each check type has its own action branch
    # below with targeted remediation instructions.
    mermaid_report = check_mermaid_syntax(md_path)
    toc_nested_report = check_toc_nested_links(md_path)
    infobox_report = check_infobox_completeness(md_path)
    auth_report = check_auth_method_decomposition(md_path, contract_path)
    control_coverage_report = check_control_subsection_coverage(md_path, contract_path)
    relevant_findings_report = check_relevant_findings_bullet_list(md_path, contract_path)
    validation_approach_report = check_validation_approach_first(md_path, contract_path)
    posture_report = check_security_posture_structure(md_path)
    compactness_report = check_diagram_compactness(md_path, contract_path)
    chain_compactness_report = check_chain_compactness(md_path, contract_path)
    chain_tid_report = check_chain_tid_consistency(md_path, output_dir)
    walkthrough_coverage_report = check_walkthrough_coverage(md_path, output_dir, contract_path)
    walkthrough_depth_report = check_walkthrough_depth(md_path, output_dir, contract_path)
    recon_iam_report = check_recon_iam_bridge(md_path, output_dir, contract_path)
    falls_short_report = check_falls_short_format(md_path, contract_path)
    mermaid_issues = list(mermaid_report.issues)
    toc_nested_issues = list(toc_nested_report.issues)
    infobox_issues = list(infobox_report.issues)
    auth_issues = list(auth_report.issues)
    control_coverage_issues = list(control_coverage_report.issues)
    relevant_findings_issues = list(relevant_findings_report.issues)
    validation_approach_issues = list(validation_approach_report.issues)
    posture_issues = list(posture_report.issues)
    compactness_issues = list(compactness_report.issues)
    chain_compactness_issues = list(chain_compactness_report.issues)
    chain_tid_issues = list(chain_tid_report.issues)
    walkthrough_coverage_issues = list(walkthrough_coverage_report.issues)
    walkthrough_depth_issues = list(walkthrough_depth_report.issues)
    recon_iam_issues = list(recon_iam_report.issues)
    falls_short_issues = list(falls_short_report.issues)
    report.issues.extend(mermaid_issues)
    report.issues.extend(toc_nested_issues)
    report.issues.extend(infobox_issues)
    report.issues.extend(auth_issues)
    report.issues.extend(control_coverage_issues)
    report.issues.extend(relevant_findings_issues)
    report.issues.extend(posture_issues)
    report.issues.extend(compactness_issues)
    report.issues.extend(chain_compactness_issues)
    report.issues.extend(chain_tid_issues)
    report.issues.extend(walkthrough_coverage_issues)
    report.issues.extend(walkthrough_depth_issues)
    report.issues.extend(recon_iam_issues)
    # falls_short issues are warnings only — extend warnings, not issues.
    report.warnings.extend(falls_short_report.warnings)
    report.issues.extend(falls_short_issues)

    actions: list[dict] = []
    # One action per mermaid-syntax finding. The offending fragment is almost
    # always `.fragments/attack-walkthroughs.md` (sequence diagrams) or
    # `.fragments/architecture-diagrams.md` (flowchart/graph). Pointing at
    # both lets the orchestrator choose based on the block index / line.
    for raw in mermaid_issues:
        actions.append(
            {
                "raw_issue": raw,
                "type": "mermaid_syntax",
                "section_id": "attack_walkthroughs",
                "fragments_to_rewrite": [
                    ".fragments/attack-walkthroughs.md",
                    ".fragments/architecture-diagrams.md",
                ],
                "remediation": (
                    "Edit the mermaid block and remove the flagged pattern. "
                    "Rules: (1) escape all inner double quotes to &quot; inside "
                    "sequenceDiagram messages and note payloads; (2) participant "
                    "aliases containing '(' must be wrapped in double quotes; "
                    "(3) `alt` / `else` labels must follow the convention "
                    "'Current state — T-NNN' for the vulnerable branch and "
                    "'After M-NNN — <short description>' for the mitigated branch. "
                    "After editing, re-run compose_threat_model.py."
                ),
            }
        )
    # One action per TOC-nested-link issue. The offending label always lives
    # in a `### ` heading inside `.fragments/attack-walkthroughs.md` (that is
    # the only fragment whose subsections drive the §3 TOC via prose-scan).
    # Re-rendering the fragment fixes both the heading and the TOC.
    for raw in toc_nested_issues:
        actions.append(
            {
                "raw_issue": raw,
                "type": "toc_nested_link",
                "section_id": "attack_walkthroughs",
                "fragments_to_rewrite": [".fragments/attack-walkthroughs.md"],
                "remediation": (
                    "Rewrite the offending `### ` heading so it does not embed a "
                    "markdown link. Keep the T-NNN citation in plain parens "
                    "(no `[..](..)`): `### 3.2 OS Command Injection (T-001)`. "
                    "If the threat reference must remain clickable, move it into "
                    "the section body as `**Threat:** [T-001](#t-001)` rather than "
                    "putting it in the heading. After editing, re-run "
                    "compose_threat_model.py."
                ),
            }
        )
    # Single action for infobox thinness — the only remedy is source
    # enrichment (yaml `project:` block or repo manifest/LICENSE/README).
    if infobox_issues:
        actions.append(
            {
                "raw_issue": "; ".join(infobox_issues),
                "type": "infobox_incomplete",
                "section_id": "infobox",
                "fragments_to_rewrite": [],  # data_source: threat-model.yaml#project
                "remediation": (
                    "Enrich the infobox data source. Either (a) add the missing "
                    "fields to `threat-model.yaml` under a top-level `project:` "
                    "block (keys: name, version, description, author, license, "
                    "repository, homepage, runtime, tags), or (b) ensure the "
                    "repository carries the manifests the renderer already "
                    "understands — package.json / pyproject.toml / Cargo.toml / "
                    "pom.xml / build.gradle — together with a LICENSE file and "
                    "a README frontmatter `tags:` list. _read_project_manifest() "
                    "in compose_threat_model.py is polyglot and will pick these "
                    "up automatically on the next run."
                ),
            }
        )
    # One action per auth_method_decomposition finding. All such violations
    # live inside `.fragments/security-architecture.md` (§7.3 IAM). The
    # orchestrator's repair branch re-authors that fragment so the next
    # compose produces the missing #### sub-blocks, sequenceDiagrams, and
    # `**Findings in this flow:**` trailers with consistent T-ID citations.
    for raw in auth_issues:
        actions.append(
            {
                "raw_issue": raw,
                "type": "auth_method_decomposition",
                "section_id": "security_architecture",
                "fragments_to_rewrite": [".fragments/security-architecture.md"],
                "remediation": (
                    "Edit `.fragments/security-architecture.md` so §7.2 Identity "
                    "and Authentication Controls is decomposed by authentication "
                    "MECHANISM (Password-Based Authentication, OAuth/OIDC, "
                    "MFA/TOTP, …) — one `####` sub-block per mechanism, not by "
                    "primitive (hashing), library (express-jwt), or token format "
                    "(JWT-RS256). Every sub-block whose heading names an auth FLOW "
                    "(login, OAuth/OIDC, SAML, TOTP/MFA, passkey, mTLS handshake, "
                    "webhook HMAC, magic link) MUST carry its own positive-flow "
                    "```mermaid sequenceDiagram```. The grouped Password-Based "
                    "Authentication block folds Login/Registration/Reset/Change/"
                    "Storage as bullets and shows the login sequenceDiagram once. "
                    "Static primitives and non-flow methods (API key, anonymous) "
                    "need no diagram. After editing, re-run compose_threat_model.py."
                ),
            }
        )

    for raw in validation_approach_issues:
        actions.append(
            {
                "raw_issue": raw,
                "type": "validation_approach_first",
                "section_id": "security_architecture",
                "fragments_to_rewrite": [".fragments/security-architecture.md"],
                "remediation": (
                    "Edit `.fragments/security-architecture.md` so §7.6 Input "
                    "Boundary Validation Controls OPENS with a general "
                    "validation-approach `####` block (e.g. `#### Validation "
                    "Approach` / `Input Validation Strategy`) that states the "
                    "architectural stance — is request validation centralized in "
                    "a schema/middleware layer, or scattered ad-hoc per endpoint? "
                    "— BEFORE the specific parser / upload / business-rule "
                    "sub-blocks. Reorder so the approach block is the FIRST H4 "
                    "under §7.6. After editing, re-run compose_threat_model.py."
                ),
            }
        )

    for raw in control_coverage_issues:
        actions.append(
            {
                "raw_issue": raw,
                "type": "control_subsection_coverage",
                "section_id": "security_architecture",
                "fragments_to_rewrite": [".fragments/security-architecture.md"],
                "remediation": (
                    "Edit `.fragments/security-architecture.md` to follow the "
                    "v2 §7 control-category shape. Each §7.2-§7.12 block needs "
                    "`**Controls covered:**` with markdown links to matching "
                    "`#### <Control Name>` subcontrols. Each subcontrol needs "
                    "`**Security assessment**` and `**Relevant findings**` "
                    "labels. Do not reintroduce legacy `#### 7.3.N ... Flow` "
                    "or `**Findings in this flow:**` requirements."
                ),
            }
        )

    for raw in relevant_findings_issues:
        actions.append(
            {
                "raw_issue": raw,
                "type": "relevant_findings_bullet_list",
                "section_id": "security_architecture",
                "fragments_to_rewrite": [".fragments/security-architecture.md"],
                "remediation": (
                    "Edit `.fragments/security-architecture.md` so every §7.2-§7.12 "
                    "H4 subcontrol uses a standalone `**Relevant findings**` label "
                    "followed by a Markdown bullet list. Do not use the inline form "
                    "`**Relevant findings:** [F-001](#f-001), [F-002](#f-002)`. "
                    "When no finding maps directly, emit "
                    "`- No dedicated finding routed in this assessment.`"
                ),
            }
        )

    # Walkthrough-coverage repairs always point at attack-walkthroughs.md —
    # missing per-Critical §3.x sub-sections can only be fixed by re-authoring
    # the fragment. The remediation enumerates the exact T-NNN ids that need
    # walkthroughs and reminds the repairer of the canonical sub-section
    # shape so a re-render produces them in one pass.
    for raw in walkthrough_coverage_issues:
        actions.append(
            {
                "raw_issue": raw,
                "type": "walkthrough_coverage",
                "section_id": "attack_walkthroughs",
                "fragments_to_rewrite": [".fragments/attack-walkthroughs.md"],
                "remediation": (
                    "Re-generate `.fragments/attack-walkthroughs.md` "
                    "deterministically — `python3 scripts/pregenerate_fragments.py "
                    "<output-dir> --force --only attack-walkthroughs.md` — which "
                    "emits one `### 3.x` sub-section per Critical threat that is "
                    "contract-clean by construction. Each sub-section declares its "
                    "owning threat on a `**Source:** [T-NNN]` line directly under "
                    "the heading and carries the `**Attack Steps**`, `**Sequence "
                    "Diagram**`, and `**Defense in Depth**` labelled sections that "
                    "`walkthrough_depth` requires. Do NOT replace those three "
                    "labelled sections with `**Impact:**`/`**Recommended fix:**` — "
                    "that satisfies this check but breaks `walkthrough_depth`. Only "
                    "hand-edit if a specific Critical is genuinely absent. After "
                    "editing, re-run compose_threat_model.py."
                ),
            }
        )

    # Walkthrough-depth repairs — short bodies, missing alt/else, or
    # trivial §3.1 chain stubs. Same fragment target as coverage; the
    # remediation reminds the repairer about the minimum content shape.
    for raw in walkthrough_depth_issues:
        actions.append(
            {
                "raw_issue": raw,
                "type": "walkthrough_depth",
                "section_id": "attack_walkthroughs",
                "fragments_to_rewrite": [".fragments/attack-walkthroughs.md"],
                "remediation": (
                    "Edit `.fragments/attack-walkthroughs.md` so each §3.x "
                    "walkthrough body meets the contract's `walkthrough_depth` "
                    "thresholds. Required shape per walkthrough: (1) intro "
                    "paragraph (3-4 sentences), (2) `sequenceDiagram` with "
                    "BOTH an `alt Current state` branch (vulnerable path "
                    "step-by-step) AND an `else After mitigation` branch "
                    "(post-fix path), (3) `**Impact:**` paragraph, (4) "
                    "`**Recommended fix:**` line with M-NNN link. For §3.1 "
                    "Attack Chain Overview chains: each `graph LR` block "
                    "needs ≥ 4 distinct nodes — a 3-node "
                    "attacker→threat→impact stub is rejected as too thin. "
                    "After editing, re-run compose_threat_model.py."
                ),
            }
        )

    for raw in recon_iam_issues:
        actions.append(
            {
                "raw_issue": raw,
                "type": "recon_iam_bridge",
                "section_id": "security_architecture",
                "fragments_to_rewrite": [".fragments/security-architecture.md"],
                "remediation": (
                    "Recon found identity/authentication evidence that is absent "
                    "from §7. Add the missing TOTP/2FA/MFA subcontrol to the "
                    "configured identity/authentication controls section, list "
                    "it in `**Controls covered:**`, and include the required "
                    "`**Security assessment**` / `**Relevant findings**` labels."
                ),
            }
        )

    # Security Posture invariants — categorise by ID prefix. D/C/F/G/T are
    # all renderer-driven; if they fire, it's a plugin bug, not content. L
    # rules (link format) typically reflect missing `title` in
    # `threat-model.yaml#threats[].title` — that is content.
    for raw in posture_issues:
        rule_id = raw.split(":", 1)[0].strip() if ":" in raw else "?"
        category = rule_id[0] if rule_id else "?"
        if category in ("D", "C", "F", "G", "T"):
            kind = "posture_renderer_bug"
            fragments = []
            remediation = (
                f"Posture invariant {rule_id} violated. This category of rule "
                "is enforced by the deterministic renderer — a violation is a "
                "compose_threat_model.py bug, not a content issue. Escalate "
                "to plugin maintainer rather than re-running Phase 9."
            )
        elif category == "L":
            kind = "posture_link_format"
            fragments = []
            remediation = (
                f"Posture invariant {rule_id} violated. F-NNN references must "
                "carry the finding title in the link text "
                "(`[F-NNN — Title](#f-nnn)`). Most common cause: a finding in "
                "`threat-model.yaml#threats[]` is missing its `title` field. "
                "Re-run Phase 9 / 10b to populate missing titles."
            )
        else:
            kind = "posture_unknown"
            fragments = []
            remediation = "See raw_issue for details."
        actions.append(
            {
                "raw_issue": raw,
                "type": kind,
                "section_id": "security_posture_at_a_glance",
                "rule_id": rule_id,
                "fragments_to_rewrite": fragments,
                "remediation": remediation,
            }
        )

    for raw in chain_compactness_issues:
        actions.append(
            {
                "raw_issue": raw,
                "type": "chain_compactness",
                "section_id": "attack_walkthroughs",
                "fragments_to_rewrite": [".fragments/attack-walkthroughs.md"],
                "remediation": (
                    "§3.1 Attack Chains must follow the per-chain compactness "
                    "rules pinned in `data/sections-contract.yaml → "
                    "chain_compactness`. Each `#### Chain N — <name>` block "
                    "must contain ONE `graph LR` mermaid block (no subgraphs), "
                    "≤6 nodes, the audit classDef block (`risk` + `impact`), "
                    "and at least one T-NNN reference whose §8 entry exists. "
                    "If a chain exceeds the size limit it should be split into "
                    "two chains OR moved to §3.2+ as a standalone walkthrough. "
                    "After editing, re-run compose_threat_model.py."
                ),
            }
        )

    for raw in chain_tid_issues:
        actions.append(
            {
                "raw_issue": raw,
                "type": "chain_tid_consistency",
                "section_id": "attack_walkthroughs",
                "fragments_to_rewrite": [".fragments/attack-walkthroughs.md"],
                "remediation": (
                    "§3.1 chain-overview node label cites a T-NNN whose actual "
                    "title in `threat-model.yaml` shares no content keyword with "
                    "the label. The chain diagram is referencing the wrong "
                    "finding (LLM authoring drift). Two valid fixes:\n"
                    "  (1) Rewrite the node label so it actually describes the "
                    "      cited T-NNN's finding (look up the title in "
                    "      `threat-model.yaml → threats[].title`).\n"
                    "  (2) Change the T-NNN reference to the threat the label "
                    "      genuinely describes — and verify §8 has a row for it.\n"
                    "After editing, re-run compose_threat_model.py."
                ),
            }
        )

    for raw in compactness_issues:
        actions.append(
            {
                "raw_issue": raw,
                "type": "diagram_compactness",
                "section_id": "architecture_diagrams",
                "fragments_to_rewrite": [".fragments/architecture-diagrams.md"],
                "remediation": (
                    "§2.3 / §2.4 must follow the compactness rules pinned in "
                    "`data/sections-contract.yaml → diagram_compactness`. "
                    "RECOMMENDED FIX: regenerate the fragment from the "
                    "deterministic Pre-Generator instead of editing by hand:\n"
                    "  python3 $CLAUDE_PLUGIN_ROOT/scripts/pregenerate_fragments.py "
                    "$OUTPUT_DIR --force --only architecture-diagrams.md\n"
                    "Then re-run compose_threat_model.py. The Pre-Generator "
                    "produces a 4-tier `flowchart TD` that obeys the limits by "
                    "construction. Manual edits to §2.3/§2.4 are forbidden by "
                    "`skip_phase11_enrichment: true` — surface details belong "
                    "in the §2.3 component table or §2.4.1–§2.4.4 layer tables, "
                    "not in node labels."
                ),
            }
        )

    for raw in report.issues:
        # Skip issues already consumed above (added by mermaid / TOC / infobox
        # / auth-method / posture / compactness / chain-compactness branches)
        # so we do not emit both a structural action and an "unclassified"
        # action for the same violation.
        if (
            raw in mermaid_issues
            or raw in toc_nested_issues
            or raw in infobox_issues
            or raw in auth_issues
            or raw in control_coverage_issues
            or raw in relevant_findings_issues
            or raw in posture_issues
            or raw in compactness_issues
            or raw in chain_compactness_issues
            or raw in chain_tid_issues
            or raw in walkthrough_coverage_issues
            or raw in walkthrough_depth_issues
            or raw in recon_iam_issues
        ):
            continue
        action: dict = {"raw_issue": raw}
        # required subsection missing under '<parent>': '<subheading>'
        m = re.match(r"required subsection missing under ['\"](.+?)['\"]: ['\"](.+?)['\"]$", raw)
        if m:
            parent_heading, subheading = m.group(1), m.group(2)
            sid = _heading_to_section_id(parent_heading, contract)
            action.update(
                {
                    "type": "missing_required_subsection",
                    "heading": subheading,
                    "parent_heading": parent_heading,
                    "section_id": sid,
                    "fragments_to_rewrite": CONTRACT_SECTION_FRAGMENTS.get(sid or "", []),
                    "remediation": (
                        f"Re-author the fragment for `{parent_heading}` so it "
                        f"contains the required subsection `{subheading}` in "
                        f"contract order. For §7 v2, use the 13-section "
                        f"control-category layout from "
                        f"`data/sections-contract.yaml → schema_v2.required_subsections`."
                    ),
                }
            )
            actions.append(action)
            continue
        # required subsection order violation under '<parent>': '<subheading>' ...
        m = re.match(r"required subsection order violation under ['\"](.+?)['\"]: ['\"](.+?)['\"]", raw)
        if m:
            parent_heading, subheading = m.group(1), m.group(2)
            sid = _heading_to_section_id(parent_heading, contract)
            action.update(
                {
                    "type": "required_subsection_order_drift",
                    "heading": subheading,
                    "parent_heading": parent_heading,
                    "section_id": sid,
                    "fragments_to_rewrite": CONTRACT_SECTION_FRAGMENTS.get(sid or "", []),
                    "remediation": (
                        f"Reorder the subsections under `{parent_heading}` to "
                        f"match the contract. For §7 v2 this means the 13 "
                        f"control-category headings 7.1 through 7.13, with no "
                        f"legacy v1/v2 headings interleaved."
                    ),
                }
            )
            actions.append(action)
            continue
        # expected section missing: '<heading>'
        m = re.match(r"expected section missing: ['\"](.+?)['\"]$", raw)
        if m:
            heading = m.group(1)
            sid = _heading_to_section_id(heading, contract)
            action.update(
                {
                    "type": "missing_section",
                    "heading": heading,
                    "section_id": sid,
                    "fragments_to_rewrite": CONTRACT_SECTION_FRAGMENTS.get(sid, []),
                    "remediation": (
                        f"Re-author the fragment(s) listed under `fragments_to_rewrite` "
                        f"so the next compose_threat_model.py call produces "
                        f"`{heading}` at the expected position. "
                        f"If `fragments_to_rewrite` is empty, the section is "
                        f"computed from threat-model.yaml — re-run compose only."
                    ),
                }
            )
            actions.append(action)
            continue
        # section order violation — '<heading>' appears before a section that should come later
        m = re.match(r"section order violation — ['\"](.+?)['\"]", raw)
        if m:
            heading = m.group(1)
            sid = _heading_to_section_id(heading, contract)
            action.update(
                {
                    "type": "section_order_drift",
                    "heading": heading,
                    "section_id": sid,
                    "fragments_to_rewrite": CONTRACT_SECTION_FRAGMENTS.get(sid, []),
                    "remediation": (
                        "Re-run compose_threat_model.py — the renderer enforces "
                        "`document.order`. If the section is still out of order "
                        "after a fresh render, inspect the contract and the "
                        "fragment for stale heading text."
                    ),
                }
            )
            actions.append(action)
            continue
        # forbidden MS heading matches /<pat>/: '<title>'
        m = re.match(r"forbidden MS heading matches /(.+?)/: ['\"](.+?)['\"]$", raw)
        if m:
            pat, title = m.group(1), m.group(2)
            action.update(
                {
                    "type": "forbidden_ms_heading",
                    "heading": title,
                    "pattern": pat,
                    "section_id": "management_summary",
                    "fragments_to_rewrite": [
                        ".fragments/ms-verdict.json",
                        ".fragments/ms-architecture-assessment.json",
                    ],
                    "remediation": (
                        f"Delete the `### {title}` heading (and its body) from the "
                        f"offending fragment. The canonical MS sub-sections are "
                        f"Verdict / Top Findings / Architecture Assessment / "
                        f"Mitigations / Operational Strengths (in that order) — "
                        f"no other `###` headings are allowed under "
                        f"`## Management Summary`."
                    ),
                }
            )
            actions.append(action)
            continue
        # <label> table does not match contract column schema (expected: '<header>')
        m = re.match(
            r"(.+?) table does not match contract column schema "
            r"\(expected: ['\"](.+?)['\"]\)$",
            raw,
        )
        if m:
            label, expected_header = m.group(1), m.group(2)
            sid = _TABLE_LABEL_TO_SECTION.get(label)
            action.update(
                {
                    "type": "table_schema_drift",
                    "label": label,
                    "expected_header": expected_header,
                    "section_id": sid,
                    "fragments_to_rewrite": CONTRACT_SECTION_FRAGMENTS.get(sid or "", []),
                    "remediation": (
                        f"The `{label}` table columns in the rendered MD do not "
                        f"match the contract. This usually means either the "
                        f"fragment has been hand-edited or compose_threat_model.py "
                        f"was bypassed. Re-run compose (not a direct Write) and, "
                        f"if the drift persists, repair the source fragment."
                    ),
                }
            )
            actions.append(action)
            continue
        # unstructured issue — fall through with generic action
        action.update(
            {
                "type": "unclassified",
                "remediation": (
                    "See `raw_issue` for details. Re-run compose_threat_model.py "
                    "and re-inspect; if the same issue reappears, escalate to the "
                    "contract maintainer."
                ),
            }
        )
        actions.append(action)

    # ---- Repair-plan deduplication ---------------------------------------
    # Multiple structural checks (e.g. ``check_mermaid_syntax`` +
    # ``check_security_posture_structure``) sometimes flag the SAME
    # defect with slightly different wording. Two repair-plan entries
    # then trigger spurious second re-render loops because the agent
    # fixes one of them and the other re-fires on the next pass. We
    # dedupe by ``(section_id, error_type)`` keeping the first action's
    # remediation but unioning ``raw_issue`` lists for traceability.
    seen: dict[tuple[str, str], dict] = {}
    deduped: list[dict] = []
    for a in actions:
        key = (
            (a.get("section_id") or "").strip().lower() or "(global)",
            (a.get("type") or "unclassified").strip().lower(),
        )
        if key in seen:
            head = seen[key]
            existing = head.setdefault("merged_raw_issues", [head.get("raw_issue", "")])
            existing.append(a.get("raw_issue", ""))
            continue
        seen[key] = a
        deduped.append(a)
    actions = deduped

    status, actionable = _classify_plan_status(report.issues, actions)

    plan: dict = {
        "generated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "md_path": str(md_path),
        "output_dir": str(output_dir),
        "contract_path": str(contract_path),
        "status": status,
        "actionable": actionable,
        "issue_count": len(report.issues),
        "action_count": len(actions),
        "actions": actions,
        "re_render_command": (
            "python3 $CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py --output-dir $OUTPUT_DIR --strict"
        ),
    }
    return plan, report


def _classify_plan_status(
    issues: list,
    actions: list[dict],
) -> tuple[str, bool]:
    """Return (status, actionable) for a repair plan.

    Sprint 1D (M3.5): the skill-layer Re-Render Loop uses ``status`` to
    decide whether iteration can possibly converge:

      * ``pass``          — no issues, no actions, no work.
      * ``manual_review`` — issues exist but every action's
                            ``fragments_to_rewrite`` is empty. Re-rendering
                            cannot fix this (typically renderer/checker
                            drift); the loop must short-circuit.
      * ``fail``          — at least one action carries a writable fragment
                            target. The loop iterates as designed.

    Without the ``manual_review`` classification, the 2026-04-27 juice-shop
    run's all-``posture_renderer_bug`` repair plan would have burnt 3 ×
    ~10 min loop iterations on a problem only a code change can fix.
    """
    actionable = any(a.get("fragments_to_rewrite") for a in actions)
    if not issues:
        return "pass", actionable
    if actions and not actionable:
        return "manual_review", actionable
    return "fail", actionable


def cmd_repair_plan(md_path: Path, output_dir: Path, contract_path: Path) -> int:
    """Run the contract check and write `.qa-repair-plan.json`.

    Exit codes:
      0 — no violations, no plan written
      1 — actionable violations, plan written (re-render is expected to fix them)
      2 — error (bad inputs, unreadable files)
      3 — non-actionable violations only, plan written (manual review required —
          re-render cannot fix them; skill-layer loop should bail out instead
          of burning iterations). Sprint 1D (M3.5).
    """
    if not md_path.is_file():
        print(f"error: {md_path} not found", file=sys.stderr)
        return 2
    output_dir.mkdir(parents=True, exist_ok=True)
    plan, report = build_repair_plan(md_path, output_dir, contract_path)
    plan_path = output_dir / ".qa-repair-plan.json"
    if plan["status"] == "pass":
        # Clear any stale plan from a prior run so the skill's post-QA
        # check sees a clean state.
        try:
            plan_path.unlink()
        except FileNotFoundError:
            pass
        print(json.dumps(plan, indent=2))
        return 0
    plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(plan, indent=2))
    if plan["status"] == "manual_review":
        return 3
    return 1


def _check_requirements_violated_coverage(
    md_path: Path,
    output_dir: Path,
    report: Report,
) -> None:
    """Check 7c-ext: every requirement-sourced threat must carry a
    'Violated: [ID](url)' annotation in its Threat Scenario cell.

    Identifies requirement-sourced threats via .threats-merged.json
    (source in {requirements-compliance, architectural-anti-pattern}).
    Falls back to regex heuristic when the file is absent.
    """
    import re

    merged_path = output_dir / ".threats-merged.json"
    req_threat_ids: set[str] = set()
    if merged_path.is_file():
        try:
            merged = json.loads(merged_path.read_text(encoding="utf-8"))
            for t in merged.get("threats", []):
                if t.get("source") in {
                    "requirements-compliance",
                    "architectural-anti-pattern",
                }:
                    tid = t.get("t_id") or t.get("id") or ""
                    if tid:
                        req_threat_ids.add(tid.upper())
        except (json.JSONDecodeError, KeyError):
            pass

    if not req_threat_ids and not merged_path.is_file():
        # No merged file — skip rather than false-positive
        return

    text = md_path.read_text(encoding="utf-8")
    # Find rows in sections 7.1–7.4 (all threat register rows)
    # Row pattern: | <a id="t-NNN"></a>T-NNN | ... | scenario_text | ...
    row_re = re.compile(
        r"\|\s*<a id=\"(t-\d+)\"></a>(T-\d+)\s*\|[^|]+\|[^|]+\|([^|]+)\|",
        re.IGNORECASE,
    )
    violated_re = re.compile(r"Violated:\s*\[", re.IGNORECASE)
    missing: list[str] = []
    for m in row_re.finditer(text):
        tid = m.group(2).upper()
        scenario_cell = m.group(3)
        if tid in req_threat_ids and not violated_re.search(scenario_cell):
            missing.append(m.group(2))

    for tid in missing:
        report.issues.append(
            f"{tid}: requirement-sourced threat is missing 'Violated: [ID](url)' annotation in Threat Scenario cell"
        )


_EVIDENCE_CODE_EXTS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".go",
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".groovy",
    ".rb",
    ".php",
    ".cs",
    ".vb",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".hpp",
    ".cxx",
    ".rs",
    ".swift",
    ".m",
    ".mm",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".env",
    ".tf",
    ".tfvars",
    ".hcl",
    ".dockerfile",
    ".containerfile",
    ".html",
    ".vue",
    ".svelte",
    ".astro",
    ".sql",
    ".graphql",
    ".proto",
    ".lock",
    ".mod",
    ".sum",
    ".gradle",
    ".pom",
    ".xml",
}
_EVIDENCE_SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".nuxt",
    "target",
    "bin",
    "obj",
}
_COMMENT_PREFIXES_BY_EXT: dict[str, tuple[str, ...]] = {
    ".py": ("#",),
    ".rb": ("#",),
    ".sh": ("#",),
    ".bash": ("#",),
    ".zsh": ("#",),
    ".yaml": ("#",),
    ".yml": ("#",),
    ".toml": ("#",),
    ".ini": (";", "#"),
    ".tf": ("#", "//"),
    ".hcl": ("#", "//"),
    ".dockerfile": ("#",),
    ".js": ("//",),
    ".jsx": ("//",),
    ".ts": ("//",),
    ".tsx": ("//",),
    ".mjs": ("//",),
    ".cjs": ("//",),
    ".go": ("//",),
    ".java": ("//",),
    ".kt": ("//",),
    ".scala": ("//",),
    ".rs": ("//",),
    ".c": ("//",),
    ".cpp": ("//",),
    ".cs": ("//",),
    ".swift": ("//",),
    ".sql": ("--",),
    ".graphql": ("#",),
    ".proto": ("//",),
}
# Lines that consist entirely of one of these tokens are structurally
# noise — pure block delimiters, comment fence end-markers, or empty
# array/object closers. A finding citing such a line as evidence is
# either drift (line numbers shifted) or a hallucinated citation.
_EVIDENCE_NOISE_LINES = {
    "",
    "{",
    "}",
    "(",
    ")",
    "[",
    "]",
    "});",
    "})",
    "}),",
    "};",
    "}, {",
    "},",
    "*/",
    "/*",
    "**/",
    "*",
    "end",
    "End",
    "END",
    "---",
    "...",
    "<!--",
    "-->",
}


def _is_suspicious_evidence_line(line: str, ext: str) -> tuple[bool, str]:
    """Heuristic: does ``line`` look like real code/config at the cited spot?

    Returns ``(suspicious, reason)``. The check is intentionally lenient — it
    flags only clearly-noise lines (empty, brace-only, comment-only) so the
    QA reviewer surfaces drift without drowning in false positives on legit
    one-liner code. The STRIDE analyzer is allowed to cite header
    declarations, decorators, and config keys; those pass through.
    """
    stripped = line.strip()
    if not stripped:
        return True, "blank line"
    if stripped in _EVIDENCE_NOISE_LINES:
        return True, f"noise-only line ({stripped!r})"
    prefixes = _COMMENT_PREFIXES_BY_EXT.get(ext.lower(), ())
    for p in prefixes:
        if stripped.startswith(p):
            # `#!shebang` is a legit cite target for some findings (e.g.
            # privileged interpreter selection); spare it.
            if p == "#" and stripped.startswith("#!"):
                return False, ""
            return True, f"comment-only line ({p}…)"
    # Block-comment middle lines like ` * docs` in C-family files.
    if ext.lower() in {
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".java",
        ".go",
        ".c",
        ".cpp",
        ".cs",
        ".swift",
        ".kt",
        ".scala",
        ".rs",
    }:
        if stripped.startswith("* ") or stripped == "*":
            return True, "block-comment continuation"
    return False, ""


def _replay_absence_grep(
    repo_root: Path,
    pattern: str,
    search_paths: list[str],
    skip_under: Optional[Path] = None,
) -> Optional[int]:
    """Re-run a STRIDE-analyzer absence grep deterministically.

    Returns the new hit count, or ``None`` when the pattern is invalid or
    no search path resolves. Normalizes BRE-style ``\\|`` alternation to
    ERE ``|`` so analyzers that emit either style both work. Walks the
    listed paths with the standard exclusion set. ``skip_under``, when
    given, prunes any file path that is inside that directory — used to
    keep the QA pre-pass from matching the analyzer's own output
    artifacts (``.threats-merged.json``, ``threat-model.yaml``) when the
    analyzer recorded ``search_paths: ["."]``.
    """
    normalized = pattern.replace(r"\|", "|")
    try:
        regex = re.compile(normalized)
    except re.error:
        return None
    if not search_paths:
        search_paths = ["."]
    skip_under_resolved = skip_under.resolve() if skip_under else None
    total = 0
    any_resolved = False
    for sp in search_paths:
        base = (repo_root / sp).resolve()
        try:
            base.relative_to(repo_root.resolve())
        except ValueError:
            continue
        if not base.exists():
            continue
        any_resolved = True
        if base.is_file():
            files = [base]
        else:
            files = []
            for root, dirs, names in os.walk(base):
                dirs[:] = [d for d in dirs if d not in _EVIDENCE_SKIP_DIRS]
                if skip_under_resolved is not None:
                    try:
                        Path(root).resolve().relative_to(skip_under_resolved)
                        dirs[:] = []
                        continue
                    except ValueError:
                        pass
                for n in names:
                    p = Path(root) / n
                    if p.suffix.lower() in _EVIDENCE_CODE_EXTS:
                        files.append(p)
        for f in files:
            try:
                txt = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            total += sum(1 for _ in regex.finditer(txt))
    return total if any_resolved else None


def check_evidence_integrity(output_dir: Path, repo_root: Path) -> Report:
    """Check that each threat's evidence.file:line points at real code.

    Reads `.threats-merged.json` (preferred — pre-render artifact, the
    canonical source for downstream rendering and ranking). When the file
    is absent, falls back to `threat-model.yaml` which carries the same
    data after Phase 11. Per-threat checks:

    1. `evidence.file` resolves on the filesystem (after the repo-root
       relative recovery used by ``check_links``).
    2. When `evidence.line` is set (schema allows null): line is in range
       for the file and is not a structurally-noise line (pure comment,
       blank, brace-only).
    3. When `controls_absent_evidence[]` is present: each grep pattern is
       re-run; a new positive hit_count when the analyzer recorded zero
       is reported as `absence_grep_drift`.

    Findings flagged here are surfaced through `evidence_integrity.issues`
    in the `.qa-prepass.json` and consumed by the QA reviewer agent. The
    check NEVER auto-repairs — the underlying defects (line drift,
    hallucinated citation, control added since scan) require human or
    LLM judgement.
    """
    report = Report("evidence_integrity")
    merged_path = output_dir / ".threats-merged.json"
    yaml_path = output_dir / "threat-model.yaml"
    threats: list[dict] = []
    if merged_path.is_file():
        try:
            data = json.loads(merged_path.read_text(encoding="utf-8"))
            raw = data.get("threats", [])
            if isinstance(raw, list):
                threats = [t for t in raw if isinstance(t, dict)]
        except (json.JSONDecodeError, OSError) as exc:
            report.warnings.append(f"could not parse .threats-merged.json — {exc.__class__.__name__}")
            return report
    elif yaml_path.is_file():
        try:
            import yaml  # type: ignore[import-not-found]

            data = _fast_yaml_load(yaml_path.read_text(encoding="utf-8")) or {}
            raw = data.get("threats", [])
            if isinstance(raw, list):
                threats = [t for t in raw if isinstance(t, dict)]
        except Exception as exc:  # noqa: BLE001
            report.warnings.append(f"could not parse threat-model.yaml — {exc.__class__.__name__}")
            return report
    else:
        report.warnings.append("neither .threats-merged.json nor threat-model.yaml present — skipping")
        return report

    repo_root_resolved = repo_root.resolve()
    file_cache: dict[Path, list[str]] = {}

    def _load_lines(path: Path) -> list[str] | None:
        cached = file_cache.get(path)
        if cached is not None:
            return cached
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        lines = text.splitlines()
        file_cache[path] = lines
        return lines

    for t in threats:
        tid = t.get("t_id") or t.get("f_id") or t.get("id") or "?"
        ev = t.get("evidence")
        if not isinstance(ev, dict):
            continue
        ev_file = ev.get("file")
        if not isinstance(ev_file, str) or not ev_file.strip():
            continue
        # Resolve path: try as-is, then relative to repo root.
        candidates = [Path(ev_file)]
        if not Path(ev_file).is_absolute():
            candidates.append(repo_root_resolved / ev_file)
        resolved = next((p for p in candidates if p.exists() and p.is_file()), None)
        if resolved is None:
            report.issues.append(f"{tid}: evidence_missing_file — {ev_file}")
            continue
        report.ok += 1
        line_no = ev.get("line")
        if isinstance(line_no, int) and line_no > 0:
            lines = _load_lines(resolved)
            if lines is None:
                continue
            if line_no > len(lines):
                report.issues.append(
                    f"{tid}: evidence_line_out_of_range — line {line_no} exceeds {len(lines)} in {ev_file}"
                )
                continue
            suspicious, reason = _is_suspicious_evidence_line(lines[line_no - 1], resolved.suffix)
            if suspicious:
                report.issues.append(f"{tid}: evidence_line_suspicious — {reason} at {ev_file}:{line_no}")
        # M4: re-run absence grep when claim is recorded.
        absent = t.get("controls_absent_evidence")
        if isinstance(absent, list):
            for idx, entry in enumerate(absent):
                if not isinstance(entry, dict):
                    continue
                pattern = entry.get("pattern")
                paths = entry.get("search_paths") or []
                recorded = entry.get("hit_count", 0)
                if not isinstance(pattern, str) or not pattern:
                    continue
                if not isinstance(paths, list):
                    paths = []
                # Cast to str list, drop non-strings.
                paths = [p for p in paths if isinstance(p, str)]
                new_count = _replay_absence_grep(
                    repo_root_resolved,
                    pattern,
                    paths,
                    skip_under=output_dir,
                )
                if new_count is None:
                    # Invalid pattern or unresolvable paths — informational.
                    report.warnings.append(
                        f"{tid}: absence_grep_unresolved — entry {idx} could not be replayed ({pattern!r})"
                    )
                    continue
                # Drift: STRIDE recorded zero, now positive (control may
                # have been added since scan). Use a tolerance of 0 — even
                # one hit means the absence claim no longer holds.
                if isinstance(recorded, int) and recorded == 0 and new_count > 0:
                    report.issues.append(
                        f"{tid}: absence_grep_drift — pattern "
                        f"{pattern!r} now matches {new_count} location(s); "
                        f"absence claim may be stale"
                    )
    return report


# ---------------------------------------------------------------------------
# §7 clarity checks (M2 / M5c / M7 / M8 — "section7_clarity" family).
#
# Why these exist
# ---------------
# A §7 fragment can be syntactically valid (right H3 set, right table columns,
# right anchor IDs) while reading nothing like the reference threat-model. The
# four checks below close the four most common Stage-2 LLM failure modes that
# the reference contract does not catch:
#
#   * narrative_placeholder_in_section7 — Stage 2 left HTML-comment placeholders
#     in §7, so the rendered MD shows the scaffold prompt instead of prose.
#   * h4_positive_intro_present — every H4 control block must open with a
#     positive intro paragraph (≥ 25 words, NO negative openers) BEFORE the
#     `**Security assessment**` label. Without it, the reader has no idea what
#     the control IS before being told what is broken.
#   * fence_intro_sentence_present — every Mermaid or code fence inside §7
#     must be preceded by exactly one sentence ending in `:` (the reference's
#     fixed form: "The diagram shows …:", "The vulnerable login lookup …:").
#     "Naked" fences are a contract violation even when their contents are
#     correct, because they break the narrative flow the reader depends on.
#   * finding_link_duplicate — bullets under `**Relevant findings**` must not
#     repeat the finding's title (e.g. `[F-009](#f-009) — Persistent XSS — Persistent XSS`),
#     which used to happen when the pregenerator appended the title and the
#     Stage 2 LLM added a second copy unaware. The pregenerator now emits
#     bare links; this check guards against regression and against Stage 2
#     re-introducing the duplicate manually.
# ---------------------------------------------------------------------------


_SECTION7_BEGIN_RE = re.compile(r"^##\s+7\.\s", re.MULTILINE)
_SECTION_AFTER7_BEGIN_RE = re.compile(r"^##\s+(?:[8-9]|1\d)\.\s", re.MULTILINE)


def _extract_section7(md_text: str) -> tuple[str, int]:
    """Return (§7 text, starting line number) — empty string if absent.

    The starting line number is 1-based so issue messages can carry a
    clickable `line N` location relative to the original threat-model.md.
    """
    m = _SECTION7_BEGIN_RE.search(md_text)
    if not m:
        return ("", 0)
    start = m.start()
    rest = md_text[start:]
    m2 = _SECTION_AFTER7_BEGIN_RE.search(rest, pos=1)
    end = (start + m2.start()) if m2 else len(md_text)
    start_line = md_text.count("\n", 0, start) + 1
    return (md_text[start:end], start_line)


# §7 may legitimately reference NARRATIVE_PLACEHOLDER inside a fenced code
# block (the renderer agent example, the security-architecture.example.md
# style anchor reproduced inline) — the strip helper blanks fences, so we
# search the stripped form.
_NARRATIVE_PLACEHOLDER_RE = re.compile(r"NARRATIVE_PLACEHOLDER", re.IGNORECASE)


def check_section7_narrative_placeholders(md_path: Path) -> Report:
    """Hard-fail when any NARRATIVE_PLACEHOLDER token survives in §7.

    Stage 2 (appsec-threat-renderer) is contractually obliged to fill every
    scaffold placeholder. A surviving placeholder almost always means the
    LLM truncated authoring and the rendered §7 reads as a TODO list. We
    elevate this from a warning to a hard issue.
    """
    report = Report(check="section7_narrative_placeholders")
    if not md_path.is_file():
        report.issues.append(f"file not found: {md_path}")
        return report
    text = md_path.read_text(encoding="utf-8")
    section, start_line = _extract_section7(text)
    if not section:
        report.warnings.append("§7 not found in document")
        report.ok = 1
        return report
    stripped = _strip_code_fences(section)
    locations: list[int] = []
    for m in _NARRATIVE_PLACEHOLDER_RE.finditer(stripped):
        line_no = stripped.count("\n", 0, m.start()) + 1 + start_line - 1
        locations.append(line_no)
    if locations:
        loc = ", ".join(f"line {n}" for n in locations[:8])
        if len(locations) > 8:
            loc += f", +{len(locations) - 8} more"
        report.issues.append(
            f"§7 contains {len(locations)} unfilled NARRATIVE_PLACEHOLDER "
            f"token(s) at {loc} — Stage 2 must fill these before render."
        )
    report.ok = 1 if not report.issues else 0
    return report


# Negative openers that disqualify a paragraph from being a "positive intro".
# Case-insensitive, word-boundary-anchored.
_NEGATIVE_OPENERS = (
    "no ", "none", "missing", "not implemented", "not present",
    "there is no", "there are no", "nothing ", "absent",
)

# Words counted toward the 25-word floor for the positive intro paragraph.
# We tokenise on whitespace AFTER stripping inline markdown markers
# (backticks, em/en dashes, asterisks) so the count reflects readable
# words, not punctuation.
_WORD_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9\-_.]*")

# H4 heading marker — `#### <Title>` at the start of a line.
_H4_RE = re.compile(r"^####\s+(.+?)\s*$", re.MULTILINE)


def _walk_h4_blocks(section_text: str) -> list[tuple[str, str, int]]:
    """Return [(heading_text, body_text, heading_line_in_section)] per H4.

    Body runs from the line after the H4 heading up to (but not including)
    the next H3, H4, or end-of-section.
    """
    out: list[tuple[str, str, int]] = []
    h4_starts: list[tuple[int, str, int]] = []
    for m in _H4_RE.finditer(section_text):
        line_no = section_text.count("\n", 0, m.start()) + 1
        h4_starts.append((m.start(), m.group(1).strip(), line_no))
    # Boundary markers: next H3 / H4 / end-of-section.
    boundary_re = re.compile(r"^(?:###\s+\d|####\s+)", re.MULTILINE)
    for i, (start, title, line) in enumerate(h4_starts):
        # Skip the heading line itself.
        body_start = section_text.find("\n", start) + 1
        # Body ends at the next boundary (H3 or H4) AFTER this body_start.
        m_next = boundary_re.search(section_text, pos=body_start)
        body_end = m_next.start() if m_next else len(section_text)
        out.append((title, section_text[body_start:body_end], line))
    return out


def check_section7_h4_positive_intro(md_path: Path) -> Report:
    """Every H4 in §7 opens with a positive intro paragraph (≥ 25 words).

    Defects flagged:
      * the first non-blank, non-fence line under the H4 is the
        `**Security assessment**` label (i.e. no intro at all);
      * the intro paragraph is < 25 words long;
      * the intro paragraph opens with a banned negative phrase
        (`No `, `Missing`, `Not implemented`, …).
    """
    report = Report(check="section7_h4_positive_intro")
    if not md_path.is_file():
        report.issues.append(f"file not found: {md_path}")
        return report
    text = md_path.read_text(encoding="utf-8")
    section, start_line = _extract_section7(text)
    if not section:
        report.warnings.append("§7 not found in document")
        report.ok = 1
        return report
    for title, body, h4_line in _walk_h4_blocks(section):
        # Skip H4s that are §7.13's cross-cutting prose (no H4 expected
        # under §7.13) and skip any inside fenced code blocks (already
        # filtered out by virtue of _H4_RE matching at line start outside
        # of fence-aware extraction; the inline example in the prompt
        # appears in a ```markdown fence which is part of the agent file,
        # not the rendered md).
        stripped_body = _strip_code_fences(body)
        # First non-blank line that is not itself a heading.
        intro_lines: list[str] = []
        for line in stripped_body.splitlines():
            ls = line.strip()
            if not ls:
                if intro_lines:
                    break
                continue
            if ls.startswith("####") or ls.startswith("### "):
                break
            if ls.startswith("**Security assessment") or ls.startswith("**Relevant findings"):
                break
            # A `**Status:**` badge line is metadata, not the intro prose —
            # it sits directly under the H4 heading. Skip it so the positive
            # intro paragraph that follows is the one validated.
            if ls.startswith("**Status:"):
                if intro_lines:
                    break
                continue
            # An HTML comment is not prose — keep scanning.
            if ls.startswith("<!--"):
                if intro_lines:
                    break
                continue
            intro_lines.append(ls)
        intro = " ".join(intro_lines).strip()
        absolute_line = start_line + h4_line - 1
        if not intro:
            report.issues.append(
                f"§7 #### {title} (line {absolute_line}) — no positive intro "
                f"paragraph before `**Security assessment**`. Every control "
                f"must be explained in 1-3 sentences BEFORE it is assessed."
            )
            continue
        words = _WORD_TOKEN_RE.findall(intro)
        if len(words) < 25:
            report.issues.append(
                f"§7 #### {title} (line {absolute_line}) — intro paragraph "
                f"is too short ({len(words)} words; minimum 25). The intro "
                f"must name routes, libraries, and the positive flow."
            )
        lower_intro = intro.lower().lstrip("*_`")
        for opener in _NEGATIVE_OPENERS:
            if lower_intro.startswith(opener):
                report.issues.append(
                    f"§7 #### {title} (line {absolute_line}) — intro "
                    f"paragraph opens with `{opener.strip()}`. Gaps belong "
                    f"in `**Security assessment**`; the intro must describe "
                    f"what the control IS, not what is missing."
                )
                break
    report.ok = 1 if not report.issues else 0
    return report


def check_section7_h4_status(md_path: Path) -> Report:
    """Every §7 H4 sub-control carries a `**Status:**` verdict badge.

    The badge (`**Status:** 🟢/🟡/🟠/🔴 <word> — <one clause>`) is the
    reader's at-a-glance signal of whether a sub-control is a positive or a
    negative finding, and — for the two red verdicts — whether the control
    must be FIXED (Unsafe: present but defeated) or ADDED (Missing: never
    built). The pregenerator emits it deterministically under each H4; this
    check flags any sub-control that lost it during Stage-2 enrichment.
    Warning-level: a missing badge degrades scannability but does not corrupt
    the document, so it should not hard-fail an otherwise valid render.
    """
    report = Report(check="section7_h4_status")
    if not md_path.is_file():
        report.issues.append(f"file not found: {md_path}")
        return report
    text = md_path.read_text(encoding="utf-8")
    section, start_line = _extract_section7(text)
    if not section:
        report.ok = 1
        return report
    for title, body, h4_line in _walk_h4_blocks(section):
        stripped_body = _strip_code_fences(body)
        has_status = any(
            line.strip().startswith("**Status:") for line in stripped_body.splitlines()
        )
        if not has_status:
            absolute_line = start_line + h4_line - 1
            report.warnings.append(
                f"§7 #### {title} (line {absolute_line}) — missing "
                f"`**Status:**` verdict badge. Open every sub-control with "
                f"`**Status:** <icon> <word> — <one clause>` so the reader "
                f"sees the verdict (and FIX-vs-ADD for red) before the prose."
            )
    report.ok = 1 if not report.issues else 0
    return report


# Fence opener — must be at start of line, must declare a known language
# (mermaid, ts, js, yaml, dockerfile, ini, json, tsx, html, py, sh, bash).
_FENCE_OPEN_RE = re.compile(
    r"^```(mermaid|ts|js|tsx|yaml|yml|dockerfile|ini|json|html|py|sh|bash)\b",
    re.MULTILINE,
)
# A valid intro is a non-empty line ending in `:` (ignoring trailing
# whitespace) directly above the fence (blank line allowed in between).
_INTRO_TAIL_RE = re.compile(r":\s*$")


def check_section7_fence_intro_sentence(md_path: Path) -> Report:
    """Every code/Mermaid fence inside §7 is preceded by an intro sentence.

    The intro sentence is the closest preceding non-blank line. It must
    end with `:` to follow the reference's fixed form. A fence under §7.1
    inside the MECHANICAL-FROZEN overview block is exempt (no fence is
    expected there; the check searches §7.2 onwards).
    """
    report = Report(check="section7_fence_intro_sentence")
    if not md_path.is_file():
        report.issues.append(f"file not found: {md_path}")
        return report
    text = md_path.read_text(encoding="utf-8")
    section, start_line = _extract_section7(text)
    if not section:
        report.warnings.append("§7 not found in document")
        report.ok = 1
        return report
    # Limit to §7.2 onwards — the §7.1 overview is pregenerator-owned.
    m72 = re.search(r"^###\s+7\.2\s", section, re.MULTILINE)
    scope_start = m72.start() if m72 else 0
    lines = section[scope_start:].splitlines()
    abs_offset = start_line + section[:scope_start].count("\n") - 1
    for i, line in enumerate(lines):
        if not _FENCE_OPEN_RE.match(line):
            continue
        # Look back over preceding lines (skip blank lines) for the intro
        # sentence. Stop at the previous structural marker (heading or
        # label) — if we hit one before any intro sentence, there is no
        # intro.
        j = i - 1
        while j >= 0 and not lines[j].strip():
            j -= 1
        if j < 0:
            report.issues.append(
                f"§7 fence at line {abs_offset + i + 1} ({line.strip()}) — "
                f"has no introducing sentence."
            )
            continue
        prev = lines[j].rstrip()
        # Structural markers that disqualify as intro:
        if (prev.lstrip().startswith("####") or
            prev.lstrip().startswith("### ") or
            prev.strip().startswith("**Security assessment") or
            prev.strip().startswith("**Relevant findings") or
            prev.strip().startswith("**Verdict") or
            prev.strip().startswith("**Controls covered") or
            prev.strip().startswith("**Implemented controls") or
            prev.strip().startswith("**Assessment")):
            report.issues.append(
                f"§7 fence at line {abs_offset + i + 1} — preceding line is "
                f"a structural marker (`{prev.strip()[:40]}…`), not an "
                f"introducing sentence. Add one sentence ending in `:` "
                f"such as 'The diagram shows …:' or 'The vulnerable code …:'."
            )
            continue
        if not _INTRO_TAIL_RE.search(prev):
            report.issues.append(
                f"§7 fence at line {abs_offset + i + 1} — preceding line "
                f"`{prev.strip()[:60]}…` does not end in `:`. The reference "
                f"form is 'The diagram shows …:' for diagrams and 'The/This "
                f"… shows/illustrates/demonstrates …:' for code excerpts."
            )
    report.ok = 1 if not report.issues else 0
    return report


# Detects bullets of the form
#   `- [F-009](#f-009) — Persistent XSS … - Persistent XSS …`
# where both trailers carry the same titlecase noun phrase. We use the
# first 3+ Unicode "word"-style tokens after the F-link and check whether
# they reappear later in the bullet.
_FINDING_BULLET_RE = re.compile(
    r"^-\s*\[(F-\d{2,4})\]\(#f-\d{2,4}\)\s*[—–-]?\s*(.+)$",
    re.MULTILINE,
)


def check_section7_finding_link_duplicate(md_path: Path) -> Report:
    """Flag `[F-NNN](#f-nnn) — TITLE — TITLE` duplicate-title bullets in §7."""
    report = Report(check="section7_finding_link_duplicate")
    if not md_path.is_file():
        report.issues.append(f"file not found: {md_path}")
        return report
    text = md_path.read_text(encoding="utf-8")
    section, start_line = _extract_section7(text)
    if not section:
        report.warnings.append("§7 not found in document")
        report.ok = 1
        return report
    for m in _FINDING_BULLET_RE.finditer(section):
        trailer = m.group(2).strip()
        # Split the trailer on em-dash / en-dash / `- `. If we get >= 2
        # non-empty halves that share a 3+ word phrase, we have a dup.
        parts = re.split(r"\s+[—–-]\s+", trailer)
        if len(parts) < 2:
            continue
        # Tokenise each part.
        def tokens(s: str) -> list[str]:
            return [t.lower() for t in re.findall(r"[A-Za-z]{3,}", s)]
        first = tokens(parts[0])
        rest = " ".join(tokens(" ".join(parts[1:])))
        if not first:
            continue
        # Take the first 3 (or all) content tokens from `first`; if the
        # same triple appears in `rest`, treat as duplicate.
        head = " ".join(first[:3])
        if head and head in rest:
            line_no = start_line + section.count("\n", 0, m.start())
            report.issues.append(
                f"§7 finding bullet duplicates title at line {line_no}: "
                f"`{m.group(0).strip()[:120]}…` — the bullet must carry the "
                f"F-link and exactly one rationale sentence, not the "
                f"finding title twice."
            )
    report.ok = 1 if not report.issues else 0
    return report


_RELEVANT_FINDING_BULLET_RE = re.compile(
    r"^[ \t]*[-*][ \t]+\[(F-\d{3,4})\]\(#f-\d{3,4}\)[ \t]+[—\-][ \t]+(.+?)\s*$",
    re.MULTILINE,
)

# Stop-words ignored when comparing F-NNN title tokens against rationale text.
_SEMANTIC_STOPWORDS: frozenset[str] = frozenset({
    "the", "a", "an", "of", "for", "and", "or", "via", "in", "on", "to",
    "with", "from", "by", "is", "are", "be", "as", "at", "this", "that",
    "has", "have", "had", "any", "all", "can", "may", "will", "would",
    "should", "could", "such", "into", "onto", "uses", "use", "used",
    "using", "than", "then", "when", "where", "what", "how", "via",
    # Generic security filler that doesn't disambiguate one finding from another
    "attack", "attacker", "user", "users", "vulnerable", "vulnerability",
    "finding", "control", "controls", "issue", "endpoint", "endpoints",
    "request", "response", "data", "value", "values",
})


def _semantic_tokens(text: str) -> set[str]:
    """Lower-cased alpha-only tokens ≥3 chars, stop-words filtered."""
    if not text:
        return set()
    raw = re.findall(r"[A-Za-z][A-Za-z\-]{2,}", text)
    return {t.lower() for t in raw if t.lower() not in _SEMANTIC_STOPWORDS}


def check_section7_finding_reference_semantic(md_path: Path) -> Report:
    """Flag `**Relevant findings**` bullets whose F-NNN reference and
    rationale sentence describe semantically different threats.

    Background (R-2 — 2026-05): Stage-2 and repair-mode renderers occasionally
    write `[F-004](#f-004) — Algorithm confusion allows forging tokens` where
    F-004's actual title in `threat-model.yaml` is `"SQL Injection — search.ts:23"`.
    The link target is well-formed but the rationale describes a different
    finding entirely — a reader following the link gets visible drift.

    Heuristic: compute the set of content tokens in the threat's title
    (excluding the filename suffix) and the set of content tokens in the
    rationale. Flag as a warning when overlap = 0 AND both sets are
    non-empty AND the rationale is long enough to expect at least one
    overlap (≥ 6 tokens).

    Soft check — emits warnings, not blocking issues, because the heuristic
    can have false-positives on legitimate cross-references (e.g. an F-NNN
    cited only to point at related context).
    """
    report = Report(check="section7_finding_reference_semantic")
    if not md_path.is_file():
        report.issues.append(f"file not found: {md_path}")
        return report
    text = md_path.read_text(encoding="utf-8")
    section, start_line = _extract_section7(text)
    if not section:
        report.warnings.append("§7 not found in document")
        report.ok = 1
        return report

    label_index = _load_label_index(md_path)
    if not label_index:
        report.warnings.append("threat-model.yaml not readable; semantic check skipped")
        report.ok = 1
        return report

    for m in _RELEVANT_FINDING_BULLET_RE.finditer(section):
        fid = m.group(1)
        rationale = m.group(2).strip()
        entry = label_index.get(fid.upper()) or label_index.get(fid.replace("F-", "T-").upper())
        if not entry:
            continue
        title = entry[0] if isinstance(entry, tuple) else entry
        # Strip the file-path suffix from the title — it adds noise that
        # rarely appears in rationale prose.
        title_clean = re.sub(r"\s*[—\-(][^—\-(]*\.\w+(:\d+)?\)?\s*$", "", title)
        title_tokens = _semantic_tokens(title_clean)
        rationale_tokens = _semantic_tokens(rationale)
        if not title_tokens or len(rationale_tokens) < 6:
            continue
        overlap = title_tokens & rationale_tokens
        if not overlap:
            line_no = start_line + section.count("\n", 0, m.start())
            report.warnings.append(
                f"§7 line {line_no}: rationale for [{fid}] mentions "
                f"{sorted(rationale_tokens)[:5]} but yaml title is "
                f"'{title_clean}' — likely wrong F-NNN reference "
                f"(Repair-Agent content drift / wrong-finding citation)."
            )
    report.ok = 1
    return report


# ---------------------------------------------------------------------------
# End of §7 clarity checks.
# ---------------------------------------------------------------------------


def cmd_autofix(md_path: Path, repo_root: Path) -> int:
    """Run only the five in-place auto-fixing passes and write the corrected
    Markdown back: links, anchors, MS structure, cell-format, and the
    heading-attribute strip.

    This is the mutation half of ``cmd_all`` without the detector battery. The
    skill calls it on every run so the persisted Markdown is always clean, and
    defers the full detector pre-pass (``cmd_all`` -> ``.qa-prepass.json``) to
    the agent-dispatch path where the JSON is actually consumed. On the clean
    fast path the QA agent is skipped, so running the ~45 detectors there only
    populates a file nobody reads. Returns 0 — auto-fixes are not failures.
    """
    md = md_path.resolve()
    _PrePass.reset()
    link_report, text_after_links = check_links(md, repo_root)
    if text_after_links != md.read_text(encoding="utf-8"):
        md.write_text(text_after_links, encoding="utf-8")
        _PrePass.reset()
    anchor_report, text_after_anchors = linkify_anchors(md)
    if text_after_anchors != md.read_text(encoding="utf-8"):
        md.write_text(text_after_anchors, encoding="utf-8")
        _PrePass.reset()
    ms_report, text_after_ms = check_ms_structure(md)
    if text_after_ms != md.read_text(encoding="utf-8"):
        md.write_text(text_after_ms, encoding="utf-8")
        _PrePass.reset()
    cell_report, text_after_cell = check_cell_format(md)
    if text_after_cell != md.read_text(encoding="utf-8"):
        md.write_text(text_after_cell, encoding="utf-8")
        _PrePass.reset()
    attr_strip_report, _ = strip_heading_attribute_artifacts(md)
    if attr_strip_report.fixes:
        _PrePass.reset()
    fixes = (
        len(link_report.fixes)
        + len(anchor_report.fixes)
        + len(ms_report.fixes)
        + len(cell_report.fixes)
        + len(attr_strip_report.fixes)
    )
    print(json.dumps({"autofix": {"fix_count": fixes}}, indent=2))
    return 0


def cmd_all(md_path: Path, repo_root: Path) -> int:
    md = md_path.resolve()
    # Reset the pre-pass cache at the start of every `all` invocation.
    # Auto-repair mutations (Check 1 / Check 10 / Check MS) write the
    # md back to disk; the cache is invalidated implicitly through the
    # ``_PrePass.text()`` mtime-of-text check in subsequent calls.
    _PrePass.reset()
    # Check 1 — links (apply in place). Each in-place write invalidates
    # the pre-pass cache so the next check re-reads fresh content.
    link_report, text_after_links = check_links(md, repo_root)
    if text_after_links != md.read_text(encoding="utf-8"):
        md.write_text(text_after_links, encoding="utf-8")
        _PrePass.reset()
    # Check 10 — anchors (apply in place against the already-linkified text).
    anchor_report, text_after_anchors = linkify_anchors(md)
    if text_after_anchors != md.read_text(encoding="utf-8"):
        md.write_text(text_after_anchors, encoding="utf-8")
        _PrePass.reset()
    # Check MS structure (apply safe rewrites in place).
    ms_report, text_after_ms = check_ms_structure(md)
    if text_after_ms != md.read_text(encoding="utf-8"):
        md.write_text(text_after_ms, encoding="utf-8")
        _PrePass.reset()
    # Cell format — stack multi-link ID cells with <br/>.  Auto-fix in
    # place so downstream presentation checks see the corrected text.
    cell_report, text_after_cell = check_cell_format(md)
    if text_after_cell != md.read_text(encoding="utf-8"):
        md.write_text(text_after_cell, encoding="utf-8")
        _PrePass.reset()
    contract_report = check_contract(md)
    xref_report = check_xrefs(md)
    inv_report = check_invariants(md)
    # Check 7c-ext — requirement-sourced threats must carry Violated annotation.
    _check_requirements_violated_coverage(md, md.parent, inv_report)
    # Strip Pandoc/Kramdown `{#anchor ...}` and `data-source-line=...` residue
    # from headings BEFORE hygiene runs — otherwise the trailer is flagged as
    # a fatal heading defect even though it's mechanically strippable.
    attr_strip_report, _ = strip_heading_attribute_artifacts(md)
    if attr_strip_report.fixes:
        _PrePass.reset()
    heading_report = check_heading_hygiene(md)
    toc_report = check_toc_closure(md)
    # New structural / rendering checks introduced to catch LLM-authored
    # defects that the contract gate alone does not notice (nested TOC
    # links, broken mermaid, thin metadata).
    mermaid_report = check_mermaid_syntax(md)
    toc_nested_report = check_toc_nested_links(md)
    infobox_report = check_infobox_completeness(md)
    # Legacy §7.3 IAM per-auth-method decomposition (no-op in current v2).
    auth_report = check_auth_method_decomposition(md)
    # Current v2 §7 — every covered control links to a concrete H4
    # subsection with Security assessment + Relevant findings labels.
    control_coverage_report = check_control_subsection_coverage(md)
    # Current v2 §7 — `Relevant findings` must be a standalone label followed
    # by bullets, not a dense inline reference sentence.
    relevant_findings_report = check_relevant_findings_bullet_list(md)
    # Current v2 §7.6 — Input Boundary Validation must open with a general
    # validation-approach H4 before the specific boundary sub-blocks.
    validation_approach_report = check_validation_approach_first(md)
    # Sprint 2 Item #5 — placeholders + yaml/md consistency.
    placeholder_report = check_placeholders(md)
    # yaml sits next to the md; allow absence (first-ever run before yaml is
    # written) to be a non-blocking warning rather than a hard failure.
    yaml_sibling = md.parent / "threat-model.yaml"
    yaml_md_report = check_yaml_md_consistency(md, yaml_sibling)
    # Security Posture at a Glance — strict structural gate (D/C/F/G/T/L
    # invariants in `data/sections-contract.yaml`).
    posture_report = check_security_posture_structure(md)
    # Diagram-compactness — §2.3 / §2.4 layout, node count, label width,
    # and threat-traceability (post-2026-05). Drives Re-Render-Loop when
    # the LLM has bloated either diagram beyond the contract limits.
    compactness_report = check_diagram_compactness(md)
    # Chain-compactness — §3.1 per-chain limits (graph LR, max blocks,
    # max nodes per block, classDef, threat-per-block).
    chain_compactness_report = check_chain_compactness(md)
    # Chain T-ID consistency — verify chain-overview node labels share at
    # least one content keyword with the actual finding title in
    # threat-model.yaml. Catches LLM-authored chain diagrams that
    # reference completely the wrong threat (P2 — A2).
    chain_tid_report = check_chain_tid_consistency(md, md.parent)
    # Walkthrough coverage + depth — one §3.x per Critical threat in yaml,
    # with non-trivial body and `alt Current state` / `else After mitigation`
    # branch in each sequenceDiagram. Closes the regression where the renderer
    # silently produced 3 stub walkthroughs for 9 Criticals (2026-05).
    walkthrough_coverage_report = check_walkthrough_coverage(md, md.parent)
    walkthrough_depth_report = check_walkthrough_depth(md, md.parent)
    # Fix (5): recon-to-IAM bridge — cross-validate recon TOTP/2FA signals
    # against the configured identity/authentication section.
    recon_iam_report = check_recon_iam_bridge(md, md.parent)
    # Fix (7): dense "Where it falls short." paragraphs — warning-only.
    falls_short_report = check_falls_short_format(md)
    # M-12c: path-shaped tokens that should be backticked per prose-style Rule 6.
    inline_code_report = check_inline_code_format(md)
    label_as_code_report = check_label_as_code(md)
    # M1: evidence-integrity check — line in-range, not pure-noise,
    # absence-greps replayed. Reads .threats-merged.json (preferred) or
    # threat-model.yaml. No-op when neither is present.
    evidence_integrity_report = check_evidence_integrity(md.parent, repo_root)
    # Unfounded perimeter-control absence claims — flags prose like
    # "no WAF", "missing IDS", "no secret scanning" that a source-tree
    # scan has no signal on. Positive identification is allowed.
    perimeter_report = check_unfounded_perimeter_claims(md)
    # Hard secret-leak gate — scans threat-model.md AND threat-model.yaml for
    # raw, unmasked secrets. Properly redacted snippets (`AIza****`,
    # `**** (12 chars)`) are ignored. A hit blocks release.
    unmasked_secrets_report = check_unmasked_secrets(md, md.parent)
    # Operational Strengths quality — flag rows naming HTTP response-header
    # hardening or other tactical baseline hygiene instead of architectural
    # strengths. The renderer filters these via `excluded_from_strengths`;
    # this check catches overrides and legacy fragments that slip through.
    strengths_report = check_strengths_row_quality(md)
    # Warning-only §7 prose checks (paragraph_density, finding_range_homogeneous,
    # dependency_cross_ref, na_against_recon, architectural_prose, generic_phrases,
    # rhetorical_severity, section_opener_restates_heading) were retired from the
    # `all` pre-pass: they reached no actuator (not in build_repair_plan, no agent
    # handoff action) and the underlying authoring rules are enforced at the
    # renderer. Each remains callable as a standalone subcommand.
    subcontrol_naming_report = check_subcontrol_naming_canonical(md)
    ai_padding_report = check_ai_padding_phrases(md)
    # §7 clarity check (M7) — H4 status label. The sibling M2/M5c/M8 checks
    # (narrative placeholders, positive-intro, fence-intro, finding-link
    # duplicate/semantic) were retired from the `all` pre-pass: they reached
    # no actuator (not in build_repair_plan, no agent handoff action) and the
    # underlying authoring rule is enforced at the renderer. Each remains
    # callable as a standalone subcommand.
    section7_h4_status_report = check_section7_h4_status(md)
    summary = {
        "links": link_report.as_dict(),
        "anchors": anchor_report.as_dict(),
        "ms_structure": ms_report.as_dict(),
        "cell_format": cell_report.as_dict(),
        "contract": contract_report.as_dict(),
        "xrefs": xref_report.as_dict(),
        "invariants": inv_report.as_dict(),
        "heading_hygiene": heading_report.as_dict(),
        "toc_closure": toc_report.as_dict(),
        "mermaid_syntax": mermaid_report.as_dict(),
        "toc_nested_links": toc_nested_report.as_dict(),
        "infobox_completeness": infobox_report.as_dict(),
        "auth_method_decomposition": auth_report.as_dict(),
        "control_subsection_coverage": control_coverage_report.as_dict(),
        "relevant_findings_bullet_list": relevant_findings_report.as_dict(),
        "validation_approach_first": validation_approach_report.as_dict(),
        "placeholders": placeholder_report.as_dict(),
        "yaml_md_consistency": yaml_md_report.as_dict(),
        "posture_structure": posture_report.as_dict(),
        "diagram_compactness": compactness_report.as_dict(),
        "chain_compactness": chain_compactness_report.as_dict(),
        "chain_tid_consistency": chain_tid_report.as_dict(),
        "walkthrough_coverage": walkthrough_coverage_report.as_dict(),
        "walkthrough_depth": walkthrough_depth_report.as_dict(),
        "recon_iam_bridge": recon_iam_report.as_dict(),
        "falls_short_format": falls_short_report.as_dict(),
        "inline_code_format": inline_code_report.as_dict(),
        "label_as_code": label_as_code_report.as_dict(),
        "evidence_integrity": evidence_integrity_report.as_dict(),
        "unfounded_perimeter_claims": perimeter_report.as_dict(),
        "unmasked_secrets": unmasked_secrets_report.as_dict(),
        "strengths_row_quality": strengths_report.as_dict(),
        "subcontrol_naming_canonical": subcontrol_naming_report.as_dict(),
        "ai_padding_phrases": ai_padding_report.as_dict(),
        "section7_h4_status": section7_h4_status_report.as_dict(),
    }
    print(json.dumps(summary, indent=2))
    total_issues = sum(s["issue_count"] for s in summary.values())
    return 0 if total_issues == 0 else 1


# ---------------------------------------------------------------------------
# Check 15 — Heading hygiene. A heading must be plain text, optionally with
# a single trailing `([T-NNN](#t-nnn))` citation. Anything else — embedded
# `[label](url) — text` pairs, unbalanced parentheses, unclosed backticks —
# is a structural defect that breaks slug generation and TOC resolution.
# ---------------------------------------------------------------------------

_HEADING_RE = re.compile(r"^(?P<hashes>\s{0,3}#{1,6})\s+(?P<text>.*?)\s*$", re.MULTILINE)

# Trailing Pandoc/Kramdown attribute syntax `{#anchor key=val ...}` (and
# any `data-source-line=...` markdown-it source-map residue) that some
# upstream tooling or hallucinating LLM passes append to heading text.
# These never belong in the visible heading — they break TOC slug
# resolution and render as literal text in gfm. Stripped before hygiene.
_HEADING_ATTR_TRAILER_RE = re.compile(r"\s*\{[^{}]*\}\s*$")
_HEADING_DATA_SOURCE_RE = re.compile(r'\s*\{?\s*#?[\w-]*\s*data-source-line\s*=[^}]*\}?\s*$')


def strip_heading_attribute_artifacts(md_path: Path) -> tuple[Report, str]:
    """Strip Pandoc-style `{#anchor ...}` and `data-source-line=...` residue
    from heading lines. Headings render as plain text in gfm and the
    attribute syntax leaks into the visible title. Operates in-place.
    """
    report = Report(check="heading_attribute_strip")
    text = md_path.read_text(encoding="utf-8")
    out_lines: list[str] = []
    in_fence = False
    stripped = 0
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            out_lines.append(line)
            continue
        if in_fence or not line.lstrip().startswith("#"):
            out_lines.append(line)
            continue
        new = line
        # Strip an open-ended `{#... data-source-line=` even when the
        # closing `}` is missing — the truncated form is exactly what
        # users have observed leaking into visible headings.
        new = re.sub(r"\s*\{[^}\n]*data-source-line[^}\n]*\}?\s*(\n?)$", r"\1", new)
        # Pandoc/Kramdown `{#anchor key=val}` trailer.
        new = _HEADING_ATTR_TRAILER_RE.sub("", new.rstrip("\n")) + ("\n" if new.endswith("\n") else "")
        if new != line:
            stripped += 1
        out_lines.append(new)
    if stripped:
        report.fixes.append(f"stripped attribute trailer from {stripped} headings")
        text = "".join(out_lines)
        md_path.write_text(text, encoding="utf-8")
    return report, text


def check_heading_hygiene(md_path: Path) -> Report:
    """Flag headings that contain markdown-link expansion artefacts."""
    report = Report(check="heading_hygiene")
    text = _read_md_cleaned(md_path)
    for m in _HEADING_RE.finditer(text):
        heading_text = m.group("text")
        # Pandoc/Kramdown attribute trailer leaking into visible heading?
        if "{#" in heading_text or "data-source-line" in heading_text:
            report.issues.append(
                f"heading contains attribute-syntax artefact ({{#...}} / "
                f"data-source-line): `{heading_text[:120]}`"
            )
            continue
        # Unbalanced parens in the heading?
        if heading_text.count("(") != heading_text.count(")"):
            report.issues.append(f"unbalanced parentheses in heading: `{heading_text[:120]}`")
            continue
        # Unclosed backticks?
        if heading_text.count("`") % 2 != 0:
            report.issues.append(f"unclosed backtick in heading: `{heading_text[:120]}`")
            continue
        # More than one markdown link inside the heading?
        link_count = len(re.findall(r"\[[^\]]+\]\([^)]+\)", heading_text))
        if link_count > 1:
            report.issues.append(f"{link_count} markdown links in heading (max 1 allowed): `{heading_text[:120]}`")
            continue
        # A link followed by an em-dash + more text suggests the composer
        # expanded a `[T-NNN](#t-nnn)` with a label inside the heading.
        if re.search(r"\]\([^)]+\)\s*—", heading_text):
            report.issues.append(f"heading contains `[...]([...]) — <text>` expansion: `{heading_text[:120]}`")
            continue
        # Heading length budget. Long headings (full-sentence threat titles
        # like "MD5 Password Hashing Combined with SQL Injection Enables
        # Full Account Takeover") wrap badly in TOCs, blow up right-side
        # outline panels, and fail to be scannable. Threshold:
        #   ≤ 80 chars : clean
        #   81–100     : warning (informational, doesn't block)
        #   > 100      : issue (flagged for repair)
        # Length includes the leading "N.M " prefix but excludes the `### `.
        heading_len = len(heading_text)
        if heading_len > 100:
            report.issues.append(
                f"heading length {heading_len} chars exceeds 100-char "
                f"hard limit — shorten the title (move the long form to "
                f"the body): `{heading_text[:120]}`"
            )
            continue
        if heading_len > 80:
            report.warnings.append(
                f"heading length {heading_len} chars exceeds 80-char "
                f"soft limit — consider shortening the title: "
                f"`{heading_text[:120]}`"
            )
        report.ok += 1
    return report


# ---------------------------------------------------------------------------
# Check 16 — TOC link closure. Every `[label](#slug)` link in the document
# that points at an in-document anchor must resolve to either:
#   (a) an `<a id="slug">` declaration somewhere in the body, OR
#   (b) the slug of an existing heading (via GitHub slug rules).
# Headings below the TOC fix points 3.2–3.9 would otherwise stay broken.
# ---------------------------------------------------------------------------


from _slug import github_slug as _github_slug  # noqa: E402  (R8 — single source of truth)


def check_toc_closure(md_path: Path) -> Report:
    """Every `[..](#xyz)` link must resolve to something inside the doc."""
    report = Report(check="toc_closure")
    raw = md_path.read_text(encoding="utf-8")
    text = _strip_code_fences(raw)

    # Build the anchor universe.
    heading_slugs: set[str] = set()
    for m in _HEADING_RE.finditer(text):
        heading_slugs.add(_github_slug(m.group("text")))
    a_ids: set[str] = set(re.findall(r'<a\s+id="([^"]+)"', text))
    anchors = heading_slugs | a_ids
    anchors_lower = {a.lower() for a in anchors}

    # Find every in-doc link `](#...)`.
    broken = 0
    for m in re.finditer(r"\]\(#([^)]+)\)", text):
        slug = m.group(1).strip()
        if not slug:
            continue
        if slug in anchors:
            report.ok += 1
            continue
        # Allow case-folded match.
        if slug.lower() in anchors_lower:
            report.ok += 1
            continue
        broken += 1
        if broken <= 25:  # cap the report payload
            report.issues.append(f"unresolved TOC/link anchor: #{slug}")
    if broken > 25:
        report.issues.append(f"…and {broken - 25} more unresolved anchors (truncated)")
    return report


# ---------------------------------------------------------------------------
# Check 16 — Mermaid syntax. Two-layer validation:
#
#   Layer A (always) — pure-Python lint of common rendering failures for
#   sequenceDiagram and graph / flowchart blocks. Narrow but free of
#   external dependencies:
#     1. Unescaped `"` inside a sequence message or note (`A->>B: foo "x"`).
#     2. Parens in `participant X as <alias>` aliases without quoting.
#     2b. Literal `;` in sequence messages / notes — mermaid statement terminator.
#     3. `alt` branch labels that are plain prose ("current vulnerable flow")
#        instead of the required "Current state — T-NNN" convention.
#
#   Layer B (authoritative, enabled when the node validator is available) —
#   shells out to scripts/mermaid_validate.mjs, which embeds the real Mermaid
#   parser. This catches every grammar violation Layer A misses (missing
#   `end` on `alt` blocks, unmatched `subgraph`/`end`, invalid arrow
#   operators, bare `[`/`{` in node labels, …). Layer B gracefully no-ops
#   when Node, the mermaid core package, or jsdom aren't available; missing
#   deps are reported once at the top of the run as a soft warning, not per
#   diagram. See scripts/mermaid_validate.mjs for install instructions.
# ---------------------------------------------------------------------------

_MERMAID_FENCE_RE = re.compile(
    r"^```mermaid\s*\n(?P<body>.*?)\n^```",
    flags=re.MULTILINE | re.DOTALL,
)

_MERMAID_VALIDATOR_JS = Path(__file__).resolve().parent / "mermaid_validate.mjs"


def _current_h2_title(md_text: str, pos: int) -> str:
    """Return the nearest preceding H2 title at byte offset ``pos``."""
    matches = list(re.finditer(r"^##\s+(.+?)\s*$", md_text[:pos], re.MULTILINE))
    return matches[-1].group(1).strip() if matches else ""


def check_mermaid_syntax(md_path: Path) -> Report:
    """Flag mermaid blocks with known-bad syntax patterns."""
    report = Report(check="mermaid_syntax")
    raw = md_path.read_text(encoding="utf-8")
    for block_idx, m in enumerate(_MERMAID_FENCE_RE.finditer(raw), start=1):
        body = m.group("body")
        line_offset = raw[: m.start()].count("\n") + 1  # 1-based line of ```mermaid
        h2_title = _current_h2_title(raw, m.start())
        in_sec7 = h2_title.startswith("7. Security Architecture")
        in_attack_walkthroughs = h2_title.startswith("3. Attack Walkthroughs")
        # Heuristic: only lint sequenceDiagram/flowchart/graph blocks. Skip
        # other diagram types (gantt, erDiagram, journey, …) to avoid false
        # positives on syntaxes we do not model.
        # Diagram type = first line that isn't a `%%{init}%%` directive or a
        # `%%` comment (a leading init directive must not hide the type).
        diagram_type = ""
        for _l in body.splitlines():
            _s = _l.strip()
            if not _s or _s.startswith("%%"):
                continue
            diagram_type = _s.split()[0]
            break
        if diagram_type not in {"sequenceDiagram", "flowchart", "graph"}:
            continue

        # (4) Block-balance tracker. Counts open `alt`/`opt`/`loop`/`par`
        # blocks (sequenceDiagram) and `subgraph` blocks (flowchart/graph),
        # decrements on `end`. Detects two showstopper bugs the per-line
        # checks above don't see:
        #   • `end` followed by `else <label>` — the `end` prematurely
        #     closes the alt and `else` becomes a parse error.
        #     Observed in juice-shop §3.2/3.3/3.4 walkthroughs.
        #   • Unclosed blocks at end-of-block (depth > 0).
        block_depth = 0
        last_opener_kind: str = ""  # "alt" | "opt" | "loop" | "par" | "subgraph"
        end_then_else_caught: bool = False

        for rel_no, line in enumerate(body.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("%%"):
                continue
            abs_line_bal = line_offset + rel_no
            if diagram_type == "sequenceDiagram":
                if re.match(r"^(alt|opt|loop|par)(\s|$)", stripped):
                    block_depth += 1
                    last_opener_kind = stripped.split()[0]
                elif stripped == "end":
                    block_depth -= 1
                    last_opener_kind = ""
                    if block_depth < 0:
                        report.issues.append(
                            f"mermaid block #{block_idx} line ~{abs_line_bal}: "
                            f"'end' without matching 'alt/opt/loop/par' opener — "
                            f"unbalanced block close"
                        )
                        block_depth = 0
                elif re.match(r"^else(\s|$)", stripped) and block_depth == 0:
                    # `else` outside any alt block — Mermaid parse error.
                    end_then_else_caught = True
                    report.issues.append(
                        f"mermaid block #{block_idx} line ~{abs_line_bal}: "
                        f"'else' outside any 'alt' block (a preceding 'end' "
                        f"likely closed the alt prematurely). Remove the "
                        f"premature 'end' so 'else' sits inside the alt/end "
                        f"pair: {stripped[:80]!r}"
                    )
            elif diagram_type in ("flowchart", "graph"):
                if stripped.startswith("subgraph "):
                    block_depth += 1
                    last_opener_kind = "subgraph"
                elif stripped == "end":
                    block_depth -= 1
                    last_opener_kind = ""
                    if block_depth < 0:
                        report.issues.append(
                            f"mermaid block #{block_idx} line ~{abs_line_bal}: "
                            f"'end' without matching 'subgraph' — unbalanced "
                            f"block close"
                        )
                        block_depth = 0

        if block_depth > 0:
            report.issues.append(
                f"mermaid block #{block_idx}: {block_depth} unclosed "
                f"'{last_opener_kind or 'block'}' block(s) at end of diagram"
            )

        for rel_no, line in enumerate(body.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("%%"):
                continue
            abs_line = line_offset + rel_no
            m_alt = None

            # (1) Unescaped double-quotes in sequence messages or notes.
            #     An ODD number of `"` in the payload leaves a bare quote
            #     that derails the parser. (The earlier "q >= 4 multiple
            #     quoted substrings" rule was a false positive — modern
            #     mermaid accepts multiple quoted substrings per payload,
            #     confirmed by the authoritative Layer B parser, so the
            #     rule has been removed.)
            is_message = bool(re.match(r"^\s*\w+\s*(-+>>?|--?>>?|->|-->>?)", stripped))
            is_note = stripped.lower().startswith(("note ", "note over", "note left", "note right"))
            if diagram_type == "sequenceDiagram" and (is_message or is_note):
                # Split off the payload (after the first `:` that is not part
                # of the arrow head).
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    payload = parts[1]
                    q = payload.count('"')
                    if q % 2 == 1:
                        report.issues.append(
                            f"mermaid block #{block_idx} line ~{abs_line}: "
                            f"unbalanced double-quote in sequenceDiagram payload "
                            f"(mermaid parser will fail). Escape to &quot; "
                            f"or use single quotes: {stripped[:80]!r}"
                        )

            # (2) Participant aliases with unquoted parentheses.
            if diagram_type == "sequenceDiagram" and not in_sec7:
                pm = re.match(r"^\s*participant\s+\w+\s+as\s+(.+?)\s*$", line)
                if pm:
                    alias = pm.group(1)
                    if "(" in alias and not (alias.startswith('"') and alias.endswith('"')):
                        report.issues.append(
                            f"mermaid block #{block_idx} line ~{abs_line}: "
                            f"participant alias contains unquoted '(' — "
                            f"wrap the alias in double quotes "
                            f"or remove the parens: {alias!r}"
                        )

            # (2b) Literal semicolons in sequenceDiagram messages or notes.
            #      Mermaid treats `;` as a statement terminator (grammar
            #      equivalent to newline). A payload like
            #        ATK->>DB: SELECT * FROM USERS; DROP TABLE USERS
            #      is parsed as two statements; the second one is read as
            #      an expected arrow/participant and the parser fails with
            #      "Expecting 'SOLID_OPEN_ARROW', …". Rewrite the payload
            #      with a connective word, split across two arrows, or use
            #      URL-encoded %3B in URL parameters.
            if diagram_type == "sequenceDiagram" and (is_message or is_note):
                parts = stripped.split(":", 1)
                if len(parts) == 2 and ";" in parts[1]:
                    report.issues.append(
                        f"mermaid block #{block_idx} line ~{abs_line}: "
                        f"literal ';' in sequenceDiagram payload — "
                        f"mermaid parses it as a statement terminator and "
                        f"the diagram fails to render. Use %3B in URL "
                        f"params, or rewrite with 'then' / split arrows: "
                        f"{stripped[:80]!r}"
                    )

            # (3) `alt` / `else` labels in sequenceDiagram that should
            #     follow the "Current state — T-NNN" / "After M-NNN — …"
            #     convention.
            if diagram_type == "sequenceDiagram":
                m_alt = re.match(r"^\s*(?:alt|else)\s+(.+?)\s*$", stripped)
                if m_alt and in_attack_walkthroughs:
                    label = m_alt.group(1)
                    low = label.lower()
                    ok = (
                        "current state" in low
                        or re.search(r"\bT-\d{3}\b", label) is not None
                        or re.search(r"\bafter\b", low) is not None
                        or re.search(r"\bM-\d{3}\b", label) is not None
                    )
                    if not ok:
                        report.issues.append(
                            f"mermaid block #{block_idx} line ~{abs_line}: "
                            f"alt/else label does not follow "
                            f"'Current state — T-NNN' / 'After M-NNN — …' "
                            f"convention: {label!r}"
                        )

            # (3b) `alt` / `else` labels in sequenceDiagram that contain a
            #      literal semicolon. Mermaid's grammar tokenises `;` as a
            #      statement terminator even inside alt/else label text, so
            #        alt After M-005 — Remove eval(); sanitise username
            #      is parsed as two statements and the diagram fails to render.
            #      Fix: replace `;` with ` then` or split into two alt blocks.
            if diagram_type == "sequenceDiagram" and m_alt:
                if ";" in m_alt.group(1):
                    report.issues.append(
                        f"mermaid block #{block_idx} line ~{abs_line}: "
                        f"literal ';' in alt/else label — mermaid grammar "
                        f"parses it as a statement terminator. Replace with "
                        f"' then' or split into two alt blocks: "
                        f"{stripped[:80]!r}"
                    )

            # (3c) HTML tags in sequenceDiagram message payloads.
            #      `<br/>` is valid in flowchart node labels but NOT in
            #      sequence-diagram arrow payloads — the Mermaid parser does
            #      not interpret HTML in that context and the diagram fails.
            #      Use a short natural-language connector or split the arrow.
            if diagram_type == "sequenceDiagram" and is_message:
                parts_html = stripped.split(":", 1)
                if len(parts_html) == 2 and re.search(r"<[a-zA-Z][^>]*>", parts_html[1]):
                    report.issues.append(
                        f"mermaid block #{block_idx} line ~{abs_line}: "
                        f"HTML tag in sequenceDiagram message payload — "
                        f"not valid Mermaid syntax. Use plain text or split "
                        f"into two arrows: {stripped[:80]!r}"
                    )

            # (4) flowchart/graph — `linkStyle` without an index list. Mermaid
            # grammar requires `linkStyle <num>(,<num>)* <styles>`; emitting
            # `linkStyle      stroke:red` (no index) is a parser error that
            # crashes the entire diagram. Common cause: Jinja template
            # interpolation produced an empty list (e.g. zero attack arrows).
            if diagram_type in ("flowchart", "graph"):
                m_ls = re.match(r"^\s*linkStyle\s+(\S+)", stripped)
                if m_ls:
                    first_token = m_ls.group(1)
                    if not re.match(r"^\d+(?:\s*,\s*\d+)*$", first_token):
                        report.issues.append(
                            f"mermaid block #{block_idx} line ~{abs_line}: "
                            f"linkStyle missing index list — Mermaid grammar "
                            f"requires `linkStyle <N>(,<N>)* <styles>`. Got: "
                            f"{stripped[:80]!r}. Common cause: empty index "
                            f"list from a template interpolation; gate the "
                            f"linkStyle line on a non-empty index list."
                        )

            # (5) flowchart/graph — multi-class chaining `:::class1:::class2`.
            # Mermaid 11+ accepts only ONE classDef per node; `:::a:::b` is a
            # parse error. Single-class is fine; flag any node decorator that
            # contains two `:::` sequences.
            if diagram_type in ("flowchart", "graph"):
                if re.search(r":::\w[\w-]*:::\w", stripped):
                    report.issues.append(
                        f"mermaid block #{block_idx} line ~{abs_line}: "
                        f"multi-class chaining `:::a:::b` is not valid "
                        f"Mermaid grammar — use a single `classDef` (combine "
                        f"styles into one class) or apply the second class "
                        f"via a separate `class <node> <className>` line. "
                        f"Got: {stripped[:80]!r}"
                    )

            # (6) flowchart/graph — `\n` literal newlines inside node labels.
            # Mermaid 10+ in HTML-mode does not honour `\n` as a line break;
            # `<br/>` is the correct escape. The parser does not error on it
            # but the rendered label collapses to a single line.
            if diagram_type in ("flowchart", "graph"):
                # Quoted labels: A["text\ntext"] or A("text\ntext") etc.
                if re.search(r'"[^"]*\\n[^"]*"', line):
                    report.issues.append(
                        f"mermaid block #{block_idx} line ~{abs_line}: "
                        f"`\\n` literal in node label — modern Mermaid renders "
                        f"this as the two characters `\\n`, not a line break. "
                        f"Use `<br/>` (HTML break) instead. Got: "
                        f"{stripped[:80]!r}"
                    )

            report.ok += 1

    # Layer C — deterministic auto-fix for two known false-negative patterns
    # that Layer A's regex check accepts but Mermaid's parser rejects:
    #   1. sequenceDiagram `participant X as "..."` quoted aliases —
    #      Mermaid's sequenceDiagram grammar does NOT support quoted
    #      aliases after `as`. The alias must be an unquoted token. The
    #      regex pre-pass (rule 2) explicitly skipped quoted aliases as
    #      "OK", letting them ship to the rendered MD.
    #   2. flowchart `[label]` with unbalanced '(' from `…` truncation —
    #      typically introduced by `_short_title()` in
    #      walkthrough_renderer.py when a finding title ending in
    #      `(<path>)` is cut mid-paren. The `(` is interpreted by
    #      Mermaid as the start of round-rect node syntax `(text)`
    #      inside `[...]` and aborts the diagram.
    #
    # The template-level fix in walkthrough_renderer.py +
    # data/walkthrough-templates/*.yaml is the primary remediation.
    # This Layer C auto-fix is a safety net for: (a) LLM-authored content
    # at --thorough that re-introduces the patterns; (b) environments
    # where Layer B (jsdom + @mermaid-js/mermaid-cli) is unavailable.
    # Both rules are idempotent — running a second time on the patched
    # text is a no-op.
    new_raw, autofix_descriptions = _apply_mermaid_autofixes(raw)
    if new_raw != raw:
        md_path.write_text(new_raw, encoding="utf-8")
        raw = new_raw
        report.fixes.extend(autofix_descriptions)

    # Layer B — authoritative parse. Only runs if the Node validator and its
    # optional deps are installed. When it runs, it catches grammar-level
    # breakages the regex layer cannot see. When it can't run (no Node,
    # missing jsdom / mermaid core), we attach a single informational issue
    # to the report so the orchestrator knows Layer B was skipped — this
    # does NOT trigger Re-Render Loop actions on its own.
    auth_issues, auth_skipped = _run_authoritative_mermaid_parse(raw)
    if auth_skipped:
        report.warnings.append(auth_skipped)
    else:
        report.issues.extend(auth_issues)
    return report


# ---------------------------------------------------------------------------
# Deterministic auto-fix rules for known Mermaid false-negatives.
# ---------------------------------------------------------------------------

_PARTICIPANT_QUOTED_ALIAS_RE = re.compile(
    r'^(?P<lead>\s*)(?P<kind>participant|actor)\s+(?P<alias>\w+)\s+as\s+"(?P<text>[^"]+)"\s*$'
)

# Match a flowchart node label `[...]` whose content contains an opening
# `(` followed by `…` but no closing `)` — the canonical signature of a
# mid-paren truncation.
_FLOWCHART_LABEL_UNBALANCED_RE = re.compile(r"\[(?P<inner>[^\]]*?\([^)]*?…)\]")


def _apply_mermaid_autofixes(md_text: str) -> tuple[str, list[str]]:
    """Patch two known Mermaid false-negative patterns in place.

    Returns ``(new_text, fix_descriptions)``. When no patterns matched, the
    text is returned unchanged with an empty list. Idempotent: a second
    invocation on the patched text is a no-op because the post-fix forms
    no longer match either regex.
    """
    fixes: list[str] = []

    def _patch_block(match: re.Match[str]) -> str:
        body = match.group("body")
        if not body:
            return match.group(0)
        lines = body.splitlines()
        if not lines:
            return match.group(0)
        first_line = lines[0].strip()
        diagram_type = first_line.split()[0] if first_line else ""

        new_body = body

        # Rule A — strip quoted aliases from sequenceDiagram `participant`
        # / `actor` declarations. The alias text is preserved as a
        # `Note over <alias>: <text>` line directly below so the
        # information is retained in the diagram.
        if diagram_type == "sequenceDiagram":
            patched_lines: list[str] = []
            for line in new_body.splitlines():
                pm = _PARTICIPANT_QUOTED_ALIAS_RE.match(line)
                if pm:
                    lead = pm.group("lead")
                    kind = pm.group("kind")
                    alias = pm.group("alias")
                    text = pm.group("text").strip()
                    patched_lines.append(f"{lead}{kind} {alias}")
                    patched_lines.append(f"{lead}Note over {alias}: {text}")
                    fixes.append(
                        f"mermaid auto-fix (participant_alias_unquote): "
                        f"`{kind} {alias} as \"{text[:60]}\"` → "
                        f"`{kind} {alias}` + Note over {alias}"
                    )
                else:
                    patched_lines.append(line)
            new_body = "\n".join(patched_lines)

        # Rule B — drop the unbalanced `(` suffix from flowchart / graph
        # node labels. The truncated path fragment is replaced with a
        # single `…` so the label remains readable but the parser sees
        # balanced bracketing.
        if diagram_type in ("flowchart", "graph"):

            def _balance(label_match: re.Match[str]) -> str:
                inner = label_match.group("inner")
                rebuilt = re.sub(r"\s*\([^)]*…\s*$", "…", inner)

                def _ellipsize(s: str, lim: int = 60) -> str:
                    # Avoid `……` in the description when the slice happens
                    # to land on the existing `…` truncation marker.
                    out = s[:lim]
                    if len(s) > lim and not out.endswith("…"):
                        out += "…"
                    return out

                fixes.append(
                    f"mermaid auto-fix (flowchart_label_balance): "
                    f"`[{_ellipsize(inner)}]` → `[{_ellipsize(rebuilt)}]` "
                    f"(stripped unbalanced '(' suffix)"
                )
                return f"[{rebuilt}]"

            new_body = _FLOWCHART_LABEL_UNBALANCED_RE.sub(_balance, new_body)

        if new_body == body:
            return match.group(0)
        return "```mermaid\n" + new_body + "\n```"

    new_text = _MERMAID_FENCE_RE.sub(_patch_block, md_text)
    return new_text, fixes


def _run_authoritative_mermaid_parse(md_text: str) -> tuple[list[str], Optional[str]]:
    """Parse every mermaid block via scripts/mermaid_validate.mjs.

    Returns (issues, skip_reason). skip_reason is None when the validator
    ran; otherwise it is a human-readable sentence explaining why the
    authoritative layer was disabled for this run. Callers should treat a
    non-None skip_reason as informational.
    """
    if not _MERMAID_VALIDATOR_JS.exists():
        return [], (f"authoritative mermaid parse skipped — {_MERMAID_VALIDATOR_JS} not found")
    node_bin = shutil.which("node")
    if not node_bin:
        return [], ("authoritative mermaid parse skipped — node not on PATH")

    blocks = list(_MERMAID_FENCE_RE.finditer(md_text))
    if not blocks:
        return [], None

    block_payload: list[dict[str, object]] = []
    line_offsets: dict[int, int] = {}
    for idx, m in enumerate(blocks, start=1):
        block_payload.append({"idx": idx, "body": m.group("body")})
        line_offsets[idx] = md_text[: m.start()].count("\n") + 1

    timeout_s = max(30, min(180, 10 + len(block_payload) * 10))
    try:
        r = subprocess.run(
            [node_bin, str(_MERMAID_VALIDATOR_JS), "--batch-json"],
            input=_json.dumps(block_payload),
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return [], (f"authoritative mermaid parse skipped — node invocation failed: {exc.__class__.__name__}")

    # The script prints a single JSON line on stdout. Exit codes: 0 = ok,
    # 1 = one or more parse errors, 2 = environment or batch-input error.
    out = (r.stdout or "").strip().splitlines()
    payload = out[-1] if out else ""
    try:
        result = _json.loads(payload) if payload else {}
    except _json.JSONDecodeError:
        # Treat as environment error — don't flag the diagrams.
        return [], (f"authoritative mermaid parse skipped — validator output not parseable as JSON: {payload[:120]!r}")

    if r.returncode == 2 or result.get("skipped"):
        # The validator told us it can't run (missing deps or unusable input).
        return [], (
            "authoritative mermaid parse skipped — " + str(result.get("error") or "validator reported missing deps")
        )

    results = result.get("results")
    if not isinstance(results, list):
        return [], ("authoritative mermaid parse skipped — validator output did not include batch results")

    issues: list[str] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        if item.get("ok"):
            continue
        idx_raw = item.get("idx")
        idx = idx_raw if isinstance(idx_raw, int) else len(issues) + 1
        line_offset = line_offsets.get(idx, 1)
        # Parse error — extract a concise first line for the report.
        err = str(item.get("error") or "").strip()
        err_head = err.splitlines()[0] if err else "unknown parse error"
        issues.append(
            f"mermaid block #{idx} (starts at line ~{line_offset}): authoritative parse failed — {err_head[:220]}"
        )
    return issues, None


# ---------------------------------------------------------------------------
# Check 17 — TOC nested-link detection. A TOC entry must be a single-level
# `[title](#anchor)` link. The title itself must not contain `[...]` markdown
# link syntax; otherwise renderers (GitHub, VS Code, MkDocs) produce broken
# output like `[3.2 Foo ([T-001](#t-001))](#32-foo-t-001)` which doesn't link
# at all and looks visually garbled.
# ---------------------------------------------------------------------------


def check_toc_nested_links(md_path: Path) -> Report:
    """Flag markdown links whose visible text contains another link."""
    report = Report(check="toc_nested_links")
    text = _strip_code_fences(md_path.read_text(encoding="utf-8"))
    # Match `[anything](#...)`, check the `anything` for nested `](`.
    # Use a non-greedy outer match, but require the outer link to be a
    # fragment link (`#...`) — we don't care about external links here.
    for m in re.finditer(r"\[((?:[^\[\]]|\[[^\]]*\])+?)\]\(#[^)]+\)", text):
        label = m.group(1)
        if "](" in label:
            line_no = text[: m.start()].count("\n") + 1
            report.issues.append(
                f"line {line_no}: TOC/inline link label contains nested "
                f"markdown link — renderers will break. Label: {label[:100]!r}"
            )
        else:
            report.ok += 1
    return report


# ---------------------------------------------------------------------------
# Check 18 — Infobox completeness. When more than half of the optional
# project-metadata fields are empty, emit a warning so the fragment author
# knows to enrich the manifest or the yaml `project:` block. Hard-fails on
# missing `required_fields`.
# ---------------------------------------------------------------------------


def check_infobox_completeness(md_path: Path) -> Report:
    """Verify the infobox at the top of threat-model.md carries the fields
    a consumer would expect for a serious threat model."""
    report = Report(check="infobox_completeness")
    text = md_path.read_text(encoding="utf-8")
    # Grab the blockquote-table block at the very top: lines starting with
    # `> |` that form a 2-column table.
    infobox_lines: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not infobox_lines and not s.startswith(">"):
            continue  # haven't hit the infobox yet
        if s.startswith(">"):
            infobox_lines.append(s)
        elif infobox_lines:
            break  # infobox ended
    fields_present: set[str] = set()
    for row in infobox_lines:
        # Extract the bold label in `| **Label** | value |`.
        m = re.search(r"\|\s*\*\*([A-Za-z][\w /]*)\*\*\s*\|", row)
        if m:
            fields_present.add(m.group(1).strip().lower())
    required = {"project", "repository", "license"}
    optional = {"author", "description", "homepage", "runtime", "tags"}
    missing_required = sorted(required - fields_present)
    missing_optional = sorted(optional - fields_present)
    if missing_required:
        report.issues.append("infobox is missing required field(s): " + ", ".join(missing_required))
    # Warn (not fail) when too many optional fields are empty.
    if len(missing_optional) > len(optional) // 2:
        report.issues.append(
            "infobox is sparse — optional fields missing: "
            + ", ".join(missing_optional)
            + ". Manifest/LICENSE/README enrichment recommended."
        )
    report.ok = len(fields_present)
    return report


# ---------------------------------------------------------------------------
# Check — Per-auth-method decomposition of §7.3 Identity & Access Management.
#
# The contract declares under
#     sections.security_architecture.domain_required_rules
#         "7.3 Identity & Access Management":
#           - rule: auth_method_decomposition
# that every row in §7.3's control table (`Control` column) must have a
# matching `#### <method>` subsection containing its own `sequenceDiagram`
# block and a bold `**Findings in this flow:**` trailer.  T-IDs cited in the
# trailer must be a subset of the matching row's `Linked Threats` cell
# (bidirectional consistency).
#
# This check is a no-op when the contract does not declare the rule, so it
# is safe to wire into the standard pipeline.
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_MD_EMPH_RE = re.compile(r"[*_`]+")


def _extract_section_body(text: str, heading_pattern: str) -> Optional[str]:
    """Return the slice of ``text`` from the heading that matches
    ``heading_pattern`` up to (but not including) the next sibling ``### `` or
    ancestor ``## `` heading, or end-of-text. Returns None when the heading is
    not found."""
    m = re.search(heading_pattern, text, re.MULTILINE)
    if not m:
        return None
    tail = text[m.end() :]
    nxt = re.search(r"^(?:##\s|###\s)", tail, re.MULTILINE)
    return tail[: nxt.start()] if nxt else tail


def _tokens(text: str) -> set[str]:
    """Lowercase alphanumeric token set — strips markdown emphasis/link
    syntax before tokenising so `[**jwt**](x)` → {'jwt', 'x'} does not occur."""
    stripped = _strip_md(text)
    return set(_TOKEN_RE.findall(stripped.lower()))


def _strip_md(s: str) -> str:
    r"""Strip markdown link, emphasis, and backtick syntax from a cell value
    so ``[`express-jwt 0.1.3`](vscode://...)`` becomes ``express-jwt 0.1.3``."""
    s = _MD_LINK_RE.sub(r"\1", s)
    s = _MD_EMPH_RE.sub("", s)
    return s.strip()


def _parse_domain_controls_table(body: str, control_column: str = "Control") -> list[dict]:
    """Parse the first pipe-table inside ``body`` whose header row contains
    ``control_column``.  Returns a list of dicts with keys ``control``,
    ``linked_threats_raw`` (exact cell text), and ``linked_tids`` (set of
    canonical ``T-NNN`` strings extracted from that cell).  Rows whose control
    cell is empty are skipped."""
    lines = body.splitlines()
    rows: list[dict] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not (line.startswith("|") and control_column in line):
            i += 1
            continue
        header_cells = [c.strip() for c in line.strip("|").split("|")]
        try:
            ci_control = header_cells.index(control_column)
        except ValueError:
            i += 1
            continue
        ci_linked = next(
            (idx for idx, c in enumerate(header_cells) if c.lower() == "linked threats"),
            None,
        )
        # Skip the header separator line.
        i += 2
        while i < len(lines):
            ln = lines[i]
            if not ln.startswith("|"):
                break
            cells = [c.strip() for c in ln.strip("|").split("|")]
            if len(cells) <= ci_control:
                i += 1
                continue
            control = _strip_md(cells[ci_control])
            if not control:
                i += 1
                continue
            linked_raw = cells[ci_linked] if ci_linked is not None and ci_linked < len(cells) else ""
            linked_tids = {f"T-{m.group(1).zfill(3)}" for m in T_ID_RE.finditer(linked_raw)}
            # The composer rewrites bare T-NNN into [F-NNN](#f-nnn) links when
            # rendering linked-id columns (see _LINKED_ID_COLUMN_HEADERS). F-NNN
            # is the canonical row-anchor alias for the same threat; treat them
            # as equivalent for trailer / cell consistency checks.
            linked_tids |= {f"T-{m.group(1).zfill(3)}" for m in F_ID_RE.finditer(linked_raw)}
            row_dict = {
                "control": control,
                "linked_threats_raw": linked_raw,
                "linked_tids": linked_tids,
            }
            # Also expose the row under the literal column name from the
            # contract (e.g. "Control") so callers that read
            # `row.get(table_column)` match successfully. Without this
            # alias, `check_auth_method_decomposition` would always report
            # "no control table found" even when the table is present.
            row_dict[control_column] = control
            rows.append(row_dict)
            i += 1
        break  # only parse the first matching table
    return rows


def _parse_subsections(body: str, level: int = 4) -> dict[str, str]:
    """Return an insertion-ordered ``{heading_text: body_text}`` for every
    ``#### …``-style subsection inside ``body``.  The ``body_text`` of each
    heading runs until the next heading of the same level (or end-of-text)."""
    pattern = re.compile(r"^" + ("#" * level) + r"\s+(.+?)\s*$", re.MULTILINE)
    matches = list(pattern.finditer(body))
    out: dict[str, str] = {}
    for idx, m in enumerate(matches):
        heading = m.group(1).strip()
        start = m.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(body)
        out[heading] = body[start:end]
    return out


def check_auth_method_decomposition(md_path: Path, contract_path: Path = DEFAULT_CONTRACT_PATH) -> Report:
    """Enforce the ``auth_method_decomposition`` rule on §7.3 IAM.

    Validation steps:
      1. Every row of the §7.3 control table (``Control`` column) must map
         to a ``#### <method>`` subsection.  Matching is done either via
         explicit ``synonyms`` overrides or via token-subset (default):
         the row's lowercased alphanumeric token set must be a subset of
         the heading's token set.
      2. Every ``####`` subsection must contain a ``sequenceDiagram`` block.
      3. Every ``####`` subsection must carry a bold
         ``**Findings in this flow:**`` trailer.
      4. T-IDs cited in the trailer must be a subset of the union of
         ``Linked Threats`` cells of all rows matched to that subsection
         (bidirectional consistency — prevents the section from citing
         threats that are not formally tied to the method via the table).

    No-op when the contract does not declare the rule.
    """
    report = Report("auth_method_decomposition")
    contract = _read_contract(contract_path)
    if not contract:
        # Contract unreadable — a different check surfaces that; stay silent here.
        return report

    sec = (contract.get("sections") or {}).get("security_architecture") or {}
    rules_map = sec.get("domain_required_rules") or {}
    # R1 — Scan every domain-rule bucket for an `auth_method_decomposition`
    # entry, not just the legacy v1 `7.3 Identity & Access Management` key.
    # Under v2, the schema_v2 overlay rewrites the rules_map; the relevant
    # key becomes `7.2 Identity and Authentication Controls`. Scanning all
    # keys keeps the check schema-agnostic and survives any future renaming
    # of the IAM section.
    domain_title = None
    rule = None
    for key, rules in rules_map.items():
        if not isinstance(rules, list):
            continue
        match = next(
            (r for r in rules if isinstance(r, dict) and r.get("rule") == "auth_method_decomposition"),
            None,
        )
        if match is not None:
            domain_title = key
            rule = match
            break
    if rule is None:
        report.ok = 1
        return report

    table_column = rule.get("table_column", "Control")
    heading_level = int(rule.get("heading_level", 4))
    trailer_label = rule.get("trailer_label", "Findings in this flow")
    match_style = rule.get("match_style", "token-subset")
    synonyms = rule.get("synonyms") or []
    enforcement = (rule.get("enforcement") or "warning").strip().lower()
    # New (additive) fields — each falls back to a no-op when absent so older
    # contracts keep working byte-identically.
    heading_pattern = rule.get("heading_pattern") or ""
    required_trailers = rule.get("required_trailers") or []
    required_body_elems = rule.get("required_body_elements") or []
    method_whitelist = rule.get("method_whitelist") or []  # Sprint 2B
    # Post-2026-05: blocks with attack-shaped headings ("alg:none Bypass
    # Flow", "JWT Forgery Flow", etc.) are forbidden under §7.3 — they
    # describe exploitation paths, not auth methods, and belong in §3
    # Attack Walkthroughs.
    forbidden_heading_patterns = rule.get("forbidden_heading_patterns") or []
    # Per-flow-method diagram enforcement (v2, migrated from the v1 rule).
    # Absent fields → no-op, so older/v1 contracts keep working unchanged.
    flow_methods_require_diagram = bool(rule.get("flow_methods_require_diagram"))
    flow_method_tokens = rule.get("flow_method_tokens") or []
    flow_diagram_token = (rule.get("flow_diagram_token") or "sequenceDiagram").strip()
    hashes = "#" * heading_level

    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return _finalize_auth_report(report, enforcement)

    # Derive the IAM-section heading from the discovered `domain_title` so the
    # rule runs under BOTH layouts:
    #   v1 → "7.3 Identity & Access Management"
    #   v2 → "7.2 Identity and Authentication Controls"
    # This used to be hardcoded to §7.3, which made the ENTIRE rule a silent
    # no-op under v2 (the IAM section is §7.2 there) — the forbidden-heading
    # and method-whitelist gates never ran, so primitive headings like
    # "Password Hashing" / "Login Rate Limiting" and token-format names
    # shipped unflagged (2026-05 juice-shop §7.2 regression).
    _num_m = re.match(r"\s*(\d+(?:\.\d+)*)\s", (domain_title or "") + " ")
    section_re = (
        r"^###\s+" + re.escape(_num_m.group(1)) + r"\b"
        if _num_m
        else r"^###\s+7\.3\s+Identity\s*&\s*Access\s+Management\b"
    )
    iam_body = _extract_section_body(text, section_re)
    if iam_body is None:
        # IAM section absent — a different contract check flags missing
        # sections, so this rule stays silent and clean to avoid double-report.
        report.ok = 1
        return report

    # Layout detection. v1 (§7.3) uses a `Control` pipe-table + per-method
    # `sequenceDiagram` + `**Findings in this flow:**` trailer. v2 (§7.2) uses
    # a `**Controls covered:**` link line (no pipe table) and optional
    # diagrams, so the v1 matching/structural gates would false-positive there.
    # The rule's `table_column` is the discriminator ("Control" → v1,
    # "Controls covered" → v2).
    if table_column.strip().lower() != "control":
        _run_auth_v2_structural_checks(
            report=report,
            iam_body=iam_body,
            heading_level=heading_level,
            method_whitelist=method_whitelist,
            forbidden_heading_patterns=forbidden_heading_patterns,
            section_label=(domain_title or "7.2 Identity and Authentication Controls"),
            flow_methods_require_diagram=flow_methods_require_diagram,
            flow_method_tokens=flow_method_tokens,
            flow_diagram_token=flow_diagram_token,
        )
        return _finalize_auth_report(report, enforcement)

    table_rows = _parse_domain_controls_table(iam_body, control_column=table_column)
    subsections = _parse_subsections(iam_body, level=heading_level)

    # Sprint 2B (M3.5) — narrow `table_rows` to actual auth methods. Rows
    # like "Password Hashing", "Login Rate Limiting", or "express-jwt
    # middleware" are implementation details / cross-cutting controls; they
    # belong in the controls table but do NOT warrant a dedicated
    # `#### Flow` sub-block. Without this filter the checker emitted 5 of
    # 11 sinnfreie warnings on the 2026-04-27 juice-shop run.
    if method_whitelist:
        table_rows = [r for r in table_rows if _row_is_auth_method(r.get(table_column, ""), method_whitelist)]

    if not table_rows:
        report.issues.append(
            f"§7.3 IAM: no control table with column {table_column!r} found — cannot verify per-method decomposition"
        )
    elif not subsections:
        report.issues.append(
            f"§7.3 IAM: no {hashes} subsections found — every control-table "
            f"row needs a dedicated sub-block with its own sequenceDiagram"
        )
    else:
        _run_auth_matching_checks(
            report=report,
            table_rows=table_rows,
            subsections=subsections,
            synonyms=synonyms,
            match_style=match_style,
            trailer_label=trailer_label,
            table_column=table_column,
            hashes=hashes,
        )
        _run_auth_structural_checks(
            report=report,
            subsections=subsections,
            heading_pattern=heading_pattern,
            required_trailers=required_trailers,
            required_body_elems=required_body_elems,
            forbidden_heading_patterns=forbidden_heading_patterns,
            hashes=hashes,
        )

    return _finalize_auth_report(report, enforcement)


def check_control_subsection_coverage(md_path: Path, contract_path: Path = DEFAULT_CONTRACT_PATH) -> Report:
    """Enforce the v2 §7 control-subsection coverage rule.

    For each configured §7 control section, the `**Controls covered:**` line
    must link to concrete H4 control subsections, and every H4 subsection must
    contain the two required labels (`Security assessment`, `Relevant findings`
    by default). This replaces the legacy §7.3.N auth-flow-only gate with a
    general control-category gate.
    """
    report = Report("control_subsection_coverage")
    contract = _read_contract(contract_path)
    if not contract:
        return report

    sec = (contract.get("sections") or {}).get("security_architecture") or {}
    rules_map = sec.get("domain_required_rules") or {}
    all_control_rules = rules_map.get("all_control_sections") or []
    rule = next(
        (r for r in all_control_rules if isinstance(r, dict) and r.get("rule") == "control_subsection_coverage"),
        None,
    )
    if rule is None:
        report.ok = 1
        return report

    section_titles = [s for s in (rule.get("section_titles") or []) if isinstance(s, str) and s.strip()]
    controls_label = (rule.get("controls_covered_label") or "Controls covered").strip()
    heading_level = int(rule.get("heading_level") or 4)
    required_labels = [s for s in (rule.get("required_subsection_labels") or []) if isinstance(s, str) and s.strip()]
    enforcement = (rule.get("enforcement") or "warning").strip().lower()
    hashes = "#" * heading_level

    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return _finalize_auth_report(report, enforcement)

    label_re = re.compile(
        r"\*\*\s*" + re.escape(controls_label) + r"\s*:?\s*\*\*\s*"
        r"(?P<body>.*?)(?=\n\s*\*\*[A-Z][^*\n]{2,80}:?\*\*|\n####\s|\n###\s|\Z)",
        re.DOTALL,
    )

    for section_title in section_titles:
        body = _extract_section_body(text, r"^###\s+" + re.escape(section_title) + r"[ \t]*$")
        if body is None:
            continue  # check_contract owns missing §7 section headings.

        # Sections that legitimately have nothing to say ship as a single
        # italic "_Not applicable — …_" stub instead of empty H4 blocks
        # (e.g. §7.12 when no real-time / WebSocket findings are routed).
        # Don't flag the absent H4 in that case — the stub is the intended
        # output, not a defect.
        if re.search(r"^\s*_Not applicable\b", body, re.MULTILINE):
            continue
        subsections = _parse_subsections(body, level=heading_level)
        if not subsections:
            report.issues.append(
                f"§{section_title}: no {hashes} control subsections found — "
                f"add one H{heading_level} block per linked control."
            )
            continue

        control_match = label_re.search(body)
        if not control_match:
            report.issues.append(
                f"§{section_title}: missing `**{controls_label}:**` label — "
                f"list the covered controls as markdown links to {hashes} headings."
            )
        else:
            linked_controls = [_strip_md(label) for label in _MD_LINK_RE.findall(control_match.group("body"))]
            linked_controls = [label for label in linked_controls if label]
            if not linked_controls:
                report.issues.append(
                    f"§{section_title}: `**{controls_label}:**` contains no markdown links — "
                    f"link each covered control to its {hashes} subsection."
                )
            # Heading lookup must tolerate the `7.X.N <title>` numbering
            # convention (2026-05) — the `**Controls covered:**` link text
            # carries the bare control name, the H4 carries that name plus
            # the dotted index prefix. We accept any heading that either
            # equals the link text or contains it as a trailing-anchored
            # whole-token match (so "JWT Authentication" matches
            # "7.2.1 JWT Authentication" but not "Old JWT Authentication
            # Was Replaced").
            #
            # Both sides must be markdown-normalized before comparison: the
            # link text is already `_strip_md`-ed (line ~4373), but the
            # heading comes raw from `_parse_subsections`. Without stripping
            # the heading too, a control whose name contains a backtick-wrapped
            # token (e.g. "WebSocket Event Bus (`Socket.IO`)", produced when
            # apply_prose_fixes.py code-spans the token in BOTH the link and
            # the heading) never matches — `_strip_md` removes the backticks
            # from the link side only, so the comparison is asymmetric and the
            # control_subsection_coverage gate raises a false positive that the
            # re-render loop can never converge on.
            def _unescape_md(s: str) -> str:
                r"""Drop backslashes that escape a non-word character.

                compose_threat_model.py's `_escape_dot_tld_identifiers` pass
                backslash-escapes the dot in brand tokens (`Socket.IO` ->
                `Socket\.IO`) in plain heading text but exempts markdown link
                labels, so the `**Controls covered:**` link label keeps the
                un-escaped form while the matching `#### ...` heading text is
                escaped. Without normalising, the two diverge by exactly one
                `\` and the control_subsection_coverage gate raises a false
                positive the re-render loop can never converge on."""
                return re.sub(r"\\([^\w\s])", r"\1", s)

            def _heading_matches(target: str, heading: str) -> bool:
                target = _unescape_md(_strip_md(target))
                heading = _unescape_md(_strip_md(heading))
                if target == heading:
                    return True
                # Allow `<number> <target>` form (e.g. `7.2.1 JWT Authentication`).
                stripped = re.sub(r"^\d+(?:\.\d+)*\s+", "", heading).strip()
                return stripped == target
            for control_name in linked_controls:
                if not any(_heading_matches(control_name, h) for h in subsections):
                    report.issues.append(
                        f"§{section_title}: `**{controls_label}:**` links to {control_name!r}, "
                        f"but no matching `{hashes} {control_name}` subsection exists."
                    )

        for heading, subsection_body in subsections.items():
            for required_label in required_labels:
                required_re = re.compile(
                    r"\*\*\s*" + re.escape(required_label) + r"\s*:?\s*\*\*",
                    re.IGNORECASE,
                )
                if not required_re.search(subsection_body):
                    report.issues.append(
                        f"§{section_title} {hashes} {heading!r}: missing "
                        f"`**{required_label}**` label."
                    )

    return _finalize_auth_report(report, enforcement)


def check_relevant_findings_bullet_list(md_path: Path, contract_path: Path = DEFAULT_CONTRACT_PATH) -> Report:
    """Enforce the v2 §7 `Relevant findings` block shape.

    `check_control_subsection_coverage` verifies that the label exists. This
    companion rule verifies that the label is standalone and followed by a
    bullet list, so the old inline form
    `**Relevant findings:** [F-001](#f-001), [F-002](#f-002)` cannot pass as a
    structurally valid H4 block.
    """
    report = Report("relevant_findings_bullet_list")
    contract = _read_contract(contract_path)
    if not contract:
        return report

    sec = (contract.get("sections") or {}).get("security_architecture") or {}
    rules_map = sec.get("domain_required_rules") or {}
    all_control_rules = rules_map.get("all_control_sections") or []
    rule = next(
        (r for r in all_control_rules if isinstance(r, dict) and r.get("rule") == "relevant_findings_bullet_list"),
        None,
    )
    if rule is None:
        report.ok = 1
        return report

    section_titles = [s for s in (rule.get("section_titles") or []) if isinstance(s, str) and s.strip()]
    heading_level = int(rule.get("heading_level") or 4)
    label = (rule.get("label") or "Relevant findings").strip()
    enforcement = (rule.get("enforcement") or "warning").strip().lower()
    hashes = "#" * heading_level

    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return _finalize_auth_report(report, enforcement)

    label_re = re.compile(
        r"^\s*\*\*\s*" + re.escape(label) + r"\s*(?P<colon>:?)\s*\*\*(?P<trailing>.*?)\s*$",
        re.IGNORECASE,
    )
    bullet_re = re.compile(r"^\s*[-*]\s+")

    for section_title in section_titles:
        body = _extract_section_body(text, r"^###\s+" + re.escape(section_title) + r"[ \t]*$")
        if body is None:
            continue  # check_contract owns missing §7 section headings.

        subsections = _parse_subsections(body, level=heading_level)
        for heading, subsection_body in subsections.items():
            lines = subsection_body.splitlines()
            for idx, line in enumerate(lines):
                m = label_re.match(line)
                if not m:
                    continue

                if m.group("colon"):
                    report.issues.append(
                        f"§{section_title} {hashes} {heading!r}: `**{label}**` "
                        f"label must be standalone without a colon."
                    )

                trailing = m.group("trailing").strip()
                if trailing:
                    report.issues.append(
                        f"§{section_title} {hashes} {heading!r}: inline "
                        f"`**{label}:** ...` content is forbidden — use one "
                        f"bullet per finding below the standalone label."
                    )
                    break

                for next_line in lines[idx + 1:]:
                    stripped = next_line.strip()
                    if not stripped or stripped.startswith("<!--"):
                        continue
                    if bullet_re.match(next_line):
                        break
                    report.issues.append(
                        f"§{section_title} {hashes} {heading!r}: first content "
                        f"after `**{label}**` is not a Markdown bullet. Use "
                        f"`- [F-NNN](#f-nnn) - rationale` or "
                        f"`- No dedicated finding routed in this assessment.`"
                    )
                    break
                else:
                    report.issues.append(
                        f"§{section_title} {hashes} {heading!r}: "
                        f"`**{label}**` has no bullet list."
                    )
                break

    return _finalize_auth_report(report, enforcement)


def check_validation_approach_first(md_path: Path, contract_path: Path = DEFAULT_CONTRACT_PATH) -> Report:
    """Enforce the §7.6 `validation_approach_first` rule (v2).

    §7.6 Input Boundary Validation must OPEN with a general validation-approach
    H4 (the architectural stance — central schema/validation layer vs. scattered
    per-endpoint checks) BEFORE drilling into specific parsers/uploads/business
    rules. An architect states the strategy first, then the boundary details.

    The rule fires only on the FIRST `####` under the configured section, so the
    agent stays free to add as many specific boundary sub-blocks afterwards as
    the codebase warrants. No-op when the contract does not declare the rule
    (e.g. under the v1 schema), so older contracts keep working byte-identically.
    """
    report = Report("validation_approach_first")
    contract = _read_contract(contract_path)
    if not contract:
        return report

    sec = (contract.get("sections") or {}).get("security_architecture") or {}
    rules_map = sec.get("domain_required_rules") or {}
    # Scan every domain-rule bucket so the check is schema-agnostic and
    # survives a future renaming of the §7.6 key.
    rule = None
    for _key, rules in rules_map.items():
        if not isinstance(rules, list):
            continue
        match = next(
            (r for r in rules if isinstance(r, dict) and r.get("rule") == "validation_approach_first"),
            None,
        )
        if match is not None:
            rule = match
            break
    if rule is None:
        report.ok = 1
        return report

    section_title = (rule.get("section_title") or "7.6 Input Boundary Validation Controls").strip()
    heading_level = int(rule.get("heading_level") or 4)
    patterns = [p for p in (rule.get("approach_heading_patterns") or []) if isinstance(p, str) and p]
    enforcement = (rule.get("enforcement") or "warning").strip().lower()
    hashes = "#" * heading_level

    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return _finalize_auth_report(report, enforcement)

    body = _extract_section_body(text, r"^###\s+" + re.escape(section_title) + r"[ \t]*$")
    if body is None:
        # check_contract owns a missing §7.6 heading.
        report.ok = 1
        return report
    # A legitimately empty section ships as a single italic "_Not applicable …_"
    # stub — no H4 expected, so the approach-first rule does not apply.
    if re.search(r"^\s*_Not applicable\b", body, re.MULTILINE):
        report.ok = 1
        return report

    subsections = _parse_subsections(body, level=heading_level)
    if not subsections:
        # control_subsection_coverage owns the missing-subsection case.
        report.ok = 1
        return report

    compiled = []
    for pat in patterns:
        try:
            compiled.append(re.compile(pat))
        except re.error as err:
            report.issues.append(
                f"§{section_title}: invalid `approach_heading_patterns` entry "
                f"{pat!r} in contract ({err}) — fix data/sections-contract.yaml"
            )
    first_heading = next(iter(subsections))
    first_norm = re.sub(r"^\d+(?:\.\d+)*\s+", "", first_heading).strip()
    if compiled and not any(p.search(first_heading) or p.search(first_norm) for p in compiled):
        report.issues.append(
            f"§{section_title}: the first {hashes} sub-block is {first_heading!r}, "
            f"but §7.6 must OPEN with a general validation-approach block "
            f"(e.g. `{hashes} Validation Approach` / `Input Validation Strategy`) "
            f"describing whether validation is centralized (schema/middleware) or "
            f"scattered per-endpoint, BEFORE specific parser/upload/business-rule "
            f"sub-blocks (contract: validation_approach_first)."
        )

    return _finalize_auth_report(report, enforcement)


def _run_auth_v2_structural_checks(
    *,
    report: Report,
    iam_body: str,
    heading_level: int,
    method_whitelist: list,
    forbidden_heading_patterns: list,
    section_label: str,
    flow_methods_require_diagram: bool = False,
    flow_method_tokens: list = None,
    flow_diagram_token: str = "sequenceDiagram",
) -> None:
    """v2 (§7.2 "… Authentication Controls") enforcement for
    ``auth_method_decomposition``.

    The v2 layout has no ``Control`` pipe-table and no per-method
    ``sequenceDiagram`` / ``**Findings in this flow:**`` trailer (the
    ``**Security assessment**`` / ``**Relevant findings**`` labels are owned by
    ``control_subsection_coverage``). This path therefore enforces only the two
    gates that are meaningful for v2:

      * every ``####`` heading must name a real authentication MECHANISM from
        ``method_whitelist`` (Password-Based Login, OAuth/OIDC, MFA/TOTP, …).
        JWT issuance/verification is a §7.3 session-token primitive, NOT a §7.2
        mechanism — the whitelist excludes it and the forbidden patterns reject
        it. Primitives/aspects like "Password Hashing" or "Login Rate Limiting"
        are not mechanisms either — they belong folded into a mechanism block,
        not promoted to a peer heading;
      * no heading may match ``forbidden_heading_patterns`` (token-format-only
        names, library names, vulnerability-class names, "Password Hashing").

    Heading matching strips a leading ``7.2.N`` numeric prefix first, so the
    rule fires on the numbered headings the composer emits — the missing prefix
    handling is exactly why the forbidden-pattern regexes silently passed
    ``#### 7.2.2 Password Hashing``.
    """
    sl = "§" + (section_label.split()[0] if section_label.strip() else "7.2")
    hashes = "#" * heading_level
    subsections = _parse_subsections(iam_body, level=heading_level)
    if not subsections:
        # control_subsection_coverage already flags a missing-subsection §7.2;
        # stay silent here to avoid double-reporting.
        report.ok = 1
        return

    compiled_forbidden = []
    for pattern in forbidden_heading_patterns or []:
        if not isinstance(pattern, str) or not pattern:
            continue
        try:
            compiled_forbidden.append((pattern, re.compile(pattern)))
        except re.error as err:
            report.issues.append(
                f"{sl}: invalid `forbidden_heading_patterns` entry {pattern!r} "
                f"in contract ({err}) — fix data/sections-contract.yaml"
            )

    for heading in subsections:
        heading_norm = re.sub(r"^\d+(?:\.\d+)*\s+", "", heading).strip()
        flagged = False
        for raw, forbid in compiled_forbidden:
            if forbid.search(heading) or forbid.search(heading_norm):
                report.issues.append(
                    f"{sl} {hashes} {heading!r}: heading matches forbidden "
                    f"pattern {raw!r}. §7.2 sub-blocks must name authentication "
                    f"MECHANISMS (Password-Based Login, OAuth/OIDC, MFA/TOTP, …), "
                    f"not primitives (hashing), libraries (express-jwt), token "
                    f"formats (JWT-RS256), or vulnerability classes. JWT "
                    f"issuance/verification belongs in §7.3 Session and Token "
                    f"Controls, not §7.2."
                )
                flagged = True
                break
        if flagged:
            continue
        if method_whitelist and not _row_is_auth_method(heading_norm, method_whitelist):
            report.issues.append(
                f"{sl} {hashes} {heading!r}: not a recognized authentication "
                f"mechanism. Structure §7.2 by real auth method (e.g. "
                f"Password-Based Login, OAuth/OIDC, MFA/TOTP) and fold aspects "
                f"such as password hashing or login rate-limiting into the "
                f"relevant mechanism block as bullets, not as peer headings. "
                f"A JWT issuance/verification/signing-key heading belongs in "
                f"§7.3 Session and Token Controls — move it there, do not rename "
                f"it into a §7.2 mechanism."
            )

    # Per-flow-method diagram gate (migrated from the v1 rule). A §7.2 ####
    # whose heading names an authentication FLOW must carry its own positive-
    # flow `sequenceDiagram` — the auth flow is the architecture view §7.2 is
    # built around. Scoped to flow-token headings so it never fires on static
    # primitives, API keys, anonymous access, or methods the agent adds that
    # have no meaningful sequence (Freiräume preserved). The grouped
    # "Password-Based Authentication" lifecycle block matches via the
    # `password-based` token and gets its login-flow diagram from the scaffold.
    if flow_methods_require_diagram and (flow_method_tokens or []):
        token = flow_diagram_token or "sequenceDiagram"
        for heading, body in subsections.items():
            heading_norm = re.sub(r"^\d+(?:\.\d+)*\s+", "", heading).strip()
            if not _row_is_auth_method(heading_norm, flow_method_tokens):
                continue
            if token not in body:
                report.issues.append(
                    f"{sl} {hashes} {heading!r}: flow-based authentication "
                    f"method has no `{token}` diagram. Every §7.2 sub-block "
                    f"that names an auth FLOW (password login, OAuth/OIDC, "
                    f"SAML, TOTP/MFA, passkey, mTLS, webhook HMAC, magic link) "
                    f"must carry its own positive-flow ```mermaid {token}``` — "
                    f"primitives and static controls are exempt "
                    f"(contract: auth_method_decomposition.flow_methods_require_diagram)."
                )


def _run_auth_structural_checks(
    *,
    report: Report,
    subsections: dict[str, str],
    heading_pattern: str,
    required_trailers: list,
    required_body_elems: list,
    forbidden_heading_patterns: list = None,
    hashes: str,
) -> None:
    """Additive structural gates for ``auth_method_decomposition`` — enforce
    the new per-flow mini-report shape (7.3.N numbering + Risk assessment
    trailer + sequenceDiagram body).

    Each gate is a no-op when its contract field is absent, so older
    contracts keep working byte-identically.
    """
    forbidden_heading_patterns = forbidden_heading_patterns or []
    # Reject ATTACK-SHAPED headings (e.g. "alg:none Bypass Flow", "JWT
    # Forgery Flow") under §7.3 — those describe exploitation paths and
    # belong in §3 Attack Walkthroughs, not in the §7.3 auth-method
    # inventory. The pattern list is sourced from the contract.
    for pattern in forbidden_heading_patterns:
        if not isinstance(pattern, str) or not pattern:
            continue
        try:
            forbid = re.compile(pattern)
        except re.error as err:
            report.issues.append(
                f"§7.3 IAM: invalid `forbidden_heading_patterns` entry "
                f"{pattern!r} in contract ({err}) — fix data/sections-contract.yaml"
            )
            continue
        for heading in subsections:
            heading_norm = re.sub(r"^\d+(?:\.\d+)*\s+", "", heading).strip()
            if forbid.search(heading) or forbid.search(heading_norm):
                report.issues.append(
                    f"§7.3 IAM {hashes} subsection {heading!r}: heading "
                    f"matches forbidden attack-shape pattern {pattern!r}. "
                    f"§7.3 sub-blocks describe AUTHENTICATION METHODS "
                    f"(Password Login, OAuth, TOTP, JWT Issuance, …), not "
                    f"attacks. Move this content to §3 Attack Walkthroughs "
                    f"and replace it with a per-method flow under §7.3."
                )
    if heading_pattern:
        try:
            pat = re.compile(heading_pattern)
        except re.error as err:
            report.issues.append(
                f"§7.3 IAM: invalid `heading_pattern` in contract ({err}) — fix data/sections-contract.yaml"
            )
            pat = None
        if pat is not None:
            for heading in subsections:
                if not pat.search(heading):
                    report.issues.append(
                        f"§7.3 IAM {hashes} subsection {heading!r}: heading "
                        f"does not match required pattern {heading_pattern!r} "
                        f"— use `{hashes} 7.3.N <Flow Name> Flow` (e.g. "
                        f"`{hashes} 7.3.1 Password Login Flow`)"
                    )
    for label in required_trailers or []:
        if not isinstance(label, str):
            continue
        label_re = re.compile(r"\*\*" + re.escape(label) + r":\*\*")
        for heading, body in subsections.items():
            if not label_re.search(body):
                report.issues.append(
                    f"§7.3 IAM {hashes} subsection {heading!r}: missing "
                    f"`**{label}:**` trailer — add a bold-label line with "
                    f"the relevant details (see contract: "
                    f"auth_method_decomposition.required_trailers)"
                )
    for needle in required_body_elems or []:
        if not isinstance(needle, str) or not needle:
            continue
        # Fix (3): `intro_before_diagram` is a sentinel that triggers a
        # structural check (prose line before first ```mermaid fence) rather
        # than a simple substring match on the body text.
        if needle == "intro_before_diagram":
            for heading, body in subsections.items():
                _check_intro_before_diagram(report, heading, body, hashes)
            continue
        # R3 / R10 — `intro_before_security_assessment` is a sentinel that
        # verifies a positive-case prose intro precedes the **Security
        # assessment** label. The reference §7.2 pattern is: 1-3 sentences
        # describing how the mechanism functions normally, THEN the
        # **Security assessment** block with the gap analysis. Without
        # the intro, the H4 block jumps straight into negative framing
        # ("**Security assessment:** ❌ Missing — ...") and loses the
        # control description the reader needs.
        if needle == "intro_before_security_assessment":
            for heading, body in subsections.items():
                _check_intro_before_security_assessment(report, heading, body, hashes)
            continue
        for heading, body in subsections.items():
            if needle not in body:
                report.issues.append(
                    f"§7.3 IAM {hashes} subsection {heading!r}: body does "
                    f"not contain required element {needle!r} — see "
                    f"contract: auth_method_decomposition.required_body_elements"
                )


def _check_intro_before_diagram(report: Report, heading: str, body: str, hashes: str) -> None:
    """Fix (3): verify that at least one non-empty prose line appears between
    the #### heading and the first ```mermaid fence in a §7.3.N flow block.

    A section that opens directly with ```mermaid gives readers no orientation
    before the timing diagram. The rule requires at least one sentence-level
    line (non-empty, not a blank, not starting with ``#``) before the fence.
    """
    fence_pos = body.find("```mermaid")
    if fence_pos < 0:
        # No diagram — the sequenceDiagram check will already flag this.
        return
    pre_fence = body[:fence_pos]
    # Count non-empty lines that are not headings or horizontal rules.
    prose_lines = [
        ln for ln in pre_fence.splitlines() if ln.strip() and not ln.strip().startswith("#") and ln.strip() != "---"
    ]
    if not prose_lines:
        report.issues.append(
            f"§7.3 IAM {hashes} subsection {heading!r}: no introductory prose "
            f"before the first ```mermaid fence — add at least one sentence "
            f"describing the flow's purpose before the diagram (QB-9 / "
            f"contract: auth_method_decomposition.required_body_elements "
            f"intro_before_diagram)"
        )


def _check_intro_before_security_assessment(report: Report, heading: str, body: str, hashes: str) -> None:
    """R3 / R10 — verify a positive-case prose intro precedes `**Security assessment**`.

    Reference §7.2 pattern (every #### sub-block):

        #### OAuth Login Adapter

        The OAuth flow is implemented in the Angular frontend, not as a
        server-side authorization-code flow. oauth.component.ts ...    ← INTRO

        ```mermaid sequenceDiagram ...```                              ← (optional)

        **Security assessment**                                        ← LABEL

        ...                                                            ← narrative

    A subsection that opens directly with `**Security assessment:**` (inline
    form) or with a Verdict-icon line drops the control description and
    jumps straight to the gap analysis — exactly the anti-pattern the v2
    contract is meant to eliminate.

    Rule:
      * At least one non-empty, non-heading, non-bold-label prose line
        between the H4 heading and the first `**Security assessment**`
        (or inline `**Security assessment:**`) marker.
      * The line must contain ≥10 non-whitespace characters (avoid
        false-positives from one-word lines).
    """
    assess_pos = body.find("**Security assessment")
    if assess_pos < 0:
        # No security assessment label — the trailer check already flags this.
        return
    pre = body[:assess_pos]
    # Strip HTML comments before counting — placeholders don't count as prose.
    pre_no_comment = re.sub(r"<!--.*?-->", "", pre, flags=re.DOTALL)
    prose_lines = []
    for ln in pre_no_comment.splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#") or s.startswith("---"):
            continue
        # Skip pure bold-label lines like `**Verdict:** 🔴 Missing` or
        # `**Implemented controls:** ...` — they are metadata, not prose intro.
        if re.match(r"^\*\*[^*]+:\*\*", s):
            continue
        # Skip mermaid / code fences and their contents.
        if s.startswith("```"):
            continue
        if len(s) < 10:
            continue
        prose_lines.append(s)
    if not prose_lines:
        report.issues.append(
            f"§7.2 IAM {hashes} subsection {heading!r}: no positive-case prose "
            f"intro before `**Security assessment**` — add 1-3 sentences "
            f"describing how this control normally functions in this codebase "
            f"(routes, libraries, intended flow) BEFORE the assessment label. "
            f"Reference §7.2 pattern: control description → optional mermaid → "
            f"**Security assessment** → assessment narrative. See contract: "
            f"auth_method_decomposition.required_body_elements "
            f"intro_before_security_assessment, and prose-style.md Rule 3."
        )


def _row_is_auth_method(name: str, whitelist: list) -> bool:
    """Return True iff ``name`` matches any auth-method entry in ``whitelist``.

    Sprint 2B (M3.5): the §7.3 control table mixes true auth methods
    (Password Login, OAuth, TOTP, …) with implementation details (Password
    Hashing, Login Rate Limiting, express-jwt middleware) and cross-cutting
    controls. Only the auth-method rows warrant a dedicated `#### Flow`
    sub-block; the others stay table-only.

    Matching rules:
      * Both sides are lowercased and tokenised on non-alphanumeric chars.
      * A whitelist entry matches when EVERY one of its tokens is present
        in the row's token set (subset match — handles "password login"
        against "Password-Based Login Flow" or "Standard Password Login").
      * Empty whitelist → match nothing (caller decides what to do — the
        caller in `check_auth_method_decomposition` only calls this when
        the whitelist is non-empty, so an empty list cannot reach here).

    Examples (with default whitelist):
      "Password Login"        → True  (matches "password login")
      "Google OAuth"          → True  (matches "oauth")
      "Two-Factor (TOTP)"     → True  (matches "totp")
      "JWT Authentication"    → True  (matches "jwt")
      "Password Hashing"      → False (no whitelist entry; "password" alone
                                       is not whitelisted, only "password
                                       login")
      "Login Rate Limiting"   → False
      "express-jwt middleware"→ True  (matches "jwt") — this is a known
                                       false-positive; safe — middleware
                                       still describes JWT behaviour and
                                       a flow diagram is acceptable.
    """
    if not whitelist:
        return False
    row_tokens = set(re.findall(r"[a-z0-9]+", name.lower()))
    for entry in whitelist:
        if not isinstance(entry, str):
            continue
        entry_tokens = set(re.findall(r"[a-z0-9]+", entry.lower()))
        if entry_tokens and entry_tokens.issubset(row_tokens):
            return True
    return False


def check_diagram_compactness(md_path: Path, contract_path: Path = DEFAULT_CONTRACT_PATH) -> Report:
    """Enforce `diagram_compactness` rules on §2 architecture diagrams.

    Rules come from
    `sections.architecture_diagrams.diagram_compactness.<heading>` in the
    contract. For each declared sub-section the check verifies:

      * The mermaid block opens with the contract's ``layout_keyword``
        (e.g. `flowchart TD` — `graph LR` is forbidden because horizontal
        layouts blow past viewport width on every viewer we tested).
      * Subgraph count ≤ ``max_subgraphs``.
      * Total node count ≤ ``max_nodes_total``.
      * Each node label ≤ ``max_label_lines`` (split on ``<br/>``) and
        each line ≤ ``max_label_chars_per_line`` characters.
      * The ``required_classdefs`` block is present at the bottom of the
        mermaid block (key + value match).
      * When ``require_threat_traceability`` is true, every T-NNN cited
        in a node label or edge label resolves to an entry in §8 Threat
        Register; AND every Critical/High threat from §8 appears EITHER
        in the diagram OR in a §2.4.x layer table.

    No-op when the contract has no `diagram_compactness` block (older
    contracts keep working byte-identically).
    """
    report = Report("diagram_compactness")
    contract = _read_contract(contract_path)
    if not contract:
        return report  # silent — different check surfaces contract problems

    arch = (contract.get("sections") or {}).get("architecture_diagrams") or {}
    rules_map = arch.get("diagram_compactness") or {}
    if not rules_map:
        report.ok = 1
        return report

    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return report

    # Build a §8 T-ID set for traceability checks.
    t_ids_in_register = _collect_threat_register_t_ids(text)
    critical_high_t_ids = _collect_critical_high_t_ids(text)

    for heading, rules in rules_map.items():
        # Locate the heading body (### 2.X ... up to the next ### or ##).
        body = _extract_arch_subsection_body(text, heading)
        if body is None:
            report.issues.append(f"§{heading}: subsection body not found — expected `### {heading}` heading")
            continue

        # Find the first mermaid block inside this sub-section. The
        # diagram is the structural target of the rules; the table that
        # follows is treated as the "supplementary detail" location.
        mb = _extract_first_mermaid_block(body)
        if mb is None:
            report.issues.append(f"§{heading}: no mermaid block found — diagram is required")
            continue

        _check_compactness_rules(report, heading, rules, mb, body)
        if rules.get("require_threat_traceability", False):
            _check_threat_traceability(
                report,
                heading,
                mb,
                body,
                text,
                t_ids_in_register,
                critical_high_t_ids,
            )

    if not report.issues:
        report.ok = 1
    return report


# ---------------------------------------------------------------------------
# Helpers for check_diagram_compactness.
# ---------------------------------------------------------------------------

# Accept both T-NNN (yaml-internal id) and F-NNN (renderer display alias) as
# equivalent threat references. compose_threat_model.py normalises T-NNN ->
# F-NNN for visible labels in §2/§3/§4/§8 tables; the checker must follow
# suit or it raises spurious traceability misses (the "Threat IDs in scope"
# blockquote repair bug, 2026-05). Capture group always returns the 3-4 digit
# numeric so downstream code can produce a canonical `T-NNN` key.
_T_ID_RE_LOCAL = re.compile(r"\b[TF]-(\d{3,4})\b")


def _collect_threat_register_t_ids(text: str) -> set[str]:
    """Set of T-NNN IDs that have an `<a id="t-NNN"></a>` anchor under
    §8 Findings Register or appear as a row in the threat table.
    """
    # Use the h2-spanning extractor: the 2026-05 card layout groups findings
    # under `### <emoji> <Severity>` (h3) sub-headers, so the section body
    # extends across several h3 blocks — stopping at the first `### ` would
    # drop every card anchor.
    body = _extract_h2_section_body(text, r"^##\s+8\.\s+Threat\s+Register\b")
    if body is None:
        return set()
    out: set[str] = set()
    for m in re.finditer(r'<a id="t-(\d{3,4})"></a>', body):
        out.add(f"T-{m.group(1).zfill(3)}")
    for m in _T_ID_RE_LOCAL.finditer(body):
        out.add(f"T-{m.group(1).zfill(3)}")
    return out


def _collect_critical_high_t_ids(text: str) -> set[str]:
    """T-IDs whose §8 finding is rated Critical or High.

    2026-05 card layout: findings are grouped under `### 🔴 Critical (n)` /
    `### 🟠 High (n)` headers, one card each opening with `<a id="t-NNN">`.
    Track the current severity group and collect the card anchors under the
    Critical / High groups.
    """
    body = _extract_h2_section_body(text, r"^##\s+8\.\s+Threat\s+Register\b")
    if body is None:
        return set()
    out: set[str] = set()
    crit_high = False
    for line in body.splitlines():
        h = re.match(r"^###\s+([🔴🟠🟡🟢⚪])", line)
        if h:
            crit_high = h.group(1) in ("🔴", "🟠")
            continue
        if crit_high:
            for m in re.finditer(r'<a id="t-(\d{3,4})"></a>', line):
                out.add(f"T-{m.group(1).zfill(3)}")
    return out


def _extract_h2_section_body(text: str, heading_pattern: str) -> str | None:
    """Like _extract_section_body but stops only at the NEXT H2 (`## `),
    not at the next H3. Used for section-spanning checks (e.g. §2 whole
    body for threat-traceability) where sub-sections must be included.
    """
    m = re.search(heading_pattern, text, re.MULTILINE)
    if not m:
        return None
    tail = text[m.end() :]
    nxt = re.search(r"^##\s", tail, re.MULTILINE)
    return tail[: nxt.start()] if nxt else tail


def _extract_arch_subsection_body(text: str, heading: str) -> str | None:
    """Locate `### {heading}` and return the body up to the next `### `
    or `## ` boundary."""
    # Heading text may carry punctuation (& vs &amp;); allow flexibility.
    pattern = re.compile(
        r"^###\s+"
        + re.escape(heading.split(" ", 1)[0])
        + r"\s+"
        + re.escape(heading.split(" ", 1)[1] if " " in heading else "")
        + r"\b",
        re.MULTILINE,
    )
    m = pattern.search(text)
    if not m:
        return None
    start = m.end()
    # Find next ### or ## boundary.
    after = text[start:]
    nxt = re.search(r"^(?:##\s|###\s)", after, re.MULTILINE)
    return after if not nxt else after[: nxt.start()]


def _extract_first_mermaid_block(body: str) -> dict | None:
    """Return ``{layout, raw, lines}`` for the first mermaid block in
    ``body``. ``layout`` is the first non-blank line inside the fence
    (e.g. `flowchart TD` or `graph LR`). Returns None when no fenced
    mermaid block is present."""
    m = re.search(r"^```mermaid\s*\n(.*?)^```", body, re.MULTILINE | re.DOTALL)
    if not m:
        return None
    raw = m.group(1)
    # Layout keyword — first non-blank, non-comment line.
    layout = ""
    for ln in raw.splitlines():
        s = ln.strip()
        if not s or s.startswith("%%"):
            continue
        layout = s
        break
    return {"layout": layout, "raw": raw, "lines": raw.splitlines()}


def _check_compactness_rules(report: Report, heading: str, rules: dict, mb: dict, body: str) -> None:
    layout_kw = (rules.get("layout_keyword") or "").strip()
    if layout_kw and not mb["layout"].startswith(layout_kw):
        report.issues.append(
            f"§{heading}: mermaid block must start with `{layout_kw}` "
            f"(found `{mb['layout']}`). Wide-layout `graph LR` overflows "
            f"the viewport — use `flowchart TD` for vertical stacking."
        )

    # Count subgraphs.
    raw = mb["raw"]
    subgraphs = re.findall(r"^\s*subgraph\s+(\w+)", raw, re.MULTILINE)
    max_sg = rules.get("max_subgraphs")
    if isinstance(max_sg, int) and len(subgraphs) > max_sg:
        report.issues.append(
            f"§{heading}: {len(subgraphs)} subgraphs found, max {max_sg} "
            f"allowed. Aggregate sub-components into bullet lists in the "
            f"parent tier's node label."
        )

    # Required-subgraphs check.
    required = rules.get("required_subgraphs") or []
    required_ids = {(r or {}).get("id") for r in required if isinstance(r, dict)}
    optional_ids = {(r or {}).get("id") for r in (rules.get("optional_subgraphs") or []) if isinstance(r, dict)}
    found_set = set(subgraphs)
    # Every required must be present unless the tier has no components
    # (we accept absent EXT/CLIENT/APP/DATA if the assessment legitimately
    # has none — but at least 2 of the 4 must be present for the diagram
    # to be meaningful).
    missing_required = required_ids - found_set - optional_ids
    if required_ids and len(found_set & required_ids) < min(2, len(required_ids)):
        report.issues.append(
            f"§{heading}: required subgraph set {sorted(required_ids)} not represented (found {sorted(found_set)})"
        )
    extra = found_set - required_ids - optional_ids
    # Only flag unexpected subgraphs when the contract defines an explicit
    # required or optional set; sections without required_subgraphs (e.g.
    # §2.2 which just caps the count) are free to use any subgraph names.
    if extra and required_ids:
        report.issues.append(
            f"§{heading}: unexpected subgraphs {sorted(extra)} present — "
            f"contract allows only {sorted(required_ids | optional_ids)}"
        )

    # Count nodes — match `ID["label"]`, `ID[("label")]`, `ID(["label"])`,
    # `ID["label"]:::class`. Nodes are word-boundary alphanumerics
    # followed by an opening bracket form.
    node_pat = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_]*)(\[\(|\(\[|\[\[|\[)", re.MULTILINE)
    nodes_found = []
    seen: set[str] = set()
    for m in node_pat.finditer(raw):
        nid = m.group(1)
        # Ignore subgraph header lines (the regex above skips them via the
        # bracket suffix anyway, but be explicit).
        if nid.lower() == "subgraph":
            continue
        if nid not in seen:
            seen.add(nid)
            nodes_found.append(nid)
    max_nodes = rules.get("max_nodes_total")
    if isinstance(max_nodes, int) and len(nodes_found) > max_nodes:
        report.issues.append(
            f"§{heading}: {len(nodes_found)} nodes found, max {max_nodes} "
            f"allowed. Move per-route / per-file detail into the "
            f"following table or §2.4.x layer tables; the diagram is the "
            f"high-level overview."
        )

    # Label-line / label-char limits. Extract every quoted label and
    # split on `<br/>`.
    max_lines = rules.get("max_label_lines")
    max_chars = rules.get("max_label_chars_per_line")
    if isinstance(max_lines, int) or isinstance(max_chars, int):
        for lblmatch in re.finditer(r'"([^"]+)"', raw):
            lbl = lblmatch.group(1)
            parts = re.split(r"<br/?>", lbl)
            if isinstance(max_lines, int) and len(parts) > max_lines:
                report.issues.append(
                    f"§{heading}: node label has {len(parts)} lines, "
                    f"max {max_lines} allowed. Truncate to title + 1 "
                    f"descriptor + (optionally) threats count: "
                    f"{lbl[:80]!r}"
                )
            if isinstance(max_chars, int):
                for p in parts:
                    # Strip simple inline tags from the count
                    plain = re.sub(r"<[^>]+>", "", p).strip()
                    if len(plain) > max_chars:
                        report.issues.append(f"§{heading}: label line exceeds {max_chars} chars: {plain[:60]!r}…")
                        break  # one finding per label is enough

    # Required classDef block — every key:value pair must be present.
    classdefs = rules.get("required_classdefs") or {}
    for css_name, css_value in classdefs.items():
        # Tolerate any whitespace/order; require the key plus the
        # essential `fill` and `stroke` substrings.
        cd_pat = re.compile(r"classDef\s+" + re.escape(css_name) + r"\s+" + re.escape(css_value))
        if not cd_pat.search(raw):
            report.issues.append(f"§{heading}: missing/divergent classDef `{css_name}` — expected `{css_value}`")

    # Fix (1): require_edge_labels — every `-->` edge must carry a `|label|`.
    # A bare unlabelled edge hides the protocol/port, which is the main
    # information the Container Architecture diagram is supposed to convey.
    if rules.get("require_edge_labels"):
        _check_edge_labels(report, heading, raw)

    # F3.2: always-on — flag unsafe edge-label characters across all
    # flowchart/graph blocks. Compose has an auto-fix pass; this check is
    # the safety net for hand-edited or post-compose-modified documents.
    _check_mermaid_label_safety(report, heading, raw)


def _check_edge_labels(report: Report, heading: str, raw: str) -> None:
    """Fix (1): flag unlabelled flowchart edges in the §2.2 Container diagram.

    An edge `A --> B` or `A ---B` without a `|label|` means the protocol
    and port are invisible to the reader. Only arrow forms that support
    labels are checked; `---` (invisible alignment edges) are excluded.
    """
    # Match edges of the form `A --> B` or `A -->B` that lack `|...|`.
    # Exclude comment lines and lines that already carry a label.
    unlabelled_edge_re = re.compile(
        r"^\s+\w+\s+(-{1,2}>+|-\.->)\s+\w+\s*$",
        re.MULTILINE,
    )
    for m in unlabelled_edge_re.finditer(raw):
        line = m.group(0).strip()
        report.issues.append(
            f"§{heading}: unlabelled edge `{line}` — add a `|protocol:port|` "
            f"label so the Container Architecture diagram conveys the "
            f"communication protocol (e.g. `-->|HTTPS :3000|`)"
        )


def _check_mermaid_label_safety(report: Report, heading: str, raw: str) -> None:
    """F3.2: flag edge labels containing unsafe characters that mermaid
    may tokenise ambiguously (`:`, `--`, `'`, `"`, `(`, `)`).

    Compose has an auto-quoting pass that fixes these before write, but
    this check warns on residual cases — useful when the document was
    edited by hand after compose or when a future renderer skips the
    auto-pass. Idempotent: labels already wrapped in `"..."` are skipped.
    """
    unsafe_chars_re = re.compile(r"[:'\(\)]|--")
    edge_label_re = re.compile(r"\|([^|\n\"][^|\n]*?)\|")
    for m in edge_label_re.finditer(raw):
        payload = m.group(1)
        if unsafe_chars_re.search(payload):
            report.issues.append(
                f"§{heading}: mermaid edge label `|{payload}|` contains "
                f"characters that mermaid may tokenise ambiguously (`:` `--` `'` `\"` `(` `)`); "
                f"wrap with `\"...\"` — e.g. `|\"{payload.strip()}\"|`"
            )


def _check_threat_traceability(
    report: Report,
    heading: str,
    mb: dict,
    body: str,
    full_text: str,
    t_ids_register: set[str],
    critical_high_t_ids: set[str],
) -> None:
    """For each T-NNN cited in the diagram or in the body table that
    follows it, verify the ID exists in §8. AND for each Critical/High
    in §8, verify it appears EITHER in the diagram (any node/edge
    label) OR in the §2.4.x layer tables.
    """
    raw = mb["raw"]
    # T-IDs cited in the diagram itself.
    cited_in_diagram = set()
    for m in _T_ID_RE_LOCAL.finditer(raw):
        cited_in_diagram.add(f"T-{m.group(1).zfill(3)}")
    # T-IDs cited in the body table directly under the diagram.
    cited_in_body = set()
    for m in _T_ID_RE_LOCAL.finditer(body):
        cited_in_body.add(f"T-{m.group(1).zfill(3)}")

    # Forward direction: every cited T-NNN must exist in §8.
    if t_ids_register:
        unknown = (cited_in_diagram | cited_in_body) - t_ids_register
        for tid in sorted(unknown):
            report.issues.append(f"§{heading}: cites {tid} but no matching entry in §8 Findings Register")

    # Reverse direction: every Critical/High in §8 must surface SOMEWHERE
    # in §2 (either the diagram, the body table, or a §2.4.x table).
    # We aggregate §2.4.x by scanning §2's full body for the T-IDs.
    # Note: `_extract_section_body` stops at the next `### ` boundary,
    # which is wrong for whole-section traceability — we need to slice
    # from `## 2.` to `## 3.` (the next H2). Locate that span manually.
    sec2_body = _extract_h2_section_body(full_text, r"^##\s+2\.\s+Architecture\s+Diagrams\b")
    if sec2_body is None or not critical_high_t_ids:
        return
    sec2_t_ids: set[str] = set()
    for m in _T_ID_RE_LOCAL.finditer(sec2_body):
        sec2_t_ids.add(f"T-{m.group(1).zfill(3)}")
    missing = critical_high_t_ids - sec2_t_ids
    if missing:
        # Only report when this is the §2.3 check (the canonical cross-
        # ref location) — running it twice would double-count.
        if heading.startswith("2.3"):
            report.issues.append(
                f"§2 architecture: Critical/High threats {sorted(missing)} "
                f"are not referenced anywhere in §2 (neither §2.3 diagram, "
                f"§2.3 component table, nor §2.4.x layer tables). "
                f"Threat-traceability requires every Critical/High to "
                f"surface in the architecture view."
            )


def check_chain_compactness(md_path: Path, contract_path: Path = DEFAULT_CONTRACT_PATH) -> Report:
    """Enforce `chain_compactness` rules on §3.1 Attack Chain Overview.

    Unlike §2.x (single mermaid block per sub-section), §3.1 has MULTIPLE
    blocks — one per attack chain under a `#### Chain N — <name>`
    heading. The contract caps the per-block size and the total number
    of chains:

      * Layout: `graph LR` (forbids vertical layouts that break read flow).
      * max_blocks: cap on the number of chains (5).
      * max_nodes_per_block: per-chain node ceiling (6).
      * max_subgraphs_per_block: 0 (no clustered mega-graphs).
      * Required classDef block (`risk` + `impact`).
      * Each chain MUST cite ≥1 T-NNN that exists in §8 Findings Register
        (otherwise it is a data-flow diagram, not an attack chain).

    No-op when the contract has no `chain_compactness` block.
    """
    report = Report("chain_compactness")
    contract = _read_contract(contract_path)
    if not contract:
        return report

    aw = (contract.get("sections") or {}).get("attack_walkthroughs") or {}
    rules_map = aw.get("chain_compactness") or {}
    if not rules_map:
        report.ok = 1
        return report

    # Skip compactness checks when SKIP_ATTACK_WALKTHROUGHS is set — the stub
    # fragment contains only a skip notice and has no mermaid blocks by design.
    try:
        import json as _json_cc

        _cfg_path = md_path.parent / ".skill-config.json"
        if _cfg_path.is_file():
            _cfg = _json_cc.loads(_cfg_path.read_text(encoding="utf-8"))
            if _cfg.get("SKIP_ATTACK_WALKTHROUGHS") or _cfg.get("skip_attack_walkthroughs"):
                report.ok = 1
                return report
    except Exception:
        pass

    # Only one rules entry is expected ("3.1 Attack Chain Overview");
    # iterate in case the contract grows.
    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return report

    t_ids_register = _collect_threat_register_t_ids(text)

    for heading, rules in rules_map.items():
        body = _extract_h3_section_body(text, heading)
        if body is None:
            report.issues.append(f"§{heading}: subsection body not found")
            continue
        _check_chain_rules(report, heading, rules, body, t_ids_register)

    if not report.issues:
        report.ok = 1
    return report


def _extract_h3_section_body(text: str, heading: str) -> str | None:
    """Slice the H3 sub-section by exact heading text, returning the body
    until the next H3 / H2 boundary."""
    parts = heading.split(" ", 1)
    if len(parts) != 2:
        return None
    num, rest = parts
    pat = re.compile(
        r"^###\s+" + re.escape(num) + r"\s+" + re.escape(rest) + r"\b",
        re.MULTILINE,
    )
    m = pat.search(text)
    if not m:
        return None
    tail = text[m.end() :]
    nxt = re.search(r"^(?:##\s|###\s)", tail, re.MULTILINE)
    return tail[: nxt.start()] if nxt else tail


def _check_chain_rules(report: Report, heading: str, rules: dict, body: str, t_ids_register: set[str]) -> None:
    layout_kw = (rules.get("layout_keyword") or "").strip()
    forbidden_kws = rules.get("forbidden_layout_keywords") or []
    max_blocks = rules.get("max_blocks")
    max_nodes_per_block = rules.get("max_nodes_per_block")
    max_subgraphs_per_block = rules.get("max_subgraphs_per_block")
    max_lines = rules.get("max_label_lines")
    max_chars = rules.get("max_label_chars_per_line")
    classdefs = rules.get("required_classdefs") or {}
    require_threat = rules.get("require_threat_per_block", False)

    # Find every mermaid block in the body. Each chain has its own block.
    blocks = re.findall(r"```mermaid\n(.*?)\n```", body, re.DOTALL)

    if not blocks:
        report.issues.append(f"§{heading}: no mermaid blocks found — at least one chain expected")
        return

    if isinstance(max_blocks, int) and len(blocks) > max_blocks:
        report.issues.append(
            f"§{heading}: {len(blocks)} attack chains found, max {max_blocks} "
            f"allowed. Consolidate the lowest-impact chains or move them "
            f"into §3.2+ as standalone walkthroughs."
        )

    for idx, raw in enumerate(blocks, start=1):
        # Layout keyword check.
        first_line = ""
        for ln in raw.splitlines():
            s = ln.strip()
            if s and not s.startswith("%%"):
                first_line = s
                break
        if layout_kw and not first_line.startswith(layout_kw):
            report.issues.append(f"§{heading} chain {idx}: must start with `{layout_kw}` (found `{first_line}`)")
        for fk in forbidden_kws:
            if first_line.startswith(fk):
                report.issues.append(
                    f"§{heading} chain {idx}: forbidden layout `{fk}` — chains must read horizontally as a sequence"
                )
                break

        # Subgraph count.
        sgs = re.findall(r"^\s*subgraph\s+(\w+)", raw, re.MULTILINE)
        if isinstance(max_subgraphs_per_block, int) and len(sgs) > max_subgraphs_per_block:
            report.issues.append(
                f"§{heading} chain {idx}: {len(sgs)} subgraphs found, max "
                f"{max_subgraphs_per_block} — split into separate `graph LR` "
                f"blocks instead of clustering"
            )

        # Node count.
        node_pat = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_]*)\s*[\[\(]", re.MULTILINE)
        nodes = []
        seen: set[str] = set()
        for m in node_pat.finditer(raw):
            nid = m.group(1)
            if nid.lower() == "subgraph":
                continue
            if nid not in seen:
                seen.add(nid)
                nodes.append(nid)
        if isinstance(max_nodes_per_block, int) and len(nodes) > max_nodes_per_block:
            report.issues.append(
                f"§{heading} chain {idx}: {len(nodes)} nodes found, max "
                f"{max_nodes_per_block} allowed — chains with more steps "
                f"belong as standalone walkthroughs in §3.2+"
            )

        # Label limits.
        if isinstance(max_lines, int) or isinstance(max_chars, int):
            for lblmatch in re.finditer(r'"([^"]+)"', raw):
                lbl = lblmatch.group(1)
                parts = re.split(r"<br/?>", lbl)
                if isinstance(max_lines, int) and len(parts) > max_lines:
                    report.issues.append(
                        f"§{heading} chain {idx}: node label has "
                        f"{len(parts)} lines, max {max_lines} allowed: "
                        f"{lbl[:80]!r}"
                    )
                if isinstance(max_chars, int):
                    for p in parts:
                        plain = re.sub(r"<[^>]+>", "", p).strip()
                        if len(plain) > max_chars:
                            report.issues.append(
                                f"§{heading} chain {idx}: label line exceeds {max_chars} chars: {plain[:60]!r}…"
                            )
                            break

        # classDef presence.
        for css_name, css_value in classdefs.items():
            cd_pat = re.compile(r"classDef\s+" + re.escape(css_name) + r"\s+" + re.escape(css_value))
            if not cd_pat.search(raw):
                report.issues.append(
                    f"§{heading} chain {idx}: missing/divergent classDef `{css_name}` — expected `{css_value}`"
                )

        # Per-block threat traceability — at least one T-NNN that exists in §8.
        if require_threat:
            t_in_block = set()
            for m in _T_ID_RE_LOCAL.finditer(raw):
                t_in_block.add(f"T-{m.group(1).zfill(3)}")
            if not t_in_block:
                report.issues.append(
                    f"§{heading} chain {idx}: no T-NNN reference in any node "
                    f"label — chains without threat references are data-flow "
                    f"diagrams, not attack chains"
                )
            elif t_ids_register:
                unknown = t_in_block - t_ids_register
                for tid in sorted(unknown):
                    report.issues.append(
                        f"§{heading} chain {idx}: cites {tid} but no matching entry in §8 Findings Register"
                    )


def _critical_threats_from_yaml(output_dir: Path) -> list[dict]:
    """Read `threat-model.yaml` and return the list of Critical-severity
    threats. Returns [] when the file is missing or unreadable so the
    coverage checker degrades to a no-op instead of false-positiving.
    """
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        return []
    try:
        import yaml as _yaml  # local — qa_checks doesn't import yaml at module scope
        data = _fast_yaml_load(yaml_path.read_text(encoding="utf-8")) or {}
    except (OSError, Exception):
        return []
    crits: list[dict] = []
    for t in data.get("threats") or []:
        if not isinstance(t, dict):
            continue
        sev = (t.get("risk") or t.get("severity") or "").strip().lower()
        if sev == "critical":
            crits.append(t)
    return crits


def check_walkthrough_coverage(
    md_path: Path,
    output_dir: Path,
    contract_path: Path = DEFAULT_CONTRACT_PATH,
) -> Report:
    """Enforce `attack_walkthroughs.per_critical_subsection` from the contract.

    Behaviour:
      * Skips when `.skill-config.json` carries `SKIP_ATTACK_WALKTHROUGHS=true`.
      * Skips when the contract turns the rule off.
      * Reads Critical threats from `threat-model.yaml` (single source of truth
        for severity — `Risk Distribution` in the MD is rendered FROM that yaml).
      * Counts `### 3.<n> ...` H3 sub-sections inside `## 3. Attack Walkthroughs`
        excluding `### 3.1 Attack Chain Overview` (the chain overview is NOT a
        per-Critical walkthrough).
      * Flags each Critical T-NNN whose ID does not appear in any §3.x
        sub-section.

    The check matches the owning T-NNN on each sub-section's canonical
    `**Source:** [T-NNN]` line — NOT the heading. The deterministic renderer
    (walkthrough_renderer.py) keeps the H3 heading short and T-NNN-free so it
    stays under check_heading_hygiene's length limit, and emits the T-NNN on
    the `**Source:**` line directly under the heading. A heading of the form
    `### 3.2 T-001 — …` is still accepted via the heading-line fallback. A
    missing T-NNN therefore means the walkthrough was not authored at all,
    independent of how long the finding title is.
    """
    report = Report("walkthrough_coverage")
    contract = _read_contract(contract_path)
    if not contract:
        return report

    aw = (contract.get("sections") or {}).get("attack_walkthroughs") or {}
    if not aw.get("per_critical_subsection"):
        report.ok = 1
        return report

    # Skip when --no-walkthroughs / quick depth turned authoring off.
    try:
        import json as _json_wc

        _cfg_path = output_dir / ".skill-config.json"
        if _cfg_path.is_file():
            _cfg = _json_wc.loads(_cfg_path.read_text(encoding="utf-8"))
            if _cfg.get("SKIP_ATTACK_WALKTHROUGHS") or _cfg.get("skip_attack_walkthroughs"):
                report.ok = 1
                return report
    except Exception:
        pass

    crits = _critical_threats_from_yaml(output_dir)
    if not crits:
        # No Critical threats -> nothing to enforce.
        report.ok = 1
        return report

    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return report

    # Slice §3 body.
    m3 = re.search(r"^##\s+3\.\s+Attack Walkthroughs\b", text, re.MULTILINE)
    if not m3:
        report.issues.append(
            f"§3 Attack Walkthroughs heading not found — contract requires "
            f"one walkthrough per Critical ({len(crits)} expected)."
        )
        return report
    tail = text[m3.end():]
    nxt = re.search(r"^##\s+\d+\.\s", tail, re.MULTILINE)
    sec3 = tail[: nxt.start()] if nxt else tail

    # Collect per-Critical §3.x sub-sections as full-text blocks (heading +
    # body up to the next §3.x heading). §3 is a flat list of per-Critical
    # walkthroughs (§3.1, §3.2, …) — the §3.1 chain overview was retired, so
    # every §3.N is now a walkthrough. We scan each block's `**Source:**
    # [T-NNN]` line — NOT the heading — for the owning Critical id (the
    # deterministic renderer keeps the heading short and T-NNN-free to
    # satisfy check_heading_hygiene).
    h3_re = re.compile(r"^###\s+3\.(\d+)\s+(.+?)$", re.MULTILINE)
    h3_matches = list(h3_re.finditer(sec3))
    subsection_blocks: list[str] = []
    for idx, mh in enumerate(h3_matches):
        block_end = (
            h3_matches[idx + 1].start() if idx + 1 < len(h3_matches) else len(sec3)
        )
        subsection_blocks.append(sec3[mh.start():block_end])

    # Each per-Critical block declares its owning threat on the canonical
    # `**Source:** [T-NNN]` line; fall back to a T-NNN/F-NNN token in the
    # heading line when the Source line is absent (legacy fragments). Matching
    # the Source line (not "any T-NNN in the block") avoids counting a
    # compound-chain cross-reference (e.g. "compound with T-009") as if it
    # were T-009's own walkthrough.
    source_re = re.compile(r"\*\*Source:\*\*\s*\[[TF]-(\d{3,4})\]")
    seen_t_ids: set[str] = set()
    for block in subsection_blocks:
        ms = source_re.search(block)
        if ms:
            seen_t_ids.add(f"T-{ms.group(1).zfill(3)}")
            continue
        head_line = block.splitlines()[0] if block else ""
        mh = _T_ID_RE_LOCAL.search(head_line)
        if mh:
            seen_t_ids.add(f"T-{mh.group(1).zfill(3)}")

    missing: list[dict] = []
    for t in crits:
        tid = (t.get("id") or t.get("t_id") or "").strip().upper()
        if not tid:
            continue
        # Normalise to canonical T-NNN.
        m_norm = re.match(r"^[TF]-(\d{3,4})$", tid)
        if m_norm:
            tid = f"T-{m_norm.group(1).zfill(3)}"
        if tid not in seen_t_ids:
            missing.append({"id": tid, "title": (t.get("title") or "").strip()})

    if missing:
        n_covered = len(crits) - len(missing)
        report.issues.append(
            f"§3 Attack Walkthroughs: {n_covered}/{len(crits)} Critical findings "
            f"have a walkthrough — missing "
            f"{', '.join(m['id'] for m in missing)}. Contract requires one "
            f"`### 3.x` sub-section per Critical threat, each declaring its "
            f"T-NNN on a `**Source:** [T-NNN]` line and carrying its own "
            f"`sequenceDiagram`."
        )
        # Per-missing entries for repair-plan granularity.
        for m in missing:
            report.issues.append(
                f"§3 missing walkthrough for {m['id']} — {m['title'][:120]}"
            )

    if not report.issues:
        report.ok = 1
    return report


def check_walkthrough_depth(
    md_path: Path,
    output_dir: Path,
    contract_path: Path = DEFAULT_CONTRACT_PATH,
) -> Report:
    """Enforce `attack_walkthroughs.walkthrough_depth` from the contract.

    Three sub-rules (all skip when SKIP_ATTACK_WALKTHROUGHS=true):

      * `min_body_lines` — each §3.x walkthrough body (between the H3
        heading and the next H3 / H2) must have at least N lines. A 5-node
        sequenceDiagram + 2 prose lines stub falls under ~8 lines; a real
        walkthrough is 25+. Guards against the "lazy LLM produced a stub"
        regression seen 2026-05.

      * `require_alt_else_block` — each §3.x sequenceDiagram MUST contain
        an `alt Current state` line AND an `else After ...` line. This is
        the canonical structure that gives the reader the pre-fix-vs-post-
        fix story; without it, the diagram is just an attack narrative
        without remediation context.

      * `min_chain_overview_nodes_per_block` — §3.1 chains must have at
        least N distinct nodes. Catches the 3-node
        `attacker -> threat -> impact` stub form. Complements the existing
        `chain_compactness.max_nodes_per_block` upper bound.
    """
    report = Report("walkthrough_depth")
    contract = _read_contract(contract_path)
    if not contract:
        return report

    aw = (contract.get("sections") or {}).get("attack_walkthroughs") or {}
    rules = aw.get("walkthrough_depth") or {}
    if not rules:
        report.ok = 1
        return report

    # Skip when --no-walkthroughs / quick depth turned authoring off.
    try:
        import json as _json_wd

        _cfg_path = output_dir / ".skill-config.json"
        if _cfg_path.is_file():
            _cfg = _json_wd.loads(_cfg_path.read_text(encoding="utf-8"))
            if _cfg.get("SKIP_ATTACK_WALKTHROUGHS") or _cfg.get("skip_attack_walkthroughs"):
                report.ok = 1
                return report
    except Exception:
        pass

    min_body_lines = rules.get("min_body_lines")
    require_alt_else = bool(rules.get("require_alt_else_block"))
    min_overview_nodes = rules.get("min_chain_overview_nodes_per_block")
    required_labelled = list(rules.get("required_labelled_sections") or [])
    forbidden_placeholders = list(rules.get("forbidden_placeholders") or [])
    require_chain_takeaway = bool(rules.get("require_chain_key_takeaway"))
    require_chain_heading = bool(rules.get("require_chain_subsection_heading"))

    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return report

    # Slice §3.
    m3 = re.search(r"^##\s+3\.\s+Attack Walkthroughs\b", text, re.MULTILINE)
    if not m3:
        report.ok = 1
        return report
    tail = text[m3.end():]
    nxt = re.search(r"^##\s+\d+\.\s", tail, re.MULTILINE)
    sec3 = tail[: nxt.start()] if nxt else tail

    # --- 1. §3.1 chain overview node-count floor.
    # Inline mermaid forms like `A[X] --> B[Y]` define both A and B on a
    # single line; the chain_compactness check uses a `^\s*<id>` anchor
    # which misses the second id. For the LOWER-bound check we need to
    # count every distinct node id, including those that appear after
    # `-->` / `-.->` arrows. The regex below matches both forms.
    if isinstance(min_overview_nodes, int):
        body_31 = _extract_h3_section_body(text, "3.1 Attack Chain Overview")
        if body_31:
            blocks = re.findall(r"```mermaid\n(.*?)\n```", body_31, re.DOTALL)
            # Two patterns combined:
            #   (a) `<id>[`, `<id>(`, `<id>{`  — node with shape body
            #   (b) `<arrow> <id>` where arrow ∈ {-->, -.->, ==>, ~~~~, --, ...}
            node_shape = re.compile(
                r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)\s*[\[\(\{]"
            )
            node_after_arrow = re.compile(
                r"(?:--\s*>|-\.\s*->|==\s*>|~~~)\s*\|?[^|]*?\|?\s*"
                r"([A-Za-z_][A-Za-z0-9_]*)\b"
            )
            mermaid_keywords = {
                "subgraph", "end", "classdef", "class", "linkstyle",
                "style", "click", "direction", "graph", "flowchart",
            }
            for idx, raw in enumerate(blocks, start=1):
                seen: set[str] = set()
                for m in node_shape.finditer(raw):
                    nid = m.group(1)
                    if nid.lower() in mermaid_keywords:
                        continue
                    seen.add(nid)
                for m in node_after_arrow.finditer(raw):
                    nid = m.group(1)
                    if nid.lower() in mermaid_keywords:
                        continue
                    seen.add(nid)
                if len(seen) < min_overview_nodes:
                    report.issues.append(
                        f"§3.1 chain {idx}: {len(seen)} nodes found, "
                        f"contract requires ≥ {min_overview_nodes} (chains "
                        f"with fewer steps read as stubs and add no signal "
                        f"beyond the §8 finding title)."
                    )

    # --- 2. Per-§3.x walkthrough body length + alt/else block.
    h3_re = re.compile(r"^###\s+3\.(\d+)\s+(.+?)$", re.MULTILINE)
    matches = list(h3_re.finditer(sec3))
    for i, mh in enumerate(matches):
        sub_num = int(mh.group(1))
        heading = mh.group(2).strip()
        body_start = mh.end()
        body_end = matches[i + 1].start() if i + 1 < len(matches) else len(sec3)
        body = sec3[body_start:body_end]
        non_blank = [ln for ln in body.splitlines() if ln.strip()]

        if isinstance(min_body_lines, int) and len(non_blank) < min_body_lines:
            report.issues.append(
                f"§3.{sub_num} '{heading[:60]}': body has {len(non_blank)} "
                f"non-blank lines, contract requires ≥ {min_body_lines}. "
                f"A real walkthrough carries (1) Attack narrative, (2) "
                f"`sequenceDiagram` with `alt Current state` / `else After "
                f"mitigation`, (3) Impact paragraph, (4) Recommended fix "
                f"linking the M-NNN mitigation."
            )

        if require_alt_else:
            seq_blocks = re.findall(
                r"```mermaid\n(.*?)\n```", body, re.DOTALL
            )
            seq_blocks = [b for b in seq_blocks if "sequenceDiagram" in b]
            if not seq_blocks:
                report.issues.append(
                    f"§3.{sub_num} '{heading[:60]}': no `sequenceDiagram` "
                    f"block — every per-Critical walkthrough must contain one."
                )
            else:
                for j, raw in enumerate(seq_blocks, start=1):
                    has_alt = re.search(
                        r"^\s*alt\s+(?:Current state|Vulnerable|vuln)",
                        raw,
                        re.MULTILINE | re.IGNORECASE,
                    )
                    has_else = re.search(
                        r"^\s*else\s+(?:After\s+(?:mitigation|M-\d{3,4}))",
                        raw,
                        re.MULTILINE | re.IGNORECASE,
                    )
                    if not (has_alt and has_else):
                        report.issues.append(
                            f"§3.{sub_num} sequenceDiagram {j}: missing "
                            f"`alt Current state` / `else After mitigation` "
                            f"branch — the canonical walkthrough shape "
                            f"contrasts the vulnerable path with the "
                            f"post-mitigation path."
                        )

        # --- 3. Per-§3.x required labelled sections (2026-05 iteration 2).
        # Every walkthrough must carry the contract's
        # `required_labelled_sections` list as bold-headed (`**Title**`)
        # blocks. Missing labels indicate a stub walkthrough that does not
        # match the labelled-form contract.
        if required_labelled:
            body_lower = body.lower()
            for label in required_labelled:
                # Match `**Label**` on its own line (allowing trailing
                # punctuation / colon), case-insensitive.
                pat = re.compile(
                    r"^\s*\*\*" + re.escape(label) + r"\*\*\s*$",
                    re.MULTILINE | re.IGNORECASE,
                )
                if not pat.search(body):
                    report.issues.append(
                        f"§3.{sub_num} '{heading[:60]}': missing required "
                        f"labelled section `**{label}**`. Each walkthrough "
                        f"must carry every section from the contract's "
                        f"`walkthrough_depth.required_labelled_sections` "
                        f"list in bold-header form."
                    )

        # --- 4. Forbidden placeholders. Surviving WALKTHROUGH_FILL tokens
        # mean the renderer agent failed to replace the scaffold prompts.
        for tok in forbidden_placeholders:
            if tok in body:
                count = body.count(tok)
                report.issues.append(
                    f"§3.{sub_num} '{heading[:60]}': {count} surviving "
                    f"`{tok}` placeholder(s) — the renderer must replace "
                    f"every `<!-- {tok}: ... -->` comment with repo-specific "
                    f"prose before composing."
                )

    # --- 5. §3.1 chain heading / `**Key takeaway:**` enforcement.
    # The contract requires each chain to be its own `#### Chain N — <name>`
    # block followed by a `graph LR` block and a `**Key takeaway:**` line.
    # Reject the "single mega-block" form (all chains in one mermaid block
    # without sub-section headings) — historic anti-pattern that breaks the
    # right-side TOC and forces the reader to interpret one wide graph.
    body_31_full = _extract_h3_section_body(text, "3.1 Attack Chain Overview") or ""
    if body_31_full:
        # Count `#### Chain N — ...` headings.
        chain_h4_re = re.compile(
            r"^####\s+Chain\s+\d+\s+—\s+\S", re.MULTILINE
        )
        chain_h4_count = len(chain_h4_re.findall(body_31_full))
        # Count graph LR blocks.
        graph_lr_count = len(re.findall(
            r"```mermaid\s*\n\s*graph\s+LR", body_31_full
        ))

        if require_chain_heading and graph_lr_count > 0 and chain_h4_count == 0:
            report.issues.append(
                "§3.1 Attack Chain Overview: no `#### Chain N — <name>` "
                f"sub-sections found, but {graph_lr_count} `graph LR` "
                "block(s) are present. The contract requires one chain "
                "per `#### Chain N` block (forbidden mega-block form)."
            )

        if (
            require_chain_heading
            and chain_h4_count > 0
            and graph_lr_count > 0
            and chain_h4_count != graph_lr_count
        ):
            report.issues.append(
                f"§3.1 Attack Chain Overview: {chain_h4_count} chain "
                f"heading(s) but {graph_lr_count} graph LR block(s) — "
                "each chain MUST have its own `graph LR` block (1:1)."
            )

        if require_chain_takeaway and chain_h4_count > 0:
            takeaway_count = len(re.findall(
                r"^\*\*Key takeaway:\*\*", body_31_full, re.MULTILINE
            ))
            if takeaway_count < chain_h4_count:
                report.issues.append(
                    f"§3.1 Attack Chain Overview: {chain_h4_count} "
                    f"chain block(s) but only {takeaway_count} "
                    f"`**Key takeaway:**` line(s) — every chain must "
                    f"close with a one-sentence Key-takeaway summary."
                )

    if not report.issues:
        report.ok = 1
    return report


def check_recon_iam_bridge(
    md_path: Path,
    output_dir: Path,
    contract_path: Path = DEFAULT_CONTRACT_PATH,
) -> Report:
    """Fix (5): cross-validate recon signals against the configured IAM section.

    If the recon summary contains TOTP/2FA signals (totpSecret, routes/2fa,
    otplib, /rest/2fa, totp_token_required) but the configured identity /
    authentication section does not mention a 2fa/totp/mfa control, flag it
    as an error.

    This closes the gap where routes/2fa.ts is found by recon but never
    surfaces in .security-controls.json, causing TOTP to be silently absent
    from §7.
    """
    report = Report("recon_iam_bridge")
    contract = _read_contract(contract_path)
    if not contract:
        return report

    sec = (contract.get("sections") or {}).get("security_architecture") or {}
    rules_map = sec.get("domain_required_rules") or {}
    bridge_rules: list[tuple[str, dict]] = []
    for domain_title, rules in rules_map.items():
        for r in rules or []:
            if isinstance(r, dict) and r.get("rule") == "recon_iam_bridge":
                bridge_rules.append((str(domain_title), r))
    if not bridge_rules:
        report.ok = 1
        return report

    recon_path = output_dir / ".recon-summary.md"
    if not recon_path.is_file():
        # No recon summary — skip silently (different check handles missing files).
        report.ok = 1
        return report
    try:
        recon_text = recon_path.read_text(encoding="utf-8")
    except OSError:
        report.ok = 1
        return report

    try:
        md_text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return report

    for domain_title, rule in bridge_rules:
        enforcement = (rule.get("enforcement") or "warning").strip().lower()
        section_title = (rule.get("section_title") or domain_title).strip()
        signal_patterns = rule.get("recon_signal_patterns") or []
        required_tokens = rule.get("required_iam_tokens") or []

        # Check if any recon signal fires.
        recon_hit = any(pat in recon_text for pat in signal_patterns if pat)
        if not recon_hit:
            continue  # No signal in recon — rule does not apply.

        # Signal present: verify at least one matching token in the configured
        # §7 section body. The current v2 shape no longer requires a control
        # table, so scan the section prose, Controls-covered line, H4 headings,
        # and any diagrams as one section-local body.
        section_body = _extract_section_body(md_text, r"^###\s+" + re.escape(section_title) + r"[ \t]*$")
        if section_body is None:
            continue  # missing heading is owned by check_contract.

        haystack = section_body.lower()
        found = any(str(tok).lower() in haystack for tok in required_tokens if tok)
        if not found:
            signals_found = [p for p in signal_patterns if p in recon_text]
            issue = (
                f"§{section_title}: recon summary contains 2FA/TOTP signals "
                f"({signals_found}) but the section has no control text "
                f"matching tokens {required_tokens}. Add a TOTP/2FA subcontrol "
                f"under this section and list it in `**Controls covered:**`."
            )
            if enforcement == "error":
                report.issues.append(issue)
            else:
                report.warnings.append(issue)

    if not report.issues:
        report.ok = 1
    return report


def check_falls_short_format(md_path: Path, contract_path: Path = DEFAULT_CONTRACT_PATH) -> Report:
    """Fix (7): enforce bullet-list format when `**Where it falls short.**`
    contains ≥N distinct [F/T-NNN] references in a single paragraph.

    Prose paragraphs mixing 3+ unrelated findings violate prose-style Rule 4
    ("enumerations of three or more items become bullet lists"). This check
    reads the threshold from contract falls_short_bullet_threshold rule.
    """
    report = Report("falls_short_format")
    contract = _read_contract(contract_path)
    if not contract:
        return report

    sec = (contract.get("sections") or {}).get("security_architecture") or {}
    rules_map = sec.get("domain_required_rules") or {}
    all_domain_rules = rules_map.get("all_domains") or []
    threshold_rule = next(
        (r for r in all_domain_rules if isinstance(r, dict) and r.get("rule") == "falls_short_bullet_threshold"),
        None,
    )
    if threshold_rule is None:
        report.ok = 1
        return report

    min_refs = int(threshold_rule.get("min_refs_before_bullet", 3))
    enforcement = (threshold_rule.get("enforcement") or "warning").strip().lower()

    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return report

    # Find all `**Where it falls short.**` blocks and inspect each paragraph.
    _FNT_REF_RE = re.compile(r"\[[FT]-\d{3,}\]")
    _FALLS_SHORT_RE = re.compile(
        r"\*\*Where it falls short\.\*\*(.+?)(?=\n\n\*\*|\n###|\n##|\Z)",
        re.DOTALL,
    )
    for m in _FALLS_SHORT_RE.finditer(text):
        block = m.group(1)
        # Split into paragraphs (blank-line separated).
        for para in re.split(r"\n{2,}", block):
            para = para.strip()
            if not para:
                continue
            refs = _FNT_REF_RE.findall(para)
            unique_refs = set(refs)
            if len(unique_refs) >= min_refs:
                # Check if this paragraph uses a bullet list already.
                has_bullets = bool(re.search(r"^\s*[-*]", para, re.MULTILINE))
                if not has_bullets:
                    excerpt = para[:80].replace("\n", " ")
                    issue = (
                        f"§7 'Where it falls short.' paragraph contains "
                        f"{len(unique_refs)} finding references ({sorted(unique_refs)}) "
                        f"but uses prose instead of a bullet list — reformat as one "
                        f"bullet per finding (prose-style Rule 4 / QB-9): "
                        f"{excerpt!r}…"
                    )
                    if enforcement == "error":
                        report.issues.append(issue)
                    else:
                        report.warnings.append(issue)

    if not report.issues:
        report.ok = 1
    return report


def check_paragraph_density(md_path: Path, contract_path: Path = DEFAULT_CONTRACT_PATH) -> Report:
    """M-6: Generic paragraph-density check across §7 narrative subsections.

    Parallel to `check_falls_short_format` but NOT scoped to `**Where it falls
    short.**` blocks. Scans every §7.x subsection's prose paragraphs for ≥N
    distinct [F/T-NNN] OR [M-NNN] references — when found in a single prose
    paragraph (no bullets), emits a warning. Tables and code-fences are
    excluded so a dense register-style table cell does not falsely fire.

    Threshold + enforcement read from contract rule
    `sections.security_architecture.domain_required_rules.all_domains[
        paragraph_density_threshold].min_refs_before_bullet`.
    """
    report = Report("paragraph_density")
    contract = _read_contract(contract_path)
    if not contract:
        return report

    sec = (contract.get("sections") or {}).get("security_architecture") or {}
    rules_map = sec.get("domain_required_rules") or {}
    all_domain_rules = rules_map.get("all_domains") or []
    threshold_rule = next(
        (r for r in all_domain_rules if isinstance(r, dict)
         and r.get("rule") == "paragraph_density_threshold"),
        None,
    )
    if threshold_rule is None:
        report.ok = 1
        return report

    min_refs = int(threshold_rule.get("min_refs_before_bullet", 3))
    enforcement = (threshold_rule.get("enforcement") or "warning").strip().lower()

    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return report

    # Strip fenced code blocks so embedded examples do not trip the check.
    code_fence_re = re.compile(r"```.*?```", re.DOTALL)
    text_no_code = code_fence_re.sub("", text)

    # Match each §7.x subsection (### 7.N <title> through next ### 7.M or ##).
    sec7_re = re.compile(
        r"(### 7\.\d+\s[^\n]*\n)(.*?)(?=\n### 7\.\d+\s|\n## |\Z)",
        re.DOTALL,
    )

    ref_re = re.compile(r"\[(?:[FT]-\d{3,}|M-\d{3,})\]")
    table_line_re = re.compile(r"^\s*\|")
    falls_short_block_re = re.compile(
        r"\*\*Where it falls short\.\*\*.+?(?=\n\n\*\*|\n###|\n##|\Z)",
        re.DOTALL,
    )

    for sec_match in sec7_re.finditer(text_no_code):
        heading = sec_match.group(1).strip()
        body = sec_match.group(2)
        # Strip table lines (start with `|`) so dense register rows are excluded.
        body_no_tables = "\n".join(
            ln for ln in body.splitlines() if not table_line_re.match(ln)
        )
        # Skip falls-short blocks — check_falls_short_format owns those.
        for fs in falls_short_block_re.findall(body_no_tables):
            body_no_tables = body_no_tables.replace(fs, "")

        # Split into paragraphs (blank-line separated).
        for para in re.split(r"\n{2,}", body_no_tables):
            para = para.strip()
            if not para:
                continue
            # Skip bullet-list paragraphs (start with - or *)
            if re.match(r"^\s*[-*]\s", para):
                continue
            refs = ref_re.findall(para)
            unique_refs = set(refs)
            if len(unique_refs) >= min_refs:
                excerpt = para[:80].replace("\n", " ")
                issue = (
                    f"{heading}: dense prose paragraph contains "
                    f"{len(unique_refs)} finding/mitigation references "
                    f"({sorted(unique_refs)}) but uses prose instead of a "
                    f"bullet list — reformat as one bullet per reference "
                    f"(prose-style Rule 4): {excerpt!r}…"
                )
                if enforcement == "error":
                    report.issues.append(issue)
                else:
                    report.warnings.append(issue)

    if not report.issues:
        report.ok = 1
    return report


def check_hypothesis_validation_objective(md_path: Path) -> Report:
    """M-19 alt: Flag threat_hypotheses[] entries whose ``validation_objective``
    is empty / placeholder.

    The schema marks the field REQUIRED but the LLM occasionally emits empty
    strings or the sentinel ``_pending validation objective_``. Silently
    filling it would mask the agent bug; this check surfaces it instead so
    the operator knows the hypothesis is unactionable.

    Looks for §7.2 "Threat Hypotheses Requiring Validation" table rows; the
    rightmost column is the validation column. Threshold: empty cell or
    placeholder text triggers a warning per row.
    """
    report = Report("hypothesis_validation_objective")
    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return report

    # Locate the hypothesis table — bounded by the heading + an immediate
    # markdown table starting with `| ID |`.
    block_re = re.compile(
        r"#### Threat Hypotheses Requiring Validation\s*\n.*?"
        r"\| ID \|.*?\n\|[-| ]+\|\n((?:\|.*\n)*)",
        re.DOTALL,
    )
    m = block_re.search(text)
    if not m:
        report.ok = 1
        return report

    table_body = m.group(1)
    placeholder_re = re.compile(
        r"(?:_pending validation objective_|_\?_|^—$)",
        re.IGNORECASE,
    )
    for line in table_body.splitlines():
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 5:
            continue
        hid = cells[0]
        validation = cells[-1]
        if not validation or placeholder_re.search(validation):
            report.warnings.append(
                f"§7.2 hypothesis {hid}: `validation_objective` is empty / "
                f"placeholder ({validation!r}) — the LLM did not emit a "
                f"validate-or-refute objective. Hypothesis is unactionable; "
                f"either populate the field in `threat-model.yaml → "
                f"threat_hypotheses[].validation_objective` or remove the "
                f"hypothesis."
            )
    if not report.issues:
        report.ok = 1
    return report


def check_inline_code_format(md_path: Path) -> Report:
    """M-12c: Flag path-shaped tokens that appear unbacked in prose.

    Conservative scope — only path-like tokens of the form
    ``segment/segment.ext[:line]`` with a recognised source-tree
    extension. Function-call tokens like ``eval()`` and dotted accesses
    are NOT flagged here because they generate too many false positives
    on benign prose ("the eval() builtin is deprecated"); prose-style.md
    Rule 6 is the authoring guidance and the QA gate enforces only the
    high-cost / high-signal subset.

    Excluded contexts:
      - inside backticks (`...`)
      - inside code fences (```...```)
      - inside markdown link targets (`[label](path/to/x)`)
      - inside HTML attributes (e.g. `href="..."`)
      - in headings (`#`/`##`/`###`/`####`/`#####`/`######` lines)
      - in table rows (lines starting with `|`)
    """
    report = Report("inline_code_format")
    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return report

    # Drop fenced code blocks entirely.
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)

    extensions = (
        "ts", "tsx", "js", "jsx", "json", "yaml", "yml",
        "py", "go", "rs", "java", "kt", "rb", "php", "cs",
        "c", "h", "cpp", "hpp", "swift", "scala",
        "md", "html", "css", "scss", "sql",
        "sh", "bash", "ps1", "toml", "lock", "env",
    )
    path_re = re.compile(
        r"[A-Za-z][\w.-]*/[\w./-]+\.(?:"
        + "|".join(extensions)
        + r")(?::\d+)?\b"
    )
    backtick_span_re = re.compile(r"`[^`\n]+`")
    md_link_url_re = re.compile(r"\]\(([^)]+)\)")
    html_attr_re = re.compile(r'(?:href|src|action|formaction)="[^"]+"')

    lines = text.splitlines()
    flagged: list[tuple[int, str]] = []
    in_html_block = False

    for lineno, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        # Skip headings, table rows.
        if stripped.startswith("#") or stripped.startswith("|"):
            continue
        # Skip raw-HTML blockquote / blocks roughly (best-effort — full
        # HTML parsing is out of scope for a regex gate).
        if "<blockquote" in stripped:
            in_html_block = True
        if in_html_block:
            if "</blockquote>" in stripped:
                in_html_block = False
            continue

        # Mask out content that is legitimately allowed to contain paths:
        # already-backticked spans, markdown-link URLs, HTML attributes.
        masked = backtick_span_re.sub(lambda m: " " * len(m.group(0)), line)
        masked = md_link_url_re.sub(lambda m: "](" + " " * len(m.group(1)) + ")", masked)
        masked = html_attr_re.sub(lambda m: " " * len(m.group(0)), masked)

        for m in path_re.finditer(masked):
            tok = m.group(0)
            # Skip the dotted glob exemption (e.g. `routes/**` — used in
            # YAML-derived prose) — these are wildcards, not file paths.
            if "**" in tok or "*" in tok:
                continue
            flagged.append((lineno, tok))

    if flagged:
        # Aggregate per-token to keep output compact.
        from collections import Counter
        counter = Counter(tok for _, tok in flagged)
        for tok, n in counter.most_common(20):
            lines_with = sorted({ln for ln, t in flagged if t == tok})[:3]
            report.warnings.append(
                f"unbacked path-shaped token {tok!r} appears {n}× in prose "
                f"(line(s) {lines_with}{'…' if n > 3 else ''}) — wrap in "
                f"backticks per prose-style Rule 6"
            )
    if not report.issues:
        report.ok = 1
    return report


# ---------------------------------------------------------------------------
# 2026-05 R-7 — Inverse check: ``label-as-code`` detector.
#
# Background: the prose-fixer aggressively backticks code-shaped tokens
# (paths, function calls, JWT literals, …). The opposite drift — names
# and labels wrapped in backticks when they should be plain prose — is
# easier for an LLM to introduce. Examples observed on the 2026-05
# juice-shop run:
#   * ``"the `Why` / `How` / verification fields"``  — labels, not code
#   * ``"takes one HTTP `POST`"``                      — protocol noun, not code
#   * ``"each row's `notes` column"``                  — table-column label
#
# This check scans prose for single-word backticked tokens against an
# allowlist of known-non-code labels and emits a warning per occurrence.
# Conservative — only the explicit allowlist fires; ambiguous tokens
# (``eval``, ``null``, ``catch``) stay backticked because in security
# prose they ARE typically code references.
# ---------------------------------------------------------------------------

# Tokens that, when seen inside `` ` ` `` in prose, are LABELS not code.
# Add a token here only when it has been observed as a false positive in
# a real assessment — the allowlist's purpose is to flag drift, not to
# strip backticks from anything that could conceivably be a label.
_LABEL_TOKENS: frozenset[str] = frozenset({
    # MS / threat-register / mitigation-register field labels
    "Why", "How", "Effort", "Priority", "Severity",
    "Addresses", "Component", "Components", "Mitigation", "Mitigations",
    "Notes", "Vektor", "Classification", "Issue", "Impact", "Fix",
    "Location", "Evidence",
    "Verification", "Steps",
    # Schema column / field names in lower case
    "notes", "addresses", "priority", "effort", "severity",
    "verify",  # JWT verify ALONE — should be jwt.verify() if code
    # HTTP methods written as bare nouns ("takes one HTTP POST")
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
})

# Detects ``` `Word` ``` in prose where Word matches the allowlist. The
# token MUST be exactly one identifier (no dots, no parens, no slashes —
# those shapes are real code).
_LABEL_AS_CODE_RE = re.compile(r"`([A-Za-z]{3,15})`")


def check_label_as_code(md_path: Path) -> Report:
    """R-7: warn when labels / field names / bare HTTP methods are
    backticked in prose. Companion to ``check_inline_code_format`` (which
    flags the inverse — code-shaped tokens left bare).

    Conservative scope:
      * Only matches tokens of length 3-15 chars made of plain Latin
        letters. Multi-word tokens, hyphenated tokens, and any token with
        a dot/paren/slash are skipped (those shapes are real code).
      * Only matches tokens in the curated ``_LABEL_TOKENS`` allowlist —
        ambiguous tokens like ``eval``, ``null``, ``catch`` are left
        backticked because in security prose they ARE typically code
        references.
      * Skips fenced code blocks, headings, table rows, HTML blockquotes.

    All findings are warnings (non-blocking). The check exists to surface
    drift back to the author, not to fail the build.
    """
    report = Report("label_as_code")
    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return report

    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    lines = text.splitlines()
    flagged: list[tuple[int, str]] = []
    in_html_block = False
    for lineno, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        if "<blockquote" in stripped:
            in_html_block = True
        if in_html_block:
            if "</blockquote>" in stripped:
                in_html_block = False
            continue
        # Drop HTML inline code spans + link URLs so we don't accidentally
        # match `<code>POST</code>` content or URL fragments.
        masked = re.sub(r"<code\b.*?</code>", "", line, flags=re.IGNORECASE)
        masked = re.sub(r"\]\(([^)]+)\)", lambda m: "](" + " " * len(m.group(1)) + ")", masked)
        for m in _LABEL_AS_CODE_RE.finditer(masked):
            tok = m.group(1)
            if tok in _LABEL_TOKENS:
                flagged.append((lineno, tok))
    if flagged:
        from collections import Counter
        counter = Counter(tok for _, tok in flagged)
        for tok, n in counter.most_common(20):
            lines_with = sorted({ln for ln, t in flagged if t == tok})[:3]
            report.warnings.append(
                f"label-as-code token `{tok}` appears {n}× in prose "
                f"(line(s) {lines_with}{'…' if n > 3 else ''}) — unwrap "
                f"the backticks (label, not code), or rewrite as a proper "
                f"code reference such as `<obj>.{tok}()` if you meant the "
                f"function call."
            )
    report.ok = 1
    return report


# ---------------------------------------------------------------------------
# Cut-2: schema_v2 §7.X "architectural prose" check.
# Catches the two failure modes of the legacy §7 template that the new
# code-first pattern is meant to eliminate:
#
#   (a) Definitional opener: "X is the process by which …" / "X controls
#       govern how …" — pure textbook content that adds no signal.
#   (b) Templated mechanism vocabulary: `boundary`, `mechanism layer`,
#       `central * layer`, `codified rule`, `enforce a policy`,
#       `security posture`, etc. — consultant-deck words that read as
#       AI-generated.
#
# All flagged occurrences are warnings (non-blocking). The check exists
# to surface drift back to the author, not to fail the build.
# ---------------------------------------------------------------------------

# Phrases the new pattern bans (case-insensitive whole-word match).
# Order matters only for readability; the matcher checks all.
_ARCH_PROSE_BANNED_PATTERNS: list[tuple[str, str]] = [
    # (regex, friendly_name)
    (r"\bcodified rule\b",                    "codified rule"),
    (r"\benforced (?:parameterization |secret |authorization |authentication )?boundary\b",
                                              "enforced ... boundary"),
    (r"\bmechanism layer\b",                  "mechanism layer"),
    (r"\bcentral [A-Za-z]+? layer\b",         "central ... layer"),
    (r"\bsecret management substrate\b",      "secret management substrate"),
    (r"\bpolicy layer\b",                     "policy layer"),
    (r"\bsecurity posture\b",                 "security posture"),
    (r"\bdefense-in-depth posture\b",         "defense-in-depth posture"),
    (r"\barchitectural anti-pattern\b",       "architectural anti-pattern"),
    (r"\bat its core\b",                      "at its core"),
    (r"\bfundamentally,\b",                   "fundamentally"),
    (r"\bin essence\b",                       "in essence"),
    (r"\bthe weakness lies in\b",             "the weakness lies in"),
    (r"\bleverages?\b",                       "leverages"),
    (r"\bcutting-edge\b",                     "cutting-edge"),
    (r"\bseamless(?:ly)?\b",                  "seamless"),
    (r"\bcomprehensive\b",                    "comprehensive"),
    (r"\bensures? that\b",                    "ensures that"),
    (r"\bfacilitates?\b",                     "facilitates"),
    (r"\brobust(?:ly)?\b",                    "robust"),
    # Textbook-purpose padding — trailing clauses restating why the
    # control class exists in the abstract. Add no fact about THIS app.
    (r"\bwith the intention that\b",          "with the intention that"),
    (r"\bwith the expectation that\b",        "with the expectation that"),
    (r"\bis (?:expected|intended) to\b",      "is expected/intended to"),
]

# Definitional opener regex — first sentence of a §7.X body whose first
# verb is one of `is the process`, `decides which`, `governs how`,
# `determines how`, `covers how`, `controls how`, applied to the section's
# own subject. Pattern: starts a sentence in the body and contains one of
# these definitional verb forms.
_DEFINITIONAL_OPENER_RE = re.compile(
    r"\b(is the process|decides which|determines (?:how|when|whether)|"
    r"governs how|covers how|controls how|refers to|describes how)\b",
    re.IGNORECASE,
)

# Formulaic generic-actor opener for H4 control intros. Flags the
# templated "The application <verb>s …" stem — and adjective-prefixed
# variants ("The Angular frontend …") — that signals pattern-filling
# when it repeats across §7's H4 intro paragraphs. A concrete opener
# ("The login query at …", "Sequelize backs …") does NOT match.
_FORMULAIC_OPENER_RE = re.compile(
    r"^The (?:[A-Z][a-z]+ )?"
    r"(?:application|system|server|framework|backend|frontend|service|platform|codebase)\b",
)

# H4 subcontrol heading inside §7.X (numbered or bare).
_SEC7_H4_HEADING_RE = re.compile(r"^#### .+$", re.MULTILINE)

# Section heading regex for §7.X — captures the section number + title.
_SEC7_HEADING_RE = re.compile(
    r"^### (7\.\d+(?:\.\d+)?)\s+(.*?)\s*$", re.MULTILINE
)


def _first_prose_line(segment: str) -> str:
    """First non-blank narrative line of a segment, skipping headings,
    anchors, label lines, tables, bullets, comments and code fences."""
    for line in segment.splitlines():
        t = line.strip()
        if not t:
            continue
        if t.startswith(("|", "-", "*", "```", "#", "<!--", "<a", "**", ">")):
            continue
        return t
    return ""


def _iter_sec7_bodies(text: str):
    """Yield (heading_number, heading_title, body_text) for every §7.X block."""
    matches = list(_SEC7_HEADING_RE.finditer(text))
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        # Stop at the next ## boundary so we don't bleed into §8.
        next_h2 = text.find("\n## ", start, end)
        if next_h2 != -1:
            end = next_h2
        body = text[start:end]
        yield m.group(1), m.group(2), body


def check_architectural_prose(md_path: Path) -> Report:
    """Flag templated mechanism vocabulary and definitional openers in §7.X.

    Warnings only — repeated occurrences in the same section get a single
    aggregated warning so the report is scannable.
    """
    report = Report("architectural_prose")
    text = _read_md(md_path)

    compiled = [(re.compile(p, re.IGNORECASE), name) for p, name in _ARCH_PROSE_BANNED_PATTERNS]

    # Accumulate H4 intro openers across all of §7 so we can flag the
    # "every control starts with The application …" template drift once.
    formulaic_openers: list[str] = []

    for num, title, body in _iter_sec7_bodies(text):
        # Strip fenced code blocks — code is allowed to use any vocabulary.
        body_no_code = re.sub(r"```.*?```", "", body, flags=re.DOTALL)

        # 0. Formulaic H4 intro openers — split this §7.X body on its H4
        # headings and test the first prose line (the intro paragraph) of
        # each subcontrol against the generic-actor stem.
        h4_starts = [m.start() for m in _SEC7_H4_HEADING_RE.finditer(body_no_code)]
        for i, h4_start in enumerate(h4_starts):
            h4_end = h4_starts[i + 1] if i + 1 < len(h4_starts) else len(body_no_code)
            # Drop the heading line itself before reading the intro.
            seg = body_no_code[h4_start:h4_end].split("\n", 1)
            intro = _first_prose_line(seg[1] if len(seg) > 1 else "")
            if intro and _FORMULAIC_OPENER_RE.match(intro):
                formulaic_openers.append(f"§{num}")

        # 1. Definitional opener — only fire when the first non-blank line
        # of the body is prose (not a bullet, table, or code fence).
        first_line = ""
        for line in body_no_code.splitlines():
            t = line.strip()
            if not t:
                continue
            if t.startswith(("|", "-", "*", "```", "###", "####", "<!--")):
                break  # not a prose opener
            first_line = t
            break
        if first_line and _DEFINITIONAL_OPENER_RE.search(first_line):
            report.warnings.append(
                f"§{num} {title!r}: definitional opener — first sentence uses "
                f"textbook verb form (`is the process / decides which / covers how`). "
                f"Replace with a concrete observation about THIS app."
            )

        # 2. Banned vocabulary — aggregate hits per section.
        hits: list[str] = []
        for pat, name in compiled:
            if pat.search(body_no_code):
                hits.append(name)
        if hits:
            uniq = sorted(set(hits))
            report.warnings.append(
                f"§{num} {title!r}: banned phrase(s) — {', '.join(uniq)}. "
                f"Replace with concrete language (file path, lint rule, "
                f"middleware name, env var)."
            )

    # Aggregate formulaic-opener warning across §7 (template drift).
    if len(formulaic_openers) >= 3:
        report.warnings.append(
            f"§7: {len(formulaic_openers)} H4 control intros open with the "
            f"formulaic `The application/system/server …` stem. A domain "
            f"expert leads with the concrete route, file, library, or "
            f"component — vary the opener (≤1 such stem per §7.X section)."
        )

    if not report.warnings:
        report.ok = 1
    return report


_TREE_NODE_ID_RE = re.compile(r"\b(?:G|AND|OR|L)_[A-Z0-9_]{2,}\b")


def check_attack_tree_node_id_leak(md_path: Path) -> Report:
    """Warn when the `## Critical Attack Tree` prose exposes a raw Mermaid
    node id (`G_ROOT`, `AND_JWT`, `OR_FORGE`, `L_T001`).

    The reader sees the rendered diagram, not its source. A subtree must be
    named by what it represents ("the offline token-forgery paths"), never
    by its node id. The defect originated from an authoring example that
    itself referenced `AND_JWT` in prose; this guard catches regressions.

    Warning-only — node ids inside the ```mermaid``` fence are legitimate
    and are stripped before scanning.
    """
    report = Report("attack_tree_node_id_leak")
    text = _read_md(md_path)

    m = re.search(r"^##\s+Critical Attack (?:Tree|Chain)\b.*$", text, re.MULTILINE)
    if not m:
        report.ok = 1
        return report
    start = m.end()
    nxt = re.search(r"^(?:##\s|#\s)", text[start:], re.MULTILINE)
    body = text[start : start + nxt.start()] if nxt else text[start:]

    # Strip fenced blocks — node ids belong inside the diagram source.
    prose = re.sub(r"```.*?```", "", body, flags=re.DOTALL)

    leaked = sorted(set(_TREE_NODE_ID_RE.findall(prose)))
    if leaked:
        report.warnings.append(
            "Critical Attack Tree prose exposes raw Mermaid node id(s) — "
            f"{', '.join(leaked)}. Name the subtree by what it represents "
            "(e.g. 'the offline token-forgery paths'), not by its node id."
        )
    else:
        report.ok = 1
    return report


def check_finding_range_homogeneous(md_path: Path, output_dir: Path | None = None) -> Report:
    """arch3.md §4 + §7 — flag `[F-NNN](...)..[F-MMM](...)` range citations
    in §7 prose when the spanned findings belong to different primary
    weakness clusters.

    Background: §7.5 in the 2026-05 juice-shop run cited "the four XSS
    findings ([F-016]..[F-021])" — but the F-016..F-021 span actually
    contains F-019 (Session/Storage, CWE-922) and F-020 (Headers,
    CWE-1021) which are NOT XSS. A range citation is only correct when
    every F-ID in the span shares the same weakness cluster.

    Detection scope:
      - §7 body only (skip §8 Findings Register tables where ranges are
        legitimate layout).
      - Only consider markdown-link ranges of the form
        `[F-NNN](#f-nnn) ... – [F-MMM](#f-mmm)` (the renderer's canonical
        form when listing two F-IDs as endpoints of a range).
      - The span between NNN and MMM is treated as inclusive.

    Verdict:
      - If yaml is unavailable, return ok (cannot verify).
      - If the spanned F-NNN set has ≥2 distinct cluster_ids → warning.

    Author note: this is intentionally a *warning* not a hard issue.
    Restructuring §7 prose is an LLM-side semantic edit; flagging it
    surfaces the inconsistency without blocking the run.
    """
    report = Report("finding_range_homogeneous")
    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return report

    output_dir = output_dir or md_path.parent
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        report.ok = 1
        return report

    try:
        import yaml as _yaml
        data = _fast_yaml_load(yaml_path.read_text(encoding="utf-8"))
    except Exception:
        report.ok = 1
        return report

    if not isinstance(data, dict):
        report.ok = 1
        return report

    # Map F-ID → cwe → cluster_id, lazily.
    threats = data.get("threats") or []
    cwe_by_fid: dict[str, str] = {}
    for t in threats:
        if not isinstance(t, dict):
            continue
        tid = (t.get("id") or "").strip().upper()
        cwe = (t.get("cwe") or "").strip().upper()
        if not tid or not cwe:
            continue
        # Both F-NNN (finding-numbered) and T-NNN come from the same id space;
        # the rendered MD uses F-NNN for findings, so derive the F-NNN form.
        if tid.startswith("T-"):
            cwe_by_fid[tid.replace("T-", "F-")] = cwe
        elif tid.startswith("F-"):
            cwe_by_fid[tid] = cwe

    if not cwe_by_fid:
        report.ok = 1
        return report

    try:
        vocab = _load_weakness_classes()
    except Exception:
        report.ok = 1
        return report

    # Locate §7 body — start at "## 7. " heading, stop at "## 8. ".
    sec7_start = text.find("## 7. ")
    if sec7_start < 0:
        report.ok = 1
        return report
    sec8_start = text.find("\n## 8.", sec7_start)
    sec7 = text[sec7_start: sec8_start if sec8_start > 0 else len(text)]

    # Range pattern: two F-NNN links joined by an en-dash (–, U+2013) or
    # em-dash (—, U+2014) on the SAME line. Plain ASCII hyphen `-` is a
    # markdown bullet marker, not a range separator, so it is excluded —
    # otherwise the regex matches consecutive bullet entries.
    # Also: no newline in the gap, no `[F-` token between (would mean
    # the gap already contains another F-NNN and the outer pair is not
    # a range but a sequence).
    _RANGE_RE = re.compile(
        r"\[F-(\d{3,})\]\(#f-\d+\)"
        r"(?P<gap>[^[\n]{0,250}?)"
        r"[–—]"
        r"\s*\[F-(\d{3,})\]\(#f-\d+\)"
    )

    flagged: list[tuple[int, str, list[str]]] = []
    seen_pairs: set[tuple[int, int]] = set()
    for m in _RANGE_RE.finditer(sec7):
        start_n = int(m.group(1))
        end_n = int(m.group(3))
        if start_n >= end_n or end_n - start_n > 30:
            # Sanity-cap: ranges spanning >30 IDs are not ranges, they're
            # accidental long-distance matches.
            continue
        if (start_n, end_n) in seen_pairs:
            continue
        seen_pairs.add((start_n, end_n))
        span_ids = [f"F-{i:03d}" for i in range(start_n, end_n + 1)]
        clusters: list[str] = []
        cwes_seen: list[str] = []
        for fid in span_ids:
            cwe = cwe_by_fid.get(fid)
            if not cwe:
                continue
            cl = _classify_threat_cluster_local(cwe, vocab)
            cwes_seen.append(f"{fid}={cwe}/{cl}")
            if cl not in clusters and cl != "_unmapped":
                clusters.append(cl)
        if len(clusters) >= 2:
            line_no = sec7[: m.start()].count("\n") + (sec7_start_line := text[:sec7_start].count("\n") + 1)
            flagged.append((line_no, m.group(0), cwes_seen))

    for line_no, snippet, cwes_seen in flagged[:10]:
        report.warnings.append(
            f"§7 finding-range citation spans heterogeneous clusters at "
            f"line {line_no}: ({', '.join(cwes_seen)}) — split into separate "
            f"finding references or restructure the prose; ranges over "
            f"mixed weakness classes mislead the reader (arch3.md §2 / §4)."
        )
    if not flagged:
        report.ok = 1
    return report


def _classify_threat_cluster_local(cwe: str, vocab: dict) -> str:
    """Standalone CWE→cluster lookup that does NOT emit the multi-match
    warning (avoiding noise when the cluster vocabulary already has a
    known ambiguity)."""
    if not cwe:
        return "_unmapped"
    cwe = cwe.strip().upper()
    for cluster in vocab.get("clusters") or []:
        if cluster.get("id") == "_unmapped":
            continue
        if cwe in {c.strip().upper() for c in (cluster.get("cwes") or [])}:
            return cluster["id"]
    return "_unmapped"


_WEAKNESS_CLASSES_CACHE_QA: dict | None = None


def _load_weakness_classes() -> dict:
    """Lazy-load + cache `data/weakness-classes.yaml`. Mirrors the loader in
    compose_threat_model.py so qa_checks.py stays self-contained (no cross-
    module dependency)."""
    global _WEAKNESS_CLASSES_CACHE_QA
    if _WEAKNESS_CLASSES_CACHE_QA is not None:
        return _WEAKNESS_CLASSES_CACHE_QA
    here = Path(__file__).resolve()
    plugin_root = here.parent.parent
    candidate = plugin_root / "data" / "weakness-classes.yaml"
    if not candidate.exists():
        _WEAKNESS_CLASSES_CACHE_QA = {"clusters": []}
        return _WEAKNESS_CLASSES_CACHE_QA
    try:
        import yaml as _yaml
        _WEAKNESS_CLASSES_CACHE_QA = _fast_yaml_load(candidate.read_text()) or {"clusters": []}
    except Exception:
        _WEAKNESS_CLASSES_CACHE_QA = {"clusters": []}
    return _WEAKNESS_CLASSES_CACHE_QA


def check_dependency_cross_ref(md_path: Path, output_dir: Path | None = None) -> Report:
    """arch3.md §4 + §7 — dependency-driven findings MUST be referenced in
    the §7 supply-chain controls section.

    Detection scope:
      - Threats whose `source == "dep-scan"` (deterministic SCA pipeline
        output, source: dep-scan).
      - Threats whose cluster == `outdated_deps` (per
        weakness-classes.yaml — CWE-1104/1395/937).
      - Threats whose title or evidence.excerpt names a known vulnerable
        library token (express-jwt 0.x, notevil, libxmljs2 with
        explicit version reference) — this captures juice-shop's
        F-014/F-003 which the LLM analyst classified under crypto /
        injection clusters but which are dependency-driven.

    Verdict:
      - If the supply-chain controls body does NOT reference each candidate F-NNN, emit a
        warning per missing reference. Hard-fail not appropriate
        because the LLM may legitimately have classified the finding
        primarily elsewhere; the warning surfaces the missing cross-ref.
    """
    report = Report("dependency_cross_ref")
    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return report

    output_dir = output_dir or md_path.parent
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        report.ok = 1
        return report

    try:
        import yaml as _yaml
        data = _fast_yaml_load(yaml_path.read_text(encoding="utf-8"))
    except Exception:
        report.ok = 1
        return report
    if not isinstance(data, dict):
        report.ok = 1
        return report

    try:
        vocab = _load_weakness_classes()
    except Exception:
        report.ok = 1
        return report

    # Known dependency-relevant library tokens — extended ad hoc when the
    # LLM analyst keeps a finding under a non-dep cluster but the underlying
    # cause is a vulnerable library version.
    _LIB_TOKENS = (
        r"express-jwt\s+\d",          # express-jwt 0.x
        r"\bnotevil\b",                # notevil sandbox
        r"libxmljs2?\s+\d",            # libxmljs2 0.x
        r"\bsanitize-html\b\s+\d",
        r"\bjsonwebtoken\b\s+[\d.]+",
        r"\bnode-fetch\b\s+[\d.]+",
        r"\bunzipper\b\s+[\d.]+",
        r"\baxios\b\s+\d",
    )
    lib_re = re.compile("|".join(_LIB_TOKENS), re.IGNORECASE)

    candidate_fids: list[tuple[str, str]] = []
    for t in data.get("threats") or []:
        if not isinstance(t, dict):
            continue
        tid = (t.get("id") or "").strip().upper()
        if not tid.startswith("T-"):
            continue
        fid = tid.replace("T-", "F-")
        # 1) Explicit dep source
        src = (t.get("source") or "").strip().lower()
        if src == "dep-scan":
            candidate_fids.append((fid, "source=dep-scan"))
            continue
        # 2) outdated_deps cluster
        cwe = (t.get("cwe") or "").strip().upper()
        cluster = _classify_threat_cluster_local(cwe, vocab)
        if cluster == "outdated_deps":
            candidate_fids.append((fid, f"cluster=outdated_deps ({cwe})"))
            continue
        # 3) Library token in title or evidence excerpt
        title = (t.get("title") or "")
        ev = t.get("evidence") or {}
        excerpts: list[str] = []
        if isinstance(ev, dict):
            ex = ev.get("excerpt") or ""
            if ex:
                excerpts.append(ex)
        elif isinstance(ev, list):
            for e in ev:
                if isinstance(e, dict):
                    ex = e.get("excerpt") or ""
                    if ex:
                        excerpts.append(ex)
        haystack = title + " " + " ".join(excerpts)
        m = lib_re.search(haystack)
        if m:
            candidate_fids.append((fid, f"library-token={m.group(0).strip()!r}"))

    if not candidate_fids:
        report.ok = 1
        return report

    # Locate the supply-chain control body in the rendered MD. v1 used
    # "7.12 Dependency & Supply Chain"; current v2 uses
    # "7.11 Operations Runtime and Supply Chain Controls".
    sec_re = re.compile(r"^###\s+(7\.\d+\s+.*Supply\s+Chain.*)$", re.IGNORECASE | re.MULTILINE)
    m_sec = sec_re.search(text)
    section_label = m_sec.group(1).strip() if m_sec else "§7 Supply Chain controls"
    if not m_sec:
        # §7.12 is missing entirely — flag a single high-level warning, then
        # don't enumerate the per-finding misses (would amount to one warning
        # per candidate, which is noise).
        report.warnings.append(
            f"§7 Supply Chain controls section is missing from the rendered MD, "
            f"but {len(candidate_fids)} finding(s) are dependency-relevant: "
            f"{', '.join(fid for fid, _ in candidate_fids[:10])}. Add the "
            f"supply-chain controls section and reference these findings per "
            f"arch3.md §4."
        )
        return report

    # End at next `### 7.` or `## ` heading.
    rest = text[m_sec.end():]
    next_heading = re.search(r"\n#{2,3}\s", rest)
    sec_body = rest[: next_heading.start() if next_heading else len(rest)]

    missing: list[tuple[str, str]] = []
    for fid, reason in candidate_fids:
        # Match by anchored F-NNN link `[F-NNN](#f-nnn)` OR plain F-NNN.
        if fid in sec_body:
            continue
        missing.append((fid, reason))

    for fid, reason in missing[:10]:
        report.warnings.append(
            f"§{section_label} does not reference {fid} "
            f"({reason}) — dependency-driven findings must appear in this "
            f"domain per arch3.md §4."
        )

    if not missing:
        report.ok = 1
    return report


# ---------------------------------------------------------------------------
# Bundle 6 — Prose-quality checks
#
# These four checks close the AI-slop detection gap that `check_architectural_prose`
# does not cover. They complement the 20+ banned-phrase list there:
#   * `check_generic_phrases`  — "an attacker could", "various endpoints", …
#   * `check_rhetorical_severity` — "trivial", "catastrophic", "collapse", …
#   * `check_section_opener_restates_heading` — "This section evaluates ..."
#   * `check_ai_padding_phrases` — "it is worth noting", "furthermore", …
#
# All four are warning-level by default; ≥N occurrences inside a single §7.x
# escalate to error-level. The thresholds are conservative (favour signal
# over noise on the first run; can be tightened later).
# ---------------------------------------------------------------------------

_GENERIC_PHRASE_PATTERNS: list[tuple[str, str]] = [
    (r"\ban attacker (?:could|might|may|can(?: potentially)?)\b", "an attacker could/might/may"),
    (r"\bcould potentially\b", "could potentially"),
    (r"\bvarious (?:endpoints|routes|files|paths|libraries|locations|places)\b", "various ..."),
    (r"\bin the codebase\b", "in the codebase"),
    (r"\bmight (?:be|allow|enable)\b", "might be/allow/enable"),
    (r"\bmay (?:be|allow|enable) (?:exploited|abused|attacked)\b", "may be exploited/abused/attacked"),
    (r"\btend(?:s)? to\b", "tend to"),
    (r"\bseemingly\b", "seemingly"),
    (r"\beffectively (?:allow|enable|provide)s?\b", "effectively allow/enable/provide"),
]


def check_generic_phrases(md_path: Path) -> Report:
    """R10a — flag generic attacker-rhetoric that prose-style Rule 1 forbids.

    `prose-style.md → Rule 1 — Specificity over generality` requires every
    statement to name a file/line/library/API. Phrases like "an attacker
    could", "various endpoints", "in the codebase" are placeholders, not
    findings — they pass `check_architectural_prose` (which scans for
    structural floskeln) but violate Rule 1.

    Warnings only; per-section count ≥3 in one §7.x escalates to error.
    """
    report = Report("generic_phrases")
    text = _read_md(md_path)
    text_no_code = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    compiled = [(re.compile(p, re.IGNORECASE), name) for p, name in _GENERIC_PHRASE_PATTERNS]
    per_section: dict[str, list[str]] = {}
    for sec_num, sec_title, body in _iter_sec7_bodies(text_no_code):
        sec_key = f"§{sec_num} {sec_title}"
        for pat, name in compiled:
            if pat.search(body):
                per_section.setdefault(sec_key, []).append(name)
    for sec_key, hits in per_section.items():
        if len(hits) >= 3:
            report.issues.append(
                f"{sec_key}: {len(hits)} generic-phrase hits — {', '.join(sorted(set(hits)))[:200]}. "
                f"Replace with file:line / library / route-specific language per prose-style.md Rule 1."
            )
        else:
            report.warnings.append(
                f"{sec_key}: generic phrasing — {', '.join(sorted(set(hits)))}. "
                f"Replace with concrete evidence (prose-style.md Rule 1)."
            )
    if not per_section:
        report.ok = 1
    return report


_RHETORICAL_SEVERITY_PATTERNS: list[tuple[str, str]] = [
    (r"\btrivial(?:ly)?\b", "trivial(ly)"),
    (r"\bcatastroph(?:ic|e)\b", "catastrophic"),
    (r"\b(?:cryptographic|security|trust) (?:model|posture) collapses?\b", "<X> model collapses"),
    (r"\bwreak(?:s|ing)? havoc\b", "wreaks havoc"),
    (r"\bdevastating\b", "devastating"),
    (r"\bjunior (?:pentester|attacker)\b", "junior pentester/attacker"),
    (r"\bunmitigated disaster\b", "unmitigated disaster"),
    (r"\bgame[- ]over\b", "game-over"),
    (r"\bthis finding is catastrophic\b", "this finding is catastrophic"),
]


def check_rhetorical_severity(md_path: Path) -> Report:
    """R10b — flag rhetorical-severity phrasing that prose-style Rule 2 forbids.

    `prose-style.md → Rule 2 — Falsifiability over rhetoric` requires
    severity to be expressed through mechanism and system behaviour,
    not through metaphor or comparison ("trivial for a junior pentester",
    "the cryptographic trust model collapses", "wreak havoc"). A reader
    who disagrees with rhetoric cannot test it; a reader who disagrees
    with a mechanism can. These phrases are HARD errors — there is no
    sensible context in which they belong in a threat report.
    """
    report = Report("rhetorical_severity")
    text = _read_md(md_path)
    text_no_code = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    compiled = [(re.compile(p, re.IGNORECASE), name) for p, name in _RHETORICAL_SEVERITY_PATTERNS]
    hits: dict[str, list[str]] = {}
    for sec_num, sec_title, body in _iter_sec7_bodies(text_no_code):
        sec_key = f"§{sec_num} {sec_title}"
        for pat, name in compiled:
            for m in pat.finditer(body):
                snippet = body[max(0, m.start() - 30):m.end() + 30].replace("\n", " ").strip()
                hits.setdefault(sec_key, []).append(f"{name!r} — …{snippet}…")
    for sec_key, found in hits.items():
        report.issues.append(
            f"{sec_key}: rhetorical-severity phrasing — {len(found)} hit(s). "
            f"Replace with the mechanism and the server's response (prose-style.md Rule 2). "
            f"First hit: {found[0][:200]}"
        )
    if not hits:
        report.ok = 1
    return report


def check_section_opener_restates_heading(md_path: Path) -> Report:
    """R10c — flag chapter/section openers that restate the heading.

    `prose-style.md → Rule 3 — Information-density over volume` says the
    first sentence of every section must add a fact the heading does not
    already convey. Openers like "This section evaluates Juice Shop's
    security control landscape across 13 control categories..." are pure
    AI scaffolding — the heading already says "Security Architecture",
    the reader does not need a sentence repeating it.

    Two detectors:
      (a) Hard-banned opener verbs at the start of the first prose
          sentence: "This section/chapter (will discuss|aims to|seeks
          to|evaluates|consolidates|covers|describes|outlines)"
      (b) Token-overlap >50% between heading and first sentence — softer
          warning, since some overlap is unavoidable.
    """
    report = Report("section_opener_restates_heading")
    text = _read_md(md_path)
    _BAD_OPENERS = re.compile(
        r"^this (?:section|chapter|subsection) (?:will discuss|aims to|seeks to|"
        r"evaluates|consolidates|covers|describes|outlines|presents|provides|introduces|"
        r"summarises|summarizes|details)\b",
        re.IGNORECASE,
    )
    # Check the ## chapter opener and every ### subsection opener.
    section_re = re.compile(
        r"^(##\s+\d+\.\s+[^\n]+|###\s+\d+\.\d+\s+[^\n]+)$",
        re.MULTILINE,
    )
    matches = list(section_re.finditer(text))
    for i, m in enumerate(matches):
        heading = m.group(1).lstrip("#").strip()
        body_start = m.end()
        body_end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[body_start:body_end]
        # First non-blank, non-bold-label prose line.
        first_line = ""
        for ln in body.splitlines():
            s = ln.strip()
            if not s:
                continue
            # Skip bold-label metadata lines.
            if s.startswith("**") and s.find(":**") <= 60:
                continue
            if s.startswith("```") or s.startswith("|") or s.startswith("<!--"):
                continue
            first_line = s
            break
        if not first_line:
            continue
        if _BAD_OPENERS.match(first_line):
            report.issues.append(
                f"{heading!r}: opener {first_line[:120]!r} restates the heading — "
                f"replace with a fact the heading does not already convey "
                f"(prose-style.md Rule 3)."
            )
            continue
        # Token-overlap detection — soft warning.
        heading_tokens = set(re.findall(r"[a-z0-9]+", heading.lower()))
        # Strip leading numbering tokens (`7`, `2`, etc.) — they overlap trivially.
        heading_tokens -= {"7", "2", "1", "3", "4", "5", "6", "8", "9", "10", "11", "12", "13"}
        first_tokens = set(re.findall(r"[a-z0-9]+", first_line.lower()[:200]))
        if heading_tokens and len(heading_tokens & first_tokens) / len(heading_tokens) > 0.6:
            report.warnings.append(
                f"{heading!r}: opener token-overlap >60% with heading — "
                f"consider rewriting to add a fact (count, constraint, exception). "
                f"Opener: {first_line[:150]!r}"
            )
    if not report.issues and not report.warnings:
        report.ok = 1
    return report


_AI_PADDING_PATTERNS: list[tuple[str, str]] = [
    (r"\bit is worth noting (?:that\b)?", "it is worth noting"),
    (r"\bit (?:should be|is important to) (?:noted|mentioned|noted|noted that|noted as|"
     r"note(?:d)?|mention(?:ed)?|highlight(?:ed)?|understand|understood|considered|emphasised|"
     r"emphasized)\b", "it should be noted / it is important to"),
    (r"\b(?:furthermore|moreover|additionally),", "furthermore/moreover/additionally,"),
    (r"\bin summary,", "in summary,"),
    (r"\bto conclude,", "to conclude,"),
    (r"\b(?:essentially|notably|crucially|importantly),", "essentially/notably/crucially/importantly,"),
    (r"\bone (?:important )?(?:aspect|thing) (?:is|to (?:note|consider))\b", "one important aspect is"),
    (r"\bthis (?:section|chapter) (?:will discuss|aims to|seeks to|presents|provides|details)\b",
     "this section will discuss/aims to"),
    (r"\bin (?:the\s+context\s+of|order\s+to)\b", "in the context of / in order to"),
    (r"\bin terms of\b", "in terms of"),
]


def check_ai_padding_phrases(md_path: Path) -> Report:
    """R10d — flag transitional / discourse-marker phrases that pad without adding information.

    `prose-style.md → Rule 5 — No boilerplate, no decorative repetition`
    forbids filler that a domain expert would not write. Phrases like
    "it is worth noting", "furthermore", "in summary" are AI-slop
    markers — they add discourse structure where bullets or paragraph
    breaks would do the job.

    Threshold: per-section count ≥2 in one §7.x escalates to error.
    Section-wide single occurrence stays warning-level.
    """
    report = Report("ai_padding_phrases")
    text = _read_md(md_path)
    text_no_code = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    compiled = [(re.compile(p, re.IGNORECASE), name) for p, name in _AI_PADDING_PATTERNS]
    per_section: dict[str, list[str]] = {}
    for sec_num, sec_title, body in _iter_sec7_bodies(text_no_code):
        sec_key = f"§{sec_num} {sec_title}"
        for pat, name in compiled:
            if pat.search(body):
                per_section.setdefault(sec_key, []).append(name)
    for sec_key, hits in per_section.items():
        unique = sorted(set(hits))
        if len(hits) >= 2:
            report.issues.append(
                f"{sec_key}: AI-padding phrases ({len(hits)} hits) — {', '.join(unique)[:200]}. "
                f"Replace transitional discourse markers with bullets or paragraph breaks "
                f"(prose-style.md Rule 5)."
            )
        else:
            report.warnings.append(
                f"{sec_key}: AI-padding phrase — {', '.join(unique)}. "
                f"Consider removing transitional filler (prose-style.md Rule 5)."
            )
    if not per_section:
        report.ok = 1
    return report


def check_subcontrol_naming_canonical(md_path: Path, contract_path: Path = DEFAULT_CONTRACT_PATH) -> Report:
    """R1 / R10 — §7.2 IAM H4 subcontrol headings must use canonical mechanism names.

    Validation rules (driven by sections-contract.yaml →
    `schema_v2.domain_required_rules['7.2 Identity and Authentication
    Controls'].auth_method_decomposition`):

      1. Every #### heading in §7.2 must either:
         (a) token-match an entry in `method_whitelist`
             (e.g. "OAuth Login Adapter" matches "oauth"),
         (b) be a Mechanism + Operation form (Enrollment / Verification /
             Issuance / Reset / Change), OR
         (c) name a recognised primitive (Password Hashing, Rate Limiting,
             JWT Signature Verification) provided at least ONE mechanism
             #### also exists in the section.

      2. No #### heading may match `forbidden_heading_patterns`
         (token-format-only: `JWT-RS256`, library-only: `JWT library`,
         vulnerability-class: `Authentication bypass prevention`).
    """
    report = Report("subcontrol_naming_canonical")
    contract = _read_contract(contract_path)
    if not contract:
        return report
    sec = (contract.get("sections") or {}).get("security_architecture") or {}
    rules_map = sec.get("domain_required_rules") or {}
    rule = None
    domain_key = None
    for key, rules in rules_map.items():
        if not isinstance(rules, list):
            continue
        match = next(
            (r for r in rules if isinstance(r, dict) and r.get("rule") == "auth_method_decomposition"),
            None,
        )
        if match is not None:
            rule = match
            domain_key = key
            break
    if rule is None or not domain_key:
        report.ok = 1
        return report
    whitelist = [w.lower() for w in (rule.get("method_whitelist") or []) if isinstance(w, str)]
    forbidden = [p for p in (rule.get("forbidden_heading_patterns") or []) if isinstance(p, str)]
    if not whitelist and not forbidden:
        report.ok = 1
        return report

    text = _read_md(md_path)
    # Find §7.2 body.
    sec_re = re.compile(
        r"^### 7\.2\s+[^\n]*$(.*?)(?=^### 7\.\d|^## )",
        re.MULTILINE | re.DOTALL,
    )
    m = sec_re.search(text)
    if not m:
        report.ok = 1
        return report
    body = m.group(1)
    # Strip code fences before scanning headings.
    body_no_code = re.sub(r"```.*?```", "", body, flags=re.DOTALL)
    h4_re = re.compile(r"^####\s+(.+?)\s*$", re.MULTILINE)
    h4s = [h.strip() for h in h4_re.findall(body_no_code)]
    if not h4s:
        report.ok = 1
        return report

    # Build operation-suffix tokens — Mechanism + Operation form is valid.
    operation_tokens = {"enrollment", "verification", "issuance", "reset", "change",
                        "registration", "sign-in", "sign-up", "signup", "login",
                        "flow", "adapter", "middleware", "handshake"}

    forbidden_hits: list[tuple[str, str]] = []
    non_canonical: list[str] = []
    canonical_hits: list[str] = []

    for heading in h4s:
        head_norm = heading.lower()
        # Check forbidden patterns first — these are hard errors.
        hit_pat = None
        for pat in forbidden:
            try:
                if re.search(pat, heading):
                    hit_pat = pat
                    break
            except re.error:
                continue
        if hit_pat:
            forbidden_hits.append((heading, hit_pat))
            continue
        # Now check whitelist match — token-subset semantics.
        heading_tokens = set(re.findall(r"[a-z0-9]+", head_norm))
        matched = False
        for entry in whitelist:
            entry_tokens = set(re.findall(r"[a-z0-9]+", entry))
            if entry_tokens and entry_tokens.issubset(heading_tokens):
                matched = True
                canonical_hits.append(heading)
                break
        if matched:
            continue
        # Allow operation-suffix forms even without whitelist match (e.g.
        # "TOTP Enrollment", "JWT Issuance" — the suffix is operation,
        # the prefix is a token-format the whitelist accepts).
        if heading_tokens & operation_tokens:
            canonical_hits.append(heading)
            continue
        non_canonical.append(heading)

    enforcement = (rule.get("enforcement") or "warning").strip().lower()
    for heading, pat in forbidden_hits:
        report.issues.append(
            f"§7.2 IAM #### heading {heading!r} matches forbidden pattern "
            f"{pat!r} — token-format-only / library-name / vulnerability-"
            f"class headings are not authentication mechanisms. Use a "
            f"canonical mechanism name (OAuth Login Adapter, OIDC Sign-In, "
            f"SAML SSO, Password-Based Login, TOTP Enrollment, JWT Issuance, "
            f"Password Reset, …) from method_whitelist or rephrase. See "
            f"data/architectural-controls.yaml for the canonical vocabulary."
        )
    # If §7.2 has at least one mechanism heading, allow primitive headings
    # too (Reference allows `JWT Issuance`, `JWT Verification`, `Password
    # Hashing` etc. as #### blocks alongside mechanisms). If §7.2 has ONLY
    # non-canonical headings (no mechanism row at all), that is the actual
    # defect — flag it as warning.
    if non_canonical and not canonical_hits:
        report.issues.append(
            f"§7.2 IAM has {len(non_canonical)} #### heading(s) but none "
            f"match an authentication mechanism from the canonical vocabulary "
            f"(OAuth, OIDC, SAML, Password Login, Password Reset, TOTP, MFA, "
            f"Passkey/WebAuthn, …). Non-matching headings: "
            f"{', '.join(repr(h) for h in non_canonical[:5])}. The §7.2 "
            f"contract requires at least one row per discovered auth mechanism."
        )
    if not forbidden_hits and (canonical_hits or not non_canonical):
        report.ok = 1
    return report


def check_section_713_no_table(md_path: Path) -> Report:
    """R7 — §7.13 Defense-in-Depth Summary must be prose-only.

    Markdown tables (`| header |` lines under §7.13) are a contract violation
    because the tabular layer-mapping format invites speculative perimeter-
    absence claims (`No WAF`, `No firewall`, `No DAM`) that violate the
    `unfounded_perimeter_claims` rule. Reference §7.13 is two short prose
    paragraphs naming the individual positive controls and the boundary
    repairs that would restore layered defense.
    """
    report = Report("section_713_no_table")
    text = _read_md(md_path)
    m = re.search(r"^### 7\.13 .*?$", text, re.MULTILINE)
    if not m:
        report.ok = 1
        return report
    start = m.end()
    next_h3 = re.search(r"^### |^## ", text[start:], re.MULTILINE)
    end = start + next_h3.start() if next_h3 else len(text)
    body = text[start:end]
    # Strip code fences first so a ```mermaid block with `|` characters
    # isn't mistaken for a markdown table.
    body_no_code = re.sub(r"```.*?```", "", body, flags=re.DOTALL)
    # A markdown table has a header separator row matching `| ---+ | ---+ |`.
    if re.search(r"^\s*\|[\s\-:|]+\|\s*$", body_no_code, re.MULTILINE):
        report.issues.append(
            "§7.13 contains a Markdown table — forbidden by the v2 contract "
            "(see sections-contract.yaml → schema_v2.domain_required_rules."
            "'7.13 Defense-in-Depth Summary'.forbidden_constructs). §7.13 "
            "must be prose-only: two short paragraphs covering (1) the "
            "individual controls that exist and (2) which boundary repairs "
            "would restore layered defense. Tables invite speculative "
            "perimeter-absence claims and miss the architecture-level "
            "narrative the section is meant to deliver."
        )
    else:
        report.ok = 1
    return report


def check_na_against_recon(md_path: Path, output_dir: Path | None = None) -> Report:
    """arch3.md §4 + §7 — `_Not applicable - no X detected_` claims in §7
    must be consistent with what the recon-scanner found.

    Detection scope:
      - Per §7.x subsection, parse the leading body text. If it starts
        with `_Not applicable` AND the recon-summary contains evidence
        of the domain's keywords → flag as warning.
      - Domain keyword map is conservative (only well-known signals).

    Verdict:
      - Warning per misclassified `_Not applicable` claim.
    """
    report = Report("na_against_recon")
    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return report

    output_dir = output_dir or md_path.parent
    recon_path = output_dir / ".recon-summary.md"
    if not recon_path.is_file():
        # No recon evidence available → cannot cross-check.
        report.ok = 1
        return report
    try:
        recon = recon_path.read_text(encoding="utf-8").lower()
    except OSError:
        report.ok = 1
        return report

    # Per-domain recon signals. Order: title pattern in §7 → recon tokens.
    _DOMAIN_RECON_TOKENS = (
        (re.compile(r"^###\s+7\.\d+\s+(.*?)WebSocket", re.MULTILINE | re.IGNORECASE),
         "WebSocket", ("socket.io", "websocket", "ws://", "wss://")),
        (re.compile(r"^###\s+7\.\d+\s+(.*?)(AI\s*/\s*LLM|AI/LLM|LLM)", re.MULTILINE | re.IGNORECASE),
         "AI/LLM", ("openai", "anthropic", "langchain", "llamaindex", " llm ", "ollama")),
        (re.compile(r"^###\s+7\.\d+\s+(.*?)Real-time", re.MULTILINE | re.IGNORECASE),
         "Real-time", ("socket.io", "websocket", "real-time", "sse ", "eventsource")),
    )

    flagged: list[str] = []
    seen_section_starts: set[int] = set()
    for sec_re, label, tokens in _DOMAIN_RECON_TOKENS:
        for sec_match in sec_re.finditer(text):
            # Dedup — multiple patterns can match the same §7.x section
            # (e.g. WebSocket pattern + Real-time pattern both hit §7.8
            # Real-time / WebSocket). Use the heading-start offset as
            # the identity key.
            if sec_match.start() in seen_section_starts:
                continue
            seen_section_starts.add(sec_match.start())
            heading_end = sec_match.end()
            # Read up to ~600 chars after the heading or until the next heading.
            window = text[heading_end: heading_end + 600]
            next_heading = re.search(r"\n#{2,3}\s", window)
            body = window[: next_heading.start() if next_heading else len(window)]
            if "_Not applicable" not in body and "_not applicable" not in body.lower():
                continue
            hits = [tok for tok in tokens if tok in recon]
            if hits:
                flagged.append(
                    f"§7 sub-section '{label}' claims `_Not applicable_` but recon evidence "
                    f"contains {hits[:3]} — restate as 'present, no findings mapped' if no "
                    f"finding was derived, or add the domain controls per arch3.md §4."
                )

    for msg in flagged[:10]:
        report.warnings.append(msg)
    if not flagged:
        report.ok = 1
    return report


def _finalize_auth_report(report: Report, enforcement: str) -> Report:
    """Apply the ``enforcement`` policy to a freshly-populated report.

    ``warning`` mode demotes every current issue into ``report.warnings`` so
    downstream consumers (the Re-Render Loop in particular) do not treat the
    rule's findings as repair triggers.  ``error`` mode leaves issues as-is.
    ``ok`` is set to 1 only when no issues remain on the report.
    """
    if enforcement == "warning" and report.issues:
        report.warnings.extend(report.issues)
        report.issues = []
    if not report.issues:
        report.ok = 1
    return report


def _run_auth_matching_checks(
    *,
    report: Report,
    table_rows: list[dict],
    subsections: dict[str, str],
    synonyms: list,
    match_style: str,
    trailer_label: str,
    table_column: str,
    hashes: str,
) -> None:
    """Core matching loop — populates ``report.issues`` with every
    row-without-subsection, missing-sequenceDiagram, missing-trailer, and
    trailer-vs-row consistency violation."""
    heading_tokens = {h: _tokens(h) for h in subsections}
    syn_by_row = {
        (s.get("row") or "").strip().lower(): (s.get("heading") or "").strip() for s in synonyms if isinstance(s, dict)
    }
    heading_to_rows: dict[str, list[dict]] = {h: [] for h in subsections}

    for row in table_rows:
        control = row["control"]
        matched: Optional[str] = None
        # (a) synonym override — authoritative.
        target = syn_by_row.get(control.lower())
        if target:
            if target in subsections:
                matched = target
            else:
                report.issues.append(
                    f"§7.3 IAM: synonym override maps row {control!r} to "
                    f"heading {target!r} but no such {hashes} subsection "
                    f"is present"
                )
                continue
        # (b) exact or token-subset matching on the heading text.
        if matched is None:
            row_toks = _tokens(control)
            if not row_toks:
                continue
            if match_style == "exact":
                matched = next(
                    (h for h in subsections if h.strip().lower() == control.lower()),
                    None,
                )
            else:  # token-subset (default)
                for h, htoks in heading_tokens.items():
                    if row_toks.issubset(htoks):
                        matched = h
                        break
        if matched is None:
            report.issues.append(
                f"§7.3 IAM: no {hashes} subsection matches control-table row "
                f"{control!r} — add a `{hashes} {control} Flow` sub-block "
                f"(with its own sequenceDiagram and a "
                f"`**{trailer_label}:**` trailer) or declare a synonym "
                f"override in data/sections-contract.yaml "
                f"(security_architecture.domain_required_rules)"
            )
            continue
        heading_to_rows[matched].append(row)

    trailer_re = re.compile(
        r"\*\*" + re.escape(trailer_label) + r":\*\*\s*(.+?)(?:\n\s*\n|\Z)",
        re.DOTALL,
    )
    for heading, body in subsections.items():
        if "sequenceDiagram" not in body:
            report.issues.append(
                f"§7.3 IAM {hashes} subsection {heading!r}: missing "
                f"`sequenceDiagram` block (every auth-method sub-block needs "
                f"its own diagram)"
            )
        m = trailer_re.search(body)
        if not m:
            report.issues.append(
                f"§7.3 IAM {hashes} subsection {heading!r}: missing "
                f"`**{trailer_label}:**` trailer — end each sub-block with "
                f"`**{trailer_label}:** [T-NNN](#t-nnn) — short label` or "
                f"`— none` when no direct findings apply"
            )
            continue
        trailer_text = m.group(1)
        trailer_tids = {f"T-{mm.group(1).zfill(3)}" for mm in T_ID_RE.finditer(trailer_text)}
        # F-NNN is the canonical row-anchor alias for the same threat (the
        # composer rewrites bare T-NNN refs into [F-NNN](#f-nnn) in some
        # contexts). Treat both forms as equivalent for the trailer/cell
        # consistency check — same partial-refactor that was applied to
        # `_parse_domain_controls_table` for the Linked Threats cell.
        trailer_tids |= {f"T-{mm.group(1).zfill(3)}" for mm in F_ID_RE.finditer(trailer_text)}
        rows_here = heading_to_rows.get(heading) or []
        if not rows_here:
            report.issues.append(
                f"§7.3 IAM {hashes} subsection {heading!r}: no matching "
                f"control-table row — add a row with a `{table_column}` that "
                f"the subsection covers, or remove the subsection"
            )
            continue
        union_tids: set[str] = set()
        for r in rows_here:
            union_tids.update(r.get("linked_tids") or set())
        extraneous = trailer_tids - union_tids
        if extraneous:
            report.issues.append(
                f"§7.3 IAM {hashes} subsection {heading!r}: trailer cites "
                f"{sorted(extraneous)} but none of those T-IDs appear in the "
                f"`Linked Threats` cell of any control-table row matched to "
                f"this subsection — add them to the row's Linked Threats "
                f"column (bidirectional consistency)"
            )


# ---------------------------------------------------------------------------
# Check 6 — Unfilled placeholders (Sprint 2 Item #5).
#
# Regex scan for template tokens that the orchestrator / LLM was supposed to
# fill in but left blank. Matches are reported as issues so the QA reviewer
# can surface them without re-scanning the document itself.
# ---------------------------------------------------------------------------

# Patterns the orchestrator is supposed to replace at finalization time.
# Each entry is (regex, human-readable name). We strip code fences before
# matching so genuine Markdown code examples (e.g. a snippet that prints
# "TODO" as literal output) do not produce false positives.
_PLACEHOLDER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"_pending_"), "_pending_"),
    (re.compile(r"\b_none detected_\b", re.IGNORECASE), "_none detected_"),
    (re.compile(r"\bREPLACE_[A-Z0-9_]+\b"), "REPLACE_* token"),
    (re.compile(r"<\s*(?:placeholder|fill[- ]?in|tbd|todo)\s*>", re.IGNORECASE), "<placeholder>"),
    # Standalone bracketed markers — must be exactly [TBD] / [TODO] / [FIXME],
    # not e.g. the leading [T-NNN] anchor link.
    (re.compile(r"(?<!\w)\[(?:TBD|TODO|FIXME|XXX)\](?!\()", re.IGNORECASE), "[TBD]/[TODO]/[FIXME]"),
    # Inline text tokens — only when they appear as a standalone word so
    # "TODO list" in narrative prose does not trip, but a bare "TODO" at
    # end-of-line or flanked by whitespace does.
    (re.compile(r"(?:^|\s)(?:TODO|TBD|FIXME|XXX)(?:\s|:|$)"), "bare TODO/TBD/FIXME/XXX"),
    (re.compile(r"\?\?\?"), "??? marker"),
    # Unsubstituted Mustache-style placeholders from narrative_template etc.
    (re.compile(r"\{\{[A-Z_][A-Z0-9_]*\}\}"), "unsubstituted {{PLACEHOLDER}}"),
]


# ---------------------------------------------------------------------------
# Chain T-ID consistency check (P2 — A2)
# ---------------------------------------------------------------------------

# Stop-words excluded from the title-overlap heuristic. These appear in
# almost every threat title and would falsely match any chain label that
# happens to use them.
_CHAIN_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "the",
        "and",
        "or",
        "of",
        "in",
        "on",
        "to",
        "for",
        "via",
        "by",
        "with",
        "from",
        "into",
        "without",
        "is",
        "are",
        "be",
        "as",
        "at",
        "this",
        "that",
        "no",
        "all",
        "any",
        "some",
        "one",
        "two",
        "three",
        # Generic security verbs that match too broadly.
        "exposes",
        "enables",
        "allows",
        "permits",
        "leads",
        "causes",
        "vulnerable",
        "vulnerability",
        "vulnerabilities",
        "attack",
        "attacks",
        "exploit",
        "exploits",
        "endpoint",
        "endpoints",
        "user",
        "users",
        "users'",
        "user-supplied",
        "input",
    }
)


def _chain_label_keywords(label: str) -> set[str]:
    """Extract content keywords from a chain node label, excluding T-NNN
    references, stopwords, and short tokens. Returns lowercase tokens
    of length ≥ 4 stripped of punctuation."""
    # Drop any T-NNN / F-NNN / M-NNN / C-NN tokens — they're identifiers,
    # not content keywords.
    cleaned = re.sub(r"\b[TFMC]-?\d{1,4}\b", " ", label, flags=re.IGNORECASE)
    cleaned = re.sub(r"\bTH-?\d{1,3}\b", " ", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.lower()
    tokens: set[str] = set()
    for raw in re.split(r"[\s/,()<>\[\]{}|·.;:!?\\]+|<br/>", cleaned):
        # Strip residual punctuation and dashes.
        tok = raw.strip("`'\"-*_")
        if len(tok) < 4:
            continue
        if tok in _CHAIN_STOPWORDS:
            continue
        tokens.add(tok)
    return tokens


def _chain_keywords_overlap(label_keywords: set[str], title_keywords: set[str], min_prefix: int = 5) -> bool:
    """Decide whether the chain label and the finding title share a content
    word, tolerating morphological variation by prefix-matching.

    "cracked" matches "crackable" (shared prefix "crack" of length 5).
    "hashes" matches "hashing" (shared prefix "hash" of length 4 — falls
    under the min_prefix threshold so it requires the additional path of
    one of them being a substring of the other).

    Three relations count as a match:
      1. Exact equality.
      2. Common prefix of length ≥ ``min_prefix`` (default 5).
      3. One token is a substring of the other AND length ≥ 4 (catches
         "hashes" ⊂ "hashed", "auth" ⊂ "authentication", etc.).
    """
    if label_keywords & title_keywords:
        return True
    for lk in label_keywords:
        for tk in title_keywords:
            # Common prefix.
            common = 0
            for c1, c2 in zip(lk, tk):
                if c1 != c2:
                    break
                common += 1
            if common >= min_prefix:
                return True
            # Substring containment (when both ≥ 4 chars).
            if len(lk) >= 4 and len(tk) >= 4 and (lk in tk or tk in lk):
                return True
    return False


def check_chain_tid_consistency(md_path: Path, output_dir: Path | None = None) -> Report:
    """**P2 — A2**: Each chain-overview node label that cites a T-NNN must
    share at least one meaningful word with the actual finding title in
    `threat-model.yaml`.

    Catches the regression where the LLM-authored chain diagrams reference
    completely the wrong threat — e.g. labelling node `T-001` as "SQL
    injection login endpoint" when T-001 is actually the hardcoded RSA
    private key finding. The rendered output looks plausible but is
    factually wrong; readers chase a non-existent finding.

    Heuristic: extract chain node labels from §3.1 Attack Chain Overview
    `graph LR` blocks; for every `T-NNN` reference, look up the finding's
    `title` field in `threat-model.yaml`; flag the node when zero
    content-keyword overlap exists between the label text and the title.
    A single shared content word is enough — the check intentionally lets
    paraphrase pass.

    No-op when threat-model.yaml is missing (legacy or pre-rendering
    scenarios).
    """
    import yaml as _yaml

    report = Report("chain_tid_consistency")
    yaml_path = (output_dir / "threat-model.yaml") if output_dir else md_path.parent / "threat-model.yaml"
    if not yaml_path.is_file():
        report.ok = 1
        return report

    try:
        ydata = _fast_yaml_load(yaml_path.read_text(encoding="utf-8")) or {}
    except (OSError, _yaml.YAMLError):
        report.ok = 1
        return report

    # Build T-NNN → title map (normalise keys to upper-case T-NNN).
    title_by_tid: dict[str, str] = {}
    for t in ydata.get("threats") or []:
        if not isinstance(t, dict):
            continue
        tid = (t.get("t_id") or t.get("id") or "").strip().upper()
        title = (t.get("title") or t.get("scenario_short") or "").strip()
        if tid and title:
            title_by_tid[tid] = title

    if not title_by_tid:
        report.ok = 1
        return report

    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return report

    body = _extract_h3_section_body(text, "3.1 Attack Chain Overview")
    if body is None:
        report.ok = 1  # no chain overview present (e.g. quick depth without §3.1)
        return report

    # Iterate mermaid blocks; for each node label that contains a T-NNN
    # reference, check keyword overlap against the finding title.
    blocks = re.findall(r"```mermaid\s*\n(.*?)```", body, re.DOTALL)
    for chain_idx, block in enumerate(blocks, start=1):
        # Match node labels in shapes [text], ["text"], (text), ((text)),
        # ([text]), {text}, {{text}} — capture the inside.
        for m in re.finditer(
            r'(?:\[\[|\[|\(\(|\(|\{\{|\{|\["|\]|\)|\}|"\])'
            r".*?",
            block,
        ):
            pass  # placeholder — actual scanning below
        # Simpler approach: scan for `T-NNN` occurrences and grab a
        # ±60-char window around each (the node label that contains it).
        for tm in re.finditer(r"\bT-(\d{1,4})\b", block):
            tid = f"T-{tm.group(1).zfill(3)}"
            title = title_by_tid.get(tid)
            if not title:
                # T-NNN that doesn't exist in yaml — flagged elsewhere by
                # check_xrefs / chain_compactness; skip here so we don't
                # double-flag.
                continue
            # Extract the surrounding label: from the last opening bracket
            # before the T-NNN to the next closing bracket. This gives us
            # the label content even when nodes use varied shapes.
            start_idx = tm.start()
            # Find label-start backward.
            label_start = -1
            for i in range(start_idx - 1, max(start_idx - 200, -1), -1):
                if block[i] in '["({':
                    label_start = i + 1
                    if i > 0 and block[i - 1] == block[i]:
                        # Double bracket like [[ or ((
                        label_start = i + 1
                    break
            if label_start < 0:
                continue
            # Find label-end forward.
            label_end = len(block)
            for i in range(start_idx, min(start_idx + 200, len(block))):
                if block[i] in '])}"':
                    label_end = i
                    break
            label = block[label_start:label_end].strip("` \t\n\r'\"")
            if not label:
                continue

            label_keywords = _chain_label_keywords(label)
            title_keywords = _chain_label_keywords(title)
            if not label_keywords or not title_keywords:
                # Label or title has no content keywords (e.g. `T-001`-only
                # label with no descriptive text) — can't validate, skip.
                continue
            if not _chain_keywords_overlap(label_keywords, title_keywords):
                report.issues.append(
                    f"§3.1 chain {chain_idx}: node label cites {tid} but the "
                    f"keywords in the label do not overlap with the finding's "
                    f"title in threat-model.yaml. "
                    f"Label keywords: {sorted(label_keywords)[:5]}; "
                    f"title keywords: {sorted(title_keywords)[:5]}; "
                    f"actual finding title: {title!r}. "
                    f"Likely the chain diagram references the wrong finding — "
                    f"either fix the chain label to match {tid}'s actual "
                    f"semantics, or change the T-NNN reference to the threat "
                    f"the label actually describes."
                )

    if not report.issues:
        report.ok = 1
    return report


def check_placeholders(md_path: Path) -> Report:
    """Scan threat-model.md for unfilled template placeholders."""
    report = Report(check="placeholders")
    if not md_path.is_file():
        report.issues.append(f"file not found: {md_path}")
        return report
    text = _strip_code_fences(md_path.read_text(encoding="utf-8"))
    seen: dict[str, list[int]] = {}
    for pat, name in _PLACEHOLDER_PATTERNS:
        for m in pat.finditer(text):
            # Convert byte offset to 1-based line number for operator readability.
            line_no = text.count("\n", 0, m.start()) + 1
            seen.setdefault(name, []).append(line_no)
    for name, lines in sorted(seen.items()):
        # Collapse runs of consecutive lines to keep the issue log readable.
        lines = sorted(set(lines))
        loc = ", ".join(f"line {n}" for n in lines[:8])
        if len(lines) > 8:
            loc += f", +{len(lines) - 8} more"
        report.issues.append(f"{name} at {loc}")
    report.ok = 1 if not report.issues else 0
    return report


# ---------------------------------------------------------------------------
# Check 4 — YAML / MD consistency (Sprint 2 Item #5).
#
# Parse threat-model.yaml and compare the threat and mitigation counts with
# the counts rendered in threat-model.md. Drift between the two is a QA
# defect because downstream consumers (Jira/Linear importers, CI SARIF
# exporters) read the yaml while humans read the md — they must agree.
# ---------------------------------------------------------------------------

_MD_THREAT_ROW_RE = re.compile(
    # A threat-register ID cell can appear in two canonical forms:
    #   1. `| [F-NNN]` or `| [T-NNN]`  — markdown-link form (older)
    #   2. `| <a id="f-001"></a>F-001` — anchor-tag form (current; see
    #      appsec-threat-analyst.md "Section 8 layout — ID cell" and
    #      phase-group-threats.md). The 2026-04-25 juice-shop Run 4 surfaced
    #      a drift where this regex only matched form 1, so md_threat_count
    #      came out as 0 while yaml had 33 threats — QA flagged it as a
    #      false-positive count mismatch even though the actual id sets
    #      matched (verified by the QA reviewer's id-set diff in qa-status).
    # The capture group keeps just the numeric portion so set-based
    # deduplication (re-references in compound-chain tables, etc.) still
    # works correctly across both forms.
    r"(?:"
    r"\|\s*\[(?:F|T)-(\d{3,4})\]"  # form 1: markdown-link in a table cell
    r"|"
    r"<a\s+id=\"[ft]-(\d{3,4})\">"  # form 2: anchor-tag — table ID cell OR
    r")",                            #         card heading (2026-05); no `|` prefix
    re.IGNORECASE,
)
_MD_MITIGATION_HEADING_RE = re.compile(
    r"^####\s+(?:<a\s+id=\"m-\d{3,4}\"></a>\s*)?M-\d+",
    re.IGNORECASE | re.MULTILINE,
)


def check_yaml_md_consistency(md_path: Path, yaml_path: Path) -> Report:
    """Verify the threat and mitigation counts in threat-model.yaml match
    what is rendered in threat-model.md. Renders a helpful delta when they
    don't so the QA reviewer can emit a targeted repair entry."""
    report = Report(check="yaml_md_consistency")

    if not yaml_path.is_file():
        report.warnings.append(f"yaml not present ({yaml_path.name}); check skipped")
        return report
    if not md_path.is_file():
        report.issues.append(f"md not found: {md_path}")
        return report

    try:
        import yaml as _yaml
    except ImportError:
        report.warnings.append("PyYAML unavailable; yaml/md consistency skipped")
        return report

    try:
        yaml_data = _fast_yaml_load(yaml_path.read_text(encoding="utf-8"))
    except _yaml.YAMLError as e:
        report.issues.append(f"yaml malformed: {e}")
        return report

    if not isinstance(yaml_data, dict):
        report.issues.append("yaml top-level is not a mapping")
        return report

    yaml_threat_count = len(yaml_data.get("threats") or [])
    yaml_mitigation_count = len(yaml_data.get("mitigations") or [])

    md_text = md_path.read_text(encoding="utf-8")
    # Count distinct F-/T-NNN ids in threat register rows. The regex has two
    # alternation groups (markdown-link form + anchor-tag form); whichever
    # matched contributes its numeric id, the other is None.
    md_threat_ids = {m.group(1) or m.group(2) for m in _MD_THREAT_ROW_RE.finditer(md_text)}
    md_threat_ids.discard(None)
    md_threat_count = len(md_threat_ids)
    md_mitigation_count = len(_MD_MITIGATION_HEADING_RE.findall(md_text))

    if yaml_threat_count != md_threat_count:
        report.issues.append(f"threat count drift: yaml={yaml_threat_count}, md (distinct F/T-NNN)={md_threat_count}")
    if yaml_mitigation_count != md_mitigation_count:
        report.issues.append(
            f"mitigation count drift: yaml={yaml_mitigation_count}, md (M-NNN headings)={md_mitigation_count}"
        )

    # meta.schema_version must be 1 — sanity check.
    schema_ver = (yaml_data.get("meta") or {}).get("schema_version")
    if schema_ver != 1:
        report.issues.append(f"meta.schema_version expected 1, got {schema_ver!r}")

    # Asset linked_threats cross-reference: every asset's linked_threats[] in
    # YAML must match the T-NNN set rendered in the MD Assets table (Section 4).
    # The MD section ends at the next ## heading.
    assets = yaml_data.get("assets") or []
    if assets:
        sec4_body = _extract_section_body(md_text, r"^##\s+4\.\s+Assets")
        if sec4_body is None:
            report.warnings.append("Section 4 (Assets) not found in MD; asset linked_threats check skipped")
        else:
            # Build a per-asset-ID → set-of-T-NNN map from the MD table cells.
            # Each row that contains an asset ID (A-NNN) is parsed; the last
            # cell is expected to be the Linked Threats column.
            _ASSET_ROW_RE = re.compile(
                r"\|\s*[^|]+\|\s*(A-\d{3,4})\s*\|[^|]*\|[^|]*\|([^|\n]*)",
                re.MULTILINE,
            )
            _ANY_FINDING_RE = re.compile(r"\b([TF]-(\d{3,4}))\b")
            md_asset_lt: dict[str, set[str]] = {}
            for m in _ASSET_ROW_RE.finditer(sec4_body):
                aid = m.group(1).strip()
                cell = m.group(2)
                tids = {t.group(1).upper() for t in _ANY_FINDING_RE.finditer(cell)}
                md_asset_lt[aid] = tids

            def _normalize_id(s: str) -> str:
                # Normalize T-NNN ↔ F-NNN: compose renders threat IDs with the
                # F- (Finding) prefix in user-facing MD while YAML uses the
                # canonical T-NNN. They refer to the same logical threat; the
                # prefix is purely a display convention.
                m = re.match(r"^[TF]-(\d{3,4})$", s.upper())
                return f"T-{m.group(1)}" if m else s.upper()

            for asset in assets:
                aid = str(asset.get("id") or "")
                if not aid:
                    continue
                yaml_lt = {_normalize_id(str(t)) for t in (asset.get("linked_threats") or [])}
                md_lt = {_normalize_id(t) for t in md_asset_lt.get(aid, set())}
                if yaml_lt != md_lt:
                    report.issues.append(
                        f"asset {aid} linked_threats mismatch: yaml={sorted(yaml_lt)} md={sorted(md_lt)}"
                    )

    report.ok = 1 if not report.issues else 0
    return report


# ---------------------------------------------------------------------------
# Check — summary_bullets. Catches summary-style blocks ("Gap summary:", "Top
# risks:", etc.) that the LLM rendered as a single run-on paragraph using
# inline ``(1) … (2) …`` numbering instead of the ``- item`` bullet form the
# renderer's ``bullet_list`` filter produces. The contract does not enforce
# this at the compose layer (the Gap Summary lives inside the
# ``security-architecture.md`` markdown fragment where the author has
# discretion over formatting), so the check has to sit in QA.
#
# Regex anatomy:
#   `\*\*...\s*summary:\*\*` — any bold summary-style lead-in
#   followed by a short intro clause, then `(1)` within ~400 chars on the
#   same logical paragraph. If a real bullet list (`\n- `) shows up first,
#   the check skips it — that's the desired form.
# ---------------------------------------------------------------------------

_SUMMARY_LEADIN_RE = re.compile(
    r"(?m)^"
    r"\s*\*\*(?P<label>[A-Z][A-Za-z /]{2,40}\s*summary)\s*:\*\*\s*"  # **Gap summary:**
    r"(?P<body>[^\n]+(?:\n(?!\n)[^\n]+)*)",  # follow-on prose (no blank line)
)

_INLINE_NUMBERED_RE = re.compile(r"\(\s*[12]\s*\)[^;]*[;:]")


def check_summary_bullets(md_path: Path) -> Report:
    """Scan for summary-style paragraphs that use inline ``(1) … (2) …``
    numbering instead of a real bulleted list.

    The fix is manual (rewriting prose is out of scope for an auto-fix),
    so the check only flags the occurrence. Fragment authors should use
    either a Markdown bullet list (``- item``) directly in the source
    fragment, or the ``bullet_list`` Jinja filter if the block is computed.
    """
    report = Report(check="summary_bullets")
    text = _strip_code_fences(md_path.read_text(encoding="utf-8"))
    for m in _SUMMARY_LEADIN_RE.finditer(text):
        body = m.group("body")
        label = m.group("label").strip()
        # Skip if the very first continuation line after the lead-in is a
        # Markdown bullet (``- ...``) — that's the correct form.
        lines = body.splitlines()
        first_nonblank = next((ln.lstrip() for ln in lines if ln.strip()), "")
        if first_nonblank.startswith(("- ", "* ", "1. ")):
            continue
        # Fire only when inline numbering is actually used.
        head = body[:400]
        if _INLINE_NUMBERED_RE.search(head):
            # Approximate the 1-based line number of the lead-in so the
            # reviewer can navigate directly.
            line_no = text.count("\n", 0, m.start()) + 1
            report.issues.append(
                f"line {line_no}: `**{label}:**` block uses inline "
                "`(1) … (2) …` numbering instead of a bulleted list. "
                f"Rewrite as `**{label}:**\\n\\n- item\\n- item` or render "
                "the source data through the `bullet_list` Jinja filter."
            )
    report.ok = 1 if not report.issues else 0
    return report


# ---------------------------------------------------------------------------
# Check — fragments_present. Hard precondition that the orchestrator actually
# went through Phase 8/9/10/11 via the fragment pipeline rather than taking
# the inline-shortcut (writing threat-model.md directly in one turn). When
# `.fragments/` is empty the contract-mandated renderers
# (``finding_list``/``bullet_list``/computed tables) never run, which is
# the root cause of several structural QA failures.
#
# Severity: "issue" (blocking) when .fragments/ missing entirely; "warning"
# when present but below the expected minimum set. Conditional fragments
# (compound-chains.json, requirements-compliance.md, out-of-scope.md) are
# skipped because they depend on run configuration and on threat counts.
# ---------------------------------------------------------------------------

# Anchored to the contract. Fragments listed here are unconditional — they
# must exist on every run that passed through compose_threat_model.py.
REQUIRED_FRAGMENTS = (
    "ms-verdict.json",
    "ms-architecture-assessment.json",
    "system-overview.md",
    "architecture-diagrams.md",
    "attack-walkthroughs.md",
    "assets.md",
    "attack-surface.md",
    "security-architecture.md",
)


def check_security_posture_structure(md_path: Path) -> Report:
    """Validate the Security Posture & Top Threats section against the
    invariants declared in
    `data/sections-contract.yaml > security_posture_at_a_glance.invariants`.

    Layout: the forward-only Mermaid heatmap (Figure 2) — 3 columns
    (ACTORS / TIERS / IMPACT) with explicit attack arrows, dashed
    consequence arrows and cross-subgraph header-alignment edges —
    followed by the **Top Threats** table.

    2026-05: the legacy per-attack-class BULLET list (former N / B / L
    invariants) was replaced by the Top Threats table, so this check now
    validates the table (T-rules) instead of the bullets.

    Categories:
      D1–D6  Diagram structure (mermaid block, subgraphs, direction)
      E1–E5  Edge structure (alignment, attack arrows, consequence, linkStyle, undeclared nodes)
      C1     Card label structure (≤6 <br/> per label; HTML emphasis allowed)
      F1–F3  Column population (HDR + content cards per column)
      G1–G2  Glyph consistency on the attack arrows (uniqueness, contiguous order)
      T1–T3  Top Threats table (header present, diagram↔table glyph parity, F-NNN links)
    """
    report = Report("posture_structure")
    text = md_path.read_text(encoding="utf-8")

    sec_start = text.find("### Security Posture & Top Threats")
    if sec_start < 0:
        report.ok = 1
        return report
    sec_end = text.find("\n### ", sec_start + 1)
    if sec_end < 0:
        sec_end = text.find("\n## ", sec_start + 1)
    if sec_end < 0:
        sec_end = len(text)
    section = text[sec_start:sec_end]

    # Locate the heatmap (Figure 2) mermaid block specifically — an optional
    # Figure 1 architecture diagram may precede it, so we anchor on the
    # ACTORS subgraph and take the ```mermaid fence that opens its block.
    heatmap_anchor = section.find("subgraph ACTORS")
    if heatmap_anchor >= 0:
        m_start = section.rfind("```mermaid", 0, heatmap_anchor)
    else:
        m_start = section.find("```mermaid")
    if m_start < 0:
        report.issues.append("D2: section has no ```mermaid block")
        return report
    m_end = section.find("```", m_start + 10)
    if m_end < 0:
        report.issues.append("D2: ```mermaid block is not closed")
        return report
    mermaid = section[m_start : m_end + 3]
    after_mermaid = section[m_end + 3 :]

    # ---- D-rules: diagram structure ----------------------------------------
    # D1: ELK renderer init directive.
    if "defaultRenderer" not in mermaid or '"elk"' not in mermaid:
        report.issues.append(
            'D1: mermaid block must declare ELK renderer via `%%{init: {"flowchart": {"defaultRenderer": "elk"}} }%%`'
        )
    # D2: flowchart LR.
    if not re.search(r"\nflowchart LR\b", mermaid):
        report.issues.append("D2: mermaid block does not contain `flowchart LR`")

    subgraph_decls = re.findall(r"^\s*subgraph\s+(\w+)\[", mermaid, re.MULTILINE)
    if subgraph_decls != ["ACTORS", "TIERS", "IMPACT"]:
        report.issues.append(f"D3: subgraph order must be exactly ACTORS, TIERS, IMPACT — got {subgraph_decls!r}")

    # D4: empty subgraph titles + HDR_A/HDR_T/HDR_I as first node of each.
    for sg, hdr in (("ACTORS", "HDR_A"), ("TIERS", "HDR_T"), ("IMPACT", "HDR_I")):
        m = re.search(rf'subgraph\s+{sg}\[\s*"\s*"\s*\]', mermaid)
        if not m:
            report.issues.append(
                f'D4: subgraph {sg} title must be empty (`[" "]`) — header is emitted as the first node ({hdr})'
            )
        if hdr not in mermaid:
            report.issues.append(f"D4: header node {hdr} missing from {sg} subgraph")

    # D5: each subgraph carries `direction TB`.
    for sg in ("ACTORS", "TIERS", "IMPACT"):
        sg_match = re.search(
            rf"subgraph\s+{sg}\[[^\n]*\n((?:\s+[^\n]*\n)+?)\s+end",
            mermaid,
        )
        if sg_match and "direction TB" not in sg_match.group(1):
            report.issues.append(f"D5: subgraph {sg} missing `direction TB`")

    # D6: no nested subgraphs.
    depth = 0
    nested = 0
    for line in mermaid.splitlines():
        s = line.strip()
        if s.startswith("subgraph "):
            if depth > 0:
                nested += 1
            depth += 1
        elif s == "end":
            depth = max(0, depth - 1)
    if nested:
        report.issues.append(f"D6: {nested} nested subgraph(s) detected — flat structure required")

    # ---- E-rules: edge structure -------------------------------------------
    # E1: alignment edges. Header chain mandatory; per-component optional but
    # warn if missing entirely.
    has_hdr_chain = "HDR_A --- HDR_T" in mermaid and "HDR_T --- HDR_I" in mermaid
    if not has_hdr_chain:
        report.issues.append(
            "E1: header alignment chain `HDR_A --- HDR_T --- HDR_I` is missing — "
            "without it the column headers may drift to different Y positions"
        )

    # E2: attack arrows (==>) with numbered glyph labels in declaration order.
    # Mermaid label syntax permits both bare (`|① label|`) and quoted
    # (`|" ① label "|`) forms — the template emits the quoted form for visual
    # spacing, so the optional `"?` and surrounding `\s*` allow either.
    # Relay arrows (victim-targeting second leg, under "%% Relay arrows" comment)
    # share the same glyphs as their parent attack arrows — exclude them from E2.
    in_relay = False
    attack_lines = []
    for ln in mermaid.splitlines():
        if re.search(r"%%\s*Relay arrows", ln):
            in_relay = True
        elif re.search(r"%%\s*(Consequence|Attack)", ln):
            in_relay = False
        if not in_relay and "==>" in ln and re.search(r"[①②③④⑤⑥⑦]", ln):
            attack_lines.append(ln)
    if not (1 <= len(attack_lines) <= 7):
        report.issues.append(f"E2: expected 1–7 attack arrows with ①–⑦ labels, found {len(attack_lines)}")
    # Reference form (2026-05): a single grouped arrow per (actor, tier) may
    # carry SEVERAL glyphs in its label, e.g. `|" ① ③ ④ ⑤ "|`. Collect every
    # glyph that appears inside an attack-arrow's edge label; the UNION must be
    # the contiguous run ① ② … N with no duplicates (G1) and no gaps (G2).
    _GLYPHS = "①②③④⑤⑥⑦"
    actual_glyphs: list[str] = []
    for ln in attack_lines:
        mlab = re.search(r"\|([^|]*)\|", ln)
        scan = mlab.group(1) if mlab else ln
        actual_glyphs.extend(ch for ch in scan if ch in _GLYPHS)
    seen: list[str] = []
    dupes: list[str] = []
    for g in actual_glyphs:
        (dupes if g in seen else seen).append(g)
    if dupes:
        report.issues.append(f"G1: glyph(s) {sorted(set(dupes))!r} appear on more than one attack arrow")
    ordered = sorted(seen, key=lambda g: _GLYPHS.index(g))
    if ordered != list(_GLYPHS[: len(seen)]):
        report.issues.append(
            f"E2/G2: attack-arrow glyphs must be the contiguous run ① ② … without gaps — got {ordered!r}"
        )

    # E3: consequence arrows (-.->).
    cons_lines = [ln for ln in mermaid.splitlines() if "-.->" in ln]
    if not (1 <= len(cons_lines) <= 6):
        report.issues.append(f"E3: expected 1–6 consequence arrows (-.->), found {len(cons_lines)}")

    # E4: linkStyle declarations exist.
    if not re.search(r"linkStyle\s+[\d,\s]+\s+stroke:transparent", mermaid):
        report.issues.append("E4: missing `linkStyle … stroke:transparent` for alignment edges")
    if "stroke:#b71c1c" not in mermaid:
        report.issues.append("E4: missing red attack-arrow linkStyle (stroke:#b71c1c)")
    if "stroke:#6b7280" not in mermaid:
        report.issues.append("E4: missing grey-dashed consequence linkStyle (stroke:#6b7280)")

    # ---- C-rules: card label structure -------------------------------------
    # Match all three card shapes the template emits — standard `["…"]`,
    # rounded `(["…"])`, and hexagonal `[["…"]]` — so C1's ≤6 <br/> rule is
    # enforced uniformly across every node, not just the rectangle ones.
    label_pattern = re.compile(r'\b\w+(?:\["([^"]+)"\]|\(\["([^"]+)"\]\)|\[\["([^"]+)"\]\])(?::::\w+)?')
    for label_match in label_pattern.finditer(mermaid):
        label = label_match.group(1) or label_match.group(2) or label_match.group(3) or ""
        # C1: ≤ 6 br tags per label (bumped from contract v1's ≤ 3).
        br_count = label.count("<br/>") + label.count("<br>")
        if br_count > 6:
            report.issues.append(f"C1: label has {br_count} <br/> tags (max 6): {label[:60]!r}")
        # (C3 removed — HTML emphasis IS allowed in contract v2.)

    # ---- F-rules: column population ----------------------------------------
    actors_block = _extract_subgraph_block(mermaid, "ACTORS")
    tiers_block = _extract_subgraph_block(mermaid, "TIERS")
    impact_block = _extract_subgraph_block(mermaid, "IMPACT")
    # Card counts include the header node.
    actor_count = _count_cards(actors_block) if actors_block else 0
    tier_count = _count_cards(tiers_block) if tiers_block else 0
    impact_count = _count_cards(impact_block) if impact_block else 0
    if not (2 <= actor_count <= 6):
        report.issues.append(f"F1: ACTORS column has {actor_count} cards (expected 2–6: HDR + 1–5 actors)")
    if not (2 <= tier_count <= 4):
        report.issues.append(f"F2: TIERS column has {tier_count} cards (expected 2–4: HDR + 1–3 tiers)")
    if not (2 <= impact_count <= 5):
        report.issues.append(f"F3: IMPACT column has {impact_count} cards (expected 2–5: HDR + 1–4 impacts)")

    # ---- E5: undeclared node check (Fix 2) ---------------------------------
    # compose_threat_model.py emits attack arrows targeting canonical node_ids
    # from _TIER_DISPLAY (BROWSER, SERVER, DATA). If any of those node_ids
    # appears in an arrow but is NOT declared as a node in the TIERS subgraph,
    # Mermaid auto-creates a bare unstyled rectangle labelled with the raw ID.
    # This is what produced the "SERVER" box in the 2026-05-08 juice-shop run.
    _check_heatmap_undeclared_nodes(report, mermaid, tiers_block or "")

    # ---- T-rules: Top Threats table below the diagram ----------------------
    # 2026-05 — the merged section renders the **Top Threats** table after
    # Figure 2 (not the legacy attack-path bullet list). Validate the table is
    # present, that its row glyphs agree 1:1 with the diagram's attack-arrow
    # glyphs (G3, now diagram↔table), and that finding/mitigation/component
    # cross-references are linked.
    # T1: table header present.
    if "| # | Threat Description | Findings (→ Component) | Risk & Impact | Fix |" not in after_mermaid:
        report.issues.append("T1: missing Top Threats table header below the diagram")
    # T2/G3: every diagram arrow glyph appears exactly once as a table-row `#`
    # glyph (the row carries `<a id="path-…"></a>①`), and vice versa.
    table_glyphs = re.findall(
        r'^\|\s*(?:<a id="[^"]+"></a>)?\s*([①②③④⑤⑥⑦])\s*\|',
        after_mermaid,
        re.MULTILINE,
    )
    arrow_glyph_set = set(actual_glyphs)
    if arrow_glyph_set and arrow_glyph_set != set(table_glyphs):
        report.issues.append(
            f"T2/G3: diagram arrow glyphs {arrow_glyph_set} ≠ Top Threats row glyphs {set(table_glyphs)}"
        )
    # T3: at least one finding is linked into §8 (`[F-NNN](#f-nnn)`); the table
    # is the canonical place those cross-references now live.
    if table_glyphs and not re.search(r"\[F-\d+\]\(#f-\d+\)", after_mermaid):
        report.issues.append("T3: Top Threats findings are not linked to §8 (`[F-NNN](#f-nnn)`)")

    if not report.issues:
        report.ok = 1
    return report


def _check_heatmap_undeclared_nodes(report: Report, mermaid: str, tiers_block: str) -> None:
    """Fix (2): detect arrow targets that are not declared as nodes in TIERS.

    compose_threat_model.py uses hardcoded node_ids (BROWSER, SERVER, DATA)
    from _TIER_DISPLAY. If the TIERS subgraph is missing a card for one of
    those ids, Mermaid auto-creates an unstyled rectangle with the raw id as
    the label. Observed in the 2026-05-08 juice-shop run: the Application
    tier card was absent so the diagram rendered a plain box labelled "SERVER".

    Strategy: collect every node_id declared inside TIERS, then check that
    every arrow target referencing a known tier node_id is declared.
    """
    # Canonical tier node_ids emitted by compose_threat_model._TIER_DISPLAY.
    canonical_tier_ids = {"BROWSER", "SERVER", "DATA"}

    # Node ids declared in the TIERS subgraph block: lines of the form
    # `    NODE_ID["…"]`, `    NODE_ID(["…"])`, etc.
    declared_in_tiers: set[str] = set(re.findall(r"^\s+([A-Z_][A-Z0-9_]*)(?:\[|\()", tiers_block, re.MULTILINE))

    # Attack / consequence arrow targets in the mermaid block.
    # Match `==>|…| TARGET` and `-.-> TARGET`.
    arrow_targets: set[str] = set(re.findall(r"(?:==>|--?>)\s*(?:\|[^|]*\|\s*)?([A-Z_][A-Z0-9_]*)\b", mermaid))
    arrow_targets.update(re.findall(r"-\.->(?:\s*\|[^|]*\|)?\s*([A-Z_][A-Z0-9_]*)\b", mermaid))

    for node_id in canonical_tier_ids:
        if node_id in arrow_targets and node_id not in declared_in_tiers:
            report.issues.append(
                f"E5: heatmap arrow references tier node {node_id!r} but that node "
                f"is not declared inside the TIERS subgraph — Mermaid will render "
                f"a bare unstyled rectangle labelled '{node_id}'. "
                f"Declared tier nodes: {sorted(declared_in_tiers) or '(none)'}. "
                f"Check that compose_threat_model._build_tier_cards() produced "
                f"a card for all three tiers (client/application/data)."
            )


def _extract_subgraph_block(mermaid: str, sg_name: str) -> str:
    """Return the body of `subgraph <name>` … `end`, or empty string."""
    m = re.search(rf"subgraph\s+{sg_name}\b[^\n]*\n((?:\s+[^\n]*\n)+?)\s+end", mermaid)
    return m.group(1) if m else ""


def _count_cards(block: str) -> int:
    """Count card declarations in a subgraph block, excluding direction lines
    and class assignments. The template emits three Mermaid node shapes:

      * standard rectangle ``NODE_ID["…"]`` — header + tier cards
      * stadium / rounded ``NODE_ID(["…"])`` — actor cards
      * hexagonal ``NODE_ID[["…"]]`` — impact cards

    All three count as one card each. ``re.search`` is used per line so a
    line with at least one declaration counts as 1 even if the regex would
    otherwise have multiple alternatives that could fire.
    """
    return sum(
        1
        for line in block.splitlines()
        if re.search(
            r'\b\w+(?:\["[^"]+"\]|\(\["[^"]+"\]\)|\[\["[^"]+"\]\])',
            line,
        )
    )


def check_fragments_present(output_dir: Path) -> Report:
    """Verify the orchestrator wrote fragments before composing the MD.

    Fragment absence is a structural contract violation: without them the
    renderer never ran, which in turn means the contract-mandated table
    stacking, bullet lists, and computed sections were all hand-authored
    as freehand markdown. The Re-Render Loop cannot repair this run
    because there is nothing on disk for compose_threat_model.py to work
    with — the only remediation is to re-run Phase 8–11 with the
    fragment pipeline explicitly enabled.

    Detection covers three independent indicators of an inline-shortcut bypass.
    Any one of them flags the run:

      A. ``.fragments/`` directory missing OR present-but-empty.
      B. Fewer than ``REQUIRED_FRAGMENTS`` files present (orchestrator
         wrote some but skipped the rest — partial bypass).
      C. ``.threats-merged.json`` missing while ``threat-model.md`` exists
         (orchestrator hand-authored the register without running the
         Phase 9 merge step). This indicator is independent of A/B and
         catches the case where the orchestrator faked a valid-looking
         ``.fragments/`` set but skipped the upstream merge work.

    The 2026-04-25 juice-shop Run 4 was the canonical case: ``.fragments/``
    existed (mkdir'd at Phase 11 start) but was empty, and the upstream
    ``.threats-merged.json`` was also missing. Indicator A caught it
    via the empty-directory check; Indicator C provided independent
    confirmation. Before this rewrite the function returned an empty
    issue list when ``.fragments/`` existed-but-empty (because the
    REQUIRED_FRAGMENTS loop reported all of them missing without any
    early signal that the directory itself was a fake — and the report
    consumer treated "many missing fragments" as repair-loop-eligible
    rather than as a hard inline-shortcut). The new structure keeps the
    per-fragment list intact but adds explicit summary issues that make
    the inline-shortcut classification unambiguous to callers.
    """
    report = Report(check="fragments_present")
    frag_dir = output_dir / ".fragments"
    md_path = output_dir / "threat-model.md"
    threats_merged = output_dir / ".threats-merged.json"

    # Indicator A1 — directory missing entirely.
    if not frag_dir.is_dir():
        report.issues.append(
            f".fragments/ directory missing at {frag_dir} — orchestrator took "
            "the inline-shortcut and bypassed compose_threat_model.py. "
            "Re-run Phase 8–11 with fragment persistence enabled."
        )
        return report

    present = {p.name for p in frag_dir.iterdir() if p.is_file()}

    # Indicator A2 — directory exists but empty / near-empty. Surface as a
    # single dedicated issue so callers can distinguish "structural bypass"
    # from "one fragment missing" without parsing the per-fragment list.
    if len(present) < 3:
        report.issues.append(
            f".fragments/ contains only {len(present)} files at {frag_dir} "
            f"(< 3 minimum; pipeline writes {len(REQUIRED_FRAGMENTS)}+) — "
            "orchestrator entered Phase 11 but skipped the fragment-writing "
            "substep. The threat model on disk is hand-authored and bypasses "
            "the schema-validated renderer."
        )

    missing = [name for name in REQUIRED_FRAGMENTS if name not in present]
    for name in missing:
        report.issues.append(
            f"required fragment missing: .fragments/{name} — orchestrator "
            "skipped the phase that was supposed to write it, or wrote it "
            "under a non-canonical filename."
        )

    # Indicator C — Phase 9 merge output missing while threat-model.md exists.
    # Independent of A/B: catches orchestrators that produced a plausible
    # fragment set but never wrote the upstream merge artifact.
    if md_path.is_file() and not threats_merged.is_file():
        report.issues.append(
            ".threats-merged.json missing while threat-model.md exists — "
            "Phase 9 merge step was bypassed. The register in the rendered "
            "Markdown is not backed by canonical merged-threat data, which "
            "means future incremental runs lose carry-forward state and the "
            "reported counts cannot be cross-validated against yaml."
        )

    # Healthy runs have at least 8 fragments present (the unconditional set).
    report.ok = len(REQUIRED_FRAGMENTS) - len(missing)
    return report


# ---------------------------------------------------------------------------
# Check — cell_format. Catches `[F-001](#f-001) [F-002](#f-002)` in table
# cells that the contract declares as `render: finding_list` (or
# `mitigation_list` / `component_list`). compose_threat_model.py's renderer
# stacks those cells with `<br/>` between items; orchestrators that skip the
# renderer leave them space-separated, which breaks the contract's "one item
# per line" visual convention. The check fires on any 2+-link cell in a
# markdown table whose links are ID-shaped, and auto-fixes them by inserting
# `<br/>` between adjacent space-separated links.
# ---------------------------------------------------------------------------

_ID_LINK_RE = re.compile(r"\[([A-Z]{1,3}-\d{2,4})\]\(#[a-z0-9-]+\)")
_TABLE_ROW_RE = re.compile(r"^\|.*\|\s*$")
_TABLE_SEP_RE = re.compile(r"^\|\s*:?-{3,}[\s:|-]*\|\s*$")


def _iter_table_blocks(text: str):
    """Yield ``(start_line, rows)`` for every GitHub-flavored table found.

    A table is: one header row, a separator row, then one or more body rows
    — all lines starting with ``|`` and ending with ``|``. We scan the
    code-fence-stripped text so fenced examples are ignored.
    """
    clean = _strip_code_fences(text)
    lines = clean.splitlines()
    i = 0
    while i < len(lines) - 1:
        if _TABLE_ROW_RE.match(lines[i]) and _TABLE_SEP_RE.match(lines[i + 1]):
            start = i
            j = i + 2
            while j < len(lines) and _TABLE_ROW_RE.match(lines[j]):
                j += 1
            yield start, lines[start:j]
            i = j
        else:
            i += 1


def _split_table_cells(row: str) -> list[str]:
    """Split a table row into cells, stripping the leading/trailing pipes."""
    stripped = row.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    return [c.strip() for c in stripped.split("|")]


def _fix_cell_stacking(cell: str) -> tuple[str, int]:
    """Insert ``<br/>`` between adjacent ``[ID](#id)`` links.

    Returns ``(new_cell, replacements)``. Replaces any combination of
    whitespace, comma, or semicolon between two ID-link tokens with a
    ``<br/>`` — these are the three separator styles seen in LLM-authored
    markdown fragments. Existing ``<br/>`` separators are left alone.

    Prose outside tables is never touched because this function is only
    called on cells already confirmed to carry 2+ ID links (see
    ``check_cell_format``).
    """
    # Target pattern: `](#..)` followed by optional `,`/`;`/whitespace, then
    # another ID-shaped link. The separator class `\s*[,;\s]\s*` covers:
    #   * `](#a) [B]`      → space-separated
    #   * `](#a), [B]`     → comma + space (most common in LLM output)
    #   * `](#a); [B]`     → semicolon + space
    #   * `](#a) , [B]`    → awkward spacing
    #   * `](#a)\n[B]`     → accidental newline (rare; tables usually one-line)
    # Existing `<br/>`-separated links do not match because `<` is not in
    # the separator class.
    pattern = re.compile(
        r"(\]\(#[a-z0-9-]+\))"  # end of first link
        r"\s*[,;\s]\s*"  # separator
        r"(\[[A-Z]{1,3}-\d{2,4}\]\(#[a-z0-9-]+\))"  # next ID link
    )
    replacements = 0
    previous = None
    new_cell = cell
    # Loop because after one replacement the trailing half may re-match a
    # third link: `]($1), [$2], [$3]` → `]<br/>[$2], [$3]` → `]<br/>[$2]<br/>[$3]`.
    while previous != new_cell:
        previous = new_cell
        new_cell, n = pattern.subn(r"\1<br/>\2", new_cell)
        replacements += n
    return new_cell, replacements


def check_cell_format(md_path: Path) -> tuple[Report, str]:
    """Scan every markdown table for space-stacked ID links and auto-fix.

    Behavior:
      - Fires once per offending cell (not once per extra link).
      - Applies the fix in place to the returned text; the caller writes
        the file back.
      - Never touches prose text outside tables, never touches fenced code
        blocks, never reorders links, never collapses whitespace inside
        non-link cell text.
    """
    report = Report(check="cell_format")
    text = md_path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    total_cells_checked = 0
    fixes_applied: list[str] = []
    issues_remaining: list[str] = []

    for start_line, block in _iter_table_blocks(text):
        # §4 Assets deliberately renders its "Linked Threats" column INLINE
        # (` · `-separated) rather than `<br/>`-stacked, so the column claims
        # enough width in content-sizing renderers — stacked links made it the
        # narrowest column while the prose Description dominated (2026-05-30 user
        # request). Skip the stacking auto-fix for that one table.
        header_cells = {c.lower() for c in _split_table_cells(block[0])} if block else set()
        if {"asset", "classification", "description", "linked threats"} <= header_cells:
            continue
        # Header + separator + body rows.  We only rewrite body rows.
        for offset, row in enumerate(block[2:], start=2):
            line_idx = start_line + offset
            cells = _split_table_cells(row)
            rewritten = False
            new_cells = []
            for cell in cells:
                total_cells_checked += 1
                # Only candidates: cells with 2+ ID-shaped links
                link_count = len(_ID_LINK_RE.findall(cell))
                if link_count < 2:
                    new_cells.append(cell)
                    continue
                if "<br/>" in cell or "<br>" in cell:
                    # Already stacked properly.
                    new_cells.append(cell)
                    continue
                # Prose cells that merely CITE findings inline (a sentence such
                # as "Bypassed by 3 High finding(s) … e.g. [F-015](…), [F-016](…)")
                # are not stacked link lists — flagging them "missing <br/>" is a
                # false positive (juice-shop 2026-06-03 §2 cluster-coverage line).
                # A genuine stack cell starts with its first link (optionally
                # behind a bullet / severity glyph); a prose cell has running
                # words before the first link. Skip when >3 prose words precede it.
                _first_link = _ID_LINK_RE.search(cell)
                if _first_link is not None:
                    _lead_words = re.findall(r"[A-Za-z]{2,}", cell[: _first_link.start()])
                    # `&nbsp;` contributes the token "nbsp"; allow a couple of
                    # those plus a stray glyph word without tripping the skip.
                    if len([w for w in _lead_words if w.lower() != "nbsp"]) > 3:
                        new_cells.append(cell)
                        continue
                # Apply the fix.  If it didn't actually help (e.g. the
                # links were separated by commas rather than whitespace),
                # flag it so the agent can inspect.
                new_cell, n = _fix_cell_stacking(cell)
                if n > 0:
                    rewritten = True
                    fixes_applied.append(f"line {line_idx + 1}: stacked {n + 1} links with <br/> (cell: {cell[:80]!r})")
                    new_cells.append(new_cell)
                else:
                    issues_remaining.append(
                        f"line {line_idx + 1}: {link_count} ID links in one cell "
                        f"with no <br/> and no space separator — inspect: "
                        f"{cell[:120]!r}"
                    )
                    new_cells.append(cell)
            if rewritten:
                # Reconstruct the row preserving leading/trailing pipes and
                # newline. GitHub-flavored markdown canonicalises to
                # ``| cell | cell | cell |``.
                new_row = "| " + " | ".join(new_cells) + " |"
                # Preserve the original line ending.
                orig_line = lines[line_idx]
                newline = "\n" if orig_line.endswith("\n") else ""
                lines[line_idx] = new_row + newline

    new_text = "".join(lines)
    report.fixes.extend(fixes_applied)
    report.issues.extend(issues_remaining)
    report.ok = total_cells_checked - len(fixes_applied) - len(issues_remaining)
    return report, new_text


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    sub = argv[1]
    if sub == "links":
        if len(argv) != 4:
            print("usage: qa_checks.py links <md> <repo-root>", file=sys.stderr)
            return 2
        report, new_text = check_links(Path(argv[2]), Path(argv[3]))
        Path(argv[2]).write_text(new_text, encoding="utf-8")
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "xrefs":
        report = check_xrefs(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "anchors":
        report, new_text = linkify_anchors(Path(argv[2]))
        Path(argv[2]).write_text(new_text, encoding="utf-8")
        print(json.dumps(report.as_dict(), indent=2))
        return 0
    if sub == "invariants":
        report = check_invariants(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "ms_structure":
        if len(argv) != 3:
            print("usage: qa_checks.py ms_structure <md>", file=sys.stderr)
            return 2
        report, new_text = check_ms_structure(Path(argv[2]))
        Path(argv[2]).write_text(new_text, encoding="utf-8")
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "contract":
        if len(argv) not in (3, 4):
            print("usage: qa_checks.py contract <md> [<contract.yaml>]", file=sys.stderr)
            return 2
        contract = Path(argv[3]) if len(argv) == 4 else DEFAULT_CONTRACT_PATH
        report = check_contract(Path(argv[2]), contract)
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "repair_plan":
        if len(argv) not in (4, 5):
            print(
                "usage: qa_checks.py repair_plan <md> <output-dir> [<contract.yaml>]",
                file=sys.stderr,
            )
            return 2
        contract = Path(argv[4]) if len(argv) == 5 else DEFAULT_CONTRACT_PATH
        return cmd_repair_plan(Path(argv[2]), Path(argv[3]), contract)
    if sub == "all":
        if len(argv) != 4:
            print("usage: qa_checks.py all <md> <repo-root>", file=sys.stderr)
            return 2
        return cmd_all(Path(argv[2]), Path(argv[3]))
    if sub == "autofix":
        if len(argv) != 4:
            print("usage: qa_checks.py autofix <md> <repo-root>", file=sys.stderr)
            return 2
        return cmd_autofix(Path(argv[2]), Path(argv[3]))
    if sub == "heading_hygiene":
        if len(argv) != 3:
            print("usage: qa_checks.py heading_hygiene <md>", file=sys.stderr)
            return 2
        report = check_heading_hygiene(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "toc_closure":
        if len(argv) != 3:
            print("usage: qa_checks.py toc_closure <md>", file=sys.stderr)
            return 2
        report = check_toc_closure(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "section7_h4_status":
        if len(argv) != 3:
            print("usage: qa_checks.py section7_h4_status <md>", file=sys.stderr)
            return 2
        report = check_section7_h4_status(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    # Warning-only structural guards retired from the `all` pre-pass (they
    # reached no actuator — not in build_repair_plan, no agent handoff action).
    # Kept callable as standalone subcommands for CI / manual regression use.
    if sub == "attack_tree_node_id_leak":
        if len(argv) != 3:
            print("usage: qa_checks.py attack_tree_node_id_leak <md>", file=sys.stderr)
            return 2
        report = check_attack_tree_node_id_leak(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "section_713_no_table":
        if len(argv) != 3:
            print("usage: qa_checks.py section_713_no_table <md>", file=sys.stderr)
            return 2
        report = check_section_713_no_table(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "hypothesis_validation_objective":
        if len(argv) != 3:
            print("usage: qa_checks.py hypothesis_validation_objective <md>", file=sys.stderr)
            return 2
        report = check_hypothesis_validation_objective(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    # Warning-only §7 prose checks retired from the `all` pre-pass (no actuator;
    # rules enforced at the renderer). Kept callable for CI / manual use.
    if sub == "paragraph_density":
        if len(argv) != 3:
            print("usage: qa_checks.py paragraph_density <md>", file=sys.stderr)
            return 2
        report = check_paragraph_density(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "architectural_prose":
        if len(argv) != 3:
            print("usage: qa_checks.py architectural_prose <md>", file=sys.stderr)
            return 2
        report = check_architectural_prose(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "generic_phrases":
        if len(argv) != 3:
            print("usage: qa_checks.py generic_phrases <md>", file=sys.stderr)
            return 2
        report = check_generic_phrases(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "rhetorical_severity":
        if len(argv) != 3:
            print("usage: qa_checks.py rhetorical_severity <md>", file=sys.stderr)
            return 2
        report = check_rhetorical_severity(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "section_opener_restates_heading":
        if len(argv) != 3:
            print("usage: qa_checks.py section_opener_restates_heading <md>", file=sys.stderr)
            return 2
        report = check_section_opener_restates_heading(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "finding_range_homogeneous":
        if len(argv) != 3:
            print("usage: qa_checks.py finding_range_homogeneous <md>", file=sys.stderr)
            return 2
        report = check_finding_range_homogeneous(Path(argv[2]), Path(argv[2]).parent)
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "dependency_cross_ref":
        if len(argv) != 3:
            print("usage: qa_checks.py dependency_cross_ref <md>", file=sys.stderr)
            return 2
        report = check_dependency_cross_ref(Path(argv[2]), Path(argv[2]).parent)
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "na_against_recon":
        if len(argv) != 3:
            print("usage: qa_checks.py na_against_recon <md>", file=sys.stderr)
            return 2
        report = check_na_against_recon(Path(argv[2]), Path(argv[2]).parent)
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "mermaid_syntax":
        if len(argv) != 3:
            print("usage: qa_checks.py mermaid_syntax <md>", file=sys.stderr)
            return 2
        report = check_mermaid_syntax(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "toc_nested_links":
        if len(argv) != 3:
            print("usage: qa_checks.py toc_nested_links <md>", file=sys.stderr)
            return 2
        report = check_toc_nested_links(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "infobox_completeness":
        if len(argv) != 3:
            print("usage: qa_checks.py infobox_completeness <md>", file=sys.stderr)
            return 2
        report = check_infobox_completeness(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "placeholders":
        if len(argv) != 3:
            print("usage: qa_checks.py placeholders <md>", file=sys.stderr)
            return 2
        report = check_placeholders(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "section7_narrative_placeholders":
        if len(argv) != 3:
            print("usage: qa_checks.py section7_narrative_placeholders <md>", file=sys.stderr)
            return 2
        report = check_section7_narrative_placeholders(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "section7_h4_positive_intro":
        if len(argv) != 3:
            print("usage: qa_checks.py section7_h4_positive_intro <md>", file=sys.stderr)
            return 2
        report = check_section7_h4_positive_intro(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "section7_fence_intro_sentence":
        if len(argv) != 3:
            print("usage: qa_checks.py section7_fence_intro_sentence <md>", file=sys.stderr)
            return 2
        report = check_section7_fence_intro_sentence(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "section7_finding_link_duplicate":
        if len(argv) != 3:
            print("usage: qa_checks.py section7_finding_link_duplicate <md>", file=sys.stderr)
            return 2
        report = check_section7_finding_link_duplicate(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "section7_finding_reference_semantic":
        if len(argv) != 3:
            print("usage: qa_checks.py section7_finding_reference_semantic <md>", file=sys.stderr)
            return 2
        report = check_section7_finding_reference_semantic(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "label_as_code":
        if len(argv) != 3:
            print("usage: qa_checks.py label_as_code <md>", file=sys.stderr)
            return 2
        report = check_label_as_code(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "yaml_md":
        if len(argv) != 4:
            print("usage: qa_checks.py yaml_md <md> <yaml>", file=sys.stderr)
            return 2
        report = check_yaml_md_consistency(Path(argv[2]), Path(argv[3]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "cell_format":
        if len(argv) != 3:
            print("usage: qa_checks.py cell_format <md>", file=sys.stderr)
            return 2
        report, new_text = check_cell_format(Path(argv[2]))
        if new_text != Path(argv[2]).read_text(encoding="utf-8"):
            Path(argv[2]).write_text(new_text, encoding="utf-8")
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "summary_bullets":
        if len(argv) != 3:
            print("usage: qa_checks.py summary_bullets <md>", file=sys.stderr)
            return 2
        report = check_summary_bullets(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "fragments":
        if len(argv) != 3:
            print("usage: qa_checks.py fragments <output-dir>", file=sys.stderr)
            return 2
        report = check_fragments_present(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "evidence_integrity":
        if len(argv) != 4:
            print(
                "usage: qa_checks.py evidence_integrity <output-dir> <repo-root>",
                file=sys.stderr,
            )
            return 2
        report = check_evidence_integrity(Path(argv[2]), Path(argv[3]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "perimeter_claims":
        if len(argv) != 3:
            print("usage: qa_checks.py perimeter_claims <threat-model.md>", file=sys.stderr)
            return 2
        report = check_unfounded_perimeter_claims(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "unmasked_secrets":
        if len(argv) not in (3, 4):
            print("usage: qa_checks.py unmasked_secrets <threat-model.md> [<output-dir>]", file=sys.stderr)
            return 2
        out_dir = Path(argv[3]) if len(argv) == 4 else None
        report = check_unmasked_secrets(Path(argv[2]), out_dir)
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "relevant_findings":
        if len(argv) not in (3, 4):
            print("usage: qa_checks.py relevant_findings <threat-model.md> [<contract.yaml>]", file=sys.stderr)
            return 2
        contract = Path(argv[3]) if len(argv) == 4 else DEFAULT_CONTRACT_PATH
        report = check_relevant_findings_bullet_list(Path(argv[2]), contract)
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "strengths_quality":
        if len(argv) != 3:
            print("usage: qa_checks.py strengths_quality <threat-model.md>", file=sys.stderr)
            return 2
        report = check_strengths_row_quality(Path(argv[2]))
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    if sub == "validation_approach_first":
        if len(argv) not in (3, 4):
            print("usage: qa_checks.py validation_approach_first <threat-model.md> [<contract.yaml>]", file=sys.stderr)
            return 2
        contract = Path(argv[3]) if len(argv) == 4 else DEFAULT_CONTRACT_PATH
        report = check_validation_approach_first(Path(argv[2]), contract)
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if not report.issues else 1
    print(f"unknown subcommand: {sub}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
