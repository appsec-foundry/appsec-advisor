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
    qa_checks.py all           <threat-model.md> <repo-root>

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
    # Both `**Total: N**` and `**Total findings: N**` accepted.
    + _DELIM
    + r"\**Total(?:\s+findings)?:\s*(\d+)\**"
)
STRIDE_COVERAGE_RE = re.compile(
    r"\*\*STRIDE Coverage:\*\*\s*"
    r"Spoofing:\s*(\d+)"
    + _DELIM
    + r"Tampering:\s*(\d+)"
    + _DELIM
    + r"Repudiation:\s*(\d+)"
    + _DELIM
    + r"Information Disclosure:\s*(\d+)"
    + _DELIM
    + r"Denial of Service:\s*(\d+)"
    + _DELIM
    + r"Elevation of Privilege:\s*(\d+)"
)
SECTION_8_SUB_RE = re.compile(r"^###\s+8\.([1-4])\s+(Critical|High|Medium|Low)\s*\((\d+)\)", re.MULTILINE)
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


def _strip_code_fences(text: str) -> str:
    """Return ``text`` with fenced code blocks blanked out (same length)."""
    out: list[str] = []
    in_fence = False
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence:
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
                cls._contract = _yaml.safe_load(contract_path.read_text(encoding="utf-8")) or {}
            except (OSError, _yaml.YAMLError):
                cls._contract = {}
        return cls._contract


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
        report.issues.append(f"orphaned-threat-ref: {tid} referenced but no Threat Register row")
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
        # Threat Register rows: inject <a id="t-nnn"></a> before T-NNN
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

        data = _yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
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
        # Skip the Threat Register ID-column rows in Section 8 — they are anchor sources.
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
            new_line = re.sub(
                r"\[([FTM]-\d{3,4})\]\(#[ftm]-\d+\)(?! — )",
                sub_existing,
                new_line,
            )
            new_line = re.sub(
                r"\[(TH-\d{2,3})\]\(#th-\d+\)(?! — )",
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


def check_invariants(md_path: Path) -> Report:
    report = Report("invariants")
    text = md_path.read_text(encoding="utf-8")
    rd = RISK_DIST_RE.search(text)
    if not rd:
        report.issues.append("Risk Distribution line not found")
    else:
        crit, high, med, low, total = (int(x) for x in rd.groups())
        if crit + high + med + low != total:
            report.issues.append(
                f"Risk Distribution sum mismatch: {crit}+{high}+{med}+{low}={crit + high + med + low} != Total {total}"
            )
        sub_counts = {int(m.group(1)): int(m.group(3)) for m in SECTION_8_SUB_RE.finditer(text)}
        for idx, (label, n) in enumerate((("Critical", crit), ("High", high), ("Medium", med), ("Low", low)), start=1):
            declared = sub_counts.get(idx)
            if declared is not None and declared != n:
                report.issues.append(f"Section 8.{idx} heading count ({declared}) != Risk Distribution {label} ({n})")
    sc = STRIDE_COVERAGE_RE.search(text)
    if not sc:
        report.issues.append("STRIDE Coverage line not found")
    elif rd:
        s_sum = sum(int(x) for x in sc.groups())
        total = int(rd.group(5))
        if s_sum != total:
            report.issues.append(f"STRIDE Coverage sum ({s_sum}) != Threat Register Total ({total})")

    # F4 — PHASE_BURST detection (moved here from phase-group-architecture.md
    # auto-repair block, which is skipped on inline-shortcut runs). Inspects
    # .agent-run.log for >3 distinct PHASE_START lines sharing the same
    # timestamp. The Phases 5+6+7 batch is legal (3 phases, by design); 4+
    # is a contract violation (look-ahead logging — see 2026-04-25 Run 1
    # where the orchestrator emitted PHASE_STARTs for Phases 3-8 in a single
    # second before doing any work).
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
            if len(phases) > 3:
                report.issues.append(
                    f"PHASE_BURST at {ts}: {len(phases)} distinct PHASE_START lines "
                    f"(phases {sorted(phases)}) — only 5+6+7 may legally share a "
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
    "Top Findings",
    "Architecture Assessment",
    "Mitigations",
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
_CRITICAL_CHAIN_RE = re.compile(r"^##\s+Critical Attack Chain\s*$", re.MULTILINE)


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
        * Missing `## Critical Attack Chain` section after MS when ≥2 Criticals.
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
    _LEGACY_RENAMES: dict[str, str] = {
        "Top Threats": "Top Findings",
        "Top Critical Findings": "Top Findings",
        "Top Risks": "Top Findings",
        "Critical Findings": "Top Findings",
        "Key Strengths": "Operational Strengths",
        "Follow-up Actions": "Mitigations",
        "Recommended Priority Actions": "Mitigations",
        "Immediate Actions": "Mitigations",
        "Immediate Actions Required": "Mitigations",
        "Immediate Actions Required (P1)": "Mitigations",
        "Risk Distribution": None,  # forbidden — strip entire heading
        "STRIDE Coverage": None,  # forbidden — strip entire heading
        "Critical Attack Chain": None,  # must be ## (promoted), not ### inside MS
        "Overall Security Rating": None,  # Verdict already carries the rating
        "Executive Overview": "Verdict",  # narrative-only → rename, body usually works as Verdict prose
        "Top Threats by Risk": "Top Findings",
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

    # --- Check 4: Attack Chain Overview is present.
    # Canonical layout places the chain overview as `### 3.1 Attack Chain
    # Overview` inside §3 (not as a standalone `## Critical Attack Chain`
    # section). Accept either form for backward compatibility.
    # Skipped when .skill-config.json sets SKIP_ATTACK_WALKTHROUGHS=true —
    # in that case a skip-notice stub is intentional and no chain is expected.
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
    has_chain = _CRITICAL_CHAIN_RE.search(text) or re.search(r"^###\s+3\.1\s+Attack Chain Overview", text, re.MULTILINE)
    if critical_count >= 2 and not has_chain and not _skip_walkthroughs:
        report.issues.append(
            "Attack Chain Overview missing — required when Critical count ≥ 2. "
            "Expected either `## Critical Attack Chain` (legacy) or "
            "`### 3.1 Attack Chain Overview` inside §3 (canonical)."
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
    table_checks = [
        ("top_findings", "Top Findings", "| # | Criticality | Pfad | Finding | Component | Primary Mitigations |"),
        ("architecture_assessment", "Architecture Assessment", "| Defect | Description | Key Findings |"),
        (
            "operational_strengths",
            "Operational Strengths",
            "| Architectural Control | Implementation | Effectiveness | Gap | Mitigates |",
        ),
        ("mitigations", "Prioritized Mitigations", "| ID | Mitigation | Component | Addresses | Effort |"),
    ]
    for _sid, label, expected_header in table_checks:
        if label in text and expected_header not in text:
            report.issues.append(f"{label} table does not match contract column schema (expected: {expected_header!r})")

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
    "threat_register": [".fragments/compound-chains.json", ".fragments/architectural-findings.json"],
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
    posture_report = check_security_posture_structure(md_path)
    compactness_report = check_diagram_compactness(md_path, contract_path)
    chain_compactness_report = check_chain_compactness(md_path, contract_path)
    chain_tid_report = check_chain_tid_consistency(md_path, output_dir)
    recon_iam_report = check_recon_iam_bridge(md_path, output_dir, contract_path)
    falls_short_report = check_falls_short_format(md_path, contract_path)
    mermaid_issues = list(mermaid_report.issues)
    toc_nested_issues = list(toc_nested_report.issues)
    infobox_issues = list(infobox_report.issues)
    auth_issues = list(auth_report.issues)
    posture_issues = list(posture_report.issues)
    compactness_issues = list(compactness_report.issues)
    chain_compactness_issues = list(chain_compactness_report.issues)
    chain_tid_issues = list(chain_tid_report.issues)
    recon_iam_issues = list(recon_iam_report.issues)
    falls_short_issues = list(falls_short_report.issues)
    report.issues.extend(mermaid_issues)
    report.issues.extend(toc_nested_issues)
    report.issues.extend(infobox_issues)
    report.issues.extend(auth_issues)
    report.issues.extend(posture_issues)
    report.issues.extend(compactness_issues)
    report.issues.extend(chain_compactness_issues)
    report.issues.extend(chain_tid_issues)
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
                    "Edit `.fragments/security-architecture.md` so §7.3 Identity "
                    "& Access Management has ONE `#### <method> Flow` sub-block "
                    "per row of the control table's `Control` column. Each "
                    "sub-block MUST contain (1) its own `sequenceDiagram`, and "
                    "(2) a bold `**Findings in this flow:**` trailer that cites "
                    "only T-IDs also listed in that row's `Linked Threats` cell. "
                    "If two table rows share a single flow (e.g. JWT Signing + "
                    "JWT Validation), either merge them into one row or declare "
                    "a synonym override in `data/sections-contract.yaml` under "
                    "`security_architecture.domain_required_rules`. "
                    "After editing, re-run compose_threat_model.py."
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
            or raw in posture_issues
            or raw in compactness_issues
            or raw in chain_compactness_issues
            or raw in chain_tid_issues
        ):
            continue
        action: dict = {"raw_issue": raw}
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

            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
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
    # Summary bullets — catches `**Gap summary:**` + inline `(1) … (2) …`
    # prose (no auto-fix; rewriting is a semantic task for the author).
    summary_report = check_summary_bullets(md)
    contract_report = check_contract(md)
    xref_report = check_xrefs(md)
    inv_report = check_invariants(md)
    # Check 7c-ext — requirement-sourced threats must carry Violated annotation.
    _check_requirements_violated_coverage(md, md.parent, inv_report)
    heading_report = check_heading_hygiene(md)
    toc_report = check_toc_closure(md)
    # New structural / rendering checks introduced to catch LLM-authored
    # defects that the contract gate alone does not notice (nested TOC
    # links, broken mermaid, thin metadata).
    mermaid_report = check_mermaid_syntax(md)
    toc_nested_report = check_toc_nested_links(md)
    infobox_report = check_infobox_completeness(md)
    # §7.3 IAM — per-auth-method decomposition (no-op when contract lacks rule).
    auth_report = check_auth_method_decomposition(md)
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
    # Fix (5): recon-to-IAM bridge — cross-validate recon TOTP/2FA signals
    # against §7.3 control table. No-op when recon summary absent.
    recon_iam_report = check_recon_iam_bridge(md, md.parent)
    # Fix (7): dense "Where it falls short." paragraphs — warning-only.
    falls_short_report = check_falls_short_format(md)
    # M1: evidence-integrity check — line in-range, not pure-noise,
    # absence-greps replayed. Reads .threats-merged.json (preferred) or
    # threat-model.yaml. No-op when neither is present.
    evidence_integrity_report = check_evidence_integrity(md.parent, repo_root)
    summary = {
        "links": link_report.as_dict(),
        "anchors": anchor_report.as_dict(),
        "ms_structure": ms_report.as_dict(),
        "cell_format": cell_report.as_dict(),
        "summary_bullets": summary_report.as_dict(),
        "contract": contract_report.as_dict(),
        "xrefs": xref_report.as_dict(),
        "invariants": inv_report.as_dict(),
        "heading_hygiene": heading_report.as_dict(),
        "toc_closure": toc_report.as_dict(),
        "mermaid_syntax": mermaid_report.as_dict(),
        "toc_nested_links": toc_nested_report.as_dict(),
        "infobox_completeness": infobox_report.as_dict(),
        "auth_method_decomposition": auth_report.as_dict(),
        "placeholders": placeholder_report.as_dict(),
        "yaml_md_consistency": yaml_md_report.as_dict(),
        "posture_structure": posture_report.as_dict(),
        "diagram_compactness": compactness_report.as_dict(),
        "chain_compactness": chain_compactness_report.as_dict(),
        "chain_tid_consistency": chain_tid_report.as_dict(),
        "recon_iam_bridge": recon_iam_report.as_dict(),
        "falls_short_format": falls_short_report.as_dict(),
        "evidence_integrity": evidence_integrity_report.as_dict(),
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


def check_heading_hygiene(md_path: Path) -> Report:
    """Flag headings that contain markdown-link expansion artefacts."""
    report = Report(check="heading_hygiene")
    text = _read_md_cleaned(md_path)
    for m in _HEADING_RE.finditer(text):
        heading_text = m.group("text")
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


def _github_slug(heading_text: str) -> str:
    """Mirror of compose_threat_model.py::_anchor_from_heading — kept here
    to keep qa_checks.py runtime-dependency-free.

    Canonical GitHub slug: lower-case, drop everything that is not word-char
    or whitespace or hyphen, collapse whitespace runs to single hyphen.
    Keeping in lock-step with the compose-side helper is critical — any
    drift causes false-positive `unresolved TOC anchor` reports.
    """
    h = heading_text.strip().lower()
    h = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", h)
    # Drop everything except word-char / whitespace / hyphen — matches
    # GitHub, MkDocs, GitLab, VS Code preview. The previous explicit
    # character allow-list missed `@`, `=`, `+`, `;`, `<`, `>`, `~`, `!`, `?`
    # producing slugs that did not match the rendered heading anchor.
    h = re.sub(r"[^\w\s-]", "", h)
    h = re.sub(r"\s+", "-", h).strip("-")
    h = re.sub(r"-+", "-", h).strip("-")
    return h


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


def check_mermaid_syntax(md_path: Path) -> Report:
    """Flag mermaid blocks with known-bad syntax patterns."""
    report = Report(check="mermaid_syntax")
    raw = md_path.read_text(encoding="utf-8")
    for block_idx, m in enumerate(_MERMAID_FENCE_RE.finditer(raw), start=1):
        body = m.group("body")
        line_offset = raw[: m.start()].count("\n") + 1  # 1-based line of ```mermaid
        # Heuristic: only lint sequenceDiagram/flowchart/graph blocks. Skip
        # other diagram types (gantt, erDiagram, journey, …) to avoid false
        # positives on syntaxes we do not model.
        first_line = body.splitlines()[0] if body else ""
        diagram_type = first_line.strip().split()[0] if first_line.strip() else ""
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
            if diagram_type == "sequenceDiagram":
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
                if m_alt:
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
    domain_title = "7.3 Identity & Access Management"
    rules = rules_map.get(domain_title) or []
    rule = next(
        (r for r in rules if isinstance(r, dict) and r.get("rule") == "auth_method_decomposition"),
        None,
    )
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
    hashes = "#" * heading_level

    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        report.issues.append(f"cannot read {md_path}: {e}")
        return _finalize_auth_report(report, enforcement)

    sec73_body = _extract_section_body(text, r"^###\s+7\.3\s+Identity\s*&\s*Access\s+Management\b")
    if sec73_body is None:
        # §7.3 absent — a different contract check flags missing sections, so
        # this rule stays silent and clean to avoid double-reporting.
        report.ok = 1
        return report

    table_rows = _parse_domain_controls_table(sec73_body, control_column=table_column)
    subsections = _parse_subsections(sec73_body, level=heading_level)

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
            if forbid.search(heading):
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

_T_ID_RE_LOCAL = re.compile(r"\bT-(\d{3,4})\b")


def _collect_threat_register_t_ids(text: str) -> set[str]:
    """Set of T-NNN IDs that have an `<a id="t-NNN"></a>` anchor under
    §8 Threat Register or appear as a row in the threat table.
    """
    body = _extract_section_body(text, r"^##\s+8\.\s+Threat\s+Register\b")
    if body is None:
        return set()
    out: set[str] = set()
    for m in re.finditer(r'<a id="t-(\d{3,4})"></a>', body):
        out.add(f"T-{m.group(1).zfill(3)}")
    for m in _T_ID_RE_LOCAL.finditer(body):
        out.add(f"T-{m.group(1).zfill(3)}")
    return out


def _collect_critical_high_t_ids(text: str) -> set[str]:
    """T-IDs whose §8 row is rated Critical or High. The threat table
    column ordering is `| ID | ... | Severity | ...`; we scan for
    `🔴` (Critical) and `🟠` (High) emoji which the renderer always
    emits in the severity cell of the per-tier 8.B/8.C tables.
    """
    body = _extract_section_body(text, r"^##\s+8\.\s+Threat\s+Register\b")
    if body is None:
        return set()
    out: set[str] = set()
    # Each row containing 🔴 or 🟠 is critical/high. The T-NNN appears
    # in the ID column at the row's start.
    for line in body.splitlines():
        if "🔴" in line or "🟠" in line:
            for m in _T_ID_RE_LOCAL.finditer(line):
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
            report.issues.append(f"§{heading}: cites {tid} but no matching entry in §8 Threat Register")

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
      * Each chain MUST cite ≥1 T-NNN that exists in §8 Threat Register
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
                        f"§{heading} chain {idx}: cites {tid} but no matching entry in §8 Threat Register"
                    )


def check_recon_iam_bridge(
    md_path: Path,
    output_dir: Path,
    contract_path: Path = DEFAULT_CONTRACT_PATH,
) -> Report:
    """Fix (5): cross-validate recon signals against the §7.3 IAM control table.

    If the recon summary contains TOTP/2FA signals (totpSecret, routes/2fa,
    otplib, /rest/2fa, totp_token_required) but the §7.3 control table has
    no row matching a 2fa/totp/mfa whitelist token, flag it as an error.

    This closes the gap where routes/2fa.ts is found by recon but never
    surfaces in .security-controls.json, causing TOTP to be silently absent
    from §7.3 and the auth_method_decomposition rule to never fire.
    """
    report = Report("recon_iam_bridge")
    contract = _read_contract(contract_path)
    if not contract:
        return report

    sec = (contract.get("sections") or {}).get("security_architecture") or {}
    rules_map = sec.get("domain_required_rules") or {}
    bridge_rules = [
        r
        for r in (rules_map.get("7.3 Identity & Access Management") or [])
        if isinstance(r, dict) and r.get("rule") == "recon_iam_bridge"
    ]
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

    for rule in bridge_rules:
        enforcement = (rule.get("enforcement") or "warning").strip().lower()
        signal_patterns = rule.get("recon_signal_patterns") or []
        required_tokens = rule.get("required_iam_tokens") or []

        # Check if any recon signal fires.
        recon_hit = any(pat in recon_text for pat in signal_patterns if pat)
        if not recon_hit:
            continue  # No signal in recon — rule does not apply.

        # Signal present: verify at least one matching row in §7.3 table.
        sec73_body = _extract_section_body(md_text, r"^###\s+7\.3\s+Identity\s*&\s*Access\s+Management\b")
        if sec73_body is None:
            continue  # §7.3 absent — different check flags this.

        table_rows = _parse_domain_controls_table(sec73_body, control_column="Control")
        row_names = [(row.get("Control") or "").lower() for row in table_rows]
        found = any(tok in name for name in row_names for tok in required_tokens)
        if not found:
            signals_found = [p for p in signal_patterns if p in recon_text]
            issue = (
                f"§7.3 IAM: recon summary contains 2FA/TOTP signals "
                f"({signals_found}) but §7.3 control table has no row "
                f"matching tokens {required_tokens}. "
                f"Add a TOTP/2FA row to the §7.3 control table and a "
                f"#### 7.3.N TOTP Second-Factor Flow sub-section."
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
        ydata = _yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
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
    r"\|\s*\[(?:F|T)-(\d{3,4})\]"  # form 1: markdown-link
    r"|"
    r"\|\s*<a\s+id=\"[ft]-(\d{3,4})\">"  # form 2: anchor-tag (no link wrap)
    r")",
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
        yaml_data = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
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

            for asset in assets:
                aid = str(asset.get("id") or "")
                if not aid:
                    continue
                yaml_lt = {str(t).upper() for t in (asset.get("linked_threats") or [])}
                md_lt = md_asset_lt.get(aid, set())
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
# (compound-chains.json, architectural-findings.json, requirements-
# compliance.md, out-of-scope.md) are skipped because they depend on run
# configuration and on threat counts.
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
    """Validate the Security Posture at a Glance section against
    contract v2 invariants (D / E / C / F / G / N / B / L) declared in
    `data/sections-contract.yaml > security_posture_at_a_glance.invariants`.

    Contract v2 (2026-04) layout: 4-column Mermaid heatmap with
    explicit attack arrows + dashed consequence arrows + cross-subgraph
    header-alignment edges, followed by 1–7 numbered attack-class
    bullets each carrying Findings / optional Architectural-root-cause /
    optional Attack-chain / Impact (comma-sep) sub-elements.

    Categories:
      D1–D6  Diagram structure (mermaid block, subgraphs, direction)
      E1–E4  Edge structure (alignment, attack arrows, consequence, linkStyle)
      C1–C3  Card label structure (br count, tier-card content, HTML allowed)
      F1–F3  Column population (HDR + content cards per column)
      G1–G3  Glyph consistency (uniqueness, order, diagram↔bullets)
      N1–N4  Narrative below the diagram (intro, actor bullets, attack-paths header)
      B1–B5  Per-attack-class bullet structure
      L1–L3  Linking format for F-NNN / AF-NNN / chain-N
    """
    report = Report("posture_structure")
    text = md_path.read_text(encoding="utf-8")

    sec_start = text.find("### Security Posture at a Glance")
    if sec_start < 0:
        report.ok = 1
        return report
    sec_end = text.find("\n### ", sec_start + 1)
    if sec_end < 0:
        sec_end = text.find("\n## ", sec_start + 1)
    if sec_end < 0:
        sec_end = len(text)
    section = text[sec_start:sec_end]

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
        if not in_relay and "==>" in ln and re.search(r'\|\s*"?\s*[①②③④⑤⑥⑦]', ln):
            attack_lines.append(ln)
    if not (1 <= len(attack_lines) <= 7):
        report.issues.append(f"E2: expected 1–7 attack arrows with ① ⑦ labels, found {len(attack_lines)}")
    expected_glyphs = ["①", "②", "③", "④", "⑤", "⑥", "⑦"][: len(attack_lines)]
    actual_glyphs: list[str] = []
    for ln in attack_lines:
        m = re.search(r'\|\s*"?\s*([①②③④⑤⑥⑦])', ln)
        if m:
            actual_glyphs.append(m.group(1))
    if actual_glyphs != expected_glyphs:
        report.issues.append(f"E2/G2: attack-arrow glyph order must be ① ② … without gaps — got {actual_glyphs!r}")

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

    # ---- N-rules: narrative section below the diagram ----------------------
    # N1: `**Threat actors.**` intro paragraph.
    if "**Threat actors.**" not in after_mermaid:
        report.issues.append("N1: missing `**Threat actors.**` intro paragraph below the diagram")
    # N2: ≥1 actor bullet `- **<Actor Name>**`.
    actor_bullets = re.findall(r"^- \*\*[^*]+\*\* —", after_mermaid, re.MULTILINE)
    if len(actor_bullets) < 1:
        report.issues.append(f"N2: expected ≥1 actor bullet `- **<Actor Name>** — …`, found {len(actor_bullets)}")
    # N3: `**Attack paths (numbered arrows in the diagram):**` header.
    if "**Attack paths (numbered arrows in the diagram):**" not in after_mermaid:
        report.issues.append("N3: missing `**Attack paths (numbered arrows in the diagram):**` header")
    # N4: 1–7 attack-class bullets. The renderer prefixes each bullet with an
    # `<a id="path-…"></a>` anchor for cross-references (`[Path ①](#path-…)`),
    # so the optional non-capturing group accepts both forms.
    class_bullets = re.findall(
        r'^- (?:<a id="[^"]+"></a>)?\*\*([①②③④⑤⑥⑦])\s+([^*]+?)\*\*',
        after_mermaid,
        re.MULTILINE,
    )
    if not (1 <= len(class_bullets) <= 7):
        report.issues.append(f"N4: expected 1–7 attack-class bullets, found {len(class_bullets)}")
    # G3: every glyph used in attack arrows appears as a bullet.
    bullet_glyphs = [g for g, _ in class_bullets]
    arrow_glyph_set = set(actual_glyphs)
    if arrow_glyph_set and arrow_glyph_set != set(bullet_glyphs):
        report.issues.append(f"G3: arrow glyphs {arrow_glyph_set} ≠ attack-class bullet glyphs {set(bullet_glyphs)}")

    # ---- B-rules: per-attack-class bullet structure ------------------------
    # Slice out each bullet block (from a class-bullet header up to the next
    # one or the end of after_mermaid) and run sub-bullet checks.
    bullet_starts = [
        m.start()
        for m in re.finditer(
            r'^- (?:<a id="[^"]+"></a>)?\*\*[①②③④⑤⑥⑦]\s',
            after_mermaid,
            re.MULTILINE,
        )
    ]
    bullet_starts.append(len(after_mermaid))
    for i in range(len(bullet_starts) - 1):
        block = after_mermaid[bullet_starts[i] : bullet_starts[i + 1]]
        # B1: bullet header format `- **<glyph> <class>** (<actor> → <target>) — <description>`.
        # Anchor prefix `<a id="path-…"></a>` between the dash and `**` is
        # tolerated (renderer-injected for cross-refs).
        first_line = block.splitlines()[0] if block else ""
        if not re.match(
            r'- (?:<a id="[^"]+"></a>)?\*\*[①②③④⑤⑥⑦] [^*]+?\*\*\s+\([^)]+→[^)]+\)\s+—',
            first_line,
        ):
            report.issues.append(f"B1: attack-class bullet header malformed: {first_line[:120]!r}")
        # B2: Findings sub-bullet exists and has ≥1 finding link.
        # Sprint 2A (M3.5): the renderer historically emitted F-NNN links
        # ([F-001](#f-001)) but switched to T-NNN ([T-001](#t-001)) once
        # threat-IDs became the canonical addressable identifier in
        # threat-model.yaml. The checker accepts both — drift here would
        # produce a long tail of false-positive B2 violations every run
        # (the 2026-04-27 juice-shop run hit 7 of them, blocking a clean
        # contract-pass until we generalised the regex).
        if "  - Findings:" not in block:
            report.issues.append(f"B2: attack-class bullet missing `Findings:` sub-bullet — {first_line[:80]!r}")
        finding_links_in_block = re.findall(
            r"\[(F|T)-\d+\]\(#(f|t)-\d+\)",
            block,
        )
        if len(finding_links_in_block) < 1:
            report.issues.append(f"B2: attack-class bullet has no F-NNN/T-NNN link — {first_line[:80]!r}")
        # B3: `Impact:` line, comma-separated.
        if not re.search(r"^\s*-\s*Impact:\s+\S", block, re.MULTILINE):
            report.issues.append(f"B3: attack-class bullet missing `Impact:` line — {first_line[:80]!r}")

    # ---- L-rules: link format ----------------------------------------------
    # L1: every finding link in the narrative is `[F-NNN](#f-nnn)` or
    # `[T-NNN](#t-nnn)` (ID-only) and is followed by ` — Title`. Accept both
    # prefixes for the same Sprint 2A reason as B2 above.
    for m in re.finditer(
        r"^    - \[(F|T)-(\d+)\]\(#(?:f|t)-\d+\)(\s+—\s+\S[^\n]*)?",
        after_mermaid,
        re.MULTILINE,
    ):
        if not m.group(3):
            report.issues.append(f"L1: Findings sub-bullet {m.group(1)}-{m.group(2)} missing ` — Title` after the link")
    # L2: AF-NNN sub-bullets follow the same shape.
    for m in re.finditer(r"^    - \[AF-(\d+)\]\(#af-\d+\)(\s+—\s+\S[^\n]*)?", after_mermaid, re.MULTILINE):
        if not m.group(2):
            report.issues.append(f"L2: Architectural-root-cause sub-bullet AF-{m.group(1)} missing ` — Title`")
    # L3: chain-N sub-bullets resolve to `<a id="chain-N">` anchors.
    for m in re.finditer(r"\[Chain\s+(\d+)\]\(#chain-(\d+)\)", after_mermaid):
        n_label, n_anchor = m.group(1), m.group(2)
        if n_label != n_anchor:
            report.issues.append(
                f"L3: Attack-chain link mismatch — label says Chain {n_label} but anchor is #chain-{n_anchor}"
            )

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
    print(f"unknown subcommand: {sub}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
