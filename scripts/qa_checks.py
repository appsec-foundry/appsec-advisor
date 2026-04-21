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
    qa_checks.py contract      <threat-model.md> [<sections-contract.yaml>]
    qa_checks.py repair_plan   <threat-model.md> <output-dir> [<sections-contract.yaml>]
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

VSCODE_LINK_RE = re.compile(r"vscode://file/([^)\s]+?)(?::(\d+))?(?=[)\s])")
T_ID_RE = re.compile(r"\bT-(\d{3,4})\b")
M_ID_RE = re.compile(r"\bM-(\d{3,4})\b")
TABLE_ID_RE = re.compile(r"^\|\s*(?:<a id=\"[tm]-\d+\"></a>)?\s*([TM]-\d+)\s*\|", re.MULTILINE)
H3_MITIGATION_RE = re.compile(r"^###\s.*?\bM-(\d{3,4})\b", re.MULTILINE)
# Risk Distribution / STRIDE Coverage regexes are deliberately lenient:
# - severity emojis (🔴 🟠 🟡 🟢) may or may not prefix each label
# - the delimiter between entries may be `·`, `|`, or plain whitespace
# - "Total" may be wrapped in `**…**` or appear as plain text
_SEV_ICON = r"(?:[🔴🟠🟡🟢⚪])?\s*"
_DELIM    = r"\s*[·\|]\s*"
RISK_DIST_RE = re.compile(
    r"\*\*Risk Distribution:\*\*\s*"
    + _SEV_ICON + r"Critical:\s*(\d+)"
    + _DELIM    + _SEV_ICON + r"High:\s*(\d+)"
    + _DELIM    + _SEV_ICON + r"Medium:\s*(\d+)"
    + _DELIM    + _SEV_ICON + r"Low:\s*(\d+)"
    # Both `**Total: N**` and `**Total findings: N**` accepted.
    + _DELIM    + r"\**Total(?:\s+findings)?:\s*(\d+)\**"
)
STRIDE_COVERAGE_RE = re.compile(
    r"\*\*STRIDE Coverage:\*\*\s*"
    r"Spoofing:\s*(\d+)"                    + _DELIM +
    r"Tampering:\s*(\d+)"                   + _DELIM +
    r"Repudiation:\s*(\d+)"                 + _DELIM +
    r"Information Disclosure:\s*(\d+)"      + _DELIM +
    r"Denial of Service:\s*(\d+)"           + _DELIM +
    r"Elevation of Privilege:\s*(\d+)"
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
        matches = [p for p in repo_root.rglob(basename)
                   if not any(part in {"node_modules", ".git", "vendor", "dist", "build"}
                              for part in p.parts)]
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
            report.issues.append(
                f"ambiguous: {basename} has {len(matches)} candidates"
            )
        else:
            report.issues.append(f"missing: {raw_path}")
    return report, new_text


def check_xrefs(md_path: Path) -> Report:
    report = Report("xrefs")
    text = md_path.read_text(encoding="utf-8")
    stripped = _strip_code_fences(text)
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
            m = re.match(r'^(\|\s*)(T-(\d{3,4}))(\s*\|)', line)
            if m and '<a id="t-' not in line:
                tid_lower = f"t-{m.group(3).zfill(3)}"
                anchor = f'<a id="{tid_lower}"></a>'
                lines[i] = f"{m.group(1)}{anchor} {m.group(2)}{line[m.end(2):]}"
                injected += 1
        # Mitigation headings: inject <a id="m-nnn"></a> before ### M-NNN
        if (in_section_10 or line.startswith("### ")) and not in_section_8:
            m = re.match(r'^(###\s+)(M-(\d{3,4}))\b', line)
            if m and '<a id="m-' not in line:
                mid_lower = f"m-{m.group(3).zfill(3)}"
                anchor = f'<a id="{mid_lower}"></a>'
                lines[i] = f"{m.group(1)}{anchor} {m.group(2)}{line[m.end(2):]}"
                injected += 1
    return lines, injected


def linkify_anchors(md_path: Path) -> tuple[Report, str]:
    report = Report("anchors")
    text = md_path.read_text(encoding="utf-8")
    # Track fence state line-by-line so we skip code blocks.
    lines = text.splitlines(keepends=True)

    # Pass 1: inject destination anchors into table rows and headings
    lines, anchor_count = _inject_row_anchors(lines)
    if anchor_count:
        report.fixes.append(f"injected {anchor_count} row/heading anchors")

    # Pass 2: linkify bare T-NNN / M-NNN references
    in_fence = False
    in_section_8 = False
    for i, line in enumerate(lines):
        stripped_lstrip = line.lstrip()
        if stripped_lstrip.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if line.startswith("## "):
            in_section_8 = line.startswith("## 8.") or line.startswith("## 8 ")
        # Skip the Threat Register ID-column rows in Section 8 — they are anchor sources.
        if in_section_8 and line.startswith("|") and re.search(r"^\|\s*(?:<a id=\"t-\d+\"></a>)?\s*T-\d+\s*\|", line):
            continue
        new_line = line
        # Linkify bare T-NNN not already part of a link or an anchor.
        def sub_t(match: re.Match[str]) -> str:
            full = match.group(0)
            start = match.start()
            prefix = new_line[max(0, start - 2):start]
            suffix = new_line[match.end():match.end() + 2]
            if prefix.endswith("[") or suffix.startswith("]("):
                return full
            if "<a id=\"t-" in new_line[max(0, start - 30):start + 10]:
                return full
            return f"[{full}](#{_lowercase_anchor('T', match.group(1))})"

        def sub_m(match: re.Match[str]) -> str:
            full = match.group(0)
            start = match.start()
            prefix = new_line[max(0, start - 2):start]
            suffix = new_line[match.end():match.end() + 2]
            if prefix.endswith("[") or suffix.startswith("]("):
                return full
            if "<a id=\"m-" in new_line[max(0, start - 30):start + 10] or new_line.startswith("### "):
                return full
            return f"[{full}](#{_lowercase_anchor('M', match.group(1))})"

        new_line = T_ID_RE.sub(sub_t, new_line)
        new_line = M_ID_RE.sub(sub_m, new_line)
        if new_line != line:
            diff_count = new_line.count("](#t-") - line.count("](#t-") + new_line.count("](#m-") - line.count("](#m-")
            if diff_count:
                report.fixes.append(f"line {i + 1}: +{diff_count} cross-links")
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
                f"Risk Distribution sum mismatch: {crit}+{high}+{med}+{low}={crit+high+med+low} != Total {total}"
            )
        sub_counts = {int(m.group(1)): int(m.group(3)) for m in SECTION_8_SUB_RE.finditer(text)}
        for idx, (label, n) in enumerate((("Critical", crit), ("High", high), ("Medium", med), ("Low", low)), start=1):
            declared = sub_counts.get(idx)
            if declared is not None and declared != n:
                report.issues.append(
                    f"Section 8.{idx} heading count ({declared}) != Risk Distribution {label} ({n})"
                )
    sc = STRIDE_COVERAGE_RE.search(text)
    if not sc:
        report.issues.append("STRIDE Coverage line not found")
    elif rd:
        s_sum = sum(int(x) for x in sc.groups())
        total = int(rd.group(5))
        if s_sum != total:
            report.issues.append(
                f"STRIDE Coverage sum ({s_sum}) != Threat Register Total ({total})"
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
        report.issues.append(
            "Management Summary heading '## Management Summary' is missing — rerun Phase 11 Part A"
        )
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
        "Risk Distribution": None,          # forbidden — strip entire heading
        "STRIDE Coverage": None,            # forbidden — strip entire heading
        "Critical Attack Chain": None,      # must be ## (promoted), not ### inside MS
        "Overall Security Rating": None,    # Verdict already carries the rating
        "Executive Overview": "Verdict",    # narrative-only → rename, body usually works as Verdict prose
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
        report.fixes.append(f"Stripped {legacy_stripped} forbidden MS sub-section heading(s) (Risk Distribution / STRIDE Coverage / etc.)")

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
            report.issues.append(
                f"Management Summary missing required sub-section '### {required}' — rerun required"
            )

    # --- Check 2: order of the required sub-sections matches canonical order.
    if all(r in names for r in _MS_REQUIRED_SUBSECTIONS):
        observed = [n for n in names if n in _MS_REQUIRED_SUBSECTIONS]
        if observed != list(_MS_REQUIRED_SUBSECTIONS):
            report.issues.append(
                f"Management Summary sub-section order is {observed}, "
                f"expected {list(_MS_REQUIRED_SUBSECTIONS)}"
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
                "style=\"border-left: 3px solid #dc2626; …\"> worst-case-scenarios block"
            )

    # --- Check 4: Attack Chain Overview is present.
    # Canonical layout places the chain overview as `### 3.1 Attack Chain
    # Overview` inside §3 (not as a standalone `## Critical Attack Chain`
    # section). Accept either form for backward compatibility.
    rd = RISK_DIST_RE.search(text)
    critical_count = int(rd.group(1)) if rd else 0
    has_chain = (
        _CRITICAL_CHAIN_RE.search(text)
        or re.search(r"^###\s+3\.1\s+Attack Chain Overview", text, re.MULTILINE)
    )
    if critical_count >= 2 and not has_chain:
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
         declared headers (Top Findings: 7 cols; Architecture Assessment:
         3 cols; Operational Strengths: 5 cols; Mitigations sub-tables:
         5 cols each).
    """
    import yaml as _yaml

    report = Report("contract")
    try:
        contract = _yaml.safe_load(contract_path.read_text(encoding="utf-8")) or {}
    except (OSError, _yaml.YAMLError) as e:
        report.issues.append(f"cannot read contract: {e}")
        return report
    if not isinstance(contract, dict):
        report.issues.append(f"contract is not a mapping: {contract_path}")
        return report

    text = md_path.read_text(encoding="utf-8")

    # 1. Section order + presence.
    rd = RISK_DIST_RE.search(text)
    critical_count = int(rd.group(1)) if rd else 0
    env = {
        "critical_count":      critical_count,
        "high_count":          int(rd.group(2)) if rd else 0,
        "medium_count":        int(rd.group(3)) if rd else 0,
        "low_count":           int(rd.group(4)) if rd else 0,
        "check_requirements":  False,
        "verbose_report":      False,           # matches renderer default (meta flag off)
        "triage_has_warnings": False,
        "has_out_of_scope":    True,
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
        idx = stripped_text.find(heading + "\n")
        if idx < 0:
            idx = stripped_text.find(heading)
        if idx < 0:
            report.issues.append(f"expected section missing: {heading!r}")
            continue
        if idx < last_idx:
            report.issues.append(
                f"section order violation — {heading!r} appears before a section "
                "that should come later"
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
                    report.issues.append(
                        f"forbidden MS heading matches /{pat}/: {title!r}"
                    )

    # 3. Required table column schemas.
    table_checks = [
        ("top_findings", "Top Findings",
         "| # | Criticality | Finding | Component | Threat | Vektor | Primary Mitigations |"),
        ("architecture_assessment", "Architecture Assessment",
         "| Defect | Description | Key Findings |"),
        ("operational_strengths", "Operational Strengths",
         "| Architectural Control | Implementation | Effectiveness | Gap | Mitigates |"),
        ("mitigations", "Prioritized Mitigations",
         "| ID | Mitigation | Component | Addresses | Effort |"),
    ]
    for _sid, label, expected_header in table_checks:
        if label in text and expected_header not in text:
            report.issues.append(
                f"{label} table does not match contract column schema "
                f"(expected: {expected_header!r})"
            )

    if not report.issues:
        report.ok = 1
    return report


def _safe_eval_cond(expr: str, env: dict) -> bool:
    """Evaluate a contract condition safely (mirrors compose_threat_model.eval_condition)."""
    if not expr:
        return False
    safe = re.fullmatch(r"[\sA-Za-z0-9_\.\(\)\[\]'\",<>=!&|+\-]*", expr)
    if not safe:
        return False
    try:
        return bool(eval(expr, {"__builtins__": {}}, dict(env)))  # noqa: S307
    except Exception:
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
    "infobox":                 [],                                  # from yaml
    "changelog":               [],                                  # from yaml
    "toc":                     [],                                  # computed
    "management_summary":      [],                                  # container only
    "verdict":                 [".fragments/ms-verdict.json"],
    "top_findings":            [],                                  # computed
    "architecture_assessment": [".fragments/ms-architecture-assessment.json"],
    "mitigations":             [],                                  # computed
    "operational_strengths":   [".fragments/operational-strengths-overrides.json"],
    "system_overview":         [".fragments/system-overview.md"],
    "architecture_diagrams":   [".fragments/architecture-diagrams.md"],
    "attack_walkthroughs":     [".fragments/attack-walkthroughs.md"],
    "assets":                  [".fragments/assets.md"],
    "attack_surface":          [".fragments/attack-surface.md"],
    "security_architecture":   [".fragments/security-architecture.md"],
    "requirements_compliance": [".fragments/requirements-compliance.md"],
    "threat_register":         [".fragments/compound-chains.json",
                                ".fragments/architectural-findings.json"],
    "mitigation_register":     [],                                  # from yaml mitigations[]
    "out_of_scope":            [".fragments/out-of-scope.md"],
    "appendix_run_statistics": [],                                  # from yaml meta
    "appendix_vektor_taxonomy":[],                                  # from plugin data
}


# Label → contract section id mapping for table-schema-drift issues
# (Top Findings / Architecture Assessment / Operational Strengths /
# Prioritized Mitigations). Used to point the orchestrator at the
# correct fragment when a column schema does not match.
_TABLE_LABEL_TO_SECTION: dict[str, str] = {
    "Top Findings":              "top_findings",
    "Architecture Assessment":   "architecture_assessment",
    "Operational Strengths":     "operational_strengths",
    "Prioritized Mitigations":   "mitigations",
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
    import yaml as _yaml

    report = check_contract(md_path, contract_path)
    try:
        contract = _yaml.safe_load(contract_path.read_text(encoding="utf-8")) or {}
    except (OSError, _yaml.YAMLError):
        contract = {}

    # Structural / rendering checks that sit alongside the contract gate.
    # Their issues are appended to ``report.issues`` so the Re-Render Loop
    # fires for them as well, and each check type has its own action branch
    # below with targeted remediation instructions.
    mermaid_report = check_mermaid_syntax(md_path)
    toc_nested_report = check_toc_nested_links(md_path)
    infobox_report = check_infobox_completeness(md_path)
    mermaid_issues = list(mermaid_report.issues)
    toc_nested_issues = list(toc_nested_report.issues)
    infobox_issues = list(infobox_report.issues)
    report.issues.extend(mermaid_issues)
    report.issues.extend(toc_nested_issues)
    report.issues.extend(infobox_issues)

    actions: list[dict] = []
    # One action per mermaid-syntax finding. The offending fragment is almost
    # always `.fragments/attack-walkthroughs.md` (sequence diagrams) or
    # `.fragments/architecture-diagrams.md` (flowchart/graph). Pointing at
    # both lets the orchestrator choose based on the block index / line.
    for raw in mermaid_issues:
        actions.append({
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
        })
    # One action per TOC-nested-link issue. The offending label always lives
    # in a `### ` heading inside `.fragments/attack-walkthroughs.md` (that is
    # the only fragment whose subsections drive the §3 TOC via prose-scan).
    # Re-rendering the fragment fixes both the heading and the TOC.
    for raw in toc_nested_issues:
        actions.append({
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
        })
    # Single action for infobox thinness — the only remedy is source
    # enrichment (yaml `project:` block or repo manifest/LICENSE/README).
    if infobox_issues:
        actions.append({
            "raw_issue": "; ".join(infobox_issues),
            "type": "infobox_incomplete",
            "section_id": "infobox",
            "fragments_to_rewrite": [],   # data_source: threat-model.yaml#project
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
        })

    for raw in report.issues:
        # Skip issues already consumed above (added by mermaid / TOC / infobox
        # branches) so we do not emit both a structural action and an
        # "unclassified" action for the same violation.
        if raw in mermaid_issues or raw in toc_nested_issues or raw in infobox_issues:
            continue
        action: dict = {"raw_issue": raw}
        # expected section missing: '<heading>'
        m = re.match(r"expected section missing: ['\"](.+?)['\"]$", raw)
        if m:
            heading = m.group(1)
            sid = _heading_to_section_id(heading, contract)
            action.update({
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
            })
            actions.append(action)
            continue
        # section order violation — '<heading>' appears before a section that should come later
        m = re.match(r"section order violation — ['\"](.+?)['\"]", raw)
        if m:
            heading = m.group(1)
            sid = _heading_to_section_id(heading, contract)
            action.update({
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
            })
            actions.append(action)
            continue
        # forbidden MS heading matches /<pat>/: '<title>'
        m = re.match(r"forbidden MS heading matches /(.+?)/: ['\"](.+?)['\"]$", raw)
        if m:
            pat, title = m.group(1), m.group(2)
            action.update({
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
            })
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
            action.update({
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
            })
            actions.append(action)
            continue
        # unstructured issue — fall through with generic action
        action.update({
            "type": "unclassified",
            "remediation": (
                "See `raw_issue` for details. Re-run compose_threat_model.py "
                "and re-inspect; if the same issue reappears, escalate to the "
                "contract maintainer."
            ),
        })
        actions.append(action)

    plan: dict = {
        "generated":         _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "md_path":           str(md_path),
        "output_dir":        str(output_dir),
        "contract_path":     str(contract_path),
        "status":            "pass" if not report.issues else "fail",
        "issue_count":       len(report.issues),
        "actions":           actions,
        "re_render_command": (
            "python3 $CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py "
            "--output-dir $OUTPUT_DIR --strict"
        ),
    }
    return plan, report


def cmd_repair_plan(md_path: Path, output_dir: Path, contract_path: Path) -> int:
    """Run the contract check and write `.qa-repair-plan.json`.

    Exit codes:
      0 — no violations, no plan written
      1 — violations found, plan written (re-render required)
      2 — error (bad inputs, unreadable files)
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
    return 1


def cmd_all(md_path: Path, repo_root: Path) -> int:
    md = md_path.resolve()
    # Check 1 — links (apply in place).
    link_report, text_after_links = check_links(md, repo_root)
    if text_after_links != md.read_text(encoding="utf-8"):
        md.write_text(text_after_links, encoding="utf-8")
    # Check 10 — anchors (apply in place against the already-linkified text).
    anchor_report, text_after_anchors = linkify_anchors(md)
    if text_after_anchors != md.read_text(encoding="utf-8"):
        md.write_text(text_after_anchors, encoding="utf-8")
    # Check MS structure (apply safe rewrites in place).
    ms_report, text_after_ms = check_ms_structure(md)
    if text_after_ms != md.read_text(encoding="utf-8"):
        md.write_text(text_after_ms, encoding="utf-8")
    contract_report = check_contract(md)
    xref_report = check_xrefs(md)
    inv_report = check_invariants(md)
    heading_report = check_heading_hygiene(md)
    toc_report = check_toc_closure(md)
    # New structural / rendering checks introduced to catch LLM-authored
    # defects that the contract gate alone does not notice (nested TOC
    # links, broken mermaid, thin metadata).
    mermaid_report = check_mermaid_syntax(md)
    toc_nested_report = check_toc_nested_links(md)
    infobox_report = check_infobox_completeness(md)
    summary = {
        "links": link_report.as_dict(),
        "anchors": anchor_report.as_dict(),
        "ms_structure": ms_report.as_dict(),
        "contract": contract_report.as_dict(),
        "xrefs": xref_report.as_dict(),
        "invariants": inv_report.as_dict(),
        "heading_hygiene": heading_report.as_dict(),
        "toc_closure": toc_report.as_dict(),
        "mermaid_syntax": mermaid_report.as_dict(),
        "toc_nested_links": toc_nested_report.as_dict(),
        "infobox_completeness": infobox_report.as_dict(),
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
    text = _strip_code_fences(md_path.read_text(encoding="utf-8"))
    for m in _HEADING_RE.finditer(text):
        heading_text = m.group("text")
        # Unbalanced parens in the heading?
        if heading_text.count("(") != heading_text.count(")"):
            report.issues.append(
                f"unbalanced parentheses in heading: `{heading_text[:120]}`"
            )
            continue
        # Unclosed backticks?
        if heading_text.count("`") % 2 != 0:
            report.issues.append(
                f"unclosed backtick in heading: `{heading_text[:120]}`"
            )
            continue
        # More than one markdown link inside the heading?
        link_count = len(re.findall(r"\[[^\]]+\]\([^)]+\)", heading_text))
        if link_count > 1:
            report.issues.append(
                f"{link_count} markdown links in heading (max 1 allowed): "
                f"`{heading_text[:120]}`"
            )
            continue
        # A link followed by an em-dash + more text suggests the composer
        # expanded a `[T-NNN](#t-nnn)` with a label inside the heading.
        if re.search(r"\]\([^)]+\)\s*—", heading_text):
            report.issues.append(
                f"heading contains `[...]([...]) — <text>` expansion: "
                f"`{heading_text[:120]}`"
            )
            continue
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
    to keep qa_checks.py runtime-dependency-free."""
    h = heading_text.strip().lower()
    h = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", h)
    for ch in "—–,.()[]'\"&/:#":
        h = h.replace(ch, "")
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
        if slug.lower() in (a.lower() for a in anchors):
            report.ok += 1
            continue
        broken += 1
        if broken <= 25:  # cap the report payload
            report.issues.append(
                f"unresolved TOC/link anchor: #{slug}"
            )
    if broken > 25:
        report.issues.append(
            f"…and {broken - 25} more unresolved anchors (truncated)"
        )
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
        line_offset = raw[:m.start()].count("\n") + 1  # 1-based line of ```mermaid
        # Heuristic: only lint sequenceDiagram/flowchart/graph blocks. Skip
        # other diagram types (gantt, erDiagram, journey, …) to avoid false
        # positives on syntaxes we do not model.
        first_line = body.splitlines()[0] if body else ""
        diagram_type = first_line.strip().split()[0] if first_line.strip() else ""
        if diagram_type not in {"sequenceDiagram", "flowchart", "graph"}:
            continue

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
            is_note    = stripped.lower().startswith(("note ", "note over", "note left", "note right"))
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
        return [], (
            f"authoritative mermaid parse skipped — "
            f"{_MERMAID_VALIDATOR_JS} not found"
        )
    node_bin = shutil.which("node")
    if not node_bin:
        return [], (
            "authoritative mermaid parse skipped — node not on PATH"
        )

    blocks = list(_MERMAID_FENCE_RE.finditer(md_text))
    if not blocks:
        return [], None

    issues: list[str] = []
    # One subprocess call per block. Shell-out cost per block is ~150 ms in
    # practice (most of it mermaid+jsdom bootstrap), but we amortize nothing
    # because each block is a fresh parser context — intentional, since the
    # goal is to catch block-level failures in isolation. For typical
    # threat-model.md inputs (5–15 blocks) the whole layer runs in < 2 s.
    for idx, m in enumerate(blocks, start=1):
        body = m.group("body")
        line_offset = md_text[:m.start()].count("\n") + 1
        try:
            r = subprocess.run(
                [node_bin, str(_MERMAID_VALIDATOR_JS)],
                input=body,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            return issues, (
                f"authoritative mermaid parse skipped — node invocation "
                f"failed: {exc.__class__.__name__}"
            )

        # The script prints a single JSON line on stdout. Exit codes: 0 = ok,
        # 1 = parse error, 2 = environment error (mermaid/jsdom missing).
        out = (r.stdout or "").strip().splitlines()
        payload = out[-1] if out else ""
        try:
            result = _json.loads(payload) if payload else {}
        except _json.JSONDecodeError:
            # Treat as environment error — don't flag the diagram.
            return issues, (
                f"authoritative mermaid parse skipped — validator output "
                f"not parseable as JSON: {payload[:120]!r}"
            )

        if r.returncode == 2 or result.get("skipped"):
            # The validator told us it can't run (missing deps).
            return issues, (
                "authoritative mermaid parse skipped — "
                + (result.get("error") or "validator reported missing deps")
            )

        if r.returncode == 0 and result.get("ok"):
            continue

        # Parse error — extract a concise first line for the report.
        err = (result.get("error") or "").strip()
        err_head = err.splitlines()[0] if err else "unknown parse error"
        issues.append(
            f"mermaid block #{idx} (starts at line ~{line_offset}): "
            f"authoritative parse failed — {err_head[:220]}"
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
            line_no = text[:m.start()].count("\n") + 1
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
    required = {"project", "description", "repository"}
    optional = {"author", "license", "homepage", "runtime", "tags"}
    missing_required = sorted(required - fields_present)
    missing_optional = sorted(optional - fields_present)
    if missing_required:
        report.issues.append(
            "infobox is missing required field(s): "
            + ", ".join(missing_required)
        )
    # Warn (not fail) when too many optional fields are empty.
    if len(missing_optional) > len(optional) // 2:
        report.issues.append(
            "infobox is sparse — optional fields missing: "
            + ", ".join(missing_optional)
            + ". Manifest/LICENSE/README enrichment recommended."
        )
    report.ok = len(fields_present)
    return report


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
    print(f"unknown subcommand: {sub}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
