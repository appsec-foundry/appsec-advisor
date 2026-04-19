#!/usr/bin/env python3
"""Deterministic QA checks for the threat model output.

Replaces expensive agent turns with mechanical checks that can be run from a
single Bash call. Each subcommand prints a short human-readable report and
exits 0 when everything is clean or 1 when fixable issues were found. Fixable
issues are either auto-applied in place (Check 1 link repair, Check 10 anchor
linkification) or printed so the QA reviewer can address them.

Usage:
    qa_checks.py links        <threat-model.md> <repo-root>
    qa_checks.py xrefs        <threat-model.md>
    qa_checks.py anchors      <threat-model.md>
    qa_checks.py invariants   <threat-model.md>
    qa_checks.py ms_structure <threat-model.md>
    qa_checks.py contract     <threat-model.md> [<sections-contract.yaml>]
    qa_checks.py all          <threat-model.md> <repo-root>

`all` runs every check in sequence and applies in-place fixes for links,
anchors, and safe Management Summary structural repairs. It prints a JSON
summary at the end so the caller can parse it.

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
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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

    def as_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "ok": self.ok,
            "issue_count": len(self.issues),
            "issues": self.issues,
            "fix_count": len(self.fixes),
            "fixes": self.fixes,
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
    summary = {
        "links": link_report.as_dict(),
        "anchors": anchor_report.as_dict(),
        "ms_structure": ms_report.as_dict(),
        "contract": contract_report.as_dict(),
        "xrefs": xref_report.as_dict(),
        "invariants": inv_report.as_dict(),
    }
    print(json.dumps(summary, indent=2))
    total_issues = sum(s["issue_count"] for s in summary.values())
    return 0 if total_issues == 0 else 1


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
    if sub == "all":
        if len(argv) != 4:
            print("usage: qa_checks.py all <md> <repo-root>", file=sys.stderr)
            return 2
        return cmd_all(Path(argv[2]), Path(argv[3]))
    print(f"unknown subcommand: {sub}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
