#!/usr/bin/env python3
"""Deterministic QA checks for the threat model output.

Replaces expensive agent turns with mechanical checks that can be run from a
single Bash call. Each subcommand prints a short human-readable report and
exits 0 when everything is clean or 1 when fixable issues were found. Fixable
issues are either auto-applied in place (Check 1 link repair, Check 10 anchor
linkification) or printed so the QA reviewer can address them.

Usage:
    qa_checks.py links    <threat-model.md> <repo-root>
    qa_checks.py xrefs    <threat-model.md>
    qa_checks.py anchors  <threat-model.md>
    qa_checks.py invariants <threat-model.md>
    qa_checks.py all      <threat-model.md> <repo-root>

`all` runs every check in sequence and applies in-place fixes for links and
anchors. It prints a JSON summary at the end so the caller can parse it.
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
RISK_DIST_RE = re.compile(
    r"\*\*Risk Distribution:\*\*\s*Critical:\s*(\d+)\s*·\s*High:\s*(\d+)\s*·\s*Medium:\s*(\d+)\s*·\s*Low:\s*(\d+)\s*·\s*\*\*Total:\s*(\d+)\*\*"
)
STRIDE_COVERAGE_RE = re.compile(
    r"\*\*STRIDE Coverage:\*\*\s*Spoofing:\s*(\d+)\s*·\s*Tampering:\s*(\d+)\s*·\s*Repudiation:\s*(\d+)\s*·\s*Information Disclosure:\s*(\d+)\s*·\s*Denial of Service:\s*(\d+)\s*·\s*Elevation of Privilege:\s*(\d+)"
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
    xref_report = check_xrefs(md)
    inv_report = check_invariants(md)
    summary = {
        "links": link_report.as_dict(),
        "anchors": anchor_report.as_dict(),
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
    if sub == "all":
        if len(argv) != 4:
            print("usage: qa_checks.py all <md> <repo-root>", file=sys.stderr)
            return 2
        return cmd_all(Path(argv[2]), Path(argv[3]))
    print(f"unknown subcommand: {sub}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
