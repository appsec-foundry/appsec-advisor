"""Drift guard: every T-NNN / M-NNN reference in a rendered threat-model.md
must be a labelled cross-link, not bare text.

This catches the regression that produced the 2026-05 example output where
bare IDs (``T-001, T-002, T-003, T-036``) leaked into prose tables and
sentences because the qa_checks linkifier ran late, without label data, or
not at all.

Skipped contexts (where bare IDs are intentional and acceptable):
  * Fenced code blocks  (```` ``` ```` … ```` ``` ````) — Mermaid
    diagrams use bare IDs in node labels and Note lines because Mermaid
    does not render Markdown links.
  * Anchor sources — ``<a id="t-001"></a>T-001`` and Threat Register
    table cells where the ID itself is the row identifier.
  * Markdown headings — ``#### M-001 — Title`` carries the ID as part of
    the heading text; in-heading links break TOC slug generation.
  * The Table of Contents block — bare IDs there are part of the link
    text, not standalone references.

Skip rules MUST stay in lockstep with ``qa_checks.linkify_anchors`` so a
true positive is not silently filtered out. When that function gains a
new skip context, mirror it here.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_MD = Path("/home/mrohr/examples/thratmodel_standard_haiku/threat-model.md")

T_RE = re.compile(r"\bT-(\d{3,4})\b")
M_RE = re.compile(r"\bM-(\d{3,4})\b")


def _scan_bare_ids(md: str) -> list[tuple[int, str, str]]:
    """Return a list of (line_no, id, surrounding_context) for every bare
    T-NNN / M-NNN reference outside accepted-skip contexts.
    """
    findings: list[tuple[int, str, str]] = []

    in_fence = False
    in_toc = False
    lines = md.splitlines()
    for i, line in enumerate(lines, start=1):
        stripped = line.lstrip()

        # Fence toggle (``` … ``` and ```mermaid).
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue

        # TOC tracking — same heuristic as linkify_anchors.
        if line.startswith("## "):
            in_toc = "Table of Contents" in line
        if in_toc:
            continue

        # Markdown headings (#…######) — IDs there are part of the heading,
        # they are anchor sources, not references.
        if stripped.startswith("#"):
            continue

        # Threat Register / Mitigation Register row — the leading column
        # carries the ID as the row identifier (anchor source). Only the
        # leading cell is exempted; subsequent cells in the same row are
        # still scanned.
        first_cell_anchor = re.match(
            r"^\|\s*(?:<a id=\"[tm]-\d+\"></a>\s*)*[TM]-\d+\s*\|", line
        )
        scan_line = line
        if first_cell_anchor:
            scan_line = scan_line[first_cell_anchor.end():]

        for rx, prefix in ((T_RE, "T"), (M_RE, "M")):
            for m in rx.finditer(scan_line):
                full = m.group(0)
                start = m.start()

                # Skip when already part of a markdown link `[ID](#…)`.
                pre = scan_line[max(0, start - 2):start]
                post = scan_line[m.end(): m.end() + 2]
                if pre.endswith("[") or post.startswith("](") or post.startswith("]("):
                    continue

                # Skip when the ID appears next to a manual `<a id="…">`
                # anchor declaration on the same line (defensive — most
                # of these are caught by first_cell_anchor above).
                window = scan_line[max(0, start - 30): start + 10]
                if f'<a id="{prefix.lower()}-' in window:
                    continue

                ctx = scan_line[max(0, start - 40): m.end() + 40].strip()
                findings.append((i, full, ctx))

    return findings


# ---------------------------------------------------------------------------
# Self-tests for the scanner — these MUST stay green so the gate is trustworthy.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("md,expect", [
    # Bare IDs in prose ⇒ FAIL.
    ("via T-007, all user passwords are gone.\n", 1),
    # Comma-separated bare IDs in a table cell ⇒ FAIL (4 hits).
    ("| Risk | Layer | Enables |\n|---|---|---|\n| X | Y | T-001, T-002, T-003, T-004 |\n", 4),
    # Properly labelled link ⇒ PASS.
    ("via [T-007](#t-007) — SQL injection in login.\n", 0),
    # Bare ID inside fenced block ⇒ PASS (Mermaid contract).
    ("```mermaid\nNote over X: T-018 reached.\n```\n", 0),
    # Anchor source row in Threat Register ⇒ PASS.
    ('| <a id="t-005"></a>T-005 | RCE in B2B endpoint | C-03 |\n', 0),
    # Heading with bare ID ⇒ PASS (anchor-source convention).
    ('#### M-001 — Rotate JWT signing key\n', 0),
    # Bare ID in TOC ⇒ PASS.
    ("## Table of Contents\n- [3.2 T-001 — RCE](#rce)\n", 0),
])
def test_scanner_self(md: str, expect: int) -> None:
    findings = _scan_bare_ids(md)
    assert len(findings) == expect, f"expected {expect} findings, got {findings}"


# ---------------------------------------------------------------------------
# Regression check: the 2026-05 example output exhibits exactly the failure
# mode this gate is meant to catch. We do not pin the fixture to the repo
# (it lives under /home/mrohr/examples) — when absent, the test is skipped
# instead of failing, so the suite still runs in clean checkouts.
# ---------------------------------------------------------------------------

def test_example_output_has_bare_ids() -> None:
    """Sanity check on the historical artefact — confirms the gate fires
    on the very file that motivated it."""
    if not EXAMPLE_MD.is_file():
        pytest.skip(f"example fixture missing: {EXAMPLE_MD}")
    findings = _scan_bare_ids(EXAMPLE_MD.read_text(encoding="utf-8"))
    assert findings, (
        "expected bare-ID findings in the historical example output — "
        "gate logic may be too lenient"
    )
    # Confirm the specific lines from the analysis are flagged.
    flagged_lines = {ln for ln, _, _ in findings}
    for expected in (1243, 1244, 1245, 1246):
        assert expected in flagged_lines, (
            f"line {expected} should be flagged but isn't — "
            f"flagged: {sorted(flagged_lines)[:20]}…"
        )


# ---------------------------------------------------------------------------
# Forward-looking gate: when a fresh threat model lives at
# `tests/fixtures/no-bare-ids/threat-model.md`, scan it. This file is added
# by integration runs that are expected to ship clean. Until that fixture
# exists, the test is a no-op.
# ---------------------------------------------------------------------------

FRESH_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "no-bare-ids" / "threat-model.md"


def test_fresh_output_has_no_bare_ids() -> None:
    if not FRESH_FIXTURE.is_file():
        pytest.skip(f"clean fixture not yet recorded: {FRESH_FIXTURE}")
    findings = _scan_bare_ids(FRESH_FIXTURE.read_text(encoding="utf-8"))
    assert not findings, (
        f"{len(findings)} bare T-NNN / M-NNN references leaked into the "
        f"rendered output — every reference must be a labelled cross-link "
        f"`[ID](#id) — Title`. First five:\n"
        + "\n".join(f"  L{ln}: {ref!r}  …{ctx}…" for ln, ref, ctx in findings[:5])
    )
