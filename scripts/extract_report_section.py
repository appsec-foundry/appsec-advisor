#!/usr/bin/env python3
"""Extract whole H2 sections out of a rendered threat-model.md.

Used to put a readable digest into a GitHub Actions job summary without
downloading the artifact: the full report is ~109 KB (and its Mermaid/SVG
figures do not render there), while the Management Summary alone is ~14 KB and
is exactly the part a reader wants first.

Read-only. Never mutates the report -- reports are produced by the render
pipeline and must not be hand-edited (AGENTS.md 1).

Fence-awareness is the whole trick: the Mitigation Register embeds shell and
Python blocks whose comments start at column 0 (`# Before (insecure):`), and a
naive `line.startswith("## ")` scan would end a section early on any `##`
inside such a block. Headings are only recognised at fence depth 0.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# ```, ~~~, and any longer run, optionally indented up to 3 spaces per CommonMark.
_FENCE = re.compile(r"^ {0,3}(?P<marker>`{3,}|~{3,})")


def _iter_lines_with_fence_state(text: str):
    """Yield (line, in_fence) for every line.

    A fence closes only on a marker of the SAME character and at least the same
    length as the one that opened it, per CommonMark -- so a ``` inside a ~~~~
    block does not close it, and neither does a shorter run.
    """
    open_marker: str | None = None
    for line in text.splitlines():
        m = _FENCE.match(line)
        if m:
            marker = m.group("marker")
            if open_marker is None:
                open_marker = marker
                yield line, True
                continue
            if marker[0] == open_marker[0] and len(marker) >= len(open_marker):
                open_marker = None
                yield line, True
                continue
        yield line, open_marker is not None


def extract_section(text: str, heading: str) -> str | None:
    """Return the ``## <heading>`` section including its heading line.

    Ends at the next H1/H2 that sits outside a code fence, or at EOF. Returns
    None when the heading is absent, so callers can distinguish "missing" from
    "present but empty".
    """
    want = heading.strip().casefold()
    out: list[str] = []
    collecting = False

    for line, in_fence in _iter_lines_with_fence_state(text):
        if not in_fence and line.startswith("## "):
            if collecting:
                break
            if line[3:].strip().casefold() == want:
                collecting = True
                out.append(line)
                continue
        elif not in_fence and collecting and line.startswith("# "):
            break

        if collecting:
            out.append(line)

    if not collecting:
        return None
    return "\n".join(out).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("report", type=Path, help="path to threat-model.md")
    ap.add_argument(
        "--section",
        action="append",
        default=None,
        help="H2 heading to extract (repeatable; order is preserved)",
    )
    ap.add_argument(
        "--skip-missing",
        action="store_true",
        help="skip absent sections instead of failing (for optional sections)",
    )
    args = ap.parse_args(argv)

    sections = args.section or ["Management Summary"]

    if not args.report.is_file():
        print(f"ERROR: no such report: {args.report}", file=sys.stderr)
        return 2

    text = args.report.read_text(encoding="utf-8")

    chunks: list[str] = []
    for heading in sections:
        found = extract_section(text, heading)
        if found is None:
            if args.skip_missing:
                print(f"note: section not found, skipping: {heading}", file=sys.stderr)
                continue
            print(f"ERROR: section not found: {heading}", file=sys.stderr)
            return 3
        chunks.append(found)

    if not chunks:
        print("ERROR: no sections extracted", file=sys.stderr)
        return 3

    sys.stdout.write("\n".join(chunks))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
