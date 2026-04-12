#!/usr/bin/env python3
"""
annotate_architecture.py — post-Phase-9 Mermaid diagram annotator.

Reads a Markdown file and a .threats-merged.json file, then rewrites every
Mermaid ``graph`` block to annotate nodes that carry a ``%% component: <id>``
comment with threat data: a severity badge appended to the node label, a
severity class, a click link to the first Critical/High finding in Section 8,
and a classDef block. A one-line legend is appended after every annotated
block so the reader knows what the colors mean.

The script is idempotent: running it a second time on an already-annotated
file produces byte-identical output.

CLI::

    python3 annotate_architecture.py \\
        --markdown <path-to-threat-model.md> \\
        --threats  <path-to-.threats-merged.json>

Exit codes:
    0 — file rewritten, or nothing to do
    1 — IO / JSON / parse error
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants and regexes
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

_ANNO_START = "    %% anno-start"
_ANNO_END = "    %% anno-end"

_LEGEND_MARKER = "<!-- anno-legend -->"
_LEGEND_ITALIC = (
    "*Legend: node color = highest-severity threat on that component — "
    "red = Critical, orange = High, yellow = Medium. "
    "Click a colored node to jump to its detail row in §8.*"
)
_LEGEND_BLOCK = f"{_LEGEND_MARKER}\n{_LEGEND_ITALIC}\n"

_CLASSDEF_LINES = [
    "    classDef critical fill:#ff4d4d,stroke:#900,color:#fff,stroke-width:2px",
    "    classDef high fill:#ff944d,stroke:#c60,color:#000",
    "    classDef medium fill:#ffd24d,stroke:#996,color:#000",
]

_NODE_RE = re.compile(
    r'^(?P<indent>[ \t]*)(?P<id>\w[\w-]*)\["(?P<label>.*?)"\]'
    r'(?P<cls>:::[\w-]+)?[ \t]*$'
)
_COMMENT_RE = re.compile(r'^[ \t]*%%[ \t]*component[ \t]*:[ \t]*(?P<id>[\w.-]+)[ \t]*$')
_BADGE_TAIL_RE = re.compile(r'(?:<br/>)?⚠[^<]*$')
_OWNED_CLASSES = {"critical", "high", "medium", "risk"}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class _Threat:
    t_id: str
    component_id: str
    risk: str
    title: str


@dataclass
class _Aggregate:
    counts: dict = field(default_factory=lambda: {s: 0 for s in _SEVERITY_ORDER})
    first: dict = field(default_factory=dict)  # risk -> _Threat

    def add(self, threat: _Threat) -> None:
        if threat.risk not in self.counts:
            return
        self.counts[threat.risk] += 1
        self.first.setdefault(threat.risk, threat)

    @property
    def needs_annotation(self) -> bool:
        return any(self.counts[s] > 0 for s in ("Critical", "High", "Medium"))

    @property
    def max_severity(self) -> str:
        for s in ("Critical", "High", "Medium", "Low"):
            if self.counts[s] > 0:
                return s
        return "Low"

    @property
    def severity_class(self) -> str:
        m = self.max_severity
        return {"Critical": "critical", "High": "high", "Medium": "medium"}.get(m, "")

    @property
    def badge(self) -> str:
        parts = []
        for risk, letter in (("Critical", "C"), ("High", "H"), ("Medium", "M")):
            if self.counts[risk]:
                parts.append(f"{self.counts[risk]}{letter}")
        return "·".join(parts)

    @property
    def click_target(self) -> "_Threat | None":
        for risk in ("Critical", "High", "Medium"):
            if risk in self.first:
                return self.first[risk]
        return None


def _aggregate(threats: list[dict]) -> dict:
    out: dict = {}
    for row in threats:
        t = _Threat(
            t_id=row.get("t_id", ""),
            component_id=row.get("component_id", ""),
            risk=row.get("risk", ""),
            title=row.get("title", "") or row.get("t_id", ""),
        )
        if not t.component_id or not t.t_id:
            continue
        # Normalize to lowercase for case-insensitive matching against Mermaid node IDs
        key = t.component_id.lower()
        out.setdefault(key, _Aggregate()).add(t)
    return out


# ---------------------------------------------------------------------------
# Mermaid block iteration
# ---------------------------------------------------------------------------

def _find_mermaid_blocks(lines: list[str]) -> list[tuple[int, int]]:
    """Return (open_idx, close_idx) pairs for every ```mermaid ... ``` block."""
    blocks = []
    i = 0
    n = len(lines)
    while i < n:
        if lines[i].rstrip("\n").rstrip().startswith("```mermaid"):
            j = i + 1
            while j < n and lines[j].rstrip("\n").rstrip() != "```":
                j += 1
            if j < n:
                blocks.append((i, j))
                i = j + 1
                continue
        i += 1
    return blocks


# ---------------------------------------------------------------------------
# Strip pass — remove all prior annotator output
# ---------------------------------------------------------------------------

def _strip_node_line(line: str) -> str:
    m = _NODE_RE.match(line)
    if not m:
        return line
    label = m.group("label")
    label = _BADGE_TAIL_RE.sub("", label).rstrip()
    while label.endswith("<br/>"):
        label = label[:-5]
    cls = m.group("cls") or ""
    if cls:
        cls_name = cls[3:].strip()
        if cls_name in _OWNED_CLASSES:
            cls = ""
    indent = m.group("indent")
    node_id = m.group("id")
    nl = "\n" if line.endswith("\n") else ""
    return f'{indent}{node_id}["{label}"]{cls}{nl}'


def _strip_block_body(body: list[str]) -> list[str]:
    out: list[str] = []
    inside_anno = False
    for raw in body:
        stripped = raw.rstrip("\n").rstrip()
        if stripped == _ANNO_START.rstrip():
            inside_anno = True
            continue
        if stripped == _ANNO_END.rstrip():
            inside_anno = False
            continue
        if inside_anno:
            continue
        out.append(_strip_node_line(raw))
    return out


def _strip_legend_after(lines: list[str], start: int) -> int:
    """If a legend appears after `start`, consume it and return the new index.

    Legend pattern (with flexible blank-line framing):
        [blank lines]
        <!-- anno-legend -->
        *Legend: ...*
        [blank lines]
    Returns the index of the first line NOT consumed. If no legend is present,
    returns `start` unchanged (leaving blank lines intact for the caller).
    """
    n = len(lines)
    k = start
    leading_blanks = 0
    while k < n and lines[k].strip() == "":
        k += 1
        leading_blanks += 1
    if k >= n or _LEGEND_MARKER not in lines[k]:
        return start
    k += 1
    if k < n and lines[k].lstrip().startswith("*Legend:"):
        k += 1
    while k < n and lines[k].strip() == "":
        k += 1
    return k


# ---------------------------------------------------------------------------
# Annotate pass — inject fresh annotations
# ---------------------------------------------------------------------------

def _annotate_block_body(
    body: list[str],
    aggs: dict,
) -> tuple[list[str], int]:
    """Annotate nodes in a stripped block body; return (new_body, n_annotated)."""
    new_body: list[str] = []
    click_lines: list[str] = []
    n_annotated = 0
    pending: str | None = None

    for raw in body:
        cm = _COMMENT_RE.match(raw.rstrip("\n"))
        if cm:
            pending = cm.group("id")
            new_body.append(raw)
            continue

        if pending is not None:
            nm = _NODE_RE.match(raw)
            if nm:
                agg = aggs.get(pending.lower())
                if agg and agg.needs_annotation:
                    label = nm.group("label").rstrip()
                    while label.endswith("<br/>"):
                        label = label[:-5]
                    new_label = f"{label}<br/>⚠ {agg.badge}"
                    nl = "\n" if raw.endswith("\n") else ""
                    raw = (
                        f'{nm.group("indent")}{nm.group("id")}'
                        f'["{new_label}"]:::{agg.severity_class}{nl}'
                    )
                    target = agg.click_target
                    if target is not None:
                        safe = target.title.replace('"', "'")
                        click_lines.append(
                            f'    click {nm.group("id")} '
                            f'"#{target.t_id.lower()}" '
                            f'"{target.t_id}: {safe}"'
                        )
                    n_annotated += 1
            pending = None
        new_body.append(raw)

    if n_annotated > 0:
        new_body.append(_ANNO_START + "\n")
        for cd in _CLASSDEF_LINES:
            new_body.append(cd + "\n")
        for cl in click_lines:
            new_body.append(cl + "\n")
        new_body.append(_ANNO_END + "\n")

    return new_body, n_annotated


# ---------------------------------------------------------------------------
# Top-level
# ---------------------------------------------------------------------------

def annotate_markdown(text: str, aggs: dict) -> str:
    lines = text.splitlines(keepends=True)
    blocks = _find_mermaid_blocks(lines)

    # Process blocks from the last to the first so earlier indices stay stable.
    # For each block: strip existing annotations, annotate fresh, update legend.
    result = list(lines)
    for open_idx, close_idx in reversed(blocks):
        body = result[open_idx + 1:close_idx]
        stripped_body = _strip_block_body(body)
        new_body, n_annotated = _annotate_block_body(stripped_body, aggs)

        legend_end = _strip_legend_after(result, close_idx + 1)

        tail_start = legend_end

        if n_annotated > 0:
            legend_chunk = ["\n", _LEGEND_MARKER + "\n", _LEGEND_ITALIC + "\n"]
            if tail_start < len(result) and result[tail_start].strip() != "":
                legend_chunk.append("\n")
        else:
            legend_chunk = []
            if legend_end == close_idx + 1:
                # No legend was present; leave trailing lines intact
                tail_start = close_idx + 1
            else:
                # Legend was stripped and no fresh annotations — restore a
                # single blank separator so the block doesn't butt up against
                # the next paragraph.
                if tail_start < len(result) and result[tail_start].strip() != "":
                    legend_chunk = ["\n"]

        result = (
            result[:open_idx + 1]
            + new_body
            + [result[close_idx]]
            + legend_chunk
            + result[tail_start:]
        )

    return "".join(result)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Annotate Mermaid architecture diagrams with STRIDE threat data."
    )
    ap.add_argument("--markdown", required=True, type=Path,
                    help="Path to the Markdown file to rewrite (in place).")
    ap.add_argument("--threats", required=True, type=Path,
                    help="Path to .threats-merged.json produced by Phase 9.")
    args = ap.parse_args(argv)

    try:
        threats_data = json.loads(args.threats.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ANNOTATE_FAILED: cannot read threats JSON: {exc}", file=sys.stderr)
        return 1

    if not isinstance(threats_data, dict) or not isinstance(
        threats_data.get("threats"), list
    ):
        print("ANNOTATE_FAILED: threats JSON must have a 'threats' list", file=sys.stderr)
        return 1

    aggs = _aggregate(threats_data["threats"])

    try:
        md_text = args.markdown.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"ANNOTATE_FAILED: cannot read markdown: {exc}", file=sys.stderr)
        return 1

    new_text = annotate_markdown(md_text, aggs)

    if new_text != md_text:
        try:
            args.markdown.write_text(new_text, encoding="utf-8")
        except OSError as exc:
            print(f"ANNOTATE_FAILED: cannot write markdown: {exc}", file=sys.stderr)
            return 1

    n_components = sum(1 for a in aggs.values() if a.needs_annotation)
    print(f"ANNOTATED: {n_components} components annotated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
