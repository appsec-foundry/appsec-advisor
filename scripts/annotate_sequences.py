#!/usr/bin/env python3
"""
annotate_sequences.py — post-Phase-9 Mermaid sequence-diagram annotator.

Reads a Markdown file and a .threats-merged.json file, then injects a
``Note over`` line into the attack branch of every ``sequenceDiagram``
that carries the three metadata comments described in
``phase-group-architecture.md`` → "Sequence diagram annotation contract":

    %% components: <id>, <id>, …
    %% stride: <letters>
    ... alt/else ... %% attack-path

The note lists the top three threats (by severity) matching the declared
components and STRIDE categories, formatted as
``T-NNN (CWE-X), T-NNN (CWE-Y)``. If more than three match, the overflow is
shown as ``+N more → §8``.

Idempotent: re-running produces byte-identical output. A wrapping
``%% anno-seq-start`` / ``%% anno-seq-end`` fence around the injected
Note lets the strip pass remove prior annotations before re-injection.

CLI::

    python3 annotate_sequences.py \\
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
from dataclasses import dataclass
from pathlib import Path

from _atomic_io import atomic_write_text


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STRIDE_LETTER_TO_WORD = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}

_SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

_MAX_NOTE_THREATS = 3

_ANNO_SEQ_START = "        %% anno-seq-start"
_ANNO_SEQ_END = "        %% anno-seq-end"

_COMPONENTS_RE = re.compile(
    r'^\s*%%\s*components\s*:\s*(?P<ids>[\w.,\s-]+?)\s*$'
)
_STRIDE_RE = re.compile(
    r'^\s*%%\s*stride\s*:\s*(?P<letters>[\w,\s]+?)\s*$'
)
_ATTACK_PATH_RE = re.compile(r'^(?P<body>.*?)\s*%%\s*attack-path\s*$')
_PARTICIPANT_RE = re.compile(
    r'^\s*(?:participant|actor)\s+(?P<id>\w[\w-]*)(?:\s+as\s+.*)?\s*$'
)
_ALT_OR_ELSE_RE = re.compile(r'^(?P<indent>\s*)(?P<kw>alt|else)\b')


# ---------------------------------------------------------------------------
# Threat filtering
# ---------------------------------------------------------------------------

@dataclass
class _Threat:
    t_id: str
    component_id: str
    stride: str
    risk: str
    cwe: str

    @classmethod
    def from_row(cls, row: dict) -> "_Threat":
        return cls(
            t_id=row.get("t_id", ""),
            component_id=row.get("component_id", ""),
            stride=row.get("stride", ""),
            risk=row.get("risk", ""),
            cwe=row.get("cwe", ""),
        )


def _filter_threats(
    threats: list[_Threat],
    components: set,
    stride_words: set,
) -> list[_Threat]:
    matches = [
        t for t in threats
        if t.component_id in components and t.stride in stride_words
    ]
    matches.sort(key=lambda t: (_SEVERITY_RANK.get(t.risk, 99), t.t_id))
    return matches


def _format_note_body(matches: list[_Threat]) -> str:
    if not matches:
        return ""
    head = matches[:_MAX_NOTE_THREATS]
    parts = [f"{t.t_id} ({t.cwe})" if t.cwe else t.t_id for t in head]
    body = ", ".join(parts)
    overflow = len(matches) - len(head)
    if overflow > 0:
        body += f" +{overflow} more → §8"
    return body


# ---------------------------------------------------------------------------
# Mermaid block walking
# ---------------------------------------------------------------------------

def _find_mermaid_blocks(lines: list) -> list:
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


def _is_sequence_diagram(body: list) -> bool:
    for raw in body:
        s = raw.strip()
        if not s:
            continue
        return s.startswith("sequenceDiagram")
    return False


# ---------------------------------------------------------------------------
# Strip pass — remove prior annotator output from a block body
# ---------------------------------------------------------------------------

def _strip_block_body(body: list) -> list:
    out = []
    inside_anno = False
    for raw in body:
        stripped = raw.rstrip("\n").rstrip()
        if stripped == _ANNO_SEQ_START.rstrip():
            inside_anno = True
            continue
        if stripped == _ANNO_SEQ_END.rstrip():
            inside_anno = False
            continue
        if inside_anno:
            continue
        out.append(raw)
    return out


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _parse_metadata(body: list) -> tuple:
    """Return (components_set, stride_words_set) from the block body.

    Both are empty when the required metadata comments are missing.
    """
    components: set = set()
    stride_words: set = set()
    for raw in body:
        cm = _COMMENTS_MATCH(_COMPONENTS_RE, raw)
        if cm is not None:
            for piece in cm.split(","):
                piece = piece.strip()
                if piece:
                    components.add(piece)
            continue
        sm = _COMMENTS_MATCH(_STRIDE_RE, raw)
        if sm is not None:
            for letter in sm.split(","):
                letter = letter.strip().upper()
                word = _STRIDE_LETTER_TO_WORD.get(letter)
                if word:
                    stride_words.add(word)
    return components, stride_words


def _COMMENTS_MATCH(pattern, raw):
    m = pattern.match(raw.rstrip("\n"))
    if not m:
        return None
    if "ids" in m.groupdict():
        return m.group("ids")
    if "letters" in m.groupdict():
        return m.group("letters")
    return None


def _parse_participants(body: list) -> list:
    ids = []
    for raw in body:
        m = _PARTICIPANT_RE.match(raw.rstrip("\n"))
        if m:
            ids.append(m.group("id"))
    return ids


def _find_attack_branch_index(body: list) -> int:
    """Return the index of the alt/else line marked `%% attack-path`, or -1."""
    for idx, raw in enumerate(body):
        line_no_nl = raw.rstrip("\n")
        if _ATTACK_PATH_RE.match(line_no_nl) and _ALT_OR_ELSE_RE.match(line_no_nl):
            return idx
    return -1


# ---------------------------------------------------------------------------
# Annotation
# ---------------------------------------------------------------------------

def _annotate_block_body(
    body: list,
    threats_by_stride: dict,
) -> tuple:
    body = _strip_block_body(body)

    if not _is_sequence_diagram(body):
        return body, False

    components, stride_words = _parse_metadata(body)
    if not components or not stride_words:
        return body, False

    attack_idx = _find_attack_branch_index(body)
    if attack_idx < 0:
        return body, False

    participants = _parse_participants(body)
    if len(participants) < 2:
        return body, False

    matches = _filter_threats(
        threats_by_stride["all"], components, stride_words
    )
    note_body = _format_note_body(matches)
    if not note_body:
        return body, False

    first_p = participants[0]
    last_p = participants[-1]
    note_line = f"        Note over {first_p},{last_p}: {note_body}\n"

    new_body = list(body[:attack_idx + 1])
    new_body.append(_ANNO_SEQ_START + "\n")
    new_body.append(note_line)
    new_body.append(_ANNO_SEQ_END + "\n")
    new_body.extend(body[attack_idx + 1:])
    return new_body, True


def annotate_markdown(text: str, threats: list) -> str:
    threat_objs = [_Threat.from_row(t) for t in threats]
    threats_by_stride = {"all": threat_objs}

    lines = text.splitlines(keepends=True)
    blocks = _find_mermaid_blocks(lines)

    result = list(lines)
    for open_idx, close_idx in reversed(blocks):
        body = result[open_idx + 1:close_idx]
        new_body, _ = _annotate_block_body(body, threats_by_stride)
        result = (
            result[:open_idx + 1]
            + new_body
            + result[close_idx:]
        )

    return "".join(result)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Annotate Mermaid sequence diagrams with STRIDE threat IDs."
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

    try:
        md_text = args.markdown.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"ANNOTATE_FAILED: cannot read markdown: {exc}", file=sys.stderr)
        return 1

    new_text = annotate_markdown(md_text, threats_data["threats"])

    if new_text != md_text:
        try:
            # Atomic — rewrites threat-model.md in place. See annotate_architecture.
            atomic_write_text(args.markdown, new_text)
        except OSError as exc:
            print(f"ANNOTATE_FAILED: cannot write markdown: {exc}", file=sys.stderr)
            return 1

    n_annotated = new_text.count(_ANNO_SEQ_START.strip())
    print(f"ANNOTATED: {n_annotated} sequence diagrams annotated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
