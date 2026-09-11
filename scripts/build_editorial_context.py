#!/usr/bin/env python3
"""build_editorial_context.py — bounded input for the Stage-4 editorial pass.

The pass must not read the 90 KB report to polish its prose. This builder
projects only editable blocks into ``.dispatch-context/editorial/blocks.json``
and partitions them into bounded ``blocks-<batch>.json`` packets. Reviewers
return block ids; addresses and original text stay with the deterministic applier.

Every emitted block is an address ``check_editorial_diff.py`` already admits, so
the projection cannot hand the pass a target that ``apply_editorial_plan.py``
would refuse. Two block shapes:

  * a **field block** — one prose field of ``threat-model.yaml`` or of a JSON
    fragment, addressed as ``threats[12].scenario``;
  * a **paragraph block** — one prose paragraph of
    ``.fragments/security-architecture.md``, quoted verbatim so the applier's
    "matches exactly once" rule holds.

Selection is deliberately blunt in this version: the verdict, the Management
Summary and the §6 narrative always come along, and the finding prose is capped
at the worst ``--max-findings`` findings at or above ``--severity-floor``,
together with the mitigations they link to. A run's full editable surface is
several hundred fields. Independent packets bound each dispatch by both block
count and UTF-8 prose bytes. Oversized blocks are explicitly reported.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import math
import re
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _atomic_io import atomic_write_json  # noqa: E402
from _path_guard import is_within_repo, run_path_arg  # noqa: E402
from check_editorial_diff import (  # noqa: E402
    EDITABLE_FRAGMENTS,
    YAML_NAME,
    fragment_editable_paths,
    yaml_editable_paths,
)

CONTEXT_DIR = ".dispatch-context/editorial"
BLOCKS_NAME = "blocks.json"
MAX_BATCH_BLOCKS = 20
MAX_BATCH_BYTES = 8000
MAX_BATCHES = 128
WORK_SCHEMA = Path(__file__).resolve().parent.parent / "schemas/editorial-work.schema.json"
MARKDOWN_FRAGMENT = ".fragments/security-architecture.md"

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}

# Paragraph openers that are not prose: headings, tables, fences, list markers,
# block quotes and the renderer's HTML blocks. Their wording belongs to the
# templates and to the composer, not to an editorial pass.
_NON_PROSE_START = ("#", "|", "```", "~~~", ">", "<", "_")

# Bold labels the §6 contract owns. `**Status:**` and the inventory lists are
# read by `sec7-quality-bar-rules.md` and rewritten by `apply_prose_fixes.py`;
# their wording is not editorial.
_MECHANICAL_LABELS = {
    "status",
    "implemented controls",
    "relevant findings",
    "controls covered",
    "evidence",
    "primary mitigation",
}

# Regions the pregenerator owns outright. The fragment marks them with a
# `FROZEN` comment; the matching `FROZEN END` closes the region, and an
# unclosed marker runs to the next `##` heading.
_FROZEN_START_RE = re.compile(r"^<!--.*FROZEN(?!\s+END).*-->\s*$", re.MULTILINE)
_FROZEN_END_RE = re.compile(r"^(?:<!--.*FROZEN END.*-->|## )", re.MULTILINE)

# §6 carries most of its prose behind a bold label — `**Assessment:** …`,
# `**Verdict:** …` — so a paragraph may not be rejected for starting with `*`.
# The label is stripped before the length test and stays in the block, because
# `sec7-quality-bar-rules.md` checks for it. Mechanical paragraphs
# (`**Status:** 🔴 Weak`, the `**Relevant findings**` link list) carry no
# sentence and fail the length test on their own.
_LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]\s|\d+[.)]\s)")
_BOLD_LABEL_RE = re.compile(r"^\s*\*\*[^*\n]{1,60}\*\*:?\s*")
_LEADING_GLYPH_RE = re.compile(r"^[^\w`(\[]+")

# Below this, a paragraph is a label, a caption or a one-line status, not prose
# an editorial pass can improve.
_MIN_PROSE_CHARS = 80


def is_editorial_path(path: Path, output_dir: Path) -> bool:
    """Keep artifact names attached to their files, including within the run.

    In-root symlinks are useful for source reads, but an editorial target must
    not alias a different artifact such as the run configuration or QA receipt.
    A symlink used for the output root itself remains supported.
    """
    try:
        relative = path.absolute().relative_to(output_dir.absolute())
        return is_within_repo(path, output_dir) and path.resolve() == output_dir.resolve() / relative
    except (OSError, ValueError, RuntimeError):
        return False


def _rank(entry: dict) -> int:
    value = str(entry.get("effective_severity") or entry.get("risk") or entry.get("severity") or "").strip().lower()
    return _SEVERITY_RANK.get(value, 0)


def select_threats(threats: list, floor: int, cap: int) -> set[int]:
    """Indices of the worst findings at or above the floor, capped."""
    ranked = [(i, _rank(t)) for i, t in enumerate(threats) if isinstance(t, dict) and _rank(t) >= floor]
    ranked.sort(key=lambda pair: (-pair[1], pair[0]))
    return {i for i, _ in ranked[:cap]}


def select_mitigations(threats: list, mitigations: list, chosen: set[int]) -> set[int]:
    """Mitigations linked to a chosen finding, in either link direction."""
    wanted_ids: set[str] = set()
    wanted_threat_ids: set[str] = set()
    for i in chosen:
        threat = threats[i]
        wanted_threat_ids.add(str(threat.get("id") or ""))
        wanted_threat_ids.add(str(threat.get("local_id") or ""))
        for mid in threat.get("mitigation_ids") or []:
            wanted_ids.add(str(mid))
    wanted_threat_ids.discard("")

    out: set[int] = set()
    for j, mitigation in enumerate(mitigations):
        if not isinstance(mitigation, dict):
            continue
        if str(mitigation.get("id") or "") in wanted_ids:
            out.add(j)
            continue
        linked = mitigation.get("threat_ids") or mitigation.get("addresses") or []
        if any(str(tid) in wanted_threat_ids for tid in linked):
            out.add(j)
    return out


def _label(document: dict, path: tuple) -> str:
    root = path[0]
    if root == "verdict":
        return "verdict · " + ".".join(str(p) for p in path[1:])
    entries = document.get(root) or []
    index = path[1] if len(path) > 1 and isinstance(path[1], int) else None
    entry = entries[index] if isinstance(index, int) and index < len(entries) else {}
    identifier = str(entry.get("id") or entry.get("local_id") or f"{root}[{index}]")
    field = ".".join(str(p) for p in path[2:]) if len(path) > 2 else ""
    severity = str(entry.get("effective_severity") or entry.get("risk") or entry.get("priority") or "").strip()
    return " · ".join(part for part in (identifier, field, severity) if part)


def _fmt_path(path: tuple) -> str:
    out = ""
    for key in path:
        out += f"[{key}]" if isinstance(key, int) else (f".{key}" if out else str(key))
    return out


def _read_path(data: Any, path: tuple) -> Any:
    node = data
    for key in path:
        try:
            node = node[key]
        except (KeyError, IndexError, TypeError):
            return None
    return node


def yaml_blocks(document: dict, floor: int, cap: int) -> list[dict]:
    threats = document.get("threats") or []
    mitigations = document.get("mitigations") or []
    chosen_threats = select_threats(threats, floor, cap)
    chosen_mitigations = select_mitigations(threats, mitigations, chosen_threats)

    blocks = []
    for path in yaml_editable_paths(document):
        root = path[0]
        if root == "threats" and path[1] not in chosen_threats:
            continue
        if root == "mitigations" and path[1] not in chosen_mitigations:
            continue
        text = _read_path(document, path)
        if not isinstance(text, str) or not text.strip():
            continue
        blocks.append(
            {
                "file": YAML_NAME,
                "path": _fmt_path(path),
                "label": _label(document, path),
                "text": text,
            }
        )
    return blocks


def json_fragment_blocks(name: str, document: Any) -> list[dict]:
    blocks = []
    for path in fragment_editable_paths(name, document):
        text = _read_path(document, path)
        if not isinstance(text, str) or not text.strip():
            continue
        blocks.append(
            {
                "file": name,
                "path": _fmt_path(path),
                "label": f"{Path(name).stem} · {_fmt_path(path)}",
                "text": text,
            }
        )
    return blocks


def is_prose_paragraph(paragraph: str) -> bool:
    """True for a paragraph an editorial pass can improve.

    Rejects the structures the composer, the templates and the quality-bar rules
    own: headings, tables, fenced blocks, HTML, list items and block quotes.
    What survives must still carry a sentence once its bold label and any
    leading glyph are stripped.
    """
    stripped = paragraph.strip()
    if not stripped or stripped.startswith(_NON_PROSE_START) or _LIST_ITEM_RE.match(stripped):
        return False
    label = _BOLD_LABEL_RE.match(stripped)
    if label and label.group(0).strip().strip("*:").strip().lower() in _MECHANICAL_LABELS:
        return False
    body = _BOLD_LABEL_RE.sub("", stripped, count=1)
    body = _LEADING_GLYPH_RE.sub("", body).strip()
    return len(body) >= _MIN_PROSE_CHARS and "." in body


def frozen_spans(text: str) -> list[tuple[int, int]]:
    """Character ranges the pregenerator owns, which no edit may enter."""
    spans = []
    for start in _FROZEN_START_RE.finditer(text):
        end = _FROZEN_END_RE.search(text, start.end())
        spans.append((start.start(), end.start() if end else len(text)))
    return spans


def markdown_blocks(name: str, text: str) -> list[dict]:
    """Prose paragraphs of the §6 fragment, each quoted verbatim."""
    frozen = frozen_spans(text)
    blocks = []
    offset = 0
    for number, paragraph in enumerate(re.split(r"(\n\s*\n)", text)[::2], start=1):
        start = text.index(paragraph, offset) if paragraph else offset
        offset = start + len(paragraph)
        candidate = paragraph.strip("\n")
        if not is_prose_paragraph(candidate):
            continue
        if any(low <= start < high for low, high in frozen):
            continue
        if text.count(candidate) != 1:
            # The applier replaces a block that occurs exactly once. A repeated
            # paragraph is skipped rather than made ambiguous.
            continue
        blocks.append({"file": name, "path": None, "label": f"§6 ¶{number}", "text": candidate})
    return blocks


def build(output_dir: Path, floor: int, cap: int) -> dict:
    import yaml

    yaml_path = output_dir / YAML_NAME
    if not is_editorial_path(yaml_path, output_dir):
        raise ValueError("editorial source escapes output directory")
    document = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{yaml_path} is not a mapping")

    blocks = yaml_blocks(document, floor, cap)
    for name in EDITABLE_FRAGMENTS:
        path = output_dir / name
        if not is_editorial_path(path, output_dir):
            raise ValueError("editorial source escapes output directory")
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if name == MARKDOWN_FRAGMENT:
            blocks.extend(markdown_blocks(name, text))
        else:
            blocks.extend(json_fragment_blocks(name, json.loads(text)))

    for i, block in enumerate(blocks, start=1):
        block["id"] = f"b{i:03d}"

    return {
        "schema_version": 1,
        "generated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "selection": {
            "severity_floor": next(k for k, v in _SEVERITY_RANK.items() if v == floor),
            "max_findings": cap,
            "blocks_total": len(blocks),
            "chars_total": sum(len(b["text"]) for b in blocks),
        },
        "blocks": blocks,
    }


def validate_work(work: dict) -> None:
    """Validate bounded work and its exact, disjoint block assignment."""
    import jsonschema

    jsonschema.validate(work, json.loads(WORK_SCHEMA.read_text(encoding="utf-8")))
    blocks = {block["id"]: block for block in work["blocks"]}
    if work["selection"]["blocks_total"] != len(blocks) or work["selection"]["chars_total"] != sum(
        len(b["text"]) for b in blocks.values()
    ):
        raise ValueError("editorial selection counts disagree with its blocks")
    assigned = [bid for batch in work["batches"] for bid in batch["block_ids"]]
    if len(blocks) != len(work["blocks"]) or sorted(assigned) != sorted(blocks):
        raise ValueError("editorial blocks must be assigned exactly once")
    if len({batch["id"] for batch in work["batches"]}) != len(work["batches"]):
        raise ValueError("duplicate editorial batch")
    for batch in work["batches"]:
        if sum(len(blocks[bid]["text"].encode("utf-8")) for bid in batch["block_ids"]) > MAX_BATCH_BYTES:
            raise ValueError("editorial batch exceeds its byte budget")


def partition(projection: dict) -> dict:
    """Balance independent packets by UTF-8 prose bytes, retaining whole blocks.

    Oversized blocks are reported as unreviewed, never truncated. A run id
    prevents plans left by an interrupted dispatch from applying to a new run.
    """
    blocks = [b for b in projection["blocks"] if len(b["text"].encode("utf-8")) <= MAX_BATCH_BYTES]
    skipped = len(projection["blocks"]) - len(blocks)
    sizes = {b["id"]: len(b["text"].encode("utf-8")) for b in blocks}
    count = max(math.ceil(len(blocks) / MAX_BATCH_BLOCKS), math.ceil(sum(sizes.values()) / MAX_BATCH_BYTES))
    if count > MAX_BATCHES:
        raise ValueError("editorial projection exceeds the batch limit")
    buckets: list[list[str]] = [[] for _ in range(count)]
    loads = [0] * count
    for block in sorted(blocks, key=lambda b: (-sizes[b["id"]], b["id"])):
        size = sizes[block["id"]]
        available = [
            i for i in range(len(buckets)) if len(buckets[i]) < MAX_BATCH_BLOCKS and loads[i] + size <= MAX_BATCH_BYTES
        ]
        if not available:
            if len(buckets) >= MAX_BATCHES:
                raise ValueError("editorial projection exceeds the batch limit")
            buckets.append([])
            loads.append(0)
            available = [len(buckets) - 1]
        index = min(available, key=lambda i: (loads[i], i))
        buckets[index].append(block["id"])
        loads[index] += size
    work = {
        **projection,
        "run_id": uuid.uuid4().hex,
        "blocks": blocks,
        "selection": {
            **projection["selection"],
            "blocks_total": len(blocks),
            "chars_total": sum(len(b["text"]) for b in blocks),
            "blocks_skipped": skipped,
        },
        "batches": [{"id": f"{i:04d}", "block_ids": sorted(ids)} for i, ids in enumerate(buckets, 1) if ids],
    }
    validate_work(work)
    return work


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="build_editorial_context.py", description=__doc__)
    parser.add_argument("output_dir", type=run_path_arg)
    parser.add_argument("--max-findings", type=int, default=20, help="cap on finding prose (default: 20)")
    parser.add_argument(
        "--severity-floor",
        default="high",
        choices=sorted({k for k in _SEVERITY_RANK if k != "informational"}),
        help="lowest severity whose finding prose is offered (default: high)",
    )
    parser.add_argument("--out", help=f"projection path (default: <output_dir>/{CONTEXT_DIR}/{BLOCKS_NAME})")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    if not output_dir.is_dir():
        print(f"build_editorial_context.py: output dir not found: {output_dir}", file=sys.stderr)
        return 2
    target = Path(args.out) if args.out else output_dir / CONTEXT_DIR / BLOCKS_NAME

    try:
        projection = partition(build(output_dir, _SEVERITY_RANK[args.severity_floor], args.max_findings))
    except (OSError, ValueError) as exc:
        print(f"build_editorial_context.py: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 — a YAML or JSON parse failure ends the step
        print(f"build_editorial_context.py: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    if not is_editorial_path(target, output_dir):
        print("build_editorial_context.py: projection target escapes output directory", file=sys.stderr)
        return 2
    target.parent.mkdir(parents=True, exist_ok=True)
    packet_paths = [target.parent / f"blocks-{batch['id']}.json" for batch in projection["batches"]]
    if any(not is_editorial_path(path, output_dir) for path in packet_paths):
        print("build_editorial_context.py: packet target escapes output directory", file=sys.stderr)
        return 2
    for batch in projection["batches"]:
        packet = {
            **projection,
            "blocks": [b for b in projection["blocks"] if b["id"] in batch["block_ids"]],
            "batches": [batch],
        }
        packet["selection"] = {
            **projection["selection"],
            "blocks_total": len(packet["blocks"]),
            "chars_total": sum(len(b["text"]) for b in packet["blocks"]),
            "blocks_skipped": 0,
        }
        validate_work(packet)
        packet_path = target.parent / f"blocks-{batch['id']}.json"
        atomic_write_json(packet_path, packet, sort_keys=False)
    atomic_write_json(target, projection, sort_keys=False)
    json.dump(
        {
            "projection": str(target),
            **projection["selection"],
            "batches": [b["id"] for b in projection["batches"]],
            "max_parallel": 3,
        },
        sys.stdout,
        indent=2,
        sort_keys=True,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
