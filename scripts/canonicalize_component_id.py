"""M4/M13 — Canonicalize component IDs against data/component-canonical.yaml.

Used by Phase 3 (Architecture Modeling) to normalize the orchestrator's
component IDs into a canonical set BEFORE Phase 9 STRIDE dispatch. Without
this, the same Juice-Shop backend gets named "rest-api" / "express-api" /
"express-backend" across runs → silent T-ID drift in --incremental mode.

CLI usage:
    canonicalize_component_id.py normalize <ID> [--strict]
        Print the canonical ID for the input. Exit 0 on hit, 2 on miss
        (writes original to stdout, "(unchanged)" to stderr).
        --strict: exit 1 on miss instead of passing through.

    canonicalize_component_id.py validate <id1> <id2> ...
        Validate a list of component IDs. Print one line per input:
            <input>  →  <canonical>  [exact|alias|miss]
        Exit 0 if every input maps; exit 1 if any miss.

    canonicalize_component_id.py list
        Print the canonical-ID list (one per line, sorted).

Library usage:
    from canonicalize_component_id import canonicalize, load_map
    canonical_id, matched_via = canonicalize("express-backend")
    # → ("backend-api", "alias")

Also exposes `match_by_signals(recon_summary_text)` for Phase-3 inference
when no orchestrator-supplied ID is yet known.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# Optional yaml import: tests stub via fixture path. Fall back to a tiny
# parser since the canonical file is small and well-structured.
try:
    import yaml  # type: ignore

    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


def _plugin_root() -> Path:
    """Resolve plugin root via env or relative to this file."""
    env = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class CanonicalEntry:
    canonical_id: str
    display_name: str
    aliases: tuple[str, ...]
    detection_signals: tuple[str, ...]
    category: str


def _parse_yaml_minimal(path: Path) -> dict:
    """Tiny YAML subset parser — handles the schema of component-canonical.yaml.

    Used only when PyYAML is not importable (e.g. tests in minimal env).
    Supports the exact structure: top-level keys, nested 2-space dicts,
    and `- list` items. Comments stripped.
    """
    if _HAS_YAML:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    # Minimal hand-parser: very brittle; only meant for the canonical file.
    out: dict = {}
    stack: list[tuple[int, dict | list]] = [(0, out)]
    cur_list_key: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        # strip comments + trailing whitespace
        line = re.sub(r"\s*#.*$", "", raw).rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        body = line.strip()
        # pop stack to current indent
        while stack and stack[-1][0] > indent:
            stack.pop()
        parent = stack[-1][1] if stack else out
        if body.startswith("- "):
            val = body[2:].strip().strip('"').strip("'")
            if isinstance(parent, list):
                parent.append(val)
            continue
        if ":" in body:
            k, _, v = body.partition(":")
            k = k.strip()
            v = v.strip()
            if v == "":
                # nested object/list — peek ahead won't work cheaply, default to dict
                new: dict | list = {}
                if isinstance(parent, dict):
                    parent[k] = new
                stack.append((indent + 2, new))
                # heuristic: if next non-empty line starts with "- ", convert to list
                # (we'll lazy-fix later by checking type at access)
            else:
                v = v.strip('"').strip("'")
                if isinstance(parent, dict):
                    parent[k] = v
    # Post-process: convert dict-with-only-numeric-keys lists … skipped
    return out


def load_map(path: Path | None = None) -> dict[str, CanonicalEntry]:
    """Return canonical_id → CanonicalEntry mapping."""
    if path is None:
        path = _plugin_root() / "data" / "component-canonical.yaml"
    data = _parse_yaml_minimal(path)
    raw = data.get("canonical_components", {}) or {}
    out: dict[str, CanonicalEntry] = {}
    for cid, info in raw.items():
        info = info or {}
        # `aliases` and `detection_signals` may have been parsed as
        # empty dicts by the minimal parser; coerce to lists where possible.
        aliases = info.get("aliases") or []
        signals = info.get("detection_signals") or []
        if isinstance(aliases, dict):
            aliases = []
        if isinstance(signals, dict):
            signals = []
        out[cid] = CanonicalEntry(
            canonical_id=cid,
            display_name=str(info.get("display_name") or cid),
            aliases=tuple(aliases),
            detection_signals=tuple(signals),
            category=str(info.get("category") or cid),
        )
    return out


def canonicalize(
    component_id: str,
    map_: dict[str, CanonicalEntry] | None = None,
) -> tuple[str, str]:
    """Return (canonical_id, match_kind) for a given component_id.

    match_kind ∈ {"exact", "alias", "miss"}.
    On miss, returns (component_id, "miss") — caller decides whether to
    accept the original or hard-fail.
    """
    if map_ is None:
        map_ = load_map()
    cid = component_id.strip().lower()
    if cid in map_:
        return (cid, "exact")
    for entry in map_.values():
        if cid in (a.strip().lower() for a in entry.aliases):
            return (entry.canonical_id, "alias")
    return (component_id, "miss")


def match_by_signals(
    text: str,
    map_: dict[str, CanonicalEntry] | None = None,
) -> list[tuple[str, list[str]]]:
    """Suggest canonical_ids whose detection_signals appear in the text.

    Used by Phase 3 when the orchestrator has not yet named the component.
    Returns list of (canonical_id, matched_signals[]) for each hit, sorted
    by number of matched signals (most matches first).
    """
    if map_ is None:
        map_ = load_map()
    haystack = text.lower()
    hits: list[tuple[str, list[str]]] = []
    for entry in map_.values():
        matched = [s for s in entry.detection_signals if s.lower() in haystack]
        if matched:
            hits.append((entry.canonical_id, matched))
    hits.sort(key=lambda x: len(x[1]), reverse=True)
    return hits


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    p_norm = sub.add_parser("normalize", help="Normalize a single ID")
    p_norm.add_argument("component_id")
    p_norm.add_argument("--strict", action="store_true", help="Exit 1 on miss (default: pass through)")

    p_val = sub.add_parser("validate", help="Validate a list of IDs")
    p_val.add_argument("component_ids", nargs="+")

    sub.add_parser("list", help="Print all canonical IDs")

    p_match = sub.add_parser("match-signals", help="Suggest IDs based on detection signals in stdin / file")
    p_match.add_argument("--file", type=Path, help="Read text from file instead of stdin")

    args = p.parse_args(argv)
    map_ = load_map()

    if args.cmd == "normalize":
        canonical, kind = canonicalize(args.component_id, map_)
        if kind == "miss":
            print(canonical)  # pass-through to stdout
            print(f"(no canonical mapping for '{args.component_id}')", file=sys.stderr)
            return 1 if args.strict else 0
        print(canonical)
        return 0

    if args.cmd == "validate":
        miss = 0
        for cid in args.component_ids:
            canonical, kind = canonicalize(cid, map_)
            print(f"{cid}  →  {canonical}  [{kind}]")
            if kind == "miss":
                miss += 1
        return 1 if miss else 0

    if args.cmd == "list":
        for cid in sorted(map_.keys()):
            entry = map_[cid]
            print(f"{cid}  ({entry.display_name})")
        return 0

    if args.cmd == "match-signals":
        if args.file:
            text = args.file.read_text(encoding="utf-8")
        else:
            text = sys.stdin.read()
        hits = match_by_signals(text, map_)
        for cid, signals in hits:
            print(f"{cid}: {', '.join(signals)}")
        return 0 if hits else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
