#!/usr/bin/env python3
"""validators/ground_truth_recall.py: measure threat-model recall against known vulnerabilities.

Developer test tool, not part of the create-threat-model pipeline. It answers
"which known vulnerabilities did a run locate?" so that depth or model changes
can be compared on hard numbers instead of finding counts.

  * `extract` builds a ground-truth file from inline source markers of the form
    `<marker> start KEY...`, `<marker> end KEY...` and `<marker> vuln-line KEY...`
    in the tracked files of a repository. A key needs a matching start/end pair
    in the same file; unbalanced markers (for example prose that mentions the
    marker) are reported and skipped.
  * `score` matches the `evidence` and `affected_files` of every threat in one or
    more `threat-model.yaml` files against the ground-truth locations.

Match levels, strongest first:
    line     an evidence line lies within --tolerance lines of a vuln-line, or
             inside the marked range when the item has no vuln-line
    range    an evidence line lies inside the marked start/end range
    file     a threat cites the file without a matching line
    miss     no threat cites the file

Exit codes:
    0  success
    2  usage, load, or parse error
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

LEVELS = ("line", "range", "file", "miss")
_KEY_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_\-]*$")
_DIRECTIVES = ("start", "end", "vuln-line")


@dataclass
class Location:
    file: str
    start: int | None = None
    end: int | None = None
    vuln_lines: list[int] = field(default_factory=list)


def _norm(path: str) -> str:
    path = path.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _parse_marker_line(line: str, marker_re: re.Pattern[str]) -> tuple[str, list[str]] | None:
    m = marker_re.search(line)
    if not m:
        return None
    keys: list[str] = []
    for token in m.group(2).split():
        if not _KEY_RE.match(token):
            break
        keys.append(token)
    return (m.group(1), keys) if keys else None


def extract_from_text(rel_path: str, text: str, marker: str) -> tuple[dict[str, list[Location]], list[str]]:
    """Return per-key locations found in one file plus warnings for unbalanced markers."""
    marker_re = re.compile(re.escape(marker) + r"\s+(" + "|".join(map(re.escape, _DIRECTIVES)) + r")\s+(.+)$")
    open_at: dict[str, int] = {}
    closed: dict[str, list[Location]] = {}
    pending_vuln: dict[str, list[int]] = {}
    warnings: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        parsed = _parse_marker_line(line, marker_re)
        if not parsed:
            continue
        directive, keys = parsed
        for key in keys:
            if directive == "start":
                if key in open_at:
                    warnings.append(f"{rel_path}:{lineno}: nested start for {key} ignored")
                    continue
                open_at[key] = lineno
                pending_vuln[key] = []
            elif directive == "end":
                if key not in open_at:
                    warnings.append(f"{rel_path}:{lineno}: end without start for {key}")
                    continue
                closed.setdefault(key, []).append(Location(rel_path, open_at.pop(key), lineno, pending_vuln.pop(key)))
            elif key in open_at:
                pending_vuln[key].append(lineno)
            else:
                warnings.append(f"{rel_path}:{lineno}: vuln-line outside a range for {key} ignored")
    for key, lineno in open_at.items():
        warnings.append(f"{rel_path}:{lineno}: start without end for {key} ignored")
    return closed, warnings


def _tracked_files(repo_root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z"],
        check=True,
        capture_output=True,
    ).stdout
    return [p for p in out.decode("utf-8", errors="replace").split("\0") if p]


def extract(repo_root: Path, marker: str) -> tuple[dict, list[str]]:
    items: dict[str, list[Location]] = {}
    warnings: list[str] = []
    for rel in _tracked_files(repo_root):
        path = repo_root / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if marker not in text:
            continue
        found, warns = extract_from_text(_norm(rel), text, marker)
        warnings.extend(warns)
        for key, locs in found.items():
            items.setdefault(key, []).extend(locs)
    doc = {
        "schema_version": 1,
        "source": {"marker": marker},
        "items": [
            {
                "id": key,
                "locations": [
                    {"file": loc.file, "lines": [loc.start, loc.end], "vuln_lines": loc.vuln_lines} for loc in locs
                ],
            }
            for key, locs in sorted(items.items())
        ],
    }
    return doc, warnings


def load_ground_truth(path: Path) -> dict[str, list[Location]]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("items"), list):
        raise ValueError(f"{path}: expected a mapping with an 'items' list")
    items: dict[str, list[Location]] = {}
    for item in doc["items"]:
        locs = []
        for loc in item.get("locations") or []:
            lines = loc.get("lines") or [None, None]
            locs.append(Location(_norm(loc["file"]), lines[0], lines[1], [int(v) for v in loc.get("vuln_lines") or []]))
        if not locs:
            raise ValueError(f"{path}: item {item.get('id')!r} has no locations")
        items[str(item["id"])] = locs
    return items


def load_threat_locations(path: Path) -> list[tuple[str, list[tuple[str, int]], set[str]]]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    threats = doc.get("threats") if isinstance(doc, dict) else None
    if not isinstance(threats, list):
        raise ValueError(f"{path}: expected a 'threats' list")
    result = []
    for t in threats:
        if not isinstance(t, dict):
            continue
        cited: list[tuple[str, int]] = []
        files: set[str] = set()
        for ev in t.get("evidence") or []:
            if isinstance(ev, dict) and ev.get("file"):
                f = _norm(str(ev["file"]))
                files.add(f)
                if isinstance(ev.get("line"), int):
                    cited.append((f, ev["line"]))
        files.update(_norm(str(f)) for f in t.get("affected_files") or [] if f)
        result.append((str(t.get("id", "?")), cited, files))
    return result


def match_item(locs: list[Location], threats, tolerance: int) -> tuple[str, list[str]]:
    best = "miss"
    by_level: dict[str, set[str]] = {lvl: set() for lvl in LEVELS}
    for tid, cited, files in threats:
        for loc in locs:
            level = None
            for f, line in cited:
                if f != loc.file:
                    continue
                in_range = loc.start is not None and loc.start <= line <= loc.end
                near = any(abs(line - v) <= tolerance for v in loc.vuln_lines)
                if near or (in_range and not loc.vuln_lines):
                    level = "line"
                    break
                if in_range:
                    level = "range"
            if level is None and loc.file in files:
                level = "file"
            if level:
                by_level[level].add(tid)
                if LEVELS.index(level) < LEVELS.index(best):
                    best = level
    return best, sorted(by_level[best]) if best != "miss" else []


def score(ground_truth: dict[str, list[Location]], runs: list[tuple[str, Path]], tolerance: int) -> dict:
    report = {"tolerance": tolerance, "items": len(ground_truth), "runs": {}}
    for label, path in runs:
        threats = load_threat_locations(path)
        per_item = {}
        counts = dict.fromkeys(LEVELS, 0)
        for item_id, locs in sorted(ground_truth.items()):
            level, tids = match_item(locs, threats, tolerance)
            per_item[item_id] = {"level": level, "threats": tids}
            counts[level] += 1
        n = len(ground_truth) or 1
        report["runs"][label] = {
            "path": str(path),
            "threats": len(threats),
            "counts": counts,
            "recall_line": round(counts["line"] / n, 3),
            "recall_located": round((counts["line"] + counts["range"]) / n, 3),
            "recall_file": round((n - counts["miss"]) / n, 3),
            "items": per_item,
        }
    return report


def render_text(report: dict) -> str:
    labels = list(report["runs"])
    width = max([len(i) for r in report["runs"].values() for i in r["items"]] + [4])
    lines = [f"Ground truth: {report['items']} items · tolerance ±{report['tolerance']} lines", ""]
    lines.append("item".ljust(width) + "  " + "  ".join(lbl.ljust(8) for lbl in labels))
    first = report["runs"][labels[0]]["items"]
    for item_id in first:
        row = [report["runs"][lbl]["items"][item_id]["level"].ljust(8) for lbl in labels]
        lines.append(item_id.ljust(width) + "  " + "  ".join(row))
    lines.append("")
    for lbl in labels:
        r = report["runs"][lbl]
        c = r["counts"]
        lines.append(
            f"{lbl}: {r['threats']} threats · line {c['line']} · range {c['range']} · file {c['file']} · miss {c['miss']}"
            f" · recall line {r['recall_line']:.0%} · located {r['recall_located']:.0%} · file {r['recall_file']:.0%}"
        )
    return "\n".join(lines)


def _parse_run(value: str) -> tuple[str, Path]:
    label, sep, path = value.partition("=")
    if not sep or not label or not path:
        raise argparse.ArgumentTypeError("expected LABEL=PATH")
    return label, Path(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    ex = sub.add_parser("extract", help="build ground truth from inline source markers")
    ex.add_argument("--repo-root", type=Path, required=True)
    ex.add_argument("--marker", required=True, help="marker prefix preceding start/end/vuln-line")
    ex.add_argument("--output", type=Path, required=True)
    sc = sub.add_parser("score", help="score threat-model.yaml runs against ground truth")
    sc.add_argument("--ground-truth", type=Path, required=True)
    sc.add_argument("--run", type=_parse_run, action="append", required=True, metavar="LABEL=PATH")
    sc.add_argument("--tolerance", type=int, default=3)
    sc.add_argument("--json", type=Path, help="also write the full report as JSON")
    args = parser.parse_args(argv)

    try:
        if args.cmd == "extract":
            doc, warnings = extract(args.repo_root, args.marker)
            for w in warnings:
                print(f"warning: {w}", file=sys.stderr)
            if not doc["items"]:
                print("error: no balanced markers found", file=sys.stderr)
                return 2
            args.output.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
            print(f"wrote {len(doc['items'])} items to {args.output}")
            return 0
        if args.tolerance < 0:
            print("error: --tolerance must be >= 0", file=sys.stderr)
            return 2
        report = score(load_ground_truth(args.ground_truth), args.run, args.tolerance)
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(render_text(report))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
