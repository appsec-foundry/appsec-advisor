#!/usr/bin/env python3
"""Project one bounded, exact-source-bound abuse-case input per candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from _atomic_io import atomic_write_json
import scan_excludes

MAX_CANDIDATES = 64
MAX_CONTEXT_BYTES = 65_536
MAX_CHAIN_STEPS = 16
MAX_PATTERNS = 32
MAX_SOURCE_WINDOW_LINES = 17
MAX_SOURCE_WINDOW_CHARS = 32_768
_CANDIDATE_RE = re.compile(r"^(?:AC-T|AC|ORG-AC|REPO-AC)-[0-9]{3,}$")


class AbuseContextError(ValueError):
    """Raised when a candidate cannot be projected without semantic loss."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _string(value: Any, field: str, *, maximum: int = 2000, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise AbuseContextError(f"{field} must be a non-empty string of at most {maximum} characters")
    return value


def _strings(value: Any, field: str, *, maximum: int = MAX_PATTERNS) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > maximum:
        raise AbuseContextError(f"{field} exceeds {maximum} values")
    return [_string(item, field, maximum=1000) for item in value]  # type: ignore[list-item]


def _project_probe(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AbuseContextError(f"{field} must be an object")
    entry = value.get("entry_points") if isinstance(value.get("entry_points"), dict) else {}
    anchors = value.get("anchors") or []
    if not isinstance(anchors, list) or len(anchors) > MAX_PATTERNS:
        raise AbuseContextError(f"{field}.anchors exceeds {MAX_PATTERNS} values")
    projected_anchors: list[dict[str, Any]] = []
    for anchor in anchors:
        if not isinstance(anchor, dict):
            raise AbuseContextError(f"{field}.anchors contains a non-object")
        line_hint = anchor.get("line_hint")
        if line_hint is not None and (not isinstance(line_hint, int) or isinstance(line_hint, bool) or line_hint < 1):
            raise AbuseContextError(f"{field}.anchors has an invalid line_hint")
        projected_anchors.append(
            {
                "file": _string(anchor.get("file"), f"{field}.anchors.file", maximum=1000),
                "line_hint": line_hint,
                "pattern": _string(anchor.get("pattern"), f"{field}.anchors.pattern", maximum=1000),
            }
        )
    sinks = _strings(value.get("sink_patterns"), f"{field}.sink_patterns")
    if not sinks:
        raise AbuseContextError(f"{field}.sink_patterns must not be empty")
    return {
        "entry_points": {
            "endpoint_patterns": _strings(entry.get("endpoint_patterns"), f"{field}.endpoint_patterns"),
            "file_hints": _strings(entry.get("file_hints"), f"{field}.file_hints"),
        },
        "sink_patterns": sinks,
        "control_patterns": _strings(value.get("control_patterns"), f"{field}.control_patterns"),
        "control_sufficiency": value.get("control_sufficiency") or "any",
        "anchors": projected_anchors,
    }


def _project_chain(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > MAX_CHAIN_STEPS:
        raise AbuseContextError(f"candidate chain must contain 1-{MAX_CHAIN_STEPS} steps")
    projected: list[dict[str, Any]] = []
    for index, step in enumerate(value, start=1):
        if not isinstance(step, dict) or step.get("step") != index:
            raise AbuseContextError("candidate chain steps must be sequential objects")
        finding = step.get("finding")
        if finding is not None and not isinstance(finding, dict):
            raise AbuseContextError("candidate step finding must be an object")
        projected_finding = None
        if isinstance(finding, dict):
            projected_finding = {
                key: finding.get(key)
                for key in ("title", "cwe", "stride", "severity", "mitigation_title", "remediation")
                if key in finding
            }
        projected.append(
            {
                "step": index,
                "label": _string(step.get("label"), f"chain[{index}].label", maximum=500),
                "grants": _string(step.get("grants"), f"chain[{index}].grants", maximum=500),
                "requires": _string(step.get("requires"), f"chain[{index}].requires", maximum=500, nullable=True),
                "description": _string(
                    step.get("description"), f"chain[{index}].description", maximum=2000, nullable=True
                ),
                "required": step.get("required", True),
                "finding": projected_finding,
                "probe": _project_probe(step.get("probe"), f"chain[{index}].probe"),
            }
        )
    return projected


def _source_window(repo_root: Path | None, evidence: dict[str, Any] | None, remaining_chars: int) -> dict | None:
    """Return a bounded exact locator window for one matched source anchor."""
    if repo_root is None or not isinstance(evidence, dict) or remaining_chars <= 0:
        return None
    relative = evidence.get("file")
    line = evidence.get("line")
    if not isinstance(relative, str) or not isinstance(line, int) or isinstance(line, bool) or line < 1:
        return None
    rel = Path(relative)
    if rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts):
        return None
    try:
        if scan_excludes.is_excluded(rel.as_posix()):
            return None
    except (FileNotFoundError, ValueError):
        pass
    root = repo_root.resolve()
    raw_path = root / rel
    if raw_path.is_symlink():
        return None
    path = raw_path.resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return None
    if path.is_symlink() or not path.is_file():
        return None
    try:
        raw_lines = path.read_bytes().splitlines()
    except OSError:
        return None
    if line > len(raw_lines):
        return None
    radius = MAX_SOURCE_WINDOW_LINES // 2
    start = max(1, line - radius)
    end = min(len(raw_lines), line + radius)
    raw = b"\n".join(raw_lines[start - 1 : end])
    content = raw.decode("utf-8", errors="replace")
    if len(content) > remaining_chars:
        return None
    return {
        "file": rel.as_posix(),
        "start_line": start,
        "end_line": end,
        "content": content,
        "content_sha256": _sha256(raw),
    }


def _project_step_matches(
    value: Any,
    step_count: int,
    *,
    repo_root: Path | None = None,
) -> tuple[list[dict[str, Any]], int]:
    if not isinstance(value, list) or len(value) != step_count:
        raise AbuseContextError("candidate step_matches do not cover the chain")
    projected: list[dict[str, Any]] = []
    source_chars = 0
    for index, match in enumerate(value, start=1):
        if not isinstance(match, dict) or match.get("step") != index:
            raise AbuseContextError("candidate step_matches must be sequential objects")
        evidence = match.get("evidence")
        projected_evidence = None
        if isinstance(evidence, dict):
            line = evidence.get("line")
            if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
                raise AbuseContextError("candidate evidence line is invalid")
            projected_evidence = {
                "file": _string(evidence.get("file"), "step_matches.evidence.file", maximum=1000),
                "line": line,
            }
        source_window = _source_window(repo_root, projected_evidence, MAX_SOURCE_WINDOW_CHARS - source_chars)
        if source_window is not None:
            source_chars += len(source_window["content"])
        projected.append(
            {
                "step": index,
                "label": _string(match.get("label"), f"step_matches[{index}].label", maximum=500),
                "required": match.get("required", True),
                "grants": _string(match.get("grants"), f"step_matches[{index}].grants", maximum=500),
                "requires": _string(
                    match.get("requires"), f"step_matches[{index}].requires", maximum=500, nullable=True
                ),
                "matched": match.get("matched") is True,
                "matched_finding_id": _string(
                    match.get("matched_finding_id"),
                    f"step_matches[{index}].matched_finding_id",
                    maximum=100,
                    nullable=True,
                ),
                "evidence": projected_evidence,
                "source_window": source_window,
                "match_basis": _string(
                    match.get("match_basis"), f"step_matches[{index}].match_basis", maximum=100, nullable=True
                ),
                "controls_found": _strings(match.get("controls_found"), f"step_matches[{index}].controls_found"),
            }
        )
    return projected, source_chars


def project_candidate(payload: bytes, candidate_id: str, repo_root: Path | None = None) -> dict[str, Any]:
    if not _CANDIDATE_RE.fullmatch(candidate_id):
        raise AbuseContextError(f"invalid abuse-case candidate id {candidate_id!r}")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AbuseContextError("abuse-case matches are not valid JSON") from exc
    matches = document.get("matches") if isinstance(document, dict) else None
    if not isinstance(matches, list) or len(matches) > 10000:
        raise AbuseContextError("abuse-case matches have no bounded matches array")
    selected = [row for row in matches if isinstance(row, dict) and row.get("abuse_case_id") == candidate_id]
    if len(selected) != 1:
        raise AbuseContextError(f"candidate {candidate_id} does not resolve to exactly one match")
    row = selected[0]
    if row.get("structural_verdict") not in {"candidate", "partial_candidate"}:
        raise AbuseContextError(f"candidate {candidate_id} is not eligible for verification")
    case = row.get("case")
    if not isinstance(case, dict) or case.get("id") != candidate_id:
        raise AbuseContextError(f"candidate {candidate_id} has no matching case definition")
    chain = _project_chain(case.get("chain"))
    attacker = case.get("attacker")
    if not isinstance(attacker, dict):
        raise AbuseContextError("candidate attacker must be an object")
    step_matches, source_chars = _project_step_matches(row.get("step_matches"), len(chain), repo_root=repo_root)
    value = {
        "schema_version": 1,
        "source": {
            "artifact_path": ".abuse-case-matches.json",
            "sha256": _sha256(payload),
            "candidate_id": candidate_id,
            "match_count": len(matches),
        },
        "limits": {
            "max_chain_steps": MAX_CHAIN_STEPS,
            "max_patterns_per_field": MAX_PATTERNS,
            "max_source_window_lines": MAX_SOURCE_WINDOW_LINES,
            "max_source_chars": MAX_SOURCE_WINDOW_CHARS,
            "source_chars": source_chars,
            "max_bytes": MAX_CONTEXT_BYTES,
            "serialized_bytes": 0,
        },
        "candidate": {
            "abuse_case_id": candidate_id,
            "title": _string(row.get("title"), "candidate.title", maximum=500),
            "source": _string(case.get("source"), "candidate.source", maximum=100),
            "structural_verdict": row.get("structural_verdict"),
            "reason": _string(row.get("reason"), "candidate.reason", maximum=2000, nullable=True),
            "attacker": {
                "actor_id": _string(attacker.get("actor_id"), "candidate.attacker.actor_id", maximum=200),
                "initial_access": attacker.get("initial_access"),
                "prerequisite": _string(
                    attacker.get("prerequisite"), "candidate.attacker.prerequisite", maximum=2000, nullable=True
                ),
            },
            "goal": _string(case.get("goal"), "candidate.goal", maximum=2000),
            "chain": chain,
            "step_matches": step_matches,
        },
    }
    return value


def _payload(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=False) + "\n").encode("utf-8")


def write_candidate(output_dir: Path, candidate_id: str, repo_root: Path | None = None) -> Path:
    source = output_dir / ".abuse-case-matches.json"
    value = project_candidate(source.read_bytes(), candidate_id, repo_root=repo_root)
    target_dir = output_dir / ".dispatch-context" / "abuse-cases"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{candidate_id}.json"
    for _ in range(3):
        value["limits"]["serialized_bytes"] = len(_payload(value))
    if len(_payload(value)) > MAX_CONTEXT_BYTES:
        raise AbuseContextError(f"candidate {candidate_id} exceeds the {MAX_CONTEXT_BYTES}-byte cap")
    atomic_write_json(target, value, sort_keys=False)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--candidate", action="append", required=True)
    parser.add_argument("--repo-root", type=Path)
    args = parser.parse_args(argv)
    if len(args.candidate) > MAX_CANDIDATES:
        print(f"build_abuse_case_contexts: maximum is {MAX_CANDIDATES} candidates", file=sys.stderr)
        return 1
    try:
        repo_root = args.repo_root.resolve() if args.repo_root else None
        paths = [write_candidate(args.output_dir.resolve(), candidate, repo_root) for candidate in args.candidate]
    except (OSError, AbuseContextError) as exc:
        print(f"build_abuse_case_contexts: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"artifacts": [str(path) for path in paths]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
