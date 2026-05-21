#!/usr/bin/env python3
"""sanitize_perimeter_claims.py — strip speculative perimeter-absence claims
from threat-model.yaml fields the LLM tends to over-author.

The threat-analyst Phase 7 prompt explicitly forbids absence claims about
deployment-time controls (WAF, IDS, network firewall, API gateway, …) in
`trust_boundaries[].enforcement` and `security_controls[].notes`. Despite
the prompt rule, the LLM occasionally emits them anyway. The post-compose
qa_check `unfounded_perimeter_claims` catches the problem in the rendered
Markdown but is NOT part of `repair_plan`, so the violation slips past the
skill's contract gate.

This deterministic pre-compose sanitizer uses the shared regex set from
`scripts/perimeter_patterns.py` and rewrites matching segments of the YAML
in-place. Idempotent — running twice yields the same output.

Fields scrubbed (in this order):
  - trust_boundaries[].enforcement
  - trust_boundaries[].description
  - security_controls[].notes
  - security_controls[].implementation
  - security_controls[].effectiveness_rationale

A matching segment is dropped (if it's a comma/semicolon-separated
sub-clause) or replaced with a neutral marker (if it consumes the whole
field). The script writes a structured summary to stderr and exits 0 on
success, 1 on IO/parse error, 2 on bad arguments.

Usage:
    python3 sanitize_perimeter_claims.py <output_dir>
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

from perimeter_patterns import PERIMETER_ABSENCE_PATTERNS as _PERIMETER_ABSENCE_PATTERNS

# Single neutral replacement appended exactly once when a field is fully
# scrubbed (i.e. nothing left after removing every matched sub-clause).
_NEUTRAL_TAIL = "deployment-time perimeter controls out of scope for source-tree review"


def _sanitize_string(value: str) -> tuple[str, list[str]]:
    """Return (cleaned_string, removed_tokens). Idempotent."""
    if not isinstance(value, str) or not value.strip():
        return value, []

    removed: list[str] = []
    # Split into sub-clauses on `;` or `,`. Preserve original separators in
    # the output so the surrounding prose stays natural-looking.
    parts = re.split(r"(\s*[;,]\s*)", value)
    cleaned_parts: list[str] = []
    i = 0
    while i < len(parts):
        chunk = parts[i]
        # Separator chunks always have odd index; pass them through unless
        # the previous chunk was removed (in which case we drop the
        # separator too).
        if i % 2 == 1:
            cleaned_parts.append(chunk)
            i += 1
            continue
        hit_token: str | None = None
        for token, pat in _PERIMETER_ABSENCE_PATTERNS:
            if pat.search(chunk):
                hit_token = token
                break
        if hit_token is None:
            cleaned_parts.append(chunk)
        else:
            removed.append(hit_token)
            # Drop this chunk AND the immediately preceding separator (if any)
            # to avoid double commas/semicolons.
            if cleaned_parts and cleaned_parts[-1].strip() in {",", ";"}:
                cleaned_parts.pop()
        i += 1

    cleaned = "".join(cleaned_parts).strip().rstrip(",;").strip()

    if removed and not cleaned:
        # Whole field was speculative — replace with the neutral marker so
        # downstream renderers (architecture-diagrams.md, §2.4 trust-boundary
        # table) still have content.
        cleaned = _NEUTRAL_TAIL
    elif removed and _NEUTRAL_TAIL not in cleaned.lower():
        # Append the neutral marker so the reader knows perimeter controls
        # weren't simply forgotten — they're out of scope.
        sep = "; " if not cleaned.endswith((".", ";", ",")) else " "
        cleaned = f"{cleaned}{sep}{_NEUTRAL_TAIL}"

    return cleaned, removed


_TARGETS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("trust_boundaries", ("enforcement", "description")),
    ("security_controls", ("notes", "implementation", "effectiveness_rationale")),
)


def sanitize_yaml(data: dict) -> tuple[dict, list[dict]]:
    """Return (mutated_data, change_records). change_records describe what
    was rewritten — used for the stderr summary and for future test assertions.
    """
    changes: list[dict] = []
    for collection_key, field_names in _TARGETS:
        items = data.get(collection_key) or []
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            for field_name in field_names:
                original = item.get(field_name)
                if not isinstance(original, str):
                    continue
                cleaned, removed = _sanitize_string(original)
                if removed:
                    item[field_name] = cleaned
                    changes.append({
                        "collection": collection_key,
                        "id": item.get("id") or item.get("name") or "<anon>",
                        "field": field_name,
                        "removed_tokens": removed,
                        "before": original,
                        "after": cleaned,
                    })
    return data, changes


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: sanitize_perimeter_claims.py <output_dir>", file=sys.stderr)
        return 2
    output_dir = Path(argv[0])
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"sanitize_perimeter_claims: no yaml at {yaml_path}", file=sys.stderr)
        return 1
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        print(f"sanitize_perimeter_claims: could not parse {yaml_path}: {exc}", file=sys.stderr)
        return 1
    if not isinstance(data, dict):
        print(f"sanitize_perimeter_claims: {yaml_path} did not parse to a mapping", file=sys.stderr)
        return 1

    data, changes = sanitize_yaml(data)

    if changes:
        yaml_path.write_text(
            yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096,
                           default_flow_style=False),
            encoding="utf-8",
        )
        summary: dict[tuple[str, str], int] = {}
        for c in changes:
            key = (c["collection"], c["field"])
            summary[key] = summary.get(key, 0) + 1
        details = ", ".join(f"{coll}.{field}×{n}" for (coll, field), n in summary.items())
        tokens = sorted({tok for c in changes for tok in c["removed_tokens"]})
        print(
            f"sanitize_perimeter_claims: scrubbed {len(changes)} field(s) "
            f"[{details}]; tokens={','.join(tokens)}"
        )
    else:
        print("sanitize_perimeter_claims: no speculative perimeter claims found — nothing to scrub")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
