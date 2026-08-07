#!/usr/bin/env python3
"""Deterministic post-pass over ``.config-scan-findings.json``.

The config-scanner is an LLM agent; it occasionally emits ``generated_at`` with
sub-second precision or strips the canonical ``CWE-`` prefix while projecting
checks from ``data/config-iac-checks.yaml``. Canonicalize those lossless format
drifts before the schema gate rather than relaxing the delivered contract.

Idempotent: a file already in canonical form is left untouched (no rewrite).
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from _atomic_io import atomic_write_json

# Whole-second prefix, with optional sub-second fraction and optional
# trailing 'Z' / numeric offset that we collapse to a bare 'Z'.
_ISO_SUBSECOND_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$")


def normalize_generated_at(value: Any) -> Any:
    """Return ``value`` with sub-second precision stripped and a trailing ``Z``.

    Non-string or unrecognised values are returned unchanged.
    """
    if not isinstance(value, str):
        return value
    m = _ISO_SUBSECOND_RE.match(value.strip())
    if not m:
        return value
    return m.group(1) + "Z"


def normalize_cwe(value: Any) -> Any:
    """Restore canonical CWE prefixes on list items without inventing IDs."""
    if not isinstance(value, list):
        return value
    normalized: list[Any] = []
    for item in value:
        if isinstance(item, int) and item >= 0:
            normalized.append(f"CWE-{item}")
        elif isinstance(item, str) and item.strip().isdigit():
            normalized.append(f"CWE-{item.strip()}")
        else:
            normalized.append(item)
    return normalized


def normalize_file(path: Path) -> bool:
    """Normalize ``generated_at`` in the JSON object at ``path``.

    Returns True when the file was rewritten, False when unchanged or absent.
    Key order is preserved (``sort_keys=False``) to minimise churn.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    changed = False
    before = data.get("generated_at")
    after = normalize_generated_at(before)
    if after != before:
        data["generated_at"] = after
        changed = True
    findings = data.get("findings")
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            before_cwe = finding.get("cwe")
            after_cwe = normalize_cwe(before_cwe)
            if after_cwe != before_cwe:
                finding["cwe"] = after_cwe
                changed = True
    if not changed:
        return False
    atomic_write_json(path, data, sort_keys=False)
    return True


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("path", type=Path, help="Path to .config-scan-findings.json")
    args = p.parse_args(argv)
    normalize_file(args.path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
