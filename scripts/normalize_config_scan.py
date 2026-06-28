#!/usr/bin/env python3
"""Deterministic post-pass over ``.config-scan-findings.json``.

The config-scanner is an LLM agent; it occasionally emits ``generated_at`` with
sub-second precision (e.g. ``2026-06-27T17:25:34.082802Z``). Every other sidecar
— and ``config-scan-findings.schema.yaml`` — uses whole-second UTC
(``%Y-%m-%dT%H:%M:%SZ``). Strip the sub-second precision deterministically before
the schema gate so the format is fixed at the producer boundary rather than by
relaxing the schema (AGENTS.md §12 — fix the producer, never loosen validation).

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
    before = data.get("generated_at")
    after = normalize_generated_at(before)
    if after == before:
        return False
    data["generated_at"] = after
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
