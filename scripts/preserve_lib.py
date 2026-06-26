#!/usr/bin/env python3
"""Shared helpers for depth-downgrade section preservation.

Single source of truth for:
  * the depth ranking used to decide "is the current run shallower than the
    snapshot's origin?"
  * the set of PRESERVABLE sections, read from the declarative
    ``preserve_on_downgrade:`` block in ``data/sections-contract.yaml``.

Both snapshot_preserved_sections.py and restore_preserved_sections.py enumerate
``preservable_sections()`` instead of hard-coding which sections they handle, so
adding a new deep-only section to preserve is a contract edit with zero code
change. (2026-06-26)
"""

from __future__ import annotations

from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

# quick < standard < thorough. Gaps left intentionally so a future depth can
# slot between without renumbering. Unknown → -1 (never "deeper than" anything).
DEPTH_RANK = {"quick": 0, "standard": 2, "thorough": 3}


def depth_rank(depth: str | None) -> int:
    return DEPTH_RANK.get((depth or "").strip().lower(), -1)


def preservable_sections(plugin_root: Path) -> list[dict]:
    """Return the declared preservable sections from the section contract.

    Each entry is normalized to::

        {
          "id": str,
          "substrate": "fragment" | "md-slice",
          "fragment": str | None,          # for substrate == fragment
          "md_section_number": int | None, # for substrate == md-slice
          "source_globs": list[str],       # optional staleness inputs
        }

    Reads the top-level ``preserve_on_downgrade:`` list in
    ``data/sections-contract.yaml``. Returns [] if the contract or block is
    absent (callers then no-op safely).
    """
    if yaml is None:
        return []
    contract_path = plugin_root / "data" / "sections-contract.yaml"
    if not contract_path.is_file():
        return []
    try:
        contract = yaml.safe_load(contract_path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return []
    raw = contract.get("preserve_on_downgrade") or []
    out: list[dict] = []
    for e in raw:
        if not isinstance(e, dict) or not e.get("id"):
            continue
        substrate = (e.get("substrate") or "fragment").strip().lower()
        out.append(
            {
                "id": e["id"],
                "substrate": substrate,
                "fragment": e.get("fragment"),
                "md_section_number": e.get("md_section_number"),
                "source_globs": e.get("source_globs") or [],
            }
        )
    return out


def source_fingerprint(repo_root: Path, globs: list[str]) -> str:
    """A stable hash of the repo files matching ``globs`` — used to detect when
    the code a preserved section describes has CHANGED since capture, so a stale
    carried section can be dropped rather than shown as current. Empty string
    when no globs are given (staleness check disabled for that section)."""
    if not globs or not repo_root.is_dir():
        return ""
    import hashlib

    h = hashlib.sha256()
    files: list[Path] = []
    for g in globs:
        files.extend(sorted(repo_root.glob(g)))
    for f in sorted(set(files)):
        if f.is_file():
            try:
                h.update(f.relative_to(repo_root).as_posix().encode())
                h.update(f.read_bytes())
            except (OSError, ValueError):
                continue
    return h.hexdigest()
