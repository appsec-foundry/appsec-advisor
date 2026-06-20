#!/usr/bin/env python3
"""
scan_excludes.py — single source of truth for scan exclusions.

Loaded from data/scan-excludes.yaml. Three consumers:

1. Recon-scanner and stride-analyzer agents call `glob_exclusion_string()`
   to build the Grep `glob:` parameter that excludes irrelevant paths.

2. `security_relevance_filter.py` calls `is_excluded()` per file during
   incremental-mode dirty-set classification.

3. Tests call `load_excludes()` to validate the contract and to drive
   drift guards.

Whitelist-wins rule: if a path matches `always_include`, it is NEVER
excluded — even if it matches a `directories` / `path_prefixes` /
`file_patterns` entry. This is how AsciiDoc source docs and OpenAPI
contracts survive aggressive `docs/*` or `examples/*` excludes.

CLI:
    python3 scripts/scan_excludes.py glob              # emits the Grep glob string
    python3 scripts/scan_excludes.py check <path>      # exit 0 if excluded, 1 if not
    python3 scripts/scan_excludes.py glob SCAN_TEST_FILES  # opt-in: un-exclude the group

Exit codes:
  0 — success (or: path IS excluded, for `check`)
  1 — path is NOT excluded (for `check`)
  2 — bad args / missing file
"""

from __future__ import annotations

import argparse
import fnmatch
import functools
import json
import os
import sys
from pathlib import Path, PurePosixPath
from typing import Iterable

try:
    import yaml
except ImportError:  # pragma: no cover - pyyaml is a hard dependency
    print("scan_excludes.py: PyYAML is required", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Resolution of the YAML file
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent
_DEFAULT_YAML = _HERE.parent / "data" / "scan-excludes.yaml"

# Per-file byte cap applied when the YAML omits `max_file_bytes`. Files larger
# than this are almost never application source — see scan-excludes.yaml.
DEFAULT_MAX_FILE_BYTES = 1_000_000


def _yaml_path() -> Path:
    """Resolve the scan-excludes.yaml location.

    Priority: SCAN_EXCLUDES_YAML env var (test override) →
    $CLAUDE_PLUGIN_ROOT/data/scan-excludes.yaml → sibling of this script.
    """
    override = os.environ.get("SCAN_EXCLUDES_YAML")
    if override:
        return Path(override)
    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if plugin_root:
        candidate = Path(plugin_root) / "data" / "scan-excludes.yaml"
        if candidate.is_file():
            return candidate
    return _DEFAULT_YAML


# ---------------------------------------------------------------------------
# Loader (cached)
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=4)
def load_excludes(yaml_path_str: str | None = None) -> dict:
    """Load and validate the excludes YAML. Cached per path."""
    path = Path(yaml_path_str) if yaml_path_str else _yaml_path()
    if not path.is_file():
        raise FileNotFoundError(f"scan-excludes.yaml not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"scan-excludes.yaml: expected top-level mapping, got {type(data).__name__}")
    if data.get("version") != 1:
        raise ValueError(f"scan-excludes.yaml: unsupported version {data.get('version')!r} (expected 1)")

    # Normalise: missing keys → empty collections
    for key in ("directories", "path_prefixes", "file_patterns"):
        data.setdefault(key, [])
        if not isinstance(data[key], list):
            raise ValueError(f"scan-excludes.yaml: {key!r} must be a list")
    data.setdefault("always_include", {})
    for key in ("file_patterns", "path_prefixes"):
        data["always_include"].setdefault(key, [])
    data.setdefault("opt_in", {})

    # Per-file byte cap. Missing → default; must be a plain integer.
    cap = data.setdefault("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
    if isinstance(cap, bool) or not isinstance(cap, int):
        raise ValueError("scan-excludes.yaml: max_file_bytes must be an integer")

    return data


def _reset_cache_for_tests() -> None:
    """Drop the cache so tests can switch yaml fixtures in the same process."""
    load_excludes.cache_clear()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _iter_path_parts(rel_path: str) -> list[str]:
    p = PurePosixPath(rel_path.replace("\\", "/"))
    return [part for part in p.parts if part not in (".", "")]


def _basename(rel_path: str) -> str:
    return _iter_path_parts(rel_path)[-1] if _iter_path_parts(rel_path) else ""


def _matches_file_pattern(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(name, pat) for pat in patterns)


def _matches_path_prefix(rel_path: str, prefixes: Iterable[str]) -> bool:
    norm = rel_path.replace("\\", "/")
    # Strip leading "./" only — NOT lstrip("./"), which would eat a leading
    # "." from paths like ".github/foo" (hidden-directory names).
    if norm.startswith("./"):
        norm = norm[2:]
    return any(norm.startswith(prefix) for prefix in prefixes)


def is_always_included(rel_path: str, excludes: dict | None = None) -> bool:
    """Whitelist check. Returns True iff the path matches always_include."""
    excludes = excludes or load_excludes()
    ai = excludes.get("always_include", {})
    name = _basename(rel_path)
    if _matches_file_pattern(name, ai.get("file_patterns", [])):
        return True
    if _matches_path_prefix(rel_path, ai.get("path_prefixes", [])):
        return True
    return False


def is_excluded(
    rel_path: str,
    opt_ins: Iterable[str] = (),
    excludes: dict | None = None,
) -> bool:
    """Return True iff `rel_path` should be excluded from security scans.

    `opt_ins` is an iterable of opt-in group names (e.g. `SCAN_TEST_FILES`);
    anything listed in an enabled group is NOT treated as excluded even if
    it would otherwise match one of the directory / file-pattern rules.

    Whitelist rule: `always_include` WINS over every exclusion.
    """
    excludes = excludes or load_excludes()
    opt_ins_set = set(opt_ins)

    # 1. Whitelist always wins.
    if is_always_included(rel_path, excludes):
        return False

    # 2. Opt-in relief.
    for group_name in opt_ins_set:
        group = excludes.get("opt_in", {}).get(group_name)
        if not group:
            continue
        parts = _iter_path_parts(rel_path)
        if any(part in group.get("directories", []) for part in parts):
            return False
        if _matches_file_pattern(_basename(rel_path), group.get("file_patterns", [])):
            return False

    # 3. Directory segments.
    parts = _iter_path_parts(rel_path)
    dirs = set(excludes.get("directories", []))
    if any(part in dirs for part in parts):
        return True

    # 4. Path prefixes.
    if _matches_path_prefix(rel_path, excludes.get("path_prefixes", [])):
        return True

    # 5. File basename patterns.
    if _matches_file_pattern(_basename(rel_path), excludes.get("file_patterns", [])):
        return True

    return False


def max_file_bytes(excludes: dict | None = None) -> int:
    """Resolve the per-file byte cap for scans.

    Precedence: ``APPSEC_MAX_FILE_BYTES`` env var → ``max_file_bytes`` in
    scan-excludes.yaml → :data:`DEFAULT_MAX_FILE_BYTES`. A value ``<= 0``
    disables the cap (no file is treated as oversize). An unparseable env
    value is ignored in favour of the configured value.
    """
    env = os.environ.get("APPSEC_MAX_FILE_BYTES")
    if env is not None and env.strip():
        try:
            return int(env)
        except ValueError:
            pass
    excludes = excludes or load_excludes()
    val = excludes.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
    try:
        return int(val)
    except (TypeError, ValueError):  # pragma: no cover - load_excludes validates
        return DEFAULT_MAX_FILE_BYTES


def is_oversize(path, limit: int | None = None) -> bool:
    """Return True iff *path* exceeds the configured byte cap.

    A cap ``<= 0`` disables the check. Stat failures return ``False`` so a
    transient error never silently drops a file from the scan.
    """
    cap = max_file_bytes() if limit is None else limit
    if cap <= 0:
        return False
    try:
        return os.path.getsize(path) > cap
    except OSError:
        return False


def glob_exclusion_string(
    opt_ins: Iterable[str] = (),
    excludes: dict | None = None,
) -> str:
    """Return a Grep `glob:` exclusion string for the given opt-in set.

    Format: `!{dir1,dir2,...}/**`. Directories contributed by enabled
    opt-in groups are subtracted from the default directory list.

    The output is deterministic (sorted directory list) so test fixtures
    remain stable.
    """
    excludes = excludes or load_excludes()
    directories = set(excludes.get("directories", []))
    for group_name in opt_ins:
        group = excludes.get("opt_in", {}).get(group_name, {})
        directories -= set(group.get("directories", []))
    if not directories:
        return ""
    return "!{" + ",".join(sorted(directories)) + "}/**"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="scan_excludes.py", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_glob = sub.add_parser("glob", help="Emit the Grep glob exclusion string")
    p_glob.add_argument("opt_ins", nargs="*", help="opt-in group names (e.g. SCAN_TEST_FILES)")

    p_check = sub.add_parser("check", help="Exit 0 iff the given path IS excluded")
    p_check.add_argument("path", help="repo-relative path to classify")
    p_check.add_argument("--opt-in", action="append", default=[], help="opt-in group name")

    p_dump = sub.add_parser("dump", help="Dump the loaded excludes as JSON")

    args = parser.parse_args(argv)

    try:
        excludes = load_excludes()
    except (FileNotFoundError, ValueError) as e:
        print(f"scan_excludes.py: {e}", file=sys.stderr)
        return 2

    if args.cmd == "glob":
        print(glob_exclusion_string(args.opt_ins, excludes))
        return 0
    if args.cmd == "check":
        excluded = is_excluded(args.path, args.opt_in, excludes)
        print("excluded" if excluded else "included")
        return 0 if excluded else 1
    if args.cmd == "dump":
        print(json.dumps(excludes, indent=2, sort_keys=True))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
