#!/usr/bin/env python3
"""
analyzers/scan_excludes.py — single source of truth for scan exclusions.

Two responsibilities, shared by the repository scanners, analyzers, and
context builders under scripts/:

1. Path exclusion policy loaded from data/scan-excludes.yaml:
   `is_excluded()` / `is_always_included()` per file, `is_oversize()` /
   `max_file_bytes()` for the per-file byte cap, and
   `glob_exclusion_string()` for the Grep `glob:` parameter agents use.

2. Assessment-output detection: `is_assessment_artifact()` and
   `assessment_output_prefixes()` find directories that hold a prior run's
   products (a threat-model.md/.yaml pair or two runtime markers) under any
   name, so scanners do not treat earlier reports as repository evidence.

3. Repository inventory: `repo_inventory()` lists the files that belong to the
   repository — tracked plus untracked files git does not ignore (repository
   `.gitignore`, `.git/info/exclude` and the user's `core.excludesFile`) —
   and records which are tracked. A developer's ignored local files, such as a
   personal agent settings file, are not repository evidence. It does not
   apply the exclusion policy above; callers that scan source apply
   `is_excluded()` on top, while the config scanner deliberately does not
   (its catalog targets files that policy drops, e.g. `package-lock.json`).
   Scanners that still walk the tree themselves: recon_patterns,
   route_inventory, db_privilege_separation, mass_assignment_scanner and
   _lib_manifest each pair the walk with their own
   skip sets and opt-ins; moving them onto this inventory changes what they
   see and needs its own verification.

Whitelist-wins rule: if a path matches `always_include`, it is NEVER
excluded — even if it matches a `directories` / `path_prefixes` /
`file_patterns` entry. This is how AsciiDoc source docs and OpenAPI
contracts survive aggressive `docs/*` or `examples/*` excludes.

CLI:
    python3 scripts/analyzers/scan_excludes.py glob              # emits the Grep glob string
    python3 scripts/analyzers/scan_excludes.py check <path>      # exit 0 if excluded, 1 if not
    python3 scripts/analyzers/scan_excludes.py glob SCAN_TEST_FILES  # opt-in: un-exclude the group

Exit codes:
  0 — success (or: path IS excluded, for `check`)
  1 — path is NOT excluded (for `check`)
  2 — bad args / missing file
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import fnmatch
import functools
import json
import os
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Iterable

from shared._paths import strip_dot_slash

try:
    import yaml
except ImportError:  # pragma: no cover - pyyaml is a hard dependency
    print("analyzers/scan_excludes.py: PyYAML is required", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Resolution of the YAML file
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parents[1]
_DEFAULT_YAML = _HERE.parent / "data" / "scan-excludes.yaml"

# Per-file byte cap applied when the YAML omits `max_file_bytes`. Files larger
# than this are almost never application source — see scan-excludes.yaml.
DEFAULT_MAX_FILE_BYTES = 1_000_000

_ASSESSMENT_RUNTIME_MARKERS = frozenset(
    {
        ".agent-run.log",
        ".appsec-checkpoint",
        ".context-routing-plan.json",
        ".hook-events.log",
        ".session-agent-map",
        ".skill-config.json",
        ".stage-stats.jsonl",
        ".stride-selection.json",
        ".threat-modeling-context.md",
    }
)
_ASSESSMENT_FINAL_PAIR = frozenset({"threat-model.md", "threat-model.yaml"})


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
    _assessment_output_prefixes.cache_clear()


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
    norm = strip_dot_slash(rel_path.replace("\\", "/"))
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


# ---------------------------------------------------------------------------
# Assessment-output detection
# ---------------------------------------------------------------------------


def is_assessment_output_dir(path: Path) -> bool:
    """Return whether ``path`` has the on-disk signature of a run output.

    Output directories are user-selectable, so a fixed ``docs/security/``
    prefix cannot protect recon from prior scans stored under another name.
    Require either the final Markdown/YAML pair or two independent runtime
    markers. A single similarly named project file is not enough.
    """
    try:
        mode = path.lstat().st_mode
        if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
            return False
        with os.scandir(path) as entries:
            names = {entry.name for entry in entries}
    except OSError:
        return False
    return _ASSESSMENT_FINAL_PAIR <= names or len(_ASSESSMENT_RUNTIME_MARKERS & names) >= 2


@functools.lru_cache(maxsize=8)
def _assessment_output_prefixes(repo_root: str) -> tuple[str, ...]:
    root = Path(repo_root)
    try:
        root = root.resolve(strict=True)
    except OSError:
        return ()
    found: list[str] = []
    for dirpath, dirnames, _filenames in os.walk(root, followlinks=False):
        kept: list[str] = []
        for dirname in sorted(dirnames):
            candidate = Path(dirpath) / dirname
            try:
                relative = candidate.relative_to(root).as_posix()
            except ValueError:
                continue
            if is_assessment_output_dir(candidate):
                found.append(relative)
                continue
            if candidate.is_symlink() or is_excluded(relative):
                continue
            kept.append(dirname)
        dirnames[:] = kept
    return tuple(sorted(found))


def assessment_output_prefixes(repo_root: Path | str) -> tuple[str, ...]:
    """Repo-relative directories that contain prior assessment products."""
    return _assessment_output_prefixes(str(Path(repo_root).resolve(strict=False)))


def is_assessment_artifact(rel_path: str, repo_root: Path | str) -> bool:
    """Return whether ``rel_path`` is inside a detected assessment output."""
    normalized = rel_path.replace("\\", "/").removeprefix("./")
    return any(
        normalized == prefix or normalized.startswith(prefix + "/") for prefix in assessment_output_prefixes(repo_root)
    )


# ---------------------------------------------------------------------------
# Repository inventory
# ---------------------------------------------------------------------------

INVENTORY_GIT = "git"
INVENTORY_WALK = "filesystem-walk"
_GIT_TIMEOUT_SECONDS = 120


class RepoInventory:
    """Repository files as repo-relative POSIX paths.

    ``files`` maps each path to whether git tracks it; the value is ``None``
    when the inventory came from a filesystem walk and tracking is unknown.
    ``source`` names how the inventory was built."""

    __slots__ = ("files", "source")

    def __init__(self, files: dict[str, bool | None], source: str) -> None:
        self.files = files
        self.source = source

    def __contains__(self, rel_path: object) -> bool:
        return rel_path in self.files

    def is_tracked(self, rel_path: str) -> bool | None:
        return self.files.get(rel_path)


def _git_paths(root: Path, *args: str) -> list[str] | None:
    try:
        proc = subprocess.run(
            ["git", "-c", "core.fsmonitor=", "-C", str(root), "ls-files", "-z", *args],
            capture_output=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return [path for path in proc.stdout.decode("utf-8", "surrogateescape").split("\0") if path]


def _git_files(root: Path, seen: set[Path]) -> dict[str, bool | None] | None:
    listed = _git_paths(root, "--cached", "--others", "--exclude-standard")
    tracked = _git_paths(root, "--cached")
    if listed is None or tracked is None:
        return None
    tracked_set = set(tracked)
    files: dict[str, bool | None] = {}
    for entry in listed:
        rel = entry.rstrip("/")
        path = root / rel
        if path.is_dir() and not path.is_symlink():
            # A submodule gitlink, or an untracked nested repository that git
            # lists as one directory entry: inventory it with its own rules.
            nested = _inventory_files(path, seen)[0]
            files.update({f"{rel}/{child}": status for child, status in nested.items()})
        elif path.is_file():
            files[rel] = rel in tracked_set
    return files


def _walk_files(root: Path) -> dict[str, bool | None]:
    files: dict[str, bool | None] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [name for name in dirnames if name != ".git"]
        base = Path(dirpath)
        for name in filenames:
            path = base / name
            if path.is_file():
                files[path.relative_to(root).as_posix()] = None
    return files


def _inventory_files(root: Path, seen: set[Path]) -> tuple[dict[str, bool | None], str]:
    if root in seen:
        return {}, INVENTORY_WALK
    seen.add(root)
    files = _git_files(root, seen)
    if files:
        return files, INVENTORY_GIT
    # Not a repository, git unavailable, or a directory git lists as empty
    # (for instance one an enclosing repository ignores): walk it instead of
    # reporting a non-empty directory as having no files.
    return _walk_files(root), INVENTORY_WALK


def repo_inventory(repo_root: Path | str) -> RepoInventory:
    """Files that belong to the repository at ``repo_root``; see module docstring §3.

    Not cached: callers build it once per scan, and a cached listing would go
    stale when files change between scans in one process."""
    root = Path(repo_root).resolve(strict=False)
    files, source = _inventory_files(root, set())
    kept = {rel: status for rel, status in files.items() if not is_assessment_artifact(rel, root)}
    return RepoInventory(kept, source)


# ---------------------------------------------------------------------------
# Per-file byte cap and Grep glob
# ---------------------------------------------------------------------------


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
    repo_root: Path | str | None = None,
) -> str:
    """Return a Grep `glob:` exclusion string for the given opt-in set.

    Format: `!{dir1,dir2,...}/**`. Directories contributed by enabled
    opt-in groups are subtracted from the default directory list. Directory
    detected assessment outputs are included. Configured path-prefix rules
    remain per-file checks so ``always_include`` can still override them.

    The output is deterministic (sorted directory list) so test fixtures
    remain stable.
    """
    excludes = excludes or load_excludes()
    directories = set(excludes.get("directories", []))
    for group_name in opt_ins:
        group = excludes.get("opt_in", {}).get(group_name, {})
        directories -= set(group.get("directories", []))
    if repo_root is not None:
        directories.update(assessment_output_prefixes(repo_root))
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
    p_glob.add_argument("--repo-root", type=Path, help="also exclude detected assessment output directories")

    p_check = sub.add_parser("check", help="Exit 0 iff the given path IS excluded")
    p_check.add_argument("path", help="repo-relative path to classify")
    p_check.add_argument("--opt-in", action="append", default=[], help="opt-in group name")

    p_dump = sub.add_parser("dump", help="Dump the loaded excludes as JSON")

    args = parser.parse_args(argv)

    try:
        excludes = load_excludes()
    except (FileNotFoundError, ValueError) as e:
        print(f"analyzers/scan_excludes.py: {e}", file=sys.stderr)
        return 2

    if args.cmd == "glob":
        print(glob_exclusion_string(args.opt_ins, excludes, repo_root=args.repo_root))
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
