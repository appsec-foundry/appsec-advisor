#!/usr/bin/env python3
"""repo_profile.py — deterministic repository profile: size, tech stack, layout.

Answers "what am I about to scan?" before a run costs anything: how large the
working tree is, which languages carry it, which build manifests it declares
and whether those sit in one root or many. No agents, no LLM, no network, and
nothing written into the target repository.

This is not a security check. It says nothing about findings, severity or risk
— ``security_score.py`` and ``/appsec-advisor:create-threat-model`` do that.

Determinism
-----------
Two runs over the same tree print the same bytes:

  * sizes are ``st_size`` sums, never ``du``, which reports allocated blocks and
    so answers differently for the identical tree on another filesystem.
  * every list is sorted explicitly with ties broken by name, so filesystem walk
    order never reaches the output.
  * no file content is read, so encoding, line endings and locale cannot move a
    number.

Speed comes from the same decision: one ``os.scandir`` pass, one ``lstat`` per
entry, no second pass over anything.

Working tree versus tracked
---------------------------
The headline describes the working tree, because that is what a scan reads. A
repository that was built once carries ``node_modules`` or ``target`` and the
scan sees them. Where the target is a git repository the tracked subset is
reported beside it: that half is reproducible from a commit, the rest depends
on who built what before the profile ran.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

GIT_TIMEOUT = 30

# Path segments whose content is not the repository's own code: installed
# dependencies, build output, caches. Counted and reported, but kept out of the
# language split — a repository is not 94% JavaScript because npm put it there.
VENDOR_DIRS = frozenset(
    {
        ".gradle",
        ".mvn",
        ".next",
        ".nuxt",
        ".terraform",
        ".tox",
        ".venv",
        "__pycache__",
        "bower_components",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "obj",
        "out",
        "site-packages",
        "target",
        "third_party",
        "vendor",
        "venv",
    }
)

# Extension → (language, category). The category exists for one decision only:
# whether the repository holds source at all. "code" counts, the rest does not.
EXTENSIONS: dict[str, tuple[str, str]] = {
    # code
    ".bash": ("Shell", "code"),
    ".c": ("C", "code"),
    ".cc": ("C++", "code"),
    ".cjs": ("JavaScript", "code"),
    ".cpp": ("C++", "code"),
    ".cs": ("C#", "code"),
    ".css": ("CSS", "code"),
    ".cxx": ("C++", "code"),
    ".dart": ("Dart", "code"),
    ".erl": ("Erlang", "code"),
    ".ex": ("Elixir", "code"),
    ".exs": ("Elixir", "code"),
    ".go": ("Go", "code"),
    ".gradle": ("Gradle", "code"),
    ".groovy": ("Groovy", "code"),
    ".h": ("C/C++ header", "code"),
    ".hpp": ("C++ header", "code"),
    ".htm": ("HTML", "code"),
    ".html": ("HTML", "code"),
    ".ipynb": ("Jupyter", "code"),
    ".java": ("Java", "code"),
    ".js": ("JavaScript", "code"),
    ".jsx": ("JavaScript (JSX)", "code"),
    ".kt": ("Kotlin", "code"),
    ".kts": ("Kotlin", "code"),
    ".less": ("CSS (Less)", "code"),
    ".lua": ("Lua", "code"),
    ".m": ("Objective-C", "code"),
    ".mjs": ("JavaScript", "code"),
    ".php": ("PHP", "code"),
    ".pl": ("Perl", "code"),
    ".proto": ("Protobuf", "code"),
    ".ps1": ("PowerShell", "code"),
    ".py": ("Python", "code"),
    ".rb": ("Ruby", "code"),
    ".rs": ("Rust", "code"),
    ".sass": ("CSS (Sass)", "code"),
    ".scala": ("Scala", "code"),
    ".scss": ("CSS (Sass)", "code"),
    ".sh": ("Shell", "code"),
    ".sql": ("SQL", "code"),
    ".svelte": ("Svelte", "code"),
    ".swift": ("Swift", "code"),
    ".tf": ("Terraform", "code"),
    ".ts": ("TypeScript", "code"),
    ".tsx": ("TypeScript (TSX)", "code"),
    ".vue": ("Vue", "code"),
    # configuration
    ".cfg": ("INI/CFG", "config"),
    ".conf": ("Config", "config"),
    ".ini": ("INI/CFG", "config"),
    ".json": ("JSON", "config"),
    ".properties": ("Properties", "config"),
    ".toml": ("TOML", "config"),
    ".xml": ("XML", "config"),
    ".yaml": ("YAML", "config"),
    ".yml": ("YAML", "config"),
    # documentation
    ".adoc": ("AsciiDoc", "docs"),
    ".md": ("Markdown", "docs"),
    ".rst": ("reStructuredText", "docs"),
    ".txt": ("Text", "docs"),
    # data and binaries
    ".csv": ("CSV", "data"),
    ".eot": ("Font", "data"),
    ".gif": ("Image", "data"),
    ".gz": ("Archive", "data"),
    ".ico": ("Image", "data"),
    ".jar": ("Archive", "data"),
    ".jpeg": ("Image", "data"),
    ".jpg": ("Image", "data"),
    ".mp3": ("Media", "data"),
    ".mp4": ("Media", "data"),
    ".pdf": ("PDF", "data"),
    ".png": ("Image", "data"),
    ".svg": ("Image", "data"),
    ".tar": ("Archive", "data"),
    ".tgz": ("Archive", "data"),
    ".tsv": ("CSV", "data"),
    ".ttf": ("Font", "data"),
    ".war": ("Archive", "data"),
    ".wav": ("Media", "data"),
    ".webp": ("Image", "data"),
    ".whl": ("Archive", "data"),
    ".woff": ("Font", "data"),
    ".woff2": ("Font", "data"),
    ".zip": ("Archive", "data"),
}

# Files that carry a language without an extension.
FILENAMES: dict[str, tuple[str, str]] = {
    "Dockerfile": ("Dockerfile", "config"),
    "Jenkinsfile": ("Groovy", "code"),
    "Makefile": ("Make", "code"),
    "Rakefile": ("Ruby", "code"),
}

# Build manifests, by exact filename. Their directories are the repository's
# real layout: one root is a service, many roots are a monorepo, and the scan
# costs accordingly.
MANIFESTS: dict[str, str] = {
    "Cargo.toml": "Cargo",
    "Gemfile": "Bundler",
    "Pipfile": "Python",
    "build.gradle": "Gradle",
    "build.gradle.kts": "Gradle",
    "composer.json": "Composer",
    "go.mod": "Go",
    "mix.exs": "Mix",
    "package.json": "npm",
    "pom.xml": "Maven",
    "pubspec.yaml": "Pub",
    "pyproject.toml": "Python",
    "requirements.txt": "Python",
    "setup.py": "Python",
}

# Manifests identified by suffix rather than by name.
MANIFEST_SUFFIXES: dict[str, str] = {
    ".csproj": ".NET",
    ".sln": ".NET",
}

# A language under this share of the source bytes is folded into the remainder
# line: a 0.2% row is noise, and the reader is deciding scan depth, not writing
# a bill of materials.
MIN_LANGUAGE_SHARE = 1.0
MAX_LANGUAGE_ROWS = 10

# Manifest directories printed per ecosystem before the rest is summarised.
MAX_MANIFEST_DIRS = 3

# Above this share of the working tree, installed dependencies and build output
# dominate what the scan walks, and the language split describes little.
VENDOR_NOTE_SHARE = 30.0
MAX_VENDOR_DIRS_NAMED = 4


def scan_tree(root: Path) -> tuple[list[tuple[str, int]], int]:
    """Walk the working tree once. Returns (relpath, size) pairs and a symlink count.

    ``.git`` is pruned everywhere — its object store is git's bookkeeping, not
    the repository's content, and a shallow clone would report a different size
    for the same commit. Symlinks are counted but never followed: a link out of
    the tree would otherwise inflate the profile with another directory, and a
    cycle would not terminate.
    """
    files: list[tuple[str, int]] = []
    symlinks = 0
    stack: list[tuple[str, str]] = [(str(root), "")]

    while stack:
        abs_dir, rel_dir = stack.pop()
        try:
            entries = list(os.scandir(abs_dir))
        except OSError:
            continue
        for entry in entries:
            rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
            try:
                if entry.is_symlink():
                    symlinks += 1
                    continue
                if entry.is_dir():
                    if entry.name == ".git":
                        continue
                    stack.append((entry.path, rel))
                    continue
                if not entry.is_file():
                    continue
                files.append((rel, entry.stat().st_size))
            except OSError:
                continue

    files.sort()
    return files, symlinks


def _git(root: Path, *args: str) -> str | None:
    """Run a read-only git command in ``root``; None when git says no.

    ``core.fsmonitor`` is cleared: the setting names a program git starts, it
    can be set in a repository's own ``.git/config``, and the target repository
    is untrusted input here.
    """
    try:
        proc = subprocess.run(
            ["git", "-c", "core.fsmonitor=", "-C", str(root), *args],
            capture_output=True,
            timeout=GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", "surrogateescape")


def tracked_paths(root: Path) -> set[str] | None:
    """Paths git tracks under ``root``, or None when this is not a git repository."""
    out = _git(root, "ls-files", "-z")
    if out is None:
        return None
    return {path for path in out.split("\0") if path}


def head_commit(root: Path) -> str | None:
    out = _git(root, "rev-parse", "--short", "HEAD")
    return out.strip() if out else None


def is_vendored(rel_path: str) -> bool:
    return any(segment in VENDOR_DIRS for segment in rel_path.split("/")[:-1])


def classify(rel_path: str) -> tuple[str, str]:
    """(language, category) for a path. Unknown extensions land in Other/other."""
    name = rel_path.rsplit("/", 1)[-1]
    if name in FILENAMES:
        return FILENAMES[name]
    dot = name.rfind(".")
    if dot > 0:
        ext = name[dot:].lower()
        if ext in EXTENSIONS:
            return EXTENSIONS[ext]
    return ("Other", "other")


def manifest_ecosystem(rel_path: str) -> str | None:
    name = rel_path.rsplit("/", 1)[-1]
    if name in MANIFESTS:
        return MANIFESTS[name]
    for suffix, ecosystem in MANIFEST_SUFFIXES.items():
        if name.lower().endswith(suffix):
            return ecosystem
    return None


def _directory(rel_path: str) -> str:
    head = rel_path.rsplit("/", 1)[0] if "/" in rel_path else ""
    return head or "."


def profile(root: Path) -> dict[str, Any]:
    """The whole profile as plain data. Rendering and JSON both read this."""
    files, symlinks = scan_tree(root)
    tracked = tracked_paths(root)

    total_bytes = sum(size for _, size in files)
    vendored = [(path, size) for path, size in files if is_vendored(path)]
    vendored_bytes = sum(size for _, size in vendored)
    source = [(path, size) for path, size in files if not is_vendored(path)]
    source_bytes = sum(size for _, size in source)
    vendor_present = sorted(
        {segment for path, _ in vendored for segment in path.split("/")[:-1] if segment in VENDOR_DIRS}
    )

    lang_files: dict[str, int] = {}
    lang_bytes: dict[str, int] = {}
    lang_category: dict[str, str] = {}
    code_bytes = 0
    for path, size in source:
        language, category = classify(path)
        lang_files[language] = lang_files.get(language, 0) + 1
        lang_bytes[language] = lang_bytes.get(language, 0) + size
        lang_category[language] = category
        if category == "code":
            code_bytes += size

    languages = [
        {
            "language": language,
            "category": lang_category[language],
            "files": lang_files[language],
            "bytes": lang_bytes[language],
            "share": round(100.0 * lang_bytes[language] / source_bytes, 1) if source_bytes else 0.0,
        }
        for language in lang_bytes
    ]
    # Bytes first, name second: two languages of equal size must not swap places
    # between runs.
    languages.sort(key=lambda row: (-row["bytes"], row["language"]))

    manifests: dict[str, set[str]] = {}
    manifest_roots: set[str] = set()
    for path, _ in source:
        ecosystem = manifest_ecosystem(path)
        if ecosystem is None:
            continue
        directory = _directory(path)
        manifests.setdefault(ecosystem, set()).add(directory)
        manifest_roots.add(directory)

    result: dict[str, Any] = {
        "repo": str(root),
        "git": tracked is not None,
        "head": head_commit(root),
        "totals": {
            "files": len(files),
            "bytes": total_bytes,
            "source_files": len(source),
            "source_bytes": source_bytes,
            "vendored_files": len(vendored),
            "vendored_bytes": vendored_bytes,
            "code_bytes": code_bytes,
            "symlinks": symlinks,
        },
        "languages": languages,
        "vendor_dirs": vendor_present,
        "manifests": [
            {"ecosystem": ecosystem, "directories": sorted(directories)}
            for ecosystem, directories in sorted(manifests.items())
        ],
        "manifest_roots": len(manifest_roots),
    }

    if tracked is not None:
        tracked_files = [(path, size) for path, size in files if path in tracked]
        result["tracked"] = {
            "files": len(tracked_files),
            "bytes": sum(size for _, size in tracked_files),
            "untracked_files": len(files) - len(tracked_files),
        }

    result["notes"] = build_notes(result)
    return result


def build_notes(result: dict[str, Any]) -> list[str]:
    """What the numbers mean for the decision the reader is about to make."""
    notes: list[str] = []
    totals = result["totals"]

    if not result["git"]:
        notes.append(
            "not a git repository — every number describes the directory as it is on disk, "
            "and nothing here is reproducible from a commit"
        )
    else:
        untracked = result["tracked"]["untracked_files"]
        if untracked:
            notes.append(
                f"{untracked} of {totals['files']} files are untracked — a scan reads them, "
                "a fresh clone would not have them"
            )

    if totals["bytes"] and 100.0 * totals["vendored_bytes"] / totals["bytes"] >= VENDOR_NOTE_SHARE:
        share = round(100.0 * totals["vendored_bytes"] / totals["bytes"])
        named = ", ".join(result["vendor_dirs"][:MAX_VENDOR_DIRS_NAMED])
        notes.append(
            f"{share}% of the working tree is installed dependencies or build output ({named}) — "
            "the language split excludes it, the scan still walks it"
        )

    if totals["code_bytes"] == 0:
        notes.append("no source files detected — this looks like a documentation, configuration or data repository")

    if result["manifest_roots"] > 1:
        notes.append(
            f"{result['manifest_roots']} manifest directories — a monorepo, so a scan covers "
            "several components and costs accordingly"
        )

    if totals["symlinks"]:
        notes.append(f"{totals['symlinks']} symlink(s), not followed and not counted in the size")

    return notes


def _human(size: int) -> str:
    """1024-based, one decimal from KB up. Deterministic for a given byte count."""
    if size < 1024:
        return f"{size} B"
    value = float(size)
    for unit in ("KB", "MB", "GB", "TB"):
        value /= 1024.0
        if value < 1024.0 or unit == "TB":
            return f"{value:.1f} {unit}"
    return f"{value:.1f} TB"


def _files(count: int) -> str:
    return "1 file" if count == 1 else f"{count} files"


def render_text(result: dict[str, Any]) -> str:
    totals = result["totals"]
    lines = [f"Repository profile — {result['repo']}"]

    if result["git"]:
        tracked = result["tracked"]
        head = result["head"] or "no commit"
        basis = f"working tree at {head} · {tracked['files']} of {totals['files']} files tracked by git"
    else:
        basis = f"working tree · {totals['files']} files · not a git repository"
    lines += [f"  {basis}", ""]

    lines += [
        f"  size        {_human(totals['bytes']):>10}  {_files(totals['files'])}",
        f"  vendored    {_human(totals['vendored_bytes']):>10}  {_files(totals['vendored_files'])}",
        f"  source      {_human(totals['source_bytes']):>10}  {_files(totals['source_files'])}",
    ]

    shown = [row for row in result["languages"][:MAX_LANGUAGE_ROWS] if row["share"] >= MIN_LANGUAGE_SHARE]
    if shown:
        lines += ["", "  languages (share of source bytes)"]
        width = max(len(row["language"]) for row in shown)
        for row in shown:
            lines.append(
                f"    {row['language']:<{width}}  {row['share']:>5.1f}%  "
                f"{_human(row['bytes']):>10}  {_files(row['files'])}"
            )
        remainder = len(result["languages"]) - len(shown)
        if remainder > 0:
            lines.append(f"    … {remainder} further language(s) below {MIN_LANGUAGE_SHARE}%")

    if result["manifests"]:
        lines += ["", "  manifests"]
        width = max(len(row["ecosystem"]) for row in result["manifests"])
        for row in result["manifests"]:
            dirs = row["directories"]
            shown_dirs = ", ".join(dirs[:MAX_MANIFEST_DIRS])
            if len(dirs) > MAX_MANIFEST_DIRS:
                shown_dirs += f", +{len(dirs) - MAX_MANIFEST_DIRS} more"
            lines.append(f"    {row['ecosystem']:<{width}}  {shown_dirs}")

    for note in result["notes"]:
        lines += ["", f"  {note}"]

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic repository profile: size, tech stack, layout. No LLM.")
    parser.add_argument("--repo", default=".", help="Repository to profile (default: current working dir)")
    parser.add_argument("--json", action="store_true", help="Emit the profile as machine-readable JSON")
    args = parser.parse_args(argv)

    repo_root = Path(args.repo).expanduser().resolve()
    if not repo_root.is_dir():
        print(f"error: not a directory: {repo_root}", file=sys.stderr)
        return 1

    result = profile(repo_root)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render_text(result))

    return 0


if __name__ == "__main__":
    sys.exit(main())
