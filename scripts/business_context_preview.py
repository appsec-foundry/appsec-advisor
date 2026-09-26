"""Bounded, local evidence for the early business-context dialog.

This is not reconnaissance: no commands, network, dependency resolution, or
security-pattern scans. The session uses one packet for a short dialog. Limits
bound the filesystem work independently of repository size and model choices.
"""

from __future__ import annotations

import json
import os
import stat
import time
from collections import deque
from pathlib import Path

import jsonschema
import secret_scan

MAX_ENTRIES = 512
MAX_FILES = 8
MAX_FILE_BYTES = 2048
MAX_CONTEXT_BYTES = 12000
MAX_PACKET_BYTES = 65536
MAX_DEPTH = 3
MAX_SECONDS = 2.0
PREVIEW_NAME = ".business-context-preview.json"
RAW_NAME = ".business-context-raw.md"
SCHEMA = Path(__file__).resolve().parents[1] / "schemas/business-context-preview.schema.json"
_EXCLUDED = {"node_modules", "vendor", "target", "build", "dist", "coverage", "venv", "__pycache__"}
_OVERVIEW_NAMES = {
    "readme.md",
    "readme.rst",
    "readme.txt",
    "readme",
    "package.json",
    "pom.xml",
    "pyproject.toml",
    "go.mod",
    "cargo.toml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "gemfile",
    "architecture.md",
    "openapi.yaml",
    "openapi.json",
    "swagger.yaml",
    "schema.prisma",
    "schema.sql",
}


def read_regular(path: Path, root: Path, limit: int) -> tuple[str, bool]:
    """Read a bounded regular file without following any symbolic-link component."""
    relative = path.absolute().relative_to(root.resolve())
    if not relative.parts or any(part in {".", ".."} for part in relative.parts):
        raise ValueError("context input escapes its root")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        child = os.open(relative.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=descriptor)
        try:
            if not stat.S_ISREG(os.fstat(child).st_mode):
                raise ValueError("context input is not a regular file")
            with os.fdopen(child, "rb", closefd=False) as handle:
                payload = handle.read(limit + 1)
        finally:
            os.close(child)
    finally:
        os.close(descriptor)
    return payload[:limit].decode("utf-8", errors="replace"), len(payload) > limit


def validate(packet: dict) -> None:
    jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text())).validate(packet)


def build(repo_root: Path, *, context_path: Path | None = None) -> dict:
    """Collect one bounded packet; withheld/truncated data is never a negative fact."""
    start = time.monotonic()
    root = repo_root.resolve()
    sources: list[dict] = []
    names: list[str] = []
    candidates: list[Path] = []
    pending = deque([(root, 0)])
    entries_seen = 0
    limited = False

    def admit(path: Path) -> None:
        nonlocal limited
        relative = path.relative_to(root).as_posix()
        if len(relative) > 512 or secret_scan.scan_text(relative):
            limited = True
            return
        try:
            text, truncated = read_regular(path, root, MAX_FILE_BYTES)
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            limited = True
            return
        if "\x00" in text or secret_scan.scan_text(text):
            limited = True
            return
        sources.append({"path": relative, "excerpt": text, "truncated": truncated})

    # Fixed root paths remain available even if a huge listing exhausts the
    # traversal budget before reaching its README.
    for name in ("README.md", "README.rst", "package.json", "pom.xml", "pyproject.toml", "go.mod", "Cargo.toml"):
        if time.monotonic() - start >= MAX_SECONDS:
            limited = True
            break
        admit(root / name)
    while pending and entries_seen < MAX_ENTRIES and time.monotonic() - start < MAX_SECONDS:
        directory, depth = pending.popleft()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    entries_seen += 1
                    if entries_seen > MAX_ENTRIES or time.monotonic() - start >= MAX_SECONDS:
                        limited = True
                        break
                    if entry.name.startswith(".") or entry.name in _EXCLUDED or entry.is_symlink():
                        continue
                    relative = Path(entry.path).relative_to(root).as_posix()
                    if secret_scan.scan_text(relative):
                        continue
                    if depth == 0 and len(names) < 40:
                        names.append(relative[:200])
                    if entry.is_dir(follow_symlinks=False) and depth < MAX_DEPTH:
                        pending.append((Path(entry.path), depth + 1))
                    elif entry.is_file(follow_symlinks=False) and entry.name.lower() in _OVERVIEW_NAMES:
                        candidates.append(Path(entry.path))
        except OSError:
            limited = True
    limited = limited or bool(pending)
    for path in sorted(
        candidates, key=lambda p: (len(p.relative_to(root).parts), p.name.lower() != "readme.md", str(p))
    ):
        if any(row["path"] == path.relative_to(root).as_posix() for row in sources):
            continue
        if len(sources) >= MAX_FILES or time.monotonic() - start >= MAX_SECONDS:
            limited = True
            break
        admit(path)
    context = ""
    context_status = "absent"
    if context_path is not None:
        context_status = "withheld"
        try:
            text, truncated = read_regular(context_path, context_path.parent, MAX_CONTEXT_BYTES)
            if not secret_scan.scan_text(text):
                context, context_status = text, "truncated" if truncated else "provided"
        except (OSError, ValueError):
            pass
    packet = {
        "schema_version": 1,
        "sources": sources,
        "top_level_names": sorted(names),
        "existing_context": context,
        "context_status": context_status,
        "limited": limited,
        "elapsed_ms": round((time.monotonic() - start) * 1000),
    }
    # JSON escaping can expand control characters and non-ASCII text. Bound
    # the actual delivery as well as its individual source reads.
    while len(json.dumps(packet).encode()) > MAX_PACKET_BYTES:
        packet["limited"] = True
        if packet["sources"]:
            packet["sources"].pop()
        elif packet["existing_context"]:
            packet["existing_context"] = packet["existing_context"][: len(packet["existing_context"]) // 2]
            packet["context_status"] = "truncated"
        else:
            packet["top_level_names"].pop()
    validate(packet)
    return packet
