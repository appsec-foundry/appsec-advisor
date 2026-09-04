#!/usr/bin/env python3
"""Stamp a finished threat model's deliverables with a shared random postfix so
several models can be copied into one directory without overwriting each other.

Copies ``threat-model.{md,yaml,figure*.svg,pdf,html,sarif.json}`` and
``pentest-tasks.yaml`` (whichever exist) to their ``-<slug>`` stamped names and
rewrites copied figure/pentest references inside the copied Markdown so they
point at the stamped files. The originals are left untouched — this only
produces an extra, collision-proof copy set.

Re-runnable: a deliverable whose stamped copy is already up to date is left
alone, so a later run picks up only what was exported since the last one.

Usage:
    python3 stamp_threat_model.py --output-dir docs/security [--slug a3f9]
                                  [--dest /path/to/collection]
"""

from __future__ import annotations

import argparse
import re
import secrets
import shutil
import sys
from pathlib import Path

_SLUG_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")

# Deliverables to stamp, in display order. Figure SVGs are discovered at runtime
# because the renderer may emit Figure 1, Figure 2, or a future numbered figure.
# `pentest-tasks.yaml` is a first-class deliverable too, so it is stamped
# alongside the others (its own prefix — it is not a `threat-model.*` file).
_STATIC_BASENAMES = [
    "threat-model.md",
    "threat-model.yaml",
    "threat-model.pdf",
    "threat-model.html",
    "threat-model.sarif.json",
    "threat-model.threatdragon.json",
    "pentest-tasks.yaml",
]

# Known deliverable prefixes, longest-first so the match is unambiguous.
_STAMP_PREFIXES = ("threat-model", "pentest-tasks")


def _stamped_name(basename: str, slug: str) -> str:
    """Insert ``-<slug>`` after the deliverable prefix.

    ``threat-model.figure1.svg`` → ``threat-model-<slug>.figure1.svg``
    ``pentest-tasks.yaml``       → ``pentest-tasks-<slug>.yaml``
    """
    for prefix in _STAMP_PREFIXES:
        if basename.startswith(prefix):
            rest = basename[len(prefix) :]  # ".figure1.svg", ".md", ".yaml", …
            return f"{prefix}-{slug}{rest}"
    raise ValueError(f"unstampable basename: {basename!r}")


def _figure_basenames(src_dir: Path) -> list[str]:
    return sorted(p.name for p in src_dir.glob("threat-model.figure*.svg") if p.is_file())


def _deliverable_basenames(src_dir: Path) -> list[str]:
    return [*_STATIC_BASENAMES[:2], *_figure_basenames(src_dir), *_STATIC_BASENAMES[2:]]


def _is_current(dst: Path, src: Path) -> bool:
    """True when ``dst`` already carries what ``src`` holds, judged by mtime.

    ``shutil.copy2`` preserves the source mtime, so an unchanged deliverable
    compares equal and is copied once rather than on every stamp call.
    """
    try:
        return dst.is_file() and dst.stat().st_mtime_ns >= src.stat().st_mtime_ns
    except OSError:
        return False


def stamped_set_is_current(src_dir: Path, slug: str, dest_dir: Path | None = None) -> bool:
    """True when every deliverable present in ``src_dir`` has an up-to-date stamp.

    The callers that anchor the stamp (`orchestration_controller` and
    `render_completion_summary`) use this to decide whether a stamp run has
    anything left to do. Asking it about the whole set matters: PDF and HTML are
    exported between the two completion-summary runs, so a check that looked
    only at the stamped Markdown reported "done" and left them unstamped.
    """
    dest = dest_dir or src_dir
    for basename in _deliverable_basenames(src_dir):
        src = src_dir / basename
        if not src.is_file():
            continue
        if not _is_current(dest / _stamped_name(basename, slug), src):
            return False
    return True


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output-dir", type=Path, required=True, help="Directory holding the rendered model.")
    p.add_argument("--slug", default=None, help="Postfix to use (default: 4 random hex chars).")
    p.add_argument("--dest", type=Path, default=None, help="Where to write the stamped copies (default: --output-dir).")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    src_dir: Path = args.output_dir
    dest_dir: Path = args.dest or src_dir
    slug = args.slug or secrets.token_hex(2)  # 4 hex chars
    if not _SLUG_RE.fullmatch(slug):
        print(
            "ERROR: --slug must be 1-64 filename-safe characters ([A-Za-z0-9._-]).",
            file=sys.stderr,
        )
        return 2
    dest_dir.mkdir(parents=True, exist_ok=True)

    md_src = src_dir / "threat-model.md"
    if not md_src.is_file():
        print(f"ERROR: {md_src} not found — render the model first.", file=sys.stderr)
        return 2

    figure_basenames = _figure_basenames(src_dir)
    stamped: list[tuple[Path, bool]] = []  # (stamped path, written by this run)
    for basename in _deliverable_basenames(src_dir):
        if basename == "threat-model.md":
            continue  # written last: it names the deliverables stamped alongside it
        src = src_dir / basename
        if not src.is_file():
            continue
        dst = dest_dir / _stamped_name(basename, slug)
        if _is_current(dst, src):
            stamped.append((dst, False))
            continue
        shutil.copy2(src, dst)
        stamped.append((dst, True))

    md_dst = dest_dir / _stamped_name("threat-model.md", slug)
    # A deliverable stamped only now — PDF and HTML are exported after an
    # earlier stamp — can change which files the Markdown must point at, so a
    # copy that is merely newer than the report is not reason enough to keep it.
    if any(written for _, written in stamped) or not _is_current(md_dst, md_src):
        text = md_src.read_text(encoding="utf-8")
        # Only remap figure references when the SVG will actually be copied.
        # This avoids creating a broken image link when figure generation was
        # skipped or failed but the Markdown still contains stale text.
        for figure in figure_basenames:
            text = text.replace(figure, _stamped_name(figure, slug))
        # Repoint the pentest-tasks prose reference at the stamped copy so a
        # stamped bundle stays self-consistent in a shared collection dir.
        # Guarded on existence, mirroring the figure rule above.
        if (src_dir / "pentest-tasks.yaml").is_file():
            text = text.replace("pentest-tasks.yaml", _stamped_name("pentest-tasks.yaml", slug))
        md_dst.write_text(text, encoding="utf-8")
        stamped.insert(0, (md_dst, True))
    else:
        stamped.insert(0, (md_dst, False))

    print(f"Stamped model with slug '{slug}':")
    for path, written in stamped:
        print(f"  {path}" if written else f"  {path} (unchanged)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
