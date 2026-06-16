#!/usr/bin/env python3
"""Stamp a finished threat model's deliverables with a shared random postfix so
several models can be copied into one directory without overwriting each other.

Copies ``threat-model.{md,yaml,figure1.svg,pdf,html,sarif.json}`` (whichever
exist) to ``threat-model-<slug>.<ext>`` and rewrites the Figure 1 reference
inside the copied Markdown so it points at the stamped SVG. The originals are
left untouched — this only produces an extra, collision-proof copy set.

Usage:
    python3 stamp_threat_model.py --output-dir docs/security [--slug a3f9]
                                  [--dest /path/to/collection]
"""

from __future__ import annotations

import argparse
import secrets
import shutil
import sys
from pathlib import Path

# Deliverables to stamp, in display order. All optional — only existing files
# are copied.
_BASENAMES = [
    "threat-model.md",
    "threat-model.yaml",
    "threat-model.figure1.svg",
    "threat-model.pdf",
    "threat-model.html",
    "threat-model.sarif.json",
]


def _stamped_name(basename: str, slug: str) -> str:
    """`threat-model.figure1.svg` → `threat-model-<slug>.figure1.svg`."""
    prefix = "threat-model"
    rest = basename[len(prefix) :]  # ".figure1.svg", ".md", …
    return f"{prefix}-{slug}{rest}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output-dir", type=Path, required=True, help="Directory holding the rendered model.")
    p.add_argument("--slug", default=None, help="Postfix to use (default: 4 random hex chars).")
    p.add_argument("--dest", type=Path, default=None, help="Where to write the stamped copies (default: --output-dir).")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    src_dir: Path = args.output_dir
    dest_dir: Path = args.dest or src_dir
    slug = args.slug or secrets.token_hex(2)  # 4 hex chars
    dest_dir.mkdir(parents=True, exist_ok=True)

    md_src = src_dir / "threat-model.md"
    if not md_src.is_file():
        print(f"ERROR: {md_src} not found — render the model first.", file=sys.stderr)
        return 2

    created: list[Path] = []
    for basename in _BASENAMES:
        src = src_dir / basename
        if not src.is_file():
            continue
        dst = dest_dir / _stamped_name(basename, slug)
        if basename == "threat-model.md":
            # Copy with the Figure 1 reference repointed at the stamped SVG.
            text = src.read_text(encoding="utf-8")
            text = text.replace("threat-model.figure1.svg", _stamped_name("threat-model.figure1.svg", slug))
            dst.write_text(text, encoding="utf-8")
        else:
            shutil.copy2(src, dst)
        created.append(dst)

    print(f"Stamped model with slug '{slug}':")
    for path in created:
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
