#!/usr/bin/env python3
"""build_verify_diff.py — compute the change set for verify-requirements.

Resolves the diff the appsec-reviewer subagent will grade and
writes it to `<output-dir>/.verify-diff.json` as untrusted data. Keeping this
in deterministic Python (not inline skill bash) sidesteps the Python-3.10
f-string / `!=` history-expansion traps and gives the diff resolution a single
tested home.

Base-ref resolution order:
    1. --base <ref>   → git diff <ref>...HEAD   (three-dot: changes on HEAD since merge-base)
    2. --staged       → git diff --cached       (pre-commit hook use)
    3. default        → merge-base with origin/HEAD, then three-dot diff
    4. fallback       → git diff HEAD~1...HEAD  (no upstream)

Prints the changed-file count to stdout. Exit 0 on success (including an empty
diff — that is a valid result, not an error), 2 on a git/usage error.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def _git(repo: Path, *args: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(repo),
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return 127, "git not found on PATH"
    return proc.returncode, proc.stdout if proc.returncode == 0 else proc.stderr


def _resolve_base(repo: Path, base: str | None, staged: bool) -> tuple[str, str | None]:
    """Return (mode, base_ref). mode is 'staged' or 'range'; base_ref is the
    left side of the three-dot range (None for staged)."""
    if staged:
        return "staged", None
    if base:
        return "range", base
    # Try merge-base with the upstream default branch.
    rc, out = _git(repo, "rev-parse", "--abbrev-ref", "origin/HEAD")
    if rc == 0 and out.strip():
        return "range", out.strip()
    # Common fallbacks for the default branch name.
    for cand in ("origin/main", "origin/master"):
        rc, _ = _git(repo, "rev-parse", "--verify", cand)
        if rc == 0:
            return "range", cand
    return "range", "HEAD~1"


def _changed_files(repo: Path, diff_args: list[str]) -> list[dict]:
    rc, out = _git(repo, "diff", "--numstat", *diff_args)
    if rc != 0:
        return []
    files: list[dict] = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        added, removed, path = parts
        files.append(
            {
                "path": path,
                "added": None if added == "-" else int(added),
                "removed": None if removed == "-" else int(removed),
            }
        )
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the .verify-diff.json change set.")
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--base", default=None, help="Base ref for git diff <base>...HEAD")
    parser.add_argument("--staged", action="store_true", help="Diff staged changes (git diff --cached)")
    args = parser.parse_args(argv)

    repo = Path(args.repo_root)
    out_dir = Path(args.output_dir)
    if not (repo / ".git").exists() and not (repo / ".git").is_file():
        rc, _ = _git(repo, "rev-parse", "--git-dir")
        if rc != 0:
            print("build-verify-diff: not a git repository", file=sys.stderr)
            return 2
    out_dir.mkdir(parents=True, exist_ok=True)

    mode, base_ref = _resolve_base(repo, args.base, args.staged)

    if mode == "staged":
        diff_args = ["--cached"]
        merge_base = None
        display_base = "STAGED"
    else:
        diff_args = [f"{base_ref}...HEAD"]
        rc, mb = _git(repo, "merge-base", base_ref, "HEAD")
        merge_base = mb.strip() if rc == 0 else None
        display_base = base_ref

    changed = _changed_files(repo, diff_args)
    rc, unified = _git(repo, "diff", *diff_args)
    if rc != 0:
        print(f"build-verify-diff: git diff failed: {unified.strip()}", file=sys.stderr)
        return 2

    payload = {
        "version": 1,
        "base_ref": display_base,
        "head_ref": "HEAD",
        "merge_base": merge_base,
        "mode": mode,
        "changed_files": changed,
        "diff_unified": unified,
    }
    (out_dir / ".verify-diff.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(str(len(changed)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
