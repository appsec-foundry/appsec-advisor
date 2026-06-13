#!/usr/bin/env python3
"""Detect — conservatively — whether the analysed repo is a PUBLIC open-source
repository, and record the result in `threat-model.yaml → meta.public_source_repo`.

Why this matters: when the source is public, the `repo-read` actor ("Internal
Developer — developer with source-repository access") is a misnomer — *anyone*
can clone the repo and read committed secrets, so that capability belongs to the
**Anonymous Internet Attacker**. `compose_threat_model._collapse_public_repo_actors`
folds `repo-read → internet-anon` when this flag is true. When the source is
NOT confidently public we leave the flag unset and the "Internal Developer"
actor is kept — exactly the user's rule (2026-06-02): only call it an anonymous
internet attacker when we are sure it is a public repo; otherwise keep the
internal-developer framing.

Conservative high-confidence heuristic (ALL signals are LOCAL — no network):
  PUBLIC requires, together:
    1. An OSI/open-source LICENSE file at the repo root (MIT, Apache-2.0, BSD,
       GPL/LGPL/AGPL, MPL, ISC, Unlicense, …), AND
    2. A public-host source URL — a `github.com` / `gitlab.com` / `bitbucket.org`
       URL in `package.json#repository` OR in a git remote (`git config`).
  Either missing  → leave `meta.public_source_repo` UNSET (keep Internal Developer).

  NOTE: `package.json "private": true` is deliberately NOT used as a signal —
  it is the npm-registry publish flag ("do not publish this package"), which
  application repos (e.g. OWASP Juice Shop) routinely set even though their
  SOURCE is fully public. It says nothing about repository visibility.

Operator override: `meta.public_source_repo_pinned: true|false` wins and is
preserved across re-runs.

Usage:
    python3 detect_public_repo.py <output_dir> --repo-root <repo>
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

_OSI_LICENSE_RE = re.compile(
    r"\b(MIT License|Apache License|BSD|GNU (GENERAL|LESSER|AFFERO)|"
    r"Mozilla Public License|ISC License|The Unlicense|"
    r"Permission is hereby granted, free of charge)\b",
    re.IGNORECASE,
)
_PUBLIC_HOST_RE = re.compile(r"(github\.com|gitlab\.com|bitbucket\.org)/", re.IGNORECASE)
_LICENSE_NAMES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.md")


def _has_osi_license(repo: Path) -> bool:
    for name in _LICENSE_NAMES:
        p = repo / name
        if p.is_file():
            try:
                head = p.read_text(encoding="utf-8", errors="replace")[:4000]
            except OSError:
                continue
            if _OSI_LICENSE_RE.search(head):
                return True
    return False


def _package_json(repo: Path) -> dict:
    p = repo / "package.json"
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def _git_remote_public(repo: Path) -> bool:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "config", "--get-regexp", r"^remote\..*\.url$"],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
    except Exception:
        return False
    return bool(_PUBLIC_HOST_RE.search(out))


def detect(repo: Path) -> tuple[bool | None, str]:
    """Return (verdict, reason). verdict True/False/None — None = leave unset.

    `package.json "private"` is intentionally ignored: it is the npm-publish
    flag, not a repo-visibility signal (OWASP Juice Shop sets it yet is public)."""
    pkg = _package_json(repo)
    osi = _has_osi_license(repo)
    repo_url = ""
    rep = pkg.get("repository")
    if isinstance(rep, str):
        repo_url = rep
    elif isinstance(rep, dict):
        repo_url = rep.get("url") or ""
    public_url = bool(_PUBLIC_HOST_RE.search(repo_url)) or _git_remote_public(repo)

    if osi and public_url:
        return True, "OSI license file + public-host source URL"
    # Not confident enough — keep the Internal Developer framing.
    missing = []
    if not osi:
        missing.append("no OSI license file at repo root")
    if not public_url:
        missing.append("no public-host (github/gitlab/bitbucket) source URL")
    return None, "insufficient public-repo evidence (" + "; ".join(missing) + ")"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Detect public open-source repo → meta.public_source_repo")
    ap.add_argument("output_dir")
    ap.add_argument("--repo-root", required=True)
    args = ap.parse_args(argv)

    tm_path = Path(args.output_dir) / "threat-model.yaml"
    if not tm_path.is_file():
        sys.stderr.write("detect_public_repo: no threat-model.yaml — skipping\n")
        return 0
    data = yaml.safe_load(tm_path.read_text(encoding="utf-8")) or {}
    meta = data.setdefault("meta", {})
    if not isinstance(meta, dict):
        meta = {}
        data["meta"] = meta

    if "public_source_repo_pinned" in meta:
        meta["public_source_repo"] = bool(meta["public_source_repo_pinned"])
        sys.stderr.write(f"detect_public_repo: pinned → public_source_repo={meta['public_source_repo']}\n")
    else:
        verdict, reason = detect(Path(args.repo_root))
        if verdict is None:
            meta.pop("public_source_repo", None)  # leave unset → Internal Developer kept
            sys.stderr.write(f"detect_public_repo: UNSET (keep Internal Developer) — {reason}\n")
        else:
            meta["public_source_repo"] = verdict
            sys.stderr.write(f"detect_public_repo: public_source_repo={verdict} — {reason}\n")

    tmp = tm_path.with_suffix(".yaml.tmp")
    tmp.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=10**9, default_flow_style=False),
        encoding="utf-8",
    )
    tmp.replace(tm_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
