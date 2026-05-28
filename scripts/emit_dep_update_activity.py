#!/usr/bin/env python3
"""Detect dependency-update activity from passive git/GitHub signals.

Looks for evidence that the team actually patches dependencies on a
recurring cadence — independent of whether Dependabot / Renovate config
files exist. The plugin never calls `npm audit` / `pip-audit` /
`govulncheck` or any other vulnerability tool; this script is purely
file-system inspection.

Signals consulted (all passive — no network requests, no package-manager
tool calls):

  1. `git log` on dependency manifests (package.json, requirements.txt,
     go.mod, pom.xml, Gemfile, composer.json, Cargo.toml, *.csproj) over
     the configurable window (default: last 90 days).
       — total count of commits touching any manifest
       — count of commits whose subject matches dependency-update
         patterns ("bump", "update X to Y", "chore(deps)", and
         attributions to dependabot[bot] / renovate[bot]).
  2. (optional) `gh pr list` when the GitHub CLI is on PATH and
     authenticated for the repo — counts merged dependency-update PRs.
     Failure is non-fatal; falls back to the git-log signal.

Output: `$OUTPUT_DIR/.dep-update-activity.json` with the shape:

    {
      "schema_version": 1,
      "window_days": 90,
      "total_manifest_commits": <int>,
      "dep_update_commits": <int>,
      "bot_authored_commits": <int>,    # dependabot[bot] / renovate[bot]
      "merged_dep_prs": <int|null>,     # null when gh CLI not used
      "manifests_seen": ["<rel-path>", ...],
      "cadence": "active|sporadic|inactive|unknown",
      "evidence": ["<short bullet>", ...]
    }

`cadence` classification (consumed by emit_sca_practice.py to lift the
"Automated dependency updates" §7.11 row out of Missing when Dependabot
/ Renovate config files are absent but the team is patching anyway):

    active     ≥ 6 dep-update commits OR ≥ 3 bot-authored commits in window
    sporadic   ≥ 1 dep-update commit in window
    inactive   git history exists, no dep-update activity
    unknown    not a git repo / git unavailable

Why passive only:

  Running `npm audit` / `pip-audit` / similar would (a) make network
  requests to npmjs / PyPI / osv.dev, (b) require the tooling to be
  installed on the host that runs the threat-modeling pipeline,
  (c) duplicate work the user's CI already does with a dedicated SCA
  tool. The plugin's job is the **architectural posture** signal
  ("does this team practice patch management?"), not per-CVE reporting.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Manifest filenames the activity check is interested in. Anything outside
# this list is ignored — vendor directories (node_modules/, .venv/, …) are
# also filtered out so generated-file churn does not contaminate the count.
_MANIFEST_NAMES = {
    "package.json",
    "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
    "Pipfile", "pyproject.toml", "setup.py",
    "go.mod",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "Gemfile",
    "composer.json",
    "Cargo.toml",
}
# Plus any *.csproj — wildcarded below.
_VENDOR_DIR_PARTS = {"node_modules", ".venv", "venv", "vendor", "target", "build", "dist", ".git", ".tox"}

# Subject patterns for dependency-update commits. Matched case-insensitive.
_DEP_UPDATE_PATTERNS = (
    r"\bbump\b",
    r"\bbumps?\s+\S+\s+from\b",            # dependabot canonical "Bumps X from"
    r"\bupdate\s+\S+\s+to\s+\d",
    r"\bupgrade\s+\S+\s+to\s+\d",
    r"\bchore\(deps\)",
    r"\bdeps\):?\s*",
    r"\bdependabot\b",
    r"\brenovate\b",
)
_DEP_UPDATE_RE = re.compile("|".join(_DEP_UPDATE_PATTERNS), re.IGNORECASE)
_BOT_AUTHOR_RE = re.compile(r"dependabot\[bot\]|renovate\[bot\]|renovate-bot", re.IGNORECASE)


def _is_git_repo(repo_root: Path) -> bool:
    try:
        r = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=10,
        )
        return r.returncode == 0 and r.stdout.strip() == "true"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _walk_manifests(repo_root: Path) -> list[str]:
    out: list[str] = []
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _VENDOR_DIR_PARTS for part in path.parts):
            continue
        if path.name in _MANIFEST_NAMES or path.suffix == ".csproj":
            try:
                out.append(str(path.relative_to(repo_root)))
            except ValueError:
                pass
    return sorted(set(out))


def _git_log(repo_root: Path, since_days: int, paths: list[str]) -> list[dict]:
    """Return list of {subject, author} dicts for commits touching `paths`
    in the last `since_days` days. Empty list on any git failure (graceful
    degradation — activity check is non-fatal)."""
    if not paths:
        return []
    cmd = [
        "git", "-C", str(repo_root),
        "log",
        f"--since={since_days} days ago",
        "--no-merges",
        "--pretty=format:%H%x09%an%x09%s",
        "--",
    ] + paths
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []
    if r.returncode != 0:
        return []
    commits: list[dict] = []
    for line in r.stdout.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        commits.append({"sha": parts[0], "author": parts[1], "subject": parts[2]})
    return commits


def _gh_dep_pr_count(repo_root: Path, since_days: int) -> int | None:
    """Use the gh CLI (if available) to count merged dependency-update
    PRs in the window. Returns None when gh is unavailable / unauthenticated
    / not configured for this repo — caller falls back to git-log signal.

    This is the only network-adjacent call in the script. It runs only
    when `gh` is on PATH and reaches a published GitHub remote; no
    package-manager / SCA tools are invoked.
    """
    if shutil.which("gh") is None:
        return None
    try:
        r = subprocess.run(
            [
                "gh", "pr", "list",
                "--state", "merged",
                "--limit", "200",
                "--search", f"label:dependencies OR title:bump OR title:\"chore(deps)\" OR author:app/dependabot OR author:app/renovate merged:>={_iso_days_ago(since_days)}",
                "--json", "number,title,mergedAt,author",
            ],
            cwd=str(repo_root),
            capture_output=True, text=True, timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return None
    return len(data) if isinstance(data, list) else None


def _iso_days_ago(days: int) -> str:
    import datetime as _dt
    return (_dt.datetime.utcnow() - _dt.timedelta(days=days)).strftime("%Y-%m-%d")


def _classify_cadence(dep_commits: int, bot_commits: int, in_git_repo: bool) -> str:
    if not in_git_repo:
        return "unknown"
    if dep_commits >= 6 or bot_commits >= 3:
        return "active"
    if dep_commits >= 1:
        return "sporadic"
    return "inactive"


def run(repo_root: Path, output_dir: Path, window_days: int, use_gh: bool) -> int:
    in_git_repo = _is_git_repo(repo_root)
    manifests = _walk_manifests(repo_root)

    commits = _git_log(repo_root, window_days, manifests) if in_git_repo else []
    dep_update_commits = [c for c in commits if _DEP_UPDATE_RE.search(c["subject"])]
    bot_commits = [c for c in commits if _BOT_AUTHOR_RE.search(c["author"]) or _BOT_AUTHOR_RE.search(c["subject"])]

    merged_dep_prs = _gh_dep_pr_count(repo_root, window_days) if use_gh else None

    cadence = _classify_cadence(len(dep_update_commits), len(bot_commits), in_git_repo)

    evidence: list[str] = []
    if not in_git_repo:
        evidence.append("Repository is not a git checkout — activity signal unavailable.")
    else:
        evidence.append(
            f"{len(commits)} commit(s) touched dependency manifests in the last {window_days} days; "
            f"{len(dep_update_commits)} matched dep-update patterns; "
            f"{len(bot_commits)} authored by dependabot[bot] / renovate[bot]."
        )
        if merged_dep_prs is not None:
            evidence.append(f"gh CLI reported {merged_dep_prs} merged dep-update PR(s) in the same window.")
        # Surface up to 3 example subjects so the human reviewer can sanity-check.
        for c in dep_update_commits[:3]:
            evidence.append(f"  e.g. {c['subject'][:120]}")

    payload = {
        "schema_version": 1,
        "window_days": window_days,
        "total_manifest_commits": len(commits),
        "dep_update_commits": len(dep_update_commits),
        "bot_authored_commits": len(bot_commits),
        "merged_dep_prs": merged_dep_prs,
        "manifests_seen": manifests,
        "cadence": cadence,
        "evidence": evidence,
    }
    out = output_dir / ".dep-update-activity.json"
    out.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")
    print(
        f"emit_dep_update_activity: cadence={cadence} "
        f"(dep_commits={len(dep_update_commits)}, bot_commits={len(bot_commits)}, "
        f"manifests={len(manifests)}, merged_dep_prs={merged_dep_prs})"
    )
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Passive dep-update-activity detector (git-log + optional gh CLI)")
    p.add_argument("--repo-root", required=True, type=Path)
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument("--window-days", type=int, default=90,
                   help="Look-back window for git log + gh pr list (default: 90 days)")
    p.add_argument("--no-gh", action="store_true",
                   help="Skip the optional gh CLI PR-count signal even when gh is on PATH")
    args = p.parse_args(argv)
    if not args.repo_root.is_dir():
        print(f"emit_dep_update_activity: repo-root not a directory: {args.repo_root}", file=sys.stderr)
        return 2
    if not args.output_dir.is_dir():
        print(f"emit_dep_update_activity: output-dir not a directory: {args.output_dir}", file=sys.stderr)
        return 2
    return run(args.repo_root, args.output_dir, args.window_days, use_gh=not args.no_gh)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
