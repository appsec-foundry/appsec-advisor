#!/usr/bin/env python3
"""validators/preflight_untrusted.py — pre-scan safety checks for the target repo.

Run BEFORE ``create-threat-model`` against a repo whose authorship is
not fully trusted. Detects repository-resident Claude Code hooks /
settings (which would be loaded by Claude Code before the plugin runs
and can therefore execute arbitrary code), symlinks pointing outside
the repository root, and remote URLs in ``docs/related-repos.yaml``
that would trigger ``contexts/load_related_repos.py`` HTTP fetches.

Exit codes::

    0   nothing to flag
    1   findings present, but the caller did not pass --strict
    2   findings present and --strict was set
    3   the repo root does not exist or is not readable
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from shared._path_guard import iter_escaping_symlinks  # noqa: E402
from shared._url_guard import validate_target_url  # noqa: E402

# These files are consumed by the host before the plugin's own prompt can
# establish its untrusted-data boundary. Keep this list intentionally small
# and executable/instruction-bearing: ordinary source and documentation are
# still scanned as data, not rejected wholesale.
_REPO_OWNED_CLAUDE_PATHS = (
    "CLAUDE.md",
    "CLAUDE.local.md",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/hooks.json",
    ".claude/hooks",
    ".claude/.mcp.json",
    ".claude/agents",
    ".claude/skills",
    ".claude/commands",
    ".claude/CLAUDE.md",
    ".vscode/tasks.json",
    ".devcontainer/devcontainer.json",
)


def _is_null_device(st: os.stat_result) -> bool:
    # The Claude Code Bash sandbox bind-mounts /dev/null over absent host
    # configuration paths to keep them unwritable. Such a mount carries no
    # configuration, and git cannot check out a device node.
    try:
        null_rdev = os.stat(os.devnull).st_rdev
    except OSError:
        return False
    return stat.S_ISCHR(st.st_mode) and st.st_rdev == null_rdev


def _scan_repo_owned_hooks(repo_root: Path, *, isolated_host: bool = False) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for rel in _REPO_OWNED_CLAUDE_PATHS:
        # TR-10: an isolated host never loads Claude Code configuration from
        # the checkout; IDE-loaded files stay findings.
        if isolated_host and (rel.startswith(".claude/") or rel.startswith("CLAUDE")):
            continue
        p = repo_root / rel
        try:
            st = p.lstat()
        except (FileNotFoundError, NotADirectoryError):
            continue
        if not _is_null_device(st):
            findings.append(
                {
                    "kind": "repo-owned-hook",
                    "path": rel,
                    "severity": "Critical" if rel.endswith(("settings.json", "hooks.json", "tasks.json")) else "High",
                    "note": (
                        "loaded by the host tool before the plugin runs; "
                        "remove, rename, or move outside the repo before scanning"
                    ),
                }
            )
    return findings


def _scan_symlinks(repo_root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for esc in iter_escaping_symlinks(repo_root):
        rel = esc.path.relative_to(repo_root)
        findings.append(
            {
                "kind": "escaping-symlink",
                "path": str(rel),
                "target": str(esc.target),
                "symlink_kind": esc.kind,
                "severity": "High",
                "note": "would read or traverse a path outside the repository root",
            }
        )
    return findings


def _scan_related_repos(repo_root: Path, *, strict_urls: bool) -> list[dict[str, Any]]:
    yaml_path = repo_root / "docs" / "related-repos.yaml"
    if not yaml_path.is_file():
        return []
    try:
        payload = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return [
            {
                "kind": "related-repos-parse-error",
                "path": "docs/related-repos.yaml",
                "severity": "Medium",
                "note": f"yaml parse failed: {exc}",
            }
        ]
    findings: list[dict[str, Any]] = []
    for i, entry in enumerate(payload.get("related") or []):
        if not isinstance(entry, dict):
            continue
        tm = entry.get("threat_model")
        if not isinstance(tm, str):
            continue
        if "://" not in tm:
            continue
        result = validate_target_url(tm, strict=strict_urls)
        if not result.ok:
            findings.append(
                {
                    "kind": "related-repos-url-rejected",
                    "path": "docs/related-repos.yaml",
                    "entry_index": i,
                    "entry_name": entry.get("name"),
                    "url": tm,
                    "severity": "High",
                    "note": result.reason,
                }
            )
    return findings


def run(repo_root: Path, *, strict: bool, strict_urls: bool, isolated_host: bool = False) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    findings.extend(_scan_repo_owned_hooks(repo_root, isolated_host=isolated_host))
    findings.extend(_scan_symlinks(repo_root))
    findings.extend(_scan_related_repos(repo_root, strict_urls=strict_urls))
    return {
        "repo_root": str(repo_root),
        "strict": strict,
        "strict_urls": strict_urls,
        "finding_count": len(findings),
        "findings": findings,
    }


def _render_human(report: dict[str, Any]) -> str:
    lines = [f"preflight-untrusted: {report['repo_root']}"]
    if report["finding_count"] == 0:
        lines.append("  no findings — repo passes pre-flight")
        return "\n".join(lines)
    lines.append(f"  {report['finding_count']} finding(s):")
    for f in report["findings"]:
        bits = [f"[{f['severity']}]", f["kind"], f.get("path", "")]
        if "url" in f:
            bits.append(f"<{f['url']}>")
        if "target" in f:
            bits.append(f"-> {f['target']}")
        bits.append(f"({f['note']})")
        lines.append("  - " + " ".join(b for b in bits if b))
    return "\n".join(lines)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo-root", required=True, type=Path)
    p.add_argument("--output", default="-", help="JSON destination, '-' for stdout")
    p.add_argument(
        "--strict",
        action="store_true",
        help="exit 2 when findings are present (default exit 1)",
    )
    p.add_argument(
        "--strict-urls",
        action="store_true",
        help="require APPSEC_URL_ALLOWLIST for related-repos URLs",
    )
    p.add_argument(
        "--isolated-host",
        action="store_true",
        help="the caller's model host runs outside the checkout with --safe-mode --restricted (TR-10); "
        "skip repository-owned Claude Code configuration",
    )
    p.add_argument(
        "--format",
        choices=("json", "text", "both"),
        default="both",
        help="output format (default: both — text to stderr, json to --output)",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repo_root = args.repo_root
    if not repo_root.is_dir():
        print(f"preflight-untrusted: repo root not found: {repo_root}", file=sys.stderr)
        return 3
    report = run(repo_root, strict=args.strict, strict_urls=args.strict_urls, isolated_host=args.isolated_host)

    if args.format in ("text", "both"):
        print(_render_human(report), file=sys.stderr)
    if args.format in ("json", "both"):
        rendered = json.dumps(report, indent=2, sort_keys=False)
        if args.output == "-":
            print(rendered)
        else:
            Path(args.output).write_text(rendered + "\n", encoding="utf-8")

    if report["finding_count"] == 0:
        return 0
    return 2 if args.strict else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
