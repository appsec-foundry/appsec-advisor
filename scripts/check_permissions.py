#!/usr/bin/env python3
"""
check_permissions.py — Preflight the Claude Code permission allow-list for
the AppSec plugin.

Reads `data/required-permissions.yaml` (source of truth), resolves the user's
effective permissions by merging user / project / local settings.json files,
and reports which required entries are missing. With `--write` it merges the
missing entries into a chosen scope so the next run stops prompting.

Exit codes:
  0 — all required permissions are granted (or were just written).
  1 — required permissions missing (read-only mode) or write target is dirty.
  2 — usage / IO / parse error.

Invoked by the `/appsec-advisor:check-permissions` skill, but also safe to
run directly for CI drift-checks.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable

try:
    import yaml  # PyYAML is already a plugin dependency
except ImportError:
    sys.stderr.write("error: PyYAML is required (pip install pyyaml)\n")
    sys.exit(2)

HERE = Path(__file__).resolve().parent
PLUGIN_ROOT = HERE.parent
DATA_FILE = PLUGIN_ROOT / "data" / "required-permissions.yaml"

SCOPE_PATHS = {
    # resolved lazily against --repo-root so tests can override
    "local": ".claude/settings.local.json",
    "project": ".claude/settings.json",
    "user": None,  # ~/.claude/settings.json — resolved via Path.home()
}


# ---------- data loading -------------------------------------------------

def load_required(path: Path = DATA_FILE) -> list[dict]:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise SystemExit(f"error: cannot read {path}: {e}")
    except yaml.YAMLError as e:
        raise SystemExit(f"error: invalid YAML in {path}: {e}")
    if not isinstance(doc, dict) or "required" not in doc:
        raise SystemExit(f"error: {path} missing top-level 'required' list")
    entries = doc["required"]
    if not isinstance(entries, list):
        raise SystemExit(f"error: {path} 'required' is not a list")
    out = []
    for i, item in enumerate(entries):
        if not isinstance(item, dict) or "entry" not in item:
            raise SystemExit(f"error: {path} entry #{i} missing 'entry' field")
        out.append({
            "entry": str(item["entry"]),
            "reason": str(item.get("reason", "")),
            "category": str(item.get("category", "other")),
        })
    return out


# ---------- template expansion -------------------------------------------

_PLACEHOLDER_RE = re.compile(r"\$\{(OUTPUT_DIR|REPO_ROOT)\}")


def expand_entry(entry: str, repo_root: Path, output_dir: Path) -> str:
    def _sub(m: re.Match[str]) -> str:
        return str(output_dir) if m.group(1) == "OUTPUT_DIR" else str(repo_root)
    return _PLACEHOLDER_RE.sub(_sub, entry)


# ---------- settings.json reading ----------------------------------------

def _settings_path(scope: str, repo_root: Path) -> Path:
    if scope == "user":
        return Path.home() / ".claude" / "settings.json"
    rel = SCOPE_PATHS[scope]
    return repo_root / rel


def load_allow(path: Path) -> list[str]:
    if not path.is_file():
        return []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        sys.stderr.write(f"warning: ignoring unreadable {path}: {e}\n")
        return []
    perms = doc.get("permissions") or {}
    allow = perms.get("allow") or []
    return [str(x) for x in allow if isinstance(x, str)]


def effective_allow(repo_root: Path) -> dict[str, list[str]]:
    """Merge permissions across all three scopes, keyed by scope."""
    return {scope: load_allow(_settings_path(scope, repo_root)) for scope in SCOPE_PATHS}


# ---------- matching -----------------------------------------------------

def _rule_covers(rule: str, needed: str) -> bool:
    """
    True if a settings.json `rule` entry would satisfy a `needed` entry.

    Handles the two forms Claude Code uses:
      • `Bash(prefix:*)` — tool-scoped; equal or more general prefix covers.
      • `Write(path)`  — glob path; `**` at the end subsumes deeper paths.
    For anything else, fall back to exact-match.
    """
    if rule == needed:
        return True
    # Tool-scoped form: Tool(args)
    m_rule = re.fullmatch(r"(\w+)\((.*)\)", rule)
    m_need = re.fullmatch(r"(\w+)\((.*)\)", needed)
    if not (m_rule and m_need):
        return False
    if m_rule.group(1) != m_need.group(1):
        return False
    rule_arg, need_arg = m_rule.group(2), m_need.group(2)
    if rule_arg == "*":
        return True
    # Bash: "prefix:*" covers "prefix:anything"
    if rule_arg.endswith(":*") and need_arg.startswith(rule_arg[:-1]):
        return True
    # Path globs: ".../**" covers deeper paths
    if rule_arg.endswith("/**"):
        base = rule_arg[:-3]
        return need_arg == base or need_arg.startswith(base)
    return False


def diff_required(required: list[dict], granted: Iterable[str]) -> list[dict]:
    granted_list = list(granted)
    missing = []
    for req in required:
        if not any(_rule_covers(rule, req["entry"]) for rule in granted_list):
            missing.append(req)
    return missing


# ---------- write path ----------------------------------------------------

def write_missing(path: Path, missing_entries: list[str]) -> tuple[int, int]:
    """Merge missing entries into path's permissions.allow. Returns (added, existing_count)."""
    doc: dict = {}
    if path.is_file():
        try:
            doc = json.loads(path.read_text(encoding="utf-8")) or {}
        except json.JSONDecodeError as e:
            raise SystemExit(f"error: cannot merge into {path} (invalid JSON): {e}")
    if not isinstance(doc, dict):
        raise SystemExit(f"error: {path} top level is not an object")
    perms = doc.setdefault("permissions", {})
    if not isinstance(perms, dict):
        raise SystemExit(f"error: {path} 'permissions' is not an object")
    allow = perms.setdefault("allow", [])
    if not isinstance(allow, list):
        raise SystemExit(f"error: {path} 'permissions.allow' is not a list")
    existing = {str(x) for x in allow if isinstance(x, str)}
    added = 0
    for e in missing_entries:
        if e not in existing:
            allow.append(e)
            existing.add(e)
            added += 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return added, len(existing) - added


# ---------- rendering -----------------------------------------------------

def _group_by_category(missing: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for m in missing:
        out.setdefault(m["category"], []).append(m)
    return out


def render_human(required: list[dict], missing: list[dict], scopes_with_counts: dict[str, int],
                 scope_in_use: str | None) -> str:
    n_req = len(required)
    n_missing = len(missing)
    lines = []
    lines.append("/appsec-advisor:check-permissions")
    lines.append("=" * 50)
    lines.append("")
    lines.append(f"Required entries ............ {n_req}")
    for scope, count in scopes_with_counts.items():
        lines.append(f"Granted via {scope:<8}......... {count}")
    lines.append(f"Missing ..................... {n_missing}")
    lines.append("")
    if not missing:
        lines.append("All required permissions are granted. Unattended runs should not prompt.")
        return "\n".join(lines) + "\n"
    lines.append(f"The following {n_missing} entr{'y is' if n_missing == 1 else 'ies are'} missing:")
    lines.append("")
    for cat, items in _group_by_category(missing).items():
        lines.append(f"  [{cat}]")
        for m in items:
            lines.append(f"    - {m['entry']}")
            if m["reason"]:
                lines.append(f"        why: {m['reason']}")
    lines.append("")
    if scope_in_use:
        lines.append(f"Run with --write (scope={scope_in_use}) to merge these into your settings.")
    else:
        lines.append("Re-run with --write to merge these into .claude/settings.local.json,")
        lines.append("or --write --scope project|user to target a different file.")
    return "\n".join(lines) + "\n"


def render_json(required: list[dict], missing: list[dict],
                scopes_with_counts: dict[str, int]) -> str:
    return json.dumps({
        "required_total": len(required),
        "granted_by_scope": scopes_with_counts,
        "missing_total": len(missing),
        "missing": missing,
    }, indent=2) + "\n"


# ---------- CLI -----------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="check_permissions.py",
        description="Preflight the AppSec plugin's Claude Code permission allow-list.",
    )
    p.add_argument("--repo-root", default=os.environ.get("REPO_ROOT", os.getcwd()),
                   help="Repo root for resolving Write/Edit glob placeholders and project settings (default: cwd)")
    p.add_argument("--output-dir", default=os.environ.get("OUTPUT_DIR", ""),
                   help="Output dir for ${OUTPUT_DIR} placeholders (default: <repo-root>/docs/security)")
    p.add_argument("--scope", choices=list(SCOPE_PATHS), default="local",
                   help="Target scope when --write is given (default: local — gitignored per-user file)")
    p.add_argument("--write", action="store_true",
                   help="Merge missing entries into the chosen scope instead of reporting")
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    output_dir = Path(args.output_dir).resolve() if args.output_dir else (repo_root / "docs" / "security")

    required_raw = load_required()
    required = [
        {**r, "entry": expand_entry(r["entry"], repo_root, output_dir)}
        for r in required_raw
    ]

    by_scope = effective_allow(repo_root)
    all_granted = [rule for scope_rules in by_scope.values() for rule in scope_rules]
    missing = diff_required(required, all_granted)
    scopes_with_counts = {scope: len(rules) for scope, rules in by_scope.items()}

    if args.write:
        target = _settings_path(args.scope, repo_root)
        added, kept = write_missing(target, [m["entry"] for m in missing])
        if args.json:
            sys.stdout.write(json.dumps({
                "wrote": str(target), "added": added, "already_present": kept,
            }, indent=2) + "\n")
        else:
            sys.stdout.write(
                f"Wrote {added} new entr{'y' if added == 1 else 'ies'} to {target} "
                f"({kept} already present).\n"
                f"Restart Claude Code or re-load the session for changes to take effect.\n"
            )
        return 0

    if args.json:
        sys.stdout.write(render_json(required, missing, scopes_with_counts))
    else:
        sys.stdout.write(render_human(required, missing, scopes_with_counts, scope_in_use=None))
    return 0 if not missing else 1


if __name__ == "__main__":
    sys.exit(main())
