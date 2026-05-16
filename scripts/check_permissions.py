#!/usr/bin/env python3
"""
check_permissions.py — Preflight the Claude Code permission allow-list for
the AppSec plugin.

Reads `data/required-permissions.yaml` (source of truth), resolves the user's
effective permissions by merging user / project / local settings.json files,
and reports which required entries are missing. With `--update` it merges the
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
        out.append(
            {
                "entry": str(item["entry"]),
                "reason": str(item.get("reason", "")),
                "category": str(item.get("category", "other")),
            }
        )
    return out


# ---------- template expansion -------------------------------------------

_PLACEHOLDER_RE = re.compile(r"\$\{(OUTPUT_DIR|REPO_ROOT|PLUGIN_ROOT)\}")


def expand_entry(entry: str, repo_root: Path, output_dir: Path, plugin_dir: Path | None = None) -> str:
    def _sub(m: re.Match[str]) -> str:
        key = m.group(1)
        if key == "OUTPUT_DIR":
            return str(output_dir)
        if key == "REPO_ROOT":
            return str(repo_root)
        return str(plugin_dir) if plugin_dir else m.group(0)

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
    m_rule = re.fullmatch(r"([\w\[]+)\((.*)\)", rule)
    m_need = re.fullmatch(r"([\w\[]+)\((.*)\)", needed)
    if not (m_rule and m_need):
        return False
    if m_rule.group(1) != m_need.group(1):
        return False
    rule_arg, need_arg = m_rule.group(2), m_need.group(2)
    if rule_arg == "*":
        return True
    # Bash: "prefix:*" covers "prefix:anything" (or "prefix anything" for [ command)
    if rule_arg.endswith(":*"):
        cmd_prefix = rule_arg[:-2]  # strip ":*" to get the command name
        if need_arg == cmd_prefix or need_arg.startswith(cmd_prefix + ":") or need_arg.startswith(cmd_prefix + " "):
            return True
    # Path globs: ".../**" covers deeper paths, but NOT dotfiles.
    # Claude Code's ** glob does not match files/dirs whose name starts with '.'.
    # Required dotfile entries must be listed as explicit paths in required-permissions.yaml
    # and as explicit entries in settings.json — there is no wildcard that covers them.
    if rule_arg.endswith("/**"):
        base = rule_arg[:-3]
        if need_arg == base:
            return True
        if need_arg.startswith(base + "/") or need_arg.startswith(base):
            remainder = need_arg[len(base) :].lstrip("/")
            if remainder.startswith("."):
                return False
            return True
    return False


def diff_required(required: list[dict], granted: Iterable[str]) -> list[dict]:
    granted_list = list(granted)
    missing = []
    for req in required:
        if not any(_rule_covers(rule, req["entry"]) for rule in granted_list):
            missing.append(req)
    return missing


def diff_required_for_project(required: list[dict], by_scope: dict[str, list[str]]) -> list[dict]:
    """Return entries not covered by project/local scopes (ignoring user-level).

    Claude Code sub-agents spawned via the Agent tool run in their own session.
    User-level (~/.claude/settings.json) permissions may not be inherited by those
    sub-agent sessions. To guarantee prompt-free unattended runs, every required
    entry must be present in the project or local settings, not just at user level.
    """
    project_grants = by_scope.get("project", []) + by_scope.get("local", [])
    missing = []
    for req in required:
        if not any(_rule_covers(rule, req["entry"]) for rule in project_grants):
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


def render_human(
    required: list[dict],
    missing: list[dict],
    scopes_with_counts: dict[str, int],
    scope_in_use: str | None,
    user_only: list[dict] | None = None,
    repo_root: Path | None = None,
    output_dir: Path | None = None,
    plugin_dir: Path | None = None,
    scope_paths: dict[str, Path] | None = None,
) -> str:
    repo_label = str(repo_root) if repo_root else "repo"
    out_label = str(output_dir) if output_dir else "output"

    lines = []
    lines.append("/appsec-advisor:check-permissions")
    lines.append("=" * 50)
    lines.append("")

    if scope_paths:
        lines.append("Settings files checked:")
        for scope, path in scope_paths.items():
            count = scopes_with_counts.get(scope, 0)
            status = f"{count} entr{'y' if count == 1 else 'ies'}" if path.is_file() else "not found"
            lines.append(f"  {scope:<8} {path} ({status})")
        lines.append("")

    # --- success path ---
    if not missing and not user_only:
        lines.append(
            f"All permissions are already configured to scan repo path {repo_label} and write output to {out_label}."
        )
        lines.append("Unattended /appsec-advisor:create-threat-model runs will not prompt.")
        return "\n".join(lines) + "\n"

    # --- user-level-only warning (no truly missing entries) ---
    if not missing and user_only:
        lines.append(f"All permissions to scan {repo_label} and write reports to {out_label} are set,")
        lines.append(
            f"but {len(user_only)} entr{'y is' if len(user_only) == 1 else 'ies are'} only in ~/.claude/settings.json (user-level)."
        )
        lines.append("Sub-agents spawned by the plugin may not inherit user-level settings and will prompt.")
        lines.append("")
        for cat, items in _group_by_category(user_only).items():
            lines.append(f"  [{cat}]")
            for m in items:
                lines.append(f"    - {m['entry']}")
        lines.append("")
        lines.append("Run /appsec-advisor:check-permissions --update to copy them into .claude/settings.local.json.")
        return "\n".join(lines) + "\n"

    # --- failure path ---
    n_missing = len(missing)
    lines.append(f"Missing permissions to scan {repo_label} and write reports to {out_label}:")
    lines.append("")
    for cat, items in _group_by_category(missing).items():
        lines.append(f"  [{cat}]")
        for m in items:
            lines.append(f"    - {m['entry']}")
            if m["reason"]:
                lines.append(f"        why: {m['reason']}")
    lines.append("")
    if user_only:
        lines.append(
            f"Additionally, {len(user_only)} entr{'y is' if len(user_only) == 1 else 'ies are'} only in ~/.claude/settings.json"
        )
        lines.append("and will not be inherited by sub-agents:")
        lines.append("")
        for cat, items in _group_by_category(user_only).items():
            lines.append(f"  [{cat}]")
            for m in items:
                lines.append(f"    - {m['entry']}")
        lines.append("")
    scope_target = f"--scope {scope_in_use} " if scope_in_use else ""
    lines.append(f"Run /appsec-advisor:check-permissions --update {scope_target}to add them to your settings.")
    return "\n".join(lines) + "\n"


def render_json(
    required: list[dict], missing: list[dict], scopes_with_counts: dict[str, int], user_only: list[dict] | None = None
) -> str:
    return (
        json.dumps(
            {
                "required_total": len(required),
                "granted_by_scope": scopes_with_counts,
                "missing_total": len(missing),
                "missing": missing,
                "user_level_only": user_only or [],
            },
            indent=2,
        )
        + "\n"
    )


# ---------- CLI -----------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="check_permissions.py",
        description="Preflight the AppSec plugin's Claude Code permission allow-list.",
        add_help=False,
    )
    p.add_argument(
        "--repo-root",
        default=os.environ.get("REPO_ROOT", os.getcwd()),
        help="Repo root for resolving Write/Edit glob placeholders and project settings (default: cwd)",
    )
    p.add_argument(
        "--output-dir",
        default=os.environ.get("OUTPUT_DIR", ""),
        help="Output dir for ${OUTPUT_DIR} placeholders (default: <repo-root>/docs/security)",
    )
    p.add_argument(
        "--plugin-dir",
        default=str(PLUGIN_ROOT),
        help="Plugin directory for resolving ${PLUGIN_ROOT} placeholders (default: auto-detected)",
    )
    p.add_argument(
        "--scope",
        choices=list(SCOPE_PATHS),
        default="local",
        help="Target scope when --update is given (default: local — gitignored per-user file)",
    )
    p.add_argument(
        "--update", action="store_true", help="Merge missing entries into the chosen scope instead of reporting"
    )
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p.add_argument("-h", "--help", action="store_true", help="Show this help and exit")
    return p


HELP_TEXT = """\
/appsec-advisor:check-permissions — Preflight Claude Code permissions.

USAGE
  /appsec-advisor:check-permissions [--repo <path>] [--output <path>]
                                    [--plugin-dir <path>]
                                    [--scope local|project|user]
                                    [--update] [--json]

OPTIONS
  --repo <path>        Repository to be scanned.
                       Grants Read(<path>/**) for recon + STRIDE.
                       Settings files checked: <path>/.claude/settings.{json,local.json}
                       Default: current working directory.
  --output <path>      Output directory for threat model files.
                       Grants Write(<path>/**) and Edit(<path>/**).
                       Default: <repo>/docs/security
  --plugin-dir <path>  Plugin installation directory.
                       Grants Read(<path>/**) for schemas, templates, CWE data.
                       Default: auto-detected from script location.
  --scope <scope>      Settings file to write into when --update is given:
                         local   → <repo>/.claude/settings.local.json  (default; gitignored)
                         project → <repo>/.claude/settings.json        (committed)
                         user    → ~/.claude/settings.json             (global)
  --update             Merge missing entries into --scope instead of reporting.
  --json               Emit machine-readable JSON.
  -h, --help           Show this help and exit.

EXIT CODES
  0   All required permissions present in project/local settings.
  1   Permissions missing or only at user-level (sub-agents won't inherit).
  2   Usage or IO error.

The default (read-only) invocation is safe at any time. It never writes
files and never dispatches an agent.
"""


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.help:
        sys.stdout.write(HELP_TEXT)
        return 0

    repo_root = Path(args.repo_root).resolve()
    output_dir = Path(args.output_dir).resolve() if args.output_dir else (repo_root / "docs" / "security")
    plugin_dir = Path(args.plugin_dir).resolve()

    required_raw = load_required()
    required = [{**r, "entry": expand_entry(r["entry"], repo_root, output_dir, plugin_dir)} for r in required_raw]

    by_scope = effective_allow(repo_root)
    all_granted = [rule for scope_rules in by_scope.values() for rule in scope_rules]
    # Entries missing from all scopes (truly absent)
    missing = diff_required(required, all_granted)
    # Entries present only at user-level — sub-agents may not inherit these
    project_missing = diff_required_for_project(required, by_scope)
    user_only = [r for r in project_missing if r not in missing]
    scopes_with_counts = {scope: len(rules) for scope, rules in by_scope.items()}

    if args.update:
        target = _settings_path(args.scope, repo_root)
        # Write both truly-missing entries AND user-only entries so the project
        # settings are self-contained and sub-agents don't inherit from user-level.
        to_write = [m["entry"] for m in missing] + [m["entry"] for m in user_only]
        added, kept = write_missing(target, to_write)
        if args.json:
            sys.stdout.write(
                json.dumps(
                    {
                        "wrote": str(target),
                        "added": added,
                        "already_present": kept,
                    },
                    indent=2,
                )
                + "\n"
            )
        else:
            sys.stdout.write(
                f"Wrote {added} new entr{'y' if added == 1 else 'ies'} to {target} "
                f"({kept} already present).\n"
                f"Restart Claude Code or re-load the session for changes to take effect.\n"
            )
        return 0

    scope_file_paths = {scope: _settings_path(scope, repo_root) for scope in SCOPE_PATHS}

    if args.json:
        sys.stdout.write(render_json(required, missing, scopes_with_counts, user_only))
    else:
        sys.stdout.write(
            render_human(
                required,
                missing,
                scopes_with_counts,
                scope_in_use=None,
                user_only=user_only or None,
                repo_root=repo_root,
                output_dir=output_dir,
                plugin_dir=plugin_dir,
                scope_paths=scope_file_paths,
            )
        )
    return 0 if not missing and not user_only else 1


if __name__ == "__main__":
    sys.exit(main())
