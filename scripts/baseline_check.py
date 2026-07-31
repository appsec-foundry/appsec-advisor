#!/usr/bin/env python3
"""Detect whether a secure-coding baseline is loaded into the assistant's instructions.

What this answers
-----------------
A secure-coding baseline is an instruction file the coding assistant reads
before it writes code. Its whole value depends on actually being *in context* —
an instruction file that never loads fails silently, and the assistant behaves
as if the rules do not exist. This module answers the one question that matters
before relying on it: does an instruction file Claude Code loads carry the
configured baseline id?

How the answer is produced
--------------------------
The baseline marks itself with a line of the form ``baseline-id: aisec-0.1``.
So the check is: walk the files Claude Code loads, follow their ``@`` imports,
and look for that marker.

The file list is not a guess. Claude Code's project instruction discovery covers
``CLAUDE.md``, ``.claude/CLAUDE.md``, ``CLAUDE.local.md`` and ``.claude/rules/``,
plus ``~/.claude/CLAUDE.md`` for the user's own machine. Nothing else is
scanned — in particular a bare ``AGENTS.md`` is *not* treated as installed,
because Claude Code does not load it. It counts only when a loaded file imports
it with ``@AGENTS.md``, which the import walk below picks up on its own.

This is presence, not compliance. It proves the rules are in context; whether
the assistant follows them is what the upstream test harness measures.

Why deterministic Python rather than asking the model
-----------------------------------------------------
The baseline also instructs the assistant to name every id it carries when
asked ``baseline?``. That is the better check in one respect — it reads the
model's actual context — and unusable here in two: the session banner is a
startup hook with no model to ask, and an assistant that can see the file in
the repository may read the id rather than recall it, which proves nothing
about loading. A file walk gives the same answer at every call site, costs
about a millisecond, and can run before the session exists.

Latency and dependencies
------------------------
``session_banner`` imports this on every session start, which imposes its
rules: standard library only (the user's ``python3`` is not guaranteed to have
PyYAML), no network, and every failure path silent. The bounds below cap the
walk so an unusual instruction tree cannot stall a session.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Bounds on the import walk. Claude Code resolves imports up to 5 hops deep;
# the file and byte caps exist so a pathological instruction tree — a directory
# of generated rules, an import of something enormous — cannot turn a startup
# hook into a stall.
MAX_IMPORT_DEPTH = 5
MAX_FILES = 64
MAX_FILE_BYTES = 1_048_576

# ``baseline-id: aisec-0.1``. The id convention is ``<name>-<version>[+<derivative>]``,
# so ``+`` and ``.`` are part of the token. The marker is written inside backticks
# in the published baseline, which the pattern simply ignores.
_MARKER_RE = re.compile(r"baseline-id:\s*`?([A-Za-z0-9][A-Za-z0-9._+-]*)")

# A Claude Code import: ``@`` at the start of a line or after whitespace,
# followed by a path. Requiring a preceding boundary keeps e-mail addresses and
# ``user@host`` strings out; the trailing class stops at quotes and backticks so
# an import mentioned inside prose still resolves.
_IMPORT_RE = re.compile(r"(?:^|\s)@([^\s`'\"]+)")

# Relative to the repository root. This is Claude Code's project instruction
# discovery, not a superset of it: a path that is not loaded must not count as
# installed, or the check reports rules that are never in context.
PROJECT_ENTRY_FILES = ("CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md")
PROJECT_ENTRY_GLOB = (".claude/rules", "*.md")

# Relative to the user's home directory. Files under ``~/.claude/rules/`` load
# for every project, ahead of the project's own rules.
USER_ENTRY_FILES = (".claude/CLAUDE.md",)
USER_ENTRY_GLOB = (".claude/rules", "*.md")

# Administrator-deployed instructions that apply to every session on the
# machine and cannot be switched off by a user. An organization that has rolled
# the baseline out this way has already installed it everywhere — so this scope
# has to be checked, or the plugin would keep telling a whole company to install
# what their IT department already deployed.
POLICY_ENTRY_FILES = (
    "/Library/Application Support/ClaudeCode/CLAUDE.md",  # macOS
    "/etc/claude-code/CLAUDE.md",  # Linux and WSL
    r"C:\Program Files\ClaudeCode\CLAUDE.md",  # Windows
)

# The same content can be delivered inline through the ``claudeMd`` key of
# managed-settings.json instead of as a separate file. Same precedence, same
# reach — so it counts the same.
POLICY_SETTINGS_FILES = (
    "/Library/Application Support/ClaudeCode/managed-settings.json",
    "/etc/claude-code/managed-settings.json",
    r"C:\Program Files\ClaudeCode\managed-settings.json",
)

# Instruction files other tools read and Claude Code does not. A baseline here
# is genuinely installed — for Codex, Cursor, Copilot — but it is not in Claude
# Code's context, so it is reported separately rather than as loaded. It is also
# what the installer reuses: where AGENTS.md already carries the rules, the right
# project install is an @AGENTS.md import, not a second copy to keep in sync.
UNLOADED_CANDIDATES = (
    ("AGENTS.md", "AGENTS.md — read by Codex, Cursor, Copilot's agent and others"),
    (".github/copilot-instructions.md", "GitHub Copilot"),
)
UNLOADED_GLOBS = ((".github/instructions", "*.md", "GitHub Copilot"),)


def _plugin_root() -> Path:
    """Resolve the plugin directory, preferring the runtime-provided root."""
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if root:
        return Path(root)
    return Path(__file__).resolve().parent.parent


# Display name for a build whose baseline block sets none. Generic on purpose:
# it heads the banner line and both skills, so a name inherited from elsewhere
# would put someone else's product name on this build's rules.
DEFAULT_NAME = "secure-coding baseline"


def load_config(plugin_root: Path | None = None) -> dict:
    """Return the ``baseline`` block, with the plugin defaults filled in.

    ``config.local.json`` wins over ``config.json``, as everywhere else in the
    plugin. Packaged builds have the organization's own baseline resolved into
    ``config.json`` at build time, so this one read covers both cases.
    """
    root = plugin_root or _plugin_root()
    local = root / "config.local.json"
    path = local if local.is_file() else root / "config.json"
    block: dict = {}
    try:
        with open(path, encoding="utf-8") as fh:
            loaded = json.load(fh).get("baseline")
        if isinstance(loaded, dict):
            block = loaded
    except Exception:  # noqa: BLE001 — a broken config must not break the caller
        block = {}

    git = block.get("git")
    config = {
        "enabled": block.get("enabled", True) is not False,
        "id": _clean(block.get("id")),
        "name": _clean(block.get("name")) or DEFAULT_NAME,
        "url": _clean(block.get("url")),
        "git": git if isinstance(git, dict) else None,
        "fallback_file": _clean(block.get("fallback_file")),
        "install_filename": _clean(block.get("install_filename")) or "secure-coding-baseline.md",
    }
    # An id is what the check compares against; without one there is nothing to
    # check for, so the feature is off regardless of ``enabled``.
    if not config["id"]:
        config["enabled"] = False
    return config


def _clean(value: object) -> str:
    """Return a single-line string, or empty when the value is unusable."""
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())


def fallback_path(config: dict, plugin_root: Path | None = None) -> Path | None:
    """Absolute path of the bundled fallback copy, when this build ships one."""
    rel = config.get("fallback_file")
    if not rel:
        return None
    root = plugin_root or _plugin_root()
    path = (root / rel) if not os.path.isabs(rel) else Path(rel)
    return path if path.is_file() else None


def _read(path: Path) -> str:
    """Read a bounded prefix of a text file; empty string on any failure."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(MAX_FILE_BYTES)
    except OSError:
        return ""


def find_ids(text: str) -> list[str]:
    """Return every baseline id declared in ``text``, in order of appearance."""
    out: list[str] = []
    for match in _MARKER_RE.finditer(text):
        found = match.group(1)
        if found not in out:
            out.append(found)
    return out


def _resolve_import(target: str, containing: Path, home: Path) -> Path | None:
    """Resolve one ``@`` import against the file that declared it.

    Relative imports resolve against the containing file's directory, which is
    how Claude Code reads them; ``~`` and absolute paths are taken as written.
    """
    raw = target.strip().rstrip(".,;:)")
    if not raw:
        return None
    try:
        if raw.startswith("~"):
            candidate = Path(home) / raw[2:] if raw.startswith("~/") else Path(raw).expanduser()
        elif os.path.isabs(raw):
            candidate = Path(raw)
        else:
            candidate = containing.parent / raw
        return candidate.resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def _walk(entry: Path, home: Path) -> list[tuple[Path, str]]:
    """Return ``entry`` and everything it imports, as (path, text) pairs.

    Breadth-first with a visited set, so an import cycle terminates and a file
    reachable by two paths is read once.
    """
    out: list[tuple[Path, str]] = []
    try:
        start = entry.resolve()
    except (OSError, RuntimeError):
        return out
    seen = {start}
    frontier = [start]
    depth = 0
    while frontier and depth <= MAX_IMPORT_DEPTH and len(out) < MAX_FILES:
        next_frontier: list[Path] = []
        for path in frontier:
            text = _read(path)
            if not text:
                continue
            out.append((path, text))
            if len(out) >= MAX_FILES:
                break
            for target in _IMPORT_RE.findall(text):
                resolved = _resolve_import(target, path, home)
                if resolved is None or resolved in seen or not resolved.is_file():
                    continue
                seen.add(resolved)
                next_frontier.append(resolved)
        frontier = next_frontier
        depth += 1
    return out


def _resolved_str(path: Path | str) -> str:
    """Canonical spelling of a path, for comparing two of them safely."""
    try:
        return str(Path(path).resolve())
    except (OSError, RuntimeError):
        return str(path)


def _glob(directory: Path, pattern: str) -> list[Path]:
    """Sorted matches, or nothing when the directory is absent or unreadable."""
    try:
        return sorted(directory.glob(pattern))
    except OSError:
        return []


def _entry_points(repo: Path | None, home: Path, policy_roots: tuple[str, ...] | None = None) -> list[tuple[str, Path]]:
    """The instruction files Claude Code loads, as (scope, path) pairs."""
    entries: list[tuple[str, Path]] = []
    if repo is not None:
        for rel in PROJECT_ENTRY_FILES:
            entries.append(("project", repo / rel))
        rules_dir, pattern = PROJECT_ENTRY_GLOB
        entries.extend(("project", p) for p in _glob(repo / rules_dir, pattern))
    for rel in USER_ENTRY_FILES:
        entries.append(("user", home / rel))
    rules_dir, pattern = USER_ENTRY_GLOB
    entries.extend(("user", p) for p in _glob(home / rules_dir, pattern))
    for raw in policy_roots if policy_roots is not None else POLICY_ENTRY_FILES:
        entries.append(("policy", Path(raw)))
    return entries


def _policy_settings_ids(paths: tuple[str, ...] | None = None) -> list[tuple[str, Path]]:
    """Baseline ids delivered inline through managed-settings.json's ``claudeMd``.

    Read as JSON rather than scanned as text, so a baseline id mentioned in some
    unrelated setting cannot pass for deployed instructions.
    """
    out: list[tuple[str, Path]] = []
    for raw in paths if paths is not None else POLICY_SETTINGS_FILES:
        path = Path(raw)
        text = _read(path)
        if not text:
            continue
        try:
            claude_md = json.loads(text).get("claudeMd")
        except (json.JSONDecodeError, AttributeError):
            continue
        if isinstance(claude_md, str):
            out.extend((found, path) for found in find_ids(claude_md))
    return out


def _unloaded_carriers(repo: Path | None, config: dict) -> list[tuple[Path, str]]:
    """Files carrying instructions that Claude Code does not load, as (path, tool)."""
    if repo is None:
        return []
    out: list[tuple[Path, str]] = [(repo / rel, tool) for rel, tool in UNLOADED_CANDIDATES]
    for directory, pattern, tool in UNLOADED_GLOBS:
        out.extend((path, tool) for path in _glob(repo / directory, pattern))
    # A baseline file dropped into the repository that nothing imports: present,
    # ready to wire up, and the most common "I already have it" case of all.
    out.append((repo / config["install_filename"], "in the repository, but nothing imports it"))
    return out


def is_match(found: str, expected: str) -> bool:
    """True when ``found`` is the expected baseline or a declared derivative of it.

    ``aisec-0.1+acme`` is the same rules adapted by someone, and the convention
    says everything after ``+`` belongs to whoever derived them — so it counts as
    installed and the reported id keeps the suffix, letting the reader see the
    adaptation. A different version (``aisec-0.2``) is deliberately *not* a match:
    it is a different text, and silently accepting it would hide exactly the
    drift this check exists to surface.
    """
    return found == expected or found.startswith(expected + "+")


# Reported narrowest-first: the scope a reader can act on locally is the more
# useful one to name, and a policy deployment is the one they cannot change.
_SCOPE_ORDER = {"project": 0, "user": 1, "policy": 2}


def check(
    repo: Path | None = None,
    home: Path | None = None,
    config: dict | None = None,
    policy_roots: tuple[str, ...] | None = None,
    policy_settings: tuple[str, ...] | None = None,
) -> dict:
    """Report where the configured baseline is loaded from, if anywhere.

    ``repo`` is the repository being worked in, or None to check only the
    machine-wide instructions. ``policy_roots`` / ``policy_settings`` override
    the administrator-deployed locations, which tests need because the real ones
    are absolute system paths.

    Returns a dict that is stable enough to be the JSON contract of this
    module's CLI. ``status`` is ``installed`` (the expected id is loaded),
    ``other`` (some baseline is loaded, but not the configured one), ``missing``
    (no baseline is in Claude Code's context), or ``disabled`` (no baseline is
    configured for this build).

    ``present_unloaded`` is separate from all of that: files that carry the
    baseline for another tool, or a copy sitting in the repository that nothing
    imports. Those are not loaded — but they are the difference between "install
    this" and "wire up what you already have".
    """
    cfg = config if config is not None else load_config()
    result: dict = {
        "status": "disabled",
        "expected_id": cfg["id"],
        "name": cfg["name"],
        "matches": [],
        "other": [],
        "present_unloaded": [],
        "scopes": [],
    }
    if not cfg["enabled"]:
        return result

    home_dir = home or Path.home()

    def record(found: str, scope: str, entry: Path, path: Path) -> None:
        item = {"id": found, "scope": scope, "entry": str(entry), "file": str(path)}
        bucket = "matches" if is_match(found, cfg["id"]) else "other"
        if item not in result[bucket]:
            result[bucket].append(item)

    for scope, entry in _entry_points(repo, home_dir, policy_roots):
        if not entry.is_file():
            continue
        for path, text in _walk(entry, home_dir):
            for found in find_ids(text):
                record(found, scope, entry, path)

    for found, path in _policy_settings_ids(policy_settings):
        record(found, "policy", path, path)

    # Compared against resolved paths, because the walk above records what an
    # import resolved to while the carriers below are spelled relative to the
    # repository. Where those two spellings differ — a symlinked checkout, or
    # macOS, where /tmp is a link to /private/tmp — an already-imported
    # AGENTS.md would be listed a second time as if it were unwired.
    loaded_files = {_resolved_str(item["file"]) for item in result["matches"] + result["other"]}
    for path, tool in _unloaded_carriers(repo, cfg):
        if not path.is_file() or _resolved_str(path) in loaded_files:
            continue
        for found in find_ids(_read(path)):
            item = {"id": found, "file": str(path), "tool": tool}
            if item not in result["present_unloaded"]:
                result["present_unloaded"].append(item)

    if result["matches"]:
        result["status"] = "installed"
        result["scopes"] = sorted({m["scope"] for m in result["matches"]}, key=lambda s: _SCOPE_ORDER.get(s, 9))
    elif result["other"]:
        result["status"] = "other"
        result["scopes"] = sorted({m["scope"] for m in result["other"]}, key=lambda s: _SCOPE_ORDER.get(s, 9))
    else:
        result["status"] = "missing"
    return result


# The scope names are the flag values; these say what each one means for the
# reader. The distinction that matters is whose install it is: "this repo" ships
# with the repository and reaches whoever clones it, while "user" is
# ``~/.claude/`` — the reader's own setup, which reaches all their projects but
# no colleague, so it is named for the machine rather than for that reach.
# "org policy" says outright that it is not the reader's to change.
SCOPE_LABELS = {"project": "this repo", "user": "this machine", "policy": "org policy"}


def scope_text(scopes: object) -> str:
    """Render scopes narrowest-first, e.g. ``this repo+this machine``.

    Public because the banner labels two sets of records — the loaded baseline
    and any foreign one beside it — and both have to read the same way.
    """
    if not isinstance(scopes, (list, tuple, set, frozenset)):
        return ""
    ordered = sorted({str(scope) for scope in scopes}, key=lambda s: _SCOPE_ORDER.get(s, 9))
    return "+".join(SCOPE_LABELS.get(scope, scope) for scope in ordered)


def _scope_labels(result: dict) -> str:
    return scope_text(result.get("scopes"))


def summary(result: dict) -> str:
    """One line naming the state, for the session banner.

    Deliberately short and free of commands: the banner composes those around
    it, and this line has to survive next to a threat-model status line.
    """
    name = result.get("name") or "secure-coding baseline"
    status = result.get("status")
    if status == "installed":
        ids = sorted({m["id"] for m in result["matches"]})
        scopes = _scope_labels(result)
        return f"{name} {', '.join(ids)}" + (f" · {scopes}" if scopes else "")

    # Not loaded, but on disk for another tool or waiting to be wired up. Worth
    # the columns: it changes the next step from "install" to "connect".
    carriers = sorted({Path(item["file"]).name for item in result.get("present_unloaded") or []})
    found_note = f" · on disk in {', '.join(carriers)}" if carriers else ""

    if status == "other":
        ids = sorted({m["id"] for m in result["other"]})
        return f"{name} {result['expected_id']} not loaded · found {', '.join(ids)}{found_note}"
    # "not installed" would contradict a file that is plainly sitting there;
    # what is missing in that case is the wiring, not the rules.
    return f"{name} not loaded{found_note}" if carriers else f"{name} not installed"


def _render(result: dict, config: dict) -> str:
    """The human-readable report printed by ``/appsec-advisor:verify-baseline``."""
    status = result["status"]
    if status == "disabled":
        return "No secure-coding baseline is configured for this build — nothing to verify."

    lines: list[str] = []
    if status == "installed":
        lines.append(f"✓ {result['name']} is loaded.")
    elif status == "other":
        lines.append(f"✗ {result['name']} ({result['expected_id']}) is NOT loaded.")
        lines.append("  A different baseline is in context — the configured rules are not.")
    else:
        lines.append(f"✗ {result['name']} ({result['expected_id']}) is NOT loaded.")

    for record in result["matches"] + result["other"]:
        mark = "✓" if is_match(record["id"], result["expected_id"]) else "!"
        scope = SCOPE_LABELS.get(record["scope"], record["scope"])
        via = "" if record["file"] == record["entry"] else f"\n      via {record['file']}"
        lines.append(f"  {mark} {record['id']}  [{scope}]\n      {record['entry']}{via}")

    carriers = result.get("present_unloaded") or []
    if carriers:
        lines.append("")
        lines.append("  On disk, but not in Claude Code's context:")
        for item in carriers:
            lines.append(f"  · {item['id']}  {item['file']}\n      {item['tool']}")
        if status != "installed":
            lines.append("")
            lines.append("  /appsec-advisor:install-baseline imports one of these instead of")
            lines.append("  writing a second copy, so there stays one file to keep current.")

    if status != "installed" and not carriers:
        lines.append("")
        lines.append("  Install it with /appsec-advisor:install-baseline")

    lines.append("")
    lines.append("  Checked, plus their @ imports: project CLAUDE.md, .claude/CLAUDE.md,")
    lines.append("           CLAUDE.local.md, .claude/rules/*.md, ~/.claude/CLAUDE.md,")
    lines.append("           ~/.claude/rules/*.md, and the managed-policy CLAUDE.md.")
    lines.append("  This confirms the rules are in context, not that they were followed.")
    if config.get("url"):
        lines.append(f"  Baseline source: {config['url']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Report whether the configured secure-coding baseline is loaded.",
    )
    parser.add_argument(
        "--repo",
        default=None,
        help="repository to check (default: current working directory; pass '' for user scope only)",
    )
    parser.add_argument("--json", action="store_true", help="emit the result as JSON")
    args = parser.parse_args(argv)

    if args.repo is None:
        repo: Path | None = Path.cwd()
    elif args.repo == "":
        repo = None
    else:
        repo = Path(args.repo).expanduser()

    config = load_config()
    result = check(repo=repo, config=config)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(_render(result, config))
    # Exit code is the verdict, so a CI step can gate on it. ``disabled`` is not
    # a failure: a build with no baseline configured has nothing to fail on.
    return 0 if result["status"] in ("installed", "disabled") else 1


if __name__ == "__main__":
    sys.exit(main())
