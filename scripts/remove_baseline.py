#!/usr/bin/env python3
"""Remove an installed secure-coding baseline from Claude Code's instruction files.

What "remove" means
-------------------
Installing wires the baseline into a file Claude Code reads. Removing it undoes
that wiring, so the rules stop loading at the next session start. That is the
whole goal, and it needs no deletion: the import line is what puts the text in
context, and dropping it is reversible by re-running the install.

Deleting the baseline file is therefore a separate, opt-in step behind
``--delete-file``. The ``project-rules`` scope is the exception: files under
``.claude/rules/`` load on their own, so there is no import to drop and removing
the file *is* the removal. That scope refuses to act without the flag.

What this program may delete
----------------------------
Only the target of ``install_baseline.plan()`` for the requested scope, and its
``.bak`` sibling. Nothing else is ever unlinked, whatever an import points at.

That matters because an install does not always write the file it wires up:
``find_existing_carrier`` deliberately imports an ``AGENTS.md`` or a
``.github/copilot-instructions.md`` the repository already carries, rather than
writing a second copy. Those are the user's files. Restricting deletion to the
scope's own target means no heuristic has to guess who wrote what.

One case stays genuinely ambiguous: a repository that committed a file at
exactly ``install_filename`` gets it left untouched by the install, which only
adds the import. Afterwards that state is indistinguishable from a
plugin-written copy. Nothing on disk records which it was — there is no install
manifest — so the report names whether git tracks the file and the caller
confirms before the flag is passed.

Write discipline
----------------
Only whole lines that consist of nothing but the import are dropped; an import
embedded in a sentence is reported and left alone, because rewriting it would
destroy text the user wrote. Every instruction file is backed up to ``.bak``
before it is edited. Nothing else in the file is reordered, reflowed, or
normalized.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import baseline_check as bc  # noqa: E402
import install_baseline as ib  # noqa: E402

SCOPES = ib.SCOPES


class RemoveError(Exception):
    """A condition the user has to resolve; reported without a traceback."""


def _declares(path: Path, config: dict) -> bool:
    """True when ``path`` carries the configured baseline id or a derivative."""
    return any(bc.is_match(found, config["id"]) for found in bc.find_ids(bc._read(path)))


def _git_tracked(path: Path, repo: Path) -> bool:
    """True when git tracks ``path``, which says the file predates any install.

    The one signal that separates a copy this plugin wrote from one the team
    committed: an installed file is left uncommitted for the user to review, so
    a tracked file is theirs until they say otherwise.
    """
    try:
        done = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "--error-unmatch", "--", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


def baseline_imports(instructions: Path, home: Path, config: dict, target: Path) -> tuple[list[int], list[str]]:
    """Line indexes of the baseline imports in ``instructions``, plus what was skipped.

    An import counts when the file it resolves to declares the baseline, or when
    it resolves to this scope's own target — the second case catches the line
    left behind after someone deleted the file by hand.

    The installer's own note above an import goes with it. Left behind it would
    describe a baseline that no longer loads, and point at commands for it.
    """
    drop: list[int] = []
    skipped: list[str] = []
    text = bc._read(instructions)
    try:
        wanted = target.resolve()
    except (OSError, RuntimeError):
        wanted = target
    lines = text.splitlines()
    for index, line in enumerate(lines):
        found = bc._IMPORT_RE.findall(line)
        if not found:
            continue
        resolved = bc._resolve_import(found[0], instructions, home)
        if resolved is None:
            continue
        if not (resolved == wanted or (resolved.is_file() and _declares(resolved, config))):
            continue
        # Only a line that is nothing but the import can be dropped whole. One
        # written into a sentence is the user's prose, and cutting the line would
        # take their words with it.
        if len(found) != 1 or line.strip() != f"@{found[0]}":
            skipped.append(f"line {index + 1} of {instructions} mentions {found[0]} in text — remove it by hand")
            continue
        drop.append(index)
        if index and bc.IMPORT_NOTE_RE.match(lines[index - 1].strip()):
            drop.append(index - 1)
    return sorted(drop), skipped


def _drop_lines(instructions: Path, indexes: list[int], *, dry_run: bool) -> list[str]:
    """Delete the given lines, keeping every other byte of the file."""
    if dry_run:
        return [f"would remove {len(indexes)} line(s) from {instructions}"]
    text = instructions.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    kept = [line for index, line in enumerate(lines) if index not in set(indexes)]
    backup = instructions.with_suffix(instructions.suffix + ".bak")
    try:
        shutil.copyfile(instructions, backup)
        instructions.write_text("".join(kept), encoding="utf-8")
    except OSError as exc:
        raise RemoveError(f"cannot write: {exc}") from exc
    return [f"removed {len(indexes)} line(s) from {instructions}", f"backup: {backup}"]


def delete_risks(target: Path, repo: Path) -> list[str]:
    """What the caller has to weigh before the file is deleted, worst first.

    Returned rather than printed so the skill can put them in front of the user
    as the confirmation, which is the only place they can still change anything.
    """
    risks = [f"deleting {target} loses any local edit to the rules; the text is not backed up"]
    if _git_tracked(target, repo):
        risks.insert(
            0,
            f"git tracks {target} — it predates this install, so it is the repository's file, not one the plugin wrote",
        )
    return risks


def _delete(target: Path, *, dry_run: bool) -> list[str]:
    """Delete the baseline file and the backup an install left beside it."""
    steps: list[str] = []
    for path in (target, target.with_suffix(target.suffix + ".bak")):
        if not path.is_file():
            continue
        if dry_run:
            steps.append(f"would delete {path}")
            continue
        try:
            path.unlink()
        except OSError as exc:
            raise RemoveError(f"cannot delete {path}: {exc}") from exc
        steps.append(f"deleted {path}")
    return steps


def remove(
    scope: str,
    repo: Path,
    home: Path,
    config: dict,
    *,
    delete_file: bool = False,
    dry_run: bool = False,
) -> list[str]:
    """Perform the removal and return the report lines."""
    if scope not in SCOPES:
        raise RemoveError(f"unknown scope '{scope}' (expected one of: {', '.join(SCOPES)})")
    if not config["enabled"]:
        raise RemoveError("no secure-coding baseline is configured for this build")

    where = ib.plan(scope, repo, home, config)
    target: Path = where["target"]
    instructions: Path | None = where["instructions"]
    steps: list[str] = []

    if instructions is None:
        if not target.is_file():
            return [f"nothing to remove: {target} does not exist"]
        if not _declares(target, config):
            raise RemoveError(f"{target} does not declare {config['id']} — left untouched")
        if not delete_file:
            raise RemoveError(
                f"in the {scope} scope the file is the wiring, so removing the baseline means "
                f"deleting {target}. Re-run with --delete-file once that is what you want."
            )
        steps.extend(f"! {risk}" for risk in delete_risks(target, repo))
        return steps + _delete(target, dry_run=dry_run)

    drop, skipped = baseline_imports(instructions, home, config, target)
    steps.extend(f"! {note}" for note in skipped)
    if drop:
        steps.extend(_drop_lines(instructions, drop, dry_run=dry_run))
    elif not skipped:
        steps.append(f"no baseline import found in {instructions}")

    if not target.is_file():
        steps.append(f"no file at {target}")
    elif not _declares(target, config):
        steps.append(f"kept {target}: it does not declare {config['id']}")
    elif delete_file:
        steps.extend(f"! {risk}" for risk in delete_risks(target, repo))
        steps.extend(_delete(target, dry_run=dry_run))
    else:
        note = " (tracked by git — it predates the install)" if _git_tracked(target, repo) else ""
        steps.append(f"kept {target}{note} — --delete-file removes the file too")

    return steps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Remove an installed secure-coding baseline from Claude Code's instruction files.",
    )
    parser.add_argument("--scope", required=True, choices=SCOPES, help="which install to remove")
    parser.add_argument("--repo", default=None, help="repository root (default: current working directory)")
    parser.add_argument("--dry-run", action="store_true", help="report what would change, write nothing")
    parser.add_argument(
        "--delete-file",
        action="store_true",
        help="also delete the baseline file, not just the import that loads it",
    )
    args = parser.parse_args(argv)

    repo = Path(args.repo).expanduser() if args.repo else Path.cwd()
    home = Path.home()
    config = bc.load_config()

    try:
        steps = remove(
            args.scope,
            repo,
            home,
            config,
            delete_file=args.delete_file,
            dry_run=args.dry_run,
        )
    except RemoveError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2

    header = "Would remove" if args.dry_run else "Removed"
    print(f"{header} {config['name']} ({config['id']}) — scope: {args.scope}")
    for step in steps:
        print(f"  {step}")

    if args.dry_run:
        return 0

    result = bc.check(repo=repo, home=home, config=config)
    print("")
    if result["status"] != "installed":
        print("✓ the baseline no longer loads (from the next session start).")
        return 0
    # Still loaded from somewhere else: a second scope, or an organization-wide
    # policy deployment that no local removal can reach. Naming it is the point.
    print(f"! still loaded — {bc.summary(result)}")
    print("  /appsec-advisor:verify-baseline shows every scope it comes from.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
