#!/usr/bin/env python3
"""Refresh an installed secure-coding baseline from the source that publishes it.

Why this is not ``install --refresh``
-------------------------------------
Installing chooses a scope and wires an import. Updating chooses nothing: the
baseline is already loaded from somewhere, and the only open question is whether
the text on disk still matches the configured source. ``install --refresh``
cannot answer that, because it writes the *scope's canonical path* — which is a
second file whenever the install reused a baseline the repository already
carried, leaving two copies of the same rules to drift apart. This command
starts from what is loaded and rewrites that file, or explains why it will not.

What it refuses to do
---------------------
* **Install.** A machine with no baseline still has a scope to choose, and that
  choice belongs to ``install-baseline``.
* **Overwrite a file it does not own.** A carrier such as ``AGENTS.md`` holds a
  team's own instructions around the rules; replacing it with the baseline text
  would delete them. Only a file named like the plugin's own artifact is
  rewritten.
* **Fall back to the bundled copy.** An update that quietly writes the plugin's
  vendored text after a failed fetch would replace a current copy with an older
  one and still report success. ``--offline`` asks for that copy explicitly.
* **Move to a different baseline id.** The id is configuration: the session
  banner, ``verify-baseline`` and an organization profile all check for the one
  this build declares. A newly published version is therefore reported, not
  installed — it arrives with the plugin release that vendors it, which is what
  ``sync_baseline.py --accept-id`` prepares.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import baseline_check as bc  # noqa: E402
import sync_baseline as sb  # noqa: E402

# Reported, not raised, when the published baseline has moved to a new id: the
# state is legitimate and the fix is a release, so it is separated from the
# failures a user can act on now.
ACTION_NEEDED = 3


class UpdateError(Exception):
    """A condition the user has to resolve; reported without a traceback."""


def source_text(config: dict, *, offline: bool) -> tuple[str, str]:
    """Return ``(text, origin)`` for the text to update to."""
    if offline:
        bundled = bc.fallback_path(config)
        if bundled is None:
            raise UpdateError("this build ships no bundled copy to update from")
        try:
            return bundled.read_text(encoding="utf-8", errors="replace"), str(bundled)
        except OSError as exc:
            raise UpdateError(f"cannot read the bundled copy: {exc}") from exc
    try:
        return sb.fetch_published(config)
    except sb.SyncError as exc:
        raise UpdateError(f"{exc}; --offline updates from the copy bundled in the plugin") from exc


def verdict(text: str, config: dict) -> tuple[str, str]:
    """Classify a fetched document as ``current``, ``changed`` or ``foreign``.

    The split follows ``sync_baseline``: a document declaring *some* baseline id
    is a published version this build has not adopted, whatever the id looks
    like — upstream renames the id as readily as it bumps the version, and
    neither is a failure. A document declaring none is not a baseline at all,
    which is the captive-portal case and the only real error of the two.
    """
    expected = config["id"]
    found = bc.find_ids(text)
    for candidate in found:
        if bc.is_match(candidate, expected):
            return "current", candidate
    if not found:
        return "foreign", ""
    return "changed", found[0]


def owned(path: Path, config: dict) -> bool:
    """True when ``path`` is the plugin's own baseline artifact.

    Filename rather than content, because the question is who maintains the
    file, not what it currently holds. ``secure-coding-baseline.md`` is written
    by an install and holds nothing else; ``AGENTS.md`` was written by the team
    and holds the baseline among their own instructions.
    """
    return path.name == config["install_filename"]


def _partition(result: dict, config: dict) -> tuple[list[Path], list[str]]:
    """Split the loaded baseline files into the ones to rewrite and notes.

    Both the matching and the outdated files: an older version of the configured
    baseline is the case this command exists for, and it lands in its own bucket
    rather than under ``matches``.
    """
    targets: list[Path] = []
    notes: list[str] = []
    seen: set[str] = set()
    for match in result["matches"] + result["older"]:
        path = Path(match["file"])
        key = bc._resolved_str(path)
        if key in seen:
            continue
        seen.add(key)
        if match["scope"] == "policy":
            notes.append(f"org policy deploys {path} — updating it is the administrator's job, not this command's")
        elif not owned(path, config):
            notes.append(
                f"left alone: {path} carries the rules among its own content, so it is not this command's to rewrite"
            )
        else:
            targets.append(path)
    return targets, notes


def update(
    repo: Path,
    home: Path,
    config: dict,
    *,
    offline: bool = False,
    dry_run: bool = False,
) -> tuple[list[str], int]:
    """Perform the update and return ``(report lines, exit code)``."""
    if not config["enabled"]:
        return ["no secure-coding baseline is configured for this build"], 0

    result = bc.check(repo=repo, home=home, config=config)
    status = result["status"]
    if status == "missing":
        return [
            f"{config['name']} ({config['id']}) is not loaded, so there is nothing to update",
            "install it with /appsec-advisor:install-baseline",
        ], 0
    if status == "other":
        loaded = ", ".join(sorted({item["id"] for item in result["other"]}))
        return [
            f"a different baseline is loaded ({loaded}), not the configured {config['id']}",
            "nothing was touched — replacing someone else's rules is not this command's call",
        ], 0
    if status == "newer":
        loaded = ", ".join(sorted({item["id"] for item in result["newer"]}))
        return [
            f"the loaded baseline ({loaded}) is ahead of the configured {config['id']} — nothing to update",
            "updating would write the older rules over the newer ones",
        ], 0

    targets, steps = _partition(result, config)
    if not targets:
        steps.append("nothing left to update")
        return steps, 0

    text, origin = source_text(config, offline=offline)
    state, found = verdict(text, config)
    if state == "foreign":
        raise UpdateError(f"{origin} declares no baseline id — refusing to install it as security rules")
    if state == "changed":
        steps.extend(
            [
                f"{origin} now publishes {found}; this build is configured for {config['id']}",
                "the id is what the session banner and verify-baseline check for, so a new version",
                "arrives with the plugin release that vendors it rather than with this command",
            ]
        )
        return steps, ACTION_NEEDED

    steps.append(f"source: {origin} ({found})")
    for path in targets:
        if bc._read(path) == text:
            steps.append(f"already current: {path}")
            continue
        if dry_run:
            steps.append(f"would update {path}")
            continue
        try:
            # One backup, replaced each time: enough to undo a bad update
            # without turning the directory into a version history.
            shutil.copyfile(path, path.with_suffix(path.suffix + ".bak"))
            path.write_text(text, encoding="utf-8")
        except OSError as exc:
            raise UpdateError(f"cannot write {path}: {exc}") from exc
        steps.append(f"updated {path}")
    return steps, 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Refresh an installed secure-coding baseline from its published source.",
    )
    parser.add_argument("--repo", default=None, help="repository root (default: current working directory)")
    parser.add_argument("--dry-run", action="store_true", help="report what would change, write nothing")
    parser.add_argument("--offline", action="store_true", help="update from the copy bundled in the plugin")
    args = parser.parse_args(argv)

    config = bc.load_config()
    if not config["enabled"]:
        print("No secure-coding baseline is configured for this build — nothing to update.")
        return 0

    try:
        steps, code = update(
            Path(args.repo).expanduser() if args.repo else Path.cwd(),
            Path.home(),
            config,
            offline=args.offline,
            dry_run=args.dry_run,
        )
    except UpdateError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2

    header = "Would update" if args.dry_run else "Update"
    print(f"{header} {config['name']} ({config['id']})")
    for step in steps:
        print(f"  {step}")
    return code


if __name__ == "__main__":
    sys.exit(main())
