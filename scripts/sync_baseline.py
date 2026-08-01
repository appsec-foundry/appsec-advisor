#!/usr/bin/env python3
"""Refresh the bundled fallback baseline from its published source.

Why this exists
---------------
The file in ``data/baselines/`` is a verbatim copy of a baseline published
elsewhere. An install fetches that published text directly, so the copy in the
repository is only what an air-gapped or proxied machine falls back to. It is
therefore exactly as current as the last time somebody vendored it, and nothing
in the runtime notices when it falls behind: the installer reports which of the
two sources it used, never how old the fallback is.

This is that vendoring step — fetch, compare, write, and say what changed.

Why it is not a gate
--------------------
It talks to the network, which makes it a maintainer command and keeps it out
of ``make check`` and ``make release-check``. Those stay deterministic and
offline, and a release must not fail because a host is unreachable. Noticing
drift between releases is a separate, scheduled question.

Why a version change stops
--------------------------
A baseline id is configuration, not just text: ``config.json`` declares the id
an install has to find, and the README beside the bundled copy names the id it
carries. Writing a newly published version into the file alone would leave both
claiming the old one, so a changed id stops and asks. ``--accept-id`` then makes
all three edits together, or none of them.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import baseline_check as bc  # noqa: E402
import install_baseline as ib  # noqa: E402


class SyncError(Exception):
    """A condition the maintainer has to resolve; reported without a traceback."""


class VersionChange(SyncError):
    """The published baseline carries a different id than this build declares."""


def load_release_config(plugin_root: Path) -> dict:
    """Return the ``baseline`` block as the release carries it.

    Deliberately reads ``config.json`` and ignores the git-ignored
    ``config.local.json`` that wins at runtime: the vendored copy and the id it
    claims ship together, so a local override must not decide what gets written
    into the repository.
    """
    path = plugin_root / "config.json"
    try:
        block = json.loads(path.read_text(encoding="utf-8")).get("baseline")
    except (OSError, ValueError) as exc:
        raise SyncError(f"cannot read {path}: {exc}") from exc
    if not isinstance(block, dict) or block.get("enabled") is False:
        raise SyncError("config.json configures no secure-coding baseline")
    if not str(block.get("id") or "").strip():
        raise SyncError("config.json declares no baseline id to sync against")
    return block


def bundled_target(config: dict, plugin_root: Path) -> Path:
    """Absolute path of the copy to refresh."""
    rel = str(config.get("fallback_file") or "").strip()
    if not rel:
        raise SyncError("config.json ships no fallback_file, so there is nothing to refresh")
    target = (plugin_root / rel).resolve()
    if not target.is_relative_to(plugin_root.resolve()):
        raise SyncError(f"fallback_file must stay inside the plugin: {rel}")
    return target


def fetch_published(config: dict) -> tuple[str, str]:
    """Return ``(text, origin)`` for the published baseline.

    Unlike an install this never falls back to the bundled copy: a sync that
    cannot reach the source would otherwise report success after writing the
    file with itself.
    """
    url = str(config.get("url") or "").strip()
    git = config.get("git") if isinstance(config.get("git"), dict) else None
    try:
        if url:
            raw = ib._fetch(url)
            if len(raw) > ib.MAX_FETCH_BYTES:
                raise ib.InstallError(f"response larger than {ib.MAX_FETCH_BYTES} bytes")
            return raw.decode("utf-8", errors="replace"), url
        if git:
            return ib._git_export(git)
    except ib.InstallError as exc:
        raise SyncError(f"could not read the published baseline: {exc}") from exc
    raise SyncError("config.json names neither a url nor a git source to sync from")


def edit_config_id(text: str, old: str, new: str) -> str:
    """Return ``config.json`` with the baseline id replaced.

    A targeted substitution rather than a re-serialisation, so the file keeps
    its comment key, its ordering, and its number formatting.
    """
    pattern = re.compile(r'("id"\s*:\s*")' + re.escape(old) + r'(")')
    edited, count = pattern.subn(lambda m: m.group(1) + new + m.group(2), text)
    if count != 1:
        raise SyncError(f'expected exactly one "id": "{old}" in config.json, found {count}')
    return edited


def edit_readme_id(text: str, filename: str, old: str, new: str) -> str:
    """Return the bundled-baselines README with the id cell of one row replaced."""
    lines = text.splitlines(keepends=True)
    hits = [
        i for i, line in enumerate(lines) if line.lstrip().startswith("|") and filename in line and f"`{old}`" in line
    ]
    if len(hits) != 1:
        raise SyncError(f"expected exactly one table row naming {filename} and `{old}`, found {len(hits)}")
    lines[hits[0]] = lines[hits[0]].replace(f"`{old}`", f"`{new}`")
    return "".join(lines)


def sync(
    plugin_root: Path,
    *,
    dry_run: bool = False,
    accept_id: str | None = None,
) -> list[str]:
    """Refresh the bundled copy and return the report lines."""
    config = load_release_config(plugin_root)
    expected = str(config["id"]).strip()
    target = bundled_target(config, plugin_root)
    text, origin = fetch_published(config)

    found = bc.find_ids(text)
    if not found:
        raise SyncError(f"{origin} declares no baseline id — refusing to vendor it as security rules")

    steps = [f"source:    {origin}", f"target:    {target.relative_to(plugin_root)}"]
    readme = target.parent / "README.md"

    if any(bc.is_match(candidate, expected) for candidate in found):
        steps.append(f"id:        {expected} (unchanged)")
        if target.is_file() and target.read_text(encoding="utf-8") == text:
            steps.append("unchanged: the bundled copy already matches the published text")
            return steps
        steps.append(_write(target, text, dry_run=dry_run))
        steps.append("installed copies are untouched — they refresh with `install-baseline --refresh`")
        return steps

    published = found[0]
    if accept_id is None:
        raise VersionChange(
            f"{origin} publishes {published}, this build declares {expected}.\n"
            f"A version change is a decision, not a copy: re-run with ACCEPT_ID={published} "
            f"to write the file, config.json and {readme.name} together."
        )
    if not any(bc.is_match(candidate, accept_id) for candidate in found):
        raise SyncError(f"{origin} declares {', '.join(found)}, not the accepted {accept_id}")

    # Every edit is computed before anything is written, so a README that does
    # not match leaves the repository consistent instead of half-bumped.
    config_path = plugin_root / "config.json"
    config_text = edit_config_id(config_path.read_text(encoding="utf-8"), expected, accept_id)
    readme_text = (
        edit_readme_id(readme.read_text(encoding="utf-8"), target.name, expected, accept_id)
        if readme.is_file()
        else None
    )

    steps.append(f"id:        {expected} -> {accept_id}")
    steps.append(_write(target, text, dry_run=dry_run))
    steps.append(_write(config_path, config_text, dry_run=dry_run))
    if readme_text is None:
        steps.append(f"! no README beside the bundled copy — record {accept_id} wherever it is documented")
    else:
        steps.append(_write(readme, readme_text, dry_run=dry_run))
    steps.append("review the diff, then run `make check` — the id gate compares config.json with the bundled copy")
    return steps


def _write(path: Path, text: str, *, dry_run: bool) -> str:
    if dry_run:
        return f"would write {path.name}"
    path.write_text(text, encoding="utf-8")
    return f"wrote      {path.name}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Refresh the bundled fallback baseline from its published source.",
    )
    parser.add_argument(
        "--plugin-root",
        default=str(Path(__file__).resolve().parent.parent),
        help="plugin root holding config.json (default: this repository)",
    )
    parser.add_argument("--dry-run", action="store_true", help="report what would change, write nothing")
    parser.add_argument(
        "--accept-id",
        default=None,
        help="accept a newly published baseline id and bump config.json and the README with it",
    )
    args = parser.parse_args(argv)

    try:
        steps = sync(
            Path(args.plugin_root).expanduser(),
            dry_run=args.dry_run,
            accept_id=(args.accept_id or None),
        )
    except VersionChange as exc:
        print(f"ACTION NEEDED: {exc}", file=sys.stderr)
        return 3
    except SyncError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    for step in steps:
        print(step)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
