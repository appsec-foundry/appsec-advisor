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

Why an org profile is the same job
----------------------------------
An organization that ships its own baseline declares the identical three things
in its profile — an id, a fetchable source, and a vendored copy — and its copy
goes stale for the identical reason. ``--profile`` points the same sync at that
profile instead of this repository. Only where the id is declared differs: the
profile YAML rather than ``config.json`` and a README table.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import baseline_check as bc  # noqa: E402
import install_baseline as ib  # noqa: E402
import validate_org_profile as vop  # noqa: E402


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


def load_profile_config(profile_path: Path) -> dict:
    """Return the ``baseline`` block of an org profile.

    The packager resolves this same block into the packaged ``config.json``, so
    what is synced here is what an install will later fetch and check against.
    """
    import yaml

    try:
        with profile_path.open(encoding="utf-8") as fh:
            profile = yaml.safe_load(fh)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise SyncError(f"cannot read {profile_path}: {exc}") from exc
    block = profile.get("baseline") if isinstance(profile, dict) else None
    if not isinstance(block, dict) or block.get("enabled") is False:
        raise SyncError(f"{profile_path.name} configures no secure-coding baseline")
    if not str(block.get("id") or "").strip():
        raise SyncError("the profile declares no baseline id to sync against")
    return block


def profile_target(config: dict, profile_dir: Path) -> Path:
    """Absolute path of the copy an org profile vendors."""
    rel = str(config.get("file") or "").strip()
    if not rel:
        raise SyncError(
            "the profile declares no baseline.file, so there is nothing to refresh — "
            "a profile without a vendored copy also has no offline install path"
        )
    resolved, err = vop.resolve_under(profile_dir, rel)
    if err or resolved is None:
        raise SyncError(f"baseline.file: {err}")
    return resolved


@dataclass(frozen=True)
class SyncTarget:
    """What one sync refreshes, and where the id it carries is declared.

    ``kind`` decides only how an accepted id change is written: the id lives in
    ``config.json`` plus a README table here, and in the profile YAML there.
    Everything else — fetching, comparing, refusing — is the same work.
    """

    kind: str
    config: dict
    root: Path
    path: Path
    declares_id: Path
    gate_hint: str


def release_target(plugin_root: Path) -> SyncTarget:
    """The bundled fallback baseline of a plugin checkout."""
    config = load_release_config(plugin_root)
    return SyncTarget(
        kind="plugin",
        config=config,
        root=plugin_root,
        path=bundled_target(config, plugin_root),
        declares_id=plugin_root / "config.json",
        gate_hint="review the diff, then run `make check` — the id gate compares config.json with the bundled copy",
    )


def org_profile_target(profile_path: Path) -> SyncTarget:
    """The baseline an org profile vendors beside its own configuration."""
    profile_dir = profile_path.parent
    config = load_profile_config(profile_path)
    return SyncTarget(
        kind="profile",
        config=config,
        root=profile_dir,
        path=profile_target(config, profile_dir),
        declares_id=profile_path,
        gate_hint=(
            f"review the diff, then validate the profile — validate_org_profile.py "
            f"compares {profile_path.name} with the vendored copy"
        ),
    )


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


def edit_profile_id(text: str, old: str, new: str) -> str:
    """Return the org profile with its baseline id replaced.

    Line-scoped and count-checked rather than clever: a profile may well carry
    other ``id:`` keys, and guessing which one means the baseline would rewrite
    the wrong block. Anything but exactly one line declaring the current id is
    reported instead of edited.
    """
    pattern = re.compile(r"^(\s*id:\s*)(['\"]?)" + re.escape(old) + r"\2(\s*(?:#.*)?)$")
    hits = [i for i, line in enumerate(text.splitlines()) if pattern.match(line)]
    if len(hits) != 1:
        raise SyncError(
            f"expected exactly one line declaring id '{old}' in the profile, found {len(hits)} — "
            f"set the id to '{new}' by hand and re-run"
        )
    lines = text.splitlines(keepends=True)
    lines[hits[0]] = pattern.sub(lambda m: m.group(1) + m.group(2) + new + m.group(2) + m.group(3), lines[hits[0]])
    return "".join(lines)


def plan_id_change(target: SyncTarget, old: str, new: str) -> tuple[list[tuple[Path, str]], list[str]]:
    """Return ``(edits, notes)`` for an accepted id change, writing nothing.

    Every edit is computed before the first write, so a file that does not match
    leaves the repository consistent instead of half-bumped.
    """
    if target.kind == "profile":
        profile_text = edit_profile_id(target.declares_id.read_text(encoding="utf-8"), old, new)
        return [(target.declares_id, profile_text)], []

    config_text = edit_config_id(target.declares_id.read_text(encoding="utf-8"), old, new)
    readme = target.path.parent / "README.md"
    if not readme.is_file():
        return (
            [(target.declares_id, config_text)],
            [f"! no README beside the bundled copy — record {new} wherever it is documented"],
        )
    readme_text = edit_readme_id(readme.read_text(encoding="utf-8"), target.path.name, old, new)
    return [(target.declares_id, config_text), (readme, readme_text)], []


def sync_target(
    target: SyncTarget,
    *,
    dry_run: bool = False,
    accept_id: str | None = None,
) -> list[str]:
    """Refresh one vendored copy and return the report lines."""
    expected = str(target.config["id"]).strip()
    text, origin = fetch_published(target.config)

    found = bc.find_ids(text)
    if not found:
        raise SyncError(f"{origin} declares no baseline id — refusing to vendor it as security rules")

    steps = [f"source:    {origin}", f"target:    {target.path.relative_to(target.root)}"]

    if any(bc.is_match(candidate, expected) for candidate in found):
        steps.append(f"id:        {expected} (unchanged)")
        if target.path.is_file() and target.path.read_text(encoding="utf-8") == text:
            steps.append("unchanged: the bundled copy already matches the published text")
            return steps
        steps.append(_write(target.path, text, dry_run=dry_run))
        steps.append("installed copies are untouched — they refresh with `install-baseline --refresh`")
        return steps

    published = found[0]
    if accept_id is None:
        raise VersionChange(
            f"{origin} publishes {published}, this build declares {expected}.\n"
            f"A version change is a decision, not a copy: re-run with ACCEPT_ID={published} "
            f"to write the file and {target.declares_id.name} together."
        )
    if not any(bc.is_match(candidate, accept_id) for candidate in found):
        raise SyncError(f"{origin} declares {', '.join(found)}, not the accepted {accept_id}")

    edits, notes = plan_id_change(target, expected, accept_id)

    steps.append(f"id:        {expected} -> {accept_id}")
    steps.append(_write(target.path, text, dry_run=dry_run))
    for path, edited in edits:
        steps.append(_write(path, edited, dry_run=dry_run))
    steps.extend(notes)
    steps.append(target.gate_hint)
    return steps


def sync(
    plugin_root: Path,
    *,
    dry_run: bool = False,
    accept_id: str | None = None,
) -> list[str]:
    """Refresh the bundled copy of a plugin checkout."""
    return sync_target(release_target(plugin_root), dry_run=dry_run, accept_id=accept_id)


def sync_profile(
    profile_path: Path,
    *,
    dry_run: bool = False,
    accept_id: str | None = None,
) -> list[str]:
    """Refresh the copy an org profile vendors."""
    return sync_target(org_profile_target(profile_path), dry_run=dry_run, accept_id=accept_id)


def _write(path: Path, text: str, *, dry_run: bool) -> str:
    if dry_run:
        return f"would write {path.name}"
    path.write_text(text, encoding="utf-8")
    return f"wrote      {path.name}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Refresh a vendored fallback baseline from its published source.",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--plugin-root",
        default=str(Path(__file__).resolve().parent.parent),
        help="plugin root holding config.json (default: this repository)",
    )
    source.add_argument(
        "--profile",
        default=None,
        help="org-profile.yaml whose own baseline.file is refreshed instead",
    )
    parser.add_argument("--dry-run", action="store_true", help="report what would change, write nothing")
    parser.add_argument(
        "--accept-id",
        default=None,
        help="accept a newly published baseline id and bump the file declaring it along with the copy",
    )
    args = parser.parse_args(argv)

    try:
        if args.profile:
            steps = sync_profile(
                Path(args.profile).expanduser().resolve(),
                dry_run=args.dry_run,
                accept_id=(args.accept_id or None),
            )
        else:
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
