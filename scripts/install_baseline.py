#!/usr/bin/env python3
"""Install a secure-coding baseline into Claude Code's instruction files.

What "install" means
--------------------
Claude Code loads instructions from its own fixed locations, so installing the
baseline means putting it where Claude Code already looks and wiring it in:

* ``user`` — the baseline lands in ``~/.claude/`` and is imported from
  ``~/.claude/CLAUDE.md``. It then applies to every repository on this machine.
* ``project`` — the baseline lands in the repository and is imported from the
  project ``CLAUDE.md``. It travels with the repository, so everyone who clones
  it gets the rules.
* ``project-rules`` — the baseline lands in ``.claude/rules/``, which loads
  automatically. This is the project option for a repository whose ``CLAUDE.md``
  should stay untouched, or which has none.

The import is a real import, not a copy of the text into ``CLAUDE.md``: there is
one file on disk, so refreshing it updates every place that reads it.

Where the text comes from
-------------------------
The published baseline, fetched from the URL in the ``baseline`` block of
``config.json``, so an install tracks upstream. The copy bundled in the plugin
is the fallback for when that URL cannot be reached — an air-gapped machine, a
proxy, an outage. The report always names which of the two was used, because a
fallback copy can be older than the published text.

Whatever the source, the content must declare the expected baseline id before
anything is written. That is what stops a captive-portal HTML page, a 404 body,
or a moved URL from being installed as security rules.

Write discipline
----------------
Existing instruction files are only ever appended to, never rewritten or
reordered, and the import line is added only when no import already resolves to
the baseline. Re-running the command is therefore safe: it converges instead of
accumulating. The baseline file itself is overwritten, since it is the plugin's
own artifact and the whole point of ``--refresh``.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _url_guard  # noqa: E402
import baseline_check as bc  # noqa: E402

# A markdown instruction file. Large enough for any real baseline, small enough
# that a redirected download cannot fill the disk.
MAX_FETCH_BYTES = 1_048_576
FETCH_TIMEOUT_SECONDS = 15

# A shallow clone of an instruction-file repository. Bounded so an unreachable
# host falls back to the bundled copy instead of hanging the skill.
GIT_TIMEOUT_SECONDS = 60

SCOPES = ("user", "project", "project-rules")


class InstallError(Exception):
    """A condition the user has to resolve; reported without a traceback."""


def _fetch(url: str) -> bytes:
    """Fetch the baseline over http(s). Raises ``InstallError`` on any failure.

    The URL comes from plugin or organization configuration rather than from a
    scanned repository, so ``check_ip_safety=False``: an internal host is a
    legitimate place for a company baseline, and the allowlist is the control.
    """
    verdict = _url_guard.validate_target_url(url, check_ip_safety=False)
    if not verdict.ok:
        raise InstallError(f"blocked by URL guard: {verdict.reason}")
    request = urllib.request.Request(url, headers={"Accept": "text/markdown, text/plain, */*"})
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310
            return response.read(MAX_FETCH_BYTES + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise InstallError(str(exc)) from exc


def _git_export(spec: dict) -> tuple[str, str]:
    """Read one file out of a git repository. Returns ``(text, origin)``.

    For a baseline kept in a git repository rather than served as a raw file —
    an internal GitLab, a mirror, anything reachable by `git clone` with the
    machine's existing credentials. The clone is shallow, checks out nothing but
    the requested ref, and is deleted afterwards.

    The repository URL is organization configuration, packaged alongside the
    profile's MCP servers and hooks and trusted at the same level. It is never
    taken from a scanned repository.
    """
    url = str(spec.get("url") or "").strip()
    path = str(spec.get("path") or "").strip()
    ref = str(spec.get("ref") or "").strip() or "HEAD"
    if not url or not path:
        raise InstallError("the git baseline source needs both 'url' and 'path'")
    if os.path.isabs(path) or ".." in Path(path).parts:
        raise InstallError(f"the git baseline path must stay inside the repository: {path}")

    with tempfile.TemporaryDirectory(prefix="appsec-baseline-") as tmp:
        command = ["git", "clone", "--depth", "1", "--quiet"]
        if ref != "HEAD":
            command += ["--branch", ref]
        command += ["--", url, tmp]
        try:
            done = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=GIT_TIMEOUT_SECONDS,
                # A prompt would hang a skill that has no terminal to answer it,
                # so an unauthenticated clone fails instead of waiting.
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise InstallError(f"git clone failed: {exc}") from exc
        if done.returncode != 0:
            detail = (done.stderr or done.stdout or "").strip().splitlines()
            raise InstallError(f"git clone failed: {detail[-1] if detail else 'unknown error'}")
        source = Path(tmp) / path
        if not source.is_file():
            raise InstallError(f"'{path}' does not exist in {url} at {ref}")
        return source.read_text(encoding="utf-8", errors="replace"), f"{url} ({ref}) :: {path}"


def _validated(text: str, expected: str, origin: str) -> str:
    """Return ``text`` only when it declares the expected baseline id.

    This is what stops a captive-portal login page, a 404 body, or a URL that
    has moved on to something else from being installed as security rules.
    """
    found = bc.find_ids(text)
    if not any(bc.is_match(f, expected) for f in found):
        got = ", ".join(found) if found else "no baseline id at all"
        raise InstallError(f"{origin} declares {got}, not {expected}")
    return text


def resolve_source(config: dict, *, offline: bool) -> tuple[str, str, str]:
    """Return ``(text, origin, note)`` for the baseline to install.

    The configured source wins — an ``http(s)`` URL, or a file in a git
    repository. The copy bundled in the plugin is the fallback, so an install
    still works air-gapped. ``note`` carries the reason the fallback was used
    and is empty when the configured source loaded.
    """
    expected = config["id"]
    reason = ""

    if offline:
        reason = "--offline"
    elif config.get("url"):
        try:
            raw = _fetch(config["url"])
            if len(raw) > MAX_FETCH_BYTES:
                raise InstallError(f"response larger than {MAX_FETCH_BYTES} bytes")
            text = raw.decode("utf-8", errors="replace")
            return _validated(text, expected, "the fetched document"), config["url"], ""
        except InstallError as exc:
            reason = str(exc)
    elif config.get("git"):
        try:
            text, origin = _git_export(config["git"])
            return _validated(text, expected, origin), origin, ""
        except InstallError as exc:
            reason = str(exc)

    bundled = bc.fallback_path(config)
    if bundled is None:
        raise InstallError(
            f"could not load the baseline ({reason or 'no source configured'}) and this build ships no bundled copy"
        )
    text = bundled.read_text(encoding="utf-8", errors="replace")
    return _validated(text, expected, f"the bundled copy at {bundled}"), str(bundled), reason


def plan(scope: str, repo: Path, home: Path, config: dict) -> dict:
    """Where this scope puts the baseline, and which file imports it."""
    filename = config["install_filename"]
    if scope == "user":
        target = home / ".claude" / filename
        # Absolute, because ``~/.claude/CLAUDE.md`` is read from every working
        # directory and a relative import would be ambiguous about which one it
        # resolves against.
        return {"target": target, "instructions": home / ".claude" / "CLAUDE.md", "import": str(target)}
    if scope == "project":
        return {"target": repo / filename, "instructions": repo / "CLAUDE.md", "import": filename}
    # project-rules: files under .claude/rules/ load on their own, so there is
    # nothing to wire and no existing file to touch.
    return {"target": repo / ".claude" / "rules" / filename, "instructions": None, "import": None}


def _existing_import(instructions: Path, target: Path, home: Path) -> bool:
    """True when ``instructions`` already imports ``target``.

    Resolved rather than string-matched, so a relative and an absolute spelling
    of the same file are recognised as the same import and re-running does not
    append a duplicate.
    """
    if not instructions.is_file():
        return False
    text = bc._read(instructions)
    try:
        wanted = target.resolve()
    except (OSError, RuntimeError):
        return False
    for raw in bc._IMPORT_RE.findall(text):
        resolved = bc._resolve_import(raw, instructions, home)
        if resolved == wanted:
            return True
    return False


def _append_import(instructions: Path, import_path: str, *, dry_run: bool) -> str:
    """Append the import line, preserving everything already in the file."""
    line = f"@{import_path}"
    if dry_run:
        verb = "append to" if instructions.is_file() else "create"
        return f"would {verb} {instructions}: {line}"
    instructions.parent.mkdir(parents=True, exist_ok=True)
    if instructions.is_file():
        current = instructions.read_text(encoding="utf-8")
        separator = "" if current.endswith("\n\n") else ("\n" if current.endswith("\n") else "\n\n")
        with open(instructions, "a", encoding="utf-8") as fh:
            fh.write(f"{separator}{line}\n")
        return f"appended to {instructions}: {line}"
    instructions.write_text(f"{line}\n", encoding="utf-8")
    return f"created {instructions} with {line}"


def find_existing_carrier(repo: Path, home: Path, config: dict, scope: str) -> Path | None:
    """An on-disk file already carrying this baseline, which the wiring can import.

    A repository frequently already has the rules — in ``AGENTS.md`` for Codex and
    Cursor, in ``.github/copilot-instructions.md`` for Copilot, or as a baseline
    file somebody committed but never imported. Writing a second copy beside one
    of those creates exactly the drift the whole design avoids: two files with
    the same rules, diverging from the day one of them is edited. So the import
    points at what is already there.

    Only files inside the repository qualify, and only for the ``project`` scope,
    which is the one that wires an import. ``user`` would import a repository
    path from ``~/.claude/CLAUDE.md`` and break in every other repository on the
    machine; ``project-rules`` wires nothing at all, so it has no import to point
    anywhere.
    """
    if scope != "project":
        return None
    result = bc.check(repo=repo, home=home, config=config)
    for item in result.get("present_unloaded") or []:
        if not bc.is_match(item["id"], config["id"]):
            continue
        path = Path(item["file"])
        # Both sides resolved, or the comparison is between a symlinked spelling
        # and a real one: on macOS /tmp is a link to /private/tmp, and a repo
        # reached through any symlink would silently fail the containment test
        # and lose the reuse.
        if _relative_to_repo(path, repo) is None:
            continue
        return path
    return None


def _relative_to_repo(path: Path, repo: Path) -> str | None:
    """``path`` spelled relative to ``repo``, or None when it lies outside."""
    try:
        return str(path.resolve().relative_to(repo.resolve()))
    except (ValueError, OSError, RuntimeError):
        return None


def install(
    scope: str,
    repo: Path,
    home: Path,
    config: dict,
    *,
    offline: bool = False,
    dry_run: bool = False,
    force: bool = False,
    reuse: bool = True,
) -> list[str]:
    """Perform the install and return the report lines."""
    if scope not in SCOPES:
        raise InstallError(f"unknown scope '{scope}' (expected one of: {', '.join(SCOPES)})")
    if not config["enabled"]:
        raise InstallError("no secure-coding baseline is configured for this build")

    where = plan(scope, repo, home, config)
    target: Path = where["target"]
    steps: list[str] = []

    carrier = find_existing_carrier(repo, home, config, scope) if reuse and not force else None
    if carrier is not None:
        # Nothing is fetched or written: the text is already here, it just was
        # not reachable from an instruction file Claude Code reads. Replacing it
        # would overwrite whatever the team has — possibly a newer text than the
        # bundled fallback — to fix a problem that is only about the wiring.
        if carrier == target:
            steps.append(f"already present: {target} carries {config['id']}, left untouched")
            steps.append("only the import was missing; --refresh replaces the text with the configured source")
        else:
            steps.append(f"reusing {carrier} — it already carries {config['id']}")
            steps.append("nothing written; only the import is added, so there stays one file to keep current")
            target = carrier
            if where["instructions"] is not None:
                where["import"] = _relative_to_repo(carrier, repo) or str(carrier)
    else:
        text, origin, note = resolve_source(config, offline=offline)
        if note == "--offline":
            steps.append("bundled copy by request (--offline) — the configured URL was not contacted")
        elif note:
            source = (
                config.get("url")
                or ((config.get("git") or {}).get("url") if config.get("git") else None)
                or "the configured source"
            )
            steps.append(f"! could not use {source} — {note}")
            steps.append("! installing the bundled copy instead, which may be older than the published text;")
            steps.append("! re-run with --refresh once the URL is reachable")
        steps.append(f"source: {origin}")

        unchanged = target.is_file() and bc._read(target) == text
        try:
            if unchanged and not force:
                steps.append(f"unchanged: {target} already holds this text")
            elif dry_run:
                steps.append(f"would write {target}")
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.is_file():
                    # One backup, replaced each time: enough to undo a bad refresh
                    # without turning the directory into a version history.
                    shutil.copyfile(target, target.with_suffix(target.suffix + ".bak"))
                target.write_text(text, encoding="utf-8")
                steps.append(f"wrote {target}")
        except OSError as exc:
            raise InstallError(f"cannot write: {exc}") from exc

    try:
        instructions: Path | None = where["instructions"]
        if instructions is None:
            steps.append(f"no wiring needed — files in {target.parent} load automatically")
        elif _existing_import(instructions, target, home):
            steps.append(f"already imported by {instructions}")
        else:
            steps.append(_append_import(instructions, where["import"], dry_run=dry_run))
    except OSError as exc:
        # A read-only checkout, a missing home directory, a permission the user
        # does not have. Report the path that failed instead of a traceback —
        # every one of these is fixed outside this program.
        raise InstallError(f"cannot write: {exc}") from exc

    return steps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Install a secure-coding baseline into Claude Code's instruction files.",
    )
    parser.add_argument("--scope", required=True, choices=SCOPES, help="where to install the baseline")
    parser.add_argument("--repo", default=None, help="repository root (default: current working directory)")
    parser.add_argument("--dry-run", action="store_true", help="report what would change, write nothing")
    parser.add_argument("--offline", action="store_true", help="skip the fetch and use the bundled copy")
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="re-fetch and overwrite an installed copy even when it looks current",
    )
    parser.add_argument(
        "--no-reuse",
        action="store_true",
        help="write a fresh copy instead of importing a baseline the repository already carries",
    )
    args = parser.parse_args(argv)

    repo = Path(args.repo).expanduser() if args.repo else Path.cwd()
    home = Path.home()
    config = bc.load_config()

    try:
        steps = install(
            args.scope,
            repo,
            home,
            config,
            offline=args.offline,
            dry_run=args.dry_run,
            force=args.refresh,
            reuse=not args.no_reuse,
        )
    except InstallError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2

    header = "Would install" if args.dry_run else "Installed"
    print(f"{header} {config['name']} ({config['id']}) — scope: {args.scope}")
    for step in steps:
        print(f"  {step}")

    if args.dry_run:
        return 0

    result = bc.check(repo=repo, home=home, config=config)
    print("")
    if result["status"] == "installed":
        print(f"✓ verified: {bc.summary(result)}")
        return 0
    # Written but not detected — the file landed somewhere Claude Code does not
    # read, so say so rather than report a success the session will not show.
    print("✗ written, but the baseline is still not loaded — run", file=sys.stderr)
    print("  /appsec-advisor:verify-baseline for the full picture.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
