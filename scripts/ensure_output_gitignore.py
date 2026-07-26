#!/usr/bin/env python3
"""ensure_output_gitignore.py — establish the secure-by-default ``.gitignore``
entry for the assessment output directory.

``skills/publish-threat-model`` describes itself as "the deliberate counterpart
to the secure-by-default ``.gitignore``", and ``publish_threat_model.patch_gitignore``
looks for a literal ``docs/security/`` line to insert its negation exceptions
after. Nothing created that line: ``setup-target`` does not, and the only
``.gitignore`` writer in the plugin is the publish step itself, which runs long
after a report exists. A first assessment therefore left the whole output
directory tracked.

That matters because the redaction sweep is deliberately narrow.
``redact_known_secrets._ARTIFACT_GLOBS`` is an allowlist covering the
deliverables and the finding pipeline; the remaining intermediates
(``.recon-summary.md``, ``.threat-modeling-context.md``, dispatch context,
logs) are never redacted precisely because they are never supposed to be
published. On the 2026-07-25 juice-shop run ``.recon-summary.md`` held a
credential in cleartext while the directory was fully committable — the
protection the allowlist relies on simply was not there.

This module writes the base ignore line once, so the layering the rest of the
plugin already assumes actually holds. The completion summary keeps its own
warning for the case where a rule cannot be added safely.

Deliberately conservative — it does nothing when:

* the output directory is not inside a git work tree;
* a rule for the directory already exists (the user's own, or ours);
* a ``!``-negation for the directory exists, meaning the user published
  already. Appending the base rule below such a line would re-ignore the very
  files that negation exists to publish, because later rules win in git.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

MARKER = "# appsec-advisor: assessment output — publish deliberately via /appsec-advisor:publish-threat-model"


def _repo_root(start: Path) -> Path | None:
    """Return the git work-tree root containing ``start``, or None."""
    try:
        done = subprocess.run(
            ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    root = done.stdout.strip()
    return Path(root) if root else None


def _rule_present(text: str, rel: str) -> bool:
    """True when .gitignore already carries a rule — or a negation — for ``rel``.

    Two things count. A rule covering the whole directory means the default is
    established. A ``!``-negation under it means the user published
    deliberately — appending the base rule after such a line would silently
    un-publish those files, because later rules win in git.

    A rule for individual entries does NOT count. Earlier versions had the
    context-resolver agent append a fixed partial denylist
    (``<dir>/.stride-*.json``, ``<dir>/.agent-run.log``, …) that never covered
    every intermediate — ``.recon-summary.md`` was absent, and that is one which
    can hold a credential in cleartext. Treating such a list as sufficient would
    leave exactly the gap this module closes.
    """
    base = rel.rstrip("/")
    whole_dir = {base, f"{base}/", f"{base}/*", f"{base}/**"}
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("!"):
            body = stripped[1:].strip().lstrip("/")
            if body == base or body.startswith(f"{base}/"):
                return True
            continue
        if stripped.lstrip("/") in whole_dir:
            return True
    return False


def ensure(output_dir: Path) -> str | None:
    """Add the base ignore rule for ``output_dir`` when it is safe to do so.

    Returns a short human-readable receipt when the file was changed, else None.
    Never raises — a failure here must not block an assessment.
    """
    try:
        output_dir = output_dir.resolve()
        root = _repo_root(output_dir)
        if root is None:
            return None
        try:
            rel = output_dir.relative_to(root.resolve()).as_posix()
        except ValueError:
            return None
        if not rel or rel == ".":
            return None

        gitignore = root / ".gitignore"
        text = gitignore.read_text(encoding="utf-8", errors="replace") if gitignore.exists() else ""
        if _rule_present(text, rel):
            return None

        # ``<dir>/**``, never ``<dir>/``. Git cannot re-include a file whose
        # parent directory is excluded, so the plain directory form silently
        # disables every ``!``-negation publish_threat_model.patch_gitignore
        # writes — the deliverable stays ignored and publishing becomes a no-op.
        # Matching the directory's entries instead keeps negation working.
        # Both forms are anchors patch_gitignore searches for; only this one
        # functions.
        block = f"{MARKER}\n{rel}/**\n"
        if text and not text.endswith("\n"):
            text += "\n"
        gitignore.write_text(f"{text}\n{block}" if text else block, encoding="utf-8")
        return f"gitignore: {rel}/ ignored by default"
    except OSError:
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args(argv)
    receipt = ensure(args.output_dir)
    if receipt:
        print(receipt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
