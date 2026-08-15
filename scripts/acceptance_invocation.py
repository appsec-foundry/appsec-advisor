#!/usr/bin/env python3
"""Generate and verify a paid acceptance invocation from the cohort manifest.

Four pre-R10 runs were rejected for the same reason: the command line was
retyped and lost a flag, so resolution produced a different run than the plan
requires, and the mistake surfaced only after the scan had been paid for. The
cohort manifest is the one definition; this tool turns a member into its exact
invocation and checks a started run against it.

  acceptance_invocation.py print  --member r10 --repo <path> --output-root <dir>
  acceptance_invocation.py verify --member r10 --output-dir <dir>

``verify`` reads the run's persisted `.skill-config.json`, compares every field
the manifest declares, and prints the cohort hash over exactly those fields.
Run it as soon as the resolved config exists — before the first model dispatch,
while the run is still free to abandon. Exit 1 on any mismatch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import sys
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
PLUGIN_ROOT = SCRIPT_DIR.parent
MANIFEST_PATH = PLUGIN_ROOT / "docs" / "internal" / "acceptance-cohort.yaml"
RUNNER = "scripts/run-headless.sh"
RESOLVED_CONFIG = ".skill-config.json"


class CohortError(RuntimeError):
    """The manifest, the member, or the started run does not match."""


def load_manifest(path: Path = MANIFEST_PATH) -> dict:
    try:
        manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CohortError(f"cannot read the acceptance cohort manifest: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise CohortError("acceptance cohort manifest has an unsupported shape")
    members = manifest.get("members")
    if not isinstance(members, dict) or not members:
        raise CohortError("acceptance cohort manifest declares no members")
    for name, member in members.items():
        if not isinstance(member, dict):
            raise CohortError(f"cohort member {name!r} is not a mapping")
        if not isinstance(member.get("flags"), list) or not member["flags"]:
            raise CohortError(f"cohort member {name!r} declares no flags")
        if not isinstance(member.get("expect"), dict) or not member["expect"]:
            raise CohortError(f"cohort member {name!r} declares no expectations")
        if not isinstance(member.get("env", {}), dict):
            raise CohortError(f"cohort member {name!r} has a malformed env block")
    return manifest


def member_of(manifest: dict, name: str) -> dict:
    try:
        return manifest["members"][name]
    except KeyError:
        known = ", ".join(sorted(manifest["members"]))
        raise CohortError(f"unknown cohort member {name!r}; the manifest defines: {known}") from None


def cohort_hash(expect: dict) -> str:
    """Stable digest over the fields that define membership, nothing else."""
    payload = json.dumps(expect, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def assert_clean_target(target: Path) -> None:
    """Refuse a target that already holds a run.

    A cohort member gets its own directory. Pointing one at a directory that
    already holds another run mixes two runs into the appended event logs and,
    with `--rebuild`, clears the artifacts that were being preserved as
    evidence — which is how a reserved postfix path was overwritten twice
    before. This is the last moment it is free to catch.
    """
    if not target.exists():
        return
    occupied = sorted(p.name for p in target.iterdir())
    if occupied:
        raise CohortError(
            f"{target} already holds a run ({len(occupied)} entries, e.g. {', '.join(occupied[:3])}). "
            "Move it aside and use an empty directory; --rebuild would clear it and the event logs would mix."
        )


def invocation(member: dict, name: str, repo: Path, output_root: Path) -> str:
    """The exact shell line for one member, ready to paste."""
    env = "".join(f"{key}={shlex.quote(str(value))} " for key, value in sorted(member.get("env", {}).items()))
    parts = [
        RUNNER,
        "--repo",
        str(repo),
        "--output",
        str(output_root / name),
        *(str(flag) for flag in member["flags"]),
    ]
    return env + " ".join(shlex.quote(part) for part in parts)


def verify(member: dict, output_dir: Path) -> list[str]:
    """Return one line per field that does not match the manifest."""
    path = output_dir / RESOLVED_CONFIG
    try:
        resolved = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CohortError(f"cannot read the resolved config at {path}: {exc}") from exc
    if not isinstance(resolved, dict):
        raise CohortError(f"the resolved config at {path} is not an object")
    mismatches = []
    for key, expected in sorted(member["expect"].items()):
        actual = resolved.get(key, "<absent>")
        if actual != expected:
            mismatches.append(f"{key}: expected {expected!r}, resolved {actual!r}")
    return mismatches


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    printer = sub.add_parser("print", help="emit the exact invocation for one member")
    printer.add_argument("--member", required=True)
    printer.add_argument("--repo", required=True, help="target repository to assess")
    printer.add_argument("--output-root", required=True, help="directory that receives one subdirectory per member")
    printer.add_argument(
        "--allow-existing",
        action="store_true",
        help="emit the invocation even though the member's directory already holds a run",
    )

    verifier = sub.add_parser("verify", help="check a started run against the manifest")
    verifier.add_argument("--member", required=True)
    verifier.add_argument("--output-dir", required=True, help="the run's OUTPUT_DIR")

    args = parser.parse_args(argv)
    try:
        manifest = load_manifest()
        member = member_of(manifest, args.member)
        if args.command == "print":
            output_root = Path(args.output_root)
            if not args.allow_existing:
                assert_clean_target(output_root / args.member)
            print(invocation(member, args.member, Path(args.repo), output_root))
            print(f"# cohort={args.member} hash={cohort_hash(member['expect'])}", file=sys.stderr)
            return 0
        mismatches = verify(member, Path(args.output_dir))
    except CohortError as exc:
        print(f"acceptance cohort: {exc}", file=sys.stderr)
        return 1
    if mismatches:
        print(f"{args.member}: the started run is not a cohort member", file=sys.stderr)
        for line in mismatches:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"{args.member}: resolved config matches  hash={cohort_hash(member['expect'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
