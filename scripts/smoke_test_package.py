#!/usr/bin/env python3
"""Smoke-test a packaged internal appsec-advisor plugin.

Checks the *built artifact contract* a developer relies on, independently of how
the build ran: plugin identity, org-profile wiring, a fully rewritten command
namespace, and a discoverable entry command. No API calls, no analysis run.

    python3 scripts/smoke_test_package.py build/acme-appsec --name acme-appsec

Exits non-zero on the first broken assertion. Run it as the last CI step after
package_internal_plugin.py, or against an extracted tarball on a dev machine.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

UPSTREAM_NAMESPACE = "appsec-advisor"
TEXT_SUFFIXES = {".json", ".md", ".txt", ".yaml", ".yml"}


def _die(message: str) -> None:
    print(f"SMOKE FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def _text_files(root: Path):
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            yield path


def check_plugin_identity(root: Path, name: str) -> None:
    plugin_path = root / ".claude-plugin" / "plugin.json"
    if not plugin_path.is_file():
        _die(f"missing {plugin_path.relative_to(root)}")
    data = json.loads(plugin_path.read_text(encoding="utf-8"))
    if data.get("name") != name:
        _die(f"plugin.json name is {data.get('name')!r}, expected {name!r}")
    if not data.get("version"):
        _die("plugin.json version is empty")


def check_org_profile_wired(root: Path) -> None:
    config_path = root / "config.json"
    if not config_path.is_file():
        _die("missing config.json")
    profile = json.loads(config_path.read_text(encoding="utf-8")).get(
        "organization_profile", {}
    )
    if profile.get("enabled") is not True:
        _die("config.json organization_profile.enabled is not true")
    rel = profile.get("path")
    if not rel:
        _die("config.json organization_profile.path is empty")
    bundled = root / rel
    if not bundled.is_file():
        _die(f"bundled org profile not found at {rel}")
    if not bundled.read_text(encoding="utf-8").strip():
        _die(f"bundled org profile {rel} is empty")


def check_namespace_rewritten(root: Path, name: str) -> None:
    needle = f"{UPSTREAM_NAMESPACE}:"
    leaks = [
        str(p.relative_to(root))
        for p in _text_files(root)
        if needle in p.read_text(encoding="utf-8", errors="ignore")
    ]
    if leaks:
        shown = "\n  - ".join(leaks[:20])
        _die(f"upstream namespace {needle!r} still present:\n  - {shown}")

    entry = f"{name}:create-threat-model"
    skills = root / "skills"
    if skills.is_dir() and not any(
        entry in p.read_text(encoding="utf-8", errors="ignore")
        for p in _text_files(skills)
    ):
        _die(f"entry command {entry!r} not found under skills/")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plugin_dir", help="packaged plugin root (e.g. build/acme-appsec)")
    parser.add_argument("--name", required=True, help="expected plugin name / namespace")
    args = parser.parse_args(argv)

    root = Path(args.plugin_dir).resolve()
    if not root.is_dir():
        _die(f"{root} is not a directory")

    check_plugin_identity(root, args.name)
    check_org_profile_wired(root)
    check_namespace_rewritten(root, args.name)

    print(f"==> Smoke test passed for {args.name} ({root})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
