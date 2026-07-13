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
import re
import sys
from pathlib import Path

from package_internal_plugin import (
    ANY_LEVEL_EXCLUDES,
    ANY_LEVEL_FILE_EXCLUDES,
    PATH_EXCLUDES,
)

UPSTREAM_NAMESPACE = "appsec-advisor"
TEXT_SUFFIXES = {".json", ".md", ".txt", ".yaml", ".yml"}
HYGIENE_TEXT_SUFFIXES = TEXT_SUFFIXES | {".j2", ".py", ".sh", ".toml"}
HOOK_SCRIPT_IDS = {
    "agent_logger.py": "agent-logger",
    "security_steering.py": "security-coach",
}
PERSONAL_PATH_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9])/(?:home|Users)/(?P<user>[A-Za-z0-9._<>$-]+)/"),
    re.compile(r"(?i)\b[A-Z]:\\\\Users\\\\(?P<user>[A-Za-z0-9._<>$-]+)\\\\"),
)
GENERIC_PATH_USERS = {"<user>", "example", "user", "you"}


def _die(message: str) -> None:
    print(f"SMOKE FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def _text_files(root: Path):
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            yield path


def _hook_id(command: str) -> str | None:
    if "/scripts/" not in command and "\\scripts\\" not in command:
        return None
    script_name = command.replace("\\", "/").split("/scripts/", 1)[1].split()[0]
    script_name = Path(script_name).name
    return HOOK_SCRIPT_IDS.get(script_name, Path(script_name).stem.replace("_", "-"))


def _registered_hook_ids(root: Path) -> set[str]:
    hooks_path = root / "hooks" / "hooks.json"
    if not hooks_path.is_file():
        return set()
    data = json.loads(hooks_path.read_text(encoding="utf-8"))
    ids: set[str] = set()
    for entries in (data.get("hooks") or {}).values():
        if not isinstance(entries, list):
            continue
        for outer in entries:
            if not isinstance(outer, dict):
                continue
            for hook in outer.get("hooks") or []:
                if not isinstance(hook, dict):
                    continue
                command = hook.get("command")
                if isinstance(command, str):
                    hook_id = _hook_id(command)
                    if hook_id:
                        ids.add(hook_id)
    return ids


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
    profile = json.loads(config_path.read_text(encoding="utf-8")).get("organization_profile", {})
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
        str(p.relative_to(root)) for p in _text_files(root) if needle in p.read_text(encoding="utf-8", errors="ignore")
    ]
    if leaks:
        shown = "\n  - ".join(leaks[:20])
        _die(f"upstream namespace {needle!r} still present:\n  - {shown}")

    entry = f"{name}:create-threat-model"
    skills = root / "skills"
    if skills.is_dir() and not any(
        entry in p.read_text(encoding="utf-8", errors="ignore") for p in _text_files(skills)
    ):
        _die(f"entry command {entry!r} not found under skills/")


def check_surface_manifest(root: Path) -> None:
    manifest_path = root / ".claude-plugin" / "package-surface.json"
    if not manifest_path.is_file():
        return
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    skills = data.get("skills") or {}
    for skill in skills.get("included") or []:
        if not (root / "skills" / skill / "SKILL.md").is_file():
            _die(f"package surface says skill {skill!r} is included, but it is missing")
    for skill in skills.get("removed") or []:
        if (root / "skills" / skill).exists():
            _die(f"package surface says skill {skill!r} is removed, but it is present")

    hook_ids = _registered_hook_ids(root)
    hooks = data.get("hooks") or {}
    for hook in hooks.get("included") or []:
        if hook not in hook_ids:
            _die(f"package surface says hook {hook!r} is included, but it is not registered")
    for hook in hooks.get("removed") or []:
        if hook in hook_ids:
            _die(f"package surface says hook {hook!r} is removed, but it is registered")
    if "security-coach" in (hooks.get("removed") or []):
        if (root / "hooks" / "steering_keywords.json").exists():
            _die("package surface removed security-coach but steering_keywords.json is still present")

    mcp = data.get("mcp_servers") or {}
    mcp_path = root / ".mcp.json"
    declared: set[str] = set()
    if mcp_path.is_file():
        declared = set(json.loads(mcp_path.read_text(encoding="utf-8")).get("mcpServers") or {})
    for server in mcp.get("included") or []:
        if server not in declared:
            _die(f"package surface says MCP server {server!r} is included, but it is not in .mcp.json")
    for server in mcp.get("removed") or []:
        if server in declared:
            _die(f"package surface says MCP server {server!r} is removed, but it is present in .mcp.json")


def check_artifact_hygiene(root: Path) -> None:
    """Reject local runtime state, dependency trees, and personal paths."""
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if path.is_dir() and path.name in ANY_LEVEL_EXCLUDES:
            _die(f"forbidden generated directory in package: {rel}")
        if path.is_file() and path.name in ANY_LEVEL_FILE_EXCLUDES:
            _die(f"forbidden runtime artifact in package: {rel}")
        if tuple(rel.parts) in PATH_EXCLUDES:
            _die(f"forbidden generated path in package: {rel}")
        if path.is_file() and path.suffix.lower() in HYGIENE_TEXT_SUFFIXES:
            text = path.read_text(encoding="utf-8", errors="ignore")
            if any(
                match.group("user").lower() not in GENERIC_PATH_USERS
                for pattern in PERSONAL_PATH_PATTERNS
                for match in pattern.finditer(text)
            ):
                _die(f"personal absolute path found in package text: {rel}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plugin_dir", help="packaged plugin root (e.g. build/acme-appsec)")
    parser.add_argument("--name", required=True, help="expected plugin name / namespace")
    args = parser.parse_args(argv)

    root = Path(args.plugin_dir).resolve()
    if not root.is_dir():
        _die(f"{root} is not a directory")

    check_artifact_hygiene(root)
    check_plugin_identity(root, args.name)
    check_org_profile_wired(root)
    check_namespace_rewritten(root, args.name)
    check_surface_manifest(root)

    print(f"==> Smoke test passed for {args.name} ({root})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
