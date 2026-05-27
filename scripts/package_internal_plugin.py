#!/usr/bin/env python3
"""Build a company-branded appsec-advisor plugin artifact.

This script keeps internal packaging logic in the upstream plugin instead of
copying fragile rsync/sed/json snippets into every company's CI repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

UPSTREAM_NAMESPACE = "appsec-advisor"
TEXT_SUFFIXES = {".json", ".md", ".txt", ".yaml", ".yml"}
TOP_LEVEL_EXCLUDES = {
    ".agents",
    ".cache",
    ".codex",
    ".env",
    ".git",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".venv",
    ".venv-tests",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
}
ANY_LEVEL_EXCLUDES = {"__pycache__"}
PATH_EXCLUDES = {
    ("docs", "security"),
    ("scripts", "docs"),
    ("tests", "fixtures", "e2e", "_last-run"),
}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def _die(message: str, code: int = 2) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(code)


def _validate_package_name(name: str) -> None:
    if not NAME_RE.match(name):
        _die(
            "plugin name must start with a lowercase letter or digit and contain "
            "only lowercase letters, digits, '.', '_' and '-'"
        )


def _validate_version(version: str) -> None:
    if not version:
        _die("version must not be empty")
    if "/" in version:
        _die("VERSION must not contain '/' because it is used in artifact paths")


def _require_plugin_root(source: Path) -> None:
    required = [
        ".claude-plugin/plugin.json",
        "config.json",
        "agents",
        "skills",
        "scripts",
        "schemas",
    ]
    missing = [rel for rel in required if not (source / rel).exists()]
    if missing:
        _die(f"{source} is not an appsec-advisor plugin root; missing {missing}")


def _copy_ignore(source_root: Path):
    source_root = source_root.resolve()

    def ignore(current: str, names: list[str]) -> set[str]:
        current_path = Path(current).resolve()
        try:
            rel = current_path.relative_to(source_root)
        except ValueError:
            rel = Path(".")

        ignored: set[str] = set()
        for name in names:
            child = current_path / name
            rel_child = tuple((rel / name).parts)
            if rel == Path(".") and name in TOP_LEVEL_EXCLUDES:
                ignored.add(name)
            elif rel_child in PATH_EXCLUDES:
                ignored.add(name)
            elif child.is_dir() and name in ANY_LEVEL_EXCLUDES:
                ignored.add(name)
        return ignored

    return ignore


def copy_source(source: Path, build: Path) -> None:
    if build.exists():
        shutil.rmtree(build)
    build.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, build, ignore=_copy_ignore(source))


def overlay_org_profile(org_profile: Path, build: Path) -> None:
    if not (org_profile / "org-profile.yaml").is_file():
        _die(f"{org_profile} must contain org-profile.yaml")
    target = build / "org-profile"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(org_profile, target)


def patch_plugin_json(build: Path, name: str, version: str, description: str | None) -> None:
    plugin_path = build / ".claude-plugin" / "plugin.json"
    data = json.loads(plugin_path.read_text(encoding="utf-8"))
    data["name"] = name
    data["version"] = version
    data["description"] = (
        description
        if description is not None
        else f"Internal packaged build of appsec-advisor for {name}."
    )
    plugin_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def patch_config(build: Path) -> None:
    config_path = build / "config.json"
    data = json.loads(config_path.read_text(encoding="utf-8"))
    data["organization_profile"] = {
        "enabled": True,
        "path": "org-profile/org-profile.yaml",
    }
    config_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _text_files(root: Path):
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            yield path


def rewrite_namespace(build: Path, name: str) -> None:
    old = f"{UPSTREAM_NAMESPACE}:"
    new = f"{name}:"
    for path in _text_files(build):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if old in text:
            path.write_text(text.replace(old, new), encoding="utf-8")


def check_namespace_leaks(build: Path) -> None:
    needle = f"{UPSTREAM_NAMESPACE}:"
    leaks: list[str] = []
    for root_name in ("skills", "agents"):
        root = build / root_name
        if not root.exists():
            continue
        for path in _text_files(root):
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if needle in text:
                leaks.append(str(path.relative_to(build)))
    if leaks:
        shown = "\n  - ".join(leaks[:20])
        _die(f"upstream namespace {needle!r} still present in packaged copy:\n  - {shown}", 1)


def run_validation(build: Path) -> None:
    subprocess.run(
        [sys.executable, str(build / "scripts" / "validate_config.py"), str(build)],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            str(build / "scripts" / "validate_org_profile.py"),
            str(build / "org-profile" / "org-profile.yaml"),
        ],
        check=True,
    )


def write_archive(build: Path, name: str, version: str, dist_dir: Path) -> tuple[Path, Path]:
    dist_dir.mkdir(parents=True, exist_ok=True)
    tar_path = dist_dir / f"{name}-{version}.tgz"
    sha_path = dist_dir / f"{name}-{version}.tgz.sha256"

    with tarfile.open(tar_path, "w:gz") as archive:
        archive.add(build, arcname=name)

    digest = hashlib.sha256(tar_path.read_bytes()).hexdigest()
    sha_path.write_text(f"{digest}  {tar_path.name}\n", encoding="utf-8")
    return tar_path, sha_path


def remove_stale_archive(name: str, version: str, dist_dir: Path) -> None:
    for path in (
        dist_dir / f"{name}-{version}.tgz",
        dist_dir / f"{name}-{version}.tgz.sha256",
    ):
        if path.exists():
            path.unlink()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build and validate an internal appsec-advisor plugin package."
    )
    parser.add_argument("--source", default=".", help="upstream appsec-advisor checkout")
    parser.add_argument("--org-profile", required=True, help="org-profile directory to bundle")
    parser.add_argument("--name", required=True, help="internal plugin name / command namespace")
    parser.add_argument("--version", required=True, help="internal package version")
    parser.add_argument("--build-dir", default="build", help="build output directory")
    parser.add_argument("--dist-dir", default="dist", help="tarball output directory")
    parser.add_argument("--description", default=None, help="plugin.json description override")
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="skip packaged config and org-profile validation",
    )
    parser.add_argument(
        "--skip-archive",
        action="store_true",
        help="build the packaged tree but do not create a tarball",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    source = Path(args.source).resolve()
    org_profile = Path(args.org_profile).resolve()
    build = (Path(args.build_dir) / args.name).resolve()
    dist_dir = Path(args.dist_dir).resolve()

    _validate_package_name(args.name)
    _validate_version(args.version)
    _require_plugin_root(source)
    remove_stale_archive(args.name, args.version, dist_dir)

    print(f"==> Packaging {args.name} {args.version}", flush=True)
    copy_source(source, build)
    overlay_org_profile(org_profile, build)
    patch_plugin_json(build, args.name, args.version, args.description)
    patch_config(build)
    rewrite_namespace(build, args.name)
    check_namespace_leaks(build)

    if not args.skip_validation:
        run_validation(build)

    if args.skip_archive:
        print(f"==> Build tree ready at {build}")
    else:
        tar_path, sha_path = write_archive(build, args.name, args.version, dist_dir)
        print(f"==> Build tree ready at {build}")
        print(f"==> Artifact: {tar_path}")
        print(f"==> SHA256:   {sha_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
