#!/usr/bin/env python3
"""Build component artifacts from pinned commits and assemble an unqualified staging plugin.

`package` builds offline from the commits and wheels pinned in data/plugin-package.json,
fetching only a pinned commit that is not cached yet. `wheels` downloads the pinned
dependency wheels with hash checking. `update` moves the commit pins to the current
remote branch heads for review.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from email.parser import BytesParser
from pathlib import Path

import compose_plugin as compose
from composition_runtime import clean_environment

ROOT = Path(__file__).resolve().parents[1]
SELECTION = ROOT / "data/plugin-package.json"
SOURCES = ROOT / "build/appsec-advisor-sources"
WHEELHOUSE = ROOT / "build/appsec-advisor-wheels"
GIT_TIMEOUT = 120
FETCH_TIMEOUT = 600
BUILD_TIMEOUT = 900
REMOTE = re.compile(r"https://[A-Za-z0-9.-]+/[A-Za-z0-9._/-]+")
PYPI = re.compile(r"https://pypi\.org/project/([A-Za-z0-9._-]+)/([A-Za-z0-9.+_-]+)")
FULL_COMMIT = re.compile(r"[a-f0-9]{40}")


class PackageError(ValueError):
    """An explicit input cannot produce the selected staging composition."""


def git(source: Path, *arguments: str, timeout: int = GIT_TIMEOUT) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(source), *arguments],
        env={**clean_environment(), "GIT_TERMINAL_PROMPT": "0"},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
    )
    if result.returncode or len(result.stdout) > compose.MAX_ARCHIVE:
        raise PackageError(f"git {arguments[0]} failed for {source.name}")
    return result.stdout


def commit(source: Path, revision: str) -> str:
    # Options and revision expressions never reach git as a selection.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", revision):
        raise PackageError("revisions must name a commit, tag or branch")
    resolved = git(source, "rev-parse", "--verify", "--quiet", revision + "^{commit}").decode().strip()
    if not FULL_COMMIT.fullmatch(resolved):
        raise PackageError(f"{revision} is not a commit of {source.name}")
    return resolved


def remote(selection: dict) -> str:
    if not REMOTE.fullmatch(selection["source"]) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", selection["id"]):
        raise PackageError(f"{selection['id']} needs an HTTPS source repository")
    return selection["source"]


def pinned_source(selection: dict, revision: str, cache: Path) -> Path:
    """Fetch exactly one pinned commit into a private bare cache; a cached commit needs no network."""
    url = remote(selection)
    if not FULL_COMMIT.fullmatch(revision):
        raise PackageError(f"{selection['id']} needs a full pinned commit without a local checkout")
    repository = cache / f"{selection['id']}.git"
    if not repository.is_dir():
        repository.mkdir(mode=0o700, parents=True)
        git(repository, "init", "--quiet", "--bare")
    try:
        commit(repository, revision)
    except PackageError:
        git(repository, "fetch", "--quiet", "--depth=1", "--no-tags", url, revision, timeout=FETCH_TIMEOUT)
    return repository


def committed_files(source: Path, revision: str, paths: list[str]) -> dict[str, bytes]:
    """Read regular committed files only; working-tree changes never enter an artifact."""
    for path in paths:
        compose.portable_path(path)
        listing = git(source, "ls-tree", "-z", revision, "--", path).rstrip(b"\0").split(b"\0")
        mode, kind = listing[0].split(b" ")[:2] if len(listing) == 1 and listing[0] else (b"", b"")
        if kind != b"blob" or mode not in {b"100644", b"100755"}:
            raise PackageError(f"{path} is not a regular committed file of {source.name}")
    return {path: git(source, "cat-file", "blob", f"{revision}:{path}") for path in paths}


def engine_wheel(source: Path, revision: str, artifacts: Path) -> tuple[str, str]:
    """Build the engine wheel from a clean export of one commit without index access."""
    epoch = git(source, "show", "-s", "--format=%ct", revision).decode().strip()
    with tempfile.TemporaryDirectory() as work:
        tree, dist = Path(work, "source"), Path(work, "dist")
        with tarfile.open(fileobj=io.BytesIO(git(source, "archive", "--format=tar", revision))) as archive:
            archive.extractall(tree, filter="data")
        env = {**clean_environment(), "SOURCE_DATE_EPOCH": epoch}
        # The work directory is the cwd, so the exported tree cannot shadow the build frontend.
        command = [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(dist), str(tree)]
        result = subprocess.run(
            command, cwd=work, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=BUILD_TIMEOUT
        )
        if result.returncode:
            tail = b"\n".join((result.stdout + result.stderr).splitlines()[-20:]).decode(errors="replace")
            raise PackageError("engine wheel build failed:\n" + tail)
        wheels = list(dist.glob("*.whl"))
        if len(wheels) != 1:
            raise PackageError("engine build must produce exactly one wheel")
        data = compose.read_bounded(wheels[0], compose.MAX_ARCHIVE)
    metadata = [c for n, c in compose.archive_files(data).items() if re.fullmatch(r"[^/]+\.dist-info/METADATA", n)]
    version = BytesParser().parsebytes(metadata[0]).get("Version", "") if len(metadata) == 1 else ""
    (artifacts / wheels[0].name).write_bytes(data)
    return wheels[0].name, version


def component(selection: dict, role: str, revision: str, version: str, artifact: str, data: bytes, files) -> dict:
    return {
        "id": selection["id"],
        "role": role,
        "source": selection["source"],
        "revision": revision,
        "version": version,
        "artifact": artifact,
        "sha256": compose.digest(data),
        "license": selection["license"],
        "interface_version": 1,
        "capabilities": selection.get("capabilities", []),
        "qualification": "unqualified-staging",
        "files": files,
    }


def load(path: Path) -> dict:
    return json.loads(compose.read_bounded(path, 1024 * 1024), object_pairs_hook=compose.unique_fields)


def pinned_wheel(wheelhouse: Path, dependency: dict) -> bytes:
    name = compose.portable_path(dependency["artifact"])
    data = compose.read_bounded(wheelhouse / name, compose.MAX_ARCHIVE)
    if compose.digest(data) != dependency["sha256"]:
        raise PackageError(f"{name} in the wheelhouse does not match its pinned SHA-256")
    return data


def download_wheels(selection: dict, wheelhouse: Path) -> None:
    """Download only the pinned wheels; pip refuses any file whose hash differs."""
    runtime = selection["runtime"]
    if len(runtime["python"]) != 1 or runtime["platforms"] != ["linux-x86_64"]:
        raise PackageError("wheel download supports one selected Python version on linux-x86_64")
    lines = []
    for dependency in selection["dependencies"]:
        match = PYPI.fullmatch(dependency["source"])
        if not match or match[2] != dependency["version"] or not re.fullmatch(r"[a-f0-9]{64}", dependency["sha256"]):
            raise PackageError(f"{dependency['id']} needs a PyPI source matching its pinned version and SHA-256")
        lines.append(f"{match[1]}=={dependency['version']} --hash=sha256:{dependency['sha256']}")
    wheelhouse.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as work:
        requirements = Path(work, "requirements.txt")
        requirements.write_text("\n".join(lines) + "\n", encoding="ascii")
        command = [sys.executable, "-m", "pip", "download", "--quiet", "--no-deps", "--only-binary=:all:"]
        command += ["--require-hashes", "--implementation", "cp", "--python-version", runtime["python"][0]]
        command += ["--platform", "manylinux2014_x86_64", "--dest", str(wheelhouse), "-r", str(requirements)]
        result = subprocess.run(
            command, cwd=work, env=clean_environment(), stdin=subprocess.DEVNULL, capture_output=True, timeout=600
        )
    if result.returncode:
        tail = b"\n".join((result.stdout + result.stderr).splitlines()[-20:]).decode(errors="replace")
        raise PackageError("wheel download failed:\n" + tail)
    for dependency in selection["dependencies"]:
        pinned_wheel(wheelhouse, dependency)


def update_pins(path: Path) -> list[str]:
    """Move commit pins to the current remote branch heads; the selection diff is the review."""
    text = path.read_text(encoding="utf-8")
    selection = json.loads(text, object_pairs_hook=compose.unique_fields)
    changes = []
    for key in ("engine", "skills"):
        item = selection[key]
        url, old, branch = remote(item), item["revision"], item["branch"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}", branch):
            raise PackageError(f"{item['id']} needs a plain branch name")
        heads = git(ROOT, "ls-remote", url, f"refs/heads/{branch}", timeout=FETCH_TIMEOUT).split()
        new = heads[0].decode() if len(heads) == 2 else ""
        if not FULL_COMMIT.fullmatch(new):
            raise PackageError(f"{url} has no branch {branch}")
        if new != old:
            entry = f'"revision": "{old}"'
            if text.count(entry) != 1:
                raise PackageError(f"{item['id']} revision pin is ambiguous in the selection")
            text = text.replace(entry, f'"revision": "{new}"')
            changes.append(f"{item['id']}: {old[:12]} -> {new[:12]}  {url}/compare/{old}...{new}")
    if changes:
        path.write_text(text, encoding="utf-8")
    return changes


def build(args: argparse.Namespace) -> Path:
    selection = load(args.selection)
    host_rev = commit(ROOT, args.host_rev)
    sources = {}
    for key, source, revision in (
        ("engine", args.analyzer_src, args.analyzer_rev),
        ("skills", args.skills_src, args.skills_rev),
    ):
        revision = revision or selection[key]["revision"]
        source = source or pinned_source(selection[key], revision, args.sources)
        sources[key] = (source, commit(source, revision))
    (engine_src, engine_rev), (skills_src, skills_rev) = sources["engine"], sources["skills"]
    host_files = committed_files(ROOT, host_rev, selection["host"]["files"])
    skill_files = committed_files(skills_src, skills_rev, selection["skills"]["files"])
    plugin = json.loads(host_files[".claude-plugin/plugin.json"], object_pairs_hook=compose.unique_fields)
    output = args.output or ROOT / f"build/{plugin['name']}-{plugin['version']}-staging"
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        artifacts = output / "artifacts"
        artifacts.mkdir()
        identity = [{"source": path, "target": path} for path in selection["host"]["files"]]
        host_zip = compose.zip_bytes(host_files)
        (artifacts / "host.zip").write_bytes(host_zip)
        components = [component(selection["host"], "host", host_rev, plugin["version"], "host.zip", host_zip, identity)]

        wheel, engine_version = engine_wheel(engine_src, engine_rev, artifacts)
        mapping = [{"source": s, "target": t} for s, t in selection["engine"]["files"].items()]
        wheel_data = (artifacts / wheel).read_bytes()
        components.append(
            component(selection["engine"], "engine", engine_rev, engine_version, wheel, wheel_data, mapping)
        )

        skills_zip = compose.zip_bytes(skill_files)
        (artifacts / "skills.zip").write_bytes(skills_zip)
        identity = [{"source": path, "target": path} for path in selection["skills"]["files"]]
        skills_version = "git-" + skills_rev[:12]
        components.append(
            component(selection["skills"], "skills", skills_rev, skills_version, "skills.zip", skills_zip, identity)
        )

        for dependency in selection["dependencies"]:
            name = dependency["artifact"]
            data = pinned_wheel(args.wheelhouse, dependency)
            (artifacts / name).write_bytes(data)
            revision = "sha256:" + dependency["sha256"]
            components.append(component(dependency, "dependency", revision, dependency["version"], name, data, []))

        lock = {
            "schema_version": 1,
            "plugin": {"name": plugin["name"], "version": plugin["version"]},
            "interface_version": 1,
            "runtime": selection["runtime"],
            "skill_bindings": selection["skill_bindings"],
            "components": components,
        }
        lock_path = output / "components.lock.json"
        lock_path.write_bytes(compose.canonical(compose.parse_lock(compose.canonical(lock))))
        compose.build(lock_path, artifacts, output / "assembly")
    except BaseException:
        # Only this invocation created the directory; never leave a partial package behind.
        shutil.rmtree(output, ignore_errors=True)
        raise
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--selection", type=Path, default=SELECTION, help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)
    package = commands.add_parser("package", help="Build the staging plugin from the pinned commits")
    package.add_argument(
        "--analyzer-src", type=Path, help="Local appsec-analyzer checkout instead of the pinned remote"
    )
    package.add_argument("--analyzer-rev", help="Analyzer revision (default: the pinned commit)")
    package.add_argument("--skills-src", type=Path, help="Local appsec-skills checkout instead of the pinned remote")
    package.add_argument("--skills-rev", help="Skills revision (default: the pinned commit)")
    package.add_argument("--wheelhouse", type=Path, default=WHEELHOUSE, help="Pinned dependency wheels")
    package.add_argument("--host-rev", default="HEAD", help="Advisor commit, tag or branch (default: HEAD)")
    package.add_argument("--sources", type=Path, default=SOURCES, help=argparse.SUPPRESS)
    package.add_argument("--output", type=Path, help="New directory (default: build/appsec-advisor-<version>-staging)")
    wheels = commands.add_parser("wheels", help="Download the pinned dependency wheels with hash checking")
    wheels.add_argument("--wheelhouse", type=Path, default=WHEELHOUSE)
    commands.add_parser("update", help="Pin the Analyzer and skills commits to their current remote branch")
    ns = parser.parse_args(argv)
    try:
        if ns.command == "update":
            changes = update_pins(ns.selection)
            print("\n".join(changes) if changes else "Pins already match the remote branches.")
            if changes:
                print(f"Review and commit {ns.selection} before building.")
            return 0
        if ns.command == "wheels":
            download_wheels(load(ns.selection), ns.wheelhouse)
            print(f"Pinned dependency wheels verified in {ns.wheelhouse}.")
            return 0
        output = build(ns)
    except (PackageError, compose.CompositionError) as exc:
        print(f"Plugin package failed: {exc}.", file=sys.stderr)
        return 2
    except FileExistsError:
        print("Plugin package failed: the output directory already exists; choose a new OUT.", file=sys.stderr)
        return 2
    except (OSError, KeyError, TypeError, ValueError, subprocess.TimeoutExpired, tarfile.TarError):
        print("Plugin package failed: invalid selection, checkout, wheelhouse or output location.", file=sys.stderr)
        return 2
    lock = compose.digest((output / "components.lock.json").read_bytes())
    print(f"Unqualified staging plugin built in {output}/assembly.")
    print(f"Review {output}/components.lock.json (SHA-256 {lock}) before passing the package on.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
