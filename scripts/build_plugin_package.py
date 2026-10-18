#!/usr/bin/env python3
"""Build component artifacts from explicit commits and assemble an unqualified staging plugin."""

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
GIT_TIMEOUT = 120
BUILD_TIMEOUT = 900


class PackageError(ValueError):
    """An explicit input cannot produce the selected staging composition."""


def git(source: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(source), *arguments], stdin=subprocess.DEVNULL, capture_output=True, timeout=GIT_TIMEOUT
    )
    if result.returncode or len(result.stdout) > compose.MAX_ARCHIVE:
        raise PackageError(f"git cannot read the selected revision of {source.name}")
    return result.stdout


def commit(source: Path, revision: str) -> str:
    # Options and revision expressions never reach git as a selection.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", revision):
        raise PackageError("revisions must name a commit, tag or branch")
    resolved = git(source, "rev-parse", "--verify", "--quiet", revision + "^{commit}").decode().strip()
    if not re.fullmatch(r"[a-f0-9]{40}", resolved):
        raise PackageError(f"{revision} is not a commit of {source.name}")
    return resolved


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


def build(args: argparse.Namespace) -> Path:
    selection = json.loads(compose.read_bounded(args.selection, 1024 * 1024), object_pairs_hook=compose.unique_fields)
    host_rev = commit(ROOT, args.host_rev)
    engine_rev = commit(args.analyzer_src, args.analyzer_rev)
    skills_rev = commit(args.skills_src, args.skills_rev)
    host_files = committed_files(ROOT, host_rev, selection["host"]["files"])
    skill_files = committed_files(args.skills_src, skills_rev, selection["skills"]["files"])
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

        wheel, engine_version = engine_wheel(args.analyzer_src, engine_rev, artifacts)
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
            name = compose.portable_path(dependency["artifact"])
            data = compose.read_bounded(args.wheelhouse / name, compose.MAX_ARCHIVE)
            if compose.digest(data) != dependency["sha256"]:
                raise PackageError(f"{name} in the wheelhouse does not match its pinned SHA-256")
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analyzer-src", type=Path, required=True, help="appsec-analyzer Git checkout")
    parser.add_argument("--analyzer-rev", required=True, help="Analyzer commit, tag or branch")
    parser.add_argument("--skills-src", type=Path, required=True, help="appsec-skills Git checkout")
    parser.add_argument("--skills-rev", required=True, help="Skills commit, tag or branch")
    parser.add_argument("--wheelhouse", type=Path, required=True, help="Directory holding the pinned dependency wheels")
    parser.add_argument("--host-rev", default="HEAD", help="Advisor commit, tag or branch (default: HEAD)")
    parser.add_argument("--selection", type=Path, default=SELECTION, help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, help="New directory (default: build/appsec-advisor-<version>-staging)")
    ns = parser.parse_args(argv)
    try:
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
