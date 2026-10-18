#!/usr/bin/env python3
"""Assemble an explicitly unqualified staging plugin from reviewed local artifacts."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import stat
import sys
import zipfile
import zlib
from email.parser import BytesParser
from pathlib import Path

import composition_runtime
from jsonschema import Draft202012Validator

SCHEMA = Path(__file__).resolve().parents[1] / "schemas/components-lock.schema.json"
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_FILE = 32 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
MAX_ENTRIES = 20000
RESERVED = {"components.lock.json", "component-manifest.json", "THIRD-PARTY-NOTICES.txt"}


class CompositionError(ValueError):
    """A reviewed input or selected output violates the staging contract."""


def canonical(document: dict) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def portable_path(value: str) -> str:
    """Reject ambiguous ZIP, Unix and Windows paths before any filesystem write."""
    parts = value.split("/")
    devices = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
    if (
        not value.isascii()
        or len(value) > 240
        or any(not p or p in {".", ".."} or p.endswith((" ", ".")) for p in parts)
        or any(ord(c) < 32 or c in '\\:<>"|?*' for c in value)
        or any(p.split(".")[0].casefold() in devices for p in parts)
    ):
        raise CompositionError("archive paths must be portable relative file paths")
    return value


def read_bounded(path: Path, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise CompositionError("input must be a regular file without links")
    with path.open("rb") as handle:
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise CompositionError("input exceeds its byte limit")
    return data


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CompositionError("composition JSON contains duplicate fields")
        result[key] = value
    return result


def parse_lock(data: bytes, schema: dict | None = None) -> dict:
    try:
        lock = json.loads(data, object_pairs_hook=unique_fields)
    except CompositionError:
        raise
    except (ValueError, RecursionError):
        raise CompositionError("composition lock is not valid JSON") from None
    schema = schema if schema is not None else json.loads(SCHEMA.read_bytes())
    if not Draft202012Validator(schema).is_valid(lock):
        raise CompositionError("composition lock does not match schema version 1")
    components = lock["components"]
    for key in ("id", "artifact"):
        if len({c[key].casefold() for c in components}) != len(components):
            raise CompositionError("component IDs and artifact names must be unique")
    for role in ("host", "engine"):
        if sum(c["role"] == role for c in components) != 1:
            raise CompositionError("composition requires exactly one host and one engine")
    for component in components:
        wheel = component["artifact"].endswith(".whl")
        if wheel != (component["role"] in {"engine", "dependency", "build-tool"}):
            raise CompositionError("engine, dependencies and build tools must use wheels; host and skills use ZIP")
        if component["role"] in {"dependency", "build-tool"} and component["files"]:
            raise CompositionError("dependency and build-tool wheels cannot overlay plugin files")
    return lock


def archive_files(data: bytes) -> dict[str, bytes]:
    """Validate the entire archive, including unselected members; never extract it."""
    result = {}
    seen = set()
    expanded = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES:
                raise CompositionError("archive entry limit exceeded")
            for entry in entries:
                name = portable_path(entry.filename.removesuffix("/") if entry.is_dir() else entry.filename)
                mode = entry.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if kind not in {0, stat.S_IFREG, stat.S_IFDIR} or entry.flag_bits & 1:
                    raise CompositionError("archive links, special files and encryption are forbidden")
                folded = name.casefold()
                if folded in seen:
                    raise CompositionError("archive contains duplicate or case-colliding paths")
                seen.add(folded)
                expanded += entry.file_size
                if entry.file_size > MAX_FILE or expanded > MAX_EXPANDED:
                    raise CompositionError("archive expanded byte limit exceeded")
                if entry.is_dir():
                    continue
                with archive.open(entry) as member:
                    content = member.read(MAX_FILE + 1)
                if len(content) > MAX_FILE or len(content) != entry.file_size:
                    raise CompositionError("archive member size mismatch")
                result[name] = content
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, UnicodeError, zlib.error):
        raise CompositionError("artifact is not a valid supported ZIP archive") from None
    files = {n.casefold() for n in result}
    for name in seen:
        if any("/".join(name.split("/")[:i]) in files for i in range(1, len(name.split("/")))):
            raise CompositionError("archive has a file/directory collision")
    return result


def assemble(lock: dict, artifacts: Path) -> dict[str, bytes]:
    outputs = {}
    owners = {}
    total = 0
    input_total = 0
    packages = set()

    def add(name: str, data: bytes, owner: str) -> None:
        nonlocal total
        portable_path(name)
        key = name.casefold()
        if key in owners or any(key.startswith(p + "/") or p.startswith(key + "/") for p in owners):
            raise CompositionError("components select colliding output paths or commands")
        total += len(data)
        if total > MAX_EXPANDED or len(outputs) >= MAX_ENTRIES:
            raise CompositionError("composition output limit exceeded")
        owners[key] = owner
        outputs[name] = data

    for component in lock["components"]:
        data = read_bounded(artifacts / component["artifact"], MAX_ARCHIVE)
        if digest(data) != component["sha256"]:
            raise CompositionError("component artifact digest mismatch")
        members = archive_files(data)
        input_total += sum(len(content) for content in members.values())
        if input_total > MAX_EXPANDED:
            raise CompositionError("combined artifact expanded byte limit exceeded")
        if component["artifact"].endswith(".whl"):
            metadata = [
                content for name, content in members.items() if re.fullmatch(r"[^/]+\.dist-info/METADATA", name)
            ]
            if len(metadata) != 1:
                raise CompositionError("wheel must contain one distribution metadata record")
            record = BytesParser().parsebytes(metadata[0])
            package = re.sub(r"[-_.]+", "-", record.get("Name", "")).lower()
            if not package or record.get("Version") != component["version"] or package in packages:
                raise CompositionError("wheel package version mismatch or duplicate distribution")
            packages.add(package)
            if component["role"] == "engine" and package != "appsec-analyzer":
                raise CompositionError("engine wheel must provide appsec-analyzer")
            add("runtime/wheels/" + component["artifact"], data, component["id"])
        for selection in component["files"]:
            source, target = portable_path(selection["source"]), portable_path(selection["target"])
            if target.casefold() in {p.casefold() for p in RESERVED} or target.casefold().startswith("runtime/wheels/"):
                raise CompositionError("component selects a reserved output")
            if source not in members:
                raise CompositionError("selected file is absent from the pinned artifact")
            add(target, members[source], component["id"])
    manifest_path = ".claude-plugin/plugin.json"
    try:
        plugin = json.loads(outputs[manifest_path], object_pairs_hook=unique_fields)
    except (KeyError, ValueError, RecursionError):
        raise CompositionError("composition must select a valid plugin manifest") from None
    if (
        not isinstance(plugin, dict)
        or plugin.get("name") != lock["plugin"]["name"]
        or plugin.get("version") != lock["plugin"]["version"]
    ):
        raise CompositionError("plugin manifest identity does not match the lock")
    for name, data in outputs.items():
        if re.fullmatch(r"skills/[^/]+/SKILL\.md", name):
            # A command has one canonical directory spelling on every platform.
            if not re.fullmatch(r"skills/[a-z][a-z0-9-]*/SKILL\.md", name):
                raise CompositionError("skill command names must be lowercase portable identifiers")
    if "security-score" in lock.get("skill_bindings", []):
        prefix = "skills/security-score/"
        required = [prefix + name for name in ("SKILL.md", "dependencies.json", "references/compatibility.md")]
        if any(name not in outputs for name in [*required, "scripts/composition_runtime.py"]):
            raise CompositionError(
                "score binding requires the portable workflow, dependencies, references and bootstrap"
            )
        engine = next(c for c in lock["components"] if c["role"] == "engine")
        if "score" not in engine["capabilities"]:
            raise CompositionError("score binding requires the locked score capability")
        try:
            declaration = json.loads(outputs[prefix + "dependencies.json"], object_pairs_hook=unique_fields)
            composition_runtime.score_requirements(declaration)
        except (ValueError, AttributeError, TypeError, RecursionError):
            raise CompositionError("unsupported portable security-score requirements") from None
        workflow = outputs.pop(prefix + "SKILL.md")
        owner = owners.pop((prefix + "SKILL.md").casefold())
        total -= len(workflow)
        add(prefix + "WORKFLOW.md", workflow, owner)
        binding = (
            "---\nname: security-score\n"
            "description: Run the bundled Analyzer's deterministic security score without model calls.\n---\n\n"
            "# Advisor staging invocation\n\n"
            "Read and follow [the portable workflow](WORKFLOW.md), including its dependencies and compatibility notes. "
            "Use the following host binding for every engine command in that workflow.\n\n"
            "Use the existing Python interpreter selected during explicit setup. Replace `python3` below with that "
            "interpreter if needed, including on Windows. Quote its path if it contains spaces.\n\n"
            "```sh\n"
            'python3 "${CLAUDE_PLUGIN_ROOT}/scripts/composition_runtime.py" run '
            '--plugin "${CLAUDE_PLUGIN_ROOT}" --skill security-score -- score /absolute/repository --json\n'
            "```\n\n"
            "For version, capabilities and help, replace only the arguments after `--` with `version`, "
            "`capabilities` or `score --help`. Pass repository paths and options as literal arguments. "
            "Never use a PATH-selected engine, private scripts or automatic setup as fallback. "
            "A missing runtime requires explicit operator setup. Preserve stdout, stderr and the engine exit status.\n"
        )
        host = next(c for c in lock["components"] if c["role"] == "host")
        add(prefix + "SKILL.md", binding.encode(), host["id"])
    if "appsec-analyzer" in lock.get("skill_bindings", []):
        prefix = "skills/appsec-analyzer/"
        engine = next(c for c in lock["components"] if c["role"] == "engine")
        required = [prefix + name for name in ("SKILL.md", "claude-code.md", "business-context.md")]
        if any(
            name not in outputs
            for name in [*required, "scripts/composition_runtime.py", "scripts/runtime/assessment_console.py"]
        ):
            raise CompositionError("assessment binding requires its complete engine entry and bootstrap")
        if any(owners[name.casefold()] != engine["id"] for name in required):
            raise CompositionError("assessment workflow must belong to the exact selected engine")
        if not set(composition_runtime.ASSESSMENT_CAPABILITIES) <= set(engine["capabilities"]):
            raise CompositionError("assessment binding requires the locked public assessment operations")
        workflow = outputs.pop(prefix + "SKILL.md")
        owner = owners.pop((prefix + "SKILL.md").casefold())
        total -= len(workflow)
        add(prefix + "WORKFLOW.md", workflow, owner)
        binding = (
            "---\nname: appsec-analyzer\n"
            "description: Run the bundled Claude security assessment, follow progress, stop it and inspect its results.\n---\n\n"
            "# Advisor staging assessment invocation\n\n"
            "Follow [the engine's Claude Code workflow](claude-code.md); the [engine entry](WORKFLOW.md) "
            "remains available as reference. Use the existing Python interpreter selected during explicit setup "
            "(replace python3 when needed, including on Windows). Every appsec-analyzer command means:\n\n"
            "```sh\n"
            'python3 "${CLAUDE_PLUGIN_ROOT}/scripts/composition_runtime.py" run '
            '--plugin "${CLAUDE_PLUGIN_ROOT}" --skill appsec-analyzer -- <public-command-and-literal-arguments>\n'
            "```\n\n"
            "The public progress follower is the same bootstrap's `follow` action with `--output <output>`; "
            "use `--from-end` when restarting the display. It only displays public engine events and never stops "
            "the owner. After an authorized stop, invoke the same bootstrap with `wait --plugin <plugin> "
            "--output <output> --timeout 300` once; only exit 0 permits restarting. "
            "Host questions, tasks and display belong to Advisor. Never use a PATH engine, private "
            "state, private scripts or automatic setup. Preserve stdout, stderr and exit status. "
            "This unqualified staging binding grants neither setup nor model-spending authorization.\n"
        )
        host = next(c for c in lock["components"] if c["role"] == "host")
        add(prefix + "SKILL.md", binding.encode(), host["id"])
    manifest = {
        "schema_version": 1,
        "qualification": "unqualified-staging",
        "lock_sha256": digest(canonical(lock)),
        "components": lock["components"],
        "files": [
            {"path": name, "sha256": digest(data), "size": len(data), "component": owners[name.casefold()]}
            for name, data in sorted(outputs.items())
        ],
    }
    add("components.lock.json", canonical(lock), "assembly")
    add("component-manifest.json", canonical(manifest), "assembly")
    notices = "Unqualified staging composition. Not a supported replacement release.\n\n"
    notices += "\n".join(
        f"{c['id']} {c['version']}: {c['license']} ({c['source']} @ {c['revision']})" for c in lock["components"]
    )
    add("THIRD-PARTY-NOTICES.txt", (notices + "\n").encode(), "assembly")
    return outputs


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
    return buffer.getvalue()


def build(lock_path: Path, artifacts: Path, destination: Path) -> Path:
    lock = parse_lock(read_bounded(lock_path, 2 * 1024 * 1024))
    files = assemble(lock, artifacts)
    data = zip_bytes(files)
    # A fresh directory prevents accidental overwrite or mixing compositions.
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    name = f"{lock['plugin']['name']}-{lock['plugin']['version']}-staging.zip"
    (destination / name).write_bytes(data)
    (destination / "SHA256SUMS").write_text(f"{digest(data)}  {name}\n", encoding="ascii")
    (destination / "component-manifest.json").write_bytes(files["component-manifest.json"])
    (destination / "THIRD-PARTY-NOTICES.txt").write_bytes(files["THIRD-PARTY-NOTICES.txt"])
    return destination / name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New output directory; parent must exist")
    ns = parser.parse_args(argv)
    try:
        build(ns.lock, ns.artifacts, ns.output)
    except CompositionError as exc:
        print(f"Composition failed: {exc}.", file=sys.stderr)
        return 2
    except OSError:
        print("Composition failed: invalid inputs, integrity, compatibility, or output destination.", file=sys.stderr)
        return 2
    print("Unqualified staging composition built; qualification and release gates remain open.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
