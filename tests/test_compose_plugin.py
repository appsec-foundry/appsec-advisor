"""Offline composition: immutable inputs, safe archive admission, explicit selection."""

from __future__ import annotations

import copy
import io
import json
import stat
import zipfile
from pathlib import Path

import compose_plugin as compose
import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource


def make_composition(tmp_path):
    inputs = tmp_path / "reviewed artifacts"
    inputs.mkdir()
    host = {
        ".claude-plugin/plugin.json": compose.canonical({"name": "appsec-advisor", "version": "1.0.0"}),
        "skills/appsec-analyzer/SKILL.md": b"Use the public pinned engine.\n",
        "scripts/composition_runtime.py": (Path(__file__).parents[1] / "scripts/composition_runtime.py").read_bytes(),
        "not-selected.txt": b"must not ship",
    }
    engine = {
        "appsec_analyzer/__main__.py": b"print('fixture only')\n",
        "appsec_analyzer-1.0.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: appsec-analyzer\nVersion: 1.0.0\n",
    }
    components = []
    for name, role, files, artifact in [
        ("advisor-host", "host", host, "host.zip"),
        ("analyzer", "engine", engine, "appsec_analyzer-1.0.0-py3-none-any.whl"),
    ]:
        data = compose.zip_bytes(files)
        (inputs / artifact).write_bytes(data)
        components.append(
            {
                "id": name,
                "role": role,
                "source": f"https://example.com/{name}",
                "revision": "a" * 40,
                "version": "1.0.0",
                "artifact": artifact,
                "sha256": compose.digest(data),
                "license": "Apache-2.0",
                "interface_version": 1,
                "capabilities": ["score"] if role == "engine" else [],
                "qualification": "unqualified-staging",
                "files": [{"source": path, "target": path} for path in host if path != "not-selected.txt"]
                if role == "host"
                else [],
            }
        )
    lock = {
        "schema_version": 1,
        "plugin": {"name": "appsec-advisor", "version": "1.0.0"},
        "interface_version": 1,
        "runtime": {"python": ["3.11"], "platforms": ["linux-x86_64"]},
        "components": components,
    }
    return lock, inputs


@pytest.fixture
def composition(tmp_path):
    return make_composition(tmp_path)


def test_reproducible_archive_selection_notices_and_manifest(composition, tmp_path):
    lock, inputs = composition
    path = tmp_path / "components.lock.json"
    path.write_bytes(compose.canonical(lock))
    first = compose.build(path, inputs, tmp_path / "build one")
    second = compose.build(path, inputs, tmp_path / "build two")
    assert first.read_bytes() == second.read_bytes()
    files = compose.archive_files(first.read_bytes())
    assert "not-selected.txt" not in files
    assert files["scripts/composition_runtime.py"].startswith(b"#!/usr/bin/env python3")
    manifest = json.loads(files["component-manifest.json"])
    assert manifest["lock_sha256"] == compose.digest(compose.canonical(lock))
    for entry in manifest["files"]:
        assert compose.digest(files[entry["path"]]) == entry["sha256"]
    assert b"Apache-2.0" in files["THIRD-PARTY-NOTICES.txt"]
    root = Path(__file__).parents[1] / "schemas"
    schema = json.loads((root / "component-manifest.schema.json").read_bytes())
    resource = Resource.from_contents(json.loads(compose.SCHEMA.read_bytes()))
    registry = Registry().with_resource("components-lock.schema.json", resource)
    Draft202012Validator(schema, registry=registry).validate(manifest)
    assert (first.parent / "SHA256SUMS").read_text().startswith(compose.digest(first.read_bytes()))
    with zipfile.ZipFile(first) as archive:
        assert all(
            i.date_time == (1980, 1, 1, 0, 0, 0) and i.external_attr >> 16 == stat.S_IFREG | 0o644
            for i in archive.infolist()
        )


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/absolute",
        "C:/drive",
        "a\\b",
        "a/../b",
        "a//b",
        "CON.txt",
        "folder./a",
        "x:stream",
        "a/\x00b",
        "café.txt",
    ],
)
def test_rejects_portable_path_escapes_and_windows_aliases(name):
    with pytest.raises(compose.CompositionError):
        compose.portable_path(name)


@pytest.mark.parametrize("member", ["../outside.txt", "nested/../../other.txt"])
def test_unselected_traversal_is_rejected(composition, member):
    lock, inputs = composition
    host = lock["components"][0]
    path = inputs / host["artifact"]
    members = compose.archive_files(path.read_bytes())
    members[member] = b"unselected"
    path.write_bytes(compose.zip_bytes(members))
    host["sha256"] = compose.digest(path.read_bytes())
    with pytest.raises(compose.CompositionError, match="relative"):
        compose.assemble(lock, inputs)


@pytest.mark.parametrize("mode", [stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o600])
def test_archive_links_and_special_files_rejected(mode):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("innocent.txt")
        info.create_system = 3
        info.external_attr = mode << 16
        archive.writestr(info, b"../../outside")
    with pytest.raises(compose.CompositionError, match="links"):
        compose.archive_files(buffer.getvalue())


@pytest.mark.parametrize("files", [{"A.txt": b"a", "a.txt": b"b"}, {"a": b"a", "a/b": b"b"}])
def test_archive_case_and_file_directory_collisions(files):
    with pytest.raises(compose.CompositionError, match="colli"):
        compose.archive_files(compose.zip_bytes(files))


def test_archive_resource_limits(monkeypatch):
    data = compose.zip_bytes({"large.txt": b"a" * 128})
    monkeypatch.setattr(compose, "MAX_FILE", 64)
    with pytest.raises(compose.CompositionError, match="byte limit"):
        compose.archive_files(data)
    monkeypatch.setattr(compose, "MAX_ENTRIES", 0)
    with pytest.raises(compose.CompositionError, match="entry limit"):
        compose.archive_files(data)


@pytest.mark.parametrize("name", ["payload.txt", "different/nested.bin"])
def test_corrupt_deflate_is_controlled_and_valid_archive_still_works(name):
    buffer = io.BytesIO()
    content = b"neutral archive content" * 100
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, content)
    original = buffer.getvalue()
    assert compose.archive_files(original) == {name: content}
    damaged = bytearray(original)
    damaged[30 + len(name)] = 255  # Invalid DEFLATE block type after the local filename.
    with pytest.raises(compose.CompositionError, match="valid supported ZIP"):
        compose.archive_files(bytes(damaged))


def test_tampered_artifact_does_not_create_output(composition, tmp_path):
    lock, inputs = composition
    (inputs / lock["components"][0]["artifact"]).write_bytes(b"tampered")
    path = tmp_path / "lock.json"
    path.write_bytes(compose.canonical(lock))
    with pytest.raises(compose.CompositionError, match="digest"):
        compose.build(path, inputs, tmp_path / "output")
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("mutation", ["interface", "duplicate", "qualified", "missing-engine", "dependency-overlay"])
def test_incompatible_and_ambiguous_locks_fail_closed(composition, mutation):
    lock, _ = composition
    if mutation == "interface":
        lock["components"][1]["interface_version"] = 2
    if mutation == "duplicate":
        lock["components"][1]["id"] = lock["components"][0]["id"]
    if mutation == "qualified":
        lock["components"][1]["qualification"] = "qualified"
    if mutation == "missing-engine":
        lock["components"][1]["role"] = "dependency"
    if mutation == "dependency-overlay":
        dependency = copy.deepcopy(lock["components"][1])
        dependency.update(
            id="dependency", role="dependency", artifact="other.whl", files=[{"source": "a", "target": "b"}]
        )
        lock["components"].append(dependency)
    with pytest.raises(compose.CompositionError):
        compose.parse_lock(compose.canonical(lock))


@pytest.mark.parametrize(
    "target", ["component-manifest.json", "runtime/wheels/replace.whl", "skills/appsec-analyzer/SKILL.md"]
)
def test_reserved_files_and_command_collision_rejected(composition, target):
    lock, inputs = composition
    lock["components"][1]["files"] = [{"source": "appsec_analyzer/__main__.py", "target": target}]
    with pytest.raises(compose.CompositionError, match="reserved|colliding"):
        compose.assemble(lock, inputs)


def test_missing_selection_and_wrong_plugin_identity_rejected(composition):
    lock, inputs = composition
    lock["components"][0]["files"].append({"source": "absent", "target": "absent"})
    with pytest.raises(compose.CompositionError, match="absent"):
        compose.assemble(lock, inputs)
    lock["components"][0]["files"].pop()
    lock["plugin"]["version"] = "2.0.0"
    with pytest.raises(compose.CompositionError, match="identity"):
        compose.assemble(lock, inputs)


def test_cli_error_has_no_traceback_or_input_content(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"secret": "do-not-print"}')
    assert compose.main(["--lock", str(bad), "--artifacts", str(tmp_path), "--output", str(tmp_path / "out")]) == 2
    error = capsys.readouterr().err
    assert "Traceback" not in error and "do-not-print" not in error and str(tmp_path) not in error


def test_content_addressed_dependency_and_committed_code_revisions(composition):
    lock, _ = composition
    dependency = copy.deepcopy(lock["components"][1])
    dependency.update(id="a-dependency", role="dependency", artifact="dependency.whl", revision="sha256:" + "b" * 64)
    lock["components"].append(dependency)
    assert compose.parse_lock(compose.canonical(lock))["components"][-1]["revision"] == dependency["revision"]
    lock["components"][0]["revision"] = dependency["revision"]
    with pytest.raises(compose.CompositionError):
        compose.parse_lock(compose.canonical(lock))


@pytest.mark.parametrize("value", [[], None])
def test_non_object_plugin_manifest_rejected(composition, value):
    lock, inputs = composition
    host = lock["components"][0]
    path = inputs / host["artifact"]
    files = compose.archive_files(path.read_bytes())
    files[".claude-plugin/plugin.json"] = json.dumps(value).encode()
    data = compose.zip_bytes(files)
    path.write_bytes(data)
    host["sha256"] = compose.digest(data)
    with pytest.raises(compose.CompositionError, match="identity"):
        compose.assemble(lock, inputs)


def test_duplicate_lock_fields_are_ambiguous_not_last_value_wins():
    with pytest.raises(compose.CompositionError, match="duplicate"):
        compose.parse_lock(b'{"schema_version": 1, "schema_version": 2}')


def test_duplicate_plugin_identity_fields_are_rejected(composition):
    lock, inputs = composition
    host = lock["components"][0]
    path = inputs / host["artifact"]
    files = compose.archive_files(path.read_bytes())
    files[".claude-plugin/plugin.json"] = b'{"name":"other","name":"appsec-advisor","version":"1.0.0"}'
    data = compose.zip_bytes(files)
    path.write_bytes(data)
    host["sha256"] = compose.digest(data)
    with pytest.raises(compose.CompositionError, match="valid plugin manifest"):
        compose.assemble(lock, inputs)


def test_deep_plugin_manifest_fails_without_traceback(composition, tmp_path, capsys):
    lock, inputs = composition
    host = lock["components"][0]
    path = inputs / host["artifact"]
    files = compose.archive_files(path.read_bytes())
    files[".claude-plugin/plugin.json"] = b"[" * 2000 + b"0" + b"]" * 2000
    data = compose.zip_bytes(files)
    path.write_bytes(data)
    host["sha256"] = compose.digest(data)
    lock_path = tmp_path / "lock.json"
    lock_path.write_bytes(compose.canonical(lock))
    assert compose.main(["--lock", str(lock_path), "--artifacts", str(inputs), "--output", str(tmp_path / "out")]) == 2
    assert "Traceback" not in capsys.readouterr().err
    assert not (tmp_path / "out").exists()
