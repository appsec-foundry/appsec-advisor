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

ORG_CONFIG_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "engine_version", "advisor_core_version", "profile"],
    "properties": {
        "schema_version": {"const": 1},
        "engine_version": {"type": "string"},
        "advisor_core_version": {"type": "string"},
        "profile": {"type": "object"},
    },
}


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
        "appsec_analyzer/schemas/organization-config.schema.json": compose.canonical(ORG_CONFIG_SCHEMA),
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
                "capabilities": ["score", "organization_config"] if role == "engine" else [],
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


def add_score_skill(lock, inputs, source_prefix="portable/score"):
    """Select a neutral portable skill from an independent reviewed artifact."""
    workflow = b"---\nname: security-score\ndescription: Neutral score workflow\n---\nRead [limits](references/compatibility.md).\n"
    declaration = {
        "schema_version": 1,
        "engine": "appsec-analyzer",
        "interface_versions": [1],
        "required_commands": ["version", "capabilities", "score"],
        "required_capabilities": {"score": {"available": True, "model_calls": False, "scoring_version": 2}},
        "model_prerequisites": [],
    }
    selected = {
        "SKILL.md": workflow,
        "dependencies.json": compose.canonical(declaration),
        "references/compatibility.md": b"Preserve undetermined outcomes and scoring version.\n",
    }
    artifact = "portable-skills.zip"
    data = compose.zip_bytes({source_prefix + "/" + name: content for name, content in selected.items()})
    (inputs / artifact).write_bytes(data)
    component = copy.deepcopy(lock["components"][0])
    component.update(
        id="portable-skills",
        role="skills",
        artifact=artifact,
        sha256=compose.digest(data),
        files=[{"source": source_prefix + "/" + name, "target": "skills/security-score/" + name} for name in selected],
    )
    lock["components"].append(component)
    lock["skill_bindings"] = ["security-score"]
    return workflow


def add_repo_profile_skill(lock, inputs, model_calls=False):
    """Select the neutral portable repository-profile skill from an independent artifact."""
    declaration = {
        "schema_version": 1,
        "engine": "appsec-analyzer",
        "interface_versions": [1],
        "required_commands": ["version", "capabilities", "repo-profile"],
        "required_capabilities": {"repo_profile": {"available": True, "model_calls": model_calls}},
        "model_prerequisites": [],
    }
    selected = {
        "SKILL.md": b"---\nname: repo-profile\ndescription: Neutral profile workflow\n---\n",
        "dependencies.json": compose.canonical(declaration),
        "references/compatibility.md": b"No security judgement.\n",
    }
    data = compose.zip_bytes({"portable/profile/" + name: content for name, content in selected.items()})
    (inputs / "profile-skills.zip").write_bytes(data)
    component = copy.deepcopy(lock["components"][0])
    component.update(
        id="profile-skills",
        role="skills",
        artifact="profile-skills.zip",
        sha256=compose.digest(data),
        files=[{"source": "portable/profile/" + name, "target": "skills/repo-profile/" + name} for name in selected],
    )
    lock["components"].append(component)
    lock["skill_bindings"] = ["repo-profile"]


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


@pytest.mark.parametrize("source_prefix", ["portable/score", "collection/independent-entry"])
def test_score_binding_preserves_workflow_and_delivered_provenance(composition, source_prefix):
    lock, inputs = composition
    workflow = add_score_skill(lock, inputs, source_prefix)
    compose.parse_lock(compose.canonical(lock))
    files = compose.assemble(lock, inputs)
    assert files == compose.assemble(lock, inputs)
    assert files["skills/security-score/WORKFLOW.md"] == workflow
    binding = files["skills/security-score/SKILL.md"].decode()
    assert "[the portable workflow](WORKFLOW.md)" in binding
    assert '--plugin "${CLAUDE_PLUGIN_ROOT}" --skill security-score -- score' in binding
    assert "references/compatibility.md" in workflow.decode()
    manifest = json.loads(files["component-manifest.json"])
    delivered = {entry["path"]: entry for entry in manifest["files"]}
    assert delivered["skills/security-score/WORKFLOW.md"]["component"] == "portable-skills"
    assert delivered["skills/security-score/SKILL.md"]["component"] == "advisor-host"
    for name in ("SKILL.md", "WORKFLOW.md", "dependencies.json", "references/compatibility.md"):
        path = "skills/security-score/" + name
        assert delivered[path]["sha256"] == compose.digest(files[path])


def test_repo_profile_binding_pins_its_own_command(composition):
    lock, inputs = composition
    add_repo_profile_skill(lock, inputs)
    lock["components"][1]["capabilities"].append("repo_profile")
    files = compose.assemble(lock, inputs)
    binding = files["skills/repo-profile/SKILL.md"].decode()
    assert "name: repo-profile" in binding
    assert "--skill repo-profile -- repo-profile /absolute/directory --json" in binding
    assert "security-score" not in binding
    assert files["skills/repo-profile/WORKFLOW.md"].startswith(b"---\nname: repo-profile")


def test_repo_profile_binding_requires_locked_engine_operation(composition):
    lock, inputs = composition
    add_repo_profile_skill(lock, inputs)
    with pytest.raises(compose.CompositionError, match="locked repo_profile"):
        compose.assemble(lock, inputs)


def test_repo_profile_binding_rejects_a_model_calling_declaration(composition):
    lock, inputs = composition
    add_repo_profile_skill(lock, inputs, model_calls=True)
    lock["components"][1]["capabilities"].append("repo_profile")
    with pytest.raises(compose.CompositionError, match="unsupported portable repo-profile"):
        compose.assemble(lock, inputs)


@pytest.mark.parametrize("missing", ["SKILL.md", "dependencies.json", "references/compatibility.md", "bootstrap"])
def test_score_binding_requires_complete_selected_resources(composition, missing):
    lock, inputs = composition
    add_score_skill(lock, inputs)
    for component in lock["components"]:
        component["files"] = [
            selection
            for selection in component["files"]
            if selection["target"]
            != ("scripts/composition_runtime.py" if missing == "bootstrap" else "skills/security-score/" + missing)
        ]
    with pytest.raises(compose.CompositionError, match="requires"):
        compose.assemble(lock, inputs)


def test_score_binding_refuses_generated_workflow_collision(composition):
    lock, inputs = composition
    add_score_skill(lock, inputs)
    lock["components"][-1]["files"].append(
        {"source": "portable/score/SKILL.md", "target": "skills/security-score/WORKFLOW.md"}
    )
    with pytest.raises(compose.CompositionError, match="colliding"):
        compose.assemble(lock, inputs)


def test_score_binding_requires_locked_engine_operation(composition):
    lock, inputs = composition
    add_score_skill(lock, inputs)
    lock["components"][1]["capabilities"] = []
    with pytest.raises(compose.CompositionError, match="locked score"):
        compose.assemble(lock, inputs)


@pytest.mark.parametrize("bindings", [["other-workflow"], ["security-score", "security-score"], "security-score"])
def test_score_binding_lock_rejects_unknown_or_duplicate_bindings(composition, bindings):
    lock, _ = composition
    lock["skill_bindings"] = bindings
    with pytest.raises(compose.CompositionError, match="schema"):
        compose.parse_lock(compose.canonical(lock))


@pytest.mark.parametrize("field,value", [("available", 1), ("model_calls", True), ("scoring_version", "2")])
def test_score_binding_rejects_incompatible_portable_declaration(composition, field, value):
    lock, inputs = composition
    add_score_skill(lock, inputs)
    component = lock["components"][-1]
    artifact = inputs / component["artifact"]
    files = compose.archive_files(artifact.read_bytes())
    path = "portable/score/dependencies.json"
    declaration = json.loads(files[path])
    declaration["required_capabilities"]["score"][field] = value
    files[path] = compose.canonical(declaration)
    data = compose.zip_bytes(files)
    artifact.write_bytes(data)
    component["sha256"] = compose.digest(data)
    with pytest.raises(compose.CompositionError, match="requirements"):
        compose.assemble(lock, inputs)


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


def add_assessment_skill(lock, inputs, source_prefix="appsec_analyzer/skills/appsec-analyzer"):
    """Select the authoritative primary entry from the same wheel as the engine."""
    engine = next(c for c in lock["components"] if c["role"] == "engine")
    members = compose.archive_files((inputs / engine["artifact"]).read_bytes())
    resources = {
        "SKILL.md": b"---\nname: appsec-analyzer\n---\nEngine-owned primary workflow.\n",
        "claude-code.md": b"Follow the existing Claude assessment lifecycle.\n",
        "business-context.md": b"Preserve explicit answers.\n",
    }
    members.update({source_prefix + "/" + name: body for name, body in resources.items()})
    wheel = compose.zip_bytes(members)
    (inputs / engine["artifact"]).write_bytes(wheel)
    engine["sha256"] = compose.digest(wheel)
    engine["capabilities"] = sorted(
        set(engine["capabilities"]) | set(compose.composition_runtime.ASSESSMENT_CAPABILITIES)
    )
    engine["files"] += [
        {"source": source_prefix + "/" + name, "target": "skills/appsec-analyzer/" + name} for name in resources
    ]
    host = next(c for c in lock["components"] if c["role"] == "host")
    host["files"] = [m for m in host["files"] if m["target"] != "skills/appsec-analyzer/SKILL.md"]
    members = compose.archive_files((inputs / host["artifact"]).read_bytes())
    renderer = "scripts/runtime/assessment_console.py"
    members[renderer] = (Path(__file__).parents[1] / renderer).read_bytes()
    data = compose.zip_bytes(members)
    (inputs / host["artifact"]).write_bytes(data)
    host["sha256"] = compose.digest(data)
    host["files"].append({"source": renderer, "target": renderer})
    lock["skill_bindings"] = [*lock.get("skill_bindings", []), "appsec-analyzer"]
    return resources


@pytest.mark.parametrize("source_prefix", ["appsec_analyzer/skills/appsec-analyzer", "engine/resources/primary"])
def test_assessment_binding_preserves_engine_workflow_and_packager_admission(composition, source_prefix):
    import package_internal_plugin as package

    lock, inputs = composition
    resources = add_assessment_skill(lock, inputs, source_prefix)
    compose.parse_lock(compose.canonical(lock))
    files = compose.assemble(lock, inputs)
    assert files["skills/appsec-analyzer/WORKFLOW.md"] == resources["SKILL.md"]
    assert files["skills/appsec-analyzer/claude-code.md"] == resources["claude-code.md"]
    assert b"--skill appsec-analyzer --" in files["skills/appsec-analyzer/SKILL.md"]
    assert b"wait --plugin <plugin> --output <output> --timeout 300" in files["skills/appsec-analyzer/SKILL.md"]
    checked, manifest, protected = package._staging_inputs(files)
    assert checked == lock
    assert "skills/appsec-analyzer/WORKFLOW.md" in protected
    files["skills/appsec-analyzer/WORKFLOW.md"] = b"altered engine instructions"
    with pytest.raises(compose.CompositionError, match="pinned wheel"):
        package._staging_inputs(files)


@pytest.mark.parametrize("defect", ["owner", "capability", "dialog", "renderer", "collision"])
def test_assessment_binding_refuses_incomplete_or_mixed_engine_surface(composition, defect):
    lock, inputs = composition
    add_assessment_skill(lock, inputs)
    engine = lock["components"][1]
    if defect == "owner":
        engine["files"] = [m for m in engine["files"] if not m["target"].endswith("/SKILL.md")]
        lock["components"][0]["files"].append(
            {"source": "skills/appsec-analyzer/SKILL.md", "target": "skills/appsec-analyzer/SKILL.md"}
        )
    elif defect == "capability":
        engine["capabilities"].remove("progress")
    elif defect in {"dialog", "renderer"}:
        target = (
            "skills/appsec-analyzer/business-context.md"
            if defect == "dialog"
            else "scripts/runtime/assessment_console.py"
        )
        for component in lock["components"]:
            component["files"] = [m for m in component["files"] if m["target"] != target]
    else:
        engine["files"].append({"source": engine["files"][0]["source"], "target": "skills/appsec-analyzer/WORKFLOW.md"})
    with pytest.raises(compose.CompositionError):
        compose.assemble(lock, inputs)


def select_from(lock, inputs, component, target, body):
    """Move one output path to another component while keeping its bytes."""
    host = lock["components"][0]
    host["files"] = [m for m in host["files"] if m["target"] != target]
    members = compose.archive_files((inputs / component["artifact"]).read_bytes())
    members["foreign/selected"] = body
    data = compose.zip_bytes(members)
    (inputs / component["artifact"]).write_bytes(data)
    component["sha256"] = compose.digest(data)
    component["files"].append({"source": "foreign/selected", "target": target})


@pytest.mark.parametrize("owner", ["skills", "engine"])
@pytest.mark.parametrize("target", compose.HOST_OWNED)
def test_identity_and_host_executed_code_must_be_host_owned(composition, owner, target):
    lock, inputs = composition
    add_score_skill(lock, inputs)
    body = compose.archive_files((inputs / "host.zip").read_bytes()).get(target, b"def render(event):\n    return []\n")
    component = next(c for c in lock["components"] if c["role"] == owner)
    select_from(lock, inputs, component, target, body)
    with pytest.raises(compose.CompositionError, match="host-owned"):
        compose.assemble(lock, inputs)


def test_packager_refuses_a_progress_renderer_from_another_component(composition, monkeypatch):
    import package_internal_plugin as package

    lock, inputs = composition
    add_assessment_skill(lock, inputs)
    renderer = "scripts/runtime/assessment_console.py"
    body = compose.archive_files((inputs / "host.zip").read_bytes())[renderer]
    select_from(lock, inputs, lock["components"][1], renderer, body)
    # Reproduces a tree assembled before the assembler enforced host ownership.
    monkeypatch.setattr(compose, "HOST_OWNED", ())
    files = compose.assemble(lock, inputs)
    with pytest.raises(compose.CompositionError, match="renderer must be host-owned"):
        package._staging_inputs(files)
