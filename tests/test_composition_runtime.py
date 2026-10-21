"""Installed staging runtime checks with a neutral offline wheel, never a model."""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import compose_plugin as compose
import composition_runtime as runtime
import pytest

from tests.test_compose_plugin import ORG_CONFIG_SCHEMA, add_score_skill, make_composition

ENGINE = """import json, os, subprocess, sys, time
from pathlib import Path
if sys.argv[1:] == ["version"]:
    print(json.dumps({"engine_version": "1.0.0", "interface_version": 1}))
elif sys.argv[1:] == ["capabilities"]:
    print(json.dumps({"interface_version": 1, "score": {"available": True, "model_calls": False, "scoring_version": 2}, "organization_config": {"available": True, "schema_version": 1, "commands": ["score"], "profile_fields": ["policy.disable_opus", "policy.url_allowlist", "presets.*.base_mode"]}}))
elif sys.argv[1:3] == ["organization-config", "run"]:
    args = sys.argv[sys.argv.index("--") + 1:]
    print(json.dumps({"python": sys.executable, "args": args, "pythonpath": os.environ.get("PYTHONPATH")}))
    sys.exit({"undetermined-source": 2, "incomplete-source": 1, "cancelled-source": 130}.get(args[1], 0))
elif sys.argv[1] == "stop":
    pass
elif sys.argv[1] == "assess":
    out = Path(sys.argv[sys.argv.index("--output") + 1])
    child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(60)"])
    (out / "child.pid").write_text(str(child.pid))
    time.sleep(60)
else:
    print(json.dumps({"python": sys.executable, "args": sys.argv[1:], "pythonpath": os.environ.get("PYTHONPATH")}))
    sys.exit({"undetermined-source": 2, "incomplete-source": 1, "cancelled-source": 130}.get(sys.argv[2], 0))
"""


@pytest.fixture
def installed_plugin(tmp_path):
    lock, inputs = make_composition(tmp_path)
    add_score_skill(lock, inputs)
    engine = lock["components"][1]
    metadata = "appsec_analyzer-1.0.0.dist-info"
    wheel = compose.zip_bytes(
        {
            "appsec_analyzer/__init__.py": b"",
            "appsec_analyzer/cli.py": ENGINE.encode(),
            "appsec_analyzer/schemas/organization-config.schema.json": compose.canonical(ORG_CONFIG_SCHEMA),
            f"{metadata}/METADATA": b"Metadata-Version: 2.1\nName: appsec-analyzer\nVersion: 1.0.0\n",
            f"{metadata}/WHEEL": b"Wheel-Version: 1.0\nGenerator: offline-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            f"{metadata}/RECORD": b"",
        }
    )
    (inputs / engine["artifact"]).write_bytes(wheel)
    engine["sha256"] = compose.digest(wheel)
    lock["runtime"] = {
        "python": [f"{sys.version_info.major}.{sys.version_info.minor}"],
        "platforms": [runtime.target_platform()],
    }
    plugin = tmp_path / "plugin location with spaces"
    plugin.mkdir()
    for name, data in compose.assemble(lock, inputs).items():
        path = plugin / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return plugin, tmp_path / "user runtime with spaces", lock


def test_offline_setup_preflight_and_pinned_launch(installed_plugin, monkeypatch, capfd):
    plugin, home, _ = installed_plugin
    shadow = home.parent / "shadow-bin"
    shadow.mkdir()
    fake = shadow / "appsec-analyzer"
    fake.write_text("#!/bin/sh\nexit 91\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(shadow) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("PYTHONPATH", str(shadow))
    monkeypatch.setenv("PIP_INDEX_URL", "https://invalid.example/no-network")
    # The installed plugin is read-only; setup writes exclusively to user storage.
    for path in plugin.rglob("*"):
        if path.is_file():
            path.chmod(0o444)
    python = runtime.setup(plugin, home)
    assert home in python.parents
    assert runtime.preflight(plugin, home)[0] == python
    assert runtime.setup(plugin, home) == python
    assert runtime.launch(plugin, home, ["score", "path with spaces;$(no-shell)"], 30, "security-score") == 0
    response = json.loads(capfd.readouterr().out)
    assert response["args"] == ["score", "path with spaces;$(no-shell)"]
    assert response["python"] == str(python)
    assert response["pythonpath"] is None
    assert (
        runtime.main(
            [
                "run",
                "--plugin",
                str(plugin),
                "--runtime-home",
                str(home),
                "--skill",
                "security-score",
                "--",
                "score",
                "another path",
            ]
        )
        == 0
    )
    assert json.loads(capfd.readouterr().out)["args"] == ["score", "another path"]
    assert runtime.launch(plugin, home, ["score", "unbound source"], 30) == 0
    assert json.loads(capfd.readouterr().out)["args"] == ["score", "unbound source"]
    for arguments, status in [
        (["score", "selected source", "--json"], 0),
        (["score", "selected source", "--yaml"], 0),
        (["score", "undetermined-source"], 2),
        (["score", "incomplete-source"], 1),
        (["score", "cancelled-source"], 130),
    ]:
        assert runtime.launch(plugin, home, arguments, 30, "security-score") == status
        assert json.loads(capfd.readouterr().out)["args"] == arguments
    assert not list(home.glob("*.setup-lock"))


@pytest.mark.parametrize("name", ["score", "scan_sources"])
@pytest.mark.parametrize("available", [None, False, 0, 1, "true"])
def test_engine_capability_requires_explicit_boolean_availability(monkeypatch, name, available):
    record = {} if available is None else {"available": available}
    payload = {"interface_version": 1, name: record}
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout=json.dumps(payload).encode())
    )
    with pytest.raises(runtime.RuntimeError, match="capabilities"):
        runtime.engine_capabilities(Path(sys.executable), [name])


@pytest.mark.parametrize(
    "record",
    [
        {"available": True},
        {"available": True, "model_calls": True, "scoring_version": 2},
        {"available": True, "model_calls": False, "scoring_version": 1},
        {"available": True, "model_calls": False, "scoring_version": "2"},
    ],
)
def test_score_binding_rejects_incompatible_engine_before_execution(installed_plugin, monkeypatch, record):
    plugin, home, lock = installed_plugin
    monkeypatch.setattr(runtime, "preflight", lambda *a: (Path(sys.executable), lock))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: pytest.fail("incompatible engine must not run score"))
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(
            returncode=0, stdout=json.dumps({"interface_version": 1, "score": record}).encode()
        ),
    )
    with pytest.raises(runtime.RuntimeError, match="security-score"):
        runtime.launch(plugin, home, ["score", "selected source"], 30, "security-score")


@pytest.mark.parametrize("command", ["assess", "analyst"])
def test_score_binding_refuses_other_workflows(installed_plugin, monkeypatch, command):
    plugin, home, lock = installed_plugin
    monkeypatch.setattr(runtime, "preflight", lambda *a: (Path(sys.executable), lock))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: pytest.fail("binding cannot invoke another workflow"))
    with pytest.raises(runtime.RuntimeError, match="permits only"):
        runtime.launch(plugin, home, [command], 30, "security-score")


def test_score_binding_cannot_be_selected_by_target_content(installed_plugin, monkeypatch):
    plugin, home, lock = installed_plugin
    lock.pop("skill_bindings")
    monkeypatch.setattr(runtime, "preflight", lambda *a: (Path(sys.executable), lock))
    with pytest.raises(runtime.RuntimeError, match="not selected"):
        runtime.launch(plugin, home, ["score", "selected source"], 30, "security-score")


@pytest.fixture
def profile_plugin(installed_plugin, monkeypatch):
    plugin, home, lock = installed_plugin
    declaration = {
        "schema_version": 1,
        "engine": "appsec-analyzer",
        "interface_versions": [1],
        "required_commands": ["version", "capabilities", "repo-profile"],
        "required_capabilities": {"repo_profile": {"available": True, "model_calls": False}},
        "model_prerequisites": [],
    }
    target = plugin / "skills/repo-profile/dependencies.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(compose.canonical(declaration))
    lock["skill_bindings"] = ["repo-profile"]
    monkeypatch.setattr(runtime, "preflight", lambda *a: (Path(sys.executable), lock))
    return plugin, home


def _engine_reports(monkeypatch, record):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(
            returncode=0, stdout=json.dumps({"interface_version": 1, "repo_profile": record}).encode()
        ),
    )


def test_repo_profile_binding_runs_its_command_without_organization_selection(profile_plugin, monkeypatch):
    plugin, home = profile_plugin
    _engine_reports(monkeypatch, {"available": True, "model_calls": False})
    started = []

    class Process:
        def wait(self, timeout):
            return 0

    monkeypatch.setattr(subprocess, "Popen", lambda command, **kw: started.append(command) or Process())
    assert runtime.launch(plugin, home, ["repo-profile", "a path", "--json"], 30, "repo-profile") == 0
    assert started[0][-3:] == ["repo-profile", "a path", "--json"]


@pytest.mark.parametrize("record", [{"available": True}, {"available": True, "model_calls": True}])
def test_repo_profile_binding_rejects_incompatible_engine_before_execution(profile_plugin, monkeypatch, record):
    plugin, home = profile_plugin
    _engine_reports(monkeypatch, record)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: pytest.fail("incompatible engine must not run"))
    with pytest.raises(runtime.RuntimeError, match="repo-profile"):
        runtime.launch(plugin, home, ["repo-profile", "."], 30, "repo-profile")


@pytest.mark.parametrize("command", ["score", "assess"])
def test_repo_profile_binding_refuses_other_workflows(profile_plugin, monkeypatch, command):
    plugin, home = profile_plugin
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: pytest.fail("binding cannot invoke another workflow"))
    with pytest.raises(runtime.RuntimeError, match="permits only"):
        runtime.launch(plugin, home, [command], 30, "repo-profile")


def test_skill_binding_is_run_only():
    with pytest.raises(SystemExit) as error:
        runtime.main(["setup", "--skill", "security-score"])
    assert error.value.code == 2


def test_missing_runtime_preflight_does_not_install(installed_plugin, monkeypatch):
    plugin, home, _ = installed_plugin
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("preflight must not execute installers"))
    with pytest.raises((runtime.RuntimeError, OSError)):
        runtime.preflight(plugin, home)
    assert not home.exists()


@pytest.mark.parametrize("kind", ["wheel", "file", "lock", "platform"])
def test_tampered_or_incompatible_package_fails_before_setup(installed_plugin, kind):
    plugin, home, lock = installed_plugin
    if kind == "wheel":
        (plugin / "runtime/wheels" / lock["components"][1]["artifact"]).write_bytes(b"tampered")
    elif kind == "file":
        (plugin / "scripts/composition_runtime.py").write_bytes(b"tampered")
    elif kind == "lock":
        lock["interface_version"] = 2
        (plugin / "components.lock.json").write_bytes(compose.canonical(lock))
    else:
        lock["runtime"]["platforms"] = ["impossible-platform"]
        (plugin / "components.lock.json").write_bytes(compose.canonical(lock))
        manifest = json.loads((plugin / "component-manifest.json").read_bytes())
        manifest["lock_sha256"] = compose.digest(compose.canonical(lock))
        (plugin / "component-manifest.json").write_bytes(compose.canonical(manifest))
    with pytest.raises(runtime.RuntimeError):
        runtime.setup(plugin, home)
    assert not home.exists()


def test_failed_setup_cleans_unactivated_runtime_and_can_retry(installed_plugin, monkeypatch):
    plugin, home, _ = installed_plugin
    checked = runtime.checked
    monkeypatch.setattr(
        runtime, "checked", lambda *a, **kw: (_ for _ in ()).throw(runtime.RuntimeError("injected failure"))
    )
    with pytest.raises(runtime.RuntimeError):
        runtime.setup(plugin, home)
    assert list(home.iterdir()) == []
    monkeypatch.setattr(runtime, "checked", checked)
    assert runtime.setup(plugin, home).is_file()


def test_concurrent_setup_refuses_existing_guard(installed_plugin):
    plugin, home, _ = installed_plugin
    _, _, identity = runtime.verified_inputs(plugin)
    home.mkdir()
    guard = home / (identity + ".setup-lock")
    guard.mkdir()
    with pytest.raises(runtime.RuntimeError, match="already active"):
        runtime.setup(plugin, home)
    assert guard.exists() and not (home / identity).exists()


def test_setup_refuses_plugin_storage_and_symlink_input(installed_plugin, tmp_path):
    plugin, _, _ = installed_plugin
    with pytest.raises(runtime.RuntimeError, match="outside"):
        runtime.setup(plugin, plugin / "environment")
    target = plugin / "scripts/composition_runtime.py"
    external = tmp_path / "outside.py"
    external.write_bytes(target.read_bytes())
    target.unlink()
    target.symlink_to(external)
    with pytest.raises(runtime.RuntimeError, match="symlinks"):
        runtime.verified_inputs(plugin)


def test_receipt_and_engine_identity_mismatch_fail_closed(installed_plugin):
    plugin, home, lock = installed_plugin
    lock["components"][1]["version"] = "9.0.0"
    (plugin / "components.lock.json").write_bytes(compose.canonical(lock))
    manifest = json.loads((plugin / "component-manifest.json").read_bytes())
    manifest["components"] = lock["components"]
    manifest["lock_sha256"] = compose.digest(compose.canonical(lock))
    (plugin / "component-manifest.json").write_bytes(compose.canonical(manifest))
    with pytest.raises(runtime.RuntimeError, match="version"):
        runtime.setup(plugin, home)
    assert list(home.iterdir()) == []


def test_missing_required_capability_does_not_activate_runtime(installed_plugin):
    plugin, home, lock = installed_plugin
    lock["components"][1]["capabilities"] = ["unavailable_operation"]
    (plugin / "components.lock.json").write_bytes(compose.canonical(lock))
    manifest = json.loads((plugin / "component-manifest.json").read_bytes())
    manifest["components"] = lock["components"]
    manifest["lock_sha256"] = compose.digest(compose.canonical(lock))
    (plugin / "component-manifest.json").write_bytes(compose.canonical(manifest))
    with pytest.raises(runtime.RuntimeError, match="capabilities"):
        runtime.setup(plugin, home)
    assert list(home.iterdir()) == []


@pytest.mark.skipif(sys.platform == "win32", reason="Unix descendant signal evidence; native Windows remains pending")
def test_timeout_stops_descendants_and_preserves_output(installed_plugin, tmp_path):
    plugin, home, _ = installed_plugin
    runtime.setup(plugin, home)
    output = tmp_path / "assessment evidence"
    output.mkdir()
    with pytest.raises(runtime.RuntimeError, match="interrupted"):
        runtime.launch(plugin, home, ["assess", "--output", str(output)], 1)
    child = int((output / "child.pid").read_text())
    state = Path(f"/proc/{child}/stat")
    if state.exists():
        assert state.read_text().split()[2] == "Z"
    assert output.exists()


def test_runtime_cli_error_is_actionable_and_redacted(installed_plugin, capsys):
    plugin, home, _ = installed_plugin
    assert runtime.main(["preflight", "--plugin", str(plugin), "--runtime-home", str(home)]) == 2
    error = capsys.readouterr().err
    assert "explicit setup" in error and "Traceback" not in error and str(home) not in error


def test_incompatible_python_has_specific_safe_guidance(installed_plugin, capsys):
    plugin, home, lock = installed_plugin
    lock["runtime"]["python"] = ["0.0"]
    (plugin / "components.lock.json").write_bytes(compose.canonical(lock))
    manifest = json.loads((plugin / "component-manifest.json").read_bytes())
    manifest["lock_sha256"] = compose.digest(compose.canonical(lock))
    (plugin / "component-manifest.json").write_bytes(compose.canonical(manifest))
    assert runtime.main(["setup", "--plugin", str(plugin), "--runtime-home", str(home)]) == 2
    error = capsys.readouterr().err
    assert "Python version is not selected" in error and "components.lock.json" in error
    assert not home.exists() and str(home) not in error


def test_duplicate_metadata_is_rejected_before_setup(installed_plugin):
    plugin, home, _ = installed_plugin
    (plugin / "components.lock.json").write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(runtime.RuntimeError, match="duplicate"):
        runtime.setup(plugin, home)
    assert not home.exists()


def test_file_size_mismatch_is_rejected_before_hashing(installed_plugin, monkeypatch):
    plugin, home, _ = installed_plugin
    (plugin / "scripts/composition_runtime.py").write_bytes(b"changed size")
    original = runtime.file_sha

    def guard(path):
        assert path.name != "composition_runtime.py", "mismatched file must not be read"
        return original(path)

    monkeypatch.setattr(runtime, "file_sha", guard)
    with pytest.raises(runtime.RuntimeError, match="integrity"):
        runtime.setup(plugin, home)
    assert not home.exists()


def test_source_checkout_cannot_host_runtime_state(installed_plugin, tmp_path):
    plugin, _, _ = installed_plugin
    repo = tmp_path / "source checkout"
    repo.mkdir()
    (repo / ".git").mkdir()
    home = repo / "state"
    for action in (runtime.setup, runtime.preflight):
        with pytest.raises(runtime.RuntimeError, match="outside Git"):
            action(plugin, home)
    assert not home.exists()


@pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX ownership/mode boundary; native Windows qualification pending"
)
def test_shared_writable_runtime_home_is_rejected(installed_plugin):
    plugin, home, _ = installed_plugin
    home.mkdir(mode=0o777)
    home.chmod(0o777)
    with pytest.raises(runtime.RuntimeError, match="not writable by other users"):
        runtime.setup(plugin, home)
    assert list(home.iterdir()) == []


@pytest.mark.parametrize(
    "arguments,environment,tail,wrapped",
    [
        (["score", "source", "--json"], {}, ["score", "source", "--json"], True),
        (["score", "source", "--preset=release"], {"APPSEC_ADVISOR_PRESET": "invalid"}, ["score", "source"], True),
        (
            ["score", "source", "--no-org-profile"],
            {"APPSEC_ADVISOR_ORG_PROFILE": "/missing.yaml"},
            ["score", "source"],
            False,
        ),
        (
            ["score", "source"],
            {"APPSEC_ADVISOR_NO_ORG_PROFILE": "1", "APPSEC_ADVISOR_PRESET": "invalid"},
            ["score", "source"],
            False,
        ),
        (["score", "--", "--preset=literal"], {}, ["score", "--", "--preset=literal"], True),
    ],
)
def test_organization_dispatch_selection_and_literal_arguments(
    tmp_path, monkeypatch, arguments, environment, tail, wrapped
):
    for key in ("APPSEC_ADVISOR_PRESET", "APPSEC_ADVISOR_ORG_PROFILE", "APPSEC_ADVISOR_NO_ORG_PROFILE"):
        monkeypatch.delenv(key, raising=False)
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    config = tmp_path / "org-profile/analyzer-config.yaml"
    config.parent.mkdir()
    config.write_text("{}")
    capability = {
        "available": True,
        "schema_version": 1,
        "commands": ["score"],
        "profile_fields": ["policy.disable_opus", "policy.url_allowlist", "presets.*.base_mode"],
    }
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout=json.dumps({"organization_config": capability}).encode()),
    )
    manifest = {"files": [{"path": runtime.ORG_DISPATCH}, {"path": "org-profile/analyzer-config.yaml"}]}
    result = runtime.organization_arguments(tmp_path, Path(sys.executable), arguments, manifest)
    if wrapped:
        assert result[:4] == ["organization-config", "run", "--config", str(config)]
        assert result[result.index("--") + 1 :] == tail
        if "--preset=release" in arguments:
            assert result[4:6] == ["--preset", "release"]
    else:
        assert result == tail


@pytest.mark.parametrize(
    "defect",
    [
        "capability",
        "availability-type",
        "version-type",
        "projection",
        "external",
        "preset-value",
        "empty-preset",
        "config-override",
        "nested-run",
    ],
)
def test_organization_dispatch_rejects_missing_context_and_bypass(tmp_path, monkeypatch, defect):
    for key in ("APPSEC_ADVISOR_PRESET", "APPSEC_ADVISOR_ORG_PROFILE", "APPSEC_ADVISOR_NO_ORG_PROFILE"):
        monkeypatch.delenv(key, raising=False)
    config = tmp_path / "org-profile/analyzer-config.yaml"
    config.parent.mkdir()
    config.write_text("{}")
    capability = {
        "available": True,
        "schema_version": 1,
        "commands": ["score"],
        "profile_fields": ["policy.disable_opus", "policy.url_allowlist", "presets.*.base_mode"],
    }
    if defect == "capability":
        capability = {}
    elif defect == "availability-type":
        capability["available"] = 1
    elif defect == "version-type":
        capability["schema_version"] = True
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout=json.dumps({"organization_config": capability}).encode()),
    )
    manifest = {"files": [{"path": runtime.ORG_DISPATCH}, {"path": "org-profile/analyzer-config.yaml"}]}
    arguments = ["score", "source"]
    if defect == "projection":
        manifest["files"].pop()
    elif defect == "external":
        monkeypatch.setenv("APPSEC_ADVISOR_ORG_PROFILE", "/missing.yaml")
    elif defect == "preset-value":
        arguments += ["--preset"]
    elif defect == "empty-preset":
        arguments += ["--preset="]
    elif defect == "config-override":
        arguments = ["organization-config", "show", "--config", "/untrusted.yaml"]
    elif defect == "nested-run":
        arguments = ["organization-config", "run"]
    with pytest.raises(runtime.RuntimeError):
        runtime.organization_arguments(tmp_path, Path(sys.executable), arguments, manifest)


def _external_case(tmp_path):
    plugin = tmp_path / "installed plugin"
    (plugin / "schemas").mkdir(parents=True)
    (plugin / "scripts").mkdir()
    root = Path(__file__).parents[1]
    for relative in ("schemas/org-profile.schema.yaml", "scripts/composition_runtime.py"):
        (plugin / relative).write_bytes((root / relative).read_bytes())
    profile = tmp_path / "operator profile.yaml"
    profile.write_text(
        "api_version: appsec-advisor.org-profile/v2\n"
        'organization: {id: external, name: External Team, profile_version: "1"}\n'
        'compatibility: {core: ">=1 <2"}\n'
        "default_preset: daily\npresets: {daily: {base_mode: standard}, release: {base_mode: thorough}}\n"
        "policy: {disable_opus: true, url_allowlist: [git.example.org]}\n"
    )
    manifest = {
        "files": [
            {"path": relative} for relative in ("schemas/org-profile.schema.yaml", "scripts/composition_runtime.py")
        ]
    }
    lock = {"plugin": {"version": "1.0.0"}, "components": [{"role": "engine", "version": "1.0.0"}]}
    return plugin, profile, manifest, lock


@pytest.mark.parametrize(
    "packaged,relative,selection_source",
    [(True, False, "cli"), (False, True, "cli"), (True, True, "env"), (False, False, "env")],
)
def test_external_profile_precedence_public_projection_and_cleanup(
    tmp_path, monkeypatch, packaged, relative, selection_source
):
    plugin, profile, manifest, lock = _external_case(tmp_path)
    if packaged:
        manifest["files"].append({"path": runtime.ORG_DISPATCH})
    monkeypatch.setenv("APPSEC_ADVISOR_ORG_PROFILE", "/missing-environment.yaml")
    monkeypatch.setenv("APPSEC_ADVISOR_PRESET", "unavailable")

    def run(command, **kwargs):
        if command[-1] == "capabilities":
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "organization_config": {
                            "available": True,
                            "schema_version": 1,
                            "commands": ["score"],
                            "profile_fields": ["policy.disable_opus", "policy.url_allowlist", "presets.*.base_mode"],
                        }
                    }
                ).encode(),
            )
        assert command[:3] == [sys.executable, "-I", "-c"]
        return SimpleNamespace(returncode=0, stdout=runtime.project_profile(*command[5:]))

    monkeypatch.setattr(runtime.subprocess, "run", run)
    selection = "../operator profile.yaml" if relative else str(profile)
    flags = ["--org-profile", selection] if selection_source == "cli" else []
    if selection_source == "env":
        monkeypatch.setenv("APPSEC_ADVISOR_ORG_PROFILE", selection)
    with contextlib.ExitStack() as stack:
        arguments = runtime.organization_arguments(
            plugin,
            Path(sys.executable),
            ["score", "/neutral/source", *flags, "--preset=release", "--json"],
            manifest,
            lock=lock,
            home=tmp_path,
            stack=stack,
        )
        assert arguments[:3] == ["organization-config", "run", "--config"]
        config = Path(arguments[3])
        projection = json.loads(config.read_bytes())
        assert projection["profile"]["organization"]["id"] == "external"
        assert projection["profile"]["default_preset"] == "daily"
        assert projection["profile"]["policy"] == {"disable_opus": True, "url_allowlist": ["git.example.org"]}
        assert projection["engine_version"] == "1.0.0" and projection["advisor_core_version"] == "1.0.0"
        assert arguments[4:] == ["--preset", "release", "--", "score", "/neutral/source", "--json"]
        assert config.stat().st_mode & 0o077 == 0
    assert not config.parent.exists()
    assert profile.exists()


@pytest.mark.parametrize(
    "setting",
    [
        "llm_policy: {approval_required_actions: [publish]}",
        "banner: {headline: Cannot apply at runtime}",
        "hooks: {}",
        "mcp: {servers: {tool: {command: forbidden}}}",
        "policy: {url_allowlist: [false]}",
        "organization: {id: incomplete}",
        "default_preset: absent",
        "unexpected: true",
        "presets: {daily: {base_mode: standard, outputs: {sarif: true}}}",
    ],
)
def test_external_profile_rejects_unsupported_or_invalid_settings(tmp_path, capfd, setting):
    plugin, profile, _, _ = _external_case(tmp_path)
    # Replace a top-level field rather than relying on duplicate-key rejection.
    import yaml

    document = yaml.safe_load(profile.read_bytes())
    document.update(yaml.safe_load(setting))
    profile.write_text(json.dumps(document))
    with pytest.raises(runtime.RuntimeError):
        runtime.project_profile(str(plugin), str(profile), "1.0.0", "1.0.0")
    assert capfd.readouterr().out == ""


@pytest.mark.parametrize(
    "content",
    [
        "!!python/object/apply:os.system ['touch forbidden']",
        "a: 1\na: 2",
        "a: &x {}\nb: *x",
        "x" * 65537,
        "[]",
        "a: .nan",
    ],
)
def test_external_profile_data_is_bounded_unambiguous_and_nonexecutable(content):
    with pytest.raises((runtime.RuntimeError, ValueError)):
        runtime.profile_data(content.encode(), maximum=65536)


@pytest.mark.parametrize("defect", ["source", "symlink", "parent-symlink", "missing-schema"])
def test_external_profile_rejects_untrusted_selection_before_adapter(tmp_path, monkeypatch, defect):
    plugin, profile, manifest, lock = _external_case(tmp_path)
    arguments = ["score", str(tmp_path)] if defect == "source" else ["score", "/selected/source"]
    if defect == "symlink":
        alias = tmp_path / "alias.yaml"
        alias.symlink_to(profile)
        profile = alias
    elif defect == "parent-symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(plugin)
        profile = alias / "schemas/org-profile.schema.yaml"
    elif defect == "missing-schema":
        manifest["files"] = []
    monkeypatch.setattr(runtime.subprocess, "run", lambda *a, **kw: pytest.fail("adapter must not run"))
    with contextlib.ExitStack() as stack, pytest.raises(runtime.RuntimeError):
        runtime.external_projection(
            plugin,
            Path(sys.executable),
            str(profile),
            arguments,
            {item["path"] for item in manifest["files"]},
            lock,
            tmp_path,
            stack,
        )


@pytest.mark.parametrize("name", ["APPSEC_ADVISOR_ORG_PROFILE", "APPSEC_ADVISOR_PRESET"])
def test_empty_environment_selection_fails_without_packaged_fallback(tmp_path, monkeypatch, name):
    monkeypatch.setenv(name, "")
    with pytest.raises(runtime.RuntimeError, match="nonempty"):
        runtime.organization_arguments(tmp_path, Path(sys.executable), ["score", "source"], {"files": []})


@pytest.mark.parametrize("status", [0, 1, 2, 130, "timeout"])
def test_external_projection_cleanup_covers_engine_outcomes(tmp_path, monkeypatch, status):
    plugin, profile, manifest, lock = _external_case(tmp_path)
    monkeypatch.setenv("APPSEC_ADVISOR_ORG_PROFILE", str(profile))
    (plugin / "component-manifest.json").write_bytes(runtime.encode(manifest))
    monkeypatch.setattr(runtime, "preflight", lambda *a: (Path(sys.executable), lock))
    config_paths = []

    def projection(*args):
        stack = args[-1]
        folder = Path(stack.enter_context(runtime.tempfile.TemporaryDirectory(dir=tmp_path)))
        config = folder / "engine.yaml"
        config.write_text("{}")
        config_paths.append(config)
        return str(config)

    monkeypatch.setattr(runtime, "external_projection", projection)
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "organization_config": {
                        "available": True,
                        "schema_version": 1,
                        "commands": ["score"],
                        "profile_fields": ["policy.disable_opus", "policy.url_allowlist", "presets.*.base_mode"],
                    }
                }
            ).encode(),
        ),
    )

    class Process:
        pid = 123
        calls = 0

        def wait(self, timeout):
            self.calls += 1
            assert config_paths[0].exists()
            if status == "timeout" and self.calls == 1:
                raise subprocess.TimeoutExpired("engine", timeout)
            return status if status != "timeout" else 1

    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *a, **kw: Process())
    monkeypatch.setattr(runtime.os, "killpg", lambda *a: None)
    if status == "timeout":
        with pytest.raises(runtime.RuntimeError, match="interrupted"):
            runtime.launch(plugin, tmp_path, ["score", "/neutral/source"], 1)
    else:
        assert runtime.launch(plugin, tmp_path, ["score", "/neutral/source"], 1) == status
    assert config_paths and not config_paths[0].parent.exists()


@pytest.mark.parametrize("command", ["assess"])
@pytest.mark.parametrize("selection", ["packaged", "external", "disabled"])
def test_assessment_dispatch_requires_declared_workflow_and_preserves_origin(tmp_path, monkeypatch, command, selection):
    plugin, profile, manifest, lock = _external_case(tmp_path)
    config = plugin / "org-profile/analyzer-config.yaml"
    config.parent.mkdir()
    config.write_text("{}")
    manifest["files"] += [{"path": runtime.ORG_DISPATCH}, {"path": "org-profile/analyzer-config.yaml"}]
    capability = {
        "available": True,
        "schema_version": 1,
        "commands": ["score", "assess"],
        "profile_source_validation": True,
        "profile_fields": ["policy.disable_opus", "policy.url_allowlist", "presets.*.base_mode"],
    }

    def run(args, **kw):
        if args[-1] == "capabilities":
            return SimpleNamespace(returncode=0, stdout=json.dumps({"organization_config": capability}).encode())
        return SimpleNamespace(returncode=0, stdout=runtime.project_profile(*args[5:]))

    monkeypatch.setattr(runtime.subprocess, "run", run)
    flags = ["--org-profile", str(profile)] if selection == "external" else []
    if selection == "disabled":
        monkeypatch.setenv("APPSEC_ADVISOR_NO_ORG_PROFILE", "1")
        monkeypatch.setenv("APPSEC_ADVISOR_ORG_PROFILE", "/missing.yaml")
    arguments = [command, "--repo", "/neutral/one", "--repo=/neutral/two", "--assessment-depth=quick", *flags]
    with contextlib.ExitStack() as stack:
        result = runtime.organization_arguments(
            plugin, Path(sys.executable), arguments, manifest, lock=lock, home=tmp_path, stack=stack
        )
        if selection == "disabled":
            assert result == [*arguments, "--no-org-profile"]
        else:
            assert result[:3] == ["organization-config", "run", "--config"]
            assert result[result.index("--") + 1 :] == arguments[:5]
            if selection == "external":
                assert result[4:6] == ["--profile-source", str(profile)]
            else:
                assert result[3] == str(config)


@pytest.mark.parametrize("defect", ["old-engine", "missing-source-validation", "source-override"])
def test_assessment_dispatch_rejects_incomplete_capability_or_provenance_override(tmp_path, monkeypatch, defect):
    capability = {
        "available": True,
        "schema_version": 1,
        "commands": ["score", "assess"],
        "profile_source_validation": True,
        "profile_fields": ["policy.disable_opus", "policy.url_allowlist", "presets.*.base_mode"],
    }
    if defect == "old-engine":
        capability["commands"] = ["score"]
    if defect == "missing-source-validation":
        capability["profile_source_validation"] = 1
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout=json.dumps({"organization_config": capability}).encode()),
    )
    config = tmp_path / "org-profile/analyzer-config.yaml"
    config.parent.mkdir()
    config.write_text("{}")
    manifest = {"files": [{"path": runtime.ORG_DISPATCH}, {"path": "org-profile/analyzer-config.yaml"}]}
    args = ["assess", "--repo", "/neutral/source"]
    if defect == "source-override":
        args = ["organization-config", "show", "--profile-source=/unchecked.yaml"]
    with pytest.raises(runtime.RuntimeError):
        runtime.organization_arguments(tmp_path, Path(sys.executable), args, manifest)


@pytest.mark.parametrize("command", ["status", "progress", "stop", "results", "query", "export", "assessment-entry"])
def test_output_consumers_remain_available_with_missing_external_profile(tmp_path, monkeypatch, command):
    monkeypatch.setenv("APPSEC_ADVISOR_ORG_PROFILE", "/missing/operator.yaml")
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: pytest.fail("output operations need no profile or model inspection")
    )
    arguments = [command, "--output", "/private/output"]
    assert (
        runtime.organization_arguments(
            tmp_path, Path(sys.executable), arguments, {"files": [{"path": runtime.ORG_DISPATCH}]}
        )
        == arguments
    )


@pytest.mark.parametrize("status", [0, 20, 3, 2, 130])
def test_assessment_binding_preserves_claude_arguments_and_real_exit_status(installed_plugin, monkeypatch, status):
    plugin, home, lock = installed_plugin
    lock["skill_bindings"].append("appsec-analyzer")
    monkeypatch.setattr(runtime, "preflight", lambda *a: (Path(sys.executable), lock))
    monkeypatch.setattr(runtime, "engine_capabilities", lambda python, names: None)
    seen = []

    class Process:
        def wait(self, timeout):
            return status

    monkeypatch.setattr(subprocess, "Popen", lambda arguments, **kw: seen.append((arguments, kw)) or Process())
    args = ["assess", "--repo", "source with spaces;$(literal)", "--output=/private/output", "--budget=7", "--resume"]
    assert runtime.launch(plugin, home, args, 60, "appsec-analyzer") == status
    assert seen[0][0] == [
        sys.executable,
        "-I",
        "-m",
        "appsec_analyzer.cli",
        *args,
        "--launch-defaults=advisor",
        "--host=claude-cli",
        "--non-interactive",
        "--width=72",
    ]
    assert not seen[0][1].get("shell")


@pytest.mark.parametrize("arguments", [["score", "source"], ["review", "/result"], ["organization-config", "run"]])
def test_assessment_binding_refuses_unrelated_or_nested_execution(installed_plugin, monkeypatch, arguments):
    plugin, home, lock = installed_plugin
    lock["skill_bindings"].append("appsec-analyzer")
    monkeypatch.setattr(runtime, "preflight", lambda *a: (Path(sys.executable), lock))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: pytest.fail("refused workflow cannot start"))
    with pytest.raises(runtime.RuntimeError, match="permits only"):
        runtime.launch(plugin, home, arguments, 60, "appsec-analyzer")


@pytest.mark.parametrize("interruption,expected", [(KeyboardInterrupt, 130), (subprocess.TimeoutExpired, 2)])
def test_assessment_cancellation_uses_public_stop_with_equals_output(
    installed_plugin, monkeypatch, interruption, expected
):
    plugin, home, lock = installed_plugin
    monkeypatch.setattr(runtime, "preflight", lambda *a: (Path(sys.executable), lock))
    called = []

    class Process:
        pid = 123
        calls = 0

        def wait(self, timeout):
            self.calls += 1
            if self.calls == 1:
                if interruption is KeyboardInterrupt:
                    raise KeyboardInterrupt
                raise subprocess.TimeoutExpired("engine", timeout)
            return 130

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: Process())
    monkeypatch.setattr(subprocess, "run", lambda arguments, **kw: called.append(arguments))
    monkeypatch.setattr(runtime.os, "killpg", lambda *a: None)
    if expected == 130:
        assert runtime.launch(plugin, home, ["assess", "--output=/private/output"], 1) == 130
    else:
        with pytest.raises(runtime.RuntimeError, match="timed out"):
            runtime.launch(plugin, home, ["assess", "--output=/private/output"], 1)
    assert called == [[sys.executable, "-I", "-m", "appsec_analyzer.cli", "stop", "--output", "/private/output"]]


def test_public_follower_finishes_after_owner_without_stopping_it(installed_plugin, monkeypatch, capsys):
    plugin, home, lock = installed_plugin
    lock["skill_bindings"].append("appsec-analyzer")
    target = plugin / "scripts/runtime/assessment_console.py"
    target.parent.mkdir(parents=True)
    target.write_bytes((Path(__file__).parents[1] / "scripts/runtime/assessment_console.py").read_bytes())
    monkeypatch.setattr(runtime, "preflight", lambda *a: (Path(sys.executable), lock))
    monkeypatch.setattr(runtime, "engine_capabilities", lambda *a: None)
    calls = []

    def invoke(arguments, **kwargs):
        args = arguments[4:]
        calls.append(args)
        if args[0] == "assessment-entry":
            document = {"live": True, "run_id": "selected-run"}
        else:
            document = {
                "run_id": "selected-run",
                "assessment_status": "complete",
                "next_offset": 1,
                "events": [{"event": "warning", "detail": "Coverage gap: optional check skipped"}],
            }
        return SimpleNamespace(returncode=0, stdout=json.dumps({"interface_version": 1, **document}).encode())

    monkeypatch.setattr(subprocess, "run", invoke)
    assert runtime.follow(plugin, home, "/private/output", 30) == 0
    assert "Coverage gap: optional check skipped" in capsys.readouterr().out
    assert [args[0] for args in calls] == ["assessment-entry", "progress"]


@pytest.mark.parametrize(
    "record",
    [
        {"available": True},
        {"available": True, "schema_version": True, "model_calls": False},
        {"available": True, "schema_version": 1, "model_calls": True},
    ],
)
def test_assessment_binding_requires_versioned_model_free_preparation(monkeypatch, record):
    capability = {name: {"available": True} for name in runtime.ASSESSMENT_CAPABILITIES}
    capability.update(interface_version=1, assessment_entry=record)
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout=json.dumps(capability).encode())
    )
    with pytest.raises(runtime.RuntimeError, match="entry contract"):
        runtime.engine_capabilities(Path(sys.executable), runtime.ASSESSMENT_CAPABILITIES)


@pytest.mark.parametrize("defect", ["cursor", "events", "event"])
def test_public_follower_rejects_malformed_engine_progress(installed_plugin, monkeypatch, defect):
    plugin, home, lock = installed_plugin
    lock["skill_bindings"].append("appsec-analyzer")
    target = plugin / "scripts/runtime/assessment_console.py"
    target.parent.mkdir(parents=True)
    target.write_bytes((Path(__file__).parents[1] / "scripts/runtime/assessment_console.py").read_bytes())
    monkeypatch.setattr(runtime, "preflight", lambda *a: (Path(sys.executable), lock))
    monkeypatch.setattr(runtime, "engine_capabilities", lambda *a: None)

    def invoke(arguments, **kwargs):
        if arguments[4] == "assessment-entry":
            document = {"live": True, "run_id": "selected-run"}
        else:
            document = {"run_id": "selected-run", "assessment_status": "complete", "next_offset": 1, "events": []}
            if defect == "cursor":
                document["next_offset"] = "1"
            elif defect == "events":
                document["events"] = {}
            else:
                document["events"] = ["execute a command"]
        return SimpleNamespace(returncode=0, stdout=json.dumps({"interface_version": 1, **document}).encode())

    monkeypatch.setattr(subprocess, "run", invoke)
    with pytest.raises(runtime.RuntimeError, match="invalid public progress"):
        runtime.follow(plugin, home, "/private/output", 30)


@pytest.mark.parametrize("holders", [[True, False], [False], [True, True, True], ["false"]])
def test_wait_uses_only_public_holder_and_fails_closed(installed_plugin, monkeypatch, holders):
    plugin, home, lock = installed_plugin
    lock["skill_bindings"].append("appsec-analyzer")
    monkeypatch.setattr(runtime, "preflight", lambda *a: (Path(sys.executable), lock))
    monkeypatch.setattr(runtime, "engine_capabilities", lambda *a: None)
    ticks = iter([0, 0, 0, 1, 2, 3, 4])
    monkeypatch.setattr(runtime.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(runtime.time, "sleep", lambda _: None)
    calls = []
    pending = iter(holders)

    def invoke(arguments, **kwargs):
        calls.append(arguments[4:])
        return subprocess.CompletedProcess(
            arguments, 0, json.dumps({"interface_version": 1, "live": next(pending)}).encode()
        )

    monkeypatch.setattr(subprocess, "run", invoke)
    if holders == ["false"]:
        with pytest.raises(runtime.RuntimeError, match="holder"):
            runtime.follow(plugin, home, "/private/output", 3, wait_for_stop=True)
    else:
        assert runtime.follow(plugin, home, "/private/output", 3, wait_for_stop=True) == (3 if all(holders) else 0)
    assert all(args == ["assessment-entry", "holder", "--output", "/private/output"] for args in calls)


@pytest.mark.parametrize("width", [["--width=96"], ["--width", "80"]])
def test_assessment_binding_keeps_explicit_display_width(installed_plugin, monkeypatch, width):
    plugin, home, lock = installed_plugin
    lock["skill_bindings"].append("appsec-analyzer")
    monkeypatch.setattr(runtime, "preflight", lambda *a: (Path(sys.executable), lock))
    monkeypatch.setattr(runtime, "engine_capabilities", lambda *a: None)
    seen = []

    class Process:
        def wait(self, timeout):
            return 0

    monkeypatch.setattr(subprocess, "Popen", lambda args, **kw: seen.append(args) or Process())
    assert runtime.launch(plugin, home, ["assess", "--output=/private/result", *width], 60, "appsec-analyzer") == 0
    assert "--width=72" not in seen[0] and all(value in seen[0] for value in width)
