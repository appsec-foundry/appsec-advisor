"""Installed staging runtime checks with a neutral offline wheel, never a model."""

from __future__ import annotations

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


@pytest.mark.parametrize("command", ["assess", "scan", "analyst"])
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
