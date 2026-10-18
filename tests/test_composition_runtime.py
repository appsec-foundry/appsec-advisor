"""Installed staging runtime checks with a neutral offline wheel, never a model."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import compose_plugin as compose
import composition_runtime as runtime
import pytest

from tests.test_compose_plugin import make_composition

ENGINE = """import json, os, subprocess, sys, time
from pathlib import Path
if sys.argv[1:] == ["version"]:
    print(json.dumps({"engine_version": "1.0.0", "interface_version": 1}))
elif sys.argv[1:] == ["capabilities"]:
    print(json.dumps({"interface_version": 1, "score": {"available": True}}))
elif sys.argv[1] == "stop":
    pass
elif sys.argv[1] == "assess":
    out = Path(sys.argv[sys.argv.index("--output") + 1])
    child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(60)"])
    (out / "child.pid").write_text(str(child.pid))
    time.sleep(60)
else:
    print(json.dumps({"python": sys.executable, "args": sys.argv[1:], "pythonpath": os.environ.get("PYTHONPATH")}))
"""


@pytest.fixture
def installed_plugin(tmp_path):
    lock, inputs = make_composition(tmp_path)
    engine = lock["components"][1]
    metadata = "appsec_analyzer-1.0.0.dist-info"
    wheel = compose.zip_bytes(
        {
            "appsec_analyzer/__init__.py": b"",
            "appsec_analyzer/cli.py": ENGINE.encode(),
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
    assert runtime.launch(plugin, home, ["score", "path with spaces;$(no-shell)"], 30) == 0
    response = json.loads(capfd.readouterr().out)
    assert response["args"] == ["score", "path with spaces;$(no-shell)"]
    assert response["python"] == str(python)
    assert response["pythonpath"] is None
    assert (
        runtime.main(["run", "--plugin", str(plugin), "--runtime-home", str(home), "--", "score", "another path"]) == 0
    )
    assert json.loads(capfd.readouterr().out)["args"] == ["score", "another path"]
    assert not list(home.glob("*.setup-lock"))


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
