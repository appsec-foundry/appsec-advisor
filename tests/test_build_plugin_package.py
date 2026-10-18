from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import build_plugin_package as package
import compose_plugin as compose
import composition_runtime
import pytest

ROOT = Path(__file__).resolve().parents[1]
SCORE = "skills/security-score"
SCORE_DECLARATION = {
    "schema_version": 1,
    "engine": "appsec-analyzer",
    "interface_versions": [1],
    "required_commands": ["version", "capabilities", "score"],
    "required_capabilities": {"score": {"available": True, "model_calls": False, "scoring_version": 2}},
    "model_prerequisites": [],
}


def commit_tree(root: Path, files: dict[str, bytes]) -> Path:
    root.mkdir()
    for name, data in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com"]
    subprocess.run([*git, "init", "-q", "-b", "main"], check=True)
    # Local fixtures stand in for the HTTPS remote, which serves pinned commits by ID.
    subprocess.run([*git, "config", "uploadpack.allowAnySHA1InWant", "true"], check=True)
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "fixture"], check=True)
    return root


@pytest.fixture
def inputs(tmp_path):
    """Neutral engine, skills and dependency inputs; the host is this repository's HEAD."""
    pytest.importorskip("build")
    engine = commit_tree(
        tmp_path / "engine checkout",
        {
            "setup.py": b"from setuptools import setup\nsetup(name='appsec-analyzer', version='1.0.0', "
            b"packages=['appsec_analyzer'], package_data={'appsec_analyzer': ['skills/primary/*.md']})\n",
            "appsec_analyzer/__init__.py": b"",
            "appsec_analyzer/skills/primary/SKILL.md": b"---\nname: appsec-analyzer\n---\nEngine entry.\n",
            "appsec_analyzer/skills/primary/claude-code.md": b"Claude workflow.\n",
            "appsec_analyzer/skills/primary/business-context.md": b"Dialogue.\n",
        },
    )
    skills = commit_tree(
        tmp_path / "skills checkout",
        {
            f"{SCORE}/SKILL.md": b"---\nname: security-score\ndescription: Score\n---\nSee references.\n",
            f"{SCORE}/dependencies.json": compose.canonical(SCORE_DECLARATION),
            f"{SCORE}/references/compatibility.md": b"Limits.\n",
        },
    )
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    wheel = compose.zip_bytes({"dep-2.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: dep\nVersion: 2.0\n"})
    (wheelhouse / "dep-2.0-py3-none-any.whl").write_bytes(wheel)
    selection = json.loads((ROOT / "data/plugin-package.json").read_bytes())
    selection["engine"]["files"] = {
        f"appsec_analyzer/skills/primary/{name}": f"skills/appsec-analyzer/{name}"
        for name in ("SKILL.md", "claude-code.md", "business-context.md")
    }
    selection["skills"]["files"] = [
        f"{SCORE}/{name}" for name in ("SKILL.md", "dependencies.json", "references/compatibility.md")
    ]
    selection["dependencies"] = [
        {
            "id": "dep",
            "version": "2.0",
            "license": "MIT",
            "source": "https://pypi.org/project/dep/2.0",
            "artifact": "dep-2.0-py3-none-any.whl",
            "sha256": compose.digest(wheel),
        }
    ]
    return engine, skills, wheelhouse, selection, tmp_path


def run(inputs, output: Path, *, analyzer_rev="HEAD", selection=None) -> int:
    engine, skills, wheelhouse, default, tmp_path = inputs
    selection_path = tmp_path / f"{output.name}-selection.json"
    selection_path.write_text(json.dumps(selection or default))
    return package.main(
        [
            *("--selection", str(selection_path), "package"),
            *("--analyzer-src", str(engine), f"--analyzer-rev={analyzer_rev}"),
            *("--skills-src", str(skills), "--skills-rev", "HEAD", "--wheelhouse", str(wheelhouse)),
            *("--output", str(output)),
        ]
    )


def head(repository: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()


def add_commit(repository: Path, name: str) -> str:
    (repository / name).write_text("next\n")
    git = ["git", "-C", str(repository), "-c", "user.name=t", "-c", "user.email=t@example.com"]
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "next"], check=True)
    return head(repository)


@pytest.fixture
def remote_pins(inputs, monkeypatch):
    """Pin the fixtures as remote sources; only the fetch location is redirected to them."""
    engine, skills, _, selection, tmp_path = inputs
    repositories = {selection["engine"]["id"]: engine, selection["skills"]["id"]: skills}
    monkeypatch.setattr(package, "remote", lambda item: str(repositories[item["id"]]))
    for key, repository in (("engine", engine), ("skills", skills)):
        selection[key].update(branch="main", revision=head(repository))
    path = tmp_path / "pinned-selection.json"
    path.write_text(json.dumps(selection, indent=2))
    return path


def test_builds_committed_inputs_reproducibly_and_ignores_working_tree_changes(inputs):
    engine, skills, _, _, tmp_path = inputs
    assert run(inputs, tmp_path / "first") == 0
    (engine / "appsec_analyzer/skills/primary/claude-code.md").write_bytes(b"uncommitted change\n")
    (skills / SCORE / "references/compatibility.md").write_bytes(b"uncommitted change\n")
    assert run(inputs, tmp_path / "second") == 0
    first, second = tmp_path / "first", tmp_path / "second"
    assert (first / "components.lock.json").read_bytes() == (second / "components.lock.json").read_bytes()
    archive = "assembly/appsec-advisor-" + json.loads((ROOT / ".claude-plugin/plugin.json").read_bytes())["version"]
    assert Path(f"{first}/{archive}-staging.zip").read_bytes() == Path(f"{second}/{archive}-staging.zip").read_bytes()
    lock = json.loads((first / "components.lock.json").read_bytes())
    assert [c["role"] for c in lock["components"]] == ["host", "engine", "skills", "dependency"]
    assert lock["components"][1]["version"] == "1.0.0"
    assert set(composition_runtime.ASSESSMENT_CAPABILITIES) <= set(lock["components"][1]["capabilities"])


def test_wheelhouse_mismatch_fails_and_removes_the_partial_package(inputs, capsys):
    _, _, wheelhouse, _, tmp_path = inputs
    (wheelhouse / "dep-2.0-py3-none-any.whl").write_bytes(b"replaced")
    assert run(inputs, tmp_path / "out") == 2
    assert "pinned SHA-256" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("revision", ["--output=/elsewhere", "HEAD~1..HEAD", "no-such-branch"])
def test_rejects_option_range_and_unknown_revisions(inputs, revision):
    _, _, _, _, tmp_path = inputs
    assert run(inputs, tmp_path / "out", analyzer_rev=revision) == 2
    assert not (tmp_path / "out").exists()


def test_existing_output_is_refused_and_left_unchanged(inputs, capsys):
    _, _, _, _, tmp_path = inputs
    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "keep.txt").write_text("operator data")
    assert run(inputs, existing) == 2
    assert "already exists" in capsys.readouterr().err
    assert (existing / "keep.txt").read_text() == "operator data"


@pytest.mark.parametrize("path", [f"{SCORE}/missing.md", f"{SCORE}/references", f"{SCORE}/link.md"])
def test_rejects_missing_directory_and_linked_selections(inputs, path):
    _, skills, _, selection, tmp_path = inputs
    (skills / SCORE / "link.md").symlink_to("SKILL.md")
    subprocess.run(["git", "-C", str(skills), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(skills), "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "x"],
        check=True,
    )
    selection = json.loads(json.dumps(selection))
    selection["skills"]["files"].append(path)
    assert run(inputs, tmp_path / "out", selection=selection) == 2
    assert not (tmp_path / "out").exists()


def test_committed_selection_names_regular_host_files_and_bound_capabilities():
    selection = json.loads((ROOT / "data/plugin-package.json").read_bytes())
    files = package.committed_files(ROOT, package.commit(ROOT, "HEAD"), selection["host"]["files"])
    assert set(compose.HOST_OWNED) <= set(files)
    assert set(composition_runtime.ASSESSMENT_CAPABILITIES) <= set(selection["engine"]["capabilities"])
    ids = [c["id"] for c in (selection["host"], selection["engine"], selection["skills"], *selection["dependencies"])]
    assert len(ids) == len(set(ids))


def test_package_fetches_only_pinned_commits_and_reuses_the_cache(inputs, remote_pins):
    engine, skills, wheelhouse, _, tmp_path = inputs
    pinned = json.loads(remote_pins.read_bytes())
    add_commit(engine, "later.txt")  # A newer remote head must not enter the package.
    common = ["--selection", str(remote_pins), "package", "--wheelhouse", str(wheelhouse)]
    common += ["--sources", str(tmp_path / "cache")]
    assert package.main([*common, "--output", str(tmp_path / "first")]) == 0
    lock = json.loads((tmp_path / "first/components.lock.json").read_bytes())
    assert [c["revision"] for c in lock["components"][1:3]] == [
        pinned["engine"]["revision"],
        pinned["skills"]["revision"],
    ]
    shutil.rmtree(engine)
    shutil.rmtree(skills)
    assert package.main([*common, "--output", str(tmp_path / "second")]) == 0
    assert (tmp_path / "first/components.lock.json").read_bytes() == (
        tmp_path / "second/components.lock.json"
    ).read_bytes()


@pytest.mark.parametrize("revision", ["main", "684a57e1"])
def test_remote_build_requires_a_full_pinned_commit(inputs, remote_pins, revision):
    _, _, wheelhouse, _, tmp_path = inputs
    arguments = ["--selection", str(remote_pins), "package", "--wheelhouse", str(wheelhouse)]
    arguments += [f"--analyzer-rev={revision}", "--sources", str(tmp_path / "cache"), "--output", str(tmp_path / "out")]
    assert package.main(arguments) == 2
    assert not (tmp_path / "out").exists()


def test_update_moves_only_commit_pins_to_the_remote_branch_head(inputs, remote_pins, capsys):
    engine, _, _, _, _ = inputs
    before = remote_pins.read_text()
    newer = add_commit(engine, "later.txt")
    assert package.main(["--selection", str(remote_pins), "update"]) == 0
    after = remote_pins.read_text()
    old = json.loads(before)["engine"]["revision"]
    assert after == before.replace(old, newer)
    assert "compare/" in capsys.readouterr().out
    assert package.main(["--selection", str(remote_pins), "update"]) == 0
    assert remote_pins.read_text() == after
    assert "already match" in capsys.readouterr().out


@pytest.mark.parametrize("field, value", [("version", "9.9"), ("source", "https://example.com/dep/2.0")])
def test_wheel_download_refuses_pins_without_matching_pypi_identity(inputs, monkeypatch, field, value):
    _, _, _, selection, tmp_path = inputs
    selection["dependencies"][0][field] = value
    monkeypatch.setattr(package.subprocess, "run", lambda *a, **k: pytest.fail("pip must not run"))
    with pytest.raises(package.PackageError, match="PyPI source"):
        package.download_wheels(selection, tmp_path / "wheels")


def test_package_downloads_only_missing_wheels(inputs, monkeypatch):
    _, _, wheelhouse, _, tmp_path = inputs
    calls = []
    fixture = (wheelhouse / "dep-2.0-py3-none-any.whl").read_bytes()

    def download(selection, target):
        calls.append(target)
        target.mkdir(exist_ok=True)
        (target / "dep-2.0-py3-none-any.whl").write_bytes(fixture)

    monkeypatch.setattr(package, "download_wheels", download)
    assert run(inputs, tmp_path / "present") == 0
    assert calls == []
    (wheelhouse / "dep-2.0-py3-none-any.whl").unlink()
    assert run(inputs, tmp_path / "missing") == 0
    assert calls == [wheelhouse]
