"""Offline modular lifecycle tests using the authenticated upstream release."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import baseline_check as bc
import baseline_modular as bm
import install_baseline as ib
import remove_baseline as rb
import update_baseline as ub


@pytest.fixture
def config():
    return bc.load_config(ROOT)


@pytest.fixture
def locations(tmp_path):
    repo, home = tmp_path / "sample-service", tmp_path / "operator"
    repo.mkdir()
    home.mkdir()
    return repo, home


def check(repo, home, config):
    return bc.check(repo=repo, home=home, config=config, policy_roots=(), policy_settings=())


@pytest.mark.parametrize("scope", ["project", "project-rules", "user"])
def test_offline_install_load_update_remove(scope, locations, config):
    repo, home = locations
    steps = ib.install(scope, repo, home, config, offline=True)
    assert any("modular" in step for step in steps)
    target = ib.plan(scope, repo, home, config)["target"]
    text = target.read_text()
    assert "aiscb-MODULES-001" in text
    assert "`module-id:" not in text, "module bodies must not enter the initial context"
    result = check(repo, home, config)
    assert result["status"] == "installed", result
    assert result["matches"][0]["loaded_modules"] is None
    assert "aiscb:llm-agents" in result["matches"][0]["available_modules"]
    fingerprint = bm.metadata(text)["digest"]
    snapshot = bm.storage(target, scope) / fingerprint
    done = subprocess.run(
        [sys.executable, str(snapshot / "policy_loader.py"), "--digest", fingerprint, "aiscb:llm-agents"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Verified aiscb:llm-applications" in done.stdout
    assert "Verified aiscb:llm-agents" in done.stdout
    refused = subprocess.run(
        [sys.executable, str(snapshot / "policy_loader.py"), "--digest", fingerprint, "unknown:module"],
        capture_output=True,
        text=True,
    )
    assert refused.returncode != 0 and not refused.stdout
    ib.install(scope, repo, home, config, offline=True)
    assert target.read_text() == text
    assert ub.update(repo, home, config, offline=True)[1] == 0
    rb.remove(scope, repo, home, config, delete_file=(scope == "project-rules"))
    assert check(repo, home, config)["status"] == "missing"
    assert snapshot.is_dir(), "existing sessions retain their snapshot"


@pytest.mark.parametrize("name", ["alpha-workspace", "nested-alternative"])
def test_project_adapter_survives_checkout_relocation(name, locations, config, tmp_path):
    repo, home = locations
    ib.install("project", repo, home, config, offline=True)
    moved = tmp_path / name
    shutil.copytree(repo, moved)
    shutil.rmtree(repo)
    result = check(moved, home, config)
    assert result["status"] == "installed", result
    target = moved / config["install_filename"]
    info = bm.metadata(target.read_text())
    loader = Path(".appsec-baseline/releases") / info["digest"] / "policy_loader.py"
    done = subprocess.run(
        [sys.executable, str(loader), "--digest", info["digest"], "aiscb:data-handling"],
        cwd=moved,
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0 and "Verified aiscb:data-handling" in done.stdout
    assert str(repo) not in target.read_text()


@pytest.mark.parametrize("damage", ["module", "loader", "manifest", "adapter", "missing", "symlink"])
def test_damaged_modular_install_fails_closed(damage, locations, config, tmp_path):
    repo, home = locations
    ib.install("project", repo, home, config, offline=True)
    target = repo / config["install_filename"]
    info = bm.metadata(target.read_text())
    snapshot = bm.storage(target, "project") / info["digest"]
    package = json.loads((snapshot / "policy.json").read_text())
    artifact = snapshot / package["modules"][0]["artifact"]
    if damage == "module":
        artifact.write_text("modified")
    elif damage == "loader":
        (snapshot / "policy_loader.py").write_text('raise SystemExit("must never execute")')
    elif damage == "manifest":
        (snapshot / "policy.json").write_text("{}")
    elif damage == "adapter":
        target.write_text(target.read_text().replace("before affected work", "after affected work"))
    elif damage == "missing":
        artifact.unlink()
    else:
        external = tmp_path / "outside.md"
        external.write_bytes(artifact.read_bytes())
        artifact.unlink()
        artifact.symlink_to(external)
    result = check(repo, home, config)
    assert result["status"] == "invalid", result
    assert bc.is_failing(result)
    before = target.read_bytes()
    with pytest.raises(ub.UpdateError):
        ub.update(repo, home, config, offline=True)
    assert target.read_bytes() == before


def test_marker_alone_and_core_without_loader_are_not_installations(locations, config):
    repo, home = locations
    (repo / "CLAUDE.md").write_text(
        "`baseline-id: aiscb-0.1.17`\nInstallation mode: modular. Source: /absent. Release: aiscb-0.1.17.\n"
    )
    assert check(repo, home, config)["status"] == "invalid"
    (repo / "CLAUDE.md").write_text("`baseline-id: aiscb-0.1.17`\naiscb-MODULES-001\n")
    assert check(repo, home, config)["status"] == "invalid"


def test_dry_run_writes_no_adapter_or_snapshot(locations, config):
    repo, home = locations
    ib.install("project", repo, home, config, offline=True, dry_run=True)
    assert not list(repo.iterdir())


def test_complete_mode_and_explicit_migration_preserve_instructions(locations, config):
    repo, home = locations
    instructions = repo / "CLAUDE.md"
    instructions.write_text("# Team instructions\nKeep this text.\n")
    ib.install("project", repo, home, config, offline=True, mode="complete")
    target = repo / config["install_filename"]
    original = target.read_bytes()
    assert check(repo, home, config)["status"] == "installed"
    with pytest.raises(ib.InstallError, match="--migrate"):
        ib.install("project", repo, home, config, offline=True, mode="modular")
    assert target.read_bytes() == original
    ib.install("project", repo, home, config, offline=True, force=True)
    assert target.read_bytes() == original, "refresh must retain complete compatibility mode"
    ib.install("project", repo, home, config, offline=True, migrate=True)
    assert check(repo, home, config)["status"] == "installed"
    assert "Keep this text." in instructions.read_text()
    assert instructions.read_text().count("@secure-coding-baseline.md") == 1
    ib.install("project", repo, home, config, offline=True, mode="complete", migrate=True)
    assert target.read_bytes() == original


def test_migration_rejects_edited_complete_baseline(locations, config):
    repo, home = locations
    ib.install("project", repo, home, config, offline=True, mode="complete")
    target = repo / config["install_filename"]
    target.write_text(target.read_text() + "\nExtra rules\n")
    before = target.read_bytes()
    with pytest.raises(ib.InstallError, match="modified"):
        ib.install("project", repo, home, config, offline=True, migrate=True)
    assert target.read_bytes() == before


def test_inherited_complete_baseline_prevents_second_modular_install(locations, config):
    repo, home = locations
    ib.install("user", repo, home, config, offline=True, mode="complete")
    with pytest.raises(ib.InstallError, match="another baseline"):
        ib.install("project", repo, home, config, offline=True)
    assert not list(repo.iterdir())


def test_modular_install_rejects_snapshot_and_backup_symlinks(locations, config, tmp_path):
    repo, home = locations
    outside = tmp_path / "outside"
    outside.mkdir()
    (repo / ".appsec-baseline").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ib.InstallError, match="symlink"):
        ib.install("project", repo, home, config, offline=True)
    assert not list(outside.iterdir())


def test_dependency_cycles_and_unsafe_paths_are_rejected(config):
    package, contents, _ = bm.from_bundle(bm.bundled(config))
    broken = copy.deepcopy(package)
    broken["modules"][0]["requires"] = [broken["modules"][0]["id"]]
    with pytest.raises(bm.ModularError, match="cyclic"):
        bm.validate(broken, contents)
    broken = copy.deepcopy(package)
    broken["files"]["../escape.md"] = broken["files"][package["core"]]
    with pytest.raises(bm.ModularError, match="unsafe"):
        bm.validate(broken, contents)


def test_offline_bundle_tampering_is_rejected(config, tmp_path):
    directory = tmp_path / "distribution"
    shutil.copytree(ROOT / config["bundle_dir"], directory)
    config["bundle_dir"] = str(directory)
    (directory / "install.py").write_text('print("never execute")')
    with pytest.raises(bm.ModularError, match="signed manifest"):
        bm.bundled(config)


@pytest.mark.parametrize("owner_scope", ["project", "user"])
def test_upstream_modular_owner_and_new_update_path(owner_scope, locations, config):
    repo, home = locations
    package, contents, raw = bm.from_bundle(bm.bundled(config))
    fingerprint = bm.digest(raw)
    base = repo if owner_scope == "project" else home
    carrier = repo / "CLAUDE.md" if owner_scope == "project" else home / ".claude/CLAUDE.md"
    carrier.parent.mkdir(parents=True, exist_ok=True)
    snapshot = base / ".aiscb/releases" / fingerprint
    snapshot.mkdir(parents=True)
    for name, data in {**contents, "policy.json": raw}.items():
        path = snapshot / name
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_bytes(data)
    import shlex

    command = shlex.join(["python3", str(snapshot / "policy_loader.py"), "--digest", fingerprint])
    block = bm.UPSTREAM_START + "\n" + contents[package["core"]].decode() + "\n"
    block += f"Installation mode: modular. Source: {snapshot}. Release: {package['release']}.\n"
    block += f"Load selected IDs with `{command} MODULE_ID [MODULE_ID ...]`.\n" + bm.UPSTREAM_END
    carrier.write_text("# Team rules\n" + block + "\n")
    (base / ".aiscb/installation.json").write_text(
        json.dumps(
            {
                "digest": fingerprint,
                "modular": True,
                "entries": {str(carrier) if owner_scope == "user" else "CLAUDE.md": bm.digest(block.encode())},
            }
        )
    )
    result = check(repo, home, config)
    assert result["status"] == "installed", result
    assert result["matches"][0]["managed_by"] == "aiscb"
    assert bc.aiscb_managed(carrier, home)
    updater = home / ".aiscb/install.py"
    updater.parent.mkdir(exist_ok=True)
    updater.write_text("# inert\n")
    assert str(updater) in bc.aiscb_update_command(home)
    original = carrier.read_bytes()
    steps, code = ub.update(repo, home, config, offline=True)
    assert code == 0 and any("aiscb installation" in step for step in steps)
    assert carrier.read_bytes() == original
    (snapshot / "policy_loader.py").unlink()
    assert check(repo, home, config)["status"] == "invalid"


def test_failed_update_preserves_adapter_and_snapshot(locations, config, monkeypatch):
    import baseline_release as br

    repo, home = locations
    ib.install("project", repo, home, config, offline=True)
    before = {str(path.relative_to(repo)): path.read_bytes() for path in repo.rglob("*") if path.is_file()}

    def refused(*args, **kwargs):
        raise br.ReleaseError("signature refused")

    monkeypatch.setattr(br, "fetch_latest", refused)
    with pytest.raises(ub.UpdateError, match="signature refused"):
        ub.update(repo, home, config)
    assert before == {str(path.relative_to(repo)): path.read_bytes() for path in repo.rglob("*") if path.is_file()}


def test_install_fallback_remains_modular(locations, config, monkeypatch):
    import baseline_release as br

    repo, home = locations

    def refused(*args, **kwargs):
        raise br.ReleaseError("signature refused")

    monkeypatch.setattr(br, "fetch_latest", refused)
    steps = ib.install("project", repo, home, config)
    assert any("signature refused" in step for step in steps)
    assert check(repo, home, config)["matches"][0]["mode"] == "modular"


def test_complete_source_never_accepts_a_modular_core(config):
    text = "`baseline-id: aiscb-0.1.17`\naiscb-MODULES-001\n"
    with pytest.raises(ib.InstallError, match="complete policy"):
        ib._validated(text, config["id"], "test source")


def test_missing_identity_cannot_be_masked_by_other_valid_copy(locations, config):
    repo, home = locations
    ib.install("project", repo, home, config, offline=True)
    target = repo / config["install_filename"]
    target.write_text(target.read_text().replace("baseline-id:", "removed-id:"))
    (home / ".claude").mkdir()
    (home / ".claude/CLAUDE.md").write_text("`baseline-id: aiscb-0.1.17`\nLegacy complete instructions\n")
    assert check(repo, home, config)["status"] == "invalid"


def test_refresh_cannot_downgrade_a_newer_modular_installation(locations, config):
    repo, home = locations
    ib.install("project", repo, home, config, offline=True)
    target = repo / config["install_filename"]
    package, contents, _ = bm.from_bundle(bm.bundled(config))
    package["release"] = "aiscb-0.1.18"
    core = package["core"]
    contents[core] = contents[core].replace(b"aiscb-0.1.17", b"aiscb-0.1.18")
    package["files"][core] = {"size": len(contents[core]), "sha256": bm.digest(contents[core])}
    raw = (json.dumps(package, indent=2) + "\n").encode()
    fingerprint = bm.digest(raw)
    snapshot = bm.storage(target, "project") / fingerprint
    snapshot.mkdir()
    for name, content in {**contents, "policy.json": raw}.items():
        path = snapshot / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    target.write_text(bm.render(target, "project", fingerprint, package, contents))
    assert check(repo, home, config)["status"] == "newer"
    before = target.read_bytes()
    with pytest.raises(ib.InstallError, match="older release"):
        ib.install("project", repo, home, config, offline=True, force=True)
    assert target.read_bytes() == before
    assert ub.update(repo, home, config, offline=True)[1] == 0
    assert target.read_bytes() == before


def test_nonregular_policy_file_is_rejected_without_opening(tmp_path):
    import os

    path = tmp_path / "policy.json"
    os.mkfifo(path)
    with pytest.raises(bm.ModularError, match="regular"):
        bm.read(path)


def test_bundled_modular_loader_has_no_implicit_command_permission(config):
    package, contents, raw = bm.from_bundle(bm.bundled(config))
    rendered = bm.render(
        Path("/workspace/project/secure-coding-baseline.md"), "project", bm.digest(raw), package, contents
    )
    assert "stop affected work if unavailable" in rendered
    assert "Bash(*)" not in rendered


def test_signed_modular_update_activates_new_snapshot_and_retains_old(locations, config, tmp_path, monkeypatch):
    import ast

    import baseline_release as br

    from tests.test_baseline_release import REPOSITORY, FakeGitHub, make_key, sign

    repo, home = locations
    ib.install("project", repo, home, config, offline=True)
    target = repo / config["install_filename"]
    before = target.read_bytes()
    old_snapshot = bm.storage(target, "project") / bm.metadata(before.decode())["digest"]
    old_bundle = bm.bundled(config)
    tree = ast.parse(old_bundle["install.py"])
    node = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "EMBEDDED_POLICY" for t in node.targets)
    )
    resources = json.loads(node.value.value)
    for name in resources:
        resources[name] = resources[name].replace("aiscb-0.1.17", "aiscb-0.1.18")
    catalog = json.loads(resources["baseline/catalog.json"])
    for entry in [catalog["core"], *catalog["modules"]]:
        raw = resources["baseline/" + entry["file"]].encode()
        entry["size"], entry["sha256"] = len(raw), bm.digest(raw)
    resources["baseline/catalog.json"] = json.dumps(catalog)
    installer = ("EMBEDDED_POLICY = " + repr(json.dumps(resources)) + "\n").encode()
    complete = old_bundle[br.BASELINE_FILE].replace(b"aiscb-0.1.17", b"aiscb-0.1.18")
    raw = json.dumps(
        {
            "schema": 1,
            "baseline_id": "aiscb-0.1.18",
            "files": {
                "scripts/install.py": {"size": len(installer), "sha256": bm.digest(installer)},
                br.BASELINE_FILE: {"size": len(complete), "sha256": bm.digest(complete)},
            },
        }
    ).encode()
    key, signer = make_key(tmp_path, "test-release")
    files = {
        br.MANIFEST_NAME: raw,
        br.SIGNATURE_NAME: sign(key, raw),
        "scripts/install.py": installer,
        br.BASELINE_FILE: complete,
    }
    github = FakeGitHub(files, tag="aiscb-0.1.18")
    config["release"] = {"repository": REPOSITORY, "allowed_signers": [signer]}
    original_fetch = br.fetch_latest
    monkeypatch.setattr(
        br,
        "fetch_latest",
        lambda release, minimum, **kwargs: original_fetch(release, minimum, fetch_json=github, **kwargs),
    )
    ub.update(repo, home, config, dry_run=True)
    assert target.read_bytes() == before
    assert len(list(bm.storage(target, "project").iterdir())) == 1
    steps, code = ub.update(repo, home, config)
    assert code == 0 and any("updated" in step for step in steps)
    assert check(repo, home, config)["status"] == "newer"
    assert target.with_suffix(".md.bak").read_bytes() == before
    assert old_snapshot.is_dir()
    assert len(list(bm.storage(target, "project").iterdir())) == 2


def test_modular_removal_rejects_instruction_backup_symlink(locations, config, tmp_path):
    repo, home = locations
    ib.install("project", repo, home, config, offline=True)
    outside = tmp_path / "private.md"
    outside.write_text("keep this unrelated file")
    (repo / "CLAUDE.md.bak").symlink_to(outside)
    before = (repo / "CLAUDE.md").read_bytes()
    with pytest.raises(rb.RemoveError, match="symlink"):
        rb.remove("project", repo, home, config)
    assert (repo / "CLAUDE.md").read_bytes() == before
    assert outside.read_text() == "keep this unrelated file"
