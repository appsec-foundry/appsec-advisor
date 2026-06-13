"""Unit tests for scripts/detect_public_repo.py — conservative public-repo
detection that gates the repo-read → internet-anon actor collapse."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "detect_public_repo.py"


def _load():
    spec = importlib.util.spec_from_file_location("detect_public_repo", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dpr = _load()

_MIT = "MIT License\n\nPermission is hereby granted, free of charge, to any person..."


def _repo(tmp: Path, *, license_text: str | None, pkg: dict | None) -> Path:
    repo = tmp / "repo"
    repo.mkdir()
    if license_text is not None:
        (repo / "LICENSE").write_text(license_text, encoding="utf-8")
    if pkg is not None:
        (repo / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    return repo


def test_osi_license_plus_public_url_is_public(tmp_path: Path):
    repo = _repo(tmp_path, license_text=_MIT, pkg={"repository": {"url": "git+https://github.com/acme/app.git"}})
    verdict, _ = dpr.detect(repo)
    assert verdict is True


def test_private_npm_flag_does_not_block_public(tmp_path: Path):
    # juice-shop case: "private": true is the npm-publish flag, not repo visibility.
    repo = _repo(
        tmp_path,
        license_text=_MIT,
        pkg={
            "private": True,
            "license": "MIT",
            "repository": {"url": "git+https://github.com/juice-shop/juice-shop.git"},
        },
    )
    verdict, reason = dpr.detect(repo)
    assert verdict is True, reason


def test_license_without_public_url_is_unset(tmp_path: Path):
    repo = _repo(tmp_path, license_text=_MIT, pkg={"name": "app"})
    verdict, _ = dpr.detect(repo)
    assert verdict is None  # not confident → keep Internal Developer


def test_public_url_without_license_is_unset(tmp_path: Path):
    repo = _repo(tmp_path, license_text=None, pkg={"repository": "https://github.com/acme/app"})
    verdict, _ = dpr.detect(repo)
    assert verdict is None


def test_missing_and_invalid_package_json_are_ignored(tmp_path: Path):
    repo = _repo(tmp_path, license_text=_MIT, pkg=None)
    assert dpr._package_json(repo) == {}

    (repo / "package.json").write_text("{not-json", encoding="utf-8")
    assert dpr._package_json(repo) == {}


def test_license_read_errors_are_ignored(tmp_path: Path, monkeypatch):
    repo = _repo(tmp_path, license_text=_MIT, pkg=None)
    original_read_text = Path.read_text

    def boom_for_license(path, *args, **kwargs):
        if path.name == "LICENSE":
            raise OSError("permission denied")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", boom_for_license)

    assert dpr._has_osi_license(repo) is False


def test_git_remote_errors_are_non_public(tmp_path: Path, monkeypatch):
    repo = _repo(tmp_path, license_text=_MIT, pkg=None)

    def boom(*_args, **_kwargs):
        raise OSError("git unavailable")

    monkeypatch.setattr(dpr.subprocess, "run", boom)

    assert dpr._git_remote_public(repo) is False


def test_git_remote_public_url_can_supply_source_signal(tmp_path: Path, monkeypatch):
    repo = _repo(tmp_path, license_text=_MIT, pkg={"name": "app"})

    class Result:
        stdout = "remote.origin.url https://gitlab.com/acme/app.git\n"

    monkeypatch.setattr(dpr.subprocess, "run", lambda *_args, **_kwargs: Result())

    verdict, reason = dpr.detect(repo)
    assert verdict is True, reason


def test_main_writes_meta_and_pin_override(tmp_path: Path):
    repo = _repo(tmp_path, license_text=_MIT, pkg={"repository": "https://github.com/acme/app"})
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.yaml").write_text(yaml.safe_dump({"meta": {}, "threats": []}))
    assert dpr.main([str(out), "--repo-root", str(repo)]) == 0
    data = yaml.safe_load((out / "threat-model.yaml").read_text())
    assert data["meta"]["public_source_repo"] is True

    # Operator pin wins and is honoured even with public signals present.
    data["meta"]["public_source_repo_pinned"] = False
    (out / "threat-model.yaml").write_text(yaml.safe_dump(data))
    dpr.main([str(out), "--repo-root", str(repo)])
    data = yaml.safe_load((out / "threat-model.yaml").read_text())
    assert data["meta"]["public_source_repo"] is False


def test_main_missing_yaml_is_best_effort_noop(tmp_path: Path, capsys):
    repo = _repo(tmp_path, license_text=_MIT, pkg={"repository": "https://github.com/acme/app"})
    out = tmp_path / "out"
    out.mkdir()

    assert dpr.main([str(out), "--repo-root", str(repo)]) == 0

    assert "no threat-model.yaml" in capsys.readouterr().err


def test_main_unsets_stale_flag_when_public_evidence_is_insufficient(tmp_path: Path, capsys):
    repo = _repo(tmp_path, license_text=None, pkg={"name": "app"})
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.yaml").write_text(
        yaml.safe_dump({"meta": {"public_source_repo": True}, "threats": []}),
        encoding="utf-8",
    )

    assert dpr.main([str(out), "--repo-root", str(repo)]) == 0

    data = yaml.safe_load((out / "threat-model.yaml").read_text(encoding="utf-8"))
    assert "public_source_repo" not in data["meta"]
    assert "UNSET" in capsys.readouterr().err


def test_main_repairs_non_dict_meta(tmp_path: Path):
    repo = _repo(tmp_path, license_text=_MIT, pkg={"repository": "https://github.com/acme/app"})
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.yaml").write_text(yaml.safe_dump({"meta": "not-a-dict"}), encoding="utf-8")

    assert dpr.main([str(out), "--repo-root", str(repo)]) == 0

    data = yaml.safe_load((out / "threat-model.yaml").read_text(encoding="utf-8"))
    assert data["meta"]["public_source_repo"] is True
