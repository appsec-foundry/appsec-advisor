"""Incremental STRIDE carry: admission, stash, per-component eligibility (IN-5, DP-2, DP-3)."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import baseline.carry_plan as carry_plan
import orchestrator.stride_dispatch_waves as stride_waves
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ANALYSIS_VERSION = 7
_GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=_GIT_ENV
    ).stdout


def _stride(component_id: str, evidence: str) -> dict:
    data = json.loads((ROOT / "tests/fixtures/valid_stride.json").read_text(encoding="utf-8"))
    data.update(component_id=component_id, component_name=component_id.title(), partial=False, skipped_categories=[])
    data["threats"][0]["evidence"] = {"file": evidence, "line": 1}
    return data


def _baseline(
    tmp_path: Path,
    components: dict[str, list[str]],
    *,
    output_in_repo: bool = False,
    depth: str = "standard",
    check_requirements: bool = False,
) -> tuple[Path, Path]:
    """A committed repository and the output of a finished run over it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    sources: dict[str, str] = {}
    for component_id, paths in components.items():
        root = paths[0].rstrip("/*")
        (repo / root).mkdir(parents=True)
        (repo / root / "app.py").write_text("def handle(value):\n    total = value + 1\n    return total\n")
        (repo / root / "README.md").write_text("# component\n")
        (repo / root / "package.json").write_text('{"name": "c", "dependencies": {"a": "1.0.0"}}\n')
        (repo / root / "tests").mkdir()
        (repo / root / "tests" / "test_app.py").write_text("def test_x():\n    assert True\n")
        sources[component_id] = f"{root}/app.py"
    output = repo / "docs" / "security" if output_in_repo else tmp_path / "out"
    output.mkdir(parents=True)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "baseline")
    sha = _git(repo, "rev-parse", "HEAD").strip()
    model = {
        "meta": {
            "assessment_depth": depth,
            "analysis_version": ANALYSIS_VERSION,
            "check_requirements": check_requirements,
            "git": {"commit_sha": sha, "branch": "main"},
        },
        "components": [{"id": cid, "name": cid, "paths": paths} for cid, paths in components.items()],
        "threats": [],
    }
    (output / "threat-model.yaml").write_text(yaml.safe_dump(model), encoding="utf-8")
    (output / ".skill-config.json").write_text(json.dumps({"repo_root": str(repo)}), encoding="utf-8")
    recorded = {}
    for component_id in components:
        path = output / f".stride-{component_id}.json"
        path.write_text(json.dumps(_stride(component_id, sources[component_id]), indent=2), encoding="utf-8")
        recorded[component_id] = {
            "path": path.name,
            "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    (output / ".appsec-cache").mkdir()
    (output / ".appsec-cache" / "baseline.json").write_text(json.dumps({"stride_files": recorded}), encoding="utf-8")
    return repo, output


def _manifest(components: dict[str, list[str]]) -> dict:
    return {
        "generated_at": "2026-10-11T00:00:00Z",
        "components": [{"component_id": cid, "component_paths": paths} for cid, paths in components.items()],
    }


def _carry(repo: Path, output: Path, components: dict[str, list[str]], **kwargs) -> dict:
    """Run the prepare-time stash, the full cleanup's STRIDE removal, then the plan."""
    carry_plan.stash(output)
    for leftover in output.glob(".stride-*.json"):
        leftover.unlink()
    return carry_plan.plan(output, repo, _manifest(components), check_requirements=False, **kwargs)


def _reasons(result: dict) -> dict[str, str]:
    return {row["component_id"]: row["reason"] for row in result["reanalyzed"]}


TWO = {"svc-a": ["svc-a/"], "svc-b": ["svc-b/**"]}
VARIANT = {"billing-core": ["src/billing/"], "ledger-worker": ["workers/ledger/**"]}


@pytest.mark.parametrize(
    ("components", "changed", "carried"),
    [(TWO, "svc-a", "svc-b"), (VARIANT, "billing-core", "ledger-worker")],
)
def test_incremental_carries_only_unchanged_components(tmp_path, components, changed, carried):
    repo, output = _baseline(tmp_path, components)
    carried_bytes = (output / f".stride-{carried}.json").read_bytes()
    changed_root = components[changed][0].rstrip("/*")
    # A keyword-free logic change still counts: the analysis read this code.
    (repo / changed_root / "app.py").write_text("def handle(value):\n    total = value + 2\n    return total\n")

    result = _carry(repo, output, components)

    assert result["carried"] == [carried]
    assert _reasons(result) == {changed: "files_changed"}
    assert (output / f".stride-{carried}.json").read_bytes() == carried_bytes
    assert not (output / f".stride-{changed}.json").exists()
    assert not (output / carry_plan.CARRY_DIR).exists()
    on_disk = json.loads((output / carry_plan.PLAN_ARTIFACT).read_text(encoding="utf-8"))
    assert on_disk == result

    # The wave plan treats the carried output as complete and leaves it untouched.
    manifest = _manifest(components)
    status = stride_waves.status(stride_waves.build_plan(manifest, 5), manifest, output)
    assert [row["component_id"] for row in status["incomplete"]] == [changed]
    assert [c["component_id"] for c in status["next_wave"]["components"]] == [changed]
    assert (output / f".stride-{carried}.json").read_bytes() == carried_bytes


def test_all_unchanged_components_carry_and_no_wave_is_pending(tmp_path):
    repo, output = _baseline(tmp_path, TWO, output_in_repo=True)
    # The plugin's own output directory is not repository source.
    (output / "threat-model.md").write_text("report", encoding="utf-8")

    result = _carry(repo, output, TWO)

    assert result["carried"] == ["svc-a", "svc-b"] and result["reanalyzed"] == []
    manifest = _manifest(TWO)
    assert stride_waves.status(stride_waves.build_plan(manifest, 5), manifest, output)["status"] == "complete"


@pytest.mark.parametrize(
    "edit",
    [
        lambda repo: (repo / "svc-b" / "README.md").write_text("# component\n\nMore prose.\n"),
        lambda repo: (repo / "svc-b" / "tests" / "test_app.py").write_text("def test_y():\n    assert 1\n"),
        lambda repo: (repo / "svc-b" / "package.json").write_text(
            '{\n  "name": "c",\n  "dependencies": {"a": "1.0.0"}\n}\n'
        ),
    ],
    ids=["documentation", "test", "whitespace-only-manifest"],
)
def test_irrelevant_path_classes_do_not_invalidate_a_carry(tmp_path, edit):
    repo, output = _baseline(tmp_path, TWO)
    edit(repo)

    result = _carry(repo, output, TWO)

    assert "svc-b" in result["carried"]


@pytest.mark.parametrize(
    "edit",
    [
        lambda repo: (repo / "svc-b" / "app.py").write_text("def handle(value):\n    return value\n"),
        lambda repo: (repo / "svc-b" / "app.py").unlink(),
        lambda repo: (repo / "svc-b" / "helper.py").write_text("def double(value):\n    return value * 2\n"),
        lambda repo: (repo / "svc-b" / "README.md").unlink(),
        lambda repo: (repo / "svc-b" / "package.json").write_text('{"name": "c", "dependencies": {"a": "2.0.0"}}\n'),
    ],
    ids=["deletion-only-diff", "deleted-source", "untracked-source", "deleted-document", "major-dependency-bump"],
)
def test_source_deletions_and_new_files_force_reanalysis(tmp_path, edit):
    repo, output = _baseline(tmp_path, TWO)
    edit(repo)

    result = _carry(repo, output, TWO)

    assert _reasons(result) == {"svc-b": "files_changed"}
    assert result["carried"] == ["svc-a"]


def test_a_committed_change_since_the_baseline_counts(tmp_path):
    repo, output = _baseline(tmp_path, TWO)
    (repo / "svc-b" / "app.py").write_text("def handle(value):\n    return -value\n")
    _git(repo, "commit", "-q", "-am", "change")

    assert _reasons(_carry(repo, output, TWO)) == {"svc-b": "files_changed"}


def test_changed_paths_new_components_and_unverified_outputs_are_reanalyzed(tmp_path):
    repo, output = _baseline(tmp_path, TWO)
    stride_b = output / ".stride-svc-b.json"
    stride_b.write_text(stride_b.read_text(encoding="utf-8") + " ", encoding="utf-8")
    components = {"svc-a": ["svc-a/", "shared/"], "svc-b": ["svc-b/**"], "svc-c": ["svc-c/"]}

    result = _carry(repo, output, components)

    assert result["carried"] == []
    assert _reasons(result) == {"svc-a": "paths_changed", "svc-b": "no_prior_output", "svc-c": "new_component"}


def test_a_carried_file_that_needs_repair_is_reanalyzed_not_rewritten(tmp_path):
    repo, output = _baseline(tmp_path, TWO)
    path = output / ".stride-svc-b.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["threats"][0]["scenario"]
    path.write_text(json.dumps(data), encoding="utf-8")
    baseline = json.loads((output / ".appsec-cache/baseline.json").read_text(encoding="utf-8"))
    baseline["stride_files"]["svc-b"]["sha256"] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    (output / ".appsec-cache/baseline.json").write_text(json.dumps(baseline), encoding="utf-8")

    result = _carry(repo, output, TWO)

    assert _reasons(result) == {"svc-b": "contract_rejected"}
    assert not path.exists()


def test_a_changed_requirements_catalog_reanalyzes_every_component(tmp_path):
    repo, output = _baseline(tmp_path, TWO, check_requirements=True)
    model = yaml.safe_load((output / "threat-model.yaml").read_text(encoding="utf-8"))
    model["requirements_provenance"] = {"catalog_sha256": hashlib.sha256(b"old catalog").hexdigest()}
    (output / "threat-model.yaml").write_text(yaml.safe_dump(model), encoding="utf-8")
    (output / ".requirements.yaml").write_text("new catalog", encoding="utf-8")
    carry_plan.stash(output)

    result = carry_plan.plan(output, repo, _manifest(TWO), check_requirements=True)

    assert result["carried"] == []
    assert set(_reasons(result).values()) == {"requirements_changed"}


def _admission(repo: Path, output: Path, **overrides) -> str | None:
    values = {"depth": "standard", "check_requirements": False, "analysis_version": ANALYSIS_VERSION, **overrides}
    return carry_plan.admission_refusal(output, repo, **values)


def test_admission_accepts_a_verified_single_repository_baseline(tmp_path):
    repo, output = _baseline(tmp_path, TWO)
    before = sorted(p.name for p in output.iterdir())
    assert _admission(repo, output) is None
    assert sorted(p.name for p in output.iterdir()) == before


@pytest.mark.parametrize(
    ("mutate", "overrides", "expected"),
    [
        (lambda repo, out: (out / ".appsec-cache/baseline.json").unlink(), {}, "baseline.json"),
        (lambda repo, out: [p.unlink() for p in out.glob(".stride-*.json")], {}, "recorded hash"),
        (lambda repo, out: None, {"depth": "quick"}, "shallower"),
        (lambda repo, out: None, {"depth": "thorough"}, "deeper"),
        (lambda repo, out: None, {"check_requirements": True}, "switched on"),
        (lambda repo, out: None, {"analysis_version": ANALYSIS_VERSION + 1}, "analysis version"),
        (lambda repo, out: subprocess.run(["rm", "-rf", str(repo / ".git")], check=True), {}, "git"),
    ],
    ids=["no-cache", "no-stride-files", "shallower", "deeper", "requirements", "analysis-version", "not-git"],
)
def test_admission_names_the_condition_that_blocks_a_carry(tmp_path, mutate, overrides, expected):
    repo, output = _baseline(tmp_path, TWO)
    mutate(repo, output)
    refusal = _admission(repo, output, **overrides)
    assert refusal and expected in refusal


def test_a_stash_from_an_interrupted_run_is_discarded(tmp_path):
    _repo, output = _baseline(tmp_path, TWO)
    carry_plan.stash(output)
    assert (output / carry_plan.CARRY_DIR / ".stride-svc-a.json").is_file()
    carry_plan.discard(output)
    assert not (output / carry_plan.CARRY_DIR).exists()
