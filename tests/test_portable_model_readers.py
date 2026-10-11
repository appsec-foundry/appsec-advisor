"""Follow-on tools read a multi-repository model through its inventory or refuse it.

A version-2 model keeps every location relative to a repository of its source
inventory. Display tools name such a location as ``<label>:<file>``; tools that
would act on one checkout fail before writing anything.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
from contexts.build_analyst_context import ContextError, _threat_model  # noqa: E402
from model.build_threat_model_yaml import build_assessment_model  # noqa: E402
from runtime.multi_repo_scope import AssessmentScope, RepositoryView  # noqa: E402
from runtime.resolve_config import resolve_assessment  # noqa: E402

from tests.test_multi_repo_builder import inputs  # noqa: E402

REFUSAL = "covers several repositories"


@pytest.fixture(scope="module")
def model(tmp_path_factory):
    scope, kwargs = inputs(tmp_path_factory.mktemp("combined"))
    document, _ = build_assessment_model(scope, **kwargs)
    assert sorted(row["label"] for row in document["source_inventory"]["repositories"]) == ["edge", "service"]
    return document


@pytest.fixture
def output(tmp_path, model):
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.yaml").write_text(yaml.safe_dump(model, sort_keys=False), encoding="utf-8")
    (out / "threat-model.md").write_text("# Combined system\n", encoding="utf-8")
    return out


def run(script: str, *args) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script), *map(str, args)], capture_output=True, text=True, timeout=120
    )


def tree(path: Path) -> list[str]:
    return sorted(p.relative_to(path).as_posix() for p in path.rglob("*"))


def test_query_names_each_location_by_its_repository_label(output):
    listing = run("model/query_threat_model.py", "--output-dir", output)
    assert listing.returncode == 0, listing.stderr
    assert "@ edge:app.py:1" in listing.stdout and "@ service:app.py:1" in listing.stdout
    detail = run("model/query_threat_model.py", "--output-dir", output, "--id", "F-001")
    assert detail.returncode == 0 and re.search(r"Location: (edge|service):app\.py:1", detail.stdout)


@pytest.mark.parametrize("script", ["model/query_threat_model.py", "renderers/summarize_threat_model.py"])
def test_display_tools_render_the_model_and_reject_a_tampered_inventory(output, model, script):
    assert run(script, "--output-dir", output).returncode == 0
    tampered = json.loads(json.dumps(model))
    tampered["source_inventory"]["repositories"][0]["label"] = "other"
    (output / "threat-model.yaml").write_text(yaml.safe_dump(tampered, sort_keys=False), encoding="utf-8")
    result = run(script, "--output-dir", output)
    assert result.returncode == 2 and "fingerprint" in result.stderr


def test_pentest_tasks_name_label_locations(output, tmp_path):
    path = output / "threat-model.yaml"
    path.write_text(re.sub(r"\bCWE-20\b", "CWE-78", path.read_text(encoding="utf-8")), encoding="utf-8")
    target = tmp_path / "pentest-tasks.yaml"
    result = run("renderers/render_pentest_tasks.py", "--threat-model", path, "--output", target)
    assert result.returncode == 0, result.stderr
    tasks = target.read_text(encoding="utf-8")
    assert "file: edge:app.py" in tasks and "file: service:app.py" in tasks


def test_eval_brief_uses_labels_and_refuses_a_single_checkout(output, tmp_path):
    refused = run(
        "validators/eval_threat_model.py", "prepare", "--run-dir", output, "--out", tmp_path / "a", "--repo", tmp_path
    )
    assert refused.returncode == 2 and REFUSAL in refused.stderr and not (tmp_path / "a").exists()
    prepared = run("validators/eval_threat_model.py", "prepare", "--run-dir", output, "--out", tmp_path / "b")
    assert prepared.returncode == 0, prepared.stderr
    brief = (tmp_path / "b" / "brief.json").read_text(encoding="utf-8")
    assert '"edge:app.py"' in brief and '"service:app.py"' in brief


@pytest.mark.parametrize(
    "command, target",
    [("console", None), ("render", "--plan"), ("promote-accepted", "--known-threats")],
)
def test_review_refuses_before_writing(output, tmp_path, command, target):
    args = [command, "--output-dir", output, "--triage", tmp_path / "triage.yaml"]
    if target:
        args += [target, tmp_path / "written.md"]
    result = run("validators/review_threat_model.py", *args)
    assert result.returncode == 2 and REFUSAL in result.stderr and "ask-threat-model" in result.stderr
    assert not (tmp_path / "written.md").exists() and not (tmp_path / "triage.yaml").exists()


def test_publish_is_blocked_without_touching_the_repository(output, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    before = tree(output)
    result = run("model/publish_threat_model.py", "--output-dir", output, "--repo-root", repo, "--commit", "--json")
    assert result.returncode == 1
    assert any(REFUSAL in blocker for blocker in json.loads(result.stdout)["blockers"])
    assert tree(repo) == [] and tree(output) == before


@pytest.mark.parametrize(
    "command, code", [("check-changes", 3), ("dirty-set", 4), ("update", 1), ("check-fingerprint", 2)]
)
def test_change_detection_refuses_the_model(output, tmp_path, command, code):
    args = [command, "--output-dir", output]
    args += ["--no-stdin", "--files", "app.py"] if command == "dirty-set" else ["--repo-root", tmp_path]
    before = tree(output)
    result = run("baseline/baseline_state.py", *args)
    assert result.returncode == code
    assert json.loads(result.stdout)["status"] == "unsupported" and REFUSAL in result.stderr
    assert tree(output) == before


def test_health_and_status_report_the_refusal_as_their_freshness(output, tmp_path):
    health = run("model/threat_model_health.py", "--repo-root", tmp_path, "--output-dir", output, "--json")
    freshness = json.loads(health.stdout)["freshness"]
    assert freshness["verdict"] == "UNKNOWN" and REFUSAL in freshness["reason"]
    status = run("runtime/appsec_status.py", "--repo", tmp_path, "--output", output)
    assert status.returncode == 0 and re.search(r"Decision\s+This threat model " + REFUSAL, status.stdout)


@pytest.mark.parametrize("mode", ["--full", "--rerender", "--rebuild"])
def test_single_repository_run_refuses_the_output_directory(output, tmp_path, mode):
    repo = tmp_path / "repo"
    repo.mkdir()
    before = tree(output)
    result = run("runtime/resolve_config.py", "--repo", repo, "--output", output, mode)
    assert result.returncode != 0 and f"{output / 'threat-model.yaml'} {REFUSAL}" in result.stderr
    assert tree(output) == before


def test_combined_resolution_still_replaces_its_own_prior_model(output, model):
    views = tuple(
        RepositoryView(row["repository_id"], output.parent / row["label"], "a" * 40, "b" * 64, {"app.py": b"x\n"})
        for row in model["source_inventory"]["repositories"]
    )
    resolved = resolve_assessment(AssessmentScope(views, output), ["--no-requirements"], ROOT)
    assert resolved["mode"] == "full" and resolved["assessment_scope"] == "multiple-repositories"


def test_analyst_refuses_the_model_as_context(output):
    with pytest.raises(ContextError, match=f"{REFUSAL}.*--isolated") as caught:
        _threat_model(output / "threat-model.yaml", False)
    assert caught.value.required
