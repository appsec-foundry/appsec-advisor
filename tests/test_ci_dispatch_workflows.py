"""Drift guards for the dispatched CI workflows.

Two invariants live here, both of which used to be enforced only by whoever
happened to read the YAML:

1. Auth preflight. Both dispatch workflows authenticate via the
   CLAUDE_CODE_OAUTH_TOKEN secret and both consume it deep into the run — after
   a target checkout, an npm install and the permission setup. Without an
   up-front check a missing secret surfaces as an auth error from inside
   run-headless.sh, minutes and one wasted matrix fan-out later.

2. One question per dimension. A threat-model preset key IS `<target>-<depth>`,
   so the two dropdowns fully determine it. The workflow previously also offered
   an `override_depth`, which changed `depth` alone while output_path, budget and
   reasoning model stayed on the preset's — producing a "thorough" run with a
   quick run's budget, written over the quick run's output. Presets are applied
   whole; these tests pin that the override cannot come back and that the
   dropdowns and presets.json stay a bijection.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

DISPATCH_WORKFLOWS = [
    "fixture-e2e-dispatch.yml",
    "threat-model-dispatch.yml",
    "repair-agent.yml",
]

TOKEN = "CLAUDE_CODE_OAUTH_TOKEN"


def _load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text())


def _steps(job: dict) -> list[dict]:
    return job.get("steps") or []


def _is_preflight(step: dict) -> bool:
    """A step that hard-fails on an empty token, not merely one that names it."""
    run = step.get("run") or ""
    return TOKEN in (step.get("env") or {}) and f'-z "${{{TOKEN}:-}}"' in run and "exit 1" in run


def _consumes_token(step: dict) -> bool:
    return TOKEN in (step.get("env") or {}) and not _is_preflight(step)


def _job_and_ancestors(jobs: dict, job_id: str) -> set[str]:
    """Job plus everything it transitively `needs` — a preflight upstream counts."""
    seen: set[str] = set()
    stack = [job_id]
    while stack:
        current = stack.pop()
        if current in seen or current not in jobs:
            continue
        seen.add(current)
        needs = jobs[current].get("needs") or []
        stack.extend([needs] if isinstance(needs, str) else needs)
    return seen


@pytest.mark.parametrize("name", DISPATCH_WORKFLOWS)
def test_token_consumer_is_gated_by_an_auth_preflight(name):
    """No step may reach the token without a preflight having run first."""
    jobs = _load(name)["jobs"]

    consumers = [
        (job_id, step.get("name", "<unnamed>"))
        for job_id, job in jobs.items()
        for step in _steps(job)
        if _consumes_token(step)
    ]
    assert consumers, f"{name}: expected at least one {TOKEN} consumer"

    for job_id, step_name in consumers:
        reachable = _job_and_ancestors(jobs, job_id)
        assert any(_is_preflight(step) for jid in reachable for step in _steps(jobs[jid])), (
            f"{name}: step '{step_name}' in job '{job_id}' uses {TOKEN} but neither "
            f"that job nor any job it needs runs an auth preflight"
        )


@pytest.mark.parametrize("name", DISPATCH_WORKFLOWS)
def test_preflight_precedes_the_consumer_within_a_job(name):
    """A preflight after the consumer would gate nothing."""
    for job_id, job in _load(name)["jobs"].items():
        steps = _steps(job)
        preflights = [i for i, s in enumerate(steps) if _is_preflight(s)]
        consumers = [i for i, s in enumerate(steps) if _consumes_token(s)]
        if preflights and consumers:
            assert min(preflights) < min(consumers), (
                f"{name}: job '{job_id}' runs its auth preflight after the step that consumes {TOKEN}"
            )


def test_sarif_upload_does_not_run_on_a_failed_scan():
    """always() made every failure emit a second, misleading 'Path does not exist'."""
    steps = _steps(_load("threat-model-dispatch.yml")["jobs"]["threat-model"])
    sarif = [s for s in steps if "SARIF" in (s.get("name") or "")]
    assert len(sarif) == 1, "expected exactly one SARIF upload step"
    condition = str(sarif[0].get("if", ""))
    assert "success()" in condition, "SARIF upload must be gated on a green scan"
    assert "always()" not in condition


def _dispatch_inputs(name: str) -> dict:
    trigger = _load(name).get("on") or _load(name)[True]  # PyYAML maps `on:` to True
    return trigger["workflow_dispatch"]["inputs"]


def test_preset_dropdowns_are_a_bijection_with_presets_json():
    """The resolve step composes '<target>-<depth>'; every product must exist."""
    presets = json.loads((REPO_ROOT / ".github" / "threat-model-presets.json").read_text())
    keys = {k for k in presets if not k.startswith("_")}

    inputs = _dispatch_inputs("threat-model-dispatch.yml")
    offered = {f"{t}-{d}" for t in inputs["target"]["options"] for d in inputs["depth"]["options"]}

    assert offered == keys, (
        f"target x depth and threat-model-presets.json disagree — "
        f"missing presets: {sorted(offered - keys)}, unoffered presets: {sorted(keys - offered)}"
    )


def test_preset_key_suffix_matches_the_declared_depth():
    """Deriving the key from `depth` is only sound while the naming holds."""
    presets = json.loads((REPO_ROOT / ".github" / "threat-model-presets.json").read_text())
    for key, preset in presets.items():
        if key.startswith("_"):
            continue
        assert key.rsplit("-", 1)[1] == preset["assessment_depth"], (
            f"preset '{key}' declares assessment_depth "
            f"'{preset['assessment_depth']}' — the key suffix must match, or "
            f"selecting a depth would silently resolve to another one"
        )


@pytest.mark.parametrize("name", ["fixture-e2e-dispatch.yml", "threat-model-dispatch.yml"])
def test_no_redundant_dispatch_inputs(name):
    """Every input must be a question the run cannot answer for itself."""
    inputs = _dispatch_inputs(name)

    # plugin_ref duplicated GitHub's own "Use workflow from" branch selector.
    assert "plugin_ref" not in inputs, (
        "the branch to run is the workflow_dispatch ref; a plugin_ref input lets the two disagree"
    )
    # An override of a preset field re-asks a question the preset answered.
    overrides = [k for k in inputs if k.startswith("override_")]
    assert not overrides, f"{name}: presets are applied whole, but found {overrides}"


def test_repair_skips_cleanly_when_the_run_published_no_artifacts():
    """A run that died before writing evidence has nothing to triage."""
    steps = _steps(_load("repair-agent.yml")["jobs"]["repair"])
    by_name = {s.get("name"): s for s in steps}

    download = by_name["Download artifacts"]
    assert download.get("id") == "artifacts"
    run = download["run"]
    assert "found=true" in run and "found=false" in run, (
        "download step must report whether artifacts were found instead of hard-failing the job"
    )

    triage = by_name["Triage failures"]
    assert "steps.artifacts.outputs.found == 'true'" in str(triage.get("if", "")), (
        "triage must be skipped when no artifact matched"
    )
