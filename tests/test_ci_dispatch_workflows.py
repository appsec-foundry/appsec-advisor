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
import re
import subprocess
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
    """A step that hard-fails on an unusable token, not merely one that names it.

    Structural locator only — whether it actually rejects the right things is
    covered by executing it (see test_preflight_rejects_credentials_that_cannot
    _work). It must read the token through the safe expansion and be able to
    exit non-zero; the value may be tested directly or via a local.
    """
    run = step.get("run") or ""
    return TOKEN in (step.get("env") or {}) and f'"${{{TOKEN}:-}}"' in run and "-z " in run and "exit 1" in run


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


def test_the_preselected_fixture_is_not_the_full_fan_out():
    """The default dispatch must not be the expensive one.

    `all` fans out ~9 full scans. It was both the declared default and the
    first option, so a dispatch whose dropdown was never touched — or whose
    selection failed to register — spent nine scans' worth of subscription
    budget without anyone choosing that. GitHub preselects the first option
    when no `default:` is given, so the invariant is positional.
    """
    fixture = _dispatch_inputs("fixture-e2e-dispatch.yml")["fixture"]
    options = fixture["options"]

    assert "all" in options, "the fan-out option must still be reachable"
    preselected = fixture.get("default", options[0])
    assert preselected != "all", (
        f"'{preselected}' is preselected — `all` must be chosen deliberately, never inherited from an untouched form"
    )


def _preflight_script(workflow: str, job: str) -> str:
    step = next(s for s in _load(workflow)["jobs"][job]["steps"] if s.get("name", "").startswith("Preflight"))
    return step["run"].replace("${{ github.repository }}", "OWNER/REPO")


def _step_script(workflow: str, step_name_prefix: str) -> str:
    """First step across any job whose name starts with the given prefix.

    Unlike `_preflight_script`, the job isn't known up front here — callers
    only care about a step name that is unique within the workflow.
    """
    for job in _load(workflow)["jobs"].values():
        for step in _steps(job):
            if step.get("name", "").startswith(step_name_prefix):
                return step["run"]
    raise AssertionError(f"no step named like {step_name_prefix!r} in {workflow}")


def _run_preflight(tmp_path: Path, workflow: str, job: str, token: str):
    script = tmp_path / "preflight.sh"
    script.write_text(_preflight_script(workflow, job))
    return subprocess.run(
        ["bash", str(script)],
        env={"PATH": "/usr/bin:/bin", "CLAUDE_CODE_OAUTH_TOKEN": token},
        capture_output=True,
        text=True,
    )


PREFLIGHTS = [
    ("threat-model-dispatch.yml", "threat-model"),
    ("fixture-e2e-dispatch.yml", "resolve"),
    ("repair-agent.yml", "repair"),
]

# A real sk-ant-oat token is much longer; this only has to clear the length floor.
VALID_OAUTH = "sk-ant-oat01-" + "A" * 44

BAD_TOKENS = [
    pytest.param("", "is not set", id="empty"),
    # What was actually in the secret on 2026-07-19: a random string that is not
    # an Anthropic credential at all. It reached the CLI and came back 401.
    pytest.param("ScU7fkQ2x9LmPq4vRt8wYz1aBcDeFgHiJkLmNoPqRsTuVwXy", "unrecognised", id="random"),
    pytest.param("sk-ant-api03-" + "A" * 44, "api-key", id="api-key-not-oauth"),
    pytest.param("sk-ant-oat01-short", "looks truncated", id="truncated-paste"),
]


@pytest.mark.parametrize("workflow,job", PREFLIGHTS)
@pytest.mark.parametrize("token,expected", BAD_TOKENS)
def test_preflight_rejects_credentials_that_cannot_work(tmp_path, workflow, job, token, expected):
    """Every rejection must name the actual problem, not just fail.

    Subscription billing needs the `claude setup-token` OAuth token
    (sk-ant-oat...). The secret box accepts anything, so without this the
    mistake surfaces as a bare 401 from deep inside the pipeline.
    """
    result = _run_preflight(tmp_path, workflow, job, token)
    assert result.returncode == 1, result.stdout
    assert expected in result.stdout


@pytest.mark.parametrize("workflow,job", PREFLIGHTS)
def test_preflight_accepts_a_subscription_oauth_token(tmp_path, workflow, job):
    result = _run_preflight(tmp_path, workflow, job, VALID_OAUTH)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("workflow,job", PREFLIGHTS)
@pytest.mark.parametrize(
    "wrapped",
    ["\n" + VALID_OAUTH, VALID_OAUTH + "\n", " " + VALID_OAUTH, " " + VALID_OAUTH + " "],
    ids=["leading-newline", "trailing-newline", "leading-space", "both"],
)
def test_preflight_trims_whitespace_and_says_so(tmp_path, workflow, job, wrapped):
    """A copy-paste newline must not read as a malformed credential.

    `gh secret set < file` and terminal copy-paste both pick up a newline. The
    token is fine; only the stored bytes are wrong. Rejecting it as
    'unrecognised' sends the user off to regenerate a token that was never the
    problem — so trim, continue, and name what was trimmed.
    """
    result = _run_preflight(tmp_path, workflow, job, wrapped)
    assert result.returncode == 0, result.stdout
    assert "contained whitespace" in result.stdout


def test_every_token_consumer_trims_whitespace_before_use():
    """The preflight's trim buys nothing if the actual consumers don't repeat it.

    Each consuming step's `env:` block reads `secrets.CLAUDE_CODE_OAUTH_TOKEN`
    directly — the raw, un-trimmed value — independent of whatever the
    preflight step computed in its own shell. For a consumer in a different
    job (fixture-e2e-dispatch.yml's matrix job, which only `needs: resolve`)
    there is no shared shell at all: a `$GITHUB_ENV` export from the preflight
    job would not even cross the job boundary. So a token with a copy-pasted
    leading/trailing newline — exactly what 9b51762 was written to handle —
    passed a preflight that now trims and warns instead of failing, and then
    reached `claude` untrimmed one step later, where it was rejected. Every
    consumer must repeat the trim right where it uses the token.
    """
    offenders = []
    for name in DISPATCH_WORKFLOWS:
        jobs = _load(name)["jobs"]
        for job_id, job in jobs.items():
            for step in _steps(job):
                if not _consumes_token(step):
                    continue
                run = step.get("run") or ""
                if not re.search(rf"{TOKEN}=.*tr -d '\[:space:\]'", run):
                    offenders.append(f"{name}: '{step.get('name')}' in job '{job_id}'")
    assert not offenders, "steps consuming the token without trimming it first: " + "; ".join(offenders)


@pytest.mark.parametrize("workflow", DISPATCH_WORKFLOWS)
@pytest.mark.parametrize(
    "wrapped",
    ["\n" + VALID_OAUTH, VALID_OAUTH + "\n", " " + VALID_OAUTH],
    ids=["leading-newline", "trailing-newline", "leading-space"],
)
def test_verify_step_trims_whitespace_before_calling_claude(tmp_path, workflow, wrapped):
    """Prove the fix, not just assert it's there.

    Stubs `claude` (and `npm`, which fixture-e2e-dispatch.yml's verify step
    installs inline) and asserts the stub actually receives the token with
    whitespace already stripped — the concrete failure this closes is the
    stub/API seeing the raw, un-trimmed value one step after preflight called
    it clean.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "npm").write_text("#!/bin/sh\nexit 0\n")
    (bin_dir / "npm").chmod(0o755)
    seen_file = tmp_path / "seen_token"
    stub = bin_dir / "claude"
    stub.write_text(f'#!/bin/sh\nprintf %s "$CLAUDE_CODE_OAUTH_TOKEN" > "{seen_file}"\necho ok\n')
    stub.chmod(0o755)

    script = tmp_path / "verify.sh"
    script.write_text(_step_script(workflow, "Verify the token is accepted"))

    result = subprocess.run(
        ["bash", str(script)],
        env={"PATH": f"{bin_dir}:/usr/bin:/bin", "CLAUDE_CODE_OAUTH_TOKEN": wrapped},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert seen_file.read_text() == VALID_OAUTH


@pytest.mark.parametrize("workflow,job", PREFLIGHTS)
def test_preflight_never_echoes_the_credential(tmp_path, workflow, job):
    """Job logs are readable by anyone with repo access."""
    secret = "sk-ant-oat01-" + "S3CR3T" * 8
    result = _run_preflight(tmp_path, workflow, job, secret)
    combined = result.stdout + result.stderr
    assert "S3CR3T" not in combined
    assert secret not in combined


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
