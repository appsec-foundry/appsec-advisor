# Single-Repo Fixture E2E

This check runs the AppSec Advisor threat-model pipeline against one synthetic
single-repo fixture and then verifies the generated report against the matching
external oracle.

By default the driver expects the shared sibling fixture-suite checkout. Clone
it next to this repo if you don't have it yet
([github.com/matthiasrohr/appsec-advisor-fixtures](https://github.com/matthiasrohr/appsec-advisor-fixtures)):

```bash
git clone git@github.com:matthiasrohr/appsec-advisor-fixtures.git ../appsec-advisor-fixtures
```

Resulting layout:

```text
<workspace>/
  appsec-advisor/
  appsec-advisor-fixtures/
    repos/
      spring-boot-threat-fixture/
      python-threat-fixture/
      rust-threat-fixture/
      go-threat-fixture/
      node-typescript-threat-fixture/
      python-langchain-llm-threat-fixture/
    oracles/
      <fixture>/
    outputs/
      <fixture>-e2e/
```

The important separation is:

- scan repo: `<fixture-root>/repos/<fixture>`
- oracle: `<fixture-root>/oracles/<fixture>`
- output: `<fixture-root>/outputs/<fixture>-e2e`

The oracle is intentionally outside the scanned repo. The threat-model skill
must infer findings from code, configuration, and deployment files; the oracle
is only used after the report has been generated.

## Fixtures

Known single-repo fixtures:

- `spring-boot-threat-fixture`
- `python-threat-fixture`
- `rust-threat-fixture`
- `go-threat-fixture`
- `node-typescript-threat-fixture`
- `python-langchain-llm-threat-fixture`

List them from the plugin root:

```bash
./scripts/e2e_fixture.sh --list
```

## Run

From the plugin root:

```bash
./scripts/e2e_fixture.sh --fixture python-threat-fixture --depth quick --clean-output
```

Useful variants:

```bash
./scripts/e2e_fixture.sh --fixture spring-boot-threat-fixture --depth quick --clean-output
./scripts/e2e_fixture.sh --fixture rust-threat-fixture --depth standard --max-duration 5400
./scripts/e2e_fixture.sh --fixture python-langchain-llm-threat-fixture --oracle-json
```

With a custom fixture root:

```bash
./scripts/e2e_fixture.sh \
  --fixture node-typescript-threat-fixture \
  --fixture-root ../appsec-advisor-fixtures \
  --depth quick \
  --clean-output
```

For non-standard layouts, either pass the three concrete paths or set the
equivalent environment variables:

```bash
./scripts/e2e_fixture.sh \
  --repo /path/to/repos/go-threat-fixture \
  --oracle /path/to/oracles/go-threat-fixture \
  --output /path/to/outputs/go-threat-fixture-e2e

APPSEC_FIXTURE_E2E_ROOT=/path/to/appsec-advisor-fixtures \
  ./scripts/e2e_fixture.sh --fixture go-threat-fixture

APPSEC_FIXTURE_E2E_NAME=python-threat-fixture \
APPSEC_FIXTURE_E2E_REPO=/path/to/repos/python-threat-fixture \
APPSEC_FIXTURE_E2E_ORACLE=/path/to/oracles/python-threat-fixture \
APPSEC_FIXTURE_E2E_OUTPUT=/path/to/outputs/python-threat-fixture-e2e \
  ./scripts/e2e_fixture.sh
```

## Run in CI

`.github/workflows/fixture-e2e-dispatch.yml` runs the same drivers on a GitHub
runner (Actions → *Fixture E2E (Dispatch)* → *Run workflow*). Inputs are
`fixture` (a dropdown: one fixture, or `all`), `depth`, optional
`plugin_ref` / `fixtures_ref`, and the repair inputs below.

Paths and driver are still derived from the checkout layout, never enumerated.
A fixture directory holding only sub-repositories and no files of its own is a
multi-repo fixture; of those only the `consumer-api/` shape has a driver, since
`scripts/e2e_cross_repo_fixture.sh` hardwires the consumer name. Any other
multi-repo fixture is reported as having no driver yet, skipped by `all`, and
rejected with a clear error if selected — rather than being mistaken for a
single repo and scanned as one.

The fixture *list*, by contrast, is not discovered: GitHub
cannot fill a `type: choice` input dynamically. **Adding a fixture to the
fixtures repo means adding it to the `fixture` input's `options` block** — the
one place it is written down. The `resolve` job reads those options back out of
the workflow file and compares them against `repos/`, hard-failing on drift and
naming the offending fixture, so a forgotten entry is loud rather than a
silently missing dropdown option. `.github/fixture-presets.json` holds only the
per-depth `--max-duration` budgets plus optional per-fixture overrides.

Each job uploads its output directory as the artifact
`fixture-e2e-<fixture>-<depth>` (30 days), including on failure, so an oracle
mismatch can be triaged without a local rerun. The artifact also carries
`e2e-result.json` (exit code + failure classification) and `e2e-console.log`.

### Triaging a failed run locally

The artifact is a complete output directory, including the dot-prefixed run
state (`include-hidden-files: true` on the upload step — without it
`upload-artifact` v4.4+ silently drops every one of those files, which is most
of the evidence). So a CI failure can be worked exactly like a local one:

```bash
gh run list --workflow fixture-e2e-dispatch.yml -L 10   # find the red run
make ci-triage RUN_ID=<run id>                          # fetch + summarise
```

`make ci-triage` wraps `scripts/ci_triage.sh` and serves this workflow and
`threat-model-dispatch.yml` alike: it downloads the `fixture-e2e-*` /
`threat-model-*` artifacts into `.appsec-ci/` (gitignored), prints one line
per fixture with its exit code and failure kind, and prints the `OUTPUT_DIR` to
export for each failure. From there the normal
`fix-run-issues` skill applies — it reads `$OUTPUT_DIR/.run-issues.json` and its
`fix_recommendation` entries, and needs `APPSEC_PLUGIN_DEV=1` to write to plugin
files.

This is the default loop when you are at your machine. Repair mode below is the
asynchronous fallback, not a replacement for it.

### Repair mode

`repair: true` adds a follow-up job that runs only if a fixture job failed. A
Claude Code agent triages the artifacts, proves the diagnosis against the code,
fixes the producer, verifies with the targeted tests plus `make lint`, and opens
a PR against `dev`.

Scope is deliberately narrow: only exits `1`, `2` and `3` (preflight, pipeline,
missing artifacts) are treated as repairable. Exit `4` — an oracle recall miss —
is reported in the job summary but never auto-fixed; whether the plugin or the
oracle is wrong is a judgement call, and an agent optimising toward the oracle
is the wrong incentive.

If the agent cannot substantiate a diagnosis, or cannot get its change green, it
makes no commit and the job explains why in the summary instead of opening a PR.

Whether a fix ships is not the agent's call. The job runs
`.github/workflows/repair-agent.yml`, shared with `threat-model-dispatch.yml`,
whose `Gate` step requires a regression test under `tests/` (an unreproduced
defect is not a verified one) and refuses any change touching `.github/` or
`.claude/`. A refused change is published as the `repair-refused-<run-id>`
artifact and fails the job rather than being dropped. That runbook
(`server-side-dispatch.md`) carries the full rationale, which is driven by the
untrusted-scan case.

To repair a run you already dispatched **without** `repair`, dispatch again with
`repair_run_id` set to that run's id (from its Actions URL). Nothing is scanned;
the agent works off the earlier run's artifacts, so it works for any red run
inside the 30-day retention window.

The PR is opened with `GITHUB_TOKEN`, which by design does not trigger workflows
— no checks run on the repair branch. Re-dispatch this workflow with
`plugin_ref: repair/run-<run id>` to validate the fix before merging.

This is separate from `threat-model-dispatch.yml`, which scans untrusted
external apps and has no oracle assertion.

## What Passes

The script exits with `0` only when:

- `scripts/run-headless.sh` completes successfully against the selected fixture
  repo.
- `threat-model.md` and `threat-model.yaml` exist in the output directory.
- `<oracle>/verify_threat_model.py` finds all expected fixture signals.
- The oracle is not located inside the scanned repo.

Non-zero exits separate failure modes:

- `1`: pre-flight failed.
- `2`: threat-model pipeline failed.
- `3`: expected report artifacts are missing.
- `4`: oracle verification failed.

## Notes

This E2E is manual and opt-in. The standard `pytest tests/` run checks only the
driver and documentation contract; it does not run Claude Code or scan the
fixture.

`--clean-output` removes only the chosen output directory before the run. It is
off by default so reruns do not delete artifacts unexpectedly.

The script does not commit, stage, or modify any fixture repository. Generated
report artifacts are written only to the configured output directory.

`scripts/e2e_spring_fixture.sh` remains available as a Spring-specific
compatibility wrapper. New single-repo fixtures should use
`scripts/e2e_fixture.sh`.
