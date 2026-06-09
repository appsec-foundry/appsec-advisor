# Single-Repo Fixture E2E

This check runs the AppSec Advisor threat-model pipeline against one synthetic
single-repo fixture and then verifies the generated report against the matching
external oracle.

By default the driver expects the shared sibling fixture-suite checkout:

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
