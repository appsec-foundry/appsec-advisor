# Spring Boot Fixture E2E

This check runs the AppSec Advisor threat-model pipeline against the Spring Boot fixture and then verifies the generated report against an external expected-signal oracle.

By default the driver expects a sibling fixture-suite checkout:

```text
<workspace>/
  appsec-advisor/
  appsec-advisor-fixtures/
    repos/
      spring-boot-threat-fixture/
    oracles/
      spring-boot-threat-fixture/
    outputs/
```

The important separation is:

- scan repo: `<fixture-root>/repos/spring-boot-threat-fixture`
- oracle: `<fixture-root>/oracles/spring-boot-threat-fixture`
- output: `<fixture-root>/outputs/spring-boot-threat-fixture-e2e`

The oracle is intentionally outside the scanned repo. The threat-model skill should infer findings from code, configuration, and deployment files; the oracle is only used after the report has been generated.

For existing local checkouts, the script still falls back to the older sibling
layout at `../appsec-advisor-tests`:

```text
appsec-advisor-tests/
  spring-boot-threat-fixture/
  oracle/
  threat-output/
```

## Run

From the plugin root:

```bash
./scripts/e2e_spring_fixture.sh --clean-output
```

Useful variants:

```bash
./scripts/e2e_spring_fixture.sh --depth quick --clean-output
./scripts/e2e_spring_fixture.sh --depth thorough --max-duration 5400
./scripts/e2e_spring_fixture.sh --oracle-json
```

With a custom fixture root:

```bash
./scripts/e2e_spring_fixture.sh \
  --fixture-root ../appsec-advisor-fixtures \
  --depth standard \
  --clean-output
```

For non-standard layouts, either pass the three concrete paths or set the
equivalent environment variables:

```bash
./scripts/e2e_spring_fixture.sh \
  --repo /path/to/spring-boot-threat-fixture \
  --oracle /path/to/oracles/spring-boot-threat-fixture \
  --output /path/to/outputs/spring-boot-threat-fixture-e2e

APPSEC_SPRING_E2E_ROOT=/path/to/appsec-advisor-fixtures ./scripts/e2e_spring_fixture.sh

APPSEC_SPRING_E2E_REPO=/path/to/spring-boot-threat-fixture \
APPSEC_SPRING_E2E_ORACLE=/path/to/oracles/spring-boot-threat-fixture \
APPSEC_SPRING_E2E_OUTPUT=/path/to/outputs/spring-boot-threat-fixture-e2e \
  ./scripts/e2e_spring_fixture.sh
```

## What Passes

The script exits with `0` only when:

- `scripts/run-headless.sh` completes successfully.
- `threat-model.md` and `threat-model.yaml` exist in the output directory.
- `oracle/verify_threat_model.py` finds all expected fixture signals in the generated report.
- The oracle is not located inside the scanned repo.

Non-zero exits separate failure modes:

- `1`: pre-flight failed.
- `2`: threat-model pipeline failed.
- `3`: expected report artifacts are missing.
- `4`: oracle verification failed.

## Notes

`--clean-output` removes only the chosen output directory before the run. It is off by default so reruns do not delete artifacts unexpectedly.

The script does not commit, stage, or modify the fixture repository. The generated report artifacts are written only to the configured output directory.
