# Cross-Repo Fixture E2E

This check runs the AppSec Advisor threat-model pipeline against a consumer repo
that declares related internal services in `docs/related-repos.yaml`. The
pipeline scans only the consumer; the producer repos provide pre-generated
`docs/security/threat-model.yaml` exports that exercise the plugin's cross-repo
context loader, register builder, STRIDE dispatch slicing, and report output.

By default the driver expects the shared sibling fixture-suite checkout:

```text
<workspace>/
  appsec-advisor/
  appsec-advisor-fixtures/
    repos/
      cross-repo-threat-fixture/
        consumer-api/
        auth-service/
        payment-service/
    oracles/
      cross-repo-threat-fixture/
    outputs/
```

The important separation is:

- scan repo: `<fixture-root>/repos/cross-repo-threat-fixture/consumer-api`
- producer repos: `<fixture-root>/repos/cross-repo-threat-fixture/auth-service` and `payment-service`
- oracle: `<fixture-root>/oracles/cross-repo-threat-fixture`
- output: `<fixture-root>/outputs/cross-repo-threat-fixture-e2e`

The oracle is intentionally outside the scanned repo. The producer repos are
not additional scan targets; they are referenced by the consumer's
`docs/related-repos.yaml`.

Example consumer declaration:

```yaml
related:
  - name: auth-service
    interface: POST /internal/auth/verify
    threat_model: ../auth-service/docs/security/threat-model.yaml
    expected_auth: JWT
    expected_validation: schema

  - name: payment-service
    interface: POST /internal/payments/charge
    threat_model: ../payment-service/docs/security/threat-model.yaml
    expected_auth: mTLS
    expected_validation: schema
```

## Run

From the plugin root:

```bash
./scripts/e2e_cross_repo_fixture.sh --clean-output
```

Useful variants:

```bash
./scripts/e2e_cross_repo_fixture.sh --depth quick --clean-output
./scripts/e2e_cross_repo_fixture.sh --depth standard --max-duration 5400
./scripts/e2e_cross_repo_fixture.sh --oracle-json
```

With a custom fixture root:

```bash
./scripts/e2e_cross_repo_fixture.sh \
  --fixture-root ../appsec-advisor-fixtures \
  --depth quick \
  --clean-output
```

For non-standard layouts, either pass the three concrete paths or set the
equivalent environment variables:

```bash
./scripts/e2e_cross_repo_fixture.sh \
  --repo /path/to/cross-repo-threat-fixture/consumer-api \
  --oracle /path/to/oracles/cross-repo-threat-fixture \
  --output /path/to/outputs/cross-repo-threat-fixture-e2e

APPSEC_CROSS_REPO_E2E_ROOT=/path/to/appsec-advisor-fixtures ./scripts/e2e_cross_repo_fixture.sh

APPSEC_CROSS_REPO_E2E_REPO=/path/to/cross-repo-threat-fixture/consumer-api \
APPSEC_CROSS_REPO_E2E_ORACLE=/path/to/oracles/cross-repo-threat-fixture \
APPSEC_CROSS_REPO_E2E_OUTPUT=/path/to/outputs/cross-repo-threat-fixture-e2e \
  ./scripts/e2e_cross_repo_fixture.sh
```

## What Passes

The script exits with `0` only when:

- `scripts/load_related_repos.py` can validate and load the consumer's `docs/related-repos.yaml`.
- All declared local producer `threat-model.yaml` exports are available.
- `scripts/run-headless.sh` completes successfully against the consumer repo.
- `threat-model.md` and `threat-model.yaml` exist in the output directory.
- `oracle/verify_threat_model.py` finds all expected cross-repo signals.
- The oracle is not located inside the scanned consumer repo.

Non-zero exits separate failure modes:

- `1`: pre-flight failed.
- `2`: threat-model pipeline failed.
- `3`: expected report artifacts are missing.
- `4`: oracle verification failed.

## Notes

This E2E is manual and opt-in. The standard `pytest tests/` run checks only the
driver and documentation contract; it does not run Claude Code or scan the
fixture.

The driver passes `--keep-runtime-files` so the oracle can inspect
`.related-repos-loaded.json`, `.cross-repo-register.json`, and per-component
dispatch context when needed.

`--clean-output` removes only the chosen output directory before the run. It is
off by default so reruns do not delete artifacts unexpectedly.

The script does not commit, stage, or modify any fixture repository. Generated
report artifacts are written only to the configured output directory.
