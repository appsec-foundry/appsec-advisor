# Combined assessment fixture E2E

This check runs a live combined assessment over three fresh local checkouts made from `tests/fixtures/multi_repo_system/`. No checkout carries a threat model, so the run must discover every service, connection and finding itself. It costs model tokens; run it only when a release or a change to the combined assessment needs live evidence.

The in-process test `tests/test_multi_repo_assessment.py` covers the same pipeline with scripted model replies. Only this live run shows whether discovery actually finds the connections.

## Create the checkouts

Run from the plugin checkout. The script copies each service into its own directory under a new temporary root and commits it:

```bash
ROOT="$(mktemp -d)"
for service in storefront orders-api fulfillment-worker; do
  cp -R "tests/fixtures/multi_repo_system/$service" "$ROOT/$service"
  git -C "$ROOT/$service" init -q
  git -C "$ROOT/$service" add -A
  git -C "$ROOT/$service" -c user.name=fixture -c user.email=fixture@example.invalid commit -q -m fixture
done
echo "$ROOT"
```

## Run the assessment

```bash
./scripts/run-headless.sh \
  --repo "$ROOT/storefront" \
  --repo "$ROOT/orders-api" \
  --repo "$ROOT/fulfillment-worker" \
  --output "$ROOT/report" \
  --soft-budget 20 \
  --sarif
```

Repeat the run with the `--repo` flags in a different order and with the directories renamed; the model must name the same components, connections and findings.

## Expected result

Check `$ROOT/report/threat-model.yaml` and `threat-model.md`:

- `source_inventory` lists all three repositories, and every finding's evidence names one of them.
- The storefront → orders-api request, the orders-api → broker publish and the broker → fulfillment-worker delivery are data flows; the broker is one node. A connection the evidence does not support stays out of the flows.
- Findings include the SQL injection and the missing caller check in `orders-api/app.py`, the HTML injection in `storefront/web/app.js` and the label path in `fulfillment-worker/worker.py`, each attributed to its own repository.
- No trust boundary exists only because two components live in different repositories.
- Figure 1 shows every component with its repository annotation and readable flow labels.
- `threat-model.sarif.json` uses one `appsec-repository://<repository-id>/` base per repository.

Record the commands, the three commit IDs, the spent amount and the duration with the result. A failed check is a plugin defect; fix the producer, not the fixture.

## Larger fixture with an oracle

`appsec-advisor-fixtures` carries `multi-repo-system-threat-fixture`: five repositories (`web-frontend`, `api-gateway`, `user-service`, `orders-api`, `fulfillment-worker`) with findings that need more than one repository, such as a JWT secret shared by issuer and verifier and identity headers the gateway lets callers set. Its `orders-api` and `fulfillment-worker` come from `tests/fixtures/multi_repo_system/`. The commands and the out-of-repository verifier are in `oracles/multi-repo-system-threat-fixture/README.md` there.
