# Coverage Test Plan: Haiku Economy vs Sonnet Default

## Purpose

Validates that `--reasoning-model haiku-economy --assessment-depth quick` causes no
quality regression relative to today's default (`--assessment-depth quick`,
implicitly `--reasoning-model sonnet`).

This test is to be run **manually** — it requires real LLM token cost
(~$15-25 one-time) and wallclock (~30-60 min for both runs combined) and cannot
be run by the automatic test suite.

## Prerequisites

- Plugin version: current `main` (with the haiku-economy patch)
- Reference repo: a proven test project (see recommendation below)
- Anthropic API quota: ~$25 available
- Time: ~90 min for both runs + comparison

## Recommended reference repos

| Repo | Size | Stack | Cost Sonnet | Cost Haiku |
|---|---|---|---|---|
| OWASP juice-shop | medium | Node/Express/Angular | ~$3-4 | ~$1-2 |
| pyca/cryptography | small-medium | Python | ~$2-3 | ~$1 |
| Own mini test repo (~30 files) | small | any | ~$1-2 | ~$0.50 |

**Recommendation:** juice-shop, because a complex stack with auth/DB/frontend → tests
the full pipeline.

## Test procedure

### Step 1: Baseline run (Sonnet)

```bash
cd <reference-repo-path>

# Local output dir so nothing gets committed into the repo
mkdir -p /tmp/coverage-test-baseline

# Clean starting point
rm -rf /tmp/coverage-test-baseline/.appsec-cache
rm -rf /tmp/coverage-test-baseline/.fragments

# Baseline run
time /appsec-advisor:create-threat-model \
    --assessment-depth quick \
    --output /tmp/coverage-test-baseline \
    --no-confirm \
    --yaml \
    2>&1 | tee /tmp/coverage-test-baseline/run.log

# Extract cost
python3 scripts/verify_run_costs.py /tmp/coverage-test-baseline
```

Expectation: `threat-model.yaml` present, findings ≥ 5, no hard error.

### Step 2: Treatment run (haiku-economy)

```bash
mkdir -p /tmp/coverage-test-treatment
rm -rf /tmp/coverage-test-treatment/.appsec-cache
rm -rf /tmp/coverage-test-treatment/.fragments

time /appsec-advisor:create-threat-model \
    --assessment-depth quick \
    --reasoning-model haiku-economy \
    --output /tmp/coverage-test-treatment \
    --no-confirm \
    --yaml \
    2>&1 | tee /tmp/coverage-test-treatment/run.log

python3 scripts/verify_run_costs.py /tmp/coverage-test-treatment
```

### Step 3: Comparison

```bash
# Wallclock + cost
echo "=== Baseline ==="
grep -E "real|cost" /tmp/coverage-test-baseline/run.log
echo "=== Treatment ==="
grep -E "real|cost" /tmp/coverage-test-treatment/run.log

# Findings count
echo "=== Findings Count ==="
yq '.threats | length' /tmp/coverage-test-baseline/threat-model.yaml
yq '.threats | length' /tmp/coverage-test-treatment/threat-model.yaml

# Severity distribution
echo "=== Baseline Severity ==="
yq '.threats[].severity' /tmp/coverage-test-baseline/threat-model.yaml | sort | uniq -c
echo "=== Treatment Severity ==="
yq '.threats[].severity' /tmp/coverage-test-treatment/threat-model.yaml | sort | uniq -c

# Critical findings
echo "=== Baseline Critical ==="
yq '.threats[] | select(.severity == "Critical") | .title' /tmp/coverage-test-baseline/threat-model.yaml
echo "=== Treatment Critical ==="
yq '.threats[] | select(.severity == "Critical") | .title' /tmp/coverage-test-treatment/threat-model.yaml
```

## Acceptance criteria

| Metric | Acceptance |
|---|---|
| **Findings-count drift** | ≤ ±10 % (treatment may have at most 10 % fewer findings) |
| **Critical retention** | 100 % — every Critical from baseline must also exist in treatment (semantically matched) |
| **High retention** | ≥ 80 % — treatment keeps at least 80 % of the baseline Highs |
| **Severity-distribution drift** | ≤ ±15 % per severity class |
| **Wallclock reduction** | ≥ 20 % (expected: 25-30 %) |
| **Cost reduction** | ≥ 25 % (expected: ~33 %) |
| **Schema validity** | both YAMLs pass `validate_intermediate.py` |

## Result documentation

If all acceptance criteria are met:
- `tests/HAIKU_COVERAGE_RESULTS.md` with date + repo + metrics
- Recommendation to plugin maintainers: consider a default switch

If a criterion fails:
- Detailed analysis of which aspect is lost
- If a Critical is missing → no default switch, possibly revert the patch
- If only the wallclock win is marginal → revise the plan

## When to run this test

- Before the default switch from haiku-economy to the quick default (= plugin-maintainer decision)
- After every Sonnet/Haiku model update from Anthropic
- After significant changes to the `agents/appsec-stride-analyzer.md` quick-profile section
- On bug reports "Haiku mode finds fewer threats"

## Automation as roadmap

Manual execution is OK for initial validation. Longer term, this
test should be integrated into the E2E CI test setup (roadmap §8 #2):

- Reference repo as a submodule or fixture
- Both runs as a CI job (daily or weekly)
- Dashboard with findings-count trend and cost trend
- Auto-alert on acceptance violation

## Status

- [ ] Step 1 run: date / reviewer
- [ ] Step 2 run: date / reviewer
- [ ] Step 3 evaluated: date / reviewer
- [ ] Result documented in `HAIKU_COVERAGE_RESULTS.md`
- [ ] Default-switch decision made
