#!/bin/sh
# Manual/nightly recall matrix over every external single-repository fixture.
set -eu

PLUGIN_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEPTH="${APPSEC_FIXTURE_SUITE_DEPTH:-quick}"
FIXTURES="
spring-boot-threat-fixture
python-threat-fixture
rust-threat-fixture
go-threat-fixture
node-typescript-threat-fixture
python-langchain-llm-threat-fixture
aws-terraform-threat-fixture
npm-supply-chain-threat-fixture
fifty-service-threat-fixture
"

case "$DEPTH" in
    quick|standard|thorough) ;;
    *) echo "ERROR: APPSEC_FIXTURE_SUITE_DEPTH must be quick, standard, or thorough" >&2; exit 3 ;;
esac

for fixture in $FIXTURES; do
    echo ""
    echo "=== fixture-suite: $fixture ($DEPTH) ==="
    "$PLUGIN_ROOT/scripts/e2e_fixture.sh" \
        --fixture "$fixture" \
        --depth "$DEPTH" \
        --clean-output
done

echo ""
echo "fixture-suite: all external oracle checks passed"
