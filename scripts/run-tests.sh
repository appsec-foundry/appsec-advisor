#!/usr/bin/env bash
# run-tests.sh — thin wrapper around pytest for the appsec-advisor test suite.
#
# Usage:
#   scripts/run-tests.sh                # run everything
#   scripts/run-tests.sh e2e            # only the frozen-run E2E pipeline suite
#   scripts/run-tests.sh quick          # fast drift guards (no pipeline replay)
#   scripts/run-tests.sh coverage       # full suite with coverage report
#   scripts/run-tests.sh <pattern>      # forward as -k <pattern> to pytest
#   scripts/run-tests.sh help           # show this help
#
# Prefers the system Python if `python3 -c "import pytest,yaml,jinja2,jsonschema"`
# succeeds. Otherwise bootstraps .venv-tests/ from tests/requirements-test.txt.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VENV="$ROOT/.venv-tests"
REQ="$ROOT/tests/requirements-test.txt"

# Resolve a Python interpreter that has every runtime dep the suite needs.
_has_deps() {
    "$1" -c "import pytest, yaml, jinja2, jsonschema" >/dev/null 2>&1
}

if _has_deps python3; then
    PY=python3
elif [[ -x "$VENV/bin/python3" ]] && _has_deps "$VENV/bin/python3"; then
    PY="$VENV/bin/python3"
else
    echo ">> bootstrapping test venv at $VENV"
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install --quiet --upgrade pip
    "$VENV/bin/pip" install --quiet -r "$REQ"
    PY="$VENV/bin/python3"
fi

mode="${1:-all}"
shift || true

case "$mode" in
    all|"")
        exec "$PY" -m pytest tests/ "$@"
        ;;
    e2e)
        exec "$PY" -m pytest tests/test_e2e_pipeline.py -v "$@"
        ;;
    quick)
        exec "$PY" -m pytest \
            tests/test_contract_integrity.py \
            tests/test_schema_integrity.py \
            tests/test_new_schemas.py \
            tests/test_runtime_cleanup.py \
            tests/test_taxonomy_coverage.py \
            "$@"
        ;;
    coverage)
        exec "$PY" -m pytest tests/ \
            --cov=scripts \
            --cov-report=term-missing \
            --cov-report=html:.coverage-html \
            "$@"
        ;;
    help|-h|--help)
        grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        exec "$PY" -m pytest tests/ -k "$mode" -v "$@"
        ;;
esac
