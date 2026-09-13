#!/usr/bin/env bash
# run-tests.sh — thin wrapper around pytest for the appsec-advisor test suite.
#
# Usage:
#   scripts/run-tests.sh                # run everything
#   scripts/run-tests.sh e2e            # only the frozen-run E2E pipeline suite
#   scripts/run-tests.sh quick          # fast drift guards (no pipeline replay)
#   scripts/run-tests.sh group report   # shared group (quick/report/scanner/prompts/runtime/incremental/e2e)
#   scripts/run-tests.sh coverage       # full suite with coverage report
#   scripts/run-tests.sh <pattern>      # forward as -k <pattern> to pytest
#   scripts/run-tests.sh help           # show this help
#
# Prefers .venv, then system Python, then .venv-tests. Bootstraps .venv-tests
# from tests/requirements-test.txt only when no interpreter has the dependencies.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VENV="$ROOT/.venv-tests"
REQ="$ROOT/tests/requirements-test.txt"

mode="${1:-all}"
shift || true

# Help must not install dependencies or access the network.
if [[ "$mode" == help || "$mode" == -h || "$mode" == --help ]]; then
    sed -n '2,/^set /{ /^#/s/^# \{0,1\}//p; }' "$0"
    exit 0
fi

# Resolve a Python interpreter that has every runtime dep the suite needs.
_has_deps() {
    "$1" -c "import pytest, yaml, jinja2, jsonschema; ${2:-pass}" >/dev/null 2>&1
}

extra_import="pass"
if [[ "$mode" == coverage ]]; then
    extra_import="import pytest_cov"
fi

if [[ -x "$ROOT/.venv/bin/python3" ]] && _has_deps "$ROOT/.venv/bin/python3" "$extra_import"; then
    PY="$ROOT/.venv/bin/python3"
elif _has_deps python3 "$extra_import"; then
    PY=python3
elif [[ -x "$VENV/bin/python3" ]] && _has_deps "$VENV/bin/python3" "$extra_import"; then
    PY="$VENV/bin/python3"
else
    echo ">> bootstrapping test venv at $VENV"
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install --quiet --upgrade pip
    "$VENV/bin/pip" install --quiet -r "$REQ"
    PY="$VENV/bin/python3"
fi

case "$mode" in
    all|"")
        exec "$PY" scripts/run_tests.py all "$@"
        ;;
    group)
        exec "$PY" scripts/run_tests.py "$@"
        ;;
    quick|e2e)
        exec "$PY" scripts/run_tests.py "$mode" "$@"
        ;;
    coverage)
        exec "$PY" scripts/run_tests.py all \
            --cov=scripts \
            --cov-report=term-missing \
            --cov-report=html:.coverage-html \
            "$@"
        ;;
    *)
        exec "$PY" scripts/run_tests.py all -k "$mode" -v "$@"
        ;;
esac
