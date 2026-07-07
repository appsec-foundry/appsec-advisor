#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# e2e_spring_fixture.sh — Run the Spring Boot fixture E2E and verify the report
#                         against the out-of-repo oracle.
#
# This is a deterministic wrapper around scripts/run-headless.sh. It deliberately
# runs the oracle only after the threat model has been generated, so the oracle
# is not part of the repository context given to create-threat-model.
#
# Claude Code goal prompt for a real run:
#
#   Goal: Run the real Spring Boot fixture E2E for appsec-advisor without editing
#   repository files.
#
#   Working directory: <checkout>/appsec-advisor
#
#   Run:
#   ./scripts/e2e_spring_fixture.sh --depth quick --clean-output
#
#   Do not modify source files. If preflight fails, stop and report the exact
#   missing path/tool. If the pipeline runs, wait for completion and report the
#   final result and artifact path.
# ─────────────────────────────────────────────────────────────────────────────

set -eu

PLUGIN_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN_PARENT="$(cd "$PLUGIN_ROOT/.." && pwd)"

FIXTURE_NAME="spring-boot-threat-fixture"
DEFAULT_FIXTURE_ROOT="$PLUGIN_PARENT/appsec-advisor-fixtures"
LEGACY_FIXTURE_ROOT="$PLUGIN_PARENT/appsec-advisor-tests"

if [ -n "${APPSEC_SPRING_E2E_ROOT:-}" ]; then
    FIXTURE_ROOT="$APPSEC_SPRING_E2E_ROOT"
elif [ -d "$DEFAULT_FIXTURE_ROOT" ]; then
    FIXTURE_ROOT="$DEFAULT_FIXTURE_ROOT"
elif [ -d "$LEGACY_FIXTURE_ROOT" ]; then
    FIXTURE_ROOT="$LEGACY_FIXTURE_ROOT"
else
    FIXTURE_ROOT="$DEFAULT_FIXTURE_ROOT"
fi

REPO="${APPSEC_SPRING_E2E_REPO:-}"
ORACLE="${APPSEC_SPRING_E2E_ORACLE:-}"
OUTPUT="${APPSEC_SPRING_E2E_OUTPUT:-}"
DEPTH="${APPSEC_SPRING_E2E_DEPTH:-standard}"
MAX_DURATION="${APPSEC_SPRING_E2E_MAX_DURATION:-3600}"
CLEAN_OUTPUT=0
ORACLE_JSON=0

usage() {
    cat <<'HELP'
Usage: scripts/e2e_spring_fixture.sh [options]

Run an end-to-end AppSec Advisor scan against the Spring Boot fixture and verify
the generated report against the external oracle.

Options:
  --fixture-root <path>  Root containing the fixture repo, oracle, and outputs
                         default: ../appsec-advisor-fixtures next to this plugin
                         fallback: ../appsec-advisor-tests for legacy checkouts
  --repo <path>          Fixture repository to scan
                         default: <fixture-root>/repos/spring-boot-threat-fixture
  --oracle <path>        External oracle directory containing verify_threat_model.py
                         default: <fixture-root>/oracles/spring-boot-threat-fixture
  --output <path>        Output directory for generated threat-model artifacts
                         default: <fixture-root>/outputs/spring-boot-threat-fixture-e2e
  --depth <level>        quick | standard | thorough
                         default: standard
  --max-duration <sec>   Pass through to run-headless.sh
                         default: 3600
  --clean-output         Remove the output directory before running
  --oracle-json          Ask the oracle verifier to emit JSON
  -h, --help             Show this help

Exit codes:
  0  pipeline and oracle verification passed
  1  pre-flight failed
  2  create-threat-model pipeline failed
  3  expected report artifacts are missing
  4  oracle verification failed
HELP
}

die_preflight() {
    echo "ERROR: $*" >&2
    exit 1
}

need_value() {
    [ $# -ge 2 ] || die_preflight "$1 requires a value"
}

infer_fixture_layout() {
    if [ -d "$FIXTURE_ROOT/repos" ] || [ -d "$FIXTURE_ROOT/oracles" ] || [ -d "$FIXTURE_ROOT/outputs" ]; then
        echo "suite"
    elif [ -d "$FIXTURE_ROOT/$FIXTURE_NAME" ] || [ -d "$FIXTURE_ROOT/oracle" ] || [ -d "$FIXTURE_ROOT/threat-output" ]; then
        echo "legacy"
    else
        echo "suite"
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --fixture-root)
            need_value "$@"; FIXTURE_ROOT="$2"; shift 2 ;;
        --repo)
            need_value "$@"; REPO="$2"; shift 2 ;;
        --oracle)
            need_value "$@"; ORACLE="$2"; shift 2 ;;
        --output)
            need_value "$@"; OUTPUT="$2"; shift 2 ;;
        --depth)
            need_value "$@"; DEPTH="$2"; shift 2 ;;
        --max-duration)
            need_value "$@"; MAX_DURATION="$2"; shift 2 ;;
        --clean-output)
            CLEAN_OUTPUT=1; shift ;;
        --oracle-json)
            ORACLE_JSON=1; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "Unknown arg: $1" >&2
            usage >&2
            exit 1 ;;
    esac
done

FIXTURE_LAYOUT="$(infer_fixture_layout)"

if [ "$FIXTURE_LAYOUT" = "suite" ]; then
    REPO="${REPO:-$FIXTURE_ROOT/repos/$FIXTURE_NAME}"
    ORACLE="${ORACLE:-$FIXTURE_ROOT/oracles/$FIXTURE_NAME}"
    OUTPUT="${OUTPUT:-$FIXTURE_ROOT/outputs/$FIXTURE_NAME-e2e}"
else
    REPO="${REPO:-$FIXTURE_ROOT/$FIXTURE_NAME}"
    ORACLE="${ORACLE:-$FIXTURE_ROOT/oracle}"
    OUTPUT="${OUTPUT:-$FIXTURE_ROOT/threat-output/$FIXTURE_NAME-e2e}"
fi

case "$DEPTH" in
    quick|standard|thorough) ;;
    *) die_preflight "--depth must be quick, standard, or thorough; got: $DEPTH" ;;
esac

[ -d "$REPO" ] || die_preflight "fixture repo not found: $REPO"
[ -f "$REPO/pom.xml" ] || die_preflight "fixture repo does not look like a Maven project: $REPO"
[ -d "$ORACLE" ] || die_preflight "oracle directory not found: $ORACLE"
[ -f "$ORACLE/verify_threat_model.py" ] || die_preflight "oracle verifier missing: $ORACLE/verify_threat_model.py"
[ -f "$ORACLE/expected-signals.json" ] || die_preflight "oracle manifest missing: $ORACLE/expected-signals.json"
[ -x "$PLUGIN_ROOT/scripts/run-headless.sh" ] || die_preflight "run-headless.sh is missing or not executable"
command -v claude >/dev/null 2>&1 || die_preflight "'claude' CLI not found on PATH"

REPO_REAL="$(cd "$REPO" && pwd -P)" || die_preflight "cannot resolve fixture repo: $REPO"
ORACLE_REAL="$(cd "$ORACLE" && pwd -P)" || die_preflight "cannot resolve oracle directory: $ORACLE"
case "$ORACLE_REAL" in
    "$REPO_REAL"|"$REPO_REAL"/*)
        die_preflight "oracle must be outside the scanned fixture repo: $ORACLE" ;;
esac

if [ "$CLEAN_OUTPUT" -eq 1 ]; then
    case "$OUTPUT" in
        ""|"/"|"/home"|"/home/"|"/tmp"|"/tmp/"|"."|"./"|".."|"../")
            die_preflight "refusing to clean unsafe output path: $OUTPUT" ;;
    esac
    if [ -d "$OUTPUT" ]; then
        OUTPUT_REAL="$(cd "$OUTPUT" && pwd -P)" || die_preflight "cannot resolve output directory: $OUTPUT"
        case "$OUTPUT_REAL" in
            "/"|"$PLUGIN_PARENT"|"$PLUGIN_ROOT"|"$REPO_REAL"|"$ORACLE_REAL")
                die_preflight "refusing to clean unsafe output path: $OUTPUT" ;;
        esac
        if [ -d "$FIXTURE_ROOT" ]; then
            FIXTURE_ROOT_REAL="$(cd "$FIXTURE_ROOT" && pwd -P)" || die_preflight "cannot resolve fixture root: $FIXTURE_ROOT"
            [ "$OUTPUT_REAL" != "$FIXTURE_ROOT_REAL" ] || die_preflight "refusing to clean fixture root as output: $OUTPUT"
        fi
    fi
    rm -rf "$OUTPUT"
fi
mkdir -p "$OUTPUT"

cat <<EOF
─────────────────────────────────────────────────────────────────────
appsec-advisor — Spring Boot fixture E2E
─────────────────────────────────────────────────────────────────────
  fixture-root:  $FIXTURE_ROOT
  layout:        $FIXTURE_LAYOUT
  repo:          $REPO
  output:        $OUTPUT
  oracle:        $ORACLE
  depth:         $DEPTH
  max-duration:  ${MAX_DURATION}s
─────────────────────────────────────────────────────────────────────
EOF

START_TS=$(date +%s)
PIPELINE_STATUS=0

"$PLUGIN_ROOT/scripts/run-headless.sh" \
    --repo "$REPO" \
    --output "$OUTPUT" \
    --full \
    --yaml \
    --sarif \
    --assessment-depth "$DEPTH" \
    --max-duration "$MAX_DURATION" \
    || PIPELINE_STATUS=$?

ELAPSED=$(( $(date +%s) - START_TS ))

echo ""
echo "→ pipeline exit code: $PIPELINE_STATUS"
echo "→ wall-time: ${ELAPSED}s"

if [ "$PIPELINE_STATUS" -ne 0 ]; then
    echo "PIPELINE FAILED — skipping oracle verification." >&2
    echo "Artifacts, if any: $OUTPUT" >&2
    exit 2
fi

REPORT="$OUTPUT/threat-model.md"
YAML_REPORT="$OUTPUT/threat-model.yaml"

[ -f "$REPORT" ] || { echo "ERROR: missing report: $REPORT" >&2; exit 3; }
[ -f "$YAML_REPORT" ] || { echo "ERROR: missing YAML report: $YAML_REPORT" >&2; exit 3; }

echo ""
echo "[oracle] verifying generated report against expected fixture signals ..."

ORACLE_STATUS=0
if [ "$ORACLE_JSON" -eq 1 ]; then
    python3 "$ORACLE/verify_threat_model.py" \
        --repo "$REPO" \
        --report "$REPORT" \
        --yaml "$YAML_REPORT" \
        --json \
        || ORACLE_STATUS=$?
else
    python3 "$ORACLE/verify_threat_model.py" \
        --repo "$REPO" \
        --report "$REPORT" \
        --yaml "$YAML_REPORT" \
        || ORACLE_STATUS=$?
fi

echo ""
if [ "$ORACLE_STATUS" -ne 0 ]; then
    echo "RESULT: FAIL — oracle verification failed." >&2
    echo "Artifacts: $OUTPUT" >&2
    exit 4
fi

echo "RESULT: PASS — pipeline completed and oracle verification passed."
echo "Artifacts: $OUTPUT"
