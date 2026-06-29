# Makefile — minimal entry points for maintainer workflows.
# This is dev tooling, not a build system. The plugin itself ships no binaries.
#
# Run `make help` for an overview.

.DEFAULT_GOAL := help

# Use .venv if present, otherwise fall back to system python3
PYTHON ?= $(if $(wildcard .venv/bin/python3),.venv/bin/python3,python3)

# ─────────────────────────────────────────────────────────────────────────────
# Manual E2E full-run
#
# Triggered ONLY manually — after a non-trivial refactor or before a release.
# Never wired into PR / push / cron hooks. See README "Manual full-run check".
#
# Auth: subscription (default, via `claude /login`) or ANTHROPIC_API_KEY.
# Cost: ~30–50% of a Pro 5h-window OR ~$0.30–1.00 with haiku-tier API usage.
# Time: ~10–15 min for `quick` depth on the bundled synthetic-repo fixture.
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: e2e-full
e2e-full:  ## Run the full E2E pipeline + assertions against the synthetic-repo fixture
	@command -v claude >/dev/null 2>&1 || { \
		echo "ERROR: 'claude' CLI not on PATH. Install Claude Code first."; exit 3; }
	@./tests/e2e/run-full.sh --depth quick

.PHONY: e2e-full-standard
e2e-full-standard:  ## Standard depth with Stage-3 QA enabled (slower, higher fidelity)
	@command -v claude >/dev/null 2>&1 || { \
		echo "ERROR: 'claude' CLI not on PATH. Install Claude Code first."; exit 3; }
	@./tests/e2e/run-full.sh --depth standard

.PHONY: e2e-full-thorough
e2e-full-thorough:  ## Thorough depth with Stage-3 QA and Stage-4 architect review
	@command -v claude >/dev/null 2>&1 || { \
		echo "ERROR: 'claude' CLI not on PATH. Install Claude Code first."; exit 3; }
	@./tests/e2e/run-full.sh --depth thorough

.PHONY: e2e-full-repair
e2e-full-repair: e2e-full-standard  ## Build a clean standard seed, corrupt §7, and verify the live Re-Render Loop
	@command -v claude >/dev/null 2>&1 || { \
		echo "ERROR: 'claude' CLI not on PATH. Install Claude Code first."; exit 3; }
	@./tests/e2e/run-repair.sh

.PHONY: e2e-full-eval
e2e-full-eval: e2e-full  ## Run the adversarial semantic-quality judge over a fresh full E2E result
	@./tests/e2e/run-eval.sh

.PHONY: e2e-fixture-suite
e2e-fixture-suite:  ## Run all six external language/architecture fixtures and their recall oracles
	@./tests/e2e/run-fixture-suite.sh

.PHONY: e2e-full-keep
e2e-full-keep:  ## Re-run assertions against the previous _last-run/ output (no pipeline re-run)
	@APPSEC_E2E_FULL=1 \
	 APPSEC_E2E_OUTPUT_DIR="$(PWD)/tests/fixtures/e2e/_last-run" \
	 $(PYTHON) -m pytest tests/test_full_run_e2e.py -v --tb=short

# ─────────────────────────────────────────────────────────────────────────────
# Fast unit tests (the per-PR safety net — runs in CI too)
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: test
test:  ## Run the standard pytest suite with coverage (no LLM)
	@$(PYTHON) -m pytest tests/ -v --tb=short --cov=scripts --cov-report=term-missing; \
		status=$$?; rm -rf .coverage-data; exit $$status

.PHONY: coverage
coverage:  ## Run the suite + write an HTML coverage report to htmlcov/index.html
	@$(PYTHON) -m pytest tests/ --tb=short --cov=scripts --cov-report=term-missing --cov-report=html; \
		status=$$?; rm -rf .coverage-data; exit $$status
	@echo "HTML report: htmlcov/index.html"

.PHONY: test-incremental
test-incremental:  ## Fast focused subset: incremental-scan reconciliation + 2-run main() E2E (no LLM)
	@$(PYTHON) -m pytest tests/test_incremental_two_run_e2e.py tests/test_build_threat_model_yaml.py -q

.PHONY: lint
lint:  ## Ruff check + format check
	@ruff check scripts/ tests/ hooks/
	@ruff format --check scripts/ tests/ hooks/

.PHONY: fix
fix:  ## Auto-repair the mechanical gate failures (ruff lint + format), then list what still needs a human
	@echo ">> ruff check --fix (safe lint fixes)"; ruff check --fix scripts/ tests/ hooks/ || true
	@echo ">> ruff format"; ruff format scripts/ tests/ hooks/
	@echo ""
	@echo "Auto-repair done. Stages 3-6 are NOT auto-fixable by design (fix the producer, not the symptom):"
	@echo "  - validate_config.py        -> correct the offending config field"
	@echo "  - check_fragment_registry   -> align the registry maps (docs/internal/runbooks/adding-a-section.md)"
	@echo "  - pytest / coverage         -> separate pre-existing from new failures; add tests, don't lower the floor"
	@echo "  - check_release_meta.py     -> reconcile pyproject version / git tag / CHANGELOG heading"
	@echo ""
	@echo "Re-run 'make check' (or 'make release-check') to see what remains."

# ─────────────────────────────────────────────────────────────────────────────
# Release gates
#
# `check`         — the continuous gate. Runs on every dev/main push & PR in CI.
#                   Must be green on EVERY commit (code health + drift guards).
# `release-check` — superset, for the release boundary only. Adds version/tag/
#                   changelog hygiene. Run it when PREPARING a release (version
#                   bumped + CHANGELOG entry written), not on routine dev commits.
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: check
check:  ## Continuous gate: lint, format, config, drift, full test suite (no coverage)
	@ruff check scripts/ tests/ hooks/
	@ruff format --check scripts/ tests/ hooks/
	@python3 scripts/validate_config.py .
	@python3 scripts/check_fragment_registry.py
	@# Run WITHOUT --cov: coverage enables `[tool.coverage.run] patch=["subprocess"]`,
	@# which instruments every child interpreter. The subprocess-heavy integration
	@# tests (e.g. test_incremental_mode spawning run-headless.sh) then crawl and the
	@# release gate appears to hang. Coverage is enforced separately by `make test` /
	@# `make coverage` (and the CI coverage job), not on this fast correctness gate.
	@$(PYTHON) -m pytest tests/ --tb=short

.PHONY: release-check
release-check:  ## Release-boundary gate: `check` + version/tag/changelog consistency
	@mkdir -p .cache
	@bash scripts/run-interruptible.sh .cache/release-check.log \
		bash -c '$(MAKE) --no-print-directory check && python3 scripts/check_release_meta.py'

.PHONY: release-all
release-all:  ## Full pre-release sequence: release-check then a live e2e-full (quick)
	@$(MAKE) --no-print-directory release-check
	@$(MAKE) --no-print-directory e2e-full

# ─────────────────────────────────────────────────────────────────────────────
# Diagnostic bundle — anonymised user→maintainer error report
#
# Build a finding-free .tgz from a failed run's OUTPUT_DIR (versions, run shape,
# metadata-only inventory, scrubbed logs) and inspect one on the analysis side.
# Never contains threat-model results, evidence, or source. See CONTRIBUTING.md.
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: diagnostic-bundle
diagnostic-bundle:  ## Build an anonymised diagnostic .tgz from a run: make diagnostic-bundle RUN=<repo>/docs/security [REPO_ROOT=<repo>] [INTO=.]
	@test -n "$(RUN)" || { echo "ERROR: set RUN=<run OUTPUT_DIR>, e.g. make diagnostic-bundle RUN=<repo>/docs/security"; exit 2; }
	@$(PYTHON) scripts/diagnostic_bundle.py collect --run "$(RUN)" --into "$(or $(INTO),.)" $(if $(REPO_ROOT),--repo-root "$(REPO_ROOT)",)

.PHONY: inspect-bundle
inspect-bundle:  ## Print a triage summary of a diagnostic bundle: make inspect-bundle BUNDLE=appsec-diag-<id>.tgz
	@test -n "$(BUNDLE)" || { echo "ERROR: set BUNDLE=<path to .tgz or unpacked dir>"; exit 2; }
	@$(PYTHON) scripts/diagnostic_bundle.py inspect --bundle "$(BUNDLE)"

# ─────────────────────────────────────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: help
help:  ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
