# Makefile — minimal entry points for maintainer workflows.
# This is dev tooling, not a build system. The plugin itself ships no binaries.
#
# Run `make help` for an overview.

.DEFAULT_GOAL := help

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
e2e-full-standard:  ## Same as e2e-full but at standard depth (slower, higher fidelity)
	@command -v claude >/dev/null 2>&1 || { \
		echo "ERROR: 'claude' CLI not on PATH. Install Claude Code first."; exit 3; }
	@./tests/e2e/run-full.sh --depth standard

.PHONY: e2e-full-repair
e2e-full-repair:  ## QA-active variant: corrupt §7.2, resume with QA on, verify the real Re-Render Loop dispatches appsec-fragment-fixer (M2b) and converges
	@command -v claude >/dev/null 2>&1 || { \
		echo "ERROR: 'claude' CLI not on PATH. Install Claude Code first."; exit 3; }
	@./tests/e2e/run-repair.sh

.PHONY: e2e-full-keep
e2e-full-keep:  ## Re-run assertions against the previous _last-run/ output (no pipeline re-run)
	@APPSEC_E2E_FULL=1 \
	 APPSEC_E2E_OUTPUT_DIR="$(PWD)/tests/fixtures/e2e/_last-run" \
	 APPSEC_E2E_DEPTH=quick \
	 python3 -m pytest tests/test_full_run_e2e.py -v --tb=short

# ─────────────────────────────────────────────────────────────────────────────
# Fast unit tests (the per-PR safety net — runs in CI too)
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: test
test:  ## Run the standard pytest suite (no LLM, ~10s)
	@python3 -m pytest tests/ -v --tb=short

.PHONY: lint
lint:  ## Ruff check + format check
	@ruff check scripts/ tests/ hooks/
	@ruff format --check scripts/ tests/ hooks/

# ─────────────────────────────────────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: help
help:  ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
