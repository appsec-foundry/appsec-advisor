# Contributing

Development conventions for the appsec-advisor repository. The plugin is the repo — there is no build system, and agent and skill definitions are plain Markdown files you edit directly.

Agent runtime behaviour — phases, output format, reliability features — is documented in [`CLAUDE.md`](CLAUDE.md), which Claude Code loads into the agent context at runtime.

## Submitting changes

Contributions are welcome! A quick heads-up first: this is a small project with
a tightly coupled producer/schema/consumer/test contract (see `AGENTS.md`), so
**where possible, please open an issue to discuss your idea before sending a
pull request.** A short conversation up front saves you wasted effort and helps
us land your change smoothly — it's a friendly request, not a hard gate.

<!-- TODO: not active yet — enable once feature-branch workflow is adopted
**Branching:** never commit directly to `main`. Do all work on **feature
branches** (`feat/<topic>` or `fix/<topic>`), then open a PR against `main`.
`main` holds releases and is tagged (`v*`) to publish; CI runs on pushes and PRs
to `main` (and `dev`).
-->

A good flow looks like:

1. **Open an issue** (bug report or feature/change proposal) describing what you
   want to change and why. For anything beyond a typo or obvious fix, it's worth
   agreeing on the approach first.
2. **Then open a PR** and link it to the issue. Keep the change surgical and
   scoped to what you described.
3. Run the targeted tests and `ruff` (below) before pushing, and fill in the PR
   template.

Maintainers are listed in [`.github/CODEOWNERS`](.github/CODEOWNERS) and review
all changes to `main`. Security issues follow a separate path — see
[Reporting security issues](#reporting-security-issues).

## Dev environment setup

On Debian/Ubuntu the system Python is externally managed — install tools into isolated environments rather than system-wide.

**ruff** (linter/formatter):
```bash
pipx install 'ruff>=0.11.13,<0.13'   # needs: sudo apt install pipx
```
The version is pinned so the lint gate behaves identically across machines —
unpinned ruff drifts rules on and off between versions (e.g. UP038 is enforced
in <0.12 but deprecated in >=0.12).

**Test dependencies** — create a project venv once, then `make` picks it up automatically:
```bash
python3 -m venv .venv
.venv/bin/pip install -r tests/requirements-test.txt
```

The `Makefile` detects `.venv/bin/python3` and uses it automatically, so plain `make test` / `make release-check` work without any extra prefix after this.

## Commands

### Tests

```bash
make test                                  # standard suite with coverage
pytest tests/                              # all tests (uses active venv/PATH python)
pytest tests/test_agent_definitions.py     # agent frontmatter validation
pytest tests/test_security_steering.py     # steering hook logic
pytest tests/test_sarif_validation.py      # SARIF v2.1.0 compliance
```

Test dependencies: `tests/requirements-test.txt` (pytest, pytest-cov, pyyaml, jsonschema, jinja2).

#### Manual full-run (end-to-end) test

After a non-trivial refactor (renderer changes, schema bumps, phase-group edits, prompt restructures, hook changes), run the bundled end-to-end check. It exercises the full pipeline against a clean copy of a code-bearing synthetic fixture and validates structural, grounding, export, orchestration, and planted-signal invariants.

> [!IMPORTANT]
> This check is **manual-only**. It is deliberately not wired into PR triggers, push hooks, or cron — it consumes real LLM budget (~30–50% of a Pro 5h subscription window, or ~$0.30–1.00 with API-key billing on `quick` depth). The standard `pytest tests/` suite (~50 deterministic tests) remains your per-PR safety net.

```bash
make e2e-full
```

or, from inside a Claude Code session in this repository:

```text
/e2e-full
```

Both routes drive `tests/e2e/run-full.sh`, which:

1. Pre-flights the `claude` CLI (uses subscription auth via `~/.claude/` or `ANTHROPIC_API_KEY` if set).
2. Copies `tests/fixtures/e2e/synthetic-repo/` to the clean, git-ignored `_last-repo/`, strips stale `docs/security/`, and initializes it as a standalone Git worktree so parent-repo discovery cannot contaminate recon.
3. Invokes `pytest tests/test_full_run_e2e.py`, which is skipped unless the driver sets `APPSEC_E2E_FULL=1`.

**What's asserted:**

| Group | Checks |
|---|---|
| Existence | Canonical outputs, audit logs, resolved config, dispatch manifest, render-integrity certificate, run issues, checkpoint, and incremental baseline are present. |
| Schemas | Final YAML, pentest tasks, merged/triage/config/source-auth artifacts, every dispatched STRIDE result, and every structured fragment validate. |
| Renderer | `compose_threat_model.render()` has zero warnings and is byte-idempotent; `.render-integrity.json` reports 100%, no degraded or empty sections. |
| Hard Gate | `check_inline_shortcut.py` confirms Stage 2 routed through the deterministic renderer (no LLM bypass). |
| QA and completeness | The full `qa_checks.py all` battery is clean and idempotent; build/render completeness contracts pass. |
| Grounding and recall | Evidence resolves against real fixture code and the out-of-repo oracle meets its planted-vulnerability recall floor. |
| Security | Raw fixture secret canaries do not leak, and malicious repository text cannot create its requested sentinel file. |
| Exports | SARIF is v2.1-valid with exact result parity; pentest tasks are schema-valid, linked, unique, and read-only; attempted HTML/PDF exports must succeed. |
| Audit trail | Expected agents and all manifest-selected STRIDE analyzers ran on the resolved model; checkpoint and run-issue state are clean. |

**Exit codes:**

| Code | Meaning |
|---|---|
| 0 | Pipeline + assertions passed |
| 1 | Pipeline failed (`run-headless.sh` non-zero) |
| 2 | Pipeline succeeded but assertions failed |
| 3 | Pre-flight failed (missing `claude` CLI or fixture) |

`make e2e-full-standard` enables the real Stage-3 QA path. `make e2e-full-thorough` additionally requires the Stage-4 architect review. `make e2e-full-repair` first creates a clean standard seed, corrupts §7, and verifies that the live fragment-fixer loop converges. `make e2e-full-eval` adds the five-dimension judge/verify semantic-quality gate and fails on confirmed High/Critical model defects.

`make e2e-fixture-suite` runs all six external language/architecture fixtures through their out-of-repo recall oracles. It is the nightly/manual breadth gate and requires the sibling `appsec-advisor-fixtures` checkout.

**Re-checking without a fresh run:** `make e2e-full-keep` replays the assertions against the previous `_last-run/` artifacts and retained `_last-repo/`. Driver metadata preserves the original depth and converter expectations.

**Additional manual fixture:** Cross-repo context has its own opt-in driver,
`scripts/e2e_cross_repo_fixture.sh`, backed by the external
`../appsec-advisor-fixtures/repos/cross-repo-threat-fixture/` suite. It is not
part of the standard test run; `tests/test_e2e_cross_repo_fixture_script.py`
only checks the driver contract. See
[`docs/internal/runbooks/e2e-cross-repo-fixture.md`](docs/internal/runbooks/e2e-cross-repo-fixture.md) for the
manual run command.

#### Targeted tests before finishing a non-trivial change

Run the relevant subset from repo root. For any non-trivial change:

```bash
python3 scripts/validate_config.py
pytest tests/test_contract_integrity.py
pytest tests/test_schema_integrity.py
pytest tests/test_runtime_cleanup.py
pytest tests/test_agent_definitions.py
```

For renderer or report-structure changes, also run:

```bash
pytest tests/test_compose_threat_model.py
pytest tests/test_render_properties.py
pytest tests/test_reference_parity.py
pytest tests/test_sarif_validation.py
```

#### Deterministic end-to-end (no LLM)

`tests/test_e2e_pipeline.py` runs in `make test`. It renders the frozen fixture
(`tests/fixtures/e2e/frozen-run/`) and checks the result against a golden copy
in `tests/fixtures/e2e/golden/` — every section present, no broken output, and
`threat-model.md` / `threat-model.sarif.json` byte-for-byte as expected.

If you change a renderer, contract, or exporter on purpose, the golden tests
will fail. Check the diff is what you intended, then regenerate the goldens:

```bash
APPSEC_UPDATE_GOLDEN=1 python3 -m pytest tests/test_e2e_pipeline.py -k golden
```

Don't edit a golden by hand to make the test pass — fix the producer.

If the repo already has failing tests, capture the baseline and clearly distinguish pre-existing failures from new failures caused by the current change. Do not normalize or hide new failures. When targeted tests fail outside touched files, report failing test names and error heads instead of stale global counts.

### Validation scripts

```bash
python3 scripts/validate_config.py .              # config schema validation
python3 scripts/validate_intermediate.py <file.json>  # intermediate file schema
```

### Development utilities

```bash
python3 scripts/mock-server.py [port]             # mock REST endpoints: context + requirements (default 4444)
./scripts/run-headless.sh --repo /path --output /out --yaml --sarif
python3 scripts/harvest_requirements.py           # regenerate fallback requirements YAML
python3 scripts/threat_fixture.py freeze --run /out --into tests/fixtures/golden/<name> --repo /path
python3 scripts/threat_fixture.py replay --fixture tests/fixtures/golden/<name> --repo /path
python3 scripts/diagnostic_bundle.py collect --run /out --into . --repo-root /path  # user → maintainer
python3 scripts/diagnostic_bundle.py inspect --bundle appsec-diag-<id>.tgz          # maintainer triage
```

`threat_fixture.py` snapshots a completed run into a golden-master fixture and
replays the deterministic tail (build-yaml → compose → SARIF + scanners) to
detect the effect of code changes across repos without re-scanning. See
[`docs/internal/runbooks/threat-fixture.md`](docs/internal/runbooks/threat-fixture.md).

`diagnostic_bundle.py` builds an **anonymised** `.tgz` a user can send the
maintainer to triage a pipeline error. It contains only tool/plugin versions,
run shape (phases reached, stage timings, aggregate count histograms), a
metadata-only file inventory (name/size/sha — never contents), and the run logs
with paths/quoted-strings/secrets scrubbed. It never includes the threat-model
results, finding evidence, component names, or any source. (Contrast
`threat_fixture.py`, which captures a full replayable fixture for your own or
consented repos.) `make diagnostic-bundle RUN=/out` / `make inspect-bundle BUNDLE=…`.

## Repository layout

| Path | What it is |
|------|-----------|
| `.claude-plugin/plugin.json` | Plugin manifest — required by Claude Code |
| `.claude/settings.json` | Contributor-convenience permission allow-list for working on this repo in Claude Code. Mirrors `data/required-permissions.yaml` (the single source of truth). End-users install permissions via `/appsec-advisor:check-permissions --update`; the committed file is **not** what ships to end-users. Drift between the two is caught by `tests/test_check_permissions.py`. |
| `agents/` | Agent definitions (Markdown with YAML frontmatter) |
| `agents/phases/` | Phase-group reference files (authoritative phase instructions) |
| `agents/shared/` | Shared standards (logging format, validation routines) |
| `skills/` | User-invocable skills, one directory per skill (e.g. `create-threat-model`, `audit-security-requirements`, `status`, `publish-threat-model`, `export-threat-model`) |
| `hooks/` | Hook definitions + configurable steering keywords |
| `schemas/` | YAML/JSON schemas for intermediate files and output |
| `templates/` | Report templates (management summary, sections) |
| `data/` | Reference data — requirements baseline, CWE eligibility lists, heuristics |
| `scripts/` | Python helpers used by agents/hooks plus user-facing CLI wrappers (`run-headless.sh`, `harvest_requirements.py`, `mock-server.py`) |
| `tests/` | Pytest suite — agent definitions, integration, steering, SARIF, schemas |
| `examples/` | Reference threat model outputs (e.g. OWASP Juice Shop) |
| `docs/` | Cross-cutting reference documentation (handwritten, durable) |
| `docs/analysis/` | Agent-authored analyses and plans (`analysis-*`, `plan-*`, `proposal-*`) — design/investigation write-ups, kept separate from the durable reference docs above |
| `docs/internal/analysis/` | Earlier agent-authored analyses and proposals — same nature as `docs/analysis/`, older write-ups |
| `config.json` | Plugin config (external context, pricing, logging) |

## Agent definition format

All agent `.md` files require YAML frontmatter with `name`, `description`, `tools`, `model`, and `maxTurns`. `tests/test_agent_definitions.py` enforces these constraints including turn-budget ceilings. Run that test after any frontmatter change.

## Code style

Python code in `scripts/`, `tests/`, and `hooks/` is linted and formatted with [ruff](https://docs.astral.sh/ruff/). The configuration lives in `pyproject.toml`. CI runs:

```bash
ruff check scripts/ tests/ hooks/
ruff format --check scripts/ tests/ hooks/
```

Run both locally before opening a PR; `ruff check --fix` and `ruff format` auto-apply most fixes. Disabled rules are listed in `pyproject.toml` with a short rationale per family — re-enable case-by-case when adding fresh code, don't bulk-modernise the 47k-LOC backlog. `scripts/resolve_config.py` is excluded from `ruff format` because its column-aligned dicts are asserted by `tests/test_incremental_mode.py` as a doc-invariant.

## Type hints

New public functions take type hints. The existing surface is partly typed; we don't backfill aggressively. `mypy` is not yet enforced — checking is by reading and by ruff `F`/`UP` rules where they apply.

## Adding components

When adding a new section to the generated threat model, see [`docs/internal/runbooks/adding-a-section.md`](docs/internal/runbooks/adding-a-section.md). It walks through the five registry maps that must stay aligned — those maps are documented at [`docs/internal/contracts/schema-invariants.md` §4f](docs/internal/contracts/schema-invariants.md#4f-fragment-registry-maps--single-source-of-truth).

## Reporting security issues

Do not open public issues for vulnerabilities. Use a [GitHub Security Advisory](../../security/advisories/new). See [`SECURITY.md`](SECURITY.md).
