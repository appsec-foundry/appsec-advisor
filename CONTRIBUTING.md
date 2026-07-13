# Contributing

Agent and skill definitions are Markdown files. Python handles validation, rendering, exports, and runtime checks.

Read [`AGENTS.md`](AGENTS.md) before changing runtime behavior, schemas, prompts, or report output. It maps each type of change to the contracts and tests that must stay aligned.

## Submitting changes

Open an issue before substantial changes so the approach can be agreed before implementation. Typos and small fixes can go directly to a pull request.

1. Describe the problem and proposed behavior in an issue.
2. Open a focused pull request and link the issue.
3. Run the relevant tests and lint checks.
4. Complete the pull request template.

Maintainers are listed in [`.github/CODEOWNERS`](.github/CODEOWNERS) and review
all changes to `main`. Security issues follow a separate path — see
[Reporting security issues](#reporting-security-issues).

## Dev environment setup

Use isolated environments instead of installing development tools into the system Python.

**ruff** (linter/formatter):
```bash
pipx install 'ruff>=0.11.13,<0.13'   # needs: sudo apt install pipx
```
Use the pinned range so local results match CI.

**Test dependencies:**
```bash
python3 -m venv .venv
.venv/bin/pip install -r tests/requirements-test.txt
```

The `Makefile` uses `.venv/bin/python3` automatically.

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

Run the manual end-to-end check after changes to renderers, schemas, phase prompts, hooks, or pipeline control flow.

> [!IMPORTANT]
> This check calls Claude Code and consumes model budget. The synthetic quick fixture typically costs about $0.30–1.00 with API billing or 30–50% of a Pro five-hour usage window. It is not part of the normal CI suite.

```bash
make e2e-full
```

or, from inside a Claude Code session in this repository:

```text
/e2e-full
```

The driver runs the full pipeline against a clean synthetic repository and checks output schemas, evidence, exports, security boundaries, and expected findings.

Additional targets cover specific paths:

| Target | Purpose |
|---|---|
| `make e2e-full-standard` | Include the full QA stage. |
| `make e2e-full-thorough` | Include QA and architecture review. |
| `make e2e-full-repair` | Verify report repair after a deliberate corruption. |
| `make e2e-full-eval` | Add the semantic-quality evaluation. |

`make e2e-fixture-suite` checks all external language and architecture fixtures. It requires the sibling `appsec-advisor-fixtures` checkout.

Use `make e2e-full-keep` to rerun assertions against the previous E2E output without another model call.

Cross-repository behavior has a separate driver. See the [cross-repository fixture runbook](docs/internal/runbooks/e2e-cross-repo-fixture.md).

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
pytest tests/test_final_render_guards.py
pytest tests/test_sarif_validation.py
```

#### Deterministic end-to-end (no LLM)

`tests/test_e2e_pipeline.py` renders a frozen run and compares the Markdown and SARIF output with committed golden files.

After an intentional renderer, contract, or exporter change, inspect the diff and regenerate the goldens:

```bash
APPSEC_UPDATE_GOLDEN=1 python3 -m pytest tests/test_e2e_pipeline.py -k golden
```

Do not edit golden output by hand to hide a producer defect.

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

`threat_fixture.py` captures and replays completed runs without another scan. See the [threat fixture runbook](docs/internal/runbooks/threat-fixture.md).

`diagnostic_bundle.py` creates a scrubbed bundle for maintainer triage. Inspect every bundle before sharing it.

## Repository layout

| Path | What it is |
|------|-----------|
| `.claude-plugin/plugin.json` | Claude Code plugin manifest |
| `.claude/settings.json` | Contributor permission settings; `data/required-permissions.yaml` remains authoritative |
| `agents/` | Agent definitions (Markdown with YAML frontmatter) |
| `agents/phases/` | Phase-group reference files (authoritative phase instructions) |
| `agents/shared/` | Shared standards (logging format, validation routines) |
| `skills/` | User-invocable skills, one directory per skill (e.g. `create-threat-model`, `audit-security-requirements`, `status`, `publish-threat-model`, `export-threat-model`) |
| `hooks/` | Hook definitions + configurable steering keywords |
| `schemas/` | YAML/JSON schemas for intermediate files and output |
| `templates/` | Report templates (management summary, sections) |
| `data/` | Requirements, policy, and rule data |
| `scripts/` | Python helpers used by agents/hooks plus user-facing CLI wrappers (`run-headless.sh`, `harvest_requirements.py`, `mock-server.py`) |
| `tests/` | Pytest suite — agent definitions, integration, steering, SARIF, schemas |
| `examples/` | Reference threat model outputs (e.g. OWASP Juice Shop) |
| `docs/` | User and maintainer documentation |
| `config.json` | Plugin config (external context, pricing, logging) |

## Agent definition format

All agent `.md` files require YAML frontmatter with `name`, `description`, `tools`, `model`, and `maxTurns`. `tests/test_agent_definitions.py` enforces these constraints including turn-budget ceilings. Run that test after any frontmatter change.

## Code style

Python code in `scripts/`, `tests/`, and `hooks/` is linted and formatted with [ruff](https://docs.astral.sh/ruff/). The configuration lives in `pyproject.toml`. CI runs:

```bash
ruff check scripts/ tests/ hooks/
ruff format --check scripts/ tests/ hooks/
```

Run both locally before opening a pull request. `ruff check --fix` and `ruff format` can apply most fixes. Keep rule exceptions scoped and documented in `pyproject.toml`.

## Type hints

Add type hints to new public functions. `mypy` is not currently enforced.

## Adding components

When adding a new section to the generated threat model, see [`docs/internal/runbooks/adding-a-section.md`](docs/internal/runbooks/adding-a-section.md). It walks through the five registry maps that must stay aligned — those maps are documented at [`docs/internal/contracts/schema-invariants.md` §4f](docs/internal/contracts/schema-invariants.md#4f-fragment-registry-maps--single-source-of-truth).

## Reporting security issues

Do not open public issues for vulnerabilities. Use a [GitHub Security Advisory](../../security/advisories/new). See [`SECURITY.md`](SECURITY.md).
