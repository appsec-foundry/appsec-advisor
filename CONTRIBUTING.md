# Contributing

Development conventions for the appsec-advisor repository. The plugin is the repo — there is no build system, and agent and skill definitions are plain Markdown files you edit directly.

Agent runtime behaviour — phases, output format, reliability features — is documented in [`CLAUDE.md`](CLAUDE.md), which Claude Code loads into the agent context at runtime.

## Commands

### Tests

```bash
pytest tests/                              # all tests
pytest tests/test_agent_definitions.py     # agent frontmatter validation
pytest tests/test_security_steering.py     # steering hook logic
pytest tests/test_sarif_validation.py      # SARIF v2.1.0 compliance
pytest tests/ -v --cov                     # with coverage
```

Test dependencies: `tests/requirements-test.txt` (pytest, pytest-cov, pyyaml).

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
python3 scripts/harvest-requirements.py           # regenerate fallback requirements YAML
```

## Repository layout

| Path | What it is |
|------|-----------|
| `.claude-plugin/plugin.json` | Plugin manifest — required by Claude Code |
| `.claude/settings.json` | Contributor-convenience permission allow-list for working on this repo in Claude Code. Mirrors `data/required-permissions.yaml` (the single source of truth). End-users install permissions via `/appsec-advisor:check-permissions --update`; the committed file is **not** what ships to end-users. Drift between the two is caught by `tests/test_check_permissions.py`. |
| `agents/` | Agent definitions (Markdown with YAML frontmatter) |
| `agents/phases/` | Phase-group reference files (authoritative phase instructions) |
| `agents/shared/` | Shared standards (logging format, validation routines) |
| `skills/` | User-invocable skills: `create-threat-model`, `audit-security-requirements` |
| `hooks/` | Hook definitions + configurable steering keywords |
| `schemas/` | YAML/JSON schemas for intermediate files and output |
| `templates/` | Report templates (management summary, sections) |
| `data/` | Reference data — requirements baseline, CWE eligibility lists, heuristics |
| `scripts/` | Python helpers used by agents/hooks plus user-facing CLI wrappers (`run-headless.sh`, `harvest-requirements.py`, `mock-server.py`) |
| `tests/` | Pytest suite — agent definitions, integration, steering, SARIF, schemas |
| `examples/` | Reference threat model outputs (e.g. OWASP Juice Shop) |
| `docs/` | Cross-cutting documentation |
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

When adding a new section to the generated threat model, see [`docs/adding-a-section.md`](docs/adding-a-section.md). It walks through the five registry maps that must stay aligned — those maps are documented at [`docs/schema-invariants.md` §4f](docs/schema-invariants.md#4f-fragment-registry-maps--single-source-of-truth).

## Reporting security issues

Do not open public issues for vulnerabilities. Use a [GitHub Security Advisory](../../security/advisories/new). See [`SECURITY.md`](SECURITY.md).
