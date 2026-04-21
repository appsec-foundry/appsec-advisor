# Contributing

Development conventions for the appsec-plugin repository. The plugin is the repo — there is no build system, and agent and skill definitions are plain Markdown files you edit directly.

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

### Validation scripts

```bash
python3 scripts/validate_config.py .              # config schema validation
python3 scripts/validate_intermediate.py <file.json>  # intermediate file schema
```

### Development utilities

```bash
python3 scripts/mock-context-server.py [port]     # mock REST endpoint (default 4444)
./scripts/run-headless.sh --repo /path --output /out --yaml --sarif
python3 scripts/harvest-requirements.py           # regenerate fallback requirements YAML
```

## Repository layout

| Path | What it is |
|------|-----------|
| `.claude-plugin/plugin.json` | Plugin manifest — required by Claude Code |
| `.claude/settings.json` | Plugin-level Bash permission allow-list |
| `agents/` | Agent definitions (Markdown with YAML frontmatter) |
| `agents/phases/` | Phase-group reference files (authoritative phase instructions) |
| `agents/shared/` | Shared standards (logging format, validation routines) |
| `skills/` | User-invocable skills: `create-threat-model`, `check-appsec-requirements` |
| `hooks/` | Hook definitions + configurable steering keywords |
| `schemas/` | YAML/JSON schemas for intermediate files and output |
| `templates/` | Report templates (management summary, sections) |
| `data/` | Reference data — requirements baseline, CWE eligibility lists, heuristics |
| `scripts/` | Python helpers used by agents/hooks plus user-facing CLI wrappers (`run-headless.sh`, `harvest-requirements.py`, `mock-context-server.py`) |
| `tests/` | Pytest suite — agent definitions, integration, steering, SARIF, schemas |
| `examples/` | Reference threat model outputs (e.g. OWASP Juice Shop) |
| `docs/` | Cross-cutting documentation |
| `config.json` | Plugin config (external context, pricing, logging) |

## Agent definition format

All agent `.md` files require YAML frontmatter with `name`, `description`, `tools`, `model`, and `maxTurns`. `tests/test_agent_definitions.py` enforces these constraints including turn-budget ceilings. Run that test after any frontmatter change.

## Reporting security issues

Do not open public issues for vulnerabilities. Use a [GitHub Security Advisory](../../security/advisories/new). See [`SECURITY.md`](SECURITY.md).
