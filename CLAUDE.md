# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Claude Code plugin for automated STRIDE-based threat modeling. No build system — agent/skill definitions are plain Markdown files. Edit them directly.

For plugin behavior, agent architecture, output format, and reliability features, see `plugin/CLAUDE.md`. That file is loaded into agent context at runtime.

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
python3 plugin/scripts/validate_config.py plugin/           # config schema validation
python3 plugin/scripts/validate_intermediate.py <file.json>  # intermediate file schema
```

### Development utilities

```bash
python3 scripts/mock-context-server.py [port]  # mock REST endpoint (default 4444)
./scripts/run-headless.sh --repo /path --output /out --yaml --sarif  # CI/CD execution
python3 scripts/harvest-requirements.py        # regenerate fallback requirements YAML
```

## Repository Layout

- `plugin/` — the installable Claude Code plugin (loaded via `claude --plugin-dir`)
  - `agents/` — agent definitions (Markdown with YAML frontmatter)
  - `agents/phases/` — phase-group reference files (authoritative phase instructions)
  - `agents/shared/` — shared standards (logging format, validation routines)
  - `skills/` — user-invocable skills: `create-threat-model`, `check-appsec-requirements`
  - `hooks/` — hook definitions + configurable steering keywords
  - `scripts/` — Python hook scripts (steering, logging, validation)
  - `config.json` — plugin config (external context, pricing, logging)
  - `CLAUDE.md` — plugin runtime documentation (agent behavior, phases, output features)
- `tests/` — pytest suite (agent definitions, integration, steering, SARIF, schemas)
- `scripts/` — development scripts (headless runner, requirements harvester, mock server)
- `examples/` — reference threat model outputs

## Agent Definition Format

All agent `.md` files require YAML frontmatter with `name`, `description`, `tools`, `model`, and `maxTurns`. The `test_agent_definitions.py` test enforces these constraints including turn budget ceilings. When changing an agent's frontmatter, run that test to verify.
