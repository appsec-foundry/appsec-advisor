# Claude AppSec Plugin

> **Status: 0.10.0-beta** — Functionally complete for guided use by AppSec teams.

A Claude Code plugin for AppSec and dev teams. Point it at any repository to generate a STRIDE-based threat model — with C4 architecture diagrams, a prioritized threat register, and actionable mitigations grounded in the actual codebase.

**What you get:**
- `threat-model.md` — human-readable report with severity badges and VS Code deep links
- `threat-model.yaml` — machine-readable export for ticketing systems and dashboards
- `threat-model.sarif.json` — SARIF v2.1.0 for GitHub Code Scanning, SonarQube, DefectDojo

## Installation

```bash
claude --plugin-dir /path/to/appsec-plugin/plugin
```

That's it. Optional integrations (external context, security requirements) can be enabled independently — see [Configuration](docs/configuration.md).

## Quick Start

### Create a threat model

```
/appsec-plugin:create-threat-model
```

Output goes to `docs/security/threat-model.md` in the current repo.

### Focus on a specific area

```
/appsec-plugin:create-threat-model focus on the authentication service
```

### Include exports for CI/CD

```
/appsec-plugin:create-threat-model --yaml --sarif
```

### Analyze an external repo (AppSec team)

```
/appsec-plugin:create-threat-model --repo /path/to/team-frontend --output /appsec-reports/team-frontend
```

### Preview before a full run

```
/appsec-plugin:create-threat-model --dry-run
```

### Incremental analysis after code changes

```
/appsec-plugin:create-threat-model --incremental
```

### Check security requirements compliance

```
/appsec-plugin:check-appsec-requirements
```

## Output

Each run writes files to the output directory (`docs/security/` by default, or the path specified with `--output`).

| Section | Content |
|---------|---------|
| 1. System Overview | Description, team, compliance scope, asset classification |
| 2. Architecture Diagrams | C4 context/container/component diagrams + technology architecture (Mermaid) |
| 3. Security Use Cases | Sequence diagrams for auth, authorization, and critical flows |
| 4. Assets | Data, code/IP, infrastructure, and availability assets |
| 5. Attack Surface | All entry points with protocol, auth requirements |
| 6. Trust Boundaries | Where trust levels change across the system |
| 7. Security Controls | Existing controls with effectiveness ratings |
| 7b. Requirements Compliance | *(only with `--requirements`)* Per-requirement PASS/PARTIAL/FAIL with evidence |
| 8. Threat Register | STRIDE threats with likelihood, impact, risk, and mitigations |
| 9. Critical Findings | Top highest-risk threats requiring immediate action |
| 10. Mitigation Register | Prioritized remediation list |
| 11. Out of Scope | What was not analyzed |

**YAML export** (with `--yaml`):

```yaml
meta:
  project: my-service
  generated: 2026-04-03T14:32:11Z
  model: claude-sonnet-4-6
  compliance_scope: [PCI-DSS, SOC2]
threats:
  - id: T-001
    stride: Spoofing
    likelihood: High
    impact: Critical
    risk: Critical
```

**SARIF export** (with `--sarif`) — integrates with GitHub Code Scanning, Azure DevOps, SonarQube, DefectDojo, Semgrep, and any SARIF-consuming tool.

> Token and cost fields are `null` at runtime — agents cannot introspect their own API usage. Check the Anthropic Console for session details. The hook logger estimates costs per session using configurable rates (see `pricing` in `plugin/config.json`).

## Common Flags

| Flag | Description |
|------|-------------|
| `--repo <path>` | Repository to analyze (default: current directory) |
| `--output <path>` | Output directory (default: `<repo>/docs/security`) |
| `--yaml` | Also write `threat-model.yaml` |
| `--sarif` | Also write `threat-model.sarif.json` |
| `--requirements` | Include requirements compliance check (Phase 8b) |
| `--with-sca` | Run SCA dependency vulnerability scan |
| `--dry-run` | Preview scope without running the full pipeline |
| `--incremental` | Delta analysis based on git diff since last assessment |
| `--resume` | Continue from the last checkpoint after a failed run |
| `--assessment-depth <level>` | `quick` / `standard` (default) / `thorough` |
| `--stride-model <model>` | Override STRIDE analyzer model (e.g. `opus`, ~5x cost) |

Full reference with all flags (interactive + headless): **[docs/flags-reference.md](docs/flags-reference.md)**

## Further Documentation

| Document | Content |
|----------|---------|
| **[Architecture](docs/architecture.md)** | Agent pipeline, orchestrator phases, intermediate files, reliability features, plugin structure |
| **[Configuration](docs/configuration.md)** | External context endpoint, known threats input, security requirements, steering hook |
| **[Headless Mode / CI/CD](docs/headless-mode.md)** | Non-interactive execution, use cases, GitHub Actions examples |
| **[Flag Reference](docs/flags-reference.md)** | Complete flag table (interactive + headless) |
| **[Harvester](docs/harvester.md)** | Requirements crawler config, scheduling, indexing modes |
| **[Model Comparison](docs/comparison-sonnet-opus.md)** | Sonnet vs Opus quality/cost trade-offs |

## Plugin Structure (Overview)

```
appsec-plugin/
├── plugin/                  # Plugin root — pass to --plugin-dir
│   ├── agents/              # 7 agent definitions (Markdown with YAML frontmatter)
│   ├── skills/              # User-invocable skills (create-threat-model, check-appsec-requirements)
│   ├── hooks/               # Security steering hook + configurable keywords
│   ├── scripts/             # Python hook scripts (steering, logging, validation)
│   ├── data/                # Fallback requirements YAML
│   └── config.json          # External context, pricing, logging config
├── docs/                    # Documentation subpages
├── examples/                # Reference threat model outputs (OWASP Juice Shop)
├── scripts/                 # Dev tools (headless runner, mock server, requirements harvester)
└── tests/                   # Pytest suite (440 tests)
```

Full directory tree: **[docs/architecture.md#plugin-structure](docs/architecture.md#plugin-structure)**
