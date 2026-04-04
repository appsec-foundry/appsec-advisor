# appsec-plugin

A Claude Code plugin for automated, STRIDE-based application security threat modeling. Analyzes a repository using a pipeline of specialized sub-agents and produces two output files: a human-readable threat model document and a machine-readable YAML export.

## Prerequisites

The MCP context server must be running **before** loading the plugin.

```bash
# Start the context server (keep running in a separate terminal)
./mcp/appsec-context/start.sh
```

It listens on `http://127.0.0.1:4444/mcp` and is registered automatically via `.mcp.json` when the plugin is loaded.

## Installation

```bash
# Load the plugin (in a second terminal, after the MCP server is up)
claude --plugin-dir /path/to/appsec-plugin
```

## Usage

```
# Full assessment of the current repository
/appsec-plugin:create-threat-model

# With scope constraint
/appsec-plugin:create-threat-model focus on the authentication service

# Incremental update of an existing threat model
/appsec-plugin:update-threat-model

# Check security requirements coverage
/appsec-plugin:check-appsec-requirements
```

## Output

Each run writes two files to the analyzed repository:

### `docs/security/threat-model.md`

Human-readable canonical document with colored severity badges (Critical / High / Medium / Low) and VS Code deep links to every referenced source file.

| Section | Content |
|---------|---------|
| Metadata | Generated date/time, duration, model, token note |
| 1. System Overview | Description, team, compliance scope, asset classification |
| 2. Architecture Diagrams | C4 context/container/component diagrams + technology architecture (Mermaid) |
| 3. Security Use Cases | Sequence diagrams for auth, authorization, and critical flows |
| 4. Assets | Data, code/IP, infrastructure, and availability assets |
| 5. Attack Surface | All entry points with protocol, auth requirements |
| 6. Trust Boundaries | Where trust levels change across the system |
| 7. Security Controls | Existing controls with colored effectiveness badges |
| 8. Threat Register | STRIDE threats with likelihood, impact, risk, and mitigations |
| 9. Critical Findings | Top highest-risk threats requiring immediate action |
| 10. Recommended Controls | Prioritized remediation list |
| 11. Out of Scope | What was not analyzed |

### `threat-model.yaml`

Machine-readable export — suitable for ingestion into ticketing systems, dashboards, or CI/CD pipelines.

```yaml
meta:
  project: my-service
  generated: 2026-04-03T14:32:11Z
  model: claude-opus-4-6
  compliance_scope: [PCI-DSS, SOC2]
threats:
  - id: T-001
    stride: Spoofing
    likelihood: High
    impact: Critical
    risk: Critical
```

> Token and cost fields are `null` at runtime — agents cannot introspect their own API usage. Check the Anthropic Console for session details.

## Agent Pipeline

The plugin uses a 5-agent pipeline. Only `appsec-threat-analyst` is user-facing; the rest are dispatched internally.

```
User
 └─ appsec-threat-analyst (Opus, orchestrator)
     ├─ appsec-context-resolver  (Sonnet) ← Phase 0, before user questions
     ├─ appsec-dep-scanner       (Sonnet) ← after Phase 1 (Recon)
     ├─ appsec-stride-analyzer   (Sonnet) ← after Phase 6, one instance per component
     └─ appsec-qa-reviewer       (Sonnet) ← Phase 10, after all output is written
```

| Agent | Model | Role |
|-------|-------|------|
| `appsec-threat-analyst` | Opus | Orchestrator. Runs all 10 phases, dispatches sub-agents, writes final output. |
| `appsec-context-resolver` | Sonnet | Calls the MCP context server and merges pre-existing AppSec knowledge into `docs/security/threat-modeling-context.md`. |
| `appsec-dep-scanner` | Sonnet | Scans for hardcoded secrets, vulnerable dependencies, and insecure defaults. Writes `.dep-scan.json`. |
| `appsec-stride-analyzer` | Sonnet | Performs focused STRIDE analysis for a single component. Writes `.stride-<component>.json`. One instance per major component, run in parallel. |
| `appsec-qa-reviewer` | Sonnet | Verifies the finished threat model: checks links, cross-references, YAML/MD consistency, placeholders, section completeness, and diagrams. Fixes issues in-place. |

### Orchestrator phases

| Phase | Description |
|-------|-------------|
| 0. Context Lookup | `appsec-context-resolver` fetches pre-existing AppSec knowledge before any user questions |
| 1. Reconnaissance | Maps tech stack, directory structure, deployment configs, CI/CD pipeline; triggers `appsec-dep-scanner` |
| 2. Architecture Modeling | C4 diagrams (context / container / component) + technology architecture diagram |
| 3. Security Use Cases | Sequence diagrams for auth flow, access control, and other critical flows |
| 4. Asset Identification | Catalogs data, code/IP, infrastructure, and availability assets |
| 5. Attack Surface Mapping | Enumerates API endpoints, auth mechanisms, file uploads, inter-service calls |
| 6. Trust Boundary Analysis | Identifies privilege and network boundary crossings; triggers `appsec-stride-analyzer` per component |
| 7. Security Controls | Catalogs existing controls by domain with colored effectiveness rating |
| 8. Threat Enumeration | Merges STRIDE JSON files from sub-agents, assigns global T-xxx IDs, rates risk |
| 9. Output Writing | Writes `docs/security/threat-model.md` and `threat-model.yaml` |
| 10. QA Review | `appsec-qa-reviewer` verifies and fixes links, references, consistency, diagrams |

### Intermediate files

Sub-agents communicate via files in `docs/security/` (gitignored by default):

| File | Written by | Read by |
|------|-----------|---------|
| `docs/security/threat-modeling-context.md` | `appsec-context-resolver` | orchestrator, `appsec-stride-analyzer` |
| `docs/security/.dep-scan.json` | `appsec-dep-scanner` | orchestrator (Phase 8) |
| `docs/security/.stride-<id>.json` | `appsec-stride-analyzer` | orchestrator (Phase 8) |

## MCP Context Server

**Tool:** `get_repo_context(repo_url)` — returns team ownership, asset classification, compliance scope, prior findings, known exceptions, and architecture notes.

**Transport:** Streamable HTTP on `http://127.0.0.1:4444/mcp`

**Pattern matching (mock data):**

| URL pattern | Context returned |
|-------------|-----------------|
| `payment\|checkout\|billing` | PCI-DSS / Payments Platform — Tier 1 |
| `auth\|identity\|sso\|oauth` | SOC2 / IAM — Tier 1 |
| `health\|medical\|patient\|ehr` | HIPAA / Clinical Data — Tier 1 |
| anything else | SOC2 default — Tier 2 |

**Starting the server:**

```bash
# Option A — shell script (auto-installs Node.js dependencies)
./mcp/appsec-context/start.sh

# Option B — Docker
docker build -t appsec-context-mcp ./mcp/appsec-context
docker run -p 4444:4444 --rm appsec-context-mcp
```

## `check-appsec-requirements` skill

Scans the repository for `[SEC-*]` requirement tags, verifies each is implemented correctly, and writes `docs/security/appsec-requirements-report.md`.

The baseline requirements file covers 57 requirements across 8 categories: input validation (SEC-INV), encryption (SEC-ENC), authentication (SEC-AUTH), authorization (SEC-AUTHZ), data handling (SEC-DATA), error handling (SEC-ERR), content security policy (SEC-CSP), and hardening (SEC-HARD).

A remote requirements URL can be configured in `skills/check-appsec-requirements/config.json`.

## Plugin Structure

```
appsec-plugin/
├── .claude-plugin/
│   └── plugin.json                        # Plugin manifest
├── .mcp.json                              # MCP server registration
├── agents/
│   ├── appsec-threat-analyst.md           # Orchestrator (Opus, 50 turns)
│   ├── appsec-context-resolver.md         # MCP context sub-agent (Sonnet)
│   ├── appsec-dep-scanner.md              # Dependency/secret scan sub-agent (Sonnet)
│   ├── appsec-stride-analyzer.md          # Per-component STRIDE sub-agent (Sonnet)
│   └── appsec-qa-reviewer.md              # QA verification sub-agent (Sonnet)
├── skills/
│   ├── create-threat-model/
│   │   └── SKILL.md                       # /appsec-plugin:create-threat-model
│   ├── update-threat-model/
│   │   └── SKILL.md                       # /appsec-plugin:update-threat-model
│   └── check-appsec-requirements/
│       ├── SKILL.md                       # /appsec-plugin:check-appsec-requirements
│       ├── config.json                    # Requirements source config
│       └── web-security-requirements.md  # Baseline (57 requirements, 8 categories)
├── mcp/
│   └── appsec-context/
│       ├── index.js                       # HTTP MCP server
│       ├── package.json
│       ├── start.sh                       # Startup script
│       └── Dockerfile
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
└── README.md
```

## License

MIT — see [LICENSE](LICENSE).
