# appsec-plugin

A Claude Code plugin for automated, STRIDE-based application security threat modeling. Analyzes a repository and produces two output files: a human-readable threat model document and a machine-readable YAML export.

## Prerequisites

The MCP context server must be running **before** loading the plugin. It listens on `http://127.0.0.1:4444/mcp` and is registered automatically via `.mcp.json` when the plugin is loaded.

```bash
# Start the context server (keep running in a separate terminal)
./mcp/appsec-context/start.sh
```

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

# Invoke the agent directly
/agents invoke appsec-threat-analyst
```

## Output

Each run writes two files to the analyzed repository:

### `docs/security/threat-model.md`
Human-readable canonical document. Includes a metadata header with timestamp, analysis duration, and model used.

| Section | Content |
|---------|---------|
| Metadata | Generated date/time, duration, model, token note |
| 1. System Overview | Description, team, compliance scope, asset classification |
| 2. Architecture Diagrams | C4 context, container, and component diagrams (Mermaid) |
| 3. Security Use Cases | Sequence diagrams for auth, authz, and other critical flows |
| 4. Assets | Data, code/IP, infrastructure, availability assets |
| 5. Attack Surface | All entry points with protocol, auth requirements |
| 6. Trust Boundaries | Where trust levels change across the system |
| 7. Security Controls | Existing controls by domain with effectiveness rating |
| 8. Threat Register | STRIDE threats with likelihood, impact, risk, mitigations |
| 9. Critical Findings | Top 5 highest-risk threats requiring immediate action |
| 10. Recommended Controls | Prioritized remediation list (Critical / High / Medium / Low) |
| 11. Out of Scope | What was not analyzed |

### `threat-model.yaml`
Machine-readable export of the same data — suitable for ingestion into ticketing systems, dashboards, or CI/CD pipelines.

```yaml
meta:
  project: my-service
  generated: 2026-04-03T14:32:11Z
  analysis_duration_seconds: 262
  model: claude-sonnet-4-6
  tokens: { input: null, output: null, cache_read: null, cache_write: null }
  estimated_cost_usd: null
  compliance_scope: [PCI-DSS, SOC2]
  ...
threats:
  - id: T-001
    stride: Spoofing
    likelihood: High
    impact: Critical
    risk: Critical
    ...
```

> Token and cost fields are `null` at runtime — agents cannot introspect their own API usage. Check the Anthropic Console for session details.

## Agent: `appsec-threat-analyst`

Runs 9 phases in order:

| Phase | Description |
|-------|-------------|
| 0. Context Lookup | Queries the MCP context server for pre-existing AppSec knowledge (findings, compliance scope, team, exceptions) |
| 1. Reconnaissance | Maps tech stack, directory structure, deployment configs, CI/CD pipeline |
| 2. Architecture Modeling | Produces C4 diagrams scaled to system complexity (Simple / Moderate / Complex) |
| 3. Security Use Cases | Sequence diagrams for auth flow, access control, and other critical flows |
| 4. Asset Identification | Catalogs data, code/IP, infrastructure, and availability assets |
| 5. Attack Surface Mapping | Enumerates API endpoints, auth mechanisms, file uploads, inter-service calls |
| 6. Trust Boundary Analysis | Identifies privilege and network boundary crossings |
| 7. Security Controls | Catalogs existing controls by domain with effectiveness rating |
| 8. Threat Enumeration | STRIDE analysis per component and boundary, rated by Likelihood × Impact |
| 9. Dependency & Secret Scanning | Flags hardcoded credentials, insecure defaults, outdated deps |

**STRIDE categories:** Spoofing · Tampering · Repudiation · Information Disclosure · Denial of Service · Elevation of Privilege

## MCP Context Server

The agent calls `get_repo_context(repo_url)` in Phase 0 to retrieve pre-existing knowledge before reading any code.

**Transport:** Streamable HTTP on `http://127.0.0.1:4444/mcp`  
**Registration:** `.mcp.json` at the plugin root (read automatically by Claude Code)

**Pattern matching (mock data):**

| URL pattern | Context returned |
|-------------|-----------------|
| `payment\|checkout\|billing` | PCI-DSS / Payments Platform — Tier 1 |
| `auth\|identity\|sso\|oauth` | SOC2 / IAM — Tier 1 |
| `health\|medical\|patient\|ehr` | HIPAA / Clinical Data — Tier 1 |
| anything else | SOC2 default — Tier 2 |

**Starting the server:**

```bash
# Option A — shell script (auto-installs Node dependencies)
./mcp/appsec-context/start.sh

# Option B — Docker
docker build -t appsec-context-mcp ./mcp/appsec-context
docker run -p 4444:4444 --rm appsec-context-mcp
```

The server logs every request and response to stdout with timestamps, client IP:port, MCP method, pattern match result, and response size. If unreachable, the agent prints a warning and continues without pre-existing context.

## Plugin Structure

```
appsec-plugin/
├── .claude-plugin/
│   └── plugin.json                  # Plugin manifest + MCP server documentation
├── .mcp.json                        # MCP server registration (read by Claude Code)
├── agents/
│   └── appsec-threat-analyst.md    # Agent definition (9-phase STRIDE analysis)
├── skills/
│   ├── create-threat-model/
│   │   └── SKILL.md                # /appsec-plugin:create-threat-model
│   └── update-threat-model/
│       └── SKILL.md                # /appsec-plugin:update-threat-model
├── mcp/
│   └── appsec-context/
│       ├── index.js                 # HTTP MCP server (Streamable HTTP transport)
│       ├── package.json
│       ├── start.sh                 # Startup script (installs deps, launches server)
│       └── Dockerfile
└── README.md
```
