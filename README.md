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

## AppSec Steering Hook

The plugin ships a `UserPromptSubmit` hook (`hooks/hooks.json`) that injects security guidance into **every prompt** Claude receives while the plugin is loaded — not just during threat modeling.

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/security_steering.py"
          }
        ]
      }
    ]
  }
}
```

`scripts/security_steering.py` runs on each user prompt and appends the following context to Claude's system message:

```
Security steering active. Always implement secure-by-default:
- Treat all input as untrusted
- Enforce authentication and least privilege
- Never hardcode or expose secrets
- Use secure defaults
- Prevent common vulns
- Do not suggest insecure shortcuts
```

This means that any code Claude writes or reviews during the session is held to these standards automatically — even when the user isn't asking about security explicitly.

## Agent Pipeline

The plugin uses a 5-agent pipeline. Only `appsec-threat-analyst` is user-facing; the rest are dispatched internally.

```
User
 └─ appsec-threat-analyst (Opus, orchestrator)
     ├─ appsec-context-resolver  (Sonnet) ← Phase 0, gathers pre-existing AppSec knowledge
     ├─ appsec-dep-scanner       (Sonnet) ← Phase 1, runs concurrently with Recon–Trust Boundary phases
     ├─ appsec-stride-analyzer   (Sonnet) ← Phase 6, one instance per major component (parallel)
     └─ appsec-qa-reviewer       (Sonnet) ← Phase 10, verifies and fixes the finished output files
```

### Agents

**`appsec-threat-analyst`** — Opus, 50 max turns, entry point

The orchestrator. Owns the full 10-phase assessment lifecycle: drives reconnaissance, architecture modeling, asset identification, attack surface mapping, trust boundary analysis, controls cataloging, threat synthesis, and output writing. Dispatches the three specialist sub-agents at the appropriate phases and reads their output files. This is the only agent a user or skill should ever invoke directly.

**`appsec-context-resolver`** — Sonnet, 25 max turns

Runs at Phase 0 before any analysis begins. Calls the AppSec MCP context server (`get_repo_context`) and reads a prioritized set of common repository files: `SECURITY.md`, architecture docs, ADRs, OpenAPI/Swagger specs, `docker-compose.yml`, Kubernetes/Terraform configs, database schemas (SQL, Prisma, GraphQL), `.env.example`, and `CHANGELOG.md`. Consolidates everything into `docs/security/threat-modeling-context.md`. All other agents read this file rather than calling the MCP themselves, so the MCP is only hit once per run.

**`appsec-dep-scanner`** — Sonnet, 20 max turns

Dispatched after Phase 1 (Recon) and runs concurrently while the orchestrator works through Phases 2–6. Scans for three categories of risk: hardcoded secrets (passwords, API keys, tokens, private keys), vulnerable or outdated dependencies (npm, pip, gem, etc.), and insecure defaults (debug mode enabled, HTTP used instead of HTTPS, weak crypto algorithms, disabled TLS verification). Writes findings to `docs/security/.dep-scan.json` for the orchestrator to fold into the threat register at Phase 8.

**`appsec-stride-analyzer`** — Sonnet, 20 max turns

One instance is spawned per major component after Phase 6 (Trust Boundary Analysis); multiple instances run in parallel. Each instance receives the component's interfaces, trust boundaries, and relevant existing controls from the orchestrator. Reads `threat-modeling-context.md` for compliance scope and prior findings, then applies the full STRIDE taxonomy (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) to that component. Writes per-component threats to `docs/security/.stride-<component-id>.json`.

**`appsec-qa-reviewer`** — Sonnet, 20 max turns

Runs at Phase 10 after both output files are written. Performs 7 checks against `docs/security/threat-model.md`: verifies that every VS Code deep link resolves to a file that exists on disk, linkifies bare file path mentions that were not already linked, checks that threat IDs cross-reference correctly between sections, verifies consistency between the Markdown and YAML exports, flags any prior findings from the context file that were not addressed in the threat register, removes unfilled placeholder text, and confirms all 11 required sections are present and non-empty. Fixes issues in-place and prints a summary of changes made.

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
├── hooks/
│   └── hooks.json                         # UserPromptSubmit hook — injects security steering
├── scripts/
│   └── security_steering.py               # Appends secure-by-default context to every prompt
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

# Used Claude Model

The agent runs on **Claude Sonnet** (claude-sonnet-4-6). Testing both Sonnet and Opus against the same repository showed that Sonnet consistently identifies more threats — 25 vs. 20 findings — with broader coverage across application, infrastructure, and deployment risks, while Opus focused primarily on core application vulnerabilities and missed operational issues such as session fixation, exposed debug ports, and the container running as root. 

Accuracy was equivalent in both models (zero false positives), and Sonnet delivers superior threat coverage at a fraction of the cost and with lower latency than Opus, making it the clear choice for automated threat modeling at scale. 
  
## License

MIT — see [LICENSE](LICENSE).
