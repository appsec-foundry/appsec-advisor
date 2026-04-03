# appsec-plugin

A Claude Code plugin for application security threat assessment and threat modeling. It includes the `appsec-threat-analyst` agent and the `/create-threat-model` command.

## Installation

```bash
claude --plugin-dir /path/to/appsec-plugin
```

## Components

### Agent: `appsec-threat-analyst`

A senior AppSec engineer persona that performs a structured, six-phase security review of a repository and writes a `THREAT_MODEL.md` document to the analyzed repo's root.

**Phases:**

| Phase | Description |
|-------|-------------|
| 1. Reconnaissance | Maps the tech stack, directory structure, deployment configs, and CI/CD pipeline |
| 2. Asset Identification | Catalogs data, code/IP, infrastructure, and availability assets |
| 3. Attack Surface Mapping | Enumerates API endpoints, auth mechanisms, file upload handlers, webhooks, and inter-service communication |
| 4. Trust Boundary Analysis | Identifies where trust levels change across user tiers, network zones, and service boundaries |
| 5. Threat Enumeration | Applies STRIDE to each component and trust boundary crossing, rating each threat by Likelihood, Impact, and Risk |
| 6. Dependency & Secret Scanning | Flags hardcoded credentials, insecure defaults, and outdated dependencies |

**STRIDE categories covered:**

- **S**poofing — impersonating users, services, or components
- **T**ampering — unauthorized modification of data or code
- **R**epudiation — denying actions without auditability
- **I**nformation Disclosure — exposing sensitive data
- **D**enial of Service — degrading or blocking availability
- **E**levation of Privilege — gaining unauthorized access levels

**Output — `THREAT_MODEL.md`:**

1. System Overview
2. Architecture Diagram (text/Mermaid)
3. Assets table
4. Attack Surface table
5. Trust Boundaries description
6. Threat Register (ID, component, STRIDE category, scenario, likelihood, impact, risk, mitigations, recommendations)
7. Critical Findings (top 5 highest-risk threats)
8. Recommended Security Controls (prioritized)
9. Out of Scope

**Invoke directly:**

```
/agents invoke appsec-threat-analyst
```

The agent will ask for the repository path, any areas of concern, and any out-of-scope components before proceeding.

---

### Command: `/create-threat-model`

A convenience command that delegates to `appsec-threat-analyst` to analyze the current repository. Accepts optional arguments to constrain scope.

**Usage:**

```
# Analyze the entire current repository
/create-threat-model

# Focus on a specific area or component
/create-threat-model focus on the authentication service

# Limit scope to a subdirectory
/create-threat-model analyze only the /api directory
```

## MCP Context Server

The agent enriches its analysis by querying an AppSec context service in Phase 0 — before reading any code. It calls `get_repo_context` with the repository's git remote URL and receives pre-existing knowledge: team ownership, asset classification, compliance scope (PCI-DSS, HIPAA, SOC2, …), open and remediated findings, known risk exceptions, and architecture notes.

### Starting the server

**Option A — shell script (auto-installs dependencies):**
```bash
./mcp/appsec-context/start.sh
```

**Option B — Docker:**
```bash
docker build -t appsec-context-mcp ./mcp/appsec-context
docker run -i --rm appsec-context-mcp
```

The server communicates over stdio and logs all requests and responses to stderr with timestamps and color coding.

### Wiring into Claude Code

Add the server to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "appsec_context": {
      "command": "/path/to/appsec-plugin/mcp/appsec-context/start.sh"
    }
  }
}
```

Or with Docker:

```json
{
  "mcpServers": {
    "appsec_context": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "appsec-context-mcp"]
    }
  }
}
```

> If the server is unreachable the agent prints a warning and continues the assessment without pre-existing context.

## Plugin Structure

```
appsec-plugin/
├── .claude-plugin/
│   └── plugin.json                  # Plugin manifest
├── agents/
│   └── appsec-threat-analyst.md    # Threat analyst agent definition
├── skills/
│   ├── create-threat-model/
│   │   └── SKILL.md                # /appsec-plugin:create-threat-model
│   └── update-threat-model/
│       └── SKILL.md                # /appsec-plugin:update-threat-model
├── mcp/
│   └── appsec-context/
│       ├── Dockerfile               # Container image for the context server
│       ├── index.js                 # MCP server implementation
│       ├── package.json
│       └── start.sh                 # Start script (installs deps, launches server)
└── README.md
```
