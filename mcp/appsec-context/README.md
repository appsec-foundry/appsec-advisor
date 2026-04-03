# appsec-context — MCP Context Server

Mock MCP server that provides the `appsec-threat-analyst` agent with pre-existing AppSec context for a repository. Called automatically in Phase 0 of the threat modeling analysis.

## What it does

When the threat analyst agent starts, it runs `git config --get remote.origin.url` and passes the result to this server's `get_repo_context` tool. The server returns:

| Field | Description |
|-------|-------------|
| `team` | Owning team name, email, Slack channel, and security champion |
| `asset_classification` | Tier, data sensitivity, data types handled, criticality, business impact |
| `compliance_scope` | Applicable frameworks (PCI-DSS, HIPAA, SOC 2, GDPR, …) |
| `architecture_notes` | Free-text notes on deployment, secret management, network topology |
| `prior_findings` | Open and remediated security findings with severity, status, and SLA dates |
| `known_exceptions` | Accepted risks with approver, expiry date, and compensating controls |
| `penetration_tests` | Past pentest records with date, scope, provider, and report ID |

All requests and responses are printed to **stderr** with timestamps and color coding so you can observe the traffic in real time.

## Requirements

- Node.js 18 or later

## Start

**Shell script** (recommended — auto-installs dependencies on first run):

```bash
./start.sh
```

**npm:**

```bash
npm install
npm start
```

**Docker:**

```bash
docker build -t appsec-context-mcp .
docker run -i --rm appsec-context-mcp
```

> The `-i` flag is required — MCP servers communicate over stdio.

## Configuration in Claude Code

The server is registered automatically when the `appsec-plugin` is loaded via its `plugin.json`. To use it standalone, add it to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "appsec_context": {
      "command": "/absolute/path/to/mcp/appsec-context/start.sh"
    }
  }
}
```

Docker alternative:

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

## Mock data

The server matches the incoming `repo_url` against three patterns and returns the corresponding sample context. If no pattern matches, a generic default is returned.

| Pattern | Team | Compliance |
|---------|------|------------|
| `payment`, `checkout`, `billing`, `commerce`, `shop` | Payments Platform | PCI-DSS v4.0, SOC 2, GDPR |
| `auth`, `identity`, `sso`, `login`, `iam`, `oauth` | Identity & Access Management | SOC 2, GDPR, ISO 27001 |
| `health`, `medical`, `patient`, `clinic`, `ehr` | Clinical Data Platform | HIPAA/HITECH, SOC 2, GDPR, CCPA |
| *(anything else)* | Engineering (default) | SOC 2 |

To add or modify contexts, edit the `SAMPLE_CONTEXTS` array in `index.js`. Each entry needs a `pattern` (RegExp) and a `context` object matching the schema above.

## Replacing with a real implementation

This mock is designed to be swapped out for a real data source with minimal changes:

1. Keep the same tool name (`get_repo_context`) and input schema (`repo_url: string`)
2. Replace the `resolveContext()` function in `index.js` with a call to your internal API, security findings database (e.g. Jira, Defect Dojo, SecurityHub), or CMDB
3. Return a JSON object with the same fields — the agent handles missing fields gracefully
