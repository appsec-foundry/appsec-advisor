# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A Claude Code plugin that adds automated STRIDE-based security threat modeling to any repository. It ships two components:

- **Agent** (`agents/appsec-threat-analyst.md`) — a Claude Opus persona (40 max turns) that performs a structured 6-phase security review and writes `THREAT_MODEL.md` to the analyzed repo's root.
- **Skills** (`skills/`) — two skills that delegate to the agent:
  - `/appsec-plugin:create-threat-model` — full assessment from scratch
  - `/appsec-plugin:update-threat-model` — incremental update of an existing `THREAT_MODEL.md`

## Plugin Architecture

Claude Code plugins are loaded via `claude --plugin-dir /path/to/appsec-plugin`. The plugin manifest lives at `.claude-plugin/plugin.json` and declares the plugin name, version, agent and command paths, and the MCP server entry point.

Agent definitions are Markdown files with a YAML frontmatter block that declares `name`, `description`, `tools`, `model`, and `maxTurns`. Skills are plain Markdown instruction files at `skills/<skill-name>/SKILL.md`.

The skill→agent delegation pattern used here is the standard way to expose an agent as a slash command: the SKILL.md simply instructs Claude to invoke the named agent and forward any user arguments.

## How the Agent Works

Phases executed in order:
1. **Reconnaissance** — reads README, CLAUDE.md, maps tech stack and deployment configs
2. **Asset Identification** — catalogs data, code/IP, infrastructure, availability assets
3. **Attack Surface Mapping** — enumerates endpoints, auth mechanisms, inter-service comms
4. **Trust Boundary Analysis** — identifies privilege/network boundary crossings
5. **Threat Enumeration** — applies STRIDE per component/boundary; rates Likelihood × Impact
6. **Dependency & Secret Scanning** — flags hardcoded credentials, insecure defaults, outdated deps

Output is a structured `THREAT_MODEL.md` with sections: System Overview, Architecture Diagram (Mermaid/ASCII), Assets table, Attack Surface table, Trust Boundaries, Threat Register, Critical Findings, Recommended Security Controls, Out of Scope.

## Usage

```bash
# Load the plugin
claude --plugin-dir /path/to/appsec-plugin

# Invoke via skill (analyzes current repo)
/create-threat-model

# With scope constraint
/create-threat-model focus on the authentication service

# Invoke agent directly
/agents invoke appsec-threat-analyst
```

## MCP Context Server (mock)

`mcp/appsec-context/` is a Node.js MCP server that the agent calls in Phase 0 to fetch pre-existing AppSec context for a repository.

```bash
# Direct (auto-installs deps on first run)
./mcp/appsec-context/start.sh

# Docker
docker build -t appsec-context-mcp ./mcp/appsec-context
docker run -i --rm appsec-context-mcp
```

**Tool exposed:** `get_repo_context(repo_url)` — accepts the git remote URL, returns team ownership, asset classification, compliance scope, prior findings, known exceptions, and architecture notes.

**Pattern matching (mock data):**
- `payment|checkout|billing|commerce|shop` → PCI-DSS / Payments Platform context
- `auth|identity|sso|login|iam|oauth` → IAM / SOC2 context
- `health|medical|patient|clinic|ehr` → HIPAA / Clinical Data context
- anything else → generic Tier 2 / SOC2 default

To wire it into Claude Code, add to `~/.claude/settings.json` under `mcpServers`:
```json
{
  "mcpServers": {
    "appsec_context": {
      "command": "/path/to/appsec-plugin/mcp/appsec-context/start.sh"
    }
  }
}
```

Or using Docker:
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

## No Build System (agents/skills)

The agent and skill definitions are plain Markdown — no build or lint tooling. Edit them directly.
