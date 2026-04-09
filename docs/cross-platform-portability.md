# Cross-Platform Portability Analysis

How the Claude AppSec Plugin maps to GitHub Copilot, Cursor, Gemini CLI, and Amazon Kiro — what transfers directly, what needs adaptation, and what has no equivalent.

## Contents

- [Plugin Anatomy](#plugin-anatomy)
- [Platform Comparison](#platform-comparison)
- [Feature-by-Feature Mapping](#feature-by-feature-mapping)
  - [Agent Definitions](#1-agent-definitions)
  - [Multi-Agent Orchestration](#2-multi-agent-orchestration)
  - [Skills / Slash Commands](#3-skills--slash-commands)
  - [Hooks](#4-hooks)
  - [Model Selection and Turn Budgets](#5-model-selection-and-turn-budgets)
  - [Tool Access](#6-tool-access)
  - [MCP Integration](#7-mcp-integration)
  - [Plugin Manifest and Packaging](#8-plugin-manifest-and-packaging)
  - [Custom Instructions](#9-custom-instructions)
  - [Inter-Agent Communication](#10-inter-agent-communication)
- [Migration Strategies per Platform](#migration-strategies-per-platform)
  - [GitHub Copilot](#github-copilot)
  - [Cursor](#cursor)
  - [Gemini CLI](#gemini-cli)
  - [Amazon Kiro](#amazon-kiro)
- [What Is Fully Portable](#what-is-fully-portable)
- [What Requires Rearchitecting](#what-requires-rearchitecting)
- [Recommended Approach](#recommended-approach)

---

## Plugin Anatomy

The plugin breaks down into these categories:

| Category | % of plugin | Examples | Portable? |
|----------|-------------|---------|-----------|
| **Prompt engineering** | ~45% | STRIDE methodology, phase instructions, fix patterns, quality standards | Yes — framework-agnostic |
| **Agent orchestration** | ~20% | 6-agent pipeline, parallel STRIDE dispatch, two-stage skill invocation | Needs adaptation per platform |
| **Hook scripts** | ~10% | Security steering, agent logging, cost tracking | Needs event system equivalent |
| **Data structures** | ~10% | Intermediate JSON/YAML, checkpoint files, lock files | Yes — file-based, framework-agnostic |
| **Platform glue** | ~15% | plugin.json manifest, settings.json permissions, frontmatter schema, skill flag parsing | Must be rewritten per platform |

The core threat modeling methodology (STRIDE categories, 11-phase pipeline, C4 diagram generation, threat register format, requirements compliance) is expressed as Markdown instructions and is **fully portable** to any LLM-based agent system. The challenge is the orchestration infrastructure around it.

---

## Platform Comparison

| Capability | Claude Code | Copilot | Cursor | Gemini CLI | Kiro |
|---|---|---|---|---|---|
| Custom agents (Markdown + YAML) | Yes | Yes | Yes | Yes | Yes (steering) |
| Sub-agent spawning | Yes (unlimited depth) | Yes | Yes (tree structure) | **No** (blocked) | Yes (parallel) |
| Hook events | 5 types | 8 types (preview) | 4 types | **None** | File-save only |
| Custom slash commands | Skills (SKILL.md) | Skills | Skills | TOML commands | **No** |
| MCP support | Yes | Yes | Yes | Yes | Yes (+ Powers) |
| Model override per agent | Yes (`model` field) | Yes (`model` field) | Yes (`model` field) | Yes (`model` field) | Limited (Sonnet/Auto) |
| Turn/token budgets | `maxTurns` per agent | **No** (billing only) | 25/200 tool calls | `max_turns` + `timeout_mins` | **No** |
| Plugin packaging | `plugin.json` + `--plugin-dir` | Agent Plugins (preview) | Plugins (v2.5+) | Skills (`npx` installable) | Powers registry |

---

## Feature-by-Feature Mapping

### 1. Agent Definitions

**Claude Code** uses Markdown files with YAML frontmatter in `plugin/agents/`:

```yaml
---
name: appsec-stride-analyzer
description: STRIDE analysis for a single component
tools: Read, Glob, Grep, Bash, Write
model: sonnet
maxTurns: 31
---
(agent instructions in Markdown)
```

| Platform | Equivalent | Location | Key differences |
|----------|-----------|----------|-----------------|
| **Copilot** | Custom agents | `.github/agents/*.md` | Same format (Markdown + YAML frontmatter). Fields: `name`, `description`, `model`, `tools`. Max 30,000 chars per agent. No `maxTurns` field. |
| **Cursor** | Custom agents | `.cursor/agents/*.md` | Same format. `model` supports `inherit` and `fast` aliases. No explicit turn budget field (governed by mode: standard=25, max=200 tool calls). |
| **Gemini CLI** | Subagents | `.gemini/agents/*.md` | Same format. Has both `max_turns` (default 15) and `timeout_mins` (default 10). Also supports `temperature` and `kind: remote`. |
| **Kiro** | Steering files + subagents | `.kiro/steering/*.md` | Different model: steering files use inclusion modes (`always`, `fileMatch`, `manual`, `auto`) instead of explicit agent definitions. Subagent configs are separate. |

**Migration effort:** Low for Copilot, Cursor, Gemini. The 6 agent `.md` files can be reformatted with minimal changes. Kiro requires restructuring into steering files.

### 2. Multi-Agent Orchestration

The plugin's core complexity is the orchestrator pattern: `appsec-threat-analyst` dispatches 4 sub-agents at specific phases, some in parallel (STRIDE analyzers), some in background (dep-scanner), and reads their file-based output.

```
Orchestrator (75 turns)
  ├── context-resolver (sync, Phase 1)
  ├── recon-scanner (sync, Phase 2)
  ├── dep-scanner (background, Phase 2, optional)
  ├── stride-analyzer × N (parallel background, Phase 9)
  └── [skill invokes qa-reviewer as Stage 2]
```

| Platform | Sub-agent support | Parallel execution | Background execution | Depth limit |
|----------|------------------|-------------------|---------------------|-------------|
| **Copilot** | Yes | Yes | Unknown | Multi-level confirmed |
| **Cursor** | Yes | Yes (async subagents, v2.5+) | Yes (async) | Unlimited (tree) |
| **Gemini CLI** | Yes | Yes (up to ~10) | No (returns summary) | **1 level only** (no recursion) |
| **Kiro** | Yes | Yes (parallel subagents) | Yes | Unknown |

**Critical issue — Gemini CLI:** Subagents cannot spawn other subagents. The orchestrator pattern works, but the orchestrator cannot be a sub-agent itself. The skill would need to directly orchestrate all agents in a flat structure, or use a third-party framework like maestro-orchestrate for deeper nesting.

**Critical issue — Copilot:** No per-agent turn budget. Long-running orchestrators may hit billing limits or implicit timeouts rather than controlled turn budgets. The dynamic STRIDE turn allocation (`--assessment-depth quick|standard|thorough`) has no direct equivalent.

**Migration effort:** Medium for Copilot and Cursor. High for Gemini (flat orchestration required). Medium for Kiro (subagent model is different).

### 3. Skills / Slash Commands

The plugin has two user-invocable skills defined as `SKILL.md` files with flag parsing, variable resolution, and multi-stage agent invocation:

- `/appsec-plugin:create-threat-model` — parses 12+ flags, resolves config, invokes orchestrator (Stage 1) then QA reviewer (Stage 2)
- `/appsec-plugin:check-appsec-requirements` — inline skill, no sub-agents

| Platform | Equivalent | Format | Flag parsing | Multi-stage invocation |
|----------|-----------|--------|-------------|----------------------|
| **Copilot** | Agent Skills | `SKILL.md` with YAML frontmatter in `.github/skills/` | Via `argument-hint` field | Yes (skills can invoke agents) |
| **Cursor** | Skills | `SKILL.md` in `.cursor/skills/` | Supported | Yes (skills invoke agents) |
| **Gemini CLI** | Custom commands | TOML files in `.gemini/commands/` | `{{args}}` placeholder | Limited — commands send prompts, not structured agent invocations |
| **Kiro** | **No equivalent** | N/A | N/A | Would need to be triggered via steering + hooks |

**Key difference:** Claude Code's `SKILL.md` files contain full procedural logic (flag parsing, config resolution, conditional agent dispatch) as prose that the LLM interprets. Copilot and Cursor support similar `SKILL.md` formats. Gemini's TOML commands are simpler — they inject prompts but don't support the same procedural complexity.

**The two-stage pattern** (skill invokes orchestrator, waits, then invokes QA reviewer) requires the skill layer to be able to invoke agents sequentially. Copilot and Cursor support this. Gemini CLI would need the orchestration logic moved into a single agent or a wrapper script.

**Migration effort:** Low for Copilot and Cursor (SKILL.md format is converging). High for Gemini (restructure into TOML + wrapper). Not directly possible on Kiro.

### 4. Hooks

The plugin uses 5 hook types:

| Hook | Script | Purpose |
|------|--------|---------|
| `UserPromptSubmit` | `security_steering.py` | Inject secure-by-default context on security-related prompts |
| `PreToolUse` (Agent) | `agent_logger.py` | Log agent spawn events |
| `PostToolUse` | `agent_logger.py` | Log tool completions, file writes |
| `Stop` | `agent_logger.py` | Log session end with token/cost data |
| `SubagentStop` | `agent_logger.py` | Log sub-agent completion |

| Platform | Hook support | Matching events | Gap |
|----------|-------------|----------------|-----|
| **Copilot** | 8 event types (preview) | `userPromptSubmitted`, `preToolUse`, `postToolUse`, `agentStop`, `subagentStop`, `sessionStart`, `sessionEnd`, `errorOccurred` | Full coverage. Closest match to Claude Code's hook system. |
| **Cursor** | 4 event types | `beforeSubmitPrompt`, `PreToolUse`, `PostToolUse`, `stop` | Missing `SubagentStop`. Would need `PostToolUse` on Agent tool as workaround. |
| **Gemini CLI** | **None** | N/A | No hook system. Steering and logging must be embedded in agent prompts or handled externally. |
| **Kiro** | File-save triggers only | File change events | No prompt-submit or tool-use hooks. Security steering would need to be implemented as an always-on steering file instead. |

**Security steering workaround for hookless platforms:** Move the keyword-matching logic into the agent's system prompt as a self-check instruction ("Before responding to any prompt, check if it contains security-relevant keywords..."). Less reliable than a hook but functional. Alternatively, use an MCP server that the agent calls to evaluate prompt context.

**Logging workaround for hookless platforms:** Embed structured logging instructions in each agent's prompt (the plugin already does this via `agents/shared/logging-standard.md`). The hook-based logging adds token/cost tracking that agents can't self-report — this data would be lost or need external tooling.

**Migration effort:** Low for Copilot (near 1:1). Medium for Cursor (missing SubagentStop). High for Gemini and Kiro (no native hooks — requires architectural workarounds).

### 5. Model Selection and Turn Budgets

**Model selection:**

| Platform | Per-agent model override | Runtime override (like `--stride-model opus`) |
|----------|------------------------|----------------------------------------------|
| **Claude Code** | `model: sonnet` in frontmatter, `model` param in Agent tool | Yes — flag parsed in SKILL.md, passed to Agent tool |
| **Copilot** | `model` field in agent YAML | Would need flag parsing in skill to select model dynamically |
| **Cursor** | `model` field (`inherit`, `fast`, or specific ID) | Same approach; known issue with nested subagent model overrides |
| **Gemini CLI** | `model` field in agent YAML | Same approach; model options are Gemini-family only |
| **Kiro** | Limited — Sonnet 4.5 or Auto | No per-agent model control |

**Turn budgets:**

The plugin uses dynamic turn budgets based on component complexity:

```
--assessment-depth quick:    STRIDE turns = 10 (simple) / 15 (moderate) / 20 (complex)
--assessment-depth standard: STRIDE turns = 15 / 22 / 28
--assessment-depth thorough: STRIDE turns = 20 / 31 / 35
```

| Platform | Turn budget mechanism | Dynamic budgets possible? |
|----------|---------------------|--------------------------|
| **Claude Code** | `maxTurns` in frontmatter + runtime override | Yes — orchestrator passes budget via prompt |
| **Copilot** | None (billing-level caps) | No — agents run until completion or billing limit |
| **Cursor** | Mode-based (25 std / 200 max tool calls) | No per-agent granularity |
| **Gemini CLI** | `max_turns` (default 15) + `timeout_mins` | Yes — subagent definitions support per-agent limits |
| **Kiro** | None exposed | No |

**Migration impact:** Gemini CLI has the closest turn budget model. Copilot and Cursor would lose fine-grained budget control — agents may over-consume on simple components or under-deliver on complex ones. The workaround is embedding budget awareness in agent prompts ("Complete your analysis within approximately N tool calls").

### 6. Tool Access

The plugin agents use: `Read`, `Glob`, `Grep`, `Bash`, `Write`, `Agent`.

| Claude Code tool | Copilot | Cursor | Gemini CLI | Kiro |
|-----------------|---------|--------|-----------|------|
| `Read` | `read` | File read | `read_file` | File read |
| `Write` | `edit` | File write | `write_file` | File write |
| `Glob` | `search` (combined) | File search | Built into grep | File search |
| `Grep` | `search` (combined) | Code search | `grep` | Code search |
| `Bash` | `execute` | Terminal | `shell` | Terminal |
| `Agent` | `agent` | Subagent spawn | Subagent spawn | Subagent spawn |

**All platforms provide equivalent filesystem and shell tools.** The specific tool names differ but semantics are the same. Agent instructions that reference tool names (e.g., "Use Glob to find...") would need updating per platform.

**Migration effort:** Low — find-and-replace tool names in agent instructions.

### 7. MCP Integration

The plugin uses an optional MCP server for external context injection:

```json
{
  "mcpServers": {
    "appsec_context": {
      "type": "http",
      "url": "http://127.0.0.1:4444/mcp"
    }
  }
}
```

**All four platforms support MCP.** Configuration format varies:

| Platform | MCP config location | Notes |
|----------|-------------------|-------|
| **Copilot** | Agent YAML `mcp-servers` field or VS Code settings | Per-agent scoping supported. Enterprise policy may disable MCP. |
| **Cursor** | `.cursor/mcp.json` | Per-agent scoping via subagent `mcpServers` field |
| **Gemini CLI** | Gemini settings JSON | Per-subagent scoping via `mcpServers` field |
| **Kiro** | Powers registry or manual config | Powers bundle MCP servers with steering. Supports remote Streamable HTTP. |

**Migration effort:** Low — reconfigure MCP endpoint in platform-specific format. The mock context server (`scripts/mock-context-server.py`) works with any MCP client.

### 8. Plugin Manifest and Packaging

Claude Code uses `plugin.json` + `--plugin-dir` for loading:

```json
{
  "name": "appsec-plugin",
  "version": "0.9.0-beta",
  "agents": ["./agents/appsec-context-resolver.md", ...],
  "skills": ["./skills/"]
}
```

| Platform | Packaging mechanism | Distribution |
|----------|-------------------|-------------|
| **Copilot** | Agent Plugins (preview) — bundles agents, skills, commands | VS Code Marketplace (planned) |
| **Cursor** | Plugins (v2.5+) — bundles skills, subagents, MCP, hooks, rules | Cursor plugin directory |
| **Gemini CLI** | Skills (`npx skills add`) or manual `.gemini/` directory setup | npm / skills.sh registry |
| **Kiro** | Powers — bundles MCP servers, steering files, hooks | Powers registry on GitHub |

**Migration effort:** Medium — each platform has its own manifest format and distribution channel. The plugin directory structure would need restructuring per platform.

### 9. Custom Instructions

The plugin uses `plugin/CLAUDE.md` (29KB) as runtime documentation loaded into agent context.

| Platform | Equivalent | Format |
|----------|-----------|--------|
| **Copilot** | `.github/copilot-instructions.md` + agent body | Markdown, always loaded |
| **Cursor** | `.cursor/rules/*.md` | Markdown with YAML frontmatter, `alwaysApply` toggle |
| **Gemini CLI** | `GEMINI.md` (hierarchical) | Markdown, all found files concatenated |
| **Kiro** | `.kiro/steering/*.md` | Markdown with inclusion modes (`always`, `fileMatch`, `manual`, `auto`) |

**Kiro's inclusion modes** are the most sophisticated — `auto` mode loads steering files based on relevance, which could help with the plugin's 29KB instruction file (only load phase-specific instructions when relevant). Claude Code achieves this by having the orchestrator read phase-group files at runtime; Kiro could do it natively.

**Migration effort:** Low — rename and restructure the instruction files. Content is portable.

### 10. Inter-Agent Communication

The plugin's agents communicate exclusively through intermediate files:

```
context-resolver  →  .threat-modeling-context.md  →  all agents
recon-scanner     →  .recon-summary.md            →  orchestrator + STRIDE analyzers
dep-scanner       →  .dep-scan.json               →  orchestrator
stride-analyzer   →  .stride-<id>.json            →  orchestrator
orchestrator      →  .appsec-checkpoint            →  skill (resume logic)
```

**This pattern is fully portable.** All platforms provide file read/write tools. No platform-specific IPC is used. The only consideration is that agents on all platforms need filesystem access to the shared output directory.

**Gemini CLI caveat:** Since subagents return a summary to the parent rather than running in background, the orchestrator would need to explicitly read the output files after each subagent returns, rather than polling for background completion.

---

## Migration Strategies per Platform

### GitHub Copilot

**Feasibility: High** — Copilot's agent architecture (as of 2026) is the closest match to Claude Code's plugin model.

**What maps directly:**
- Agent definitions → `.github/agents/*.md` (same Markdown + YAML format)
- Skills → `.github/skills/` (same SKILL.md format)
- Hooks → `.github/hooks/` (8 event types, superset of Claude Code's 5)
- MCP → per-agent `mcp-servers` field
- Model override → `model` field in agent YAML

**What needs adaptation:**
- `maxTurns` → no equivalent; embed budget awareness in prompts or accept billing-level caps
- `plugin.json` → Copilot Agent Plugin manifest (different schema)
- `settings.json` tool permissions → Copilot tool allowlists in agent YAML `tools` field
- Tool name references in prompts (`Read` → `read`, `Glob` → `search`, `Bash` → `execute`)

**Steps:**
1. Move agent `.md` files to `.github/agents/`, update frontmatter (remove `maxTurns`, map tool names)
2. Move skills to `.github/skills/`, verify SKILL.md format compatibility
3. Move hooks to `.github/hooks/`, update `hooks.json` event names (`UserPromptSubmit` → `userPromptSubmitted`, etc.)
4. Update Python hook scripts for Copilot's hook input JSON schema
5. Create Agent Plugin manifest for distribution
6. Test with Copilot agent mode in VS Code

**Estimated effort:** 2–3 weeks for a working port. The prompt engineering (STRIDE methodology, phase instructions) transfers unchanged.

### Cursor

**Feasibility: High** — Cursor's plugin system (v2.5+) bundles the same primitives.

**What maps directly:**
- Agent definitions → `.cursor/agents/*.md`
- Skills → `.cursor/skills/`
- Hooks → `.cursor/hooks/` (4 event types cover most needs)
- MCP → `.cursor/mcp.json`
- Async subagents → background STRIDE analyzer dispatch
- Model override → `model` field

**What needs adaptation:**
- `maxTurns` → no per-agent budgets; Cursor uses mode-based limits (25 std / 200 max)
- `SubagentStop` hook → not available; use `PostToolUse` filtered to Agent tool as workaround
- `plugin.json` → Cursor plugin manifest
- Tool name references in prompts

**Steps:**
1. Move agent `.md` files to `.cursor/agents/`, update frontmatter
2. Move skills to `.cursor/skills/`
3. Move hooks to `.cursor/hooks/`, drop `SubagentStop` (fold into `PostToolUse`)
4. Create `.cursor/mcp.json` from `.mcp.json`
5. Package as Cursor plugin
6. Test in Cursor agent mode (recommend Max mode for the full pipeline)

**Estimated effort:** 2–3 weeks. Cursor's async subagent support makes the parallel STRIDE pattern natural.

### Gemini CLI

**Feasibility: Medium** — capable but requires architectural changes due to the no-recursion constraint.

**What maps directly:**
- Agent definitions → `.gemini/agents/*.md` (same format, plus `max_turns` and `timeout_mins`)
- Custom commands → `.gemini/commands/*.toml` (simpler than SKILL.md)
- MCP → Gemini settings JSON
- Model override → `model` field
- Turn budgets → `max_turns` per subagent (closest match to Claude Code's `maxTurns`)

**What needs rearchitecting:**
- **No sub-agent recursion** — the orchestrator cannot be a sub-agent itself, and sub-agents cannot spawn sub-agents. The entire orchestration must happen at the top level or in a single agent.
- **No hooks** — security steering must move into agent prompts or an MCP server. Logging must be prompt-embedded (the `shared/logging-standard.md` approach already handles this partially).
- **Skills** → TOML commands are simpler; complex flag parsing and multi-stage invocation need a wrapper approach.

**Rearchitected pipeline:**

```
# Option A: Flat orchestration via custom command
/.gemini/commands/create-threat-model.toml
  → Triggers a single orchestrator agent that:
     1. Spawns context-resolver (subagent, sync)
     2. Spawns recon-scanner (subagent, sync)
     3. Spawns dep-scanner (subagent, sync, optional)
     4. Performs Phases 3-8 inline
     5. Spawns stride-analyzer × N (subagents, parallel)
     6. Merges results inline
     7. Spawns qa-reviewer (subagent, sync)

# Option B: Shell wrapper script
scripts/run-gemini.sh
  → Invokes Gemini CLI multiple times sequentially:
     gemini -p "Run context resolution..." > .context.md
     gemini -p "Run reconnaissance..." > .recon.md
     gemini -p "Run STRIDE for component X..." > .stride-X.json
     gemini -p "Merge and finalize..." > threat-model.md
     gemini -p "QA review..." 
```

Option A is preferred — it keeps the pipeline in a single session with shared context. The orchestrator agent would need elevated `max_turns` (e.g., 100+) and `timeout_mins` (e.g., 60) to complete the full pipeline.

**Steps:**
1. Move agent `.md` files to `.gemini/agents/`, add `max_turns` and `timeout_mins` fields
2. Create TOML command files for slash commands
3. Flatten the two-stage skill invocation into single-agent orchestration (QA becomes a subagent of the orchestrator, not a separate stage)
4. Embed security steering logic in `GEMINI.md` or as an always-on instruction
5. Embed logging instructions in agent prompts (already partially done via `logging-standard.md`)
6. Configure MCP in Gemini settings

**Estimated effort:** 4–6 weeks. The no-recursion constraint forces restructuring the orchestration model, and the lack of hooks requires workarounds for steering and logging.

### Amazon Kiro

**Feasibility: Medium-Low** — Kiro's spec-driven model is fundamentally different from the agent-pipeline approach.

**What maps (with adaptation):**
- Agent instructions → `.kiro/steering/*.md` with inclusion modes
- MCP → Powers or manual MCP config
- Parallel subagents → Kiro custom subagents

**What has no equivalent:**
- **Skills / slash commands** — Kiro has no custom command system. The entry point would need to be a manual prompt or an automation trigger.
- **Hook event types** — only file-save triggers. No prompt-submit or tool-use hooks.
- **Model selection** — limited to Sonnet 4.5 or Auto. No per-agent model override for the `--stride-model opus` pattern.
- **Turn budgets** — not exposed.

**Alternative approach — Kiro's spec-driven model:**

Instead of porting the agent pipeline directly, reframe the threat model as a Kiro spec workflow:

```
.kiro/specs/threat-model/
  requirements.md    ← "Generate a STRIDE threat model for this repository"
  design.md          ← Phase instructions (architecture, STRIDE methodology)
  tasks.md           ← Auto-generated task breakdown (context, recon, analysis, etc.)
```

Kiro's autonomous agent would then execute the tasks, using steering files for methodology guidance and Powers for MCP integration. This loses the fine-grained phase control but aligns with Kiro's philosophy.

**Steps:**
1. Create steering files from phase-group instructions (`.kiro/steering/stride-methodology.md`, etc.)
2. Map security steering keywords into an `always` inclusion steering file
3. Create a spec template for threat model generation
4. Configure MCP via Powers or manual setup
5. Create custom subagent configs for parallel STRIDE analysis
6. Accept loss of: hook-based logging, per-agent model override, turn budgets, slash commands

**Estimated effort:** 6–8 weeks. Requires rethinking the plugin's architecture to fit Kiro's spec-driven paradigm rather than porting the agent pipeline.

---

## What Is Fully Portable

These components transfer to any platform without modification:

1. **STRIDE threat modeling methodology** — the 11-phase pipeline, threat categories, fix patterns, quality standards, and severity rating criteria are expressed as Markdown prose
2. **Phase-group reference files** (`agents/phases/*.md`) — pure instruction content
3. **Shared standards** (`agents/shared/logging-standard.md`, `owasp-llm-top10.md`) — pure reference content
4. **Intermediate file schemas** — JSON/YAML data structures for inter-agent communication
5. **Requirements YAML format** (`data/appsec-requirements-fallback.yaml`) — framework-agnostic
6. **Python validation scripts** (`validate_config.py`, `validate_intermediate.py`) — standard Python
7. **Mock context server** (`mock-context-server.py`) — standard REST/MCP endpoint
8. **Headless runner concept** (`run-headless.sh`) — adaptable to any CLI-based tool
9. **SARIF output format** — industry standard, framework-agnostic
10. **Known threats input format** (`docs/known-threats.yaml`) — framework-agnostic

## What Requires Rearchitecting

These components are tightly coupled to Claude Code and need platform-specific solutions:

| Component | Why it's coupled | Rearchitecting needed |
|-----------|-----------------|----------------------|
| Two-stage skill invocation | Skills invoke agents sequentially; not all platforms support this | Flatten into single-agent orchestration or use wrapper scripts |
| Dynamic turn budgets | `maxTurns` is Claude Code-specific; few platforms match this | Embed budget awareness in prompts or accept platform defaults |
| Hook-based security steering | Requires `UserPromptSubmit` hook with keyword matching | Move to always-on instruction file or MCP-based evaluation |
| Hook-based cost tracking | Requires `Stop`/`SubagentStop` hooks with token data | Lose per-session cost data or build external telemetry |
| Tool permission allowlist | `settings.json` is Claude Code-specific | Use platform-specific permission models |
| Checkpoint/resume | Skill reads `.appsec-checkpoint` and re-invokes orchestrator | Reimplement in platform's command/automation layer |

---

## Recommended Approach

### For maximum reach: abstract the methodology

Rather than maintaining 5 platform-specific ports, extract the portable core into a shared methodology layer:

```
appsec-methodology/
  phases/
    phase-group-recon.md
    phase-group-architecture.md
    phase-group-threats.md
    phase-group-finalization.md
  shared/
    logging-standard.md
    owasp-llm-top10.md
    validation-routine.md
  data/
    appsec-requirements-fallback.yaml
  schemas/
    stride-component.json
    dep-scan.json
  scripts/
    validate_intermediate.py
    security_steering.py
    mock-context-server.py
```

Then maintain thin platform adapters that wire this methodology into each tool's agent/skill/hook system. Changes to the STRIDE methodology propagate to all platforms; only orchestration glue is platform-specific.

### If choosing one platform to port to first

**Copilot** is the lowest-effort port — its agent, skill, and hook systems are near-identical to Claude Code's. Cursor is a close second (missing only `SubagentStop`). Gemini CLI is viable but requires flattening the orchestration. Kiro requires the most fundamental rethinking.

| Priority | Platform | Effort | Coverage |
|----------|---------|--------|----------|
| 1 | GitHub Copilot | 2–3 weeks | VS Code, GitHub.com, JetBrains, CLI |
| 2 | Cursor | 2–3 weeks | Cursor IDE |
| 3 | Gemini CLI | 4–6 weeks | Terminal, VS Code (via Gemini Code Assist) |
| 4 | Amazon Kiro | 6–8 weeks | Kiro IDE |
