# Design: `mitigate` Skill

A user-invocable skill that parses an existing threat model and generates a phased mitigation implementation plan with code-level verification of current status.

## Motivation

After `create-threat-model` produces a threat model with a Mitigation Register (Section 9), teams need to plan the actual implementation work. Currently, mitigations are listed with steps and code examples, but there is no structured plan that accounts for current code state, dependencies between mitigations, or phased rollout. The `mitigate` skill bridges the gap between "what to fix" and "how to schedule fixing it."

## Invocation

```
/appsec-plugin:mitigate [filter...] [flags]
```

### Filters (positional, combinable, required)

At least one filter is required. Without a filter, the skill prints an error with usage help.

| Filter type | Recognition | Example |
|---|---|---|
| Priority | Matches `P1`, `P2`, `P3`, `P4` (case-insensitive) | `/appsec-plugin:mitigate P1 P2` |
| Mitigation ID | Matches `M-NNN` pattern | `/appsec-plugin:mitigate M-003 M-007` |
| Component | Everything else — matched against `components[].id` and `components[].name` in `threat-model.yaml` | `/appsec-plugin:mitigate auth-service` |

Filter types can be combined: `/appsec-plugin:mitigate P1 auth-service` selects all P1 mitigations that address threats in `auth-service`.

### Flags

| Flag | Variable | Default | Description |
|---|---|---|---|
| `--md` | `WRITE_MD=true` | `false` | Write `$OUTPUT_DIR/mitigation-plan.md` |
| `--yaml` | `WRITE_YAML=true` | `false` | Write `$OUTPUT_DIR/mitigation-plan.yaml` |
| `--save` | `WRITE_MD=true, WRITE_YAML=true` | `false` | Write both files |
| `--repo <path>` | `REPO_ROOT=<path>` | cwd | Path to the analyzed repository |
| `--output <path>` | `OUTPUT_DIR=<path>` | `$REPO_ROOT/docs/security` | Output directory |

### Prerequisites

- `$OUTPUT_DIR/threat-model.yaml` must exist. If absent, the skill aborts with: "No threat model found. Run `/appsec-plugin:create-threat-model` first."
- `$OUTPUT_DIR/threat-model.yaml` must contain a `mitigations[]` array. If empty, the skill prints "No mitigations in threat model" and exits.

## Architecture

**Inline skill** — no dedicated agent. The skill runs directly in the user's session using Read, Grep, Glob, and Bash tools. This follows the pattern of `check-appsec-requirements`.

No new intermediate files. Output files (`mitigation-plan.md`, `mitigation-plan.yaml`) are end products — no dot-prefix, no `.gitignore` entry, no stale-file cleanup.

## Processing Pipeline

### Step 1: Parse & Filter (1-2 turns)

1. Read `threat-model.yaml`
2. Filter `mitigations[]` by user-provided filters:
   - Priority filter: match `mitigations[].priority` against `P1`, `P2`, etc.
   - Mitigation ID filter: match `mitigations[].id` against `M-NNN` patterns
   - Component filter: resolve `mitigations[].threat_ids` -> `threats[].component_id`, match against filter
   - Combined filters: intersection (all conditions must match)
3. For each filtered mitigation, resolve linked `threats[]` via `threat_ids`
4. Print summary:

```
[mitigate] Loaded threat-model.yaml
  > Total: 18 mitigations, 24 threats
  > Filter: P1, P2
  > Selected: 6 mitigations addressing 9 threats
```

If no mitigations match the filter, print "No mitigations match filter '<filter>'" and exit.

### Step 2: Code Analysis (3-10 turns)

For each selected mitigation:

1. Use `evidence.file:line` from linked threats as starting points
2. Check if vulnerable code still exists at the referenced location (Grep/Read)
3. Check if mitigation steps are already (partially) implemented — search for patterns from `code_example` ("After" section) and `steps[]` keywords
4. Determine status per mitigation:
   - **Open** — vulnerable code exists, no fix detected
   - **Partial** — fix partially present (e.g., 2 of 4 locations fixed)
   - **Resolved** — vulnerable code no longer present or fix fully detected
5. Collect concrete file:line references for the technical drill-down

Progress output per mitigation:
```
[mitigate]   > M-001 -- Remove eval from run-headless.sh ... Open (1 location)
[mitigate]   > M-002 -- Add parameterized queries ... Partial (3/5 fixed)
[mitigate]   > M-003 -- Rotate hardcoded JWT secret ... Resolved
```

Resolved mitigations are included in the plan as "already implemented" — the user should see the confirmation.

### Step 3: Strategic Plan (1-2 turns)

Derive a phased implementation plan from the analysis results:

1. **Detect dependencies** — mitigations touching the same files belong in the same phase
2. **Form phases** — grouped by priority level and dependencies:
   - Phase 1: P1 mitigations (0-48h timeline)
   - Phase 2: P2 mitigations (sprint timeline)
   - Phase 3: P3/P4 mitigations if in filter scope
3. **Aggregate effort per phase** — from mitigation `effort` fields (Low/Medium/High)
4. **Identify quick wins** — Low-effort mitigations addressing multiple threats

### Step 4: Technical Drill-Down (2-5 turns)

For each Open or Partial mitigation:

1. **What:** Mitigation title + addressed threats with severity
2. **Where:** Concrete files and lines from Step 2 analysis
3. **How:** Steps from `threat-model.yaml` + code example (before/after)
4. **Order:** If multiple locations, recommended change sequence
5. **Verification:** Verification instruction from the mitigation
6. **Status:** Open/Partial with specifics on what remains

Resolved mitigations get a short confirmation block (no drill-down).

## Output Formats

### Console (always)

Structured terminal output with box-drawing characters:

- **Header:** Project name, filter, mitigation/threat counts, source file date
- **Status Overview:** Open/Partial/Resolved counts with mitigation IDs
- **Strategic Plan:** Phased table with mitigation ID, title, status, effort, quick-win markers
- **Technical Details:** Per-mitigation blocks with location, steps, verification
- **Footer:** Summary counts + hint to save with `--save`

### Markdown (`--md`)

File: `$OUTPUT_DIR/mitigation-plan.md`

Same structure as console output, rendered as Markdown:
- Headings instead of box-drawing
- VS Code deep links (`vscode://file/<abs-path>:<line>`) on all file:line references
- Code examples rendered as fenced code blocks
- Tables for the strategic overview
- T-NNN and M-NNN as clickable internal anchors

### YAML (`--yaml`)

File: `$OUTPUT_DIR/mitigation-plan.yaml`

```yaml
meta:
  generated: <ISO 8601>
  source: threat-model.yaml
  source_generated: <ISO from threat-model.yaml meta.generated>
  filter: [P1, P2]
  repo_root: /path/to/repo
plan:
  phases:
    - name: "Immediate (P1)"
      effort: Low
      mitigations:
        - id: M-001
          title: "Remove eval from run-headless.sh"
          status: open
          effort: Low
          threat_ids: [T-001]
          locations:
            - file: scripts/run-headless.sh
              line: 47
              finding: "eval still present"
          steps:
            - "Replace eval with direct execution"
            - "Quote all variable expansions"
          verification: "grep -n 'eval' scripts/run-headless.sh returns 0 matches"
summary:
  total: 6
  open: 3
  partial: 2
  resolved: 1
```

## File Structure

```
plugin/skills/mitigate/
  SKILL.md          # Skill definition (single file)
```

No `config.json` — no configurable settings. Everything comes from `threat-model.yaml` and arguments.

## Skill Frontmatter

```yaml
---
name: mitigate
description: Parse an existing threat model and generate a phased mitigation implementation plan with code-level verification of current status.
---
```

## Plugin Integration

### CLAUDE_PLUGIN_ROOT Discovery

Same pattern as `create-threat-model` and `check-appsec-requirements` — fallback search via `find` when the env variable is not set.

### Documentation Updates

- `plugin/CLAUDE.md` — add to Skills table
- `docs/architecture.md` — add to Skills section
- `docs/flags-reference.md` — new "Mitigation Plan Flags" section
- `README.md` — add quick-start example

### Test Coverage

No new agent, so no changes to `test_agent_definitions.py`. Integration tests:

- `test_integration.py` — verify `skills/mitigate/SKILL.md` exists and has valid frontmatter
- `test_integration.py` — verify skill references `threat-model.yaml`

## Scope Boundaries

**In scope:**
- Parsing threat-model.yaml for mitigations and threats
- Code analysis to determine current mitigation status
- Phased strategic plan with dependency detection
- Technical drill-down with concrete file:line references
- Console, Markdown, and YAML output

**Out of scope:**
- Implementing mitigations (code changes) — this is a planning skill, not an implementation skill
- Creating new mitigations beyond what the threat model contains
- Modifying threat-model.yaml or threat-model.md
- Ticket/issue creation in external systems (Jira, Linear, GitHub Issues)
- Re-running the threat model or any of its phases
