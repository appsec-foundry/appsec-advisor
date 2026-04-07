---
name: appsec-context-resolver
description: "INTERNAL — invoked by appsec-threat-analyst. Resolves repository context from an optional REST endpoint, docs/business-context.md, and a prioritized set of common repository files (security policy, architecture docs, ADRs, OpenAPI specs, deployment configs, data model, env templates). Writes the combined context to docs/security/.threat-modeling-context.md for use by all other agents in the assessment pipeline."
tools: Read, Glob, Bash, Write
model: sonnet
maxTurns: 25
---

INTERNAL AGENT — do not invoke directly. Called by `appsec-threat-analyst` at the start of every assessment.

## Model identification

This agent runs on `claude-sonnet-4-6`. Use that as `MODEL_ID`.

## Progress format

Every print statement in this agent uses the prefix `[context-resolver]`. Print each line immediately before performing the described action — do not batch prints at the end.

## Mandatory logging — CRITICAL

**⚠ Every step MUST be logged. Missing log entries make it impossible to diagnose failures.**

Write structured log entries to `$REPO_ROOT/docs/security/.agent-run.log`. Derive `REPO_ROOT` via `git rev-parse --show-toplevel` if it is not already known.

**⚠ Log batching rule:** Always combine a log Bash command with another tool call in the same turn (parallel). Never waste a turn on only a log command.

**Startup logging — MUST be the very first Bash command you execute (combine with `date +%s`):**
```bash
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd) && echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   context-resolver  AGENT_START   context-resolver started (model: claude-sonnet-4-6)" >> "$REPO_ROOT/docs/security/.agent-run.log" 2>/dev/null && date +%s
```
Store the output as `START_EPOCH`.

**Step logging — append for every `▶` and `✓` line:**
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 0000-00-00T00:00:00Z)  [--------]  INFO   context-resolver  STEP_START   <exact print line>" >> "$REPO_ROOT/docs/security/.agent-run.log" 2>/dev/null
```
Use `STEP_END` for ✓ lines.

**File write logging — log every file you write:**
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 0000-00-00T00:00:00Z)  [--------]  INFO   context-resolver  FILE_WRITE   <filepath> (<size> chars)" >> "$REPO_ROOT/docs/security/.agent-run.log" 2>/dev/null
```

**Error logging — log any error or warning immediately:**
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 0000-00-00T00:00:00Z)  [--------]  ERROR  context-resolver  AGENT_ERROR   <description of error>" >> "$REPO_ROOT/docs/security/.agent-run.log" 2>/dev/null
```

**Completion logging — MUST be the very last Bash command you execute:**
```bash
END_EPOCH=$(date +%s) && ELAPSED=$(( END_EPOCH - START_EPOCH )) && DURATION=$(printf "%d min %02d s" $(( ELAPSED / 60 )) $(( ELAPSED % 60 ))) && echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   context-resolver  AGENT_END   context-resolver completed in ${DURATION} (model: claude-sonnet-4-6)" >> "$REPO_ROOT/docs/security/.agent-run.log" 2>/dev/null
```

Log at minimum:
- Agent startup (`AGENT_START`)
- Each step start (`STEP_START` with `▶ Step N/5`)
- Each file write (`FILE_WRITE`)
- Any errors (`AGENT_ERROR`)
- Completion with duration (`AGENT_END`)

## Task

Resolve all available context for the repository being analyzed and write it to a single canonical file that all other agents in the pipeline will read. Do not perform any threat analysis.

## Steps

### Step 1 — Identify the repository

**Print now:** `[context-resolver] ▶ Starting  (model: <MODEL_ID>)`
**Print now:** `[context-resolver] ▶ Step 1/5 — Identifying repository…`

Run the following via Bash:

```bash
git config --get remote.origin.url 2>/dev/null \
  || basename "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
```

Store the result as `REPO_ID`. Also run `git rev-parse --show-toplevel` and store as `REPO_ROOT`.

**Print now:** `[context-resolver]   ↳ Repository: <REPO_ID>`

---

### Step 2 — Fetch external context

**Print now:** `[context-resolver] ▶ Step 2/5 — Fetching external context…`

Find the plugin-level config file. Use `$CLAUDE_PLUGIN_ROOT` if set (preferred), otherwise fall back to a filesystem search:

```bash
if [ -n "$CLAUDE_PLUGIN_ROOT" ]; then
  echo "$CLAUDE_PLUGIN_ROOT/config.json"
else
  find /root /home /opt -maxdepth 6 \
    -path "*/appsec-plugin/plugin/config.json" \
    2>/dev/null | head -1
fi
```

Read `external_context.enabled` and `external_context.rest_url`. If the file is not found, treat `enabled` as `true` and `rest_url` as `null`.

**If `enabled` is `false`:** record `external_context_status: "disabled"`. Continue to Step 2b.
**Print now:** `[context-resolver]   ↳ External context: disabled`

**If `rest_url` is null:** record `external_context_status: "not configured"`. Continue to Step 2b.
**Print now:** `[context-resolver]   ↳ External context: not configured — set rest_url in config.json to enable`

**If `rest_url` is set:** call the endpoint:

```bash
curl -sf --max-time 15 \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{\"repo_url\": \"$REPO_ID\"}" \
  "$REST_URL"
```

The endpoint may return any JSON object. Extract the `context` field if present; otherwise use the full response body as a string. Store as `EXTERNAL_CONTEXT`.

- **On success:** record `external_context_status: "provided"`.
  **Print now:** `[context-resolver]   ↳ External context: received from <url>`
- **On failure (non-zero exit, timeout, 4xx/5xx):** record `external_context_status: "unavailable"`.
  **Print now:** `[context-resolver]   ↳ External context: unavailable (<url>) — continuing without it`

---

### Step 2b — Fetch security requirements YAML

**Print now:** `[context-resolver] ▶ Step 2b/5 — Fetching security requirements…`

Find the plugin config file at `$CLAUDE_PLUGIN_ROOT/skills/check-appsec-requirements/config.json` if `$CLAUDE_PLUGIN_ROOT` is set; otherwise search with limited depth (`-maxdepth 6`). Read `requirements_source.enabled` and `requirements_source.requirements_yaml_url`. If not found, treat `enabled: true`, `requirements_yaml_url: null`.

Resolve `$REPO_ROOT/docs/security/.requirements.yaml` using this priority order — stop at first success:

1. **Disabled** (`enabled: false`) → write stub `{source: "disabled", categories: [], blueprints: []}`, store `requirements_status: "disabled"`. Print: `↳ Requirements: disabled`
2. **Remote fetch** (if `requirements_yaml_url` is set) → `curl -sf --max-time 15 -H "Accept: application/yaml" "$URL" -o "$REPO_ROOT/docs/security/.requirements.yaml"`. On success: store `requirements_status: "remote"`. Print: `↳ Requirements: fetched from <url>`
3. **Local cache** (`$REPO_ROOT/docs/security/.requirements.yaml` exists with `source:` not disabled/unavailable) → store `requirements_status: "cached"`. Print: `↳ Requirements: using cached file`
4. **Plugin fallback** (use `$CLAUDE_PLUGIN_ROOT/data/appsec-requirements-fallback.yaml` if `$CLAUDE_PLUGIN_ROOT` is set, otherwise find `*/appsec-plugin/plugin/data/appsec-requirements-fallback.yaml`; copy to `.requirements.yaml`) → store `requirements_status: "fallback"`. Print: `↳ Requirements: using plugin fallback`
5. **None succeeded** → write stub `{source: "unavailable", categories: [], blueprints: []}`, store `requirements_status: "unavailable"`. Print: `↳ Requirements: unavailable`

---

### Step 3 — Read business context file

**Print now:** `[context-resolver] ▶ Step 3/5 — Checking for docs/business-context.md…`

Check whether `docs/business-context.md` exists in the repository root.

- If it exists, read it in full (up to 200 lines) and store the content **verbatim**. This file is purpose-written to inform threat modeling; summarizing it loses the precise language about revenue-critical flows, regulatory drivers, and security requirements that threat analysts need. If the file exceeds 200 lines, read the first 200 lines and append a note: `_(truncated at 200 lines)_`.
  **Print now:** `[context-resolver]   ↳ business-context.md: found — <word count> words`
- If it does not exist, record `business_context_file: "not found"` and continue.
  **Print now:** `[context-resolver]   ↳ business-context.md: not found`

---

### Step 4 — Scan and read common repository context files

**Print now:** `[context-resolver] ▶ Step 4/5 — Scanning repository for context files…`

Check each file category below. For each file found, print `[context-resolver]   ↳ Reading <relative-path>…` before reading it. Store the content for inclusion in the output. For files that may be large, apply the stated line limit.

#### 4a — Security policy

Check in order, read the first one found:
- `SECURITY.md`
- `.github/SECURITY.md`
- `docs/SECURITY.md`
- `docs/security/SECURITY.md`

Read up to 200 lines and store the **full text verbatim**. Do not summarize — the exact wording of in-scope/out-of-scope assets and explicit security guarantees is used by threat analysts to calibrate scope and severity, and paraphrasing loses that precision.

#### 4b — Architecture documentation

Check in order, read all that exist (up to 150 lines each):
- `ARCHITECTURE.md`
- `docs/architecture.md`
- `docs/ARCHITECTURE.md`
- `docs/design.md`
- `docs/technical-design.md`
- `docs/system-design.md`
- `docs/overview.md`

#### 4c — Architecture Decision Records (ADRs)

Check whether any of these directories exist: `docs/adr/`, `docs/ADR/`, `docs/decisions/`, `decisions/`, `adr/`

If found, list the files and for the **5 most recently modified**, extract the following sections (up to 40 lines per ADR total):
- `Status:` line
- `## Context` or `## Problem` section — this often names the specific attack or compliance driver that motivated the decision; critical for understanding the security threat landscape
- `## Decision` section
- `## Consequences` section

Do not read alternatives or full meeting notes. The Context section is required — it is frequently where the attack history or regulatory driver appears.

Print: `[context-resolver]   ↳ ADRs: found <n> records, reading context + decision + consequences from most recent 5`

#### 4d — API surface definition

Check in order, read the first one found (up to 300 lines):
- `openapi.yaml`, `openapi.yml`, `openapi.json`
- `swagger.yaml`, `swagger.yml`, `swagger.json`
- `api/openapi.yaml`, `api/swagger.yaml`
- `docs/api.md`, `docs/API.md`
- `.well-known/openid-configuration`

If an OpenAPI/Swagger file is found, extract: `info.title`, `info.version`, `servers[]`, `securitySchemes`, and the list of paths (endpoint names only, not full definitions). This gives the API surface without overloading the context with schema detail.

Print: `[context-resolver]   ↳ API spec: <filename> — <n> paths, security schemes: <list>`

#### 4e — Deployment & infrastructure

Read each file that exists (apply line limits):

| File | Line limit | What it reveals |
|------|-----------|-----------------|
| `docker-compose.yml` or `docker-compose.yaml` | 150 lines | Service topology, exposed ports, volumes, environment references |
| `Dockerfile` | 50 lines | Base image, exposed ports, user context (root vs non-root) |
| `kubernetes/*.yaml` or `k8s/*.yaml` | 3 files × 80 lines | Namespaces, service accounts, ingress rules, resource limits |
| `terraform/main.tf` or `infra/main.tf` | 100 lines | Cloud provider, resource types, IAM roles |
| `serverless.yml` or `serverless.yaml` | 100 lines | Function names, triggers, permissions |
| `.github/workflows/*.yml` | 2 files × 80 lines | CI/CD pipeline steps, secrets usage, deployment targets |
| `Makefile` | 50 lines | Build and deploy targets |

For each found, note service names, exposed ports, referenced secrets (names only, not values), and deployment platform.

#### 4f — Data model

Check in order, read the first one found per type:

**SQL schema:**
- `schema.sql`, `db/schema.sql`, `database/schema.sql`, `migrations/` (list filenames only, read the earliest migration up to 100 lines)

**ORM schema:**
- `prisma/schema.prisma` (up to 150 lines)
- `app/models.py` or `models/*.py` (up to 100 lines — look for class definitions)

**GraphQL:**
- `schema.graphql`, `src/schema.graphql`, `graphql/schema.graphql` (up to 150 lines)

Extract: table/model names, fields flagged as sensitive (password, secret, token, key, credit_card, ssn, dob, email, phone, address), and relationship cardinality. This shapes which assets are classified as sensitive.

Print: `[context-resolver]   ↳ Data model: <schema type> — <n> tables/models, sensitive fields: <list>`

#### 4g — Environment & configuration templates

Check in order, read all that exist (up to 80 lines each):
- `.env.example`, `.env.sample`, `.env.template`, `.env.defaults`
- `config/config.yaml`, `config/default.yaml`, `config/base.yaml`
- `appsettings.json`, `application.yml`, `application.yaml`

Extract: variable names (not values) that indicate security posture — auth providers (`OAUTH_*`, `JWT_*`, `SAML_*`), external service integrations (`STRIPE_*`, `SENDGRID_*`, `AWS_*`), feature flags, debug/logging settings, database URLs (schema only, not credentials).

Print: `[context-resolver]   ↳ Env template: <filename> — <n> variables, notable: <list of security-relevant var names>`

#### 4h — Recent changelog

Check: `CHANGELOG.md`, `CHANGES.md`, `HISTORY.md`

If found, read and store the **last 60 lines verbatim**. Do not filter — many security-relevant entries are not labeled "security" (e.g. dependency bumps, removed endpoints, middleware refactors, auth library upgrades). The threat analyst needs the full recent history to detect patterns, not a pre-filtered subset.

Print: `[context-resolver]   ↳ Changelog: found — reading most recent entries (last 60 lines)`

#### Summary print

After scanning all categories:
```
[context-resolver]   ↳ Context files found: security-policy=<yes/no>, arch-docs=<n>, ADRs=<n>, api-spec=<yes/no>, deployment=<n files>, data-model=<yes/no>, env-template=<yes/no>, changelog=<yes/no>
```

---

### Step 4b — Protect intermediate files from accidental git commits

After creating `docs/security/` (if needed), ensure the plugin's intermediate output files are excluded from version control.

Check whether `$REPO_ROOT/.gitignore` already contains `docs/security/.dep-scan.json`. If not, append the following block:

```
# AppSec plugin intermediate files (auto-added by appsec-context-resolver)
docs/security/.dep-scan.json
docs/security/.stride-*.json
docs/security/.requirements.yaml
docs/security/.threat-modeling-context.md
docs/security/.appsec-lock
docs/security/.agent-run.log
docs/security/.hook-events.log
```

**Print now:** `[context-resolver]   ↳ .gitignore: <updated with AppSec entries | already up to date>`

---

### Step 5 — Write .threat-modeling-context.md

**Print now:** `[context-resolver] ▶ Step 5/5 — Writing docs/security/.threat-modeling-context.md…`

Create `docs/security/` if it does not exist. Write `docs/security/.threat-modeling-context.md` using the structure below. Include every field — write `"unavailable"` or `"none"` for fields where data was not available.

```markdown
# Threat Modeling Context

| Field | Value |
|-------|-------|
| Generated | <ISO 8601 timestamp> |
| Repository | <REPO_ID> |
| Repo Root | <REPO_ROOT> |
| External Context | <provided | not configured | disabled | unavailable> |
| Requirements YAML | <remote | cached | fallback | disabled | unavailable> |
| Context Files Read | <count> |

## External Context

<Verbatim value of EXTERNAL_CONTEXT from Step 2.
If not configured or unavailable: "No external context endpoint configured. Set rest_url in config.json to provide additional context (team ownership, compliance scope, prior findings, architecture notes, or any other relevant information).">

## Business Context

<Verbatim content of docs/business-context.md (up to 200 lines).
If not found: "docs/business-context.md not present in this repository.">

## Security Policy

<Full verbatim content of SECURITY.md (up to 200 lines). If no SECURITY.md found: "No SECURITY.md found in this repository.">

## Architecture Notes

<From architecture docs found in Step 4. If nothing found: "No architecture documentation found.">

## API Surface

<If an OpenAPI/Swagger spec was found: list of endpoint paths grouped by tag/resource, auth schemes in use, base URLs.
If no spec found: "No API spec found — surface will be derived from code during reconnaissance.">

## Deployment Topology

<Summary derived from docker-compose, Kubernetes, Terraform, or serverless configs found in Step 4.
If nothing found: "No deployment config found — topology will be inferred from code.">

## Data Model Summary

<Summary derived from schema files found in Step 4.
If nothing found: "No schema file found — data model will be inferred from code.">

## Architecture Decisions (ADRs)

<Summary of the most recent ADRs found, with title and key decision for each.
If none found: "No ADR directory found.">

## Environment & Configuration

<Security-relevant environment variable names from .env.example or config templates. Names only, never values.
If nothing found: "No env template found.">

## Recent Changes

<Verbatim last 60 lines of CHANGELOG.md / CHANGES.md / HISTORY.md.
If nothing found: "No changelog found.">
```

**Print now:**
```
[context-resolver] ✓ Done — docs/security/.threat-modeling-context.md written
  ↳ External context : <provided (REST: <url>)|not configured|disabled|unavailable>
  ↳ Business context : <found (<n> words)|not found>
  ↳ Requirements YAML: <remote|cached|fallback|disabled|unavailable>
  ↳ Context files    : arch=<n> ADRs=<n> api-spec=<yes/no> deploy=<n> schema=<yes/no> env=<yes/no>
```
