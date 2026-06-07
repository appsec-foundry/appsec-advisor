---
name: audit-security-requirements
description: Audit the current repository against tagged security requirements (e.g. [SEC-CSP-1]) and verify whether each one is implemented. Prints open requirements to the conversation with color-coded status and concise evidence. Optionally saves as JSON or Markdown.
---

You are auditing whether security requirements are implemented in the current repository. Follow the steps below exactly.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, **do not scan the repository**. Print the block below verbatim to the conversation and exit with status 0.

```
/appsec-advisor:audit-security-requirements — Audit a repo against the SEC-* baseline.

USAGE
  /appsec-advisor:audit-security-requirements [CATEGORY_FILTER] [FLAGS]

  CATEGORY_FILTER is an optional substring matched against requirement IDs
  (e.g. "SEC-AUTH" or "AUTH"). When given, only matching requirements are
  checked. MUST-level requirements are always included regardless of filter.

FLAGS
  --md                     Save the rendered report as
                           docs/security/appsec-requirements-report.md
  --json                   Save the raw findings as
                           docs/security/appsec-requirements-report.json
  --save                   Both --md and --json
  --requirements <src>     Load the requirements YAML from <src> instead
                           of the configured source; no cache fallback.
                           <src> is an http(s):// URL (fetched remotely) or
                           a local file path (absolute, relative, or ~).
  --org-profile <path>     Use this org profile for source resolution.
  --preset <name>          Use a specific preset from the active org profile.
  --no-org-profile         Ignore packaged/env-pointed org profiles.

See `/appsec-advisor:status` for plugin & configuration status, and
`docs/configuration.md` → "Security Requirements Management" for the source
resolution rules.
```

After printing, exit. Do not read any files or perform any other action.

## Step 1 — Parse arguments and load requirements

### 1a — Parse arguments

The user may pass arguments after the skill name. Parse them now:

- **Category filter** — any word that does not start with `--` (e.g. `AUTH`, `SQL`) — filter results to requirements whose ID or category contains this string. `MUST` requirements are always included regardless of filter.
- `--md` — save results as `docs/security/appsec-requirements-report.md` after rendering
- `--json` — save results as `docs/security/appsec-requirements-report.json` after rendering
- `--save` — save both formats
- `--requirements <src>` — override the configured `requirements_yaml_url` for this run. `<src>` is an http(s):// URL (fetched remotely) or a local file path (absolute or relative). The source must load; there is no cache fallback when an explicit source is provided.
- `--org-profile <path>` — use this org profile for source resolution instead of the packaged default.
- `--preset <name>` — use a specific preset when resolving the active org profile.
- `--no-org-profile` — ignore any packaged or env-pointed org profile for this run.

Store the resolved flags: `save_md`, `save_json`, `category_filter`,
`requirements_url_override`, `org_profile_override`, `preset_override`,
`no_org_profile`.

#### Reject unknown flags (hard fail)

Non-flag words (tokens that do not start with `--`) are always valid — they
are treated as the `category_filter`. But any token starting with `--` that
is not one of the recognized flags above — or is not the value consumed by
`--requirements` — is a hard error. DO NOT proceed. Do not read any files,
do not fetch requirements, do not scan the repository. Print the following
block verbatim to stderr, substituting `<TOKEN>` with the first unknown
flag, then exit with status `2`:

```
Error: unknown argument '<TOKEN>'

/appsec-advisor:audit-security-requirements accepts only:
  [CATEGORY_FILTER]        Optional substring (e.g. AUTH, SQL) — no -- prefix
  --md                     Save the rendered report as Markdown
  --json                   Save the raw findings as JSON
  --save                   Both --md and --json
  --requirements <url>     Override the configured requirements YAML source
  --org-profile <path>     Override the packaged org profile
  --preset <name>          Select an org-profile preset
  --no-org-profile         Ignore org-profile defaults
  --help, -h               Show full help and exit

Run `/appsec-advisor:audit-security-requirements --help` for details.
```

`--requirements`, `--org-profile`, and `--preset` count as unknown when their
value is missing — treat the flag itself as the offending token in that case.

### 1b — Resolve the org profile and requirements YAML

Find the plugin root:

```bash
if [ -z "$CLAUDE_PLUGIN_ROOT" ]; then
  SKILL_MD_PATH=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-advisor/skills/audit-security-requirements/SKILL.md" \
    2>/dev/null | head -1)
  if [ -n "$SKILL_MD_PATH" ]; then
    CLAUDE_PLUGIN_ROOT=$(dirname "$(dirname "$(dirname "$SKILL_MD_PATH")")")
  fi
fi
export CLAUDE_PLUGIN_ROOT
if [ -z "$CLAUDE_PLUGIN_ROOT" ] || [ ! -d "$CLAUDE_PLUGIN_ROOT" ]; then
  echo "Error: CLAUDE_PLUGIN_ROOT could not be resolved — install appsec-advisor or set the variable manually." >&2
  exit 2
fi
```

Resolve the active org profile before resolving the requirements source. The
audit report output directory is the current repository's `docs/security/`;
the resolver writes `.org-profile-effective.json` there so the shared
requirements resolver and fetch gate see the same profile state as
`create-threat-model`.

```bash
AUDIT_OUTPUT_DIR="${PWD}/docs/security"
mkdir -p "$AUDIT_OUTPUT_DIR"

ORG_ARGS=()
[ -n "$ORG_PROFILE_OVERRIDE" ] && ORG_ARGS+=(--org-profile "$ORG_PROFILE_OVERRIDE")
[ -n "$PRESET_OVERRIDE" ] && ORG_ARGS+=(--preset "$PRESET_OVERRIDE")
[ "$NO_ORG_PROFILE" = "true" ] && ORG_ARGS+=(--no-org-profile)

python3 "$CLAUDE_PLUGIN_ROOT/scripts/resolve_org_profile.py" \
  --output-dir "$AUDIT_OUTPUT_DIR" \
  --emit-file \
  "${ORG_ARGS[@]}" >/dev/null
ORG_RESOLVE_EXIT=$?
if [ "$ORG_RESOLVE_EXIT" -ne 0 ]; then
  exit "$ORG_RESOLVE_EXIT"
fi
```

Resolve the source with `scripts/resolve_requirements_source.py`. Resolution
order is: explicit `--requirements <src>` > `--no-org-profile` / active org
profile source and `standalone_audit.enabled` > legacy
`skills/audit-security-requirements/config.json` > plugin cache fallback.

```bash
REQ_SOURCE_ARGS=(--caller audit-security-requirements --output-dir "$AUDIT_OUTPUT_DIR")
[ -n "$REQUIREMENTS_URL_OVERRIDE" ] && REQ_SOURCE_ARGS+=(--requirements "$REQUIREMENTS_URL_OVERRIDE")

REQ_SOURCE_JSON=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/resolve_requirements_source.py" \
  "${REQ_SOURCE_ARGS[@]}")
REQ_SOURCE_ENABLED=$(printf '%s' "$REQ_SOURCE_JSON" | python3 -c "import json,sys;print(str(json.load(sys.stdin).get('enabled',False)).lower())")
REQ_SOURCE_KIND=$(printf '%s' "$REQ_SOURCE_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('source') or '')")
```

If `REQ_SOURCE_KIND` is `org-profile` and `REQ_SOURCE_ENABLED` is `false`,
abort. This is the org profile's explicit `requirements.standalone_audit.enabled:
false` setting; do not silently fall back to the legacy config or cache.

```bash
if [ "$REQ_SOURCE_KIND" = "org-profile" ] && [ "$REQ_SOURCE_ENABLED" != "true" ]; then
  echo "✗ Requirements audit is disabled by the active org profile." >&2
  echo "  Set requirements.standalone_audit.enabled: true or pass --requirements <src>." >&2
  exit 2
fi
```

Fetch or load the requirements through the shared deterministic gate. Explicit
`--requirements <src>` is fail-closed with no cache fallback. Without an explicit
source, this audit is an explicit user action: require a usable org-profile or
legacy source, or a populated plugin cache.

```bash
FETCH_ARGS=(--caller audit-security-requirements --output-dir "$AUDIT_OUTPUT_DIR" --plugin-root "$CLAUDE_PLUGIN_ROOT")
if [ -n "$REQUIREMENTS_URL_OVERRIDE" ]; then
  FETCH_ARGS+=(--requirements "$REQUIREMENTS_URL_OVERRIDE")
else
  FETCH_ARGS+=(--require)
fi

python3 "$CLAUDE_PLUGIN_ROOT/scripts/fetch_requirements.py" "${FETCH_ARGS[@]}"
REQ_FETCH_EXIT=$?
if [ "$REQ_FETCH_EXIT" = "2" ]; then
  exit 2
fi
if [ "$REQ_FETCH_EXIT" -ne 0 ]; then
  exit "$REQ_FETCH_EXIT"
fi

REQUIREMENTS_YAML="$AUDIT_OUTPUT_DIR/.requirements.yaml"
```

Use `REQUIREMENTS_YAML` as the loaded catalog in Step 1c. The skill cannot
produce meaningful results without this file.

### 1c — Parse the YAML

From the loaded YAML, extract all requirements by iterating `categories[].requirements[]`. For each requirement record:

- **ID** — `requirements[].id` (e.g. `SEC-SQL`)
- **Category** — parent `categories[].id`
- **Category title** — parent `categories[].title`
- **Description** — `requirements[].text`
- **Requirement URL** — `requirements[].url` (may be null in fallback mode)
- **Priority** — `requirements[].priority` (`MUST` / `SHOULD` / `MAY`)

Apply the category filter from Step 1a if set.

### 1c-ii — Load blueprints (if present)

If the YAML contains a top-level `blueprints[]` section, build a blueprint index:

For each blueprint in `blueprints[]`, iterate its `sections[]`. For each section that has a `references[]` list, map every referenced requirement ID to the blueprint section:

```
blueprint_map[ref.id] → { bp_id, bp_title, section_title, section_url }
```

This map is used in Step 3b to show relevant blueprint guidance alongside violations.

### 1d — Scan for requirement references in the repository

Search source code, comments, and documentation for occurrences of all requirement IDs:

```bash
grep -rn "\[<ID>\]" --include="*.{ts,js,py,go,java,kt,rb,cs,php,md,yaml,yml}"
```

Run for every known requirement ID (or a combined regex). This surfaces code that already references requirements.

---

## Step 1.5 — Load threat model context (non-fatal)

Try to read `docs/security/threat-model.yaml` relative to the current working directory (the repo root). This step is always non-fatal — if the file is absent or unreadable, skip silently and continue to Step 2 with an empty `req_to_threats` map.

If the file exists and is valid YAML:

1. Extract `meta.generated` and store as `model_generated` (ISO 8601 string, for display).
2. Build a `req_to_threats` map by iterating `threats[]`:
   - For each threat that has a non-empty `violated_requirements` array, add an entry for each requirement ID in that array:
     ```
     req_to_threats[req_id] → [{ f_id, risk, title }, ...]
     ```
   - Use the threat's `id` field as `f_id`, `risk` as the severity label, and `title` as the short label. Current threat-model.yaml exports use final `F-NNN` IDs; do not convert them back to internal `T-NNN` IDs.
3. If `threats[]` is missing or empty, `req_to_threats` remains empty — no error.

This map is used in Step 3b to annotate violations with Threat Register links.

---

## Step 2 — Verify implementation for each requirement

For each requirement, search the codebase for evidence using `Grep` and `Read`.

Assign one of four statuses:

| Status | Icon | Meaning |
|--------|------|---------|
| PASS | ✅ | Implementation found; code demonstrably satisfies the requirement |
| PARTIAL | ⚠️ | Some implementation exists but incomplete, inconsistent, or only partial |
| FAIL | ❌ | No implementation found, or existing code contradicts the requirement |
| UNVERIFIABLE | ❓ | Cannot be verified from static analysis alone |

Collect for each requirement:
- Status
- Evidence: file path(s) and line number(s) — formatted as VS Code deep links `[path:line](vscode://file/ABSOLUTE_REPO_ROOT/path:line)`
- One-line finding
- For **FAIL**, **PARTIAL**, and **UNVERIFIABLE** additionally collect:
  - **Fix**: a specific, codebase-aware recommendation. Reference exact file and function names. Do not give generic advice if the specific code is available. For console output, keep it to one to three concise lines; for Markdown output, include a short before/after code block when meaningful code evidence exists.
  - **Effort**: `S` (< 1 hour, isolated change), `M` (half day, several files), or `L` (multi-day, architectural change)

---

## Step 3 — Render console output

Print a concise console summary plus only open requirements. "Open" means
`FAIL` or `PARTIAL`. Do not print `PASS` or `UNVERIFIABLE` items anywhere in
the console output. Keep `PASS` and `UNVERIFIABLE` in internal stats and JSON
output only.

Use ANSI colors when the target terminal supports them and `NO_COLOR` is not
set. If color support is unknown, render the same text and glyphs without ANSI
escape codes. Do not use emoji in the console output — use the geometric glyphs
`●` (filled) and `○` (hollow), which colorize cleanly via ANSI and degrade to
plain characters when color is off.

Each stats row and each open-requirement block leads with a **criticality dot**
that encodes status at a glance: filled `●` for the actionable statuses, hollow
`○` for the non-actionable `UNVERIFIABLE`. The dot color always matches the
status color in the table below, so the report reads as a single coherent
red/yellow/green scale.

ANSI color rules:

| Field | Color |
|-------|-------|
| `●` dot / `[FAIL]` | bold red (`\033[1;31m`) |
| `●` dot / `[PARTIAL]` | bold yellow (`\033[1;33m`) |
| `●` dot / `PASS` (stats only) | green (`\033[32m`) |
| `○` dot / `UNVERIFIABLE` (stats only) | dim gray (`\033[2m`) |
| `MUST` | red (`\033[31m`) |
| `SHOULD` | yellow (`\033[33m`) |
| `MAY` | cyan (`\033[36m`) |
| Requirement ID | cyan (`\033[36m`) |
| Field labels (`Finding`, `Risk`, etc.) | dim gray (`\033[2m`) |
| Paths / line references | dim gray (`\033[2m`) |

### 3a — Header

Print the header and stats block:

```
AppSec Requirements Audit
Repo   : <Project Name>
Source : <remote url | plugin cache path>
Scope  : <n> requirements checked<, filter: <filter> if set>

Result
  ● FAIL          <n>
  ● PARTIAL       <n>
  ● PASS          <n>
  ○ UNVERIFIABLE  <n>
```

Color each leading dot per the ANSI table (red / yellow / green / dim); the
status label keeps its own color. Use the canonical status token `UNVERIFIABLE` here — the same label used in
the Step 2 status table and the JSON `unverifiable` stat. Do not invent
synonyms such as "ignored" or "untestable". Right-align the counts in a single
column as shown.

### 3b — Findings

Print all open requirements (`FAIL` and `PARTIAL`) sorted in this order:

1. `FAIL` before `PARTIAL`
2. within each status: `MUST`, then `SHOULD`, then `MAY`
3. within each priority: requirement ID ascending

If there are zero open requirements, print:

```
Open Requirements

  None. All verifiable requirements passed.
```

Otherwise print `Open Requirements` followed by one block per open requirement.

Per-finding block:

```
● [FAIL] MUST  SEC-SQL  Parameterized SQL Queries
Finding : raw request input reaches sequelize.query() in routes/search.ts:23
Risk    : attacker-controlled search terms can alter the SQL predicate
Evidence: routes/search.ts:23
Fix     : replace string interpolation with bound parameters.
          Use `sequelize.query(sql, { replacements: { term } })` or the ORM query builder.
Effort  : M
Links   : requirement · blueprint · threat model F-014
```

Rules:

- **First line:** `<DOT> [<STATUS>] <PRIORITY>  <ID>  <Short Title>`, where
  `<DOT>` is a colored `●` — red for `FAIL`, yellow for `PARTIAL` — so the gap
  list scans as a colored column down the left edge.
  - Use `[FAIL]` or `[PARTIAL]` exactly.
  - Keep the title to 3-8 words in Title Case.
  - Do not use Markdown headings.
- **Finding:** one concrete sentence naming the file/function/config key and the failing mechanism.
- **Risk:** one concrete sentence fragment describing what the attacker or misuse path can do. No hype.
- **Evidence:** one line with up to three `path:line` entries. If there is no direct file evidence, use a concise process/config evidence phrase such as `no .github/workflows SAST job found`.
- **Fix:** one to three concise lines. Prefer code-aware guidance using the actual API, config key, or file name. It may include 1-2 short code fragments inline when that makes the required change clearer. Do not render a full before/after code block in the console.
- **Effort:** `S`, `M`, or `L`.
- **Links:** short labels only: `requirement`, `blueprint`, `threat model F-NNN`. Do not print full URLs in the console; save them for Markdown/JSON.
- Separate finding blocks with one blank line. Do not use `---` separators.

### 3c — Footer

Always print one footer block after open requirements:

```
Output
  Save Markdown: /appsec-advisor:audit-security-requirements --md
  Save JSON    : /appsec-advisor:audit-security-requirements --json
  Save both    : /appsec-advisor:audit-security-requirements --save
```

If one or more reports were saved in Step 4, print the written file paths
instead of the save-command reminder.

---

## Step 4 — Save output (conditional)

### 4a — If `save_md` is true

Write the full report to `docs/security/appsec-requirements-report.md` (create `docs/security/` if needed).

The Markdown report is more detailed than the console, but still includes
only open requirements (`FAIL` and `PARTIAL`). Do not include `PASS` or
`UNVERIFIABLE` requirement entries. Prefix with a metadata table:

````markdown
# AppSec Requirements — <Project Name>

| Field | Value |
|-------|-------|
| Generated | <ISO 8601 timestamp> |
| Repository | <git remote URL or directory name> |
| Source | <remote \| cached> |
| Open Requirements | <n> |
| 🔴 Failed | <n> |
| 🟡 Partial | <n> |
| 🟢 Passed | <n> |
| ⚪ Unverifiable | <n> |

## Open Requirements

> 🔴 fail · 🟡 partial — open gaps detailed below. 🟢 passed and ⚪ unverifiable are counted in the summary only.

| Status | Priority | ID | Requirement | Effort |
|--------|----------|----|-------------|--------|
| 🔴 FAIL | MUST | SEC-SQL | Parameterized SQL Queries | M |
| 🟡 PARTIAL | SHOULD | SEC-CSP-1 | Content Security Policy | S |

### 🔴 FAIL · MUST · SEC-SQL — Parameterized SQL Queries

Raw request input reaches `sequelize.query()` at `routes/search.ts:23`, so the query predicate can be changed by user-controlled input.

**Evidence:** `routes/search.ts:23`

**Risk:** An attacker can submit a crafted search term that changes the SQL predicate.

**Fix:** Replace string interpolation with bound parameters in `routes/search.ts`.

```ts
// Before
sequelize.query(`select * from product where name like '%${term}%'`)

// After
sequelize.query("select * from product where name like :term", {
  replacements: { term: `%${term}%` },
})
```

**Effort:** M

**Links:**
- Requirement: <full requirement url>
- Blueprint: <full blueprint section url, if available>
- Threat model: [F-014](docs/security/threat-model.md#f-014)

---

*Effort: S = under 1 hour · M = about half a day · L = multi-day or architectural change.*

````

Markdown rules:

- Prefix every status — in the summary metadata table, the overview table, and
  each `###` heading — with its criticality circle, reusing the threat model's
  house palette: 🔴 FAIL · 🟡 PARTIAL · 🟢 PASS · ⚪ UNVERIFIABLE. Keep the
  one-line palette legend (the `>` blockquote) directly under the
  `## Open Requirements` heading.
- Lead the `## Open Requirements` section with an overview table
  (`Status | Priority | ID | Requirement | Effort`) listing every open
  requirement in the sort order below. The detailed `###` blocks follow
  beneath it, so a reviewer can scan the whole gap list before reading details.
- Close the report with the one-line effort legend shown above
  (`*Effort: S = … · M = … · L = …*`), preceded by a `---` rule.
- Sort open requirements with the same order as console output.
- Use one `###` heading per open requirement: `### <STATUS> · <PRIORITY> · <ID> — <Title>`.
- Include full URLs for requirement and blueprint links.
- If `req_to_threats[req_id]` is non-empty (from Step 1.5), add one Threat model bullet per linked `F-NNN`, linking to `docs/security/threat-model.md#f-nnn`. Canonical link shape: `[F-NNN · Risk](docs/security/threat-model.md#f-nnn)`.
- Include a short before/after code block only when there is meaningful code evidence. Omit code blocks for missing process controls or absent configuration.
- Do not add a Passed section.
- Do not add an Unverifiable section.

Print: `✓ Markdown report written to docs/security/appsec-requirements-report.md`

### 4b — If `save_json` is true

Write structured JSON to `docs/security/appsec-requirements-report.json` using this schema:

```json
{
  "generated": "<ISO 8601>",
  "repository": "<remote URL or directory>",
  "requirements_source": "remote|cached|disabled",
  "filter": "<filter string or null>",
  "stats": {
    "total": 0,
    "pass": 0,
    "partial": 0,
    "fail": 0,
    "unverifiable": 0
  },
  "results": [
    {
      "id": "SEC-SQL",
      "category": "SEC-SECURE_DATA_HANDLING",
      "category_title": "Secure Data Handling",
      "priority": "MUST",
      "description": "Use parameterized SQL queries...",
      "status": "FAIL",
      "url": "https://req.example.com/sec-sql",
      "evidence": [
        { "file": "routes/search.ts", "line": 23 }
      ],
      "finding": "raw sequelize.query() with string interpolation",
      "fix": "Replace with parameterized queries or ORM methods",
      "effort": "M",
      "blueprint": {
        "id": "BP-API-VALIDATION",
        "section": "Parameterized Data Access",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
      }
    }
  ]
}
```

Print: `✓ JSON report written to docs/security/appsec-requirements-report.json`

### 4c — If neither flag is set

The save-command reminder is already covered by the Step 3 footer. Do not
print a second `Save:` line.

---

Note: if no `[SEC-*]` tags are found in the analyzed repo itself that is fine — the loaded requirements baseline is always checked regardless of existing code references. The skill requires a requirements YAML to be available (explicit `--requirements`, active org-profile source, legacy configured source, or plugin cache). If none is available, the skill aborts in Step 1b.
