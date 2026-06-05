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

Store the resolved flags: `save_md`, `save_json`, `category_filter`, `requirements_url_override`.

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
  --help, -h               Show full help and exit

Run `/appsec-advisor:audit-security-requirements --help` for details.
```

`--requirements` counts as unknown when its URL value is missing — treat
the flag itself as the offending token in that case.

### 1b — Read config and resolve the requirements YAML

Find the plugin config:

```bash
SKILL_CONFIG=""
if [ -n "$CLAUDE_PLUGIN_ROOT" ]; then
  SKILL_CONFIG="$CLAUDE_PLUGIN_ROOT/skills/audit-security-requirements/config.json"
else
  SKILL_CONFIG=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-advisor/skills/audit-security-requirements/config.json" \
    2>/dev/null | head -1)
fi
```

Read `requirements_source.enabled` and `requirements_source.requirements_yaml_url`. If the file is not found, treat `enabled` as `false` and `requirements_yaml_url` as `null`.

Determine the plugin cache path:

```bash
if [ -n "$CLAUDE_PLUGIN_ROOT" ]; then
  REQUIREMENTS_CACHE="$CLAUDE_PLUGIN_ROOT/.cache/requirements.yaml"
else
  PLUGIN_ROOT=$(echo "$SKILL_CONFIG" | sed 's|/skills/audit-security-requirements/config.json||')
  REQUIREMENTS_CACHE="${PLUGIN_ROOT:-.}/.cache/requirements.yaml"
fi
```

**Note:** This skill always attempts to load requirements regardless of the `enabled` config value — it is an explicit user action. The `enabled` field only controls the default behavior for the `create-threat-model` skill.

Resolve the requirements YAML. The loading strategy depends on whether `--requirements <url>` was provided:

---

**Path A — `requirements_url_override` is set** (explicit source from `--requirements <src>`):

Load from the override source. No cache fallback — the explicit source must load.
An `http(s)://` value is fetched remotely; anything else is read as a local file
path (absolute or relative).

```bash
mkdir -p "$(dirname "$REQUIREMENTS_CACHE")"
case "$REQUIREMENTS_URL_OVERRIDE" in
  http://*|https://*)
    curl -sf --max-time 15 -H "Accept: application/yaml" "$REQUIREMENTS_URL_OVERRIDE" \
      -o "$REQUIREMENTS_CACHE" ;;
  *)  # local file path — no scheme, no file://
    cp "$REQUIREMENTS_URL_OVERRIDE" "$REQUIREMENTS_CACHE" ;;
esac
```

- On success: use `$REQUIREMENTS_CACHE`. Print: `▶ Requirements: loaded from <src> (cached to <REQUIREMENTS_CACHE>)`
- On failure: abort with:
  ```
  ✗ Could not load requirements from <src>

    The source was passed via --requirements and must load.
    For an http(s):// URL, verify it is correct and the server is running;
    for a local path, verify the file exists and is readable.

    Need a starting point? The plugin ships a reference YAML at
      data/appsec-requirements-fallback.yaml
    (63 baseline requirements across 38 categories, plus 9 blueprint entries,
    with CWE/OWASP links where available). Copy it, adapt the IDs and URLs
    to your organization, serve it over HTTP
    (e.g. `python3 scripts/mock-server.py`), and pass the
    resulting URL via --requirements or requirements_yaml_url.
  ```
  **Stop here — do not proceed to Step 1c.**

---

**Path B — no `requirements_url_override`** (no explicit URL — use configured URL / cache):

Try the following sources in order. Stop at the first success.

**1. Remote fetch** — only if `requirements_yaml_url` is set:

```bash
mkdir -p "$(dirname "$REQUIREMENTS_CACHE")"
curl -sf --max-time 15 -H "Accept: application/yaml" "$REQUIREMENTS_YAML_URL" \
  -o "$REQUIREMENTS_CACHE"
```

- On success: use `$REQUIREMENTS_CACHE`. Print: `▶ Requirements: fetched from <url> (cached to <REQUIREMENTS_CACHE>)`
- On failure: print `⚠ Could not fetch from <url> — checking plugin cache…` and continue.

**2. Plugin cache** — use `$REQUIREMENTS_CACHE` if it exists and is not empty:

```bash
test -s "$REQUIREMENTS_CACHE" && echo exists || echo missing
```

If found: use this file. Print: `▶ Requirements: loaded from plugin cache (<REQUIREMENTS_CACHE>)`

**3. No requirements available** — abort with:

```
✗ Could not load requirements.

  No remote endpoint responded and no plugin cache exists.
  To fix this:
    1. Set requirements_yaml_url in skills/audit-security-requirements/config.json
    2. Or pass --requirements <url> to provide a URL directly
    3. Run this skill once with the endpoint reachable to populate the cache

  The cache is stored at: <REQUIREMENTS_CACHE>

  Starter template: data/appsec-requirements-fallback.yaml contains
  63 baseline requirements (38 categories plus 9 blueprint entries) as a
  reference. Copy and adapt it, then serve it from any HTTP endpoint
  (e.g. `python3 scripts/mock-server.py`) — that URL goes into
  requirements_yaml_url.
```

**Stop here — do not proceed to Step 1c.** The skill cannot produce meaningful results without a requirements baseline.

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

Note: if no `[SEC-*]` tags are found in the analyzed repo itself that is fine — the loaded requirements baseline is always checked regardless of existing code references. The skill requires a requirements YAML to be available (either fetched from the configured URL or from the plugin cache). If neither is available, the skill aborts in Step 1b.
