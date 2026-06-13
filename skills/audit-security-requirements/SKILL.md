---
name: audit-security-requirements
description: Audit the current repository against a security requirements catalog and verify whether each requirement is implemented. Requirement IDs follow your catalog's own naming scheme (e.g. SEC-CSP-1, SCG-HARDENXML, or anything your YAML defines); tagging code with those IDs is optional and not required. Prints open requirements to the conversation with color-coded status and concise evidence. Optionally saves as JSON or Markdown.
---

You are auditing whether security requirements are implemented in the current repository. Follow the steps below exactly.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, **do not scan the repository**. Print the block below verbatim to the conversation and exit with status 0.

```
/appsec-advisor:audit-security-requirements — Audit a repo against your security requirements.

USAGE
  /appsec-advisor:audit-security-requirements [CATEGORY_FILTER] [FLAGS]

  CATEGORY_FILTER is an optional substring matched against requirement IDs
  (e.g. "SEC-AUTH" or "AUTH"). When given, only matching requirements are
  checked. MUST-level requirements are always included regardless of filter.

WHERE REQUIREMENTS COME FROM (highest priority first)
  1. --requirements <src>      explicit source for this run (no cache fallback)
  2. --demo                    packaged example catalog (clearly stamped DEMO)
  3. docs/security/requirements.yaml   a local repo catalog, if present
                               (beats the org profile; surfaced in the banner)
  4. the active org profile's configured source
  5. the legacy configured source
  6. the remembered source     the URL the catalog was last fetched from,
                               served from the plugin cache
  On first use with none of the above, the audit explains what to pass and
  offers to run against --demo.

SOURCE FLAGS
  --requirements <src>     http(s):// URL or local file path (abs/rel/~).
  --update                 force a fresh re-fetch from the remembered/configured
                           source and refresh the cache.
  --cache-only             use the plugin cache only; never touch the network.
  --demo                   audit against the packaged example catalog (DEMO).
  --status                 show which requirements WOULD be used (source, date,
                           count, freshness) and exit — no audit, no fetch.
  --clear-requirements     forget the remembered source + cached catalog, exit.
  --org-profile <path>     use this org profile for source resolution.
  --preset <name>          use a specific preset from the active org profile.
  --no-org-profile         ignore packaged/env-pointed org profiles.

OUTPUT FLAGS
  --md                     save the rendered report as
                           docs/security/appsec-requirements-report.md
  --json                   save the raw findings as
                           docs/security/appsec-requirements-report.json
  --save                   both --md and --json

DEFAULT BEHAVIOUR
  Every audit prints a banner first: which catalog is in effect, where it came
  from, when it was fetched, how many requirements, and whether it is still
  fresh (cache younger than 30 days is reused without a network round-trip;
  older triggers a refresh attempt, falling back to the cache if unreachable).

See `/appsec-advisor:status` for plugin & configuration status, and
`docs/security-requirements-audit-skill.md` for the full source-resolution rules.
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
- `--update` — force a fresh re-fetch from the remembered/configured source and refresh the plugin cache before auditing.
- `--cache-only` — use the plugin cache only; never touch the network.
- `--demo` — audit against the packaged example catalog. The report is stamped **DEMO**.
- `--status` — **mode flag**: print the resolution banner (source, date, count, freshness) and exit. Do not scan the repository.
- `--clear-requirements` — **mode flag**: forget the remembered source and delete the cached catalog, then exit. Do not scan the repository.
- `--org-profile <path>` — use this org profile for source resolution instead of the packaged default.
- `--preset <name>` — use a specific preset when resolving the active org profile.
- `--no-org-profile` — ignore any packaged or env-pointed org profile for this run.

Store the resolved flags: `save_md`, `save_json`, `category_filter`,
`requirements_url_override`, `update`, `cache_only`, `demo`, `status_mode`,
`clear_requirements`, `org_profile_override`, `preset_override`,
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
  --update                 Force a fresh re-fetch and refresh the cache
  --cache-only             Use the plugin cache only; never touch the network
  --demo                   Audit against the packaged example catalog (DEMO)
  --status                 Show which requirements would be used, then exit
  --clear-requirements     Forget the remembered source + cache, then exit
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

#### Mode flags — `--clear-requirements` and `--status` exit early

These two flags are maintenance/inspection modes. Handle them **before** any
repository scan. If `CLEAR_REQUIREMENTS` is set, run the gate's clear mode and
exit; the skill does not audit on this invocation:

```bash
if [ "$CLEAR_REQUIREMENTS" = "true" ]; then
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/fetch_requirements.py" \
    --caller audit-security-requirements --output-dir "$AUDIT_OUTPUT_DIR" \
    --plugin-root "$CLAUDE_PLUGIN_ROOT" --clear-requirements
  exit 0
fi
```

#### Honour an org profile that disables the standalone audit (governance-first)

Resolve the source first. When the active org profile configures a requirements
source but sets `requirements.standalone_audit.enabled: false`, that governance
decision wins — **even if a local `docs/security/requirements.yaml` is present**.
A passive in-repo catalog must not silently defeat the org policy. Only an
explicit per-run override — `--requirements <src>` or `--demo` (which resolve to
source `cli` / `demo`) — bypasses the block.

```bash
REQ_SOURCE_ARGS=(--caller audit-security-requirements --output-dir "$AUDIT_OUTPUT_DIR" --plugin-root "$CLAUDE_PLUGIN_ROOT")
[ -n "$REQUIREMENTS_URL_OVERRIDE" ] && REQ_SOURCE_ARGS+=(--requirements "$REQUIREMENTS_URL_OVERRIDE")
[ "$DEMO" = "true" ] && REQ_SOURCE_ARGS+=(--demo)

REQ_SOURCE_JSON=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/resolve_requirements_source.py" "${REQ_SOURCE_ARGS[@]}")
REQ_SOURCE_KIND=$(printf '%s' "$REQ_SOURCE_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('source') or '')")
ORG_AUDIT_DISABLED=$(printf '%s' "$REQ_SOURCE_JSON" | python3 -c "import json,sys;print(str(json.load(sys.stdin).get('org_audit_disabled',False)).lower())")

# Block when the org disabled the standalone audit, unless an explicit per-run
# source (--requirements / --demo → source cli/demo) overrides it.
if [ "$ORG_AUDIT_DISABLED" = "true" ] && [ "$REQ_SOURCE_KIND" != "cli" ] && [ "$REQ_SOURCE_KIND" != "demo" ]; then
  echo "✗ Requirements audit is disabled by the active org profile (standalone_audit.enabled: false)." >&2
  if [ "$REQ_SOURCE_KIND" = "local" ]; then
    echo "  A local docs/security/requirements.yaml does not override this org policy." >&2
  fi
  echo "  Override for this run with --requirements <src> or --demo, or set" >&2
  echo "  requirements.standalone_audit.enabled: true in the org profile." >&2
  exit 2
fi
```

#### Fetch or inspect through the shared deterministic gate

Resolution precedence (highest first): explicit `--requirements <src>` >
`--demo` > local `docs/security/requirements.yaml` > active org-profile source
(honouring `standalone_audit.enabled`) > legacy config > remembered source via
the plugin cache. A **local repo catalog overrides the org profile** and is
surfaced in the banner. The gate also writes a `.requirements-resolution.json`
sidecar describing the chosen source — render it as the startup banner.

Pass the user's source flags straight through to the gate. `--status` is a
no-fetch inspection mode; every other invocation loads the catalog:

```bash
FETCH_ARGS=(--caller audit-security-requirements --output-dir "$AUDIT_OUTPUT_DIR" --plugin-root "$CLAUDE_PLUGIN_ROOT")
if [ -n "$REQUIREMENTS_URL_OVERRIDE" ]; then
  FETCH_ARGS+=(--requirements "$REQUIREMENTS_URL_OVERRIDE")
else
  FETCH_ARGS+=(--require)
fi
[ "$DEMO" = "true" ]       && FETCH_ARGS+=(--demo)
[ "$UPDATE" = "true" ]     && FETCH_ARGS+=(--update)
[ "$CACHE_ONLY" = "true" ] && FETCH_ARGS+=(--cache-only)
[ "$STATUS_MODE" = "true" ] && FETCH_ARGS+=(--status)

python3 "$CLAUDE_PLUGIN_ROOT/scripts/fetch_requirements.py" "${FETCH_ARGS[@]}"
REQ_FETCH_EXIT=$?

REQ_RESOLUTION="$AUDIT_OUTPUT_DIR/.requirements-resolution.json"
REQUIREMENTS_YAML="$AUDIT_OUTPUT_DIR/.requirements.yaml"
```

**First-run / no-source handling (`REQ_FETCH_EXIT` == 2).** The gate aborts with
exit 2 only when requirements were requested but nothing loaded — no configured
source, and an empty cache. This is the genuine first-run case. Do not proceed
to scan. Print the guidance below, then **offer to run against the packaged demo
catalog** (decision A). When running interactively you may ask the user with
`AskUserQuestion` whether to re-run with `--demo`; otherwise just print the hint
and exit 2:

```
No security requirements are configured yet, and the plugin cache is empty.

Tell the audit where your requirements live, one of:
  • --requirements https://your-org/appsec-requirements.yaml   (fetch + remember)
  • drop a catalog at docs/security/requirements.yaml          (local repo file)
  • configure an org profile (see docs/org-profiles.md)

Or try it now against the bundled example catalog:
  /appsec-advisor:audit-security-requirements --demo
```

For any other non-zero, non-2 exit, propagate it:

```bash
if [ "$REQ_FETCH_EXIT" = "2" ]; then
  exit 2   # after printing the first-run guidance above
fi
if [ "$REQ_FETCH_EXIT" -ne 0 ]; then
  exit "$REQ_FETCH_EXIT"
fi
```

#### Render the startup banner (always, before scanning)

Read `REQ_RESOLUTION` and print a banner so the user always knows **which
requirements are in effect and how current they are** before any findings.
Derive a human "fetched N days ago" from `freshness.age_days`. Example:

```
Requirements Source
  Catalog  : Acme Application Security Requirements
  Source   : remembered · https://security.example.com/appsec-requirements.yaml
  Fetched  : 2026-06-05 (7 days ago) · catalog generated 2026-04-09
  Count    : 63 requirements
  Freshness: ● fresh (cache < 30 days)
  Override : --update (refresh) · --cache-only · --demo · --requirements <url> · --status · --clear-requirements
```

Banner rules:
- If `demo` is `true`, title the catalog line `Catalog  : <desc>  ⚠ DEMO — not your organization's requirements` and colour it yellow. The audit still runs, but every report it writes must carry the DEMO stamp (Steps 3a/4a).
- If `surfaced` is `true` (a local `docs/security/requirements.yaml` is in effect), add a line `Note     : using local repo catalog (overrides org profile)`.
- If `freshness.stale` is `true`, render `Freshness: ● STALE (cache ≥ 30 days) — refresh with --update` in yellow, and note that an `--update` attempt was already made this run if the disposition is `cache_after_fetch_fail`.
- If `disposition` is `cache_after_fetch_fail`, add `Source    : unreachable this run — served the cached copy` so the user knows the network refresh failed.
- If `STATUS_MODE` is set, print the banner and **stop here** — do not scan the repository, do not render findings, exit 0.

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

### 1d — Scan for inline requirement references (optional, non-essential)

Some teams annotate code with their requirement IDs; one common convention is
the bracket form `[<ID>]` (e.g. `[SEC-CSP-1]`). Many teams use a **different
convention or none at all** — that is expected. This scan is a convenience that
surfaces such references when they exist; the audit does **not** depend on it,
and finding zero references is normal and fine. Requirement IDs come from the
loaded catalog (Step 1c) and may use any naming scheme.

```bash
# Optional — only meaningful if this repo uses the [<ID>] tag convention.
grep -rn "\[<ID>\]" --include="*.{ts,js,py,go,java,kt,rb,cs,php,md,yaml,yml}"
```

Run for every known requirement ID (or a combined regex) if you scan at all.
Grading in Step 2 searches for actual implementation evidence per requirement
and is independent of any inline tag.

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

If the resolution banner reported `demo: true`, print a yellow line directly
under the header: `⚠ DEMO catalog — results do not reflect your organization's
requirements.` Keep the `Source :` line pointing at the example file.

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

- If the resolution banner reported `demo: true`, insert a blockquote warning
  directly under the `#` title: `> ⚠ **DEMO catalog** — audited against the
  packaged example requirements, not your organization's. Configure a real
  source with --requirements / an org profile.` Also set the metadata
  `| Source |` cell to `packaged example (DEMO)`.
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

Note: the analyzed repository does **not** need to tag its code with requirement IDs. The `[<ID>]` bracket form (e.g. `[SEC-CSP-1]`) is just one optional convention; many teams use a different scheme or none, and finding zero inline references is fine — the loaded catalog is always graded in full from codebase evidence regardless of inline tags. The skill requires a requirements catalog to be available, resolved in this priority order: explicit `--requirements`, `--demo`, a local `docs/security/requirements.yaml`, the active org-profile source, the legacy configured source, or the remembered source served from the plugin cache. On a fresh machine with none of these, the skill prints first-run guidance and offers `--demo` instead of failing cryptically (Step 1b). A successful fetch from a configured/remembered source remembers the URL (`.cache/requirements.source.json`) and refreshes the cache; a fresh cache (< 30 days) is reused without a network round-trip, while a stale cache triggers a refresh attempt that falls back to the cache when the source is unreachable.
