---
name: check-appsec-requirements
description: Scans the current repository for tagged security requirements (e.g. [SEC-CSP-1]) and verifies whether each one is implemented. Prints results to the conversation with color-coded status and clickable links. Optionally saves as JSON or Markdown.
---

You are checking whether security requirements are implemented in the current repository. Follow the steps below exactly.

## Step 1 — Parse arguments and load requirements

### 1a — Parse arguments

The user may pass arguments after the skill name. Parse them now:

- **Category filter** — any word that does not start with `--` (e.g. `AUTH`, `SQL`) — filter results to requirements whose ID or category contains this string. `MUST` requirements are always included regardless of filter.
- `--md` — save results as `docs/security/appsec-requirements-report.md` after rendering
- `--json` — save results as `docs/security/appsec-requirements-report.json` after rendering
- `--save` — save both formats
- `--requirements-url <url>` — override the configured `requirements_yaml_url` for this run. The URL must be reachable; there is no cache fallback when an explicit URL is provided.

Store the resolved flags: `save_md`, `save_json`, `category_filter`, `requirements_url_override`.

### 1b — Read config and resolve the requirements YAML

Find the plugin config:

```bash
SKILL_CONFIG=""
if [ -n "$CLAUDE_PLUGIN_ROOT" ]; then
  SKILL_CONFIG="$CLAUDE_PLUGIN_ROOT/skills/check-appsec-requirements/config.json"
else
  SKILL_CONFIG=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-plugin/plugin/skills/check-appsec-requirements/config.json" \
    2>/dev/null | head -1)
fi
```

Read `requirements_source.enabled` and `requirements_source.requirements_yaml_url`. If the file is not found, treat `enabled` as `false` and `requirements_yaml_url` as `null`.

Determine the plugin cache path:

```bash
if [ -n "$CLAUDE_PLUGIN_ROOT" ]; then
  REQUIREMENTS_CACHE="$CLAUDE_PLUGIN_ROOT/.cache/requirements.yaml"
else
  PLUGIN_ROOT=$(echo "$SKILL_CONFIG" | sed 's|/skills/check-appsec-requirements/config.json||')
  REQUIREMENTS_CACHE="${PLUGIN_ROOT:-.}/.cache/requirements.yaml"
fi
```

**Note:** This skill always attempts to load requirements regardless of the `enabled` config value — it is an explicit user action. The `enabled` field only controls the default behavior for the `create-threat-model` skill.

Resolve the requirements YAML. The loading strategy depends on whether `--requirements-url` was provided:

---

**Path A — `requirements_url_override` is set** (explicit URL from `--requirements-url`):

Fetch from the override URL. No cache fallback — the explicit URL must be reachable.

```bash
mkdir -p "$(dirname "$REQUIREMENTS_CACHE")"
curl -sf --max-time 15 -H "Accept: application/yaml" "$REQUIREMENTS_URL_OVERRIDE" \
  -o "$REQUIREMENTS_CACHE"
```

- On success: use `$REQUIREMENTS_CACHE`. Print: `▶ Requirements: fetched from <url> (cached to <REQUIREMENTS_CACHE>)`
- On failure: abort with:
  ```
  ✗ Could not fetch requirements from <url>

    The URL was passed via --requirements-url and must be reachable.
    Verify the URL is correct and the server is running.
  ```
  **Stop here — do not proceed to Step 1c.**

---

**Path B — no `requirements_url_override`** (use configured URL / cache):

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
    1. Set requirements_yaml_url in plugin/skills/check-appsec-requirements/config.json
    2. Or pass --requirements-url <url> to provide a URL directly
    3. Run this skill once with the endpoint reachable to populate the cache

  The cache is stored at: <REQUIREMENTS_CACHE>
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

### 1d — Scan for requirement references in the repository

Search source code, comments, and documentation for occurrences of all requirement IDs:

```bash
grep -rn "\[<ID>\]" --include="*.{ts,js,py,go,java,kt,rb,cs,php,md,yaml,yml}"
```

Run for every known requirement ID (or a combined regex). This surfaces code that already references requirements.

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
  - **Fix**: a specific, codebase-aware recommendation as a before/after code snippet using actual lines from the repository. Reference exact file and function names. Do not give generic advice if the specific code is available.
  - **Effort**: `S` (< 1 hour, isolated change), `M` (half day, several files), or `L` (multi-day, architectural change) — used in the Remediation Roadmap only, not shown per violation

---

## Step 3 — Render console output

Print the full results to the conversation. Use the exact format below.

### 3a — Header and scorecard

Print the header with the scorecard immediately visible — the user sees the overall status first:

```
# AppSec Requirements — <Project Name>

  Source    <remote | cached>
  Checked   <timestamp>
  Filter    <filter value, or "none">

  ✅ <n> passed   ⚠️ <n> partial   ❌ <n> failed   ❓ <n> unverifiable   (<n> total)
```

### 3b — Violations

Print only FAIL, PARTIAL, and UNVERIFIABLE items. Do **not** print PASS items here — they appear in a compact list at the end (Step 3d). Sort violations: all ❌ FAIL first (MUST before SHOULD before MAY), then all ⚠️ PARTIAL, then all ❓ UNVERIFIABLE.

```
──────────────────────────────────────────
## Violations
```

**Per-violation block:**

```
### ❌ [SEC-SQL](https://req.example.com/sec-sql) `MUST`
<one-line finding describing the problem>

  [file:line](vscode://...) · [file:line](vscode://...)

  ```<language>
  // Before (file:line):
  <vulnerable code, 1–3 lines>

  // After:
  <corrected code, 1–3 lines>
  ```
```

Rules:
- **Heading**: `### <icon> [<ID>](<url>) \`<PRIORITY>\`` — the requirement ID is always a link (if URL available) so the user can click through to the requirement definition. If no URL: `### <icon> **<ID>** \`<PRIORITY>\``
- **Finding**: one line directly below the heading — concise description of what is wrong
- **Evidence**: indented file links, joined with ` · `. Only list files where the problem was observed.
- **Fix**: standard fenced code block with language tag. Show Before/After as comments within a single code block. Keep to 2–6 lines total. Omit the fix block only for UNVERIFIABLE items where there is genuinely nothing to show.
- Do **not** include an Attack line, Effort line, or category header per violation. Keep each violation compact.

**Full example:**

```
──────────────────────────────────────────
## Violations

### ❌ [SEC-SQL](https://req.example.com/sec-sql) `MUST`
Raw sequelize.query() with string interpolation in login and search

  [routes/login.ts:34](vscode://file/…) · [routes/search.ts:23](vscode://file/…)

  ```ts
  // Before (routes/login.ts:34):
  models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'`)

  // After:
  models.User.findOne({ where: { email: req.body.email } })
  ```
  Apply the same ORM substitution to routes/search.ts:23.

### ❌ [SEC-HSTS](https://req.example.com/sec-hsts) `MUST`
No Strict-Transport-Security header set on responses

  [server.ts:185](vscode://file/…)

  ```ts
  // Add to Express middleware:
  app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }))
  ```

### ⚠️ [SEC-VALIDATE-FILES](https://req.example.com/sec-validate-files) `MUST`
Profile image MIME check present; XML upload vulnerable to XXE

  [routes/fileUpload.ts:83](vscode://file/…)

  ```ts
  // Before:
  libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })

  // After:
  libxml.parseXml(data, { noblanks: true, noent: false, nocdata: false })
  ```

### ❓ [SEC-PENTEST](https://req.example.com/sec-pentest) `SHOULD`
Cannot verify whether annual penetration testing is performed from static analysis
```

If there are zero violations, print:
```
──────────────────────────────────────────
## Violations

None — all requirements passed.
```

### 3c — Remediation Roadmap

Print a single table with all FAIL and PARTIAL items, sorted by Effort (S first), then Priority (MUST first). Omit this section entirely if there are no FAIL/PARTIAL items.

```
──────────────────────────────────────────
## Remediation Roadmap

| # | Effort | ID | Priority | Finding | File |
|---|--------|----|----------|---------|------|
| 1 | S | [SEC-HSTS](url) | `MUST` | no HSTS header | [server.ts:185](vscode://…) |
| 2 | S | [SEC-VALIDATE-FILES](url) | `MUST` | XXE in XML parser | [routes/fileUpload.ts:83](vscode://…) |
| 3 | M | [SEC-SQL](url) | `MUST` | raw SQL interpolation | [routes/login.ts:34](vscode://…) |
| 4 | L | [SEC-USER-AUTH](url) | `MUST` | custom auth with no MFA | [routes/login.ts](vscode://…) |
```

### 3d — Passed requirements

Print a compact one-line list of all PASS item IDs. This confirms coverage without cluttering the output:

```
──────────────────────────────────────────
## Passed (<n>)

AUTH-1 · AUTH-2 · AUTH-3 · SEC-IV · SEC-CORS · SEC-CSP · SEC-CSRF · …
```

If the list exceeds ~120 characters, wrap to multiple lines. Each ID should be a link if a URL is available: `[AUTH-1](url)`.

If no items passed, omit this section entirely.

---

## Step 4 — Save output (conditional)

### 4a — If `save_md` is true

Write the full report to `docs/security/appsec-requirements-report.md` (create `docs/security/` if needed).

Use the **same layout as the console output** (Steps 3a–3d), written as a Markdown file. Prefix with a metadata table:

```markdown
# AppSec Requirements — <Project Name>

| Field | Value |
|-------|-------|
| Generated | <ISO 8601 timestamp> |
| Repository | <git remote URL or directory name> |
| Source | <remote \| cached> |
| Checked | <total count> |

✅ <n> passed · ⚠️ <n> partial · ❌ <n> failed · ❓ <n> unverifiable

## Violations

<same format as Step 3b — one ### heading per violation with fix code block>

## Remediation Roadmap

<same table as Step 3c>

## Passed (<n>)

<same compact ID list as Step 3d>
```

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
        { "file": "routes/search.ts", "line": 23, "vscode_link": "vscode://file/…/routes/search.ts:23" }
      ],
      "finding": "raw sequelize.query() with string interpolation",
      "recommendation": "Replace with parameterized queries or ORM methods"
    }
  ]
}
```

Print: `✓ JSON report written to docs/security/appsec-requirements-report.json`

### 4c — If neither flag is set

Print a single prompt offering to save:

```
─────────────────────────────────────────────────────
💾 To save these results, re-run with a flag:
   /check-appsec-requirements --md      → Markdown report
   /check-appsec-requirements --json    → JSON report
   /check-appsec-requirements --save    → both
```

---

Note: if no `[SEC-*]` tags are found in the analyzed repo itself that is fine — the loaded requirements baseline is always checked regardless of existing code references. The skill requires a requirements YAML to be available (either fetched from the configured URL or from the plugin cache). If neither is available, the skill aborts in Step 1b.
