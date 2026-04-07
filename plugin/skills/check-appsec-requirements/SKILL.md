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

Store the resolved flags: `save_md`, `save_json`, `category_filter`.

### 1b — Read config and resolve the requirements YAML

Find the plugin config:

```bash
find /root /home /opt -maxdepth 6 \
  -path "*/appsec-plugin/plugin/skills/check-appsec-requirements/config.json" \
  2>/dev/null | head -1
```

Read `requirements_source.enabled` and `requirements_source.requirements_yaml_url`. If the file is not found, treat `enabled` as `true` and `requirements_yaml_url` as `null`.

**If `enabled` is `false`:** proceed with an empty baseline and use OWASP references only.
Print: `▶ Requirements: disabled in config — using OWASP references`

**If `enabled` is `true`**, resolve the requirements YAML using the following order. Stop at the first success.

**1. Remote fetch** — only if `requirements_yaml_url` is set:

```bash
curl -sf --max-time 15 "$REQUIREMENTS_YAML_URL" -o /tmp/.skill-requirements.yaml
```

- On success: use `/tmp/.skill-requirements.yaml`. Print: `▶ Requirements: fetched from <url>`
- On failure: print `⚠ Could not fetch from <url> — trying local cache` and continue.

**2. Local cache** — use `docs/security/.requirements.yaml` in the analyzed repo if it exists and `source:` is not `"disabled"` or `"unavailable"`:

```bash
test -f "$REPO_ROOT/docs/security/.requirements.yaml" && echo exists || echo missing
```

If found: use this file. Print: `▶ Requirements: loaded from local cache (docs/security/.requirements.yaml)`

**3. Plugin-bundled fallback**:

```bash
find /root /home /opt -maxdepth 6 \
  -path "*/appsec-plugin/plugin/data/appsec-requirements-fallback.yaml" \
  2>/dev/null | head -1
```

If found: use this file. Print: `▶ Requirements: using plugin fallback`

**If none succeeded**, abort with:
> ⚠ Could not load requirements. Set `requirements_yaml_url` in `config.json` or ensure `appsec-requirements-fallback.yaml` is present in `plugin/data/`.

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
  - **Attack**: one sentence describing the concrete attack this gap enables (e.g. "SQL Injection — attacker can bypass authentication and dump the full database")
  - **Fix**: a specific, codebase-aware recommendation. Where possible include a short before/after code snippet using the actual patterns found in the repository (e.g. quote the vulnerable line and show the corrected version). Reference exact file and function names. Do not give generic advice if the specific code is available.
  - **Effort**: `S` (< 1 hour, isolated change), `M` (half day, several files), or `L` (multi-day, architectural change)

---

## Step 3 — Render console output

Print the full results to the conversation. Use the exact format below — it renders richly in Claude Code.

### 3a — Header

```
# AppSec Requirements — <Project Name>

  Repository   <git remote URL or directory>
  Source       <remote | cached | fallback | disabled>
  Checked      <timestamp>
  Filter       <filter value, or "none">
```

### 3b — Results by category

For each category, print a section header followed by one block per requirement.

**Category header:**
```
──────────────────────────────────────────
### <CATEGORY ID> — <Category Title>
```

**Per-requirement block** — the format differs by status:

**PASS items** — single line only:
```
✅ `MUST`  **SEC-IV** — <one-line finding>  [file:line](vscode://...)
```

**FAIL / PARTIAL / UNVERIFIABLE items** — expanded multi-line block:
```
❌ `MUST`  **SEC-SQL** — <one-line finding>

   Attack   <one sentence: what attack this enables and its impact>
   Files    [file:line](vscode://...) · [file:line](vscode://...)
   Effort   S | M | L

   Fix
   ┌─ Before (<file>:<line>) ──────────────────────────────────────────
   │  <verbatim vulnerable code snippet, 1–5 lines>
   └────────────────────────────────────────────────────────────────────
   ┌─ After ────────────────────────────────────────────────────────────
   │  <corrected code snippet using actual repo patterns>
   └────────────────────────────────────────────────────────────────────
   <one sentence of additional context if needed, otherwise omit>
```

Rules:
- `<icon>`: always `✅` / `⚠️` / `❌` / `❓` — never omit even for `SHOULD` or `MAY` requirements
- `**<ID>**`: always bold; additionally render as `[**<ID>**](<req_url>)` hyperlink if a URL is available
- `<PRIORITY>` rendered as inline code (backticks) for visual weight: `` `MUST` ``, `` `SHOULD` ``, `` `MAY` ``
- Code snippets in Fix blocks MUST use actual lines from the repository when available (quote the real code, not a generic placeholder). If the real code is unavailable, write a representative pattern using the project's existing style.
- Omit the Fix block only for UNVERIFIABLE items where there is genuinely nothing to show.
- Keep each Before/After block to 1–5 lines — enough to be actionable, not a full file dump.

Example output for a category section:

```
──────────────────────────────────────────
### SEC-SECURE_DATA_HANDLING — Secure Data Handling

✅ `MUST`  **SEC-IV** — Zod strict schema applied to all inbound API payloads  [middleware/validate.ts:12](vscode://file/…)

❌ `MUST`  [**SEC-SQL**](https://req.example.com/sec-sql) — raw sequelize.query() with string interpolation in login and search

   Attack   SQL Injection — attacker can bypass authentication (e.g. `' OR 1=1--`) and dump the entire Users table
   Files    [routes/login.ts:34](vscode://file/…/routes/login.ts:34) · [routes/search.ts:23](vscode://file/…/routes/search.ts:23)
   Effort   M (2 files, straightforward substitution)

   Fix
   ┌─ Before (routes/login.ts:34) ──────────────────────────────────────
   │  models.sequelize.query(
   │    `SELECT * FROM Users WHERE email = '${req.body.email}'...`)
   └────────────────────────────────────────────────────────────────────
   ┌─ After ────────────────────────────────────────────────────────────
   │  models.User.findOne({
   │    where: { email: req.body.email, password: hash(req.body.password) }
   │  })
   └────────────────────────────────────────────────────────────────────
   Apply the same ORM substitution to the LIKE query in routes/search.ts:23.

⚠️ `MUST`  [**SEC-VALIDATE-FILES**](https://req.example.com/sec-validate-files) — profile image MIME check present; complaint XML upload vulnerable to XXE

   Attack   XXE — server-side file read (e.g. /etc/passwd) or SSRF via crafted XML entity
   Files    [routes/fileUpload.ts:83](vscode://file/…/routes/fileUpload.ts:83)
   Effort   S (single option flag change)

   Fix
   ┌─ Before (routes/fileUpload.ts:83) ─────────────────────────────────
   │  libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })
   └────────────────────────────────────────────────────────────────────
   ┌─ After ────────────────────────────────────────────────────────────
   │  libxml.parseXml(data, { noblanks: true, noent: false, nocdata: false })
   └────────────────────────────────────────────────────────────────────
```

### 3c — Summary and Remediation Roadmap

After all categories, print the score block followed by a prioritised remediation roadmap.

**Score block:**
```
──────────────────────────────────────────
## Summary

  ✅ PASS           <n>
  ⚠️  PARTIAL        <n>
  ❌ FAIL           <n>
  ❓ UNVERIFIABLE   <n>
  ─────────────────────
  Total             <n>
```

**Remediation Roadmap** — group all FAIL and PARTIAL items into three tiers based on the Effort rating you assigned in Step 2. Within each tier, sort MUST before SHOULD before MAY, then by category order.

```
──────────────────────────────────────────
## Remediation Roadmap

### Quick Wins — fix in < 1 hour each  (Effort S)
| # | ID | Priority | Finding | File |
|---|-----|----------|---------|------|
| 1 | [**SEC-HSTS**](url) | `MUST` | no Strict-Transport-Security header | [server.ts:185](vscode://...) |

### Standard Tasks — up to half a day each  (Effort M)
| # | ID | Priority | Finding | File |
|---|-----|----------|---------|------|
| 2 | [**SEC-SQL**](url) | `MUST` | string interpolation in sequelize.query() | [routes/login.ts:34](vscode://...) |

### Major Work — multi-day effort  (Effort L)
| # | ID | Priority | Finding | File |
|---|-----|----------|---------|------|
| 3 | [**SEC-USER-AUTH**](url) | `MUST` | custom auth with no MFA | [routes/login.ts](vscode://...) |
```

Omit a tier entirely if it has no items. If all FAIL/PARTIAL items have the same effort level, use a single flat table instead of three headers.

---

## Step 4 — Save output (conditional)

### 4a — If `save_md` is true

Write the full report to `docs/security/appsec-requirements-report.md` (create `docs/security/` if needed).

Use this Markdown structure:

```markdown
# AppSec Requirements Compliance Report — <Project Name>

| Field | Value |
|-------|-------|
| Generated | <ISO 8601 timestamp> |
| Analyst | Claude (check-appsec-requirements skill) |
| Repository | <git remote URL or directory name> |
| Requirements source | <remote \| cached \| fallback \| disabled> |
| Requirements checked | <total count> |
| PASS | <count> |
| PARTIAL | <count> |
| FAIL | <count> |
| UNVERIFIABLE | <count> |

## Summary

<paragraph describing overall posture; call out FAIL items by ID>

## Results by Category

### <CATEGORY> — <Category Title> — <n> requirements

| ID | Priority | Description | Status | Requirement | Evidence | Finding |
|----|----------|-------------|--------|-------------|----------|---------|
| SEC-X-1 | MUST | <description> | ✅ PASS | [SEC-X-1](req_url) | [file:line](vscode://...) | <verdict> |
| SEC-X-2 | MUST | <description> | ❌ FAIL | [SEC-X-2](req_url) | — | <verdict> |

> **[SEC-X-2] Recommendation:** <what needs to be done>

## Requirements Not Found in Code

<list any requirement IDs that appear only in documentation, never in source>

## Appendix — All Requirement Sources

| ID | Category | Priority | URL |
|----|----------|----------|-----|
```

Print: `✓ Markdown report written to docs/security/appsec-requirements-report.md`

### 4b — If `save_json` is true

Write structured JSON to `docs/security/appsec-requirements-report.json` using this schema:

```json
{
  "generated": "<ISO 8601>",
  "repository": "<remote URL or directory>",
  "requirements_source": "remote|cached|fallback|disabled",
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

Note: if no `[SEC-*]` tags are found in the analyzed repo itself that is fine — the plugin baseline from `appsec-requirements-fallback.yaml` is always checked. Only print the warning below if the baseline YAML itself cannot be loaded:
> ⚠ Could not load baseline requirements. Configure `requirements_yaml_url` in `config.json` or ensure `appsec-requirements-fallback.yaml` is present in `plugin/data/`.
