---
name: check-appsec-requirements
description: Scans the current repository for tagged security requirements (e.g. [SEC-CSP-1]) and verifies whether each one is implemented. Produces a compliance report at docs/security/appsec-requirements-report.md.
---

You are checking whether security requirements tagged with identifiers like `[SEC-CSP-1]` are implemented in the current repository. Follow the steps below exactly.

## Step 1 — Load requirement definitions

### 1a — Read config and resolve the requirements YAML

Find the plugin config:

```bash
find /root /home /opt /usr/local -maxdepth 12 \
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
find /root /home /opt /usr/local -maxdepth 12 \
  -path "*/appsec-plugin/plugin/skills/check-appsec-requirements/appsec-requirements-fallback.yaml" \
  2>/dev/null | head -1
```

If found: use this file. Print: `▶ Requirements: using plugin fallback`

**If none succeeded**, abort with:
> ⚠ Could not load requirements. Set `requirements_yaml_url` in `config.json` or ensure `appsec-requirements-fallback.yaml` is present.

### 1b — Parse the YAML

From the loaded YAML, extract all requirements by iterating `categories[].requirements[]`. For each requirement record:

- **ID** — `requirements[].id` (e.g. `SEC-CSP-1`)
- **Category** — parent `categories[].id` (e.g. `SEC-CSP`)
- **Category title** — parent `categories[].title`
- **Description** — `requirements[].text`
- **Requirement URL** — `requirements[].url` (link back to the source requirement page; may be null in fallback mode)
- **Priority** — `requirements[].priority` (`MUST` / `SHOULD` / `MAY`)

### 1c — Scan for requirement references in the repository

Build a list of all requirement IDs from the loaded YAML: collect every `categories[].requirements[].id` value. Use this list to search the codebase for existing references.

Search source code, comments, and documentation for any occurrence of these IDs:

```bash
# Build pattern from known IDs and search — example for IDs like AUTH-1, INV-3, etc.
grep -rn "\[<ID>\]" --include="*.{ts,js,py,go,java,kt,rb,cs,php,md,yaml,yml}"
```

Run the search for every known requirement ID (or build a combined regex from the full ID list). This surfaces code that already references requirements — evidence that an ID is in use.

If the user passed arguments to this skill, filter to requirements whose ID or category matches the argument (e.g. `/check-appsec-requirements AUTH` checks only requirements whose ID contains `AUTH`). Priority `MUST` requirements are always included regardless of filter.

## Step 2 — Verify implementation for each requirement

For each discovered requirement, search the codebase for evidence that it is implemented. Use `Grep` and `Read` to find relevant code.

Assign one of four statuses:

| Status | Meaning |
|--------|---------|
| ✅ **PASS** | Implementation found; the code demonstrably satisfies the requirement |
| ⚠️ **PARTIAL** | Some implementation exists but it is incomplete, inconsistently applied, or only covers part of the requirement |
| ❌ **FAIL** | No implementation found, or the existing code contradicts the requirement |
| ❓ **UNVERIFIABLE** | Requirement cannot be verified from static analysis alone (e.g. runtime config, infrastructure-only, or external dependency) |

For each requirement record:
- The status
- The evidence: file path(s) and line number(s) that support the status — formatted as VS Code deep links `[path:line](vscode://file/REPO_ROOT/path:line)` using the absolute repo root from `git rev-parse --show-toplevel`
- A one-line finding explaining the verdict
- A recommendation if the status is PARTIAL, FAIL, or UNVERIFIABLE

## Step 3 — Write the report

Write the report to `docs/security/appsec-requirements-report.md` (create `docs/security/` if it does not exist).

Use this structure:

```
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

One paragraph describing the overall compliance posture. Call out any FAIL items by ID. Note if entire categories are missing.

## Results by Category

For each category (e.g. CSP, AUTH, INJ), one subsection:

### <CATEGORY> — <Category Title> — <n> requirements

| ID | Priority | Description | Status | Requirement | Evidence | Finding |
|----|----------|-------------|--------|-------------|----------|---------|
| SEC-X-1 | MUST | <description> | ✅ PASS | [SEC-X-1](req_url) | [file:line](vscode://...) | <one-line verdict> |
| SEC-X-2 | MUST | <description> | ❌ FAIL | [SEC-X-2](req_url) | — | <one-line verdict> |

If `requirements[].url` is null (fallback mode), write `SEC-X-1` as plain text instead of a link.

For PARTIAL / FAIL / UNVERIFIABLE rows, add a recommendation below the table as a blockquote:
> **[SEC-X-2] Recommendation:** <what needs to be done>

## Requirements Not Found in Code

If any requirement tags appear only in documentation and have no reference anywhere in source code (not even in comments), list them here. These are defined but never referenced — they may be missing an implementation or the tag was not applied to the code.

## Appendix — All Requirement Sources

| ID | Source File | Line | Definition |
|----|-------------|------|------------|
```

## Step 4 — Print a summary to the conversation

After writing the file, print:
- Total requirements checked
- Counts per status
- Any FAIL items by ID and one-line finding
- Path to the written report

Note: if no `[SEC-*]` tags are found in the analyzed repo itself that is fine — the plugin baseline from `appsec-requirements-fallback.yaml` is always checked. Only print the warning below if the baseline YAML itself cannot be loaded:
> ⚠ Could not load baseline requirements. Configure `requirements_yaml_url` in `config.json` or ensure `appsec-requirements-fallback.yaml` is present in the plugin directory.
