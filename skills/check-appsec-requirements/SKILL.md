---
name: check-appsec-requirements
description: Scans the current repository for tagged security requirements (e.g. [SEC-CSP-1]) and verifies whether each one is implemented. Produces a compliance report at docs/security/appsec-requirements-report.md.
---

You are checking whether security requirements tagged with identifiers like `[SEC-CSP-1]` are implemented in the current repository. Follow the steps below exactly.

## Step 1 — Discover requirement definitions

Search for all requirement definitions. A definition is any line that:
- Contains a tag matching the pattern `[SEC-<CATEGORY>-<NUMBER>]` (e.g. `[SEC-CSP-1]`, `[SEC-AUTH-3]`, `[SEC-INJ-12]`)
- Is followed by or accompanied by a description of what is required

Search these locations in order:
1. **Skill baseline** — load the requirements using the following resolution order:
   1. Read `config.json` from the same directory as this skill file (`skills/check-appsec-requirements/config.json`). Parse the `requirements_source` object.
   2. If `requirements_source.url` is a non-null string, fetch it with `WebFetch`. Treat the response body as the requirements document (Markdown with `[SEC-*]` tags).
      - If the fetch fails or returns a non-200 response, print a warning: `⚠ Could not fetch requirements from <url> — falling back to local file.` and continue to step 3.
   3. If `url` is null **or** the fetch failed and `fallback_to_local` is `true`, read `web-security-requirements.md` from the same skill directory.
   4. If neither source is available, abort with an error message.
2. Any file named `security-requirements.*`, `appsec-requirements.*`, `sec-requirements.*`, or `web-security-requirements.*` in the **analyzed repository** — these are project-specific overrides or additions
3. `docs/` directory of the analyzed repository recursively — look for `.md`, `.txt`, `.yaml`, `.yml` files
4. `README.md`, `CLAUDE.md` at the repo root
5. Source code comments anywhere in the repo (use `grep -r '\[SEC-[A-Z]\+-[0-9]\+\]'`)

When the same requirement ID appears in both the plugin baseline and the analyzed repo, the repo version takes precedence (it may have customized the description or acceptance criteria).

For each tag found, extract:
- **ID** — the full tag, e.g. `[SEC-CSP-1]`
- **Category** — the middle segment (e.g. `CSP`, `AUTH`, `INJ`, `SESS`, `CRYPT`, `LOG`, `DEP`)
- **Description** — the requirement text associated with that tag (the sentence or bullet it annotates)
- **Source file and line** — where the definition was found

If the user passed arguments to this skill, treat them as an additional filter: only check requirements whose ID or category matches the argument (e.g. `/check-appsec-requirements SEC-AUTH` checks only `[SEC-AUTH-*]` requirements).

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
| Requirements checked | <total count> |
| PASS | <count> |
| PARTIAL | <count> |
| FAIL | <count> |
| UNVERIFIABLE | <count> |

## Summary

One paragraph describing the overall compliance posture. Call out any FAIL items by ID. Note if entire categories are missing.

## Results by Category

For each category (e.g. CSP, AUTH, INJ), one subsection:

### <CATEGORY> — <n> requirements

| ID | Description | Status | Evidence | Finding |
|----|-------------|--------|----------|---------|
| [SEC-X-1] | <description> | ✅ PASS | [file:line](vscode://...) | <one-line verdict> |
| [SEC-X-2] | <description> | ❌ FAIL | — | <one-line verdict> |

For PARTIAL / FAIL / UNVERIFIABLE rows, add a indented recommendation below the table row as a blockquote:
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

Note: if no `[SEC-*]` tags are found in the analyzed repo itself that is fine — the plugin baseline from `requirements/web-security-requirements.md` is always checked. Only print the warning below if the baseline file itself cannot be read:
> ⚠ Could not load baseline requirements. Check `skills/check-appsec-requirements/config.json` — set `url` to a reachable endpoint or ensure `web-security-requirements.md` is present in the same directory.
