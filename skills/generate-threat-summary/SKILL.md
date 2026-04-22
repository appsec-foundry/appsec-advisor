---
name: generate-threat-summary
description: Aggregate threat model data from one or more repositories into a consolidated threat summary. Reads existing threat-model.yaml files — does not perform new analysis or STRIDE scanning. Supports a single repo (default) or multiple repos via --repos.
---

This skill reads finished `threat-model.yaml` files and produces a consolidated `threat-summary.md`. It does **not** run reconnaissance, STRIDE analysis, or any code scanning — it aggregates and cross-correlates existing threat model data.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:generate-threat-summary — Consolidated threat summary from one or more repos.

USAGE
  /appsec-advisor:generate-threat-summary [FLAGS]

FLAGS
  --repos <path>[,<path>...]   Comma-separated list of repo paths to aggregate
                               (default: current working directory only)
  --output <path>              Where to write threat-summary.md
                               (default: first repo's docs/security/ or cwd/docs/security/)
  --format md|json             Output format (default: md; json emits threat-summary.json)
  --min-severity low|medium|high|critical
                               Only include findings at or above this severity
                               (default: medium)
  --open-only                  Exclude mitigated findings (default: include all)
  --dry-run                    Print summary to console only, do not write files

EXAMPLES
  # Summary of current repo only
  /appsec-advisor:generate-threat-summary

  # Aggregate three services
  /appsec-advisor:generate-threat-summary --repos ../auth-service,../api-gateway,../frontend

  # High+ findings, open only, JSON output
  /appsec-advisor:generate-threat-summary --repos ../auth-service,. --min-severity high --open-only --format json
```

After printing, exit.

## Step 1 — Parse arguments and resolve repo paths

Parse `--repos`, `--output`, `--format`, `--min-severity`, `--open-only`, `--dry-run` from the invocation.

**Default `REPOS`:** if `--repos` is not provided, use the current working directory as a single-element list.

**Resolve each repo path:**
```bash
for repo_arg in $(echo "$REPOS_ARG" | tr ',' '\n'); do
  abs_path=$(cd "$repo_arg" 2>/dev/null && pwd)
  if [ -z "$abs_path" ]; then
    echo "Error: repo path not found: $repo_arg" >&2
    exit 1
  fi
  echo "$abs_path"
done
```

**Locate `threat-model.yaml` for each repo:** check `<repo>/docs/security/threat-model.yaml` first, then `<repo>/threat-model.yaml` as fallback.

**Resolve `OUTPUT_DIR`:** if `--output` is provided use that path. Otherwise use `<first_repo>/docs/security/`. Create if not exists (unless `--dry-run`).

Print resolved configuration:
```
[generate-threat-summary] Repos       : <n> (<comma-separated names>)
[generate-threat-summary] Output      : <OUTPUT_DIR or "(dry-run, console only)">
[generate-threat-summary] Severity    : <min-severity>+
[generate-threat-summary] Open only   : <yes|no>
```

## Step 2 — Load and validate threat models

For each resolved repo:

1. Check that `threat-model.yaml` exists. If not: print `[generate-threat-summary]   ✗ <repo-name>: no threat-model.yaml found — skipping` and exclude from aggregation.
2. Read the full file. Extract:
   - `meta.project`, `meta.generated`, `meta.mode`, `meta.git.commit_sha`, `meta.git.branch`
   - `components[]` — full list with `id`, `name`
   - `threats[]` or `threat_categories[].findings[]` (handle both schema v1 flat list and v2 categorised structure)
   - `mitigations[]` — `id`, `title`, `priority`, `threats_addressed[]`
   - `security_controls[]` — count by effectiveness (`adequate`, `partial`, `weak`, `missing`)
3. Filter findings by `--min-severity` and `--open-only` flags.
4. Record a per-repo summary:
```yaml
- repo: <name>
  path: <abs path>
  generated: <ISO timestamp>
  commit_sha: <sha>
  findings_total: <int>
  findings_after_filter: <int>
  by_severity:
    critical: <int>
    high: <int>
    medium: <int>
    low: <int>
  by_status:
    open: <int>
    mitigated: <int>
  controls_missing: <int>
  findings: [<filtered finding objects>]
  mitigations: [<mitigation objects>]
```

Print per repo:
- `[generate-threat-summary]   ✓ <repo-name>: <n> findings loaded (<n> after filter), generated <date>`
- `[generate-threat-summary]   ⚠ <repo-name>: outdated (>90 days) — loaded anyway`

## Step 3 — Cross-repo analysis

Only runs when 2+ repos are loaded.

**3a — Risk distribution table.** Build a combined table: one row per repo, columns: repo name, Critical, High, Medium, Low, Open, Mitigated, Controls Missing, Last Analysed.

**3b — Shared CWE patterns.** Group all findings across repos by CWE. CWEs that appear in 2+ repos are "shared weaknesses" — flag these as systemic. List the top 5 shared CWEs with count of affected repos and total finding count.

**3c — Cross-repo attack chain detection.** For each repo pair (A → B) where B appears in A's `docs/related-repos.yaml` or B's components are referenced in A's `trust_boundaries[]`:
- Find open Critical/High findings in B whose `component` matches an interface component.
- Find open findings in A at the corresponding trust boundary.
- If both exist: flag as a potential cross-repo attack chain: "Finding `<B-TID>` in `<B>` at `<interface>` may propagate to `<A-TID>` in `<A>`."
- Cap at 5 chains. If more exist, note the count.

This is heuristic — the STRIDE analyzer does the authoritative chain analysis during `create-threat-model`. Flag these as "candidates for review", not confirmed chains.

**3d — Shared mitigations.** Find mitigations across repos that address the same CWE. Group and surface as "candidate shared mitigations" — teams may be able to implement these once at a platform level rather than per-service.

## Step 4 — Render `threat-summary.md`

Write `$OUTPUT_DIR/threat-summary.md` (or print to console if `--dry-run`).

Structure:

```markdown
# Threat Summary
<!-- generated by /appsec-advisor:generate-threat-summary -->

| Field | Value |
|-------|-------|
| Generated | <ISO timestamp> |
| Repos | <n> |
| Findings included | <n> (severity: <min>+, open-only: <yes/no>) |

## Risk Overview

<Risk distribution table — one row per repo>

| Repo | Critical | High | Medium | Low | Open | Mitigated | Controls Missing | Last Analysed |
|------|----------|------|--------|-----|------|-----------|-----------------|---------------|
| ... |

**Total across all repos:** <n> Critical, <n> High, <n> Medium, <n> Low

## Consolidated Finding Register

<All findings after filter, sorted by: severity DESC, repo name ASC>
<For each finding: repo prefix in ID column, e.g. "[auth-service] T-042">

| Repo | ID | Title | Severity | STRIDE | CWE | Status | Component |
|------|----|-------|----------|--------|-----|--------|-----------|
| ... |

## Cross-Repo Attack Chain Candidates

<Only rendered when 3b produced results — omit section entirely if none>

<Heuristic candidates — not confirmed by STRIDE analysis>

## Systemic Weaknesses

<Only rendered when 3b produced shared CWEs — omit section if none>

| CWE | Affected Repos | Total Findings | Recommendation |
|-----|----------------|----------------|----------------|
| ... |

## Shared Mitigation Candidates

<Only rendered when 3d produced results — omit section if none>

## Per-Repo Summaries

<One subsection per repo: ### <repo-name>>
<Meta: generated date, commit, mode>
<Controls summary: n adequate, n partial, n weak, n missing>
<Top 3 open findings by severity>
<Link to full threat-model.md if it exists at the standard path>
```

## Step 5 — Emit `threat-summary.json` (when `--format json`)

When `--format json` is set, write `$OUTPUT_DIR/threat-summary.json` instead of (or in addition to) the Markdown file. Structure:

```json
{
  "meta": {
    "generated": "<ISO>",
    "repos": ["<name>", ...],
    "filter": {"min_severity": "<value>", "open_only": true}
  },
  "repos": [<per-repo summary objects from Step 2>],
  "shared_cwes": [...],
  "cross_repo_chain_candidates": [...],
  "shared_mitigation_candidates": [...]
}
```

## Step 6 — Print completion summary

```
[generate-threat-summary] ✓ Done
  ↳ Repos processed  : <n> (<n> skipped — no threat-model.yaml)
  ↳ Findings included: <n> (<n> critical, <n> high, <n> medium, <n> low)
  ↳ Shared CWEs      : <n> appearing in 2+ repos
  ↳ Chain candidates : <n>
  ↳ Output           : <OUTPUT_DIR/threat-summary.md | dry-run>
```
