---
name: generate-threat-overview
description: Aggregate threat model data from one or more repositories into a cross-repo threat overview. Reads existing threat-model.yaml files — does not perform new analysis or STRIDE scanning. Supports a single repo (default) or multiple repos via --repos. Aggregation, filtering, shared-CWE detection, and chain-candidate heuristics are deterministic — handled end-to-end by scripts/aggregate_threat_summary.py.
---

This skill produces a cross-repo `threat-summary.md` (and optional
`threat-summary.json`) from finished `threat-model.yaml` files. It does **not**
run reconnaissance, STRIDE analysis, or any code scanning — it aggregates and
cross-correlates existing threat model data.

All aggregation, filtering, shared-CWE grouping, attack-chain-candidate
detection, and Markdown/JSON rendering is performed by
`scripts/aggregate_threat_summary.py`. The output JSON conforms to
`schemas/threat-summary.schema.json` — a stable contract drift-guarded by
`tests/test_aggregate_threat_summary.py`.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:generate-threat-overview — Cross-repo overview from one or more threat models.

USAGE
  /appsec-advisor:generate-threat-overview [FLAGS]

FLAGS
  --repos <path>[,<path>...]   Comma-separated list of repo paths to aggregate
                               (default: current working directory only)
  --output <path>              Where to write threat-summary.md
                               (default: first repo's docs/security/ or cwd/docs/security/)
  --format md|json|both        Output format (default: md)
  --min-severity low|medium|high|critical
                               Only include findings at or above this severity
                               (default: medium)
  --open-only                  Exclude mitigated findings (default: include all)
  --dry-run                    Print summary to console only, do not write files

EXAMPLES
  # Summary of current repo only
  /appsec-advisor:generate-threat-overview

  # Aggregate three services
  /appsec-advisor:generate-threat-overview --repos ../auth-service,../api-gateway,../frontend

  # High+ findings, open only, JSON output
  /appsec-advisor:generate-threat-overview --repos ../auth-service,. --min-severity high --open-only --format json
```

After printing, exit.

## Step 1 — Parse arguments and reject unknowns

Recognised flags:

  `--repos <paths>`  `--output <path>`  `--format <md|json|both>`
  `--min-severity <low|medium|high|critical>`  `--open-only`  `--dry-run`
  `--help` | `-h`

If the invocation contains any token that is not one of the recognised
flags above — or is not the value consumed by `--repos` / `--output` /
`--format` / `--min-severity` — do not proceed. Print the following block
verbatim to stderr, substituting `<TOKEN>` with the first unknown token,
then exit with status `2`:

```
Error: unknown argument '<TOKEN>'

/appsec-advisor:generate-threat-overview accepts only:
  --repos <path>[,<path>...]   Comma-separated repo paths to aggregate
  --output <path>              Where to write threat-summary.{md,json}
  --format md|json|both        Output format (default: md)
  --min-severity <level>       low | medium | high | critical (default: medium)
  --open-only                  Exclude mitigated findings
  --dry-run                    Print to console only, do not write files
  --help, -h                   Show full help and exit

Run `/appsec-advisor:generate-threat-overview --help` for details.
```

**Default `REPOS`:** if `--repos` is not provided, use the current working directory as a single-element list.

**Resolve `OUTPUT_DIR`:** if `--output` is provided use that path. Otherwise use `<first_repo>/docs/security/`. Create if not exists (unless `--dry-run`).

Print resolved configuration:

```
[generate-threat-overview] Repos       : <n> (<comma-separated names>)
[generate-threat-overview] Output      : <OUTPUT_DIR or "(dry-run, console only)">
[generate-threat-overview] Severity    : <min-severity>+
[generate-threat-overview] Open only   : <yes|no>
```

## Step 2 — Run the aggregator

Invoke `scripts/aggregate_threat_summary.py` exactly once with the resolved
arguments. The script does all loading, filtering, cross-repo correlation,
schema validation, and rendering:

```bash
REPO_FLAGS=$(echo "$REPOS" | tr ',' '\n' | awk 'NF { printf "--repo %s ", $0 }')

python3 "$CLAUDE_PLUGIN_ROOT/scripts/aggregate_threat_summary.py" \
    $REPO_FLAGS \
    --format        "$FORMAT" \
    --min-severity  "$MIN_SEVERITY" \
    $([ "$OPEN_ONLY" = "true" ] && echo "--open-only") \
    $([ "$DRY_RUN" = "true" ]   && echo "--dry-run") \
    $([ -n "$OUTPUT_DIR" ] && [ "$DRY_RUN" != "true" ] \
        && echo "--output $OUTPUT_DIR/")
```

The script exits non-zero only on schema-validation failure or argument
errors. Print its stdout to the user verbatim.

## Step 3 — Print completion summary

When `--dry-run` was not set, the aggregator writes:

- `<OUTPUT_DIR>/threat-summary.md` (always, unless `--format json`)
- `<OUTPUT_DIR>/threat-summary.json` (when `--format json` or `--format both`)

Print:

```
[generate-threat-overview] ✓ Done
  ↳ Repos processed  : <n> (<n> skipped — no threat-model.yaml)
  ↳ Findings included: <n>
  ↳ Shared CWEs      : <n> appearing in 2+ repos
  ↳ Chain candidates : <n> (heuristic — not confirmed by STRIDE)
  ↳ Output           : <OUTPUT_DIR/threat-summary.md | dry-run>
```

Cross-repo attack chain candidates remain heuristic by definition — the
authoritative chain analysis happens during `create-threat-model`. The
aggregator surfaces them as candidates for human review.
