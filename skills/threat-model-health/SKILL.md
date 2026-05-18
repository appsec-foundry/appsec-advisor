---
name: threat-model-health
description: Read-only three-check health probe for the threat model. Checks (1) whether a threat model exists and is still current, (2) whether intermediate artifacts are present and should be cleaned up, and (3) whether a threat model assessment is currently running. Check 3 runs first; if a run is active checks 1 and 2 are skipped so the command returns in under 1 second.
---

You are running a read-only health probe for the threat model in the target
repository. This skill does **not** analyze code, does **not** spawn agents,
and does **not** write files. It only reads existing state and reports.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim
and exit.

```
/appsec-advisor:threat-model-health — Read-only threat model health probe.

USAGE
  /appsec-advisor:threat-model-health [--repo <path>] [--output <path>] [--json]

FLAGS
  --repo <path>     Repository to inspect (default: current working dir)
  --output <path>   Output directory to inspect (default: <repo>/docs/security)
  --json            Emit results as machine-readable JSON

CHECKS
  3. Active run     Is a threat model assessment currently running?
                    (always first; exits immediately if active — checks 1+2 skipped)
  1. Freshness      Does a threat model exist? Is it still current?
                    Verdict: FRESH | STALE | NO_MODEL | UNKNOWN
  2. Artifacts      Are intermediate artifacts present that should be cleaned?
                    Tier 1: run-state orphans → /appsec-advisor:clean-run-state
                    Tier 2: post-run intermediates → runtime_cleanup.py --stage all
                    Special: needs_stage2 (Stage 1 done, Stage 2 never dispatched)

EXIT CODES
  0  Fresh and clean, no active run   (CI gate: pass)
  1  Threat model stale or absent     (CI gate: fail — re-analysis needed)
  2  Debris present                   (CI gate: warn or fail per policy)
  3  Active run in progress           (CI gate: skip / retry later)
  4  Unknown / error                  (CI gate: fail)

WHEN TO USE
  * Quick check before opening a PR: is the threat model up to date?
  * CI/CD gate: enforce that security-relevant changes trigger a new assessment.
  * After a session crash: verify what state the output directory is in.
  * Before running /appsec-advisor:create-threat-model: understand what
    intermediate artifacts are already on disk.
```

After printing the help block, exit. Do not proceed.

## Step 1 — Parse arguments

Recognized flags (and the values consumed by `--repo` / `--output`):

  `--repo <path>`  `--output <path>`  `--json`  `--help` | `-h`

Parse these and set `REPO_ROOT`, `OUTPUT_DIR`, `JSON_MODE`.

- Default `REPO_ROOT` to the current working directory.
- Default `OUTPUT_DIR` to `$REPO_ROOT/docs/security`.
- `--repo <path>` overrides `REPO_ROOT`.
- `--output <path>` overrides `OUTPUT_DIR`.

### Reject unknown arguments (hard fail)

If the invocation contains **any** token that is not one of the recognized
flags above — or is not the value consumed by `--repo` / `--output` — DO NOT
proceed. Do not resolve `CLAUDE_PLUGIN_ROOT`, do not invoke the helper, do
not touch any file. Print the following block verbatim to stderr, substituting
`<TOKEN>` with the first unknown token, then exit with status `2`:

```
Error: unknown argument '<TOKEN>'

/appsec-advisor:threat-model-health accepts only:
  --repo <path>     Repository to inspect (default: current working dir)
  --output <path>   Output directory to inspect (default: <repo>/docs/security)
  --json            Emit results as machine-readable JSON
  --help, -h        Show full help and exit

Run `/appsec-advisor:threat-model-health --help` for details.
```

A flag that takes a value (e.g. `--repo` or `--output`) counts as unknown
when its value is missing — treat the flag itself as the offending token.
Repeated occurrences of the same flag are allowed; the last value wins.

## Step 2 — Resolve `CLAUDE_PLUGIN_ROOT`

```bash
if [ -z "$CLAUDE_PLUGIN_ROOT" ]; then
  CLAUDE_PLUGIN_ROOT=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-advisor/skills/threat-model-health/SKILL.md" \
    2>/dev/null | head -1 | xargs -r dirname | xargs -r dirname | xargs -r dirname)
fi
export CLAUDE_PLUGIN_ROOT
if [ -z "$CLAUDE_PLUGIN_ROOT" ] || [ ! -d "$CLAUDE_PLUGIN_ROOT" ]; then
  echo "Error: CLAUDE_PLUGIN_ROOT could not be resolved." >&2
  exit 2
fi
```

## Step 3 — Dispatch to the helper

```bash
ARGS="--repo-root $REPO_ROOT --output-dir $OUTPUT_DIR"
[ "$JSON_MODE" = "true" ] && ARGS="$ARGS --json"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/threat_model_health.py" $ARGS
EXIT=$?
```

Propagate the helper's exit code exactly. Do not add any commentary — the
helper's output is the complete deliverable.

Exit-code reference (for shell callers):
- `0` — fresh and clean
- `1` — stale or absent
- `2` — debris present
- `3` — active run in progress
- `4` — unknown / error
