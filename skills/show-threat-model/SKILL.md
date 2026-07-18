---
name: show-threat-model
description: >-
  Read-only, deterministic overview of the current threat model — the FIXED set
  of facts about it: whether a model exists at all, project and scan identity,
  findings by severity, top-Critical threats, mitigation/control counts, and
  whether the model is still up to date. Use it for presence and status
  questions and for plain display requests ("is there a threat model here?",
  "gibt es hier ein bedrohungsmodell?", "do we have one?", "show me the threat
  model", "zeig mir das bedrohungsmodell", "how does the model stand?", "is it
  still current?"). Reuses the same change detection that decides if an
  incremental scan is needed. Does not analyze code, write files, or compose
  prose — it prints a rendered block verbatim. When the answer instead needs an
  ARBITRARY subset of the model, reached by lookup or filtering — a specific
  finding, "does it cover X?", what to fix first, what a term means — use
  ask-threat-model.
---

You are printing a human-facing overview of the threat model in the target
repository. This skill is **read-only** — it does **not** analyze code, does
**not** spawn agents, and does **not** write files. It reads the committed
`threat-model.yaml` and reports.

The freshness verdict comes from `threat_model_health.py --json`, which wraps
`baseline_state.py check-changes` + `dirty-set` — the **same** change detection
the pipeline uses to decide whether an incremental scan is needed. This skill
does not re-implement that logic; it folds the verdict into the overview.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim
and exit.

```
/appsec-advisor:show-threat-model — Read-only threat model overview.

USAGE
  /appsec-advisor:show-threat-model [--repo <path>] [--output <path>] [--all] [--json]

FLAGS
  --repo <path>     Repository to inspect (default: current working dir)
  --output <path>   Output directory to inspect (default: <repo>/docs/security)
  --all             List every threat grouped by severity (default: top Critical only)
  --json            Emit the overview as machine-readable JSON

WHAT IT SHOWS
  * Project + scan identity (commit, branch, model, depth, scan date)
  * Freshness: is the model still current, or has security-relevant code changed?
    (same change detection that drives the incremental-scan decision)
  * Findings by severity (Critical / High / Medium / Low)
  * Remediation backlog by mitigation priority (P1 / P2 / P3) and how many
    findings have a proposed mitigation vs. are uncovered
  * The top "worst case if nothing changes" scenarios (from the model's
    curated critical findings, with the covering mitigation)
  * Top Critical threats (or all threats with --all)
  * Control posture: effectiveness mix (Missing / Weak / Partial / Adequate)
    and the weakest control domains
  * Mitigation and control counts, plus the rendered report path

RELATED
  /appsec-advisor:threat-model-health   Ops/CI probe: freshness + cleanup + run state
  /appsec-advisor:create-threat-model   Generate or update the threat model
```

After printing the help block, exit. Do not proceed.

## Step 1 — Parse arguments

Recognized flags (and the values consumed by `--repo` / `--output`):

  `--repo <path>`  `--output <path>`  `--all`  `--json`  `--help` | `-h`

Parse these and set `REPO_ROOT`, `OUTPUT_DIR`, `ALL_MODE`, `JSON_MODE`.

- Default `REPO_ROOT` to the current working directory.
- Default `OUTPUT_DIR` to `$REPO_ROOT/docs/security`.
- `--repo <path>` overrides `REPO_ROOT`; `--output <path>` overrides `OUTPUT_DIR`.
- `--all` and `--json` are boolean toggles that consume no value.

### Reject unknown arguments (hard fail)

If the invocation contains **any** token that is not one of the recognized
flags above — or is not the value consumed by `--repo` / `--output` — DO NOT
proceed. Do not resolve `CLAUDE_PLUGIN_ROOT`, do not invoke any helper, do not
touch any file. Print the following block verbatim to stderr, substituting
`<TOKEN>` with the first unknown token, then exit with status `2`:

```
Error: unknown argument '<TOKEN>'

/appsec-advisor:show-threat-model accepts only:
  --repo <path>     Repository to inspect (default: current working dir)
  --output <path>   Output directory to inspect (default: <repo>/docs/security)
  --all             List every threat grouped by severity
  --json            Emit the overview as machine-readable JSON
  --help, -h        Show full help and exit

Run `/appsec-advisor:show-threat-model --help` for details.
```

A flag that takes a value (e.g. `--repo` or `--output`) counts as unknown
when its value is missing — treat the flag itself as the offending token.
Repeated occurrences of the same flag are allowed; the last value wins.

## Step 2 — Resolve `CLAUDE_PLUGIN_ROOT`

```bash
if [ -z "$CLAUDE_PLUGIN_ROOT" ]; then
  CLAUDE_PLUGIN_ROOT=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-advisor/skills/show-threat-model/SKILL.md" \
    2>/dev/null | head -1 | xargs -r dirname | xargs -r dirname | xargs -r dirname)
fi
export CLAUDE_PLUGIN_ROOT
if [ -z "$CLAUDE_PLUGIN_ROOT" ] || [ ! -d "$CLAUDE_PLUGIN_ROOT" ]; then
  echo "Error: CLAUDE_PLUGIN_ROOT could not be resolved." >&2
  exit 2
fi
```

## Step 3 — Dispatch to the helpers

Run the freshness probe in JSON mode and pipe it into the summary renderer so
the freshness verdict is folded into one deterministic block. Do not set
`pipefail`: the meaningful exit code is the renderer's (0 = model present,
1 = no model), not the health probe's CI exit code.

```bash
EXTRA=""
[ "$ALL_MODE" = "true" ]  && EXTRA="$EXTRA --all"
[ "$JSON_MODE" = "true" ] && EXTRA="$EXTRA --json"

python3 "$CLAUDE_PLUGIN_ROOT/scripts/threat_model_health.py" \
    --repo-root "$REPO_ROOT" --output-dir "$OUTPUT_DIR" --json 2>/dev/null \
| python3 "$CLAUDE_PLUGIN_ROOT/scripts/summarize_threat_model.py" \
    --output-dir "$OUTPUT_DIR" --repo-root "$REPO_ROOT" --health-json - $EXTRA
EXIT=$?
```

Print the renderer's output as the complete deliverable — do not add
commentary. If the renderer exits `1` (no model found), it already prints the
hint to run `/appsec-advisor:create-threat-model`; surface that as-is.

Exit-code reference (for shell callers):
- `0` — threat model present, overview rendered
- `1` — no threat model found at `<output>/threat-model.yaml`
- `2` — error (unreadable / unparseable model, or unknown argument)
