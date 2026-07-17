---
name: review-threat-model
description: User-facing triage of an existing threat model — walk the findings in an already-generated threat-model.yaml, decide fix / accept-risk / defer per finding (with owner and target), and emit a remediation-plan.md. Runs later and completely independently of create-threat-model; reads the model, never regenerates or re-scores it. Not an artifact-quality check (that is eval-threat-model).
---

You help a user **triage** the findings of a threat model that already exists.
This skill is a **Consumer**, never a Producer:

- It **reads** `threat-model.yaml` — it does **not** analyze code, spawn agents,
  recompute severity, or re-author mitigations.
- Triage decisions live **only** in a sidecar (`<repo>/.appsec-triage/triage.yaml`),
  **never** written back into `threat-model.yaml` (the pipeline overwrites that
  on re-scan).
- The sidecar and the plan live under `<repo>/.appsec-triage/`, a namespace the
  generation pipeline never touches — so this skill changes nothing about the
  create-threat-model workflow.

The deterministic work (rank, merge, render) lives in
`scripts/review_threat_model.py`. Your job is the interactive layer: capture the
user's decisions and hand them to that script. Do **not** hand-write the plan.

## `--help` — inline help (early exit)

If the arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:review-threat-model — Triage an existing threat model.

USAGE
  /appsec-advisor:review-threat-model [--repo <path>] [--output <path>] [--plan <path>]

FLAGS
  --repo <path>     Repository the model belongs to (default: current working dir)
  --output <path>   Directory holding threat-model.yaml (default: <repo>/docs/security)
  --plan <path>     Where to write remediation-plan.md
                    (default: <repo>/.appsec-triage/remediation-plan.md)

WHAT IT DOES
  * Ranks findings by effective severity, merged with any prior triage.
  * Walks untriaged findings and asks you: fix / accept-risk / defer
    (accept-risk requires a rationale; fix/defer take an optional owner + target).
  * Persists your decisions to <repo>/.appsec-triage/triage.yaml (survives re-scan).
  * Renders a grouped remediation-plan.md with the model's remediation steps.

DOES NOT
  * Analyze code, regenerate, or re-score the model (use create-threat-model).
  * Judge the model's quality (use eval-threat-model).

RELATED
  /appsec-advisor:show-threat-model     Read-only overview by severity
  /appsec-advisor:create-threat-model   Generate or update the threat model
```

After printing the help block, exit. Do not proceed.

## Step 1 — Parse arguments

Recognized flags: `--repo <path>`  `--output <path>`  `--plan <path>`  `--help` | `-h`.

- Default `REPO_ROOT` to the current working directory.
- Default `OUTPUT_DIR` to `$REPO_ROOT/docs/security`; `--output` overrides.
- Default `TRIAGE` to `$REPO_ROOT/.appsec-triage/triage.yaml`.
- Default `PLAN` to `$REPO_ROOT/.appsec-triage/remediation-plan.md`; `--plan` overrides.

**Reject unknown arguments (hard fail).** If the invocation contains any token
that is not one of the recognized flags — or is not the value consumed by
`--repo` / `--output` / `--plan` — do not proceed, do not touch any file. Print
to stderr, substituting the first unknown token, then exit `2`:

```
Error: unknown argument '<TOKEN>'
Run /appsec-advisor:review-threat-model --help for usage.
```

## Step 2 — Resolve `CLAUDE_PLUGIN_ROOT`

```bash
if [ -z "$CLAUDE_PLUGIN_ROOT" ]; then
  CLAUDE_PLUGIN_ROOT=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-advisor/skills/review-threat-model/SKILL.md" \
    2>/dev/null | head -1 | xargs -r dirname | xargs -r dirname | xargs -r dirname)
fi
export CLAUDE_PLUGIN_ROOT
if [ -z "$CLAUDE_PLUGIN_ROOT" ] || [ ! -d "$CLAUDE_PLUGIN_ROOT" ]; then
  echo "Error: CLAUDE_PLUGIN_ROOT could not be resolved." >&2
  exit 2
fi
```

## Step 3 — Reconcile the model against prior triage

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/review_threat_model.py" reconcile \
    --output-dir "$OUTPUT_DIR" --triage "$TRIAGE"
```

Exit `1` means no model was found — tell the user to run
`/appsec-advisor:create-threat-model` first, then stop. Otherwise parse the JSON:
`findings[]` are severity-ranked and carry a `decision` (`untriaged` when never
triaged), and `stale[]` lists prior decisions whose finding is gone.

If there are **no** `untriaged` findings, skip Step 4 — the user is just
re-rendering. Go to Step 5.

## Step 4 — Walk the untriaged findings (interactive)

Triage **severity bucket by severity bucket**, Critical first, then High,
Medium, Low. Within a bucket, ask per finding using `AskUserQuestion` — batch up
to 4 findings per call, one question each:

- Question: `[<id>] <title>  (<severity> · <component>)` — decision?
- Options: **Fix**, **Accept risk**, **Defer**. (The user can pick "Other" to
  add a free-text note, e.g. an owner or sprint.)

Rules:
- **Accept risk requires a rationale** — if chosen without a note, ask a short
  follow-up for the reason. Do not persist an accept-risk with an empty rationale.
- For **Fix** / **Defer**, an owner and target sprint are optional; capture them
  only if the user volunteers them (via "Other" or a follow-up you offer once).
- Stop early whenever the user says they are done; findings left untriaged
  simply stay `untriaged` in the plan.

Keep it calm and fast — this is a review, not an interrogation. Do not editorialize
the severity; it is the model's, read verbatim.

## Step 5 — Persist decisions to the sidecar

Merge the newly captured decisions **into** the existing sidecar (do not drop
prior entries). Write `$TRIAGE` with the Write tool in this exact shape, keyed by
each finding's `key` (from the reconcile JSON — this is `local_id`, stable across
re-scans):

```yaml
version: 1
findings:
  <key>:
    decision: fix | accept-risk | defer
    rationale: "<required for accept-risk, else omit>"
    owner: "<optional>"
    target_sprint: "<optional>"
```

Only include fields you actually captured. Never write a `decision` value other
than `fix`, `accept-risk`, or `defer` (the renderer coerces anything else to
untriaged). Preserve any keys already present that you did not re-triage.

## Step 6 — Render the plan

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/review_threat_model.py" render \
    --output-dir "$OUTPUT_DIR" --triage "$TRIAGE" --plan "$PLAN"
```

The script writes `remediation-plan.md` deterministically (findings grouped by
decision, severity-ranked, with the model's remediation steps). Print the plan
path and a one-line triage summary (counts per decision from the reconcile JSON).
Do not paste the whole plan; point the user to the file.

If `stale[]` was non-empty, mention it once: some prior decisions reference
findings no longer in the model (fixed, merged, or renumbered) and are listed at
the bottom of the plan for review.
