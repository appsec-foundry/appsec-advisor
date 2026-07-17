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

The deterministic work (verdict roll-up, rank, group, merge, render) lives in
`scripts/review_threat_model.py`. Your job is the interactive layer: run an
**overview-first triage console** — show the user where they stand, let them
drill into top findings / top mitigations / a security domain, act on a
free-text selection (bulk), and hand the decisions to that script. Do **not**
hand-write the plan and do **not** re-score or invent severities/areas — every
number you show comes from the `console` payload.

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
  * Opens a triage console: a one-screen verdict (severity mix, hottest areas
    and components, mitigation coverage), then a menu.
  * Menu: Quick-triage (Critical+High -> fix) · Top findings · Top mitigations ·
    By area (authentication, injection, access control, …) · Write plan & exit.
  * You select findings/mitigations by id or range (e.g. `T-001..T-005, T-012`)
    and pick one action for the whole selection: mitigate / accept-risk / defer.
    Acting on a mitigation triages every finding it covers at once.
  * accept-risk requires a rationale (one shared reason for a bulk selection);
    fix/defer take an optional owner + target.
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

## Step 3 — Load the console payload

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/review_threat_model.py" console \
    --output-dir "$OUTPUT_DIR" --triage "$TRIAGE"
```

Exit `1` means no model was found — tell the user to run
`/appsec-advisor:create-threat-model` first, then stop. Otherwise parse the JSON
**once** and keep it in context for the whole session — it is the single source
for every screen below. Do not re-run `console` on each loop; the static data
(findings, mitigations, areas) does not change, only your decisions do.

Payload shape (all read from the model — never recompute):
- `verdict` — `by_severity`, `unrated`, `components`, `top_components`,
  `top_areas`, `weaknesses`, `with_mitigation`, `p1_mitigations`, `triaged`.
- `findings[]` — severity-ranked; each has `key` (stable `local_id`), `id`
  (`T-NNN`), `title`, `component`, `severity`, `category_name`, `has_mitigation`,
  `decision` (`untriaged` until triaged).
- `mitigations[]` — ranked by priority then leverage; each has `id` (`M-NNN`),
  `title`, `priority`, `severity`, `coverage`, and `covered_keys` (the finding
  `key`s it resolves).
- `areas[]` — findings grouped by security domain; each has `category_name`,
  `total`, `critical`, `high`, and `keys`.
- `stale[]` — prior decisions whose finding is gone from the model.

## Step 4 — Show the verdict (one screen)

Print a compact briefing from `verdict` — do not editorialize, these are the
model's numbers:

```
<project> · generated <generated> · <total> findings
Posture: <C> Critical · <H> High · <M> Medium (<unrated> unrated) · <components> components · <weaknesses> design weaknesses
Hottest areas: <a1> (<n>) · <a2> (<n>) · <a3> (<n>)
Hottest components: <c1> (<n>) · <c2> (<n>) · <c3> (<n>)
Coverage: <with_mitigation>/<total> findings have a proposed mitigation · <p1_mitigations>× P1
Triage: <triaged>/<total> decided
```

If `triaged == 0`, offer the express lane before the menu with one
`AskUserQuestion`: "Mark all Critical + High findings as **fix** now and only
walk the rest?" — options **Yes, fix them** / **No, let me navigate**. On yes,
apply `fix` to every Critical/High finding (Step 6 write), then go to the menu.

## Step 5 — The menu loop

Ask with `AskUserQuestion` (one question, four options):

1. **Top findings** — severity-ranked
2. **Top mitigations** — by priority & leverage
3. **By area** — pick a security domain
4. **Write plan & exit**

After each action, redisplay the menu with an updated `Triage: X/<total>`
counter. The user may also type a free-text intent at any time ("accept all
Low", "fix the auth ones") — honour it directly, then return to the menu. The
user can stop whenever they want; untriaged findings simply stay untriaged.

### View: Top findings
Print an untriaged-first, severity-ranked table (skip already-decided unless the
user asks to see all). One row per finding:
`T-NNN · <severity> · <component> · <category_name> · <title>  [<decision if any>]`.
Then run **Select & act** (below).

### View: Top mitigations
Print the `mitigations[]` table:
`M-NNN · <priority> · <severity> · covers <coverage> · <title>`.
Selecting a mitigation and choosing an action applies that action to **all** its
`covered_keys` at once — say so explicitly (e.g. "M-012 → fix 5 findings"). Then
run **Select & act**, treating `covered_keys` as the selection.

### View: By area
Print `areas[]` as a numbered list:
`N. <category_name> — <total> findings (<critical> Critical, <high> High)`.
Ask the user which area (by number or name, free text). Then print that area's
findings (its `keys`, formatted as in Top findings) and run **Select & act**.

### Select & act (shared)
1. Ask the user which items to act on — **free text**, e.g. `T-001..T-005, T-012`,
   a comma list, `all`, or (in an area/mitigation view) `all shown`. Resolve
   tokens to finding `key`s via the `id`↔`key` map from the payload; ignore
   unknown tokens but tell the user which you dropped.
2. Ask the action with `AskUserQuestion`: **Mitigate (fix)** / **Accept risk** /
   **Defer**.
3. **Accept risk** requires a rationale — ask once for a single reason that
   applies to the whole selection; write it to every selected key. Never persist
   an accept-risk with an empty rationale.
4. **Fix / Defer** take an optional owner + target sprint — offer once, capture
   only if volunteered.
5. Persist (Step 6), then return to the menu.

## Step 6 — Persist decisions to the sidecar

Merge captured decisions **into** the existing sidecar (never drop prior
entries). Write `$TRIAGE` with the Write tool, keyed by each finding's `key`
(the stable `local_id`):

```yaml
version: 1
findings:
  <key>:
    decision: fix | accept-risk | defer
    rationale: "<required for accept-risk, else omit>"
    owner: "<optional>"
    target_sprint: "<optional>"
```

Only include fields you actually captured. Never write a `decision` other than
`fix`, `accept-risk`, or `defer` (the renderer coerces anything else to
untriaged). Preserve keys already present that you did not re-triage. After
writing, update your in-context `triaged` count for the menu counter.

## Step 7 — Render the plan (menu option 4 / when the user is done)

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/review_threat_model.py" render \
    --output-dir "$OUTPUT_DIR" --triage "$TRIAGE" --plan "$PLAN"
```

The script writes `remediation-plan.md` deterministically (findings grouped by
decision, severity-ranked, with the model's remediation steps). Print the plan
path and a one-line triage summary (counts per decision). Do not paste the whole
plan; point the user to the file.

If `stale[]` was non-empty, mention it once: some prior decisions reference
findings no longer in the model (fixed, merged, or renumbered) and are listed at
the bottom of the plan for review.
