---
name: review-threat-model
description: User-facing triage of an existing threat model — open an overview-first console over an already-generated threat-model.yaml (backlog by priority, severity mix, worst-case scenarios), then bulk-decide mitigate / accept-risk / defer (with owner and target) on a selection of findings or mitigations, and emit a remediation-plan.md. Runs later and completely independently of create-threat-model; reads the model, never regenerates or re-scores it. Not an artifact-quality check (that is eval-threat-model).
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
  * Opens a triage console: a landing screen (backlog by priority + severity mix
    + the top "worst case if nothing changes" scenarios), then a menu.
  * Menu spine is the Remediation backlog (P1 -> P2 -> P3). Also: Browse by lens
    (severity / area / requirement), Findings without a mitigation, Write plan.
  * You select findings/mitigations by id or range (e.g. `T-001..T-005, T-012`
    or `M-003..M-009`) and pick one action for the whole selection: mitigate /
    accept-risk / defer. Acting on a mitigation triages every finding it covers.
  * accept-risk requires a rationale (one shared reason for a bulk selection);
    mitigate/defer take an optional owner + target.
  * When explicit custom requirements were integrated, finding rows carry a
    [req: …] badge and a By-requirement lens (never for the OWASP baseline).
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
  `top_areas`, `weaknesses`, `with_mitigation`, `by_priority` (`{P1,P2,P3}`
  mitigation counts — the backlog spine), `p1_mitigations`, `uncovered`
  (findings with no proposed mitigation), `triaged`, and `requirements`
  (`{integrated, findings_violating, requirement_count}` — `integrated` is
  `false` unless explicit custom requirements were integrated; see the badge
  rule in Step 5).
- `worst_case[]` — up to 3 concrete "if you do nothing" scenarios, read verbatim
  from the model's curated `critical_findings`; each has `id` (`T-NNN`),
  `severity`, `component`, `summary`, `mitigation_id`, `priority`.
- `findings[]` — severity-ranked; each has `key` (stable `local_id`), `id`
  (`T-NNN`), `title`, `component`, `severity`, `category_name`, `has_mitigation`,
  `requirements` (custom requirement IDs it violates — empty unless integrated),
  `decision` (`untriaged` until triaged).
- `mitigations[]` — ranked by priority, then kind (fix before investigate/review),
  then leverage; each has `id` (`M-NNN`), `title`, `priority`, `severity`, `kind`,
  `coverage`, `covered_keys` (the finding `key`s it resolves), and
  `covered_severities` (their severity mix).
- `areas[]` — findings grouped by security domain; each has `category_name`,
  `total`, `critical`, `high`, and `keys`.
- `requirements[]` — findings grouped by violated custom requirement (empty
  unless integrated); each has `requirement_id`, `url`, `total`, `critical`,
  `high`, and `keys`.
- `stale[]` — prior decisions whose finding is gone from the model.

## Step 4 — Show the landing screen (verdict + worst case)

This prints immediately on invocation — the user sees where they stand before
any menu. Do not editorialize; every number/line comes from the payload.

First the verdict from `verdict` (omit the Requirements line unless
`verdict.requirements.integrated` is true):

```
<project> · generated <generated> · <total> findings · <triaged>/<total> triaged
Backlog: <P1>× P1 · <P2>× P2 · <P3>× P3   (<uncovered> findings have no mitigation)
Severity: <C> Critical · <H> High · <M> Medium (<unrated> unrated) · <weaknesses> design weaknesses
Requirements: <findings_violating> findings violate <requirement_count> custom requirements
Hottest areas: <a1> (<n>) · <a2> (<n>) · <a3> (<n>)
```

Then the worst-case block from `worst_case[]` (skip the whole block only if it
is empty). One line each, verbatim `summary`, no scenario/walkthrough dumps:

```
Worst case if nothing changes:
  ⚠ [<id>] <severity> · <component> · <summary>   → <mitigation_id> (<priority>)
```

Drop the `→ <mitigation_id> (<priority>)` tail for any row whose `mitigation_id`
is empty. These lines double as a fast entry into triage — the user may act on
them directly (their `mitigation_id`s are a ready-made selection for **Select &
act**).

If `triaged == 0`, offer the express lane before the menu, targeting the
**top non-empty priority band** — P1 if `verdict.by_priority` has a non-zero
`P1`, else P2. (Never P3: the express lane is the "clear the urgent thing fast"
shortcut, and P3 is deferred-tier work — if only P3 mitigations exist, or none
carry a priority, **skip the offer** and go straight to the menu.)

Let `<band>` be that band and `<n>` the number of findings its mitigations
cover (the union of their `covered_keys`). Ask with one `AskUserQuestion`:
"Fix the **<band>** findings now (the `<n>` findings the `<band>`-priority
mitigations cover) and walk the rest?" — options **Yes, fix the <band>s** /
**No, let me navigate**. On yes, apply `fix` to every finding in that union
(Step 6 write), then go to the menu. Always state `<n>` in the prompt so a large
band (e.g. many P2s) is a considered choice, not a blind sweep.

Why the top priority band and not a Critical+High sweep: priority is the model's
own "do this first" call — it already folds in severity, kind and effort — so it
stays consistent with the backlog spine. Any high-severity finding the band does
not cover still appears in the landing screen's worst-case block, so it is never
hidden.

## Step 5 — The menu loop

The spine is the **remediation backlog by priority** (P1 → P2 → P3): the plan
you emit *is* a prioritized backlog, so walking it that way keeps the flow and
the artifact aligned. Severity and area are alternate lenses, not the default.

Ask with `AskUserQuestion` (one question). List the **Findings without a
mitigation** option **only when `verdict.uncovered > 0`** (otherwise it is a
dead slot — drop it and the menu is three options):

1. **Remediation backlog** — by priority (P1 → P2 → P3)
2. **Browse by lens** — severity · area · requirement
3. **Findings without a mitigation** *(only if `uncovered > 0`)*
4. **Write plan & exit**

After each action, redisplay the menu with an updated `Triage: X/<total>`
counter. The user may also type a free-text intent at any time ("accept all
Low", "fix the auth ones") — honour it directly, then return to the menu. The
user can stop whenever they want; untriaged findings simply stay untriaged.

### View: Remediation backlog (default spine)
Print `mitigations[]` grouped into P1 / P2 / P3 bands (they arrive already
sorted: priority, then fix-before-investigate, then leverage). One row each:
`M-NNN · <kind> · covers <coverage> · <covered_severities> · <title>`.
Then ask which band to act on with `AskUserQuestion`: **P1** / **P2** / **P3** /
**All shown** (offer only bands that exist). Print that band and run **Select &
act**, treating each chosen mitigation's `covered_keys` as the selection.
When a mitigation's `coverage > 1`, state the fan-out explicitly ("M-012 → fix 5
findings"); when it covers one finding, say so plainly ("M-012 → fix T-007").

### View: Browse by lens
Ask which lens with `AskUserQuestion` — **By severity** / **By area** /
**By requirement** / **Back**. List **By requirement** **only when
`verdict.requirements.integrated` is true**; otherwise offer three options.
- **By severity** — print an untriaged-first, severity-ranked finding table
  (skip already-decided unless the user asks to see all):
  `T-NNN · <severity> · <component> · <category_name> · <title> [req: …] [<decision>]`.
- **By area** — print `areas[]` numbered:
  `N. <category_name> — <total> findings (<critical> Critical, <high> High)`.
  Ask which area (number or name), then print its `keys` as findings.
- **By requirement** — print `requirements[]` numbered:
  `N. <requirement_id> — <total> findings (<critical> Critical, <high> High)`.
  Ask which requirement, then print its `keys` as findings.
Then run **Select & act**.

### View: Findings without a mitigation
Print the findings whose `has_mitigation` is false, formatted as in By severity.
These have no proposed fix — they most need a human decision. Run **Select &
act**.

### Requirements badge (all finding rows)
When (and only when) `verdict.requirements.integrated` is true, append the
finding's violated custom requirements to its row as `[req: R-12, R-19]` (from
`findings[].requirements`; omit when empty). Never show this for the bundled
best-practices baseline or a skipped requirements stub — the payload already
gates it (the list is empty in those cases). Never fold requirements into
priority or severity — it is a badge/lens, not a re-score.

### Select & act (shared)
1. Ask the user which items to act on — **free text**, e.g. `T-001..T-005, T-012`,
   `M-003..M-009`, a comma list, `all`, or (in a band/area/requirement view)
   `all shown`. Resolve `T-NNN`/`M-NNN` tokens to finding `key`s via the payload
   (`id`↔`key`; a mitigation resolves to its `covered_keys`); ignore unknown
   tokens but tell the user which you dropped.
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
