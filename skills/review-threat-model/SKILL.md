---
name: review-threat-model
description: User-facing triage of an existing threat model — open an overview-first console over an already-generated threat-model.yaml (backlog by priority, severity mix, worst-case scenarios), then bulk-decide mitigate / accept-risk / defer (with owner and target) on a selection of findings or mitigations, and emit a remediation-plan.md. On explicit request it also implements the fixes for the findings you select — one at a time, for review. Runs later and completely independently of create-threat-model; reads the model, never regenerates or re-scores it. Not an artifact-quality check (that is eval-threat-model).
---

You help a user **triage** the findings of a threat model that already exists —
and, on explicit request, **implement** the fixes for the findings they select.

**Consumer guarantee (about the *threat model*)** — never violated:
- It **reads** `threat-model.yaml` — it never recomputes severity, re-authors
  mitigations, regenerates, or writes back to it (the pipeline owns that).
- Triage decisions live **only** in a sidecar (`<repo>/.appsec-triage/triage.yaml`);
  the sidecar and the plan live under `<repo>/.appsec-triage/`, a namespace the
  generation pipeline never touches — triage changes nothing about the
  create-threat-model workflow.

**Code changes (about the *target repo's source*)** happen **only** through the
explicit **Implement** action (Step 5b): for findings the user has selected, one
at a time, with the user reviewing each change. The triage/console flow itself
never edits source, and you never touch code the user did not select.

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
  * Menu spine is the Remediation backlog — a terse, priority-ordered P1/P2 list
    (Quick wins marked ★); you pick the specific fixes to act on by number/id.
    Also: Browse by lens (severity / area / requirement / uncovered), Security
    posture by domain, Write plan.
  * You select findings/mitigations by id or range (e.g. `T-001..T-005, T-012`
    or `M-003..M-009`) and pick one action for the whole selection: mitigate /
    accept-risk / defer. Acting on a mitigation triages every finding it covers.
  * accept-risk requires a rationale (one shared reason for a bulk selection);
    mitigate/defer take an optional owner + target.
  * When explicit custom requirements were integrated, finding rows carry a
    [req: …] badge and a By-requirement lens (never for the OWASP baseline).
  * Persists your decisions to <repo>/.appsec-triage/triage.yaml (survives re-scan).
  * Renders a grouped remediation-plan.md with the model's remediation steps.
  * On request ("Mitigate + implement now"), applies the code changes for the
    findings you select — one at a time, for review — based on their remediation.

DOES NOT
  * Regenerate or re-score the threat model (use create-threat-model).
  * Judge the model's quality (use eval-threat-model).
  * Bulk-apply code changes blindly, commit, or touch findings you did not select.

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
- `quick_wins[]` — low-effort mitigations that cover at least one Critical/High
  finding (value/effort sweet spot), ranked by leverage; a subset of
  `mitigations[]` (same fields). `verdict.quick_wins` is the count.
- `control_posture[]` — security controls grouped by `domain`, worst-first by
  effectiveness; each has `domain`, `worst_effectiveness`
  (`Missing`/`Weak`/`Partial`/`Adequate`), `total`, `by_effectiveness`, and
  `controls[]` (`control`, `effectiveness`, `kind`, `assessment`). Read verbatim
  from the model — a rating, never a re-score. Empty if the model has no
  `security_controls`.
- `stale[]` — prior decisions whose finding is gone from the model.

## Step 4 — Show the landing screen (verdict + worst case)

This prints immediately on invocation — the user sees where they stand before
any menu. Do not editorialize; every number/line comes from the payload.

**Empty model guard.** If `total == 0` (the model exists but has no findings —
e.g. a stub or a threats-less file), do **not** show the landing or the menu.
Tell the user the threat model has no findings yet and to (re-)run
`/appsec-advisor:create-threat-model` to scan, then stop. (A *missing* model is
already handled at Step 3 by the `console` exit `1`.)

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
(**Quick wins (<q>)** when `verdict.quick_wins > 0`) / **No, let me navigate**.
On **Yes**, apply `fix` to every finding in that union (Step 6 write). On
**Quick wins**, apply `fix` to the union of the `quick_wins[]` mitigations'
`covered_keys` instead — the low-effort, high-impact set. Then go to the menu.
Always state the counts in the prompt so a large band (e.g. many P2s) is a
considered choice, not a blind sweep.

Why the top priority band and not a Critical+High sweep: priority is the model's
own "do this first" call — it already folds in severity, kind and effort — so it
stays consistent with the backlog spine. Any high-severity finding the band does
not cover still appears in the landing screen's worst-case block, so it is never
hidden.

## Step 5 — The menu loop

The spine is the **remediation backlog by priority** (P1 → P2 → P3): the plan
you emit *is* a prioritized backlog, so walking it that way keeps the flow and
the artifact aligned. Severity and area are alternate lenses, not the default.

Ask with `AskUserQuestion` (one question, four options):

1. **Remediation backlog** — a terse P1/P2 list; pick the specific fixes to act on
2. **Browse by lens** — severity · area · requirement · uncovered
3. **Security posture by domain** — control ratings *(only if `control_posture` is non-empty)*
4. **Write plan & exit**

After each action, redisplay the menu with an updated `Triage: X/<total>`
counter. The user may also type a free-text intent at any time ("accept all
Low", "fix the auth ones", "show quick wins") — honour it directly, then return
to the menu. The user can stop whenever they want; untriaged findings simply
stay untriaged.

### View: Remediation backlog (default spine)
Keep the display **terse** — a long, multi-field dump of every mitigation is slow
to render and is what makes the view feel sluggish. Print a compact **numbered
list**, one short line per item, and by default show only the actionable bands
**P1 + P2** (already priority-sorted). Note the P3 count and include it only if
the developer asks (`show P3`). One row = number, id, band, `★` if it is a Quick
win, and a trimmed title — nothing else (no kind / coverage / covered_severities
inline; the developer can ask about a specific item):

```
 1. M-015 (P1) <short title> ★
 2. M-010 (P2) <short title> ★
 3. M-003 (P2) <short title>
 … (+8 P3 — type `show P3` to include)
```

Then ask **which specific items the developer wants to act on** — a hand-picked
selection, never an assumed "fix everything":

> "Which do you want to act on? Type the numbers or ids — e.g. `1, 3, 7` or
> `M-003, M-015` (ranges like `2..5` work too)."

Resolve the picked numbers/ids to finding `key`s (a mitigation → its
`covered_keys`); drop unknown tokens with a note. Act **only** on what the
developer named — `all` / `all P1` work only if they explicitly type them; never
default to a bulk sweep. Then run **Select & act** on that selection. Do not
reprint the whole list between selections — if it is already on screen, just ask
for the next picks. When a mitigation's `coverage > 1`, state the fan-out
("M-015 → fix 3 findings"); else say it plainly ("M-015 → fix T-001").

### View: Browse by lens
Ask which lens with `AskUserQuestion` — offer only the ones that apply, in this
order, and let the user type `back` to return: **By severity**, **By area**,
**By requirement** (only when `verdict.requirements.integrated` is true),
**Without a mitigation** (only when `verdict.uncovered > 0`).
- **By severity** — print an untriaged-first, severity-ranked finding table
  (skip already-decided unless the user asks to see all):
  `T-NNN · <severity> · <component> · <category_name> · <title> [req: …] [<decision>]`.
- **By area** — print `areas[]` numbered:
  `N. <category_name> — <total> findings (<critical> Critical, <high> High)`.
  Ask which area (number or name), then print its `keys` as findings.
- **By requirement** — print `requirements[]` numbered:
  `N. <requirement_id> — <total> findings (<critical> Critical, <high> High)`.
  Ask which requirement, then print its `keys` as findings.
- **Without a mitigation** — print the findings whose `has_mitigation` is false.
  These have no proposed fix — they most need a human decision.
Then run **Select & act**.

### View: Security posture by domain
Print `control_posture[]` — the model's own control ratings, worst-first, one
row per domain: `<domain> — <worst_effectiveness> (<total> controls: <mix>)`.
Domains carry canonical display names, so **Authentication** and **Authorization**
always appear as such (the payload already folds the model's verbose control-domain
labels — e.g. "Identity and Authentication Controls" — into these). On request,
drill into a domain to show its `controls[]` (`control` · `effectiveness` ·
`assessment`). This is a **read-only rating** the analyst
recorded — display it, never recompute or triage it, and do **not** invent a
score. It orients the user ("authorization is Missing, crypto is Weak"); to act
on the findings behind a weak domain, point them to the matching **By area**
lens. (The control `domain` vocabulary and the finding `category_name`
vocabulary differ and share no key, so do not fabricate a join between them.)

### Requirements badge (all finding rows)
When (and only when) `verdict.requirements.integrated` is true, append the
finding's violated custom requirements to its row as `[req: R-12, R-19]` (from
`findings[].requirements`; omit when empty). Never show this for the bundled
best-practices baseline or a skipped requirements stub — the payload already
gates it (the list is empty in those cases). Never fold requirements into
priority or severity — it is a badge/lens, not a re-score.

### Select & act (shared)
1. The developer **names the specific items** to act on — a hand-picked selection
   is the whole point, so this is a typed pick, not a bulk button. Accept, against
   the numbered/id items shown (resolve to keys, drop unknown tokens with a note):
   - numbers from the list: `1, 3, 7`
   - ids across any band/view: `M-003, M-015` or `T-001, T-012`
   - a range: `2..5`, `M-003..M-009`, `T-001..T-005`
   `all` / `all P1` / `quick wins` work **only if explicitly typed** — never
   assume them. A mitigation resolves to its `covered_keys`; findings by
   `id`↔`key`. (Offer **Back** to return to the menu without acting.)
2. Ask the action with `AskUserQuestion`: **Mitigate (fix)** / **Accept risk** /
   **Defer** / **Mitigate + implement now**. It applies to the named selection —
   **Accept risk** / **Defer** triage it; **Mitigate + implement now**
   additionally applies the code changes (Step 5b).
3. **Accept risk** requires a rationale — ask once for a single reason that
   applies to the whole selection; write it to every selected key. Never persist
   an accept-risk with an empty rationale.
4. **Mitigate / Defer** take an optional owner + target sprint — offer once, capture
   only if volunteered.
5. Persist (Step 6). If the action was **Mitigate + implement now**, run Step 5b
   for the selection before returning to the menu; otherwise return to the menu.

Mitigate/Accept/Defer record the triage **decision** only (they feed
`triage.yaml` and `remediation-plan.md`); code changes happen solely via Step 5b.

## Step 5b — Implement selected fixes (code changes)

Reached only from **Mitigate + implement now** (or when the user explicitly asks
to implement a selection). This is the one place the skill edits the target
repo's source. Work through the selected findings **one at a time**, never as a
blind bulk apply:

1. For each selected finding (resolve mitigations to their `covered_keys`), read
   its remediation detail from `threat-model.yaml` — the `remediation.steps` and
   `affected_files` on the threat (and the covering mitigation). These are the
   **only** basis for the change; do not invent unrelated edits or touch files
   the finding does not name.
2. Show the user what you will change (file + intended edit) and apply it with
   Edit. Keep the change minimal and scoped to the finding. If the remediation is
   ambiguous or needs a decision, ask rather than guess; the user may **skip** a
   finding or **stop** the loop at any point.
3. After each applied finding, record its decision as `fix` in the sidecar
   (Step 6) so the plan and triage state stay consistent. Note which findings you
   implemented vs skipped.
4. When done, suggest verifying — run the project's tests or the `verify` flow if
   present — and point the user at `git diff` to review. Do **not** commit; leave
   that to the user. Then return to the menu.

Guardrails: only findings the user selected; one at a time with review; changes
traceable to the finding's own remediation; the threat model itself is never
edited (Consumer guarantee holds — you change source, not `threat-model.yaml`).

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
