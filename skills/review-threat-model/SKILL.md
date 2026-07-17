---
name: review-threat-model
description: User-facing triage of an existing threat model — an overview-first console over an already-generated threat-model.yaml (backlog by priority, severity mix, worst-case scenarios), then one of two modes: Fix or accept findings now (apply the code fix for findings you pick — or accept the risk instead — one at a time for review) or Build a remediation plan (decide mitigate / accept-risk per finding and emit a remediation-plan.md, no code changes). Runs later and completely independently of create-threat-model; reads the model, never regenerates or re-scores it. Not an artifact-quality check (that is eval-threat-model).
---

You help a user work through the findings of a threat model that already exists,
in one of two modes they choose up front: **Fix or accept findings now**
(**implement** the fix for findings they select — or accept the risk instead —
one at a time, for review) or **Build a remediation plan** (decide fix / accept
per finding → `remediation-plan.md`, no code changes).

**Consumer guarantee (about the *threat model*)** — never violated:
- It **reads** `threat-model.yaml` — it never recomputes severity, re-authors
  mitigations, regenerates, or writes back to it (the pipeline owns that).
- Triage decisions live **only** in a sidecar (`<repo>/.appsec-triage/triage.yaml`);
  the sidecar and the plan live under `<repo>/.appsec-triage/`, a namespace the
  generation pipeline never touches — triage changes nothing about the
  create-threat-model workflow.
- **One explicit, opt-in exception (Step 6b):** on the user's request, `accept-risk`
  decisions may be promoted into `<repo>/docs/known-threats.yaml` as `status:
  accepted` entries. That file is a create-threat-model **input** (re-read each
  scan), *not* the generated model — so the accepted threat is skipped (not
  re-raised) on the next scan and surfaced as an accepted risk. This still never
  writes `threat-model.yaml`, never runs automatically, and preserves any
  team-authored entries in that file.

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
  * You first choose a mode: "Fix or accept findings now" (apply the code fix for
    findings you pick — or accept the risk instead — one at a time for review, no
    plan) or "Build a remediation plan" (decide fix / accept per finding →
    remediation-plan.md, never changes code).
  * Both modes find and select findings the same way — a recommended "fix first"
    set (shown with criticality, type and file:line), a pick list, or browse by
    severity / type / requirement / unmitigated; posture ratings orient Plan mode.
  * You select findings/mitigations by id or range (e.g. `T-001..T-005, T-012`
    or `M-003..M-009`). In Plan mode the selection is decided (mark to fix /
    accept-risk); in Fix mode it is fixed in code. accept-risk requires a
    rationale; mark-to-fix takes an optional owner + target.
  * When explicit custom requirements were integrated, finding rows carry a
    [req: …] badge and a By-requirement lens (never for the OWASP baseline).
  * Persists your decisions to <repo>/.appsec-triage/triage.yaml (survives re-scan).
  * Renders a grouped remediation-plan.md with the model's remediation steps.
  * In "Fix or accept findings now" mode, applies the code changes for the findings you
    select — one at a time, for review — based on their remediation.
  * After an accept-risk, optionally (opt-in) records the accepted risks in
    <repo>/docs/known-threats.yaml as status: accepted, so the next
    create-threat-model scan skips them (not re-raised) and shows them as accepted.

DOES NOT
  * Regenerate or re-score the threat model (use create-threat-model).
  * Judge the model's quality (use eval-threat-model).
  * Write back to threat-model.yaml, or promote accepted risks without your
    explicit opt-in.
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
  (`T-NNN`), `title`, `component`, `severity`, `cwe`, `location` (best
  `file:line`, from evidence → affected_files → component), `category_name`,
  `has_mitigation`, `requirements` (custom requirement IDs it violates — empty
  unless integrated), `decision` (`untriaged` until triaged).
- `mitigations[]` — ranked by priority, then kind (fix before investigate/review),
  then leverage; each has `id` (`M-NNN`), `title`, `priority`, `severity`, `kind`,
  `coverage`, `covered_keys` (the finding `key`s it resolves), and
  `covered_severities` (their severity mix).
- `areas[]` — findings grouped by security domain; each has `category_name`,
  `total`, `critical`, `high`, and `keys`.
- `requirements[]` — findings grouped by violated custom requirement (empty
  unless integrated); each has `requirement_id`, `url`, `total`, `critical`,
  `high`, and `keys`.
- `recommended[]` — the "fix first" set: concrete `fix`-kind mitigations that are
  `Low` effort and cover a Critical/High finding (high value, low cost, low
  implementation risk), worst-severity first; a subset of `mitigations[]` (same
  fields). `verdict.recommended` is the count. This is what the Fix-findings view
  leads with.
- `quick_wins[]` — low-effort mitigations that cover at least one Critical/High
  finding (value/effort sweet spot, any kind), ranked by leverage; a subset of
  `mitigations[]`. `verdict.quick_wins` is the count.
- `control_posture[]` — security controls grouped by `domain`, worst-first by
  effectiveness; each has `domain`, `worst_effectiveness`
  (`Missing`/`Weak`/`Partial`/`Adequate`), `total`, `by_effectiveness`, and
  `controls[]` (`control`, `effectiveness`, `kind`, `assessment`). Read verbatim
  from the model — a rating, never a re-score. Empty if the model has no
  `security_controls`.
- `stale[]` — prior decisions whose finding is gone from the model.
- `screens` — **pre-rendered, ready-to-print text blocks** for the heavy views,
  formatted deterministically by the script (glyph contract, category grouping
  and continuous numbering already baked in). Print the relevant one **verbatim**
  instead of re-composing it from the arrays above — that is what makes each
  screen appear as a fast echo rather than a fresh compose, and it keeps the
  glyphs/numbering drift-free. Keys: `landing`, `fix_start`, `fix_list`
  (P1+P2, with a `show P3` hint), `fix_list_full` (all bands), `browse_severity`,
  `browse_type`, `browse_requirement`, `posture`. An **empty string** means
  "nothing to show" — the array fields above still drive *when* to offer a screen
  (e.g. `posture` only when `control_posture` is non-empty) and every
  id/number/range pick and free-text intent (the screens are display only).

## Step 4 — Show the landing screen (verdict + worst case)

This prints immediately on invocation — the user sees where they stand before
any menu. Do not editorialize; every number/line comes from the payload.

**Glyph conventions (mirror the rendered report — two distinct axes).** The
plugin annotates findings and measures differently on purpose; the triage
console reuses the *same* visual language so it stays consistent with
`threat-model.md`:

- **Findings** (`T-NNN`) — a **severity colour dot**: 🔴 Critical · 🟠 High ·
  🟡 Medium · 🟢 Low · ⚪ unrated. Colour is the risk axis; use it wherever a
  finding's severity is shown.
- **Measures / mitigations** (`M-NNN`) — a **monochrome priority fill-ramp**
  whose grey tone encodes rollout priority (dark→light): ● P1 · ◕ P2 · ◑ P3 ·
  ○ P4. This matches the report's measure annotation (`_PRIO_RAMP_TBL` in
  `compose_threat_model.py`) — measures are **never** coloured by severity; the
  ramp glyph is their marker.

Never invent other glyphs or colours, and never colour a measure — a measure's
axis is priority (the ramp), a finding's axis is severity (the colour dot).

**Empty model guard.** If `total == 0` (the model exists but has no findings —
e.g. a stub or a threats-less file), do **not** show the landing or the menu.
Tell the user the threat model has no findings yet and to (re-)run
`/appsec-advisor:create-threat-model` to scan, then stop. (A *missing* model is
already handled at Step 3 by the `console` exit `1`.)

Print `screens.landing` **verbatim**. The script already formatted it: a bold
title line, the aligned stat rows (**Backlog** by priority, **Severity** mix with
glyphs, **Hot areas**, and the **Requirements** row only when
`verdict.requirements.integrated` is true), then the **⚠ Worst case if nothing
changes** block — every glyph, count and `→ fix with <ramp> <M-NNN>` reference
baked in per the glyph conventions above. Do **not** re-compose, re-order, or add
lines; echo the block as-is (that is the whole latency win). The worst-case rows
double as a fast entry into triage — each row's `mitigation_id` (from
`worst_case[]`) is a ready-made selection once a mode is chosen. After the landing,
go to the **mode choice** (Step 4b); the fast path is then "pick a mode → act on
the recommended set", which each mode shows first. Do **not** apply any decision or
code change before the user has chosen a mode.

## Step 4b — Choose the mode (after the landing, before any menu)

The skill does two different jobs; ask which one **first**, so everything after is
unambiguous. One `AskUserQuestion`, two options:

1. **Fix or accept findings now** — work through the findings you pick one at a
   time: apply the code fix, or accept the risk instead. **No plan.**
2. **Build a remediation plan** — decide per finding (fix / accept), produce
   `remediation-plan.md`. **Never changes code.**

Both modes **find and select** findings the same way (the pre-rendered
"Selecting findings" screens below); they differ only in what the selection
**does** — *decide* (Mode 5A) vs. *change code* (Mode 5B). Run the chosen mode's
loop. The user may type a free-text intent at any time ("accept all Low", "fix the
auth ones") — honour it in-mode. They can stop whenever they want.

## Step 5A — Mode: Build a remediation plan (decide → plan, no code)

A menu loop that records decisions. On entry and after each action, first print
the recommendation (`screens.fix_start`, see **Selecting findings**), then ask with
`AskUserQuestion` — put `Decided: X/<total>` in the prompt:

1. **Decide on the recommended set** — act on the `recommended[]` fixes just shown
2. **Browse & select** — by severity / type / requirement / unmitigated (see **Look around**)
3. **Security posture** — control ratings *(only when `control_posture` is non-empty)*
4. **Done — write plan & exit**

After a selection (from 1 or 2), run the **Decide** action (below): **Mark to fix**
or **Accept risk**. On **Done**, render the plan (Step 7), then offer the **bridge**
with one `AskUserQuestion`: *"Fix the To-Fix findings now directly?"* — **Yes**
switches to Mode 5B with that set preselected; **No** finishes.

### Decide action (Mode 5A terminal)
Applies to the named selection — record the decision only, never touch code:
- **Mark to fix** — write `fix` to the sidecar (Step 6); it lands in the plan's
  *To Fix* bucket with the model's remediation steps. Optional owner + target
  sprint — offer once, capture only if volunteered.
- **Accept risk** — requires a rationale; ask once for one shared reason and write
  it to every selected key (never an empty rationale). Persist `accept-risk`
  (Step 6), then offer the opt-in promotion to `docs/known-threats.yaml` (Step 6b).

## Step 5B — Mode: Fix or accept findings now (change code, one at a time)

A menu loop that changes code. On entry and after each fix, first print
`screens.fix_start`, then ask — put `Fixed: X` in the prompt:

1. **Fix the recommended set** — implement the `recommended[]` fixes shown
2. **Browse & pick** — by severity / type / requirement / unmitigated
3. **Done — finish** — point the user at `git diff`

After a selection, run the **Fix loop** (Step 5b) on the named findings — one at a
time, for review. There is no plan step; the output is the code diff. A finding the
user would rather not fix can be accepted inline via the loop's **Accept instead**.
(Entered from the Mode-5A bridge with a set preselected, skip the menu and go
straight to the Fix loop on that set.)

## Selecting findings (shared by both modes)

Both modes surface and select findings with the same pre-rendered screens — the
mode only changes the terminal action. Never re-compose these; echo them.

### Recommended set — print `screens.fix_start` **verbatim**
The script already computed and formatted it from `recommended[]` (concrete
`fix`es, `Low` effort, removing a Critical/High finding) — bucketed by what each
fix hardens (`**Fix <category_name>** — <n>` groups, worst-severity-first), each
**measure** line led by its **priority ramp** glyph and its covered **finding** on
an indented severity-dot sub-line with `id` + `location`. Echo as-is; do not
regroup, renumber, or re-glyph. If `recommended[]` is empty, `screens.fix_start` is
an empty string (nothing is both cheap and low-risk) — say so plainly and use the
pick list instead; never invent a recommendation.

### Pick list — print `screens.fix_list` **verbatim**
The same category
groups as the recommendation, each item a **continuously numbered** line
(number, priority-ramp glyph, id, band, trimmed title, `★` when recommended)
with the covered finding on an indented severity-dot sub-line showing its
`location` (`file:line`, or a bare `file` / component when the payload has no
line — the script never fabricates one). It defaults to P1 + P2 and ends with a
`… (+N P3 — type show P3 to include)` hint; on `show P3`, print
`screens.fix_list_full` (all bands) instead. Echo as-is — the numbering is the
script's, so a pick like `3` is unambiguous; do not renumber or reprint the full
list between picks.

### Naming the selection (shared)
The developer **names the specific items** — a hand-picked selection is the point,
so this is a typed pick, not a bulk button, against the numbered/id items shown:
- numbers from the pick list: `1, 3, 7`
- ids across any view: `M-003, M-015` or `T-001, T-012`
- a range: `2..5`, `M-003..M-009`, `T-001..T-005`

`all` / `all P1` / `quick wins` work **only if explicitly typed** — never assume a
bulk sweep. A mitigation resolves to its `covered_keys`; findings by `id`↔`key`;
drop unknown tokens with a note. Offer **Back** to return without acting. Before
acting, **echo the picked findings** — lead with the severity glyph — e.g.
`🟠 [T-003] High · Injection · scripts/run-headless.sh:526` — so they confirm; when
a mitigation's `coverage > 1` state the fan-out ("M-015 → fix 3 findings").

Then run the **mode's terminal action** on exactly that selection — the **Decide**
action (Mode 5A) or the **Fix loop** (Step 5b, Mode 5B). Do not reprint the list
between picks.

### Look around — browse & posture (shared)
The non-fixing lenses, used by both modes to find findings to act on. Ask which
lens with `AskUserQuestion`, offering only the ones that apply and letting the user
type `back` to return: the **Browse** lenses below, plus **Security posture**
(Mode 5A only) when `control_posture` is non-empty. Route to the matching lens,
then run the mode's terminal action on the selection; posture is read-only and
never triaged.

**Browse lenses** — offer only the ones that apply, in this order: **By
severity**, **By type**, **By requirement** (only when
`verdict.requirements.integrated` is true), **Unmitigated** (only when
`verdict.uncovered > 0`).
- **By severity** — print `screens.browse_severity` **verbatim**: an
  untriaged-first, severity-ranked finding table, each row led by the severity
  glyph (`<glyph> T-NNN · <severity> · <type> · <location> · <title> [req: …]
  [<decision>]`, type = `category_name` else `cwe`, the `[req: …]`/`[<decision>]`
  badges already gated in).
- **By type** — print `screens.browse_type` **verbatim** (the `areas[]` numbered
  as `N. <category_name> — <total> findings (🔴 <critical> · 🟠 <high>)`), then
  ask which area (number or name) and print its `keys` as findings.
- **By requirement** — print `screens.browse_requirement` **verbatim** (the
  `requirements[]` numbered the same way), then ask which requirement and print
  its `keys` as findings.
- **Unmitigated** — print the findings whose `has_mitigation` is false. These
  have no proposed fix — they most need a human decision.
Name the selection (see **Naming the selection**), then run the mode's terminal
action.

**Security posture lens** (Mode 5A only; only when `control_posture` is non-empty)
Print `screens.posture` **verbatim** — the model's own control ratings, worst-first,
one row per domain: `<domain> — <worst_effectiveness> (<total> controls: <mix>)`.
Domains carry canonical display names, so **Authentication** and **Authorization**
always appear as such (the payload already folds the model's verbose control-domain
labels — e.g. "Identity and Authentication Controls" — into these). On request,
drill into a domain to show its `controls[]` (`control` · `effectiveness` ·
`assessment`). This is a **read-only rating** the analyst
recorded — display it, never recompute or triage it, and do **not** invent a
score. It orients the user ("authorization is Missing, crypto is Weak"); to act
on the findings behind a weak domain, point them to the matching **By type**
lens. (The control `domain` vocabulary and the finding `category_name`
vocabulary differ and share no key, so do not fabricate a join between them.)

### Requirements badge (all finding rows)
When (and only when) `verdict.requirements.integrated` is true, append the
finding's violated custom requirements to its row as `[req: R-12, R-19]` (from
`findings[].requirements`; omit when empty). Never show this for the bundled
best-practices baseline or a skipped requirements stub — the payload already
gates it (the list is empty in those cases). Never fold requirements into
priority or severity — it is a badge/lens, not a re-score.

## Step 5b — Fix loop (Mode 5B terminal — code changes)

The terminal action of **Fix or accept findings now** (also reached from the Mode-5A
bridge). This is the one place the skill edits the target repo's source. Work
through the selected findings **one at a time**, never as a blind bulk apply:

1. For each selected finding (resolve mitigations to their `covered_keys`), read
   its remediation detail from `threat-model.yaml` — the `remediation.steps` and
   `affected_files` on the threat (and the covering mitigation). These are the
   **only** basis for the change; do not invent unrelated edits or touch files
   the finding does not name.
2. Show the user what you will change (file + intended edit), then per finding
   offer **Apply** / **Skip** / **Accept instead** / **Stop**:
   - **Apply** — make the edit (minimal, scoped to the finding). If the remediation
     is ambiguous or needs a decision, ask rather than guess.
   - **Skip** — move to the next finding, unchanged.
   - **Accept instead** — the user would rather accept this finding's risk than
     fix it: ask for a rationale and record `accept-risk` in the sidecar (Step 6),
     then continue. (Offer the Step 6b known-threats promotion once at loop end for
     any accepted findings.)
   - **Stop** — end the loop, return to the Mode 5B menu.
3. After each **applied** finding, record its decision as `fix` in the sidecar
   (Step 6) so triage state stays consistent. Note which findings you implemented,
   skipped, or accepted.
4. When done, suggest verifying — run the project's tests or the `verify` flow if
   present — and point the user at `git diff` to review. Do **not** commit; leave
   that to the user. Then return to the Mode 5B menu.

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
    decision: fix | accept-risk
    rationale: "<required for accept-risk, else omit>"
    owner: "<optional>"
    target_sprint: "<optional>"
```

Only include fields you actually captured. Write only `fix` or `accept-risk` as
the `decision` — the two verbs the menu offers. (The renderer still tolerates a
legacy `defer` decision left in a prior sidecar and buckets it as *Deferred*, but
the triage flow no longer offers it; anything else is coerced to untriaged.)
Preserve keys already present that you did not re-triage. After writing, update
your in-context `triaged` count for the menu counter.

## Step 6b — Promote accepted risks to `docs/known-threats.yaml` (opt-in)

Reached right after an **accept-risk** decision — the *Decide* action in Mode 5A,
or *Accept instead* in the Mode 5B fix loop — and only on the user's explicit
**yes**, never automatically. This is the one time the skill writes outside
`.appsec-triage/`. Ask once with `AskUserQuestion`:

> Also record these as accepted in `docs/known-threats.yaml`? On the next
> `create-threat-model` scan they'll be treated as accepted — skipped (not
> re-raised as open findings) and shown as accepted risks — instead of
> reappearing. (Your triage sidecar is unaffected either way.)

Options: **Yes, record as accepted** / **No, keep in triage only**. On **No**, do
nothing and return to the menu. On **Yes**, run the deterministic promoter — it
reads *every* `accept-risk` decision from the sidecar, synthesizes a schema-valid
`status: accepted` entry per finding (id = the finding's stable `local_id`; title,
STRIDE, component from the model; severity derived; `accepted_risk` = the
rationale; evidence = the finding's `file:line`), and **merges** into the file,
preserving any team-authored entries and deduping by id:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/review_threat_model.py" promote-accepted \
    --output-dir "$OUTPUT_DIR" --triage "$TRIAGE" \
    --known-threats "$REPO_ROOT/docs/known-threats.yaml"
```

It prints a JSON summary (`added` / `updated` / `skipped` / `total`). Report the
counts in one line and point the user at `docs/known-threats.yaml`. `skipped`
lists accepted findings that are stale (gone from the model) or lack a STRIDE
category — mention it only if non-empty. The command validates against
`known-threats.schema.yaml` before writing and fails loudly on invalid output; it
never touches `threat-model.yaml`. Do not commit the file — leave that to the user.

## Step 7 — Write the plan (menu "Done — write plan & exit" / when the user is done)

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/review_threat_model.py" render \
    --output-dir "$OUTPUT_DIR" --triage "$TRIAGE" --plan "$PLAN"
```

The script writes `remediation-plan.md` deterministically: **every** finding is
grouped by its current triage decision — **To Fix** (with the model's remediation
steps), **Accepted Risk** (with the rationale), and **Untriaged — decision still
needed** (anything not yet decided is listed here, never dropped) — severity-ranked
within each bucket, plus a Stale section for decisions whose finding left the
model. (A legacy **Deferred** bucket still renders if a prior sidecar carried a
`defer` decision, but the flow no longer produces new ones.) It is a snapshot of the sidecar at this
moment (decisions from this and prior sessions). When you describe this option to
the user, say concretely what the plan contains — not a vague "from current
decisions". Print the plan path and a one-line triage summary (counts per
decision). Do not paste the whole plan; point the user to the file.

If `stale[]` was non-empty, mention it once: some prior decisions reference
findings no longer in the model (fixed, merged, or renumbered) and are listed at
the bottom of the plan for review.
