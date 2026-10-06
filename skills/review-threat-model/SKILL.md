---
name: review-threat-model
description: >-
  User-facing triage of an existing threat model — an overview-first console
  over an already-generated threat-model.yaml (backlog by priority, severity
  mix, worst-case scenarios), then one of three modes. "Just look around"
  browses findings read-only by severity, security aspect, requirement, or
  control posture. "Fix or accept findings now" applies the code fix for
  findings you pick — or accepts the risk instead — one at a time for review.
  "Build a remediation plan" decides mitigate / accept-risk per finding and
  emits a remediation-plan.md without code changes. Within a session you can
  also discuss a single finding by id (F-/T-/M-/W-), a read-only aside that
  changes nothing. Runs later and independently of create-threat-model; reads
  the model, never regenerates or re-scores it. Not an artifact-quality check
  (that is eval-threat-model). To only *ask* about the model without acting on
  it, use ask-threat-model.
---

You help a user work through the findings of a threat model that already exists,
in one of three modes they choose up front: **Just look around** (browse the
findings read-only — overall and by security aspect such as authentication or
access control — making no decisions and no changes), **Fix or accept findings
now** (**implement** the fix for findings they select — or accept the risk
instead — one at a time, for review), or **Build a remediation plan** (decide
fix / accept per finding → `remediation-plan.md`, no code changes).

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
`scripts/validators/review_threat_model.py`. Your job is the interactive layer: run an
**overview-first triage console** — show the user where they stand, let them
drill into top findings / top mitigations / a security domain, act on a
free-text selection (bulk), and hand the decisions to that script. Do **not**
hand-write the plan and do **not** re-score or invent severities/areas — every
number you show comes from the `console` payload.

## `--help` — help (early exit)

If the arguments contain `--help` or `-h`, run the following Bash command, output
its stdout verbatim, then exit. Do not read any other file besides `HELP.txt`.

```bash
cat "<base-dir>/HELP.txt"
```

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
  # <base-dir> from the invocation line. Never search the filesystem: several
  # checkouts may exist and the first hit is arbitrary.
  CLAUDE_PLUGIN_ROOT=$(cd "<base-dir>/../.." && pwd)
fi
export CLAUDE_PLUGIN_ROOT
if [ -z "$CLAUDE_PLUGIN_ROOT" ] || [ ! -d "$CLAUDE_PLUGIN_ROOT" ]; then
  echo "Error: CLAUDE_PLUGIN_ROOT could not be resolved." >&2
  exit 2
fi
```

## Step 3 — Load the console payload

Pipe the freshness probe into `console` so the landing screen can say whether the
model still matches the code. Do not set `pipefail`: the meaningful exit code is
`console`'s, not the health probe's CI exit code.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/model/threat_model_health.py" \
    --repo-root "$REPO_ROOT" --output-dir "$OUTPUT_DIR" --json 2>/dev/null \
| python3 "$CLAUDE_PLUGIN_ROOT/scripts/validators/review_threat_model.py" console \
    --output-dir "$OUTPUT_DIR" --triage "$TRIAGE" --health-json -
```

Exit `1` means no model was found — tell the user to run
`/appsec-advisor:create-threat-model` first, then stop. Otherwise parse the JSON
**once** and keep it in context for the whole session — it is the single source
for every screen below. Do not re-run `console` on each loop; the static data
(findings, mitigations, areas) does not change, only your decisions do.

Payload shape (all read from the model — never recompute):
- `freshness` — the piped health verdict (`verdict` `FRESH`/`STALE`/`UNKNOWN`,
  `reason`, `recommend`), or `null` when no health payload reached the console.
  It is the **same** change detection that decides whether an incremental scan
  is needed; the console never recomputes it. Already folded into
  `screens.landing` as the **Status** row — you only read it for the Mode 5B
  guard (Step 5B).
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
  `renderers/compose_threat_model.py`) — measures are **never** coloured by severity; the
  ramp glyph is their marker.

Never invent other glyphs or colours, and never colour a measure — a measure's
axis is priority (the ramp), a finding's axis is severity (the colour dot).

**Empty model guard.** If `total == 0` (the model exists but has no findings —
e.g. a stub or a threats-less file), do **not** show the landing or the menu.
Tell the user the threat model has no findings yet and to (re-)run
`/appsec-advisor:create-threat-model` to scan, then stop. (A *missing* model is
already handled at Step 3 by the `console` exit `1`.)

Print `screens.landing` **verbatim**. The script already formatted it: a bold
title line, the aligned stat rows (**Status** — the freshness verdict, only when
a health payload was piped in — **Backlog** by priority, **Severity** mix with
glyphs, **Hot areas**, and the **Requirements** row only when
`verdict.requirements.integrated` is true), then the **⚠ Worst case if nothing
changes** block — every glyph, count and `→ fix with <ramp> <M-NNN>` reference
baked in per the glyph conventions above. Do **not** re-compose, re-order, or add
lines; echo the block as-is (that is the whole latency win). The worst-case rows
double as a fast entry into triage — each row's `mitigation_id` (from
`worst_case[]`) is a ready-made selection once a mode is chosen. After the landing,
go to the **mode choice** (Step 4b); the fast path is then "pick a mode → act on
the fix-first set", which each mode shows first. Do **not** apply any decision or
code change before the user has chosen a mode.

## Step 4b — Choose the mode (after the landing, before any menu)

Ask which job **first**, so everything after is unambiguous. One `AskUserQuestion`,
three options — offer **Just look around** first so a user who only wants to
understand the findings never has to commit to acting:

1. **Just look around** — browse the findings read-only, overall and by aspect
   (authentication, access control, …), and **ask about any one** (why it rates
   as it does, whether it's real, how to fix — Step 5D). **No decisions, no changes.**
2. **Fix or accept findings now** — work through the findings you pick one at a
   time: apply the code fix, or accept the risk instead. **No plan.**
3. **Build a remediation plan** — decide per finding (fix / accept), produce
   `remediation-plan.md`. **Never changes code.**

The two **action** modes (5A, 5B) **find and select** findings the same way (the
pre-rendered "Selecting findings" screens below); they differ only in what the
selection **does** — *decide* (Mode 5A) vs. *change code* (Mode 5B). **Just look
around** (Mode 5C) uses the same browse lenses but never acts on the selection.
Run the chosen mode's loop. The user may type a free-text intent at any time
("accept all Low", "fix the auth ones", "show me the access-control findings") —
honour it in the current mode; they can switch modes or stop whenever they want.
A typed **id** — or "discuss F-003" — opens **Discuss** (Step 5D): a read-only
Q&A about that one finding/weakness that changes nothing and returns to wherever
it was opened from (see **Navigation**). The user can also enter it straight from
here, before picking a mode, when they only want to understand a specific finding.

## Navigation (shared by every menu loop)

Menus nest, so going **up** must always be possible — and visible enough to find.
The levels, innermost first:

`finding detail / Discuss aside` → `lens` → `mode menu` → `mode picker (Step 4b)` → `exit`

Rules every loop below applies:
- **`back` goes up exactly one level**, honoured at every prompt — the user can
  always type it (`AskUserQuestion`'s free-text accepts it) even when it is not a
  button. `modes` (or "switch mode") jumps straight to the mode picker.
- **When a menu has fewer than 4 options, add `← Back` as the last visible
  option.** `AskUserQuestion` renders at most 4, so a full menu keeps `back`
  typed-only — but never silently: end the prompt with "…or type `back`".
- **On return, re-print that level's screen verbatim**, so the user lands
  somewhere recognizable instead of at a bare prompt.
- **Going up never acts and never writes** — no decision, no code, no plan. Backing
  out of a selection is always safe.
- **`Done` is not `back`:** `Done` ends the mode (and in Plan mode writes the
  plan). Where they differ, offer both.

## Step 5A — Mode: Build a remediation plan (decide → plan, no code)

When the user picks this mode, read `<base-dir>/modes/plan.md` in full and follow
it. It holds the mode menu, the Decide action, and Step 7 (writing the plan).

## Step 5B — Mode: Fix or accept findings now (change code, one at a time)

When the user picks this mode — or bridges into it from Mode 5A, Mode 5C or
Discuss — read `<base-dir>/modes/fix.md` in full and follow it. It holds the mode
menu, the stale-model warning, and the Fix loop (Step 5b), the one place this
skill edits source.

## Step 5C — Mode: Just look around (read-only overview)

A read-only browse loop — **no decisions, no code, nothing written**. It exists so
the user can understand the findings (overall and by security aspect — e.g.
authentication, access control) before committing to a mode. On entry and after
each view, ask with `AskUserQuestion` which lens to open, offering only the ones
that apply, in this order:

1. **By severity** — the severity-ranked finding table (`screens.browse_severity`)
2. **By type** — findings grouped by security aspect (authentication, access
   control, injection, …); drill into one aspect to list its findings
3. **By requirement** — *(only when `verdict.requirements.integrated` is true)*
4. **Unmitigated** — findings with no proposed fix *(only when `verdict.uncovered > 0`)*
5. **Security posture** — the model's control ratings by domain *(only when
   `control_posture` is non-empty)*
6. **Discuss one (enter id)** — interrogate a single finding/weakness (Step 5D)
7. **Act on these / Done** — leave read-only mode

Route each choice to the matching lens in **Look around** and print its screen
**verbatim**. The user may drill into a specific finding by `id` to see its detail
(severity, component, `location`, type, whether it has a mitigation) — read from
`findings[]`, never re-scored. Do **not** name a selection to act on, and do **not**
write anything (no sidecar, no plan, no code) — this mode only *shows*.

When the user wants to act, offer the **bridge** with one `AskUserQuestion`: switch
to **Fix or accept findings now** (Mode 5B) or **Build a remediation plan**
(Mode 5A) — carrying the findings they were just looking at (e.g. the aspect they
drilled into) over as a suggested starting selection — or **Done** to exit. (For a
read-only overview outside the console, `/appsec-advisor:show-threat-model` is the
standalone equivalent.)

## Step 5D — Discuss a finding (read-only, nothing written)

A free-text lane reachable from any mode (and from Step 4b before a mode is
picked). When the user names a finding or weakness by id to interrogate it, read
`<base-dir>/discuss.md` in full and follow it. It changes nothing (no sidecar, no
plan, no code) and returns to the level it was opened from (see **Navigation**).

## Selecting findings (shared by the action modes)

Both action modes surface and select findings with the same pre-rendered screens —
the mode only changes the terminal action. (The look-around Mode 5C reuses the
browse lenses below but never selects-to-act.) Never re-compose these; echo them.

### Fix-first set — print `screens.fix_start` **verbatim**
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
(number, priority-ramp glyph, id, band, trimmed title, `★` when in the fix-first set)
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
The non-fixing lenses — used by the action modes to find findings to act on, and by
the look-around Mode 5C to just view them. Ask which lens with `AskUserQuestion`,
offering only the ones that apply and following **Navigation** above (`← Back`
as the last option whenever fewer than 4 lenses apply, else the typed `back`): the
**Browse** lenses below, plus **Security posture** (Mode 5A and the look-around
Mode 5C) when `control_posture` is non-empty. Route to the matching lens, then run
the action mode's terminal action on the selection (the look-around Mode 5C never
acts — it only views); posture is read-only and never triaged.

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
Name the selection (see **Naming the selection**), then run the action mode's
terminal action. (In the look-around Mode 5C there is no terminal action — just
view the findings, then pick another lens or leave.)

**Security posture lens** (Mode 5A and the look-around Mode 5C; only when
`control_posture` is non-empty)
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
the `decision` — the two verbs the menu offers.
Preserve keys already present that you did not re-triage. After writing, update
your in-context `triaged` count for the menu counter.

## Step 6b — Promote accepted risks to `docs/known-threats.yaml` (opt-in)

Reached right after an **accept-risk** decision — the *Decide* action in Mode 5A,
or *Accept instead* in the Mode 5B fix loop. Read `<base-dir>/promote-accepted.md`
in full and follow it. It writes only on the user's explicit **yes**.
