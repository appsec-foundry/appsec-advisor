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
  * Menu spine is fixing — two of the four slots are fix paths: "Fix — start
    here" leads with a recommended "fix first" set (cheap, low-risk, high-impact,
    each shown with criticality, type and file:line) you act on in one step;
    "Fix — pick specific" lists the fixes so you name the exact ones by number/id.
    Also: Look around (browse by severity / type / requirement / unmitigated, plus
    security-posture control ratings), and Done — write plan & exit.
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

First the verdict from `verdict` — a bold title line, then aligned stat rows
(omit the Requirements row unless `verdict.requirements.integrated` is true).
Render it exactly like this (the labels are bold, the severity counts carry
their glyph):

```
**<project>** · generated <generated> · **<total> findings** · <triaged>/<total> triaged

  **Backlog**    <P1>× P1 · <P2>× P2 · <P3>× P3   ·   <uncovered> without a fix
  **Severity**   🔴 <C> Critical · 🟠 <H> High · 🟡 <M> Medium · ⚪ <unrated> unrated · 🧩 <weaknesses> design weaknesses
  **Requirements**  <findings_violating> findings violate <requirement_count> custom requirements
  **Hot areas**  <a1> (<n>) · <a2> (<n>) · <a3> (<n>)
```

Then the worst-case block from `worst_case[]` (skip the whole block only if it
is empty) as a bold header + one bullet each, verbatim `summary`, severity
glyph up front, no scenario/walkthrough dumps:

```
**⚠ Worst case if nothing changes**

  🔴 **[<id>]** <component> — <summary>   → fix with <ramp> <mitigation_id>
```

The `[<id>]` is a finding, so use the row's **severity colour dot** (🔴/🟠/…) in
place of the 🔴 above; the fix reference is a **measure**, so use its **priority
ramp** glyph (`●◕◑○`) for `<ramp>` — not a `(P1)` text tag. Drop the
`→ fix with …` tail for any row whose `mitigation_id` is empty. These lines
double as a fast entry into triage — the user may act on them directly (their
`mitigation_id`s are a ready-made selection for **Select & act**).

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

The spine is **Fix findings** — this is where a developer actually remediates.
Lead with a recommendation (what to fix first), and always let them pick a
specific fix instead. Severity and area are alternate lenses.

Ask with `AskUserQuestion` (one question, four options). The spine is fixing, so
**two of the four are fix paths**; one is the look-around lens, one is the finish:

1. **Fix — start here** — show the recommended "fix first" set and act on it
2. **Fix — pick specific** — list the fixes and name the exact ones to act on
3. **Look around** — browse findings (by severity / type / requirement /
   unmitigated) and, when `control_posture` is non-empty, the security-posture
   control ratings
4. **Done — write plan & exit** — render `remediation-plan.md` and finish. Your
   triage decisions are **already saved** to the sidecar after every action, so
   this step only produces the deliverable — it is not what keeps your work.

After each action, redisplay the menu with an updated `Triage: X/<total>`
counter. The user may also type a free-text intent at any time ("accept all
Low", "fix the auth ones") — honour it directly, then return to the menu. The
user can stop whenever they want; untriaged findings simply stay untriaged.

### View: Fix — start here (menu option 1)
Do not dump the whole list. **Lead with the recommendation** from `recommended[]`
— the "fix first" set the payload already computed (mitigations that are
concrete `fix`es, `Low` effort, and remove a Critical/High finding = high value,
low cost, low implementation risk).

**Group by what each fix hardens.** Bucket the mitigations by the
`category_name` of the finding they resolve (a `fix` covers one finding; if it
covers several, use the worst-severity one). Print one bold group header per
category — `**Fix <category_name>** — <n>` — then its fixes, worst-severity
first; order the groups worst-severity-first too. This turns the flat list into
"here's the auth work, here's the injection work" so the developer can attack a
theme at a time. Lead each **measure** line with its **priority ramp** glyph
(`●◕◑○`, the report's convention), and put the covered **finding** on an indented
sub-line prefixed with its **severity colour dot** — the category is already the
header, so don't repeat the type per row:

```
🛠 **Recommended to fix first** — cheap, low-risk, high-impact   (● P1 · ◕ P2 · ◑ P3 · ○ P4)

**Fix Broken Authentication** — 2
  ● M-003 (P1) <short title>
        └ 🔴 T-003 · authentication/LegacyJwtVerifier.java:15
  ● M-005 (P1) <short title>
        └ 🔴 T-005 · authentication/LegacySqliteUserStore.java:64

**Fix Injection** — 2
  ● M-006 (P1) <short title>
        └ 🔴 T-006 · inputvalidation/OrderLookupDao.java:22
  …
```

The ramp glyph is the mitigation's `priority`; keep the `(P1)` text too (console
users pick by band, e.g. "all P1"). The sub-line dot is the covered finding's
`severity`, then its `id` + `location` (`file:line` from the payload). This
grouped, richer detail is affordable because the recommended set is small; keep
the browse list (below) terse.

Then offer, with `AskUserQuestion`:

1. **Fix the recommended set (<n>)** — take the `recommended[]` mitigations as the
   selection and go to **Select & act** (the developer then picks the action,
   e.g. *Mitigate + implement now*). This is the guided "just tell me where to
   start" path.
2. **Pick a specific fix instead** — switch to **Fix — pick specific** (the terse
   list below).
3. **Back**.

If `recommended[]` is empty (nothing is both cheap and low-risk), say so plainly
and switch straight to **Fix — pick specific** — never invent a recommendation.

### View: Fix — pick specific (menu option 2)
Reached from the menu, or from "pick a specific fix instead" above.

**The terse list**: the same **category groups** as the recommendation (bold
`**<category_name>**` header per bucket, worst-severity-first). Each item is a
numbered line — number, **priority ramp** glyph (`●◕◑○`), id, band, trimmed
title, `★` if it is in `recommended[]` — with the covered finding on an indented
sub-line prefixed with its **severity colour dot**, exactly like the recommended
view. **Always show the covered finding's `location`** (for a multi-cover fix use
the worst-severity finding and append `+N`). It is `file:line` for code findings,
but a `file` alone for dependency findings (e.g. `package-lock.json` — no
meaningful line) and a component name for design-level findings (e.g. `JWT
Service` — no file); show whatever the payload gives and **never fabricate a line
number**. No kind/coverage/severities inline. **Number continuously across
groups** so a pick like `3` stays unambiguous. Default to P1 + P2; add P3 only on
request (`show P3`).

```
(● P1 · ◕ P2 · ◑ P3 · ○ P4)
**Broken Authentication**
  1. ● M-003 (P1) <short title> ★
        └ 🔴 T-003 · authentication/LegacyJwtVerifier.java:15
  2. ● M-004 (P1) <short title>
        └ 🔴 T-004 · authentication/TokenIssuer.java:22
**Injection**
  3. ● M-006 (P1) <short title> ★
        └ 🔴 T-006 · inputvalidation/OrderLookupDao.java:22
 … (+8 P3 — type `show P3` to include)
```

The developer names the specific items (`1, 3, 7` / `M-003, M-015` / range
`2..5`); resolve to `covered_keys`, drop unknown tokens with a note. Before
acting, **echo the picked findings** with **criticality · type · location** (as
in the recommendation) so they confirm what they are about to fix — lead with
the severity glyph — e.g.
`🟠 [T-003] High · Injection · scripts/run-headless.sh:526`. Then run **Select &
act**. Act only on what they named — never an assumed bulk sweep. Do not reprint
the full list between picks. When a mitigation's `coverage > 1` state the fan-out
("M-015 → fix 3 findings"); else say it plainly ("M-015 → fix T-001").

### View: Look around (menu option 3)
The non-fixing lenses, folded behind one menu slot. Ask which lens with
`AskUserQuestion`, offering only the ones that apply and letting the user type
`back` to return: the **Browse** lenses below, plus **Security posture** when
`control_posture` is non-empty. Route to the matching lens, then (for Browse
lenses) run **Select & act**; posture is read-only and never triaged.

**Browse lenses** — offer only the ones that apply, in this order: **By
severity**, **By type**, **By requirement** (only when
`verdict.requirements.integrated` is true), **Unmitigated** (only when
`verdict.uncovered > 0`).
- **By severity** — print an untriaged-first, severity-ranked finding table
  (skip already-decided unless the user asks to see all); lead each row with the
  severity glyph:
  `<glyph> T-NNN · <severity> · <type> · <location> · <title> [req: …] [<decision>]`
  (type = `category_name` else `cwe`).
- **By type** — print `areas[]` numbered:
  `N. <category_name> — <total> findings (🔴 <critical> · 🟠 <high>)`.
  Ask which area (number or name), then print its `keys` as findings.
- **By requirement** — print `requirements[]` numbered:
  `N. <requirement_id> — <total> findings (🔴 <critical> · 🟠 <high>)`.
  Ask which requirement, then print its `keys` as findings.
- **Unmitigated** — print the findings whose `has_mitigation` is false. These
  have no proposed fix — they most need a human decision.
Then run **Select & act**.

**Security posture lens** (under Look around; only when `control_posture` is non-empty)
Print `control_posture[]` — the model's own control ratings, worst-first, one
row per domain: `<domain> — <worst_effectiveness> (<total> controls: <mix>)`.
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
   for the selection before returning to the menu. If the action was **Accept
   risk**, offer the optional promotion to `docs/known-threats.yaml` (Step 6b)
   before returning; otherwise return to the menu.

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

## Step 7 — Write the plan (menu "Done — write plan & exit" / when the user is done)

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/review_threat_model.py" render \
    --output-dir "$OUTPUT_DIR" --triage "$TRIAGE" --plan "$PLAN"
```

The script writes `remediation-plan.md` deterministically: **every** finding is
grouped by its current triage decision — **To Fix** and **Deferred** (each with
the model's remediation steps), **Accepted Risk** (with the rationale), and
**Untriaged — decision still needed** (anything not yet decided is listed here,
never dropped) — severity-ranked within each bucket, plus a Stale section for
decisions whose finding left the model. It is a snapshot of the sidecar at this
moment (decisions from this and prior sessions). When you describe this option to
the user, say concretely what the plan contains — not a vague "from current
decisions". Print the plan path and a one-line triage summary (counts per
decision). Do not paste the whole plan; point the user to the file.

If `stale[]` was non-empty, mention it once: some prior decisions reference
findings no longer in the model (fixed, merged, or renumbered) and are listed at
the bottom of the plan for review.
