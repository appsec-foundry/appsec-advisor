---
name: authnz-review
description: >-
  Standalone AuthN/AuthZ review of any repository. Runs three deterministic
  Python scanners (route inventory, auth-check scanner, IDOR confirmer) and
  dispatches a specialized agent that reasons over the combined output:
  cross-component IDOR chains, RBAC coverage gaps, JWT misconfiguration, and
  privilege-escalation signals. Optionally annotates findings with violated
  requirement IDs from a requirements catalog or Phase 8b violations index,
  and exports the findings as pentest tasks for an AI pentest agent. Does NOT
  require a prior threat model run. Prints results to the console; file output
  only with --save or --pentest-tasks.
---

You are performing a focused AuthN/AuthZ review of a repository. Follow the
steps below exactly.

## Colour palette

This report appears in the conversation as rendered Markdown. Raw ANSI escapes
do **not** colourise there — the reliable real-colour indicator is the
**coloured-circle emoji**. Use exactly this palette, mirroring the
`audit-security-requirements` skill so both skills read as one system:

| Severity / Status | Circle | Use |
|---|---|---|
| Critical | 🔴 | finding dot, stats row |
| High | 🟠 | finding dot, stats row |
| Medium | 🟡 | finding dot, stats row |
| Low | 🔵 | finding dot, stats row |
| Clean / pass | 🟢 | phase summary when no findings |
| Informational | ⚪ | deduplicated / skipped |

ANSI fallback (CLI embedding / `NO_COLOR` absent):

| Field | Escape |
|---|---|
| `●` dot / severity label Critical | bold red `\033[1;31m` |
| `●` dot / severity label High | bold yellow `\033[1;33m` |
| `●` dot / severity label Medium | yellow `\033[33m` |
| `●` dot / severity label Low | cyan `\033[36m` |
| Finding ID (`AZ-NNN`) | cyan `\033[36m` |
| Short title (first line of finding) | bold `\033[1m` |
| Field labels (`Evidence`, `Fix`, `Reference`) | dim gray `\033[2m` |
| File paths / line references | dim gray `\033[2m` |
| Phase headers | bold `\033[1m` |
| Progress percentage | dim gray `\033[2m` |

Keep the colour budget restrained: circle + severity + ID anchor each finding
line; bold title carries the eye. No box drawing, no background fills, no
accent stripes — the output must stay clean and copy-paste friendly. When
`NO_COLOR` is set or colour is unavailable, render identical text and glyphs
without escapes.

## Output discipline

**Console-first**: all output goes to the conversation. File output is opt-in
via `--save`. Print each phase header and progress line immediately before
performing the described action. No trailing summaries, no preamble, no
"now I will…" narration between steps.

---

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:authnz-review — Cross-component AuthN/AuthZ review

USAGE
  /appsec-advisor:authnz-review [--repo <path>] [--requirements <path>]
                                 [--with-threat-model] [--save] [--gate]
                                 [--pentest-tasks | --no-pentest-tasks]
                                 [--pentest-format <fmt>] [--pentest-target <url>]

OPTIONS
  --repo <path>           Repository root to analyze (default: current directory)
  --requirements <path>   Requirements YAML or Phase 8b violations JSON;
                          findings are annotated with violated requirement IDs
  --with-threat-model     Deduplicate EoP findings already covered by a prior
                          STRIDE run in docs/security/
  --save                  Write authnz-report.md + .authnz-report.json to
                          docs/security/ in addition to console output
  --pentest-tasks         Write docs/security/pentest-tasks-authnz.yaml —
                          verification tasks for an AI pentest agent, one per
                          finding with an eligible CWE and file:line evidence
  --no-pentest-tasks      Skip that export even if the org profile enables it
  --pentest-format <fmt>  generic (default) or strix
  --pentest-target <url>  Base URL of the running target, e.g.
                          http://localhost:3000

  The three pentest values default to the organization profile's outputs
  block (pentest_tasks, pentest_format, pentest_target) when one is active.
  --gate                  Exit non-zero when Critical or High findings exist

WHAT IT ANALYZES
  Phase 1  Route inventory         — every route, its auth middleware, handler
  Phase 2  Auth-check scan         — JWT misconfig, mass assignment, missing guards
  Phase 3  IDOR/BOLA confirmation  — handler body reads to confirm suspects
  Phase 4  Cross-component reasoning — RBAC matrix, escalation chains, AuthN↔AuthZ
  Phase 5  Requirements annotation — maps findings to violated req IDs (opt-in)

EXIT CODES
  0   No Critical/High findings (or --gate not passed)
  1   Critical or High findings found (only with --gate)
```

---

## Step 1 — Parse arguments and print introduction

Parse the user's message or slash-command arguments:
- `--repo <path>` → `REPO_ROOT` (default: current working directory)
- `--requirements <path>` → `REQUIREMENTS_PATH` (default: `none`; also
  auto-detect `$REPO_ROOT/docs/security/.phase-8b-violations.json` then
  `$REPO_ROOT/docs/security/requirements.yaml` — use first that exists)
- `--with-threat-model` → `WITH_THREAT_MODEL=true`
- `--save` → `SAVE_FILES=true`; set `OUTPUT_DIR=<REPO_ROOT>/docs/security`
  and run `mkdir -p "$OUTPUT_DIR"`
- `--pentest-tasks` → `PENTEST_TASKS=true`
- `--no-pentest-tasks` → `PENTEST_TASKS=false`, even when the organization
  profile enables it
- `--pentest-format <fmt>` → `PENTEST_FORMAT` (`generic` | `strix`; reject any
  other value with a one-line error and stop)
- `--pentest-target <url>` → `PENTEST_TARGET`
- `--gate` → `GATE_MODE=true`

Then resolve the organization defaults for the three pentest values — the
same `outputs` block `create-threat-model` honours, so both skills answer to
one profile:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/resolve_org_profile.py" --repo "$REPO_ROOT"
```

The resolver prints JSON and writes nothing. Read `defaults.write_pentest_tasks`,
`defaults.pentest_format` and `defaults.pentest_target` from it; a key that is
absent or `null` means the profile says nothing. A command-line flag always
wins over the profile. Where neither speaks: `PENTEST_TASKS=false`,
`PENTEST_FORMAT=generic`, `PENTEST_TARGET=none`. Any resolver failure (non-zero
exit, unparseable output) leaves all three at those defaults — a broken profile
must not silently change what a review writes. Record `PENTEST_SOURCE` as
`flag` or `org profile <preset>` for the introduction block.

When `SAVE_FILES` is not set, use a temp dir for scanner sidecar files:
```bash
SCRATCH_DIR="$(mktemp -d)"
trap 'rm -rf "$SCRATCH_DIR"' EXIT
OUTPUT_DIR="$SCRATCH_DIR"
```

The pentest exporter reads the report from disk, so set
`AGENT_SAVE_MODE=true` when `SAVE_FILES=true` **or** `PENTEST_TASKS=true`,
else `false`. With `--pentest-tasks` but no `--save`, the report is written
into the temp dir and removed on exit — only the task file survives.

Record start time: `START_EPOCH=$(date +%s)`

Print the introduction block:

```
authnz-review  <repo name (basename of REPO_ROOT)>

  <REPO_ROOT>
  route inventory · auth-check scan · IDOR confirmation · cross-component reasoning
  requirements: <REQUIREMENTS_PATH or: none>  ·  output: <docs/security/ | console only>
  pentest tasks: <PENTEST_FORMAT>  ·  target: <PENTEST_TARGET or: none>  ·  <PENTEST_SOURCE>
                                       ← omit line when PENTEST_TASKS is false
```

---

## Step 2 — Phase 1: Route inventory

Print:
```
Phase 1/5 · Route inventory                             [  0%]
  Parsing routes, middleware chains, and handler locations…
```

Run:
```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/route_inventory.py" \
  --repo-root "$REPO_ROOT" \
  --output-dir "$OUTPUT_DIR"
```

If non-zero exit, print the stderr and stop.

Read `$OUTPUT_DIR/.route-inventory.json`. Print:
```
  🟢 <N> routes parsed across <M> files
     authenticated <A>  ·  public <P>  ·  unknown <U>
     suspects: missing authz <X>  ·  missing auth <Y>

Phase 1/5 complete                                      [ 20%]
```

If `X + Y == 0`, use 🟢. If `X + Y > 0 and < 5`, use 🟡. If `X + Y >= 5`, use 🔴.

---

## Step 3 — Phase 2: Auth-check scan

Print:
```
Phase 2/5 · Auth-check scan                             [ 20%]
  Running pattern checks across all source files…
  AUTHZ-001 BFLA  ·  AUTHZ-002 IDOR  ·  AUTHZ-003/004 mass-assign
  AUTHZ-005/006/007 JWT algorithm     ·  AUTHZ-008 missing route auth
  + equivalents for Python · Java · Go · C# · PHP · Ruby · Android
```

Run:
```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/source_auth_scanner.py" \
  --repo-root "$REPO_ROOT" \
  --output-dir "$OUTPUT_DIR"
```

If non-zero exit, print the stderr and stop.

Read `$OUTPUT_DIR/.source-auth-findings.json`. Count findings by category
(`jwt` = AUTHZ-005/006/007/103/201; `mass_assign` = AUTHZ-003/004/101/102;
`route_auth` = AUTHZ-001/008; `other` = rest). Print:

```
  <circle> <N> findings  (JWT <jwt>  ·  mass-assign <ma>  ·  route auth <ra>  ·  other <o>)

Phase 2/5 complete                                      [ 40%]
```

Circle: 🟢 for 0, 🟡 for 1–4, 🔴 for 5+.

---

## Step 4 — Phase 3: IDOR/BOLA confirmation

Print:
```
Phase 3/5 · IDOR/BOLA confirmation                      [ 40%]
  Reading handler bodies to confirm object-level auth suspects…
  Suspects without a resolvable handler body are kept as hypotheses,
  not emitted as confirmed findings.
```

Run:
```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/authz_confirm.py" \
  --repo-root "$REPO_ROOT" \
  --output-dir "$OUTPUT_DIR"
```

If non-zero exit, print the stderr and stop.

Read `$OUTPUT_DIR/.authz-confirm-findings.json`. Print:
```
  <circle> <confirmed> confirmed  (<idor> IDOR/BOLA  ·  <mra> missing route auth)
     <unresolvable> suspects unresolvable — kept as design-level hypotheses

Phase 3/5 complete                                      [ 60%]
```

Circle: 🟢 for 0 confirmed, 🟡 for 1–2, 🔴 for 3+.

---

## Step 4b — No-auth-layer early exit

After reading the Phase 1–3 results, check whether the repository has any
authentication or authorization signals at all:

- `authenticated_routes == 0` (from `.route-inventory.json`)
- scanner findings == 0 (from `.source-auth-findings.json`)
- confirmed instances == 0 (from `.authz-confirm-findings.json`)

When **all three** are true, skip Steps 5–9b and print (when
`PENTEST_TASKS=true`, add `⚪ --pentest-tasks: no findings with code evidence
— no task file written` after the finding block):

```
Phase 4/5 · Cross-component reasoning                   [ 60%]
  Skipped — no authentication or authorization layer detected.

Results · <repo name> · 1 finding

  🟠 High       1
  ──────────────────────────────────────
  completed in  <Xm Ys>

🟠 **[AZ-001] No authentication layer detected**

   *Evidence*    <N> routes scanned, 0 authenticated
   *Attack path* Any endpoint in the application is reachable without
                 credentials — there is no token, session, or access guard
                 to bypass.
   *Fix*         Introduce an authentication middleware (e.g. JWT, session)
                 at the framework router level before any route handler.
   *Reference*   CWE-306 — Missing Authentication for Critical Function
```

Then proceed to Step 10 (gate check).

---

## Step 5 — Resolve STRIDE EoP input

Only when `WITH_THREAT_MODEL=true`: glob for
`$REPO_ROOT/docs/security/.stride-*.json`. If files exist set
`STRIDE_FINDINGS_GLOB="$REPO_ROOT/docs/security/.stride-*.json"`.
Otherwise set `STRIDE_FINDINGS_GLOB=none` and print:
```
  ⚪ --with-threat-model: no .stride-*.json found in docs/security/ — running standalone
```

When `WITH_THREAT_MODEL` is not set: `STRIDE_FINDINGS_GLOB=none`.

---

## Step 6 — Phase 4: Cross-component reasoning

Print (using counts already read from Phases 1–3):
```
Phase 4/5 · Cross-component reasoning                   [ 60%]
  <N> routes  ·  <M> scanner signals  ·  <K> confirmed instances
  Dispatching authnz-analyzer — this step runs silently…
```

Dispatch `appsec-advisor:appsec-authnz-analyzer` with this prompt
(stable values first for prompt-cache friendliness):

```
REPO_ROOT=<REPO_ROOT>
OUTPUT_DIR=<OUTPUT_DIR>
MODEL_ID=<session model, e.g. sonnet>
SAVE_MODE=<AGENT_SAVE_MODE>

SOURCE_AUTH_FINDINGS_PATH=<OUTPUT_DIR>/.source-auth-findings.json
ROUTE_INVENTORY_PATH=<OUTPUT_DIR>/.route-inventory.json
AUTHZ_CONFIRM_PATH=<OUTPUT_DIR>/.authz-confirm-findings.json

REQUIREMENTS_PATH=<REQUIREMENTS_PATH>
STRIDE_FINDINGS_GLOB=<STRIDE_FINDINGS_GLOB>
COMPONENT_INVENTORY_PATH=<$REPO_ROOT/docs/security/.components.json if exists, else none>
```

Wait for the agent to complete.

**When `AGENT_SAVE_MODE=false`:** extract the JSON from the agent's final
message between the `AUTHNZ_REPORT_START` and `AUTHNZ_REPORT_END` markers.
Parse it into memory as `REPORT`. Do not read from disk.

**When `AGENT_SAVE_MODE=true`:** read `$OUTPUT_DIR/.authnz-report.json` into
memory as `REPORT`.

Extract the `summary` block from `REPORT`.

Print:
```
  🔴 Critical <critical>  🟠 High <high>  🟡 Medium <medium>  🔵 Low <low>
     IDOR confirmed <idor_confirmed>  ·  chains <chain_count>  ·  STRIDE deduped <stride_deduplicated>

Phase 4/5 complete                                      [ 80%]
```

Use `chain_count = len(chain_findings)` from the report. Omit the `STRIDE deduped` token when `stride_deduplicated == 0`.

---

## Step 7 — Phase 5: Requirements annotation

Print:
```
Phase 5/5 · Requirements annotation                     [ 80%]
```

If `REQUIREMENTS_PATH` is `none`:
```
  (skipped — no requirements source; pass --requirements to enable)

                                                        [100%]
```

Otherwise the authnz-analyzer already performed annotation in its Step 5.
From `REPORT`, count findings where `requirement_id` is non-null, and print:
```
  🟢 <N> of <total> findings linked to requirement IDs  (<source>)
     <M> findings use OWASP/CWE fallback references

                                                        [100%]
```

---

## Step 8 — Print results

Use `REPORT` (already in memory from Step 6). Do not read from disk.

### 8a — Results header

Print exactly this fixed block — never as prose:

```
Results · <repo name> · <total> findings

  🔴 Critical  <N>
  🟠 High      <N>
  🟡 Medium    <N>
  🔵 Low       <N>
  ──────────────────────────────────────
  IDOR confirmed          <N>
  Missing auth (routes)   <N>
  JWT misconfigurations   <N>
  Privilege escalation    <N>
  ──────────────────────────────────────
  Req. violations linked  <N>        ← omit row when REQUIREMENTS_PATH=none
  STRIDE deduplicated     <N>        ← omit row when STRIDE_FINDINGS_GLOB=none
  ──────────────────────────────────────
  completed in            <Xm Ys>
```

Right-align counts in one column as shown. Compute elapsed as `$(( $(date +%s) - START_EPOCH ))` seconds, format as `Xm Ys` (omit minutes when < 60s).

### 8b — Chain findings (when present)

When `REPORT` contains `chain_findings[]` with at least one entry,
print this section before the per-finding blocks:

```
AuthN → AuthZ chains
────────────────────
```

For each chain:
```
🔴 **[<root_id>] <root_title>** makes <N> authorization finding(s) exploitable

   <chain_ids joined by " · ">  are all bypassed when this token is forged.
   <one-sentence impact statement>
```

### 8c — Critical and High findings

Sort Critical before High, then by component. For each:

```
🔴 **[AZ-NNN] <title>**

   *Evidence*    `<file>:<line>` (list all evidence entries, one per line when grouped)
   *Attack path* <attack_path>
   *Component*   <component_id or: cross-component>
   *Fix*         <remediation.summary>
   *Reference*   <remediation.reference>
   *Requirement* <requirement_id>  ← omit line when null
```

One blank line between findings.

### 8d — Medium findings

Print a compact block per finding, grouped under a header:

```
Medium findings
───────────────
🟡 **[AZ-NNN] <title>**  ·  `<file>:<line>` [+N more]
   <attack_path>
   <remediation.summary>

```

### 8e — Low findings

Print a single aligned table:

```
Low findings
────────────
🔵 AZ-NNN  <title>  (<file>:<line>)
🔵 AZ-NNN  <title>  (<file>:<line>)
```

### 8f — Clean result

When total findings == 0:
```
🟢 No AuthN/AuthZ findings.
```

---

## Step 9 — Save files (only when --save)

Only when `SAVE_FILES=true`.

Write `$OUTPUT_DIR/authnz-report.md` using the same circles and bold/link
conventions as the console output, with full Markdown heading structure:

```markdown
# AuthN/AuthZ Review — <repo name>

**Repository:** <REPO_ROOT>
**Date:** <ISO date>
**Requirements:** <REQUIREMENTS_PATH or: none>

## Summary

| Severity  | Count |
|-----------|------:|
| 🔴 Critical | <N> |
| 🟠 High     | <N> |
| 🟡 Medium   | <N> |
| 🔵 Low      | <N> |

| Signal                 | Count |
|------------------------|------:|
| IDOR confirmed         | <N>   |
| Missing auth (routes)  | <N>   |
| JWT misconfigurations  | <N>   |
| Privilege escalation   | <N>   |

## AuthN → AuthZ Chains
<!-- omit section when no chains -->
...

## Critical and High Findings
...

## Medium Findings
...

## Low Findings
...
```

Write `$OUTPUT_DIR/.authnz-report.json` from `REPORT` (serialize to JSON).

Print:
```
  Saved → docs/security/authnz-report.md
  Saved → docs/security/.authnz-report.json
```

---

## Step 9b — Pentest tasks (only when --pentest-tasks)

Only when `PENTEST_TASKS=true`. Run:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/render_pentest_tasks.py" \
  --authnz "$OUTPUT_DIR/.authnz-report.json" \
  --route-inventory "$OUTPUT_DIR/.route-inventory.json" \
  --output "$REPO_ROOT/docs/security/pentest-tasks-authnz.yaml" \
  --dialect "$PENTEST_FORMAT" \
  --project "<repo name>"
```

Append `--target-url "$PENTEST_TARGET"` when `PENTEST_TARGET` is not `none`.
The exporter emits one verification task per finding whose CWE is on
`data/pentest-eligible-cwes.yaml` and whose evidence carries file **and**
line — design-level findings without code evidence are dropped, so the task
count is normally lower than the finding count. Every task carries a
`safety` block declaring the run read-only; the target URL is written to
`meta.target.base_url` and never contacted.

If non-zero exit, print the stderr and continue to Step 10 — a failed export
does not invalidate the review.

Print (task count from the exporter's `VALID: wrote <N> pentest tasks` line):
```
  Saved → docs/security/pentest-tasks-authnz.yaml  (<N> tasks, <PENTEST_FORMAT>, target <PENTEST_TARGET or: none>)
```

---

## Step 10 — Gate check

If `GATE_MODE=true` and Critical or High findings exist:
```
  GATE FAILED — <N> Critical/High findings require attention.
```
Exit non-zero by printing `exit_code: 1` as the final line.

Otherwise (no Critical/High, or gate not set): no extra line needed.
