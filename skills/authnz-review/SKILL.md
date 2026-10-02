---
name: authnz-review
description: >-
  Standalone AuthN/AuthZ review of any repository. Runs three deterministic
  Python scanners (route inventory, auth-check scanner, IDOR confirmer) and
  dispatches a specialized agent that reasons over the combined output:
  cross-component IDOR chains, RBAC coverage gaps, JWT misconfiguration, and
  privilege-escalation signals. Optionally annotates findings with violated
  requirement IDs from a requirements catalog, and exports the findings as pentest tasks for an AI pentest agent. Does NOT
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

## `--help` — help (early exit)

If the user's arguments contain `--help` or `-h`, run the following Bash command,
output its stdout verbatim, then exit. Do not read any other file besides `HELP.txt`.

```bash
cat "<base-dir>/HELP.txt"
```

---

## Step 1 — Parse arguments and print introduction

Parse the user's message or slash-command arguments:
- `--repo <path>` → `REPO_ROOT` (default: current working directory)
- `--requirements <path>` → `REQUIREMENTS_PATH` (default: `none`; also
  auto-detect `$REPO_ROOT/docs/security/requirements.yaml` when it exists)
- `--with-threat-model` → `WITH_THREAT_MODEL=true`
- `--save` → `SAVE_FILES=true`; set `OUTPUT_DIR=<REPO_ROOT>/docs/security`
  and run `mkdir -p "$OUTPUT_DIR"`
- `--pentest-tasks` → `PENTEST_TASKS=true`
- `--no-pentest-tasks` → `PENTEST_TASKS=false`, even when the organization
  profile enables it
- `--pentest-format <fmt>` → `PENTEST_FORMAT` (`generic` | `strix`; reject any
  other value with a one-line error and stop)
- `--pentest-target <url>` → `PENTEST_TARGET`
- `--slug <value>` → `SLUG` (reject a value that is not 1-64 characters from
  `[A-Za-z0-9._-]` with a one-line error and stop); set
  `PENTEST_FILE=pentest-tasks-authnz-<SLUG>.yaml`, else
  `PENTEST_FILE=pentest-tasks-authnz.yaml`
- `--gate` → `GATE_MODE=true`

Then resolve the organization defaults for the three pentest values — the
same `outputs` block `create-threat-model` honours, so both skills answer to
one profile:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/runtime/resolve_org_profile.py" --repo "$REPO_ROOT"
```

The resolver prints JSON and writes nothing. Read `defaults.write_pentest_tasks`,
`defaults.pentest_format` and `defaults.pentest_target` from it; a key that is
absent or `null` means the profile says nothing. A command-line flag always
wins over the profile. Where neither speaks: `PENTEST_TASKS=false`,
`PENTEST_FORMAT=generic`, `PENTEST_TARGET=none`. Any resolver failure (non-zero
exit, unparseable output) leaves all three at those defaults — a broken profile
must not silently change what a review writes. Record `PENTEST_SOURCE` as
`flag` or `org profile <preset>` for the introduction block.

When `SAVE_FILES` is not set, use a temp dir for scanner sidecar files.
Shell state does not survive between Bash calls, so print the path once and
write it literally as `OUTPUT_DIR` in every later command:
```bash
mktemp -d
```
Set `SCRATCH_DIR` and `OUTPUT_DIR` to the printed path.

The analyzer always writes `.authnz-report.json` into `OUTPUT_DIR`. Without
`--save`, that is the temp dir, which Step 10 removes — with `--pentest-tasks`
only the task file survives.

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
python3 "$CLAUDE_PLUGIN_ROOT/scripts/analyzers/route_inventory.py" \
  --repo-root "$REPO_ROOT" \
  --output-dir "$OUTPUT_DIR"
```

If non-zero exit, print the stderr and stop.

Read `$OUTPUT_DIR/.route-inventory.json`. Take every count from its
`coverage` block — `route_count`, `authenticated_count`, `authn_absent_count`,
`authn_unknown_count`, `missing_authz_suspect_count`,
`missing_auth_suspect_count` — and never recount routes yourself. A route is
unauthenticated only when the inventory proved it (`absent`); `unknown` may sit
behind a guard the scanner cannot see. Print:
```
  🟢 <N> routes parsed
     authenticated <A>  ·  no authentication <B>  ·  unknown <U>
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
  IDOR · missing route auth · mass assignment · JWT verification · credential policy
```

Run:
```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/analyzers/source_auth_scanner.py" \
  --repo-root "$REPO_ROOT" \
  --output-dir "$OUTPUT_DIR"
```

If non-zero exit, print the stderr and stop.

Count the findings by category; never count them yourself:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/model/authnz_report.py" counts --output-dir "$OUTPUT_DIR"
```

If non-zero exit, print the stderr and stop. From its `scanner` object, print
(`<N>` is `in_scope`; omit the `out of scope` token when it is 0):

```
  <circle> <N> findings  (IDOR <idor>  ·  route auth <route_auth>  ·  mass-assign <mass_assign>  ·  JWT <jwt>  ·  credential <credential>)
     <out_of_scope> out of scope (injection, crypto, mobile) — not part of this review

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
python3 "$CLAUDE_PLUGIN_ROOT/scripts/analyzers/authz_confirm.py" \
  --repo-root "$REPO_ROOT" \
  --output-dir "$OUTPUT_DIR"
```

If non-zero exit, print the stderr and stop.

Run the `counts` command from Phase 2 again and, from its `confirmed` object,
print (omit the second line when `unresolved_suspects` is 0):
```
  <circle> <total> confirmed  (<idor> IDOR/BOLA  ·  <route_auth> missing route auth)
     <unresolved_suspects> suspects unresolvable — kept as design-level hypotheses

Phase 3/5 complete                                      [ 60%]
```

Circle: 🟢 for 0 confirmed, 🟡 for 1–2, 🔴 for 3+.

---

## Step 4b — No-auth-layer early exit

After reading the Phase 1–3 results, check whether the repository provably
has no authentication layer:

- `route_count > 0` and `authn_absent_count == route_count` (from
  `.route-inventory.json` `coverage`) — every route proven unauthenticated
- `scanner.in_scope == 0` (from the Phase 3 `counts` output)
- `confirmed.total == 0` (from the same output)

A route with `unknown` authentication is not proof of a missing layer; when
any route is `unknown`, continue with Step 5.

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

   *Evidence*    <N> routes scanned, every one proven unauthenticated
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
CLAUDE_PLUGIN_ROOT=<CLAUDE_PLUGIN_ROOT>
MODEL_ID=<session model, e.g. sonnet>

SOURCE_AUTH_FINDINGS_PATH=<OUTPUT_DIR>/.source-auth-findings.json
ROUTE_INVENTORY_PATH=<OUTPUT_DIR>/.route-inventory.json
AUTHZ_CONFIRM_PATH=<OUTPUT_DIR>/.authz-confirm-findings.json

REQUIREMENTS_PATH=<REQUIREMENTS_PATH>
STRIDE_FINDINGS_GLOB=<STRIDE_FINDINGS_GLOB>
COMPONENT_INVENTORY_PATH=<$REPO_ROOT/docs/security/.components.json if exists, else none>
```

Wait for the agent to complete, then validate the report and compute its
summary:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/model/authnz_report.py" finalize --report "$OUTPUT_DIR/.authnz-report.json"
```

If non-zero exit, print the stderr and stop: an invalid report is never
printed. Otherwise read `$OUTPUT_DIR/.authnz-report.json` into memory as
`REPORT`; every count below comes from `REPORT.summary`. When `REPORT.partial`
is `true`, the analyzer stopped early: print
`  ⚪ partial report — the analyzer stopped after <last_step>` before the counts.

Print:
```
  🔴 Critical <critical>  🟠 High <high>  🟡 Medium <medium>  🔵 Low <low>
     IDOR confirmed <idor_confirmed>  ·  chains <chains>  ·  STRIDE deduped <stride_deduplicated>

Phase 4/5 complete                                      [ 80%]
```

Omit the `STRIDE deduped` token when `stride_deduplicated == 0`.

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

Otherwise the analyzer has already annotated the findings. Print, with
`<N>` = `summary.requirements_annotated`:
```
  🟢 <N> of <total> findings linked to requirement IDs  (<source>)
     <M> findings use OWASP/CWE fallback references

                                                        [100%]
```

---

## Step 8 — Print results

Use `REPORT` (already in memory from Step 6). Do not read from disk.

### 8a — Results header

Print exactly this fixed block — never as prose. Every count is the named
`REPORT.summary` field; never recount findings:

```
Results · <repo name> · <total_findings> findings

  🔴 Critical  <critical>
  🟠 High      <high>
  🟡 Medium    <medium>
  🔵 Low       <low>
  ──────────────────────────────────────
  IDOR confirmed          <idor_confirmed>
  Missing auth (routes)   <missing_auth>
  JWT misconfigurations   <jwt_findings>
  Credential policy       <credential_findings>
  Privilege escalation    <privilege_escalation>
  ──────────────────────────────────────
  Req. violations linked  <requirements_annotated>   ← omit row when REQUIREMENTS_PATH=none
  STRIDE deduplicated     <stride_deduplicated>   ← omit row when STRIDE_FINDINGS_GLOB=none
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

## Step 9 — Save files and pentest tasks (only when --save or --pentest-tasks)

When `SAVE_FILES=true` or `PENTEST_TASKS=true`, read `<base-dir>/save-and-export.md`
in full and follow it: Step 9 writes the Markdown and JSON report, Step 9b exports
the pentest task file. Otherwise skip to Step 10.

---

## Step 10 — Gate check

If `GATE_MODE=true` and Critical or High findings exist:
```
  GATE FAILED — <N> Critical/High findings require attention.
```
Exit non-zero by printing `exit_code: 1` as the final line.

Otherwise (no Critical/High, or gate not set): no extra line needed.

When `SCRATCH_DIR` is set, remove it last, including after the Step 4b early
exit: `rm -rf "<SCRATCH_DIR>"`.
