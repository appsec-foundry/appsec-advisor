# Proposal — `appsec-reviewer` subagent + `verify-requirements` skill

> **Re-framed 2026-06-07:** this is now **Layer 2 (on-demand check)** of the
> layered **Dev Security Helper** — see `proposal-dev-security-helper.md`. The
> emphasis shifted from *compliance gate* to *dev help*: it is **advisory by
> default**, works **zero-config** via the best-practices baseline fallback
> (Layer 0), and the `--gate` described below is **strictly opt-in**. The
> sections below remain accurate for the mechanics; read the layered proposal
> for the current framing.

**Status:** ✅ IMPLEMENTED 2026-06-07 (see §12). Approved design decisions:
diff-scoped · advisory default with `--gate` hard exit · ship as a dispatchable
subagent fronted by a thin skill. This doc is the design record; the §10 open
questions were resolved with the recommended defaults (name `verify-requirements`,
MUST floor with SHOULD opt-in, deterministic Stage-A pre-filter, reuse audit
report format).

**Goal (verbatim):** a new subagent that development teams embed in their *own*
development workflow to verify their implementation against the security
requirements — built on top of the security-audit skill family.

---

## 1. Why this is a new thing, not the existing audit skill

`/appsec-advisor:audit-security-requirements` already grades requirements
against a repo. But it is the wrong tool for a dev loop:

| | `audit-security-requirements` (exists) | `verify-requirements` (proposed) |
|---|---|---|
| Scope | **Whole repo**, every SEC-* requirement | **The diff** — only what this change touched |
| Cost / latency | Full-repo grade, slow | Bounded by diff size → fast, CI-affordable |
| Executor | Inline in the skill (no isolated context) | **Dispatchable subagent** (fresh budget, reusable by other orchestrators) |
| Audience | AppSec reviewer, periodic audit | **Dev team, every PR / pre-commit** |
| Primary output | Console + saved report | **Machine verdict JSON + exit code** (gate) + readable summary |
| Failure posture | Advisory | Advisory by default, **blocking under `--gate`** |

The two are complementary: the audit answers *"where does the whole codebase
stand?"*; the verifier answers *"does **this change** keep us compliant — may I
merge it?"*. They deliberately **share** the requirements catalog, the
fetch-or-abort gate, and the `PASS / PARTIAL / FAIL / UNVERIFIABLE` status model
so a team sees one consistent vocabulary.

A subagent (not inline skill logic) is the right shape because: it runs in an
isolated context with its own turn budget; it is independently dispatchable from
CI *and* from other orchestrators (e.g. `create-threat-model` could call it on
the changed surface); and it keeps a single, testable contract.

---

## 2. Component overview

Three new artifacts + small edits to existing contracts:

```
agents/appsec-reviewer.md      # NEW — the subagent (executor)
skills/verify-requirements/SKILL.md         # NEW — thin entry point (dev-facing)
scripts/requirements_gate.py                # NEW — deterministic exit-code computer
schemas/fragments/requirements-verification.schema.json   # NEW — verdict schema
data/required-permissions.yaml              # edit — only if new commands appear (see §9)
AGENTS.md (roster)                          # edit — register the agent (drift-guarded)
tests/...                                    # NEW — schema + gate + drift tests
```

Data flow:

```
dev / CI ──▶ /appsec-advisor:verify-requirements [--gate] [--base <ref>]
                │
                │ 1. resolve_requirements_source.py + fetch_requirements.py  (fail-closed gate)
                │    → $OUTPUT_DIR/.requirements.yaml
                │ 2. git diff <base>..HEAD  (or --cached)  → $OUTPUT_DIR/.verify-diff.json  (untrusted data)
                │ 3. dispatch ────────────────────────────────────────────────┐
                ▼                                                              ▼
        deterministic Python                                   appsec-reviewer
                │                                              reads diff + .requirements.yaml,
                │ 4. requirements_gate.py reads JSON           selects in-scope reqs, verifies each,
                │    → exit code (advisory|gate)               writes .requirements-verification.json
                ▼                                              + prints readable console summary
        exit 0 / 1 / 2
```

The LLM (subagent) produces **structured findings only**. The gate decision and
exit code are **deterministic Python** (`requirements_gate.py`) — never the LLM.
This follows AGENTS.md §1/§12 ("agents write fragments; scripts validate/decide")
and "prefer deterministic Python for final artifacts."

---

## 3. Scope model — what "the diff" means

The skill resolves the change set deterministically before dispatch and writes
it to a sidecar the agent reads as **untrusted data** (AGENTS.md §3). Resolution
order for the base ref:

1. `--base <ref>` explicit → `git diff <ref>...HEAD`
2. `--staged` → `git diff --cached` (pre-commit hook use)
3. default → merge-base with the upstream default branch:
   `git merge-base HEAD origin/HEAD` then `git diff <merge-base>...HEAD`
4. fallback when no upstream → `git diff HEAD~1...HEAD`

The sidecar `.verify-diff.json`:

```json
{
  "base_ref": "origin/main",
  "head_ref": "HEAD",
  "merge_base": "<sha>",
  "changed_files": [
    { "path": "src/routes/search.ts", "status": "M", "added": 12, "removed": 3 }
  ],
  "diff_unified": "<full `git diff` text, untrusted>"
}
```

**Empty-diff behavior:** zero changed files → the skill exits 0 with
`No changes to verify.` and does **not** dispatch the agent (no cost).

---

## 4. The hard part — requirement relevance (which reqs are in-scope for a diff)

A full catalog has 60+ requirements; re-grading all of them per PR defeats the
purpose. The verifier selects the **triggered subset** in two stages:

**Stage A — deterministic candidate pre-filter (cheap, stable).** Map changed
files to candidate requirement *categories* using a path/keyword signal table.
This is the CI-stability anchor: the same diff always yields the same candidate
set. Signals (illustrative — finalized at implementation against the live
catalog category IDs):

| Diff signal | Candidate category |
|---|---|
| `*.sql`, `query(`, `sequelize`, ORM raw-query calls | `SEC-*` SQL / data-handling |
| auth/session/login/jwt/cookie paths or tokens | `SEC-AUTH*`, `SEC-ANTI-CSRF` |
| CORS / CSP / security-header config | `SEC-CORS`, `SEC-CSP`, `SEC-HSTS` |
| frontend templates, DOM sinks, `innerHTML` | `SEC-FRONTEND_SECURITY` |
| `Dockerfile`, `.github/workflows/**`, IaC | SSDLC / pipeline reqs |
| crypto APIs, secrets, `.env` | crypto / secrets reqs |

Plus a policy knob: **always-include MUST** requirements whose category is
implicated by *any* security-sensitive file in the diff (conservative — a dev
adding an endpoint should be reminded of the baseline MUSTs for that surface).

**Stage B — LLM relevance confirmation + verification.** The subagent receives
the candidate requirements, the diff, and read-access to the repo. For each
candidate it decides:

- **in-scope?** — does this change actually implicate the requirement? (drops
  false positives from the keyword filter). Out-of-scope candidates are recorded
  with `status: NOT_APPLICABLE` and a one-line reason; they never gate.
- if in-scope → assign `PASS / PARTIAL / FAIL / UNVERIFIABLE` against the
  **post-change** state of the code, with evidence `file:line`, a one-line
  finding, a code-aware fix, and effort `S/M/L` — identical to the audit skill's
  Step 2 model (reuse `agents/shared/` contracts for evidence + prose style).

**Stability tradeoff (documented, not hidden):** Stage A is deterministic; Stage
B's PASS/FAIL judgement is LLM and therefore not bit-stable across runs. We
mitigate at the *gate*, not the analysis: the gate (§6) fires only on
unambiguous `FAIL` of an in-scope requirement at/above the priority floor.
`PARTIAL`/`UNVERIFIABLE` are surfaced but do **not** block by default, so
borderline LLM variance cannot flap a build red/green. Teams that want stricter
gating opt in via `--gate-on partial`.

---

## 5. Subagent contract — `agents/appsec-reviewer.md`

Frontmatter (mirrors the roster convention; `model: sonnet` pinned for the
drift guard, runtime override via dispatch `MODEL_ID`):

```yaml
---
name: appsec-reviewer
description: "Verifies a code change (diff) against the in-scope security requirements. Reads .verify-diff.json + .requirements.yaml, selects the triggered requirement subset, grades each PASS/PARTIAL/FAIL/UNVERIFIABLE/NOT_APPLICABLE against the post-change code with file:line evidence + code-aware fix, and writes .requirements-verification.json. Does not decide the gate — that is requirements_gate.py."
tools: Read, Grep, Bash, Write
model: sonnet
maxTurns: 40
---
```

**Inputs (invocation prompt — Group A stable → B scalars → C volatile paths, per
the caching discipline in AGENTS.md):**

- `REPO_ROOT`, `OUTPUT_DIR` (stable)
- `PRIORITY_FLOOR` (default `MUST`), `MODEL_ID`, `MAX_REQUIREMENTS` cap (scalars)
- `DIFF_FILE` = `$OUTPUT_DIR/.verify-diff.json`,
  `REQUIREMENTS_YAML` = `$OUTPUT_DIR/.requirements.yaml` (volatile paths)

**Procedure:** (1) startup log via `shared/logging-standard.md` (agent
`requirements-verifier`); (2) load catalog + diff; (3) Stage-A candidate filter;
(4) Stage-B per-requirement relevance + verdict; (5) write JSON + console
summary. Reuses the evidence/prose/secret-handling shared contracts.

**Failure modes** (mirror evidence-verifier discipline): missing/malformed diff
or catalog → log `AGENT_ERROR`, write an empty verdict with
`summary.in_scope: 0`, exit cleanly (the gate then treats it as a usage error,
exit 2). Turn-budget exhaustion → write what's done, mark remaining candidates
`UNVERIFIABLE`, emit `BASH_WARN`.

**What it is NOT:** not a full-repo audit (scope is the diff), not a threat
modeler, not the gate decision-maker, not a code-style reviewer.

---

## 6. Output contract

### 6a. Verdict fragment — `.requirements-verification.json`

New schema `schemas/fragments/requirements-verification.schema.json`:

```json
{
  "version": 1,
  "generated_at": "<ISO 8601 UTC>",
  "model_id": "sonnet",
  "base_ref": "origin/main",
  "priority_floor": "MUST",
  "requirements_source": "remote|cached",
  "summary": {
    "changed_files": 0,
    "candidates": 0,
    "in_scope": 0,
    "pass": 0, "partial": 0, "fail": 0, "unverifiable": 0, "not_applicable": 0,
    "gating_failures": 0
  },
  "results": [
    {
      "id": "SEC-SQL",
      "category": "SEC-SECURE_DATA_HANDLING",
      "priority": "MUST",
      "status": "FAIL",
      "in_scope": true,
      "evidence": [{ "file": "src/routes/search.ts", "line": 23 }],
      "finding": "raw request input reaches sequelize.query() at line 23",
      "fix": "bind the term: sequelize.query(sql, { replacements: { term } })",
      "effort": "M",
      "url": "https://asr.int.example.com/scg/...#sec-sql",
      "gating": true
    }
  ]
}
```

`gating` is `true` when `in_scope && status == FAIL && priority >= floor`.
The agent sets it per its own assessment; `requirements_gate.py`
**recomputes it deterministically** from `status`/`priority`/`in_scope` and is
the authority — the agent's value is advisory/diagnostic only.

Validation wired into `validate_fragment.py` (or a dedicated
`scripts/validate_requirements_verification.py`), per the schema-change
bidirectional rule (AGENTS.md §4).

### 6b. Readable console summary (the "lesbare Ausgabe" half)

Reuse the audit skill's console grammar verbatim so the two tools read alike:
criticality dots (`●`/`○`), the `[FAIL]/[PARTIAL]` blocks, ANSI palette,
`NO_COLOR` honoring. Header reframed for the diff:

```
AppSec Requirements — Change Verification
Base   : origin/main..HEAD   (7 files changed)
Source : https://asr.int.example.com (remote)
Scope  : 4 in-scope of 9 candidate requirements

Result
  ● FAIL          1   (1 gating)
  ● PARTIAL       1
  ● PASS          2
  ○ UNVERIFIABLE  0

Open (in-scope) Requirements
  ● [FAIL] MUST  SEC-SQL  Parameterized SQL Queries
  Finding : raw request input reaches sequelize.query() in src/routes/search.ts:23
  ...
```

### 6c. Gate / exit codes — `scripts/requirements_gate.py`

Deterministic, LLM-free:

| Exit | Meaning |
|---|---|
| `0` | advisory mode (always 0), **or** gate mode with zero gating failures |
| `1` | gate mode **and** ≥1 in-scope `FAIL` at/above `PRIORITY_FLOOR` (or `PARTIAL` too under `--gate-on partial`) |
| `2` | usage / load error (no catalog, malformed verdict, empty-on-error) |

The skill calls it last and propagates the code. CI fails the job on `1`.

---

## 7. How dev teams embed it (both workflows, per the decision)

**Advisory (default) — local dev loop:**
```bash
claude -p "/appsec-advisor:verify-requirements"
```
Prints the readable summary, always exits 0. Non-blocking reminder.

**Gate — CI / PR check:**
```yaml
# .github/workflows/appsec.yml
- name: Verify security requirements on the diff
  run: |
    claude -p "/appsec-advisor:verify-requirements --gate --base origin/${{ github.base_ref }}"
```
Exit 1 fails the check when a MUST requirement regresses on the changed surface.

**Pre-commit (staged):**
```bash
claude -p "/appsec-advisor:verify-requirements --gate --staged"
```

`--requirements <src>` / `--org-profile` / `--preset` / `--no-org-profile` carry
through to the shared resolver exactly as in the audit skill (same flags, same
fail-closed semantics).

---

## 8. Skill outline — `skills/verify-requirements/SKILL.md`

Thin orchestrator (no inline grading — it dispatches the subagent):

1. `--help` early-exit block (verbatim usage).
2. Parse flags: `--gate`, `--gate-on must|partial` (default `must`), `--base <ref>`,
   `--staged`, `--priority-floor`, requirements-source flags (reused), `--md/--json/--save`,
   reject unknown flags (hard fail, exit 2) — same discipline as the audit skill.
3. Resolve plugin root + org profile + requirements source; run
   `fetch_requirements.py` fail-closed gate → `.requirements.yaml`.
4. Compute the diff sidecar `.verify-diff.json` (git). Empty diff → exit 0, no dispatch.
5. Dispatch `appsec-reviewer` with the Group A/B/C input ordering.
6. Run `requirements_gate.py` → exit code. In `--gate` mode propagate; in
   advisory mode always exit 0 but still print the gating count.
7. Optional `--md/--json/--save` writes under `docs/security/` reusing the audit
   skill's report format (open + gating requirements only).

---

## 9. Impact checklist (the bidirectional-contract surface — AGENTS.md §4/§4f)

| Touch | Action |
|---|---|
| **New agent** `appsec-reviewer.md` | add; register in AGENTS.md **roster** (drift-guarded by `tests/test_agent_definitions.py::TestAgentsMdDocDrift`) — note it is **standalone**, *not* in the create-threat-model Phase map |
| **Agent-definitions drift test** | `tests/test_agent_definitions.py` pins `model: sonnet` + turn budget for every agent → add the new file's expected row |
| **New schema** | `requirements-verification.schema.json` → register in `check_fragment_registry.py`, add to `docs/internal/contracts/schema-invariants.md`, wire a validator |
| **New skill** | `skills/verify-requirements/` (+ `config.json` if needed); confirm skill-discovery tests pick it up |
| **`requirements_gate.py`** | new script; add to `data/required-permissions.yaml` **only if** it introduces a command not already under `Bash(*)` — it does not (pure Python + git). Read/Write of `$OUTPUT_DIR/**` + Read `$REPO_ROOT/**` are already permitted. **Net: no new permission entries expected** — re-verify at implementation. |
| **Logging** | route all log lines through `scripts/event_log.py` (agent id `requirements-verifier`); no hand-rolled f-strings (§13) |
| **Tests** | `tests/test_requirements_verification_schema.py` (schema round-trip), `tests/test_requirements_gate.py` (exit-code matrix: advisory always-0, gate fail on MUST FAIL, exit 2 on malformed), `tests/test_verify_requirements_skill.py` (flag parsing / unknown-flag fail / empty-diff no-dispatch) |
| **Stage-A signal table** | finalize category mappings against the **live** catalog category IDs (see `data/appsec-requirements-fallback.yaml`) — the §4 table is illustrative |

---

## 10. Open questions for review

1. **Skill name:** `verify-requirements` vs `verify-implementation` vs
   `requirements-check`. `verify-requirements` chosen for symmetry with
   `audit-security-requirements`. OK?
2. **Default gate priority floor** = `MUST`. Should `SHOULD` be gateable only via
   `--priority-floor should`, or never gate on SHOULD? (Current design: opt-in.)
3. **Relevance Stage A** — keep the deterministic keyword pre-filter as the
   stability anchor, or let the LLM see the *whole* catalog and self-select?
   (Design favors pre-filter for CI determinism + token cost; whole-catalog is
   simpler but flakier and pricier.)
4. **`--md/--json` reports** — reuse the audit skill's exact format, or a
   diff-oriented variant? (Design: reuse, scoped to in-scope/gating reqs.)
5. **Reuse by `create-threat-model`** — out of scope for v1, but the contract is
   designed so Phase 8b *could* dispatch this on the changed surface later.

---

## 12. Delivered artifacts (2026-06-07)

- `agents/appsec-reviewer.md` — subagent (Sonnet, 40 turns, INTERNAL).
- `skills/verify-requirements/SKILL.md` — thin entry point (--help, flag parse,
  shared requirements fetch, diff build, dispatch, gate).
- `scripts/build_verify_diff.py` — deterministic diff sidecar builder.
- `scripts/requirements_gate.py` — deterministic exit-code authority.
- `schemas/requirements-verification.schema.json` — verdict schema (top-level,
  **not** a render fragment → not in the fragment registry).
- Drift guards updated: AGENTS.md roster + `tests/test_agent_definitions.py`
  (`EXPECTED_MAX_TURNS` + `INTERNAL_AGENTS`); `.gitignore-template` += the two
  new intermediate dot-files.
- Tests: `tests/test_requirements_gate.py` (exit-code matrix incl.
  advisory-ignores-agent-flags), `tests/test_requirements_verification.py`
  (schema validity + real-git diff smoke).
- Permissions: **no new entries needed** (git + python under `Bash(*)`;
  Read `$REPO_ROOT/**` + Read/Write `$OUTPUT_DIR/**` already allowed) —
  `tests/test_check_permissions.py` green.

## 11. Non-goals (v1)

- Not a full-repo audit (that's `audit-security-requirements`).
- Not threat modeling / STRIDE.
- The agent does not decide the gate or write the final report markdown.
- No schema relaxation to make borderline diffs pass (AGENTS.md §12).
