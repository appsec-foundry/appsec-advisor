# Proposal — Dev Security Helper (layered)

**Status:** design + partial implementation (2026-06-07). Supersedes the framing
of `proposal-requirements-verifier-subagent.md`, which becomes **Layer 2** here.

**Goal (user, verbatim sense):** give development teams an *easy* way to
automatically check the code they write against their **company requirements if
available, otherwise against general best practices** — as **real help for
developers, not a compliance/audit gate.**

**Confirmed design decisions (AskUserQuestion, 2026-06-07):**
- Deliver **both layers** — proactive help *while coding* **and** an on-demand
  check — over a **shared** best-practices baseline.
- The compliance gate stays, but **strictly opt-in** — default is help, not block.

---

## The reframe that drives this

What was first built (`verify-requirements` + `requirements-verifier`) was, in
its DNA, a **compliance gate**: fail-closed (no catalog → abort), exit-code
centric, `--gate` blocks the merge. That answers *"did this code pass the audit?"*

The actual goal is **a helper**: it should *help a developer build secure code*,
proactively and with zero friction, and only block if a team deliberately asks
it to. The content the verifier already produces — *what is wrong + a code-aware
fix + effort* — is genuinely helpful; what was mis-framed is the **wrapper**
(fail-closed, gate-as-default). This proposal keeps the helpful content and
re-frames everything around *help first*.

---

## Architecture — three layers over one foundation

```
        ┌──────────────────────────────────────────────────────────┐
 L0     │ Foundation: requirements resolution                       │
        │   company catalog (SEC-*) if configured                   │
        │   ELSE bundled best-practices baseline (BP-*)             │
        │   → never refuses to help                                 │
        └───────────────┬───────────────────────┬──────────────────┘
                        │                        │
        ┌───────────────▼─────────┐   ┌──────────▼───────────────────┐
 L1     │ Coach (proactive)       │   │ L2  On-demand check           │
        │ UserPromptSubmit hook   │   │ /verify-requirements skill    │
        │ injects relevant rule   │   │ + appsec-requirements-verifier│
        │ guidance WHILE coding   │   │ advisory by default,          │
        │ non-blocking            │   │ --gate strictly opt-in        │
        └─────────────────────────┘   └───────────────────────────────┘
            "help me write it right"      "check what I just changed"
```

### Layer 0 — Foundation: company-or-best-practices resolution  ✅ DONE

- `data/appsec-bestpractices-baseline.yaml` — **NEW**, vendor-neutral,
  OWASP-derived (9 categories, 20 reqs). Same YAML shape as
  `appsec-requirements-fallback.yaml`, so every consumer (resolver, coach,
  check) reads it unchanged.
- **Requirement IDs are opaque, org-defined strings — no fixed prefix.** The
  company-vs-best-practices distinction is read from the catalog's top-level
  `source:` field, **not** inferred from an id prefix. The bundled baseline
  happens to use `BP-*` and our sample company catalog uses `SEC-*`, but those
  are just the ids those two files chose; a company catalog may use any scheme
  (`ACME-AUTH-01`, …). Nothing in the schema, validators, agent, skill, or hook
  enforces a prefix. Code/tests that need to know which catalog is active key off
  `source:`, and id-membership is resolved by set-intersection with the loaded
  catalog (so any scheme works).
- `scripts/fetch_requirements.py` — **NEW opt-in flag** `--fallback-baseline
  <path>`: on the `cache_fallback` path, if no company source/cache loads, write
  the baseline instead of aborting. An **explicit** `--requirements` failure
  still aborts (fail-closed, step 1) — a deliberately-named source must work.
  Other callers (create-threat-model / audit) never pass the flag → unchanged.

Net effect: "company reqs if available, else best practices, never refuse" is
now true at the foundation, for both layers.

### Layer 1 — Proactive in-session guidance  ✅ ALREADY EXISTS (corrected 2026-06-07)

**Correction:** an earlier draft called this an unbuilt "Coach". It is in fact
**already built, wired, and tested** — it is the *security-steering* hook:
- `hooks/hooks.json` → registers `UserPromptSubmit` → `scripts/security_steering.py`
- `scripts/security_steering.py` — matches the prompt against topic triggers,
  injects a secure-by-default baseline + topic guidance + the applicable
  requirement texts. Non-blocking, never calls the model itself
  (`scripts/security_steering.py`).
- `hooks/steering_keywords.json` — the topic map: `topics.<name>.{triggers,
  guidance, requirements:[SEC-…]}` (e.g. `auth → ['SEC-API-AUTH']`).
- `tests/test_security_steering.py` — covered.

So Layer 1 needs **no new build** — only two wiring fixes (below) to honour the
"best-practices fallback" goal and to become the single relevance source.

**Naming:** the dev-facing helper is branded **`appsec-reviewer`** (not "coach").
See the Naming note at the end.

### The encapsulation — one relevance source for both layers  ⏳ THE GAP TO FIX

`hooks/steering_keywords.json` is *already* a structured topic→requirement map.
The verified duplication (file:line):

- **Gap A — verifier re-describes relevance in prose.** `agents/appsec-requirements-verifier.md:93–108`
  hand-writes "example signals" (keyword→category) instead of consuming
  `steering_keywords.json`. **Fix:** the verifier's Stage-A reads the shared map
  (`topics.<name>.triggers` → which topics the diff touches →
  `topics.<name>.requirements` → candidate requirement ids). One map, two
  consumers (steering hook + verifier). This is the "an einer Stelle gekapselt"
  the design should have.
- **Gap B — best-practices baseline missing from the steering fallback.**
  `scripts/security_steering.py:78–79` resolves requirements from
  `.cache/requirements.yaml` then `data/appsec-requirements-fallback.yaml` only —
  **not** the new `data/appsec-bestpractices-baseline.yaml`. So the proactive
  layer does not degrade to best-practices when no company catalog exists. **Fix:**
  append the baseline to `requirements_source.paths` (and the script default) so
  L1 matches L0/L2's "company else best-practices" behaviour. The BP-* topics
  also need adding to `steering_keywords.json` so baseline ids resolve.

**Why this is the right encapsulation (not "L1 calls L2"):** the proactive hook
(remind the rule, pre-prompt, no model call) and the on-demand review (grade the
diff) are different operations with different latency budgets — they must not be
welded together. What they legitimately *share* is the **relevance map** and the
**catalog (L0)**. Encapsulating those two is the correct single-source-of-truth.

### Layer 2 — On-demand check: "review what I just changed"  ✅ DONE (re-framed)

The diff-scoped check, now **advisory-first**:
- `skills/verify-requirements/SKILL.md` + `agents/appsec-requirements-verifier.md`
  + `scripts/build_verify_diff.py` + `scripts/requirements_gate.py` +
  `schemas/requirements-verification.schema.json` (all from Layer-2's own
  proposal; see `proposal-requirements-verifier-subagent.md`).
- **Re-framed for help:** default advisory (always exit 0), zero-config (Layer-0
  fallback means it works with no setup), output = concrete *what-to-fix + how*.
- **Gate strictly opt-in:** `--gate` turns it into a CI/merge gate
  (`requirements_gate.py` owns the exit code). Teams that want enforcement get
  it; nobody hits a block by default.

### Layer 3 — `appsec-reviewer` CLI wrapper (clean CI entry)  ⏳ NEW (requested)

Dev teams want to embed this in CI as a **plain command that emits a report
artifact**, not as `claude -p "/skill …"`. Target invocation (user-supplied):

```yaml
security_review:
  stage: test
  script:
    - appsec-reviewer review --diff origin/main --output security-review.md
  artifacts:
    paths:
      - security-review.md
```

- **Artifact:** a thin executable `bin/appsec-reviewer` (on the team's PATH) with
  one subcommand `review`. Flags mirror the user's snippet: `--diff <ref>`
  (→ skill `--base`), `--output <file>` (→ rendered Markdown report), plus
  pass-throughs `--requirements <src>`, `--gate` / `--fail-on`.
- **What it does (deterministic wrapper):**
  1. `claude -p "/appsec-advisor:verify-requirements --base <diff> …"` headless
     (`--permission-mode bypassPermissions`, auth via `ANTHROPIC_API_KEY` or
     subscription) → produces `.requirements-verification.json`.
  2. A deterministic Python renderer turns that JSON into the `--output`
     Markdown (`security-review.md`) — reuses the audit report format. (This is
     the report renderer that was "skill Step 6 / optional" — now a first-class
     artifact.)
  3. Exit 0 by default (advisory — the snippet just collects the artifact);
     `--fail-on must` / `--gate` flips to the `requirements_gate.py` exit code
     for teams that want the job to fail.
- **Relationship to `run-headless.sh`:** same headless mechanics (auth detect,
  permission mode, exit propagation) but a clean, narrow command surface scoped
  to the review use case. Either share its internals or call it underneath.

---

## How dev teams use it (mapped to the layers)

| Need | Layer | How |
|---|---|---|
| Help *while* I write security-sensitive code | L1 `appsec-reviewer` steering hook | enable once (`APPSEC_COACH=1` / config); automatic, non-blocking |
| "Review the change I just made" (interactive) | L2 | `/appsec-advisor:verify-requirements` — advisory |
| CI report artifact on every MR (not blocking) | L3 CLI | `appsec-reviewer review --diff origin/main --output security-review.md` |
| Hard PR/merge enforcement (teams that want it) | L3 + gate | add `--fail-on must` (or L2 `--gate`) |
| No company catalog at all | L0 | automatic best-practices fallback (`BP-*`) — nothing to configure |

The **easy default** is: enable the steering hook, and run the `appsec-reviewer`
CLI in CI to drop a `security-review.md` on each MR. Blocking is opt-in only.

---

## Delivered vs pending (2026-06-07)

**Delivered + tested (green):**
- `data/appsec-bestpractices-baseline.yaml` (vendor-neutral, BP-*).
- `fetch_requirements.py --fallback-baseline` (+ `verify-requirements` caller).
- `verify-requirements` skill re-framed to helper / advisory-default / fallback.
- Layer-2 verifier + gate + diff-builder + schema (from the Layer-2 proposal).
- Tests: baseline validity, fetch fallback, explicit-source-still-fail-closed,
  gate exit-code matrix, schema, diff smoke.

**Already existed (corrected — not a new build):**
- **Layer 1** proactive steering = `scripts/security_steering.py` +
  `hooks/steering_keywords.json` + `hooks/hooks.json` (`UserPromptSubmit`) +
  `tests/test_security_steering.py`. Built, wired, tested.

**Pending (the actual work):**
- **Gap A** — wire the verifier's Stage-A to consume `hooks/steering_keywords.json`
  (shared relevance map) instead of prose signals. `agents/appsec-requirements-verifier.md:93–108`.
- **Gap B** — add `data/appsec-bestpractices-baseline.yaml` to
  `security_steering.py` `requirements_source.paths` + add BP-* topics to
  `steering_keywords.json` so the steering hook also degrades to best-practices.
- **Layer 3** — the `bin/appsec-reviewer` CLI wrapper + the deterministic
  JSON→Markdown report renderer (the `--output security-review.md` artifact).
- Stage-A live tuning against real catalog category ids (Layer-2 carry-over).

---

## Impact / contracts touched

- `fetch_requirements.py`: new optional flag + new `--caller` choice
  `verify-requirements` (graceful in `resolve_requirements_source.resolve` →
  `enabled=True` for unknown callers). Surgical — no behavior change for existing
  callers.
- New data file is not a render fragment and not enumerated by any schema test.
- L1 steering hook already exists → wiring fixes only; if its
  `requirements_source.paths` change, re-check `tests/test_security_steering.py`.
- L3 CLI wrapper is a new executable invoking `claude -p` → no new plugin
  permission entry (it runs outside the plugin sandbox, like `run-headless.sh`),
  but document auth/permission-mode prerequisites.

## Naming

The dev-facing helper is branded **`appsec-reviewer`** (per user decision — not
"coach"). Open point: the CI snippet used the binary name `security-review-agent`;
this proposal standardises on `appsec-reviewer` to match the plugin's `appsec-`
prefix and avoid collision with the existing `appsec-architect-reviewer` agent.
The internal artifacts keep their accurate mechanism names
(`security_steering.py` = the L1 hook; `appsec-requirements-verifier` = the L2
grader); `appsec-reviewer` is the umbrella product name + the L3 CLI binary.
**Confirm:** binary name `appsec-reviewer` vs `security-review-agent`, and
whether to physically rename the shipped `security_steering.py` (invasive:
script + config keys + tests + docs) or keep it as the internal mechanism under
the `appsec-reviewer` brand.

## Non-goals
- Not a compliance/audit tool (that is `audit-security-requirements`).
- The gate never blocks by default.
- The baseline is a floor, never an override of a configured company catalog.
