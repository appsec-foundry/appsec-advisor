# Run defects — juice-shop, 2026-07-24

Six defects surfaced by a full `--cheap-stride` assessment of juice-shop
(run `c27f6fdc`, 11 components, 74 threats). The run produced a complete,
QA-clean `threat-model.md`; none of these blocked the deliverable, which is
precisely why they had gone unnoticed. Each entry records the evidence, the
root cause, and the fix. Regressions: `tests/test_run_defect_fixes_2026_07_24.py`.

---

## 1. Zone vocabulary — 9 of 11 components fell off-vocabulary

**Evidence.** `build_stride_dispatch_manifest.py` emitted `ZONE_DRIFT` for 9
components: 7 backend units tagged `['server']`, plus `ci-cd-pipeline` tagged
`['ci']`. Only `frontend-spa` (`browser`) and the two reconciled components
carried canonical zones.

**Root cause.** `deployment_zones[]` has no enum — `schemas/fragments/components.schema.json:58-63`
declares `items: {type: string}` and lists the vocabulary only in prose. The
Phase-3 prompt (`agents/phases/phase-group-architecture.md:865`) already states
the rule in the strongest available terms ("MUST use canonical access-zone
tokens only … an invented label silently disables the exposure/ci-cd signal"),
and the analyst violated it anyway by writing the *tier* (server vs browser)
into the *zone* field. Prompt hardening was already maxed out, so the lever had
to be deterministic.

**Impact.** No lost coverage — the exposure-unknown fail-safe included every
component anyway. The concrete losses are the inert signal itself: the `ci` tag
lost its zonal supply-chain classification and `ci-cd-pipeline` survived only
because `_is_cicd` falls back to text hints, and no component could be proven
internal (hence none sheddable at the ceiling).

Measured after the fix: `ZONE_DRIFT` 9 → 0 on the same inputs.
`EXPOSURE_CAP_LIFT` still fires, and **correctly so** — all 11 components earn
selection on a non-zonal criterion (auth, frontend, file-upload, AI/LLM,
real-time, crown-jewel, data-store, ci-cd), so the ceiling lift is a genuine
"this repo has 11 security-relevant components" signal, not a consequence of
the drift. Do not expect this fix to silence it.

**Fix.** Extend the recognised vocabulary the way `EXPOSED_ZONES` was already
extended for synonyms (`build_stride_dispatch_manifest.py:126-131` documents the
same precedent):

* `RUNTIME_ONLY_ZONES` += `server`, `server-side`, `backend`, `app-server`,
  `application-server`, `service`, `worker`, `daemon`, `on-premise`, `on-prem`,
  `cloud`. These say *where it runs*, never *how reachable it is*, so they are
  recognised but remain **exposure-unknown** — the fail-safe is preserved and
  they can never be mistaken for "proven internal".
* `CICD_ZONES` += `ci`, `cicd`, `ci-cd`, `ci-runner`, `build`, `build-server`,
  `pipeline`, `release-pipeline` — restores the zonal CI signal.

Genuinely invented labels (`application-zone`) still drift, so the warning keeps
its meaning.

---

## 2. `Rate Limiting` re-routed out of §6.11 by a comma

**Evidence.**
`CONTROL_TAXONOMY_DRIFT domain ('Rate Limiting'): 'Operations, Runtime and Supply Chain Controls' -> 'Identity and Authentication Controls'`.
Three sibling drifts in the same run were benign comma-stripping; this one moved
a control to a semantically different §6 section.

**Root cause.** Two compounding defects.

1. The canonical §6 titles in `data/sections-contract.yaml:1033-1035` are
   **comma-free**, but the plugin's own deterministic producer
   (`assess_supply_chain_controls.py:985`) hardcoded the comma form, and the
   Stage-1 prompt (`phase-group-architecture.md:1414`) listed all three
   compound domains with commas. Producer and enforcer disagreed on canonical
   spelling.
2. `enforce_control_taxonomy.py` builds `known_domain_strings` comma-free, so
   the comma form matched nothing; the guard at `:407`
   (`current_norm not in known_domain_strings`) therefore treated a perfectly
   valid domain as *unknown* and let `_infer_domain` re-route on the control
   name alone. `_DOMAIN_TOKEN_INDEX:167` maps the bare tokens `{rate, limiting}`
   unconditionally to IAM, even though the catalog deliberately splits
   `Authentication Rate Limiting` (IAM) from `API Rate Limiting` (Infra).

**Fix.** All three layers:

* `_strip_domain_commas()` + a comma-normalisation branch that mirrors the
  existing suffix branch — a comma-only difference is stylistic, normalised in
  place, never a re-route. Guarded by the same
  `session_primitive_reroute` / `crypto_primitive_reroute` exceptions, so the
  intentional `Password Hashing → §6.9` and `JWT → §6.3` moves still fire.
* The producer now emits the canonical comma-free domain.
* The prompt lists the canonical spellings and says why commas break routing.

---

## 3. `SESSION_ABORTED_MIDRUN` fired on every stop — 11 false WARNs

**Evidence.** 11 `WARN … SESSION_ABORTED_MIDRUN phase=N reason=unknown` on a
run that completed successfully; `stop=unknown` in **325 of 325** trace records;
`MAX_TURNS` logged **0** times despite two abuse verifiers demonstrably hitting
their ceiling.

**Root cause.** `agent_logger.py` read `data.get("stop_reason", "unknown")`, but
the Claude Code `Stop`/`SubagentStop` payload carries no `stop_reason` key at
all. Every consumer downstream was therefore blind:

* `_CLEAN_STOP_REASONS = {"end_turn", "stop_sequence"}` never matched, so
  `_mark_checkpoint_aborted_if_dirty()` ran on *every* stop — emitting the WARN
  **and rewriting the live `.appsec-checkpoint` to `status=aborted` mid-run**,
  which has previously misled operators into reporting a dead agent.
* The `reason == "max_turns"` branch was unreachable, so genuine turn-ceiling
  terminations were invisible (see defect 6).

A signal that fires 100 % of the time carries no information.

**Fix.** Derive the reason from the transcript, which *does* carry it. Measured
on this run's transcripts, the terminal `stop_reason` of the last assistant
record discriminates cleanly:

| session | last `stop_reason` |
|---|---|
| AC-T-001, AC-T-005, STRIDE frontend (all finished) | `end_turn` |
| AC-T-002, AC-T-003 (both cut off mid-grep) | `tool_use` |

`_stop_reason_from_transcript()` supplies it only when the payload omits it, and
returns `""` (→ the previous `unknown` fallback) when the transcript is missing
or unreadable. Clean stops now short-circuit before the checkpoint rewrite.

**Known residual risk.** If the Stop hook ever fires before the harness has
flushed the final assistant record, the last value read would be `tool_use` and
the run would log the same false WARN it logs today. The failure mode therefore
degrades to the current behaviour and never below it. Verified empirically
against five transcripts from this run (three clean → `end_turn`, two cut off →
`tool_use`); no race was observed.

---

## 4. `wall_secs=?` for every dispatched sub-agent

**Root cause.** `_record_dispatch_time()` keys the timestamp on the **parent**
session id in `handle_pre_tool_use` (`agent_logger.py:1863`), but
`_take_dispatch_time()` redeems it with the **child** session id at Stop
(`:2180`). The two never match for a dispatched sub-agent, so `wall_secs` kept
its `"?"` initialiser; the only numeric values in the log came from the parent
session stopping on itself.

**Fix.** Also index the dispatch under the agent short name — derived
identically at both ends — as `agent:<short>:<ts>`, and redeem the oldest
pending entry for that agent when the sid lookup misses. FIFO matching is exact
for equal-duration siblings and bounded otherwise; a parallel fan-out of 8
STRIDE analyzers keeps one entry per dispatch.

---

## 5. Stage 2 threw away two finished renders on a misleading receipt

**Evidence.** Both specialist renderers succeeded (`security-architecture.md`,
`ms-verdict.json` and three siblings all on disk). `orchestration_controller.py next`
nonetheless returned `Stage-2 render fragments incomplete; retry 1/2`, and a full
`appsec-threat-renderer` re-dispatch redid ~9 minutes of work already done.

**Root cause.** `_compose_if_ready()` is a twelve-step pipeline (4 mitigation
helpers → forced pregenerate → conditional MS pregenerate → `compose --strict`
→ prose-fix → autofix → checkpoint) that collapses **every** failure into a bare
`False`, while the caller labels every `False` "render fragments incomplete" —
even though the fragment existence check is only the *first* exit point. The
local `_run` helper captured and discarded all subprocess output, so nothing was
logged. Forensics (`mtime` of the forced-pregenerate outputs) place the abort in
steps 1–4, i.e. a mitigation gate, not a missing fragment.

**Fix.**

* `_block(step, detail)` records the failing step and its captured stderr to
  `.compose-blocked.json`; every mandatory step routes through `_step()`.
* The caller reads it and names the real blocker; "fragments incomplete" is now
  reserved for the existence check alone.
* `ms-verdict.json` joins the deterministic floor in the conditional MS
  pregenerate pass. It is the one MANDATORY MS fragment that compose hard-fails
  without, and neither `prepare_stage2` nor this pass regenerated it — a latent
  cause of exactly this message with a genuine gap.

---

## 6. Abuse-case matcher bound a step to an unrelated same-family finding

**Evidence.** `AC-T-003` step 2 — *"Role claim trusted from token without
re-fetch"*, chain CWE-863 — was matched to **T-016 "Discount Cap Bypass via
Prompt Injection in generateCoupon Tool"** (CWE-862, `routes/chat.ts:179`). The
verifier immediately recognised the mismatch ("chat.ts:179 isn't a role trust
point"), searched for the real thing, and hit its ceiling. Both `AC-T-002` and
`AC-T-003` shipped step 2 as an empty-excerpt `inconclusive`.

**Root cause.** Reproduced exactly: the step's sink patterns are three
case-sensitive code shapes (`token\.role`, `decoded\.role`, `req\.user\.role`)
plus the family alternation `CWE-(863|862|266|269)`. **No code pattern matched
any finding.** Four unrelated findings all carry CWE-862 and all scored exactly
5 on the alternation alone — a four-way tie broken by *finding list order*.
T-016 won because it came first.

`_CONTEXT_DEPENDENT_CWES` exists for this class of problem but is a hardcoded
CWE denylist that did not contain 862/863/266/269 — whack-a-mole. Worse,
`has_mechanism_match` is misnamed: it is set for a plain CWE-field hit too, so
it could not be used to detect "no real mechanism evidence".

**Fix — structural, not another denylist entry.**

* New `has_non_cwe_match`: true only when a **non-CWE** pattern matched.
* `exact_cwe`: the catalog declares the CWE each chain step is about; a finding
  carrying exactly that CWE is the intended target. Added to the sort key above
  the arbitrary list-order tie-break.
* A match resting on neither (`weak`) that **ties with another weak candidate**
  is genuinely ambiguous → the binding is dropped rather than guessed, and the
  step falls through to the source probe.

Verified against the real run: `AC-T-003` s2 → no match (correct, juice-shop
does not trust a token role claim); `AC-T-002` s1 keeps T-009 via exact CWE-639;
and two previously-wrong links improved — `AC-T-001` s1 `T-001` (localStorage) →
`T-029` (XSS) for a stored-XSS step, `AC-T-003` s1 `T-005` (CWE-287) → `T-006`
"Insecure JWT Verification" (CWE-347, the step's own CWE).

### 6b. The source probe quoted the assessment's own output back at itself

The fallback returned `docs/security/.abuse-case-matches.json:331` as "source
evidence" for the role-claim sink. `_is_runtime_surface_evidence()` — whose
`_NON_RUNTIME_EVIDENCE_PREFIXES` already lists `docs/` — existed but was never
applied in `_source_probe`. Now it is.

With that filter alone the probe still returned an Arabic i18n bundle matching
the prose pattern `(?i)(role|privilege) escalation`. A sink probe must search
for **code**, so it now compiles only code patterns: catalog prose patterns are
authored `(?i)` precisely because they target English text, while code patterns
are case-sensitive. Bare identifiers such as `innerHTML` remain probeable —
`_pattern_specificity` would have mis-classified those as prose, which is why
the `(?i)` marker, not the weight, is the discriminator.

### 6c. Turn budget

`maxTurns` 28 → 36. Measured need on this run: successful verifiers used 11–25
tool uses (including a 3-step chain at 25); the two cut-off ones were at 28 and
33 and still mid-grep. The per-step write-first contract in the agent body —
which exists for this exact failure and has now missed three times
(2026-06-12, 2026-06-13, 2026-07-24) — gained an explicit budgeting rule:
a reasoned `inconclusive` is a legitimate outcome, an unreasoned blank is not.
