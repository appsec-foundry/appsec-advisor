# Proposal — a mandatory STRIDE check catalogue with a deterministic coverage receipt

**Status:** OPEN / design. Analysis only; no code until reviewed. Anchors are
`file:line`, re-verified against `e4a7eb19` on 2026-08-15.

## What triggered this

The stated direction is to move the plugin away from a SAST-shaped output
(findings with `file:line`, CWE, CVSS, SARIF) toward a threat-model-shaped one.
A threat model's credibility rests on stated coverage — what was examined, what
was found, what was ruled out, what could not be decided. A scanner's rests on
findings alone. The catalogue below is the mechanism that produces the first.

Stated coverage alone still leaves a scanner, just an honest one. What separates
a threat model is that severity comes from what the business loses, and that
misuse of a working feature counts as a threat. Blocks A and C exist for that.

## What "category complete" means today

STRIDE per component is dispatched with all six letters mandatory, including in
the cheap-stride tier (`scripts/build_stride_dispatch_manifest.py:1251`). What
"complete" means is asserted by the analyzer, not established:

- The analyzer pre-seeds `.stride-<COMPONENT_ID>.json` with all six letters in
  `skipped_categories` and clears them on completion
  (`agents/appsec-stride-analyzer.md:213`, `agents/appsec-stride-analyzer-v2.md:262`).
- The wave gate accepts a component on the artifact's own word: `partial: false`,
  no `seed_only`, empty `skipped_categories` (`scripts/stride_dispatch_waves.py:292`).
  Every one of those fields is written by the analyzer being judged.
- The literal log line `All six STRIDE categories complete`
  (`scripts/check_stride_dispatch.py:321`) is not that gate. It feeds
  serial-dispatch detection, sits there as an alternative to `AGENT_END`, and no
  producer emits the string — the analyzer logs `Completed all six STRIDE
  categories for <COMPONENT_NAME>` (`agents/appsec-stride-analyzer-v2.md:264`).
- Per-category coverage is judged post-hoc and only in the dev-only eval skill
  (`scripts/eval_threat_model.py:64`, `:310`; `agents/appsec-eval-judge.md:56`).

So a component can produce zero Repudiation threats because nothing is wrong,
because the model ran out of turns, or because it never looked — and the
artifact records the same thing in all three cases.

## The proposal

Keep STRIDE as the spine and bind each letter to a fixed catalogue of checks.
Each check declares applicability rules, the signals and paths to inspect,
explicit pass/fail conditions, false-positive exclusions, and the evidence
required to justify its outcome. Each returns exactly one of `passed`, `failed`,
`not_applicable`, `not_verifiable`. A category may be reported complete only
when every applicable check carries an outcome, validated against a receipt
rather than asserted in prose.

Four blocks, because they run at different scopes and produce different things.

### A — Business context (once per system, only where declared context exists)

Answers here are weights, not findings. They feed crown-jewel marking, actor
relevance, abuse cases and the severity caps. Without them, block B is a
vulnerability list with guessed severity.

- **CTX-01** Which assets does the system carry, and what is the worst outcome per asset — money, data, outage, regulation, physical safety?
- **CTX-02** Who uses it legitimately, who would gain from abusing it, and with what means?
- **CTX-03** What is the authoritative record here, and what happens if it is wrong without anyone noticing?
- **CTX-04** Which transaction has to be provable afterwards, to a customer or a regulator?
- **CTX-05** What is entrusted to which third party and which internal role, and what does a takeover of either do?
- **CTX-06** How long may this be down, how much data loss is tolerable, and which data may not leave its permitted area?

Source is repository-declared context — README, requirements catalog, `docs/`,
org profile. Absent that, the honest outcome is `not_verifiable` with a reason,
never a guess.

### B — STRIDE (per component)

- **STR-S01** Is every incoming token verified against an expected algorithm and a server-side key, or does the token header get a vote?
- **STR-S02** Does the session get a new id on login and on every change of authentication state, and is it invalidated server-side?
- **STR-S03** How do password reset, MFA reset and support-initiated takeover work, and can an account be taken over without the second channel?
- **STR-S04** How does a service or partner identify itself to this component, and does network position suffice?
- **STR-T01** Does input reach an interpreter — SQL, shell, template, deserializer — without parameterization?
- **STR-T02** Can the caller set fields on write that are not theirs: role, price, owner, status?
- **STR-T03** Are dependencies, images and build artifacts pinned and integrity-checked?
- **STR-T04** Are webhooks, callbacks and messages signature-verified, in constant time, against a server-side key?
- **STR-R01** Do authentication outcomes, authorization denials and administrative state changes reach a log?
- **STR-R02** Does the entry carry the acting identity from the session rather than from the request?
- **STR-R03** Is only the success path logged, or also failure and denied?
- **STR-R04** Does unfiltered input reach the log, and can anyone overwrite or delete logs?
- **STR-I01** Are keys, passwords or tokens present in code, configuration, fixtures or git history?
- **STR-I02** Does a response return more fields or records than the caller's role may see?
- **STR-I03** Do stack traces, internal paths, versions or debug endpoints reach the outside?
- **STR-I04** Is TLS enforced, are sensitive fields protected at rest, and are passwords hashed with a slow KDF?
- **STR-D01** Is there a rate limit and a size limit before the expensive work?
- **STR-D02** Can the caller set filter or limit so that the result set grows without bound?
- **STR-D03** Are uploads, archives, XML or images processed without size, depth and time limits?
- **STR-D04** Does a retry or fan-out amplify one request into many downstream calls without a cap?
- **STR-E01** Is it checked server-side, on every access, that this caller may use this object and this function?
- **STR-E02** Do administrative functions hang on a server-side role rather than a flag from token or client?
- **STR-E03** Is the owner identity part of the query, and does it come from the session rather than a parameter?
- **STR-E04** Is generated or loaded code executed, and inside which boundary?

### C — Abuse of legitimate function (targeting, not a new finding class)

STRIDE has no letter for using a feature exactly as designed, against the
business. Forcing it into one of the six is wrong. These questions name the
function that carries business value; what becomes a finding is a block-B check
pointed at that function. See the reconciliation section below for why they
cannot enter as abuse cases in the shipped sense.

- **ABU-01** Which function earns someone money or advantage when used often, fast, or out of order?
- **ABU-02** Which function releases data in volumes that are permitted individually and a data exfiltration in aggregate?
- **ABU-03** Which function causes cost or effect at third parties — mail, SMS, payments, foreign APIs — and who may trigger it?

### D — LLM-conditional (from PHANTOM-B)

- **LLM-D1** Is a consequential model-driven action bound to an audit record carrying prompt, response and model version? (R)
- **LLM-D2** Which business decision is delegated to the model, and is there human approval before irreversible effect? (E)
- **LLM-D3** Is the only guardrail on a behaviour a prompt instruction rather than an enforced boundary in code? (T)
- **LLM-D4** Which data category reaches the model or a shared context, and is it permitted there? (I)

## Why this fits the existing model

- AGENTS.md already requires exactly this contract of a security check —
  inspected signal, trigger, false-positive exclusions, CWE/severity/type
  mapping, required evidence. Today it binds the deterministic scanners. The
  proposal extends the same contract to the LLM STRIDE pass.
- `not_applicable` as a first-class outcome has precedent: decision SA-1
  (`docs/internal/decisions.md:154`) states that absence of signal yields
  `not_applicable`, never a negative rating, enforced through
  `data/architecture-coverage-rules.yaml`.
- Coverage-gap findings already exist as a class that carries no CVSS, so
  `not_verifiable` has somewhere to go without inventing a finding type.
- Deterministic Python owning validation while agents own discovery and prose is
  the repository's existing split.

## Decisions to make before any code

**1. Check IDs must not collide with report anchors.** `T-NNN` is the threat ID
space and a public report anchor; `M-NNN` and `W-NNN` are likewise taken. A
check called `T-01` is ambiguous in exactly the artifact this is meant to make
more trustworthy. Use a distinct prefix (`STR-T01`).

**2. Applicability is a manifest decision, not a prompt decision.** If the agent
decides which of the 24 block-B checks apply, the receipt is another self-report
and the whole prompt has to carry all of them.
`build_stride_dispatch_manifest.py` already
computes per-component predicates (`_is_auth:250`, `_is_frontend:255`,
`_is_llm:335`, `_is_exposed:420`, combined in `_in_scope:544`). Deriving
applicability there bounds the
prompt to the applicable subset and makes the receipt checkable against an
input the agent did not write.

**3. What `not_verifiable` does to the report.** It is a hypothesis by another
name, and unlinked hypotheses were deliberately removed from the report on
2026-07-03 (`proposal-threat-hypotheses-promotion.md`). The defensible landing
is a coverage statement — this check applied, could not be decided, here is why
— never a finding and never a severity.

**4. Where the receipt lives.** `checks[]` next to `skipped_categories` in
`.stride-<COMPONENT_ID>.json` (`schemas/stride.schema.yaml:105`), with a schema
entry, a validator script, and a blocking gate at the phase boundary. Anything
looser reproduces the self-reported `skipped_categories` that exists today.

**5. Where outcomes surface.** Per-component, per-category coverage is the
threat-model-shaped half of the output. It has to reach the report, or the
catalogue only makes the run more expensive.

**6. How far the configuration layers may go.** Two limits need a ruling before
the resolver exists. Whether `threat_checks.inherit_defaults: false` is offered
at all — for abuse cases it is harmless, here it empties the coverage claim the
catalogue was built to make. And whether an org can mark a check as not
disableable by the repo layer, the way an enterprise actor disable is already
terminal against the repo layer (`schemas/org-profile.schema.yaml` →
`actors.disable`). My reading: offer `inherit_defaults` for block A only, and
let an org mark checks the repo layer cannot disable, because layer 3 belongs to
the team being assessed.

## How it plugs in

**The catalogue is data, not prompt text.** `data/threat-checks/default-catalogue.yaml`
carries all four blocks, one entry per check: id, block, letter, the question in
one plain sentence, applicability predicate, signals and paths, pass/fail
conditions, false-positive exclusions, required evidence, and the CWE/type
mapping a `failed` outcome inherits. It has a schema and a drift test. Editing a
check must not mean editing an agent. Who may edit it and how is the next
section.

**Applicability is resolved in the manifest.**
`scripts/build_stride_dispatch_manifest.py` evaluates each check's predicate
against the per-component flags it already computes (`_is_auth:250`,
`_is_frontend:255`, `_is_llm:335`, `_is_exposed:420`, zone derivation) and writes
`applicable_checks: ["STR-T01", …]` into the component's manifest entry. The
agent never decides what applies to it, so the receipt can be checked against an
input it did not author.

**Dispatch respects the prompt-cache contract.** The catalogue text is identical
for every component, so it belongs in Group A (stable run values) where it is
cached once per run. Only the applicable-ID list is component-specific and
belongs in Group B. Putting the catalogue in the per-component block would pay
for it once per dispatch. `tests/test_dispatch_prompt_cache_order.py` guards the
order; the canonical layout is `agents/phases/phase-group-threats.md` → Dispatch.

**The receipt is part of the existing artifact.** `.stride-<COMPONENT_ID>.json`
gains `checks[]` alongside `skipped_categories`
(`schemas/stride.schema.yaml:105`): per entry an id, one of the four outcomes,
the evidence locations, a one-line rationale, and the local threat ids the check
produced. Every id in `applicable_checks` must appear exactly once.

**A new validator owns the verdict.** `scripts/validate_stride_receipt.py` loads
manifest, catalogue and receipts and enforces the coupling: `failed` needs
evidence or a linked threat, `passed` needs the evidence the catalogue demands,
`not_applicable` needs a false predicate or a stated reason, `not_verifiable`
needs a reason. It becomes what "category complete" means in
`scripts/stride_dispatch_waves.py:292`, beside the `partial` and `seed_only`
checks that stay. The log-line branch in `scripts/check_stride_dispatch.py:321`
belongs to serial-dispatch detection and is out of scope.

**Failure must not kill the run.** A component with an incomplete receipt gets
one targeted re-dispatch carrying only the missing checks; if it comes back
incomplete again, the missing checks are recorded as `not_verifiable` with the
reason and the run continues. Blocking outright would let one stubborn component
end a scan, and the fail-safe direction here matches how unknown reachability is
already handled.

**Outcomes reach the report through paths that exist.** A `failed` check
produces a threat through the normal merge contract. `not_verifiable` becomes a
coverage-gap entry with no CVSS. Per-component, per-category coverage is the
threat-model-shaped output; `scripts/arch_coverage_to_threats.py` and
`scripts/qa_arch_coverage.py` are the precedent for turning coverage into report
content rather than leaving it in an artifact.

**Sequencing.** Each step is shippable and reversible on its own.

1. Catalogue file, schema, tests, and `resolve_threat_checks.py --list`. No
   runtime change, and the questions are already readable from the plugin.
2. Manifest emits `applicable_checks`. No agent change. Measure the subset size
   per component on the fixtures before going further.
3. `checks[]` in the schema, the agent contract, and the validator in warn-only
   mode. This is where the real cost shows up.
4. Flip the validator to a gate and retire the self-reported `skipped_categories`
   as the meaning of complete.
5. Surface coverage in the report.
6. Org and repo layers. They come after step 5 so that a disabled check is
   visible in the report the first moment it can be disabled.
7. Add the block-D LLM-conditional checks.
8. Block A, wired to the existing weight consumers — crown-jewel marking, actor
   relevance, severity caps — not to a new report section.
9. Block C as targeting for block B — no new case class, no new chain layer.

Blocks A and C come last because they change how findings are weighted and named,
and doing that before the receipt is trustworthy makes both harder to judge.

## Where the questions live and who may change them

The questions are the product here, not an implementation detail. They have to be
readable without reading Python, editable without touching an agent, and
extendable by an organization without forking the plugin. Three properties, and
the repository already has the machinery for all three.

**One file, plain sentences.** Every question is one entry in
`data/threat-checks/default-catalogue.yaml`, written as a sentence an engineer
can argue with. The same sentence is what the report prints as the coverage line,
so there is no second wording to keep in sync.

```yaml
- id: STR-E03
  block: stride
  letter: E
  question: >-
    Is the owner identity part of the query, and does it come from the session
    rather than a parameter?
  applies_when: component.persists_records and system.multi_tenant
  signals: [data-access sites, query construction, origin of the identity]
  pass: Every read and write of a user-owned record is constrained by an identity the caller cannot set.
  fail: An access path takes the owner from a request parameter, or applies no owner predicate.
  not_verifiable_when: The data layer is generated or indirect enough that the predicate cannot be read from source.
  exclusions: [ORM scope or middleware applying the predicate centrally, genuinely global records]
  evidence: [data-access site, origin of the identity]
  on_fail: {cwe: CWE-639, type: authorization}
```

**Four layers, the same shape the plugin already uses.**
`scripts/resolve_threat_checks.py` merges them the way `resolve_abuse_cases.py`
and `resolve_actors.py` merge theirs, stamps `_provenance.source_file` per entry
and writes one resolved set:

1. the plugin catalogue, unless `threat_checks.inherit_defaults: false`;
2. the org profile — `threat_checks.add` (a glob relative to the profile
   directory, validated against the catalogue schema) and `threat_checks.disable`
   (ids, each with a reason);
3. `<repo>/.appsec/threat-checks.yaml` for the team being assessed;
4. nothing else. Neither depth, nor preset, nor a CLI flag adds or removes a
   question.

**Readable from the outside.** `resolve_threat_checks.py --list` prints the
active questions with their block, id and provenance — the precedent is
`resolve_abuse_cases.py --list-ids`. `docs/threat-checks.md` carries the shipped
catalogue as a table, and the org-profile block is documented in
`docs/org-profiles.md` next to `abuse_cases` and `actors`.

**Namespaces stay separate.** Shipped ids are `CTX-`, `STR-`, `ABU-`, `LLM-`;
anything added by an org or a repo is `ORG-…`, the way `ORG-AC-NNN` already works
for abuse cases. A layer may never redefine a shipped id — it disables it and
adds its own.

**A disable is a coverage statement, not a deletion.** The point of the catalogue
is honest coverage, so a disabled check appears in the report as not evaluated,
with the layer that disabled it and the reason. This is also what keeps layer 3
safe: the repository being assessed may state why a check does not apply to it,
and it may not make the question disappear from the output. Silent removal turns
the receipt into self-certification.

**Imported text is data.** Questions from layers 2 and 3 reach an agent prompt,
so they are untrusted content in the sense AGENTS.md already uses: length-capped,
never able to choose a path, command, tool or permission, and never carrying
instructions to the agent. `applies_when` is not free text — it resolves against
the manifest's existing named predicates and nothing else. `security_coach`
(`schemas/org-profile.schema.yaml`) is the precedent for org text injected as
advisory context under a cap.

## What a single check looks like

Before any block-B check can be written, each needs an owner. Several already have a
deterministic one, and the repository's stated default is to prefer a
deterministic emitter where it can own a category. Where a scanner owns a check,
the agent records the outcome instead of re-deriving it — that is both the
quality argument and the largest single saving in prompt cost.

| Check | Existing owner |
|---|---|
| STR-I01 secrets in code and configuration | `scripts/secret_scan.py`, `scripts/postscan_secret_check.py` |
| STR-T03 pinning and integrity of dependencies and artifacts | `scripts/assess_supply_chain_controls.py`; `scripts/config_iac_scanner.py` for the configuration half |
| STR-E01 object and function authorization | `scripts/source_auth_scanner.py` |
| STR-T02 manipulation of persisted objects | `scripts/mass_assignment_scanner.py` (partial) |

The rest have no deterministic owner today and fall to the agent. Three worked
examples, spanning the range:

**STR-I01 — Secrets in code and configuration.** Owner: deterministic.
Applicable to every component. Signals: the secret-scan findings already
attached to this component's paths. Pass: no secret finding on the component's
paths. Fail: at least one, and the check inherits that finding rather than
producing a second one. False-positive exclusions: whatever the scanner already
excludes — the check adds none of its own. Evidence: the scanner's `file:line`.
`not_verifiable` cannot occur; the scanner either ran or the run is broken.

**STR-E03 — Tenant and ownership isolation.** Owner: agent. Applicable when the
component reads or writes persisted records and the system has more than one
tenant or user-owned resource class. Signals: query construction at data-access
sites, whether the owning identity is part of the predicate, and where that
identity comes from. Pass: every read and write of a user-owned record is
constrained by an identity the caller cannot set. Fail: at least one access path
takes the owner from a request parameter, or applies no owner predicate at all.
False-positive exclusions: an ORM scope or middleware that applies the predicate
centrally, and endpoints whose records are genuinely global. Evidence: the
data-access site and the origin of the identity, both at `file:line`.
`not_verifiable` when the data layer is generated or indirect enough that the
predicate cannot be read from source.

**STR-R01 — Coverage of security-relevant events.** Owner: agent.
Applicable when the component performs authentication, authorization decisions,
or state-changing administrative actions. Signals: log call sites near those
decisions. Pass: authentication outcomes, authorization denials, and
administrative state changes each reach a log sink. Fail: a named class of
those events has no log call on any path. False-positive exclusions: a logging
middleware or framework-level audit hook covering the class centrally, and
components that delegate the action rather than performing it. Evidence: the
decision site and the log site, or the named absence. `not_verifiable` when
logging is configured outside the repository.

Two things this format makes visible. A check with no false-positive exclusion
is not finished, and a check whose fail condition cannot name a `file:line` or a
concrete absence belongs in the coverage output rather than in the register.

## Cost

24 block-B checks plus up to four LLM-conditional ones per component collides
head-on with the running context and turn reduction work
(`implplan-threat-analysis-context-and-turn-reduction-2026-08-05.md`). Three
levers keep it bounded: applicability resolved in the manifest so each
component's prompt carries only its subset, deterministic owners answering their
own checks so the agent only records the outcome, and a screened cheap-stride
component receiving the mandatory subset only. All three need measuring against
the current per-component turn budget before this is worth building.

Block A is cheap by comparison — six questions once per run, not per component.
Block C is per system too, and adds no run of its own — it redirects block-B
checks that would run anyway.

## Reconciliation with the shipped abuse cases

Checked against `data/abuse-cases/default-library.yaml` and decisions AC-1…AC-5.

The shipped library is seven technical chains — AC-T-001 account takeover via
stored XSS, AC-T-002 bulk exfiltration via broken object authorization, AC-T-003
JWT algorithm confusion, AC-T-004 mass assignment on registration, AC-T-005
exposed secret material, AC-T-006 server-side injection, AC-T-007 a privileged
action via prompt injection into a tool-calling model. Every step carries a
CWE and a `probe` with `sink_patterns` and `control_patterns`, gated by
`scope_qualifier.required_signals` (AC-T-006 alone is ungated). Nothing in it
models misuse of a working feature.

So block C does not duplicate the library by subject. It cannot ride its
mechanism either: AC-1 promotes only a confirmed probe, and business misuse has
no sink pattern to confirm. A block-C case entering there would sit unpromoted
forever — the same dead end as the unlinked hypotheses removed on 2026-07-03.

The resolution is that block C produces targeting, not cases. It names the
function that earns money, releases data in aggregate, or spends at a third
party; the confirmable part is then STR-D01, STR-D02, STR-E01/E03 or STR-I02
applied to that named function, weighted by block A. That keeps AC-1 and AC-2
intact and adds no third chain layer — `data/compound-chain-patterns.yaml`
(CC-01…CC-06) already overlaps the AC-T templates, and that redundancy is open.

One question needs sharpening against the library rather than merging into it:
ABU-02 sits next to AC-T-002 but is the opposite case — export that is permitted
per record and an exfiltration in aggregate, with no broken authorization
anywhere. It has to state that difference or it will re-ask AC-T-002.

## Known gaps in the catalogue

Block A has no mechanism yet for the case where declared context contradicts the
code — a README claiming single-tenant against a schema with a tenant column.
That is a real signal and neither block currently owns it.

## The LLM extension (PHANTOM-B), as checks in the same catalogue

The same mechanism answers the open question of how PHANTOM-B — Shostack's
LLM threat-modeling mnemonic — enters the pipeline. Writing pass/fail conditions
for its eight points shows that the categories the OWASP LLM Top 10 does not
cover are code-checkable after all, and that they fall inside letters the
catalogue already has. That is block D:

| PHANTOM-B point | Check | Letter |
|---|---|---|
| Non-explainability | LLM-D1 | R |
| Overreliance | LLM-D2 | E |
| Anthropomorphization | LLM-D3 | T |
| Training issues (data provenance half) | LLM-D4 | I |
| Bias | No check. Not a defect an AppSec finding can state or a fix can close. | — |

The rest map onto existing coverage: prompt injection to the LLM01 lens,
hallucination to LLM09, the supply-chain half of training issues to LLM03, and
missing security engineering to STRIDE itself.

Two consequences. PHANTOM-B needs no third lens file next to
`agents/shared/owasp-llm-top10.md` and `owasp-asi-top10.md`, so the context cost
is four conditional checks rather than a parallel catalogue. And applicability is
already computable: `_is_llm` (`scripts/build_stride_dispatch_manifest.py:335`)
and `KNOWN_LLM_PATTERNS` decide who gets them, with the agentic subset gated the
way the ASI lens is gated today.

LLM-D3 is the most useful of the four, and the pipeline currently works against
it. AC-T-007 step 1 lists `guardrail` and `instruction.?hierarch` among its
`probe.control_patterns` with `control_sufficiency: any`, so a prompt saying
"never reveal the API key" marks the step control-guarded
(`scripts/match_abuse_cases.py:33`). LLM-D3 is the check that disputes exactly
that: a prompt instruction is not an enforced boundary. Adding it means deciding
what happens to that pattern list. LLM-D2 is the one that needs block A
— whether a delegated decision is consequential is a business question, not a
code question.

## Risks of the changeover

Ranked by what they cost if they land. The first three decide whether this is
buildable at all; the rest are design work that has to happen before step 3.

**1. The receipt asks for more verdicts than the budget has turns.** A component
at standard/moderate gets 22 turns, a screened one gets 8
(`build_stride_dispatch_manifest.py:78`, `:701`), against 24 block-B checks plus
up to four conditional ones. The precedent is recorded in
`classify_component._footprint_turn_floor:229`: on 2026-07-20 juice-shop's
`data-persistence` needed 24 model file reads plus 8 mandatory context reads, and
both dispatch attempts died at the 40-call ceiling having completed zero STRIDE
categories. Mandating a per-check verdict moves every component toward that
shape. The subset size per component has to be measured on the fixtures at step 2,
before anything depends on it.

**2. It pushes into the model loop what the current direction pulls out.** The
execution rule of `implplan-threat-analysis-context-and-turn-reduction-2026-08-05.md`
is turn admission: status, fixed routing, successful validation and mechanical
normalization must not enter a model loop. Twenty-four model-authored verdicts
per component is the opposite motion on the most expensive stage of the run.
Only the deterministic owners make the two compatible, so their share is not a
nice-to-have — it is the condition.

**3. A well-shaped receipt can still be an empty one.** The validator can check
that every applicable id carries an outcome, a reason and the demanded evidence.
It cannot check that the model looked. Under turn pressure the cheapest
compliant strategy is `not_verifiable` everywhere, and the fail-safe in
"Failure must not kill the run" writes exactly that outcome by design. Silence
today is honest; a full receipt of unexamined checks is worse, because the report
now claims coverage on it. A component whose receipt is mostly `not_verifiable`
has to be reported as not covered, not as checked.

**4. A deterministic owner that did not run.** Four checks are answered by
scanners, and not every scanner runs in every mode — the config/IaC pass is
conditional and quick mode drops stages. If the owner never ran, an empty finding
set reads as `passed`. The receipt has to record which producer answered a check,
and an absent owner must resolve to `not_verifiable`.

**5. The same weakness twice.** STR-I01 inherits the secret-scan finding rather
than authoring one, and per-instance findings stay separate by default, so a
check that emits its own threat produces a second F-ID for the same evidence.
This is the first open question at the end of this document, and it belongs in
the validator rather than in prompt wording.

**6. Coverage output can drown the findings.** Per component and per check, a
ten-component model produces roughly 250 outcome rows. Whether the report carries
outcomes per check or aggregates them per category — six rows per component — is
a decision to make before step 5, not after, because it changes the sections
contract and the QA rules with it.

**7. Incremental runs have no answer yet.** A carried-forward `passed` masks new
code in a changed component; recomputing every outcome removes the point of an
incremental run. T/F identity is contractually preserved across runs and check
outcomes have no such contract, so this needs one before the gate flips.

**8. A fifth public ID class.** `agents/shared/qa-crossref-rules.md` enumerates
`T-NNN`, `M-NNN`, `F-NNN`, `TH-NN` and `C-NN` explicitly, and reference formats,
anchors and deep links hang off that list. `STR-…` and `ORG-…` in the report mean
touching that contract, the sections contract and the QA cross-reference checks
in one change.

**9. Attempt accounting.** `stride_dispatch_waves.py:94` allows two attempts per
component, and the wave plan persists attempt counts strictly enough to raise on
a mismatch. The targeted re-dispatch for an incomplete receipt is a third attempt
unless it is planned inside that budget.

**10. Two profiles, two meanings.** With the configuration layers, the same
repository under two org profiles produces different coverage claims under
identical section titles. The provenance and the visible-disable rule only work
if the report prints both.

## Option B — rename instead of building

If the catalogue is not built, the honest move is to stop claiming STRIDE
coverage and rename the categories after what the pass actually does:

Identity threat review · Integrity threat review · Auditability review ·
Confidentiality review · Availability review · Authorization review

This adds no coverage. It only stops the report from overclaiming, it is cheap,
and it does not foreclose Option A later.

## Open questions

- Does a `failed` check always produce a finding, or can it be satisfied by an
  existing one?
- Do check outcomes carry into incremental runs, or are they recomputed per run?
- Does the receipt gate block the phase, or only annotate the report?
