# Proposal: cross-component signals between analysis agents

Status: proposal, not implemented. Date: 2026-10-09.

## Problem

Each STRIDE analyzer sees one component and its bounded evidence bundle. A discovery that matters beyond that component reaches no other analyzer. Examples: a shared JWT helper skips signature verification, a gateway middleware does not enforce authorization on one route prefix, a reusable fetch helper accepts arbitrary URLs, or one service holds a secret that other services trust.

Today such a discovery meets other components only after analysis. The merger deduplicates overlapping findings, `control_scope` groups findings on one shared control, the architect reviewer corrects one component at a time, and the post-STRIDE synthesizer writes tier root causes. None of these lets component B's analysis use what component A's analysis proved. Component B can therefore miss the consequence or rate it on an assumption that component A already disproved, for example "authorization is enforced at the gateway".

## Goal and non-goals

Goal: an analyzer can publish a small number of central, evidenced observations, and can hand another component's analyzer something suspicious it could not resolve itself. The analyzers and reviewers for affected components receive exactly the items that concern them and nothing else.

The binding constraint is context hygiene. A receiving agent's context must not fill up with low-value hints. Every rule below that bounds, filters, or drops signals serves that constraint first.

Non-goals:

- No live channel between running agents. Concurrent agents in one wave never read each other's output, because the result would depend on timing.
- No shared, growing file that every agent reads. That recreates the resident-context floor the context-v2 migration removed.
- No free-text messages. A signal is structured data with a closed vocabulary.
- A signal never becomes a finding by itself. Only the receiving analyzer's own repository evidence establishes a finding.

## Design overview

The mechanism follows the pattern that already carries control-analyst overlays into STRIDE: a producer writes a schema-bounded artifact, deterministic code validates and routes it, and each consumer receives a receipted per-component projection.

1. **Emit.** The STRIDE output gains an optional `signals[]` list.
2. **Validate.** Wave verification checks each signal against the schema and the repository.
3. **Route.** A deterministic router decides which components a signal reaches.
4. **Consume.** STRIDE analyzers in later waves and architect reviewers of all affected components receive a bounded projection.
5. **Account.** Every delivered signal receives a recorded disposition from its consumer.

## 1. Emit

A signal has one of two classes:

- A **finding signal** states an evidenced observation whose effect plausibly extends beyond the emitting component, for example a shared helper that skips signature verification.
- A **lead** hands over something suspicious that the emitter could not resolve inside its own scope, for example an unusual header pass-through into another service, or a configuration value that disables a check whose consumer lives elsewhere. A lead is a request to look closer, not a claim.

A STRIDE analyzer may add at most two finding signals and one lead to its output.

| Field | Content | Bound |
|---|---|---|
| `class` | `finding` or `lead` | one value |
| `kind` | Closed enum. Finding: `shared_control_weak`, `shared_control_absent`, `assumption_disproved`, `shared_credential`, `reusable_sink`, `trust_extended`. Lead: `unresolved_flow`, `suspicious_config`, `unexpected_bypass` | one value per class |
| `subject` | Stable identifier in `control_scope` form, for example `gateway-authz-middleware` | pattern `^[a-z][a-z0-9-]{1,63}$` |
| `evidence` | Repository-relative path and line range | 1–3 locations |
| `claim` | Finding: one sentence describing the observed state. Lead: one sentence stating what looks wrong and what would decide it | ≤ 200 characters |
| `source_threat` | Index of the emitting component's own finding, when one exists | optional, finding signals only |

A lead must cite at least one evidence location outside the emitter's own paths. A suspicion inside the emitter's own scope is the emitter's own work, and the validator drops such a lead.

The analyzer does not name receiving components. Reach is a routing decision, and a model-chosen target list would let repository content steer which agents receive text.

The emit rule replaces existing prompt text rather than adding to it: a signal is warranted only when the evidence location is outside the component's own paths or is imported by code outside them.

## 2. Validate

The analyzer never writes its output file directly; `runtime/stride_attempt_writer.py` owns it. Signals and dispositions therefore enter through the writer's `finish` call, which rejects malformed input without persisting it, as it does for categories. `orchestrator/stride_dispatch_waves.py verify` then validates signals together with the STRIDE output:

- schema and enum conformance;
- each evidence path resolves to a contained regular file, and the line range exists;
- each evidence location is bound by content hash, using the same slice hashing as the evidence bundle;
- `claim` is stored as untrusted data and is fenced wherever it is delivered.

An invalid signal is dropped and counted in the wave record. It never fails the component, because signals are optional enrichment. An invalid finding stays fatal as before.

## 3. Route

A new deterministic producer, `contexts/build_peer_signals.py`, reads the validated signals after each wave and writes one projection per receiving component. A signal reaches component C when at least one deterministic relation holds:

- an evidence path lies inside C's finalized paths;
- C's evidence bundle has a source slice on the same file;
- a data flow in `.data-flows.json` has the emitter and C as its `from` and `to` endpoints, and the signal kind concerns that flow (`shared_control_*`, `trust_extended`, `shared_credential`).

Two relations that seem natural have no deterministic source today. Recon does not resolve import edges, so "C imports the evidence file" cannot be decided. The control-analyst overlay states controls as free text, not as `control_scope` identifiers, so "C names the same subject" cannot be matched. Either relation needs its own producer first and is out of scope.

A lead reaches only the component whose finalized paths contain one of its evidence locations. The broader relations above apply to finding signals only, because a lead is a pointer to a place, not a claim with consequences.

Signals with the same `kind` and `subject` are merged, keeping all evidence up to the bound. Admission limits and ordering are defined in the flooding section below.

A finding signal that reaches no component is retained for the post-STRIDE stages only. A lead that reaches no component is dropped and counted.

## Flood control

Each limit applies at a different point, so no single misbehaving producer can fill a receiver's context:

| Point | Rule |
|---|---|
| Emitter | At most two finding signals and one lead per component, enforced by schema |
| Validation | Signals without valid, contained, hash-bound evidence are dropped; leads without evidence outside the emitter's scope are dropped |
| Routing | Delivery only through a deterministic relation; no broadcast, and no model-chosen targets |
| Deduplication | Identical `kind` and `subject` from several emitters arrive as one signal with merged evidence |
| Receiver | At most four finding signals and two leads, and at most 2,048 bytes per projection; finding signals rank before leads, then by kind and subject; omissions are counted, never truncated mid-item |
| Delivery shape | Only `kind`, `subject`, evidence locations, and `claim`; no excerpts, no emitter findings, no emitter reasoning |
| Empty case | No projection file when nothing qualifies, so the common case costs nothing |

A signal adds a pointer, not source text. The receiver's read scope does not grow. Its broad search stays within `component.paths`, but its admitted bundle slices regularly cover shared files outside them (see Measurement). For a finding signal the receiver checks its own use of the shared mechanism and does not re-verify the emitter's evidence, which was already validated and hash-bound at the emitter.

The run audit records per kind how many signals were emitted, dropped, delivered, and confirmed. A kind whose leads are rarely confirmed across runs is evidence for tightening or removing that kind. Raising a limit needs the measured confirmation rate as evidence, in line with the repository's limit policy.

## 4. Consume

### Later STRIDE waves

STRIDE runs in sequential waves of at most five components in manifest order. The controller writes each component's context plan when it prepares that component's wave, not when it builds the manifest, so a later wave can carry signals from earlier waves without rebuilding bundles. A component in wave N receives signals from waves 1 to N−1 through a new optional per-component context, `threats.peer_signals`, in `data/context-routing-catalog.yaml` (`applies_to: current_component`, `importance: supporting`). It is absent when empty.

The signals travel inline in the receipted component plan, like the existing `repair` brief, and not as a separate artifact. A wave already carries up to eleven receipts per component plus the effective-plan receipt against a 64-artifact cap, and the controller's own comment on `repair` names that cap as the reason for inlining.

This is asymmetric: wave 1 receives nothing. The routing step therefore does not replace the post-STRIDE check below.

### Post-STRIDE check through the architect reviewer

After all waves, the router determines for every delivered or deliverable signal whether the receiving component addressed it. A component counts as having addressed a signal when it recorded a disposition (section 5) or owns a finding with the same `control_scope` or an evidence location inside the signal's evidence range. The `control_scope` comparison must read the per-component STRIDE files, because merge prefixes every `control_scope` with its component ID. The merger's comment says that actual shared mechanisms need a separate review; this proposal is that review path.

Unaddressed leads go to the run audit only. Forwarding them to the reviewer would move the noise one stage later instead of removing it.

Unaddressed finding signals become an additional packet type for the architect reviewer, which already runs once per component on bounded packets and returns validated proposals. The reviewer may propose a correction to an existing finding, for example a rating that rested on the disproved assumption. It may not create a finding from the signal alone. When the architect review is disabled, unaddressed signals are reported in the run audit and do not trigger any dispatch. The review is enabled automatically only at `thorough` depth or with `--architect-review`. At the default `standard` depth, later-wave delivery is the only path on which a signal changes the analysis.

A targeted STRIDE redispatch for unaddressed signals is deliberately excluded. It would double the cost for the components that matter most and reintroduce retry budgets for a non-failure condition.

## 5. Account

A STRIDE analyzer that received signals records one disposition per signal:

| Disposition | Meaning |
|---|---|
| `confirmed` | The component is affected; a finding cites the component's own evidence |
| `not_applicable` | Concrete evidence shows the component is unaffected, for example its own verification call |
| `not_verifiable` | The component's admitted evidence cannot decide it |

Wave verification rejects a `confirmed` disposition without a linked finding that cites evidence in the component's own scope. `not_verifiable` is legitimate and keeps the gap visible instead of forcing a guess. A finding created on a signal and not exploitably proven remains unproven under REQ-MOD-009.

## Trust and security

The main new risk is injection amplification: repository text read by analyzer A could reach analyzer B's prompt through a signal. The design contains it in four ways:

- the vocabulary is closed, and `claim` is short, fenced, and delivered as data;
- routing ignores model-chosen targets and uses only deterministic relations;
- every evidence location is re-validated and hash-bound before delivery, and a signal never expands the receiver's evidence bundle beyond its existing caps or containment;
- a signal cannot create, rate, or suppress a finding; only receiver-owned evidence and the existing deterministic gates can.

CR-3 and CR-5 apply unchanged. The new context has a visible catalog assignment and is forbidden for every role that is not listed as a consumer.

## Cost

| Item | Estimate, to be measured |
|---|---|
| Emit | ≤ 3 signals of roughly 80 tokens each per component, in output that is already being written |
| STRIDE consume | ≤ 2,048 bytes for affected components in later waves only, plus the receiver's own reads of cited code |
| Architect review | Additional packets only for unaddressed signals, within existing job limits |
| Dispatches | none added |

## Optional extension: wave ordering

The value of in-wave delivery depends on hub components running first. The wave planner could order components by deterministic hub rank, measured as inbound data flows plus shared-control references, while keeping manifest selection unchanged. This changes which components benefit, not which components are analyzed. It is listed separately because it changes wave composition, which existing resume and retry logic persists.

## Verification plan

- Neutral reproduction: three components share one token-verification helper, and only one component's evidence bundle contains the defect. Without signals, the other two components rate on the assumption that tokens are verified. With signals, they record a disposition and either cite their own evidence or report `not_verifiable`.
- Variant: the same mechanism with a shared URL-fetch helper and different names and paths.
- Lead case: one component forwards an unusual header into a second component's handler, and the emitter cannot see how the handler uses it. The lead reaches only the second component, which records a disposition based on its own evidence.
- Negative case: two components without import, data-flow, or overlay relation. No signal reaches either one.
- Flood case: every component emits its maximum. No receiver projection exceeds its limits, and omissions are counted.
- Injection case: a repository comment that reads like an instruction appears in `claim`. It is delivered fenced, routing is unchanged, and the receiver's findings do not change from that text alone.
- Measurement: tokens per component and the count of contradicting cross-component assumptions in a golden-fixture A/B, using `scripts/threat_fixture.py`.

## Affected sources

- `schemas/stride.schema.yaml`: `signals[]` and `signal_dispositions[]`
- `scripts/runtime/stride_attempt_writer.py`: accept signals and dispositions in `finish`
- `scripts/orchestrator/stride_dispatch_waves.py`: signal validation and disposition gate
- `scripts/orchestrator/orchestration_controller.py`: inline signals in the component plan for later waves
- `schemas/stride-component-context-plan.schema.json`: inline `peer_signals`
- new `scripts/contexts/build_peer_signals.py` and `tests/test_build_peer_signals.py`
- `data/context-routing-catalog.yaml`, `data/context-routing-bindings.json`: `threats.peer_signals`
- `scripts/contexts/build_stride_evidence_bundles.py`: projection delivery and plan binding
- `agents/appsec-stride-analyzer-v2.md`: emit and disposition rules, replacing existing text
- `scripts/analyzers/architect_review_runtime.py`: unaddressed-signal packet type
- `docs/internal/contracts/orchestration-actions.md`: Phase-9 row
- a new decision entry in `docs/internal/decisions.md`, with operator confirmation

## Measurement (2026-10-09)

Two full context-v2 runs on OWASP Juice Shop (`docs/security` and `docs/security-run-1146`, 8 STRIDE components each) were compared at the per-component STRIDE output level.

| Metric | Run 1 | Run 2 |
|---|---:|---:|
| STRIDE findings | 71 | 66 |
| Findings whose evidence lies in another component's paths | 15 | 9 |
| Findings at a file and line also cited by another component | 18 | 14 |
| Shared file-and-line locations | 6 | 6 |
| Threats after merge | 53 | 57 |
| Components in wave 1 / wave 2 | 5 / 3 | 5 / 3 |

Observations:

- Missed cross-component knowledge was not observed. Shared mechanisms such as `lib/insecurity.ts` and `routes/login.ts` reached two or three analyzers through their own bundles, and each analyzer found the defect independently.
- Contradicting assumptions were rare and mild. One SPA finding per run credited the JWT as an effective authentication control while the auth component proved token forgery. Neither changed a rating that the report relies on.
- The dominant cross-component effect is duplicate work: 20–25 % of STRIDE findings repeat a location another component already analyzed, which the merger later collapses.
- The producing and the affected components ran in the same first wave in both runs, so later-wave delivery would not have reached them.

Juice Shop is one monolith split into logical components, so shared code is visible to several analyzers. The result does not transfer to repositories whose components have physically separate code, such as microservices or multi-repository runs. There, an analyzer sees only the client side of a shared mechanism, and the signal case is more likely.

Assessment: on this sample, the mechanism would add little value. A second sample with physically separated components is needed before deciding. The duplicate-work finding is a separate, measurable cost issue that the router's ownership relation could address by assigning each shared location to one owning component.

## Re-verification: what already exists, and the gap that remains

A second pass checked the proposal against mechanisms the pipeline already has.

| Existing mechanism | What it covers | Verified in |
|---|---|---|
| `boundary_refs[]` on every STRIDE finding, with `boundary_id`, `leg`, `rationale`, and `evidence_locations` | A finding states which trust-boundary assumption leg it breaks. Boundaries carry `assumption` and `assumption_legs` | `schemas/stride.schema.yaml`, `.trust-boundary-candidates.json`, juice-shop run: 10 boundaries referenced, `tb-4` and `tb-5` by two components each |
| `trust_boundaries.component_context` | Every STRIDE analyzer receives its adjacent boundaries and their assumptions before analysis | `data/context-routing-catalog.yaml` |
| Deterministic scanner results in every component context | Config/IaC, known secrets, known vulnerabilities, and supply-chain findings reach all affected analyzers without any agent channel | `build_stride_dispatch_manifest.py`, `build_stride_evidence_bundles.py` |
| `discovery_escapes[]` | An analyzer that needs evidence outside its slices searches itself, within a recorded reason; 8 escapes across the two runs, mostly `missing-control-proof` into `server.ts` | `agents/appsec-stride-analyzer-v2.md`, run outputs |
| Triage step 1 | Flags the same CWE rated two or more levels apart across components | `triage_validate_ratings.py` |
| `docs/related-repos.yaml` | A called service's finished model enters as untrusted context; the cross-repository form of a signal | `docs/threat-modeler.md` |

The gap that remains is specific: nothing propagates a broken boundary leg to the components behind that boundary. `_compute_breach_distance` derives distance from title patterns, CWE defaults, and route-guard hints only; it never reads another finding's `boundary_refs`. In the juice-shop run, `juice-shop-api` proves that the authentication leg of `tb-1` (external to API) is broken by the hardcoded signing key, yet the breach distance of findings in `sqlite-store`, `marsdb-store`, and `realtime-channel` behind that boundary is unaffected.

This gap has a deterministic solution, because the join key already exists. A post-STRIDE pass can walk the data-flow graph from each broken boundary leg and lower the breach distance of findings whose reachability depended on that leg, recording the breaking finding as the reason. It costs no prompt text, treats every wave alike, and reuses `_severity_policy`'s existing breach-distance input.

Revised assessment of the use cases:

- **Broken-boundary propagation**: real, measured, and solvable without an agent channel. This is the recommended first step.
- **Physically separated services and multi-repository runs**: plausible but unmeasured; no sample run exists in `appsec-advisor-examples` or the e2e fixture, which are monoliths plus infrastructure. If a sample shows the need, deliver broken boundary legs to later waves as a projection keyed by `boundary_id`. No free-text claim, no new vocabulary, and routing follows the data-flow graph.
- **Leads**: weak. `discovery_escapes` already lets the analyzer look itself, and a handover would only move an unresolved question to a context that has less of its evidence.
- **Free-text assumptions**: `architecture_assumptions` are strings without IDs and cannot be referenced deterministically; boundary legs are their identified form.

### Third pass: the deterministic propagation checked against the final model

Replaying the proposed rule on the juice-shop run's final `threat-model.yaml` changes nothing:

- The components behind the broken boundary hold no findings. `reclassify_components.py` moves each finding to the component that owns its evidence file, so the SQL-injection findings that STRIDE attributed to `sqlite-store` and `marsdb-store` end up in `auth-module` and `juice-shop-api`. The final model has 0 findings in either store.
- The findings that remain behind an external boundary (`realtime-channel`) already have breach distance 1.
- Cross-finding propagation already exists in a different form: the Stage-1d abuse-case chains mark the hardcoded signing key (`T-021`) as a `keystone` of two verified chains, and ranking raises chain severity for keystones and contributors.
- Boundary IDs are renumbered between the STRIDE outputs and the final model (`.trust-boundary-renumber.json`), so any pass must resolve references through that map.
- A separate anomaly surfaced: the keystone finding itself carries breach distance 3 (`cwe_default:CWE-321`) although the key is readable by anyone with the public source. That is a breach-distance default question for secret-in-source findings, not a propagation question.

Conclusion: neither the agent-to-agent channel nor the deterministic propagation changes a result on the available samples. The structural gap is real only for components whose code is physically separate from the control they rely on, and no such sample exists. Nothing is implemented. The trigger for reopening this proposal is a run with physically separated services in which findings behind a verified-broken authentication or authorization leg carry breach distance 2 or more.

## Open decisions

1. Deliver signals to later STRIDE waves, or only to the post-STRIDE architect review. Later-wave delivery improves analysis but is asymmetric. Review-only delivery is symmetric and cheaper but corrects instead of informing.
2. Adopt hub-first wave ordering.
3. Make dispositions mandatory for every delivered signal, or record them only when the analyzer acts on a signal.
4. Confirm the initial bounds: two finding signals and one lead emitted per component, four finding signals and two leads delivered per component, 2,048 bytes per projection.
