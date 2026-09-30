# Architect review: corrections from an architect's perspective

Revised on 2026-09-27. The bounded assessment/remediation review is integrated before triage; accepted corrections survive YAML rebuilds and pass a final preservation gate. Offline tests verify behavior and contracts. Live model quality and throughput remain unmeasured. The attempted four-call calibration timed out in a sandbox whose provider DNS lookup failed; an unauthenticated HTTPS probe outside it reached the provider. These timeouts do not measure model performance.

## Goal

The architect review exists to review and revise the threat model from an architect's perspective. That covers the prose, the evidence, the mappings and the ratings of findings. The operator confirmed this goal on 2026-09-27. The former Stage 4 was a copy editor that could change wording only. The current bounded implementation covers ratings and remediation; the broader corrections below remain future extensions.

## Implementation status

The implemented scope independently reviews and corrects risk, likelihood, impact and remediation text. `scripts/analyzers/architect_review.py` validates proposals, applies independent finding transactions and enforces existing policy caps with the run's scoring profile. `scripts/contexts/build_architect_context.py` admits component-local findings, evidence summaries, controls and business/architecture context without truncating oversized findings. Excluded and missing results remain explicit coverage gaps.

`scripts/analyzers/architect_review_runtime.py` integrates the tool-free process transport after evidence validation and component reconciliation, before triage, grouping and rendering. A schema-validated `.architect-review.json` preserves source snapshots, proposals, accepted changes and per-packet outcomes. Interrupted calls are not retried. A completed transaction recovers interrupted publication without spending model budget again.

The YAML builder projects accepted remediation after grouping and before requirements annotation. It separates distinct reviewed fixes from shared cards and rederives linked priorities after rating changes. An old authored priority without source-bound exception evidence cannot supersede a changed rating. Unrelated priorities remain unchanged. Enrichment and final gates reject lost corrections. Stage 4 now validates preservation instead of dispatching a blanket copy-editing pass.

General prose, evidence changes, CVSS edits, CWE changes, ownership changes and finding deletion remain outside the bounded correction schema. Source excerpts and additional boundary/catalog context are not yet projected; decisions requiring them must remain unresolved. A future extension for justified priority exceptions requires a source-bound exception contract before those exceptions can survive changed assessments.

The separate calibration driver remains offline by default. Its live mode is optional measurement, not a prerequisite for deterministic implementation. No live quality or efficiency claim follows from the current offline verification. Runtime limits are conservative allowances, not benchmark results. New runs use the existing `architect_review` enablement and model configuration; rerendering an old report does not retroactively run semantic analysis.

## Baseline state and measurement limits

**Former role.** Before this change, `agents/appsec-architect-reviewer.md` defined a copy editor that "does not review, judge, verify or investigate" and never opens the repository, the report or the YAML. The 2026-08-30 redesign removed the review deliberately: it cost 867k tokens and 40 minutes for four fragment edits, its findings went to `.architect-review.md`, which no deliverable reads, and every repair forced a second full review. That document lists cross-block consistency as the open loss.

**Guard.** `validators/check_editorial_diff.py` keeps every identifier, number, path, link target and claim marker (`may`, `not`, `critical`, `high`, …) of a block as an unchanged multiset (`_ID_RE`, `_CLAIM_RE`, lines 65–75). Outside the editable text fields `threat-model.yaml` must stay structurally identical. Ratings, CVSS, evidence locators, CWE and requirement links are therefore locked, and a rewrite that adds a reference such as `F-012` is reverted.

**Packets.** `contexts/build_editorial_context.py::partition` sizes packets by `max(ceil(blocks/20), ceil(bytes/8000))` and balances them by text size. The recorded example is block-bound. In the juice-shop2 run of 2026-09-27, 216 blocks and 47 KB of prose became 11 packets of about 4.3 KB each, every packet mixing 10–13 YAML blocks, 5–9 §6 paragraphs and Management-Summary blocks. That is four sequential waves of three.

**Where the time goes.** Transcripts of session `1c9b03f5`, first wave:

| Packet | Packet and style read | Next action | Plan written |
|---|---|---|---|
| 0001 | 16:33:47Z | 16:36:50Z | 16:37:54Z |
| 0003 | 16:33:47Z | 16:38:45Z | 16:39:30Z |
| 0002 | 16:33:49Z | 16:36:30Z | none after 13 minutes of silence |

Visible output per message is 8–24 tokens and the whole plan about 1,300 tokens. The silent intervals do not establish their cause; the JSONL does not expose the intervening reasoning. Excessive reasoning is a hypothesis to test, not a measured attribution. Packet 0002 stalled inside one message, the same shape as the 2026-09-11 failure, where four responses of 32,000 tokens each produced no tool call. The wave waits for its slowest packet. The deterministic steps before and after the dispatch take under a minute.

The September run counts, timestamps and lifecycle observations above come from the previous investigation and have not been independently replayed for this revision. Step 1 must locate the original artifacts and distinguish observed usage from hypotheses. No efficiency claim below depends on treating those numbers as verified measurements.

**Side defect, out of scope.** The run log records `AGENT_FAILED reason=superseded_without_return` for packets 0001 and 0002 in the second they were spawned, although 0001 completed normally. The call-lifecycle recording treats parallel spawns as superseding each other, which can mislead run-issue aggregation. It needs its own fix.

## Where ratings, evidence and mappings are owned today

| Field | Producer | Deterministic validation | Existing correction channel |
|---|---|---|---|
| Severity, likelihood, impact, CVSS | STRIDE agents; `_severity_policy.normalize_risks` applies ceilings from `data/severity-caps.yaml` and `data/critical-criteria.yaml` | `validators/triage_validate_ratings.py` (advisory flags only), `validators/validate_intermediate.py` CVSS eligibility (FE-1, `data/cvss-eligible-cwes.yaml`) | none: `.triage-flags.json` carries free-text `suggested_action`, and nothing applies a flag |
| `effective_severity`, ranking | `model/triage_compute_ranking.py` (`_compute_effective`, `compute_ranking`) | caps re-applied inside ranking | none |
| Mitigation priority P1–P4 | derived from severity in `model/build_threat_model_yaml.py` | `validators/validate_mitigation_quality.py` | authored override honoured in the build |
| Evidence locator and summary | STRIDE agents; `appsec-evidence-verifier` stamps `evidence_check` | `validators/validate_evidence_lines.py` checks file existence and individual line plausibility, marks out-of-range lines ambiguous, skips prior verdicts and performs no quote comparison; `drop_refuted_findings` removes refuted findings, `validators/guard_evidence_verification.py` rejects degenerate verdicts | `.evidence-verification.json`, schema and receipt enforced |
| CWE, weakness class | STRIDE agents; `weakness_classifier`, `data/cwe-taxonomy.yaml` (WK-1) | format checks in `model/merge_threats.py` and `validators/validate_intermediate.py` | none |
| Requirement links | STRIDE agents | `_filter_violated_requirements` against the catalog, `requirements/requirements_trace.py` (REQ-REQ-001) | none |
| Control and component mapping | `model/enforce_control_taxonomy.py`, `model/reclassify_components.py --strict` (FE-12) | same | none |

The pattern to reuse is the validated sidecar: `.mitigation-overrides.json` and `.tier-root-causes.json` are agent-authored, validated by `validators/validate_fragment.py` against a schema with a receipt, and merged by the YAML build in `_context_v2_finalize` (`orchestrator/orchestration_controller.py:5872`).

Changing a rating after Stage 3 invalidates what was derived from it: ranking, mitigation priorities, the severity-rationale emitter, the composed report, the requirement trace, QA and the exports. A rebuild of `threat-model.yaml` drops the enrichment receipt, and rendering refuses a model without one, so every rebuild must run `_enrich_and_gate_yaml` again.

## Binding constraints

- REQ-RPT-001: severity and score follow demonstrated evidence and policy caps. A correction passes through the same caps; the architect cannot lift a ceiling.
- REQ-MOD-005: evidence comes from the target repository. A new or changed locator is verified against the repository before it counts.
- REQ-MOD-009: an unproven finding stays marked unproven and carries no score.
- REQ-REQ-001: a requirement link is explicit and names a catalog id; nothing is inferred.
- REQ-RPT-005: every finding has a prioritized mitigation; urgent fixes include concrete steps and a way to verify the result without invented source examples.
- REQ-BIZ-003: validated declared context may inform impact and ordering, never establish a finding or relax caps; context-based judgments retain their source.
- REQ-RPT-002: finding anchors stay consistent across reports and exports produced from one model.
- aiscb-LLM-001: agent output is untrusted. Every correction is validated deterministically against a strict schema and value allow-lists before any consumer reads it. Repository text the agent reads is data, never instructions.

No requirement text has to change. Decisions `FE-1`, `FE-7`, `FE-16`, `WK-4`, `AC-9` and the Stage-4 entries in `docs/internal/decisions.md` need review, and new entries are proposed below for operator approval.

## Design

The review corrects existing findings with bounded work. It does not repeat STRIDE discovery, rewrite every paragraph, or run a second whole-report review. Every eligible finding receives a recorded disposition or is explicitly counted as unreviewed; prioritization must not conceal incomplete coverage.

### D1. Review before triage and synthesis

Split `_context_v2_after_evidence` after existing evidence handling, strict component reconciliation and merged-artifact validation, but before `validators/triage_validate_ratings.py` and bootstrap ranking. Both `context_v2_post_evidence` and the path without an evidence-verifier dispatch reach this shared helper. Dispatch the architect there and resume the existing triage continuation after deterministic application. Do not place the review after `_context_v2_finalize`: that function already builds, enriches and gates the YAML.

The intended sequence is:

1. Finalize merge, run existing evidence verification and reconcile component ownership.
2. Build bounded architect packets, collect dispositions and corrections, and atomically apply accepted changes.
3. Run existing triage, weakness refresh and synthesis on the corrected intermediate.
4. Build the canonical YAML and run ranking and enrichment in an explicitly tested order.
5. Run optional Stage 1d with its existing necessary rebuild and ranking, then Stage 2, composition, QA and exports.

The review adds no YAML rebuild and triggers no second synthesis. This does not promise that the existing pipeline builds or ranks only once: triage uses a bootstrap YAML, and Stage 1d can rebuild the canonical model. Preserve those consumers until replay proves an existing pass redundant. A resumed completed review must not run again because rendering or QA is retried.

`triage_compute_ranking.write_outputs` writes effective severity to YAML, not to the merged intermediate. Establish a canonical ranking pass after the initial build on both abuse-enabled and abuse-disabled paths. Place it before consumers that emit ranking-dependent prose and counts. Preserve required reranking after Stage 1d changes the model. Verify enrichment receipts against the final model; do not assume bootstrap ranking survives the build.

### D2. Small packets with reusable context

Add `contexts/build_architect_context.py`; do not rename the editorial builder until the post-render decision is resolved. Group findings by component and related control or boundary, then split at finding boundaries under both a finding-count cap and a serialized-byte cap. Component size never overrides either cap. Benchmark small packets against one-finding dispatches to account for repeated prompt overhead; select the smallest bounded grouping that meets the quality and cost gates in D7.

Each packet contains the review policy once, a compact component and boundary summary, its assigned findings, applicable severity ceilings and CVSS eligibility, and catalog entries relevant to their current mappings. Findings carry their original IDs, ratings and rating rationale, evidence verdicts and locators, remediation, and only the neighboring findings needed to assess a shared control or boundary. Include a bounded projection of validated business context: affected assets, declared consequences and obligations, applicability to the component, and source references. Preserve the distinction between unknown impact and an explicit declaration of no material business harm. Include existing mitigation links and any applicable authored priority, effort estimate and justification; label the ordinary risk-derived priority as derived. Missing context stays explicit rather than being filled by the reviewer. Neighbors are read-only and retain their owning packet IDs. A concern about a neighbor is recorded for its owner; it cannot authorize a foreign correction or recursive dispatch.

Reuse existing source-bound evidence windows and verification results. Include additional bounded windows only for a concrete contradiction, ambiguous evidence, disputed rating, mapping or fix, or missing context needed for the assigned decision. Avoid reading the whole repository, full model, report, unrelated taxonomy, or full requirements catalog. A verified pointer need not be re-read merely to rewrite a sentence. Changed evidence always needs fresh validation.

The controller owns source selection, containment checks, redaction and source hashes. Repository bytes remain untrusted data. Context caches are confined to the current run and authorized repository roots, with policy, catalog and source fingerprints checked before reuse. A single finding that cannot fit is reported as oversized; it is never silently truncated or admitted without a bound.

All non-refuted merged findings are eligible, including findings below the report floor whose rating could change. Order unresolved evidence and rating conflicts first, then higher policy-rated risk, using stable IDs to break ties. The scheduling order does not exempt other findings from review. Refuted findings retain their existing audit disposition and are not resurrected by this stage.

### D3. Review only what needs a decision

The reviewer checks consistency between each finding's claim, architecture, evidence, rating, mappings and proposed fix. Deterministic checks handle schema, catalog membership, cap calculations and reference integrity. The model handles the semantic judgment those checks cannot establish.

Each finding receives two compact dispositions, one for its assessment and one for its remediation: `unchanged`, `corrected`, or `unresolved`. A correct assessment with an unresolved fix is not a fully reviewed finding. An unchanged finding needs no rewritten prose or explanation of every passing check. A correction carries a short rationale and the evidence supporting the changed claim. An unresolved finding identifies the missing evidence or exhausted allowance without pretending the review succeeded. Missing or invalid records become controller-owned `unreviewed` outcomes.

For assessments, check the attack preconditions and exposure supporting likelihood, the demonstrated technical consequences supporting impact, and any applicable declared business consequences. Check the proposed risk against the existing likelihood/impact guidance and documented exceptions, then check CVSS metrics and eligibility separately. Caps are ceilings, not a justification for any value below them. A changed rating needs a finding-specific reason; a business declaration alone cannot justify raising risk or scoring an unproven claim. Preserve valid ratings without a cosmetic rewrite. Architecture-domain effectiveness ratings remain with their existing producer; this correction channel covers finding assessments and remediation, not every rating in §6.

For remediation, check whether the proposed change breaks the evidenced attack mechanism at the correct component and trust boundary, can be implemented in the observed stack, and preserves required behavior and existing controls. The reviewer may add a missing remediation, replace an ineffective or unsuitable one, and revise its title, steps, effort and verification without changing the finding or its rating. Several necessary changes may form one ordered remediation. Do not invent repository symbols or claim proposed code already exists. Verification names an observable post-change result, including rejection of the attack and retained legitimate behavior where applicable; another generic scan is not sufficient when it cannot test the claimed fix. Unknown deployment assumptions remain explicit unresolved decisions.

Prose changes repair a misleading claim or an actionable clarity defect. They are not an invitation to polish every sentence. Remediation changes are first-class semantic corrections, not wording-only edits. The review edits source remediation before synthesis, not rendered mitigation cards. One finding's fix does not authorize rewriting the fixes of other findings sharing a mitigation. D4 defines how accepted source corrections survive grouping and enrichment.

### D4. Corrections are atomic finding transactions

The agent writes controller-assigned part files under `.architect-corrections/`. Define strict schemas for the packet, manifest, part, consolidated corrections and application report. Bind every part to the run, packet, original finding ID and input fingerprint. The fingerprint covers merged findings, component and boundary inventory, policy, catalog, validated business context, applicable mitigation overrides, and admitted repository sources. Reject stale parts, foreign IDs, duplicate finding transactions, arbitrary paths and unknown fields. The controller creates the consolidated `.architect-corrections.json`; the model cannot choose its write target.

Each corrected finding carries one transaction with all requested field changes. Apply it to a copy, validate the resulting finding and affected cross-finding invariants, and commit it atomically only if the complete transaction is accepted. One rejected field rejects that finding's transaction; other independent accepted findings may proceed. Stage candidates in deterministic ID order and validate the final register before replacing the canonical file. Recheck accepted transactions against the final companion set so later changes cannot invalidate an earlier cap exception. If final consistency cannot be established, retain the original register and report application failure instead of publishing a partial invalid model.

| Change | Payload and acceptance |
|---|---|
| Rating | Explicit proposed `risk`, `likelihood`, `impact`, a finding-specific rationale with evidence and applicable business-context references, and CVSS vector when applicable. CVSS changes require a verified deterministic v4 scorer before they can be accepted; the current normalization helper is not a scorer. Reapply policy ceilings with the final companion findings; record the normalized accepted value. `normalize_risks` only caps existing risk and cannot derive it from likelihood and impact. |
| Evidence | Structured contained file and line range, revised summary, and a bounded supporting excerpt where safe. Add shared range and excerpt validation; `validators/validate_evidence_lines.py` currently has neither. Validate every proposed locator, not just one surviving locator. Never copy credential values into packets or sidecars; masked evidence follows the existing secret-evidence contract and cannot pass as a literal quote. |
| CWE | Validate the supported CWE through the existing taxonomy loaders, refresh weakness classification, reapply severity policy and recheck CVSS eligibility against the final evidence and CWE. Remove an ineligible score; reject an incomplete transaction when a newly required eligible score is absent. |
| Requirements | Explicit additions or removals with catalog IDs and finding-specific justification. Membership alone does not establish a violation. Reject additions without a configured catalog or supporting evidence. |
| Control or component | Validate membership and evidence-backed ownership. Revalidate `boundary_refs`, instance owners and affected merged provenance through the shared FE-12 and FE-16 rules; never retain references valid only for the previous owner. |
| Remediation | An explicit `add`, `replace`, or `revise` operation on the assigned finding, with the complete resulting `mitigation_title` and allow-listed `remediation` fields (`steps`, `verification`, `effort`, and supported reference or code-example fields). State which attack mechanism the fix prevents and why it is feasible. An addition requires missing source remediation; replacement or revision binds to its prior fingerprint. Validate source-field schemas, required actionable content, contained source references and finding ownership. The operation must work without a rating or evidence change; it cannot delete the only fix or allocate public mitigation IDs. |
| Prose | Allow only declared source fields with exact field addresses. Wording-only changes retain the existing lexical guard. A substantive claim change must accompany the matching semantic correction and supporting evidence; membership of an identifier in context alone does not justify adding it to a claim. |

Evidence changes invalidate prior evidence verdicts for the changed content. Reuse the existing source-bound verification path for only the affected findings, through a bounded targeted verification phase before commit. File existence and a matching excerpt prove location, not exploitability. A missing fresh semantic verdict rejects the evidence transaction and retains the original finding. Do not reset an old verdict and allow the deterministic line floor to manufacture semantic confirmation. Existing evidence-verification receipts remain historical; new accepted verdicts receive their own source-bound receipt and provenance.

Final validation applies REQ-MOD-009, FE-1, policy caps and reference integrity to the whole candidate, including combinations of rating, CWE, evidence and component changes. Unproven findings stay unscored. Review provenance is separate from `risk_before_policy`; clear or recompute stale policy metadata through the existing policy owner. Treat CVSS eligibility and score consistency as final-state properties, not checks of isolated payloads.

The applier updates `.threats-merged.json` before triage. It does not directly set effective severity, mitigation priority, public anchors or exported counts. The existing producers derive these from the accepted `risk` and other corrected fields. Synthesis consumes the corrected remediation and mappings. Carry accepted remediation field values and provenance through the merged and output schemas so downstream code can distinguish them from unreviewed or derived content.

Accepted remediation fields take precedence over synthesized or older authored values for that finding. `apply_mitigation_overrides`, scanner backfill, deterministic emitters and `hydrate_mitigation_details` must share this precedence rule: fill unreviewed missing fields, but do not overwrite a reviewed field or append steps the reviewer replaced. Preserve the approved text and verification through the canonical build, Stage 1d rebuild, rendering and applicable exports. Validate this projection deterministically at the final model gate; a lost accepted correction is a producer failure, not a reason to ask the architect again.

Grouping must preserve each finding's corrected fix and verification. Reuse the existing mitigation grouping and split machinery when its rules keep those source fields intact. If distinct reviewed remediations cannot be represented together without overwriting one, keep separate derived cards and let the deterministic owner assign IDs and links. Record which reviewed source fields each card carries. Never use first-writer order, a shared title or a subset of finding IDs as proof that different fixes are interchangeable.

Mitigation priority remains producer-owned. The ordinary priority follows the highest applicable policy-rated `risk` of linked findings through the existing mapping; business context can order work within that priority under FE-7. Bind any accepted authored priority exception to its rationale, linked finding set and assessment fingerprint. Preserve an unchanged valid exception. If review changes that basis, do not carry the override forward automatically: mark it stale, use the newly derived priority and report the displaced value and reason. An unbound override on an affected measure is not a proven exception. A later synthesis cannot introduce an unexplained priority override for a reviewed measure. Preserve unrelated override behavior, and document this scoped precedence change and its compatibility impact before implementation. Shared cards and Stage 1d additions re-evaluate the basis against their final linked findings.

Write `.architect-corrections-report.json` with accepted, normalized, rejected, unresolved and unreviewed outcomes. Accepted rating changes retain the previous assessment, requested value, accepted value and rationale under explicit review provenance. Remediation corrections retain their operation, prior and accepted source values, rationale and derived card references. Report assessment and remediation coverage separately, including unresolved fixes, stale priority overrides and measures generated after review. Update model schemas, rationale rendering and export consumers together. A reader can distinguish a reviewer decision from an original STRIDE assessment and a deterministic cap.

### D5. Bound execution outside the prompt

The agent receives only its packet and bounded, authorized evidence access. Prefer prebuilt evidence windows; any additional Read or Grep is limited to authorized roots, bounded ranges or result counts, and the packet's remaining allowance. A tool name in frontmatter does not enforce a path restriction. Runtime hooks or the dispatch adapter must enforce reads and writes, reject escaping symlinks and foreign output paths, and deny shell execution, edits to source artifacts and child-agent delegation.

A part file is useful for recovery after a completed finding. It does not bound the reasoning before the first write. Following aiscb-AGENTBOUNDS-001, persist and enforce per-job wall-clock deadlines, tool-call limits, turn limits and a total stage allowance outside the model. Use an output-token limit where the host supports it; do not claim a hard token or monetary ceiling if usage is observable only after completion. Account for active jobs when reserving the remaining stage budget.

Measure concrete limits in D7 and store them in the existing authoritative budget and configuration sources. The model cannot increase them. The host must support cancellation or enforced termination; merely timing out the waiter is insufficient. Once a job expires, close its claim, cancel it and reject late writes. The next stage starts only when active writers are terminated or isolated from canonical artifacts. Missing enforcement support blocks activation of this design.

Keep one attempt per packet and no automatic review-of-review. Bounded targeted evidence verification is separately accounted work, not a retry of the architect. Completed valid parts survive another finding's failure. Resume consumes matching committed results once; source or policy drift invalidates affected parts without silently starting another paid review. Exhaustion leaves original values and visible incomplete coverage.

The default model remains Sonnet; `--architect-model` and `APPSEC_ARCHITECT_MODEL` remain effective. Keep the existing enablement controls: automatic at `thorough`, explicit `--architect-review` elsewhere. Do not add a stronger model or higher budget as a fallback for a stalled job.

### D6. Dispatch and post-render scope

Start with the existing maximum concurrency of three and one attempt per packet. Dispatch labels identify the component, review concern and finding count. Record queue delay separately from model duration. Benchmark a bounded replenishing queue only if the host supports independent completion and cancellation and measurements show wave barriers dominate; no scheduler rewrite is assumed to be free.

There is no second semantic review after rendering. Stage 1d additions continue through their existing verifier and validation path; the receipt explicitly distinguishes them from architect-reviewed findings. Reopening review for new abuse findings is a separate scope decision, not an implicit loop.

Recommended post-render default: remove the blanket editorial model pass and rely on existing authoring instructions, deterministic emitters and QA. The architect corrects finding and remediation prose before synthesis; §6 and Management Summary are authored afterward from corrected inputs. Confirm this scope choice before changing runtime behavior. Keeping a separate editorial pass would need its own measured benefit and explicit budget; it must not be hidden in the architect's cost.

### D7. Measure useful work, cost and completeness

Before setting production limits, replay the deterministic path with and without abuse verdicts and capture source hashes, build counts, ranking counts and final receipts. Verify that review itself adds no YAML rebuild, no second synthesis and no re-render. Skip model dispatch entirely when disabled or when no eligible findings exist.

For live calibration, use the same frozen inputs, model and settings to compare small component packets with one-finding packets. Record actual model IDs, input, cached and output tokens, available billed cost, queue time, time to first valid result, p50/p95 job duration, tool calls, source bytes read, accepted corrections, incorrect corrections, unresolved findings and coverage. Keep editorial-only historical measurements separate because they do not measure equivalent work. Investigate silent intervals from host telemetry; absence of tool calls is not a measured reasoning-token count.

Use known semantic defects and unchanged negative controls to measure correction quality. Report correction recall and harmful changes separately for assessments and remediation, alongside cost per reviewed finding and cost per correct accepted correction. Include an ineffective fix, a missing fix, an unsuitable verification, and unjustified rating changes in the semantic evaluation. Deterministic acceptance proves contract conformance, not that a fix works; a fixed rubric and independently reviewed fixture expectations establish that part of the calibration. A fast run that leaves more work unreviewed is not an efficiency win. Select limits and grouping only after comparing completed coverage and quality on neutral fixtures plus a realistic larger run.

The operator subsequently approved implementing the bounded runtime without making live calibration a prerequisite. Runtime limits remain conservative allowances with functioning hard execution bounds, regression checks and visible incomplete coverage. Publish measured results before claiming an efficiency improvement or tuning those limits. Do not invent a percentage speedup or use the historical token total as an automatic budget.

## Implementation steps

1. **Establish evidence and sequencing.** Locate the original run artifacts, mark unavailable observations unverified, and replay both abuse paths. Trace synthesis, risk, ranking, enrichment, checkpoint and rendering consumers. Record the exact continuation split and required ranking calls before editing the controller.
2. **Define contracts and budgets.** Add strict schemas and source bindings for contexts, manifests, parts, corrections and reports. Define transaction semantics, the standalone remediation operations, source-field addresses, business-context projection, reviewed-field precedence, priority-exception validity, provenance, targeted verification receipts and terminal job states. Update permission, context-budget, cleanup and audit-retention contracts; preserve review provenance after temporary packet cleanup.
3. **Build deterministic context and application.** Add `contexts/build_architect_context.py` and `apply_architect_corrections.py`, sharing existing policy, taxonomy, CVSS, path and boundary-reference owners. Extend shared evidence validation for ranges and safe excerpt matching. Validate proposed findings in staging and publish only an accepted complete register.
4. **Integrate the bounded review.** Split the post-evidence continuation before triage, add dispatch, cancellation, idempotent resume and targeted evidence verification, then resume existing synthesis and YAML construction. Preserve abuse-finalization behavior and establish canonical ranking on both branches. Update orchestration contracts and the thin runtime together.
5. **Update agent and consumers.** Replace the copy-editor prompt with bounded semantic review instructions and compact dispositions. Update schemas, synthesis projections, mitigation grouping, overrides, backfill, hydration, final-model gates, severity rationale, exports, completion summary and run issues for review provenance and separate assessment/remediation coverage. Preserve accepted remediation fields across every producer, and rederive priorities when review invalidates their override basis. Implement the approved post-render choice without a hidden second model pass.
6. **Prove correctness and measure efficiency separately.** Add tests and reviewed source routes and replay the golden fixture. Implement and validate the bounded runtime offline. Use separately authorized live calibration later to measure quality and throughput; lack of live evidence does not block integration.
7. **Document the delivered behavior.** Update decision entries, `docs/threat-modeler.md` and one relevant unreleased CHANGELOG outcome when runtime work is complete. The implemented assessment/remediation slice updates those contracts and user-facing capabilities.

## Tests and release evidence

- Rating changes update `risk`, effective severity, derived mitigation priority, report-floor membership, Management Summary, register and SARIF. Test lowering and raising, cap normalization, no score on an unproven finding, valid unchanged priority exceptions, stale and unbound affected overrides, shared-card priorities and new Stage 1d members. Verify FE-7 ordering without a business-driven priority override.
- Assessment cases distinguish technical impact, declared business harm, unknown business impact and declared no material harm. Reject unsupported rating changes even when their values fit the schema and caps; preserve legitimate ratings and documented exceptions. Use semantic fixture review for judgments that deterministic checks cannot prove.
- Remediation-only corrections add a missing fix and replace an ineffective one while leaving rating and evidence unchanged. Cover an inappropriate control, invented source symbol, unusable implementation step, inadequate verification, uncertain effort and a correct fix that must remain unchanged. Verify REQ-RPT-005 coverage and reject removing the sole actionable fix.
- Accepted remediation survives synthesis, override collisions by ID or finding subset, scanner backfill, hydration, shared-card splitting, Stage 1d rebuild, final rendering and applicable exports. Include stale steps and an old non-empty verification that must not reappear. Test incomplete remediation coverage independently of complete assessment coverage.
- Combined changes cover CWE becoming CVSS-ineligible, newly required CVSS, changed component and boundary references, changed companion-cap exceptions, and stale `risk_before_policy`. Reject an invalid transaction without retaining any of its field changes.
- Evidence cases cover changed previously verified pointers, fresh semantic verification, quote mismatch, range errors, safe masked-secret evidence, traversal and symlink escapes. An existing source line alone never validates a new exploitation claim.
- Part handling covers stale run/source hashes, duplicate transactions, foreign finding IDs, malformed or oversized output, late writes, interrupted jobs, exactly-once application and resume without another dispatch. Test shared mitigation ownership and partial packet completion.
- Execution tests cover a job that produces no first write, tool and deadline exhaustion, cancellation, reservation for active jobs, unauthorized reads and writes, and attempted delegation. Schema-valid malicious proposals must still fail authorization or semantic checks; schema validation alone is not an injection test.
- Pipeline tests cover enabled, disabled and empty review, canonical ranking with and without abuse verdicts, Stage 1d additions and provenance, QA retry without re-review, synthesis using corrected inputs, and no review-induced rebuild. A rejected proposal does not abort the run; corrupt canonical inputs or failed existing hard gates remain fatal.
- Use a neutral reproduction, a renamed variant and an unchanged negative control, plus the original run as supplemental evidence. Replay a golden fixture with `scripts/threat_fixture.py` according to the runbook. Tests must show both useful corrections and preservation of correct findings.
- For implementation, inspect `make test-plan BASE=origin/dev` and, where applicable, `BASE=HEAD`; update and audit changed routes. Run `make check` for the coupled controller and artifact-boundary changes; it includes validation, lint and the full suite, so do not repeat those gates afterward. Live calibration requires separate authorization because it consumes model budget. It measures model quality and throughput after offline integration; it does not block implementation.

## Proposed decisions and remaining choices

The recommended implementation is an incremental semantic review before triage, with compact component packets, atomic source corrections, enforced execution bounds and no automatic second review. Ratings may move in either direction within evidence and policy constraints. The reviewer may independently add, replace or revise remediation. Accepted fixes survive downstream production, and priority exceptions are retained only while their reviewed basis remains valid on affected measures. No producer can bypass the normal gates. These are proposed decisions, not recorded approvals or changed requirement text.

The operator approved the following scope direction. The bounded assessment/remediation slice now uses the implemented enforcement and integration described above; broader correction types still require their own validation paths:

- **Post-render prose:** remove the blanket editorial pass when the semantic replacement is integrated. Do not claim the pre-render architect reviewed prose that did not yet exist.
- **Refuted findings:** route a reviewer refutation through fresh evidence verification and the existing refuted-finding policy. Do not introduce a direct model-controlled delete operation. Until that verification path is integrated, leave deletion unavailable and report concerns as unresolved.
- **Measurement:** retain hard execution bounds and explicit coverage while live quality and throughput remain unverified. Tune packet sizes and deadlines only from measured useful work; do not treat a sandbox networking failure as model latency.
