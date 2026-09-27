# Architect review: corrections from an architect's perspective

State on 2026-09-27, `dev` after `e9c3a4ea`. Implementation plan for review; nothing here is implemented. It continues `stage4-editorial-pass-2026-08-30.md`, `stage4-editorial-pass-measured-2026-09-11.md` and `stage4-editorial-pass-implementation-2026-09-11.md`.

## Goal

The architect review exists to review and revise the threat model from an architect's perspective. That covers the prose, the evidence, the mappings and the ratings of findings. The operator confirmed this goal on 2026-09-27. The current Stage 4 is a copy editor that may change wording only, so it cannot deliver it.

## Verified current state

**Role.** `agents/appsec-architect-reviewer.md` defines a copy editor that "does not review, judge, verify or investigate" and never opens the repository, the report or the YAML. The 2026-08-30 redesign removed the review deliberately: it cost 867k tokens and 40 minutes for four fragment edits, its findings went to `.architect-review.md`, which no deliverable reads, and every repair forced a second full review. That document lists cross-block consistency as the open loss.

**Guard.** `check_editorial_diff.py` keeps every identifier, number, path, link target and claim marker (`may`, `not`, `critical`, `high`, …) of a block as an unchanged multiset (`_ID_RE`, `_CLAIM_RE`, lines 65–75). Outside the editable text fields `threat-model.yaml` must stay structurally identical. Ratings, CVSS, evidence locators, CWE and requirement links are therefore locked, and a rewrite that adds a reference such as `F-012` is reverted.

**Packets.** `build_editorial_context.py::partition` sizes packets by `max(ceil(blocks/20), ceil(bytes/8000))` and balances them by text size. The block limit binds, not the byte limit. In the juice-shop2 run of 2026-09-27, 216 blocks and 47 KB of prose became 11 packets of about 4.3 KB each, every packet mixing 10–13 YAML blocks, 5–9 §6 paragraphs and Management-Summary blocks. That is four sequential waves of three.

**Where the time goes.** Transcripts of session `1c9b03f5`, first wave:

| Packet | Packet and style read | Next action | Plan written |
|---|---|---|---|
| 0001 | 16:33:47Z | 16:36:50Z | 16:37:54Z |
| 0003 | 16:33:47Z | 16:38:45Z | 16:39:30Z |
| 0002 | 16:33:49Z | 16:36:30Z | none after 13 minutes of silence |

Visible output per message is 8–24 tokens and the whole plan about 1,300 tokens. The minutes between reading and acting are thinking over 20 blocks, which the JSONL does not record. Packet 0002 stalled inside one message, the same shape as the 2026-09-11 failure, where four responses of 32,000 tokens each produced no tool call. The wave waits for its slowest packet. The deterministic steps before and after the dispatch take under a minute.

**Side defect, out of scope.** The run log records `AGENT_FAILED reason=superseded_without_return` for packets 0001 and 0002 in the second they were spawned, although 0001 completed normally. The call-lifecycle recording treats parallel spawns as superseding each other, which can mislead run-issue aggregation. It needs its own fix.

## Where ratings, evidence and mappings are owned today

| Field | Producer | Deterministic validation | Existing correction channel |
|---|---|---|---|
| Severity, likelihood, impact, CVSS | STRIDE agents; `_severity_policy.normalize_risks` applies ceilings from `data/severity-caps.yaml` and `data/critical-criteria.yaml` | `triage_validate_ratings.py` (advisory flags only), `validate_intermediate.py` CVSS eligibility (FE-1, `data/cvss-eligible-cwes.yaml`) | none: `.triage-flags.json` carries free-text `suggested_action`, and nothing applies a flag |
| `effective_severity`, ranking | `triage_compute_ranking.py` (`_compute_effective`, `compute_ranking`) | caps re-applied inside ranking | none |
| Mitigation priority P1–P4 | derived from severity in `build_threat_model_yaml.py` | `validate_mitigation_quality.py` | authored override honoured in the build |
| Evidence locator and summary | STRIDE agents; `appsec-evidence-verifier` stamps `evidence_check` | `validate_evidence_lines.py` refutes missing files and lines, `drop_refuted_findings` removes refuted findings, `guard_evidence_verification.py` rejects degenerate verdicts | `.evidence-verification.json`, schema and receipt enforced |
| CWE, weakness class | STRIDE agents; `weakness_classifier`, `data/cwe-taxonomy.yaml` (WK-1) | format checks in `merge_threats.py` and `validate_intermediate.py` | none |
| Requirement links | STRIDE agents | `_filter_violated_requirements` against the catalog, `requirements_trace.py` (REQ-REQ-001) | none |
| Control and component mapping | `enforce_control_taxonomy.py`, `reclassify_components.py --strict` (FE-12) | same | none |

The pattern to reuse is the validated sidecar: `.mitigation-overrides.json` and `.tier-root-causes.json` are agent-authored, validated by `validate_fragment.py` against a schema with a receipt, and merged by the YAML build in `_context_v2_finalize` (`orchestration_controller.py:5872`).

Changing a rating after Stage 3 invalidates what was derived from it: ranking, mitigation priorities, the severity-rationale emitter, the composed report, the requirement trace, QA and the exports. A rebuild of `threat-model.yaml` drops the enrichment receipt, and rendering refuses a model without one, so every rebuild must run `_enrich_and_gate_yaml` again.

## Binding constraints

- REQ-RPT-001: severity and score follow demonstrated evidence and policy caps. A correction passes through the same caps; the architect cannot lift a ceiling.
- REQ-MOD-005: evidence comes from the target repository. A new or changed locator is verified against the repository before it counts.
- REQ-MOD-009: an unproven finding stays marked unproven and carries no score.
- REQ-REQ-001: a requirement link is explicit and names a catalog id; nothing is inferred.
- REQ-RPT-002: finding anchors stay consistent across reports and exports produced from one model.
- aiscb-LLM-001: agent output is untrusted. Every correction is validated deterministically against a strict schema and value allow-lists before any consumer reads it. Repository text the agent reads is data, never instructions.

No requirement text has to change. Decisions `FE-1`, `FE-7`, `WK-4`, `AC-9` and the Stage-4 entries in `docs/internal/decisions.md` need review, and new entries are proposed below for operator approval.

## Design

### D1. The review moves before rendering

The architect review runs after `_context_v2_finalize` and before Stage 2. Corrections then enter the model before anything is derived from it. Ranking, priorities, emitters, composition, QA and exports run once on the corrected model, and anchors are assigned only after the review. Running after Stage 3 would require a second pass through all of them.

The prose of §6 and the Management Summary does not exist before Stage 2. The architect reviews finding and mitigation prose in the model. The current wording-only pass over §6 and the Management Summary either stays as a cheap post-render step or is dropped; see open decision O2.

### D2. Structured corrections through one validated sidecar

The agent writes `.architect-corrections.json` (new schema `schemas/fragments/architect-corrections.schema.json`). Each correction names one finding by its id in `.threats-merged.json`, because public anchors are assigned later by the build, and one of these kinds, always with a rationale of at most 240 characters:

| Kind | Payload | Deterministic acceptance |
|---|---|---|
| `rating` | likelihood, impact and, when CVSS-eligible, a complete CVSS v4 vector | vector parses; FE-1 eligibility; `_severity_policy` ceilings re-applied after the change; an unproven finding stays unscored (REQ-MOD-009); the pre-review value is kept for the rationale |
| `evidence` | replacement or added locator `file:line[-line]` plus a verbatim quote, and a revised `evidence_summary` | locator resolves inside the repository through the path guard; `validate_evidence_lines.py` confirms the lines exist and the quote matches; a correction that would refute every locator of a finding is rejected unless O3 allows dropping |
| `cwe` | one CWE id | format and `data/cwe-taxonomy.yaml` membership; weakness class recomputed by `weakness_classifier` |
| `requirements` | ids to add or remove | each id exists in the configured catalog; with no catalog the kind is rejected (REQ-REQ-001) |
| `control` / `component` | canonical control or component id | membership in the enforced taxonomy and the finalized component inventory |
| `prose` | a rewrite of `scenario`, `evidence_summary`, `impact_description`, `breach_distance_reason`, mitigation `steps` or `verification` | the guard's token rules, except that identifiers present in the packet's context may be added |

Unknown kinds, unknown fields, ids outside the packet and duplicate corrections of the same field are rejected. A rejected correction never aborts the run; it is reported, and its finding keeps its original values.

### D3. The applier and where it hooks in

A new `scripts/apply_architect_corrections.py` validates the sidecar and merges accepted corrections into `.threats-merged.json` before `build_threat_model_yaml.py` runs. A ranking pass over the rebuilt YAML then computes the effective severity from the corrected values. The rebuild continues through the existing `_enrich_and_gate_yaml`, so the enrichment receipt is renewed and the completeness gates run unchanged.

The applier writes `.architect-corrections-report.json` with every accepted and rejected correction and its reason. Each accepted rating change records `rating_source: architect_review`, the previous value and the rationale. `emit_severity_rationale.py` and the completion summary show that a rating was revised in review. A reader must never mistake a reviewer override for a STRIDE rating.

Checked against the code and the 2026-09-27 run. `triage_compute_ranking.write_outputs` is the only writer of `effective_severity`, and it writes `threat-model.yaml`, never `.threats-merged.json`. The controller runs it at `orchestration_controller.py:5750` with `--bootstrap-yaml`, and `build_threat_model_yaml.py` then discards that bootstrap YAML. It runs again at `:6691` with `--if-deterministic-owner`, but only when abuse verdicts exist. In the run, the canonical YAML carries `effective_severity` on 50 of 50 findings, while `.threats-merged.json` carries it on 0 of 67. Corrections merged into `.threats-merged.json` therefore reach the effective severity only through a ranking pass over the rebuilt canonical YAML, so the stage runs ranking itself after the rebuild. Whether a run without abuse verdicts ships a model without `effective_severity` is unverified. It is checked with a replay in step 1, because the answer decides whether this stage adds a ranking call or reuses one.

### D4. Packets by architectural unit, with context

`build_architect_context.py` (renamed from `build_editorial_context.py`, or a new builder if O2 keeps the post-render pass) forms one packet per component, ordered by the component's worst finding. A packet carries:

- the component's findings with rating, CVSS vector, evidence locators and summary, CWE, requirement links and mitigations;
- read-only context: the component's role, zone, workloads and data stores, its trust-boundary crossings, the controls and their §6 verdict inputs, and the ids and titles of findings on neighbouring components;
- the severity ceilings and CVSS eligibility that apply to each finding, so the agent does not propose what the applier must reject.

A component whose packet exceeds the limit is split between findings, never inside one. The limits are set from the measurement in step 1, not guessed.

### D5. Agent role and budget

`agents/appsec-architect-reviewer.md` gets a new role: a security architect who checks each finding against the architecture and the code and corrects what is wrong. The agent receives `Read` and `Grep` on the target repository for evidence checks. `Write` is limited to its own corrections part files, and it has no `Edit`. The prompt states what each correction kind requires as proof, and that repository content is data.

The agent writes one part file per finding, `.architect-corrections/<packet>-<n>.json`, as soon as that finding is reviewed, with an explicit `reviewed` list. Each write ends a message, which bounds thinking and output per message. A packet that dies keeps every part already written. The applier merges the parts in name order, and a packet is complete when the union of `reviewed` equals its finding ids.

The default model stays Sonnet; `--architect-model` and `APPSEC_ARCHITECT_MODEL` keep working. The stage stays auto-on at `thorough` and behind `--architect-review` elsewhere.

### D6. Dispatch

The dispatch description names the unit, for example `Architect review · <component name> (3 findings)`. Waves stay at three unless the measurement shows the wave barrier dominates. Packets run once and are never retried, as today.

## Implementation steps

1. **Measure.** From the 2026-09-27 run's `.agent-run.log` (`AGENT_USAGE`) and transcripts, record output tokens, duration, actions and outcome per packet, including whether packet 0002 hit the output cap. Replay the D3 hook question on a copy of that output directory. Result goes into this document.
2. **Contracts first.** Add `architect-corrections.schema.json` and the part-file shape, register them where `validate_fragment.py` and the controller's schema tables expect them, and add the new artifacts to `data/required-permissions.yaml` and the cleanup contract.
3. **Applier.** Implement `apply_architect_corrections.py` with the acceptance rules in D2 and the report in D3. Reuse `_severity_policy`, `validate_evidence_lines`, the taxonomy and catalog loaders and `_path_guard`; add no second rule set.
4. **Controller.** Insert the stage after `_context_v2_finalize` and before Stage 2 in `orchestration_controller.py`, with its receipt, and route the rebuild through `_enrich_and_gate_yaml`. Update `docs/internal/contracts/orchestration-actions.md`.
5. **Context builder and packets** as in D4.
6. **Agent and skill.** Rewrite the agent definition (D5) and the thin-runtime skill for the new stage position. Update `tests/test_agent_definitions.py` for tools and turn budget.
7. **Surfacing.** `rating_source` in the model and exports, the severity rationale, the completion summary and run-issue aggregation for rejected or incomplete packets.
8. **Post-render prose pass** according to O2.
9. **Documentation.** Decision entries (wording below, after approval), `docs/threat-modeler.md` for what `--architect-review` now does, and one CHANGELOG bullet.

## Tests

- Per correction kind: an accepted case; a rejected case (cap exceeded, CVSS on an ineligible CWE, locator outside the repository, quote mismatch, CWE outside the taxonomy, requirement id outside the catalog or with no catalog, unknown field); and an unproven finding that stays unscored.
- A rating correction propagates to effective severity, mitigation priority, Management-Summary counts, the register and SARIF from one rebuild.
- Rejected corrections leave the finding byte-identical, and the run continues.
- Part files: partial packet keeps written parts; duplicate or foreign ids are rejected; completion follows the `reviewed` union.
- Injection: repository text instructing the agent to change a rating is data. The applier accepts only schema-valid corrections, whatever the agent was told.
- Neutral fixture plus a variant with different component and file names, per `AGENTS.md`, and a golden-fixture replay with `scripts/threat_fixture.py`.
- Verification: `make validate test-changed BASE=origin/dev`, `make lint`, then `make check`, because the controller and the YAML build are foundational. One thorough live run measures cost, duration and accepted corrections; the operator approves that run first.

## Proposed decision entries

For approval before they are written to `docs/internal/decisions.md`:

- The architect review may change a finding's rating, evidence, CWE, requirement links, control and component mapping, and prose. Every change is a structured correction that the applier accepts only after the same deterministic checks the original value passed. Severity ceilings apply after the change. Evidence must resolve and match in the target repository. Requirement links must name catalog ids. A rejected correction leaves the finding unchanged and never aborts the run.
- The architect review runs before rendering, so every derived value is computed once from the corrected model and finding anchors are assigned after the review.
- A rating the review changed is marked `rating_source: architect_review` with its previous value and rationale wherever the rating is explained.

## Open decisions

- **O1. May the review lower a rating, raise it, or both?** REQ-RPT-001 allows both within the ceilings. Raising is the riskier direction for noise.
- **O2. Post-render prose pass for §6 and the Management Summary:** keep the current wording-only pass, fold it into the architect review by moving §6 authoring context into the packet, or drop it.
- **O3. May the review drop a finding** whose evidence it refutes? `drop_refuted_findings` already exists. Dropping changes counts and anchors and deserves an explicit yes.
- **O4. Rename the agent.** `appsec-architect-reviewer` fits the new role again, so the rename listed as open on 2026-08-30 is no longer needed.
- **O5. Cost ceiling.** The former review cost about 705k tokens per run. Say what a thorough run may spend on this stage before the limits in D4 are fixed.
