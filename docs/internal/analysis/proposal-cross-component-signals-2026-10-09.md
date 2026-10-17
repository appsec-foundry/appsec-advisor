# Cross-component signals between STRIDE analyzers: studied and not built

Status: rejected for now. Date: 2026-10-09.

## Result

The idea: a STRIDE analyzer that finds something affecting other components, such as a broken shared login helper, hands that fact to the analyzers of the affected components, so they rate their own findings correctly.

The study checked this against two full runs on OWASP Juice Shop and against the final models in `appsec-advisor-examples`. On these samples the mechanism would not have changed a single result. The analyzers of the affected components had already read the shared code themselves, and the pipeline's later stages already link the findings. A simpler variant, a deterministic pass that re-rates findings behind a broken trust boundary, was checked as well and would also change nothing.

Nothing is implemented. The idea becomes relevant again for applications whose components are physically separate, such as microservices or multi-repository setups, where one analyzer cannot see the code of the control its component relies on. No such sample exists yet. The trigger for reopening this study is a run on such an application in which findings behind a verified-broken authentication or authorization boundary carry breach distance 2 or more.

## What already exists

Most of what the idea needs is already in the pipeline, in a different place or form.

| Mechanism | What it does | Where |
|---|---|---|
| Control analysis overlays | The control analyst runs before STRIDE and hands each STRIDE analyzer a bounded note on interfaces, controls, known secrets, and known vulnerabilities. This is the same pattern the idea proposes, in the one direction the stage order allows | `.stride-analyst-context.json`, routing catalog |
| Deterministic scanner results | Config/IaC, secret, and supply-chain findings reach every affected analyzer without any agent involved | `build_stride_dispatch_manifest.py`, `build_stride_evidence_bundles.py` |
| Trust-boundary references | Every finding can state which boundary assumption it breaks, with `boundary_id`, `leg`, rationale, and evidence. Boundaries carry their assumptions, and each analyzer receives its adjacent boundaries | `boundary_refs[]` in `schemas/stride.schema.yaml`, `.trust-boundaries.json` |
| Discovery escapes | An analyzer that needs evidence outside its slices searches for it itself and records why. Eight escapes across the two runs | `discovery_escapes[]` |
| Abuse-case chains | Stage 1d links findings into verified attack chains and marks keystones; ranking raises chain severity. The hardcoded signing key is a keystone of two chains in the Juice Shop run | `chain_role`, `verified_chain_ids` |
| Triage consistency check | Flags the same CWE rated two or more levels apart across components | `triage_validate_ratings.py`, step 1 |
| Related repositories | A called service's finished model enters as untrusted context; the cross-repository form of a signal | `docs/related-repos.yaml` |
| Component reclassification | Each finding moves to the component that owns its evidence file, so findings concentrate where the defect lives | `reclassify_components.py` |

One gap in this list is real: `control_scope`, the field that lets a finding name the shared mechanism it depends on, is in the schema but in no prompt. No analyzer set it in either run. It is a separate, small improvement and not part of this study.

## Measurement

Two full context-v2 runs on Juice Shop, 8 STRIDE components each, compared at the per-component output level.

| Metric | Run 1 | Run 2 |
|---|---:|---:|
| STRIDE findings | 71 | 66 |
| Findings whose evidence lies in another component's paths | 15 | 9 |
| Findings at a file and line also cited by another component | 18 | 14 |
| Threats after merge | 53 | 57 |

What this shows:

- Shared code reaches several analyzers through their own evidence bundles. `lib/insecurity.ts` and `routes/login.ts` were analyzed by two or three components each, and each found the defect independently. No analyzer lacked a fact another one had.
- Contradictions were rare and mild: one SPA finding per run credited the JWT as an effective control while the auth component proved token forgery. No rating that the report relies on changed because of it.
- The main cross-component effect is duplicate work. About a fifth of STRIDE findings repeat a location another component already analyzed; the merge step collapses them deterministically, and the merger agent was not even dispatched.
- The producing and affected components ran in the same STRIDE wave in both runs, so delivery to later waves would not have reached them.

The simpler deterministic variant was replayed on the final model: after reclassification, the components behind the broken authentication boundary hold no findings, and the findings that remain behind an external boundary already have breach distance 1. Boundary IDs are also renumbered between the STRIDE outputs and the final model (`.trust-boundary-renumber.json`), which any such pass would have to resolve.

A side observation: the keystone finding, the hardcoded signing key, itself carries breach distance 3 from its CWE default, although anyone with the public source can read it. That is a question about breach-distance defaults for secrets in source, not about propagation.

The examples repository and the e2e fixture contain monoliths plus infrastructure only, so no sample with physically separated components was available.

## Appendix: the design that was studied

Kept short, for whoever reopens this.

- A STRIDE analyzer may append at most two finding signals and one lead to its output, through the attempt writer's `finish` call. A finding signal states an evidenced fact with effect beyond the component: a closed kind such as `shared_control_weak` or `assumption_disproved`, a subject in `control_scope` form, one to three hash-bound evidence locations, and one sentence. A lead points at something suspicious outside the emitter's own paths that it could not resolve.
- The analyzer never names receivers. A deterministic router delivers a signal only where a relation holds: the evidence path lies in the receiver's paths, the receiver's bundle has a slice on the same file, or a data flow connects both components. Import edges and control-overlay matching are not available as relations today.
- Receivers in later STRIDE waves get the signals inline in their receipted component plan, like the existing `repair` brief, because a separate artifact would push a wave past the 64-receipt cap. At most four finding signals, two leads, and 2,048 bytes per receiver; no projection file when nothing qualifies. Unaddressed finding signals become architect-review packets at thorough depth; unaddressed leads go to the run audit only.
- A receiver records one disposition per signal: `confirmed` with its own evidence, `not_applicable`, or `not_verifiable`. A signal never creates, rates, or suppresses a finding.
- Injection containment: closed vocabulary, short fenced claim text, deterministic routing, re-validated evidence, and no change to the receiver's evidence caps.

If reopened, the first version should drop the lead class and the free-text claim and use the existing trust-boundary legs as the only signal vocabulary: a broken `boundary_id` and `leg` with evidence. That needs no new terms, routes along the data-flow graph, and carries no repository text.
