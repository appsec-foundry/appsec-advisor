# Implplan: consistent Figure 1 for arbitrary repositories

**Status:** measures verified by replay on 2026-09-27 and re-verified independently the same day. Implemented: M1 and M1b (`e978f404`), M3 (`8b9eef9e`), M6 (`48e7a60e`), M5 (`9a24382f`, glyph numbering `31ceef8e`, `46d1cc83`). Deferred: M2 (§4) and M4 (§6).

**Trigger:** operator review of the juice-shop2 Figure 1 (run 2026-09-26, rendered before `96c919ba`) and of the same model rendered with the current code.

**Replay set:** juice-shop2, VulnerableApp, insecure-ai-app, insecure-spring-app (local runs), plus the published v0.6.0b4 examples in `appsec-advisor-examples/threat-modeler/`. Replays copy each output directory to a scratch location and run `renderers/compose_threat_model.py` with the measure simulated by monkeypatching; manifests are copied next to the copy so the display name resolves as in a real run.

## 1. Observed symptoms and verified causes

| # | Symptom | Cause | Class | Anchor |
|---|---|---|---|---|
| S1 | Actors scattered in the left column; build attacker not beside CI | `_overview_groups` runs only for the overview; `96c919ba` made the detail rendering Figure 1 for in-cap models | regression | `renderers/figure1_dfd.py:3728`, `renderers/compose_threat_model.py:_render_figure1_svg` |
| S2 | Boundary IDs, boundary legend and "internal interfaces" count back in Figure 1 | same commit rewrote RA-15 from "overview shows no boundary IDs" to "Figure 1 is the detail rendering with boundary IDs" | regression | `docs/internal/decisions.md` RA-15 |
| S3 | One boundary shows one crossing although eight flows cross the line (juice-shop2 `tb-1`) | chips bind only to flows with identical `from`/`to`, and only when exactly one drawn edge matches; boundary-stage signal→flow mapping and `covers_components` are ignored | defect | `renderers/figure1_dfd.py:1500-1520`, `contexts/prepare_trust_boundary_context.py:1153`, `:2400-2476` |
| S4 | Second boundary line between application and data layer looks like a database boundary | overview moves backend-only third parties to the data column (`_overview_groups`), so egress `tb-5` gets its own full-height line. Overview only: the current detail rendering draws one line, so the symptom returns with M1 | design gap | `renderers/figure1_dfd.py:2244-2270` |
| S5 | Two cards for the same people ("Juice Shop User", "End User (Browser)") | analyst wrote one catch-all role without `access`; RA-11 keeps the generic victim beside an unclassified role | producer gap, no guard | `.data-flows.json` `ext-001`; `renderers/figure1_dfd.py:1031-1058` |
| S6 | Admin role without any flow | `reconcile_privileged_roles` needs a regular role's `interaction` flow as template; none exists | producer gap, no guard | `model/reconcile_privileged_roles.py:_interaction_template` |
| S7 | CI component isolated; supply-chain inputs and published artifact absent | no producer models build inputs/outputs although `.deployment-inventory.json` holds them | coverage gap | `analyzers/deployment_inventory.py` output unused by Figure 1 |
| S8 | Build attacker labelled with "Bypass or Forge Authentication" / "Bypass Authorization" | attack-class taxonomy has no supply-chain class; 12 of 14 build findings map to no class, the two that do (CWE-347, CWE-732) define the A2 scenarios | taxonomy gap | `data/attack-class-taxonomy.yaml` |
| S9 | "juice-shop2 User" instead of "Juice Shop User" when the output directory is not `<repo>/docs/security` | display name resolved from a manifest found via `OUTPUT_DIR.parent.parent`; fallback is `meta.project` (directory name) | fragile fallback | `shared/_manifest_readers.py:45`, `renderers/compose_threat_model.py:5882` |
| — | No boundary line to SQLite/MarsDB | embedded stores are internal interfaces (RA-15); correct | intended | `renderers/figure1_dfd.py:_internal_interface` |

Evidence for S5/S6 (juice-shop2, patched copies of `.data-flows.json`, reconciled with `reconcile_privileged_roles.reconcile`, composed):

| Variant | `ext-001.access` | role `interaction` flow | user cards | admin edge |
|---|---|---|---|---|
| A original | — | — | 2 | none (`flow_id: None`) |
| C | — | yes | 2 | yes |
| D | `internet-user` | — | 1 | none |
| B | `internet-user` | yes | 1 | yes (`df-014`) |

Both conditions are necessary; neither alone fixes both symptoms.

## 2. M1 — Figure 1 is the overview again (S1, S2)

Change `_render_figure1_svg` so Figure 1 always renders with `detail=False`; render the paged detail sibling only when `needs_views` is true. Keep the other half of `96c919ba`: an in-cap model writes no `figure1-detail.svg`.

Touch: `scripts/renderers/compose_threat_model.py`, RA-15 (§8), `docs/internal/contracts/schema-invariants.md` (Figure 1 paragraph), `docs/threat-modeler.md`, the unreleased `CHANGELOG.md` bullet added by `96c919ba`, `data/requirement-bindings.yaml` test selector, `tests/test_compose_threat_model.py`, `tests/test_figure1_dfd.py`.

Verified (current code, overview forced):

| Repo | Attackers group | Build-attacker zone | chips | self-check |
|---|---|---|---|---|
| juice-shop2 | yes | yes | 0 | pass |
| VulnerableApp | yes | yes | 0 | pass |
| insecure-ai-app | yes | n/a (no build zone) | 0 | pass |
| insecure-spring-app | yes | n/a (no build attacker) | 0 | pass |

Not verified by replay: the absence of the detail sibling. The copied output directories already hold versioned sibling files from the original runs, so only a fresh fixture can show it.

Guards: a composed in-cap model in a fresh output directory has Figure 1 with the `Attackers` group, no `tb-N` chip, no boundary legend and no detail sibling; a model with a build zone and a build-time actor places the actor in `build-threat`; a model beyond the caps still gets the paged sibling with chips.

## 3. M1b — one perimeter line for ingress and egress (S4)

M1b is a required part of M1, not an independent measure: the second line exists only in the overview, which M1 makes Figure 1 again.

In `_overview_groups`, keep third-party entities in the external column instead of moving backend-only peers next to the data column. Every external participant then sits left of the perimeter, and ingress and egress boundaries share one line; a second line appears only for a boundary between drawn components (for example a networked database with a trust transition).

Verified: juice-shop2 `tb-1 tb-2` + `tb-5` → one line `tb-1 tb-2 tb-5`; insecure-spring-app `tb-1 tb-2` + `tb-6` → one line; VulnerableApp and insecure-ai-app unchanged (already one line); self-check passes on all four. Cost: egress edges to third parties become longer (Ollama edge crosses the application column once).

Guard: a model whose only non-internal boundaries touch `external` draws exactly one boundary line; a model with a component-to-component boundary that is not an internal interface still draws its own line (negative case).

## 4. M2 — boundary chips from the boundary stage's flow mapping (S3), deferred

**Deferred.** After M1 an in-cap model has no chips, so S3 is no longer visible there. In a paged detail view M2 changes the result only when flows are mapped to a boundary whose endpoints differ from their own, as with client-tier flows on an `external → server` boundary. None of the four replayed runs is such a model beyond the caps: juice-shop2 has the pattern but is in-cap, and the other three derive the same flows as exact endpoint matching. The cost is a new persisted model field across two schemas, the builder, the renderer, the schema invariants and a decision row. Implement M2 when a report of a large model shows the wrong chip placement; that report is then the reproduction.

Listing the crossing flows in the §1 Trust Boundaries catalogue was considered and rejected: the figure already shows which edges cross the line, the catalogue already carries control, assumption, verdict and linked findings, and findings attach through `covers_components`, not through flows.

The design below stays as the verified starting point.

The boundary stage already knows which flows each boundary covers: every signal in `.trust-boundary-assessment-input.json` carries `flow_ids`, and `.trust-boundary-coverage.json` assigns `boundary_ids` per signal. Persist the union per boundary as `crossing_flow_ids` on each `.trust-boundaries.json` row, carry it into the canonical YAML, and let the detail renderer place chips only from that list, falling back to exact `from`/`to` for models without the field. The coverage file survives cleanup (`runtime/runtime_cleanup.py:292` is in the `NEVER` set), but the assessment input that holds the `flow_ids` is removed (`runtime/runtime_cleanup.py:173`), and a published model ships without either; the field must live in the model.

The coverage `boundary_ids` are the IDs before delivery renumbering (`model/build_threat_model_yaml.py:3333` writes `.trust-boundary-renumber.json`). The field is therefore attached to the row in the boundary stage and travels with the row through renumbering; nothing joins by boundary ID after that point.

The renderer change is more than a new source for the flow list: today a chip is placed only when exactly one drawn edge matches (`renderers/figure1_dfd.py:1513`), otherwise the node tag is used. With `crossing_flow_ids` the renderer places the chip on every drawn edge that carries a mapped flow.

Verified derivation (pre-renumber IDs, identical to canonical IDs only for juice-shop2, whose mapping is empty): juice-shop2 `tb-1` → df-001, df-002, df-003, df-004, df-005, df-006, df-007, df-012; `tb-3` → df-008; `tb-4` → df-009; `tb-5` → df-010; `tb-2` → none (see M4). The derivation also resolves on VulnerableApp, insecure-ai-app and insecure-spring-app, whose mappings are not empty (VulnerableApp: `tb-10` → `tb-4`); there it yields the same flows as exact endpoint matching, and the build boundary has none.

Touch: `scripts/contexts/prepare_trust_boundary_context.py` (coverage block `:2400-2476`), `schemas/fragments/trust-boundaries.schema.json` and `schemas/threat-model.output.schema.yaml` (both `additionalProperties: false`), YAML builder passthrough, `renderers/figure1_dfd.py:1500-1520`, schema invariants. After M1 this affects only paged detail views and any catalogue that lists crossing flows.

Guard: an SPA fixture whose client-tier flows are mapped to an `external → server` boundary shows the chip on each mapped flow in the detail view, including several edges of one boundary; a variant with different component names behaves identically; a fixture whose boundaries are renumbered keeps each list on its own boundary; a boundary without mapped flows keeps the node tag (negative case). Extend the self-check: every drawn flow that crosses a boundary line in a detail view carries a chip or belongs to an internal interface.

## 5. M3 — legitimate roles cannot collapse or lose their edges (S5, S6)

**M3a validator (analyst retry).** In `architecture_reference_errors`, when the model has a client-tier component and at least one regular legitimate role, require at least one regular role with an `interaction` flow to a client component. The error message names the client component and the roles.

Verified rule matrix:

| Model | fires | expected |
|---|---|---|
| juice-shop2 | yes | yes (S5/S6) |
| example juice-shop thorough b4 | yes | yes (its Admin has no edge either) |
| example juice-shop standard b4 | no | no |
| example vulnerableapp b4 (user + scanner) | no | no (scanner exempt, user interacts) |
| VulnerableApp (no client component) | no | no |
| insecure-ai-app (client, no roles) | no | no |

Both positive cases are Juice Shop models. The neutral SPA fixture and its renamed variant supply the positive case outside Juice Shop; no replayed non-Juice-Shop run has the defect.

**M3b deterministic access classification, unambiguous paths only.** In `model/reconcile_role_access.py`, classify an unclassified, undeclared regular role from its own request path (`request_path`) only when the path is unambiguous: every counted hop with a known scheme authenticates → `internet-user`; every counted hop is `none` → `internet-anon`. A mixed path (`none` beside an authenticating scheme) leaves the role unclassified and becomes an architecture validator error that names the role and the hops of each kind, so the analyst splits it into one role per privilege level. An unknown-only path leaves the role unclassified without an error.

The first draft classified any path with one authenticating hop as `internet-user`. It was rejected: `request_path` includes every hop reachable behind the client, so a single authenticated API endpoint would make every role behind an SPA `internet-user`, including a purely anonymous visitor. A requirement that the analyst always sets `access` was rejected too: it fires on the VulnerableApp scanner role, which is legitimately unauthenticated.

Verified: VulnerableApp `ext-security-scanner` → only `none` → `internet-anon`. juice-shop2 variant C (with an interaction flow) → `none` beside `password`, `bearer`, `cookie` → mixed, so M3b alone does not remove the duplicate card there; the retry after the validator error does. The expected effect on juice-shop2 therefore rests on the analyst following the error, not on a deterministic classification.

**Prompt.** `appsec-architecture-analyst.md`: one role per privilege level (never one role spanning anonymous, user and admin), and the human interaction with each client component is required, not optional. Served client code stays a prompt rule (`schema-invariants.md:150`); no reliable deterministic signal was found.

Guards: neutral SPA fixture without interaction → validator error; renamed variant → same error; API-only fixture → no error. Classification: fully authenticated path → `internet-user`, fully unauthenticated path → `internet-anon`, mixed path → unchanged plus validator error, SPA whose only authenticated hop is one API endpoint behind an anonymous role's path → not `internet-user`, unknown-only → unchanged without error, declared role → unchanged.

## 6. M4 — supply-chain inputs and outputs for build components (S7)

Add a deterministic emitter that turns `.deployment-inventory.json` into external entities and flows of the build component: dependency sources per manifest ecosystem, base-image registries, third-party CI action sources, and every `ci[].publishes` target. It emits only what the inventory evidences and nothing without a build-zone component.

Verified: build components have zero flows in all three replayed repos that have one (juice-shop2, VulnerableApp, insecure-spring-app); the inventory carries CI systems, publish targets, base images and dependency counts for juice-shop2 and VulnerableApp; insecure-spring-app has an empty inventory and must stay unchanged (negative case).

**Deferred.** Every external entity and data flow in the model requires file/line evidence, and the inventory records only the workflow directory for a CI system and no location for a publish target, action source or dependency source. M4 therefore first needs the inventory to record those locations. The inventory and the deployment topology it feeds were being reworked in parallel when M1–M6 landed, so M4 waits for that work to settle.

Resolved design point: registries and package sources are `external-service` entities with the existing `package-registry` service role; no enum change is needed.

Open design points: entity `kind` for artifact sources and registries (extend the enum or use `external-service` with `service_roles`); file/line evidence for CI entries (the inventory records only the workflow directory today); interaction with boundary `external → ci-cd-pipeline`, which is a boundary without a single flow in all three repos today. The emitted flows share its endpoints, so they bind to it by exact endpoint matching and need no M2.

## 7. M5 and M6 — attack class and display name (S8, S9)

**M5.** Two causes, both generic:

1. The taxonomy has no supply-chain class, so 12 of 14 juice-shop2 build findings map to no class (VulnerableApp 11 of 13, insecure-spring-app 5 of 7, same CWE pattern).
2. A finding takes the first class whose `cwes` contains its CWE (`renderers/compose_threat_model.py:2988-3003`); the attributed actor plays no part. CWE-347 and CWE-732 on build components therefore become "Bypass or Forge Authentication" and "Bypass Authorization", and exactly these two findings define the A2 scenarios today. A new class alone would leave both wrong titles in place.

Change: add a supply-chain class with default actor `build-time`, and assign a finding whose attribution is the `build-time` group to that class before the CWE lookup. The class takes its CWE list from `restricted_groups.build-time.cwes` in `data/actor-attribution-rules.yaml` (494, 506, 829, 830, 1104, 1357, 1395) instead of a second list, so attribution and classification cannot drift. A finding without a build-time attribution keeps the CWE lookup. CWE-250 (container runs as root) stays in its current class, because the actor rule decides, not the CWE.

The first draft used the CWEs observed on juice-shop2 build findings (829, 494, 1104, 506, 345). It was rejected: the list came from one run and duplicated the attribution rule.

This changes scenario numbering, Figure 2, top threats and Management Summary counts, so it needs its own change with golden-fixture replay and a decision row.

Guards: a build-time-attributed CWE-347 finding lands in the supply-chain class; the same CWE on an internet-attributed finding stays in `auth-bypass` (negative case); a renamed build component behaves identically; the class list and the attribution rule cannot diverge (one source).

**M6.** Resolve the display name once in the YAML builder from the manifest under its `repo_root` argument (`model/build_threat_model_yaml.py`, `--repo-root` or `.skill-config.json`) and persist it as `meta.project_name`; the renderer never derives it from the output directory. No producer writes `meta.repository_root` today, so the renderer cannot find the repository itself. The readers of `meta.project_name` already exist (`renderers/figure1_dfd.py:_project_name`, `renderers/compose_threat_model.py:_figure1_display_data`); only the writer is missing. Without a manifest, fall back to the role noun alone. Verified: a copy outside `<repo>/docs/security` renders "juice-shop2 User"; with the manifest beside it, "Juice Shop User".

## 8. Decision edits

Confirmed and committed: RA-15 with its M1b addition (`e978f404`), the RA-11 addition (`8b9eef9e`), RA-25 for M5 (`9a24382f`), and the RA-18 note on the recorded project name (`48e7a60e`). Confirmed wording:

- RA-11 addition (M3b): "An unclassified, undeclared regular role takes `internet-user` only when every counted hop of its request path with a known scheme authenticates, and `internet-anon` only when every counted hop is `none`. A mixed path is an architecture error that returns to the analyst; an unknown-only path leaves the role unclassified."
- New row (M5): "A finding attributed to the build-time group takes the supply-chain attack class before any CWE lookup; that class reuses the build-time CWE list of the attribution rules."

Deferred with M2, not up for confirmation: "Boundary chips in detail views follow the boundary stage's persisted `crossing_flow_ids`, which stay on their boundary row through delivery renumbering; exact endpoint matching is only the fallback for models without that field."

## 9. Rejected: an LLM agent that checks and corrects Figure 1

Figure 1 is a deterministic projection of the canonical model. Every verified defect above sits in the renderer rules, a missing deterministic mapping, or the architecture analyst's model; an agent that edits the SVG or the figure data would hide these producer defects (AGENTS.md: fix the producer, not the rendered report), would vary between runs, and adds cost to every run. The QA reviewer is also the wrong place: it triages a compact repair plan and can only rewrite fragments.

What replaces it: deterministic checks at the stage that can correct the defect. Drawing rules stay in the renderer and its self-check (`check_diagram`): actors grouped and build attacker in the build zone (M1), one perimeter line (M1b). Model rules go into the architecture validator, which returns them to the analyst for a retry: at most one card per access class and no regular or privileged role without an edge when a client exists (M3). Model rules do not belong in the figure self-check, because a failed self-check replaces Figure 1 with the tier-stack fallback and corrects nothing. For finding new defect classes during development, a Figure 1 dimension in `eval-threat-model` can judge the rendered figure without touching the pipeline.

## 10. Order

1. Done (`e978f404`): M1 + M1b in one change with the RA-15 edits. M1 alone would bring S4 back.
2. Done (`8b9eef9e`): M3a + M3b + prompt. M3a and the mixed-path error carry the effect; M3b only closes unambiguous cases. An existing model keeps both cards until it is analysed again.
3. Done (`48e7a60e`): M6.
4. Done (`9a24382f`, `31ceef8e`): M5. The eighth class needed attack-path numbering from `glyph_sequence` in the composer and the posture QA checks, and a build-time attack edge ends at the finding's build component.

Deferred: M4 until the inventory records CI and publish locations (§6); M2 until a large model shows the wrong chip placement in a report (§4).

Each step: neutral reproduction that fails before the change, a renamed variant, a negative case, replay of the four repos above, `make validate test-changed BASE=origin/dev`, `make lint`.

Limit of the evidence: all four replayed repositories are deliberately vulnerable demo applications, and the positive M3a cases are Juice Shop models. No production application, monorepo, or repository without a web client (library, CLI) was replayed. The neutral fixtures cover the mechanisms; a run on such a repository after steps 2 and 4 is the open generality check.
