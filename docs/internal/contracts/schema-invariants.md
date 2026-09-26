# Schema Invariants

Detailed schema and pipeline invariants for `threat-model.md` and
`threat-model.yaml`. Summarised in `AGENTS.md` Rule 4 — this file is the
authoritative source for the §4a–§4h details.

## §4a. Cross-reference labelling invariant

Reader-facing references normally render as `[ID](#anchor) — <short-title>`. This applies to `T-NNN`, `F-NNN`, `M-NNN`, `W-NNN`, `TH-NN`, and the `C-NN` / deprecated `AF-NNN` classes covered by the composer. Use a shorter form only where the layout or sentence already provides the meaning: declaration sites, ID columns, headings, narrow tables, inline citations, the Verdict citation form, Top Weaknesses proof lists, Open Questions for the Team bullets, and the Critical Attack Tree findings pointer. These exceptions are deliberate and must stay narrow; ordinary table and list references need a title.

Three things must stay aligned for the invariant to hold:

1. **Schema source of truth.** `schemas/threat-model.output.schema.yaml`
   declares `title` as **required** on `threats[]` (`minLength: 10`, `maxLength: 60`) and on `mitigations[]`. Do NOT make it optional or raise the 60-char ceiling; longer titles wrap in tables. `scripts/build_threat_model_yaml.py` MUST copy `.threats-merged.json[].title` verbatim or the report degrades into `(untitled)` cross-references.

2. **Deterministic link owners.** `scripts/qa_checks.py:linkify_anchors` is the
   only legal normalizer for T/F/M/TH/C cross-references. It runs from `qa_checks.py all` and is idempotent. `scripts/compose_threat_model.py` owns the context-specific full, compact, and inline forms and emits titled W-NNN references directly from `weaknesses[]`; QA does not infer W-NNN labels. Their invariants:
   - `_load_label_index` builds T-NNN and F-NNN aliases for the same numeric suffix.
   - `_load_th_label_index` parses TH-NN titles from §8 / §7.2 declarations (`<a id="th-NN"></a>TH-NN — Title`); TH titles do not live in yaml.
   - The bare-ref pass covers `sub_t`, `sub_f`, `sub_m`, `sub_th`; a new ID class needs its own substitution function.
   - The idempotent suffix regex matches `[FTM]-` AND `TH-`, so existing un-suffixed `[F-NNN](#f-nnn)` / `[TH-NN](#th-nn)` links gain `— Title` on rerun.

3. **Tests pin the invariant.**
   `tests/test_qa_checks.py:TestCrossReferenceLabellingInvariant` and `tests/test_p4_cross_reference_coverage.py:TestCrossReferenceTitleCoverageEndToEnd` cover ordinary QA-owned references. Composer and QA tests cover compact citations, inline labels, the weakness register, §7 rewrites, Top Weaknesses, Open Questions for the Team, and the Critical Attack Tree pointer. Removing or broadening an exception requires an explicit migration justification.

Failure modes to watch for in PR review:
- A schema PR that drops `title` from `threats[].required` → bare links
  ship silently because `_load_label_index` returns empty entries.
- An LLM author hand-formatting `[T-001 — Custom Title](#t-001)` in a
  fragment → bypasses single-source-of-truth and drifts on rerun.
- A new ID class introduced without assigning it to the composer or linkifier → that class ships as bare links on every rendered MD.

## Actor registration evidence

Current actor resolutions carry `open_registration_resolution` with an open/disputed decision, reason, and repository file/line evidence; the YAML builder preserves it in `meta`. Reach-equivalence and abuse-case applicability consume this decision without rewriting recon evidence or changing STRIDE severity. Disputed candidates enter the shared team-question selection even when no finding anchor exists. Historical actor artifacts remain readable, and models without actor resolution retain their curated attack-surface fallback.

Generic-route corroboration is limited to the Node/Express JavaScript and TypeScript routes covered by `AUTHZ-008`; Java, Python, Go, .NET, Ruby, PHP, GraphQL mutations, and external identity-provider signup need explicit registration-route or recon evidence. A candidate without sufficient support stays disputed rather than asserting closed registration.

## Public-source overview grouping

`meta.public_source_repo` affects overview actor grouping, not finding evidence or severity. Repository-read access folds into anonymous internet access when the flag is true; build-time and privileged access do not. Detection uses local license and source-host metadata without network calls, so a self-hosted public repository may remain unknown and a private repository on a known host may appear public. YAML-only pins remain transient across rebuilds; this verification adds no configuration or organization-profile override source.

## Finding actor attribution in overview diagrams

Canonical `actors[]` retains configured roles and active automatic roles linked to findings after runtime cleanup. Unused default and discovery roles remain analysis input and do not enter this report inventory. Its optional presence preserves compatibility with earlier models. A role contributes to an overview group only through an explicit finding assignment and a declared display category. Disabled configured roles and configured roles without a mapping do not establish a diagram assignment. Identified Actors shows only the attackers and roles Figure 1 draws; an active configured role is named inside the drawn group it maps to.

Figure 1 groups roles into the fixed access categories without equating their permissions. Each group's attack edges retain only its attributed findings and components. Multiple groups may share one scenario number. Figure 2 selects an actor group applicable to its example finding. The numbered table and actor legend use the same assignments. Canonical finding prerequisites and severity remain unchanged. Unattributed findings retain the legacy scenario category.

## Legitimate-role access in Figure 1

An external entity may carry `access` only with `kind: legitimate-role`, using `internet-anon`, `internet-user`, or `internet-priv-user` when cited code establishes that access. Boundary assessment and canonical YAML preserve this optional field and the original entity and flow identities. Older entities without access remain valid and distinct.

Figure 1 may combine explicitly classified regular roles with equivalent access, using canonical registration evidence and vocabulary labels. Privileged and unclassified roles remain separate. The figure may assign a generic victim to a unique combined regular role only when no other regular or unclassified role makes that assignment ambiguous. Unnamed flow endpoints retain their generic participant. The report paragraph immediately below the figure explains the actual grouping and retained login requirements; the SVG keeps a short role subtitle instead. A fallback figure that does not combine those roles must not claim that it does. The canonical model retains individual flow identities.

## §4b. Mitigation synthesis invariant

Every successful canonical YAML rebuild is followed by the deterministic emitter pass and the shared schema, mitigation-quality, and build-completeness gates. The final render-completeness gate requires `meta.enrichment_pass` to match the current model. Canonical writers after enrichment may carry forward only a receipt verified before their mutation; missing or stale receipts remain invalid. The marker is optional in the export schema so prior reports remain readable, but it is mandatory for run completion. Its shape lives in the output schema and its hash algorithm in `scripts/enrichment_pass.py`.

When P1/P2/P3 threats exist in `threat-model.yaml`, `mitigations[]` MUST be non-empty. An empty register means the model builder skipped mandatory synthesis. `scripts/validate_intermediate.py:validate_threat_model_output` enforces this; a non-zero post-write self-check MUST block Stage 2.

**Canonical field names** — deviating causes silent data loss:

| Correct field name | WRONG — do not use |
|--------------------|--------------------|
| `mitigations[].id` | ~~`m_id`~~ |
| `mitigations[].title` | ~~`mitigation_title`~~ |
| `mitigations[].threat_ids` | ~~`addresses`~~ |
| `mitigations[].priority` | P1/P2/P3/P4 — NEVER severity words (Critical/High/…) |
| `threats[].mitigation_ids` | ~~`threats[].mitigations`~~ |

The last row is critical: `scripts/compose_threat_model.py` reads `t.get("mitigation_ids")` for §8 Primary Mitigations and §1 Top Findings. `threats[].mitigations` makes those columns render `—`.

## §4c. `components[].threat_ids[]` directionality

After Phase 11, `components[i].threat_ids[]` MUST be the reverse index of `threats[j].component`. The Linked Threats column of the §2.3 component table reads it and renders `—` when it is missing.

## §4d. Flag-conditional QA/contract gates (`skip_attack_walkthroughs`)

`scripts/qa_checks.py` and `scripts/check_inline_shortcut.py` read `.skill-config.json` before applying gates that only matter when attack walkthroughs were authored:

- **`check_ms_structure` Check 4** (Attack Chain Overview required when
  Critical ≥ 2) — skipped when `SKIP_ATTACK_WALKTHROUGHS=true`.
- **`check_chain_compactness`** (flags "no mermaid blocks found") — skipped
  when `SKIP_ATTACK_WALKTHROUGHS=true`.

When `SKIP_ATTACK_WALKTHROUGHS=true`, `attack-walkthroughs.md` contains only a skip notice and no Mermaid blocks. Any QA/contract check that would fire on this stub is a false positive and MUST be conditioned on the flag. `data/sections-contract.yaml` documents this with `required_patterns_condition` and `per_critical_subsection_condition`.

## §4e. §8 Threat Register — source locations

When a threat carries `evidence.file` (and optionally `evidence.line`), §8 must surface that exact source location in the finding card's `**Location:**` meta field. `scripts/compose_threat_model.py:_build_threat_card` renders it as one backticked token, for example `` `lib/insecurity.ts:58` ``, while the component remains a separate `C-NN` anchor in the same meta line. Do not collapse the location back into the component anchor or split the line number outside the code span.

When the merger folds multiple members, it MUST retain every member as an
`instances[]` record with its file, line, severity and available scenario /
source reference. `affected_files[]` and `instance_count` are derived from
that list; `merged_from` alone is not sufficient audit evidence.

## §4f. Fragment registry maps — single source of truth

Five maps across three Python files implicitly encode the fragment ↔ schema ↔ contract-section relation. Any change to one MUST be reflected in the others, or the pipeline silently produces broken cross-references or skipped validations. Keep this table in sync whenever a map moves:

| Map | File | Purpose |
|---|---|---|
| `_SECTION_FRAGMENT_MAP` | `scripts/compose_threat_model.py:131` | section_id → ordered list of fragment ids the composer pastes for that section |
| `_KNOWN_JSON_FRAGMENT_SCHEMAS` | `scripts/compose_threat_model.py:148` | fragment filename → (schema name, schema file) for composer-side JSON validation |
| `FRAGMENT_SCHEMAS` | `scripts/validate_fragment.py:39` | fragment id → schema file used by `validate_fragment.py` (the producer-facing validator the LLM is told to run) |
| `_FRAGMENT_FILENAMES` | `scripts/validate_fragment.py:55` | fragment id → on-disk filename under `.fragments/` |
| `CONTRACT_SECTION_FRAGMENTS` | `scripts/qa_checks.py:1163` | section_id → fragment ids that `qa_checks` emits in `fragments_to_rewrite` repair plans |

> Line numbers drift as the files evolve; the canonical match is on the symbol name, not the number. ``scripts/check_fragment_registry.py`` extracts each map by name via AST, so the gate keeps working even when the line numbers go stale.

`data/sections-contract.yaml` is the human-edited declaration that every other map should align with; the maps duplicate fragments of it because each consumer reads only the slice it needs. Adding a new fragment means touching all five maps + the contract + the schema + the fragment's `.j2` template under `templates/fragments/` when it renders via one (the `_render_template` call in `docs/internal/runbooks/adding-a-section.md`). The mechanical sequence is documented in `docs/internal/runbooks/adding-a-section.md`. The automated drift gate lives in `scripts/check_fragment_registry.py` (see Phase A1 of the refactoring plan) — when present it MUST stay green in CI.

## §4g. Systemic weakness evidence invariant

`weaknesses[]` records are first-class assessment conclusions rendered in the
unnumbered **Systemic Weaknesses** chapter. A W-NNN may cite confirmed F-NNN
findings, unsafe-practice locations, or absent-control evidence. Its
`severity_basis` is therefore `confirmed`, `observed-practice`, or
`design-risk`; only the linked findings may carry CVSS. A CWE family is never a
weakness scope: `scripts/merge_threats.py` may group evidence only when it
shares one concrete control scope. Management Summary and §7 links point to W,
while W links to its supporting findings.

Every W-NNN has a required `title` of at most 80 characters. It is the short,
reader-facing heading and must not contain CWE IDs, source paths, routes, or
code snippets; `statement` holds the explanatory detail instead.

## Architecture identity and evidence

Optional `external_entities[]` travels from `.data-flows.json` through boundary-assessment input into the canonical export. Entity IDs are unique and distinct from component IDs. A flow's `from_entity` or `to_entity` resolves in this registry and requires the corresponding endpoint to remain `external`. Boundary adjacency and exposure continue to use canonical component/external endpoints. Missing legacy identities stay generic; consumers must not invent a role or provider.

Before the architecture analyst runs, the controller projects the role-bearing units that component-inventory finalization would add into `.dispatch-context/architecture/role-units.json` (`schemas/architecture-role-units.schema.json`), using the detectors finalization uses; the dispatch receipt requires the file to equal a fresh derivation. A unit modelled under its ID, or whose role another component carries, is not added again. A unit finalization still adds and no data flow reaches is reported as a run issue.

At the controller-owned architecture handoff, `scripts/discover_identity_providers.py` reconciles concrete outbound OAuth/OIDC/SAML client calls and declarative client endpoints with finalized components and data flows. Generated entities and flows carry contained source evidence and satisfy the existing data-flow schema before publication. Explicit internal identity-server topology takes precedence. An authored outbound flow of the same owner already represents a request when its evidence calls the function that makes it, and gains the request's evidence instead of a generated duplicate; callers that name different entities leave the request generated. Ambiguous component ownership blocks the handoff; dependency names, unused URLs, disabled configuration blocks, and unknown dynamic addresses do not create external entities. Deployment activation remains qualified, and discovery never fetches an endpoint or emits a security finding. The renderer consumes the reconciled inventory without performing discovery.

`components[].sensitive_data[]` provides category, observed or declared basis, handling, and contained repository evidence. The legacy `handles_sensitive_data` Boolean remains a conservative analysis-selection signal. Figure 1 does not display a sensitive-data-handling marker. `assets[].component_refs[]` records an evidenced storage, processing, or transmission relation to a known component. Classification and a single-store topology do not establish where an asset is stored. Optional `components[].capabilities[]` and `external_entities[].service_roles[]` name evidenced security-relevant functions from `data/security-capabilities.yaml`, each with contained repository evidence; legitimate roles carry no service role. Component finalization replaces `llm-calls` with `llm-tools` when a file that capability cites passes tools to a model call. Figure 1 shows up to three known labels per participant, those with the most severe linked finding first, without a risk rating; a missing label does not mean the function is absent. Optional `components[].framework` names the primary framework, or for a data component the storage engine and never the ORM. Component finalization sets `components[].language` from file extensions to the implementation language holding most bytes under the component's own paths, replaces any producer value, and sets none for data components. Figure 1 shows framework and language under the component name and leaves out a value that the name or the framework already contains.

RAG retrieval/ingestion, persistent AI memory, agent delegation, and runtime MCP client/server roles use the same optional capability/evidence contract. External MCP and retrieval services use the service-role vocabulary. RAG, memory and MCP alone do not establish model-directed actions. Component-table labels and Figure 1 consume that vocabulary without assigning security effectiveness. Older artifacts remain valid; absent capabilities and unresolved external enforcement stay unknown. Inspection scope and qualifications use existing control assessment prose and component architecture assumptions rather than a second coverage or authorization model.

ORM setters, query construction, and rendering execute in application components. A data store may cite a storage schema, but executable ORM source also requires an application owner independent of its framework label. A database engine is not an XSS sink. SQL-injection and XSS findings share a consolidated card only when the same sink or an explicit common control scope establishes the shared defect. Instance provenance retains the originating component and scenario. Figure 1 annotates each component with all short, evidenced Critical causes and adds High causes up to five annotations in total. More than five Critical causes remain fully visible. A compact count identifies omitted High categories without counting their individual findings. Annotations use consistent security-mechanism terms such as `Insecure Output Handling` and `Improper Client Trust`. They omit register IDs, full titles, and finding lists; the report retains the concrete mechanisms and complete register. Asset storage labels require evidenced storage relationships, and the data-flow legend resolves the IDs displayed on edges. Its counts need not sum to the number of unique findings across components.

When validated actor resolution establishes open self-registration, overview diagrams combine anonymous and regular authenticated internet access. Findings retain their authentication prerequisites and privileged actors remain separate. Attacker arrows retain their source actor's identifier; the compact overview uses red for all attack paths. Data-flow identifiers remain available in SVG titles and the detailed diagram.

Figure 1 names an evidenced attack mechanism and action or consequence through optional `attack_paths[].scenario_title`; older fragments retain descriptive class labels. The title must cover the referenced findings without inventing a subtype or impact. A title authored for a narrower finding set cannot describe a path expanded during reconciliation. Optional `data_flows[].diagram_label` summarizes the flow purpose while the canonical `label`, endpoints, protocol, direction, classification, and evidence remain intact through the architecture handoff and YAML export. Protocol names are not restricted to a display catalogue. The legend groups the identities on each drawn edge and uses the component IDs already displayed in the diagram. Distinct payloads and protocols remain distinguishable; longer legacy text remains readable. Applied attacker groupings are explained inside the receiving actor card, including the retained per-finding login and privilege requirements. Asset location and handling may share a legend column with data flows.

The default report figure is the Architecture and Threat Overview. Figure 1 is the detail rendering; only a model that exceeds the overview caps renders Figure 1 as the compact overview described below. The figure labels relevant payloads on connections and retains zone outlines without boundary-verdict badges. A dashed trust-boundary line marks a column gap only when a resolved boundary that is not an internal interface connects endpoints on both sides; an `external` endpoint takes the column of the drawn participant on a flow with the same canonical endpoints. The publication self-check verifies that drawn lines and resolved crossings agree. The overview shows no boundary IDs or per-boundary legend; its header counts trust boundaries with their inferred share, and the report's boundary catalogue remains the complete inventory. The overview omits process-to-process calls that a canonical internal interface places inside one process. Detail views keep boundary IDs on unambiguously matched flows and a boundary legend with endpoints, transition types, existence confidence and verdicts; in-process interfaces without a trust transition appear there without contributing to the trust-boundary count. The figure header total matches the Management Summary tally; node severity counts use the findings-register basis. Grouped participants and connections identify their endpoint groups and omitted-flow counts. A collapsed-participant bar always shows its member and threat counts and names every member in its tooltip. Only beside a compact overview, a linked `figure1-detail.svg` sibling preserves the full flow and boundary-verdict legends; custom report stems apply to both files. Large detail diagrams contain an index, navigable SVG views of connections, and complete catalogues with stable component, scenario, and authentication references. Their publication check verifies every component and catalogue identity, each view's geometry, and local navigation targets. Component titles must not overlap boundary badges. The standalone HTML export exposes the views as separate collapsible images. The PDF export places the detail in an appendix that Figure 1's link targets, and drops the link when the detail cannot be read. A failed detail self-check removes the stale generated detail and omits its link. The renderer never changes canonical topology, evidence, findings, or severity for presentation.

Optional `data_flows[].authentication` carries a receiving-access scheme, scope, and repository file/line evidence through the architecture fragment, boundary-assessment input, and canonical YAML. The architecture producer inspects the implementation; deterministic rendering does not infer a mechanism from names, dependencies, flow prose, or global controls. Missing or incomplete evidence remains unknown. At the controller-owned architecture handoff, an open access into a data component linked to an embedded engine instantiation (SQLite, MarsDB, NeDB or LokiJS) through the component's framework, its paths, or flow evidence near that instantiation records `none` with the instantiation lines as evidence; a declared network engine prevents the link, and producer values stay. No separate authentication requires explicit access-specific evidence, including local embedded calls; it does not by itself establish an exposed service or finding. MFA records checked independent factors, OAuth and OIDC remain distinct, and a signing key alone is not proof of caller key possession. Numbered hexagons identify equivalent methods within the figure; `0` always means no separate authentication and `?` means unknown: the code does not show how the receiver authenticates. Numbered methods follow the canonical presentation order, keep OAuth 2.0 and OpenID Connect variants adjacent, and place other authentication last before unknown. Colour expresses qualified method properties, not implementation effectiveness or a new severity assessment.

An optional `interaction: true` flow denotes a human using a client, not a direct API call. The architecture stage requires its evidence to lie in the client component's own paths; export and rerender of an existing model do not re-check that evidence. Figure 1 labels and describes it on hover as "User input" with its evidence, whatever payload label it carries. A server that delivers client code is a separate flow from that server to the client component. Technical requests originate from their evidenced sender; the renderer never invents an intermediary. Optional `protocol_group` identifies evidenced steps of one integration eligible for endpoint references in the overview. Matching E-labelled rows inside both participants identify the peer and flow direction, with authentication markers only at their receiving access. References retain participant identities, operation-specific authentication, and all member flow IDs. Store accesses, finding-linked flows, and boundary findings cannot be removed merely by assigning a group. Distinct receiving interfaces, protocols, and authentication variants remain distinguishable.

Optional `data_flows[].access_group` describes evidenced alternatives or successive checks at one receiving component. Members retain individual identities, interfaces, authentication evidence and labels; the shared label states conditional applicability. Sender, receiver, protocol and direction agree across members, and sequence steps are consecutive and unique. The overview may share a connection with `/` between alternative methods or `→` between successive checks. It never interprets proximity, names or input order as proof of a relationship. The detail diagram retains the individual operations. Human-to-client accesses and endpoint-reference integrations cannot also be access groups. Invalid groups fail architecture validation; older inventories without grouping remain valid and do not acquire inferred authentication claims.

Figure 2 shares the reconciled scenario numbers and actor groupings of Figure 1 and the Top Threats table. Each row keeps one example finding connected to its actor, attack route, underlying weakness and group impact; each card shows one statement, and the attack step, component and technical consequence stay in the route tooltip. W-references require explicit instance or practice-evidence links to that finding; without one the card states that no register weakness is linked and never substitutes finding prose, and a missing link never implies absence of a weakness. Qualitative business harm belongs to the reported group impact categories. Consecutive routes of one actor and interaction mode share one actor card. Per-finding prerequisites and unproven status survive overview grouping. The in-memory presentation and embedded SVG metadata satisfy `schemas/figure2-diagram.schema.json`; publication checks also verify visible numbers, references, actor coverage and card geometry. Compact excerpts retain complete source text in SVG tooltips and the referenced findings. The report introduces the figure; the image contains column headers without a visible title or subtitle.

## §4h. Trust-boundary catalogue and finding-reference invariant

Trust zones and trust boundaries are different objects. A diagram may draw a
deployment or trust zone as a subgraph. A canonical trust boundary is one
crossing between two endpoints. Only a `resolution_status: resolved` row with
explicit `from` and `to` values may affect adjacency, exposure, analyzer
context, finding links, Figure 1, or effective-severity weighting. Each
endpoint must be the literal `external` or an ID in the finalized component
registry. In particular, external exposure requires the literal endpoint
`from: external`; a missing, prose-shaped, or unknown endpoint never implies
external access.

The canonical v2 row is strict and contains only `id`, `name`, optional
endpoints, `kind`, `assumption`, bounded repository-relative `evidence`,
`confidence`, `resolution_status`, `sources`, and optional
`declaration_key`. A present v2 `trust_boundaries: []` is valid and
authoritative. Legacy fields such as `description`, `enforcement`,
`crossing_enforcement`, `controls`, `trust_level`, and `weakness` are
normalizer inputs only and never survive into canonical output.

`tb-N` IDs are the run-internal boundary identity. The deterministic
normalizer owns allocation through the locked baseline counter. It reuses prior
identity conservatively, never trusts an unmatched current-input ID to raise the
high-watermark, never reuses a retired ID during normal full or incremental
runs, and resets continuity only for `--rebuild`. Sidecars, dispatch context,
diagnostics, STRIDE `boundary_refs[]`, and merge all speak these counter IDs.

The DELIVERED `threat-model.yaml` does not. `build_threat_model_yaml.
renumber_trust_boundaries` renumbers the catalogue to a contiguous `tb-1 … tb-N`
as the last pass before the dump, in ascending counter order — so the §1
catalogue order is unchanged and only the offset disappears (a churned repo
otherwise ships `tb-37 … tb-45` for nine boundaries). The remap covers every
occurrence in the document: catalogue IDs, `boundary_refs[].boundary_id`,
`meta.boundary_selection` ID lists and `focus_reasons` keys, and IDs mentioned
in prose. This mirrors `merge_threats._assign_t_ids` + `_remap_scenario_local_
refs`, which have always numbered delivered `T-NNN` from 1 while the threat
counter runs ahead. Consequence, identical to `T-NNN`: a delivered `tb-N` is
stable only as long as the boundary set is, and a retired number can be reused
by a different boundary in a later run. Cross-run identity therefore never runs
through the delivered number — `_assign_ids` re-identifies by `declaration_key`,
authored ID against the prior model's own numbering, exact `(from,to,name)`, then
endpoints — and no artifact diffs boundaries by ID.

The internal `.dispatch-context/trust-boundary-selection.json` audit conforms to
`schemas/trust-boundary-selection.schema.json` at production and consumption.
Its per-component shape is the same closed shape delivered under
`meta.boundary_selection.components`. `inherited_from` names the canonical
containing component whose candidates were used when a selected nested
component had no boundary candidates of its own; it is provenance only and does
not change boundary identity or selection limits.

Repository declarations in `.appsec/trust-boundaries.yaml` are untrusted,
data-only, additive input. They cannot disable detected rows, set confidence,
claim that a control is effective, affect ratings by themselves, choose paths
or commands, or suppress a finding. Declaration-only rows are at most `inferred`.
Conflicting endpoints become non-semantic `conflicted` rows. A malformed file
is rejected as a whole without discarding detected boundaries.

Analyzer candidacy is separate from reference validity and deliberately wider. A
component is offered a resolved crossing when it is an endpoint or owns the cited
evidence file, so the component implementing an egress is analyzable without
being an endpoint. It inherits its container's candidates only when it has none
of its own. Confidence orders candidates; it never gates them. Each component is
capped by depth (`BOUNDARY_CANDIDATE_LIMITS`), and quick depth admits `primary`
focus only. No resolved crossing may be silently uncovered by those caps: it is
redistributed to a component that can carry it, or reported as a gap.

`boundary_refs[]` is optional finding traceability, not finding evidence and
not a consolidation key. Each reference must target a resolved, confirmed
canonical row, be adjacent to its required `origin_component_id`, repeat only
evidence locations already owned by the finding, and use a unique
`(boundary_id, origin_component_id)` pair. At most two references survive.
Exact-identity deduplication retains a deterministic subset, preferring the
survivor's origin and distinct origins; semantic consolidation stays separate
when its union would exceed the cap.
A surviving reference is rendered as a link: the §1 catalogue's row cap bounds
unreferenced rows only, so every referenced row keeps its `#tb-N` anchor.
Fresh analyzer references must also come from that component's prepared
candidate file. Invalid optional references are removed at the merge, builder,
or post-reclassification trust boundary while the finding remains intact.
Adding or removing a reference cannot change likelihood, impact, raw risk,
CVSS, mitigation priority, or `architectural_violation`. Deterministic triage
owns the only severity exception: a validated finding-level reference to a
resolved, confirmed `external → origin_component_id` crossing may raise
effective severity by one band, capped at High, before the CWE cap and
Critical-criteria gate. The finding must not be `refuted` or `ambiguous`;
multiple eligible references still cause one step. Every actual change is
persisted as a `severity_reconciliation` flag carrying the eligible `tb-N`
IDs, and removing the cause clears the elevation and flag.

The field ownership matrix is:

| Contract surface | Producer / owner | Validation | Semantic consumers |
|---|---|---|---|
| Final component identity | `finalize_component_inventory.py` after Phase 3 | components schema, contained repository path/glob resolution, and finalization receipt/fingerprint | data-flow producer, Stage-1b input builder, manifest drift gate |
| Persisted topology | Phase-3 `.data-flows.json` producer | data-flow schema plus existing repository evidence, dynamic endpoint, and fingerprint checks | Stage-1b input builder and YAML builder |
| Deterministic crossing signals | `build_trust_boundary_assessment_input.py` | assessment-input schema and bounded source validation | dedicated boundary agent only |
| Untrusted boundary candidates | `appsec-trust-boundary-analyst` | candidate schema plus disposition/foreign-key gate | `prepare_trust_boundary_context.py promote` only |
| Repository declarations | Repository author | `schemas/trust-boundaries-repo.schema.yaml` plus whole-file rejection | Normalizer merge only |
| Canonical sidecar, stable IDs, resolution diagnostics, and signal coverage | `prepare_trust_boundary_context.py promote/normalize`, `reserve_ids.py`, `baseline_state.py` | canonical, diagnostics, and coverage schemas | YAML builder, context selector, cross-repo slicer, run-issue aggregator |
| Component candidate slices | `prepare_trust_boundary_context.py contexts` after final component selection | Structural cap and canonical-source checks | STRIDE analyzer through a Group-C path |
| Finding references | STRIDE analyzer; merge/builder/reclassifier preserve or remove | STRIDE/merged/output schemas plus the shared boundary-reference validator and `validate_intermediate.py` post-checks | Composer, deterministic triage, query, SARIF |
| Canonical YAML catalogue | `build_threat_model_yaml.py` | `schemas/threat-model.output.schema.yaml` | Composer, Figure 1, query, SARIF, rerender |
| Report catalogue and cards | `compose_threat_model.py` | compose/QA anchor and cross-reference tests | Human readers |
| Runtime and permissions | `runtime_cleanup.py`, `data/required-permissions.yaml` | cleanup and permission tests | `.dispatch-context/**`, sidecars, optional repository input |

Legacy pregenerators may display unresolved rows for compatibility but must not
mint IDs or feed semantic consumers. Both Figure-1 implementations,
cross-repository slicing, query, SARIF, post-build component
reclassification, rerender, cleanup, and permission tests are part of this
contract and must change atomically when the row shape changes.

The canonical YAML exposes assessment mode, not cleanup mode. An operational
`--rebuild` therefore writes `meta.mode: full` and a `changelog[].mode: full`
entry; its invocation and changelog note retain the explicit rebuild audit.

Context-v2 dispatch vocabulary is one logical contract even where standalone
schemas repeat it because their runtime validators do not share an external
reference registry. Analysis depth, threat-count bands, lens IDs, component
security context IDs, and routing projector enums must remain identical across
the action, manifest, component-plan, projection, effective-plan, and binding
schemas. `tests/test_schemas.py` is the cross-schema drift gate; a future shared
definition may replace the repetitions only when every validator resolves it
locally and fail-closed without network access.

## §4i. Requirements compliance export invariant

When `.requirements.yaml` is configured, strict Stage-2 composition must assess every catalog requirement exactly once before publication completes. `emit_requirement_trace_to_model.py` is the post-compose producer for both `requirements_compliance` and the completed mitigation requirement trace; missing, malformed, incomplete, or schema-invalid input blocks the compose tail without rewriting `threat-model.yaml`.

The exported status vocabulary is `PASS`, `FAIL`, `PARTIAL`, `UNVERIFIABLE`, and `N/A`; `ANTI-PATTERN` normalizes to `FAIL` and `NOT OBSERVABLE` normalizes to `UNVERIFIABLE`. The five counters must sum to `total`, the row count must equal `total`, requirement IDs must be unique, and row priority comes from the configured catalog rather than the LLM-authored table. `schemas/threat-model.output.schema.yaml` owns the row shape and `validate_intermediate.py` owns the cross-field reconciliation.

## §4j. Export traceability invariant

`threat-model.yaml` is the canonical machine-readable trace. New runs persist an explicit `business_context_trace` even when context was skipped or absent, a complete `abuse_case_analysis` after the deterministic verifier fold, and `requirements_provenance` whenever a catalog was assessed. These blocks carry bounded semantic values and hashes, never raw business-context prose or rendering tokens.

An optional boolean `impact_is_material` accompanies declared `impact_if_compromised` in analyst, dispatch, and component business context. False records an explicit no-material-harm declaration and its stated conditions; absence remains unknown or legacy context. The canonical component coverage preserves that boolean alongside the impact field name. Findings covered by explicit no-harm context count as context-applied without receiving an impact-based priority bonus. Independently declared sensitive assets and obligations remain material, and technical findings and severity rules stay authoritative.

The canonical verdict optionally carries `business_context_note`, a deterministic disclosure of the component scope with explicitly declared no material business harm. The Management Summary renders the same note. It does not lower technical finding severity or the verdict concern level, and unknown context never produces it.

Every finding, mitigation, requirement, and abuse-case reference inside those blocks must resolve against the same YAML document. `validate_intermediate.py` owns this reconciliation, and a producer that adds or changes canonical trace data validates the updated document before replacing the last valid model.

Threat Dragon has no native structures for these dimensions. Its exporter attaches applicable trace to the existing finding and mitigation text fields and reports counted omissions; it never creates a second threat merely to represent an abuse chain or requirement.

## Finding severity policy

Individual `risk` is constrained by the applicable CWE ceiling before merge finalization and canonical YAML construction. When a policy corrects the analyst rating, `risk_before_policy` preserves that rating for audit. It never contributes to ranking, counts or exported severity. CVSS and matrix consistency compare the original assessment when a policy correction exists; a policy ceiling does not rewrite the CVSS score.

New merged artifacts carry `severity_policy_version: 1` and their validation enforces these ceilings. Historical merged artifacts without the marker remain readable; YAML construction applies the policy before any derived register or export. Final YAML validation enforces the ceilings regardless of input age.

`effective_severity` describes contextual prioritization and remains subject to the CWE ceiling. A pattern match alone never establishes a viable attack chain. Only fully viable verified abuse cases may supply chain elevation, and a Critical exception requires a Critical keystone relationship. Missing or refuted required members cannot justify another member's elevation. Register, summary and exports continue to use the corrected individual risk. Artifact gates reject remaining policy violations without mutating their input.

An abuse case's combined risk is the highest policy-rated individual risk among its linked findings. Verification establishes the path without adding a severity level. A verified chain may raise a weaker member's contextual priority to the risk already established by another member, subject to the existing ceilings. Report cases are grouped by verification status and prioritized within each group; their stable IDs are identifiers, not ranks. The Markdown, render sidecar and canonical abuse-case export preserve the same case order. Candidate dispatch order is provisional and never suppresses a candidate or establishes a finding.
