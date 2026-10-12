# Application security assessment concept

Status: discussion draft, 2026-10-12. This proposal does not change approved requirements, record an accepted technical decision, or authorize implementation.

The proposed main workflow is **Application Security Assessment**, invoked through `/appsec-advisor:assess-security`. Its result is an **Application Security Assessment Report**, saved as `security-assessment.md` with canonical data in `security-assessment.yaml`. Threat modeling remains an analysis method and part of the result. A later extension could explicitly compare selected requirements and design documents with implementation evidence.

## Purpose and terminology

The current name emphasizes the threat model even though the report also evaluates security architecture, describes systemic weaknesses, records concrete findings, and recommends mitigations. The proposed terminology names the overall assessment and its deliverable. It also accommodates multiple evidence sources without implying that reading a document verifies its implementation.

| Term | Proposed meaning |
|---|---|
| AppSec Advisor | The existing plugin and product name. |
| Application Security Assessment | The bounded analysis of an application's security using the sources admitted for that run. |
| Application Security Assessment Report | The human-readable result, including scope, evidence, limitations, findings, and recommendations. |
| Assessment data | The canonical structured result consumed by renderers and follow-on tools. |
| Threat model | The representation of assets, actors, flows, trust boundaries, threats, and protection assumptions within the assessment. |
| Threat modeling | A method used to investigate how the system can be attacked. STRIDE remains relevant. |
| Security architecture assessment | The assessment of protection mechanisms and architectural weaknesses. |
| Requirements assessment | The comparison of applicable security expectations with available evidence. |

“Security assessment report” is an established term for documenting findings and corrective recommendations in the [NIST glossary](https://csrc.nist.gov/glossary/term/security_assessment_report). [OWASP SAMM Architecture Assessment](https://owaspsamm.org/model/verification/architecture-assessment/) examines architecture against security requirements and threats. These support the terminology; they do not imply that this plugin implements a particular assessment standard or certification.

Suggested English description: “Assess application security across requirements, architecture, and implementation.” Suggested German description: “Sicherheitsanalyse auf Basis von Anforderungen, Architektur und Implementierung.” Use the broader description only when those sources are supported. Each report names the sources actually analyzed.

Avoid making “code-based” part of the permanent product name. Code remains an important source, but requirements, design intent, configuration, and declarations answer different questions. “Code-informed” can describe the current approach without becoming the umbrella term.

## Current capabilities and the proposed extension

The existing product is an application to evolve, not a new pipeline to replace. The distinction between renaming and additional analysis is essential for compatibility and for an honest capability description.

| Area | Current basis | Proposed treatment |
|---|---|---|
| Repository assessment | `REQ-PUR-001` and `REQ-PUR-002` cover code, configuration, design assumptions, and missing controls. | Keep the current assessment semantics while changing the public name. |
| Report content | The [section registry](../../data/sections-contract.yaml) already includes security architecture, weaknesses, findings, abuse cases, and mitigations. | Retain this content; the name change alone does not require a new chapter structure. |
| Canonical data | `REQ-RPT-006` names canonical YAML; the composer consumes `threat-model.yaml`. | Rename the public basename to `security-assessment.yaml`; do not replace YAML with JSON. |
| Business context | `REQ-BIZ-*` separates declared context from evidence and records its use. | Preserve these distinctions when adding document sources. |
| Security requirements | The assessment accepts a configured catalog; `audit-security-requirements` performs a dedicated repository audit. | Reuse catalog resolution and assessment machinery without claiming that linked findings alone establish complete compliance. |
| Requirements harvesting | The [harvester](../harvester.md) produces a YAML catalog and can export functional sources as OpenSpec Markdown or SpecDD. | Do not confuse producing specification files with assessing arbitrary specification files. |
| Design analysis | [analyze-threats](../../skills/analyze-threats/SKILL.md) already accepts design text or a design file and can work without code under `REQ-ANA-010`. | Preserve this workflow rather than adding a second design-only engine to the first rename release. |
| Project specification comparison | The existing interfaces cited above do not establish a general full-assessment contract for arbitrary `specs/` documents or `requirements.md`. | Treat explicit ingestion, provenance, coverage, and implementation comparison as a separate feature. |

The name “Assessment” does not promise a pentest, runtime verification, exhaustive vulnerability discovery, certification, or a release approval. The existing limitation that production-only controls cannot be verified from repository evidence remains relevant.

## Proposed skill names

Use an action for the main skill and a consistent assessment noun for consumers. The table describes a target naming scheme, not commands available today.

| Current skill | Proposed public name | Responsibility |
|---|---|---|
| `create-threat-model` | `assess-security` | Run the assessment and produce the report. |
| `update-threat-model` | `update-security-assessment` | Explain how to update an existing assessment; retain its current non-mutating helper behavior. |
| `show-threat-model` | `show-security-assessment` | Present an existing report. |
| `ask-threat-model` | `ask-security-assessment` | Answer questions using the assessment. |
| `review-threat-model` | `review-security-assessment` | Review and triage its findings. |
| `export-threat-model` | `export-security-assessment` | Generate supported exports from an existing result. |
| `publish-threat-model` | `publish-security-assessment` | Publish using the existing explicit workflow and checks. |
| `threat-model-health` | `security-assessment-health` | Inspect freshness, retained artifacts, and active-run state. |
| `eval-threat-model` | `eval-security-assessment` | Evaluate result quality for development and testing. |

Keep `analyze-threats`, `audit-security-requirements`, `verify-requirements`, `authnz-review`, and `security-score` as distinct specialized workflows. Their scopes do not become full assessments because the main workflow is renamed. Keep `status` and run-diagnostic commands unchanged.

Legacy skill names should be thin compatibility entry points into the same implementation. Normalize the selected operation before routing, permission checks, packaging checks, and headless execution. An alias must not create a second orchestration path or bypass a disabled capability. The initial renamed release should retain old names; their eventual removal needs a separately announced compatibility boundary.

## Proposed delivered files

Keep the default output directory `docs/security/`. Change the common basename while preserving established formats and optional export behavior.

| Current artifact | Proposed artifact |
|---|---|
| `threat-model.md` | `security-assessment.md` |
| `threat-model.yaml` | `security-assessment.yaml` |
| `threat-model.pdf` | `security-assessment.pdf` |
| `threat-model.html` | `security-assessment.html` |
| `threat-model.sarif.json` | `security-assessment.sarif.json` |
| `threat-model.threatdragon.json` | `security-assessment.threatdragon.json` |
| `threat-model.figure1.svg` and related figures | Corresponding `security-assessment.*` figure names, with references updated together. |
| `threat-model-changelog.md` and `.jsonl` | Corresponding `security-assessment-changelog.*` history files when that migration is supported. |
| `pentest-tasks.yaml` | Keep the current name and restricted publication behavior. |

The full report title would be “Application Security Assessment — Project name”. A dedicated `security-assessment.json` is not part of this proposal: the existing structured contract is YAML, and SARIF already has its own JSON representation. Adding another full representation would need a separate consumer need and fidelity contract.

Keep `business-context.md`, source specifications, requirements catalogs, and `requirements.md` as input documents. Keep `SECURITY.md` for the repository's security information, optionally linking to the assessment. Do not generate a separate `threat-model.md` containing a second independently maintained report. A compatibility copy of the same report is a migration mechanism, not a second analysis product.

Internal names such as schema files, Python modules, cache directories, and stage identifiers do not need cosmetic renaming. In particular, renaming a public YAML file does not require changing schema IDs or the `threats` collection. Preserve public finding anchors and triage identity across a name-only migration.

## Requirements and specifications as analysis sources

The proposed extension compares three views: what is required, how the design proposes to achieve it, and what the implementation evidences. It focuses on security-relevant behavior; it does not become a general functional acceptance checker.

| Source | What it can establish | What it cannot establish alone |
|---|---|---|
| Project requirements | Declared behavior, constraints, protected business operations, and acceptance expectations. | That a control exists or works. |
| Architecture and design specifications | Intended components, flows, boundaries, and protection assumptions. | The architecture currently deployed or implemented. |
| Code and configuration | Implemented mechanisms and security-relevant paths within the inspected scope. | Production behavior or controls outside that scope. |
| Organization security catalog | Applicable security expectations from the configured source. | Fulfillment merely because no linked finding exists. |
| Business and operator declarations | Stated purpose, critical assets, and assumptions. | Verification, policy exemptions, or acceptance of risk. |

Start with explicit local Markdown and the existing structured catalog format. A user could select `requirements.md`, individual files below `specs/`, or architecture documents. The filename itself gives no authority. Discovery may suggest candidates, but should not silently treat every Markdown file as an approved specification. A future CLI or schema-validated configuration interface should distinguish project documents from the existing `--requirements` catalog input instead of overloading that flag.

Track each admitted source by repository or source identity, relative path, content fingerprint, role, and revision where available. Track extracted statements with their source locations and original identifiers. Preserve separate identities when two repositories use the same path or requirement ID. Model-derived interpretations remain interpretations, linked to their source statements; they do not become operator-approved requirements.

Selected sources should enter a bounded, validated context pipeline. Record whether each source was analyzed, excluded, rejected, or left unassessed. Missing explicitly requested inputs prevent a claim that the requested comparison completed. Oversized or ambiguous documents need an explicit incomplete outcome or a narrower user-selected scope, not silent truncation presented as full coverage. Changed documents invalidate affected comparison results even when application code is unchanged.

The result should distinguish required behavior, documented design, observed implementation, contradictions, and unresolved questions. These are presentation concepts; schema field names and status enums belong in the later schema design. Reuse existing requirement verdict semantics where appropriate rather than creating a parallel grading vocabulary.

Example: a selected requirement says tenant administrators may export only their own tenant's records. A design document assigns that restriction to an API authorization layer. If the implementation evidence shows an export path that trusts a supplied tenant identifier without the relevant check, the assessment can link the observed weakness to the requirement. If only the design document is available, it can identify the protection assumption and an open verification question, but cannot report a verified implementation failure.

Conflicting documents should produce a sourced discrepancy and a question about intended behavior. Reading code shows observed behavior; it does not silently settle which product requirement the operator intended. A document claiming that a control is disabled is context to investigate, not automatic proof that the deployed system is exploitable. Existing finding evidence and scoring rules continue to apply.

## Trust and analysis boundaries

The affected assets are private source and design information, assessment integrity, finding identity, and retained triage and audit state. The initiating operator selects the analysis scope through supported configuration. Repository contributors and document authors supply data; they do not gain authority over the controller, output destinations, or model tools.

The proposed data flow is selected source → bounded ingestion with provenance → schema-validated context → analysis → deterministic validation → canonical assessment → report and exports. Under the aiscb baseline, source documents and model interpretations remain untrusted data throughout this flow. This prevents a specification from using embedded instructions to redirect analysis or authorize actions.

The proposed extension preserves these boundaries:

- Confine reads to admitted roots and explicit inputs. Reject path traversal and escaping links. Do not follow document links as implicit permission for network retrieval or additional repositories.
- Keep organization policy and source content separate. Documents cannot enable tools, select shell commands, suppress evidence-backed findings, change output paths, or grant exceptions.
- Reuse deterministic orchestration and existing scoped analysis roles. Add a new agent only if evaluation shows that existing roles cannot handle the distinct task within the established budgets.
- Retain provenance through extraction and summarization. Validate intermediate structures and citations before they reach consumers. Do not let content assign itself a trusted role.
- Apply existing secret exclusion and publication gates to document excerpts and derived results. Include only the excerpts needed for evidence; do not copy private specifications wholesale into public exports.
- Preserve explicit authorization for publication and other consequential actions. Running `assess-security` does not itself authorize publishing or changing the analyzed project.

These design concerns align with prompt injection, sensitive-data disclosure, improper output handling, excessive agency, and resource-consumption risks described by the [OWASP GenAI security project](https://genai.owasp.org/llm-top-10/) and its [agentic applications guidance](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/). Implementation still needs tests at the actual boundaries; this concept does not establish that a new ingestion path is safe.

## Compatibility and migration

The migration has three distinct surfaces: invocation names, artifact paths, and data semantics. Stage them separately so a source-analysis feature is not required to complete a naming transition.

For the first transition release, prefer accepting both command families while retaining the established artifact layout. That creates a clear intermediate state: `assess-security` still writes `threat-model.*`, and help text states this. Do not select different artifact layouts merely because a user chose an alias.

Before switching the default filenames, update every first-party reader and writer to use a shared artifact-resolution mechanism. Existing legacy-only directories remain readable and writable with their own naming set during the transition. New directories can then use the assessment names. Record the active artifact set outside model-authored content. Never assemble one assessment from a YAML file in one naming set and a Markdown file in another.

When both naming sets exist, use validated run identity and artifact provenance to establish whether they represent the same result. If the relationship is ambiguous or contradictory, stop the affected operation with a concrete migration instruction. File modification time alone is not sufficient. A stale success report from a previous run cannot satisfy completion of a new run.

Explicit migration should check for an active run, validate the source set, preserve history and triage, update relative figure links, and publish a coherent new artifact set. It should leave a recoverable prior set until the new set is validated. Resume an interrupted legacy run under its recorded layout rather than renaming files mid-run. Implement the transaction and rollback behavior in deterministic code.

Avoid permanent dual writes. If an external consumer still needs the old filenames, a bounded compatibility export may produce copies from the same validated run, with provenance and consistent links. Such copies are not writable canonical inputs. Document the supported release window before removing legacy reads or aliases; this draft proposes no removal date.

Optional exports retain their current meaning. SARIF contains applicable findings, not the complete assessment. Threat Dragon represents the threat-model subset and remains subject to its documented information loss. A rename does not change that limitation. Publishing and cleanup use explicit artifact sets; a broader wildcard must not accidentally publish private sidecars or pentest tasks.

## Implementation impact

The following locations establish concrete change surfaces. They are an initial impact map; implementation work still needs `check_specs.py --for` for every changed path and the returned contracts.

| Surface | Current locations | Expected work |
|---|---|---|
| Public skills and help | `skills/create-threat-model/`, related skill directories, `skills/help/`, `README.md` | Add canonical names and thin aliases; update descriptions, invocation examples, and completion guidance. |
| Packaging policy | `scripts/runtime/skill_policy_gate.py`, `scripts/package_internal_plugin.py`, `docs/internal-plugin-packaging.md`, decision `EX-3` | Handle the currently mandatory `create-threat-model` capability and aliases without permitting policy bypass. An approved decision change precedes changing the mandatory name. |
| Routing and headless execution | `scripts/orchestrator/orchestration_controller.py`, `scripts/runtime/resolve_config.py`, `scripts/run-headless.sh` | Normalize commands; make output detection, compose recovery, success gates, update, and resume use the selected artifact set. |
| Canonical result and rendering | `scripts/model/build_threat_model_yaml.py`, `scripts/renderers/compose_threat_model.py`, `data/sections-contract.yaml`, `templates/`, `schemas/threat-model.output*.schema.yaml` | Change visible titles and destinations together. Introduce versioned source-comparison data only in the later feature. |
| Report authoring and QA | `agents/`, `agents/shared/`, fragment schemas and validators | Align terminology; keep evidence rules. If new report sections are needed, change the registry, producers, templates, composer, schemas, and QA atomically. |
| Exports and post-run consumers | `scripts/exporters/`, export, ask, review, show, publish, and health skills | Resolve both supported layouts; preserve finding anchors, triage links, relative assets, and explicit paths. |
| Requirements integration | `scripts/requirements/`, `scripts/contexts/build_requirements_contexts.py`, `schemas/requirements-*.schema.*` | Keep catalog semantics; add explicit project-document roles, provenance, comparison coverage, and validation through appropriate contracts. |
| Context routing | `data/context-routing-catalog.yaml`, `data/context-routing-bindings.json`, `data/context-budgets.yaml`, context builders | Route only relevant document material and account for its budget. Measure added work before changing limits. |
| Related and combined repositories | `scripts/shared/assessment_sources.py`, `scripts/runtime/multi_repo_scope.py`, related-repository readers | Resolve legacy imported model paths and preserve repository-qualified evidence and source identities. |
| Retained state and permissions | `scripts/runtime/runtime_cleanup.py`, cleanup and audit-artifact contracts, `data/required-permissions.yaml` | Preserve baseline, history, audit, and triage state; update declared command and file targets where needed. |
| Distribution and documentation | `.claude-plugin/`, `docs/threat-modeler.md`, headless and export guides, examples | Present the new workflow consistently; document compatibility. Coordinate separately with external launchers and CI templates. |
| Regression evidence | `scripts/run_tests.py`, skill, resolver, controller, schema, compose, export, publication, and cleanup tests | Update only affected routes and guards; prove compatibility rather than replacing old fixtures to hide breakage. |

The [approved requirements](../../specs/requirements.md) need review around `REQ-PUR-*`, `REQ-MOD-*`, `REQ-REQ-001`, `REQ-BIZ-*`, `REQ-RPT-*`, `REQ-ANA-*`, `REQ-TRU-*`, and `REQ-EVO-003`. The [decision catalog](../internal/decisions.md) includes relevant artifact, context, and packaging choices, notably `RA-1`, `RA-3`, `RA-6`, and `EX-3`. Wording changes to requirements or decisions require the operator to confirm the exact text and its meaning before those files are edited. This draft identifies the affected promises without replacing their wording.

## Delivery sequence and acceptance evidence

Deliver the name change first, then document comparison. Each work package should leave a usable plugin and an explicit account of what is supported.

| Package | Deliverable | Acceptance evidence |
|---|---|---|
| 1. Terminology and command compatibility | New main and consumer names with a shared implementation; established files initially retained. | Old and new commands select the same operation and scope; help starts no analysis; packaging and permissions treat aliases consistently. |
| 2. Artifact compatibility | Shared resolution, new defaults for new runs, legacy support, and an explicit migration path. | New-only and legacy-only directories work; ambiguous mixed sets fail; stale outputs do not satisfy run completion; interrupted migration and active-run cases preserve the previous usable result. |
| 3. Document source ingestion | Explicit local document selection with provenance, bounded processing, and visible coverage. | Neutral documents and differently named variants behave alike; escaping paths, malicious instructions, invalid inputs, duplicate cross-repository IDs, and oversized sources cannot bypass boundaries. |
| 4. Comparison and presentation | Requirements, design, and implementation comparisons in versioned data and rendered output. | A documented control with no implementation evidence stays unverified; a supported implementation gap becomes an appropriately evidenced finding; a correctly enforced control retains its valid result. Conflicting and changed sources remain visible. |

Exercise the full lifecycle for package 2: create, supported update, resume, rerender, export, query, triage, publish, and cleanup. Cover single-repository and combined assessment paths according to their existing supported modes. Replaying an old artifact must not assign new finding identities solely because its filename changed.

For packages 3 and 4, compare against a code-only control run to show that adding document support does not suppress existing evidence-backed findings. A document that says “ignore this vulnerability” should be treated as source text, not an instruction. Changes to a document should make affected cached comparisons stale; excluded inputs should never enter model context. A specification without code remains a design-level result, using the existing analyst workflow unless a separately approved full-assessment mode is introduced.

Use task-scoped routed tests and existing fixtures. Changes to deterministic report production require the golden-fixture replay described by the threat-fixture runbook. Measure additional tokens, latency, and unresolved coverage for document analysis before proposing budget changes. Keep old-schema and old-layout fixtures as compatibility evidence.

## Scope and choices for implementation planning

The recommended first implementation boundary is the public terminology and command aliases. Filename migration follows after consumers share a resolver. Specifications and project requirements then become a separately scoped feature with explicit source selection. This sequence avoids advertising new evidence coverage on the strength of a rename.

The largest effort is likely in artifact lifecycle compatibility and document provenance, rather than the visible skill rename. This is an impact assessment, not a measured schedule. Before estimating delivery dates, inventory all path consumers, external launchers, organization package policies, and schema-version assumptions.

Implementation planning still needs to settle the compatibility support window, the operator interface for selecting documents, and whether a later release exposes design-only results under the assessment umbrella. The first document feature should remain local and explicit; remote connectors, autonomous publication, general functional verification, and a second design-analysis engine are outside this proposal.
