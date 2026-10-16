# Application security assessment concept

Status: discussion draft, 2026-10-13. This proposal does not change approved requirements, record an accepted technical decision, or authorize implementation.

The proposed main workflow is **Application Security Assessment**, invoked through `/appsec-advisor:create-security-assessment`. Its result is a **Security Assessment Report**, saved as `security-assessment.md` with canonical data in `security-assessment.yaml`. The report subtitle makes its focus on security architecture, threats, and requirements implementation explicit. Threat modeling remains an analysis method and part of the result. This release changes commands, report titles, file names, and the default storage location together. It preserves the analysis content and removes the repository-publication skill. New project-document analysis and a design-based threat-modeling workflow are outside this proposal's implementation scope.

## Purpose and terminology

The current name emphasizes the threat model even though the report also evaluates security architecture, describes systemic weaknesses, records concrete findings, and recommends mitigations. The proposed terminology names the existing overall assessment and its deliverable without promising additional analysis capabilities.

| Term | Proposed meaning |
|---|---|
| AppSec Advisor | The existing plugin and product name. |
| Application Security Assessment | The bounded analysis of an application's security using the sources admitted for that run. |
| Security Assessment Report | The human-readable result, including scope, evidence, limitations, findings, and recommendations. Its subtitle identifies the architectural focus. |
| Assessment data | The canonical structured result consumed by renderers and follow-on tools. |
| Threat model | The representation of assets, actors, flows, trust boundaries, threats, and protection assumptions within the assessment. |
| Threat modeling | A method used to investigate how the system can be attacked. STRIDE remains relevant. |
| Security architecture assessment | The assessment of protection mechanisms and architectural weaknesses. |
| Requirements assessment | The comparison of applicable security expectations with available evidence. |

“Security assessment report” is an established term for documenting findings and corrective recommendations in the [NIST glossary](https://csrc.nist.gov/glossary/term/security_assessment_report). [OWASP SAMM Architecture Assessment](https://owaspsamm.org/model/verification/architecture-assessment/) examines architecture against security requirements and threats. These support the terminology; they do not imply that this plugin implements a particular assessment standard or certification.

Suggested English description: “Assess application security from source code and configuration.” Suggested German description: “Sicherheitsanalyse auf Basis von Quellcode und Konfiguration.” The existing optional assessment of a configured security requirements catalog remains available. Each report names the sources actually analyzed.

Avoid making “code-based” part of the permanent product name. Describe the current evidence basis in the workflow description and report rather than encoding it in the product name.

## Current capabilities to preserve

The existing product is an application to evolve, not a new pipeline to replace. The distinction between renaming and additional analysis is essential for compatibility and for an honest capability description.

| Area | Current basis | Proposed treatment |
|---|---|---|
| Repository assessment | `REQ-PUR-001` and `REQ-PUR-002` cover code, configuration, design assumptions, and missing controls. | Keep the current assessment semantics while changing the public name. |
| Report content | The [section registry](../../data/sections-contract.yaml) already includes security architecture, weaknesses, findings, abuse cases, and mitigations. | Retain this content; the name change alone does not require a new chapter structure. |
| Canonical data | The [export traceability invariant](../internal/contracts/schema-invariants.md#4j-export-traceability-invariant) defines canonical YAML; `REQ-RPT-006` requires preserved assessment traceability. | Rename the public basename to `security-assessment.yaml`; do not replace YAML with JSON. |
| Business context | `REQ-BIZ-*` separates declared context from evidence and records its use. | Preserve the existing context handling and evidence distinctions. |
| Security requirements | The assessment accepts a configured catalog; `audit-security-requirements` performs a dedicated repository audit. | Preserve catalog resolution, assessment statuses, and report coverage without adding arbitrary project-document comparison. |
| Requirements harvesting | The [harvester](../harvester.md) produces a YAML catalog and can export functional sources as OpenSpec Markdown or SpecDD. | Do not confuse producing specification files with assessing arbitrary specification files. |
| Design analysis | [analyze-threats](../../skills/analyze-threats/SKILL.md) already accepts design text or a design file and can work without code under `REQ-ANA-010`. | Preserve this workflow rather than adding a second design-only engine to the first rename release. |
| Project specification comparison | The existing interfaces cited above do not establish a general full-assessment contract for arbitrary `specs/` documents or `requirements.md`. | Outside this proposal; add no document-discovery dialog or new document-analysis input. |

The name “Assessment” does not promise a pentest, runtime verification, exhaustive vulnerability discovery, certification, or a release approval. The existing limitation that production-only controls cannot be verified from repository evidence remains relevant.

## Proposed skill names

Use an action for the main skill and a consistent assessment noun for consumers. The table describes a target naming scheme, not commands available today.

| Current skill | Proposed public name | Responsibility |
|---|---|---|
| `create-threat-model` | `create-security-assessment` | Run the assessment and produce the report. |
| `update-threat-model` | `update-security-assessment` | Explain how to update an existing assessment; retain its current non-mutating helper behavior. |
| `show-threat-model` | `show-security-assessment` | Present an existing report. |
| `ask-threat-model` | `ask-security-assessment` | Answer questions using the assessment. |
| `review-threat-model` | `review-security-assessment` | Review and triage its findings. |
| `export-threat-model` | `export-security-assessment` | Generate supported exports from an existing result. |
| `publish-threat-model` | Removed; no assessment replacement. | Retire the workflow that makes generated files trackable and commits them to the analyzed repository. |
| `threat-model-health` | `security-assessment-health` | Inspect freshness, retained artifacts, and active-run state. |
| `eval-threat-model` | `eval-security-assessment` | Evaluate result quality for development and testing. |

Keep `analyze-threats`, `audit-security-requirements`, `verify-requirements`, `authnz-review`, and `security-score` as distinct specialized workflows. Their scopes do not become full assessments because the main workflow is renamed. Keep `status` and run-diagnostic commands unchanged.

The renamed release does not retain the old assessment commands as aliases. Reserve `create-threat-model` for the later design-based workflow. Announce the command changes as an incompatible release boundary and update first-party invocations, headless launchers, packaging policies, and permissions together. Existing automation must explicitly select `create-security-assessment`; it must never silently start a future design-only workflow. Removal of command aliases does not authorize deleting existing reports or their retained state.

## Proposed delivered files

Use an application-specific directory outside the analyzed repositories as the default assessment destination. On Linux, place it under `$XDG_DATA_HOME/appsec-advisor/assessments/<application-id>/`, with `~/.local/share` as the base when `XDG_DATA_HOME` is unset or empty. Follow the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir/latest/) for the base directory; the `appsec-advisor/assessments/` layout is this product's choice, not an assessment-industry standard. Preserve `--output` as an explicit destination override.

Keep the report, canonical YAML, figures, retained triage, and assessment history together in that application directory. These are durable data, not disposable cache. Use a stable application identity so unrelated projects with the same display name cannot share results or overwrite one another. A combined assessment has its own identity for the selected application scope. The identity and lookup mechanism still need an implementation contract; model-authored names and repository content cannot select arbitrary write paths. Non-Linux default locations remain to be specified before claiming equivalent platform support.

All assessment consumers, including show, ask, review, health, export, and specialized analysis that uses an existing assessment, resolve the same application destination. Completion output links to the generated report. A missing or ambiguous association cannot silently select another application's assessment. The default run keeps generated artifacts outside the source checkout and does not need publication exceptions in that checkout's `.gitignore`.

Change the common basename while preserving established formats and optional export behavior.

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

The proposed title and subtitle are:

> **Security Assessment Report — Project name**
>
> Analysis of security architecture, threats, and requirements implementation

The German subtitle is “Analyse von Sicherheitsarchitektur, Bedrohungen und Anforderungsumsetzung”. The broad title covers the overall result, while the subtitle makes the architecture focus visible alongside concrete findings and requirements assessment. “Requirements implementation” refers to the existing configured security catalog, not a comparison with arbitrary project specifications. If catalog assessment is outside a run's scope, omit requirements implementation from its subtitle and state that limitation in the scope section.

A dedicated `security-assessment.json` is not part of this proposal: the existing structured contract is YAML, and SARIF already has its own JSON representation. Adding another full representation would need a separate consumer need and fidelity contract.

Keep the existing business-context and requirements-catalog inputs available. Moving generated output does not implicitly relocate repository-owned inputs or introduce new input roles for `requirements.md` or files below `specs/`. Audit existing input discovery and persistent operator answers separately so they remain available after the output move. Keep `SECURITY.md` for the repository's security information; a shared assessment can be linked through a team-accessible location rather than another user's local data path. Do not generate a separate `threat-model.md` containing a second independently maintained assessment report.

Internal names such as schema files, Python modules, cache directories, and stage identifiers do not need cosmetic renaming. In particular, renaming a public YAML file does not require changing schema IDs or the `threats` collection. Preserve public finding anchors and triage identity across a name-only migration.

The first release changes public names and artifact storage without adding analysis sources. Section structure, findings, scoring, evidence rules, and section prose stay unchanged except for references to the renamed result. The [report producer](../../scripts/renderers/pregenerate_fragments.py) already states that its basis is static analysis of source and configuration without dynamic or penetration testing. Preserve that limitation and identify the inspected repository state, including uncommitted changes where applicable; a commit identifier alone does not describe every supported assessment input.

### Export and sharing

Remove `publish-threat-model` rather than renaming it. Its repository-specific `.gitignore` changes and signed Git commit are unnecessary for the external default destination. `export-security-assessment` continues to produce local files in the requested supported formats. Export does not authorize a Git commit, upload, or external publication, and this proposal adds no automatic sharing workflow.

Retain shared secret validation and artifact-selection controls when retiring the publishing helper. Any future supported publication path must still satisfy `REQ-USE-007` and `REQ-TRU-002`. Private sidecars and `pentest-tasks.yaml` do not become ordinary publication artifacts because their parent directory moved. Related-repository analysis currently uses published YAML; its consumers need explicit local assessment references or operator-provided shared locations after the move. A path under one user's data directory is not a portable team reference.

## Trust and analysis boundaries

The affected assets are private source information, assessment integrity, finding identity, and retained triage and audit state. The initiating operator selects the analysis scope through supported configuration. Repository contributors supply data; they do not gain authority over the controller, output destinations, or model tools.

Retain the existing analysis and deterministic validation pipeline. Under the aiscb baseline, repository content and model output remain untrusted data. The new storage resolver and migration code must not let that content choose another application's destination or overwrite unrelated files.

The workflow and storage transition preserves these boundaries:

- Confine reads to admitted roots and explicit inputs. Reject path traversal and escaping links when resolving or migrating assessment artifacts.
- Keep organization policy and source content separate. Source content cannot enable tools, select shell commands, suppress evidence-backed findings, change output paths, or grant exceptions.
- Preserve deterministic orchestration, existing scoped analysis roles, context routing, and budgets. This transition adds no analysis agent or model task.
- Validate legacy artifacts before importing or reusing them. Preserve provenance, finding identity, and retained operator decisions across the move.
- Retain existing secret exclusion and artifact-selection controls. Moving files outside the checkout does not make private sidecars suitable for sharing.
- Preserve explicit authorization for publication and other consequential actions. Running `create-security-assessment` does not itself authorize publishing or changing the analyzed project.

Implementation needs boundary tests for destination resolution, application isolation, and migration. This concept does not establish that those new paths are safe.

## Compatibility and migration

This release changes invocation names and artifact locations together. Data semantics and admitted analysis sources remain unchanged. Build the shared resolver before switching producers and consumers, but ship the public command and file transition in one release.

New assessments use `security-assessment.*` in the resolved external application directory unless the operator supplies `--output`. There is no release in which a new assessment command deliberately retains the old default filenames, and no old assessment command aliases. Document this boundary for existing users, organization packages, and CI callers under `REQ-EVO-003`.

Before switching the default filenames, update every first-party reader and writer to use a shared artifact-resolution mechanism. Keep existing legacy sets readable as migration inputs. Record the active artifact set and its application association outside model-authored content. Never assemble one assessment from a YAML file in one naming set and a Markdown file in another. A future design-based `threat-model.yaml` must not be mistaken for a legacy assessment solely because of its basename.

When both naming sets exist, use validated run identity and artifact provenance to establish whether they represent the same result. If the relationship is ambiguous or contradictory, stop the affected operation with a concrete migration instruction. File modification time alone is not sufficient. A stale success report from a previous run cannot satisfy completion of a new run.

At the next interactive assessment, offer once to import a detected legacy assessment into the external application directory. Explain that the import preserves existing results, history, and triage decisions. Import only after the operator agrees; declining or leaving the question unanswered does not authorize migration. Keep the old files after a successful import as well. Removing them is a separate operator action. Headless runs do not ask questions or infer migration consent; their explicit migration interface remains to be specified.

Migration from `docs/security/` to the external destination should check for an active run, validate the source set, preserve history and triage, update relative figure links, and install a coherent new artifact set. Preserve relative source-evidence links and repository-qualified references when moving away from the checkout. Never rename files underneath an active run. Define how an interrupted legacy run is resumed or completed before migration. Implement the transaction and rollback behavior in deterministic code. Neither deletion of the old set nor changes to tracked files are implicit.

Do not write a second assessment under the old filenames. Existing consumers move to the new names or use explicitly selected legacy inputs during migration. The support window for reading and migrating old artifacts remains open; it is separate from the removal of command aliases in the first release.

Optional exports retain their current meaning. SARIF contains applicable findings, not the complete assessment. Threat Dragon represents the threat-model subset and remains subject to its documented information loss. A rename does not change that limitation. Exports, any future publication, and cleanup use explicit artifact sets; a broader wildcard must not accidentally disclose private sidecars or pentest tasks.

## Implementation impact

The following locations establish concrete change surfaces. They are an initial impact map; implementation work still needs `check_specs.py --for` for every changed path and the returned contracts.

| Surface | Current locations | Expected work |
|---|---|---|
| Public skills and help | `skills/create-threat-model/`, related skill directories, `skills/help/`, `README.md` | Replace assessment command names without aliases; update descriptions, invocation examples, and completion guidance. |
| Packaging policy | `scripts/runtime/skill_policy_gate.py`, `scripts/package_internal_plugin.py`, `docs/internal-plugin-packaging.md`, decision `EX-3` | Replace the currently mandatory `create-threat-model` assessment capability without permitting policy bypass. An approved decision change precedes changing the mandatory name. |
| Routing and headless execution | `scripts/orchestrator/orchestration_controller.py`, `scripts/runtime/resolve_config.py`, `scripts/run-headless.sh` | Normalize commands; make output detection, compose recovery, success gates, update, and resume use the selected artifact set. |
| Canonical result and rendering | `scripts/model/build_threat_model_yaml.py`, `scripts/renderers/compose_threat_model.py`, `data/sections-contract.yaml`, `templates/`, `schemas/threat-model.output*.schema.yaml` | Change visible titles and destinations together; preserve canonical analysis semantics. |
| Report authoring and QA | `agents/`, `agents/shared/`, fragment schemas and validators | Align result terminology and file references; preserve report sections and evidence rules. |
| Exports and post-run consumers | `scripts/exporters/`, export, ask, review, show, and health skills, `scripts/appsec-analyst-cli` | Resolve the application destination and legacy migration inputs; preserve finding anchors, triage links, relative assets, and explicit paths. |
| Repository publication | `skills/publish-threat-model/`, `scripts/model/publish_threat_model.py`, shared secret validator, publication tests | Remove the public skill and repository-commit workflow without deleting shared secret checks or broadening the publishable artifact set. |
| Requirements integration | `scripts/requirements/`, `scripts/contexts/build_requirements_contexts.py`, `schemas/requirements-*.schema.*` | Preserve catalog discovery, assessment, and report traceability when moving the output directory. |
| Context routing | `data/context-routing-catalog.yaml`, `data/context-routing-bindings.json`, context builders | Update affected artifact references while preserving context selection and budgets. |
| Related and combined repositories | `scripts/shared/assessment_sources.py`, `scripts/runtime/multi_repo_scope.py`, related-repository readers | Resolve explicit external assessment references and legacy inputs; preserve repository-qualified evidence and source identities. |
| Storage, retained state, and permissions | `scripts/runtime/resolve_config.py`, `scripts/runtime/runtime_cleanup.py`, cleanup and audit-artifact contracts, `data/required-permissions.yaml` | Introduce the XDG data destination and application lookup; preserve baseline, history, audit, triage, and input discovery; scope cleanup to one assessment and update declared command and file targets. |
| Distribution and documentation | `.claude-plugin/`, `README.md`, `CONTRIBUTING.md`, `docs/threat-modeler.md`, `docs/headless-mode.md`, `docs/threat-dragon-export.md`, `docs/configuration.md`, `docs/model-selection.md`, `docs/org-profiles.md`, `docs/threat-analyst.md`, `docs/security-requirements-audit-skill.md`, `docs/harvester.md`, `docs/baselines/README.md`, `examples/` | Present the new workflow consistently; document compatibility. Rename `docs/threat-modeler.md` to `docs/security-assessment.md` and update every inbound link in the same change. Coordinate separately with external launchers and CI templates. |
| Report templates | `templates/fragments/` | Change visible report titles and references to the result document; leave section content unchanged. |
| Internal documentation | `docs/internal/` contracts, decisions, and runbooks | Update references to skill names and artifact paths; decision wording follows the confirmation rule below. |
| Release notes | `CHANGELOG.md` | Describe the renamed commands and files, external default destination, removed publish skill, and migration boundary. |
| Regression evidence | `scripts/run_tests.py`, skill, resolver, controller, schema, compose, export, publication, and cleanup tests | Update only affected routes and guards; prove compatibility rather than replacing old fixtures to hide breakage. |

Dated analysis documents keep their original names. Existing run-state files below `docs/security/` are migration inputs, not documentation to rewrite as part of this concept edit.

The [approved requirements](../../requirements.md) need review around `REQ-PUR-*`, `REQ-MOD-*`, `REQ-REQ-001`, `REQ-BIZ-*`, `REQ-RPT-*`, `REQ-ANA-*`, `REQ-TRU-*`, and `REQ-EVO-003`. The [decision catalog](../internal/decisions.md) includes relevant artifact, context, and packaging choices, notably `RA-1`, `RA-3`, `RA-6`, and `EX-3`. Wording changes to requirements or decisions require the operator to confirm the exact text and its meaning before those files are edited. This draft identifies the affected promises without replacing their wording. For example, `REQ-PUR-004` currently states that “the threat model must help developers, architects, and AppSec reviewers understand risks and plan remediation”; its new wording needs that confirmation.

## Delivery sequence and acceptance evidence

Deliver the workflow and storage transition together. These work packages contain no new document-analysis feature.

| Package | Deliverable | Acceptance evidence |
|---|---|---|
| 1. Public workflow transition | New main and consumer names, report titles, and file basenames; no old command aliases or publish skill. Ship with package 2. | New commands select the intended operation and scope; help starts no analysis; old invocations cannot silently select another workflow; packaging and permissions use the new capability names. |
| 2. External artifact storage and migration | Shared application resolution, XDG data destination, explicit output override, and a one-time interactive offer to import legacy results. Ship with package 1. | Consumers find the same result outside the checkout; equal project names do not collide; ambiguous mixed sets fail; stale outputs do not satisfy completion; migration requires agreement and preserves results, triage, and original files on success or interruption; one application's cleanup cannot remove another's data. |

Exercise the full lifecycle for packages 1 and 2: create, supported update, resume, rerender, export, query, triage, and cleanup. Cover single-repository and combined assessment paths according to their existing supported modes. Verify explicit related-assessment inputs still work without committing generated reports to source repositories. Replaying an old artifact must not assign new finding identities solely because its filename or location changed. Preserve security validation while removing the repository-publication entry point.

Verify that configured catalog assessments retain their statuses, evidence links, and canonical traceability after the move. Existing business-context inputs and retained operator answers remain available. The presence of `requirements.md` or `specs/` alone does not trigger a new selection dialog or comparison stage.

Use task-scoped routed tests and existing fixtures. Changes to deterministic report production require the golden-fixture replay described by the threat-fixture runbook. Keep old-schema and old-layout fixtures as migration evidence.

## Deferred: project-document comparison

Automatic discovery, operator selection, and systematic comparison of arbitrary requirements and design documents are outside this proposal. They may be considered in a separate future concept. No new document prompt, ingestion interface, report section, or delivery package is planned here. The existing structured security requirements catalog and the separate `analyze-threats` design mode remain supported.

## Deferred: design-based threat modeling

A threat model can be created from requirements and architecture documents without any code. Such a workflow would describe the intended system with its components, actors, data flows, trust boundaries, and assets, and derive design-level threats, protection assumptions, and open questions without code findings or CVSS scores. Its result would be committed and maintained by the team, and a later assessment could compare implementation evidence against it. The existing `analyze-threats` design mode does not produce such a structured system model and accepts only a single design input.

This workflow is deferred to a later phase with its own concept. Reserve `create-threat-model` for that purpose rather than retaining it as an assessment alias. Its later introduction needs an explicit interface boundary so legacy assessment invocations cannot silently produce a design-only result. Define the accepted inputs and distinguish its structured model from old assessment YAML before reusing the name. A design model remains a team-maintained repository artifact; the generated assessment uses the separate destination described above.

## Scope and choices for implementation planning

This release combines public terminology, command replacement without aliases, renamed artifacts, external default storage, and removal of the repository-publication skill. Its implementation starts with shared destination and artifact resolution before changing producers and consumers. It preserves existing analysis coverage without adding project-document comparison.

The largest effort is likely in artifact lifecycle compatibility and application-to-output resolution. This is an impact assessment, not a measured schedule. Before estimating delivery dates, inventory all path consumers, external launchers, organization package policies, and schema-version assumptions.

Implementation planning still needs to settle application identity and lookup, non-Linux storage defaults, the headless migration interface, interrupted legacy runs, and the legacy-artifact support window. Project-document comparison and the future design-based workflow require their own concepts and do not block this transition. Remote connectors, autonomous publication, and general functional verification are also outside this proposal.
