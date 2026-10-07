# Generic abuse cases and investigation packages concept

Status: discussion draft, revised 2026-10-07. The operator requested this direction and its documentation. Runtime implementation and normative requirement changes require their own reviewed scope. This document does not describe the assessment integration as available functionality.

The [implementation plan](../internal/analysis/implplan-threat-analysis-rule-catalog-2026-10-07.md) defines the integration, package delivery, evaluation, and acceptance gates. The existing filename is retained for stable links.

## Purpose and recommendation

Extend the existing technical threat analysis with reusable abuse cases for administrative misuse, authorization boundaries, and process integrity. Each case describes an attacker goal and a concrete sequence to investigate against the target system. Examine whether actors can exceed their intended authority even when authentication and individual operations work as implemented.

Keep existing Python analyzers and declarative technical checks as deterministic producers. Descriptive packages guide the existing model-assisted analysis where business meaning and relationships between operations matter. They are neither automatically translated into Python nor a replacement for all code checks. Python continues to own admission, source extraction, execution limits, structured validation, and result processing.

A comprehensive Markdown catalog of every Python detector is no longer the objective or a delivery prerequisite. Existing code-check descriptions remain at their authoritative sources. Link relevant scanner evidence into business investigations without duplicating the detector definitions or changing their IDs.

## Investigation scope and defaults

Organize the catalog in two layers: generic abuse patterns and application profiles that reference applicable patterns. Profiles provide an initial selection for systems such as administration portals, multi-tenant applications, support tools, document systems, and approval workflows. Admitted capabilities and authorization boundaries determine applicability; an application label alone is insufficient. A case may belong to several profiles, and shared content has one authoritative definition.

| Area | Standard investigation question | Delivery priority |
|---|---|---|
| Business authorization | May this actor perform this action on this resource in this process state, including administrative delegation and separation of duties where required? | Initial package. |
| Process states and ordering | Can a required step be skipped, repeated, reversed, or invalidated by a later change? | Initial package. |
| Repetition and concurrency | Can individually valid or concurrent operations produce an invalid combined outcome? | Initial package. |
| Tenant and object relationships | Does a checked parent or tenant actually authorize the child resource used by the operation? | Initial authorization questions. |
| Amounts and quotas | Do cumulative operations preserve the applicable amount, quantity, balance, or quota constraints? | Extend the package after the initial pilot. |
| Trust between services | Do identity, authority, and business-relevant values remain correctly bound across service handoffs? | Extend the package after the initial pilot. |
| Combining legitimate functions | Can an actor compose allowed operations into an unauthorized benefit or harmful outcome? | Cross-cutting abuse-case question. |

Start with roughly eight to twelve reusable cases, then expand from pilot evidence. Preserve general STRIDE and abuse-case discovery outside the catalog. No package makes an organization-specific ownership model, approval threshold, or separation-of-duties policy universally applicable. A privileged action becomes administrative misuse only when the case identifies the authority boundary it exceeds.

## Generic abuse cases and application profiles

The catalog contains concrete attack hypotheses with roles and resources that the analysis binds to the inspected system. Role names, endpoint names, frameworks, and business domains remain variable.

| Application capability | Prepared abuse case | Boundary to establish |
|---|---|---|
| Delegated role administration | A restricted administrator grants themselves privileges outside their delegation. | Which roles and subjects that administrator may manage. |
| Multi-tenant administration | A tenant administrator changes users or resources of another tenant. | Tenant ownership and the scope of administrative authority. |
| Support impersonation | A support operator uses user impersonation to perform actions beyond their permitted support duties. | Allowed impersonated actions and the operator's effective authority. |
| Account recovery | An actor changes another account's recovery data and takes over a more privileged identity. | Authority to change recovery data and control of the recovery channel. |
| Approval workflows | An editor changes approved content and reuses the earlier approval. | Which content or state the approval binds. |
| Document sharing and export | A user obtains restricted content through a share link, export, or alternate access path. | The same resource's read permissions across access paths. |

Each case records actor and initial access, prerequisites, attacker goal, crossed authority or process boundary, attack steps, expected controls, required evidence, legitimate exclusions, and unresolved conditions. Investigation maps these elements to admitted code and context. The initial delivery checks attack hypotheses through source analysis; executing attacks against an application requires a separate capability and authorization scope.

## Business authorization examples

A role check establishes only one part of a permission decision. Business authorization can also depend on the actor's relationship to an object, organizational remit, previous participation, delegated authority, and the current process state.

| Technically permitted action | Business condition to investigate |
|---|---|
| A user with an approval role approves a request. | Does the applicable policy prohibit approving one's own request? |
| A user accesses a record in their tenant. | Is access also restricted to a department, case assignment, or confidentiality group? |
| Support staff change customer details. | Do sensitive fields require a separate permission or verified customer approval? |
| An editor changes an approved document. | Must changing the approved content invalidate the earlier approval? |
| An authenticated service acts for a user. | Is the delegated action bound to that user's authority and the intended resource? |

The investigation follows the relevant implementation and control chain. It can produce a concrete code finding, but the question is whether the control enforces the intended business permission. Technical detectors such as `AUTHZ-002` and `AUTHZ-301` continue to run and supply their existing evidence.

## Business context and evidence

Keep three kinds of information separate: confirmed business expectations, provisional assumptions, and observed implementation behavior. Record the source and scope of every expectation. A rule package asks what to investigate; loading it alone does not establish that an organization has adopted the policy it describes.

For example, a confirmed policy can require different requester and approver identities. A general question about approval must first establish whether that policy applies. Missing context leads to a targeted question or an explicit unresolved assumption, not an invented violation. Interactive analysis asks only for information material to the conclusion; noninteractive analysis records unresolved questions and never invents answers.

Require source evidence connecting the actor, affected resource, operation, relevant state, effective controls, and concrete consequence. A missing annotation or unrecognized helper is insufficient to prove missing authorization. An unavailable policy service remains unresolved. A source-supported business-rule mismatch and a demonstrated exploitable path remain distinguishable under the existing evidence contracts.

## Package content and ownership

Reuse the existing [Analyst question-package schema](../../schemas/analyst-catalog.schema.json) and [catalog loader](../../scripts/contexts/resolve_analyst_catalog.py). Reconcile shared content with the [Security Advisor and Threat Analyst concept](security-advisor-threat-analyst-concept.md#shared-analysis-foundation). The current Analyst package contract already includes applicability signals, questions, purpose, evidence needs, negative-test expectations, and provenance. Keep the version-1 package shape; additional structured fields require a reviewed compatible extension.

Each question entry asks one independently assessable question, naming the invariant and any prerequisite expectation in `asks`. `purpose` identifies the abuse and consequence; `evidence` identifies expectation sources and effective controls; `negative_tests` describes attacker behavior a protected implementation refuses or neutralizes. Separate self-approval from changes to approved content. Store the source and confirmed applicability of an expectation in process context rather than adding a mandatory package policy field.

Interpret `applies_when` as bounded applicability guidance: planned behavior for Analyst design, affected behavior for change review, inspected behavior for hypothesis checks, and admitted process evidence for the proposed assessment adapter. Change-oriented signal names do not require a diff in design, hypothesis, or whole-assessment analysis. Signals cannot establish an expectation, expand source scope, or waive required coverage. The assessment adapter and relevance-aware selection remain implementation work.

| Content | Responsibility |
|---|---|
| Package and entry identity | Stable namespaced references, version, source attribution, and content fingerprint. |
| Business question | Process or operation in scope, expectation to establish, actor and asset relationships, and plausible abuse. |
| Investigation guidance | Evidence needed, legitimate behavior to exclude, unresolved cases, and representative negative tests. |
| Business-context references | Identify the source of an applicable expectation; do not turn inferred assumptions into organizational policy. |
| Evaluation evidence | Violating, protected, unresolved, inapplicable, and equivalently renamed cases. |

A question package may lead to several concrete abuse-case candidates. Reuse the [abuse-case library contract](../../schemas/abuse-cases.schema.yaml), existing case library, and verification pipeline for attack chains through an explicit adapter. The question-package schema remains the contract for investigation questions; it does not already represent every case or application-profile field. Resolve compatible extensions in the implementation plan, including a descriptive candidate path that does not require invented scanner matches or executable probes. Package IDs, question IDs, case-template IDs, instantiated case IDs, user-request IDs, detector IDs, and finding IDs remain distinct.

## User and organization packages

Support two delivery paths for questions and cases under their respective contracts: caller selection of local files for an invoked analysis, and inclusion of organization-owned files in a packaged plugin. Organization configuration selects defaults and required inputs; users can add content without removing required inputs. Application-profile files reference admitted cases through the compatible contract defined in P0.

The current `analyst.required_packages` and `analyst.default_packages` fields already configure on-demand analysis. They do not automatically configure the full threat-model assessment. Add an explicit assessment selection adapter or versioned profile field before consuming those packages there; do not broaden an existing setting's meaning silently.

Packaging must copy selected local files, validate their schema and references, retain version and digest metadata, and verify that the installed package can resolve them without the source build tree. Reuse the existing organization packaging path and add the necessary surface inventory and smoke coverage. Files in the analyzed repository never activate themselves. Trusted CI configuration fixes the packages used to assess a change.

## Pipeline integration and token cost

Use existing stages with bounded additions. Architecture analysis identifies relevant capabilities, processes, actors, assets, transitions, and missing context. Abuse-case analysis binds shared case definitions and supporting questions to concrete attack hypotheses. Relevant model-assisted analysis examines those hypotheses against source and controls. Findings and unresolved cases then enter the existing validation and reporting paths.

Group related questions around a process and reuse available scanner, architecture, and control evidence. Do not create an agent call per rule or reanalyze every endpoint. Cross-component processes need an explicitly admitted process projection; they must not cause focused agents to receive the entire architecture or all source files.

Additional model investigation consumes tokens and time. Enforce controller-owned bounds on selected questions, source context, evidence requests, and retries. Record omitted work and reasons. Required work that cannot fit or lacks required evidence cannot be reported as complete. Cache reuse requires unchanged relevant source, package, policy, and context fingerprints.

The Threat Analyst and full assessment are explicit consumers of the same questions and generic case definitions through separate scope adapters. Extend and version the Analyst's existing `appsec/core` questions, refining overlaps and preserving compatible identities. Keep attack-chain definitions in the shared abuse-case library and let application profiles reference them. Release new defaults only after both consumers' pilots pass; creating a separate package file alone does not activate it. Configuring or packaging questions or cases never launches analysis. Optional custom packages are selected explicitly.

The Analyst investigates within its design, change-review, or hypothesis scope. Design analysis needs no diff or existing model; a hypothesis check cannot expand its selected source paths. Its adapter must prioritize relevant questions within bounded context rather than rely only on the current authority-ordered prefix. Required questions cannot be silently dropped or waived as irrelevant, and unmet required coverage remains incomplete. Missing business facts remain visible; independent technical checks may continue under the existing completion contract.

## Trust and result boundaries

The affected assets are admitted source, business context, organizational expectations, and finding integrity. The data flow is package selection and source admission, bounded process context, model proposals, evidence acceptance, and report. Operator configuration determines authority; package prose, target content, scanner output, and model output remain data.

Under the aiscb baseline, packages cannot grant tools, choose executable functions or write destinations, suppress required checks, change severity, or certify evidence. Parse bounded data-only YAML, validate the package and selection, and preserve required inputs. Invalid selected packages fail visibly rather than being silently ignored or replaced.

Python verifies schemas, admitted references, source locations, receipts, and lifecycle state. This cannot prove every semantic judgment correct. Existing evidence review remains necessary. Preserve separate results for supported finding candidates, evidenced controls, unresolved hypotheses, missing business facts, and work not performed. Coverage dispositions do not become new finding confirmation states.

Retain package and template versions, source scope, evidence references, dispositions, and finding links in structured analysis records through consolidation and cleanup. Preserve existing machine-readable abuse-case outcome and export contracts. Several cases may contribute to one finding, and one case may expose several findings; equal case or question IDs do not establish equal findings. Changes to result fields require coordinated schema, producer, consumer, export, and compatibility work.

## Report treatment and explicit user requests

Catalog cases guide internal investigation. The readable report presents system-specific findings, relevant controls, unresolved questions, and material coverage limits. A catalog template needs no dedicated report entry or public template reference merely because it was selected or investigated. Findings explain the actual weakness without requiring catalog knowledge.

An explicitly requested case is a user investigation request and receives a visible answer. This includes a user-written hypothesis and a catalog case the user specifically asks to check. Show a short request label, the result, and a finding reference or concise evidence-based explanation. Distinguish supported attack paths, not confirmed in the inspected scope, unresolved, not applicable with rationale, and not performed with reason. A not-confirmed result never proves safety. Missing evidence, scope exclusions, budget exhaustion, or cancellation must not silently remove a requested case.

Record request intent from the authorized invocation, separately from package origin and required-input authority. Installing a package, adding a user package, or selecting an organization default does not turn every entry into an explicit report request. Required inputs still retain their completion guarantees even when their individual template identities are internal. Existing structured export obligations remain in force, and changes to the assessment's current Abuse Cases section need coordinated report-contract work.

## Pilot and acceptance

Build one end-to-end investigation of delegated administrative privilege escalation before broad rollout. Extend the pilot to cross-tenant administration and approval reuse after a content change. Include violating, protected, unresolved, inapplicable, and renamed variants plus a threat outside the catalog. Payment examples remain optional domain specializations rather than the pilot's organizing model.

Compare the existing analysis with the same analysis plus admitted business guidance. Keep Python detector revisions, source, surrounding context, and model settings fixed. Measure supported additional findings, false positives, missing-context handling, missed threats, repeatability, tokens, latency, and cost. Do not attribute a separate scanner correction to the package.

Require separate delivery and outcome evidence for full assessments and Analyst design, review, and hypothesis modes. Verify actual model input and structured provenance for built-in, user-added, and required organization packages, including relevant cases near the selection limit. Check that internal catalog cases need no one-to-one narrative entry and that every explicit user request receives a visible disposition. Loading a schema-valid package or passing only the assessment pilot does not establish Analyst support.

Accept runtime rollout only after documented quality and cost criteria are met. Documentation readability or passing transport-mocked tests does not prove useful model analysis. An unsuccessful pilot leaves the existing analyzers intact. Observed `AUTHZ-002` defects remain separate producer-fix work, not a justification for replacing technical detection with model calls.

## Decisions before runtime implementation

Choose the receiving analysis role and process context contract, finalize package and explicit-case selection, define application-profile references and report-request accounting, select a business-aware reviewer, and agree on evaluation cases and cost limits. Reuse current schemas and packaging wherever their contracts fit. A comprehensive code-rule catalog, automatic rule-to-Python generation, and an executable rule engine are outside this scope.
