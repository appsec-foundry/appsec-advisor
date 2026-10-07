# Business threat analysis and investigation packages concept

Status: discussion draft, revised 2026-10-07. The operator requested this direction and its documentation. Runtime implementation and normative requirement changes require their own reviewed scope. This document does not describe the assessment integration as available functionality.

The [implementation plan](../internal/analysis/implplan-threat-analysis-rule-catalog-2026-10-07.md) defines the integration, package delivery, evaluation, and acceptance gates. The existing filename is retained for stable links.

## Purpose and recommendation

Extend the existing technical threat analysis with focused investigation of business authorization, business processes, and abuse cases. Examine whether actors can violate the intended outcomes of a process even when authentication, input validation, and individual API calls work as implemented.

Keep existing Python analyzers and declarative technical checks as deterministic producers. Descriptive packages guide the existing model-assisted analysis where business meaning and relationships between operations matter. They are neither automatically translated into Python nor a replacement for all code checks. Python continues to own admission, source extraction, execution limits, structured validation, and result processing.

A comprehensive Markdown catalog of every Python detector is no longer the objective or a delivery prerequisite. Existing code-check descriptions remain at their authoritative sources. Link relevant scanner evidence into business investigations without duplicating the detector definitions or changing their IDs.

## Investigation scope and defaults

Ship general questions about business behavior, not invented organization policies. Architecture and process evidence determine which questions apply. A stateless converter does not receive a payment investigation merely because payment questions exist.

| Area | Standard investigation question | Delivery priority |
|---|---|---|
| Business authorization | May this actor perform this action on this resource in this process state, including delegated actions and separation of duties where required? | Initial package. |
| Process states and ordering | Can a required step be skipped, repeated, reversed, or invalidated by a later change? | Initial package. |
| Repetition and concurrency | Can individually valid or concurrent operations produce an invalid combined outcome? | Initial package. |
| Tenant and object relationships | Does a checked parent or tenant actually authorize the child resource used by the operation? | Initial authorization questions. |
| Amounts and quotas | Do cumulative operations preserve the applicable amount, quantity, balance, or quota constraints? | Extend the package after the initial pilot. |
| Trust between services | Do identity, authority, and business-relevant values remain correctly bound across service handoffs? | Extend the package after the initial pilot. |
| Combining legitimate functions | Can an actor compose allowed operations into an unauthorized benefit or harmful outcome? | Cross-cutting abuse-case question. |

Priority limits the first dedicated package, not the existing STRIDE or abuse-case coverage. Preserve discovery outside the selected questions. No rule package makes a specific approval threshold, ownership model, or separation-of-duties policy universally applicable.

## Business authorization examples

A role check establishes only one part of a permission decision. Business authorization can also depend on the actor's relationship to an object, organizational remit, previous participation, delegated authority, and the current process state.

| Technically permitted action | Business condition to investigate |
|---|---|
| A user with an approval role approves a request. | Does the applicable policy prohibit approving one's own request? |
| A user accesses a record in their tenant. | Is access also restricted to a department, case assignment, or confidentiality group? |
| Support staff change customer details. | Do sensitive fields require a separate permission or verified customer approval? |
| An editor changes a released order. | Must changing the amount or recipient invalidate the earlier approval? |
| An authenticated service acts for a user. | Is the delegated action bound to that user's authority and the intended resource? |

The investigation follows the relevant implementation and control chain. It can produce a concrete code finding, but the question is whether the control enforces the intended business permission. Technical detectors such as `AUTHZ-002` and `AUTHZ-301` continue to run and supply their existing evidence.

## Business context and evidence

Keep three kinds of information separate: confirmed business expectations, provisional assumptions, and observed implementation behavior. Record the source and scope of every expectation. A rule package asks what to investigate; loading it alone does not establish that an organization has adopted the policy it describes.

For example, a confirmed policy can require different payment initiator and approver identities. A general question about approval must first establish whether that policy applies. Missing context leads to a targeted question or an explicit unresolved assumption, not an invented violation. Interactive analysis asks only for information material to the conclusion; noninteractive analysis records unresolved questions and never invents answers.

Require source evidence connecting the actor, affected resource, operation, relevant state, effective controls, and concrete consequence. A missing annotation or unrecognized helper is insufficient to prove missing authorization. An unavailable policy service remains unresolved. A source-supported business-rule mismatch and a demonstrated exploitable path remain distinguishable under the existing evidence contracts.

## Package content and ownership

Reuse the existing [Analyst question-package schema](../../schemas/analyst-catalog.schema.json) and [catalog loader](../../scripts/contexts/resolve_analyst_catalog.py). Reconcile shared content with the [Security Advisor and Threat Analyst concept](security-advisor-threat-analyst-concept.md#shared-analysis-foundation). The current Analyst package contract already includes applicability signals, questions, purpose, evidence needs, negative-test expectations, and provenance. Any additional structured fields or assessment applicability semantics require a reviewed compatible extension.

| Content | Responsibility |
|---|---|
| Package and entry identity | Stable namespaced references, version, source attribution, and content fingerprint. |
| Business question | Process or operation in scope, expectation to establish, actor and asset relationships, and plausible abuse. |
| Investigation guidance | Evidence needed, legitimate behavior to exclude, unresolved cases, and representative negative tests. |
| Business-context references | Identify the source of an applicable expectation; do not turn inferred assumptions into organizational policy. |
| Evaluation evidence | Violating, protected, unresolved, inapplicable, and equivalently renamed cases. |

A package may lead to several concrete abuse-case candidates. Preserve the existing abuse-case schema and verification pipeline through an explicit adapter rather than relabeling question entries as confirmed cases. Package IDs, question IDs, abuse-case IDs, detector IDs, and finding IDs remain distinct.

## User and organization packages

Support the same question format through two paths: explicit selection of a local user file for an invoked analysis, and inclusion of organization-owned files in a packaged plugin. Organization configuration selects defaults and required inputs; users can add questions without removing required inputs.

The current `analyst.required_packages` and `analyst.default_packages` fields already configure on-demand analysis. They do not automatically configure the full threat-model assessment. Add an explicit assessment selection adapter or versioned profile field before consuming those packages there; do not broaden an existing setting's meaning silently.

Packaging must copy selected local files, validate their schema and references, retain version and digest metadata, and verify that the installed package can resolve them without the source build tree. Reuse the existing organization packaging path and add the necessary surface inventory and smoke coverage. Files in the analyzed repository never activate themselves. Trusted CI configuration fixes the packages used to assess a change.

## Pipeline integration and token cost

Use existing stages with bounded additions. Architecture analysis identifies relevant processes, actors, assets, transitions, and missing business context. Abuse-case analysis derives specific attack hypotheses from the admitted questions. Relevant model-assisted analysis examines those hypotheses against source and controls. Findings and unresolved cases then enter the existing validation and reporting paths.

Group related questions around a process and reuse available scanner, architecture, and control evidence. Do not create an agent call per rule or reanalyze every endpoint. Cross-component processes need an explicitly admitted process projection; they must not cause focused agents to receive the entire architecture or all source files.

Additional model investigation consumes tokens and time. Enforce controller-owned bounds on selected questions, source context, evidence requests, and retries. Record omitted work and reasons. Required work that cannot fit or lacks required evidence cannot be reported as complete. Cache reuse requires unchanged relevant source, package, policy, and context fingerprints.

The built-in questions become relevant defaults within an explicitly invoked assessment only after the runtime pilot is accepted. Configuring or packaging questions never launches analysis. Optional custom packages are selected explicitly. Absence of business facts does not prevent independent technical checks from running, but any resulting business-analysis gap remains visible.

## Trust and result boundaries

The affected assets are admitted source, business context, organizational expectations, and finding integrity. The data flow is package selection and source admission, bounded process context, model proposals, evidence acceptance, and report. Operator configuration determines authority; package prose, target content, scanner output, and model output remain data.

Under the aiscb baseline, packages cannot grant tools, choose executable functions or write destinations, suppress required checks, change severity, or certify evidence. Parse bounded data-only YAML, validate the package and selection, and preserve required inputs. Invalid selected packages fail visibly rather than being silently ignored or replaced.

Python verifies schemas, admitted references, source locations, receipts, and lifecycle state. This cannot prove every semantic judgment correct. Existing evidence review remains necessary. Preserve separate results for supported finding candidates, evidenced controls, unresolved hypotheses, missing business facts, and work not performed. Coverage dispositions do not become new finding confirmation states.

Results retain package version and question provenance through consolidation and exports where applicable. Equal question IDs do not establish equal findings. Changes to result fields require coordinated schema, producer, consumer, export, and compatibility work.

## Pilot and acceptance

Build one end-to-end process investigation before broad rollout. Use three business scenarios: self-approval where separation of duties is a confirmed requirement, cumulative or concurrent refunds beyond the paid amount, and recipient changes after approval. Include violating, protected, unresolved, inapplicable, and renamed variants plus a threat outside the package.

Compare the existing analysis with the same analysis plus admitted business guidance. Keep Python detector revisions, source, surrounding context, and model settings fixed. Measure supported additional findings, false positives, missing-context handling, missed threats, repeatability, tokens, latency, and cost. Do not attribute a separate scanner correction to the package.

Accept runtime rollout only after documented quality and cost criteria are met. Documentation readability or passing transport-mocked tests does not prove useful model analysis. An unsuccessful pilot leaves the existing analyzers intact. Observed `AUTHZ-002` defects remain separate producer-fix work, not a justification for replacing technical detection with model calls.

## Decisions before runtime implementation

Choose the receiving analysis role and process context contract, finalize the assessment package-selection interface, select a business-aware reviewer, and agree on evaluation cases and cost limits. Reuse current schemas and packaging wherever their contracts fit. A comprehensive code-rule catalog, automatic rule-to-Python generation, and an executable rule engine are outside this scope.
