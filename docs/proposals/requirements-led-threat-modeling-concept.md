# Threat modeling from requirements and design

Status: concept draft, 2026-10-13. This proposal describes an independent skill for creating and maintaining a team's threat model. It does not change approved product requirements, record accepted implementation decisions, or introduce an executable skill.

The skill helps teams understand what they need to protect, how their system could be misused, and which design choices address those threats. Existing requirements are the primary starting point. Specifications, architecture descriptions, team knowledge, and optional bounded code exploration provide further context. The workflow works before implementation exists.

The main deliverable is a human-maintained `threatmodel.md` at the repository root, linked from the repository's `security.md` or `SECURITY.md`. Teams can edit, review, and commit it alongside requirements and design changes. Its central relationship is: security objective, affected interaction, threat scenario, control, remaining risk, and treatment decision.

## Purpose and scope

Support three tasks: create an initial model, update it for a change, and review its assumptions, threats, and treatment. A scope can cover a system, a feature, or a proposed design change. Each model identifies its scope, responsible team, intended audience, source state, and review status.

The workflow is independent of the existing code assessment pipeline. A threat scenario can be relevant without an implementation flaw or a vulnerable source line. Existing controls and planned safeguards belong in the model alongside unresolved risks. Their presence does not establish that they work in production.

Selective reuse of suitable catalogs, source handling, or validation helpers is possible after checking their semantics. Reuse should preserve this workflow's focus on design and team decisions. The separate [application security assessment concept](application-security-assessment-concept.md) describes the assessment naming proposal; implementing either concept does not depend on implementing the other.

## Methodological basis

Use the four questions described by [OWASP Threat Modeling](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html): what are we working on, what can go wrong, what will we do about it, and did we do a good enough job? OWASP describes common approaches rather than a universally prescribed process.

Use [STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) to prompt consideration of technical threats. Add abuse cases for business workflows and attack trees when a significant attacker goal needs several steps or alternatives. Select additional methods when the scope warrants them, including privacy analysis where relevant. A method or catalog supplies perspectives; applicability still depends on the system.

The [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/) supports collaboration and continuous refinement. [NIST SSDF practices PW.1 and PW.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf) provide a reference for modeling risks, maintaining security requirements and design decisions, and reviewing designs. These references guide the proposed workflow without implying certification or complete conformance.

## Sources and their roles

Read available sources in the following order to establish intended behavior before examining implementation details. Requirements include functional behavior, business rules, and nonfunctional expectations as well as explicit security requirements.

| Source | Contribution |
|---|---|
| Requirements and confirmed business context | System purpose, valuable assets and operations, required properties, roles, obligations, and binding constraints. |
| Specifications, design descriptions, diagrams, and ADRs | Proposed components, interactions, dependencies, trust boundaries, and design rationale. |
| Existing threat models and selected security profiles | Prior assumptions, scenarios, decisions, known threats, actors, and organizational expectations. |
| Optional bounded code and configuration exploration | Implementation observations that clarify a particular model element or reveal a conflict with the intended design. |

This reading order is not an automatic conflict-resolution rule. Record each source's identity, version or revision where available, applicable scope, and status. A draft requirement, an approved organizational obligation, and a model-generated suggestion have different authority. Surface disagreements between requirements, design, code, and prior team decisions instead of silently selecting a convenient interpretation.

A requirement describes intended behavior. A design describes how that behavior is meant to be achieved. Code can support an observation about implementation. None of these alone proves operational effectiveness. Mark whether the model describes the current system, a proposed system, or a transition between them.

When requirements are absent, derive a provisional understanding from the remaining sources and identify which important assumptions need team input. Analysis can continue with those limitations visible. Code availability is never a prerequisite for modeling a proposed design.

## Preliminary analysis and optional dialogue

Perform a short preliminary analysis before asking questions whenever relevant sources exist. Extract candidate assets, security objectives, actors, flows, constraints, and plausible harmful outcomes. Reuse applicable answers from the existing model. Optional code exploration addresses specific gaps, such as a component's role or an integration's data types; it does not turn this step into a vulnerability scan.

Questions follow from missing information, ambiguity, or contradictions in that preliminary understanding. Prioritize questions whose answers could change scope, security objectives, significant consequences, or a treatment choice. Start with a small useful round, such as three questions, and offer deeper discussion when needed rather than imposing a universal questionnaire.

Each question connects an observation and its source to a proposed interpretation or uncertainty, then asks for the concrete decision the team can make. The following examples are illustrative:

| Observation from the preliminary analysis | Contextual question | Effect on the model |
|---|---|---|
| Requirements permit sharing customer contracts with external recipients. | I would classify contract contents as confidential. Does that apply to every document, or are several protection classes needed? | Asset classification and disclosure consequences. |
| Requirements allow external access but do not define its duration. | I propose revocable, expiring shares. Are there use cases that require permanent access? | Sharing constraints and authorization design. |
| The design gives support personnel access across tenants. | Is this access necessary, and which actions and tenant scopes should it permit? | Actor privileges, trust boundaries, and abuse scenarios. |
| An import operation can replace existing business records. | I see unnoticed bulk modification as a serious scenario. Which consequences matter most, and how much can recovery reverse? | Integrity objectives, credible impact, and recovery assumptions. |

Let the user confirm, correct, supplement, leave unknown, or skip a proposed answer. Make uncertainty a normal answer. Silence or a skipped question does not confirm a suggestion or accept a risk. Preserve an opportunity to add a concern outside the suggested scenarios so the initial analysis does not constrain the team's perspective.

For assets, reuse the organization's classification scheme where available. Also describe confidentiality, integrity, and availability needs: public data can still require strong integrity. Include valuable capabilities and business processes, such as approving a payment, alongside data and infrastructure.

For worst-case scenarios, explore the most serious plausible harm within scope and state its prerequisites, affected parties, and reach. Keep impact separate from likelihood and avoid invented probabilities or financial estimates. Team concerns can reveal consequences that source files do not describe.

The proposed default is a short guided dialogue, with optional deeper discussion and a mode without questions. A run without answers produces a draft with unresolved assumptions and decisions. Record useful answers with their source and applicability in the model; the conversation transcript is not part of the deliverable. Revisit answers when their supporting requirements, design, or scope change.

## Reusable security context

Accept explicitly selected context from plugin-provided catalogs, organization or domain profiles, and project-specific inputs. Small projects can maintain this context directly in the model. Shared profiles can use separate versioned files when reuse warrants them. Record the sources and versions used so a later model update can explain changes in context.

| Input | Purpose and treatment |
|---|---|
| General threat patterns | Suggest relevant mechanisms, prerequisites, and affected security properties. Instantiate applicable patterns against the system model. |
| Known threats | Carry scenarios from earlier models, incidents, reviews, or team concerns into explicit consideration. Preserve origin and reassess applicability and treatment. |
| Threat actors | Describe goals, initial access, permissions, controllable inputs, capabilities, and relevant resource assumptions. |
| Constraints | Describe binding obligations, negotiable product or technical choices, and external dependencies. Keep these categories distinguishable. |
| Security requirements | Define the properties the design needs to preserve and support traceability to mitigations and verification criteria. |
| Assumptions | State dependencies on behavior, deployment, users, or external controls, with an owner or review trigger where useful. |

Selected [CAPEC patterns](https://capec.mitre.org/about/index.html) can supply attack mechanisms. [MITRE ATT&CK](https://attack.mitre.org/) can inform relevant adversary behavior and operational scenarios. Neither replaces project-specific analysis or exhausts the threats worth considering.

Actor descriptions emphasize capabilities and access. An authenticated tenant, a former recipient with a saved link, or a partner that supplies business data is more useful for a concrete scenario than an unsupported claim about a named adversary. The team can supply additional actor knowledge and explain exclusions.

For each explicitly supplied known threat, retain an applicability outcome and rationale: applicable, not applicable, or unresolved. Link applicable entries to scenarios and merge duplicate mechanisms without losing source references. Track control and treatment state separately. An applicable threat may already have a safeguard or an accepted residual risk; imported status alone does not establish that the decision still applies.

A constraint limits available responses; it does not remove the underlying exposure. Surface conflicts with security objectives and describe alternatives for team review. A profile update proposes changes to the model and highlights affected assumptions and decisions. It does not silently accept new risk, replace team decisions, or expand execution permissions.

## Modeling workflow

The dialogue feeds the modeling work and can resume when a material uncertainty emerges. The following phases describe the proposed responsibilities rather than a requirement for a fixed number of agent calls.

1. Establish scope and objectives from requirements and context. Identify assets, valuable operations, actors, exclusions, and uncertain assumptions. Use the preliminary analysis to prepare optional questions.
2. Describe the system. Model components, stores, external parties, important interactions, and trust boundaries. Explain the identity, ownership, privilege, or control assumption that changes at each boundary. Use a compact diagram and supporting prose; add a detailed view only where it helps reasoning.
3. Develop scenarios. Examine how an actor could violate an objective through an interaction or workflow. Use STRIDE, relevant patterns, known threats, and team concerns. Include multi-step paths and business abuse where applicable. Lack of code evidence does not disqualify a design threat.
4. Evaluate responses. Identify existing and planned controls, explain how they address the scenario, and describe remaining uncertainty and risk. Propose elimination, mitigation, transfer, or acceptance as applicable. State who retains responsibility for controls and residual risk when transferring responsibility.
5. Review the model with the team. Check architectural accuracy, coverage of significant interactions and objectives, treatment rationale, testability, and unresolved decisions. Record actual review participation and scope without presenting automated analysis as human approval.
6. Maintain the model with changes. Update affected objectives, scenarios, assumptions, and decisions while preserving stable references and unaffected content.

Use qualitative, explained risk prioritization that considers plausible harm, prerequisites, access, and relevant controls. Separate confidence in the underlying information from risk priority. Concrete vulnerability scoring can be supplemental when justified; a CVSS score is not required for a design scenario. Unknown impact or exposure stays visible instead of receiving an invented precise score.

## Maintained model and repository integration

Use `threatmodel.md` as the leading, directly editable artifact. Markdown and text-based diagrams allow the team to review changes through ordinary pull requests. A separate canonical YAML or JSON model is not needed for the initial workflow; add structured interchange only when a concrete consumer justifies it and its schema and synchronization rules are defined.

The proposed document structure is:

| Section | Content |
|---|---|
| Scope and ownership | Purpose, responsible team, intended audience, model scope, review status, and exclusions. |
| Sources and assumptions | Requirements, design references, selected profiles, source state, assumptions, and unresolved conflicts. |
| Assets and security objectives | Asset classification, valuable operations, protection needs, and relevant consequences. |
| Actors and constraints | Actor access and capabilities, binding and negotiable constraints, and important dependencies. |
| System model | Components, flows, stores, trust boundaries, and maintainable diagrams. |
| Threat scenarios | Stable scenario IDs, prerequisites, mechanisms, affected objectives, impact, and applicability. |
| Treatment and verification | Existing and planned safeguards, decisions, responsible roles, remaining risks, and verification criteria. |
| Review and open questions | Review participants and scope, unresolved decisions, coverage gaps, and reassessment triggers. |

Keep each scenario readable as a short record. Link to detailed requirements, ADRs, issues, or tests instead of duplicating their contents. Use stable identifiers for scenarios and referenced model elements. A diagram summarizes the model; supporting text retains details that cannot be shown clearly. Mermaid is a proposed default for diagrams when the repository renderer supports it.

Add a relative link to the existing `security.md` or `SECURITY.md`, preserving its naming and security reporting instructions. If neither exists, the proposed default is `SECURITY.md` with a short model reference; do not invent a vulnerability reporting address or disclosure policy. An illustrative link section is:

```markdown
## Threat model

See [the threat model](threatmodel.md) for security objectives, threat scenarios, design decisions, and review responsibilities.
```

The model is suitable for the repository's intended audience. Keep credentials, personal data, and restricted incident details out of a shared artifact; use approved references or bounded summaries where necessary. Do not make a private document public merely by linking it. Writing the model and its repository link does not authorize committing, pushing, or publishing them.

## Example scenario

This illustrative scenario concerns a proposed sharing feature before implementation. It combines a requirement, a constraint, an actor, and a known threat without claiming that a vulnerability has been found.

```markdown
### T-003 Access continues after a document share is revoked

A former recipient uses a saved share link to retrieve further document versions after its owner revokes access.

- Objective: Owners can terminate delegated access to future server responses.
- Design basis: The sharing requirement permits external recipients and requires revocation.
- Constraint: External recipients can access a share without creating an account.
- Actor: A former recipient who retains the original link.
- Affected flow: Recipient to share endpoint to document store.
- Known threat: Previously issued links remain usable after authorization changes.
- Consequence: Continued disclosure of confidential document contents.
- Proposed response: Check current share authorization on every document request.
- Control state: Planned; implementation and effectiveness remain unverified.
- Remaining exposure: Previously downloaded copies remain outside server revocation.
- Verification criterion: A revoked link cannot retrieve another document version; an active authorized share still works.
- Decision state: Proposed; no acceptance decision has been recorded.
- Open question: What should happen to active downloads and intermediary caches?
```

Keep applicability, control state, and team decisions as separate dimensions. Planned, implemented, and verified controls have different meanings. A scenario can remain relevant after treatment, and verification records what was checked and under which conditions. Explicit risk acceptance identifies the responsible person, rationale, scope, remaining exposure, and a review date or trigger.

## Change and review behavior

Update the model alongside requirements and design changes that affect objectives, actors, permissions, assets, flows, dependencies, or operating assumptions. A focused update explains which source changed and which model elements and decisions need reconsideration. A broader review can be scheduled by the team according to its development process.

Preserve human edits, stable IDs, and still-applicable decisions. Modify affected sections rather than replacing the entire document. Retain treated or retired scenarios with enough rationale to explain their state, and use Git for textual history. Reopen a decision when its underlying assumptions materially change; do not silently extend an old acceptance to a new exposure.

Review status describes actual work: a draft, a partially reviewed scope, or a recorded team review. Missing answers remain open. A document's existence, an empty threat list, or a passing structural check does not establish that its coverage or risk treatment is sufficient. Changes to an existing model should carry its review status forward only where the review still applies.

## Skill design and execution boundaries

Keep the skill entry point short. Describe creation, focused updates, and review, and load method guidance, examples, or context profiles only when relevant. The model performs synthesis, scenario development, and explanation. Deterministic helpers can check identifiers, local links, source references, and any structured exchanges when those helpers provide a concrete benefit. Formal checks cannot establish semantic completeness.

The aiscb baseline guides execution boundaries for the proposed skill. Protected assets include private requirements, source content, team decisions, and the integrity of the maintained model. The initiating user's authorized project scope governs source access and result writes; repository documents and model output cannot grant authority. Key boundaries are source admission into model context, proposed tool actions, and document updates.

Read only authorized sources, including when using shared profiles or cached context. Treat imported requirements, threat catalogs, existing models, and code as data rather than executable instructions. Retain provenance without promoting source text to tool policy. Keep optional code exploration read-only, with no execution of target scripts or implicit network discovery. Bound reading, model calls, and retries outside the model and support cancellation.

Validate any structured tool proposals against defined schemas and allow-listed operations before execution. Constrain paths and reject escaping links. Restrict writes to the selected model and security-document destinations, detect intervening edits, and preserve unrelated content. Imported strings cannot select commands or new write targets. Missing authorization stops the affected action while leaving a visible incomplete result. These boundaries address prompt injection, unintended disclosure, and unauthorized document changes considered in the [OWASP LLM application risks](https://genai.owasp.org/llm-top-10/) and [OWASP agentic application risks](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

## Evaluation before implementation delivery

Evaluate behavior through small, neutral examples with different names and domain details. The following cases define useful evidence for a future implementation without adding tests or runtime changes in this concept:

- Requirements and a design alone produce system-specific objectives and plausible scenarios, without requesting source code as a prerequisite.
- A known requirement answers a potential question, so the skill reuses it; an ambiguous requirement produces a question tied to that ambiguity and its consequence.
- Equivalent designs with different incidental names receive comparable analysis, while a materially different control or constraint changes the relevant scenario and response.
- A declined or unanswered question remains unresolved; a suggestion never becomes a confirmed classification or accepted risk through silence.
- Conflicting requirements and implementation observations remain visible without silently rewriting intended behavior.
- Known threats and actor profiles receive traceable applicability treatment, including a justified non-applicable case and an unresolved case.
- A focused change preserves unrelated human prose, stable IDs, and still-valid decisions, and reopens decisions whose assumptions changed.
- Malicious instructions in a source cannot authorize execution, unrelated reads, data disclosure, or writes outside the selected artifacts; resource limits and cancellation work without corrupting an existing model.
- The model link resolves using the repository's existing security-document naming, and existing disclosure instructions remain intact.

## Remaining implementation choices

Choose the public skill name without colliding with current commands. Define supported profile formats, source discovery rules, dialogue controls, and any structured tool contracts during implementation design. Establish the rules for concurrent edits and the minimum local validation needed to preserve document integrity. Evaluate selective reuse against the independent workflow rather than assuming compatibility with assessment artifacts.

Normative requirements and costly technical decisions need separate reviewed wording under the repository's change workflow before implementation. The first useful delivery would cover requirement-based creation, contextual optional questions, Markdown maintenance, and the security-document link, with focused update and review behavior evaluated against the same model.
