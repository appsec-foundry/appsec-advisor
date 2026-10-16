# Threat modeling from requirements and design

Status: concept draft, 2026-10-13; revised 2026-10-16. This proposal describes an independent skill for creating and maintaining a team's threat model. It does not change approved product requirements, record accepted implementation decisions, or introduce an executable skill.

The skill helps teams understand what they need to protect, how their system could be misused, and which design choices address those threats. Requirements and specifications establish intended behavior and the proposed system. Architecture descriptions, team knowledge, and optional bounded code exploration provide further context. The workflow works before implementation exists.

The main deliverable is a human-maintained `threat-model.md` at the target repository root, linked from the repository's `SECURITY.md` or `security.md`. Teams can edit, review, and commit it alongside requirements and design changes. Its central relationship is: security objective, affected interaction, threat scenario, control, remaining risk, and treatment decision.

## Purpose and scope

Support three tasks: create an initial model, update it for a change, and review its assumptions, threats, and treatment. A scope can cover a system, a feature, or a proposed design change. Each model identifies its scope, responsible team, intended audience, source state, and review status.

| Requested task | Result and write behavior |
|---|---|
| Create | Create an initial model when no model exists at the selected destination. If one already exists, preserve it and offer a focused update instead of replacing it. |
| Update | Apply the requested changes to the existing model, preserving unaffected content and decisions. Include a new feature in that model rather than creating a separate feature file. |
| Review | Present observations, gaps, and proposed changes in the conversation. Leave the model, its review status, and the security document unchanged. Applying suggestions requires an explicit update request. |

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

When requirements are absent, derive a provisional understanding from the remaining sources and identify which important assumptions need team input. Label inferred requirements as proposals; architecture and code observations do not establish business intent. Code availability is never a prerequisite for modeling a proposed design.

## Entry flow and missing sources

Use this sequence for creation. For an update or review, start from the existing model and inspect changed or missing sources before reopening questions. Apply the requested task's write behavior throughout; a review ends with feedback, not file changes.

1. Establish the requested system or feature scope and authorized source locations. Ask a scope question first only when the target is ambiguous; do not explore unrelated projects to choose a target. Resolve any selected organization package and its applicable context before preliminary analysis.
2. Discover candidate sources within that scope, starting with user-selected sources, the existing model, and repository documentation entry points. Check an existing model's purpose and scope under the repository integration rules below before treating it as the maintained model. Look for requirements, specifications, architecture descriptions, ADRs, and diagrams without depending on exact filenames. Record what was read, inaccessible, unsupported, or left unread at the discovery limit. Report “not found in the inspected scope” rather than claiming that a document does not exist. Document links are candidates subject to access and path checks, not permission to read external locations.
3. Read relevant requirements and specifications, then architecture and other context. Use bounded architecture exploration where needed. Read available architecture before asking users to restate it, including when requirements are missing. An unreadable document does not trigger code execution, remote fetching, or unrestricted scanning.
4. Use the source situations below to prepare a preliminary understanding and optional questions. Incorporate applicable organization context when identifying gaps and scenarios. If no useful sources exist, start with the user's description rather than inventing an architecture.
5. Develop scenarios and treatments when sources or answers support a system-specific account of purpose, valuable assets or operations, actors, and an important interaction. Partial knowledge is sufficient with explicit uncertainty. If that basis remains absent, return an incomplete outcome describing the missing context rather than generic findings or an empty model.
6. Review traceability, contradictions, and scope coverage. For creation or an authorized update, write the supported model changes and its repository link. For a review, present feedback and proposed changes without writing either file. Preserve an existing model when there is no supported update. Report what was examined or modeled and what still needs team input; a written draft does not establish team approval.

The source situations guide the next action without prescribing question wording:

| Available basis | Next action and result |
|---|---|
| Requirements and specifications, with or without code | Read them and relevant architecture; clarify material gaps. Missing design details can remain proposed or unresolved. A model can be produced before implementation. |
| Architecture, ADRs, or diagrams without requirements or specifications | Extract the documented system first, then ask about missing objectives, harmful outcomes, and constraints. Produce a provisional model with inferred business intent clearly marked. |
| Code or configuration only | Use optional, bounded, read-only architecture exploration within the selected scope, then ask about intent. If exploration is declined, use team context. Implementation observations do not become reconstructed requirements or verified controls. |
| Only an existing model or a user description | Reuse the relevant account, distinguishing historical assumptions from current statements. Ask about missing interactions or changes; disclose unavailable corroborating sources. |
| No useful sources or description | Ask a small opening round about purpose, valuable data or operations, and users or external parties, adapting to anything already known. Continue if answers provide a modeling basis. If questions are disabled, skipped, or still insufficient, return an incomplete outcome without creating an empty model or replacing an existing one. |
| Conflicting, unreadable, or incompletely inspected sources | Model supported parts with explicit gaps and targeted clarification where enabled. Stop the affected inference or update when its basis is insufficient. |

### Bounded architecture exploration

Use an architecture agent when relevant architecture spans several documents or a specific structural question requires inspecting code. Missing specifications alone do not justify delegation. The coordinating skill can read a small, clear document set directly. Assign exploration after discovery and await its result before forming questions that depend on it. The coordinator remains responsible for reconciling the result with requirements and user answers.

Give the agent a concrete question, authorized source locations, and externally enforced resource limits. It returns components, stores, actors, important interactions, and candidate trust boundaries with source references, distinguishing explicit statements from inference. Include conflicts, gaps, and the scope actually inspected. The coordinator checks references and the support for conclusions before using them; an agent summary has no higher authority than its sources. Define and validate the structured handoff schema before implementation.

The agent receives read access only. It cannot run target code, install dependencies, contact services, write the model, accept risks, question the user independently, or delegate further. Its task is architecture exploration, not a general vulnerability assessment. If it is unavailable, fails, or reaches its limit, the coordinator can read the same bounded sources within the remaining run budget or proceed with visible gaps. Do not restart unrestricted discovery or treat partial output as complete architecture. Ask about a material remaining gap only when dialogue is enabled.

## Preliminary analysis and optional dialogue

Perform a short preliminary analysis before asking questions whenever relevant sources exist. Extract candidate assets, security objectives, actors, flows, constraints, and plausible harmful outcomes. Reuse applicable answers from the existing model. Optional code exploration addresses specific gaps, such as a component's role or an integration's data types; it does not turn this step into a vulnerability scan.

The LLM selects and formulates questions from missing information, ambiguity, or contradictions in that preliminary understanding. There is no fixed questionnaire, mandatory wording, or deterministic mapping from a keyword to a question. Method guidance supplies perspectives to consider, including harmful outcomes, actor privileges, trust assumptions, manual exceptions, and recovery. An applicable perspective already covered by the sources needs no question; an uncovered one needs either a useful question or a visible unresolved assumption.

Prioritize questions whose answers could change scope, security objectives, significant consequences, a trust boundary, or a treatment choice. Ask at most three questions in the initial round. After incorporating the answers, reassess the remaining uncertainties and offer a further short round only when it could materially change the model. Later rounds also contain at most three questions. Do not ask again for an applicable answer already available in the sources or conversation; a changed source or unresolved contradiction can justify revisiting it. If no material question remains, proceed to the model without filling a question quota.

Each question identifies the relevant observation and source, explains briefly why the uncertainty matters, and asks one concrete question in the team's language. When the gap concerns undocumented team knowledge, identify the missing context instead of inventing a source. Distinguish a question about current behavior from a proposed design choice. Suggested answers may help users respond, but remain tentative and allow correction or a free-form answer. The following examples illustrate reasoning, not a question bank to replay:

| Observation from the preliminary analysis | Contextual question | Effect on the model |
|---|---|---|
| Requirements permit sharing customer contracts with external recipients but omit classification. | Sharing can expose contract contents outside the organization. Which protection classification applies to these documents? | Asset classification and disclosure consequences. |
| Requirements allow external access but do not define its duration. | Access duration affects how long a saved link remains useful. Which business cases, if any, require access without an expiry? | Sharing constraints and authorization design. |
| The design gives support personnel access across tenants without defining permitted actions. | Cross-tenant support access could expose another customer's records. Which actions does support need to perform across tenants? | Actor privileges, trust boundaries, and abuse scenarios. |
| A specification lets external partners change orders but omits the approval boundary. | A delivery-address change could redirect an approved order. Are partners allowed to change that address after approval? | Business authorization, approval integrity, and abuse scenarios. |
| An import operation can replace existing business records. | An incorrect import could alter many records unnoticed. What would be the most serious business consequence? | Integrity objectives and credible impact; the answer may motivate a focused recovery question. |

Let the user confirm, correct, supplement, leave unknown, or skip a proposed answer. Make uncertainty a normal answer. Silence or a skipped question does not confirm a suggestion or accept a risk. A factual answer about current behavior also does not approve that behavior or accept its exposure. Keep risk acceptance separate and explicit under the treatment rules below; answering a modeling question does not authorize tool actions or expand source access.

Offer an open closing question, such as “What concern or exception have we missed?”, within the dialogue's round size. Do not force a final question when the user skips or ends the dialogue. Incorporate new concerns even when they fall outside the LLM's initial scenarios. Stop questioning when the user ends the dialogue, declines further discussion, or the remaining answers would not materially change the model. Carry unresolved items into the draft with their affected scenarios or decisions; do not repeat unanswered questions merely to obtain completion. Execution limits still apply independently of the LLM's decision to continue.

For assets, reuse the organization's classification scheme where available. Also describe confidentiality, integrity, and availability needs: public data can still require strong integrity. Include valuable capabilities and business processes, such as approving a payment, alongside data and infrastructure.

For worst-case scenarios, explore the most serious plausible harm within scope and state its prerequisites, affected parties, and reach. Keep impact separate from likelihood and avoid invented probabilities or financial estimates. Team concerns can reveal consequences that source files do not describe.

The proposed default is a short guided dialogue, with optional deeper discussion and a mode without questions. That mode performs the same preliminary analysis and records material gaps without asking questions. A run without answers produces a draft or review feedback when the available context supports it; otherwise the entry flow returns an incomplete outcome. During creation or an authorized update, record useful answers as concise statements in the relevant model sections, with their source, applicability, and affected assumptions, scenarios, or decisions. During a review, include them in proposed changes without modifying the model. Distinguish a user-reported fact, a desired future behavior, and an LLM inference; a reported control is not verified effectiveness. The conversation transcript is not part of the deliverable. Preserve conflicts with other sources and revisit answers when their supporting requirements, design, or scope change. Ask for the minimum context needed, without requesting credentials, personal records, or confidential incident details for inclusion in the model.

## Reusable security context

Accept context from plugin-provided catalogs, organization or domain profiles, and project-specific inputs selected by the user or trusted installation configuration. A packaged organization profile can supply defaults without requiring users to select each case on every run; show which package and context were activated. Small projects can maintain context directly in the model. Shared profiles can use separate versioned files when reuse warrants them. Record the sources and versions used so a later model update can explain changes in context.

| Input | Purpose and treatment |
|---|---|
| General threat patterns | Suggest relevant mechanisms, prerequisites, and affected security properties. Instantiate applicable patterns against the system model. |
| Targeted abuse cases | Describe an unwanted business outcome, relevant actors and prerequisites, affected workflow, legitimate exceptions, and expected safeguards where known. Use these to investigate the design and identify material questions. |
| Known threats | Carry scenarios from earlier models, incidents, reviews, or team concerns into explicit consideration. Preserve origin and reassess applicability and treatment. |
| Threat actors | Describe goals, initial access, permissions, controllable inputs, capabilities, and relevant resource assumptions. |
| Constraints | Describe binding obligations, negotiable product or technical choices, and external dependencies. Keep these categories distinguishable. |
| Security requirements | Define the properties the design needs to preserve and support traceability to mitigations and verification criteria. |
| Assumptions | State dependencies on behavior, deployment, users, or external controls, with an owner or review trigger where useful. |

Selected [CAPEC patterns](https://capec.mitre.org/about/index.html) can supply attack mechanisms. [MITRE ATT&CK](https://attack.mitre.org/) can inform relevant adversary behavior and operational scenarios. Neither replaces project-specific analysis or exhausts the threats worth considering.

Actor descriptions emphasize capabilities and access. An authenticated tenant, a former recipient with a saved link, or a partner that supplies business data is more useful for a concrete scenario than an unsupported claim about a named adversary. The team can supply additional actor knowledge and explain exclusions.

For each explicitly supplied known threat, retain an applicability outcome and rationale: applicable, not applicable, or unresolved. Link applicable entries to scenarios and merge duplicate mechanisms without losing source references. Track control and treatment state separately. An applicable threat may already have a safeguard or an accepted residual risk; imported status alone does not establish that the decision still applies.

A constraint limits available responses; it does not remove the underlying exposure. Surface conflicts with security objectives and describe alternatives for team review. A profile update proposes changes to the model and highlights affected assumptions and decisions. It does not silently accept new risk, replace team decisions, or expand execution permissions.

### Context supplied through organization packaging

Allow an organization package to bundle targeted abuse cases and organization or domain context: asset classifications, actor profiles, security objectives, requirements, architectural constraints, known incidents summarized without sensitive details, and review expectations. Each reusable entry has a stable identifier, source and version, applicable scope, and a declared role such as binding obligation, recommendation, or contextual assumption. Validate the supported package format before admission. An entry's self-description does not establish its authority; binding status depends on the selected organization's authorized configuration and applicable source. Invalid or incompatible selected context remains a visible input failure, not a silently omitted obligation.

Resolve the selected package before preliminary analysis. After reading project sources, assess each selected abuse case as applicable, not applicable with a rationale, or unresolved. If a case has not been examined because of resource limits, record that separately rather than implying an applicability decision. Missing code or a missing keyword cannot establish non-applicability to a proposed design. Instantiate applicable cases against actual actors, operations, and boundaries, merging duplicate mechanisms while retaining their source identifiers. A case is a scenario to examine, not proof of a vulnerability or a preset severity.

Use case-specific uncertainties to generate contextual questions. For example, a package may describe reuse of an approval after the approved content changes. If the specification allows later edits but says nothing about approval validity, ask which changes require renewed approval. If it already defines that behavior, reuse the answer and model the relevant control. Optional example questions in a package guide interpretation; they do not become a mandatory script or replace the LLM's selection of useful questions.

Keep declared obligations, team preferences, and model suggestions distinguishable. Surface conflicts between package content, project requirements, and user answers without silently choosing a convenient precedence. An ordinary dialogue answer does not waive a binding obligation. Record applicability and treatment separately, and preserve the existing rule that explicit risk acceptance identifies responsibility and remaining exposure. A package update prompts review of affected scenarios and decisions instead of silently rewriting them. Organization cases supplement project-specific exploration; a short package is not evidence of complete coverage.

Admit packaged content as labeled reference data through a defined context interface. Text in a case or profile cannot change tools, permissions, write destinations, model instructions, or the security baseline. The same restrictions apply to the architecture agent. Do not execute bundled hooks, scripts, or remote downloads as part of importing modeling context. Record only the minimum package references and summaries suitable for the model's audience; inclusion in a package does not authorize publishing confidential content.

The existing assessment workflow supports organization cases through `abuse_cases.add` and descriptive business cases with `check`, `exclusions`, and `open_questions`; see [organization profiles](../org-profiles.md#business-abuse-cases). These are reuse candidates, not an implemented interface for this skill. Their code-based applicability and finding-verification semantics need explicit adaptation for modeling before code exists. Define any profile extension, packaging behavior, and consumer schema under the [org-profile invariants](../internal/contracts/org-profile-invariants.md) before implementation.

## Modeling workflow

The dialogue feeds the modeling work and can resume when a material uncertainty emerges. The following phases describe the proposed responsibilities rather than a requirement for a fixed number of agent calls.

1. Follow the entry flow to establish scope and objectives from requirements, specifications, and available context. Identify assets, valuable operations, actors, exclusions, and uncertain assumptions. Use the preliminary analysis to prepare optional questions.
2. Describe the system. Model components, stores, external parties, important interactions, and trust boundaries. Explain the identity, ownership, privilege, or control assumption that changes at each boundary. Use a compact diagram and supporting prose; add a detailed view only where it helps reasoning.
3. Develop scenarios. Examine how an actor could violate an objective through an interaction or workflow. Use STRIDE, relevant patterns, known threats, and team concerns. Include multi-step paths and business abuse where applicable. Lack of code evidence does not disqualify a design threat.
4. Evaluate responses. Identify existing and planned controls, explain how they address the scenario, and describe remaining uncertainty and risk. Propose elimination, mitigation, transfer, or acceptance as applicable. State who retains responsibility for controls and residual risk when transferring responsibility.
5. Review the model with the team. Check architectural accuracy, coverage of significant interactions and objectives, treatment rationale, testability, and unresolved decisions. Record actual review participation and scope without presenting automated analysis as human approval.
6. Maintain the model with changes. Update affected objectives, scenarios, assumptions, and decisions while preserving stable references and unaffected content.

Use qualitative, explained risk prioritization that considers plausible harm, prerequisites, access, and relevant controls. Separate confidence in the underlying information from risk priority. Concrete vulnerability scoring can be supplemental when justified; a CVSS score is not required for a design scenario. Unknown impact or exposure stays visible instead of receiving an invented precise score.

## Maintained model and repository integration

Use `<repo>/threat-model.md` as the leading, directly editable artifact, where `<repo>` is the target repository root. Markdown and text-based diagrams allow the team to review changes through ordinary pull requests. A separate canonical YAML or JSON model is not needed for the initial workflow; add structured interchange only when a concrete consumer justifies it and its schema and synchronization rules are defined.

Before changing an existing file, inspect its content, stated purpose, provenance where available, and scope. The filename alone does not distinguish a maintained design model from a generated assessment report. When that distinction or the intended use is unclear, preserve the file and ask the user how to use it before modification or conversion. If questions are disabled or no answer arrives, leave the file and its security-document link unchanged and report the unresolved choice. Do not automatically migrate an assessment or create a competing model file to bypass this choice.

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

During creation or an authorized update, add a relative link from the existing `SECURITY.md` or `security.md` to the model, preserving the document's location, naming, and security reporting instructions. Reuse an existing model link rather than adding a duplicate. If neither document exists, create `<repo>/SECURITY.md` with a short security heading and model reference; do not invent a vulnerability reporting address or disclosure policy. Create the link only when the model exists, and resolve its relative path from the security document's location. A review can propose a missing link but does not write it. For a security document at the repository root, the link section is:

```markdown
## Threat model

See [the threat model](threat-model.md) for security objectives, threat scenarios, design decisions, and review responsibilities.
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

A feature or design-change update extends the existing repository model. Integrate its actors, flows, scenarios, and treatments into the relevant sections, including affected shared boundaries, while retaining unrelated system content. Identify the scope actually examined; a feature review does not establish review of the entire application. If no model exists, an explicitly requested initial model may cover only that feature and must state that limitation. Separate files for individual features are outside the initial workflow.

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
- Architecture without specifications is read before questions are asked about documented facts; absent business intent remains provisional. Code-only exploration stays bounded and distinguishes observation from intended behavior.
- With no useful documents, a user description can establish the modeling basis. With neither usable context nor answers, the result is incomplete and an existing model remains unchanged. Unreadable files and exhausted discovery limits are reported without claiming that sources do not exist.
- A small document set is read directly; a delegated architecture task returns traceable observations and gaps. Unavailable or failed delegation permits bounded fallback without repeated discovery, invented architecture, independent user questioning, or broader permissions.
- A known requirement or specification answers a potential question, so the skill reuses it; an ambiguous approval boundary produces a question tied to that ambiguity and its consequence. Repeat the case with different operation and role names, and use an explicit boundary as the negative case where no clarification is needed.
- An answer reveals a manual exception and changes the next relevant question and scenario. An answer that resolves the uncertainty produces no redundant follow-up. Judge relevance and model effects rather than exact wording or question order.
- Each round contains at most three questions. The user can add an unanticipated concern, decline another round, or stop; material gaps remain visible without repeated questioning. A mode without questions still produces a draft and open items from requirements and specifications alone.
- Equivalent designs with different incidental names receive comparable analysis, while a materially different control or constraint changes the relevant scenario and response.
- A declined or unanswered question remains unresolved; a suggestion never becomes a confirmed classification or accepted risk through silence. A user report of an existing control remains attributed and unverified, and an answer describing risky behavior never becomes risk acceptance or tool authorization.
- Conflicting requirements and implementation observations remain visible without silently rewriting intended behavior.
- Known threats and actor profiles receive traceable applicability treatment, including a justified non-applicable case and an unresolved case.
- A selected organization package supplies an abuse case that changes a relevant question or scenario. A renamed workflow preserves the mechanism; an explicit legitimate exception supports non-applicability. Missing code alone does not exclude a design case, and an already answered case causes no redundant question.
- Organization and project cases with the same mechanism retain both source references after merging. Conflicting obligations stay visible; invalid package content and unexamined cases are not silently treated as satisfied. Package updates preserve unrelated model content and reopen only affected decisions.
- Instructions embedded in package content or an architecture summary cannot authorize commands, external reads, broader delegation, confidential publication, or risk acceptance.
- A focused change preserves unrelated human prose, stable IDs, and still-valid decisions, and reopens decisions whose assumptions changed.
- A review identifies gaps and proposed changes while leaving the model, its review status, and the security document unchanged, even when dialogue supplies new answers. An explicit subsequent update applies only the requested changes.
- A feature update integrates new scenarios and affected shared boundaries into the existing model without a separate feature file or loss of unrelated content. Its review scope does not imply review of the whole application.
- A creation request encountering an existing model preserves it and offers an update. An ambiguously identified model or assessment prompts a question before modification; declined or unavailable answers, including a mode without questions, leave the existing files unchanged.
- Malicious instructions in a source cannot authorize execution, unrelated reads, data disclosure, or writes outside the selected artifacts; resource limits and cancellation work without corrupting an existing model.
- The model link resolves using the repository's existing security-document naming, and existing disclosure instructions remain intact.

## Remaining implementation choices

Choose the public skill name without colliding with current commands. Define supported profile formats and packaging admission, bounded discovery limits, dialogue controls, the architecture-agent handoff schema, and any structured tool contracts during implementation design. Establish the rules for concurrent edits and the minimum local validation needed to preserve document integrity. Evaluate selective reuse against the independent workflow rather than assuming compatibility with assessment artifacts.

Normative requirements and costly technical decisions need separate reviewed wording under the repository's change workflow before implementation. The first useful delivery would cover requirement-based creation, contextual optional questions, Markdown maintenance, and the security-document link, with focused update and review behavior evaluated against the same model.
