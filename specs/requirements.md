# Plugin requirements

What the plugin must do. This catalog contains stable promises a user would
recognize, not the implementation choices used to keep them.

Technical ownership, affected paths, decision references, and test evidence
live in `data/requirement-bindings.yaml` so routine refactors do not rewrite the
approved product specification.

## Purpose

### REQ-PUR-001 — The model is derived from the repository and stays current

The threat model comes from code and configuration rather than a workshop.
Running the analysis again produces a model of the repository as it exists then.

### REQ-PUR-002 — The subject is the design, not only the code

The analysis covers exploitable design assumptions and missing controls as well
as vulnerable code. It complements code scanners and provides review input, not
a release verdict.

### REQ-PUR-003 — Developer and AppSec teams can both run it

A team can analyze its own repository or select separate input and output
locations without changing the analysis semantics.

## Finding model

### REQ-MOD-001 — A finding is a concrete instance backed by evidence

A finding identifies a security problem in the target repository and cites the
evidence that supports it. Separate instances remain separate unless they share
the same affected object and security mechanism.

### REQ-MOD-002 — A weakness describes the class above its findings

A weakness groups related findings under the security pattern they exhibit and
may also describe an architectural problem with no vulnerable source line.

### REQ-MOD-003 — Trust boundaries are derived assumptions that can fail

Trust boundaries are derived from repository evidence, while declarations may
only add or clarify crossings. A declaration or absence of contrary evidence
never proves that a boundary control works.

### REQ-MOD-004 — Abuse cases remain hypotheses until evidence confirms them

The operator controls which abuse-case sources are used. A technical abuse case becomes a finding only when target-repository evidence confirms it. Standard and thorough assessments also load the plugin's generic business abuse cases unless the organization profile disables the defaults, and a business case is verified only when deterministic preselection finds code it applies to. A confirmed business case becomes a finding. An unconfirmed business case that cites code where no enforcing control was found becomes a finding marked as unproven; any other unconfirmed business case is reported as unresolved, not as safe. Thorough assessments also let the model propose up to three application-specific business abuse cases, which are marked as model-derived and follow the same verification and reporting rules.

### REQ-MOD-010 — Users can list and check abuse cases individually

A user can list the abuse and business cases defined for a repository, each with its title, kind, and whether it comes from the plugin, the organization profile, the repository, or a per-scan file. A user can select one or more of these cases and have them checked without a full assessment. When a threat model exists, the check uses it; the user can instead choose an isolated check against the code alone. Either check follows REQ-MOD-004: a case is confirmed only by repository evidence, and a case without decisive evidence is reported as unresolved, never as safe. An isolated check states that it ran without a threat model. When an existing model records a case as inconclusive or not performed, the plugin may suggest this check, but never starts it on its own.

### REQ-MOD-005 — Findings require evidence from the target repository

External context may identify a hypothesis, but only source, configuration, git
history, or target-owned declarations can establish and score a finding.

### REQ-MOD-009 — An unproven finding says that it is unproven

A finding whose insecure state is observed but whose exploitability is not
established is reported and is marked as unproven wherever it appears. Its
severity follows the security impact it would have, not the strength of its
evidence. It carries no score and does not count as a confirmed instance, and a
verdict that asserts confirmed exploitation does not rest on it.

## Security architecture

### REQ-ARC-001 — Architecture ratings describe the controls that apply

Each control domain is rated from evidence of what the system actually uses.
An absent surface is not applicable, and a broken control remains distinct from
a missing control.

## Analysis

### REQ-FLW-002 — Every analyzed component receives complete STRIDE coverage

Every component a threat-model assessment analyzes is checked against all six
STRIDE categories in every depth mode. Cost and pacing choices may not silently
reduce that coverage.

### REQ-FLW-003 — Invalid required analysis data cannot produce a report

Required analysis inputs and outputs are validated before they are consumed or
published. Missing or invalid required data stops the run instead of producing
an apparently complete report.

### REQ-REQ-001 — Requirements mapping contains only linked findings

Requirements mapping follows explicit links from findings to the configured
catalog. It never infers a link from an identifier or invents one when no catalog
is present.

## Business context

### REQ-BIZ-005 — Early questions inform the same analysis

Interactive full and rebuild runs use a bounded application overview to ask at most two relevant business-context questions before expensive scanning. The dialog first confirms or corrects the intended use case, then asks for the worst plausible business or user harm in that use case. Technical attack mechanisms alone are not business-harm choices. Choices reflect the confirmed application use and available evidence, with the most plausible option recommended first and explicit confirmation required. No material business harm is a supported answer, including a conditional recommendation for training or demo use with synthetic data and no important business operations. Existing context informs the questions, and already answered topics are omitted. Answers reach the analysis in that same run as optional, validated context and inform relevant finding impact and mitigation ordering. Substantive dialog answers are also saved in `docs/security/business-context.md`, preserving existing repository context, so later analyses reuse them. The legacy `docs/business-context.md` remains a read fallback when the new file is absent. If both exist, the new file takes precedence. Saving dialog answers copies effective legacy context into the new file without modifying the legacy file. Persistent business context survives run cleanup. An explicit run-only context source is not persisted with those answers. Users can skip questions; headless runs and `--skip-context` never wait for this dialog or write dialog answers. Limited discovery yields explicit uncertainty rather than an extended reconnaissance loop.

### REQ-BIZ-001 — Declared context is validated and treated as data

Repository and operator supplied context is validated before use and remains
untrusted data. Its contents cannot instruct or redirect the analysis.

### REQ-BIZ-002 — Only repository configuration persists actor choices

Actors and their objectives may guide an individual run, but conversational or
per-run choices are not written back to the target repository.

### REQ-BIZ-003 — Business context weights supported findings, it does not establish them

Business purpose, sensitive assets, compromise impact, and obligations may weight
the impact rating and the presentation order of findings that already stand on
repository evidence. They never determine whether a finding exists, never relax a
severity cap, and never substitute for evidence. A finding whose impact rating
rests on declared context names the context that carried it.

An explicit declaration of no material business harm remains distinct from unknown impact. It does not by itself add a business-priority bonus or trigger a request to raise impact. Independently declared sensitive assets and obligations remain relevant, and technical evidence still governs findings and ratings. The verdict distinguishes the declared no-harm scope from its technical concern level.

### REQ-BIZ-004 — A run says whether declared context reached the analysis

When context is declared for a run, the run reports whether it was read, which
file it came from, and how many findings it applied to. Context that reaches no
component is reported as such rather than passing silently.

## Report

### REQ-RPT-001 — Severity is earned from evidence

Severity and any score follow demonstrated evidence and applicable policy caps.
They are never raised merely to attract attention.

### REQ-RPT-002 — Public finding anchors remain internally consistent

Finding anchors remain consistent across the reports, exports, and follow-on
tools produced from the same model. A deliberate rebuild creates a new model and
may assign them again.

### REQ-RPT-003 — The report is concise and actionable for engineers

A finding identifies where the problem is, why an attack works, and what must change in the repository's own vocabulary. References point only to locations that exist. Code symbols, source paths, configuration identifiers, and complete code expressions use one inline-code format consistently across report sections without consuming surrounding prose. When the analysis leaves decisions open that only the team can settle, the Management Summary shows up to three questions: how critical the affected assets are when no business context declares it, then design and deployment decisions with their weakness and finding references; it never asks the team to verify individual findings and omits the block when the selection is empty. The completion summary points readers to the report, finding triage, and the ask skill without repeating the questions.

### REQ-RPT-005 — Mitigations are prioritized and verifiable

Every finding has a prioritized mitigation. Urgent work states concrete steps
and a way to verify the result without inventing source examples.

### REQ-RPT-006 — Machine-readable exports preserve security traceability

The canonical YAML records abuse-case outcomes, the use and provenance of business context without copying its prose beyond a bounded, plain-text statement of the use case the user confirmed, and the complete configured requirements assessment. Narrower exports retain applicable requirement, abuse-case, and business-context traces as native fields or bounded text and identify semantics they cannot represent.

### REQ-RPT-007 — Figure 1a stays readable at page width

Figure 1a shows each column only as wide as its content needs, so its labels stay legible when the figure is scaled to the width of a report page or README. Making the figure more compact never removes a data-flow label from the drawing.

### REQ-RPT-008 — The report shows how a supply-chain attack reaches production

When the repository evidences a CI build or the analysis reports a build-time attack, the Management Summary includes a supply-chain view of the evidenced inputs, build systems and release artifacts and of the running system they feed. A reported finding adds an attack entry only when it establishes the attack mechanism. A highlighted path follows evidenced relationships, and a relationship the evidence does not establish is shown as not evidenced. The runtime figure then shows no build element. The supply-chain view stays readable at the supported report and README widths and in HTML and PDF exports, with distinct and unclipped labels, connections, arrowheads and badges. When it cannot be drawn cleanly and legibly, the report presents the same information as a table and records the fallback.

## Quick security score

### REQ-SCO-001 — A comparable score requires complete scanner evidence

The deterministic repository score validates every required scanner artifact and withholds the aggregate when execution or validation is incomplete. Both incomplete and insufficient-coverage results retain available findings and diagnostics. Structured output identifies producer completion, scoring and catalog versions, and applicable coverage for commit comparisons. Findings excluded from scoring remain visible with their severity.

## After the run

### REQ-USE-001 — Findings remain usable after publication

Users can query and triage the model finding by finding, with decisions stored
next to it. Stale decisions are identified rather than silently reused.

## On-demand threat analysis

### REQ-ANA-001 — Threat analysis runs only when someone asks for it

Installing the plugin, configuring an organization profile, or selecting
question packages or a methodology profile never starts a threat analysis. It
runs when a developer invokes it or a team configures it in its own CI.

### REQ-ANA-002 — An advisory analysis never reports a failure as success

A complete analysis succeeds regardless of its findings and grants no security
approval. Invalid input, missing required context or answers, and incomplete
required work end without success.

### REQ-ANA-003 — Threat analysis leaves the threat model and assessments untouched

An analysis never changes the threat model or its finding identities. Its
completion, failure, or cancellation leaves any assessment intact, including
one running at the same time.

### REQ-ANA-004 — Required analysis inputs cannot be weakened

A developer can add question packages and methodology profiles to an analysis
but cannot remove inputs the organization requires. A change under review
cannot choose the inputs that assess it.

### REQ-ANA-005 — Questions and methodology guide the analysis without deciding it

Question packages and methodology profiles direct what the analysis
investigates. They cannot establish a vulnerability or requirement violation
on their own or grant the analysis additional permissions.

### REQ-ANA-006 — The Threat Modeling Manifesto profile is optional

The plugin provides a methodology profile based on the Threat Modeling
Manifesto. It applies only when selected, names its source, and does not
certify compliance.

### REQ-ANA-007 — Answers are saved only on request

Answers to analysis questions last for the session unless the developer saves
them to a feature file of their choice. Saving never commits and never changes
business context or the threat model, and a saved answer is rechecked before
reuse.

### REQ-ANA-008 — A change review states how each finding relates to the change

Each finding of a change review states whether the change introduced,
worsened, or mitigated it, whether it existed before, or that the relationship
is unknown.

### REQ-ANA-009 — A hypothesis check examines an explicitly selected source scope

A developer can ask the analyst to check a concrete threat hypothesis against named files or directories at a Git revision without supplying a code change. The result identifies the inspected revision and scope, distinguishes code-supported, not-confirmed-in-scope, and unresolved hypotheses, and cites evidence for a supported or not-confirmed conclusion. Missing required evidence leaves the analysis incomplete. The model cannot expand the authorized source scope, and a not-confirmed hypothesis never constitutes proof of safety.

## Trust

### REQ-TRU-001 — A scanned repository cannot steer the run

Repository content is untrusted by default. Repository-owned agent settings,
instructions, hooks, and paths outside the selected root are rejected before
they can influence analysis behavior.

### REQ-TRU-002 — A leaked secret prevents publication

If a run artifact contains an unmasked secret, the run fails instead of
publishing it.

## Configuration

### REQ-CFG-001 — Organizations configure the plugin without forking it

Supported organizational extensions are supplied through the organization
profile and package policy. A build records the surface it includes.

### REQ-CFG-002 — Repositories configure analysis through declared inputs

Supported repository context is supplied through documented, schema-validated
files. Repository configuration cannot suppress a finding supported by target
evidence.

### REQ-CFG-003 — A vendored baseline can be refreshed from the source that declares it

Where a secure-coding baseline is configured with both a fetchable source and a
vendored copy, the copy can be refreshed from that source, and a refresh reports
whether the two had drifted. A published id that differs from the configured one
stops the refresh until the new id is accepted explicitly, and accepting it
updates the copy and every place declaring the id together. A refresh never
falls back to the vendored copy and is never part of a release gate.

## Compatibility

### REQ-EVO-003 — Published contracts change through explicit compatibility handling

Published artifact formats, report anchors, and organization configuration
interfaces are versioned or migrated when an incompatible change is necessary.
