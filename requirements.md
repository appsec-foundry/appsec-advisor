# Product requirements

The plugin's required behavior, grouped by topic. Implementation bindings and test evidence live in [data/requirement-bindings.yaml](data/requirement-bindings.yaml).

## Purpose and audience

- **REQ-PUR-001:** The tool must derive a threat model of the analyzed system from its code and configuration.
- **REQ-PUR-002:** The analysis must cover implementation weaknesses and insecure design assumptions without claiming runtime verification or release approval.
- **REQ-PUR-004:** The threat model must help developers, architects, and AppSec reviewers understand risks and plan remediation.

## Analysis scope

- **REQ-PUR-003:** Users must be able to select local repositories or Git URLs and a separate output location, including combined assessments of multiple repositories.
- **REQ-FLW-005:** Each assessment must identify its source revisions, analysis scope, context sources, exclusions, and coverage gaps.
- **REQ-FLW-009:** Users must be able to select analysis depth; a request to narrow the analysis to specific components or directories must be refused, never silently run in full.
- **REQ-FLW-002:** Every analyzed component must receive all six STRIDE checks at every analysis depth.
- **REQ-FLW-010:** Analysis must inspect applicable authentication, authorization, input handling, cryptography, secrets, frontend, deployment, supply-chain, and AI security controls.

## Architecture and trust boundaries

- **REQ-ARC-003:** The model must describe assets, actors, components, interfaces, data flows, trust boundaries, and security controls.
- **REQ-ARC-001:** Control assessments must distinguish evidenced controls, broken controls, missing controls, uncertainty, and non-applicable surfaces.
- **REQ-MOD-003:** Trust boundaries must represent evidenced enforcement points; declarations and missing findings must never prove that controls work.
- **REQ-ARC-002:** Combined models must preserve repository provenance and require evidence from both sides for cross-repository connections.
- **REQ-ARC-004:** Related-repository imports must remain contextual input and must not imply that the imported repositories were scanned.

## Findings and evidence

- **REQ-MOD-001:** Each finding must identify a concrete security problem and supporting target-repository evidence; distinct instances must remain distinguishable.
- **REQ-MOD-002:** Weaknesses must group related findings and support architectural problems without a single vulnerable source line.
- **REQ-MOD-009:** Unproven findings must remain visibly unproven, carry no score, and never count as confirmed exploitation.
- **REQ-MOD-015:** Imported known threats must be revalidated, checked for mitigation, recorded as accepted, or skipped according to their declared status.

## Risk assessment

- **REQ-RPT-001:** Severity and scores must follow supported security impact and applicable policy caps.
- **REQ-BIZ-003:** Business context may affect supported impact and ordering within a priority tier, but must not create findings, raise likelihood, change priority tiers, or relax caps.
- **REQ-BIZ-008:** Declared absence of material business harm must remain distinct from unknown impact and must not suppress technical findings or independent obligations.

## Business context and actors

- **REQ-BIZ-001:** Supplied business context must be validated and treated as untrusted data, never as analysis instructions.
- **REQ-BIZ-005:** Interactive full and rebuild assessments must ask at most two optional use-case and business-harm questions, reuse existing answers, and apply confirmed answers in the same run.
- **REQ-BIZ-006:** Confirmed dialog answers must be preserved for later assessments; explicit run-only context must not be persisted.
- **REQ-BIZ-010:** Headless runs must accept context without questions; `--skip-context` must skip both the dialog and stored business context.
- **REQ-BIZ-004:** Reports must identify the context source and affected findings, including when supplied context affects none.
- **REQ-BIZ-002:** Conversational actor choices must remain run-local; persistent actor configuration must respect organization restrictions and explicit opt-in requirements.

## Abuse cases

- **REQ-MOD-004:** Users must control abuse-case sources; standard and thorough assessments must include enabled business cases, with up to three model-derived cases at thorough depth.
- **REQ-MOD-010:** Users must be able to list case titles, types, and origins and explicitly check selected cases using an existing model or an identified isolated scope.
- **REQ-MOD-012:** Business-case results must distinguish confirmed, unproven, mitigated, unresolved, not applicable, and not checked, with findings created or linked only under the applicable evidence rules.

## Remediation

- **REQ-RPT-005:** Every finding must have a prioritized, system-specific mitigation; urgent mitigations must include concrete steps and verification, with unresolved decisions stated explicitly.

## Reports and diagrams

- **REQ-RPT-003:** Findings must explain the affected location, attack mechanism, and required change in clear developer language with valid references.
- **REQ-RPT-002:** Finding IDs and references must remain consistent across outputs from the same model; deliberate rebuilds may assign new IDs.
- **REQ-RPT-006:** Structured exports must preserve requirements assessments, abuse-case outcomes, and business-context provenance without copying context prose beyond the bounded confirmed use case.
- **REQ-RPT-007:** Architecture diagrams must remain legible at report width and retain required flow labels, with detailed catalogs available for omitted connections and boundaries.
- **REQ-RPT-008:** Evidenced build pipelines and build-time attacks must appear in a separate supply-chain view, with an equivalent table when a readable diagram is unavailable.
- **REQ-RPT-009:** Reports must present up to three unresolved business, design, or deployment decisions without asking users to verify individual findings.
- **REQ-RPT-012:** Narrower export formats must retain applicable traceability and disclose information they cannot represent.
- **REQ-RPT-016:** Users must be able to export existing models as Markdown, YAML, PDF, HTML, SARIF, Threat Dragon, and pentest tasks without rerunning analysis.

## Model lifecycle and review

- **REQ-USE-004:** Full assessments must preserve the history of earlier results; deliberate rebuilds may reset the model and history.
- **REQ-USE-005:** Model questions and overviews must read existing results without rescanning sources or changing files.
- **REQ-USE-006:** Users must be able to determine whether a model is fresh, stale, missing, or blocked.
- **REQ-USE-001:** Users must be able to review findings, record decisions, and plan remediation; decisions must survive reassessment, and code changes must require explicit selection.
- **REQ-USE-007:** Publication must require successful publication checks and include only selected report artifacts.
- **REQ-USE-008:** Configurable architect review must preserve accepted corrections and distinguish reviewed, incomplete, and unreviewed findings.

## On-demand threat analysis

- **REQ-ANA-001:** Advisory analysis must run only through explicit invocation or team-configured CI.
- **REQ-ANA-002:** Complete advisory analysis must succeed regardless of findings; invalid inputs or incomplete required work must not report success.
- **REQ-ANA-003:** Advisory analysis must leave existing threat models, finding IDs, and concurrent assessments unchanged.
- **REQ-ANA-004:** Organization-required analysis inputs must remain mandatory and must not be selected or weakened by the change under review.
- **REQ-ANA-005:** Question packages and methodology profiles must guide analysis without proving findings or granting permissions; optional profiles must identify their source without certifying compliance.
- **REQ-ANA-007:** Analysis answers must be saved only on request, revalidated before reuse, and never automatically committed or copied into the threat model or business context.
- **REQ-ANA-008:** Change reviews must identify whether each finding is introduced, worsened, mitigated, pre-existing, or of unknown relationship to the change.
- **REQ-ANA-009:** Hypothesis checks must stay within selected revision and paths and distinguish supported, not confirmed in scope, and unresolved results.
- **REQ-ANA-010:** Design analysis must work without code and report scenarios, assumptions, recommendations, and questions while identifying any model or source context used.
- **REQ-ANA-011:** Repository exploration must be explicitly enabled, interactive, organization-permitted, and restricted to a redacted, read-only snapshot without execution or network tools.

## Security requirements audit

- **REQ-REQ-001:** Findings must map to configured requirements only through explicit, evidence-supported links.
- **REQ-REQ-002:** Users must be able to audit a validated requirements catalog without creating a threat model, with catalog provenance and inspected scope recorded.
- **REQ-REQ-003:** Requirement assessments must distinguish pass, partial, fail, unverifiable, and not applicable.
- **REQ-REQ-005:** Audits must support advisory results and explicitly configured CI gates based on assessment status and requirement priority.

## Security score

- **REQ-SCO-001:** Scanner-only assessment must return a 0–100 score, `undetermined` for insufficient coverage, or `incomplete` for failed or invalid required scans, while retaining findings and diagnostics.
- **REQ-SCO-002:** Structured score output must expose producer completion, scoring and catalog versions, applicable coverage, and excluded findings so comparisons remain meaningful.

## Configuration and compatibility

- **REQ-CFG-001:** Organizations must be able to configure supported extensions without forking the plugin, with included capabilities recorded.
- **REQ-CFG-002:** Repository configuration must use documented, validated inputs and must not suppress evidence-supported findings.
- **REQ-CFG-003:** Baseline refresh must use the declared source, report drift, and require explicit acceptance of changed baseline IDs before updating all declarations consistently.
- **REQ-EVO-003:** Incompatible changes to published artifacts, report anchors, or organization interfaces must receive explicit versioning or migration handling.

## Trust and data protection

- **REQ-TRU-001:** Repository content must be untrusted by default and must not activate repository-owned instructions or hooks or redirect analysis outside selected roots.
- **REQ-TRU-002:** Unmasked secrets in generated artifacts must block publication.
- **REQ-TRU-003:** The tool must disclose which repository data is sent to external model providers.
- **REQ-TRU-004:** Model-directed actions must remain within the user-authorized task, resources, and permissions.

## Execution and recovery

- **REQ-FLW-003:** Required inputs and outputs must be validated before use; missing or invalid required data must stop publication of an apparently complete result.
- **REQ-FLW-006:** Headless execution must require no interactive responses and must distinguish completion, incomplete execution, and failure.
- **REQ-FLW-007:** Runs must expose progress, actionable diagnostics, and recovery options; external issue publication must require approval of the prepared content.
- **REQ-FLW-008:** Budget behavior must be explicit for each execution mode, and interrupted or incomplete work must never be reported as successfully completed. Deterministic controller runs must reserve resources for required completion work, omit optional model work when necessary, and provide a clearly marked incomplete report of validated results when the budget cannot cover required analysis.
